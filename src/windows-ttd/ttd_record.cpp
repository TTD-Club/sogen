#include "ttd_record.hpp"
#include "snapshot.hpp"

#include <disassembler.hpp>
#include <memory_utils.hpp>

#include <utils/compression.hpp>
#include <utils/finally.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <random>
#include <ranges>
#include <sstream>
#include <stdexcept>

namespace sogen::ttd
{
    static_assert(std::endian::native == std::endian::little, "TTD trace requires a little-endian host");

    namespace
    {
        constexpr uint64_t page_size = 4096;
        constexpr int checkpoint_compression_level = 3;
        constexpr int code_table_compression_level = 9;
        constexpr size_t max_instruction_size = 15;

        // The length of an instruction the backend executed without decoding it (size 0: it raises an exception), as
        // capstone decodes it, or 1 when capstone cannot decode it either. Recording and replay both use this, so the
        // execute event matches.
        size_t executed_size(windows_emulator& emu, const uint64_t address, const size_t reported)
        {
            if (reported)
            {
                return reported;
            }
            auto& cpu = emu.emu();
            std::array<uint8_t, max_instruction_size> bytes{};
            size_t readable = 0;
            while (readable < bytes.size() && cpu.try_read_memory(address + readable, bytes.data() + readable, 1))
            {
                ++readable;
            }
            const disassembler decoder{};
            const auto decoded =
                decoder.disassemble(cpu, cpu.reg<uint16_t>(x86_register::cs), std::span(bytes).first(readable), 1, address);
            return decoded.empty() ? 1 : static_cast<size_t>(decoded[0].size);
        }

        uint64_t mix_position(uint64_t position)
        {
            position += 0x9E3779B97F4A7C15;
            position = (position ^ (position >> 30)) * 0xBF58476D1CE4E5B9;
            position = (position ^ (position >> 27)) * 0x94D049BB133111EB;
            return position ^ (position >> 31);
        }

        // TTD's CPUID hides RDRAND (cpuid_override), yet the backend runs RDRAND and RDSEED for a guest that executes
        // them anyway, and Unicorn's helper returns host randomness outside MSVC builds (a constant in them). Recordings
        // and replays run them here instead, before the backend does: the result derives from the position, with the
        // flags of a successful call. Both only exist with a register operand (0F C7 /6 and /7); with a LOCK or REP
        // prefix the backend raises #UD.
        void run_random_instruction(windows_emulator& emu, const uint64_t address, const std::span<const uint8_t> instruction)
        {
            constexpr std::array<uint8_t, 6> segment_prefixes{0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65};
            size_t offset = 0;
            size_t operand_size = 4;
            for (; offset < instruction.size(); ++offset)
            {
                if (instruction[offset] == 0x66)
                {
                    operand_size = 2;
                }
                else if (std::ranges::find(segment_prefixes, instruction[offset]) == segment_prefixes.end())
                {
                    break;
                }
            }
            uint8_t rex = 0;
            if (offset < instruction.size() && (instruction[offset] & 0xF0) == 0x40)
            {
                rex = instruction[offset++];
            }
            if (instruction.size() - offset != 3 || instruction[offset] != 0x0F || instruction[offset + 1] != 0xC7)
            {
                return;
            }
            const auto modrm = instruction[offset + 2];
            const auto operation = (modrm >> 3) & 7;
            if ((modrm >> 6) != 3 || (operation != 6 && operation != 7))
            {
                return;
            }

            constexpr std::array registers{x86_register::rax, x86_register::rcx, x86_register::rdx, x86_register::rbx,
                                           x86_register::rsp, x86_register::rbp, x86_register::rsi, x86_register::rdi,
                                           x86_register::r8,  x86_register::r9,  x86_register::r10, x86_register::r11,
                                           x86_register::r12, x86_register::r13, x86_register::r14, x86_register::r15};
            const auto destination = registers[(modrm & 7) | ((rex & 1) << 3)];
            if (rex & 8)
            {
                operand_size = 8;
            }

            auto& cpu = emu.emu();
            const auto value = mix_position(emu.get_executed_instructions());
            auto result = value;
            if (operand_size == 4)
            {
                result = static_cast<uint32_t>(value);
            }
            else if (operand_size == 2)
            {
                result = (cpu.reg<uint64_t>(destination) & ~0xFFFFULL) | (value & 0xFFFF);
            }
            cpu.reg<uint64_t>(destination, result);

            constexpr uint32_t carry_flag = 0x1;
            constexpr uint32_t status_flags = 0x8D5;
            cpu.reg<uint32_t>(x86_register::eflags, (cpu.reg<uint32_t>(x86_register::eflags) & ~status_flags) | carry_flag);
            cpu.reg<uint64_t>(x86_register::rip, address + instruction.size());
        }

        void run_random_instruction(windows_emulator& emu, const uint64_t address, const size_t size)
        {
            std::array<uint8_t, max_instruction_size> instruction{};
            const auto length = std::min(size, instruction.size());
            if (emu.emu().try_read_memory(address, instruction.data(), length))
            {
                run_random_instruction(emu, address, std::span(instruction).first(length));
            }
        }

        template <typename T>
        std::optional<PEDirectory_t2> read_export_directory(const memory_manager& memory, const uint64_t base, const uint64_t offset)
        {
            PENTHeaders_t<T> headers{};
            if (!memory.try_read_memory(base + offset, &headers, sizeof(headers)) ||
                headers.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
            {
                return std::nullopt;
            }
            return headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }

        // The export directory of a mapped image, which holds the forwarder strings of its forwarded exports.
        std::optional<PEDirectory_t2> export_directory(const memory_manager& memory, const mapped_module& mod)
        {
            PEDosHeader_t dos{};
            uint16_t magic{};
            const auto magic_offset = sizeof(uint32_t) + sizeof(PEFileHeader_t);
            if (!memory.try_read_memory(mod.image_base, &dos, sizeof(dos)) ||
                !memory.try_read_memory(mod.image_base + dos.e_lfanew + magic_offset, &magic, sizeof(magic)))
            {
                return std::nullopt;
            }
            if (magic == PEOptionalHeader_t<uint64_t>::k_Magic)
            {
                return read_export_directory<uint64_t>(memory, mod.image_base, dos.e_lfanew);
            }
            if (magic == PEOptionalHeader_t<uint32_t>::k_Magic)
            {
                return read_export_directory<uint32_t>(memory, mod.image_base, dos.e_lfanew);
            }
            return std::nullopt;
        }

        std::string read_c_string(const memory_manager& memory, const uint64_t address, const uint64_t end)
        {
            std::string text{};
            char c{};
            while (address + text.size() < end && memory.try_read_memory(address + text.size(), &c, 1) && c)
            {
                text.push_back(c);
            }
            return text;
        }

        // "MODULE.name" or "MODULE.#ordinal" as "module.dll!name", with an API set name resolved to its host module.
        std::string resolve_forwarder(const std::string_view forwarder, const apiset_map& apiset)
        {
            const auto dot = forwarder.rfind('.');
            if (dot == std::string_view::npos || dot == 0 || dot + 1 == forwarder.size())
            {
                return std::string(forwarder);
            }
            std::u16string module_name{};
            for (const auto c : forwarder.substr(0, dot))
            {
                module_name.push_back(static_cast<char16_t>(std::tolower(static_cast<unsigned char>(c))));
            }
            module_name += u".dll";
            if (module_name.starts_with(u"api-") || module_name.starts_with(u"ext-"))
            {
                auto host = apiset.find(module_name);
                if (host == apiset.end())
                {
                    // The loader ignores the last version number: "-l1-1-0" also finds the contract the schema lists as
                    // "-l1-1-1".
                    const auto prefix = module_name.substr(0, module_name.rfind(u'-') + 1);
                    host = apiset.lower_bound(prefix);
                    if (host != apiset.end() && !host->first.starts_with(prefix))
                    {
                        host = apiset.end();
                    }
                }
                if (host != apiset.end() && !host->second.empty())
                {
                    module_name = host->second;
                }
            }
            for (auto& c : module_name)
            {
                c = static_cast<char16_t>(c < 0x80 ? std::tolower(static_cast<int>(c)) : c);
            }
            return u16_to_u8(module_name) + "!" + std::string(forwarder.substr(dot + 1));
        }

        // A checkpoint delta's zstd reference is its base state followed by the bulk blocks recorded in between. This
        // returns that concatenation, or nothing when those blocks are empty and the base state alone is the reference.
        std::vector<std::byte> extended_reference(const std::span<const std::byte> base, const std::span<const bulk_block> between)
        {
            size_t bulk_size = 0;
            for (const auto& block : between)
            {
                bulk_size += block->size();
            }
            if (!bulk_size)
            {
                return {};
            }
            std::vector<std::byte> reference{};
            reference.reserve(base.size() + bulk_size);
            reference.insert(reference.end(), base.begin(), base.end());
            for (const auto& block : between)
            {
                reference.insert(reference.end(), block->begin(), block->end());
            }
            return reference;
        }

        void describe_event(std::ostream& stream, const access_event& event)
        {
            stream << access_kind_name(event.kind) << " step=" << std::hex << event.step << " ip=" << event.ip
                   << " address=" << event.address << std::dec << " size=" << event.size;
        }

        template <typename T>
        void write_object(std::ostream& stream, const T& object)
        {
            stream.write(reinterpret_cast<const char*>(&object), sizeof(object));
            if (!stream)
            {
                throw std::runtime_error("TTD trace write failed");
            }
        }

        template <typename T>
        std::span<const std::byte> bytes_of(const std::vector<T>& values)
        {
            return std::as_bytes(std::span(values));
        }

        constexpr auto writes_required = "TTD replay scans require a trace recorded with write events";

        // 128 random bits as 32 hex digits: the recording's trace::id().
        std::string random_trace_id()
        {
            std::random_device source{};
            std::ostringstream id{};
            id << std::hex << std::setfill('0');
            for (int i = 0; i < 4; ++i)
            {
                id << std::setw(8) << static_cast<uint32_t>(source());
            }
            return id.str();
        }

        uint64_t last_byte(const uint64_t address, const uint64_t size)
        {
            return address + std::min<uint64_t>(size - 1, UINT64_MAX - address);
        }

        constexpr uint64_t max_manifest_size = 1024 * 1024;

        std::vector<std::byte> encode_manifest(const manifest_entries& manifest)
        {
            std::vector<std::byte> encoded{};
            const auto append = [&](const void* data, const size_t size) {
                const auto* bytes = static_cast<const std::byte*>(data);
                encoded.insert(encoded.end(), bytes, bytes + size);
            };
            for (const auto& [key, value] : manifest)
            {
                const auto key_size = static_cast<uint32_t>(key.size());
                const auto value_size = static_cast<uint32_t>(value.size());
                append(&key_size, sizeof(key_size));
                append(&value_size, sizeof(value_size));
                append(key.data(), key.size());
                append(value.data(), value.size());
            }
            if (encoded.size() > max_manifest_size)
            {
                throw std::invalid_argument("TTD manifest exceeds 1 MiB");
            }
            return encoded;
        }
    }

    recorder::recorder(windows_emulator& emu, const std::filesystem::path& path, const uint64_t access_mask, manifest_entries manifest)
        : emu_(emu),
          path_(path),
          file_(path, std::ios::binary | std::ios::trunc),
          manifest_(std::move(manifest))
    {
        // Every recording gets its own id, also one forked from a replay of another.
        std::erase_if(manifest_, [](const auto& entry) { return entry.first == trace_id_key; });
        manifest_.emplace_back(trace_id_key, random_trace_id());
        encode_manifest(manifest_);
        if (!(access_mask & all_access_kinds))
        {
            throw std::invalid_argument("A TTD recording needs at least one access kind");
        }
        if (!file_)
        {
            throw std::runtime_error("Cannot create TTD trace: " + path.string());
        }
        header_.access_mask = access_mask & all_access_kinds;
        write_object(file_, header_);
        chunk_events_.reserve(events_per_chunk);
        recent_page_of_kind_.fill(no_recent_page);
        tracks_instructions_ = (access_mask & static_cast<uint64_t>(access_kind::execute)) != 0;
        constexpr auto code_changes = static_cast<uint64_t>(access_kind::execute) | static_cast<uint64_t>(access_kind::write) |
                                      static_cast<uint64_t>(access_kind::host_write);
        caches_instructions_ = (access_mask & code_changes) == code_changes;

        // This also makes the initial process/thread state explicit in the snapshot.
        emu_.setup_process_if_necessary();
        instruction_ip_ = emu_.emu().read_instruction_pointer();
        write_checkpoint(emu_.get_executed_instructions());

        auto& cpu = emu_.emu();
        if (access_mask & static_cast<uint64_t>(access_kind::write))
        {
            write_hook_ = scoped_hook(
                cpu, cpu.hook_memory_write_data(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, std::span<const std::byte> data) {
                    append_data_event(access_kind::write, address, data);
                }));
        }
        if (access_mask & static_cast<uint64_t>(access_kind::read))
        {
            read_hook_ = scoped_hook(
                cpu, cpu.hook_memory_read_data(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, std::span<const std::byte> data) {
                    append_data_event(access_kind::read, address, data);
                }));
        }
        // Without execute events, instructions are still looked at for RDRAND and RDSEED.
        const auto record_execute = [this](const uint64_t address, const size_t size) {
            const auto length = executed_size(emu_, address, size);
            if (!tracks_instructions_)
            {
                run_random_instruction(emu_, address, length);
                return;
            }
            const auto instruction = append_event(access_kind::execute, address, length);
            run_random_instruction(emu_, address, std::span(instruction).first(std::min(length, instruction.size())));
        };
        // With instruction precision the emulator already handles every instruction; its callback saves the backend a
        // second hook call per instruction.
        if (emu_.uses_instruction_precision())
        {
            instruction_callback_ = instruction_callback(emu_.callbacks.on_instruction_executed, record_execute);
        }
        else
        {
            execute_hook_ = scoped_hook(
                cpu, cpu.hook_memory_execution_metadata(
                         [record_execute](cpu_interface&, const uint64_t address, const size_t size) { record_execute(address, size); }));
        }
        if (access_mask & static_cast<uint64_t>(access_kind::host_write))
        {
            host_write_hook_ =
                scoped_hook(cpu, cpu.hook_host_memory_write([this](cpu_interface&, uint64_t address, std::span<const std::byte> data) {
                    append_data_event(access_kind::host_write, address, data);
                }));
        }
        snapshots_registers_ = header_.access_mask == all_access_kinds && cpu.get_register_generation().has_value();
        if (snapshots_registers_)
        {
            // Within a translated block the backend may keep part of the CPU state (such as how to compute the flags)
            // outside the registers it saves, so snapshots are only taken where a block starts.
            block_hook_ = scoped_hook(cpu, cpu.hook_basic_block([this](cpu_interface&, const basic_block&) { at_block_start_ = true; }));
        }
        // The memory map at the start; its changes follow from the callback below.
        note_memory_regions(0, MAX_ALLOCATION_END_EXCL, true);
        // Last, so a constructor that throws never leaves a callback behind.
        emu_.memory.set_mapping_change_callback([this](const uint64_t address, const size_t size) {
            mapping_changes_.push_back(
                {.step = emu_.get_executed_instructions(), .event_number = header_.event_count, .address = address, .size = size});
            forget_instructions(address, size);
        });
        emu_.memory.set_region_change_callback(
            [this](const uint64_t address, const size_t size) { note_memory_regions(address, size, false); });
        ui_ = dynamic_cast<recordable_ui_backend*>(&emu_.ui());
        if (ui_)
        {
            ui_->start_recording([this](const ui_event& event) {
                ui_inputs_.push_back({.checkpoint = checkpoints_.size() - 1,
                                      .event_number = header_.event_count,
                                      .step = emu_.get_executed_instructions(),
                                      .window = static_cast<uint64_t>(event.window),
                                      .message = event.message,
                                      .wparam = event.wParam,
                                      .lparam = event.lParam});
            });
        }
        syscall_enter_ = syscall_callback(emu_.callbacks.on_syscall_enter, [this](uint32_t) {
            open_syscall_ = syscall_entry{.step = emu_.get_executed_instructions(), .event_number = header_.event_count};
        });
        syscall_exit_ = syscall_callback(emu_.callbacks.on_syscall_exit, [this](const uint32_t id) { close_syscall(id); });

        for (const auto& mod : emu_.mod_manager.modules() | std::views::values)
        {
            add_module(mod);
        }
        module_load_ = module_callback(emu_.callbacks.on_module_load, [this](const mapped_module& mod) { add_module(mod); });
        module_unload_ = module_callback(emu_.callbacks.on_module_unload, [this](const mapped_module& mod) {
            const auto loaded = loaded_modules_.find(mod.image_base);
            if (loaded == loaded_modules_.end())
            {
                return;
            }
            auto& entry = modules_[loaded->second];
            entry.unload_step = emu_.get_executed_instructions();
            entry.unload_event_number = header_.event_count;
            loaded_modules_.erase(loaded);
        });
    }

    void recorder::add_module(const mapped_module& mod)
    {
        auto exports = std::make_shared<std::vector<module_export>>();
        exports->reserve(mod.exports.size());
        const auto directory = export_directory(emu_.memory, mod);
        for (const auto& symbol : mod.exports)
        {
            auto& entry = exports->emplace_back(module_export{.rva = symbol.rva, .ordinal = symbol.ordinal, .name = symbol.name});
            if (directory && symbol.rva - directory->VirtualAddress < directory->Size)
            {
                const auto end = mod.image_base + directory->VirtualAddress + directory->Size;
                entry.forwarder = resolve_forwarder(read_c_string(emu_.memory, mod.image_base + symbol.rva, end), emu_.process.apiset);
            }
        }
        std::ranges::sort(*exports, {}, [](const module_export& symbol) { return std::tie(symbol.rva, symbol.name); });
        loaded_modules_[mod.image_base] = modules_.size();
        modules_.push_back({.base = mod.image_base,
                            .size = mod.size_of_image,
                            .load_step = emu_.get_executed_instructions(),
                            .load_event_number = header_.event_count,
                            .name = mod.name,
                            .path = mod.module_path.string(),
                            .exports = std::move(exports),
                            .machine = mod.machine});
    }

    void recorder::note_thread(const access_event& event)
    {
        const auto* thread = emu_.vcpu(0).active_thread;
        if (!thread || running_thread_ == thread->id)
        {
            return;
        }
        running_thread_ = thread->id;
        // The event is already counted.
        threads_.switches.push_back({.step = event.step, .event_number = header_.event_count - 1, .thread_id = thread->id});
        threads_.names[thread->id] = u16_to_u8(thread->name);
        if (std::ranges::find(thread_stacks_, thread->id, &thread_stack::thread_id) == thread_stacks_.end())
        {
            note_thread_stack(*thread, event);
        }
    }

    void recorder::note_memory_regions(const uint64_t address, const uint64_t size, const bool initial)
    {
        constexpr uint32_t mem_commit = 0x1000;
        constexpr uint32_t mem_reserve = 0x2000;
        constexpr uint32_t mem_free = 0x10000;
        constexpr uint32_t page_guard = 0x100;
        const auto protection_of = [](const nt_memory_permission permission) {
            return map_emulator_to_nt_protection(permission.common) | (permission.is_guarded() ? page_guard : 0);
        };

        const auto step = emu_.get_executed_instructions();
        auto cursor = address & ~(page_size - 1);
        const auto end = address + size;
        while (cursor < end)
        {
            const auto info = emu_.memory.get_region_info(cursor);
            const auto region_end = std::min<uint64_t>(info.start + info.length, end);
            if (region_end <= cursor)
            {
                break;
            }

            memory_region region{.step = step, .event_number = header_.event_count, .address = cursor, .size = region_end - cursor};
            if (info.is_reserved)
            {
                region.allocation_base = info.allocation_base;
                region.allocation_protection = protection_of(info.initial_permissions);
                region.state = info.is_committed ? mem_commit : mem_reserve;
                region.type = memory_region_policy::to_memory_basic_information_type(info.kind);
                region.protection = info.is_committed ? protection_of(info.permissions) : 0;
                region.kind = static_cast<uint32_t>(info.kind);
                if (const auto file = emu_.memory.get_region_mapped_filename(cursor))
                {
                    const auto name = u16_to_u8(*file);
                    const auto known = memory_region_names_.try_emplace(name, static_cast<uint32_t>(memory_regions_.names.size()));
                    if (known.second)
                    {
                        memory_regions_.names.push_back(name);
                    }
                    region.name = known.first->second;
                }
            }
            else
            {
                region.state = mem_free;
            }

            // At the start, free memory is what is not listed.
            if (!initial || info.is_reserved)
            {
                memory_regions_.regions.push_back(region);
            }
            cursor = region_end;
        }
    }

    void recorder::note_thread_stack(const emulator_thread& thread, const access_event& event)
    {
        thread_stack stack{.thread_id = thread.id, .step = event.step, .event_number = header_.event_count - 1};
        // Read as the guest sees them (the TEB, not the emulator's bookkeeping), without recording the reads.
        if (thread.teb64)
        {
            const auto teb = thread.teb64->read();
            stack.teb = thread.teb64->value();
            stack.stack_base = teb.NtTib.StackBase;
            stack.stack_limit = teb.NtTib.StackLimit;
        }
        if (thread.teb32)
        {
            const auto teb = thread.teb32->read();
            stack.teb32 = thread.teb32->value();
            stack.stack32_base = teb.NtTib.StackBase;
            stack.stack32_limit = teb.NtTib.StackLimit;
        }
        thread_stacks_.push_back(stack);
    }

    void recorder::close_syscall(const uint32_t id)
    {
        if (!open_syscall_)
        {
            return;
        }
        auto entry = *open_syscall_;
        open_syscall_.reset();
        entry.id = id;
        entry.event_count = header_.event_count - entry.event_number;
        entry.result = emu_.emu().reg<uint64_t>(x86_register::rax);
        if (!syscalls_.names.contains(id))
        {
            try
            {
                syscalls_.names[id] = emu_.dispatcher.get_syscall_name(id);
            }
            catch (const std::out_of_range&)
            {
                // An unknown syscall: the emulator stops at it.
            }
        }
        syscalls_.entries.push_back(entry);
    }

    recorder::~recorder()
    {
        try
        {
            finish();
        }
        catch (const std::exception& e)
        {
            emu_.log.error("TTD trace %s was not finalized: %s\n", path_.string().c_str(), e.what());
        }
        catch (...)
        {
            emu_.log.error("TTD trace %s was not finalized\n", path_.string().c_str());
        }
    }

    std::array<uint8_t, inline_data_limit> recorder::append_event(access_kind kind, uint64_t address, size_t size)
    {
        if (!size)
        {
            return {};
        }
        // The backend reports an instruction before running it, with the instruction pointer at its address.
        instruction_ip_ = address;
        access_event event{.step = emu_.get_executed_instructions(), .ip = address, .address = address, .size = size, .kind = kind};
        if (snapshots_registers_)
        {
            // Anything but a guest instruction that changed registers or memory ends the snapshot interval right away.
            // Those changes come from backend helpers (syscalls, CPUID, RDTSC) that bring the CPU state up to date first,
            // so the snapshot is complete even inside a translated block. A periodic snapshot waits for a block start,
            // where the backend has the whole state in its registers.
            const auto changed = register_snapshots_.empty() || host_changed_memory_ ||
                                 emu_.emu().get_register_generation() != snapshot_register_generation_;
            const auto due = !register_snapshots_.empty() && event.step - 1 - register_snapshots_.back().step >= register_snapshot_interval;
            if (changed || (due && at_block_start_))
            {
                // The instruction is about to run, so the registers are those of the position before it.
                snapshot_registers(event.step - 1);
            }
            at_block_start_ = false;
        }
        if (size < inline_data_limit)
        {
            const auto* cached = caches_instructions_ ? instruction_cache_.find(address) : nullptr;
            if (cached && cached_instructions_[static_cast<size_t>(*cached)].size == size)
            {
                const auto& entry = cached_instructions_[static_cast<size_t>(*cached)];
                event.payload = entry.bytes;
                chunk_code_ids_.push_back(entry.code_id);
            }
            else
            {
                if (!emu_.emu().try_read_memory(address, event.payload.data(), size))
                {
                    throw std::runtime_error("Cannot read executed instruction bytes");
                }
                // Code ids follow the order of first execution across the whole trace.
                const auto code_id = code_.id_of(event);
                chunk_code_ids_.push_back(code_id);
                if (caches_instructions_)
                {
                    instruction_cache_.set(address, cached_instructions_.size());
                    cached_instructions_.push_back({.size = size, .bytes = event.payload, .code_id = code_id});
                    const auto last = last_byte(address, size);
                    for (auto page = address / page_size; page <= last / page_size; ++page)
                    {
                        const auto* list = cached_instructions_by_page_.find(page);
                        if (!list)
                        {
                            cached_instructions_by_page_.set(page, cached_pages_.size());
                            cached_pages_.emplace_back();
                            list = cached_instructions_by_page_.find(page);
                        }
                        cached_pages_[static_cast<size_t>(*list)].push_back(address);
                    }
                }
            }
        }
        else
        {
            chunk_code_ids_.push_back(code_.id_of(event));
        }
        push_event(event);
        return event.payload;
    }

    void recorder::forget_instructions(const uint64_t address, const uint64_t size)
    {
        if (cached_pages_.empty() || !size)
        {
            return;
        }
        const auto last = last_byte(address, size);
        for (auto page = address / page_size; page <= last / page_size; ++page)
        {
            const auto* list = cached_instructions_by_page_.find(page);
            if (!list)
            {
                continue;
            }
            auto& instructions = cached_pages_[static_cast<size_t>(*list)];
            for (const auto instruction : instructions)
            {
                if (const auto* index = instruction_cache_.find(instruction))
                {
                    cached_instructions_[static_cast<size_t>(*index)].size = 0;
                }
            }
            instructions.clear();
        }
    }

    void recorder::append_data_event(access_kind kind, uint64_t address, std::span<const std::byte> data)
    {
        if (data.empty())
        {
            return;
        }
        // A guest access belongs to the instruction the execute hook just reported. Host writes happen outside guest
        // instructions (syscalls, exception dispatch), where the instruction pointer can differ.
        const auto ip = kind != access_kind::host_write && tracks_instructions_ ? instruction_ip_ : emu_.emu().read_instruction_pointer();
        if (kind != access_kind::read)
        {
            forget_instructions(address, data.size());
        }
        host_changed_memory_ |= kind == access_kind::host_write;
        access_event event{.step = emu_.get_executed_instructions(), .ip = ip, .address = address, .size = data.size(), .kind = kind};
        if (data.size() <= inline_data_limit)
        {
            memcpy(event.payload.data(), data.data(), data.size());
        }
        else
        {
            const uint64_t offset = current_bulk_->size();
            const uint64_t block = bulk_table_.size();
            current_bulk_->insert(current_bulk_->end(), data.begin(), data.end());
            memcpy(event.payload.data(), &offset, sizeof(offset));
            memcpy(event.payload.data() + sizeof(offset), &block, sizeof(block));
        }
        push_event(event);
    }

    void recorder::snapshot_registers(const uint64_t position)
    {
        host_changed_memory_ = false;
        snapshot_register_generation_ = emu_.emu().get_register_generation();
        auto registers = std::make_shared<const std::vector<std::byte>>(emu_.emu().save_registers());
        const auto index = static_cast<uint64_t>(register_snapshots_.size());
        register_snapshot_entry entry{.step = position, .event_number = header_.event_count};
        if (index % register_snapshots_per_base == 0)
        {
            register_base_ = registers;
            register_compressor_.submit_job(index, [registers] { return utils::compression::zstd::compress(*registers, 3); });
        }
        else
        {
            entry.base = index - index % register_snapshots_per_base;
            register_compressor_.submit_job(
                index, [registers, base = register_base_] { return utils::compression::zstd::compress_with_reference(*registers, *base); });
        }
        register_snapshots_.push_back(entry);
    }

    void recorder::push_event(const access_event& event)
    {
        chunk_events_.push_back(event);
        ++header_.event_count;
        // A thread's first instruction after a switch marks the switch; without execute events, any event does.
        if (event.kind == access_kind::execute || !tracks_instructions_)
        {
            note_thread(event);
        }
        const auto first_page = event.address / page_size;
        const auto last_page = last_byte(event.address, event.size) / page_size;
        auto& recent_page = recent_page_of_kind_[static_cast<size_t>(event.kind)];
        if (first_page != last_page || recent_page != first_page)
        {
            for (auto page = first_page; page <= last_page; ++page)
            {
                const auto* kinds = chunk_pages_.find(page);
                if (!kinds)
                {
                    chunk_page_list_.push_back(page);
                }
                chunk_pages_.set(page, (kinds ? *kinds : 0) | static_cast<uint64_t>(event.kind));
            }
            recent_page = first_page == last_page ? first_page : no_recent_page;
        }
        if (chunk_events_.size() == events_per_chunk)
        {
            flush_chunk();
        }
    }

    void recorder::flush_chunk()
    {
        if (chunk_events_.empty())
        {
            return;
        }
        // The execute events' code ids were assigned as they were recorded; the rest of the encoding runs on a worker.
        // The chunk's large accesses are the tail of the open bulk block, copied because the block keeps growing.
        auto code_ids = std::move(chunk_code_ids_);
        chunk_code_ids_ = {};
        chunk_code_ids_.reserve(code_ids.size());
        chunk_bulk_bytes bulk{.block = bulk_table_.size(), .offset = chunk_bulk_start_};
        if (current_bulk_->size() > chunk_bulk_start_)
        {
            bulk.bytes = std::make_shared<const std::vector<std::byte>>(current_bulk_->begin() + static_cast<ptrdiff_t>(chunk_bulk_start_),
                                                                        current_bulk_->end());
        }
        chunk_bulk_start_ = current_bulk_->size();

        const auto index = static_cast<uint32_t>(chunks_.size());
        chunks_.push_back({.first_event = header_.event_count - chunk_events_.size(),
                           .event_count = chunk_events_.size(),
                           .first_step = chunk_events_.front().step,
                           .last_step = chunk_events_.back().step});
        for (const auto page : chunk_page_list_)
        {
            pages_.push_back({.page = page, .chunk = index, .kinds = static_cast<uint32_t>(*chunk_pages_.find(page))});
        }
        // The next chunk fills an allocation an earlier chunk's encoding released, if there is one: a fresh one costs a page
        // fault per page as it fills.
        std::vector<access_event> next_events{};
        {
            const std::lock_guard lock{event_pool_->mutex};
            if (!event_pool_->free.empty())
            {
                next_events = std::move(event_pool_->free.back());
                event_pool_->free.pop_back();
            }
        }
        next_events.clear();
        next_events.reserve(events_per_chunk);
        auto owned = std::make_unique<std::vector<access_event>>(std::move(chunk_events_));
        const std::shared_ptr<const std::vector<access_event>> events(owned.release(),
                                                                      [pool = event_pool_](std::vector<access_event>* released) {
                                                                          const std::unique_ptr<std::vector<access_event>> freed(released);
                                                                          const std::lock_guard lock{pool->mutex};
                                                                          if (pool->free.size() < chunk_workers + 2)
                                                                          {
                                                                              pool->free.push_back(std::move(*freed));
                                                                          }
                                                                      });
        chunk_events_ = std::move(next_events);
        chunk_pages_.clear();
        chunk_page_list_.clear();
        recent_page_of_kind_.fill(no_recent_page);
        chunk_compressor_.submit_job(index, [events, code_ids = std::move(code_ids), bulk = std::move(bulk)] {
            return utils::compression::zstd::compress(encode_chunk(*events, code_ids, bulk), chunk_compression_level);
        });
        write_compressed(false);
    }

    void recorder::close_bulk_block()
    {
        if (!current_bulk_->empty())
        {
            bulk_compressor_.submit(bulk_table_.size(), current_bulk_);
        }
        bulk_table_.push_back({});
        recent_bulk_.push_back(std::move(current_bulk_));
        if (recent_bulk_.size() > bulk_reference_span)
        {
            recent_bulk_.pop_front();
        }
        current_bulk_ = std::make_shared<std::vector<std::byte>>();
        chunk_bulk_start_ = 0;
        write_compressed(false);
    }

    void recorder::write_compressed(const bool wait)
    {
        for (const auto& [index, compressed] : chunk_compressor_.take_finished(wait))
        {
            if (compressed.empty())
            {
                throw std::runtime_error("Cannot compress TTD event chunk");
            }
            auto& entry = chunks_.at(static_cast<size_t>(index));
            entry.offset = append_to_file(compressed);
            entry.size = compressed.size();
        }
        for (const auto& [index, compressed] : bulk_compressor_.take_finished(wait))
        {
            if (compressed.empty())
            {
                throw std::runtime_error("Cannot compress TTD bulk data");
            }
            bulk_table_.at(static_cast<size_t>(index)) = {.offset = append_to_file(compressed), .size = compressed.size()};
        }
        for (const auto& [index, compressed] : checkpoint_compressor_.take_finished(wait))
        {
            if (compressed.empty())
            {
                throw std::runtime_error("Cannot compress TTD checkpoint");
            }
            auto& entry = checkpoints_.at(static_cast<size_t>(index));
            entry.offset = append_to_file(compressed);
            entry.size = compressed.size();
        }
        for (const auto& [index, compressed] : register_compressor_.take_finished(wait))
        {
            if (compressed.empty())
            {
                throw std::runtime_error("Cannot compress TTD register snapshot");
            }
            auto& entry = register_snapshots_.at(static_cast<size_t>(index));
            entry.offset = append_to_file(compressed);
            entry.size = compressed.size();
        }
    }

    void recorder::write_checkpoint(const uint64_t step)
    {
        // A little headroom over the previous state covers ordinary growth without a reallocation.
        const auto expected_size = base_states_.empty() ? 0 : base_states_.front()->size() + base_states_.front()->size() / 16;
        std::vector<std::byte> storage{};
        {
            const std::lock_guard lock{state_pool_->mutex};
            if (!state_pool_->free.empty())
            {
                storage = std::move(state_pool_->free.back());
                state_pool_->free.pop_back();
            }
        }
        // A released state returns its allocation to the pool, which keeps a couple.
        constexpr size_t kept_allocations = 2;
        size_t memory_offset{};
        auto owned = std::make_unique<std::vector<std::byte>>(
            snapshot::create_emulator_state(emu_, expected_size, std::move(storage), memory_offset));
        checkpoint_memory_offsets_.push_back(memory_offset);
        const std::shared_ptr<const std::vector<std::byte>> state(owned.release(), [pool = state_pool_](std::vector<std::byte>* released) {
            const std::unique_ptr<std::vector<std::byte>> freed(released);
            const std::lock_guard lock{pool->mutex};
            if (pool->free.size() < kept_allocations)
            {
                pool->free.push_back(std::move(*freed));
            }
        });
        const auto index = static_cast<uint64_t>(checkpoints_.size());
        if (!index)
        {
            checkpoints_.push_back({.step = step});
            checkpoint_compressor_.submit_job(index,
                                              [state] { return utils::compression::zstd::compress(*state, checkpoint_compression_level); });
            base_states_.assign(checkpoint_levels, state);
            write_compressed(false);
            return;
        }

        // Checkpoint i is a delta against i - p, where p is the largest power of checkpoints_per_level dividing i, so
        // restoring any checkpoint applies fewer than checkpoints_per_level deltas per level.
        size_t level = 0;
        uint64_t distance = 1;
        while (level + 1 < checkpoint_levels && index % (distance * checkpoints_per_level) == 0)
        {
            ++level;
            distance *= checkpoints_per_level;
        }
        std::vector<bulk_block> between{};
        if (distance <= bulk_reference_span)
        {
            between.assign(recent_bulk_.end() - static_cast<ptrdiff_t>(distance), recent_bulk_.end());
        }
        checkpoints_.push_back({.step = step, .base = index - distance});
        checkpoint_compressor_.submit_job(index, [state, base = base_states_[level], between = std::move(between)] {
            const auto extended = extended_reference(*base, between);
            return utils::compression::zstd::compress_with_reference(*state, extended.empty() ? std::span(*base) : std::span(extended));
        });
        std::fill_n(base_states_.begin(), level + 1, state);
        write_compressed(false);
    }

    uint64_t recorder::append_to_file(const std::span<const std::byte> bytes)
    {
        const auto offset = static_cast<uint64_t>(file_.tellp());
        file_.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!file_)
        {
            throw std::runtime_error("TTD trace write failed");
        }
        return offset;
    }

    void recorder::checkpoint()
    {
        if (finished_)
        {
            throw std::runtime_error("Cannot checkpoint a finished TTD trace");
        }
        const auto step = emu_.get_executed_instructions();
        if (step <= checkpoints_.back().step)
        {
            throw std::runtime_error("TTD checkpoints must have increasing instruction positions");
        }
        flush_chunk();
        close_bulk_block();
        write_checkpoint(step);
    }

    void recorder::finish()
    {
        if (finished_)
        {
            return;
        }
        finished_ = true;
        syscall_enter_.reset();
        syscall_exit_.reset();
        module_load_.reset();
        module_unload_.reset();
        // Names given after a thread's last switch.
        for (const auto& thread : emu_.process.threads | std::views::values)
        {
            if (threads_.names.contains(thread.id))
            {
                threads_.names[thread.id] = u16_to_u8(thread.name);
            }
        }
        write_hook_.remove();
        read_hook_.remove();
        execute_hook_.remove();
        instruction_callback_.reset();
        host_write_hook_.remove();
        block_hook_.remove();
        emu_.memory.set_mapping_change_callback({});
        emu_.memory.set_region_change_callback({});
        if (ui_)
        {
            ui_->stop();
        }
        // The registers at the end, where no further instruction takes a snapshot.
        if (snapshots_registers_ && (register_snapshots_.empty() || register_snapshots_.back().step < emu_.get_executed_instructions()))
        {
            snapshot_registers(emu_.get_executed_instructions());
        }
        flush_chunk();
        close_bulk_block();
        write_compressed(true);
        register_base_.reset();
        base_states_.clear();
        recent_bulk_.clear();
        header_.instruction_count = emu_.get_executed_instructions();

        std::ranges::sort(
            pages_, [](const page_entry& a, const page_entry& b) { return a.page < b.page || (a.page == b.page && a.chunk < b.chunk); });
        std::vector<page_block> page_blocks{};
        for (size_t first = 0; first < pages_.size(); first += page_block_entries)
        {
            const auto entries = std::span(pages_).subspan(first, std::min<size_t>(page_block_entries, pages_.size() - first));
            const auto encoded = encode_page_block(entries);
            page_blocks.push_back({.first_page = entries.front().page,
                                   .entry_count = entries.size(),
                                   .offset = append_to_file(encoded),
                                   .size = encoded.size()});
        }
        pages_ = {};
        const auto code = utils::compression::zstd::compress(bytes_of(code_.entries()), code_table_compression_level);
        if (code.empty())
        {
            throw std::runtime_error("Cannot compress TTD code table");
        }
        const auto manifest = encode_manifest(manifest_);
        const auto syscalls = encode_syscalls(syscalls_);
        const auto modules = encode_modules(modules_);
        const auto threads = encode_threads(threads_);
        const auto exports = encode_exports(modules_);
        const auto forwarders = encode_export_forwarders(modules_);
        const auto snapshots = encode_register_snapshots(register_snapshots_);
        const auto mappings = encode_mapping_changes(mapping_changes_);
        const auto machines = encode_module_machines(modules_);
        const auto stacks = encode_thread_stacks(thread_stacks_);
        const auto regions = encode_memory_regions(memory_regions_);
        const auto memory_offsets = encode_checkpoint_memory_offsets(checkpoint_memory_offsets_);
        const std::array sections{
            section_entry{.type = section_type::chunk_table, .offset = append_to_file(bytes_of(chunks_)), .size = chunks_.size()},
            section_entry{
                .type = section_type::checkpoint_table, .offset = append_to_file(bytes_of(checkpoints_)), .size = checkpoints_.size()},
            section_entry{.type = section_type::page_index, .offset = append_to_file(bytes_of(page_blocks)), .size = page_blocks.size()},
            section_entry{.type = section_type::code_table, .offset = append_to_file(code), .size = code.size()},
            section_entry{.type = section_type::bulk_table, .offset = append_to_file(bytes_of(bulk_table_)), .size = bulk_table_.size()},
            section_entry{.type = section_type::manifest, .offset = append_to_file(manifest), .size = manifest.size()},
            section_entry{.type = section_type::ui_inputs, .offset = append_to_file(bytes_of(ui_inputs_)), .size = ui_inputs_.size()},
            section_entry{.type = section_type::syscalls, .offset = append_to_file(syscalls), .size = syscalls.size()},
            section_entry{.type = section_type::modules, .offset = append_to_file(modules), .size = modules.size()},
            section_entry{.type = section_type::threads, .offset = append_to_file(threads), .size = threads.size()},
            section_entry{.type = section_type::exports, .offset = append_to_file(exports), .size = exports.size()},
            section_entry{.type = section_type::export_forwarders, .offset = append_to_file(forwarders), .size = forwarders.size()},
            section_entry{.type = section_type::register_snapshots, .offset = append_to_file(snapshots), .size = snapshots.size()},
            section_entry{.type = section_type::mapping_changes, .offset = append_to_file(mappings), .size = mappings.size()},
            section_entry{.type = section_type::module_machines, .offset = append_to_file(machines), .size = machines.size()},
            section_entry{.type = section_type::thread_stacks, .offset = append_to_file(stacks), .size = stacks.size()},
            section_entry{.type = section_type::memory_regions, .offset = append_to_file(regions), .size = regions.size()},
            section_entry{.type = section_type::checkpoint_memory, .offset = append_to_file(memory_offsets), .size = memory_offsets.size()},
        };
        header_.section_count = sections.size();
        header_.section_table_offset = append_to_file(std::as_bytes(std::span(sections)));
        file_.seekp(0);
        write_object(file_, header_);
        file_.flush();
        if (!file_)
        {
            throw std::runtime_error("Cannot finalize TTD trace");
        }
    }

    replay_verifier::replay_verifier(windows_emulator& emu, trace& recorded, const uint64_t from_step, const bool strict)
        : emu_(emu),
          trace_(recorded),
          first_number_(recorded.first_event_after(from_step)),
          reader_(recorded, first_number_),
          access_mask_(recorded.access_mask()),
          strict_(strict)
    {
        caches_code_ = recorded.has_mapping_changes() && recorded.has_instruction_bytes();
        const auto changes = recorded.mapping_changes();
        pending_mapping_changes_ = changes.subspan(
            static_cast<size_t>(std::ranges::upper_bound(changes, first_number_, {}, &mapping_change::event_number) - changes.begin()));
        auto& cpu = emu_.emu();
        if (access_mask_ & static_cast<uint64_t>(access_kind::write))
        {
            write_hook_ = scoped_hook(
                cpu, cpu.hook_memory_write_data(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, std::span<const std::byte> data) {
                    verify(access_kind::write, address, data.size(), data);
                }));
        }
        if (access_mask_ & static_cast<uint64_t>(access_kind::read))
        {
            read_hook_ = scoped_hook(
                cpu, cpu.hook_memory_read_data(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, std::span<const std::byte> data) {
                    verify(access_kind::read, address, data.size(), data);
                }));
        }
        // As in the recorder, also without execute events.
        const auto verify_execute = [this](const uint64_t address, const size_t size) {
            const auto length = executed_size(emu_, address, size);
            if (access_mask_ & static_cast<uint64_t>(access_kind::execute))
            {
                verify(access_kind::execute, address, length);
            }
            if (!error_)
            {
                const auto instruction = instruction_bytes(address, length);
                run_random_instruction(emu_, address, std::span(instruction).first(std::min(length, instruction.size())));
            }
        };
        // As in the recorder: with instruction precision, the emulator's own per-instruction callback.
        if (emu_.uses_instruction_precision())
        {
            instruction_callback_ = instruction_callback(emu_.callbacks.on_instruction_executed, verify_execute);
        }
        else
        {
            execute_hook_ = scoped_hook(
                cpu, cpu.hook_memory_execution_metadata(
                         [verify_execute](cpu_interface&, const uint64_t address, const size_t size) { verify_execute(address, size); }));
        }
        if (access_mask_ & static_cast<uint64_t>(access_kind::host_write))
        {
            host_write_hook_ =
                scoped_hook(cpu, cpu.hook_host_memory_write([this](cpu_interface&, uint64_t address, std::span<const std::byte> data) {
                    verify(access_kind::host_write, address, data.size(), data);
                }));
        }
        if (!recorded.has_syscalls())
        {
            return;
        }
        const auto syscalls = recorded.syscalls();
        const auto first = std::ranges::upper_bound(syscalls, from_step, {}, &syscall_entry::step);
        syscalls_ = syscalls.subspan(static_cast<size_t>(first - syscalls.begin()));
        if (access_mask_ & static_cast<uint64_t>(access_kind::host_write))
        {
            host_write_before_hook_ = scoped_hook(cpu, cpu.hook_host_memory_write_before([this](cpu_interface&, const uint64_t address,
                                                                                                const std::span<const std::byte> data) {
                if (!in_syscall_ || substituting_ || error_)
                {
                    return;
                }
                previous_bytes_.resize(data.size());
                if (!emu_.emu().try_read_memory(address, previous_bytes_.data(), previous_bytes_.size()))
                {
                    previous_bytes_.clear();
                }
            }));
        }
        syscall_enter_ = syscall_callback(emu_.callbacks.on_syscall_enter, [this](const uint32_t id) { enter_syscall(id); });
        syscall_exit_ = syscall_callback(emu_.callbacks.on_syscall_exit, [this](uint32_t) { exit_syscall(); });
    }

    void replay_verifier::diverge(const std::string& message)
    {
        error_ = message;
        emu_.stop();
    }

    std::string replay_verifier::syscall_description(const syscall_entry& entry) const
    {
        std::ostringstream description;
        description << "syscall " << trace_.syscall_name(entry.id).value_or("<unknown>") << " (0x" << std::hex << entry.id << ") at step "
                    << entry.step;
        return description.str();
    }

    void replay_verifier::enter_syscall(const uint32_t id)
    {
        if (error_)
        {
            return;
        }
        const auto step = emu_.get_executed_instructions();
        const auto* expected = next_syscall_ < syscalls_.size() ? &syscalls_[next_syscall_] : nullptr;
        if (expected && expected->step == step && expected->event_number == next_event_number() && expected->id == id)
        {
            in_syscall_ = true;
            syscall_events_.clear();
            return;
        }
        std::ostringstream message;
        message << "TTD replay diverged from the recording: dispatched " << syscall_description({.step = step, .id = id}) << ", expected "
                << (expected ? syscall_description(*expected) : "no further syscall");
        diverge(message.str());
    }

    void replay_verifier::exit_syscall()
    {
        if (!in_syscall_)
        {
            return;
        }
        in_syscall_ = false;
        const auto& expected = syscalls_[next_syscall_++];
        if (error_)
        {
            return;
        }
        const auto first_number = next_event_number();
        std::vector<access_event> recorded{};
        recorded.reserve(static_cast<size_t>(expected.event_count));
        for (uint64_t i = 0; i < expected.event_count; ++i)
        {
            const auto event = reader_.next(access_mask_);
            if (!event)
            {
                diverge("TTD trace ends within " + syscall_description(expected));
                return;
            }
            recorded.push_back(*event);
        }

        auto& cpu = emu_.emu();
        const auto result = cpu.reg<uint64_t>(x86_register::rax);
        std::optional<size_t> different_event{};
        for (size_t i = 0; i < std::max(recorded.size(), syscall_events_.size()); ++i)
        {
            if (i >= recorded.size() || i >= syscall_events_.size() ||
                !matches(recorded[i], syscall_events_[i].event, syscall_events_[i].data))
            {
                different_event = i;
                break;
            }
        }
        if (!different_event && result == expected.result)
        {
            verified_events_ += recorded.size();
            return;
        }

        if (strict_)
        {
            std::ostringstream message;
            message << "TTD replay diverged from the recording at event " << first_number + different_event.value_or(recorded.size())
                    << " in " << syscall_description(expected) << ": ";
            if (!different_event)
            {
                message << "it returned 0x" << std::hex << result << ", recorded 0x" << expected.result;
            }
            else if (const auto i = *different_event;
                     i < recorded.size() && i < syscall_events_.size() && matches(recorded[i], syscall_events_[i].event, {}, false))
            {
                describe_event(message, syscall_events_[i].event);
                message << " accessed different data";
            }
            else
            {
                message << "expected ";
                if (i < recorded.size())
                {
                    describe_event(message, recorded[i]);
                }
                else
                {
                    message << "no further event";
                }
                message << ", observed ";
                if (i < syscall_events_.size())
                {
                    describe_event(message, syscall_events_[i].event);
                }
                else
                {
                    message << "no further event";
                }
            }
            diverge(message.str());
            return;
        }

        // The guest gets what the recording gave it: the live host writes are undone, newest first, then the recorded
        // ones are applied in order. The handler's other events are descriptor table reads, which change nothing.
        try
        {
            substituting_ = true;
            const auto restore = utils::finally([this] { substituting_ = false; });
            for (const auto& live : std::views::reverse(syscall_events_))
            {
                if (live.event.kind != access_kind::host_write)
                {
                    continue;
                }
                if (live.previous.size() != live.data.size())
                {
                    std::ostringstream message;
                    message << "TTD replay cannot undo a live host write to " << std::hex << live.event.address << " in "
                            << syscall_description(expected);
                    diverge(message.str());
                    return;
                }
                cpu.write_memory(live.event.address, live.previous.data(), live.previous.size());
            }
            for (const auto& event : recorded)
            {
                if (event.kind == access_kind::host_write)
                {
                    const auto data = trace_.access_data(event);
                    cpu.write_memory(event.address, data.data(), data.size());
                }
            }
            cpu.reg<uint64_t>(x86_register::rax, expected.result);
        }
        catch (const std::exception& e)
        {
            diverge("TTD replay cannot apply the recorded results of " + syscall_description(expected) + ": " + e.what());
            return;
        }
        ++substituted_inputs_;
        verified_events_ += recorded.size();
    }

    bool replay_verifier::matches(const access_event& expected, const access_event& observed, const std::span<const std::byte> data,
                                  const bool compare_data)
    {
        if (expected.kind != observed.kind || expected.step != observed.step || expected.ip != observed.ip ||
            expected.address != observed.address || expected.size != observed.size)
        {
            return false;
        }
        if (observed.kind == access_kind::execute)
        {
            return !trace_.has_instruction_bytes() || expected.payload == observed.payload;
        }
        return !compare_data || !trace_.has_access_data() || std::ranges::equal(trace_.access_data(expected), data);
    }

    void replay_verifier::verify(const access_kind kind, const uint64_t address, const size_t size, const std::span<const std::byte> data)
    {
        // Every write counts for the instruction cache, also the replay's own substitutions.
        if (caches_code_ && (kind == access_kind::write || kind == access_kind::host_write))
        {
            note_write(address, size);
        }
        if (error_ || !size || substituting_)
        {
            return;
        }
        if (write_observer_ && (kind == access_kind::write || kind == access_kind::host_write))
        {
            write_observer_(address, size);
        }
        // An instruction runs with the instruction pointer at its address, and guest accesses belong to the instruction
        // reported last; host writes happen outside instructions.
        if (kind == access_kind::execute)
        {
            instruction_ip_ = address;
        }
        const auto ip = kind == access_kind::host_write || !(access_mask_ & static_cast<uint64_t>(access_kind::execute))
                            ? emu_.emu().read_instruction_pointer()
                            : instruction_ip_;
        access_event observed{.step = emu_.get_executed_instructions(), .ip = ip, .address = address, .size = size, .kind = kind};
        const auto has_bytes = kind == access_kind::execute && trace_.has_instruction_bytes() && size < inline_data_limit;
        if (in_syscall_)
        {
            if (has_bytes)
            {
                emu_.emu().try_read_memory(address, observed.payload.data(), size);
            }
            syscall_events_.push_back({.event = observed,
                                       .previous = kind == access_kind::host_write ? std::move(previous_bytes_) : std::vector<std::byte>{},
                                       .data = {data.begin(), data.end()}});
            previous_bytes_ = {};
            return;
        }
        const auto expected = reader_.next(access_mask_);
        if (has_bytes)
        {
            // Mapping changes recorded before this event have happened by now.
            while (!pending_mapping_changes_.empty() && pending_mapping_changes_.front().event_number <= reader_.last_number())
            {
                ++layout_epoch_;
                pending_mapping_changes_ = pending_mapping_changes_.subspan(1);
            }
            observed.payload = instruction_bytes(address, size);
        }
        const auto same_event = expected && expected->kind == observed.kind && expected->step == observed.step &&
                                expected->ip == observed.ip && expected->address == observed.address && expected->size == observed.size;
        const auto same_instruction =
            kind != access_kind::execute || !trace_.has_instruction_bytes() || (same_event && expected->payload == observed.payload);
        const auto same_data =
            kind == access_kind::execute || !trace_.has_access_data() ||
            (same_event &&
             (expected->size <= inline_data_limit
                  ? std::ranges::equal(std::as_bytes(std::span(expected->payload)).first(static_cast<size_t>(expected->size)), data)
                  : std::ranges::equal(trace_.access_data(*expected), data)));
        if (same_event && same_instruction && same_data)
        {
            ++verified_events_;
            return;
        }
        if (same_event && same_instruction && kind == access_kind::host_write && !strict_)
        {
            const auto recorded = trace_.access_data(*expected);
            substituting_ = true;
            const auto restore = utils::finally([this] { substituting_ = false; });
            emu_.emu().write_memory(address, recorded.data(), recorded.size());
            ++substituted_inputs_;
            ++verified_events_;
            return;
        }
        if (same_event && same_instruction)
        {
            std::ostringstream message;
            message << "TTD replay diverged from the recording at event " << reader_.last_number() << ": ";
            describe_event(message, observed);
            message << " accessed different data";
            diverge(message.str());
            return;
        }
        std::ostringstream message;
        message << "TTD replay diverged from the recording";
        if (expected)
        {
            message << " at event " << reader_.last_number() << ": expected ";
            describe_event(message, *expected);
        }
        else
        {
            message << " after its last event: expected nothing";
        }
        message << ", observed ";
        describe_event(message, observed);
        diverge(message.str());
    }

    uint64_t replay_verifier::page_epoch(const uint64_t address, const size_t size) const
    {
        const auto* first = page_epochs_.find(address / page_size);
        const auto* last = page_epochs_.find(last_byte(address, size) / page_size);
        return std::max(first ? *first : 0, last ? *last : 0);
    }

    void replay_verifier::note_write(const uint64_t address, const uint64_t size)
    {
        if (!size)
        {
            return;
        }
        ++write_epoch_;
        const auto last = last_byte(address, size);
        for (auto page = address / page_size; page <= last / page_size; ++page)
        {
            page_epochs_.set(page, write_epoch_);
        }
    }

    std::array<uint8_t, inline_data_limit> replay_verifier::instruction_bytes(const uint64_t address, const size_t size)
    {
        if (caches_code_)
        {
            if (const auto* index = code_index_.find(address))
            {
                const auto& entry = code_cache_[static_cast<size_t>(*index)];
                if (entry.size == size && entry.layout_epoch == layout_epoch_ && entry.page_epoch == page_epoch(address, size))
                {
                    return entry.bytes;
                }
            }
        }
        std::array<uint8_t, inline_data_limit> bytes{};
        emu_.emu().try_read_memory(address, bytes.data(), size);
        if (caches_code_)
        {
            const auto* index = code_index_.find(address);
            const cached_code entry{.size = size, .bytes = bytes, .page_epoch = page_epoch(address, size), .layout_epoch = layout_epoch_};
            if (index)
            {
                code_cache_[static_cast<size_t>(*index)] = entry;
            }
            else
            {
                code_index_.set(address, code_cache_.size());
                code_cache_.push_back(entry);
            }
        }
        return bytes;
    }

    void replay_verifier::finish()
    {
        syscall_enter_.reset();
        syscall_exit_.reset();
        host_write_before_hook_.remove();
        write_hook_.remove();
        read_hook_.remove();
        execute_hook_.remove();
        instruction_callback_.reset();
        host_write_hook_.remove();
        if (error_)
        {
            throw divergence_error(*error_);
        }
        const auto position = emu_.get_executed_instructions();
        if (const auto missed = reader_.next(access_mask_); missed && missed->step <= position)
        {
            std::ostringstream message;
            message << "TTD replay reached position " << std::hex << position << " without recorded event " << std::dec
                    << reader_.last_number() << " at step " << std::hex << missed->step;
            throw divergence_error(message.str());
        }
    }

    replay_selfmod_scanner::replay_selfmod_scanner(windows_emulator& emu, trace& recorded_writes, const uint64_t capture_address,
                                                   const size_t capture_size, const size_t capture_wave)
        : emu_(emu),
          recorded_writes_(recorded_writes),
          expected_writes_(recorded_writes, recorded_writes.first_event_after(emu.get_executed_instructions())),
          capture_address_(capture_address),
          capture_size_(capture_size),
          capture_wave_(capture_wave)
    {
        if (!(recorded_writes_.access_mask() & static_cast<uint64_t>(access_kind::write)))
        {
            throw std::runtime_error(writes_required);
        }
        auto& cpu = emu_.emu();
        emu_.memory.set_mapping_change_callback([this](const uint64_t address, const size_t size) {
            if (!size)
            {
                return;
            }
            const auto last = last_byte(address, size);
            const auto first_page = address / page_size;
            const auto last_page = last / page_size;
            for (auto it = writers_.begin(); it != writers_.end();)
            {
                if (it->first >= first_page && it->first <= last_page)
                {
                    page_latest_write_.erase(it->first);
                    reported_page_writes_.erase(it->first);
                    it = writers_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        });
        write_hook_ = scoped_hook(
            cpu, cpu.hook_memory_write_data(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, std::span<const std::byte> data) {
                const auto size = data.size();
                if (error_ || !size)
                {
                    return;
                }
                const auto expected = expected_writes_.next(static_cast<uint64_t>(access_kind::write));
                if (!expected)
                {
                    error_ = "TTD replay produced an unrecorded memory write";
                    emu_.stop();
                    return;
                }
                const auto number = expected_writes_.last_number();
                const auto step = emu_.get_executed_instructions();
                const auto ip = emu_.emu().read_instruction_pointer();
                if (expected->step != step || expected->ip != ip || expected->address != address || expected->size != size)
                {
                    std::ostringstream message;
                    message << "TTD replay memory write diverged at event " << number << ": expected step=" << expected->step
                            << " ip=" << std::hex << expected->ip << " address=" << expected->address << std::dec
                            << " size=" << expected->size << ", observed step=" << step << " ip=" << std::hex << ip
                            << " address=" << address << std::dec << " size=" << size;
                    error_ = message.str();
                    emu_.stop();
                    return;
                }
                const auto last = last_byte(address, size);
                for (uint64_t byte = address; byte <= last; ++byte)
                {
                    auto [it, inserted] = writers_.try_emplace(byte / page_size);
                    if (inserted)
                    {
                        it->second.first_number = number;
                    }
                    it->second.bytes[(byte % page_size) / 64] |= uint64_t{1} << (byte % 64);
                    page_latest_write_[byte / page_size] = number + 1;
                    if (byte == UINT64_MAX)
                    {
                        break;
                    }
                }
                last_write_number_ = number;
                ++verified_writes_;
            }));
        execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t address, size_t size) {
            if (error_ || !size || hits_.size() >= 256)
            {
                return;
            }
            const auto last = last_byte(address, size);
            for (uint64_t byte = address; byte <= last; ++byte)
            {
                const auto page = writers_.find(byte / page_size);
                if (page != writers_.end() && (page->second.bytes[(byte % page_size) / 64] & (uint64_t{1} << (byte % 64))))
                {
                    const auto reported = reported_page_writes_.find(byte / page_size);
                    const auto latest = page_latest_write_.at(byte / page_size);
                    if (reported != reported_page_writes_.end() && reported->second >= latest)
                    {
                        continue;
                    }
                    const auto first_number = reported == reported_page_writes_.end() ? page->second.first_number : reported->second;
                    const auto writer_number =
                        recorded_writes_.latest_write_to_byte(byte / page_size, byte, first_number, last_write_number_);
                    if (!writer_number)
                    {
                        continue;
                    }
                    reported_page_writes_[byte / page_size] = latest;
                    const auto writer = recorded_writes_.event_at(*writer_number);
                    const auto hit = self_modifying_hit{.address = address,
                                                        .size = size,
                                                        .write_step = writer.step,
                                                        .write_ip = writer.ip,
                                                        .execute_step = emu_.get_executed_instructions(),
                                                        .execute_ip = emu_.emu().read_instruction_pointer(),
                                                        .executions = 1};
                    if (!first_hit_)
                    {
                        first_hit_ = hit;
                    }
                    if (hits_.size() + 1 == capture_wave_ && capture_size_)
                    {
                        captured_memory_.resize(capture_size_);
                        for (size_t offset = 0; offset < capture_size_; offset += page_size)
                        {
                            const auto length = std::min<size_t>(page_size, capture_size_ - offset);
                            if (!emu_.emu().try_read_memory(capture_address_ + offset, captured_memory_.data() + offset, length))
                            {
                                std::fill_n(captured_memory_.data() + offset, length, uint8_t{0});
                                ++missing_capture_pages_;
                            }
                        }
                    }
                    if (hits_.size() < 256)
                    {
                        hits_.push_back(hit);
                    }
                    return;
                }
                if (byte == UINT64_MAX)
                {
                    break;
                }
            }
        }));
    }

    replay_selfmod_scanner::~replay_selfmod_scanner()
    {
        emu_.memory.set_mapping_change_callback({});
    }

    void replay_selfmod_scanner::finish()
    {
        emu_.memory.set_mapping_change_callback({});
        write_hook_.remove();
        execute_hook_.remove();
        if (error_)
        {
            throw std::runtime_error(*error_);
        }
        if (expected_writes_.next(static_cast<uint64_t>(access_kind::write)))
        {
            throw std::runtime_error("TTD replay ended before all recorded writes occurred");
        }
    }
}
