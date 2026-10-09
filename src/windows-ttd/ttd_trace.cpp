#include "ttd_trace.hpp"
#include "snapshot.hpp"

#include <disassembler.hpp>

#include <utils/compression.hpp>
#include <utils/finally.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cstring>
#include <future>
#include <map>
#include <mutex>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>

namespace sogen::ttd
{
    static_assert(std::endian::native == std::endian::little, "TTD trace requires a little-endian host");

    namespace
    {
        constexpr uint64_t page_size = 4096;
        constexpr size_t cached_chunks = 4;
        constexpr size_t cached_bulk_blocks = bulk_reference_span + 1;
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

        // Versions 1-4 stored every event as a fixed-size record, followed by full checkpoint snapshots and a
        // per-event page index. They remain readable.
        struct v1_header
        {
            std::array<char, 8> magic{};
            uint64_t snapshot_size{};
            uint64_t instruction_count{};
            uint64_t write_count{};
            uint64_t index_offset{};
            uint64_t index_count{};
        };

        struct v4_header
        {
            std::array<char, 8> magic{};
            uint64_t snapshot_size{};
            uint64_t instruction_count{};
            uint64_t event_count{};
            uint64_t checkpoint_count{};
            uint64_t checkpoint_table_offset{};
            uint64_t index_offset{};
            uint64_t index_count{};
        };

        struct v1_index_entry
        {
            uint64_t page;
            uint64_t event_number;
        };

        struct v3_index_entry
        {
            uint64_t page;
            uint64_t event_number;
            access_kind kind;
        };

        struct v1_event
        {
            uint64_t step;
            uint64_t ip;
            uint64_t address;
            uint64_t size;
        };

        struct v3_event
        {
            uint64_t step;
            uint64_t ip;
            uint64_t address;
            uint64_t size;
            access_kind kind;
        };

        struct v4_checkpoint_entry
        {
            uint64_t step;
            uint64_t offset;
            uint64_t size;
        };

        static_assert(sizeof(v1_header) == 48);
        static_assert(sizeof(v4_header) == 64);
        static_assert(sizeof(v1_event) == 32);
        static_assert(sizeof(v3_event) == 40);
        static_assert(sizeof(v3_index_entry) == 24);
        static_assert(sizeof(v4_checkpoint_entry) == 24);

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
        T read_object(std::istream& stream)
        {
            T object{};
            stream.read(reinterpret_cast<char*>(&object), sizeof(object));
            if (!stream)
            {
                throw std::runtime_error("Truncated TTD trace");
            }
            return object;
        }

        template <typename T>
        std::span<const std::byte> bytes_of(const std::vector<T>& values)
        {
            return std::as_bytes(std::span(values));
        }

        constexpr auto writes_required = "TTD replay scans require a trace recorded with write events";

        bool overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
        {
            return as && bs && a <= b + std::min(bs - 1, UINT64_MAX - b) && b <= a + std::min(as - 1, UINT64_MAX - a);
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

        manifest_entries decode_manifest(const std::span<const std::byte> encoded)
        {
            manifest_entries manifest{};
            size_t offset = 0;
            const auto take = [&](const size_t size) {
                if (size > encoded.size() - offset)
                {
                    throw std::runtime_error("Invalid TTD manifest");
                }
                const auto bytes = encoded.subspan(offset, size);
                offset += size;
                return bytes;
            };
            const auto text = [](const std::span<const std::byte> bytes) {
                return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            };
            while (offset < encoded.size())
            {
                uint32_t key_size{};
                uint32_t value_size{};
                memcpy(&key_size, take(sizeof(key_size)).data(), sizeof(key_size));
                memcpy(&value_size, take(sizeof(value_size)).data(), sizeof(value_size));
                auto key = text(take(key_size));
                manifest.emplace_back(std::move(key), text(take(value_size)));
            }
            return manifest;
        }
    }

    recorder::recorder(windows_emulator& emu, const std::filesystem::path& path, const uint64_t access_mask, manifest_entries manifest)
        : emu_(emu),
          path_(path),
          file_(path, std::ios::binary | std::ios::trunc),
          manifest_(std::move(manifest))
    {
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
        if (access_mask & static_cast<uint64_t>(access_kind::execute))
        {
            execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t address, size_t size) {
                append_event(access_kind::execute, address, executed_size(emu_, address, size));
            }));
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
        // Last, so a constructor that throws never leaves a callback behind.
        emu_.memory.set_mapping_change_callback([this](const uint64_t address, const size_t size) {
            mapping_changes_.push_back(
                {.step = emu_.get_executed_instructions(), .event_number = header_.event_count, .address = address, .size = size});
            forget_instructions(address, size);
        });
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
                            .exports = std::move(exports)});
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

    void recorder::append_event(access_kind kind, uint64_t address, size_t size)
    {
        if (!size)
        {
            return;
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
            const auto cached = caches_instructions_ ? instruction_cache_.find(address) : instruction_cache_.end();
            if (cached != instruction_cache_.end() && cached->second.size == size)
            {
                event.payload = cached->second.bytes;
            }
            else
            {
                if (!emu_.emu().try_read_memory(address, event.payload.data(), size))
                {
                    throw std::runtime_error("Cannot read executed instruction bytes");
                }
                if (caches_instructions_)
                {
                    instruction_cache_[address] = {.size = size, .bytes = event.payload};
                    const auto last = last_byte(address, size);
                    for (auto page = address / page_size; page <= last / page_size; ++page)
                    {
                        cached_instructions_by_page_[page].push_back(address);
                    }
                }
            }
        }
        push_event(event);
    }

    void recorder::forget_instructions(const uint64_t address, const uint64_t size)
    {
        if (cached_instructions_by_page_.empty() || !size)
        {
            return;
        }
        const auto last = last_byte(address, size);
        for (auto page = address / page_size; page <= last / page_size; ++page)
        {
            const auto entry = cached_instructions_by_page_.find(page);
            if (entry == cached_instructions_by_page_.end())
            {
                continue;
            }
            for (const auto instruction : entry->second)
            {
                instruction_cache_.erase(instruction);
            }
            cached_instructions_by_page_.erase(entry);
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
                chunk_pages_[page] |= static_cast<uint32_t>(event.kind);
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
        // Code ids follow the order of first execution across the whole trace, so they are assigned here; the rest of
        // the encoding runs on a worker. The chunk's large accesses are the tail of the open bulk block, copied because
        // the block keeps growing.
        std::vector<uint64_t> code_ids{};
        for (const auto& event : chunk_events_)
        {
            if (event.kind == access_kind::execute)
            {
                code_ids.push_back(code_.id_of(event));
            }
        }
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
        for (const auto& [page, kinds] : chunk_pages_)
        {
            pages_.push_back({.page = page, .chunk = index, .kinds = kinds});
        }
        auto events = std::make_shared<const std::vector<access_event>>(std::move(chunk_events_));
        chunk_events_ = {};
        chunk_events_.reserve(events_per_chunk);
        chunk_pages_.clear();
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
        auto state = std::make_shared<const std::vector<std::byte>>(snapshot::create_emulator_state(emu_, expected_size));
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
        host_write_hook_.remove();
        block_hook_.remove();
        emu_.memory.set_mapping_change_callback({});
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

    trace::trace(const std::filesystem::path& path)
        : file_(path, std::ios::binary),
          path_(path)
    {
        if (!file_)
        {
            throw std::runtime_error("Cannot open TTD trace: " + path.string());
        }
        std::array<char, 8> magic{};
        file_.read(magic.data(), magic.size());
        if (!file_)
        {
            throw std::runtime_error("Truncated TTD trace");
        }
        const std::string_view name(magic.data(), magic.size());
        if (!name.starts_with("SOGTTD") || magic[7] != '\0' || magic[6] < '1' || magic[6] > '9')
        {
            throw std::runtime_error("Unsupported TTD trace format");
        }
        version_ = static_cast<uint32_t>(magic[6] - '0');
        if (version_ == 5 || version_ == 6 || version_ > 8)
        {
            throw std::runtime_error("Unsupported TTD trace format");
        }
        file_.seekg(0, std::ios::end);
        const auto length = static_cast<uint64_t>(file_.tellg());
        file_.seekg(0);
        if (this->chunked())
        {
            read_chunked_layout(length);
        }
        else
        {
            read_legacy_layout(length);
        }
    }

    void trace::read_chunked_layout(const uint64_t length)
    {
        const auto header = read_object<file_header>(file_);
        if (!header.section_table_offset)
        {
            throw std::runtime_error("TTD trace was not finalized; the recording was interrupted");
        }
        if (!header.access_mask || (header.access_mask & ~all_access_kinds))
        {
            throw std::runtime_error("Invalid TTD trace access mask");
        }
        metadata_ = {.instruction_count = header.instruction_count, .event_count = header.event_count};
        access_mask_ = header.access_mask;

        const auto fits = [&](const uint64_t offset, const uint64_t count, const uint64_t size) {
            return offset <= length && count <= (length - offset) / size;
        };
        if (header.section_count > 64 || !fits(header.section_table_offset, header.section_count, sizeof(section_entry)))
        {
            throw std::runtime_error("Invalid TTD trace offsets");
        }
        file_.seekg(static_cast<std::streamoff>(header.section_table_offset));
        std::vector<section_entry> sections(static_cast<size_t>(header.section_count));
        for (auto& section : sections)
        {
            section = read_object<section_entry>(file_);
        }
        // Decoded once the modules they belong to are.
        std::optional<std::vector<std::byte>> exports{};
        std::optional<std::vector<std::byte>> forwarders{};
        for (const auto& section : sections)
        {
            if (section.type == section_type::chunk_table)
            {
                if (!fits(section.offset, section.size, sizeof(chunk_entry)))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                file_.seekg(static_cast<std::streamoff>(section.offset));
                chunks_.resize(static_cast<size_t>(section.size));
                for (auto& chunk : chunks_)
                {
                    chunk = read_object<chunk_entry>(file_);
                }
            }
            else if (section.type == section_type::checkpoint_table)
            {
                if (!fits(section.offset, section.size, sizeof(checkpoint_entry)))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                file_.seekg(static_cast<std::streamoff>(section.offset));
                checkpoints_.resize(static_cast<size_t>(section.size));
                for (auto& checkpoint : checkpoints_)
                {
                    checkpoint = read_object<checkpoint_entry>(file_);
                }
            }
            else if (section.type == section_type::page_index)
            {
                if (!fits(section.offset, section.size, sizeof(page_block)))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                file_.seekg(static_cast<std::streamoff>(section.offset));
                page_blocks_.resize(static_cast<size_t>(section.size));
                for (auto& block : page_blocks_)
                {
                    block = read_object<page_block>(file_);
                    if (!block.entry_count || block.entry_count > page_block_entries || !fits(block.offset, block.size, 1) ||
                        (&block != page_blocks_.data() && block.first_page < (&block - 1)->first_page))
                    {
                        throw std::runtime_error("Invalid TTD page index block");
                    }
                }
            }
            else if (section.type == section_type::code_table)
            {
                if (!fits(section.offset, section.size, 1))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                const auto code = utils::compression::zstd::decompress(read_bytes(section.offset, section.size));
                if (code.size() % sizeof(code_entry))
                {
                    throw std::runtime_error("Invalid TTD code table");
                }
                code_.resize(code.size() / sizeof(code_entry));
                std::ranges::copy(code, reinterpret_cast<std::byte*>(code_.data()));
            }
            else if (section.type == section_type::bulk_table)
            {
                if (!fits(section.offset, section.size, sizeof(bulk_entry)))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                file_.seekg(static_cast<std::streamoff>(section.offset));
                bulk_table_.resize(static_cast<size_t>(section.size));
                for (auto& entry : bulk_table_)
                {
                    entry = read_object<bulk_entry>(file_);
                    if (!fits(entry.offset, entry.size, 1))
                    {
                        throw std::runtime_error("Invalid TTD bulk block entry");
                    }
                }
            }
            else if (section.type == section_type::manifest)
            {
                if (section.size > max_manifest_size || !fits(section.offset, section.size, 1))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                manifest_ = decode_manifest(read_bytes(section.offset, section.size));
            }
            else if (section.type == section_type::ui_inputs)
            {
                if (!fits(section.offset, section.size, sizeof(ui_input_entry)))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                file_.seekg(static_cast<std::streamoff>(section.offset));
                ui_inputs_.resize(static_cast<size_t>(section.size));
                for (auto& input : ui_inputs_)
                {
                    input = read_object<ui_input_entry>(file_);
                }
            }
            else if (section.type == section_type::syscalls)
            {
                if (!fits(section.offset, section.size, 1))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                syscalls_ = decode_syscalls(read_bytes(section.offset, section.size));
            }
            else if (section.type == section_type::register_snapshots)
            {
                if (!fits(section.offset, section.size, 1))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                register_snapshots_ = decode_register_snapshots(read_bytes(section.offset, section.size));
                for (const auto& entry : register_snapshots_)
                {
                    if (!fits(entry.offset, entry.size, 1) ||
                        (entry.base != UINT64_MAX && register_snapshots_[static_cast<size_t>(entry.base)].base != UINT64_MAX))
                    {
                        throw std::runtime_error("Invalid TTD register snapshot entry");
                    }
                }
            }
            else if (section.type == section_type::mapping_changes)
            {
                if (!fits(section.offset, section.size, 1))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                mapping_changes_ = decode_mapping_changes(read_bytes(section.offset, section.size));
            }
            else if (section.type == section_type::modules || section.type == section_type::threads ||
                     section.type == section_type::exports || section.type == section_type::export_forwarders)
            {
                if (!fits(section.offset, section.size, 1))
                {
                    throw std::runtime_error("Invalid TTD trace offsets");
                }
                auto bytes = read_bytes(section.offset, section.size);
                if (section.type == section_type::modules)
                {
                    modules_ = decode_modules(bytes);
                }
                else if (section.type == section_type::threads)
                {
                    threads_ = decode_threads(bytes);
                }
                else if (section.type == section_type::exports)
                {
                    exports = std::move(bytes);
                }
                else
                {
                    forwarders = std::move(bytes);
                }
            }
        }
        if (exports)
        {
            decode_exports(*exports, modules_);
            if (forwarders)
            {
                decode_export_forwarders(*forwarders, modules_);
            }
        }

        uint64_t next_event = 0;
        uint64_t previous_step = 0;
        for (const auto& chunk : chunks_)
        {
            if (chunk.first_event != next_event || !chunk.event_count || chunk.first_step > chunk.last_step ||
                chunk.first_step < previous_step || !fits(chunk.offset, chunk.size, 1))
            {
                throw std::runtime_error("Invalid TTD event chunk entry");
            }
            next_event += chunk.event_count;
            previous_step = chunk.last_step;
        }
        if (next_event != metadata_.event_count)
        {
            throw std::runtime_error("Invalid TTD event chunk entry");
        }
        if (checkpoints_.empty())
        {
            throw std::runtime_error("TTD trace has no initial state");
        }
        if (!chunks_.empty() && chunks_.front().first_step < checkpoints_.front().step)
        {
            throw std::runtime_error("TTD trace has events before its initial state");
        }
        if (bulk_table_.size() != checkpoints_.size())
        {
            throw std::runtime_error("TTD trace needs one bulk block per checkpoint interval");
        }
        for (size_t i = 0; i < checkpoints_.size(); ++i)
        {
            const auto& checkpoint = checkpoints_[i];
            if ((i && checkpoint.step <= checkpoints_[i - 1].step) || checkpoint.step > metadata_.instruction_count ||
                !fits(checkpoint.offset, checkpoint.size, 1) || (checkpoint.base != no_base_checkpoint && checkpoint.base >= i))
            {
                throw std::runtime_error("Invalid TTD checkpoint entry");
            }
        }
        for (size_t i = 0; i < ui_inputs_.size(); ++i)
        {
            const auto& input = ui_inputs_[i];
            const auto ordered = !i || std::pair(ui_inputs_[i - 1].checkpoint, ui_inputs_[i - 1].event_number) <=
                                           std::pair(input.checkpoint, input.event_number);
            if (input.checkpoint >= checkpoints_.size() || input.event_number > metadata_.event_count || !ordered)
            {
                throw std::runtime_error("Invalid TTD UI input entry");
            }
        }
        for (const auto& entry : this->syscalls())
        {
            // decode_syscalls keeps the entries ordered and their event ranges apart.
            if (entry.step <= checkpoints_.front().step || entry.step > metadata_.instruction_count ||
                entry.event_number + entry.event_count > metadata_.event_count)
            {
                throw std::runtime_error("Invalid TTD syscall entry");
            }
        }
        for (const auto& mod : modules_)
        {
            if (mod.load_step > metadata_.instruction_count || mod.load_event_number > metadata_.event_count ||
                (mod.unload_step && (*mod.unload_step < mod.load_step || *mod.unload_step > metadata_.instruction_count ||
                                     *mod.unload_event_number < mod.load_event_number || *mod.unload_event_number > metadata_.event_count)))
            {
                throw std::runtime_error("Invalid TTD module entry");
            }
        }
        for (const auto& entry : threads_.switches)
        {
            if (entry.step > metadata_.instruction_count || entry.event_number >= metadata_.event_count)
            {
                throw std::runtime_error("Invalid TTD thread switch");
            }
        }
    }

    void trace::read_legacy_layout(const uint64_t length)
    {
        uint64_t snapshot_size{};
        uint64_t checkpoint_count{};
        uint64_t checkpoint_table_offset{};
        uint64_t header_size{};
        if (version_ == 1)
        {
            const auto header = read_object<v1_header>(file_);
            header_size = sizeof(v1_header);
            snapshot_size = header.snapshot_size;
            metadata_ = {.instruction_count = header.instruction_count, .event_count = header.write_count};
            checkpoint_table_offset = header.index_offset;
            legacy_index_offset_ = header.index_offset;
            legacy_index_count_ = header.index_count;
        }
        else
        {
            const auto header = read_object<v4_header>(file_);
            header_size = sizeof(v4_header);
            snapshot_size = header.snapshot_size;
            metadata_ = {.instruction_count = header.instruction_count, .event_count = header.event_count};
            checkpoint_count = header.checkpoint_count;
            checkpoint_table_offset = header.checkpoint_table_offset;
            legacy_index_offset_ = header.index_offset;
            legacy_index_count_ = header.index_count;
        }
        if (!legacy_index_offset_)
        {
            throw std::runtime_error("TTD trace was not finalized; the recording was interrupted");
        }
        if (version_ <= 2)
        {
            access_mask_ = static_cast<uint64_t>(access_kind::write);
        }
        legacy_event_size_ = sizeof(access_event);
        if (version_ <= 2)
        {
            legacy_event_size_ = sizeof(v1_event);
        }
        else if (version_ == 3)
        {
            legacy_event_size_ = sizeof(v3_event);
        }
        legacy_event_offset_ = header_size + snapshot_size;
        const auto index_entry_size = version_ <= 2 ? sizeof(v1_index_entry) : sizeof(v3_index_entry);
        if (length < header_size || snapshot_size > length - header_size)
        {
            throw std::runtime_error("Invalid TTD trace snapshot size");
        }
        const auto event_end = legacy_event_offset_ + metadata_.event_count * legacy_event_size_;
        if (metadata_.event_count > (UINT64_MAX - legacy_event_offset_) / legacy_event_size_ || checkpoint_table_offset < event_end ||
            checkpoint_table_offset > legacy_index_offset_ ||
            checkpoint_count > (legacy_index_offset_ - checkpoint_table_offset) / sizeof(v4_checkpoint_entry) ||
            legacy_index_offset_ > length || legacy_index_count_ > (length - legacy_index_offset_) / index_entry_size)
        {
            throw std::runtime_error("Invalid TTD trace offsets");
        }

        checkpoints_.push_back({.step = 0, .offset = header_size, .size = snapshot_size});
        file_.seekg(static_cast<std::streamoff>(checkpoint_table_offset));
        for (uint64_t i = 0; i < checkpoint_count; ++i)
        {
            const auto entry = read_object<v4_checkpoint_entry>(file_);
            if (!entry.step || entry.step <= checkpoints_.back().step || entry.step > metadata_.instruction_count ||
                entry.offset < event_end || entry.offset > checkpoint_table_offset || entry.size > checkpoint_table_offset - entry.offset)
            {
                throw std::runtime_error("Invalid TTD checkpoint entry");
            }
            checkpoints_.push_back({.step = entry.step, .offset = entry.offset, .size = entry.size});
        }
    }

    std::vector<std::byte> trace::read_bytes(const uint64_t offset, const uint64_t size)
    {
        std::vector<std::byte> bytes(static_cast<size_t>(size));
        file_.clear();
        file_.seekg(static_cast<std::streamoff>(offset));
        file_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!file_)
        {
            throw std::runtime_error("Truncated TTD trace");
        }
        return bytes;
    }

    const decoded_chunk& trace::chunk(const uint32_t index)
    {
        const auto cached = std::ranges::find(chunk_cache_, index, &cached_chunk::index);
        if (cached != chunk_cache_.end())
        {
            std::rotate(cached, cached + 1, chunk_cache_.end());
            return chunk_cache_.back().chunk;
        }
        const auto& entry = chunks_.at(index);
        auto decoded = decode_chunk(read_bytes(entry.offset, entry.size), code_, [this](const uint64_t block) { return bulk(block); });
        if (decoded.events.size() != entry.event_count)
        {
            throw std::runtime_error("Invalid TTD event chunk");
        }
        if (chunk_cache_.size() == cached_chunks)
        {
            chunk_cache_.erase(chunk_cache_.begin());
        }
        chunk_cache_.push_back({.index = index, .chunk = std::move(decoded)});
        return chunk_cache_.back().chunk;
    }

    bulk_block trace::bulk(const uint64_t index)
    {
        const auto cached = std::ranges::find(bulk_cache_, index, &cached_bulk::index);
        if (cached != bulk_cache_.end())
        {
            std::rotate(cached, cached + 1, bulk_cache_.end());
            return bulk_cache_.back().block;
        }
        if (index >= bulk_table_.size())
        {
            throw std::runtime_error("Invalid TTD bulk block reference");
        }
        const auto& entry = bulk_table_[static_cast<size_t>(index)];
        auto block = std::make_shared<std::vector<std::byte>>();
        if (entry.size)
        {
            *block = decode_bulk_block(read_bytes(entry.offset, entry.size), version_ >= 8);
            if (block->empty())
            {
                throw std::runtime_error("Cannot decompress TTD bulk block");
            }
        }
        remember_bulk(index, block);
        return block;
    }

    std::unordered_map<uint64_t, bulk_block> trace::bulk_blocks(const std::span<const uint64_t> indexes)
    {
        std::unordered_map<uint64_t, bulk_block> blocks{};
        std::vector<std::pair<uint64_t, std::future<std::vector<std::byte>>>> decoding{};
        for (const auto index : indexes)
        {
            if (index >= bulk_table_.size())
            {
                throw std::runtime_error("Invalid TTD bulk block reference");
            }
            if (blocks.contains(index) || std::ranges::find(decoding, index, &decltype(decoding)::value_type::first) != decoding.end())
            {
                continue;
            }
            const auto& entry = bulk_table_[static_cast<size_t>(index)];
            if (!entry.size || std::ranges::find(bulk_cache_, index, &cached_bulk::index) != bulk_cache_.end())
            {
                blocks[index] = bulk(index);
                continue;
            }
            decoding.emplace_back(
                index, std::async(std::launch::async, [compressed = read_bytes(entry.offset, entry.size), filtered = version_ >= 8] {
                    return decode_bulk_block(compressed, filtered);
                }));
        }
        for (auto& [index, decoded] : decoding)
        {
            auto block = std::make_shared<const std::vector<std::byte>>(decoded.get());
            if (block->empty())
            {
                throw std::runtime_error("Cannot decompress TTD bulk block");
            }
            remember_bulk(index, block);
            blocks[index] = std::move(block);
        }
        return blocks;
    }

    void trace::remember_bulk(const uint64_t index, bulk_block block)
    {
        if (bulk_cache_.size() == cached_bulk_blocks)
        {
            bulk_cache_.erase(bulk_cache_.begin());
        }
        bulk_cache_.push_back({.index = index, .block = std::move(block)});
    }

    uint32_t trace::chunk_of(const uint64_t number) const
    {
        const auto next = std::ranges::upper_bound(chunks_, number, {}, &chunk_entry::first_event);
        return static_cast<uint32_t>(next - chunks_.begin() - 1);
    }

    std::shared_ptr<const std::vector<std::byte>> trace::checkpoint_state_at(const uint64_t index)
    {
        if (!this->chunked())
        {
            const auto& entry = checkpoints_.at(static_cast<size_t>(index));
            return std::make_shared<const std::vector<std::byte>>(snapshot::get_emulator_state(read_bytes(entry.offset, entry.size)));
        }
        if (state_cache_ && state_cache_->first == index)
        {
            return state_cache_->second;
        }

        std::vector<uint64_t> chain{index};
        while (checkpoints_.at(static_cast<size_t>(chain.back())).base != no_base_checkpoint &&
               (!state_cache_ || state_cache_->first != chain.back()))
        {
            chain.push_back(checkpoints_.at(static_cast<size_t>(chain.back())).base);
        }
        const auto from_cache = state_cache_ && state_cache_->first == chain.back();

        // A delta's reference is its base state followed by the bulk blocks in between. Each restored state is
        // decompressed with room for the next delta's blocks, so they can be appended in place instead of copying the
        // state into a new reference buffer.
        const auto referenced_blocks = [this](const uint64_t current) {
            const auto base = checkpoints_.at(static_cast<size_t>(current)).base;
            if (base == no_base_checkpoint || current - base > bulk_reference_span)
            {
                return std::views::iota(uint64_t{0}, uint64_t{0});
            }
            return std::views::iota(base, current);
        };
        // All deltas' blocks are decoded in parallel up front; decoding them one delta at a time took about half of a
        // restore.
        std::vector<uint64_t> needed{};
        for (const auto current : std::span(chain).first(chain.size() - (from_cache ? 1 : 0)))
        {
            std::ranges::copy(referenced_blocks(current), std::back_inserter(needed));
        }
        const auto decoded = bulk_blocks(needed);
        const auto blocks_between = [&](const uint64_t current) {
            std::vector<bulk_block> blocks{};
            for (const auto block : referenced_blocks(current))
            {
                blocks.push_back(decoded.at(block));
            }
            return blocks;
        };
        const auto total_size = [](const std::span<const bulk_block> blocks) {
            size_t size = 0;
            for (const auto& block : blocks)
            {
                size += block->size();
            }
            return size;
        };

        // Reserving discards a buffer's stale contents instead of copying them, with slack so slowly growing states
        // keep their allocation.
        const auto reserve = [](std::vector<std::byte>& buffer, const size_t size) {
            if (buffer.capacity() < size)
            {
                buffer = {};
                buffer.reserve(size + size / 16);
            }
        };

        std::vector<std::byte> state{};
        std::vector<std::byte> next{};
        std::vector<bulk_block> between{};
        if (from_cache)
        {
            chain.pop_back();
            const auto& cached = *state_cache_->second;
            if (!chain.empty())
            {
                between = blocks_between(chain.back());
            }
            reserve(state, cached.size() + total_size(between));
            state.assign(cached.begin(), cached.end());
        }
        while (!chain.empty())
        {
            const auto current = chain.back();
            const auto& entry = checkpoints_.at(static_cast<size_t>(current));
            const auto compressed = read_bytes(entry.offset, entry.size);
            chain.pop_back();
            const auto size = utils::compression::zstd::decompressed_size(compressed);
            if (!size)
            {
                throw std::runtime_error("Cannot decompress TTD checkpoint");
            }
            if (entry.base == no_base_checkpoint)
            {
                state.clear();
            }
            for (const auto& block : between)
            {
                state.insert(state.end(), block->begin(), block->end());
            }
            between = chain.empty() ? std::vector<bulk_block>{} : blocks_between(chain.back());
            reserve(next, *size + total_size(between));
            if (!utils::compression::zstd::decompress_with_reference(compressed, state, next))
            {
                throw std::runtime_error("Cannot decompress TTD checkpoint");
            }
            std::swap(state, next);
        }
        auto restored = std::make_shared<const std::vector<std::byte>>(std::move(state));
        state_cache_ = std::make_pair(index, restored);
        return restored;
    }

    std::optional<std::string_view> trace::manifest_value(const std::string_view key) const
    {
        const auto entry = std::ranges::find(manifest_, key, &manifest_entries::value_type::first);
        if (entry == manifest_.end())
        {
            return std::nullopt;
        }
        return entry->second;
    }

    std::optional<std::string_view> trace::syscall_name(const uint32_t id) const
    {
        if (!syscalls_)
        {
            return std::nullopt;
        }
        const auto entry = syscalls_->names.find(id);
        return entry == syscalls_->names.end() ? std::nullopt : std::optional<std::string_view>(entry->second);
    }

    const module_entry* trace::module_at(const uint64_t address, const uint64_t step) const
    {
        // The latest load wins: an image base can be reused after an unload.
        for (const auto& mod : std::views::reverse(modules_))
        {
            if (address - mod.base < mod.size && mod.load_step <= step && (!mod.unload_step || step < *mod.unload_step))
            {
                return &mod;
            }
        }
        return nullptr;
    }

    std::optional<symbol_location> trace::symbol_at(const uint64_t address, const uint64_t step) const
    {
        const auto* mod = module_at(address, step);
        if (!mod)
        {
            return std::nullopt;
        }
        const auto rva = address - mod->base;
        if (!mod->exports)
        {
            return symbol_location{.module = mod, .offset = rva};
        }
        const auto& exports = *mod->exports;
        // Forwarded exports point at their forwarder strings, not at code.
        const auto below = std::ranges::find_if(
            std::ranges::subrange(exports.begin(), std::ranges::upper_bound(exports, rva, {}, &module_export::rva)) | std::views::reverse,
            [](const module_export& symbol) { return symbol.forwarder.empty(); });
        if (below.base() == exports.begin())
        {
            return symbol_location{.module = mod, .offset = rva};
        }
        // Of several names for one address, the first by name, preferring a real name over "#<ordinal>".
        const auto aliases = std::ranges::equal_range(exports, below->rva, {}, &module_export::rva);
        const auto named = std::ranges::find_if(aliases, [](const module_export& symbol) { return !symbol.name.starts_with('#'); });
        const auto& symbol = named == aliases.end() ? aliases.front() : *named;
        return symbol_location{.module = mod, .symbol = &symbol, .offset = rva - symbol.rva};
    }

    std::vector<module_symbol> trace::find_exports(const std::string_view name) const
    {
        const auto separator = name.find('!');
        const auto module_name = separator == std::string_view::npos ? std::string_view{} : name.substr(0, separator);
        const auto symbol_name = separator == std::string_view::npos ? name : name.substr(separator + 1);
        const auto equal_ignoring_case = [](const std::string_view a, const std::string_view b) {
            return std::ranges::equal(a, b, [](const char x, const char y) {
                return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
            });
        };
        const auto module_matches = [&](const module_entry& mod) {
            if (module_name.empty() || equal_ignoring_case(mod.name, module_name))
            {
                return true;
            }
            constexpr std::string_view extension = ".dll";
            return mod.name.size() == module_name.size() + extension.size() &&
                   equal_ignoring_case(std::string_view(mod.name).substr(0, module_name.size()), module_name) &&
                   equal_ignoring_case(std::string_view(mod.name).substr(module_name.size()), extension);
        };

        std::vector<module_symbol> found{};
        for (const auto& mod : modules_)
        {
            if (!mod.exports || !module_matches(mod))
            {
                continue;
            }
            for (const auto& symbol : *mod.exports)
            {
                // A forwarder can name a function by ordinal that also has a name.
                if (symbol.name == symbol_name || (symbol_name.starts_with('#') && symbol_name.substr(1) == std::to_string(symbol.ordinal)))
                {
                    found.push_back({.module = &mod, .symbol = &symbol});
                }
            }
        }
        return found;
    }

    std::vector<access_event> trace::calls(const std::string_view name, const uint64_t start, const uint64_t end)
    {
        struct target
        {
            uint64_t address{};
            uint64_t first{};
            uint64_t last{};
        };

        std::vector<target> targets{};
        // A forwarded export runs as its target, in the window where both modules are loaded; forwarders can chain.
        constexpr size_t max_forwarder_depth = 8;
        const auto add = [&](const auto& self, const module_symbol& found, uint64_t first, uint64_t last, const size_t depth) -> void {
            first = std::max(first, found.module->load_step);
            last = found.module->unload_step ? std::min(last, *found.module->unload_step) : last;
            if (first > last)
            {
                return;
            }
            if (found.symbol->forwarder.empty())
            {
                targets.push_back({.address = found.module->base + found.symbol->rva, .first = first, .last = last});
                return;
            }
            if (depth < max_forwarder_depth)
            {
                for (const auto& forwarded : find_exports(found.symbol->forwarder))
                {
                    self(self, forwarded, first, last, depth + 1);
                }
            }
        };
        for (const auto& symbol : find_exports(name))
        {
            add(add, symbol, start, end, 0);
        }

        std::vector<access_event> found{};
        for (const auto& [address, first, last] : targets)
        {
            for (const auto& event : accesses(address, 1, first, last, static_cast<uint64_t>(access_kind::execute)))
            {
                if (event.address == address)
                {
                    found.push_back(event);
                }
            }
        }
        // Several names (an export and the forwarders to it) can lead to the same function.
        std::ranges::sort(found, {}, [](const access_event& event) { return std::tie(event.step, event.address); });
        const auto duplicates =
            std::ranges::unique(found, {}, [](const access_event& event) { return std::tie(event.step, event.address); });
        found.erase(duplicates.begin(), duplicates.end());
        return found;
    }

    std::optional<uint32_t> trace::thread_at(const uint64_t step) const
    {
        const auto& switches = threads_.switches;
        const auto next = std::ranges::upper_bound(switches, step, {}, &thread_switch::step);
        if (next == switches.begin())
        {
            return std::nullopt;
        }
        return std::prev(next)->thread_id;
    }

    std::vector<std::byte> trace::snapshot_registers(const size_t index)
    {
        const auto& entry = register_snapshots_.at(index);
        const auto base = entry.base == UINT64_MAX ? index : entry.base;
        if (!register_base_cache_ || register_base_cache_->first != base)
        {
            const auto& base_entry = register_snapshots_[static_cast<size_t>(base)];
            register_base_cache_.emplace(base, utils::compression::zstd::decompress(read_bytes(base_entry.offset, base_entry.size)));
        }
        if (base == index)
        {
            return register_base_cache_->second;
        }
        return utils::compression::zstd::decompress_with_reference(read_bytes(entry.offset, entry.size), register_base_cache_->second);
    }

    uint64_t trace::checkpoint_index(const uint64_t step) const
    {
        const auto entry = std::ranges::lower_bound(checkpoints_, step, {}, &checkpoint_entry::step);
        if (entry == checkpoints_.end() || entry->step != step)
        {
            throw std::out_of_range("No TTD checkpoint at this position");
        }
        return static_cast<uint64_t>(entry - checkpoints_.begin());
    }

    uint64_t trace::checkpoint_step_for(const uint64_t step) const
    {
        if (step > metadata_.instruction_count)
        {
            throw std::out_of_range("TTD position is beyond end of trace");
        }
        if (step < this->start_position())
        {
            throw std::out_of_range("TTD position is before the start of the trace");
        }
        return std::prev(std::ranges::upper_bound(checkpoints_, step, {}, &checkpoint_entry::step))->step;
    }

    checkpoint_state trace::checkpoint_for_step(const uint64_t step)
    {
        const auto index = this->checkpoint_index(this->checkpoint_step_for(step));
        return {.step = checkpoints_[static_cast<size_t>(index)].step, .state = checkpoint_state_at(index)};
    }

    access_event trace::event_at(const uint64_t number)
    {
        if (number >= metadata_.event_count)
        {
            throw std::out_of_range("TTD event is beyond end of trace");
        }
        if (this->chunked())
        {
            const auto index = chunk_of(number);
            return chunk(index).events.at(static_cast<size_t>(number - chunks_[index].first_event));
        }
        access_event event{};
        read_events(number, std::span(&event, 1));
        return event;
    }

    size_t trace::read_events(const uint64_t first_number, const std::span<access_event> output)
    {
        if (first_number >= metadata_.event_count || output.empty())
        {
            return 0;
        }
        const auto count = static_cast<size_t>(std::min<uint64_t>(output.size(), metadata_.event_count - first_number));
        if (this->chunked())
        {
            size_t copied = 0;
            while (copied < count)
            {
                const auto number = first_number + copied;
                const auto index = chunk_of(number);
                const auto& events = chunk(index).events;
                const auto start = static_cast<size_t>(number - chunks_[index].first_event);
                const auto available = std::min(count - copied, events.size() - start);
                std::copy_n(events.begin() + static_cast<ptrdiff_t>(start), available, output.begin() + static_cast<ptrdiff_t>(copied));
                copied += available;
            }
            return count;
        }

        const auto raw = read_bytes(legacy_event_offset_ + first_number * legacy_event_size_, count * legacy_event_size_);
        for (size_t i = 0; i < count; ++i)
        {
            const auto* entry = raw.data() + i * legacy_event_size_;
            if (version_ <= 2)
            {
                v1_event old{};
                memcpy(&old, entry, sizeof(old));
                output[i] = {.step = old.step, .ip = old.ip, .address = old.address, .size = old.size, .kind = access_kind::write};
            }
            else if (version_ == 3)
            {
                v3_event old{};
                memcpy(&old, entry, sizeof(old));
                output[i] = {.step = old.step, .ip = old.ip, .address = old.address, .size = old.size, .kind = old.kind};
            }
            else
            {
                memcpy(&output[i], entry, sizeof(access_event));
            }
        }
        return count;
    }

    uint64_t trace::first_event_after(const uint64_t step)
    {
        if (this->chunked())
        {
            const auto first = std::ranges::partition_point(chunks_, [&](const chunk_entry& entry) { return entry.last_step <= step; });
            if (first == chunks_.end())
            {
                return metadata_.event_count;
            }
            const auto index = static_cast<uint32_t>(first - chunks_.begin());
            const auto& events = chunk(index).events;
            const auto after = std::ranges::upper_bound(events, step, {}, &access_event::step);
            return chunks_[index].first_event + static_cast<uint64_t>(after - events.begin());
        }
        uint64_t low = 0;
        uint64_t high = metadata_.event_count;
        while (low < high)
        {
            const auto middle = low + (high - low) / 2;
            if (event_at(middle).step <= step)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }
        return low;
    }

    uint64_t trace::first_event_at_or_after(const uint64_t step)
    {
        return step ? first_event_after(step - 1) : 0;
    }

    uint64_t trace::access_mask()
    {
        if (!access_mask_)
        {
            uint64_t mask = 0;
            event_reader reader(*this);
            while (mask != all_access_kinds)
            {
                const auto event = reader.next();
                if (!event)
                {
                    break;
                }
                mask |= static_cast<uint64_t>(event->kind);
            }
            access_mask_ = mask;
        }
        return *access_mask_;
    }

    std::vector<std::byte> trace::access_data(const access_event& event)
    {
        if (!this->has_access_data() || event.kind == access_kind::execute)
        {
            return {};
        }
        if (event.size <= inline_data_limit)
        {
            const auto bytes = std::as_bytes(std::span(event.payload)).first(static_cast<size_t>(event.size));
            return {bytes.begin(), bytes.end()};
        }
        uint64_t offset{};
        uint64_t index{};
        memcpy(&offset, event.payload.data(), sizeof(offset));
        memcpy(&index, event.payload.data() + sizeof(offset), sizeof(index));
        const auto block = bulk(index);
        if (offset > block->size() || event.size > block->size() - offset)
        {
            throw std::runtime_error("Invalid TTD access data reference");
        }
        const auto begin = block->begin() + static_cast<ptrdiff_t>(offset);
        return {begin, begin + static_cast<ptrdiff_t>(event.size)};
    }

    std::vector<trace::number_range> trace::candidates(const uint64_t first_page, const uint64_t last_page, const uint64_t kind_mask,
                                                       const uint64_t first_number, const uint64_t end_number)
    {
        if (first_number >= end_number)
        {
            return {};
        }
        if (!this->chunked())
        {
            return legacy_candidates(first_page, last_page, kind_mask, first_number, end_number);
        }
        std::vector<number_range> ranges{};
        for (const auto& range : chunked_candidates(first_page, last_page, kind_mask))
        {
            const auto begin = std::max(range.begin, first_number);
            const auto end = std::min(range.end, end_number);
            if (begin < end)
            {
                ranges.push_back({.begin = begin, .end = end});
            }
        }
        return ranges;
    }

    std::vector<trace::number_range> trace::chunked_candidates(const uint64_t first_page, const uint64_t last_page,
                                                               const uint64_t kind_mask)
    {
        // Entries of one page can continue from the block before the first block starting at or after it.
        auto block = std::ranges::lower_bound(page_blocks_, first_page, {}, &page_block::first_page);
        if (block != page_blocks_.begin())
        {
            --block;
        }

        std::vector<uint32_t> matches{};
        for (; block != page_blocks_.end() && block->first_page <= last_page; ++block)
        {
            for (const auto& entry : decode_page_block(read_bytes(block->offset, block->size), *block))
            {
                if (entry.page < first_page || entry.page > last_page || !(entry.kinds & kind_mask))
                {
                    continue;
                }
                if (entry.chunk >= chunks_.size())
                {
                    throw std::runtime_error("Invalid TTD page index entry");
                }
                matches.push_back(entry.chunk);
            }
        }
        std::ranges::sort(matches);
        const auto duplicates = std::ranges::unique(matches);
        matches.erase(duplicates.begin(), duplicates.end());

        std::vector<number_range> ranges{};
        ranges.reserve(matches.size());
        for (const auto index : matches)
        {
            ranges.push_back({.begin = chunks_[index].first_event, .end = chunks_[index].first_event + chunks_[index].event_count});
        }
        return ranges;
    }

    std::vector<access_event> trace::matching_events(const std::span<const number_range> ranges,
                                                     const std::function<bool(const access_event&)>& matches, const bool with_data)
    {
        std::vector<access_event> result{};
        const auto collect = [&](std::vector<access_event>& output, const std::span<const access_event> events, const uint64_t first_event,
                                 const number_range& range) {
            for (auto number = range.begin; number < range.end; ++number)
            {
                const auto& event = events[static_cast<size_t>(number - first_event)];
                if (matches(event))
                {
                    output.push_back(event);
                }
            }
        };

        // Workers resolve bulk blocks through the trace's cache and file, one at a time; the main thread waits meanwhile.
        std::mutex bulk_mutex{};
        const bulk_resolver shared_bulk = [&](const uint64_t block) {
            const std::scoped_lock lock(bulk_mutex);
            return bulk(block);
        };
        const auto batch_size = static_cast<size_t>(std::max(1U, std::thread::hardware_concurrency()));
        for (size_t first = 0; first < ranges.size(); first += batch_size)
        {
            const auto batch = ranges.subspan(first, std::min(batch_size, ranges.size() - first));
            std::vector<std::future<std::vector<access_event>>> decoding(batch.size());
            for (size_t i = 0; i < batch.size(); ++i)
            {
                const auto index = chunk_of(batch[i].begin);
                if (batch[i].end > chunks_[index].first_event + chunks_[index].event_count)
                {
                    throw std::runtime_error("TTD event range crosses a chunk");
                }
                if (std::ranges::find(chunk_cache_, index, &cached_chunk::index) != chunk_cache_.end())
                {
                    continue;
                }
                const auto entry = chunks_[index];
                decoding[i] =
                    std::async(std::launch::async, [&, entry, compressed = read_bytes(entry.offset, entry.size), range = batch[i]] {
                        const auto decoded = decode_chunk(compressed, code_, shared_bulk, with_data);
                        if (decoded.events.size() != entry.event_count)
                        {
                            throw std::runtime_error("Invalid TTD event chunk");
                        }
                        std::vector<access_event> found{};
                        collect(found, decoded.events, entry.first_event, range);
                        return found;
                    });
            }
            // Every worker finishes before the batch is left, also when one throws: they reference this frame.
            std::exception_ptr error{};
            for (size_t i = 0; i < batch.size(); ++i)
            {
                if (decoding[i].valid())
                {
                    try
                    {
                        auto found = decoding[i].get();
                        result.insert(result.end(), found.begin(), found.end());
                    }
                    catch (...)
                    {
                        error = error ? error : std::current_exception();
                    }
                }
                else if (!error)
                {
                    const auto index = chunk_of(batch[i].begin);
                    collect(result, chunk(index).events, chunks_[index].first_event, batch[i]);
                }
            }
            if (error)
            {
                std::rethrow_exception(error);
            }
        }
        return result;
    }

    std::vector<trace::number_range> trace::legacy_candidates(const uint64_t first_page, const uint64_t last_page, const uint64_t kind_mask,
                                                              const uint64_t first_number, const uint64_t end_number)
    {
        const auto entry_size = version_ <= 2 ? sizeof(v1_index_entry) : sizeof(v3_index_entry);
        const auto entry_at = [&](const uint64_t position) {
            file_.clear();
            file_.seekg(static_cast<std::streamoff>(legacy_index_offset_ + position * entry_size));
            auto entry = version_ <= 2 ? [&] {
                const auto old = read_object<v1_index_entry>(file_);
                return v3_index_entry{.page = old.page, .event_number = old.event_number, .kind = access_kind::write};
            }()
                                       : read_object<v3_index_entry>(file_);
            if (entry.event_number >= metadata_.event_count)
            {
                throw std::runtime_error("Invalid TTD index entry");
            }
            return entry;
        };
        const auto lower_bound = [&](const uint64_t page, const access_kind kind, const uint64_t number) {
            uint64_t low = 0;
            uint64_t high = legacy_index_count_;
            while (low < high)
            {
                const auto middle = low + (high - low) / 2;
                const auto entry = entry_at(middle);
                if (entry.page < page || (entry.page == page && (entry.kind < kind || (entry.kind == kind && entry.event_number < number))))
                {
                    low = middle + 1;
                }
                else
                {
                    high = middle;
                }
            }
            return low;
        };

        std::vector<uint64_t> numbers{};
        auto position = lower_bound(first_page, access_kind::read, 0);
        while (position < legacy_index_count_)
        {
            const auto entry = entry_at(position);
            if (entry.page > last_page)
            {
                break;
            }
            const auto group_end = lower_bound(entry.page, entry.kind, UINT64_MAX);
            if (kind_mask & static_cast<uint64_t>(entry.kind))
            {
                const auto end = lower_bound(entry.page, entry.kind, end_number);
                for (auto member = lower_bound(entry.page, entry.kind, first_number); member < end; ++member)
                {
                    numbers.push_back(entry_at(member).event_number);
                }
            }
            position = group_end;
        }
        std::ranges::sort(numbers);
        const auto duplicates = std::ranges::unique(numbers);
        numbers.erase(duplicates.begin(), duplicates.end());

        std::vector<number_range> ranges{};
        for (const auto number : numbers)
        {
            if (!ranges.empty() && ranges.back().end == number)
            {
                ++ranges.back().end;
            }
            else
            {
                ranges.push_back({.begin = number, .end = number + 1});
            }
        }
        return ranges;
    }

    std::optional<uint64_t> trace::latest_write_to_byte(const uint64_t page, const uint64_t address, const uint64_t first_number,
                                                        const uint64_t last_number)
    {
        if (first_number > last_number)
        {
            return std::nullopt;
        }
        const auto end_number = last_number == UINT64_MAX ? metadata_.event_count : last_number + 1;
        for (const auto& range :
             std::views::reverse(candidates(page, page, static_cast<uint64_t>(access_kind::write), first_number, end_number)))
        {
            for (auto number = range.end; number-- > range.begin;)
            {
                const auto event = event_at(number);
                if (event.kind == access_kind::write && event.address <= address && address - event.address < event.size)
                {
                    return number;
                }
            }
        }
        return std::nullopt;
    }

    std::vector<access_event> trace::accesses(uint64_t address, uint64_t size, uint64_t first_step, uint64_t last_step, uint64_t kind_mask)
    {
        std::vector<access_event> result{};
        if (!size || first_step > last_step)
        {
            return result;
        }
        const auto first_number = first_event_at_or_after(first_step);
        const auto end_number = last_step == UINT64_MAX ? metadata_.event_count : first_event_after(last_step);
        const auto last = last_byte(address, size);
        const auto ranges = candidates(address / page_size, last / page_size, kind_mask, first_number, end_number);
        const auto matches = [&](const access_event& event) {
            return (kind_mask & static_cast<uint64_t>(event.kind)) && overlaps(event.address, event.size, address, size);
        };
        if (this->chunked())
        {
            // Execute events carry their bytes from the code table; only data accesses need the chunk's values.
            return matching_events(ranges, matches, (kind_mask & ~static_cast<uint64_t>(access_kind::execute)) != 0);
        }
        for (const auto& range : ranges)
        {
            for (auto number = range.begin; number < range.end; ++number)
            {
                const auto event = event_at(number);
                if (matches(event))
                {
                    result.push_back(event);
                }
            }
        }
        return result;
    }

    std::optional<access_event> trace::next_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask)
    {
        if (!size || step == UINT64_MAX)
        {
            return std::nullopt;
        }
        const auto last = last_byte(address, size);
        for (const auto& range :
             candidates(address / page_size, last / page_size, kind_mask, first_event_after(step), metadata_.event_count))
        {
            for (auto number = range.begin; number < range.end; ++number)
            {
                const auto event = event_at(number);
                if ((kind_mask & static_cast<uint64_t>(event.kind)) && overlaps(event.address, event.size, address, size))
                {
                    return event;
                }
            }
        }
        return std::nullopt;
    }

    std::optional<access_event> trace::previous_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask)
    {
        if (!size || !step)
        {
            return std::nullopt;
        }
        const auto last = last_byte(address, size);
        const auto ranges = candidates(address / page_size, last / page_size, kind_mask, 0, first_event_after(step - 1));
        for (const auto& range : std::views::reverse(ranges))
        {
            for (auto number = range.end; number-- > range.begin;)
            {
                const auto event = event_at(number);
                if ((kind_mask & static_cast<uint64_t>(event.kind)) && overlaps(event.address, event.size, address, size))
                {
                    return event;
                }
            }
        }
        return std::nullopt;
    }

    std::vector<std::optional<uint8_t>> trace::memory_at(const uint64_t position, const uint64_t address, const uint64_t size)
    {
        if (position > metadata_.instruction_count)
        {
            throw std::out_of_range("TTD position is beyond end of trace");
        }
        std::vector<std::optional<uint8_t>> value(static_cast<size_t>(size));
        if (!size)
        {
            return value;
        }
        // Per byte: whether an access settled it, and whether the latest access up to the position was found (an older
        // one says less).
        std::vector<bool> settled(value.size());
        std::vector<bool> seen_before(value.size());
        auto unsettled = value.size();
        auto unseen_before = value.size();
        const auto boundary = first_event_after(position);
        const auto event_bytes = [&](const access_event& event) {
            if (event.kind != access_kind::execute)
            {
                return access_data(event);
            }
            const auto* bytes = reinterpret_cast<const std::byte*>(event.payload.data());
            return std::vector<std::byte>(bytes, bytes + event.size);
        };
        const auto last = last_byte(address, size);

        // The latest access up to the position shows a byte, unless its memory was mapped or unmapped since.
        for (const auto& range : std::views::reverse(candidates(address / page_size, last / page_size, all_access_kinds, 0, boundary)))
        {
            for (auto number = range.end; unseen_before && number-- > range.begin;)
            {
                const auto event = event_at(number);
                if (!overlaps(event.address, event.size, address, size))
                {
                    continue;
                }
                std::vector<std::byte> data{};
                for (auto byte = std::max(event.address, address); byte < std::min(event.address + event.size, address + size); ++byte)
                {
                    const auto index = static_cast<size_t>(byte - address);
                    if (seen_before[index])
                    {
                        continue;
                    }
                    seen_before[index] = true;
                    --unseen_before;
                    if (remapped(byte, number, boundary))
                    {
                        continue;
                    }
                    if (data.empty())
                    {
                        data = event_bytes(event);
                    }
                    value[index] = static_cast<uint8_t>(data.at(static_cast<size_t>(byte - event.address)));
                    settled[index] = true;
                    --unsettled;
                }
            }
        }

        // Other bytes still hold what the first later access reads or executes, unless something changed them before.
        for (const auto& range : candidates(address / page_size, last / page_size, all_access_kinds, boundary, metadata_.event_count))
        {
            for (auto number = range.begin; unsettled && number < range.end; ++number)
            {
                const auto event = event_at(number);
                if (!overlaps(event.address, event.size, address, size))
                {
                    continue;
                }
                const auto shows = event.kind == access_kind::read || event.kind == access_kind::execute;
                std::vector<std::byte> data{};
                for (auto byte = std::max(event.address, address); byte < std::min(event.address + event.size, address + size); ++byte)
                {
                    const auto index = static_cast<size_t>(byte - address);
                    if (settled[index])
                    {
                        continue;
                    }
                    settled[index] = true;
                    --unsettled;
                    if (!shows || remapped(byte, boundary, number))
                    {
                        continue;
                    }
                    if (data.empty())
                    {
                        data = event_bytes(event);
                    }
                    value[index] = static_cast<uint8_t>(data.at(static_cast<size_t>(byte - event.address)));
                }
            }
        }
        return value;
    }

    bool trace::remapped(const uint64_t address, const uint64_t after_number, const uint64_t through_number) const
    {
        const auto first = std::ranges::upper_bound(mapping_changes_, after_number, {}, &mapping_change::event_number);
        for (auto change = first; change != mapping_changes_.end() && change->event_number <= through_number; ++change)
        {
            if (address - change->address < change->size)
            {
                return true;
            }
        }
        return false;
    }

    event_reader::event_reader(trace& recorded, const uint64_t first_number)
        : trace_(recorded),
          buffer_first_(first_number),
          last_number_(first_number ? first_number - 1 : 0)
    {
    }

    std::optional<access_event> event_reader::next(const uint64_t kind_mask)
    {
        constexpr size_t buffer_events = 16384;
        while (true)
        {
            if (position_ == buffer_.size())
            {
                buffer_first_ += buffer_.size();
                buffer_.resize(buffer_events);
                buffer_.resize(trace_.read_events(buffer_first_, buffer_));
                position_ = 0;
                if (buffer_.empty())
                {
                    return std::nullopt;
                }
            }
            const auto& event = buffer_[position_];
            last_number_ = buffer_first_ + position_++;
            if (kind_mask & static_cast<uint64_t>(event.kind))
            {
                return event;
            }
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
        if (access_mask_ & static_cast<uint64_t>(access_kind::execute))
        {
            execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t address, size_t size) {
                verify(access_kind::execute, address, executed_size(emu_, address, size));
            }));
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
        if (error_ || !size || substituting_)
        {
            return;
        }
        if (write_observer_ && (kind == access_kind::write || kind == access_kind::host_write))
        {
            write_observer_(address, size);
        }
        access_event observed{.step = emu_.get_executed_instructions(),
                              .ip = emu_.emu().read_instruction_pointer(),
                              .address = address,
                              .size = size,
                              .kind = kind};
        if (kind == access_kind::execute && trace_.has_instruction_bytes() && size < inline_data_limit)
        {
            emu_.emu().try_read_memory(address, observed.payload.data(), size);
        }
        if (in_syscall_)
        {
            syscall_events_.push_back({.event = observed,
                                       .previous = kind == access_kind::host_write ? std::move(previous_bytes_) : std::vector<std::byte>{},
                                       .data = {data.begin(), data.end()}});
            previous_bytes_ = {};
            return;
        }
        const auto expected = reader_.next(access_mask_);
        const auto same_event = expected && expected->kind == observed.kind && expected->step == observed.step &&
                                expected->ip == observed.ip && expected->address == observed.address && expected->size == observed.size;
        const auto same_instruction =
            kind != access_kind::execute || !trace_.has_instruction_bytes() || (same_event && expected->payload == observed.payload);
        const auto same_data = kind == access_kind::execute || !trace_.has_access_data() ||
                               (same_event && std::ranges::equal(trace_.access_data(*expected), data));
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

    void replay_verifier::finish()
    {
        syscall_enter_.reset();
        syscall_exit_.reset();
        host_write_before_hook_.remove();
        write_hook_.remove();
        read_hook_.remove();
        execute_hook_.remove();
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

    std::optional<trace_difference> first_difference(trace& first, trace& second)
    {
        const auto kinds = first.access_mask() & second.access_mask();
        if (!kinds)
        {
            throw std::runtime_error("The TTD traces record no common access kind");
        }
        const auto start = std::max(first.start_position(), second.start_position());
        const auto end = std::min(first.metadata().instruction_count, second.metadata().instruction_count);
        const auto instruction_bytes = first.has_instruction_bytes() && second.has_instruction_bytes();
        const auto access_data = first.has_access_data() && second.has_access_data();
        event_reader first_reader(first, first.first_event_after(start));
        event_reader second_reader(second, second.first_event_after(start));
        const auto next = [&](event_reader& reader) {
            auto event = reader.next(kinds);
            return event && event->step <= end ? event : std::nullopt;
        };
        while (true)
        {
            const auto a = next(first_reader);
            const auto b = next(second_reader);
            if (!a && !b)
            {
                return std::nullopt;
            }
            auto same =
                a && b && a->kind == b->kind && a->step == b->step && a->ip == b->ip && a->address == b->address && a->size == b->size;
            const auto compare_payload = a && (a->kind == access_kind::execute ? instruction_bytes && a->size < inline_data_limit
                                                                               : access_data && a->size <= inline_data_limit);
            if (same && compare_payload)
            {
                same = std::ranges::equal(std::span(a->payload).first(static_cast<size_t>(a->size)),
                                          std::span(b->payload).first(static_cast<size_t>(b->size)));
            }
            else if (same && access_data && a->kind != access_kind::execute)
            {
                same = first.access_data(*a) == second.access_data(*b);
            }
            if (!same)
            {
                return trace_difference{
                    .first_number = first_reader.last_number(), .first = a, .second_number = second_reader.last_number(), .second = b};
            }
        }
    }

    std::vector<self_modifying_hit> trace::self_modifying_code()
    {
        using written_bytes = std::array<uint64_t, page_size / 64>;
        std::unordered_map<uint64_t, written_bytes> written{};

        struct pending_hit
        {
            access_event execution;
            uint64_t writer_number;
            uint64_t count;
        };

        const auto is_written = [&](const uint64_t address) {
            const auto page = written.find(address / page_size);
            return page != written.end() && (page->second[(address % page_size) / 64] & (uint64_t{1} << (address % 64)));
        };

        std::map<uint64_t, pending_hit> hits{};
        event_reader reader(*this);
        const auto kinds = static_cast<uint64_t>(access_kind::write) | static_cast<uint64_t>(access_kind::execute);
        while (const auto event = reader.next(kinds))
        {
            if (!event->size)
            {
                continue;
            }
            const auto last = last_byte(event->address, event->size);
            for (uint64_t address = event->address;; ++address)
            {
                if (event->kind == access_kind::write)
                {
                    written[address / page_size][(address % page_size) / 64] |= uint64_t{1} << (address % 64);
                }
                else if (is_written(address))
                {
                    auto [it, inserted] =
                        hits.try_emplace(event->address, pending_hit{.execution = *event, .writer_number = 0, .count = 0});
                    if (inserted)
                    {
                        const auto writer = latest_write_to_byte(address / page_size, address, 0, reader.last_number());
                        if (!writer)
                        {
                            throw std::runtime_error("TTD index is missing a recorded write");
                        }
                        it->second.writer_number = *writer;
                    }
                    ++it->second.count;
                    break;
                }
                if (address == last)
                {
                    break;
                }
            }
        }
        std::vector<self_modifying_hit> result{};
        result.reserve(hits.size());
        for (const auto& [address, hit] : hits)
        {
            const auto write = event_at(hit.writer_number);
            result.push_back({.address = address,
                              .size = hit.execution.size,
                              .write_step = write.step,
                              .write_ip = write.ip,
                              .execute_step = hit.execution.step,
                              .execute_ip = hit.execution.ip,
                              .executions = hit.count});
        }
        return result;
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
