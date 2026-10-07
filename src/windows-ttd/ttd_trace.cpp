#include "ttd_trace.hpp"
#include "snapshot.hpp"

#include <disassembler.hpp>

#include <utils/compression.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <future>
#include <map>
#include <sstream>
#include <stdexcept>
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
        uint64_t executed_size(windows_emulator& emu, const uint64_t address, const size_t reported)
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
            return decoded.empty() ? 1 : decoded[0].size;
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

        // Versions 1-4 stored every event as a fixed-size record, followed by full checkpoint snapshots and a
        // per-event page index. They remain readable.
        struct v1_header
        {
            char magic[8]{};
            uint64_t snapshot_size{};
            uint64_t instruction_count{};
            uint64_t write_count{};
            uint64_t index_offset{};
            uint64_t index_count{};
        };

        struct v4_header
        {
            char magic[8]{};
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
        if (size < inline_data_limit && !emu_.emu().try_read_memory(address, event.payload.data(), size))
        {
            throw std::runtime_error("Cannot read executed instruction bytes");
        }
        push_event(event);
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

    void recorder::push_event(const access_event& event)
    {
        chunk_events_.push_back(event);
        ++header_.event_count;
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
        write_hook_.remove();
        read_hook_.remove();
        execute_hook_.remove();
        host_write_hook_.remove();
        flush_chunk();
        close_bulk_block();
        write_compressed(true);
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
        const std::array sections{
            section_entry{.type = section_type::chunk_table, .offset = append_to_file(bytes_of(chunks_)), .size = chunks_.size()},
            section_entry{
                .type = section_type::checkpoint_table, .offset = append_to_file(bytes_of(checkpoints_)), .size = checkpoints_.size()},
            section_entry{.type = section_type::page_index, .offset = append_to_file(bytes_of(page_blocks)), .size = page_blocks.size()},
            section_entry{.type = section_type::code_table, .offset = append_to_file(code), .size = code.size()},
            section_entry{.type = section_type::bulk_table, .offset = append_to_file(bytes_of(bulk_table_)), .size = bulk_table_.size()},
            section_entry{.type = section_type::manifest, .offset = append_to_file(manifest), .size = manifest.size()},
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
        : file_(path, std::ios::binary)
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
        if (name.substr(0, 6) != "SOGTTD" || magic[7] != '\0' || magic[6] < '1' || magic[6] > '9')
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
        legacy_event_size_ = version_ <= 2 ? sizeof(v1_event) : version_ == 3 ? sizeof(v3_event) : sizeof(access_event);
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

    std::vector<bulk_block> trace::bulk_range(const uint64_t first, const uint64_t end)
    {
        if (end < first || end - first > cached_bulk_blocks || end > bulk_table_.size())
        {
            throw std::runtime_error("Invalid TTD bulk block range");
        }
        std::vector<bulk_block> blocks(static_cast<size_t>(end - first));
        std::vector<std::pair<uint64_t, std::future<std::vector<std::byte>>>> decoding{};
        for (auto index = first; index < end; ++index)
        {
            const auto& entry = bulk_table_[static_cast<size_t>(index)];
            if (!entry.size || std::ranges::find(bulk_cache_, index, &cached_bulk::index) != bulk_cache_.end())
            {
                blocks[static_cast<size_t>(index - first)] = bulk(index);
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
            blocks[static_cast<size_t>(index - first)] = std::move(block);
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

    std::vector<std::byte> trace::checkpoint_state_at(const uint64_t index)
    {
        if (!this->chunked())
        {
            const auto& entry = checkpoints_.at(static_cast<size_t>(index));
            return snapshot::get_emulator_state(read_bytes(entry.offset, entry.size));
        }

        std::vector<uint64_t> chain{index};
        while (checkpoints_.at(static_cast<size_t>(chain.back())).base != no_base_checkpoint &&
               (!state_cache_ || state_cache_->first != chain.back()))
        {
            chain.push_back(checkpoints_.at(static_cast<size_t>(chain.back())).base);
        }
        // A delta's reference is its base state followed by the bulk blocks in between. Each restored state is
        // decompressed with room for the next delta's blocks, so they can be appended in place instead of copying the
        // state into a new reference buffer.
        const auto blocks_between = [this](const uint64_t current) {
            const auto base = checkpoints_.at(static_cast<size_t>(current)).base;
            if (base == no_base_checkpoint || current - base > bulk_reference_span)
            {
                return std::vector<bulk_block>{};
            }
            return bulk_range(base, current);
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
        if (state_cache_ && state_cache_->first == chain.back())
        {
            chain.pop_back();
            const auto& cached = state_cache_->second;
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
        state_cache_ = std::make_pair(index, state);
        return state;
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

    checkpoint_state trace::checkpoint_for_step(const uint64_t step)
    {
        if (step > metadata_.instruction_count)
        {
            throw std::out_of_range("TTD position is beyond end of trace");
        }
        if (step < this->start_position())
        {
            throw std::out_of_range("TTD position is before the start of the trace");
        }
        const auto next = std::ranges::upper_bound(checkpoints_, step, {}, &checkpoint_entry::step);
        const auto index = static_cast<uint64_t>(next - checkpoints_.begin() - 1);
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
        const auto ranges = candidates(page, page, static_cast<uint64_t>(access_kind::write), first_number, end_number);
        for (auto range = ranges.rbegin(); range != ranges.rend(); ++range)
        {
            for (auto number = range->end; number-- > range->begin;)
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
        for (const auto& range : candidates(address / page_size, last / page_size, kind_mask, first_number, end_number))
        {
            for (auto number = range.begin; number < range.end; ++number)
            {
                const auto event = event_at(number);
                if ((kind_mask & static_cast<uint64_t>(event.kind)) && overlaps(event.address, event.size, address, size))
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
        for (auto range = ranges.rbegin(); range != ranges.rend(); ++range)
        {
            for (auto number = range->end; number-- > range->begin;)
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

    replay_verifier::replay_verifier(windows_emulator& emu, trace& recorded, const uint64_t from_step)
        : emu_(emu),
          trace_(recorded),
          reader_(recorded, recorded.first_event_after(from_step)),
          access_mask_(recorded.access_mask())
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
    }

    void replay_verifier::verify(const access_kind kind, const uint64_t address, const size_t size, const std::span<const std::byte> data)
    {
        if (error_ || !size)
        {
            return;
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
        const auto describe = [](std::ostream& stream, const access_event& event) {
            stream << access_kind_name(event.kind) << " step=" << std::hex << event.step << " ip=" << event.ip
                   << " address=" << event.address << std::dec << " size=" << event.size;
        };
        if (same_event && same_instruction)
        {
            std::ostringstream message;
            message << "TTD replay diverged from the recording at event " << reader_.last_number() << ": ";
            describe(message, observed);
            message << " accessed different data";
            error_ = message.str();
            emu_.stop();
            return;
        }
        std::ostringstream message;
        message << "TTD replay diverged from the recording";
        if (expected)
        {
            message << " at event " << reader_.last_number() << ": expected ";
            describe(message, *expected);
        }
        else
        {
            message << " after its last event: expected nothing";
        }
        message << ", observed ";
        describe(message, observed);
        error_ = message.str();
        emu_.stop();
    }

    void replay_verifier::finish()
    {
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
                    auto [it, inserted] = hits.try_emplace(event->address, pending_hit{*event, 0, 0});
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
            result.push_back({address, hit.execution.size, write.step, write.ip, hit.execution.step, hit.execution.ip, hit.count});
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
                    const auto hit = self_modifying_hit{
                        address, size, writer.step, writer.ip, emu_.get_executed_instructions(), emu_.emu().read_instruction_pointer(), 1};
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
