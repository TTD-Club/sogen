#include "ttd_trace.hpp"
#include "snapshot_format.hpp"

#include <utils/compression.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cstring>
#include <future>
#include <iomanip>
#include <map>
#include <mutex>
#include <ranges>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>

#define XXH_INLINE_ALL
#include <common/xxhash.h>

namespace sogen::ttd
{
    static_assert(std::endian::native == std::endian::little, "TTD trace requires a little-endian host");

    namespace
    {
        constexpr uint64_t page_size = 4096;
        constexpr size_t cached_chunks = 4;
        constexpr size_t cached_bulk_blocks = bulk_reference_span + 1;

        // "SOGTTD<digit>\0" at the start of every trace file, the digit being the format version.
        std::optional<uint32_t> version_from_magic(const std::array<char, 8>& magic)
        {
            const std::string_view name(magic.data(), magic.size());
            if (!name.starts_with("SOGTTD") || magic[7] != '\0' || magic[6] < '1' || magic[6] > '9')
            {
                return std::nullopt;
            }
            return static_cast<uint32_t>(magic[6] - '0');
        }

        // What an instruction does to control flow, from its bytes alone.
        struct branch_info
        {
            bool is_call{};
            bool is_jump{};
            bool is_return{};
            // Through a register or memory operand.
            bool indirect{};
        };

        branch_info classify_branch(const std::span<const uint8_t> bytes)
        {
            size_t i = 0;
            // Legacy prefixes (operand/address size, lock, rep/bnd, segments).
            while (i < bytes.size() &&
                   (bytes[i] == 0x66 || bytes[i] == 0x67 || bytes[i] == 0xF0 || bytes[i] == 0xF2 || bytes[i] == 0xF3 || bytes[i] == 0x2E ||
                    bytes[i] == 0x36 || bytes[i] == 0x3E || bytes[i] == 0x26 || bytes[i] == 0x64 || bytes[i] == 0x65))
            {
                ++i;
            }
            // A REX prefix. In 32-bit code 0x40-0x4F are INC/DEC, which are whole one-byte instructions, so a byte that
            // more of the instruction follows is a prefix in either mode.
            if (i + 1 < bytes.size() && (bytes[i] & 0xF0) == 0x40)
            {
                ++i;
            }
            if (i >= bytes.size())
            {
                return {};
            }
            switch (bytes[i])
            {
            case 0xE8:
            case 0x9A:
                return {.is_call = true};
            case 0xE9:
            case 0xEB:
            case 0xEA:
                return {.is_jump = true};
            case 0xC2:
            case 0xC3:
            case 0xCA:
            case 0xCB:
                return {.is_return = true};
            case 0xFF: {
                if (i + 1 >= bytes.size())
                {
                    return {};
                }
                const auto operation = (bytes[i + 1] >> 3) & 7;
                if (operation == 2 || operation == 3)
                {
                    return {.is_call = true, .indirect = true};
                }
                if (operation == 4 || operation == 5)
                {
                    return {.is_jump = true, .indirect = true};
                }
                return {};
            }
            default:
                return {};
            }
        }

        branch_info classify_branch(const access_event& execute)
        {
            const auto size = std::min<size_t>(static_cast<size_t>(execute.size), execute.payload.size());
            return classify_branch(std::span(execute.payload).first(size));
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

        bool overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
        {
            return as && bs && a <= b + std::min(bs - 1, UINT64_MAX - b) && b <= a + std::min(as - 1, UINT64_MAX - a);
        }

        uint64_t last_byte(const uint64_t address, const uint64_t size)
        {
            return address + std::min<uint64_t>(size - 1, UINT64_MAX - address);
        }

        constexpr uint64_t max_manifest_size = 1024 * 1024;

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
        const auto version = version_from_magic(magic);
        if (!version)
        {
            throw std::runtime_error("Not a Sogen TTD trace: " + path.string());
        }
        if (!is_supported_trace_version(*version))
        {
            throw std::runtime_error("Unsupported TTD trace format version " + std::to_string(*version) + " (this build reads " +
                                     std::to_string(oldest_trace_version) + "-4 and 7-" + std::to_string(newest_trace_version) + ")");
        }
        version_ = *version;
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
        compute_id();
    }

    void trace::compute_id()
    {
        if (const auto stored = manifest_value(trace_id_key))
        {
            id_ = *stored;
            return;
        }
        // Older recordings: a hash of what identifies the file's contents without reading all of it: the header, the
        // checkpoint table (offsets and sizes differ between any two recordings), and the chunk table.
        std::vector<std::byte> identity(64);
        file_.clear();
        file_.seekg(0);
        file_.read(reinterpret_cast<char*>(identity.data()), static_cast<std::streamsize>(identity.size()));
        identity.resize(static_cast<size_t>(file_.gcount()));
        const auto append = [&](const auto& values) {
            const auto bytes = std::as_bytes(std::span(values));
            identity.insert(identity.end(), bytes.begin(), bytes.end());
        };
        append(checkpoints_);
        append(chunks_);
        std::ostringstream id{};
        id << 'h' << std::hex << std::setfill('0') << std::setw(16) << XXH64(identity.data(), identity.size(), 0) << std::setw(16)
           << XXH64(identity.data(), identity.size(), 1);
        id_ = id.str();
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
        std::optional<std::vector<std::byte>> machines{};
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
                has_mapping_changes_ = true;
            }
            else if (section.type == section_type::modules || section.type == section_type::threads ||
                     section.type == section_type::exports || section.type == section_type::export_forwarders ||
                     section.type == section_type::module_machines)
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
                else if (section.type == section_type::module_machines)
                {
                    machines = std::move(bytes);
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
        if (machines)
        {
            decode_module_machines(*machines, modules_);
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

    std::vector<access_event> trace::calls(const std::string_view name, const uint64_t start, const uint64_t end,
                                           const operation_control& control)
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
        // Progress counts targets; each query only checks for interruption.
        const operation_control check_only{.interrupted = control.interrupted};
        for (size_t done = 0; done < targets.size(); ++done)
        {
            control.report(done, targets.size());
            const auto& [address, first, last] = targets[done];
            for (const auto& event : accesses(address, 1, first, last, static_cast<uint64_t>(access_kind::execute), check_only))
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
                                                     const std::function<bool(const access_event&)>& matches, const bool with_data,
                                                     const operation_control& control)
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
            control.report(first + batch.size(), ranges.size());
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

    std::vector<access_event> trace::accesses(uint64_t address, uint64_t size, uint64_t first_step, uint64_t last_step, uint64_t kind_mask,
                                              const operation_control& control)
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
            return matching_events(ranges, matches, (kind_mask & ~static_cast<uint64_t>(access_kind::execute)) != 0, control);
        }
        for (size_t done = 0; done < ranges.size(); ++done)
        {
            const auto& range = ranges[done];
            control.report(done, ranges.size());
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

    std::vector<std::optional<uint8_t>> trace::memory_at(const uint64_t position, const uint64_t address, const uint64_t size,
                                                         const operation_control& control)
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
        const auto before = candidates(address / page_size, last / page_size, all_access_kinds, 0, boundary);
        const auto after = candidates(address / page_size, last / page_size, all_access_kinds, boundary, metadata_.event_count);
        const auto total = before.size() + after.size();
        uint64_t done = 0;

        // The latest access up to the position shows a byte, unless its memory was mapped or unmapped since.
        for (const auto& range : std::views::reverse(before))
        {
            control.report(done++, total);
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
        for (const auto& range : after)
        {
            if (!unsettled)
            {
                break;
            }
            control.report(done++, total);
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

    std::vector<self_modifying_hit> trace::self_modifying_code(const operation_control& control)
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
        constexpr uint64_t report_interval = 1 << 20;
        uint64_t next_report = 0;
        while (const auto event = reader.next(kinds))
        {
            if (reader.last_number() >= next_report)
            {
                control.report(reader.last_number(), metadata_.event_count);
                next_report = reader.last_number() + report_interval;
            }
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

    std::optional<uint32_t> trace_file_version(const std::filesystem::path& path)
    {
        std::ifstream file(path, std::ios::binary);
        std::array<char, 8> magic{};
        if (!file.read(magic.data(), magic.size()))
        {
            return std::nullopt;
        }
        return version_from_magic(magic);
    }

    bool is_trace_file(const std::filesystem::path& path)
    {
        return trace_file_version(path).has_value();
    }

    bool is_supported_trace_version(const uint32_t version)
    {
        // Versions 5 and 6 were development formats that were never kept.
        return version >= oldest_trace_version && version <= newest_trace_version && version != 5 && version != 6;
    }

    std::optional<access_event> trace::execute_at(const uint64_t position)
    {
        if (!position || position > metadata_.instruction_count)
        {
            return std::nullopt;
        }
        // The execute event comes first among an instruction's events.
        for (auto number = first_event_at_or_after(position); number < metadata_.event_count; ++number)
        {
            const auto event = event_at(number);
            if (event.step != position)
            {
                break;
            }
            if (event.kind == access_kind::execute)
            {
                return event;
            }
        }
        return std::nullopt;
    }

    std::optional<access_event> trace::previous_instruction(const uint64_t step, const uint32_t thread_id)
    {
        if (step <= start_position() + 1)
        {
            return std::nullopt;
        }
        const auto& switches = threads_.switches;
        if (switches.empty())
        {
            return execute_at(step - 1);
        }
        // The run of the thread that holds position step - 1 or ends before it: a run starts at a switch and lasts until
        // the next one.
        auto next = std::ranges::upper_bound(switches, step - 1, {}, &thread_switch::step);
        while (next != switches.begin())
        {
            const auto run = std::prev(next);
            if (run->thread_id == thread_id)
            {
                const auto last = next == switches.end() ? step - 1 : std::min(step - 1, next->step - 1);
                return last > start_position() ? execute_at(last) : std::nullopt;
            }
            next = run;
        }
        return std::nullopt;
    }

    std::optional<access_event> trace::next_instruction(const uint64_t step, const uint32_t thread_id)
    {
        const auto& switches = threads_.switches;
        if (switches.empty())
        {
            return execute_at(step + 1);
        }
        auto next = std::ranges::upper_bound(switches, step, {}, &thread_switch::step);
        const auto running = next == switches.begin() ? std::nullopt : std::optional(std::prev(next)->thread_id);
        if (running == thread_id && (next == switches.end() || next->step > step + 1))
        {
            return execute_at(step + 1);
        }
        for (; next != switches.end(); ++next)
        {
            if (next->thread_id == thread_id)
            {
                return execute_at(next->step);
            }
        }
        return std::nullopt;
    }

    std::optional<uint64_t> trace::return_of_call(const access_event& call, const uint64_t entry_step, const uint32_t thread_id)
    {
        constexpr auto reads_and_writes = static_cast<uint64_t>(access_kind::read) | static_cast<uint64_t>(access_kind::write);
        if ((access_mask() & reads_and_writes) != reads_and_writes || !has_access_data())
        {
            return std::nullopt;
        }
        // The call pushed its return address: that stack slot identifies the invocation, also under recursion.
        const auto return_address = call.ip + call.size;
        std::optional<access_event> push{};
        for (auto number = first_event_at_or_after(call.step); number < metadata_.event_count; ++number)
        {
            const auto event = event_at(number);
            if (event.step != call.step)
            {
                break;
            }
            if (event.kind != access_kind::write || (event.size != 8 && event.size != 4))
            {
                continue;
            }
            uint64_t pushed{};
            memcpy(&pushed, event.payload.data(), static_cast<size_t>(event.size));
            const auto expected = event.size == 8 ? return_address : (return_address & 0xFFFFFFFF);
            if (pushed == expected)
            {
                push = event;
                break;
            }
        }
        if (!push)
        {
            return std::nullopt;
        }
        // The invocation returns at the first return instruction that reads the slot. A write to the slot first means the
        // frame is gone (unwound, or the thread left it another way); reads by other instructions (_ReturnAddress, stack
        // walks) do not end it.
        constexpr auto slot_accesses = reads_and_writes | static_cast<uint64_t>(access_kind::host_write);
        for (auto from = entry_step - 1;;)
        {
            const auto access = next_access(push->address, push->size, from, slot_accesses);
            if (!access || access->kind != access_kind::read)
            {
                return std::nullopt;
            }
            from = access->step;
            if (access->address != push->address || access->size != push->size || thread_at(access->step).value_or(thread_id) != thread_id)
            {
                continue;
            }
            if (const auto instruction = execute_at(access->step); instruction && classify_branch(*instruction).is_return)
            {
                return access->step;
            }
        }
    }

    std::vector<call_event> trace::calls_to(const uint64_t address, const uint64_t start, const uint64_t end,
                                            const operation_control& control)
    {
        if (!(access_mask() & static_cast<uint64_t>(access_kind::execute)))
        {
            throw std::runtime_error("TTD call queries need a trace recorded with execute events");
        }
        std::vector<access_event> entries{};
        for (const auto& event : accesses(address, 1, start, end, static_cast<uint64_t>(access_kind::execute), control))
        {
            if (event.address == address)
            {
                entries.push_back(event);
            }
        }

        std::vector<call_event> result{};
        result.reserve(entries.size());
        for (size_t done = 0; done < entries.size(); ++done)
        {
            control.report(done, entries.size());
            const auto& entry = entries[done];
            const auto thread_id = thread_at(entry.step).value_or(0);
            call_event call{.entry_step = entry.step, .target = address, .thread_id = thread_id};
            if (const auto previous = previous_instruction(entry.step, thread_id))
            {
                call.step = previous->step;
                call.site = previous->ip;
                call.is_call = classify_branch(*previous).is_call;
                if (call.is_call)
                {
                    call.return_step = return_of_call(*previous, entry.step, thread_id).value_or(UINT64_MAX);
                }
            }
            result.push_back(call);
        }
        return result;
    }

    std::vector<indirect_branch> trace::indirect_branches(const std::span<const std::pair<uint64_t, uint64_t>> ranges, const bool jumps,
                                                          const operation_control& control)
    {
        if (!(access_mask() & static_cast<uint64_t>(access_kind::execute)) || !has_instruction_bytes())
        {
            throw std::runtime_error("TTD branch queries need a trace recorded with execute events and their bytes");
        }
        const auto in_ranges = [&](const uint64_t ip) {
            return std::ranges::any_of(ranges, [&](const auto& range) { return range.second && ip - range.first < range.second; });
        };
        const auto wanted = [&](const access_event& event) {
            if (event.kind != access_kind::execute || !in_ranges(event.ip))
            {
                return false;
            }
            const auto branch = classify_branch(event);
            return branch.indirect && (branch.is_call || (jumps && branch.is_jump));
        };

        std::set<std::pair<uint64_t, uint64_t>> chunk_ranges{};
        for (const auto& [address, size] : ranges)
        {
            if (!size)
            {
                continue;
            }
            for (const auto& range : candidates(address / page_size, last_byte(address, size) / page_size,
                                                static_cast<uint64_t>(access_kind::execute), 0, metadata_.event_count))
            {
                chunk_ranges.emplace(range.begin, range.end);
            }
        }
        // Overlapping candidate lists (legacy traces list single events) merge into disjoint ranges.
        std::vector<number_range> merged{};
        for (const auto& [begin, end] : chunk_ranges)
        {
            if (!merged.empty() && begin < merged.back().end)
            {
                merged.back().end = std::max(merged.back().end, end);
            }
            else
            {
                merged.push_back({.begin = begin, .end = end});
            }
        }

        std::vector<access_event> sites{};
        if (this->chunked())
        {
            sites = matching_events(merged, wanted, false, control);
        }
        else
        {
            for (size_t done = 0; done < merged.size(); ++done)
            {
                control.report(done, merged.size());
                for (auto number = merged[done].begin; number < merged[done].end; ++number)
                {
                    if (const auto event = event_at(number); wanted(event))
                    {
                        sites.push_back(event);
                    }
                }
            }
        }

        // A branch that faults reaches the exception dispatcher instead of its target.
        std::set<uint64_t> dispatchers{};
        for (const auto& found : find_exports("ntdll.dll!KiUserExceptionDispatcher"))
        {
            if (found.symbol->forwarder.empty())
            {
                dispatchers.insert(found.module->base + found.symbol->rva);
            }
        }

        std::map<std::pair<uint64_t, uint64_t>, indirect_branch> found{};
        for (size_t i = 0; i < sites.size(); ++i)
        {
            if (i % 4096 == 0)
            {
                control.check();
            }
            const auto& site = sites[i];
            const auto next = next_instruction(site.step, thread_at(site.step).value_or(0));
            if (!next || dispatchers.contains(next->ip))
            {
                continue;
            }
            auto [entry, inserted] = found.try_emplace(
                {site.ip, next->ip},
                indirect_branch{.site = site.ip, .target = next->ip, .first_step = site.step, .is_call = classify_branch(site).is_call});
            ++entry->second.hits;
        }
        std::vector<indirect_branch> result{};
        result.reserve(found.size());
        for (const auto& branch : found | std::views::values)
        {
            result.push_back(branch);
        }
        return result;
    }

    std::vector<exception_event> trace::exceptions(const operation_control& control)
    {
        constexpr auto needed = static_cast<uint64_t>(access_kind::execute) | static_cast<uint64_t>(access_kind::host_write);
        if ((access_mask() & needed) != needed || !has_access_data())
        {
            throw std::runtime_error("TTD exception queries need a trace recorded with execute and host write events");
        }
        // The 64-bit EXCEPTION_RECORD: code, flags, nested record, address, parameter count, then the parameters. The
        // dispatch writes it in one host write just before the dispatcher runs (also for exceptions in WoW64 code).
        constexpr uint64_t record_size = 0x98;
        constexpr uint64_t record_lookback = 64;

        std::vector<exception_event> result{};
        for (const auto& dispatcher : find_exports("ntdll.dll!KiUserExceptionDispatcher"))
        {
            if (!dispatcher.symbol->forwarder.empty())
            {
                continue;
            }
            const auto address = dispatcher.module->base + dispatcher.symbol->rva;
            const auto last = dispatcher.module->unload_step.value_or(UINT64_MAX);
            for (const auto& entry :
                 accesses(address, 1, dispatcher.module->load_step, last, static_cast<uint64_t>(access_kind::execute), control))
            {
                if (entry.address != address)
                {
                    continue;
                }
                const auto thread_id = thread_at(entry.step).value_or(0);
                exception_event exception{.step = entry.step, .thread_id = thread_id};
                const auto entry_number = first_event_at_or_after(entry.step);
                for (auto number = entry_number; number-- > 0 && entry_number - number <= record_lookback;)
                {
                    const auto event = event_at(number);
                    if (event.kind != access_kind::host_write || event.size != record_size)
                    {
                        continue;
                    }
                    const auto record = access_data(event);
                    memcpy(&exception.code, record.data(), sizeof(exception.code));
                    memcpy(&exception.flags, record.data() + 0x4, sizeof(exception.flags));
                    memcpy(&exception.address, record.data() + 0x10, sizeof(exception.address));
                    memcpy(exception.information.data(), record.data() + 0x20, sizeof(exception.information));
                    // The dispatch happens between instructions: the raising instruction is the thread's last one.
                    if (const auto raised = previous_instruction(entry.step, thread_id))
                    {
                        exception.raise_step = raised->step;
                    }
                    break;
                }
                result.push_back(exception);
            }
        }
        std::ranges::sort(result, {}, &exception_event::step);
        return result;
    }
}
