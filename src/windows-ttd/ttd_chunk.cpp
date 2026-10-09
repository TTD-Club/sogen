#include "ttd_chunk.hpp"

#include <utils/compression.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace sogen::ttd
{
    namespace
    {
        constexpr int page_block_compression_level = 6;
        // Syscall, module, and thread tables.
        constexpr int syscall_compression_level = 19;
        constexpr size_t syscall_stream_count = 6;
        constexpr uint64_t no_previous_version = UINT64_MAX;

        constexpr uint8_t tag_kind_mask = 0x0F;
        constexpr uint8_t tag_irregular_step = 0x10;
        // Execute: a code id follows. Read: the value equals the bytes earlier events of the chunk left there.
        constexpr uint8_t tag_extra = 0x20;

        constexpr size_t tag_stream = 0;
        constexpr size_t step_stream = 1;
        constexpr size_t ip_stream = 2;
        constexpr size_t code_stream = 3;
        constexpr size_t address_stream = 4;
        constexpr size_t size_stream = 5;
        constexpr size_t data_stream = 6;
        constexpr size_t bulk_stream = 7;
        constexpr size_t stream_count = 8;

        struct chunk_header
        {
            uint64_t event_count{};
            std::array<uint64_t, stream_count> stream_sizes{};
        };

        enum class displacement_opcode : uint8_t
        {
            none,
            relative_branch,
            indirect_branch,
            rex_w,
        };

        constexpr auto displacement_opcodes = [] {
            std::array<displacement_opcode, 256> table{};
            table[0xE8] = table[0xE9] = displacement_opcode::relative_branch;
            table[0xFF] = displacement_opcode::indirect_branch;
            table[0x48] = table[0x4C] = displacement_opcode::rex_w;
            return table;
        }();

        // Distance from `p` to the 32-bit displacement of a call/jmp rel32, call/jmp [rip+disp32], or 64-bit mov/lea
        // with a RIP-relative operand starting there, or 0. Only opcode bytes before the displacement are inspected.
        size_t displacement_at(const uint8_t* p)
        {
            switch (displacement_opcodes[p[0]])
            {
            case displacement_opcode::relative_branch:
                return 1;
            case displacement_opcode::indirect_branch:
                return p[1] == 0x15 || p[1] == 0x25 ? 2 : 0;
            case displacement_opcode::rex_w:
                return (p[1] == 0x89 || p[1] == 0x8B || p[1] == 0x8D) && (p[2] & 0xC7) == 0x05 ? 3 : 0;
            case displacement_opcode::none:
                break;
            }
            return 0;
        }

        // Turns relative displacements into block offsets (or back), so repeated targets become repeated bytes. Only
        // displacements in [-2^24, 2^24) are converted, into the same range, so the decoder finds the same ones. A
        // rejected candidate skips to its displacement's last byte, so no later conversion changes a byte the
        // rejection looked at.
        void convert_displacements(const std::span<std::byte> data, const bool encode)
        {
            constexpr size_t lookahead = 8;
            if (data.size() <= lookahead)
            {
                return;
            }
            auto* bytes = reinterpret_cast<uint8_t*>(data.data());
            const auto end = data.size() - lookahead;
            for (size_t i = 0; i < end;)
            {
                const auto distance = displacement_at(bytes + i);
                if (!distance)
                {
                    ++i;
                    continue;
                }
                const auto field = i + distance;
                const auto high = bytes[field + 3];
                if (high != 0x00 && high != 0xFF)
                {
                    i = field + 3;
                    continue;
                }
                uint32_t value{};
                memcpy(&value, bytes + field, sizeof(value));
                const auto position = static_cast<uint32_t>(field);
                value = (encode ? value + position : value - position) & 0x1FFFFFF;
                if (value & 0x1000000)
                {
                    value |= 0xFE000000;
                }
                memcpy(bytes + field, &value, sizeof(value));
                i = field + sizeof(value);
            }
        }

        uint64_t zigzag(const uint64_t delta)
        {
            return (delta << 1) ^ (0 - (delta >> 63));
        }

        uint64_t unzigzag(const uint64_t value)
        {
            return (value >> 1) ^ (0 - (value & 1));
        }

        void put_varint(std::vector<std::byte>& output, uint64_t value)
        {
            while (value >= 0x80)
            {
                output.push_back(static_cast<std::byte>((value & 0x7F) | 0x80));
                value >>= 7;
            }
            output.push_back(static_cast<std::byte>(value));
        }

        class stream_reader
        {
          public:
            stream_reader() = default;

            explicit stream_reader(const std::span<const std::byte> data)
                : data_(data)
            {
            }

            uint8_t byte()
            {
                return static_cast<uint8_t>(this->bytes(1)[0]);
            }

            uint64_t varint()
            {
                uint64_t value = 0;
                for (unsigned shift = 0; shift < 64; shift += 7)
                {
                    const auto next = this->byte();
                    value |= static_cast<uint64_t>(next & 0x7F) << shift;
                    if (!(next & 0x80))
                    {
                        return value;
                    }
                }
                throw std::runtime_error("Invalid TTD event chunk varint");
            }

            std::span<const std::byte> bytes(const uint64_t count)
            {
                if (count > this->data_.size() - this->offset_)
                {
                    throw std::runtime_error("Truncated TTD event chunk");
                }
                const auto result = this->data_.subspan(this->offset_, static_cast<size_t>(count));
                this->offset_ += static_cast<size_t>(count);
                return result;
            }

            size_t offset() const
            {
                return this->offset_;
            }

            bool done() const
            {
                return this->offset_ == this->data_.size();
            }

          private:
            std::span<const std::byte> data_{};
            size_t offset_{};
        };

        void put_text(std::vector<std::byte>& output, const std::string_view text)
        {
            put_varint(output, text.size());
            const auto* bytes = reinterpret_cast<const std::byte*>(text.data());
            output.insert(output.end(), bytes, bytes + text.size());
        }

        std::string read_text(stream_reader& reader)
        {
            const auto bytes = reader.bytes(reader.varint());
            return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
        }

        // `prefix`, the stream sizes as little-endian uint64 values, and the streams, as one buffer. It is sized up front
        // and filled with memcpy: GCC 13 misreads appending byte ranges to a vector as writing past its end.
        std::vector<std::byte> join_streams(const std::span<const std::byte> prefix, const std::span<const std::vector<std::byte>> streams)
        {
            size_t total = prefix.size() + streams.size() * sizeof(uint64_t);
            for (const auto& stream : streams)
            {
                total += stream.size();
            }
            std::vector<std::byte> raw(total);
            size_t offset = 0;
            const auto append = [&](const void* data, const size_t size) {
                if (size)
                {
                    memcpy(raw.data() + offset, data, size);
                    offset += size;
                }
            };
            append(prefix.data(), prefix.size());
            for (const auto& stream : streams)
            {
                const uint64_t size = stream.size();
                append(&size, sizeof(size));
            }
            for (const auto& stream : streams)
            {
                append(stream.data(), stream.size());
            }
            return raw;
        }

        std::vector<std::byte> compress_table(const std::span<const std::byte> raw, const std::string_view name)
        {
            auto compressed = utils::compression::zstd::compress(raw, syscall_compression_level);
            if (compressed.empty())
            {
                throw std::runtime_error("Cannot compress TTD " + std::string(name));
            }
            return compressed;
        }

        // Guest memory as far as the chunk's own accesses have shown it, in pages with one validity bit per byte.
        class known_memory
        {
          public:
            void store(uint64_t address, std::span<const std::byte> data)
            {
                while (!data.empty())
                {
                    auto& page = this->page_at(address);
                    const auto offset = static_cast<size_t>(address % known_page_size);
                    const auto count = std::min(data.size(), known_page_size - offset);
                    memcpy(page.bytes.data() + offset, data.data(), count);
                    page.mark_valid(offset, count);
                    address += count;
                    data = data.subspan(count);
                }
            }

            bool load(uint64_t address, std::span<std::byte> output)
            {
                while (!output.empty())
                {
                    const auto* page = this->find_page(address);
                    const auto offset = static_cast<size_t>(address % known_page_size);
                    const auto count = std::min(output.size(), known_page_size - offset);
                    if (!page || !page->all_valid(offset, count))
                    {
                        return false;
                    }
                    memcpy(output.data(), page->bytes.data() + offset, count);
                    address += count;
                    output = output.subspan(count);
                }
                return true;
            }

          private:
            static constexpr size_t known_page_size = 4096;

            struct page
            {
                // Only bytes marked valid are ever read, so the bytes need no initialization.
                std::array<std::byte, known_page_size> bytes;
                std::array<uint64_t, known_page_size / 64> valid{};

                void mark_valid(size_t offset, const size_t count)
                {
                    const auto end = offset + count;
                    while (offset < end)
                    {
                        const auto bits = std::min<size_t>(64 - offset % 64, end - offset);
                        this->valid[offset / 64] |= (bits == 64 ? ~uint64_t{0} : ((uint64_t{1} << bits) - 1)) << (offset % 64);
                        offset += bits;
                    }
                }

                bool all_valid(size_t offset, const size_t count) const
                {
                    const auto end = offset + count;
                    while (offset < end)
                    {
                        const auto bits = std::min<size_t>(64 - offset % 64, end - offset);
                        const auto mask = (bits == 64 ? ~uint64_t{0} : ((uint64_t{1} << bits) - 1)) << (offset % 64);
                        if ((this->valid[offset / 64] & mask) != mask)
                        {
                            return false;
                        }
                        offset += bits;
                    }
                    return true;
                }
            };

            std::vector<std::unique_ptr<page>> pages_{};
            // Index in pages_ by page number.
            flat_map page_index_{};
            uint64_t last_number_{UINT64_MAX};
            page* last_page_{};

            page* find_page(const uint64_t address)
            {
                const auto number = address / known_page_size;
                if (number != this->last_number_)
                {
                    const auto* index = this->page_index_.find(number);
                    if (!index)
                    {
                        return nullptr;
                    }
                    this->last_number_ = number;
                    this->last_page_ = this->pages_[static_cast<size_t>(*index)].get();
                }
                return this->last_page_;
            }

            page& page_at(const uint64_t address)
            {
                if (auto* existing = this->find_page(address))
                {
                    return *existing;
                }
                const auto number = address / known_page_size;
                this->page_index_.set(number, this->pages_.size());
                this->pages_.push_back(std::make_unique_for_overwrite<page>());
                this->last_number_ = number;
                this->last_page_ = this->pages_.back().get();
                return *this->last_page_;
            }
        };

        struct bulk_reference
        {
            uint64_t offset{};
            uint64_t block{};
        };

        bulk_reference bulk_reference_of(const access_event& event)
        {
            bulk_reference reference{};
            memcpy(&reference.offset, event.payload.data(), sizeof(reference.offset));
            memcpy(&reference.block, event.payload.data() + sizeof(reference.offset), sizeof(reference.block));
            return reference;
        }

        // Prediction state; the encoder and the decoder update it identically after every event.
        struct predictor
        {
            uint64_t step{};
            uint64_t ip{};
            uint64_t next_ip{};
            uint64_t next_code{};
            flat_map code_at{};
            std::array<uint64_t, 16> last_address_of_kind{};
            flat_map last_address_at{};
            known_memory memory{};
            uint64_t bulk_block_index{};
            uint64_t bulk_next_offset{};

            uint64_t bulk_offset_base(const uint64_t block) const
            {
                return block == this->bulk_block_index ? this->bulk_next_offset : 0;
            }

            void remember_bulk(const bulk_reference& reference, const uint64_t size)
            {
                this->bulk_block_index = reference.block;
                this->bulk_next_offset = reference.offset + size;
            }

            static uint64_t site(const access_event& event)
            {
                return (event.ip << 4) | static_cast<uint64_t>(event.kind);
            }

            uint64_t address_base(const access_event& event) const
            {
                const auto* entry = this->last_address_at.find(site(event));
                return entry ? *entry : this->last_address_of_kind[static_cast<size_t>(event.kind)];
            }

            void remember_access(const access_event& event, const std::span<const std::byte> data)
            {
                this->last_address_at.set(site(event), event.address);
                this->last_address_of_kind[static_cast<size_t>(event.kind)] = event.address;
                this->memory.store(event.address, data);
            }
        };

        uint64_t regular_step_delta(const access_kind kind)
        {
            return kind == access_kind::execute ? 1 : 0;
        }

        bool valid_kind(const uint8_t kind)
        {
            return kind == static_cast<uint8_t>(access_kind::read) || kind == static_cast<uint8_t>(access_kind::write) ||
                   kind == static_cast<uint8_t>(access_kind::execute) || kind == static_cast<uint8_t>(access_kind::host_write);
        }

        // Keeps the most recently used bulk block alive while a chunk refers to it.
        class bulk_cursor
        {
          public:
            explicit bulk_cursor(const bulk_resolver& resolve)
                : resolve_(resolve)
            {
            }

            std::span<const std::byte> data(const bulk_reference& reference, const uint64_t size)
            {
                if (!this->block_ || reference.block != this->index_)
                {
                    this->block_ = this->resolve_(reference.block);
                    this->index_ = reference.block;
                    if (!this->block_)
                    {
                        throw std::runtime_error("Missing TTD bulk block");
                    }
                }
                const auto& bytes = *this->block_;
                if (reference.offset > bytes.size() || size > bytes.size() - reference.offset)
                {
                    throw std::runtime_error("Invalid TTD bulk data reference");
                }
                return std::span(bytes).subspan(static_cast<size_t>(reference.offset), static_cast<size_t>(size));
            }

          private:
            const bulk_resolver& resolve_;
            bulk_block block_{};
            uint64_t index_{};
        };
    }

    uint64_t code_table::id_of(const access_event& execute)
    {
        const auto* latest = this->latest_version_.find(execute.address);
        if (latest)
        {
            for (auto id = *latest; id != no_previous_version; id = this->previous_version_[static_cast<size_t>(id)])
            {
                const auto& entry = this->entries_[static_cast<size_t>(id)];
                if (entry.size == execute.size && entry.bytes == execute.payload)
                {
                    return id;
                }
            }
        }
        const auto id = static_cast<uint64_t>(this->entries_.size());
        this->entries_.push_back({.address = execute.address, .size = execute.size, .bytes = execute.payload});
        this->previous_version_.push_back(latest ? *latest : no_previous_version);
        this->latest_version_.set(execute.address, id);
        return id;
    }

    std::vector<std::byte> encode_chunk(const std::span<const access_event> events, const std::span<const uint64_t> code_ids,
                                        const chunk_bulk_bytes& bulk)
    {
        std::array<std::vector<std::byte>, stream_count> streams{};
        streams[tag_stream].reserve(events.size());
        predictor state{};
        size_t next_code_id = 0;
        const auto bulk_data = [&](const bulk_reference& reference, const uint64_t size) {
            const auto available = bulk.bytes ? bulk.bytes->size() : 0;
            if (reference.block != bulk.block || reference.offset < bulk.offset || size > available ||
                reference.offset - bulk.offset > available - size)
            {
                throw std::runtime_error("Invalid TTD bulk data reference");
            }
            return std::span(*bulk.bytes).subspan(static_cast<size_t>(reference.offset - bulk.offset), static_cast<size_t>(size));
        };

        for (const auto& event : events)
        {
            auto tag = static_cast<uint8_t>(event.kind);
            const auto execute = event.kind == access_kind::execute;
            const auto step_delta = event.step - state.step;
            if (step_delta != regular_step_delta(event.kind))
            {
                tag |= tag_irregular_step;
                put_varint(streams[step_stream], step_delta);
            }
            state.step = event.step;

            if (execute)
            {
                put_varint(streams[ip_stream], zigzag(event.ip - state.next_ip));
                put_varint(streams[address_stream], zigzag(event.address - event.ip));
                if (next_code_id == code_ids.size())
                {
                    throw std::runtime_error("Missing TTD code id");
                }
                const auto id = code_ids[next_code_id++];
                const auto* known = state.code_at.find(event.address);
                if (!known || *known != id)
                {
                    tag |= tag_extra;
                    put_varint(streams[code_stream], zigzag(id - state.next_code));
                    state.code_at.set(event.address, id);
                    state.next_code = id + 1;
                }
                state.next_ip = event.ip + event.size;
            }
            else
            {
                put_varint(streams[ip_stream], zigzag(event.ip - state.ip));
                put_varint(streams[address_stream], zigzag(event.address - state.address_base(event)));
                put_varint(streams[size_stream], event.size);
                std::span<const std::byte> data{};
                if (event.size > inline_data_limit)
                {
                    const auto reference = bulk_reference_of(event);
                    data = bulk_data(reference, event.size);
                    put_varint(streams[bulk_stream], zigzag(reference.block - state.bulk_block_index));
                    put_varint(streams[bulk_stream], zigzag(reference.offset - state.bulk_offset_base(reference.block)));
                    state.remember_bulk(reference, event.size);
                }
                else
                {
                    data = std::as_bytes(std::span(event.payload)).first(static_cast<size_t>(event.size));
                    std::array<std::byte, inline_data_limit> known{};
                    if (event.kind == access_kind::read && state.memory.load(event.address, std::span(known).first(data.size())) &&
                        std::ranges::equal(std::span(known).first(data.size()), data))
                    {
                        tag |= tag_extra;
                    }
                    else
                    {
                        streams[data_stream].insert(streams[data_stream].end(), data.begin(), data.end());
                    }
                }
                state.remember_access(event, data);
            }
            state.ip = event.ip;
            streams[tag_stream].push_back(static_cast<std::byte>(tag));
        }

        chunk_header header{.event_count = events.size()};
        size_t raw_size = sizeof(header);
        for (size_t i = 0; i < stream_count; ++i)
        {
            header.stream_sizes[i] = streams[i].size();
            raw_size += streams[i].size();
        }
        std::vector<std::byte> raw{};
        raw.reserve(raw_size);
        const auto* header_bytes = reinterpret_cast<const std::byte*>(&header);
        raw.insert(raw.end(), header_bytes, header_bytes + sizeof(header));
        for (const auto& bytes : streams)
        {
            raw.insert(raw.end(), bytes.begin(), bytes.end());
        }
        return raw;
    }

    decoded_chunk decode_chunk(const std::span<const std::byte> compressed, const std::span<const code_entry> code,
                               const bulk_resolver& bulk, const bool with_data)
    {
        bulk_cursor cursor(bulk);
        const auto raw = utils::compression::zstd::decompress(compressed);
        chunk_header header{};
        if (raw.size() < sizeof(header))
        {
            throw std::runtime_error("Truncated TTD event chunk");
        }
        memcpy(&header, raw.data(), sizeof(header));
        std::span<const std::byte> rest = std::span(raw).subspan(sizeof(header));
        std::array<stream_reader, stream_count> streams{};
        for (size_t i = 0; i < stream_count; ++i)
        {
            if (header.stream_sizes[i] > rest.size())
            {
                throw std::runtime_error("Invalid TTD event chunk");
            }
            streams[i] = stream_reader(rest.first(static_cast<size_t>(header.stream_sizes[i])));
            rest = rest.subspan(static_cast<size_t>(header.stream_sizes[i]));
        }
        if (!rest.empty() || header.event_count != header.stream_sizes[tag_stream])
        {
            throw std::runtime_error("Invalid TTD event chunk");
        }

        decoded_chunk chunk{};
        chunk.events.resize(static_cast<size_t>(header.event_count));
        predictor state{};
        for (auto& event : chunk.events)
        {
            const auto tag = streams[tag_stream].byte();
            const auto kind = static_cast<uint8_t>(tag & tag_kind_mask);
            if (!valid_kind(kind) || (tag & ~(tag_kind_mask | tag_irregular_step | tag_extra)))
            {
                throw std::runtime_error("Invalid TTD event tag");
            }
            event.kind = static_cast<access_kind>(kind);
            const auto execute = event.kind == access_kind::execute;
            event.step = state.step + ((tag & tag_irregular_step) ? streams[step_stream].varint() : regular_step_delta(event.kind));
            state.step = event.step;

            if (execute)
            {
                event.ip = state.next_ip + unzigzag(streams[ip_stream].varint());
                event.address = event.ip + unzigzag(streams[address_stream].varint());
                uint64_t id{};
                if (tag & tag_extra)
                {
                    id = state.next_code + unzigzag(streams[code_stream].varint());
                    state.code_at.set(event.address, id);
                    state.next_code = id + 1;
                }
                else
                {
                    const auto* known = state.code_at.find(event.address);
                    if (!known)
                    {
                        throw std::runtime_error("TTD execute event has no code entry");
                    }
                    id = *known;
                }
                if (id >= code.size() || code[static_cast<size_t>(id)].address != event.address)
                {
                    throw std::runtime_error("Invalid TTD code entry reference");
                }
                event.size = code[static_cast<size_t>(id)].size;
                event.payload = code[static_cast<size_t>(id)].bytes;
                state.next_ip = event.ip + event.size;
            }
            else
            {
                event.ip = state.ip + unzigzag(streams[ip_stream].varint());
                event.address = state.address_base(event) + unzigzag(streams[address_stream].varint());
                event.size = streams[size_stream].varint();
                std::span<const std::byte> data{};
                const auto output = std::as_writable_bytes(std::span(event.payload));
                if (event.size > inline_data_limit)
                {
                    if (tag & tag_extra)
                    {
                        throw std::runtime_error("Invalid TTD known-value read");
                    }
                    bulk_reference reference{};
                    reference.block = state.bulk_block_index + unzigzag(streams[bulk_stream].varint());
                    reference.offset = state.bulk_offset_base(reference.block) + unzigzag(streams[bulk_stream].varint());
                    if (with_data)
                    {
                        data = cursor.data(reference, event.size);
                    }
                    state.remember_bulk(reference, event.size);
                    memcpy(event.payload.data(), &reference.offset, sizeof(reference.offset));
                    memcpy(event.payload.data() + sizeof(reference.offset), &reference.block, sizeof(reference.block));
                }
                else if (tag & tag_extra)
                {
                    if (event.kind != access_kind::read ||
                        (with_data && !state.memory.load(event.address, output.first(static_cast<size_t>(event.size)))))
                    {
                        throw std::runtime_error("Invalid TTD known-value read");
                    }
                    data = output.first(static_cast<size_t>(event.size));
                }
                else
                {
                    data = streams[data_stream].bytes(event.size);
                    memcpy(event.payload.data(), data.data(), data.size());
                }
                state.remember_access(event, with_data ? data : std::span<const std::byte>{});
            }
            state.ip = event.ip;
        }
        for (const auto& reader : streams)
        {
            if (!reader.done())
            {
                throw std::runtime_error("Invalid TTD event chunk");
            }
        }
        return chunk;
    }

    std::vector<std::byte> encode_page_block(const std::span<const page_entry> entries)
    {
        std::array<std::vector<std::byte>, 3> streams{};
        uint64_t page = entries.empty() ? 0 : entries.front().page;
        uint32_t chunk = 0;
        for (const auto& entry : entries)
        {
            const auto same_page = entry.page == page;
            put_varint(streams[0], entry.page - page);
            put_varint(streams[1], same_page ? entry.chunk - chunk : entry.chunk);
            streams[2].push_back(static_cast<std::byte>(entry.kinds));
            page = entry.page;
            chunk = entry.chunk;
        }

        const auto raw = join_streams({}, streams);
        auto compressed = utils::compression::zstd::compress(raw, page_block_compression_level);
        if (compressed.empty())
        {
            throw std::runtime_error("Cannot compress TTD page index");
        }
        return compressed;
    }

    std::vector<page_entry> decode_page_block(const std::span<const std::byte> compressed, const page_block& block)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        std::array<uint64_t, 3> sizes{};
        if (raw.size() < sizeof(sizes))
        {
            throw std::runtime_error("Invalid TTD page index block");
        }
        memcpy(sizes.data(), raw.data(), sizeof(sizes));
        auto rest = std::span(raw).subspan(sizeof(sizes));
        std::array<stream_reader, 3> streams{};
        for (size_t i = 0; i < streams.size(); ++i)
        {
            if (sizes[i] > rest.size())
            {
                throw std::runtime_error("Invalid TTD page index block");
            }
            streams[i] = stream_reader(rest.first(static_cast<size_t>(sizes[i])));
            rest = rest.subspan(static_cast<size_t>(sizes[i]));
        }
        if (!rest.empty() || sizes[2] != block.entry_count)
        {
            throw std::runtime_error("Invalid TTD page index block");
        }

        std::vector<page_entry> entries(static_cast<size_t>(block.entry_count));
        uint64_t page = block.first_page;
        uint32_t chunk = 0;
        for (auto& entry : entries)
        {
            const auto delta = streams[0].varint();
            const auto value = streams[1].varint();
            if (delta > UINT64_MAX - page || value > (delta ? UINT32_MAX : UINT32_MAX - chunk))
            {
                throw std::runtime_error("Invalid TTD page index entry");
            }
            entry.page = page + delta;
            entry.chunk = delta ? static_cast<uint32_t>(value) : chunk + static_cast<uint32_t>(value);
            entry.kinds = streams[2].byte();
            page = entry.page;
            chunk = entry.chunk;
        }
        if (!streams[0].done() || !streams[1].done())
        {
            throw std::runtime_error("Invalid TTD page index block");
        }
        return entries;
    }

    std::vector<std::byte> encode_syscalls(const syscall_table& table)
    {
        std::array<std::vector<std::byte>, syscall_stream_count> streams{};
        uint64_t step = 0;
        uint64_t next_event = 0;
        for (const auto& entry : table.entries)
        {
            if (entry.step < step || entry.event_number < next_event)
            {
                throw std::runtime_error("TTD syscalls must be in recording order");
            }
            put_varint(streams[0], entry.step - step);
            put_varint(streams[1], entry.event_number - next_event);
            put_varint(streams[2], entry.id);
            put_varint(streams[3], entry.event_count);
            const auto* result = reinterpret_cast<const std::byte*>(&entry.result);
            streams[4].insert(streams[4].end(), result, result + sizeof(entry.result));
            step = entry.step;
            next_event = entry.event_number + entry.event_count;
        }
        for (const auto& [id, name] : table.names)
        {
            put_varint(streams[5], id);
            put_text(streams[5], name);
        }

        const std::array<uint64_t, 2> counts{table.entries.size(), table.names.size()};
        return compress_table(join_streams(std::as_bytes(std::span(counts)), streams), "syscalls");
    }

    syscall_table decode_syscalls(const std::span<const std::byte> compressed)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        std::array<uint64_t, 2> counts{};
        std::array<uint64_t, syscall_stream_count> sizes{};
        if (raw.size() < sizeof(counts) + sizeof(sizes))
        {
            throw std::runtime_error("Invalid TTD syscalls");
        }
        memcpy(counts.data(), raw.data(), sizeof(counts));
        memcpy(sizes.data(), raw.data() + sizeof(counts), sizeof(sizes));
        auto rest = std::span(raw).subspan(sizeof(counts) + sizeof(sizes));
        std::array<stream_reader, syscall_stream_count> streams{};
        for (size_t i = 0; i < streams.size(); ++i)
        {
            if (sizes[i] > rest.size())
            {
                throw std::runtime_error("Invalid TTD syscalls");
            }
            streams[i] = stream_reader(rest.first(static_cast<size_t>(sizes[i])));
            rest = rest.subspan(static_cast<size_t>(sizes[i]));
        }
        // Every entry takes at least one byte of the step stream and every name one of the name stream.
        if (!rest.empty() || counts[0] > sizes[0] || counts[1] > sizes[5])
        {
            throw std::runtime_error("Invalid TTD syscalls");
        }

        syscall_table table{};
        table.entries.resize(static_cast<size_t>(counts[0]));
        uint64_t step = 0;
        uint64_t next_event = 0;
        for (auto& entry : table.entries)
        {
            const auto step_delta = streams[0].varint();
            const auto event_gap = streams[1].varint();
            const auto id = streams[2].varint();
            entry.event_count = streams[3].varint();
            if (step_delta > UINT64_MAX - step || event_gap > UINT64_MAX - next_event || id > UINT32_MAX ||
                entry.event_count > UINT64_MAX - next_event - event_gap)
            {
                throw std::runtime_error("Invalid TTD syscall entry");
            }
            entry.step = step + step_delta;
            entry.event_number = next_event + event_gap;
            entry.id = static_cast<uint32_t>(id);
            memcpy(&entry.result, streams[4].bytes(sizeof(entry.result)).data(), sizeof(entry.result));
            step = entry.step;
            next_event = entry.event_number + entry.event_count;
        }
        for (uint64_t i = 0; i < counts[1]; ++i)
        {
            const auto id = streams[5].varint();
            if (id > UINT32_MAX)
            {
                throw std::runtime_error("Invalid TTD syscall name");
            }
            table.names[static_cast<uint32_t>(id)] = read_text(streams[5]);
        }
        if (!std::ranges::all_of(streams, [](const stream_reader& stream) { return stream.done(); }))
        {
            throw std::runtime_error("Invalid TTD syscalls");
        }
        return table;
    }

    std::vector<std::byte> encode_modules(const std::span<const module_entry> modules)
    {
        std::vector<std::byte> raw{};
        put_varint(raw, modules.size());
        for (const auto& mod : modules)
        {
            put_varint(raw, mod.base);
            put_varint(raw, mod.size);
            put_varint(raw, mod.load_step);
            put_varint(raw, mod.load_event_number);
            put_varint(raw, mod.unload_step ? *mod.unload_step + 1 : 0);
            put_varint(raw, mod.unload_event_number.value_or(0));
            put_text(raw, mod.name);
            put_text(raw, mod.path);
        }
        return compress_table(raw, "modules");
    }

    std::vector<module_entry> decode_modules(const std::span<const std::byte> compressed)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        stream_reader reader(raw);
        const auto count = reader.varint();
        // Every module takes at least eight bytes.
        if (count > raw.size() / 8)
        {
            throw std::runtime_error("Invalid TTD modules");
        }
        std::vector<module_entry> modules(static_cast<size_t>(count));
        for (auto& mod : modules)
        {
            mod.base = reader.varint();
            mod.size = reader.varint();
            mod.load_step = reader.varint();
            mod.load_event_number = reader.varint();
            const auto unload_step = reader.varint();
            const auto unload_event_number = reader.varint();
            if (unload_step)
            {
                mod.unload_step = unload_step - 1;
                mod.unload_event_number = unload_event_number;
            }
            mod.name = read_text(reader);
            mod.path = read_text(reader);
        }
        if (!reader.done())
        {
            throw std::runtime_error("Invalid TTD modules");
        }
        return modules;
    }

    namespace
    {
        constexpr size_t export_stream_count = 3;

        std::string ordinal_name(const uint64_t ordinal)
        {
            return "#" + std::to_string(ordinal);
        }
    }

    std::vector<std::byte> encode_exports(const std::span<const module_entry> modules)
    {
        std::array<std::vector<std::byte>, export_stream_count> streams{};
        for (const auto& mod : modules)
        {
            std::vector<const module_export*> exports{};
            if (mod.exports)
            {
                for (const auto& symbol : *mod.exports)
                {
                    exports.push_back(&symbol);
                }
            }
            std::ranges::sort(exports, {}, &module_export::ordinal);
            put_varint(streams[0], exports.size());
            uint64_t ordinal = 0;
            std::string_view previous{};
            for (const auto* symbol : exports)
            {
                if (symbol->ordinal < ordinal || symbol->rva > UINT32_MAX)
                {
                    throw std::runtime_error("Invalid TTD module export");
                }
                put_varint(streams[0], symbol->ordinal - ordinal);
                const auto rva = static_cast<uint32_t>(symbol->rva);
                const auto* rva_bytes = reinterpret_cast<const std::byte*>(&rva);
                streams[1].insert(streams[1].end(), rva_bytes, rva_bytes + sizeof(rva));
                const auto name = symbol->name == ordinal_name(symbol->ordinal) ? std::string_view{} : std::string_view(symbol->name);
                const auto shared = static_cast<size_t>(std::ranges::mismatch(previous, name).in2 - name.begin());
                put_varint(streams[2], shared);
                put_text(streams[2], name.substr(shared));
                ordinal = symbol->ordinal;
                previous = name;
            }
        }

        const uint64_t count = modules.size();
        return compress_table(join_streams(std::as_bytes(std::span(&count, 1)), streams), "exports");
    }

    void decode_exports(const std::span<const std::byte> compressed, const std::span<module_entry> modules)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        uint64_t count{};
        std::array<uint64_t, export_stream_count> sizes{};
        if (raw.size() < sizeof(count) + sizeof(sizes))
        {
            throw std::runtime_error("Invalid TTD exports");
        }
        memcpy(&count, raw.data(), sizeof(count));
        memcpy(sizes.data(), raw.data() + sizeof(count), sizeof(sizes));
        if (count != modules.size())
        {
            throw std::runtime_error("TTD exports do not match the modules");
        }
        auto rest = std::span(raw).subspan(sizeof(count) + sizeof(sizes));
        std::array<stream_reader, export_stream_count> streams{};
        for (size_t i = 0; i < streams.size(); ++i)
        {
            if (sizes[i] > rest.size())
            {
                throw std::runtime_error("Invalid TTD exports");
            }
            streams[i] = stream_reader(rest.first(static_cast<size_t>(sizes[i])));
            rest = rest.subspan(static_cast<size_t>(sizes[i]));
        }

        for (auto& mod : modules)
        {
            const auto export_count = streams[0].varint();
            // Every export takes four bytes of the RVA stream.
            if (export_count > sizes[1] / sizeof(uint32_t))
            {
                throw std::runtime_error("Invalid TTD exports");
            }
            auto exports = std::make_shared<std::vector<module_export>>(static_cast<size_t>(export_count));
            uint64_t ordinal = 0;
            std::string previous{};
            for (auto& symbol : *exports)
            {
                const auto delta = streams[0].varint();
                if (delta > UINT64_MAX - ordinal)
                {
                    throw std::runtime_error("Invalid TTD export");
                }
                ordinal += delta;
                uint32_t rva{};
                memcpy(&rva, streams[1].bytes(sizeof(rva)).data(), sizeof(rva));
                const auto shared = streams[2].varint();
                if (shared > previous.size())
                {
                    throw std::runtime_error("Invalid TTD export");
                }
                auto name = previous.substr(0, static_cast<size_t>(shared)) + read_text(streams[2]);
                symbol = {.rva = rva, .ordinal = ordinal, .name = name.empty() ? ordinal_name(ordinal) : name};
                previous = std::move(name);
            }
            std::ranges::sort(*exports, {}, [](const module_export& symbol) { return std::tie(symbol.rva, symbol.name); });
            mod.exports = std::move(exports);
        }
        if (!rest.empty() || !std::ranges::all_of(streams, [](const stream_reader& stream) { return stream.done(); }))
        {
            throw std::runtime_error("Invalid TTD exports");
        }
    }

    std::vector<std::byte> encode_export_forwarders(const std::span<const module_entry> modules)
    {
        std::vector<std::byte> raw{};
        put_varint(raw, modules.size());
        for (const auto& mod : modules)
        {
            std::vector<const module_export*> forwarded{};
            if (mod.exports)
            {
                for (const auto& symbol : *mod.exports)
                {
                    if (!symbol.forwarder.empty())
                    {
                        forwarded.push_back(&symbol);
                    }
                }
            }
            std::ranges::sort(forwarded, {}, &module_export::ordinal);
            put_varint(raw, forwarded.size());
            uint64_t ordinal = 0;
            for (const auto* symbol : forwarded)
            {
                put_varint(raw, symbol->ordinal - ordinal);
                put_text(raw, symbol->forwarder);
                ordinal = symbol->ordinal;
            }
        }
        return compress_table(raw, "export forwarders");
    }

    void decode_export_forwarders(const std::span<const std::byte> compressed, const std::span<module_entry> modules)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        stream_reader reader(raw);
        if (reader.varint() != modules.size())
        {
            throw std::runtime_error("TTD export forwarders do not match the modules");
        }
        for (auto& mod : modules)
        {
            const auto count = reader.varint();
            if (count == 0)
            {
                continue;
            }
            if (!mod.exports || count > mod.exports->size())
            {
                throw std::runtime_error("Invalid TTD export forwarders");
            }
            auto exports = std::make_shared<std::vector<module_export>>(*mod.exports);
            uint64_t ordinal = 0;
            for (uint64_t i = 0; i < count; ++i)
            {
                const auto delta = reader.varint();
                if (delta > UINT64_MAX - ordinal)
                {
                    throw std::runtime_error("Invalid TTD export forwarders");
                }
                ordinal += delta;
                const auto symbol = std::ranges::find(*exports, ordinal, &module_export::ordinal);
                if (symbol == exports->end())
                {
                    throw std::runtime_error("TTD export forwarder for an unknown ordinal");
                }
                symbol->forwarder = read_text(reader);
            }
            mod.exports = std::move(exports);
        }
        if (!reader.done())
        {
            throw std::runtime_error("Invalid TTD export forwarders");
        }
    }

    std::vector<std::byte> encode_threads(const thread_table& threads)
    {
        std::vector<std::byte> raw{};
        put_varint(raw, threads.switches.size());
        uint64_t step = 0;
        uint64_t event_number = 0;
        for (const auto& entry : threads.switches)
        {
            if (entry.step < step || entry.event_number < event_number)
            {
                throw std::runtime_error("TTD thread switches must be in recording order");
            }
            put_varint(raw, entry.step - step);
            put_varint(raw, entry.event_number - event_number);
            put_varint(raw, entry.thread_id);
            step = entry.step;
            event_number = entry.event_number;
        }
        put_varint(raw, threads.names.size());
        for (const auto& [id, name] : threads.names)
        {
            put_varint(raw, id);
            put_text(raw, name);
        }
        return compress_table(raw, "threads");
    }

    thread_table decode_threads(const std::span<const std::byte> compressed)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        stream_reader reader(raw);
        const auto count = reader.varint();
        // Every switch takes at least three bytes.
        if (count > raw.size() / 3)
        {
            throw std::runtime_error("Invalid TTD threads");
        }
        thread_table threads{};
        threads.switches.resize(static_cast<size_t>(count));
        uint64_t step = 0;
        uint64_t event_number = 0;
        for (auto& entry : threads.switches)
        {
            const auto step_delta = reader.varint();
            const auto event_delta = reader.varint();
            const auto id = reader.varint();
            if (step_delta > UINT64_MAX - step || event_delta > UINT64_MAX - event_number || id > UINT32_MAX)
            {
                throw std::runtime_error("Invalid TTD thread switch");
            }
            step += step_delta;
            event_number += event_delta;
            entry = {.step = step, .event_number = event_number, .thread_id = static_cast<uint32_t>(id)};
        }
        const auto names = reader.varint();
        for (uint64_t i = 0; i < names; ++i)
        {
            const auto id = reader.varint();
            if (id > UINT32_MAX)
            {
                throw std::runtime_error("Invalid TTD thread name");
            }
            threads.names[static_cast<uint32_t>(id)] = read_text(reader);
        }
        if (!reader.done())
        {
            throw std::runtime_error("Invalid TTD threads");
        }
        return threads;
    }

    std::vector<std::byte> encode_register_snapshots(const std::span<const register_snapshot_entry> entries)
    {
        std::vector<std::byte> raw{};
        put_varint(raw, entries.size());
        register_snapshot_entry previous{};
        for (size_t i = 0; i < entries.size(); ++i)
        {
            const auto& entry = entries[i];
            if (entry.step < previous.step || entry.event_number < previous.event_number || (entry.base != UINT64_MAX && entry.base >= i))
            {
                throw std::runtime_error("Invalid TTD register snapshot");
            }
            put_varint(raw, entry.step - previous.step);
            put_varint(raw, entry.event_number - previous.event_number);
            put_varint(raw, zigzag(entry.offset - (previous.offset + previous.size)));
            put_varint(raw, entry.size);
            put_varint(raw, entry.base == UINT64_MAX ? 0 : i - entry.base);
            previous = entry;
        }
        return compress_table(raw, "register snapshots");
    }

    std::vector<register_snapshot_entry> decode_register_snapshots(const std::span<const std::byte> compressed)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        stream_reader reader(raw);
        const auto count = reader.varint();
        // Every entry takes at least five bytes.
        if (count > raw.size() / 5)
        {
            throw std::runtime_error("Invalid TTD register snapshots");
        }
        std::vector<register_snapshot_entry> entries(static_cast<size_t>(count));
        register_snapshot_entry previous{};
        for (size_t i = 0; i < entries.size(); ++i)
        {
            const auto step_delta = reader.varint();
            const auto event_delta = reader.varint();
            const auto offset_delta = unzigzag(reader.varint());
            const auto size = reader.varint();
            const auto base_distance = reader.varint();
            if (step_delta > UINT64_MAX - previous.step || event_delta > UINT64_MAX - previous.event_number || base_distance > i)
            {
                throw std::runtime_error("Invalid TTD register snapshot");
            }
            auto& entry = entries[i];
            entry = {.step = previous.step + step_delta,
                     .event_number = previous.event_number + event_delta,
                     .offset = previous.offset + previous.size + offset_delta,
                     .size = size,
                     .base = base_distance ? i - base_distance : UINT64_MAX};
            previous = entry;
        }
        if (!reader.done())
        {
            throw std::runtime_error("Invalid TTD register snapshots");
        }
        return entries;
    }

    std::vector<std::byte> encode_mapping_changes(const std::span<const mapping_change> changes)
    {
        std::vector<std::byte> raw{};
        put_varint(raw, changes.size());
        mapping_change previous{};
        for (const auto& change : changes)
        {
            if (change.step < previous.step || change.event_number < previous.event_number)
            {
                throw std::runtime_error("Invalid TTD mapping change");
            }
            put_varint(raw, change.step - previous.step);
            put_varint(raw, change.event_number - previous.event_number);
            put_varint(raw, zigzag(change.address - previous.address));
            put_varint(raw, change.size);
            previous = change;
        }
        return compress_table(raw, "mapping changes");
    }

    std::vector<mapping_change> decode_mapping_changes(const std::span<const std::byte> compressed)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        stream_reader reader(raw);
        const auto count = reader.varint();
        // Every change takes at least four bytes.
        if (count > raw.size() / 4)
        {
            throw std::runtime_error("Invalid TTD mapping changes");
        }
        std::vector<mapping_change> changes(static_cast<size_t>(count));
        mapping_change previous{};
        for (auto& change : changes)
        {
            const auto step_delta = reader.varint();
            const auto event_delta = reader.varint();
            if (step_delta > UINT64_MAX - previous.step || event_delta > UINT64_MAX - previous.event_number)
            {
                throw std::runtime_error("Invalid TTD mapping change");
            }
            change.step = previous.step + step_delta;
            change.event_number = previous.event_number + event_delta;
            change.address = previous.address + unzigzag(reader.varint());
            change.size = reader.varint();
            previous = change;
        }
        if (!reader.done())
        {
            throw std::runtime_error("Invalid TTD mapping changes");
        }
        return changes;
    }

    std::vector<std::byte> encode_bulk_block(const std::span<const std::byte> data, const int level)
    {
        std::vector<std::byte> filtered(data.begin(), data.end());
        convert_displacements(filtered, true);
        return utils::compression::zstd::compress(filtered, level);
    }

    std::vector<std::byte> decode_bulk_block(const std::span<const std::byte> compressed, const bool filtered)
    {
        auto data = utils::compression::zstd::decompress(compressed);
        if (filtered)
        {
            convert_displacements(data, false);
        }
        return data;
    }
}
