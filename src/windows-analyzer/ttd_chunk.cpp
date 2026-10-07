#include "ttd_chunk.hpp"

#include <utils/compression.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace sogen::ttd
{
    namespace
    {
        constexpr int chunk_compression_level = 6;
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
        constexpr size_t stream_count = 7;

        struct chunk_header
        {
            uint64_t event_count{};
            std::array<uint64_t, stream_count> stream_sizes{};
        };

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

        // Guest memory as far as the chunk's own accesses have shown it.
        class known_memory
        {
          public:
            void store(const uint64_t address, const std::span<const std::byte> data)
            {
                qword* current = nullptr;
                uint64_t current_base = 0;
                for (size_t i = 0; i < data.size(); ++i)
                {
                    const auto byte_address = address + i;
                    const auto base = byte_address & ~uint64_t{7};
                    if (!current || base != current_base)
                    {
                        current = &this->qwords_[base];
                        current_base = base;
                    }
                    const auto lane = static_cast<size_t>(byte_address & 7);
                    current->bytes[lane] = data[i];
                    current->valid |= static_cast<uint8_t>(1U << lane);
                }
            }

            bool load(const uint64_t address, const std::span<std::byte> output) const
            {
                for (size_t i = 0; i < output.size(); ++i)
                {
                    const auto byte_address = address + i;
                    const auto entry = this->qwords_.find(byte_address & ~uint64_t{7});
                    const auto lane = static_cast<size_t>(byte_address & 7);
                    if (entry == this->qwords_.end() || !(entry->second.valid & (1U << lane)))
                    {
                        return false;
                    }
                    output[i] = entry->second.bytes[lane];
                }
                return true;
            }

          private:
            struct qword
            {
                std::array<std::byte, 8> bytes{};
                uint8_t valid{};
            };

            std::unordered_map<uint64_t, qword> qwords_{};
        };

        // Prediction state; the encoder and the decoder update it identically after every event.
        struct predictor
        {
            uint64_t step{};
            uint64_t ip{};
            uint64_t next_ip{};
            uint64_t next_code{};
            std::unordered_map<uint64_t, uint64_t> code_at{};
            std::array<uint64_t, 16> last_address_of_kind{};
            std::unordered_map<uint64_t, uint64_t> last_address_at{};
            known_memory memory{};

            static uint64_t site(const access_event& event)
            {
                return (event.ip << 4) | static_cast<uint64_t>(event.kind);
            }

            uint64_t address_base(const access_event& event) const
            {
                const auto entry = this->last_address_at.find(site(event));
                return entry != this->last_address_at.end() ? entry->second : this->last_address_of_kind[static_cast<size_t>(event.kind)];
            }

            void remember_access(const access_event& event, const std::span<const std::byte> data)
            {
                this->last_address_at[site(event)] = event.address;
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

        std::span<const std::byte> event_data(const access_event& event, const std::span<const std::byte> blob)
        {
            if (event.size <= inline_data_limit)
            {
                return std::as_bytes(std::span(event.payload)).first(static_cast<size_t>(event.size));
            }
            uint64_t offset{};
            memcpy(&offset, event.payload.data(), sizeof(offset));
            if (offset > blob.size() || event.size > blob.size() - offset)
            {
                throw std::runtime_error("Invalid TTD access data offset");
            }
            return blob.subspan(static_cast<size_t>(offset), static_cast<size_t>(event.size));
        }
    }

    uint64_t code_table::id_of(const access_event& execute)
    {
        const auto latest = this->latest_version_.find(execute.address);
        if (latest != this->latest_version_.end())
        {
            for (auto id = latest->second; id != no_previous_version; id = this->previous_version_[id])
            {
                const auto& entry = this->entries_[id];
                if (entry.size == execute.size && entry.bytes == execute.payload)
                {
                    return id;
                }
            }
        }
        const auto id = static_cast<uint64_t>(this->entries_.size());
        this->entries_.push_back({.address = execute.address, .size = execute.size, .bytes = execute.payload});
        this->previous_version_.push_back(latest != this->latest_version_.end() ? latest->second : no_previous_version);
        this->latest_version_[execute.address] = id;
        return id;
    }

    std::vector<std::byte> encode_chunk(const std::span<const access_event> events, const std::span<const std::byte> blob, code_table& code)
    {
        std::array<std::vector<std::byte>, stream_count> streams{};
        streams[tag_stream].reserve(events.size());
        predictor state{};

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
                const auto id = code.id_of(event);
                const auto known = state.code_at.find(event.address);
                if (known == state.code_at.end() || known->second != id)
                {
                    tag |= tag_extra;
                    put_varint(streams[code_stream], zigzag(id - state.next_code));
                    state.code_at[event.address] = id;
                    state.next_code = id + 1;
                }
                state.next_ip = event.ip + event.size;
            }
            else
            {
                put_varint(streams[ip_stream], zigzag(event.ip - state.ip));
                put_varint(streams[address_stream], zigzag(event.address - state.address_base(event)));
                put_varint(streams[size_stream], event.size);
                const auto data = event_data(event, blob);
                std::array<std::byte, inline_data_limit> known{};
                if (event.kind == access_kind::read && data.size() <= known.size() &&
                    state.memory.load(event.address, std::span(known).first(data.size())) &&
                    std::ranges::equal(std::span(known).first(data.size()), data))
                {
                    tag |= tag_extra;
                }
                else
                {
                    streams[data_stream].insert(streams[data_stream].end(), data.begin(), data.end());
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

        auto compressed = utils::compression::zstd::compress(raw, chunk_compression_level);
        if (compressed.empty())
        {
            throw std::runtime_error("Cannot compress TTD event chunk");
        }
        return compressed;
    }

    decoded_chunk decode_chunk(const std::span<const std::byte> compressed, const uint32_t chunk_index,
                               const std::span<const code_entry> code)
    {
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
                    state.code_at[event.address] = id;
                    state.next_code = id + 1;
                }
                else
                {
                    const auto known = state.code_at.find(event.address);
                    if (known == state.code_at.end())
                    {
                        throw std::runtime_error("TTD execute event has no code entry");
                    }
                    id = known->second;
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
                if (tag & tag_extra)
                {
                    const auto output = std::as_writable_bytes(std::span(event.payload));
                    if (event.kind != access_kind::read || event.size > output.size() ||
                        !state.memory.load(event.address, output.first(static_cast<size_t>(event.size))))
                    {
                        throw std::runtime_error("Invalid TTD known-value read");
                    }
                    data = output.first(static_cast<size_t>(event.size));
                }
                else
                {
                    const uint64_t offset = streams[data_stream].offset();
                    data = streams[data_stream].bytes(event.size);
                    if (event.size <= inline_data_limit)
                    {
                        memcpy(event.payload.data(), data.data(), data.size());
                    }
                    else
                    {
                        const uint64_t index = chunk_index;
                        memcpy(event.payload.data(), &offset, sizeof(offset));
                        memcpy(event.payload.data() + sizeof(offset), &index, sizeof(index));
                    }
                }
                state.remember_access(event, data);
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

        const auto data_begin = raw.size() - static_cast<size_t>(header.stream_sizes[data_stream]);
        chunk.blob.assign(raw.begin() + static_cast<ptrdiff_t>(data_begin), raw.end());
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

        std::vector<std::byte> raw{};
        for (const auto& bytes : streams)
        {
            const uint64_t size = bytes.size();
            const auto* size_bytes = reinterpret_cast<const std::byte*>(&size);
            raw.insert(raw.end(), size_bytes, size_bytes + sizeof(size));
        }
        for (const auto& bytes : streams)
        {
            raw.insert(raw.end(), bytes.begin(), bytes.end());
        }
        auto compressed = utils::compression::zstd::compress(raw, chunk_compression_level);
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
}
