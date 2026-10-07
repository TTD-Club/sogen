#include "ttd_chunk.hpp"

#include <utils/compression.hpp>

#include <cstring>
#include <stdexcept>

namespace sogen::ttd
{
    namespace
    {
        constexpr int chunk_compression_level = 6;

        struct chunk_header
        {
            uint64_t event_count{};
            uint64_t blob_size{};
        };

        template <typename T>
        void append(std::vector<std::byte>& output, const T& value)
        {
            const auto* bytes = reinterpret_cast<const std::byte*>(&value);
            output.insert(output.end(), bytes, bytes + sizeof(value));
        }

        class column_reader
        {
          public:
            explicit column_reader(const std::span<const std::byte> data)
                : data_(data)
            {
            }

            template <typename T>
            T read()
            {
                if (sizeof(T) > this->data_.size() - this->offset_)
                {
                    throw std::runtime_error("Truncated TTD event chunk");
                }
                T value{};
                memcpy(&value, this->data_.data() + this->offset_, sizeof(value));
                this->offset_ += sizeof(value);
                return value;
            }

            std::span<const std::byte> rest() const
            {
                return this->data_.subspan(this->offset_);
            }

          private:
            std::span<const std::byte> data_;
            size_t offset_{};
        };
    }

    std::vector<std::byte> encode_chunk(const std::span<const access_event> events, const std::span<const std::byte> blob)
    {
        std::vector<std::byte> raw{};
        raw.reserve(sizeof(chunk_header) + events.size() * (8 * 4 + 1 + inline_data_limit) + blob.size());
        append(raw, chunk_header{.event_count = events.size(), .blob_size = blob.size()});

        uint64_t previous_step = 0;
        for (const auto& event : events)
        {
            append(raw, event.step - previous_step);
            previous_step = event.step;
        }
        uint64_t previous_ip = 0;
        for (const auto& event : events)
        {
            append(raw, event.ip - previous_ip);
            previous_ip = event.ip;
        }
        for (const auto& event : events)
        {
            append(raw, event.address - event.ip);
        }
        for (const auto& event : events)
        {
            append(raw, event.size);
        }
        for (const auto& event : events)
        {
            append(raw, static_cast<uint8_t>(event.kind));
        }
        for (const auto& event : events)
        {
            append(raw, event.payload);
        }
        raw.insert(raw.end(), blob.begin(), blob.end());

        auto compressed = utils::compression::zstd::compress(raw, chunk_compression_level);
        if (compressed.empty())
        {
            throw std::runtime_error("Cannot compress TTD event chunk");
        }
        return compressed;
    }

    decoded_chunk decode_chunk(const std::span<const std::byte> compressed, const uint32_t chunk_index)
    {
        const auto raw = utils::compression::zstd::decompress(compressed);
        column_reader reader(raw);
        const auto header = reader.read<chunk_header>();
        const auto event_bytes = 8 * 4 + 1 + inline_data_limit;
        if (header.event_count > reader.rest().size() / event_bytes ||
            header.blob_size != reader.rest().size() - header.event_count * event_bytes)
        {
            throw std::runtime_error("Invalid TTD event chunk");
        }

        decoded_chunk chunk{};
        chunk.events.resize(static_cast<size_t>(header.event_count));
        uint64_t step = 0;
        for (auto& event : chunk.events)
        {
            step += reader.read<uint64_t>();
            event.step = step;
        }
        uint64_t ip = 0;
        for (auto& event : chunk.events)
        {
            ip += reader.read<uint64_t>();
            event.ip = ip;
        }
        for (auto& event : chunk.events)
        {
            event.address = event.ip + reader.read<uint64_t>();
        }
        for (auto& event : chunk.events)
        {
            event.size = reader.read<uint64_t>();
        }
        for (auto& event : chunk.events)
        {
            event.kind = static_cast<access_kind>(reader.read<uint8_t>());
        }
        for (auto& event : chunk.events)
        {
            event.payload = reader.read<decltype(event.payload)>();
        }
        const auto blob = reader.rest();
        chunk.blob.assign(blob.begin(), blob.end());

        for (auto& event : chunk.events)
        {
            if (event.kind == access_kind::execute || event.size <= inline_data_limit)
            {
                continue;
            }
            uint64_t offset{};
            memcpy(&offset, event.payload.data(), sizeof(offset));
            if (offset > chunk.blob.size() || event.size > chunk.blob.size() - offset)
            {
                throw std::runtime_error("Invalid TTD access data offset");
            }
            const uint64_t index = chunk_index;
            memcpy(event.payload.data() + sizeof(offset), &index, sizeof(index));
        }
        return chunk;
    }
}
