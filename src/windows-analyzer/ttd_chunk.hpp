#pragma once

#include "ttd_format.hpp"

#include <span>
#include <unordered_map>
#include <vector>

namespace sogen::ttd
{
    struct decoded_chunk
    {
        std::vector<access_event> events{};
        std::vector<std::byte> blob{};
    };

    // Distinct executed instructions of a whole recording, in order of first execution.
    class code_table
    {
      public:
        uint64_t id_of(const access_event& execute);

        const std::vector<code_entry>& entries() const
        {
            return entries_;
        }

      private:
        std::vector<code_entry> entries_{};
        std::vector<uint64_t> previous_version_{};
        std::unordered_map<uint64_t, uint64_t> latest_version_{};
    };

    // A chunk is a zstd frame of a header and seven streams: one tag byte per event (kind, irregular step, and new code
    // or known value flags), then varint steps, instruction pointers, code ids, addresses, sizes, and access data. Each
    // stream predicts from earlier events of the same chunk only, so chunks decode independently given the code table.
    // Encoded payloads of accesses larger than an event payload hold only their offset into the data stream.
    std::vector<std::byte> encode_chunk(std::span<const access_event> events, std::span<const std::byte> blob, code_table& code);
    decoded_chunk decode_chunk(std::span<const std::byte> compressed, uint32_t chunk_index, std::span<const code_entry> code);

    // A page block stores page deltas, chunks (as deltas while the page repeats), and kinds as three streams.
    std::vector<std::byte> encode_page_block(std::span<const page_entry> entries);
    std::vector<page_entry> decode_page_block(std::span<const std::byte> compressed, const page_block& block);
}
