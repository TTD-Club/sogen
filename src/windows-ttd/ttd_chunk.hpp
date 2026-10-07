#pragma once

#include "ttd_format.hpp"

#include <functional>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

namespace sogen::ttd
{
    struct decoded_chunk
    {
        std::vector<access_event> events{};
    };

    using bulk_block = std::shared_ptr<const std::vector<std::byte>>;
    using bulk_resolver = std::function<bulk_block(uint64_t index)>;

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

    // A chunk is a zstd frame of a header and eight streams: one tag byte per event (kind, irregular step, and new code
    // or known value flags), then varint steps, instruction pointers, code ids, addresses, sizes, access data, and bulk
    // references. Each stream predicts from earlier events of the same chunk only, so chunks decode independently given
    // the code table and the bulk blocks. Accesses larger than an event payload keep their bytes in a bulk block; their
    // payload holds the offset and block index, which `bulk` resolves.
    std::vector<std::byte> encode_chunk(std::span<const access_event> events, code_table& code, const bulk_resolver& bulk);
    decoded_chunk decode_chunk(std::span<const std::byte> compressed, std::span<const code_entry> code, const bulk_resolver& bulk);

    // A page block stores page deltas, chunks (as deltas while the page repeats), and kinds as three streams.
    std::vector<std::byte> encode_page_block(std::span<const page_entry> entries);
    std::vector<page_entry> decode_page_block(std::span<const std::byte> compressed, const page_block& block);
}
