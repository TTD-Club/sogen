#pragma once

#include "ttd_format.hpp"

#include <span>
#include <vector>

namespace sogen::ttd
{
    struct decoded_chunk
    {
        std::vector<access_event> events{};
        std::vector<std::byte> blob{};
    };

    // A chunk is stored as zstd-compressed columns (step, ip and address deltas, sizes, kinds, payloads) followed by
    // the data of accesses larger than an event payload. Encoded payloads of such accesses hold only the blob offset.
    std::vector<std::byte> encode_chunk(std::span<const access_event> events, std::span<const std::byte> blob);
    decoded_chunk decode_chunk(std::span<const std::byte> compressed, uint32_t chunk_index);
}
