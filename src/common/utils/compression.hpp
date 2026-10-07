#pragma once

#include <span>
#include <vector>

namespace sogen
{

    namespace utils::compression
    {
        namespace zstd
        {
            std::vector<std::byte> compress(std::span<const std::byte> data, int compression_level = 8);
            std::vector<std::byte> decompress(std::span<const std::byte> data);

            // Delta compression: data is encoded against reference, which decompression must be given again.
            std::vector<std::byte> compress_with_reference(std::span<const std::byte> data, std::span<const std::byte> reference,
                                                           int compression_level = 3);
            std::vector<std::byte> decompress_with_reference(std::span<const std::byte> data, std::span<const std::byte> reference);
        }
    }
} // namespace sogen
