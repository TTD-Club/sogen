#pragma once

#include <cstddef>
#include <optional>
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
            // The size a frame decompresses to, or nothing when the frame header does not record it.
            std::optional<size_t> decompressed_size(std::span<const std::byte> data);

            // Delta compression: data is encoded against reference, which decompression must be given again.
            std::vector<std::byte> compress_with_reference(std::span<const std::byte> data, std::span<const std::byte> reference,
                                                           int compression_level = 3);
            std::vector<std::byte> decompress_with_reference(std::span<const std::byte> data, std::span<const std::byte> reference);
            // Decompresses into `output`, reusing its allocation; `output` must not overlap `reference`.
            bool decompress_with_reference(std::span<const std::byte> data, std::span<const std::byte> reference,
                                           std::vector<std::byte>& output);
        }
    }
} // namespace sogen
