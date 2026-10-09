#include "compression.hpp"

#include <zstd.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>

namespace sogen
{

    namespace utils::compression
    {
        namespace zstd
        {
            std::vector<std::byte> decompress(const std::span<const std::byte> data)
            {
                const auto decompressed_size = ZSTD_getFrameContentSize(data.data(), data.size());

                if (decompressed_size == ZSTD_CONTENTSIZE_ERROR || decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN)
                {
                    return {};
                }

                std::vector<std::byte> buffer(static_cast<size_t>(decompressed_size));

                const auto result = ZSTD_decompress(buffer.data(), buffer.size(), data.data(), data.size());

                if (ZSTD_isError(result))
                {
                    return {};
                }

                return buffer;
            }

            std::optional<size_t> decompressed_size(const std::span<const std::byte> data)
            {
                const auto size = ZSTD_getFrameContentSize(data.data(), data.size());
                if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN)
                {
                    return std::nullopt;
                }
                return static_cast<size_t>(size);
            }

            std::vector<std::byte> compress(const std::span<const std::byte> data, const int compression_level)
            {
                const auto max_size = ZSTD_compressBound(data.size());
                std::vector<std::byte> result(max_size);

                const auto compressed_size = ZSTD_compress(result.data(), max_size, data.data(), data.size(), compression_level);

                if (ZSTD_isError(compressed_size))
                {
                    return {};
                }

                result.resize(compressed_size);
                return result;
            }

            namespace
            {
                // The window must cover the reference and the data for matches into the reference to be found.
                int reference_window_log(const size_t data_size, const size_t reference_size)
                {
                    constexpr int maximum_window_log = 30;
                    const auto total = static_cast<uint64_t>(data_size) + reference_size;
                    int log = 10;
                    while (log < maximum_window_log && (uint64_t{1} << log) < total)
                    {
                        ++log;
                    }
                    return log;
                }
            }

            std::vector<std::byte> compress_with_reference(const std::span<const std::byte> data,
                                                           const std::span<const std::byte> reference, const int compression_level)
            {
                const std::unique_ptr<ZSTD_CCtx, decltype(&ZSTD_freeCCtx)> context(ZSTD_createCCtx(), &ZSTD_freeCCtx);
                if (!context)
                {
                    return {};
                }
                ZSTD_CCtx_setParameter(context.get(), ZSTD_c_compressionLevel, compression_level);
                ZSTD_CCtx_setParameter(context.get(), ZSTD_c_enableLongDistanceMatching, 1);
                ZSTD_CCtx_setParameter(context.get(), ZSTD_c_windowLog, reference_window_log(data.size(), reference.size()));
                if (ZSTD_isError(ZSTD_CCtx_refPrefix(context.get(), reference.data(), reference.size())))
                {
                    return {};
                }

                std::vector<std::byte> result(ZSTD_compressBound(data.size()));
                const auto compressed_size = ZSTD_compress2(context.get(), result.data(), result.size(), data.data(), data.size());
                if (ZSTD_isError(compressed_size))
                {
                    return {};
                }

                result.resize(compressed_size);
                return result;
            }

            bool decompress_with_reference(const std::span<const std::byte> data, const std::span<const std::byte> reference,
                                           std::vector<std::byte>& output)
            {
                const auto decompressed_size = ZSTD_getFrameContentSize(data.data(), data.size());
                if (decompressed_size == ZSTD_CONTENTSIZE_ERROR || decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN)
                {
                    return false;
                }

                const std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> context(ZSTD_createDCtx(), &ZSTD_freeDCtx);
                if (!context)
                {
                    return false;
                }
                ZSTD_DCtx_setParameter(context.get(), ZSTD_d_windowLogMax,
                                       reference_window_log(static_cast<size_t>(decompressed_size), reference.size()));
                if (ZSTD_isError(ZSTD_DCtx_refPrefix(context.get(), reference.data(), reference.size())))
                {
                    return false;
                }

                output.resize(static_cast<size_t>(decompressed_size));
                const auto result = ZSTD_decompressDCtx(context.get(), output.data(), output.size(), data.data(), data.size());
                return !ZSTD_isError(result) && result == output.size();
            }

            std::vector<std::byte> decompress_with_reference(const std::span<const std::byte> data,
                                                             const std::span<const std::byte> reference)
            {
                std::vector<std::byte> buffer{};
                if (!decompress_with_reference(data, reference, buffer))
                {
                    return {};
                }
                return buffer;
            }
        }
    }
} // namespace sogen
