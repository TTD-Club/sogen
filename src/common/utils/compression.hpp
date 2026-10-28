#pragma once

#include <cstddef>
#include <optional>
#include <functional>
#include <memory>
#include <span>
#include <vector>

struct ZSTD_outBuffer_s;

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
            // For frames written by a stream_compressor, which do not record their decompressed size.
            std::vector<std::byte> decompress(std::span<const std::byte> data, size_t decompressed_size);

            class stream_compressor
            {
              public:
                using sink = std::function<void(std::span<const std::byte> compressed)>;

                stream_compressor(sink output, int compression_level, unsigned workers);
                ~stream_compressor();

                stream_compressor(const stream_compressor&) = delete;
                stream_compressor& operator=(const stream_compressor&) = delete;
                stream_compressor(stream_compressor&&) = delete;
                stream_compressor& operator=(stream_compressor&&) = delete;

                void write(std::span<const std::byte> data);
                void finish();

              private:
                struct context_deleter
                {
                    void operator()(void* context) const;
                };

                sink output_;
                std::unique_ptr<void, context_deleter> context_;
                std::vector<std::byte> out_buffer_;

                void compress(std::span<const std::byte> data, bool end);
            };

            class stream_decompressor
            {
              public:
                // Reads up to the size of the span from the compressed data and returns how much it read, 0 at its end.
                using source = std::function<size_t(std::span<std::byte> compressed)>;

                explicit stream_decompressor(source input);
                ~stream_decompressor();

                stream_decompressor(const stream_decompressor&) = delete;
                stream_decompressor& operator=(const stream_decompressor&) = delete;
                stream_decompressor(stream_decompressor&&) = delete;
                stream_decompressor& operator=(stream_decompressor&&) = delete;

                void read(std::span<std::byte> data);
                void finish();

              private:
                struct context_deleter
                {
                    void operator()(void* context) const;
                };

                source input_;
                std::unique_ptr<void, context_deleter> context_;
                std::vector<std::byte> in_buffer_;
                size_t in_position_{};
                size_t in_size_{};
                bool frame_complete_{};

                bool fill_input();
                void decompress(ZSTD_outBuffer_s& output);
            };
        }
    }
} // namespace sogen
