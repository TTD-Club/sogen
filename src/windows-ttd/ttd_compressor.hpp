#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <thread>
#include <utility>
#include <vector>

namespace sogen::ttd
{
    // Encodes buffers on one worker thread, in submission order. A failed encoding yields an empty result.
    class background_compressor
    {
      public:
        using result = std::pair<uint64_t, std::vector<std::byte>>;
        using encoder = std::function<std::vector<std::byte>(std::span<const std::byte>)>;

        explicit background_compressor(encoder encode);
        ~background_compressor();
        background_compressor(const background_compressor&) = delete;
        background_compressor& operator=(const background_compressor&) = delete;
        background_compressor(background_compressor&&) = delete;
        background_compressor& operator=(background_compressor&&) = delete;

        void submit(uint64_t id, std::shared_ptr<const std::vector<std::byte>> data);
        // The results finished so far; with `wait`, blocks until every submitted buffer is done.
        std::vector<result> take_finished(bool wait);

      private:
        encoder encode_{};
        std::mutex mutex_{};
        std::condition_variable work_available_{};
        std::condition_variable work_done_{};
        std::deque<std::pair<uint64_t, std::shared_ptr<const std::vector<std::byte>>>> pending_{};
        std::vector<result> finished_{};
        size_t unfinished_{};
        bool stopping_{};
        std::thread worker_{};

        void run();
    };
}
