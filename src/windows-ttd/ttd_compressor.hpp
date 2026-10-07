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
    // Encodes buffers on worker threads; results finish in any order. A failed encoding yields an empty result. Once
    // max_pending buffers wait for a worker, submit blocks.
    class background_compressor
    {
      public:
        using result = std::pair<uint64_t, std::vector<std::byte>>;
        using encoder = std::function<std::vector<std::byte>(std::span<const std::byte>)>;

        background_compressor(encoder encode, size_t workers, size_t max_pending);
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
        size_t max_pending_{};
        std::mutex mutex_{};
        std::condition_variable work_available_{};
        std::condition_variable work_done_{};
        std::condition_variable space_available_{};
        std::deque<std::pair<uint64_t, std::shared_ptr<const std::vector<std::byte>>>> pending_{};
        std::vector<result> finished_{};
        size_t unfinished_{};
        bool stopping_{};
        std::vector<std::thread> workers_{};

        void run();
    };
}
