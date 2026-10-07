#include "ttd_compressor.hpp"

#include <utils/compression.hpp>

namespace sogen::ttd
{
    background_compressor::background_compressor(const int level)
        : level_(level),
          worker_([this] { this->run(); })
    {
    }

    background_compressor::~background_compressor()
    {
        {
            const std::scoped_lock lock(this->mutex_);
            this->stopping_ = true;
        }
        this->work_available_.notify_all();
        this->worker_.join();
    }

    void background_compressor::submit(const uint64_t id, std::shared_ptr<const std::vector<std::byte>> data)
    {
        {
            const std::scoped_lock lock(this->mutex_);
            this->pending_.emplace_back(id, std::move(data));
            ++this->unfinished_;
        }
        this->work_available_.notify_one();
    }

    std::vector<background_compressor::result> background_compressor::take_finished(const bool wait)
    {
        std::unique_lock lock(this->mutex_);
        if (wait)
        {
            this->work_done_.wait(lock, [this] { return !this->unfinished_; });
        }
        return std::exchange(this->finished_, {});
    }

    void background_compressor::run()
    {
        while (true)
        {
            std::pair<uint64_t, std::shared_ptr<const std::vector<std::byte>>> job{};
            {
                std::unique_lock lock(this->mutex_);
                this->work_available_.wait(lock, [this] { return this->stopping_ || !this->pending_.empty(); });
                if (this->stopping_)
                {
                    return;
                }
                job = std::move(this->pending_.front());
                this->pending_.pop_front();
            }

            auto compressed = utils::compression::zstd::compress(*job.second, this->level_);
            job.second.reset();

            {
                const std::scoped_lock lock(this->mutex_);
                this->finished_.emplace_back(job.first, std::move(compressed));
                --this->unfinished_;
            }
            this->work_done_.notify_all();
        }
    }
}
