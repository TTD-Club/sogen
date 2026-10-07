#include "ttd_compressor.hpp"

namespace sogen::ttd
{
    background_compressor::background_compressor(encoder encode, const size_t workers, const size_t max_pending)
        : encode_(std::move(encode)),
          max_pending_(max_pending)
    {
        for (size_t i = 0; i < workers; ++i)
        {
            this->workers_.emplace_back([this] { this->run(); });
        }
    }

    background_compressor::~background_compressor()
    {
        {
            const std::scoped_lock lock(this->mutex_);
            this->stopping_ = true;
        }
        this->work_available_.notify_all();
        this->space_available_.notify_all();
        for (auto& worker : this->workers_)
        {
            worker.join();
        }
    }

    void background_compressor::submit(const uint64_t id, std::shared_ptr<const std::vector<std::byte>> data)
    {
        {
            std::unique_lock lock(this->mutex_);
            this->space_available_.wait(lock, [this] { return this->stopping_ || this->pending_.size() < this->max_pending_; });
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
            this->space_available_.notify_one();

            auto compressed = this->encode_(*job.second);
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
