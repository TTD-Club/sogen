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
        this->submit_job(id, [this, data = std::move(data)] { return this->encode_(*data); });
    }

    void background_compressor::submit_job(const uint64_t id, job work)
    {
        {
            std::unique_lock lock(this->mutex_);
            this->space_available_.wait(lock, [this] { return this->stopping_ || this->pending_.size() < this->max_pending_; });
            this->pending_.emplace_back(id, std::move(work));
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
            std::pair<uint64_t, job> next{};
            {
                std::unique_lock lock(this->mutex_);
                this->work_available_.wait(lock, [this] { return this->stopping_ || !this->pending_.empty(); });
                if (this->stopping_)
                {
                    return;
                }
                next = std::move(this->pending_.front());
                this->pending_.pop_front();
            }
            this->space_available_.notify_one();

            auto compressed = next.second();
            next.second = nullptr;

            {
                const std::scoped_lock lock(this->mutex_);
                this->finished_.emplace_back(next.first, std::move(compressed));
                --this->unfinished_;
            }
            this->work_done_.notify_all();
        }
    }
}
