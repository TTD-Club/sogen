#pragma once

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include "adaptive_mutex.hpp"
#include <platform/compiler.hpp>
#include <thread>

namespace sogen
{

    // The emulator kernel lock (docs/multi-vcpu-design.md, sections 2 and 7).
    // Serializes all emulator code that touches shared kernel state: acquired at
    // every entry point (VM-exit hook callbacks, UI event delivery, scheduler
    // iterations) and released while guest code executes, unless the instruction
    // hook keeps it (see keep). Interior code asserts ownership instead of
    // re-acquiring; the lock is deliberately not recursive, so nested acquisition
    // is caught immediately in debug builds.
    class kernel_lock
    {
      public:
        struct profile_stats
        {
            uint64_t acquisitions; // total successful lock() calls
            uint64_t contended;    // acquisitions that had to block because another thread held it
            uint64_t wait_nanos;   // cumulative time spent blocked on contended acquisitions
            uint64_t held_nanos;   // cumulative time the lock was held (BEL "busy" time)
        };

        // Env-gated so a normal run pays nothing: the instrumented path (a try_lock plus two
        // steady_clock reads per acquisition) only runs when SOGEN_LOCK_PROFILE is set. It is read once
        // per lock: a function-local static checks its initialization on every call, about 1% of a run
        // with instruction precision, which takes the lock for every instruction.
        bool profiling_enabled() const
        {
            return this->profiling_;
        }

        // Taking the lock while this thread keeps it (see keep) takes over that hold.
        void lock()
        {
            const auto self = std::this_thread::get_id();
            if (this->owner_.load(std::memory_order_relaxed) == self && this->kept_.load(std::memory_order_relaxed))
            {
                this->kept_.store(false, std::memory_order_relaxed);
                return;
            }

            assert(this->owner_.load(std::memory_order_relaxed) != self && "The kernel lock is not recursive");

            if (profiling_enabled())
            {
                this->lock_profiled();
            }
            else if (!this->mutex_.try_lock())
            {
                this->lock_contended();
            }

            this->owner_.store(self, std::memory_order_relaxed);
        }

        // The instruction hook of a single vCPU takes the lock for every instruction. Releasing it after each one costs
        // two atomic operations per instruction, so the hook can keep it instead, until another thread waits for it.
        // keep ends a hold without releasing it. lock_kept takes it at the next instruction: it lets a waiting thread in
        // first, or else keeps the hold. release_kept releases a hold this thread still keeps. A thread that only tries the
        // lock does not wait for it, so it fails while the lock is kept.
        void keep()
        {
            assert(this->is_held_by_current_thread() && "The kernel lock must be held");
            this->kept_.store(true, std::memory_order_relaxed);
        }

        void lock_kept()
        {
            if (this->kept_.load(std::memory_order_relaxed) && this->waiters_.load(std::memory_order_relaxed) == 0)
            {
                assert(this->is_held_by_current_thread() && "Only the thread that keeps the kernel lock takes it back");
                this->kept_.store(false, std::memory_order_relaxed);
                return;
            }

            this->lock_kept_slowly();
        }

        void release_kept()
        {
            if (this->kept_.load(std::memory_order_relaxed))
            {
                this->unlock();
            }
        }

        // Acquire only if the lock is free. Lets a host-owned thread touch kernel state without ever stalling
        // behind a long-running emulator operation; the caller is expected to retry later or skip the work.
        bool try_lock()
        {
            assert(!this->is_held_by_current_thread() && "The kernel lock is not recursive");

            if (!this->mutex_.try_lock())
            {
                return false;
            }

            if (profiling_enabled())
            {
                this->acquisitions_.fetch_add(1, std::memory_order_relaxed);
                this->held_since_ = std::chrono::steady_clock::now();
            }

            this->owner_.store(std::this_thread::get_id(), std::memory_order_relaxed);
            return true;
        }

        void unlock()
        {
            this->kept_.store(false, std::memory_order_relaxed);
            this->owner_.store({}, std::memory_order_relaxed);

            if (profiling_enabled())
            {
                this->held_nanos_.fetch_add(nanos_since(this->held_since_), std::memory_order_relaxed);
            }

            this->mutex_.unlock();
        }

        bool is_held_by_current_thread() const
        {
            return this->owner_.load(std::memory_order_relaxed) == std::this_thread::get_id();
        }

        void assert_held() const
        {
            // Evaluated outside assert() so the member access survives in NDEBUG builds (where assert
            // expands to nothing); the relaxed load is otherwise dead and elided by the optimizer.
            [[maybe_unused]] const bool held = this->is_held_by_current_thread();
            assert(held && "The kernel lock must be held");
        }

        profile_stats profile() const
        {
            return {
                .acquisitions = this->acquisitions_.load(std::memory_order_relaxed),
                .contended = this->contended_.load(std::memory_order_relaxed),
                .wait_nanos = this->wait_nanos_.load(std::memory_order_relaxed),
                .held_nanos = this->held_nanos_.load(std::memory_order_relaxed),
            };
        }

      private:
        using clock = std::chrono::steady_clock;
        static constexpr auto hand_over_time = std::chrono::microseconds(200);

        static uint64_t nanos_since(const clock::time_point start)
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now() - start).count());
        }

        NO_INLINE void lock_kept_slowly()
        {
            if (this->kept_.load(std::memory_order_relaxed))
            {
                this->unlock();
                this->let_waiter_in();
            }

            this->lock();
        }

        void lock_contended()
        {
            this->waiters_.fetch_add(1, std::memory_order_relaxed);
            this->mutex_.lock();
            this->waiters_.fetch_sub(1, std::memory_order_relaxed);
        }

        // A waiter that spins takes the lock within nanoseconds; one that has parked needs the OS to wake it first.
        void let_waiter_in() const
        {
            const auto start = clock::now();
            for (uint32_t i = 1; this->waiters_.load(std::memory_order_relaxed) != 0 && !this->mutex_.is_locked(); ++i)
            {
                utils::concurrency::cpu_relax();
                if ((i & 63) == 0 && clock::now() - start >= hand_over_time)
                {
                    return;
                }
            }
        }

        void lock_profiled()
        {
            if (!this->mutex_.try_lock())
            {
                const auto start = clock::now();
                this->lock_contended();
                this->wait_nanos_.fetch_add(nanos_since(start), std::memory_order_relaxed);
                this->contended_.fetch_add(1, std::memory_order_relaxed);
            }

            this->acquisitions_.fetch_add(1, std::memory_order_relaxed);
            this->held_since_ = clock::now();
        }

        adaptive_mutex mutex_{};
        std::atomic<std::thread::id> owner_{};
        std::atomic<uint32_t> waiters_{};

        // Set only by the thread that keeps the lock, and only while it holds it, so that thread can read it without
        // finding out whether it holds the lock.
        std::atomic<bool> kept_{false};

        // Guarded by mutex_ (written/read only by the current holder).
        clock::time_point held_since_{};

        std::atomic<uint64_t> acquisitions_{};
        std::atomic<uint64_t> contended_{};
        std::atomic<uint64_t> wait_nanos_{};
        std::atomic<uint64_t> held_nanos_{};

        bool profiling_{std::getenv("SOGEN_LOCK_PROFILE") != nullptr};
    };

} // namespace sogen
