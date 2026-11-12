#include <gtest/gtest.h>

#include <kernel_lock.hpp>

#include <atomic>
#include <chrono>
#include <thread>

namespace sogen::test
{
    namespace
    {
        bool is_free_for_another_thread(kernel_lock& lock)
        {
            bool acquired = false;
            std::thread([&] {
                acquired = lock.try_lock();
                if (acquired)
                {
                    lock.unlock();
                }
            }).join();
            return acquired;
        }
    }

    TEST(KernelLockTest, AKeptLockStaysHeldUntilReleased)
    {
        kernel_lock lock{};
        lock.lock_kept();
        lock.keep();

        EXPECT_FALSE(is_free_for_another_thread(lock));

        lock.lock_kept();
        lock.keep();
        EXPECT_FALSE(is_free_for_another_thread(lock));

        lock.release_kept();
        EXPECT_TRUE(is_free_for_another_thread(lock));
    }

    TEST(KernelLockTest, LockingTakesOverAKeptHold)
    {
        kernel_lock lock{};
        lock.lock_kept();
        lock.keep();

        lock.lock();
        EXPECT_TRUE(lock.is_held_by_current_thread());
        lock.unlock();

        EXPECT_TRUE(is_free_for_another_thread(lock));
        lock.release_kept();
        EXPECT_TRUE(is_free_for_another_thread(lock));
    }

    TEST(KernelLockTest, AWaitingThreadGetsTheLockAtTheNextTake)
    {
        kernel_lock lock{};
        lock.lock_kept();
        lock.keep();

        std::atomic<bool> entered{false};
        std::thread waiter([&] {
            lock.lock();
            entered = true;
            lock.unlock();
        });

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!entered && std::chrono::steady_clock::now() < deadline)
        {
            lock.lock_kept();
            lock.keep();
        }

        lock.release_kept();
        waiter.join();
        EXPECT_TRUE(entered);
    }
}
