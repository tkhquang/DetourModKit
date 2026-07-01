#include "internal/srw_shared_mutex.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <type_traits>

using DetourModKit::detail::SrwSharedMutex;

// SRWLOCK owners and waiters reference the lock by address, so an SrwSharedMutex must keep a stable address for its
// entire lifetime. All four copy/move special members are deleted; these guards keep that contract from regressing.
static_assert(!std::is_copy_constructible_v<SrwSharedMutex>,
              "SrwSharedMutex must remain non-copyable: SRWLOCK state cannot be duplicated while owners or waiters "
              "reference its address.");
static_assert(!std::is_copy_assignable_v<SrwSharedMutex>,
              "SrwSharedMutex must remain non-copyable: SRWLOCK state cannot be duplicated while owners or waiters "
              "reference its address.");
static_assert(!std::is_move_constructible_v<SrwSharedMutex>,
              "SrwSharedMutex must remain non-movable: waiters block on the SRWLOCK's address, which must stay "
              "stable.");
static_assert(!std::is_move_assignable_v<SrwSharedMutex>,
              "SrwSharedMutex must remain non-movable: waiters block on the SRWLOCK's address, which must stay "
              "stable.");

TEST(SrwSharedMutexTest, SharedReadersCanOverlap)
{
    SrwSharedMutex mutex;
    std::shared_lock first_reader(mutex);

    std::atomic<bool> acquired{false};
    std::thread reader(
        [&]() -> void
        {
            std::shared_lock second_reader(mutex, std::try_to_lock);
            acquired.store(second_reader.owns_lock(), std::memory_order_release);
        });

    reader.join();

    EXPECT_TRUE(acquired.load(std::memory_order_acquire));
}

TEST(SrwSharedMutexTest, ExclusiveTryLockFailsWhileReaderHeld)
{
    SrwSharedMutex mutex;
    std::shared_lock reader(mutex);

    std::atomic<bool> acquired{true};
    std::thread writer(
        [&]() -> void
        {
            std::unique_lock writer_lock(mutex, std::try_to_lock);
            acquired.store(writer_lock.owns_lock(), std::memory_order_release);
        });

    writer.join();

    EXPECT_FALSE(acquired.load(std::memory_order_acquire));
}

TEST(SrwSharedMutexTest, SharedTryLockFailsWhileWriterHeld)
{
    SrwSharedMutex mutex;
    std::unique_lock writer(mutex);

    std::atomic<bool> acquired{true};
    std::thread reader(
        [&]() -> void
        {
            std::shared_lock reader_lock(mutex, std::try_to_lock);
            acquired.store(reader_lock.owns_lock(), std::memory_order_release);
        });

    reader.join();

    EXPECT_FALSE(acquired.load(std::memory_order_acquire));
}

TEST(SrwSharedMutexTest, TryLockSucceedsWhenFreeAndUnlockReleases)
{
    SrwSharedMutex mutex;

    // After the first acquisition, each subsequent one can only succeed if the preceding unlock genuinely released
    // ownership, so this sequence pins the success mapping of both try paths and the release mapping of both unlock
    // paths in one pass.
    ASSERT_TRUE(mutex.try_lock());
    mutex.unlock();
    ASSERT_TRUE(mutex.try_lock_shared());
    mutex.unlock_shared();
    EXPECT_TRUE(mutex.try_lock());
    mutex.unlock();
}

TEST(SrwSharedMutexTest, BlockedWriterAcquiresAfterReaderReleases)
{
    SrwSharedMutex mutex;
    std::shared_lock reader(mutex);

    std::atomic<bool> writer_started{false};
    std::atomic<bool> writer_acquired{false};
    std::thread writer(
        [&]() -> void
        {
            writer_started.store(true, std::memory_order_release);
            std::unique_lock writer_lock(mutex);
            writer_acquired.store(true, std::memory_order_release);
        });

    while (!writer_started.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // The writer's blocking lock() cannot return while the shared owner is live, so the flag must still be clear
    // here regardless of scheduling.
    EXPECT_FALSE(writer_acquired.load(std::memory_order_acquire));

    // Releasing the shared owner must wake the blocked writer. A broken release manifests as a deterministic hang
    // (test timeout), never a flaky pass.
    reader.unlock();
    writer.join();

    EXPECT_TRUE(writer_acquired.load(std::memory_order_acquire));
}
