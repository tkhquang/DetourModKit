#include "DetourModKit/address.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

// Deterministic thread-local out-of-memory injection for the allocation-failure tests of the region cache.
#include "test_alloc_probe.hpp"

// Shared [B-100] loader-probe scope.
#include "fixtures/loader_lock_scope.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include "fixtures/memory_fixture.hpp"
using namespace dmk_test::memory_fixture;

using namespace DetourModKit;

namespace
{
    inline memory::ReadableStatus is_readable_nonblocking(const void *p, std::size_t n) noexcept
    {
        return memory::is_readable_nonblocking(region_of(p, n));
    }

    inline void invalidate_range(const void *p, std::size_t n) noexcept
    {
        memory::invalidate_range(region_of(p, n));
    }
} // namespace

TEST_F(MemoryTest, InitMemoryCache)
{
    bool result = memory::init_cache();
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, InitMemoryCache_CustomParams)
{
    memory::shutdown_cache();

    bool result = memory::init_cache(64, 10000);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, ClearMemoryCache)
{
    EXPECT_NO_THROW(memory::clear_cache());
    EXPECT_NO_THROW(memory::clear_cache());
    EXPECT_NO_THROW(memory::clear_cache());
}

TEST_F(MemoryTest, GetMemoryCacheStats)
{
    std::string stats = memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
    EXPECT_NE(stats.find("Hits:"), std::string::npos);
    EXPECT_NE(stats.find("Misses:"), std::string::npos);
}

TEST_F(MemoryTest, GetMemoryStats_PopulatedAndConsistentWithString)
{
    const memory::MemoryStats stats = memory::get_memory_stats();

    // SetUp() initialized the cache, so the configuration fields are populated.
    EXPECT_GT(stats.shard_count, 0u);
    EXPECT_GT(stats.max_entries_per_shard, 0u);

    // hit_rate_percent is either the documented "no queries" sentinel or a real percentage.
    EXPECT_TRUE(stats.hit_rate_percent == -1.0 || (stats.hit_rate_percent >= 0.0 && stats.hit_rate_percent <= 100.0));

    // get_cache_stats() is a thin formatter over the same snapshot: the struct's counters appear verbatim.
    const std::string str = memory::get_cache_stats();
    EXPECT_NE(str.find("Shards: " + std::to_string(stats.shard_count)), std::string::npos);
    EXPECT_NE(str.find("Hits: " + std::to_string(stats.hits)), std::string::npos);
    EXPECT_NE(str.find("Misses: " + std::to_string(stats.misses)), std::string::npos);
}

TEST_F(MemoryTest, GetMemoryStats_NoQueriesSentinel)
{
    memory::clear_cache();
    const memory::MemoryStats stats = memory::get_memory_stats();
    // clear_cache() resets the hit/miss counters and no lookup runs before this read, so the "no queries" state is
    // deterministic and the sentinel must always hold.
    EXPECT_EQ(stats.hits + stats.misses, 0u);
    EXPECT_DOUBLE_EQ(stats.hit_rate_percent, -1.0);
    EXPECT_NE(memory::get_cache_stats().find("N/A (no queries tracked)"), std::string::npos);
}

TEST_F(MemoryTest, IsMemoryReadable_Valid)
{
    char buffer[100] = {0};

    bool result = is_readable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryReadable_ValidHeap)
{
    auto buffer = std::make_unique<char[]>(100);

    bool result = is_readable(buffer.get(), 100);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryReadable_SingleByte)
{
    char c = 'A';
    bool result = is_readable(&c, 1);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryReadable_Invalid)
{
    bool result = is_readable(nullptr, 100);
    EXPECT_FALSE(result);
}

TEST_F(MemoryTest, IsMemoryReadable_ZeroSize)
{
    char buffer[100] = {0};

    bool result = is_readable(buffer, 0);
    EXPECT_FALSE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_Valid)
{
    char buffer[100] = {0};

    bool result = is_writable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_ValidHeap)
{
    auto buffer = std::make_unique<char[]>(100);

    bool result = is_writable(buffer.get(), 100);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_StackCharArray)
{
    char buffer[] = "test";
    bool result = is_writable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_Invalid)
{
    bool result = is_writable(nullptr, 100);
    EXPECT_FALSE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_ZeroSize)
{
    char buffer[100] = {0};

    bool result = is_writable(buffer, 0);
    EXPECT_FALSE(result);
}

TEST_F(MemoryTest, CacheBehavior)
{
    char buffer[100] = {0};

    bool result1 = is_readable(buffer, sizeof(buffer));
    EXPECT_TRUE(result1);

    bool result2 = is_readable(buffer, sizeof(buffer));
    EXPECT_TRUE(result2);

    std::string stats = memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, MultipleRegions)
{
    char buffer1[100] = {0};
    char buffer2[200] = {0};

    EXPECT_TRUE(is_readable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(is_readable(buffer2, sizeof(buffer2)));
    EXPECT_TRUE(is_writable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(is_writable(buffer2, sizeof(buffer2)));
}

TEST_F(MemoryTest, CacheAfterClear)
{
    char buffer[100] = {0};

    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));
    memory::clear_cache();
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));
}

TEST_F(MemoryTest, InvalidateRangeEvictsMultiPageRegionInterior)
{
    // The interior page hashes to another shard than the region base. Only a containment search can find the cached
    // three-page region.
    const SIZE_T page_size = 4096;
    const SIZE_T region_size = page_size * 3;
    void *region = VirtualAlloc(nullptr, region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);

    auto *base = static_cast<uint8_t *>(region);
    // Inside the second page, so neither the region base nor a page-aligned key.
    uint8_t *interior = base + page_size + 64;

    // Warm the cache with a READABLE verdict for the interior address.
    EXPECT_TRUE(is_readable(interior, 16));

    // The protection change leaves a stale readable entry until invalidation.
    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(region, region_size, PAGE_NOACCESS, &old_protect), 0);

    // Invalidate the interior address. A correct invalidation evicts the covering entry regardless of which shard
    // stored it.
    invalidate_range(interior, 16);

    // The re-query must re-run VirtualQuery and observe the no-access protection.
    EXPECT_FALSE(is_readable(interior, 16));

    VirtualProtect(region, region_size, old_protect, &old_protect);
    VirtualFree(region, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheClearStressTest)
{
    char buffer[100] = {0};

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));
        memory::clear_cache();
        // Small yield to allow any background threads to process
        std::this_thread::yield();
    }
}

TEST_F(MemoryTest, CacheInitClearCycle)
{
    for (int i = 0; i < 5; ++i)
    {
        memory::shutdown_cache();
        EXPECT_TRUE(memory::init_cache());
        memory::clear_cache();
    }
}

TEST_F(MemoryTest, IsMemoryReadable_StringLiteral)
{
    const char *str = "Hello, World!";
    bool result = is_readable(str, strlen(str));
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, CacheExpiry)
{
    memory::shutdown_cache();
    (void)memory::init_cache(64, 10);

    char buffer[100] = {0};
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));
}

TEST_F(MemoryTest, CacheBehavior_Overlapping)
{
    memory::shutdown_cache();
    (void)memory::init_cache(64, 10000);

    char buffer[100] = {0};

    EXPECT_TRUE(is_readable(buffer, 50));
    EXPECT_TRUE(is_readable(buffer, 100));
    EXPECT_TRUE(is_readable(buffer + 10, 40));
}

TEST_F(MemoryTest, IsMemoryReadable_ReservedMemory)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    EXPECT_FALSE(is_readable(reserved, 1));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_ReservedMemory)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    EXPECT_FALSE(is_writable(reserved, 1));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_ReadOnlyMemory)
{
    void *readonly = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(readonly, nullptr);

    EXPECT_FALSE(is_writable(readonly, 1));

    VirtualFree(readonly, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_NoAccess)
{
    void *noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noaccess, nullptr);

    EXPECT_FALSE(is_readable(noaccess, 1));

    VirtualFree(noaccess, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_NoAccess)
{
    void *noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noaccess, nullptr);

    EXPECT_FALSE(is_writable(noaccess, 1));

    VirtualFree(noaccess, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_FreedMemory)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    VirtualFree(mem, 0, MEM_RELEASE);

    EXPECT_FALSE(is_readable(mem, 1));
}

TEST_F(MemoryTest, IsMemoryWritable_ExecuteOnly)
{
    void *exec = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE);
    ASSERT_NE(exec, nullptr);

    EXPECT_FALSE(is_writable(exec, 1));

    VirtualFree(exec, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_ExecuteReadWrite)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(is_readable(mem, 1));
    EXPECT_TRUE(is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheFifoEviction)
{
    memory::shutdown_cache();
    (void)memory::init_cache(2, 60000);

    void *mem1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem3 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ASSERT_NE(mem1, nullptr);
    ASSERT_NE(mem2, nullptr);
    ASSERT_NE(mem3, nullptr);

    EXPECT_TRUE(is_readable(mem1, 1));
    EXPECT_TRUE(is_readable(mem2, 1));
    EXPECT_TRUE(is_readable(mem3, 1));
    EXPECT_TRUE(is_readable(mem1, 1));

    VirtualFree(mem1, 0, MEM_RELEASE);
    VirtualFree(mem2, 0, MEM_RELEASE);
    VirtualFree(mem3, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_SizeOverflow)
{
    char buffer[1] = {0};
    EXPECT_FALSE(is_readable(buffer, SIZE_MAX));
}

TEST_F(MemoryTest, IsMemoryWritable_SizeOverflow)
{
    char buffer[1] = {0};
    EXPECT_FALSE(is_writable(buffer, SIZE_MAX));
}

TEST_F(MemoryTest, IsMemoryWritable_ValidWritable)
{
    memory::shutdown_cache();
    (void)memory::init_cache(4, 60000);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(is_writable(mem, 1));

    EXPECT_TRUE(is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_PageGuard)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    DWORD old_protect;
    BOOL ok = VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect);
    ASSERT_TRUE(ok);

    memory::clear_cache();
    EXPECT_FALSE(is_readable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_PageGuard)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    DWORD old_protect;
    BOOL ok = VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect);
    ASSERT_TRUE(ok);

    memory::clear_cache();
    EXPECT_FALSE(is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// A range that starts in a committed region but extends past its end into non-committed space must fail closed. The
// byte one past a standalone 4096-byte commit is reserved-or-free (not MEM_COMMIT), so the range walk stops there.
TEST_F(MemoryTest, IsMemoryReadable_CrossRegionBoundary)
{
    void *region1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *region2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region1, nullptr);
    ASSERT_NE(region2, nullptr);

    memory::clear_cache();
    size_t oversized = 4096 + 1;
    EXPECT_FALSE(is_readable(region1, oversized));

    VirtualFree(region1, 0, MEM_RELEASE);
    VirtualFree(region2, 0, MEM_RELEASE);
}

// A two-page reservation keeps the pages contiguous. Re-protecting the second page as read-only splits the reservation
// into two VirtualQuery regions, both readable, so a range spanning the full reservation must be readable.
TEST_F(MemoryTest, IsMemoryReadable_SpansAdjacentReadableRegions)
{
    const SIZE_T page_size = 4096;
    uint8_t *base =
        static_cast<uint8_t *>(VirtualAlloc(nullptr, 2 * page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(base + page_size, page_size, PAGE_READONLY, &old_protect));

    // Cache-miss path: the first query caches the first region and walks the readable tail.
    memory::clear_cache();
    EXPECT_TRUE(is_readable(base, 2 * page_size));

    // A cached first page cannot prove that the tail of a larger span is readable.
    memory::clear_cache();
    EXPECT_TRUE(is_readable(base, page_size));
    EXPECT_TRUE(is_readable(base, 2 * page_size));

    memory::clear_cache();
    EXPECT_TRUE(is_readable(base + page_size, page_size));
    memory::clear_cache();
    EXPECT_FALSE(is_writable(base, 2 * page_size));

    // No-cache cold fallback: check_memory_permission and is_readable_nonblocking both perform the same range walk.
    memory::shutdown_cache();
    EXPECT_TRUE(is_readable(base, 2 * page_size));
    EXPECT_EQ(is_readable_nonblocking(base, 2 * page_size), memory::ReadableStatus::Readable);

    // Re-init for TearDown so the cache-dependent paths are restored for later tests.
    (void)memory::init_cache();
    VirtualFree(base, 0, MEM_RELEASE);
}

// A readable first page followed by a no-access second page is not readable across the boundary, even though the first
// page alone is readable.
TEST_F(MemoryTest, IsMemoryReadable_SpanFailsClosedOnUnreadableTail)
{
    const SIZE_T page_size = 4096;
    uint8_t *base =
        static_cast<uint8_t *>(VirtualAlloc(nullptr, 2 * page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(base + page_size, page_size, PAGE_NOACCESS, &old_protect));

    memory::clear_cache();
    EXPECT_TRUE(is_readable(base, page_size));

    // The first page stays cached while the tail becomes NOACCESS. Partial cached coverage cannot authorize the full
    // query.
    EXPECT_FALSE(is_readable(base, 2 * page_size));

    memory::clear_cache();
    EXPECT_FALSE(is_readable(base, 2 * page_size));

    memory::shutdown_cache();
    EXPECT_FALSE(is_readable(base, 2 * page_size));
    EXPECT_EQ(is_readable_nonblocking(base, 2 * page_size), memory::ReadableStatus::NotReadable);

    // Re-init for TearDown so the cache-dependent paths are restored for later tests.
    (void)memory::init_cache();
    VirtualFree(base, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, InitCacheWithShards)
{
    memory::shutdown_cache();
    bool result = memory::init_cache(32, 5000, 4);
    EXPECT_TRUE(result);

    // Subsequent init with different params returns true but does not reconfigure
    result = memory::init_cache(64, 10000, 8);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, InvalidateRangeBasic)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    invalidate_range(buffer, sizeof(buffer));

    std::string stats = memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, InvalidateRangeNull)
{
    EXPECT_NO_THROW(invalidate_range(nullptr, 100));
    EXPECT_NO_THROW(invalidate_range(reinterpret_cast<const void *>(static_cast<uintptr_t>(0x1000)), 0));
}

// Interior-page reads miss entries.find and reach sorted_ranges. Concurrent invalidation then exercises the shard lock
// that protects that range search.
TEST_F(MemoryTest, SortedRangesInsertDuringReadDoesNotCrash)
{
    memory::shutdown_cache();
    // One shard so every probe and invalidation hashes to the same sorted_ranges container.
    (void)memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 16 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Prime the cache so the region's sorted_ranges entry exists before contention starts.
    EXPECT_TRUE(is_readable(mem, 64));

    // Interior page: not the region base, so the page-aligned entries.find fast path misses and the lookup falls
    // through to the sorted_ranges upper_bound containment path.
    char *interior = static_cast<char *>(mem) + 8 * 4096;

    const int iterations = 500;
    std::atomic<bool> stop{false};
    std::atomic<int> reader_count{0};

    // Reader threads: continuously probe is_readable on the interior page.
    const int reader_threads = 2;
    std::vector<std::thread> readers;
    readers.reserve(reader_threads);
    for (int t = 0; t < reader_threads; ++t)
    {
        readers.emplace_back(
            [&stop, &reader_count, interior]()
            {
                while (!stop.load(std::memory_order_relaxed))
                {
                    (void)is_readable(interior, 64);
                    reader_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        );
    }

    // Writer thread: repeatedly invalidates the region, churning the lock-serialized insert/erase path in
    // sorted_ranges.
    std::thread writer(
        [&stop, &reader_count, mem]()
        {
            // At least one reader must enter the contention window.
            while (reader_count.load(std::memory_order_relaxed) == 0)
            {
                std::this_thread::yield();
            }
            for (int i = 0; i < iterations && !stop.load(std::memory_order_relaxed); ++i)
            {
                invalidate_range(mem, 64);
            }
            stop.store(true, std::memory_order_release);
        }
    );

    writer.join();
    for (auto &r : readers)
    {
        r.join();
    }

    EXPECT_GT(reader_count.load(), 0);
    // Final read is still consistent.
    EXPECT_TRUE(is_readable(interior, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, InvalidateRangeDoesNotAffectOtherRegions)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 4);

    char buffer1[100] = {0};
    char buffer2[100] = {0};

    EXPECT_TRUE(is_readable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(is_readable(buffer2, sizeof(buffer2)));

    invalidate_range(buffer1, sizeof(buffer1));

    EXPECT_TRUE(is_readable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(is_readable(buffer2, sizeof(buffer2)));
}

TEST_F(MemoryTest, ThreadSafetyHighConcurrency)
{
    const int num_threads = 8;
    const int iterations = 500;
    std::atomic<int> success_count{0};

    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back(
            [iterations, i, &success_count]()
            {
                char buffers[4][100] = {};
                for (int j = 0; j < iterations; ++j)
                {
                    const int buf_idx = (i + j) % 4;
                    if (is_readable(buffers[buf_idx], sizeof(buffers[buf_idx])) &&
                        is_writable(buffers[buf_idx], sizeof(buffers[buf_idx])))
                    {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
        );
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_EQ(success_count.load(), num_threads * iterations);
}

TEST_F(MemoryTest, CacheStatsWithShards)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 5000, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));
    }

    std::string stats = memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, InvalidateRangeAcrossShards)
{
    memory::shutdown_cache();
    (void)memory::init_cache(8, 60000, 4);

    void *mem1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ASSERT_NE(mem1, nullptr);
    ASSERT_NE(mem2, nullptr);

    EXPECT_TRUE(is_readable(mem1, 64));
    EXPECT_TRUE(is_readable(mem2, 64));

    invalidate_range(mem1, 4096);

    EXPECT_TRUE(is_readable(mem1, 64));
    EXPECT_TRUE(is_readable(mem2, 64));

    VirtualFree(mem1, 0, MEM_RELEASE);
    VirtualFree(mem2, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheStampedeCoalescing)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    const int num_threads = 8;
    const int iterations = 50;
    std::atomic<int> success_count{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                for (int j = 0; j < iterations; ++j)
                {
                    if (is_readable(mem, 64))
                    {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
        );
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_EQ(success_count.load(), num_threads * iterations);

    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("Coalesced:"), std::string::npos);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheStatsAvailableInRelease)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 5000, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));
    EXPECT_TRUE(is_writable(buffer, sizeof(buffer)));

    std::string stats = memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
    EXPECT_NE(stats.find("Hits:"), std::string::npos);
    EXPECT_NE(stats.find("Misses:"), std::string::npos);
    EXPECT_NE(stats.find("Coalesced:"), std::string::npos);
    EXPECT_NE(stats.find("Hit Rate:"), std::string::npos);
}

TEST_F(MemoryTest, ClearCacheResetsAllStats)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 5000, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 5; ++i)
    {
        (void)is_readable(buffer, sizeof(buffer));
    }

    memory::clear_cache();

    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("Hits: 0"), std::string::npos);
    EXPECT_NE(stats.find("Misses: 0"), std::string::npos);
}

TEST_F(MemoryTest, InvalidateRangeIncrementsCounter)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 60000, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    invalidate_range(buffer, sizeof(buffer));

    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("Invalidations:"), std::string::npos);
}

TEST_F(MemoryTest, HardUpperBoundEnforced)
{
    memory::shutdown_cache();
    // 1 shard, capacity=2, hard_max = capacity * 2 = 4
    (void)memory::init_cache(2, 60000, 1);

    // Allocate 10 distinct pages to force cache past capacity
    std::vector<void *> regions;
    for (int i = 0; i < 10; ++i)
    {
        void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        ASSERT_NE(mem, nullptr);
        regions.push_back(mem);
        EXPECT_TRUE(is_readable(mem, 1));
    }

    std::string stats = memory::get_cache_stats();
    // Extract TotalEntries value and verify it respects hard upper bound
    auto pos = stats.find("TotalEntries: ");
    ASSERT_NE(pos, std::string::npos);
    size_t total_entries = std::stoull(stats.substr(pos + 14));
    EXPECT_LE(total_entries, 4u);

    for (void *mem : regions)
    {
        VirtualFree(mem, 0, MEM_RELEASE);
    }
}

TEST_F(MemoryTest, BackgroundCleanupThreadRuns)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 10, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    // Wait for at least one pass of the one-second cleanup cycle.
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    std::string stats = memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, InvalidateRangeTriggersBackgroundCleanup)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(is_readable(mem, 64));

    EXPECT_NO_THROW(invalidate_range(mem, 64));

    EXPECT_TRUE(is_readable(mem, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, DefaultExpiryIs50ms)
{
    memory::shutdown_cache();
    // Use default parameters (50ms expiry)
    (void)memory::init_cache(16, memory::DEFAULT_CACHE_EXPIRY_MS, 4);

    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("Expiry: 50ms"), std::string::npos);
}

TEST_F(MemoryTest, OnDemandCleanupStatExists)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 100, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("OnDemandCleanups:"), std::string::npos);
}

TEST_F(MemoryTest, ClearCacheResetsOnDemandCleanupStat)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 100, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 5; ++i)
    {
        (void)is_readable(buffer, sizeof(buffer));
    }

    memory::clear_cache();

    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("OnDemandCleanups: 0"), std::string::npos);
}

TEST_F(MemoryTest, ExpiredEntryTriggersReFetch)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 10, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    // Capture miss count after warm-up
    std::string stats_before = memory::get_cache_stats();
    auto pos_before = stats_before.find("Misses: ");
    ASSERT_NE(pos_before, std::string::npos);
    const uint64_t prev_misses = std::stoull(stats_before.substr(pos_before + 8));

    // Wait for cache entry to expire (10ms expiry)
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    // The new miss distinguishes a fresh OS query from a stale cache hit.
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    std::string stats_after = memory::get_cache_stats();
    auto pos_after = stats_after.find("Misses: ");
    ASSERT_NE(pos_after, std::string::npos);
    const uint64_t misses = std::stoull(stats_after.substr(pos_after + 8));
    EXPECT_GE(misses, prev_misses + 1u);
}

TEST_F(MemoryTest, CacheHitPerformance_SingleThread)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i)
    {
        EXPECT_TRUE(is_readable(mem, 64));
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    EXPECT_LT(duration, 1000);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheStatsIncludeHardMax)
{
    memory::shutdown_cache();
    (void)memory::init_cache(16, 5000, 4);

    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("HardMax/Shard:"), std::string::npos);
}

TEST_F(MemoryTest, ShutdownWhileReadersActive)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Warm up cache so readers hit the fast path
    EXPECT_TRUE(is_readable(mem, 64));

    std::atomic<bool> keep_reading{true};
    std::atomic<int> readers_entered{0};

    const int num_threads = 4;
    std::vector<std::thread> readers;
    for (int i = 0; i < num_threads; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                readers_entered.fetch_add(1, std::memory_order_release);
                while (keep_reading.load(std::memory_order_acquire))
                {
                    // After shutdown, is_readable falls back to direct VirtualQuery
                    (void)is_readable(mem, 64);
                }
            }
        );
    }

    while (readers_entered.load(std::memory_order_acquire) < num_threads)
    {
        std::this_thread::yield();
    }

    // Readers remain active across shutdown. Reentry after shard removal uses the direct VirtualQuery fallback.
    std::thread shutdown_thread([&]() { memory::shutdown_cache(); });

    // Let shutdown and readers race briefly
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Signal readers to stop, then join them
    keep_reading.store(false, std::memory_order_release);

    for (auto &t : readers)
    {
        t.join();
    }

    shutdown_thread.join();

    // Re-init and verify cache still works after concurrent shutdown
    EXPECT_TRUE(memory::init_cache());
    EXPECT_TRUE(is_readable(mem, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReinitAfterShutdown_DataIntegrity)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    for (int round = 0; round < 3; ++round)
    {
        memory::shutdown_cache();
        EXPECT_TRUE(memory::init_cache(16, 5000, 4));

        EXPECT_TRUE(is_readable(mem, 64));
        EXPECT_TRUE(is_writable(mem, 64));

        std::string stats = memory::get_cache_stats();
        EXPECT_NE(stats.find("Hits:"), std::string::npos);
        EXPECT_NE(stats.find("Misses:"), std::string::npos);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, NoCacheFallback_Readable)
{
    // Shut down cache so is_readable uses direct VirtualQuery fallback
    memory::shutdown_cache();

    char buffer[100] = {0};
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));
    EXPECT_FALSE(is_readable(nullptr, 1));
    EXPECT_FALSE(is_readable(buffer, 0));

    // Re-init for TearDown
    (void)memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_Writable)
{
    // Shut down cache so is_writable uses direct VirtualQuery fallback
    memory::shutdown_cache();

    char buffer[100] = {0};
    EXPECT_TRUE(is_writable(buffer, sizeof(buffer)));
    EXPECT_FALSE(is_writable(nullptr, 1));
    EXPECT_FALSE(is_writable(buffer, 0));

    // Re-init for TearDown
    (void)memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_ReservedMemory)
{
    memory::shutdown_cache();

    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    EXPECT_FALSE(is_readable(reserved, 1));
    EXPECT_FALSE(is_writable(reserved, 1));

    VirtualFree(reserved, 0, MEM_RELEASE);

    // Re-init for TearDown
    (void)memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_ReadOnlyMemory)
{
    memory::shutdown_cache();

    void *readonly = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(readonly, nullptr);

    EXPECT_TRUE(is_readable(readonly, 1));
    EXPECT_FALSE(is_writable(readonly, 1));

    VirtualFree(readonly, 0, MEM_RELEASE);

    // Re-init for TearDown
    (void)memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_SizeOverflow)
{
    memory::shutdown_cache();

    char buffer[1] = {0};
    EXPECT_FALSE(is_readable(buffer, SIZE_MAX));
    EXPECT_FALSE(is_writable(buffer, SIZE_MAX));

    // Re-init for TearDown
    (void)memory::init_cache();
}

TEST_F(MemoryTest, CacheRangeLookup_MidRegionHit)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 1);

    // Allocate a large region so VirtualQuery returns a base address that differs from the queried address within the
    // region
    void *mem = VirtualAlloc(nullptr, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Prime cache with a query at the region base
    EXPECT_TRUE(is_readable(mem, 1));

    void *mid = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(mem) + 8192);
    EXPECT_TRUE(is_readable(mid, 64));
    EXPECT_TRUE(is_writable(mid, 64));

    std::string stats = memory::get_cache_stats();
    auto pos = stats.find("Hits: ");
    ASSERT_NE(pos, std::string::npos);
    const uint64_t hits = std::stoull(stats.substr(pos + 6));
    EXPECT_GE(hits, 2u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheHitRate_RepeatedAccess)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    for (int i = 0; i < 100; ++i)
    {
        EXPECT_TRUE(is_readable(mem, 64));
    }

    std::string stats = memory::get_cache_stats();
    auto hits_pos = stats.find("Hits: ");
    auto misses_pos = stats.find("Misses: ");
    ASSERT_NE(hits_pos, std::string::npos);
    ASSERT_NE(misses_pos, std::string::npos);

    const uint64_t hits = std::stoull(stats.substr(hits_pos + 6));
    const uint64_t misses = std::stoull(stats.substr(misses_pos + 8));

    // With 100 queries, expect at least 95% hit rate (first query is miss)
    EXPECT_GE(hits, 95u);
    EXPECT_LE(misses, 5u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadable_AddressOverflow)
{
    // Use a real mapped buffer so VirtualQuery succeeds and the code reaches the address+size overflow guard in the
    // cache/query path.
    void *buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(buf, nullptr);

    // Prime the cache so the overflow check in is_entry_valid_and_covers is exercised
    EXPECT_TRUE(is_readable(buf, 1));

    // size chosen so that (address + size) wraps around
    const size_t wrapping_size = UINTPTR_MAX - reinterpret_cast<uintptr_t>(buf) + 2;
    EXPECT_FALSE(is_readable(buf, wrapping_size));

    VirtualFree(buf, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsWritable_AddressOverflow)
{
    void *buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(buf, nullptr);

    EXPECT_TRUE(is_writable(buf, 1));

    const size_t wrapping_size = UINTPTR_MAX - reinterpret_cast<uintptr_t>(buf) + 2;
    EXPECT_FALSE(is_writable(buf, wrapping_size));

    VirtualFree(buf, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ShutdownCache_ConcurrentReaders)
{
    // Ensure shutdown waits for active readers to finish
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::atomic<bool> reader_started{false};
    std::atomic<bool> reader_done{false};

    // Start a reader thread that will be in-flight during shutdown
    std::thread reader(
        [&]()
        {
            reader_started.store(true);
            for (int i = 0; i < 100; ++i)
            {
                (void)is_readable(mem, 4);
            }
            reader_done.store(true);
        }
    );

    // Wait for reader to start
    while (!reader_started.load())
    {
        std::this_thread::yield();
    }

    memory::shutdown_cache();
    reader.join();

    EXPECT_TRUE(reader_done.load());

    // Re-init for TearDown
    (void)memory::init_cache();
    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ShutdownCache_DrainsManyStripedReaders)
{
    // The admitted-reader count uses many per-thread cache lines. Shutdown must sum every stripe before release.
    // Drive is_readable from many threads while shutdown overlaps. Round-robin assignment selects distinct stripes.
    // Every reader must finish without a crash. If the drain reads one stripe, another reader can touch freed shards.
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    constexpr unsigned READER_THREADS = 16;
    constexpr int READS_PER_THREAD = 5000;
    std::atomic<unsigned> started{0};
    std::atomic<unsigned> finished{0};
    std::vector<std::thread> readers;
    readers.reserve(READER_THREADS);
    for (unsigned t = 0; t < READER_THREADS; ++t)
    {
        readers.emplace_back(
            [&]()
            {
                for (int i = 0; i < READS_PER_THREAD; ++i)
                {
                    // The started flag belongs inside the read loop. A spawned thread alone cannot establish the
                    // contention premise.
                    if (i == 0)
                    {
                        started.fetch_add(1, std::memory_order_acq_rel);
                    }
                    (void)is_readable(mem, 4);
                }
                finished.fetch_add(1, std::memory_order_acq_rel);
            }
        );
    }
    // Wait until every reader is live and hammering, so shutdown overlaps in-flight reads on many stripes.
    while (started.load(std::memory_order_acquire) < READER_THREADS)
    {
        std::this_thread::yield();
    }

    memory::shutdown_cache();
    for (auto &r : readers)
    {
        r.join();
    }
    EXPECT_EQ(finished.load(std::memory_order_acquire), READER_THREADS);

    // Re-init for TearDown
    (void)memory::init_cache();
    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadable_NoCacheInitialized_OverflowGuard)
{
    memory::shutdown_cache();

    // Use a real mapped buffer so VirtualQuery succeeds and the code reaches the overflow guard in the direct
    // (no-cache) path.
    void *buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(buf, nullptr);

    const size_t wrapping_size = UINTPTR_MAX - reinterpret_cast<uintptr_t>(buf) + 2;
    EXPECT_FALSE(is_readable(buf, wrapping_size));

    VirtualFree(buf, 0, MEM_RELEASE);

    // Re-init for TearDown
    (void)memory::init_cache();
}

TEST_F(MemoryTest, IsReadableNonblocking_ValidMemory)
{
    char buffer[100] = {0};
    auto status = is_readable_nonblocking(buffer, sizeof(buffer));
    EXPECT_NE(status, memory::ReadableStatus::NotReadable);
}

TEST_F(MemoryTest, IsReadableNonblocking_NullAddress)
{
    auto status = is_readable_nonblocking(nullptr, 100);
    EXPECT_EQ(status, memory::ReadableStatus::NotReadable);
}

TEST_F(MemoryTest, IsReadableNonblocking_ZeroSize)
{
    char buffer[100] = {0};
    auto status = is_readable_nonblocking(buffer, 0);
    EXPECT_EQ(status, memory::ReadableStatus::NotReadable);
}

TEST_F(MemoryTest, IsReadableNonblocking_NoAccessMemory)
{
    void *noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noaccess, nullptr);

    // Prime cache so nonblocking has data
    (void)is_readable(noaccess, 1);

    auto status = is_readable_nonblocking(noaccess, 1);
    EXPECT_EQ(status, memory::ReadableStatus::NotReadable);

    VirtualFree(noaccess, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_CachedHit)
{
    char buffer[100] = {0};

    // Prime cache with a regular read
    EXPECT_TRUE(is_readable(buffer, sizeof(buffer)));

    auto status = is_readable_nonblocking(buffer, sizeof(buffer));
    EXPECT_EQ(status, memory::ReadableStatus::Readable);
}

TEST_F(MemoryTest, IsReadableNonblocking_NoCacheInitialized)
{
    memory::shutdown_cache();

    char buffer[100] = {0};
    auto status = is_readable_nonblocking(buffer, sizeof(buffer));
    // Falls back to direct VirtualQuery when cache is not initialized
    EXPECT_EQ(status, memory::ReadableStatus::Readable);

    (void)memory::init_cache();
}

TEST_F(MemoryTest, IsReadableNonblocking_FreedMemory)
{
    memory::clear_cache();
    memory::shutdown_cache();

    // Another allocation can map the address after VirtualFree. Bounded cycles find an address that stays free after
    // the probe. A re-mapped cycle proves nothing about freed memory and is discarded.
    bool proved = false;
    for (int attempt = 0; attempt < 8 && !proved; ++attempt)
    {
        void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        ASSERT_NE(mem, nullptr);
        VirtualFree(mem, 0, MEM_RELEASE);

        const auto status = is_readable_nonblocking(mem, 1);

        MEMORY_BASIC_INFORMATION info{};
        const bool still_free = VirtualQuery(mem, &info, sizeof(info)) == sizeof(info) && info.State == MEM_FREE;
        if (!still_free)
        {
            continue;
        }
        EXPECT_EQ(status, memory::ReadableStatus::NotReadable);
        proved = true;
    }
    EXPECT_TRUE(proved) << "every cycle lost the freed address to a concurrent re-mapping";

    (void)memory::init_cache();
}

TEST_F(MemoryTest, IsReadableNonblocking_ReservedMemory)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    // Prime cache
    (void)is_readable(reserved, 1);

    auto status = is_readable_nonblocking(reserved, 1);
    EXPECT_EQ(status, memory::ReadableStatus::NotReadable);

    VirtualFree(reserved, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_GuardPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    DWORD old_protect;
    VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect);

    memory::clear_cache();
    // Prime cache with guard-page state
    (void)is_readable(mem, 1);

    auto status = is_readable_nonblocking(mem, 1);
    EXPECT_EQ(status, memory::ReadableStatus::NotReadable);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_ReadOnlyPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    // Prime cache
    (void)is_readable(mem, 1);

    auto status = is_readable_nonblocking(mem, 1);
    EXPECT_EQ(status, memory::ReadableStatus::Readable);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_SizeOverflow)
{
    char buffer[1] = {0};
    auto status = is_readable_nonblocking(buffer, SIZE_MAX);
    // Overflow in address arithmetic must not yield Readable.
    EXPECT_NE(status, memory::ReadableStatus::Readable);
}

TEST_F(MemoryTest, IsReadableNonblocking_HeapAllocation)
{
    auto buffer = std::make_unique<char[]>(100);

    // Prime cache
    (void)is_readable(buffer.get(), 100);

    auto status = is_readable_nonblocking(buffer.get(), 100);
    EXPECT_EQ(status, memory::ReadableStatus::Readable);
}

TEST_F(MemoryTest, ReadableStatus_EnumValues)
{
    EXPECT_NE(memory::ReadableStatus::Readable, memory::ReadableStatus::NotReadable);
    EXPECT_NE(memory::ReadableStatus::Readable, memory::ReadableStatus::Unknown);
    EXPECT_NE(memory::ReadableStatus::NotReadable, memory::ReadableStatus::Unknown);
}

TEST_F(MemoryTest, InvalidateRange_WraparoundAddress)
{
    uintptr_t near_max = UINTPTR_MAX - 0x10;
    size_t large_size = 0x100;

    EXPECT_NO_THROW(invalidate_range(reinterpret_cast<const void *>(near_max), large_size));
}

TEST_F(MemoryTest, IsReadableNonblocking_LargeValidRegion)
{
    void *mem = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // First call populates cache
    auto status1 = is_readable_nonblocking(mem, 0x10000);
    EXPECT_NE(status1, memory::ReadableStatus::NotReadable);

    auto status2 = is_readable_nonblocking(mem, 0x10000);
    EXPECT_NE(status2, memory::ReadableStatus::NotReadable);

    VirtualFree(mem, 0, MEM_RELEASE);
}

// is_readable and is_writable fall back to a direct VirtualQuery walk while the cache is stopped. The walk
// answers from the live page protection.
TEST(MemoryUninitializedCache, PermissionChecksFallBackToDirectQuery)
{
    // Force the zero-shard state regardless of prior tests' cache lifecycle.
    memory::shutdown_cache();

    void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);

    EXPECT_TRUE(is_readable(region, 64));
    EXPECT_TRUE(is_writable(region, 64));

    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(region, 4096, PAGE_NOACCESS, &old_protect), 0);
    EXPECT_FALSE(is_readable(region, 64));
    EXPECT_FALSE(is_writable(region, 64));

    VirtualProtect(region, 4096, old_protect, &old_protect);
    VirtualFree(region, 0, MEM_RELEASE);
}

// The reader guard protects the shard array during the stats walk. The initialization gate also protects the config
// snapshot from concurrent shutdown.
TEST_F(MemoryTest, GetMemoryStats_ConcurrentWithShutdownNoUseAfterFree)
{
    std::atomic<bool> stop{false};
    std::atomic<bool> torn{false};
    std::atomic<long long> reads{0};

    std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i)
    {
        readers.emplace_back(
            [&stop, &torn, &reads]() -> void
            {
                while (!stop.load(std::memory_order_relaxed))
                {
                    const memory::MemoryStats s = memory::get_memory_stats();
                    // The worker reports through an atomic flag. Each snapshot must contain either zero shard-derived
                    // fields or a complete live config.
                    if (s.shard_count == 0)
                    {
                        if (s.total_entries != 0 || s.hard_max_per_shard != 0 || s.max_entries_per_shard != 0 ||
                            s.expiry_ms != 0)
                        {
                            torn.store(true, std::memory_order_relaxed);
                        }
                    }
                    else if (s.expiry_ms == 0)
                    {
                        torn.store(true, std::memory_order_relaxed);
                    }
                    reads.fetch_add(1, std::memory_order_relaxed);
                }
            }
        );
    }

    // A fatal assertion before the reader joins terminates the process. The failure path records the error and retains
    // the stop-and-join sequence.
    bool init_ok = true;
    for (int cycle = 0; cycle < 200 && init_ok; ++cycle)
    {
        memory::shutdown_cache();
        init_ok = memory::init_cache(64, 10000);
        if (!init_ok)
        {
            break;
        }
        // Populate an entry so the stats loop has shard content to walk during the race.
        int probe = 0;
        (void)memory::is_readable(Region{Address{&probe}, sizeof(probe)});
    }

    stop.store(true, std::memory_order_relaxed);
    for (auto &t : readers)
    {
        t.join();
    }

    EXPECT_TRUE(init_ok);
    EXPECT_GT(reads.load(), 0);
    EXPECT_FALSE(torn.load());
    // The loop leaves the cache initialized with capacity 64 and TTL 10000.
}

// Only one concurrent shutdown_cache caller can join the cleanup thread. A second join can throw out of noexcept and
// terminate the process.
TEST_F(MemoryTest, ShutdownCache_ConcurrentCallersJoinExactlyOnceNoTerminate)
{
    // Start from a known-initialized state so a background cleanup thread exists and the join/detach path is exercised.
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(32, 5000));

    int probe = 0;
    (void)memory::is_readable(Region{Address{&probe}, sizeof(probe)});

    constexpr int THREAD_COUNT = 8;
    std::vector<std::thread> callers;
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        callers.emplace_back(
            [&ready, &go]()
            {
                ready.fetch_add(1, std::memory_order_relaxed);
                while (!go.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                memory::shutdown_cache();
            }
        );
    }
    while (ready.load(std::memory_order_relaxed) < THREAD_COUNT)
    {
        std::this_thread::yield();
    }
    go.store(true, std::memory_order_release);
    for (auto &t : callers)
    {
        t.join();
    }

    // A fresh init must succeed after concurrent teardown.
    EXPECT_TRUE(memory::init_cache(32, 5000));
}

// Start, stop, and reads share one lifecycle generation. The final restart detects a stale state or joinable handle
// left by the concurrent transition storm.
TEST(MemoryCacheLifecycleProof, ConcurrentInitShutdownNeverLeavesJoinableGeneration)
{
    memory::shutdown_cache(); // start from a known Stopped state

    constexpr int INITIALIZERS = 2;
    constexpr int SHUTDOWNERS = 2;
    constexpr int READERS = 4;
    constexpr int ITERATIONS = 2000;
    const int total_workers = INITIALIZERS + SHUTDOWNERS + READERS;

    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    int probe = 0;
    std::vector<std::thread> workers;

    for (int i = 0; i < INITIALIZERS; ++i)
    {
        workers.emplace_back(
            [&ready, &go]()
            {
                ready.fetch_add(1, std::memory_order_relaxed);
                while (!go.load(std::memory_order_acquire))
                    std::this_thread::yield();
                for (int n = 0; n < ITERATIONS; ++n)
                    (void)memory::init_cache(32, 5000);
            }
        );
    }
    for (int i = 0; i < SHUTDOWNERS; ++i)
    {
        workers.emplace_back(
            [&ready, &go]()
            {
                ready.fetch_add(1, std::memory_order_relaxed);
                while (!go.load(std::memory_order_acquire))
                    std::this_thread::yield();
                for (int n = 0; n < ITERATIONS; ++n)
                    memory::shutdown_cache();
            }
        );
    }
    for (int i = 0; i < READERS; ++i)
    {
        workers.emplace_back(
            [&ready, &go, &probe]()
            {
                ready.fetch_add(1, std::memory_order_relaxed);
                while (!go.load(std::memory_order_acquire))
                    std::this_thread::yield();
                for (int n = 0; n < ITERATIONS; ++n)
                    (void)memory::is_readable(Region{Address{&probe}, sizeof(probe)});
            }
        );
    }

    while (ready.load(std::memory_order_relaxed) < total_workers)
        std::this_thread::yield();
    go.store(true, std::memory_order_release);
    for (auto &worker : workers)
        worker.join();

    // Reaching here without std::terminate (no thread-handle data race, no assign-into-joinable, no double-join) is the
    // core proof. Now require a clean restart, probe, and shutdown after the storm.
    ASSERT_TRUE(memory::init_cache(32, 5000));
    EXPECT_TRUE(memory::is_readable(Region{Address{&probe}, sizeof(probe)}));
    memory::shutdown_cache();

    // Shutdown joins before init reassigns the cleanup handle. The sticky counter must detect any violation of that
    // order.
    ASSERT_TRUE(memory::init_cache(32, 5000));
    EXPECT_EQ(memory::get_memory_stats().lifecycle_violations, 0u);
    memory::shutdown_cache();
}

// DMK_ENABLE_TEST_SEAMS excludes these schedules from the shipped library.
#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    extern void (*g_memory_cache_before_lifecycle_lock_test_hook)();
    extern void (*g_memory_cache_before_running_publish_test_hook)();
    extern void (*g_memory_cache_reopen_window_test_hook)();
    extern void (*g_memory_cache_shutdown_window_test_hook)();
    extern void (*g_memory_cache_leader_publish_window_test_hook)();
    extern HMODULE (*g_memory_cache_keepalive_ref_override)() noexcept;
    void memory_cache_abandon_for_test() noexcept;
    std::uint64_t memory_cache_admitted_reader_count_for_test() noexcept;
    bool memory_cache_reader_would_be_admitted_for_test() noexcept;
    void memory_cache_hold_shared_shard_lock_for_test(Address address, void (*callback)() noexcept) noexcept;
    void memory_cache_shard_index_sizes_for_test(
        Address address,
        std::size_t &entries,
        std::size_t &fifo,
        std::size_t &ranges
    ) noexcept;
} // namespace DetourModKit::detail

namespace
{
    std::atomic<bool> s_seam_init_at_lifecycle_lock{false};
    std::atomic<bool> s_seam_init_finished{false};
    std::atomic<bool> s_seam_init_ok{false};
    std::thread s_seam_initializer;

    void mark_initializer_at_lifecycle_lock()
    {
        s_seam_init_at_lifecycle_lock.store(true, std::memory_order_release);
    }

    std::atomic<bool> s_publish_window_entered{false};
    std::atomic<bool> s_release_publish_window{false};

    void wait_before_running_publish()
    {
        s_publish_window_entered.store(true, std::memory_order_release);
        while (!s_release_publish_window.load(std::memory_order_acquire))
            std::this_thread::yield();
    }

    void abandon_during_admission_reopen()
    {
        DetourModKit::detail::memory_cache_abandon_for_test();
    }

    HMODULE refuse_cache_keepalive() noexcept
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }

    // Spawn an initializer and wait until it reaches the lifecycle-lock boundary held by shutdown.
    void spawn_concurrent_initializer_hook()
    {
        s_seam_initializer = std::thread(
            []()
            {
                const bool ok = memory::init_cache(32, 5000);
                s_seam_init_ok.store(ok, std::memory_order_release);
                s_seam_init_finished.store(true, std::memory_order_release);
            }
        );
        while (!s_seam_init_at_lifecycle_lock.load(std::memory_order_acquire))
            std::this_thread::yield();
        EXPECT_FALSE(s_seam_init_finished.load(std::memory_order_acquire))
            << "concurrent init completed while shutdown held the lifecycle mutex: start not serialized after stop";
    }

    void *s_leader_seam_page = nullptr;
    std::atomic<int> s_leader_seam_fires{0};

    // The seam clears the cache generation and makes the page read-only before the leader publishes its writable
    // result.
    void clear_and_reprotect_in_leader_window_hook()
    {
        if (s_leader_seam_fires.fetch_add(1, std::memory_order_relaxed) != 0)
            return;
        memory::clear_cache();
        DWORD old_protect = 0;
        (void)VirtualProtect(s_leader_seam_page, 1, PAGE_READONLY, &old_protect);
    }

    std::atomic<int> s_leader_inval_fires{0};

    // The seam invalidates an in-flight leader's range and makes the page read-only. Its eventual writable result
    // carries the old generation.
    void invalidate_and_reprotect_in_leader_window_hook()
    {
        if (s_leader_inval_fires.fetch_add(1, std::memory_order_relaxed) != 0)
            return;
        memory::invalidate_range(Region{Address{s_leader_seam_page}, 1});
        DWORD old_protect = 0;
        (void)VirtualProtect(s_leader_seam_page, 1, PAGE_READONLY, &old_protect);
    }

    void *s_contended_invalidation_page = nullptr;
    std::atomic<bool> s_contended_shard_locked{false};
    std::atomic<bool> s_release_contended_shard{false};

    void wait_with_shared_shard_lock() noexcept
    {
        s_contended_shard_locked.store(true, std::memory_order_release);
        while (!s_release_contended_shard.load(std::memory_order_acquire))
            std::this_thread::yield();
    }

    void *s_post_stop_probe_page = nullptr;
    std::atomic<int> s_post_stop_hook_fires{0};
    std::atomic<bool> s_post_stop_reader_answer{false};
    std::atomic<bool> s_post_stop_admission_granted{true};
    std::atomic<std::uint64_t> s_post_stop_admitted_before{1};
    std::atomic<std::uint64_t> s_post_stop_admitted_after{1};

    // Fire after shutdown_cache publishes Stopping and closes admission. A permission query must take the uncached
    // route and must not join the drain population.
    void post_stop_reader_probe_hook()
    {
        if (s_post_stop_hook_fires.fetch_add(1, std::memory_order_relaxed) != 0)
            return;
        s_post_stop_admitted_before.store(
            DetourModKit::detail::memory_cache_admitted_reader_count_for_test(),
            std::memory_order_relaxed
        );
        // The closed-bit compare-exchange itself must refuse the reader.
        s_post_stop_admission_granted.store(
            DetourModKit::detail::memory_cache_reader_would_be_admitted_for_test(),
            std::memory_order_relaxed
        );
        s_post_stop_reader_answer.store(
            memory::is_readable(Region{Address{s_post_stop_probe_page}, 1}),
            std::memory_order_relaxed
        );
        s_post_stop_admitted_after.store(
            DetourModKit::detail::memory_cache_admitted_reader_count_for_test(),
            std::memory_order_relaxed
        );
    }
} // namespace

TEST(MemoryCacheLifecycleProof, ForcedOldStopNewStartScheduleIsSerialized)
{
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(32, 5000));

    s_seam_init_at_lifecycle_lock.store(false, std::memory_order_relaxed);
    s_seam_init_finished.store(false, std::memory_order_relaxed);
    s_seam_init_ok.store(false, std::memory_order_relaxed);

    DetourModKit::detail::g_memory_cache_before_lifecycle_lock_test_hook = &mark_initializer_at_lifecycle_lock;
    DetourModKit::detail::g_memory_cache_shutdown_window_test_hook = &spawn_concurrent_initializer_hook;
    memory::shutdown_cache();
    DetourModKit::detail::g_memory_cache_shutdown_window_test_hook = nullptr;
    DetourModKit::detail::g_memory_cache_before_lifecycle_lock_test_hook = nullptr;

    ASSERT_TRUE(s_seam_initializer.joinable());
    s_seam_initializer.join();

    EXPECT_TRUE(s_seam_init_finished.load(std::memory_order_acquire));
    EXPECT_TRUE(s_seam_init_ok.load(std::memory_order_acquire));

    int probe = 0;
    EXPECT_TRUE(memory::is_readable(Region{Address{&probe}, sizeof(probe)}));
    EXPECT_EQ(memory::get_memory_stats().lifecycle_violations, 0u);

    memory::shutdown_cache();
}

// A permission query after shutdown closes admission must use the uncached route. It must not extend the drain
// population ([B-73]).
TEST(MemoryCacheLifecycleProof, ShutdownRejectsPostStopReaderWithoutExtendingDrain)
{
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(32, 5000));

    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);
    ASSERT_TRUE(memory::is_readable(Region{Address{page}, 1}));

    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::MemoryCache);

    s_post_stop_probe_page = page;
    s_post_stop_hook_fires.store(0, std::memory_order_relaxed);
    DetourModKit::detail::g_memory_cache_shutdown_window_test_hook = &post_stop_reader_probe_hook;
    memory::shutdown_cache();
    DetourModKit::detail::g_memory_cache_shutdown_window_test_hook = nullptr;

    EXPECT_EQ(s_post_stop_hook_fires.load(std::memory_order_relaxed), 1);
    // The closed admission word refused the post-stop reader outright.
    EXPECT_FALSE(s_post_stop_admission_granted.load(std::memory_order_relaxed));
    // The rejected reader still receives the correct uncached answer.
    EXPECT_TRUE(s_post_stop_reader_answer.load(std::memory_order_relaxed));
    // It never entered the closed drain population: the admitted count stayed zero around its whole call.
    EXPECT_EQ(s_post_stop_admitted_before.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(s_post_stop_admitted_after.load(std::memory_order_relaxed), 0u);
    // The drain therefore saw a closed, empty population: no timeout retention was recorded.
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::MemoryCache),
        leaks_before
    );

    VirtualFree(page, 0, MEM_RELEASE);
    ASSERT_TRUE(memory::init_cache(32, 5000));
    const int probe = 0;
    EXPECT_TRUE(memory::is_readable(Region{Address{&probe}, sizeof(probe)}));
    memory::shutdown_cache();
}

// Loader abandonment can cancel Starting without the lifecycle lock. Final publication cannot overwrite that
// cancellation.
TEST(MemoryCacheLifecycleProof, AbandonedStartingGenerationCannotPublishRunning)
{
    memory::shutdown_cache();
    s_publish_window_entered.store(false, std::memory_order_relaxed);
    s_release_publish_window.store(false, std::memory_order_relaxed);
    std::atomic<bool> init_ok{true};

    DetourModKit::detail::g_memory_cache_before_running_publish_test_hook = &wait_before_running_publish;
    std::thread initializer([&init_ok]() { init_ok.store(memory::init_cache(32, 5000), std::memory_order_release); });

    while (!s_publish_window_entered.load(std::memory_order_acquire))
        std::this_thread::yield();

    DetourModKit::detail::memory_cache_abandon_for_test();
    s_release_publish_window.store(true, std::memory_order_release);
    initializer.join();
    DetourModKit::detail::g_memory_cache_before_running_publish_test_hook = nullptr;

    EXPECT_FALSE(init_ok.load(std::memory_order_acquire));
    EXPECT_EQ(memory::get_memory_stats().shard_count, 0u);

    ASSERT_TRUE(memory::init_cache(32, 5000));
    const int probe = 0;
    EXPECT_TRUE(memory::is_readable(Region{Address{&probe}, sizeof(probe)}));
    memory::shutdown_cache();
}

TEST(MemoryCacheLifecycleProof, AdmissionReopenCannotOutrunConcurrentAbandonment)
{
    memory::shutdown_cache();
    DetourModKit::detail::g_memory_cache_reopen_window_test_hook = &abandon_during_admission_reopen;
    const bool started = memory::init_cache(32, 5000);
    DetourModKit::detail::g_memory_cache_reopen_window_test_hook = nullptr;

    EXPECT_FALSE(started);
    EXPECT_FALSE(DetourModKit::detail::memory_cache_reader_would_be_admitted_for_test());
    memory::shutdown_cache();

    ASSERT_TRUE(memory::init_cache(32, 5000));
    const int probe = 0;
    EXPECT_TRUE(memory::is_readable(Region{Address{&probe}, sizeof(probe)}));
    memory::shutdown_cache();
}

TEST(MemoryCacheLifecycleProof, StartRefusesWithoutPrecommittedTimeoutKeepalive)
{
    memory::shutdown_cache();
    DetourModKit::detail::g_memory_cache_keepalive_ref_override = &refuse_cache_keepalive;
    const bool started = memory::init_cache(32, 5000);
    DetourModKit::detail::g_memory_cache_keepalive_ref_override = nullptr;

    EXPECT_FALSE(started);
    if (started)
        memory::shutdown_cache();

    ASSERT_TRUE(memory::init_cache(32, 5000));
    const int probe = 0;
    EXPECT_TRUE(memory::is_readable(Region{Address{&probe}, sizeof(probe)}));
    memory::shutdown_cache();
}

// A clear in the query/publish window invalidates the leader's captured generation.
TEST(MemoryCacheLifecycleProof, ClearDuringInFlightLeaderCannotRepublishStale)
{
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(8, 60000, 1)); // single shard

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    s_leader_seam_page = mem;
    s_leader_seam_fires.store(0, std::memory_order_relaxed);
    DetourModKit::detail::g_memory_cache_leader_publish_window_test_hook = &clear_and_reprotect_in_leader_window_hook;

    // The first miss elects a leader. A concurrent clear and reprotection make its eventual writable publication stale.
    (void)memory::is_writable(Region{Address{mem}, 1});

    DetourModKit::detail::g_memory_cache_leader_publish_window_test_hook = nullptr;

    // The stale entry's generation no longer matches, so the next probe re-queries and sees the real protection.
    EXPECT_FALSE(memory::is_writable(Region{Address{mem}, 1}));
    EXPECT_TRUE(memory::is_readable(Region{Address{mem}, 1}));
    EXPECT_EQ(s_leader_seam_fires.load(std::memory_order_relaxed), 1);

    VirtualFree(mem, 0, MEM_RELEASE);
    memory::shutdown_cache();
}

// Invalidation that wins the lock while a leader is in flight invalidates the leader's captured generation.
TEST(MemoryCacheLifecycleProof, InvalidateDuringInFlightLeaderCannotRepublishStale)
{
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(8, 60000, 1)); // single shard

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    s_leader_seam_page = mem;
    s_leader_inval_fires.store(0, std::memory_order_relaxed);
    DetourModKit::detail::g_memory_cache_leader_publish_window_test_hook =
        &invalidate_and_reprotect_in_leader_window_hook;

    // The first miss elects a leader. Invalidation advances the in-flight generation before that leader publishes its
    // old writable result.
    (void)memory::is_writable(Region{Address{mem}, 1});

    DetourModKit::detail::g_memory_cache_leader_publish_window_test_hook = nullptr;

    // The generation mismatch forces a re-query that sees the real read-only protection.
    EXPECT_FALSE(memory::is_writable(Region{Address{mem}, 1}));
    EXPECT_TRUE(memory::is_readable(Region{Address{mem}, 1}));
    EXPECT_EQ(s_leader_inval_fires.load(std::memory_order_relaxed), 1);

    VirtualFree(mem, 0, MEM_RELEASE);
    memory::shutdown_cache();
}

// A failed exclusive try-lock must still invalidate the shard logically, so the next probe cannot use stale protection.
TEST(MemoryCacheLifecycleProof, ContendedInvalidationAdvancesContentGeneration)
{
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(8, 60000, 1));

    void *const mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    ASSERT_TRUE(memory::is_writable(Region{Address{mem}, 1}));

    s_contended_invalidation_page = mem;
    s_contended_shard_locked.store(false, std::memory_order_relaxed);
    s_release_contended_shard.store(false, std::memory_order_relaxed);
    std::thread lock_holder(
        []()
        {
            DetourModKit::detail::memory_cache_hold_shared_shard_lock_for_test(
                Address{s_contended_invalidation_page},
                &wait_with_shared_shard_lock
            );
        }
    );

    while (!s_contended_shard_locked.load(std::memory_order_acquire))
        std::this_thread::yield();

    DWORD old_protect = 0;
    const BOOL protect_ok = VirtualProtect(mem, 1, PAGE_READONLY, &old_protect);
    memory::invalidate_range(Region{Address{mem}, 1});

    s_release_contended_shard.store(true, std::memory_order_release);
    lock_holder.join();

    ASSERT_NE(protect_ok, FALSE);

    if (dmk_test::stl_supports_exact_allocation_budgets())
    {
        bool writable_after_failure = true;
        {
            dmk_test::AllocFailScope fail{0};
            writable_after_failure = memory::is_writable(Region{Address{mem}, 1});
        }
        EXPECT_FALSE(writable_after_failure);

        std::size_t entries = 0;
        std::size_t fifo = 0;
        std::size_t ranges = 0;
        DetourModKit::detail::memory_cache_shard_index_sizes_for_test(Address{mem}, entries, fifo, ranges);
        EXPECT_EQ(entries, static_cast<std::size_t>(0));
        EXPECT_EQ(fifo, static_cast<std::size_t>(0));
        EXPECT_EQ(ranges, static_cast<std::size_t>(0));
    }

    EXPECT_FALSE(memory::is_writable(Region{Address{mem}, 1}));
    EXPECT_TRUE(memory::is_readable(Region{Address{mem}, 1}));

    VirtualFree(mem, 0, MEM_RELEASE);
    memory::shutdown_cache();
}
#endif // DMK_ENABLE_TEST_SEAMS

// The sweep reaches each cache insertion allocation, including the deque chunk. Failure must preserve the authoritative
// VirtualQuery answer.
TEST_F(MemoryTest, IsReadable_CacheInsertAllocFailureFailsSoftAtEveryStage)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    int probe = 7;

    for (int allow = 0; allow <= 4; ++allow)
    {
        // The sweep reaches the insert_sorted_range deque allocation. init_cache stays outside the poisoned window, so
        // shard and handler allocations cannot explain the result.
        memory::shutdown_cache();
        ASSERT_TRUE(memory::init_cache(16, 60000));

        bool readable = false;
        {
            // The sweep reaches the unordered_map node, FIFO node, and deque chunk. GoogleTest macros allocate, so none
            // can run inside the poisoned window.
            dmk_test::AllocFailScope fail{allow};
            readable = memory::is_readable(Region{Address{&probe}, sizeof(probe)});
        }

        // The VirtualQuery answer must stay correct after concurrent teardown.
        EXPECT_TRUE(readable) << "allow=" << allow;
    }
}

namespace
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    // A live cache bypasses the start veto. A stopped cache still rejects a vetoed start.
    TEST_F(MemoryTest, InitCacheVetoedWhileRunningStaysTrue)
    {
        memory::shutdown_cache();
        ASSERT_TRUE(memory::init_cache(64, 60000, 2));
        ASSERT_EQ(memory::get_memory_stats().shard_count, static_cast<std::size_t>(2));

        {
            const dmk_test::ForcedLoaderProbe veto;
            EXPECT_TRUE(memory::init_cache(64, 60000, 2)) << "a running cache is already the requested state";
        }

        const memory::MemoryStats after = memory::get_memory_stats();
        EXPECT_EQ(after.shard_count, static_cast<std::size_t>(2)) << "the vetoed call must reconfigure nothing";
        EXPECT_EQ(after.max_entries_per_shard, static_cast<std::size_t>(32));

        // The veto still refuses a new start.
        memory::shutdown_cache();
        {
            const dmk_test::ForcedLoaderProbe veto;
            EXPECT_FALSE(memory::init_cache(64, 60000, 2));
        }
        EXPECT_EQ(memory::get_memory_stats().shard_count, static_cast<std::size_t>(0));
    }

    // Each failed insert must leave all three shard indexes equal and within the hard bound.
    TEST_F(MemoryTest, CacheInsertFaultRollbackStaysConsistent)
    {
        DMK_REQUIRE_PROXY_FREE_STL();
        memory::shutdown_cache();
        // One shard makes the soft capacity the requested 2, and the hard bound that times the production multiplier.
        ASSERT_TRUE(memory::init_cache(2, 60000, 1));
        constexpr std::size_t hard_bound = 2 * memory::DEFAULT_MAX_CACHE_SIZE_MULTIPLIER;

        std::vector<void *> pages;
        std::size_t entries = 0;
        std::size_t fifo = 0;
        std::size_t ranges = 0;

        // Repeated budgets cover each allocation site and expose any orphan index.
        for (int round = 0; round < 24; ++round)
        {
            void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            ASSERT_NE(page, nullptr);
            pages.push_back(page);

            {
                // No GoogleTest macro runs inside the armed window. Each one allocates and consumes the budget.
                dmk_test::AllocFailScope fail{round % 6};
                (void)memory::is_readable(Region{Address{page}, 1});
            }

            DetourModKit::detail::memory_cache_shard_index_sizes_for_test(Address{page}, entries, fifo, ranges);
            EXPECT_EQ(entries, fifo) << "round " << round << ": an entry with no FIFO record can never be evicted";
            EXPECT_EQ(entries, ranges) << "round " << round << ": an entry with no range record is unreachable";
            EXPECT_LE(entries, hard_bound) << "round " << round;
        }

        // The shard accepts new entries after every fault and enforces its bound.
        for (void *const page : pages)
        {
            EXPECT_TRUE(memory::is_readable(Region{Address{page}, 1}));
        }
        DetourModKit::detail::memory_cache_shard_index_sizes_for_test(Address{pages.front()}, entries, fifo, ranges);
        EXPECT_GT(entries, static_cast<std::size_t>(0)) << "the shard must accept entries again after the failures";
        EXPECT_EQ(entries, fifo);
        EXPECT_EQ(entries, ranges);
        EXPECT_LE(entries, hard_bound);
        EXPECT_LE(memory::get_memory_stats().total_entries, hard_bound);

        for (void *const page : pages)
        {
            VirtualFree(page, 0, MEM_RELEASE);
        }
        memory::shutdown_cache();
    }
#endif // DMK_ENABLE_TEST_SEAMS

    // Extreme sizes must fail through the bool boundary without cache state publication.
    TEST_F(MemoryTest, InitCacheRejectsWrappingAndThrowingSizes)
    {
        memory::shutdown_cache();

        struct ExtremeCase
        {
            const char *label;
            std::size_t cache_size;
            std::size_t shard_count;
        };
        // Cases cover ceiling overflow, hard-bound overflow, max_size, and zero-shard normalization.
        static constexpr ExtremeCase cases[] = {
            {"sum wraps to a zero capacity", SIZE_MAX, 64},
            {"multiplier overflows", SIZE_MAX, 1},
            {"multiplier wraps to a zero hard bound", (SIZE_MAX / 2) + 1, 1},
            {"reserve exceeds max_size", SIZE_MAX / 4, 1},
            {"zero shards normalize to one", SIZE_MAX, 0},
        };

        for (const ExtremeCase &extreme : cases)
        {
            bool accepted = true;
            EXPECT_NO_THROW(accepted = memory::init_cache(extreme.cache_size, 100, extreme.shard_count))
                << extreme.label << ": the bool boundary must contain every exception";
            EXPECT_FALSE(accepted) << extreme.label;

            // Failure publishes no cache state.
            const memory::MemoryStats stats = memory::get_memory_stats();
            EXPECT_EQ(stats.shard_count, static_cast<std::size_t>(0)) << extreme.label;
            EXPECT_EQ(stats.max_entries_per_shard, static_cast<std::size_t>(0)) << extreme.label;
            EXPECT_EQ(stats.hard_max_per_shard, static_cast<std::size_t>(0)) << extreme.label;

            // A rejected request leaves the permission queries on their authoritative uncached route.
            int probe = 0;
            EXPECT_TRUE(memory::is_readable(Region{Address{&probe}, sizeof(probe)}));
        }

        // A valid request remains usable after each rejected size.
        ASSERT_TRUE(memory::init_cache(256, 50, 4));
        const memory::MemoryStats recovered = memory::get_memory_stats();
        EXPECT_EQ(recovered.shard_count, static_cast<std::size_t>(4));
        EXPECT_EQ(recovered.max_entries_per_shard, static_cast<std::size_t>(64));
        EXPECT_EQ(recovered.hard_max_per_shard, static_cast<std::size_t>(128));
        EXPECT_EQ(recovered.expiry_ms, 50u);
    }
} // namespace
