#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <atomic>
#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "memory_internal.hpp"

using namespace DetourModKit;

class MemoryTest : public ::testing::Test
{
protected:
    void SetUp() override { (void)Memory::init_cache(); }

    void TearDown() override { Memory::shutdown_cache(); }
};

TEST_F(MemoryTest, InitMemoryCache)
{
    bool result = Memory::init_cache();
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, InitMemoryCache_CustomParams)
{
    Memory::shutdown_cache();

    bool result = Memory::init_cache(64, 10000);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, ClearMemoryCache)
{
    EXPECT_NO_THROW(Memory::clear_cache());
    EXPECT_NO_THROW(Memory::clear_cache());
    EXPECT_NO_THROW(Memory::clear_cache());
}

TEST_F(MemoryTest, GetMemoryCacheStats)
{
    std::string stats = Memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
    EXPECT_NE(stats.find("Hits:"), std::string::npos);
    EXPECT_NE(stats.find("Misses:"), std::string::npos);
}

TEST_F(MemoryTest, GetMemoryStats_PopulatedAndConsistentWithString)
{
    const Memory::MemoryStats stats = Memory::get_memory_stats();

    // SetUp() initialized the cache, so the configuration fields are populated.
    EXPECT_GT(stats.shard_count, 0u);
    EXPECT_GT(stats.max_entries_per_shard, 0u);

    // hit_rate_percent is either the documented "no queries" sentinel or a real percentage.
    EXPECT_TRUE(stats.hit_rate_percent == -1.0 || (stats.hit_rate_percent >= 0.0 && stats.hit_rate_percent <= 100.0));

    // get_cache_stats() is a thin formatter over the same snapshot: the struct's counters appear verbatim.
    const std::string str = Memory::get_cache_stats();
    EXPECT_NE(str.find("Shards: " + std::to_string(stats.shard_count)), std::string::npos);
    EXPECT_NE(str.find("Hits: " + std::to_string(stats.hits)), std::string::npos);
    EXPECT_NE(str.find("Misses: " + std::to_string(stats.misses)), std::string::npos);
}

TEST_F(MemoryTest, GetMemoryStats_NoQueriesSentinel)
{
    Memory::clear_cache();
    const Memory::MemoryStats stats = Memory::get_memory_stats();
    // clear_cache() resets the hit/miss counters and no lookup runs before this read, so the "no queries" state is
    // deterministic and the sentinel must always hold.
    EXPECT_EQ(stats.hits + stats.misses, 0u);
    EXPECT_DOUBLE_EQ(stats.hit_rate_percent, -1.0);
    EXPECT_NE(Memory::get_cache_stats().find("N/A (no queries tracked)"), std::string::npos);
}

TEST_F(MemoryTest, IsMemoryReadable_Valid)
{
    char buffer[100] = {0};

    bool result = Memory::is_readable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryReadable_ValidHeap)
{
    auto buffer = std::make_unique<char[]>(100);

    bool result = Memory::is_readable(buffer.get(), 100);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryReadable_SingleByte)
{
    char c = 'A';
    bool result = Memory::is_readable(&c, 1);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryReadable_Invalid)
{
    bool result = Memory::is_readable(nullptr, 100);
    EXPECT_FALSE(result);
}

TEST_F(MemoryTest, IsMemoryReadable_ZeroSize)
{
    char buffer[100] = {0};

    bool result = Memory::is_readable(buffer, 0);
    EXPECT_FALSE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_Valid)
{
    char buffer[100] = {0};

    bool result = Memory::is_writable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_ValidHeap)
{
    auto buffer = std::make_unique<char[]>(100);

    bool result = Memory::is_writable(buffer.get(), 100);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_StackCharArray)
{
    char buffer[] = "test";
    bool result = Memory::is_writable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_Invalid)
{
    bool result = Memory::is_writable(nullptr, 100);
    EXPECT_FALSE(result);
}

TEST_F(MemoryTest, IsMemoryWritable_ZeroSize)
{
    char buffer[100] = {0};

    bool result = Memory::is_writable(buffer, 0);
    EXPECT_FALSE(result);
}

TEST_F(MemoryTest, write_bytes)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0x12},
                                     std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};

    auto result = Memory::write_bytes(target.data(), source.data(), source.size());
    EXPECT_TRUE(result.has_value());

    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }
}

TEST_F(MemoryTest, write_bytes_NullTarget)
{
    std::vector<std::byte> source = {std::byte{0x90}, std::byte{0x90}};

    auto result = Memory::write_bytes(nullptr, source.data(), source.size());
    EXPECT_FALSE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_NullSource)
{
    std::vector<std::byte> target(16, std::byte{0x00});

    auto result = Memory::write_bytes(target.data(), nullptr, 10);
    EXPECT_FALSE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_ZeroSize)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {std::byte{0x90}};

    auto result = Memory::write_bytes(target.data(), source.data(), 0);
    EXPECT_TRUE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_Large)
{
    std::vector<std::byte> target(1024, std::byte{0x00});
    std::vector<std::byte> source(512, std::byte{0xCC});

    auto result = Memory::write_bytes(target.data(), source.data(), source.size());
    EXPECT_TRUE(result.has_value());

    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }

    for (size_t i = source.size(); i < target.size(); ++i)
    {
        EXPECT_EQ(target[i], std::byte{0x00});
    }
}

TEST_F(MemoryTest, CacheBehavior)
{
    char buffer[100] = {0};

    bool result1 = Memory::is_readable(buffer, sizeof(buffer));
    EXPECT_TRUE(result1);

    bool result2 = Memory::is_readable(buffer, sizeof(buffer));
    EXPECT_TRUE(result2);

    std::string stats = Memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, MultipleRegions)
{
    char buffer1[100] = {0};
    char buffer2[200] = {0};

    EXPECT_TRUE(Memory::is_readable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(Memory::is_readable(buffer2, sizeof(buffer2)));
    EXPECT_TRUE(Memory::is_writable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(Memory::is_writable(buffer2, sizeof(buffer2)));
}

TEST_F(MemoryTest, CacheAfterClear)
{
    char buffer[100] = {0};

    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
    Memory::clear_cache();
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
}

TEST_F(MemoryTest, InvalidateRangeEvictsMultiPageRegionInterior)
{
    // Reserve and commit a three-page region so the cached VirtualQuery region spans multiple pages and the invalidated
    // interior address is not the region base. This exercises the case a single per-page key probe cannot find: the
    // entry is keyed by the region base, but the interior address hashes to a different shard, so only a per-shard
    // containment scan can locate the covering entry.
    const SIZE_T page_size = 4096;
    const SIZE_T region_size = page_size * 3;
    void *region = VirtualAlloc(nullptr, region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);

    auto *base = static_cast<uint8_t *>(region);
    // Inside the second page, so neither the region base nor a page-aligned key.
    uint8_t *interior = base + page_size + 64;

    // Warm the cache with a READABLE verdict for the interior address.
    EXPECT_TRUE(Memory::is_readable(interior, 16));

    // Flip the whole region to no-access. The cached entry is now stale: without a correct invalidation a subsequent
    // query would still report READABLE.
    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(region, region_size, PAGE_NOACCESS, &old_protect), 0);

    // Invalidate the interior address. A correct invalidation evicts the covering entry regardless of which shard
    // stored it.
    Memory::invalidate_range(interior, 16);

    // The re-query must re-run VirtualQuery and observe the no-access protection.
    EXPECT_FALSE(Memory::is_readable(interior, 16));

    VirtualProtect(region, region_size, old_protect, &old_protect);
    VirtualFree(region, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheClearStressTest)
{
    char buffer[100] = {0};

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
        Memory::clear_cache();
        // Small yield to allow any background threads to process
        std::this_thread::yield();
    }
}

TEST_F(MemoryTest, CacheInitClearCycle)
{
    for (int i = 0; i < 5; ++i)
    {
        Memory::shutdown_cache();
        EXPECT_TRUE(Memory::init_cache());
        Memory::clear_cache();
    }
}

TEST_F(MemoryTest, write_bytes_DataIntegrity)
{
    std::vector<std::byte> target(64);
    for (size_t i = 0; i < target.size(); ++i)
    {
        target[i] = std::byte{static_cast<uint8_t>(i)};
    }

    std::vector<std::byte> source = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    auto result = Memory::write_bytes(target.data() + 10, source.data(), source.size());
    EXPECT_TRUE(result.has_value());

    for (size_t i = 0; i < 10; ++i)
    {
        EXPECT_EQ(target[i], std::byte{static_cast<uint8_t>(i)});
    }

    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[10 + i], source[i]);
    }

    for (size_t i = 14; i < target.size(); ++i)
    {
        EXPECT_EQ(target[i], std::byte{static_cast<uint8_t>(i)});
    }
}

TEST_F(MemoryTest, IsMemoryReadable_StringLiteral)
{
    const char *str = "Hello, World!";
    bool result = Memory::is_readable(str, strlen(str));
    EXPECT_TRUE(result);
}

TEST(MemoryErrorTest, ErrorToString)
{
    EXPECT_FALSE(memory_error_to_string(MemoryError::NullTargetAddress).empty());
    EXPECT_FALSE(memory_error_to_string(MemoryError::NullSourceBytes).empty());
    EXPECT_FALSE(memory_error_to_string(MemoryError::ProtectionChangeFailed).empty());
    EXPECT_FALSE(memory_error_to_string(MemoryError::ProtectionRestoreFailed).empty());
    EXPECT_FALSE(memory_error_to_string(MemoryError::SizeTooLarge).empty());
    EXPECT_FALSE(memory_error_to_string(static_cast<MemoryError>(999)).empty());
}

TEST_F(MemoryTest, CacheExpiry)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(64, 10);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
}

TEST_F(MemoryTest, CacheBehavior_Overlapping)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(64, 10000);

    char buffer[100] = {0};

    EXPECT_TRUE(Memory::is_readable(buffer, 50));
    EXPECT_TRUE(Memory::is_readable(buffer, 100));
    EXPECT_TRUE(Memory::is_readable(buffer + 10, 40));
}

TEST_F(MemoryTest, IsMemoryReadable_ReservedMemory)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    EXPECT_FALSE(Memory::is_readable(reserved, 1));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_ReservedMemory)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    EXPECT_FALSE(Memory::is_writable(reserved, 1));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_ReadOnlyMemory)
{
    void *readonly = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(readonly, nullptr);

    EXPECT_FALSE(Memory::is_writable(readonly, 1));

    VirtualFree(readonly, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_NoAccess)
{
    void *noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noaccess, nullptr);

    EXPECT_FALSE(Memory::is_readable(noaccess, 1));

    VirtualFree(noaccess, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_NoAccess)
{
    void *noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noaccess, nullptr);

    EXPECT_FALSE(Memory::is_writable(noaccess, 1));

    VirtualFree(noaccess, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_FreedMemory)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    VirtualFree(mem, 0, MEM_RELEASE);

    EXPECT_FALSE(Memory::is_readable(mem, 1));
}

TEST_F(MemoryTest, IsMemoryWritable_ExecuteOnly)
{
    void *exec = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE);
    ASSERT_NE(exec, nullptr);

    EXPECT_FALSE(Memory::is_writable(exec, 1));

    VirtualFree(exec, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_ExecuteReadWrite)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(Memory::is_readable(mem, 1));
    EXPECT_TRUE(Memory::is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheLRUEviction)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(2, 60000);

    void *mem1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem3 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ASSERT_NE(mem1, nullptr);
    ASSERT_NE(mem2, nullptr);
    ASSERT_NE(mem3, nullptr);

    EXPECT_TRUE(Memory::is_readable(mem1, 1));
    EXPECT_TRUE(Memory::is_readable(mem2, 1));
    EXPECT_TRUE(Memory::is_readable(mem3, 1));
    EXPECT_TRUE(Memory::is_readable(mem1, 1));

    VirtualFree(mem1, 0, MEM_RELEASE);
    VirtualFree(mem2, 0, MEM_RELEASE);
    VirtualFree(mem3, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_SizeOverflow)
{
    char buffer[1] = {0};
    EXPECT_FALSE(Memory::is_readable(buffer, SIZE_MAX));
}

TEST_F(MemoryTest, IsMemoryWritable_SizeOverflow)
{
    char buffer[1] = {0};
    EXPECT_FALSE(Memory::is_writable(buffer, SIZE_MAX));
}

TEST_F(MemoryTest, write_bytes_ErrorTypes)
{
    std::byte source[] = {std::byte{0x90}};

    auto r1 = Memory::write_bytes(nullptr, source, 1);
    EXPECT_FALSE(r1.has_value());
    EXPECT_EQ(r1.error(), MemoryError::NullTargetAddress);

    std::byte target[1] = {std::byte{0}};
    auto r2 = Memory::write_bytes(target, nullptr, 1);
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), MemoryError::NullSourceBytes);
}

TEST_F(MemoryTest, write_bytes_SizeTooLarge)
{
    std::byte target[1] = {std::byte{0x00}};
    std::byte source[1] = {std::byte{0x90}};

    auto result = Memory::write_bytes(target, source, MAX_WRITE_SIZE + 1);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), MemoryError::SizeTooLarge);
}

TEST_F(MemoryTest, write_bytes_ZeroBytes)
{
    std::byte target[4] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
    std::byte source[1] = {std::byte{0x00}};

    auto result = Memory::write_bytes(target, source, 0);
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0xAA});
}

TEST_F(MemoryTest, write_bytes_Success)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);
    std::byte source[] = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto result = Memory::write_bytes(target, source, 3);
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0x90});
    EXPECT_EQ(target[1], std::byte{0x90});
    EXPECT_EQ(target[2], std::byte{0x90});

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_ValidWritable)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(4, 60000);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(Memory::is_writable(mem, 1));

    EXPECT_TRUE(Memory::is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, write_bytes_PageReadOnly)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);
    std::byte source[] = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    auto result = Memory::write_bytes(target, source, sizeof(source));
    EXPECT_TRUE(result.has_value());

    if (result.has_value())
    {
        EXPECT_EQ(target[0], std::byte{0xDE});
        EXPECT_EQ(target[1], std::byte{0xAD});
        EXPECT_EQ(target[2], std::byte{0xBE});
        EXPECT_EQ(target[3], std::byte{0xEF});
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_PageGuard)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    DWORD old_protect;
    BOOL ok = VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect);
    ASSERT_TRUE(ok);

    Memory::clear_cache();
    EXPECT_FALSE(Memory::is_readable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_PageGuard)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    DWORD old_protect;
    BOOL ok = VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect);
    ASSERT_TRUE(ok);

    Memory::clear_cache();
    EXPECT_FALSE(Memory::is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryReadable_CrossRegionBoundary)
{
    void *region1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *region2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region1, nullptr);
    ASSERT_NE(region2, nullptr);

    Memory::clear_cache();
    size_t oversized = 4096 + 1;
    EXPECT_FALSE(Memory::is_readable(region1, oversized));

    VirtualFree(region1, 0, MEM_RELEASE);
    VirtualFree(region2, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, InitCacheWithShards)
{
    Memory::shutdown_cache();
    bool result = Memory::init_cache(32, 5000, 4);
    EXPECT_TRUE(result);

    // Subsequent init with different params returns true but does not reconfigure
    result = Memory::init_cache(64, 10000, 8);
    EXPECT_TRUE(result);
}

TEST_F(MemoryTest, InvalidateRangeBasic)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(32, 60000, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    Memory::invalidate_range(buffer, sizeof(buffer));

    std::string stats = Memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, InvalidateRangeNull)
{
    EXPECT_NO_THROW(Memory::invalidate_range(nullptr, 100));
    EXPECT_NO_THROW(Memory::invalidate_range(reinterpret_cast<const void *>(static_cast<uintptr_t>(0x1000)), 0));
}

// Reader/writer contention stress over the region cache's sorted_ranges insert/erase churn. The shard SRW lock
// (shared for lookups, exclusive for mutation) is the correctness guarantee under test: reader threads probe an
// interior page of a multi-page region, which misses the page-aligned entries.find fast path and exercises the
// sorted_ranges containment search, while a single writer thread repeatedly invalidates the region. The test
// asserts the cache returns a consistent result for the same input across many iterations under contention.
TEST_F(MemoryTest, SortedRangesInsertDuringReadDoesNotCrash)
{
    Memory::shutdown_cache();
    // One shard so every probe and invalidation hashes to the same sorted_ranges container.
    (void)Memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 16 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Prime the cache so the region's sorted_ranges entry exists before contention starts.
    EXPECT_TRUE(Memory::is_readable(mem, 64));

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
                    (void)Memory::is_readable(interior, 64);
                    reader_count.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }

    // Writer thread: repeatedly invalidates the region, churning the lock-serialized insert/erase path in
    // sorted_ranges.
    std::thread writer(
        [&stop, &reader_count, mem]()
        {
            // Wait until at least one reader has been scheduled so the contention window is real.
            while (reader_count.load(std::memory_order_relaxed) == 0)
            {
                std::this_thread::yield();
            }
            for (int i = 0; i < iterations && !stop.load(std::memory_order_relaxed); ++i)
            {
                Memory::invalidate_range(mem, 64);
            }
            stop.store(true, std::memory_order_release);
        });

    writer.join();
    for (auto &r : readers)
    {
        r.join();
    }

    EXPECT_GT(reader_count.load(), 0);
    // Final read is still consistent.
    EXPECT_TRUE(Memory::is_readable(interior, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteBytesInvalidatesCache)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(32, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);

    EXPECT_TRUE(Memory::is_readable(target, 64));
    EXPECT_TRUE(Memory::is_writable(target, 64));

    std::byte source[] = {std::byte{0x90}, std::byte{0x91}, std::byte{0x92}};
    auto result = Memory::write_bytes(target, source, sizeof(source));
    EXPECT_TRUE(result.has_value());

    EXPECT_TRUE(Memory::is_readable(target, 64));
    EXPECT_TRUE(Memory::is_writable(target, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, InvalidateRangeDoesNotAffectOtherRegions)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(32, 60000, 4);

    char buffer1[100] = {0};
    char buffer2[100] = {0};

    EXPECT_TRUE(Memory::is_readable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(Memory::is_readable(buffer2, sizeof(buffer2)));

    Memory::invalidate_range(buffer1, sizeof(buffer1));

    EXPECT_TRUE(Memory::is_readable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(Memory::is_readable(buffer2, sizeof(buffer2)));
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
                    if (Memory::is_readable(buffers[buf_idx], sizeof(buffers[buf_idx])) &&
                        Memory::is_writable(buffers[buf_idx], sizeof(buffers[buf_idx])))
                    {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_EQ(success_count.load(), num_threads * iterations);
}

TEST_F(MemoryTest, CacheStatsWithShards)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 5000, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
    }

    std::string stats = Memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, InvalidateRangeAcrossShards)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(8, 60000, 4);

    void *mem1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ASSERT_NE(mem1, nullptr);
    ASSERT_NE(mem2, nullptr);

    EXPECT_TRUE(Memory::is_readable(mem1, 64));
    EXPECT_TRUE(Memory::is_readable(mem2, 64));

    Memory::invalidate_range(mem1, 4096);

    EXPECT_TRUE(Memory::is_readable(mem1, 64));
    EXPECT_TRUE(Memory::is_readable(mem2, 64));

    VirtualFree(mem1, 0, MEM_RELEASE);
    VirtualFree(mem2, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheStampedeCoalescing)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(32, 60000, 4);

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
                    if (Memory::is_readable(mem, 64))
                    {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_EQ(success_count.load(), num_threads * iterations);

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("Coalesced:"), std::string::npos);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheStatsAvailableInRelease)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 5000, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
    EXPECT_TRUE(Memory::is_writable(buffer, sizeof(buffer)));

    std::string stats = Memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
    EXPECT_NE(stats.find("Hits:"), std::string::npos);
    EXPECT_NE(stats.find("Misses:"), std::string::npos);
    EXPECT_NE(stats.find("Coalesced:"), std::string::npos);
    EXPECT_NE(stats.find("Hit Rate:"), std::string::npos);
}

TEST_F(MemoryTest, ClearCacheResetsAllStats)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 5000, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 5; ++i)
    {
        (void)Memory::is_readable(buffer, sizeof(buffer));
    }

    Memory::clear_cache();

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("Hits: 0"), std::string::npos);
    EXPECT_NE(stats.find("Misses: 0"), std::string::npos);
}

TEST_F(MemoryTest, InvalidateRangeIncrementsCounter)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 60000, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    Memory::invalidate_range(buffer, sizeof(buffer));

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("Invalidations:"), std::string::npos);
}

TEST_F(MemoryTest, HardUpperBoundEnforced)
{
    Memory::shutdown_cache();
    // 1 shard, capacity=2, hard_max = capacity * 2 = 4
    (void)Memory::init_cache(2, 60000, 1);

    // Allocate 10 distinct pages to force cache past capacity
    std::vector<void *> regions;
    for (int i = 0; i < 10; ++i)
    {
        void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        ASSERT_NE(mem, nullptr);
        regions.push_back(mem);
        EXPECT_TRUE(Memory::is_readable(mem, 1));
    }

    std::string stats = Memory::get_cache_stats();
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
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 10, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    // Background cleanup thread runs every 1 second; sleep long enough for at least one pass
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    // Cache should still work after background cleanup has run
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::string stats = Memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, InvalidateRangeTriggersBackgroundCleanup)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(Memory::is_readable(mem, 64));

    // Invalidate should trigger cleanup request
    EXPECT_NO_THROW(Memory::invalidate_range(mem, 64));

    // Cache should still work after invalidation
    EXPECT_TRUE(Memory::is_readable(mem, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, DefaultExpiryIs50ms)
{
    Memory::shutdown_cache();
    // Use default parameters (50ms expiry)
    (void)Memory::init_cache(16, DEFAULT_CACHE_EXPIRY_MS, 4);

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("Expiry: 50ms"), std::string::npos);
}

TEST_F(MemoryTest, OnDemandCleanupStatExists)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 100, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("OnDemandCleanups:"), std::string::npos);
}

TEST_F(MemoryTest, ClearCacheResetsOnDemandCleanupStat)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 100, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 5; ++i)
    {
        (void)Memory::is_readable(buffer, sizeof(buffer));
    }

    Memory::clear_cache();

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("OnDemandCleanups: 0"), std::string::npos);
}

TEST_F(MemoryTest, ExpiredEntryTriggersReFetch)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 10, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    // Capture miss count after warm-up
    std::string stats_before = Memory::get_cache_stats();
    auto pos_before = stats_before.find("Misses: ");
    ASSERT_NE(pos_before, std::string::npos);
    const uint64_t prev_misses = std::stoull(stats_before.substr(pos_before + 8));

    // Wait for cache entry to expire (10ms expiry)
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    // Re-query should succeed (re-fetch from OS) and register as a new miss
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::string stats_after = Memory::get_cache_stats();
    auto pos_after = stats_after.find("Misses: ");
    ASSERT_NE(pos_after, std::string::npos);
    const uint64_t misses = std::stoull(stats_after.substr(pos_after + 8));
    EXPECT_GE(misses, prev_misses + 1u);
}

TEST_F(MemoryTest, CacheHitPerformance_SingleThread)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i)
    {
        EXPECT_TRUE(Memory::is_readable(mem, 64));
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // 1000 cache-hit reads should complete well under 1 second
    EXPECT_LT(duration, 1000);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheStatsIncludeHardMax)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(16, 5000, 4);

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("HardMax/Shard:"), std::string::npos);
}

TEST_F(MemoryTest, ShutdownWhileReadersActive)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(32, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Warm up cache so readers hit the fast path
    EXPECT_TRUE(Memory::is_readable(mem, 64));

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
                    (void)Memory::is_readable(mem, 64);
                }
            });
    }

    // Wait until all readers are actively reading
    while (readers_entered.load(std::memory_order_acquire) < num_threads)
    {
        std::this_thread::yield();
    }

    // Shutdown on a separate thread while readers are still active. shutdown_cache waits for s_activeReaders == 0
    // before destroying data. Readers that re-enter after shutdown use direct VirtualQuery fallback.
    std::thread shutdown_thread([&]() { Memory::shutdown_cache(); });

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
    EXPECT_TRUE(Memory::init_cache());
    EXPECT_TRUE(Memory::is_readable(mem, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReinitAfterShutdown_DataIntegrity)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    for (int round = 0; round < 3; ++round)
    {
        Memory::shutdown_cache();
        EXPECT_TRUE(Memory::init_cache(16, 5000, 4));

        EXPECT_TRUE(Memory::is_readable(mem, 64));
        EXPECT_TRUE(Memory::is_writable(mem, 64));

        std::string stats = Memory::get_cache_stats();
        EXPECT_NE(stats.find("Hits:"), std::string::npos);
        EXPECT_NE(stats.find("Misses:"), std::string::npos);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, NoCacheFallback_Readable)
{
    // Shut down cache so is_readable uses direct VirtualQuery fallback
    Memory::shutdown_cache();

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
    EXPECT_FALSE(Memory::is_readable(nullptr, 1));
    EXPECT_FALSE(Memory::is_readable(buffer, 0));

    // Re-init for TearDown
    (void)Memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_Writable)
{
    // Shut down cache so is_writable uses direct VirtualQuery fallback
    Memory::shutdown_cache();

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_writable(buffer, sizeof(buffer)));
    EXPECT_FALSE(Memory::is_writable(nullptr, 1));
    EXPECT_FALSE(Memory::is_writable(buffer, 0));

    // Re-init for TearDown
    (void)Memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_ReservedMemory)
{
    Memory::shutdown_cache();

    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    EXPECT_FALSE(Memory::is_readable(reserved, 1));
    EXPECT_FALSE(Memory::is_writable(reserved, 1));

    VirtualFree(reserved, 0, MEM_RELEASE);

    // Re-init for TearDown
    (void)Memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_ReadOnlyMemory)
{
    Memory::shutdown_cache();

    void *readonly = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(readonly, nullptr);

    EXPECT_TRUE(Memory::is_readable(readonly, 1));
    EXPECT_FALSE(Memory::is_writable(readonly, 1));

    VirtualFree(readonly, 0, MEM_RELEASE);

    // Re-init for TearDown
    (void)Memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_SizeOverflow)
{
    Memory::shutdown_cache();

    char buffer[1] = {0};
    EXPECT_FALSE(Memory::is_readable(buffer, SIZE_MAX));
    EXPECT_FALSE(Memory::is_writable(buffer, SIZE_MAX));

    // Re-init for TearDown
    (void)Memory::init_cache();
}

TEST_F(MemoryTest, CacheRangeLookup_MidRegionHit)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(32, 60000, 1);

    // Allocate a large region so VirtualQuery returns a base address that differs from the queried address within the
    // region
    void *mem = VirtualAlloc(nullptr, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Prime cache with a query at the region base
    EXPECT_TRUE(Memory::is_readable(mem, 1));

    // Query at an offset within the same region - should hit cache via range lookup
    void *mid = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(mem) + 8192);
    EXPECT_TRUE(Memory::is_readable(mid, 64));
    EXPECT_TRUE(Memory::is_writable(mid, 64));

    std::string stats = Memory::get_cache_stats();
    auto pos = stats.find("Hits: ");
    ASSERT_NE(pos, std::string::npos);
    const uint64_t hits = std::stoull(stats.substr(pos + 6));
    // At least 2 hits: the mid-region readable and writable checks should hit
    EXPECT_GE(hits, 2u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheHitRate_RepeatedAccess)
{
    Memory::shutdown_cache();
    (void)Memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // First access is a miss, subsequent accesses should hit
    for (int i = 0; i < 100; ++i)
    {
        EXPECT_TRUE(Memory::is_readable(mem, 64));
    }

    std::string stats = Memory::get_cache_stats();
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
    EXPECT_TRUE(Memory::is_readable(buf, 1));

    // size chosen so that (address + size) wraps around
    const size_t wrapping_size = UINTPTR_MAX - reinterpret_cast<uintptr_t>(buf) + 2;
    EXPECT_FALSE(Memory::is_readable(buf, wrapping_size));

    VirtualFree(buf, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsWritable_AddressOverflow)
{
    void *buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(buf, nullptr);

    EXPECT_TRUE(Memory::is_writable(buf, 1));

    const size_t wrapping_size = UINTPTR_MAX - reinterpret_cast<uintptr_t>(buf) + 2;
    EXPECT_FALSE(Memory::is_writable(buf, wrapping_size));

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
                (void)Memory::is_readable(mem, 4);
            }
            reader_done.store(true);
        });

    // Wait for reader to start
    while (!reader_started.load())
    {
        std::this_thread::yield();
    }

    // Shutdown should wait for readers to finish without crash
    Memory::shutdown_cache();
    reader.join();

    EXPECT_TRUE(reader_done.load());

    // Re-init for TearDown
    (void)Memory::init_cache();
    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ShutdownCache_DrainsManyStripedReaders)
{
    // The reader-tracking count is striped across many per-thread cache lines; shutdown_cache must sum every stripe to
    // drain safely. Drive is_readable from many threads (round-robin stripe assignment puts them on distinct stripes)
    // overlapping shutdown, then assert every reader finished without a crash -- i.e. shutdown waited for all stripes,
    // not just one. If the drain summed only a single stripe a reader on another stripe could touch shards freed out
    // from under it.
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
                    // Count the thread as started only once it is actually in the read loop, so the main thread's
                    // wait gates on readers that are hammering reads rather than on threads that have merely spawned.
                    if (i == 0)
                    {
                        started.fetch_add(1, std::memory_order_acq_rel);
                    }
                    (void)Memory::is_readable(mem, 4);
                }
                finished.fetch_add(1, std::memory_order_acq_rel);
            });
    }
    // Wait until every reader is live and hammering, so shutdown overlaps in-flight reads on many stripes.
    while (started.load(std::memory_order_acquire) < READER_THREADS)
    {
        std::this_thread::yield();
    }

    Memory::shutdown_cache();
    for (auto &r : readers)
    {
        r.join();
    }
    EXPECT_EQ(finished.load(std::memory_order_acquire), READER_THREADS);

    // Re-init for TearDown
    (void)Memory::init_cache();
    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadable_NoCacheInitialized_OverflowGuard)
{
    Memory::shutdown_cache();

    // Use a real mapped buffer so VirtualQuery succeeds and the code reaches the overflow guard in the direct
    // (no-cache) path.
    void *buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(buf, nullptr);

    const size_t wrapping_size = UINTPTR_MAX - reinterpret_cast<uintptr_t>(buf) + 2;
    EXPECT_FALSE(Memory::is_readable(buf, wrapping_size));

    VirtualFree(buf, 0, MEM_RELEASE);

    // Re-init for TearDown
    (void)Memory::init_cache();
}

TEST_F(MemoryTest, ReadPtrUnsafe_ValidPointer)
{
    uintptr_t value = 0xDEADBEEF;
    uintptr_t result = Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0xDEADBEEF);
}

TEST_F(MemoryTest, ReadPtrUnsafe_WithOffset)
{
    uintptr_t values[2] = {0x11111111, 0x22222222};
    uintptr_t result = Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(values), sizeof(uintptr_t));
    EXPECT_EQ(result, 0x22222222);
}

TEST_F(MemoryTest, ReadPtrUnsafe_NullAddress)
{
    uintptr_t result = Memory::read_ptr_unsafe(0, 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_InvalidAddress)
{
    uintptr_t result = Memory::read_ptr_unsafe(0xDEAD, 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_FreedMemory)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uintptr_t *>(mem) = 0xCAFEBABE;
    VirtualFree(mem, 0, MEM_RELEASE);

    uintptr_t result = Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(mem), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_HeapAllocation)
{
    auto buffer = std::make_unique<uintptr_t>(0xABCD1234);
    uintptr_t result = Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(buffer.get()), 0);
    EXPECT_EQ(result, 0xABCD1234);
}

TEST_F(MemoryTest, IsReadableNonblocking_ValidMemory)
{
    char buffer[100] = {0};
    auto status = Memory::is_readable_nonblocking(buffer, sizeof(buffer));
    // Cache is not primed, so this will be a cache miss returning Unknown
    EXPECT_NE(status, Memory::ReadableStatus::NotReadable);
}

TEST_F(MemoryTest, IsReadableNonblocking_NullAddress)
{
    auto status = Memory::is_readable_nonblocking(nullptr, 100);
    EXPECT_EQ(status, Memory::ReadableStatus::NotReadable);
}

TEST_F(MemoryTest, IsReadableNonblocking_ZeroSize)
{
    char buffer[100] = {0};
    auto status = Memory::is_readable_nonblocking(buffer, 0);
    EXPECT_EQ(status, Memory::ReadableStatus::NotReadable);
}

TEST_F(MemoryTest, IsReadableNonblocking_NoAccessMemory)
{
    void *noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noaccess, nullptr);

    // Prime cache so nonblocking has data
    (void)Memory::is_readable(noaccess, 1);

    auto status = Memory::is_readable_nonblocking(noaccess, 1);
    EXPECT_EQ(status, Memory::ReadableStatus::NotReadable);

    VirtualFree(noaccess, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_CachedHit)
{
    char buffer[100] = {0};

    // Prime cache with a regular read
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    // Nonblocking should hit cache
    auto status = Memory::is_readable_nonblocking(buffer, sizeof(buffer));
    EXPECT_EQ(status, Memory::ReadableStatus::Readable);
}

TEST_F(MemoryTest, IsReadableNonblocking_NoCacheInitialized)
{
    Memory::shutdown_cache();

    char buffer[100] = {0};
    auto status = Memory::is_readable_nonblocking(buffer, sizeof(buffer));
    // Falls back to direct VirtualQuery when cache is not initialized
    EXPECT_EQ(status, Memory::ReadableStatus::Readable);

    (void)Memory::init_cache();
}

TEST_F(MemoryTest, IsReadableNonblocking_FreedMemory)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    VirtualFree(mem, 0, MEM_RELEASE);

    Memory::clear_cache();
    Memory::shutdown_cache();

    auto status = Memory::is_readable_nonblocking(mem, 1);
    EXPECT_EQ(status, Memory::ReadableStatus::NotReadable);

    (void)Memory::init_cache();
}

TEST_F(MemoryTest, ReadPtrUnsafe_NoAccessPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(mem, nullptr);

    uintptr_t result = Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(mem), 0);
    EXPECT_EQ(result, 0u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_GuardPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uintptr_t *>(mem) = 0x12345678;

    DWORD old_protect;
    VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect);

    uintptr_t result = Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(mem), 0);
    // MSVC SEH catches the guard-page exception and returns 0. MinGW's vectored fault handler swallows the same
    // STATUS_GUARD_PAGE_VIOLATION and returns 0.
    EXPECT_EQ(result, 0u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_ReadOnlyPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uintptr_t *>(mem) = 0xFEEDFACE;

    DWORD old_protect;
    VirtualProtect(mem, 4096, PAGE_READONLY, &old_protect);

    uintptr_t result = Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(mem), 0);
    EXPECT_EQ(result, 0xFEEDFACE);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_NegativeOffset)
{
    uintptr_t values[3] = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC};
    uintptr_t base = reinterpret_cast<uintptr_t>(&values[2]);
    uintptr_t result = Memory::read_ptr_unsafe(base, -static_cast<ptrdiff_t>(sizeof(uintptr_t)));
    EXPECT_EQ(result, 0xBBBBBBBB);
}

// --- Tests for read_ptr_unchecked (inline hot-path pointer dereference) ---

TEST_F(MemoryTest, ReadPtrUnchecked_ValidHighPointer)
{
    uintptr_t value = 0x00007FF700000000;
    uintptr_t result = Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0x00007FF700000000);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsNullValue)
{
    uintptr_t value = 0;
    uintptr_t result = Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsLowPointer)
{
    uintptr_t value = 0x1000;
    uintptr_t result = Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsBoundaryValue)
{
    uintptr_t value = 0x10000;
    uintptr_t result = Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_AcceptsAboveBoundary)
{
    uintptr_t value = 0x10001;
    uintptr_t result = Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0x10001);
}

TEST_F(MemoryTest, ReadPtrUnchecked_WithOffset)
{
    uintptr_t values[2] = {0x1000, 0x00007FF700001234};
    uintptr_t result = Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(values), sizeof(uintptr_t));
    EXPECT_EQ(result, 0x00007FF700001234);
}

TEST_F(MemoryTest, ReadPtrUnchecked_CustomThreshold)
{
    uintptr_t value = 0x500;
    EXPECT_EQ(Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&value), 0, 0x1000), 0u);
    EXPECT_EQ(Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&value), 0, 0x100), 0x500);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ZeroThreshold)
{
    uintptr_t value = 1;
    uintptr_t result = Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&value), 0, 0);
    EXPECT_EQ(result, 1u);
}

TEST_F(MemoryTest, IsReadableNonblocking_ReservedMemory)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    // Prime cache
    (void)Memory::is_readable(reserved, 1);

    auto status = Memory::is_readable_nonblocking(reserved, 1);
    EXPECT_EQ(status, Memory::ReadableStatus::NotReadable);

    VirtualFree(reserved, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_GuardPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    DWORD old_protect;
    VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect);

    Memory::clear_cache();
    // Prime cache with guard-page state
    (void)Memory::is_readable(mem, 1);

    auto status = Memory::is_readable_nonblocking(mem, 1);
    EXPECT_EQ(status, Memory::ReadableStatus::NotReadable);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_ReadOnlyPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    // Prime cache
    (void)Memory::is_readable(mem, 1);

    auto status = Memory::is_readable_nonblocking(mem, 1);
    EXPECT_EQ(status, Memory::ReadableStatus::Readable);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_SizeOverflow)
{
    char buffer[1] = {0};
    auto status = Memory::is_readable_nonblocking(buffer, SIZE_MAX);
    // Overflow in address arithmetic must not yield Readable.
    EXPECT_NE(status, Memory::ReadableStatus::Readable);
}

TEST_F(MemoryTest, IsReadableNonblocking_HeapAllocation)
{
    auto buffer = std::make_unique<char[]>(100);

    // Prime cache
    (void)Memory::is_readable(buffer.get(), 100);

    auto status = Memory::is_readable_nonblocking(buffer.get(), 100);
    EXPECT_EQ(status, Memory::ReadableStatus::Readable);
}

TEST_F(MemoryTest, ReadableStatus_EnumValues)
{
    EXPECT_NE(Memory::ReadableStatus::Readable, Memory::ReadableStatus::NotReadable);
    EXPECT_NE(Memory::ReadableStatus::Readable, Memory::ReadableStatus::Unknown);
    EXPECT_NE(Memory::ReadableStatus::NotReadable, Memory::ReadableStatus::Unknown);
}

TEST_F(MemoryTest, ReadPtrUnchecked_SourceInLowAddressRange)
{
    uintptr_t base = 0x100;
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = Memory::read_ptr_unchecked(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_SourceAtMinValid)
{
    uintptr_t base = 0x10000;
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = Memory::read_ptr_unchecked(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ValidSourceLowResult)
{
    uintptr_t low_value = 0x100;
    uintptr_t base = reinterpret_cast<uintptr_t>(&low_value);
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = Memory::read_ptr_unchecked(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ValidSourceValidResult)
{
    uintptr_t high_value = 0x7FFE0000;
    uintptr_t base = reinterpret_cast<uintptr_t>(&high_value);
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = Memory::read_ptr_unchecked(base, offset, min_valid);
    EXPECT_EQ(result, high_value);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsKernelRangeSource)
{
    // A kernel-range source is rejected by the upper-bound guard before any dereference (early return), so this is safe
    // to call with a non-readable base.
    const uintptr_t base = 0xFFFF800000000000ULL;
    EXPECT_EQ(Memory::read_ptr_unchecked(base, 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsSourceAtCeiling)
{
    // USERSPACE_PTR_MAX is the first non-canonical address; the window is half-open, so a source exactly at the ceiling
    // is rejected (also before any dereference).
    EXPECT_EQ(Memory::read_ptr_unchecked(Memory::USERSPACE_PTR_MAX, 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsSourceOffsetCrossingCeiling)
{
    // A positive offset that carries the source up to the ceiling is rejected; this is also how the range guard
    // subsumes pointer-arithmetic wraparound.
    const uintptr_t base = Memory::USERSPACE_PTR_MAX - 0x100;
    EXPECT_EQ(Memory::read_ptr_unchecked(base, 0x100), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsKernelRangeResult)
{
    // A structurally valid source that yields a kernel-range pointer must not be propagated down the chain; the result
    // guard rejects it like the source guard.
    uintptr_t kernel_value = 0xFFFF800000000000ULL;
    EXPECT_EQ(Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&kernel_value), 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsResultAtCeiling)
{
    uintptr_t ceiling_value = Memory::USERSPACE_PTR_MAX;
    EXPECT_EQ(Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&ceiling_value), 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_AcceptsResultJustBelowCeiling)
{
    uintptr_t high_value = Memory::USERSPACE_PTR_MAX - 1;
    uintptr_t result = Memory::read_ptr_unchecked(reinterpret_cast<uintptr_t>(&high_value), 0);
    EXPECT_EQ(result, high_value);
}

TEST_F(MemoryTest, InvalidateRange_WraparoundAddress)
{
    uintptr_t near_max = UINTPTR_MAX - 0x10;
    size_t large_size = 0x100;

    EXPECT_NO_THROW(Memory::invalidate_range(reinterpret_cast<const void *>(near_max), large_size));
}

TEST_F(MemoryTest, WriteBytesToReadOnlyMemory_ExercisesVirtualProtect)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    std::byte data[] = {std::byte{0xDE}, std::byte{0xAD}};
    auto result = Memory::write_bytes(static_cast<std::byte *>(mem), data, sizeof(data));

    // write_bytes changes protection temporarily; this should succeed
    if (result.has_value())
    {
        EXPECT_EQ(std::memcmp(mem, data, sizeof(data)), 0);
    }
    else
    {
        EXPECT_EQ(result.error(), MemoryError::ProtectionChangeFailed);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteBytesToExecuteReadPage_ExercisesFlushCache)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte data[] = {std::byte{0x90}, std::byte{0x90}, std::byte{0xC3}};
    auto result = Memory::write_bytes(static_cast<std::byte *>(mem), data, sizeof(data));
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(std::memcmp(mem, data, sizeof(data)), 0);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_LargeValidRegion)
{
    void *mem = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // First call populates cache
    auto status1 = Memory::is_readable_nonblocking(mem, 0x10000);
    EXPECT_NE(status1, Memory::ReadableStatus::NotReadable);

    // Second call should hit cache
    auto status2 = Memory::is_readable_nonblocking(mem, 0x10000);
    EXPECT_NE(status2, Memory::ReadableStatus::NotReadable);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_AfterCachePrime)
{
    uintptr_t value = 0xDEADBEEF;
    auto addr = reinterpret_cast<uintptr_t>(&value);

    // Prime the cache with a readable check. read_ptr_unsafe consults no cache (the fault guard makes a probe
    // unnecessary), so this only confirms a primed region still reads back its value through the guarded path.
    EXPECT_TRUE(Memory::is_readable(&value, sizeof(uintptr_t)));

    uintptr_t result = Memory::read_ptr_unsafe(addr, 0);
    EXPECT_EQ(result, value);
}

TEST_F(MemoryTest, WriteBytesInvalidatesAndRevalidates)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Prime the cache
    EXPECT_TRUE(Memory::is_readable(mem, 4));

    // Write invalidates cached region
    std::byte data[] = {std::byte{0xAA}, std::byte{0xBB}};
    auto result = Memory::write_bytes(static_cast<std::byte *>(mem), data, sizeof(data));
    ASSERT_TRUE(result.has_value());

    // Subsequent check should still work (re-fetches into cache)
    EXPECT_TRUE(Memory::is_readable(mem, 4));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(MemoryErrorTest, MemoryErrorToString_IsNoexcept)
{
    static_assert(noexcept(memory_error_to_string(MemoryError::NullTargetAddress)));
}

// --- Tests for seh_read_bytes ---

TEST_F(MemoryTest, SehReadBytes_ValidStackBuffer)
{
    const uint64_t source = 0xCAFEBABEDEADBEEFULL;
    uint64_t out = 0;
    EXPECT_TRUE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(&source), &out, sizeof(out)));
    EXPECT_EQ(out, source);
}

TEST_F(MemoryTest, SehReadBytes_ZeroBytesIsNoOp)
{
    char dst = 'X';
    EXPECT_TRUE(Memory::seh_read_bytes(0x1000, &dst, 0));
    EXPECT_EQ(dst, 'X');
}

TEST_F(MemoryTest, SehReadBytes_NullOutRejected)
{
    const uint32_t source = 0xDEADC0DE;
    EXPECT_FALSE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(&source), nullptr, sizeof(source)));
}

TEST_F(MemoryTest, SehReadBytes_LowAddressRejected)
{
    uint32_t out = 0xAAAAAAAA;
    EXPECT_FALSE(Memory::seh_read_bytes(0x100, &out, sizeof(out)));
    EXPECT_FALSE(Memory::seh_read_bytes(0xFFFF, &out, sizeof(out)));
}

TEST_F(MemoryTest, SehReadBytes_AddressWraparoundRejected)
{
    uint64_t out = 0;
    const uintptr_t near_max = UINTPTR_MAX - 8;
    EXPECT_FALSE(Memory::seh_read_bytes(near_max, &out, 64));
}

TEST_F(MemoryTest, SehReadBytes_FreedMemoryReturnsFalse)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uint64_t *>(mem) = 0x1122334455667788ULL;
    VirtualFree(mem, 0, MEM_RELEASE);

    uint64_t out = 0;
    EXPECT_FALSE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));
}

TEST_F(MemoryTest, SehReadBytes_NoAccessReturnsFalse)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(mem, nullptr);

    uint64_t out = 0;
    EXPECT_FALSE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, SehReadBytes_GuardPageReturnsFalse)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uint64_t *>(mem) = 0x42;

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect));

    uint64_t out = 0;
    EXPECT_FALSE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, SehReadBytes_LargeRangePartialUnmapped)
{
    // Read more bytes than are available after a committed page; the second half lives in unmapped territory and the
    // read must fail.
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::vector<uint8_t> buf(8192, 0);
    EXPECT_FALSE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(mem), buf.data(), buf.size()));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// --- Tests for seh_read<T> ---

TEST_F(MemoryTest, SehRead_Uintptr)
{
    const uintptr_t source = 0xFEEDFACEBADDCAFEULL;
    auto value = Memory::seh_read<uintptr_t>(reinterpret_cast<uintptr_t>(&source));
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, source);
}

TEST_F(MemoryTest, SehRead_Uint32)
{
    const uint32_t source = 0xABCDEF01u;
    auto value = Memory::seh_read<uint32_t>(reinterpret_cast<uintptr_t>(&source));
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, source);
}

TEST_F(MemoryTest, SehRead_Struct)
{
    struct Sample
    {
        uint32_t a;
        uint32_t b;
        uint64_t c;
    };
    static_assert(std::is_trivially_copyable_v<Sample>);
    const Sample source{0x11111111u, 0x22222222u, 0x3333333344444444ULL};

    auto value = Memory::seh_read<Sample>(reinterpret_cast<uintptr_t>(&source));
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(value->a, source.a);
    EXPECT_EQ(value->b, source.b);
    EXPECT_EQ(value->c, source.c);
}

TEST_F(MemoryTest, SehRead_NullAddressReturnsNullopt)
{
    auto value = Memory::seh_read<uint64_t>(0);
    EXPECT_FALSE(value.has_value());
}

TEST_F(MemoryTest, SehRead_LowAddressReturnsNullopt)
{
    auto value = Memory::seh_read<uint64_t>(0x100);
    EXPECT_FALSE(value.has_value());
}

TEST_F(MemoryTest, SehRead_FreedMemoryReturnsNullopt)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uint64_t *>(mem) = 0xDEADBEEFu;
    VirtualFree(mem, 0, MEM_RELEASE);

    auto value = Memory::seh_read<uint64_t>(reinterpret_cast<uintptr_t>(mem));
    EXPECT_FALSE(value.has_value());
}

// --- Tests for ModuleRange / module_range_for / own_module_range / host_module_range ---

TEST_F(MemoryTest, ModuleRange_DefaultIsInvalid)
{
    Memory::ModuleRange range;
    EXPECT_FALSE(range.valid());
    EXPECT_EQ(range.base, 0u);
    EXPECT_EQ(range.end, 0u);
}

TEST_F(MemoryTest, ModuleRange_ContainsRejectsInvalid)
{
    Memory::ModuleRange range;
    EXPECT_FALSE(Memory::contains(range, 0x1000));
}

TEST_F(MemoryTest, ModuleRange_ContainsBoundary)
{
    constexpr Memory::ModuleRange range{0x10000, 0x20000};
    EXPECT_TRUE(Memory::contains(range, 0x10000));
    EXPECT_TRUE(Memory::contains(range, 0x1FFFF));
    EXPECT_FALSE(Memory::contains(range, 0x20000));
    EXPECT_FALSE(Memory::contains(range, 0xFFFF));
}

TEST_F(MemoryTest, ModuleRange_ConstexprValid)
{
    static_assert(Memory::ModuleRange{0x10000, 0x20000}.valid());
    static_assert(!Memory::ModuleRange{0, 0x20000}.valid());
    static_assert(!Memory::ModuleRange{0x20000, 0x10000}.valid());
    static_assert(Memory::contains(Memory::ModuleRange{0x1000, 0x2000}, 0x1500));
}

TEST_F(MemoryTest, ModuleRangeFor_NullReturnsNullopt)
{
    EXPECT_FALSE(Memory::module_range_for(nullptr).has_value());
}

TEST_F(MemoryTest, ModuleRangeFor_OwnFunctionResolves)
{
    // The test exe is itself a loaded module; resolving any address in it must return a valid range that contains the
    // queried address.
    const auto range = Memory::module_range_for(reinterpret_cast<const void *>(&Memory::module_range_for));
    ASSERT_TRUE(range.has_value());
    EXPECT_TRUE(range->valid());
    EXPECT_TRUE(Memory::contains(*range, reinterpret_cast<uintptr_t>(&Memory::module_range_for)));
}

TEST_F(MemoryTest, ModuleRangeFor_HeapAddressReturnsNullopt)
{
    // A heap allocation lives in committed memory that is not part of any loaded image, so GetModuleHandleEx returns
    // nullptr and the function returns std::nullopt.
    auto buffer = std::make_unique<int>(42);
    const auto range = Memory::module_range_for(buffer.get());
    EXPECT_FALSE(range.has_value());
}

TEST_F(MemoryTest, ModuleRangeFor_CacheReturnsConsistentValue)
{
    const void *probe = reinterpret_cast<const void *>(&Memory::own_module_range);
    const auto first = Memory::module_range_for(probe);
    ASSERT_TRUE(first.has_value());

    const auto second = Memory::module_range_for(probe);
    ASSERT_TRUE(second.has_value());

    EXPECT_EQ(first->base, second->base);
    EXPECT_EQ(first->end, second->end);
}

TEST_F(MemoryTest, OwnModuleRange_IsValid)
{
    const auto range = Memory::own_module_range();
    EXPECT_TRUE(range.valid());
    EXPECT_TRUE(Memory::contains(range, reinterpret_cast<uintptr_t>(&Memory::own_module_range)));
}

TEST_F(MemoryTest, OwnModuleRange_StableAcrossCalls)
{
    const auto a = Memory::own_module_range();
    const auto b = Memory::own_module_range();
    EXPECT_EQ(a.base, b.base);
    EXPECT_EQ(a.end, b.end);
}

TEST_F(MemoryTest, HostModuleRange_IsValid)
{
    const auto range = Memory::host_module_range();
    EXPECT_TRUE(range.valid());

    // The test executable's main() symbol lives inside the host EXE image.
    HMODULE host = GetModuleHandleW(nullptr);
    ASSERT_NE(host, nullptr);
    EXPECT_EQ(range.base, reinterpret_cast<uintptr_t>(host));
}

TEST_F(MemoryTest, HostModuleRange_ContainsItself)
{
    // The test process is its own host; any code address inside the test exe must fall inside host_module_range().
    const auto range = Memory::host_module_range();
    ASSERT_TRUE(range.valid());

    HMODULE host = GetModuleHandleW(nullptr);
    ASSERT_NE(host, nullptr);
    EXPECT_TRUE(Memory::contains(range, reinterpret_cast<uintptr_t>(host)));
}

TEST_F(MemoryTest, HostModuleRange_StableAcrossCalls)
{
    const auto a = Memory::host_module_range();
    const auto b = Memory::host_module_range();
    EXPECT_EQ(a.base, b.base);
    EXPECT_EQ(a.end, b.end);
}

TEST_F(MemoryTest, ModuleRangeFor_KernelModuleResolves)
{
    // kernel32.dll is loaded into every Windows process; resolving any address inside it must yield a valid range.
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel, nullptr);

    const auto range = Memory::module_range_for(reinterpret_cast<const void *>(kernel));
    ASSERT_TRUE(range.has_value());
    EXPECT_TRUE(range->valid());
    EXPECT_EQ(range->base, reinterpret_cast<uintptr_t>(kernel));
}

// Every SEH-guarded foreign read must swallow EXCEPTION_IN_PAGE_ERROR (a file-backed page failing to page in) alongside
// the access-violation and guard-page faults, or the fault continues the handler search and terminates the host. The
// four __except filters in memory.cpp and the region/window guards in scanner.cpp / string_xref.cpp share this single
// predicate, so pinning it pins all of them.
TEST(MemoryGuardedReadFault, AcceptsForeignReadFaultsAndRejectsOthers)
{
    using Memory::detail::is_guarded_read_fault;

    // The three codes a guarded probe owns. Spelled via the Windows macros here to prove the predicate's literals match
    // the platform values.
    static_assert(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_ACCESS_VIOLATION)));
    static_assert(is_guarded_read_fault(static_cast<unsigned long>(STATUS_GUARD_PAGE_VIOLATION)));
    static_assert(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_IN_PAGE_ERROR)));

    EXPECT_TRUE(is_guarded_read_fault(0xC0000005ul)); // EXCEPTION_ACCESS_VIOLATION
    EXPECT_TRUE(is_guarded_read_fault(0x80000001ul)); // STATUS_GUARD_PAGE_VIOLATION
    EXPECT_TRUE(is_guarded_read_fault(0xC0000006ul)); // EXCEPTION_IN_PAGE_ERROR

    // Codes that did not originate from the probe's own read must continue the search.
    EXPECT_FALSE(is_guarded_read_fault(0ul));
    EXPECT_FALSE(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_BREAKPOINT)));          // 0x80000003
    EXPECT_FALSE(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_ILLEGAL_INSTRUCTION))); // 0xC000001D
    EXPECT_FALSE(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_STACK_OVERFLOW)));      // 0xC00000FD
    EXPECT_FALSE(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_INT_DIVIDE_BY_ZERO)));  // 0xC0000094
}

// read_ptr_unsafe reads through std::memcpy rather than a *reinterpret_cast deref, so a misaligned foreign pointer is
// read without invoking the undefined behavior of dereferencing a misaligned pointer. A pointer-sized value planted at
// an odd offset must round-trip exactly.
TEST_F(MemoryTest, ReadPtrUnsafeReadsMisalignedPointer)
{
    void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);

    auto *base = static_cast<std::uint8_t *>(region);
    constexpr std::uintptr_t kSentinel = 0xDEADBEEFCAFEF00Dull;
    constexpr ptrdiff_t kMisalignedOffset = 1; // deliberately not a multiple of alignof(uintptr_t)
    std::memcpy(base + kMisalignedOffset, &kSentinel, sizeof(kSentinel));

    const std::uintptr_t value = Memory::read_ptr_unsafe(reinterpret_cast<std::uintptr_t>(base), kMisalignedOffset);
    EXPECT_EQ(value, kSentinel);

    // An unmapped low address still fails closed to 0 (the fault is swallowed, not propagated).
    EXPECT_EQ(Memory::read_ptr_unsafe(0, 0), 0u);

    VirtualFree(region, 0, MEM_RELEASE);
}

// is_readable / is_writable must fall back to a direct VirtualQuery whenever the cache reports zero shards. The
// externally reachable zero-shard state is "cache not initialized"; the same code path also serves the brief init
// publication window where s_cache_initialized is true but s_shard_count is still 0. Returning false there would
// wrongly report a readable region as non-readable, so the fallback must produce correct answers without the cache.
TEST(MemoryUninitializedCache, PermissionChecksFallBackToDirectQuery)
{
    // Force the zero-shard state regardless of prior tests' cache lifecycle.
    Memory::shutdown_cache();

    void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);

    EXPECT_TRUE(Memory::is_readable(region, 64));
    EXPECT_TRUE(Memory::is_writable(region, 64));

    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(region, 4096, PAGE_NOACCESS, &old_protect), 0);
    EXPECT_FALSE(Memory::is_readable(region, 64));
    EXPECT_FALSE(Memory::is_writable(region, 64));

    VirtualProtect(region, 4096, old_protect, &old_protect);
    VirtualFree(region, 0, MEM_RELEASE);
}

// A reserved-but-uncommitted page is backed by no physical storage, so any read of it faults. The guarded read must
// fail closed rather than terminate the host. On MinGW the vectored handler swallows the access violation; on MSVC the
// __except filter does.
TEST_F(MemoryTest, SehReadBytes_ReservedUncommittedReturnsFalse)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    uint64_t out = 0;
    EXPECT_FALSE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(reserved), &out, sizeof(out)));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

// With the cache reporting a page readable, an external reprotect to PAGE_NOACCESS must not crash a subsequent
// read_ptr_unsafe. The guarded read must ignore stale protection data and fail closed through the same "0 on fault"
// contract on both toolchains.
TEST_F(MemoryTest, ReadPtrUnsafeSurvivesStaleCacheReprotect)
{
    void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);
    const uintptr_t addr = reinterpret_cast<uintptr_t>(region);
    *reinterpret_cast<uintptr_t *>(region) = 0xABCDEF0123456789ULL;

    // Prime the cache so the region is recorded as readable.
    EXPECT_TRUE(Memory::is_readable(region, sizeof(uintptr_t)));
    EXPECT_EQ(Memory::read_ptr_unsafe(addr, 0), 0xABCDEF0123456789ULL);

    // Reprotect out from under the still-readable cache entry. The cache is not invalidated, so a cache-trusting read
    // would dereference a now-inaccessible page.
    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(region, 4096, PAGE_NOACCESS, &old_protect), 0);

    // The fault is swallowed and reported as the pointer-read failure value.
    EXPECT_EQ(Memory::read_ptr_unsafe(addr, 0), 0u);

    VirtualProtect(region, 4096, old_protect, &old_protect);
    VirtualFree(region, 0, MEM_RELEASE);
}

namespace
{
    // A consumer-style vectored handler that never claims a fault, standing in for an unrelated VEH a host might
    // register without interfering with the guarded read.
    LONG CALLBACK consumer_passthrough_veh(PEXCEPTION_POINTERS)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
} // namespace

// The MinGW guarded read installs a process-wide vectored exception handler, which must coexist with a handler the host
// registered. Exercise both list orderings (consumer registered before and after DMK's handler exists) and assert the
// guarded reads still fail closed on bad memory and succeed on live memory. On MSVC there is no DMK VEH; the consumer
// handler simply passes the first-chance fault through to the frame-based __except, so the test is meaningful on both.
TEST_F(MemoryTest, VectoredHandlerCoexistsWithConsumerHandler)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    const uintptr_t bad_addr = reinterpret_cast<uintptr_t>(mem);
    // Now unmapped; any read of bad_addr faults.
    VirtualFree(mem, 0, MEM_RELEASE);

    const uint64_t live = 0x1122334455667788ULL;

    auto exercise = [&]()
    {
        uint64_t out = 0;
        EXPECT_FALSE(Memory::seh_read_bytes(bad_addr, &out, sizeof(out)));
        EXPECT_EQ(Memory::read_ptr_unsafe(bad_addr, 0), 0u);
        out = 0;
        EXPECT_TRUE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(&live), &out, sizeof(out)));
        EXPECT_EQ(out, live);
    };

    // Ordering 1: consumer handler registered before DMK performs (and lazily installs) its own guarded read.
    void *consumer = AddVectoredExceptionHandler(1, consumer_passthrough_veh);
    ASSERT_NE(consumer, nullptr);
    exercise();
    RemoveVectoredExceptionHandler(consumer);

    // Ordering 2: DMK's handler already exists; register the consumer in front of it and repeat.
    consumer = AddVectoredExceptionHandler(1, consumer_passthrough_veh);
    ASSERT_NE(consumer, nullptr);
    exercise();
    RemoveVectoredExceptionHandler(consumer);
}

// A wrapping or low source range must fail closed to 0 rather than crash. On MinGW the wrap matters specifically: a
// source within 8 bytes of UINTPTR_MAX would make the guarded read's [lo, hi) range wrap so the fault-claim check
// inverts and a real read fault escapes the guard; the shared entry point rejects the wrap before reading. On MSVC the
// __try simply catches the fault. Both return 0.
TEST_F(MemoryTest, ReadPtrUnsafeWraparoundAndLowAddressReturnZero)
{
    // An 8-byte read would wrap past the top of the address space.
    EXPECT_EQ(Memory::read_ptr_unsafe(UINTPTR_MAX - 3, 0), 0u);

    // Below the user-mode floor.
    EXPECT_EQ(Memory::read_ptr_unsafe(0x100, 0), 0u);

    // A low base plus a large negative offset underflows the source to a high, unmapped address; still 0, no crash.
    EXPECT_EQ(Memory::read_ptr_unsafe(0x20000, -static_cast<ptrdiff_t>(0x30000)), 0u);
}

// Each guarded read arms its own per-read guard published to a thread-local slot, so concurrent reads of mixed
// good/bad memory across many threads must each get the right answer with no cross-thread guard corruption and no
// crash. This pins the per-thread isolation of the fault guard.
TEST_F(MemoryTest, GuardedReadsAreThreadIsolatedUnderConcurrency)
{
    void *good = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(good, nullptr);
    constexpr uintptr_t kSentinel = 0x5151515151515151ULL;
    *reinterpret_cast<uintptr_t *>(good) = kSentinel;

    // A deliberately non-readable page the test owns until teardown. This used to MEM_RELEASE a PAGE_READWRITE region
    // to get an unmapped address, but a released VA can be recycled and remapped by the allocations that spawning the
    // reader threads triggers (thread stacks/TEBs, more so under AddressSanitizer); a read then lands on live memory
    // instead of faulting, so the "must fault to 0" assertion flaked on about one read in many thousands. A committed
    // PAGE_NOACCESS page the test holds faults deterministically and cannot be recycled, so it exercises the guard's
    // per-thread fault isolation without that artifact.
    void *unreadable = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(unreadable, nullptr);

    std::atomic<bool> all_correct{true};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < 1000; ++i)
                {
                    if (t % 2 == 0)
                    {
                        if (Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(good), 0) != kSentinel)
                            all_correct.store(false, std::memory_order_relaxed);
                    }
                    else if (Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(unreadable), 0) != 0u)
                    {
                        all_correct.store(false, std::memory_order_relaxed);
                    }
                }
            });
    }
    for (auto &th : threads)
        th.join();

    EXPECT_TRUE(all_correct.load());
    VirtualFree(unreadable, 0, MEM_RELEASE);
    VirtualFree(good, 0, MEM_RELEASE);
}

// shutdown_cache removes the MinGW vectored handler; it must drain reads still on the handler path first, so a fault
// cannot arrive after the handler is gone. Race continuous guarded reads (some faulting) against repeated
// shutdown/re-init and assert survival, then that the subsystem still answers. On MSVC there is no handler to remove,
// so this exercises read_ptr_unsafe / cache-shutdown concurrency.
TEST_F(MemoryTest, GuardedReadsSurviveConcurrentShutdown)
{
    void *good = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(good, nullptr);
    constexpr uintptr_t kSentinel = 0xA5A5A5A5A5A5A5A5ULL;
    *reinterpret_cast<uintptr_t *>(good) = kSentinel;

    // A deliberately non-readable page the test owns until teardown: a committed PAGE_NOACCESS page faults on every
    // read and cannot be recycled, unlike a MEM_RELEASE'd VA, which the allocations from spawning the reader threads
    // can remap so a "faulting" read lands on live memory.
    void *unreadable = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(unreadable, nullptr);

    std::atomic<bool> stop{false};
    std::atomic<int> seen_good{0};
    std::atomic<int> seen_fault{0};
    std::vector<std::thread> readers;
    for (int t = 0; t < 3; ++t)
    {
        readers.emplace_back(
            [&, t]()
            {
                void *const target = (t % 2) ? unreadable : good;
                while (!stop.load(std::memory_order_acquire))
                {
                    const uintptr_t v = Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(target), 0);
                    if (target == good)
                    {
                        if (v == kSentinel)
                            seen_good.fetch_add(1, std::memory_order_relaxed);
                    }
                    else if (v == 0u)
                    {
                        seen_fault.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }

    // Wait until both guarded-read paths are actually live (one good-path read, one faulting-path read) before racing
    // teardown, so the shutdown loop deterministically exercises the in-flight-read drain rather than possibly running
    // before any guarded read happened.
    while (seen_good.load(std::memory_order_acquire) == 0 || seen_fault.load(std::memory_order_acquire) == 0)
        std::this_thread::yield();

    for (int round = 0; round < 12; ++round)
    {
        Memory::shutdown_cache();
        (void)Memory::init_cache();
    }

    stop.store(true, std::memory_order_release);
    for (auto &th : readers)
        th.join();

    EXPECT_EQ(Memory::read_ptr_unsafe(reinterpret_cast<uintptr_t>(good), 0), kSentinel);
    VirtualFree(unreadable, 0, MEM_RELEASE);
    VirtualFree(good, 0, MEM_RELEASE);
}

namespace
{
    std::atomic<void *> g_recover_page{nullptr};
    std::atomic<int> g_recover_hits{0};

    // A consumer handler that recovers an access violation on a registered sentinel page by making it readable and
    // re-executing the faulting instruction. Used to prove DMK's handler passed an unrelated fault through.
    LONG CALLBACK recover_noaccess_veh(PEXCEPTION_POINTERS info)
    {
        void *const page = g_recover_page.load(std::memory_order_acquire);
        const EXCEPTION_RECORD *const rec = info->ExceptionRecord;
        if (page != nullptr && rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2)
        {
            const uintptr_t fault = static_cast<uintptr_t>(rec->ExceptionInformation[1]);
            const uintptr_t base = reinterpret_cast<uintptr_t>(page);
            if (fault >= base && fault < base + 4096)
            {
                DWORD old_protect = 0;
                VirtualProtect(page, 4096, PAGE_READWRITE, &old_protect);
                g_recover_hits.fetch_add(1, std::memory_order_relaxed);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
} // namespace

// DMK's process-wide handler runs on every thread for every fault, including threads that never armed a guarded read.
// Such a fault must be passed straight through (the handler reads its per-thread slot with an allocation-free
// TlsGetValue and sees null), never claimed or hijacked. Here a worker thread that has never issued a DMK guarded read
// faults on a no-access page while DMK's handler is installed; a consumer handler recovers it. A spurious DMK claim
// (longjmp into a frame that never armed) or a crash would fail this. On MSVC there is no DMK handler, so the consumer
// simply recovers the fault directly.
TEST_F(MemoryTest, UnarmedThreadFaultIsPassedThroughNotClaimed)
{
    // Arm and disarm DMK's handler on this thread so it is installed for the process.
    uint64_t probe_src = 0xC3C3C3C3C3C3C3C3ULL;
    uint64_t probe_out = 0;
    ASSERT_TRUE(Memory::seh_read_bytes(reinterpret_cast<uintptr_t>(&probe_src), &probe_out, sizeof(probe_out)));

    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(page, nullptr);
    g_recover_page.store(page, std::memory_order_release);
    g_recover_hits.store(0, std::memory_order_release);

    // Last in the list, so DMK's first-in-list handler sees the fault first and must decline it.
    void *consumer = AddVectoredExceptionHandler(0, recover_noaccess_veh);
    ASSERT_NE(consumer, nullptr);

    std::atomic<uint32_t> observed{0xFFFFFFFFu};
    std::thread worker(
        [&]()
        {
            volatile uint32_t *const p = reinterpret_cast<volatile uint32_t *>(page);
            // Faults once; the consumer handler makes the page readable and retries the instruction.
            observed.store(*p, std::memory_order_release);
        });
    worker.join();

    RemoveVectoredExceptionHandler(consumer);
    g_recover_page.store(nullptr, std::memory_order_release);

    // The unarmed-thread fault reached the consumer, proving DMK passed it through.
    EXPECT_GE(g_recover_hits.load(), 1);

    // The recommitted page reads as zero.
    EXPECT_EQ(observed.load(), 0u);
    VirtualFree(page, 0, MEM_RELEASE);
}
