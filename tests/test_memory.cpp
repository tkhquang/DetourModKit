#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <atomic>
#include <array>
#include <span>
#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/address.hpp"

// White-box engine seams for the vectored-handler / fault-isolation tests.
#include "internal/memory_guarded.hpp"
#include "internal/memory_fault.hpp"

// Deterministic thread-local out-of-memory injection for the ProtectGuard allocation-failure test.
#include "test_alloc_probe.hpp"

using namespace DetourModKit;

namespace
{
    // These shims re-create the removed raw (void*/uintptr_t + size) call shapes so the existing test bodies did not
    // have to be rewritten against the memory:: surface (Address/Region/Result). They add no behavior; they only wrap
    // arguments.
    //
    // ANTI-PATTERN: a test should exercise the memory:: surface directly, not a local adapter that resurrects the old
    // shapes. Treat this namespace as a temporary scaffold and remove it by rewriting the affected bodies to call
    // memory:: directly. (The same scaffold exists in bench_memory.cpp.)

    inline Region region_of(const void *p, std::size_t n) noexcept
    {
        return Region{Address{const_cast<void *>(p)}, n};
    }
    inline Region region_of(std::uintptr_t p, std::size_t n) noexcept
    {
        return Region{Address{p}, n};
    }

    inline bool is_readable(const void *p, std::size_t n) noexcept
    {
        return memory::is_readable(region_of(p, n));
    }
    inline bool is_writable(const void *p, std::size_t n) noexcept
    {
        return memory::is_writable(region_of(p, n));
    }
    inline memory::ReadableStatus is_readable_nonblocking(const void *p, std::size_t n) noexcept
    {
        return memory::is_readable_nonblocking(region_of(p, n));
    }

    inline void invalidate_range(const void *p, std::size_t n) noexcept
    {
        memory::invalidate_range(region_of(p, n));
    }

    // Guarded byte read returning a plain bool (true on full success) rather than a Result, as the test bodies expect.
    inline bool read_bytes(std::uintptr_t addr, void *out, std::size_t n) noexcept
    {
        if (out == nullptr && n != 0)
        {
            return false;
        }
        return memory::read_into(Address{addr}, std::span<std::byte>{static_cast<std::byte *>(out), n}).has_value();
    }

    // Guarded "read pointer, 0 on fault" -- the v3 read_ptr_unsafe contract.
    inline std::uintptr_t guarded_ptr_or_zero(std::uintptr_t base, std::ptrdiff_t off) noexcept
    {
        return memory::read<std::uintptr_t>(Address{base}.offset(off)).value_or(0);
    }

    // v3 read_ptr_unchecked validated source & result against a plausibility window, then did a raw read. v4 splits
    // these: is_plausible_ptr is the window screen; unchecked::read is the raw read. This shim reproduces the v3 gated
    // behavior (0 when source or result is implausible) so the boundary-rejection cases keep asserting through it,
    // while the happy paths exercise the same unchecked::read the production hot path uses.
    inline std::uintptr_t screened_unchecked_ptr(std::uintptr_t base, std::ptrdiff_t off,
                                                 std::uintptr_t min_valid = memory::USERSPACE_PTR_MIN) noexcept
    {
        const std::uintptr_t source = base + static_cast<std::uintptr_t>(off);
        // v3 read_ptr_unchecked source gate: the floor is EXCLUSIVE (one address more conservative than
        // is_plausible_ptr) because the dereference below is unguarded, so min_valid itself is the first untrusted
        // address. The ceiling rejects kernel-range / non-canonical sources and subsumes pointer-arithmetic wraparound.
        if (source <= min_valid || source >= memory::USERSPACE_PTR_MAX)
        {
            return 0;
        }
        const std::uintptr_t value = memory::unchecked::read<std::uintptr_t>(Address{source});
        // Apply the same exclusive window to the loaded value so a structurally valid source that yields a kernel-range
        // or implausible pointer is rejected rather than propagated to the next link of a chain.
        return (value > min_valid && value < memory::USERSPACE_PTR_MAX) ? value : 0;
    }
} // namespace

class MemoryTest : public ::testing::Test
{
protected:
    void SetUp() override { (void)memory::init_cache(); }

    void TearDown() override { memory::shutdown_cache(); }
};

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

TEST_F(MemoryTest, write_bytes)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0x12},
                                     std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};

    auto result = memory::write_bytes(Address{target.data()}, std::span<const std::byte>{source});
    EXPECT_TRUE(result.has_value());

    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }
}

TEST_F(MemoryTest, write_bytes_NullTarget)
{
    std::vector<std::byte> source = {std::byte{0x90}, std::byte{0x90}};

    auto result = memory::write_bytes(Address{nullptr}, std::span<const std::byte>{source});
    EXPECT_FALSE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_NullSource)
{
    std::vector<std::byte> target(16, std::byte{0x00});

    auto result = memory::write_bytes(Address{target.data()},
                                      std::span<const std::byte>{static_cast<const std::byte *>(nullptr), 10});
    EXPECT_FALSE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_ZeroSize)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {std::byte{0x90}};

    auto result = memory::write_bytes(Address{target.data()}, std::span<const std::byte>{source.data(), 0});
    EXPECT_TRUE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_Large)
{
    std::vector<std::byte> target(1024, std::byte{0x00});
    std::vector<std::byte> source(512, std::byte{0xCC});

    auto result = memory::write_bytes(Address{target.data()}, std::span<const std::byte>{source});
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
    EXPECT_TRUE(is_readable(interior, 16));

    // Flip the whole region to no-access. The cached entry is now stale: without a correct invalidation a subsequent
    // query would still report READABLE.
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

TEST_F(MemoryTest, write_bytes_DataIntegrity)
{
    std::vector<std::byte> target(64);
    for (size_t i = 0; i < target.size(); ++i)
    {
        target[i] = std::byte{static_cast<uint8_t>(i)};
    }

    std::vector<std::byte> source = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    auto result = memory::write_bytes(Address{target.data() + 10}, std::span<const std::byte>{source});
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
    bool result = is_readable(str, strlen(str));
    EXPECT_TRUE(result);
}

TEST(MemoryErrorTest, ErrorToString)
{
    EXPECT_FALSE(to_string(ErrorCode::NullTargetAddress).empty());
    EXPECT_FALSE(to_string(ErrorCode::NullSourceBytes).empty());
    EXPECT_FALSE(to_string(ErrorCode::ProtectionChangeFailed).empty());
    EXPECT_FALSE(to_string(ErrorCode::ProtectionRestoreFailed).empty());
    EXPECT_FALSE(to_string(ErrorCode::SizeTooLarge).empty());
    EXPECT_FALSE(to_string(static_cast<ErrorCode>(999)).empty());
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

TEST_F(MemoryTest, CacheLRUEviction)
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

TEST_F(MemoryTest, write_bytes_ErrorTypes)
{
    std::byte source[] = {std::byte{0x90}};

    auto r1 = memory::write_bytes(Address{nullptr}, std::span<const std::byte>{source, 1});
    EXPECT_FALSE(r1.has_value());
    EXPECT_EQ(r1.error().code, ErrorCode::NullTargetAddress);

    std::byte target[1] = {std::byte{0}};
    auto r2 =
        memory::write_bytes(Address{target}, std::span<const std::byte>{static_cast<const std::byte *>(nullptr), 1});
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error().code, ErrorCode::NullSourceBytes);
}

TEST_F(MemoryTest, write_bytes_SizeTooLarge)
{
    std::byte target[1] = {std::byte{0x00}};
    std::byte source[1] = {std::byte{0x90}};

    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, memory::MAX_WRITE_SIZE + 1});
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::SizeTooLarge);
}

TEST_F(MemoryTest, write_bytes_ZeroBytes)
{
    std::byte target[4] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
    std::byte source[1] = {std::byte{0x00}};

    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, 0});
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0xAA});
}

TEST_F(MemoryTest, write_bytes_Success)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);
    std::byte source[] = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, 3});
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0x90});
    EXPECT_EQ(target[1], std::byte{0x90});
    EXPECT_EQ(target[2], std::byte{0x90});

    VirtualFree(mem, 0, MEM_RELEASE);
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

TEST_F(MemoryTest, write_bytes_PageReadOnly)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);
    std::byte source[] = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    // v4 write_bytes auto-unprotects a read-only page, so the write SUCCEEDS and the bytes change.
    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, sizeof(source)});
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

// Reader/writer contention stress over the region cache's sorted_ranges insert/erase churn. The shard SRW lock
// (shared for lookups, exclusive for mutation) is the correctness guarantee under test: reader threads probe an
// interior page of a multi-page region, which misses the page-aligned entries.find fast path and exercises the
// sorted_ranges containment search, while a single writer thread repeatedly invalidates the region. The test
// asserts the cache returns a consistent result for the same input across many iterations under contention.
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
                invalidate_range(mem, 64);
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
    EXPECT_TRUE(is_readable(interior, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteBytesInvalidatesCache)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);

    EXPECT_TRUE(is_readable(target, 64));
    EXPECT_TRUE(is_writable(target, 64));

    std::byte source[] = {std::byte{0x90}, std::byte{0x91}, std::byte{0x92}};
    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, sizeof(source)});
    EXPECT_TRUE(result.has_value());

    EXPECT_TRUE(is_readable(target, 64));
    EXPECT_TRUE(is_writable(target, 64));

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
            });
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

    // Background cleanup thread runs every 1 second; sleep long enough for at least one pass
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    // Cache should still work after background cleanup has run
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

    // Invalidate should trigger cleanup request
    EXPECT_NO_THROW(invalidate_range(mem, 64));

    // Cache should still work after invalidation
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

    // Re-query should succeed (re-fetch from OS) and register as a new miss
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

    // 1000 cache-hit reads should complete well under 1 second
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
            });
    }

    // Wait until all readers are actively reading
    while (readers_entered.load(std::memory_order_acquire) < num_threads)
    {
        std::this_thread::yield();
    }

    // Shutdown on a separate thread while readers are still active. shutdown_cache waits for s_activeReaders == 0
    // before destroying data. Readers that re-enter after shutdown use direct VirtualQuery fallback.
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

    // Query at an offset within the same region - should hit cache via range lookup
    void *mid = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(mem) + 8192);
    EXPECT_TRUE(is_readable(mid, 64));
    EXPECT_TRUE(is_writable(mid, 64));

    std::string stats = memory::get_cache_stats();
    auto pos = stats.find("Hits: ");
    ASSERT_NE(pos, std::string::npos);
    const uint64_t hits = std::stoull(stats.substr(pos + 6));
    // At least 2 hits: the mid-region readable and writable checks should hit
    EXPECT_GE(hits, 2u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, CacheHitRate_RepeatedAccess)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // First access is a miss, subsequent accesses should hit
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
        });

    // Wait for reader to start
    while (!reader_started.load())
    {
        std::this_thread::yield();
    }

    // Shutdown should wait for readers to finish without crash
    memory::shutdown_cache();
    reader.join();

    EXPECT_TRUE(reader_done.load());

    // Re-init for TearDown
    (void)memory::init_cache();
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
                    (void)is_readable(mem, 4);
                }
                finished.fetch_add(1, std::memory_order_acq_rel);
            });
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

// read<T> and the read<T>(addr).value_or(0) guarded-pointer idiom

TEST_F(MemoryTest, ReadPtrUnsafe_ValidPointer)
{
    uintptr_t value = 0xDEADBEEF;
    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0xDEADBEEF);
}

TEST_F(MemoryTest, ReadPtrUnsafe_WithOffset)
{
    uintptr_t values[2] = {0x11111111, 0x22222222};
    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(values), sizeof(uintptr_t));
    EXPECT_EQ(result, 0x22222222);
}

TEST_F(MemoryTest, ReadPtrUnsafe_NullAddress)
{
    uintptr_t result = guarded_ptr_or_zero(0, 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_InvalidAddress)
{
    uintptr_t result = guarded_ptr_or_zero(0xDEAD, 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_FreedMemory)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uintptr_t *>(mem) = 0xCAFEBABE;
    VirtualFree(mem, 0, MEM_RELEASE);

    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(mem), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_HeapAllocation)
{
    auto buffer = std::make_unique<uintptr_t>(0xABCD1234);
    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(buffer.get()), 0);
    EXPECT_EQ(result, 0xABCD1234);
}

TEST_F(MemoryTest, IsReadableNonblocking_ValidMemory)
{
    char buffer[100] = {0};
    auto status = is_readable_nonblocking(buffer, sizeof(buffer));
    // Cache is not primed, so this will be a cache miss returning Unknown
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

    // Nonblocking should hit cache
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
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    VirtualFree(mem, 0, MEM_RELEASE);

    memory::clear_cache();
    memory::shutdown_cache();

    auto status = is_readable_nonblocking(mem, 1);
    EXPECT_EQ(status, memory::ReadableStatus::NotReadable);

    (void)memory::init_cache();
}

TEST_F(MemoryTest, ReadPtrUnsafe_NoAccessPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(mem, nullptr);

    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(mem), 0);
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

    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(mem), 0);
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

    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(mem), 0);
    EXPECT_EQ(result, 0xFEEDFACE);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_NegativeOffset)
{
    uintptr_t values[3] = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC};
    uintptr_t base = reinterpret_cast<uintptr_t>(&values[2]);
    uintptr_t result = guarded_ptr_or_zero(base, -static_cast<ptrdiff_t>(sizeof(uintptr_t)));
    EXPECT_EQ(result, 0xBBBBBBBB);
}

// Window screen (is_plausible_ptr) plus the raw unchecked::read

TEST_F(MemoryTest, ReadPtrUnchecked_ValidHighPointer)
{
    uintptr_t value = 0x00007FF700000000;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0x00007FF700000000);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsNullValue)
{
    uintptr_t value = 0;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsLowPointer)
{
    uintptr_t value = 0x1000;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsBoundaryValue)
{
    // The result gate floor is EXCLUSIVE at min_valid (0x10000), so a loaded value exactly at the floor is rejected.
    uintptr_t value = 0x10000;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_AcceptsAboveBoundary)
{
    uintptr_t value = 0x10001;
    EXPECT_TRUE(memory::is_plausible_ptr(Address{value}));
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0x10001);
}

TEST_F(MemoryTest, ReadPtrUnchecked_WithOffset)
{
    uintptr_t values[2] = {0x1000, 0x00007FF700001234};
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(values), sizeof(uintptr_t));
    EXPECT_EQ(result, 0x00007FF700001234);
}

TEST_F(MemoryTest, ReadPtrUnchecked_CustomThreshold)
{
    uintptr_t value = 0x500;
    EXPECT_EQ(screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0, 0x1000), 0u);
    EXPECT_EQ(screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0, 0x100), 0x500);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ZeroThreshold)
{
    uintptr_t value = 1;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0, 0);
    EXPECT_EQ(result, 1u);
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

TEST_F(MemoryTest, ReadPtrUnchecked_SourceInLowAddressRange)
{
    uintptr_t base = 0x100;
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = screened_unchecked_ptr(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_SourceAtMinValid)
{
    uintptr_t base = 0x10000;
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = screened_unchecked_ptr(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ValidSourceLowResult)
{
    uintptr_t low_value = 0x100;
    uintptr_t base = reinterpret_cast<uintptr_t>(&low_value);
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = screened_unchecked_ptr(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ValidSourceValidResult)
{
    uintptr_t high_value = 0x7FFE0000;
    uintptr_t base = reinterpret_cast<uintptr_t>(&high_value);
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = screened_unchecked_ptr(base, offset, min_valid);
    EXPECT_EQ(result, high_value);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsKernelRangeSource)
{
    // A kernel-range source is rejected by the upper-bound guard before any dereference (early return), so this is safe
    // to call with a non-readable base.
    const uintptr_t base = 0xFFFF800000000000ULL;
    EXPECT_FALSE(memory::is_plausible_ptr(Address{base}));
    EXPECT_EQ(screened_unchecked_ptr(base, 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsSourceAtCeiling)
{
    // USERSPACE_PTR_MAX is the first non-canonical address; the window is half-open, so a source exactly at the ceiling
    // is rejected (also before any dereference).
    EXPECT_FALSE(memory::is_plausible_ptr(Address{memory::USERSPACE_PTR_MAX}));
    EXPECT_EQ(screened_unchecked_ptr(memory::USERSPACE_PTR_MAX, 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsSourceOffsetCrossingCeiling)
{
    // A positive offset that carries the source up to the ceiling is rejected; this is also how the range guard
    // subsumes pointer-arithmetic wraparound.
    const uintptr_t base = memory::USERSPACE_PTR_MAX - 0x100;
    EXPECT_EQ(screened_unchecked_ptr(base, 0x100), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsKernelRangeResult)
{
    // A structurally valid source that yields a kernel-range pointer must not be propagated down the chain; the result
    // guard rejects it like the source guard.
    uintptr_t kernel_value = 0xFFFF800000000000ULL;
    EXPECT_EQ(screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&kernel_value), 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsResultAtCeiling)
{
    uintptr_t ceiling_value = memory::USERSPACE_PTR_MAX;
    EXPECT_EQ(screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&ceiling_value), 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_AcceptsResultJustBelowCeiling)
{
    uintptr_t high_value = memory::USERSPACE_PTR_MAX - 1;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&high_value), 0);
    EXPECT_EQ(result, high_value);
}

TEST_F(MemoryTest, InvalidateRange_WraparoundAddress)
{
    uintptr_t near_max = UINTPTR_MAX - 0x10;
    size_t large_size = 0x100;

    EXPECT_NO_THROW(invalidate_range(reinterpret_cast<const void *>(near_max), large_size));
}

TEST_F(MemoryTest, WriteBytesToReadOnlyMemory_ExercisesVirtualProtect)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    std::byte data[] = {std::byte{0xDE}, std::byte{0xAD}};
    auto result =
        memory::write_bytes(Address{static_cast<std::byte *>(mem)}, std::span<const std::byte>{data, sizeof(data)});

    // write_bytes changes protection temporarily; this should succeed
    if (result.has_value())
    {
        EXPECT_EQ(std::memcmp(mem, data, sizeof(data)), 0);
    }
    else
    {
        EXPECT_EQ(result.error().code, ErrorCode::ProtectionChangeFailed);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteBytesToExecuteReadPage_ExercisesFlushCache)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte data[] = {std::byte{0x90}, std::byte{0x90}, std::byte{0xC3}};
    auto result =
        memory::write_bytes(Address{static_cast<std::byte *>(mem)}, std::span<const std::byte>{data, sizeof(data)});
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(std::memcmp(mem, data, sizeof(data)), 0);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadableNonblocking_LargeValidRegion)
{
    void *mem = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // First call populates cache
    auto status1 = is_readable_nonblocking(mem, 0x10000);
    EXPECT_NE(status1, memory::ReadableStatus::NotReadable);

    // Second call should hit cache
    auto status2 = is_readable_nonblocking(mem, 0x10000);
    EXPECT_NE(status2, memory::ReadableStatus::NotReadable);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_AfterCachePrime)
{
    uintptr_t value = 0xDEADBEEF;
    auto addr = reinterpret_cast<uintptr_t>(&value);

    // Prime the cache with a readable check. read consults no cache (the fault guard makes a probe
    // unnecessary), so this only confirms a primed region still reads back its value through the guarded path.
    EXPECT_TRUE(is_readable(&value, sizeof(uintptr_t)));

    uintptr_t result = guarded_ptr_or_zero(addr, 0);
    EXPECT_EQ(result, value);
}

TEST_F(MemoryTest, WriteBytesInvalidatesAndRevalidates)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Prime the cache
    EXPECT_TRUE(is_readable(mem, 4));

    // Write invalidates cached region
    std::byte data[] = {std::byte{0xAA}, std::byte{0xBB}};
    auto result =
        memory::write_bytes(Address{static_cast<std::byte *>(mem)}, std::span<const std::byte>{data, sizeof(data)});
    ASSERT_TRUE(result.has_value());

    // Subsequent check should still work (re-fetches into cache)
    EXPECT_TRUE(is_readable(mem, 4));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(MemoryErrorTest, MemoryErrorToString_IsNoexcept)
{
    static_assert(noexcept(to_string(ErrorCode::NullTargetAddress)));
}

// read_into

TEST_F(MemoryTest, SehReadBytes_ValidStackBuffer)
{
    const uint64_t source = 0xCAFEBABEDEADBEEFULL;
    auto value = memory::read<uint64_t>(Address{reinterpret_cast<uintptr_t>(&source)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, source);
}

TEST_F(MemoryTest, SehReadBytes_ZeroBytesIsNoOp)
{
    char dst = 'X';
    EXPECT_TRUE(read_bytes(0x1000, &dst, 0));
    EXPECT_EQ(dst, 'X');
}

TEST_F(MemoryTest, SehReadBytes_NullOutRejected)
{
    const uint32_t source = 0xDEADC0DE;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(&source), nullptr, sizeof(source)));
}

TEST_F(MemoryTest, SehReadBytes_LowAddressRejected)
{
    uint32_t out = 0xAAAAAAAA;
    EXPECT_FALSE(read_bytes(0x100, &out, sizeof(out)));
    EXPECT_FALSE(read_bytes(0xFFFF, &out, sizeof(out)));
}

TEST_F(MemoryTest, SehReadBytes_AddressWraparoundRejected)
{
    uint64_t out = 0;
    const uintptr_t near_max = UINTPTR_MAX - 8;
    EXPECT_FALSE(read_bytes(near_max, &out, 64));
}

TEST_F(MemoryTest, SehReadBytes_FreedMemoryReturnsFalse)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uint64_t *>(mem) = 0x1122334455667788ULL;
    VirtualFree(mem, 0, MEM_RELEASE);

    uint64_t out = 0;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));
}

TEST_F(MemoryTest, SehReadBytes_NoAccessReturnsFalse)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(mem, nullptr);

    uint64_t out = 0;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));

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
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, SehReadBytes_LargeRangePartialUnmapped)
{
    // Read more bytes than are available after a committed page; the second half lives in unmapped territory and the
    // read must fail.
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::vector<uint8_t> buf(8192, 0);
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(mem), buf.data(), buf.size()));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// read<T>

TEST_F(MemoryTest, SehRead_Uintptr)
{
    const uintptr_t source = 0xFEEDFACEBADDCAFEULL;
    auto value = memory::read<uintptr_t>(Address{reinterpret_cast<uintptr_t>(&source)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, source);
}

TEST_F(MemoryTest, SehRead_Uint32)
{
    const uint32_t source = 0xABCDEF01u;
    auto value = memory::read<uint32_t>(Address{reinterpret_cast<uintptr_t>(&source)});
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

    auto value = memory::read<Sample>(Address{reinterpret_cast<uintptr_t>(&source)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(value->a, source.a);
    EXPECT_EQ(value->b, source.b);
    EXPECT_EQ(value->c, source.c);
}

TEST_F(MemoryTest, SehRead_NullAddressReturnsNullopt)
{
    auto value = memory::read<uint64_t>(Address{static_cast<std::uintptr_t>(0)});
    EXPECT_FALSE(value.has_value());
}

TEST_F(MemoryTest, SehRead_LowAddressReturnsNullopt)
{
    auto value = memory::read<uint64_t>(Address{static_cast<std::uintptr_t>(0x100)});
    EXPECT_FALSE(value.has_value());
}

TEST_F(MemoryTest, SehRead_FreedMemoryReturnsNullopt)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uint64_t *>(mem) = 0xDEADBEEFu;
    VirtualFree(mem, 0, MEM_RELEASE);

    auto value = memory::read<uint64_t>(Address{reinterpret_cast<uintptr_t>(mem)});
    EXPECT_FALSE(value.has_value());
}

// Region / module_of / Region::own / Region::host

TEST_F(MemoryTest, ModuleRange_DefaultIsInvalid)
{
    Region range;
    EXPECT_EQ(range.size, 0u);
    EXPECT_FALSE(static_cast<bool>(range.base));
    EXPECT_EQ(range.base.raw(), 0u);
    EXPECT_EQ(range.end().raw(), 0u);
}

TEST_F(MemoryTest, ModuleRange_ContainsRejectsInvalid)
{
    Region range;
    EXPECT_FALSE(range.contains(Address{static_cast<std::uintptr_t>(0x1000)}));
}

TEST_F(MemoryTest, ModuleRange_ContainsBoundary)
{
    constexpr Region range{Address{static_cast<std::uintptr_t>(0x10000)}, 0x10000};
    EXPECT_TRUE(range.contains(Address{static_cast<std::uintptr_t>(0x10000)}));
    EXPECT_TRUE(range.contains(Address{static_cast<std::uintptr_t>(0x1FFFF)}));
    EXPECT_FALSE(range.contains(Address{static_cast<std::uintptr_t>(0x20000)}));
    EXPECT_FALSE(range.contains(Address{static_cast<std::uintptr_t>(0xFFFF)}));
}

TEST_F(MemoryTest, ModuleRange_ConstexprValid)
{
    static_assert(Region{Address{static_cast<std::uintptr_t>(0x10000)}, 0x10000}.size != 0);
    static_assert(Region{Address{static_cast<std::uintptr_t>(0x1000)}, 0x1000}.contains(
        Address{static_cast<std::uintptr_t>(0x1500)}));
}

TEST_F(MemoryTest, ModuleRangeFor_NullReturnsNullopt)
{
    const Region range = memory::module_of(Address{nullptr});
    EXPECT_EQ(range.size, 0u);
    EXPECT_FALSE(static_cast<bool>(range.base));
}

TEST_F(MemoryTest, ModuleRangeFor_OwnFunctionResolves)
{
    // The test exe is itself a loaded module; resolving any address in it must return a valid range that contains the
    // queried address.
    const Address probe{reinterpret_cast<const void *>(&memory::module_of)};
    const Region range = memory::module_of(probe);
    ASSERT_NE(range.size, 0u);
    EXPECT_TRUE(range.contains(probe));
}

TEST_F(MemoryTest, ModuleRangeFor_HeapAddressReturnsNullopt)
{
    // A heap allocation lives in committed memory that is not part of any loaded image, so GetModuleHandleEx returns
    // nullptr and the function returns an empty Region.
    auto buffer = std::make_unique<int>(42);
    const Region range = memory::module_of(Address{buffer.get()});
    EXPECT_EQ(range.size, 0u);
    EXPECT_FALSE(static_cast<bool>(range.base));
}

TEST_F(MemoryTest, ModuleRangeFor_CacheReturnsConsistentValue)
{
    const Address probe{reinterpret_cast<const void *>(&Region::own)};
    const Region first = memory::module_of(probe);
    ASSERT_NE(first.size, 0u);

    const Region second = memory::module_of(probe);
    ASSERT_NE(second.size, 0u);

    EXPECT_EQ(first.base.raw(), second.base.raw());
    EXPECT_EQ(first.end().raw(), second.end().raw());
}

TEST_F(MemoryTest, OwnModuleRange_IsValid)
{
    const Region range = Region::own();
    EXPECT_NE(range.size, 0u);
    EXPECT_TRUE(range.contains(Address{reinterpret_cast<const void *>(&Region::own)}));
}

TEST_F(MemoryTest, OwnModuleRange_StableAcrossCalls)
{
    const Region a = Region::own();
    const Region b = Region::own();
    EXPECT_EQ(a.base.raw(), b.base.raw());
    EXPECT_EQ(a.end().raw(), b.end().raw());
}

TEST_F(MemoryTest, HostModuleRange_IsValid)
{
    const Region range = Region::host();
    EXPECT_NE(range.size, 0u);

    // The test executable's main() symbol lives inside the host EXE image.
    HMODULE host = GetModuleHandleW(nullptr);
    ASSERT_NE(host, nullptr);
    EXPECT_EQ(range.base.raw(), reinterpret_cast<uintptr_t>(host));
}

TEST_F(MemoryTest, HostModuleRange_ContainsItself)
{
    // The test process is its own host; any code address inside the test exe must fall inside host().
    const Region range = Region::host();
    ASSERT_NE(range.size, 0u);

    HMODULE host = GetModuleHandleW(nullptr);
    ASSERT_NE(host, nullptr);
    EXPECT_TRUE(range.contains(Address{reinterpret_cast<void *>(host)}));
}

TEST_F(MemoryTest, HostModuleRange_StableAcrossCalls)
{
    const Region a = Region::host();
    const Region b = Region::host();
    EXPECT_EQ(a.base.raw(), b.base.raw());
    EXPECT_EQ(a.end().raw(), b.end().raw());
}

TEST_F(MemoryTest, ModuleRangeFor_KernelModuleResolves)
{
    // kernel32.dll is loaded into every Windows process; resolving any address inside it must yield a valid range.
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel, nullptr);

    const Region range = memory::module_of(Address{reinterpret_cast<void *>(kernel)});
    ASSERT_NE(range.size, 0u);
    EXPECT_EQ(range.base.raw(), reinterpret_cast<uintptr_t>(kernel));
}

// Every SEH-guarded foreign read must swallow EXCEPTION_IN_PAGE_ERROR (a file-backed page failing to page in) alongside
// the access-violation and guard-page faults, or the fault continues the handler search and terminates the host. The
// __except filters in the memory engine and the region/window guards in the scan engine share this single predicate, so
// pinning it pins all of them.
TEST(MemoryGuardedReadFault, AcceptsForeignReadFaultsAndRejectsOthers)
{
    using detail::is_guarded_read_fault;

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

// read reads through std::memcpy rather than a *reinterpret_cast deref, so a misaligned foreign pointer is
// read without invoking the undefined behavior of dereferencing a misaligned pointer. A pointer-sized value planted at
// an odd offset must round-trip exactly.
TEST_F(MemoryTest, ReadPtrUnsafeReadsMisalignedPointer)
{
    void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);

    auto *base = static_cast<std::uint8_t *>(region);
    constexpr std::uintptr_t SENTINEL = 0xDEADBEEFCAFEF00Dull;
    constexpr ptrdiff_t MISALIGNED_OFFSET = 1; // deliberately not a multiple of alignof(uintptr_t)
    std::memcpy(base + MISALIGNED_OFFSET, &SENTINEL, sizeof(SENTINEL));

    const std::uintptr_t value = guarded_ptr_or_zero(reinterpret_cast<std::uintptr_t>(base), MISALIGNED_OFFSET);
    EXPECT_EQ(value, SENTINEL);

    // An unmapped low address still fails closed to 0 (the fault is swallowed, not propagated).
    EXPECT_EQ(guarded_ptr_or_zero(0, 0), 0u);

    VirtualFree(region, 0, MEM_RELEASE);
}

// is_readable / is_writable must fall back to a direct VirtualQuery whenever the cache reports zero shards. The
// externally reachable zero-shard state is "cache not initialized"; the same code path also serves the brief init
// publication window where the cache flag is true but the shard count is still 0. Returning false there would wrongly
// report a readable region as non-readable, so the fallback must produce correct answers without the cache.
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

// A reserved-but-uncommitted page is backed by no physical storage, so any read of it faults. The guarded read must
// fail closed rather than terminate the host. On MinGW the vectored handler swallows the access violation; on MSVC the
// __except filter does.
TEST_F(MemoryTest, SehReadBytes_ReservedUncommittedReturnsFalse)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    uint64_t out = 0;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(reserved), &out, sizeof(out)));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

// With the cache reporting a page readable, an external reprotect to PAGE_NOACCESS must not crash a subsequent
// guarded read. The guarded read must ignore stale protection data and fail closed through the same "0 on fault"
// contract on both toolchains.
TEST_F(MemoryTest, ReadPtrUnsafeSurvivesStaleCacheReprotect)
{
    void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);
    const uintptr_t addr = reinterpret_cast<uintptr_t>(region);
    *reinterpret_cast<uintptr_t *>(region) = 0xABCDEF0123456789ULL;

    // Prime the cache so the region is recorded as readable.
    EXPECT_TRUE(is_readable(region, sizeof(uintptr_t)));
    EXPECT_EQ(guarded_ptr_or_zero(addr, 0), 0xABCDEF0123456789ULL);

    // Reprotect out from under the still-readable cache entry. The cache is not invalidated, so a cache-trusting read
    // would dereference a now-inaccessible page.
    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(region, 4096, PAGE_NOACCESS, &old_protect), 0);

    // The fault is swallowed and reported as the pointer-read failure value.
    EXPECT_EQ(guarded_ptr_or_zero(addr, 0), 0u);

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
// White-box: drives the engine's detail::guarded_read_bytes seam directly.
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
        EXPECT_FALSE(detail::guarded_read_bytes(bad_addr, &out, sizeof(out)));
        EXPECT_EQ(guarded_ptr_or_zero(bad_addr, 0), 0u);
        out = 0;
        EXPECT_TRUE(detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(&live), &out, sizeof(out)));
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
    EXPECT_EQ(guarded_ptr_or_zero(UINTPTR_MAX - 3, 0), 0u);

    // Below the user-mode floor.
    EXPECT_EQ(guarded_ptr_or_zero(0x100, 0), 0u);

    // A low base plus a large negative offset underflows the source to a high, unmapped address; still 0, no crash.
    EXPECT_EQ(guarded_ptr_or_zero(0x20000, -static_cast<ptrdiff_t>(0x30000)), 0u);
}

// Each guarded read arms its own per-read guard published to a thread-local slot, so concurrent reads of mixed
// good/bad memory across many threads must each get the right answer with no cross-thread guard corruption and no
// crash. This pins the per-thread isolation of the fault guard. White-box: drives detail::guarded_read_bytes.
TEST_F(MemoryTest, GuardedReadsAreThreadIsolatedUnderConcurrency)
{
    void *good = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(good, nullptr);
    constexpr uintptr_t SENTINEL = 0x5151515151515151ULL;
    *reinterpret_cast<uintptr_t *>(good) = SENTINEL;

    // A deliberately non-readable page the test owns until teardown. A committed PAGE_NOACCESS page faults
    // deterministically and cannot be recycled, so it exercises the guard's per-thread fault isolation without the
    // artifact of a released VA being remapped by the thread-spawn allocations.
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
                        uintptr_t v = 0;
                        if (!detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(good), &v, sizeof(v)) ||
                            v != SENTINEL)
                            all_correct.store(false, std::memory_order_relaxed);
                    }
                    else
                    {
                        uintptr_t v = 0;
                        if (detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(unreadable), &v, sizeof(v)))
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
// so this exercises guarded-read / cache-shutdown concurrency. White-box: drives detail::guarded_read_bytes.
TEST_F(MemoryTest, GuardedReadsSurviveConcurrentShutdown)
{
    void *good = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(good, nullptr);
    constexpr uintptr_t SENTINEL = 0xA5A5A5A5A5A5A5A5ULL;
    *reinterpret_cast<uintptr_t *>(good) = SENTINEL;

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
                    uintptr_t v = 0;
                    const bool ok = detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(target), &v, sizeof(v));
                    if (target == good)
                    {
                        if (ok && v == SENTINEL)
                            seen_good.fetch_add(1, std::memory_order_relaxed);
                    }
                    else if (!ok)
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
        memory::shutdown_cache();
        (void)memory::init_cache();
    }

    stop.store(true, std::memory_order_release);
    for (auto &th : readers)
        th.join();

    uintptr_t final_value = 0;
    EXPECT_TRUE(detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(good), &final_value, sizeof(final_value)));
    EXPECT_EQ(final_value, SENTINEL);
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
// simply recovers the fault directly. White-box: arms via detail::guarded_read_bytes.
TEST_F(MemoryTest, UnarmedThreadFaultIsPassedThroughNotClaimed)
{
    // Arm and disarm DMK's handler on this thread so it is installed for the process.
    uint64_t probe_src = 0xC3C3C3C3C3C3C3C3ULL;
    uint64_t probe_out = 0;
    ASSERT_TRUE(detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(&probe_src), &probe_out, sizeof(probe_out)));

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

// Coverage for the per-frame guarded WRITE primitives (write_bytes / write). They write to already-writable
// memory under a fault guard, changing no page protection and running no i-cache flush or cache invalidation, so they
// need no cache state; the fixture's cache is left in its default state.

TEST_F(MemoryTest, SehWrite_TypedRoundTripsToLocal)
{
    uint64_t target = 0;
    const uint64_t expected = 0x1122334455667788ull;

    EXPECT_TRUE(memory::write<uint64_t>(Address{reinterpret_cast<uintptr_t>(&target)}, expected).has_value());
    EXPECT_EQ(target, expected);

    // Read it back through the guarded read primitive to confirm the byte image matches.
    const auto value = memory::read<uint64_t>(Address{reinterpret_cast<uintptr_t>(&target)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, expected);
}

TEST_F(MemoryTest, SehWriteBytes_RoundTripsToHeap)
{
    auto buffer = std::make_unique<std::byte[]>(16);
    std::memset(buffer.get(), 0, 16);
    const std::byte source[] = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    EXPECT_TRUE(
        memory::write_bytes(Address{buffer.get()}, std::span<const std::byte>{source, sizeof(source)}).has_value());

    for (size_t i = 0; i < sizeof(source); ++i)
    {
        EXPECT_EQ(buffer[i], source[i]);
    }
    // Bytes beyond the written span are untouched.
    EXPECT_EQ(buffer[sizeof(source)], std::byte{0x00});
}

TEST_F(MemoryTest, SehWriteBytes_ZeroBytesIsNoOpSuccess)
{
    uint64_t target = 0xFEEDFACEull;
    const uint64_t source = 0x0;

    // Zero-byte write is a no-op success that leaves the target unchanged.
    EXPECT_TRUE(memory::write_bytes(Address{reinterpret_cast<uintptr_t>(&target)},
                                    std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), 0})
                    .has_value());
    EXPECT_EQ(target, 0xFEEDFACEull);
}

TEST_F(MemoryTest, SehWriteBytes_NullSourceReturnsFalse)
{
    uint64_t target = 0xFEEDFACEull;

    // nullptr source is rejected without a write.
    EXPECT_FALSE(
        memory::write_bytes(Address{reinterpret_cast<uintptr_t>(&target)},
                            std::span<const std::byte>{static_cast<const std::byte *>(nullptr), sizeof(target)})
            .has_value());
    EXPECT_EQ(target, 0xFEEDFACEull);
}

TEST_F(MemoryTest, SehWriteBytes_LowAddressReturnsFalse)
{
    const uint32_t source = 0x11223344u;

    // An address below 0x10000 (the Windows reserved low range) is rejected without a write and must not crash.
    EXPECT_FALSE(
        memory::write_bytes(Address{static_cast<uintptr_t>(0x100)},
                            std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)})
            .has_value());
}

// BEHAVIOR FLIP (v3 -> v4): v4 write_bytes auto-unprotects, so a write into a committed PAGE_READONLY page now SUCCEEDS
// and the bytes change, where v3 fails-closed. The page is held until TearDown via the local scope so a released VA
// cannot be remapped and the result stays deterministic.
TEST_F(MemoryTest, WriteBytes_ReadOnlyPageUnprotectsAndSucceeds)
{
    // A page seeded as PAGE_READWRITE so we can plant a known sentinel, then flipped to PAGE_READONLY before the write.
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);

    constexpr uint32_t SENTINEL = 0xA5A5A5A5u;
    *reinterpret_cast<uint32_t *>(page) = SENTINEL;

    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(page, 4096, PAGE_READONLY, &old_protect), 0);

    const uint32_t source = 0xDEADBEEFu;
    // The guarded write takes the slow path: change protection to writable, copy, restore. It SUCCEEDS.
    auto result = memory::write_bytes(
        Address{page}, std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)});
    EXPECT_TRUE(result.has_value());

    // The byte image changed to the new value.
    EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), source);

    VirtualFree(page, 0, MEM_RELEASE);
}

// BEHAVIOR FLIP (v3 -> v4), no-access variant: a COMMITTED PAGE_NOACCESS page can be reprotected to writable by
// VirtualProtect, so v4 write_bytes takes its auto-unprotect slow path and the write SUCCEEDS (v3 fails-closed). A
// genuinely unmapped / freed region cannot be reprotected and still fails closed (covered by the freed-memory read
// paths and WriteBytesToReadOnlyMemory's ProtectionChangeFailed branch). The page is held until after the assertion so
// the result is deterministic.
TEST_F(MemoryTest, WriteBytes_NoAccessPageUnprotectsAndSucceeds)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(page, nullptr);

    const uint32_t source = 0xDEADBEEFu;
    auto result = memory::write_bytes(
        Address{page}, std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)});
    EXPECT_TRUE(result.has_value());

    // Read the bytes back (the page is writable post-restore-to-NOACCESS only on the page itself, so verify via a
    // temporary reprotect to readable).
    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(page, 4096, PAGE_READWRITE, &old_protect), 0);
    EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), source);

    VirtualFree(page, 0, MEM_RELEASE);
}

// memory::write_in_place is the strict, no-reprotect write: it writes only when the target is already writable and
// FAILS CLOSED otherwise, never escalating to VirtualProtect the way write_bytes does. These cases pin both halves of
// that contract.
TEST_F(MemoryTest, WriteInPlace_WritableTargetSucceeds)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);

    const uint32_t source = 0xDEADBEEFu;
    auto result = memory::write_in_place(
        Address{page}, std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), source);

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteInPlace_ReadOnlyPageFailsClosedWithoutUnprotecting)
{
    // The capability that distinguishes write_in_place from write_bytes: a read-only target is REJECTED and the bytes
    // are left untouched (no silent unprotect-and-write).
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);

    constexpr uint32_t SENTINEL = 0xA5A5A5A5u;
    *reinterpret_cast<uint32_t *>(page) = SENTINEL;

    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(page, 4096, PAGE_READONLY, &old_protect), 0);

    const uint32_t source = 0xDEADBEEFu;
    auto result = memory::write_in_place(
        Address{page}, std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::WriteFaulted);

    // Reprotect to readable and confirm the sentinel is intact: the write never landed.
    ASSERT_NE(VirtualProtect(page, 4096, PAGE_READWRITE, &old_protect), 0);
    EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), SENTINEL);

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteInPlace_NoAccessPageFailsClosed)
{
    // Contrast with WriteBytes_NoAccessPageUnprotectsAndSucceeds: write_in_place changes no protection, so a committed
    // no-access page is rejected rather than reprotected and written.
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(page, nullptr);

    const uint32_t source = 0xDEADBEEFu;
    auto result = memory::write_in_place(
        Address{page}, std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::WriteFaulted);

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteInPlace_TypedRoundTripsToWritableLocal)
{
    uint64_t target = 0;
    const uint64_t value = 0x0123456789ABCDEFull;
    auto result = memory::write_in_place(Address{&target}, value);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(target, value);
}

TEST_F(MemoryTest, WriteInPlace_NullTargetReturnsError)
{
    const uint32_t source = 0;
    auto result = memory::write_in_place(
        Address{}, std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullTargetAddress);
}

TEST_F(MemoryTest, WriteInPlace_NullSourceReturnsError)
{
    uint32_t target = 0;
    auto result = memory::write_in_place(Address{&target},
                                         std::span<const std::byte>{static_cast<const std::byte *>(nullptr), 4});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullSourceBytes);
}

TEST_F(MemoryTest, WriteInPlace_ZeroBytesIsNoOpSuccess)
{
    uint32_t target = 0x11111111u;
    auto result = memory::write_in_place(Address{&target}, std::span<const std::byte>{});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(target, 0x11111111u);
}

// (a) ProtectGuard lifecycle.
TEST_F(MemoryTest, ProtectGuard_MakeOnReadOnlyPageSucceedsAndRestores)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(page, nullptr);

    {
        auto guard = memory::ProtectGuard::make(Region{Address{page}, 4096}, Prot::RW);
        ASSERT_TRUE(guard.has_value());
        EXPECT_TRUE(static_cast<bool>(*guard));

        // While the guard is armed the page is writable: a plain store does not fault.
        *reinterpret_cast<uint32_t *>(page) = 0xC0FFEEu;
        EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), 0xC0FFEEu);
    } // guard destructor restores PAGE_READONLY here

    // After restoration the page is read-only again: is_writable must report false.
    EXPECT_FALSE(is_writable(page, 4));

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ProtectGuard_MoveOnlyMovedFromIsFalsy)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(page, nullptr);

    auto made = memory::ProtectGuard::make(Region{Address{page}, 4096}, Prot::RW);
    ASSERT_TRUE(made.has_value());

    memory::ProtectGuard original = std::move(*made);
    EXPECT_TRUE(static_cast<bool>(original));

    memory::ProtectGuard moved = std::move(original);
    // The moved-from guard is disarmed (falsy); the destination owns the restore.
    EXPECT_FALSE(static_cast<bool>(original));
    EXPECT_TRUE(static_cast<bool>(moved));

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ProtectGuard_ReleaseLeavesProtectionChanged)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(page, nullptr);

    {
        auto guard = memory::ProtectGuard::make(Region{Address{page}, 4096}, Prot::RW);
        ASSERT_TRUE(guard.has_value());
        EXPECT_TRUE(static_cast<bool>(*guard));
        guard->release();
        // After release() the guard is disarmed and the destructor will NOT restore the original protection.
        EXPECT_FALSE(static_cast<bool>(*guard));
    }

    // Protection was left changed to RW, so the page is still writable after the guard's scope ended.
    EXPECT_TRUE(is_writable(page, 4));

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ProtectGuard_MakeOnEmptyRegionFails)
{
    auto guard = memory::ProtectGuard::make(Region{}, Prot::RW);
    ASSERT_FALSE(guard.has_value());
    EXPECT_EQ(guard.error().code, ErrorCode::ProtectionChangeFailed);
}

// (b) unchecked::read happy path on a known local.
TEST_F(MemoryTest, UncheckedRead_HappyPathOnKnownLocal)
{
    const uint64_t value = 0x0123456789ABCDEFull;
    const uint64_t got = memory::unchecked::read<uint64_t>(Address{reinterpret_cast<uintptr_t>(&value)});
    EXPECT_EQ(got, value);
}

// (c) Region::own() is valid and contains a DMK function; module_of an in-image address returns a region containing it.
TEST_F(MemoryTest, RegionOwn_ContainsDmkFunctionAndModuleOfAgrees)
{
    const Address fn{reinterpret_cast<const void *>(&memory::init_cache)};

    const Region own = Region::own();
    ASSERT_NE(own.size, 0u);
    EXPECT_TRUE(own.contains(fn));

    const Region module = memory::module_of(fn);
    ASSERT_NE(module.size, 0u);
    EXPECT_TRUE(module.contains(fn));
}

// (d) to_string(ErrorCode::ReadFaulted) round-trips to its exact name.
TEST(MemoryErrorTest, ToString_ReadFaulted)
{
    EXPECT_EQ(to_string(ErrorCode::ReadFaulted), "ReadFaulted");
}

// Memory-fault containment and cache coherence.

namespace
{
    // Current page protection of a single address via VirtualQuery, or 0 when the query fails.
    [[nodiscard]] DWORD current_page_protection(const void *address) noexcept
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
        {
            return 0;
        }
        return mbi.Protect;
    }
} // namespace

// write_bytes' protection-changing slow path routes its copy through the guarded writer and restores the ORIGINAL
// protection on the success exit, so a patched read-only page ends up read-only again rather than stranded writable.
TEST_F(MemoryTest, WriteBytes_ReadOnlyPageRestoresProtectionAfterSlowPath)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);
    auto *target = static_cast<std::byte *>(mem);

    const std::array<std::byte, 4> source{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
    const auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(target[0], std::byte{0x11});
    EXPECT_EQ(target[3], std::byte{0x44});

    // The captured original protection is restored after the guarded copy: the page is read-only again.
    EXPECT_EQ(current_page_protection(mem), static_cast<DWORD>(PAGE_READONLY));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Patching an executable page leaves it PAGE_EXECUTE_READ, never stranded PAGE_EXECUTE_READWRITE: the slow path
// restores the captured original protection, so a code patch cannot leave an RWX page behind for an attacker to reuse.
TEST_F(MemoryTest, WriteBytes_ExecutablePageRestoresExecuteProtection)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    ASSERT_NE(mem, nullptr);
    auto *target = static_cast<std::byte *>(mem);

    const std::array<std::byte, 3> source{std::byte{0x90}, std::byte{0x90}, std::byte{0xC3}};
    const auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(target[2], std::byte{0xC3});

    EXPECT_EQ(current_page_protection(mem), static_cast<DWORD>(PAGE_EXECUTE_READ));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// write_in_place rejects an oversized span with SizeTooLarge, matching write_bytes' cap. The source pointer is never
// dereferenced -- the cap is checked before any copy -- so an obviously-wrong length is a clean rejection.
TEST_F(MemoryTest, WriteInPlace_SizeTooLarge)
{
    std::array<std::byte, 16> target{};
    const std::byte source_byte{0xAB};
    const auto result = memory::write_in_place(Address{target.data()},
                                               std::span<const std::byte>{&source_byte, memory::MAX_WRITE_SIZE + 1});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::SizeTooLarge);
}

// ProtectGuard::make allocates its capture state BEFORE changing protection, so an allocation failure leaves the page's
// protection untouched (no leak) and is reported as OutOfMemory rather than thrown out of the noexcept factory. OOM is
// injected deterministically on this thread for the single make() call.
TEST_F(MemoryTest, ProtectGuard_BadAllocDoesNotLeakProtection)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    bool has_value = true;
    ErrorCode code = ErrorCode::ProtectionChangeFailed; // sentinel distinct from the expected OutOfMemory
    {
        // allow = 0 fails the very first throwing operator new on this thread: the make() pimpl allocation. No gtest
        // macro (which would allocate) runs inside the armed window.
        dmk_test::AllocFailScope fail{0};
        auto guard = memory::ProtectGuard::make(Region{Address{mem}, 4096}, Prot::RW);
        has_value = guard.has_value();
        if (!has_value)
        {
            code = guard.error().code;
        }
    }

    EXPECT_FALSE(has_value);
    EXPECT_EQ(code, ErrorCode::OutOfMemory);
    // The protection change never ran, so the page is still read-only: no leaked PAGE_READWRITE.
    EXPECT_EQ(current_page_protection(mem), static_cast<DWORD>(PAGE_READONLY));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// ProtectGuard::make and ~ProtectGuard each invalidate the protection cache for the guarded span, so a stale
// is_writable snapshot cannot survive the protection change or its restoration.
TEST_F(MemoryTest, ProtectGuard_MakeAndDestroyInvalidateCache)
{
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(16, 60000));

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    // Prime the cache: the read-only page caches "not writable".
    EXPECT_FALSE(is_writable(mem, 1));

    {
        auto guard = memory::ProtectGuard::make(Region{Address{mem}, 4096}, Prot::RW);
        ASSERT_TRUE(guard.has_value());
        // make() dropped the stale entry, so a re-query sees the now-writable page rather than the cached "no".
        EXPECT_TRUE(is_writable(mem, 1));
    }

    // ~ProtectGuard restored PAGE_READONLY and invalidated again, so is_writable re-queries and sees read-only.
    EXPECT_FALSE(is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Move-assigning into an armed guard restores the guard's OWN region before adopting the source's, so reassignment
// never silently abandons a protection change the destination still owned.
TEST_F(MemoryTest, ProtectGuard_MoveAssignRestoresReplacedRegion)
{
    void *mem1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    void *mem2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem1, nullptr);
    ASSERT_NE(mem2, nullptr);

    auto r1 = memory::ProtectGuard::make(Region{Address{mem1}, 4096}, Prot::RW);
    auto r2 = memory::ProtectGuard::make(Region{Address{mem2}, 4096}, Prot::RW);
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(current_page_protection(mem1), static_cast<DWORD>(PAGE_READWRITE));
    EXPECT_EQ(current_page_protection(mem2), static_cast<DWORD>(PAGE_READWRITE));

    {
        memory::ProtectGuard g1 = std::move(*r1);
        memory::ProtectGuard g2 = std::move(*r2);

        // Move-assign: g1 restores its own region (mem1 -> read-only) before adopting g2's (mem2 stays writable).
        g1 = std::move(g2);
        EXPECT_EQ(current_page_protection(mem1), static_cast<DWORD>(PAGE_READONLY));
        EXPECT_EQ(current_page_protection(mem2), static_cast<DWORD>(PAGE_READWRITE));
    } // g1 (now owning mem2) restores mem2 -> read-only on destruction

    EXPECT_EQ(current_page_protection(mem1), static_cast<DWORD>(PAGE_READONLY));
    EXPECT_EQ(current_page_protection(mem2), static_cast<DWORD>(PAGE_READONLY));

    VirtualFree(mem1, 0, MEM_RELEASE);
    VirtualFree(mem2, 0, MEM_RELEASE);
}

// get_memory_stats walks the shard array behind the reader guard and the SAME seq_cst s_cache_initialized gate the
// permission readers use, so a concurrent shutdown_cache (which frees that array) cannot pull it out from under the
// stats loop, and cannot tear the config snapshot against its field-by-field zeroing.
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
                    // Snapshot coherence, recorded via a flag because gtest macros are not safe to call off the main
                    // thread. A down cache reports every shard-derived field as zero; a live cache (non-zero shard
                    // count) reports the configured non-zero expiry, never a torn mix of the two.
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
            });
    }

    // A failed init must NOT longjmp out of the test via ASSERT_* while the reader threads are still running: that
    // would skip the join loop below and destroy joinable std::thread objects, calling std::terminate. Record the
    // failure, break, and let stop + join + the assert run afterwards.
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
    // The loop ended with the cache initialized (64, 10000); the fixture TearDown shuts it down.
}

// The typed write<T> / write_in_place<T> overloads are constrained against byte spans so a mutable
// std::span<std::byte> cannot exact-match the typed template and bit-copy the span object into the target.
namespace
{
    template <class Arg>
    concept WriteCallable = requires(Address a, Arg v) { memory::write(a, v); };
    template <class Arg>
    concept WriteInPlaceCallable = requires(Address a, Arg v) { memory::write_in_place(a, v); };

    // write has no byte-span overload, so a byte span is intentionally not callable through it (use write_bytes).
    static_assert(!WriteCallable<std::span<std::byte>>, "write(addr, span<byte>) must be ill-formed; use write_bytes");
    static_assert(!WriteCallable<std::span<const std::byte>>, "write(addr, span<const byte>) must be ill-formed");
    // A genuine trivially-copyable value still binds the typed template.
    static_assert(WriteCallable<int>, "write(addr, value) must remain valid");
    static_assert(WriteCallable<std::array<std::byte, 4>>, "write(addr, array-of-bytes) is a value, not a span");

    // write_in_place keeps its byte-span overload, so a byte span routes there rather than the hijacked typed template.
    static_assert(WriteInPlaceCallable<std::span<std::byte>>, "write_in_place(addr, span<byte>) must select the sink");
    static_assert(WriteInPlaceCallable<std::span<const std::byte>>);
    static_assert(WriteInPlaceCallable<int>, "write_in_place(addr, value) must remain valid");

    // A cv/ref-qualified byte-span type (reachable only through an EXPLICIT template argument, since argument
    // deduction never yields a cv/ref T) must not slip past the constraint. The bare trait matches only the
    // unqualified span specializations, so the write / write_in_place constraints inspect std::remove_cvref_t<T>:
    // these assert both halves of that reasoning so a future edit that drops the normalization is caught here.
    static_assert(!detail::is_byte_span_v<const std::span<std::byte>>,
                  "the bare trait does not see through const, so the constraint must normalize the type");
    static_assert(detail::is_byte_span_v<std::remove_cvref_t<const std::span<std::byte>>>,
                  "the normalization the constraints apply recognizes a const byte span");
    static_assert(detail::is_byte_span_v<std::remove_cvref_t<std::span<std::byte> &>>,
                  "the normalization also strips a reference qualifier");
} // namespace

TEST_F(MemoryTest, WriteInPlace_MutableByteSpanWritesViewedBytes)
{
    std::array<std::byte, 8> target{};
    std::array<std::byte, 4> source{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

    const auto result = memory::write_in_place(Address{target.data()}, std::span<std::byte>{source});
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0x11});
    EXPECT_EQ(target[1], std::byte{0x22});
    EXPECT_EQ(target[2], std::byte{0x33});
    EXPECT_EQ(target[3], std::byte{0x44});
    EXPECT_EQ(target[4], std::byte{0x00});
}

// A ProtectGuard laid over a span that crosses a protection seam restores each region to its own prior protection on
// scope exit, so an executable region adjacent to a read-only one is not flattened to PAGE_READONLY.
TEST_F(MemoryTest, ProtectGuard_MultiRegionRestoresEachRegionsOwnProtection)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;

    auto *base = static_cast<std::byte *>(VirtualAlloc(nullptr, 2 * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);
    DWORD old = 0;
    ASSERT_TRUE(VirtualProtect(base, page, PAGE_READONLY, &old));
    ASSERT_TRUE(VirtualProtect(base + page, page, PAGE_EXECUTE_READ, &old));

    {
        // One guard spanning both differently-protected regions makes the whole span writable.
        auto guard = memory::ProtectGuard::make(Region{Address{base}, 2 * page}, Prot::RW);
        ASSERT_TRUE(guard.has_value());
        EXPECT_EQ(current_page_protection(base), static_cast<DWORD>(PAGE_READWRITE));
        EXPECT_EQ(current_page_protection(base + page), static_cast<DWORD>(PAGE_READWRITE));
        // Both regions are writable while the guard is armed: a plain store faults neither.
        base[0] = std::byte{0x5A};
        base[page] = std::byte{0xA5};
    } // guard destructor restores each region to its own captured protection

    EXPECT_EQ(current_page_protection(base), static_cast<DWORD>(PAGE_READONLY));
    EXPECT_EQ(current_page_protection(base + page), static_cast<DWORD>(PAGE_EXECUTE_READ));

    VirtualFree(base, 0, MEM_RELEASE);
}

// A guarded read of a PAGE_GUARD page fails closed and re-arms the guard the OS consumed on dispatch, so the host's
// fence survives and a retry re-faults rather than reading straight through it.
TEST_F(MemoryTest, GuardedRead_GuardPageRearmedFailsClosedOnRetry)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *static_cast<uint32_t *>(mem) = 0xFEEDFACEu;
    DWORD old = 0;
    ASSERT_TRUE(VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old));

    const Address addr{mem};
    // First guarded read faults on the guard page and fails closed; the handler re-armed the guard the OS cleared.
    EXPECT_FALSE(memory::read<uint32_t>(addr).has_value());
    EXPECT_NE(current_page_protection(mem) & PAGE_GUARD, 0u);
    // The retry re-faults on the re-armed guard rather than reading through the fence.
    EXPECT_FALSE(memory::read<uint32_t>(addr).has_value());
    EXPECT_NE(current_page_protection(mem) & PAGE_GUARD, 0u);

    // Clear the guard before freeing so nothing else faults on it.
    DWORD cleared = 0;
    VirtualProtect(mem, 4096, PAGE_READWRITE, &cleared);
    VirtualFree(mem, 0, MEM_RELEASE);
}

// Several threads racing shutdown_cache must not both join the same cleanup std::thread (a std::system_error out of a
// noexcept function -> std::terminate). The join mutex lets exactly one caller join; the rest skip.
TEST_F(MemoryTest, ShutdownCache_ConcurrentCallersJoinExactlyOnceNoTerminate)
{
    // Start from a known-initialized state so a background cleanup thread exists and the join/detach path is exercised.
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(32, 5000));

    // Prime an entry so the cleanup thread has content and is definitely running.
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
            });
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

    // Reaching here without std::terminate is the proof; the cache is down and a fresh init still works.
    EXPECT_TRUE(memory::init_cache(32, 5000));
}

// is_module_loaded widens the name into a std::wstring, which can throw bad_alloc. The noexcept query wraps that
// allocation and fails soft under memory pressure rather than letting the throw terminate the host.
TEST_F(MemoryTest, IsModuleLoaded_AllocFailureFailsSoftNoTerminate)
{
    // Control: kernel32 is always loaded, so the normal path is true.
    EXPECT_TRUE(memory::is_module_loaded("kernel32.dll"));

    bool under_oom = true;
    {
        // allow = 0 fails the first throwing operator new on this thread -- the widen_module_name wstring allocation
        // (MultiByteToWideChar takes no C++ heap). No gtest macro runs inside the armed window (it would allocate).
        dmk_test::AllocFailScope fail{0};
        under_oom = memory::is_module_loaded("kernel32.dll");
    }
    // The widen allocation failed, so the query fails closed to false instead of terminating the noexcept host path.
    EXPECT_FALSE(under_oom);
}

// write_bytes' slow path across a protection seam restores EACH region to its own prior protection: a patch straddling
// a read-only / executable boundary leaves the executable side executable, never flattened to PAGE_READONLY (which
// would access-violate under DEP on its next execution). This drives patch_bytes' multi-segment protect/restore, which
// a single uniform-protection page cannot.
TEST_F(MemoryTest, WriteBytes_AcrossProtectionSeamRestoresEachRegion)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;

    auto *base = static_cast<std::byte *>(VirtualAlloc(nullptr, 2 * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);
    DWORD old = 0;
    ASSERT_TRUE(VirtualProtect(base, page, PAGE_READONLY, &old));
    ASSERT_TRUE(VirtualProtect(base + page, page, PAGE_EXECUTE_READ, &old));

    // Straddle the seam: two bytes in the read-only page's tail, two in the executable page's head.
    const std::size_t split = page - 2;
    const std::array<std::byte, 4> source{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    const auto result = memory::write_bytes(Address{base + split}, std::span<const std::byte>{source});
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(base[split + 0], std::byte{0xDE});
    EXPECT_EQ(base[split + 1], std::byte{0xAD}); // last byte of the read-only page
    EXPECT_EQ(base[page + 0], std::byte{0xBE});  // first byte of the executable page
    EXPECT_EQ(base[page + 1], std::byte{0xEF});

    // Each region is restored to its OWN protection, not a single flattened value.
    EXPECT_EQ(current_page_protection(base), static_cast<DWORD>(PAGE_READONLY));
    EXPECT_EQ(current_page_protection(base + page), static_cast<DWORD>(PAGE_EXECUTE_READ));

    DWORD cleared = 0;
    VirtualProtect(base, 2 * page, PAGE_READWRITE, &cleared);
    VirtualFree(base, 0, MEM_RELEASE);
}

// A span crossing more distinct protection regions than protect_across_regions can track (MAX_PROTECTION_SEGMENTS) is
// the security-critical fail-closed branch: ProtectGuard::make must return an error AND roll back, leaving no page
// stranded in the changed (writable) protection. Alternating each page's protection makes every page its own
// VirtualQuery region, so the span crosses far more than the 64-segment cap.
TEST_F(MemoryTest, ProtectGuard_OverSegmentCapFailsClosedAndRollsBack)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;
    constexpr std::size_t page_count = 96; // comfortably past MAX_PROTECTION_SEGMENTS (64)

    auto *base =
        static_cast<std::byte *>(VirtualAlloc(nullptr, page_count * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);

    // Alternate protections so no two adjacent pages coalesce into one region; the span then crosses page_count
    // distinct regions.
    const auto protection_of = [](std::size_t i) -> DWORD
    { return (i % 2 == 0) ? static_cast<DWORD>(PAGE_READONLY) : static_cast<DWORD>(PAGE_EXECUTE_READ); };
    for (std::size_t i = 0; i < page_count; ++i)
    {
        DWORD old = 0;
        ASSERT_TRUE(VirtualProtect(base + i * page, page, protection_of(i), &old));
    }

    // One guard over the whole multi-region span exceeds the segment cap and must fail closed.
    auto guard = memory::ProtectGuard::make(Region{Address{base}, page_count * page}, Prot::RW);
    EXPECT_FALSE(guard.has_value());

    // Rollback: every page kept its original protection; none was left PAGE_EXECUTE_READWRITE.
    for (std::size_t i = 0; i < page_count; ++i)
    {
        EXPECT_EQ(current_page_protection(base + i * page), protection_of(i));
    }

    DWORD cleared = 0;
    VirtualProtect(base, page_count * page, PAGE_READWRITE, &cleared);
    VirtualFree(base, 0, MEM_RELEASE);
}

// A bad_alloc anywhere in a cache-miss insert (the unordered_map node, the lru map node, or the sorted-range deque
// chunk) must fail SOFT: update_shard_with_region catches it and is_readable still returns the authoritative
// VirtualQuery answer, never terminating. This drives the failure across each successive insert allocation, so one
// iteration lands on the deque insert -- the stage that terminated while insert_sorted_range was noexcept (a throw at
// its own noexcept frame never reaching the wrapper's catch). Every iteration returning cleanly is the fix's proof.
TEST_F(MemoryTest, IsReadable_CacheInsertAllocFailureFailsSoftAtEveryStage)
{
    int probe = 7;

    for (int allow = 0; allow <= 4; ++allow)
    {
        // Re-init a FRESH cache each iteration so the shard's sorted-range deque is truly empty -- no node retained by a
        // prior clear (libstdc++ deque::clear keeps one 32-slot chunk, MSVC differs), so its first insert reliably
        // allocates. That makes some `allow` land squarely on the insert_sorted_range deque allocation, the stage that
        // terminated the host while it was noexcept (a throw at its own noexcept frame never reaches the wrapper catch).
        // init_cache runs OUTSIDE the armed window, so the shard-array / handler-install allocations are not injected.
        memory::shutdown_cache();
        ASSERT_TRUE(memory::init_cache(16, 60000));

        bool readable = false;
        {
            // Allow the first `allow` allocations of the cache-miss insert, fail the next: across the sweep the failing
            // one is in turn the unordered_map node, the lru map node, and the deque chunk. No gtest macro runs inside
            // the armed window (it would allocate).
            dmk_test::AllocFailScope fail{allow};
            readable = memory::is_readable(Region{Address{&probe}, sizeof(probe)});
        }

        // Reaching here without std::terminate is half the proof; the VirtualQuery answer must still be correct.
        EXPECT_TRUE(readable) << "allow=" << allow;
    }
}
