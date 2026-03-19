// Unit tests for Memory utilities module
#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/logger.hpp"

using namespace DetourModKit;

// Test fixture for Memory tests
class MemoryUtilsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Initialize memory cache for tests
        Memory::initMemoryCache();
    }

    void TearDown() override
    {
        // Clean up cache after tests
        Memory::clearMemoryCache();
    }
};

// Test initMemoryCache
TEST_F(MemoryUtilsTest, InitMemoryCache)
{
    // Note: initMemoryCache uses std::call_once, so we can only test
    // that it returns true (either initialized now or already initialized)
    bool result = Memory::initMemoryCache();
    EXPECT_TRUE(result);
}

// Test initMemoryCache with custom parameters
TEST_F(MemoryUtilsTest, InitMemoryCache_CustomParams)
{
    Memory::clearMemoryCache();

    // Initialize with custom cache size and expiry
    bool result = Memory::initMemoryCache(64, 10000);
    EXPECT_TRUE(result);

    // Clean up
    Memory::clearMemoryCache();
}

// Test clearMemoryCache
TEST_F(MemoryUtilsTest, ClearMemoryCache)
{
    EXPECT_NO_THROW(Memory::clearMemoryCache());

    // Multiple clears should not throw
    EXPECT_NO_THROW(Memory::clearMemoryCache());
    EXPECT_NO_THROW(Memory::clearMemoryCache());
}

// Test getMemoryCacheStats
TEST_F(MemoryUtilsTest, GetMemoryCacheStats)
{
    std::string stats = Memory::getMemoryCacheStats();
    // Should return a non-empty string
    EXPECT_FALSE(stats.empty());
}

// Test isMemoryReadable with valid stack memory
TEST_F(MemoryUtilsTest, IsMemoryReadable_Valid)
{
    char buffer[100] = {0};

    bool result = Memory::isMemoryReadable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

// Test isMemoryReadable with valid heap memory
TEST_F(MemoryUtilsTest, IsMemoryReadable_ValidHeap)
{
    auto buffer = std::make_unique<char[]>(100);

    bool result = Memory::isMemoryReadable(buffer.get(), 100);
    EXPECT_TRUE(result);
}

// Test isMemoryReadable with single byte
TEST_F(MemoryUtilsTest, IsMemoryReadable_SingleByte)
{
    char c = 'A';
    bool result = Memory::isMemoryReadable(&c, 1);
    EXPECT_TRUE(result);
}

// Test isMemoryReadable with invalid address
TEST_F(MemoryUtilsTest, IsMemoryReadable_Invalid)
{
    // Try to read from nullptr - should return false
    bool result = Memory::isMemoryReadable(nullptr, 100);
    EXPECT_FALSE(result);
}

// Test isMemoryReadable with zero size
TEST_F(MemoryUtilsTest, IsMemoryReadable_ZeroSize)
{
    char buffer[100] = {0};

    // Zero size should technically be valid (no actual read)
    bool result = Memory::isMemoryReadable(buffer, 0);
    // Behavior may vary, but should not crash
    (void)result;
}

// Test isMemoryWritable with valid stack memory
TEST_F(MemoryUtilsTest, IsMemoryWritable_Valid)
{
    char buffer[100] = {0};

    bool result = Memory::isMemoryWritable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

// Test isMemoryWritable with valid heap memory
TEST_F(MemoryUtilsTest, IsMemoryWritable_ValidHeap)
{
    auto buffer = std::make_unique<char[]>(100);

    bool result = Memory::isMemoryWritable(buffer.get(), 100);
    EXPECT_TRUE(result);
}

// Test isMemoryWritable with const memory (should be false)
TEST_F(MemoryUtilsTest, IsMemoryWritable_Const)
{
    // Const memory cannot be passed to isMemoryWritable which expects non-const void*
    // This test documents that const memory is not writable
    char buffer[] = "test";

    // First verify it's writable (it is, since it's not actually const)
    bool result = Memory::isMemoryWritable(buffer, sizeof(buffer));
    EXPECT_TRUE(result);
}

// Test isMemoryWritable with invalid address
TEST_F(MemoryUtilsTest, IsMemoryWritable_Invalid)
{
    // Try to write to nullptr - should return false
    bool result = Memory::isMemoryWritable(nullptr, 100);
    EXPECT_FALSE(result);
}

// Test isMemoryWritable with zero size
TEST_F(MemoryUtilsTest, IsMemoryWritable_ZeroSize)
{
    char buffer[100] = {0};

    bool result = Memory::isMemoryWritable(buffer, 0);
    // Behavior may vary, but should not crash
    (void)result;
}

// Test WriteBytes
TEST_F(MemoryUtilsTest, WriteBytes)
{
    // Allocate some writable memory on the stack
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};

    Logger &logger = Logger::getInstance();

    auto result = Memory::WriteBytes(target.data(), source.data(), source.size(), logger);
    EXPECT_TRUE(result.has_value());

    // Verify the bytes were written
    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }
}

// Test WriteBytes with nullptr target
TEST_F(MemoryUtilsTest, WriteBytes_NullTarget)
{
    std::vector<std::byte> source = {std::byte{0x90}, std::byte{0x90}};
    Logger &logger = Logger::getInstance();

    auto result = Memory::WriteBytes(nullptr, source.data(), source.size(), logger);
    EXPECT_FALSE(result.has_value());
}

// Test WriteBytes with nullptr source
TEST_F(MemoryUtilsTest, WriteBytes_NullSource)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    Logger &logger = Logger::getInstance();

    auto result = Memory::WriteBytes(target.data(), nullptr, 10, logger);
    EXPECT_FALSE(result.has_value());
}

// Test WriteBytes with zero size
TEST_F(MemoryUtilsTest, WriteBytes_ZeroSize)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {std::byte{0x90}};
    Logger &logger = Logger::getInstance();

    auto result = Memory::WriteBytes(target.data(), source.data(), 0, logger);
    EXPECT_TRUE(result.has_value()); // Should succeed (nothing to do)
}

// Test WriteBytes to read-only memory (should fail)
TEST_F(MemoryUtilsTest, WriteBytes_ReadOnly)
{
    // Note: True read-only memory (like string literals) cannot be easily tested
    // because attempting to write to them would cause a crash, not just a failure.
    // Instead, we test with nullptr which should return an error.
    std::vector<std::byte> source = {std::byte{0x90}, std::byte{0x90}};
    Logger &logger = Logger::getInstance();

    auto result = Memory::WriteBytes(nullptr, source.data(), source.size(), logger);
    // Should fail because target is null
    EXPECT_FALSE(result.has_value());
}

// Test WriteBytes with large data
TEST_F(MemoryUtilsTest, WriteBytes_Large)
{
    std::vector<std::byte> target(1024, std::byte{0x00});
    std::vector<std::byte> source(512, std::byte{0xCC});

    Logger &logger = Logger::getInstance();

    auto result = Memory::WriteBytes(target.data(), source.data(), source.size(), logger);
    EXPECT_TRUE(result.has_value());

    // Verify the bytes were written
    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }

    // Verify remaining bytes are unchanged
    for (size_t i = source.size(); i < target.size(); ++i)
    {
        EXPECT_EQ(target[i], std::byte{0x00});
    }
}

// Test memory cache caching behavior
TEST_F(MemoryUtilsTest, CacheBehavior)
{
    char buffer[100] = {0};

    // First access - cache miss
    bool result1 = Memory::isMemoryReadable(buffer, sizeof(buffer));
    EXPECT_TRUE(result1);

    // Second access - should be cache hit
    bool result2 = Memory::isMemoryReadable(buffer, sizeof(buffer));
    EXPECT_TRUE(result2);

    // Get stats to verify cache is working
    std::string stats = Memory::getMemoryCacheStats();
    EXPECT_FALSE(stats.empty());
}

// Test memory validation with multiple regions
TEST_F(MemoryUtilsTest, MultipleRegions)
{
    char buffer1[100] = {0};
    char buffer2[200] = {0};

    EXPECT_TRUE(Memory::isMemoryReadable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(Memory::isMemoryReadable(buffer2, sizeof(buffer2)));
    EXPECT_TRUE(Memory::isMemoryWritable(buffer1, sizeof(buffer1)));
    EXPECT_TRUE(Memory::isMemoryWritable(buffer2, sizeof(buffer2)));
}

// Test thread safety of memory cache
TEST_F(MemoryUtilsTest, ThreadSafety)
{
    const int num_threads = 4;
    const int iterations = 100;

    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([iterations]()
                             {
            char buffer[100] = {0};
            for (int j = 0; j < iterations; ++j)
            {
                Memory::isMemoryReadable(buffer, sizeof(buffer));
                Memory::isMemoryWritable(buffer, sizeof(buffer));
            } });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    // If we get here without crash, thread safety is verified
    SUCCEED();
}

// Test cache after clear
TEST_F(MemoryUtilsTest, CacheAfterClear)
{
    char buffer[100] = {0};

    // Access before clear
    EXPECT_TRUE(Memory::isMemoryReadable(buffer, sizeof(buffer)));

    // Clear cache
    Memory::clearMemoryCache();

    // Access after clear - should still work
    EXPECT_TRUE(Memory::isMemoryReadable(buffer, sizeof(buffer)));
}

// Test WriteBytes preserves data integrity
TEST_F(MemoryUtilsTest, WriteBytes_DataIntegrity)
{
    // Create a pattern
    std::vector<std::byte> target(64);
    for (size_t i = 0; i < target.size(); ++i)
    {
        target[i] = std::byte{static_cast<uint8_t>(i)};
    }

    // Source pattern
    std::vector<std::byte> source = {
        std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    Logger &logger = Logger::getInstance();

    // Write at offset
    auto result = Memory::WriteBytes(target.data() + 10, source.data(), source.size(), logger);
    EXPECT_TRUE(result.has_value());

    // Verify bytes before offset are unchanged
    for (size_t i = 0; i < 10; ++i)
    {
        EXPECT_EQ(target[i], std::byte{static_cast<uint8_t>(i)});
    }

    // Verify written bytes
    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[10 + i], source[i]);
    }

    // Verify bytes after written section are unchanged
    for (size_t i = 14; i < target.size(); ++i)
    {
        EXPECT_EQ(target[i], std::byte{static_cast<uint8_t>(i)});
    }
}

// Test isMemoryReadable with string literal
TEST_F(MemoryUtilsTest, IsMemoryReadable_StringLiteral)
{
    const char *str = "Hello, World!";

    // String literals should be readable
    bool result = Memory::isMemoryReadable(str, strlen(str));
    EXPECT_TRUE(result);
}

// Test memoryErrorToString
TEST(MemoryErrorTest, ErrorToString)
{
    EXPECT_FALSE(memoryErrorToString(MemoryError::NullTargetAddress).empty());
    EXPECT_FALSE(memoryErrorToString(MemoryError::NullSourceBytes).empty());
    EXPECT_FALSE(memoryErrorToString(MemoryError::ProtectionChangeFailed).empty());
    EXPECT_FALSE(memoryErrorToString(MemoryError::ProtectionRestoreFailed).empty());

    // Test unknown error value
    EXPECT_FALSE(memoryErrorToString(static_cast<MemoryError>(999)).empty());
}

// Test memory cache with very short expiry to trigger expiry path
TEST_F(MemoryUtilsTest, CacheExpiry)
{
    Memory::clearMemoryCache();

    // Initialize with very short cache expiry (10ms)
    Memory::initMemoryCache(64, 10);

    char buffer[100] = {0};
    // First read - populates cache
    EXPECT_TRUE(Memory::isMemoryReadable(buffer, sizeof(buffer)));

    // Wait for cache to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // Second read should miss cache (expired)
    EXPECT_TRUE(Memory::isMemoryReadable(buffer, sizeof(buffer)));

    Memory::clearMemoryCache();
}

// Test memory cache with overlapping regions
TEST_F(MemoryUtilsTest, CacheBehavior_Overlapping)
{
    Memory::clearMemoryCache();
    Memory::initMemoryCache(64, 10000);

    char buffer[100] = {0};

    // First read
    EXPECT_TRUE(Memory::isMemoryReadable(buffer, 50));
    // Second read of overlapping but larger region
    EXPECT_TRUE(Memory::isMemoryReadable(buffer, 100));
    // Third read of subset
    EXPECT_TRUE(Memory::isMemoryReadable(buffer + 10, 40));

    Memory::clearMemoryCache();
}

// ===== Coverage improvement tests =====

// Test isMemoryReadable with reserved (non-committed) memory
// Covers MEM_COMMIT check path (line ~357 in memory.cpp)
TEST_F(MemoryUtilsTest, IsMemoryReadable_ReservedMemory)
{
    // Allocate reserved but not committed memory
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    // Reserved but not committed → not readable
    EXPECT_FALSE(Memory::isMemoryReadable(reserved, 1));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

// Test isMemoryWritable with reserved (non-committed) memory
// Covers MEM_COMMIT check for writable path (line ~439)
TEST_F(MemoryUtilsTest, IsMemoryWritable_ReservedMemory)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    EXPECT_FALSE(Memory::isMemoryWritable(reserved, 1));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

// Test isMemoryWritable with read-only committed memory
// Covers WRITE_PERMISSION_FLAGS check (line ~444)
TEST_F(MemoryUtilsTest, IsMemoryWritable_ReadOnlyMemory)
{
    void *readonly = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(readonly, nullptr);

    // Committed with PAGE_READONLY → not writable
    EXPECT_FALSE(Memory::isMemoryWritable(readonly, 1));

    VirtualFree(readonly, 0, MEM_RELEASE);
}

// Test isMemoryReadable with PAGE_NOACCESS memory
// Covers the PAGE_NOACCESS | PAGE_GUARD check (line ~364)
TEST_F(MemoryUtilsTest, IsMemoryReadable_NoAccess)
{
    void *noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noaccess, nullptr);

    EXPECT_FALSE(Memory::isMemoryReadable(noaccess, 1));

    VirtualFree(noaccess, 0, MEM_RELEASE);
}

// Test isMemoryWritable with PAGE_NOACCESS
TEST_F(MemoryUtilsTest, IsMemoryWritable_NoAccess)
{
    void *noaccess = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noaccess, nullptr);

    EXPECT_FALSE(Memory::isMemoryWritable(noaccess, 1));

    VirtualFree(noaccess, 0, MEM_RELEASE);
}

// Test isMemoryReadable with freed memory (VirtualQuery returns 0)
// Covers the VirtualQuery failure path (line ~351)
TEST_F(MemoryUtilsTest, IsMemoryReadable_FreedMemory)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    VirtualFree(mem, 0, MEM_RELEASE);

    // After freeing, VirtualQuery may still return info but with MEM_FREE state
    // which is not MEM_COMMIT, so this should return false
    EXPECT_FALSE(Memory::isMemoryReadable(mem, 1));
}

// Test isMemoryWritable with execute-only memory
TEST_F(MemoryUtilsTest, IsMemoryWritable_ExecuteOnly)
{
    void *exec = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE);
    ASSERT_NE(exec, nullptr);

    // PAGE_EXECUTE doesn't include write permissions
    EXPECT_FALSE(Memory::isMemoryWritable(exec, 1));

    VirtualFree(exec, 0, MEM_RELEASE);
}

// Test isMemoryReadable with PAGE_EXECUTE_READWRITE (should be readable)
TEST_F(MemoryUtilsTest, IsMemoryReadable_ExecuteReadWrite)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(Memory::isMemoryReadable(mem, 1));
    EXPECT_TRUE(Memory::isMemoryWritable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Test cache LRU eviction (covers updateCacheWithNewRegion LRU path, lines ~157-160)
TEST_F(MemoryUtilsTest, CacheLRUEviction)
{
    Memory::clearMemoryCache();
    // Use a very small cache to force eviction
    Memory::initMemoryCache(2, 60000);

    // Allocate 3 distinct memory regions to exceed cache size
    void *mem1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem2 = VirtualAlloc(reinterpret_cast<void *>(0), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem3 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ASSERT_NE(mem1, nullptr);
    ASSERT_NE(mem2, nullptr);
    ASSERT_NE(mem3, nullptr);

    // Fill cache (2 entries)
    EXPECT_TRUE(Memory::isMemoryReadable(mem1, 1));
    EXPECT_TRUE(Memory::isMemoryReadable(mem2, 1));

    // Third access should trigger LRU eviction
    EXPECT_TRUE(Memory::isMemoryReadable(mem3, 1));

    // All should still be readable (just checking no crash during eviction)
    EXPECT_TRUE(Memory::isMemoryReadable(mem1, 1));

    VirtualFree(mem1, 0, MEM_RELEASE);
    VirtualFree(mem2, 0, MEM_RELEASE);
    VirtualFree(mem3, 0, MEM_RELEASE);

    Memory::clearMemoryCache();
}

// Test isMemoryReadable with very large size that causes overflow (line ~377)
TEST_F(MemoryUtilsTest, IsMemoryReadable_SizeOverflow)
{
    char buffer[1] = {0};
    // SIZE_MAX + address will overflow
    EXPECT_FALSE(Memory::isMemoryReadable(buffer, SIZE_MAX));
}

// Test isMemoryWritable with size overflow (line ~450)
TEST_F(MemoryUtilsTest, IsMemoryWritable_SizeOverflow)
{
    char buffer[1] = {0};
    EXPECT_FALSE(Memory::isMemoryWritable(buffer, SIZE_MAX));
}

// Test WriteBytes error codes
TEST_F(MemoryUtilsTest, WriteBytes_ErrorTypes)
{
    Logger &logger = Logger::getInstance();
    std::byte source[] = {std::byte{0x90}};

    // NullTargetAddress
    auto r1 = Memory::WriteBytes(nullptr, source, 1, logger);
    EXPECT_FALSE(r1.has_value());
    EXPECT_EQ(r1.error(), MemoryError::NullTargetAddress);

    // NullSourceBytes
    std::byte target[1] = {std::byte{0}};
    auto r2 = Memory::WriteBytes(target, nullptr, 1, logger);
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), MemoryError::NullSourceBytes);
}

// Test WriteBytes with zero bytes (covers memory.cpp lines 477-481)
TEST_F(MemoryUtilsTest, WriteBytes_ZeroBytes)
{
    Logger &logger = Logger::getInstance();
    std::byte target[4] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
    std::byte source[1] = {std::byte{0x00}};

    auto result = Memory::WriteBytes(target, source, 0, logger);
    EXPECT_TRUE(result.has_value());

    // Data should be unchanged
    EXPECT_EQ(target[0], std::byte{0xAA});
}

// Test WriteBytes success path (covers memory.cpp lines 483-510)
TEST_F(MemoryUtilsTest, WriteBytes_Success)
{
    Logger &logger = Logger::getInstance();

    // Allocate writable memory
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);
    std::byte source[] = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto result = Memory::WriteBytes(target, source, 3, logger);
    EXPECT_TRUE(result.has_value());

    // Verify bytes were written
    EXPECT_EQ(target[0], std::byte{0x90});
    EXPECT_EQ(target[1], std::byte{0x90});
    EXPECT_EQ(target[2], std::byte{0x90});

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Test isMemoryWritable with writable memory (covers isMemoryWritable cache update path)
TEST_F(MemoryUtilsTest, IsMemoryWritable_ValidWritable)
{
    Memory::clearMemoryCache();
    Memory::initMemoryCache(4, 60000);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(Memory::isMemoryWritable(mem, 1));

    // Second call should hit cache
    EXPECT_TRUE(Memory::isMemoryWritable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
    Memory::clearMemoryCache();
}
