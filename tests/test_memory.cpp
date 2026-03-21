#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <atomic>
#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/logger.hpp"

using namespace DetourModKit;

class MemoryTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Memory::init_cache();
    }

    void TearDown() override
    {
        Memory::shutdown_cache();
    }
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
    std::vector<std::byte> source = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};

    Logger &logger = Logger::get_instance();

    auto result = Memory::write_bytes(target.data(), source.data(), source.size(), logger);
    EXPECT_TRUE(result.has_value());

    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }
}

TEST_F(MemoryTest, write_bytes_NullTarget)
{
    std::vector<std::byte> source = {std::byte{0x90}, std::byte{0x90}};
    Logger &logger = Logger::get_instance();

    auto result = Memory::write_bytes(nullptr, source.data(), source.size(), logger);
    EXPECT_FALSE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_NullSource)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    Logger &logger = Logger::get_instance();

    auto result = Memory::write_bytes(target.data(), nullptr, 10, logger);
    EXPECT_FALSE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_ZeroSize)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {std::byte{0x90}};
    Logger &logger = Logger::get_instance();

    auto result = Memory::write_bytes(target.data(), source.data(), 0, logger);
    EXPECT_TRUE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_Large)
{
    std::vector<std::byte> target(1024, std::byte{0x00});
    std::vector<std::byte> source(512, std::byte{0xCC});

    Logger &logger = Logger::get_instance();

    auto result = Memory::write_bytes(target.data(), source.data(), source.size(), logger);
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

    std::vector<std::byte> source = {
        std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    Logger &logger = Logger::get_instance();

    auto result = Memory::write_bytes(target.data() + 10, source.data(), source.size(), logger);
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
    EXPECT_FALSE(memory_error_to_string(static_cast<MemoryError>(999)).empty());
}

TEST_F(MemoryTest, CacheExpiry)
{
    Memory::shutdown_cache();
    Memory::init_cache(64, 10);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
}

TEST_F(MemoryTest, CacheBehavior_Overlapping)
{
    Memory::shutdown_cache();
    Memory::init_cache(64, 10000);

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
    Memory::init_cache(2, 60000);

    void *mem1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mem2 = VirtualAlloc(reinterpret_cast<void *>(0), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
    Logger &logger = Logger::get_instance();
    std::byte source[] = {std::byte{0x90}};

    auto r1 = Memory::write_bytes(nullptr, source, 1, logger);
    EXPECT_FALSE(r1.has_value());
    EXPECT_EQ(r1.error(), MemoryError::NullTargetAddress);

    std::byte target[1] = {std::byte{0}};
    auto r2 = Memory::write_bytes(target, nullptr, 1, logger);
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), MemoryError::NullSourceBytes);
}

TEST_F(MemoryTest, write_bytes_ZeroBytes)
{
    Logger &logger = Logger::get_instance();
    std::byte target[4] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
    std::byte source[1] = {std::byte{0x00}};

    auto result = Memory::write_bytes(target, source, 0, logger);
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0xAA});
}

TEST_F(MemoryTest, write_bytes_Success)
{
    Logger &logger = Logger::get_instance();

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);
    std::byte source[] = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto result = Memory::write_bytes(target, source, 3, logger);
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0x90});
    EXPECT_EQ(target[1], std::byte{0x90});
    EXPECT_EQ(target[2], std::byte{0x90});

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsMemoryWritable_ValidWritable)
{
    Memory::shutdown_cache();
    Memory::init_cache(4, 60000);

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
    Logger &logger = Logger::get_instance();

    auto result = Memory::write_bytes(target, source, sizeof(source), logger);
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
    Memory::init_cache(32, 60000, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    Memory::invalidate_range(buffer, sizeof(buffer));

    std::string stats = Memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());
}

TEST_F(MemoryTest, InvalidateRangeNull)
{
    EXPECT_NO_THROW(Memory::invalidate_range(nullptr, 100));
    EXPECT_NO_THROW(Memory::invalidate_range(reinterpret_cast<const void *>(0x1000), 0));
}

TEST_F(MemoryTest, WriteBytesInvalidatesCache)
{
    Memory::shutdown_cache();
    Memory::init_cache(32, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);

    EXPECT_TRUE(Memory::is_readable(target, 64));
    EXPECT_TRUE(Memory::is_writable(target, 64));

    Logger &logger = Logger::get_instance();
    std::byte source[] = {std::byte{0x90}, std::byte{0x91}, std::byte{0x92}};
    auto result = Memory::write_bytes(target, source, sizeof(source), logger);
    EXPECT_TRUE(result.has_value());

    EXPECT_TRUE(Memory::is_readable(target, 64));
    EXPECT_TRUE(Memory::is_writable(target, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, InvalidateRangeDoesNotAffectOtherRegions)
{
    Memory::shutdown_cache();
    Memory::init_cache(32, 60000, 4);

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
        threads.emplace_back([iterations, i, &success_count]()
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
            } });
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
    Memory::init_cache(16, 5000, 4);

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
    Memory::init_cache(8, 60000, 4);

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
    Memory::init_cache(32, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    const int num_threads = 8;
    const int iterations = 50;
    std::atomic<int> success_count{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&]()
                             {
            for (int j = 0; j < iterations; ++j)
            {
                if (Memory::is_readable(mem, 64))
                {
                    success_count.fetch_add(1, std::memory_order_relaxed);
                }
            } });
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
    Memory::init_cache(16, 5000, 4);

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
    Memory::init_cache(16, 5000, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 5; ++i)
    {
        Memory::is_readable(buffer, sizeof(buffer));
    }

    Memory::clear_cache();

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("Hits: 0"), std::string::npos);
    EXPECT_NE(stats.find("Misses: 0"), std::string::npos);
}

TEST_F(MemoryTest, InvalidateRangeIncrementsCounter)
{
    Memory::shutdown_cache();
    Memory::init_cache(16, 60000, 4);

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
    Memory::init_cache(2, 60000, 1);

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
    Memory::init_cache(16, 10, 4);

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
    Memory::init_cache(16, 60000, 4);

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
    Memory::init_cache(16, DEFAULT_CACHE_EXPIRY_MS, 4);

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("Expiry: 50ms"), std::string::npos);
}

TEST_F(MemoryTest, OnDemandCleanupStatExists)
{
    Memory::shutdown_cache();
    Memory::init_cache(16, 100, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("OnDemandCleanups:"), std::string::npos);
}

TEST_F(MemoryTest, ClearCacheResetsOnDemandCleanupStat)
{
    Memory::shutdown_cache();
    Memory::init_cache(16, 100, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 5; ++i)
    {
        Memory::is_readable(buffer, sizeof(buffer));
    }

    Memory::clear_cache();

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("OnDemandCleanups: 0"), std::string::npos);
}

TEST_F(MemoryTest, ExpiredEntryTriggersReFetch)
{
    Memory::shutdown_cache();
    Memory::init_cache(16, 10, 4);

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
    Memory::init_cache(32, 60000, 1);

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
    Memory::init_cache(16, 5000, 4);

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("HardMax/Shard:"), std::string::npos);
}

TEST_F(MemoryTest, ShutdownWhileReadersActive)
{
    Memory::shutdown_cache();
    Memory::init_cache(32, 60000, 4);

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
        readers.emplace_back([&]()
                             {
            readers_entered.fetch_add(1, std::memory_order_release);
            while (keep_reading.load(std::memory_order_acquire))
            {
                // After shutdown, is_readable falls back to direct VirtualQuery
                Memory::is_readable(mem, 64);
            } });
    }

    // Wait until all readers are actively reading
    while (readers_entered.load(std::memory_order_acquire) < num_threads)
    {
        std::this_thread::yield();
    }

    // Shutdown on a separate thread while readers are still active.
    // shutdown_cache waits for s_activeReaders == 0 before destroying data.
    // Readers that re-enter after shutdown use direct VirtualQuery fallback.
    std::thread shutdown_thread([&]()
                                { Memory::shutdown_cache(); });

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
    Memory::init_cache();
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
    Memory::init_cache();
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
    Memory::init_cache();
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
    Memory::init_cache();
}

TEST_F(MemoryTest, NoCacheFallback_SizeOverflow)
{
    Memory::shutdown_cache();

    char buffer[1] = {0};
    EXPECT_FALSE(Memory::is_readable(buffer, SIZE_MAX));
    EXPECT_FALSE(Memory::is_writable(buffer, SIZE_MAX));

    // Re-init for TearDown
    Memory::init_cache();
}

TEST_F(MemoryTest, CacheRangeLookup_MidRegionHit)
{
    Memory::shutdown_cache();
    Memory::init_cache(32, 60000, 1);

    // Allocate a large region so VirtualQuery returns a base address that differs
    // from the queried address within the region
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
    Memory::init_cache(32, 60000, 1);

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
    // Address near the top of address space: address + size would overflow
    const void *near_end = reinterpret_cast<const void *>(UINTPTR_MAX - 4);
    EXPECT_FALSE(Memory::is_readable(near_end, 16));
}

TEST_F(MemoryTest, IsWritable_AddressOverflow)
{
    void *near_end = reinterpret_cast<void *>(UINTPTR_MAX - 4);
    EXPECT_FALSE(Memory::is_writable(near_end, 16));
}

TEST_F(MemoryTest, ShutdownCache_ConcurrentReaders)
{
    // Ensure shutdown waits for active readers to finish
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::atomic<bool> reader_started{false};
    std::atomic<bool> reader_done{false};

    // Start a reader thread that will be in-flight during shutdown
    std::thread reader([&]()
                       {
        reader_started.store(true);
        for (int i = 0; i < 100; ++i)
        {
            Memory::is_readable(mem, 4);
        }
        reader_done.store(true); });

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
    Memory::init_cache();
    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, IsReadable_NoCacheInitialized_OverflowGuard)
{
    Memory::shutdown_cache();

    // Without cache, direct VirtualQuery path also has overflow guard
    const void *near_end = reinterpret_cast<const void *>(UINTPTR_MAX - 4);
    EXPECT_FALSE(Memory::is_readable(near_end, 16));

    // Re-init for TearDown
    Memory::init_cache();
}
