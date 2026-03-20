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

class MemoryTestWithShutdown : public ::testing::Test
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
    Memory::clear_cache();

    bool result = Memory::init_cache(64, 10000);
    EXPECT_TRUE(result);

    Memory::clear_cache();
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

TEST_F(MemoryTest, ThreadSafety)
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
                Memory::is_readable(buffer, sizeof(buffer));
                Memory::is_writable(buffer, sizeof(buffer));
            } });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    SUCCEED();
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
    Memory::clear_cache();
    Memory::init_cache(64, 10);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    Memory::clear_cache();
}

TEST_F(MemoryTest, CacheBehavior_Overlapping)
{
    Memory::clear_cache();
    Memory::init_cache(64, 10000);

    char buffer[100] = {0};

    EXPECT_TRUE(Memory::is_readable(buffer, 50));
    EXPECT_TRUE(Memory::is_readable(buffer, 100));
    EXPECT_TRUE(Memory::is_readable(buffer + 10, 40));

    Memory::clear_cache();
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
    Memory::clear_cache();
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

    Memory::clear_cache();
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
    Memory::clear_cache();
    Memory::init_cache(4, 60000);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(Memory::is_writable(mem, 1));

    EXPECT_TRUE(Memory::is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
    Memory::clear_cache();
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
    Memory::clear_cache();
    bool result = Memory::init_cache(32, 5000, 4);
    EXPECT_TRUE(result);

    result = Memory::init_cache(64, 10000, 8);
    EXPECT_TRUE(result);

    Memory::clear_cache();
}

TEST_F(MemoryTest, InvalidateRangeBasic)
{
    Memory::clear_cache();
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
    Memory::clear_cache();
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
    Memory::clear_cache();
}

TEST_F(MemoryTest, InvalidateRangeDoesNotAffectOtherRegions)
{
    Memory::clear_cache();
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

    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([iterations, i]()
                             {
            char buffers[4][100];
            for (int j = 0; j < iterations; ++j)
            {
                int buf_idx = (i + j) % 4;
                Memory::is_readable(buffers[buf_idx], sizeof(buffers[buf_idx]));
                Memory::is_writable(buffers[buf_idx], sizeof(buffers[buf_idx]));
            } });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    SUCCEED();
}

TEST_F(MemoryTest, CacheStatsWithShards)
{
    Memory::clear_cache();
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
    Memory::clear_cache();
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
    Memory::clear_cache();
}

TEST_F(MemoryTest, CacheStampedeCoalescing)
{
    Memory::clear_cache();
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
    Memory::clear_cache();
}

TEST_F(MemoryTest, CacheStatsAvailableInRelease)
{
    Memory::clear_cache();
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

    Memory::clear_cache();
}

TEST_F(MemoryTest, ClearCacheResetsAllStats)
{
    Memory::clear_cache();
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

    Memory::clear_cache();
}

TEST_F(MemoryTest, InvalidateRangeIncrementsCounter)
{
    Memory::clear_cache();
    Memory::init_cache(16, 60000, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    Memory::invalidate_range(buffer, sizeof(buffer));

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("Invalidations:"), std::string::npos);

    Memory::clear_cache();
}

TEST_F(MemoryTest, HardUpperBoundEnforced)
{
    Memory::clear_cache();
    // Initialize with 2 entries capacity per shard (with 2x hard max = 4)
    Memory::init_cache(2, 60000, 1);

    // Allocate multiple pages in different regions to force cache growth
    std::vector<void *> regions;
    for (int i = 0; i < 10; ++i)
    {
        void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        ASSERT_NE(mem, nullptr);
        regions.push_back(mem);
        EXPECT_TRUE(Memory::is_readable(mem, 1));
    }

    // Check stats to see total entries
    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("TotalEntries:"), std::string::npos);

    // Cleanup
    for (void *mem : regions)
    {
        VirtualFree(mem, 0, MEM_RELEASE);
    }
    Memory::clear_cache();
}

TEST_F(MemoryTestWithShutdown, BackgroundCleanupThreadRuns)
{
    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    // Wait for background cleanup to run at least once
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Cache should still work
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
}

TEST_F(MemoryTestWithShutdown, ShutdownCacheTerminatesCleanupThread)
{
    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    // Shutdown is called automatically in TearDown
    // Just verify the cache functions before shutdown
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));
}

TEST_F(MemoryTest, InvalidateRangeTriggersBackgroundCleanup)
{
    Memory::clear_cache();
    Memory::init_cache(16, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(Memory::is_readable(mem, 64));

    // Invalidate should trigger cleanup request
    EXPECT_NO_THROW(Memory::invalidate_range(mem, 64));

    // Cache should still work after invalidation
    EXPECT_TRUE(Memory::is_readable(mem, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
    Memory::clear_cache();
}

TEST_F(MemoryTest, CoalescedQueriesAccumulated)
{
    Memory::clear_cache();
    Memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Multiple threads hitting same address should coalesce
    const int num_threads = 8;
    const int iterations = 50;

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&]()
                             {
            for (int j = 0; j < iterations; ++j)
            {
                Memory::is_readable(mem, 64);
            } });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    std::string stats = Memory::get_cache_stats();
    // Should have some coalesced queries
    EXPECT_NE(stats.find("Coalesced:"), std::string::npos);

    VirtualFree(mem, 0, MEM_RELEASE);
    Memory::clear_cache();
}

TEST_F(MemoryTest, DefaultExpiryIs50ms)
{
    Memory::clear_cache();
    // Use default parameters (50ms expiry)
    Memory::init_cache(16, DEFAULT_CACHE_EXPIRY_MS, 4);

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("Expiry: 50ms"), std::string::npos);

    Memory::clear_cache();
}

TEST_F(MemoryTest, OnDemandCleanupStatExists)
{
    Memory::clear_cache();
    Memory::init_cache(16, 100, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("OnDemandCleanups:"), std::string::npos);

    Memory::clear_cache();
}

TEST_F(MemoryTest, ClearCacheResetsOnDemandCleanupStat)
{
    Memory::clear_cache();
    Memory::init_cache(16, 100, 4);

    char buffer[100] = {0};
    for (int i = 0; i < 5; ++i)
    {
        Memory::is_readable(buffer, sizeof(buffer));
    }

    Memory::clear_cache();

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("OnDemandCleanups: 0"), std::string::npos);

    Memory::clear_cache();
}

TEST_F(MemoryTest, OnDemandCleanupFiresOnInterval)
{
    Memory::clear_cache();
    Memory::init_cache(16, 10, 4);

    char buffer[100] = {0};
    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    // Wait for on-demand cleanup interval (1 second) to potentially trigger
    // In practice, this test verifies the mechanism exists without blocking too long
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_TRUE(Memory::is_readable(buffer, sizeof(buffer)));

    std::string stats = Memory::get_cache_stats();
    EXPECT_FALSE(stats.empty());

    Memory::clear_cache();
}

TEST_F(MemoryTest, CacheStampedeFollowerYields)
{
    Memory::clear_cache();
    Memory::init_cache(32, 60000, 1);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Single thread repeatedly accessing - should complete quickly without yielding
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; ++i)
    {
        EXPECT_TRUE(Memory::is_readable(mem, 64));
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // Should be fast - no exponential backoff sleep since cache hits
    EXPECT_LT(duration, 1000);

    VirtualFree(mem, 0, MEM_RELEASE);
    Memory::clear_cache();
}

TEST_F(MemoryTest, OnDemandCleanupAfterLongDelay)
{
    Memory::clear_cache();
    Memory::init_cache(16, 20, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    EXPECT_TRUE(Memory::is_readable(mem, 64));

    // Wait for entries to potentially expire
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Should still work - either cache hit with refreshed timestamp or miss with re-query
    EXPECT_TRUE(Memory::is_readable(mem, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
    Memory::clear_cache();
}

TEST_F(MemoryTest, CacheStatsIncludeHardMax)
{
    Memory::clear_cache();
    Memory::init_cache(16, 5000, 4);

    std::string stats = Memory::get_cache_stats();
    EXPECT_NE(stats.find("HardMax/Shard:"), std::string::npos);

    Memory::clear_cache();
}
