#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
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
        Memory::clear_cache();
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

    // Allocate 3 distinct memory regions to exceed cache size
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
