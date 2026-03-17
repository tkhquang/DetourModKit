// Unit tests for Memory utilities module
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

#include "DetourModKit/memory_utils.hpp"
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
};

// Test initMemoryCache
TEST_F(MemoryUtilsTest, InitMemoryCache)
{
    // Should return false on second call (already initialized)
    bool result = Memory::initMemoryCache();
    EXPECT_FALSE(result);
}

// Test clearMemoryCache
TEST_F(MemoryUtilsTest, ClearMemoryCache)
{
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

// Test isMemoryReadable with invalid address
TEST_F(MemoryUtilsTest, IsMemoryReadable_Invalid)
{
    // Try to read from nullptr - should return false
    bool result = Memory::isMemoryReadable(nullptr, 100);
    EXPECT_FALSE(result);
}

// Test isMemoryWritable with valid stack memory
TEST_F(MemoryUtilsTest, IsMemoryWritable_Valid)
{
    char buffer[100] = {0};

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

// Test WriteBytes
TEST_F(MemoryUtilsTest, WriteBytes)
{
    // Allocate some writable memory on the stack
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};

    Logger &logger = Logger::getInstance();

    bool result = Memory::WriteBytes(target.data(), source.data(), source.size(), logger);
    EXPECT_TRUE(result);

    // Verify the bytes were written
    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }
}
