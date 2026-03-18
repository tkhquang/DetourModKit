// Unit tests for AOB Scanner module
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

#include "DetourModKit/aob_scanner.hpp"

using namespace DetourModKit;

// Test parseAOB with valid pattern
TEST(AOBScannerTest, ParseAOB_Valid)
{
    // "48 8B 05 ?? ?? ?? ??" has 7 tokens: 48, 8B, 05, ??, ??, ??, ??
    auto result = Scanner::parseAOB("48 8B 05 ?? ?? ?? ??");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 7);
}

// Test parseAOB with all wildcards
TEST(AOBScannerTest, ParseAOB_AllWildcards)
{
    auto result = Scanner::parseAOB("?? ?? ??");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3);
}

// Test parseAOB with empty string
TEST(AOBScannerTest, ParseAOB_Empty)
{
    auto result = Scanner::parseAOB("");

    // Empty string returns std::nullopt (not a valid pattern)
    ASSERT_FALSE(result.has_value());
}

// Test FindPattern - pattern found
TEST(AOBScannerTest, FindPattern_Found)
{
    // Create test data with known pattern
    std::vector<std::byte> data(256, std::byte{0x00});

    // Insert pattern at offset 100: 48 8B 05 (like in a typical instruction)
    data[100] = std::byte{0x48};
    data[101] = std::byte{0x8B};
    data[102] = std::byte{0x05};

    auto pattern = Scanner::parseAOB("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

// Test FindPattern - pattern not found
TEST(AOBScannerTest, FindPattern_NotFound)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    auto pattern = Scanner::parseAOB("AA BB CC DD");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    EXPECT_EQ(result, nullptr);
}

// Test FindPattern with wildcard
TEST(AOBScannerTest, FindPattern_WithWildcard)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    // Insert pattern with wildcard at offset 50: 48 8B ??
    data[50] = std::byte{0x48};
    data[51] = std::byte{0x8B};
    data[52] = std::byte{0x12}; // This matches ??

    auto pattern = Scanner::parseAOB("48 8B ??");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 50);
}
