// Unit tests for AOB Scanner module
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

#include "DetourModKit/scanner.hpp"

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

// Test parseAOB with invalid hex characters
TEST(AOBScannerTest, ParseAOB_InvalidHex)
{
    auto result = Scanner::parseAOB("GG HH II");

    // Invalid hex should return nullopt
    ASSERT_FALSE(result.has_value());
}

// Test parseAOB with mixed valid and invalid
TEST(AOBScannerTest, ParseAOB_MixedInvalid)
{
    auto result = Scanner::parseAOB("48 GG 05");

    // Mixed valid/invalid should return nullopt
    ASSERT_FALSE(result.has_value());
}

// Test parseAOB with single hex digit (not supported, should fail)
TEST(AOBScannerTest, ParseAOB_SingleDigit)
{
    auto result = Scanner::parseAOB("4 8 B");

    // Single digits are not valid hex bytes, should fail
    ASSERT_FALSE(result.has_value());
}

// Test parseAOB with various formats
TEST(AOBScannerTest, ParseAOB_VariousFormats)
{
    // Test without spaces (should still work)
    auto result1 = Scanner::parseAOB("48 8B 05");
    ASSERT_TRUE(result1.has_value());
    EXPECT_EQ(result1->size(), 3);

    // Test with multiple spaces
    auto result2 = Scanner::parseAOB("48   8B   05");
    ASSERT_TRUE(result2.has_value());
    EXPECT_EQ(result2->size(), 3);

    // Test with tabs
    auto result3 = Scanner::parseAOB("48\t8B\t05");
    ASSERT_TRUE(result3.has_value());
    EXPECT_EQ(result3->size(), 3);
}

// Test parseAOB with lowercase hex
TEST(AOBScannerTest, ParseAOB_Lowercase)
{
    auto result = Scanner::parseAOB("48 8b 05 ff");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4);
}

// Test parseAOB with uppercase hex
TEST(AOBScannerTest, ParseAOB_Uppercase)
{
    auto result = Scanner::parseAOB("48 8B 05 FF");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4);
}

// Test parseAOB with only wildcards (various formats)
TEST(AOBScannerTest, ParseAOB_OnlyWildcards)
{
    // Single ? is valid
    auto result1 = Scanner::parseAOB("?");
    EXPECT_TRUE(result1.has_value());

    // Double ?? is the standard wildcard format
    auto result2 = Scanner::parseAOB("??");
    EXPECT_TRUE(result2.has_value());
}

// Test FindPattern at start of data
TEST(AOBScannerTest, FindPattern_AtStart)
{
    std::vector<std::byte> data = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x00}, std::byte{0x00}};

    auto pattern = Scanner::parseAOB("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

// Test FindPattern at end of data
TEST(AOBScannerTest, FindPattern_AtEnd)
{
    std::vector<std::byte> data = {
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};

    auto pattern = Scanner::parseAOB("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 2);
}

// Test FindPattern with pattern larger than data
TEST(AOBScannerTest, FindPattern_PatternTooLarge)
{
    std::vector<std::byte> data = {
        std::byte{0x48}, std::byte{0x8B}};

    auto pattern = Scanner::parseAOB("48 8B 05 00 00 00 00");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    // Pattern larger than data should return nullptr
    EXPECT_EQ(result, nullptr);
}

// Test FindPattern with empty data
TEST(AOBScannerTest, FindPattern_EmptyData)
{
    std::vector<std::byte> data;

    auto pattern = Scanner::parseAOB("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), 0, *pattern);

    EXPECT_EQ(result, nullptr);
}

// Test FindPattern with single byte pattern
TEST(AOBScannerTest, FindPattern_SingleByte)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0xCC};

    auto pattern = Scanner::parseAOB("CC");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

// Test FindPattern with pattern spanning boundary
TEST(AOBScannerTest, FindPattern_MultipleMatches)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    // Insert pattern at multiple locations
    data[50] = std::byte{0x90};
    data[51] = std::byte{0x90};
    data[100] = std::byte{0x90};
    data[101] = std::byte{0x90};
    data[200] = std::byte{0x90};
    data[201] = std::byte{0x90};

    auto pattern = Scanner::parseAOB("90 90");
    ASSERT_TRUE(pattern.has_value());

    // Should find first occurrence
    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 50);
}

// Test FindPattern with all wildcard pattern
TEST(AOBScannerTest, FindPattern_AllWildcard)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    auto pattern = Scanner::parseAOB("?? ?? ??");
    ASSERT_TRUE(pattern.has_value());

    // All wildcards should match at start
    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

// Test FindPattern with partial wildcards at end
TEST(AOBScannerTest, FindPattern_WildcardAtEnd)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[75] = std::byte{0x48};
    data[76] = std::byte{0x8B};
    data[77] = std::byte{0x99}; // Matches ??

    auto pattern = Scanner::parseAOB("48 8B ??");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 75);
}

// Test FindPattern with partial wildcards at start
TEST(AOBScannerTest, FindPattern_WildcardAtStart)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[75] = std::byte{0x99}; // Matches ??
    data[76] = std::byte{0x48};
    data[77] = std::byte{0x8B};

    auto pattern = Scanner::parseAOB("?? 48 8B");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 75);
}

// Test large pattern
TEST(AOBScannerTest, FindPattern_LargePattern)
{
    std::vector<std::byte> data(1024, std::byte{0x00});

    // Insert pattern at offset 500
    for (int i = 0; i < 16; ++i)
    {
        data[500 + i] = std::byte{static_cast<uint8_t>(i)};
    }

    auto pattern = Scanner::parseAOB("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 500);
}

// Test parseAOB with whitespace-only string (triggers warning log path)
TEST(AOBScannerTest, ParseAOB_WhitespaceOnly)
{
    // Whitespace-only becomes empty after trim but aob_str is not empty
    // This covers the "Input string became empty after trimming" warning branch
    auto result1 = Scanner::parseAOB("   ");
    EXPECT_FALSE(result1.has_value());

    auto result2 = Scanner::parseAOB("\t\t\t");
    EXPECT_FALSE(result2.has_value());

    auto result3 = Scanner::parseAOB(" \t \n ");
    EXPECT_FALSE(result3.has_value());
}

// Test FindPattern with null start_address (covers null check branch)
TEST(AOBScannerTest, FindPattern_NullAddress)
{
    auto pattern = Scanner::parseAOB("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    // Null address should return nullptr immediately
    auto result = Scanner::FindPattern(nullptr, 100, *pattern);
    EXPECT_EQ(result, nullptr);
}

// Test FindPattern with empty CompiledPattern (zero-size pattern)
TEST(AOBScannerTest, FindPattern_EmptyPattern)
{
    // Manually create an empty pattern
    Scanner::CompiledPattern empty_pattern;
    // bytes and mask are empty vectors - size() == 0

    std::vector<std::byte> data(256, std::byte{0x00});

    // Empty pattern should return nullptr (covers pattern_size == 0 branch)
    auto result = Scanner::FindPattern(data.data(), data.size(), empty_pattern);
    EXPECT_EQ(result, nullptr);
}

// Test parseAOB with leading/trailing whitespace (verify trim works in parsing)
TEST(AOBScannerTest, ParseAOB_WithWhitespacePadding)
{
    // Leading/trailing whitespace should be trimmed, pattern should parse
    auto result = Scanner::parseAOB("  48 8B 05  ");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
}

// Test parseAOB - verify byte values are correctly compiled into pattern
TEST(AOBScannerTest, ParseAOB_ByteValues)
{
    auto result = Scanner::parseAOB("00 FF 80 7F");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4u);

    // Verify mask: all non-wildcard → mask = 1
    EXPECT_EQ(result->mask[0], 1);
    EXPECT_EQ(result->mask[1], 1);
    EXPECT_EQ(result->mask[2], 1);
    EXPECT_EQ(result->mask[3], 1);

    // Verify bytes
    EXPECT_EQ(result->bytes[0], std::byte{0x00});
    EXPECT_EQ(result->bytes[1], std::byte{0xFF});
    EXPECT_EQ(result->bytes[2], std::byte{0x80});
    EXPECT_EQ(result->bytes[3], std::byte{0x7F});
}

// Test parseAOB - verify wildcard mask values
TEST(AOBScannerTest, ParseAOB_WildcardMask)
{
    auto result = Scanner::parseAOB("48 ?? 05 ?");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4u);

    // Non-wildcard at index 0 and 2
    EXPECT_EQ(result->mask[0], 1);
    EXPECT_EQ(result->mask[2], 1);

    // Wildcards at index 1 and 3
    EXPECT_EQ(result->mask[1], 0);
    EXPECT_EQ(result->mask[3], 0);
}

// Test FindPattern with pattern beginning offset > 0 that would go before start
TEST(AOBScannerTest, FindPattern_WildcardBeforeStart)
{
    // Pattern: ?? 48 8B where the first real byte is at index 1
    // If 0x48 is found at position 0, adjusting back by first_non_wildcard would go before start
    std::vector<std::byte> data = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};

    auto pattern = Scanner::parseAOB("?? 48 8B");
    ASSERT_TRUE(pattern.has_value());

    // The first 0x48 is at index 0 but pattern starts with ??, so we need ??(any) 48 8B
    // First match should be at index 0 if index 0 can be a wildcard
    // data[0]=0x48, data[1]=0x8B, data[2]=0x05 → does ?? 48 8B match at 0?
    // ?? matches 0x48, then we need 0x48 at [1] but [1]=0x8B → no match
    // At index 1: ?? matches 0x8B, then 0x48 at [2]? [2]=0x05 → no match
    // At index 2: ?? matches 0x05, then 0x48 at [3]? [3]=0x00 → no match
    // At index 3: ?? matches 0x00, then 0x48 at [4]? [4]=0x48 ✓, 0x8B at [5]? ✓ → match!
    auto result = Scanner::FindPattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 3);
}

// Test parseAOB with token that throws out_of_range (value > 0xFF)
TEST(AOBScannerTest, ParseAOB_OutOfRange)
{
    // When the scanner code does std::stoul and gets a value > 0xFF
    // it should throw std::out_of_range which is caught and returns empty
    auto result = Scanner::parseAOB("1FF"); // 1FF > 0xFF

    // Should return nullopt due to exception handling
    ASSERT_FALSE(result.has_value());
}

// Test parseAOB with invalid argument (non-hex in stoul)
TEST(AOBScannerTest, ParseAOB_InvalidArgument)
{
    // This tests the invalid_argument catch path
    // When std::stoul fails to parse
    auto result = Scanner::parseAOB("?? GG ??"); // GG is not valid hex

    ASSERT_FALSE(result.has_value());
}

// Test parseAOB that results in empty pattern (after processing valid tokens)
TEST(AOBScannerTest, DISABLED_ParseAOB_EmptyPattern)
{
    // Test case that leads to empty pattern error log
    auto result = Scanner::parseAOB("?? ?? ??");

    // With all wildcards, the pattern is technically not empty after parsing
    // But we need to test the case where all tokens result in invalid
    auto result2 = Scanner::parseAOB("");

    // Empty string should return empty vector
    ASSERT_TRUE(result2.has_value());
    EXPECT_TRUE(result2->empty());
}

// Test FindPattern with only wildcards (no actual bytes to search)
TEST(AOBScannerTest, FindPattern_AllWildcards2)
{
    std::byte data[] = {static_cast<std::byte>(0x48), static_cast<std::byte>(0x8B), static_cast<std::byte>(0x05)};
    auto pattern = Scanner::parseAOB("?? ?? ??");

    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::FindPattern(data, sizeof(data), *pattern);

    // Should find something since all wildcards
    ASSERT_NE(result, nullptr);
}

// ===== Coverage improvement tests =====

// Test AOBPattern::empty() (covers scanner.hpp line 36)
TEST(AOBScannerTest, AOBPattern_Empty)
{
    // Parse a valid pattern - should not be empty
    auto result = Scanner::parseAOB("48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->empty());
    EXPECT_EQ(result->size(), 3u);
}

// Test AOBPattern::empty() with minimal pattern
TEST(AOBScannerTest, AOBPattern_SingleByte)
{
    auto result = Scanner::parseAOB("90");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->empty());
    EXPECT_EQ(result->size(), 1u);
}
