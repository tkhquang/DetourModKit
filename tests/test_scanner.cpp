#include <gtest/gtest.h>
#include <vector>
#include <cstring>

#include "DetourModKit/scanner.hpp"

using namespace DetourModKit;

TEST(ScannerTest, parse_aob_valid)
{
    auto result = Scanner::parse_aob("48 8B 05 ?? ?? ?? ??");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 7);
}

TEST(ScannerTest, parse_aob_all_wildcards)
{
    auto result = Scanner::parse_aob("?? ?? ??");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3);
}

TEST(ScannerTest, parse_aob_empty)
{
    auto result = Scanner::parse_aob("");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, find_pattern_found)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[100] = std::byte{0x48};
    data[101] = std::byte{0x8B};
    data[102] = std::byte{0x05};

    auto pattern = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

TEST(ScannerTest, find_pattern_not_found)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    auto pattern = Scanner::parse_aob("AA BB CC DD");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_with_wildcard)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[50] = std::byte{0x48};
    data[51] = std::byte{0x8B};
    data[52] = std::byte{0x12};

    auto pattern = Scanner::parse_aob("48 8B ??");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 50);
}

TEST(ScannerTest, parse_aob_invalid_hex)
{
    auto result = Scanner::parse_aob("GG HH II");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_mixed_invalid)
{
    auto result = Scanner::parse_aob("48 GG 05");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_single_digit)
{
    auto result = Scanner::parse_aob("4 8 B");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_various_formats)
{
    auto result1 = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(result1.has_value());
    EXPECT_EQ(result1->size(), 3);

    auto result2 = Scanner::parse_aob("48   8B   05");
    ASSERT_TRUE(result2.has_value());
    EXPECT_EQ(result2->size(), 3);

    auto result3 = Scanner::parse_aob("48\t8B\t05");
    ASSERT_TRUE(result3.has_value());
    EXPECT_EQ(result3->size(), 3);
}

TEST(ScannerTest, parse_aob_lowercase)
{
    auto result = Scanner::parse_aob("48 8b 05 ff");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4);
}

TEST(ScannerTest, parse_aob_uppercase)
{
    auto result = Scanner::parse_aob("48 8B 05 FF");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4);
}

TEST(ScannerTest, parse_aob_only_wildcards)
{
    auto result1 = Scanner::parse_aob("?");
    EXPECT_TRUE(result1.has_value());

    auto result2 = Scanner::parse_aob("??");
    EXPECT_TRUE(result2.has_value());
}

TEST(ScannerTest, find_pattern_at_start)
{
    std::vector<std::byte> data = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x00}, std::byte{0x00}};

    auto pattern = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

TEST(ScannerTest, find_pattern_at_end)
{
    std::vector<std::byte> data = {
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};

    auto pattern = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 2);
}

TEST(ScannerTest, find_pattern_pattern_too_large)
{
    std::vector<std::byte> data = {
        std::byte{0x48}, std::byte{0x8B}};

    auto pattern = Scanner::parse_aob("48 8B 05 00 00 00 00");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_empty_data)
{
    std::vector<std::byte> data;

    auto pattern = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), 0, *pattern);

    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_single_byte)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0xCC};

    auto pattern = Scanner::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

TEST(ScannerTest, find_pattern_multiple_matches)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[50] = std::byte{0x90};
    data[51] = std::byte{0x90};
    data[100] = std::byte{0x90};
    data[101] = std::byte{0x90};
    data[200] = std::byte{0x90};
    data[201] = std::byte{0x90};

    auto pattern = Scanner::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 50);
}

TEST(ScannerTest, find_pattern_all_wildcard)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    auto pattern = Scanner::parse_aob("?? ?? ??");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

TEST(ScannerTest, find_pattern_wildcard_at_end)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[75] = std::byte{0x48};
    data[76] = std::byte{0x8B};
    data[77] = std::byte{0x99};

    auto pattern = Scanner::parse_aob("48 8B ??");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 75);
}

TEST(ScannerTest, find_pattern_wildcard_at_start)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[75] = std::byte{0x99};
    data[76] = std::byte{0x48};
    data[77] = std::byte{0x8B};

    auto pattern = Scanner::parse_aob("?? 48 8B");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 75);
}

TEST(ScannerTest, find_pattern_large_pattern)
{
    std::vector<std::byte> data(1024, std::byte{0x00});

    for (int i = 0; i < 16; ++i)
    {
        data[500 + i] = std::byte{static_cast<uint8_t>(i)};
    }

    auto pattern = Scanner::parse_aob("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 500);
}

TEST(ScannerTest, parse_aob_whitespace_only)
{
    auto result1 = Scanner::parse_aob("   ");
    EXPECT_FALSE(result1.has_value());

    auto result2 = Scanner::parse_aob("\t\t\t");
    EXPECT_FALSE(result2.has_value());

    auto result3 = Scanner::parse_aob(" \t \n ");
    EXPECT_FALSE(result3.has_value());
}

TEST(ScannerTest, find_pattern_null_address)
{
    auto pattern = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(static_cast<const std::byte *>(nullptr), 100, *pattern);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_empty_pattern)
{
    Scanner::CompiledPattern empty_pattern;
    std::vector<std::byte> data(256, std::byte{0x00});

    auto result = Scanner::find_pattern(data.data(), data.size(), empty_pattern);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, parse_aob_with_whitespace_padding)
{
    auto result = Scanner::parse_aob("  48 8B 05  ");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
}

TEST(ScannerTest, parse_aob_byte_values)
{
    auto result = Scanner::parse_aob("00 FF 80 7F");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4u);

    EXPECT_EQ(result->mask[0], std::byte{0xFF});
    EXPECT_EQ(result->mask[1], std::byte{0xFF});
    EXPECT_EQ(result->mask[2], std::byte{0xFF});
    EXPECT_EQ(result->mask[3], std::byte{0xFF});

    EXPECT_EQ(result->bytes[0], std::byte{0x00});
    EXPECT_EQ(result->bytes[1], std::byte{0xFF});
    EXPECT_EQ(result->bytes[2], std::byte{0x80});
    EXPECT_EQ(result->bytes[3], std::byte{0x7F});
}

TEST(ScannerTest, parse_aob_wildcard_mask)
{
    auto result = Scanner::parse_aob("48 ?? 05 ?");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4u);

    EXPECT_EQ(result->mask[0], std::byte{0xFF});
    EXPECT_EQ(result->mask[2], std::byte{0xFF});

    EXPECT_EQ(result->mask[1], std::byte{0x00});
    EXPECT_EQ(result->mask[3], std::byte{0x00});
}

TEST(ScannerTest, find_pattern_wildcard_before_start)
{
    std::vector<std::byte> data = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};

    auto pattern = Scanner::parse_aob("?? 48 8B");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 3);
}

TEST(ScannerTest, parse_aob_out_of_range)
{
    auto result = Scanner::parse_aob("1FF");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_invalid_argument)
{
    auto result = Scanner::parse_aob("?? GG ??");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, aob_pattern_empty)
{
    auto result = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->empty());
    EXPECT_EQ(result->size(), 3u);
}

TEST(ScannerTest, find_pattern_overlapping_matches)
{
    std::vector<std::byte> data = {
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto pattern = Scanner::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

TEST(ScannerTest, find_pattern_wildcard_middle_multiple_candidates)
{
    std::vector<std::byte> data = {
        std::byte{0x48}, std::byte{0xAA}, std::byte{0x05},
        std::byte{0x00},
        std::byte{0x48}, std::byte{0xBB}, std::byte{0x05}};

    auto pattern = Scanner::parse_aob("48 ?? 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

TEST(ScannerTest, find_pattern_memchr_boundary)
{
    std::vector<std::byte> data(64, std::byte{0x00});
    data[63] = std::byte{0xCC};

    auto pattern = Scanner::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 63);
}

TEST(ScannerTest, find_pattern_long_wildcard_prefix)
{
    std::vector<std::byte> data = {
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
        std::byte{0x44}, std::byte{0x55},
        std::byte{0x48}, std::byte{0x8B},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto pattern = Scanner::parse_aob("?? ?? ?? ?? ?? 48 8B");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);

    std::vector<std::byte> small = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x48}};

    auto result2 = Scanner::find_pattern(small.data(), small.size(), *pattern);
    EXPECT_EQ(result2, nullptr);
}

TEST(ScannerTest, find_pattern_anchor_selection)
{
    // Fill data with 0x00 (very common byte). Place a pattern where the first
    // non-wildcard is 0x00 but a later byte is rare (0x37). The smarter anchor
    // should still find the correct match by anchoring on the rare byte.
    std::vector<std::byte> data(512, std::byte{0x00});

    // Place the real match at offset 200: 00 37 00
    data[200] = std::byte{0x00};
    data[201] = std::byte{0x37};
    data[202] = std::byte{0x00};

    auto pattern = Scanner::parse_aob("00 37 00");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 200);
}

TEST(ScannerTest, parse_aob_invariant)
{
    auto result = Scanner::parse_aob("48 ?? 8B 05 ?? ??");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->bytes.size(), result->mask.size());

    auto single = Scanner::parse_aob("CC");
    ASSERT_TRUE(single.has_value());
    EXPECT_EQ(single->bytes.size(), single->mask.size());
}

TEST(ScannerTest, find_pattern_const_correctness)
{
    const std::vector<std::byte> data = {
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x00}, std::byte{0x00}};

    auto pattern = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 2);
}
