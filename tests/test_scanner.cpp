#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <span>

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

// windows.h included after project headers to avoid macro conflicts (e.g., 'small')
#include <windows.h>
#ifdef small
#undef small
#endif

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

// --- Pipe offset marker ---

TEST(ScannerTest, parse_aob_offset_marker)
{
    auto result = Scanner::parse_aob("48 8B 88 B8 00 00 00 | 48 89 4C 24 68");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 12u);
    EXPECT_EQ(result->offset, 7u);
    EXPECT_EQ(result->bytes[0], std::byte{0x48});
    EXPECT_EQ(result->bytes[7], std::byte{0x48});
}

TEST(ScannerTest, parse_aob_offset_marker_at_start)
{
    auto result = Scanner::parse_aob("| 48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
    EXPECT_EQ(result->offset, 0u);
}

TEST(ScannerTest, parse_aob_offset_marker_at_end)
{
    auto result = Scanner::parse_aob("48 8B 05 |");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
    EXPECT_EQ(result->offset, 3u);
}

TEST(ScannerTest, parse_aob_no_offset_marker)
{
    auto result = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0u);
}

TEST(ScannerTest, parse_aob_multiple_offset_markers_fails)
{
    auto result = Scanner::parse_aob("48 | 8B | 05");
    EXPECT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_offset_marker_with_wildcards)
{
    auto result = Scanner::parse_aob("?? ?? | 48 8B ??");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 5u);
    EXPECT_EQ(result->offset, 2u);
}

TEST(ScannerTest, find_pattern_with_offset_marker)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0xAA};
    data[51] = std::byte{0xBB};
    data[52] = std::byte{0xCC};
    data[53] = std::byte{0xDD};

    auto pattern = Scanner::parse_aob("AA BB | CC DD");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 50);

    // The caller can use result + pattern->offset to get the marked position
    EXPECT_EQ((result + pattern->offset) - data.data(), 52);
}

// --- Nth-occurrence matching ---

TEST(ScannerTest, find_pattern_nth_occurrence_first)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0x90};
    data[51] = std::byte{0x90};
    data[100] = std::byte{0x90};
    data[101] = std::byte{0x90};

    auto pattern = Scanner::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern, 1);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 50);
}

TEST(ScannerTest, find_pattern_nth_occurrence_second)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0x90};
    data[51] = std::byte{0x90};
    data[100] = std::byte{0x90};
    data[101] = std::byte{0x90};

    auto pattern = Scanner::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern, 2);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

TEST(ScannerTest, find_pattern_nth_occurrence_third)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[30] = std::byte{0xAB};
    data[31] = std::byte{0xCD};
    data[80] = std::byte{0xAB};
    data[81] = std::byte{0xCD};
    data[200] = std::byte{0xAB};
    data[201] = std::byte{0xCD};

    auto pattern = Scanner::parse_aob("AB CD");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern, 3);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 200);
}

TEST(ScannerTest, find_pattern_nth_occurrence_not_enough)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0x90};
    data[51] = std::byte{0x90};

    auto pattern = Scanner::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern, 2);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_nth_occurrence_zero)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0x90};

    auto pattern = Scanner::parse_aob("90");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern, 0);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_nth_occurrence_with_offset)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[40] = std::byte{0xAA};
    data[41] = std::byte{0xBB};
    data[42] = std::byte{0xCC};
    data[100] = std::byte{0xAA};
    data[101] = std::byte{0xBB};
    data[102] = std::byte{0xCC};

    auto pattern = Scanner::parse_aob("AA | BB CC");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern, 2);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
    EXPECT_EQ((result + pattern->offset) - data.data(), 101);
}

TEST(ScannerTest, find_pattern_nth_occurrence_with_overlap)
{
    std::vector<std::byte> data = {
        std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA}};

    auto pattern = Scanner::parse_aob("AA AA");
    ASSERT_TRUE(pattern.has_value());

    auto r1 = Scanner::find_pattern(data.data(), data.size(), *pattern, 1);
    ASSERT_NE(r1, nullptr);
    EXPECT_EQ(r1 - data.data(), 0);

    auto r2 = Scanner::find_pattern(data.data(), data.size(), *pattern, 2);
    ASSERT_NE(r2, nullptr);
    EXPECT_EQ(r2 - data.data(), 1);

    auto r3 = Scanner::find_pattern(data.data(), data.size(), *pattern, 3);
    ASSERT_NE(r3, nullptr);
    EXPECT_EQ(r3 - data.data(), 2);

    auto r4 = Scanner::find_pattern(data.data(), data.size(), *pattern, 4);
    EXPECT_EQ(r4, nullptr);
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

TEST(ScannerTest, find_pattern_sse2_path_exact_16_bytes)
{
    std::vector<std::byte> data(512, std::byte{0x00});

    for (int i = 0; i < 16; ++i)
    {
        data[200 + i] = std::byte{static_cast<uint8_t>(0x10 + i)};
    }

    auto pattern = Scanner::parse_aob("10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->size(), 16u);

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 200);
}

TEST(ScannerTest, find_pattern_sse2_path_with_wildcards)
{
    std::vector<std::byte> data(512, std::byte{0x00});

    for (int i = 0; i < 20; ++i)
    {
        data[100 + i] = std::byte{static_cast<uint8_t>(0x30 + i)};
    }

    auto pattern = Scanner::parse_aob("30 31 ?? 33 34 35 ?? 37 38 39 3A 3B 3C 3D ?? 3F 40 41 42 43");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->size(), 20u);

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

TEST(ScannerTest, find_pattern_sse2_path_not_found)
{
    std::vector<std::byte> data(512, std::byte{0x00});

    for (int i = 0; i < 16; ++i)
    {
        data[200 + i] = std::byte{static_cast<uint8_t>(0x10 + i)};
    }

    auto pattern = Scanner::parse_aob("10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E FF");
    ASSERT_TRUE(pattern.has_value());

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);

    EXPECT_EQ(result, nullptr);
}

class ScannerRipTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(Memory::init_cache());
    }

    void TearDown() override
    {
        Memory::shutdown_cache();
    }
};

TEST_F(ScannerRipTest, resolve_rip_relative_positive_displacement)
{
    // MOV RAX, [RIP+0x12345678]  =>  48 8B 05 78 56 34 12
    std::vector<std::byte> code = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12}};

    auto result = Scanner::resolve_rip_relative(code.data(), 3, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + 0x12345678;
    EXPECT_EQ(*result, expected);
}

TEST_F(ScannerRipTest, resolve_rip_relative_negative_displacement)
{
    // MOV RAX, [RIP-0x10]  =>  48 8B 05 F0 FF FF FF
    std::vector<std::byte> code = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0xF0}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    auto result = Scanner::resolve_rip_relative(code.data(), 3, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + static_cast<uintptr_t>(static_cast<intptr_t>(-16));
    EXPECT_EQ(*result, expected);
}

TEST_F(ScannerRipTest, resolve_rip_relative_zero_displacement)
{
    std::vector<std::byte> code = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::resolve_rip_relative(code.data(), 3, 7);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, reinterpret_cast<uintptr_t>(code.data()) + 7);
}

TEST_F(ScannerRipTest, resolve_rip_relative_call_rel32)
{
    // CALL rel32  =>  E8 10 00 00 00
    std::vector<std::byte> code = {
        std::byte{0xE8},
        std::byte{0x10}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::resolve_rip_relative(code.data(), 1, 5);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 5 + 0x10;
    EXPECT_EQ(*result, expected);
}

TEST_F(ScannerRipTest, resolve_rip_relative_null_address)
{
    auto result = Scanner::resolve_rip_relative(nullptr, 3, 7);

    EXPECT_FALSE(result.has_value());
}

TEST_F(ScannerRipTest, find_and_resolve_mov_rax_rip)
{
    // Padding + MOV RAX, [RIP+0x00000020]
    std::vector<std::byte> code = {
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, // NOP padding
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, // MOV RAX, [RIP+disp32]
        std::byte{0x20}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x90}, std::byte{0x90}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_MOV_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t instr_addr = reinterpret_cast<uintptr_t>(&code[3]);
    EXPECT_EQ(*result, instr_addr + 7 + 0x20);
}

TEST_F(ScannerRipTest, find_and_resolve_lea_rax_rip)
{
    // LEA RAX, [RIP+0x100]
    std::vector<std::byte> code = {
        std::byte{0x48}, std::byte{0x8D}, std::byte{0x05},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_LEA_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + 0x100;
    EXPECT_EQ(*result, expected);
}

TEST_F(ScannerRipTest, find_and_resolve_call_rel32)
{
    std::vector<std::byte> code = {
        std::byte{0x55}, // PUSH RBP
        std::byte{0xE8}, // CALL rel32
        std::byte{0xFF}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x90}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    uintptr_t instr_addr = reinterpret_cast<uintptr_t>(&code[1]);
    EXPECT_EQ(*result, instr_addr + 5 + 0xFF);
}

TEST_F(ScannerRipTest, find_and_resolve_jmp_rel32)
{
    std::vector<std::byte> code = {
        std::byte{0xE9},
        std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_JMP_REL32, 5);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 5 + 0x05;
    EXPECT_EQ(*result, expected);
}

TEST_F(ScannerRipTest, find_and_resolve_prefix_not_found)
{
    // Region large enough for prefix + disp32 but contains no matching prefix
    std::vector<std::byte> code = {
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_MOV_RAX_RIP, 7);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::PrefixNotFound);
}

TEST_F(ScannerRipTest, find_and_resolve_null_start)
{
    auto result = Scanner::find_and_resolve_rip_relative(
        nullptr, 100,
        Scanner::PREFIX_MOV_RAX_RIP, 7);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::NullInput);
}

TEST_F(ScannerRipTest, find_and_resolve_region_too_small)
{
    std::vector<std::byte> code = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};

    // Region is smaller than prefix + disp32
    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_MOV_RAX_RIP, 7);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::RegionTooSmall);
}

TEST_F(ScannerRipTest, find_and_resolve_first_match_wins)
{
    // Two MOV RAX, [RIP+disp32] with different displacements
    std::vector<std::byte> code = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x10}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x20}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_MOV_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + 0x10;
    EXPECT_EQ(*result, expected);
}

TEST_F(ScannerRipTest, find_and_resolve_partial_prefix_no_false_match)
{
    // 48 8B followed by wrong third byte, then the real prefix
    std::vector<std::byte> code = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x0D}, // MOV RCX, not RAX
        std::byte{0xFF}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, // MOV RAX
        std::byte{0x30}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_MOV_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t instr_addr = reinterpret_cast<uintptr_t>(&code[7]);
    EXPECT_EQ(*result, instr_addr + 7 + 0x30);
}

TEST_F(ScannerRipTest, resolve_rip_relative_custom_instruction_form)
{
    // MOVSS XMM0, [RIP+disp32] => F3 0F 10 05 <disp32>  (prefix_len=4, instr_len=8)
    std::vector<std::byte> code = {
        std::byte{0xF3}, std::byte{0x0F}, std::byte{0x10}, std::byte{0x05},
        std::byte{0x40}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::resolve_rip_relative(code.data(), 4, 8);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 8 + 0x40;
    EXPECT_EQ(*result, expected);
}

TEST_F(ScannerRipTest, find_and_resolve_empty_prefix)
{
    std::vector<std::byte> code = {std::byte{0x90}};
    std::span<const std::byte> empty;

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(), empty, 5);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::NullInput);
}

TEST_F(ScannerRipTest, resolve_rip_relative_null_input)
{
    auto result = Scanner::resolve_rip_relative(nullptr, 3, 7);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::NullInput);
}

TEST_F(ScannerRipTest, rip_resolve_error_to_string_coverage)
{
    EXPECT_FALSE(rip_resolve_error_to_string(RipResolveError::NullInput).empty());
    EXPECT_FALSE(rip_resolve_error_to_string(RipResolveError::PrefixNotFound).empty());
    EXPECT_FALSE(rip_resolve_error_to_string(RipResolveError::RegionTooSmall).empty());
    EXPECT_FALSE(rip_resolve_error_to_string(RipResolveError::UnreadableDisplacement).empty());
}

TEST_F(ScannerRipTest, find_and_resolve_prefix_at_boundary)
{
    // Prefix starts at the last valid position
    std::vector<std::byte> code = {
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0xE8},
        std::byte{0x0A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    uintptr_t instr_addr = reinterpret_cast<uintptr_t>(&code[3]);
    EXPECT_EQ(*result, instr_addr + 5 + 0x0A);
}

TEST_F(ScannerRipTest, find_and_resolve_mov_rcx_rip)
{
    std::vector<std::byte> code = {
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x0D},
        std::byte{0x50}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_MOV_RCX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + 0x50;
    EXPECT_EQ(*result, expected);
}

// --- Tests for scan_executable_regions ---

TEST(ScannerExecRegionTest, FindsPatternInExecutableMemory)
{
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0xCC, 4096);

    // 16-byte pattern unlikely to appear elsewhere in process memory
    const std::byte sig[] = {
        std::byte{0x7A}, std::byte{0x3F}, std::byte{0xE1}, std::byte{0x9C},
        std::byte{0x42}, std::byte{0xB8}, std::byte{0x05}, std::byte{0xD7},
        std::byte{0x6E}, std::byte{0xA3}, std::byte{0x11}, std::byte{0x8F},
        std::byte{0x54}, std::byte{0xC6}, std::byte{0x29}, std::byte{0x70}};
    std::memcpy(&bytes[256], sig, sizeof(sig));

    auto pattern = Scanner::parse_aob("7A 3F E1 9C 42 B8 05 D7 6E A3 11 8F 54 C6 29 70");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = Scanner::scan_executable_regions(*pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &bytes[256]);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerExecRegionTest, ReturnsNullForNoMatch)
{
    // Pattern unlikely to exist in any executable page
    auto pattern = Scanner::parse_aob("FE ED FA CE DE AD BE EF CA FE BA BE 01 02 03 04");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = Scanner::scan_executable_regions(*pattern);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerExecRegionTest, EmptyPattern)
{
    Scanner::CompiledPattern empty;
    const std::byte *result = Scanner::scan_executable_regions(empty);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerExecRegionTest, ZeroOccurrence)
{
    auto pattern = Scanner::parse_aob("CC CC CC");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = Scanner::scan_executable_regions(*pattern, 0);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerExecRegionTest, NthOccurrence)
{
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0x00, 4096);

    // 16-byte unique pattern placed at two offsets within our page
    const std::byte sig[] = {
        std::byte{0xB1}, std::byte{0x4D}, std::byte{0xF8}, std::byte{0xA2},
        std::byte{0x63}, std::byte{0xC9}, std::byte{0x07}, std::byte{0xE5},
        std::byte{0x3A}, std::byte{0x96}, std::byte{0x1B}, std::byte{0xD4},
        std::byte{0x58}, std::byte{0x0E}, std::byte{0x7C}, std::byte{0x2F}};
    std::memcpy(&bytes[100], sig, sizeof(sig));
    std::memcpy(&bytes[500], sig, sizeof(sig));

    auto pattern = Scanner::parse_aob("B1 4D F8 A2 63 C9 07 E5 3A 96 1B D4 58 0E 7C 2F");
    ASSERT_TRUE(pattern.has_value());

    const auto *region_start = reinterpret_cast<const std::byte *>(exec_mem);
    const auto *region_end = region_start + 4096;

    const std::byte *first = Scanner::scan_executable_regions(*pattern, 1);
    ASSERT_NE(first, nullptr);
    EXPECT_GE(first, region_start);
    EXPECT_LT(first, region_end);
    EXPECT_EQ(first, &bytes[100]);

    const std::byte *second = Scanner::scan_executable_regions(*pattern, 2);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second, &bytes[500]);

    // Third occurrence should not exist
    const std::byte *third = Scanner::scan_executable_regions(*pattern, 3);
    EXPECT_EQ(third, nullptr);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerExecRegionTest, SkipsNonExecutableMemory)
{
    void *rw_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(rw_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(rw_mem);
    std::memset(bytes, 0x00, 4096);

    const std::byte sig[] = {
        std::byte{0xF0}, std::byte{0x0D}, std::byte{0xCA}, std::byte{0xFE},
        std::byte{0x91}, std::byte{0x3E}, std::byte{0x7B}, std::byte{0xA5},
        std::byte{0xD2}, std::byte{0x48}, std::byte{0x16}, std::byte{0xC3},
        std::byte{0x6A}, std::byte{0xEF}, std::byte{0x04}, std::byte{0x87}};
    std::memcpy(&bytes[0], sig, sizeof(sig));

    auto pattern = Scanner::parse_aob("F0 0D CA FE 91 3E 7B A5 D2 48 16 C3 6A EF 04 87");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = Scanner::scan_executable_regions(*pattern);
    EXPECT_EQ(result, nullptr);

    VirtualFree(rw_mem, 0, MEM_RELEASE);
}

TEST(ScannerExecRegionTest, RespectsPatternOffset)
{
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0xCC, 4096);

    // Unique 12-byte pattern with offset marker after byte 4
    bytes[200] = std::byte{0xD3};
    bytes[201] = std::byte{0x7A};
    bytes[202] = std::byte{0xE9};
    bytes[203] = std::byte{0x15};
    bytes[204] = std::byte{0x82};
    bytes[205] = std::byte{0xF6};
    bytes[206] = std::byte{0x4B};
    bytes[207] = std::byte{0xC0};
    bytes[208] = std::byte{0x37};
    bytes[209] = std::byte{0xA1};
    bytes[210] = std::byte{0x5E};
    bytes[211] = std::byte{0x94};

    auto pattern = Scanner::parse_aob("D3 7A E9 15 | 82 F6 4B C0 37 A1 5E 94");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 4u);

    const std::byte *result = Scanner::scan_executable_regions(*pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &bytes[204]);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerExecRegionTest, SkipsGuardPages)
{
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0x00, 4096);

    const std::byte sig[] = {
        std::byte{0xC7}, std::byte{0x3B}, std::byte{0xA0}, std::byte{0xD9},
        std::byte{0x14}, std::byte{0x6F}, std::byte{0xE2}, std::byte{0x85},
        std::byte{0x4C}, std::byte{0x01}, std::byte{0x7D}, std::byte{0xF3},
        std::byte{0xA8}, std::byte{0x56}, std::byte{0x2E}, std::byte{0xBB}};
    std::memcpy(&bytes[0], sig, sizeof(sig));

    DWORD old_protect;
    VirtualProtect(exec_mem, 4096, PAGE_EXECUTE_READ | PAGE_GUARD, &old_protect);

    auto pattern = Scanner::parse_aob("C7 3B A0 D9 14 6F E2 85 4C 01 7D F3 A8 56 2E BB");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = Scanner::scan_executable_regions(*pattern);
    EXPECT_EQ(result, nullptr);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerStringTest, RipResolveErrorToString_IsNoexcept)
{
    static_assert(noexcept(rip_resolve_error_to_string(RipResolveError::NullInput)));
    static_assert(noexcept(rip_resolve_error_to_string(RipResolveError::PrefixNotFound)));
    static_assert(noexcept(rip_resolve_error_to_string(RipResolveError::RegionTooSmall)));
    static_assert(noexcept(rip_resolve_error_to_string(RipResolveError::UnreadableDisplacement)));
}

TEST(ScannerTest, find_pattern_common_byte_anchoring)
{
    // Patterns containing common x64 opcodes (0x00, 0xCC, 0x90, 0xFF, 0x48,
    // 0x8B, 0x89, 0x0F, 0xE8, 0xE9, 0x83, 0xC3) exercise byte-frequency
    // scoring in the anchor selection path.
    const std::byte data[] = {
        std::byte{0xCC}, std::byte{0xCC}, std::byte{0x48}, std::byte{0x8B},
        std::byte{0x05}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
        std::byte{0x90}, std::byte{0x90}, std::byte{0xC3}, std::byte{0x00},
        std::byte{0xFF}, std::byte{0xE8}, std::byte{0x83}, std::byte{0x0F},
        std::byte{0xE9}, std::byte{0x89}, std::byte{0x42}, std::byte{0x10}};

    // Search for a rare anchor byte (0x42) surrounded by common bytes
    const auto pattern = Scanner::parse_aob("89 42 10");
    ASSERT_TRUE(pattern.has_value());

    const auto *result = Scanner::find_pattern(data, sizeof(data), pattern.value());
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[17]);
}

TEST(ScannerTest, find_pattern_all_common_bytes_still_found)
{
    // Pattern made entirely of common opcodes (high frequency scores)
    const std::byte data[] = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0xCC}, std::byte{0x90},
        std::byte{0xFF}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x00}};

    const auto pattern = Scanner::parse_aob("CC 90 FF 48 8B");
    ASSERT_TRUE(pattern.has_value());

    const auto *result = Scanner::find_pattern(data, sizeof(data), pattern.value());
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[2]);
}

// --- SIMD level detection ---

TEST(ScannerTest, active_simd_level_returns_valid_tier)
{
    const auto level = Scanner::active_simd_level();
    // Must be one of the three defined tiers
    EXPECT_TRUE(level == Scanner::SimdLevel::Scalar ||
                level == Scanner::SimdLevel::Sse2 ||
                level == Scanner::SimdLevel::Avx2);

    // On x86-64, SSE2 is guaranteed at minimum
#if defined(__x86_64__) || defined(_M_X64)
    EXPECT_GE(static_cast<int>(level), static_cast<int>(Scanner::SimdLevel::Sse2));
#endif
}

TEST(ScannerTest, active_simd_level_is_deterministic)
{
    // Runtime detection is cached; repeated calls must return the same value
    const auto a = Scanner::active_simd_level();
    const auto b = Scanner::active_simd_level();
    EXPECT_EQ(a, b);
}

TEST(ScannerTest, active_simd_level_print)
{
    // Diagnostic: prints the active tier so CI logs confirm which path ran.
    // Not a correctness assertion -- purely informational.
    const auto level = Scanner::active_simd_level();
    const char *names[] = {"Scalar", "SSE2", "AVX2"};
    std::printf("[  DIAG   ] Scanner SIMD level: %s\n", names[static_cast<int>(level)]);
}

// --- AVX2 path tests (32+ byte patterns) ---
// Correctness tests for patterns that exercise the AVX2 verification tier.
// active_simd_level() above confirms whether AVX2 is actually in use.

TEST(ScannerTest, find_pattern_avx2_path_exact_32_bytes)
{
    // 32-byte pattern: one full AVX2 iteration, no SSE2/scalar tail
    std::vector<std::byte> data(64, std::byte{0x00});
    for (size_t i = 16; i < 48; ++i)
        data[i] = static_cast<std::byte>(i & 0xFF);

    std::string aob;
    for (size_t i = 16; i < 48; ++i)
    {
        if (!aob.empty()) aob += ' ';
        aob += std::format("{:02X}", i & 0xFF);
    }

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 32u);

    const auto *result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[16]);
}

TEST(ScannerTest, find_pattern_avx2_path_48_bytes)
{
    // 48-byte pattern: one AVX2 iteration (32B) + one SSE2 iteration (16B)
    std::vector<std::byte> data(80, std::byte{0xAA});
    for (size_t i = 8; i < 56; ++i)
        data[i] = static_cast<std::byte>((i * 7) & 0xFF);

    std::string aob;
    for (size_t i = 8; i < 56; ++i)
    {
        if (!aob.empty()) aob += ' ';
        aob += std::format("{:02X}", (i * 7) & 0xFF);
    }

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 48u);

    const auto *result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[8]);
}

TEST(ScannerTest, find_pattern_avx2_path_64_bytes)
{
    // 64-byte pattern: two full AVX2 iterations
    std::vector<std::byte> data(128, std::byte{0x00});
    for (size_t i = 32; i < 96; ++i)
        data[i] = static_cast<std::byte>(i & 0xFF);

    std::string aob;
    for (size_t i = 32; i < 96; ++i)
    {
        if (!aob.empty()) aob += ' ';
        aob += std::format("{:02X}", i & 0xFF);
    }

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 64u);

    const auto *result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[32]);
}

TEST(ScannerTest, find_pattern_avx2_path_with_wildcards)
{
    // 32-byte pattern with wildcards at AVX2-significant positions
    std::vector<std::byte> data(64, std::byte{0x00});
    for (size_t i = 0; i < 64; ++i)
        data[i] = static_cast<std::byte>(i & 0xFF);

    // Pattern: first 32 bytes with wildcards at positions 4, 12, 20, 28
    std::string aob;
    for (size_t i = 16; i < 48; ++i)
    {
        if (!aob.empty()) aob += ' ';
        if ((i - 16) % 8 == 4)
            aob += "??";
        else
            aob += std::format("{:02X}", i & 0xFF);
    }

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 32u);

    const auto *result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[16]);
}

TEST(ScannerTest, find_pattern_avx2_path_mismatch_in_second_chunk)
{
    // 64-byte pattern where the first 32 bytes match but the second 32 don't
    std::vector<std::byte> data(128, std::byte{0x00});
    for (size_t i = 0; i < 128; ++i)
        data[i] = static_cast<std::byte>(i & 0xFF);

    std::string aob;
    for (size_t i = 32; i < 96; ++i)
    {
        if (!aob.empty()) aob += ' ';
        aob += std::format("{:02X}", i & 0xFF);
    }

    // Corrupt byte 65 in the data so second AVX2 chunk fails
    data[65] = std::byte{0xFE};

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto *result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_avx2_path_not_found)
{
    // 32-byte pattern not present in the data
    std::vector<std::byte> data(128, std::byte{0xBB});

    std::string aob;
    for (int i = 0; i < 32; ++i)
    {
        if (!aob.empty()) aob += ' ';
        aob += std::format("{:02X}", i);
    }

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto *result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    EXPECT_EQ(result, nullptr);
}
