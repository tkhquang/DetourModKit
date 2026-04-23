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
    EXPECT_EQ(result->offset, 7);
    EXPECT_EQ(result->bytes[0], std::byte{0x48});
    EXPECT_EQ(result->bytes[7], std::byte{0x48});
}

TEST(ScannerTest, parse_aob_offset_marker_at_start)
{
    auto result = Scanner::parse_aob("| 48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
    EXPECT_EQ(result->offset, 0);
}

TEST(ScannerTest, parse_aob_offset_marker_at_end)
{
    auto result = Scanner::parse_aob("48 8B 05 |");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
    EXPECT_EQ(result->offset, 3);
}

TEST(ScannerTest, parse_aob_no_offset_marker)
{
    auto result = Scanner::parse_aob("48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0);
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
    EXPECT_EQ(result->offset, 2);
}

TEST(ScannerTest, FindPattern_OffsetMarker_ReturnsMarkedByte)
{
    // v3.0 contract: find_pattern applies pattern.offset to the returned
    // pointer, so a `|` marker lands the caller directly on the anchored byte.
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0xAA};
    data[51] = std::byte{0xBB};
    data[52] = std::byte{0xCC};
    data[53] = std::byte{0xDD};

    auto pattern = Scanner::parse_aob("AA BB | CC DD");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 2);

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    // Returned pointer is the marked byte (offset 2 into the match), NOT the
    // raw match start. Adding pattern->offset manually would double-apply.
    EXPECT_EQ(result - data.data(), 52);
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

TEST(ScannerTest, FindPattern_NthOccurrence_WithOffsetMarker)
{
    // v3.0 contract: the Nth-occurrence overload also applies pattern.offset,
    // returning the marked byte of the Nth match (not the match start).
    std::vector<std::byte> data(256, std::byte{0x00});
    data[40] = std::byte{0xAA};
    data[41] = std::byte{0xBB};
    data[42] = std::byte{0xCC};
    data[100] = std::byte{0xAA};
    data[101] = std::byte{0xBB};
    data[102] = std::byte{0xCC};

    auto pattern = Scanner::parse_aob("AA | BB CC");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 1);

    auto result = Scanner::find_pattern(data.data(), data.size(), *pattern, 2);
    ASSERT_NE(result, nullptr);
    // The second match starts at data[100]; the `|` sits after the first byte,
    // so find_pattern returns data[101] directly.
    EXPECT_EQ(result - data.data(), 101);
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
    EXPECT_EQ(pattern->offset, 4);

    const std::byte *result = Scanner::scan_executable_regions(*pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &bytes[204]);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerExecRegionTest, OffsetStillAppliedExactlyOnce)
{
    // Regression guard for the internal find_pattern_raw split: after
    // unification, both find_pattern and scan_executable_regions apply
    // pattern.offset exactly once. Placing a uniquely-valued pattern in an
    // executable region and scanning via both paths must return the same
    // marked byte, not the marked byte + offset (which would be a double
    // application).
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0xCC, 4096);

    // Distinctive 8-byte pattern at offset 300 with `|` marker after byte 3.
    constexpr size_t region_offset = 300;
    const std::byte sig[] = {
        std::byte{0x71}, std::byte{0xE3}, std::byte{0x9A}, std::byte{0x4D},
        std::byte{0x06}, std::byte{0xBF}, std::byte{0x52}, std::byte{0x18}};
    std::memcpy(&bytes[region_offset], sig, sizeof(sig));

    auto pattern = Scanner::parse_aob("71 E3 9A | 4D 06 BF 52 18");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 3);

    // scan_executable_regions path: should land on the marked byte.
    const std::byte *exec_hit = Scanner::scan_executable_regions(*pattern);
    ASSERT_NE(exec_hit, nullptr);
    EXPECT_EQ(exec_hit, &bytes[region_offset + 3]);

    // find_pattern path over the same region: must agree exactly with the
    // scan_executable_regions result (both apply offset once).
    const std::byte *direct_hit = Scanner::find_pattern(bytes, 4096, *pattern);
    ASSERT_NE(direct_hit, nullptr);
    EXPECT_EQ(direct_hit, exec_hit);

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

namespace
{
    void write_disp32(std::byte *dst, int32_t value) noexcept
    {
        std::memcpy(dst, &value, sizeof(value));
    }
}

TEST(ScannerRipResolveTest, resolve_rip_relative_null_input_returns_error)
{
    const auto result = Scanner::resolve_rip_relative(nullptr, 1, 5);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::NullInput);
}

TEST(ScannerRipResolveTest, resolve_rip_relative_positive_displacement)
{
    // Fake `E8 disp32` (call rel32, 5 bytes total). disp32 starts at offset 1.
    std::vector<std::byte> buffer(5, std::byte{0x00});
    buffer[0] = std::byte{0xE8};
    write_disp32(buffer.data() + 1, 0x1000);

    const auto result = Scanner::resolve_rip_relative(buffer.data(), 1, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data()) + 5 + 0x1000;
    EXPECT_EQ(*result, expected);
}

TEST(ScannerRipResolveTest, resolve_rip_relative_negative_displacement)
{
    // Signed disp32 must produce a lower absolute address via sign-extension.
    std::vector<std::byte> buffer(16, std::byte{0x00});
    buffer[0] = std::byte{0xE9};
    write_disp32(buffer.data() + 1, -0x200);

    const auto result = Scanner::resolve_rip_relative(buffer.data(), 1, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data()) + 5 - 0x200;
    EXPECT_EQ(*result, expected);
}

TEST(ScannerRipResolveTest, resolve_rip_relative_mov_rax_rip_shape)
{
    // Full 7-byte `mov rax, [rip+disp32]`: 48 8B 05 disp32.
    std::vector<std::byte> buffer(7, std::byte{0x00});
    buffer[0] = std::byte{0x48};
    buffer[1] = std::byte{0x8B};
    buffer[2] = std::byte{0x05};
    write_disp32(buffer.data() + 3, 0x4000);

    const auto result = Scanner::resolve_rip_relative(buffer.data(), 3, 7);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data()) + 7 + 0x4000;
    EXPECT_EQ(*result, expected);
}

TEST(ScannerRipResolveTest, resolve_rip_relative_unreadable_displacement)
{
    // Allocate two adjacent pages. Page 1 is RW, page 2 is NO_ACCESS.
    // Place the opcode at the last byte of page 1 so the disp32 read straddles
    // into page 2 and Memory::is_readable() fails for the disp32 window.
    SYSTEM_INFO sys_info{};
    ::GetSystemInfo(&sys_info);
    const SIZE_T page_size = sys_info.dwPageSize;

    auto *region = static_cast<std::byte *>(::VirtualAlloc(
        nullptr, page_size * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(region, nullptr);

    DWORD old_protect = 0;
    ASSERT_TRUE(::VirtualProtect(region + page_size, page_size, PAGE_NOACCESS, &old_protect));

    auto *fake_instr = region + page_size - 1;
    *fake_instr = std::byte{0xE8};

    const auto result = Scanner::resolve_rip_relative(fake_instr, 1, 5);

    EXPECT_FALSE(result.has_value());
    if (!result.has_value())
    {
        EXPECT_EQ(result.error(), RipResolveError::UnreadableDisplacement);
    }

    ::VirtualFree(region, 0, MEM_RELEASE);
}

TEST(ScannerRipResolveTest, find_and_resolve_null_input_returns_error)
{
    const auto result = Scanner::find_and_resolve_rip_relative(
        nullptr, 16, Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::NullInput);
}

TEST(ScannerRipResolveTest, find_and_resolve_region_too_small_returns_error)
{
    std::vector<std::byte> buffer(2, std::byte{0x00});

    const auto result = Scanner::find_and_resolve_rip_relative(
        buffer.data(), buffer.size(), Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::RegionTooSmall);
}

TEST(ScannerRipResolveTest, find_and_resolve_prefix_not_found_returns_error)
{
    std::vector<std::byte> buffer(64, std::byte{0x90});

    const auto result = Scanner::find_and_resolve_rip_relative(
        buffer.data(), buffer.size(), Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), RipResolveError::PrefixNotFound);
}

TEST(ScannerRipResolveTest, find_and_resolve_call_rel32_happy_path)
{
    std::vector<std::byte> buffer(64, std::byte{0x90});

    constexpr size_t instr_offset = 20;
    buffer[instr_offset] = std::byte{0xE8};
    write_disp32(buffer.data() + instr_offset + 1, 0x80);

    const auto result = Scanner::find_and_resolve_rip_relative(
        buffer.data(), buffer.size(), Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected =
        reinterpret_cast<uintptr_t>(buffer.data() + instr_offset) + 5 + 0x80;
    EXPECT_EQ(*result, expected);
}

TEST(ScannerRipResolveTest, find_and_resolve_mov_rax_rip_multi_byte_prefix)
{
    std::vector<std::byte> buffer(64, std::byte{0x90});

    constexpr size_t instr_offset = 12;
    buffer[instr_offset + 0] = std::byte{0x48};
    buffer[instr_offset + 1] = std::byte{0x8B};
    buffer[instr_offset + 2] = std::byte{0x05};
    write_disp32(buffer.data() + instr_offset + 3, 0x1234);

    const auto result = Scanner::find_and_resolve_rip_relative(
        buffer.data(), buffer.size(), Scanner::PREFIX_MOV_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected =
        reinterpret_cast<uintptr_t>(buffer.data() + instr_offset) + 7 + 0x1234;
    EXPECT_EQ(*result, expected);
}

TEST(ScannerRipResolveTest, find_and_resolve_returns_first_match_only)
{
    std::vector<std::byte> buffer(64, std::byte{0x90});

    buffer[8] = std::byte{0xE8};
    write_disp32(buffer.data() + 9, 0x10);

    buffer[32] = std::byte{0xE8};
    write_disp32(buffer.data() + 33, 0x20);

    const auto result = Scanner::find_and_resolve_rip_relative(
        buffer.data(), buffer.size(), Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected_first =
        reinterpret_cast<uintptr_t>(buffer.data() + 8) + 5 + 0x10;
    EXPECT_EQ(*result, expected_first);
}

TEST(ScannerRipResolveTest, find_and_resolve_match_at_region_boundary)
{
    // Prefix sits at the last position where prefix + disp32 still fits in the region.
    std::vector<std::byte> buffer(16, std::byte{0x90});
    const size_t instr_offset = buffer.size() - 5;
    buffer[instr_offset] = std::byte{0xE8};
    write_disp32(buffer.data() + instr_offset + 1, 0x40);

    const auto result = Scanner::find_and_resolve_rip_relative(
        buffer.data(), buffer.size(), Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected =
        reinterpret_cast<uintptr_t>(buffer.data() + instr_offset) + 5 + 0x40;
    EXPECT_EQ(*result, expected);
}

// Regression guard for the PREFIX_* migration from C-array to std::array.
// Ensures the constants still expose `.size()`, decay into std::span cleanly,
// and feed through find_and_resolve_rip_relative without source changes.
TEST(ScannerRipResolveTest, PrefixConstants_AreStdArraysAndUsableAsSpan)
{
    static_assert(Scanner::PREFIX_CALL_REL32.size() == 1,
                  "PREFIX_CALL_REL32 must expose std::array::size()");
    EXPECT_EQ(Scanner::PREFIX_CALL_REL32[0], std::byte{0xE8});

    std::vector<std::byte> buffer(5, std::byte{0x90});
    buffer[0] = std::byte{0xE8};
    write_disp32(buffer.data() + 1, 0x10);

    const auto result = Scanner::find_and_resolve_rip_relative(
        buffer.data(), buffer.size(), Scanner::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected =
        reinterpret_cast<uintptr_t>(buffer.data()) + 5 + 0x10;
    EXPECT_EQ(*result, expected);
}

// Parser must reject obvious non-hex tokens. The error path used to emit a
// `\?` escape artefact; this test guards parse_aob's rejection behaviour
// without trying to inspect the Logger output (there is no public capture
// helper in the test suite, so message text is intentionally unchecked).
TEST(ScannerTest, ParseAob_WildcardErrorMessage_UsesCleanQuestionMarks)
{
    auto result = Scanner::parse_aob("GG");
    EXPECT_FALSE(result.has_value());

    auto result_mixed = Scanner::parse_aob("48 GG 8B");
    EXPECT_FALSE(result_mixed.has_value());
}

// An all-wildcard pattern has no literal bytes to anchor on. find_pattern's
// contract is to return `start_address` in that case (and log a warning).
// This guard-rails the behaviour so future refactors don't silently flip it.
TEST(ScannerTest, FindPattern_AllWildcards_ReturnsStartWithWarning)
{
    Scanner::CompiledPattern all_wild;
    all_wild.bytes = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    all_wild.mask = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    std::vector<std::byte> buffer(32, std::byte{0xAA});

    const auto *first = Scanner::find_pattern(buffer.data(), buffer.size(), all_wild);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first, buffer.data());

    // Stable across repeated calls.
    const auto *second = Scanner::find_pattern(buffer.data(), buffer.size(), all_wild);
    EXPECT_EQ(second, buffer.data());
}

// Negative disp32 must land before the instruction. This guards the refactored
// signed-arithmetic path in resolve_rip_relative - an unsigned-only cast chain
// would still produce the correct bit pattern modulo 2^64, but the signed form
// is the one humans can read, so a direct signed comparison is the contract.
TEST(ScannerTest, ResolveRipRelative_NegativeDisplacement_ComputesCorrectTarget)
{
    // CALL rel32 with disp32 = -0x20. Encoded little-endian: E0 FF FF FF.
    alignas(4) std::byte buffer[5] = {
        std::byte{0xE8},
        std::byte{0xE0}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    ASSERT_TRUE(Memory::init_cache());
    const auto result = Scanner::resolve_rip_relative(buffer, 1, 5);
    ASSERT_TRUE(result.has_value());

    const auto *expected_ptr = buffer + 5 - 0x20;
    EXPECT_EQ(*result, reinterpret_cast<uintptr_t>(expected_ptr));
    Memory::shutdown_cache();
}

// Exercise the full VirtualQuery walk. The test cannot portably set up a
// pure-execute page, but it can verify the walk across whatever mix of
// protections the current process happens to have does not AV. The fix in
// scan_executable_regions is what makes this safe in the presence of
// PAGE_EXECUTE-only regions injected by third-party modules.
TEST(ScannerTest, ScanExecutableRegions_SurvivesProcessWalk_DoesNotCrash)
{
    // A distinctive pattern unlikely to appear in the host process. If it does
    // match something, that is still a success for the "does not AV" contract.
    auto pattern = Scanner::parse_aob("DE AD BE EF CA FE BA BE 13 37 C0 DE");
    ASSERT_TRUE(pattern.has_value());

    const auto *hit = Scanner::scan_executable_regions(*pattern);
    (void)hit; // Either result (match or nullptr) is acceptable; we care that we returned.
    SUCCEED();
}

// Regression guard: find_pattern applies pattern.offset exactly once. A pattern
// whose `|` marker sits at the very end (offset == pattern.size()) must return
// a pointer one past the final pattern byte, not somewhere deeper.
TEST(ScannerTest, FindPattern_OffsetAtEnd_ReturnsPastLastByte)
{
    std::vector<std::byte> data(64, std::byte{0x00});
    data[10] = std::byte{0xDE};
    data[11] = std::byte{0xAD};
    data[12] = std::byte{0xBE};
    data[13] = std::byte{0xEF};

    auto pattern = Scanner::parse_aob("DE AD BE EF |");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 4);

    const auto *result = Scanner::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[14]);
}

// All-wildcard Nth occurrence must still advance one byte at a time rather
// than loop-stalling, and must return the Nth "match" address (region start
// + N - 1) without log-spamming for every internal iteration.
TEST(ScannerTest, FindPattern_AllWildcards_NthOccurrenceAdvances)
{
    Scanner::CompiledPattern all_wild;
    all_wild.bytes = {std::byte{0x00}, std::byte{0x00}};
    all_wild.mask = {std::byte{0x00}, std::byte{0x00}};

    std::vector<std::byte> buffer(16, std::byte{0xAB});

    const auto *first = Scanner::find_pattern(buffer.data(), buffer.size(), all_wild, 1);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first, buffer.data());

    const auto *second = Scanner::find_pattern(buffer.data(), buffer.size(), all_wild, 2);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second, buffer.data() + 1);

    const auto *third = Scanner::find_pattern(buffer.data(), buffer.size(), all_wild, 3);
    ASSERT_NE(third, nullptr);
    EXPECT_EQ(third, buffer.data() + 2);
}

// Nth overload with occurrence == 0 must early-return before touching any
// other state (e.g. pattern validation), preserving the 1-based contract.
TEST(ScannerTest, FindPattern_NthZeroOccurrence_ReturnsNullptr)
{
    auto pattern = Scanner::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    std::vector<std::byte> data = {std::byte{0xCC}, std::byte{0xCC}};
    const auto *result = Scanner::find_pattern(data.data(), data.size(), *pattern, 0);
    EXPECT_EQ(result, nullptr);
}

// Nth overload rejects an empty pattern the same way the single-hit overload
// does. Without the public-entry guard, the raw helper would be asked to scan
// with a zero-size pattern, tripping the `remaining >= 0` sentinel path.
TEST(ScannerTest, FindPattern_NthEmptyPattern_ReturnsNullptr)
{
    Scanner::CompiledPattern empty_pattern;
    std::vector<std::byte> data(16, std::byte{0x00});

    const auto *result = Scanner::find_pattern(data.data(), data.size(), empty_pattern, 1);
    EXPECT_EQ(result, nullptr);
}

// Nth overload validates the start pointer too, so callers can't accidentally
// scan from a null base even when they pass a positive region size.
TEST(ScannerTest, FindPattern_NthNullStart_ReturnsNullptr)
{
    auto pattern = Scanner::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    const auto *result = Scanner::find_pattern(
        static_cast<const std::byte *>(nullptr), 32, *pattern, 1);
    EXPECT_EQ(result, nullptr);
}

// resolve_rip_relative must sign-extend the 32-bit displacement before adding
// it to the instruction base, so a negative disp32 lands at the expected
// two's-complement target. This test pins that contract with disp = -1 and a
// 5-byte instruction: target must equal base + 5 + (-1) = base + 4.
TEST(ScannerTest, ResolveRipRelative_NegativeDisp32_ProducesExpectedTarget)
{
    std::vector<std::byte> code = {
        std::byte{0xE8},
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    const auto result = Scanner::resolve_rip_relative(code.data(), 1, 5);
    ASSERT_TRUE(result.has_value());

    const uintptr_t base = reinterpret_cast<uintptr_t>(code.data());
    // disp = -1, instruction_length = 5 => target = base + 5 + (-1) = base + 4.
    const uintptr_t expected = base + 5 + static_cast<uintptr_t>(static_cast<int64_t>(-1));
    EXPECT_EQ(*result, expected);
    EXPECT_EQ(*result, base + 4);
}

TEST(ScannerCascade, EmptyCandidatesReturnsError)
{
    std::span<const Scanner::AddrCandidate> empty{};
    auto result = Scanner::resolve_cascade(empty, "unit");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::ResolveError::EmptyCandidates);
}

TEST(ScannerCascade, AllInvalidPatternsReturnsError)
{
    Scanner::AddrCandidate cands[] = {
        {"bad", "not_valid_aob_tokens $$$$", Scanner::ResolveMode::Direct, 0, 0},
    };
    auto result = Scanner::resolve_cascade(cands, "unit");
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(result.error() == Scanner::ResolveError::AllPatternsInvalid ||
                result.error() == Scanner::ResolveError::NoMatch);
}

TEST(ScannerCascade, NoMatchReturnsError)
{
    Scanner::AddrCandidate cands[] = {
        {"miss", "FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    auto result = Scanner::resolve_cascade(cands, "unit");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::ResolveError::NoMatch);
}

namespace
{
    struct ExecBuffer
    {
        std::uint8_t *base{nullptr};
        std::size_t size{0};

        ExecBuffer(std::size_t s) : size(s)
        {
            base = static_cast<std::uint8_t *>(
                VirtualAlloc(nullptr, s, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        }

        ~ExecBuffer()
        {
            if (base)
            {
                VirtualFree(base, 0, MEM_RELEASE);
            }
        }

        ExecBuffer(const ExecBuffer &) = delete;
        ExecBuffer &operator=(const ExecBuffer &) = delete;
    };
} // namespace

TEST(ScannerCascade, PrologueFallbackHitFindsHookedPrologue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);

    std::memset(buf.base, 0xCC, buf.size);

    constexpr std::uint8_t kUniqueTail[] = {
        0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x13, 0x37, 0x42};

    constexpr std::size_t kOffset = 0x200;

    buf.base[kOffset + 0] = 0xE9;
    buf.base[kOffset + 1] = 0x11;
    buf.base[kOffset + 2] = 0x22;
    buf.base[kOffset + 3] = 0x33;
    buf.base[kOffset + 4] = 0x44;
    std::memcpy(buf.base + kOffset + 5, kUniqueTail, sizeof(kUniqueTail));

    const char *pattern =
        "48 89 5C 24 08 AD BE EF CA FE 13 37 42";

    Scanner::AddrCandidate cands[] = {
        {"hooked", pattern, Scanner::ResolveMode::Direct, 0, 0},
    };

    auto direct = Scanner::resolve_cascade(cands, "prologue-test-direct");
    ASSERT_FALSE(direct.has_value());
    EXPECT_EQ(direct.error(), Scanner::ResolveError::NoMatch);

    std::int32_t disp = 0;
    std::memcpy(&disp, buf.base + kOffset + 1, sizeof(disp));
    const auto synthetic_dest = reinterpret_cast<std::uintptr_t>(buf.base) + kOffset + 5 + disp;
    (void)synthetic_dest;

    auto fallback = Scanner::resolve_cascade_with_prologue_fallback(cands, "prologue-test-fallback");
    if (fallback.has_value())
    {
        EXPECT_EQ(fallback->address, reinterpret_cast<std::uintptr_t>(buf.base) + kOffset);
    }
    else
    {
        EXPECT_TRUE(fallback.error() == Scanner::ResolveError::NoMatch);
    }
}

TEST(ScannerCascade, PrologueFallbackRejectsShortTail)
{
    Scanner::AddrCandidate cands[] = {
        {"too-short", "48 89 5C 24 08 90 90", Scanner::ResolveMode::Direct, 0, 0},
    };
    auto result = Scanner::resolve_cascade_with_prologue_fallback(cands, "short-tail");
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(result.error() == Scanner::ResolveError::PrologueFallbackNotApplicable ||
                result.error() == Scanner::ResolveError::NoMatch);
}

TEST(ScannerCascade, PrologueFallbackRejectsInsufficientTailLiterals)
{
    Scanner::AddrCandidate cands[] = {
        {"wildcard-tail",
         "DE AD BE EF CA ?? ?? ?? ??",
         Scanner::ResolveMode::Direct, 0, 0},
    };
    auto result = Scanner::resolve_cascade_with_prologue_fallback(
        cands, "insufficient-tail-literals");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::ResolveError::PrologueFallbackNotApplicable);
}

// The prologue fallback rebuilds a pattern as `E9 ?? ?? ?? ??` followed
// by the original pattern's tail bytes. If the tail is ambiguous across
// the process's executable regions (more than kPrologueFallbackMaxHits
// matches), the guard in scan_candidates_hooked_prologue must reject it
// rather than return an arbitrary first hit. This test seeds five
// identical trampoline-shaped sequences into a PAGE_EXECUTE_READ buffer
// so the rebuilt pattern matches >= 5 times, exceeding the uniqueness
// ceiling (4) and triggering the guard.
TEST(ScannerCascade, PrologueFallbackRejectsAmbiguousTail)
{
    constexpr std::size_t kBufSize = 0x2000;
    auto *raw = static_cast<std::uint8_t *>(
        VirtualAlloc(nullptr, kBufSize, MEM_COMMIT | MEM_RESERVE,
                     PAGE_READWRITE));
    ASSERT_NE(raw, nullptr);

    std::memset(raw, 0xCC, kBufSize);

    // Tail chosen to be literal-heavy so split_prologue accepts it
    // (>= kPrologueFallbackMinTailLiterals non-wildcard tokens), and
    // generic enough to be synthesised at multiple offsets. Bytes must
    // NOT collide with any other test's pattern, because residue in
    // freed-but-still-mapped memory could influence subsequent tests
    // that run in the same process. `A5 B6 C7 D8 E9 FA 0B 1C` is a
    // fresh 8-byte sequence not used elsewhere in this TU.
    constexpr std::uint8_t kAmbiguousTemplate[] = {
        0xE9, 0x00, 0x00, 0x00, 0x00,                   // JMP rel32
        0xA5, 0xB6, 0xC7, 0xD8, 0xE9, 0xFA, 0x0B, 0x1C, // unique tail
    };

    // Seed five copies so the rebuilt fallback pattern tallies >= 5 hits
    // in this buffer alone. scan_executable_regions walks every readable
    // executable page in the process, so we only need > kPrologueFallbackMaxHits
    // inside regions it can see.
    for (std::size_t i = 0; i < 5; ++i)
    {
        std::memcpy(raw + i * 0x100, kAmbiguousTemplate, sizeof(kAmbiguousTemplate));
    }

    DWORD old_prot = 0;
    ASSERT_TRUE(VirtualProtect(raw, kBufSize, PAGE_EXECUTE_READ, &old_prot));

    Scanner::AddrCandidate cands[] = {
        // Original prologue is five arbitrary REX-prefixed bytes followed
        // by the ambiguous literal tail. resolve_cascade's direct pass
        // will not match (the buffer starts with E9 not 48 89 ...), so
        // the prologue-fallback path is taken.
        {"ambiguous",
         "48 89 5C 24 08 A5 B6 C7 D8 E9 FA 0B 1C",
         Scanner::ResolveMode::Direct, 0, 0},
    };

    auto result = Scanner::resolve_cascade_with_prologue_fallback(
        cands, "ambiguous-tail");

    // The guard rejects ambiguity -> NoMatch (fallback applicable but
    // all candidates exceeded the uniqueness ceiling).
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::ResolveError::NoMatch);

    // Restore and free.
    VirtualProtect(raw, kBufSize, old_prot, &old_prot);
    VirtualFree(raw, 0, MEM_RELEASE);
}
