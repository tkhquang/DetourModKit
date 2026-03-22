#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <span>

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

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

class ScannerRipTest : public ::testing::Test
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
    std::vector<std::byte> code = {
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto result = Scanner::find_and_resolve_rip_relative(
        code.data(), code.size(),
        Scanner::PREFIX_MOV_RAX_RIP, 7);

    EXPECT_FALSE(result.has_value());
}

TEST_F(ScannerRipTest, find_and_resolve_null_start)
{
    auto result = Scanner::find_and_resolve_rip_relative(
        nullptr, 100,
        Scanner::PREFIX_MOV_RAX_RIP, 7);

    EXPECT_FALSE(result.has_value());
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
