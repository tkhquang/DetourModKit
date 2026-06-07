#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

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

// parse_aob() must pre-populate CompiledPattern::anchor so find_pattern hits
// the cached fast path on the very first scan. The chosen index must point
// at a literal (non-wildcard) byte; the actual position is implementation
// defined but is documented to be the rarest literal byte.
TEST(ScannerTest, parse_aob_caches_anchor_index)
{
    // Every literal byte in the pattern below appears in the common-byte
    // frequency table EXCEPT 0x37, so 0x37 is the unambiguous winner. Using
    // a clean tie-free pattern keeps the test stable against future tweaks
    // to the frequency table or tie-break order.
    const auto pattern = Scanner::parse_aob("48 8B 89 37 0F E8 90 CC");
    ASSERT_TRUE(pattern.has_value());

    ASSERT_LT(pattern->anchor, pattern->size());
    EXPECT_EQ(pattern->mask[pattern->anchor], std::byte{0xFF});
    EXPECT_EQ(pattern->bytes[pattern->anchor], std::byte{0x37});
}

// An all-wildcard pattern produced through parse_aob() must mark the anchor
// as "no literal byte" (anchor == size()), short-circuiting find_pattern to
// its degenerate path without re-scanning the mask on every call.
TEST(ScannerTest, parse_aob_all_wildcards_anchor_equals_size)
{
    const auto pattern = Scanner::parse_aob("?? ?? ??");
    ASSERT_TRUE(pattern.has_value());

    EXPECT_EQ(pattern->anchor, pattern->size());
}

// compile_anchor() is the explicit hook for manually constructed patterns
// and must be safe to call repeatedly without drifting (idempotent).
TEST(ScannerTest, compile_anchor_is_idempotent_for_manual_patterns)
{
    Scanner::CompiledPattern manual;
    manual.bytes = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x37}, std::byte{0xFF}};
    manual.mask = {std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    manual.compile_anchor();
    const std::size_t first_anchor = manual.anchor;
    EXPECT_EQ(manual.bytes[first_anchor], std::byte{0x37});

    manual.compile_anchor();
    EXPECT_EQ(manual.anchor, first_anchor);
}

// Manually constructed patterns without a compile_anchor() call must still
// scan correctly: find_pattern_raw selects an anchor inline when the cached
// value is missing (sentinel). Without this fallback, the new caching path
// would crash on patterns built field-by-field in older consumer code.
TEST(ScannerTest, find_pattern_uncompiled_manual_pattern_still_matches)
{
    Scanner::CompiledPattern manual;
    manual.bytes = {std::byte{0x37}, std::byte{0x48}, std::byte{0x8B}};
    manual.mask = {std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};
    // Anchor deliberately left at its sentinel value.
    ASSERT_GT(manual.anchor, manual.size());

    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0x37};
    data[101] = std::byte{0x48};
    data[102] = std::byte{0x8B};

    const auto *result = Scanner::find_pattern(data.data(), data.size(), manual);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

// compile_anchor() on an empty pattern is well-defined: the selection loop
// has nothing to walk, so the anchor collapses to `size() == 0` (the same
// "no literal byte" encoding used for all-wildcard patterns). find_pattern
// short-circuits on `pattern_size == 0` before consulting the anchor, so
// this state never reaches the scan body; the test pins the boundary
// behaviour against accidental regressions.
TEST(ScannerTest, compile_anchor_empty_pattern_marks_no_anchor)
{
    Scanner::CompiledPattern empty;
    empty.compile_anchor();
    EXPECT_EQ(empty.anchor, empty.size());
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

// Mirror of the RIP mapper coverage above for the cascade ResolveError mapper.
// Every enumerator must map to a non-empty string, including InvalidRange, which
// the module-scoped resolvers return for a range whose valid() check fails.
TEST(ScannerCascade, resolve_error_to_string_coverage)
{
    EXPECT_FALSE(Scanner::resolve_error_to_string(Scanner::ResolveError::EmptyCandidates).empty());
    EXPECT_FALSE(Scanner::resolve_error_to_string(Scanner::ResolveError::NoMatch).empty());
    EXPECT_FALSE(Scanner::resolve_error_to_string(Scanner::ResolveError::AllPatternsInvalid).empty());
    EXPECT_FALSE(Scanner::resolve_error_to_string(Scanner::ResolveError::PrologueFallbackNotApplicable).empty());
    EXPECT_FALSE(Scanner::resolve_error_to_string(Scanner::ResolveError::InvalidRange).empty());
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

// --- Tests for scan_readable_regions ---

namespace
{
    // Writes a signature into dst and returns the matching AOB string. The AOB
    // is built as ASCII hex, a different byte sequence that cannot itself match
    // the binary signature. The step (37) is coprime to 256, so the generated
    // bytes are distinct for any run shorter than 256. marker_index, when
    // non-negative, inserts a `|` offset token before that byte.
    std::string write_signature(std::byte *dst, std::size_t count, std::uint8_t seed,
                                std::ptrdiff_t marker_index = -1)
    {
        static constexpr char hex_digits[] = "0123456789ABCDEF";
        std::string aob;
        aob.reserve(count * 4);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto value = static_cast<std::uint8_t>(
                seed + static_cast<std::uint8_t>(i) * 37u + 11u);
            dst[i] = static_cast<std::byte>(value);
            if (i != 0)
            {
                aob.push_back(' ');
            }
            if (marker_index >= 0 && static_cast<std::size_t>(marker_index) == i)
            {
                aob.append("| ");
            }
            aob.push_back(hex_digits[value >> 4]);
            aob.push_back(hex_digits[value & 0x0F]);
        }
        return aob;
    }

    // Enumerates the readable-memory occurrences of a pattern up to a cap.
    // scan_readable_regions sweeps the whole process, so a signature staged by a
    // test legitimately appears in more than one readable place: the target
    // buffer, plus any transient copy the optimizer leaves on the stack while
    // building it. (The compiled needle is excluded by the scanner itself.)
    // Tests therefore assert that the target address is among the occurrences,
    // not that it is the first one, which keeps them independent of memory
    // layout and optimizer behaviour across toolchains.
    std::vector<const std::byte *> collect_readable_hits(const Scanner::CompiledPattern &pattern)
    {
        constexpr std::size_t scan_cap = 64;
        std::vector<const std::byte *> hits;
        for (std::size_t occ = 1; occ <= scan_cap; ++occ)
        {
            const auto *hit = Scanner::scan_readable_regions(pattern, occ);
            if (hit == nullptr)
            {
                break;
            }
            hits.push_back(hit);
        }
        return hits;
    }

    bool hits_contain(const std::vector<const std::byte *> &hits, const std::byte *target)
    {
        return std::find(hits.begin(), hits.end(), target) != hits.end();
    }

    bool any_hit_in_range(const std::vector<const std::byte *> &hits,
                          const std::byte *lo, const std::byte *hi)
    {
        return std::any_of(hits.begin(), hits.end(),
                           [lo, hi](const std::byte *h)
                           { return h >= lo && h < hi; });
    }
} // namespace

TEST(ScannerReadableRegionTest, FindsPatternInReadOnlyMemory)
{
    // .rdata is mapped PAGE_READONLY: write the signature while writable, then
    // flip to read-only to model a real data section.
    void *ro_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(ro_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(ro_mem);
    std::memset(bytes, 0x00, 4096);

    const std::string aob = write_signature(&bytes[512], 16, 0x11);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(ro_mem, 4096, PAGE_READONLY, &old_protect));

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[512]));

    // The scanner skips the compiled pattern's own bytes buffer (the needle),
    // so that readable copy is never returned.
    EXPECT_FALSE(hits_contain(hits, pattern->bytes.data()));

    // The executable-only sweep must not reach a PAGE_READONLY region.
    EXPECT_EQ(Scanner::scan_executable_regions(*pattern), nullptr);

    VirtualFree(ro_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, FindsPatternInReadWriteData)
{
    void *rw_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(rw_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(rw_mem);
    std::memset(bytes, 0x00, 4096);

    const std::string aob = write_signature(&bytes[256], 16, 0x29);

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[256]));

    const std::byte *exec_hit = Scanner::scan_executable_regions(*pattern);
    EXPECT_EQ(exec_hit, nullptr);

    VirtualFree(rw_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, SupersetIncludesExecutableReadable)
{
    // PAGE_EXECUTE_READ is in both masks, so a pattern in executable-readable
    // memory must be found by the readable sweep as well as the executable one.
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0xCC, 4096);

    const std::string aob = write_signature(&bytes[128], 16, 0x3D);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(exec_mem, 4096, PAGE_EXECUTE_READ, &old_protect));

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[128]));

    // The executable buffer is the only executable copy (the needle and any
    // transient stack copy are not executable), so it is the first exec hit.
    const std::byte *exec_hit = Scanner::scan_executable_regions(*pattern);
    ASSERT_NE(exec_hit, nullptr);
    EXPECT_EQ(exec_hit, &bytes[128]);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, SkipsGuardPages)
{
    // A guarded read-only page reads as PAGE_READONLY | PAGE_GUARD; the guard
    // modifier must exclude it from the readable sweep, otherwise the first
    // touch raises STATUS_GUARD_PAGE_VIOLATION.
    void *guard_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(guard_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(guard_mem);
    std::memset(bytes, 0x00, 4096);

    const std::string aob = write_signature(&bytes[0], 16, 0x57);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(guard_mem, 4096, PAGE_READONLY | PAGE_GUARD, &old_protect));

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    // The guarded region must be skipped: no occurrence may fall inside it.
    // (Transient readable copies of the signature elsewhere are allowed.)
    const auto hits = collect_readable_hits(*pattern);
    EXPECT_FALSE(any_hit_in_range(hits, bytes, bytes + 4096));

    VirtualFree(guard_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, SkipsNoAccessPages)
{
    void *na_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(na_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(na_mem);
    std::memset(bytes, 0x00, 4096);

    const std::string aob = write_signature(&bytes[0], 16, 0x6B);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(na_mem, 4096, PAGE_NOACCESS, &old_protect));

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto hits = collect_readable_hits(*pattern);
    EXPECT_FALSE(any_hit_in_range(hits, bytes, bytes + 4096));

    VirtualFree(na_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, NthOccurrence)
{
    void *ro_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(ro_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(ro_mem);
    std::memset(bytes, 0x00, 4096);

    // Two copies of the same signature in one region (same seed -> same bytes).
    const std::string aob = write_signature(&bytes[100], 16, 0x84);
    (void)write_signature(&bytes[600], 16, 0x84);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(ro_mem, 4096, PAGE_READONLY, &old_protect));

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    // Both copies must be reachable across the enumerated occurrences.
    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[100]));
    EXPECT_TRUE(hits_contain(hits, &bytes[600]));

    VirtualFree(ro_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, RespectsPatternOffset)
{
    void *ro_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(ro_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(ro_mem);
    std::memset(bytes, 0x00, 4096);

    // 8-byte signature with a `|` marker after byte 3; the returned pointer must
    // be the marked byte, with pattern.offset applied exactly once.
    constexpr size_t region_offset = 320;
    const std::string aob = write_signature(&bytes[region_offset], 8, 0x9C, /*marker_index=*/3);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(ro_mem, 4096, PAGE_READONLY, &old_protect));

    const auto pattern = Scanner::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 3);

    // The marked byte of the buffer copy is at region_offset + 3.
    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[region_offset + 3]));

    VirtualFree(ro_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, EmptyPattern)
{
    Scanner::CompiledPattern empty;
    const std::byte *result = Scanner::scan_readable_regions(empty);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerReadableRegionTest, ZeroOccurrence)
{
    auto pattern = Scanner::parse_aob("5E 91 C4 2A 7F 38 D6 0B E3 4C 9A 17 62 F5 8D 30");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = Scanner::scan_readable_regions(*pattern, 0);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerStringTest, RipResolveErrorToString_IsNoexcept)
{
    static_assert(noexcept(rip_resolve_error_to_string(RipResolveError::NullInput)));
    static_assert(noexcept(rip_resolve_error_to_string(RipResolveError::PrefixNotFound)));
    static_assert(noexcept(rip_resolve_error_to_string(RipResolveError::RegionTooSmall)));
    static_assert(noexcept(rip_resolve_error_to_string(RipResolveError::UnreadableDisplacement)));
}

TEST(ScannerStringTest, ResolveErrorToString_IsNoexcept)
{
    static_assert(noexcept(Scanner::resolve_error_to_string(Scanner::ResolveError::EmptyCandidates)));
    static_assert(noexcept(Scanner::resolve_error_to_string(Scanner::ResolveError::NoMatch)));
    static_assert(noexcept(Scanner::resolve_error_to_string(Scanner::ResolveError::AllPatternsInvalid)));
    static_assert(noexcept(Scanner::resolve_error_to_string(Scanner::ResolveError::PrologueFallbackNotApplicable)));
    static_assert(noexcept(Scanner::resolve_error_to_string(Scanner::ResolveError::InvalidRange)));
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

TEST(ScannerCascade, ReadableKindResolvesDataSectionMatch)
{
    // A Direct-mode candidate whose signature lives in PAGE_READONLY data is
    // reachable only through ScannerKind::Readable; the executable default must
    // miss it.
    void *ro_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(ro_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(ro_mem);
    std::memset(bytes, 0x00, 4096);

    // The AOB string backs the candidate's string_view, so it must outlive the
    // resolve_cascade calls below.
    const std::string aob = write_signature(&bytes[384], 16, 0xC1);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(ro_mem, 4096, PAGE_READONLY, &old_protect));

    // require_unique is left false: this is a whole-process sweep and
    // write_signature leaves transient stack copies of the bytes, so the
    // signature is not globally unique. The test exercises ScannerKind, not the
    // uniqueness guard.
    Scanner::AddrCandidate cands[] = {
        {"data-sig", aob, Scanner::ResolveMode::Direct, 0, 0, /*require_unique=*/false},
    };

    // ScannerKind::Readable reaches data sections, so the cascade resolves a
    // signature that lives in PAGE_READONLY memory; the executable default
    // cannot see it and reports NoMatch.
    const auto readable =
        Scanner::resolve_cascade(cands, "data-cascade", Scanner::ScannerKind::Readable);
    EXPECT_TRUE(readable.has_value());

    const auto executable =
        Scanner::resolve_cascade(cands, "data-cascade", Scanner::ScannerKind::Executable);
    ASSERT_FALSE(executable.has_value());
    EXPECT_EQ(executable.error(), Scanner::ResolveError::NoMatch);

    VirtualFree(ro_mem, 0, MEM_RELEASE);
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

    // Ten literal tail bytes satisfy kPrologueFallbackMinTailLiterals and
    // keep the rebuilt pattern unique enough in the process's executable
    // regions to land a single match.
    constexpr std::uint8_t kUniqueTail[] = {
        0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x13, 0x37, 0x42, 0x5B, 0x6A};

    constexpr std::size_t kOffset = 0x200;

    buf.base[kOffset + 0] = 0xE9;
    buf.base[kOffset + 1] = 0x11;
    buf.base[kOffset + 2] = 0x22;
    buf.base[kOffset + 3] = 0x33;
    buf.base[kOffset + 4] = 0x44;
    std::memcpy(buf.base + kOffset + 5, kUniqueTail, sizeof(kUniqueTail));

    const char *pattern =
        "48 89 5C 24 08 AD BE EF CA FE 13 37 42 5B 6A";

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
// by the original pattern's tail bytes. The uniqueness guard in
// scan_candidates_hooked_prologue rejects any rebuilt pattern that
// matches more than kPrologueFallbackMaxHits locations across the
// process's executable regions, because a legitimate sibling-mod hook
// rewrites exactly one prologue and so a unique scan target must
// resolve to exactly one site. This test seeds two trampoline-shaped
// sequences with the same literal tail to force a multi-match outcome.
TEST(ScannerCascade, PrologueFallbackRejectsAmbiguousTail)
{
    // ExecBuffer allocates PAGE_EXECUTE_READWRITE, so seeding and
    // scanning both work without a mid-test VirtualProtect toggle.
    // scan_executable_regions walks any page with the EXECUTE bit,
    // so RX and RWX are both visible. Using RAII ensures the region
    // is released even if a following ASSERT short-circuits the test.
    ExecBuffer buf(0x2000);
    ASSERT_NE(buf.base, nullptr);

    std::memset(buf.base, 0xCC, buf.size);

    // Tail chosen literal-heavy enough to pass kPrologueFallbackMinTailLiterals
    // (10 non-wildcard bytes after the rewritten prologue). Bytes must NOT
    // collide with any other test's pattern, because residue in
    // freed-but-still-mapped memory could influence subsequent tests that
    // run in the same process.
    // Prefix mimics a SafetyHook-installed JMP rel32 over the original
    // prologue -- the only shape the fallback recognises before rebuilding
    // the AOB from the literal tail described above.
    constexpr std::uint8_t kAmbiguousTemplate[] = {
        0xE9, 0x00, 0x00, 0x00, 0x00,
        0xA5, 0xB6, 0xC7, 0xD8, 0xE9, 0xFA, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F,
    };

    // Seed two copies so the rebuilt fallback pattern tallies >= 2 hits in
    // this buffer alone, which exceeds the uniqueness ceiling of 1 and
    // forces the guard to engage.
    for (std::size_t i = 0; i < 2; ++i)
    {
        std::memcpy(buf.base + i * 0x100, kAmbiguousTemplate, sizeof(kAmbiguousTemplate));
    }

    Scanner::AddrCandidate cands[] = {
        // Original prologue is five arbitrary REX-prefixed bytes followed
        // by the ambiguous literal tail. resolve_cascade's direct pass
        // will not match (the buffer starts with E9 not 48 89 ...), so
        // the prologue-fallback path is taken.
        {"ambiguous",
         "48 89 5C 24 08 A5 B6 C7 D8 E9 FA 0B 1C 2D 3E 4F",
         Scanner::ResolveMode::Direct, 0, 0},
    };

    auto result = Scanner::resolve_cascade_with_prologue_fallback(
        cands, "ambiguous-tail");

    // The guard rejects ambiguity -> NoMatch (fallback applicable but
    // every candidate exceeded the uniqueness ceiling).
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::ResolveError::NoMatch);
}

// Boundary regression: a literal tail of exactly nine bytes must be
// rejected as PrologueFallbackNotApplicable. Under the previous
// threshold (five) the fallback would have engaged with this candidate
// and produced an unstable resolution; the tightened floor (ten)
// surfaces the refusal at the API boundary instead.
TEST(ScannerCascade, PrologueFallbackRejectsNineByteTail)
{
    Scanner::AddrCandidate cands[] = {
        {"nine-byte-tail",
         "48 89 5C 24 08 AA BB CC DD EE 11 22 33 44",
         Scanner::ResolveMode::Direct, 0, 0},
    };

    auto result = Scanner::resolve_cascade_with_prologue_fallback(
        cands, "nine-byte-tail");

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::ResolveError::PrologueFallbackNotApplicable);
}

// Boundary regression: exactly two matches of the rebuilt pattern must
// trip the uniqueness guard. Under the previous ceiling (four) two hits
// were accepted and the first arbitrary site was hooked; the tightened
// ceiling (one) demands exact uniqueness, and any duplicate must surface
// as NoMatch.
TEST(ScannerCascade, PrologueFallbackRejectsExactlyTwoMatches)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);

    std::memset(buf.base, 0xCC, buf.size);

    // Prefix mimics a SafetyHook-installed JMP rel32 over the original
    // prologue (the shape the fallback rebuilds around). The 11-byte
    // tail clears kPrologueFallbackMinTailLiterals so the test reaches
    // the uniqueness check rather than the literal-floor refusal.
    constexpr std::uint8_t kTemplate[] = {
        0xE9, 0x00, 0x00, 0x00, 0x00,
        0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6, 0xD7, 0xE8, 0xF9, 0x0A, 0x1B,
    };

    std::memcpy(buf.base + 0x000, kTemplate, sizeof(kTemplate));
    std::memcpy(buf.base + 0x200, kTemplate, sizeof(kTemplate));

    Scanner::AddrCandidate cands[] = {
        {"two-match",
         "48 89 5C 24 08 71 82 93 A4 B5 C6 D7 E8 F9 0A 1B",
         Scanner::ResolveMode::Direct, 0, 0},
    };

    auto result = Scanner::resolve_cascade_with_prologue_fallback(
        cands, "two-match");

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::ResolveError::NoMatch);
}

// --- Tests for resolve_cascade_in_module / _with_prologue_fallback ---

// A module-scoped scan must reach the read-only data section of a real mapped
// PE with a single range scan: there is no separate Readable kind to opt into.
// The fixture DLL exports dmk_scan_marker, a fixed signature that lands in
// .rdata; resolving it proves both the .rdata reach and the in-range result.
TEST(ScannerModuleCascade, ScopedHitFindsMarkerInFixtureRdata)
{
    HMODULE dll = LoadLibraryA("hook_target_lib.dll");
    ASSERT_NE(dll, nullptr)
        << "Failed to load hook_target_lib.dll. Error: " << GetLastError();

    const auto *marker = reinterpret_cast<const std::byte *>(
        reinterpret_cast<void *>(GetProcAddress(dll, "dmk_scan_marker")));
    ASSERT_NE(marker, nullptr) << "dmk_scan_marker export not found";

    const auto range = Memory::module_range_for(marker);
    ASSERT_TRUE(range.has_value());
    ASSERT_TRUE(range->valid());

    Scanner::AddrCandidate cands[] = {
        {"marker", "A7 3C F1 88 5E 22 D9 04 6B B0 1F 97 4A E3 7D 50",
         Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto hit = Scanner::resolve_cascade_in_module(cands, "marker", *range);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address, reinterpret_cast<std::uintptr_t>(marker));
    EXPECT_TRUE(Memory::contains(*range, hit->address));

    FreeLibrary(dll);
}

// The same byte sequence planted in two independent "module" images: a
// module-scoped scan must return only the copy inside the range it was given,
// never the identical copy in the sibling region. This is the cross-module
// collision a first-match-wins whole-process scan cannot disambiguate.
TEST(ScannerModuleCascade, NoCrossModuleBleedReturnsInRangeCopy)
{
    void *mod_a = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mod_b = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mod_a, nullptr);
    ASSERT_NE(mod_b, nullptr);

    auto *bytes_a = reinterpret_cast<std::byte *>(mod_a);
    auto *bytes_b = reinterpret_cast<std::byte *>(mod_b);
    std::memset(bytes_a, 0xCC, 4096);
    std::memset(bytes_b, 0xCC, 4096);

    // Same seed and length => identical bytes in both regions, at different
    // offsets so an address comparison can tell which copy resolved.
    const std::string aob = write_signature(&bytes_a[256], 16, 0x6E);
    (void)write_signature(&bytes_b[1024], 16, 0x6E);

    const Memory::ModuleRange range_a{reinterpret_cast<std::uintptr_t>(mod_a),
                                      reinterpret_cast<std::uintptr_t>(mod_a) + 4096};
    const Memory::ModuleRange range_b{reinterpret_cast<std::uintptr_t>(mod_b),
                                      reinterpret_cast<std::uintptr_t>(mod_b) + 4096};

    Scanner::AddrCandidate cands[] = {
        {"sig", aob, Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto hit_a = Scanner::resolve_cascade_in_module(cands, "sig-a", range_a);
    ASSERT_TRUE(hit_a.has_value());
    EXPECT_EQ(hit_a->address, reinterpret_cast<std::uintptr_t>(&bytes_a[256]));

    const auto hit_b = Scanner::resolve_cascade_in_module(cands, "sig-b", range_b);
    ASSERT_TRUE(hit_b.has_value());
    EXPECT_EQ(hit_b->address, reinterpret_cast<std::uintptr_t>(&bytes_b[1024]));

    VirtualFree(mod_a, 0, MEM_RELEASE);
    VirtualFree(mod_b, 0, MEM_RELEASE);
}

// A signature that exists only outside the supplied range must not be found.
// A whole-process readable scan does find it; the module-scoped scan must not,
// which is the entire point of scoping.
TEST(ScannerModuleCascade, SignaturePresentOnlyOutsideRangeReturnsNoMatch)
{
    void *mod_a = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *mod_b = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mod_a, nullptr);
    ASSERT_NE(mod_b, nullptr);
    std::memset(mod_a, 0xCC, 4096);
    std::memset(mod_b, 0xCC, 4096);

    const std::string aob =
        write_signature(reinterpret_cast<std::byte *>(mod_b) + 128, 16, 0x33);

    const auto base_a = reinterpret_cast<std::uintptr_t>(mod_a);
    const Memory::ModuleRange range_a{base_a, base_a + 4096};

    // require_unique is left false: this test exercises scope, not uniqueness,
    // and write_signature leaves transient stack copies of the bytes that make
    // the signature non-unique under a whole-process sweep (see
    // collect_readable_hits). A real whole-process consumer of a non-unique
    // pattern opts out the same way.
    Scanner::AddrCandidate cands[] = {
        {"elsewhere", aob, Scanner::ResolveMode::Direct, 0, 0, /*require_unique=*/false},
    };

    // Sanity: the readable whole-process sweep finds the copy in region B.
    const auto whole = Scanner::resolve_cascade(cands, "whole", Scanner::ScannerKind::Readable);
    EXPECT_TRUE(whole.has_value());

    // The module-scoped scan of region A must not see region B's copy.
    const auto scoped = Scanner::resolve_cascade_in_module(cands, "scoped", range_a);
    ASSERT_FALSE(scoped.has_value());
    EXPECT_EQ(scoped.error(), Scanner::ResolveError::NoMatch);

    VirtualFree(mod_a, 0, MEM_RELEASE);
    VirtualFree(mod_b, 0, MEM_RELEASE);
}

// Bounds-aware fall-through: a RipRelative P1 that matches in-module but whose
// disp32 resolves outside the range must be skipped so the in-range Direct P2
// wins. This is the fix a post-resolution caller check cannot express.
TEST(ScannerModuleCascade, RipRelativeResolvingOutOfRangeFallsThroughToNextCandidate)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    auto *bytes = reinterpret_cast<std::byte *>(mem);
    std::memset(bytes, 0xCC, 4096);

    const auto base = reinterpret_cast<std::uintptr_t>(mem);
    const Memory::ModuleRange range{base, base + 4096};

    // P1: mov rax,[rip+disp32] whose disp resolves BELOW the module base, i.e.
    // outside the range. Target = (base + 7) - 0x1000 < base.
    bytes[0] = std::byte{0x48};
    bytes[1] = std::byte{0x8B};
    bytes[2] = std::byte{0x05};
    const std::int32_t disp = -0x1000;
    std::memcpy(&bytes[3], &disp, sizeof(disp));

    // P2: a plain in-range Direct signature.
    const std::string p2_aob = write_signature(&bytes[256], 16, 0x4B);

    Scanner::AddrCandidate cands[] = {
        {"p1_riprel", "48 8B 05 ?? ?? ?? ??", Scanner::ResolveMode::RipRelative, 3, 7},
        {"p2_direct", p2_aob, Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto hit = Scanner::resolve_cascade_in_module(cands, "riprel-fallthrough", range);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->winning_name, "p2_direct");
    EXPECT_EQ(hit->address, reinterpret_cast<std::uintptr_t>(&bytes[256]));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Bounds-aware fall-through for Direct mode: P1 matches in the scanned half of
// the image, but its disp_offset pushes the resolved address into the second
// half, outside the supplied range. The cascade must fall through to P2.
TEST(ScannerModuleCascade, DirectResolvingOutOfRangeFallsThroughToNextCandidate)
{
    void *mem = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    auto *bytes = reinterpret_cast<std::byte *>(mem);
    std::memset(bytes, 0xCC, 0x2000);

    const auto base = reinterpret_cast<std::uintptr_t>(mem);
    // The range covers only the first half; the second half is "out of module".
    const Memory::ModuleRange range{base, base + 0x1000};

    const std::string p1_aob = write_signature(&bytes[0], 16, 0x21);
    const std::string p2_aob = write_signature(&bytes[512], 16, 0x77);

    Scanner::AddrCandidate cands[] = {
        // disp_offset 0x1800 pushes the resolved address past range.end.
        {"p1_direct", p1_aob, Scanner::ResolveMode::Direct, 0x1800, 0},
        {"p2_direct", p2_aob, Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto hit = Scanner::resolve_cascade_in_module(cands, "direct-fallthrough", range);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->winning_name, "p2_direct");
    EXPECT_EQ(hit->address, reinterpret_cast<std::uintptr_t>(&bytes[512]));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Positive RipRelative case: a mov reg,[rip+disp32] candidate whose
// displacement targets data inside the same module must resolve to that
// in-module address and win. This is the success path for a RipRelative global
// (e.g. a context-pointer storage slot in .data): under a whole-process scan the
// instruction could match in a sibling module and resolve out of bounds, but the
// module-scoped scan finds the in-module instruction and resolves it in range. A
// decoy with the same instruction shape in a sibling region is never consulted.
TEST(ScannerModuleCascade, RipRelativeResolvingInsideRangeResolvesInModule)
{
    void *mod = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *sibling = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mod, nullptr);
    ASSERT_NE(sibling, nullptr);
    auto *bytes = reinterpret_cast<std::byte *>(mod);
    auto *sib = reinterpret_cast<std::byte *>(sibling);
    std::memset(bytes, 0xCC, 4096);
    std::memset(sib, 0xCC, 4096);

    const auto base = reinterpret_cast<std::uintptr_t>(mod);
    const Memory::ModuleRange range{base, base + 4096};

    // In-module instruction at offset 0: target = (base + 7) + disp = base + 0x800.
    bytes[0] = std::byte{0x48};
    bytes[1] = std::byte{0x8B};
    bytes[2] = std::byte{0x05};
    const std::int32_t disp_in = static_cast<std::int32_t>(0x800 - 7);
    std::memcpy(&bytes[3], &disp_in, sizeof(disp_in));

    // Sibling decoy with the same instruction shape; its disp is irrelevant
    // because the module-scoped scan never inspects this region.
    sib[0] = std::byte{0x48};
    sib[1] = std::byte{0x8B};
    sib[2] = std::byte{0x05};
    const std::int32_t disp_decoy = 0;
    std::memcpy(&sib[3], &disp_decoy, sizeof(disp_decoy));

    Scanner::AddrCandidate cands[] = {
        {"global_ptr", "48 8B 05 ?? ?? ?? ??", Scanner::ResolveMode::RipRelative, 3, 7},
    };

    const auto hit = Scanner::resolve_cascade_in_module(cands, "global-ptr", range);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address, base + 0x800);
    EXPECT_TRUE(Memory::contains(range, hit->address));

    VirtualFree(mod, 0, MEM_RELEASE);
    VirtualFree(sibling, 0, MEM_RELEASE);
}

// Cascade fall-through when the first candidate is absent from the image: a
// generic prologue P1 that does not appear in this module simply does not match,
// so the cascade falls through to the mid-body anchor P2 that does. Under a
// whole-process scan the same P1 false-matches inside a sibling module and wins
// (first-match-wins), shadowing the correct target -- the exact cross-module
// shadowing this overload prevents. The test asserts both halves: the
// whole-process cascade returns P1, the module-scoped cascade returns P2.
TEST(ScannerModuleCascade, FirstCandidateAbsentInModuleFallsThroughToNextCandidate)
{
    void *mod = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void *sibling = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mod, nullptr);
    ASSERT_NE(sibling, nullptr);
    auto *bytes = reinterpret_cast<std::byte *>(mod);
    auto *sib = reinterpret_cast<std::byte *>(sibling);
    std::memset(bytes, 0xCC, 4096);
    std::memset(sib, 0xCC, 4096);

    const auto base = reinterpret_cast<std::uintptr_t>(mod);
    const Memory::ModuleRange range{base, base + 4096};

    // P1 (generic prologue) exists ONLY in the sibling module, not the target.
    const std::string p1_aob = write_signature(&sib[128], 16, 0x55);
    // P2 (mid-body anchor) exists in the target module.
    const std::string p2_aob = write_signature(&bytes[640], 16, 0x9C);

    // require_unique is left false to isolate scope from uniqueness: the
    // whole-process contrast below would otherwise reject both candidates as
    // ambiguous, since write_signature leaves transient stack copies of the
    // bytes (see collect_readable_hits).
    Scanner::AddrCandidate cands[] = {
        {"p1_prologue", p1_aob, Scanner::ResolveMode::Direct, 0, 0, /*require_unique=*/false},
        {"p2_anchor", p2_aob, Scanner::ResolveMode::Direct, 0, 0, /*require_unique=*/false},
    };

    // Whole-process first-match returns P1 (it matches outside this module) and
    // shadows P2: the cross-module shadowing that produced the bug.
    const auto whole = Scanner::resolve_cascade(cands, "anchor-whole",
                                                Scanner::ScannerKind::Readable);
    ASSERT_TRUE(whole.has_value());
    EXPECT_EQ(whole->winning_name, "p1_prologue");

    // Module-scoped scan does not see P1 (it lives only outside this range), so
    // it falls through to the in-module P2.
    const auto scoped = Scanner::resolve_cascade_in_module(cands, "anchor-scoped", range);
    ASSERT_TRUE(scoped.has_value());
    EXPECT_EQ(scoped->winning_name, "p2_anchor");
    EXPECT_EQ(scoped->address, reinterpret_cast<std::uintptr_t>(&bytes[640]));

    VirtualFree(mod, 0, MEM_RELEASE);
    VirtualFree(sibling, 0, MEM_RELEASE);
}

TEST(ScannerModuleCascade, FullMissReturnsNoMatch)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    std::memset(mem, 0xCC, 4096);
    const auto base = reinterpret_cast<std::uintptr_t>(mem);
    const Memory::ModuleRange range{base, base + 4096};

    Scanner::AddrCandidate cands[] = {
        {"absent", "DE AD BE EF 11 22 33 44 55 66 77 88 99 AA BB 12",
         Scanner::ResolveMode::Direct, 0, 0},
    };
    const auto hit = Scanner::resolve_cascade_in_module(cands, "miss", range);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Scanner::ResolveError::NoMatch);

    VirtualFree(mem, 0, MEM_RELEASE);
}

// An invalid range must surface a distinct error and never silently fall back
// to a whole-process scan, which would re-introduce the cross-module shadowing
// the overload exists to prevent.
TEST(ScannerModuleCascade, InvalidRangeReturnsInvalidRange)
{
    Scanner::AddrCandidate cands[] = {
        {"sig", "DE AD BE EF 11 22 33 44 55 66 77 88 99 AA BB 12",
         Scanner::ResolveMode::Direct, 0, 0},
    };
    const Memory::ModuleRange invalid{}; // base == end == 0 => valid() is false
    const auto hit = Scanner::resolve_cascade_in_module(cands, "invalid", invalid);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Scanner::ResolveError::InvalidRange);
}

TEST(ScannerModuleCascade, EmptyCandidatesReturnsError)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    const auto base = reinterpret_cast<std::uintptr_t>(mem);
    const Memory::ModuleRange range{base, base + 4096};

    std::span<const Scanner::AddrCandidate> empty{};
    const auto hit = Scanner::resolve_cascade_in_module(empty, "empty", range);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Scanner::ResolveError::EmptyCandidates);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(ScannerModuleCascade, AllInvalidPatternsReturnsError)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    const auto base = reinterpret_cast<std::uintptr_t>(mem);
    const Memory::ModuleRange range{base, base + 4096};

    Scanner::AddrCandidate cands[] = {
        {"bad", "not_valid_aob_tokens $$$$", Scanner::ResolveMode::Direct, 0, 0},
    };
    const auto hit = Scanner::resolve_cascade_in_module(cands, "bad", range);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Scanner::ResolveError::AllPatternsInvalid);

    VirtualFree(mem, 0, MEM_RELEASE);
}

namespace
{
    // Allocates an executable page within an int32 rel32 displacement of
    // `anchor`, mirroring how inline-hook trampoline allocators (MinHook,
    // SafetyHook) place a detour close to its target so a 5-byte E9 can reach
    // it. Returns nullptr if no free region within range is found; the caller
    // owns a non-null result and must VirtualFree it.
    std::uint8_t *alloc_exec_near(std::uintptr_t anchor, std::size_t size)
    {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const auto gran = static_cast<std::uintptr_t>(si.dwAllocationGranularity);
        // Stay comfortably inside the +-2GB rel32 reach on either side of anchor.
        constexpr std::uintptr_t search_radius = 0x6000'0000;

        const std::uintptr_t lo = anchor > search_radius ? anchor - search_radius : gran;
        const std::uintptr_t hi = anchor + search_radius;

        std::uintptr_t probe = (lo + gran - 1) & ~(gran - 1);
        while (probe < hi)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(probe), &mbi, sizeof(mbi)) == 0)
            {
                break;
            }
            const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            if (mbi.State == MEM_FREE)
            {
                const std::uintptr_t aligned = (region_base + gran - 1) & ~(gran - 1);
                if (aligned + size <= region_base + mbi.RegionSize)
                {
                    void *p = VirtualAlloc(reinterpret_cast<LPVOID>(aligned), size,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (p != nullptr)
                    {
                        return static_cast<std::uint8_t *>(p);
                    }
                }
            }
            probe = region_base + mbi.RegionSize;
        }
        return nullptr;
    }
} // namespace

// Regression guard for the module-scoped prologue fallback: the rewritten
// near-JMP must be FOUND inside the module, but its destination (a sibling
// mod's trampoline) lives OUTSIDE it. Constraining the destination to the
// module range would reject this recovery, so the destination is validated
// only against "lies in some loaded module". Here the trampoline target is the
// test executable image, a different module than the scanned scratch buffer,
// which is allocated within rel32 reach so the E9 can encode the jump.
TEST(ScannerModuleCascade, PrologueFallbackAllowsTrampolineOutsideModule)
{
    const auto dest = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));

    std::uint8_t *region = alloc_exec_near(dest, 0x1000);
    if (region == nullptr)
    {
        GTEST_SKIP() << "no free executable region within rel32 of the test image";
    }
    std::memset(region, 0xCC, 0x1000);

    constexpr std::size_t kOffset = 0x200;
    const auto match_site = reinterpret_cast<std::uintptr_t>(region) + kOffset;
    const std::int64_t rel =
        static_cast<std::int64_t>(dest) - static_cast<std::int64_t>(match_site + 5);
    ASSERT_GE(rel, INT32_MIN);
    ASSERT_LE(rel, INT32_MAX);

    constexpr std::uint8_t kTail[] = {
        0x5A, 0xB4, 0xD1, 0xE7, 0xF9, 0x2B, 0x4D, 0x6F, 0x81, 0x93};

    region[kOffset + 0] = 0xE9;
    const std::int32_t disp = static_cast<std::int32_t>(rel);
    std::memcpy(region + kOffset + 1, &disp, sizeof(disp));
    std::memcpy(region + kOffset + 5, kTail, sizeof(kTail));

    const Memory::ModuleRange range{reinterpret_cast<std::uintptr_t>(region),
                                    reinterpret_cast<std::uintptr_t>(region) + 0x1000};

    // The original (unhooked) prologue starts with five REX-prefixed bytes the
    // buffer does not contain (it starts with E9), so the direct pass misses and
    // the fallback rebuilds E9 ?? ?? ?? ?? + tail to match the planted site.
    Scanner::AddrCandidate cands[] = {
        {"hooked", "48 89 5C 24 08 5A B4 D1 E7 F9 2B 4D 6F 81 93",
         Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto hit = Scanner::resolve_cascade_in_module_with_prologue_fallback(
        cands, "trampoline-out-of-module", range);
    ASSERT_TRUE(hit.has_value())
        << "module-scoped fallback rejected an out-of-module trampoline destination";
    EXPECT_EQ(hit->address, match_site);

    VirtualFree(region, 0, MEM_RELEASE);
}

// Page-scope regression guard for the module-scoped prologue fallback: a hooked
// near-JMP only ever overwrites a code prologue, so the fallback must search the
// image's executable pages only -- matching the whole-process fallback, which
// counts and scans through scan_executable_regions. Here the E9 + literal tail is
// planted in a READ-ONLY data page (the execute bit is stripped after seeding)
// inside the range, with a rel32 that resolves into a loaded module. The fallback
// must NOT resolve it: a hit would mean it scanned a non-code page. (Under the
// earlier readable-page mask this resolved to the data-page address.)
TEST(ScannerModuleCascade, PrologueFallbackIgnoresNonExecutableDataPage)
{
    const auto dest = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));

    std::uint8_t *region = alloc_exec_near(dest, 0x1000);
    if (region == nullptr)
    {
        GTEST_SKIP() << "no free region within rel32 of the test image";
    }
    std::memset(region, 0xCC, 0x1000);

    constexpr std::size_t kOffset = 0x200;
    const auto match_site = reinterpret_cast<std::uintptr_t>(region) + kOffset;
    const std::int64_t rel =
        static_cast<std::int64_t>(dest) - static_cast<std::int64_t>(match_site + 5);
    ASSERT_GE(rel, INT32_MIN);
    ASSERT_LE(rel, INT32_MAX);

    // Distinct from the trampoline test's tail so freed-but-mapped residue cannot
    // cross-contaminate; ten literals clear kPrologueFallbackMinTailLiterals.
    constexpr std::uint8_t kTail[] = {
        0x6C, 0x5D, 0x4E, 0x3F, 0x20, 0x11, 0x02, 0xF3, 0xE4, 0xD5};

    region[kOffset + 0] = 0xE9;
    const std::int32_t disp = static_cast<std::int32_t>(rel);
    std::memcpy(region + kOffset + 1, &disp, sizeof(disp));
    std::memcpy(region + kOffset + 5, kTail, sizeof(kTail));

    // Strip execute: the planted bytes now live in a readable, non-executable page.
    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(region, 0x1000, PAGE_READONLY, &old_protect));

    const Memory::ModuleRange range{reinterpret_cast<std::uintptr_t>(region),
                                    reinterpret_cast<std::uintptr_t>(region) + 0x1000};

    Scanner::AddrCandidate cands[] = {
        {"hooked", "48 89 5C 24 08 6C 5D 4E 3F 20 11 02 F3 E4 D5",
         Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto hit = Scanner::resolve_cascade_in_module_with_prologue_fallback(
        cands, "data-page-fallback", range);
    ASSERT_FALSE(hit.has_value())
        << "module fallback matched an E9 prologue in a non-executable data page";
    EXPECT_EQ(hit.error(), Scanner::ResolveError::NoMatch);

    VirtualFree(region, 0, MEM_RELEASE);
}

// require_unique: an ambiguous primary (matches more than once in the module) is
// skipped so the cascade falls through to the next candidate, instead of
// silently committing to the lowest-address match. Here P2 is provably unique
// and wins.
TEST(ScannerModuleCascade, RequireUniqueAmbiguousCandidateFallsThroughToUniqueNext)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    auto *bytes = reinterpret_cast<std::byte *>(mem);
    std::memset(bytes, 0xCC, 4096);

    const auto base = reinterpret_cast<std::uintptr_t>(mem);
    const Memory::ModuleRange range{base, base + 4096};

    // P1 planted twice -> ambiguous. Neither candidate sets require_unique, so
    // both rely on the default (true): the ambiguous P1 is skipped.
    const std::string p1 = write_signature(&bytes[128], 16, 0x40);
    (void)write_signature(&bytes[2048], 16, 0x40);
    // P2 planted once -> unique.
    const std::string p2 = write_signature(&bytes[512], 16, 0x8A);

    Scanner::AddrCandidate cands[] = {
        {"p1_ambiguous", p1, Scanner::ResolveMode::Direct, 0, 0},
        {"p2_unique", p2, Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto hit = Scanner::resolve_cascade_in_module(cands, "require-unique", range);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->winning_name, "p2_unique");
    EXPECT_EQ(hit->address, reinterpret_cast<std::uintptr_t>(&bytes[512]));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// require_unique is per-candidate, not a blanket per-call policy: a strict
// primary that is ambiguous is skipped, while a deliberately broad fallback
// (require_unique left false) accepts its first match even though it too is
// non-unique.
TEST(ScannerModuleCascade, RequireUniquePerCandidateStrictSkipsLooseAccepts)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    auto *bytes = reinterpret_cast<std::byte *>(mem);
    std::memset(bytes, 0xCC, 4096);

    const auto base = reinterpret_cast<std::uintptr_t>(mem);
    const Memory::ModuleRange range{base, base + 4096};

    // P1 (strict) ambiguous -> skipped. It relies on the default (require_unique
    // true). P2 (loose) is also ambiguous but opts out and accepts the first
    // (lowest-address) match.
    const std::string p1 = write_signature(&bytes[128], 16, 0x40);
    (void)write_signature(&bytes[1024], 16, 0x40);
    const std::string p2 = write_signature(&bytes[256], 16, 0x77);
    (void)write_signature(&bytes[2048], 16, 0x77);

    Scanner::AddrCandidate cands[] = {
        {"p1_strict", p1, Scanner::ResolveMode::Direct, 0, 0},
        {"p2_loose", p2, Scanner::ResolveMode::Direct, 0, 0, /*require_unique=*/false},
    };

    const auto hit = Scanner::resolve_cascade_in_module(cands, "per-candidate", range);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->winning_name, "p2_loose");
    EXPECT_EQ(hit->address, reinterpret_cast<std::uintptr_t>(&bytes[256]));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// require_unique with no unique candidate yields a clean NoMatch -- the "binary
// changed, update signatures" signal -- rather than a confident wrong hit.
TEST(ScannerModuleCascade, RequireUniqueAllAmbiguousReturnsNoMatch)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    auto *bytes = reinterpret_cast<std::byte *>(mem);
    std::memset(bytes, 0xCC, 4096);

    const auto base = reinterpret_cast<std::uintptr_t>(mem);
    const Memory::ModuleRange range{base, base + 4096};

    // The single candidate relies on the default (require_unique true) and is
    // ambiguous, so there is no provably-unique candidate to win.
    const std::string sig = write_signature(&bytes[128], 16, 0x40);
    (void)write_signature(&bytes[2048], 16, 0x40);

    Scanner::AddrCandidate cands[] = {
        {"ambiguous", sig, Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto hit = Scanner::resolve_cascade_in_module(cands, "all-ambiguous", range);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Scanner::ResolveError::NoMatch);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(ScannerPrologueTest, NullAddrReturnsFalse)
{
    EXPECT_FALSE(Scanner::is_likely_function_prologue(0));
}

TEST(ScannerPrologueTest, ZeroByteReturnsFalse)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0x00;
    EXPECT_FALSE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, Int3PadReturnsFalse)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    EXPECT_FALSE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, BareRetC3ReturnsFalse)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xC3;
    EXPECT_FALSE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, BareRetC2ReturnsFalse)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xC2;
    EXPECT_FALSE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, PushRbpReturnsTrue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0x55; // push rbp -- canonical x86-64 prologue
    EXPECT_TRUE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

// Load-bearing case: documents the no-interference-with-nested-hooks
// contract. A target whose prologue has already been overwritten by
// SafetyHook or MinHook starts with a JMP rel32 (0xE9); the helper must
// still accept it so the resolver path stays usable when a sibling mod
// hooked the same function first.
TEST(ScannerPrologueTest, PatchedJmpE9ReturnsTrue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xE9;
    EXPECT_TRUE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

// Short JMP (0xEB rel8) is the second prologue-overwrite shape the helper
// is documented to accept. Some mid-function hookers prefer 0xEB when the
// target lives within +/-127 bytes; the resolver must still treat it as a
// real prologue so cascade recovery keeps working under nested hooks.
TEST(ScannerPrologueTest, PatchedJmpEBReturnsTrue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xEB;
    EXPECT_TRUE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

// Indirect JMP through memory (0xFF 0x25 disp32) is the third documented
// prologue-overwrite shape, used by trampoline allocators that need a full
// 64-bit reach. Only the first byte (0xFF) is examined by the helper, but
// the test seeds both bytes so the buffer matches what a real patched
// prologue would look like.
TEST(ScannerPrologueTest, PatchedJmpFF25ReturnsTrue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xFF;
    buf.base[0x101] = 0x25;
    EXPECT_TRUE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, UnreadableAddrReturnsFalse)
{
    void *na = VirtualAlloc(nullptr, 0x1000,
                            MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(na, nullptr);
    EXPECT_FALSE(Scanner::is_likely_function_prologue(
        reinterpret_cast<std::uintptr_t>(na)));
    VirtualFree(na, 0, MEM_RELEASE);
}
