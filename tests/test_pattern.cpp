#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "DetourModKit/detail/pattern_core.hpp"
#include "DetourModKit/scan.hpp"

using namespace DetourModKit;

namespace
{
    // A small byte-window helper so the matches_at tests read as the bytes a scan would see at a candidate position.
    template <std::size_t N>
    [[nodiscard]] constexpr std::array<std::byte, N> window(const std::array<unsigned char, N> &raw) noexcept
    {
        std::array<std::byte, N> out{};
        for (std::size_t i = 0; i < N; ++i)
        {
            out[i] = static_cast<std::byte>(raw[i]);
        }
        return out;
    }
} // namespace

// Compile-time proof that literal() parses, anchors, and records the offset during constant evaluation. A regression
// in the constexpr core fails the build here rather than a test run.
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ??").size() == 7);
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ??").offset() == 0);
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ??").has_anchor());
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ??").anchor_index() == 2);
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ??").anchor_byte() == std::byte{0x05});
static_assert(scan::Pattern::literal("48 8B | 05").offset() == 2);

TEST(Pattern, ConstevalLiteralUsableAtRuntime)
{
    constexpr scan::Pattern pattern = scan::Pattern::literal("48 8B 05 ?? ?? ?? ??");
    EXPECT_EQ(pattern.size(), 7U);
    EXPECT_EQ(pattern.offset(), 0U);
    EXPECT_TRUE(pattern.has_anchor());
    EXPECT_EQ(pattern.anchor_index(), 2U);
    EXPECT_EQ(pattern.anchor_byte(), std::byte{0x05});
}

TEST(Pattern, CompileMatchesLiteralForSameInput)
{
    const auto compiled = scan::Pattern::compile("48 8B 05 ?? ?? ?? ??");
    ASSERT_TRUE(compiled.has_value());
    constexpr scan::Pattern literal = scan::Pattern::literal("48 8B 05 ?? ?? ?? ??");
    EXPECT_EQ(compiled->size(), literal.size());
    EXPECT_EQ(compiled->anchor_index(), literal.anchor_index());
    EXPECT_EQ(compiled->offset(), literal.offset());
}

TEST(Pattern, CompileRejectsMalformedInput)
{
    EXPECT_FALSE(scan::Pattern::compile("").has_value());
    EXPECT_FALSE(scan::Pattern::compile("   ").has_value());
    EXPECT_FALSE(scan::Pattern::compile("GG").has_value());
    EXPECT_FALSE(scan::Pattern::compile("1FF").has_value());
    EXPECT_FALSE(scan::Pattern::compile("4").has_value());

    const auto duplicate_marker = scan::Pattern::compile("48 | 8B | 05");
    ASSERT_FALSE(duplicate_marker.has_value());
    EXPECT_EQ(duplicate_marker.error().code, ErrorCode::BadPattern);
    EXPECT_EQ(duplicate_marker.error().extra, static_cast<std::uint32_t>(detail::PatternStatus::DuplicateOffset));
}

TEST(Pattern, CompileRejectsOverCapAndReportsStatus)
{
    // One byte over the inline-storage cap must fail closed rather than overrun the fixed array.
    std::string over_cap;
    for (std::size_t i = 0; i < detail::MAX_PATTERN_BYTES + 1; ++i)
    {
        over_cap += "00 ";
    }
    const auto result = scan::Pattern::compile(over_cap);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::BadPattern);
    EXPECT_EQ(result.error().extra, static_cast<std::uint32_t>(detail::PatternStatus::TooLong));

    // Exactly at the cap still compiles.
    std::string at_cap;
    for (std::size_t i = 0; i < detail::MAX_PATTERN_BYTES; ++i)
    {
        at_cap += "00 ";
    }
    const auto exact = scan::Pattern::compile(at_cap);
    ASSERT_TRUE(exact.has_value());
    EXPECT_EQ(exact->size(), detail::MAX_PATTERN_BYTES);
}

TEST(Pattern, WildcardTokensMatchAnyByte)
{
    // "??" and a single "?" are both full wildcards.
    const auto pattern = scan::Pattern::compile("48 ?? 8B ? C3");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->size(), 5U);

    const auto bytes_a = window<5>({0x48, 0x00, 0x8B, 0xFF, 0xC3});
    const auto bytes_b = window<5>({0x48, 0x99, 0x8B, 0x12, 0xC3});
    const auto bytes_miss = window<5>({0x48, 0x00, 0x8C, 0x00, 0xC3});
    EXPECT_TRUE(pattern->matches_at(bytes_a));
    EXPECT_TRUE(pattern->matches_at(bytes_b));
    EXPECT_FALSE(pattern->matches_at(bytes_miss));
}

TEST(Pattern, PerNibbleTokensCompareOnlyTheFixedNibble)
{
    const auto high = scan::Pattern::compile("4?");
    const auto low = scan::Pattern::compile("?5");
    ASSERT_TRUE(high.has_value());
    ASSERT_TRUE(low.has_value());

    // "4?" fixes the high nibble: any 0x4_ matches, 0x5_ does not.
    EXPECT_TRUE(high->matches_at(window<1>({0x4A})));
    EXPECT_TRUE(high->matches_at(window<1>({0x40})));
    EXPECT_FALSE(high->matches_at(window<1>({0x5A})));

    // "?5" fixes the low nibble: any 0x_5 matches, 0x_6 does not.
    EXPECT_TRUE(low->matches_at(window<1>({0xA5})));
    EXPECT_TRUE(low->matches_at(window<1>({0x05})));
    EXPECT_FALSE(low->matches_at(window<1>({0xA6})));

    // A nibble-only pattern has no fully-known byte to anchor on.
    EXPECT_FALSE(high->has_anchor());
    EXPECT_FALSE(low->has_anchor());
}

TEST(Pattern, OffsetMarkerRecordsPointOfInterest)
{
    const auto mid = scan::Pattern::compile("48 8B | 05 E8");
    ASSERT_TRUE(mid.has_value());
    EXPECT_EQ(mid->size(), 4U);
    EXPECT_EQ(mid->offset(), 2U);

    // A trailing marker records one past the last byte.
    const auto trailing = scan::Pattern::compile("48 8B |");
    ASSERT_TRUE(trailing.has_value());
    EXPECT_EQ(trailing->size(), 2U);
    EXPECT_EQ(trailing->offset(), 2U);

    // No marker leaves the offset at the match start.
    const auto none = scan::Pattern::compile("48 8B");
    ASSERT_TRUE(none.has_value());
    EXPECT_EQ(none->offset(), 0U);
}

TEST(Pattern, AnchorSelectsRarestFullyKnownByte)
{
    // 0x8B (frequency class 7) is rarer than 0x48 (class 8), so it wins over the leading REX prefix.
    const auto rex_lead = scan::Pattern::compile("48 8B");
    ASSERT_TRUE(rex_lead.has_value());
    EXPECT_TRUE(rex_lead->has_anchor());
    EXPECT_EQ(rex_lead->anchor_index(), 1U);
    EXPECT_EQ(rex_lead->anchor_byte(), std::byte{0x8B});

    // An uncommon byte (class 0) beats any tabled opcode regardless of position.
    const auto rare = scan::Pattern::compile("48 8B 05");
    ASSERT_TRUE(rare.has_value());
    EXPECT_EQ(rare->anchor_index(), 2U);
    EXPECT_EQ(rare->anchor_byte(), std::byte{0x05});

    // An all-wildcard pattern has no anchor at all.
    const auto wildcard = scan::Pattern::compile("?? ?? ??");
    ASSERT_TRUE(wildcard.has_value());
    EXPECT_FALSE(wildcard->has_anchor());
    EXPECT_EQ(wildcard->anchor_byte(), std::byte{0x00});
}

TEST(Pattern, MatchesAtAppliesMaskedCompare)
{
    const auto pattern = scan::Pattern::compile("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    EXPECT_TRUE(pattern->matches_at(window<3>({0x48, 0x8B, 0x05})));
    EXPECT_FALSE(pattern->matches_at(window<3>({0x48, 0x8B, 0x06})));

    // A window shorter than the pattern can never match.
    EXPECT_FALSE(pattern->matches_at(window<2>({0x48, 0x8B})));

    // A longer window matches as long as the leading bytes agree.
    EXPECT_TRUE(pattern->matches_at(window<5>({0x48, 0x8B, 0x05, 0xCC, 0xCC})));
}

TEST(Pattern, BytesAndMaskExposeCompiledForm)
{
    const auto pattern = scan::Pattern::compile("48 ?? 4? ?5");
    ASSERT_TRUE(pattern.has_value());

    const std::span<const std::byte> bytes = pattern->bytes();
    const std::span<const std::byte> mask = pattern->mask();
    ASSERT_EQ(bytes.size(), 4U);
    ASSERT_EQ(mask.size(), 4U);

    EXPECT_EQ(bytes[0], std::byte{0x48});
    EXPECT_EQ(mask[0], std::byte{0xFF});
    EXPECT_EQ(mask[1], std::byte{0x00});
    EXPECT_EQ(bytes[2], std::byte{0x40});
    EXPECT_EQ(mask[2], std::byte{0xF0});
    EXPECT_EQ(bytes[3], std::byte{0x05});
    EXPECT_EQ(mask[3], std::byte{0x0F});
}
