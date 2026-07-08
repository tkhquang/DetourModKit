#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

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

// Compile-time proof that a bounded jump parses and reports its segmentation during constant evaluation.
static_assert(scan::Pattern::literal("48 8B [2-5] E8").has_jumps());
static_assert(scan::Pattern::literal("48 8B [2-5] E8").segment_count() == 2);
static_assert(scan::Pattern::literal("48 8B [2-5] E8").size() == 3);             // fixed bytes only: 48 8B E8
static_assert(scan::Pattern::literal("48 8B [2-5] E8").min_match_length() == 5); // 3 fixed + 2 min gap
static_assert(scan::Pattern::literal("48 8B [2-5] E8").max_match_length() == 8); // 3 fixed + 5 max gap
// A jump-free pattern reports one segment and equal min / max span, so nothing about the plain case shifts.
static_assert(scan::Pattern::literal("48 8B 05").segment_count() == 1);
static_assert(!scan::Pattern::literal("48 8B 05").has_jumps());
static_assert(scan::Pattern::literal("48 8B 05").min_match_length() == 3);
static_assert(scan::Pattern::literal("48 8B 05").max_match_length() == 3);
// A bounded jump literal is usable in matches_at during constant evaluation (the same backtracking search). The window
// is a named constexpr array so the span binds to an lvalue.
inline constexpr std::array<std::byte, 3> kJumpMatchWindow = {std::byte{0xAA}, std::byte{0x00}, std::byte{0xBB}};
static_assert(scan::Pattern::literal("AA [1-2] BB").matches_at(kJumpMatchWindow));
// A worked two-instruction example: 12 fixed bytes (7 in segment 0, 5 in segment 1) framing a 2-to-6-byte gap, so a
// match spans 14 to 18 bytes. Pins the multi-segment span arithmetic so the documented figures cannot drift.
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ?? [2-6] E8 ?? ?? ?? ??").segment_count() == 2);
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ?? [2-6] E8 ?? ?? ?? ??").size() == 12);
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ?? [2-6] E8 ?? ?? ?? ??").min_match_length() == 14);
static_assert(scan::Pattern::literal("48 8B 05 ?? ?? ?? ?? [2-6] E8 ?? ?? ?? ??").max_match_length() == 18);

TEST(PatternJumps, CompileParsesBoundedJump)
{
    const auto p = scan::Pattern::compile("48 8B [2-5] E8");
    ASSERT_TRUE(p.has_value());
    EXPECT_TRUE(p->has_jumps());
    EXPECT_EQ(p->segment_count(), 2U);
    EXPECT_EQ(p->size(), 3U);
    EXPECT_EQ(p->min_match_length(), 5U);
    EXPECT_EQ(p->max_match_length(), 8U);
    // The anchor stays in segment 0: 0x8B (class 7) beats 0x48 (class 8); the rarer 0xE8 in segment 1 is never chosen.
    EXPECT_TRUE(p->has_anchor());
    EXPECT_EQ(p->anchor_index(), 1U);
    EXPECT_EQ(p->anchor_byte(), std::byte{0x8B});

    const detail::PatternParse parsed = detail::parse_pattern("48 8B [2-5] E8");
    ASSERT_EQ(parsed.status, detail::PatternStatus::Ok);
    ASSERT_EQ(parsed.buffer.jump_count, 1U);
    EXPECT_EQ(parsed.buffer.jumps[0].position, 2U);
    EXPECT_EQ(parsed.buffer.jumps[0].min_skip, 2U);
    EXPECT_EQ(parsed.buffer.jumps[0].max_skip, 5U);
}

TEST(PatternJumps, ExactJumpShorthand)
{
    const auto p = scan::Pattern::compile("AA [3] BB");
    ASSERT_TRUE(p.has_value());
    EXPECT_TRUE(p->has_jumps());
    EXPECT_EQ(p->segment_count(), 2U);
    EXPECT_EQ(p->min_match_length(), p->max_match_length());
    EXPECT_EQ(p->min_match_length(), 5U); // 2 fixed + exactly 3 gap
}

TEST(PatternJumps, MatchesAtHonorsVariableGap)
{
    const auto p = scan::Pattern::compile("AA BB [1-3] CC");
    ASSERT_TRUE(p.has_value());

    EXPECT_TRUE(p->matches_at(window<4>({0xAA, 0xBB, 0x99, 0xCC})));                    // gap 1
    EXPECT_TRUE(p->matches_at(window<5>({0xAA, 0xBB, 0x11, 0x22, 0xCC})));              // gap 2
    EXPECT_TRUE(p->matches_at(window<6>({0xAA, 0xBB, 0x11, 0x22, 0x33, 0xCC})));        // gap 3
    EXPECT_FALSE(p->matches_at(window<3>({0xAA, 0xBB, 0xCC})));                         // gap 0 < min
    EXPECT_FALSE(p->matches_at(window<7>({0xAA, 0xBB, 0x11, 0x22, 0x33, 0x44, 0xCC}))); // gap 4 > max
    EXPECT_FALSE(p->matches_at(window<4>({0xAB, 0xBB, 0x99, 0xCC})));                   // leading mismatch
}

TEST(PatternJumps, MatchesAtBacktracksStrandedSegment)
{
    // The first B0 placement strands the final C0; matches_at must backtrack to the second B0.
    const auto p = scan::Pattern::compile("A0 [0-3] B0 [0-1] C0");
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->segment_count(), 3U);
    EXPECT_TRUE(p->matches_at(window<5>({0xA0, 0xB0, 0x11, 0xB0, 0xC0})));
    // No C0 reachable after any B0 placement: no match.
    EXPECT_FALSE(p->matches_at(window<5>({0xA0, 0xB0, 0x11, 0xB0, 0x99})));
}

TEST(PatternJumps, MatchesAtWorkBudgetCapsPathologicalBacktracking)
{
    const auto p = scan::Pattern::compile("A5 [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? "
                                          "[0-255] ?? [0-255] FF");
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->segment_count(), detail::MAX_PATTERN_JUMPS + 1);

    // This is the same pathological placement shape the runtime scanner guards: one literal leading segment, then the
    // widest admitted set of wildcard gaps, and no terminal 0xFF anywhere. matches_at checks only this one start
    // position, so the shared per-position budget must stop the otherwise product-sized search and return a clean miss.
    // The asserted miss is the correct answer with OR without the cap (the region has no 0xFF), so this test proves the
    // cap by TERMINATING quickly: with the budget removed the single-position search fans out toward the gap-span
    // product and the case hangs until the ctest timeout fails it, rather than tripping the assertion below.
    std::vector<std::byte> bytes(3072, std::byte{0x00});
    bytes[0] = std::byte{0xA5};

    EXPECT_FALSE(p->matches_at(bytes));
}

TEST(PatternJumps, RejectsMalformedAndIllegalJumps)
{
    EXPECT_FALSE(scan::Pattern::compile("[2-5] 48").has_value());          // leading jump
    EXPECT_FALSE(scan::Pattern::compile("48 [2-5]").has_value());          // trailing jump
    EXPECT_FALSE(scan::Pattern::compile("48 [1-2] [3-4] 8B").has_value()); // consecutive jumps
    EXPECT_FALSE(scan::Pattern::compile("48 [5-2] 8B").has_value());       // inverted range
    EXPECT_FALSE(scan::Pattern::compile("48 [2-] 8B").has_value());        // unbounded, not this dialect
    EXPECT_FALSE(scan::Pattern::compile("48 [2 8B").has_value());          // missing close bracket
    EXPECT_FALSE(scan::Pattern::compile("48 [] 8B").has_value());          // empty brackets
    EXPECT_FALSE(scan::Pattern::compile("48 [x-y] 8B").has_value());       // non-decimal

    // The specific parse status rides in the Error's extra slot, so a caller can tell a bad jump from another failure.
    const auto inverted = scan::Pattern::compile("48 [5-2] 8B");
    ASSERT_FALSE(inverted.has_value());
    EXPECT_EQ(inverted.error().code, ErrorCode::BadPattern);
    EXPECT_EQ(inverted.error().extra, static_cast<std::uint32_t>(detail::PatternStatus::InvalidJump));
}

TEST(PatternJumps, RejectsTooManyJumps)
{
    // Exactly MAX_PATTERN_JUMPS gaps compiles; one more fails closed with the TooManyJumps status.
    std::string at_cap = "00";
    for (std::size_t i = 0; i < detail::MAX_PATTERN_JUMPS; ++i)
    {
        at_cap += " [1] 00";
    }
    const auto ok = scan::Pattern::compile(at_cap);
    ASSERT_TRUE(ok.has_value());
    EXPECT_EQ(ok->segment_count(), detail::MAX_PATTERN_JUMPS + 1);

    std::string over_cap = "00";
    for (std::size_t i = 0; i < detail::MAX_PATTERN_JUMPS + 1; ++i)
    {
        over_cap += " [1] 00";
    }
    const auto over = scan::Pattern::compile(over_cap);
    ASSERT_FALSE(over.has_value());
    EXPECT_EQ(over.error().extra, static_cast<std::uint32_t>(detail::PatternStatus::TooManyJumps));
}

TEST(PatternJumps, JumpBoundIsCapped)
{
    // A gap upper bound within MAX_JUMP_SPAN compiles; one above it is rejected as an invalid jump.
    EXPECT_TRUE(scan::Pattern::compile("AA [1-" + std::to_string(detail::MAX_JUMP_SPAN) + "] BB").has_value());
    EXPECT_FALSE(scan::Pattern::compile("AA [1-" + std::to_string(detail::MAX_JUMP_SPAN + 1) + "] BB").has_value());
}
