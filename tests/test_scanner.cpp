#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "DetourModKit/scan.hpp"

// White-box engine tests: the raw matcher, page walks, and batch live in the private engine.
#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "test_alloc_probe.hpp"

// windows.h included after project headers to avoid macro conflicts (e.g., 'small')
#include <windows.h>
#ifdef small
#undef small
#endif

using namespace DetourModKit;

namespace
{
    // Thin shape adapters so the engine white-box tests below drive one fixed call shape: the page-gated whole-process
    // scans return a MatchResult (the .match pointer plus an incomplete-scan flag), and the prologue gate takes an
    // Address. Pure shape adapters with no behaviour of their own.
    [[nodiscard]] inline const std::byte *scan_exec(const detail::EnginePattern &pattern,
                                                    std::size_t occurrence = 1) noexcept
    {
        return detail::scan_executable_regions(pattern, detail::ScanQuery{occurrence}).match;
    }
    [[nodiscard]] inline const std::byte *scan_read(const detail::EnginePattern &pattern,
                                                    std::size_t occurrence = 1) noexcept
    {
        return detail::scan_readable_regions(pattern, detail::ScanQuery{occurrence}).match;
    }
    [[nodiscard]] inline bool is_likely_prologue(std::uintptr_t address) noexcept
    {
        return scan::is_likely_function_prologue(Address{address});
    }
    // resolve_rip_relative / find_and_resolve_rip_relative take an Address / Region; these adapters let the tests drive
    // them from a raw pointer (+ length) by building the Address / Region scope types in one place.
    [[nodiscard]] inline Result<Address> resolve_rip(const std::byte *instruction, std::size_t displacement_offset,
                                                     std::size_t instruction_length) noexcept
    {
        return scan::resolve_rip_relative(Address{instruction}, displacement_offset, instruction_length);
    }
    [[nodiscard]] inline Result<Address> find_and_resolve_rip(const std::byte *search_start, std::size_t search_length,
                                                              std::span<const std::byte> opcode_prefix,
                                                              std::size_t instruction_length) noexcept
    {
        return scan::find_and_resolve_rip_relative(Region{Address{search_start}, search_length}, opcode_prefix,
                                                   instruction_length);
    }
} // namespace

TEST(ScannerTest, parse_aob_valid)
{
    auto result = detail::parse_aob("48 8B 05 ?? ?? ?? ??");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 7);
}

TEST(ScannerTest, parse_aob_all_wildcards)
{
    auto result = detail::parse_aob("?? ?? ??");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3);
}

TEST(ScannerTest, parse_aob_empty)
{
    auto result = detail::parse_aob("");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, find_pattern_found)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[100] = std::byte{0x48};
    data[101] = std::byte{0x8B};
    data[102] = std::byte{0x05};

    auto pattern = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

TEST(ScannerTest, find_pattern_span_overload)
{
    std::vector<std::byte> data(128, std::byte{0x00});
    data[40] = std::byte{0xAA};
    data[41] = std::byte{0xBB};
    data[42] = std::byte{0xCC};
    // A second occurrence so the Nth-occurrence span overload has something to find.
    data[90] = std::byte{0xAA};
    data[91] = std::byte{0xBB};
    data[92] = std::byte{0xCC};

    auto pattern = detail::parse_aob("AA BB CC");
    ASSERT_TRUE(pattern.has_value());

    const std::span<const std::byte> region{data};

    // The span overload must return the identical pointer as the pointer+size form.
    const std::byte *via_span = detail::find_pattern(region, *pattern);
    const std::byte *via_ptr = detail::find_pattern(data.data(), data.size(), *pattern);
    EXPECT_EQ(via_span, via_ptr);
    ASSERT_NE(via_span, nullptr);
    EXPECT_EQ(via_span - data.data(), 40);

    // The Nth-occurrence span overload mirrors the pointer+size form too.
    const std::byte *second_span = detail::find_pattern(region, *pattern, 2);
    const std::byte *second_ptr = detail::find_pattern(data.data(), data.size(), *pattern, 2);
    EXPECT_EQ(second_span, second_ptr);
    ASSERT_NE(second_span, nullptr);
    EXPECT_EQ(second_span - data.data(), 90);

    // An empty span yields nullptr.
    EXPECT_EQ(detail::find_pattern(std::span<const std::byte>{}, *pattern), nullptr);
}

namespace
{
    // Builds a byte buffer from raw byte values so the jump-matcher tests read as the bytes a scan would see.
    [[nodiscard]] std::vector<std::byte> bytes_of(std::initializer_list<unsigned char> raw)
    {
        std::vector<std::byte> out;
        out.reserve(raw.size());
        for (const unsigned char b : raw)
        {
            out.push_back(std::byte{b});
        }
        return out;
    }
} // namespace

// The unified parser accepts bounded jumps at the engine layer too, because parse_aob now delegates to the same
// constexpr core scan::Pattern uses. The gap is recorded as a segment boundary; the fixed byte count excludes gap
// bytes.
TEST(ScannerJumpsTest, ParseAobAcceptsBoundedJump)
{
    auto p = detail::parse_aob("48 8B [2-5] E8");
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->size(), 3U); // fixed bytes only: 48 8B E8
    ASSERT_EQ(p->jumps.size(), 1U);
    EXPECT_EQ(p->jumps[0].position, 2U);
    EXPECT_EQ(p->jumps[0].min_skip, 2U);
    EXPECT_EQ(p->jumps[0].max_skip, 5U);
    EXPECT_EQ(p->min_match_length(), 5U);
    EXPECT_EQ(p->max_match_length(), 8U);
    // The anchor is confined to segment 0 (index 1 = 0x8B), never the rarer 0xE8 that sits in segment 1.
    EXPECT_EQ(p->anchor, 1U);
}

// Every illegal jump placement / form fails the shared parser, so parse_aob returns nullopt rather than a broken engine
// pattern.
TEST(ScannerJumpsTest, ParseAobRejectsBadJumps)
{
    EXPECT_FALSE(detail::parse_aob("[2-5] 48").has_value());      // leading jump
    EXPECT_FALSE(detail::parse_aob("48 [2-5]").has_value());      // trailing jump
    EXPECT_FALSE(detail::parse_aob("48 [1] [2] 8B").has_value()); // consecutive jumps
    EXPECT_FALSE(detail::parse_aob("48 [5-2] 8B").has_value());   // inverted range
    EXPECT_FALSE(detail::parse_aob("48 [2-] 8B").has_value());    // unbounded (bounded dialect only)
    EXPECT_FALSE(detail::parse_aob("48 [2 8B").has_value());      // missing close bracket
    EXPECT_FALSE(detail::parse_aob("48 [] 8B").has_value());      // empty brackets
}

// The segmented matcher finds a signature whose two fixed runs are separated by a run-time-variable gap.
TEST(ScannerJumpsTest, FindsMatchAcrossVariableGap)
{
    const auto data = bytes_of({0x00, 0x00, 0x11, 0x22, 0xAA, 0xBB, 0xCC, 0x00}); // gap of 2 (AA BB) between 22 and CC
    const auto p = detail::parse_aob("11 22 [1-3] CC");
    ASSERT_TRUE(p.has_value());
    const std::byte *m = detail::find_pattern(data.data(), data.size(), *p);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m - data.data(), 2); // match starts at the 0x11
}

// A gap smaller than the pattern's minimum skip is not a match.
TEST(ScannerJumpsTest, GapBelowMinDoesNotMatch)
{
    const auto data = bytes_of({0x11, 0x22, 0xCC, 0x00, 0x00}); // CC immediately after 22: gap 0 < min 1
    const auto p = detail::parse_aob("11 22 [1-3] CC");
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(detail::find_pattern(data.data(), data.size(), *p), nullptr);
}

// Backtracking: the first placement of a middle segment can strand a later one, so the matcher must try a farther gap
// position that lets the whole ladder fit.
TEST(ScannerJumpsTest, BacktracksStrandedMiddleSegment)
{
    // A0 [0-3] B0 [0-1] C0 : the B0 at gap 0 leaves no C0 within [0-1] after it; the B0 at gap 2 does.
    const auto data = bytes_of({0xA0, 0xB0, 0x11, 0xB0, 0xC0, 0x00});
    const auto p = detail::parse_aob("A0 [0-3] B0 [0-1] C0");
    ASSERT_TRUE(p.has_value());
    const std::byte *m = detail::find_pattern(data.data(), data.size(), *p);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m - data.data(), 0);
}

// The `|` marker resolves through the actual gap bytes, so its result address includes the gap width chosen at match
// time (not just the fixed offset).
TEST(ScannerJumpsTest, OffsetMarkerResolvesThroughGap)
{
    // "11 22 [2] | 33": start + 2 fixed + 2 gap = the 0x33 at index 4.
    const auto data = bytes_of({0x11, 0x22, 0xAA, 0xBB, 0x33, 0x00});
    const auto p = detail::parse_aob("11 22 [2] | 33");
    ASSERT_TRUE(p.has_value());
    const std::byte *m = detail::find_pattern(data.data(), data.size(), *p);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m - data.data(), 4); // points at 0x33

    const auto before_jump = detail::parse_aob("11 22 | [2] 33");
    ASSERT_TRUE(before_jump.has_value());
    const std::byte *before_jump_match = detail::find_pattern(data.data(), data.size(), *before_jump);
    ASSERT_NE(before_jump_match, nullptr);
    EXPECT_EQ(before_jump_match - data.data(), 4);
}

// Ascending gap widths make the nearest placement win, so a marker after the gap resolves to the closest matching run.
TEST(ScannerJumpsTest, LeftmostGapPlacementWins)
{
    // "AA [0-3] | BB": two BBs reachable (gap 1 and gap 3); the marker resolves to the nearer one (index 2).
    const auto data = bytes_of({0xAA, 0x00, 0xBB, 0x00, 0xBB, 0x00});
    const auto p = detail::parse_aob("AA [0-3] | BB");
    ASSERT_TRUE(p.has_value());
    const std::byte *m = detail::find_pattern(data.data(), data.size(), *p);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m - data.data(), 2);
}

// Nth-occurrence works for jump patterns: the continuation advances past each match START.
TEST(ScannerJumpsTest, NthOccurrenceWithGap)
{
    const auto data = bytes_of({0xAA, 0x00, 0xBB, 0x00, 0xAA, 0x00, 0x00, 0xBB, 0x00});
    const auto p = detail::parse_aob("AA [1-2] BB");
    ASSERT_TRUE(p.has_value());
    const std::byte *first = detail::find_pattern(data.data(), data.size(), *p, 1);
    const std::byte *second = detail::find_pattern(data.data(), data.size(), *p, 2);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(first - data.data(), 0);
    EXPECT_EQ(second - data.data(), 4);
}

// Segment 0 without a literal anchor (nibble-only) falls back to scanning every start position and still matches.
TEST(ScannerJumpsTest, SegmentZeroWithoutLiteralAnchor)
{
    const auto data = bytes_of({0x00, 0x4A, 0x99, 0xCC, 0x00});
    const auto p = detail::parse_aob("4? [1-2] CC"); // seg0 "4?" carries no fully-known byte
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->anchor, p->size()); // no anchor sentinel
    const std::byte *m = detail::find_pattern(data.data(), data.size(), *p);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m - data.data(), 1); // 0x4A matches 4?
}

// A multi-gap pattern with an all-wildcard leading segment drives the worst-case matcher shape: no anchor forces an
// iterate-every-start sweep, and each start explores the product of the gap spans (no memoization). This pins that the
// shape TERMINATES and is CORRECT -- a miss returns nullptr after exhausting every start x skip combination, and a
// reachable target is still found -- documenting that the cost is bounded in depth but combinatorial in work.
TEST(ScannerJumpsTest, MultiGapExhaustiveBacktrackingTerminates)
{
    const auto p = detail::parse_aob("?? [0-3] ?? [0-3] FF");
    ASSERT_TRUE(p.has_value());

    // No 0xFF anywhere: every start and every gap combination is explored and rejected, and the scan still returns.
    std::vector<std::byte> miss(64, std::byte{0x00});
    EXPECT_EQ(detail::find_pattern(miss.data(), miss.size(), *p), nullptr);

    // A single 0xFF reachable only by the widest gaps (offset 2 + 3 + 3 = 8) is still found from the first start.
    std::vector<std::byte> hit(64, std::byte{0x00});
    hit[8] = std::byte{0xFF};
    const std::byte *m = detail::find_pattern(hit.data(), hit.size(), *p);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m - hit.data(), 0);
}

// The segmented matcher caps per-position backtracking with a work budget. Eight maximum-width gaps between
// all-wildcard segments give a per-position worst case of roughly 256^8 combinations; without the budget a single
// anchor position over a large enough region would hang. The literal segment-0 anchor appears exactly once, so exactly
// one extension tree runs; the budget bounds it and the guaranteed miss returns promptly. The region carries no 0xFF,
// so the correct answer is a clean no-match.
TEST(ScannerJumpsTest, MultiGapWorkBudgetCapsPathologicalBacktracking)
{
    const auto p = detail::parse_aob("A5 [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? "
                                     "[0-255] FF");
    ASSERT_TRUE(p.has_value());
    ASSERT_EQ(p->jumps.size(), 8u); // MAX_PATTERN_JUMPS: the widest gap count the grammar admits.

    // 3 KiB of zeros with a lone anchor byte and no 0xFF anywhere: the extension from the single A5 must explore (and,
    // absent the budget, exhaustively backtrack) the full gap product before failing. The region is large enough that
    // the gaps can try their full 256-byte span, so the un-budgeted worst case is genuinely astronomical. The asserted
    // no-match is the correct answer either way, so the cap is proven by TERMINATION: revert it and this case hangs
    // until the ctest timeout fails it, rather than tripping the assertion below.
    std::vector<std::byte> region(3072, std::byte{0x00});
    region[0] = std::byte{0xA5};

    EXPECT_EQ(detail::find_pattern(region.data(), region.size(), *p), nullptr);
}

// Spending the backtracking budget is not the same as proving no match. When the segmented matcher cuts a sweep short
// at its per-position or region-wide budget, it MUST surface RawMatch::budget_exhausted so a caller counting
// occurrences fails closed rather than treating the truncated no-match as a proven absence (a page-gated uniqueness
// check would otherwise present a lower bound as complete). The pathological pattern below drives a single extension
// tree straight past the per-position budget.
TEST(ScannerJumpsTest, BudgetExhaustionIsSignalledOnRawMatch)
{
    const auto p = detail::parse_aob("A5 [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? "
                                     "[0-255] FF");
    ASSERT_TRUE(p.has_value());

    std::vector<std::byte> region(3072, std::byte{0x00});
    region[0] = std::byte{0xA5}; // the lone segment-0 anchor; no 0xFF, so every gap combination is explored and fails

    detail::SegmentedScanBudget budget{};
    const detail::RawMatch match = detail::find_pattern_raw(region.data(), region.size(), *p, &budget);
    EXPECT_EQ(match.start, nullptr);     // no confident match ...
    EXPECT_TRUE(match.budget_exhausted); // ... but the truncation is surfaced, not hidden as a clean miss
    EXPECT_EQ(budget.node_visits, detail::SEGMENT_MATCH_STEP_BUDGET);
}

// Positive control: an ordinary candidate that enters the segmented matcher and cleanly misses well within the budget
// must NOT flag exhaustion, so a genuine no-match stays distinguishable from a truncated one.
TEST(ScannerJumpsTest, BudgetNotExhaustedForOrdinaryPattern)
{
    const auto p = detail::parse_aob("AA BB [0-4] CC");
    ASSERT_TRUE(p.has_value());

    std::vector<std::byte> region(64, std::byte{0x00});
    region[0] = std::byte{0xAA};
    region[1] = std::byte{0xBB}; // segment 0 matches, then every bounded-gap placement cleanly misses on CC
    const detail::RawMatch miss = detail::find_pattern_raw(region.data(), region.size(), *p);
    EXPECT_EQ(miss.start, nullptr);
    EXPECT_FALSE(miss.budget_exhausted);
}

// Reaching a per-position ceiling on the final feasible branch is exhaustive, not a truncation. This shape visits
// exactly 1 + 255 + 255 * 256 == SEGMENT_MATCH_STEP_BUDGET nodes without finding FF, so the raw result must preserve
// a confident no-match and the counter must never exceed the ceiling.
TEST(ScannerJumpsTest, ExactPerPositionBudgetCompletesExhaustiveMiss)
{
    const auto pattern = detail::parse_aob("A5 [0-254] ?? [0-255] FF");
    ASSERT_TRUE(pattern.has_value());

    std::vector<std::byte> region(512, std::byte{0x00});
    region[0] = std::byte{0xA5};

    detail::SegmentedScanBudget budget{};
    const detail::RawMatch miss = detail::find_pattern_raw(region.data(), region.size(), *pattern, &budget);
    EXPECT_EQ(miss.start, nullptr);
    EXPECT_FALSE(miss.budget_exhausted);
    EXPECT_EQ(budget.node_visits, detail::SEGMENT_MATCH_STEP_BUDGET);
    EXPECT_FALSE(budget.region_exhausted);
}

// An exact-budget exhaustive miss at an earlier anchor must not hide a later valid match. The second A5 can only form
// the short [0-254]/[0-255] placement at the tail, so returning it proves the outer sweep continued after the first
// candidate used its full per-position allowance without being marked incomplete.
TEST(ScannerJumpsTest, ExactPerPositionBudgetAllowsLaterMatch)
{
    const auto pattern = detail::parse_aob("A5 [0-254] ?? [0-255] FF");
    ASSERT_TRUE(pattern.has_value());

    std::vector<std::byte> region(523, std::byte{0x00});
    region[0] = std::byte{0xA5};
    region[520] = std::byte{0xA5};
    region[522] = std::byte{0xFF};

    const detail::RawMatch raw = detail::find_pattern_raw(region.data(), region.size(), *pattern);
    ASSERT_EQ(raw.start, region.data() + 520);
    EXPECT_FALSE(raw.budget_exhausted);
    EXPECT_EQ(detail::find_pattern(region.data(), region.size(), *pattern), region.data() + 520);
}

// The page-gated scan must carry budget exhaustion up to MatchResult, on its own channel rather than folded into the
// faulted-region signal, and the public scan must map it to ErrorCode::BudgetExceeded. A later real match must still
// carry the flag, so its address is not mistaken for a proven first occurrence. This exercises the end-to-end plumbing
// (find_pattern_raw -> scan_region_for_match -> scan_region_guarded -> scan_regions_filtered -> MatchResult).
TEST(ScannerJumpsTest, PageGatedScanPropagatesBudgetExhaustionAsBudgetExceeded)
{
    const auto p = detail::parse_aob("A5 [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? "
                                     "[0-255] FF");
    ASSERT_TRUE(p.has_value());

    void *base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(base, nullptr);
    std::memset(base, 0x00, 0x1000);
    auto *const bytes = static_cast<std::uint8_t *>(base);
    bytes[0] = 0xA5;    // first anchor: its reachable range contains no 0xFF, so it exhausts the per-position budget
    bytes[2600] = 0xA5; // later anchor, beyond the first anchor's maximum reach
    bytes[2608] = 0xFF; // a genuine later match through the all-minimum gap placement

    const detail::ModuleSpan range{reinterpret_cast<std::uintptr_t>(base),
                                   reinterpret_cast<std::uintptr_t>(base) + 0x1000};
    const detail::MatchResult result = detail::scan_module_readable(*p, range, detail::ScanQuery{.occurrence = 1});
    EXPECT_EQ(result.match, reinterpret_cast<const std::byte *>(bytes + 2600));
    // Budget exhaustion surfaces alongside the later match, never as a confident hit, and it is reported on its own
    // channel: a caller can tell an over-broad pattern from a concurrent unmap of the scanned range.
    EXPECT_TRUE(result.budget_exhausted);
    EXPECT_FALSE(result.incomplete);
    EXPECT_TRUE(result.truncated());

    const auto public_pattern = scan::Pattern::compile(
        "A5 [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] FF");
    ASSERT_TRUE(public_pattern.has_value());
    const Region scope{Address{reinterpret_cast<std::uintptr_t>(base)}, 0x1000};
    const auto public_result = scan::scan(*public_pattern, scope, 1, scan::Pages::Readable);
    ASSERT_FALSE(public_result.has_value());
    EXPECT_EQ(public_result.error().code, ErrorCode::BudgetExceeded);

    VirtualFree(base, 0, MEM_RELEASE);
}

// The raw pointer APIs have no incomplete result channel. If an earlier placement exhausts the bounded-jump budget and
// a later placement matches, they must return nullptr rather than present the later address as the first occurrence.
TEST(ScannerJumpsTest, UncheckedScanFailsClosedOnBudgetExhaustion)
{
    const auto pattern = scan::Pattern::compile(
        "A5 [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] FF");
    ASSERT_TRUE(pattern.has_value());

    std::vector<std::byte> region(4096, std::byte{0x00});
    region[0] = std::byte{0xA5};
    region[2600] = std::byte{0xA5};
    region[2608] = std::byte{0xFF};

    const std::size_t anchor = pattern->has_anchor() ? pattern->anchor_index() : pattern->size();
    const detail::EnginePattern engine = detail::engine_pattern_from(*pattern, anchor);
    const detail::RawMatch raw = detail::find_pattern_raw(region.data(), region.size(), engine);
    ASSERT_NE(raw.start, nullptr);
    ASSERT_TRUE(raw.budget_exhausted);

    EXPECT_EQ(detail::find_pattern(region.data(), region.size(), engine), nullptr);
    const Region scope{Address{region.data()}, region.size()};
    EXPECT_EQ(scan::unchecked::find_pattern(scope, *pattern), nullptr);
}

// Nth-occurrence scans restart at the byte after each prior match. The shared work state must survive that real suffix
// loop: after the first two-node match consumes the final two visits, the second suffix must fail closed rather than
// reset the region budget and return the second match.
TEST(ScannerJumpsTest, SharedRegionBudgetPersistsAcrossNthSuffixScan)
{
    const auto pattern = detail::parse_aob("A5 [0] FF");
    ASSERT_TRUE(pattern.has_value());

    detail::SegmentedScanBudget budget{.node_visits = detail::SEGMENT_MATCH_REGION_STEP_BUDGET - 2};
    const std::array<std::byte, 4> two_matches = {std::byte{0xA5}, std::byte{0xFF}, std::byte{0xA5}, std::byte{0xFF}};
    const std::byte *const second =
        detail::find_pattern_nth(two_matches.data(), two_matches.size(), *pattern, /*occurrence=*/2, budget);
    EXPECT_EQ(second, nullptr);
    EXPECT_EQ(budget.node_visits, detail::SEGMENT_MATCH_REGION_STEP_BUDGET);
    EXPECT_TRUE(budget.region_exhausted);
}

// The runtime AOB parser grows a heap-backed pattern, so an allocation failure mid-parse must fail closed to nullopt
// rather than terminate. parse_pattern_into is intentionally not noexcept, and parse_aob catches bad_alloc; without
// that, the bad_alloc would cross a noexcept boundary and std::terminate would abort this process.
TEST(ScannerTest, parse_aob_allocation_failure_fails_soft)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    dmk_test::AllocFailScope fail(0); // fail every allocation the parse attempts, starting with the first push_back
    const auto result = detail::parse_aob("48 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ??");
    EXPECT_FALSE(result.has_value());
}

// The runtime engine parser and the compile-time value parser are one and the same, so both produce an identical
// segmentation, and engine_pattern_from carries the jumps over from a value Pattern.
TEST(ScannerJumpsTest, ParserUnifiedWithPatternCore)
{
    const char *dsl = "48 8B [2-5] E8 ?? ?? ?? ??";
    const auto engine = detail::parse_aob(dsl);
    const auto value = scan::Pattern::compile(dsl);
    ASSERT_TRUE(engine.has_value());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(engine->size(), value->size());
    EXPECT_EQ(static_cast<std::size_t>(engine->offset), value->offset());
    const detail::PatternBuffer &value_buffer = detail::pattern_buffer(*value);
    ASSERT_EQ(engine->jumps.size(), value_buffer.jump_count);
    for (std::size_t i = 0; i < engine->jumps.size(); ++i)
    {
        EXPECT_EQ(engine->jumps[i].position, value_buffer.jumps[i].position);
        EXPECT_EQ(engine->jumps[i].min_skip, value_buffer.jumps[i].min_skip);
        EXPECT_EQ(engine->jumps[i].max_skip, value_buffer.jumps[i].max_skip);
    }
    const std::size_t anchor = value->has_anchor() ? value->anchor_index() : value->size();
    const detail::EnginePattern via_value = detail::engine_pattern_from(*value, anchor);
    EXPECT_EQ(via_value.jumps.size(), engine->jumps.size());
}

// The page-gated whole-process readable sweep (the path public scan() takes) drives the segmented matcher through
// find_pattern_raw, so a jump-bearing signature planted in a readable static is found end-to-end.
TEST(ScannerJumpsTest, PageGatedScanFindsJumpPattern)
{
    static const unsigned char kBlob[] = {0x63, 0x1C, 0xB4, 0x2F, 0x88, 0xD6, 0x00, 0x00, 0x5A, 0x91, 0x07, 0xE3};
    const auto p = detail::parse_aob("63 1C B4 2F 88 D6 [1-4] 5A 91 07 E3");
    ASSERT_TRUE(p.has_value());
    const std::byte *m = scan_read(*p);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(reinterpret_cast<const unsigned char *>(m), kBlob);
}

// The runtime engine parser shares the compile-time grammar but not its fixed-array cap: a pattern longer than
// MAX_PATTERN_BYTES (which the value Pattern rejects as TooLong) still compiles and scans at run time, preserving
// long-string-xref patterns built from large string literals.
TEST(ScannerJumpsTest, RuntimeParserAcceptsPatternLongerThanLiteralCap)
{
    static constexpr char kHex[] = "0123456789ABCDEF";
    const std::size_t long_len = detail::MAX_PATTERN_BYTES + 8;
    std::string aob;
    std::vector<std::byte> needle;
    needle.reserve(long_len);
    for (std::size_t i = 0; i < long_len; ++i)
    {
        // A dense, zero-free byte run so it is unique against the zero padding below (i < 219 never yields 0x00).
        const auto b = static_cast<unsigned char>((i * 7 + 3) & 0xFF);
        aob += kHex[b >> 4];
        aob += kHex[b & 0x0F];
        aob += ' ';
        needle.push_back(std::byte{b});
    }

    // Runtime engine parser: uncapped heap storage accepts the long pattern.
    const auto engine = detail::parse_aob(aob);
    ASSERT_TRUE(engine.has_value());
    EXPECT_EQ(engine->size(), long_len);

    // Value Pattern: the fixed-array literal storage rejects the identical string as TooLong.
    const auto value = scan::Pattern::compile(aob);
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().extra, static_cast<std::uint32_t>(detail::PatternStatus::TooLong));

    // And the long runtime pattern actually resolves against memory.
    std::vector<std::byte> region(64, std::byte{0x00});
    region.insert(region.end(), needle.begin(), needle.end());
    region.resize(region.size() + 64, std::byte{0x00});
    const std::byte *m = detail::find_pattern(region.data(), region.size(), *engine);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m - region.data(), 64);
}

// The AOB prefilter routes through a self-provided dmk_memchr that is ASan-safe in every build. The observable
// contract pinned here is "first match wins, nullptr when no match, treat n==0 as no match", covered across the
// boundary cases of the 8-byte qword loop: the unaligned head, the aligned body, and the byte-wise tail. The qword
// path compiles only under MSVC; other toolchains run the scalar loop against the same assertions.
TEST(ScannerTest, PrefilterReturnsFirstMatchAcrossBoundaries)
{
    auto pattern = detail::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    // The prefilter (dmk_memchr) is tiered: an AVX2 32-byte body, an SSE2 16-byte body, and a scalar byte tail.
    // dmk_memchr routes by span length -- spans of 32 bytes or more take the AVX2 body when the CPU has AVX2, shorter
    // spans take the SSE2 body, and the sub-16 remainder of either falls to the scalar tail -- so the three buffer
    // sizes below exercise all three bodies even on an AVX2 host. The filler byte 0xAB differs from the 0xCC needle
    // while sharing its high bit, so a compare that only tested the sign bit (rather than full-byte equality) would
    // wrongly match the filler and the test would catch it.

    // 64-byte buffer (>= 32, so the AVX2 body runs on this host). Positions cover the 16-byte SSE-lane seam (15/16),
    // the 32-byte AVX2 chunk seam (31/32/33), an interior position, and the last byte (63).
    const std::size_t avx2_positions[] = {0, 1, 15, 16, 17, 31, 32, 33, 47, 63};
    for (const std::size_t pos : avx2_positions)
    {
        std::vector<std::byte> data(64, std::byte{0xAB});
        data[pos] = std::byte{0xCC};

        auto result = detail::find_pattern(data.data(), data.size(), *pattern);
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(static_cast<std::size_t>(result - data.data()), pos);

        // Scanning from a misaligned base proves the unaligned vector loads (loadu) find the match at any alignment.
        if (pos >= 1)
        {
            auto misaligned = detail::find_pattern(data.data() + 1, data.size() - 1, *pattern);
            ASSERT_NE(misaligned, nullptr);
            EXPECT_EQ(static_cast<std::size_t>(misaligned - (data.data() + 1)), pos - 1);
        }
    }

    // 24-byte buffer (16 <= span < 32) forces the SSE2 body plus scalar tail even when the CPU has AVX2, since the
    // span is below the AVX2 threshold. Positions cover the 16-byte chunk seam (15/16) and the last byte (23).
    const std::size_t sse2_positions[] = {0, 15, 16, 23};
    for (const std::size_t pos : sse2_positions)
    {
        std::vector<std::byte> data(24, std::byte{0xAB});
        data[pos] = std::byte{0xCC};

        auto result = detail::find_pattern(data.data(), data.size(), *pattern);
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(static_cast<std::size_t>(result - data.data()), pos);
    }

    // No-match case: a buffer with no occurrence.
    std::vector<std::byte> empty(64, std::byte{0xAB});
    auto miss = detail::find_pattern(empty.data(), empty.size(), *pattern);
    EXPECT_EQ(miss, nullptr);

    // n == 0: a zero-size region cannot contain the pattern and must report no match without reading any byte.
    EXPECT_EQ(detail::find_pattern(empty.data(), 0, *pattern), nullptr);

    // A sub-16 buffer skips both vector bodies and runs only the scalar byte tail.
    std::vector<std::byte> tiny{std::byte{0xAB}, std::byte{0xAB}, std::byte{0xCC}, std::byte{0xAB}};
    auto tiny_result = detail::find_pattern(tiny.data(), tiny.size(), *pattern);
    ASSERT_NE(tiny_result, nullptr);
    EXPECT_EQ(tiny_result - tiny.data(), 2);
}

TEST(ScannerTest, find_pattern_not_found)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    auto pattern = detail::parse_aob("AA BB CC DD");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_with_wildcard)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[50] = std::byte{0x48};
    data[51] = std::byte{0x8B};
    data[52] = std::byte{0x12};

    auto pattern = detail::parse_aob("48 8B ??");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 50);
}

TEST(ScannerTest, parse_aob_invalid_hex)
{
    auto result = detail::parse_aob("GG HH II");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_mixed_invalid)
{
    auto result = detail::parse_aob("48 GG 05");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_single_digit)
{
    auto result = detail::parse_aob("4 8 B");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_various_formats)
{
    auto result1 = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(result1.has_value());
    EXPECT_EQ(result1->size(), 3);

    auto result2 = detail::parse_aob("48   8B   05");
    ASSERT_TRUE(result2.has_value());
    EXPECT_EQ(result2->size(), 3);

    auto result3 = detail::parse_aob("48\t8B\t05");
    ASSERT_TRUE(result3.has_value());
    EXPECT_EQ(result3->size(), 3);
}

TEST(ScannerTest, parse_aob_lowercase)
{
    auto result = detail::parse_aob("48 8b 05 ff");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4);
}

TEST(ScannerTest, parse_aob_uppercase)
{
    auto result = detail::parse_aob("48 8B 05 FF");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4);
}

TEST(ScannerTest, parse_aob_only_wildcards)
{
    auto result1 = detail::parse_aob("?");
    EXPECT_TRUE(result1.has_value());

    auto result2 = detail::parse_aob("??");
    EXPECT_TRUE(result2.has_value());
}

TEST(ScannerTest, find_pattern_at_start)
{
    std::vector<std::byte> data = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00}};

    auto pattern = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

TEST(ScannerTest, find_pattern_at_end)
{
    std::vector<std::byte> data = {std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};

    auto pattern = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 2);
}

TEST(ScannerTest, find_pattern_pattern_too_large)
{
    std::vector<std::byte> data = {std::byte{0x48}, std::byte{0x8B}};

    auto pattern = detail::parse_aob("48 8B 05 00 00 00 00");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_empty_data)
{
    std::vector<std::byte> data;

    auto pattern = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), 0, *pattern);

    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_single_byte)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0xCC};

    auto pattern = detail::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

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

    auto pattern = detail::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 50);
}

TEST(ScannerTest, find_pattern_all_wildcard)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    auto pattern = detail::parse_aob("?? ?? ??");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

TEST(ScannerTest, find_pattern_wildcard_at_end)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[75] = std::byte{0x48};
    data[76] = std::byte{0x8B};
    data[77] = std::byte{0x99};

    auto pattern = detail::parse_aob("48 8B ??");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 75);
}

TEST(ScannerTest, find_pattern_wildcard_at_start)
{
    std::vector<std::byte> data(256, std::byte{0x00});

    data[75] = std::byte{0x99};
    data[76] = std::byte{0x48};
    data[77] = std::byte{0x8B};

    auto pattern = detail::parse_aob("?? 48 8B");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

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

    auto pattern = detail::parse_aob("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 500);
}

TEST(ScannerTest, parse_aob_whitespace_only)
{
    auto result1 = detail::parse_aob("   ");
    EXPECT_FALSE(result1.has_value());

    auto result2 = detail::parse_aob("\t\t\t");
    EXPECT_FALSE(result2.has_value());

    auto result3 = detail::parse_aob(" \t \n ");
    EXPECT_FALSE(result3.has_value());
}

TEST(ScannerTest, find_pattern_null_address)
{
    auto pattern = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(static_cast<const std::byte *>(nullptr), 100, *pattern);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_empty_pattern)
{
    detail::EnginePattern empty_pattern;
    std::vector<std::byte> data(256, std::byte{0x00});

    auto result = detail::find_pattern(data.data(), data.size(), empty_pattern);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, parse_aob_with_whitespace_padding)
{
    auto result = detail::parse_aob("  48 8B 05  ");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
}

TEST(ScannerTest, parse_aob_byte_values)
{
    auto result = detail::parse_aob("00 FF 80 7F");
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
    auto result = detail::parse_aob("48 ?? 05 ?");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4u);

    EXPECT_EQ(result->mask[0], std::byte{0xFF});
    EXPECT_EQ(result->mask[2], std::byte{0xFF});

    EXPECT_EQ(result->mask[1], std::byte{0x00});
    EXPECT_EQ(result->mask[3], std::byte{0x00});
}

// Per-nibble wildcard tokens

// A high-nibble token ("A?") fixes the high nibble and wildcards the low one: the byte holds the known nibble in place
// (0xA0) with the unknown nibble zeroed, and the mask is 0xF0 so the masked compare checks only the high nibble.
TEST(ScannerTest, parse_aob_nibble_high)
{
    auto result = detail::parse_aob("A?");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 1u);

    EXPECT_EQ(result->mask[0], std::byte{0xF0});
    EXPECT_EQ(result->bytes[0], std::byte{0xA0});
}

// A low-nibble token ("?A") fixes the low nibble: the byte holds 0x0A (high nibble zeroed) with a 0x0F mask.
TEST(ScannerTest, parse_aob_nibble_low)
{
    auto result = detail::parse_aob("?A");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 1u);

    EXPECT_EQ(result->mask[0], std::byte{0x0F});
    EXPECT_EQ(result->bytes[0], std::byte{0x0A});
}

// A pattern mixing high-nibble, low-nibble, and full-literal tokens must carry the three distinct masks in order, with
// bytes and mask sized identically.
TEST(ScannerTest, parse_aob_nibble_mixed)
{
    auto result = detail::parse_aob("4? ?B 8B");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
    EXPECT_EQ(result->bytes.size(), result->mask.size());

    EXPECT_EQ(result->mask[0], std::byte{0xF0});
    EXPECT_EQ(result->mask[1], std::byte{0x0F});
    EXPECT_EQ(result->mask[2], std::byte{0xFF});

    EXPECT_EQ(result->bytes[0], std::byte{0x40});
    EXPECT_EQ(result->bytes[1], std::byte{0x0B});
    EXPECT_EQ(result->bytes[2], std::byte{0x8B});
}

// find_pattern verifies a high-nibble token via the masked compare: 0xA3 (high nibble matches) is a hit; 0xB3 (high
// nibble differs) is a miss, proving only the known nibble is compared and the unknown nibble is ignored.
TEST(ScannerTest, find_pattern_nibble_high_matches)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0xA3};

    auto pattern = detail::parse_aob("A?");
    ASSERT_TRUE(pattern.has_value());

    const auto *hit = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit - data.data(), 100);

    // A byte whose high nibble differs must not match.
    std::vector<std::byte> miss_data(256, std::byte{0x00});
    miss_data[100] = std::byte{0xB3};
    const auto *miss = detail::find_pattern(miss_data.data(), miss_data.size(), *pattern);
    EXPECT_EQ(miss, nullptr);
}

// find_pattern verifies a low-nibble token: 0x53 (low nibble 3 matches) hits; 0x54 (low nibble differs) misses.
TEST(ScannerTest, find_pattern_nibble_low_matches)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0x53};

    auto pattern = detail::parse_aob("?3");
    ASSERT_TRUE(pattern.has_value());

    const auto *hit = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit - data.data(), 100);

    std::vector<std::byte> miss_data(256, std::byte{0x00});
    miss_data[100] = std::byte{0x54};
    const auto *miss = detail::find_pattern(miss_data.data(), miss_data.size(), *pattern);
    EXPECT_EQ(miss, nullptr);
}

// Anchor selection must skip a partially-masked nibble byte: the memchr / SIMD prefilter searches for one exact byte
// value, which a nibble does not provide. With a nibble byte and full wildcards surrounding it, the only fully-known
// (0xFF) byte is 0x37, so the cached anchor must point there. The pattern then matches a buffer whose nibble byte
// agrees and rejects one whose known nibble differs.
TEST(ScannerTest, find_pattern_nibble_anchor_skips_partial)
{
    auto pattern = detail::parse_aob("A? 37 ?? 5C");
    ASSERT_TRUE(pattern.has_value());

    ASSERT_LT(pattern->anchor, pattern->size());
    EXPECT_EQ(pattern->mask[pattern->anchor], std::byte{0xFF});
    EXPECT_EQ(pattern->bytes[pattern->anchor], std::byte{0x37});

    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0xA1}; // high nibble A matches the "A?" token
    data[101] = std::byte{0x37};
    data[102] = std::byte{0x99}; // wildcard
    data[103] = std::byte{0x5C};

    const auto *hit = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit - data.data(), 100);

    // High nibble of the first byte wrong (B instead of A) -> no match.
    std::vector<std::byte> miss_data(256, std::byte{0x00});
    miss_data[100] = std::byte{0xB1};
    miss_data[101] = std::byte{0x37};
    miss_data[102] = std::byte{0x99};
    miss_data[103] = std::byte{0x5C};
    const auto *miss = detail::find_pattern(miss_data.data(), miss_data.size(), *pattern);
    EXPECT_EQ(miss, nullptr);
}

// A pattern with no fully-known byte (only a nibble constraint) still scans correctly: the anchor collapses to size()
// and the scan falls back to a masked compare at every position, finding the right offset rather than degenerating to
// the region start. Here the only candidate that satisfies "?A" is at offset 100.
TEST(ScannerTest, find_pattern_nibble_only_brute_force_scan)
{
    auto pattern = detail::parse_aob("?A");
    ASSERT_TRUE(pattern.has_value());
    // No fully-known byte, so there is no anchor.
    EXPECT_EQ(pattern->anchor, pattern->size());

    std::vector<std::byte> data(256, std::byte{0x00}); // low nibble 0 everywhere except the plant
    data[100] = std::byte{0x7A};                       // low nibble A

    const auto *hit = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit - data.data(), 100);
}

// A pattern whose ONLY fully-literal byte is rare and surrounded by nibble-masked neighbours must anchor on that rare
// literal, not on a common nibble. The scan finds the planted site whose nibbles agree and rejects a copy whose tail
// nibble differs, proving the masked verify runs around the literal anchor.
TEST(ScannerTest, find_pattern_nibble_neighbours_anchor_on_rare_literal)
{
    auto pattern = detail::parse_aob("4? 37 ?5");
    ASSERT_TRUE(pattern.has_value());

    ASSERT_LT(pattern->anchor, pattern->size());
    EXPECT_EQ(pattern->bytes[pattern->anchor], std::byte{0x37});

    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0x41}; // high nibble 4
    data[101] = std::byte{0x37};
    data[102] = std::byte{0xC5}; // low nibble 5

    const auto *hit = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit - data.data(), 100);

    // Tail low nibble wrong (6 instead of 5) -> no match.
    std::vector<std::byte> miss_data(256, std::byte{0x00});
    miss_data[100] = std::byte{0x41};
    miss_data[101] = std::byte{0x37};
    miss_data[102] = std::byte{0xC6};
    const auto *miss = detail::find_pattern(miss_data.data(), miss_data.size(), *pattern);
    EXPECT_EQ(miss, nullptr);
}

// A pattern long enough to cross the SIMD verify boundary with a nibble-masked byte in the scalar tail exercises the
// scalar masked-compare path (a full-byte compare there would be wrong for a nibble). The 20-byte pattern matches when
// the tail nibble agrees and misses when it differs.
TEST(ScannerTest, find_pattern_nibble_scalar_tail)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    // Distinctive 20 bytes at offset 64; the last byte (0x9C) carries a known high nibble 9.
    const std::uint8_t bytes[20] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
                                    0xBB, 0xCC, 0xDD, 0xEE, 0x10, 0x20, 0x30, 0x40, 0x50, 0x9C};
    for (std::size_t i = 0; i < 20; ++i)
    {
        data[64 + i] = static_cast<std::byte>(bytes[i]);
    }

    // Last token "9?" fixes only the high nibble of the final byte, landing it in the post-SIMD scalar tail of a
    // 20-byte verify.
    auto pattern = detail::parse_aob("11 22 33 44 55 66 77 88 99 AA BB CC DD EE 10 20 30 40 50 9?");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->size(), 20u);

    const auto *hit = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit - data.data(), 64);

    // Flip the final byte's high nibble (0x9C -> 0xAC) so the scalar-tail masked compare must reject it.
    data[64 + 19] = std::byte{0xAC};
    const auto *miss = detail::find_pattern(data.data(), data.size(), *pattern);
    EXPECT_EQ(miss, nullptr);
}

TEST(ScannerTest, find_pattern_wildcard_before_start)
{
    std::vector<std::byte> data = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0x00},
                                   std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};

    auto pattern = detail::parse_aob("?? 48 8B");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 3);
}

TEST(ScannerTest, parse_aob_out_of_range)
{
    auto result = detail::parse_aob("1FF");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_invalid_argument)
{
    auto result = detail::parse_aob("?? GG ??");

    ASSERT_FALSE(result.has_value());
}

TEST(ScannerTest, aob_pattern_empty)
{
    auto result = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->empty());
    EXPECT_EQ(result->size(), 3u);
}

TEST(ScannerTest, find_pattern_overlapping_matches)
{
    std::vector<std::byte> data = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto pattern = detail::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

TEST(ScannerTest, find_pattern_wildcard_middle_multiple_candidates)
{
    std::vector<std::byte> data = {std::byte{0x48}, std::byte{0xAA}, std::byte{0x05}, std::byte{0x00},
                                   std::byte{0x48}, std::byte{0xBB}, std::byte{0x05}};

    auto pattern = detail::parse_aob("48 ?? 05");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);
}

TEST(ScannerTest, find_pattern_memchr_boundary)
{
    std::vector<std::byte> data(64, std::byte{0x00});
    data[63] = std::byte{0xCC};

    auto pattern = detail::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 63);
}

TEST(ScannerTest, find_pattern_long_wildcard_prefix)
{
    std::vector<std::byte> data = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
                                   std::byte{0x48}, std::byte{0x8B}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto pattern = detail::parse_aob("?? ?? ?? ?? ?? 48 8B");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 0);

    std::vector<std::byte> small = {std::byte{0x00}, std::byte{0x00}, std::byte{0x48}};

    auto result2 = detail::find_pattern(small.data(), small.size(), *pattern);
    EXPECT_EQ(result2, nullptr);
}

TEST(ScannerTest, find_pattern_anchor_selection)
{
    // Fill data with 0x00 (very common byte). Place a pattern where the first non-wildcard is 0x00 but a later byte is
    // rare (0x37). The smarter anchor should still find the correct match by anchoring on the rare byte.
    std::vector<std::byte> data(512, std::byte{0x00});

    // Place the real match at offset 200: 00 37 00
    data[200] = std::byte{0x00};
    data[201] = std::byte{0x37};
    data[202] = std::byte{0x00};

    auto pattern = detail::parse_aob("00 37 00");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 200);
}

// parse_aob() must pre-populate CompiledPattern::anchor so find_pattern hits the cached fast path on the very first
// scan. The chosen index must point at a literal (non-wildcard) byte; the actual position is implementation defined but
// is documented to be the rarest literal byte.
TEST(ScannerTest, parse_aob_caches_anchor_index)
{
    // Every literal byte in the pattern below appears in the common-byte frequency table EXCEPT 0x37, so 0x37 is the
    // unambiguous winner. Using a clean tie-free pattern keeps the test stable against future tweaks to the frequency
    // table or tie-break order.
    const auto pattern = detail::parse_aob("48 8B 89 37 0F E8 90 CC");
    ASSERT_TRUE(pattern.has_value());

    ASSERT_LT(pattern->anchor, pattern->size());
    EXPECT_EQ(pattern->mask[pattern->anchor], std::byte{0xFF});
    EXPECT_EQ(pattern->bytes[pattern->anchor], std::byte{0x37});
}

// An all-wildcard pattern produced through parse_aob() must mark the anchor as "no literal byte" (anchor == size()),
// short-circuiting find_pattern to its degenerate path without re-scanning the mask on every call.
TEST(ScannerTest, parse_aob_all_wildcards_anchor_equals_size)
{
    const auto pattern = detail::parse_aob("?? ?? ??");
    ASSERT_TRUE(pattern.has_value());

    EXPECT_EQ(pattern->anchor, pattern->size());
}

// compile_anchor() is the explicit hook for manually constructed patterns and must be safe to call repeatedly without
// drifting (idempotent).
TEST(ScannerTest, compile_anchor_is_idempotent_for_manual_patterns)
{
    detail::EnginePattern manual;
    manual.bytes = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x37}, std::byte{0xFF}};
    manual.mask = {std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    manual.compile_anchor();
    const std::size_t first_anchor = manual.anchor;
    EXPECT_EQ(manual.bytes[first_anchor], std::byte{0x37});

    manual.compile_anchor();
    EXPECT_EQ(manual.anchor, first_anchor);
}

// Manually constructed patterns without a compile_anchor() call must still scan correctly: find_pattern_raw selects an
// anchor inline when the cached value is missing (sentinel). Without this fallback, the anchor-caching path would crash
// on patterns built field-by-field by consumers that never call compile_anchor().
TEST(ScannerTest, find_pattern_uncompiled_manual_pattern_still_matches)
{
    detail::EnginePattern manual;
    manual.bytes = {std::byte{0x37}, std::byte{0x48}, std::byte{0x8B}};
    manual.mask = {std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};
    // Anchor deliberately left at its sentinel value.
    ASSERT_GT(manual.anchor, manual.size());

    std::vector<std::byte> data(256, std::byte{0x00});
    data[100] = std::byte{0x37};
    data[101] = std::byte{0x48};
    data[102] = std::byte{0x8B};

    const auto *result = detail::find_pattern(data.data(), data.size(), manual);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 100);
}

// compile_anchor() on an empty pattern is well-defined: the selection loop has nothing to walk, so the anchor collapses
// to `size() == 0` (the same "no literal byte" encoding used for all-wildcard patterns). find_pattern short-circuits on
// `pattern_size == 0` before consulting the anchor, so this state never reaches the scan body; the test pins the
// boundary behaviour against accidental regressions.
TEST(ScannerTest, compile_anchor_empty_pattern_marks_no_anchor)
{
    detail::EnginePattern empty;
    empty.compile_anchor();
    EXPECT_EQ(empty.anchor, empty.size());
}

TEST(ScannerTest, parse_aob_invariant)
{
    auto result = detail::parse_aob("48 ?? 8B 05 ?? ??");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->bytes.size(), result->mask.size());

    auto single = detail::parse_aob("CC");
    ASSERT_TRUE(single.has_value());
    EXPECT_EQ(single->bytes.size(), single->mask.size());
}

// Pipe offset marker

TEST(ScannerTest, parse_aob_offset_marker)
{
    auto result = detail::parse_aob("48 8B 88 B8 00 00 00 | 48 89 4C 24 68");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 12u);
    EXPECT_EQ(result->offset, 7);
    EXPECT_EQ(result->bytes[0], std::byte{0x48});
    EXPECT_EQ(result->bytes[7], std::byte{0x48});
}

TEST(ScannerTest, parse_aob_offset_marker_at_start)
{
    auto result = detail::parse_aob("| 48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
    EXPECT_EQ(result->offset, 0);
}

TEST(ScannerTest, parse_aob_offset_marker_at_end)
{
    auto result = detail::parse_aob("48 8B 05 |");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3u);
    EXPECT_EQ(result->offset, 3);
}

TEST(ScannerTest, parse_aob_no_offset_marker)
{
    auto result = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->offset, 0);
}

TEST(ScannerTest, parse_aob_multiple_offset_markers_fails)
{
    auto result = detail::parse_aob("48 | 8B | 05");
    EXPECT_FALSE(result.has_value());
}

TEST(ScannerTest, parse_aob_offset_marker_with_wildcards)
{
    auto result = detail::parse_aob("?? ?? | 48 8B ??");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 5u);
    EXPECT_EQ(result->offset, 2);
}

TEST(ScannerTest, FindPattern_OffsetMarker_ReturnsMarkedByte)
{
    // Contract: find_pattern applies pattern.offset to the returned
    // pointer, so a `|` marker lands the caller directly on the anchored byte.
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0xAA};
    data[51] = std::byte{0xBB};
    data[52] = std::byte{0xCC};
    data[53] = std::byte{0xDD};

    auto pattern = detail::parse_aob("AA BB | CC DD");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 2);

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    // Returned pointer is the marked byte (offset 2 into the match), NOT the raw match start. Adding pattern->offset
    // manually would double-apply.
    EXPECT_EQ(result - data.data(), 52);
}

// Nth-occurrence matching

TEST(ScannerTest, find_pattern_nth_occurrence_first)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0x90};
    data[51] = std::byte{0x90};
    data[100] = std::byte{0x90};
    data[101] = std::byte{0x90};

    auto pattern = detail::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern, 1);
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

    auto pattern = detail::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern, 2);
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

    auto pattern = detail::parse_aob("AB CD");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern, 3);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result - data.data(), 200);
}

TEST(ScannerTest, find_pattern_nth_occurrence_not_enough)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0x90};
    data[51] = std::byte{0x90};

    auto pattern = detail::parse_aob("90 90");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern, 2);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_nth_occurrence_zero)
{
    std::vector<std::byte> data(256, std::byte{0x00});
    data[50] = std::byte{0x90};

    auto pattern = detail::parse_aob("90");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern, 0);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, FindPattern_NthOccurrence_WithOffsetMarker)
{
    // Contract: the Nth-occurrence overload also applies pattern.offset,
    // returning the marked byte of the Nth match (not the match start).
    std::vector<std::byte> data(256, std::byte{0x00});
    data[40] = std::byte{0xAA};
    data[41] = std::byte{0xBB};
    data[42] = std::byte{0xCC};
    data[100] = std::byte{0xAA};
    data[101] = std::byte{0xBB};
    data[102] = std::byte{0xCC};

    auto pattern = detail::parse_aob("AA | BB CC");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 1);

    auto result = detail::find_pattern(data.data(), data.size(), *pattern, 2);
    ASSERT_NE(result, nullptr);
    // The second match starts at data[100]; the `|` sits after the first byte,
    // so find_pattern returns data[101] directly.
    EXPECT_EQ(result - data.data(), 101);
}

TEST(ScannerTest, find_pattern_nth_occurrence_with_overlap)
{
    std::vector<std::byte> data = {std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA}};

    auto pattern = detail::parse_aob("AA AA");
    ASSERT_TRUE(pattern.has_value());

    auto r1 = detail::find_pattern(data.data(), data.size(), *pattern, 1);
    ASSERT_NE(r1, nullptr);
    EXPECT_EQ(r1 - data.data(), 0);

    auto r2 = detail::find_pattern(data.data(), data.size(), *pattern, 2);
    ASSERT_NE(r2, nullptr);
    EXPECT_EQ(r2 - data.data(), 1);

    auto r3 = detail::find_pattern(data.data(), data.size(), *pattern, 3);
    ASSERT_NE(r3, nullptr);
    EXPECT_EQ(r3 - data.data(), 2);

    auto r4 = detail::find_pattern(data.data(), data.size(), *pattern, 4);
    EXPECT_EQ(r4, nullptr);
}

TEST(ScannerTest, find_pattern_const_correctness)
{
    const std::vector<std::byte> data = {std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B},
                                         std::byte{0x05}, std::byte{0x00}, std::byte{0x00}};

    auto pattern = detail::parse_aob("48 8B 05");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = detail::find_pattern(data.data(), data.size(), *pattern);

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

    auto pattern = detail::parse_aob("10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->size(), 16u);

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

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

    auto pattern = detail::parse_aob("30 31 ?? 33 34 35 ?? 37 38 39 3A 3B 3C 3D ?? 3F 40 41 42 43");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->size(), 20u);

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

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

    auto pattern = detail::parse_aob("10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E FF");
    ASSERT_TRUE(pattern.has_value());

    auto result = detail::find_pattern(data.data(), data.size(), *pattern);

    EXPECT_EQ(result, nullptr);
}

class ScannerRipTest : public ::testing::Test
{
protected:
    void SetUp() override { ASSERT_TRUE(memory::init_cache()); }

    void TearDown() override { memory::shutdown_cache(); }
};

TEST_F(ScannerRipTest, resolve_rip_relative_positive_displacement)
{
    // MOV RAX, [RIP+0x12345678]  =>  48 8B 05 78 56 34 12
    std::vector<std::byte> code = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0x78},
                                   std::byte{0x56}, std::byte{0x34}, std::byte{0x12}};

    auto result = resolve_rip(code.data(), 3, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + 0x12345678;
    EXPECT_EQ(result->raw(), expected);
}

TEST_F(ScannerRipTest, resolve_rip_relative_negative_displacement)
{
    // MOV RAX, [RIP-0x10]  =>  48 8B 05 F0 FF FF FF
    std::vector<std::byte> code = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0xF0},
                                   std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    auto result = resolve_rip(code.data(), 3, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected =
        reinterpret_cast<uintptr_t>(code.data()) + 7 + static_cast<uintptr_t>(static_cast<intptr_t>(-16));
    EXPECT_EQ(result->raw(), expected);
}

TEST_F(ScannerRipTest, resolve_rip_relative_zero_displacement)
{
    std::vector<std::byte> code = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0x00},
                                   std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = resolve_rip(code.data(), 3, 7);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), reinterpret_cast<uintptr_t>(code.data()) + 7);
}

// The helpers receive only a disp32 layout, not a decoded instruction, but x86-64 still imposes a hard 15-byte upper
// bound. Accepting 16 would advance the synthetic next-RIP by one byte and return a plausible but wrong target.
TEST_F(ScannerRipTest, rip_relative_helpers_reject_layout_above_x86_instruction_limit)
{
    std::vector<std::byte> code(16, std::byte{0x00});
    code[0] = std::byte{0xE8};

    const auto direct = resolve_rip(code.data(), 1, 16);
    ASSERT_FALSE(direct.has_value());
    EXPECT_EQ(direct.error().code, ErrorCode::InvalidArg);

    const auto searched = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_CALL_REL32, 16);
    ASSERT_FALSE(searched.has_value());
    EXPECT_EQ(searched.error().code, ErrorCode::InvalidArg);
}

TEST_F(ScannerRipTest, resolve_rip_relative_call_rel32)
{
    // CALL rel32  =>  E8 10 00 00 00
    std::vector<std::byte> code = {std::byte{0xE8}, std::byte{0x10}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = resolve_rip(code.data(), 1, 5);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 5 + 0x10;
    EXPECT_EQ(result->raw(), expected);
}

TEST_F(ScannerRipTest, resolve_rip_relative_null_address)
{
    auto result = resolve_rip(nullptr, 3, 7);

    EXPECT_FALSE(result.has_value());
}

TEST_F(ScannerRipTest, resolve_rip_relative_implausible_target_rejected)
{
    // Resolve a RIP-relative instruction whose computed target lands below
    // USERSPACE_PTR_MIN (0x10000). The displacement bytes are read from committed memory, but the resolved address is
    // not a plausible user-mode pointer, so the resolver must fail closed with ImplausibleTarget rather than return a
    // near-null address that faults on first dereference.
    //
    // A sub-0x10000 target is only reachable when the instruction itself lives at the lowest user-allocatable address
    // (the int32 displacement cannot move a normal high allocation out of user range). Request that page explicitly and
    // skip when the slot is already taken in this process; the allocation is environment dependent, never
    // flaky-failing.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    constexpr uintptr_t LOW_BASE = 0x10000; // USERSPACE_PTR_MIN, the allocation granularity.
    void *region =
        VirtualAlloc(reinterpret_cast<LPVOID>(LOW_BASE), si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (region != reinterpret_cast<LPVOID>(LOW_BASE))
    {
        if (region)
        {
            VirtualFree(region, 0, MEM_RELEASE);
        }
        GTEST_SKIP() << "low-address page at 0x10000 unavailable in this process";
    }

    // MOV RAX, [RIP+disp] => 48 8B 05 <disp32>, length 7, disp at offset 3. target = base + 7 + disp; disp = -15 gives
    // base - 8 == 0xFFF8, which is below USERSPACE_PTR_MIN and therefore implausible.
    auto *bytes = static_cast<std::uint8_t *>(region);
    bytes[0] = 0x48;
    bytes[1] = 0x8B;
    bytes[2] = 0x05;
    const std::int32_t disp = -15;
    std::memcpy(bytes + 3, &disp, sizeof(disp));

    const auto result = resolve_rip(reinterpret_cast<const std::byte *>(region), 3, 7);

    EXPECT_FALSE(result.has_value());
    if (!result)
    {
        EXPECT_EQ(result.error().code, ErrorCode::ImplausibleTarget);
    }

    VirtualFree(region, 0, MEM_RELEASE);
}

TEST_F(ScannerRipTest, find_and_resolve_mov_rax_rip)
{
    // Padding + MOV RAX, [RIP+0x00000020]
    std::vector<std::byte> code = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, // NOP padding
                                   std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, // MOV RAX, [RIP+disp32]
                                   std::byte{0x20}, std::byte{0x00}, std::byte{0x00},
                                   std::byte{0x00}, std::byte{0x90}, std::byte{0x90}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_MOV_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t instr_addr = reinterpret_cast<uintptr_t>(&code[3]);
    EXPECT_EQ(result->raw(), instr_addr + 7 + 0x20);
}

TEST_F(ScannerRipTest, find_and_resolve_lea_rax_rip)
{
    // LEA RAX, [RIP+0x100]
    std::vector<std::byte> code = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x05}, std::byte{0x00},
                                   std::byte{0x01}, std::byte{0x00}, std::byte{0x00}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_LEA_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + 0x100;
    EXPECT_EQ(result->raw(), expected);
}

TEST_F(ScannerRipTest, find_and_resolve_call_rel32)
{
    std::vector<std::byte> code = {std::byte{0x55}, // PUSH RBP
                                   std::byte{0xE8}, // CALL rel32
                                   std::byte{0xFF}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x90}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    uintptr_t instr_addr = reinterpret_cast<uintptr_t>(&code[1]);
    EXPECT_EQ(result->raw(), instr_addr + 5 + 0xFF);
}

TEST_F(ScannerRipTest, find_and_resolve_jmp_rel32)
{
    std::vector<std::byte> code = {std::byte{0xE9}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_JMP_REL32, 5);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 5 + 0x05;
    EXPECT_EQ(result->raw(), expected);
}

TEST_F(ScannerRipTest, find_and_resolve_prefix_not_found)
{
    // Region large enough for prefix + disp32 but contains no matching prefix
    std::vector<std::byte> code = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
                                   std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_MOV_RAX_RIP, 7);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::PrefixNotFound);
}

TEST_F(ScannerRipTest, find_and_resolve_null_start)
{
    auto result = find_and_resolve_rip(nullptr, 100, scan::PREFIX_MOV_RAX_RIP, 7);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullInput);
}

TEST_F(ScannerRipTest, find_and_resolve_region_too_small)
{
    std::vector<std::byte> code = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};

    // Region is smaller than prefix + disp32
    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_MOV_RAX_RIP, 7);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::RegionTooSmall);
}

TEST_F(ScannerRipTest, find_and_resolve_first_match_wins)
{
    // Two MOV RAX, [RIP+disp32] with different displacements
    std::vector<std::byte> code = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0x10}, std::byte{0x00},
                                   std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
                                   std::byte{0x20}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_MOV_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + 0x10;
    EXPECT_EQ(result->raw(), expected);
}

TEST_F(ScannerRipTest, find_and_resolve_skips_implausible_decoy_and_finds_genuine_site)
{
    // find_and_resolve_rip_relative scans left to right for the opcode prefix, resolves each occurrence, and returns
    // the FIRST one whose displacement yields a plausible target -- it does NOT abort on the first prefix that
    // resolves implausibly. Plant a decoy prefix whose disp32 lands the target below USERSPACE_PTR_MIN (must be
    // skipped) followed by a genuine prefix whose disp32 stays inside the page (must be found), so a decoy in front of
    // a real site cannot hide it. A sub-0x10000 decoy target is only reachable when the code lives at the lowest
    // user-allocatable page, so request 0x10000 explicitly and skip when the slot is already taken in this process
    // (environment dependent, never flaky-failing) -- the same low-allocation idiom as the implausible-target test.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    constexpr uintptr_t LOW_BASE = 0x10000; // USERSPACE_PTR_MIN, the allocation granularity.
    const auto release_region = [](void *ptr) noexcept -> void
    {
        if (ptr != nullptr)
        {
            VirtualFree(ptr, 0, MEM_RELEASE);
        }
    };
    void *const raw_region =
        VirtualAlloc(reinterpret_cast<LPVOID>(LOW_BASE), si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    std::unique_ptr<void, decltype(release_region)> region(raw_region, release_region);
    if (region.get() != reinterpret_cast<LPVOID>(LOW_BASE))
    {
        GTEST_SKIP() << "low-address page at 0x10000 unavailable in this process";
    }

    auto *bytes = static_cast<std::uint8_t *>(region.get());
    std::memset(bytes, 0x90, si.dwPageSize); // NOP fill so no stray prefix matches between the two planted sites.

    // Decoy at offset 0: MOV RAX, [RIP+disp32], disp = -0x100. target = 0x10000 + 7 - 0x100 = 0xFF07, below
    // USERSPACE_PTR_MIN -> ImplausibleTarget, so the scanner must skip it and keep scanning.
    bytes[0] = 0x48;
    bytes[1] = 0x8B;
    bytes[2] = 0x05;
    const std::int32_t decoy_disp = -0x100;
    std::memcpy(bytes + 3, &decoy_disp, sizeof(decoy_disp));

    // Genuine site at offset 16: MOV RAX, [RIP+disp32], disp = +0x10. target = (0x10000 + 16) + 7 + 0x10 = 0x10027,
    // inside the committed page -> plausible, so this is the occurrence that resolves and is returned.
    constexpr std::size_t genuine_off = 16;
    bytes[genuine_off + 0] = 0x48;
    bytes[genuine_off + 1] = 0x8B;
    bytes[genuine_off + 2] = 0x05;
    const std::int32_t genuine_disp = 0x10;
    std::memcpy(bytes + genuine_off + 3, &genuine_disp, sizeof(genuine_disp));

    const auto result = find_and_resolve_rip(reinterpret_cast<const std::byte *>(region.get()), si.dwPageSize,
                                             scan::PREFIX_MOV_RAX_RIP, 7);

    // The decoy resolved implausibly and was skipped; the genuine site at +16 resolves to base + 16 + 7 + 0x10.
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), LOW_BASE + genuine_off + 7 + 0x10);
}

TEST_F(ScannerRipTest, find_and_resolve_partial_prefix_no_false_match)
{
    // 48 8B followed by wrong third byte, then the real prefix
    std::vector<std::byte> code = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x0D}, // MOV RCX, not RAX
                                   std::byte{0xFF}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                   std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, // MOV RAX
                                   std::byte{0x30}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_MOV_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t instr_addr = reinterpret_cast<uintptr_t>(&code[7]);
    EXPECT_EQ(result->raw(), instr_addr + 7 + 0x30);
}

TEST_F(ScannerRipTest, resolve_rip_relative_custom_instruction_form)
{
    // MOVSS XMM0, [RIP+disp32] => F3 0F 10 05 <disp32>  (prefix_len=4, instr_len=8)
    std::vector<std::byte> code = {std::byte{0xF3}, std::byte{0x0F}, std::byte{0x10}, std::byte{0x05},
                                   std::byte{0x40}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = resolve_rip(code.data(), 4, 8);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 8 + 0x40;
    EXPECT_EQ(result->raw(), expected);
}

TEST_F(ScannerRipTest, find_and_resolve_empty_prefix)
{
    std::vector<std::byte> code = {std::byte{0x90}};
    std::span<const std::byte> empty;

    auto result = find_and_resolve_rip(code.data(), code.size(), empty, 5);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullInput);
}

TEST_F(ScannerRipTest, resolve_rip_relative_null_input)
{
    auto result = resolve_rip(nullptr, 3, 7);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullInput);
}

TEST_F(ScannerRipTest, rip_resolve_error_to_string_coverage)
{
    EXPECT_FALSE(to_string(ErrorCode::NullInput).empty());
    EXPECT_FALSE(to_string(ErrorCode::PrefixNotFound).empty());
    EXPECT_FALSE(to_string(ErrorCode::RegionTooSmall).empty());
    EXPECT_FALSE(to_string(ErrorCode::UnreadableDisplacement).empty());
}

TEST_F(ScannerRipTest, find_and_resolve_prefix_at_boundary)
{
    // Prefix starts at the last valid position
    std::vector<std::byte> code = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0xE8},
                                   std::byte{0x0A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    uintptr_t instr_addr = reinterpret_cast<uintptr_t>(&code[3]);
    EXPECT_EQ(result->raw(), instr_addr + 5 + 0x0A);
}

TEST_F(ScannerRipTest, find_and_resolve_mov_rcx_rip)
{
    std::vector<std::byte> code = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x0D}, std::byte{0x50},
                                   std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    auto result = find_and_resolve_rip(code.data(), code.size(), scan::PREFIX_MOV_RCX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    uintptr_t expected = reinterpret_cast<uintptr_t>(code.data()) + 7 + 0x50;
    EXPECT_EQ(result->raw(), expected);
}

// Tests for scan_executable_regions

TEST(ScannerExecRegionTest, FindsPatternInExecutableMemory)
{
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0xCC, 4096);

    // 16-byte pattern unlikely to appear elsewhere in process memory
    const std::byte sig[] = {std::byte{0x7A}, std::byte{0x3F}, std::byte{0xE1}, std::byte{0x9C},
                             std::byte{0x42}, std::byte{0xB8}, std::byte{0x05}, std::byte{0xD7},
                             std::byte{0x6E}, std::byte{0xA3}, std::byte{0x11}, std::byte{0x8F},
                             std::byte{0x54}, std::byte{0xC6}, std::byte{0x29}, std::byte{0x70}};
    std::memcpy(&bytes[256], sig, sizeof(sig));

    auto pattern = detail::parse_aob("7A 3F E1 9C 42 B8 05 D7 6E A3 11 8F 54 C6 29 70");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = scan_exec(*pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &bytes[256]);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerExecRegionTest, ReturnsNullForNoMatch)
{
    // Pattern unlikely to exist in any executable page
    auto pattern = detail::parse_aob("FE ED FA CE DE AD BE EF CA FE BA BE 01 02 03 04");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = scan_exec(*pattern);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerExecRegionTest, EmptyPattern)
{
    detail::EnginePattern empty;
    const std::byte *result = scan_exec(empty);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerExecRegionTest, ZeroOccurrence)
{
    auto pattern = detail::parse_aob("CC CC CC");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = scan_exec(*pattern, 0);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerExecRegionTest, NthOccurrence)
{
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0x00, 4096);

    // 16-byte unique pattern placed at two offsets within our page
    const std::byte sig[] = {std::byte{0xB1}, std::byte{0x4D}, std::byte{0xF8}, std::byte{0xA2},
                             std::byte{0x63}, std::byte{0xC9}, std::byte{0x07}, std::byte{0xE5},
                             std::byte{0x3A}, std::byte{0x96}, std::byte{0x1B}, std::byte{0xD4},
                             std::byte{0x58}, std::byte{0x0E}, std::byte{0x7C}, std::byte{0x2F}};
    std::memcpy(&bytes[100], sig, sizeof(sig));
    std::memcpy(&bytes[500], sig, sizeof(sig));

    auto pattern = detail::parse_aob("B1 4D F8 A2 63 C9 07 E5 3A 96 1B D4 58 0E 7C 2F");
    ASSERT_TRUE(pattern.has_value());

    const auto *region_start = reinterpret_cast<const std::byte *>(exec_mem);
    const auto *region_end = region_start + 4096;

    const std::byte *first = scan_exec(*pattern, 1);
    ASSERT_NE(first, nullptr);
    EXPECT_GE(first, region_start);
    EXPECT_LT(first, region_end);
    EXPECT_EQ(first, &bytes[100]);

    const std::byte *second = scan_exec(*pattern, 2);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second, &bytes[500]);

    // Third occurrence should not exist
    const std::byte *third = scan_exec(*pattern, 3);
    EXPECT_EQ(third, nullptr);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerExecRegionTest, SkipsNonExecutableMemory)
{
    void *rw_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(rw_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(rw_mem);
    std::memset(bytes, 0x00, 4096);

    const std::byte sig[] = {std::byte{0xF0}, std::byte{0x0D}, std::byte{0xCA}, std::byte{0xFE},
                             std::byte{0x91}, std::byte{0x3E}, std::byte{0x7B}, std::byte{0xA5},
                             std::byte{0xD2}, std::byte{0x48}, std::byte{0x16}, std::byte{0xC3},
                             std::byte{0x6A}, std::byte{0xEF}, std::byte{0x04}, std::byte{0x87}};
    std::memcpy(&bytes[0], sig, sizeof(sig));

    auto pattern = detail::parse_aob("F0 0D CA FE 91 3E 7B A5 D2 48 16 C3 6A EF 04 87");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = scan_exec(*pattern);
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

    auto pattern = detail::parse_aob("D3 7A E9 15 | 82 F6 4B C0 37 A1 5E 94");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 4);

    const std::byte *result = scan_exec(*pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &bytes[204]);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerExecRegionTest, OffsetStillAppliedExactlyOnce)
{
    // Regression guard: find_pattern and scan_executable_regions share the raw scan helper (find_pattern_raw) and each
    // applies pattern.offset exactly once. Placing a uniquely-valued pattern in an executable region and scanning via
    // both paths must return the same marked byte, not the marked byte + offset (which would be a double application).
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0xCC, 4096);

    // Distinctive 8-byte pattern at offset 300 with `|` marker after byte 3.
    constexpr size_t region_offset = 300;
    const std::byte sig[] = {std::byte{0x71}, std::byte{0xE3}, std::byte{0x9A}, std::byte{0x4D},
                             std::byte{0x06}, std::byte{0xBF}, std::byte{0x52}, std::byte{0x18}};
    std::memcpy(&bytes[region_offset], sig, sizeof(sig));

    auto pattern = detail::parse_aob("71 E3 9A | 4D 06 BF 52 18");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 3);

    // scan_executable_regions path: should land on the marked byte.
    const std::byte *exec_hit = scan_exec(*pattern);
    ASSERT_NE(exec_hit, nullptr);
    EXPECT_EQ(exec_hit, &bytes[region_offset + 3]);

    // find_pattern path over the same region: must agree exactly with the scan_executable_regions result (both apply
    // offset once).
    const std::byte *direct_hit = detail::find_pattern(bytes, 4096, *pattern);
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

    const std::byte sig[] = {std::byte{0xC7}, std::byte{0x3B}, std::byte{0xA0}, std::byte{0xD9},
                             std::byte{0x14}, std::byte{0x6F}, std::byte{0xE2}, std::byte{0x85},
                             std::byte{0x4C}, std::byte{0x01}, std::byte{0x7D}, std::byte{0xF3},
                             std::byte{0xA8}, std::byte{0x56}, std::byte{0x2E}, std::byte{0xBB}};
    std::memcpy(&bytes[0], sig, sizeof(sig));

    DWORD old_protect;
    VirtualProtect(exec_mem, 4096, PAGE_EXECUTE_READ | PAGE_GUARD, &old_protect);

    auto pattern = detail::parse_aob("C7 3B A0 D9 14 6F E2 85 4C 01 7D F3 A8 56 2E BB");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = scan_exec(*pattern);
    EXPECT_EQ(result, nullptr);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

// Tests for scan_readable_regions

namespace
{
    // Writes a signature into dst and returns the matching AOB string. The AOB is built as ASCII hex, a different byte
    // sequence that cannot itself match the binary signature. The step (37) is coprime to 256, so the generated bytes
    // are distinct for any run shorter than 256. marker_index, when
    // non-negative, inserts a `|` offset token before that byte.
    std::string write_signature(std::byte *dst, std::size_t count, std::uint8_t seed, std::ptrdiff_t marker_index = -1)
    {
        static constexpr char hex_digits[] = "0123456789ABCDEF";
        std::string aob;
        aob.reserve(count * 4);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto value = static_cast<std::uint8_t>(seed + static_cast<std::uint8_t>(i) * 37u + 11u);
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

    // Enumerates the readable-memory occurrences of a pattern up to a cap. scan_readable_regions sweeps the whole
    // process, so a signature constructed by a test legitimately appears in more than one readable place: the target
    // buffer, plus any transient copy the optimizer leaves on the stack while building it. (The compiled needle is
    // excluded by the scanner itself.) Tests therefore assert that the target address is among the occurrences, not
    // that it is the first one, which keeps them independent of memory layout and optimizer behaviour across
    // toolchains.
    std::vector<const std::byte *> collect_readable_hits(const detail::EnginePattern &pattern)
    {
        constexpr std::size_t scan_cap = 64;
        std::vector<const std::byte *> hits;
        for (std::size_t occ = 1; occ <= scan_cap; ++occ)
        {
            const auto *hit = scan_read(pattern, occ);
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

    bool any_hit_in_range(const std::vector<const std::byte *> &hits, const std::byte *lo, const std::byte *hi)
    {
        return std::any_of(hits.begin(), hits.end(), [lo, hi](const std::byte *h) { return h >= lo && h < hi; });
    }
} // namespace

TEST(ScannerReadableRegionTest, FindsPatternInReadOnlyMemory)
{
    // .rdata is mapped PAGE_READONLY: write the signature while writable, then flip to read-only to model a real data
    // section.
    void *ro_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(ro_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(ro_mem);
    std::memset(bytes, 0x00, 4096);

    const std::string aob = write_signature(&bytes[512], 16, 0x11);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(ro_mem, 4096, PAGE_READONLY, &old_protect));

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[512]));

    // The scanner skips the compiled pattern's own bytes buffer (the needle), so that readable copy is never returned.
    EXPECT_FALSE(hits_contain(hits, pattern->bytes.data()));

    // The executable-only sweep must not reach a PAGE_READONLY region.
    EXPECT_EQ(scan_exec(*pattern), nullptr);

    VirtualFree(ro_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, FindsPatternInReadWriteData)
{
    void *rw_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(rw_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(rw_mem);
    std::memset(bytes, 0x00, 4096);

    const std::string aob = write_signature(&bytes[256], 16, 0x29);

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[256]));

    const std::byte *exec_hit = scan_exec(*pattern);
    EXPECT_EQ(exec_hit, nullptr);

    VirtualFree(rw_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, SupersetIncludesExecutableReadable)
{
    // PAGE_EXECUTE_READ is in both masks, so a pattern in executable-readable memory must be found by the readable
    // sweep as well as the executable one.
    void *exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(exec_mem);
    std::memset(bytes, 0xCC, 4096);

    const std::string aob = write_signature(&bytes[128], 16, 0x3D);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(exec_mem, 4096, PAGE_EXECUTE_READ, &old_protect));

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[128]));

    // The executable buffer is the only executable copy (the needle and any transient stack copy are not executable),
    // so it is the first exec hit.
    const std::byte *exec_hit = scan_exec(*pattern);
    ASSERT_NE(exec_hit, nullptr);
    EXPECT_EQ(exec_hit, &bytes[128]);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, SkipsGuardPages)
{
    // A guarded read-only page reads as PAGE_READONLY | PAGE_GUARD; the guard
    // modifier must exclude it from the readable sweep, otherwise the first touch raises STATUS_GUARD_PAGE_VIOLATION.
    void *guard_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(guard_mem, nullptr);

    auto *bytes = reinterpret_cast<std::byte *>(guard_mem);
    std::memset(bytes, 0x00, 4096);

    const std::string aob = write_signature(&bytes[0], 16, 0x57);

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(guard_mem, 4096, PAGE_READONLY | PAGE_GUARD, &old_protect));

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    // The guarded region must be skipped: no occurrence may fall inside it. (Transient readable copies of the signature
    // elsewhere are allowed.)
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

    const auto pattern = detail::parse_aob(aob);
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

    const auto pattern = detail::parse_aob(aob);
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

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 3);

    // The marked byte of the buffer copy is at region_offset + 3.
    const auto hits = collect_readable_hits(*pattern);
    EXPECT_TRUE(hits_contain(hits, &bytes[region_offset + 3]));

    VirtualFree(ro_mem, 0, MEM_RELEASE);
}

TEST(ScannerReadableRegionTest, EmptyPattern)
{
    detail::EnginePattern empty;
    const std::byte *result = scan_read(empty);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerReadableRegionTest, ZeroOccurrence)
{
    auto pattern = detail::parse_aob("5E 91 C4 2A 7F 38 D6 0B E3 4C 9A 17 62 F5 8D 30");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *result = scan_read(*pattern, 0);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerStringTest, RipResolveErrorToString_IsNoexcept)
{
    static_assert(noexcept(to_string(ErrorCode::NullInput)));
    static_assert(noexcept(to_string(ErrorCode::PrefixNotFound)));
    static_assert(noexcept(to_string(ErrorCode::RegionTooSmall)));
    static_assert(noexcept(to_string(ErrorCode::UnreadableDisplacement)));
}

TEST(ScannerTest, find_pattern_common_byte_anchoring)
{
    // Patterns containing common x64 opcodes (0x00, 0xCC, 0x90, 0xFF, 0x48, 0x8B, 0x89, 0x0F, 0xE8, 0xE9, 0x83, 0xC3)
    // exercise byte-frequency scoring in the anchor selection path.
    const std::byte data[] = {std::byte{0xCC}, std::byte{0xCC}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
                              std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}, std::byte{0x90}, std::byte{0x90},
                              std::byte{0xC3}, std::byte{0x00}, std::byte{0xFF}, std::byte{0xE8}, std::byte{0x83},
                              std::byte{0x0F}, std::byte{0xE9}, std::byte{0x89}, std::byte{0x42}, std::byte{0x10}};

    // Search for a rare anchor byte (0x42) surrounded by common bytes
    const auto pattern = detail::parse_aob("89 42 10");
    ASSERT_TRUE(pattern.has_value());

    const auto *result = detail::find_pattern(data, sizeof(data), pattern.value());
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[17]);
}

TEST(ScannerTest, find_pattern_all_common_bytes_still_found)
{
    // Pattern made entirely of common opcodes (high frequency scores)
    const std::byte data[] = {std::byte{0x00}, std::byte{0x00}, std::byte{0xCC}, std::byte{0x90},
                              std::byte{0xFF}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x00}};

    const auto pattern = detail::parse_aob("CC 90 FF 48 8B");
    ASSERT_TRUE(pattern.has_value());

    const auto *result = detail::find_pattern(data, sizeof(data), pattern.value());
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[2]);
}

// SIMD level detection

TEST(ScannerTest, active_simd_level_returns_valid_tier)
{
    const auto level = scan::active_simd_level();
    // Must be one of the defined tiers. Avx512 is only reachable in a DMK_ENABLE_AVX512 build on AVX-512 hardware;
    // on every other build/host the runtime gate falls back to a lower tier, which is what this also asserts.
    EXPECT_TRUE(level == scan::SimdLevel::Scalar || level == scan::SimdLevel::Sse2 || level == scan::SimdLevel::Avx2 ||
                level == scan::SimdLevel::Avx512);

    // On x86-64, SSE2 is guaranteed at minimum
#if defined(__x86_64__) || defined(_M_X64)
    EXPECT_GE(static_cast<int>(level), static_cast<int>(scan::SimdLevel::Sse2));
#endif
}

TEST(ScannerTest, active_simd_level_is_deterministic)
{
    // Runtime detection is cached; repeated calls must return the same value
    const auto a = scan::active_simd_level();
    const auto b = scan::active_simd_level();
    EXPECT_EQ(a, b);
}

TEST(ScannerTest, active_simd_level_print)
{
    // Diagnostic: prints the active tier so CI logs confirm which path ran.
    // Not a correctness assertion -- purely informational.
    const auto level = scan::active_simd_level();
    const char *names[] = {"Scalar", "SSE2", "AVX2", "AVX-512"};
    std::printf("[  DIAG   ] Scanner SIMD level: %s\n", names[static_cast<int>(level)]);
}

// AVX2 path tests (32+ byte patterns)
// Correctness tests for patterns that exercise the AVX2 verification tier. active_simd_level() above confirms whether
// AVX2 is actually in use.

TEST(ScannerTest, find_pattern_avx2_path_exact_32_bytes)
{
    // 32-byte pattern: one full AVX2 iteration, no SSE2/scalar tail
    std::vector<std::byte> data(64, std::byte{0x00});
    for (size_t i = 16; i < 48; ++i)
        data[i] = static_cast<std::byte>(i & 0xFF);

    std::string aob;
    for (size_t i = 16; i < 48; ++i)
    {
        if (!aob.empty())
            aob += ' ';
        aob += std::format("{:02X}", i & 0xFF);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 32u);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
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
        if (!aob.empty())
            aob += ' ';
        aob += std::format("{:02X}", (i * 7) & 0xFF);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 48u);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
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
        if (!aob.empty())
            aob += ' ';
        aob += std::format("{:02X}", i & 0xFF);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 64u);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[32]);
}

// AVX-512 path tests (64+ byte patterns)
// Patterns of 64 bytes or more drive the AVX-512 verify body (64 bytes per iteration) when the library is built with
// DMK_ENABLE_AVX512 and the host has AVX-512F + AVX-512BW; on every other build or host the same patterns fall through
// to the AVX2 -> SSE2 -> scalar tiers. Each test asserts an identical result regardless of which tier runs, so it
// validates both the AVX-512 body (on a capable CI host) and the tier-chaining handoff at offsets 64/96 (everywhere).

TEST(ScannerTest, find_pattern_avx512_path_96_bytes)
{
    // 96-byte pattern: one AVX-512 iteration (64B) hands off to one AVX2 iteration (32B).
    std::vector<std::byte> data(160, std::byte{0x11});
    for (size_t i = 32; i < 128; ++i)
        data[i] = static_cast<std::byte>((i * 5) & 0xFF);

    std::string aob;
    for (size_t i = 32; i < 128; ++i)
    {
        if (!aob.empty())
            aob += ' ';
        aob += std::format("{:02X}", (i * 5) & 0xFF);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 96u);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[32]);
}

TEST(ScannerTest, find_pattern_avx512_path_128_bytes)
{
    // 128-byte pattern: two full AVX-512 iterations (no AVX2/SSE2/scalar tail).
    std::vector<std::byte> data(256, std::byte{0x00});
    for (size_t i = 64; i < 192; ++i)
        data[i] = static_cast<std::byte>((i * 3) & 0xFF);

    std::string aob;
    for (size_t i = 64; i < 192; ++i)
    {
        if (!aob.empty())
            aob += ' ';
        aob += std::format("{:02X}", (i * 3) & 0xFF);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 128u);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[64]);
}

TEST(ScannerTest, find_pattern_avx512_path_wildcards_across_64_boundary)
{
    // 96-byte pattern with wildcards straddling the 64-byte AVX-512 chunk seam (positions 60..67), so the per-lane
    // mask must be applied correctly on both sides of the AVX-512 -> AVX2 handoff.
    std::vector<std::byte> data(160, std::byte{0x00});
    for (size_t i = 0; i < 160; ++i)
        data[i] = static_cast<std::byte>((i * 9) & 0xFF);

    std::string aob;
    for (size_t i = 16; i < 112; ++i) // 96-byte pattern anchored at data[16]
    {
        if (!aob.empty())
            aob += ' ';
        const size_t rel = i - 16;
        if (rel >= 60 && rel <= 67)
            aob += "??";
        else
            aob += std::format("{:02X}", (i * 9) & 0xFF);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 96u);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[16]);
}

TEST(ScannerTest, find_pattern_avx512_path_mismatch_after_first_chunk)
{
    // 96-byte pattern whose byte at offset 70 (in the AVX2 chunk after the first AVX-512 chunk) cannot match, so the
    // chained tiers must reject the only anchor-aligned candidate and report no match.
    std::vector<std::byte> data(160, std::byte{0x00});
    for (size_t i = 0; i < 160; ++i)
        data[i] = static_cast<std::byte>((i * 9) & 0xFF);

    std::string aob;
    for (size_t i = 16; i < 112; ++i)
    {
        if (!aob.empty())
            aob += ' ';
        const size_t rel = i - 16;
        if (rel == 70)
            aob += std::format("{:02X}", (((i * 9) & 0xFF) + 1) & 0xFF); // never equals data[i]
        else
            aob += std::format("{:02X}", (i * 9) & 0xFF);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 96u);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
    EXPECT_EQ(result, nullptr);
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
        if (!aob.empty())
            aob += ' ';
        if ((i - 16) % 8 == 4)
            aob += "??";
        else
            aob += std::format("{:02X}", i & 0xFF);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());
    ASSERT_EQ(pattern->size(), 32u);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
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
        if (!aob.empty())
            aob += ' ';
        aob += std::format("{:02X}", i & 0xFF);
    }

    // Corrupt byte 65 in the data so second AVX2 chunk fails
    data[65] = std::byte{0xFE};

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
    EXPECT_EQ(result, nullptr);
}

TEST(ScannerTest, find_pattern_avx2_path_not_found)
{
    // 32-byte pattern not present in the data
    std::vector<std::byte> data(128, std::byte{0xBB});

    std::string aob;
    for (int i = 0; i < 32; ++i)
    {
        if (!aob.empty())
            aob += ' ';
        aob += std::format("{:02X}", i);
    }

    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
    EXPECT_EQ(result, nullptr);
}

namespace
{
    void write_disp32(std::byte *dst, int32_t value) noexcept
    {
        std::memcpy(dst, &value, sizeof(value));
    }
} // namespace

TEST(ScannerRipResolveTest, resolve_rip_relative_null_input_returns_error)
{
    const auto result = resolve_rip(nullptr, 1, 5);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullInput);
}

TEST(ScannerRipResolveTest, resolve_rip_relative_positive_displacement)
{
    // Fake `E8 disp32` (call rel32, 5 bytes total). disp32 starts at offset 1.
    std::vector<std::byte> buffer(5, std::byte{0x00});
    buffer[0] = std::byte{0xE8};
    write_disp32(buffer.data() + 1, 0x1000);

    const auto result = resolve_rip(buffer.data(), 1, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data()) + 5 + 0x1000;
    EXPECT_EQ(result->raw(), expected);
}

TEST(ScannerRipResolveTest, resolve_rip_relative_negative_displacement)
{
    // Signed disp32 must produce a lower absolute address via sign-extension.
    std::vector<std::byte> buffer(16, std::byte{0x00});
    buffer[0] = std::byte{0xE9};
    write_disp32(buffer.data() + 1, -0x200);

    const auto result = resolve_rip(buffer.data(), 1, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data()) + 5 - 0x200;
    EXPECT_EQ(result->raw(), expected);
}

TEST(ScannerRipResolveTest, resolve_rip_relative_mov_rax_rip_shape)
{
    // Full 7-byte `mov rax, [rip+disp32]`: 48 8B 05 disp32.
    std::vector<std::byte> buffer(7, std::byte{0x00});
    buffer[0] = std::byte{0x48};
    buffer[1] = std::byte{0x8B};
    buffer[2] = std::byte{0x05};
    write_disp32(buffer.data() + 3, 0x4000);

    const auto result = resolve_rip(buffer.data(), 3, 7);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data()) + 7 + 0x4000;
    EXPECT_EQ(result->raw(), expected);
}

TEST(ScannerRipResolveTest, resolve_rip_relative_unreadable_displacement)
{
    // Allocate two adjacent pages. Page 1 is RW, page 2 is NO_ACCESS. Place the opcode at the last byte of page 1 so
    // the disp32 read straddles into page 2 and the SEH-guarded displacement read fails for the disp32 window.
    SYSTEM_INFO sys_info{};
    ::GetSystemInfo(&sys_info);
    const SIZE_T page_size = sys_info.dwPageSize;

    auto *region =
        static_cast<std::byte *>(::VirtualAlloc(nullptr, page_size * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(region, nullptr);

    DWORD old_protect = 0;
    ASSERT_TRUE(::VirtualProtect(region + page_size, page_size, PAGE_NOACCESS, &old_protect));

    auto *fake_instr = region + page_size - 1;
    *fake_instr = std::byte{0xE8};

    const auto result = resolve_rip(fake_instr, 1, 5);

    EXPECT_FALSE(result.has_value());
    if (!result.has_value())
    {
        EXPECT_EQ(result.error().code, ErrorCode::UnreadableDisplacement);
    }

    ::VirtualFree(region, 0, MEM_RELEASE);
}

TEST(ScannerRipResolveTest, find_and_resolve_null_input_returns_error)
{
    const auto result = find_and_resolve_rip(nullptr, 16, scan::PREFIX_CALL_REL32, 5);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullInput);
}

TEST(ScannerRipResolveTest, find_and_resolve_region_too_small_returns_error)
{
    std::vector<std::byte> buffer(2, std::byte{0x00});

    const auto result = find_and_resolve_rip(buffer.data(), buffer.size(), scan::PREFIX_CALL_REL32, 5);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::RegionTooSmall);
}

TEST(ScannerRipResolveTest, find_and_resolve_prefix_not_found_returns_error)
{
    std::vector<std::byte> buffer(64, std::byte{0x90});

    const auto result = find_and_resolve_rip(buffer.data(), buffer.size(), scan::PREFIX_CALL_REL32, 5);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::PrefixNotFound);
}

TEST(ScannerRipResolveTest, find_and_resolve_call_rel32_happy_path)
{
    std::vector<std::byte> buffer(64, std::byte{0x90});

    constexpr size_t instr_offset = 20;
    buffer[instr_offset] = std::byte{0xE8};
    write_disp32(buffer.data() + instr_offset + 1, 0x80);

    const auto result = find_and_resolve_rip(buffer.data(), buffer.size(), scan::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data() + instr_offset) + 5 + 0x80;
    EXPECT_EQ(result->raw(), expected);
}

TEST(ScannerRipResolveTest, find_and_resolve_mov_rax_rip_multi_byte_prefix)
{
    std::vector<std::byte> buffer(64, std::byte{0x90});

    constexpr size_t instr_offset = 12;
    buffer[instr_offset + 0] = std::byte{0x48};
    buffer[instr_offset + 1] = std::byte{0x8B};
    buffer[instr_offset + 2] = std::byte{0x05};
    write_disp32(buffer.data() + instr_offset + 3, 0x1234);

    const auto result = find_and_resolve_rip(buffer.data(), buffer.size(), scan::PREFIX_MOV_RAX_RIP, 7);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data() + instr_offset) + 7 + 0x1234;
    EXPECT_EQ(result->raw(), expected);
}

TEST(ScannerRipResolveTest, find_and_resolve_returns_first_match_only)
{
    std::vector<std::byte> buffer(64, std::byte{0x90});

    buffer[8] = std::byte{0xE8};
    write_disp32(buffer.data() + 9, 0x10);

    buffer[32] = std::byte{0xE8};
    write_disp32(buffer.data() + 33, 0x20);

    const auto result = find_and_resolve_rip(buffer.data(), buffer.size(), scan::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected_first = reinterpret_cast<uintptr_t>(buffer.data() + 8) + 5 + 0x10;
    EXPECT_EQ(result->raw(), expected_first);
}

TEST(ScannerRipResolveTest, find_and_resolve_match_at_region_boundary)
{
    // Prefix sits at the last position where prefix + disp32 still fits in the region.
    std::vector<std::byte> buffer(16, std::byte{0x90});
    const size_t instr_offset = buffer.size() - 5;
    buffer[instr_offset] = std::byte{0xE8};
    write_disp32(buffer.data() + instr_offset + 1, 0x40);

    const auto result = find_and_resolve_rip(buffer.data(), buffer.size(), scan::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data() + instr_offset) + 5 + 0x40;
    EXPECT_EQ(result->raw(), expected);
}

// Regression guard: the PREFIX_* constants must expose std::array::size(), decay into std::span cleanly, and feed
// through find_and_resolve_rip_relative without source changes.
TEST(ScannerRipResolveTest, PrefixConstants_AreStdArraysAndUsableAsSpan)
{
    static_assert(scan::PREFIX_CALL_REL32.size() == 1, "PREFIX_CALL_REL32 must expose std::array::size()");
    EXPECT_EQ(scan::PREFIX_CALL_REL32[0], std::byte{0xE8});

    std::vector<std::byte> buffer(5, std::byte{0x90});
    buffer[0] = std::byte{0xE8};
    write_disp32(buffer.data() + 1, 0x10);

    const auto result = find_and_resolve_rip(buffer.data(), buffer.size(), scan::PREFIX_CALL_REL32, 5);

    ASSERT_TRUE(result.has_value());
    const uintptr_t expected = reinterpret_cast<uintptr_t>(buffer.data()) + 5 + 0x10;
    EXPECT_EQ(result->raw(), expected);
}

// Parser must reject obvious non-hex tokens. Guards parse_aob's rejection behaviour without inspecting the Logger
// output (no public capture helper exists in the test suite, so message text is intentionally unchecked).
TEST(ScannerTest, ParseAob_WildcardErrorMessage_UsesCleanQuestionMarks)
{
    auto result = detail::parse_aob("GG");
    EXPECT_FALSE(result.has_value());

    auto result_mixed = detail::parse_aob("48 GG 8B");
    EXPECT_FALSE(result_mixed.has_value());
}

// An all-wildcard pattern has no literal bytes to anchor on. find_pattern's contract is to return `start_address` in
// that case (and log a warning). This guard-rails the behaviour so future refactors don't silently flip it.
TEST(ScannerTest, FindPattern_AllWildcards_ReturnsStartWithWarning)
{
    detail::EnginePattern all_wild;
    all_wild.bytes = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    all_wild.mask = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};

    std::vector<std::byte> buffer(32, std::byte{0xAA});

    const auto *first = detail::find_pattern(buffer.data(), buffer.size(), all_wild);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first, buffer.data());

    // Stable across repeated calls.
    const auto *second = detail::find_pattern(buffer.data(), buffer.size(), all_wild);
    EXPECT_EQ(second, buffer.data());
}

// Negative disp32 must land before the instruction. This guards the signed-arithmetic path in resolve_rip_relative --
// an unsigned-only cast chain would still produce the correct bit pattern modulo 2^64, but the signed form is the one
// humans can read, so a direct signed comparison is the contract.
TEST(ScannerTest, ResolveRipRelative_NegativeDisplacement_ComputesCorrectTarget)
{
    // CALL rel32 with disp32 = -0x20. Encoded little-endian: E0 FF FF FF.
    alignas(4) std::array<std::byte, 0x40> buffer{};
    std::byte *const instruction = buffer.data() + 0x20;
    instruction[0] = std::byte{0xE8};
    instruction[1] = std::byte{0xE0};
    instruction[2] = std::byte{0xFF};
    instruction[3] = std::byte{0xFF};
    instruction[4] = std::byte{0xFF};

    ASSERT_TRUE(memory::init_cache());
    const auto result = resolve_rip(instruction, 1, 5);
    ASSERT_TRUE(result.has_value());

    const std::byte *expected_ptr = instruction + 5 - 0x20;
    EXPECT_EQ(result->raw(), reinterpret_cast<std::uintptr_t>(expected_ptr));
    memory::shutdown_cache();
}

// Exercise the full VirtualQuery walk. The test cannot portably set up a pure-execute page, but it can verify the walk
// across whatever mix of protections the current process happens to have does not AV. scan_executable_regions skips
// PAGE_EXECUTE-only regions (execute without a read bit), which is what makes the walk safe when third-party modules
// inject them.
TEST(ScannerTest, ScanExecutableRegions_SurvivesProcessWalk_DoesNotCrash)
{
    // A distinctive pattern unlikely to appear in the host process. If it does match something, that is still a success
    // for the "does not AV" contract.
    auto pattern = detail::parse_aob("DE AD BE EF CA FE BA BE 13 37 C0 DE");
    ASSERT_TRUE(pattern.has_value());

    const auto *hit = scan_exec(*pattern);
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

    auto pattern = detail::parse_aob("DE AD BE EF |");
    ASSERT_TRUE(pattern.has_value());
    EXPECT_EQ(pattern->offset, 4);

    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result, &data[14]);
}

// All-wildcard Nth occurrence must still advance one byte at a time rather than loop-stalling, and must return the Nth
// "match" address (region start
// + N - 1) without log-spamming for every internal iteration.
TEST(ScannerTest, FindPattern_AllWildcards_NthOccurrenceAdvances)
{
    detail::EnginePattern all_wild;
    all_wild.bytes = {std::byte{0x00}, std::byte{0x00}};
    all_wild.mask = {std::byte{0x00}, std::byte{0x00}};

    std::vector<std::byte> buffer(16, std::byte{0xAB});

    const auto *first = detail::find_pattern(buffer.data(), buffer.size(), all_wild, 1);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first, buffer.data());

    const auto *second = detail::find_pattern(buffer.data(), buffer.size(), all_wild, 2);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second, buffer.data() + 1);

    const auto *third = detail::find_pattern(buffer.data(), buffer.size(), all_wild, 3);
    ASSERT_NE(third, nullptr);
    EXPECT_EQ(third, buffer.data() + 2);
}

// Nth overload with occurrence == 0 must early-return before touching any other state (e.g. pattern validation),
// preserving the 1-based contract.
TEST(ScannerTest, FindPattern_NthZeroOccurrence_ReturnsNullptr)
{
    auto pattern = detail::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    std::vector<std::byte> data = {std::byte{0xCC}, std::byte{0xCC}};
    const auto *result = detail::find_pattern(data.data(), data.size(), *pattern, 0);
    EXPECT_EQ(result, nullptr);
}

// Nth overload rejects an empty pattern the same way the single-hit overload does. Without the public-entry guard, the
// raw helper would be asked to scan with a zero-size pattern, tripping the `remaining >= 0` sentinel path.
TEST(ScannerTest, FindPattern_NthEmptyPattern_ReturnsNullptr)
{
    detail::EnginePattern empty_pattern;
    std::vector<std::byte> data(16, std::byte{0x00});

    const auto *result = detail::find_pattern(data.data(), data.size(), empty_pattern, 1);
    EXPECT_EQ(result, nullptr);
}

// Nth overload validates the start pointer too, so callers can't accidentally scan from a null base even when they pass
// a positive region size.
TEST(ScannerTest, FindPattern_NthNullStart_ReturnsNullptr)
{
    auto pattern = detail::parse_aob("CC");
    ASSERT_TRUE(pattern.has_value());

    const auto *result = detail::find_pattern(static_cast<const std::byte *>(nullptr), 32, *pattern, 1);
    EXPECT_EQ(result, nullptr);
}

// resolve_rip_relative must sign-extend the 32-bit displacement before adding it to the instruction base, so a negative
// disp32 lands at the expected two's-complement target. This test pins that contract with disp = -1 and a
// 5-byte instruction: target must equal base + 5 + (-1) = base + 4.
TEST(ScannerTest, ResolveRipRelative_NegativeDisp32_ProducesExpectedTarget)
{
    std::vector<std::byte> code = {std::byte{0xE8}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    const auto result = resolve_rip(code.data(), 1, 5);
    ASSERT_TRUE(result.has_value());

    const uintptr_t base = reinterpret_cast<uintptr_t>(code.data());
    // disp = -1, instruction_length = 5 => target = base + 5 + (-1) = base + 4.
    const uintptr_t expected = base + 5 + static_cast<uintptr_t>(static_cast<int64_t>(-1));
    EXPECT_EQ(result->raw(), expected);
    EXPECT_EQ(result->raw(), base + 4);
}

namespace
{
    struct ExecBuffer
    {
        std::uint8_t *base{nullptr};
        std::size_t size{0};

        ExecBuffer(std::size_t s) : size(s)
        {
            base =
                static_cast<std::uint8_t *>(VirtualAlloc(nullptr, s, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
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

namespace
{
    struct VirtualFreeDeleter
    {
        void operator()(std::uint8_t *ptr) const noexcept
        {
            if (ptr != nullptr)
            {
                VirtualFree(ptr, 0, MEM_RELEASE);
            }
        }
    };

    using VirtualPagePtr = std::unique_ptr<std::uint8_t, VirtualFreeDeleter>;

} // namespace

TEST(ScannerPrologueTest, NullAddrReturnsFalse)
{
    EXPECT_FALSE(is_likely_prologue(0));
}

TEST(ScannerPrologueTest, ZeroByteReturnsFalse)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0x00;
    EXPECT_FALSE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, Int3PadReturnsFalse)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    EXPECT_FALSE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, BareRetC3ReturnsFalse)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xC3;
    EXPECT_FALSE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, BareRetC2ReturnsFalse)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xC2;
    EXPECT_FALSE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, PushRbpReturnsTrue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0x55; // push rbp -- canonical x86-64 prologue
    EXPECT_TRUE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

// Load-bearing case: documents the no-interference-with-nested-hooks contract. A target whose prologue has already been
// overwritten by
// SafetyHook or MinHook starts with a JMP rel32 (0xE9); the helper must still accept it so the resolver path stays
// usable when a sibling mod hooked the same function first.
TEST(ScannerPrologueTest, PatchedJmpE9ReturnsTrue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xE9;
    EXPECT_TRUE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

// Short JMP (0xEB rel8) is the second prologue-overwrite shape the helper is documented to accept. Some mid-function
// hookers prefer 0xEB when the target lives within +/-127 bytes; the resolver must still treat it as a real prologue so
// ladder recovery keeps working under nested hooks.
TEST(ScannerPrologueTest, PatchedJmpEBReturnsTrue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xEB;
    EXPECT_TRUE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

// Indirect JMP through memory (0xFF 0x25 disp32) is the third documented prologue-overwrite shape, used by trampoline
// allocators that need a full
// 64-bit reach. Only the first byte (0xFF) is examined by the helper, but the test seeds both bytes so the buffer
// matches what a real patched prologue would look like.
TEST(ScannerPrologueTest, PatchedJmpFF25ReturnsTrue)
{
    ExecBuffer buf(0x1000);
    ASSERT_NE(buf.base, nullptr);
    std::memset(buf.base, 0xCC, buf.size);
    buf.base[0x100] = 0xFF;
    buf.base[0x101] = 0x25;
    EXPECT_TRUE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(buf.base + 0x100)));
}

TEST(ScannerPrologueTest, UnreadableAddrReturnsFalse)
{
    void *na = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(na, nullptr);
    EXPECT_FALSE(is_likely_prologue(reinterpret_cast<std::uintptr_t>(na)));
    VirtualFree(na, 0, MEM_RELEASE);
}

// Tests for host-module-scoped resolve() and prologue-fallback recovery

// A unique 16-byte signature compiled into the test executable's own image so a host-module-scoped ladder has a real
// in-host target to resolve. volatile const keeps the linker from folding the bytes or discarding them as unused (the
// fixture DLL uses the same idiom for its stable AOB markers).
static volatile const unsigned char s_host_marker[16] = {0x5A, 0xC3, 0x91, 0x44, 0xE2, 0x7B, 0x10, 0x8F,
                                                         0x36, 0xBD, 0x09, 0xA1, 0xCE, 0x52, 0x74, 0xF0};

// A signature that straddles the boundary between two adjacent accepted executable regions must be found. Two committed
// pages allocated as one span but given different executable protections (RWX then RX) are reported by VirtualQuery as
// two separate adjacent regions, because VirtualQuery never coalesces regions with differing attributes. The scanner
// extends each accepted region's scan back into the contiguous already-accepted run it abuts, so a match beginning in
// the first page's tail and ending in the second is recovered. Without that overlap the straddling match would be
// missed (each region scanned independently). The signature is a rare 16-byte sequence so a process-wide scan returns
// this planted copy.
TEST(ScannerBoundaryTest, FindsPatternStraddlingAdjacentExecutableRegions)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;

    // One reservation spanning two pages so they are virtually contiguous, committed executable.
    auto *base =
        static_cast<std::uint8_t *>(VirtualAlloc(nullptr, page * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    ASSERT_NE(base, nullptr);
    std::memset(base, 0xCC, page * 2);

    // A rare 16-byte signature straddling the page boundary: 8 bytes end the first page, 8 begin the second.
    const std::uint8_t sig[16] = {0x3E, 0x9D, 0x71, 0xC4, 0x06, 0xBA, 0x58, 0xEF,
                                  0x12, 0xA7, 0x4F, 0x83, 0xDC, 0x6B, 0x90, 0x25};
    std::uint8_t *const plant = base + page - 8; // last 8 bytes of page 1, first 8 of page 2
    std::memcpy(plant, sig, sizeof(sig));

    // Force VirtualQuery to report two adjacent regions: flip the second page to a DIFFERENT executable protection so
    // the attributes differ and the regions are not coalesced. Both remain execute-readable and accepted.
    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(base + page, page, PAGE_EXECUTE_READ, &old_protect));

    auto pattern = detail::parse_aob("3E 9D 71 C4 06 BA 58 EF 12 A7 4F 83 DC 6B 90 25");
    ASSERT_TRUE(pattern.has_value());

    // The straddling match must be found at the plant address even though it begins in the first region and ends in the
    // second.
    const std::byte *hit = scan_exec(*pattern);
    ASSERT_NE(hit, nullptr) << "cross-boundary straddling match was missed";
    EXPECT_EQ(hit, reinterpret_cast<const std::byte *>(plant));

    // The straddling occurrence is reported exactly once: a second occurrence of this unique signature must not exist
    // (the overlap must not double-count the match by scanning it from both regions).
    const std::byte *second = scan_exec(*pattern, 2);
    EXPECT_EQ(second, nullptr);

    VirtualFree(base, 0, MEM_RELEASE);
}

TEST(ScannerBoundaryTest, FindsBoundedJumpPatternStraddlingAdjacentExecutableRegions)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;

    auto *base =
        static_cast<std::uint8_t *>(VirtualAlloc(nullptr, page * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    ASSERT_NE(base, nullptr);
    std::memset(base, 0xCC, page * 2);

    // The fixed bytes occupy only 8 bytes, but the actual match spans 32 bytes once the gap is included. A fixed
    // size() - 1 carry would not reach back far enough from the second page to include this start.
    const std::uint8_t head[] = {0x13, 0x57, 0x9B, 0xDF};
    const std::uint8_t tail[] = {0x24, 0x68, 0xAC, 0xF0};
    constexpr std::size_t gap = 24;
    std::uint8_t *const plant = base + page - 16;
    std::memcpy(plant, head, sizeof(head));
    std::memset(plant + sizeof(head), 0xA5, gap);
    std::memcpy(plant + sizeof(head) + gap, tail, sizeof(tail));

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(base + page, page, PAGE_EXECUTE_READ, &old_protect));

    auto pattern = detail::parse_aob("13 57 9B DF [24] 24 68 AC F0");
    ASSERT_TRUE(pattern.has_value());

    const std::byte *hit = scan_exec(*pattern);
    ASSERT_NE(hit, nullptr) << "bounded-jump cross-boundary match was missed";
    EXPECT_EQ(hit, reinterpret_cast<const std::byte *>(plant));

    const std::byte *second = scan_exec(*pattern, 2);
    EXPECT_EQ(second, nullptr);

    VirtualFree(base, 0, MEM_RELEASE);
}

#if defined(_MSC_VER) || defined(_WIN64)
// The per-region VirtualQuery gate in scan_regions_filtered proves a region readable only at gate time.
// scan_region_guarded backstops a concurrent decommit / reprotect that races the unguarded find_pattern_raw reads:
// without the __try / VEH guard, the faulting read would terminate the process. This test sweeps a committed range
// repeatedly (through the module-scoped readable entry point, which routes through scan_regions_filtered) while a
// second thread decommits and recommits an interior page. A pre-race positive control proves the refactored scan body
// still finds a planted needle; the loop then asserts the sweep survives every iteration (a crash is the regression)
// and never reports a false match for an absent needle. A run where the decommit never lands inside the read window is
// a valid pass for the fault path; the __except / VEH skip-the-region mechanism is pinned deterministically by
// MemoryGuardedReadFault and the seh_read_bytes NoAccess / GuardPage tests in test_memory.cpp. 32-bit MinGW is excluded
// because the process-wide vectored guard is x64-only there.
TEST(ScannerRegionGuard, SurvivesConcurrentDecommitMidSweep)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;
    const SIZE_T pages = 16;
    const SIZE_T size = page * pages;

    VirtualPagePtr allocation(static_cast<std::uint8_t *>(VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_NOACCESS)));
    ASSERT_NE(allocation.get(), nullptr);
    auto *base = allocation.get();
    ASSERT_NE(VirtualAlloc(base, size, MEM_COMMIT, PAGE_READWRITE), nullptr);
    std::memset(base, 0xAB, size); // 0xAB never matches the needle below; a fresh-recommitted page reads as 0x00

    auto pattern = detail::parse_aob("DE AD BE EF CA FE");
    ASSERT_TRUE(pattern.has_value());

    const detail::ModuleSpan range{reinterpret_cast<std::uintptr_t>(base),
                                   reinterpret_cast<std::uintptr_t>(base) + size};

    // Positive control: the refactored scan body still finds a planted needle at the right address.
    const std::uint8_t needle[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    std::memcpy(base + 0x123, needle, sizeof(needle));
    const std::byte *found = detail::scan_module_readable(*pattern, range, detail::ScanQuery{1}).match;
    ASSERT_EQ(found, reinterpret_cast<const std::byte *>(base + 0x123));
    std::memset(base + 0x123, 0xAB, sizeof(needle)); // remove it so the race loop expects nullptr

    // A skipped-region fault surfaces on the diagnostic bus too. The race is non-deterministic, so a sweep
    // that never overlapped the decommit window emits nothing -- a valid pass. But every event that does fire must
    // carry a positive skipped-region count and the exact scanned window. The scan runs on this thread, so the handler
    // never races the toggler.
    const std::uintptr_t window_low = reinterpret_cast<std::uintptr_t>(base);
    const std::uintptr_t window_high = window_low + size;
    std::size_t fault_events = 0;
    bool event_payload_ok = true;
    auto fault_sub = diagnostics::scanner_faults().subscribe(
        [&fault_events, &event_payload_ok, window_low, window_high](const diagnostics::ScannerFaultEvent &e)
        {
            ++fault_events;
            if (e.faulted_regions == 0 || e.window_low != window_low || e.window_high != window_high)
            {
                event_payload_ok = false;
            }
        });

    const std::uintptr_t middle = reinterpret_cast<std::uintptr_t>(base) + (pages / 2) * page;
    std::jthread toggler(
        [middle, page](std::stop_token stop_token)
        {
            while (!stop_token.stop_requested())
            {
                VirtualFree(reinterpret_cast<void *>(middle), page, MEM_DECOMMIT);
                VirtualAlloc(reinterpret_cast<void *>(middle), page, MEM_COMMIT, PAGE_READWRITE);
            }
        });

    for (int i = 0; i < 5000; ++i)
    {
        const std::byte *hit = detail::scan_module_readable(*pattern, range, detail::ScanQuery{1}).match;
        EXPECT_EQ(hit, nullptr);
    }

    // Whether or not any fault landed, no emitted event may carry a zero count or a mismatched window.
    EXPECT_TRUE(event_payload_ok);
}
#endif // _MSC_VER || _WIN64
