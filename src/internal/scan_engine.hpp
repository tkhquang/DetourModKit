#ifndef DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP
#define DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP

/**
 * @file internal/scan_engine.hpp
 * @brief True-private raw AOB matching engine: the compiled-pattern representation, the rarest-byte anchor selector,
 *        the memchr-prefiltered SIMD match loop, and the runtime SIMD-tier report.
 * @details This header is never installed. It owns the heap-backed engine vocabulary the public scan module builds on:
 *          EnginePattern (the heap-backed compiled byte/mask representation), parse_aob (string -> EnginePattern),
 *          the raw find_pattern matcher (single + Nth occurrence) with its SSE2 / AVX2 / AVX-512 verify tiers, and
 *          active_simd_level(). The public scan::Pattern is converted to an EnginePattern through
 *          engine_pattern_from() so the matcher sees one representation regardless of whether the pattern came from a
 *          DSL string or the value-semantic Pattern.
 */

#include "DetourModKit/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @brief Region-wide ceiling on total bounded-jump backtracking node visits for one segmented scan.
         * @details The per-position @ref SEGMENT_MATCH_STEP_BUDGET caps one start position, but a non-anchored pattern
         *          tries every start in a region and can otherwise degrade to O(region_size x per-position budget).
         *          This internal scanner policy accumulates work across all starts and suffix continuations of one
         *          physical region, then marks the result incomplete when another node visit would exceed the ceiling.
         *          An ordinary literal-anchored signature stays far below it; an over-broad bounded-jump pattern
         *          should add a literal in its leading
         *          segment instead of consuming unbounded work.
         */
        inline constexpr std::size_t SEGMENT_MATCH_REGION_STEP_BUDGET = 1u << 26;
        static_assert(SEGMENT_MATCH_REGION_STEP_BUDGET >= SEGMENT_MATCH_STEP_BUDGET,
                      "The per-region budget must let at least one start position run to its per-position ceiling.");

        /**
         * @struct EnginePattern
         * @brief A heap-backed compiled AOB pattern with separate bytes and mask, plus a cached scan anchor.
         * @details The heap-backed compiled engine pattern. Stores the pattern bytes and a
         *          per-byte mask: a position passes when (memory_byte ^ bytes) & mask == 0, so 0xFF marks a fully
         *          literal byte, 0x00 a wildcard, and 0xF0 / 0x0F a per-nibble token. @ref offset is the `|` result
         *          marker (0 when absent). @ref anchor is the rarest fully-known byte the memchr prefilter sweeps for.
         */
        struct EnginePattern
        {
            /**
             * @brief Pattern bytes, one per token in the source AOB string.
             * @details Each entry is pre-masked to its known bits: a wildcard position (mask 0x00) holds 0, and a
             *          partially-masked nibble position holds its known nibble with the wildcard nibble zeroed. A plain
             *          (memory_byte ^ bytes) & mask compare is therefore correct at every position without
             *          special-casing the wildcard slots.
             */
            std::vector<std::byte> bytes;

            /**
             * @brief Per-byte match mask paralleling @ref bytes.
             * @details The mask selects which bits of each byte must match: a position passes when
             *          (memory_byte ^ @ref bytes) & mask == 0. 0xFF marks a fully-literal byte, 0x00 a wildcard slot,
             *          and 0xF0 / 0x0F a per-nibble wildcard. Sized identically to @ref bytes.
             */
            std::vector<std::byte> mask;

            /**
             * @brief Byte offset from pattern start to the point of interest.
             * @details Set by the `|` marker in the AOB string, or 0 if absent. May equal bytes.size() when `|` appears
             *          at the end of the pattern. Signed to match pointer-arithmetic conventions.
             */
            std::ptrdiff_t offset = 0;

            /**
             * @brief Cached anchor index selected by compile_anchor().
             * @details find_pattern() drives its memchr sweep on the byte at this position: the rarest literal byte in
             *          segment 0 (the fixed run before the first bounded jump), so a single memchr pass produces far
             *          fewer false candidate hits than anchoring on bytes[0]. The anchor is confined to segment 0
             *          because the matcher finds that first run and then extends across the variable gaps; a byte in a
             *          later segment sits at a gap-dependent address the prefilter cannot sweep for.
             *
             *          Sentinel values:
             *          - `[0, size())`   valid anchor.
             *          - `size()`        segment 0 has no fully-known byte to anchor on (all wildcards, or only nibble
             *                            constraints); the scan degenerates accordingly.
             *          - `>= size() + 1` anchor not yet selected; find_pattern() picks one inline (slower path).
             */
            std::size_t anchor = std::numeric_limits<std::size_t>::max();

            /**
             * @brief Bounded-jump gaps between fixed segments, in ascending position order.
             * @details Empty for a plain (single-segment) pattern, in which case the matcher takes the single
             *          fixed-width fast path. Each gap records the fixed-byte position it precedes and the [min, max]
             *          byte span the following segment may sit at. Copied verbatim from the shared parser so the
             *          runtime matcher and the compile-time Pattern agree on the segmentation.
             */
            std::vector<PatternJump> jumps;

            /// Returns the number of fixed bytes in the pattern (all segments concatenated, gaps excluded).
            [[nodiscard]] std::size_t size() const noexcept { return bytes.size(); }

            /// Checks if the pattern has no bytes.
            [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }

            /// Fewest bytes any match can occupy: the fixed byte count plus every gap's minimum skip.
            [[nodiscard]] std::size_t min_match_length() const noexcept
            {
                std::size_t total = bytes.size();
                for (const PatternJump &gap : jumps)
                {
                    total += gap.min_skip;
                }
                return total;
            }

            /// Most bytes any match can occupy: the fixed byte count plus every gap's maximum skip.
            [[nodiscard]] std::size_t max_match_length() const noexcept
            {
                std::size_t total = bytes.size();
                for (const PatternJump &gap : jumps)
                {
                    total += gap.max_skip;
                }
                return total;
            }

            /**
             * @brief Selects and stores the rarest fully-known byte's index in segment 0 as the scan anchor.
             * @details Walks segment 0 (the fixed run before the first bounded jump; the whole pattern when jump-free)
             *          once, scoring each fully-known (mask 0xFF) byte against a small byte-frequency table (common
             *          opcodes / padding score high; uncommon bytes score 0), and stores the lowest-scoring index in
             *          @ref anchor. Partially-masked nibble bytes are skipped: the prefilter needs one exact byte
             *          value, which a nibble does not provide. Ties break by first occurrence. A segment 0 with no
             *          fully-known byte sets @ref anchor to size(). Idempotent and O(size()). Callers that mutate
             *          @ref bytes, @ref mask, or @ref jumps afterwards MUST call it again before the next scan or the
             *          cached anchor drifts. Not thread-safe with concurrent find_pattern() on the same instance.
             */
            void compile_anchor() noexcept;
        };

        /**
         * @brief Parses a space-separated AOB string into a compiled EnginePattern.
         * @details Drives the single shared grammar (detail::parse_pattern_into) through a heap-backed sink, so the
         *          runtime engine and the compile-time scan::Pattern accept exactly the same DSL (hex bytes, `??` / `?`
         *          wildcards, `4?` / `?5` nibbles, `[X]` / `[X-Y]` bounded jumps, and the `|` offset marker) and can
         *          never silently diverge. Unlike the fixed-array scan::Pattern storage, the heap-backed EnginePattern
         *          imposes no MAX_PATTERN_BYTES cap, so a long runtime pattern (e.g. the byte pattern find_string_xref
         *          builds from a long search string) compiles here even when it would overflow a literal Pattern. The
         *          jump count is still capped at MAX_PATTERN_JUMPS (the segmented matcher's fixed segment array). The
         *          segment-0 anchor is computed after the parse.
         * @param aob_str The AOB pattern string.
         * @return The compiled pattern, or std::nullopt on any parse failure (empty, malformed token, bad jump, or
         *         duplicate offset).
         */
        [[nodiscard]] std::optional<EnginePattern> parse_aob(std::string_view aob_str);

        /**
         * @struct RawMatch
         * @brief A raw match location: the match start, its one-past-last-byte end, and the offset-applied point.
         * @details The raw matcher reports all three because a bounded-jump match has a variable span. @ref start is
         *          the leftmost match start (segment 0's address), used for self-exclusion and Nth-occurrence
         *          continuation; @ref end is one past the last matched byte (start plus the actual match length), used
         *          to size the match for self-exclusion and the page scanner's cross-boundary counting rule; and
         *          @ref point is the address the `|` marker resolves to (start + offset for a plain pattern, start +
         *          fixed offset + actual gap bytes for a jump-bearing one). All three are null on no match.
         */
        struct RawMatch
        {
            /// Leftmost match start (segment 0 address), or nullptr on no match.
            const std::byte *start = nullptr;
            /// One past the last matched byte (start + actual match length), or nullptr on no match.
            const std::byte *end = nullptr;
            /// The offset-applied result address the `|` marker resolves to, or nullptr on no match.
            const std::byte *point = nullptr;
            /**
             * @brief True when the bounded-jump segmented matcher spent its per-position or per-region backtracking
             *        budget before the scan was exhaustive, so the match/no-match verdict is only a lower bound.
             * @details A truncated segmented scan cannot prove there is no earlier match (nor that a found match is the
             *          leftmost), so a caller counting occurrences or checking uniqueness MUST treat this exactly like
             *          a faulted-region skip: fail closed rather than trust a possibly-incomplete count. The flat
             *          (jump-free) matcher never sets it. Independent of start/end/point: it can be true on both a
             *          found match (an earlier candidate was truncated) and a no-match return.
             */
            bool budget_exhausted = false;
        };

        /**
         * @struct SegmentedScanBudget
         * @brief Shared bounded-jump work state for one pattern over one physical readable region.
         * @details The Nth-occurrence helpers continue a scan from the byte after each prior match. They pass the same
         *          state to every suffix scan so the region-wide ceiling cannot reset at a continuation boundary. This
         *          is meaningful only for one pattern and one contiguous region; flat patterns ignore it.
         */
        struct SegmentedScanBudget
        {
            /// Node visits already spent across all segmented suffix scans of the region.
            std::size_t node_visits = 0;
            /// True once a per-position or region-wide cap made the occurrence count incomplete.
            bool exhausted = false;
            /// True once the region-wide cap prevents any further segmented node visits.
            bool region_exhausted = false;
        };

        /**
         * @brief Builds an EnginePattern from a public value-semantic scan::Pattern.
         * @param pattern The compiled value Pattern.
         * @param anchor_index The position the scan should prefilter on, already translated to the engine sentinel
         *                      convention (anchor == size() means "no fully-known byte").
         * @return The heap-backed engine pattern. Allocates two small vectors, so callers on a noexcept path guard this
         *         against std::bad_alloc.
         */
        [[nodiscard]] EnginePattern engine_pattern_from(const scan::Pattern &pattern, std::size_t anchor_index);

        /**
         * @brief Scans a readable memory region for the first occurrence of a byte pattern.
         * @details Optimized search: finds the rarest non-wildcard byte and uses memchr for fast skipping, then
         * verifies
         *          the full pattern with the widest available SIMD tier.
         * @param start_address Pointer to the beginning of the region to scan.
         * @param region_size The size in bytes of the region to scan.
         * @param pattern The compiled pattern.
         * @return Pointer to the match (adjusted by pattern.offset), or nullptr if not found.
         * @warning READABLE-RANGE PRECONDITION: this raw matcher performs no page filtering. The caller MUST guarantee
         *          the entire span is committed and readable; the search reads it with raw memchr/SIMD loads.
         */
        [[nodiscard]] const std::byte *find_pattern(const std::byte *start_address, std::size_t region_size,
                                                    const EnginePattern &pattern);

        /**
         * @brief Scans a readable region for the Nth occurrence of a byte pattern.
         * @param start_address Pointer to the beginning of the region to scan.
         * @param region_size The size in bytes of the region to scan.
         * @param pattern The compiled pattern.
         * @param occurrence Which occurrence to return (1-based). Passing 0 returns nullptr.
         * @return Pointer to the Nth occurrence (adjusted by pattern.offset), or nullptr if fewer than N matches exist.
         * @warning Same READABLE-RANGE PRECONDITION as the single-occurrence overload.
         */
        [[nodiscard]] const std::byte *find_pattern(const std::byte *start_address, std::size_t region_size,
                                                    const EnginePattern &pattern, std::size_t occurrence);

        /**
         * @brief Implements an Nth-occurrence scan with caller-owned bounded-jump work state.
         * @details The ordinary Nth-occurrence overload creates a fresh @p segmented_budget and delegates here. Keeping
         *          this state outside the suffix loop ensures that bounded-jump work cannot reset after each prior
         *          match. The state must belong to this one pattern and contiguous readable region.
         * @param start_address Pointer to the beginning of the region to scan.
         * @param region_size The size in bytes of the region to scan.
         * @param pattern The compiled pattern.
         * @param occurrence Which occurrence to return (1-based). Passing 0 returns nullptr.
         * @param segmented_budget Shared bounded-jump work state for all suffix scans of this region.
         * @return Pointer to the Nth occurrence (adjusted by pattern.offset), or nullptr on a miss or incomplete scan.
         * @warning Same READABLE-RANGE PRECONDITION as the single-occurrence overload.
         */
        [[nodiscard]] const std::byte *find_pattern_nth(const std::byte *start_address, std::size_t region_size,
                                                        const EnginePattern &pattern, std::size_t occurrence,
                                                        SegmentedScanBudget &segmented_budget);

        /// Span convenience over the pointer+size single-occurrence matcher (same READABLE-RANGE precondition).
        [[nodiscard]] inline const std::byte *find_pattern(std::span<const std::byte> region,
                                                           const EnginePattern &pattern)
        {
            return find_pattern(region.data(), region.size(), pattern);
        }

        /// Span convenience over the pointer+size Nth-occurrence matcher (same READABLE-RANGE precondition).
        [[nodiscard]] inline const std::byte *find_pattern(std::span<const std::byte> region,
                                                           const EnginePattern &pattern, std::size_t occurrence)
        {
            return find_pattern(region.data(), region.size(), pattern, occurrence);
        }

        /**
         * @brief Internal raw scan primitive: locates the leftmost match and reports its start, end, and resolved
         * point.
         * @details The single dispatch point for both a plain single fixed-width pattern (the flat fixed-width fast
         *          path) and a bounded-jump pattern (the segmented backtracking matcher). The page-walking sweeps and
         *          the Nth-occurrence loop call this directly: they use RawMatch::start for self-exclusion and to
         *          continue past a hit, RawMatch::end to size the match, and RawMatch::point as the offset-applied
         *          result. The offset is baked into RawMatch::point so it is applied exactly once regardless of gap
         *          widths. When @p segmented_budget is supplied, bounded-jump work accumulates across every suffix
         *          continuation over the same physical region; its exhaustion is reflected in @ref RawMatch.
         * @param segmented_budget Optional shared state for bounded-jump suffix continuations of one region.
         */
        [[nodiscard]] RawMatch find_pattern_raw(const std::byte *start_address, std::size_t region_size,
                                                const EnginePattern &pattern,
                                                SegmentedScanBudget *segmented_budget = nullptr) noexcept;

        /**
         * @brief True when @p pattern carries at least one literal (non-wildcard) byte.
         * @details Shared guard for the "all wildcards matches anywhere" degenerate case the page sweeps screen for.
         */
        [[nodiscard]] bool pattern_has_literal_byte(const EnginePattern &pattern) noexcept;

        /**
         * @brief Reports the SIMD tier find_pattern matching uses at runtime.
         * @details Reflects compile-time support (which intrinsics were built) and runtime CPU detection (CPUID + OS
         *          XGETBV). Reports Avx512 only on a DMK_ENABLE_AVX512 build on an AVX-512F + AVX-512BW host; otherwise
         *          the highest available lower tier.
         */
        [[nodiscard]] scan::SimdLevel active_simd_level() noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP
