#ifndef DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP
#define DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP

/**
 * @file internal/scan_engine.hpp
 * @brief Raw AOB matching engine: the compiled-pattern representation, the rarest-byte anchor selector, the
 *        memchr-prefiltered SIMD match loop, and the runtime SIMD-tier report.
 * @details Never installed. The public scan::Pattern is converted to an EnginePattern through engine_pattern_from(), so
 *          the matcher sees one representation regardless of whether the pattern came from a DSL string or the
 *          value-semantic Pattern.
 */

#include "DetourModKit/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @brief Region-wide ceiling on bounded-jump node visits for one segmented scan (`[B-65]`).
         * @details @ref SEGMENT_MATCH_STEP_BUDGET caps one start position. This ceiling caps the sum over every start
         *          and suffix continuation of one physical region. A spent ceiling marks the result truncated.
         */
        inline constexpr std::size_t SEGMENT_MATCH_REGION_STEP_BUDGET = 1u << 26;
        static_assert(
            SEGMENT_MATCH_REGION_STEP_BUDGET >= SEGMENT_MATCH_STEP_BUDGET,
            "The per-region budget must let at least one start position run to its per-position ceiling."
        );

        /**
         * @struct EnginePattern
         * @brief A heap-backed compiled AOB pattern with separate bytes and mask, plus a cached scan anchor.
         * @details A position matches when (memory_byte ^ @ref bytes) & @ref mask == 0. @ref PatternBuffer owns the
         *          mask values, and @ref bytes holds values pre-masked to their known bits.
         */
        struct EnginePattern
        {
            /// Pattern bytes, one per token in the source AOB string, pre-masked to their known bits.
            std::vector<std::byte> bytes;

            /// Per-byte match mask paralleling @ref bytes; sized identically.
            std::vector<std::byte> mask;

            /**
             * @brief Byte offset from pattern start to the point of interest, from the `|` marker (0 if absent).
             * @details May equal bytes.size() when `|` appears at the end. Signed to match pointer arithmetic.
             */
            std::ptrdiff_t offset = 0;

            /**
             * @brief Index of the byte that the memchr prefilter sweeps for, confined to segment 0 (`[B-55]`).
             * @details Sentinel values:
             *          - `[0, size())`   valid anchor.
             *          - `size()`        segment 0 has no fully-known byte, so the scan degenerates.
             *          - `>= size() + 1` no anchor selected yet, so find_pattern() selects one inline (slower path).
             */
            std::size_t anchor = std::numeric_limits<std::size_t>::max();

            /**
             * @brief Bounded-jump gaps between fixed segments, in ascending position order.
             * @details Empty for a plain pattern, which takes the single fixed-width fast path. Copied verbatim from
             *          the shared parser so the runtime matcher and the compile-time Pattern agree on the segmentation.
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
             * @details Idempotent. A caller that changes @ref bytes, @ref mask, or @ref jumps must call it again.
             */
            void compile_anchor() noexcept;
        };

        /**
         * @brief Parses a space-separated AOB string into a compiled EnginePattern.
         * @param aob_str The AOB pattern string.
         * @return The compiled pattern, or std::nullopt on any parse failure or allocation failure.
         * @details The heap sink runs the shared grammar with no MAX_PATTERN_BYTES cap. The jump count keeps the
         *          MAX_PATTERN_JUMPS cap.
         */
        [[nodiscard]] std::optional<EnginePattern> parse_aob(std::string_view aob_str);

        /**
         * @struct RawMatch
         * @brief A raw match location: the match start, its one-past-last-byte end, and the offset-applied point.
         * @details All three are reported because a bounded-jump match has a variable span, and a caller doing
         *          exclusion or cross-boundary counting needs the true end rather than a fixed pattern length. All are
         *          null on no match.
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
             * @brief True when the segmented matcher spent its backtracking budget before the scan was exhaustive.
             * @details A truncated scan cannot prove there is no earlier match, nor that a found match is the leftmost,
             *          so a caller counting occurrences MUST fail closed. Independent of start/end/point: it can be
             *          true on both a found match and a no-match return. The flat matcher never sets it.
             */
            bool budget_exhausted = false;
        };

        /**
         * @struct SegmentedScanBudget
         * @brief Bounded-jump work state for one pattern over one physical readable region.
         * @details Every suffix scan of the region shares it, so the region-wide ceiling cannot reset at a
         *          continuation boundary. Flat patterns ignore it.
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
         * @param anchor_index The prefilter position, already in the engine sentinel convention (size() means "no
         *                     fully-known byte").
         * @return The heap-backed engine pattern. Allocates, so a caller on a noexcept path must guard std::bad_alloc.
         */
        [[nodiscard]] EnginePattern engine_pattern_from(const scan::Pattern &pattern, std::size_t anchor_index);

        /**
         * @brief Scans a readable memory region for the first occurrence of a byte pattern.
         * @param start_address Pointer to the beginning of the region to scan.
         * @param region_size The size in bytes of the region to scan.
         * @param pattern The compiled pattern.
         * @return Pointer to the match (adjusted by pattern.offset), or nullptr if not found.
         * @warning READABLE-RANGE PRECONDITION: this raw matcher performs no page filtering. The caller MUST guarantee
         *          the entire span is committed and readable; the search reads it with raw memchr/SIMD loads.
         */
        [[nodiscard]] const std::byte *
        find_pattern(const std::byte *start_address, std::size_t region_size, const EnginePattern &pattern);

        /**
         * @brief Scans a readable region for the Nth occurrence of a byte pattern.
         * @param start_address Pointer to the beginning of the region to scan.
         * @param region_size The size in bytes of the region to scan.
         * @param pattern The compiled pattern.
         * @param occurrence Which occurrence to return (1-based). Passing 0 returns nullptr.
         * @return Pointer to the Nth occurrence (adjusted by pattern.offset), or nullptr if fewer than N matches exist.
         * @warning Same READABLE-RANGE PRECONDITION as the single-occurrence overload.
         */
        [[nodiscard]] const std::byte *find_pattern(
            const std::byte *start_address,
            std::size_t region_size,
            const EnginePattern &pattern,
            std::size_t occurrence
        );

        /**
         * @brief Implements an Nth-occurrence scan with caller-owned bounded-jump work state.
         * @param start_address Pointer to the beginning of the region to scan.
         * @param region_size The size in bytes of the region to scan.
         * @param pattern The compiled pattern.
         * @param occurrence Which occurrence to return (1-based). Passing 0 returns nullptr.
         * @param segmented_budget Shared bounded-jump work state for all suffix scans of this region.
         * @return Pointer to the Nth occurrence (adjusted by pattern.offset), or nullptr on a miss or truncated scan.
         * @warning Same READABLE-RANGE PRECONDITION as the single-occurrence overload.
         */
        [[nodiscard]] const std::byte *find_pattern_nth(
            const std::byte *start_address,
            std::size_t region_size,
            const EnginePattern &pattern,
            std::size_t occurrence,
            SegmentedScanBudget &segmented_budget
        );

        /**
         * @brief Locates the leftmost match and reports its start, end, and resolved point.
         * @param segmented_budget Optional shared state for bounded-jump suffix continuations of one region.
         * @details The single dispatch point for both the flat fixed-width fast path and the segmented backtracking
         *          matcher. The offset is baked into RawMatch::point so it is applied exactly once regardless of gap
         *          widths.
         */
        [[nodiscard]] RawMatch find_pattern_raw(
            const std::byte *start_address,
            std::size_t region_size,
            const EnginePattern &pattern,
            SegmentedScanBudget *segmented_budget = nullptr
        ) noexcept;

        /**
         * @brief True when @p pattern carries at least one literal (non-wildcard) byte.
         * @details Shared guard for the "all wildcards matches anywhere" degenerate case the page sweeps screen for.
         */
        [[nodiscard]] bool pattern_has_literal_byte(const EnginePattern &pattern) noexcept;

        /**
         * @brief Reports the SIMD tier find_pattern matching uses at runtime.
         * @details Reflects compile-time support and runtime CPU detection. Reports Avx512 only on a DMK_ENABLE_AVX512
         *          build on an AVX-512F + AVX-512BW host; otherwise the highest available lower tier.
         */
        [[nodiscard]] scan::SimdLevel active_simd_level() noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP
