#ifndef DETOURMODKIT_INTERNAL_SCAN_PAGES_HPP
#define DETOURMODKIT_INTERNAL_SCAN_PAGES_HPP

/**
 * @file internal/scan_pages.hpp
 * @brief Page-gated scan primitives: the VirtualQuery page walk, the TOCTOU-guarded region reads, the committed-window
 *        collector, and the executable-page predicates.
 * @details Never installed. Wraps the raw scan_engine matcher in the OS page map so a scan over arbitrary process or
 *          module memory reads only committed pages of the requested protection class instead of faulting the host.
 *          The Windows page-protection masks stay private to scan_pages.cpp; callers select a class through the Pages
 *          mapping or the named module/process scans.
 */

#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"
#include "internal/scan_exclusions.hpp"

#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct ScanQuery
         * @brief What one page-gated sweep is asked to find and what it must not match.
         * @details @ref count_beyond is what makes a uniqueness verdict sound: the sweep keeps traversing past the Nth
         *          match to look for an (N+1)th within the SAME pass, so the two counts come from one view of memory.
         *          Running two independent scans instead lets a concurrent write between them produce a count pair that
         *          never existed.
         */
        struct ScanQuery
        {
            /// Which occurrence to report (1-based). Zero yields an empty result.
            std::size_t occurrence = 1;
            /// Keep counting one occurrence past @ref occurrence so the caller can tell unique from ambiguous.
            bool count_beyond = false;
            /// Spans a match may not intersect (query-owned storage); null excludes nothing.
            const ScanExclusions *exclusions = nullptr;
        };

        /**
         * @struct MatchResult
         * @brief A page-gated scan result: the requested match, how many occurrences the pass counted, and why the
         *        count may be a lower bound.
         * @details @ref count is capped at `occurrence + count_beyond`, so it distinguishes zero, exactly the requested
         *          occurrence, and at-least-one-more without traversing the whole scope after the answer is known.
         *          @ref incomplete (a region faulted under the TOCTOU guard and was skipped) and @ref budget_exhausted
         *          (a bounded-jump matcher spent its backtracking budget) are reported separately because they are
         *          different caller problems: one is a concurrent unmap, the other an over-broad pattern.
         */
        struct MatchResult
        {
            /// The Nth match with pattern.offset applied, or nullptr when fewer than N occurrences were counted.
            const std::byte *match = nullptr;
            /// Occurrences counted, capped by the query.
            std::size_t count = 0;
            /// A faulted region was skipped, so unscanned bytes may hide further matches.
            bool incomplete = false;
            /// Bounded-jump backtracking was truncated, so unvisited start positions may hide further matches.
            bool budget_exhausted = false;

            /// True when @ref count is only a lower bound, for either reason, so a uniqueness verdict must fail closed.
            [[nodiscard]] constexpr bool truncated() const noexcept { return incomplete || budget_exhausted; }
        };

        /// Module-scoped sweep over the image's execute-readable pages, so a match can only land on code.
        [[nodiscard]] MatchResult scan_module_executable(const EnginePattern &pattern, ModuleSpan range,
                                                         const ScanQuery &query) noexcept;

        /// Module-scoped sweep over every readable page, so one pass covers code and .rdata / .data candidates.
        [[nodiscard]] MatchResult scan_module_readable(const EnginePattern &pattern, ModuleSpan range,
                                                       const ScanQuery &query) noexcept;

        /**
         * @brief Whole-process sweep over committed execute-readable pages.
         * @details A pattern straddling two adjacent accepted regions is found via a max_match_length() - 1 carry.
         */
        [[nodiscard]] MatchResult scan_executable_regions(const EnginePattern &pattern,
                                                          const ScanQuery &query) noexcept;

        /// Whole-process sweep over committed readable pages; a strict superset of @ref scan_executable_regions.
        [[nodiscard]] MatchResult scan_readable_regions(const EnginePattern &pattern, const ScanQuery &query) noexcept;

        /// Maps a public scan::Pages class to the matching module-scoped sweep.
        [[nodiscard]] MatchResult scan_module_pages(const EnginePattern &pattern, ModuleSpan range, scan::Pages pages,
                                                    const ScanQuery &query) noexcept;

        /**
         * @brief True when a readable-page sweep of @p range can produce an authoritative result.
         * @param range The scope the sweep will read.
         * @param pages The page class the sweep accepts.
         * @param exclusions Caller-declared copies of the query material; a non-empty span asserts completeness.
         * @details A readable sweep reads every committed page of its scope, so a scope that spans arbitrary process
         *          memory also covers the allocator pages the caller's own copies of the query bytes live on. DMK
         *          excludes every query representation it owns, but it cannot discover a caller-retained copy, so such
         *          a scope can only report that the query found itself. A scope confined to one mapped image or to one
         *          memory allocation is fine: the caller named exactly what it wanted searched. An executable-page
         *          sweep is always authoritative, because no query representation is placed on an execute-readable
         *          page.
         */
        [[nodiscard]] bool readable_scan_is_authoritative(ModuleSpan range, scan::Pages pages,
                                                          std::span<const Region> exclusions) noexcept;

        /**
         * @struct ExecutableWindow
         * @brief One committed, execute-readable slice of a module image.
         * @details The gate proves readability only at gate time, so a caller reading [base, base + span) should still
         *          wrap the read in a fault guard against a concurrent decommit / reprotect.
         */
        struct ExecutableWindow
        {
            /// Absolute address of the first readable byte.
            std::uintptr_t base = 0;
            /// Window length in bytes.
            std::size_t span = 0;
        };

        /**
         * @brief Collects the execute-readable windows of a module image in ascending address order.
         * @return The windows; empty when @p range is invalid or exposes no readable code pages.
         * @details Centralizes the executable-page gate so an out-of-TU caller (the string-xref backend) scans the
         *          image's code without re-deriving the Windows page masks.
         */
        [[nodiscard]] std::vector<ExecutableWindow> collect_executable_windows(ModuleSpan range);

        /**
         * @brief True when @p address lies on a committed, execute-readable page.
         * @details The destination is intentionally NOT module-constrained (a sibling mod's trampoline is allocated
         *          outside every loaded module), while this still rejects a jump into unmapped or data-only memory.
         */
        [[nodiscard]] bool is_executable_address(std::uintptr_t address) noexcept;

        /**
         * @brief True when every byte in [@p address, @p address + @p size) is committed and execute-readable.
         * @details Stricter than testing the first byte: a decoded x86 instruction can straddle a protection boundary,
         *          and a code-only decoder must not consume a readable data-page tail as instruction bytes.
         */
        [[nodiscard]] bool is_executable_range(std::uintptr_t address, std::size_t size) noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_PAGES_HPP
