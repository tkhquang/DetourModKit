#ifndef DETOURMODKIT_INTERNAL_SCAN_PAGES_HPP
#define DETOURMODKIT_INTERNAL_SCAN_PAGES_HPP

/**
 * @file internal/scan_pages.hpp
 * @brief True-private page-gated scan primitives: the VirtualQuery page walk, the TOCTOU-guarded region reads, the
 *        committed-window collection, and the single-address executable-page predicate.
 * @details Never installed. Wraps the raw scan_engine matcher in the OS page map so a scan over arbitrary process or
 *          module memory reads only committed pages of the requested protection class and skips unmapped / guard /
 *          no-access pages instead of faulting the host. The Windows page-protection masks (PAGE_EXECUTE_READ, ...)
 *          stay private to scan_pages.cpp; callers select a class through the Pages mapping or the named module/process
 *          scans. A page-gated scan returns a MatchResult so the caller learns whether a region faulted mid-scan (the
 *          occurrence count is then only a lower bound), so the fault state rides on the return value rather than a
 *          thread-local side channel.
 */

#include "internal/scan_engine.hpp"

#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct MatchResult
         * @brief A page-gated scan result: the match pointer plus whether the sweep skipped a faulted region.
         * @details @ref match is the Nth match (adjusted by pattern.offset) or nullptr when not found. @ref incomplete
         *          is true when the sweep skipped a region that faulted mid-scan under the TOCTOU guard: the occurrence
         *          count is then only a lower bound (a hidden match could live in the skipped bytes), so a caller doing
         *          a uniqueness check must fail closed. The fault state rides on the return value rather than a
         *          thread-local side channel, so concurrent scans cannot clobber each other's incomplete state.
         */
        struct MatchResult
        {
            /// The Nth match (offset-applied) or nullptr.
            const std::byte *match = nullptr;
            /// True when a region faulted mid-scan and was skipped, making any occurrence count a lower bound.
            bool incomplete = false;
        };

        /**
         * @brief Module-scoped scan over the image's execute-readable pages.
         * @details Searches only [range.base, range.end) and only execute-readable pages, so a match can only land on
         *          code. Returns the Nth match (1-based, adjusted by pattern.offset) and the incomplete flag.
         */
        [[nodiscard]] MatchResult scan_module_executable(const EnginePattern &pattern, Memory::ModuleRange range,
                                                         std::size_t occurrence = 1) noexcept;

        /**
         * @brief Module-scoped scan over every readable page of the image.
         * @details Superset of @ref scan_module_executable that also accepts non-executable readable pages
         *          (.rdata / .data), so one pass covers both code and data candidates. Returns the Nth match and the
         *          incomplete flag.
         */
        [[nodiscard]] MatchResult scan_module_readable(const EnginePattern &pattern, Memory::ModuleRange range,
                                                       std::size_t occurrence = 1) noexcept;

        /**
         * @brief Whole-process scan over committed execute-readable pages.
         * @details Walks the entire user address space; a pattern straddling two adjacent accepted regions is found via
         *          a pattern_len-1 carry. Returns the Nth match and the incomplete flag.
         */
        [[nodiscard]] MatchResult scan_executable_regions(const EnginePattern &pattern,
                                                          std::size_t occurrence = 1) noexcept;

        /**
         * @brief Whole-process scan over committed readable pages (.text + .rdata / .data + read-only heaps).
         * @details A strict superset of @ref scan_executable_regions. Excludes any match overlapping the pattern's own
         *          bytes buffer so a readable sweep never returns the needle's own storage. Returns the Nth match and
         *          the incomplete flag.
         */
        [[nodiscard]] MatchResult scan_readable_regions(const EnginePattern &pattern,
                                                        std::size_t occurrence = 1) noexcept;

        /**
         * @brief Maps a public scan::Pages class to a module-scoped page-gated scan.
         * @details Pages::Readable selects @ref scan_module_readable (the data-capable superset), Pages::Executable
         *          selects @ref scan_module_executable (code-only).
         */
        [[nodiscard]] MatchResult scan_module_pages(const EnginePattern &pattern, Memory::ModuleRange range,
                                                    scan::Pages pages, std::size_t occurrence) noexcept;

        /**
         * @struct ExecutableWindow
         * @brief One committed, execute-readable slice of a module image.
         * @details @ref base / @ref span describe bytes that passed the same VirtualQuery protection gate the scans
         *          apply (MEM_COMMIT, execute-readable, not PAGE_GUARD / PAGE_NOACCESS) at gate time. The gate proves
         *          readability only at that instant, so a caller reading [base, base + span) should still wrap the read
         *          in a fault guard against a concurrent decommit / reprotect.
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
         * @details Walks [range.base, range.end) via VirtualQuery, returning each committed, execute-readable region
         *          clamped to the range. Centralizes the executable-page gate so an out-of-TU caller (the string-xref
         *          backend) scans the image's code without re-deriving the Windows page masks.
         * @return The execute-readable windows; empty when @p range is invalid or it exposes no readable code pages.
         */
        [[nodiscard]] std::vector<ExecutableWindow> collect_executable_windows(Memory::ModuleRange range);

        /**
         * @brief True when @p address lies on a committed, execute-readable page.
         * @details Single-address VirtualQuery gate using the same page-protection set the module and whole-process
         *          executable scans accept. The prologue-recovery fallback validates a decoded jump destination with
         *          it; the destination is intentionally NOT module-constrained (a sibling mod's trampoline is allocated
         *          outside every loaded module), while this still rejects a jump into unmapped or data-only memory.
         */
        [[nodiscard]] bool is_executable_address(std::uintptr_t address) noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_PAGES_HPP
