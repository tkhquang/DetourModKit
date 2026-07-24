#ifndef DETOURMODKIT_INTERNAL_SCAN_PROLOGUE_RECOVERY_HPP
#define DETOURMODKIT_INTERNAL_SCAN_PROLOGUE_RECOVERY_HPP

/**
 * @file internal/scan_prologue_recovery.hpp
 * @brief True-private hooked-prologue recovery: rebuild each Direct candidate's prologue as a recognised inline-hook
 *        jump shape and recover the single site a sibling mod already inline-hooked.
 * @details Never installed. The resolver runs this only when every direct candidate missed and the request enabled a
 *          non-Off fallback policy. It is an implementation strategy of scan_resolution, not a public entry point: for
 *          each Direct candidate it tries each jump shape (E9 near jump, FF 25 indirect, FF 25 absolute, mov rax/jmp
 *          rax), requires the rebuilt pattern to match exactly once in the scope's executable pages, decodes the jump
 *          to confirm a real redirect, and resolves the anchored match.
 */

#include "DetourModKit/scan.hpp"

#include "internal/memory_guarded.hpp"

#include <cstddef>
#include <optional>
#include <span>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct FallbackOutcome
         * @brief The result of a prologue-recovery pass over a candidate ladder.
         * @details @ref hit holds the recovered Hit when a shape uniquely recovered an executable target and that site
         *          passed the request's identity gate (@ref scan::FallbackPolicy). @ref not_applicable stays true until
         *          some Direct candidate yields a usable rebuilt pattern, so the resolver can report
         *          PrologueFallbackNotApplicable only when a Direct row existed but its literal tail was too short.
         *          @ref had_direct is true once any Direct candidate was a real rebuild target. @ref identity_rejected
         *          is set when RequireIdentity refused a structurally-recovered site, so the resolver reports
         *          PrologueIdentityRejected rather than a plain miss. @ref identity_warned is set when a WarnOnly
         *          witness disagreed with the returned site, so the resolver can log the drift while still accepting.
         *          @ref incomplete records that some shape's rebuilt-pattern sweep skipped a faulted region, so a
         *          recovery that found nothing is an unproven absence rather than a miss. @ref ambiguous records that a
         *          rebuilt shape matched more than one executable site, so the recovery cannot name a single redirect.
         */
        struct FallbackOutcome
        {
            std::optional<scan::Hit> hit;
            bool not_applicable = true;
            bool had_direct = false;
            bool identity_rejected = false;
            bool identity_warned = false;
            bool incomplete = false;
            bool ambiguous = false;
        };

        /**
         * @brief Runs hooked-prologue recovery across the ordered ladder.
         * @param request The resolution request (its ladder is indexed through @p order).
         * @param order The try order (indices into request.ladder), as produced by order_candidates.
         * @param range The module image to scan, in engine ModuleSpan form.
         * @return The recovery outcome: a Hit when a shape uniquely recovered an executable target, plus the
         *         applicability diagnostics. May allocate while rebuilding patterns, so it is not noexcept.
         */
        [[nodiscard]] FallbackOutcome resolve_prologue_fallback(const scan::ScanRequest &request,
                                                                std::span<const std::size_t> order, ModuleSpan range);
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_PROLOGUE_RECOVERY_HPP
