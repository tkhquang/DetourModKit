#ifndef DETOURMODKIT_INTERNAL_ANCHOR_RESOLUTION_HPP
#define DETOURMODKIT_INTERNAL_ANCHOR_RESOLUTION_HPP

/**
 * @file internal/anchor_resolution.hpp
 * @brief Supplies private anchor resolution data for mutation-gate freshness checks.
 */

#include "DetourModKit/anchor.hpp"

namespace DetourModKit::anchor::internal
{
    /**
     * @brief Resolves an anchor and returns the selected byte rung's match span.
     * @param anchor The anchor to resolve.
     * @param scope The memory scope to inspect.
     * @param winning_span Receives the selected byte rung's match span. Other backends leave it empty.
     * @return The normal anchor resolution result.
     */
    [[nodiscard]] ResolvedAnchor resolve_with_winning_span(const Anchor &anchor, Region scope, Region &winning_span);
} // namespace DetourModKit::anchor::internal

#endif // DETOURMODKIT_INTERNAL_ANCHOR_RESOLUTION_HPP
