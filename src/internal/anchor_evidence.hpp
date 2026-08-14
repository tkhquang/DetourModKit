#ifndef DETOURMODKIT_INTERNAL_ANCHOR_EVIDENCE_HPP
#define DETOURMODKIT_INTERNAL_ANCHOR_EVIDENCE_HPP

/**
 * @file internal/anchor_evidence.hpp
 * @brief Evidence-identity seam owned by anchor_evidence.cpp for the anchor resolution TU.
 */

#include "DetourModKit/anchor.hpp"

#include <span>

namespace DetourModKit::anchor::internal
{
    /**
     * @brief Reports whether every quorum member pair provides independent evidence.
     * @details One dependent pair can count one site twice. This rule limits WithinTolerance to content-independent
     *          members and prevents a near-value cluster from two adjacent reads of one site. The evidence atoms in
     *          anchor_evidence.cpp define the canonical independence axes. An atom collision rejects a valid pair and
     *          therefore fails closed. Complexity is O(M^2) for the small declared M.
     * @param members Quorum member pointers. Each pointer must be non-null.
     * @return true if every member pair is independent, otherwise false.
     */
    [[nodiscard]] bool quorum_members_pairwise_independent(std::span<const Anchor *const> members);
} // namespace DetourModKit::anchor::internal

#endif // DETOURMODKIT_INTERNAL_ANCHOR_EVIDENCE_HPP
