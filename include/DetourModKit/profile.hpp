#ifndef DETOURMODKIT_PROFILE_HPP
#define DETOURMODKIT_PROFILE_HPP

/**
 * @file profile.hpp
 * @brief Per-game scan-tuning control plane.
 * @details A @ref DetourModKit::ScanProfile bundles a few setup-only defaults a consumer can vary per game: whether the
 *          broad string-xref sweep is on by default, the cascade candidate-ordering preference, and a backend
 *          deny-list. It is a value type with no hot-path role and no hidden global state: a profile only supplies
 *          defaults, so explicitly declared per-call options stay visible at the call site. The deny-list fails closed
 *          -- a denied backend reports a typed failure, never a silent substitution of a different (possibly wrong)
 *          target. This header sits above both
 *          @ref scanner.hpp and @ref anchors.hpp because the profile spans the Scanner per-call options and the
 *          Anchors backend kinds; neither of those headers depends on this one.
 */

#include "DetourModKit/anchors.hpp"
#include "DetourModKit/scanner.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace DetourModKit
{
    /**
     * @enum CandidateOrder
     * @brief Cascade candidate-ordering preference a @ref ScanProfile supplies as a default.
     */
    enum class CandidateOrder : std::uint8_t
    {
        /// Try candidates exactly in declared array order (the existing behaviour).
        AsDeclared,
        /// Try strictly-unique (require_unique) candidates before the rest, declared order preserved within each group.
        UniqueFirst
    };

    /**
     * @brief Human-readable mapping for @ref CandidateOrder.
     * @param order The ordering preference.
     * @return A string view describing the ordering.
     */
    [[nodiscard]] constexpr std::string_view candidate_order_to_string(CandidateOrder order) noexcept
    {
        switch (order)
        {
        case CandidateOrder::AsDeclared:
            return "AsDeclared";
        case CandidateOrder::UniqueFirst:
            return "UniqueFirst";
        }
        return "Unknown candidate order";
    }

    /**
     * @struct ScanProfile
     * @brief Setup-only control-plane defaults for scan tuning. Value-semantic, not hot-path.
     * @details Bundles three per-game defaults: the broad string-xref sweep, the cascade candidate-ordering preference,
     *          and a backend deny-list. A profile only supplies defaults: broad string-xref can only widen, and
     *          candidate ordering is applied by building a local reordered span rather than mutating caller-owned
     *          tables. Trivially copyable; hold one per game in static or owner storage and pass it by const reference.
     *          Used only at setup/resolve time, never on a hot path.
     */
    struct ScanProfile
    {
        /**
         * @brief Default broad string-xref mode applied when a query leaves
         *        @ref Scanner::StringRefQuery::broad_match at its default.
         * @details Can only widen coverage, never disable it (see @ref apply_profile).
         */
        bool default_broad_string_xref = false;

        /// Cascade candidate-ordering preference. @ref CandidateOrder::AsDeclared preserves existing behaviour.
        CandidateOrder candidate_order = CandidateOrder::AsDeclared;

        /**
         * @brief Backend deny-list indexed by @ref Anchors::AnchorKind: a kind is denied when its slot is true.
         * @details A denied kind fails closed at resolve time (status Failed, value 0); it is never silently replaced
         *          by another backend. Default (all false) denies nothing.
         */
        std::array<bool, Anchors::ANCHOR_KIND_COUNT> deny_backend{};

        /**
         * @brief Whether @p kind is on the deny-list.
         * @param kind The anchor backend kind.
         * @return true when the kind is denied.
         */
        [[nodiscard]] bool is_denied(Anchors::AnchorKind kind) const noexcept
        {
            const auto index = static_cast<std::size_t>(kind);
            return index < deny_backend.size() && deny_backend[index];
        }
    };

    /**
     * @brief Returns a copy of @p query with profile defaults filled into any field left at its default.
     * @details Per-call wins: @c broad_match is turned on only when the query left it false AND the profile defaults it
     *          on. A query that explicitly set @c broad_match = true is never downgraded. Because a bool cannot
     *          distinguish "left default" from "explicitly off", the profile can only ever widen coverage (turn broad
     *          on), never force it off -- which only adds fail-closed coverage and never removes it. Pure, value in /
     *          value out.
     * @param profile The control-plane defaults.
     * @param query The per-call query (taken by value, returned modified).
     * @return The query with the profile's broad default applied.
     */
    [[nodiscard]] inline Scanner::StringRefQuery apply_profile(const ScanProfile &profile,
                                                               Scanner::StringRefQuery query) noexcept
    {
        if (!query.broad_match && profile.default_broad_string_xref)
        {
            query.broad_match = true;
        }
        return query;
    }

    /**
     * @brief Writes candidate indices into @p out in the profile's preferred order.
     * @details Produces a permutation of @c [0, candidates.size()) rather than mutating the caller's (typically static)
     *          candidate span: a consumer builds a reordered local array from the indices and passes it to a
     *          @c resolve_cascade* entry point. @ref CandidateOrder::AsDeclared writes the identity permutation; @ref
     *          CandidateOrder::UniqueFirst writes the require_unique candidates first (declared order preserved within
     *          each group). Reordering only changes WHICH provably-unique candidate is tried first; it cannot
     *          manufacture a wrong hit, because each candidate is still verified unique-in-scope and in-range at
     *          resolve time, so promoting strict anchors ahead of broad fallbacks is strictly a safety improvement.
     * @param profile The ordering preference.
     * @param candidates The candidate cascade.
     * @param out Destination index buffer; at most @c out.size() indices are written.
     * @return The number of indices written: @c min(candidates.size(), out.size()).
     */
    [[nodiscard]] inline std::size_t order_candidates(const ScanProfile &profile,
                                                      std::span<const Scanner::AddrCandidate> candidates,
                                                      std::span<std::size_t> out) noexcept
    {
        const std::size_t count = (candidates.size() < out.size()) ? candidates.size() : out.size();
        if (profile.candidate_order == CandidateOrder::UniqueFirst)
        {
            std::size_t written = 0;
            for (std::size_t i = 0; i < candidates.size() && written < count; ++i)
            {
                if (candidates[i].require_unique)
                {
                    out[written++] = i;
                }
            }
            for (std::size_t i = 0; i < candidates.size() && written < count; ++i)
            {
                if (!candidates[i].require_unique)
                {
                    out[written++] = i;
                }
            }
            return written;
        }
        for (std::size_t i = 0; i < count; ++i)
        {
            out[i] = i;
        }
        return count;
    }

    namespace Anchors
    {
        /**
         * @brief Resolves one anchor against a module range, honoring a @ref ScanProfile.
         * @details Identical to @ref resolve except that the profile is consulted first: a backend on the profile's
         *          deny-list fails closed (status @ref AnchorStatus::Failed, value 0) before any scan, never a silent
         *          substitution; @ref AnchorKind::StringXref inherits the profile's broad-default (widening only); and
         *          cascade-backed anchors (@ref AnchorKind::RipGlobal and @ref AnchorKind::CodeOperand) apply the
         *          profile's candidate-order preference through a local reordered span. For a @ref AnchorKind::Quorum
         *          the profile threads into both sub-anchors, so a denied sub-anchor kind fails the quorum closed and
         *          ordering/broad defaults stay uniform.
         * @param anchor The anchor declaration.
         * @param profile The control-plane defaults and deny-list.
         * @param range Module image to resolve in. Defaults to the host EXE.
         * @return The resolved value and status.
         */
        [[nodiscard]] ResolvedAnchor resolve_with_profile(const Anchor &anchor, const ScanProfile &profile,
                                                          Memory::ModuleRange range = Memory::host_module_range());

        /**
         * @brief Resolves a whole anchor table in one pass, honoring a @ref ScanProfile.
         * @param anchors The declarative anchor table.
         * @param out Destination, parallel to @p anchors. At most @c out.size() entries are written.
         * @param profile The control-plane defaults and deny-list.
         * @param range Module image to resolve in. Defaults to the host EXE.
         * @return The number of entries written: @c min(anchors.size(), out.size()).
         */
        [[nodiscard]] std::size_t resolve_all_with_profile(std::span<const Anchor> anchors,
                                                           std::span<ResolvedAnchor> out, const ScanProfile &profile,
                                                           Memory::ModuleRange range = Memory::host_module_range());
    } // namespace Anchors
} // namespace DetourModKit

#endif // DETOURMODKIT_PROFILE_HPP
