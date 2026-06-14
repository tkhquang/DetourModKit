#ifndef DETOURMODKIT_DIAGNOSTICS_DUMP_HPP
#define DETOURMODKIT_DIAGNOSTICS_DUMP_HPP

/**
 * @file diagnostics_dump.hpp
 * @brief One-call aggregator that snapshots DMK's runtime diagnostics -- intentional-leak counters, hook population,
 *        anchor-manifest robustness, and self-heal drift -- into a single struct.
 * @details Each piece is already queryable on its own (@ref DetourModKit::Diagnostics::intentional_leak_count, @ref
 *          DetourModKit::HookManager::get_hook_counts, @ref DetourModKit::Anchors::assess_quality, @ref
 *          DetourModKit::Rtti::heal_report). This header only bundles them so a consumer can capture a one-shot health
 *          view in a single call instead of stitching four sources together by hand.
 */

#include "DetourModKit/anchors.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/rtti_dissect.hpp"

#include <array>
#include <cstddef>
#include <span>

namespace DetourModKit
{
    namespace Diagnostics
    {
        /**
         * @struct Snapshot
         * @brief A point-in-time aggregate of DMK's runtime diagnostics.
         * @details A plain value snapshot produced by @ref collect. It re-resolves nothing: every field is copied from
         *          a source that already holds the live state, so reading the snapshot never touches a lock or the
         *          scanner again.
         */
        struct Snapshot
        {
            /// Intentional leak / detach events per subsystem, indexed by @c static_cast<std::size_t>(LeakSubsystem).
            std::array<std::size_t, static_cast<std::size_t>(LeakSubsystem::Count)> intentional_leaks{};
            /// Total intentional leak / detach events across all subsystems.
            std::size_t total_intentional_leaks = 0;

            /// Inline + mid hooks currently active (@ref HookStatus::Active).
            std::size_t hooks_active = 0;
            /// Inline + mid hooks currently disabled (@ref HookStatus::Disabled).
            std::size_t hooks_disabled = 0;
            /// Inline + mid hooks the HookManager owns, in any status (VMT hooks are tracked separately).
            std::size_t hooks_total = 0;

            /// Anchor-manifest robustness summary over the supplied report.
            Anchors::AnchorQuality anchor_quality{};

            /// Landmarks in the supplied drift report.
            std::size_t drift_total = 0;
            /// Landmarks that healed (@ref Rtti::DriftEntry::ok).
            std::size_t drift_healed = 0;
            /// Landmarks that failed to heal.
            std::size_t drift_failed = 0;
        };

        /**
         * @brief Aggregates DMK's live diagnostics into one @ref Snapshot.
         * @details Reads the process-wide intentional-leak counters, folds @p hooks.get_hook_counts() into active /
         *          disabled / total tallies, summarizes @p anchor_report through @ref Anchors::assess_quality, and
         *          counts healed vs failed entries in @p drift_report. The anchor and drift reports are caller-owned
         *          (typically the output of @ref Anchors::resolve_all and @ref Rtti::heal_report); pass empty spans to
         *          omit either.
         * @param hooks The HookManager whose population to snapshot (typically @ref HookManager::get_instance()).
         * @param anchor_report A resolved anchor report, or an empty span to skip the anchor summary.
         * @param drift_report A self-heal drift report, or an empty span to skip the drift summary.
         * @return The aggregated snapshot.
         * @note Setup/control-plane only: @ref HookManager::get_hook_counts allocates and takes a shared lock, so this
         *       is not callback-safe. Call it from init / a worker / a diagnostics command, never from a hook callback.
         */
        [[nodiscard]] Snapshot collect(const HookManager &hooks,
                                       std::span<const Anchors::ResolvedAnchor> anchor_report = {},
                                       std::span<const Rtti::DriftEntry> drift_report = {});
    } // namespace Diagnostics
} // namespace DetourModKit

#endif // DETOURMODKIT_DIAGNOSTICS_DUMP_HPP
