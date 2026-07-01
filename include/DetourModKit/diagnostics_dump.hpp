#ifndef DETOURMODKIT_DIAGNOSTICS_DUMP_HPP
#define DETOURMODKIT_DIAGNOSTICS_DUMP_HPP

/**
 * @file diagnostics_dump.hpp
 * @brief One-call aggregator that snapshots DMK's runtime diagnostics -- intentional-leak counters and self-heal
 *        drift -- into a single struct.
 * @details Each piece is already queryable on its own (@ref DetourModKit::Diagnostics::intentional_leak_count, @ref
 *          DetourModKit::rtti::heal_report). This header only bundles them so a consumer can capture a one-shot health
 *          view in a single call instead of stitching the sources together by hand.
 */

#include "DetourModKit/diagnostics.hpp"
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

            /// Landmarks in the supplied drift report.
            std::size_t drift_total = 0;
            /// Landmarks that healed (@ref rtti::DriftEntry::ok).
            std::size_t drift_healed = 0;
            /// Landmarks that failed to heal.
            std::size_t drift_failed = 0;
        };

        /**
         * @brief Aggregates DMK's live diagnostics into one @ref Snapshot.
         * @details Reads the process-wide intentional-leak counters and counts healed vs failed entries in
         *          @p drift_report. The drift report is caller-owned (typically the output of @ref rtti::heal_report);
         *          pass an empty span to skip the drift summary.
         * @param drift_report A self-heal drift report, or an empty span to skip the drift summary.
         * @return The aggregated snapshot.
         * @note Setup/control-plane only: not callback-safe. Call it from init / a worker / a diagnostics command.
         */
        [[nodiscard]] Snapshot collect(std::span<const rtti::DriftEntry> drift_report = {});
    } // namespace Diagnostics
} // namespace DetourModKit

#endif // DETOURMODKIT_DIAGNOSTICS_DUMP_HPP
