#ifndef DETOURMODKIT_DIAGNOSTICS_HPP
#define DETOURMODKIT_DIAGNOSTICS_HPP

/**
 * @file diagnostics.hpp
 * @brief Consumer-queryable counters for DMK's intentional leak / detach paths, a process-wide diagnostic event bus
 *        for scanner-fault and hook-lifecycle transitions, and a one-call runtime-diagnostics @ref
 *        DetourModKit::diagnostics::Snapshot aggregator.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/detail/event_dispatcher.hpp"
#include "DetourModKit/rtti_dissect.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace DetourModKit
{
    namespace diagnostics
    {
        /**
         * @enum LeakSubsystem
         * @brief Identifies the subsystem that took an intentional leak / detach path.
         * @details Each enumerator names one teardown site that deliberately leaks storage or detaches a thread instead
         *          of joining or freeing, to stay safe under the Windows loader lock (where a join or free would risk a
         *          deadlock or a use-after-unmap). These events fire at most once per subsystem per process and only on
         *          the loader-lock teardown path; they are not normal-shutdown counters.
         */
        enum class LeakSubsystem : std::uint8_t
        {
            HookManager,
            Logger,
            AsyncLogger,
            ConfigWatcher,
            Input,
            MemoryCache,
            Worker,
            Bootstrap,
            /// Sentinel: the number of tracked subsystems. Not a subsystem.
            Count
        };

        /**
         * @brief Records that @p subsystem took an intentional leak / detach path.
         * @details Performs a single relaxed atomic increment on a process-wide counter. Safe to call from a noexcept
         *          destructor and from
         *          DllMain / loader-lock context: it touches only a static atomic and never allocates, locks, or calls
         *          a Win32 API.
         * @param subsystem The subsystem reporting the event. @ref LeakSubsystem::Count (or any out-of-range value) is
         *                  ignored.
         * @note Relaxed ordering is sufficient: the counter is an independent event tally with no happens-before
         *       relationship to other state.
         */
        void record_intentional_leak(LeakSubsystem subsystem) noexcept;

        /**
         * @brief Returns how many intentional leak / detach events @p subsystem recorded.
         * @param subsystem The subsystem to query.
         * @return The event count, or 0 if @p subsystem is out of range.
         */
        [[nodiscard]] std::size_t intentional_leak_count(LeakSubsystem subsystem) noexcept;

        /**
         * @brief Returns the total intentional leak / detach events across all subsystems.
         * @return The summed event count.
         */
        [[nodiscard]] std::size_t total_intentional_leaks() noexcept;

        /**
         * @brief Resets every subsystem counter to zero.
         * @details Intended for test isolation; consumers normally only read.
         */
        void reset_intentional_leaks() noexcept;

        /**
         * @struct ScannerFaultEvent
         * @brief A region-walking AOB sweep skipped one or more regions that faulted mid-scan.
         * @details Emitted once per sweep by the page-filtered scanners (the executable and readable region walks and
         *          the module-scoped sweeps) when a concurrent decommit / reprotect faults a region between the
         *          per-region VirtualQuery gate and the unguarded read. The sweep already skipped each faulted region
         *          and continued; the event surfaces the same count the scanner also logs at Debug, so a consumer can
         *          observe TOCTOU pressure without scraping logs. A clean sweep emits nothing.
         */
        struct ScannerFaultEvent
        {
            /// Number of regions skipped because they faulted mid-scan.
            std::size_t faulted_regions = 0;
            /// Inclusive low bound of the scanned window.
            std::uintptr_t window_low = 0;
            /// Exclusive high bound of the scanned window.
            std::uintptr_t window_high = 0;
        };

        /**
         * @enum HookKind
         * @brief Which hook flavor a @ref HookLifecycleEvent describes.
         */
        enum class HookKind : std::uint8_t
        {
            Inline,
            Mid,
            Vmt
        };

        /**
         * @enum HookTransition
         * @brief The lifecycle transition a @ref HookLifecycleEvent reports.
         */
        enum class HookTransition : std::uint8_t
        {
            /// A hook was created (installed) by an install verb (inline_at / mid_at / vmt_for).
            Created,
            /// An existing hook was enabled.
            Enabled,
            /// An existing hook was disabled.
            Disabled,
            /// A hook was removed.
            Removed
        };

        /**
         * @struct HookLifecycleEvent
         * @brief A hook crossed an install / enable / disable / remove transition.
         * @details Emitted by the hook surface after the operation completes; the emit holds no hook lock, so a handler
         *          runs outside any hook critical section. Failed operations and idempotent no-ops emit nothing: every
         *          event represents a completed state transition. If a handler performs another hook mutation, that
         *          mutation is a new operation and may emit nested lifecycle events; avoid unbounded event recursion.
         *          @ref name aliases the hook id only for the duration of the emit call; copy it if the handler retains
         *          it past the call.
         */
        struct HookLifecycleEvent
        {
            /// The hook id (the caller-supplied name). Valid only for the duration of the emit call; copy to retain.
            std::string_view name;
            /// Process-unique lifetime identity for this hook; 0 means the hook is untracked.
            std::uint64_t ledger_id = 0;
            /// The hook flavor.
            HookKind kind = HookKind::Inline;
            /// The transition that occurred.
            HookTransition transition = HookTransition::Created;
        };

        /**
         * @brief Returns the process-wide dispatcher for @ref ScannerFaultEvent.
         * @details A single shared dispatcher the stateless scanner emits to. Subscribe before running a scan to see
         *          skipped-region faults. The returned reference is stable for the process lifetime.
         * @return The shared @ref ScannerFaultEvent dispatcher.
         * @note Setup/control-plane only on first call: lazily constructs the dispatcher (one heap allocation). Every
         *       subsequent call only returns the existing reference.
         */
        EventDispatcher<ScannerFaultEvent> &scanner_faults();

        /**
         * @brief Returns the process-wide dispatcher for @ref HookLifecycleEvent.
         * @details A single shared dispatcher the hook surface emits hook lifecycle transitions to. The returned
         *          reference is stable for the process lifetime.
         * @return The shared @ref HookLifecycleEvent dispatcher.
         * @note Setup/control-plane only on first call: lazily constructs the dispatcher (one heap allocation). Every
         *       subsequent call only returns the existing reference.
         */
        EventDispatcher<HookLifecycleEvent> &hook_lifecycle();

        /**
         * @struct Snapshot
         * @brief A point-in-time aggregate of DMK's runtime diagnostics, produced by @ref collect.
         * @details A plain value snapshot. It re-resolves nothing: the intentional-leak counters and the live hook
         *          population are copied from process-wide state that already holds them, and the drift / anchor
         *          summaries are tallied from the caller-supplied reports, so reading the snapshot never touches a lock
         *          on the hot path or re-runs the scanner.
         */
        struct Snapshot
        {
            /// Intentional leak / detach events per subsystem, indexed by @c static_cast<std::size_t>(LeakSubsystem).
            std::array<std::size_t, static_cast<std::size_t>(LeakSubsystem::Count)> intentional_leaks{};
            /// Total intentional leak / detach events across all subsystems.
            std::size_t total_intentional_leaks = 0;

            /// Live DMK hooks (inline + mid + VMT) across the process.
            std::size_t hooks_total = 0;
            /// Live hooks currently enabled (armed).
            std::size_t hooks_active = 0;
            /// Live hooks currently disabled. @ref hooks_active + @ref hooks_disabled == @ref hooks_total.
            std::size_t hooks_disabled = 0;

            /// Landmarks in the supplied drift report.
            std::size_t drift_total = 0;
            /// Landmarks that healed (@ref rtti::DriftEntry::ok).
            std::size_t drift_healed = 0;
            /// Landmarks that failed to heal.
            std::size_t drift_failed = 0;

            /// Robustness roll-up of the supplied anchor report (empty when no anchor report is passed).
            anchor::AnchorQuality anchor_quality{};
        };

        /**
         * @brief Aggregates DMK's live diagnostics into one @ref Snapshot.
         * @details Reads the process-wide intentional-leak counters and the live hook population (derived from the
         *          hook-lifecycle transition stream), and rolls up the two caller-owned reports: it counts healed vs
         *          failed entries in @p drift_report (typically @ref rtti::heal_report output) and runs
         *          @ref anchor::assess_quality over @p anchor_report (typically a resolve_all output). Pass an empty
         *          span to skip either summary.
         * @param drift_report A self-heal drift report, or an empty span to skip the drift summary.
         * @param anchor_report An anchor drift report, or an empty span to skip the anchor-quality summary.
         * @return The aggregated snapshot.
         * @note Setup/control-plane only: not callback-safe. Call it from init / a worker / a diagnostics command.
         */
        [[nodiscard]] Snapshot collect(std::span<const rtti::DriftEntry> drift_report = {},
                                       std::span<const anchor::ResolvedAnchor> anchor_report = {});
    } // namespace diagnostics
} // namespace DetourModKit

#endif // DETOURMODKIT_DIAGNOSTICS_HPP
