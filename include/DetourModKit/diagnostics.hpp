#ifndef DETOURMODKIT_DIAGNOSTICS_HPP
#define DETOURMODKIT_DIAGNOSTICS_HPP

/**
 * @file diagnostics.hpp
 * @brief Consumer-queryable counters for DMK's intentional leak / detach paths, plus a process-wide diagnostic event
 *        bus for scanner-fault and hook-lifecycle transitions.
 */

#include "DetourModKit/event_dispatcher.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace DetourModKit
{
    namespace Diagnostics
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
            /// A hook was created (installed) by a create_*_hook call.
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
         * @brief A HookManager hook crossed an install / enable / disable / remove transition.
         * @details Emitted by @ref DetourModKit::HookManager after the operation completes and its registry locks are
         *          released. Failed operations and idempotent no-ops emit nothing: every event represents a completed
         *          state transition. A handler therefore runs outside the hook registry's critical section. If a
         *          handler performs another hook mutation, that mutation is a new operation and may emit nested
         *          lifecycle events; avoid unbounded event recursion. @ref name aliases the hook id only for the
         *          duration of the emit call; copy it if the handler retains it past the call.
         */
        struct HookLifecycleEvent
        {
            /// The hook id. Valid only for the duration of the emit call; copy to retain.
            std::string_view name;
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
         * @details A single shared dispatcher every HookManager emits hook lifecycle transitions to. The returned
         *          reference is stable for the process lifetime.
         * @return The shared @ref HookLifecycleEvent dispatcher.
         * @note Setup/control-plane only on first call: lazily constructs the dispatcher (one heap allocation). Every
         *       subsequent call only returns the existing reference.
         */
        EventDispatcher<HookLifecycleEvent> &hook_lifecycle();
    } // namespace Diagnostics
} // namespace DetourModKit

#endif // DETOURMODKIT_DIAGNOSTICS_HPP
