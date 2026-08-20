#ifndef DETOURMODKIT_DIAGNOSTICS_HPP
#define DETOURMODKIT_DIAGNOSTICS_HPP

/**
 * @file diagnostics.hpp
 * @brief Consumer-queryable counters for DMK's intentional leak / detach paths, a diagnostic event bus for
 *        scanner-fault and hook-lifecycle transitions, and a one-call runtime-diagnostics @ref
 *        DetourModKit::diagnostics::Snapshot aggregator.
 *
 * @details Every counter and dispatcher here is scoped to one linked DMK instance, not to the process. DMK is a static
 *          library, so two modules in one process that each link it hold independent diagnostic state: a subscriber
 *          registered through one module's dispatcher never observes the other module's events.
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
         * @details Each enumerator names a class of site that deliberately leaks storage or detaches a thread instead
         *          of joining or freeing. The caller-requested retention verbs book here too. These are not
         *          normal-shutdown counters, and a subsystem may record several events.
         *          @ref LeakSubsystem::HookManager books one per hook that pins its backend.
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
         * @details Performs a single relaxed atomic increment. Safe to call from a noexcept destructor and from
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
         * @details A Worker event can appear here and in @ref LifecycleCounters, so their sum is not a
         *          unique-incident count. The @ref intentional_leak_count function provides subsystem attribution.
         * @return The summed event count.
         * @note The function snapshots relaxed counters and never throws.
         */
        [[nodiscard]] std::size_t total_intentional_leaks() noexcept;

        /**
         * @brief Resets every subsystem counter to zero.
         * @details Intended for test isolation; consumers normally only read.
         */
        void reset_intentional_leaks() noexcept;

        /**
         * @enum ModulePinReason
         * @brief Identifies the purpose of a counted module reference.
         * @details Each counted reference uses one reason.
         *          Its live count equals successful acquires minus releases.
         *          Every reason except XInputTarget refers to the module that hosts this linked DMK instance.
         *          XInputTarget refers to an XInput provider module.
         * @note After Session teardown, WndprocKeepalive and a retained XInput pair are inert.
         *       Other open self-module reasons can identify live code.
         */
        enum class ModulePinReason : std::uint8_t
        {
            /// Tracks one reference per live inline, mid, or VMT hook until its teardown is proved.
            Hook,
            /// Tracks a StoppableWorker reference from before thread start until after its join.
            Worker,
            /// Tracks the bootstrap worker reference until the worker exits.
            Bootstrap,
            /// Tracks the async logger writer reference.
            AsyncLogger,
            /// Tracks the memory-cache cleanup thread reference.
            MemoryCache,
            /// Tracks the input poll thread reference.
            InputPoller,
            /// Tracks the permanent lifecycle-reaper reference also reported by @ref LifecycleCounters.
            LifecycleReaper,
            /// Tracks the permanent WndProc keepalive from the first eligible subclass attempt.
            WndprocKeepalive,
            /// Tracks the XInput self-reference until rollback or a proved clean uninstall.
            XInputKeepalive,
            /** @brief Tracks an XInput provider reference paired with @ref XInputKeepalive. */
            XInputTarget,
            /// Gives the number of tracked reasons and is not a reason.
            Count
        };

        /**
         * @brief Returns how many counted module references are outstanding under @p reason.
         * @details The count belongs to one linked DMK instance.
         *          It stays readable after @c ~Session and throughout static teardown.
         * @param reason The reason to query.
         * @return The outstanding reference count, or 0 if @p reason is out of range.
         * @note Callback-safe:
         *       - It performs one relaxed atomic read.
         *       - It allocates no memory.
         *       - It takes no lock and makes no Win32 call.
         */
        [[nodiscard]] std::size_t module_pin_count(ModulePinReason reason) noexcept;

        /**
         * @brief Returns the outstanding counted module references summed across all reasons.
         * @details Each reason has an independent sample.
         *          Concurrent transitions can skew the sum.
         * @return The summed outstanding reference count.
         * @note Callback-safe:
         *       - It performs relaxed atomic reads.
         *       - It allocates no memory.
         *       - It takes no lock and makes no Win32 call.
         */
        [[nodiscard]] std::size_t total_module_pins() noexcept;

        /**
         * @struct LifecycleCounters
         * @brief Contains observability counters for the lifecycle machinery's own retention decisions.
         * @details These counters expose the off-thread retirement facility. Each counter is monotonic and belongs to
         *          one linked DMK instance. The reaper can retain an unbounded number of parcels. A Worker retirement
         *          can increment an intentional-leak counter and @ref abandoned_owners. Their sum does not represent
         *          unique incidents. The abandoned-owner tally has no subsystem attribution.
         */
        struct LifecycleCounters
        {
            /// Holds 1 after the process-lifetime reaper thread launches and 0 before it launches.
            std::size_t reaper_started = 0;
            /// Counts the permanent module reference that the reaper takes when its thread starts.
            std::size_t permanent_pins = 0;
            /// Counts failed retirements that the reaper retains permanently.
            std::size_t abandoned_owners = 0;
        };

        /**
         * @brief Returns the lifecycle observability counters.
         * @return The current @ref LifecycleCounters values.
         * @note The function uses callback-safe relaxed atomic reads:
         *       - It allocates no memory.
         *       - It takes no lock.
         *       - It makes no Win32 call.
         * @note Each field is sampled independently. Concurrent lifecycle transitions can produce cross-field skew.
         */
        [[nodiscard]] LifecycleCounters lifecycle_counters() noexcept;

        /**
         * @struct ScannerFaultEvent
         * @brief A region-walking AOB sweep skipped one or more regions that faulted mid-scan.
         * @details Emitted once per sweep by the page-filtered scanners when a concurrent decommit / reprotect faults
         *          a region between the per-region VirtualQuery gate and the read. The region-granular fault guard
         *          covers both toolchains, so the sweep skipped each faulted region and continued. A clean sweep
         *          emits nothing.
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
            /**
             * @brief A hook was created by an install verb (inline_at / mid_at / vmt_for).
             * @details Inline and mid hooks are created disabled, so this reports the install, not an armed target;
             *          @ref Enabled reports the arming. A VMT hook is live on creation.
             */
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
            /// Lifetime identity unique within this linked DMK instance; 0 means the hook is untracked.
            std::uint64_t ledger_id = 0;
            /// The hook flavor.
            HookKind kind = HookKind::Inline;
            /// The transition that occurred.
            HookTransition transition = HookTransition::Created;
        };

        /**
         * @brief Returns this linked DMK instance's dispatcher for @ref ScannerFaultEvent.
         * @details A single shared dispatcher the stateless scanner emits to. Subscribe before running a scan to see
         *          skipped-region faults. The dispatcher is never destroyed, so the returned reference and the emit
         *          path both stay valid through static teardown and a late module-pinned emitter is still delivered.
         * @return The shared @ref ScannerFaultEvent dispatcher.
         * @note Setup/control-plane only on first call: construction may allocate. Every subsequent call only returns
         *       the existing reference.
         */
        EventDispatcher<ScannerFaultEvent> &scanner_faults();

        /**
         * @brief Returns this linked DMK instance's dispatcher for @ref HookLifecycleEvent.
         * @details A single shared dispatcher the hook surface emits hook lifecycle transitions to. Never destroyed, so
         *          a hook destroyed during static teardown still emits safely.
         * @return The shared @ref HookLifecycleEvent dispatcher.
         * @note Setup/control-plane only on first call: construction may allocate. Every subsequent call only returns
         *       the existing reference.
         */
        EventDispatcher<HookLifecycleEvent> &hook_lifecycle();

        /**
         * @struct Snapshot
         * @brief Holds an aggregate observation of DMK's runtime diagnostics from @ref collect.
         * @details This is a plain value snapshot. Independent counter groups can reflect different instants amid
         *          concurrent updates. Collection re-runs no scanner and tallies caller-supplied reports directly.
         */
        struct Snapshot
        {
            /// Intentional leak / detach events per subsystem, indexed by @c static_cast<std::size_t>(LeakSubsystem).
            std::array<std::size_t, static_cast<std::size_t>(LeakSubsystem::Count)> intentional_leaks{};
            /// Total intentional leak / detach events across all subsystems.
            std::size_t total_intentional_leaks = 0;

            /**
             * @brief Live DMK hooks (inline + mid + VMT) held by this linked DMK instance.
             * @details Tallied without allocation from process start, including hooks created before the first
             *          @ref collect.
             * @note A hook whose target or clone remains conservatively tracked after teardown stays counted, as does
             *       one abandoned by @c Hook::release() or @c VmtHook::release().
             */
            std::size_t hooks_total = 0;
            /// Live hooks currently enabled (armed). A VMT hook is armed from creation; inline and mid hooks are not.
            std::size_t hooks_active = 0;
            /// Live disabled hooks. @ref hooks_active + @ref hooks_disabled == @ref hooks_total, from one observation.
            std::size_t hooks_disabled = 0;

            /// Contains lifecycle observability counters copied from @ref lifecycle_counters.
            LifecycleCounters lifecycle{};

            /// Landmarks in the supplied drift report.
            std::size_t drift_total = 0;
            /// Landmarks that healed (@ref rtti::DriftEntry::ok).
            std::size_t drift_healed = 0;
            /// Landmarks that failed to heal.
            std::size_t drift_failed = 0;

            /// Robustness roll-up of the supplied anchor report (empty when no anchor report is passed).
            anchor::AnchorQuality anchor_quality{};

            /**
             * @brief Holds counted module references per reason.
             * @details Index each value with
             *          @c static_cast<std::size_t>(ModulePinReason).
             */
            std::array<std::size_t, static_cast<std::size_t>(ModulePinReason::Count)> module_pins{};
            /// Total outstanding counted module references across all reasons.
            std::size_t total_module_pins = 0;
        };

        /**
         * @brief Aggregates DMK's live diagnostics into one @ref Snapshot.
         * @details Reads this instance's intentional-leak counters, module pins, and hook population.
         *          It then rolls up both caller-owned reports.
         *          Subscriber retirement and a cleared @ref hook_lifecycle do not affect the population.
         *          Pass an empty span to skip either report.
         * @param drift_report A self-heal drift report.
         *                     Pass an empty span to skip the drift summary.
         * @param anchor_report An anchor drift report.
         *                      Pass an empty span to skip the anchor-quality summary.
         * @return The aggregated snapshot.
         * @note Setup/control-plane only: not callback-safe. Call it from init / a worker / a diagnostics command.
         */
        [[nodiscard]] Snapshot collect(std::span<const rtti::DriftEntry> drift_report = {},
                                       std::span<const anchor::ResolvedAnchor> anchor_report = {});
    } // namespace diagnostics
} // namespace DetourModKit

#endif // DETOURMODKIT_DIAGNOSTICS_HPP
