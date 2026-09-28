#ifndef DETOURMODKIT_DIAGNOSTICS_HPP
#define DETOURMODKIT_DIAGNOSTICS_HPP

/**
 * @file diagnostics.hpp
 * @brief Leak and module-pin counters, scanner-fault and hook-lifecycle event buses, and a Snapshot aggregator.
 * @details Every counter and dispatcher belongs to one linked DMK instance, not to the process.
 * @warning `[B-100]` Run dispatcher first use, subscription, and collect() outside the loader lock. Counter queries and
 *          recorders use only relaxed static atomics and stay Callback-safe. `DiagnosticsLoaderBoundary.*` pins the
 *          boundary.
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
         * @brief Identifies a subsystem that took an intentional leak or detach path. Caller-requested retention verbs
         *        also record here. These are not normal-shutdown counters. HookManager records one event per hook that
         *        retains its backend.
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
            /// A diagnostics dispatcher kept its emit-chain TLS index at teardown. See @ref hook_lifecycle.
            Diagnostics,
            /// The number of tracked subsystems, not a subsystem.
            Count
        };

        /**
         * @brief Adds one relaxed count to @p subsystem. An out-of-range value such as @ref LeakSubsystem::Count is
         *        ignored. A noexcept destructor or a DllMain caller can use it.
         */
        void record_intentional_leak(LeakSubsystem subsystem) noexcept;

        /** @brief Returns the event count of @p subsystem, or 0 if @p subsystem is out of range. */
        [[nodiscard]] std::size_t intentional_leak_count(LeakSubsystem subsystem) noexcept;

        /** @brief Returns the relaxed sum of all subsystem counts. @ref LifecycleCounters states the Worker overlap. */
        [[nodiscard]] std::size_t total_intentional_leaks() noexcept;

        /** @brief Resets every subsystem count to zero, for test isolation. */
        void reset_intentional_leaks() noexcept;

        /**
         * @brief Identifies the purpose of a counted module reference. Counts stay readable after Session teardown and
         *        during static teardown. Every reason except @ref XInputTarget references the module that links DMK.
         * @note After Session teardown, @ref MessageHookKeepalive is inert. A retained XInput pair or chain can still
         *       forward calls, and another open self-module reason can identify live code.
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
            /// Reserved inert value for the WndProc keepalive. It keeps its numeric value and never counts.
            WndprocKeepalive,
            /// Tracks the XInput self-reference until a rollback or uninstall that retains no XInput chain.
            XInputKeepalive,
            /// Tracks an XInput provider reference paired with @ref XInputKeepalive.
            XInputTarget,
            /// Tracks the permanent message-hook keepalive from the first successful local-backend hook publication.
            MessageHookKeepalive,
            /// The number of tracked reasons, not a reason.
            Count
        };

        /**
         * @brief Returns the outstanding counted module references of @p reason, or 0 if @p reason is out of range.
         * @note Callback-safe.
         */
        [[nodiscard]] std::size_t module_pin_count(ModulePinReason reason) noexcept;

        /**
         * @brief Returns the sum of @ref module_pin_count over all reasons. Concurrent transitions can skew it.
         * @note Callback-safe.
         */
        [[nodiscard]] std::size_t total_module_pins() noexcept;

        /**
         * @brief Monotonic counters of the lifecycle reaper, which can retain unbounded parcels. A Worker retirement
         *        can count in @ref abandoned_owners and in an intentional-leak counter, so their sum can overcount.
         */
        struct LifecycleCounters
        {
            /// Holds 1 after the process-lifetime reaper thread starts, and 0 before.
            std::size_t reaper_started = 0;
            /// Counts the permanent module reference that the reaper takes when its thread starts.
            std::size_t permanent_pins = 0;
            /// Counts failed retirements that the reaper retains permanently, with no subsystem attribution.
            std::size_t abandoned_owners = 0;
        };

        /**
         * @brief Returns the current @ref LifecycleCounters. Concurrent transitions can skew one field against another.
         * @note Callback-safe.
         */
        [[nodiscard]] LifecycleCounters lifecycle_counters() noexcept;

        /**
         * @brief A page-filtered AOB sweep skipped regions that faulted during the read, for example after a concurrent
         *        decommit or reprotect. On MinGW, it also skips each region while no guarded-read fault handler is
         *        installed, for example after Session teardown. One event follows the sweep. A clean sweep emits none.
         */
        struct ScannerFaultEvent
        {
            /// The number of regions skipped for a read fault or, on MinGW, a missing fault handler.
            std::size_t faulted_regions = 0;
            /// Inclusive low bound of the scanned window.
            std::uintptr_t window_low = 0;
            /// Exclusive high bound of the scanned window.
            std::uintptr_t window_high = 0;
        };

        /** @brief The hook flavor that a @ref HookLifecycleEvent describes. */
        enum class HookKind : std::uint8_t
        {
            Inline,
            Mid,
            Vmt
        };

        /** @brief The lifecycle transition that a @ref HookLifecycleEvent reports. */
        enum class HookTransition : std::uint8_t
        {
            /// An install verb (inline_at, mid_at, vmt_for) created the hook. Only a VMT hook starts Active.
            Created,
            /// An existing hook published Active: physically armed, or possibly reachable by a conservative estimate.
            Enabled,
            /// An existing hook was disabled.
            Disabled,
            /// A hook was removed.
            Removed
        };

        /**
         * @brief A hook crossed an install, enable, disable, or remove transition. The emit runs after the operation
         *        completes, outside every hook lock. A completed physical and published transition emits once, even
         *        when its Result carries a post-commit error. A failure without a transition, or an idempotent no-op,
         *        emits nothing. A hook mutation in a handler can emit nested events. Avoid unbounded event recursion.
         */
        struct HookLifecycleEvent
        {
            /// The caller-supplied hook name. It is valid only during the emit call, so copy it to retain it.
            std::string_view name;
            /// A lifetime identity, unique within this DMK instance. 0 means that the hook is untracked.
            std::uint64_t ledger_id = 0;
            /// The hook flavor.
            HookKind kind = HookKind::Inline;
            /// The transition that occurred.
            HookTransition transition = HookTransition::Created;
        };

        /**
         * @brief Returns the shared dispatcher for @ref ScannerFaultEvent. The dispatcher is never destroyed, so it
         *        stays valid through static teardown for a late module-pinned emitter. The TLS index contract of
         *        @ref hook_lifecycle also applies here.
         * @note Setup/control-plane only on the first call, which can allocate. Later calls only return the reference.
         */
        EventDispatcher<ScannerFaultEvent> &scanner_faults();

        /**
         * @brief Returns the shared dispatcher for @ref HookLifecycleEvent. It is never destroyed, so a hook destroyed
         *        during static teardown still emits safely.
         * @note Setup/control-plane only on the first call, which can allocate. Later calls only return the reference.
         * @note A subscription makes this dispatcher an owner of the emit-chain TLS index of this DMK instance. Session
         *       teardown returns that ownership when no subscription is live and no emit runs. Without an active
         *       Session, memory::shutdown_cache() returns an idle ownership, also one that an earlier teardown kept.
         *       For a live subscription, memory::shutdown_cache() keeps the ownership silently, with no leak record.
         * @note An authorized teardown waits up to one second for an emit to finish. It does not wait under the loader
         *       lock, inside a diagnostics handler, or while an untracked emit runs. If an emit still runs, teardown
         *       keeps the index and records one @ref LeakSubsystem::Diagnostics event per kept ownership. Teardown
         *       does not log under the loader lock and skips the release at process exit.
         *       `Lifecycle.DiagnosticsTlsIndex*` pins this contract.
         * @warning Drop every subscription before Session teardown. A subscription that is live at Session teardown
         *          keeps the index and records one @ref LeakSubsystem::Diagnostics event.
         */
        EventDispatcher<HookLifecycleEvent> &hook_lifecycle();

        /** @brief A value snapshot from @ref collect. Each counter group can reflect a different instant. */
        struct Snapshot
        {
            /// Events per subsystem, indexed by @c static_cast<std::size_t>(LeakSubsystem).
            std::array<std::size_t, static_cast<std::size_t>(LeakSubsystem::Count)> intentional_leaks{};
            /// The sum of @ref intentional_leaks.
            std::size_t total_intentional_leaks = 0;

            /**
             * @brief Live inline, mid, and VMT hooks. The count includes hooks created before the first @ref collect. A
             *        hook still counts after Hook::release() or VmtHook::release(), and while teardown keeps its target
             *        or clone conservatively tracked.
             */
            std::size_t hooks_total = 0;
            /// Live hooks in the Active state that @ref HookTransition::Enabled defines. A VMT hook starts Active.
            std::size_t hooks_active = 0;
            /// Live disabled hooks. @ref hooks_active + @ref hooks_disabled == @ref hooks_total, from one observation.
            std::size_t hooks_disabled = 0;

            /// The @ref lifecycle_counters values.
            LifecycleCounters lifecycle{};

            /// Landmarks in the supplied drift report.
            std::size_t drift_total = 0;
            /// Landmarks that healed (@ref rtti::DriftEntry::ok).
            std::size_t drift_healed = 0;
            /// Landmarks that failed to heal.
            std::size_t drift_failed = 0;

            /// Robustness roll-up of the supplied anchor report, empty when no anchor report is passed.
            anchor::AnchorQuality anchor_quality{};

            /// Outstanding counted references per reason, indexed by @c static_cast<std::size_t>(ModulePinReason).
            std::array<std::size_t, static_cast<std::size_t>(ModulePinReason::Count)> module_pins{};
            /// The sum of @ref module_pins.
            std::size_t total_module_pins = 0;
        };

        /**
         * @brief Aggregates the leak counters, counted module references, and hook population into a @ref Snapshot. It
         *        tallies the caller-owned reports without a scan. Pass an empty span to skip either report. Subscriber
         *        retirement and a cleared @ref hook_lifecycle do not change the hook population.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] Snapshot collect(
            std::span<const rtti::DriftEntry> drift_report = {},
            std::span<const anchor::ResolvedAnchor> anchor_report = {}
        );
    } // namespace diagnostics
} // namespace DetourModKit

#endif // DETOURMODKIT_DIAGNOSTICS_HPP
