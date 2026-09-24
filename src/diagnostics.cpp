/**
 * @file diagnostics.cpp
 * @brief Counters for DMK's intentional leak / detach paths, the per-reason module-pin counts, the diagnostic event
 *        bus, the live hook population tally, and the one-call Snapshot aggregator. All of it is scoped to one linked
 *        DMK instance.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "internal/diagnostics_population.hpp"
#include "internal/drain_backoff.hpp"
#include "internal/lifecycle_context.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <new>

namespace DetourModKit
{
    namespace diagnostics
    {
        namespace
        {
            // Published once each dispatcher exists, so teardown never constructs one.
            constinit std::atomic<EventDispatcher<ScannerFaultEvent> *> s_scanner_faults{nullptr};
            constinit std::atomic<EventDispatcher<HookLifecycleEvent> *> s_hook_lifecycle{nullptr};

            constexpr std::size_t LEAK_SUBSYSTEM_COUNT = static_cast<std::size_t>(LeakSubsystem::Count);

            // One independent event tally per subsystem. Relaxed throughout: the counters carry no ordering obligation
            // toward any other state.
            std::array<std::atomic<std::size_t>, LEAK_SUBSYSTEM_COUNT> s_leak_counts{};

            constexpr std::size_t MODULE_PIN_REASON_COUNT = static_cast<std::size_t>(ModulePinReason::Count);
            static_assert(
                MODULE_PIN_REASON_COUNT == DetourModKit::detail::module_pin_observability::MODULE_PIN_REASON_COUNT,
                "ModulePinReason::Count and the internal counter array size must stay equal"
            );
        } // namespace

        void record_intentional_leak(LeakSubsystem subsystem) noexcept
        {
            const auto index = static_cast<std::size_t>(subsystem);
            if (index >= LEAK_SUBSYSTEM_COUNT)
            {
                return;
            }
            s_leak_counts[index].fetch_add(1, std::memory_order_relaxed);
        }

        std::size_t intentional_leak_count(LeakSubsystem subsystem) noexcept
        {
            const auto index = static_cast<std::size_t>(subsystem);
            if (index >= LEAK_SUBSYSTEM_COUNT)
            {
                return 0;
            }
            return s_leak_counts[index].load(std::memory_order_relaxed);
        }

        std::size_t total_intentional_leaks() noexcept
        {
            std::size_t total = 0;
            for (const auto &counter : s_leak_counts)
            {
                total += counter.load(std::memory_order_relaxed);
            }
            return total;
        }

        void reset_intentional_leaks() noexcept
        {
            for (auto &counter : s_leak_counts)
            {
                counter.store(0, std::memory_order_relaxed);
            }
        }

        std::size_t module_pin_count(ModulePinReason reason) noexcept
        {
            const auto index = static_cast<std::size_t>(reason);
            if (index >= MODULE_PIN_REASON_COUNT)
            {
                return 0;
            }
            return DetourModKit::detail::module_pin_observability::s_outstanding[index].load(std::memory_order_relaxed);
        }

        std::size_t total_module_pins() noexcept
        {
            std::size_t total = 0;
            for (const auto &counter : DetourModKit::detail::module_pin_observability::s_outstanding)
            {
                total += counter.load(std::memory_order_relaxed);
            }
            return total;
        }

        LifecycleCounters lifecycle_counters() noexcept
        {
            LifecycleCounters counters;
            counters.reaper_started =
                DetourModKit::detail::lifecycle_observability::s_reaper_started.load(std::memory_order_relaxed);
            counters.permanent_pins =
                DetourModKit::detail::lifecycle_observability::s_permanent_pins.load(std::memory_order_relaxed);
            counters.abandoned_owners =
                DetourModKit::detail::lifecycle_observability::s_abandoned_owners.load(std::memory_order_relaxed);
            return counters;
        }

        EventDispatcher<ScannerFaultEvent> &scanner_faults()
        {
            // Never destroyed, for the same reason as hook_lifecycle(). A scan can be driven from a namespace-scope
            // object's destructor or from a module-pinned thread that outlives this TU's static destructors, and the
            // consumer's own Subscription can likewise be destroyed after them; both would then reach a destroyed
            // mutex and subscriber list, which no try/catch can contain because it is undefined behaviour rather than
            // an exception.
            alignas(
                EventDispatcher<ScannerFaultEvent>
            ) static unsigned char storage[sizeof(EventDispatcher<ScannerFaultEvent>)];
            static EventDispatcher<ScannerFaultEvent> *const dispatcher = []
            {
                auto *const created = ::new (static_cast<void *>(storage)) EventDispatcher<ScannerFaultEvent>();
                s_scanner_faults.store(created, std::memory_order_release);
                return created;
            }();
            return *dispatcher;
        }

        EventDispatcher<HookLifecycleEvent> &hook_lifecycle()
        {
            // Never destroyed because ~Hook and ~VmtHook may emit after this translation unit's static destructors.
            alignas(
                EventDispatcher<HookLifecycleEvent>
            ) static unsigned char storage[sizeof(EventDispatcher<HookLifecycleEvent>)];
            static EventDispatcher<HookLifecycleEvent> *const dispatcher = []
            {
                auto *const created = ::new (static_cast<void *>(storage)) EventDispatcher<HookLifecycleEvent>();
                s_hook_lifecycle.store(created, std::memory_order_release);
                return created;
            }();
            return *dispatcher;
        }

        Snapshot
        collect(std::span<const rtti::DriftEntry> drift_report, std::span<const anchor::ResolvedAnchor> anchor_report)
        {
            Snapshot snapshot;

            // Derive the total by summing the per-subsystem values captured into this snapshot (rather than a second
            // independent total_intentional_leaks() read), so snapshot.total_intentional_leaks always equals the sum of
            // the breakdown even if a counter is incremented concurrently between the copy and the total.
            for (std::size_t i = 0; i < snapshot.intentional_leaks.size(); ++i)
            {
                snapshot.intentional_leaks[i] = intentional_leak_count(static_cast<LeakSubsystem>(i));
                snapshot.total_intentional_leaks += snapshot.intentional_leaks[i];
            }

            DetourModKit::detail::hook_population::read(
                snapshot.hooks_total,
                snapshot.hooks_active,
                snapshot.hooks_disabled
            );

            // Same derivation rule as the leak total: sum the captured breakdown, not a second independent read.
            for (std::size_t i = 0; i < snapshot.module_pins.size(); ++i)
            {
                snapshot.module_pins[i] = module_pin_count(static_cast<ModulePinReason>(i));
                snapshot.total_module_pins += snapshot.module_pins[i];
            }

            snapshot.lifecycle = lifecycle_counters();

            snapshot.drift_total = drift_report.size();
            for (const rtti::DriftEntry &entry : drift_report)
            {
                if (entry.ok)
                {
                    ++snapshot.drift_healed;
                }
                else
                {
                    ++snapshot.drift_failed;
                }
            }

            snapshot.anchor_quality = anchor::assess_quality(anchor_report);

            return snapshot;
        }
    } // namespace diagnostics

    namespace detail
    {
        struct DiagnosticsEmitOwner
        {
            /// The event-independent form of the dispatcher's release outcome.
            enum class Outcome : std::uint8_t
            {
                Returned,
                LiveSubscription,
                Busy,
                Unwaitable
            };

            template <typename Event>
            [[nodiscard]] static Outcome release(EventDispatcher<Event> &dispatcher, bool may_prune) noexcept
            {
                using Release = typename EventDispatcher<Event>::EmitOwnerRelease;
                switch (dispatcher.release_idle_emit_owner(may_prune))
                {
                case Release::Released:
                case Release::NotOwner:
                    return Outcome::Returned;
                case Release::LiveSubscription:
                    return Outcome::LiveSubscription;
                case Release::Busy:
                    return Outcome::Busy;
                case Release::Unwaitable:
                    break;
                }
                return Outcome::Unwaitable;
            }
        };

        namespace
        {
            using Outcome = DiagnosticsEmitOwner::Outcome;

            /// Bounds the teardown wait for a diagnostics emit. Expiry keeps the index ([B-73]).
            constexpr auto DIAGNOSTICS_DRAIN_TIMEOUT = std::chrono::seconds{1};

            // One releaser at a time settles the records below.
            constinit std::atomic_flag s_release_running{};
            // Set while a kept ownership holds its one LeakSubsystem::Diagnostics record.
            constinit std::atomic<bool> s_scanner_faults_recorded{false};
            constinit std::atomic<bool> s_hook_lifecycle_recorded{false};

            /// The teardown result of one diagnostics dispatcher.
            struct KeptIndex
            {
                const char *dispatcher_name;
                Outcome outcome;
                std::atomic<bool> &recorded;
            };

            [[nodiscard]] bool process_is_exiting() noexcept
            {
                if (lifecycle().loader_context() == LoaderContext::ProcessExit)
                {
                    return true;
                }
                // A consumer without bootstrap_detach publishes no context, so the loader supplies the answer.
                using ShutdownProbe = BOOLEAN(NTAPI *)();
                const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
                // GCC treats void (*)() as compatible with every function type.
                using AnyFunction = void (*)();
                const auto probe = ntdll != nullptr ? reinterpret_cast<ShutdownProbe>(reinterpret_cast<AnyFunction>(
                                                          ::GetProcAddress(ntdll, "RtlDllShutdownInProgress")
                                                      ))
                                                    : nullptr;
                return probe != nullptr && probe() != FALSE;
            }

            [[nodiscard]] const char *kept_cause(Outcome outcome) noexcept
            {
                switch (outcome)
                {
                case Outcome::LiveSubscription:
                    return "a subscription is still live. Drop every subscription before Session teardown";
                case Outcome::Busy:
                    return "an emit still held a handler list";
                case Outcome::Returned:
                case Outcome::Unwaitable:
                    break;
                }
                return "the teardown ran inside a diagnostics emit or while an untracked emit ran";
            }

            void settle(const KeptIndex &kept, DiagnosticsTeardown teardown, bool may_block) noexcept
            {
                if (kept.outcome == Outcome::Returned)
                {
                    kept.recorded.store(false, std::memory_order_relaxed);
                    return;
                }
                // Outside Session teardown, a live subscription is an ordinary owner, for example across a cache
                // restart.
                if (kept.outcome == Outcome::LiveSubscription && teardown == DiagnosticsTeardown::CacheShutdown)
                {
                    return;
                }
                if (kept.recorded.exchange(true, std::memory_order_relaxed))
                {
                    return;
                }
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Diagnostics);
                if (!may_block)
                {
                    return;
                }
                try
                {
                    (void)log().try_log(
                        LogLevel::Warning,
                        "Diagnostics: the {} dispatcher kept its emit TLS index at teardown. Cause: {}.",
                        kept.dispatcher_name,
                        kept_cause(kept.outcome)
                    );
                }
                catch (...)
                {
                }
            }
        } // namespace

        void release_diagnostics_emit_owners(DiagnosticsTeardown teardown, bool may_block) noexcept
        {
            // The index dies with the process, and a killed thread can still hold a list lock.
            if (process_is_exiting())
            {
                return;
            }
            auto *const hooks = diagnostics::s_hook_lifecycle.load(std::memory_order_acquire);
            auto *const scans = diagnostics::s_scanner_faults.load(std::memory_order_acquire);
            if ((hooks == nullptr && scans == nullptr) || s_release_running.test_and_set(std::memory_order_acquire))
            {
                return;
            }

            // A wait from inside a diagnostics emit, or beside an untracked emit, can wait on this thread.
            const bool may_wait = may_block && !(hooks != nullptr && thread_is_emitting_dispatcher(hooks)) &&
                                  !(scans != nullptr && thread_is_emitting_dispatcher(scans)) &&
                                  untracked_emit_frames().load(std::memory_order_seq_cst) == 0;
            const auto release_hooks = [hooks, may_block]() noexcept
            { return hooks != nullptr ? DiagnosticsEmitOwner::release(*hooks, may_block) : Outcome::Returned; };
            const auto release_scans = [scans, may_block]() noexcept
            { return scans != nullptr ? DiagnosticsEmitOwner::release(*scans, may_block) : Outcome::Returned; };
            Outcome hook_outcome = release_hooks();
            Outcome scan_outcome = release_scans();
            if (may_wait)
            {
                const auto deadline = std::chrono::steady_clock::now() + DIAGNOSTICS_DRAIN_TIMEOUT;
                DrainBackoff backoff;
                while ((hook_outcome == Outcome::Busy || scan_outcome == Outcome::Busy) &&
                       std::chrono::steady_clock::now() < deadline)
                {
                    backoff.pause();
                    if (hook_outcome == Outcome::Busy)
                    {
                        hook_outcome = release_hooks();
                    }
                    if (scan_outcome == Outcome::Busy)
                    {
                        scan_outcome = release_scans();
                    }
                }
            }
            settle({"hook_lifecycle", hook_outcome, s_hook_lifecycle_recorded}, teardown, may_block);
            settle({"scanner_faults", scan_outcome, s_scanner_faults_recorded}, teardown, may_block);
            s_release_running.clear(std::memory_order_release);
        }
    } // namespace detail
} // namespace DetourModKit
