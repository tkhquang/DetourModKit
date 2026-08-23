/**
 * @file diagnostics.cpp
 * @brief Counters for DMK's intentional leak / detach paths, the per-reason module-pin counts, the diagnostic event
 *        bus, the live hook population tally, and the one-call Snapshot aggregator. All of it is scoped to one linked
 *        DMK instance.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "internal/diagnostics_population.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <new>

namespace DetourModKit
{
    namespace diagnostics
    {
        namespace
        {
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
            static EventDispatcher<ScannerFaultEvent> *const dispatcher =
                ::new (static_cast<void *>(storage)) EventDispatcher<ScannerFaultEvent>();
            return *dispatcher;
        }

        EventDispatcher<HookLifecycleEvent> &hook_lifecycle()
        {
            // Never destroyed because ~Hook and ~VmtHook may emit after this translation unit's static destructors.
            alignas(
                EventDispatcher<HookLifecycleEvent>
            ) static unsigned char storage[sizeof(EventDispatcher<HookLifecycleEvent>)];
            static EventDispatcher<HookLifecycleEvent> *const dispatcher =
                ::new (static_cast<void *>(storage)) EventDispatcher<HookLifecycleEvent>();
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
} // namespace DetourModKit
