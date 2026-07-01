/**
 * @file diagnostics.cpp
 * @brief Process-wide counters for DMK's intentional leak / detach paths, the diagnostic event bus, the live hook
 *        population tally, and the one-call Snapshot aggregator.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/diagnostics.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace DetourModKit
{
    namespace Diagnostics
    {
        namespace
        {
            constexpr std::size_t LEAK_SUBSYSTEM_COUNT = static_cast<std::size_t>(LeakSubsystem::Count);

            // One independent event tally per subsystem. Relaxed throughout: the counters carry no ordering obligation
            // toward any other state, and each leak site fires at most once per process, so there is no meaningful
            // contention to order.
            std::array<std::atomic<std::size_t>, LEAK_SUBSYSTEM_COUNT> s_leak_counts{};

            // Live hook population, derived from the hook-lifecycle transition stream the hook surface emits.
            //
            // The safety ledger (src/internal/hook_ledger.hpp) tracks live hooks for duplicate / teardown-order
            // detection but records no enable state and exposes no enumeration, so it cannot supply the active-vs-
            // disabled split on its own. The lifecycle stream carries exactly the missing piece -- every completed
            // Created / Enabled / Disabled / Removed transition, tagged with the hook id -- so one `name -> enabled`
            // map fed by a permanent subscription is the single self-consistent source for all three population
            // figures (total = live entries, active = enabled entries, disabled = the remainder). Deriving all three
            // from one map guarantees total == active + disabled, which two independent sources could not.
            class HookPopulation
            {
            public:
                HookPopulation()
                    : m_subscription(hook_lifecycle().subscribe([this](const HookLifecycleEvent &event) noexcept
                                                                { apply(event); }))
                {
                }

                void apply(const HookLifecycleEvent &event) noexcept
                {
                    try
                    {
                        const std::lock_guard<std::mutex> guard(m_mutex);
                        switch (event.transition)
                        {
                        case HookTransition::Created:
                        case HookTransition::Enabled:
                            m_live[std::string(event.name)] = true;
                            break;
                        case HookTransition::Disabled:
                            m_live[std::string(event.name)] = false;
                            break;
                        case HookTransition::Removed:
                            m_live.erase(std::string(event.name));
                            break;
                        }
                    }
                    catch (...)
                    {
                        // A bookkeeping allocation failed under memory pressure; drop this update rather than let an
                        // exception escape a lifecycle handler. The snapshot is a best-effort diagnostic, never
                        // load-bearing, so a missed transition only skews a count, never corrupts hook state.
                    }
                }

                void counts(std::size_t &total, std::size_t &active, std::size_t &disabled) const noexcept
                {
                    const std::lock_guard<std::mutex> guard(m_mutex);
                    total = m_live.size();
                    active = 0;
                    for (const auto &entry : m_live)
                    {
                        if (entry.second)
                        {
                            ++active;
                        }
                    }
                    disabled = total - active;
                }

            private:
                mutable std::mutex m_mutex;
                std::unordered_map<std::string, bool> m_live; // hook id -> enabled
                Subscription m_subscription;                  // declared last: subscribes after the map/mutex exist
            };

            HookPopulation &hook_population()
            {
                static HookPopulation population;
                return population;
            }

            // Establish the lifecycle subscription at static-init so a hook created before the first collect() is still
            // counted (a lazily-established subscription would miss every transition that preceded it).
            const bool s_hook_population_installed = []
            {
                (void)hook_population();
                return true;
            }();
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

        EventDispatcher<ScannerFaultEvent> &scanner_faults()
        {
            // Function-local static: a single process-wide dispatcher constructed on first use, so the stateless
            // scanner and any consumer share the same subscriber set without a static-init-order dependency.
            static EventDispatcher<ScannerFaultEvent> dispatcher;
            return dispatcher;
        }

        EventDispatcher<HookLifecycleEvent> &hook_lifecycle()
        {
            static EventDispatcher<HookLifecycleEvent> dispatcher;
            return dispatcher;
        }

        Snapshot collect(std::span<const rtti::DriftEntry> drift_report,
                         std::span<const anchor::ResolvedAnchor> anchor_report)
        {
            Snapshot snapshot;

            for (std::size_t i = 0; i < snapshot.intentional_leaks.size(); ++i)
            {
                snapshot.intentional_leaks[i] = intentional_leak_count(static_cast<LeakSubsystem>(i));
            }
            snapshot.total_intentional_leaks = total_intentional_leaks();

            hook_population().counts(snapshot.hooks_total, snapshot.hooks_active, snapshot.hooks_disabled);

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
    } // namespace Diagnostics
} // namespace DetourModKit
