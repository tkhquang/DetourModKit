/**
 * @file diagnostics.cpp
 * @brief Process-wide counters for DMK's intentional leak / detach paths.
 */

#include "DetourModKit/diagnostics.hpp"

#include <array>
#include <atomic>
#include <cstddef>

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
    } // namespace Diagnostics
} // namespace DetourModKit
