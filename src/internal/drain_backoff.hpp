#ifndef DETOURMODKIT_INTERNAL_DRAIN_BACKOFF_HPP
#define DETOURMODKIT_INTERNAL_DRAIN_BACKOFF_HPP

/**
 * @file internal/drain_backoff.hpp
 * @brief Paces drains with yields followed by sleeps while another thread exits.
 */

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Counts every sleep-tier pause across all drains, so a proof can observe the escalation.
    extern std::atomic<std::uint64_t> g_drain_backoff_sleeps;
#endif

    /**
     * @brief Paces one drain loop with a short yield burst followed by 1 ms sleeps.
     * @details A drained thread can stay descheduled for a long time (a parked callback, a preempted entrant).
     *          Bare yields burn a core in that wait. The sleep tier limits the cost to one wake per millisecond.
     *          One instance belongs to each wait. It allocates nothing and takes no lock.
     */
    class DrainBackoff
    {
    public:
        void pause() noexcept
        {
            if (m_yields < YIELD_BURST)
            {
                ++m_yields;
                std::this_thread::yield();
                return;
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            g_drain_backoff_sleeps.fetch_add(1, std::memory_order_relaxed);
#endif
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }

    private:
        static constexpr std::uint32_t YIELD_BURST = 64;
        std::uint32_t m_yields{0};
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_DRAIN_BACKOFF_HPP
