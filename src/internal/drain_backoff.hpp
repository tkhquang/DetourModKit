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
#include <utility>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Exposes yield-tier pauses to the no-pause proofs.
    extern std::atomic<std::uint64_t> g_drain_backoff_yields;

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
#if defined(DMK_ENABLE_TEST_SEAMS)
                g_drain_backoff_yields.fetch_add(1, std::memory_order_relaxed);
#endif
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

    /**
     * @brief Waits with DrainBackoff pauses until @p count returns zero or @p deadline passes.
     * @param count A no-throw callable that returns a count comparable with zero.
     * @return true when the count reached zero. A false return never licenses reclamation: the caller must retain
     *         the undrained resource per [B-73].
     */
    template <class CountFn>
        requires(noexcept(std::declval<CountFn &>()() != 0))
    [[nodiscard]] bool drain_until_zero(CountFn &&count, std::chrono::steady_clock::time_point deadline) noexcept
    {
        DrainBackoff backoff;
        while (count() != 0)
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }
            backoff.pause();
        }
        return true;
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_DRAIN_BACKOFF_HPP
