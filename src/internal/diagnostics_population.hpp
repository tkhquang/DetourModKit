#ifndef DETOURMODKIT_INTERNAL_DIAGNOSTICS_POPULATION_HPP
#define DETOURMODKIT_INTERNAL_DIAGNOSTICS_POPULATION_HPP

/**
 * @file diagnostics_population.hpp
 * @brief Live hook population tally, packed into one constant-initialized atomic word.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace DetourModKit::detail
{
    namespace hook_population
    {
        /// Active occupies the low 32 bits, total the high 32.
        inline constexpr std::uint64_t ACTIVE_UNIT = 1ULL;
        inline constexpr std::uint64_t TOTAL_UNIT = 1ULL << 32U;
        inline constexpr std::uint64_t ACTIVE_MASK = 0xFFFFFFFFULL;

        // Loader-lock teardown requires updates that cannot allocate or enter a lock-backed atomic implementation.
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free,
                      "the hook population tally must be lock-free to stay callable under the loader lock");

        // constinit makes any future dynamic initialization a compile-time error.
        inline constinit std::atomic<std::uint64_t> s_counts{0};

        /**
         * @brief Records a completed install.
         * @param active Whether the hook is live on creation. VMT hooks are; inline and mid hooks are armed by a later
         *               enable and are counted disabled until then.
         */
        inline void record_created(bool active) noexcept
        {
            s_counts.fetch_add(active ? TOTAL_UNIT + ACTIVE_UNIT : TOTAL_UNIT, std::memory_order_relaxed);
        }

        /// Records a completed disabled-to-active transition.
        inline void record_enabled() noexcept
        {
            s_counts.fetch_add(ACTIVE_UNIT, std::memory_order_relaxed);
        }

        /// Records a completed active-to-disabled transition.
        inline void record_disabled() noexcept
        {
            s_counts.fetch_sub(ACTIVE_UNIT, std::memory_order_relaxed);
        }

        /**
         * @brief Records a hook leaving the live population.
         * @param was_active Whether this hook was still counted armed. A teardown that forces its own status to
         *                   Disabled before it emits must pass the state the hook held on entry, not the forced one, or
         *                   the armed unit it added at enable is never taken back.
         */
        inline void record_removed(bool was_active) noexcept
        {
            s_counts.fetch_sub(was_active ? TOTAL_UNIT + ACTIVE_UNIT : TOTAL_UNIT, std::memory_order_relaxed);
        }

        /// Reads all three figures from one load, so they are always mutually consistent.
        inline void read(std::size_t &total, std::size_t &active, std::size_t &disabled) noexcept
        {
            const std::uint64_t packed = s_counts.load(std::memory_order_relaxed);
            total = static_cast<std::size_t>(packed >> 32U);
            active = static_cast<std::size_t>(packed & ACTIVE_MASK);
            disabled = total - active;
        }
    } // namespace hook_population
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_DIAGNOSTICS_POPULATION_HPP
