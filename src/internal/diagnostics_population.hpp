#ifndef DETOURMODKIT_INTERNAL_DIAGNOSTICS_POPULATION_HPP
#define DETOURMODKIT_INTERNAL_DIAGNOSTICS_POPULATION_HPP

/**
 * @file diagnostics_population.hpp
 * @brief Defines constant-initialized module-pin, hook-population, and lifecycle counters.
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace DetourModKit::diagnostics
{
    enum class ModulePinReason : std::uint8_t; // Full definition: DetourModKit/diagnostics.hpp.
} // namespace DetourModKit::diagnostics

namespace DetourModKit::detail
{
    namespace hook_population
    {
        /// Active occupies the low 32 bits, total the high 32.
        inline constexpr std::uint64_t ACTIVE_UNIT = 1ULL;
        inline constexpr std::uint64_t TOTAL_UNIT = 1ULL << 32U;
        inline constexpr std::uint64_t ACTIVE_MASK = 0xFFFFFFFFULL;

        // Loader-lock teardown requires updates that cannot allocate or enter a lock-backed atomic implementation.
        static_assert(
            std::atomic<std::uint64_t>::is_always_lock_free,
            "the hook population tally must be lock-free to stay callable under the loader lock"
        );

        // constinit makes any future dynamic initialization a compile-time error.
        inline constinit std::atomic<std::uint64_t> s_counts{0};

        /**
         * @brief Records a completed install.
         * @param active True if creation publishes Active. VMT hooks start Active. Inline and mid hooks start Disabled.
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
         * @brief Records removal from the live population.
         * @param was_active True if the entry state counted this hook as Active. Teardown can force Disabled before it
         *                   emits. Pass the entry state so removal subtracts the Active unit.
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

    /**
     * @brief Provides counters behind @ref DetourModKit::diagnostics::lifecycle_counters.
     * @details Each relaxed atomic is an independent monotonic event tally with no cross-counter order obligation. The
     *          recorders run on reaper and teardown paths:
     *          - They allocate no memory.
     *          - They take no lock.
     *          - They make no Win32 call.
     */
    namespace lifecycle_observability
    {
        static_assert(
            std::atomic<std::size_t>::is_always_lock_free,
            "lifecycle observability must stay lock-free on teardown paths"
        );

        inline constinit std::atomic<std::size_t> s_reaper_started{0};
        inline constinit std::atomic<std::size_t> s_permanent_pins{0};
        inline constinit std::atomic<std::size_t> s_abandoned_owners{0};

        /// Records the process-lifetime reaper thread launch and its permanent module reference.
        inline void record_reaper_started() noexcept
        {
            s_reaper_started.fetch_add(1, std::memory_order_relaxed);
            s_permanent_pins.fetch_add(1, std::memory_order_relaxed);
        }

        /// Records a failed retirement that the reaper retains permanently.
        inline void record_abandoned_owner() noexcept
        {
            s_abandoned_owners.fetch_add(1, std::memory_order_relaxed);
        }
    } // namespace lifecycle_observability

    /**
     * @brief Provides the outstanding-count storage behind @ref DetourModKit::diagnostics::module_pin_count.
     * @details One relaxed atomic per @ref DetourModKit::diagnostics::ModulePinReason holds acquires minus releases.
     *          The recorders run on install, teardown, and loader-lock paths:
     *          - They allocate no memory.
     *          - They take no lock.
     *          - They make no Win32 call.
     */
    namespace module_pin_observability
    {
        /// Mirrors ModulePinReason::Count. diagnostics.cpp static_asserts that the two values stay equal.
        inline constexpr std::size_t MODULE_PIN_REASON_COUNT = 11;

        static_assert(
            std::atomic<std::size_t>::is_always_lock_free,
            "module pin observability must stay lock-free on teardown paths"
        );

        inline constinit std::array<std::atomic<std::size_t>, MODULE_PIN_REASON_COUNT> s_outstanding{};

        /// Records one counted module reference taken under @p reason.
        inline void note_acquired(DetourModKit::diagnostics::ModulePinReason reason) noexcept
        {
            const auto index = static_cast<std::size_t>(reason);
            if (index < MODULE_PIN_REASON_COUNT)
            {
                s_outstanding[index].fetch_add(1, std::memory_order_relaxed);
            }
        }

        /**
         * @brief Records the release of one counted module reference taken under @p reason.
         * @details A release must pass the reason its acquire passed.
         *          An unmatched release wraps the unsigned count.
         *          The wrap exposes the imbalance.
         */
        inline void note_released(DetourModKit::diagnostics::ModulePinReason reason) noexcept
        {
            const auto index = static_cast<std::size_t>(reason);
            if (index < MODULE_PIN_REASON_COUNT)
            {
                s_outstanding[index].fetch_sub(1, std::memory_order_relaxed);
            }
        }
    } // namespace module_pin_observability
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_DIAGNOSTICS_POPULATION_HPP
