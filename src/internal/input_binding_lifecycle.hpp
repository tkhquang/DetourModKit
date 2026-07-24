#ifndef DETOURMODKIT_INTERNAL_INPUT_BINDING_LIFECYCLE_HPP
#define DETOURMODKIT_INTERNAL_INPUT_BINDING_LIFECYCLE_HPP

/**
 * @file input_binding_lifecycle.hpp
 * @brief Per-registration callback admission state shared by an input binding's engine entries and teardown gate.
 * @details The control block is allocated with the registration and keeps reshape-time retirement allocation-free.
 *          Staged callbacks use its generation and in-flight counters to synchronize with remove, clear, and rebind.
 *          Not installed.
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace DetourModKit::detail
{
    /**
     * @brief Generation, tombstone, and in-flight counts for one input registration.
     * @details Invocation admission uses increment-then-recheck with sequentially consistent atomics. A reshape first
     *          advances the generation or publishes the one-way tombstone, then drains in-flight callbacks. An advanced
     *          (surviving) registration drains only the retired parity slot so it never waits on live new-generation
     *          work; a tombstone drains BOTH slots, because it admits nothing further and a caller relies on the drain
     *          to see out an admit-across release edge that a prior advance may have left in the other parity slot.
     *          Presses and held(true) edges are refused across any advance, so only a benign, gate-serialized release
     *          edge can ever straddle two generations.
     */
    class BindingLifecycle
    {
    public:
        explicit BindingLifecycle(std::uint64_t initial_generation) noexcept : m_generation(initial_generation) {}

        /// Returns the generation to carry with a staged callback.
        [[nodiscard]] std::uint64_t generation() const noexcept { return m_generation.load(std::memory_order_acquire); }

        /// Returns whether removal permanently retired this registration.
        [[nodiscard]] bool tombstoned() const noexcept { return m_tombstoned.load(std::memory_order_acquire); }

        /**
         * @brief Advances to the next generation and returns the retired generation.
         * @note Serialized by the poller's binding writer lock.
         */
        [[nodiscard]] std::uint64_t advance_generation() noexcept
        {
            return m_generation.fetch_add(1, std::memory_order_seq_cst);
        }

        /**
         * @brief Permanently retires this registration and returns the generation to drain.
         * @note Serialized by the poller's binding writer lock.
         */
        [[nodiscard]] std::uint64_t tombstone() noexcept
        {
            const std::uint64_t retired_generation = m_generation.load(std::memory_order_seq_cst);
            m_tombstoned.store(true, std::memory_order_seq_cst);
            return retired_generation;
        }

        /**
         * @brief Attempts to admit a callback staged from @p expected_generation.
         * @param admit_across_generation When true, admit even if the generation advanced since staging, provided the
         *        registration was not tombstoned. Set only for a terminal hold-release (false) edge: it can only end a
         *        held state and never fires a stale activation, so an in-place rebind that merely advanced the
         *        generation must still deliver it, or the gate's held count desyncs from the poller and the consumer
         *        is stranded holding a released binding. A tombstone (remove / clear) still refuses it, because that
         *        path publishes its own balancing false and must not race a post-return delivery against state the
         *        caller is destroying.
         * @return true when the callback is counted and may begin; false when its registration was reshaped.
         */
        [[nodiscard]] bool try_enter(std::uint64_t expected_generation, bool admit_across_generation) noexcept
        {
            if (m_tombstoned.load(std::memory_order_acquire) ||
                (!admit_across_generation && m_generation.load(std::memory_order_acquire) != expected_generation))
            {
                return false;
            }

            auto &counter = m_in_flight[slot(expected_generation)];
            counter.fetch_add(1, std::memory_order_seq_cst);
            if (m_tombstoned.load(std::memory_order_seq_cst) ||
                (!admit_across_generation && m_generation.load(std::memory_order_seq_cst) != expected_generation))
            {
                counter.fetch_sub(1, std::memory_order_seq_cst);
                return false;
            }
            return true;
        }

        /// Releases one callback admitted for @p entered_generation.
        void leave(std::uint64_t entered_generation) noexcept
        {
            m_in_flight[slot(entered_generation)].fetch_sub(1, std::memory_order_seq_cst);
        }

        /// Returns callbacks still running from @p retired_generation.
        [[nodiscard]] std::uint32_t in_flight(std::uint64_t retired_generation) const noexcept
        {
            return m_in_flight[slot(retired_generation)].load(std::memory_order_seq_cst);
        }

        /**
         * @brief Returns callbacks still running from either generation slot.
         * @details A tombstone drains on this so an admit-across release edge left in a prior advance's parity slot
         *          cannot outlive the reshape that retired the binding.
         */
        [[nodiscard]] std::uint32_t in_flight_total() const noexcept
        {
            return m_in_flight[0].load(std::memory_order_seq_cst) + m_in_flight[1].load(std::memory_order_seq_cst);
        }

    private:
        [[nodiscard]] static constexpr std::size_t slot(std::uint64_t generation) noexcept
        {
            return static_cast<std::size_t>(generation & 1U);
        }

        std::atomic<std::uint64_t> m_generation;
        std::atomic<bool> m_tombstoned{false};
        std::array<std::atomic<std::uint32_t>, 2> m_in_flight{};
    };

    /**
     * @brief RAII admission for one staged callback.
     */
    class BindingInvocation
    {
    public:
        BindingInvocation(BindingLifecycle *lifecycle, std::uint64_t staged_generation,
                          bool admit_across_generation) noexcept
            : m_lifecycle(lifecycle), m_generation(staged_generation),
              m_admitted(lifecycle == nullptr || lifecycle->try_enter(staged_generation, admit_across_generation))
        {
        }

        ~BindingInvocation() noexcept
        {
            if (m_lifecycle != nullptr && m_admitted)
            {
                m_lifecycle->leave(m_generation);
            }
        }

        BindingInvocation(const BindingInvocation &) = delete;
        BindingInvocation &operator=(const BindingInvocation &) = delete;
        BindingInvocation(BindingInvocation &&) = delete;
        BindingInvocation &operator=(BindingInvocation &&) = delete;

        /// Returns whether this callback may begin.
        [[nodiscard]] bool admitted() const noexcept { return m_admitted; }

    private:
        BindingLifecycle *m_lifecycle;
        std::uint64_t m_generation;
        bool m_admitted;
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_INPUT_BINDING_LIFECYCLE_HPP
