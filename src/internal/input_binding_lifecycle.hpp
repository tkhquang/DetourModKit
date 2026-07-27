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
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <utility>

namespace DetourModKit::detail
{
    namespace input_callback_lifecycle
    {
        inline constexpr std::uint32_t ADMISSION_OPEN = 1U;
        inline constexpr std::uint32_t DRAIN_PENDING = 1U << 1U;

        inline std::atomic<std::uint32_t> s_state{ADMISSION_OPEN};
        inline std::atomic<std::uint32_t> s_staged_count{0};
    } // namespace input_callback_lifecycle

    /// Returns whether process-wide staging admission is open.
    [[nodiscard]] inline bool input_callback_admission_open() noexcept
    {
        return (input_callback_lifecycle::s_state.load(std::memory_order_seq_cst) &
                input_callback_lifecycle::ADMISSION_OPEN) != 0;
    }

    /**
     * @brief Opens process-wide admission for staged input callback storage unless a drain remains unresolved.
     * @return true when admission is open; false when a pending drain kept it closed.
     */
    [[nodiscard]] inline bool open_input_callback_admission() noexcept
    {
        std::uint32_t state = input_callback_lifecycle::s_state.load(std::memory_order_seq_cst);
        while ((state & input_callback_lifecycle::DRAIN_PENDING) == 0)
        {
            if ((state & input_callback_lifecycle::ADMISSION_OPEN) != 0)
            {
                return true;
            }
            const std::uint32_t desired = state | input_callback_lifecycle::ADMISSION_OPEN;
            if (input_callback_lifecycle::s_state.compare_exchange_weak(state, desired, std::memory_order_seq_cst))
            {
                return true;
            }
        }
        return false;
    }

    /// Closes process-wide admission for staged input callback storage.
    inline void close_input_callback_admission() noexcept
    {
        input_callback_lifecycle::s_state.fetch_and(~input_callback_lifecycle::ADMISSION_OPEN,
                                                    std::memory_order_seq_cst);
    }

    /// Marks input callback rundown as unresolved and atomically closes staging admission.
    inline void mark_input_callback_drain_pending() noexcept
    {
        std::uint32_t state = input_callback_lifecycle::s_state.load(std::memory_order_seq_cst);
        for (;;)
        {
            const std::uint32_t desired =
                (state | input_callback_lifecycle::DRAIN_PENDING) & ~input_callback_lifecycle::ADMISSION_OPEN;
            if (input_callback_lifecycle::s_state.compare_exchange_weak(state, desired, std::memory_order_seq_cst))
            {
                return;
            }
        }
    }

    /// Marks the current input callback rundown as complete.
    inline void resolve_input_callback_drain() noexcept
    {
        input_callback_lifecycle::s_state.fetch_and(~input_callback_lifecycle::DRAIN_PENDING,
                                                    std::memory_order_seq_cst);
    }

    /// Returns whether a failed or active callback rundown still needs completion.
    [[nodiscard]] inline bool input_callback_drain_pending() noexcept
    {
        return (input_callback_lifecycle::s_state.load(std::memory_order_seq_cst) &
                input_callback_lifecycle::DRAIN_PENDING) != 0;
    }

    /// Returns the number of staged callback records whose callable storage is still alive.
    [[nodiscard]] inline std::uint32_t staged_input_callback_count() noexcept
    {
        return input_callback_lifecycle::s_staged_count.load(std::memory_order_seq_cst);
    }

    /**
     * @brief Converts a caller timeout into an absolute rundown deadline, saturating instead of overflowing.
     * @details One owner for the clamp so the input and config halves of an unload transaction cannot drift apart on
     *          it. A non-positive timeout yields "now" (poll once, never wait), and a timeout that would run past the
     *          clock's range yields time_point::max() rather than wrapping into an already-expired deadline.
     */
    [[nodiscard]] inline std::chrono::steady_clock::time_point
    drain_deadline(std::chrono::milliseconds timeout) noexcept
    {
        const auto now = std::chrono::steady_clock::now();
        if (timeout <= std::chrono::milliseconds{0})
        {
            return now;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::time_point::max() - now);
        if (timeout >= remaining)
        {
            return std::chrono::steady_clock::time_point::max();
        }
        return now + std::chrono::duration_cast<std::chrono::steady_clock::duration>(timeout);
    }

    /**
     * @brief Waits until every staged input callback record has been destroyed or @p deadline is reached.
     * @return true when no staged record remains; false on timeout.
     */
    [[nodiscard]] inline bool await_staged_input_callbacks(std::chrono::steady_clock::time_point deadline) noexcept
    {
        while (staged_input_callback_count() != 0)
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }
            std::this_thread::yield();
        }
        return true;
    }

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
     * @brief RAII lease spanning a staged callback's callable copies, dispatch, and destruction.
     * @details Counts process-wide staged callable storage so an unload drain can wait, to its own deadline, until
     *          every copied callable and capture manager is gone. The lease must be declared before callable-storage
     *          members so reverse member destruction releases it only after that storage has been destroyed.
     *
     *          It deliberately does NOT hold a BindingLifecycle in-flight slot. That slot is the per-registration
     *          reshape rundown, which waits with no deadline; pinning it from staging until the whole poll cycle's
     *          staged storage is destroyed would make one binding's reshape or removal block on every other binding
     *          dispatched in the same cycle, and a control thread holding a lock one of those callbacks wants would
     *          deadlock. BindingInvocation scopes that slot to the callback body instead.
     */
    class StagedCallbackLease
    {
    public:
        StagedCallbackLease(std::shared_ptr<BindingLifecycle> lifecycle, std::uint64_t staged_generation) noexcept
            : m_lifecycle(std::move(lifecycle)), m_generation(staged_generation)
        {
            if (!input_callback_admission_open())
            {
                return;
            }

            input_callback_lifecycle::s_staged_count.fetch_add(1, std::memory_order_seq_cst);
            if (!input_callback_admission_open())
            {
                input_callback_lifecycle::s_staged_count.fetch_sub(1, std::memory_order_seq_cst);
                return;
            }
            m_engaged = true;
        }

        ~StagedCallbackLease() noexcept
        {
            if (m_engaged)
            {
                input_callback_lifecycle::s_staged_count.fetch_sub(1, std::memory_order_seq_cst);
            }
        }

        StagedCallbackLease(const StagedCallbackLease &) = delete;
        StagedCallbackLease &operator=(const StagedCallbackLease &) = delete;
        StagedCallbackLease &operator=(StagedCallbackLease &&) = delete;

        // Move construction is what lets a lease reach the staged record it guards, both into the record and through a
        // vector reallocation of the poll cycle's staged storage.
        StagedCallbackLease(StagedCallbackLease &&other) noexcept
            : m_lifecycle(std::move(other.m_lifecycle)), m_generation(other.m_generation),
              m_engaged(std::exchange(other.m_engaged, false))
        {
        }

        /// Returns whether the callback was admitted into staged storage.
        [[nodiscard]] bool engaged() const noexcept { return m_engaged; }

        /// The registration this callback was staged from, for the dispatch-time BindingInvocation.
        [[nodiscard]] BindingLifecycle *lifecycle() const noexcept { return m_lifecycle.get(); }

        /// The generation this callback was staged at.
        [[nodiscard]] std::uint64_t generation() const noexcept { return m_generation; }

    private:
        std::shared_ptr<BindingLifecycle> m_lifecycle;
        std::uint64_t m_generation{0};
        bool m_engaged{false};
    };

    /**
     * @brief RAII admission for one staged callback's dispatch.
     * @details Holds the registration's in-flight slot for exactly the callback body, so a reshape or removal of this
     *          binding waits only on its own callback and never on an unrelated binding dispatched in the same cycle.
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
