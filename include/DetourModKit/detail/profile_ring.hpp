#ifndef DETOURMODKIT_DETAIL_PROFILE_RING_HPP
#define DETOURMODKIT_DETAIL_PROFILE_RING_HPP

/**
 * @file profile_ring.hpp
 * @brief The sample slot, the saturating tick conversion, and the ticket publication protocol behind
 *        @ref DetourModKit::Profiler.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>

namespace DetourModKit::detail
{
    /**
     * @brief Computes `remainder * multiplier / divisor` exactly, without a wide integer type.
     * @return The truncated quotient, or 0 when @p divisor is 0.
     * @pre `remainder < divisor`. A larger numerator wraps, and the result is meaningless.
     */
    [[nodiscard]] inline constexpr std::uint64_t
    multiply_fraction(std::uint64_t remainder, std::uint64_t multiplier, std::uint64_t divisor) noexcept
    {
        if (remainder == 0 || multiplier == 0 || divisor == 0)
        {
            return 0;
        }

        std::uint64_t quotient = 0;
        std::uint64_t reduced = 0;

        std::uint64_t bit = std::uint64_t{1} << 63;
        while ((bit & multiplier) == 0)
        {
            bit >>= 1;
        }

        for (; bit != 0; bit >>= 1)
        {
            quotient *= 2;
            if (reduced >= divisor - reduced)
            {
                reduced -= divisor - reduced;
                ++quotient;
            }
            else
            {
                reduced += reduced;
            }

            if ((bit & multiplier) == 0)
            {
                continue;
            }
            if (reduced >= divisor - remainder)
            {
                reduced -= divisor - remainder;
                ++quotient;
            }
            else
            {
                reduced += remainder;
            }
        }
        return quotient;
    }

    /** @brief One ring slot: a committed timing sample plus the ticket word that publishes it. */
    struct ProfileSample
    {
        /**
         * @brief Publication word `((ticket + 1) << 1) | busy`, where `ticket` is the ring write position that owns
         *        the slot.
         * @details Zero means that no writer committed the slot. Odd means a write is in flight, so readers skip the
         *          slot. The encoded ticket increases on every reuse, so the same word before and after a payload copy
         *          proves one committed sample.
         */
        std::atomic<std::uint64_t> state{0};
        /**
         * @brief Non-owning sample name. A committed slot can hold null, and export skips such a slot.
         * @note The name must outlive the process, because the exporter reads it asynchronously.
         */
        const char *name{nullptr};
        /// QPC tick count at scope entry.
        std::int64_t start_ticks{0};
        /// Duration in microseconds, saturated at UINT32_MAX (about 71 minutes).
        std::uint32_t duration_us{0};
        /// Win32 thread ID of the thread that recorded the sample.
        std::uint32_t thread_id{0};
        /** @brief Byte count of @ref name, published with it. The exporter never scans for a terminator. */
        std::uint32_t name_length{0};

        ProfileSample() noexcept = default;
        ProfileSample(const ProfileSample &) = delete;
        ProfileSample &operator=(const ProfileSample &) = delete;
        ProfileSample(ProfileSample &&) = delete;
        ProfileSample &operator=(ProfileSample &&) = delete;
    };

    /**
     * @brief Converts a QPC tick interval to microseconds without overflow or undefined behavior.
     * @param frequency Ticks per second.
     * @return Microseconds, saturated at UINT32_MAX. The function accepts any tick values. A non-increasing interval or
     *         a non-positive @p frequency returns 0.
     */
    [[nodiscard]] inline std::uint32_t
    ticks_to_microseconds(std::int64_t start_ticks, std::int64_t end_ticks, std::int64_t frequency) noexcept
    {
        constexpr std::uint64_t US_PER_SECOND = 1'000'000;
        constexpr std::uint64_t MAX_US = UINT32_MAX;

        if (frequency <= 0 || end_ticks <= start_ticks)
        {
            return 0;
        }

        const std::uint64_t delta = static_cast<std::uint64_t>(end_ticks) - static_cast<std::uint64_t>(start_ticks);
        const auto ticks_per_second = static_cast<std::uint64_t>(frequency);

        const std::uint64_t whole_seconds = delta / ticks_per_second;
        if (whole_seconds > MAX_US / US_PER_SECOND)
        {
            return static_cast<std::uint32_t>(MAX_US);
        }

        const std::uint64_t remainder = delta % ticks_per_second;
        const std::uint64_t fraction_us = (remainder <= UINT64_MAX / US_PER_SECOND)
                                              ? (remainder * US_PER_SECOND) / ticks_per_second
                                              : multiply_fraction(remainder, US_PER_SECOND, ticks_per_second);

        const std::uint64_t micros = whole_seconds * US_PER_SECOND + fraction_us;
        return static_cast<std::uint32_t>(micros > MAX_US ? MAX_US : micros);
    }

    /**
     * @brief Fixed-capacity sample ring with lock-free claim/publish and drop-on-collision.
     * @details @ref claim refuses a slot that another writer still owns or that a later writer already committed, and
     *          counts a drop. See docs/design/events.md "Profiler" for the torn-payload rationale.
     *
     * **Thread safety:** `claim` / `publish` are lock-free and callable from any thread. `visit_committed` can run
     * concurrently with them.
     */
    class ProfileRing
    {
    public:
        /** @brief A slot reservation. */
        struct Claim
        {
            /// Ring slot index owned by the claim.
            std::size_t index{0};
            /// Global write position represented by the claim.
            std::uint64_t ticket{0};
            /// True only when the slot was reserved successfully.
            bool owned{false};
        };

        /**
         * @brief Allocates @p capacity slots, which must be a power of two.
         * @details Zero, a non-power-of-two, or an allocation failure yields an inert ring that drops every claim.
         */
        explicit ProfileRing(std::size_t capacity) noexcept
        {
            if (capacity == 0 || (capacity & (capacity - 1)) != 0)
            {
                return;
            }
            m_slots.reset(::new (std::nothrow) ProfileSample[capacity]);
            if (m_slots)
            {
                m_capacity = capacity;
                m_mask = capacity - 1;
            }
        }

        ProfileRing(const ProfileRing &) = delete;
        ProfileRing &operator=(const ProfileRing &) = delete;
        ProfileRing(ProfileRing &&) = delete;
        ProfileRing &operator=(ProfileRing &&) = delete;
        ~ProfileRing() noexcept = default;

        /// Takes the next ring position and does not inspect its slot. @ref claim_at completes the reservation.
        [[nodiscard]] std::uint64_t reserve_position() noexcept
        {
            return m_write_pos.fetch_add(1, std::memory_order_relaxed);
        }

        /// Reserves the next slot, or returns a refused claim and counts a drop.
        [[nodiscard]] Claim claim() noexcept { return claim_at(reserve_position()); }

        /**
         * @brief Completes a reservation for a @p position that @ref reserve_position returned.
         * @pre Pass each reserved position exactly once. This function does not advance the ring.
         */
        [[nodiscard]] Claim claim_at(std::uint64_t position) noexcept
        {
            if (m_capacity == 0 || position > MAX_POSITION)
            {
                m_dropped.fetch_add(1, std::memory_order_relaxed);
                return Claim{};
            }

            const auto index = static_cast<std::size_t>(position & m_mask);
            std::atomic<std::uint64_t> &state = m_slots[index].state;

            // Refuse every collision. An odd word means another writer still owns the slot. A committed ticket above
            // ours means a later writer published here, and an equal ticket means a repeated claim of this position.
            std::uint64_t observed = state.load(std::memory_order_acquire);
            const std::uint64_t encoded_ticket = position + TICKET_OFFSET;
            if ((observed & BUSY_BIT) != 0 || (observed != EMPTY_STATE && (observed >> 1) >= encoded_ticket))
            {
                m_dropped.fetch_add(1, std::memory_order_relaxed);
                return Claim{};
            }

            const std::uint64_t owned_word = state_word(position, true);
            if (!state.compare_exchange_strong(
                    observed,
                    owned_word,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed
                ))
            {
                m_dropped.fetch_add(1, std::memory_order_relaxed);
                return Claim{};
            }
            return Claim{
                .index = index,
                .ticket = position,
                .owned = true,
            };
        }

        /// Writes the payload into a claimed slot and commits it. A refused claim publishes nothing.
        void publish(
            const Claim &claim,
            const char *name,
            std::uint32_t name_length,
            std::int64_t start_ticks,
            std::uint32_t duration_us,
            std::uint32_t thread_id
        ) noexcept
        {
            if (!claim.owned)
            {
                return;
            }
            ProfileSample &slot = m_slots[claim.index];

            // The exporter reads these fields concurrently, so they go through std::atomic_ref. The release store on
            // the ticket word below orders them for a reader that accepts the slot.
            std::atomic_ref<const char *>(slot.name).store(name, std::memory_order_relaxed);
            std::atomic_ref<std::uint32_t>(slot.name_length).store(name_length, std::memory_order_relaxed);
            std::atomic_ref<std::int64_t>(slot.start_ticks).store(start_ticks, std::memory_order_relaxed);
            std::atomic_ref<std::uint32_t>(slot.duration_us).store(duration_us, std::memory_order_relaxed);
            std::atomic_ref<std::uint32_t>(slot.thread_id).store(thread_id, std::memory_order_relaxed);

            slot.state.store(state_word(claim.ticket, false), std::memory_order_release);
        }

        /**
         * @brief Invokes @p visitor for each committed sample in ring traversal order.
         * @param visitor Called as `visitor(name, name_length, start_ticks, duration_us, thread_id)`.
         */
        template <typename Visitor> void visit_committed(Visitor &&visitor) const
        {
            const std::uint64_t total = m_write_pos.load(std::memory_order_relaxed);
            const std::uint64_t resident = total < m_capacity ? total : m_capacity;
            const std::size_t start = total > m_capacity ? static_cast<std::size_t>(total & m_mask) : 0;

            for (std::uint64_t i = 0; i < resident; ++i)
            {
                ProfileSample &slot = m_slots[(start + static_cast<std::size_t>(i)) & m_mask];

                const std::uint64_t before = slot.state.load(std::memory_order_acquire);
                if (before == EMPTY_STATE || (before & BUSY_BIT) != 0)
                {
                    continue;
                }
                const char *const name = std::atomic_ref<const char *>(slot.name).load(std::memory_order_relaxed);
                if (name == nullptr)
                {
                    continue;
                }
                const auto name_length =
                    std::atomic_ref<std::uint32_t>(slot.name_length).load(std::memory_order_relaxed);
                const auto start_ticks =
                    std::atomic_ref<std::int64_t>(slot.start_ticks).load(std::memory_order_relaxed);
                const auto duration_us =
                    std::atomic_ref<std::uint32_t>(slot.duration_us).load(std::memory_order_relaxed);
                const auto thread_id = std::atomic_ref<std::uint32_t>(slot.thread_id).load(std::memory_order_relaxed);

                std::atomic_thread_fence(std::memory_order_acquire);
                if (slot.state.load(std::memory_order_relaxed) != before)
                {
                    continue;
                }
                visitor(name, name_length, start_ticks, duration_us, thread_id);
            }
        }

        /// Discards every sample and restarts the ticket sequence. Requires that no claim or visit is in flight.
        void reset() noexcept
        {
            m_write_pos.store(0, std::memory_order_relaxed);
            m_dropped.store(0, std::memory_order_relaxed);
            for (std::size_t i = 0; i < m_capacity; ++i)
            {
                ProfileSample &slot = m_slots[i];
                std::atomic_ref<const char *>(slot.name).store(nullptr, std::memory_order_relaxed);
                std::atomic_ref<std::uint32_t>(slot.name_length).store(0, std::memory_order_relaxed);
                std::atomic_ref<std::int64_t>(slot.start_ticks).store(0, std::memory_order_relaxed);
                std::atomic_ref<std::uint32_t>(slot.duration_us).store(0, std::memory_order_relaxed);
                std::atomic_ref<std::uint32_t>(slot.thread_id).store(0, std::memory_order_relaxed);
                slot.state.store(0, std::memory_order_relaxed);
            }
        }

        /// Slot count, or 0 for an inert ring.
        [[nodiscard]] std::size_t capacity() const noexcept { return m_capacity; }

        /// Claims attempted since construction or the last @ref reset. Refused claims count too.
        [[nodiscard]] std::uint64_t claims() const noexcept { return m_write_pos.load(std::memory_order_relaxed); }

        /// Claims refused because the slot was owned, already newer, or the ring is inert.
        [[nodiscard]] std::uint64_t dropped() const noexcept { return m_dropped.load(std::memory_order_relaxed); }

        /// Committed samples still resident. Exact when no claim is in flight.
        [[nodiscard]] std::uint64_t resident() const noexcept
        {
            const std::uint64_t dropped_now = m_dropped.load(std::memory_order_relaxed);
            const std::uint64_t claims_now = m_write_pos.load(std::memory_order_relaxed);
            const std::uint64_t committed = claims_now > dropped_now ? claims_now - dropped_now : 0;
            return committed < m_capacity ? committed : m_capacity;
        }

    private:
        static constexpr std::uint64_t BUSY_BIT{1};
        static constexpr std::uint64_t TICKET_OFFSET{1};
        static constexpr std::uint64_t EMPTY_STATE{0};
        static constexpr std::uint64_t MAX_POSITION{(UINT64_MAX >> 1) - 1};

        [[nodiscard]] static constexpr std::uint64_t state_word(std::uint64_t position, bool busy) noexcept
        {
            return ((position + TICKET_OFFSET) << 1) | static_cast<std::uint64_t>(busy);
        }

        static_assert((TICKET_OFFSET << 1) != EMPTY_STATE, "the first committed ticket must differ from an empty slot");
        static_assert(
            std::atomic<std::uint64_t>::is_always_lock_free,
            "the profile ring requires lock-free 64-bit atomics"
        );
        static_assert(
            std::atomic_ref<const char *>::is_always_lock_free,
            "the profile ring requires lock-free pointer publication"
        );
        static_assert(
            std::atomic_ref<std::int64_t>::is_always_lock_free,
            "the profile ring requires lock-free 64-bit payload publication"
        );
        static_assert(
            std::atomic_ref<std::uint32_t>::is_always_lock_free,
            "the profile ring requires lock-free 32-bit payload publication"
        );

        alignas(64) std::atomic<std::uint64_t> m_write_pos{0};
        std::atomic<std::uint64_t> m_dropped{0};
        std::unique_ptr<ProfileSample[]> m_slots;
        std::size_t m_capacity{0};
        std::size_t m_mask{0};
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_DETAIL_PROFILE_RING_HPP
