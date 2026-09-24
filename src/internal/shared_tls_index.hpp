#ifndef DETOURMODKIT_INTERNAL_SHARED_TLS_INDEX_HPP
#define DETOURMODKIT_INTERNAL_SHARED_TLS_INDEX_HPP

/**
 * @file internal/shared_tls_index.hpp
 * @brief A Win32 TLS index that counted owners share and the last owner returns.
 */

#include <windows.h>

#include <atomic>
#include <cstdint>

namespace DetourModKit::detail
{
    /**
     * @brief One Win32 TLS index that counted owners share.
     * @details An owner is an object whose lifetime spans every write through the index on any thread. Each acquire
     *          reserves an index while none is published. The last release unpublishes the index before TlsFree, so a
     *          later acquire reserves a fresh one. The owner count and the index share one word, so a reservation
     *          cannot interleave with a return. A reader with a stale index reads only its own slot, which TlsFree
     *          zeroes, so a read needs no owner. Constant initialization and a trivial destructor keep the object
     *          usable after static destruction (`[B-47]`).
     */
    class SharedTlsIndex
    {
    public:
        constexpr SharedTlsIndex() noexcept = default;
        SharedTlsIndex(const SharedTlsIndex &) = delete;
        SharedTlsIndex &operator=(const SharedTlsIndex &) = delete;

        /**
         * @brief Registers one owner, and reserves an index when none is published.
         * @param error Receives GetLastError() from a failed reservation. Can be null.
         * @return The published index, or TLS_OUT_OF_INDEXES when the process has none. The owner stays registered in
         *         both cases, so each call needs one @ref release.
         */
        [[nodiscard]] DWORD acquire(DWORD *error = nullptr) noexcept
        {
            DWORD spare = TLS_OUT_OF_INDEXES;
            std::uint64_t state = m_state.load(std::memory_order_acquire);
            for (;;)
            {
                DWORD index = index_of(state);
                if (index == TLS_OUT_OF_INDEXES)
                {
                    if (spare == TLS_OUT_OF_INDEXES)
                    {
                        spare = ::TlsAlloc();
                        if (spare == TLS_OUT_OF_INDEXES && error != nullptr)
                        {
                            *error = ::GetLastError();
                        }
                    }
                    index = spare;
                }
                if (m_state.compare_exchange_weak(
                        state,
                        pack(owners_of(state) + 1, index),
                        std::memory_order_acq_rel,
                        std::memory_order_acquire
                    ))
                {
                    // A spare that lost to a published index was never visible to another thread.
                    if (spare != TLS_OUT_OF_INDEXES && spare != index)
                    {
                        (void)::TlsFree(spare);
                    }
                    return index;
                }
            }
        }

        /// Deregisters one owner. The last owner unpublishes the index, then frees it.
        void release() noexcept
        {
            std::uint64_t state = m_state.load(std::memory_order_acquire);
            for (;;)
            {
                const std::uint32_t owners = owners_of(state);
                if (owners == 0)
                {
                    return;
                }
                const std::uint64_t next = owners == 1 ? UNOWNED : pack(owners - 1, index_of(state));
                if (m_state.compare_exchange_weak(state, next, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    if (owners == 1 && index_of(state) != TLS_OUT_OF_INDEXES)
                    {
                        (void)::TlsFree(index_of(state));
                    }
                    return;
                }
            }
        }

        /// Returns the published index, or TLS_OUT_OF_INDEXES.
        [[nodiscard]] DWORD index() const noexcept { return index_of(m_state.load(std::memory_order_acquire)); }

        /// Returns the registered owner count.
        [[nodiscard]] std::uint32_t owners() const noexcept
        {
            return owners_of(m_state.load(std::memory_order_acquire));
        }

    private:
        [[nodiscard]] static constexpr std::uint64_t pack(std::uint32_t owners, DWORD index) noexcept
        {
            return (static_cast<std::uint64_t>(owners) << 32) | index;
        }

        [[nodiscard]] static constexpr DWORD index_of(std::uint64_t state) noexcept
        {
            return static_cast<DWORD>(state & 0xFFFFFFFFULL);
        }

        [[nodiscard]] static constexpr std::uint32_t owners_of(std::uint64_t state) noexcept
        {
            return static_cast<std::uint32_t>(state >> 32);
        }

        /// No owner and no published index: the high word is zero and the low word is TLS_OUT_OF_INDEXES.
        static constexpr std::uint64_t UNOWNED = TLS_OUT_OF_INDEXES;
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

        std::atomic<std::uint64_t> m_state{UNOWNED};
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_SHARED_TLS_INDEX_HPP
