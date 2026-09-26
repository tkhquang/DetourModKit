/**
 * @file input_delivery_scope.cpp
 * @brief Owned-Win32-TLS depth plus the stack-local teardown registry behind input_delivery_scope.hpp.
 * @details Every ordinary failure mode reports "not recorded" to the constructing frame and nothing at all to other
 *          threads, so a gate can refuse the delivery it was about to run instead of the marker guessing on its
 *          behalf. The teardown registry has no failure mode: its node lives on the caller's stack and the list is a
 *          pointer splice under a statically initialized SRW lock.
 */

#include "internal/input_delivery_scope.hpp"

#include "internal/shared_tls_index.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace DetourModKit
{
    namespace detail
    {
        namespace
        {
            // Owned TLS slot that holds this thread's gate-delivery depth as an integer cast into the void* value.
            constinit SharedTlsIndex s_depth_tls;

            // Teardown registry. SRWLOCK_INIT is a constant initializer, so the lock is usable from the first
            // teardown in the process without a dynamic initializer that could itself fail or order badly.
            SRWLOCK s_teardown_lock = SRWLOCK_INIT;
            TeardownRegistration *s_teardown_head{nullptr};
            // Lets the query skip the lock entirely while no teardown span is open, which is the ordinary case on the
            // delivery path that also asks this question.
            std::atomic<bool> s_teardown_open{false};

#if defined(DMK_ENABLE_TEST_SEAMS)
            DeliveryScopeReservationSeam s_reservation_seam{nullptr};
            // Native thread identities whose depth store must report failure. A fixed array keeps the seam exact and
            // allocation-free while letting the cross-gate compositions refuse on two threads at once.
            constexpr std::size_t MAX_STORE_FAILURE_THREADS = 4;
            std::array<std::atomic<std::uint32_t>, MAX_STORE_FAILURE_THREADS> s_store_failure_threads{};

            [[nodiscard]] bool store_failure_armed(std::uint32_t thread) noexcept
            {
                for (const std::atomic<std::uint32_t> &slot : s_store_failure_threads)
                {
                    if (slot.load(std::memory_order_acquire) == thread)
                    {
                        return true;
                    }
                }
                return false;
            }
#endif

            void register_teardown(TeardownRegistration &node) noexcept
            {
                ::AcquireSRWLockExclusive(&s_teardown_lock);
                node.next = s_teardown_head;
                s_teardown_head = &node;
                s_teardown_open.store(true, std::memory_order_release);
                ::ReleaseSRWLockExclusive(&s_teardown_lock);
            }

            void unregister_teardown(TeardownRegistration &node) noexcept
            {
                ::AcquireSRWLockExclusive(&s_teardown_lock);
                for (TeardownRegistration **link = &s_teardown_head; *link != nullptr; link = &(*link)->next)
                {
                    if (*link == &node)
                    {
                        *link = node.next;
                        break;
                    }
                }
                node.next = nullptr;
                s_teardown_open.store(s_teardown_head != nullptr, std::memory_order_release);
                ::ReleaseSRWLockExclusive(&s_teardown_lock);
            }

            [[nodiscard]] bool teardown_registered(std::uint32_t thread) noexcept
            {
                if (!s_teardown_open.load(std::memory_order_acquire))
                {
                    return false;
                }
                bool found = false;
                ::AcquireSRWLockShared(&s_teardown_lock);
                for (const TeardownRegistration *node = s_teardown_head; node != nullptr; node = node->next)
                {
                    if (node->thread == thread)
                    {
                        found = true;
                        break;
                    }
                }
                ::ReleaseSRWLockShared(&s_teardown_lock);
                return found;
            }

            // The one store whose failure a caller's correctness depends on. Routed through a single function so the
            // seam sits exactly where the platform call does and cannot drift away from the branch it drives.
            [[nodiscard]] bool store_depth(DWORD index, std::uintptr_t depth) noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (store_failure_armed(static_cast<std::uint32_t>(::GetCurrentThreadId())))
                {
                    return false;
                }
#endif
                return ::TlsSetValue(index, reinterpret_cast<void *>(depth)) != FALSE;
            }

            [[nodiscard]] bool depth_recorded_for_this_thread() noexcept
            {
                const DWORD index = s_depth_tls.index();
                if (index == TLS_OUT_OF_INDEXES)
                {
                    return false;
                }
                return reinterpret_cast<std::uintptr_t>(::TlsGetValue(index)) != 0;
            }
        } // namespace

        DeliveryTlsOwner::DeliveryTlsOwner() noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (s_reservation_seam != nullptr && s_depth_tls.index() == TLS_OUT_OF_INDEXES)
            {
                s_reservation_seam();
            }
#endif
            m_reserved = s_depth_tls.acquire() != TLS_OUT_OF_INDEXES;
        }

        DeliveryTlsOwner::~DeliveryTlsOwner() noexcept
        {
            s_depth_tls.release();
        }

        std::uint32_t current_native_thread_id() noexcept
        {
            return static_cast<std::uint32_t>(::GetCurrentThreadId());
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        void set_delivery_scope_reservation_seam_for_test(DeliveryScopeReservationSeam seam) noexcept
        {
            s_reservation_seam = seam;
        }

        DWORD delivery_scope_tls_index_for_test() noexcept
        {
            return s_depth_tls.index();
        }

        std::uint32_t delivery_scope_tls_owners_for_test() noexcept
        {
            return s_depth_tls.owners();
        }

        bool set_delivery_scope_store_failure_for_test(bool fail) noexcept
        {
            const auto thread = static_cast<std::uint32_t>(::GetCurrentThreadId());
            if (!fail)
            {
                for (std::atomic<std::uint32_t> &slot : s_store_failure_threads)
                {
                    std::uint32_t expected = thread;
                    if (slot.compare_exchange_strong(expected, 0, std::memory_order_acq_rel, std::memory_order_relaxed))
                    {
                        return true;
                    }
                }
                return true;
            }
            if (store_failure_armed(thread))
            {
                return true;
            }
            for (std::atomic<std::uint32_t> &slot : s_store_failure_threads)
            {
                std::uint32_t expected = 0;
                if (slot.compare_exchange_strong(
                        expected,
                        thread,
                        std::memory_order_acq_rel,
                        std::memory_order_relaxed
                    ))
                {
                    return true;
                }
            }
            return false;
        }
#endif

        bool current_thread_in_delivery() noexcept
        {
            if (depth_recorded_for_this_thread())
            {
                return true;
            }
            return teardown_registered(current_native_thread_id());
        }

        DeliveryScope::DeliveryScope() noexcept : m_index(s_depth_tls.index()), m_admitted(false)
        {
            // The enclosing gate owns the index, so it stays published until this frame ends.
            if (m_index == TLS_OUT_OF_INDEXES)
            {
                return;
            }
            const DWORD index = m_index;
            const auto depth = reinterpret_cast<std::uintptr_t>(::TlsGetValue(index));
            // A store can fail for a high slot index whose lazily heap-allocated TEB expansion array cannot be grown
            // under OOM. Leaving the depth understated would let a nested release wrongly conclude it is control-plane
            // and block into the ABBA, so the frame is refused instead and the caller declines the delivery.
            if (!store_depth(index, depth + 1))
            {
                return;
            }
            m_admitted = true;
        }

        DeliveryScope::~DeliveryScope() noexcept
        {
            if (!m_admitted)
            {
                return;
            }
            const auto depth = reinterpret_cast<std::uintptr_t>(::TlsGetValue(m_index));
            // The matching push succeeded, so this thread's expansion array for the slot already exists and the store
            // cannot fail for want of one. Floor at zero defensively.
            (void)::TlsSetValue(m_index, reinterpret_cast<void *>(depth > 0 ? depth - 1 : 0));
        }

        MandatoryDeliveryScope::MandatoryDeliveryScope() noexcept
        {
            m_registration.thread = current_native_thread_id();
            register_teardown(m_registration);
        }

        MandatoryDeliveryScope::~MandatoryDeliveryScope() noexcept
        {
            unregister_teardown(m_registration);
        }
    } // namespace detail
} // namespace DetourModKit
