/**
 * @file input_delivery_scope.cpp
 * @brief Reserved-Win32-TLS backing for the input-gate delivery-depth marker (input_delivery_scope.hpp).
 * @details Every failure mode reports "not recorded" to the constructing frame and nothing at all to other threads, so
 *          a gate can refuse the delivery it was about to run instead of the marker guessing on its behalf.
 */

#include "internal/input_delivery_scope.hpp"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <mutex>

namespace DetourModKit
{
    namespace detail
    {
        namespace
        {
            constexpr DWORD TLS_UNAVAILABLE = TLS_OUT_OF_INDEXES - 1;

            // Reserved TLS slot holding this thread's gate-delivery depth as an integer cast into the void* value.
            // TLS_OUT_OF_INDEXES means reservation has not run; TLS_UNAVAILABLE records a permanent failure.
            std::atomic<DWORD> s_depth_tls{TLS_OUT_OF_INDEXES};

            // Serializes the one-time slot reservation. Control-plane only; the hot delivery path never reaches it.
            std::mutex s_depth_tls_mutex;

#if defined(DMK_ENABLE_TEST_SEAMS)
            DeliveryScopeReservationSeam s_reservation_seam{nullptr};
            // Native thread identity keeps the seam exact without adding compiler TLS to the callback path.
            std::atomic<std::uint32_t> s_store_failure_thread{0};
#endif

            // The one store whose failure a caller's correctness depends on. Routed through a single function so the
            // seam sits exactly where the platform call does and cannot drift away from the branch it drives.
            [[nodiscard]] bool store_depth(DWORD index, std::uintptr_t depth) noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (s_store_failure_thread.load(std::memory_order_relaxed) ==
                    static_cast<std::uint32_t>(::GetCurrentThreadId()))
                {
                    return false;
                }
#endif
                return ::TlsSetValue(index, reinterpret_cast<void *>(depth)) != FALSE;
            }

            bool ensure_depth_tls() noexcept
            {
                const DWORD current_index = s_depth_tls.load(std::memory_order_acquire);
                if (current_index == TLS_UNAVAILABLE)
                {
                    return false;
                }
                if (current_index != TLS_OUT_OF_INDEXES)
                {
                    return true;
                }
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (s_reservation_seam != nullptr)
                {
                    s_reservation_seam();
                }
#endif
                try
                {
                    std::scoped_lock lock{s_depth_tls_mutex};
                    const DWORD locked_index = s_depth_tls.load(std::memory_order_relaxed);
                    if (locked_index != TLS_OUT_OF_INDEXES)
                    {
                        return locked_index != TLS_UNAVAILABLE;
                    }
                    const DWORD index = ::TlsAlloc();
                    if (index == TLS_OUT_OF_INDEXES)
                    {
                        s_depth_tls.store(TLS_UNAVAILABLE, std::memory_order_release);
                        return false;
                    }
                    s_depth_tls.store(index, std::memory_order_release);
                    return true;
                }
                catch (...)
                {
                    DWORD expected = TLS_OUT_OF_INDEXES;
                    (void)s_depth_tls.compare_exchange_strong(expected, TLS_UNAVAILABLE, std::memory_order_release,
                                                              std::memory_order_relaxed);
                    return false;
                }
            }
        } // namespace

        bool reserve_delivery_scope_tls() noexcept
        {
            return ensure_depth_tls();
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

        void set_delivery_scope_store_failure_for_test(bool fail) noexcept
        {
            s_store_failure_thread.store(fail ? static_cast<std::uint32_t>(::GetCurrentThreadId()) : 0,
                                         std::memory_order_release);
        }
#endif

        bool current_thread_in_delivery() noexcept
        {
            const DWORD index = s_depth_tls.load(std::memory_order_acquire);
            if (index == TLS_OUT_OF_INDEXES || index == TLS_UNAVAILABLE)
            {
                return false;
            }
            return reinterpret_cast<std::uintptr_t>(::TlsGetValue(index)) != 0;
        }

        DeliveryScope::DeliveryScope() noexcept : m_admitted(false)
        {
            if (!ensure_depth_tls())
            {
                return;
            }
            const DWORD index = s_depth_tls.load(std::memory_order_acquire);
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
            const DWORD index = s_depth_tls.load(std::memory_order_acquire);
            const auto depth = reinterpret_cast<std::uintptr_t>(::TlsGetValue(index));
            // The matching push succeeded, so this thread's expansion array for the slot already exists and the store
            // cannot fail for want of one. Floor at zero defensively.
            (void)::TlsSetValue(index, reinterpret_cast<void *>(depth > 0 ? depth - 1 : 0));
        }
    } // namespace detail
} // namespace DetourModKit
