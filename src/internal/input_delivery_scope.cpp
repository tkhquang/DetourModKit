/**
 * @file input_delivery_scope.cpp
 * @brief Reserved-Win32-TLS backing for the input-gate delivery-depth marker (input_delivery_scope.hpp).
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

            // Deliveries whose depth could not be recorded in TLS (slot unavailable, or a TlsSetValue expansion-array
            // allocation failed under OOM). While any exist, current_thread_in_delivery() reports true process-wide so
            // every release defers its rundown rather than block: fail-closed toward the no-deadlock outcome. This is
            // an extreme-OOM-only fallback.
            std::atomic<std::uint32_t> s_untracked_frames{0};

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
                try
                {
                    std::scoped_lock lock{s_depth_tls_mutex};
                    if (s_depth_tls.load(std::memory_order_relaxed) != TLS_OUT_OF_INDEXES)
                    {
                        return true;
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

        bool current_thread_in_delivery() noexcept
        {
            if (s_untracked_frames.load(std::memory_order_acquire) != 0)
            {
                return true;
            }
            const DWORD index = s_depth_tls.load(std::memory_order_acquire);
            if (index == TLS_OUT_OF_INDEXES || index == TLS_UNAVAILABLE)
            {
                return false;
            }
            return reinterpret_cast<std::uintptr_t>(::TlsGetValue(index)) != 0;
        }

        DeliveryScope::DeliveryScope() noexcept
        {
            if (!ensure_depth_tls())
            {
                m_tracked = false;
                s_untracked_frames.fetch_add(1, std::memory_order_acq_rel);
                return;
            }
            const DWORD index = s_depth_tls.load(std::memory_order_acquire);
            const auto depth = reinterpret_cast<std::uintptr_t>(::TlsGetValue(index));
            // A store can fail for a high slot index whose lazily heap-allocated TEB expansion array cannot be grown
            // under OOM. Record an untracked frame rather than leave the depth understated, which would let a nested
            // release wrongly conclude it is control-plane and block into the ABBA.
            if (::TlsSetValue(index, reinterpret_cast<void *>(depth + 1)) == FALSE)
            {
                m_tracked = false;
                s_untracked_frames.fetch_add(1, std::memory_order_acq_rel);
                return;
            }
            m_tracked = true;
        }

        DeliveryScope::~DeliveryScope() noexcept
        {
            if (!m_tracked)
            {
                s_untracked_frames.fetch_sub(1, std::memory_order_acq_rel);
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
