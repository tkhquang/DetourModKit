#include "lifecycle_context.hpp"

#include "platform.hpp"

namespace DetourModKit
{
    namespace detail
    {
        namespace
        {
            // Constant initialization avoids a dynamic-initialization-order dependency between translation units.
            constinit LifecycleContext s_lifecycle;
        } // namespace

#if defined(DMK_ENABLE_TEST_SEAMS)
        bool (*g_loader_lock_override)() noexcept = nullptr;
#endif

        LifecycleContext &lifecycle() noexcept
        {
            return s_lifecycle;
        }

        bool LifecycleContext::begin_start() noexcept
        {
            LifecycleState expected = LifecycleState::Stopped;
            if (!m_state.compare_exchange_strong(expected, LifecycleState::Starting, std::memory_order_acq_rel))
            {
                return false;
            }
            // Publish the new generation and neutral loader context before mark_running() releases the admitted
            // session.
            m_generation.fetch_add(1, std::memory_order_acq_rel);
            m_loader_context.store(LoaderContext::Normal, std::memory_order_release);
            return true;
        }

        void LifecycleContext::mark_running() noexcept
        {
            m_state.store(LifecycleState::Running, std::memory_order_release);
        }

        void LifecycleContext::begin_stop() noexcept
        {
            m_state.store(LifecycleState::Stopping, std::memory_order_release);
        }

        void LifecycleContext::mark_stopped() noexcept
        {
            m_state.store(LifecycleState::Stopped, std::memory_order_release);
        }

        void LifecycleContext::publish_worker_thread() noexcept
        {
            m_worker_thread_id.store(static_cast<std::uint32_t>(GetCurrentThreadId()), std::memory_order_release);
        }

        void LifecycleContext::clear_worker_thread() noexcept
        {
            m_worker_thread_id.store(0, std::memory_order_release);
        }

        bool LifecycleContext::is_worker_thread() const noexcept
        {
            const std::uint32_t worker = worker_thread_id();
            return worker != 0 && worker == static_cast<std::uint32_t>(GetCurrentThreadId());
        }

        bool teardown_caller_authorized() noexcept
        {
            return lifecycle().context_permits_blocking() || lifecycle().is_worker_thread();
        }

        bool blocking_teardown_permitted() noexcept
        {
            // Authorization comes from the explicit context or the worker identity; the heuristic only ever subtracts
            // from it. Evaluated in this order so the cheap atomic loads reject a loader callback without paying for
            // the PEB probe.
            return teardown_caller_authorized() && !is_loader_lock_held();
        }
    } // namespace detail
} // namespace DetourModKit
