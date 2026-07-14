#include "lifecycle_context.hpp"

namespace DetourModKit::detail
{
    namespace
    {
        // Constant initialization avoids a dynamic-initialization-order dependency between translation units.
        constinit LifecycleContext s_lifecycle;
    } // namespace

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
        // Publish the new generation and neutral loader context before mark_running() releases the admitted session.
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
} // namespace DetourModKit::detail
