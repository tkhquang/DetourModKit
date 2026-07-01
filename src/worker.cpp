#include "DetourModKit/worker.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"
#include "platform.hpp"

#include <utility>

namespace DetourModKit
{
    StoppableWorker::StoppableWorker(std::string_view name, std::function<void(std::stop_token)> body) : m_name(name)
    {
        if (!body)
        {
            log().error("StoppableWorker '{}': empty body; no thread started.", m_name);
            m_joined.store(true, std::memory_order_release);
            return;
        }

        m_thread = std::jthread(
            [fn = std::move(body), label = m_name](std::stop_token st)
            {
                try
                {
                    fn(st);
                }
                catch (const std::exception &e)
                {
                    log().error("StoppableWorker '{}': unhandled exception: {}", label, e.what());
                }
                catch (...)
                {
                    log().error("StoppableWorker '{}': unknown exception escaped body.", label);
                }
            });

        m_stop_source = m_thread.get_stop_source();

        // Publish liveness through an atomic once both the thread handle and stop source are initialized.
        // is_running() reads only this snapshot, and request_stop() signals m_stop_source, so neither path touches the
        // std::jthread handle concurrently with shutdown()'s join()/detach().
        m_started.store(true, std::memory_order_release);

        log().debug("StoppableWorker '{}' started.", m_name);
    }

    StoppableWorker::~StoppableWorker() noexcept
    {
        shutdown();
    }

    void StoppableWorker::request_stop() noexcept
    {
        // Gate on the liveness atomics rather than m_thread.joinable(): a concurrent shutdown() may be inside join()/
        // detach(), which mutate the handle. Signal the copied stop_source so this path never touches m_thread.
        if (m_started.load(std::memory_order_acquire) && !m_joined.load(std::memory_order_acquire))
        {
            m_stop_source.request_stop();
        }
    }

    bool StoppableWorker::is_running() const noexcept
    {
        return m_started.load(std::memory_order_acquire) && !m_joined.load(std::memory_order_acquire);
    }

    void StoppableWorker::shutdown() noexcept
    {
        bool expected = false;
        if (!m_joined.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return;
        }

        if (!m_thread.joinable())
        {
            return;
        }

        m_stop_source.request_stop();

        if (detail::is_loader_lock_held())
        {
            detail::pin_current_module();
            m_thread.detach();
            DetourModKit::Diagnostics::record_intentional_leak(DetourModKit::Diagnostics::LeakSubsystem::Worker);
            return;
        }

        m_thread.join();
    }
} // namespace DetourModKit
