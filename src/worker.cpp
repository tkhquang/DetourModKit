#include "DetourModKit/worker.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"
#include "platform.hpp"

#include <utility>

namespace DetourModKit
{
    StoppableWorker::StoppableWorker(std::string_view name,
                                     std::function<void(std::stop_token)> body)
        : m_name(name)
    {
        if (!body)
        {
            Logger::get_instance().error(
                "StoppableWorker '{}': empty body; no thread started.", m_name);
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
                    Logger::get_instance().error(
                        "StoppableWorker '{}': unhandled exception: {}", label, e.what());
                }
                catch (...)
                {
                    Logger::get_instance().error(
                        "StoppableWorker '{}': unknown exception escaped body.", label);
                }
            });

        Logger::get_instance().debug("StoppableWorker '{}' started.", m_name);
    }

    StoppableWorker::~StoppableWorker() noexcept
    {
        shutdown();
    }

    void StoppableWorker::request_stop() noexcept
    {
        if (m_thread.joinable())
        {
            m_thread.request_stop();
        }
    }

    bool StoppableWorker::is_running() const noexcept
    {
        return m_thread.joinable() && !m_joined.load(std::memory_order_acquire);
    }

    void StoppableWorker::shutdown() noexcept
    {
        bool expected = false;
        if (!m_joined.compare_exchange_strong(expected, true,
                                             std::memory_order_acq_rel))
        {
            return;
        }

        if (!m_thread.joinable())
        {
            return;
        }

        m_thread.request_stop();

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
