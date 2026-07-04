#include "DetourModKit/detail/worker.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"
#include "platform.hpp"

#include <system_error>
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

        // Take the module reference before creating the thread. Once std::jthread returns, the new thread may already
        // be executing library code, so the keepalive has to exist before the thread is published to the scheduler.
        const HMODULE self_ref = detail::acquire_module_ref();
        if (self_ref == nullptr)
        {
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                    "StoppableWorker: acquire_module_ref failed");
        }
        try
        {
            m_thread = std::jthread(
                [fn = std::move(body), label = m_name](const std::stop_token &st)
                {
                    try
                    {
                        fn(st);
                    }
                    catch (const std::exception &e)
                    {
                        // try_log, not error(): a throw from the logger here would escape the thread function and
                        // terminate the process, defeating the very containment these handlers provide.
                        (void)log().try_log(LogLevel::Error, "StoppableWorker '{}': unhandled exception: {}", label,
                                            e.what());
                    }
                    catch (...)
                    {
                        (void)log().try_log(LogLevel::Error, "StoppableWorker '{}': unknown exception escaped body.",
                                            label);
                    }
                });
        }
        catch (...)
        {
            detail::release_module_ref(self_ref);
            throw;
        }

        m_self_ref = self_ref;
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
            // Under the loader lock we cannot join without risking a deadlock. Detach the worker and leak its module
            // reference (never released), so the module's code stays mapped for the rest of the process while the
            // detached thread finishes.
            m_thread.detach();
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Worker);
            return;
        }

        m_thread.join();

        // Joined off the loader lock: the worker's code has finished, so drop the reference taken before thread
        // creation.
        // Another reference on the module still exists (the caller is executing this module's code), so this release is
        // never the terminal one that could unmap the module out from under us.
        detail::release_module_ref(static_cast<HMODULE>(m_self_ref));
        m_self_ref = nullptr;
    }
} // namespace DetourModKit
