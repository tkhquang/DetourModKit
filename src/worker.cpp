#include "DetourModKit/detail/worker.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"
#include "internal/lifecycle_context.hpp"
#include "internal/lifecycle_reaper.hpp"
#include "platform.hpp"

#include <atomic>
#include <memory>
#include <system_error>
#include <thread>
#include <utility>

namespace DetourModKit
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    namespace detail
    {
        // A throwing probe exercises construction failure after thread creation but before ownership publication.
        void (*g_worker_post_thread_start_seam)() = nullptr;

        // A throwing probe exercises shutdown's join/detach-failure containment after its safety guards pass.
        void (*g_worker_join_fail_seam)() = nullptr;
    } // namespace detail
#endif

    StoppableWorker::StoppableWorker(std::string_view name, std::function<void(std::stop_token)> body)
        : m_name(name), m_state(std::make_shared<std::atomic<State>>(State::Starting))
    {
        if (!body)
        {
            (void)log().try_log(LogLevel::Error, "StoppableWorker '{}': empty body; no thread started.", m_name);
            m_state->store(State::Stopped, std::memory_order_release);
            return;
        }

        // Take the module reference before creating the thread: once std::jthread returns the new thread may
        // already be running library code, so the keepalive must exist first.
        const HMODULE self_ref = detail::acquire_module_ref();
        if (self_ref == nullptr)
        {
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                    "StoppableWorker: acquire_module_ref failed");
        }

        try
        {
            m_thread = std::make_unique<std::jthread>(
                [fn = std::move(body), label = m_name, state = m_state](const std::stop_token &st)
                {
                    // First act: mark Running, unless a racing shutdown() already claimed teardown.
                    State expected = State::Starting;
                    state->compare_exchange_strong(expected, State::Running, std::memory_order_acq_rel);
                    try
                    {
                        fn(st);
                    }
                    catch (const std::exception &e)
                    {
                        // try_log, not error(): a throw from the logger here would escape the thread function
                        // and terminate the process, defeating the very containment these handlers provide.
                        (void)log().try_log(LogLevel::Error, "StoppableWorker '{}': unhandled exception: {}", label,
                                            e.what());
                    }
                    catch (...)
                    {
                        (void)log().try_log(LogLevel::Error, "StoppableWorker '{}': unknown exception escaped body.",
                                            label);
                    }
                    // Last act: mark Exited so a caller can distinguish a self-exited body from a live one,
                    // unless shutdown() already moved the state to Stopping/Stopped.
                    State running = State::Running;
                    state->compare_exchange_strong(running, State::Exited, std::memory_order_acq_rel);
                });

#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *seam = detail::g_worker_post_thread_start_seam)
            {
                seam();
            }
#endif

            m_stop_source = m_thread->get_stop_source();
            m_self_ref = self_ref;
        }
        catch (...)
        {
            // A throw after the thread was created (the test seam, or any would-be publication step). The
            // thread may be running: request stop and join it -- this runs on the constructing thread, never
            // the worker's own and never under the loader lock -- then release the module reference so
            // acquire/release stay balanced. No thread is ever left behind, and m_self_ref was not yet set,
            // so nothing is double-released.
            if (m_thread != nullptr && m_thread->joinable())
            {
                m_thread->request_stop();
                try
                {
                    m_thread->join();
                }
                catch (...)
                {
                    detail::reap_worker_thread(std::move(m_thread), self_ref);
                    throw;
                }
            }
            detail::release_module_ref(self_ref);
            throw;
        }

        // Best-effort log AFTER publication. try_log never throws, so a logging failure here can neither
        // unwind the constructor nor leak the module reference the worker now owns.
        (void)log().try_log(LogLevel::Debug, "StoppableWorker '{}' started.", m_name);
    }

    StoppableWorker::~StoppableWorker() noexcept
    {
        shutdown();
    }

    void StoppableWorker::request_stop() noexcept
    {
        // Signal the copied stop_source while the body may still observe it. Stopping/Stopped already
        // requested stop; Exited has no body left to notify. Reading the shared state never touches m_thread,
        // so this stays race-free against a concurrent shutdown() join/detach.
        const State s = m_state->load(std::memory_order_acquire);
        if (s == State::Starting || s == State::Running)
        {
            m_stop_source.request_stop();
        }
    }

    bool StoppableWorker::is_running() const noexcept
    {
        const State s = m_state->load(std::memory_order_acquire);
        return s == State::Starting || s == State::Running;
    }

    void StoppableWorker::shutdown() noexcept
    {
        // Single-entry: claim teardown by moving to Stopping. A second shutdown (or the destructor after an
        // explicit shutdown) observes Stopping/Stopped and returns.
        State prev = m_state->load(std::memory_order_acquire);
        for (;;)
        {
            if (prev == State::Stopping || prev == State::Stopped)
            {
                return;
            }
            if (m_state->compare_exchange_weak(prev, State::Stopping, std::memory_order_acq_rel))
            {
                break;
            }
        }

        if (m_thread == nullptr || !m_thread->joinable())
        {
            m_state->store(State::Stopped, std::memory_order_release);
            return;
        }

        m_stop_source.request_stop();

        if (!detail::blocking_teardown_permitted())
        {
            // No authorization to block: either a loader callback is in progress or the fail-closed probe vetoed.
            // Joining a worker that may itself await the loader lock deadlocks. Detach and leave the module
            // reference outstanding so the detached thread's code pages stay mapped.
            std::unique_ptr<std::jthread> retained_thread = std::move(m_thread);
            try
            {
                retained_thread->detach();
            }
            catch (...)
            {
                // A joinable jthread cannot be destroyed safely after detach failed. Its heap cell and the
                // module reference remain paired and reachable for the life of the running thread.
                (void)retained_thread.release();
            }
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Worker);
            m_self_ref = nullptr;
            m_state->store(State::Stopped, std::memory_order_release);
            return;
        }

        if (m_thread->get_id() == std::this_thread::get_id())
        {
            // Self-shutdown reached from inside the body (e.g. a reload setter destroying the servicer whose
            // worker runs it). A self-join would raise std::system_error out of this noexcept function. Hand
            // the thread and module reference to the reaper: it joins once the body returns and then releases
            // the reference, so nothing is permanently leaked.
            detail::reap_worker_thread(std::move(m_thread), m_self_ref);
            m_self_ref = nullptr;
            m_state->store(State::Stopped, std::memory_order_release);
            return;
        }

        try
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *seam = detail::g_worker_join_fail_seam)
            {
                seam();
            }
#endif
            m_thread->join();
            m_thread.reset();

            // Joined off the loader lock: the worker's code has finished, so drop the reference taken before
            // thread creation. Another reference on the module still exists (the caller is executing this
            // module's code), so this release is never the terminal one that could unmap the module out from
            // under us.
            detail::release_module_ref(static_cast<HMODULE>(m_self_ref));
            m_self_ref = nullptr;
        }
        catch (...)
        {
            // Contain a join failure (std::system_error) inside this noexcept function. The thread's completion
            // is now uncertain, so detach it (both to abandon it safely and to stop the eventual ~jthread from
            // re-attempting the join and re-throwing into a noexcept destructor) and leave the module reference
            // outstanding rather than release it into a possibly-still-running thread. That leaves a safe,
            // diagnosed Stopped state.
            try
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *seam = detail::g_worker_join_fail_seam)
                {
                    seam();
                }
#endif
                if (m_thread != nullptr && m_thread->joinable())
                {
                    m_thread->detach();
                }
            }
            catch (...)
            {
                // Retain a still-joinable jthread so its destructor cannot retry the failed operation.
                (void)m_thread.release();
            }
            (void)log().try_log(LogLevel::Error,
                                "StoppableWorker '{}': join failed; abandoning module reference to stay safe.", m_name);
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Worker);
            m_self_ref = nullptr;
        }
        m_state->store(State::Stopped, std::memory_order_release);
    }
} // namespace DetourModKit
