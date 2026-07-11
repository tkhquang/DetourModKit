#ifndef DETOURMODKIT_WORKER_HPP
#define DETOURMODKIT_WORKER_HPP

/**
 * @file worker.hpp
 * @brief RAII wrapper around std::jthread with a named stop signal.
 * @note This header sits in the detail/ directory for compile visibility: the umbrella must include it. It declares
 *       StoppableWorker at the module-root DetourModKit namespace because it is a public background-worker utility a
 *       consumer reaches through the umbrella, not an implementation detail (no installed header names the type in a
 *       signature). Directory placement and namespace placement are independent; the directory reflects compile
 *       visibility, not privacy.
 */

#include <atomic>
#include <functional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

namespace DetourModKit
{
    /**
     * @class StoppableWorker
     * @brief RAII-owned named background worker built on std::jthread.
     * @details The body receives a std::stop_token and must poll it cooperatively. On destruction the worker requests
     *          stop and joins the thread, unless a join would deadlock -- when the current thread holds the Windows
     *          loader lock, or when shutdown() runs on the worker's own thread (a self-join) -- in which case the thread
     *          is detached instead. Callers that need to preempt the loader-lock case should call shutdown() from a
     *          thread outside DllMain prior to teardown.
     *
     *          Non-copyable and non-movable: the name, stop state, and thread handle form a single invariant. Copying
     *          would duplicate the thread handle; moving would race with a running body.
     */
    class StoppableWorker
    {
    public:
        /**
         * @brief Starts a new worker thread running the supplied body.
         * @param name Descriptive name for logging. Copied into the worker.
         * @param body Invocable receiving a stop_token. Must return promptly when stop_requested() becomes true.
         * @throws std::system_error if the worker's counted module reference cannot be taken (the keepalive must exist
         *         before the thread can run library code) or if the thread itself cannot be created. Construction is
         *         all-or-nothing: on throw no thread exists and the reference has been released, so callers may treat
         *         a constructed worker as fully started.
         */
        StoppableWorker(std::string_view name, std::function<void(std::stop_token)> body);

        ~StoppableWorker() noexcept;

        StoppableWorker(const StoppableWorker &) = delete;
        StoppableWorker &operator=(const StoppableWorker &) = delete;
        StoppableWorker(StoppableWorker &&) = delete;
        StoppableWorker &operator=(StoppableWorker &&) = delete;

        /**
         * @brief Signals the worker to stop cooperatively.
         * @details Idempotent. Does not block.
         */
        void request_stop() noexcept;

        /**
         * @brief Returns true once the worker thread has started and before it has been shut down.
         * @details Reads liveness from atomics, never the std::jthread handle, so it is race-free against a concurrent
         *          shutdown() that joins or detaches the thread.
         */
        [[nodiscard]] bool is_running() const noexcept;

        /**
         * @brief Returns the worker's descriptive name.
         */
        [[nodiscard]] const std::string &name() const noexcept { return m_name; }

        /**
         * @brief Requests stop and joins the worker thread.
         * @details Safe to call multiple times. If a join would be unsafe -- invoked under the Windows loader lock, or
         *          on the worker's own thread (a self-join, which would otherwise raise
         *          std::system_error(resource_deadlock_would_occur) and escape this noexcept function) -- the thread is
         *          detached instead of joined, and the module reference taken before thread creation is left outstanding
         *          so the detached worker's code pages stay mapped (documented trade-off).
         */
        void shutdown() noexcept;

    private:
        std::string m_name;
        std::jthread m_thread;
        // Stable copy of the jthread stop source. request_stop() signals this shared stop state instead of touching
        // m_thread while shutdown() may be joining or detaching the handle.
        std::stop_source m_stop_source;
        // Liveness snapshot read by is_running()/request_stop(). m_started is set once m_thread and m_stop_source are
        // both initialized; m_joined is set when shutdown begins (or in the empty-body early return).
        std::atomic<bool> m_started{false};
        std::atomic<bool> m_joined{false};
        // Counted reference on the module this worker's code lives in, taken before thread creation while the module is
        // fully mapped. shutdown() releases it after a clean join, or leaks it on either detach path (loader lock or
        // self-join) so the module stays mapped for the detached thread. Stored as void* to keep this installed header
        // free of <windows.h>; it holds an HMODULE in the implementation. See detail::acquire_module_ref.
        void *m_self_ref{nullptr};
    };
} // namespace DetourModKit

#endif // DETOURMODKIT_WORKER_HPP
