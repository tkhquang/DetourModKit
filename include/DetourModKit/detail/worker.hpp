#ifndef DETOURMODKIT_WORKER_HPP
#define DETOURMODKIT_WORKER_HPP

/**
 * @file worker.hpp
 * @brief RAII wrapper around std::jthread with a named stop signal and explicit lifecycle state.
 * @note Lives in detail/ for compile visibility but declares the public utility at the DetourModKit root.
 */

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

namespace DetourModKit
{
    /**
     * @class StoppableWorker
     * @brief RAII-owned named background worker built on std::jthread.
     * @details The body receives a std::stop_token and must poll it cooperatively. Destruction requests stop
     *          and joins. Under the Windows loader lock the thread is detached and its module reference leaked;
     *          self-shutdown hands the thread and reference to an off-thread reaper. The type is non-copyable
     *          and non-movable because its name, stop state, lifecycle, and thread handle form one invariant.
     */
    class StoppableWorker
    {
    public:
        /**
         * @brief Starts a worker thread running @p body.
         * @param name Descriptive name for logging. Copied into the worker.
         * @param body Invocable receiving a stop_token. Must return promptly once stop_requested().
         * @throws std::system_error if the counted module reference cannot be taken (the keepalive must exist
         *         before the thread runs library code) or the thread cannot be created.
         * @throws std::bad_alloc if owned setup state cannot be allocated.
         * @note Construction is all-or-nothing: on throw no thread survives and the module reference is released.
         */
        StoppableWorker(std::string_view name, std::function<void(std::stop_token)> body);

        ~StoppableWorker() noexcept;

        StoppableWorker(const StoppableWorker &) = delete;
        StoppableWorker &operator=(const StoppableWorker &) = delete;
        StoppableWorker(StoppableWorker &&) = delete;
        StoppableWorker &operator=(StoppableWorker &&) = delete;

        /// Signals the worker to stop cooperatively. Idempotent; does not block.
        void request_stop() noexcept;

        /**
         * @brief Returns true while the body is starting or executing.
         * @details Returns false once the body returns or shutdown begins. Reads shared atomic state rather
         *          than the jthread handle, so it is race-free against concurrent shutdown.
         */
        [[nodiscard]] bool is_running() const noexcept;

        /// Returns the worker's descriptive name.
        [[nodiscard]] const std::string &name() const noexcept { return m_name; }

        /**
         * @brief Requests stop and retires the worker thread.
         * @details Idempotent. Joins off the loader lock and off the worker's own thread; under the loader
         *          lock it detaches and leaks the module reference (documented trade-off); on the worker's
         *          own thread it hands the thread and reference to the off-thread reaper so a self-join can
         *          never raise std::system_error inside this noexcept function.
         */
        void shutdown() noexcept;

    private:
        enum class State : std::uint8_t
        {
            Starting,
            Running,
            Exited,
            Stopping,
            Stopped
        };

        std::string m_name;
        // Heap ownership lets a failed detach retain the still-joinable jthread without running its destructor.
        std::unique_ptr<std::jthread> m_thread;
        // Stable copy of the jthread stop source: request_stop() signals this instead of touching m_thread
        // while shutdown() may be joining or detaching the handle.
        std::stop_source m_stop_source;
        // Lifecycle phase, heap-shared with the body so the body can publish Running/Exited even if the owner
        // is reaped or detached while the body still runs. is_running()/request_stop()/shutdown() read and
        // write it without touching the jthread handle.
        std::shared_ptr<std::atomic<State>> m_state;
        // Counted reference on the module this worker's code lives in, taken before thread creation while the
        // module is mapped. shutdown() releases it after a clean join, hands it to the reaper on
        // self-shutdown, or leaks it on a loader-lock detach. void* keeps this installed header free of
        // <windows.h>; it holds an HMODULE. See detail::acquire_module_ref.
        void *m_self_ref{nullptr};
    };
} // namespace DetourModKit

#endif // DETOURMODKIT_WORKER_HPP
