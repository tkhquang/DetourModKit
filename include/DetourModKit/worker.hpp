#ifndef DETOURMODKIT_WORKER_HPP
#define DETOURMODKIT_WORKER_HPP

/**
 * @file worker.hpp
 * @brief RAII wrapper around std::jthread with a named stop signal.
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
     * @details The body receives a std::stop_token and must poll it
     *          cooperatively. On destruction the worker requests stop and
     *          joins the thread, unless it detects that the current thread
     *          is executing under the Windows loader lock -- in which case
     *          the thread is detached to avoid deadlock. Callers that need
     *          to preempt the loader-lock case should call request_stop()
     *          and join() from a thread outside DllMain prior to teardown.
     *
     *          Non-copyable and non-movable: the name, stop state, and
     *          thread handle form a single invariant. Copying would
     *          duplicate the thread handle; moving would race with a
     *          running body.
     */
    class StoppableWorker
    {
    public:
        /**
         * @brief Starts a new worker thread running the supplied body.
         * @param name Descriptive name for logging. Copied into the worker.
         * @param body Invocable receiving a stop_token. Must return promptly
         *             when stop_requested() becomes true.
         */
        StoppableWorker(std::string_view name,
                        std::function<void(std::stop_token)> body);

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
         * @brief Returns true while the worker thread is still joinable.
         */
        [[nodiscard]] bool is_running() const noexcept;

        /**
         * @brief Returns the worker's descriptive name.
         */
        [[nodiscard]] const std::string &name() const noexcept { return name_; }

        /**
         * @brief Requests stop and joins the worker thread.
         * @details Safe to call multiple times. If invoked under the
         *          Windows loader lock the thread is detached instead of
         *          joined (documented trade-off -- the pinned module
         *          keeps code pages alive).
         */
        void shutdown() noexcept;

    private:
        std::string name_;
        std::jthread thread_;
        std::atomic<bool> joined_{false};
    };
} // namespace DetourModKit

#endif // DETOURMODKIT_WORKER_HPP
