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
    /** @brief Named background worker built on std::jthread. The destructor runs @ref shutdown. */
    class StoppableWorker
    {
    public:
        /**
         * @brief Starts a worker thread that runs @p body.
         * @param name Name for log records. The worker copies it.
         * @param body Must poll its std::stop_token cooperatively and return promptly once stop is requested. An
         *             empty body logs an error and starts no thread.
         * @throws std::system_error if the module reference cannot be taken or the thread cannot be created.
         * @throws std::bad_alloc if owned setup state cannot be allocated.
         * @note After a throw, the worker owns no thread and no module reference. If the cleanup join throws, the
         *       constructor hands the thread and the reference to the reaper instead.
         */
        StoppableWorker(std::string_view name, std::function<void(std::stop_token)> body);

        ~StoppableWorker() noexcept;

        StoppableWorker(const StoppableWorker &) = delete;
        StoppableWorker &operator=(const StoppableWorker &) = delete;
        StoppableWorker(StoppableWorker &&) = delete;
        StoppableWorker &operator=(StoppableWorker &&) = delete;

        /// Requests a stop. Registered stop callbacks run synchronously on the calling thread and can block.
        void request_stop() noexcept;

        /**
         * @brief Returns true while the body starts or runs, and false once it returns or shutdown begins.
         * @note Race-free against a concurrent shutdown().
         */
        [[nodiscard]] bool is_running() const noexcept;

        /// Returns the worker name.
        [[nodiscard]] const std::string &name() const noexcept { return m_name; }

        /**
         * @brief Retires the worker thread. Idempotent.
         * @details Without blocking-teardown authorization, for example under the loader lock, it detaches with no stop
         *          request and leaks the module reference. Otherwise it requests stop, then joins and releases the
         *          reference. A failed join detaches the thread and keeps the reference. On the worker's own thread, it
         *          hands the thread and the reference to the reaper instead.
         * @note Setup/control-plane only.
         * @warning The join has no timeout. A body that ignores its std::stop_token hangs this call.
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
        // Heap ownership lets a failed detach retain the still-joinable jthread, so its destructor does not run.
        std::unique_ptr<std::jthread> m_thread;
        // Copy of the jthread stop source, so request_stop() never touches m_thread during a shutdown().
        std::stop_source m_stop_source;
        // Shared with the body, so its late state CAS touches live storage after a detach or a reaper hand-off.
        std::shared_ptr<std::atomic<State>> m_state;
        // Counted HMODULE reference on this module, taken before thread creation. shutdown() documents its release.
        // void* keeps <windows.h> out of this installed header. See detail::acquire_module_ref.
        void *m_self_ref{nullptr};
    };
} // namespace DetourModKit

#endif // DETOURMODKIT_WORKER_HPP
