#ifndef DETOURMODKIT_ASYNC_LOGGER_HPP
#define DETOURMODKIT_ASYNC_LOGGER_HPP

#include "DetourModKit/async_logger_config.hpp"
#include "DetourModKit/logger.hpp"

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace DetourModKit
{
    /// Default timeout for a blocking flush to complete.
    inline constexpr auto DEFAULT_FLUSH_TIMEOUT = std::chrono::milliseconds(500);

    /**
     * @class AsyncLogger
     * @brief Asynchronous logger that decouples log production from file I/O.
     * @details Uses a lock-free queue to accept log messages from multiple threads and a dedicated writer thread to
     *          perform batched file writes. This significantly reduces latency on the producer side. The configuration
     *          type (AsyncLoggerConfig) lives in async_logger_config.hpp. All implementation state -- the MPMC queue,
     *          the overflow string pool, the per-message record, the writer thread, and the flush synchronization --
     *          lives behind a pimpl (Impl, defined in src/async_logger.cpp over the non-installed
     *          src/internal/async_logger_queue.hpp), so this public header names none of it and a consumer compiles
     *          with the queue / pool / threading internals off its include path.
     * @note Internal transport, not a consumer-constructible type: its only constructor takes a
     *       `detail::WinFileStream` (a private, never-installed sink) plus the Logger's file mutex, so only `Logger`
     *       -- which owns both -- builds one, driven by `Logger::enable_async_mode()`. A consumer logs through the
     *       `Logger` value facade or the free `log()`, never by constructing an `AsyncLogger` directly; the class is
     *       named on the public surface only because `Logger` holds it behind an `atomic<shared_ptr<AsyncLogger>>`.
     * @note Uses shared_ptr<detail::WinFileStream> to safely handle Logger reconfiguration during runtime.
     * @note The destructor is self-safe under the Windows loader lock: if teardown had to detach the writer thread
     *       (because a join would deadlock under the loader lock), the destructor leaks the pimpl in place so the
     *       queue / condition variable / file stream the detached writer still reads are never freed under it. An owner
     *       therefore does not have to leak the handle itself to destroy an AsyncLogger safely from a loader-lock path.
     */
    class AsyncLogger
    {
    public:
        /**
         * @brief Constructs an AsyncLogger with the given configuration.
         * @param config The async logger configuration.
         * @param file_stream Shared pointer to the output file stream (allows safe reconfigure).
         * @param log_mutex Shared pointer to the mutex protecting the file stream.
         */
        explicit AsyncLogger(const AsyncLoggerConfig &config, std::shared_ptr<detail::WinFileStream> file_stream,
                             std::shared_ptr<std::mutex> log_mutex);

        /**
         * @brief Stops the writer and destroys the logger, staying safe under the Windows loader lock.
         * @details Runs shutdown() first. On a clean off-loader-lock teardown the writer is joined and the pimpl is
         *          destroyed normally. If shutdown() had to DETACH the writer (loader-lock path), the pimpl is instead
         *          leaked in place -- the already-heap-allocated implementation is abandoned rather than freed -- so the
         *          detached writer keeps reading a live queue / condition variable / file stream until it observes the
         *          stop and exits. The writer's own counted module reference keeps its code pages mapped.
         */
        ~AsyncLogger() noexcept;

        AsyncLogger(const AsyncLogger &) = delete;
        AsyncLogger &operator=(const AsyncLogger &) = delete;
        AsyncLogger(AsyncLogger &&) = delete;
        AsyncLogger &operator=(AsyncLogger &&) = delete;

        /**
         * @brief Enqueues a log message for asynchronous writing.
         * @param level The log level.
         * @param message The message string.
         * @return true if the message was successfully enqueued or written, false if dropped or timed out.
         * @details Non-blocking under the DropNewest / DropOldest policies. Under OverflowPolicy::Block a full queue
         *          parks the caller up to block_timeout_ms, and under OverflowPolicy::SyncFallback a full queue writes
         *          the message synchronously on the calling thread, so neither of those policies is callback-safe (see
         *          OverflowPolicy). Otherwise the message is written by the writer thread.
         * @note Best-effort: never throws and returns false on drop. Callback-safe only under the DropNewest /
         *       DropOldest policies (see @details).
         */
        [[nodiscard]] bool enqueue(LogLevel level, std::string_view message) noexcept;

        /**
         * @brief Flushes all pending log messages with a timeout.
         * @param timeout Maximum time to wait for flush to complete.
         * @return true if all messages were flushed, false if timeout occurred.
         */
        [[nodiscard]] bool flush_with_timeout(std::chrono::milliseconds timeout) noexcept;

        /**
         * @brief Flushes all pending log messages.
         * @details Waits up to 500ms for all queued messages to be written. Uses a timeout to prevent indefinite
         *          blocking.
         */
        void flush() noexcept;

        /**
         * @brief Stops the writer thread and drains remaining queued messages.
         * @details Signals shutdown. Off the Windows loader lock, joins the writer thread, then drains any messages
         * that
         *          arrived between the stop signal and thread exit. Under the loader lock, detaches the writer instead
         *          of joining; the destructor observes that detach and leaks the pimpl in place so the detached writer's
         *          queue, condition variable, and file stream stay alive until the writer exits.
         * @note A producer that already passed the shutdown check but has not yet completed try_push() can enqueue at
         *       most one message after the final drain. This is an accepted trade-off to avoid adding atomic overhead
         *       (producers_in_flight counter) to every enqueue() call.
         */
        void shutdown() noexcept;

        [[nodiscard]] bool is_running() const noexcept;

        /**
         * @brief Reports whether the writer thread is currently parked on the flush condition variable.
         * @details Observability accessor for the idle-park state set by the writer immediately before it
         *          blocks in wait_for and cleared when it wakes. Lets a test or diagnostic confirm the
         *          writer has reached the parked path deterministically instead of relying on a fixed
         *          sleep. The flag can flip at any time, so treat the result as a point-in-time snapshot.
         */
        [[nodiscard]] bool is_writer_waiting() const noexcept;

        [[nodiscard]] size_t queue_size() const noexcept;

        /**
         * @brief Returns the total number of messages dropped due to queue overflow.
         * @return size_t Number of dropped messages.
         */
        [[nodiscard]] size_t dropped_count() const noexcept;

        /**
         * @brief Resets the dropped message counter.
         */
        void reset_dropped_count() noexcept;

    private:
        friend class Logger;

        // Logger::reconfigure holds the shared sink mutex while pushing a new timestamp format into the writer's
        // private config snapshot. The setter takes no lock because taking that same non-recursive mutex here would
        // self-deadlock the reconfigure path.
        void set_timestamp_format(std::string timestamp_format) noexcept;

        // All implementation state and behaviour live behind this pimpl so the queue, string pool, per-message record,
        // writer thread, and flush synchronization stay off the public include path (their definitions live in the
        // non-installed src/internal/async_logger_queue.hpp, reached only by src/async_logger.cpp).
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_ASYNC_LOGGER_HPP
