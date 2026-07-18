#ifndef DETOURMODKIT_INTERNAL_ASYNC_LOGGER_HPP
#define DETOURMODKIT_INTERNAL_ASYNC_LOGGER_HPP

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
     * @details A dedicated writer thread drains a lock-free MPMC queue and performs batched writes, so producers pay
     *          only an enqueue. All transport state (queue, string pool, per-message record, writer, flush
     *          synchronization) lives behind a pimpl, so this header names none of it.
     * @note Internal transport, not a consumer-constructible type. Its constructor takes a private, never-installed
     *       `detail::WinFileStream` sink plus the Logger's file mutex, so only `Logger` builds one (through
     *       `Logger::enable_async_mode()`); a consumer logs through the `Logger` facade or the free `log()`.
     * @note The sink is held by shared_ptr so a runtime Logger reconfigure can swap it safely.
     * @note The destructor is self-safe under the Windows loader lock: if shutdown() had to detach the writer (a join
     *       would deadlock under the loader lock), it leaks the pimpl in place so the queue / condition variable / file
     *       stream the detached writer still reads are never freed under it.
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
         * @details Runs shutdown() first. Off the loader lock the writer is joined and the pimpl destroyed normally. If
         *          shutdown() had to detach the writer (loader-lock path), the pimpl is leaked in place so the detached
         *          writer keeps reading a live queue / condition variable / file stream until it observes the stop; its
         *          own counted module reference keeps its code pages mapped.
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
         *          OverflowPolicy). Otherwise the message is written by the writer thread. Once shutdown has begun the
         *          message is dropped and counted under every policy; a callback-safe producer never blocks on
         *          synchronous I/O during teardown.
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
         * @brief Requests shutdown and gives the drain and final sink access a single owner.
         * @details Stops admission, waits for producers already admitted, and lets the writer alone finish the drain
         *          and sink flush. Off the Windows loader lock it joins the writer. Under the loader lock it abandons
         *          the writer and pimpl without waiting, draining, or touching the sink.
         */
        void shutdown() noexcept;

        [[nodiscard]] bool is_running() const noexcept;

        /**
         * @brief Reports whether shutdown() detached the writer under the loader lock instead of joining it.
         * @details The owner reads this after shutdown() to decide sink ownership: a detached writer still owns final
         *          sink access, so the sink must be abandoned (leaked with the detached Impl), never closed. Tying that
         *          decision to the actual detach outcome, rather than an independent loader-lock re-query, removes a
         *          TOCTOU between the two.
         */
        [[nodiscard]] bool writer_was_detached() const noexcept;

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
        // non-installed src/internal/async_logger_queue.hpp, reached only by src/internal/async_logger.cpp).
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_ASYNC_LOGGER_HPP
