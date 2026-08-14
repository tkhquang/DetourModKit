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
     *       would deadlock under the loader lock), it leaks the pimpl in place so the queue / wake event / condition
     *       variable / file stream the detached writer still reads are never freed under it.
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
         *          writer keeps reading a live queue / wake event / condition variable / file stream until it observes
         *          the stop; its own counted module reference keeps its code pages mapped.
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
         * @details The policies have these effects:
         *          - DropNewest does not wait for queue capacity.
         *          - DropOldest does not wait for queue capacity, but it can take the string-pool lock.
         *          - Block parks the caller up to block_timeout_ms.
         *          - SyncFallback writes the message on the caller thread.
         * @note A new long message takes the string-pool lock before policy selection. Shutdown drops and counts every
         *       new message.
         * @note The function never throws and returns false on a drop. It is callback-safe only under DropNewest for a
         *       message within LOG_INLINE_MESSAGE_SIZE.
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

#if defined(DMK_ENABLE_TEST_SEAMS)
        /**
         * @brief Reports whether the writer thread is currently parked on its wake event.
         * @details Test observability for the point-in-time idle flag published immediately before the event wait.
         */
        [[nodiscard]] bool is_writer_waiting() const noexcept;
#endif

        [[nodiscard]] size_t queue_size() const noexcept;

        /**
         * @brief Returns the total messages rejected or not confirmed delivered.
         * @return Number rejected by admission, validation, overflow, fallback, or writer failure.
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

        // Armed after make_shared and before publication. Copying this established strong owner allocates no control
        // block, so detach can retain the writer by leaving the root intact. Serialized by the async lifecycle mutex.
        void arm_retention_root(const std::shared_ptr<AsyncLogger> &self) noexcept;

        // The caller holds an external strong owner while breaking the root, either before publication or after a
        // clean join. Serialized by the async lifecycle mutex.
        void release_retention_root() noexcept;

        // All implementation state and behaviour live behind this pimpl so the queue, string pool, per-message record,
        // writer thread, and flush synchronization stay off the public include path (their definitions live in the
        // non-installed src/internal/async_logger_queue.hpp, reached only by src/internal/async_logger.cpp).
        struct Impl;
        std::unique_ptr<Impl> m_impl;

        // Self-reference that keeps this object (and therefore the Impl a detached writer still reads) alive when the
        // owner cannot join. Owning yourself is a deliberate cycle: it is the only retention whose storage is already
        // provisioned before the state that needs retaining exists, so the detach path never allocates, never throws,
        // and has no exhaustion case. Empty on the ordinary path, where the owner breaks it after a clean join.
        std::shared_ptr<AsyncLogger> m_retention_root;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_ASYNC_LOGGER_HPP
