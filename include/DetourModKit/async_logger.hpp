#ifndef DETOURMODKIT_ASYNC_LOGGER_HPP
#define DETOURMODKIT_ASYNC_LOGGER_HPP

#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger_config.hpp"
#include "DetourModKit/detail/async_logger_internal.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>
#include <thread>

namespace DetourModKit
{
    /// Default timeout for a blocking flush to complete.
    inline constexpr auto DEFAULT_FLUSH_TIMEOUT = std::chrono::milliseconds(500);

    /**
     * @class AsyncLogger
     * @brief Asynchronous logger that decouples log production from file I/O.
     * @details Uses a lock-free queue to accept log messages from multiple threads and a dedicated writer thread to
     *          perform batched file writes. This significantly reduces latency on the producer side. The configuration
     *          type (AsyncLoggerConfig) lives in async_logger_config.hpp; the queue, string pool, and per-message
     *          record (DynamicMPMCQueue / StringPool / LogMessage) live in detail/async_logger_internal.hpp.
     * @note Uses shared_ptr<WinFileStream> to safely handle Logger reconfiguration during runtime.
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
        explicit AsyncLogger(const AsyncLoggerConfig &config, std::shared_ptr<WinFileStream> file_stream,
                             std::shared_ptr<std::mutex> log_mutex);

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
         * @details Sets m_shutdown_requested, joins the writer thread, then drains any messages that arrived between
         *          the stop signal and thread exit.
         * @note A producer that already passed the m_shutdown_requested check but has not yet completed try_push() can
         *       enqueue at most one message after the final drain. This is an accepted trade-off to avoid adding atomic
         *       overhead (producers_in_flight counter) to every enqueue() call.
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
        void writer_thread_func() noexcept;

        /**
         * @brief Drains any messages remaining in the queue after the writer thread exits.
         * @details Called during shutdown to flush late-enqueued messages that arrived between m_running=false and the
         *          writer thread observing an empty queue. No external lock is required; the writer thread has already
         *          been joined.
         */
        void drain_remaining() noexcept;

        void write_batch(std::span<detail::LogMessage> messages) noexcept;

        bool handle_overflow(detail::LogMessage &&message) noexcept;

        /**
         * @brief Wakes the writer thread if it is parked on m_flush_cv after a successful push.
         * @details A successful producer has already made m_pending_messages non-zero before publishing
         *          a new queue slot, or preserved it while replacing an old slot. The writer publishes
         *          m_writer_waiting before checking that same pending count and blocking. Those seq_cst
         *          operations form a store/load handshake: if the writer misses the pending state, the
         *          producer observes m_writer_waiting and notifies under m_flush_mutex; if the producer
         *          observes false, the writer's pending-count predicate sees the work and does not block.
         *          notify_all (not notify_one) is used so a flusher waiting on the same condition variable
         *          cannot absorb the notification and leave the writer asleep. When the writer is
         *          draining, this is a seq_cst flag load with no mutex or syscall.
         */
        void notify_writer() noexcept;

        detail::DynamicMPMCQueue m_queue;
        AsyncLoggerConfig m_config;

        std::shared_ptr<WinFileStream> m_file_stream;
        std::shared_ptr<std::mutex> m_log_mutex;

        std::jthread m_writer_thread;
        std::atomic<bool> m_running{false};
        std::atomic<bool> m_shutdown_requested{false};

        std::mutex m_flush_mutex;
        std::condition_variable m_flush_cv;

        // Set true by the writer immediately before it parks on m_flush_cv and cleared when it wakes.
        // Producers read it outside m_flush_mutex after a successful queue push; the seq_cst order shared
        // with m_pending_messages makes a racing push either visible to the writer's wait predicate or
        // visible here as a parked-writer wake.
        std::atomic<bool> m_writer_waiting{false};

        std::atomic<size_t> m_pending_messages{0};
        std::atomic<size_t> m_dropped_messages{0};
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_ASYNC_LOGGER_HPP
