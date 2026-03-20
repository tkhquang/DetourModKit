#ifndef ASYNC_LOGGER_HPP
#define ASYNC_LOGGER_HPP

/**
 * @file async_logger.hpp
 * @brief Asynchronous logging system for high-throughput scenarios.
 * @details Provides a lock-free, bounded queue-based async logger that decouples
 *          log message production from file I/O. Designed for minimal latency
 *          on the producer side (calling thread) with batched writes on the
 *          consumer side (writer thread).
 */

#include "DetourModKit/logger.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace DetourModKit
{
    inline constexpr size_t DEFAULT_QUEUE_CAPACITY = 8192;
    inline constexpr size_t DEFAULT_BATCH_SIZE = 64;
    inline constexpr auto DEFAULT_FLUSH_INTERVAL = std::chrono::milliseconds(100);

    /**
     * @enum OverflowPolicy
     * @brief Defines behavior when the async log queue is full.
     */
    enum class OverflowPolicy
    {
        DropNewest,  /**< Discard the incoming message if queue is full. */
        DropOldest,  /**< Discard the oldest message to make room for the new one. */
        Block,       /**< Block the caller until space is available. */
        SyncFallback /**< Write the message synchronously if queue is full. */
    };

    /**
     * @struct LogMessage
     * @brief Represents a single log message in the async queue.
     * @details Uses a fixed-size buffer for small messages to avoid heap allocation
     *          on the hot path. Falls back to heap allocation for larger messages.
     */
    struct LogMessage
    {
        LogLevel level;
        std::chrono::system_clock::time_point timestamp;
        std::thread::id thread_id;

        /// 256 fits typical single-line log messages and keeps LogMessage compact.
        static constexpr size_t MAX_INLINE_SIZE = 256;
        std::array<char, MAX_INLINE_SIZE> buffer{};
        size_t length{0};

        /// Heap-allocated storage for messages exceeding MAX_INLINE_SIZE.
        std::unique_ptr<std::string> overflow;

        /**
         * @brief Constructs a LogMessage from a string.
         * @param lvl The log level.
         * @param msg The message string.
         */
        LogMessage(LogLevel lvl, std::string msg);

        LogMessage() = default;
        LogMessage(LogMessage &&other) noexcept;
        LogMessage &operator=(LogMessage &&other) noexcept;
        LogMessage(const LogMessage &) = delete;
        LogMessage &operator=(const LogMessage &) = delete;

        /// Returns a view into the message content (inline buffer or heap overflow).
        std::string_view message() const;
    };

    /**
     * @class DynamicMPMCQueue
     * @brief A dynamically-sized, bounded Multi-Producer Multi-Consumer queue.
     * @details Uses a ring buffer with atomic sequence numbers for lock-free
     *          synchronization. Capacity is determined at construction time.
     */
    class DynamicMPMCQueue
    {
    public:
        /**
         * @brief Constructs a queue with the specified capacity.
         * @param capacity The maximum number of elements (must be power of 2).
         */
        explicit DynamicMPMCQueue(size_t capacity);

        ~DynamicMPMCQueue() = default;

        DynamicMPMCQueue(const DynamicMPMCQueue &) = delete;
        DynamicMPMCQueue &operator=(const DynamicMPMCQueue &) = delete;

        /**
         * @brief Attempts to push an item into the queue.
         * @param item The item to push. Moved into the queue on success only;
         *             left unchanged on failure so the caller can retry or handle overflow.
         * @return true if successful, false if queue is full.
         */
        bool try_push(LogMessage &item);

        /**
         * @brief Attempts to pop an item from the queue.
         * @param item Reference to store the popped item.
         * @return true if successful, false if queue is empty.
         */
        bool try_pop(LogMessage &item);

        /// Returns the approximate number of items in the queue.
        size_t size() const noexcept;

        /// Checks if the queue is approximately empty.
        bool empty() const noexcept;

        /**
         * @brief Returns the capacity of the queue.
         * @return size_t The maximum number of elements.
         */
        size_t capacity() const noexcept { return capacity_; }

    private:
        struct Slot
        {
            std::atomic<size_t> sequence;
            LogMessage data;

            Slot() : sequence(0) {}

            Slot(const Slot &) = delete;
            Slot &operator=(const Slot &) = delete;

            // WARNING: Move operations are only safe during queue initialization
            // or when the slot is known to be unused (sequence == 0).
            // Moving a slot while another thread accesses it causes data races.
            Slot(Slot &&other) noexcept
                : sequence(other.sequence.load(std::memory_order_relaxed)), data(std::move(other.data))
            {
                // Safety check: only move if slot is empty (sequence == 0)
                // This prevents data races during concurrent access
                assert(sequence.load(std::memory_order_relaxed) == 0 &&
                       "Slot::move called on non-empty slot - potential data race");
            }

            Slot &operator=(Slot &&other) noexcept
            {
                if (this != &other)
                {
                    // Safety check: only move if both slots are empty
                    assert(sequence.load(std::memory_order_relaxed) == 0 &&
                           "Slot::move assignment called on non-empty slot - potential data race");
                    assert(other.sequence.load(std::memory_order_relaxed) == 0 &&
                           "Slot::move assignment from non-empty slot - potential data race");

                    sequence.store(other.sequence.load(std::memory_order_relaxed), std::memory_order_relaxed);
                    data = std::move(other.data);
                }
                return *this;
            }
        };

        // Read-only after construction — grouped before the hot atomics.
        size_t capacity_;
        size_t mask_;
        std::vector<Slot> buffer_;

        // Cache-line aligned to prevent false sharing between producers and consumers.
        alignas(64) std::atomic<size_t> enqueue_pos_{0};
        alignas(64) std::atomic<size_t> dequeue_pos_{0};
    };

    /**
     * @struct AsyncLoggerConfig
     * @brief Configuration for the asynchronous logger.
     */
    struct AsyncLoggerConfig
    {
        size_t queue_capacity = DEFAULT_QUEUE_CAPACITY;           ///< Must be power of 2.
        size_t batch_size = DEFAULT_BATCH_SIZE;                    ///< Messages per batch write.
        std::chrono::milliseconds flush_interval = DEFAULT_FLUSH_INTERVAL;
        OverflowPolicy overflow_policy = OverflowPolicy::DropOldest;

        /**
         * @brief Validates the configuration parameters.
         * @return true if configuration is valid, false otherwise.
         */
        bool validate() const
        {
            if (queue_capacity == 0 || (queue_capacity & (queue_capacity - 1)) != 0)
                return false;
            if (batch_size == 0)
                return false;
            if (flush_interval.count() <= 0)
                return false;
            return true;
        }
    };

    // Compile-time validation: Default queue capacity must be power of 2
    static_assert((DEFAULT_QUEUE_CAPACITY & (DEFAULT_QUEUE_CAPACITY - 1)) == 0,
                  "DEFAULT_QUEUE_CAPACITY must be a power of 2");

    /**
     * @class AsyncLogger
     * @brief Asynchronous logger that decouples log production from file I/O.
     * @details Uses a lock-free queue to accept log messages from multiple threads
     *          and a dedicated writer thread to perform batched file writes.
     *          This significantly reduces latency on the producer side.
     */
    class AsyncLogger
    {
    public:
        /**
         * @brief Constructs an AsyncLogger with the given configuration.
         * @param config The async logger configuration.
         * @param file_stream Reference to the output file stream.
         * @param log_mutex Reference to the mutex protecting the file stream.
         */
        explicit AsyncLogger(const AsyncLoggerConfig &config,
                             std::ofstream &file_stream,
                             std::mutex &log_mutex);

        ~AsyncLogger();

        AsyncLogger(const AsyncLogger &) = delete;
        AsyncLogger &operator=(const AsyncLogger &) = delete;
        AsyncLogger(AsyncLogger &&) = delete;
        AsyncLogger &operator=(AsyncLogger &&) = delete;

        /**
         * @brief Enqueues a log message for asynchronous writing.
         * @param level The log level.
         * @param message The message string.
         * @details This method is non-blocking (unless OverflowPolicy::Block is used).
         *          The message will be written to the log file by the writer thread.
         */
        void enqueue(LogLevel level, std::string message);

        /**
         * @brief Flushes all pending messages to the log file.
         * @details Blocks until all queued messages have been written.
         */
        void flush();

        /**
         * @brief Initiates graceful shutdown of the writer thread.
         * @details Flushes all remaining messages before stopping.
         */
        void shutdown();

        /**
         * @brief Checks if the async logger is running.
         * @return true if running, false if shutdown.
         */
        bool is_running() const;

        /**
         * @brief Returns the current queue size.
         * @return size_t Number of messages in the queue.
         */
        size_t queue_size() const;

    private:
        /**
         * @brief The writer thread function.
         * @details Continuously dequeues messages and writes them in batches.
         */
        void writer_thread_func();

        /**
         * @brief Writes a batch of messages to the log file.
         * @param messages Span of messages to write.
         */
        void write_batch(std::span<LogMessage> messages);

        /**
         * @brief Handles queue overflow based on the configured policy.
         * @param message The message that couldn't be enqueued.
         * @return true if the message was handled, false if dropped.
         */
        bool handle_overflow(LogMessage &&message);

        DynamicMPMCQueue queue_;
        AsyncLoggerConfig config_;

        std::ofstream &file_stream_;
        std::mutex &log_mutex_;

        std::jthread writer_thread_;
        std::atomic<bool> running_{false};
        std::atomic<bool> shutdown_requested_{false};

        std::mutex flush_mutex_;
        std::condition_variable flush_cv_;
        std::atomic<size_t> pending_messages_{0};
    };

} // namespace DetourModKit

#endif // ASYNC_LOGGER_HPP
