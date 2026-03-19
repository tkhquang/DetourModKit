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
    // Async logger configuration defaults
    inline constexpr size_t DEFAULT_QUEUE_CAPACITY = 8192;
    inline constexpr size_t DEFAULT_BATCH_SIZE = 64;
    inline constexpr auto DEFAULT_FLUSH_INTERVAL = std::chrono::milliseconds(100);
    inline constexpr size_t MAX_INLINE_MESSAGE_SIZE = 256;

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

        /** @brief Fixed-size buffer for small messages (avoids heap allocation). */
        static constexpr size_t MAX_INLINE_SIZE = 256;
        std::array<char, MAX_INLINE_SIZE> buffer{};
        size_t length{0};

        /** @brief Heap-allocated string for messages exceeding MAX_INLINE_SIZE. */
        std::unique_ptr<std::string> overflow;

        /**
         * @brief Constructs a LogMessage from a string.
         * @param lvl The log level.
         * @param msg The message string.
         */
        LogMessage(LogLevel lvl, std::string msg);

        /** @brief Default constructor. */
        LogMessage() = default;

        /** @brief Move constructor. */
        LogMessage(LogMessage &&other) noexcept;

        /** @brief Move assignment operator. */
        LogMessage &operator=(LogMessage &&other) noexcept;

        /** @brief Deleted copy constructor (non-copyable). */
        LogMessage(const LogMessage &) = delete;

        /** @brief Deleted copy assignment operator (non-copyable). */
        LogMessage &operator=(const LogMessage &) = delete;

        /**
         * @brief Retrieves the message content.
         * @return std::string_view The message content.
         */
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

        /** @brief Deleted copy constructor. */
        DynamicMPMCQueue(const DynamicMPMCQueue &) = delete;

        /** @brief Deleted copy assignment operator. */
        DynamicMPMCQueue &operator=(const DynamicMPMCQueue &) = delete;

        /**
         * @brief Attempts to push an item into the queue.
         * @param item The item to push (moved into the queue).
         * @return true if successful, false if queue is full.
         */
        bool try_push(LogMessage item);

        /**
         * @brief Attempts to pop an item from the queue.
         * @param item Reference to store the popped item.
         * @return true if successful, false if queue is empty.
         */
        bool try_pop(LogMessage &item);

        /**
         * @brief Returns the approximate number of items in the queue.
         * @return size_t Approximate size.
         */
        size_t size() const;

        /**
         * @brief Checks if the queue is empty.
         * @return true if empty, false otherwise.
         */
        bool empty() const;

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

            // Delete copy constructor and copy assignment
            Slot(const Slot &) = delete;
            Slot &operator=(const Slot &) = delete;

            // Allow move constructor and move assignment
            // WARNING: These are only safe to call during queue initialization
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

        size_t capacity_;
        size_t mask_;
        std::vector<Slot> buffer_;

        /** @brief Cache-line aligned to prevent false sharing. */
        alignas(64) std::atomic<size_t> enqueue_pos_{0};
        alignas(64) std::atomic<size_t> dequeue_pos_{0};
    };

    /**
     * @struct AsyncLoggerConfig
     * @brief Configuration for the asynchronous logger.
     */
    struct AsyncLoggerConfig
    {
        /** @brief Queue capacity (must be power of 2). Default: 8192. */
        size_t queue_capacity = DEFAULT_QUEUE_CAPACITY;

        /** @brief Number of messages to batch per write. Default: 64. */
        size_t batch_size = DEFAULT_BATCH_SIZE;

        /** @brief Interval between forced flushes. Default: 100ms. */
        std::chrono::milliseconds flush_interval = DEFAULT_FLUSH_INTERVAL;

        /** @brief Behavior when queue is full. Default: DropOldest. */
        OverflowPolicy overflow_policy = OverflowPolicy::DropOldest;

        /**
         * @brief Validates the configuration parameters.
         * @return true if configuration is valid, false otherwise.
         */
        bool validate() const
        {
            // Queue capacity must be power of 2
            if (queue_capacity == 0 || (queue_capacity & (queue_capacity - 1)) != 0)
            {
                return false;
            }

            // Batch size must be > 0
            if (batch_size == 0)
            {
                return false;
            }

            // Flush interval must be > 0
            if (flush_interval.count() <= 0)
            {
                return false;
            }

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

        /**
         * @brief Destructor. Ensures graceful shutdown and flush.
         */
        ~AsyncLogger();

        /** @brief Deleted copy constructor. */
        AsyncLogger(const AsyncLogger &) = delete;

        /** @brief Deleted copy assignment operator. */
        AsyncLogger &operator=(const AsyncLogger &) = delete;

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
