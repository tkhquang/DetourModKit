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
    inline constexpr size_t MAX_MESSAGE_SIZE = 16777216; // 16MB max message size to prevent abuse
    inline constexpr size_t DEFAULT_SPIN_BACKOFF_ITERATIONS = 32;

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

        static constexpr size_t MAX_INLINE_SIZE = 256;
        static constexpr size_t MAX_VALID_LENGTH = MAX_MESSAGE_SIZE;
        std::array<char, MAX_INLINE_SIZE> buffer{};
        size_t length{0};

        std::unique_ptr<std::string> overflow;

        LogMessage(LogLevel lvl, std::string msg) noexcept;

        LogMessage() noexcept = default;
        LogMessage(LogMessage &&other) noexcept = default;
        LogMessage &operator=(LogMessage &&other) noexcept = default;
        LogMessage(const LogMessage &) = delete;
        LogMessage &operator=(const LogMessage &) = delete;

        [[nodiscard]] std::string_view message() const noexcept;
        [[nodiscard]] bool is_valid() const noexcept;
    };

    /**
     * @class DynamicMPMCQueue
     * @brief A dynamically-sized, bounded Multi-Producer Multi-Consumer queue.
     * @details Uses a ring buffer with atomic sequence numbers for lock-free
     *          synchronization. Capacity is determined at construction time.
     * @note This queue is designed to be constructed once and never resized.
     *       Moving slots after construction is not supported and will cause data corruption.
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

        /**
         * @brief Attempts to pop multiple items up to a maximum count.
         * @param items Reference to a vector to store popped items.
         * @param max_count Maximum number of items to pop.
         * @return size_t Number of items actually popped.
         */
        size_t try_pop_batch(std::vector<LogMessage> &items, size_t max_count);

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

            Slot(Slot &&other) noexcept : sequence(other.sequence.load(std::memory_order_relaxed)), data(std::move(other.data)) {}

            Slot &operator=(Slot &&other) noexcept
            {
                if (this != &other)
                {
                    sequence.store(other.sequence.load(std::memory_order_relaxed), std::memory_order_relaxed);
                    data = std::move(other.data);
                }
                return *this;
            }
        };

        // Read-only after construction
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
        size_t queue_capacity = DEFAULT_QUEUE_CAPACITY;
        size_t batch_size = DEFAULT_BATCH_SIZE;
        std::chrono::milliseconds flush_interval = DEFAULT_FLUSH_INTERVAL;
        OverflowPolicy overflow_policy = OverflowPolicy::DropOldest;
        size_t spin_backoff_iterations = DEFAULT_SPIN_BACKOFF_ITERATIONS;

        [[nodiscard]] constexpr bool validate() const noexcept
        {
            if (queue_capacity == 0 || (queue_capacity & (queue_capacity - 1)) != 0)
                return false;
            if (batch_size == 0)
                return false;
            if (flush_interval.count() <= 0)
                return false;
            if (spin_backoff_iterations == 0)
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
     * @note Uses shared_ptr<ofstream> to safely handle Logger reconfiguration during runtime.
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
        explicit AsyncLogger(const AsyncLoggerConfig &config,
                             std::shared_ptr<std::ofstream> file_stream,
                             std::shared_ptr<std::mutex> log_mutex);

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
        void enqueue(LogLevel level, std::string message) noexcept;

        void flush() noexcept;

        void shutdown() noexcept;

        [[nodiscard]] bool is_running() const noexcept;

        [[nodiscard]] size_t queue_size() const noexcept;

    private:
        void writer_thread_func() noexcept;

        void write_batch(std::span<LogMessage> messages) noexcept;

        bool handle_overflow(LogMessage &&message) noexcept;

        DynamicMPMCQueue queue_;
        AsyncLoggerConfig config_;

        std::shared_ptr<std::ofstream> file_stream_;
        std::shared_ptr<std::mutex> log_mutex_;

        std::jthread writer_thread_;
        std::atomic<bool> running_{false};
        std::atomic<bool> shutdown_requested_{false};

        std::mutex flush_mutex_;
        std::condition_variable flush_cv_;
        std::atomic<size_t> pending_messages_{0};
    };

} // namespace DetourModKit

#endif // ASYNC_LOGGER_HPP
