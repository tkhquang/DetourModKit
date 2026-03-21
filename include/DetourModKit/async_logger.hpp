#ifndef ASYNC_LOGGER_HPP
#define ASYNC_LOGGER_HPP

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
    inline constexpr size_t MAX_MESSAGE_SIZE = 16777216;
    inline constexpr size_t DEFAULT_SPIN_BACKOFF_ITERATIONS = 32;
    inline constexpr auto DEFAULT_FLUSH_TIMEOUT = std::chrono::milliseconds(500);
    inline constexpr size_t MEMORY_POOL_BLOCK_SIZE = 4096;
    inline constexpr size_t MEMORY_POOL_BLOCK_COUNT = 64;
    inline constexpr size_t POOL_SLOTS_PER_BLOCK = 16;

    enum class OverflowPolicy
    {
        DropNewest,
        DropOldest,
        Block,
        SyncFallback
    };

    /**
     * @class StringPool
     * @brief Memory pool for small string allocations to reduce heap fragmentation.
     * @details Uses a free-list approach for O(1) allocation/deallocation.
     *          Blocks are allocated on-demand up to MEMORY_POOL_BLOCK_COUNT.
     *          Each block is cache-line aligned to prevent false sharing.
     */
    class StringPool
    {
    public:
        static StringPool &instance() noexcept;

        [[nodiscard]] std::string *allocate(size_t size);
        void deallocate(std::string *ptr) noexcept;

        StringPool(const StringPool &) = delete;
        StringPool &operator=(const StringPool &) = delete;
        StringPool(StringPool &&) = delete;
        StringPool &operator=(StringPool &&) = delete;

    private:
        struct PoolSlot
        {
            std::string str;
            PoolSlot *next_free{nullptr};
        };

        struct Block
        {
            alignas(64) char data[POOL_SLOTS_PER_BLOCK * sizeof(PoolSlot)];
            Block *next{nullptr};
            PoolSlot *free_list{nullptr};
            size_t slot_count{0};
            uint32_t constructed_mask{0};

            PoolSlot *get_slot(size_t index) noexcept
            {
                return reinterpret_cast<PoolSlot *>(data) + index;
            }
        };

        StringPool();
        ~StringPool() noexcept;

        void grow_pool();
        PoolSlot *claim_free_slot() noexcept;
        void release_slot(PoolSlot *slot) noexcept;

        alignas(64) std::atomic<Block *> head_{nullptr};
        std::atomic<size_t> pool_size_{0};
        std::mutex pool_mutex_;
    };

    /**
     * @struct LogMessage
     * @brief A log entry with inline buffer optimization and overflow handling.
     * @details Messages <= 256 bytes are stored inline. Larger messages use
     *          heap allocation via StringPool.
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

        std::string *overflow{nullptr};

        LogMessage(LogLevel lvl, std::string msg);
        LogMessage() noexcept = default;

        ~LogMessage();

        LogMessage(LogMessage &&other) noexcept;
        LogMessage &operator=(LogMessage &&other) noexcept;

        LogMessage(const LogMessage &) = delete;
        LogMessage &operator=(const LogMessage &) = delete;

        [[nodiscard]] std::string_view message() const noexcept;
        [[nodiscard]] bool is_valid() const noexcept;
        void reset() noexcept;
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

            Slot() noexcept : sequence(0) {}

            Slot(const Slot &) = delete;
            Slot &operator=(const Slot &) = delete;

            // Move operations are safe because:
            // 1. Only the single writer thread calls try_pop (consumer)
            // 2. try_push only moves INTO empty slots (enqueue_pos slots)
            // 3. No concurrent moves can occur on the same slot
            Slot(Slot &&other) noexcept
                : sequence(other.sequence.load(std::memory_order_relaxed)), data(std::move(other.data))
            {
            }

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
     * @brief Configuration for the async logger.
     */
    struct AsyncLoggerConfig
    {
        size_t queue_capacity = DEFAULT_QUEUE_CAPACITY;
        size_t batch_size = DEFAULT_BATCH_SIZE;
        std::chrono::milliseconds flush_interval = DEFAULT_FLUSH_INTERVAL;
        OverflowPolicy overflow_policy = OverflowPolicy::DropOldest;
        size_t spin_backoff_iterations = DEFAULT_SPIN_BACKOFF_ITERATIONS;
        std::chrono::milliseconds block_timeout_ms{16};
        size_t block_max_spin_iterations{1000};

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
            if (block_timeout_ms.count() <= 0)
                return false;
            if (block_max_spin_iterations == 0)
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
         * @return true if the message was successfully enqueued or written, false if dropped or timed out.
         * @details This method is non-blocking (unless OverflowPolicy::Block is used).
         *          The message will be written to the log file by the writer thread.
         */
        [[nodiscard]] bool enqueue(LogLevel level, std::string message) noexcept;

        /**
         * @brief Flushes all pending log messages with a timeout.
         * @param timeout Maximum time to wait for flush to complete.
         * @return true if all messages were flushed, false if timeout occurred.
         */
        [[nodiscard]] bool flush_with_timeout(std::chrono::milliseconds timeout) noexcept;

        /**
         * @brief Flushes all pending log messages.
         * @details Waits up to 500ms for all queued messages to be written.
         *          Uses a timeout to prevent indefinite blocking.
         */
        void flush() noexcept;

        void shutdown() noexcept;

        [[nodiscard]] bool is_running() const noexcept;

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
        std::atomic<size_t> dropped_messages_{0};
    };

} // namespace DetourModKit

#endif // ASYNC_LOGGER_HPP
