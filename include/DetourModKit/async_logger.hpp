#ifndef DETOURMODKIT_ASYNC_LOGGER_HPP
#define DETOURMODKIT_ASYNC_LOGGER_HPP

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
#include <string_view>
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
     *
     * @note The singleton returned by instance() is intentionally leaked to
     *       avoid the static destruction order fiasco with late LogMessage
     *       teardown. Neither Bootstrap::request_shutdown() nor DMK_Shutdown()
     *       reclaim it; the OS releases the memory at process exit. The leak
     *       is bounded to MEMORY_POOL_BLOCK_COUNT blocks of
     *       MEMORY_POOL_BLOCK_SIZE bytes.
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
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
#endif
        static_assert(offsetof(PoolSlot, str) == 0,
                      "PoolSlot::str must be the first member for pointer arithmetic in deallocate()");
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

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

        /// Must be called with pool_mutex_ held.
        void grow_pool_locked();
        PoolSlot *claim_free_slot() noexcept;
        void return_slot_locked(PoolSlot *slot, Block *block) noexcept;

        std::atomic<Block *> head_{nullptr};
        std::atomic<size_t> pool_size_{0};
        std::atomic<size_t> heap_fallback_count_{0};
        std::mutex pool_mutex_;
    };

    /**
     * @struct LogMessage
     * @brief A log entry with inline buffer optimization and overflow handling.
     * @details Messages <= 512 bytes are stored inline. Larger messages use
     *          heap allocation via StringPool.
     */
    struct LogMessage
    {
        LogLevel level;
        std::chrono::system_clock::time_point timestamp;
        std::thread::id thread_id;

        static constexpr size_t MAX_INLINE_SIZE = 512;
        static constexpr size_t MAX_VALID_LENGTH = MAX_MESSAGE_SIZE;
        std::array<char, MAX_INLINE_SIZE> buffer;
        size_t length{0};

        // Owned: allocated by StringPool, freed by reset().
        std::string *overflow{nullptr};

        LogMessage(LogLevel lvl, std::string_view msg);
        LogMessage() noexcept = default;

        ~LogMessage() noexcept;

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
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4324) // structure was padded due to alignment specifier
#endif

    class DynamicMPMCQueue
    {
    public:
        /**
         * @brief Constructs a queue with the specified capacity.
         * @param capacity The maximum number of elements (must be power of 2 and >= 2).
         */
        explicit DynamicMPMCQueue(size_t capacity);

        ~DynamicMPMCQueue() = default;

        DynamicMPMCQueue(const DynamicMPMCQueue &) = delete;
        DynamicMPMCQueue &operator=(const DynamicMPMCQueue &) = delete;
        DynamicMPMCQueue(DynamicMPMCQueue &&) = delete;
        DynamicMPMCQueue &operator=(DynamicMPMCQueue &&) = delete;

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
            Slot(Slot &&) = delete;
            Slot &operator=(Slot &&) = delete;
        };

        /// Validates capacity before member initialization to prevent
        /// allocation of an invalid-sized buffer in the initializer list.
        static size_t validated_capacity(size_t capacity);

        // Immutable after construction — never resized.
        const size_t capacity_;
        const size_t mask_;

        // Allocated once in the constructor; the unique_ptr ensures immutability
        // (no accidental resize) while maintaining contiguous cache-friendly layout.
        std::unique_ptr<Slot[]> buffer_;

        // Cache-line aligned to prevent false sharing between producers and consumers.
        alignas(64) std::atomic<size_t> enqueue_pos_{0};
        alignas(64) std::atomic<size_t> dequeue_pos_{0};
    };

#ifdef _MSC_VER
#pragma warning(pop)
#endif

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
            if (queue_capacity < 2 || (queue_capacity & (queue_capacity - 1)) != 0)
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

    // Compile-time validation: Default queue capacity must be a power of 2 and >= 2
    static_assert(DEFAULT_QUEUE_CAPACITY >= 2 && (DEFAULT_QUEUE_CAPACITY & (DEFAULT_QUEUE_CAPACITY - 1)) == 0,
                  "DEFAULT_QUEUE_CAPACITY must be a power of 2 and at least 2");

    /**
     * @class AsyncLogger
     * @brief Asynchronous logger that decouples log production from file I/O.
     * @details Uses a lock-free queue to accept log messages from multiple threads
     *          and a dedicated writer thread to perform batched file writes.
     *          This significantly reduces latency on the producer side.
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
        explicit AsyncLogger(const AsyncLoggerConfig &config,
                             std::shared_ptr<WinFileStream> file_stream,
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
         * @details This method is non-blocking (unless OverflowPolicy::Block is used).
         *          The message will be written to the log file by the writer thread.
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
         * @details Waits up to 500ms for all queued messages to be written.
         *          Uses a timeout to prevent indefinite blocking.
         */
        void flush() noexcept;

        /**
         * @brief Stops the writer thread and drains remaining queued messages.
         * @details Sets shutdown_requested_, joins the writer thread, then drains
         *          any messages that arrived between the stop signal and thread exit.
         * @note A producer that already passed the shutdown_requested_ check but has
         *       not yet completed try_push() can enqueue at most one message after the
         *       final drain. This is an accepted trade-off to avoid adding atomic
         *       overhead (producers_in_flight counter) to every enqueue() call.
         */
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

        /**
         * @brief Drains any messages remaining in the queue after the writer thread exits.
         * @details Called during shutdown to flush late-enqueued messages that arrived
         *          between running_=false and the writer thread observing an empty queue.
         *          No external lock is required; the writer thread has already been joined.
         */
        void drain_remaining() noexcept;

        void write_batch(std::span<LogMessage> messages) noexcept;

        bool handle_overflow(LogMessage &&message) noexcept;

        DynamicMPMCQueue queue_;
        AsyncLoggerConfig config_;

        std::shared_ptr<WinFileStream> file_stream_;
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

#endif // DETOURMODKIT_ASYNC_LOGGER_HPP
