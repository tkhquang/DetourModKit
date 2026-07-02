#ifndef DETOURMODKIT_INTERNAL_ASYNC_LOGGER_QUEUE_HPP
#define DETOURMODKIT_INTERNAL_ASYNC_LOGGER_QUEUE_HPP

/**
 * @file internal/async_logger_queue.hpp
 * @brief True-private async-logger transport: the overflow string pool, the per-message record, and the MPMC queue.
 * @details Houses the overflow string pool (StringPool), the per-message transport record (LogMessage), and the
 *          bounded Vyukov MPMC ring buffer (DynamicMPMCQueue), all in namespace DetourModKit::detail. It is never
 *          installed: AsyncLogger holds these behind its pimpl (see src/async_logger.cpp), so the public
 *          async_logger.hpp names none of them and a consumer compiles without the queue/pool/threading internals on
 *          its include path. Only the AsyncLogger pimpl translation unit and the async-logger white-box tests reach in
 *          here.
 */

#include "DetourModKit/logger.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace DetourModKit::detail
{
    /// Maximum length, in bytes, of a single log message.
    inline constexpr size_t MAX_MESSAGE_SIZE = 16777216;
    /// Byte size of one StringPool overflow block.
    inline constexpr size_t MEMORY_POOL_BLOCK_SIZE = 4096;
    /// Number of overflow blocks the StringPool preallocates.
    inline constexpr size_t MEMORY_POOL_BLOCK_COUNT = 64;
    /// Number of allocation slots carved from each StringPool block.
    inline constexpr size_t POOL_SLOTS_PER_BLOCK = 16;

    /**
     * @class StringPool
     * @brief Memory pool for small string allocations to reduce heap fragmentation.
     * @details Uses a free-list approach for O(1) allocation/deallocation. Blocks are allocated on-demand up to
     *          MEMORY_POOL_BLOCK_COUNT. Each block is cache-line aligned to prevent false sharing.
     *
     * @note The singleton returned by instance() is intentionally leaked to avoid the static destruction order fiasco
     *       with late LogMessage teardown. Neither request_shutdown() nor the Session teardown reclaim it; the OS
     *       releases the memory at process exit. The leak is bounded to MEMORY_POOL_BLOCK_COUNT blocks of
     *       MEMORY_POOL_BLOCK_SIZE bytes.
     */
    class StringPool
    {
    public:
        static StringPool &instance() noexcept;

        [[nodiscard]] std::string *allocate(size_t size) noexcept;
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
            uint32_t constructed_mask{0};
        };

        StringPool() noexcept;
        ~StringPool() noexcept;

        /**
         * @brief Appends one block to the pool. Must be called with m_pool_mutex held.
         * @details No-throw: an allocation failure leaves the pool unchanged so
         *          callers can fall back to a nothrow heap string instead of throwing out of the logging path.
         */
        void grow_pool_locked() noexcept;
        PoolSlot *claim_free_slot() noexcept;
        void return_slot_locked(PoolSlot *slot, Block *block) noexcept;

        std::atomic<Block *> m_head{nullptr};
        std::atomic<size_t> m_heap_fallback_count{0};
        std::mutex m_pool_mutex;
    };

    /**
     * @struct LogMessage
     * @brief A log entry with inline buffer optimization and overflow handling.
     * @details Messages <= 512 bytes are stored inline. Larger messages use heap allocation via StringPool. This is a
     *          move-only transport/value type (copy deleted, move defined) carried by value through the queue; it
     *          keeps plain field names rather than the m_ member prefix, per the POD-struct naming convention, even
     *          though @ref overflow is an owned heap pointer (its lifetime is self-contained, released by reset() and
     *          the destructor), so no class invariant rides on member encapsulation.
     */
    struct LogMessage
    {
        LogLevel level{LogLevel::Info};
        std::chrono::system_clock::time_point timestamp;
        std::thread::id thread_id;

        static constexpr size_t MAX_INLINE_SIZE = LOG_INLINE_MESSAGE_SIZE;
        static constexpr size_t MAX_VALID_LENGTH = MAX_MESSAGE_SIZE;
        // Left uninitialized (raw storage): only [0, length) is ever read, and every constructor/move writes exactly
        // length bytes before any read. Zero-filling the whole inline buffer would memset MAX_INLINE_SIZE bytes on each
        // construction/enqueue for no observable effect.
        std::array<char, MAX_INLINE_SIZE> buffer;
        size_t length{0};

        // Owned: allocated by StringPool, freed by reset().
        std::string *overflow{nullptr};

        LogMessage(LogLevel lvl, std::string_view msg) noexcept;
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
     * @details Uses a ring buffer with atomic sequence numbers for lock-free synchronization. Capacity is determined at
     *          construction time.
     * @note This queue is designed to be constructed once and never resized. Moving slots after construction is not
     *       supported and will cause data corruption.
     */
#ifdef _MSC_VER
#pragma warning(push)
// structure was padded due to alignment specifier
#pragma warning(disable : 4324)
#endif

    class DynamicMPMCQueue
    {
    public:
        /**
         * @brief Constructs a queue with the specified capacity.
         * @param capacity The maximum number of elements (must be power of 2 and >= 2).
         */
        explicit DynamicMPMCQueue(size_t capacity);

        ~DynamicMPMCQueue() noexcept = default;

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
        [[nodiscard]] bool try_push(LogMessage &item);

        /**
         * @brief Attempts to pop an item from the queue.
         * @param item Reference to store the popped item.
         * @return true if successful, false if queue is empty.
         */
        [[nodiscard]] bool try_pop(LogMessage &item);

        /**
         * @brief Attempts to pop multiple items up to a maximum count.
         * @param items Reference to a vector to store popped items.
         * @param max_count Maximum number of items to pop.
         * @return size_t Number of items actually popped.
         * @note noexcept and fail-closed under allocation pressure. It is called from the writer thread's noexcept
         *       frames (writer_thread_func / drain_remaining), so a throwing reserve would be an unrecoverable
         *       std::terminate. Instead it reserves headroom under a local try/catch and, if that allocation fails,
         *       pops only as many items as the vector's existing spare capacity allows -- the LogMessage move is
         *       noexcept, so push_back within capacity never allocates and never throws. Under OOM a smaller batch
         *       (possibly zero) is returned this call; the un-popped items stay queued for the next call.
         */
        [[nodiscard]] size_t try_pop_batch(std::vector<LogMessage> &items, size_t max_count) noexcept;

        /// Returns the approximate number of items in the queue.
        [[nodiscard]] size_t size() const noexcept;

        /// Checks if the queue is approximately empty.
        [[nodiscard]] bool empty() const noexcept;

        /**
         * @brief Returns the capacity of the queue.
         * @return size_t The maximum number of elements.
         */
        [[nodiscard]] size_t capacity() const noexcept { return m_capacity; }

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

        /**
         * @brief Validates capacity before member initialization to prevent allocation of an invalid-sized buffer in
         *        the initializer list.
         */
        static size_t validated_capacity(size_t capacity);

        // Immutable after construction; never resized.
        const size_t m_capacity;
        const size_t m_mask;

        // Allocated once in the constructor; the unique_ptr ensures immutability (no accidental resize) while
        // maintaining contiguous cache-friendly layout.
        std::unique_ptr<Slot[]> m_buffer;

        // Cache-line aligned to prevent false sharing between producers and consumers.
        alignas(64) std::atomic<size_t> m_enqueue_pos{0};
        alignas(64) std::atomic<size_t> m_dequeue_pos{0};
    };

#ifdef _MSC_VER
#pragma warning(pop)
#endif

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_ASYNC_LOGGER_QUEUE_HPP
