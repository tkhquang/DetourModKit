#ifndef DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP
#define DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP

/**
 * @file async_logger_config.hpp
 * @brief Lightweight, public async-logger configuration surface.
 * @details Carries only the control-plane configuration types plus their default constants, and none of the
 *          async-logger plumbing, so ModInfo can embed an AsyncLoggerConfig by value without forcing every consumer
 *          translation unit to compile the queue and pool.
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace DetourModKit
{
    /// Default strftime-style timestamp format for the async sink.
    inline constexpr std::string_view DEFAULT_ASYNC_TIMESTAMP_FORMAT{"%Y-%m-%d %H:%M:%S"};
    /// Default capacity (slot count) of the bounded MPMC message queue.
    inline constexpr std::size_t DEFAULT_QUEUE_CAPACITY = 8192;
    /// Default number of messages the writer drains per write batch.
    inline constexpr std::size_t DEFAULT_BATCH_SIZE = 64;
    /// Default interval between periodic writer flushes.
    inline constexpr auto DEFAULT_FLUSH_INTERVAL = std::chrono::milliseconds(100);
    /// Default spin-backoff iteration count before a producer yields/parks.
    inline constexpr std::size_t DEFAULT_SPIN_BACKOFF_ITERATIONS = 32;

    /**
     * @enum OverflowPolicy
     * @brief Defines the action that AsyncLogger::enqueue takes when the bounded queue is full.
     * @warning On a callback path, use only DropNewest. For callback-safe use, keep the new record within
     *          @ref LOG_INLINE_MESSAGE_SIZE. The other policies have these hazards:
     *          - DropOldest can take the string-pool lock when it evicts an older long record.
     *          - Block parks the producer.
     *          - SyncFallback writes synchronously.
     * @note The drop policies change acceptance, not producer latency. Under a saturating burst, DropNewest
     *       accepted under 3 percent of the records and DropOldest accepted almost all, at the same p50
     *       (`docs/analysis/hot_path_bench_v4/`).
     */
    enum class OverflowPolicy : std::uint8_t
    {
        /// Drops the new message when the queue is full and performs no wait at the overflow step.
        DropNewest,
        /**
         * @brief Evicts the oldest queued message and performs no queue-capacity wait.
         * @note The eviction can take the string-pool lock when the old record exceeds the inline bound.
         */
        DropOldest,
        /// Parks the producer until space frees or block_timeout_ms elapses and can stall the caller.
        Block,
        /**
         * @brief Applies the synchronous fallback policy.
         * @details The policy has these effects:
         *          - It writes on the producer thread.
         *          - It takes the sink lock.
         *          - It performs I/O.
         */
        SyncFallback
    };

    /**
     * @struct AsyncLoggerConfig
     * @brief Configuration for the async logger.
     * @details The default queue holds DEFAULT_QUEUE_CAPACITY (8192) slots; each slot embeds a LogMessage with a
     *          LOG_INLINE_MESSAGE_SIZE (512) byte inline buffer, so the ring buffer's resident footprint is on the
     *          order of a few MiB at the default capacity (queue_capacity must stay a power of two). The overflow
     *          string pool (for messages larger than the inline buffer) is a separate, lazily grown allocation behind
     *          the AsyncLogger pimpl (detail::StringPool). Shrink queue_capacity for memory-constrained hosts.
     */
    struct AsyncLoggerConfig
    {
        std::size_t queue_capacity = DEFAULT_QUEUE_CAPACITY;
        /// Records the writer drains per write batch; clamped to @ref queue_capacity, which is all the queue can hold.
        std::size_t batch_size = DEFAULT_BATCH_SIZE;
        std::chrono::milliseconds flush_interval = DEFAULT_FLUSH_INTERVAL;
        OverflowPolicy overflow_policy = OverflowPolicy::DropOldest;
        std::size_t spin_backoff_iterations = DEFAULT_SPIN_BACKOFF_ITERATIONS;
        std::chrono::milliseconds block_timeout_ms{16};
        std::size_t block_max_spin_iterations{1000};
        /**
         * @brief strftime-style date/time format for the async sink; empty selects
         *        @ref DEFAULT_ASYNC_TIMESTAMP_FORMAT.
         * @details The empty default keeps value construction allocation-free. The async writer materializes the
         *          effective format in its owned configuration before starting; Logger::enable_async_mode replaces it
         *          with the Logger's format so both sinks stay identical. The writer appends the millisecond fraction.
         */
        std::string timestamp_format{};

        /**
         * @brief Reports whether every field satisfies its documented bound.
         * @return true when queue_capacity is a power of two of at least 2 and each duration or count is positive.
         */
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

    // Compile-time validation: the default queue capacity must be a power of 2 and at least 2.
    static_assert(
        DEFAULT_QUEUE_CAPACITY >= 2 && (DEFAULT_QUEUE_CAPACITY & (DEFAULT_QUEUE_CAPACITY - 1)) == 0,
        "DEFAULT_QUEUE_CAPACITY must be a power of 2 and at least 2"
    );

} // namespace DetourModKit

#endif // DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP
