#ifndef DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP
#define DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP

/**
 * @file async_logger_config.hpp
 * @brief Lightweight, public async-logger configuration surface.
 * @details This header carries only the control-plane configuration types (OverflowPolicy and AsyncLoggerConfig) plus
 *          the default constants the configuration references. It deliberately pulls none of the async-logger plumbing
 *          (no MPMC queue, no string pool, no <atomic> machinery), so a DllMain-entry header such as bootstrap.hpp can
 *          embed an AsyncLoggerConfig by value without forcing every consumer translation unit to compile the queue and
 *          pool. The internal writer header includes this header too, so the public Logger facade and private async
 *          transport share one configuration type.
 */

#include <chrono>
#include <cstddef>
#include <string>

namespace DetourModKit
{
    /// Default capacity (slot count) of the bounded MPMC message queue.
    inline constexpr size_t DEFAULT_QUEUE_CAPACITY = 8192;
    /// Default number of messages the writer drains per write batch.
    inline constexpr size_t DEFAULT_BATCH_SIZE = 64;
    /// Default interval between periodic writer flushes.
    inline constexpr auto DEFAULT_FLUSH_INTERVAL = std::chrono::milliseconds(100);
    /// Default spin-backoff iteration count before a producer yields/parks.
    inline constexpr size_t DEFAULT_SPIN_BACKOFF_ITERATIONS = 32;

    /**
     * @enum OverflowPolicy
     * @brief Action taken by AsyncLogger::enqueue when the bounded queue is full.
     * @warning Only DropNewest and DropOldest are callback-safe. Block parks the producer and SyncFallback writes
     *          synchronously, so neither may be used by a logger that hook or input callbacks emit through; reserve
     *          them for setup/control-plane logging where a brief stall under sink backpressure is acceptable.
     */
    enum class OverflowPolicy
    {
        /// Drop the message being enqueued when the queue is full. Non-blocking and callback-safe.
        DropNewest,
        /// Evict the oldest queued message to make room for the new one. Non-blocking and callback-safe.
        DropOldest,
        /// Park the producer until space frees or block_timeout_ms elapses. Not callback-safe (can stall the caller).
        Block,
        /// Write the message synchronously on the producer thread. Not callback-safe (synchronous sink I/O).
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
        size_t queue_capacity = DEFAULT_QUEUE_CAPACITY;
        size_t batch_size = DEFAULT_BATCH_SIZE;
        std::chrono::milliseconds flush_interval = DEFAULT_FLUSH_INTERVAL;
        OverflowPolicy overflow_policy = OverflowPolicy::DropOldest;
        size_t spin_backoff_iterations = DEFAULT_SPIN_BACKOFF_ITERATIONS;
        std::chrono::milliseconds block_timeout_ms{16};
        size_t block_max_spin_iterations{1000};
        /**
         * @brief strftime-style date/time format for the async sink.
         * @details Kept in sync with the synchronous Logger by Logger::enable_async_mode so both sinks emit identical
         *          timestamps; the trailing ".<ms>" is appended by the writer, not this format.
         */
        std::string timestamp_format{"%Y-%m-%d %H:%M:%S"};

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
    static_assert(DEFAULT_QUEUE_CAPACITY >= 2 && (DEFAULT_QUEUE_CAPACITY & (DEFAULT_QUEUE_CAPACITY - 1)) == 0,
                  "DEFAULT_QUEUE_CAPACITY must be a power of 2 and at least 2");

} // namespace DetourModKit

#endif // DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP
