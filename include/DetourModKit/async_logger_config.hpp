#ifndef DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP
#define DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP

/**
 * @file async_logger_config.hpp
 * @brief Async-logger configuration types and their defaults.
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
    /// Default capacity, in slots, of the bounded MPMC record queue.
    inline constexpr std::size_t DEFAULT_QUEUE_CAPACITY = 8192;
    /// Default number of records that the writer drains per write batch.
    inline constexpr std::size_t DEFAULT_BATCH_SIZE = 64;
    /// Default interval between periodic writer flushes.
    inline constexpr auto DEFAULT_FLUSH_INTERVAL = std::chrono::milliseconds(100);
    /// Default spin-backoff iteration count before a producer yields or parks.
    inline constexpr std::size_t DEFAULT_SPIN_BACKOFF_ITERATIONS = 32;

    /**
     * @brief Defines the action of a producer when the bounded queue is full.
     * @warning On a callback path, use only DropNewest. On that path, keep each record within
     *          @ref LOG_INLINE_MESSAGE_SIZE. Each other policy has the hazard that its enumerator states.
     * @note The drop policies change acceptance, not producer latency.
     */
    enum class OverflowPolicy : std::uint8_t
    {
        /// Drops the new record without a wait.
        DropNewest,
        /** @brief Evicts the oldest record with no queue wait. Eviction of a long record takes the string-pool lock. */
        DropOldest,
        /// Parks the producer until space frees or block_timeout_ms elapses.
        Block,
        /** @brief Writes the record on the producer thread under the sink lock and performs I/O. */
        SyncFallback
    };

    /**
     * @brief Configuration for the async logger.
     * @details Each queue slot embeds a LOG_INLINE_MESSAGE_SIZE inline buffer, so the default queue uses a few MiB.
     *          A longer record uses a bounded overflow string pool, or the heap once the pool is full or the record
     *          exceeds the pool's record size. For a small memory budget, shrink queue_capacity.
     */
    struct AsyncLoggerConfig
    {
        std::size_t queue_capacity = DEFAULT_QUEUE_CAPACITY;
        /// Number of records that the writer drains per write batch. The writer clamps it to @ref queue_capacity.
        std::size_t batch_size = DEFAULT_BATCH_SIZE;
        std::chrono::milliseconds flush_interval = DEFAULT_FLUSH_INTERVAL;
        OverflowPolicy overflow_policy = OverflowPolicy::DropOldest;
        std::size_t spin_backoff_iterations = DEFAULT_SPIN_BACKOFF_ITERATIONS;
        std::chrono::milliseconds block_timeout_ms{16};
        std::size_t block_max_spin_iterations{1000};
        /**
         * @brief strftime-style timestamp format of the async sink. Empty selects @ref DEFAULT_ASYNC_TIMESTAMP_FORMAT.
         * @details The empty default does not allocate. Logger::enable_async_mode ignores this field.
         */
        std::string timestamp_format{};

        /** @brief Returns true if queue_capacity is a power of two above 1 and each duration or count is positive. */
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

    static_assert(
        DEFAULT_QUEUE_CAPACITY >= 2 && (DEFAULT_QUEUE_CAPACITY & (DEFAULT_QUEUE_CAPACITY - 1)) == 0,
        "DEFAULT_QUEUE_CAPACITY must be a power of 2 and at least 2"
    );

} // namespace DetourModKit

#endif // DETOURMODKIT_ASYNC_LOGGER_CONFIG_HPP
