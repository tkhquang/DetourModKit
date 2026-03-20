#ifndef MEMORY_HPP
#define MEMORY_HPP

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace DetourModKit
{
    class Logger;

    /**
     * @enum MemoryError
     * @brief Error codes for memory operation failures.
     */
    enum class MemoryError
    {
        NullTargetAddress,
        NullSourceBytes,
        ProtectionChangeFailed,
        ProtectionRestoreFailed
    };

    /**
     * @brief Converts a MemoryError to a human-readable string.
     * @param error The error code.
     * @return A string view describing the error.
     */
    constexpr std::string_view memory_error_to_string(MemoryError error)
    {
        switch (error)
        {
        case MemoryError::NullTargetAddress:
            return "Target address is null";
        case MemoryError::NullSourceBytes:
            return "Source bytes pointer is null";
        case MemoryError::ProtectionChangeFailed:
            return "Failed to change memory protection";
        case MemoryError::ProtectionRestoreFailed:
            return "Failed to restore original memory protection";
        default:
            return "Unknown memory error";
        }
    }

    // Memory cache configuration defaults
    inline constexpr size_t DEFAULT_CACHE_SIZE = 256;
    inline constexpr unsigned int DEFAULT_CACHE_EXPIRY_MS = 50;
    inline constexpr size_t MIN_CACHE_SIZE = 1;
    inline constexpr size_t DEFAULT_CACHE_SHARD_COUNT = 16;
    inline constexpr size_t DEFAULT_MAX_CACHE_SIZE_MULTIPLIER = 2;

    namespace Memory
    {
        /**
         * @brief Initializes the memory region cache with specified parameters.
         * @details Sets up an internal cache to store information about memory regions,
         *          reducing overhead of frequent VirtualQuery system calls.
         * @param cache_size The desired number of entries in the cache. Defaults to 256.
         * @param expiry_ms Cache entry expiry time in milliseconds. Defaults to 50ms.
         * @param shard_count Number of cache shards for concurrent access. Defaults to 16.
         * @return true if this call performed initialization, false if already initialized.
         * @note Only the first call to init_cache has effect; subsequent calls return false.
         * @note Starts a background cleanup thread that runs periodically.
         */
        bool init_cache(size_t cache_size = DEFAULT_CACHE_SIZE,
                        unsigned int expiry_ms = DEFAULT_CACHE_EXPIRY_MS,
                        size_t shard_count = DEFAULT_CACHE_SHARD_COUNT);

        /**
         * @brief Clears all entries from the memory region cache.
         * @details Invalidates all currently cached memory region information.
         *         The background cleanup thread continues running.
         */
        void clear_cache();

        /**
         * @brief Shuts down the memory cache and stops the background cleanup thread.
         * @details Call this before program exit to cleanly terminate the cleanup thread.
         *         After calling shutdown, the cache cannot be reused without re-initialization.
         */
        void shutdown_cache();

        /**
         * @brief Retrieves statistics about the memory cache usage.
         * @details Returns cache hits, misses, and hit rate information.
         *          Statistics are only available in debug builds.
         * @return std::string A human-readable string of cache statistics.
         */
        std::string get_cache_stats();

        /**
         * @brief Invalidates cache entries that overlap with the specified address range.
         * @details Used to force re-query of memory region info after external changes
         *          such as VirtualProtect calls by other code.
         * @param address Starting address of the range to invalidate.
         * @param size Size of the range to invalidate.
         */
        void invalidate_range(const void *address, size_t size);

        /**
         * @brief Checks if a specified memory region is readable.
         * @details Verifies if the memory range has read permissions and is committed.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return true if the entire region is readable, false otherwise.
         */
        bool is_readable(const void *address, size_t size);

        /**
         * @brief Checks if a specified memory region is writable.
         * @details Verifies if the memory range has write permissions and is committed.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return true if the entire region is writable, false otherwise.
         */
        bool is_writable(void *address, size_t size);

        /**
         * @brief Writes a sequence of bytes to a target memory address.
         * @details Handles changing memory protection, performs the write operation,
         *          and restores original protection. Also flushes instruction cache.
         *          Automatically invalidates the affected cache range.
         * @param targetAddress Destination memory address.
         * @param sourceBytes Pointer to the source buffer containing data to write.
         * @param numBytes Number of bytes to write.
         * @param logger Reference to a Logger instance for error reporting.
         * @return std::expected<void, MemoryError> on success, or the specific error on failure.
         */
        [[nodiscard]] std::expected<void, MemoryError> write_bytes(std::byte *targetAddress, const std::byte *sourceBytes, size_t numBytes, Logger &logger);
    } // namespace Memory
} // namespace DetourModKit

#endif // MEMORY_HPP
