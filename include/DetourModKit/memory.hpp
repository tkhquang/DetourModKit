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
    constexpr std::string_view memoryErrorToString(MemoryError error)
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
    inline constexpr size_t DEFAULT_CACHE_SIZE = 32;
    inline constexpr unsigned int DEFAULT_CACHE_EXPIRY_MS = 5000;
    inline constexpr size_t MIN_CACHE_SIZE = 1;

    namespace Memory
    {
        /**
         * @brief Initializes the memory region cache with specified parameters.
         * @details Sets up an internal cache to store information about memory regions,
         *          reducing overhead of frequent VirtualQuery system calls.
         * @param cache_size The desired number of entries in the cache. Defaults to 32.
         * @param expiry_ms Cache entry expiry time in milliseconds. Defaults to 5000ms.
         * @return true if this call performed initialization, false if already initialized.
         * @note Only the first call to initMemoryCache has effect; subsequent calls return false.
         */
        bool initMemoryCache(size_t cache_size = DEFAULT_CACHE_SIZE,
                             unsigned int expiry_ms = DEFAULT_CACHE_EXPIRY_MS);

        /**
         * @brief Clears all entries from the memory region cache.
         * @details Invalidates all currently cached memory region information.
         */
        void clearMemoryCache();

        /**
         * @brief Retrieves statistics about the memory cache usage.
         * @details Returns cache hits, misses, and hit rate information.
         *          Statistics are only available in debug builds.
         * @return std::string A human-readable string of cache statistics.
         */
        std::string getMemoryCacheStats();

        /**
         * @brief Checks if a specified memory region is readable.
         * @details Verifies if the memory range has read permissions and is committed.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return true if the entire region is readable, false otherwise.
         */
        bool isMemoryReadable(const void *address, size_t size);

        /**
         * @brief Checks if a specified memory region is writable.
         * @details Verifies if the memory range has write permissions and is committed.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return true if the entire region is writable, false otherwise.
         */
        bool isMemoryWritable(void *address, size_t size);

        /**
         * @brief Writes a sequence of bytes to a target memory address.
         * @details Handles changing memory protection, performs the write operation,
         *          and restores original protection. Also flushes instruction cache.
         * @param targetAddress Destination memory address.
         * @param sourceBytes Pointer to the source buffer containing data to write.
         * @param numBytes Number of bytes to write.
         * @param logger Reference to a Logger instance for error reporting.
         * @return std::expected<void, MemoryError> on success, or the specific error on failure.
         */
        [[nodiscard]] std::expected<void, MemoryError> WriteBytes(std::byte *targetAddress, const std::byte *sourceBytes, size_t numBytes, Logger &logger);
    } // namespace Memory
} // namespace DetourModKit

#endif // MEMORY_HPP
