#ifndef MEMORY_UTILS_HPP
#define MEMORY_UTILS_HPP

#include <string>
#include <cstdint>
#include <cstddef>

namespace DetourModKit
{
    class Logger;

    namespace Memory
    {
        /**
         * @brief Initializes the memory region cache with specified parameters.
         * @details Sets up an internal cache to store information about memory regions,
         *          reducing overhead of frequent VirtualQuery system calls.
         * @param cache_size The desired number of entries in the cache. Defaults to 32.
         * @param expiry_ms Cache entry expiry time in milliseconds. Defaults to 5000ms.
         */
        void initMemoryCache(size_t cache_size = 32, unsigned int expiry_ms = 5000);

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
        bool isMemoryReadable(const volatile void *address, size_t size);

        /**
         * @brief Checks if a specified memory region is writable.
         * @details Verifies if the memory range has write permissions and is committed.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return true if the entire region is writable, false otherwise.
         */
        bool isMemoryWritable(volatile void *address, size_t size);

        /**
         * @brief Writes a sequence of bytes to a target memory address.
         * @details Handles changing memory protection, performs the write operation,
         *          and restores original protection. Also flushes instruction cache.
         * @param targetAddress Destination memory address.
         * @param sourceBytes Pointer to the source buffer containing data to write.
         * @param numBytes Number of bytes to write.
         * @param logger Reference to a Logger instance for error reporting.
         * @return true if the write operation succeeds, false otherwise.
         */
        bool WriteBytes(std::byte *targetAddress, const std::byte *sourceBytes, size_t numBytes, Logger &logger);
    } // namespace Memory
} // namespace DetourModKit

#endif // MEMORY_UTILS_HPP
