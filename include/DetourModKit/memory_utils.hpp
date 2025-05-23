#ifndef MEMORY_UTILS_HPP
#define MEMORY_UTILS_HPP

#include <string>
#include <cstdint>
#include <cstddef>

// Forward declaration for Logger, if its types are used in function signatures.
class Logger;

/**
 * @brief Initializes the memory region cache with specified parameters.
 * @details Sets up an internal cache to store information about memory regions,
 *          aiming to reduce the overhead of frequent `VirtualQuery` system calls.
 *          This function is thread-safe and uses `std::call_once` to ensure
 *          initialization happens only once, even if called multiple times.
 * @param cache_size The desired number of entries in the cache. If 0 is passed,
 *                   a minimum default (e.g., 1) will be used. Defaults to 32.
 * @param expiry_ms The duration in milliseconds after which a cached entry
 *                  is considered stale and will trigger a fresh query.
 *                  Defaults to 5000ms (5 seconds).
 */
void initMemoryCache(size_t cache_size = 32, unsigned int expiry_ms = 5000);

/**
 * @brief Clears all entries from the memory region cache.
 * @details Invalidates all currently cached memory region information, forcing
 *          subsequent memory checks to perform fresh system queries.
 *          This function is thread-safe.
 */
void clearMemoryCache();

/**
 * @brief Retrieves statistics about the memory cache usage.
 * @details Returns a string containing information such as cache hits, misses,
 *          and hit rate. This is primarily intended for debugging and performance
 *          tuning. Statistics are only actively tracked and reported in debug
 *          builds (when `_DEBUG` is defined). In release builds, it will indicate
 *          that stats are unavailable.
 * @return std::string A human-readable string of cache statistics or a message
 *         indicating unavailability in release builds.
 */
std::string getMemoryCacheStats();

/**
 * @brief Checks if a specified memory region is readable.
 * @details Verifies if the memory range from `address` to `address + size - 1`
 *          has read permissions and is committed (MEM_COMMIT). It utilizes an
 *          internal cache (if initialized) to optimize repeated queries for the
 *          same or overlapping memory regions.
 * @param address Starting address (const volatile void*) of the memory region.
 *                This is kept as void* for compatibility with Windows API expectations.
 * @param size Number of bytes in the memory region to check. Must be greater than 0.
 * @return `true` if the entire region is readable, `false` otherwise.
 */
bool isMemoryReadable(const volatile void *address, size_t size);

/**
 * @brief Checks if a specified memory region is writable.
 * @details Verifies if the memory range from `address` to `address + size - 1`
 *          has write permissions and is committed (MEM_COMMIT). It also uses the
 *          internal cache for optimization.
 * @param address Starting address (volatile void*) of the memory region.
 * @param size Number of bytes in the memory region to check. Must be greater than 0.
 * @return `true` if the entire region is writable, `false` otherwise.
 */
bool isMemoryWritable(volatile void *address, size_t size);

/**
 * @brief Writes a sequence of bytes to a target memory address.
 * @details This function handles changing memory protection to allow writing
 *          (PAGE_EXECUTE_READWRITE), performs the memory copy, and then attempts
 *          to restore the original memory protection. It also flushes the
 *          instruction cache for the modified region.
 * @param targetAddress Destination memory address where bytes will be written.
 *                      This will be a pointer to std::byte.
 * @param sourceBytes Pointer to the source buffer containing the std::byte data to write.
 * @param numBytes Number of bytes to write from `sourceBytes` to `targetAddress`.
 * @param logger Reference to a Logger instance for reporting errors or warnings.
 * @return `true` if the write operation succeeds, `false` otherwise.
 */
bool WriteBytes(std::byte *targetAddress, const std::byte *sourceBytes, size_t numBytes, Logger &logger);

#endif // MEMORY_UTILS_HPP
