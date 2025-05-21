#ifndef MEMORY_UTILS_H
#define MEMORY_UTILS_H

#include <windows.h>
// Note: <array>, <mutex>, <chrono>, <atomic> for internal cache implementation are now only in .cpp
#include <string>
#include <cstdint>
#include "logger.hpp" // Forward declaration or include might be needed if Logger types used in public API

/**
 * @struct CachedMemoryRegionInfo
 * @brief Structure to hold cached memory region information.
 * @details Internal structure for the memory_utils implementation.
 */
struct CachedMemoryRegionInfo // This struct definition can stay if needed for external understanding, or be moved to .cpp
{
    uintptr_t baseAddress;
    size_t regionSize;
    DWORD protection;
    std::chrono::steady_clock::time_point timestamp; // Keep this visible for understanding cache behavior
    bool valid;

    CachedMemoryRegionInfo()
        : baseAddress(0), regionSize(0), protection(0), valid(false) {}
};

/**
 * @brief Initializes the memory region cache.
 * @details Sets up the internal cache to store memory region information,
 *          reducing redundant system calls to VirtualQuery.
 *          This function is thread-safe and should be called once during
 *          program initialization.
 * @param cache_size The number of entries to allocate for the cache.
 *                   Defaults to 32.
 * @param expiry_ms The duration in milliseconds after which a cache entry
 *                  is considered stale and will be re-queried.
 *                  Defaults to 5000ms (5 seconds).
 */
void initMemoryCache(size_t cache_size = 32, unsigned int expiry_ms = 5000);

/**
 * @brief Clears the memory region cache.
 * @details Invalidates all entries in the internal cache. This forces fresh
 *          memory queries on subsequent access checks.
 *          This function is thread-safe.
 */
void clearMemoryCache();

/**
 * @brief Retrieves memory cache usage statistics.
 * @details Returns a string detailing cache hit/miss counts and hit rate.
 *          This function is primarily for debugging and performance tuning.
 *          Statistics are only tracked in debug builds (_DEBUG preprocessor macro).
 * @return std::string A human-readable string of cache statistics.
 */
std::string getMemoryCacheStats();

/**
 * @brief Checks if a memory region is readable.
 * @details Verifies if the specified memory range (from address to address + size - 1)
 *          has read permissions and is committed. Utilizes an internal cache
 *          to optimize repeated queries for the same memory regions.
 * @param address Starting address of the memory region to check.
 * @param size Number of bytes in the memory region to verify.
 * @return True if the entire region is readable, false otherwise (e.g., null address,
 *         zero size, no read permission, not committed).
 */
bool isMemoryReadable(const volatile void *address, size_t size);

/**
 * @brief Checks if a memory region is writable.
 * @details Verifies if the specified memory range (from address to address + size - 1)
 *          has write permissions and is committed. Utilizes an internal cache
 *          to optimize repeated queries for the same memory regions.
 * @param address Starting address of the memory region to check.
 * @param size Number of bytes in the memory region to verify.
 * @return True if the entire region is writable, false otherwise (e.g., null address,
 *         zero size, no write permission, not committed).
 */
bool isMemoryWritable(volatile void *address, size_t size);

/**
 * @brief Writes bytes to a target memory address, handling memory protection.
 * @details This function attempts to change the memory protection of the target
 *          region to PAGE_EXECUTE_READWRITE, performs the memory copy, and then
 *          restores the original memory protection. It also flushes the
 *          instruction cache for the modified region.
 * @param targetAddress Destination memory address where bytes will be written.
 * @param sourceBytes Pointer to the source data to be written.
 * @param numBytes Number of bytes to write from sourceBytes to targetAddress.
 * @param logger Reference to a Logger instance for reporting errors or warnings.
 * @return True if the write operation (including protection changes and cache flush)
 *         succeeds, false if any step fails.
 */
bool WriteBytes(BYTE *targetAddress, const BYTE *sourceBytes, size_t numBytes, Logger &logger);

#endif // MEMORY_UTILS_H
