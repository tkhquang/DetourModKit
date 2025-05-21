/**
 * @file memory_utils.cpp
 * @brief Implementation of memory manipulation and validation utilities.
 *
 * Provides functions for checking memory readability and writability, writing bytes to memory,
 * and managing a memory region cache for performance optimization.
 * The cache mechanism is internal to this translation unit.
 */

#include "memory_utils.hpp"
#include "string_utils.hpp" // For format_address in potential logging
#include "logger.hpp"
#include <windows.h>
#include <vector>
#include <mutex>
#include <chrono>
#include <string>
#include <atomic>
#include <sstream>   // For std::ostringstream in getMemoryCacheStats
#include <iomanip>   // For std::fixed, std::setprecision in getMemoryCacheStats
#include <algorithm> // For std::find_if, std::min_element in cache operations
#include <stdexcept> // For std::bad_alloc if vector resize fails

/**
 * @namespace Anonymous_MemoryUtils
 * @brief Encapsulates internal static variables and helper functions for memory_utils.
 * @details This ensures that cache implementation details do not pollute the global namespace
 *          or other translation units.
 */
namespace
{
    //
    // Internal Cache Implementation Details
    //

    /**
     * @var s_memoryCache
     * @brief File-static vector serving as the memory region cache. Dynamically sized.
     */
    static std::vector<CachedMemoryRegionInfo> s_memoryCache;

    /**
     * @var s_cacheMutex
     * @brief File-static mutex protecting concurrent access to s_memoryCache.
     */
    static std::mutex s_cacheMutex;

    /**
     * @var s_memoryCacheInitFlag
     * @brief File-static flag ensuring one-time initialization of the cache.
     */
    static std::once_flag s_memoryCacheInitFlag;

    /**
     * @var s_cacheSize
     * @brief File-static variable storing the configured cache size.
     */
    static size_t s_cacheSize = 0;

    /**
     * @var s_cacheExpiryMs
     * @brief File-static variable storing the configured cache expiry time in milliseconds.
     */
    static unsigned int s_cacheExpiryMs = 0;

#ifdef _DEBUG
    /**
     * @var s_cacheHits
     * @brief File-static atomic counter for cache hits (Debug builds only).
     */
    static std::atomic<uint64_t> s_cacheHits{0};
    /**
     * @var s_cacheMisses
     * @brief File-static atomic counter for cache misses (Debug builds only).
     */
    static std::atomic<uint64_t> s_cacheMisses{0};
#endif

    /**
     * @brief Internal helper: Finds a cache entry containing the given memory range.
     * @details Iterates through the cache, checks for entry validity (not expired),
     *          and if the requested address range is within a cached region.
     *          Updates the timestamp of a found entry (Least Recently Used strategy part).
     * @param address Start address of the memory range to find.
     * @param size Size of the memory range.
     * @return Pointer to the CachedMemoryRegionInfo entry if found and valid, nullptr otherwise.
     * @note This function assumes s_cacheMutex is ALREADY HELD by the caller.
     */
    CachedMemoryRegionInfo *findCacheEntryInternal(uintptr_t address, size_t size)
    {
        uintptr_t endAddress = address + size;
        if (endAddress < address)
        {
            return nullptr;
        }
        auto now = std::chrono::steady_clock::now();
        for (auto &entry : s_memoryCache)
        {
            if (!entry.valid)
            {
                continue;
            }
            auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - entry.timestamp).count();
            if (age > static_cast<long long>(s_cacheExpiryMs))
            {
                entry.valid = false;
                continue;
            }
            uintptr_t entryEnd = entry.baseAddress + entry.regionSize;
            if (address >= entry.baseAddress && endAddress <= entryEnd)
            {
                entry.timestamp = now;
                return &entry;
            }
        }
        return nullptr;
    }

    /**
     * @brief Internal helper: Adds or updates a cache entry with new region info.
     * @details Finds an invalid entry to overwrite, or if all are valid,
     *          it replaces the oldest entry (Least Recently Used eviction strategy).
     * @param mbi MEMORY_BASIC_INFORMATION structure containing the region data to cache.
     * @note This function assumes s_cacheMutex is ALREADY HELD by the caller.
     */
    void updateCacheEntryInternal(const MEMORY_BASIC_INFORMATION &mbi)
    {
        if (s_memoryCache.empty())
            return; // Should not happen if initialized

        auto now = std::chrono::steady_clock::now();
        auto it = std::find_if(s_memoryCache.begin(), s_memoryCache.end(),
                               [](const CachedMemoryRegionInfo &entry) -> bool
                               { return !entry.valid; });

        if (it == s_memoryCache.end())
        {
            it = std::min_element(s_memoryCache.begin(), s_memoryCache.end(),
                                  [](const CachedMemoryRegionInfo &a, const CachedMemoryRegionInfo &b)
                                  {
                                      return a.timestamp < b.timestamp;
                                  });
        }
        it->baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        it->regionSize = mbi.RegionSize;
        it->protection = mbi.Protect;
        it->timestamp = now;
        it->valid = true;
    }

} // Anonymous namespace

/**
 * Public API functions
 */

void initMemoryCache(size_t cache_size, unsigned int expiry_ms)
{
    std::call_once(s_memoryCacheInitFlag, [cache_size, expiry_ms]()
                   {
        std::lock_guard<std::mutex> lock(s_cacheMutex);

        s_cacheSize = (cache_size == 0) ? 1 : cache_size; // Ensure at least 1 entry if 0 is passed
        s_cacheExpiryMs = expiry_ms;

        try
        {
            s_memoryCache.resize(s_cacheSize); // Resize the vector
        }
        catch (const std::bad_alloc& e)
        {
            // Not much we can do if allocation fails, perhaps log and try a minimal size?
            // For now, let it propagate or log an error and disable cache.
            // Or, more gracefully, try to allocate a smaller default.
            Logger::getInstance().log(LOG_ERROR, "Memory cache allocation failed for size " + std::to_string(s_cacheSize) + ": " + e.what() + ". Attempting minimal cache.");
            try {
                s_cacheSize = 1; // Minimal fallback
                s_memoryCache.resize(s_cacheSize);
            } catch (const std::bad_alloc& e_min) {
                Logger::getInstance().log(LOG_ERROR, "Minimal memory cache allocation also failed: " + std::string(e_min.what()) + ". Cache disabled.");
                s_cacheSize = 0; // Mark cache as unusable
                s_memoryCache.clear();
                // No return here, functions using the cache will check s_memoryCache.empty()
            }
        }


        for (auto& entry : s_memoryCache)
        {
            entry.valid = false;
        }

        if (s_cacheSize > 0) {
            Logger::getInstance().log(LOG_DEBUG, "Memory region cache initialized with " +
                std::to_string(s_cacheSize) + " entries and " +
                std::to_string(s_cacheExpiryMs) + "ms expiry.");
        } });
}

void clearMemoryCache()
{
    std::lock_guard<std::mutex> lock(s_cacheMutex);
    for (auto &entry : s_memoryCache)
    {
        entry.valid = false;
    }
    if (s_cacheSize > 0)
    {
        // Only log if cache was actually supposed to be active
        Logger::getInstance().log(LOG_DEBUG, "Memory region cache cleared.");
    }
}

std::string getMemoryCacheStats()
{
#ifdef _DEBUG
    uint64_t hits = s_cacheHits.load(std::memory_order_relaxed);
    uint64_t misses = s_cacheMisses.load(std::memory_order_relaxed);
    uint64_t total = hits + misses;

    size_t currentSize = 0;
    unsigned int currentExpiry = 0;
    {
        std::lock_guard<std::mutex> lock(s_cacheMutex); // Protect access to s_cacheSize and s_cacheExpiryMs
        currentSize = s_cacheSize;
        currentExpiry = s_cacheExpiryMs;
    }

    std::ostringstream oss;
    oss << "Cache (Size: " << currentSize << ", Expiry: " << currentExpiry << "ms) "
        << "Hits: " << hits << ", Misses: " << misses;
    if (total > 0)
    {
        double hitRate = (static_cast<double>(hits) / static_cast<double>(total)) * 100.0;
        oss << ", Hit Rate: " << std::fixed << std::setprecision(2) << hitRate << "%";
    }
    else
    {
        oss << ", Hit Rate: N/A";
    }
    return oss.str();
#else
    return "Cache statistics not available in release build.";
#endif
}

bool isMemoryReadable(const volatile void *address, size_t size)
{
    if (!address || size == 0)
    {
        return false;
    }
    std::call_once(s_memoryCacheInitFlag, initMemoryCache); // Default params used if consumer doesn't call init

    // If cache failed to initialize (e.g. bad_alloc resulted in s_cacheSize = 0)
    // then we bypass cache logic entirely and go straight to VirtualQuery.
    bool useCache = false;
    { // Minimal scope for mutex
        std::lock_guard<std::mutex> lock(s_cacheMutex);
        useCache = !s_memoryCache.empty(); // Check if cache vector has elements
    }

    if (useCache)
    {
        uintptr_t addrValue = reinterpret_cast<uintptr_t>(address);
        bool cacheHit = false;
        bool isRegionReadable = false;

        {
            std::lock_guard<std::mutex> lock(s_cacheMutex);
            // Ensure s_memoryCache isn't accessed if s_cacheSize is 0 due to alloc failure
            if (!s_memoryCache.empty())
            {
                CachedMemoryRegionInfo *cachedInfo = findCacheEntryInternal(addrValue, size);
                if (cachedInfo)
                {
                    const DWORD READ_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                             PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                    isRegionReadable = ((cachedInfo->protection & READ_FLAGS) != 0) &&
                                       !((cachedInfo->protection & PAGE_NOACCESS) ||
                                         (cachedInfo->protection & PAGE_GUARD));
                    cacheHit = true;
#ifdef _DEBUG
                    s_cacheHits.fetch_add(1, std::memory_order_relaxed);
#endif
                }
            }
        }
        if (cacheHit)
            return isRegionReadable;
#ifdef _DEBUG
        if (!s_memoryCache.empty())
            s_cacheMisses.fetch_add(1, std::memory_order_relaxed);
#endif
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(const_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    const DWORD READ_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                             PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!((mbi.Protect & READ_FLAGS) != 0) || ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)))
        return false;
    uintptr_t start = reinterpret_cast<uintptr_t>(address);
    uintptr_t end = start + size;
    if (end < start)
        return false;
    uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t region_end = region_start + mbi.RegionSize;
    bool result = (start >= region_start && end <= region_end);

    if (result && useCache) // Only update cache if it's active
    {
        std::lock_guard<std::mutex> lock(s_cacheMutex);
        if (!s_memoryCache.empty())
            updateCacheEntryInternal(mbi);
    }
    return result;
}

bool isMemoryWritable(volatile void *address, size_t size)
{
    if (!address || size == 0)
        return false;
    std::call_once(s_memoryCacheInitFlag, initMemoryCache);

    bool useCache = false;
    {
        std::lock_guard<std::mutex> lock(s_cacheMutex);
        useCache = !s_memoryCache.empty();
    }

    if (useCache)
    {
        uintptr_t addrValue = reinterpret_cast<uintptr_t>(address);
        bool cacheHit = false;
        bool isRegionWritable = false;
        {
            std::lock_guard<std::mutex> lock(s_cacheMutex);
            if (!s_memoryCache.empty())
            {
                CachedMemoryRegionInfo *cachedInfo = findCacheEntryInternal(addrValue, size);
                if (cachedInfo)
                {
                    const DWORD WRITE_FLAGS = PAGE_READWRITE | PAGE_WRITECOPY |
                                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                    isRegionWritable = ((cachedInfo->protection & WRITE_FLAGS) != 0) &&
                                       !((cachedInfo->protection & PAGE_NOACCESS) ||
                                         (cachedInfo->protection & PAGE_GUARD));
                    cacheHit = true;
#ifdef _DEBUG
                    s_cacheHits.fetch_add(1, std::memory_order_relaxed);
#endif
                }
            }
        }
        if (cacheHit)
            return isRegionWritable;
#ifdef _DEBUG
        if (!s_memoryCache.empty())
            s_cacheMisses.fetch_add(1, std::memory_order_relaxed);
#endif
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(const_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    const DWORD WRITE_FLAGS = PAGE_READWRITE | PAGE_WRITECOPY |
                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!((mbi.Protect & WRITE_FLAGS) != 0) || ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)))
        return false;
    uintptr_t start = reinterpret_cast<uintptr_t>(address);
    uintptr_t end = start + size;
    if (end < start)
        return false;
    uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t region_end = region_start + mbi.RegionSize;
    bool result = (start >= region_start && end <= region_end);

    if (result && useCache) // Only update cache if it's active
    {
        std::lock_guard<std::mutex> lock(s_cacheMutex);
        if (!s_memoryCache.empty())
            updateCacheEntryInternal(mbi);
    }
    return result;
}

bool WriteBytes(BYTE *targetAddress, const BYTE *sourceBytes, size_t numBytes, Logger &logger)
{
    if (!targetAddress || !sourceBytes || numBytes == 0)
    {
        logger.log(LOG_ERROR, "WriteBytes: Invalid parameters (null address, null source, or zero bytes).");
        return false;
    }

    DWORD oldProtect;
    // Attempt to change protection to allow writing
    if (!VirtualProtect(targetAddress, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        logger.log(LOG_ERROR, "WriteBytes: VirtualProtect (to RWX) failed: " +
                                  std::to_string(GetLastError()) +
                                  " at address " + format_address(reinterpret_cast<uintptr_t>(targetAddress)));
        return false;
    }

    // Perform the memory copy
    // Consider using a try-catch block for SEH if dealing with potentially very unstable memory,
    // though VirtualProtect should guard against most access violations here.
    memcpy(targetAddress, sourceBytes, numBytes);

    // Attempt to restore original protection
    DWORD tempProtectHolder; // Required by VirtualProtect, value not typically used on success
    if (!VirtualProtect(targetAddress, numBytes, oldProtect, &tempProtectHolder))
    {
        // Log as warning because the write succeeded, but protection couldn't be restored.
        logger.log(LOG_WARNING, "WriteBytes: VirtualProtect (restore original) failed: " +
                                    std::to_string(GetLastError()) +
                                    " at address " + format_address(reinterpret_cast<uintptr_t>(targetAddress)) +
                                    ". Original protection: " + format_hex(static_cast<int>(oldProtect)));
        // Continue, as write was successful.
    }

    // Flush instruction cache for the modified region
    if (!FlushInstructionCache(GetCurrentProcess(), targetAddress, numBytes))
    {
        // Log as warning; not all architectures/situations strictly require this,
        // but it's good practice for self-modifying code.
        logger.log(LOG_WARNING, "WriteBytes: FlushInstructionCache failed: " +
                                    std::to_string(GetLastError()) +
                                    " at address " + format_address(reinterpret_cast<uintptr_t>(targetAddress)));
    }
    return true;
}
