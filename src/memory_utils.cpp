/**
 * @file memory_utils.cpp
 * @brief Implementation of memory manipulation and validation utilities.
 *
 * Provides functions for checking memory readability and writability, writing bytes to memory,
 * and managing a memory region cache for performance optimization.
 * The cache mechanism is internal to this translation unit.
 */

#include "DetourModKit/memory_utils.hpp"
#include "DetourModKit/string_utils.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <vector>
#include <mutex>
#include <chrono>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cstddef>

using namespace DetourModKit;
using namespace DetourModKit::String;

// Anonymous namespace for internal helpers and storage
namespace
{
    /**
     * @struct CachedMemoryRegionInfo
     * @brief Structure to hold cached memory region information.
     * @details Internal structure for the memory_utils cache implementation.
     */
    struct CachedMemoryRegionInfo
    {
        uintptr_t baseAddress;                           /**< Base address of the memory region. */
        size_t regionSize;                               /**< Size of the memory region. */
        DWORD protection;                                /**< Protection flags of the region (e.g., PAGE_READWRITE). */
        std::chrono::steady_clock::time_point timestamp; /**< Timestamp of when this entry was last validated/updated. */
        bool valid;                                      /**< True if this cache entry is currently valid. */

        /**
         * @brief Default constructor initializing an invalid entry.
         */
        CachedMemoryRegionInfo()
            : baseAddress(0), regionSize(0), protection(0), valid(false) {}
    };
}

/**
 * @namespace Anonymous_MemoryUtils
 * @brief Encapsulates internal static variables and helper functions for memory_utils.
 * @details This ensures that cache implementation details do not pollute the global namespace
 *          or other translation units. This replaced the simple file-static approach for clarity.
 */
namespace MemoryUtilsCacheInternal
{
    /** @brief Vector serving as the memory region cache. Dynamically sized upon initialization. */
    static std::vector<CachedMemoryRegionInfo> s_memoryCache;
    /** @brief Mutex protecting concurrent access to s_memoryCache and related settings. */
    static std::mutex s_cacheMutex;
    /** @brief Flag ensuring one-time initialization of the cache settings and vector. */
    static std::once_flag s_memoryCacheInitFlag;
    /** @brief Configured maximum number of entries in the cache. */
    static size_t s_configuredCacheSize = 0;
    /** @brief Configured cache entry expiry time in milliseconds. */
    static unsigned int s_configuredCacheExpiryMs = 0;

// Cache statistics are only compiled and tracked in Debug builds.
#ifdef _DEBUG
    /** @brief Atomic counter for cache hits (Debug builds only). */
    static std::atomic<uint64_t> s_cacheHits{0};
    /** @brief Atomic counter for cache misses (Debug builds only). */
    static std::atomic<uint64_t> s_cacheMisses{0};
#endif

    /**
     * @brief Internal helper: Finds a cache entry containing the given memory range.
     * @details Iterates through the cache, checks for entry validity (not expired),
     *          and if the requested address range is within a cached region.
     *          Updates the timestamp of a found entry (part of LRU strategy).
     * @param address Start address of the memory range to find.
     * @param size Size of the memory range.
     * @return Pointer to the CachedMemoryRegionInfo entry if found and valid, nullptr otherwise.
     * @note This function assumes s_cacheMutex is ALREADY HELD by the caller.
     */
    CachedMemoryRegionInfo *findCacheEntry(uintptr_t address, size_t size)
    {
        uintptr_t endAddress = address + size;
        // Check for overflow if size is very large
        if (endAddress < address && size != 0) // size != 0 to allow address + 0 for a zero-size check if ever needed
        {
            Logger::getInstance().log(LOG_WARNING, "MemoryCache: Address + size caused overflow in findCacheEntry.");
            return nullptr;
        }

        auto current_time = std::chrono::steady_clock::now();
        for (auto &entry : s_memoryCache)
        {
            if (!entry.valid)
            {
                continue; // Skip invalid entries
            }

            // Check for expiry
            auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - entry.timestamp).count();
            if (age_ms > static_cast<long long>(s_configuredCacheExpiryMs))
            {
                entry.valid = false; // Mark as expired
                continue;
            }

            // Check if the requested range [address, address + size) is within the cached entry's range
            uintptr_t entryEndAddress = entry.baseAddress + entry.regionSize;
            if (address >= entry.baseAddress && endAddress <= entryEndAddress)
            {
                entry.timestamp = current_time; // Update timestamp (Least Recently Used)
                return &entry;                  // Found a covering, valid, non-expired entry
            }
        }
        return nullptr; // Not found or not fully covered by any valid entry
    }

    /**
     * @brief Internal helper: Adds or updates a cache entry with new region info.
     * @details Finds an invalid entry to overwrite, or if all are valid,
     *          it replaces the oldest entry (Least Recently Used eviction strategy).
     * @param mbi MEMORY_BASIC_INFORMATION structure containing the region data to cache.
     * @note This function assumes s_cacheMutex is ALREADY HELD by the caller.
     */
    void updateCacheWithNewRegion(const MEMORY_BASIC_INFORMATION &mbi)
    {
        if (s_memoryCache.empty()) // Cache not initialized or failed to allocate
            return;

        auto current_time = std::chrono::steady_clock::now();

        // Try to find an invalid (empty or expired) slot first
        auto available_slot_it = std::find_if(s_memoryCache.begin(), s_memoryCache.end(),
                                              [](const CachedMemoryRegionInfo &entry) -> bool
                                              {
                                                  return !entry.valid;
                                              });

        if (available_slot_it == s_memoryCache.end())
        {
            // No invalid slots, find the least recently used (oldest timestamp)
            available_slot_it = std::min_element(s_memoryCache.begin(), s_memoryCache.end(),
                                                 [](const CachedMemoryRegionInfo &a, const CachedMemoryRegionInfo &b)
                                                 {
                                                     return a.timestamp < b.timestamp;
                                                 });
        }

        // Update the chosen slot with the new region information
        available_slot_it->baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        available_slot_it->regionSize = mbi.RegionSize;
        available_slot_it->protection = mbi.Protect;
        available_slot_it->timestamp = current_time;
        available_slot_it->valid = true;
    }

    /**
     * @brief Initializes the cache structures. Called once by initMemoryCache.
     * @param cache_size_param Desired number of cache entries.
     * @param expiry_ms_param Desired expiry time in milliseconds for entries.
     */
    void performCacheInitialization(size_t cache_size_param, unsigned int expiry_ms_param)
    {
        std::lock_guard<std::mutex> lock(s_cacheMutex); // Protect static cache settings

        s_configuredCacheSize = (cache_size_param == 0) ? 1 : cache_size_param; // Min 1 entry if 0 specified
        s_configuredCacheExpiryMs = expiry_ms_param;

        try
        {
            s_memoryCache.resize(s_configuredCacheSize); // Pre-allocate cache entries
        }
        catch (const std::bad_alloc &e)
        {
            Logger::getInstance().log(LOG_ERROR, "MemoryCache: Failed to allocate memory for cache (size: " +
                                                     std::to_string(s_configuredCacheSize) + "). Error: " + e.what() +
                                                     ". Attempting minimal cache.");
            try
            {
                s_configuredCacheSize = 1; // Try with a minimal size
                s_memoryCache.resize(s_configuredCacheSize);
            }
            catch (const std::bad_alloc &e_min)
            {
                Logger::getInstance().log(LOG_ERROR, "MemoryCache: Minimal cache allocation also failed. Error: " +
                                                         std::string(e_min.what()) + ". Cache will be disabled.");
                s_configuredCacheSize = 0; // Mark cache as unusable
                s_memoryCache.clear();     // Ensure vector is empty
                return;                    // Exit: cache setup failed
            }
        }

        // Initialize all entries as invalid
        for (auto &entry : s_memoryCache)
        {
            entry.valid = false;
        }

        if (s_configuredCacheSize > 0)
        {
            Logger::getInstance().log(LOG_DEBUG, "MemoryCache: Initialized with " +
                                                     std::to_string(s_configuredCacheSize) + " entries and " +
                                                     std::to_string(s_configuredCacheExpiryMs) + "ms expiry.");
        }
    }

} // namespace MemoryUtilsCacheInternal

// --- Public API functions for Memory Utilities ---

void DetourModKit::Memory::initMemoryCache(size_t cache_size, unsigned int expiry_ms)
{
    // Use std::call_once to ensure performCacheInitialization is called exactly once
    // across all threads, even if initMemoryCache is called multiple times.
    std::call_once(MemoryUtilsCacheInternal::s_memoryCacheInitFlag,
                   MemoryUtilsCacheInternal::performCacheInitialization,
                   cache_size, expiry_ms);
}

void DetourModKit::Memory::clearMemoryCache()
{
    std::lock_guard<std::mutex> lock(MemoryUtilsCacheInternal::s_cacheMutex);
    for (auto &entry : MemoryUtilsCacheInternal::s_memoryCache)
    {
        entry.valid = false; // Mark all entries as invalid
    }

    if (MemoryUtilsCacheInternal::s_configuredCacheSize > 0)
    {
        Logger::getInstance().log(LOG_DEBUG, "MemoryCache: All entries cleared.");
    }
#ifdef _DEBUG // Reset stats if compiled in debug
    MemoryUtilsCacheInternal::s_cacheHits.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_cacheMisses.store(0, std::memory_order_relaxed);
#endif
}

std::string DetourModKit::Memory::getMemoryCacheStats()
{
#ifdef _DEBUG
    uint64_t hits = MemoryUtilsCacheInternal::s_cacheHits.load(std::memory_order_relaxed);
    uint64_t misses = MemoryUtilsCacheInternal::s_cacheMisses.load(std::memory_order_relaxed);
    uint64_t total_queries = hits + misses;

    size_t current_cache_capacity = 0;
    unsigned int current_expiry_setting_ms = 0;
    {
        // Briefly lock to read configuration settings safely
        std::lock_guard<std::mutex> lock(MemoryUtilsCacheInternal::s_cacheMutex);
        current_cache_capacity = MemoryUtilsCacheInternal::s_configuredCacheSize;
        current_expiry_setting_ms = MemoryUtilsCacheInternal::s_configuredCacheExpiryMs;
    }

    std::ostringstream oss;
    oss << "MemoryCache Stats (Capacity: " << current_cache_capacity
        << ", Expiry: " << current_expiry_setting_ms << "ms) - "
        << "Hits: " << hits << ", Misses: " << misses;

    if (total_queries > 0)
    {
        double hit_rate_percent = (static_cast<double>(hits) / static_cast<double>(total_queries)) * 100.0;
        oss << ", Hit Rate: " << std::fixed << std::setprecision(2) << hit_rate_percent << "%";
    }
    else
    {
        oss << ", Hit Rate: N/A (no queries tracked)";
    }
    return oss.str();
#else
    return "MemoryCache statistics are only available in Debug builds.";
#endif
}

bool DetourModKit::Memory::isMemoryReadable(const volatile void *address, size_t size)
{
    if (!address || size == 0) // Reading zero bytes is trivially true but often indicates an error in calling code.
    {                          // For consistency with how VirtualQuery might treat it, or if size=0 indicates no check needed.
                               // Let's consider size=0 invalid for a "readable check".
        return false;
    }

    // Ensure cache is initialized (does nothing if already initialized)
    DetourModKit::Memory::initMemoryCache(); // Uses default parameters if not called explicitly by user

    uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
    bool is_region_readable_from_cache = false;
    bool cache_hit_occurred = false;

    // Scope for cache lock
    {
        std::lock_guard<std::mutex> lock(MemoryUtilsCacheInternal::s_cacheMutex);
        if (!MemoryUtilsCacheInternal::s_memoryCache.empty()) // Check if cache is active
        {
            CachedMemoryRegionInfo *cached_info = MemoryUtilsCacheInternal::findCacheEntry(query_addr_val, size);
            if (cached_info) // A valid, non-expired entry covers the requested range
            {
                const DWORD READ_PERMISSION_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                // Check if protection flags allow reading and it's not guarded/no-access
                is_region_readable_from_cache = ((cached_info->protection & READ_PERMISSION_FLAGS) != 0) &&
                                                !((cached_info->protection & PAGE_NOACCESS) || (cached_info->protection & PAGE_GUARD));
                cache_hit_occurred = true;
#ifdef _DEBUG
                MemoryUtilsCacheInternal::s_cacheHits.fetch_add(1, std::memory_order_relaxed);
#endif
            }
        }
    } // Cache lock released

    if (cache_hit_occurred)
    {
        return is_region_readable_from_cache;
    }

// Cache miss or cache inactive, proceed with VirtualQuery
#ifdef _DEBUG
    // Only increment misses if the cache was actually active and consulted
    if (!MemoryUtilsCacheInternal::s_memoryCache.empty())
    {
        MemoryUtilsCacheInternal::s_cacheMisses.fetch_add(1, std::memory_order_relaxed);
    }
#endif

    MEMORY_BASIC_INFORMATION mbi;
    // VirtualQuery expects a non-const LPCVOID for the address
    if (VirtualQuery(const_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
    {
        // VirtualQuery failed (e.g., address is invalid or outside user address space)
        return false;
    }

    // Region must be committed memory
    if (mbi.State != MEM_COMMIT)
    {
        return false;
    }

    const DWORD READ_PERMISSION_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    // Check protection flags for readability
    if (!((mbi.Protect & READ_PERMISSION_FLAGS) != 0) || ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)))
    {
        return false;
    }

    // Final check: ensure the entire requested range [address, address+size)
    // is within the single region returned by VirtualQuery.
    uintptr_t region_start_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t region_end_addr = region_start_addr + mbi.RegionSize;
    uintptr_t query_end_addr = query_addr_val + size;

    // Overflow check for query_end_addr already implicitly handled by checking query_addr_val >= region_start_addr
    // and query_end_addr <= region_end_addr, IF query_end_addr calculation itself didn't overflow.
    // More robustly:
    if (query_end_addr < query_addr_val && size != 0)
        return false; // Overflow

    bool is_fully_contained = (query_addr_val >= region_start_addr && query_end_addr <= region_end_addr);

    if (is_fully_contained)
    {
        // Add/update this region in the cache if cache is active
        std::lock_guard<std::mutex> lock(MemoryUtilsCacheInternal::s_cacheMutex);
        if (!MemoryUtilsCacheInternal::s_memoryCache.empty())
        {
            MemoryUtilsCacheInternal::updateCacheWithNewRegion(mbi);
        }
    }
    return is_fully_contained;
}

bool DetourModKit::Memory::isMemoryWritable(volatile void *address, size_t size)
{
    if (!address || size == 0)
    {
        return false;
    }
    DetourModKit::Memory::initMemoryCache(); // Ensure cache is initialized

    uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
    bool is_region_writable_from_cache = false;
    bool cache_hit_occurred = false;

    {
        std::lock_guard<std::mutex> lock(MemoryUtilsCacheInternal::s_cacheMutex);
        if (!MemoryUtilsCacheInternal::s_memoryCache.empty())
        {
            CachedMemoryRegionInfo *cached_info = MemoryUtilsCacheInternal::findCacheEntry(query_addr_val, size);
            if (cached_info)
            {
                const DWORD WRITE_PERMISSION_FLAGS = PAGE_READWRITE | PAGE_WRITECOPY |
                                                     PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                is_region_writable_from_cache = ((cached_info->protection & WRITE_PERMISSION_FLAGS) != 0) &&
                                                !((cached_info->protection & PAGE_NOACCESS) || (cached_info->protection & PAGE_GUARD));
                cache_hit_occurred = true;
#ifdef _DEBUG
                MemoryUtilsCacheInternal::s_cacheHits.fetch_add(1, std::memory_order_relaxed);
#endif
            }
        }
    }

    if (cache_hit_occurred)
    {
        return is_region_writable_from_cache;
    }

#ifdef _DEBUG
    if (!MemoryUtilsCacheInternal::s_memoryCache.empty())
    {
        MemoryUtilsCacheInternal::s_cacheMisses.fetch_add(1, std::memory_order_relaxed);
    }
#endif

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(const_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;

    const DWORD WRITE_PERMISSION_FLAGS = PAGE_READWRITE | PAGE_WRITECOPY |
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!((mbi.Protect & WRITE_PERMISSION_FLAGS) != 0) || ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)))
        return false;

    uintptr_t region_start_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t region_end_addr = region_start_addr + mbi.RegionSize;
    uintptr_t query_end_addr = query_addr_val + size;
    if (query_end_addr < query_addr_val && size != 0)
        return false;

    bool is_fully_contained = (query_addr_val >= region_start_addr && query_end_addr <= region_end_addr);

    if (is_fully_contained)
    {
        std::lock_guard<std::mutex> lock(MemoryUtilsCacheInternal::s_cacheMutex);
        if (!MemoryUtilsCacheInternal::s_memoryCache.empty())
        {
            MemoryUtilsCacheInternal::updateCacheWithNewRegion(mbi);
        }
    }
    return is_fully_contained;
}

bool DetourModKit::Memory::WriteBytes(std::byte *targetAddress, const std::byte *sourceBytes, size_t numBytes, Logger &logger)
{
    if (!targetAddress)
    {
        logger.log(LOG_ERROR, "WriteBytes: Target address is null.");
        return false;
    }
    if (!sourceBytes && numBytes > 0) // Allow null source if numBytes is 0
    {
        logger.log(LOG_ERROR, "WriteBytes: Source bytes pointer is null for non-zero numBytes.");
        return false;
    }
    if (numBytes == 0)
    {
        logger.log(LOG_WARNING, "WriteBytes: Number of bytes to write is zero. Operation has no effect.");
        return true;
    }

    DWORD old_protection_flags;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(targetAddress), numBytes, PAGE_EXECUTE_READWRITE, &old_protection_flags))
    {
        logger.log(LOG_ERROR, "WriteBytes: VirtualProtect failed to set PAGE_EXECUTE_READWRITE at address " +
                                  format_address(reinterpret_cast<uintptr_t>(targetAddress)) +
                                  ". Windows Error: " + std::to_string(GetLastError()));
        return false;
    }

    try
    {
        memcpy(reinterpret_cast<void *>(targetAddress), reinterpret_cast<const void *>(sourceBytes), numBytes);
    }
    catch (const std::exception &e)
    {
        logger.log(LOG_ERROR, "WriteBytes: memcpy threw an unexpected C++ exception: " + std::string(e.what()));
        DWORD temp_protect_holder;
        VirtualProtect(reinterpret_cast<LPVOID>(targetAddress), numBytes, old_protection_flags, &temp_protect_holder);
        return false;
    }

    DWORD temp_holder_for_old_protect_after_restore;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(targetAddress), numBytes, old_protection_flags, &temp_holder_for_old_protect_after_restore))
    {
        logger.log(LOG_WARNING, "WriteBytes: VirtualProtect failed to restore original protection (" +
                                    format_hex(static_cast<int>(old_protection_flags)) + ") at address " +
                                    format_address(reinterpret_cast<uintptr_t>(targetAddress)) +
                                    ". Windows Error: " + std::to_string(GetLastError()));
    }

    if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(targetAddress), numBytes))
    {
        logger.log(LOG_WARNING, "WriteBytes: FlushInstructionCache failed for address " +
                                    format_address(reinterpret_cast<uintptr_t>(targetAddress)) +
                                    ". Windows Error: " + std::to_string(GetLastError()));
    }

    logger.log(LOG_DEBUG, "WriteBytes: Successfully wrote " + std::to_string(numBytes) +
                              " bytes to address " + format_address(reinterpret_cast<uintptr_t>(targetAddress)) + ".");
    return true;
}
