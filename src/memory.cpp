/**
 * @file memory.cpp
 * @brief Implementation of memory manipulation and validation utilities.
 *
 * Provides functions for checking memory readability and writability, writing bytes to memory,
 * and managing a memory region cache for performance optimization.
 * The cache uses sharded locks with SRWLOCK for high-concurrency read-heavy access.
 * Uses monotonic counter-keyed map for O(log n) LRU eviction instead of O(n) scan.
 * In-flight query coalescing prevents cache stampede under high concurrency.
 * On-demand cleanup handles expired entry removal to avoid polluting the miss path.
 * Epoch-based reader tracking prevents use-after-free during shutdown.
 */

#include "DetourModKit/memory.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <shared_mutex>
#include <unordered_map>
#include <map>
#include <vector>
#include <chrono>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cstddef>
#include <thread>
#include <condition_variable>

using namespace DetourModKit;

// Permission flags as constexpr for compile-time constants
namespace CachePermissions
{
    constexpr DWORD READ_PERMISSION_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    constexpr DWORD WRITE_PERMISSION_FLAGS = PAGE_READWRITE | PAGE_WRITECOPY |
                                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    constexpr DWORD NOACCESS_GUARD_FLAGS = PAGE_NOACCESS | PAGE_GUARD;
}

// Anonymous namespace for internal helpers and storage
namespace
{
    /**
     * @class SrwSharedMutex
     * @brief Shared mutex backed by Windows SRWLOCK instead of pthread_rwlock_t.
     * @details MinGW/winpthreads' pthread_rwlock_t corrupts internal state under
     *          high reader contention, causing assertion failures in lock_shared().
     *          SRWLOCK is kernel-level, lock-free for uncontended cases, and does
     *          not suffer from this bug.
     */
    class SrwSharedMutex
    {
    public:
        SrwSharedMutex() noexcept { InitializeSRWLock(&srw_); }

        SrwSharedMutex(const SrwSharedMutex &) = delete;
        SrwSharedMutex &operator=(const SrwSharedMutex &) = delete;

        void lock() noexcept { AcquireSRWLockExclusive(&srw_); }
        bool try_lock() noexcept { return TryAcquireSRWLockExclusive(&srw_) != 0; }
        void unlock() noexcept { ReleaseSRWLockExclusive(&srw_); }

        void lock_shared() noexcept { AcquireSRWLockShared(&srw_); }
        bool try_lock_shared() noexcept { return TryAcquireSRWLockShared(&srw_) != 0; }
        void unlock_shared() noexcept { ReleaseSRWLockShared(&srw_); }

    private:
        SRWLOCK srw_;
    };

    /**
     * @struct CachedMemoryRegionInfo
     * @brief Structure to hold cached memory region information.
     * @details Uses timestamp for thread-safe updates and reduced memory footprint.
     */
    struct CachedMemoryRegionInfo
    {
        uintptr_t baseAddress;
        size_t regionSize;
        DWORD protection;
        uint64_t timestamp_ns;
        uint64_t lru_key;
        bool valid;

        CachedMemoryRegionInfo()
            : baseAddress(0), regionSize(0), protection(0), timestamp_ns(0), lru_key(0), valid(false)
        {
        }
    };

    /**
     * @struct CacheShard
     * @brief Individual cache shard with O(1) address lookup and O(log n) LRU eviction.
     * @details Uses unordered_map keyed by region base address for fast lookup.
     *          std::map keyed by monotonic counter for efficient oldest-entry eviction.
     *          SrwSharedMutex allows multiple concurrent readers.
     *          in_flight flag prevents cache stampede by coalescing concurrent VirtualQuery calls.
     *          Mutex is stored separately to allow vector resize operations.
     */
    struct CacheShard
    {
        // Map from baseAddress -> CachedMemoryRegionInfo for O(1) lookup by address
        std::unordered_map<uintptr_t, CachedMemoryRegionInfo> entries;
        // Map from monotonic counter -> baseAddress for O(log n) oldest-entry lookup (LRU)
        // Monotonic counter guarantees insertion-order uniqueness for correct eviction
        std::map<uint64_t, uintptr_t> lru_index;
        uint64_t entry_counter{0};
        size_t capacity;
        size_t max_capacity;

        CacheShard() : capacity(0), max_capacity(0)
        {
            entries.reserve(64);
        }
    };

    /**
     * @brief Returns current time in nanoseconds.
     */
    inline uint64_t current_time_ns() noexcept
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    /**
     * @brief Computes the shard index for a given address.
     * @param address The address to hash.
     * @param shard_count Total number of shards.
     * @return The shard index.
     * @note Uses golden ratio bit-mixing to spread adjacent addresses across shards.
     */
    constexpr inline size_t compute_shard_index(uintptr_t address, size_t shard_count) noexcept
    {
        return (static_cast<size_t>((address * 0x9E3779B97F4A7C15ULL) >> 58)) % shard_count;
    }
}

/**
 * @namespace MemoryUtilsCacheInternal
 * @brief Encapsulates internal static variables and helper functions for memory cache.
 */
namespace MemoryUtilsCacheInternal
{
    std::vector<CacheShard> s_cacheShards;
    std::vector<std::unique_ptr<SrwSharedMutex>> s_shardMutexes;
    std::unique_ptr<std::atomic<char>[]> s_inFlight;
    std::atomic<size_t> s_shardCount{0};
    std::atomic<size_t> s_maxEntriesPerShard{0};
    std::atomic<unsigned int> s_configuredExpiryMs{0};
    std::atomic<bool> s_cacheInitialized{false};

    // Global cache state mutex to serialize init/clear/shutdown transitions
    // Protects against concurrent state changes that could leave vectors in invalid state
    std::mutex s_cacheStateMutex;

    // Epoch-based reader tracking to prevent use-after-free during shutdown.
    // Readers increment on entry to is_readable/is_writable and decrement on exit.
    // shutdown_cache waits for this to reach zero before destroying data structures.
    std::atomic<int32_t> s_activeReaders{0};

    /**
     * @class ActiveReaderGuard
     * @brief RAII guard that increments s_activeReaders on construction and
     *        decrements on destruction, ensuring correct pairing on all exit paths.
     */
    class ActiveReaderGuard
    {
    public:
        ActiveReaderGuard() noexcept
        {
            s_activeReaders.fetch_add(1, std::memory_order_acq_rel);
        }

        ~ActiveReaderGuard() noexcept
        {
            s_activeReaders.fetch_sub(1, std::memory_order_release);
        }

        ActiveReaderGuard(const ActiveReaderGuard &) = delete;
        ActiveReaderGuard &operator=(const ActiveReaderGuard &) = delete;
    };

    // Background cleanup thread
    std::atomic<bool> s_cleanupThreadRunning{false};
    std::thread s_cleanupThread;
    std::mutex s_cleanupMutex;
    std::condition_variable s_cleanupCv;
    std::atomic<bool> s_cleanupRequested{false};

    // On-demand cleanup fallback timer (used when background thread is disabled)
    std::atomic<uint64_t> s_lastCleanupTimeNs{0};
    constexpr uint64_t CLEANUP_INTERVAL_NS = 1'000'000'000ULL; // 1 second in nanoseconds

    // Always-available cache statistics
    struct CacheStats
    {
        std::atomic<uint64_t> cacheHits{0};
        std::atomic<uint64_t> cacheMisses{0};
        std::atomic<uint64_t> invalidations{0};
        std::atomic<uint64_t> coalescedQueries{0};
        std::atomic<uint64_t> onDemandCleanups{0};
    };
    CacheStats s_stats;

    /**
     * @brief Checks if a cache entry covers the requested address range and is valid.
     * @param entry The cache entry to check.
     * @param address Start address of the query.
     * @param size Size of the query range.
     * @param current_time_ns Current timestamp in nanoseconds.
     * @param expiry_ns Expiry time in nanoseconds.
     * @return true if the entry is valid and covers the range.
     */
    constexpr inline bool is_entry_valid_and_covers(const CachedMemoryRegionInfo &entry,
                                                    uintptr_t address,
                                                    size_t size,
                                                    uint64_t current_time_ns,
                                                    uint64_t expiry_ns) noexcept
    {
        if (!entry.valid)
            return false;

        const uint64_t entry_age = current_time_ns - entry.timestamp_ns;
        if (entry_age > expiry_ns)
            return false;

        const uintptr_t endAddress = address + size;
        if (endAddress < address)
            return false;

        const uintptr_t entryEndAddress = entry.baseAddress + entry.regionSize;
        if (entryEndAddress < entry.baseAddress)
            return false;

        return address >= entry.baseAddress && endAddress <= entryEndAddress;
    }

    /**
     * @brief Checks protection flags for read permission.
     */
    constexpr inline bool check_read_permission(DWORD protection) noexcept
    {
        return (protection & CachePermissions::READ_PERMISSION_FLAGS) != 0 &&
               (protection & CachePermissions::NOACCESS_GUARD_FLAGS) == 0;
    }

    /**
     * @brief Checks protection flags for write permission.
     */
    constexpr inline bool check_write_permission(DWORD protection) noexcept
    {
        return (protection & CachePermissions::WRITE_PERMISSION_FLAGS) != 0 &&
               (protection & CachePermissions::NOACCESS_GUARD_FLAGS) == 0;
    }

    /**
     * @brief Finds and validates a cache entry in a shard by scanning for range containment.
     * @param shard The cache shard to search.
     * @param address Address to look up.
     * @param size Size of the query range.
     * @param current_time_ns Current timestamp in nanoseconds.
     * @param expiry_ns Expiry time in nanoseconds.
     * @return Pointer to the matching entry, or nullptr if not found or expired.
     * @note Must be called with shard mutex held (shared or exclusive).
     * @note First attempts direct lookup by page-aligned base address for O(1) fast path,
     *       then falls back to linear scan for addresses within larger regions.
     */
    CachedMemoryRegionInfo *find_in_shard(CacheShard &shard,
                                          uintptr_t address,
                                          size_t size,
                                          uint64_t current_time_ns,
                                          uint64_t expiry_ns) noexcept
    {
        // Fast path: direct lookup by page-aligned base address
        const uintptr_t base_addr = address & ~static_cast<uintptr_t>(0xFFF);
        auto it = shard.entries.find(base_addr);
        if (it != shard.entries.end())
        {
            CachedMemoryRegionInfo &entry = it->second;
            if (is_entry_valid_and_covers(entry, address, size, current_time_ns, expiry_ns))
            {
                return &entry;
            }
        }

        // Slow path: scan all entries for a region that contains the queried range.
        // This handles addresses that fall within a larger region whose base address
        // differs from the queried page. Shard sizes are bounded so this is fast.
        for (auto &pair : shard.entries)
        {
            CachedMemoryRegionInfo &entry = pair.second;
            if (is_entry_valid_and_covers(entry, address, size, current_time_ns, expiry_ns))
            {
                return &entry;
            }
        }

        return nullptr;
    }

    /**
     * @brief Evicts the oldest entry from the shard using O(log n) LRU lookup.
     * @note Must be called with shard mutex held (exclusive).
     * @return true if an entry was evicted, false if shard is empty.
     */
    bool evict_oldest_entry(CacheShard &shard) noexcept
    {
        if (shard.lru_index.empty())
            return false;

        const auto lru_it = shard.lru_index.begin();
        const uintptr_t oldest_base = lru_it->second;

        shard.lru_index.erase(lru_it);

        const auto entry_it = shard.entries.find(oldest_base);
        if (entry_it != shard.entries.end())
        {
            shard.entries.erase(entry_it);
            return true;
        }
        return false;
    }

    /**
     * @brief Force-evicts entries until shard is at or below max_capacity.
     * @note Must be called with shard mutex held (exclusive).
     * @param shard The cache shard to trim.
     */
    void trim_to_max_capacity(CacheShard &shard) noexcept
    {
        while (shard.entries.size() > shard.max_capacity && !shard.lru_index.empty())
        {
            evict_oldest_entry(shard);
        }
    }

    /**
     * @brief Updates or inserts a cache entry in a specific shard.
     * @param shard The cache shard to update.
     * @param mbi Memory basic information from VirtualQuery.
     * @param current_time_ns Current timestamp in nanoseconds.
     * @note Must be called with shard mutex held (exclusive).
     */
    void update_shard_with_region(CacheShard &shard, const MEMORY_BASIC_INFORMATION &mbi, uint64_t current_time_ns) noexcept
    {
        const uintptr_t base_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);

        auto it = shard.entries.find(base_addr);
        if (it != shard.entries.end())
        {
            // Remove old entry from LRU index using stored lru_key
            CachedMemoryRegionInfo &old_entry = it->second;
            const auto lru_it = shard.lru_index.find(old_entry.lru_key);
            if (lru_it != shard.lru_index.end() && lru_it->second == base_addr)
            {
                shard.lru_index.erase(lru_it);
            }

            // Update existing entry with new monotonic LRU key
            const uint64_t new_lru_key = shard.entry_counter++;
            old_entry.baseAddress = base_addr;
            old_entry.regionSize = mbi.RegionSize;
            old_entry.protection = mbi.Protect;
            old_entry.timestamp_ns = current_time_ns;
            old_entry.lru_key = new_lru_key;
            old_entry.valid = true;

            // Insert new composite key into LRU index
            shard.lru_index.emplace(new_lru_key, base_addr);
        }
        else
        {
            // Evict oldest if at capacity - O(log n) via map
            if (shard.entries.size() >= shard.capacity)
            {
                evict_oldest_entry(shard);
            }

            // Hard upper bound: trim if exceeding max_capacity
            if (shard.entries.size() >= shard.max_capacity)
            {
                trim_to_max_capacity(shard);
            }

            // Generate unique monotonic LRU key
            const uint64_t new_lru_key = shard.entry_counter++;

            CachedMemoryRegionInfo new_entry;
            new_entry.baseAddress = base_addr;
            new_entry.regionSize = mbi.RegionSize;
            new_entry.protection = mbi.Protect;
            new_entry.timestamp_ns = current_time_ns;
            new_entry.lru_key = new_lru_key;
            new_entry.valid = true;

            shard.entries.insert_or_assign(base_addr, std::move(new_entry));
            shard.lru_index.emplace(new_lru_key, base_addr);
        }
    }

    /**
     * @brief Removes expired entries from a shard.
     * @note Must be called with shard mutex held (exclusive).
     * @return Number of entries removed from this shard.
     */
    size_t cleanup_expired_entries_in_shard(CacheShard &shard,
                                            uint64_t current_time_ns,
                                            uint64_t expiry_ns) noexcept
    {
        size_t removed = 0;
        auto it = shard.entries.begin();
        while (it != shard.entries.end())
        {
            const CachedMemoryRegionInfo &entry = it->second;
            const uint64_t entry_age = current_time_ns - entry.timestamp_ns;

            if (!entry.valid || entry_age > expiry_ns)
            {
                // Remove from LRU index using stored lru_key
                const auto lru_it = shard.lru_index.find(entry.lru_key);
                if (lru_it != shard.lru_index.end() && lru_it->second == it->first)
                {
                    shard.lru_index.erase(lru_it);
                }

                it = shard.entries.erase(it);
                ++removed;
            }
            else
            {
                ++it;
            }
        }
        return removed;
    }

    /**
     * @brief Performs cleanup of expired cache entries across all shards.
     * @details Called by the background cleanup thread or on-demand timer.
     * @param force Force cleanup regardless of timing.
     */
    void cleanup_expired_entries(bool force) noexcept
    {
        // Always hold state mutex to prevent racing with shutdown_cache()
        // which clears the shard vectors. try_lock for on-demand to avoid
        // blocking the hot path; forced cleanup blocks to guarantee progress.
        std::unique_lock<std::mutex> lock(s_cacheStateMutex, std::defer_lock);
        if (force)
        {
            lock.lock();
        }
        else if (!lock.try_lock())
        {
            return; // Shutdown or forced cleanup in progress, skip
        }

        if (s_cacheShards.empty())
            return;

        const size_t shard_count = s_shardCount.load(std::memory_order_acquire);
        if (shard_count == 0)
            return;

        const uint64_t current_ts = current_time_ns();
        const uint64_t expiry_ns = static_cast<uint64_t>(s_configuredExpiryMs.load(std::memory_order_acquire)) * 1'000'000ULL;

        for (size_t i = 0; i < shard_count; ++i)
        {
            std::unique_lock<SrwSharedMutex> lock(*s_shardMutexes[i], std::try_to_lock);
            if (lock.owns_lock())
            {
                cleanup_expired_entries_in_shard(s_cacheShards[i], current_ts, expiry_ns);
                // Also trim to hard upper bound
                trim_to_max_capacity(s_cacheShards[i]);
            }
        }
    }

    /**
     * @brief Checks if on-demand cleanup should run based on elapsed time.
     * @return true if cleanup was performed, false otherwise.
     */
    bool try_trigger_on_demand_cleanup() noexcept
    {
        if (!s_cacheInitialized.load(std::memory_order_acquire))
            return false;

        const uint64_t now_ns = current_time_ns();
        const uint64_t last_cleanup = s_lastCleanupTimeNs.load(std::memory_order_acquire);
        const uint64_t elapsed_ns = now_ns - last_cleanup;

        if (elapsed_ns >= CLEANUP_INTERVAL_NS)
        {
            // Atomically update last cleanup time to prevent multiple threads triggering
            uint64_t expected = last_cleanup;
            if (s_lastCleanupTimeNs.compare_exchange_strong(expected, now_ns, std::memory_order_acq_rel))
            {
                cleanup_expired_entries(false);
                s_stats.onDemandCleanups.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Background cleanup thread function.
     * @details Runs periodically to clean up expired entries without impacting the miss path.
     */
    void cleanup_thread_func() noexcept
    {
        while (s_cleanupThreadRunning.load(std::memory_order_acquire))
        {
            {
                std::unique_lock<std::mutex> lock(s_cleanupMutex);
                s_cleanupCv.wait_for(lock, std::chrono::seconds(1), [&]()
                                     { return s_cleanupRequested.load(std::memory_order_acquire) || !s_cleanupThreadRunning.load(std::memory_order_acquire); });
            }

            if (!s_cleanupThreadRunning.load(std::memory_order_acquire))
                break;

            cleanup_expired_entries(true); // force=true to hold state mutex during vector iteration
            s_cleanupRequested.store(false, std::memory_order_relaxed);
        }
    }

    /**
     * @brief Signals the cleanup thread to run or triggers on-demand cleanup.
     */
    void request_cleanup() noexcept
    {
        if (s_cleanupThreadRunning.load(std::memory_order_acquire))
        {
            s_cleanupRequested.store(true, std::memory_order_relaxed);
            s_cleanupCv.notify_one();
        }
        else
        {
            // Background thread disabled (MinGW) - use on-demand timer-based cleanup
            try_trigger_on_demand_cleanup();
        }
    }

    /**
     * @brief Invalidates cache entries in shards that overlap with the given range.
     * @details Only invalidates specific entries that overlap, not entire shards.
     *          Uses retry loop to handle locked shards gracefully.
     */
    void invalidate_range_internal(uintptr_t address, size_t size) noexcept
    {
        if (s_cacheShards.empty() || size == 0)
            return;

        const uintptr_t endAddress = address + size;
        const size_t shard_count = s_shardCount.load(std::memory_order_acquire);

        const uintptr_t start_page = address >> 12;
        const uintptr_t end_page = (endAddress == 0 ? address : endAddress - 1) >> 12;

        constexpr size_t MAX_INVALIDATION_RETRIES = 3;

        for (uintptr_t page = start_page; page <= end_page; ++page)
        {
            const size_t shard_idx = compute_shard_index(page << 12, shard_count);

            bool invalidated = false;
            for (size_t retry = 0; retry < MAX_INVALIDATION_RETRIES && !invalidated; ++retry)
            {
                std::unique_lock<SrwSharedMutex> lock(*s_shardMutexes[shard_idx], std::try_to_lock);
                if (!lock.owns_lock())
                {
                    // Shard is locked by another writer - yield and retry
                    if (retry < MAX_INVALIDATION_RETRIES - 1)
                    {
                        std::this_thread::yield();
                    }
                    continue;
                }

                CacheShard &shard = s_cacheShards[shard_idx];
                const uintptr_t page_base = page << 12;

                auto it = shard.entries.find(page_base);
                if (it != shard.entries.end())
                {
                    CachedMemoryRegionInfo &entry = it->second;
                    if (!entry.valid)
                    {
                        invalidated = true;
                        continue;
                    }

                    const uintptr_t entryEndAddress = entry.baseAddress + entry.regionSize;
                    const bool overlaps = address < entryEndAddress && endAddress > entry.baseAddress;
                    if (overlaps)
                    {
                        // Remove from LRU index using stored lru_key to avoid tombstone accumulation
                        const auto lru_it = shard.lru_index.find(entry.lru_key);
                        if (lru_it != shard.lru_index.end() && lru_it->second == page_base)
                        {
                            shard.lru_index.erase(lru_it);
                        }
                        // Erase entry immediately instead of leaving tombstone
                        shard.entries.erase(it);
                        s_stats.invalidations.fetch_add(1, std::memory_order_relaxed);
                        invalidated = true;
                    }
                }
                else
                {
                    invalidated = true;
                }
            }

            if (start_page == end_page)
                break;
        }
    }

    /**
     * @brief Performs one-time cache initialization.
     */
    bool perform_cache_initialization(size_t cache_size, unsigned int expiry_ms, size_t shard_count)
    {
        if (cache_size == 0)
            cache_size = 1;
        if (shard_count == 0)
            shard_count = 1;

        const size_t entries_per_shard = (cache_size + shard_count - 1) / shard_count;
        const size_t hard_max_per_shard = entries_per_shard * 2; // Hard upper bound: 2x capacity

        try
        {
            s_cacheShards.resize(shard_count);
            s_shardMutexes.resize(shard_count);
            s_inFlight = std::make_unique<std::atomic<char>[]>(shard_count);
            for (size_t i = 0; i < shard_count; ++i)
            {
                s_cacheShards[i].entries.reserve(entries_per_shard * 2);
                s_cacheShards[i].capacity = entries_per_shard;
                s_cacheShards[i].max_capacity = hard_max_per_shard;
                s_shardMutexes[i] = std::make_unique<SrwSharedMutex>();
                s_inFlight[i].store(0, std::memory_order_relaxed);
            }
        }
        catch (const std::bad_alloc &)
        {
            Logger::get_instance().error("MemoryCache: Failed to allocate memory for cache shards.");
            s_cacheShards.clear();
            s_shardMutexes.clear();
            s_inFlight.reset();
            // Reset initialization flag so retry can work
            s_cacheInitialized.store(false, std::memory_order_relaxed);
            return false;
        }

        s_shardCount.store(shard_count, std::memory_order_release);
        s_maxEntriesPerShard.store(entries_per_shard, std::memory_order_release);
        s_configuredExpiryMs.store(expiry_ms, std::memory_order_release);
        s_lastCleanupTimeNs.store(current_time_ns(), std::memory_order_release);

        Logger::get_instance().debug("MemoryCache: Initialized with {} shards ({} entries/shard, {}ms expiry, {} max).",
                                     shard_count, entries_per_shard, expiry_ms, hard_max_per_shard);

        return true;
    }

    /**
     * @brief Performs VirtualQuery and updates cache with coalescing support.
     * @param shard_idx Index of the shard to update.
     * @param address Address to query.
     * @param mbi_out Output buffer for VirtualQuery result.
     * @return true if VirtualQuery succeeded.
     */
    bool query_and_update_cache(size_t shard_idx, LPCVOID address, MEMORY_BASIC_INFORMATION &mbi_out) noexcept
    {
        CacheShard &shard = s_cacheShards[shard_idx];

        // Try to claim in-flight status (stampede coalescing)
        char expected = 0;
        if (s_inFlight[shard_idx].compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
        {
            // We are the leader - perform VirtualQuery
            const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
            const uint64_t now_ns = current_time_ns();

            if (result)
            {
                std::unique_lock<SrwSharedMutex> lock(*s_shardMutexes[shard_idx]);
                update_shard_with_region(shard, mbi_out, now_ns);
            }

            // Release in-flight status
            s_inFlight[shard_idx].store(0, std::memory_order_release);
            return result;
        }
        else
        {
            // We are a follower - VirtualQuery already in progress by another thread.
            // Bounded wait to avoid stalling game threads on render-critical paths.
            const uint64_t expiry_ns = static_cast<uint64_t>(s_configuredExpiryMs.load(std::memory_order_acquire)) * 1'000'000ULL;
            constexpr size_t MAX_FOLLOWER_YIELDS = 8;

            for (size_t yield_count = 0; yield_count < MAX_FOLLOWER_YIELDS; ++yield_count)
            {
                if (s_inFlight[shard_idx].load(std::memory_order_acquire) == 0)
                {
                    // Query completed, check cache
                    const uintptr_t addr_val = reinterpret_cast<uintptr_t>(address);
                    std::shared_lock<SrwSharedMutex> lock(*s_shardMutexes[shard_idx]);
                    CachedMemoryRegionInfo *cached = find_in_shard(shard, addr_val, 1, current_time_ns(), expiry_ns);
                    if (cached)
                    {
                        s_stats.coalescedQueries.fetch_add(1, std::memory_order_relaxed);
                        // Copy cached info to output for consistency
                        mbi_out.BaseAddress = reinterpret_cast<PVOID>(cached->baseAddress);
                        mbi_out.RegionSize = cached->regionSize;
                        mbi_out.Protect = cached->protection;
                        mbi_out.State = MEM_COMMIT;
                        return true;
                    }
                    // Cache not populated, break to retry as leader
                    break;
                }

                // Yield to allow the leader thread to complete
                std::this_thread::yield();
            }

            // Retry as leader if follower wait timed out
            expected = 0;
            if (s_inFlight[shard_idx].compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
            {
                const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                if (result)
                {
                    std::unique_lock<SrwSharedMutex> lock(*s_shardMutexes[shard_idx]);
                    const uint64_t now_ns = current_time_ns();
                    update_shard_with_region(shard, mbi_out, now_ns);
                }
                s_inFlight[shard_idx].store(0, std::memory_order_release);
                return result;
            }

            // Last resort: just do VirtualQuery without cache update
            return VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
        }
    }

    /**
     * @brief Shuts down the cleanup thread.
     * @note Background cleanup thread is disabled on mingw due to pthreads compatibility issues.
     *       On-demand cleanup timer handles expiration in this case.
     */
    void shutdown_cleanup_thread() noexcept
    {
        // Signal cleanup thread to stop
        s_cleanupThreadRunning.store(false, std::memory_order_release);
        s_cleanupCv.notify_one();

        // Wait for cleanup thread to finish if it was started
        if (s_cleanupThread.joinable())
        {
            s_cleanupThread.join();
        }
    }

} // namespace MemoryUtilsCacheInternal

bool DetourModKit::Memory::init_cache(size_t cache_size, unsigned int expiry_ms, size_t shard_count)
{
    // Hold state mutex to prevent concurrent clear_cache or shutdown_cache
    // This serializes init/clear/shutdown transitions to ensure vectors are not accessed while being resized or cleared
    std::lock_guard<std::mutex> state_lock(MemoryUtilsCacheInternal::s_cacheStateMutex);

    // Fast path: already initialized
    if (MemoryUtilsCacheInternal::s_cacheInitialized.load(std::memory_order_acquire))
        return true;

    // Try to initialize
    bool expected = false;
    if (MemoryUtilsCacheInternal::s_cacheInitialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        if (!MemoryUtilsCacheInternal::perform_cache_initialization(cache_size, expiry_ms, shard_count))
        {
            // Initialization failed - s_cacheInitialized already reset to false in perform_cache_initialization
            return false;
        }

        // Try to start background cleanup thread (may fail silently on MinGW)
        MemoryUtilsCacheInternal::s_cleanupThreadRunning.store(true, std::memory_order_release);
        try
        {
            MemoryUtilsCacheInternal::s_cleanupThread = std::thread(MemoryUtilsCacheInternal::cleanup_thread_func);
        }
        catch (const std::system_error &)
        {
            // Background thread creation failed (MinGW pthreads issue) - use on-demand cleanup
            MemoryUtilsCacheInternal::s_cleanupThreadRunning.store(false, std::memory_order_release);
            Logger::get_instance().debug("MemoryCache: Background cleanup thread unavailable, using on-demand cleanup.");
        }

        return true;
    }

    // Another thread initialized while we were waiting
    return true;
}

void DetourModKit::Memory::clear_cache()
{
    // Hold state mutex to serialize with shutdown and cleanup thread
    std::lock_guard<std::mutex> state_lock(MemoryUtilsCacheInternal::s_cacheStateMutex);

    if (!MemoryUtilsCacheInternal::s_cacheInitialized.load(std::memory_order_acquire))
        return;

    const size_t shard_count = MemoryUtilsCacheInternal::s_shardCount.load(std::memory_order_acquire);
    if (shard_count == 0)
        return;

    // Acquire exclusive lock on each shard and clear entries.
    // Uses blocking lock to guarantee all entries are cleared.
    // The background cleanup thread uses try_to_lock on shard mutexes,
    // so it will skip shards we hold without deadlocking.
    for (size_t i = 0; i < shard_count; ++i)
    {
        auto &mutex_ptr = MemoryUtilsCacheInternal::s_shardMutexes[i];
        if (mutex_ptr)
        {
            std::unique_lock<SrwSharedMutex> shard_lock(*mutex_ptr);
            MemoryUtilsCacheInternal::s_cacheShards[i].entries.clear();
            MemoryUtilsCacheInternal::s_cacheShards[i].lru_index.clear();
            MemoryUtilsCacheInternal::s_inFlight[i].store(0, std::memory_order_relaxed);
        }
    }

    MemoryUtilsCacheInternal::s_stats.cacheHits.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_stats.cacheMisses.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_stats.invalidations.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_stats.coalescedQueries.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_stats.onDemandCleanups.store(0, std::memory_order_relaxed);

    MemoryUtilsCacheInternal::s_lastCleanupTimeNs.store(current_time_ns(), std::memory_order_relaxed);

    Logger::get_instance().debug("MemoryCache: All entries cleared.");
}

void DetourModKit::Memory::shutdown_cache()
{
    // Signal and join cleanup thread BEFORE acquiring state mutex.
    // The cleanup thread acquires s_cacheStateMutex in cleanup_expired_entries(force=true),
    // so joining while holding the state mutex would deadlock.
    MemoryUtilsCacheInternal::s_cleanupThreadRunning.store(false, std::memory_order_release);
    MemoryUtilsCacheInternal::s_cleanupCv.notify_one();

    if (MemoryUtilsCacheInternal::s_cleanupThread.joinable())
    {
        MemoryUtilsCacheInternal::s_cleanupThread.join();
    }

    // Acquire state mutex to serialize with clear_cache and protect data teardown
    std::lock_guard<std::mutex> state_lock(MemoryUtilsCacheInternal::s_cacheStateMutex);

    // Mark as not initialized and zero shard count.
    // This prevents new readers from entering the critical section.
    // acquire/release is sufficient here because the state mutex provides the
    // cross-thread ordering guarantee. Readers that observe shard_count == 0
    // immediately exit without touching data structures.
    MemoryUtilsCacheInternal::s_cacheInitialized.store(false, std::memory_order_release);
    MemoryUtilsCacheInternal::s_shardCount.store(0, std::memory_order_release);

    // Wait for in-flight readers to finish before destroying data structures.
    // Readers increment s_activeReaders on entry and decrement on exit.
    // acquire ordering ensures we see the latest reader decrements.
    while (MemoryUtilsCacheInternal::s_activeReaders.load(std::memory_order_acquire) > 0)
    {
        std::this_thread::yield();
    }

    // All readers have exited - safe to destroy data structures
    const size_t shard_count = MemoryUtilsCacheInternal::s_cacheShards.size();
    for (size_t i = 0; i < shard_count; ++i)
    {
        if (MemoryUtilsCacheInternal::s_shardMutexes[i])
        {
            std::unique_lock<SrwSharedMutex> shard_lock(*MemoryUtilsCacheInternal::s_shardMutexes[i]);
            MemoryUtilsCacheInternal::s_cacheShards[i].entries.clear();
            MemoryUtilsCacheInternal::s_cacheShards[i].lru_index.clear();
        }
    }

    MemoryUtilsCacheInternal::s_cacheShards.clear();
    MemoryUtilsCacheInternal::s_shardMutexes.clear();
    MemoryUtilsCacheInternal::s_inFlight.reset();

    // Reset all stats and config so a subsequent init_cache starts from a clean state
    MemoryUtilsCacheInternal::s_stats.cacheHits.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_stats.cacheMisses.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_stats.invalidations.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_stats.coalescedQueries.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_stats.onDemandCleanups.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_lastCleanupTimeNs.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_configuredExpiryMs.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_maxEntriesPerShard.store(0, std::memory_order_relaxed);
    MemoryUtilsCacheInternal::s_cleanupRequested.store(false, std::memory_order_relaxed);

    Logger::get_instance().debug("MemoryCache: Shutdown complete.");
}

std::string DetourModKit::Memory::get_cache_stats()
{
    const uint64_t hits = MemoryUtilsCacheInternal::s_stats.cacheHits.load(std::memory_order_relaxed);
    const uint64_t misses = MemoryUtilsCacheInternal::s_stats.cacheMisses.load(std::memory_order_relaxed);
    const uint64_t invalidations = MemoryUtilsCacheInternal::s_stats.invalidations.load(std::memory_order_relaxed);
    const uint64_t coalesced = MemoryUtilsCacheInternal::s_stats.coalescedQueries.load(std::memory_order_relaxed);
    const uint64_t on_demand_cleanups = MemoryUtilsCacheInternal::s_stats.onDemandCleanups.load(std::memory_order_relaxed);
    const uint64_t total_queries = hits + misses;

    const size_t shard_count = MemoryUtilsCacheInternal::s_shardCount.load(std::memory_order_acquire);
    const size_t max_entries_per_shard = MemoryUtilsCacheInternal::s_maxEntriesPerShard.load(std::memory_order_acquire);
    const unsigned int expiry_ms = MemoryUtilsCacheInternal::s_configuredExpiryMs.load(std::memory_order_acquire);

    // Calculate total entries and hard max with reader guard
    size_t total_entries = 0;
    size_t total_hard_max = 0;

    {
        MemoryUtilsCacheInternal::ActiveReaderGuard reader_guard;
        const size_t active_shard_count = MemoryUtilsCacheInternal::s_shardCount.load(std::memory_order_acquire);
        for (size_t i = 0; i < active_shard_count; ++i)
        {
            auto &mutex_ptr = MemoryUtilsCacheInternal::s_shardMutexes[i];
            if (mutex_ptr)
            {
                std::shared_lock<SrwSharedMutex> shard_lock(*mutex_ptr);
                total_entries += MemoryUtilsCacheInternal::s_cacheShards[i].entries.size();
                total_hard_max += MemoryUtilsCacheInternal::s_cacheShards[i].max_capacity;
            }
        }
    }

    std::ostringstream oss;
    oss << "MemoryCache Stats (Shards: " << shard_count
        << ", Entries/Shard: " << max_entries_per_shard
        << ", HardMax/Shard: " << (shard_count > 0 ? total_hard_max / shard_count : 0)
        << ", Expiry: " << expiry_ms << "ms) - "
        << "Hits: " << hits << ", Misses: " << misses
        << ", Invalidations: " << invalidations
        << ", Coalesced: " << coalesced
        << ", OnDemandCleanups: " << on_demand_cleanups
        << ", TotalEntries: " << total_entries;

    if (total_queries > 0)
    {
        const double hit_rate_percent = (static_cast<double>(hits) / static_cast<double>(total_queries)) * 100.0;
        oss << ", Hit Rate: " << std::fixed << std::setprecision(2) << hit_rate_percent << "%";
    }
    else
    {
        oss << ", Hit Rate: N/A (no queries tracked)";
    }
    return oss.str();
}

void DetourModKit::Memory::invalidate_range(const void *address, size_t size)
{
    if (!address || size == 0)
        return;

    if (!MemoryUtilsCacheInternal::s_cacheInitialized.load(std::memory_order_acquire))
        return;

    MemoryUtilsCacheInternal::ActiveReaderGuard reader_guard;

    const size_t shard_count = MemoryUtilsCacheInternal::s_shardCount.load(std::memory_order_acquire);
    if (shard_count == 0)
        return;

    const uintptr_t addr_val = reinterpret_cast<uintptr_t>(address);
    MemoryUtilsCacheInternal::invalidate_range_internal(addr_val, size);

    // request_cleanup may trigger on-demand cleanup_expired_entries(force=false)
    // which iterates shards without s_cacheStateMutex. Keep s_activeReaders > 0
    // so shutdown_cache cannot destroy shards during the cleanup pass.
    MemoryUtilsCacheInternal::request_cleanup();
}

bool DetourModKit::Memory::is_readable(const void *address, size_t size)
{
    if (!address || size == 0)
        return false;

    if (!MemoryUtilsCacheInternal::s_cacheInitialized.load(std::memory_order_acquire))
    {
        // Cache not initialized - fall back to direct VirtualQuery
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(address, &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT)
            return false;
        if (!MemoryUtilsCacheInternal::check_read_permission(mbi.Protect))
            return false;
        const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
        const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t query_end = query_addr_val + size;
        if (query_end < query_addr_val)
            return false;
        return query_addr_val >= region_start && query_end <= region_start + mbi.RegionSize;
    }

    MemoryUtilsCacheInternal::ActiveReaderGuard reader_guard;

    const size_t shard_count = MemoryUtilsCacheInternal::s_shardCount.load(std::memory_order_acquire);
    if (shard_count == 0)
        return false;

    const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
    const size_t shard_idx = compute_shard_index(query_addr_val, shard_count);
    const uint64_t now_ns = current_time_ns();
    const uint64_t expiry_ns = static_cast<uint64_t>(MemoryUtilsCacheInternal::s_configuredExpiryMs.load(std::memory_order_acquire)) * 1'000'000ULL;

    // Fast path: blocking shared lock for concurrent read access (multiple readers allowed)
    {
        std::shared_lock<SrwSharedMutex> lock(*MemoryUtilsCacheInternal::s_shardMutexes[shard_idx]);
        CachedMemoryRegionInfo *cached_info = MemoryUtilsCacheInternal::find_in_shard(
            MemoryUtilsCacheInternal::s_cacheShards[shard_idx],
            query_addr_val, size, now_ns, expiry_ns);
        if (cached_info)
        {
            MemoryUtilsCacheInternal::s_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
            return MemoryUtilsCacheInternal::check_read_permission(cached_info->protection);
        }
    }

    MemoryUtilsCacheInternal::s_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);

    // Cache miss: call VirtualQuery with stampede coalescing
    MEMORY_BASIC_INFORMATION mbi;
    if (!MemoryUtilsCacheInternal::query_and_update_cache(shard_idx, address, mbi))
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    if (!MemoryUtilsCacheInternal::check_read_permission(mbi.Protect))
        return false;

    const uintptr_t region_start_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    const uintptr_t region_end_addr = region_start_addr + mbi.RegionSize;
    const uintptr_t query_end_addr = query_addr_val + size;

    if (query_end_addr < query_addr_val)
        return false;

    return query_addr_val >= region_start_addr && query_end_addr <= region_end_addr;
}

bool DetourModKit::Memory::is_writable(void *address, size_t size)
{
    if (!address || size == 0)
        return false;

    if (!MemoryUtilsCacheInternal::s_cacheInitialized.load(std::memory_order_acquire))
    {
        // Cache not initialized - fall back to direct VirtualQuery
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(address, &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT)
            return false;
        if (!MemoryUtilsCacheInternal::check_write_permission(mbi.Protect))
            return false;
        const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
        const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t query_end = query_addr_val + size;
        if (query_end < query_addr_val)
            return false;
        return query_addr_val >= region_start && query_end <= region_start + mbi.RegionSize;
    }

    MemoryUtilsCacheInternal::ActiveReaderGuard reader_guard;

    const size_t shard_count = MemoryUtilsCacheInternal::s_shardCount.load(std::memory_order_acquire);
    if (shard_count == 0)
        return false;

    const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
    const size_t shard_idx = compute_shard_index(query_addr_val, shard_count);
    const uint64_t now_ns = current_time_ns();
    const uint64_t expiry_ns = static_cast<uint64_t>(MemoryUtilsCacheInternal::s_configuredExpiryMs.load(std::memory_order_acquire)) * 1'000'000ULL;

    // Fast path: blocking shared lock for concurrent read access (multiple readers allowed)
    {
        std::shared_lock<SrwSharedMutex> lock(*MemoryUtilsCacheInternal::s_shardMutexes[shard_idx]);
        CachedMemoryRegionInfo *cached_info = MemoryUtilsCacheInternal::find_in_shard(
            MemoryUtilsCacheInternal::s_cacheShards[shard_idx],
            query_addr_val, size, now_ns, expiry_ns);
        if (cached_info)
        {
            MemoryUtilsCacheInternal::s_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
            return MemoryUtilsCacheInternal::check_write_permission(cached_info->protection);
        }
    }

    MemoryUtilsCacheInternal::s_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);

    MEMORY_BASIC_INFORMATION mbi;
    if (!MemoryUtilsCacheInternal::query_and_update_cache(shard_idx, address, mbi))
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    if (!MemoryUtilsCacheInternal::check_write_permission(mbi.Protect))
        return false;

    const uintptr_t region_start_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    const uintptr_t region_end_addr = region_start_addr + mbi.RegionSize;
    const uintptr_t query_end_addr = query_addr_val + size;

    if (query_end_addr < query_addr_val)
        return false;

    return query_addr_val >= region_start_addr && query_end_addr <= region_end_addr;
}

std::expected<void, MemoryError> DetourModKit::Memory::write_bytes(std::byte *targetAddress, const std::byte *sourceBytes, size_t numBytes, Logger &logger)
{
    if (!targetAddress)
    {
        logger.error("write_bytes: Target address is null.");
        return std::unexpected(MemoryError::NullTargetAddress);
    }
    if (!sourceBytes && numBytes > 0)
    {
        logger.error("write_bytes: Source bytes pointer is null for non-zero numBytes.");
        return std::unexpected(MemoryError::NullSourceBytes);
    }
    if (numBytes == 0)
    {
        logger.warning("write_bytes: Number of bytes to write is zero. Operation has no effect.");
        return {};
    }

    DWORD old_protection_flags;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(targetAddress), numBytes, PAGE_EXECUTE_READWRITE, &old_protection_flags))
    {
        logger.error("write_bytes: VirtualProtect failed to set PAGE_EXECUTE_READWRITE at address {}. Windows Error: {}",
                     DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(targetAddress)), GetLastError());
        return std::unexpected(MemoryError::ProtectionChangeFailed);
    }

    memcpy(reinterpret_cast<void *>(targetAddress), reinterpret_cast<const void *>(sourceBytes), numBytes);

    DWORD temp_old_protect;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(targetAddress), numBytes, old_protection_flags, &temp_old_protect))
    {
        logger.error("write_bytes: VirtualProtect failed to restore original protection ({}) at address {}. Windows Error: {}. Memory may remain writable!",
                     DetourModKit::Format::format_hex(static_cast<int>(old_protection_flags)),
                     DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(targetAddress)), GetLastError());
        return std::unexpected(MemoryError::ProtectionRestoreFailed);
    }

    if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(targetAddress), numBytes))
    {
        logger.warning("write_bytes: FlushInstructionCache failed for address {}. Windows Error: {}",
                       DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(targetAddress)), GetLastError());
    }

    Memory::invalidate_range(targetAddress, numBytes);

    logger.debug("write_bytes: Successfully wrote {} bytes to address {}.",
                 numBytes, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(targetAddress)));
    return {};
}
