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
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/logger.hpp"
#include "platform.hpp"

#include <windows.h>
#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)
#include <intrin.h> // __movsb -- ASan-safe copy in the SEH probe read
#endif
#include <shared_mutex>
#include <unordered_map>
#include <map>
#include <vector>
#include <chrono>
#include <atomic>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cstddef>
#include <thread>
#include <condition_variable>

using namespace DetourModKit;

using DetourModKit::detail::is_loader_lock_held;
using DetourModKit::detail::pin_current_module;

// Anonymous namespace for internal helpers and storage
namespace
{
    // Page-protection flag groups for the cache permission checks. Grouped in a
    // struct rather than a named namespace so the constants keep internal
    // linkage through the enclosing anonymous namespace, per the .cpp
    // internal-linkage convention.
    struct CachePermissions
    {
        static constexpr DWORD READ_PERMISSION_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        static constexpr DWORD WRITE_PERMISSION_FLAGS = PAGE_READWRITE | PAGE_WRITECOPY |
                                                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        static constexpr DWORD NOACCESS_GUARD_FLAGS = PAGE_NOACCESS | PAGE_GUARD;
    };

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
        SrwSharedMutex() noexcept { InitializeSRWLock(&m_srw); }

        SrwSharedMutex(const SrwSharedMutex &) = delete;
        SrwSharedMutex &operator=(const SrwSharedMutex &) = delete;

        void lock() noexcept { AcquireSRWLockExclusive(&m_srw); }
        bool try_lock() noexcept { return TryAcquireSRWLockExclusive(&m_srw) != 0; }
        void unlock() noexcept { ReleaseSRWLockExclusive(&m_srw); }

        void lock_shared() noexcept { AcquireSRWLockShared(&m_srw); }
        bool try_lock_shared() noexcept { return TryAcquireSRWLockShared(&m_srw) != 0; }
        void unlock_shared() noexcept { ReleaseSRWLockShared(&m_srw); }

    private:
        SRWLOCK m_srw;
    };

    /**
     * @struct CachedMemoryRegionInfo
     * @brief Structure to hold cached memory region information.
     * @details Uses timestamp for thread-safe updates and reduced memory footprint.
     */
    struct CachedMemoryRegionInfo
    {
        uintptr_t base_address;
        size_t region_size;
        DWORD protection;
        DWORD state;
        uint64_t timestamp_ns;
        uint64_t lru_key;
        bool valid;

        CachedMemoryRegionInfo()
            : base_address(0), region_size(0), protection(0), state(0), timestamp_ns(0), lru_key(0), valid(false)
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
        // Map from base_address -> CachedMemoryRegionInfo for O(1) lookup by address
        std::unordered_map<uintptr_t, CachedMemoryRegionInfo> entries;
        // Map from monotonic counter -> base_address for O(log n) oldest-entry lookup (LRU)
        // Monotonic counter guarantees insertion-order uniqueness for correct eviction
        std::map<uint64_t, uintptr_t> lru_index;
        // Sorted by base address for O(log n) containment lookup
        // {base, base+size}
        std::vector<std::pair<uintptr_t, uintptr_t>> sorted_ranges;
        uint64_t entry_counter{0};
        size_t capacity;
        size_t max_capacity;

        CacheShard()
            : capacity(0), max_capacity(0)
        {
            entries.reserve(64);
            sorted_ranges.reserve(64);
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
        return (static_cast<size_t>((address * 0x9E3779B97F4A7C15ULL) >> 48)) % shard_count;
    }
} // namespace

// Internal static variables and helper functions for memory cache.
// Anonymous namespace ensures internal linkage, preventing ODR violations
// if this translation unit's declarations were ever duplicated.
namespace
{
    std::vector<CacheShard> s_cache_shards;
    std::vector<std::unique_ptr<SrwSharedMutex>> s_shard_mutexes;
    std::unique_ptr<std::atomic<char>[]> s_in_flight;
    std::atomic<size_t> s_shard_count{0};
    std::atomic<size_t> s_max_entries_per_shard{0};
    std::atomic<unsigned int> s_configured_expiry_ms{0};
    std::atomic<bool> s_cache_initialized{false};

    // Global cache state mutex to serialize init/clear/shutdown transitions
    // Protects against concurrent state changes that could leave vectors in invalid state
    std::mutex s_cache_state_mutex;

    // Epoch-based reader tracking to prevent use-after-free during shutdown.
    // Readers increment on entry to is_readable/is_writable and decrement on exit.
    // shutdown_cache waits for this to reach zero before destroying data structures.
    std::atomic<int32_t> s_active_readers{0};

    /**
     * @class ActiveReaderGuard
     * @brief RAII guard that increments s_active_readers on construction and
     *        decrements on destruction, ensuring correct pairing on all exit paths.
     */
    class ActiveReaderGuard
    {
    public:
        ActiveReaderGuard() noexcept
        {
            // seq_cst (not acq_rel) so this increment and the reader's
            // subsequent seq_cst load of s_cache_initialized share the single
            // total order that forbids the store-buffering (Dekker) outcome with
            // shutdown_cache: shutdown stores s_cache_initialized=false then loads
            // s_active_readers, while a reader increments s_active_readers then
            // loads s_cache_initialized. Under seq_cst a reader that observes the
            // cache live was necessarily counted before shutdown reads the reader
            // count, so shutdown cannot free shard data out from under it. On
            // x86-64 this is the same lock xadd as acq_rel, so the hot path pays
            // nothing.
            s_active_readers.fetch_add(1, std::memory_order_seq_cst);
        }

        ~ActiveReaderGuard() noexcept
        {
            s_active_readers.fetch_sub(1, std::memory_order_release);
        }

        ActiveReaderGuard(const ActiveReaderGuard &) = delete;
        ActiveReaderGuard &operator=(const ActiveReaderGuard &) = delete;
    };

    // Background cleanup thread.
    // Uses std::thread (not jthread) because these are namespace-scope statics:
    // jthread's auto-join destructor would run after s_cleanup_cv/s_cleanup_mutex
    // are destroyed (reverse declaration order), causing UB. Manual join in
    // shutdown_cache() avoids this. DMK_Shutdown() calls shutdown_cache()
    // which joins this thread before any other cleanup proceeds, ensuring
    // the thread is fully stopped before static destruction begins.
    std::atomic<bool> s_cleanup_thread_running{false};
    std::thread s_cleanup_thread;
    std::mutex s_cleanup_mutex;
    std::condition_variable s_cleanup_cv;
    std::atomic<bool> s_cleanup_requested{false};

    // On-demand cleanup fallback timer (used when background thread is disabled)
    std::atomic<uint64_t> s_last_cleanup_time_ns{0};
    // 1 second in nanoseconds
    constexpr uint64_t CLEANUP_INTERVAL_NS = 1'000'000'000ULL;

    // Always-available cache statistics
    struct CacheStats
    {
        std::atomic<uint64_t> cache_hits{0};
        std::atomic<uint64_t> cache_misses{0};
        std::atomic<uint64_t> invalidations{0};
        std::atomic<uint64_t> coalesced_queries{0};
        std::atomic<uint64_t> on_demand_cleanups{0};
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

        const uintptr_t end_address = address + size;
        if (end_address < address)
            return false;

        const uintptr_t entry_end_address = entry.base_address + entry.region_size;
        if (entry_end_address < entry.base_address)
            return false;

        return address >= entry.base_address && end_address <= entry_end_address;
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
     * @brief Inserts a range into the shard's sorted auxiliary vector.
     * @note Must be called with shard mutex held (exclusive).
     */
    void insert_sorted_range(CacheShard &shard, uintptr_t base_addr, size_t region_size) noexcept
    {
        auto range = std::make_pair(base_addr, base_addr + region_size);
        auto pos = std::lower_bound(shard.sorted_ranges.begin(),
                                    shard.sorted_ranges.end(), range);
        shard.sorted_ranges.insert(pos, range);
    }

    /**
     * @brief Removes a range from the shard's sorted auxiliary vector.
     * @note Must be called with shard mutex held (exclusive).
     */
    void remove_sorted_range(CacheShard &shard, uintptr_t base_addr) noexcept
    {
        auto it = std::lower_bound(shard.sorted_ranges.begin(),
                                   shard.sorted_ranges.end(),
                                   std::make_pair(base_addr, uintptr_t{0}));
        if (it != shard.sorted_ranges.end() && it->first == base_addr)
            shard.sorted_ranges.erase(it);
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
     *       then falls back to O(log n) binary search via sorted_ranges for addresses
     *       within larger regions.
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

        // Slow path: O(log n) containment lookup via sorted ranges.
        // Finds the last range starting at or before the queried address,
        // then verifies containment and entry validity.
        auto range_it = std::upper_bound(shard.sorted_ranges.begin(),
                                         shard.sorted_ranges.end(),
                                         std::make_pair(address, UINTPTR_MAX));
        if (range_it != shard.sorted_ranges.begin())
        {
            --range_it;
            if (address >= range_it->first && address < range_it->second)
            {
                auto entry_it = shard.entries.find(range_it->first);
                if (entry_it != shard.entries.end())
                {
                    CachedMemoryRegionInfo &entry = entry_it->second;
                    if (is_entry_valid_and_covers(entry, address, size, current_time_ns, expiry_ns))
                    {
                        return &entry;
                    }
                }
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
            remove_sorted_range(shard, oldest_base);
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

            // Update sorted range if region size changed
            if (old_entry.region_size != mbi.RegionSize)
            {
                remove_sorted_range(shard, base_addr);
                insert_sorted_range(shard, base_addr, mbi.RegionSize);
            }

            // Update existing entry with new monotonic LRU key
            const uint64_t new_lru_key = shard.entry_counter++;
            old_entry.base_address = base_addr;
            old_entry.region_size = mbi.RegionSize;
            old_entry.protection = mbi.Protect;
            old_entry.state = mbi.State;
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
            new_entry.base_address = base_addr;
            new_entry.region_size = mbi.RegionSize;
            new_entry.protection = mbi.Protect;
            new_entry.state = mbi.State;
            new_entry.timestamp_ns = current_time_ns;
            new_entry.lru_key = new_lru_key;
            new_entry.valid = true;

            shard.entries.insert_or_assign(base_addr, std::move(new_entry));
            shard.lru_index.emplace(new_lru_key, base_addr);
            insert_sorted_range(shard, base_addr, mbi.RegionSize);
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

                remove_sorted_range(shard, entry.base_address);
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
        std::unique_lock<std::mutex> lock(s_cache_state_mutex, std::defer_lock);
        if (force)
        {
            lock.lock();
        }
        else if (!lock.try_lock())
        {
            return; // Shutdown or forced cleanup in progress, skip
        }

        if (s_cache_shards.empty())
            return;

        const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
        if (shard_count == 0)
            return;

        const uint64_t current_ts = current_time_ns();
        const uint64_t expiry_ns = static_cast<uint64_t>(s_configured_expiry_ms.load(std::memory_order_acquire)) * 1'000'000ULL;

        for (size_t i = 0; i < shard_count; ++i)
        {
            std::unique_lock<SrwSharedMutex> shard_lock(*s_shard_mutexes[i], std::try_to_lock);
            if (shard_lock.owns_lock())
            {
                cleanup_expired_entries_in_shard(s_cache_shards[i], current_ts, expiry_ns);
                // Also trim to hard upper bound
                trim_to_max_capacity(s_cache_shards[i]);
            }
        }
    }

    /**
     * @brief Checks if on-demand cleanup should run based on elapsed time.
     * @return true if cleanup was performed, false otherwise.
     */
    bool try_trigger_on_demand_cleanup() noexcept
    {
        if (!s_cache_initialized.load(std::memory_order_seq_cst))
            return false;

        const uint64_t now_ns = current_time_ns();
        const uint64_t last_cleanup = s_last_cleanup_time_ns.load(std::memory_order_acquire);
        const uint64_t elapsed_ns = now_ns - last_cleanup;

        if (elapsed_ns >= CLEANUP_INTERVAL_NS)
        {
            // Atomically update last cleanup time to prevent multiple threads triggering
            uint64_t expected = last_cleanup;
            if (s_last_cleanup_time_ns.compare_exchange_strong(expected, now_ns, std::memory_order_acq_rel))
            {
                cleanup_expired_entries(false);
                s_stats.on_demand_cleanups.fetch_add(1, std::memory_order_relaxed);
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
        while (s_cleanup_thread_running.load(std::memory_order_acquire))
        {
            {
                std::unique_lock<std::mutex> lock(s_cleanup_mutex);
                s_cleanup_cv.wait_for(lock, std::chrono::seconds(1), [&]()
                                      { return s_cleanup_requested.load(std::memory_order_acquire) || !s_cleanup_thread_running.load(std::memory_order_acquire); });
            }

            if (!s_cleanup_thread_running.load(std::memory_order_acquire))
                break;

            // force=true to hold state mutex during vector iteration
            cleanup_expired_entries(true);
            s_cleanup_requested.store(false, std::memory_order_relaxed);
        }
    }

    /**
     * @brief Signals the cleanup thread to run or triggers on-demand cleanup.
     */
    void request_cleanup() noexcept
    {
        if (s_cleanup_thread_running.load(std::memory_order_acquire))
        {
            s_cleanup_requested.store(true, std::memory_order_relaxed);
            s_cleanup_cv.notify_one();
        }
        else
        {
            // Background thread disabled (MinGW) - use on-demand timer-based cleanup
            try_trigger_on_demand_cleanup();
        }
    }

    /**
     * @brief Evicts every entry in a shard whose region overlaps [address, end_address).
     * @param shard The cache shard to scan.
     * @param address Inclusive start of the invalidated range.
     * @param end_address Exclusive end of the invalidated range (wrap-clamped by the caller).
     * @return Number of entries evicted.
     * @note Must be called with the shard mutex held (exclusive).
     * @note Scans the whole shard rather than probing a single key. An entry is keyed by its
     *       VirtualQuery region base, but it is stored in the shard chosen from the original
     *       query address (compute_shard_index mixes the full address, not the region base),
     *       so one region can be cached in several shards under the same base key. A single
     *       key/shard probe therefore cannot locate every covering entry; only a per-shard
     *       containment scan can. The shard is bounded by max_capacity and invalidation runs
     *       only after a write, so this linear scan is never on a read hot path.
     */
    size_t evict_overlapping_entries_in_shard(CacheShard &shard,
                                              uintptr_t address,
                                              uintptr_t end_address) noexcept
    {
        size_t evicted = 0;
        auto it = shard.entries.begin();
        while (it != shard.entries.end())
        {
            const CachedMemoryRegionInfo &entry = it->second;
            const uintptr_t entry_end_address = entry.base_address + entry.region_size;
            // A VirtualQuery region cannot extend past the address space, but a corrupt
            // cached size could; treat a wrapped end as covering the top of the space so a
            // poisoned entry is still evicted rather than skipped.
            const uintptr_t clamped_entry_end = (entry_end_address < entry.base_address)
                                                    ? UINTPTR_MAX
                                                    : entry_end_address;
            const bool overlaps = entry.valid &&
                                  address < clamped_entry_end &&
                                  end_address > entry.base_address;
            if (overlaps)
            {
                // Drop the LRU back-reference by the stored key so no tombstone accumulates.
                const auto lru_it = shard.lru_index.find(entry.lru_key);
                if (lru_it != shard.lru_index.end() && lru_it->second == it->first)
                {
                    shard.lru_index.erase(lru_it);
                }
                remove_sorted_range(shard, entry.base_address);
                it = shard.entries.erase(it);
                s_stats.invalidations.fetch_add(1, std::memory_order_relaxed);
                ++evicted;
            }
            else
            {
                ++it;
            }
        }
        return evicted;
    }

    /**
     * @brief Invalidates cache entries overlapping [address, address + size) across all shards.
     * @details Every shard is scanned because an entry's storage shard is derived from the
     *          original query address, not its region base, so a covering entry may live in
     *          any shard (see evict_overlapping_entries_in_shard). A bounded try-lock retry
     *          per shard keeps the writer that triggered the invalidation from blocking on a
     *          momentarily contended shard.
     */
    void invalidate_range_internal(uintptr_t address, size_t size) noexcept
    {
        if (s_cache_shards.empty() || size == 0)
            return;

        // Guard against address + size wrapping around the address space.
        const uintptr_t end_address = (address + size < address) ? UINTPTR_MAX : address + size;
        const size_t shard_count = s_shard_count.load(std::memory_order_acquire);

        constexpr size_t MAX_INVALIDATION_RETRIES = 3;

        for (size_t shard_idx = 0; shard_idx < shard_count; ++shard_idx)
        {
            for (size_t retry = 0; retry < MAX_INVALIDATION_RETRIES; ++retry)
            {
                std::unique_lock<SrwSharedMutex> lock(*s_shard_mutexes[shard_idx], std::try_to_lock);
                if (!lock.owns_lock())
                {
                    // Shard is held by another writer - yield and retry rather than block.
                    if (retry < MAX_INVALIDATION_RETRIES - 1)
                    {
                        std::this_thread::yield();
                    }
                    continue;
                }

                evict_overlapping_entries_in_shard(s_cache_shards[shard_idx], address, end_address);
                break;
            }
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
        // Hard upper bound: 2x capacity
        const size_t hard_max_per_shard = entries_per_shard * 2;

        try
        {
            s_cache_shards.resize(shard_count);
            s_shard_mutexes.resize(shard_count);
            s_in_flight = std::make_unique<std::atomic<char>[]>(shard_count);
            for (size_t i = 0; i < shard_count; ++i)
            {
                s_cache_shards[i].entries.reserve(entries_per_shard * 2);
                s_cache_shards[i].sorted_ranges.reserve(entries_per_shard * 2);
                s_cache_shards[i].capacity = entries_per_shard;
                s_cache_shards[i].max_capacity = hard_max_per_shard;
                s_shard_mutexes[i] = std::make_unique<SrwSharedMutex>();
                s_in_flight[i].store(0, std::memory_order_relaxed);
            }
        }
        catch (const std::bad_alloc &)
        {
            Logger::get_instance().error("MemoryCache: Failed to allocate memory for cache shards.");
            s_cache_shards.clear();
            s_shard_mutexes.clear();
            s_in_flight.reset();
            // Reset initialization flag so retry can work
            s_cache_initialized.store(false, std::memory_order_relaxed);
            return false;
        }

        s_shard_count.store(shard_count, std::memory_order_release);
        s_max_entries_per_shard.store(entries_per_shard, std::memory_order_release);
        s_configured_expiry_ms.store(expiry_ms, std::memory_order_release);
        s_last_cleanup_time_ns.store(current_time_ns(), std::memory_order_release);

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
        CacheShard &shard = s_cache_shards[shard_idx];

        // Try to claim in-flight status (stampede coalescing)
        char expected = 0;
        if (s_in_flight[shard_idx].compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
        {
            // We are the leader - perform VirtualQuery
            const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
            const uint64_t now_ns = current_time_ns();

            if (result)
            {
                std::unique_lock<SrwSharedMutex> lock(*s_shard_mutexes[shard_idx]);
                update_shard_with_region(shard, mbi_out, now_ns);
            }

            // Release in-flight status
            s_in_flight[shard_idx].store(0, std::memory_order_release);
            return result;
        }
        else
        {
            // We are a follower - VirtualQuery already in progress by another thread.
            // Bounded wait to avoid stalling game threads on render-critical paths.
            const uint64_t expiry_ns = static_cast<uint64_t>(s_configured_expiry_ms.load(std::memory_order_acquire)) * 1'000'000ULL;
            constexpr size_t MAX_FOLLOWER_YIELDS = 8;

            for (size_t yield_count = 0; yield_count < MAX_FOLLOWER_YIELDS; ++yield_count)
            {
                if (s_in_flight[shard_idx].load(std::memory_order_acquire) == 0)
                {
                    // Query completed, check cache
                    const uintptr_t addr_val = reinterpret_cast<uintptr_t>(address);
                    std::shared_lock<SrwSharedMutex> lock(*s_shard_mutexes[shard_idx]);
                    CachedMemoryRegionInfo *cached = find_in_shard(shard, addr_val, 1, current_time_ns(), expiry_ns);
                    if (cached)
                    {
                        s_stats.coalesced_queries.fetch_add(1, std::memory_order_relaxed);
                        // Copy cached info to output for consistency
                        mbi_out.BaseAddress = reinterpret_cast<PVOID>(cached->base_address);
                        mbi_out.RegionSize = cached->region_size;
                        mbi_out.Protect = cached->protection;
                        mbi_out.State = cached->state;
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
            if (s_in_flight[shard_idx].compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
            {
                const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                if (result)
                {
                    std::unique_lock<SrwSharedMutex> lock(*s_shard_mutexes[shard_idx]);
                    const uint64_t now_ns = current_time_ns();
                    update_shard_with_region(shard, mbi_out, now_ns);
                }
                s_in_flight[shard_idx].store(0, std::memory_order_release);
                return result;
            }

            // Last resort: just do VirtualQuery without cache update
            return VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
        }
    }

} // namespace

bool DetourModKit::Memory::init_cache(size_t cache_size, unsigned int expiry_ms, size_t shard_count)
{
    // Hold state mutex to prevent concurrent clear_cache or shutdown_cache
    // This serializes init/clear/shutdown transitions to ensure vectors are not accessed while being resized or cleared
    std::lock_guard<std::mutex> state_lock(s_cache_state_mutex);

    // Fast path: already initialized
    if (s_cache_initialized.load(std::memory_order_seq_cst))
        return true;

    // Try to initialize
    bool expected = false;
    if (s_cache_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        if (!perform_cache_initialization(cache_size, expiry_ms, shard_count))
        {
            // Initialization failed - s_cache_initialized already reset to false in perform_cache_initialization
            return false;
        }

        // Try to start background cleanup thread (may fail silently on MinGW)
        s_cleanup_thread_running.store(true, std::memory_order_release);
        try
        {
            s_cleanup_thread = std::thread(cleanup_thread_func);
        }
        catch (const std::system_error &)
        {
            // Background thread creation failed (MinGW pthreads issue) - use on-demand cleanup
            s_cleanup_thread_running.store(false, std::memory_order_release);
            Logger::get_instance().debug("MemoryCache: Background cleanup thread unavailable, using on-demand cleanup.");
        }

        // Register atexit handler as a last-resort safety net in case the
        // consumer forgets to call shutdown_cache() / DMK_Shutdown().
        // Prevents std::terminate from the joinable std::thread destructor.
        // The handler detects loader-lock context (FreeLibrary) and skips
        // the thread join to avoid deadlock.
        static bool atexit_registered = false;
        if (!atexit_registered)
        {
            std::atexit([]()
                        {
                if (s_cache_initialized.load(std::memory_order_seq_cst))
                {
                    if (is_loader_lock_held())
                    {
                        // Under loader lock (FreeLibrary path): pin the module
                        // so code pages remain valid for the detached thread,
                        // then signal it to stop and detach.
                        s_cleanup_thread_running.store(false, std::memory_order_release);
                        s_cleanup_cv.notify_one();
                        if (s_cleanup_thread.joinable())
                        {
                            pin_current_module();
                            s_cleanup_thread.detach();
                            DetourModKit::Diagnostics::record_intentional_leak(DetourModKit::Diagnostics::LeakSubsystem::MemoryCache);
                        }
                        s_cache_initialized.store(false, std::memory_order_release);
                        return;
                    }
                    Memory::shutdown_cache();
                } });
            atexit_registered = true;
        }

        return true;
    }

    // Another thread initialized while we were waiting
    return true;
}

void DetourModKit::Memory::clear_cache()
{
    // Hold state mutex to serialize with shutdown and cleanup thread
    std::lock_guard<std::mutex> state_lock(s_cache_state_mutex);

    if (!s_cache_initialized.load(std::memory_order_seq_cst))
        return;

    const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
    if (shard_count == 0)
        return;

    // Acquire exclusive lock on each shard and clear entries.
    // Uses blocking lock to guarantee all entries are cleared.
    // The background cleanup thread uses try_to_lock on shard mutexes,
    // so it will skip shards we hold without deadlocking.
    for (size_t i = 0; i < shard_count; ++i)
    {
        auto &mutex_ptr = s_shard_mutexes[i];
        if (mutex_ptr)
        {
            std::unique_lock<SrwSharedMutex> shard_lock(*mutex_ptr);
            s_cache_shards[i].entries.clear();
            s_cache_shards[i].lru_index.clear();
            s_cache_shards[i].sorted_ranges.clear();
            s_in_flight[i].store(0, std::memory_order_relaxed);
        }
    }

    s_stats.cache_hits.store(0, std::memory_order_relaxed);
    s_stats.cache_misses.store(0, std::memory_order_relaxed);
    s_stats.invalidations.store(0, std::memory_order_relaxed);
    s_stats.coalesced_queries.store(0, std::memory_order_relaxed);
    s_stats.on_demand_cleanups.store(0, std::memory_order_relaxed);

    s_last_cleanup_time_ns.store(current_time_ns(), std::memory_order_relaxed);

    Logger::get_instance().debug("MemoryCache: All entries cleared.");
}

void DetourModKit::Memory::shutdown_cache()
{
    // Signal and join cleanup thread BEFORE acquiring state mutex.
    // The cleanup thread acquires s_cache_state_mutex in cleanup_expired_entries(force=true),
    // so joining while holding the state mutex would deadlock.
    s_cleanup_thread_running.store(false, std::memory_order_release);
    s_cleanup_cv.notify_one();

    if (s_cleanup_thread.joinable())
    {
        if (is_loader_lock_held())
        {
            // Under loader lock (DllMain / FreeLibrary): thread join would
            // deadlock because the cleanup thread cannot exit while the
            // loader lock is held. Pin the module so code and static data
            // remain valid, then detach. The thread will observe the stop
            // flag and exit on its own.
            pin_current_module();
            s_cleanup_thread.detach();
            DetourModKit::Diagnostics::record_intentional_leak(DetourModKit::Diagnostics::LeakSubsystem::MemoryCache);
        }
        else
        {
            s_cleanup_thread.join();
        }
    }

    // Acquire state mutex to serialize with clear_cache and protect data teardown
    std::lock_guard<std::mutex> state_lock(s_cache_state_mutex);

    // Mark as not initialized and zero shard count so new readers do not enter
    // the critical section. The s_cache_initialized store is seq_cst (not just
    // release): it pairs with the reader's seq_cst load in the ActiveReaderGuard
    // protocol so the store-buffering (Dekker) race against the reader-count
    // load below is forbidden by the single total order. s_shard_count stays
    // release because readers only read it after passing the seq_cst
    // s_cache_initialized gate.
    s_cache_initialized.store(false, std::memory_order_seq_cst);
    s_shard_count.store(0, std::memory_order_release);

    // Wait for in-flight readers to finish before destroying data structures.
    // Readers increment s_active_readers on entry and decrement on exit.
    // ActiveReaderGuard is RAII so readers always decrement; this loop is
    // bounded by the maximum time a single cache lookup can take.
    // Escalate from yield to sleep to avoid burning CPU if a reader is
    // preempted by the OS scheduler.
    constexpr int yield_spins = 4096;
    int spins = 0;
    while (s_active_readers.load(std::memory_order_seq_cst) > 0)
    {
        if (spins < yield_spins)
        {
            std::this_thread::yield();
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        ++spins;
    }

    // All readers have exited - safe to destroy data structures
    const size_t shard_count = s_cache_shards.size();
    for (size_t i = 0; i < shard_count; ++i)
    {
        if (s_shard_mutexes[i])
        {
            std::unique_lock<SrwSharedMutex> shard_lock(*s_shard_mutexes[i]);
            s_cache_shards[i].entries.clear();
            s_cache_shards[i].lru_index.clear();
            s_cache_shards[i].sorted_ranges.clear();
        }
    }

    s_cache_shards.clear();
    s_shard_mutexes.clear();
    s_in_flight.reset();

    // Reset all stats and config so a subsequent init_cache starts from a clean state
    s_stats.cache_hits.store(0, std::memory_order_relaxed);
    s_stats.cache_misses.store(0, std::memory_order_relaxed);
    s_stats.invalidations.store(0, std::memory_order_relaxed);
    s_stats.coalesced_queries.store(0, std::memory_order_relaxed);
    s_stats.on_demand_cleanups.store(0, std::memory_order_relaxed);
    s_last_cleanup_time_ns.store(0, std::memory_order_relaxed);
    s_configured_expiry_ms.store(0, std::memory_order_relaxed);
    s_max_entries_per_shard.store(0, std::memory_order_relaxed);
    s_cleanup_requested.store(false, std::memory_order_relaxed);

    Logger::get_instance().debug("MemoryCache: Shutdown complete.");
}

std::string DetourModKit::Memory::get_cache_stats()
{
    const uint64_t hits = s_stats.cache_hits.load(std::memory_order_relaxed);
    const uint64_t misses = s_stats.cache_misses.load(std::memory_order_relaxed);
    const uint64_t invalidations = s_stats.invalidations.load(std::memory_order_relaxed);
    const uint64_t coalesced = s_stats.coalesced_queries.load(std::memory_order_relaxed);
    const uint64_t on_demand_cleanups = s_stats.on_demand_cleanups.load(std::memory_order_relaxed);
    const uint64_t total_queries = hits + misses;

    const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
    const size_t max_entries_per_shard = s_max_entries_per_shard.load(std::memory_order_acquire);
    const unsigned int expiry_ms = s_configured_expiry_ms.load(std::memory_order_acquire);

    // Calculate total entries and hard max with reader guard
    size_t total_entries = 0;
    size_t total_hard_max = 0;

    {
        ActiveReaderGuard reader_guard;
        const size_t active_shard_count = s_shard_count.load(std::memory_order_acquire);
        for (size_t i = 0; i < active_shard_count; ++i)
        {
            auto &mutex_ptr = s_shard_mutexes[i];
            if (mutex_ptr)
            {
                std::shared_lock<SrwSharedMutex> shard_lock(*mutex_ptr);
                total_entries += s_cache_shards[i].entries.size();
                total_hard_max += s_cache_shards[i].max_capacity;
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

    // Construct reader guard BEFORE checking s_cache_initialized to prevent
    // shutdown_cache from destroying data structures between the check and access.
    ActiveReaderGuard reader_guard;

    if (!s_cache_initialized.load(std::memory_order_seq_cst))
        return;

    const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
    if (shard_count == 0)
        return;

    const uintptr_t addr_val = reinterpret_cast<uintptr_t>(address);
    invalidate_range_internal(addr_val, size);

    // request_cleanup may trigger on-demand cleanup_expired_entries(force=false)
    // which iterates shards without s_cache_state_mutex. Keep s_active_readers > 0
    // so shutdown_cache cannot destroy shards during the cleanup pass.
    request_cleanup();
}

namespace
{
    /**
     * @brief Unified permission check for is_readable/is_writable.
     * @details Parameterized by permission checker to avoid duplicating the
     *          cache lookup, VirtualQuery fallback, and range validation logic.
     * @param address Starting address of the memory region.
     * @param size Number of bytes in the memory region to check.
     * @param check_permission Function that validates protection flags.
     * @return true if the entire region has the requested permission.
     */
    bool check_memory_permission(const void *address, size_t size,
                                 bool (*check_permission)(DWORD) noexcept) noexcept
    {
        if (!address || size == 0)
            return false;

        // Construct reader guard BEFORE checking s_cache_initialized to prevent
        // shutdown_cache from destroying data structures between the check and access.
        ActiveReaderGuard reader_guard;

        if (!s_cache_initialized.load(std::memory_order_seq_cst))
        {
            // Cache not initialized -- fall back to direct VirtualQuery
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(address, &mbi, sizeof(mbi)))
                return false;
            if (mbi.State != MEM_COMMIT)
                return false;
            if (!check_permission(mbi.Protect))
                return false;
            const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
            const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t query_end = query_addr_val + size;
            if (query_end < query_addr_val)
                return false;
            return query_addr_val >= region_start && query_end <= region_start + mbi.RegionSize;
        }

        // Reader guard already active -- safe to access cache data structures

        const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
        if (shard_count == 0)
            return false;

        const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
        const size_t shard_idx = compute_shard_index(query_addr_val, shard_count);
        const uint64_t now_ns = current_time_ns();
        const uint64_t expiry_ns = static_cast<uint64_t>(s_configured_expiry_ms.load(std::memory_order_acquire)) * 1'000'000ULL;

        // Fast path: blocking shared lock for concurrent read access (multiple readers allowed)
        {
            std::shared_lock<SrwSharedMutex> lock(*s_shard_mutexes[shard_idx]);
            CachedMemoryRegionInfo *cached_info = find_in_shard(
                s_cache_shards[shard_idx],
                query_addr_val, size, now_ns, expiry_ns);
            if (cached_info)
            {
                s_stats.cache_hits.fetch_add(1, std::memory_order_relaxed);
                return check_permission(cached_info->protection);
            }
        }

        s_stats.cache_misses.fetch_add(1, std::memory_order_relaxed);

        // Cache miss: call VirtualQuery with stampede coalescing
        MEMORY_BASIC_INFORMATION mbi;
        if (!query_and_update_cache(shard_idx, address, mbi))
            return false;

        if (mbi.State != MEM_COMMIT)
            return false;

        if (!check_permission(mbi.Protect))
            return false;

        const uintptr_t region_start_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t region_end_addr = region_start_addr + mbi.RegionSize;
        const uintptr_t query_end_addr = query_addr_val + size;

        if (query_end_addr < query_addr_val)
            return false;

        return query_addr_val >= region_start_addr && query_end_addr <= region_end_addr;
    }
} // anonymous namespace

bool DetourModKit::Memory::is_readable(const void *address, size_t size)
{
    return check_memory_permission(address, size, check_read_permission);
}

bool DetourModKit::Memory::is_writable(void *address, size_t size)
{
    return check_memory_permission(address, size, check_write_permission);
}

std::expected<void, MemoryError> DetourModKit::Memory::write_bytes(std::byte *target_address, const std::byte *source_bytes, size_t num_bytes)
{
    auto &logger = Logger::get_instance();

    if (!target_address)
    {
        logger.error("write_bytes: Target address is null.");
        return std::unexpected(MemoryError::NullTargetAddress);
    }
    if (!source_bytes && num_bytes > 0)
    {
        logger.error("write_bytes: Source bytes pointer is null for non-zero num_bytes.");
        return std::unexpected(MemoryError::NullSourceBytes);
    }
    if (num_bytes == 0)
    {
        logger.warning("write_bytes: Number of bytes to write is zero. Operation has no effect.");
        return {};
    }
    if (num_bytes > MAX_WRITE_SIZE)
    {
        logger.error("write_bytes: Requested size {} exceeds MAX_WRITE_SIZE ({}).", num_bytes, MAX_WRITE_SIZE);
        return std::unexpected(MemoryError::SizeTooLarge);
    }

    DWORD old_protection_flags;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(target_address), num_bytes, PAGE_EXECUTE_READWRITE, &old_protection_flags))
    {
        logger.error("write_bytes: VirtualProtect failed to set PAGE_EXECUTE_READWRITE at address {}. Windows Error: {}",
                     DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(target_address)), GetLastError());
        return std::unexpected(MemoryError::ProtectionChangeFailed);
    }

    memcpy(reinterpret_cast<void *>(target_address), reinterpret_cast<const void *>(source_bytes), num_bytes);

    // The bytes are now modified. The instruction-cache flush and the DMK
    // cache-range invalidation must run on every path from here -- they are
    // promised unconditionally, and skipping them after a write would leave stale
    // cached state for bytes that have already changed. Restore the original page
    // protection first so its outcome can be reported, but keep that out of an
    // early return: the cleanup below is a single unconditional block, so the
    // restore-failure path runs exactly the same maintenance as the success path
    // by construction and cannot diverge.
    DWORD temp_old_protect;
    const bool restore_succeeded =
        VirtualProtect(reinterpret_cast<LPVOID>(target_address), num_bytes, old_protection_flags, &temp_old_protect) != FALSE;
    if (!restore_succeeded)
    {
        logger.error("write_bytes: VirtualProtect failed to restore original protection ({}) at address {}. Windows Error: {}. Memory may remain writable!",
                     DetourModKit::Format::format_hex(static_cast<int>(old_protection_flags)),
                     DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(target_address)), GetLastError());
    }

    if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(target_address), num_bytes))
    {
        logger.warning("write_bytes: FlushInstructionCache failed for address {}. Windows Error: {}",
                       DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(target_address)), GetLastError());
    }

    Memory::invalidate_range(target_address, num_bytes);

    // Surface the restore failure only after cache maintenance has run.
    if (!restore_succeeded)
    {
        return std::unexpected(MemoryError::ProtectionRestoreFailed);
    }

    logger.debug("write_bytes: Successfully wrote {} bytes to address {}.",
                 num_bytes, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(target_address)));
    return {};
}

Memory::ReadableStatus DetourModKit::Memory::is_readable_nonblocking(const void *address, size_t size)
{
    if (!address || size == 0)
        return ReadableStatus::NotReadable;

    ActiveReaderGuard reader_guard;

    if (!s_cache_initialized.load(std::memory_order_seq_cst))
    {
        // Cache not initialized - fall back to direct VirtualQuery (blocking)
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(address, &mbi, sizeof(mbi)))
            return ReadableStatus::NotReadable;
        if (mbi.State != MEM_COMMIT)
            return ReadableStatus::NotReadable;
        if (!check_read_permission(mbi.Protect))
            return ReadableStatus::NotReadable;
        const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
        const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t query_end = query_addr_val + size;
        if (query_end < query_addr_val)
            return ReadableStatus::NotReadable;
        if (query_addr_val >= region_start && query_end <= region_start + mbi.RegionSize)
            return ReadableStatus::Readable;
        return ReadableStatus::NotReadable;
    }

    const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
    if (shard_count == 0)
        return ReadableStatus::Unknown;

    const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
    const size_t shard_idx = compute_shard_index(query_addr_val, shard_count);
    const uint64_t now_ns = current_time_ns();
    const uint64_t expiry_ns = static_cast<uint64_t>(s_configured_expiry_ms.load(std::memory_order_acquire)) * 1'000'000ULL;

    // Non-blocking: try_lock_shared to avoid stalling latency-sensitive threads
    std::shared_lock<SrwSharedMutex> lock(*s_shard_mutexes[shard_idx], std::try_to_lock);
    if (!lock.owns_lock())
        return ReadableStatus::Unknown;

    CachedMemoryRegionInfo *cached_info = find_in_shard(
        s_cache_shards[shard_idx],
        query_addr_val, size, now_ns, expiry_ns);
    if (cached_info)
    {
        s_stats.cache_hits.fetch_add(1, std::memory_order_relaxed);
        return check_read_permission(cached_info->protection)
                   ? ReadableStatus::Readable
                   : ReadableStatus::NotReadable;
    }

    // Cache miss with non-blocking semantics: return Unknown rather than issuing VirtualQuery
    return ReadableStatus::Unknown;
}

uintptr_t DetourModKit::Memory::read_ptr_unsafe(uintptr_t base, ptrdiff_t offset) noexcept
{
#ifdef _MSC_VER
    __try
    {
        return *reinterpret_cast<const uintptr_t *>(base + offset);
    }
    __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
               GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION)
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH)
    {
        return 0;
    }
#else
    // MinGW/GCC lacks __try/__except. Probe the cache with a trylock
    // to avoid a VirtualQuery syscall when the region is already cached.
    // Falls back to VirtualQuery on cache miss or when cache is off.
    // ActiveReaderGuard is required to prevent shutdown_cache() from
    // destroying shard vectors between our check and access.
    const auto src = base + static_cast<uintptr_t>(offset);

    {
        ActiveReaderGuard reader_guard;

        if (s_cache_initialized.load(std::memory_order_seq_cst))
        {
            const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            if (shard_count != 0)
            {
                const size_t shard_idx = compute_shard_index(src, shard_count);
                std::shared_lock<SrwSharedMutex> lock(*s_shard_mutexes[shard_idx], std::try_to_lock);
                if (lock.owns_lock())
                {
                    const uint64_t now_ns = current_time_ns();
                    const uint64_t expiry_ns = static_cast<uint64_t>(
                                                   s_configured_expiry_ms.load(std::memory_order_acquire)) *
                                               1'000'000ULL;
                    CachedMemoryRegionInfo *cached = find_in_shard(
                        s_cache_shards[shard_idx],
                        src, sizeof(uintptr_t), now_ns, expiry_ns);
                    if (cached)
                    {
                        if (check_read_permission(cached->protection))
                            return *reinterpret_cast<const uintptr_t *>(src);
                        return 0;
                    }
                }
            }
        }
    }

    // Cache miss, lock contention, or cache not initialized
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(reinterpret_cast<const void *>(src), &mbi, sizeof(mbi)))
        return 0;
    if (mbi.State != MEM_COMMIT)
        return 0;
    if ((mbi.Protect & CachePermissions::READ_PERMISSION_FLAGS) == 0 ||
        (mbi.Protect & CachePermissions::NOACCESS_GUARD_FLAGS) != 0)
        return 0;
    // Verify the full read fits within the committed region (overflow-safe)
    const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    const uintptr_t region_end = region_start + mbi.RegionSize;
    const uintptr_t read_end = src + sizeof(uintptr_t);
    if (read_end < src || src < region_start || read_end > region_end)
        return 0;
    return *reinterpret_cast<const uintptr_t *>(src);
#endif
}

// Lower bound on a valid usermode pointer on x64 Windows. The null page plus
// the standard NoAccess guard region cover [0, 0x10000); rejecting addresses
// in this range without a memory access keeps stale or sentinel pointers from
// raising first-chance exceptions in callers' debuggers.
namespace
{
    inline constexpr uintptr_t SEH_READ_MIN_VALID_ADDR = 0x10000;
} // namespace

bool DetourModKit::Memory::seh_read_bytes(uintptr_t addr, void *out, size_t bytes) noexcept
{
    if (bytes == 0)
        return true;
    if (!out || addr < SEH_READ_MIN_VALID_ADDR)
        return false;

    // Overflow guard on (addr + bytes); a wraparound source range can never be
    // a valid mapped image.
    if (addr + bytes < addr)
        return false;

#ifdef _MSC_VER
    __try
    {
#if defined(__SANITIZE_ADDRESS__)
        // Copy via __movsb (rep movsb) under ASan: MSVC routes std::memcpy through
        // the ASan interceptor, which inspects the source against ASan's shadow and
        // false-positives on the foreign mapped memory this probe legitimately
        // reads (e.g. a module's data section during the RTTI walk). __movsb emits
        // the copy inline with no interceptable call. Release keeps std::memcpy.
        __movsb(static_cast<unsigned char *>(out),
                reinterpret_cast<const unsigned char *>(addr), bytes);
#else
        std::memcpy(out, reinterpret_cast<const void *>(addr), bytes);
#endif
        return true;
    }
    __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
               GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION)
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
#else
    // MinGW lacks __try/__except. Validate every region the read spans with
    // VirtualQuery before issuing the memcpy. The loop chains across adjacent
    // regions so multi-region reads (which happen for any buffer that crosses
    // an allocation boundary) succeed when every covered page is committed
    // and readable.
    size_t copied = 0;
    while (copied < bytes)
    {
        const uintptr_t cur = addr + copied;
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(reinterpret_cast<const void *>(cur), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT)
            return false;
        if ((mbi.Protect & CachePermissions::READ_PERMISSION_FLAGS) == 0 ||
            (mbi.Protect & CachePermissions::NOACCESS_GUARD_FLAGS) != 0)
            return false;

        const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t region_end = region_start + mbi.RegionSize;
        if (cur < region_start || cur >= region_end)
            return false;

        const size_t available = static_cast<size_t>(region_end - cur);
        const size_t remaining = bytes - copied;
        const size_t to_copy = (remaining < available) ? remaining : available;
        std::memcpy(static_cast<std::byte *>(out) + copied,
                    reinterpret_cast<const void *>(cur),
                    to_copy);
        copied += to_copy;
    }
    return true;
#endif
}

namespace
{
    // Walk a Cheat-Engine-style pointer chain inside a single fault guard.
    // Every offset except the last is added and dereferenced to obtain the next
    // link; the last offset is added but not dereferenced, yielding the target
    // field address in out_addr. Each intermediate link is screened with
    // plausible_userspace_ptr so a torn or sentinel pointer aborts the walk
    // before the next dereference faults. Returns false on any fault or
    // implausible intermediate link.
    bool resolve_chain_guarded(uintptr_t base, const ptrdiff_t *offsets,
                               size_t count, uintptr_t &out_addr) noexcept
    {
#ifdef _MSC_VER
        __try
        {
            uintptr_t cur = base;
            for (size_t i = 0; i + 1 < count; ++i)
            {
                uintptr_t next = 0;
                std::memcpy(&next,
                            reinterpret_cast<const void *>(cur + static_cast<uintptr_t>(offsets[i])),
                            sizeof(next));
                if (!Memory::plausible_userspace_ptr(next))
                    return false;
                cur = next;
            }
            out_addr = (count == 0)
                           ? cur
                           : cur + static_cast<uintptr_t>(offsets[count - 1]);
            return true;
        }
        __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
                   GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION)
                      ? EXCEPTION_EXECUTE_HANDLER
                      : EXCEPTION_CONTINUE_SEARCH)
        {
            return false;
        }
#else
        // MinGW lacks __try/__except. Each intermediate link is read through
        // read_ptr_unsafe (VirtualQuery-guarded, returns 0 on fault); the
        // plausibility screen also rejects that 0.
        uintptr_t cur = base;
        for (size_t i = 0; i + 1 < count; ++i)
        {
            const uintptr_t next = Memory::read_ptr_unsafe(cur, offsets[i]);
            if (!Memory::plausible_userspace_ptr(next))
                return false;
            cur = next;
        }
        out_addr = (count == 0)
                       ? cur
                       : cur + static_cast<uintptr_t>(offsets[count - 1]);
        return true;
#endif
    }
} // namespace

std::optional<uintptr_t> DetourModKit::Memory::seh_resolve_chain(
    uintptr_t base, std::span<const ptrdiff_t> offsets) noexcept
{
    uintptr_t addr = 0;
    if (resolve_chain_guarded(base, offsets.data(), offsets.size(), addr))
        return addr;
    return std::nullopt;
}

bool DetourModKit::Memory::seh_read_chain_bytes(
    uintptr_t base, std::span<const ptrdiff_t> offsets, void *out, size_t bytes) noexcept
{
    if (bytes == 0)
        return true;
    if (!out)
        return false;

#ifdef _MSC_VER
    // The walk is inlined here rather than reusing resolve_chain_guarded so the
    // resolve and the terminal read sit in one __try region. On x64 the __try
    // is table-driven and free on the no-fault path, so this is a structural
    // choice (one uniform failure path for the whole operation) and not a
    // measurable saving over two adjacent guarded regions.
    const ptrdiff_t *const offs = offsets.data();
    const size_t count = offsets.size();
    __try
    {
        uintptr_t cur = base;
        for (size_t i = 0; i + 1 < count; ++i)
        {
            uintptr_t next = 0;
            std::memcpy(&next,
                        reinterpret_cast<const void *>(cur + static_cast<uintptr_t>(offs[i])),
                        sizeof(next));
            if (!Memory::plausible_userspace_ptr(next))
                return false;
            cur = next;
        }
        const uintptr_t final_addr = (count == 0)
                                         ? cur
                                         : cur + static_cast<uintptr_t>(offs[count - 1]);
        // Apply seh_read_bytes' own prechecks on the terminal address so a low
        // or wrapping final address fails identically on both toolchains. The
        // MinGW branch below already routes through seh_read_bytes, which
        // rejects these; matching here keeps a stale or sentinel final address
        // from raising a (benign but debugger-visible) first-chance exception.
        if (final_addr < SEH_READ_MIN_VALID_ADDR || final_addr + bytes < final_addr)
            return false;
        std::memcpy(out, reinterpret_cast<const void *>(final_addr), bytes);
        return true;
    }
    __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
               GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION)
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
#else
    // MinGW: resolve through the VirtualQuery-guarded helper, then read the
    // terminal range with seh_read_bytes, which validates every region the
    // read spans before copying.
    uintptr_t final_addr = 0;
    if (!resolve_chain_guarded(base, offsets.data(), offsets.size(), final_addr))
        return false;
    return Memory::seh_read_bytes(final_addr, out, bytes);
#endif
}

namespace
{
    // PE header layout for module range resolution. Pulled into an anonymous
    // namespace so the helper is internal to memory.cpp and shared between
    // module_range_for, own_module_range, and host_module_range.
    DetourModKit::Memory::ModuleRange module_range_from_handle(HMODULE mod) noexcept
    {
        if (!mod)
            return {};

        const uintptr_t base = reinterpret_cast<uintptr_t>(mod);

        IMAGE_DOS_HEADER dos{};
        if (!DetourModKit::Memory::seh_read_bytes(base, &dos, sizeof(dos)))
            return {};
        if (dos.e_magic != IMAGE_DOS_SIGNATURE)
            return {};

        // Bound e_lfanew. A genuine PE places NT headers within the first few
        // KiB; anything beyond a generous 1 MiB cap is corrupt or hostile.
        if (dos.e_lfanew <= 0 || static_cast<uint32_t>(dos.e_lfanew) > 0x100000U)
            return {};

        IMAGE_NT_HEADERS nt{};
        if (!DetourModKit::Memory::seh_read_bytes(base + static_cast<uintptr_t>(dos.e_lfanew),
                                                  &nt, sizeof(nt)))
            return {};
        if (nt.Signature != IMAGE_NT_SIGNATURE)
            return {};

        const uintptr_t size_of_image = nt.OptionalHeader.SizeOfImage;
        if (size_of_image == 0)
            return {};

        return {base, base + size_of_image};
    }

    // Per-process ModuleRange cache shared by module_range_for. Constructed on
    // first use; survives until process exit. Static-storage destruction is
    // deliberately a non-issue here because the cache is consulted only by
    // DetourModKit code that has already shut down its own subsystems via
    // DMK_Shutdown() (callers do not query ranges from atexit handlers).
    struct ModuleRangeCache
    {
        std::shared_mutex mtx;
        std::unordered_map<HMODULE, DetourModKit::Memory::ModuleRange> entries;
    };

    ModuleRangeCache &get_module_range_cache() noexcept
    {
        static ModuleRangeCache cache;
        return cache;
    }
} // namespace

std::optional<DetourModKit::Memory::ModuleRange>
DetourModKit::Memory::module_range_for(const void *address) noexcept
{
    if (!address)
        return std::nullopt;

    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address),
            &mod) ||
        mod == nullptr)
    {
        return std::nullopt;
    }

    auto &cache = get_module_range_cache();
    {
        std::shared_lock<std::shared_mutex> lock(cache.mtx);
        const auto it = cache.entries.find(mod);
        if (it != cache.entries.end())
            return it->second;
    }

    const auto range = module_range_from_handle(mod);
    if (!range.valid())
        return std::nullopt;

    {
        std::unique_lock<std::shared_mutex> lock(cache.mtx);
        // Another thread may have inserted between our shared/unique transition;
        // emplace skips on collision so we keep the first-resolved entry.
        cache.entries.emplace(mod, range);
    }
    return range;
}

DetourModKit::Memory::ModuleRange DetourModKit::Memory::own_module_range() noexcept
{
    // Magic-static initialization: the lambda runs exactly once per module,
    // guarded by the C++23 thread-safe-initialization rules. Taking the
    // address of own_module_range itself anchors the lookup in whichever
    // DLL/EXE statically linked this translation unit.
    static const ModuleRange cached = []
    {
        HMODULE mod = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&DetourModKit::Memory::own_module_range),
                &mod) ||
            mod == nullptr)
        {
            return ModuleRange{};
        }
        return module_range_from_handle(mod);
    }();
    return cached;
}

DetourModKit::Memory::ModuleRange DetourModKit::Memory::host_module_range() noexcept
{
    static const ModuleRange cached = []
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod)
            return ModuleRange{};
        return module_range_from_handle(mod);
    }();
    return cached;
}
