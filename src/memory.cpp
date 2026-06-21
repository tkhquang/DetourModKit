/**
 * @file memory.cpp
 * @brief Implementation of memory manipulation and validation utilities.
 *
 * Provides functions for checking memory readability and writability, writing bytes to memory, and managing a memory
 * region cache for performance optimization. The cache uses sharded locks with SRWLOCK for high-concurrency read-heavy
 * access. Uses monotonic counter-keyed map for O(log n) LRU eviction instead of O(n) scan. In-flight query coalescing
 * prevents cache stampede under high concurrency. On-demand cleanup handles expired entry removal to avoid polluting
 * the miss path. Epoch-based reader tracking prevents use-after-free during shutdown.
 */

#include "DetourModKit/memory.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/srw_shared_mutex.hpp"
#include "platform.hpp"
#include "memory_internal.hpp"

#include <windows.h>
#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)
#include <intrin.h> // __movsb -- ASan-safe copy in the SEH probe read
#endif
#include <shared_mutex>
#include <unordered_map>
#include <map>
#include <vector>
#include <deque>
#include <type_traits>
#include <chrono>
#include <array>
#include <atomic>
#include <mutex>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cstddef>
#include <thread>
#include <condition_variable>

namespace DetourModKit
{
    using DetourModKit::detail::is_loader_lock_held;
    using DetourModKit::detail::pin_current_module;
    using DetourModKit::detail::SrwSharedMutex;

    // Anonymous namespace for internal helpers and storage
    namespace
    {
        // Page-protection flag groups for the cache permission checks. Grouped in a struct rather than a named
        // namespace so the constants keep internal linkage through the enclosing anonymous namespace, per the .cpp
        // internal-linkage convention.
        struct CachePermissions
        {
            static constexpr DWORD READ_PERMISSION_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                                           PAGE_EXECUTE_WRITECOPY;
            static constexpr DWORD WRITE_PERMISSION_FLAGS =
                PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            static constexpr DWORD NOACCESS_GUARD_FLAGS = PAGE_NOACCESS | PAGE_GUARD;
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
         * @details Uses unordered_map keyed by region base address for fast lookup. std::map keyed by monotonic counter
         *          for efficient oldest-entry eviction. The per-shard SrwSharedMutex (multiple concurrent readers) and
         *          the in_flight stampede-coalescing flag are stored inline, and the whole struct is aligned to a cache
         *          line, so one shard's lock word and in_flight flag never share a line with another shard's:
         *          concurrent access to different shards stays off each other's cache lines. Inlining the mutex (rather
         *          than a separate heap-allocated lock per shard) is what fixes the cache-line layout, and it makes the
         *          shard non-movable -- SrwSharedMutex and std::atomic are non-movable -- so the shards are allocated
         *          once as a fixed-size array that never relocates, not a resizable std::vector.
         */
#if defined(_MSC_VER)
#pragma warning(push)
// C4324: CacheShard is intentionally padded to a full cache line by alignas(64) for cache-line hygiene.
#pragma warning(disable : 4324)
#endif
        struct alignas(64) CacheShard
        {
            // Map from base_address -> CachedMemoryRegionInfo for O(1) lookup by address
            std::unordered_map<uintptr_t, CachedMemoryRegionInfo> entries;
            // Map from monotonic counter -> base_address for O(log n) oldest-entry lookup (LRU)
            // Monotonic counter guarantees insertion-order uniqueness for correct eviction
            std::map<uint64_t, uintptr_t> lru_index;
            // Sorted by base address for O(log n) containment lookup. All sorted_ranges access is serialized by the
            // shard SRW lock (shared for lookups, exclusive for mutation), so iterators never outlive a critical
            // section. The std::deque is defense-in-depth that prevents wholesale buffer relocation on growth, though
            // interior insert/erase still invalidates deque iterators per the standard. The hit path is dominated by
            // the direct entries lookup; the sorted-ranges path is the slow-path fallback for regions larger than one
            // page, and the deque's extra indirection on random-access iterators is in the noise at the bounded size
            // (hard_max_per_shard).
            // {base, base+size}
            std::deque<std::pair<uintptr_t, uintptr_t>> sorted_ranges;
            // Per-shard reader/writer lock (shared for lookups, exclusive for mutation). Inline so it lives in the
            // shard's own cache line(s) rather than behind a separately heap-allocated lock word, and is kept off other
            // shards' lines by the struct's alignas(64).
            SrwSharedMutex mtx;
            // Stampede-coalescing flag: the first thread to CAS it from 0 to 1 becomes the VirtualQuery leader for this
            // shard and the rest coalesce onto its result. Stored inline (not in a shared global array) so it never
            // shares a cache line with a neighbouring shard's flag.
            std::atomic<char> in_flight{0};
            uint64_t entry_counter{0};
            size_t capacity;
            size_t max_capacity;

            CacheShard() : capacity(0), max_capacity(0) { entries.reserve(64); }
        };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

        // The sorted-ranges container type is pinned as a deliberate refactor tripwire: with a deque, mutation never
        // relocates the whole buffer under the lock. This is not iterator stability (deque insert/erase invalidates
        // iterators); the lock is what excludes concurrent access.
        static_assert(
            std::is_same_v<decltype(CacheShard::sorted_ranges), std::deque<std::pair<uintptr_t, uintptr_t>>>,
            "CacheShard::sorted_ranges is pinned to std::deque so mutation never relocates the whole buffer.");

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
    } // anonymous namespace

    // Internal static variables and helper functions for memory cache. Anonymous namespace ensures internal linkage,
    // preventing ODR violations if this translation unit's declarations were ever duplicated.
    namespace
    {
        // Fixed-size shard array, allocated once by perform_cache_initialization and never resized: CacheShard owns its
        // SrwSharedMutex and in_flight atomic inline and so is non-movable, which rules out a resizable std::vector.
        // null until init, reset on shutdown. The per-shard lock and in_flight flag are reached through
        // s_cache_shards[i].mtx and s_cache_shards[i].in_flight.
        std::unique_ptr<CacheShard[]> s_cache_shards;
        std::atomic<size_t> s_shard_count{0};
        std::atomic<size_t> s_max_entries_per_shard{0};
        std::atomic<unsigned int> s_configured_expiry_ms{0};
        std::atomic<bool> s_cache_initialized{false};

        /// Configured cache-entry expiry converted from milliseconds to nanoseconds.
        [[nodiscard]] inline uint64_t configured_expiry_ns() noexcept
        {
            return static_cast<uint64_t>(s_configured_expiry_ms.load(std::memory_order_acquire)) * 1'000'000ULL;
        }

        // Global cache state mutex to serialize init/clear/shutdown transitions
        // Protects against concurrent state changes that could leave vectors in invalid state
        std::mutex s_cache_state_mutex;

        // Epoch-based reader tracking to prevent use-after-free during shutdown. Readers increment on entry to
        // is_readable/is_writable and decrement on exit; shutdown_cache waits for the count to reach zero before
        // destroying data structures. The count is striped across many cache-line-padded counters rather than a single
        // global atomic: a single counter is a shared-cache-line hotspot that re-serializes readers despite the sharded
        // SRWLOCKs, so each thread increments its own stripe and shutdown sums them. Distributing the increment does
        // not weaken the shutdown drain -- see active_reader_total() and the ActiveReaderGuard Dekker note below.
        constexpr size_t READER_STRIPE_COUNT = 64;

#if defined(_MSC_VER)
#pragma warning(push)
// C4324: ReaderStripe is intentionally padded to a full cache line by alignas(64) so stripes never share a line.
#pragma warning(disable : 4324)
#endif
        struct alignas(64) ReaderStripe
        {
            std::atomic<int32_t> count{0};
        };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

        std::array<ReaderStripe, READER_STRIPE_COUNT> s_reader_stripes{};

        /**
         * @brief Returns this thread's reader stripe, assigned round-robin on first use so concurrent readers spread
         *        across distinct cache lines instead of contending on one counter.
         */
        [[nodiscard]] inline size_t reader_stripe_index() noexcept
        {
            static std::atomic<size_t> s_next_stripe{0};
            thread_local const size_t stripe =
                s_next_stripe.fetch_add(1, std::memory_order_relaxed) % READER_STRIPE_COUNT;
            return stripe;
        }

        /**
         * @brief Sum of all reader stripes: the number of readers currently inside an ActiveReaderGuard.
         * @details shutdown_cache spins on this reaching zero (under seq_cst) after publishing
         * s_cache_initialized=false,
         *          before freeing shard storage.
         */
        [[nodiscard]] inline int64_t active_reader_total() noexcept
        {
            int64_t total = 0;
            for (const ReaderStripe &stripe : s_reader_stripes)
            {
                total += stripe.count.load(std::memory_order_seq_cst);
            }
            return total;
        }

        /**
         * @class ActiveReaderGuard
         * @brief RAII guard that increments this thread's reader stripe on construction and decrements it on
         * destruction,
         *        ensuring correct pairing on all exit paths.
         */
        class ActiveReaderGuard
        {
        public:
            ActiveReaderGuard() noexcept : m_stripe(reader_stripe_index())
            {
                // seq_cst (not acq_rel) so this increment and the reader's subsequent seq_cst load of
                // s_cache_initialized share the single total order that forbids the store-buffering (Dekker) outcome
                // with shutdown_cache: shutdown stores s_cache_initialized=false then sums every stripe, while a reader
                // increments its stripe then loads s_cache_initialized. Under seq_cst a reader that observes the cache
                // live was necessarily counted on its stripe before shutdown reads that stripe, so shutdown cannot free
                // shard data out from under it -- the per-stripe argument is identical to the single-counter one
                // because each reader touches exactly one stripe for its whole lifetime. On x86-64 this is the same
                // lock xadd as acq_rel, so the hot path pays nothing beyond landing on a per-thread cache line instead
                // of one shared line.
                s_reader_stripes[m_stripe].count.fetch_add(1, std::memory_order_seq_cst);
            }

            ~ActiveReaderGuard() noexcept { s_reader_stripes[m_stripe].count.fetch_sub(1, std::memory_order_release); }

            ActiveReaderGuard(const ActiveReaderGuard &) = delete;
            ActiveReaderGuard &operator=(const ActiveReaderGuard &) = delete;

        private:
            const size_t m_stripe;
        };

        // Background cleanup thread. Uses std::thread (not jthread) because these are namespace-scope statics:
        // jthread's auto-join destructor would run after s_cleanup_cv/s_cleanup_mutex are destroyed (reverse
        // declaration order), causing UB. Manual join in shutdown_cache() avoids this. DMK_Shutdown() calls
        // shutdown_cache() which joins this thread before any other cleanup proceeds, ensuring the thread is fully
        // stopped before static destruction begins.
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
        constexpr inline bool is_entry_valid_and_covers(const CachedMemoryRegionInfo &entry, uintptr_t address,
                                                        size_t size, uint64_t current_time_ns,
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
         * @brief Inserts a range into the shard's sorted auxiliary container.
         * @note Must be called with shard mutex held (exclusive).
         */
        void insert_sorted_range(CacheShard &shard, uintptr_t base_addr, size_t region_size) noexcept
        {
            auto range = std::make_pair(base_addr, base_addr + region_size);
            auto pos = std::lower_bound(shard.sorted_ranges.begin(), shard.sorted_ranges.end(), range);
            shard.sorted_ranges.insert(pos, range);
        }

        /**
         * @brief Removes a range from the shard's sorted auxiliary container.
         * @note Must be called with shard mutex held (exclusive).
         */
        void remove_sorted_range(CacheShard &shard, uintptr_t base_addr) noexcept
        {
            auto it = std::lower_bound(shard.sorted_ranges.begin(), shard.sorted_ranges.end(),
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
         * @note First attempts direct lookup by page-aligned base address for O(1) fast path, then falls back to O(log
         * n)
         *       binary search via sorted_ranges for addresses within larger regions.
         */
        CachedMemoryRegionInfo *find_in_shard(CacheShard &shard, uintptr_t address, size_t size,
                                              uint64_t current_time_ns, uint64_t expiry_ns) noexcept
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

            // Slow path: O(log n) containment lookup via sorted ranges. Finds the last range starting at or before the
            // queried address, then verifies containment and entry validity.
            auto range_it = std::upper_bound(shard.sorted_ranges.begin(), shard.sorted_ranges.end(),
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
        void update_shard_with_region(CacheShard &shard, const MEMORY_BASIC_INFORMATION &mbi,
                                      uint64_t current_time_ns) noexcept
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
        size_t cleanup_expired_entries_in_shard(CacheShard &shard, uint64_t current_time_ns,
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
            // Always hold state mutex to prevent racing with shutdown_cache() which clears the shard vectors. try_lock
            // for on-demand to avoid blocking the hot path; forced cleanup blocks to guarantee progress.
            std::unique_lock<std::mutex> lock(s_cache_state_mutex, std::defer_lock);
            if (force)
            {
                lock.lock();
            }
            else if (!lock.try_lock())
            {
                return; // Shutdown or forced cleanup in progress, skip
            }

            if (!s_cache_shards)
                return;

            const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            if (shard_count == 0)
                return;

            const uint64_t current_ts = current_time_ns();
            const uint64_t expiry_ns = configured_expiry_ns();

            for (size_t i = 0; i < shard_count; ++i)
            {
                std::unique_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx, std::try_to_lock);
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
                    s_cleanup_cv.wait_for(lock, std::chrono::seconds(1),
                                          [&]()
                                          {
                                              return s_cleanup_requested.load(std::memory_order_acquire) ||
                                                     !s_cleanup_thread_running.load(std::memory_order_acquire);
                                          });
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
         * @note Scans the whole shard rather than probing a single key. An entry is keyed by its VirtualQuery region
         *       base, but it is stored in the shard chosen from the original query address (compute_shard_index mixes
         *       the full address, not the region base), so one region can be cached in several shards under the same
         *       base key. A single key/shard probe therefore cannot locate every covering entry; only a per-shard
         *       containment scan can. The shard is bounded by max_capacity and invalidation runs only after a write, so
         *       this linear scan is never on a read hot path.
         */
        size_t evict_overlapping_entries_in_shard(CacheShard &shard, uintptr_t address, uintptr_t end_address) noexcept
        {
            size_t evicted = 0;
            auto it = shard.entries.begin();
            while (it != shard.entries.end())
            {
                const CachedMemoryRegionInfo &entry = it->second;
                const uintptr_t entry_end_address = entry.base_address + entry.region_size;
                // A VirtualQuery region cannot extend past the address space, but a corrupt cached size could; treat a
                // wrapped end as covering the top of the space so a poisoned entry is still evicted rather than
                // skipped.
                const uintptr_t clamped_entry_end =
                    (entry_end_address < entry.base_address) ? UINTPTR_MAX : entry_end_address;
                const bool overlaps = entry.valid && address < clamped_entry_end && end_address > entry.base_address;
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
         * @details Every shard is scanned because an entry's storage shard is derived from the original query address,
         *          not its region base, so a covering entry may live in any shard (see
         *          evict_overlapping_entries_in_shard). A bounded try-lock retry per shard keeps the writer that
         *          triggered the invalidation from blocking on a momentarily contended shard.
         */
        void invalidate_range_internal(uintptr_t address, size_t size) noexcept
        {
            if (!s_cache_shards || size == 0)
                return;

            // Guard against address + size wrapping around the address space.
            const uintptr_t end_address = (address + size < address) ? UINTPTR_MAX : address + size;
            const size_t shard_count = s_shard_count.load(std::memory_order_acquire);

            constexpr size_t MAX_INVALIDATION_RETRIES = 3;

            size_t skipped_shards = 0;
            for (size_t shard_idx = 0; shard_idx < shard_count; ++shard_idx)
            {
                bool invalidated = false;
                for (size_t retry = 0; retry < MAX_INVALIDATION_RETRIES; ++retry)
                {
                    std::unique_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx, std::try_to_lock);
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
                    invalidated = true;
                    break;
                }
                if (!invalidated)
                {
                    ++skipped_shards;
                }
            }

            if (skipped_shards > 0)
            {
                // A shard that stayed contended across every retry keeps its entries in place, so they answer from the
                // pre-write protection state until the configured expiry sweeps them. This matters chiefly when the
                // caller could not restore protection (write_bytes restores on success), so surface it for diagnosis
                // instead of skipping silently. try_log keeps this noexcept path honest when the level is enabled.
                (void)Logger::get_instance().try_log(
                    LogLevel::Debug,
                    "MemoryCache: invalidate_range left {} contended shard(s) unswept; "
                    "stale entries persist until expiry.",
                    skipped_shards);
            }
        }

        /**
         * @brief Performs one-time cache initialization.
         */
        bool perform_cache_initialization(size_t cache_size, unsigned int expiry_ms, size_t shard_count)
        {
            if (cache_size == 0)
                cache_size = MIN_CACHE_SIZE;
            if (shard_count == 0)
                shard_count = 1;

            const size_t entries_per_shard = (cache_size + shard_count - 1) / shard_count;
            // Hard upper bound: nominal per-shard capacity scaled by the multiplier
            const size_t hard_max_per_shard = entries_per_shard * DEFAULT_MAX_CACHE_SIZE_MULTIPLIER;

            try
            {
                // One allocation for the whole fixed-size array; each shard default-constructs its inline mutex and
                // in_flight flag in place (no per-shard heap allocation, no relocation).
                s_cache_shards = std::make_unique<CacheShard[]>(shard_count);
                for (size_t i = 0; i < shard_count; ++i)
                {
                    s_cache_shards[i].entries.reserve(hard_max_per_shard);
                    s_cache_shards[i].capacity = entries_per_shard;
                    s_cache_shards[i].max_capacity = hard_max_per_shard;
                }
            }
            catch (const std::bad_alloc &)
            {
                Logger::get_instance().error("MemoryCache: Failed to allocate memory for cache shards.");
                s_cache_shards.reset();
                // Reset initialization flag so retry can work
                s_cache_initialized.store(false, std::memory_order_relaxed);
                return false;
            }

            s_shard_count.store(shard_count, std::memory_order_release);
            s_max_entries_per_shard.store(entries_per_shard, std::memory_order_release);
            s_configured_expiry_ms.store(expiry_ms, std::memory_order_release);
            s_last_cleanup_time_ns.store(current_time_ns(), std::memory_order_release);

            Logger::get_instance().debug(
                "MemoryCache: Initialized with {} shards ({} entries/shard, {}ms expiry, {} max).", shard_count,
                entries_per_shard, expiry_ms, hard_max_per_shard);

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
            if (shard.in_flight.compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
            {
                // We are the leader - perform VirtualQuery
                const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                const uint64_t now_ns = current_time_ns();

                if (result)
                {
                    std::unique_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                    update_shard_with_region(shard, mbi_out, now_ns);
                }

                // Release in-flight status
                shard.in_flight.store(0, std::memory_order_release);
                return result;
            }
            else
            {
                // We are a follower - VirtualQuery already in progress by another thread. Bounded wait to avoid
                // stalling game threads on render-critical paths.
                const uint64_t expiry_ns = configured_expiry_ns();
                constexpr size_t MAX_FOLLOWER_YIELDS = 8;

                for (size_t yield_count = 0; yield_count < MAX_FOLLOWER_YIELDS; ++yield_count)
                {
                    if (shard.in_flight.load(std::memory_order_acquire) == 0)
                    {
                        // Query completed, check cache
                        const uintptr_t addr_val = reinterpret_cast<uintptr_t>(address);
                        std::shared_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                        CachedMemoryRegionInfo *cached =
                            find_in_shard(shard, addr_val, 1, current_time_ns(), expiry_ns);
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
                if (shard.in_flight.compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
                {
                    const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                    if (result)
                    {
                        std::unique_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                        const uint64_t now_ns = current_time_ns();
                        update_shard_with_region(shard, mbi_out, now_ns);
                    }
                    shard.in_flight.store(0, std::memory_order_release);
                    return result;
                }

                // Last resort: just do VirtualQuery without cache update
                return VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
            }
        }

    } // anonymous namespace

    // Lower bound on a valid usermode pointer on x64 Windows. The null page plus the standard NoAccess guard region
    // cover [0, 0x10000); rejecting addresses in this range without a memory access keeps stale or sentinel pointers
    // from raising first-chance exceptions in callers' debuggers. Shared by seh_read_bytes and the MinGW guarded-read
    // entry point.
    namespace
    {
        inline constexpr uintptr_t SEH_READ_MIN_VALID_ADDR = 0x10000;
    } // anonymous namespace

#ifndef _MSC_VER
    // MinGW/GCC has no __try / __except, so the foreign-memory probes in this file cannot wrap their accesses in
    // frame-based SEH the way the MSVC paths do. A single process-wide vectored exception handler provides the
    // equivalent fault guard: each guarded access marks the foreign range it is about to touch in a thread-local slot,
    // and a fault inside that range is intercepted and turned into a clean failure instead of terminating the host. The
    // guarded path avoids a per-call VirtualQuery on successful terminal reads/writes and keeps stale cache entries
    // from authorizing unguarded dereferences after a page is reprotected.
    namespace
    {
        // VirtualQuery-validated read. On x64 it is the fallback used only when the vectored handler could not be
        // installed; on a 32-bit MinGW build, where the handler's x64 register redirect is unavailable, it is the only
        // guard. The copy itself goes through ReadProcessMemory so a page that changes after the query fails as an API
        // result rather than as a user-mode fault.
        bool virtualquery_validated_copy(uintptr_t addr, void *out, size_t bytes) noexcept
        {
            size_t copied = 0;
            while (copied < bytes)
            {
                const uintptr_t cur = addr + copied;
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void *>(cur), &mbi, sizeof(mbi)))
                    return false;
                if (mbi.State != MEM_COMMIT)
                    return false;
                if ((mbi.Protect & CachePermissions::READ_PERMISSION_FLAGS) == 0 ||
                    (mbi.Protect & CachePermissions::NOACCESS_GUARD_FLAGS) != 0)
                    return false;

                const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                const uintptr_t region_end = region_start + mbi.RegionSize;
                if (region_end < region_start)
                    return false;
                if (cur < region_start || cur >= region_end)
                    return false;

                const size_t available = static_cast<size_t>(region_end - cur);
                const size_t remaining = bytes - copied;
                const size_t to_copy = (remaining < available) ? remaining : available;
                SIZE_T copied_now = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void *>(cur),
                                       static_cast<std::byte *>(out) + copied, to_copy, &copied_now) ||
                    copied_now != to_copy)
                    return false;
                copied += to_copy;
            }
            return true;
        }

        // VirtualQuery-validated write fallback for MinGW when no frame/vectored fault guard is available. It never
        // changes page protection: if the current protection is not writable, the write fails closed. The copy itself
        // goes through WriteProcessMemory so a page that changes after the query fails as an API result rather than as
        // a user-mode fault.
        bool virtualquery_validated_write(uintptr_t addr, const void *source, size_t bytes) noexcept
        {
            size_t copied = 0;
            while (copied < bytes)
            {
                const uintptr_t cur = addr + copied;
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void *>(cur), &mbi, sizeof(mbi)))
                    return false;
                if (mbi.State != MEM_COMMIT)
                    return false;
                if ((mbi.Protect & CachePermissions::WRITE_PERMISSION_FLAGS) == 0 ||
                    (mbi.Protect & CachePermissions::NOACCESS_GUARD_FLAGS) != 0)
                    return false;

                const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                const uintptr_t region_end = region_start + mbi.RegionSize;
                if (region_end < region_start)
                    return false;
                if (cur < region_start || cur >= region_end)
                    return false;

                const size_t available = static_cast<size_t>(region_end - cur);
                const size_t remaining = bytes - copied;
                const size_t to_copy = (remaining < available) ? remaining : available;
                SIZE_T copied_now = 0;
                if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void *>(cur),
                                        static_cast<const std::byte *>(source) + copied, to_copy, &copied_now) ||
                    copied_now != to_copy)
                    return false;
                copied += to_copy;
            }
            return true;
        }

#if defined(_WIN64)
        // Per-access record describing the foreign range and the recovery snapshot. It lives on the guarded access's
        // own stack (one per nested-free synchronous access) and is published to the thread's Win32 TLS slot for the
        // duration of the access; the handler reads that slot. A Win32 TLS slot is used rather than a thread_local /
        // __thread because mingw lowers thread-locals to __emutls_get_address, which allocates and locks on a thread's
        // first access -- forbidden in the exception-dispatch context the handler runs in. TlsGetValue is documented to
        // be callable there: it reads the thread's TLS array with no allocation and no lock, and returns null on any
        // thread that has not armed an access.
        struct VehAccessGuard
        {
            void *env[5]; // __builtin_setjmp buffer; the recovery stub longjmps through it (5 words is the GCC ABI)
            uintptr_t guard_lo; // first byte of the foreign range being accessed
            uintptr_t guard_hi; // one past the last byte of that range
        };

        std::mutex s_veh_mutex;
        std::atomic<void *> s_veh_handle{nullptr};
        // Process-lifetime TLS index, allocated once and reused across install/remove cycles (never freed so a removal
        // can never invalidate an index a concurrent access still holds). The handler reads it with an acquire load.
        std::atomic<DWORD> s_veh_tls_index{TLS_OUT_OF_INDEXES};
        // Count of accesses currently on the guarded path. shutdown_cache drains this to zero before unregistering the
        // handler so a fault can never arrive after the handler is gone.
        std::atomic<int> s_veh_in_flight{0};

        // Recovery stub the handler redirects a faulting thread into. __builtin_longjmp restores the stack pointer,
        // frame pointer and program counter from the snapshot the matching __builtin_setjmp captured before the access,
        // so recovery is correct no matter which frame the fault occurred in and without invoking SEH unwinding (which
        // can abort when unwound from a vectored-handler-resumed context). The handler passes the buffer in the
        // first-argument register so the stub touches no thread-local itself. noinline gives it a stable address for
        // the handler to target.
        [[noreturn]] __attribute__((noinline)) void veh_perform_longjmp(void *env) noexcept
        {
            __builtin_longjmp(env, 1);
        }

        // Vectored exception handler, installed at the front of the list. It claims a fault only when the current
        // thread is inside a guarded access (the TLS slot is non-null), the code is one a guarded probe owns
        // (is_guarded_read_fault -- the same set the MSVC __except filters use), the record carries a faulting address,
        // and that address falls inside the foreign range being accessed. Every other fault is passed straight through,
        // so a host software exception reusing one of these codes, or any code running outside a guarded access, still
        // reaches the host's own handlers unchanged. On a claimed fault it redirects the thread into
        // veh_perform_longjmp, which reports the access as failed.
        LONG NTAPI dmk_veh_read_handler(PEXCEPTION_POINTERS info) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            if (slot == TLS_OUT_OF_INDEXES)
                return EXCEPTION_CONTINUE_SEARCH;

            auto *const guard = static_cast<VehAccessGuard *>(TlsGetValue(slot));
            if (guard == nullptr)
                return EXCEPTION_CONTINUE_SEARCH;

            const EXCEPTION_RECORD *const record = info->ExceptionRecord;
            if (!Memory::detail::is_guarded_read_fault(record->ExceptionCode))
                return EXCEPTION_CONTINUE_SEARCH;

            // A guarded foreign access can only fault with a hardware access-violation, guard-page or in-page-error,
            // all of which carry the faulting data address in ExceptionInformation[1]. Refuse to claim a record without
            // it: that rules out a host RaiseException reusing one of these NTSTATUS codes with no address from being
            // hijacked out of the host's control flow while a guarded access happens to be in flight on this thread.
            if (record->NumberParameters < 2)
                return EXCEPTION_CONTINUE_SEARCH;

            // Confine the claim to the foreign range this operation explicitly armed. A bug that faults outside the
            // range reaches the host's handlers instead of being silently swallowed.
            const uintptr_t fault_address = static_cast<uintptr_t>(record->ExceptionInformation[1]);
            if (fault_address < guard->guard_lo || fault_address >= guard->guard_hi)
                return EXCEPTION_CONTINUE_SEARCH;

            // Disarm before resuming so a fault inside the longjmp stub would pass through rather than recurse.
            TlsSetValue(slot, nullptr);

            // Resume the faulting thread in veh_perform_longjmp(env): instruction pointer to the stub, setjmp buffer in
            // the Win64 first-argument register (RCX). The stub is entered by an injected RIP change, not a CALL, so
            // the fault-point RSP is not the ABI-required call alignment; pre-align it (the stub reloads RSP from the
            // snapshot anyway, so this only protects the stub's own prologue) to keep the resume robust against future
            // codegen that might touch an aligned stack slot before the reload.
            CONTEXT *const ctx = info->ContextRecord;
            ctx->Rsp = (ctx->Rsp & ~static_cast<DWORD64>(15)) - 8;
            ctx->Rcx = reinterpret_cast<DWORD64>(&guard->env);
            ctx->Rip = reinterpret_cast<DWORD64>(&veh_perform_longjmp);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Install the handler once, lazily. Re-installable across an init/shutdown cycle: shutdown_cache removes it and
        // clears the handle, so a later guarded access or re-init installs a fresh one. Best-effort: if either TlsAlloc
        // or AddVectoredExceptionHandler fails (realistic only under exhaustion) the handle stays null; byte-copy
        // guards fall back to VirtualQuery plus ReadProcessMemory / WriteProcessMemory, while in-place region guards
        // fail closed without touching the foreign range.
        void ensure_veh_installed() noexcept
        {
            if (s_veh_handle.load(std::memory_order_acquire) != nullptr)
                return;

            // Names the step that left the guard unavailable, read after the lock is released so the best-effort Logger
            // call never runs while s_veh_mutex is held (the deferred-logging discipline: Logger takes its own locks).
            const char *unavailable_reason = nullptr;
            {
                std::lock_guard<std::mutex> lock(s_veh_mutex);
                if (s_veh_handle.load(std::memory_order_relaxed) != nullptr)
                    return;
                if (s_veh_tls_index.load(std::memory_order_relaxed) == TLS_OUT_OF_INDEXES)
                {
                    const DWORD slot = TlsAlloc();
                    if (slot == TLS_OUT_OF_INDEXES)
                        unavailable_reason =
                            "TLS slot exhausted"; // cannot guard; access paths take their fail-closed fallback
                    else
                        s_veh_tls_index.store(slot, std::memory_order_release);
                }
                if (unavailable_reason == nullptr)
                {
                    // First in the list (FirstHandler = 1): a guarded access always resolves through this handler
                    // before any consumer VEH or frame-based SEH. Every fault that is not this thread's own in-flight
                    // guarded access is passed through with EXCEPTION_CONTINUE_SEARCH, so being first never starves the
                    // host's handlers.
                    void *const handle = AddVectoredExceptionHandler(1, dmk_veh_read_handler);
                    s_veh_handle.store(handle, std::memory_order_release);
                    if (handle == nullptr)
                        unavailable_reason = "AddVectoredExceptionHandler failed";
                }
            }

            // Surface a guard-unavailable condition once. The guarded access paths stay correct by failing closed or
            // using kernel-mediated byte copies, so this is observability only; a single latched emission keeps a
            // retried path -- which re-enters here while the handle stays null -- from spamming the sink. Realistic
            // only under resource exhaustion.
            if (unavailable_reason != nullptr)
            {
                static std::atomic<bool> s_veh_unavailable_warned{false};
                if (!s_veh_unavailable_warned.exchange(true, std::memory_order_relaxed))
                {
                    (void)Logger::get_instance().try_log(
                        LogLevel::Warning,
                        "MemoryCache: vectored access guard unavailable ({}); guarded byte copies use kernel-mediated "
                        "fallbacks and guarded region scans fail closed.",
                        unavailable_reason);
                }
            }
        }

        void remove_veh_handler() noexcept
        {
            std::lock_guard<std::mutex> lock(s_veh_mutex);
            void *const handle = s_veh_handle.load(std::memory_order_relaxed);
            if (handle == nullptr)
                return;
            // Stop new guarded accesses from taking the handler path, then wait for any access already committed to it
            // to finish before unregistering, so a fault cannot arrive after the handler is gone. The seq_cst store
            // pairs with the seq_cst fetch_add / handle-load in the guarded access helpers (the Dekker protocol the
            // cache reader epoch uses): an access that observed a live handle is necessarily counted in s_veh_in_flight
            // before this store is observed.
            s_veh_handle.store(nullptr, std::memory_order_seq_cst);
            int spins = 0;
            while (s_veh_in_flight.load(std::memory_order_seq_cst) > 0)
            {
                if (spins < 4096)
                    std::this_thread::yield();
                else
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                ++spins;
            }
            RemoveVectoredExceptionHandler(handle);
        }

        // Copy [src, src + len) into out under the vectored handler. The copy is a single rep movsb emitted as raw
        // inline assembly: inline asm is invisible to AddressSanitizer, which instruments only compiler-emitted loads,
        // so this deliberate cross-region read cannot raise an ASan false positive (the same reason the MSVC probe
        // copies via the
        // __movsb intrinsic). __builtin_setjmp records the recovery point; the guard is then published to this thread's
        // TLS slot so a read fault is claimable, and the handler longjmps back here so the setjmp expression returns
        // non-zero and the function reports failure. noinline keeps the read and its setjmp anchor in one
        // self-contained frame.
        __attribute__((noinline)) bool veh_guarded_copy(void *out, const void *src, size_t len) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            VehAccessGuard guard;
            guard.guard_lo = reinterpret_cast<uintptr_t>(src);
            guard.guard_hi = guard.guard_lo + len;

            if (__builtin_setjmp(guard.env) != 0)
            {
                // Reached only when the handler longjmped here after swallowing a read fault; the handler already
                // cleared the TLS slot. Report the failure.
                return false;
            }

            // Arm after the setjmp captures env and before the read, so a fault in the rep movsb below is claimable
            // while a fault before the buffer is valid is not. TlsSetValue writes the thread's TLS array with no
            // allocation.
            TlsSetValue(slot, &guard);

            void *dst = out;
            const void *cur = src;
            size_t n = len;
            __asm__ __volatile__("rep movsb" : "+D"(dst), "+S"(cur), "+c"(n) : : "memory");

            TlsSetValue(slot, nullptr);
            return true;
        }

        // Runs fn(ctx) with the vectored handler armed over [lo, hi). Used for in-place accesses where the operation is
        // not the simple rep movsb read that veh_guarded_copy performs. __builtin_setjmp records the recovery point,
        // the guard is published to this thread's TLS slot so a fault inside [lo, hi) is claimable, and the handler
        // longjmps back here so the setjmp expression returns non-zero and the function reports failure. fn must touch
        // only [lo, hi); a fault outside that range (e.g. a bug in fn) is not claimed and reaches the host's handlers.
        // fn is abandoned on a fault via __builtin_longjmp without running destructors, so it must hold no resources
        // that need unwinding -- the scanner sweep and write wrapper use only POD locals. noinline keeps the setjmp
        // anchor and the fn call in one self-contained frame.
        __attribute__((noinline)) bool veh_guarded_region(uintptr_t lo, uintptr_t hi, void (*fn)(void *) noexcept,
                                                          void *ctx) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            VehAccessGuard guard;
            guard.guard_lo = lo;
            guard.guard_hi = hi;

            if (__builtin_setjmp(guard.env) != 0)
            {
                // Reached only when the handler longjmped here after swallowing a fault inside [lo, hi); the
                // handler already cleared the TLS slot. Report the failure.
                return false;
            }

            // Arm after the setjmp captures env and before invoking fn, so a fault in the guarded access is claimable
            // while a fault before the buffer is valid is not.
            TlsSetValue(slot, &guard);
            fn(ctx);
            TlsSetValue(slot, nullptr);
            return true;
        }

        // Single entry point the MinGW read paths share. Rejects a wrapping or low source range first (a wrapped
        // addr + bytes would invert the handler's [guard_lo, guard_hi) check and let a real fault escape the guard);
        // mirrors seh_read_bytes' own precheck so read_ptr_unsafe, which has no precheck of its own, is covered too.
        // Counts the read in the drain epoch around the path decision so a read on the guarded path is always visible
        // to remove_veh_handler's drain. Falls back to a VirtualQuery plus ReadProcessMemory copy when the handler is
        // unavailable.
        bool veh_read_bytes(uintptr_t addr, void *out, size_t bytes) noexcept
        {
            if (addr < SEH_READ_MIN_VALID_ADDR || addr + bytes < addr)
                return false;

            ensure_veh_installed();

            s_veh_in_flight.fetch_add(1, std::memory_order_seq_cst);
            const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
            const bool ok = armed ? veh_guarded_copy(out, reinterpret_cast<const void *>(addr), bytes)
                                  : virtualquery_validated_copy(addr, out, bytes);
            s_veh_in_flight.fetch_sub(1, std::memory_order_release);
            return ok;
        }

        bool veh_write_bytes(uintptr_t addr, const void *source, size_t bytes) noexcept
        {
            if (addr < SEH_READ_MIN_VALID_ADDR || addr + bytes < addr)
                return false;

            struct WriteContext
            {
                uintptr_t dst;
                const void *src;
                size_t bytes;
            } ctx{addr, source, bytes};

            const auto do_write = [](void *opaque) noexcept -> void
            {
                auto *context = static_cast<WriteContext *>(opaque);
                std::memcpy(reinterpret_cast<void *>(context->dst), context->src, context->bytes);
            };

            ensure_veh_installed();

            s_veh_in_flight.fetch_add(1, std::memory_order_seq_cst);
            const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
            const bool ok = armed ? veh_guarded_region(addr, addr + bytes, do_write, &ctx)
                                  : virtualquery_validated_write(addr, source, bytes);
            s_veh_in_flight.fetch_sub(1, std::memory_order_release);
            return ok;
        }
#else  // !_WIN64
       // 32-bit MinGW: the handler's recovery redirect rewrites x64 CONTEXT registers (Rcx/Rip) and the longjmp buffer
       // is x64-sized, so the vectored guard is x64-only. A guarded read here validates every region with VirtualQuery
       // before copying through ReadProcessMemory instead.
        bool veh_read_bytes(uintptr_t addr, void *out, size_t bytes) noexcept
        {
            if (addr < SEH_READ_MIN_VALID_ADDR || addr + bytes < addr)
                return false;
            return virtualquery_validated_copy(addr, out, bytes);
        }

        bool veh_write_bytes(uintptr_t addr, const void *source, size_t bytes) noexcept
        {
            if (addr < SEH_READ_MIN_VALID_ADDR || addr + bytes < addr)
                return false;
            return virtualquery_validated_write(addr, source, bytes);
        }
#endif // _WIN64
    } // anonymous namespace
#endif // !_MSC_VER

#if !defined(_MSC_VER) && defined(_WIN64)
    bool DetourModKit::Memory::detail::run_guarded_region(uintptr_t lo, uintptr_t hi, void (*fn)(void *) noexcept,
                                                          void *ctx) noexcept
    {
        // An empty or wrapping range has nothing to guard; run the access directly. A wrapped [lo, hi) would also
        // invert the handler's range check, the same input veh_read_bytes rejects up front.
        if (hi <= lo)
        {
            fn(ctx);
            return true;
        }

        ensure_veh_installed();

        // Count the call in the drain epoch around the path decision (mirroring veh_read_bytes) so a guarded access is
        // always visible to remove_veh_handler's drain.
        s_veh_in_flight.fetch_add(1, std::memory_order_seq_cst);
        const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
        bool completed = true;
        if (armed)
        {
            completed = veh_guarded_region(lo, hi, fn, ctx);
        }
        else
        {
            // Handler unavailable (install failed, realistic only under resource exhaustion): do not run an in-place
            // scan unguarded. The caller treats false as a skipped/faulted region and fails uniqueness-sensitive work
            // closed.
            completed = false;
        }
        s_veh_in_flight.fetch_sub(1, std::memory_order_release);
        return completed;
    }
#endif // !_MSC_VER && _WIN64

    bool DetourModKit::Memory::init_cache(size_t cache_size, unsigned int expiry_ms, size_t shard_count)
    {
        // Hold state mutex to prevent concurrent clear_cache or shutdown_cache
        // This serializes init/clear/shutdown transitions to ensure vectors are not accessed while being resized or
        // cleared
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

#if !defined(_MSC_VER) && defined(_WIN64)
            // MinGW has no frame-based SEH; install the process-wide vectored fault handler the seh_read paths rely on
            // so a guarded read never has to fall back to a per-call VirtualQuery. Best-effort and independent of cache
            // success: a failed install only costs the guarded reads their VirtualQuery fallback.
            ensure_veh_installed();
#endif

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
                Logger::get_instance().debug(
                    "MemoryCache: Background cleanup thread unavailable, using on-demand cleanup.");
            }

            // Register atexit handler as a last-resort safety net in case the consumer forgets to call shutdown_cache()
            // / DMK_Shutdown(). Prevents std::terminate from the joinable std::thread destructor. The handler detects
            // loader-lock context (FreeLibrary) and skips the thread join to avoid deadlock.
            static bool atexit_registered = false;
            if (!atexit_registered)
            {
                std::atexit(
                    []()
                    {
                        if (s_cache_initialized.load(std::memory_order_seq_cst))
                        {
                            if (is_loader_lock_held())
                            {
#if !defined(_MSC_VER) && defined(_WIN64)
                                // Remove the vectored fault handler before the module can be unloaded: a list removal
                                // is safe under loader lock, and leaving the handler registered against
                                // soon-to-be-freed code is worse than the pinned-thread leak below (it would actively
                                // claim faults on a defunct subsystem). shutdown_cache is not reached on this branch,
                                // so do it here.
                                remove_veh_handler();
#endif
                                // Under loader lock (FreeLibrary path): pin the module so code pages remain valid for
                                // the detached thread, then signal it to stop and detach.
                                s_cleanup_thread_running.store(false, std::memory_order_release);
                                s_cleanup_cv.notify_one();
                                if (s_cleanup_thread.joinable())
                                {
                                    pin_current_module();
                                    s_cleanup_thread.detach();
                                    DetourModKit::Diagnostics::record_intentional_leak(
                                        DetourModKit::Diagnostics::LeakSubsystem::MemoryCache);
                                }
                                s_cache_initialized.store(false, std::memory_order_release);
                                return;
                            }
                            Memory::shutdown_cache();
                        }
                    });
                atexit_registered = true;
            }

            return true;
        }

        // Another thread initialized while we were waiting
        return true;
    }

    void DetourModKit::Memory::clear_cache() noexcept
    {
        // Hold state mutex to serialize with shutdown and cleanup thread
        std::lock_guard<std::mutex> state_lock(s_cache_state_mutex);

        if (!s_cache_initialized.load(std::memory_order_seq_cst))
            return;

        const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
        if (shard_count == 0)
            return;

        // Acquire exclusive lock on each shard and clear entries. Uses blocking lock to guarantee all entries are
        // cleared. The background cleanup thread uses try_to_lock on shard mutexes, so it will skip shards we hold
        // without deadlocking.
        for (size_t i = 0; i < shard_count; ++i)
        {
            std::unique_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx);
            s_cache_shards[i].entries.clear();
            s_cache_shards[i].lru_index.clear();
            s_cache_shards[i].sorted_ranges.clear();
            s_cache_shards[i].in_flight.store(0, std::memory_order_relaxed);
        }

        s_stats.cache_hits.store(0, std::memory_order_relaxed);
        s_stats.cache_misses.store(0, std::memory_order_relaxed);
        s_stats.invalidations.store(0, std::memory_order_relaxed);
        s_stats.coalesced_queries.store(0, std::memory_order_relaxed);
        s_stats.on_demand_cleanups.store(0, std::memory_order_relaxed);

        s_last_cleanup_time_ns.store(current_time_ns(), std::memory_order_relaxed);

        // Diagnostic-only tail. The method is noexcept (a cache teardown must not throw), and Logger::debug can format
        // and flush a sink, so fail closed: a sink or format failure drops the line rather than escaping clear_cache.
        try
        {
            Logger::get_instance().debug("MemoryCache: All entries cleared.");
        }
        catch (...)
        {
        }
    }

    void DetourModKit::Memory::shutdown_cache() noexcept
    {
        // Signal and join cleanup thread BEFORE acquiring state mutex. The cleanup thread acquires s_cache_state_mutex
        // in cleanup_expired_entries(force=true), so joining while holding the state mutex would deadlock.
        s_cleanup_thread_running.store(false, std::memory_order_release);
        s_cleanup_cv.notify_one();

        if (s_cleanup_thread.joinable())
        {
            if (is_loader_lock_held())
            {
                // Under loader lock (DllMain / FreeLibrary): thread join would deadlock because the cleanup thread
                // cannot exit while the loader lock is held. Pin the module so code and static data remain valid, then
                // detach. The thread will observe the stop flag and exit on its own.
                pin_current_module();
                s_cleanup_thread.detach();
                DetourModKit::Diagnostics::record_intentional_leak(
                    DetourModKit::Diagnostics::LeakSubsystem::MemoryCache);
            }
            else
            {
                s_cleanup_thread.join();
            }
        }

        // Acquire state mutex to serialize with clear_cache and protect data teardown
        std::lock_guard<std::mutex> state_lock(s_cache_state_mutex);

        // Mark as not initialized and zero shard count so new readers do not enter the critical section. The
        // s_cache_initialized store is seq_cst (not just
        // release): it pairs with the reader's seq_cst load in the ActiveReaderGuard
        // protocol so the store-buffering (Dekker) race against the reader-count load below is forbidden by the single
        // total order. s_shard_count stays release because readers only read it after passing the seq_cst
        // s_cache_initialized gate.
        // Capture the shard count before zeroing it: the destroy loop below needs the array length, and s_cache_shards
        // is a fixed-size array (no size() of its own). The array is never resized between here and the reset() below.
        const size_t shard_count = s_shard_count.load(std::memory_order_acquire);

        s_cache_initialized.store(false, std::memory_order_seq_cst);
        s_shard_count.store(0, std::memory_order_release);

        // Wait for in-flight readers to finish before destroying data structures. Readers increment their reader stripe
        // on entry and decrement on exit; active_reader_total() sums the stripes. ActiveReaderGuard is RAII so readers
        // always decrement; this loop is bounded by the maximum time a single cache lookup can take. Escalate from
        // yield to sleep to avoid burning CPU if a reader is preempted by the OS scheduler.
        constexpr int yield_spins = 4096;
        int spins = 0;
        while (active_reader_total() > 0)
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
        for (size_t i = 0; i < shard_count; ++i)
        {
            std::unique_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx);
            s_cache_shards[i].entries.clear();
            s_cache_shards[i].lru_index.clear();
            s_cache_shards[i].sorted_ranges.clear();
        }

        s_cache_shards.reset();

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

#if !defined(_MSC_VER) && defined(_WIN64)
        // Remove the vectored fault handler installed for the MinGW seh_read paths so it cannot dangle into freed code
        // if the DMK module is unloaded after teardown. remove_veh_handler drains guarded reads still on the handler
        // path before unregistering, so an in-flight read cannot fault into a missing handler. Idempotent: a no-op when
        // the handler was never installed (cache used without any guarded read) or already removed. A later guarded
        // read re-installs it.
        remove_veh_handler();
#endif

        // Diagnostic-only tail. shutdown_cache() is noexcept, so a sink or format failure must not escape teardown.
        try
        {
            Logger::get_instance().debug("MemoryCache: Shutdown complete.");
        }
        catch (...)
        {
        }
    }

    DetourModKit::Memory::MemoryStats DetourModKit::Memory::get_memory_stats() noexcept
    {
        MemoryStats stats{};
        stats.hits = s_stats.cache_hits.load(std::memory_order_relaxed);
        stats.misses = s_stats.cache_misses.load(std::memory_order_relaxed);
        stats.invalidations = s_stats.invalidations.load(std::memory_order_relaxed);
        stats.coalesced_queries = s_stats.coalesced_queries.load(std::memory_order_relaxed);
        stats.on_demand_cleanups = s_stats.on_demand_cleanups.load(std::memory_order_relaxed);

        stats.shard_count = s_shard_count.load(std::memory_order_acquire);
        stats.max_entries_per_shard = s_max_entries_per_shard.load(std::memory_order_acquire);
        stats.expiry_ms = s_configured_expiry_ms.load(std::memory_order_acquire);

        // Sum live entries and hard-max capacity across shards under the reader guard. A non-zero shard count implies
        // s_cache_shards is allocated (init publishes the count after the array) and the reader guard keeps it alive;
        // when the count is zero the loop simply does not run.
        size_t total_hard_max = 0;
        {
            ActiveReaderGuard reader_guard;
            const size_t active_shard_count = s_shard_count.load(std::memory_order_acquire);
            for (size_t i = 0; i < active_shard_count; ++i)
            {
                std::shared_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx);
                stats.total_entries += s_cache_shards[i].entries.size();
                total_hard_max += s_cache_shards[i].max_capacity;
            }
        }
        stats.hard_max_per_shard = (stats.shard_count > 0) ? total_hard_max / stats.shard_count : 0;

        const uint64_t total_queries = stats.hits + stats.misses;
        stats.hit_rate_percent =
            (total_queries > 0) ? (static_cast<double>(stats.hits) / static_cast<double>(total_queries)) * 100.0 : -1.0;
        return stats;
    }

    std::string DetourModKit::Memory::get_cache_stats()
    {
        const MemoryStats s = get_memory_stats();

        std::ostringstream oss;
        oss << "MemoryCache Stats (Shards: " << s.shard_count << ", Entries/Shard: " << s.max_entries_per_shard
            << ", HardMax/Shard: " << s.hard_max_per_shard << ", Expiry: " << s.expiry_ms << "ms) - "
            << "Hits: " << s.hits << ", Misses: " << s.misses << ", Invalidations: " << s.invalidations
            << ", Coalesced: " << s.coalesced_queries << ", OnDemandCleanups: " << s.on_demand_cleanups
            << ", TotalEntries: " << s.total_entries;

        if (s.hit_rate_percent >= 0.0)
        {
            oss << ", Hit Rate: " << std::fixed << std::setprecision(2) << s.hit_rate_percent << "%";
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

        // Construct reader guard BEFORE checking s_cache_initialized to prevent shutdown_cache from destroying data
        // structures between the check and access.
        ActiveReaderGuard reader_guard;

        if (!s_cache_initialized.load(std::memory_order_seq_cst))
            return;

        const size_t shard_count = s_shard_count.load(std::memory_order_acquire);
        if (shard_count == 0)
            return;

        const uintptr_t addr_val = reinterpret_cast<uintptr_t>(address);
        invalidate_range_internal(addr_val, size);

        // request_cleanup may trigger on-demand cleanup_expired_entries(force=false) which iterates shards without
        // s_cache_state_mutex. The ActiveReaderGuard held by this call keeps a reader stripe non-zero so shutdown_cache
        // cannot destroy shards during the cleanup pass.
        request_cleanup();
    }

    namespace
    {
        /**
         * @brief Unified permission check for is_readable/is_writable.
         * @details Parameterized by permission checker to avoid duplicating the cache lookup, VirtualQuery fallback,
         * and
         *          range validation logic.
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

            // Construct reader guard BEFORE loading s_cache_initialized to prevent shutdown_cache from destroying data
            // structures between the check and access.
            ActiveReaderGuard reader_guard;

            // Snapshot cache readiness once, under the guard. The guard's seq_cst increment is ordered before this
            // seq_cst load of s_cache_initialized (the Dekker protocol that lets shutdown_cache drain readers safely).
            // shard_count is loaded only when initialized, so the cache path below operates on a single consistent
            // value.
            const bool cache_initialized = s_cache_initialized.load(std::memory_order_seq_cst);
            const size_t shard_count = cache_initialized ? s_shard_count.load(std::memory_order_acquire) : 0;

            // Fall back to a direct VirtualQuery whenever the cache is unavailable: never initialized, observed in the
            // brief init publication window where s_cache_initialized is already true but s_shard_count is still 0
            // (init_cache publishes the flag before perform_cache_initialization stores the count), or a concurrent
            // shutdown that has already zeroed the count. Treating shard_count == 0 as "use the direct query" --
            // matching read_ptr_unsafe and invalidate_range -- avoids wrongly reporting a readable region as
            // non-readable during that window.
            if (shard_count == 0)
            {
                MEMORY_BASIC_INFORMATION mbi{};
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

            // Cache is live and shard_count is non-zero -- the reader guard keeps the shard vectors alive for the
            // access.
            const uintptr_t query_addr_val = reinterpret_cast<uintptr_t>(address);
            const size_t shard_idx = compute_shard_index(query_addr_val, shard_count);
            const uint64_t now_ns = current_time_ns();
            const uint64_t expiry_ns = configured_expiry_ns();

            // Fast path: blocking shared lock for concurrent read access (multiple readers allowed)
            {
                std::shared_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                CachedMemoryRegionInfo *cached_info =
                    find_in_shard(s_cache_shards[shard_idx], query_addr_val, size, now_ns, expiry_ns);
                if (cached_info)
                {
                    s_stats.cache_hits.fetch_add(1, std::memory_order_relaxed);
                    return check_permission(cached_info->protection);
                }
            }

            s_stats.cache_misses.fetch_add(1, std::memory_order_relaxed);

            // Cache miss: call VirtualQuery with stampede coalescing
            MEMORY_BASIC_INFORMATION mbi{};
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

    std::expected<void, MemoryError> DetourModKit::Memory::write_bytes(std::byte *target_address,
                                                                       const std::byte *source_bytes, size_t num_bytes)
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
        if (!VirtualProtect(reinterpret_cast<LPVOID>(target_address), num_bytes, PAGE_EXECUTE_READWRITE,
                            &old_protection_flags))
        {
            logger.error(
                "write_bytes: VirtualProtect failed to set PAGE_EXECUTE_READWRITE at address {}. Windows Error: {}",
                DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(target_address)), GetLastError());
            return std::unexpected(MemoryError::ProtectionChangeFailed);
        }

        memcpy(reinterpret_cast<void *>(target_address), reinterpret_cast<const void *>(source_bytes), num_bytes);

        // The bytes are now modified. The instruction-cache flush and the DMK cache-range invalidation must run on
        // every path from here -- they are promised unconditionally, and skipping them after a write would leave stale
        // cached state for bytes that have already changed. Restore the original page protection first so its outcome
        // can be reported, but keep that out of an early return: the cleanup below is a single unconditional block, so
        // the restore-failure path runs exactly the same maintenance as the success path by construction and cannot
        // diverge.
        DWORD temp_old_protect;
        const bool restore_succeeded = VirtualProtect(reinterpret_cast<LPVOID>(target_address), num_bytes,
                                                      old_protection_flags, &temp_old_protect) != FALSE;
        if (!restore_succeeded)
        {
            logger.error("write_bytes: VirtualProtect failed to restore original protection ({}) at address {}. "
                         "Windows Error: {}. Memory may remain writable!",
                         DetourModKit::Format::format_hex(static_cast<int>(old_protection_flags)),
                         DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(target_address)),
                         GetLastError());
        }

        if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(target_address), num_bytes))
        {
            logger.warning("write_bytes: FlushInstructionCache failed for address {}. Windows Error: {}",
                           DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(target_address)),
                           GetLastError());
        }

        Memory::invalidate_range(target_address, num_bytes);

        // Surface the restore failure only after cache maintenance has run.
        if (!restore_succeeded)
        {
            return std::unexpected(MemoryError::ProtectionRestoreFailed);
        }

        // Gate the success log behind the level check so the format_address call is skipped entirely when Debug is off
        // (the shipping default). write_bytes is setup/patch-only, but a consumer that does drive it frequently should
        // not pay a hex format per call just to discard the line.
        if (logger.is_enabled(LogLevel::Debug))
        {
            logger.debug("write_bytes: Successfully wrote {} bytes to address {}.", num_bytes,
                         DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(target_address)));
        }
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
            MEMORY_BASIC_INFORMATION mbi{};
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
        const uint64_t expiry_ns = configured_expiry_ns();

        // Non-blocking: try_lock_shared to avoid stalling latency-sensitive threads
        std::shared_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx, std::try_to_lock);
        if (!lock.owns_lock())
            return ReadableStatus::Unknown;

        CachedMemoryRegionInfo *cached_info =
            find_in_shard(s_cache_shards[shard_idx], query_addr_val, size, now_ns, expiry_ns);
        if (cached_info)
        {
            s_stats.cache_hits.fetch_add(1, std::memory_order_relaxed);
            return check_read_permission(cached_info->protection) ? ReadableStatus::Readable
                                                                  : ReadableStatus::NotReadable;
        }

        // Cache miss with non-blocking semantics: return Unknown rather than issuing VirtualQuery
        return ReadableStatus::Unknown;
    }

    uintptr_t DetourModKit::Memory::read_ptr_unsafe(uintptr_t base, ptrdiff_t offset) noexcept
    {
        // Route the pointer-sized read through the shared guarded-read entry point rather than a private __try/memcpy
        // so a single implementation owns every safety property: the low/null source floor, the (src + size) wrap
        // rejection, and
        // -- under AddressSanitizer on MSVC -- the __movsb copy that seh_read_bytes uses because the compiler otherwise
        // routes std::memcpy through the ASan interceptor, which both false-positives on the foreign mapped memory
        // these probes legitimately read and aborts on a wrapping source range before the SEH guard can turn the fault
        // into a 0 return. seh_read_bytes' byte-wise copy also keeps a misaligned foreign pointer free of cast-deref
        // undefined behavior. A rejected or faulting read yields 0; on a hit, value holds the bytes.
        uintptr_t value = 0;
        if (!seh_read_bytes(base + static_cast<uintptr_t>(offset), &value, sizeof(value)))
            return 0;
        return value;
    }

    bool DetourModKit::Memory::seh_read_bytes(uintptr_t addr, void *out, size_t bytes) noexcept
    {
        if (bytes == 0)
            return true;
        if (!out || addr < SEH_READ_MIN_VALID_ADDR)
            return false;

        // Overflow guard on (addr + bytes); a wraparound source range can never be a valid mapped image.
        if (addr + bytes < addr)
            return false;

#ifdef _MSC_VER
        __try
        {
#if defined(__SANITIZE_ADDRESS__)
            // Copy via __movsb (rep movsb) under ASan: MSVC routes std::memcpy through the ASan interceptor, which
            // inspects the source against ASan's shadow and false-positives on the foreign mapped memory this probe
            // legitimately reads (e.g. a module's data section during the RTTI walk). __movsb emits the copy inline
            // with no interceptable call. Release keeps std::memcpy.
            __movsb(static_cast<unsigned char *>(out), reinterpret_cast<const unsigned char *>(addr), bytes);
#else
            std::memcpy(out, reinterpret_cast<const void *>(addr), bytes);
#endif
            return true;
        }
        __except (Memory::detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                            : EXCEPTION_CONTINUE_SEARCH)
        {
            return false;
        }
#else
        // MinGW lacks __try/__except. Read through the process-wide vectored fault guard (see veh_read_bytes): the
        // success path is a single rep movsb with no syscall, and any read fault across the span -- including a
        // multi-region read that crosses into unmapped or protected memory -- is swallowed and reported as failure.
        return veh_read_bytes(addr, out, bytes);
#endif
    }

    namespace
    {
        // Walk a Cheat-Engine-style pointer chain inside a single fault guard. Every offset except the last is added
        // and dereferenced to obtain the next link; the last offset is added but not dereferenced, yielding the target
        // field address in out_addr. Each intermediate link is screened with plausible_userspace_ptr so a torn or
        // sentinel pointer aborts the walk before the next dereference faults. Returns false on any fault or
        // implausible intermediate link.
        bool resolve_chain_guarded(uintptr_t base, const ptrdiff_t *offsets, size_t count, uintptr_t &out_addr) noexcept
        {
#ifdef _MSC_VER
            __try
            {
                uintptr_t cur = base;
                for (size_t i = 0; i + 1 < count; ++i)
                {
                    uintptr_t next = 0;
                    std::memcpy(&next, reinterpret_cast<const void *>(cur + static_cast<uintptr_t>(offsets[i])),
                                sizeof(next));
                    if (!Memory::plausible_userspace_ptr(next))
                        return false;
                    cur = next;
                }
                out_addr = (count == 0) ? cur : cur + static_cast<uintptr_t>(offsets[count - 1]);
                return true;
            }
            __except (Memory::detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                                : EXCEPTION_CONTINUE_SEARCH)
            {
                return false;
            }
#else
            // MinGW lacks __try/__except. Each intermediate link is read through read_ptr_unsafe, which returns 0 on
            // fault; the plausibility screen also rejects that 0.
            uintptr_t cur = base;
            for (size_t i = 0; i + 1 < count; ++i)
            {
                const uintptr_t next = Memory::read_ptr_unsafe(cur, offsets[i]);
                if (!Memory::plausible_userspace_ptr(next))
                    return false;
                cur = next;
            }
            out_addr = (count == 0) ? cur : cur + static_cast<uintptr_t>(offsets[count - 1]);
            return true;
#endif
        }
    } // anonymous namespace

    std::optional<uintptr_t> DetourModKit::Memory::seh_resolve_chain(uintptr_t base,
                                                                     std::span<const ptrdiff_t> offsets) noexcept
    {
        uintptr_t addr = 0;
        if (resolve_chain_guarded(base, offsets.data(), offsets.size(), addr))
            return addr;
        return std::nullopt;
    }

    bool DetourModKit::Memory::seh_read_chain_bytes(uintptr_t base, std::span<const ptrdiff_t> offsets, void *out,
                                                    size_t bytes) noexcept
    {
        if (bytes == 0)
            return true;
        if (!out)
            return false;

#ifdef _MSC_VER
        // The walk is inlined here rather than reusing resolve_chain_guarded so the resolve and the terminal read sit
        // in one __try region. On x64 the __try is table-driven and free on the no-fault path, so this is a structural
        // choice (one uniform failure path for the whole operation) and not a measurable saving over two adjacent
        // guarded regions.
        const ptrdiff_t *const offs = offsets.data();
        const size_t count = offsets.size();
        __try
        {
            uintptr_t cur = base;
            for (size_t i = 0; i + 1 < count; ++i)
            {
                uintptr_t next = 0;
                std::memcpy(&next, reinterpret_cast<const void *>(cur + static_cast<uintptr_t>(offs[i])), sizeof(next));
                if (!Memory::plausible_userspace_ptr(next))
                    return false;
                cur = next;
            }
            const uintptr_t final_addr = (count == 0) ? cur : cur + static_cast<uintptr_t>(offs[count - 1]);
            // Apply seh_read_bytes' own prechecks on the terminal address so a low or wrapping final address fails
            // identically on both toolchains. The
            // MinGW branch below already routes through seh_read_bytes, which rejects these; matching here keeps a
            // stale or sentinel final address from raising a (benign but debugger-visible) first-chance exception.
            if (final_addr < SEH_READ_MIN_VALID_ADDR || final_addr + bytes < final_addr)
                return false;
            std::memcpy(out, reinterpret_cast<const void *>(final_addr), bytes);
            return true;
        }
        __except (Memory::detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                            : EXCEPTION_CONTINUE_SEARCH)
        {
            return false;
        }
#else
        // MinGW: resolve through the shared guarded-link helper, then read the terminal range with seh_read_bytes so
        // the same vectored fault guard covers the final byte span.
        uintptr_t final_addr = 0;
        if (!resolve_chain_guarded(base, offsets.data(), offsets.size(), final_addr))
            return false;
        return Memory::seh_read_bytes(final_addr, out, bytes);
#endif
    }

    bool DetourModKit::Memory::seh_write_bytes(uintptr_t addr, const void *source, size_t bytes) noexcept
    {
        if (bytes == 0)
            return true;
        if (!source || addr < SEH_READ_MIN_VALID_ADDR)
            return false;

        // Overflow guard on (addr + bytes); a wraparound destination range can never be a valid mapped target.
        if (addr + bytes < addr)
            return false;

#ifdef _MSC_VER
        __try
        {
#if defined(__SANITIZE_ADDRESS__)
            // Copy via __movsb (rep movsb) under ASan for the same reason seh_read_bytes does: MSVC routes std::memcpy
            // through the ASan interceptor, which inspects the operands against ASan's shadow and false-positives on
            // the foreign mapped memory this primitive legitimately writes. __movsb emits the copy inline with no
            // interceptable call. Release keeps std::memcpy.
            __movsb(reinterpret_cast<unsigned char *>(addr), static_cast<const unsigned char *>(source), bytes);
#else
            std::memcpy(reinterpret_cast<void *>(addr), source, bytes);
#endif
            return true;
        }
        __except (Memory::detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                            : EXCEPTION_CONTINUE_SEARCH)
        {
            return false;
        }
#else
        // MinGW: write through the same guard/fallback split as seh_read_bytes. x64 uses the process-wide vectored
        // guard when available; if the handler cannot be installed, and on 32-bit builds, the fallback validates the
        // destination and writes through WriteProcessMemory.
        return veh_write_bytes(addr, source, bytes);
#endif
    }

    bool DetourModKit::Memory::seh_write_chain_bytes(uintptr_t base, std::span<const ptrdiff_t> offsets,
                                                     const void *source, size_t bytes) noexcept
    {
        if (bytes == 0)
            return true;
        if (!source)
            return false;

#ifdef _MSC_VER
        // The walk is inlined here rather than reusing resolve_chain_guarded so the resolve and the terminal write sit
        // in one __try region, mirroring seh_read_chain_bytes: one uniform failure path for the whole operation.
        const ptrdiff_t *const offs = offsets.data();
        const size_t count = offsets.size();
        __try
        {
            uintptr_t cur = base;
            for (size_t i = 0; i + 1 < count; ++i)
            {
                uintptr_t next = 0;
                std::memcpy(&next, reinterpret_cast<const void *>(cur + static_cast<uintptr_t>(offs[i])), sizeof(next));
                if (!Memory::plausible_userspace_ptr(next))
                    return false;
                cur = next;
            }
            const uintptr_t final_addr = (count == 0) ? cur : cur + static_cast<uintptr_t>(offs[count - 1]);
            // Same terminal-address prechecks as seh_read_chain_bytes so a low or wrapping final address fails
            // identically on both toolchains before the store is attempted.
            if (final_addr < SEH_READ_MIN_VALID_ADDR || final_addr + bytes < final_addr)
                return false;
            std::memcpy(reinterpret_cast<void *>(final_addr), source, bytes);
            return true;
        }
        __except (Memory::detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                            : EXCEPTION_CONTINUE_SEARCH)
        {
            return false;
        }
#else
        // MinGW: resolve through the shared guarded-link helper (its intermediate reads use the vectored guard), then
        // write the terminal range through seh_write_bytes so the same guard covers the final store.
        uintptr_t final_addr = 0;
        if (!resolve_chain_guarded(base, offsets.data(), offsets.size(), final_addr))
            return false;
        return Memory::seh_write_bytes(final_addr, source, bytes);
#endif
    }

    namespace
    {
        // PE header layout for module range resolution. Pulled into an anonymous namespace so the helper is internal to
        // memory.cpp and shared between module_range_for, own_module_range, and host_module_range.
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
            if (!DetourModKit::Memory::seh_read_bytes(base + static_cast<uintptr_t>(dos.e_lfanew), &nt, sizeof(nt)))
                return {};
            if (nt.Signature != IMAGE_NT_SIGNATURE)
                return {};

            const uintptr_t size_of_image = nt.OptionalHeader.SizeOfImage;
            if (size_of_image == 0)
                return {};

            return {base, base + size_of_image};
        }

        // Per-process ModuleRange cache shared by module_range_for. Constructed on first use; survives until process
        // exit. Static-storage destruction is deliberately a non-issue here because the cache is consulted only by
        // DetourModKit code that has already shut down its own subsystems via
        // DMK_Shutdown() (callers do not query ranges from atexit handlers).
        struct ModuleRangeCache
        {
            SrwSharedMutex mtx;
            std::unordered_map<HMODULE, DetourModKit::Memory::ModuleRange> entries;
        };

        ModuleRangeCache &get_module_range_cache() noexcept
        {
            static ModuleRangeCache cache;
            return cache;
        }
    } // anonymous namespace

    std::optional<DetourModKit::Memory::ModuleRange>
    DetourModKit::Memory::module_range_for(const void *address) noexcept
    {
        if (!address)
            return std::nullopt;

        HMODULE mod = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(address), &mod) ||
            mod == nullptr)
        {
            return std::nullopt;
        }

        auto &cache = get_module_range_cache();
        {
            std::shared_lock<SrwSharedMutex> lock(cache.mtx);
            const auto it = cache.entries.find(mod);
            if (it != cache.entries.end())
                return it->second;
        }

        const auto range = module_range_from_handle(mod);
        if (!range.valid())
            return std::nullopt;

        {
            std::unique_lock<SrwSharedMutex> lock(cache.mtx);
            // Another thread may have inserted between our shared/unique transition;
            // emplace skips on collision so we keep the first-resolved entry.
            cache.entries.emplace(mod, range);
        }
        return range;
    }

    DetourModKit::Memory::ModuleRange DetourModKit::Memory::own_module_range() noexcept
    {
        // Magic-static initialization: the lambda runs exactly once per module, guarded by the C++23
        // thread-safe-initialization rules. Taking the address of own_module_range itself anchors the lookup in
        // whichever DLL/EXE statically linked this translation unit.
        static const ModuleRange cached = []
        {
            HMODULE mod = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(&DetourModKit::Memory::own_module_range), &mod) ||
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
} // namespace DetourModKit
