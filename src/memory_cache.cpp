/**
 * @file memory_cache.cpp
 * @brief The protection-region cache and the readability predicates built over it.
 *
 * Provides memory::is_readable / is_writable / is_readable_nonblocking and the cache lifecycle (init / clear / shutdown
 * / stats / invalidate). The cache uses sharded SRW locks for high-concurrency read-heavy access, a monotonic-counter
 * LRU map for O(log n) eviction, in-flight query coalescing to prevent VirtualQuery stampedes, on-demand cleanup to
 * keep the miss path clean, and epoch-based reader tracking so shutdown can drain readers before freeing shard storage.
 * This TU touches no Structured Exception Handling; on MinGW it drives the guarded-engine vectored-handler lifecycle
 * through the engine seam so a guarded read never has to fall back to a per-call VirtualQuery.
 */

#include "DetourModKit/memory.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/srw_shared_mutex.hpp"
#include "platform.hpp"
#include "internal/memory_guarded.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>

namespace DetourModKit
{
    namespace memory
    {
        using DetourModKit::detail::is_loader_lock_held;
        using DetourModKit::detail::pin_current_module;
        using DetourModKit::detail::SrwSharedMutex;

        namespace
        {
            // Page-protection flag groups for the cache permission checks. Grouped in a struct rather than a named
            // namespace so the constants keep internal linkage through the enclosing anonymous namespace.
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
             * @brief Cached protection snapshot for one VirtualQuery region, with an LRU key and validity timestamp.
             */
            struct CachedMemoryRegionInfo
            {
                std::uintptr_t base_address;
                std::size_t region_size;
                DWORD protection;
                DWORD state;
                std::uint64_t timestamp_ns;
                std::uint64_t lru_key;
                bool valid;

                CachedMemoryRegionInfo()
                    : base_address(0), region_size(0), protection(0), state(0), timestamp_ns(0), lru_key(0),
                      valid(false)
                {
                }
            };

            /**
             * @struct CacheShard
             * @brief One cache shard with O(1) address lookup and O(log n) LRU eviction.
             * @details An unordered_map keyed by region base address gives the fast hit path; a std::map keyed by a
             *          monotonic counter gives oldest-entry eviction; a sorted deque gives O(log n) containment lookup
             *          for sub-page queries inside larger regions. The per-shard SRW lock and the in_flight
             *          stampede-coalescing flag are inline and the struct is cache-line aligned, so one shard's lock
             *          word never shares a line with another's. Inlining the mutex makes the shard non-movable, so the
             *          shards are a fixed-size array allocated once, never a resizable vector.
             */
#if defined(_MSC_VER)
#pragma warning(push)
// C4324: CacheShard is intentionally padded to a full cache line by alignas(64) for cache-line hygiene.
#pragma warning(disable : 4324)
#endif
            struct alignas(64) CacheShard
            {
                std::unordered_map<std::uintptr_t, CachedMemoryRegionInfo> entries;
                std::map<std::uint64_t, std::uintptr_t> lru_index;
                // Sorted by base address for O(log n) containment lookup. All access is serialized by the shard SRW
                // lock (shared for lookups, exclusive for mutation), so iterators never outlive a critical section. The
                // deque prevents wholesale buffer relocation on growth, though interior insert/erase still invalidates
                // deque iterators per the standard. {base, base + size}.
                std::deque<std::pair<std::uintptr_t, std::uintptr_t>> sorted_ranges;
                SrwSharedMutex mtx;
                // The first thread to CAS this 0 -> 1 becomes the VirtualQuery leader for the shard; the rest coalesce
                // onto its result. Inline so it never shares a cache line with a neighbouring shard's flag.
                std::atomic<char> in_flight{0};
                std::uint64_t entry_counter{0};
                std::size_t capacity;
                std::size_t max_capacity;

                CacheShard() : capacity(0), max_capacity(0) { entries.reserve(64); }
            };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

            // The sorted-ranges container type is pinned as a refactor tripwire: with a deque, mutation never relocates
            // the whole buffer under the lock. This is not iterator stability (deque insert/erase invalidates
            // iterators); the lock is what excludes concurrent access.
            static_assert(std::is_same_v<decltype(CacheShard::sorted_ranges),
                                         std::deque<std::pair<std::uintptr_t, std::uintptr_t>>>,
                          "CacheShard::sorted_ranges is pinned to std::deque so mutation never relocates the buffer.");

            /// Current steady-clock time in nanoseconds.
            inline std::uint64_t current_time_ns() noexcept
            {
                return std::chrono::duration_cast<std::chrono::nanoseconds>(
                           std::chrono::steady_clock::now().time_since_epoch())
                    .count();
            }

            /**
             * @brief Computes the shard index for an address.
             * @note Uses golden-ratio bit-mixing to spread adjacent addresses across shards.
             */
            constexpr inline std::size_t compute_shard_index(std::uintptr_t address, std::size_t shard_count) noexcept
            {
                return (static_cast<std::size_t>((address * 0x9E3779B97F4A7C15ULL) >> 48)) % shard_count;
            }

            // Fixed-size shard array, allocated once by perform_cache_initialization and never resized: CacheShard owns
            // its SrwSharedMutex and in_flight atomic inline and so is non-movable. null until init, reset on shutdown.
            std::unique_ptr<CacheShard[]> s_cache_shards;
            std::atomic<std::size_t> s_shard_count{0};
            std::atomic<std::size_t> s_max_entries_per_shard{0};
            std::atomic<unsigned int> s_configured_expiry_ms{0};
            std::atomic<bool> s_cache_initialized{false};

            /// Configured cache-entry expiry converted from milliseconds to nanoseconds.
            [[nodiscard]] inline std::uint64_t configured_expiry_ns() noexcept
            {
                return static_cast<std::uint64_t>(s_configured_expiry_ms.load(std::memory_order_acquire)) *
                       1'000'000ULL;
            }

            // Serializes init/clear/shutdown transitions so the shard array is never accessed while being allocated or
            // cleared.
            std::mutex s_cache_state_mutex;

            // Epoch-based reader tracking to prevent use-after-free during shutdown. Readers increment on entry and
            // decrement on exit; shutdown waits for the count to reach zero before freeing data. The count is striped
            // across cache-line-padded counters rather than a single global atomic, so concurrent readers do not
            // re-serialize on one shared line. Distributing the increment does not weaken the drain -- see
            // active_reader_total and the ActiveReaderGuard Dekker note.
            constexpr std::size_t READER_STRIPE_COUNT = 64;

#if defined(_MSC_VER)
#pragma warning(push)
// C4324: ReaderStripe is intentionally padded to a full cache line by alignas(64) so stripes never share a line.
#pragma warning(disable : 4324)
#endif
            struct alignas(64) ReaderStripe
            {
                std::atomic<std::int32_t> count{0};
            };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

            std::array<ReaderStripe, READER_STRIPE_COUNT> s_reader_stripes{};

            /**
             * @brief Returns this thread's reader stripe, assigned round-robin on first use so concurrent readers
             * spread
             *        across distinct cache lines instead of contending on one counter.
             */
            [[nodiscard]] inline std::size_t reader_stripe_index() noexcept
            {
                static std::atomic<std::size_t> s_next_stripe{0};
                thread_local const std::size_t stripe =
                    s_next_stripe.fetch_add(1, std::memory_order_relaxed) % READER_STRIPE_COUNT;
                return stripe;
            }

            /**
             * @brief Sum of all reader stripes: the number of readers currently inside an ActiveReaderGuard.
             * @details shutdown_cache spins on this reaching zero (under seq_cst) after publishing
             *          s_cache_initialized=false, before freeing shard storage.
             */
            [[nodiscard]] inline std::int64_t active_reader_total() noexcept
            {
                std::int64_t total = 0;
                for (const ReaderStripe &stripe : s_reader_stripes)
                {
                    total += stripe.count.load(std::memory_order_seq_cst);
                }
                return total;
            }

            /**
             * @class ActiveReaderGuard
             * @brief RAII guard that increments this thread's reader stripe on construction and decrements on
             *        destruction, ensuring correct pairing on all exit paths.
             */
            class ActiveReaderGuard
            {
            public:
                ActiveReaderGuard() noexcept : m_stripe(reader_stripe_index())
                {
                    // seq_cst (not acq_rel) so this increment and the reader's subsequent seq_cst load of
                    // s_cache_initialized share the single total order that forbids the store-buffering (Dekker)
                    // outcome with shutdown_cache: shutdown stores s_cache_initialized=false then sums every stripe,
                    // while a reader increments its stripe then loads s_cache_initialized. Under seq_cst a reader that
                    // observes the cache live was necessarily counted before shutdown reads that stripe. On x86-64 this
                    // is the same lock xadd as acq_rel, so the hot path pays nothing beyond landing on a per-thread
                    // line.
                    s_reader_stripes[m_stripe].count.fetch_add(1, std::memory_order_seq_cst);
                }

                ~ActiveReaderGuard() noexcept
                {
                    s_reader_stripes[m_stripe].count.fetch_sub(1, std::memory_order_release);
                }

                ActiveReaderGuard(const ActiveReaderGuard &) = delete;
                ActiveReaderGuard &operator=(const ActiveReaderGuard &) = delete;

            private:
                const std::size_t m_stripe;
            };

            // Background cleanup thread. Uses std::thread (not jthread) because these are namespace-scope statics:
            // jthread's auto-join destructor would run after s_cleanup_cv/s_cleanup_mutex are destroyed (reverse
            // declaration order), causing UB. Manual join in shutdown_cache avoids this.
            std::atomic<bool> s_cleanup_thread_running{false};
            std::thread s_cleanup_thread;
            std::mutex s_cleanup_mutex;
            std::condition_variable s_cleanup_cv;
            std::atomic<bool> s_cleanup_requested{false};

            // On-demand cleanup fallback timer (used when the background thread is disabled).
            std::atomic<std::uint64_t> s_last_cleanup_time_ns{0};
            constexpr std::uint64_t CLEANUP_INTERVAL_NS = 1'000'000'000ULL;

            // Always-available cache statistics.
            struct CacheStats
            {
                std::atomic<std::uint64_t> cache_hits{0};
                std::atomic<std::uint64_t> cache_misses{0};
                std::atomic<std::uint64_t> invalidations{0};
                std::atomic<std::uint64_t> coalesced_queries{0};
                std::atomic<std::uint64_t> on_demand_cleanups{0};
            };
            CacheStats s_stats;

            /**
             * @brief Checks if a cache entry is valid and covers [address, address + size).
             */
            constexpr inline bool is_entry_valid_and_covers(const CachedMemoryRegionInfo &entry, std::uintptr_t address,
                                                            std::size_t size, std::uint64_t current_ns,
                                                            std::uint64_t expiry_ns) noexcept
            {
                if (!entry.valid)
                    return false;

                const std::uint64_t entry_age = current_ns - entry.timestamp_ns;
                if (entry_age > expiry_ns)
                    return false;

                const std::uintptr_t end_address = address + size;
                if (end_address < address)
                    return false;

                const std::uintptr_t entry_end_address = entry.base_address + entry.region_size;
                if (entry_end_address < entry.base_address)
                    return false;

                return address >= entry.base_address && end_address <= entry_end_address;
            }

            /// Checks protection flags for read permission.
            constexpr inline bool check_read_permission(DWORD protection) noexcept
            {
                return (protection & CachePermissions::READ_PERMISSION_FLAGS) != 0 &&
                       (protection & CachePermissions::NOACCESS_GUARD_FLAGS) == 0;
            }

            /// Checks protection flags for write permission.
            constexpr inline bool check_write_permission(DWORD protection) noexcept
            {
                return (protection & CachePermissions::WRITE_PERMISSION_FLAGS) != 0 &&
                       (protection & CachePermissions::NOACCESS_GUARD_FLAGS) == 0;
            }

            /**
             * @brief Inserts a range into the shard's sorted auxiliary container.
             * @note Must be called with the shard mutex held (exclusive).
             */
            void insert_sorted_range(CacheShard &shard, std::uintptr_t base_addr, std::size_t region_size) noexcept
            {
                auto range = std::make_pair(base_addr, base_addr + region_size);
                auto pos = std::lower_bound(shard.sorted_ranges.begin(), shard.sorted_ranges.end(), range);
                shard.sorted_ranges.insert(pos, range);
            }

            /**
             * @brief Removes a range from the shard's sorted auxiliary container.
             * @note Must be called with the shard mutex held (exclusive).
             */
            void remove_sorted_range(CacheShard &shard, std::uintptr_t base_addr) noexcept
            {
                auto it = std::lower_bound(shard.sorted_ranges.begin(), shard.sorted_ranges.end(),
                                           std::make_pair(base_addr, std::uintptr_t{0}));
                if (it != shard.sorted_ranges.end() && it->first == base_addr)
                    shard.sorted_ranges.erase(it);
            }

            /**
             * @brief Finds and validates a cache entry in a shard by scanning for range containment.
             * @note Must be called with the shard mutex held (shared or exclusive).
             * @note First attempts direct lookup by page-aligned base address for the O(1) fast path, then falls back
             * to
             *       O(log n) binary search via sorted_ranges for addresses within larger regions.
             */
            CachedMemoryRegionInfo *find_in_shard(CacheShard &shard, std::uintptr_t address, std::size_t size,
                                                  std::uint64_t current_ns, std::uint64_t expiry_ns) noexcept
            {
                const std::uintptr_t base_addr = address & ~static_cast<std::uintptr_t>(0xFFF);
                auto it = shard.entries.find(base_addr);
                if (it != shard.entries.end())
                {
                    CachedMemoryRegionInfo &entry = it->second;
                    if (is_entry_valid_and_covers(entry, address, size, current_ns, expiry_ns))
                    {
                        return &entry;
                    }
                }

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
                            if (is_entry_valid_and_covers(entry, address, size, current_ns, expiry_ns))
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
             * @note Must be called with the shard mutex held (exclusive).
             * @return true if an entry was evicted, false if the shard is empty.
             */
            bool evict_oldest_entry(CacheShard &shard) noexcept
            {
                if (shard.lru_index.empty())
                    return false;

                const auto lru_it = shard.lru_index.begin();
                const std::uintptr_t oldest_base = lru_it->second;

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
             * @brief Force-evicts entries until the shard is at or below max_capacity.
             * @note Must be called with the shard mutex held (exclusive).
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
             * @note Must be called with the shard mutex held (exclusive).
             */
            void update_shard_with_region(CacheShard &shard, const MEMORY_BASIC_INFORMATION &mbi,
                                          std::uint64_t current_ns) noexcept
            {
                const std::uintptr_t base_addr = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);

                auto it = shard.entries.find(base_addr);
                if (it != shard.entries.end())
                {
                    CachedMemoryRegionInfo &old_entry = it->second;
                    const auto lru_it = shard.lru_index.find(old_entry.lru_key);
                    if (lru_it != shard.lru_index.end() && lru_it->second == base_addr)
                    {
                        shard.lru_index.erase(lru_it);
                    }

                    if (old_entry.region_size != mbi.RegionSize)
                    {
                        remove_sorted_range(shard, base_addr);
                        insert_sorted_range(shard, base_addr, mbi.RegionSize);
                    }

                    const std::uint64_t new_lru_key = shard.entry_counter++;
                    old_entry.base_address = base_addr;
                    old_entry.region_size = mbi.RegionSize;
                    old_entry.protection = mbi.Protect;
                    old_entry.state = mbi.State;
                    old_entry.timestamp_ns = current_ns;
                    old_entry.lru_key = new_lru_key;
                    old_entry.valid = true;

                    shard.lru_index.emplace(new_lru_key, base_addr);
                }
                else
                {
                    if (shard.entries.size() >= shard.capacity)
                    {
                        evict_oldest_entry(shard);
                    }

                    if (shard.entries.size() >= shard.max_capacity)
                    {
                        trim_to_max_capacity(shard);
                    }

                    const std::uint64_t new_lru_key = shard.entry_counter++;

                    CachedMemoryRegionInfo new_entry;
                    new_entry.base_address = base_addr;
                    new_entry.region_size = mbi.RegionSize;
                    new_entry.protection = mbi.Protect;
                    new_entry.state = mbi.State;
                    new_entry.timestamp_ns = current_ns;
                    new_entry.lru_key = new_lru_key;
                    new_entry.valid = true;

                    shard.entries.insert_or_assign(base_addr, std::move(new_entry));
                    shard.lru_index.emplace(new_lru_key, base_addr);
                    insert_sorted_range(shard, base_addr, mbi.RegionSize);
                }
            }

            /**
             * @brief Removes expired entries from a shard.
             * @note Must be called with the shard mutex held (exclusive).
             * @return Number of entries removed from this shard.
             */
            std::size_t cleanup_expired_entries_in_shard(CacheShard &shard, std::uint64_t current_ns,
                                                         std::uint64_t expiry_ns) noexcept
            {
                std::size_t removed = 0;
                auto it = shard.entries.begin();
                while (it != shard.entries.end())
                {
                    const CachedMemoryRegionInfo &entry = it->second;
                    const std::uint64_t entry_age = current_ns - entry.timestamp_ns;

                    if (!entry.valid || entry_age > expiry_ns)
                    {
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
             * @param force Force cleanup regardless of state-mutex contention.
             */
            void cleanup_expired_entries(bool force) noexcept
            {
                // Always hold the state mutex to prevent racing with shutdown_cache, which frees the shard array.
                // try_lock for on-demand to avoid blocking the hot path; forced cleanup blocks to guarantee progress.
                std::unique_lock<std::mutex> lock(s_cache_state_mutex, std::defer_lock);
                if (force)
                {
                    lock.lock();
                }
                else if (!lock.try_lock())
                {
                    return;
                }

                if (!s_cache_shards)
                    return;

                const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
                if (shard_count == 0)
                    return;

                const std::uint64_t current_ts = current_time_ns();
                const std::uint64_t expiry_ns = configured_expiry_ns();

                for (std::size_t i = 0; i < shard_count; ++i)
                {
                    std::unique_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx, std::try_to_lock);
                    if (shard_lock.owns_lock())
                    {
                        cleanup_expired_entries_in_shard(s_cache_shards[i], current_ts, expiry_ns);
                        trim_to_max_capacity(s_cache_shards[i]);
                    }
                }
            }

            /**
             * @brief Checks whether on-demand cleanup should run based on elapsed time.
             * @return true if cleanup was performed.
             */
            bool try_trigger_on_demand_cleanup() noexcept
            {
                if (!s_cache_initialized.load(std::memory_order_seq_cst))
                    return false;

                const std::uint64_t now_ns = current_time_ns();
                const std::uint64_t last_cleanup = s_last_cleanup_time_ns.load(std::memory_order_acquire);
                const std::uint64_t elapsed_ns = now_ns - last_cleanup;

                if (elapsed_ns >= CLEANUP_INTERVAL_NS)
                {
                    std::uint64_t expected = last_cleanup;
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
             * @brief Background cleanup thread body: removes expired entries periodically off the miss path.
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

                    cleanup_expired_entries(true);
                    s_cleanup_requested.store(false, std::memory_order_relaxed);
                }
            }

            /**
             * @brief Signals the cleanup thread to run, or triggers on-demand cleanup when the thread is disabled.
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
                    try_trigger_on_demand_cleanup();
                }
            }

            /**
             * @brief Evicts every entry in a shard whose region overlaps [address, end_address).
             * @note Must be called with the shard mutex held (exclusive).
             * @note Scans the whole shard rather than probing a single key: an entry is keyed by its VirtualQuery
             * region
             *       base but stored in the shard chosen from the original query address, so one region can be cached in
             *       several shards under the same base key. The shard is bounded by max_capacity and invalidation runs
             *       only after a write, so this linear scan is never on a read hot path.
             */
            std::size_t evict_overlapping_entries_in_shard(CacheShard &shard, std::uintptr_t address,
                                                           std::uintptr_t end_address) noexcept
            {
                std::size_t evicted = 0;
                auto it = shard.entries.begin();
                while (it != shard.entries.end())
                {
                    const CachedMemoryRegionInfo &entry = it->second;
                    const std::uintptr_t entry_end_address = entry.base_address + entry.region_size;
                    // A VirtualQuery region cannot extend past the address space, but a corrupt cached size could;
                    // treat a wrapped end as covering the top of the space so a poisoned entry is still evicted.
                    const std::uintptr_t clamped_entry_end =
                        (entry_end_address < entry.base_address) ? UINTPTR_MAX : entry_end_address;
                    const bool overlaps =
                        entry.valid && address < clamped_entry_end && end_address > entry.base_address;
                    if (overlaps)
                    {
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
             */
            void invalidate_range_internal(std::uintptr_t address, std::size_t size) noexcept
            {
                if (!s_cache_shards || size == 0)
                    return;

                const std::uintptr_t end_address = (address + size < address) ? UINTPTR_MAX : address + size;
                const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);

                constexpr std::size_t MAX_INVALIDATION_RETRIES = 3;

                std::size_t skipped_shards = 0;
                for (std::size_t shard_idx = 0; shard_idx < shard_count; ++shard_idx)
                {
                    bool invalidated = false;
                    for (std::size_t retry = 0; retry < MAX_INVALIDATION_RETRIES; ++retry)
                    {
                        std::unique_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx, std::try_to_lock);
                        if (!lock.owns_lock())
                        {
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
                    // A shard that stayed contended across every retry keeps its entries until the configured expiry
                    // sweeps them. Surface it for diagnosis instead of skipping silently; try_log keeps this noexcept
                    // path honest when the level is enabled.
                    (void)Logger::get_instance().try_log(
                        LogLevel::Debug,
                        "MemoryCache: invalidate_range left {} contended shard(s) unswept; "
                        "stale entries persist until expiry.",
                        skipped_shards);
                }
            }

            /**
             * @brief Performs one-time cache initialization (allocates the shard array, configures bounds).
             */
            bool perform_cache_initialization(std::size_t cache_size, unsigned int expiry_ms, std::size_t shard_count)
            {
                if (cache_size == 0)
                    cache_size = MIN_CACHE_SIZE;
                if (shard_count == 0)
                    shard_count = 1;

                const std::size_t entries_per_shard = (cache_size + shard_count - 1) / shard_count;
                const std::size_t hard_max_per_shard = entries_per_shard * DEFAULT_MAX_CACHE_SIZE_MULTIPLIER;

                try
                {
                    s_cache_shards = std::make_unique<CacheShard[]>(shard_count);
                    for (std::size_t i = 0; i < shard_count; ++i)
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
             * @brief Performs VirtualQuery and updates the cache with stampede coalescing.
             * @return true if VirtualQuery (or a coalesced follower read) succeeded.
             */
            bool query_and_update_cache(std::size_t shard_idx, LPCVOID address,
                                        MEMORY_BASIC_INFORMATION &mbi_out) noexcept
            {
                CacheShard &shard = s_cache_shards[shard_idx];

                char expected = 0;
                if (shard.in_flight.compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
                {
                    const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                    const std::uint64_t now_ns = current_time_ns();

                    if (result)
                    {
                        std::unique_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                        update_shard_with_region(shard, mbi_out, now_ns);
                    }

                    shard.in_flight.store(0, std::memory_order_release);
                    return result;
                }
                else
                {
                    const std::uint64_t expiry_ns = configured_expiry_ns();
                    constexpr std::size_t MAX_FOLLOWER_YIELDS = 8;

                    for (std::size_t yield_count = 0; yield_count < MAX_FOLLOWER_YIELDS; ++yield_count)
                    {
                        if (shard.in_flight.load(std::memory_order_acquire) == 0)
                        {
                            const std::uintptr_t addr_val = reinterpret_cast<std::uintptr_t>(address);
                            std::shared_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                            CachedMemoryRegionInfo *cached =
                                find_in_shard(shard, addr_val, 1, current_time_ns(), expiry_ns);
                            if (cached)
                            {
                                s_stats.coalesced_queries.fetch_add(1, std::memory_order_relaxed);
                                mbi_out.BaseAddress = reinterpret_cast<PVOID>(cached->base_address);
                                mbi_out.RegionSize = cached->region_size;
                                mbi_out.Protect = cached->protection;
                                mbi_out.State = cached->state;
                                return true;
                            }
                            break;
                        }

                        std::this_thread::yield();
                    }

                    expected = 0;
                    if (shard.in_flight.compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
                    {
                        const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                        if (result)
                        {
                            std::unique_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                            const std::uint64_t now_ns = current_time_ns();
                            update_shard_with_region(shard, mbi_out, now_ns);
                        }
                        shard.in_flight.store(0, std::memory_order_release);
                        return result;
                    }

                    return VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                }
            }

            /**
             * @brief Unified permission check shared by is_readable and is_writable.
             * @param address Start address of the query (0 fails closed).
             * @param size Number of bytes to check (0 fails closed).
             * @param check_permission Predicate validating the protection flags.
             */
            bool check_memory_permission(std::uintptr_t address, std::size_t size,
                                         bool (*check_permission)(DWORD) noexcept) noexcept
            {
                if (address == 0 || size == 0)
                    return false;

                // Construct the reader guard BEFORE loading s_cache_initialized so shutdown_cache cannot free the shard
                // array between the check and the access.
                ActiveReaderGuard reader_guard;

                const bool cache_initialized = s_cache_initialized.load(std::memory_order_seq_cst);
                const std::size_t shard_count = cache_initialized ? s_shard_count.load(std::memory_order_acquire) : 0;

                // Fall back to a direct VirtualQuery whenever the cache is unavailable: never initialized, observed in
                // the brief init publication window (flag set but count still 0), or a concurrent shutdown that already
                // zeroed the count.
                if (shard_count == 0)
                {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
                        return false;
                    if (mbi.State != MEM_COMMIT)
                        return false;
                    if (!check_permission(mbi.Protect))
                        return false;
                    const std::uintptr_t region_start = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                    const std::uintptr_t query_end = address + size;
                    if (query_end < address)
                        return false;
                    return address >= region_start && query_end <= region_start + mbi.RegionSize;
                }

                const std::size_t shard_idx = compute_shard_index(address, shard_count);
                const std::uint64_t now_ns = current_time_ns();
                const std::uint64_t expiry_ns = configured_expiry_ns();

                {
                    std::shared_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                    CachedMemoryRegionInfo *cached_info =
                        find_in_shard(s_cache_shards[shard_idx], address, size, now_ns, expiry_ns);
                    if (cached_info)
                    {
                        s_stats.cache_hits.fetch_add(1, std::memory_order_relaxed);
                        return check_permission(cached_info->protection);
                    }
                }

                s_stats.cache_misses.fetch_add(1, std::memory_order_relaxed);

                MEMORY_BASIC_INFORMATION mbi{};
                if (!query_and_update_cache(shard_idx, reinterpret_cast<LPCVOID>(address), mbi))
                    return false;

                if (mbi.State != MEM_COMMIT)
                    return false;

                if (!check_permission(mbi.Protect))
                    return false;

                const std::uintptr_t region_start_addr = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::uintptr_t region_end_addr = region_start_addr + mbi.RegionSize;
                const std::uintptr_t query_end_addr = address + size;

                if (query_end_addr < address)
                    return false;

                return address >= region_start_addr && query_end_addr <= region_end_addr;
            }
        } // namespace

        bool init_cache(std::size_t cache_size, unsigned int expiry_ms, std::size_t shard_count)
        {
            std::lock_guard<std::mutex> state_lock(s_cache_state_mutex);

            if (s_cache_initialized.load(std::memory_order_seq_cst))
                return true;

            bool expected = false;
            if (s_cache_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
            {
                if (!perform_cache_initialization(cache_size, expiry_ms, shard_count))
                {
                    return false;
                }

#if !defined(_MSC_VER) && defined(_WIN64)
                // MinGW has no frame-based SEH; install the process-wide vectored fault handler the guarded reads rely
                // on so a guarded read never has to fall back to a per-call VirtualQuery. Best-effort and independent
                // of cache success.
                detail::ensure_guarded_engine_installed();
#endif

                s_cleanup_thread_running.store(true, std::memory_order_release);
                try
                {
                    s_cleanup_thread = std::thread(cleanup_thread_func);
                }
                catch (const std::system_error &)
                {
                    s_cleanup_thread_running.store(false, std::memory_order_release);
                    Logger::get_instance().debug(
                        "MemoryCache: Background cleanup thread unavailable, using on-demand cleanup.");
                }

                // Last-resort safety net: clean up if the consumer forgets to call shutdown_cache. The handler detects
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
                                    // Remove the vectored fault handler before the module can unload: a list removal is
                                    // safe under loader lock, and leaving the handler registered against
                                    // soon-to-be-freed code is worse than the pinned-thread leak below.
                                    detail::release_guarded_engine();
#endif
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
                                shutdown_cache();
                            }
                        });
                    atexit_registered = true;
                }

                return true;
            }

            return true;
        }

        void clear_cache() noexcept
        {
            std::lock_guard<std::mutex> state_lock(s_cache_state_mutex);

            if (!s_cache_initialized.load(std::memory_order_seq_cst))
                return;

            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            if (shard_count == 0)
                return;

            // Blocking exclusive lock per shard to guarantee all entries are cleared. The cleanup thread uses try_lock,
            // so it skips shards we hold without deadlocking.
            for (std::size_t i = 0; i < shard_count; ++i)
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

            // Diagnostic-only tail; clear_cache is noexcept, so a sink or format failure drops the line.
            try
            {
                Logger::get_instance().debug("MemoryCache: All entries cleared.");
            }
            catch (...)
            {
            }
        }

        void shutdown_cache() noexcept
        {
            // Signal and join the cleanup thread BEFORE acquiring the state mutex: the thread takes s_cache_state_mutex
            // in cleanup_expired_entries(force=true), so joining while holding it would deadlock.
            s_cleanup_thread_running.store(false, std::memory_order_release);
            s_cleanup_cv.notify_one();

            if (s_cleanup_thread.joinable())
            {
                if (is_loader_lock_held())
                {
                    // Under loader lock (DllMain / FreeLibrary): a join would deadlock because the cleanup thread
                    // cannot exit while the loader lock is held. Pin the module so its code stays valid, then detach.
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

            std::lock_guard<std::mutex> state_lock(s_cache_state_mutex);

            // Capture the shard count before zeroing it: the destroy loop needs the array length, and the array is
            // never resized between here and the reset() below. The s_cache_initialized store is seq_cst so it pairs
            // with the reader's seq_cst load in ActiveReaderGuard, forbidding the store-buffering race against the
            // reader-count load below.
            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);

            s_cache_initialized.store(false, std::memory_order_seq_cst);
            s_shard_count.store(0, std::memory_order_release);

            // Wait for in-flight readers to exit before destroying data. ActiveReaderGuard is RAII so readers always
            // decrement; escalate yield -> sleep to avoid burning CPU if a reader is preempted.
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

            for (std::size_t i = 0; i < shard_count; ++i)
            {
                std::unique_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx);
                s_cache_shards[i].entries.clear();
                s_cache_shards[i].lru_index.clear();
                s_cache_shards[i].sorted_ranges.clear();
            }

            s_cache_shards.reset();

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
            // Remove the vectored fault handler so it cannot dangle into freed code if the DMK module is unloaded after
            // teardown. The engine drains guarded reads still on the handler path before unregistering, so an in-flight
            // read cannot fault into a missing handler. Idempotent; a later guarded read re-installs it.
            detail::release_guarded_engine();
#endif

            try
            {
                Logger::get_instance().debug("MemoryCache: Shutdown complete.");
            }
            catch (...)
            {
            }
        }

        MemoryStats get_memory_stats() noexcept
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

            // Sum live entries and hard-max capacity across shards under the reader guard. A non-zero shard count
            // implies the array is allocated (init publishes the count after the array) and the reader guard keeps it
            // alive.
            std::size_t total_hard_max = 0;
            {
                ActiveReaderGuard reader_guard;
                const std::size_t active_shard_count = s_shard_count.load(std::memory_order_acquire);
                for (std::size_t i = 0; i < active_shard_count; ++i)
                {
                    std::shared_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx);
                    stats.total_entries += s_cache_shards[i].entries.size();
                    total_hard_max += s_cache_shards[i].max_capacity;
                }
            }
            stats.hard_max_per_shard = (stats.shard_count > 0) ? total_hard_max / stats.shard_count : 0;

            const std::uint64_t total_queries = stats.hits + stats.misses;
            stats.hit_rate_percent =
                (total_queries > 0) ? (static_cast<double>(stats.hits) / static_cast<double>(total_queries)) * 100.0
                                    : -1.0;
            return stats;
        }

        std::string get_cache_stats()
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

        void invalidate_range(Region range) noexcept
        {
            if (!range.base || range.size == 0)
                return;

            // Construct the reader guard BEFORE checking s_cache_initialized so shutdown_cache cannot free the shard
            // array between the check and the access.
            ActiveReaderGuard reader_guard;

            if (!s_cache_initialized.load(std::memory_order_seq_cst))
                return;

            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            if (shard_count == 0)
                return;

            invalidate_range_internal(range.base.raw(), range.size);

            // request_cleanup may run cleanup_expired_entries(force=false), which iterates shards without the state
            // mutex; the reader guard held here keeps a stripe non-zero so shutdown_cache cannot free shards during it.
            request_cleanup();
        }

        bool is_readable(Region range) noexcept
        {
            return check_memory_permission(range.base.raw(), range.size, check_read_permission);
        }

        bool is_writable(Region range) noexcept
        {
            return check_memory_permission(range.base.raw(), range.size, check_write_permission);
        }

        ReadableStatus is_readable_nonblocking(Region range) noexcept
        {
            const std::uintptr_t address = range.base.raw();
            const std::size_t size = range.size;
            if (address == 0 || size == 0)
                return ReadableStatus::NotReadable;

            ActiveReaderGuard reader_guard;

            if (!s_cache_initialized.load(std::memory_order_seq_cst))
            {
                // No cache to consult: fall back to a single blocking VirtualQuery and return a definite answer.
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
                    return ReadableStatus::NotReadable;
                if (mbi.State != MEM_COMMIT)
                    return ReadableStatus::NotReadable;
                if (!check_read_permission(mbi.Protect))
                    return ReadableStatus::NotReadable;
                const std::uintptr_t region_start = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::uintptr_t query_end = address + size;
                if (query_end < address)
                    return ReadableStatus::NotReadable;
                if (address >= region_start && query_end <= region_start + mbi.RegionSize)
                    return ReadableStatus::Readable;
                return ReadableStatus::NotReadable;
            }

            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            if (shard_count == 0)
                return ReadableStatus::Unknown;

            const std::size_t shard_idx = compute_shard_index(address, shard_count);
            const std::uint64_t now_ns = current_time_ns();
            const std::uint64_t expiry_ns = configured_expiry_ns();

            // Non-blocking: try_lock_shared so a latency-sensitive thread is never stalled on a contended shard.
            std::shared_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx, std::try_to_lock);
            if (!lock.owns_lock())
                return ReadableStatus::Unknown;

            CachedMemoryRegionInfo *cached_info =
                find_in_shard(s_cache_shards[shard_idx], address, size, now_ns, expiry_ns);
            if (cached_info)
            {
                s_stats.cache_hits.fetch_add(1, std::memory_order_relaxed);
                return check_read_permission(cached_info->protection) ? ReadableStatus::Readable
                                                                      : ReadableStatus::NotReadable;
            }

            // Cache miss under non-blocking semantics: return Unknown rather than issuing a VirtualQuery.
            return ReadableStatus::Unknown;
        }
    } // namespace memory
} // namespace DetourModKit
