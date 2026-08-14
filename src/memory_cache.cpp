/**
 * @file memory_cache.cpp
 * @brief This TU implements the protection-region cache and its readability predicates.
 *
 * The sharded cache uses SRW locks. It provides FIFO eviction and exact invalidation without SEH.
 * Shutdown drains reader epochs before shard release. This TU controls the MinGW guarded-engine lifecycle.
 */

#include "DetourModKit/memory.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"
#include "internal/lifecycle_context.hpp"
#include "internal/srw_shared_mutex.hpp"
#include "platform.hpp"
#include "internal/memory_guarded.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
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

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    void (*g_memory_cache_before_lifecycle_lock_test_hook)() = nullptr;
    void (*g_memory_cache_before_running_publish_test_hook)() = nullptr;
    void (*g_memory_cache_shutdown_window_test_hook)() = nullptr;
    void (*g_memory_cache_leader_publish_window_test_hook)() = nullptr;
} // namespace DetourModKit::detail
#endif

namespace DetourModKit
{
    namespace memory
    {
        using DetourModKit::detail::acquire_module_ref;
        using DetourModKit::detail::release_module_ref;
        using DetourModKit::detail::SrwSharedMutex;

        namespace
        {
            // CachePermissions groups page-protection flags for cache permission checks. A struct preserves internal
            // linkage through the outer anonymous namespace without a named namespace.
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
             * @brief Stores a cached protection snapshot for one VirtualQuery region.
             * @details A hit requires content_gen to equal the shard's current generation. A clear or contended
             *          invalidation therefore invalidates this entry in O(1), regardless of physical eviction.
             */
            struct CachedMemoryRegionInfo
            {
                std::uintptr_t base_address;
                std::size_t region_size;
                DWORD protection;
                DWORD state;
                std::uint64_t timestamp_ns;
                std::uint64_t fifo_key;
                std::uint64_t content_gen;
                bool valid;

                CachedMemoryRegionInfo()
                    : base_address(0), region_size(0), protection(0), state(0), timestamp_ns(0), fifo_key(0),
                      content_gen(0), valid(false)
                {
                }
            };

            /**
             * @struct CacheShard
             * @brief Stores one shard with a hit map, FIFO map, sorted range index, and content generation.
             * @details The unordered_map is keyed by region base, so its O(1) hit covers only a query in a region's
             *          FIRST page. Deeper queries use the sorted range index. The std::map keyed by a
             *          monotonic counter gives oldest-first eviction. alignas(64) aligns each shard object to a 64-byte
             *          boundary. The inline mutex makes the shard non-movable, so shards use a fixed-size array that
             *          never relocates.
             */
#if defined(_MSC_VER)
#pragma warning(push)
// C4324: CacheShard is intentionally padded to a full cache line by alignas(64) for cache-line hygiene.
#pragma warning(disable : 4324)
#endif
            struct alignas(64) CacheShard
            {
                std::unordered_map<std::uintptr_t, CachedMemoryRegionInfo> entries;
                std::map<std::uint64_t, std::uintptr_t> fifo_index;
                // The shard SRW lock serializes this base-sorted O(log n) containment index. The deque prevents full
                // buffer relocation during growth. Each entry stores [base, base + size).
                std::deque<std::pair<std::uintptr_t, std::uintptr_t>> sorted_ranges;
                SrwSharedMutex mtx;
                // The first thread to CAS this 0 -> 1 becomes the VirtualQuery leader. The rest coalesce onto its
                // result.
                std::atomic<char> in_flight{0};
                // Content generation provides exact invalidation. clear_cache advances it under the exclusive lock.
                // A contended invalidate_range advances it through fetch_add. A hit requires a current entry stamp.
                std::atomic<std::uint64_t> content_gen{0};
                // The query thread already touches this per-shard hit and miss counter line. A busy workload therefore
                // does not move one global counter line across every core.
                std::atomic<std::uint64_t> hits{0};
                std::atomic<std::uint64_t> misses{0};
                std::uint64_t entry_counter{0};
                std::size_t capacity;
                std::size_t max_capacity;

                CacheShard() : capacity(0), max_capacity(0) { entries.reserve(64); }
            };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

            static_assert(std::is_same_v<decltype(CacheShard::sorted_ranges),
                                         std::deque<std::pair<std::uintptr_t, std::uintptr_t>>>,
                          "CacheShard::sorted_ranges is pinned to std::deque so mutation never relocates the buffer.");

            inline std::uint64_t current_time_ns() noexcept
            {
                return std::chrono::duration_cast<std::chrono::nanoseconds>(
                           std::chrono::steady_clock::now().time_since_epoch())
                    .count();
            }

            /**
             * @brief Computes the shard index for an address.
             * @note Uses a golden-ratio hash to spread adjacent addresses across shards.
             */
            constexpr inline std::size_t compute_shard_index(std::uintptr_t address, std::size_t shard_count) noexcept
            {
                return (static_cast<std::size_t>((address * 0x9E3779B97F4A7C15ULL) >> 48)) % shard_count;
            }

            // The fixed-size shard array never resizes because CacheShard is non-movable. It is null before init and
            // after shutdown.
            std::unique_ptr<CacheShard[]> s_cache_shards;
            std::atomic<std::size_t> s_shard_count{0};
            std::atomic<std::size_t> s_max_entries_per_shard{0};
            std::atomic<unsigned int> s_configured_expiry_ms{0};

            /**
             * @enum LifecycleState
             * @brief Defines the cache lifecycle authority: Stopped -> Starting -> Running -> Stopping -> Stopped.
             * @details The seq_cst order pairs the reader hot path with the ActiveReaderGuard stripe increment.
             *          Running is published last by init_cache and cleared first by shutdown_cache. Normal
             *          transitions use s_lifecycle_mutex. Loader-lock abandonment uses compare/exchange because it
             *          cannot wait for that mutex.
             */
            enum class LifecycleState : std::uint8_t
            {
                Stopped,
                Starting,
                Running,
                Stopping
            };
            std::atomic<LifecycleState> s_lifecycle_state{LifecycleState::Stopped};

            /// Reports whether the cache is active under the seq_cst reader-liveness gate in LifecycleState.
            [[nodiscard]] inline bool cache_is_running() noexcept
            {
                return s_lifecycle_state.load(std::memory_order_seq_cst) == LifecycleState::Running;
            }

            /// Returns the configured cache-entry expiry in nanoseconds.
            [[nodiscard]] inline std::uint64_t configured_expiry_ns() noexcept
            {
                return static_cast<std::uint64_t>(s_configured_expiry_ms.load(std::memory_order_acquire)) *
                       1'000'000ULL;
            }

            // Serializes shard-array mutation against cleanup. It nests inside s_lifecycle_mutex on init/shutdown.
            SrwSharedMutex s_cache_state_mutex;

            // This is the outermost lifecycle lock. Cleanup and readers never take it, and loader-lock teardown never
            // waits on it. Lock order is lifecycle -> state -> shard. The join lock nests only inside lifecycle.
            SrwSharedMutex s_lifecycle_mutex;

            // Advances on every admitted start. The cleanup thread exits once its captured value no longer matches,
            // so a worker cannot outlive its session and touch a later generation's shards.
            std::atomic<std::uint64_t> s_lifecycle_generation{0};

            // This sticky counter records unexpected joinable handles recovered before a new cleanup worker appears.
            std::atomic<std::uint64_t> s_lifecycle_violations{0};

            // Reader epochs let shutdown wait for zero before data release. Cache-line-padded counters stripe readers,
            // so concurrent reads do not serialize on one shared line. See active_reader_total() and the
            // ActiveReaderGuard Dekker note.
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
             * @brief Returns this thread's reader stripe, derived from its Win32 thread id.
             * @details A hash of GetCurrentThreadId allocates nothing and takes no lock, so loader lock permits it.
             *          In contrast, MinGW lowers first access to a thread_local counter into __emutls_get_address,
             *          which can allocate. The id is stable for the thread's life, so the same stripe carries the
             *          increment and its paired decrement. A collision adds contention but never a drain miscount.
             */
            [[nodiscard]] inline std::size_t reader_stripe_index() noexcept
            {
                const std::uint64_t mixed = static_cast<std::uint64_t>(GetCurrentThreadId()) * 0x9E3779B97F4A7C15ULL;
                return static_cast<std::size_t>(mixed >> 48) % READER_STRIPE_COUNT;
            }

            /**
             * @brief Returns the sum of all reader stripes inside an ActiveReaderGuard.
             * @details After shutdown_cache publishes Stopping, it waits for this sum to reach zero under seq_cst.
             *          It then frees shard storage.
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
             * @brief Tracks one reader with paired stripe updates across every exit path.
             */
            class ActiveReaderGuard
            {
            public:
                ActiveReaderGuard() noexcept : m_stripe(reader_stripe_index())
                {
                    // This increment and the reader lifecycle load use seq_cst. Their total order forbids the Dekker
                    // StoreLoad outcome with shutdown_cache. A reader that observes Running enters the count before
                    // shutdown reads that stripe. On x86-64, this is the same lock xadd as acq_rel.
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

            // Use std::thread, not jthread. The jthread auto-join destructor runs after s_cleanup_cv and
            // s_cleanup_mutex are destroyed in reverse declaration order. Manual join in shutdown_cache avoids this.
            std::atomic<bool> s_cleanup_thread_running{false};
            std::thread s_cleanup_thread;
            // s_cleanup_self_ref holds a counted module reference acquired before thread creation. A clean join
            // releases it. The loader-lock detach path leaks it so the detached thread's code stays mapped.
            HMODULE s_cleanup_self_ref{nullptr};
            std::mutex s_cleanup_mutex;
            std::condition_variable s_cleanup_cv;
            std::atomic<bool> s_cleanup_requested{false};
            // Serializes the cleanup handle's join/detach/assignment. Loader-lock teardown only tries this lock.
            SrwSharedMutex s_cleanup_join_mutex;

            // This timer controls on-demand cleanup when the background thread is disabled.
            std::atomic<std::uint64_t> s_last_cleanup_time_ns{0};
            constexpr std::uint64_t CLEANUP_INTERVAL_NS = 1'000'000'000ULL;

            // These instance-wide COLD counters advance only off the read hot path. The hot hit and miss tallies live
            // per shard. Each counter is alignas(64), so the three never share a cache line.
#if defined(_MSC_VER)
#pragma warning(push)
// C4324: each counter is intentionally padded to a full cache line by alignas(64) to prevent line overlap.
#pragma warning(disable : 4324)
#endif
            struct CacheStats
            {
                alignas(64) std::atomic<std::uint64_t> invalidations{0};
                alignas(64) std::atomic<std::uint64_t> coalesced_queries{0};
                alignas(64) std::atomic<std::uint64_t> on_demand_cleanups{0};
            };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
            CacheStats s_stats;

            /**
             * @brief Checks if a cache entry is valid, current for the shard generation, and covers [address, address +
             *        size).
             * @param shard_content_gen The shard's current content generation. A clear or contended invalidation
             *                           advances it. An older stamp marks the entry invalid, so lookup returns a miss.
             */
            constexpr inline bool is_entry_valid_and_covers(const CachedMemoryRegionInfo &entry, std::uintptr_t address,
                                                            std::size_t size, std::uint64_t current_ns,
                                                            std::uint64_t expiry_ns,
                                                            std::uint64_t shard_content_gen) noexcept
            {
                if (!entry.valid)
                    return false;

                if (entry.content_gen != shard_content_gen)
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
             * @note Must be called with the shard mutex held (exclusive). This helper is deliberately not noexcept
             *       because bad_alloc must reach update_shard_with_region's fail-soft catch.
             */
            void insert_sorted_range(CacheShard &shard, std::uintptr_t base_addr, std::size_t region_size)
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
             * @brief Finds and validates a cache entry in a shard that covers [address, address + size).
             * @note Must be called with the shard mutex held (shared or exclusive).
             * @note The shard-local direct probe is a first-page fast path because the map key is the region base.
             *       Deeper queries use the O(log n) search over sorted_ranges. A miss returns nullptr. The caller then
             *       queries through VirtualQuery and inserts the result. There is deliberately no
             *       per-page index. The per-shard entry count is small and bounded.
             */
            CachedMemoryRegionInfo *find_in_shard(CacheShard &shard, std::uintptr_t address, std::size_t size,
                                                  std::uint64_t current_ns, std::uint64_t expiry_ns) noexcept
            {
                // One acquire load reads the shard generation for both tiers. An entry with an older stamp is skipped.
                // Thus a lost physical eviction or a clear that races a leader cannot serve a stale hit.
                const std::uint64_t shard_content_gen = shard.content_gen.load(std::memory_order_acquire);

                const std::uintptr_t base_addr = address & ~static_cast<std::uintptr_t>(0xFFF);
                auto it = shard.entries.find(base_addr);
                if (it != shard.entries.end())
                {
                    CachedMemoryRegionInfo &entry = it->second;
                    if (is_entry_valid_and_covers(entry, address, size, current_ns, expiry_ns, shard_content_gen))
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
                            if (is_entry_valid_and_covers(entry, address, size, current_ns, expiry_ns,
                                                          shard_content_gen))
                            {
                                return &entry;
                            }
                        }
                    }
                }

                return nullptr;
            }

            /**
             * @brief Evicts the oldest shard entry through an O(log n) FIFO lookup.
             * @note Must be called with the shard mutex held (exclusive).
             * @return true if an entry was evicted, false if the shard is empty.
             */
            bool evict_oldest_entry(CacheShard &shard) noexcept
            {
                if (shard.fifo_index.empty())
                    return false;

                const auto fifo_it = shard.fifo_index.begin();
                const std::uintptr_t oldest_base = fifo_it->second;

                shard.fifo_index.erase(fifo_it);

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
                while (shard.entries.size() > shard.max_capacity && !shard.fifo_index.empty())
                {
                    evict_oldest_entry(shard);
                }
            }

            /**
             * @brief Updates or inserts a cache entry in a specific shard and can throw.
             * @param content_gen Generation captured before the leader's VirtualQuery. An entry published across a
             *        clear or invalidation starts stale, so the next hit queries again.
             * @note Must be called with the shard mutex held (exclusive). Can throw bad_alloc. The noexcept
             *       @ref update_shard_with_region wrapper fails soft on that.
             */
            void update_shard_with_region_impl(CacheShard &shard, const MEMORY_BASIC_INFORMATION &mbi,
                                               std::uint64_t current_ns, std::uint64_t content_gen)
            {
                const std::uintptr_t base_addr = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);

                auto it = shard.entries.find(base_addr);
                if (it != shard.entries.end())
                {
                    CachedMemoryRegionInfo &old_entry = it->second;
                    const auto fifo_it = shard.fifo_index.find(old_entry.fifo_key);
                    if (fifo_it != shard.fifo_index.end() && fifo_it->second == base_addr)
                    {
                        shard.fifo_index.erase(fifo_it);
                    }

                    if (old_entry.region_size != mbi.RegionSize)
                    {
                        remove_sorted_range(shard, base_addr);
                        insert_sorted_range(shard, base_addr, mbi.RegionSize);
                    }

                    const std::uint64_t new_fifo_key = shard.entry_counter++;
                    old_entry.base_address = base_addr;
                    old_entry.region_size = mbi.RegionSize;
                    old_entry.protection = mbi.Protect;
                    old_entry.state = mbi.State;
                    old_entry.timestamp_ns = current_ns;
                    old_entry.fifo_key = new_fifo_key;
                    old_entry.content_gen = content_gen;
                    old_entry.valid = true;

                    shard.fifo_index.emplace(new_fifo_key, base_addr);
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

                    const std::uint64_t new_fifo_key = shard.entry_counter++;

                    CachedMemoryRegionInfo new_entry;
                    new_entry.base_address = base_addr;
                    new_entry.region_size = mbi.RegionSize;
                    new_entry.protection = mbi.Protect;
                    new_entry.state = mbi.State;
                    new_entry.timestamp_ns = current_ns;
                    new_entry.fifo_key = new_fifo_key;
                    new_entry.content_gen = content_gen;
                    new_entry.valid = true;

                    shard.entries.insert_or_assign(base_addr, new_entry);
                    shard.fifo_index.emplace(new_fifo_key, base_addr);
                    insert_sorted_range(shard, base_addr, mbi.RegionSize);
                }
            }

            /**
             * @brief Updates or inserts a cache entry in a specific shard with soft allocation failure.
             * @note Must be called with the shard mutex held (exclusive).
             * @details The cache is a performance hint over the authoritative VirtualQuery result. Allocation failure
             *          fails soft instead of host termination under memory pressure. Lookups tolerate cross-container
             *          inconsistency in either direction. They reconcile against the map entry, and cleanup sweeps
             *          entries by expiry. An abandoned partial update leaves the shard valid.
             */
            void update_shard_with_region(CacheShard &shard, const MEMORY_BASIC_INFORMATION &mbi,
                                          std::uint64_t current_ns, std::uint64_t content_gen) noexcept
            {
                try
                {
                    update_shard_with_region_impl(shard, mbi, current_ns, content_gen);
                }
                catch (const std::bad_alloc &)
                {
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
                        const auto fifo_it = shard.fifo_index.find(entry.fifo_key);
                        if (fifo_it != shard.fifo_index.end() && fifo_it->second == it->first)
                        {
                            shard.fifo_index.erase(fifo_it);
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
                // The state mutex stays locked while this function iterates the shards. It excludes shard-array release
                // by shutdown_cache. On-demand cleanup uses try_lock, so the hot path never blocks. Forced cleanup
                // waits for the lock.
                std::unique_lock lock(s_cache_state_mutex, std::defer_lock);
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
             * @brief Checks whether elapsed time permits on-demand cleanup.
             * @return true if this caller claims the cleanup trigger. Contended shards can remain unprocessed.
             */
            bool try_trigger_on_demand_cleanup() noexcept
            {
                if (!cache_is_running())
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
             * @brief Runs the background cleanup thread for one lifecycle generation.
             * @param generation Lifecycle generation captured at thread creation.
             * @note Exits after the live generation no longer matches @p generation.
             */
            void cleanup_thread_func(std::uint64_t generation) noexcept
            {
                while (s_cleanup_thread_running.load(std::memory_order_acquire) &&
                       s_lifecycle_generation.load(std::memory_order_acquire) == generation)
                {
                    {
                        std::unique_lock<std::mutex> lock(s_cleanup_mutex);
                        s_cleanup_cv.wait_for(lock, std::chrono::seconds(1),
                                              [&]()
                                              {
                                                  return s_cleanup_requested.load(std::memory_order_acquire) ||
                                                         !s_cleanup_thread_running.load(std::memory_order_acquire) ||
                                                         s_lifecycle_generation.load(std::memory_order_acquire) !=
                                                             generation;
                                              });
                    }

                    if (!s_cleanup_thread_running.load(std::memory_order_acquire) ||
                        s_lifecycle_generation.load(std::memory_order_acquire) != generation)
                        break;

                    cleanup_expired_entries(true);
                    s_cleanup_requested.store(false, std::memory_order_relaxed);
                }
            }

            /**
             * @brief Requests cleanup through the worker or the on-demand path.
             * @details Signals the worker when it is active. Otherwise, attempts on-demand cleanup.
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
             * @brief Detaches the cleanup thread and retains its counted module reference.
             * @return true if no joinable thread exists or detachment succeeds. Returns false if std::thread::detach()
             *         throws.
             */
            bool detach_cleanup_thread_retained() noexcept
            {
                if (!s_cleanup_thread.joinable())
                {
                    return true;
                }

                try
                {
                    // The retained module reference keeps the detached worker's code mapped.
                    s_cleanup_thread.detach();
                    DetourModKit::diagnostics::record_intentional_leak(
                        DetourModKit::diagnostics::LeakSubsystem::MemoryCache);
                    return true;
                }
                catch (...)
                {
                    s_lifecycle_violations.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
            }

            /**
             * @brief Tries to claim and detach the cleanup thread without a wait for an unauthorized teardown.
             * @return true if this caller claims the mutex and finds no joinable thread or detaches it. Returns false
             *         on contention or if std::thread::detach() throws.
             */
            bool try_detach_cleanup_thread_unauthorized() noexcept
            {
                std::unique_lock join_lock(s_cleanup_join_mutex, std::try_to_lock);
                if (!join_lock.owns_lock())
                {
                    // Do not wait because the owner already controls the join or detach decision.
                    return false;
                }

                return detach_cleanup_thread_retained();
            }

            /**
             * @brief Claims and joins the cleanup thread after the caller authorizes a teardown wait.
             * @return true if a joinable handle was joined (init uses this to count a reaped leftover as a lifecycle
             *         violation). Returns false when nothing needs a reap or retention contains a failed join.
             * @note The joinable() check and mutation both run under s_cleanup_join_mutex. Callers must not check
             *       joinable() first outside that mutex because this races the abandon-path detach.
             */
            bool join_cleanup_thread() noexcept
            {
                std::lock_guard join_lock(s_cleanup_join_mutex);
                if (!s_cleanup_thread.joinable())
                {
                    return false;
                }

                try
                {
                    s_cleanup_thread.join();
                }
                catch (...)
                {
                    s_lifecycle_violations.fetch_add(1, std::memory_order_relaxed);
                    (void)detach_cleanup_thread_retained();
                    return false;
                }
                // After a join outside the loader lock, drop the reference from creation. The caller retains another
                // module reference, so this is never the terminal release.
                if (s_cleanup_self_ref != nullptr)
                {
                    release_module_ref(s_cleanup_self_ref);
                    s_cleanup_self_ref = nullptr;
                }
                return true;
            }

            /**
             * @brief Abandons the cache without a wait when teardown lacks block authority.
             * @details A wait on s_lifecycle_mutex under the loader lock can deadlock against an initializer that
             *          creates the cleanup thread because thread creation takes the loader lock. This path stops and
             *          attempts to detach the cleanup thread, drops the guarded engine, and unpublishes a Starting or
             *          Running generation. It drains no readers and frees no shards.
             */
            void abandon_cache_unauthorized() noexcept
            {
#if !defined(_MSC_VER) && defined(_WIN64)
                // Remove the vectored fault handler before module unload. This operation takes the VEH mutex and drains
                // in-flight guarded accesses, so it is not wait-free. A handler in unmapped code faults the host.
                // Therefore, the wait is safer than omission of handler removal.
                detail::release_guarded_engine();
#endif
                s_cleanup_thread_running.store(false, std::memory_order_release);
                s_cleanup_cv.notify_one();
                // If another thread owns the handle lock, it completes the join/detach decision after loader unlock.
                (void)try_detach_cleanup_thread_unauthorized();

                LifecycleState state = s_lifecycle_state.load(std::memory_order_seq_cst);
                while (state == LifecycleState::Starting || state == LifecycleState::Running)
                {
                    if (s_lifecycle_state.compare_exchange_weak(state, LifecycleState::Stopped,
                                                                std::memory_order_seq_cst, std::memory_order_seq_cst))
                    {
                        break;
                    }
                }
            }

            /**
             * @brief Evicts every entry in a shard whose region overlaps [address, end_address).
             * @note Must be called with the shard mutex held (exclusive).
             * @note Scans the whole shard: one region can be cached in several shards under the same base key (the
             *       shard is chosen from the query address). The shard remains bounded by max_capacity, and this scan
             *       never runs on a read hot path.
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
                    // A VirtualQuery region cannot extend past the address space, but a corrupt cached size can.
                    // Treat a wrapped end as the top of the address space so a poisoned entry is still evicted.
                    const std::uintptr_t clamped_entry_end =
                        (entry_end_address < entry.base_address) ? UINTPTR_MAX : entry_end_address;
                    const bool overlaps =
                        entry.valid && address < clamped_entry_end && end_address > entry.base_address;
                    if (overlaps)
                    {
                        const auto fifo_it = shard.fifo_index.find(entry.fifo_key);
                        if (fifo_it != shard.fifo_index.end() && fifo_it->second == it->first)
                        {
                            shard.fifo_index.erase(fifo_it);
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
             * @brief Invalidates cache entries that overlap [address, address + size) across all shards.
             * @details Uses one try-lock per shard. On success, entries that overlap are physically evicted. Under
             *          contention, the content generation advances instead. This invalidates every entry in O(1), so
             *          correctness never depends on lock success. The fallback over-invalidates the contended
             *          shard, an accepted trade on the rare, off-hot-path protection-change caller.
             */
            void invalidate_range_internal(std::uintptr_t address, std::size_t size) noexcept
            {
                if (!s_cache_shards || size == 0)
                    return;

                const std::uintptr_t end_address = (address + size < address) ? UINTPTR_MAX : address + size;
                const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);

                for (std::size_t shard_idx = 0; shard_idx < shard_count; ++shard_idx)
                {
                    CacheShard &shard = s_cache_shards[shard_idx];
                    std::unique_lock<SrwSharedMutex> lock(shard.mtx, std::try_to_lock);
                    if (lock.owns_lock())
                    {
                        evict_overlapping_entries_in_shard(shard, address, end_address);
                        // An earlier leader keeps in_flight set until publication under this lock. A generation advance
                        // makes its entry stale. A later leader queries after this eviction and the caller's completed
                        // protection change, so physical eviction suffices without a shard-wide generation change.
                        if (shard.in_flight.load(std::memory_order_acquire) != 0)
                        {
                            shard.content_gen.fetch_add(1, std::memory_order_acq_rel);
                        }
                    }
                    else
                    {
                        // Contention advances the generation, so every entry becomes invalid. A leader that captured
                        // the old generation republishes a stale entry.
                        shard.content_gen.fetch_add(1, std::memory_order_acq_rel);
                        s_stats.invalidations.fetch_add(1, std::memory_order_relaxed);
                    }
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
                    log().error("MemoryCache: Failed to allocate memory for cache shards.");
                    s_cache_shards.reset();
                    return false;
                }

                s_max_entries_per_shard.store(entries_per_shard, std::memory_order_release);
                s_configured_expiry_ms.store(expiry_ms, std::memory_order_release);
                s_last_cleanup_time_ns.store(current_time_ns(), std::memory_order_release);
                // Publish the shard count LAST so a reader that observes Running also sees the shard array and
                // config fields, never a torn half-initialized snapshot.
                s_shard_count.store(shard_count, std::memory_order_release);

                log().debug("MemoryCache: Initialized with {} shards ({} entries/shard, {}ms expiry, {} max).",
                            shard_count, entries_per_shard, expiry_ms, hard_max_per_shard);

                return true;
            }

            /**
             * @brief Performs VirtualQuery and updates the cache with stampede coalescence.
             * @return true if VirtualQuery (or a coalesced follower read) succeeded.
             */
            bool query_and_update_cache(std::size_t shard_idx, LPCVOID address,
                                        MEMORY_BASIC_INFORMATION &mbi_out) noexcept
            {
                CacheShard &shard = s_cache_shards[shard_idx];

                char expected = 0;
                if (shard.in_flight.compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
                {
                    // Capture the generation before the query. A clear or invalidation before publication stamps this
                    // entry stale.
                    const std::uint64_t gen_at_query = shard.content_gen.load(std::memory_order_acquire);
                    const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                    const std::uint64_t now_ns = current_time_ns();

#if defined(DMK_ENABLE_TEST_SEAMS)
                    // Inject a clear/protection change into the post-query, pre-publish window.
                    if (auto *const hook = DetourModKit::detail::g_memory_cache_leader_publish_window_test_hook)
                        hook();
#endif

                    if (result)
                    {
                        std::unique_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                        update_shard_with_region(shard, mbi_out, now_ns, gen_at_query);
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
                        const std::uint64_t gen_at_query = shard.content_gen.load(std::memory_order_acquire);
                        const bool result = VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                        if (result)
                        {
                            std::unique_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                            const std::uint64_t now_ns = current_time_ns();
                            update_shard_with_region(shard, mbi_out, now_ns, gen_at_query);
                        }
                        shard.in_flight.store(0, std::memory_order_release);
                        return result;
                    }

                    return VirtualQuery(address, &mbi_out, sizeof(mbi_out)) != 0;
                }
            }

            /**
             * @brief Walks a range through VirtualQuery without cache involvement.
             * @param address Start of the range. Callers screen a zero address before the call.
             * @param size Byte length of the range. Callers screen a zero size before the call.
             * @param check_permission Predicate over one region's protection flags.
             * @return true only when every region the range touches is committed and satisfies @p check_permission,
             *         with no unmapped gap between them.
             * @details The loop repeats only when the range crosses different protections. VirtualQuery already
             *          coalesces neighbors with the same protection, so the common single-region case uses one query.
             *          Every failure closes the result. A wrap, invalid sub-region, disallowed protection, failed
             *          query, or no cursor advance returns false. The returned region contains `cursor`, which
             *          guarantees progress.
             */
            bool range_permission_uncached(std::uintptr_t address, std::size_t size,
                                           bool (*check_permission)(DWORD) noexcept) noexcept
            {
                const std::uintptr_t query_end = address + size;
                if (query_end < address)
                    return false;

                std::uintptr_t cursor = address;
                while (cursor < query_end)
                {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0)
                        return false;
                    if (mbi.State != MEM_COMMIT)
                        return false;
                    if (!check_permission(mbi.Protect))
                        return false;

                    const std::uintptr_t region_end =
                        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                    // A zero-size or wrapped region fails closed instead of a spin.
                    if (region_end <= cursor)
                        return false;
                    cursor = region_end;
                }
                return true;
            }

            /**
             * @brief Checks permissions for is_readable and is_writable.
             * @param address Start address of the query (0 fails closed).
             * @param size Number of bytes to check (0 fails closed).
             * @param check_permission Predicate that validates the protection flags.
             */
            bool check_memory_permission(std::uintptr_t address, std::size_t size,
                                         bool (*check_permission)(DWORD) noexcept) noexcept
            {
                if (address == 0 || size == 0)
                    return false;

                // Guard before the lifecycle load so shutdown cannot free the shard array between check and access.
                ActiveReaderGuard reader_guard;

                const bool cache_running = cache_is_running();
                const std::size_t shard_count = cache_running ? s_shard_count.load(std::memory_order_acquire) : 0;

                // If no cache is available, walk the range directly. This occurs outside Running or after a concurrent
                // shutdown clears the count. The walk spans protection boundaries, so a re-protected interior
                // page is answered correctly.
                if (shard_count == 0)
                {
                    return range_permission_uncached(address, size, check_permission);
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
                        s_cache_shards[shard_idx].hits.fetch_add(1, std::memory_order_relaxed);
                        // Require MEM_COMMIT exactly as the miss and uncached paths do. Non-committed regions report
                        // Protect == 0, so check_permission already rejects them. The explicit state check keeps every
                        // path symmetric.
                        return cached_info->state == MEM_COMMIT && check_permission(cached_info->protection);
                    }
                }

                s_cache_shards[shard_idx].misses.fetch_add(1, std::memory_order_relaxed);

                MEMORY_BASIC_INFORMATION mbi{};
                if (!query_and_update_cache(shard_idx, reinterpret_cast<LPCVOID>(address), mbi))
                    return false;

                if (mbi.State != MEM_COMMIT)
                    return false;

                if (!check_permission(mbi.Protect))
                    return false;

                const std::uintptr_t region_end_addr =
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                const std::uintptr_t query_end_addr = address + size;

                if (query_end_addr < address)
                    return false;
                if (region_end_addr <= address)
                    return false;

                // The common case fits within the cached region, so answer directly. A range past it crosses into an
                // adjacent protection region that one cache entry cannot cover. Walk the remainder without the cache.
                // Fail closed on any uncommitted, disallowed, or gapped sub-region.
                if (query_end_addr <= region_end_addr)
                    return true;

                return range_permission_uncached(region_end_addr, query_end_addr - region_end_addr, check_permission);
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            /**
             * @brief Holds the selected shard's shared lock and invokes a deterministic test callback.
             */
            void hold_shard_shared_lock_for_test(Address address, void (*callback)() noexcept) noexcept
            {
                if (callback == nullptr)
                    return;

                ActiveReaderGuard reader_guard;
                if (!cache_is_running())
                    return;

                const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
                if (shard_count == 0)
                    return;

                const std::size_t shard_idx = compute_shard_index(address.raw(), shard_count);
                std::shared_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx);
                callback();
            }
#endif

        } // namespace

        bool init_cache(std::size_t cache_size, unsigned int expiry_ms, std::size_t shard_count)
        {
            // Refuse whenever the lifecycle gate does not authorize a wait. Cleanup-thread creation under loader lock
            // deadlocks. Readers use uncached VirtualQuery until an authorized init succeeds.
            if (!DetourModKit::detail::blocking_teardown_permitted())
            {
                return false;
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *const hook = DetourModKit::detail::g_memory_cache_before_lifecycle_lock_test_hook)
                hook();
#endif

            // Serialize the whole start against shutdown_cache across the cleanup-thread handle.
            std::lock_guard lifecycle_lock(s_lifecycle_mutex);

            if (s_lifecycle_state.load(std::memory_order_seq_cst) == LifecycleState::Running)
                return true;

            // Recover any unexpected joinable handle before assignment of the next worker.
            const bool reaped_leftover = join_cleanup_thread();
            if (reaped_leftover)
            {
                s_lifecycle_violations.fetch_add(1, std::memory_order_relaxed);
            }
            {
                std::lock_guard join_lock(s_cleanup_join_mutex);
                if (s_cleanup_thread.joinable())
                {
                    s_lifecycle_violations.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
            }

            s_lifecycle_state.store(LifecycleState::Starting, std::memory_order_seq_cst);

            {
                std::lock_guard state_lock(s_cache_state_mutex);
                // A loader-lock abandon leaves the previous session shard array allocated with readers undrained. A
                // preempted reader can still hold a pointer into it, so drain before the array is freed. Starting
                // is already published, so no new reader enters.
                if (s_cache_shards)
                {
                    s_shard_count.store(0, std::memory_order_release);
                    constexpr int yield_spins = 4096;
                    int spins = 0;
                    while (active_reader_total() > 0)
                    {
                        if (spins < yield_spins)
                            std::this_thread::yield();
                        else
                            std::this_thread::sleep_for(std::chrono::microseconds(100));
                        ++spins;
                    }
                }

                if (!perform_cache_initialization(cache_size, expiry_ms, shard_count))
                {
                    s_lifecycle_state.store(LifecycleState::Stopped, std::memory_order_seq_cst);
                    return false;
                }
            }

            // Advance the generation this session's cleanup thread binds to, after the shards are built.
            const std::uint64_t generation = s_lifecycle_generation.fetch_add(1, std::memory_order_acq_rel) + 1;

#if !defined(_MSC_VER) && defined(_WIN64)
            // MinGW has no frame-based SEH. A successful vectored-handler install avoids the per-call VirtualQuery
            // fallback. Installation remains best-effort and independent of cache success.
            detail::ensure_guarded_engine_installed();
#endif

            s_cleanup_thread_running.store(true, std::memory_order_release);
            // Hold a counted reference before cleanup thread creation. A creation failure releases it below.
            s_cleanup_self_ref = acquire_module_ref();
            if (s_cleanup_self_ref == nullptr)
            {
                s_cleanup_thread_running.store(false, std::memory_order_release);
                log().debug("MemoryCache: Module reference unavailable, using on-demand cleanup instead of background "
                            "cleanup.");
            }
            else
            {
                try
                {
                    // Publish the handle under the join mutex so this never races the loader-lock detach path. A
                    // concurrent detach tries the mutex, fails, and returns without access to the handle. This lock can
                    // remain held across thread creation without a deadlock.
                    std::lock_guard join_lock(s_cleanup_join_mutex);
                    assert(!s_cleanup_thread.joinable());
                    s_cleanup_thread = std::thread(cleanup_thread_func, generation);
                }
                catch (...)
                {
                    release_module_ref(s_cleanup_self_ref);
                    s_cleanup_self_ref = nullptr;
                    s_cleanup_thread_running.store(false, std::memory_order_release);
                    log().debug("MemoryCache: Background cleanup thread unavailable, using on-demand cleanup.");
                }
            }

            // The atexit handler is a last-resort safety net when the consumer omits shutdown_cache.
            static bool atexit_registered = false;
            if (!atexit_registered)
            {
                std::atexit(
                    []()
                    {
                        if (s_lifecycle_state.load(std::memory_order_seq_cst) != LifecycleState::Running)
                            return;
                        shutdown_cache();
                    });
                atexit_registered = true;
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *const hook = DetourModKit::detail::g_memory_cache_before_running_publish_test_hook)
                hook();
#endif

            // Publish only if unauthorized abandonment did not cancel this Starting generation.
            LifecycleState expected_state = LifecycleState::Starting;
            if (!s_lifecycle_state.compare_exchange_strong(expected_state, LifecycleState::Running,
                                                           std::memory_order_seq_cst, std::memory_order_seq_cst))
            {
                s_cleanup_thread_running.store(false, std::memory_order_release);
                s_cleanup_cv.notify_one();
                (void)join_cleanup_thread();

                std::lock_guard<SrwSharedMutex> state_lock(s_cache_state_mutex);
                s_shard_count.store(0, std::memory_order_release);
                while (active_reader_total() > 0)
                    std::this_thread::yield();
                s_cache_shards.reset();
                s_configured_expiry_ms.store(0, std::memory_order_relaxed);
                s_max_entries_per_shard.store(0, std::memory_order_relaxed);
#if !defined(_MSC_VER) && defined(_WIN64)
                detail::release_guarded_engine();
#endif
                return false;
            }
            return true;
        }

        void clear_cache() noexcept
        {
            std::lock_guard state_lock(s_cache_state_mutex);

            if (!cache_is_running())
                return;

            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            if (shard_count == 0)
                return;

            // Acquire an exclusive lock for each shard and wait if needed. The cleanup thread uses try_lock, so it
            // skips held shards.
            for (std::size_t i = 0; i < shard_count; ++i)
            {
                std::unique_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx);
                s_cache_shards[i].entries.clear();
                s_cache_shards[i].fifo_index.clear();
                s_cache_shards[i].sorted_ranges.clear();
                s_cache_shards[i].hits.store(0, std::memory_order_relaxed);
                s_cache_shards[i].misses.store(0, std::memory_order_relaxed);
                // Advance the generation so an in-flight leader cannot republish a pre-clear result.
                s_cache_shards[i].content_gen.fetch_add(1, std::memory_order_release);
            }

            s_stats.invalidations.store(0, std::memory_order_relaxed);
            s_stats.coalesced_queries.store(0, std::memory_order_relaxed);
            s_stats.on_demand_cleanups.store(0, std::memory_order_relaxed);

            s_last_cleanup_time_ns.store(current_time_ns(), std::memory_order_relaxed);

            // This diagnostic tail is optional. clear_cache is noexcept, so a sink or format failure drops the line.
            try
            {
                log().debug("MemoryCache: All entries cleared.");
            }
            catch (...)
            {
            }
        }

        void shutdown_cache() noexcept
        {
            // Decide the block policy once for the whole teardown. A second query lets a concurrent publication split
            // one teardown across both policies.
            const bool may_block = DetourModKit::detail::blocking_teardown_permitted();
            if (!may_block)
            {
                abandon_cache_unauthorized();
                return;
            }

            // Serialize the whole stop against init_cache across the cleanup-thread handle.
            std::lock_guard lifecycle_lock(s_lifecycle_mutex);

            const LifecycleState state = s_lifecycle_state.load(std::memory_order_seq_cst);
            if (state != LifecycleState::Running && !(state == LifecycleState::Stopped && s_cache_shards))
                return;

            // Stopped with a live shard array is a prior loader-lock abandonment, safe to finish here off the
            // loader lock. Stopping also prevents a concurrent loader-lock callback from another Stopped publication.
            s_lifecycle_state.store(LifecycleState::Stopping, std::memory_order_seq_cst);

#if defined(DMK_ENABLE_TEST_SEAMS)
            // Force an initializer to attempt this lifecycle lock before teardown continues.
            if (auto *const hook = DetourModKit::detail::g_memory_cache_shutdown_window_test_hook)
                hook();
#endif

            // Join the cleanup thread before acquisition of the state mutex. The thread takes s_cache_state_mutex in
            // forced cleanup. A join under that mutex can deadlock.
            s_cleanup_thread_running.store(false, std::memory_order_release);
            s_cleanup_cv.notify_one();
            (void)join_cleanup_thread();

            std::lock_guard state_lock(s_cache_state_mutex);

            // Capture the shard count before its reset to zero because the destroy loop needs the length.
            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            s_shard_count.store(0, std::memory_order_release);

            // Wait for active readers to exit before data destruction. Escalate yield -> sleep.
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
                s_cache_shards[i].fifo_index.clear();
                s_cache_shards[i].sorted_ranges.clear();
            }

            s_cache_shards.reset();

            // Only the global cold counters need an explicit reset. s_lifecycle_violations is intentionally NOT
            // reset: a sticky diagnostic that must survive a restart.
            s_stats.invalidations.store(0, std::memory_order_relaxed);
            s_stats.coalesced_queries.store(0, std::memory_order_relaxed);
            s_stats.on_demand_cleanups.store(0, std::memory_order_relaxed);
            s_last_cleanup_time_ns.store(0, std::memory_order_relaxed);
            s_configured_expiry_ms.store(0, std::memory_order_relaxed);
            s_max_entries_per_shard.store(0, std::memory_order_relaxed);
            s_cleanup_requested.store(false, std::memory_order_relaxed);

#if !defined(_MSC_VER) && defined(_WIN64)
            // Remove the vectored fault handler so it cannot dangle into freed code if the DMK module is unloaded after
            // teardown. The engine drains guarded reads on the handler path before handler removal. An in-flight read
            // cannot fault into a missing handler. The operation is idempotent. A later guarded read reinstalls it.
            detail::release_guarded_engine();
#endif

            // Publish Stopped last, under the lifecycle mutex, so the next init_cache admits a fresh start.
            s_lifecycle_state.store(LifecycleState::Stopped, std::memory_order_seq_cst);

            try
            {
                log().debug("MemoryCache: Shutdown complete.");
            }
            catch (...)
            {
            }
        }

        MemoryStats get_memory_stats() noexcept
        {
            MemoryStats stats{};
            // The COLD counters are independent of the shard-array lifetime, so a relaxed load outside the reader
            // guard is safe. The hot per-shard tallies are summed under the guard below.
            stats.invalidations = s_stats.invalidations.load(std::memory_order_relaxed);
            stats.coalesced_queries = s_stats.coalesced_queries.load(std::memory_order_relaxed);
            stats.on_demand_cleanups = s_stats.on_demand_cleanups.load(std::memory_order_relaxed);
            stats.lifecycle_violations = s_lifecycle_violations.load(std::memory_order_relaxed);

            // Capture the config fields and entry totals behind the reader guard and the same seq_cst lifecycle
            // gate that permission readers use. A plain acquire of s_shard_count alone lets a concurrent
            // shutdown free the array between a stale non-zero count and the loop. Every field stays at its zero
            // default while the cache is down.
            {
                ActiveReaderGuard reader_guard;
                if (cache_is_running())
                {
                    const std::size_t active_shard_count = s_shard_count.load(std::memory_order_acquire);
                    if (active_shard_count > 0)
                    {
                        stats.shard_count = active_shard_count;
                        stats.max_entries_per_shard = s_max_entries_per_shard.load(std::memory_order_acquire);
                        stats.expiry_ms = s_configured_expiry_ms.load(std::memory_order_acquire);

                        std::size_t total_hard_max = 0;
                        for (std::size_t i = 0; i < active_shard_count; ++i)
                        {
                            std::shared_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx);
                            stats.total_entries += s_cache_shards[i].entries.size();
                            total_hard_max += s_cache_shards[i].max_capacity;
                            stats.hits += s_cache_shards[i].hits.load(std::memory_order_relaxed);
                            stats.misses += s_cache_shards[i].misses.load(std::memory_order_relaxed);
                        }
                        stats.hard_max_per_shard = total_hard_max / active_shard_count;
                    }
                }
            }

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
                << ", TotalEntries: " << s.total_entries << ", LifecycleViolations: " << s.lifecycle_violations;

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

            // Guard before the lifecycle check so shutdown cannot free the shard array between check and access.
            ActiveReaderGuard reader_guard;

            if (!cache_is_running())
                return;

            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            if (shard_count == 0)
                return;

            invalidate_range_internal(range.base.raw(), range.size);

            // The on-demand cleanup fallback holds s_cache_state_mutex while it iterates the shards.
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

            if (!cache_is_running())
            {
                // No cache is available. Use a range walk that can wait and return a definite answer. The
                // cache-present path below never issues a VirtualQuery and returns Unknown on a miss.
                return range_permission_uncached(address, size, check_read_permission) ? ReadableStatus::Readable
                                                                                       : ReadableStatus::NotReadable;
            }

            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
            if (shard_count == 0)
                return ReadableStatus::Unknown;

            const std::size_t shard_idx = compute_shard_index(address, shard_count);
            const std::uint64_t now_ns = current_time_ns();
            const std::uint64_t expiry_ns = configured_expiry_ns();

            // The shared try-lock prevents a wait by a latency-sensitive thread on a contended shard.
            std::shared_lock<SrwSharedMutex> lock(s_cache_shards[shard_idx].mtx, std::try_to_lock);
            if (!lock.owns_lock())
                return ReadableStatus::Unknown;

            CachedMemoryRegionInfo *cached_info =
                find_in_shard(s_cache_shards[shard_idx], address, size, now_ns, expiry_ns);
            if (cached_info)
            {
                s_cache_shards[shard_idx].hits.fetch_add(1, std::memory_order_relaxed);
                // Require MEM_COMMIT alongside the read permission, symmetric with the blocking hit path.
                return (cached_info->state == MEM_COMMIT && check_read_permission(cached_info->protection))
                           ? ReadableStatus::Readable
                           : ReadableStatus::NotReadable;
            }

            // Under non-blocking semantics, return Unknown on a cache miss instead of a VirtualQuery call.
            return ReadableStatus::Unknown;
        }
    } // namespace memory
} // namespace DetourModKit

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    void memory_cache_abandon_for_test() noexcept
    {
        memory::abandon_cache_unauthorized();
    }

    void memory_cache_hold_shared_shard_lock_for_test(Address address, void (*callback)() noexcept) noexcept
    {
        memory::hold_shard_shared_lock_for_test(address, callback);
    }
} // namespace DetourModKit::detail
#endif
