/**
 * @file memory_cache.cpp
 * @brief The protection-region cache and the readability predicates built over it.
 *
 * Provides memory::is_readable / is_writable / is_readable_nonblocking and the cache lifecycle (init / clear / shutdown
 * / stats / invalidate). The cache uses sharded SRW locks for high-concurrency read-heavy access, a monotonic-counter
 * insertion/refresh FIFO map for O(log n) eviction, in-flight query coalescing to prevent VirtualQuery stampedes,
 * on-demand cleanup to keep the miss path clean, and epoch-based reader tracking so shutdown can drain readers before
 * freeing shard storage. Init and shutdown run under one Stopped/Starting/Running/Stopping lifecycle mutex so start can
 * never race stop across the cleanup-thread handle; a per-shard content generation makes invalidation exact even when a
 * shard cannot be locked and forbids an in-flight query leader from republishing a result cached across a clear. This
 * TU touches no Structured Exception Handling; on MinGW it drives the guarded-engine vectored-handler lifecycle through
 * the engine seam so a guarded read never has to fall back to a per-call VirtualQuery.
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
    // Deterministic lifecycle/cache-publication test seams, compiled ONLY when DMK_ENABLE_TEST_SEAMS is defined (set on
    // the library and test targets when DMK_BUILD_TESTS is ON). A shipping build (tests off) omits them entirely, so no
    // test-only symbol or branch is present at runtime. A test installs a hook before starting the participating
    // threads and clears it after they join; production leaves them null.
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
             * @brief Cached protection snapshot for one VirtualQuery region, with a FIFO key, content generation, and
             *        validity timestamp.
             * @details content_gen is the shard content generation captured when this entry was published. A hit is
             *          served only while it still equals the shard's current generation, so a clear or a contended
             *          invalidation that bumped the generation logically invalidates this entry in O(1) regardless of
             *          whether it was physically evicted.
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
             * @brief One cache shard: a base-keyed hit map, an insertion/refresh FIFO map for O(log n) eviction, a
             *        sorted range index, and a content generation.
             * @details An unordered_map keyed by region base address (mbi.BaseAddress) is the store. It gives a direct
             *          O(1) hit only for a query whose page base equals a region base -- a query landing in the FIRST
             *          page of a cached region -- because it is keyed by the region base, not by every page the region
             *          spans; a query deeper into a multi-page region is served by the sorted range index instead. A
             *          std::map keyed by a monotonic insert/refresh counter gives oldest-first eviction; a sorted
             *          deque (`sorted_ranges`) gives the O(log n) containment lookup for an address anywhere inside a
             *          larger cached region. content_gen is bumped (under the exclusive lock by clear_cache, or via an
             *          atomic fetch_add by invalidate_range when the shard cannot be locked) so an entry stamped with
             *          an older generation is logically invalid; the hit path compares an entry's stamp against it. The
             *          per-shard SRW lock and the in_flight stampede-coalescing flag are inline and the struct is
             *          cache-line aligned, so one shard's lock word never shares a line with another's. Inlining the
             *          mutex makes the shard non-movable, so shards use a fixed-size array that never relocates.
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
                // Sorted by base address for O(log n) containment lookup. All access is serialized by the shard SRW
                // lock (shared for lookups, exclusive for mutation), so iterators never outlive a critical section. The
                // deque prevents wholesale buffer relocation on growth, though interior insert/erase still invalidates
                // deque iterators per the standard. {base, base + size}.
                std::deque<std::pair<std::uintptr_t, std::uintptr_t>> sorted_ranges;
                SrwSharedMutex mtx;
                // The first thread to CAS this 0 -> 1 becomes the VirtualQuery leader for the shard; the rest coalesce
                // onto its result. Inline so it never shares a cache line with a neighbouring shard's flag.
                std::atomic<char> in_flight{0};
                // Content generation for exact invalidation. clear_cache bumps it under the exclusive lock; a contended
                // invalidate_range bumps it via fetch_add without the lock. Each entry stores the value current
                // when it was published, and a hit is served only while the stamp still matches, so a lost physical
                // eviction (a shard too contended to lock) or a clear racing an in-flight leader still invalidates in
                // O(1). Read on the hit path (acquire) but bumped only off it (clear / protection-change invalidate).
                std::atomic<std::uint64_t> content_gen{0};
                // Per-shard hit / miss tallies. The hot is_readable / is_writable path bumps one of these on every
                // query; keeping them in the shard (which the querying thread is already touching) rather than one
                // process-global pair of counters keeps the increment on a line no other shard's readers contend for,
                // so a busy multi-threaded workload does not ping-pong a single global counter line across every core.
                // get_memory_stats sums them across shards under the same reader guard it uses for the entry totals.
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

            /**
             * @enum LifecycleState
             * @brief The cache's single lifecycle authority: Stopped -> Starting -> Running -> Stopping -> Stopped.
             * @details Held as a seq_cst atomic so the reader hot path can load it while it pairs (Dekker) with the
             *          ActiveReaderGuard stripe increment for an exact shutdown drain. Running is published
             *          last by init_cache (after the shard array and generation) and cleared first by shutdown_cache
             *          (before the drain), so a reader observes Running only when the cache is fully built and never
             *          while it is being torn down. Normal transitions use s_lifecycle_mutex; loader-lock abandonment
             *          uses compare/exchange because it cannot wait for that mutex.
             */
            enum class LifecycleState : std::uint8_t
            {
                Stopped,
                Starting,
                Running,
                Stopping
            };
            std::atomic<LifecycleState> s_lifecycle_state{LifecycleState::Stopped};

            /// True while the cache is fully built and serving; the seq_cst reader-liveness gate (see LifecycleState).
            [[nodiscard]] inline bool cache_is_running() noexcept
            {
                return s_lifecycle_state.load(std::memory_order_seq_cst) == LifecycleState::Running;
            }

            /// Configured cache-entry expiry converted from milliseconds to nanoseconds.
            [[nodiscard]] inline std::uint64_t configured_expiry_ns() noexcept
            {
                return static_cast<std::uint64_t>(s_configured_expiry_ms.load(std::memory_order_acquire)) *
                       1'000'000ULL;
            }

            // Serializes shard-array mutation against cleanup. It nests inside s_lifecycle_mutex on init/shutdown.
            SrwSharedMutex s_cache_state_mutex;

            // Outermost lifecycle lock. Cleanup and readers never take it, and loader-lock teardown never waits on it.
            // Lock order: lifecycle -> state -> shard; the join lock nests only inside lifecycle.
            SrwSharedMutex s_lifecycle_mutex;

            // Advances on every admitted start. The cleanup thread captures its value at creation and exits once it no
            // longer matches, so a worker cannot outlive the session that spawned it and touch a later generation's
            // shards.
            std::atomic<std::uint64_t> s_lifecycle_generation{0};

            // Sticky count of unexpected joinable handles recovered before a new cleanup worker is published.
            std::atomic<std::uint64_t> s_lifecycle_violations{0};

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
             * @brief Returns this thread's reader stripe, derived from its Win32 thread id so concurrent readers spread
             *        across distinct cache lines instead of contending on one counter.
             * @details Golden-ratio bit-mixing of GetCurrentThreadId gives a stable per-thread stripe with no
             *          allocation and no lock, so it is safe on a readability check driven under loader lock (setup
             *          from DllMain), unlike a thread_local round-robin counter whose MinGW first touch lowers to an
             *          allocating __emutls_get_address. A thread id is stable for the thread's life, so the same stripe
             *          carries the ActiveReaderGuard increment and its paired decrement; two ids colliding onto one
             *          stripe only add minor contention, never a miscount of the drain.
             */
            [[nodiscard]] inline std::size_t reader_stripe_index() noexcept
            {
                const std::uint64_t mixed = static_cast<std::uint64_t>(GetCurrentThreadId()) * 0x9E3779B97F4A7C15ULL;
                return static_cast<std::size_t>(mixed >> 48) % READER_STRIPE_COUNT;
            }

            /**
             * @brief Sum of all reader stripes: the number of readers currently inside an ActiveReaderGuard.
             * @details shutdown_cache spins on this reaching zero (under seq_cst) after publishing the Stopping state,
             *          before freeing shard storage.
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
                    // seq_cst (not acq_rel) so this increment and the reader's subsequent seq_cst load of the lifecycle
                    // state share the single total order that forbids the store-buffering (Dekker) outcome with
                    // shutdown_cache: shutdown stores Stopping then sums every stripe, while a reader increments its
                    // stripe then loads the state. Under seq_cst a reader that observes Running was necessarily counted
                    // before shutdown reads that stripe. On x86-64 this is the same lock xadd as acq_rel, so the hot
                    // path pays nothing beyond landing on a per-thread line.
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
            // Counted reference on this module, taken before the cleanup thread is created while the module is fully
            // mapped, so its code cannot be unmapped by a caller's FreeLibrary while it runs. Released after a clean
            // join; leaked on the loader-lock detach path so the detached thread's code stays mapped.
            HMODULE s_cleanup_self_ref{nullptr};
            std::mutex s_cleanup_mutex;
            std::condition_variable s_cleanup_cv;
            std::atomic<bool> s_cleanup_requested{false};
            // Serializes the cleanup handle's join/detach/assignment. Loader-lock teardown only tries this lock.
            SrwSharedMutex s_cleanup_join_mutex;

            // On-demand cleanup fallback timer (used when the background thread is disabled).
            std::atomic<std::uint64_t> s_last_cleanup_time_ns{0};
            constexpr std::uint64_t CLEANUP_INTERVAL_NS = 1'000'000'000ULL;

            // Process-global cache statistics for the COLD counters. The hot hit / miss tallies live per-shard in
            // CacheShard (summed at snapshot time), so a hot query bumps only the shard line it is already touching
            // rather than one process-global counter line. The counters here are bumped only off the read hot path --
            // invalidations after a write, coalesced queries on a stampede, on-demand cleanups periodically -- so a
            // single line is fine. Each is alignas(64) so the three never false-share with one another. Same rationale
            // as CacheShard / ReaderStripe.
#if defined(_MSC_VER)
#pragma warning(push)
// C4324: each counter is intentionally padded to a full cache line by alignas(64) to prevent false sharing.
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
             * @param shard_content_gen The shard's current content generation; an entry stamped with an older value has
             *        been logically invalidated (by a clear or a contended invalidation) and is treated as a miss.
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
             * @note Must be called with the shard mutex held (exclusive).
             * @note Deliberately NOT noexcept: the std::deque insert allocates and can throw std::bad_alloc when it
             *       grows. Both callers run inside the throwing update_shard_with_region_impl, whose noexcept
             *       update_shard_with_region wrapper catches that allocation failure and fails soft -- so this must let
             *       bad_alloc propagate to that catch rather than terminate at its own noexcept frame.
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
             * @note Two-tier lookup, and both tiers are shard-LOCAL: the caller has already picked the shard via
             *       compute_shard_index(address), so this only ever sees entries seeded from a query that hashed to the
             *       same shard. The unordered_map probe by page-aligned base address hits only when that key equals a
             *       cached entry's STORE key (the region base, mbi.BaseAddress) -- i.e. when the query lands in the
             *       first page of a region already cached in THIS shard -- so it is a first-page fast path, not a
             *       general O(1) path. A query anywhere deeper into a multi-page region misses the direct probe and is
             *       served by the O(log n) binary search over this shard's sorted_ranges when the region is cached
             *       here; if it is not (the shard was never seeded for it), this returns nullptr and the caller
             *       re-queries via VirtualQuery, seeding the shard. There is no per-page index (one would be unbounded
             *       for a large module), and the per-shard entry count is small and bounded, so the containment search
             *       is effectively constant-time for interior addresses in practice.
             */
            CachedMemoryRegionInfo *find_in_shard(CacheShard &shard, std::uintptr_t address, std::size_t size,
                                                  std::uint64_t current_ns, std::uint64_t expiry_ns) noexcept
            {
                // One acquire load of the shard generation for both lookup tiers: an entry stamped with an older
                // generation was logically invalidated and is skipped, so a lost physical eviction or a clear that
                // raced a leader never serves a stale hit. Read under the shard lock the caller already holds.
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
             * @brief Evicts the oldest entry from the shard using an O(log n) insertion/refresh-order (FIFO) lookup.
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
             * @brief Updates or inserts a cache entry in a specific shard (the throwing body).
             * @param content_gen The shard content generation the leader captured BEFORE its VirtualQuery. The entry is
             *        stamped with it, so if a clear or contended invalidation advanced the shard generation between the
             *        query and this publish, the entry is born stale (stamp != current) and the next hit re-queries.
             * @note Must be called with the shard mutex held (exclusive). Inserts unordered_map / map / deque nodes, so
             *       it can throw bad_alloc; the noexcept @ref update_shard_with_region wrapper fails soft on that.
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
             * @brief Updates or inserts a cache entry in a specific shard, failing soft on allocation failure.
             * @note Must be called with the shard mutex held (exclusive).
             * @details The cache is a performance hint layered over the authoritative VirtualQuery the caller already
             *          holds, so a node-allocation failure must fail SOFT (skip the cache update) rather than escape
             *          this noexcept path and terminate the host under the exact memory pressure the query must
             *          survive.
             *          The shard containers give at least the basic guarantee on a single-element insert, and the
             *          shard's lookups tolerate a cross-container inconsistency in either direction -- a stray FIFO /
             *          sorted-range entry with no matching map entry, or a map entry whose FIFO / sorted-range mate was
             *          dropped when a throwing insert abandoned the update mid-way -- because a lookup reconciles
             *          against the map entry (a missing sorted-range only forces a re-query) and cleanup sweeps the
             *          survivor by expiry, so an abandoned partial update leaves the shard valid. Mirrors the fail-soft
             *          caching in detail::cached_module_image_region.
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
                // Always hold the state mutex to prevent racing with shutdown_cache, which frees the shard array.
                // try_lock for on-demand to avoid blocking the hot path; forced cleanup blocks to guarantee progress.
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
             * @brief Checks whether on-demand cleanup should run based on elapsed time.
             * @return true if cleanup was performed.
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
             * @brief Background cleanup thread body: removes expired entries periodically off the miss path.
             * @param generation The lifecycle generation this worker was created for. It exits once the live generation
             *        no longer matches, so a worker cannot outlive its session and touch a later generation's shards.
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
             * @brief Detaches the cleanup thread while retaining its counted module reference.
             * @return true when the handle is non-joinable on return.
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
             * @brief Tries to claim and detach the cleanup thread without blocking, for a teardown not authorized to.
             * @return true if this caller claimed the join mutex and observed the thread state; false if another
             *         shutdown is already joining or detaching the thread.
             */
            bool try_detach_cleanup_thread_unauthorized() noexcept
            {
                std::unique_lock join_lock(s_cleanup_join_mutex, std::try_to_lock);
                if (!join_lock.owns_lock())
                {
                    // Do not wait: this caller has no authorization to block. The owner is already handling the
                    // join/detach decision; after this thread returns from detach, the cleanup thread can finish its
                    // own loader notifications and let that owner complete.
                    return false;
                }

                return detach_cleanup_thread_retained();
            }

            /**
             * @brief Claims and joins the cleanup thread after the caller has authorized blocking teardown.
             * @return true if a joinable handle was joined (init uses this to count a reaped leftover as a lifecycle
             *         violation); false when there is nothing to reap or a failing join was contained by retention.
             * @note The joinable() check and the mutation both run under s_cleanup_join_mutex, so callers must not
             *       pre-check joinable() outside that mutex (it would race the abandon path's detach).
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
                // Joined off the loader lock: drop the reference taken at creation. Another reference on the module
                // still exists (the caller running this teardown), so this is never the terminal release.
                if (s_cleanup_self_ref != nullptr)
                {
                    release_module_ref(s_cleanup_self_ref);
                    s_cleanup_self_ref = nullptr;
                }
                return true;
            }

            /**
             * @brief Cache abandonment for a teardown with no authorization to block: the minimum rundown that never
             *        waits on the cache's own locks.
             * @details Used from shutdown_cache and the atexit handler whenever blocking teardown is unauthorized, most
             *          importantly under the loader lock, where waiting on s_lifecycle_mutex could deadlock a detaching
             *          thread against an initializer that holds it while creating the cleanup thread (thread creation
             *          takes the loader lock). It stops and try-detaches the cleanup thread, drops the guarded engine,
             *          and atomically unpublishes a Starting or Running generation. It does not drain readers or free
             *          shards.
             * @note The MinGW guarded-engine release below is the one step here that can wait; see its own comment.
             */
            void abandon_cache_unauthorized() noexcept
            {
#if !defined(_MSC_VER) && defined(_WIN64)
                // Remove the vectored fault handler before the module can unload: leaving it registered against
                // soon-to-be-freed code is worse than the leak below. This is not wait-free -- release_guarded_engine
                // takes the VEH mutex and drains in-flight guarded accesses -- but a handler dangling into unmapped
                // code faults the host, so the wait is preferred to skipping the unregister.
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
             * @brief Invalidates cache entries overlapping [address, address + size) across all shards.
             * @details Each shard is invalidated exactly once with a single try-lock: if the lock is acquired the
             *          overlapping entries are physically evicted (freeing the slots); if the shard is contended the
             *          physical sweep is skipped and the shard's content generation is bumped instead, which logically
             *          invalidates every entry it holds in O(1). A subsequent hit re-queries because find_in_shard
             *          rejects an entry whose stamped generation no longer matches. Correctness therefore no longer
             *          depends on winning the lock, so no retry loop is needed and no stale entry survives to expiry.
             *          The fallback over-invalidates the contended shard (entries outside the requested range re-query
             *          too), an accepted trade for O(1) exactness on the rare, off-hot-path protection-change caller.
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
                        // A query leader may be in-flight for this shard: it set in_flight before its VirtualQuery but
                        // has not yet taken the shard lock this thread holds, so it will publish an entry stamped with
                        // the pre-invalidate generation. Bump the generation so that entry is born stale, closing
                        // the invalidate-vs-leader analogue of the clear-vs-leader race. With no leader in-flight the
                        // physical eviction above suffices and the generation is left untouched (no over-scan).
                        if (shard.in_flight.load(std::memory_order_acquire) != 0)
                        {
                            shard.content_gen.fetch_add(1, std::memory_order_acq_rel);
                        }
                    }
                    else
                    {
                        // Contended: skip the physical sweep but bump the generation so every entry in the shard is
                        // logically invalidated; a leader that captured the old generation republishes born stale too.
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
                // Publish the shard count LAST here in the build. init_cache stores Running only after this returns, so
                // a reader that observes Running is guaranteed (release/acquire) to also see the shard array and the
                // config fields stored above -- never a torn half-initialized snapshot where shard_count is set but
                // expiry / max-entries are still zero.
                s_shard_count.store(shard_count, std::memory_order_release);

                log().debug("MemoryCache: Initialized with {} shards ({} entries/shard, {}ms expiry, {} max).",
                            shard_count, entries_per_shard, expiry_ms, hard_max_per_shard);

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
                    // Capture the shard generation BEFORE the query so a clear or invalidation that intervenes before
                    // the publish below stamps this entry stale (its stamp will not match the advanced generation).
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
             * @brief Range-spanning permission walk via VirtualQuery, with no cache involvement.
             * @param address Start of the range; callers screen a zero address before calling.
             * @param size Byte length of the range; callers screen a zero size before calling.
             * @param check_permission Predicate over one region's protection flags.
             * @return true only when every region the range touches is committed and satisfies @p check_permission,
             *         with no unmapped gap between them.
             * @details A single VirtualQuery describes only the region that contains its argument, so a range that
             *          legitimately crosses a protection boundary -- for example a large allocation whose interior page
             *          was re-protected, which splits one reservation into several MEMORY_BASIC_INFORMATION regions --
             *          would fail closed against the first region's end even when every byte it spans is readable.
             *          Adjacent regions that share protection, state, and type are already coalesced by VirtualQuery
             *          into one region, so this loop iterates more than once only when the range genuinely crosses
             *          differing protections; the common single-region case runs exactly one query, the same cost as a
             *          direct single-region permission check. Fail-closed throughout: an address-space wrap, an
             *          unmapped or non-committed sub-region, a disallowed protection, or a VirtualQuery that fails or
             *          does not advance the cursor all return false. Forward progress is guaranteed because
             *          VirtualQuery returns a region that contains `cursor`, whose end is strictly greater than
             *          `cursor`, so each iteration jumps the cursor to the next region base and the loop is bounded by
             *          the region count of the range.
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
                    // VirtualQuery's region always contains `cursor`, so region_end > cursor. The guard is a defensive
                    // backstop: a pathological zero-size or wrapped region that did not advance the cursor fails closed
                    // rather than spinning.
                    if (region_end <= cursor)
                        return false;
                    cursor = region_end;
                }
                return true;
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

                // Construct the reader guard before loading the lifecycle state so shutdown_cache cannot free the shard
                // array between the check and the access.
                ActiveReaderGuard reader_guard;

                const bool cache_running = cache_is_running();
                const std::size_t shard_count = cache_running ? s_shard_count.load(std::memory_order_acquire) : 0;

                // Fall back to a direct VirtualQuery when the cache is unavailable: not Running (never started, still
                // Starting, or Stopping/Stopped) so shard_count reads 0, or a concurrent shutdown that already zeroed
                // the count under the reader guard.
                if (shard_count == 0)
                {
                    // No cache to consult: walk the range directly. The walk spans protection boundaries, so a range
                    // that crosses a re-protected interior page is answered correctly instead of failing closed on the
                    // first region's end.
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
                        // Require MEM_COMMIT on the hit path exactly as the miss and uncached-walk paths do below: a
                        // cached region whose stored state is not committed (a reserved or freed range) is not
                        // readable/writable regardless of its protection mask, matching the "readable and committed"
                        // contract this predicate documents. VirtualQuery reports Protect == 0 for a non-committed
                        // region, which check_permission already rejects, so this is defense-in-depth that keeps the
                        // hit path symmetric with every other path rather than a currently-reachable wrong answer.
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

                // The query landed inside the region just cached by query_and_update_cache (VirtualQuery always returns
                // the region that contains `address`, so the range starts at or after its base). The common case is
                // that the whole range fits within this one region -- answer directly and keep the region cached for
                // the next probe. When the range extends past this region it crosses into an adjacent protection
                // region, which a single cache entry can never cover, so walk the remainder uncached: fail closed if
                // any sub-region is uncommitted, disallowed, or separated by an unmapped gap.
                if (query_end_addr <= region_end_addr)
                    return true;

                return range_permission_uncached(region_end_addr, query_end_addr - region_end_addr, check_permission);
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            /**
             * @brief Holds the selected shard's shared lock while invoking a deterministic test callback.
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
            // Init is an off-loader-lock setup call. Refuse whenever the lifecycle gate does not authorize blocking:
            // creating the cleanup thread under the loader lock deadlocks, and blocking on the lifecycle mutex could
            // deadlock a concurrent shutdown joining that thread. Readers fall back to uncached VirtualQuery until an
            // authorized init succeeds.
            if (!DetourModKit::detail::blocking_teardown_permitted())
            {
                return false;
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *const hook = DetourModKit::detail::g_memory_cache_before_lifecycle_lock_test_hook)
                hook();
#endif

            // The lifecycle mutex serializes the whole start against shutdown_cache so the cleanup-thread handle is
            // never raced or assigned into while a stop is in flight.
            std::lock_guard lifecycle_lock(s_lifecycle_mutex);

            if (s_lifecycle_state.load(std::memory_order_seq_cst) == LifecycleState::Running)
                return true;

            // Recover any unexpected joinable handle before assigning the next worker. The lifecycle gate above has
            // already authorized blocking for the complete setup.
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
                // A loader-lock abandon leaves the previous session's shard array allocated with its readers undrained.
                // A reader preempted across that abandon can still hold a shard lock and a pointer into the old array,
                // so drain before perform_cache_initialization frees it via make_unique. Starting is already published,
                // so no new reader enters the cache. After a clean shutdown the array is null and this is skipped.
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
            // MinGW has no frame-based SEH; install the process-wide vectored fault handler the guarded reads use so
            // a guarded read never has to fall back to a per-call VirtualQuery. Best-effort and independent of cache
            // success.
            detail::ensure_guarded_engine_installed();
#endif

            s_cleanup_thread_running.store(true, std::memory_order_release);
            // Hold a counted reference before creating the cleanup thread; after std::thread returns the routine
            // may already be executing library code. A creation failure releases this reference below.
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
                    // Publish the handle under the join mutex so this never races the loader-lock detach path, which
                    // touches the same handle under this mutex (via a try-lock) without the lifecycle mutex. The reap
                    // above already ran the handle non-joinable, so this move-assign never targets a joinable handle.
                    // A loader-lock detach concurrent with this construction try-locks the join mutex, fails, and
                    // returns without touching the handle, so holding it across thread creation cannot deadlock.
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

            // Last-resort safety net if the consumer forgets shutdown_cache. Without authorization to block it
            // abandons rather than joins; abandon_cache_unauthorized never blocks on the lifecycle mutex.
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

            // Publish only if unauthorized abandonment did not cancel this Starting generation. Compare/exchange
            // keeps abandonment from being overwritten by a later unconditional Running store.
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

            // Blocking exclusive lock per shard to guarantee all entries are cleared. The cleanup thread uses try_lock,
            // so it skips shards we hold without deadlocking.
            for (std::size_t i = 0; i < shard_count; ++i)
            {
                std::unique_lock<SrwSharedMutex> shard_lock(s_cache_shards[i].mtx);
                s_cache_shards[i].entries.clear();
                s_cache_shards[i].fifo_index.clear();
                s_cache_shards[i].sorted_ranges.clear();
                s_cache_shards[i].hits.store(0, std::memory_order_relaxed);
                s_cache_shards[i].misses.store(0, std::memory_order_relaxed);
                // Advance the content generation so an in-flight query leader that captured the previous generation
                // before its VirtualQuery cannot republish a pre-clear result: its entry is stamped stale, re-queried.
                s_cache_shards[i].content_gen.fetch_add(1, std::memory_order_release);
            }

            s_stats.invalidations.store(0, std::memory_order_relaxed);
            s_stats.coalesced_queries.store(0, std::memory_order_relaxed);
            s_stats.on_demand_cleanups.store(0, std::memory_order_relaxed);

            s_last_cleanup_time_ns.store(current_time_ns(), std::memory_order_relaxed);

            // Diagnostic-only tail; clear_cache is noexcept, so a sink or format failure drops the line.
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
            // Unauthorized teardown only unpublishes and retains reachable state; it never waits for lifecycle/readers.
            // Decided once and carried through the whole teardown: the loader context is process-global, so re-asking
            // partway would let a concurrent publication split one teardown across both policies.
            const bool may_block = DetourModKit::detail::blocking_teardown_permitted();
            if (!may_block)
            {
                abandon_cache_unauthorized();
                return;
            }

            // Off the loader lock: serialize the whole stop against init_cache so a start can never race this teardown
            // across the cleanup-thread handle.
            std::lock_guard lifecycle_lock(s_lifecycle_mutex);

            const LifecycleState state = s_lifecycle_state.load(std::memory_order_seq_cst);
            if (state != LifecycleState::Running && !(state == LifecycleState::Stopped && s_cache_shards))
                return;

            // Stopped with a live shard array is a prior loader-lock abandonment. Off loader lock it is safe to finish
            // that retained teardown. Stopping also keeps a concurrent loader-lock callback from republishing Stopped
            // as a new start waits on the lifecycle lock.
            s_lifecycle_state.store(LifecycleState::Stopping, std::memory_order_seq_cst);

#if defined(DMK_ENABLE_TEST_SEAMS)
            // Force an initializer to attempt this lifecycle lock before teardown continues.
            if (auto *const hook = DetourModKit::detail::g_memory_cache_shutdown_window_test_hook)
                hook();
#endif

            // Signal and join the cleanup thread before acquiring the state mutex: the thread takes s_cache_state_mutex
            // in cleanup_expired_entries(force=true), so joining while holding it would deadlock. The lifecycle mutex
            // still serializes the whole sequence against init_cache.
            s_cleanup_thread_running.store(false, std::memory_order_release);
            s_cleanup_cv.notify_one();
            (void)join_cleanup_thread();

            std::lock_guard state_lock(s_cache_state_mutex);

            // Capture the shard count before zeroing it: the destroy loop needs the length, and the array is never
            // resized between here and the reset() below.
            const std::size_t shard_count = s_shard_count.load(std::memory_order_acquire);
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
                s_cache_shards[i].fifo_index.clear();
                s_cache_shards[i].sorted_ranges.clear();
            }

            s_cache_shards.reset();

            // The per-shard hit / miss tallies were freed with the shard array; only the global cold counters need
            // an explicit reset here. s_lifecycle_violations is intentionally NOT reset -- it is a sticky diagnostic
            // that must survive a restart.
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
            // The COLD counters live in the static CacheStats, independent of the shard-array lifetime, so a relaxed
            // load outside the reader guard is safe. The hot hits / misses tallies live per-shard and are summed under
            // the reader guard below (alongside the entry totals), so while the cache is down -- no shard array to sum
            // -- they read 0, the zero a fresh snapshot reports.
            stats.invalidations = s_stats.invalidations.load(std::memory_order_relaxed);
            stats.coalesced_queries = s_stats.coalesced_queries.load(std::memory_order_relaxed);
            stats.on_demand_cleanups = s_stats.on_demand_cleanups.load(std::memory_order_relaxed);
            // Sticky lifecycle-violation tally: independent of the shard-array lifetime and never reset, so a relaxed
            // load outside the reader guard reports its running total even while the cache is down.
            stats.lifecycle_violations = s_lifecycle_violations.load(std::memory_order_relaxed);

            // Capture the configuration fields and the live-entry totals as one coherent snapshot behind the reader
            // guard and the same seq_cst lifecycle gate the permission readers use (see check_memory_permission). The
            // gate is what makes the shard-array access below safe: ActiveReaderGuard's seq_cst increment, paired with
            // an observed Running state, forbids the store-buffering race with shutdown_cache (which stores Stopping
            // seq_cst, then drains readers before freeing s_cache_shards). Loading s_shard_count with a plain acquire
            // alone does not establish that pairing, so a concurrent shutdown could free the array between a stale
            // non-zero count and the loop (a use-after-free) and could tear these config fields against its
            // field-by-field zeroing.
            // Leaving every field at its zero default while the cache is down keeps the snapshot internally consistent.
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

            // Construct the reader guard before checking the lifecycle state so shutdown_cache cannot free the shard
            // array between the check and the access.
            ActiveReaderGuard reader_guard;

            if (!cache_is_running())
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

            if (!cache_is_running())
            {
                // No cache to consult: fall back to a blocking range walk and return a definite answer. The walk spans
                // protection boundaries, so a range that crosses a re-protected page is not reported as a false
                // NotReadable. This is the no-cache path only; the non-blocking (cache-present) path below never issues
                // a VirtualQuery and returns Unknown on a miss.
                return range_permission_uncached(address, size, check_read_permission) ? ReadableStatus::Readable
                                                                                       : ReadableStatus::NotReadable;
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
                s_cache_shards[shard_idx].hits.fetch_add(1, std::memory_order_relaxed);
                // Require MEM_COMMIT alongside the read permission, symmetric with the blocking hit path and the miss
                // paths: a non-committed cached region is never readable even if its protection bits looked permissive.
                return (cached_info->state == MEM_COMMIT && check_read_permission(cached_info->protection))
                           ? ReadableStatus::Readable
                           : ReadableStatus::NotReadable;
            }

            // Cache miss under non-blocking semantics: return Unknown rather than issuing a VirtualQuery.
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
