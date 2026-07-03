/**
 * @file bench_memory.cpp
 * @brief Standalone microbenchmark for the Memory validation and access paths.
 *
 * Quantifies the per-call cost of each way to read game memory from a hot path so callers can choose between a
 * validation predicate and a direct fault-guarded read with data rather than intuition. Measured on the shipping
 * toolchain (MSVC, where the guarded reads use real __try/__except):
 *
 *   - is_readable / is_writable  WARM HIT   (cache on, entry fresh)
 *   - is_readable / is_writable  COLD MISS  (cache off -> direct VirtualQuery)
 *   - raw VirtualQuery                       (the syscall a cache miss pays)
 *   - unchecked::read<uint64_t>              (raw inline read, no guard, no syscall)
 *   - read<uint64_t> (guarded)               (fault-guarded read)
 *   - walk / walk + read<uint64_t>           (one fault guard for a whole chain)
 *   - direct volatile load / store           (floor)
 *   - write_bytes (8 bytes)                  (VirtualProtect x2 + Flush + invalidate)
 *
 * Scenario studies (each letter is annotated with the [N] phase marker the program prints; the basic per-call cost
 * tables are the unlettered phases
 * [1]-[3], so the lettered scenario studies start at (D)):
 *   (D) [Phase 4] VirtualQuery cost vs VAD-tree size (reserve N regions, then
 *       re-time) to show whether process address-space size inflates the miss cost.
 *   (E) [Phase 5] is_readable latency p50/p99/max under 1/2/4 threads forcing
 *       cache misses on a shared shard set. Tail latency, not average, is what a frame loop feels as a hitch (the
 *       shared shard set models the render thread racing the input and entity detours).
 *   (F) [Phases 6-7] Probe model (the hot-path validation regression this
 *       benchmark guards): a hook that runs many probes per frame, each doing K dependent reads across a few DISTINCT
 *       (cache-missing) objects. Reports per-probe p50/p99/max for GATED (is_readable before each read) vs DIRECT (raw
 *       volatile reads, no predicate or guard), then a per-frame budget vs probes-per-frame. The gate cost scales with
 *       the read count and the miss rate, which a single average-per-call number does not capture.
 *   (G) [Phase 8] Pointer-chain primitives: a GATED per-link walk (is_readable
 *       before each dereference) vs walk / walk + read<uint64_t> (one fault guard for the whole walk).
 *
 * Build with -DDMK_BUILD_BENCHMARKS=ON. Executable: DetourModKit_bench_memory
 * Output: human-readable tables plus a TSV block on stdout.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <thread>
#include <vector>

namespace
{
    using Clock = std::chrono::steady_clock;
    namespace Mem = DetourModKit::memory;
    using DetourModKit::Address;
    using DetourModKit::Region;

    // The readability predicates take a Region; the bench works in (pointer, size). Wrap once here so the call sites
    // below stay readable.
    // ANTI-PATTERN: these wrappers resurrect the removed (pointer, size) call shape so the bench bodies did not have to
    // change. Treat them as a temporary scaffold: rewrite the call sites to build a Region directly and remove these.
    // (The same scaffold exists in test_memory.cpp.)
    inline bool is_readable(const void *p, std::size_t n) noexcept
    {
        return Mem::is_readable(Region{Address{p}, n});
    }
    inline bool is_writable(const void *p, std::size_t n) noexcept
    {
        return Mem::is_writable(Region{Address{p}, n});
    }

    // Anti-dead-code sink: every measured op feeds this so the optimizer cannot observe an unused result and delete the
    // work being timed.
    std::atomic<std::uint64_t> s_sink{0};

    inline void sink(std::uint64_t v) noexcept
    {
        s_sink.fetch_add(v, std::memory_order_relaxed);
    }

    // Amortized timing: run `op` `iters` times per sample, `samples` samples, return the median ns-per-call. Matches
    // the bench_scanner.cpp idiom but reports nanoseconds because these ops are sub-microsecond.
    template <typename Op> double median_ns_per_call(std::size_t iters, std::size_t samples, Op &&op)
    {
        std::vector<double> per_call;
        per_call.reserve(samples);
        for (std::size_t s = 0; s < samples; ++s)
        {
            const auto start = Clock::now();
            for (std::size_t i = 0; i < iters; ++i)
            {
                op();
            }
            const auto end = Clock::now();
            const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            per_call.push_back(static_cast<double>(ns) / static_cast<double>(iters));
        }
        std::sort(per_call.begin(), per_call.end());
        const std::size_t n = per_call.size();
        return (n % 2 == 0) ? (per_call[n / 2 - 1] + per_call[n / 2]) / 2.0 : per_call[n / 2];
    }

    struct Row
    {
        const char *name;
        double ns;
    };
    std::vector<Row> g_rows;

    void report(const char *name, double ns)
    {
        g_rows.push_back({name, ns});
        const double per_sec = ns > 0.0 ? 1.0e9 / ns : 0.0;
        std::printf("  %-26s %10.2f ns/call   %14.0f calls/s\n", name, ns, per_sec);
    }

    // Allocate a single committed, readable+writable page to stand in for a "stable" game pose buffer. Seed it with a
    // non-zero qword so the value-returning reads (unchecked::read) load a real value rather than zero.
    std::uint64_t *make_stable_page()
    {
        void *p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!p)
        {
            std::fprintf(stderr, "[bench] VirtualAlloc failed: %lu\n", GetLastError());
            std::exit(1);
        }
        auto *q = static_cast<std::uint64_t *>(p);
        *q = 0x1122334455667788ull;
        return q;
    }

    // Reserve (not commit) `count` regions to inflate the process VAD tree. Reserve-only keeps RAM cost near zero while
    // still creating VAD nodes that
    // VirtualQuery's tree lookup must traverse.
    void grow_vad(std::size_t count)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            // 64 KiB allocation granularity => each call is its own VAD node.
            (void)VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_NOACCESS);
        }
    }
} // namespace

// (E) Contention study: p50/p99 latency of is_readable under N threads forcing cache misses. Each thread round-robins
// over a large set of distinct committed addresses so most lookups miss (256-entry cache vs thousands of addresses) and
// take the per-shard EXCLUSIVE lock on the rebuild path -> cross-thread serialization. This is the jitter source behind
// "framerate instability".
namespace
{
    struct LatencyResult
    {
        double p50_ns;
        double p99_ns;
        double max_ns;
    };

    LatencyResult percentiles(std::vector<double> &lat)
    {
        std::sort(lat.begin(), lat.end());
        const std::size_t n = lat.size();
        if (n == 0)
            return {0, 0, 0};
        auto pct = [&](double p)
        {
            const std::size_t idx = std::min(n - 1, static_cast<std::size_t>(p * static_cast<double>(n)));
            return lat[idx];
        };
        return {pct(0.50), pct(0.99), lat[n - 1]};
    }

    // Build a pool of committed RW pages whose addresses we round-robin to defeat the cache and force the miss path.
    std::vector<void *> make_churn_pool(std::size_t pages)
    {
        std::vector<void *> pool;
        pool.reserve(pages);
        for (std::size_t i = 0; i < pages; ++i)
        {
            void *p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (p)
                pool.push_back(p);
        }
        // An empty pool would make run_contention and run_probe divide by / index past pool.size(); fail fast on a
        // setup error rather than later crashing inside a timed loop.
        if (pool.empty())
        {
            std::fprintf(stderr, "[bench] make_churn_pool: all %zu VirtualAlloc reservations failed (%lu)\n", pages,
                         GetLastError());
            std::exit(1);
        }
        return pool;
    }

    LatencyResult run_contention(const std::vector<void *> &pool, unsigned threads, std::size_t ops_per_thread)
    {
        std::vector<std::vector<double>> per_thread(threads);
        std::atomic<bool> go{false};
        std::vector<std::thread> workers;
        workers.reserve(threads);

        for (unsigned t = 0; t < threads; ++t)
        {
            workers.emplace_back(
                [&, t]()
                {
                    auto &lat = per_thread[t];
                    lat.reserve(ops_per_thread);
                    // Each thread starts at a different offset so they collide on shards rather than marching in
                    // lockstep over the same address.
                    std::size_t idx = (t * 1597u) % pool.size();
                    while (!go.load(std::memory_order_acquire))
                    {
                    }
                    for (std::size_t i = 0; i < ops_per_thread; ++i)
                    {
                        void *addr = pool[idx];
                        idx += 251u; // stride coprime-ish with pool size to spread
                        if (idx >= pool.size())
                            idx -= pool.size();
                        const auto s = Clock::now();
                        const bool r = is_readable(addr, 8);
                        const auto e = Clock::now();
                        sink(r ? 1u : 0u);
                        lat.push_back(
                            static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(e - s).count()));
                    }
                });
        }

        go.store(true, std::memory_order_release);
        for (auto &w : workers)
            w.join();

        std::vector<double> all;
        for (auto &v : per_thread)
            all.insert(all.end(), v.begin(), v.end());
        return percentiles(all);
    }

    // Warm-HIT contention throughput. Every thread hammers is_readable over a small, pre-warmed pool so almost all
    // lookups hit the cache. With the lookup reduced to a per-shard shared lock plus the reader-tracking counter, the
    // throughput ceiling is set by cross-thread cache-line contention on those words -- exactly what the striped reader
    // counters and the per-shard cache-line alignment target. Returns aggregate throughput (million is_readable/s),
    // the metric that collapses when readers re-serialize on one shared line. A warm address re-misses at most once per
    // cache TTL, so the periodic re-warm is negligible against the hit stream.
    double run_warm_contention(const std::vector<void *> &pool, unsigned threads, std::size_t ops_per_thread)
    {
        std::atomic<bool> go{false};
        std::atomic<unsigned> ready{0};
        std::vector<std::thread> workers;
        workers.reserve(threads);

        for (unsigned t = 0; t < threads; ++t)
        {
            workers.emplace_back(
                [&, t]()
                {
                    std::size_t idx = (t * 1597u) % pool.size();
                    std::uint32_t local = 0;
                    ready.fetch_add(1, std::memory_order_acq_rel);
                    while (!go.load(std::memory_order_acquire))
                    {
                    }
                    for (std::size_t i = 0; i < ops_per_thread; ++i)
                    {
                        local += is_readable(pool[idx], 8) ? 1u : 0u;
                        ++idx;
                        if (idx >= pool.size())
                            idx = 0;
                    }
                    sink(local);
                });
        }

        // Start timing only once every worker is spun up and waiting, so the window is the parallel work rather than
        // thread creation.
        while (ready.load(std::memory_order_acquire) < threads)
        {
        }
        const auto start = Clock::now();
        go.store(true, std::memory_order_release);
        for (auto &w : workers)
            w.join();
        const auto end = Clock::now();

        const double secs =
            static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()) / 1.0e9;
        const double total_ops = static_cast<double>(threads) * static_cast<double>(ops_per_thread);
        return secs > 0.0 ? (total_ops / secs) / 1.0e6 : 0.0;
    }

    // Probe model: a hook resolves one object and reads K dependent fields off it, spanning a few distinct heap objects
    // rather than a single page.
    //
    // GATED puts is_readable(addr, size) in front of every read. On a hot path that touches many distinct objects,
    // those addresses are mostly cache misses (one new page per object thrashes the fixed-size cache), so each gated
    // read pays a VirtualQuery plus a shard lock. DIRECT drops the predicate and does a raw volatile dereference per
    // read (no guarded-read call, no
    // __try frame), which isolates the predicate cost. On MSVC a guarded direct read (read<T>) costs about the same,
    // since the SEH frame is table-driven and free on the no-fault path (Phase 3). This measures both, per-probe,
    // including the tail.
    //
    // reads_per_obj models how many of the K reads land on the same page (same object) before the walk jumps to a new
    // object: the first read of each object misses; the rest hit within the cache TTL. With K=8 and reads_per_obj=3 a
    // probe pays about 3 misses and 5 hits when gated.
    struct ProbeStats
    {
        double p50, p99, max, mean;
    };

    ProbeStats run_probe(const std::vector<void *> &pool, std::size_t probes, std::size_t k_reads,
                         std::size_t reads_per_obj, bool gated)
    {
        std::vector<double> lat;
        lat.reserve(probes);
        std::size_t obj = 0;
        for (std::size_t pr = 0; pr < probes; ++pr)
        {
            std::uintptr_t base = reinterpret_cast<std::uintptr_t>(pool[obj]);
            const auto s = Clock::now();
            std::uint64_t acc = 0;
            std::size_t within = 0;
            for (std::size_t r = 0; r < k_reads; ++r)
            {
                if (within >= reads_per_obj)
                {
                    // Chain jumps to a new distinct object -> new page -> miss.
                    within = 0;
                    obj += 977; // coprime-ish stride to spread across the pool
                    if (obj >= pool.size())
                        obj -= pool.size();
                    base = reinterpret_cast<std::uintptr_t>(pool[obj]);
                }
                const std::uintptr_t a = base + within * 8; // same page, distinct field
                ++within;
                if (gated)
                {
                    if (is_readable(reinterpret_cast<void *>(a), 8))
                        acc += *reinterpret_cast<volatile std::uint64_t *>(a);
                }
                else
                {
                    acc += *reinterpret_cast<volatile std::uint64_t *>(a);
                }
            }
            const auto e = Clock::now();
            sink(acc);
            lat.push_back(static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(e - s).count()));
            // Advance to a fresh starting object for the next probe.
            obj += 977;
            if (obj >= pool.size())
                obj -= pool.size();
        }
        const LatencyResult pc = percentiles(lat);
        double mean = 0.0;
        for (double x : lat)
            mean += x;
        mean /= static_cast<double>(lat.empty() ? 1 : lat.size());
        return {pc.p50_ns, pc.p99_ns, pc.max_ns, mean};
    }
} // namespace

int main()
{
    // Silence write_bytes' success/debug logging so we time the memory work, not the log path. The level gate is an
    // atomic check before any string formatting, so Error-level leaves the hot ops uninstrumented.
    DetourModKit::log().set_log_level(DetourModKit::LogLevel::Error);

    constexpr std::size_t ITERS = 200000;
    constexpr std::size_t SAMPLES = 15;
    constexpr std::size_t WRITE_ITERS = 20000; // write_bytes is syscall-heavy

    std::uint64_t *page = make_stable_page();
    const auto addr = reinterpret_cast<std::uintptr_t>(page);
    std::byte src[8];
    std::memcpy(src, page, 8);

    std::printf("DetourModKit Memory microbenchmark (toolchain: %s)\n",
#ifdef _MSC_VER
                "MSVC (seh_* use __try/__except)"
#else
                "non-MSVC (seh_* use the vectored-handler fault guard)"
#endif
    );
    std::printf("DEFAULT_CACHE_EXPIRY_MS = %u\n\n", static_cast<unsigned>(Mem::DEFAULT_CACHE_EXPIRY_MS));

    // Phase 1: cache OFF -> validators take the direct-VirtualQuery branch.
    Mem::shutdown_cache(); // ensure uninitialized
    std::printf("[1] Validation MISS / uncached (cache off -> VirtualQuery branch)\n");
    const double ns_qry = median_ns_per_call(ITERS, SAMPLES,
                                             [&]()
                                             {
                                                 MEMORY_BASIC_INFORMATION mbi;
                                                 sink(VirtualQuery(page, &mbi, sizeof(mbi)));
                                             });
    report("raw VirtualQuery", ns_qry);
    const double ns_isr_miss = median_ns_per_call(ITERS, SAMPLES, [&]() { sink(is_readable(page, 8) ? 1u : 0u); });
    report("is_readable MISS", ns_isr_miss);
    const double ns_isw_miss = median_ns_per_call(ITERS, SAMPLES, [&]() { sink(is_writable(page, 8) ? 1u : 0u); });
    report("is_writable MISS", ns_isw_miss);

    // Phase 2: cache ON, warm -> validators hit the fresh entry.
    if (!Mem::init_cache())
    {
        std::fprintf(stderr, "[bench] init_cache failed\n");
        return 1;
    }
    sink(is_readable(page, 8) ? 1u : 0u); // warm the entry
    sink(is_writable(page, 8) ? 1u : 0u);
    std::printf("\n[2] Validation WARM HIT (cache on, entry fresh within TTL)\n");
    const double ns_isr_hit = median_ns_per_call(ITERS, SAMPLES, [&]() { sink(is_readable(page, 8) ? 1u : 0u); });
    report("is_readable HIT", ns_isr_hit);
    const double ns_isw_hit = median_ns_per_call(ITERS, SAMPLES, [&]() { sink(is_writable(page, 8) ? 1u : 0u); });
    report("is_writable HIT", ns_isw_hit);

    // Phase 3: direct access primitives (no cache dependence).
    std::printf("\n[3] Direct access primitives\n");
    const double ns_dread =
        median_ns_per_call(ITERS, SAMPLES, [&]() { sink(*reinterpret_cast<volatile std::uint64_t *>(page)); });
    report("direct volatile load", ns_dread);
    const double ns_unchecked =
        median_ns_per_call(ITERS, SAMPLES, [&]() { sink(Mem::unchecked::read<std::uint64_t>(Address{addr})); });
    report("unchecked::read<u64>", ns_unchecked);
    const double ns_sehread = median_ns_per_call(ITERS, SAMPLES,
                                                 [&]()
                                                 {
                                                     auto v = Mem::read<std::uint64_t>(Address{addr});
                                                     sink(v ? *v : 0u);
                                                 });
    report("read<u64> (guarded)", ns_sehread);
    const double ns_dstore = median_ns_per_call(
        ITERS, SAMPLES,
        [&]() { *reinterpret_cast<volatile std::uint64_t *>(page) = s_sink.load(std::memory_order_relaxed); });
    report("direct volatile store", ns_dstore);
    const double ns_wbytes = median_ns_per_call(
        WRITE_ITERS, SAMPLES, [&]() { (void)Mem::write_bytes(Address{page}, std::span<const std::byte>{src, 8}); });
    report("write_bytes(8)", ns_wbytes);

    std::printf("\n  cache stats: %s\n", Mem::get_cache_stats().c_str());

    // Phase 4: VirtualQuery cost vs VAD-tree size.
    std::printf("\n[4] raw VirtualQuery vs VAD-tree size (single fixed address)\n");
    const std::size_t vad_steps[] = {0, 1000, 4000, 12000};
    std::size_t grown = 0;
    for (std::size_t target : vad_steps)
    {
        if (target > grown)
        {
            grow_vad(target - grown);
            grown = target;
        }
        const double ns = median_ns_per_call(ITERS, SAMPLES,
                                             [&]()
                                             {
                                                 MEMORY_BASIC_INFORMATION mbi;
                                                 sink(VirtualQuery(page, &mbi, sizeof(mbi)));
                                             });
        std::printf("  +%6zu reserved regions   %10.2f ns/call\n", grown, ns);
    }

    // Phase 5: contention p50/p99 (the jitter mechanism).
    std::printf("\n[5] is_readable latency under contention (mostly-miss workload)\n");
    auto pool = make_churn_pool(4096); // 4096 addrs vs 256-entry cache => ~mostly miss
    std::printf("  churn pool: %zu committed pages\n", pool.size());
    for (unsigned threads : {1u, 2u, 4u})
    {
        auto r = run_contention(pool, threads, 50000);
        std::printf("  %u thread(s):  p50 %8.0f ns   p99 %9.0f ns   max %10.0f ns\n", threads, r.p50_ns, r.p99_ns,
                    r.max_ns);
    }

    // Phase 6: REALISTIC probe cost + tail. A probe = K dependent reads across a few distinct objects. GATED =
    // is_readable() before each read (the per-read gated pattern). DIRECT = raw volatile read, no predicate and no
    // __try (the direct, unchecked access path; on MSVC a guarded read is about as cheap, Phase 3). Distinct objects
    // per probe -> cache misses dominate (the real apply path).
    constexpr std::size_t K_READS = 8;       // fields per probe (~5-8 typical)
    constexpr std::size_t READS_PER_OBJ = 3; // ~3 distinct objects per probe
    constexpr std::size_t PROBES = 30000;
    std::printf("\n[6] Per-probe cost: %zu reads across ~%zu distinct (cache-missing) objects\n", K_READS,
                (K_READS + READS_PER_OBJ - 1) / READS_PER_OBJ);
    const ProbeStats gated = run_probe(pool, PROBES, K_READS, READS_PER_OBJ, true);
    const ProbeStats direct = run_probe(pool, PROBES, K_READS, READS_PER_OBJ, false);
    std::printf("  GATED  (is_readable+read): p50 %7.0f  p99 %8.0f  max %9.0f  mean %7.0f ns/probe\n", gated.p50,
                gated.p99, gated.max, gated.mean);
    std::printf("  DIRECT (raw read)        : p50 %7.0f  p99 %8.0f  max %9.0f  mean %7.0f ns/probe\n", direct.p50,
                direct.p99, direct.max, direct.mean);
    std::printf("  gated/direct mean ratio  : %.1fx   (added by the per-read gate: %.0f ns/probe)\n",
                direct.mean > 0 ? gated.mean / direct.mean : 0.0, gated.mean - direct.mean);
    std::printf("  cache stats after probes : %s\n", Mem::get_cache_stats().c_str());

    // Phase 7: per-frame budget. A per-bind / apply hook fires P probes in a frame (one per material instance /
    // bound object touched). Show what fraction of a 16.67 ms (60 FPS) frame the GATED vs DIRECT path consumes. This is
    // the model that matters: cost scales with PROBES-PER-FRAME, which for an apply path touching many bound objects is
    // large -- not "2/frame".
    std::printf("\n[7] Per-frame budget (16.67 ms frame): cost = probes/frame x ns/probe\n");
    std::printf("  %-12s %13s %9s %13s %9s\n", "probes/fr", "gated ms/fr", "%frame", "direct ms/fr", "%frame");
    for (std::size_t P : {1u, 8u, 64u, 256u, 1024u})
    {
        const double g_ms = static_cast<double>(P) * gated.mean / 1.0e6;
        const double d_ms = static_cast<double>(P) * direct.mean / 1.0e6;
        std::printf("  %-12zu %13.4f %8.2f%% %13.4f %8.2f%%\n", P, g_ms, 100.0 * g_ms / 16.667, d_ms,
                    100.0 * d_ms / 16.667);
    }
    std::printf("  (worst single GATED probe this run: %.0f ns = %.4f ms -> a one-probe frame\n"
                "   can spike %.2f%% of budget from the tail alone)\n",
                gated.max, gated.max / 1.0e6, 100.0 * (gated.max / 1.0e6) / 16.667);

    // Contrast: the light case is a handful of validations per frame on a few
    // stable (cached) addresses. With warm hits that is sub-microsecond per frame, which is why a low-frequency
    // validated path is imperceptible while the high-frequency probe path above is not.
    std::printf("  contrast (2 warm validations/frame): %.4f ms/frame\n", (ns_isr_hit + ns_isw_hit) / 1.0e6);

    // Phase 8: pointer-chain primitives. Walk a stable in-process chain (warm cache, the favorable case for the
    // gated walk) three ways: a GATED per-link walk that calls is_readable before each dereference, vs walk (resolve
    // the leaf address) and walk + read<u64> (resolve then load) which guard the whole walk with one fault frame.
    // Shows the per-link predicate cost stacking up even when every address is cached.
    constexpr std::size_t CHAIN_CELLS = 6;
    std::vector<std::uintptr_t> nodes(CHAIN_CELLS, 0);
    nodes[CHAIN_CELLS - 1] = 0xABCDEF0123456789ull;
    for (std::size_t i = 0; i + 1 < CHAIN_CELLS; ++i)
        nodes[i] = reinterpret_cast<std::uintptr_t>(&nodes[i + 1]);
    const std::uintptr_t chain_base = reinterpret_cast<std::uintptr_t>(&nodes[0]);
    std::array<std::ptrdiff_t, CHAIN_CELLS> chain_offsets{}; // all zero
    const std::span<const std::ptrdiff_t> chain_span{chain_offsets};

    std::printf("\n[8] Pointer chain (%zu links, warm cache)\n", CHAIN_CELLS);
    const double ns_gated_walk =
        median_ns_per_call(ITERS, SAMPLES,
                           [&]()
                           {
                               std::uintptr_t cur = chain_base;
                               bool ok = true;
                               for (std::size_t i = 0; i + 1 < CHAIN_CELLS; ++i)
                               {
                                   if (!is_readable(reinterpret_cast<void *>(cur), sizeof(std::uintptr_t)))
                                   {
                                       ok = false;
                                       break;
                                   }
                                   cur = *reinterpret_cast<volatile std::uintptr_t *>(cur);
                               }
                               std::uint64_t v = 0;
                               if (ok && is_readable(reinterpret_cast<void *>(cur), sizeof(std::uint64_t)))
                                   v = *reinterpret_cast<volatile std::uint64_t *>(cur);
                               sink(v);
                           });
    report("gated link walk", ns_gated_walk);
    const double ns_resolve_chain = median_ns_per_call(ITERS, SAMPLES,
                                                       [&]()
                                                       {
                                                           const auto a = Mem::walk(Address{chain_base}, chain_span);
                                                           sink(a ? a->raw() : 0u);
                                                       });
    report("walk (resolve chain)", ns_resolve_chain);
    const double ns_read_chain = median_ns_per_call(ITERS, SAMPLES,
                                                    [&]()
                                                    {
                                                        // walk resolves the leaf address under one fault guard; the
                                                        // guarded read then loads the value. Together they are the v4
                                                        // equivalent of the old single read-chain primitive.
                                                        const auto a = Mem::walk(Address{chain_base}, chain_span);
                                                        std::uint64_t v = 0;
                                                        if (a)
                                                        {
                                                            const auto leaf = Mem::read<std::uint64_t>(*a);
                                                            v = leaf ? *leaf : 0u;
                                                        }
                                                        sink(v);
                                                    });
    report("walk + read<u64>", ns_read_chain);
    std::printf("  gated/(walk+read) ratio: %.1fx\n", ns_read_chain > 0 ? ns_gated_walk / ns_read_chain : 0.0);

    // Phase 9: warm-HIT is_readable throughput under contention. The cache stays on and a small pre-warmed pool
    // keeps almost every lookup a hit, so this isolates the cross-thread cost of the reader-tracking counter and the
    // per-shard shared lock -- the path the striped reader counters and cache-line-aligned shards target. Throughput
    // that keeps scaling with thread count (rather than flattening as readers serialize on one counter line) is the
    // win this phase measures.
    {
        constexpr std::size_t WARM_POOL = 256; // fits the cache (<= 16 shards x 32 hard-max) so all entries stay warm
        constexpr std::size_t WARM_OPS = 1u << 20; // is_readable calls per thread
        auto warm_pool = make_churn_pool(WARM_POOL);
        for (void *p : warm_pool)
            sink(is_readable(p, 8) ? 1u : 0u); // pre-warm every entry into the cache

        std::printf("\n[9] is_readable warm-HIT throughput under contention (Mops/s, higher is better)\n");
        for (const unsigned threads : {1u, 2u, 4u, 8u})
        {
            const double mops = run_warm_contention(warm_pool, threads, WARM_OPS);
            std::printf("  %u thread(s): %10.2f Mops/s\n", threads, mops);
            std::printf("#TSV\twarm_hit_mops_%u_threads\t%.2f\n", threads, mops);
        }
    }

    // TSV block for machine parsing.
    std::printf("\n#TSV\tscenario\tns_per_call\n");
    for (const auto &r : g_rows)
        std::printf("#TSV\t%s\t%.2f\n", r.name, r.ns);
    std::printf("#TSV\tprobe_gated_mean\t%.2f\n", gated.mean);
    std::printf("#TSV\tprobe_gated_p99\t%.2f\n", gated.p99);
    std::printf("#TSV\tprobe_gated_max\t%.2f\n", gated.max);
    std::printf("#TSV\tprobe_direct_mean\t%.2f\n", direct.mean);
    std::printf("#TSV\tprobe_gated_over_direct\t%.2f\n", direct.mean > 0 ? gated.mean / direct.mean : 0.0);

    Mem::shutdown_cache();
    std::printf("\n(sink=%llu)\n", static_cast<unsigned long long>(s_sink.load(std::memory_order_relaxed)));
    return 0;
}
