// Guarded-dispatch microbenchmark for an armed inline hook (B1). Hook::call pins the refcounted call gate and holds
// its recursive mutex across the dispatch, so hook.hpp warns that concurrent calls through one handle serialize and
// names Hook::original as the route for a hot multi-threaded target. This benchmark measures what that warning costs:
// Hook::call on one thread, Hook::call on two contending threads, and Hook::original on two threads as the unguarded
// reference. Prints one TSV row per workload plus the gate records described in bench_gate.hpp to stdout.
//
// Each workload runs twice. The untimed batch carries the reported throughput and mean, because steady_clock's tick
// on this platform is coarser than one dispatch and a per-call timer pair costs more than the call it wraps.
// The sampled pass carries the percentiles, which show the tail that contention produces and the mean hides. The
// tick column states the granularity the percentiles round to.

#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "bench_gate.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <utility>
#include <vector>

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace std::chrono;

#if defined(_MSC_VER)
#define DMK_BENCH_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_BENCH_NOINLINE [[gnu::noinline]]
#else
#define DMK_BENCH_NOINLINE
#endif

namespace
{
    using TargetFn = int (*)(int);

    constexpr int WARMUP = 20000;
    constexpr int ITERATIONS = 200000;

    // A real, hookable body. The volatile result keeps the call at the patched entry, so the measurement times the
    // dispatch rather than a constant the optimizer folded at the call site.
    DMK_BENCH_NOINLINE int bench_hook_target(int x)
    {
        volatile int r = x;
        return r;
    }

    // The detour returns a distinguishable value, so a call that reached the detour instead of the trampoline is
    // visible in the gate records rather than hidden in the percentiles.
    int bench_hook_detour(int x)
    {
        return x + 100000;
    }

    // Releases every participating thread at the same instant, so a contended run overlaps instead of queueing
    // behind a staggered start.
    class StartLine
    {
    public:
        explicit StartLine(int participants) noexcept : m_participants(participants) {}

        void wait() noexcept
        {
            if (m_participants <= 1)
            {
                return;
            }
            m_arrived.fetch_add(1, std::memory_order_acq_rel);
            while (m_arrived.load(std::memory_order_acquire) < m_participants)
            {
                std::this_thread::yield();
            }
        }

    private:
        int m_participants;
        std::atomic<int> m_arrived{0};
    };

    /// One thread's contribution to one workload.
    struct ThreadResult
    {
        std::vector<long long> samples;
        std::size_t correct = 0;
        long long batch_ns = 0;
    };

    // Warms up, waits at @p batch_line, runs ITERATIONS untimed calls, then waits at @p sample_line and runs
    // ITERATIONS sampled calls. @p dispatch returns the callee's value, which equals the argument only when the call
    // reached the original body through the trampoline.
    void run_thread(ThreadResult &out, auto &&dispatch, StartLine &batch_line, StartLine &sample_line)
    {
        for (int i = 0; i < WARMUP; ++i)
        {
            (void)dispatch(i);
        }

        batch_line.wait();
        std::size_t batch_correct = 0;
        const auto batch_start = steady_clock::now();
        for (int i = 0; i < ITERATIONS; ++i)
        {
            batch_correct += (dispatch(i) == i) ? 1u : 0u;
        }
        out.batch_ns = duration_cast<nanoseconds>(steady_clock::now() - batch_start).count();

        sample_line.wait();
        out.samples.reserve(static_cast<std::size_t>(ITERATIONS));
        std::size_t sampled_correct = 0;
        for (int i = 0; i < ITERATIONS; ++i)
        {
            const auto start = steady_clock::now();
            const int value = dispatch(i);
            const auto end = steady_clock::now();
            out.samples.push_back(duration_cast<nanoseconds>(end - start).count());
            sampled_correct += (value == i) ? 1u : 0u;
        }
        out.correct = batch_correct + sampled_correct;
    }

    /// One workload's merged figures across its threads.
    struct Measurement
    {
        double mean_ns = 0.0;
        double calls_per_second = 0.0;
        long long p50 = 0;
        long long p99 = 0;
        long long p999 = 0;
        long long max = 0;
        std::size_t calls = 0;
        std::size_t correct = 0;
    };

    // Runs @p dispatch on @p threads threads and merges them. Throughput uses the slowest thread's batch wall clock,
    // because that is when the whole workload finished.
    [[nodiscard]] Measurement measure(int threads, auto &&dispatch)
    {
        std::vector<ThreadResult> results(static_cast<std::size_t>(threads));
        StartLine batch_line(threads);
        StartLine sample_line(threads);

        if (threads == 1)
        {
            run_thread(results[0], dispatch, batch_line, sample_line);
        }
        else
        {
            std::vector<std::thread> workers;
            workers.reserve(static_cast<std::size_t>(threads));
            for (int t = 0; t < threads; ++t)
            {
                workers.emplace_back(
                    [&, t] { run_thread(results[static_cast<std::size_t>(t)], dispatch, batch_line, sample_line); });
            }
            for (std::thread &worker : workers)
            {
                worker.join();
            }
        }

        Measurement out;
        std::vector<long long> merged;
        long long slowest_batch_ns = 0;
        for (const ThreadResult &result : results)
        {
            merged.insert(merged.end(), result.samples.begin(), result.samples.end());
            out.correct += result.correct;
            slowest_batch_ns = std::max(slowest_batch_ns, result.batch_ns);
        }

        const auto batch_calls = static_cast<double>(threads) * static_cast<double>(ITERATIONS);
        out.calls = static_cast<std::size_t>(batch_calls) * 2u;
        if (slowest_batch_ns > 0)
        {
            out.mean_ns = static_cast<double>(slowest_batch_ns) * static_cast<double>(threads) / batch_calls;
            out.calls_per_second = batch_calls * 1e9 / static_cast<double>(slowest_batch_ns);
        }

        std::sort(merged.begin(), merged.end());
        const auto at = [&](double fraction) -> long long
        { return merged[static_cast<std::size_t>(fraction * static_cast<double>(merged.size() - 1))]; };
        out.p50 = at(0.50);
        out.p99 = at(0.99);
        out.p999 = at(0.999);
        out.max = merged.back();
        return out;
    }

    // The smallest nonzero gap between two consecutive clock reads, which is the granularity every percentile column
    // rounds to. A p50 below this value means the dispatch completed inside one tick, not that it took zero time.
    [[nodiscard]] long long clock_tick_ns(int samples) noexcept
    {
        long long smallest = 0;
        for (int i = 0; i < samples; ++i)
        {
            const auto start = steady_clock::now();
            const auto end = steady_clock::now();
            const auto delta = duration_cast<nanoseconds>(end - start).count();
            if (delta > 0 && (smallest == 0 || delta < smallest))
            {
                smallest = delta;
            }
        }
        return smallest;
    }

    void print_row(const char *workload, int threads, const Measurement &m, long long tick_ns) noexcept
    {
        std::printf("%s\t%d\t%zu\t%.1f\t%lld\t%lld\t%lld\t%lld\t%.0f\t%lld\n", workload, threads, m.calls, m.mean_ns,
                    m.p50, m.p99, m.p999, m.max, m.calls_per_second, tick_ns);
    }
} // namespace

int main()
{
    dmk_bench::GateLedger gates("hook");

    const Address target{reinterpret_cast<std::uintptr_t>(&bench_hook_target)};
    Result<Hook> created =
        inline_at(InlineRequest{.name = "BenchGuardedDispatch", .target = target}, &bench_hook_detour);
    if (!created.has_value())
    {
        std::fprintf(stderr, "bench_hook: inline_at failed: %s\n", created.error().message().c_str());
        gates.abort_setup("hook.created");
    }
    Hook hook = std::move(*created);
    gates.fact("hook.created", static_cast<bool>(hook));

    if (!hook.enable().has_value())
    {
        gates.abort_setup("hook.enabled");
    }
    gates.fact("hook.enabled", hook.is_enabled());

    auto *original = hook.original<TargetFn>();
    if (original == nullptr)
    {
        gates.abort_setup("hook.trampoline_published");
    }
    gates.fact("hook.trampoline_published", true);

    const long long tick_ns = clock_tick_ns(50000);

    const auto guarded = [&hook](int i) { return hook.call<int>(i); };
    const auto unguarded = [original](int i) { return original(i); };

    const Measurement guarded_single = measure(1, guarded);
    const Measurement guarded_two = measure(2, guarded);
    const Measurement unguarded_two = measure(2, unguarded);

    std::printf("workload\tthreads\tcalls\tmean_ns\tp50_ns\tp99_ns\tp999_ns\tmax_ns\tcalls_per_s\tclock_tick_ns\n");
    print_row("hook_call_guarded", 1, guarded_single, tick_ns);
    print_row("hook_call_guarded", 2, guarded_two, tick_ns);
    print_row("hook_original_unguarded", 2, unguarded_two, tick_ns);

    // Every measured call must have reached the original body through the trampoline. A refused guarded dispatch
    // returns a value-initialized int and a call that reached the detour returns i + 100000. Either one leaves the
    // table measuring something other than the dispatch path.
    gates.fact("hook.guarded_single_reached_the_original", guarded_single.correct == guarded_single.calls);
    gates.fact("hook.guarded_two_thread_reached_the_original", guarded_two.correct == guarded_two.calls);
    gates.fact("hook.unguarded_two_thread_reached_the_original", unguarded_two.correct == unguarded_two.calls);
    gates.metric("hook.call_guarded_1t_mean_ns", guarded_single.mean_ns);
    gates.metric("hook.call_guarded_2t_mean_ns", guarded_two.mean_ns);
    gates.metric("hook.original_unguarded_2t_mean_ns", unguarded_two.mean_ns);
    gates.metric("hook.call_guarded_1t_calls_per_s", guarded_single.calls_per_second);
    gates.metric("hook.call_guarded_2t_calls_per_s", guarded_two.calls_per_second);
    gates.metric("hook.original_unguarded_2t_calls_per_s", unguarded_two.calls_per_second);
    return gates.close();
}
