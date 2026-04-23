/**
 * @file bench_event_dispatcher.cpp
 * @brief Standalone microbenchmark harness for EventDispatcher<T>.
 *
 * Measures emit(), emit_safe(), subscribe + unsubscribe round-trip, and
 * concurrent emit throughput. Uses only std::chrono::steady_clock so no
 * extra dependency is pulled in.
 *
 * Build with -DDMK_BUILD_BENCHMARKS=ON. Executable name: DetourModKit_bench.
 *
 * Output is a tab-separated table on stdout. One row per metric. Columns:
 *   scenario, subscribers, iterations, median_ns_per_op, total_ms
 *
 * This binary is deliberately not a gtest: it is a separate executable so
 * it can run under whatever build configuration the user wants (release,
 * release+PGO, etc.) without dragging in the gtest runtime.
 */

#include "DetourModKit/event_dispatcher.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

namespace
{
    struct BenchEvent
    {
        int value{0};
    };

    using Clock = std::chrono::steady_clock;

    // Compiler barrier / value sink. Prevents the optimizer from noticing
    // that the handler result is unused and deleting the whole emit loop.
    // Atomic so bench_concurrent_emit can fan out across threads without a
    // data race on the sink; relaxed order because the numeric value is
    // never read for synchronization, only printed after join() synchronizes
    // with the producers.
    std::atomic<std::uint64_t> g_sink{0};

    void noop_handler(const BenchEvent &e) noexcept
    {
        g_sink.fetch_add(static_cast<std::uint64_t>(e.value),
                         std::memory_order_relaxed);
    }

    // Runs `op` `iterations` times within a single sample, repeats the
    // sample `samples` times, and returns the median wall time per sample
    // in nanoseconds divided by iterations (i.e. per-op cost).
    template <typename Op>
    double median_ns_per_op(std::size_t iterations, std::size_t samples, Op &&op)
    {
        std::vector<double> per_op;
        per_op.reserve(samples);

        for (std::size_t s = 0; s < samples; ++s)
        {
            const auto start = Clock::now();
            for (std::size_t i = 0; i < iterations; ++i)
            {
                op();
            }
            const auto end = Clock::now();
            const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                end - start)
                                .count();
            per_op.push_back(static_cast<double>(ns) / static_cast<double>(iterations));
        }

        std::sort(per_op.begin(), per_op.end());
        // Average the two middle samples on even counts so the helper
        // returns the true median regardless of sample parity. Current
        // callers use 11 samples (odd), but future callers may not.
        const std::size_t n = per_op.size();
        if ((n % 2) == 0)
        {
            return (per_op[(n / 2) - 1] + per_op[n / 2]) / 2.0;
        }
        return per_op[n / 2];
    }

    void bench_emit(std::size_t subscriber_count,
                    std::size_t iterations,
                    std::size_t samples,
                    const char *label,
                    bool use_safe)
    {
        DetourModKit::EventDispatcher<BenchEvent> dispatcher;
        std::vector<DetourModKit::Subscription> subs;
        subs.reserve(subscriber_count);
        for (std::size_t i = 0; i < subscriber_count; ++i)
        {
            subs.push_back(dispatcher.subscribe(&noop_handler));
        }

        const BenchEvent evt{42};
        const auto total_start = Clock::now();
        const double med = median_ns_per_op(iterations, samples, [&]() {
            if (use_safe)
            {
                dispatcher.emit_safe(evt);
            }
            else
            {
                dispatcher.emit(evt);
            }
        });
        const auto total_end = Clock::now();

        const auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  total_end - total_start)
                                  .count();

        std::printf("%s\t%zu\t%zu\t%.2f\t%lld\n",
                    label,
                    subscriber_count,
                    iterations,
                    med,
                    static_cast<long long>(total_ms));
    }

    void bench_subscribe_unsubscribe(std::size_t iterations, std::size_t samples)
    {
        DetourModKit::EventDispatcher<BenchEvent> dispatcher;

        const auto total_start = Clock::now();
        const double med = median_ns_per_op(iterations, samples, [&]() {
            auto sub = dispatcher.subscribe(&noop_handler);
            // sub destroyed here: triggers unsubscribe
        });
        const auto total_end = Clock::now();

        const auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  total_end - total_start)
                                  .count();

        std::printf("subscribe_unsub_roundtrip\t0\t%zu\t%.2f\t%lld\n",
                    iterations,
                    med,
                    static_cast<long long>(total_ms));
    }

    void bench_concurrent_emit(std::size_t thread_count,
                               std::size_t per_thread_iters,
                               std::size_t subscriber_count)
    {
        DetourModKit::EventDispatcher<BenchEvent> dispatcher;
        std::vector<DetourModKit::Subscription> subs;
        subs.reserve(subscriber_count);
        for (std::size_t i = 0; i < subscriber_count; ++i)
        {
            subs.push_back(dispatcher.subscribe(&noop_handler));
        }

        std::atomic<bool> go{false};
        std::vector<std::thread> workers;
        workers.reserve(thread_count);

        const BenchEvent evt{7};

        for (std::size_t t = 0; t < thread_count; ++t)
        {
            workers.emplace_back([&dispatcher, &go, &evt, per_thread_iters]() {
                while (!go.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                for (std::size_t i = 0; i < per_thread_iters; ++i)
                {
                    dispatcher.emit(evt);
                }
            });
        }

        const auto start = Clock::now();
        go.store(true, std::memory_order_release);
        for (auto &w : workers)
        {
            w.join();
        }
        const auto end = Clock::now();

        const auto total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                  end - start)
                                  .count();
        const auto total_ops = thread_count * per_thread_iters;
        const double per_op =
            static_cast<double>(total_ns) / static_cast<double>(total_ops);

        std::printf("emit_concurrent_%zu_threads\t%zu\t%zu\t%.2f\t%lld\n",
                    thread_count,
                    subscriber_count,
                    total_ops,
                    per_op,
                    static_cast<long long>(total_ns / 1'000'000));
    }

    void bench_reentrancy_rejection(std::size_t iterations, std::size_t samples)
    {
        DetourModKit::EventDispatcher<BenchEvent> dispatcher;

        // Inside the handler, subscribe() will be rejected by the
        // reentrancy guard. The cost measured here is the rejection path.
        auto sub = dispatcher.subscribe([&dispatcher](const BenchEvent &) {
            auto inner = dispatcher.subscribe(&noop_handler);
            (void)inner;
        });

        const BenchEvent evt{0};

        const auto total_start = Clock::now();
        const double med = median_ns_per_op(iterations, samples, [&]() {
            dispatcher.emit(evt);
        });
        const auto total_end = Clock::now();

        const auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  total_end - total_start)
                                  .count();

        std::printf("reentrancy_rejection\t1\t%zu\t%.2f\t%lld\n",
                    iterations,
                    med,
                    static_cast<long long>(total_ms));
    }
} // namespace

int main()
{
    constexpr std::size_t samples = 11; // odd, so median is well-defined

    std::printf("scenario\tsubscribers\titerations\tmedian_ns_per_op\ttotal_ms\n");

    // --- Single-thread emit() ---
    bench_emit(0, 10'000'000, samples, "emit", false);
    bench_emit(1, 5'000'000, samples, "emit", false);
    bench_emit(8, 1'000'000, samples, "emit", false);
    bench_emit(64, 200'000, samples, "emit", false);

    // --- Single-thread emit_safe() ---
    bench_emit(0, 10'000'000, samples, "emit_safe", true);
    bench_emit(1, 5'000'000, samples, "emit_safe", true);
    bench_emit(8, 1'000'000, samples, "emit_safe", true);
    bench_emit(64, 200'000, samples, "emit_safe", true);

    // --- Subscribe + unsubscribe round-trip ---
    bench_subscribe_unsubscribe(100'000, samples);

    // --- Concurrent emit throughput ---
    bench_concurrent_emit(4, 1'000'000, 8);

    // --- Reentrancy-rejection path ---
    bench_reentrancy_rejection(500'000, samples);

    // Touch g_sink so the optimizer keeps the handler body.
    std::printf("# sink=%llu\n",
                static_cast<unsigned long long>(
                    g_sink.load(std::memory_order_relaxed)));
    return 0;
}
