// Guarded-dispatch microbenchmark for an armed inline hook (B1). Hook::call pins the refcounted call gate and holds
// its recursive mutex across the dispatch, so hook.hpp warns that concurrent calls through one handle serialize and
// names Hook::original as the route for a hot multi-threaded target. This benchmark measures what that warning costs:
// Hook::call on one thread, Hook::call on two contending threads, and Hook::original on two threads as the unguarded
// reference. Prints one TSV row per workload plus the gate records described in bench_gate.hpp to stdout.
//
// The entry workloads time a call at the patched entry itself. A raw and a counted inline hook run one detour on one
// target, so their difference is the cost of the counted thunk. Calls across 1 and 16 bypassed layers give the cost
// of one residue hop. A closed mid route under a restored inline layer gives the entry cost of a retired mid hook.
//
// Each round of a workload runs two passes. The untimed batch carries the reported throughput and mean. The tick of
// steady_clock on this platform is coarser than one dispatch, and a per-call timer pair costs more than the call it
// wraps. The sampled pass carries the percentiles, which show the tail that contention produces and the mean hides.
// The tick column states the granularity the percentiles round to.
//
// A guarded workload runs one round. The entry workloads run ENTRY_ROUNDS interleaved rounds, and each round installs
// and removes its own hooks. An entry row reports the median batch mean and pools the samples of every round. Each
// derived cost subtracts two medians, so one preempted batch does not flip its sign.
//
// The retire workloads time one HookStack::retire of 29 counted hooks, as many as the field retirement held. The idle
// workload adds no thread. The parked workload adds 150 waiting threads, and the saturated workload also spins 8 more
// threads than the logical processors. Each workload runs RETIRE_ROUNDS rounds and reports the median.

#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "bench_gate.hpp"
#include "fixtures/proof_section.hpp"
#include "fixtures/thread_load.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace std::chrono;

namespace
{
    using TargetFn = int (*)(int);

    constexpr int WARMUP = 20000;
    constexpr int ITERATIONS = 200000;
    /// The rounds of each entry workload. An odd count makes the median one measured batch mean.
    constexpr int ENTRY_ROUNDS = 9;
    /// The value that every detour adds, so a result shows whether the call reached a detour.
    constexpr int DETOUR_BONUS = 100000;
    /// The bypassed layers that a call of the short residue workload crosses. Each chain holds one more layer.
    constexpr int SHORT_CHAIN_HOPS = 1;
    /// The bypassed layers that a call of the long residue workload crosses.
    constexpr int LONG_CHAIN_HOPS = 16;
    /// The size of the jump that a patch writes at a target entry.
    constexpr std::size_t ENTRY_JUMP_SIZE = 5;

    // A real, hookable body. The volatile result keeps the call at the patched entry, so the measurement times the
    // dispatch rather than a constant the optimizer folded at the call site.
    DMK_PROOF_TARGET int bench_hook_target(int x)
    {
        volatile int r = x;
        return r;
    }

    // The detour returns a distinguishable value, so a call that reached the detour instead of the trampoline is
    // visible in the gate records rather than hidden in the percentiles.
    int bench_hook_detour(int x)
    {
        return x + DETOUR_BONUS;
    }

    // The body differs from bench_hook_target, so no toolchain folds the two targets into one address. The raw and the
    // counted entry workloads hook it in turn.
    DMK_PROOF_TARGET int entry_target(int x)
    {
        volatile std::int64_t r = x;
        return static_cast<int>(r);
    }

    // The residue and mid workloads hook this target in turn. Its result stays below DETOUR_BONUS, so a call that
    // reached a detour never returns an original result.
    DMK_PROOF_SEEDED_TARGET(residue_target, 211)

    /// The trampoline of the entry hook under measurement. Each entry workload sets it before its enable.
    TargetFn s_entry_original = nullptr;

    // The raw and the counted entry hook both install this detour, so their rows differ only by the counted thunk.
    int entry_detour(int x) noexcept
    {
        return s_entry_original(x) + DETOUR_BONUS;
    }

    /// The calls that reached the mid callback. A closed route leaves it at zero.
    std::atomic<int> s_mid_callbacks{0};

    void count_mid_callback(MidContext &) noexcept
    {
        s_mid_callbacks.fetch_add(1, std::memory_order_relaxed);
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

    /// The figures of every round of one workload.
    struct Rounds
    {
        std::vector<double> batch_means;
        std::vector<long long> samples;
        std::size_t calls = 0;
        std::size_t correct = 0;
    };

    /// One workload's merged figures across its threads and rounds.
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

    // Runs one round of @p dispatch on @p threads threads and adds its figures to @p rounds. The batch mean uses the
    // slowest thread's batch wall clock, because that is when the whole round finished.
    void run_round(Rounds &rounds, int threads, auto &&dispatch)
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
                    [&, t] { run_thread(results[static_cast<std::size_t>(t)], dispatch, batch_line, sample_line); }
                );
            }
            for (std::thread &worker : workers)
            {
                worker.join();
            }
        }

        long long slowest_batch_ns = 0;
        for (const ThreadResult &result : results)
        {
            rounds.samples.insert(rounds.samples.end(), result.samples.begin(), result.samples.end());
            rounds.correct += result.correct;
            slowest_batch_ns = std::max(slowest_batch_ns, result.batch_ns);
        }
        rounds.calls += static_cast<std::size_t>(threads) * static_cast<std::size_t>(ITERATIONS) * 2u;
        rounds.batch_means.push_back(static_cast<double>(slowest_batch_ns) / static_cast<double>(ITERATIONS));
    }

    // Merges @p rounds into one row. The mean is the median batch mean, and the percentiles pool the samples of every
    // round.
    [[nodiscard]] Measurement summarize(Rounds rounds, int threads)
    {
        Measurement out;
        out.calls = rounds.calls;
        out.correct = rounds.correct;

        const auto median = rounds.batch_means.begin() + static_cast<std::ptrdiff_t>(rounds.batch_means.size() / 2);
        std::nth_element(rounds.batch_means.begin(), median, rounds.batch_means.end());
        out.mean_ns = *median;
        if (out.mean_ns > 0.0)
        {
            out.calls_per_second = static_cast<double>(threads) * 1e9 / out.mean_ns;
        }

        std::vector<long long> &merged = rounds.samples;
        std::sort(merged.begin(), merged.end());
        const auto at = [&](double fraction) -> long long
        { return merged[static_cast<std::size_t>(fraction * static_cast<double>(merged.size() - 1))]; };
        out.p50 = at(0.50);
        out.p99 = at(0.99);
        out.p999 = at(0.999);
        out.max = merged.back();
        return out;
    }

    [[nodiscard]] Measurement measure(int threads, auto &&dispatch)
    {
        Rounds rounds;
        run_round(rounds, threads, dispatch);
        return summarize(std::move(rounds), threads);
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
        std::printf(
            "%s\t%d\t%zu\t%.1f\t%lld\t%lld\t%lld\t%lld\t%.0f\t%lld\n",
            workload,
            threads,
            m.calls,
            m.mean_ns,
            m.p50,
            m.p99,
            m.p999,
            m.max,
            m.calls_per_second,
            tick_ns
        );
    }

    using EntryBytes = std::array<std::uint8_t, ENTRY_JUMP_SIZE>;

    [[nodiscard]] EntryBytes entry_bytes(TargetFn target) noexcept
    {
        EntryBytes bytes{};
        std::memcpy(bytes.data(), reinterpret_cast<const void *>(target), bytes.size());
        return bytes;
    }

    [[nodiscard]] Address address_of(TargetFn target) noexcept
    {
        return Address{reinterpret_cast<std::uintptr_t>(target)};
    }

    struct EntryWorkload
    {
        const char *fact = nullptr;
        Rounds rounds{};
        /// False after a round in which a condition other than the call results failed.
        bool held = true;
    };

    struct EntryRun
    {
        const char *fact = nullptr;
        Measurement measurement;
        bool passed = false;
    };

    /// Merges @p workload. Its fact holds when every call returned its expected value and every round held.
    [[nodiscard]] EntryRun merge_entry(EntryWorkload workload)
    {
        const Measurement measurement = summarize(std::move(workload.rounds), 1);
        return EntryRun{
            .fact = workload.fact,
            .measurement = measurement,
            .passed = workload.held && measurement.correct == measurement.calls,
        };
    }

    /**
     * @brief Records @p fact as failed and exits when @p target already holds a hook.
     * @details The workloads of one target run in turn. A hook that an earlier workload left behind adds layers that
     *          the row does not name.
     */
    void require_unhooked(dmk_bench::GateLedger &gates, const char *fact, TargetFn target) noexcept
    {
        if (is_target_hooked(address_of(target)))
        {
            std::fprintf(stderr, "bench_hook: %s: the target still holds a hook of an earlier workload\n", fact);
            gates.abort_setup(fact);
        }
    }

    /// Pushes @p hook onto @p stack. A failed install records @p fact as failed and exits.
    [[nodiscard]] Hook &push_hook(dmk_bench::GateLedger &gates, const char *fact, HookStack &stack, Result<Hook> hook)
    {
        if (!hook.has_value())
        {
            std::fprintf(stderr, "bench_hook: %s: install failed: %s\n", fact, hook.error().message().c_str());
            gates.abort_setup(fact);
        }
        return stack.push(std::move(*hook));
    }

    /// Records @p fact as failed and exits when the enable or disable that returned @p toggled failed.
    void require_toggled(dmk_bench::GateLedger &gates, const char *fact, const Result<void> &toggled)
    {
        if (!toggled.has_value())
        {
            std::fprintf(stderr, "bench_hook: %s: toggle failed: %s\n", fact, toggled.error().message().c_str());
            gates.abort_setup(fact);
        }
    }

    /**
     * @brief Installs a hook on entry_target through @p install, arms it, and times one round at the patched entry.
     * @details A setup failure records the workload fact as failed and exits. A call is correct when it returned its
     *          argument plus DETOUR_BONUS, which only entry_detour adds to the original result.
     */
    template <class Install>
    void run_entry_round(dmk_bench::GateLedger &gates, EntryWorkload &workload, const char *name, Install install)
    {
        const char *const fact = workload.fact;
        require_unhooked(gates, fact, &entry_target);
        HookStack stack;
        Hook &hook = push_hook(
            gates,
            fact,
            stack,
            install(
                InlineRequest{
                    .name = name,
                    .target = address_of(&entry_target),
                }
            )
        );
        s_entry_original = hook.original<TargetFn>();
        if (s_entry_original == nullptr)
        {
            gates.abort_setup(fact);
        }
        require_toggled(gates, fact, hook.enable());

        run_round(workload.rounds, 1, [](int i) { return dmk_test::call_unfolded(&entry_target, i) - DETOUR_BONUS; });
    }

    /// Returns the result of the unhooked residue_target for every argument that measure() passes.
    [[nodiscard]] std::vector<int> residue_results()
    {
        std::vector<int> results(static_cast<std::size_t>(ITERATIONS));
        for (int i = 0; i < ITERATIONS; ++i)
        {
            results[static_cast<std::size_t>(i)] = dmk_test::call_unfolded(&residue_target, i);
        }
        return results;
    }

    /**
     * @brief Times one round at the entry of residue_target.
     * @details run_thread() counts a call as correct only when it returns its argument. A call that returned the
     *          original result in @p pristine therefore maps to its argument.
     */
    void run_residue_entry_round(Rounds &rounds, const std::vector<int> &pristine)
    {
        run_round(
            rounds,
            1,
            [&pristine](int i)
            { return dmk_test::call_unfolded(&residue_target, i) == pristine[static_cast<std::size_t>(i)] ? i : -1; }
        );
    }

    /**
     * @brief Builds a chain whose calls cross @p hops bypassed layers on residue_target and times one round.
     * @details The chain arms hops + 1 layers. Each lower layer then bypasses under the top layer, and the top layer
     *          restores its saved prologue, which is the jump into the bypassed chain. A bypassed layer runs the same
     *          relay and trampoline jumps as a residue position. A setup failure records the workload fact as failed
     *          and exits. The round holds when the entry still held a patch after the calls.
     */
    void run_residue_round(
        dmk_bench::GateLedger &gates,
        EntryWorkload &workload,
        int hops,
        const std::vector<int> &pristine,
        const EntryBytes &pristine_entry
    )
    {
        const char *const fact = workload.fact;
        require_unhooked(gates, fact, &residue_target);
        HookStack stack;
        std::vector<Hook *> layers;
        stack.reserve(static_cast<std::size_t>(hops) + 1u);
        layers.reserve(static_cast<std::size_t>(hops) + 1u);
        for (int layer = 0; layer <= hops; ++layer)
        {
            Hook &hook = push_hook(
                gates,
                fact,
                stack,
                inline_at(
                    InlineRequest{
                        .name = "BenchResidueHops" + std::to_string(hops) + "Layer" + std::to_string(layer),
                        .target = address_of(&residue_target),
                    },
                    &bench_hook_detour
                )
            );
            require_toggled(gates, fact, hook.enable());
            layers.push_back(&hook);
        }
        // A newer layer sits above each lower layer, so each lower disable bypasses. The top disable restores.
        for (Hook *layer : layers)
        {
            require_toggled(gates, fact, layer->disable());
        }

        run_residue_entry_round(workload.rounds, pristine);
        workload.held = workload.held && entry_bytes(&residue_target) != pristine_entry;
    }

    /**
     * @brief Closes a mid route under a restored inline layer on residue_target and times one round at its entry.
     * @details The mid hook bypasses under the armed inline layer, so its route closes. The inline layer then restores
     *          the mid patch. A setup failure records the workload fact as failed and exits. The round holds when no
     *          callback ran and the entry still held a patch.
     */
    void run_mid_closed_round(
        dmk_bench::GateLedger &gates,
        EntryWorkload &workload,
        const std::vector<int> &pristine,
        const EntryBytes &pristine_entry
    )
    {
        const char *const fact = workload.fact;
        require_unhooked(gates, fact, &residue_target);
        HookStack stack;
        Hook &mid = push_hook(
            gates,
            fact,
            stack,
            mid_at(
                MidRequest{
                    .name = "BenchMidClosedEntry",
                    .target = address_of(&residue_target),
                },
                &count_mid_callback
            )
        );
        require_toggled(gates, fact, mid.enable());
        Hook &top = push_hook(
            gates,
            fact,
            stack,
            inline_at(
                InlineRequest{
                    .name = "BenchMidClosedEntryTop",
                    .target = address_of(&residue_target),
                },
                &bench_hook_detour
            )
        );
        require_toggled(gates, fact, top.enable());
        require_toggled(gates, fact, mid.disable());
        require_toggled(gates, fact, top.disable());

        run_residue_entry_round(workload.rounds, pristine);
        workload.held = workload.held && s_mid_callbacks.load(std::memory_order_relaxed) == 0 &&
                        entry_bytes(&residue_target) != pristine_entry;
    }

    /// The counted hooks of each retire workload, as many as the field retirement held.
    constexpr std::size_t RETIRE_HOOKS = 29;
    /// The rounds of each retire workload. An odd count makes the median one measured retirement.
    constexpr int RETIRE_ROUNDS = 5;
    /// The waiting threads of the parked and saturated retire workloads.
    constexpr std::size_t RETIRE_PARKED_THREADS = 150;
    /// The spinning threads beyond the logical processors in the saturated retire workload.
    constexpr std::size_t RETIRE_EXTRA_SPINNERS = 8;
    /// The drain deadline of one retirement. A slow pass then shows as time, not as Busy.
    constexpr milliseconds RETIRE_DEADLINE{60000};
    /// The gate that every retire round holds.
    constexpr const char *RETIRE_FACT = "hook.retire_counted_restored_every_hook";

    // One target per index. The constant differs for each index, so no toolchain folds two targets.
    template <std::size_t Index> DMK_PROOF_TARGET int retire_target(int x)
    {
        volatile std::int64_t r = static_cast<std::int64_t>(x) * static_cast<std::int64_t>(2 * Index + 3);
        return static_cast<int>(r);
    }

    // The retire workloads never call the hooked targets, so the detour only needs the counted signature.
    template <std::size_t Index> int retire_detour(int x) noexcept
    {
        return x + DETOUR_BONUS;
    }

    /// Arms a counted hook on retire_target<Index>. A failed setup records RETIRE_FACT as failed and exits.
    template <std::size_t Index> void push_retire_hook(dmk_bench::GateLedger &gates, HookStack &stack)
    {
        Hook &hook = push_hook(
            gates,
            RETIRE_FACT,
            stack,
            inline_at<&retire_detour<Index>>(InlineRequest{
                .name = "BenchRetire" + std::to_string(Index),
                .target = address_of(&retire_target<Index>),
            })
        );
        require_toggled(gates, RETIRE_FACT, hook.enable());
    }

    template <std::size_t... Index>
    void push_retire_hooks(dmk_bench::GateLedger &gates, HookStack &stack, std::index_sequence<Index...>)
    {
        (push_retire_hook<Index>(gates, stack), ...);
    }

    struct RetireWorkload
    {
        const char *name = nullptr;
        const char *metric = nullptr;
        std::size_t threads = 0;
        std::vector<double> ms;
        /// False after a round that did not retire every hook by restore.
        bool restored_every_hook = true;
    };

    /// Installs RETIRE_HOOKS counted hooks and times one HookStack::retire over them.
    void run_retire_round(dmk_bench::GateLedger &gates, RetireWorkload &workload)
    {
        HookStack stack;
        stack.reserve(RETIRE_HOOKS);
        push_retire_hooks(gates, stack, std::make_index_sequence<RETIRE_HOOKS>{});
        const auto start = steady_clock::now();
        const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
        workload.ms.push_back(duration<double, std::milli>(steady_clock::now() - start).count());
        workload.restored_every_hook = workload.restored_every_hook && retired.outcome == RetirementOutcome::Retired &&
                                       retired.restored == RETIRE_HOOKS;
    }

    /// Runs RETIRE_ROUNDS retire rounds of @p workload.
    void run_retire_workload(dmk_bench::GateLedger &gates, RetireWorkload &workload)
    {
        for (int round = 0; round < RETIRE_ROUNDS; ++round)
        {
            run_retire_round(gates, workload);
        }
    }

    [[nodiscard]] double median_of(std::vector<double> values)
    {
        std::sort(values.begin(), values.end());
        return values.empty() ? 0.0 : values[values.size() / 2];
    }
} // namespace

int main()
{
    dmk_bench::GateLedger gates("hook");

    const Address target{reinterpret_cast<std::uintptr_t>(&bench_hook_target)};
    Result<Hook> created = inline_at(
        InlineRequest{
            .name = "BenchGuardedDispatch",
            .target = target,
        },
        &bench_hook_detour
    );
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

    EntryWorkload raw_rounds{
        .fact = "hook.raw_inline_entry_reached_the_detour",
    };
    EntryWorkload counted_rounds{
        .fact = "hook.counted_inline_entry_reached_the_detour",
    };
    EntryWorkload short_rounds{
        .fact = "hook.residue_hops_1_skipped_every_detour",
    };
    EntryWorkload long_rounds{
        .fact = "hook.residue_hops_16_skipped_every_detour",
    };
    EntryWorkload mid_rounds{
        .fact = "hook.mid_closed_entry_skipped_the_callback",
    };
    const std::vector<int> pristine = residue_results();
    const EntryBytes pristine_entry = entry_bytes(&residue_target);
    for (int i = 0; i < ENTRY_ROUNDS; ++i)
    {
        run_entry_round(
            gates,
            raw_rounds,
            "BenchRawInlineEntry",
            [](InlineRequest request) { return inline_at(std::move(request), &entry_detour); }
        );
        run_entry_round(
            gates,
            counted_rounds,
            "BenchCountedInlineEntry",
            [](InlineRequest request) { return inline_at<&entry_detour>(std::move(request)); }
        );
        run_residue_round(gates, short_rounds, SHORT_CHAIN_HOPS, pristine, pristine_entry);
        run_residue_round(gates, long_rounds, LONG_CHAIN_HOPS, pristine, pristine_entry);
        run_mid_closed_round(gates, mid_rounds, pristine, pristine_entry);
    }
    const EntryRun raw_entry = merge_entry(std::move(raw_rounds));
    const EntryRun counted_entry = merge_entry(std::move(counted_rounds));
    const EntryRun short_chain = merge_entry(std::move(short_rounds));
    const EntryRun long_chain = merge_entry(std::move(long_rounds));
    const EntryRun mid_closed = merge_entry(std::move(mid_rounds));

    const std::size_t spinners = std::max<std::size_t>(std::thread::hardware_concurrency(), 1) + RETIRE_EXTRA_SPINNERS;
    RetireWorkload retire_idle{
        .name = "retire_counted_29_idle",
        .metric = "hook.retire_counted_29_idle_ms",
    };
    RetireWorkload retire_parked{
        .name = "retire_counted_29_parked_150",
        .metric = "hook.retire_counted_29_parked_150_ms",
        .threads = RETIRE_PARKED_THREADS,
    };
    RetireWorkload retire_saturated{
        .name = "retire_counted_29_saturated",
        .metric = "hook.retire_counted_29_saturated_ms",
        .threads = RETIRE_PARKED_THREADS + spinners,
    };
    run_retire_workload(gates, retire_idle);
    {
        const dmk_test::ParkedThreads parked{RETIRE_PARKED_THREADS};
        if (!parked.wait_until_started(RETIRE_PARKED_THREADS))
        {
            gates.abort_setup(RETIRE_FACT);
        }
        run_retire_workload(gates, retire_parked);
        const dmk_test::SpinningThreads spinning{spinners};
        if (!spinning.wait_until_started(spinners))
        {
            gates.abort_setup(RETIRE_FACT);
        }
        run_retire_workload(gates, retire_saturated);
    }

    std::printf("workload\tthreads\tcalls\tmean_ns\tp50_ns\tp99_ns\tp999_ns\tmax_ns\tcalls_per_s\tclock_tick_ns\n");
    print_row("hook_call_guarded", 1, guarded_single, tick_ns);
    print_row("hook_call_guarded", 2, guarded_two, tick_ns);
    print_row("hook_original_unguarded", 2, unguarded_two, tick_ns);
    print_row("raw_inline_entry", 1, raw_entry.measurement, tick_ns);
    print_row("counted_inline_entry", 1, counted_entry.measurement, tick_ns);
    print_row("residue_hops_1", 1, short_chain.measurement, tick_ns);
    print_row("residue_hops_16", 1, long_chain.measurement, tick_ns);
    print_row("mid_closed_entry", 1, mid_closed.measurement, tick_ns);

    std::printf("\nretire_workload\thooks\textra_threads\trounds\tmedian_ms\tmax_ms\n");
    for (const RetireWorkload *workload : {&retire_idle, &retire_parked, &retire_saturated})
    {
        std::printf(
            "%s\t%zu\t%zu\t%d\t%.2f\t%.2f\n",
            workload->name,
            RETIRE_HOOKS,
            workload->threads,
            RETIRE_ROUNDS,
            median_of(workload->ms),
            *std::max_element(workload->ms.begin(), workload->ms.end())
        );
    }

    // A guarded or unguarded call must reach the original body through the trampoline. A refused guarded dispatch
    // returns a value-initialized int, and a call that reached the detour returns i + DETOUR_BONUS. Either one leaves
    // a row that times something other than the dispatch path.
    gates.fact("hook.guarded_single_reached_the_original", guarded_single.correct == guarded_single.calls);
    gates.fact("hook.guarded_two_thread_reached_the_original", guarded_two.correct == guarded_two.calls);
    gates.fact("hook.unguarded_two_thread_reached_the_original", unguarded_two.correct == unguarded_two.calls);

    gates.fact(raw_entry.fact, raw_entry.passed);
    gates.fact(counted_entry.fact, counted_entry.passed);
    gates.fact(short_chain.fact, short_chain.passed);
    gates.fact(long_chain.fact, long_chain.passed);
    gates.fact(mid_closed.fact, mid_closed.passed);
    gates.fact(
        RETIRE_FACT,
        retire_idle.restored_every_hook && retire_parked.restored_every_hook && retire_saturated.restored_every_hook
    );

    gates.metric("hook.call_guarded_1t_mean_ns", guarded_single.mean_ns);
    gates.metric("hook.call_guarded_2t_mean_ns", guarded_two.mean_ns);
    gates.metric("hook.original_unguarded_2t_mean_ns", unguarded_two.mean_ns);
    gates.metric("hook.call_guarded_1t_calls_per_s", guarded_single.calls_per_second);
    gates.metric("hook.call_guarded_2t_calls_per_s", guarded_two.calls_per_second);
    gates.metric("hook.original_unguarded_2t_calls_per_s", unguarded_two.calls_per_second);
    gates.metric("hook.raw_inline_entry_mean_ns", raw_entry.measurement.mean_ns);
    gates.metric("hook.counted_inline_entry_mean_ns", counted_entry.measurement.mean_ns);
    gates.metric("hook.residue_hops_1_mean_ns", short_chain.measurement.mean_ns);
    gates.metric("hook.residue_hops_16_mean_ns", long_chain.measurement.mean_ns);
    gates.metric("hook.mid_closed_entry_mean_ns", mid_closed.measurement.mean_ns);
    gates.metric("hook.counted_thunk_ns", counted_entry.measurement.mean_ns - raw_entry.measurement.mean_ns);
    gates.metric(
        "hook.residue_hop_ns",
        (long_chain.measurement.mean_ns - short_chain.measurement.mean_ns) /
            static_cast<double>(LONG_CHAIN_HOPS - SHORT_CHAIN_HOPS)
    );
    for (const RetireWorkload *workload : {&retire_idle, &retire_parked, &retire_saturated})
    {
        gates.metric(workload->metric, median_of(workload->ms));
    }
    return gates.close();
}
