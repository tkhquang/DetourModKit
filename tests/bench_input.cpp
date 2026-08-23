#include "DetourModKit/input.hpp"

#include "bench_gate.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <vector>

using namespace DetourModKit;
using namespace std::chrono;

namespace
{
    constexpr std::size_t WIDE_COMBOS = 8;

    // The workloads use F13 through F21. Functional gates reject an active queried key.
    // Each combo has no modifiers, so strict modifier checks remain inert.
    constexpr int NARROW_FIRST_KEY = 0x7C; // VK_F13
    constexpr int WIDE_FIRST_KEY = 0x7D;   // VK_F14 through VK_F21

    constexpr int WARMUP = 20000;
    constexpr int ITERATIONS = 200000;

    struct Measurement
    {
        double mean_ns = 0.0;
        long long p50 = 0;
        long long p99 = 0;
        long long p999 = 0;
        long long max = 0;
        std::size_t iterations = 0;
        std::size_t expected_answers = 0;
    };

    void summarize_into(Measurement &out, std::vector<long long> &samples) noexcept
    {
        std::sort(samples.begin(), samples.end());
        const auto at = [&](double fraction) -> long long
        { return samples[static_cast<std::size_t>(fraction * static_cast<double>(samples.size() - 1))]; };
        out.p50 = at(0.50);
        out.p99 = at(0.99);
        out.p999 = at(0.999);
        out.max = samples.back();
    }

    /**
     * @brief Measures one query with a batch mean and per-call samples.
     * @param warmup This value sets the call count before measurement.
     * @param iterations This value sets the call count in each measured pass.
     * @param probe This callable returns true for an expected answer.
     * @return The result contains the batch mean, coarse percentiles, and expected-answer count.
     * @details The batch timer amortizes clock quantization. The answer count prevents optimizer removal.
     */
    [[nodiscard]] Measurement measure(int warmup, int iterations, auto &&probe)
    {
        Measurement result;
        result.iterations = static_cast<std::size_t>(iterations);

        for (int i = 0; i < warmup; ++i)
        {
            (void)probe();
        }

        std::size_t batch_expected = 0;
        const auto batch_start = steady_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            batch_expected += probe() ? 1u : 0u;
        }
        const auto batch_ns = duration_cast<nanoseconds>(steady_clock::now() - batch_start).count();
        result.mean_ns = static_cast<double>(batch_ns) / static_cast<double>(iterations);

        std::vector<long long> samples;
        samples.reserve(static_cast<std::size_t>(iterations));
        std::size_t sampled_expected = 0;
        for (int i = 0; i < iterations; ++i)
        {
            const auto start = steady_clock::now();
            const bool ok = probe();
            const auto end = steady_clock::now();
            samples.push_back(duration_cast<nanoseconds>(end - start).count());
            sampled_expected += ok ? 1u : 0u;
        }
        summarize_into(result, samples);
        result.expected_answers = batch_expected + sampled_expected;
        return result;
    }

    /**
     * @brief Finds the smallest nonzero delta between consecutive clock reads.
     * @param samples The value specifies the clock-read pair count.
     * @return The smallest nonzero delta, or zero when every pair matches.
     */
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

    void print_row(const char *workload, std::size_t entries, const Measurement &m, long long tick_ns) noexcept
    {
        std::printf("%s\t%zu\t%zu\t%.1f\t%lld\t%lld\t%lld\t%lld\t%lld\n", workload, entries, m.iterations, m.mean_ns,
                    m.p50, m.p99, m.p999, m.max, tick_ns);
    }

    [[nodiscard]] input::KeyComboList combos_from(int first_key, std::size_t count)
    {
        input::KeyComboList combos;
        combos.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            combos.push_back(input::KeyCombo{{keyboard_key(first_key + static_cast<int>(i))}, {}});
        }
        return combos;
    }
} // namespace

int main()
{
    dmk_bench::GateLedger gates("input");

    auto &mgr = input::Input::instance();

    auto narrow_guard = input::register_combo(input::ComboBinding{
        .name = "bench_narrow",
        .trigger = input::Trigger::Press,
        .combos = combos_from(NARROW_FIRST_KEY, 1),
        .on_press = [] {},
    });
    if (!narrow_guard.has_value())
    {
        gates.abort_setup("input.narrow_binding_registered");
    }

    auto wide_guard = input::register_combo(input::ComboBinding{
        .name = "bench_wide",
        .trigger = input::Trigger::Press,
        .combos = combos_from(WIDE_FIRST_KEY, WIDE_COMBOS),
        .on_press = [] {},
    });
    if (!wide_guard.has_value())
    {
        gates.abort_setup("input.wide_binding_registered");
    }

    if (!mgr.start().has_value() || !mgr.is_running())
    {
        gates.abort_setup("input.engine_started");
    }

    const input::BindingToken narrow_token = mgr.acquire_token("bench_narrow");
    const input::BindingToken wide_token = mgr.acquire_token("bench_wide");
    const input::BindingToken invalid_token;
    if (!narrow_token.valid() || !wide_token.valid() || invalid_token.valid())
    {
        gates.abort_setup("input.tokens_acquired");
    }

    const long long tick_ns = clock_tick_ns(50000);

    const Measurement invalid = measure(WARMUP, ITERATIONS, [&] { return !mgr.is_active(invalid_token); });
    const Measurement current = measure(WARMUP, ITERATIONS, [&] { return mgr.token_current(narrow_token); });
    const Measurement narrow = measure(WARMUP, ITERATIONS, [&] { return !mgr.is_active(narrow_token); });
    const Measurement wide = measure(WARMUP, ITERATIONS, [&] { return !mgr.is_active(wide_token); });
    const Measurement by_name = measure(WARMUP, ITERATIONS, [&] { return !mgr.is_active("bench_wide"); });

    std::printf("workload\tentries\titerations\tmean_ns\tp50_ns\tp99_ns\tp999_ns\tmax_ns\tclock_tick_ns\n");
    print_row("is_active_invalid_token", 0, invalid, tick_ns);
    print_row("token_current", 1, current, tick_ns);
    print_row("is_active_token", 1, narrow, tick_ns);
    print_row("is_active_token", WIDE_COMBOS, wide, tick_ns);
    print_row("is_active_name", WIDE_COMBOS, by_name, tick_ns);

    // A query that answered the wrong way, or a token that went stale mid-run, still produces a full table. These
    // facts are what make the table a measurement of the intended path.
    const std::size_t expected = static_cast<std::size_t>(ITERATIONS) * 2u;
    gates.fact("input.invalid_token_fails_closed", invalid.expected_answers == expected);
    gates.fact("input.token_stays_current", current.expected_answers == expected);
    gates.fact("input.narrow_token_reads_released", narrow.expected_answers == expected);
    gates.fact("input.wide_token_reads_released", wide.expected_answers == expected);
    gates.fact("input.name_query_reads_released", by_name.expected_answers == expected);
    gates.metric("input.is_active_invalid_token_mean_ns", invalid.mean_ns);
    gates.metric("input.token_current_mean_ns", current.mean_ns);
    gates.metric("input.is_active_token_1_entry_mean_ns", narrow.mean_ns);
    gates.metric("input.is_active_token_8_entries_mean_ns", wide.mean_ns);
    gates.metric("input.is_active_name_8_entries_mean_ns", by_name.mean_ns);
    gates.metric("input.is_active_token_per_entry_mean_ns",
                 (wide.mean_ns - narrow.mean_ns) / static_cast<double>(WIDE_COMBOS - 1));

    mgr.shutdown();
    return gates.close();
}
