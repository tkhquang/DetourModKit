// RTTI identity-probe microbenchmark (B1). It measures the two paths a per-frame consumer reaches: the warm
// TypeIdentity::matches test, and the find_in_pointer_table sweep with no cache, which walks RTTI for every slot.
// Prints one TSV row per workload plus the gate records described in bench_gate.hpp to stdout.
//
// The fixtures are synthetic MSVC COL/TypeDescriptor/vtable triples written into this executable's data segment, the
// shape tests/test_rtti_reverse.cpp builds. Their addresses are real host-image addresses: memory::module_of resolves
// them back to this executable's PE range, and the resolver validates every candidate against that module, so the
// measured cost is the shipping prelude rather than a stub. A live C++ class instead of a synthetic triple
// restricts the whole benchmark to MSVC, because the MinGW Itanium ABI emits no COL for the walker to find.
//
// Each workload runs twice. The untimed batch carries the reported mean, because steady_clock's tick on this platform
// is coarser than a warm probe and a per-call timer pair both quantizes and inflates it. The sampled pass carries
// the percentiles, which show the tail the mean hides. The tick column states the granularity the percentiles round
// to, so a reader can tell a measured difference from a rounding artifact.

#include "DetourModKit/region.hpp"
#include "DetourModKit/rtti.hpp"

#include "bench_gate.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

using namespace DetourModKit;
using namespace std::chrono;

namespace
{
    // Synthetic MSVC x64 RTTI layout offsets, mirroring the reverse-resolver fixture. The COL, TypeDescriptor, and
    // vtable storage are placed apart from each other and from page boundaries.
    constexpr std::size_t BUF_SIZE = 4096;
    constexpr std::size_t COL_OFFSET = 256;
    constexpr std::size_t TD_OFFSET = COL_OFFSET + 24; // COL is 24 bytes
    constexpr std::size_t TD_NAME_OFFSET = TD_OFFSET + 16;
    constexpr std::size_t COL_PTR_OFFSET = 2048; // the vtable[-1] meta-slot
    constexpr std::size_t VTABLE_OFFSET = COL_PTR_OFFSET + 8;

    constexpr std::size_t SLOT_COUNT = 64;
    constexpr std::size_t POOL_FIXTURES = SLOT_COUNT + 2;

    alignas(8) std::array<std::byte, BUF_SIZE * POOL_FIXTURES> s_pool{};
    std::size_t s_used = 0;

    // Slot backing storage. Each entry's first qword is its object's vtable, so a table slot pointing at it presents
    // the layout find_in_pointer_table dereferences.
    alignas(8) std::array<std::uintptr_t, SLOT_COUNT> s_objects{};
    alignas(8) std::array<std::uintptr_t, SLOT_COUNT> s_table{};

    template <typename T> void pool_write(std::byte *buf, std::size_t off, const T &value) noexcept
    {
        std::memcpy(buf + off, &value, sizeof(T));
    }

    // Builds one synthetic COL/TypeDescriptor/vtable carrying @p name and returns the synthetic vtable address, or 0
    // when the pool is exhausted or the data segment sits below the image base, which wraps the RVA.
    [[nodiscard]] std::uintptr_t build_synth(std::string_view name) noexcept
    {
        if (s_used + BUF_SIZE > s_pool.size())
        {
            return 0;
        }
        std::byte *buf = s_pool.data() + s_used;
        s_used += BUF_SIZE;
        std::memset(buf, 0, BUF_SIZE);

        const std::uintptr_t exe_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const std::uintptr_t buf_base = reinterpret_cast<std::uintptr_t>(buf);
        if (buf_base < exe_base)
        {
            return 0;
        }
        const std::uintptr_t buf_rva = buf_base - exe_base;

        pool_write<std::uint32_t>(buf, COL_OFFSET + 0, 1); // signature (x64)
        pool_write<std::uint32_t>(buf, COL_OFFSET + 4, 0); // offset in complete object
        pool_write<std::uint32_t>(buf, COL_OFFSET + 8, 0); // cd_offset
        pool_write<std::uint32_t>(buf, COL_OFFSET + 12, static_cast<std::uint32_t>(buf_rva + TD_OFFSET));
        pool_write<std::uint32_t>(buf, COL_OFFSET + 16, 0);
        pool_write<std::uint32_t>(buf, COL_OFFSET + 20, static_cast<std::uint32_t>(buf_rva + COL_OFFSET));

        const std::size_t max_name = COL_PTR_OFFSET - TD_NAME_OFFSET - 1;
        const std::size_t name_len = name.size() < max_name ? name.size() : max_name;
        std::memcpy(buf + TD_NAME_OFFSET, name.data(), name_len);
        buf[TD_NAME_OFFSET + name_len] = std::byte{0};

        pool_write<std::uintptr_t>(buf, COL_PTR_OFFSET, buf_base + COL_OFFSET);
        return buf_base + VTABLE_OFFSET;
    }

    // The pool sub-range written so far. It is not a PE image, so the resolver sweeps exactly this range instead of
    // this executable's whole image, which keeps the one-shot TypeIdentity resolve off the measured warm path.
    [[nodiscard]] Region pool_range() noexcept
    {
        return Region{Address{reinterpret_cast<std::uintptr_t>(s_pool.data())}, s_used};
    }

    // One workload's two passes. @p mean_ns comes from the untimed batch; the percentiles come from the sampled pass.
    struct Measurement
    {
        double mean_ns = 0.0;
        long long p50 = 0;
        long long p99 = 0;
        long long p999 = 0;
        long long max = 0;
        std::size_t iterations = 0;
        std::size_t correct = 0;
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

    // Runs @p probe for @p warmup then @p iterations untimed calls to derive the mean, then @p iterations sampled
    // calls to derive the percentiles. @p probe returns whether the call produced its expected answer; the untimed
    // pass counts those, which is what keeps the optimizer from discarding a batch whose result is never read.
    [[nodiscard]] Measurement measure(int warmup, int iterations, auto &&probe)
    {
        Measurement result;
        result.iterations = static_cast<std::size_t>(iterations);

        for (int i = 0; i < warmup; ++i)
        {
            (void)probe();
        }

        std::size_t batch_correct = 0;
        const auto batch_start = steady_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            batch_correct += probe() ? 1u : 0u;
        }
        const auto batch_ns = duration_cast<nanoseconds>(steady_clock::now() - batch_start).count();
        result.mean_ns = static_cast<double>(batch_ns) / static_cast<double>(iterations);

        std::vector<long long> samples;
        samples.reserve(static_cast<std::size_t>(iterations));
        std::size_t sampled_correct = 0;
        for (int i = 0; i < iterations; ++i)
        {
            const auto start = steady_clock::now();
            const bool ok = probe();
            const auto end = steady_clock::now();
            samples.push_back(duration_cast<nanoseconds>(end - start).count());
            sampled_correct += ok ? 1u : 0u;
        }
        summarize_into(result, samples);
        result.correct = batch_correct + sampled_correct;
        return result;
    }

    // The smallest nonzero gap between two consecutive clock reads, which is the granularity every percentile column
    // rounds to. A p50 below this value means the operation completed inside one tick, not that it took zero time.
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

    void print_row(const char *workload, std::size_t slots, const Measurement &m, long long tick_ns) noexcept
    {
        std::printf(
            "%s\t%zu\t%zu\t%.1f\t%lld\t%lld\t%lld\t%lld\t%lld\n",
            workload,
            slots,
            m.iterations,
            m.mean_ns,
            m.p50,
            m.p99,
            m.p999,
            m.max,
            tick_ns
        );
    }
} // namespace

int main()
{
    dmk_bench::GateLedger gates("rtti");

    constexpr std::string_view WARM_NAME = ".?AVBenchRttiWarm@@";
    constexpr std::string_view SLOT_NAME = ".?AVBenchRttiSlot@@";
    constexpr std::string_view ABSENT_NAME = ".?AVBenchRttiAbsent@@";

    const std::uintptr_t warm_vtable = build_synth(WARM_NAME);
    if (warm_vtable == 0)
    {
        gates.abort_setup("rtti.warm_fixture_built");
    }
    for (std::size_t i = 0; i < SLOT_COUNT; ++i)
    {
        const std::uintptr_t slot_vtable = build_synth(SLOT_NAME);
        if (slot_vtable == 0)
        {
            gates.abort_setup("rtti.slot_fixtures_built");
        }
        s_objects[i] = slot_vtable;
        s_table[i] = reinterpret_cast<std::uintptr_t>(&s_objects[i]);
    }

    const long long tick_ns = clock_tick_ns(50000);

    // Warm TypeIdentity::matches. The first call resolves; every measured call is the per-frame path the header
    // documents as callback-safe once warm.
    rtti::TypeIdentity identity(WARM_NAME, pool_range());
    const bool resolved = identity.matches(Address{warm_vtable});

    constexpr int WARM_WARMUP = 20000;
    constexpr int WARM_ITERATIONS = 200000;
    const Measurement warm =
        measure(WARM_WARMUP, WARM_ITERATIONS, [&] { return identity.matches(Address{warm_vtable}); });

    // find_in_pointer_table with no cache. Every call walks RTTI for every slot, which is the cold cost the header
    // warns about. The miss variant sweeps all SLOT_COUNT slots and finds nothing; the first-hit variant stops at
    // slot 0, so the pair brackets the sweep and separates the per-slot cost from the fixed call cost.
    constexpr int TABLE_WARMUP = 50;
    constexpr int TABLE_ITERATIONS = 2000;
    const Address table_base{reinterpret_cast<std::uintptr_t>(s_table.data())};
    const Address expected_first_slot{s_table[0]};

    const Measurement miss = measure(
        TABLE_WARMUP,
        TABLE_ITERATIONS,
        [&] { return !rtti::find_in_pointer_table(table_base, SLOT_COUNT, ABSENT_NAME, nullptr).has_value(); }
    );

    const Measurement hit = measure(
        TABLE_WARMUP,
        TABLE_ITERATIONS,
        [&]
        {
            const auto found = rtti::find_in_pointer_table(table_base, SLOT_COUNT, SLOT_NAME, nullptr);
            return found.has_value() && *found == expected_first_slot;
        }
    );

    std::printf("workload\tslots\titerations\tmean_ns\tp50_ns\tp99_ns\tp999_ns\tmax_ns\tclock_tick_ns\n");
    print_row("type_identity_matches_warm", 1, warm, tick_ns);
    print_row("find_in_pointer_table_cold_miss", SLOT_COUNT, miss, tick_ns);
    print_row("find_in_pointer_table_cold_first_hit", SLOT_COUNT, hit, tick_ns);

    // A warm path that never matched, or a sweep that returned the wrong slot, still produces a full table.
    // These facts are what make the table a measurement of the intended path.
    const std::size_t warm_expected = static_cast<std::size_t>(WARM_ITERATIONS) * 2u;
    const std::size_t table_expected = static_cast<std::size_t>(TABLE_ITERATIONS) * 2u;
    gates.fact("rtti.identity_resolved", resolved);
    gates.fact("rtti.warm_matches_every_call", warm.correct == warm_expected);
    gates.fact("rtti.cold_miss_returns_empty", miss.correct == table_expected);
    gates.fact("rtti.cold_hit_returns_first_slot", hit.correct == table_expected);
    gates.metric("rtti.matches_warm_mean_ns", warm.mean_ns);
    gates.metric("rtti.pointer_table_cold_miss_mean_ns", miss.mean_ns);
    gates.metric("rtti.pointer_table_cold_miss_mean_ns_per_slot", miss.mean_ns / static_cast<double>(SLOT_COUNT));
    gates.metric("rtti.pointer_table_cold_first_hit_mean_ns", hit.mean_ns);
    return gates.close();
}
