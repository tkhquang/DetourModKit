/**
 * @file bench_scanner.cpp
 * @brief Standalone microbenchmark harness for Scanner::find_pattern.
 *
 * Measures find_pattern throughput across realistic and adversarial pattern shapes, and contrasts the rare-byte anchor
 * heuristic against a "first literal byte" anchor that mimics the simpler scanner described in
 * Otis Inf's blog comment (the original Witcher 3 mod scanner uses an
 * 8-byte XOR+AND verify with pattern[0] as the anchor).
 *
 * The benchmark generates one shared 8 MiB buffer with a byte distribution tuned to typical x64 PE .text frequencies
 * (so the common-byte set 0x48, 0x8B, 0xCC, ... is over-represented and rare bytes really are rare). Each pattern is
 * timed on the same buffer with both anchor strategies; the "smart" run is the production DMK scanner, the "naive" run
 * reuses the same scanner with pattern.anchor manually overridden to the first literal byte index. Apples-to-apples:
 * every other code path (memchr loop, SIMD verify, SSE2/AVX2 tier) stays identical.
 *
 * Build with -DDMK_BUILD_BENCHMARKS=ON. Executable name:
 *   DetourModKit_bench_scanner
 *
 * Output is a tab-separated table on stdout. Columns:
 *   scenario, anchor, iterations, median_us_per_scan, scans_per_second, speedup_vs_naive
 */

#include "DetourModKit/scanner.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <span>
#include <vector>

namespace
{
    using Clock = std::chrono::steady_clock;
    using DetourModKit::Scanner::CompiledPattern;

    // Sink so the optimizer can't observe that the return value of find_pattern is unused and delete the work.
    std::atomic<std::uintptr_t> s_sink{0};

    // Generate a buffer that approximates x64 .text byte frequencies. The numbers below are loose but realistic: common
    // opcodes / prefixes are over-represented, the rest are uniform over the byte space. A fixed seed keeps results
    // comparable across runs.
    std::vector<std::byte> make_codelike_buffer(std::size_t size_bytes, std::uint64_t seed)
    {
        struct WeightedByte
        {
            std::uint8_t value;
            double weight;
        };

        constexpr std::array<WeightedByte, 12> hot_bytes{{
            {0x48, 0.12}, // REX.W prefix
            {0x8B, 0.06}, // MOV reg, r/m
            {0x89, 0.06}, // MOV r/m, reg
            {0xFF, 0.05}, // call/jmp indirect
            {0x0F, 0.05}, // two-byte opcode escape
            {0xE8, 0.05}, // CALL rel32
            {0xCC, 0.04}, // INT3 padding
            {0xE9, 0.03}, // JMP rel32
            {0x83, 0.03}, // arithmetic imm8
            {0x90, 0.03}, // NOP
            {0xC3, 0.02}, // RET
            {0x00, 0.05}, // null padding / zeros
        }};

        double hot_total = 0.0;
        for (const auto &h : hot_bytes)
        {
            hot_total += h.weight;
        }

        std::mt19937_64 rng{seed};
        std::uniform_real_distribution<double> dist{0.0, 1.0};
        std::uniform_int_distribution<int> uniform_byte{0, 255};

        std::vector<std::byte> out(size_bytes);
        for (std::size_t i = 0; i < size_bytes; ++i)
        {
            const double r = dist(rng);
            if (r < hot_total)
            {
                double accum = 0.0;
                std::uint8_t chosen = 0;
                for (const auto &h : hot_bytes)
                {
                    accum += h.weight;
                    if (r < accum)
                    {
                        chosen = h.value;
                        break;
                    }
                }
                out[i] = std::byte{chosen};
            }
            else
            {
                out[i] = std::byte{static_cast<std::uint8_t>(uniform_byte(rng))};
            }
        }

        return out;
    }

    // Drop a known signature into the buffer at a fixed offset so the scan has a real match to find rather than
    // terminating on "not found".
    void plant_signature(std::span<std::byte> buffer, std::size_t offset, std::initializer_list<std::uint8_t> bytes)
    {
        std::size_t i = 0;
        for (const auto b : bytes)
        {
            if (offset + i >= buffer.size())
            {
                break;
            }
            buffer[offset + i] = std::byte{b};
            ++i;
        }
    }

    // Build a CompiledPattern whose anchor is forced to the first literal byte. This emulates the simpler scanner: it
    // always anchors on the start of the pattern (after skipping leading wildcards), rather than on the rarest literal.
    CompiledPattern make_naive_pattern(const CompiledPattern &smart)
    {
        CompiledPattern copy = smart;
        std::size_t anchor = smart.size();
        for (std::size_t i = 0; i < smart.size(); ++i)
        {
            if (smart.mask[i] != std::byte{0x00})
            {
                anchor = i;
                break;
            }
        }
        copy.anchor = anchor;
        return copy;
    }

    // Runs the scan `iterations` times within a single sample, repeats the sample `samples` times, returns the median
    // wall time per iteration in microseconds.
    template <typename Op> double median_us_per_iter(std::size_t iterations, std::size_t samples, Op &&op)
    {
        std::vector<double> per_iter;
        per_iter.reserve(samples);

        for (std::size_t s = 0; s < samples; ++s)
        {
            const auto start = Clock::now();
            for (std::size_t i = 0; i < iterations; ++i)
            {
                op();
            }
            const auto end = Clock::now();
            const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            per_iter.push_back(static_cast<double>(ns) / static_cast<double>(iterations) / 1000.0);
        }

        std::sort(per_iter.begin(), per_iter.end());
        const std::size_t n = per_iter.size();
        if ((n % 2) == 0)
        {
            return (per_iter[(n / 2) - 1] + per_iter[n / 2]) / 2.0;
        }
        return per_iter[n / 2];
    }

    struct Scenario
    {
        const char *name;
        const char *aob;
    };

    void run_scenario(const Scenario &scenario, std::span<const std::byte> buffer, std::size_t iterations,
                      std::size_t samples)
    {
        auto parsed = DetourModKit::Scanner::parse_aob(scenario.aob);
        if (!parsed.has_value())
        {
            std::fprintf(stderr, "[bench] failed to parse AOB: %s\n", scenario.aob);
            return;
        }
        const CompiledPattern smart = std::move(*parsed);
        const CompiledPattern naive = make_naive_pattern(smart);

        // Sanity check: warm up + assert both anchors point at literal bytes.
        const auto *warm_smart = DetourModKit::Scanner::find_pattern(buffer.data(), buffer.size(), smart);
        const auto *warm_naive = DetourModKit::Scanner::find_pattern(buffer.data(), buffer.size(), naive);
        // Both must agree on the result (either both nullptr or both same address).
        if (warm_smart != warm_naive)
        {
            std::fprintf(stderr, "[bench] mismatch on '%s': smart=%p naive=%p\n", scenario.name,
                         static_cast<const void *>(warm_smart), static_cast<const void *>(warm_naive));
            return;
        }
        s_sink.fetch_add(reinterpret_cast<std::uintptr_t>(warm_smart), std::memory_order_relaxed);

        const double us_smart =
            median_us_per_iter(iterations, samples,
                               [&]()
                               {
                                   const auto *m =
                                       DetourModKit::Scanner::find_pattern(buffer.data(), buffer.size(), smart);
                                   s_sink.fetch_add(reinterpret_cast<std::uintptr_t>(m), std::memory_order_relaxed);
                               });

        const double us_naive =
            median_us_per_iter(iterations, samples,
                               [&]()
                               {
                                   const auto *m =
                                       DetourModKit::Scanner::find_pattern(buffer.data(), buffer.size(), naive);
                                   s_sink.fetch_add(reinterpret_cast<std::uintptr_t>(m), std::memory_order_relaxed);
                               });

        const double speedup = us_naive / us_smart;
        const double smart_throughput = 1.0e6 / us_smart;
        const double naive_throughput = 1.0e6 / us_naive;

        std::printf("%-32s\t%-6s\t%9zu\t%12.3f\t%14.1f\t%9.2fx\n", scenario.name, "smart", iterations, us_smart,
                    smart_throughput, 1.0);
        std::printf("%-32s\t%-6s\t%9zu\t%12.3f\t%14.1f\t%9.2fx\n", scenario.name, "naive", iterations, us_naive,
                    naive_throughput, 1.0 / speedup);
        std::printf("%-32s\t%-6s\t%9zu\t%12s\t%14s\t%9.2fx\n", scenario.name, "ratio", iterations, "-", "-", speedup);
    }
} // namespace

int main()
{
    constexpr std::size_t BUFFER_SIZE = 8u * 1024u * 1024u; // 8 MiB
    constexpr std::uint64_t SEED = 0xD37011CDull;
    constexpr std::size_t SAMPLES = 11;

    std::printf("DetourModKit Scanner microbenchmark\n");
    std::printf("Buffer: %zu bytes (code-like byte distribution, seed 0x%llx)\n", BUFFER_SIZE,
                static_cast<unsigned long long>(SEED));
    std::printf("SIMD tier: ");
    switch (DetourModKit::Scanner::active_simd_level())
    {
    case DetourModKit::Scanner::SimdLevel::Avx2:
        std::printf("AVX2\n");
        break;
    case DetourModKit::Scanner::SimdLevel::Sse2:
        std::printf("SSE2\n");
        break;
    case DetourModKit::Scanner::SimdLevel::Scalar:
        std::printf("Scalar\n");
        break;
    }
    std::printf("\n");

    auto buffer = make_codelike_buffer(BUFFER_SIZE, SEED);

    // Match-present scenarios: a known signature is planted near the end of the buffer so the scan has to walk most of
    // the region before finding it. The plant byte sequences begin with a rare byte (0x37) so the signature itself is
    // unambiguous; what differs is whether the pattern's anchor selection lands on a common byte (naive) or the rare
    // one (smart).
    constexpr std::size_t PLANT_OFFSET = 7u * 1024u * 1024u + 137u;

    plant_signature(buffer, PLANT_OFFSET, {0x48, 0x8B, 0x05, 0x37, 0xDE, 0xAD, 0xBE, 0xEF});

    // Scenarios. Each runs the planted buffer through both anchor variants of the SAME find_pattern code path.
    // Mismatches abort the scenario, which doubles as a correctness check.
    constexpr std::array<Scenario, 6> scenarios = {{
        {"common_first_rare_buried_8", "48 8B 05 37 DE AD BE EF"},
        {"common_first_rare_buried_16", "48 8B 05 37 DE AD BE EF 90 90 CC CC E8 ?? ?? ??"},
        {"all_common_first_no_match", "48 8B 05 89 0F E8 90 CC"},
        {"rare_first_short_no_match", "37 6B C1 BA 5E 71"},
        {"long_mostly_wildcards", "48 8B 05 ?? ?? ?? ?? 48 89 ?? ?? ?? ?? 37 DE AD"},
        {"verify_heavy_32B_match", "48 8B 05 37 DE AD BE EF 90 90 CC CC E8 ?? ?? ?? "
                                   "?? ?? ?? ?? 48 89 5C 24 08 48 89 6C 24 10 48 89"},
    }};

    // Header
    std::printf("%-32s\t%-6s\t%9s\t%12s\t%14s\t%10s\n", "scenario", "anchor", "iters", "median_us", "scans/sec",
                "speedup");
    std::printf("%-32s\t%-6s\t%9s\t%12s\t%14s\t%10s\n", "--------", "------", "-----", "---------", "---------",
                "-------");

    constexpr std::size_t ITERS = 200; // each iteration is a full 8 MiB scan
    for (const auto &s : scenarios)
    {
        run_scenario(s, buffer, ITERS, SAMPLES);
    }

    // Touch the sink so it can never be optimized away.
    std::printf("\n(sink=%llu)\n", static_cast<unsigned long long>(s_sink.load(std::memory_order_relaxed)));
    return 0;
}
