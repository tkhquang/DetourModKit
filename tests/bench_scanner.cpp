/**
 * @file bench_scanner.cpp
 * @brief Standalone microbenchmark harness for detail::find_pattern.
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

#include "DetourModKit/scan.hpp"
#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <span>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "DetourModKit/memory.hpp"

namespace
{
    using Clock = std::chrono::steady_clock;
    using DetourModKit::detail::EnginePattern;

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

        std::mt19937_64 rng(seed);
        std::uniform_real_distribution<double> prob(0.0, 1.0);
        std::uniform_int_distribution<int> uniform_byte(0, 255);

        std::vector<std::byte> out(size_bytes);
        for (std::size_t i = 0; i < size_bytes; ++i)
        {
            const double p = prob(rng);
            double accum = 0.0;
            std::uint8_t chosen = static_cast<std::uint8_t>(uniform_byte(rng));
            for (const auto &h : hot_bytes)
            {
                accum += h.weight;
                if (p < accum / hot_total)
                {
                    chosen = h.value;
                    break;
                }
            }
            out[i] = std::byte{chosen};
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

    std::array<std::byte, 16> make_resolver_signature(std::uint32_t seed) noexcept
    {
        std::array<std::byte, 16> sig{};
        std::uint32_t state = 0xA5A55A5Au ^ (seed * 0x9E3779B1u);
        for (std::byte &b : sig)
        {
            state = state * 1664525u + 1013904223u;
            b = std::byte{static_cast<std::uint8_t>((state >> 24) & 0xFFu)};
        }
        return sig;
    }

    std::string bytes_to_aob(std::span<const std::byte> bytes)
    {
        constexpr char digits[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(bytes.size() * 3);
        for (const std::byte b : bytes)
        {
            const auto value = std::to_integer<unsigned>(b);
            out.push_back(digits[(value >> 4) & 0xFu]);
            out.push_back(digits[value & 0xFu]);
            out.push_back(' ');
        }
        return out;
    }

    class BenchPage
    {
    public:
        explicit BenchPage(std::size_t bytes)
            : m_base(VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)), m_size(bytes)
        {
        }

        ~BenchPage()
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        BenchPage(const BenchPage &) = delete;
        BenchPage &operator=(const BenchPage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        [[nodiscard]] std::byte *bytes() const noexcept { return static_cast<std::byte *>(m_base); }

        [[nodiscard]] std::size_t size() const noexcept { return m_size; }

        [[nodiscard]] DetourModKit::detail::ModuleSpan range() const noexcept
        {
            const auto base = reinterpret_cast<std::uintptr_t>(m_base);
            return DetourModKit::detail::ModuleSpan{base, base + m_size};
        }

    private:
        void *m_base = nullptr;
        std::size_t m_size = 0;
    };

    // Build an EnginePattern whose anchor is forced to the first literal byte. This emulates the simpler scanner: it
    // always anchors on the start of the pattern (after skipping leading wildcards), rather than on the rarest literal.
    EnginePattern make_naive_pattern(const EnginePattern &smart)
    {
        EnginePattern copy = smart;
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
        auto parsed = DetourModKit::detail::parse_aob(scenario.aob);
        if (!parsed.has_value())
        {
            std::fprintf(stderr, "[bench] failed to parse AOB: %s\n", scenario.aob);
            return;
        }
        const EnginePattern smart = std::move(*parsed);
        const EnginePattern naive = make_naive_pattern(smart);

        // Sanity check: warm up + assert both anchors point at literal bytes.
        const auto *warm_smart = DetourModKit::detail::find_pattern(buffer.data(), buffer.size(), smart);
        const auto *warm_naive = DetourModKit::detail::find_pattern(buffer.data(), buffer.size(), naive);
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
                                       DetourModKit::detail::find_pattern(buffer.data(), buffer.size(), smart);
                                   s_sink.fetch_add(reinterpret_cast<std::uintptr_t>(m), std::memory_order_relaxed);
                               });

        const double us_naive =
            median_us_per_iter(iterations, samples,
                               [&]()
                               {
                                   const auto *m =
                                       DetourModKit::detail::find_pattern(buffer.data(), buffer.size(), naive);
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

    // Prefilter isolation: measure the dmk_memchr sweep on its own. A sentinel byte is scrubbed out of the whole
    // buffer and re-planted exactly once near the end, so find_pattern does a single full-buffer prefilter sweep
    // followed by one verify -- the measured wall time is the prefilter's, not the verify tier's. libc memchr over the
    // same buffer is the reference bar: the no-regression half of the gate is "not slower than the libc memchr the
    // earlier libc-backed scanner used", and the SIMD tier must beat the scalar/SWAR build by >= 1.5x. The production
    // scanner never calls libc memchr (it would re-arm the AddressSanitizer interceptor the self-provided dmk_memchr
    // exists to avoid); this row exists only to anchor the comparison.
    void run_prefilter_bench(std::size_t buffer_size, std::uint64_t seed, std::size_t iterations, std::size_t samples)
    {
        constexpr std::uint8_t SENTINEL = 0x37;
        auto buffer = make_codelike_buffer(buffer_size, seed);
        // Scrub every naturally-occurring sentinel; replace it with a common opcode so the distribution stays
        // code-like. After the scrub the only sentinel is the one planted below, so the anchor byte is unique and the
        // sweep walks the whole buffer in one dmk_memchr call.
        for (auto &b : buffer)
        {
            if (b == std::byte{SENTINEL})
            {
                b = std::byte{0x90};
            }
        }
        const std::size_t plant_offset = buffer_size - 4096u;
        plant_signature(buffer, plant_offset, {SENTINEL, 0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0x1D, 0xF0});

        auto parsed = DetourModKit::detail::parse_aob("37 DE AD BE EF C0 1D F0");
        if (!parsed.has_value())
        {
            std::fprintf(stderr, "[bench] prefilter AOB parse failed\n");
            return;
        }
        const EnginePattern pattern = std::move(*parsed);

        const auto *warm = DetourModKit::detail::find_pattern(buffer.data(), buffer.size(), pattern);
        if (warm == nullptr)
        {
            std::fprintf(stderr, "[bench] prefilter signature not found\n");
            return;
        }
        s_sink.fetch_add(reinterpret_cast<std::uintptr_t>(warm), std::memory_order_relaxed);

        const double us_scanner =
            median_us_per_iter(iterations, samples,
                               [&]()
                               {
                                   const auto *m =
                                       DetourModKit::detail::find_pattern(buffer.data(), buffer.size(), pattern);
                                   s_sink.fetch_add(reinterpret_cast<std::uintptr_t>(m), std::memory_order_relaxed);
                               });

        const double us_libc =
            median_us_per_iter(iterations, samples,
                               [&]()
                               {
                                   const void *m = std::memchr(buffer.data(), SENTINEL, buffer.size());
                                   s_sink.fetch_add(reinterpret_cast<std::uintptr_t>(m), std::memory_order_relaxed);
                               });

        const double bytes = static_cast<double>(buffer_size);
        const auto gib_per_s = [bytes](double us) { return bytes / (us * 1.0e-6) / (1024.0 * 1024.0 * 1024.0); };

        std::printf("\nPrefilter sweep (dmk_memchr isolation, %zu MiB buffer, unique sentinel anchor)\n",
                    buffer_size / (1024u * 1024u));
        std::printf("%-22s\t%12s\t%12s\n", "impl", "median_us", "GiB/s");
        std::printf("%-22s\t%12.3f\t%12.2f\n", "dmk_memchr (scanner)", us_scanner, gib_per_s(us_scanner));
        std::printf("%-22s\t%12.3f\t%12.2f\n", "libc memchr (ref)", us_libc, gib_per_s(us_libc));
        std::printf("dmk/libc throughput ratio: %.2fx (>= 1.00x means no regression below libc)\n",
                    us_libc / us_scanner);
    }

    /// Returns the human-readable name of the SIMD verify tier find_pattern selects at runtime.
    const char *active_simd_tier_name()
    {
        switch (DetourModKit::detail::active_simd_level())
        {
        case DetourModKit::scan::SimdLevel::Avx512:
            return "AVX-512";
        case DetourModKit::scan::SimdLevel::Avx2:
            return "AVX2";
        case DetourModKit::scan::SimdLevel::Sse2:
            return "SSE2";
        case DetourModKit::scan::SimdLevel::Scalar:
            return "Scalar";
        }
        return "?";
    }

    // Verify-throughput isolation for the SIMD verify tiers -- the AVX-512 throughput gate harness. The buffer is a
    // long run of one byte with a different byte sprinkled in at a fixed stride, and the pattern is a long all-literal
    // run of the majority byte (stride < pattern_len so no position ever fully matches). Every position is an anchor
    // hit, so the prefilter returns immediately and each candidate's verify proceeds through several SIMD chunks before
    // it reaches the next sprinkled byte -- the scan is dominated by deep per-candidate verification, not the
    // prefilter. On an AVX-512 build the 64-byte verify body runs; comparing this throughput between an AVX-512 build
    // and an AVX2 build on the same AVX-512 host is the verify tier's >= 30% throughput gate (see the avx512 CI
    // workflow). On a host without AVX-512 it measures the AVX2 tier, which is the fallback the AVX-512 build also uses
    // there.
    void run_verify_bench(std::size_t buffer_size, std::size_t pattern_len, std::size_t stride, std::size_t iterations,
                          std::size_t samples)
    {
        constexpr std::uint8_t MAJORITY = 0xAA;
        constexpr std::uint8_t BREAK = 0xBB;
        std::vector<std::byte> buffer(buffer_size, std::byte{MAJORITY});
        for (std::size_t i = stride; i < buffer_size; i += stride)
        {
            buffer[i] = std::byte{BREAK};
        }

        std::string aob;
        aob.reserve(pattern_len * 3);
        for (std::size_t i = 0; i < pattern_len; ++i)
        {
            aob += "AA ";
        }
        auto parsed = DetourModKit::detail::parse_aob(aob);
        if (!parsed.has_value())
        {
            std::fprintf(stderr, "[bench] verify AOB parse failed\n");
            return;
        }
        const EnginePattern pattern = std::move(*parsed);

        const double us =
            median_us_per_iter(iterations, samples,
                               [&]()
                               {
                                   const auto *m =
                                       DetourModKit::detail::find_pattern(buffer.data(), buffer.size(), pattern);
                                   s_sink.fetch_add(reinterpret_cast<std::uintptr_t>(m), std::memory_order_relaxed);
                               });

        const double bytes = static_cast<double>(buffer_size);
        const double gib_per_s = bytes / (us * 1.0e-6) / (1024.0 * 1024.0 * 1024.0);
        std::printf("\nVerify throughput (deep verify, %zu-byte literal pattern, break stride %zu, %zu MiB buffer)\n",
                    pattern_len, stride, buffer_size / (1024u * 1024u));
        std::printf("%-22s\t%12s\t%12s\n", "tier", "median_us", "GiB/s");
        std::printf("%-22s\t%12.3f\t%12.2f\n", active_simd_tier_name(), us, gib_per_s);
        // Machine-readable verify-throughput line for the >= 30% AVX-512-vs-AVX2 gate: on a real AVX-512 host a
        // tier-enabled build and an AVX2 baseline build are compared and the ratio must clear the bar.
        std::printf("#GATE\tverify_gib_per_s\t%.4f\t%s\n", gib_per_s, active_simd_tier_name());
    }

    void run_resolver_batch_bench(std::size_t module_size, std::size_t target_count, std::size_t iterations,
                                  std::size_t samples, std::size_t max_workers)
    {
        using namespace DetourModKit;

        BenchPage page(module_size);
        if (!page.ok())
        {
            std::fprintf(stderr, "[bench] resolver page allocation failed\n");
            return;
        }
        std::memset(page.bytes(), 0xCC, page.size());

        // OwnedScanRequest owns ladder + label, so the spans stay valid for the lifetime of the bench.
        std::vector<scan::OwnedScanRequest> owned(target_count);
        std::vector<std::uintptr_t> expected(target_count, 0);

        const detail::ModuleSpan mod_range = page.range();
        const Region mod_region{Address{mod_range.base}, mod_range.end - mod_range.base};
        const std::size_t spacing = (module_size - 8192u) / target_count;
        for (std::size_t i = 0; i < target_count; ++i)
        {
            const auto sig = make_resolver_signature(static_cast<std::uint32_t>(5000 + i));
            const std::size_t offset = 4096u + i * spacing;
            std::memcpy(page.bytes() + offset, sig.data(), sig.size());
            expected[i] = reinterpret_cast<std::uintptr_t>(page.bytes() + offset);
            const std::string aob = bytes_to_aob(sig);
            auto pat = scan::Pattern::compile(aob);
            if (!pat.has_value())
            {
                std::fprintf(stderr, "[bench] failed to compile pattern for resolver_%zu\n", i);
                return;
            }
            owned[i].label = "resolver_" + std::to_string(i);
            owned[i].ladder.push_back(scan::Candidate::direct(owned[i].label, std::move(*pat)));
            owned[i].scope = mod_region;
        }

        // Build a vector of borrowed ScanRequests for resolve_batch.
        std::vector<scan::ScanRequest> requests;
        requests.reserve(target_count);
        for (auto &o : owned)
        {
            requests.push_back(o.view());
        }

        for (std::size_t i = 0; i < target_count; ++i)
        {
            const auto serial = scan::resolve(requests[i]);
            if (!serial || serial->address.raw() != expected[i])
            {
                std::fprintf(stderr, "[bench] resolver serial sanity failed at item %zu\n", i);
                return;
            }
        }

        const auto warm_batch = scan::resolve_batch(std::span{requests}, max_workers);
        if (warm_batch.size() != target_count)
        {
            std::fprintf(stderr, "[bench] resolver batch sanity returned wrong size\n");
            return;
        }
        for (std::size_t i = 0; i < target_count; ++i)
        {
            if (!warm_batch[i] || warm_batch[i]->address.raw() != expected[i])
            {
                std::fprintf(stderr, "[bench] resolver batch sanity failed at item %zu\n", i);
                return;
            }
            s_sink.fetch_add(warm_batch[i]->address.raw(), std::memory_order_relaxed);
        }

        const double us_serial =
            median_us_per_iter(iterations, samples,
                               [&]()
                               {
                                   for (const auto &request : requests)
                                   {
                                       const auto hit = scan::resolve(request);
                                       s_sink.fetch_add(hit ? hit->address.raw() : 0, std::memory_order_relaxed);
                                   }
                               });

        const double us_batch =
            median_us_per_iter(iterations, samples,
                               [&]()
                               {
                                   const auto results = scan::resolve_batch(std::span{requests}, max_workers);
                                   for (std::size_t ri = 0; ri < results.size(); ++ri)
                                   {
                                       const auto &hit = results[ri];
                                       s_sink.fetch_add(hit ? hit->address.raw() : 0, std::memory_order_relaxed);
                                   }
                               });

        std::printf("\nStartup resolver batch (%zu module-scoped cascades, %zu MiB module, %zu workers)\n",
                    target_count, module_size / (1024u * 1024u), max_workers);
        std::printf("%-22s\t%12s\t%12s\t%12s\n", "mode", "median_us", "targets/s", "speedup");
        std::printf("%-22s\t%12.3f\t%12.1f\t%12.2f\n", "serial", us_serial,
                    static_cast<double>(target_count) * 1.0e6 / us_serial, 1.0);
        std::printf("%-22s\t%12.3f\t%12.1f\t%12.2f\n", "batch", us_batch,
                    static_cast<double>(target_count) * 1.0e6 / us_batch, us_serial / us_batch);
    }
} // namespace

int main(int argc, char **argv)
{
    // Instruction-count proxy mode (run under Intel SDE's -mix). A real wall-clock verify-throughput comparison needs
    // AVX-512 silicon; without it SDE timing is meaningless. What SDE can measure hardware-independently is the
    // executed instruction count, so this mode runs a single deep-verify pass over a small buffer -- skipping the
    // timing-driven full suite, which is far too heavy under -mix -- and exits. Run it under -spr (Sapphire Rapids
    // selects the AVX-512 verify tier) and -hsw (Haswell selects AVX2) and compare the counts: the 64-byte AVX-512
    // verify body should execute materially fewer instructions than the 32-byte AVX2 body for the same work. This is a
    // proxy for work performed, not wall-clock throughput (zmm downclock and port pressure can make fewer instructions
    // slower on real silicon).
    if (argc > 1 && std::strcmp(argv[1], "--verify-icount") == 0)
    {
        constexpr std::size_t ICOUNT_BUFFER = 1u * 1024u * 1024u;
        constexpr std::size_t ICOUNT_PATTERN_LEN = 96;
        constexpr std::size_t ICOUNT_STRIDE = 64;
        run_verify_bench(ICOUNT_BUFFER, ICOUNT_PATTERN_LEN, ICOUNT_STRIDE, 1, 1);
        return 0;
    }

    constexpr std::size_t BUFFER_SIZE = 8u * 1024u * 1024u; // 8 MiB
    constexpr std::uint64_t SEED = 0xD37011CDull;
    constexpr std::size_t SAMPLES = 11;

    std::printf("DetourModKit Scanner microbenchmark\n");
    std::printf("Buffer: %zu bytes (code-like byte distribution, seed 0x%llx)\n", BUFFER_SIZE,
                static_cast<unsigned long long>(SEED));
    std::printf("SIMD tier: ");
    switch (DetourModKit::detail::active_simd_level())
    {
    case DetourModKit::scan::SimdLevel::Avx512:
        std::printf("AVX-512\n");
        break;
    case DetourModKit::scan::SimdLevel::Avx2:
        std::printf("AVX2\n");
        break;
    case DetourModKit::scan::SimdLevel::Sse2:
        std::printf("SSE2\n");
        break;
    case DetourModKit::scan::SimdLevel::Scalar:
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

    // Scenarios. Each runs the planted buffer through both anchor variants of the same find_pattern code path.
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

    // Prefilter-bound isolation on a larger buffer so the dmk_memchr sweep dominates and per-call overhead is
    // amortized. This isolates the prefilter so a SIMD prefilter change can be gated against the scalar/SWAR baseline
    // and the libc reference.
    constexpr std::size_t PREFILTER_BUFFER = 64u * 1024u * 1024u;
    constexpr std::size_t PREFILTER_ITERS = 20;
    run_prefilter_bench(PREFILTER_BUFFER, SEED, PREFILTER_ITERS, SAMPLES);

    // Verify-throughput isolation (AVX-512 throughput gate harness). Every byte is an anchor hit so verify dominates;
    // the 96-byte literal pattern and 64-byte break stride make each candidate cover one-plus full 64-byte chunk.
    constexpr std::size_t VERIFY_BUFFER = 2u * 1024u * 1024u;
    constexpr std::size_t VERIFY_PATTERN_LEN = 96;
    constexpr std::size_t VERIFY_STRIDE = 64;
    constexpr std::size_t VERIFY_ITERS = 10;
    run_verify_bench(VERIFY_BUFFER, VERIFY_PATTERN_LEN, VERIFY_STRIDE, VERIFY_ITERS, SAMPLES);

    // Startup-resolution layer benchmark. This times the consumer-facing ladder resolver instead of the raw
    // EnginePattern batch, preserving per-target candidate order and uniqueness checks.
    constexpr std::size_t RESOLVER_MODULE = 8u * 1024u * 1024u;
    constexpr std::size_t RESOLVER_TARGETS = 16;
    constexpr std::size_t RESOLVER_ITERS = 5;
    constexpr std::size_t RESOLVER_WORKERS = 4;
    run_resolver_batch_bench(RESOLVER_MODULE, RESOLVER_TARGETS, RESOLVER_ITERS, SAMPLES, RESOLVER_WORKERS);

    // Touch the sink so it can never be optimized away.
    std::printf("\n(sink=%llu)\n", static_cast<unsigned long long>(s_sink.load(std::memory_order_relaxed)));
    return 0;
}
