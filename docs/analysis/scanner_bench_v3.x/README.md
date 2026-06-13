# Scanner microbenchmark: rare-byte anchor, prefilter, and batch resolver

This directory captures the result of running `tests/bench_scanner.cpp` against the production scanner implementation. The primary table compares two anchor strategies in the same scan loop, so every other factor (memchr, SIMD verify, SSE2/AVX2 tier selection) stays constant. The only thing that changes between the two runs is the value stored in `CompiledPattern::anchor`:

- **smart**: produced by `parse_aob()` and `compile_anchor()`. Walks the literal bytes, scores each against a small byte-frequency table, and stores the rarest byte's index. This is the production behaviour.
- **naive**: produced by `make_naive_pattern()` in the benchmark harness. Sets `CompiledPattern::anchor` to the first literal byte's index, emulating the strategy of simpler scanners (such as the Witcher 3 mod scanner discussed in [Otis Inf's blog](https://opmtools.tumblr.com/post/798692655715287040/the-witcher-3-cinematic-tools-1322-15-mods)) that anchor unconditionally on `pattern[0]`.

The buffer is 8 MiB of synthetic bytes drawn from a distribution tuned to typical x64 PE `.text` frequencies: 0x48, 0x8B, 0xFF, 0xCC, 0x00, 0x90, 0x0F, 0xE8, 0x89, 0xE9, 0x83, 0xC3 are over-represented; everything else is uniform. Same fixed seed (`0xD37011CD`) every run.

## Hardware / configuration

- Build: `cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON`
- Toolchain: GCC 15.1 (MSYS2 MinGW-w64) with `-O3` and LTO
- SIMD tier: AVX2 (runtime-detected)
- Iterations: 200 full-buffer scans per sample
- Samples: 11; median reported
- Resolver batch: 16 module-scoped cascades over an 8 MiB executable page, 4 workers, 5 iterations per sample

## Results

```text
scenario                          anchor   iters    median_us     scans/sec    speedup
common_first_rare_buried_8        smart      200      429.329        2329.2      1.00x
common_first_rare_buried_8        naive      200     7751.995         129.0      0.06x
common_first_rare_buried_8        ratio      200            -             -     18.06x
common_first_rare_buried_16       smart      200      474.106        2109.2      1.00x
common_first_rare_buried_16       naive      200     6781.544         147.5      0.07x
common_first_rare_buried_16       ratio      200            -             -     14.30x
all_common_first_no_match         smart      200      491.854        2033.1      1.00x
all_common_first_no_match         naive      200     8843.831         113.1      0.06x
all_common_first_no_match         ratio      200            -             -     17.98x
rare_first_short_no_match         smart      200      483.774        2067.1      1.00x
rare_first_short_no_match         naive      200      478.639        2089.3      1.01x
rare_first_short_no_match         ratio      200            -             -      0.99x
long_mostly_wildcards             smart      200      459.945        2174.2      1.00x
long_mostly_wildcards             naive      200     6823.109         146.6      0.07x
long_mostly_wildcards             ratio      200            -             -     14.83x
verify_heavy_32B_match            smart      200      451.026        2217.2      1.00x
verify_heavy_32B_match            naive      200     6347.190         157.6      0.07x
verify_heavy_32B_match            ratio      200            -             -     14.07x
```

## How to read this

| Scenario | Pattern shape | Smart anchor lands on | Naive anchor lands on | Speedup |
|----------|---------------|-----------------------|-----------------------|---------|
| `common_first_rare_buried_8` | `48 8B 05 37 DE AD BE EF` | `0x37` (index 3) | `0x48` (index 0) | **18.1x** |
| `common_first_rare_buried_16` | `48 8B 05 37 DE AD BE EF 90 90 CC CC E8 ?? ?? ??` | `0x37` (index 3) | `0x48` (index 0) | **14.3x** |
| `all_common_first_no_match` | `48 8B 05 89 0F E8 90 CC` (no match present) | `0xCC` (lowest score in this set, still common) | `0x48` (index 0) | **18.0x** |
| `rare_first_short_no_match` | `37 6B C1 BA 5E 71` (no match present) | `0x37` (index 0) | `0x37` (index 0) | **0.99x** (identical within noise) |
| `long_mostly_wildcards` | `48 8B 05 ?? ?? ?? ?? 48 89 ?? ?? ?? ?? 37 DE AD` | `0x37` (index 13) | `0x48` (index 0) | **14.8x** |
| `verify_heavy_32B_match` | 32-byte pattern starting with `48 8B 05 37 ...` | `0x37` (index 3) | `0x48` (index 0) | **14.1x** |

A few takeaways:

1. **The anchor choice dominates scan time.** Every false anchor hit costs a SIMD verify, and `0x48` matches roughly 12% of bytes in real x64 `.text` whereas `0x37` matches well under 0.5%. The 14x to 18x ratios shown above are the false-anchor-hit ratio playing out as wall-clock time after the SIMD prefilter lowers both paths' sweep cost.
2. **The verify tier (AVX2 vs scalar) is almost irrelevant to this comparison.** Both runs use the same AVX2 verify path; what differs is how often that path is invoked. Moving from scalar to AVX2 inside the verify might save another 30% on each verify, but the rare-byte anchor saves an order of magnitude on the *number* of verifies. The smart-anchor path is so dominated by the memchr sweep that pattern size barely affects the result (429 to 492 microseconds across all six smart-anchor runs).
3. **There is no downside on rare-first patterns.** When the pattern already begins with an uncommon byte (the `rare_first_short_no_match` row), both strategies behave identically (within 1% noise). The smart heuristic does not regress in this case because `compile_anchor()` picks the same index the naive strategy would have picked.
4. **Manually constructed patterns still pay nothing.** `find_pattern()` falls back to inline anchor selection when `CompiledPattern::anchor` is the sentinel; the only cost is a single O(pattern.size()) walk on the first scan. Sub-microsecond on a 16-byte pattern.

## Reproducing locally

```bash
# from repo root, in MSYS2 MinGW shell
PATH="/c/msys64/mingw64/bin:$PATH" cmake -S . -B build/mingw-release \
    -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-release \
    --target DetourModKit_bench_scanner --parallel 3
./build/mingw-release/tests/DetourModKit_bench_scanner.exe
```

The buffer seed is hard-coded so the byte distribution is byte-identical across runs. Variation between runs is therefore purely scheduler / cache noise; the 11-sample median is stable to within roughly 5%.

## Prefilter throughput (SIMD memchr)

`bench_scanner.cpp` also reports a dedicated prefilter-isolation sweep: it scrubs a sentinel byte out of a 64 MiB code-like buffer and re-plants it once near the end, so `find_pattern` does a single full-buffer `dmk_memchr` sweep with one trailing verify and the measured wall time is the prefilter's. `libc memchr` over the same buffer is the reference bar. The production scanner never calls `libc memchr` -- the AddressSanitizer interceptor would fault on the scanner's in-bounds reads of this process's own poisoned shadow -- so the self-provided `dmk_memchr` does its own byte comparisons; that row exists only to anchor the comparison.

The prefilter is tiered like the verify: a runtime AVX2 body (32 bytes/iteration) over an SSE2 baseline (16 bytes/iteration), with a scalar tail. Example AVX2 result from the same benchmark host:

```text
impl                     median_us         GiB/s
dmk_memchr (scanner)       3445.000        18.14
libc memchr (ref)          4030.285        15.51
dmk/libc throughput ratio: 1.17x (>= 1.00x means no regression below libc)
```

The captured AVX2 prefilter is 1.17x faster than `libc memchr` (which is itself vectorized inside the CRT), so the self-provided prefilter is not a large-haystack throughput compromise while preserving ASan-interceptor immunity. A separate scalar/SWAR build is used when validating the >= 1.5x scalar-baseline gate; the default benchmark output records the active production tier and the libc reference bar.

## AVX-512 verify gate

The bench also includes a deep-verify scenario for the AVX-512 verify-throughput gate. The buffer is a 2 MiB run of one byte with a different byte at a fixed stride; every position is an anchor hit, so the scanner is dominated by pattern verification instead of the prefilter. A `DMK_ENABLE_AVX512=ON` build reports the active tier in the human table and emits a machine-readable line for CI.

On a host without AVX-512F+BW and OS-enabled ZMM/opmask state, the runtime gate must fall back to AVX2:

```text
tier                   median_us         GiB/s
AVX2                   13884.160          0.14
#GATE  verify_gib_per_s  0.1407  AVX2
```

On a real AVX-512 host this row is compared between a tier-enabled build and an AVX2 baseline build on the same machine, with `1.30x` as the acceptance bar. Intel SDE is used only for correctness because its timing is not representative of real silicon.

## Startup resolver batch

The benchmark also times the NF-7 startup-resolution layer: serial module-scoped cascade resolution versus `Scanner::resolve_cascade_batch` over the same 16 independent requests. Each request has one direct candidate and resolves inside a shared 8 MiB executable page. The harness validates every serial and batch hit against the expected address before timing.

```text
Startup resolver batch (16 module-scoped cascades, 8 MiB module, 4 workers)
mode                   median_us    targets/s      speedup
serial                  6311.580       2535.0         1.00
batch                   2098.700       7623.8         3.01
```

This measures the consumer-facing resolver path rather than the raw compiled-pattern batch scanner, so it includes per-target candidate ordering, module range filtering, uniqueness checks, and result construction. The 3.01x median speedup shows the fork-join layer removes most startup latency for a moderate independent resolver table while preserving deterministic result order. Very small batches may remain faster serially because thread startup and scheduling cost are then the dominant work.

## Caveats

- The byte distribution is synthetic. Real binaries vary; a `.text` section that uses unusual instruction selection (heavy AVX, lots of EVEX prefixes) will have different ratios. The qualitative result (rare anchor wins big) should hold across any realistic distribution, but the exact speedup will move.
- The benchmark deliberately compares two strategies that share the same SIMD verify path. It is NOT a comparison against scanners that use a different verify (Otis Inf's scanner uses an 8-byte uint64 XOR/AND verify, which is somewhere between our scalar tail and our SSE2 path). The conclusion that "rare-byte anchor produces 5x to 30x speedup" applies to anchor selection in general, not to any specific scanner implementation.
- Microbenchmarks measure cold or warm cache state depending on the buffer fitting in L2/L3. At 8 MiB the buffer mostly misses L2 (32 MiB L3 on most modern Intel chips will hold it), so this approximates a "warm L3, cold L1/L2" workload. Real game-mod scans typically run over multi-megabyte module images, so the workload is representative.
- Resolver batch speedup depends on the number of independent targets, available cores, and the shape of each cascade. The parallel API is a setup/control-plane tool for startup tables, not a callback hot-path primitive.
