# Scanner microbenchmark: rare-byte anchor vs first-literal anchor

This directory captures the result of running `tests/bench_scanner.cpp` against the production `Scanner::find_pattern` implementation. The benchmark compares two anchor strategies in the same scan loop, so every other factor (memchr, SIMD verify, SSE2/AVX2 tier selection) stays constant. The only thing that changes between the two runs is the value stored in `CompiledPattern::anchor`:

- **smart**: produced by `parse_aob()` and `compile_anchor()`. Walks the literal bytes, scores each against a small byte-frequency table, and stores the rarest byte's index. This is the production behaviour.
- **naive**: produced by `make_naive_pattern()` in the benchmark harness. Sets `CompiledPattern::anchor` to the first literal byte's index, emulating the strategy of simpler scanners (such as the Witcher 3 mod scanner discussed in [Otis Inf's blog](https://opmtools.tumblr.com/post/798692655715287040/the-witcher-3-cinematic-tools-1322-15-mods)) that anchor unconditionally on `pattern[0]`.

The buffer is 8 MiB of synthetic bytes drawn from a distribution tuned to typical x64 PE `.text` frequencies: 0x48, 0x8B, 0xFF, 0xCC, 0x00, 0x90, 0x0F, 0xE8, 0x89, 0xE9, 0x83, 0xC3 are over-represented; everything else is uniform. Same fixed seed (`0xD37011CD`) every run.

## Hardware / configuration

- Build: `cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON`
- Toolchain: GCC 15.1 (MSYS2 MinGW-w64) with `-O3` and LTO
- SIMD tier: AVX2 (runtime-detected)
- Iterations: 200 full-buffer scans per sample
- Samples: 11; median reported

## Results

```text
scenario                          anchor   iters    median_us     scans/sec    speedup
common_first_rare_buried_8        smart      200      409.214        2443.7      1.00x
common_first_rare_buried_8        naive      200     7244.500         138.0      0.06x
common_first_rare_buried_8        ratio      200            -             -     17.70x
common_first_rare_buried_16       smart      200      462.594        2161.7      1.00x
common_first_rare_buried_16       naive      200     6912.899         144.7      0.07x
common_first_rare_buried_16       ratio      200            -             -     14.94x
all_common_first_no_match         smart      200      467.025        2141.2      1.00x
all_common_first_no_match         naive      200     8392.462         119.2      0.06x
all_common_first_no_match         ratio      200            -             -     17.97x
rare_first_short_no_match         smart      200      467.646        2138.4      1.00x
rare_first_short_no_match         naive      200      485.314        2060.5      0.96x
rare_first_short_no_match         ratio      200            -             -      1.04x
long_mostly_wildcards             smart      200      451.193        2216.3      1.00x
long_mostly_wildcards             naive      200     6975.918         143.4      0.06x
long_mostly_wildcards             ratio      200            -             -     15.46x
verify_heavy_32B_match            smart      200      438.560        2280.2      1.00x
verify_heavy_32B_match            naive      200     6328.513         158.0      0.07x
verify_heavy_32B_match            ratio      200            -             -     14.43x
```

## How to read this

| Scenario | Pattern shape | Smart anchor lands on | Naive anchor lands on | Speedup |
|----------|---------------|-----------------------|-----------------------|---------|
| `common_first_rare_buried_8` | `48 8B 05 37 DE AD BE EF` | `0x37` (index 3) | `0x48` (index 0) | **17.7x** |
| `common_first_rare_buried_16` | `48 8B 05 37 DE AD BE EF 90 90 CC CC E8 ?? ?? ??` | `0x37` (index 3) | `0x48` (index 0) | **14.9x** |
| `all_common_first_no_match` | `48 8B 05 89 0F E8 90 CC` (no match present) | `0xCC` (lowest score in this set, still common) | `0x48` (index 0) | **18.0x** |
| `rare_first_short_no_match` | `37 6B C1 BA 5E 71` (no match present) | `0x37` (index 0) | `0x37` (index 0) | **1.04x** (identical within noise) |
| `long_mostly_wildcards` | `48 8B 05 ?? ?? ?? ?? 48 89 ?? ?? ?? ?? 37 DE AD` | `0x37` (index 13) | `0x48` (index 0) | **15.5x** |
| `verify_heavy_32B_match` | 32-byte pattern starting with `48 8B 05 37 ...` | `0x37` (index 3) | `0x48` (index 0) | **14.4x** |

A few takeaways:

1. **The anchor choice dominates scan time.** Every false anchor hit costs a SIMD verify, and `0x48` matches roughly 12% of bytes in real x64 `.text` whereas `0x37` matches well under 0.5%. The 14x to 18x ratios shown above are the false-anchor-hit ratio playing out as wall-clock time after the SIMD prefilter lowers both paths' sweep cost.
2. **The verify tier (AVX2 vs scalar) is almost irrelevant to this comparison.** Both runs use the same AVX2 verify path; what differs is how often that path is invoked. Moving from scalar to AVX2 inside the verify might save another 30% on each verify, but the rare-byte anchor saves an order of magnitude on the *number* of verifies. The smart-anchor path is so dominated by the memchr sweep that pattern size barely affects the result (409 to 468 microseconds across all six smart-anchor runs).
3. **There is no downside on rare-first patterns.** When the pattern already begins with an uncommon byte (the `rare_first_short_no_match` row), both strategies behave identically (within 1% noise). The smart heuristic does not regress in this case because `compile_anchor()` picks the same index the naive strategy would have picked.
4. **Manually constructed patterns still pay nothing.** `find_pattern()` falls back to inline anchor selection when `CompiledPattern::anchor` is the sentinel; the only cost is a single O(pattern.size()) walk on the first scan. Sub-microsecond on a 16-byte pattern.

## Reproducing locally

```bash
# from repo root, in MSYS2 MinGW shell
PATH="/c/msys64/mingw64/bin:$PATH" cmake -S . -B build/mingw-release \
    -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-release \
    --target DetourModKit_bench_scanner --parallel
./build/mingw-release/tests/DetourModKit_bench_scanner.exe
```

The buffer seed is hard-coded so the byte distribution is byte-identical across runs. Variation between runs is therefore purely scheduler / cache noise; the 11-sample median is stable to within roughly 5%.

## Prefilter throughput (SIMD memchr)

`bench_scanner.cpp` also reports a dedicated prefilter-isolation sweep: it scrubs a sentinel byte out of a 64 MiB code-like buffer and re-plants it once near the end, so `find_pattern` does a single full-buffer `dmk_memchr` sweep with one trailing verify and the measured wall time is the prefilter's. `libc memchr` over the same buffer is the reference bar. The production scanner never calls `libc memchr` -- the AddressSanitizer interceptor would fault on the scanner's in-bounds reads of this process's own poisoned shadow -- so the self-provided `dmk_memchr` does its own byte comparisons; that row exists only to anchor the comparison.

The prefilter is tiered like the verify: a runtime AVX2 body (32 bytes/iteration) over an SSE2 baseline (16 bytes/iteration), with a scalar tail. Example AVX2 result from the same benchmark host:

```text
impl                     median_us         GiB/s
dmk_memchr (scalar)       32614.8           1.92
dmk_memchr (SIMD AVX2)     3218.425        19.42
libc memchr (ref)          3928.470        15.91
```

The SIMD prefilter is roughly 10.1x faster than the scalar baseline and 1.22x faster than `libc memchr` (which is itself vectorized inside the CRT), so the self-provided prefilter is no longer the large-haystack throughput compromise it was when it dropped to a scalar loop for ASan-interceptor immunity. The gate for landing the SIMD tier was exactly this: beat the scalar baseline by >= 1.5x and never regress below the `libc memchr` the pre-self-provided scanner used.

## AVX-512 verify gate

The bench also includes a deep-verify scenario for the AVX-512 verify-throughput gate. The buffer is a 2 MiB run of one byte with a different byte at a fixed stride; every position is an anchor hit, so the scanner is dominated by pattern verification instead of the prefilter. A `DMK_ENABLE_AVX512=ON` build reports the active tier in the human table and emits a machine-readable line for CI.

On a host without AVX-512F+BW and OS-enabled ZMM/opmask state, the runtime gate must fall back to AVX2:

```text
tier                   median_us         GiB/s
AVX2                   13899.640          0.14
#GATE  verify_gib_per_s  0.1405  AVX2
```

On a real AVX-512 host this row is compared between a tier-enabled build and an AVX2 baseline build on the same machine, with `1.30x` as the acceptance bar. Intel SDE is used only for correctness because its timing is not representative of real silicon.

## Caveats

- The byte distribution is synthetic. Real binaries vary; a `.text` section that uses unusual instruction selection (heavy AVX, lots of EVEX prefixes) will have different ratios. The qualitative result (rare anchor wins big) should hold across any realistic distribution, but the exact speedup will move.
- The benchmark deliberately compares two strategies that share the same SIMD verify path. It is NOT a comparison against scanners that use a different verify (Otis Inf's scanner uses an 8-byte uint64 XOR/AND verify, which is somewhere between our scalar tail and our SSE2 path). The conclusion that "rare-byte anchor produces 5x to 30x speedup" applies to anchor selection in general, not to any specific scanner implementation.
- Microbenchmarks measure cold or warm cache state depending on the buffer fitting in L2/L3. At 8 MiB the buffer mostly misses L2 (32 MiB L3 on most modern Intel chips will hold it), so this approximates a "warm L3, cold L1/L2" workload. Real game-mod scans typically run over multi-megabyte module images, so the workload is representative.
