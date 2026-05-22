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
common_first_rare_buried_8        smart      200      622.664        1606.0      1.00x
common_first_rare_buried_8        naive      200    14370.049          69.6      0.04x
common_first_rare_buried_8        ratio      200            -             -     23.08x
common_first_rare_buried_16       smart      200      553.646        1806.2      1.00x
common_first_rare_buried_16       naive      200    13910.845          71.9      0.04x
common_first_rare_buried_16       ratio      200            -             -     25.13x
all_common_first_no_match         smart      200      578.455        1728.7      1.00x
all_common_first_no_match         naive      200    16003.189          62.5      0.04x
all_common_first_no_match         ratio      200            -             -     27.67x
rare_first_short_no_match         smart      200      575.287        1738.3      1.00x
rare_first_short_no_match         naive      200      571.359        1750.2      1.01x
rare_first_short_no_match         ratio      200            -             -      0.99x
long_mostly_wildcards             smart      200      565.515        1768.3      1.00x
long_mostly_wildcards             naive      200    14037.218          71.2      0.04x
long_mostly_wildcards             ratio      200            -             -     24.82x
verify_heavy_32B_match            smart      200      564.149        1772.6      1.00x
verify_heavy_32B_match            naive      200    14176.547          70.5      0.04x
verify_heavy_32B_match            ratio      200            -             -     25.13x
```

## How to read this

| Scenario | Pattern shape | Smart anchor lands on | Naive anchor lands on | Speedup |
|----------|---------------|-----------------------|-----------------------|---------|
| `common_first_rare_buried_8` | `48 8B 05 37 DE AD BE EF` | `0x37` (index 3) | `0x48` (index 0) | **23.1x** |
| `common_first_rare_buried_16` | `48 8B 05 37 DE AD BE EF 90 90 CC CC E8 ?? ?? ??` | `0x37` (index 3) | `0x48` (index 0) | **25.1x** |
| `all_common_first_no_match` | `48 8B 05 89 0F E8 90 CC` (no match present) | `0xCC` (lowest score in this set, still common) | `0x48` (index 0) | **27.7x** |
| `rare_first_short_no_match` | `37 6B C1 BA 5E 71` (no match present) | `0x37` (index 0) | `0x37` (index 0) | **0.99x** (identical) |
| `long_mostly_wildcards` | `48 8B 05 ?? ?? ?? ?? 48 89 ?? ?? ?? ?? 37 DE AD` | `0x37` (index 13) | `0x48` (index 0) | **24.8x** |
| `verify_heavy_32B_match` | 32-byte pattern starting with `48 8B 05 37 ...` | `0x37` (index 3) | `0x48` (index 0) | **25.1x** |

A few takeaways:

1. **The anchor choice dominates scan time.** Every false anchor hit costs a SIMD verify, and `0x48` matches roughly 12% of bytes in real x64 `.text` whereas `0x37` matches well under 0.5%. The 23x to 28x ratios shown above are exactly the false-anchor-hit ratio playing out as wall-clock time.
2. **The verify tier (AVX2 vs scalar) is almost irrelevant to this comparison.** Both runs use the same AVX2 verify path; what differs is how often that path is invoked. Moving from scalar to AVX2 inside the verify might save another 30% on each verify, but the rare-byte anchor saves an order of magnitude on the *number* of verifies. The smart-anchor path is so dominated by the memchr sweep that pattern size barely affects the result (550 to 625 microseconds across all six smart-anchor runs).
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

## Caveats

- The byte distribution is synthetic. Real binaries vary; a `.text` section that uses unusual instruction selection (heavy AVX, lots of EVEX prefixes) will have different ratios. The qualitative result (rare anchor wins big) should hold across any realistic distribution, but the exact speedup will move.
- The benchmark deliberately compares two strategies that share the same SIMD verify path. It is NOT a comparison against scanners that use a different verify (Otis Inf's scanner uses an 8-byte uint64 XOR/AND verify, which is somewhere between our scalar tail and our SSE2 path). The conclusion that "rare-byte anchor produces 5x to 30x speedup" applies to anchor selection in general, not to any specific scanner implementation.
- Microbenchmarks measure cold or warm cache state depending on the buffer fitting in L2/L3. At 8 MiB the buffer mostly misses L2 (32 MiB L3 on most modern Intel chips will hold it), so this approximates a "warm L3, cold L1/L2" workload. Real game-mod scans typically run over multi-megabyte module images, so the workload is representative.
