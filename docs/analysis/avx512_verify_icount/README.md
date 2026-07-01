# AVX-512 verify tier: instruction-count proxy

> Archived benchmark snapshot; record new measurements in a new folder rather than editing existing results.

This directory captures a no-hardware bench signal for the opt-in AVX-512 scanner verify tier (`DMK_ENABLE_AVX512`). It records *instruction counts*, not wall-clock time, because AVX-512 wall-clock can only be measured on real AVX-512 hardware; Intel SDE, which is what makes this measurable without that hardware, emulates the ISA and its timing is not representative of real silicon. What SDE *can* measure deterministically on any host is how many guest instructions each verify tier executes for the same work.

The trick is that one `DMK_ENABLE_AVX512=ON` binary selects its verify body at runtime from the CPU it sees, so running it under two emulated CPUs exercises two tiers from the same build:

- `sde -spr` (Sapphire Rapids) -> `cpu_has_avx512()` true -> the 64-byte AVX-512 verify body.
- `sde -hsw` (Haswell) -> AVX-512 absent, AVX2 present -> the 32-byte AVX2 verify body.

`sde -mix` counts the executed guest instructions for each. The bench runs in `--verify-icount` mode (a single deep-verify pass over a 1 MiB buffer, then exits) so the count is verify-dominated and the SDE run stays cheap.

## Configuration

- Build: `cmake -B build/icount -G Ninja -DCMAKE_BUILD_TYPE=Release -DDMK_BUILD_BENCHMARKS=ON -DDMK_ENABLE_AVX512=ON`
- Toolchain: MSVC (x64), Release
- Mode: `--verify-icount` (one deep-verify pass; 1 MiB buffer, 96-byte literal pattern, break stride 64)
- Emulator: Intel SDE with `-mix` (dynamic instruction count); `-spr` selects the AVX-512 tier, `-hsw` the AVX2 tier

## Results

```text
[-spr] bench verify tier: AVX-512
[-hsw] bench verify tier: AVX2
AVX-512 (-spr) verify-pass instructions: 63,243,163
AVX2    (-hsw) verify-pass instructions: 71,277,872
instruction-count ratio (AVX2 / AVX-512): 1.127x
```

## How to read this

| Tier (SDE chip) | Verify body | Executed instructions |
|-----------------|-------------|-----------------------|
| AVX-512 (`-spr`) | 64 bytes/iteration | 63,243,163 |
| AVX2 (`-hsw`) | 32 bytes/iteration | 71,277,872 |
| Ratio (AVX2 / AVX-512) | | **1.127x** |

A few takeaways:

1. **AVX-512 does measurably less work, but not dramatically less.** ~11% fewer instructions for the same verify pass confirms the 64-byte body covers ground the 32-byte body needs two iterations for. The margin is modest because the deep-verify scenario breaks within a chunk or two, so the per-position prefilter and loop overhead -- identical on both tiers -- dominates the short verify and dilutes the chunk-width saving.
2. **This is a proxy for work, not for time.** A lower instruction count usually helps, but 512-bit downclock and port pressure can offset or even reverse it on real silicon, and the tier's acceptance criterion was a wall-clock target (`>= 1.30x` over AVX2), not an instruction-count one. 1.127x instructions is the optimistic proxy and is already below that bar; wall-clock would have to be measured before the tier could be turned on by default.
3. **Correctness is a separate, stronger signal.** The AVX-512 leg of the per-tier correctness matrix (`simd-tier-correctness.yml`) executes the full scanner suite under emulated AVX-512 and requires results identical to the scalar/AVX2 path. That validates the 64-byte body; this directory only addresses whether the tier is worth turning on.

## Reproducing locally

Any host, no AVX-512 hardware required (SDE emulates the ISA):

```bash
cmake -S . -B build/icount -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DDMK_BUILD_BENCHMARKS=ON -DDMK_ENABLE_AVX512=ON
cmake --build build/icount --target DetourModKit_bench_scanner
sde -spr -mix -- build/icount/tests/DetourModKit_bench_scanner.exe --verify-icount
sde -hsw -mix -- build/icount/tests/DetourModKit_bench_scanner.exe --verify-icount
```

Read the global dynamic instruction total from each `sde-mix-out.txt` (the largest `*total` entry). The `--verify-icount` buffer has a fixed layout, so the counts are deterministic across runs.

## Caveats

- **Instruction count is not wall-clock.** This whole directory is a proxy. The real `>= 1.30x` throughput target can only be measured on real AVX-512 hardware; until that is done, the tier stays opt-in (`DMK_ENABLE_AVX512` OFF).
- **The Scalar tier is not represented.** On x64, SSE2 is the ABI baseline, so `active_simd_level()` never returns `Scalar` and no SDE chip can force it; the scalar code paths survive only as verify tails and the prefilter fallback.
- **The modest margin is workload-specific.** The deep-verify microbench maximizes verify work relative to the prefilter. In a normal scan the verify is rarer relative to the prefilter sweep, so the real-world AVX-512-vs-AVX2 instruction delta is smaller still.
