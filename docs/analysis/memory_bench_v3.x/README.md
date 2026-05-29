# Memory microbenchmark: validation predicate vs direct SEH-guarded read

This directory captures a run of `tests/bench_memory.cpp` against the production `Memory` paths. The benchmark quantifies the per-call cost of each way to read game memory from a hot path, so a caller can choose between a validation predicate (`is_readable` / `is_writable`) and a direct SEH-guarded read (`seh_read`, `seh_read_chain`) with data rather than intuition. The guidance these numbers back is in [../../misc/hot-path-memory.md](../../misc/hot-path-memory.md).

The benchmark measures:

- **Per-call cost** of each primitive (validation warm-hit / cold-miss, raw `VirtualQuery`, `read_ptr_unchecked`, `seh_read`, direct load/store, `write_bytes`).
- **VirtualQuery vs address-space size** (reserve N regions, re-time) to show whether a large VAD tree inflates the miss cost.
- **`is_readable` tail latency** (p50/p99/max) under 1/2/4 threads forcing cache misses on a shared shard set. Tail latency, not average, is what a frame loop feels as a hitch.
- **Probe model**: a hook that resolves an object and reads K dependent fields across a few distinct (cache-missing) objects, GATED (`is_readable` before every read) vs DIRECT (one fault guard, raw reads), reported per probe including the tail, plus a per-frame budget.
- **Pointer chain**: a GATED per-link walk vs `seh_resolve_chain` / `seh_read_chain` (one fault guard for the whole walk).

## Hardware / configuration

- Build: MSVC 2022, Ninja, Release (`/O2`), `-DDMK_BUILD_BENCHMARKS=ON`
- Toolchain: MSVC, where `seh_*` use real `__try` / `__except` (table-driven on x64, free on the no-fault path)
- Iterations: 200,000 per sample (20,000 for `write_bytes`)
- Samples: 15; median reported. Latency studies report p50/p99/max over the raw sample set
- `DEFAULT_CACHE_EXPIRY_MS = 50`

## Results

```text
[1] Validation MISS / uncached (cache off -> VirtualQuery branch)
  raw VirtualQuery               217.78 ns/call
  is_readable MISS               236.65 ns/call
  is_writable MISS               227.87 ns/call

[2] Validation WARM HIT (cache on, entry fresh within TTL)
  is_readable HIT                 54.47 ns/call
  is_writable HIT                 55.35 ns/call

[3] Direct access primitives
  direct volatile load             3.93 ns/call
  read_ptr_unchecked               3.92 ns/call
  seh_read<u64>                    7.42 ns/call
  direct volatile store            0.45 ns/call
  write_bytes(8)                5650.69 ns/call

[4] raw VirtualQuery vs VAD-tree size (single fixed address)
  +     0 reserved regions       237.48 ns/call
  +  1000 reserved regions       218.41 ns/call
  +  4000 reserved regions       220.93 ns/call
  + 12000 reserved regions       224.38 ns/call

[5] is_readable latency under contention (mostly-miss workload, 4096 pages)
  1 thread(s):  p50  800 ns   p99  1700 ns   max  77600 ns
  2 thread(s):  p50 1100 ns   p99  2400 ns   max 107000 ns
  4 thread(s):  p50 1700 ns   p99  6100 ns   max  81500 ns

[6] Per-probe cost: 8 reads across ~3 distinct (cache-missing) objects
  GATED  (is_readable+read): p50  5900   p99 10500   max 152100   mean 6120 ns/probe
  DIRECT (raw read)        : p50   100   p99   400   max   5100   mean   89 ns/probe
  gated/direct mean ratio  : 68.7x

[7] Per-frame budget (16.67 ms frame): cost = probes/frame x ns/probe
  probes/fr      gated %frame   direct %frame
  1                    0.04%          0.00%
  8                    0.29%          0.00%
  64                   2.35%          0.03%
  256                  9.40%          0.14%
  1024                37.60%          0.55%

[8] Pointer chain (6 links, warm cache)
  gated link walk                316.10 ns/call
  seh_resolve_chain                9.14 ns/call
  seh_read_chain<u64>             10.93 ns/call
  gated/seh_read_chain ratio: 28.9x
```

## How to read this

| Comparison | Numbers | Takeaway |
|------------|---------|----------|
| `seh_read<u64>` vs direct load | 7.4 ns vs 3.9 ns | A typed SEH-guarded read is within ~2x of a raw dereference, because the x64 `__try` is table-driven and free on the no-fault path. |
| `is_readable` HIT vs `seh_read` | 54.5 ns vs 7.4 ns | Even a warm cache hit on the predicate costs ~7x a direct guarded read: it takes a shard reader lock and a cache lookup. |
| `is_readable` MISS vs HIT | 236.7 ns vs 54.5 ns | A miss issues a `VirtualQuery` syscall and rebuilds the entry under an exclusive lock. When target addresses keep changing, almost every lookup misses. |
| `seh_read_chain` vs gated per-link walk | 10.9 ns vs 316.1 ns | Resolving a 6-link chain under one fault guard is ~29x faster than calling `is_readable` before every dereference. |
| Probe GATED vs DIRECT (mean) | 6120 ns vs 89 ns | Gating each of 8 dependent reads across cache-missing objects costs ~69x the direct cost per probe. |
| Probe tail (p99 / max) | 10500 / 152100 ns vs 400 / 5100 ns | The gate hurts the tail far more than the mean. A single worst-case gated probe (152 us) is ~0.9% of a 16.67 ms frame on its own. |

A few takeaways:

1. **The predicate is the wrong tool on a hot path.** It is not free even on a cache hit (a lock plus a lookup), and on a cache miss it pays a `VirtualQuery` plus an exclusive-lock rebuild. The probe model, where each object is a fresh page, is miss-dominated, so the gate runs ~69x slower per probe than reading directly under one guard.
2. **The cost scales with probes-per-frame, and the tail is the real hazard.** At a few probes per frame the gate is imperceptible. At a few hundred per frame (an apply path touching many bound objects) it climbs to a large fraction of the frame budget, and the p99/max tail can spike a frame on its own. A single average-per-call number hides this.
3. **A single SEH-guarded read is nearly free on MSVC.** `seh_read` is within ~2x of a raw load, and the chain primitives keep that property across a whole multi-level walk: one guard for the walk instead of N predicate calls.
4. **`VirtualQuery` cost is flat in address-space size.** Growing the VAD tree to 12,000 reserved regions does not move the per-call cost (the kernel walks a balanced tree), so the miss cost is intrinsic, not a function of how fragmented the process is.

## Reproducing locally

```bash
# MSVC (Developer Command Prompt), from repo root
cmake -S . -B build/msvc-release -G Ninja -DCMAKE_BUILD_TYPE=Release ^
    -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF
cmake --build build/msvc-release --target DetourModKit_bench_memory --parallel
build\msvc-release\tests\DetourModKit_bench_memory.exe
```

The harness prints the human-readable tables above plus a `#TSV` block on stdout for machine parsing (`probe_gated_over_direct` is the headline gated-vs-direct ratio).

## Caveats

- Numbers are from a single development machine and are illustrative. The miss-path cost is dominated by `VirtualQuery` latency and shard-lock contention, so it varies by CPU, Windows build, and core count. Run the bench for your own target; the qualitative result (predicate expensive on the hot path, direct read cheap, chain cheap) holds across machines.
- These are MSVC numbers, the shipping configuration. On MinGW there is no SEH, so `seh_read` / `seh_read_chain` fall back to a `VirtualQuery`-guarded read and pay a syscall per access; on that toolchain the gated walk can be faster than the chain primitives, which is why mod builds target MSVC and why `read_ptr_unchecked` is the recommended MinGW hot-path read (see [../../misc/hot-path-memory.md](../../misc/hot-path-memory.md)).
- On MinGW the benchmark targets are built with the same Release LTO as the library (`INTERPROCEDURAL_OPTIMIZATION_RELEASE`, set in `tests/CMakeLists.txt` when IPO is supported), so each bench object and the LTO-only library archive form one LTO unit. This sidesteps a GCC linker-plugin bug where a mixed link (a non-LTO bench object against the LTO Release archive) re-emits libstdc++'s C++20-constrained `std::thread` / `std::tuple` linkonce symbol twice and fails with a spurious multiple-definition. No manual step is needed; do not force a non-LTO Release for the bench, since that mixed link is exactly what triggers the failure. The library and tests are unaffected.
- The probe model uses synthetic page-per-object churn to force the miss path. A real hook whose objects share pages will miss less often and see a smaller gate penalty, but the structural point (the predicate adds a lock and a possible syscall the direct read does not) is independent of the hit rate.
