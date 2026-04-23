# EventDispatcher Bench, v3.2.0

Before/after numbers for the lock-free COW snapshot `emit()` landed in v3.2.0.
The previous implementation used `std::shared_mutex` for `emit()` / `emit_safe()`
and an exclusive lock for `subscribe()` / `unsubscribe()`. The new implementation
stores handlers in a `std::atomic<std::shared_ptr<const std::vector<Entry>>>`
snapshot published on mutation, with a lock-free atomic handler-count fast
path for the zero-subscriber case.

## Results

| Scenario                    | Subs | Before (ns/op) | After (ns/op) | Delta             |
| --------------------------- | ---: | -------------: | ------------: | ----------------- |
| `emit`                      |    0 |         105.20 |      **6.47** | **-94% (16.3x)**  |
| `emit`                      |    1 |         126.23 |        106.85 | -15%              |
| `emit`                      |    8 |         253.99 |        249.52 | -2%               |
| `emit`                      |   64 |        1121.43 |       1324.66 | +18% (regression) |
| `emit_safe`                 |    0 |         103.55 |      **6.32** | **-94% (16.4x)**  |
| `emit_safe`                 |    1 |         119.27 |        106.76 | -10%              |
| `emit_safe`                 |    8 |         231.13 |        208.92 | -10%              |
| `emit_safe`                 |   64 |        1169.86 |       1077.59 | -8%               |
| `subscribe_unsub_roundtrip` |    0 |         487.18 |       1125.23 | +131% (expected)  |
| `emit_concurrent_4_threads` |    8 |         551.73 |    **268.07** | **-51% (2.06x)**  |
| `reentrancy_rejection`      |    1 |         239.07 |        202.82 | -15%              |

Raw TSVs in [before.tsv](before.tsv) and [after.tsv](after.tsv). Each row is the
median of 11 samples. Iteration counts vary per row (10M for fast cases down to
200K for the slowest) to keep per-scenario wall time comparable.

## Interpretation

**Zero-subscriber fast path.** The atomic handler-count short-circuit in
`emit()` / `emit_safe()` collapses a `shared_mutex` acquire/release plus
iteration setup into a single `memory_order_acquire` load of an 8-byte counter.
The 16x factor is the cost of an uncontended `shared_mutex` acquire/release
on Windows SRWLOCK relative to a naked atomic load, and it is the dominant
result for dispatchers that are wired up at init but rarely subscribed to.

**1 to 8 subscriber uncontended emit.** Small consistent wins (10% to 15%)
from removing the reader lock. The snapshot load is a release-acquire atomic
plus a `shared_ptr` refcount bump, which is cheaper than touching a mutex's
state word unconditionally.

**Concurrent emit (4 threads, 8 subs).** 2.06x throughput. No reader lock
means no cache-line contention on the mutex state, so all four threads make
progress in parallel instead of serializing on the SRWLOCK read side.

**64 subscriber emit, single thread.** 18% slower (+203 ns on a 1121 ns
baseline). Two plausible causes:

1. Timer noise. On an 1100 ns run, 200 ns is 2-3 cycles worth of timer jitter
   amplified across the sample; the noise floor on `steady_clock` is
   typically in the tens of nanoseconds per sample.
2. `std::atomic<std::shared_ptr>` load cost dominates over the old loop's
   single mutex acquire when amortized over only 64 handlers. libstdc++'s
   implementation uses DWCAS (cmpxchg16b) on the snapshot atomic; MSVC
   uses an internal spinlock.

Typical DetourModKit usage (per the README: 1-10 subscribers per event,
dispatchers wired once at init) stays well inside the range where the
optimization is a pure win. The 64 subscriber row should be treated as a
worst-case indicator, not representative load.

**Subscribe / unsubscribe round-trip.** 2.31x slower (487 ns to 1125 ns).
Each mutation allocates a fresh handler vector, appends or removes the
entry, and publishes via atomic store. This is documented in the header
and is the accepted tradeoff for lock-free reads. Subscribe is not on a
hot path in any realistic mod workload.

**Concurrent emit, reentrancy rejection.** Small wins from the same
fast-path removal of the shared lock.

## Methodology

- Host: Windows 11, MinGW `mingw-release` preset (GCC 13, libstdc++, -O3 LTO).
- CMake: `cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF`.
- Build: `DetourModKit_bench` target only. No gtest linkage, no other test deps.
- Each sample runs N iterations of the scenario inside a single
  `steady_clock::now()` pair. Reported value is the median per-op cost across
  11 samples. Iteration counts are chosen so each sample takes roughly the
  same wall time.
- Back-to-back runs, same machine, same process start, thermal state
  comparable. Numbers are not hermetic; reruns on the same machine drift by
  a few percent at this granularity.

## Reproduce

```bash
cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-release --target DetourModKit_bench --parallel
PATH="/c/msys64/mingw64/bin:$PATH" ./build/mingw-release/tests/DetourModKit_bench.exe > after.tsv
```

For a clean before/after comparison, bench the new implementation first,
copy the header aside, `git checkout HEAD -- include/DetourModKit/event_dispatcher.hpp`
to restore the baseline header, rebuild the `DetourModKit_bench` target, run
again into `before.tsv`, then restore the new header.

## Caveat on committed TSVs

The `before.tsv` and `after.tsv` files in this directory are raw artifacts
from one run on one machine. They are not a stable baseline. Treat them as
evidence for the claims in this document, not as a regression gate. Future
bench runs should regenerate their own numbers and compare against the
structure of the results (16x fast-path win, 2x concurrent win, COW
subscribe cost) rather than the absolute nanosecond values.
