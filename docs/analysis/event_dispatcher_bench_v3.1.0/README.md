# EventDispatcher Bench, v3.1.0

Before/after numbers for the lock-free COW snapshot `emit()` landed in v3.1.0.
The previous implementation used `std::shared_mutex` for `emit()` / `emit_safe()`
and an exclusive lock for `subscribe()` / `unsubscribe()`. The new implementation
stores handlers in a `std::atomic<std::shared_ptr<const std::vector<Entry>>>`
snapshot published on mutation, with a lock-free atomic handler-count fast
path for the zero-subscriber case.

## Results (median of 5 runs per side)

| Scenario                    | Subs | Before (ns/op) | After (ns/op) | Delta             | Verdict |
| --------------------------- | ---: | -------------: | ------------: | ----------------- | :------ |
| `emit`                      |    0 |          103.9 |       **6.0** | **-94.2% (17x)**  | REAL    |
| `emit`                      |    1 |          120.1 |          94.4 | **-21.4%**        | REAL    |
| `emit`                      |    8 |          245.6 |         216.3 | **-11.9%**        | REAL    |
| `emit`                      |   64 |         1103.5 |        1092.1 | -1.0%             | NOISE   |
| `emit_safe`                 |    0 |          103.1 |       **5.7** | **-94.5% (18x)**  | REAL    |
| `emit_safe`                 |    1 |          118.6 |          96.4 | **-18.7%**        | REAL    |
| `emit_safe`                 |    8 |          233.2 |         219.1 | -6.0%             | REAL    |
| `emit_safe`                 |   64 |         1086.3 |        1099.8 | +1.2%             | NOISE   |
| `emit_concurrent_4_threads` |    8 |          517.9 |     **248.2** | **-52.1% (2.1x)** | REAL    |
| `subscribe_unsub_roundtrip` |    — |          446.0 |        1150.4 | +158.0%           | REAL    |
| `reentrancy_rejection`      |    1 |          212.5 |         192.7 | -9.4%             | marginal|

Verdict key:

- **REAL**: median delta exceeds 1.5x the combined run-to-run spread on both sides.
- **NOISE**: median delta is smaller than the run-to-run spread; cannot be distinguished from measurement jitter.
- **marginal**: delta is larger than spread but smaller than 1.5x spread.

Run-to-run coefficient of variation was 1% to 5% per scenario. Full per-run
TSVs live in [runs/](runs/) (5 OLD + 5 NEW). A representative single run per
side is preserved in [before.tsv](before.tsv) and [after.tsv](after.tsv) for
quick reference.

## Interpretation

**Zero-subscriber fast path.** The atomic handler-count short-circuit in
`emit()` / `emit_safe()` collapses a `shared_mutex` acquire/release plus
iteration setup into a single `memory_order_acquire` load of an 8-byte counter.
The 17x factor is the cost of an uncontended `shared_mutex` acquire/release
on Windows SRWLOCK relative to a naked atomic load, and it is the dominant
result for dispatchers that are wired up at init but rarely subscribed to.

**1 to 8 subscriber uncontended emit.** Consistent wins (6% to 21%) from
removing the reader lock. The snapshot load is a release-acquire atomic plus
a `shared_ptr` refcount bump, which is cheaper than touching a mutex's state
word unconditionally.

**Concurrent emit (4 threads, 8 subs).** 2.1x throughput. No reader lock
means no cache-line contention on the mutex state, so all four threads make
progress in parallel instead of serializing on the SRWLOCK read side.

**64 subscriber emit.** Within noise on both `emit` (-1.0%) and `emit_safe`
(+1.2%). An earlier single-run measurement suggested an 18% regression; that
was a statistical outlier. Across 5 runs per side the two implementations
are indistinguishable at this subscriber count: the per-handler iteration
cost dominates and both paths reach the same `std::vector<Entry>` buffer
layout through one extra dereference either way.

**Subscribe / unsubscribe round-trip.** 2.6x slower (446 ns to 1150 ns).
Each mutation allocates a fresh handler vector, appends or removes the
entry, and publishes via atomic store. This is documented in the header
and is the accepted tradeoff for lock-free reads. Subscribe is not on a
hot path in any realistic mod workload.

**Reentrancy rejection.** Marginal improvement (within 1.5x spread). Not a
meaningful claim; effectively unchanged.

## Methodology

- Host: Windows 11, MinGW `mingw-release` preset (GCC 13, libstdc++, -O3 LTO).
- CMake: `cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF`.
- Build: `DetourModKit_bench` target only. No gtest linkage, no other test deps.
- Each sample runs N iterations of the scenario inside a single
  `steady_clock::now()` pair. Reported value is the median per-op cost across
  11 samples inside one process invocation. Iteration counts are chosen so
  each sample takes roughly the same wall time.
- 5 process invocations per side (OLD vs NEW), back-to-back, same machine,
  same thermal state. Tables above report the median across those 5 runs
  for each scenario.
- Verdicts use run-to-run spread (max minus min across the 5 runs) as the
  noise floor. A claim is "REAL" only when the median delta exceeds 1.5x
  that noise floor on both sides.

## Reproduce

```bash
cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-release --target DetourModKit_bench --parallel
PATH="/c/msys64/mingw64/bin:$PATH" ./build/mingw-release/tests/DetourModKit_bench.exe > run.tsv
```

For a clean before/after comparison, bench the new implementation first,
copy the header aside, `git checkout HEAD -- include/DetourModKit/event_dispatcher.hpp`
to restore the baseline header, rebuild the `DetourModKit_bench` target, run
again into the baseline TSV, then restore the new header. Repeat N times
per side and compare medians with an explicit noise-floor check.

## Caveat on committed TSVs

The TSVs in this directory are raw artifacts from a specific host and
compiler version. They are not a stable baseline. Treat them as evidence
for the claims in this document, not as a regression gate. Future bench
runs should regenerate their own numbers and compare against the structure
of the results (17x fast-path win, 2x concurrent win, COW subscribe cost)
rather than the absolute nanosecond values.
