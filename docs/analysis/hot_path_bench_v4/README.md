# Hot-path bench pass: identity probe, guarded dispatch, and logger producer (B1)

> Archived benchmark snapshot; record new measurements in a new folder rather than editing existing results.

This directory captures the four hot-path costs that the audit series asked to see measured before any of them is redesigned. Three of them were disclosed in the headers as costs but never quantified, and one design proposal (the `TypeIdentity` generation-memo redesign) was held until a number existed. The producers are `tests/bench_rtti.cpp` (`DetourModKit_bench_rtti`), `tests/bench_hook.cpp` (`DetourModKit_bench_hook`), and `tests/bench_logger.cpp` (`DetourModKit_bench_logger`).

## Hardware and configuration

- Host: Windows 11 (10.0.26200), x64
- MSVC: 19.43 (VS 2022 17.13), Ninja, Release, `DMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF`
- MinGW: GCC 15.1.0 (MSYS2), Ninja, Release, same options
- `steady_clock` granularity on this host is 100 ns, reported in each table as `clock_tick_ns`

## Method

Each workload runs twice. An untimed batch of N calls carries the reported mean and throughput. A second pass of N calls with a `steady_clock` pair around each call carries the percentiles. The split is necessary because one dispatch is shorter than one clock tick: a per-call timer both quantizes the result to 100 ns and costs more than the operation it wraps. Read the mean as the cost and the percentiles as the tail shape.

Every figure is one run, not a median of repetitions. Repeat runs of the same binary move the RTTI and hook means by a few percent on this host, so read a difference under about 10 percent as noise. Every run is gated. A percentile table proves nothing if the measured call never reached the intended path, so each benchmark asserts that its calls produced the expected answer and exits nonzero otherwise. The gate records are in `runs/`.

## Results

### Type identity and pointer-table sweep

| Figure | MSVC Release | MinGW Release |
|---|---|---|
| `TypeIdentity::matches`, warm, mean ns | 79.2 | 452.4 |
| `find_in_pointer_table` 64 slots, no cache, full miss, mean ns | 5,566 | 18,415 |
| Same, per slot | 87.0 | 287.7 |
| `find_in_pointer_table` 64 slots, no cache, hit at slot 0, mean ns | 105.6 | 384.1 |

The fixtures are synthetic MSVC COL/TypeDescriptor/vtable triples in the benchmark executable's own data segment. They carry real host-image addresses, so `memory::module_of` resolves them to the executable's PE range and the resolver runs its real validation prelude on every candidate. A live C++ class restricts the whole measurement to MSVC, because the MinGW Itanium ABI emits no COL for the walker to find. The synthetic triple avoids that limit.

### Guarded hook dispatch

| Figure | MSVC Release | MinGW Release |
|---|---|---|
| `Hook::call`, 1 thread, mean ns | 44.0 | 37.0 |
| `Hook::call`, 1 thread, calls/s | 22.7 M | 27.1 M |
| `Hook::call`, 2 threads, mean ns | 231.1 | 141.7 |
| `Hook::call`, 2 threads, calls/s | 8.7 M | 14.1 M |
| `Hook::original`, 2 threads, mean ns | 2.2 | 2.0 |
| `Hook::original`, 2 threads, calls/s | 911 M | 1,009 M |
| `Hook::call` 2-thread p99 / p999 ns | 600 / 1,900 | 300 / 600 |

### Async logger producer

Queue capacity 8192, batch size 64, flush interval 5 ms, 500,000 samples per row, writer actively draining.

| Row | MSVC p50/p99 ns | MinGW p50/p99 ns | MSVC accepted | MinGW accepted |
|---|---|---|---|---|
| `AsyncLogger::enqueue`, DropOldest | 100 / 200 | 100 / 200 | 499,877 | 499,998 |
| `AsyncLogger::enqueue`, DropNewest | 100 / 100 | 100 / 200 | 13,888 | 5,120 |
| `Logger::log`, DropNewest | 100 / 100 | 100 / 200 | 18,752 | 5,888 |

## Reading

- The warm identity probe costs 79 ns on MSVC Release. It is a per-frame-affordable test, which is what the `matches` contract claims, and the cost is the bounded guarded PE-header reads of the generation check rather than a resolve.
- The uncached pointer-table sweep costs 87 ns per slot on MSVC Release, so a 64-slot miss is about 5.6 us. This is the cost the header calls setup/control-plane work, and the number confirms the classification: a caller that runs it per frame over a wide table pays milliseconds, and a caller that caches pays the warm path above.
- Guarded dispatch is where the disclosed cost is largest. `Hook::call` costs 44 ns against 2.2 ns for `Hook::original` on one thread, and adding a second thread through the same handle raises the mean to 231 ns while throughput falls from 22.7 M/s to 8.7 M/s. The unguarded route scales instead, to 911 M/s across two threads. The measurement matches the `Hook::call` warning exactly: the per-hook recursive gate mutex serializes concurrent callers, and `Hook::original` is the route for a hot multi-threaded target.
- The overflow policy does not change producer latency; it changes acceptance. Both policies refuse or evict at the same p50, but DropOldest evicts to make room and accepts essentially every record, while DropNewest accepts under 3 percent of a saturating burst. The public `Logger::log` facade adds no measurable latency over the raw enqueue at this granularity.
- The MinGW column is slower on the RTTI paths and faster on hook dispatch. The RTTI gap is the guarded-read implementation: MinGW routes each guarded read through the vectored exception handler path, and MSVC uses zero-cost SEH. The hook gap is smaller and within the noise this method resolves.

## Decision

**No design item opened.** B1's standing rule is that only a measured regression may open one, and every figure matches its disclosed contract. Two specific consequences:

- The `TypeIdentity` generation-memo redesign stays declined. It was held pending this number, and 79 ns on the warm path does not justify the added state.
- The `Hook::call` contention cost is real and large, but it is already the documented behavior with a documented alternative in the same header. The fix a consumer needs is the existing `Hook::original`, not a change to the gate.

Any future change to these paths must cite this report's method and beat these numbers on the same workload.
