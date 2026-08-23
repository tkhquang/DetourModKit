# Input token query: per-frame `is_active` cost (C17)

> Preserve this archived snapshot. Record a new measurement in a new folder.

The benchmark measures `Input::is_active(token)` and related public queries. It separates the live-poller load, shared lock, index traversal, and name lookup path. `tests/bench_input.cpp` produces the record through `DetourModKit_bench_input`.

## Hardware and configuration

- The host ran Windows 11 (10.0.26200) on x64 with 16 logical cores.
- The MSVC route used 19.43.34809, Ninja, Release, and `-DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF`.
- The MinGW route used GCC 15.1.0, MSYS2, Ninja, Release, and the same options.
- The smallest observed nonzero `steady_clock` delta was 100 ns.

## Method

Each public query loads the live poller through one atomic `shared_ptr`. The workloads separate the relevant costs:

- `is_active_invalid_token` stops before the lock and provides the poller-load floor.
- `token_current` adds the shared lock and one generation comparison.
- `is_active_token` adds index traversal at one entry and eight entries.
- `is_active_name` measures the full name-index lookup and eight index loads.

Each workload uses one 200,000-call batch for the mean. A second 200,000-call pass records per-call samples. The samples follow the 100 ns clock step. Therefore, the means drive the decision. Percentiles provide coarse tail bins.

The workloads use F13 through F21 with no modifiers. Five functional gates reject an unexpected answer. Each gate covers all 400,000 measured calls.

The `runs/` captures contain the five gate records and all measurement rows.

## Results

| Figure | MSVC Release | MinGW Release |
|---|---|---|
| Acquire floor (invalid token), mean ns | 23.5 | 20.1 |
| `token_current`, mean ns | 36.5 | 34.0 |
| `is_active(token)`, 1 entry, mean ns | 38.3 | 36.1 |
| `is_active(token)`, 8 entries, mean ns | 45.0 | 39.2 |
| `is_active(name)`, 8 entries, mean ns | 53.5 | 58.8 |
| Marginal cost of one extra entry, ns | 0.96 | 0.46 |

The 100 ns clock step limits percentile precision. All p50 and p99 values are at or below 100 ns. Nine of ten p999 values meet that bound. The MinGW name p999 is 200 ns. Maxima range from 3.2 to 128.8 microseconds and receive no policy role.

## What the numbers decide

The fixed cost dominates. On MinGW, the poller load costs at most 20.1 ns. The lock and generation comparison add 14.0 ns. The one-entry token query adds another 2.0 ns. MSVC reports 23.5 ns, 13.0 ns, and 1.8 ns for the same three stages.

Seven extra indices add 3.2 ns on MinGW and 6.8 ns on MSVC. The eight-entry name query exceeds its token peer by 19.5 ns on MinGW and 8.4 ns on MSVC.

An unsafe raw snapshot can remove at most the poller-load floor. That upper bound is 20.1 ns on MinGW and 23.5 ns on MSVC.

At 100 one-entry token queries per frame, current cost is 3.6 microseconds on MinGW and 3.8 microseconds on MSVC. Each total is about 0.02 percent of a 16.6 ms frame. The potential gain does not justify loss of the `shared_ptr` lifetime across concurrent shutdown. The existing snapshot design remains.

The eight-entry name path remains slower than its token peer. `input.hpp` already directs per-frame consumers to `acquire_token`. No guidance change is necessary.

## Reproduce

```bash
PATH="/c/msys64/mingw64/bin:$PATH"
cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON
cmake --build build/mingw-release --parallel --target DetourModKit_bench_input
./build/mingw-release/tests/DetourModKit_bench_input.exe
```

`scripts/check_benchmark_results.py` accepts the MinGW capture. The release `benchmark-evidence` route omits this decision-specific producer.
