# Protection-cache reader admission comparison (P1)

> This benchmark snapshot is an archive. Record new measurements in a new folder. Do not edit this record.

This record compares the prior open counters, one closed-bit word, and 64 closed-bit words. The closed bit and reader count share one atomic word. One compare-exchange refuses a closed stripe or adds one reader.

The roadmap proposed one process-wide word. The striped variant selects one cache-line-padded word from a thread ID hash.

Phase 2 measures one deterministic warm hit. Phase 9 measures warm-hit throughput with 1, 2, 4, and 8 threads. Phase 9 address placement varies by process and affects shard occupancy. The comparison uses the median from five interleaved runs per binary.

## Hardware and configuration

- Host: Windows 11 (10.0.26200), x64, 2026-08-25
- MinGW: GCC 15.1.0, MSYS2, Ninja, Release
- MSVC: Visual Studio 2022 Community, cl 19.4x, Ninja, Release
- Configure: `-DCMAKE_BUILD_TYPE=Release -DDMK_BUILD_TESTS=OFF -DDMK_BUILD_BENCHMARKS=ON`
- Cache: 256 entries, 16 shards, 50 ms expiry
- Baseline: unmodified `b053389` with the same configure command

## MinGW results

Phase 9 warm-hit throughput uses Mops/s. Samples appear in parentheses.

| Threads | Prior striped open counter | 64 closed-bit words | 1 closed-bit word |
|---:|---:|---:|---:|
| 1 | 2.76 (12.57, 2.76, 2.71, 2.17, 3.28) | 2.67 (3.90, 2.11, 2.57, 2.67, 2.80) | 7.33 |
| 8 | 23.70 (41.05, 30.48, 23.70, 15.23, 22.96) | 25.71 (28.34, 18.72, 14.87, 27.35, 25.71) | 9.89 |

The single word reaches 9.27, 10.32, and 9.89 Mops/s with 2, 4, and 8 threads. One shared cache line prevents scale. The 64-word result overlaps the prior result at each thread count.

Phase 2 reports nanoseconds per `is_readable` warm hit.

| Design | Run 1 | Run 2 |
|---|---:|---:|
| Prior striped open counter | 81.29 | 79.51 |
| 64 closed-bit words | 83.64 | 85.20 |
| 1 closed-bit word | 82.89 | not run |

The 64-word variant adds about 4 ns on this host. The warm hit remains about 2.7 times faster than the uncached miss. Both memory permission time gates pass in every run.

## MSVC results

The MSVC comparison uses two interleaved runs per binary. Phase 9 reports Mops/s.

| Threads | Prior striped open counter | 64 closed-bit words |
|---:|---:|---:|
| 1 | 2.21, 3.27 | 3.84, 2.57 |
| 8 | 17.24, 27.55 | 31.86, 10.85 |

Phase 2 reports 58.28 and 58.26 ns for the prior design. The 64-word variant reports 59.21 and 58.69 ns. The sample ranges overlap at each thread count. The MinGW result rejects the single-word variant, so MSVC did not run that variant.

## Decision

Adopt the 64 striped closed-bit words. Reject the single process-wide word.

- The single word loses 58 percent against the prior 8-thread median. This result exceeds the P1 budget.
- Each stripe checks closure and adds its reader in one compare-exchange.
- Teardown closes every stripe before it reads any admitted count.
- Admission opens only from the exact closed and zero-reader state.
- The 64-word throughput overlaps the prior throughput on both toolchains.
- The accepted warm-hit cost preserves both time gates.
