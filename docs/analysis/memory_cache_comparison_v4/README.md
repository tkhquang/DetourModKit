# Protection-cache comparison: current cache vs `range_permission_uncached` (A3)

> Archived benchmark snapshot; record new measurements in a new folder rather than editing existing results.

This directory captures the A3 instrumented design decision for the protection-region cache in
`src/memory_cache.cpp`. The comparison set is the current sharded cache and the uncached
`range_permission_uncached` branch (`is_readable`/`is_writable` with the cache off). No third candidate was
measured: the previously proposed fixed-array/page-base-hash design is prohibited by the roadmap on
corrected-arithmetic grounds, and no other candidate design carries evidence.

The measurement is phases 1, 2, 5, 9, 10, 11, and 12 of `tests/bench_memory.cpp`
(`DetourModKit_bench_memory`), which cover every axis A3 names: warm hits, interior addresses of one
region, misses, churn, invalidation, allocations, retained bytes, and latency percentiles (p50/p95/p99).
Allocation and retained-byte figures come from the executable's counting `operator new`/`operator delete`
(`tests/bench_alloc.hpp`), snapshotted single-threaded so the deltas are attributable to the cache.

## Hardware / configuration

- Host: Windows 11 (10.0.26200), x64
- MinGW: GCC 15.1.0 (MSYS2), Ninja, Release (`-O3`, scan engine `-O2`)
- MSVC: 19.43 (VS 2022 17.13, cl 14.43.34808), Ninja, Release (`/O2`)
- `-DDMK_BUILD_BENCHMARKS=ON`, defaults throughout: 256 entries, 16 shards, 50 ms expiry
- Iterations: 200,000 per sample, 15 samples, median reported

## Results

| Workload | MinGW ns/call | MSVC ns/call |
|---|---|---|
| Warm hit (`is_readable`, first page) | 81.7 | 59.2 |
| Uncached miss (`is_readable`, cache off) | 235.0 | 231.4 |
| Raw `VirtualQuery` | 214.8 | 214.8 |
| Interior hit (containment index, 64 MiB region) | 94.1 | 75.4 |
| Interior raw `VirtualQuery` | 661.8 | 639.9 |
| Query + `invalidate_range` cycle (patch path) | 1196.0 | 1078.8 |
| `invalidate_range` idempotent floor | 409.5 | 442.2 |

Churn latency (mostly-miss, 4096 pages vs 256 entries, MinGW): 1 thread p50 900 / p95 1000 / p99 1100 ns;
4 threads p50 1600 / p95 3200 / p99 6400 ns. Warm-hit contention throughput keeps scaling: 7.3 -> 37.1
Mops/s from 1 to 8 threads (MinGW), 3.1 -> 28.8 (MSVC).

Footprint (counting allocator, defaults):

| Figure | MinGW | MSVC |
|---|---|---|
| `init_cache` heap bytes | 18,136 | 21,840 |
| Retained while running (full 256 entries) | 55,512 | 66,896 |
| Churn allocations per miss op | 1.99 | 2.00 |
| Leak after `shutdown_cache` | 0 | 0 |

## Decision

**Keep the current cache; adopt no candidate; do not remove.** The published measurements decide every axis:

- Warm hits beat the uncached branch 2.9x (MinGW) / 3.9x (MSVC); the timing gate
  `memory.is_readable_miss_over_hit` pins the direction permanently.
- Interior addresses beat the interior syscall 7.0x / 8.5x through the per-shard containment index; the
  sharding duplication cost (an interior address warms its own shard's copy) is bounded by shard count and
  is what buys the 8-thread scaling above. Gate: `memory.is_readable_miss_over_interior_hit`.
- The whole default cache retains ~55-67 KB while running, releases to exactly 0 bytes on
  `shutdown_cache` (deterministic gate `memory.cache_shutdown_releases_heap`), and costs ~2 allocations
  per miss in eviction steady state. Removal would save ~60 KB and forfeit the multiples above.
- Invalidation adds ~950-1000 ns to a patch cycle over the pure miss; `write_bytes` callers pay it once
  per patch, not per query, and the patch path is not a per-frame hot path.

Arbitrary public `cache_size` / `shard_count` semantics are unchanged.
