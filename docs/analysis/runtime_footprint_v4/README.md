# Runtime footprint: logger and profiler resident bytes and high-water (P2-4)

> Archived benchmark snapshot; record new measurements in a new folder rather than editing existing results.

This directory captures the P2-4 measurement of the async logger's and the profiler's actual heap, private-commit, and high-water bytes at their default capacities, per linked DMK instance. P2-4 requires these figures before any capacity default changes; static footprint estimates alone must not tune them. The producer is `tests/bench_footprint.cpp` (`DetourModKit_bench_footprint`), using the counting allocator in `tests/bench_alloc.hpp` plus `GetProcessMemoryInfo`.

## Hardware / configuration

- Host: Windows 11 (10.0.26200), x64
- MinGW: GCC 15.1.0 (MSYS2), Ninja, Release; MSVC: 19.43 (VS 2022 17.13), Ninja, Release
- Defaults throughout: `queue_capacity` 8192, `LOG_INLINE_MESSAGE_SIZE` 512, `Profiler::DEFAULT_CAPACITY` 65536

## Results

| Figure | MinGW | MSVC |
|---|---|---|
| `sizeof(detail::LogMessage)` (queue slot) | 552 | 552 |
| AsyncLogger construction, heap bytes | 4,596,663 | 4,596,736 |
| AsyncLogger construction, private-commit bytes | 4,653,056 | 4,624,384 |
| Inline streaming, allocations per message (producer+writer) | 0.0000 | 0.0000 |
| Over-inline burst (5000 x 2 KiB), high-water bytes | 9,953,225 | 9,222,112 |
| Over-inline, retained after drain | 2,143,232 | 2,158,592 |
| Retained after logger shutdown | 2,145,305 | 2,160,752 |
| Profiler ring resident (65536 x 32 B) | 2,097,152 | 2,097,152 |
| Profiler `record()` x 100,000, allocations | 0 | 0 |
| `export_chrome_json` high-water | 7,864,395 | 7,864,471 |

Reading:

- The logger's dominant cost is the queue ring: 8192 slots x 552 bytes = 4.52 MB of the ~4.6 MB construction delta, allocated eagerly and released at shutdown. The steady-state inline path allocates nothing (deterministic behavior, both toolchains).
- The over-inline retained ~2.1 MB is the StringPool free list: the pool slots' `std::string` buffers grow to the record size and stay pooled. The pool singleton is the documented bounded leak (`MEMORY_POOL_BLOCK_COUNT` = 64 blocks), so this figure persists past logger shutdown by design.
- The profiler's ring is exactly `capacity x sizeof(ProfileSample)` = 2 MB, resident for process life once first-used (the instance is deliberately never destroyed), and the `record()` hot path is allocation-free (deterministic release gate `footprint.profiler_record_allocation_free`).
- Export is a tool-path cost: ~120 bytes of transient high-water per resident sample.

## Decision

**No default changes.** The measured figures match the disclosed contracts: `async_logger_config.hpp` already documents the few-MiB ring and advises shrinking `queue_capacity` on memory-constrained hosts; the profiler header documents the fixed ring. A host that links N DMK instances multiplies these figures by N only for the subsystems it actually starts (async mode and profiler are both first-use/opt-in). Any future default change must cite this report's method and beat these numbers on a representative workload.
