# DetourModKit Documentation

Guides and references for building mods with DetourModKit. New here? Start with the top-level [README](../README.md) for install and a minimal example, then [The Minimal Core](guides/minimal-core.md) for the leanest include set, then reach for the subsystem guide below.

## Guides

### Getting Started

- [The Minimal Core](guides/minimal-core.md). The five-header core set and the shortest path from process attach to read, patch, and hook game code, for a mod that wants a leaner include than the full umbrella.
- [Error Handling](guides/errors.md). The two-tier error model: `Result<T>` / `Error` / `ErrorCode`, the `DMK_TRY` / `DMK_TRY_VOID` macros, and the `GetLastError()` detail slot.

### Scanning

- [AOB Signature Scanning](misc/aob-signatures.md). Pattern syntax, RIP-relative resolution, and patch-proof signature practices.
- [Anchor Registry](guides/scanning/anchors.md). Declare every patch-fragile constant once and resolve the whole table in a single self-healing pass.
- [Signature Manifest](guides/scanning/signature-manifest.md). Ship the resolved contract (address plus register/offset/vtable-slot binding) as an editable `.signatures.ini`, so a game-patch repair is a text edit gated into trusted vs safe-disabled instead of a recompiled DLL.
- [Offline Signature Health](guides/scanning/signature-health.md). Grade a signature's strength (atom rarity, byte entropy, expected ambiguity) from its declarative bytes alone, before it ever runs against a game. A brittle anchor is caught at authoring time or in CI.

### Hooking

- [Hook Type Coverage](guides/hooking/hook-type-coverage.md). The inline / mid / VMT surface DMK ships, and the hook types (IAT/EAT, software and hardware breakpoints, DBI trace) it deliberately excludes, with the reason for each.
- [VMT Hook Configuration](guides/hooking/vmt-hook-config.md). Object and per-method virtual-table hooking and the `VmtOptions` pre-flight safety knobs.

### Memory

- [Hot-Path Memory](guides/memory/hot-path-memory.md). Read and write game memory in per-frame hot paths with the `memory::read` / `write` / `walk` and `unchecked::read` primitives.
- [AddressSanitizer and the Memory Scanner](guides/memory/asan-memory-scanner.md). Why deliberate foreign-memory reads trip ASan, and the pattern to follow for any new foreign-memory primitive.

### RTTI

- [MSVC RTTI Walker](guides/rtti/rtti-walker.md). Recover concrete type names from runtime vtables across DLL boundaries without `typeid` or `dynamic_cast`.
- [RTTI Self-Heal](guides/rtti/rtti-self-heal.md). Reverse-identify objects behind pointer slots and self-heal field offsets after a game patch shifts the struct layout.

### Hot-Reload

- [Hot-Reload Development Guide](guides/hot-reload/README.md). What DetourModKit guarantees across a logic-DLL unload, and the two topologies that consume it.
- [Config Hot-Reload](guides/hot-reload/config-hot-reload.md). The INI filesystem watcher and hotkey-triggered `config::reload()`.

### Header-owned surfaces

The input, logger, diagnostics, profiler, and event-dispatcher subsystems have no separate task guide. Their public headers (`input.hpp`, `logger.hpp`, `diagnostics.hpp`, `profiler.hpp`, `detail/event_dispatcher.hpp`) carry the full contract in Doxygen, and the design notes below cover the mechanism. Read the header first.

## Design notes

These notes document subsystem designs. Each note supports the `AGENTS.md` boundary rules that cite it and uses the same `[B-nn]` IDs.

- [Hook engine and backend](design/hooking.md) documents hook design.
- [Process and DLL lifecycle](design/lifecycle.md) documents lifecycle design.
- [Input subsystem](design/input.md) documents input design.
- [Logger and async logger](design/logging.md) documents log design.
- [Memory access and scanning](design/memory-scanning.md) documents memory and scan design.
- [Scanner, anchor, manifest, and RTTI resolution](design/resolution.md) documents address resolution.
- [Config subsystem](design/config.md) documents config design.
- [Event dispatcher and profiler](design/events.md) documents event and profiler design.
- [Public API](design/public-api.md) documents public API design.
- [Build, CI, and release](design/build-ci.md) documents build and release design.
- [Test architecture](design/testing.md) documents test design.

## Migration

- [Migrating from v3.x to v4.0.0](migration/migrating-v3-to-v4.md). Maps the old surface onto the clean-break v4 API (errors-as-values, RAII hooks, the `scan::resolve` surface, and the ABI contract).

## Testing

- [Test Coverage Guide](tests/README.md). Suite layout, per-module coverage, and the concurrency and fixture patterns.

## Benchmarks (archive)

Archived benchmark snapshots. Record new measurements in a new folder rather than an edit of existing results.

- [Scanner](analysis/scanner_bench_v3.x/README.md). Rare-byte anchor, prefilter, and batch resolver.
- [Memory](analysis/memory_bench_v3.x/README.md). Validation predicate vs direct SEH-guarded read.
- [Memory (MinGW VEH)](analysis/memory_veh_bench_v3.x/README.md). Vectored-handler fault guard.
- [EventDispatcher](analysis/event_dispatcher_bench_v3.1.0/README.md). Emit and subscribe throughput.
- [AVX-512 verify tier](analysis/avx512_verify_icount/README.md). Instruction-count proxy for the verify throughput gate.
- [Protection-cache comparison](analysis/memory_cache_comparison_v4/README.md). Cache vs uncached decision record (A3).
- [Protection-cache reader admission](analysis/memory_cache_admission_v5/README.md). Closed-bit admission word decision record (P1).
- [Runtime footprint](analysis/runtime_footprint_v4/README.md). Logger and profiler resident bytes and high-water (P2-4).
- [Signature-health corpus](analysis/sighealth_corpus_v4/README.md). Estimate vs ground truth over real x64 code (P1-9).
- [Hot-path costs](analysis/hot_path_bench_v4/README.md). Type identity, guarded hook dispatch, and the asynchronous log producer (B1).
- [Input token query](analysis/input_token_bench_v4/README.md). Per-frame `is_active` cost and the poller-acquire floor (C17).
