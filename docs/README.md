# DetourModKit Documentation

Guides and references for building mods with DetourModKit. New here? Start with the top-level [README](../README.md) for install and a minimal example, then [The Minimal Core](guides/minimal-core.md) for the leanest include set, then reach for the subsystem guide below.

## Guides

### Getting Started

- [The Minimal Core](guides/minimal-core.md) -- the five-header core set and the shortest path from process attach to reading, patching, and hooking game code, for a mod that wants a leaner include than the full umbrella.

### Scanning

- [AOB Signature Scanning](misc/aob-signatures.md) -- pattern syntax, RIP-relative resolution, and patch-proof signature practices.
- [Anchor Registry](guides/scanning/anchors.md) -- declare every patch-fragile constant once and resolve the whole table in a single self-healing pass.
- [Signature Manifest](guides/scanning/signature-manifest.md) -- ship the resolved contract (address plus register/offset/vtable-slot binding) as an editable `.signatures.ini`, so a game-patch repair is a text edit gated into trusted vs safe-disabled instead of a recompiled DLL.
- [Offline Signature Health](guides/scanning/signature-health.md) -- grade a signature's robustness (atom rarity, byte entropy, expected ambiguity) from its declarative bytes alone, before it ever runs against a game, so a brittle anchor is caught at authoring time or in CI.

### Hooking

- [Hook Type Coverage](guides/hooking/hook-type-coverage.md) -- the inline / mid / VMT surface DMK ships, and the hook types (IAT/EAT, software and hardware breakpoints, DBI trace) it deliberately excludes, with the reason for each.
- [VMT Hook Configuration](guides/hooking/vmt-hook-config.md) -- object and per-method virtual-table hooking and the `VmtOptions` pre-flight safety knobs.

### Memory

- [Hot-Path Memory](guides/memory/hot-path-memory.md) -- reading and writing game memory in per-frame hot paths with the `memory::read` / `write` / `walk` and `unchecked::read` primitives.
- [AddressSanitizer and the Memory Scanner](guides/memory/asan-memory-scanner.md) -- why deliberate foreign-memory reads trip ASan, and the pattern to follow for any new foreign-memory primitive.

### RTTI

- [MSVC RTTI Walker](guides/rtti/rtti-walker.md) -- recover concrete type names from runtime vtables across DLL boundaries without `typeid` or `dynamic_cast`.
- [RTTI Self-Heal](guides/rtti/rtti-self-heal.md) -- reverse-identify objects behind pointer slots and self-heal field offsets after a game patch shifts the struct layout.

### Hot-Reload

- [Hot-Reload Development Guide](guides/hot-reload/README.md) -- what DetourModKit guarantees across a logic-DLL unload, and the two topologies that consume it.
- [Config Hot-Reload](guides/hot-reload/config-hot-reload.md) -- the INI filesystem watcher and hotkey-triggered `config::reload()`.

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

- [Migrating from v3.x to v4.0.0](migration/migrating-v3-to-v4.md) -- maps the old surface onto the clean-break v4 API (errors-as-values, RAII hooks, the `scan::resolve` surface, and the ABI contract).

## Testing

- [Test Coverage Guide](tests/README.md) -- suite layout, per-module coverage, and the concurrency and fixture patterns.

## Benchmarks (archive)

Archived benchmark snapshots. Record new measurements in a new folder rather than editing existing results.

- [Scanner](analysis/scanner_bench_v3.x/README.md) -- rare-byte anchor, prefilter, and batch resolver.
- [Memory](analysis/memory_bench_v3.x/README.md) -- validation predicate vs direct SEH-guarded read.
- [Memory (MinGW VEH)](analysis/memory_veh_bench_v3.x/README.md) -- vectored-handler fault guard.
- [EventDispatcher](analysis/event_dispatcher_bench_v3.1.0/README.md) -- emit and subscribe throughput.
- [AVX-512 verify tier](analysis/avx512_verify_icount/README.md) -- instruction-count proxy for the verify throughput gate.
- [Protection-cache comparison](analysis/memory_cache_comparison_v4/README.md) -- cache vs uncached decision record (A3).
- [Runtime footprint](analysis/runtime_footprint_v4/README.md) -- logger/profiler resident bytes and high-water (P2-4).
- [Signature-health corpus](analysis/sighealth_corpus_v4/README.md) -- estimate vs ground truth over real x64 code (P1-9).
