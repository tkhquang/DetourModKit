# DetourModKit

[![Coverage Report ≥ 80%](https://github.com/tkhquang/DetourModKit/actions/workflows/coverage-pages.yml/badge.svg)](https://tkhquang.github.io/DetourModKit/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Features](#features) | [Building](#building-detourmodkit-static-library-via-cmake) | [Testing](#running-unit-tests) | [Guides](#guides) | [Integration](#using-detourmodkit-in-your-mod-project) | [Example](#code-example)

DetourModKit is a full-featured C++23 toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, input handling, configuration management, and DLL lifecycle orchestration. It targets Windows x64 and builds under both MSVC 2022+ and MinGW (GCC 12+).

## Features

| Module | Description | Header |
|--------|-------------|--------|
| AOB Scanner | SIMD-accelerated pattern scanning with full-byte and per-nibble wildcards, cross-region-boundary overlap, RIP resolution, raw pattern batch scanning, multi-candidate cascade resolver with prologue-recovery fallback (E9 near-jump, FF25 indirect-jump, and absolute far-jump shapes), parallel cascade batch resolution, host-EXE cascade overloads, in-code constant (immediate/displacement) extraction, and string-reference (xref) resolution (load site, enclosing function, or cached global pointer slot; fast lea/mov shape scan plus an opt-in Zydis sweep for cmp/push/no-REX shapes) | `scanner.hpp` |
| Hook Manager | Inline, mid-function, and VMT hooks via SafetyHook with cross-module duplicate-hook detection | `hook_manager.hpp` |
| Configuration | INI-based settings with key combo support and hot-reload (file watcher + hotkey) | `config.hpp`, `config_watcher.hpp` |
| Logger | Synchronous singleton logger with format strings | `logger.hpp` |
| Async Logger | Lock-free bounded queue logger with batched writes | `async_logger.hpp` |
| Memory Utilities | Readability checks, region cache, safe pointer reads, typed SEH reads, PE module range queries | `memory.hpp` |
| MSVC RTTI Walker | Recover mangled type names from runtime vtables; pointer-table scan with caller-owned cache; reverse name-to-vtable resolver and cached identity handle | `rtti.hpp` |
| RTTI Self-Heal | Reverse-identify the object behind a pointer slot (typed-error and ordered candidate-fallback forms); self-heal a field offset after a patch shifts the struct layout; rigid multi-field drift solver; drift-telemetry report with a durable, diffable manifest (open-failure distinguished from corrupt) | `rtti_dissect.hpp`, `drift_manifest.hpp` |
| Anchor Registry | One declarative table over the self-healing backends (vtable-by-name, AOB/RIP cascade, in-code constant, string xref, pinned literal) plus two-signal quorum corroboration with sub-anchor independence checks, optional post-resolve validators and opt-in validator policies, a manifest quality diagnostic, an address-independent evidence fingerprint for manifest diffing, opt-in parallel table resolution, and a per-game scan profile (broad-mode default, candidate order, backend deny-list), resolved and reported in a single pass | `anchors.hpp`, `profile.hpp` |
| Event Dispatcher | Typed pub/sub with RAII subscriptions | `event_dispatcher.hpp` |
| Profiler | Scoped timing with Chrome Tracing export (zero-cost when disabled) | `profiler.hpp` |
| Format Utilities | `std::format` helpers for addresses, bytes, and VK codes; string trim | `format.hpp` |
| Filesystem Utilities | Module directory resolution (wide-string and UTF-8 APIs) | `filesystem.hpp` |
| Math Utilities | Angle conversions (header-only) | `math.hpp` |
| Version Macros | Compile-time version checking generated from CMake | `version.hpp` |
| Input System | Hotkey monitoring with background polling (keyboard/mouse/gamepad) | `input.hpp`, `input_codes.hpp` |
| Mod Bootstrap | DllMain scaffolding, instance mutex, process gate, lifecycle worker | `bootstrap.hpp` |
| Diagnostics | Consumer-queryable counters for intentional loader-lock leak/detach events per subsystem, a process-wide typed event bus for scanner-fault and hook install/enable/disable/remove transitions, and a one-call snapshot aggregator over the counters, hook counts, anchor quality, and drift report | `diagnostics.hpp`, `diagnostics_dump.hpp` |
| Stoppable Worker | RAII named `std::jthread` wrapper, loader-lock-safe teardown | `worker.hpp` |

<details>
<summary><strong>AOB Scanner</strong></summary>

- Find array-of-bytes (signatures) in memory with full-byte literals, full wildcards (`??` / `?`), and per-nibble wildcard tokens (`4?` fixes the high nibble, `?5` the low nibble) for an operand where only one nibble is invariant across builds
- Rare-byte anchor heuristic: `parse_aob()` scores every fully-known literal byte in the pattern against a small frequency table (`0x00`, `0xCC`, `0x48`, `0x8B`, ...) and caches the rarest byte's index on `CompiledPattern::anchor` (a per-nibble byte is never chosen, since the prefilter needs an exact byte; an all-nibble pattern still resolves via a masked compare at every position). `find_pattern()` drives its `memchr` sweep on that byte, so a signature like `48 8B 05 37 DE AD BE EF` anchors on `0x37` rather than the very common `0x48`, cutting false candidate hits by an order of magnitude on realistic code
- SIMD-accelerated prefilter and pattern verification:
  - The `memchr` anchor prefilter and the verify pass both tier at runtime: AVX2 (32 bytes/iteration, runtime-detected on Haswell+ CPUs) over an SSE2 baseline (16 bytes/iteration), with a scalar tail. The self-provided prefilter does its own byte comparisons (never calling libc) so the AddressSanitizer interceptor cannot fault on the scanner's in-bounds reads
  - Opt-in AVX-512F + AVX-512BW verify tier (64 bytes/iteration), gated behind the `DMK_ENABLE_AVX512` build option and a runtime CPUID + XGETBV check; off by default and never selected on a CPU that lacks it (it falls back to AVX2)
- `|` offset markers for targeting a specific instruction within a wider pattern (e.g., `"48 8B 88 B8 00 00 00 | 48 89 4C 24 68"` sets the offset to byte 7)
- Nth-occurrence matching (1-based) for patterns that hit multiple locations
- RIP-relative instruction resolution for extracting absolute addresses from x86-64 code (returns `std::expected` with typed `RipResolveError` for actionable diagnostics)
- `scan_executable_regions()` for scanning all committed executable pages in the process - useful for games with packed or protected binaries that unpack code into anonymous memory outside any loaded module (pure-execute pages without a read bit are skipped to avoid access violations; a region decommitted or reprotected concurrently mid-sweep is skipped rather than faulting the host on MSVC, where each region read runs inside a structured-exception guard)
- `scan_readable_regions()` -- the data-section sibling of `scan_executable_regions()` -- sweeps every committed readable page (`.rdata` / `.data`, read-only heaps) to reach C++ vtables, RTTI type descriptors, and read-only metadata the executable-only sweep cannot see (guard / no-access / uncommitted pages are skipped); opt a cascade into it with `resolve_cascade(..., ScannerKind::Readable)`
- The region-walking sweeps (`scan_executable_regions` / `scan_readable_regions` and the module-scoped scans) carry a `pattern_len - 1` overlap across adjacent accepted `VirtualQuery` regions, so a signature that straddles a protection split (two adjacent regions whose base protections differ, e.g. after a sibling `VirtualProtect` carves up `.text`) is still found, without re-counting a match that lies wholly inside one region
- `scan_regions_batch()` / `scan_module_batch()` -- opt-in fork-join batch scanners that resolve many compiled patterns concurrently (whole process or one mapped image). Each `BatchScanItem` is one independent serial scan distributed across a transient worker pool, so a startup set of N signatures resolves in roughly the time of the slowest single scan rather than their sum; results come back in input order, each item fails closed on a null/empty pattern, zero occurrence, or no match, and patterns are shared read-only (a compiled `CompiledPattern` is immutable during scanning, so no cloning). Setup/control-plane only -- it spawns and joins threads, so never call it from a hook/input callback or under the loader lock
- `resolve_cascade_batch()` -- opt-in fork-join resolver for startup target tables. Each `CascadeRequest` dispatches to the existing serial cascade resolver (whole-process, module-scoped, with or without prologue fallback), so candidate priority, uniqueness checks, typed errors, and `winning_name` aliasing stay identical to the one-at-a-time calls while results come back in input order
- `resolve_cascade()` and the module-scoped `resolve_cascade_in_module()` -- ordered multi-candidate resolution (try signatures in priority order, return the first that resolves), with an optional hooked-prologue recovery pass that recovers an `E9` near-jump, an `FF 25` RIP-relative indirect jump (both the separate-slot form and the 14-byte `FF 25 00000000 <abs64>` inline-target form), and a `mov rax, imm64; jmp rax` overwritten prologue (so a target inline-hooked by another mod with a near or far jump is recovered); the `_in_module` variants confine the scan to one mapped image `[base, end)` and reject out-of-module resolutions, so a generic signature that also matches inside another injected module (a graphics overlay, a sibling mod) cannot shadow the correct in-module target. By default each candidate must match uniquely in the scanned scope: an ambiguous signature (more than one match) falls through to the next candidate instead of silently committing to an arbitrary match, so a too-loose pattern surfaces as a clean failure to fix rather than a wrong hook. Set `require_unique = false` per candidate only to opt out a deliberately non-unique, separately-verified candidate
- `resolve_cascade_in_host_module()` / `resolve_cascade_in_host_module_with_prologue_fallback()` -- one-line convenience overloads that scope a cascade to the host EXE (`host_module_range()`), removing the boilerplate of building the range at every call site. They return `ResolveError::InvalidRange` if the host range cannot be determined. Use them only when the target lives in the host EXE; for a game whose logic is in a separate module (an engine DLL), resolve that module's range and call `resolve_cascade_in_module()` instead
- `read_code_constant(cc, range?)` -- the code-side twin of the RTTI self-heal: declare an instruction site (an AOB cascade) plus which operand to read, and it decodes the live instruction and returns the current immediate or `[reg + disp]` displacement, so a hand-read array stride or struct displacement re-derives itself after a patch instead of being a baked literal. It always decodes (the `nominal` field is telemetry only, never a short-circuit, so a same-shape / different-value drift is reported as the new value), indexes the **visible** operands, resolves a RIP-relative operand to its absolute target, and fails closed (`DecodeFailed` / `UnexpectedShape` / `OperandOutOfRange`). Built on a Zydis decoder kept entirely inside the implementation, so no consumer needs Zydis headers
- `is_likely_function_prologue(addr)` heuristic that rejects scan poison (zero pages, alignment pads, bare RET stubs) while still accepting JMP-shaped patched prologues so nested-hook scenarios resolve

</details>

<details>
<summary><strong>Hook Manager</strong></summary>

- C++ wrapper around [SafetyHook](https://github.com/cursey/safetyhook) for creating and managing hooks
- **Inline hooks** and **mid-function hooks** - target functions by direct address or AOB scan
  - **Same-address layering is teardown-safe**: when more than one managed hook stacks on one address, bulk teardown (`remove_all_hooks`, `shutdown`, the destructor) disables and destroys them newest-first so each prologue restore lands on still-valid bytes instead of a freed trampoline. `HookConfig::fail_if_already_hooked` refuses a second managed hook on an address this HookManager already hooks (a registry-exact check, in addition to the prologue-byte heuristic that catches foreign-module hooks); explicit single removals must still be ordered newest-first by the caller.
  - **Unsafe-prologue pre-flight**: inline and mid hook creation decodes the target's first byte under a fault guard and flags a leading `E8` (call rel32) or `0xCC`/`0xCD` (breakpoint) prologue -- a relative call whose displacement would be relocated wrongly, or an already-patched / padding entry. `HookConfig::prologue_policy` selects `InlineProloguePolicy::Warn` (the default: log and install anyway, preserving prior behaviour) or `Fail` (refuse with `HookError::TargetPrologueUnsafe`).
- **VMT (virtual method table) hooks** - clone an object's vtable and replace individual method slots by index
  - Per-object interception of virtual calls (e.g., D3D device methods, game AI interfaces)
  - Apply a single hooked vtable to multiple objects
  - Safe callback-based access to hooked methods via `with_vmt_method()`
  - **`VmtHookConfig` symmetric with inline `HookConfig`**: opt-in `fail_if_already_hooked` refuses a second create/apply whose vptr is already on a clone owned by this HookManager (the silent double-clone bug class), and opt-in `fail_on_non_function_pointer` pre-flight-decodes the first byte of the original vtable slot to reject int3 padding/breakpoints and same-module jump stubs. Both default to off; the single-arg `create_vmt_hook(name, object)` and `apply_vmt_hook(name, object)` overloads are preserved for backward compatibility.
- **Convenience helpers**: `try_install_inline` / `try_install_inline_aob` / `try_install_mid` / `try_install_mid_aob` fuse `create_*_hook` with single-line Error logging on failure, returning `optional<string>` of the registered name
- **Duplicate-target query**: `HookManager::is_target_already_hooked(addr)` reports whether the local registry already patches a given address with an inline or mid hook (does not see hooks installed by other statically-linked DMK consumers in the same process)
- **Batch toggling**: `enable_hooks` / `disable_hooks` (by name span) and `enable_all_hooks` / `disable_all_hooks` toggle many hooks under one lock acquisition for startup and hot-reload phases, returning the count affected (ergonomics, not a performance change: SafetyHook installs via a vectored exception handler and does not suspend threads)

</details>

<details>
<summary><strong>Configuration System</strong></summary>

- Load settings from INI files (powered by [SimpleIni](https://github.com/brofield/simpleini))
- Mods register configuration variables; the kit handles parsing and value assignment
- Key combo support via `register_key_combo`:
  - Format: `modifier+trigger` (e.g., `Ctrl+Shift+F3`)
  - Comma-separated independent combos (e.g., `F3,Gamepad_LT+Gamepad_B`)
  - Named keys (`Ctrl`, `F3`, `Mouse1`, `Gamepad_A`), hex VK codes (`0x72`), and mixed formats
  - Opt-out sentinels: an empty value or the literal `NONE` (case-insensitive, whole-string only) leaves the binding unbound silently. A non-empty value whose every token fails to parse is logged at WARNING level naming the binding and the offending raw string.
- Convenience helpers: `register_log_level` (parses an INI string into a `Logger::set_log_level` call) and `register_atomic<T>` for `int`/`bool`/`float` (writes the parsed value into a caller-supplied `std::atomic<T>` with `memory_order_relaxed`; the 4-argument overload uses the atomic's current value as the registration default)
- **Hot-reload** (see [Config Hot-Reload Guide](docs/config-hot-reload/README.md)):
  - `Config::reload()` re-runs every registered setter against the last-loaded INI without touching registrations; skips setters when the on-disk bytes are byte-identical to the last load (FNV-1a content hash)
  - `Config::enable_auto_reload()` starts a background `ConfigWatcher` (`config_watcher.hpp`) that debounces editor save-flurries and triggers `reload()` automatically; returns an `AutoReloadStatus` enum indicating outcome
  - `Config::register_reload_hotkey()` wires a user-configurable key combo to `reload()` via the kit `InputManager`; the press callback hands off to a dedicated reload-servicer thread so the input poll thread never blocks on INI parsing

</details>

<details>
<summary><strong>Config Hot-Reload</strong></summary>

Two mechanisms share the same `Config::reload()` primitive - use either or both:

```cpp
// 1. Initial load stashes the INI path.
Config::load("mymod.ini");

// 2. Filesystem watcher: auto-reload on file change (250 ms debounce).
//    on_reload receives true when setters actually ran, false when the
//    content-hash short-circuit skipped the work.
(void)Config::enable_auto_reload(std::chrono::milliseconds{250},
                                 [](bool content_changed)
                                 {
                                     if (content_changed)
                                     {
                                         Logger::get_instance().info("Config reloaded");
                                     }
                                 });

// 3. Hotkey: user presses Ctrl+F5 (or whatever the INI says) to force reload.
Config::register_reload_hotkey("ReloadConfig", "Ctrl+F5");
InputManager::get_instance().start();
```

See the [Config Hot-Reload Guide](docs/config-hot-reload/README.md) for the thread-safety contract, debounce rationale, rename-swap-save handling, and the list of settings that are safe to hot-reload vs restart-required.

</details>

<details>
<summary><strong>Logger</strong></summary>

- Flexible singleton logger for outputting messages to a log file
- Configurable log levels, timestamps, and prefixes
- Async logging for high-throughput scenarios
- Format string placeholders for concise log messages
- Concurrent file access via Win32 shared-access file handles (log files readable by external tools while logging is active)
- `is_enabled(LogLevel)` for gating expensive trace-only work

</details>

<details>
<summary><strong>Async Logger</strong></summary>

- Lock-free, bounded queue-based async logger decoupling log production from file I/O
- Minimal latency on the producer side with batched writes on the consumer thread; a parked writer is woken promptly through a pending-count/flag handshake, so no message waits out the flush interval
- Configurable overflow policies: DropNewest / DropOldest / Block / SyncFallback
- Bounded Block policy with 16 ms default timeout (one frame at 60 fps) to prevent thread starvation
- Inline buffer optimization for messages <= 512 bytes; a formatted log line that fits is rendered into a stack buffer and never materializes a heap string
- Message size validation with truncation for messages > 16 MB

</details>

<details>
<summary><strong>Memory Utilities</strong></summary>

- Functions for checking memory readability/writability and writing bytes to memory
- Optional memory region cache with sharded SRWLOCK concurrency, LRU eviction, and stampede coalescing. Each shard is cache-line-aligned with its lock word and stampede flag stored inline, and in-flight reader liveness is tracked in cache-line-padded per-thread stripes summed at shutdown rather than a single global counter, so concurrent readers do not re-serialize on one shared cache line
- `is_readable_nonblocking()` - tri-state (readable/not-readable/unknown) for latency-sensitive threads
- `read_ptr_unsafe()` - safe pointer reads in hot paths (SEH-protected on MSVC, guarded by a process-wide vectored exception handler on MinGW, so the success path issues no per-call VirtualQuery)
- `read_ptr_unchecked()` - inline header-only variant with a configurable lower-bound guard plus a `USERSPACE_PTR_MAX` ceiling for pointer chain traversal without per-call SEH overhead (caller must guarantee structural pointer validity)
- `seh_read<T>()` / `seh_read_bytes()` - typed SEH-guarded reads for arbitrary trivially copyable T (and contiguous byte ranges), used to walk torn pointer chains and parse PE headers without per-site `__try` boilerplate. Returns `std::optional<T>` / `bool` so callers can distinguish "read faulted" from "read returned zero"
- `module_range_for(addr)` / `own_module_range()` / `host_module_range()` - PE image range queries (base + SizeOfImage) for sanity-checking that a resolved vtable or return address lives inside the game image vs the heap or an injected DLL. Per-HMODULE cache for `module_range_for`; magic-static cache for the own and host variants
- `Memory::contains(range, p)` - constexpr point-in-range test

</details>

<details>
<summary><strong>MSVC RTTI Walker</strong></summary>

- Walks the MSVC x64 RTTI layout (RTTICompleteObjectLocator at `vtable - 8`, TypeDescriptor at `col + 0x0C`, mangled name at `td + 0x10`) to recover an object's concrete type without committing to a fragile vtable address
- `Rtti::type_name_of(vtable)` returns the mangled name (e.g. `.?AVMyClass@ns@@`) as `std::optional<std::string>`; `type_name_into(vtable, buf, len)` writes into a caller buffer for zero-allocation per-frame probes
- `Rtti::vtable_is_type(vtable, expected)` performs a byte-exact NUL-terminated comparison against an expected mangled name (single SEH-guarded read of `expected.size() + 1` bytes; no allocation)
- `Rtti::find_in_pointer_table(table, slot_count, expected, vtable_cache?, stride?)` scans a sparse pointer table for the first slot whose object has the given type; an optional caller-owned `std::atomic<uintptr_t>` cache slot lets repeated calls take a single qword-compare fast path after the first match
- `Rtti::vtable_for_type(mangled, range?)` is the reverse of `vtable_is_type`: it sweeps a module's readable, non-executable sections for the COL whose name matches and returns the primary (COL.offset == 0) vtable, so a mod keys on a stable class name instead of a patch-fragile vtable literal. `vtables_for_type(...)` returns every sub-object vtable (multiple/virtual inheritance gives one name many vtables); an ambiguous primary fails closed. Returning the COL-anchored vtable address (not its folded slot contents) keeps identity correct under the linker's `/OPT:ICF`
- `Rtti::TypeIdentity(mangled, range?)` resolves the primary vtable once, then `matches(vtable)` is a single qword compare -- a name-keyed, patch-surviving per-frame identity check
- Image-base recovery via `COL.pSelf` (canonical IDA/Ghidra approach) so vtables in any loaded module resolve correctly without trusting `GetModuleHandleEx`; the loader call is used only as a fallback for the x86 signature
- All entry points are noexcept and SEH-guarded; unreadable pages, missing COLs, and zero RVAs never fault. Failure surfaces through the return type of each API: `std::nullopt` for the `std::optional` returns (`type_name_of`, `find_in_pointer_table`), `false` for the boolean return (`vtable_is_type`), and `0` for the size return (`type_name_into`, which additionally sets `out[0] = '\0'` on failure)

</details>

<details>
<summary><strong>RTTI Self-Heal (reverse dissection + offset recovery)</strong></summary>

- The reverse direction of the walker, slot-first. It reuses the same verified COL prelude (module-bound-checked, SEH-guarded) rather than duplicating it, and every entry point is noexcept and fails closed
- `Rtti::identify_pointee_type(slot_addr, out)` reverse-identifies the object a pointer slot refers to. It accepts whichever shape resolves -- a pointer-to-object (deref once, resolve the pointee's vtable) or a direct object base (the slot is the object, its value is the vtable) -- so an object whose vtable lives in a different DLL than the struct still resolves. The reported `was_pointer` flag is a result, not a precondition. `identify_pointee_typed(...)` is the typed form returning the specific fail-closed reason (`IdentifyError`) instead of a bool, and `identify_pointee_type_or(candidate, out, fallbacks...)` probes a primary slot then ordered fallback slots, returning the first that resolves and preserving the primary's error when all fail
- `Rtti::reverse_scan_block(start, slot_count, out, stride?)` RTTI-labels every pointer slot in a struct (allocating triage tool; init-time only)
- `Rtti::heal_landmark(lm)` / `Rtti::heal_offset(lm)` -- the self-healing offset resolver. Record a landmark once (`"a field of mangled type T sits near offset O within struct S"`); after a small patch shifts the layout, it scans a `+/-` window around the nominal offset, reverse-RTTI-identifies each slot, and returns the healed field offset. The nominal offset is checked first and short-circuits, the widened scan prefers the nearest match, and an equidistant tie fails closed as `Ambiguous` -- the same `require_unique` philosophy the module-scoped cascade uses, transplanted from an AOB scan to a slot scan
- For an embedded object that may use multiple inheritance, record the landmark with `Indirection::CompleteObject`: it matches only the primary subobject (`COL.offset == 0`), so a heal can never latch a secondary base's adjacent vtable (whose COL still names the complete type) and report an offset shifted by the subobject delta. `HealHit::col_offset` reports that delta; when `was_pointer == false`, a nonzero value means the direct-object match landed on a secondary base
- `Rtti::solve_fingerprint(base, landmarks, window)` recovers a single uniform shift across several co-moving fields when one landmark alone would be ambiguous in a dense region
- `Rtti::heal_report(landmarks, out)` heals a set in one pass and fills a `DriftEntry` per landmark (`{name, nominal_offset, healed_offset, delta, ok}`) -- a structured "what moved and by how much" report for changelogs, derived purely from the existing heal path
- Consumers cache the healed **offset** (a `std::ptrdiff_t`), never an absolute address, so a cached delta stays valid across instances and sessions. The library stores nothing: no registry, no lifetimes
- Init-time / re-heal-on-miss, not per-frame: each probe runs the syscall-heavy module-range lookup up to twice. The search window is hard-capped; the hot heal path allocates nothing

</details>

<details>
<summary><strong>Anchor Registry</strong></summary>

- One declarative table (`Anchors::Anchor[]`) over the self-healing backends, so every magic constant a mod depends on is declared once with its kind and inputs, then resolved and reported in a single pass instead of a scattered wall of hand-maintained offsets and per-call-site resolvers
- `AnchorKind` covers the backends that resolve from a module range alone: `VtableIdentity` (`Rtti::vtable_for_type`), `RipGlobal` (an AOB/RIP cascade returning an absolute address), `CodeOperand` (`Scanner::read_code_constant`), `StringXref` (`Scanner::find_string_xref`, the most update-resilient kind: the unique instruction or enclosing function that references an immutable string literal), and `Manual` (a pinned literal, surfaced as at-risk in a report). `Quorum` layers corroboration on top: it accepts a target only when two independent sub-anchors resolve and agree (exact or within a tolerance), so a coincidental match must fool both signals. `CallArgHome` is reserved for a future prologue-dataflow backend and reports `Unsupported`
- Any backend-resolved anchor may carry an optional `validator` (`bool(*)(value, context) noexcept`) that screens the resolved value and fails the anchor closed when it returns false, letting a caller assert a domain invariant a generic backend cannot know
- `Anchors::resolve(anchor, range?)` resolves one entry; `resolve_all(anchors, out, range?)` fills a `ResolvedAnchor` report (`{label, kind, status, value}`), and `resolve_all_parallel` does the same work through an opt-in fork-join table resolver. Profile-aware callers have matching `resolve_all_with_profile` and `resolve_all_with_profile_parallel` entry points. Resolution is idempotent and side-effect-free, so re-heal-on-miss is just re-running `resolve` on the failing anchor
- RTTI pointer-field offset healing (`heal_landmark`) is intentionally not a registry kind: it needs a runtime struct base resolved from another anchor, so it is driven directly once that base is known
- `Anchors::anchor_fingerprint(anchor)` hashes only an anchor's declarative resolution evidence -- its kind plus the kind's inputs (vtable mangled name, cascade pattern bytes and decode params, string-xref literal and shape flags, or the `Manual` literal) -- and deliberately excludes any resolved address. Two anchors that resolve the same target through the same evidence share a fingerprint even when the target moved between game versions, so a future manifest diff can tell "same evidence, new address" (expected drift the anchor self-healed) from "new evidence path" (the signature itself was rewritten). A `Quorum` combines its two sub-anchors' fingerprints order-independently; the result is a stable 64-bit FNV-1a hash, not a cryptographic digest

</details>

<details>
<summary><strong>Event Dispatcher</strong></summary>

- Typed pub/sub event system with RAII subscription management
- Each `EventDispatcher<Event>` manages a single event type
- Reader-side fast path with no user-visible mutex: `emit()` / `emit_safe()` acquire-load a `std::shared_ptr<const vector>` snapshot and iterate with no reader lock; the snapshot load is genuinely lock-free on toolchains with a DWCAS-backed `std::atomic<std::shared_ptr<T>>` and may use an implementation-internal bit lock on toolchains that do not (for example MSVC's STL)
- Zero-subscriber fast path: `emit()` / `emit_safe()` short-circuit on a single `memory_order_acquire` counter load, skipping the snapshot load entirely (wait-free on every toolchain)
- `subscribe()` / `unsubscribe()` are copy-on-write under a small writer mutex
- Subscriptions auto-unsubscribe on destruction
- Handlers invoked in subscription order (preserved across unsubscribe)
- Thread-local reentrancy guard detects and rejects subscribe/unsubscribe calls from within a handler, keeping the no-mutation-during-emit invariant intact
- Compose multiple dispatchers for multi-event architectures
- `emit_safe()` for exception-tolerant dispatch (recommended for hook callbacks)
- Safe when the dispatcher is destroyed before its subscriptions (weak_ptr guard)
- Trade-off: `subscribe()` / `unsubscribe()` allocate a new handler list each call (O(n) publish). Suited for 1-10 subscribers per event and write-rarely access patterns, which matches typical mod usage

</details>

<details>
<summary><strong>Profiler</strong></summary>

- Opt-in scoped timing instrumentation with zero overhead when disabled
- Compile-time gated via `DMK_ENABLE_PROFILING`
- When enabled, records lock-free timing samples (~50 ns per scope) into a fixed-size ring buffer (64K samples, ~1.5 MB)
- Odd/even sequence counter per sample slot so `export_chrome_json()` can safely skip in-flight writes without torn reads; sequence updates are unconditional `fetch_add` increments (open and close), so concurrent producers racing on the same ring slot can never roll a slot's sequence backwards
- Exports to [Chrome Tracing JSON](https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/preview) format viewable in `chrome://tracing` or [Perfetto](https://ui.perfetto.dev)
- Instrument with `DMK_PROFILE_SCOPE("name")` or `DMK_PROFILE_FUNCTION()` macros; `DMK_PROFILE_SCOPE` requires a string literal (enforced at compile time via `const char (&)[N]`) so the stored name pointer always points at static program memory; export via `Profiler::get_instance().export_to_file()`

</details>

<details>
<summary><strong>Format, Filesystem, Math, and Version Utilities</strong></summary>

- **Format** (`format.hpp`): Inline formatting helpers for memory addresses, byte values, VK codes, and hex integer vectors using `std::format`. Also includes string trim utilities.
- **Filesystem** (`filesystem.hpp`): Module directory resolution via `get_runtime_directory()` (wide-string) and `get_runtime_directory_utf8()` (UTF-8).
- **Math** (`math.hpp`): Angle conversions (header-only).
- **Version** (`version.hpp`): Compile-time version checking via `DMK_VERSION_MAJOR`, `DMK_VERSION_MINOR`, `DMK_VERSION_PATCH`, `DMK_VERSION_STRING`, and `DMK_VERSION_AT_LEAST(major, minor, patch)`. Generated from CMake's `project(VERSION)` at configure time.

</details>

<details>
<summary><strong>Input System</strong></summary>

**Input sources and modes:**

- Keyboard, mouse, and XInput gamepad input via a unified `InputCode` tagged type (`InputSource` + button code)
- Press (edge-triggered) and hold (level-triggered) input modes with modifier combinations
  - AND logic for modifiers, OR logic between independent combos
- Strict modifier matching - a binding only fires when exactly its declared modifiers are held (pressing `Shift+V` will never trigger a plain `V` binding)
- Multiple independent combos can share a single binding name for cross-device hotkeys (e.g., keyboard F3 OR gamepad LT+B)
- Gamepad analog triggers (LT/RT) and thumbstick axes treated as digital buttons with configurable deadzone thresholds
- Focus-aware by default - input events are ignored when the process does not own the foreground window

**Threading and lifecycle:**

- Available as an RAII `InputPoller` building block or via the thread-safe `InputManager` singleton
- Two-phase initialization (construct then start) for safe thread launching
- `condition_variable_any` with `stop_token` for responsive cooperative shutdown
- Exception-safe callback invocation
- Automatic hold release on shutdown
- Loader-lock-aware shutdown: background threads are safely detached instead of joined when called from `DllMain` or `FreeLibrary` context

**Performance:**

- Hash-map-backed `is_binding_active()` query for low-overhead cross-thread state reads (e.g., from render hooks at 60+ fps)
- Generation-checked `BindingToken`s for the highest-frequency consumers: `acquire_binding_token(name)` resolves a name once, then the `is_binding_active(token)` overload queries it every frame without the per-call name hash. The token carries the binding generation it was minted at; any reshape (register / remove / clear / combo update / consume change) advances the generation, so a stale token fails closed (returns false) instead of reading a different binding, and `binding_token_current(token)` lets a consumer detect the reshape and re-acquire. The generation is process-wide unique, so a token can never alias a different poller after a shutdown / start cycle
- SRWLOCK-backed reader/writer synchronization for live binding reshapes, using the same native Windows lock primitive as hook registries and memory caches
- Multiple bindings per name for multi-combo hotkeys
- Keyboard and mouse virtual-key reads are memoized once per distinct VK per poll cycle, giving every binding in that cycle one coherent sample while avoiding duplicate `GetAsyncKeyState` calls
- Lock-free `is_running()` via atomic flag
- O(1) reverse name lookup for `input_code_to_name()`

**Gamepad and polling:**

- XInput polled once per cycle; skipped entirely when no gamepad bindings are registered
- Reconnection attempts throttled to every 2 seconds when no controller is connected, avoiding per-cycle overhead of `XInputGetState` on disconnected slots

**Mouse wheel and input suppression (opt-in):**

- Bind the mouse wheel with `WheelUp` / `WheelDown` / `WheelLeft` / `WheelRight`. The wheel has no virtual-key code, so it is captured by a window-procedure hook the poll loop installs lazily only when a wheel binding exists; each notch fires once as a Press edge.
- `InputManager::set_consume(name, true)` hides a binding's trigger from the game so the mod and the game do not both act on it -- applied per binding, so one binding can pass through while another is blocked. Honored for digital gamepad buttons (D-pad, face buttons, bumpers, stick clicks) via an `XInputGetState` hook, and for the mouse wheel; analog triggers, stick directions, keyboard, and mouse-button suppression are not provided (the gamepad detour clears only the digital `wButtons` bitmask). The fix targets the classic chord case (e.g. "LB + D-pad" zoom) where releasing the modifier a frame before the trigger would otherwise leak a bare trigger: suppression is latched to the trigger button's own release, plus a short grace window. Only the trigger is hidden, not the modifier.
- `Config::register_consume_flag(section, ini_key, log_name, binding_name, default)` drives the same flag from the INI, so the choice lives next to the combo (register the binding first, then the flag):

  ```ini
  [Hotkeys]
  SetXToggle = Gamepad_LB+Gamepad_RB    ; passes through to the game
  SetYToggle = Gamepad_LB+Gamepad_Y     ; blocked from the game
  SetYToggle.Consume = true
  ```

  ```cpp
  im.register_press("set_x", cfg.set_x, []{ /* ... */ });
  im.register_press("set_y", cfg.set_y, []{ /* ... */ });
  DMKConfig::register_consume_flag("Hotkeys", "SetYToggle.Consume", "Set Y Consume", "set_y", false);
  ```
- Both hooks are opt-in: a mod that registers neither a wheel binding nor a `consume` binding installs nothing and the input system stays purely observational.

**Configuration integration:**

- Load input codes from INI files (named keys, hex VK codes, or mixed)
- Named key resolution uses binary search for efficient lookup
- `register_press` and `register_hold` accept `KeyComboList` directly for zero-boilerplate binding of config-parsed key combos
- Live registration: `register_press` / `register_hold` append bindings to a running poller, and `clear_bindings()` / `remove_binding_by_name()` drop bindings without stopping the poll thread, so consumers can re-arm input on hot-reload without a full restart
- `Config::register_press_combo` / `Config::register_hold_combo` fuse an INI combo item, the matching `InputManager::register_press` / `register_hold` binding, automatic rebind on `reload()`, and an `InputBindingGuard` cancellation token into one call. The hold variant's guard synthesizes a single balancing `on_state_change(false)` when cancelled mid-hold, so tearing a hold down cannot strand the consumer in the held state
- Both combo registrars take an optional per-binding `consume` facet: pass `consume` to register a `"<ini_key>.Consume"` bool inline (wired to `set_consume`) instead of a separate `register_consume_flag` call. `std::nullopt` (the default) registers no extra key and preserves the prior behavior exactly; suppression honors the same gamepad-digital + mouse-wheel scope noted above, so a `.Consume` key on a keyboard-only binding is inert

</details>

<details>
<summary><strong>Mod Bootstrap</strong></summary>

- `DMKBootstrap::on_dll_attach()` / `on_dll_detach()` pair that replaces the manual `DllMain` + `CreateThread` + `InitThread` scaffolding every mod would otherwise write
- Configures `Logger` (`prefix` + `log_file`) and enables async logging (`async_cfg`) automatically before the user init function runs, so the first message travels the async path
- Optional process-name gate (`game_process_name`): short-circuits attach when the DLL is loaded into a non-matching executable (case-insensitive basename)
- Optional per-PID named mutex (`instance_mutex_prefix`): blocks duplicate ASI loads from double-initializing
- Runs `init_fn` and `shutdown_fn` on a dedicated Win32 worker thread off the loader lock, so both are free to call into Win32 APIs that would otherwise deadlock under `DllMain`
- `DMK_Shutdown()` is invoked unconditionally after the user shutdown function, guaranteeing the correct teardown order
- `request_shutdown()` signals the worker to drain so a mod can trigger its own unload before `FreeLibrary` and keep teardown off the loader lock (see the [Hot-Reload Guide](docs/hot-reload/README.md))
- Handles the `DLL_PROCESS_DETACH` process-exit vs dynamic-unload distinction automatically via `lpvReserved`
- `on_logic_dll_unload(hook_names, binding_names)` drops only the per-Logic-DLL hooks and bindings owned by the caller, leaving Logger and Config alive for whichever container hosts the next Logic-DLL incarnation
- `on_logic_dll_unload_all()` is the catch-all variant for callers without an explicit name registry; in a host that loads multiple Logic DLLs sharing one DMK instance, prefer the named-list overload because the catch-all rips out every Logic DLL's state
- Hot-reload teardown: `Bootstrap::on_logic_dll_unload` is the lighter alternative to `DMK_Shutdown` for multi-DLL or fast-iteration setups (see [docs/hot-reload/README.md](docs/hot-reload/README.md))

</details>

<details>
<summary><strong>Stoppable Worker</strong></summary>

- `DMKStoppableWorker` - RAII wrapper around `std::jthread` with a descriptive name, `std::stop_token` cooperation, and loader-lock-safe teardown
- Body is invoked with a `std::stop_token` and must poll `stop_requested()` cooperatively
- Destructor (and explicit `shutdown()`) requests stop and joins the thread; when called under the Windows loader lock the thread is detached instead, pinning the module so code pages stay mapped
- Non-copyable and non-movable: the name, stop state, and thread handle form a single invariant
- Replaces the hand-rolled `std::atomic<bool>` + `std::thread` + bounded-join pattern typically written for mod background tasks (deferred scanning, periodic polling, async I/O)

</details>

<details>
<summary><strong>Diagnostics</strong></summary>

- `Diagnostics::record_intentional_leak` / `intentional_leak_count` / `total_intentional_leaks` / `reset_intentional_leaks` -- per-subsystem tallies for the deliberate leak/detach paths DMK takes under the Windows loader lock (a teardown where a join or free would risk deadlock or use-after-unmap). Each site fires at most once per process; relaxed atomics, allocation-free, safe from a `noexcept` destructor
- Process-wide typed event bus: `Diagnostics::scanner_faults()` and `Diagnostics::hook_lifecycle()` each return one stable `EventDispatcher<>` for the process lifetime. The stateless scanner emits a `ScannerFaultEvent` (skipped-region count + scanned window) once per sweep that skips a region faulting mid-scan; every `HookManager` emits a `HookLifecycleEvent` (`name`, `HookKind`, `HookTransition`) after a create / enable / disable / remove transition completes and its registry locks are released, so a handler runs outside the critical section. Failed operations and idempotent no-ops emit nothing. Both use `emit_safe`, so with no subscribers the cost is a single atomic load after the dispatcher has been constructed
- `Diagnostics::collect(hooks, anchor_report?, drift_report?)` aggregates the live diagnostics into one `Diagnostics::Snapshot` -- the leak tallies, `get_hook_counts()` folded into active / disabled / total, `assess_quality()` over a resolved anchor report, and a healed/failed count over a `heal_report()` drift report -- so a diagnostics command can capture a one-shot health view in a single call. Setup/control-plane only (it takes a shared lock to read hook counts)

</details>

## Testing

* **Comprehensive Test Suite:** Full unit test coverage for all modules using GoogleTest.
* **Code Coverage:** Automated coverage analysis with 80% minimum line coverage gate in CI.
* **Coverage Tools:** Built-in scripts for parsing and analyzing coverage reports.

For detailed coverage analysis and test architecture, see the [Test Coverage Guide](docs/tests/README.md).

## Guides

* [AOB Signature Scanning Guide](docs/misc/aob-signatures.md) - Pattern syntax, RIP-relative resolution, and patch-proof signature practices
* [MSVC RTTI Walker Guide](docs/misc/rtti-walker.md) - Recover concrete type names from runtime vtables across DLL boundaries without `typeid`/`dynamic_cast`
* [RTTI Self-Heal Guide](docs/misc/rtti-self-heal.md) - Reverse-identify objects behind pointer slots and self-heal field offsets after a game patch shifts the struct layout
* [Anchor Registry Guide](docs/misc/anchors.md) - Declare every patch-fragile constant once and resolve the whole table in a single self-healing pass
* [Hot-Path Memory Guide](docs/misc/hot-path-memory.md) - Reading and writing game memory in per-frame hot paths with the `seh_*` and `read_ptr_*` primitives
* [Hot-Reload Development Guide](docs/hot-reload/README.md) - Development workflow for iterating on hooks with live reload
* [Config Hot-Reload Guide](docs/config-hot-reload/README.md) - INI filesystem watcher and hotkey-triggered `Config::reload()`
* [Test Coverage Guide](docs/tests/README.md) - Coverage analysis, test architecture, and module-level breakdown

## Prerequisites

* A C++ compiler supporting C++23 (e.g., MinGW g++ 12+ or newer, MSVC 2022+).
* [CMake](https://cmake.org/) 3.25 or newer.
* [Ninja](https://ninja-build.org/) build system (ships with Visual Studio; for MSYS2: `pacman -S ninja`).
* `make` (optional, for the Makefile wrapper -- e.g., `mingw32-make` for MinGW environments).
* Git (for cloning and managing submodules).

## Building DetourModKit (Static Library via CMake)

This project uses CMake with [CMake Presets](https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html) and Ninja to orchestrate its build. A thin Makefile wrapper is provided for convenience.

1. **Clone the repository (with submodules):**

    ```bash
    git clone --recursive https://github.com/tkhquang/DetourModKit.git
    cd DetourModKit
    ```

    If you've already cloned without `--recursive`:

    ```bash
    git submodule update --init --recursive
    ```

    To update submodules to the latest upstream version (when not pinned to a specific commit):

    ```bash
    git submodule update --init --recursive --remote
    ```

2. **Build & Package for Distribution:**

   ### Using the Makefile wrapper (Recommended)

    ```bash
    # Build the library (MinGW Release by default)
    make

    # Install to build/install/
    make install

    # Build with a different preset
    make PRESET=msvc-release
    make install PRESET=msvc-release
    ```

   ### Using CMake presets directly

    ```bash
    # MinGW
    cmake --preset mingw-release
    cmake --build --preset mingw-release --parallel
    cmake --install build/mingw-release --prefix ./install_package/mingw

    # MSVC (run from a Visual Studio Developer Command Prompt)
    cmake --preset msvc-release
    cmake --build --preset msvc-release --parallel
    cmake --install build/msvc-release --prefix ./install_package/msvc
    ```

   ### Available presets

    | Preset | Compiler | Build Type | Tests | Notes |
    | --- | --- | --- | --- | --- |
    | `mingw-debug` | GCC (MinGW) | Debug | ON | |
    | `mingw-debug-coverage` | GCC (MinGW) | Debug | ON | gcov coverage |
    | `mingw-release` | GCC (MinGW) | Release | OFF | |
    | `msvc-debug` | MSVC (cl) | Debug | ON | |
    | `msvc-debug-asan` | MSVC (cl) | Debug | ON | AddressSanitizer (the only sanitizer on Windows) |
    | `msvc-release` | MSVC (cl) | Release | OFF | |

   ### Installed package smoke test

    ```bash
    cmake -S tests/package_smoke -B build/package-smoke-mingw -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DDetourModKit_DIR="$PWD/install_package/mingw/lib/cmake/DetourModKit" \
        -DCMAKE_CXX_COMPILER=g++
    cmake --build build/package-smoke-mingw --parallel
    ctest --test-dir build/package-smoke-mingw --output-on-failure
    ```

    The package smoke project includes the installed headers, links the
    installed `DetourModKit::DetourModKit` target, and touches `HookManager`
    so the static dependency chain is pulled into the consumer link.

> [!NOTE]
> Release builds enable Link-Time Optimization (LTO) when supported by the compiler,
> along with dead code elimination (`/Gy /Gw` on MSVC, `-ffunction-sections -fdata-sections`
> with `--gc-sections` on GCC/Clang). `--gc-sections` propagates to consumers via INTERFACE
> linkage so unused DetourModKit symbols are stripped at final link time. MinGW Release builds
> use `-O2` (overriding CMake's default `-O3`) for a better code-size/performance tradeoff.
> MSVC Debug builds embed CodeView debug info (`/Z7`) for parallel build compatibility;
> Release builds omit debug info entirely to minimize binary size.

---

> [!TIP]
> You can create a `CMakeUserPresets.json` file (git-ignored) to define your own local presets that inherit from the ones above.

   After running the install command, the install directory (`build/install/` for the Makefile wrapper, or whichever `--prefix` you passed to `cmake --install`) will contain:

    ```text
    <install_prefix>/
    ├── include/
    │   ├── DetourModKit/             <-- DetourModKit public headers
    │   │   ├── scanner.hpp           <-- AOB scanner
    │   │   ├── async_logger.hpp      <-- Async logging system
    │   │   ├── bootstrap.hpp         <-- DllMain lifecycle helpers
    │   │   ├── config.hpp
    │   │   ├── event_dispatcher.hpp  <-- Typed pub/sub with RAII subscriptions
    │   │   ├── format.hpp            <-- String & format utilities
    │   │   ├── math.hpp              <-- Math utilities (angle conversions)
    │   │   ├── memory.hpp            <-- Memory utilities
    │   │   ├── profiler.hpp          <-- Scoped timing (zero-cost when disabled)
    │   │   ├── filesystem.hpp        <-- Filesystem utilities
    │   │   ├── hook_manager.hpp      <-- Hook management
    │   │   ├── input.hpp             <-- Input/hotkey system
    │   │   ├── input_codes.hpp       <-- Unified input codes (keyboard/mouse/gamepad)
    │   │   ├── logger.hpp            <-- Synchronous logger
    │   │   ├── version.hpp           <-- Version macros (generated by CMake)
    │   │   ├── win_file_stream.hpp   <-- Win32 shared-access file stream
    │   │   ├── worker.hpp            <-- StoppableWorker (std::jthread RAII wrapper)
    │   │   └── ...
    │   ├── DetourModKit.hpp          <-- Main DetourModKit include
    │   ├── DirectXMath/              <-- DirectXMath headers
    │   │   ├── DirectXMath.h
    │   │   ├── DirectXMathVector.inl
    │   │   └── ...
    │   ├── safetyhook/               <-- SafetyHook detail headers
    │   │   ├── common.hpp
    │   │   ├── inline_hook.hpp
    │   │   └── ...
    │   └── safetyhook.hpp            <-- Main SafetyHook include
    ├── lib/
    │   ├── libDetourModKit.a         <-- Static libraries (.a for MinGW, .lib for MSVC)
    │   ├── libsafetyhook.a
    │   ├── libZydis.a
    │   └── libZycore.a
    └── lib/cmake/DetourModKit/       <-- CMake config files
        ├── DetourModKitConfig.cmake
        ├── DetourModKitConfigVersion.cmake
        └── DetourModKitTargets.cmake
    ```

## Running Unit Tests

DetourModKit includes a comprehensive unit test suite using GoogleTest. The debug presets (`mingw-debug`, `msvc-debug`) have tests enabled by default.

### Using the Makefile wrapper

```bash
# Build and run tests (MinGW by default)
make test

# Run tests with MSVC (requires VS Developer Command Prompt)
make test_msvc

# Clean all build directories
make clean
```

### Using CMake presets for tests

```bash
# MinGW
cmake --preset mingw-debug
cmake --build --preset mingw-debug --parallel
ctest --preset mingw-debug

# MSVC
cmake --preset msvc-debug
cmake --build --preset msvc-debug --parallel
ctest --preset msvc-debug
```

> [!TIP]
> If the MSVC build is failing due to a PDB file locking issue, kill stale compiler processes:
>
> ```bash
> taskkill /F /IM cl.exe 2>nul || echo No cl.exe processes found
> ```

### Warnings as Errors

To treat compiler warnings as errors (enabled by default in CI):

```bash
cmake --preset mingw-debug -DDMK_WARNINGS_AS_ERRORS=ON
cmake --build --preset mingw-debug --parallel
```

### Enabling Profiling

To enable the opt-in profiler instrumentation (`DMK_PROFILE_SCOPE` / `DMK_PROFILE_FUNCTION` macros):

```bash
cmake --preset mingw-debug -DDMK_ENABLE_PROFILING=ON
cmake --build --preset mingw-debug --parallel
```

When `DMK_ENABLE_PROFILING` is OFF (the default), all profiling macros expand to `((void)0)` with zero overhead. The `Profiler` class and `ScopedProfile` are still compiled into the library (so tests always work), but the macros that instrument user code are no-ops.

### Enabling the AVX-512 verify tier

The scanner ships an opt-in AVX-512F + AVX-512BW pattern-verification tier (64 bytes per iteration), off by default:

```bash
cmake --preset mingw-debug -DDMK_ENABLE_AVX512=ON
cmake --build --preset mingw-debug --parallel
```

When `DMK_ENABLE_AVX512` is OFF (the default) the tier compiles out entirely. When ON, the AVX-512 intrinsics are confined to that single function via a per-function `target` attribute (no global `/arch:AVX512` or `-mavx512`), so the rest of the library keeps its AVX2 baseline and the produced binary still runs on CPUs without AVX-512: the tier is selected only when a runtime `CPUID` + `XGETBV` check confirms both the CPU and OS support AVX-512F and AVX-512BW, otherwise the scanner falls back to AVX2. `Scanner::active_simd_level()` reports the tier actually in use. The tier's `>= 30%` throughput gate is hardware-specific and can only be measured on a real AVX-512 host. Per-tier correctness (including AVX-512) runs under Intel SDE on every push to main via `.github/workflows/simd-tier-correctness.yml`.

### Enabling Sanitizers

AddressSanitizer is available on Windows through **MSVC only**. GCC and Clang on mingw-w64 ship no ASan/UBSan runtime for the Windows target, so a MinGW sanitizer build cannot link here; UndefinedBehaviorSanitizer is not available on Windows.

```bash
# AddressSanitizer via MSVC -- run from a Developer Command Prompt.
cmake --preset msvc-debug-asan
cmake --build --preset msvc-debug-asan --parallel
ctest --preset msvc-debug-asan
```

> [!NOTE]
> MSVC ASan needs `clang_rt.asan_dynamic-x86_64.dll` on `PATH` at run time; a
> Developer Command Prompt (or `Enter-VsDevShell`) provides it. ASan only -- there
> is no UBSan or LeakSanitizer on MSVC. The GCC/Clang `-fsanitize=address,undefined`
> path only links where the runtimes exist (a Linux toolchain), which does not
> apply to this Windows-only library. Setting `DMK_ENABLE_SANITIZERS=ON` under a
> non-MSVC Windows toolchain (e.g. MinGW) fails fast at configure time with a
> `FATAL_ERROR` pointing to the MSVC route.

### Enabling Code Coverage

To generate code coverage reports (requires GCC/Clang), pass the coverage option when configuring:

```bash
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
cmake --build --preset mingw-debug --parallel
```

All pull requests to `main` are automatically tested via CI with an **80% minimum line coverage** gate. See the [PR Check workflow](.github/workflows/pr-check.yml) for details. The latest coverage report is published to [GitHub Pages](https://tkhquang.github.io/DetourModKit/) on every push to `main`.

## Using DetourModKit in Your Mod Project

There are two main approaches to integrate DetourModKit into your project:

### Method 1: Using DetourModKit as a Submodule (Recommended)

This method is ideal for active development and ensures you always have the latest compatible version.

1. **Add DetourModKit as a submodule:**

    ```bash
    # In your project root
    git submodule add https://github.com/tkhquang/DetourModKit.git external/DetourModKit
    git submodule update --init --recursive
    ```

    To pin a specific release version:

    ```bash
    cd external/DetourModKit
    git checkout v2.0.0          # or v1.0.1, v1.0.0, etc.
    cd ../..
    git add external/DetourModKit
    git commit -m "pin DetourModKit to v2.0.0"
    ```

    To upgrade to a newer version later:

    ```bash
    cd external/DetourModKit
    git fetch --tags
    git checkout v2.1.0          # desired version
    cd ../..
    git add external/DetourModKit
    git commit -m "upgrade DetourModKit to v2.1.0"
    ```

2. **Configure your CMakeLists.txt:**

    ```cmake
    cmake_minimum_required(VERSION 3.28)
    project(MyMod VERSION 1.0.0 LANGUAGES CXX)

    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    # Add DetourModKit as subdirectory
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/DetourModKit/CMakeLists.txt")
      message(STATUS "Configuring DetourModKit from: external/DetourModKit")
      add_subdirectory(external/DetourModKit)

      if(TARGET DetourModKit)
        set(DETOURMODKIT_TARGET DetourModKit)
        message(STATUS "DetourModKit target found: ${DETOURMODKIT_TARGET}")
      else()
        message(FATAL_ERROR "DetourModKit target not created by subdirectory")
      endif()
    else()
      message(FATAL_ERROR "DetourModKit not found at 'external/DetourModKit'. "
        "Please ensure the submodule is initialized: "
        "'git submodule update --init --recursive'")
    endif()

    # Create your mod target
    add_library(MyMod SHARED src/main.cpp)

    # Link against DetourModKit (all dependencies are transitively linked).
    # user32 and xinput1_4 propagate automatically via DetourModKit's INTERFACE linkage.
    target_link_libraries(MyMod PRIVATE DetourModKit)

    # Add any extra system libraries your own mod code needs (Windows)
    if(WIN32)
        target_link_libraries(MyMod PRIVATE psapi kernel32)
    endif()
    ```

3. **In your GitHub Actions workflow (if using CI):**

    ```yaml
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        submodules: "recursive"  # This ensures DetourModKit is pulled
    ```

### Method 2: Using Pre-built DetourModKit Package

This method uses a pre-built and installed version of DetourModKit.

1. **Download a release package:**

    Pre-built packages for MinGW and MSVC are available on the [Releases](https://github.com/tkhquang/DetourModKit/releases) page. Download the zip matching your toolchain and version (e.g., `DetourModKit_MinGW_v2.0.0.zip` or `DetourModKit_MSVC_v2.0.0.zip`).

    To upgrade, download the newer release zip and replace the contents of your `external/DetourModKit/` directory.

2. **Integrate DetourModKit:**
    * Extract the downloaded zip into your mod project (e.g., into an `external/DetourModKit/` subdirectory).
    * Alternatively, build from source and run `cmake --install` to produce the same directory layout (see [Building](#building-detourmodkit-static-library-via-cmake)).

3. **Configure Your Mod's Build System:**

   #### CMake

    ```cmake
    # In your mod's CMakeLists.txt
    cmake_minimum_required(VERSION 3.25)
    project(MyMod)

    set(CMAKE_CXX_STANDARD 23)

    # Find DetourModKit
    set(DetourModKit_DIR "external/DetourModKit/lib/cmake/DetourModKit")
    find_package(DetourModKit REQUIRED)

    # Create your mod target
    add_library(MyMod SHARED src/main.cpp)

    # Link against DetourModKit.
    # user32 and xinput1_4 propagate automatically via DetourModKit's INTERFACE linkage.
    target_link_libraries(MyMod PRIVATE DetourModKit::DetourModKit)

    # Add any extra system libraries your own mod code needs (Windows)
    if(WIN32)
        target_link_libraries(MyMod PRIVATE psapi kernel32)
    endif()
    ```

   #### Makefile (Example for g++ MinGW)

    ```makefile
    # In your mod's Makefile
    DETOURMODKIT_DIR := external/DetourModKit

    CXXFLAGS += -I$(DETOURMODKIT_DIR)/include
    LDFLAGS += -L$(DETOURMODKIT_DIR)/lib
    LIBS += -lDetourModKit -lsafetyhook -lZydis -lZycore
    # Add system libs: -luser32 -lxinput1_4 are required by DetourModKit.
    # Add -lpsapi -lkernel32 etc. if your own mod code uses them.
    LIBS += -luser32 -lxinput1_4 -static-libgcc -static-libstdc++

    # Example link command:
    # $(CXX) $(YOUR_OBJECTS) -o YourMod.asi -shared $(LDFLAGS) $(LIBS)
    ```

## Code Example

> **Short names and `DMK_NO_SHORT_NAMES`:** including `<DetourModKit.hpp>` introduces `DMK`-prefixed convenience aliases. The namespace aliases (`DMK::`, `DMKConfig::`, `DMKScanner::`, ...) are always present, and the type aliases used below (`DMKLogger`, `DMKHookManager`, `DMKKeyComboList`, ...) keep mod code terse. They are all `DMK`-prefixed, so collision risk is low. For a larger consumer project that prefers to keep the global namespace minimal, define `DMK_NO_SHORT_NAMES` before the include to drop the type aliases (the `DMK::` namespace aliases remain) and use the fully qualified `DetourModKit::` names instead.

```cpp
// MyMod/src/main.cpp
#include <windows.h>
#include <Psapi.h>

// Single include for all DetourModKit functionality
#include <DetourModKit.hpp>

// SafetyHook headers are installed alongside DetourModKit and are transitively available.
// SimpleIni is an internal build-time dependency and is NOT installed; do not include <SimpleIni.h>
// from a find_package consumer. Use the DetourModKit::Config API for INI access instead.
#include <safetyhook.hpp>

// Global variables for your mod's configuration
struct ModConfiguration
{
    bool enable_greeting_hook = true;
    std::string log_level_setting = "INFO";
    DMKKeyComboList toggle_combo;
    DMKKeyComboList hold_scroll_combo;
} g_mod_config;

// Example Hook: Target function signature
using OriginalGameFunction_PrintMessage_t = void (__stdcall *)(const char *message, int type);
OriginalGameFunction_PrintMessage_t original_GameFunction_PrintMessage = nullptr;

// Detour function
void __stdcall Detour_GameFunction_PrintMessage(const char *message, int type)
{
    auto &logger = DMKLogger::get_instance();
    logger.info("Detour_GameFunction_PrintMessage CALLED! Original message: \"{}\", type: {}", message, type);

    if (g_mod_config.enable_greeting_hook)
    {
        logger.debug("Modifying message because greeting hook is enabled.");
        if (original_GameFunction_PrintMessage)
        {
            original_GameFunction_PrintMessage("Hello from DetourModKit! Hooked!", type + 100);
        }
        return;
    }

    if (original_GameFunction_PrintMessage)
    {
        original_GameFunction_PrintMessage(message, type);
    }
}

// Mod Initialization Function (runs on DMKBootstrap's worker thread, off the loader lock)
bool InitializeMyMod()
{
    // Logger + async mode are already configured by DMKBootstrap::on_dll_attach()
    // using the ModInfo passed into the attach call below.
    auto &logger = DMKLogger::get_instance();

    // Register your configuration variables (using callback-based API)
    DMKConfig::register_bool("Hooks", "EnableGreetingHook", "Enable Greeting Hook",
        [](bool v) { g_mod_config.enable_greeting_hook = v; }, true);
    DMKConfig::register_string("Debug", "LogLevel", "Log Level",
        [](const std::string &v) { g_mod_config.log_level_setting = v; }, "INFO");

    // Register hotkey bindings from INI (modifier+trigger format)
    // Comma separates independent combos: "F3,Gamepad_LT+Gamepad_B" (F3 OR LT+B)
    // Plus separates modifiers from trigger: "Ctrl+Shift+F3" (AND for modifiers, last = trigger)
    // Hex VK codes still work: "0x72", "0x11+0x72"
    // Mouse: "Mouse4", "Ctrl+Mouse1"
    // Gamepad: "Gamepad_A", "Gamepad_LB+Gamepad_A"
    DMKConfig::register_key_combo("Hotkeys", "ToggleKey", "Toggle Keys",
        [](const DMKKeyComboList &c) { g_mod_config.toggle_combo = c; }, "F3");
    DMKConfig::register_key_combo("Hotkeys", "HoldScrollKey", "Hold Scroll Keys",
        [](const DMKKeyComboList &c) { g_mod_config.hold_scroll_combo = c; }, "");

    // Load configuration from INI file
    DMKConfig::load("MyMod.ini");

    // Apply LogLevel from loaded configuration
    logger.set_log_level(DMKLogger::string_to_log_level(g_mod_config.log_level_setting));

    // Log the loaded configuration
    logger.info("MyMod configuration loaded and applied.");
    DMKConfig::log_all();

    // Initialize Hooks
    auto &hook_manager = DMKHookManager::get_instance();

    uintptr_t target_function_address = 0;

    // Example: AOB Scan
    const HMODULE game_module = GetModuleHandleA(nullptr);
    if (game_module)
    {
        MODULEINFO module_info{};
        if (GetModuleInformation(GetCurrentProcess(), game_module, &module_info, sizeof(module_info)))
        {
            logger.debug("Scanning module at {} size {}",
                         DMKFormat::format_address(reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll)),
                         module_info.SizeOfImage);

            // Replace with actual AOB pattern from your target game
            const std::string aob_sig_str = "48 89 ?? ?? 57";
            const ptrdiff_t pattern_offset = 0;

            const auto pattern = DMKScanner::parse_aob(aob_sig_str);
            if (pattern.has_value())
            {
                const std::byte *found_pattern = DMKScanner::find_pattern(
                    reinterpret_cast<const std::byte *>(module_info.lpBaseOfDll),
                    module_info.SizeOfImage,
                    *pattern
                );
                if (found_pattern)
                {
                    target_function_address = reinterpret_cast<uintptr_t>(found_pattern) + pattern_offset;
                    logger.info("Pattern found at: {}, target address: {}",
                                DMKFormat::format_address(reinterpret_cast<uintptr_t>(found_pattern)),
                                DMKFormat::format_address(target_function_address));
                }
                else
                {
                    logger.error("AOB pattern not found in target module.");
                }
            }
            else
            {
                logger.error("Failed to parse AOB pattern: {}", aob_sig_str);
            }
        }
        else
        {
            logger.error("GetModuleInformation failed: {}", GetLastError());
        }
    }
    else
    {
        logger.error("Failed to get game module handle.");
    }

    if (target_function_address != 0)
    {
        const DMKHookConfig hook_cfg;
        auto result = hook_manager.create_inline_hook(
            "GameFunction_PrintMessage_Hook",
            target_function_address,
            reinterpret_cast<void *>(Detour_GameFunction_PrintMessage),
            reinterpret_cast<void **>(&original_GameFunction_PrintMessage),
            hook_cfg
        );

        if (result.has_value())
        {
            logger.info("Successfully created hook: {}", result.value());
        }
        else
        {
            logger.error("Failed to create hook: {}",
                         DMK::Hook::error_to_string(result.error()));
            return false;
        }
    }
    else
    {
        logger.warning("Target address is 0 or not found. Hook not created.");
    }

    // Register hotkey bindings with the InputManager (after hooks are ready).
    // register_press/register_hold accept a KeyComboList directly. One binding
    // is created per combo, all sharing the same name for OR-logic queries.
    auto &input_mgr = DMKInputManager::get_instance();

    input_mgr.register_press("toggle_view", g_mod_config.toggle_combo, []()
    {
        DMKLogger::get_instance().info("Toggle key pressed!");
    });

    input_mgr.register_hold("hold_scroll", g_mod_config.hold_scroll_combo, [](bool held)
    {
        DMKLogger::get_instance().info("Hold scroll: {}", held ? "active" : "released");
    });

    // Start the input polling thread (focus-aware by default)
    input_mgr.start();

    logger.info("MyMod Initialized using DetourModKit!");
    return true;
}

// Mod Shutdown Function (runs on DMKBootstrap's worker thread, before DMK_Shutdown())
void ShutdownMyMod()
{
    DMKLogger::get_instance().info("MyMod Shutting Down...");
    // DMK_Shutdown() is invoked automatically by on_dll_detach() after this
    // function returns, in the correct order:
    //   Config auto-reload watcher -> InputManager -> HookManager -> Memory cache -> Config registry -> Logger
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DMKBootstrap::ModInfo info{
            .prefix = "MyMod",
            .log_file = "MyMod.log",
            .game_process_name = "MyGame.exe",          // optional -- set "" to disable
            .instance_mutex_prefix = "MyMod_Instance",  // optional -- set "" to disable
        };
        info.async_cfg.queue_capacity = 8192;
        info.async_cfg.batch_size = 64;

        return DMKBootstrap::on_dll_attach(hModule, info,
                                           &InitializeMyMod,
                                           &ShutdownMyMod);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        DMKBootstrap::on_dll_detach(lpReserved != nullptr);
    }
    return TRUE;
}
```

> [!WARNING]
> `DMKBootstrap::on_dll_attach()` runs `InitializeMyMod` / `ShutdownMyMod` on a
> dedicated worker thread, so both execute off the loader lock. For a dynamic
> `FreeLibrary` unload, call `DMKBootstrap::request_shutdown()` *before* issuing
> `FreeLibrary` so the worker has time to drain. Each subsystem also detects the
> loader lock and will detach background threads instead of joining them, but
> requesting shutdown early ensures all log messages are flushed and hooks are
> cleanly removed. See the [Hot-Reload Guide](docs/hot-reload/README.md) for the
> recommended two-DLL architecture.

## Configuration File Example

Create a `MyMod.ini` file alongside your DLL:

```ini
[Hooks]
EnableGreetingHook=true

[Debug]
LogLevel=INFO

[Hotkeys]
; Named keys (recommended)
ToggleKey=F3                 ; Single key
HoldScrollKey=LShift         ; Left Shift
DebugCombo=Ctrl+Shift+D      ; Ctrl AND Shift AND D (plus = AND for modifiers, last = trigger)

; Multiple independent combos (comma = OR between combos)
DualInput=F3,Gamepad_LT+Gamepad_B     ; F3 alone OR (hold LT + press B)
MultiCombo=Ctrl+F3,Ctrl+F4            ; Ctrl+F3 OR Ctrl+F4

; Mouse buttons
AimToggle=Mouse4             ; Mouse button 4 (side button)
QuickAction=Ctrl+Mouse1      ; Ctrl + Left click

; Gamepad buttons (XInput)
GamepadToggle=Gamepad_A                ; A button
GamepadCombo=Gamepad_LB+Gamepad_A      ; LB (modifier) + A (trigger)
GamepadTrigger=Gamepad_LT              ; Left trigger (digital, configurable deadzone)

; Hex VK codes still supported
LegacyKey=0x72               ; F3 by hex code
LegacyCombo=0x11+0x10+0x44   ; Ctrl+Shift+D by hex codes

; Opt-out sentinels (silent, no warning)
DisabledHotkey=               ; empty value -> binding registered but unbound
AlsoDisabled=NONE             ; literal NONE (case-insensitive) -> same effect
```

## Supported Input Names

The configuration system recognizes the following named input codes (case-insensitive):

| Category | Names |
| --- | --- |
| **Modifiers** | `Ctrl`, `LCtrl`, `RCtrl`, `Shift`, `LShift`, `RShift`, `Alt`, `LAlt`, `RAlt` |
| **Letters** | `A`-`Z` |
| **Digits** | `0`-`9` |
| **Function keys** | `F1`-`F24` |
| **Navigation** | `Left`, `Right`, `Up`, `Down`, `Home`, `End`, `PageUp`, `PageDown`, `Insert`, `Delete` |
| **Common** | `Space`, `Enter`, `Escape`, `Tab`, `Backspace`, `CapsLock`, `NumLock`, `ScrollLock`, `PrintScreen`, `Pause` |
| **Windows / Menu** | `LWin`, `RWin`, `Apps` (alias `Menu`) |
| **OEM punctuation** | `Semicolon`, `Equals`, `Comma`, `Minus`, `Period`, `Slash`, `Grave` (aliases `Backtick`, `Tilde`; the usual console hotkey), `LBracket`, `Backslash`, `RBracket`, `Apostrophe` (alias `Quote`) |
| **Numpad** | `Numpad0`-`Numpad9`, `NumpadAdd`, `NumpadSubtract`, `NumpadMultiply`, `NumpadDivide`, `NumpadDecimal` |
| **Mouse** | `Mouse1` (left), `Mouse2` (right), `Mouse3` (middle), `Mouse4`, `Mouse5` |
| **Mouse wheel** | `WheelUp`, `WheelDown`, `WheelLeft`, `WheelRight` (trigger-only, Press mode) |
| **Gamepad** | `Gamepad_A`, `Gamepad_B`, `Gamepad_X`, `Gamepad_Y`, `Gamepad_LB`, `Gamepad_RB`, `Gamepad_LT`, `Gamepad_RT`, `Gamepad_Start`, `Gamepad_Back`, `Gamepad_LS`, `Gamepad_RS`, `Gamepad_DpadUp`, `Gamepad_DpadDown`, `Gamepad_DpadLeft`, `Gamepad_DpadRight` |
| **Gamepad sticks** | `Gamepad_LSUp`, `Gamepad_LSDown`, `Gamepad_LSLeft`, `Gamepad_LSRight`, `Gamepad_RSUp`, `Gamepad_RSDown`, `Gamepad_RSLeft`, `Gamepad_RSRight` |

Hex VK codes with `0x` prefix (e.g., `0x72` for F3) are also accepted and default to keyboard input. A code that has no table name but is not a keyboard code is written back to the INI in a source-tagged hex form (`Mouse:0xFE`, `Gamepad:0x800`, `MouseWheel:0x9`) and parsed back to the same device source, so a non-keyboard code survives a config round-trip instead of decaying to a keyboard key.

## Gamepad Compatibility

Gamepad support uses the **XInput** API. The following controllers are supported natively:

| Controller | Supported |
| --- | --- |
| Xbox 360 | Yes (native XInput) |
| Xbox One / Series X\|S | Yes (native XInput) |
| GameSir (XInput mode) | Yes (switch controller to XInput mode) |
| PS4 DualShock 4 | Via [DS4Windows](https://github.com/ds4windowsapp/DS4Windows) or Steam Input |
| PS5 DualSense | Via [DualSenseX](https://github.com/Paliverse/DualSenseX) or Steam Input |
| Nintendo Switch Pro | Via [BetterJoy](https://github.com/Davidobot/BetterJoy) or Steam Input |
| Generic USB gamepads | Only if the controller exposes an XInput interface |

**Why XInput only?** DetourModKit's input system is designed for mod hotkeys and toggles, not for replacing a game's primary input handling. XInput covers Xbox controllers natively, and the vast majority of PC players using non-Xbox controllers already use Steam Input or similar remapping tools that present their controller as XInput. Adding DirectInput or Windows.Gaming.Input would significantly increase complexity for a use case where XInput + keyboard/mouse covers nearly all real users.

**Limitations:**

* Maximum 4 controllers (XInput hard limit, indices 0-3).
* Analog triggers (LT/RT) and thumbstick axes are treated as digital buttons with configurable deadzone thresholds.
* No event-driven hot-plug detection; controller connection is checked via polling (reconnection attempts are throttled to every 2 seconds when disconnected).
* **Shift + Numpad keys:** When Shift is held, Windows translates numpad keys to their navigation equivalents (e.g., `Numpad5` becomes `VK_CLEAR` instead of `VK_NUMPAD5`). This means combos like `LShift+Numpad5` will never fire because `GetAsyncKeyState` sees the translated VK code, not the original numpad code. **Workaround:** use `Ctrl` or `Alt` instead of `Shift` for numpad combos, or use non-numpad keys. ([More info](https://learn.microsoft.com/en-us/answers/questions/3935239/how-to-make-it-so-left-shift-doesnt-affect-number))

## Projects Using DetourModKit

For practical reference and real-world usage examples:

* **OBR-NoCarryWeight**: [https://github.com/tkhquang/OBRTools/tree/main/NoCarryWeight](https://github.com/tkhquang/OBRTools/tree/main/NoCarryWeight)
* **KCD1-TPVToggle**: [https://github.com/tkhquang/KCD1Tools/tree/main/TPVToggle](https://github.com/tkhquang/KCD1Tools/tree/main/TPVToggle)
* **KCD2-TPVToggle**: [https://github.com/tkhquang/KCD2Tools/tree/main/TPVToggle](https://github.com/tkhquang/KCD2Tools/tree/main/TPVToggle)
* **KCD2-TPVCamera**: [https://github.com/tkhquang/KCD2Tools/tree/main/TPVCamera](https://github.com/tkhquang/KCD2Tools/tree/main/TPVCamera)
* **CrimsonDesert-EquipHide**: [https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertEquipHide](https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertEquipHide)
* **CrimsonDesert-LiveTransmog**: [https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertLiveTransmog](https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertLiveTransmog)

## Acknowledgements

DetourModKit incorporates components from other open-source projects. See [DetourModKit_Acknowledgements.txt](DetourModKit_Acknowledgements.txt) for full details.

* [SafetyHook](https://github.com/cursey/safetyhook) (Boost Software License 1.0)
* [SimpleIni](https://github.com/brofield/simpleini) (MIT)
* [DirectXMath](https://github.com/microsoft/DirectXMath) (MIT)
* [Zydis & Zycore](https://github.com/zyantific/zydis) (MIT)

The RTTI self-heal / reverse-dissection design was **inspired by** (no code incorporated) the [CERTTIExplorer](https://github.com/FransBouma/InjectableGenericCameraSystem/tree/master/Tools/CERTTIExplorer) Cheat Engine script ([GhostInTheCamera](https://github.com/ghostinthecamera), with improvements by [Frans Bouma](https://github.com/FransBouma) / Otis_Inf; BSD-2-Clause) and the [FramedSC RTTI guide](https://framedsc.com/GeneralGuides/using_rtti.htm). See [docs/misc/rtti-self-heal.md](docs/misc/rtti-self-heal.md#prior-art-and-acknowledgements) for the full credit.
