# DetourModKit

[![Coverage Report ≥ 80%](https://github.com/tkhquang/DetourModKit/actions/workflows/coverage-pages.yml/badge.svg)](https://tkhquang.github.io/DetourModKit/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Features](#features) | [Building](#building-detourmodkit-static-library-via-cmake) | [Testing](#running-unit-tests) | [Guides](#guides) | [Integration](#using-detourmodkit-in-your-mod-project) | [Example](#code-example)

DetourModKit is a full-featured C++23 toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, input handling, configuration management, and DLL lifecycle orchestration. It targets Windows x64 and builds under both MSVC 2022+ and MinGW (GCC 12+).

## Features

| Module | Description | Header |
|--------|-------------|--------|
| Core Vocabulary (v4) | Strongly-typed `Address` and `Region` value types (constexpr arithmetic, a single audited cast surface, named scope factories), the backend-neutral `Prot` protection flags, and one unified error idiom: the eight per-domain enums folded into one high-byte-tagged `ErrorCode` superset (`category()` recovers the subsystem), a trivially-copyable `Error`, `Result<T> = std::expected<T, Error>`, and the `DMK_TRY` / `DMK_TRY_VOID` propagation macros | `address.hpp`, `region.hpp`, `error.hpp`, `defines.hpp` |
| AOB Scanner | v4 `scan.hpp` surface with value-semantic `Pattern`, factory-only `Candidate` tiers, borrowed and owned `ScanRequest`, `resolve` / `resolve_batch`, page-gated `scan`, and `unchecked::find_pattern`, backed by the existing SIMD scanner with full-byte and per-nibble wildcards, cross-region-boundary overlap, RIP resolution, prologue-recovery fallback, raw and resolve-ladder batch scanning, in-code constants, and string-reference xrefs | `scan.hpp` |
| Hook (v4) | Free verbs (`hook::inline_at` / `mid_at` / `install_all` / `vmt_for`) returning move-only RAII `Hook` / `VmtHook` handles whose destructors restore the prologue, with the SafetyHook backend fully hidden behind an opaque `hook::MidContext` | `hook.hpp` |
| Configuration | INI-based settings with key combo support and hot-reload (folded-in file watcher + hotkey) | `config.hpp` |
| Logger | Process logger value facade with format strings | `logger.hpp` |
| Async Logger | Lock-free bounded queue logger with batched writes | `async_logger.hpp` |
| Memory Utilities | Readability checks, region cache, safe pointer reads, typed fault-guarded reads/writes (`Result<T>`), fault-guarded pointer-chain walks, page-protection guards, PE module range queries | `memory.hpp` |
| MSVC RTTI Walker | Recover mangled type names from runtime vtables; pointer-table scan with caller-owned cache; reverse name-to-vtable resolver and cached identity handle | `rtti.hpp` |
| RTTI Self-Heal | Reverse-identify the object behind a pointer slot (`Result<...>` and ordered candidate-fallback forms); self-heal a field offset after a patch shifts the struct layout; rigid multi-field drift solver; a frame-driven `HealScheduler` runner for self-healing offset groups; drift-telemetry report with a durable, diffable manifest (open-failure distinguished from corrupt). Speaks value-typed `Address` / `Result<T>` with self-contained owned `Landmark` / `TypeIdentity` | `rtti_dissect.hpp`, `detail/drift_manifest.hpp` |
| Anchor Registry | One declarative table over the self-healing backends (vtable-by-name, AOB/RIP cascade, in-code constant, string xref, pinned literal) plus two-signal quorum corroboration with sub-anchor independence checks, optional post-resolve validators and opt-in validator policies, a manifest quality diagnostic, an address-independent evidence fingerprint for manifest diffing, opt-in parallel table resolution, and a per-game scan profile (broad-mode default, candidate order, backend deny-list), resolved and reported in a single pass. The four resolution backends are `scan::resolve` / `scan::read_code_constant` / `scan::find_string_xref` / `rtti::vtable_for_type`. | `anchor.hpp` |
| Event Dispatcher | Typed pub/sub with RAII subscriptions | `detail/event_dispatcher.hpp` |
| Profiler | Scoped timing with Chrome Tracing export (zero-cost when disabled) | `profiler.hpp` |
| Format Utilities | `std::format` helpers for addresses, bytes, and VK codes; string trim | `format.hpp` |
| Filesystem Utilities | Module directory resolution (wide-string and UTF-8 APIs) | `filesystem.hpp` |
| Math Utilities | Angle conversions (header-only) | `math.hpp` |
| Version Macros | Compile-time version checking generated from CMake | `version.hpp` |
| Input System | Hotkey monitoring with background polling (keyboard/mouse/gamepad) | `input.hpp`, `input_codes.hpp` |
| Session and Bootstrap | RAII process lifetime with ordered teardown, DllMain scaffolding, instance mutex, process gate, lifecycle worker | `dmk.hpp` |
| Diagnostics | Consumer-queryable counters for intentional loader-lock leak/detach events per subsystem, a process-wide typed event bus for scanner-fault and hook install/enable/disable/remove transitions, and a one-call snapshot aggregator over the counters, hook counts, anchor quality, and drift report | `diagnostics.hpp` |
| Stoppable Worker | RAII named `std::jthread` wrapper, loader-lock-safe teardown | `detail/worker.hpp` |

<details>
<summary><strong>AOB Scanner</strong></summary>

- Find array-of-bytes (signatures) in memory with full-byte literals, full wildcards (`??` / `?`), and per-nibble wildcard tokens (`4?` fixes the high nibble, `?5` the low nibble) for an operand where only one nibble is invariant across builds
- Rare-byte anchor heuristic: `scan::Pattern::compile()` scores every fully-known literal byte in the pattern against a small frequency table (`0x00`, `0xCC`, `0x48`, `0x8B`, ...) and caches the rarest byte's index (a per-nibble byte is never chosen, since the prefilter needs an exact byte; an all-nibble pattern still resolves via a masked compare at every position). The scan engine drives its `memchr` sweep on that byte, so a signature like `48 8B 05 37 DE AD BE EF` anchors on `0x37` rather than the very common `0x48`, cutting false candidate hits by an order of magnitude on realistic code
- SIMD-accelerated prefilter and pattern verification:
  - The `memchr` anchor prefilter and the verify pass both tier at runtime: AVX2 (32 bytes/iteration, runtime-detected on Haswell+ CPUs) over an SSE2 baseline (16 bytes/iteration), with a scalar tail. The self-provided prefilter does its own byte comparisons (never calling libc) so the AddressSanitizer interceptor cannot fault on the scanner's in-bounds reads
  - Opt-in AVX-512F + AVX-512BW verify tier (64 bytes/iteration), gated behind the `DMK_ENABLE_AVX512` build option and a runtime CPUID + XGETBV check; off by default and never selected on a CPU that lacks it (it falls back to AVX2)
- `|` offset markers for targeting a specific instruction within a wider pattern (e.g., `"48 8B 88 B8 00 00 00 | 48 89 4C 24 68"` sets the offset to byte 7)
- Nth-occurrence matching (1-based) for patterns that hit multiple locations
- RIP-relative instruction resolution for extracting absolute addresses from x86-64 code (returns `Result<Address>` with a unified `ErrorCode` for actionable diagnostics)
- `scan::scan(pattern, scope, occurrence, Pages::Executable)` for scanning all committed executable pages in a region -- useful for games with packed or protected binaries that unpack code into anonymous memory outside any loaded module (pure-execute pages without a read bit are skipped to avoid access violations; a region decommitted or reprotected concurrently mid-sweep is skipped rather than faulting the host). `Pages::Readable` (the default) widens the sweep to all committed readable pages (`.rdata` / `.data`, read-only heaps) to reach C++ vtables, RTTI type descriptors, and read-only metadata. The unsafe twin `scan::unchecked::find_pattern(region, pattern, occurrence)` accepts a caller-guaranteed-readable region with no page filtering.
- The region-walking sweeps carry a `pattern_len - 1` overlap across adjacent accepted `VirtualQuery` regions, so a signature that straddles a protection split (two adjacent regions whose base protections differ, e.g. after a sibling `VirtualProtect` carves up `.text`) is still found, without re-counting a match that lies wholly inside one region
- `scan::resolve_batch(requests, max_workers)` -- opt-in noexcept fork-join resolver for startup target tables. Each `ScanRequest` dispatches to the resolver concurrently and returns one `Result<Hit>` per request in input order. A per-request failure never sinks the batch.
- `scan::resolve(request)` -- ordered multi-candidate resolution (try `Candidate` tiers in priority order, return the first that resolves), with an optional hooked-prologue recovery pass (`ScanRequest::prologue_fallback = true`) that recovers an `E9` near-jump, an `FF 25` RIP-relative indirect jump, and a `mov rax, imm64; jmp rax` overwritten prologue (so a target inline-hooked by another mod with a near or far jump is recovered). The `ScanRequest::scope` field (a `Region` -- build with `Region::host()`, `Region::module_named(...)`, or `Region::whole_process()`) confines the scan to a single mapped image and rejects out-of-scope resolutions, so a generic signature that also matches inside another injected module (a graphics overlay, a sibling mod) cannot shadow the correct target. By default each candidate must match uniquely in the scope (`require_unique = true`): an ambiguous signature falls through to the next candidate instead of silently committing to an arbitrary match.
- A `Candidate` can carry a name or string resilience tier, not just a byte AOB: `Candidate::rtti_vtable(name, mangled)` resolves an MSVC mangled type name via `rtti::vtable_for_type`, and `Candidate::string_xref(name, literal)` (or `Candidate::string_xref(name, StringRefQuery{...})` for full facet control) resolves a literal string through `scan::find_string_xref`. These sit above the byte tiers in one ordered ladder -- "try the RTTI name, else the string xref, else the byte AOB" -- are unique-only by construction (the backend fails closed on ambiguity), and are automatically skipped by the prologue-fallback recovery (which only rewrites `Candidate::direct` rows).
- `scan::read_code_constant(cc, scope)` -- the code-side twin of the RTTI self-heal: declare an instruction site (a `CodeConstant` with a `Candidate` ladder for the site) plus which operand to read (`OperandKind::Immediate` or `MemoryDisplacement`), and it decodes the live instruction and returns the current value. It always decodes (`CodeConstant::nominal` is telemetry only, never a short-circuit), indexes the **visible** operands, resolves a RIP-relative memory operand to its absolute target, and fails closed (`ErrorCode::DecodeFailed` / `UnexpectedShape` / `OperandOutOfRange`). Built on a Zydis decoder kept entirely inside the implementation, so no consumer needs Zydis headers.
- `scan::is_likely_function_prologue(addr)` heuristic that rejects scan poison (zero pages, alignment pads, bare RET stubs) while still accepting JMP-shaped patched prologues so nested-hook scenarios resolve

</details>

<details>
<summary><strong>Hook (v4)</strong></summary>

- Free-verb API around [SafetyHook](https://github.com/cursey/safetyhook): `hook::inline_at` / `hook::mid_at` install one hook and return a move-only RAII `Hook` whose destructor restores the prologue, so a hook's lifetime is its handle's scope (no central singleton, no name-keyed registry). The backend is confined to the library: no public header includes or names SafetyHook, and a mid-hook detour takes an opaque `hook::MidContext` read/written through `gpr()` / `stack_pointer()` / `resume_stack_pointer()` / `instruction_pointer()` / `flags()` / `xmm()` accessors, so a consumer writes a detour without SafetyHook on its own include path
- **Inline hooks** and **mid-function hooks** - the `InlineRequest` / `MidRequest` `target` is either an absolute `Address` or a `scan::OwnedScanRequest` resolved at install time (resolve-on-install)
  - `Hook::original<Fn>()` returns the typed trampoline (the UNGUARDED fast path, inline-only); `Hook::call<Ret>(args...)` calls the original through the trampoline under a DMK-owned per-hook `std::recursive_mutex` (by-value `Args` so the reconstructed `Ret(*)(Args...)` is the real by-value C ABI), returning `Ret{}` when the hook is inactive. `enable()` / `disable()` return `Result<void>` and toggle via an atomic CAS; `is_enabled()`, `name()`, and `operator bool` query state; `release()` detaches the hook so it stays installed for the process lifetime
  - **Same-address layering is teardown-safe by RAII contract**: when two hooks layer on one address, destroy the newest handle first (natural reverse-order destruction of stack/member handles satisfies this automatically). A process-wide ledger detects and warns on an out-of-order teardown instead of silently corrupting the restore. `~Hook` is a loader-lock leaf: under the loader lock it pins the module and records an intentional leak rather than restoring
  - **Unsafe-prologue pre-flight**: inline and mid hook creation decodes the target's first byte under a fault guard and flags a leading `E8` (call rel32) or `0xCC`/`0xCD` (breakpoint) prologue -- a relative call whose displacement would be relocated wrongly, or an already-patched / padding entry. `Options::prologue` selects `Prologue::Fail` (the v4 default, safe-by-default: refuse with `ErrorCode::TargetPrologueUnsafe`) or `Prologue::Relocate` (log and install anyway, the old v3 `Warn` behaviour). `Options::fail_if_already_hooked` refuses an install when an exact same-kit ledger hit or a foreign-JMP prologue heuristic shows the target is already hooked
- **Declarative install tables**: `hook::install_all(span<const HookSpec>)` installs a whole table in one call, returning one `InstallOutcome{name, severity, Result<Hook>}` per row. Each `HookSpec::inline_hook` / `mid_hook` factory carries a per-row `Severity`: a `Mandatory` miss fails the whole call and rolls back; a `BestEffort` miss is recorded per-row and skipped while the call still succeeds
- **VMT (virtual method table) hooks** - `hook::vmt_for(name, object, VmtOptions{...})` clones an object's vtable and returns a move-only `VmtHook`; `apply_to(object)` / `remove_from(object)` add or restore additional objects and `~VmtHook` restores every applied vptr newest-first. `VmtOptions::fail_if_already_hooked` rejects a double-clone, `fail_on_non_function_pointer` pre-flight-decodes the slot to reject int3 padding/breakpoints and same-module jump stubs. Per-method slot replacement (`hook_method<Fn>`) is deferred to a later VMT release
- **Duplicate-target query**: `hook::is_target_hooked(Address)` reports whether a hook from this kit currently patches a given address (an exact same-kit ledger query; it does not see hooks installed by other statically-linked DMK consumers in the same process). To also catch foreign hooks, set `Options::fail_if_already_hooked` on the install
- **Unified errors**: every verb returns `Result<T>` over the unified `ErrorCode`; read `result.error().message()` / `result.error().code` (the old `HookError` / `HookStatus` / `HookType` enums and `error_to_string` are folded into the one error idiom)

</details>

<details>
<summary><strong>Configuration System</strong></summary>

- Load settings from INI files (powered by [SimpleIni](https://github.com/brofield/simpleini))
- Free functions over the process config registry (namespace `DetourModKit::config`); the kit handles parsing and value assignment
- Key combo support via `config::bind_combos` (delivers the parsed `input::KeyComboList` to a callback) and the `config::press_combo` / `config::hold_combo` fusions that also register a live input binding:
  - Format: `modifier+trigger` (e.g., `Ctrl+Shift+F3`)
  - Comma-separated independent combos (e.g., `F3,Gamepad_LT+Gamepad_B`)
  - Named keys (`Ctrl`, `F3`, `Mouse1`, `Gamepad_A`), hex VK codes (`0x72`), and mixed formats
  - Opt-out sentinels: an empty value or the literal `NONE` (case-insensitive, whole-string only) leaves the binding unbound silently. A non-empty value whose every token fails to parse is logged at WARNING level naming the binding and the offending raw string.
- Binding helpers: `config::bind<T>` for `int`/`bool`/`float` (the hot path -- writes the parsed value into a caller-supplied `std::atomic<T>` with `memory_order_relaxed`; the overload without a default uses the atomic's current value as the registration default), the callback-store forms `config::bind_int` / `bind_float` / `bind_bool` / `bind_string`, `config::bind_parsed` (an `std::atomic<uint32_t>` written through a user parse function, e.g. a bitmask), and `config::bind_log_level` (parses an INI string into a logger level). `config::section("X")` returns a `SectionBinder` that drops the repeated section argument, and an `Ini` handle exposes the same operations plus `section()`
- Config is fail-soft: `bind` / `load` return void, `reload` returns `bool`, and `enable_auto_reload` returns an `AutoReloadStatus` enum -- there is no `Result` and no per-domain error enum (a missing or malformed key falls back to the registered default and is logged, never reported as an error)
- **Hot-reload** (see [Config Hot-Reload Guide](docs/config-hot-reload/README.md)):
  - `config::reload()` re-runs every bound setter against the last-loaded INI without touching registrations; skips setters when the on-disk bytes are byte-identical to the last load (FNV-1a content hash)
  - `config::enable_auto_reload()` starts the folded-in background filesystem watcher that debounces editor save-flurries and triggers `reload()` automatically; returns an `AutoReloadStatus` enum indicating outcome. `config::disable_auto_reload()` stops it. There is no separate watcher header -- the watcher engine lives in the non-installed `src/internal/`
  - `config::reload_hotkey()` wires a user-configurable key combo to `reload()` via a `config::press_combo`; the press callback hands off to a dedicated reload-servicer thread so the input poll thread never blocks on INI parsing

</details>

<details>
<summary><strong>Config Hot-Reload</strong></summary>

Two mechanisms share the same `config::reload()` primitive - use either or both:

```cpp
// 1. Initial load stashes the INI path.
config::load("mymod.ini");

// 2. Filesystem watcher: auto-reload on file change (250 ms debounce).
//    on_reload receives true when setters actually ran, false when the
//    content-hash short-circuit skipped the work.
(void)config::enable_auto_reload(std::chrono::milliseconds{250},
                                 [](bool content_changed)
                                 {
                                     if (content_changed)
                                     {
                                         log().info("Config reloaded");
                                     }
                                 });

// 3. Hotkey: user presses Ctrl+F5 (or whatever the INI says) to force reload.
(void)config::reload_hotkey("ReloadConfig", "Ctrl+F5");
input::Input::instance().start();
```

See the [Config Hot-Reload Guide](docs/config-hot-reload/README.md) for the thread-safety contract, debounce rationale, rename-swap-save handling, and the list of settings that are safe to hot-reload vs restart-required.

</details>

<details>
<summary><strong>Logger</strong></summary>

- Process logger value facade reached through the free function `log()` for outputting messages to a log file; construct a dedicated `Logger custom("Prefix", "file.log", "%Y-%m-%d %H:%M:%S")` pointed at its own sink when you need a separate stream (`Logger` is non-copyable and non-movable)
- Configurable log levels, timestamps, and prefixes
- Async logging for high-throughput scenarios
- Format string placeholders for concise log messages
- Formatted methods auto-stamp each record with the call site via `std::source_location`, rendered as a compact `[file:line]` prefix right after the `::` separator
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

- Functions for checking memory readability/writability and writing bytes to memory, all in `namespace DetourModKit::memory` and keyed on the v4 `Address` / `Region` value types
- Optional memory region cache with sharded SRWLOCK concurrency, LRU eviction, and stampede coalescing. Each shard is cache-line-aligned with its lock word and stampede flag stored inline, and in-flight reader liveness is tracked in cache-line-padded per-thread stripes summed at shutdown rather than a single global counter, so concurrent readers do not re-serialize on one shared cache line
- `is_readable_nonblocking(Region)` - tri-state (`ReadableStatus`: readable/not-readable/unknown) for latency-sensitive threads
- `read<std::uintptr_t>(addr)` - safe pointer reads in hot paths (SEH-protected on MSVC, guarded by a process-wide vectored exception handler on MinGW, so the success path issues no per-call VirtualQuery), returning `Result<T>`; `unchecked::read<std::uintptr_t>(addr)` is the raw twin for pointer-chain traversal without per-call SEH overhead (caller must guarantee structural pointer validity), best screened by `is_plausible_ptr(Address)`
- `read<T>(Address)` / `read_into(Address, std::span<std::byte>)` - typed fault-guarded reads for arbitrary trivially copyable T (and contiguous byte ranges), used to walk torn pointer chains and parse PE headers without per-site `__try` boilerplate. Returns `Result<T>` / `Result<void>` so callers can distinguish "read faulted" from "read returned zero"
- `walk(Address base, {offsets})` - resolve a multi-level pointer chain (Cheat-Engine semantics) under one fault guard, so a torn or implausible link aborts the walk and reports the failing hop index in `Error::detail` instead of faulting the host; read or write the resolved `Address` with `read<T>` / `write<T>`. `walk` also accepts `ChainStep{offset, min_valid}` per-hop floors and an optional `std::span<Address>` trace out-param
- `write_in_place<T>(Address, value)` / `write_in_place(Address, std::span<const std::byte>)` - the per-frame data write: it changes no page protection and fails closed (`WriteFaulted`) if the target is not already writable, so a stale pointer that drifts onto a read-only page is reported instead of silently mutating it. Use it for writes to memory the target keeps writable (a camera transform, a player field)
- `write<T>(Address, value)` / `write_bytes(Address, std::span<const std::byte>)` - the escalating write counterpart: they auto-unprotect (a write to a read-only page succeeds; protection is changed only when the fast guarded write faults), which is what a one-shot code patch needs. All return `Result<void>`
- `ProtectGuard::make(Region, Prot)` - move-only RAII page-protection guard that restores the original protection on scope exit
- `module_of(Address)` (returns a `Region`) / `Region::own()` / `Region::host()` - PE image range queries (base + SizeOfImage) for sanity-checking that a resolved vtable or return address lives inside the game image vs the heap or an injected DLL; `is_module_loaded(basename)` checks a module by name. Per-HMODULE cache for `module_of`; magic-static cache for the own and host variants
- `Region::contains(Address)` - constexpr point-in-range test

</details>

<details>
<summary><strong>MSVC RTTI Walker</strong></summary>

- Walks the MSVC x64 RTTI layout (RTTICompleteObjectLocator at `vtable - 8`, TypeDescriptor at `col + 0x0C`, mangled name at `td + 0x10`) to recover an object's concrete type without committing to a fragile vtable address
- `rtti::type_name_of(vtable)` returns the mangled name (e.g. `.?AVMyClass@ns@@`) as `std::optional<std::string>`; `type_name_into(vtable, buf, len)` writes into a caller buffer for zero-allocation per-frame probes
- `rtti::vtable_is_type(vtable, expected)` performs a byte-exact NUL-terminated comparison against an expected mangled name (single SEH-guarded read of `expected.size() + 1` bytes; no allocation)
- `rtti::find_in_pointer_table(table, slot_count, expected, vtable_cache?, stride?)` scans a sparse pointer table for the first slot whose object has the given type; an optional caller-owned `std::atomic<Address>` cache slot lets repeated calls take a single qword-compare fast path after the first match
- `rtti::vtable_for_type(mangled, range?)` is the reverse of `vtable_is_type`: it sweeps a module's readable, non-executable sections for the COL whose name matches and returns the primary (COL.offset == 0) vtable, so a mod keys on a stable class name instead of a patch-fragile vtable literal. `vtables_for_type(...)` returns every sub-object vtable (multiple/virtual inheritance gives one name many vtables); an ambiguous primary fails closed. Returning the COL-anchored vtable address (not its folded slot contents) keeps identity correct under the linker's `/OPT:ICF`
- `rtti::TypeIdentity(mangled, range?)` resolves the primary vtable once, then `matches(vtable)` is a single qword compare -- a name-keyed, patch-surviving per-frame identity check. The mangled name is owned (the `std::string_view` is copied into a `std::string`), so a `std::string` temporary is accepted safely
- Image-base recovery via `COL.pSelf` (canonical IDA/Ghidra approach) so vtables in any loaded module resolve correctly without trusting `GetModuleHandleEx`; the loader call is used only as a fallback for the x86 signature
- All entry points are noexcept and SEH-guarded; unreadable pages, missing COLs, and zero RVAs never fault. Failure surfaces through the return type of each API: `std::nullopt` for the `std::optional` returns (`type_name_of`, `find_in_pointer_table`), `false` for the boolean return (`vtable_is_type`), and `0` for the size return (`type_name_into`, which additionally sets `out[0] = '\0'` on failure)

</details>

<details>
<summary><strong>RTTI Self-Heal (reverse dissection + offset recovery)</strong></summary>

- The reverse direction of the walker, slot-first. It reuses the same verified COL prelude (module-bound-checked, SEH-guarded) rather than duplicating it, and every entry point is noexcept and fails closed
- `rtti::identify_pointee_type(slot_addr, out)` reverse-identifies the object a pointer slot refers to. It accepts whichever shape resolves -- a pointer-to-object (deref once, resolve the pointee's vtable) or a direct object base (the slot is the object, its value is the vtable) -- so an object whose vtable lives in a different DLL than the struct still resolves. The reported `was_pointer` flag is a result, not a precondition. `identify_pointee_typed(...)` is the typed form returning `Result<...>` with the specific fail-closed reason (`ErrorCode::BadSlotAddress` / `UnreadableSlot` / `NoRtti`, in the `ErrorCategory::Rtti` block) instead of a bool, and `identify_pointee_type_or(candidate, out, fallbacks...)` probes a primary slot then ordered fallback slots, returning the first that resolves and preserving the primary's error when all fail
- `rtti::reverse_scan_block(start, slot_count, out, stride?)` RTTI-labels every pointer slot in a struct (allocating triage tool; init-time only)
- `rtti::heal_landmark(lm)` -- the self-healing offset resolver, returning a `Result<HealHit>`. Record a landmark once (`"a field of mangled type T sits near offset O within struct S"`); after a small patch shifts the layout, it scans a `+/-` window around the nominal offset, reverse-RTTI-identifies each slot, and returns the healed field offset via `heal_landmark(lm)->healed_offset`. The nominal offset is checked first and short-circuits, the widened scan prefers the nearest match, and an equidistant tie fails closed as `ErrorCode::HealAmbiguous` (a no-match is `HealNoMatch`, a bad descriptor is `BadDescriptor`) -- the same `require_unique` philosophy the module-scoped `resolve()` uses, transplanted from an AOB scan to a slot scan. The `Landmark` owns its expected mangled name (an `expected_mangled` `std::string`), so it is self-contained and built as a plain runtime value rather than a `static constexpr`
- For an embedded object that may use multiple inheritance, record the landmark with `Indirection::CompleteObject`: it matches only the primary subobject (`COL.offset == 0`), so a heal can never latch a secondary base's adjacent vtable (whose COL still names the complete type) and report an offset shifted by the subobject delta. `HealHit::col_offset` reports that delta; when `was_pointer == false`, a nonzero value means the direct-object match landed on a secondary base
- `rtti::solve_fingerprint(base, landmarks, window)` recovers a single uniform shift across several co-moving fields when one landmark alone would be ambiguous in a dense region
- `rtti::heal_report(landmarks, out)` heals a set in one pass and fills a `DriftEntry` per landmark (`{name, nominal_offset, healed_offset, delta, ok}`) -- a structured "what moved and by how much" report for changelogs, derived purely from the existing heal path
- `rtti::HealScheduler` is a frame-driven runner for self-healing offset groups. `start(HealConfig)` returns a `Result<HealScheduler>` (an `interval_frames == 0` fails closed as `ErrorCode::InvalidArg`); it owns a fixed retry interval (default 30 frames, not geometric backoff), a per-group success latch (retry-until-resolved, no attempt cap), and a CAS one-shot layout-drift `Warning`. `add_group(work, gate?)` registers an independently-latched group whose `work` callback heals via a `HealRun` (`HealRun::heal_into` stores the healed offset to a caller-owned `std::atomic<std::ptrdiff_t>` slot on a hit and keeps the nominal on a miss; `HealRun::note_drift` reports a `solve_fingerprint` bracket's moves). `tick()` drives one frame; the optional gate runs before the interval countdown for a silent pre-gate. Move-only, render-thread only
- Consumers cache the healed **offset** (a `std::ptrdiff_t`), never an absolute address, so a cached delta stays valid across instances and sessions. The library stores nothing: no registry, no lifetimes
- Init-time / re-heal-on-miss, not per-frame: each probe runs the syscall-heavy module-range lookup up to twice. The search window is hard-capped; the hot heal path allocates nothing

</details>

<details>
<summary><strong>Anchor Registry</strong></summary>

- One declarative table (`anchor::Anchor[]`) over the self-healing backends, so every magic constant a mod depends on is declared once with its kind and inputs, then resolved and reported in a single pass instead of a scattered wall of hand-maintained offsets and per-call-site resolvers
- `AnchorKind` covers the backends that resolve from a module range alone: `VtableIdentity` (`rtti::vtable_for_type`), `RipGlobal` (an AOB/RIP cascade returning an absolute address), `CodeOperand` (`scan::read_code_constant`), `StringXref` (`scan::find_string_xref`, the most update-resilient kind: the unique instruction or enclosing function that references an immutable string literal), and `Manual` (a pinned literal, surfaced as at-risk in a report). `Quorum` layers corroboration on top: it accepts a target only when two independent sub-anchors resolve and agree (exact or within a tolerance), so a coincidental match must fool both signals. `CallArgHome` is reserved for a future prologue-dataflow backend and reports `Unsupported`
- Any backend-resolved anchor may carry an optional `validator` (`bool(*)(value, context) noexcept`) that screens the resolved value and fails the anchor closed when it returns false, letting a caller assert a domain invariant a generic backend cannot know
- `anchor::resolve(anchor, range?)` resolves one entry; `resolve_all(anchors, out, range?)` fills a `ResolvedAnchor` report (`{label, kind, status, value}`), and `resolve_all_parallel` does the same work through an opt-in fork-join table resolver. Profile-aware callers have matching `resolve_all_with_profile` and `resolve_all_with_profile_parallel` entry points. Resolution is idempotent and side-effect-free, so re-heal-on-miss is just re-running `anchor::resolve` on the failing anchor
- RTTI pointer-field offset healing (`heal_landmark`) is intentionally not a registry kind: it needs a runtime struct base resolved from another anchor, so it is driven directly once that base is known
- `anchor::anchor_fingerprint(anchor)` hashes only an anchor's declarative resolution evidence -- the compiled `Pattern` content (bytes + wildcard mask + decode params) plus the kind's other inputs (vtable mangled name, string-xref literal and shape flags, or the `Manual` literal) -- and deliberately excludes any resolved address. Two anchors that resolve the same target through the same evidence share a fingerprint even when the target moved between game versions, so a future manifest diff can tell "same evidence, new address" (expected drift the anchor self-healed) from "new evidence path" (the signature itself was rewritten). A `Quorum` combines its two sub-anchors' fingerprints order-independently; the result is a stable 64-bit FNV-1a hash, not a cryptographic digest

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

- Driven through the thread-safe `input::Input` process singleton (`input::Input::instance()`), which owns the poll thread, the binding set, and the process-global interception layer; the poll/edge engine itself lives in the non-installed `src/internal/`
- Two-phase initialization (register bindings, then `start()`) for safe thread launching
- `condition_variable_any` with `stop_token` for responsive cooperative shutdown
- Exception-safe callback invocation
- Automatic hold release on shutdown
- Loader-lock-aware shutdown: background threads are safely detached instead of joined when called from `DllMain` or `FreeLibrary` context

**Performance:**

- Hash-map-backed `Input::is_active(name)` query for low-overhead cross-thread state reads (e.g., from render hooks at 60+ fps)
- Generation-checked `BindingToken`s for the highest-frequency consumers: `Input::acquire_token(name)` resolves a name once, then the `Input::is_active(token)` overload queries it every frame without the per-call name hash. The token carries the binding generation it was minted at; any reshape (register / remove / clear / rebind / consume change) advances the generation, so a stale token fails closed (returns false) instead of reading a different binding, and `Input::token_current(token)` lets a consumer detect the reshape and re-acquire. The generation is process-wide unique, so a token can never alias a different engine after a shutdown / start cycle
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
- `Input::set_consume(name, true)` hides a binding's trigger from the game so the mod and the game do not both act on it -- applied per binding, so one binding can pass through while another is blocked. Honored for digital gamepad buttons (D-pad, face buttons, bumpers, stick clicks) via an `XInputGetState` hook, and for the mouse wheel; analog triggers, stick directions, keyboard, and mouse-button suppression are not provided (the gamepad detour clears only the digital `wButtons` bitmask). The fix targets the classic chord case (e.g. "LB + D-pad" zoom) where releasing the modifier a frame before the trigger would otherwise leak a bare trigger: suppression is latched to the trigger button's own release, plus a short grace window. Only the trigger is hidden, not the modifier.
- `config::consume_flag(section, ini_key, display_name, binding_name, default)` drives the same flag from the INI, so the choice lives next to the combo (register the binding first, then the flag):

  ```ini
  [Hotkeys]
  SetXToggle = Gamepad_LB+Gamepad_RB    ; passes through to the game
  SetYToggle = Gamepad_LB+Gamepad_Y     ; blocked from the game
  SetYToggle.Consume = true
  ```

  ```cpp
  (void)input::register_combo({.name = "set_x", .combos = cfg.set_x, .on_press = []{ /* ... */ }});
  (void)input::register_combo({.name = "set_y", .combos = cfg.set_y, .on_press = []{ /* ... */ }});
  config::consume_flag("Hotkeys", "SetYToggle.Consume", "Set Y Consume", "set_y", false);
  ```
- Both hooks are opt-in: a mod that registers neither a wheel binding nor a `consume` binding installs nothing and the input system stays purely observational.

**Configuration integration:**

- Load input codes from INI files (named keys, hex VK codes, or mixed)
- Named key resolution uses binary search for efficient lookup
- `input::register_combo(ComboBinding{...})` takes a designated-init aggregate carrying a `KeyComboList` directly, for zero-boilerplate binding of config-parsed key combos; it returns a move-only `input::BindingGuard` (wrapped in a `Result`) that owns the callback's lifetime
- Live registration: `register_combo` appends bindings to a running engine, and `Input::clear_bindings()` / `Input::remove_bindings_by_name()` drop bindings without stopping the poll thread, so consumers can re-arm input on hot-reload without a full restart
- `config::press_combo` / `config::hold_combo` fuse an INI combo item, the matching press/hold input binding, automatic rebind on `reload()`, and an `input::BindingGuard` cancellation token into one call. The hold variant's guard synthesizes a single balancing `on_state_change(false)` when cancelled mid-hold, so tearing a hold down cannot strand the consumer in the held state. An `input::Scope` (or the process-default `input::scope()`) owns a batch of guards and releases them in reverse insertion order
- Both combo fusions take an optional per-binding `consume` facet: pass `consume` to register a `"<ini_key>.Consume"` bool inline (wired to `set_consume`) instead of a separate `config::consume_flag` call. `std::nullopt` (the default) registers no extra key and preserves the prior behavior exactly; suppression honors the same gamepad-digital + mouse-wheel scope noted above, so a `.Consume` key on a keyboard-only binding is inert

</details>

<details>
<summary><strong>Session and Mod Bootstrap</strong></summary>

- `Session` is the RAII owner of a mod's process lifetime: its destructor runs the correctly ordered teardown of every process-wide subsystem, replacing the error-prone manual shutdown sequencing a mod would otherwise write by hand. Two ways to build one: `Session::start(ModInfo)` (synchronous, returns `Result<Session>`; the simple/testable path) and `bootstrap(ModInfo, on_ready)` (the DllMain path)
- `bootstrap()` / `bootstrap_detach()` replace the manual `DllMain` + `CreateThread` + `InitThread` scaffolding every mod would otherwise write; `bootstrap()` spawns a worker thread that runs `on_ready(Session&)` off the loader lock, then hosts the Session until detach
- Configures `Logger` (`name` prefix + `log_file`) and enables async logging (`log`) automatically before `on_ready` runs, so the first message travels the async path
- Optional process-name gate (`game_process_name`): a mismatch makes `start()` return `ErrorCode::ProcessMismatch` so the DLL can decline to load in the wrong executable (case-insensitive basename)
- Optional per-PID named mutex (`instance_mutex_prefix`): a duplicate load returns `ErrorCode::InstanceAlreadyRunning`
- `on_ready` runs on a dedicated Win32 worker thread off the loader lock, free to call Win32 APIs that would deadlock under `DllMain`; there is no separate shutdown callback, because `~Session` (RAII) is the teardown
- `~Session` clears the mod's `input::Scope` first, then tears down the config watcher, input, memory cache, config registry, and logger (last) in reverse dependency order; each subsystem embeds its own loader-lock guard (join when safe, detach-and-leak when the loader lock is held)
- `request_shutdown()` signals the worker to drain so a mod can trigger its own clean unload before `FreeLibrary` and keep teardown off the loader lock (see the [Hot-Reload Guide](docs/hot-reload/README.md))
- `bootstrap_detach(lpvReserved)` handles the `DLL_PROCESS_DETACH` process-exit vs dynamic-unload distinction automatically: `NULL` runs the ordered teardown, non-`NULL` takes the `abandon()` path (do nothing; the OS reclaims a dying process)
- `on_logic_dll_unload(binding_names)` drops only the named per-Logic-DLL bindings and the config registry, leaving Logger alive for whichever container hosts the next Logic-DLL incarnation (hooks are caller-owned RAII and are never touched)
- `on_logic_dll_unload_all()` is the catch-all variant for callers without an explicit name registry; in a host that loads multiple Logic DLLs sharing one DMK instance, prefer the named-list overload because the catch-all rips out every Logic DLL's bindings
- Hot-reload teardown: `on_logic_dll_unload` is the lighter alternative to a full `~Session` for multi-DLL or fast-iteration setups (see [docs/hot-reload/README.md](docs/hot-reload/README.md))

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
- Process-wide typed event bus: `Diagnostics::scanner_faults()` and `Diagnostics::hook_lifecycle()` each return one stable `EventDispatcher<>` for the process lifetime. The stateless scanner emits a `ScannerFaultEvent` (skipped-region count + scanned window) once per sweep that skips a region faulting mid-scan; a `Hook` emits a `HookLifecycleEvent` (`name`, `HookKind`, `HookTransition`) after a create / enable / disable / remove transition completes, so a handler runs outside the hook's critical section. Failed operations and idempotent no-ops emit nothing. Both use `emit_safe`, so with no subscribers the cost is a single atomic load after the dispatcher has been constructed
- `Diagnostics::collect(drift_report?, anchor_report?)` aggregates the live diagnostics into one `Diagnostics::Snapshot` -- the leak tallies, the live hook population (`hooks_total` / `hooks_active` / `hooks_disabled`, derived from the hook-lifecycle transition stream), a healed/failed count over a `heal_report()` drift report, and an `anchor_quality` roll-up (via `anchor::assess_quality`) over a resolved-anchor report -- so a diagnostics command can capture a one-shot health view in a single call

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
* [Hot-Path Memory Guide](docs/misc/hot-path-memory.md) - Reading and writing game memory in per-frame hot paths with the `memory::read` / `write` / `walk` and `unchecked::read` primitives
* [Hot-Reload Development Guide](docs/hot-reload/README.md) - Development workflow for iterating on hooks with live reload
* [Config Hot-Reload Guide](docs/config-hot-reload/README.md) - INI filesystem watcher and hotkey-triggered `config::reload()`
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
    installed `DetourModKit::DetourModKit` target, and touches `hook::inline_at`
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
    │   │   ├── defines.hpp           <-- v4 portability macros + `dmk` alias
    │   │   ├── address.hpp           <-- v4 Address value type
    │   │   ├── region.hpp            <-- v4 Region + Prot flags
    │   │   ├── error.hpp             <-- v4 ErrorCode / Error / Result<T> / DMK_TRY
    │   │   ├── scan.hpp              <-- v4 scanning surface (scan::Pattern + resolve / Candidate / ScanRequest)
    │   │   ├── anchor.hpp            <-- Declarative anchor registry (namespace anchor): AnchorKind / Anchor / ResolvedAnchor / AnchorQuality / ScanProfile / resolve_all / anchor_fingerprint
    │   │   ├── async_logger.hpp      <-- Async logging system (AsyncLogger)
    │   │   ├── async_logger_config.hpp <-- Lightweight OverflowPolicy + AsyncLoggerConfig (logger.hpp / dmk.hpp stay light)
    │   │   ├── detail/               <-- Installed compile-visible support (pattern_core.hpp + demoted headers: event_dispatcher.hpp, win_file_stream.hpp, worker.hpp, drift_manifest.hpp; private impl lives in src/internal/)
    │   │   ├── dmk.hpp               <-- Umbrella + Session / bootstrap / bootstrap_detach / ModInfo (DllMain lifecycle)
    │   │   ├── config.hpp
    │   │   ├── diagnostics.hpp       <-- Per-subsystem intentional-leak counters + process-wide event bus + one-call Snapshot aggregator (hooks_total/active/disabled, anchor quality, drift report)
    │   │   ├── format.hpp            <-- String & format utilities
    │   │   ├── math.hpp              <-- Math utilities (angle conversions)
    │   │   ├── memory.hpp            <-- Memory utilities
    │   │   ├── profiler.hpp          <-- Scoped timing (zero-cost when disabled)
    │   │   ├── filesystem.hpp        <-- Filesystem utilities
    │   │   ├── hook.hpp              <-- v4 hooking surface (inline_at / mid_at / install_all / vmt_for -> RAII Hook)
    │   │   ├── input.hpp             <-- Input/hotkey system
    │   │   ├── input_codes.hpp       <-- Unified input codes (keyboard/mouse/gamepad)
    │   │   ├── logger.hpp            <-- Synchronous logger
    │   │   ├── version.hpp           <-- Version macros (generated by CMake)
    │   │   └── ...
    │   └── DirectXMath/              <-- DirectXMath headers (re-exported by default; -DDMK_INSTALL_DIRECTXMATH=OFF omits them)
    │       ├── DirectXMath.h
    │       ├── DirectXMathVector.inl
    │       └── ...
    │                                 (no safetyhook headers: the backend is confined, so its headers are not installed)
    ├── lib/
    │   ├── libDetourModKit.a         <-- Static libraries (.a for MinGW, .lib for MSVC)
    │   ├── libsafetyhook.a           <-- Backend archives ship for the transitive link only; their headers are not installed
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

When `DMK_ENABLE_AVX512` is OFF (the default) the tier compiles out entirely. When ON, the AVX-512 intrinsics are confined to that single function via a per-function `target` attribute (no global `/arch:AVX512` or `-mavx512`), so the rest of the library keeps its AVX2 baseline and the produced binary still runs on CPUs without AVX-512: the tier is selected only when a runtime `CPUID` + `XGETBV` check confirms both the CPU and OS support AVX-512F and AVX-512BW, otherwise the scanner falls back to AVX2. `scan::active_simd_level()` reports the tier actually in use. The tier's `>= 30%` throughput gate is hardware-specific and can only be measured on a real AVX-512 host. Per-tier correctness (including AVX-512) runs under Intel SDE on every push to main via `.github/workflows/simd-tier-correctness.yml`.

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

> **Short names and `DMK_NO_SHORT_NAMES`:** including `<DetourModKit/dmk.hpp>` introduces `DMK`-prefixed convenience aliases. The namespace aliases (`DMK::`, `DMKConfig::`, `DMKScan::`, `DMKHook::`, ...) are always present, and the type aliases used below (`DMKLogger`, `DMKKeyComboList`, ...) keep mod code terse. They are all `DMK`-prefixed, so collision risk is low. For a larger consumer project that prefers to keep the global namespace minimal, define `DMK_NO_SHORT_NAMES` before the include to drop the type aliases (the `DMK::` namespace aliases remain) and use the fully qualified `DetourModKit::` names instead.

```cpp
// MyMod/src/main.cpp
#include <windows.h>
#include <Psapi.h>

#include <optional>   // the RAII Hook handle is stored in an std::optional global

// Single include for all DetourModKit functionality (umbrella + Session / bootstrap lifecycle)
#include <DetourModKit/dmk.hpp>

// The v4 hooking surface lives in hook.hpp (pulled in by the umbrella above): hook::inline_at / mid_at install a hook
// and hand back a move-only RAII DetourModKit::hook::Hook whose destructor restores the prologue. A mid-hook detour
// takes an opaque DetourModKit::hook::MidContext, so a detour body no longer needs SafetyHook on the include path.
// The backend is confined: SafetyHook's headers are not installed with DetourModKit (only its static archive ships, for
// the transitive link), so `#include <safetyhook.hpp>` is not reachable from a find_package consumer; vendor SafetyHook
// yourself if you must call it directly. SimpleIni is an internal build-time dependency and is likewise NOT installed;
// do not include <SimpleIni.h> from a find_package consumer. Use the DetourModKit::config API for INI access instead.

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

// The hook is owned by its RAII handle. Hook is move-only with no default constructor, so a global one lives in an
// std::optional that InitializeMyMod engages via std::optional::emplace; dropping it (or letting it leave scope)
// restores the original prologue.
std::optional<DMKHook::Hook> g_print_hook;

// Detour function
void __stdcall Detour_GameFunction_PrintMessage(const char *message, int type)
{
    auto &logger = DMK::log();
    logger.info("Detour_GameFunction_PrintMessage CALLED! Original message: \"{}\", type: {}", message, type);

    // original<Fn>() is the typed trampoline to the un-hooked function (UNGUARDED fast path). It is non-null only
    // while the hook is engaged; use call<Ret>(args...) instead if a teardown can race this detour.
    const auto call_original =
        g_print_hook ? g_print_hook->original<OriginalGameFunction_PrintMessage_t>() : nullptr;
    if (!call_original)
    {
        return;
    }

    if (g_mod_config.enable_greeting_hook)
    {
        logger.debug("Modifying message because greeting hook is enabled.");
        call_original("Hello from DetourModKit! Hooked!", type + 100);
        return;
    }

    call_original(message, type);
}

// Mod init callback (runs on the bootstrap worker thread, off the loader lock). It receives the live Session and
// returns a Result<void>, so an init failure is a value logged on the worker, never a throw across the loader lock.
DMK::Result<void> InitializeMyMod(DMK::Session &session)
{
    // Logger + async mode are already configured by bootstrap() using the ModInfo passed into the attach call below.
    // session.log() is the same process-default logger DMK::log() returns.
    auto &logger = session.log();

    // Bind your configuration variables (callback-store API; config::bind<T> is the atomic hot path)
    DMKConfig::bind_bool("Hooks", "EnableGreetingHook", "Enable Greeting Hook",
        [](bool v) { g_mod_config.enable_greeting_hook = v; }, true);
    DMKConfig::bind_string("Debug", "LogLevel", "Log Level",
        [](std::string_view v) { g_mod_config.log_level_setting = std::string{v}; }, "INFO");

    // Bind hotkey combos from INI (modifier+trigger format)
    // Comma separates independent combos: "F3,Gamepad_LT+Gamepad_B" (F3 OR LT+B)
    // Plus separates modifiers from trigger: "Ctrl+Shift+F3" (AND for modifiers, last = trigger)
    // Hex VK codes still work: "0x72", "0x11+0x72"
    // Mouse: "Mouse4", "Ctrl+Mouse1"
    // Gamepad: "Gamepad_A", "Gamepad_LB+Gamepad_A"
    DMKConfig::bind_combos("Hotkeys", "ToggleKey", "Toggle Keys",
        [](const DMKKeyComboList &c) { g_mod_config.toggle_combo = c; }, "F3");
    DMKConfig::bind_combos("Hotkeys", "HoldScrollKey", "Hold Scroll Keys",
        [](const DMKKeyComboList &c) { g_mod_config.hold_scroll_combo = c; }, "");

    // Load configuration from INI file (after the binds above, so load() applies file values to them). session.ini()
    // is a thin handle to the same process config registry the free config:: functions act on.
    session.ini().load("MyMod.ini");

    // Apply LogLevel from loaded configuration
    logger.set_log_level(DMK::string_to_log_level(g_mod_config.log_level_setting));

    // Log the loaded configuration
    logger.info("MyMod configuration loaded and applied.");
    DMKConfig::log_all();

    // Initialize Hooks (v4: free verbs returning a move-only RAII Hook handle).
    // DMKScan is the namespace alias for DetourModKit::scan (from scan.hpp); DMKHook for DetourModKit::hook.

    // The hook target is a scan::OwnedScanRequest: hook::inline_at resolves it at install time (resolve-on-install)
    // and never carries a dangling pattern span. A one-candidate ladder is the simplest form; ship a fallback
    // ladder for a long-lived mod (see the AOB Signature Scanning Guide).
    DMKScan::OwnedScanRequest target{
        .ladder = {DMKScan::Candidate::direct("GameFunction_PrintMessage",
                                              DMKScan::Pattern::literal("48 89 ?? ?? 57"))},
        .label = "GameFunction_PrintMessage",
        .scope = DetourModKit::Region::host(),   // the host EXE; defaults here too
    };

    // inline_at performs the single audited function-to-void* cast for you; the call site writes no reinterpret_cast.
    // Options::prologue defaults to Prologue::Fail (v4 safe-by-default: an E8/CC/CD prologue is refused with
    // ErrorCode::TargetPrologueUnsafe). Pass Options{.prologue = DMKHook::Prologue::Relocate} for the old install-anyway.
    auto result = DMKHook::inline_at(
        DMKHook::InlineRequest{
            .name = "GameFunction_PrintMessage_Hook",
            .target = std::move(target),
        },
        &Detour_GameFunction_PrintMessage);

    if (result.has_value())
    {
        // Take ownership of the RAII handle for the hook's lifetime. While it lives, the detour is engaged and
        // g_print_hook->original<Fn>() is the trampoline; dropping it restores the prologue.
        g_print_hook.emplace(std::move(*result));
        logger.info("Successfully installed hook: {}", g_print_hook->name());
    }
    else
    {
        logger.error("Failed to install hook: {}", result.error().message());
        return false;
    }

    // Register hotkey bindings with the input system (after hooks are ready).
    // register_combo takes a ComboBinding aggregate carrying the KeyComboList
    // directly. One engine entry is created per combo, all sharing the binding
    // name for OR-logic queries. It returns a Result<BindingGuard>; on success,
    // park the move-only guard in the process-default scope so it lives for the
    // process. (config::press_combo / hold_combo wrap this with INI parsing and
    // hand back the guard directly, no Result to unwrap.)
    if (auto toggle = DMKInput::register_combo({
            .name = "toggle_view",
            .trigger = DMKInput::Trigger::Press,
            .combos = g_mod_config.toggle_combo,
            .on_press = []() { DMK::log().info("Toggle key pressed!"); },
        }))
    {
        // Park the guard in the Session's scope: ~Session clears it first, in reverse insertion order.
        session.scope().add(std::move(*toggle));
    }

    if (auto scroll = DMKInput::register_combo({
            .name = "hold_scroll",
            .trigger = DMKInput::Trigger::Hold,
            .combos = g_mod_config.hold_scroll_combo,
            .on_state_change = [](bool held)
            { DMK::log().info("Hold scroll: {}", held ? "active" : "released"); },
        }))
    {
        session.scope().add(std::move(*scroll));
    }

    // Start the input polling thread (focus-aware by default)
    (void)DMKInput::Input::instance().start();

    logger.info("MyMod Initialized using DetourModKit!");
    return {}; // success
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DMK::ModInfo info{
            .name = "MyMod",                            // logger prefix + mod identity
            .log_file = "MyMod.log",
            .game_process_name = "MyGame.exe",          // optional -- set "" to disable
            .instance_mutex_prefix = "MyMod_Instance",  // optional -- set "" to disable
        };
        info.log.queue_capacity = 8192;
        info.log.batch_size = 64;

        // bootstrap() spawns the worker, runs InitializeMyMod(session) off the loader lock, and hosts the Session until
        // detach. It returns Result<void>; a failure (process gate / instance mutex / worker spawn) declines the load.
        return DMK::bootstrap(info, &InitializeMyMod).has_value() ? TRUE : FALSE;
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        // Drop caller-owned hooks to restore prologues on an explicit FreeLibrary (lpReserved == NULL). On process exit
        // (lpReserved != NULL) leave them: the OS reclaims a dying process and touching patched pages is a UAF.
        if (lpReserved == nullptr)
        {
            g_print_hook.reset();
        }
        // NULL -> the ordered ~Session teardown; non-NULL -> abandon (do nothing).
        DMK::bootstrap_detach(lpReserved);
    }
    return TRUE;
}
```

> [!WARNING]
> `DMK::bootstrap()` runs `InitializeMyMod` on a dedicated worker thread, so it
> executes off the loader lock, and `~Session` runs the ordered teardown there too.
> For a dynamic `FreeLibrary` unload, call `DMK::request_shutdown()` *before* issuing
> `FreeLibrary` so the worker has time to drain (and drop your caller-owned `Hook`
> handles to restore prologues). Each subsystem also detects the loader lock and will
> detach background threads instead of joining them, but requesting shutdown early
> ensures all log messages are flushed. See the
> [Hot-Reload Guide](docs/hot-reload/README.md) for the recommended two-DLL
> architecture.

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
