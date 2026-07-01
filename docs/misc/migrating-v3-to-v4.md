# Migrating from DetourModKit v3.x to v4.0.0

v4.0.0 is a deliberate clean break: it ships zero legacy spellings and drops backward compatibility to
establish a 100% modern C++23 surface. Every distinct v3 capability survives in a clean v4 idiom -- this
guide maps the old surface onto the new one. Nothing here is a capability loss except the one documented
deferral (per-method VMT hooking).

## At a glance

| Area | v3 | v4 |
|---|---|---|
| Errors | per-domain enums (`HookError`, `ResolveError`, `RipResolveError`, `StringXrefError`, ...) | one unified `ErrorCode` returned in `Result<T>` (`std::expected<T, Error>`) |
| Hooks | `HookManager` singleton + registry batch ops | caller-owned RAII `Hook` / `VmtHook` handles; free verbs `inline_at` / `mid_at` / `vmt_for` |
| Scanner cascades | `resolve_cascade_*` family, `scan_regions_batch` / `scan_module_batch` | `scan::resolve(ScanRequest)` / `scan::resolve_batch` |
| RTTI heal | `Rtti::heal_offset(...)` | `rtti::heal_landmark(...)->healed_offset` |
| Shared mutex | public `DetourModKit::SharedMutex` | removed from the public API (vendor your own) |
| Anchor identity | `anchor_fingerprint` hashed the AOB source text | hashes the compiled `Pattern` bytes + mask (evidence, not spelling) |

## Errors are values

Every fallible entry point now returns `Result<T>` (`std::expected<T, Error>`) over a single `ErrorCode`.
The per-domain error enums are gone; branch on `result.error().code` and stringify with
`to_string(result.error().code)`. The formerly-separate `HookError` / `ResolveError` / `RipResolveError` /
`StringXrefError` values are folded into the one `ErrorCode`.

## Hooks: caller-owned RAII, no registry

The `HookManager` singleton and its aggregate operations are removed:

- `enable_all_hooks` / `disable_all_hooks` -- gone. Each hook is owned by its own `Hook` handle; enable or
  disable it directly (`h.enable()` / `h.disable()`), or store the handles and iterate your own container.
- `get_hook_counts` / `get_hook_ids` -- gone. Aggregate population figures are now read-only via
  `Diagnostics::collect().hooks_total` / `hooks_active` / `hooks_disabled`. That tally is keyed on each
  hook's process-unique ledger id, so two hooks that share a name (on distinct targets) each count.
- Install a hook with `hook::inline_at` / `hook::mid_at` / `hook::vmt_for`; drop the returned handle to
  unhook. The declarative `hook::install_all(span<HookSpec>) -> Result<vector<InstallOutcome>>` table folds
  the ceremony into rows with a per-row `Mandatory` / `BestEffort` severity.
- **Per-method typed VMT hooking is deferred** to a later release. Object-level VMT hooking (`vmt_for` /
  `apply_to` / `remove_from`, restoring every vptr on drop) ships in v4.0.0.

## Scanning: one resolver surface

The v3 `resolve_cascade_*` family and the public raw batch primitives (`scan_regions_batch` /
`scan_module_batch`) collapse into the `scan::resolve` surface:

- `scan::resolve(ScanRequest)` resolves an ordered candidate ladder; scope, prologue fallback, per-request
  uniqueness, candidate order, and byte-tier page class are `ScanRequest` fields rather than function-name
  variants.
- `scan::resolve_batch(requests, max_workers)` is the parallel batch. **Its return type changed to**
  `Result<std::vector<Result<Hit>>>`: the OUTER `Result` is the whole-batch signal (`Error{OutOfMemory}`
  when even the per-request result container cannot be allocated), and the inner vector holds one
  `Result<Hit>` per request in input order. Unwrap the outer `Result` before indexing so a whole-batch
  failure can never be silently indexed past (the same shape as `hook::install_all`). On GCC/libstdc++,
  index the inner vector rather than range-for over it (a bare `std::expected` element trips an `<expected>`
  equality-constraint recursion; indexed access sidesteps it).
- `ScanRequest::pages` (default `Pages::Readable`) selects the byte tiers' page class. `Pages::Executable`
  narrows the sweep to code pages so a byte signature that must land on an instruction cannot alias an
  identical run in `.rdata` / `.data`. This restores v3's executable-only cascade knob.
- The raw parallel batch primitive is retained privately (`src/internal/scan_batch.*`); the public parallel
  batch is `resolve_batch`.

## RTTI self-heal

The `Rtti::heal_offset(...)` convenience wrapper is removed. Read the healed value through the landmark:
`rtti::heal_landmark(...)->healed_offset`.

## `SharedMutex` is no longer public

`DetourModKit::SharedMutex` is now an internal implementation detail (`src/internal/`), never installed. A
consumer that used it must vendor its own shared/reader-writer mutex.

## `memory::unchecked::read<T>`

The raw fast path keeps its "the caller has proven this access is safe" contract. In a **Debug** build it now
carries a dev-only `assert(is_readable(...))` that trips at the offending call site instead of a raw access
violation deep in the copy. In a **Release** build (`NDEBUG`) the assert is compiled out entirely, so there
is **no diagnostic at all** -- an invalid address faults the host exactly as before. Reach for the guarded
`memory::read` whenever an address might be stale.

## Anchor fingerprints changed their hash domain

`anchor::anchor_fingerprint` hashes the compiled `Pattern` bytes + wildcard mask (plus the decode
parameters), not the authored AOB source text v3 hashed. This is a correctness improvement (evidence over
spelling), but **any v3-persisted fingerprint will not match its v4 recomputation** -- rebuild any stored
fingerprint baselines.

## Toolchain / ABI

v4 is a C++23 static library with a pure C++ ABI (no `extern "C"` boundary). Consume it only from the same
compiler family, standard library, and CRT / iterator-debug configuration that built the installed prefix.
The configure step probes for `std::expected`, `std::move_only_function`, and `std::format` and fails early
on a standard library too old to provide them. See the "ABI / toolchain compatibility" note in the README.
