# Public API design

This note explains the public API. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-12]`, `[B-13]`, `[B-69]`, `[B-78]`.

## detail/ header placement

`include/DetourModKit/detail/` holds compile-visible support that a public header or the umbrella must include: templates, constexpr, public object layout. Membership is allowlisted only, backend-free (no SafetyHook/Zydis), and Win32-free. Support that touches a backend or Win32 belongs in `src/internal/`.

Membership is gated on compile-visibility, not purity:

- Requirement: a header that an installed header must include at compile time stays in `detail/`. Such a header can use the heap or the logger when the installed header it supports genuinely needs that. Prefer to keep it logger-free and heap-free where the support allows.
- Prohibition: never push such a header down to `src/internal/`, where it can no longer be included, merely to satisfy that preference.

The `detail/` directory and the `detail` namespace are independent axes. A `detail/` header declares its types in whatever namespace its supported surface needs: the root `::detail` namespace, a module root, or a module's own namespace. A published header path is a consumer contract, so a member is blessed in place rather than relocated to line the two axes up. New implementation-support *types* still default to `namespace detail` (see the AGENTS.md rulebook).

## TU placement

TU placement mirrors the header's install-visibility. A `.cpp` lives beside the KIND of header it implements:

- A TU that implements an installed header (a public `include/DetourModKit/*.hpp` or an allowlisted `detail/*.hpp`) goes in `src/`.
- A TU that implements a true-private `src/internal/*.hpp` goes in `src/internal/` beside that header.
- A headerless facade-split of a public module owns no same-named header but implements part of the module's surface. It is public-module implementation and goes in `src/`.

The `.cpp` location is contract-neutral, because no `.cpp` is ever installed. This is a legibility rule, not an ABI one. It is still enforced uniformly, so a reader can predict where any definition lives from its header.

## Windows header boundary

Installed headers also serve consumer tools that do not expose Win32 names. The preprocessor guard preserves that boundary. `scripts/check_header_hygiene.py` separately rejects direct Win32 includes and private implementation leaks.

## API-discipline labels

Three labels classify a function's call-site safety. A public docblock must carry one label when the declaration is a mutating verb (for example install/enable/disable/teardown, cache init/shutdown, config load or reload), a documented hot-path function, or a cache predicate. Other docblocks can carry a label but do not have to. This section owns the scope rule. A label can be state-qualified when the tier boundary is part of the contract (for example `Callback-safe once warm`). The qualifier and the fallback tier stay in the same `@note`. The label is applied as a `@note` and kept alongside, never in place of, any existing more-specific caveat. The label states where a call belongs. A hazard that the caller can deadlock or hang on belongs in a sibling `@warning`, not folded into the label's `@note`. Examples: an unbounded wait, consumer code run on the caller's thread, a lock or join the caller must not hold.

- *Callback-safe*: non-blocking, no unbounded allocation, no blocking I/O, no lock escalation. Safe to call from a hook or input callback on a game thread. This tier holds the hot-path reads and status queries.
- *Setup/control-plane only*: the call can block, allocate, take exclusive locks, or do I/O. Call it from init, shutdown, or a worker thread, never from a hook or input callback. This tier holds create/remove, enable/disable, start/stop/shutdown, config load/reload, and cache init.
- *Best-effort*: on failure the call fails closed (no-op, false, or dropped) and never throws or terminates the host. This tier holds logging, diagnostics counters, `emit_safe`, and the noexcept fail-closed paths.

## Error returns

The error model is two-tier, not uniform.

Fallible mutating operations on the memory, scanner, resolver, anchor, manifest, and hook-core surfaces return `Result<T>`. That is the single library-wide error-as-value alias `std::expected<T, Error>`, with `Result<void>` when there is no value. A nested failure propagates through the `DMK_TRY` / `DMK_TRY_VOID` pair rather than a hand-unwrap of the `std::expected`.

By contrast, deliberately best-effort and query surfaces return `bool`, `std::optional`, or `void` by design and never surface an `Error`. Those surfaces are:

- the RTTI query API (`type_name_of`, `vtable_is_type`, `region_has_rtti`),
- config load/reload/bind (fail-soft to registered defaults, see `config.hpp`),
- `EventDispatcher` emit/subscribe.

Those belong to the *Best-effort* tier of the API-discipline labels above. A surface in that tier MUST document its non- `Result` return rather than let the reader assume uniformity.

Reserve exceptions for construction failures and truly exceptional conditions.

## Rules

### [B-12]

A third-party backend type that a public signature otherwise names is pimpl'd behind a forward-declared `Impl`. The `Impl` definition lives in a non-installed `src/internal/` header included only by the owning `.cpp` (the SafetyHook objects behind `src/internal/hook_backend.hpp`). A backend value that the API must hand to a callback is surfaced as an opaque pass-through type plus free accessors. It never appears as the backend type in the header. `hook::MidContext` with `gpr()`, `stack_pointer()`, `instruction_pointer()`, and `xmm()` is the worked example.

### [B-13]

The struct form is already the dominant DMK shape: `hook::Options`, `hook::VmtOptions`, `scan::ScanRequest`, `StringRefQuery`, `CodeConstant`, `anchor::GatePolicy`, `manifest::Binding`. `scan::resolve(ScanRequest)` keeps scope, uniqueness, candidate order, and page class in struct fields instead of positional arguments. A struct self-documents the call site and removes the transpose hazard.

A new field must follow all established fields and have a default. That addition preserves source compatibility only when a caller's positional aggregate initialization supplies the established prefix and does not depend on the old member count. It does not preserve binary compatibility, because object size and layout can change. A new positional parameter breaks source compatibility.

The two standing high-arity idioms are deliberately mitigated and are the pattern for anything new, not a licence to reflood:

- The config binding family (`bind_*`, `press_combo`, `consume_flag`) leads with `section` + `key` + `display_name`. The `SectionBinder` overloads reduce it: they capture the section once.
- The `scan::borrow*` factories are convenience presets over the safe `ScanRequest` struct. That struct, or the named `borrow_code_target`, is the transpose-free path.

Reach for the struct form on every new public entry point.

### [B-69]

`error.hpp` documents that `SystemCallFailed`'s `detail` carries `GetLastError()`, and `detail::acquire_module_ref` restores the thread's last-error on failure precisely so its caller can read it. A failure site that builds `Error{SystemCallFailed, where}` with no detail leaves the consumer with a read of 0.

Capture `::GetLastError()` into a local the instant the primitive returns failure. Any intervening call (a ledger `release_hook`, a log, an allocation) can overwrite the thread's last-error. Then build the Error from that captured local. The three `acquire_hook_self_ref` failure branches in `hook.cpp` do this. The DWORD widens into the `std::uintptr_t detail` slot without narrowing.

### [B-78]

A public header that publishes a global alias, `using` -declaration, or macro adds that name to every consumer's global scope, wanted or not. A short project tag is exactly the kind of name a consumer plausibly already owns: their own `dmk` variable, a `DMK` macro, another library's namespace.

`defines.hpp` publishes the convenience namespace aliases `dmk` / `DMK`, so it wraps both in `#if !defined(DMK_NO_NAMESPACE_ALIASES)`. A consumer with a collision, or one who prefers the full spelling, defines that macro before the first DetourModKit include and the aliases vanish. The primary `DetourModKit` namespace is always established either way, so `DetourModKit::Foo` keeps working and no capability is lost.

Any future global-scope injection from a public header follows the same shape: additive by default, suppressible by a documented `DMK_NO_*` macro, never unconditional.
