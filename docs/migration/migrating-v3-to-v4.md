# Migrating from DetourModKit v3.x to v4.0.0

v4.0.0 is a deliberate clean break: it ships zero legacy spellings and drops backward compatibility to establish a C++23 value/RAII surface. The core modding capabilities carry forward, but several v3 helper/support types were deliberately internalized or demoted. This guide maps the old surface onto the new one and calls out the few places where a consumer must vendor its own helper.

## At a glance

| Area | v3 | v4 |
|---|---|---|
| Namespaces | PascalCase modules (`Config`, `Scanner`, `Memory`, `Rtti`, `Anchors`, `Diagnostics`) plus umbrella aliases (`DMKConfig`, ...) | lowercase modules (`config`, `scan`, `memory`, `rtti`, `anchor`, `diagnostics`); add your own aliases if desired |
| Errors | per-domain enums (`HookError`, `ResolveError`, `MemoryError`, `HealError`, ...) | one unified `ErrorCode` returned in `Result<T>` (`std::expected<T, Error>`) |
| Lifecycle | `DMK_Shutdown`, `Bootstrap::on_dll_attach`, `Bootstrap::on_dll_detach` | RAII `Session`, `bootstrap`, `bootstrap_detach`, `shutdown_and_wait`, `request_shutdown` in `<DetourModKit.hpp>` |
| Hooks | `HookManager` singleton + registry batch ops | caller-owned RAII `hook::Hook` / `hook::VmtHook` handles; free verbs `inline_at` / `mid_at` / `vmt_for` |
| Scanner cascades | `Scanner::resolve_cascade_*`, `scan_regions_batch` / `scan_module_batch` | `scan::resolve(ScanRequest)` / `scan::resolve_batch` |
| Memory | `Memory::*`, raw pointers / `uintptr_t`, `ModuleRange`, `std::optional` / bool failure | `memory::*`, `Address`, `Region`, `Prot`, `Result<T>` |
| Config/input | `Config::register_*`, `InputManager`, public `InputPoller` | `config::bind_*`, `config::press_combo` / `hold_combo`, `input::Input`, `input::BindingGuard`, `input::Scope` |
| RTTI heal | `Rtti::heal_offset(...)` | `rtti::heal_landmark(...)->healed_offset` |
| Anchor identity | `anchor_fingerprint` hashed the AOB source text | hashes the compiled `Pattern` bytes + mask (evidence, not spelling) |
| Shared mutex / file stream | public `SharedMutex`, `WinFileStream` | removed from the public API (vendor your own if you used them directly) |

## Include and namespace map

The umbrella include is still `<DetourModKit.hpp>`, but v3's convenience namespace aliases and short type aliases are gone. Prefer local aliases in your mod, for example `namespace dmk = DetourModKit; namespace sc = DetourModKit::scan;`.

| v3 include / symbol | v4 replacement |
|---|---|
| `<DetourModKit/scanner.hpp>`, `DetourModKit::Scanner` | `<DetourModKit/scan.hpp>`, `DetourModKit::scan` |
| `<DetourModKit/anchors.hpp>`, `DetourModKit::Anchors` | `<DetourModKit/anchor.hpp>`, `DetourModKit::anchor` |
| `<DetourModKit/hook_manager.hpp>`, `HookManager` | `<DetourModKit/hook.hpp>`, `DetourModKit::hook` |
| `<DetourModKit/bootstrap.hpp>`, `DetourModKit::Bootstrap` | `<DetourModKit.hpp>`, top-level `Session` / `bootstrap` / `bootstrap_detach` |
| `<DetourModKit/diagnostics_dump.hpp>` | folded into `<DetourModKit/diagnostics.hpp>` |
| `<DetourModKit/config_watcher.hpp>` | no public watcher type; use `config::enable_auto_reload` / `disable_auto_reload` |
| `<DetourModKit/profile.hpp>` | folded into `anchor::ScanProfile`, `anchor::apply_profile`, and `scan::order_candidates` |
| `<DetourModKit/async_logger.hpp>` | async transport is internal; `AsyncLoggerConfig` remains in `<DetourModKit/async_logger_config.hpp>` |
| `<DetourModKit/drift_manifest.hpp>` | `<DetourModKit/detail/drift_manifest.hpp>`; declarations remain in `DetourModKit::rtti` |
| `<DetourModKit/event_dispatcher.hpp>`, `<DetourModKit/worker.hpp>` | `<DetourModKit/detail/event_dispatcher.hpp>`, `<DetourModKit/detail/worker.hpp>`; still installed, demoted from first-class module headers |
| `<DetourModKit/srw_shared_mutex.hpp>`, `<DetourModKit/win_file_stream.hpp>` | no public replacement |

## Errors are values

Every fallible entry point on the Result-bearing surfaces -- memory, scan, resolver, anchor, manifest, and the hook core -- now returns `Result<T>` (`std::expected<T, Error>`) over a single `ErrorCode`. (The deliberately best-effort / query surfaces -- the RTTI query API, `config` load/reload/bind, and `EventDispatcher` -- keep returning `bool` / `std::optional` / `void` as they did in v3; the error model is two-tier, not uniform.) The per-domain error enums are gone; branch on `result.error().code`, inspect `category(result.error().code)` if you need the subsystem, and stringify with `to_string(result.error().code)`. The formerly separate `HookError` / `ResolveError` / `RipResolveError` / `StringXrefError` / `MemoryError` / `IdentifyError` / `HealError` / `ManifestError` values are folded into the one `ErrorCode`.

## Lifecycle: Session owns teardown

`DMK_Shutdown()` is removed. Hold a `Session` returned by `Session::start(info)` for a synchronous host, or call `bootstrap(info, on_ready)` from `DllMain` attach and `bootstrap_detach(lpvReserved)` from detach. `Session::~Session` owns the ordered teardown: session input scope first, then config auto-reload, input, memory cache, config registry, and logger last. Hooks are not session-owned; their `hook::Hook` / `hook::VmtHook` handles still define hook lifetime.

`Bootstrap::ModInfo` became the top-level `ModInfo`: `prefix` -> `name`, `async_cfg` -> `log`, while `log_file`, `game_process_name`, and `instance_mutex_prefix` keep the same meaning. `Bootstrap::on_dll_attach(hMod, info, init_fn, shutdown_fn)` becomes `bootstrap(info, on_ready)`, which auto-captures the module handle, performs only allocation-free gating and worker publication in DllMain, then configures logging and calls `on_ready(Session&)` on that worker off the loader lock. `Bootstrap::on_dll_detach(is_process_exit)` becomes `bootstrap_detach(lpvReserved)`, using DllMain's raw reserved pointer rather than a bool.

The Logic-DLL helpers are also handle-aware now. `Bootstrap::on_logic_dll_unload(hook_names, binding_names)` becomes top-level `on_logic_dll_unload(binding_names)`, and `on_logic_dll_unload_all()` still exists. Drop your hook handles before the Logic DLL unloads; the helper clears input bindings and config registry state but does not own or remove hooks.

## Hooks: caller-owned RAII, no registry

The `HookManager` singleton and its aggregate operations are removed:

- `create_inline_hook` / `create_mid_hook` -> `hook::inline_at(InlineRequest, detour)` / `hook::mid_at(MidRequest, detour)`, returning a move-only `Hook` handle. For a scanned target, put a `scan::OwnedScanRequest` in the request's `target` variant.
- **Install now returns a disabled hook.** `inline_at`, `mid_at`, and `install_all` no longer arm the target; the returned `Hook` is disabled and you must call `h.enable()` to patch it. Store the handle first, then enable, so a detour that reaches the original through that handle cannot run before the handle exists. `vmt_for` is unchanged (a VMT clone is live on creation).
- `HookConfig::fail_if_already_hooked` -> `hook::Options::fail_if_already_hooked`.
- v3's default `InlineProloguePolicy::Warn` installed through unsafe prologues with a warning. v4 defaults to `hook::Prologue::Fail`. To preserve v3's permissive install-anyway behavior, pass `hook::Options{.prologue = hook::Prologue::Relocate}`.
- `enable_all_hooks` / `disable_all_hooks` -- gone. Each hook is owned by its own `Hook` handle; enable or disable it directly (`h.enable()` / `h.disable()`), or store the handles and iterate your own container. Use `hook::HookStack` when layered hooks on one target must tear down newest-first by construction.
- `get_hook_counts` / `get_hook_ids` -- gone. Aggregate population figures are now read-only via `diagnostics::collect().hooks_total` / `hooks_active` / `hooks_disabled`. That tally is keyed on each hook's process-unique ledger id, so two hooks that share a name (on distinct targets) each count.
- Install a table with `hook::install_all(std::span<const hook::HookSpec>) -> Result<std::vector<hook::InstallOutcome>>`. Each row is built with `hook::HookSpec::inline_hook(...)` or `hook::HookSpec::mid_hook(...)` and a per-row `hook::Severity::Mandatory` / `hook::Severity::BestEffort`.
- **VMT hooking** is the RAII `VmtHook` from `vmt_for`, which clones the seed object's vtable; the handle's object-level `apply_to` / `remove_from` move further objects on and off that clone, and every original vptr is restored on drop. The v3 name-keyed method surface maps onto handle methods: `hook_vmt_method(name, index, detour)` -> `vh.hook_method<Fn>(index, detour)`; the `with_vmt_method(name, index, cb)` accessor -> `vh.original<Fn>(index)` (a typed pre-hook function pointer the detour calls directly, so the reader-lock callback is no longer needed); `remove_vmt_method(name, index)` -> `vh.remove_method(index)`. The v3 per-method original-call helpers (`thiscall` / `ccall` / `stdcall` / `fastcall`, reached through the `with_vmt_method` callback) collapse into the single `VmtHook::original<Fn>(index)` because Win64 has one calling convention; encode the convention in `Fn` if you ever target x86.

## Scanning: one resolver surface

The v3 `resolve_cascade_*` family and the public raw batch primitives (`scan_regions_batch` / `scan_module_batch`) collapse into the `scan::resolve` surface:

- `Scanner::CompiledPattern` -> `scan::Pattern`. Use `scan::Pattern::compile(aob)` for runtime input (`Result<Pattern>`) or `scan::Pattern::literal("48 8B ...")` for compile-time literals.
- Raw `Scanner::find_pattern(...)` -> `scan::unchecked::find_pattern(Region, Pattern, occurrence)`. It still has the caller-proved-readable precondition.
- Page-gated scans -> `scan::scan(pattern, scope, occurrence, pages)`, with scopes expressed as `Region::host()`, `Region::own()`, `Region::module_named("game.exe")`, or `Region::whole_process()`. A `Pages::Readable` sweep must be confined to one mapped image or one reserved allocation, so the first three scopes are fine and `Region::whole_process()` returns `ErrorCode::NotAuthoritative` on that page class: DMK cannot enumerate caller-retained copies of the query bytes across an unbounded scope. Scan `Pages::Executable`, narrow the scope, or declare the copies through the exclusion-taking overload.
- `Scanner::AddrCandidate` -> `scan::Candidate::direct`, `rip_relative`, `rtti_vtable`, or `string_xref`. `ResolveHit` -> `scan::Hit`; use `hit.address`.
- `scan::resolve(ScanRequest)` resolves an ordered candidate ladder; scope, prologue fallback, per-request uniqueness, candidate order, and byte-tier page class are `ScanRequest` fields rather than function-name variants.
- `scan::borrow(...)` builds a borrowed request for immediate use. Use `scan::OwnedScanRequest` for stored/deferred requests such as hook install tables.
- `scan::borrow_code_target(...)` is the hook/code-target preset: `Pages::Executable`, `CandidateOrder::UniqueFirst`, and a `WarnOnly` prologue-recovery fallback by default.
- `scan::resolve_batch(requests, max_workers)` is the parallel batch. Its return type is `Result<std::vector<Result<Hit>>>`: the outer `Result` is the whole-batch signal (`Error{OutOfMemory}` when even the per-request result container cannot be allocated), and the inner vector holds one `Result<Hit>` per request in input order. Unwrap the outer `Result` before indexing so a whole-batch failure can never be silently indexed past (the same shape as `hook::install_all`). On GCC/libstdc++, index the inner vector rather than range-for over it (a bare `std::expected` element trips an `<expected>` equality-constraint recursion; indexed access sidesteps it).
- `ScanRequest::pages` (default `Pages::Readable`) selects the byte tiers' page class. `Pages::Executable` narrows the sweep to code pages so a byte signature that must land on an instruction cannot alias an identical run in `.rdata` / `.data`. This restores v3's executable-only cascade knob.

## Memory: Address, Region, Result

The public memory vocabulary is no longer raw `uintptr_t` / pointer pairs. Wrap locations in `Address`, ranges in `Region`, and protection choices in `Prot`.

- `Memory::seh_read<T>(addr)` -> `memory::read<T>(Address{addr})`, returning `Result<T>`.
- `Memory::seh_read_bytes(addr, out, bytes)` -> `memory::read_into(Address{addr}, std::span<std::byte>{...})`.
- `Memory::seh_resolve_chain(...)` -> `memory::walk(Address{base}, offsets)`, returning the terminal `Address`. Then call `memory::read<T>(*leaf)` or `memory::write_in_place<T>(*leaf, value)`.
- `Memory::seh_write*` per-frame data writes -> `memory::write_in_place`, which never changes page protection and fails closed with `ErrorCode::WriteFaulted` when the target is not already writable.
- `Memory::write_bytes` / `write<T>` are now the escalating patch primitives: they first try the same guarded write, then change protection and flush the instruction cache if the target is read-only or executable. Use them for one-shot code patches, not repeated per-frame field writes.
- `Memory::read_ptr_unchecked(base, offset)` -> `memory::unchecked::read<std::uintptr_t>(Address{base}.offset(offset))` when the caller has proven the source is live. The v4 unchecked read does not validate the loaded value as a plausible pointer; add `memory::is_plausible_ptr(Address{value})` yourself when you need that screen.
- `Memory::plausible_userspace_ptr(ptr)` -> `memory::is_plausible_ptr(Address{ptr})`.
- `Memory::ModuleRange`, `own_module_range`, `host_module_range`, `module_range_for`, and `contains(range, ptr)` -> `Region::own()`, `Region::host()`, `memory::module_of(Address{ptr})`, and `region.contains(Address{ptr})`.
- `Memory::invalidate_range(address, size)`, `is_readable(address, size)`, and `is_writable(address, size)` now take a `Region`.

The raw fast path `memory::unchecked::read<T>` keeps its "the caller has proven this access is safe" contract. In a Debug build it now carries a dev-only `assert(is_readable(...))` that trips at the offending call site instead of a raw access violation deep in the copy. In a Release build (`NDEBUG`) the assert is compiled out entirely, so there is no diagnostic at all -- an invalid address faults the host exactly as before. Reach for the guarded `memory::read` whenever an address might be stale.

## Config and input

`Config` is now `config`, and the names describe binding rather than registration:

- `Config::register_int` / `register_float` / `register_bool` / `register_string` -> `config::bind_int` / `bind_float` / `bind_bool` / `bind_string`.
- `Config::register_atomic` -> `config::bind`.
- `Config::register_key_combo` -> `config::bind_combos`.
- `Config::register_press_combo` / `register_hold_combo` -> `config::press_combo` / `config::hold_combo`, returning `input::BindingGuard`.
- `Config::register_consume_flag` -> `config::consume_flag`; `register_reload_hotkey` -> `config::reload_hotkey`; `clear_registered_items` -> `config::clear`.
- `Config::KeyCombo` / `KeyComboList` moved to `input::KeyCombo` / `input::KeyComboList`.
- `ConfigWatcher` is not public. Auto-reload is `config::enable_auto_reload` / `disable_auto_reload`; `config::Ini` and `config::SectionBinder` are lightweight handles over the same process registry.

`InputManager` and the public `InputPoller` collapse into `input::Input`:

- `InputManager::get_instance()` -> `input::Input::instance()`.
- `InputBinding` -> `input::ComboBinding`; `InputMode` -> `input::Trigger`.
- `register_press` / `register_hold` -> `input::register_combo(input::ComboBinding{...})`, with `.trigger = input::Trigger::Press` or `Hold`.
- `update_binding_combos` -> `Input::rebind`; `is_binding_active` -> `Input::is_active`; `acquire_binding_token` -> `Input::acquire_token`; `binding_token_current` -> `Input::token_current`.
- Store returned `input::BindingGuard`s, or put them in an `input::Scope` / `input::scope()` so callbacks remain live and release in reverse insertion order. `Scope` precommits heap ownership of its guard container on the first `add()`, so `Session::abandon()` on the process-termination path can retain the guards and their callback captures instead of destroying them under the loader lock.

## Logging and async transport

`Logger::get_instance()` is gone. The process-default logger is the free `log()` accessor, so `Logger::get_instance().info("...")` becomes `log().info("...")`. Construct `Logger` directly only when you need a dedicated sink.

The public logger still supports synchronous and async modes, but `AsyncLogger` itself is internal. Keep using `AsyncLoggerConfig` through `Logger::enable_async_mode(config)` or `ModInfo::log`. `AsyncLoggerConfig::timestamp_format` is not consumer-settable on these routes: `Logger::enable_async_mode` (and therefore `ModInfo::log`) overwrites it with the Logger's own format so both sinks stay identical. Set the format through `Logger::configure` (the process default) or `Logger::reconfigure` (a directly-held `Logger`). The empty default exists so value construction allocates nothing. For noexcept boundaries such as hooks, prefer `log().try_log(...)` or `log().log_noexcept(...)` after async mode is enabled.

## Diagnostics and profile

`Diagnostics` is now `diagnostics`, and `diagnostics_dump.hpp` is folded into `diagnostics.hpp`. `diagnostics::collect(drift_report, anchor_report)` no longer takes a `HookManager&`; hook totals are derived from the hook lifecycle stream and returned as `hooks_total`, `hooks_active`, and `hooks_disabled`.

The old `profile.hpp` scan-tuning layer is folded into the modules that use it: `CandidateOrder` is `scan::CandidateOrder`, `order_candidates` is `scan::order_candidates`, `ScanProfile` is `anchor::ScanProfile`, and `apply_profile` is `anchor::apply_profile`. The timing profiler remains in `profiler.hpp` as `Profiler`, `ScopedProfile`, `DMK_PROFILE_SCOPE`, and `DMK_PROFILE_FUNCTION`.

## RTTI, anchors, manifests

`Rtti` is now `rtti`. The `Rtti::heal_offset(...)` convenience wrapper is removed; read the healed value through the landmark: `rtti::heal_landmark(...)->healed_offset`.

`Anchors` is now `anchor`, and `<DetourModKit/anchors.hpp>` is now `<DetourModKit/anchor.hpp>`. `Anchor::kind` now defaults to `AnchorKind::Unset`, so an omitted kind fails closed instead of silently becoming a trusted manual zero. Quorum anchors also changed shape: v3's fixed `quorum_a` / `quorum_b` pair is now `quorum_members` plus `quorum_threshold` for N-of-M voting. A threshold of `0` means unanimous, so a two-member span with the default threshold is the old strict 2-of-2 case.

`anchor::anchor_fingerprint` hashes the compiled `Pattern` bytes + wildcard mask (plus the decode parameters), not the authored AOB source text v3 hashed. This is a correctness improvement (evidence over spelling), but any v3-persisted fingerprint will not match its v4 recomputation -- rebuild any stored fingerprint baselines.

`<DetourModKit/detail/drift_manifest.hpp>` still provides the durable RTTI drift-report archive, but it now returns `Result<std::vector<rtti::DriftRecord>>` and reports parse/file failures via the unified `ErrorCode`. New v4 signature-overrides and offline signature-health APIs live in `<DetourModKit/manifest.hpp>` and `<DetourModKit/sighealth.hpp>`; they are additive, not required for a straight v3 port.

## Support headers with no public replacement

The v3 `DetourModKit::SharedMutex` has no public replacement. The reader/writer lock DetourModKit uses internally is now `DetourModKit::detail::SrwSharedMutex` under `src/internal/`, never installed. A consumer that used the old public mutex must vendor its own shared/reader-writer mutex.

`WinFileStream` / `WinFileStreamBuf` are also internal now, used only by `Logger`. A consumer that used them directly should use `std::ofstream`, a platform stream of its own, or its own Win32 wrapper.

## Toolchain / ABI

v4 is a C++23 static library with a pure C++ ABI (no `extern "C"` boundary). Consume it only from the same compiler family, standard library, and CRT / iterator-debug configuration that built the installed prefix. The configure step probes for `std::expected`, `std::move_only_function`, and `std::format` and fails early on a standard library too old to provide them. See the "ABI / toolchain compatibility" note in the README.
