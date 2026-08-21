# Migrating from DetourModKit v3.x to v4.0.0

v4.0.0 is a deliberate clean break from the general v3 surface and establishes a C++23 value/RAII API. The core modding capabilities carry forward, but several v3 helper and support types were deliberately internalized or demoted. The two `on_logic_dll_unload*` spellings remain as explicitly limited best-effort wrappers and do not restore the v3 lifecycle contract. This guide maps the old surface onto the new one and calls out the few places where a consumer must vendor its own helper.

## At a glance

| Area | v3 | v4 |
|---|---|---|
| Namespaces | PascalCase modules plus umbrella aliases (`DMKConfig`, ...) | lowercase modules (`config`, `scan`, `memory`, `rtti`, `anchor`, `diagnostics`). Add your own aliases if desired |
| Errors | per-domain enums (`HookError`, `ResolveError`, `MemoryError`, `HealError`, ...) | one unified `ErrorCode` returned in `Result<T>` (`std::expected<T, Error>`) |
| Lifecycle | `DMK_Shutdown`, `Bootstrap::on_dll_attach`, `Bootstrap::on_dll_detach` | RAII `Session`, `bootstrap`, `bootstrap_detach`, `shutdown_and_wait`, `request_shutdown` |
| Hooks | `HookManager` singleton + registry batch ops | caller-owned RAII `hook::Hook` / `hook::VmtHook` handles. Free verbs `inline_at` / `mid_at` / `vmt_for` |
| Scanner cascades | `Scanner::resolve_cascade_*`, `scan_regions_batch` / `scan_module_batch` | `scan::resolve(ScanRequest)` / `scan::resolve_batch` |
| Memory | `Memory::*`, raw pointers / `uintptr_t`, `ModuleRange`, `std::optional` / bool failure | `memory::*`, `Address`, `Region`, `Prot`, `Result<T>` |
| Config/input | `Config::register_*`, `InputManager`, public `InputPoller` | `config::bind_*`, `config::press_combo` / `hold_combo`, `input::Input`, `input::BindingGuard`, `input::Scope` |
| RTTI heal | `Rtti::heal_offset(...)` | `rtti::heal_landmark(...)->healed_offset` |
| Anchor identity | `anchor_fingerprint` hashed the AOB source text | hashes the compiled `Pattern` bytes + mask (evidence, not spelling) |
| Shared mutex / file stream | public `SharedMutex`, `WinFileStream` | removed from the public API (vendor your own if you used them directly) |

## Include and namespace map

The umbrella include is still `<DetourModKit.hpp>`. The v3 module aliases and short type aliases are gone, while v4 provides the global convenience namespace aliases `dmk` and `DMK` for `DetourModKit`. Define `DMK_NO_NAMESPACE_ALIASES` before the first DetourModKit include to suppress both, then add only the local aliases your mod wants, for example `namespace sc = DetourModKit::scan;`.

| v3 include / symbol | v4 replacement |
|---|---|
| `<DetourModKit/scanner.hpp>`, `DetourModKit::Scanner` | `<DetourModKit/scan.hpp>`, `DetourModKit::scan` |
| `<DetourModKit/anchors.hpp>`, `DetourModKit::Anchors` | `<DetourModKit/anchor.hpp>`, `DetourModKit::anchor` |
| `<DetourModKit/hook_manager.hpp>`, `HookManager` | `<DetourModKit/hook.hpp>`, `DetourModKit::hook` |
| `<DetourModKit/bootstrap.hpp>`, `DetourModKit::Bootstrap` | `<DetourModKit.hpp>`, top-level `Session` / `bootstrap` / `bootstrap_detach` |
| `<DetourModKit/diagnostics_dump.hpp>` | folded into `<DetourModKit/diagnostics.hpp>` |
| `<DetourModKit/config_watcher.hpp>` | no public watcher type. Use `config::enable_auto_reload` / `disable_auto_reload` |
| `<DetourModKit/profile.hpp>` | folded into `anchor::ScanProfile`, `anchor::apply_profile`, and `scan::order_candidates` |
| `<DetourModKit/async_logger.hpp>` | async transport is internal. `AsyncLoggerConfig` remains in `<DetourModKit/async_logger_config.hpp>` |
| `<DetourModKit/drift_manifest.hpp>` | `<DetourModKit/detail/drift_manifest.hpp>`. Declarations remain in `DetourModKit::rtti` |
| `<DetourModKit/event_dispatcher.hpp>`, `<DetourModKit/worker.hpp>` | `<DetourModKit/detail/event_dispatcher.hpp>`, `<DetourModKit/detail/worker.hpp>`. Still installed, demoted |
| `<DetourModKit/srw_shared_mutex.hpp>`, `<DetourModKit/win_file_stream.hpp>` | no public replacement |

## Errors are values

Every fallible entry point on the Result-bearing surfaces (memory, scan, resolver, anchor, manifest, and the hook core) now returns `Result<T>` (`std::expected<T, Error>`) over a single `ErrorCode`. The deliberately best-effort and query surfaces (the RTTI query API, `config` load/reload/bind, and `EventDispatcher`) keep a return of `bool` / `std::optional` / `void` as they did in v3. The error model is therefore two-tier, not uniform. The per-domain error enums are gone. Branch on `result.error().code`, inspect `category(result.error().code)` if you need the subsystem, and stringify with `to_string(result.error().code)`. The formerly separate `HookError` / `ResolveError` / `RipResolveError` / `StringXrefError` / `MemoryError` / `IdentifyError` / `HealError` / `ManifestError` values are folded into the one `ErrorCode`.

## Lifecycle: Session owns teardown

`DMK_Shutdown()` is removed. A synchronous host holds the `Session::start(info)` result.

DllMain uses `bootstrap_attach(info, on_ready)` for attach and `bootstrap_detach(lpvReserved)` for detach. The [session contract](../../include/DetourModKit/session.hpp) defines both callback forms.

`Session::~Session` owns subsystem teardown. Hook handles remain caller-owned and define hook lifetime.

`Bootstrap::ModInfo` became the top-level `ModInfo`. The `prefix` field became `name`, and `async_cfg` became `log`. The other lifecycle fields retain their meanings. `Bootstrap::on_dll_attach(...)` became `bootstrap_attach(info, on_ready)`. `Bootstrap::on_dll_detach(is_process_exit)` became `bootstrap_detach(lpvReserved)` and now accepts the raw DllMain pointer.

### Hot reload: v4 pins where v3 unmapped unsafely

Both input interception paths traded unloadability for correctness, and a two-DLL reload loop that appeared to work on v3.9.0 therefore stops working in the DMK-in-the-logic-DLL topology.

- XInput (consume gamepad bindings): v3.9.0 restored the prologue unconditionally at teardown. That overwrote any rival hook layered on top, and it freed a trampoline the rival's chain still entered. v4 verifies the prologue bytes first and retains the hooks, permanently, when restoration cannot be proved. The Steam overlay layers on these hooks by default, so the retention is the common case, not the exception.
- Wheel bindings: v3.9.0 subclassed the window, took no module reference in the common path, and unmapped after a pointer restore. A message frame still inside the window procedure then executed unmapped code. v4.0.0 took a permanent counted module reference at the first subclass install. 4.1.0 removed the subclass. The wheel source is a thread-scoped `WH_GETMESSAGE` hook that takes the same permanent reference, booked as `ModulePinReason::MessageHookKeepalive`, at its first successful mount.

Both retentions pin the module that hosts DetourModKit. In the logic-DLL topology that module is the logic DLL, `FreeLibrary` cannot unmap it, and a `LoadLibrary` on the same path silently returns the stale image. v4 also replaced v3.9.0's unreleasable `GET_MODULE_HANDLE_EX_FLAG_PIN` sites with counted acquire/release pairs, so v4 pins less overall and pins recoverably where it can. The [hot-reload guide](../guides/hot-reload/README.md) states the pin rules and the staged-generation loader pattern that restores repeatable reload.

The Logic-DLL helpers are also handle-aware now. `Bootstrap::on_logic_dll_unload(hook_names, binding_names)` becomes `prepare_logic_dll_unload(binding_names)`, and the catch-all form is `prepare_logic_dll_unload_all()`. Run either from an off-loader-lock shutdown thread after you stop consumer workers and drop subscriptions and hook handles, then call `FreeLibrary` only when it returns `LogicDllUnloadStatus::SafeToUnload`. Input guards need no particular order, because the drain destroys the gate-owned callable itself, so one you keep cannot outlive `SafeToUnload`. `TimedOut`, `LoaderLock`, `SelfDelivery`, `InProgress`, and `RetireFailed` are refusals. The old void `on_logic_dll_unload*` spellings remain as source-compatible best-effort abandon wrappers and never authorize unmapping. Rebuild the persistent host and Logic DLL together so both consume the typed v4 header and library symbols.

## Hooks: caller-owned RAII, no registry

The `HookManager` singleton and its aggregate operations are removed:

- `create_inline_hook` / `create_mid_hook` -> `hook::inline_at(InlineRequest, detour)` / `hook::mid_at(MidRequest, detour)`, which return a move-only `Hook` handle. For a scanned target, put a `scan::OwnedScanRequest` in the request's `target` variant.
- **Install now returns a disabled hook.** `inline_at`, `mid_at`, and `install_all` no longer arm the target. The returned `Hook` is disabled and you must call `h.enable()` to patch it. Store the handle first, then enable, so a detour that reaches the original through that handle cannot run before the handle exists. `vmt_for` is unchanged (a VMT clone is live on creation).
- `HookConfig::fail_if_already_hooked` -> `hook::Options::fail_if_already_hooked`. Its refusal is two mechanisms with two codes. `ErrorCode::TargetAlreadyHookedByThisKit` fires when this linked DMK archive already holds a record for the address (a hook created but not yet armed counts, so the prologue is not necessarily patched). `ErrorCode::TargetAlreadyHookedByAnotherModule` fires when the ledger has no record and the prologue decode finds a branch out of the target's own module. The correct response differs (drop your own handle, versus coexist with or abandon a target someone else owns), so branch on the code rather than on a single already-hooked value. A record a pin left behind (`Hook::release()`, or a teardown that failed to restore) belongs to no handle. There the first code has no handle to drop, and it refuses every later strict install on that target for good. v3's `HookError::TargetAlreadyHookedInProcess` and the pre-split v4 `ErrorCode::TargetAlreadyHookedInProcess` have no direct replacement. There is no compatibility alias, and a match on either name fails to compile. The split of the enumerator renumbers every hook code declared after it, so a consumer that persists or transmits raw `ErrorCode` values must re-read them rather than compare across versions.
- `diagnostics::total_intentional_leaks()` now counts the caller-requested leaks too, not only DMK's defensive pins. `Hook::release()` and `VmtHook::release()` each book one event. Absolute totals therefore step up against v3 and against earlier v4 builds, so compare deltas across an operation instead.
- v3's default `InlineProloguePolicy::Warn` installed through unsafe prologues with a warning. v4 defaults to `hook::Prologue::Fail`. To preserve v3's permissive install-anyway behavior, pass `hook::Options{.prologue = hook::Prologue::Relocate}`.
- `enable_all_hooks` / `disable_all_hooks` are gone. Each hook is owned by its own `Hook` handle. Enable or disable it directly (`h.enable()` / `h.disable()`), or store the handles and iterate your own container. Use `hook::HookStack` when layered hooks on one target must tear down newest-first by construction.
- `get_hook_counts` / `get_hook_ids` are gone. Aggregate population figures are now read-only via `diagnostics::collect().hooks_total` / `hooks_active` / `hooks_disabled`. Each live hook counts on its own, so two hooks that share a name (on distinct targets) both appear in the totals.
- Install a table with `hook::install_all(std::span<const hook::HookSpec>) -> Result<std::vector<hook::InstallOutcome>>`. Each row is built with `hook::HookSpec::inline_hook(...)` or `hook::HookSpec::mid_hook(...)` and a per-row `hook::Severity::Mandatory` / `hook::Severity::BestEffort`.
- **VMT hooking** is the RAII `VmtHook` from `vmt_for`, which clones the seed object's vtable. The handle's object-level `apply_to` / `remove_from` move further objects on and off that clone, and every original vptr is restored on drop. The v3 name-keyed method surface maps onto handle methods. `hook_vmt_method(name, index, detour)` -> `vh.hook_method<Fn>(index, detour)`. The `with_vmt_method(name, index, cb)` accessor -> `vh.original<Fn>(index)` (a typed pre-hook function pointer the detour calls directly, so the reader-lock callback is no longer needed). `remove_vmt_method(name, index)` -> `vh.remove_method(index)`. The v3 per-method original-call helpers (`thiscall` / `ccall` / `stdcall` / `fastcall`, reached through the `with_vmt_method` callback) collapse into the single `VmtHook::original<Fn>(index)` because Win64 has one calling convention. Encode the convention in `Fn` if you ever target x86.

## Scanning: one resolver surface

The v3 `resolve_cascade_*` family and the public raw batch primitives (`scan_regions_batch` / `scan_module_batch`) collapse into the `scan::resolve` surface:

- `Scanner::CompiledPattern` -> `scan::Pattern`. Use `scan::Pattern::compile(aob)` for runtime input (`Result<Pattern>`) or `scan::Pattern::literal("48 8B ...")` for compile-time literals.
- Raw `Scanner::find_pattern(...)` -> `scan::unchecked::find_pattern(Region, Pattern, occurrence)`. It still has the caller-proved-readable precondition.
- Page-gated scans -> `scan::scan(pattern, scope, occurrence, pages)`, with scopes expressed as `Region::host()`, `Region::own()`, `Region::module_named("game.exe")`, or `Region::whole_process()`. A `Pages::Readable` sweep must be confined to one mapped image or one reserved allocation, so the first three scopes are fine and `Region::whole_process()` returns `ErrorCode::NotAuthoritative` on that page class. DMK cannot enumerate caller-retained copies of the query bytes across an unbounded scope. Scan `Pages::Executable`, narrow the scope, or declare the copies through the exclusion-taking overload.
- `Scanner::AddrCandidate` -> `scan::Candidate::direct`, `rip_relative`, `rtti_vtable`, or `string_xref`. `ResolveHit` -> `scan::Hit`. Use `hit.address`.
- `scan::resolve(ScanRequest)` resolves an ordered candidate ladder. Scope, prologue fallback, per-request uniqueness, candidate order, and byte-tier page class are `ScanRequest` fields rather than function-name variants.
- `scan::borrow(...)` builds a borrowed request for immediate use. Use `scan::OwnedScanRequest` for stored or deferred requests such as hook install tables.
- `scan::borrow_code_target(...)` is the hook/code-target preset: `Pages::Executable`, `CandidateOrder::UniqueFirst`, and a `WarnOnly` prologue-recovery fallback by default.
- `scan::resolve_batch(requests, max_workers)` is the parallel batch. Its return type is `Result<std::vector<Result<Hit>>>`. The outer `Result` is the whole-batch signal (`Error{OutOfMemory}` when even the per-request result container cannot be allocated), and the inner vector holds one `Result<Hit>` per request in input order. Unwrap the outer `Result` before you index so a whole-batch failure can never be silently indexed past (the same shape as `hook::install_all`). On GCC/libstdc++, index the inner vector rather than a range-for over it (a bare `std::expected` element trips an `<expected>` equality-constraint recursion, and indexed access sidesteps it).
- `ScanRequest::pages` (default `Pages::Readable`) selects the byte tiers' page class. `Pages::Executable` narrows the sweep to code pages so a byte signature that must land on an instruction cannot alias an identical run in `.rdata` / `.data`. This restores v3's executable-only cascade knob.

## Memory: Address, Region, Result

The public memory vocabulary is no longer raw `uintptr_t` / pointer pairs. Wrap locations in `Address`, ranges in `Region`, and protection choices in `Prot`.

- `Memory::seh_read<T>(addr)` -> `memory::read<T>(Address{addr})`, which returns `Result<T>`.
- `Memory::seh_read_bytes(addr, out, bytes)` -> `memory::read_into(Address{addr}, std::span<std::byte>{...})`.
- `Memory::seh_resolve_chain(...)` -> `memory::walk(Address{base}, offsets)`, which returns the terminal `Address`. Then call `memory::read<T>(*leaf)` or `memory::write_in_place<T>(*leaf, value)`.
- `Memory::seh_write*` per-frame data writes -> `memory::write_in_place`, which never changes page protection and fails closed with `ErrorCode::WriteFaulted` when the target is not already writable.
- `Memory::write_bytes` / typed one-shot data writes -> `memory::write_bytes` / `memory::write<T>`, which try a guarded copy and then change protection when needed. Migrate code patches to `memory::patch_code`. It also checks instruction-cache maintenance for already-writable and partial-prefix writes.
- `Memory::read_ptr_unchecked(base, offset)` -> `memory::unchecked::read<std::uintptr_t>(Address{base}.offset(offset))` when the caller has proven the source is live. The v4 unchecked read does not validate the loaded value as a plausible pointer. Add `memory::is_plausible_ptr(Address{value})` yourself when you need that screen.
- `Memory::plausible_userspace_ptr(ptr)` -> `memory::is_plausible_ptr(Address{ptr})`.
- `Memory::ModuleRange`, `own_module_range`, `host_module_range`, `module_range_for`, and `contains(range, ptr)` -> `Region::own()`, `Region::host()`, `memory::module_of(Address{ptr})`, and `region.contains(Address{ptr})`.
- `Memory::invalidate_range(address, size)`, `is_readable(address, size)`, and `is_writable(address, size)` now take a `Region`.

`memory::read<T>`, `memory::unchecked::read<T>`, and the engine's `detail::guarded_read<T>` accept a narrower set of types than v3's `Memory::seh_read<T>`, which templated on anything trivially copyable. A reinterpret of foreign bytes is only defined when every bit pattern is a valid object representation, so the following no longer compile. Each has a mechanical replacement, and none loses the ability to obtain the bytes.

- **`bool` and arrays of `bool`.** A foreign byte other than 0 or 1 is not a valid `bool`. Use `memory::read_bool`, which reports `ErrorCode::InvalidRepresentation`.
- **`long double` on MinGW/GCC.** The x87 80-bit format occupies 16 bytes, so 48 bits are padding with no defined value. Unaffected on MSVC, where `long double` is `double`. Use `memory::read_into` a 16-byte buffer, then validate and decode the x87 representation before you form a value.
- **An unscoped enumeration with no fixed base**, for example `enum Mode { A, B };`. Its valid range is the smallest bit-field that holds its enumerators, which is narrower than its storage. Give it a base (`enum Mode : int`), or read the underlying integer and validate the value.
- **An enumeration over `bool`.** It inherits `bool`'s two valid representations. Use `memory::read_bool`, then convert.
- **`std::nullptr_t`.** Its only valid value is the null pointer constant. Read `void *` or `std::uintptr_t`.
- **Pointer-to-member-object and pointer-to-member-function.** Implementation-defined multi-field representations with invalid patterns. MinGW's member-function pointer is 16 bytes. Use `memory::read_into` and decode against the documented ABI.

Unchanged: every integral type except `bool`, `float`, `double`, fixed-underlying and scoped enumerations, `std::byte`, and object and function pointers under the Windows x64 ABI. Also unchanged: bounded built-in arrays and `std::array` of accepted elements, and any class or union opted in through `detail::enable_representation_safe_aggregate`. A top-level built-in array request now returns the equivalent nested `std::array`, because C++ functions cannot return a built-in array by value. `DetourModKit::Address` is newly accepted, so `memory::read<Address>(addr)` now compiles and yields the foreign pointer directly in the addressing vocabulary.

The raw fast path `memory::unchecked::read<T>` keeps its "the caller has proven this access is safe" contract. In a Debug build it now carries a dev-only `assert(is_readable(...))` that trips at the offending call site instead of a raw access violation deep in the copy. In a Release build (`NDEBUG`) the assert is compiled out entirely, so there is no diagnostic at all, and an invalid address faults the host exactly as before. Reach for the guarded `memory::read` whenever an address can be stale.

## Config and input

`Config` is now `config`, and the names describe binding rather than registration:

- `Config::register_int` / `register_float` / `register_bool` / `register_string` -> `config::bind_int` / `bind_float` / `bind_bool` / `bind_string`.
- `Config::register_atomic` -> `config::bind`.
- `Config::register_key_combo` -> `config::bind_combos`.
- `Config::register_press_combo` / `register_hold_combo` -> `config::press_combo` / `config::hold_combo`, which return `input::BindingGuard`.
- `Config::register_consume_flag` -> `config::consume_flag`. `register_reload_hotkey` -> `config::reload_hotkey`. `clear_registered_items` -> `config::clear`.
- `Config::KeyCombo` / `KeyComboList` moved to `input::KeyCombo` / `input::KeyComboList`.
- `ConfigWatcher` is not public. Auto-reload is `config::enable_auto_reload` / `disable_auto_reload`. `config::Ini` and `config::SectionBinder` are lightweight handles over the same process registry.

`InputManager` and the public `InputPoller` collapse into `input::Input`:

- `InputManager::get_instance()` -> `input::Input::instance()`.
- `InputBinding` -> `input::ComboBinding`. `InputMode` -> `input::Trigger`.
- `register_press` / `register_hold` -> `input::register_combo(input::ComboBinding{...})`, with `.trigger = input::Trigger::Press` or `Hold`.
- `update_binding_combos` -> `Input::rebind`. `is_binding_active` -> `Input::is_active`. `acquire_binding_token` -> `Input::acquire_token`. `binding_token_current` -> `Input::token_current`.
- Store returned `input::BindingGuard`s, or put them in an `input::Scope` / `input::scope()` so callbacks remain live and release in reverse insertion order. `Scope` precommits heap ownership of its guard container on the first `add()`. `Session::abandon()` on the process-termination path can then retain the guards and their callback captures rather than destroy them under the loader lock.

## Logging and async transport

`Logger::get_instance()` is gone. The process-default logger is the free `log()` accessor, so `Logger::get_instance().info("...")` becomes `log().info("...")`. Construct `Logger` directly only when you need a dedicated sink.

The public logger still supports synchronous and async modes, but `AsyncLogger` itself is internal. Keep the use of `AsyncLoggerConfig` through `Logger::enable_async_mode(config)` or `ModInfo::log`. `AsyncLoggerConfig::timestamp_format` is not consumer-settable on these routes. `Logger::enable_async_mode` (and therefore `ModInfo::log`) overwrites it with the Logger's own format so both sinks stay identical. Set the format through `Logger::configure` (the process default) or `Logger::reconfigure` (a directly-held `Logger`). The empty default exists so value construction allocates nothing. For noexcept boundaries such as hooks, prefer `log().try_log(...)` or `log().log_noexcept(...)` after async mode is enabled.

## Diagnostics and profile

`Diagnostics` is now `diagnostics`, and `diagnostics_dump.hpp` is folded into `diagnostics.hpp`. `diagnostics::collect(drift_report, anchor_report)` no longer takes a `HookManager&`. The hook surface maintains the totals itself, independently of any lifecycle subscription, and returns them as `hooks_total`, `hooks_active`, and `hooks_disabled`.

The old `profile.hpp` scan-tuning layer is folded into the modules that use it. `CandidateOrder` is `scan::CandidateOrder`, `order_candidates` is `scan::order_candidates`, `ScanProfile` is `anchor::ScanProfile`, and `apply_profile` is `anchor::apply_profile`. The timing profiler remains in `profiler.hpp` as `Profiler`, `ScopedProfile`, `DMK_PROFILE_SCOPE`, and `DMK_PROFILE_FUNCTION`.

## RTTI, anchors, manifests

`Rtti` is now `rtti`. The `Rtti::heal_offset(...)` convenience wrapper is removed. Read the healed value through the landmark: `rtti::heal_landmark(...)->healed_offset`.

`Anchors` is now `anchor`, and `<DetourModKit/anchors.hpp>` is now `<DetourModKit/anchor.hpp>`. `Anchor::kind` now defaults to `AnchorKind::Unset`, so an omitted kind fails closed where v3 treated it as a trusted manual zero. Quorum anchors also changed shape. v3's fixed `quorum_a` / `quorum_b` pair is now `quorum_members` plus `quorum_threshold` for N-of-M voting. A threshold of `0` means unanimous, so a two-member span with the default threshold is the old strict 2-of-2 case.

Physical trust is stricter at the v4 boundary. A quorum returns `QuorumNotIndependent` when differently authored byte selectors resolve through overlapping physical spans, even if their declarations differ. Genuinely distinct instruction sites can still agree on one value. A `rip_relative` candidate or manifest rung must include its complete disp32 in the matched suffix from the `|` marker, and target decode uses the sweep-time snapshot rather than a reread of live bytes. That snapshot is clamped to the scope you declare, not to the owning module. A rung whose declared `instruction_length` runs past the end of a narrow scope now reports `NoMatch` where the v3 live reread resolved it. Widen the scope to cover the whole instruction. `CodeConstant::byte_width` and its anchor and manifest equivalents accept only 0 or 1 through 8. Older out-of-domain values now fail before the scan. v3 treated them as full width.

`anchor::anchor_fingerprint` hashes the compiled `Pattern` bytes + wildcard mask (plus the decode parameters), not the authored AOB source text v3 hashed. This is a correctness improvement (evidence over spelling), but any v3-persisted fingerprint will not match its v4 recomputation. Rebuild any stored fingerprint baselines.

`<DetourModKit/detail/drift_manifest.hpp>` still provides the durable RTTI drift-report archive, but it now returns `Result<std::vector<rtti::DriftRecord>>` and reports parse and file failures via the unified `ErrorCode`. New v4 signature-overrides and offline signature-health APIs live in `<DetourModKit/manifest.hpp>` and `<DetourModKit/sighealth.hpp>`. They are additive, not required for a straight v3 port.

The v4 manifest INI backend is case-sensitive. The reserved keys and the `manifest` / `sig.` section prefixes must be canonical lowercase, while enum-token values stay case-insensitive. The `.rung.<N>` marker is also case-sensitive, but a miscased marker reads as ordinary record-label text rather than a fail of the parse. `manifest::serialize_checked(manifest, limits) -> Result<std::string>` is the sole encoder (there is no unchecked `serialize`), and it validates label framing, cross-record identity, every string field, and the resource caps before it emits. `save` routes through it. `parse`, `load`, `serialize_checked`, and `save` take an optional trailing `ManifestLimits` (default `conservative()`, and `advanced()` lifts the caps for a trusted authoring tool) and return `SizeTooLarge` past a bound. A noncanonical or identity-colliding manifest is rejected outright (`MalformedLine` / `ManifestIdentityCollision`) with no permissive fallback parser. Hand-edit the offending file to canonical lowercase keys and prefixes, or regenerate it from the mod's in-code defaults through `Signature::adopt` and `save`. An adopted record carries no ladder text (a compiled pattern cannot be turned back into source AOB), so a regenerated `rip_global` / `code_operand` record is a skeleton. Re-add its `[sig.<label>.rung.<N>]` sections by hand before the file can override those kinds. A file that still parses can be re-saved through `serialize_checked` / `save` to normalize its framing. A key the parser never reads for its section (a wholly-unknown key, or an evidence key inert for the record's kind) is now rejected (`MalformedLine`) rather than silently ignored. Remove any stray key from a hand-edited manifest.

The drift report and the manifest gate gained additive trust surfaces:

- `ResolvedAnchor::witness`: a live-image identity, physical source, completeness, and the winning span's literal bytes per resolved entry.
- `anchor::anchor_trust_fingerprint` and `scan::image_identity`.
- For a manifest that authorizes a write, `SignatureRecord::expected_image_identity` (the optional `image_identity` key) and `SignatureRecord::expected_winning_bytes` (the optional `winning_bytes` key).

A read-only port needs none of these, but the `ResolvedAnchor`, `SignatureRecord`, and `scan::Hit` size growth means a clean rebuild against the v4 headers, as for any static-library ABI change.

**`GatePolicy::mutation_strict()` is now complete-evidence, and this is a behavioral change for a v3 manifest that authorizes writes.** It previously checked an image baseline only when one happened to be captured, and ran no contract-revision check at all on the plain overload. It now safe-disables a mutation-capable entry unless it carries the complete set:

- A captured fingerprint.
- A captured and matching image identity.
- A captured and matching winning-span content baseline.
- A mutation-safe non-`Manual` binding.
- A contract revision that was compared. That requires the `resolve_and_gate(sigs, header, build_revision, policy)` overload with a non-zero `build_revision`.

A manifest that carries no baselines therefore goes from "trusted to write" to "safe-disabled for writing" on upgrade.

Nothing about read-only lookup changed. The plain overload, a zero build revision, and an uncaptured baseline skip the new baseline gate rather than fail it. The normal no-match, ambiguity, and fingerprint-drift failures still apply. To restore write authority, call the new `Signature::recapture(scope)` on each signature against the shipping game build and re-save the manifest. It adopts all three baselines together and reports `UnexpectedShape` for a rung that witnesses no content span (RTTI, export, string-xref, `Manual`). That is exactly the set that cannot authorize a write under the new rules. See [the signature-manifest guide](../guides/scanning/signature-manifest.md) for the authoring and repair workflow.

## Support headers with no public replacement

The v3 `DetourModKit::SharedMutex` has no public replacement. The reader/writer lock DetourModKit uses internally is now `DetourModKit::detail::SrwSharedMutex` under `src/internal/`, never installed. A consumer that used the old public mutex must vendor its own shared or reader-writer mutex.

`WinFileStream` / `WinFileStreamBuf` are also internal now, used only by `Logger`. A consumer that used them directly can use `std::ofstream`, a platform stream of its own, or its own Win32 wrapper.

## Toolchain / ABI

v4 is a C++23 static library with a pure C++ ABI (no `extern "C"` boundary). Consume it only from the same compiler family, standard library, and CRT / iterator-debug configuration that built the installed prefix. The configure step probes for `std::expected`, `std::move_only_function`, and `std::format` and fails early on a standard library too old to provide them. See the "ABI / toolchain compatibility" note in the README.
