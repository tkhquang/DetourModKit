# Migration from DetourModKit v3.x to v4

This page maps DetourModKit v3.9.0 names to v4 and lists the behavior and build breaks. Each row maps a v3 name to its v4 replacement. The linked header or guide owns the full contract. The umbrella include stays `<DetourModKit.hpp>`. `manifest.hpp` and `sighealth.hpp` add surfaces that v3 lacked, and a straight port needs neither.

## Headers

| v3 header | v4 header |
|---|---|
| `<DetourModKit/scanner.hpp>` | `<DetourModKit/scan.hpp>` |
| `<DetourModKit/anchors.hpp>` | `<DetourModKit/anchor.hpp>` |
| `<DetourModKit/hook_manager.hpp>` | `<DetourModKit/hook.hpp>` |
| `<DetourModKit/bootstrap.hpp>` | `<DetourModKit/session.hpp>` |
| `<DetourModKit/diagnostics_dump.hpp>` | `<DetourModKit/diagnostics.hpp>` |
| `<DetourModKit/config_watcher.hpp>` | `<DetourModKit/config.hpp>` (`config::enable_auto_reload`, `config::disable_auto_reload`) |
| `<DetourModKit/profile.hpp>` | `<DetourModKit/anchor.hpp>` and `<DetourModKit/scan.hpp>` |
| `<DetourModKit/async_logger.hpp>` | `<DetourModKit/async_logger_config.hpp>`, which keeps `AsyncLoggerConfig` and `OverflowPolicy` |
| `<DetourModKit/drift_manifest.hpp>` | `<DetourModKit/detail/drift_manifest.hpp>` |
| `<DetourModKit/event_dispatcher.hpp>` | `<DetourModKit/detail/event_dispatcher.hpp>` |
| `<DetourModKit/worker.hpp>` | `<DetourModKit/detail/worker.hpp>` |
| `<DetourModKit/srw_shared_mutex.hpp>` | None. `detail::SrwSharedMutex` is internal. Use a reader-writer mutex of your own. |
| `<DetourModKit/win_file_stream.hpp>` | None. `WinFileStream` and `WinFileStreamBuf` are internal. Use `std::ofstream` or a stream of your own. |

`StoppableWorker` and `EventDispatcher` keep their `DetourModKit` namespace.

## Namespaces and aliases

| v3 | v4 |
|---|---|
| `Scanner` | `scan` |
| `Memory` | `memory` |
| `Config` | `config` |
| `Rtti` | `rtti` |
| `Anchors` | `anchor` |
| `Diagnostics` | `diagnostics` |
| `String`, `Format`, `Filesystem`, `Math` | `string`, `format`, `filesystem`, `math` |
| `Bootstrap` | Free functions in `DetourModKit`. See [Lifecycle](#lifecycle). |
| `HookManager` class | `hook` namespace |
| `InputManager` class | `input::Input` |

The umbrella aliases `DMKConfig`, `DMKScanner`, `DMKString`, `DMKFormat`, `DMKFilesystem`, `DMKMemory`, `DMKMath`, `DMKBootstrap`, `DMKRtti`, and `DMKAnchors` are gone. The short type aliases, such as `DMKLogger` and `DMKHookManager`, and their `DMK_NO_SHORT_NAMES` switch are gone. v4 keeps `DMK` and adds `dmk` as aliases of `DetourModKit`. To suppress both, define `DMK_NO_NAMESPACE_ALIASES` before the first DetourModKit include. [defines.hpp](../../include/DetourModKit/defines.hpp) owns the aliases.

## Errors

The v3 enums `HookError`, `ResolveError`, `RipResolveError`, `StringXrefError`, `MemoryError`, `IdentifyError`, `HealError`, and `ManifestError` fold into one `ErrorCode`. Each v3 error mapper, such as `Hook::error_to_string` or `memory_error_to_string`, becomes `to_string(ErrorCode)`. A Result-tier call returns `Result<T>`, an alias of `std::expected<T, Error>`. `Error::code` carries the `ErrorCode`, and `category(ErrorCode)` names the subsystem. The [errors guide](../guides/errors.md) lists the Result tier and the best-effort tier.

## Lifecycle

| v3 | v4 |
|---|---|
| `DMK_Shutdown()` | `Session::~Session` runs the ordered teardown. A bootstrap host ends its session with `request_shutdown` or `shutdown_and_wait`. |
| `Bootstrap::ModInfo` | `ModInfo`. `prefix` is now `name`, and `async_cfg` is now `log`. |
| `Bootstrap::on_dll_attach(hMod, info, init_fn, shutdown_fn)` | `bootstrap_attach(info, on_ready)`. It captures the module that contains the call and takes no shutdown callback. |
| `Bootstrap::on_dll_detach(is_process_exit)` | `bootstrap_detach(lpvReserved)`, which takes the raw DllMain pointer |
| `Bootstrap::request_shutdown()`, `Bootstrap::module_handle()` | `request_shutdown()`, `module_handle()` |
| `Bootstrap::on_logic_dll_unload(hook_names, binding_names)` | `prepare_logic_dll_unload(binding_names)`. Only `LogicDllUnloadStatus::SafeToUnload` authorizes `FreeLibrary`. |
| `Bootstrap::on_logic_dll_unload_all()` | `prepare_logic_dll_unload_all()`, with the same `SafeToUnload` rule |

A synchronous host holds the `Session::start(info)` result. Hooks are caller-owned `Hook` handles, and the unload helpers take no hook names. The top-level void `on_logic_dll_unload(binding_names)` and `on_logic_dll_unload_all()` are best-effort wrappers that never authorize `FreeLibrary`. [session.hpp](../../include/DetourModKit/session.hpp) states the call thread, the call order, and each refusal status.

Gamepad bindings with `input::ComboBinding::consume` set and wheel bindings on the local `MessageHook` backend can pin the module that hosts DetourModKit. `FreeLibrary` then leaves that module mapped. The [hot-reload guide](../guides/hot-reload/README.md) lists every pin source and the staged-generation reload.

## Hooks

| v3 | v4 (`hook`) |
|---|---|
| `create_inline_hook(name, target, detour, &original, config)` | `inline_at(InlineRequest, detour)`, which returns `Result<Hook>` |
| `create_mid_hook(...)` | `mid_at(MidRequest, detour)` |
| `create_inline_hook_aob`, `create_mid_hook_aob`, `try_install_inline`, `try_install_inline_aob`, `try_install_mid`, `try_install_mid_aob` | `inline_at` or `mid_at`. A scanned target is a `scan::OwnedScanRequest` in the request `target`. |
| `create_vmt_hook(name, object)` | `vmt_for(name, object, options)`, which returns `Result<VmtHook>` |
| `apply_vmt_hook(name, object)`, `remove_vmt_from_object(name, object)` | `VmtHook::apply_to(object)`, `VmtHook::remove_from(object)` |
| `hook_vmt_method(name, index, detour)` | `VmtHook::hook_method<Fn>(index, detour)` |
| `remove_vmt_method(name, index)` | `VmtHook::remove_method(index)` |
| `with_vmt_method(name, index, callback)` | `VmtHook::original<Fn>(index)` |
| `with_inline_hook(id, callback)`, `try_with_inline_hook(id, callback)`, `InlineHook::get_original<T>()` | `Hook::original<Fn>()` |
| `enable_hook`, `disable_hook`, `enable_hooks`, `disable_hooks`, `enable_all_hooks`, `disable_all_hooks` | `Hook::enable()` and `Hook::disable()` on each handle |
| `HookStatus`, `Hook::get_status()`, `get_hook_status(id)` | `Hook::is_enabled()` |
| `remove_hook`, `remove_all_hooks`, `remove_vmt_hook`, `remove_all_vmt_hooks` | Destroy the handle. `HookStack` tears layered hooks down newest-first. |
| `get_hook_counts`, `get_hook_ids` | `diagnostics::collect()` fields `hooks_total`, `hooks_active`, and `hooks_disabled` |
| `is_target_already_hooked(address)` | `is_target_hooked(Address)` |
| `HookConfig`, `VmtHookConfig` | `Options`, `VmtOptions` |
| `HookConfig::prologue_policy` | `Options::prologue` |
| `InlineProloguePolicy::Warn`, `InlineProloguePolicy::Fail` | `Prologue::Relocate`, `Prologue::Fail` |

- `inline_at`, `mid_at`, and `install_all` return a disabled hook. After you store the handle, call `Hook::enable()`. v3 `HookConfig::auto_enable` defaulted to `true`. `vmt_for` is live at creation.
- `Options::prologue` defaults to `Prologue::Fail`, and v3 defaulted to `InlineProloguePolicy::Warn`. To install through a breakpoint prologue, pass `hook::Options{.prologue = hook::Prologue::Relocate}`. A relative call as the first instruction passes the v4 prologue check.
- `HookError::TargetAlreadyHookedInProcess` splits into `ErrorCode::TargetAlreadyHookedByThisKit` and `ErrorCode::TargetAlreadyHookedByAnotherModule`. [error.hpp](../../include/DetourModKit/error.hpp) states when each code fires.

[hook.hpp](../../include/DetourModKit/hook.hpp) owns each hook contract.

## Scan

| v3 (`Scanner`) | v4 (`scan`) |
|---|---|
| `CompiledPattern`, `parse_aob(text)` | `Pattern`, `Pattern::compile(text)`. `Pattern::literal("...")` compiles an in-source literal. |
| `find_pattern(start, size, pattern)` | `unchecked::find_pattern(Region, Pattern, occurrence)`. The caller still proves the range readable. |
| `scan_executable_regions`, `scan_readable_regions` | `scan(pattern, scope, occurrence, pages)` with `Pages::Executable` or `Pages::Readable` |
| `AddrCandidate` | `Candidate::direct`, `Candidate::rip_relative`, `Candidate::rtti_vtable`, or `Candidate::string_xref` |
| `ResolveHit` | `Hit`. Read `hit.address`. |
| `resolve_cascade` and its `_in_module`, `_in_host_module`, and `_with_prologue_fallback` forms | `resolve(ScanRequest)`. Scope, fallback, candidate order, uniqueness, and page class are `ScanRequest` fields. |
| `resolve_cascade_batch`, `scan_regions_batch`, `scan_module_batch` | `resolve_batch(requests, max_workers)` |
| `resolve_rip_relative`, `find_and_resolve_rip_relative`, `find_string_xref`, `is_likely_function_prologue`, `read_code_constant` | The same names in `scan`, over `Address` and `Region` |

- A `Pages::Readable` scan of an unconfined scope with no exclusions returns `ErrorCode::NotAuthoritative`. `Region::whole_process()` is such a scope.
- `Candidate::rip_relative` throws `std::invalid_argument` unless the matched suffix of the pattern spans the complete disp32.
- The resolver decodes a RIP target from the sweep snapshot, clamped to the declared scope. An instruction that ends past the scope returns `ErrorCode::NoMatch`. To resolve it, widen the scope over the whole instruction.
- `CodeConstant::byte_width` accepts 0 through 8. `read_code_constant` returns `ErrorCode::InvalidArg` for a larger value before site resolution.
- `resolve_batch` returns `Result<std::vector<Result<Hit>>>`. Before you index a slot, unwrap the outer `Result`.

[scan.hpp](../../include/DetourModKit/scan.hpp) owns each scan contract.

## Memory

| v3 (`Memory`) | v4 (`memory`) |
|---|---|
| `seh_read<T>(addr)` | `read<T>(Address{addr})`, which returns `Result<T>` |
| `seh_read_bytes(addr, out, bytes)` | `read_into(Address{addr}, std::span<std::byte>{...})` |
| `read_ptr_unsafe(base, offset)` | `read<std::uintptr_t>(Address{base}.offset(offset))` |
| `seh_resolve_chain`, `seh_read_chain`, `seh_read_chain_bytes` | `walk(Address{base}, offsets)`, then `read<T>` at the returned `Address` |
| `seh_write`, `seh_write_bytes`, `seh_write_chain`, `seh_write_chain_bytes` | `write_in_place`, after `walk` for a chain |
| `write_bytes` | `write_bytes(Address, source)` or `write<T>`. Use `patch_code` for a code patch. |
| `read_ptr_unchecked(base, offset)` | `unchecked::read<std::uintptr_t>(Address{base}.offset(offset))` |
| `plausible_userspace_ptr(ptr)` | `is_plausible_ptr(Address{ptr})` |
| `ModuleRange`, `own_module_range`, `host_module_range`, `module_range_for`, `contains(range, ptr)` | `Region::own()`, `Region::host()`, `module_of(Address{ptr})`, `region.contains(Address{ptr})` |
| `invalidate_range`, `is_readable`, `is_writable`, `is_readable_nonblocking` with a pointer and a size | The same names with a `Region` |

- `unchecked::read<std::uintptr_t>` screens neither the source address nor the loaded value. v3 `read_ptr_unchecked` returned 0 when either fell outside the user-mode window. When a chain needs that screen, call `is_plausible_ptr` on both.
- `write<T>` and `write_in_place<T>` reject every view type, such as `std::span` or `std::string_view` (`[B-21]`). For a view, use `write_bytes` or the `write_in_place` byte-span overload.

`read<T>` and `unchecked::read<T>` accept only representation-safe types. A v3 `seh_read<T>` call with one of these `T` types no longer compiles:

- `bool` and arrays of `bool`. Use `read_bool`, which reports `ErrorCode::InvalidRepresentation`.
- `long double` on MinGW. Decode it from a 16-byte `read_into` buffer.
- An unscoped enum with no fixed base. Give it a fixed base. Otherwise, read the integer that backs it. Before you convert that integer, validate it.
- An enum over `bool`. Decode it through `read_bool`.
- `std::nullptr_t`. Read `void *` or `std::uintptr_t`.
- A member pointer. Decode it from `read_into` bytes against the ABI.
- A class or union with no opt-in. After you check its complete object representation, specialize `detail::enable_representation_safe_aggregate`.

[`memory-scanning.md`](../design/memory-scanning.md) owns the accepted domain. [memory.hpp](../../include/DetourModKit/memory.hpp) owns each memory contract.

## Config and input

| v3 | v4 |
|---|---|
| `Config::register_int`, `register_float`, `register_bool`, `register_string` | `config::bind_int`, `bind_float`, `bind_bool`, `bind_string` |
| `Config::register_log_level` | `config::bind_log_level` |
| `Config::register_atomic` | `config::bind` |
| `Config::register_key_combo` | `config::bind_combos` |
| `Config::register_press_combo`, `register_hold_combo` | `config::press_combo`, `config::hold_combo`, which return `input::BindingGuard` |
| `Config::register_consume_flag`, `register_reload_hotkey`, `clear_registered_items` | `config::consume_flag`, `config::reload_hotkey`, `config::clear` |
| `Config::InputBindingGuard` | `input::BindingGuard` |
| `Config::KeyCombo`, `Config::KeyComboList` | `input::KeyCombo`, `input::KeyComboList` |
| `ConfigWatcher` | `config::enable_auto_reload`, `config::disable_auto_reload` |
| `InputManager::get_instance()` | `input::Input::instance()` |
| `InputBinding` | `input::ComboBinding` |
| `InputMode`, `input_mode_to_string` | `input::Trigger`, `input::to_string(Trigger)` |
| `register_press`, `register_hold` | `input::register_combo(input::ComboBinding{...})` with `.trigger = input::Trigger::Press` or `Hold` |
| `update_binding_combos`, `is_binding_active` | `Input::rebind`, `Input::is_active` |
| `acquire_binding_token`, `binding_token_current` | `Input::acquire_token`, `Input::token_current` |
| Public `InputPoller` | None. The poll engine is internal. |

Store each returned `input::BindingGuard`, or add it to an `input::Scope`. [input.hpp](../../include/DetourModKit/input.hpp) and [config.hpp](../../include/DetourModKit/config.hpp) own each contract.

## Logger and diagnostics

| v3 | v4 |
|---|---|
| `Logger::get_instance()` | `log()`. For a dedicated sink, construct a `Logger`. |
| `Logger::string_to_log_level`, `log_level_to_string` | `string_to_log_level`, `to_string(LogLevel)` |
| Public `AsyncLogger` | None. Set `ModInfo::log`, or pass an `AsyncLoggerConfig` to `Logger::enable_async_mode`. |
| `Diagnostics::collect(hooks, anchor_report, drift_report)` | `diagnostics::collect(drift_report, anchor_report)` |
| `ScanProfile`, `apply_profile` | `anchor::ScanProfile`, `anchor::apply_profile` |
| `CandidateOrder`, `order_candidates(profile, candidates, out)` | `scan::CandidateOrder`, `scan::order_candidates(order, ladder, out)` |

## RTTI and anchors

| v3 | v4 |
|---|---|
| `Rtti::heal_offset(landmark)` | `rtti::heal_landmark(landmark)`, which returns `Result<HealHit>`. After the check, `healed_offset` holds the value that `heal_offset` returned. On failure, `error().code` is `BadDescriptor`, `HealNoMatch`, or `HealAmbiguous`. [rtti-self-heal.md](../guides/rtti/rtti-self-heal.md) shows the checked call. |
| `Rtti` queries over `std::uintptr_t` and `ModuleRange` | The same names in `rtti` over `Address` and `Region` |
| `Anchor::quorum_a`, `Anchor::quorum_b` | `Anchor::quorum_members` and `Anchor::quorum_threshold`. A zero threshold requires every member. |

- `Anchor::kind` defaults to `AnchorKind::Unset`, and v3 defaulted to `AnchorKind::Manual`. An anchor that omits `kind` reports `AnchorStatus::Failed`.
- `anchor_fingerprint` hashes the compiled `Pattern` bytes, mask, and decode parameters. v3 hashed the AOB text. Recompute every stored fingerprint.
- A quorum whose member pair shares one independence atom fails closed. The [resolution note](../design/resolution.md) lists the atoms.
- `Anchor::byte_width` takes the same 0 through 8 domain as `CodeConstant::byte_width`.

[anchor.hpp](../../include/DetourModKit/anchor.hpp) owns each anchor contract.

## Build and toolchain

- Configure fails on a target other than Windows and on GCC older than 14.
- Compilation fails on a target other than native x86-64 Windows. `defines.hpp` rejects 32-bit x86, ARM64, and ARM64EC with `#error`.
- Configure fails when the standard library lacks `std::expected`, `std::move_only_function`, or `std::format`.
- `find_package(DetourModKit)` fails when the consumer's compiler ABI family, standard library, target system, pointer size, or target architecture differs from the producer.
- Link the `DetourModKit` archive only with the compiler family, standard library, CRT, and `_ITERATOR_DEBUG_LEVEL` that built it.

The [ABI compatibility section](../../README.md#abi-compatibility) of the README lists each axis.
