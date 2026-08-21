# Hot-reload development guide

Split a mod into a thin loader and a logic DLL to change mod code without a game restart. The loader lives for the process. The logic DLL is replaced on demand.

| Binary              | Role                                        | Lifetime         |
|---------------------|---------------------------------------------|------------------|
| `ModName.asi`       | Stages, loads, and replaces the logic DLL   | The game session |
| `ModName.logic.dll` | Hooks, features, config, and input bindings | One generation   |

This guide defines DetourModKit unload guarantees, module pin sources, and the staged-generation pattern for repeatable reloads.

The code below is a skeleton, not a supported loader product. CI compiles the [reference pair](../../../examples/staged_reload/) to check current API use. [The examples contract](../../../examples/README.md) defines ownership and compatibility.

## What pins the module that hosts DetourModKit

Some subsystems take counted module references on the module that links the archive. `FreeLibrary` cannot unmap a pinned module. A later `LoadLibrary` on the same path silently returns the stale image instead of the new build.

| Source | `ModulePinReason` | Reference taken | Released |
| --- | --- | --- | --- |
| A live inline, mid, or VMT hook | `Hook` | Before hook publication | After proved teardown. A failed proof retains the reference. |
| A `StoppableWorker` | `Worker` | Before thread start | After join. A detach or failed join retains the reference. |
| The bootstrap worker | `Bootstrap` | Before thread start | Immediately before its terminal `FreeLibraryAndExitThread`. |
| The async logger writer | `AsyncLogger` | Before thread start | After join. |
| The memory-cache cleanup thread | `MemoryCache` | Before thread start | After join. |
| The input poll thread | `InputPoller` | Before thread start | After join. A loader-lock detach retains the reference. |
| The lifecycle reaper | `LifecycleReaper` | Before thread start | Never. The process-lifetime thread owns this permanent reference. |
| A wheel binding (WndProc subclass) | `WndprocKeepalive` | First successful subclass publication | Never. |
| A wheel binding (local message-hook fallback) | `MessageHookKeepalive` | First successful hook publication | Never. Hook removal is cleanup only, because a selected callback can run after `UnhookWindowsHookEx`. |
| XInput interception self-reference | `XInputKeepalive` | Before hook creation | On install rollback or proved clean uninstall. Retention keeps it permanently. |
| XInput provider reference | `XInputTarget` | Before hook creation | With `XInputKeepalive`. It pins the provider module, not the DMK host module. |

Each permanent wheel reference enters the intentional-leak tally after successful publication, not at teardown. A leak-counter delta across teardown therefore reads zero for an existing wheel keepalive. Read open references through `diagnostics::module_pin_count(reason)`, which stays readable after `~Session`. `WndprocKeepalive` and a retained XInput set are inert after teardown. A retained XInput set has one `XInputKeepalive` plus one or two `XInputTarget` references. Every other nonzero reason reports code that can still run.

XInput retention also logs each witness and target address. The next staged generation's first sink open erases those lines under the default `LogOpenMode::Truncate`. Set `ModInfo::log_open_mode = LogOpenMode::Append` to keep them across generations. If the loader needs a separate copy, record the lines in loader-owned storage.

The resident wheel host removes the wheel pin from the logic image. With `input::Input::Settings::wheel_backend = WheelBackend::ExternalHost`, the loader owns that keepalive. A successful lease close is necessary but does not authorize unload. Require the typed drain, complete pin verdict, loader lease probe, `FreeLibrary`, and address-unmap probe. The existing [`staged_reload` pair](../../../examples/staged_reload/) shows this order. The [input design note](../../design/input.md) owns the backend contract.

## Reload sequence (staged generations)

Keep DetourModKit linked in the logic DLL, exactly as in the release build. Only the loader is development-specific:

1. Disable the reload hotkey, so a second press cannot start a concurrent reload.
2. Call the logic DLL's `Shutdown()` export. If it returns zero, keep the DLL mapped, log the refusal, and stop.
3. Open and close a loader probe lease. If open reports `Busy`, keep the DLL mapped and stop.
4. Save one logic code address, then call `FreeLibrary` exactly once.
5. Require the saved address to become unmapped before the next load. If it stays mapped, request a game restart.
6. Copy the rebuilt DLL to a unique staged name, for example `ModName.gen0042.logic.dll`, and call `LoadLibrary` on the copy.
7. Resolve the `Init` and `Shutdown` exports with `GetProcAddress`, then pass the resident table to `Init`.
8. Log a build revision constant exported by the DLL. `__DATE__` alone moves only when its translation unit recompiles.
9. Re-enable the hotkey.

Never load two generations by the same file name. Mapping the build output directly locks the path, so a rebuild cannot land, and every reload replays identical bytes while it reports success. A unique staged name gives every generation a fresh image, so a pinned predecessor can never be handed back as a stale image, and function-local `static` state can never replay.

### Retained generations are the accepted cost

A generation that took a permanent pin stays mapped after `FreeLibrary`. That is safe: its interception data is revoked before uninstall, so the old image is either unreachable or an inert forwarding layer. The WndProc chain grows only when a foreign subclasser layered on a generation, not on every reload, because a topmost teardown restores the previous procedure.

Do not fight the pins:

- Do not call `FreeLibrary` repeatedly to defeat the reference count.
- Do not force an unmap. The permanent reference is the safety mechanism for a frame that is still executing, or for a foreign subclasser that captured the old procedure address.
- Do not treat every `LeakSubsystem::Input` leak as harmless.
- That subsystem also records abandoned pollers and other state that can still execute.
- Accept only `ModulePinReason::WndprocKeepalive` and a retained `XInputKeepalive` / `XInputTarget` pair.
- Refuse the reload for every other nonzero reason, any drain refusal, any unjoined worker, and any unknown reason.

Budget the cost with both a generation count and a byte estimate. With an image of roughly 3.5 MiB, 32 retained generations cost about 112 MiB.

## What DetourModKit guarantees across an unload

### Hook removal needs a quiescent target

Dropping a `Hook` handle rewrites the original prologue bytes back. It does not freeze threads. During the rewrite the backend strips execute from the patched page. A vectored exception handler relocates the instruction pointer of a thread that *faults* on that page. A thread already inside the trampoline or the detour body is not relocated. Removal is therefore safe only when the hooked function is quiescent.

A fixed sleep cannot prove quiescence. `Shutdown()` must return false while any consumer-owned worker, subscription, hook caller, or other callback source can still run. The loader must keep the DLL mapped and retry later.

### Layered hooks unwind newest-first

When several handles target the same address, destroy them newest-first. `hook::HookStack` owns the handles and drains them newest-first in its destructor, its move-assignment, and `clear()`. Prefer it to a bare `std::vector<Hook>`, which carries no such order. Out-of-order teardown is contained, not corrupting: the older backend is retained instead of restored over the newer layer. The retention is permanent, so only newest-first returns the pristine prologue.

### Session teardown owns the process-wide subsystems

`~Session` runs the ordered teardown: config auto-reload watcher, input, memory cache, config registry, then the logger last. The process-default logger storage is process-lifetime on purpose, so CRT static destructors never touch it. The teardown flushes and closes the sink instead. Each generation's first sink open truncates the file under the default `LogOpenMode::Truncate`, so each reload starts a clean log. `ModInfo::log_open_mode = LogOpenMode::Append` preserves the prior generation's records instead, teardown warnings included.

Destroy the `Session` before `FreeLibrary`. Skipping it can leave the old sink and the async writer alive after the image is gone.

### What does not reset

- Game memory. Direct `memory::patch_code` and `memory::write_bytes` changes survive the reload. Track them and revert them in `Shutdown()`.
- The config file on disk. Edit the INI, reload, and the new values take effect.
- State you want to keep. Store it in the loader, which is never unloaded.

Global and static variables in the logic DLL reset on every cycle. The profiler ring buffer lives in logic-DLL memory, so export it before `Shutdown()` if you need the samples.

### Threads, TLS, and static constructors

Join every consumer-owned thread in `Shutdown()`, before the `Session` teardown. A thread that outlives `FreeLibrary` executes unmapped code.

Use [`dmk::StoppableWorker`](../../../include/DetourModKit/detail/worker.hpp). Normal destruction requests stop and joins. When the loader lock forbids a blocking teardown it detaches instead, runs no stop callbacks, and leaves its counted module reference outstanding so the code pages stay mapped. That branch requests no stop at all, so an abandoned body never observes `stop_requested()`. Publish your own cancellation flag beside the stop token when the body must terminate on that path.

`FreeLibrary` does not run `thread_local` destructors for threads the DLL did not create. Avoid `thread_local` in a logic DLL, or clean it up in `Shutdown()`. Prefer explicit `Init` and `Shutdown` functions to file-scope static constructors.

Build the loader and the logic DLL with the same compiler and C runtime. A mixed pair crashes on the ABI boundary.

## Topology: DetourModKit in the logic DLL

This is the recommended topology, combined with the staged-generation loader above. Development and production run identical mod code, and each cycle exercises the production teardown.

```cpp
// mod_logic/dllmain.cpp
static std::optional<dmk::Session> s_session;
static dmk::hook::HookStack s_hooks;
static std::unique_ptr<dmk::StoppableWorker> s_scan_worker;
static bool s_hook_restore_failed = false;

extern "C" __declspec(dllexport) bool Init() noexcept
{
    auto started = dmk::Session::start(/* ModInfo */);
    if (!started)
    {
        return false;
    }
    s_session.emplace(std::move(*started));
    // install hooks into s_hooks, bind config, register input
    return true;
}

extern "C" __declspec(dllexport) bool Shutdown() noexcept
{
    s_scan_worker.reset();   // request stop and join, off the loader lock
    revert_all_patches();    // your own raw byte patches
    if (dmk::prepare_logic_dll_unload_all() != dmk::LogicDllUnloadStatus::SafeToUnload)
    {
        return false;
    }
    const auto hook_pins_before =
        dmk::diagnostics::intentional_leak_count(dmk::diagnostics::LeakSubsystem::HookManager);
    s_hooks.clear();         // newest-first, while the code pages are mapped
    s_hook_restore_failed = s_hook_restore_failed ||
                            dmk::diagnostics::intentional_leak_count(
                                dmk::diagnostics::LeakSubsystem::HookManager) != hook_pins_before;
    s_session.reset();       // ordered teardown. The XInput retention can pin HERE.
    const std::size_t wheel =
        dmk::diagnostics::module_pin_count(dmk::diagnostics::ModulePinReason::WndprocKeepalive);
    const std::size_t xinput_self =
        dmk::diagnostics::module_pin_count(dmk::diagnostics::ModulePinReason::XInputKeepalive);
    const std::size_t xinput_targets =
        dmk::diagnostics::module_pin_count(dmk::diagnostics::ModulePinReason::XInputTarget);
    const bool xinput_inert = (xinput_self == 0 && xinput_targets == 0) ||
                              (xinput_self == 1 && xinput_targets >= 1 && xinput_targets <= 2);
    const bool only_inert_pins = wheel <= 1 && xinput_inert &&
                                 dmk::diagnostics::total_module_pins() == wheel + xinput_self + xinput_targets;
    return !s_hook_restore_failed && only_inert_pins;
}
```

Read the counters after `s_session.reset()`. The XInput retention happens inside `~Session`, so a verdict computed before the reset cannot see it. The counters are static atomics, so they stay readable after the `Session` is gone.

`s_hook_restore_failed` latches the first failed restore. A retry must never convert retained patched bytes into an unload acceptance.

If a HookManager delta occurs, keep every saved original pointer and target-module reference alive for the process lifetime. The leaked inline route can still enter the detour.

## Advanced topology: DetourModKit in a persistent host

Use this topology only when old generations must actually unmap, for example when the retained-generation budget is unacceptable. It trades development/production identity for real unmaps: the host owns DetourModKit, so hooks, bindings, and teardown behave differently from the single-DLL release build.

The host links the archive and owns every DetourModKit object: the `Session`, the hook handles, config storage, and the input bindings. The logic DLL links no DetourModKit archive. It contributes executable callables only and reaches the host through a small versioned C table. Enforce that split with a link gate in the logic target, with the pattern from `tests/lifecycle/CMakeLists.txt`. A logic DLL that links its own archive is a second library instance: it holds its own ledger, and its pins land on the logic DLL again.

Three ownership rules. Each broken rule reintroduces the pin:

1. Config storage lives in the host, keyed by section and key, so a re-bind reuses the slot. A bound reference into DLL memory dangles at unmap.
2. The host calls `input::Input::start()`. The poll thread's module reference must land on the host.
3. The host drops every hook whose detour lives in the DLL, newest-first, before `FreeLibrary`. A retained hook keeps that detour reachable, so a `HookManager` pin refuses the unload absolutely.

`prepare_logic_dll_unload(binding_names)` is the safe-unmap transaction. It retires the named input bindings, closes callback staging, requests the watcher and the reload servicer to stop without a join, and waits to one end-to-end deadline. `SafeToUnload` means that no selected input callable copy, config setter, user reload callback, or DetourModKit worker callable remains. `TimedOut`, `LoaderLock`, `SelfDelivery`, `InProgress`, and `RetireFailed` are refusals. Do not call `FreeLibrary` for any of them. Keep the DLL mapped and retry from an off-loader-lock control thread. A timed-out attempt keeps callback admission closed, so it cannot authorize new callback work while the retry is pending.

`prepare_logic_dll_unload_all()` clears every input binding but keeps the poll thread alive. Use it only when the unloading DLL owns the whole process-wide input and config surface. The registry is process-scoped, so the all-bindings form also retires a sibling DLL's bindings. Prefer the named-list overload when several logic DLLs share one instance.

After `FreeLibrary`, verify the unmap. Probe an export address captured before the unload with `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT)`. A surviving module means a pin. Do not load a successor onto it.

### Binding guards during the drain

Drop a consumer-owned `BindingGuard` before, during, or after the drain. Retirement reaches the callback through the binding's delivery gate, so a guard you keep cannot hold a callable alive. A Hold binding still held when the drain runs receives its balancing `on_state_change(false)` there, while your module is still mapped.

Drop a guard without a held lock, and without a join your balancing callback or your captures' destructors can wait on. Otherwise the drain thread and the releasing thread wait on each other.

[`[B-74]` in the lifecycle note](../../design/lifecycle.md) owns the full transaction contract and the binding-guard rules.

## Idempotency on a second `Init()`

In a persistent host, every call into a process-wide singleton from `Init()` is the second or later call in the process.

| API                                        | Second-call behavior                                  | Do first                                |
|--------------------------------------------|-------------------------------------------------------|-----------------------------------------|
| `Logger::configure`                        | Replaces the config and never truncates a target file | Nothing                                 |
| `hook::inline_at` / `mid_at` (per address) | `TargetAlreadyHookedByThisKit` under strict refusal   | Drop the prior `Hook` handle            |
| `config::bind_*`                           | Replaces the item and its setter in place             | Nothing                                 |
| `config::press_combo` / `hold_combo`       | Replaces the config item, appends the input binding   | `input::Input::remove_bindings_by_name` |
| `input::register_combo`                    | Appends a second binding under the same name          | `input::Input::remove_bindings_by_name` |
| `input::Input::start`                      | No-op, and the new `poll_interval` is ignored         | `shutdown()`, to change the interval    |
| `bootstrap_attach` / `bootstrap`           | Returns a failed `Result` while a session is attached | `bootstrap_detach`                      |

`input::register_combo` is append-only. The engine treats `name` as a label, not a key. That is the most common surprise across reloads. Under staged generations, re-registration from each generation's `Init()` is the supported path: `config::bind_*` replaces the item in place, and the previous generation's `Shutdown()` retired its bindings.

## Proof pointers

`tests/lifecycle/test_logic_dll_unload.cpp` drives a real logic DLL through each contract above. Each scenario is its own process:

- `Lifecycle.LogicDllDrainReleasesEveryStagedCallable`
- `Lifecycle.LogicDllRetainedGuardCannotKeepCallableAlive`
- `Lifecycle.LogicDllHeldBindingIsBalancedByTheDrain`
- `Lifecycle.LogicDllParkedInputCallbackRefusesUnload`
- `Lifecycle.LogicDllParkedConfigSetterRefusesUnload`
- `Lifecycle.LogicDllParkedConfigCallbackRefusesUnload`
- `Lifecycle.LogicDllMidTeardownWaitsForParkedCallback`
- `Lifecycle.LogicDllMidPreAdapterRouteDrainsBeforeUnload`
- `Lifecycle.LogicDllMidPostAdapterRouteDrainsBeforeUnload`
- `Lifecycle.LogicDllPinnedMidStubStaysInertAfterUnload`
- `Lifecycle.LogicDllInlineCallerQuiescenceAllowsUnload`

Run them with `bash scripts/run_lifecycle_proofs.sh`, or with `ctest -L lifecycle-proof`.

`tests/lifecycle/staged_generation_soak.cpp` pins the staged-generation loader pattern above. It reloads a generation DLL that links its own archive, and each scenario is its own process:

- `Lifecycle.StagedGenerationSoakReloadsWithFreshBytes`
- `Lifecycle.StagedGenerationWheelResubclassesPerGeneration`
- `Lifecycle.StagedGenerationReloadNeverUninstallsInterception`
- `Lifecycle.StagedGenerationParkedCallbackRefusesReload`
- `Lifecycle.StagedGenerationReleasedCallbackAllowsReload`
- `Lifecycle.StagedGenerationPartialInitRollsBackAndUnmaps`
- `Lifecycle.StagedGenerationForeignXInputRetainsThePair`

## Related documentation

- [Config hot-reload](config-hot-reload.md) contains the INI reload API and its thread-safety contract.
- [The lifecycle note](../../design/lifecycle.md) contains `[B-44]`, `[B-73]`, and `[B-74]`.
- [The config note](../../design/config.md) contains the combo string syntax, and the opt-out sentinel.
- [`worker.hpp`](../../../include/DetourModKit/detail/worker.hpp) contains `dmk::StoppableWorker`.
- [Migrating v3 to v4](../../migration/migrating-v3-to-v4.md) states the reload behavior change for consume and wheel users.
