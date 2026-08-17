# Hot-reload development guide

Split a mod into a thin loader and a logic DLL to change mod code without a game restart. The loader lives for the process. The logic DLL is unloaded and reloaded on demand.

| Binary           | Role                                          | Lifetime           |
|------------------|-----------------------------------------------|--------------------|
| `mod_loader.asi` | Loads, unloads, and reloads the logic DLL     | The game session   |
| `mod_logic.dll`  | Hooks, features, config, and input bindings   | One reload cycle   |

This note states what DetourModKit guarantees across an unload. It does not ship a loader. The two-DLL pattern is a consumer pattern, and the code below is a skeleton, not a product.

## Reload sequence

1. Disable the reload hotkey, so a second press cannot start a concurrent reload.
2. Call the logic DLL's `Shutdown()` export.
3. Call `FreeLibrary` only after `Shutdown()` reports success.
4. Call `LoadLibrary` on the rebuilt logic DLL.
5. Resolve the `Init` and `Shutdown` exports with `GetProcAddress`.
6. Call `Init()`.
7. Re-enable the hotkey.

Windows holds a file lock on a loaded DLL. Build into a staging directory and copy from it before step 4, or unload before you rebuild.

## What DetourModKit guarantees across an unload

### Hook removal needs a quiescent target

Dropping a `Hook` handle rewrites the original prologue bytes back. It does not freeze threads. During the rewrite the backend strips execute from the patched page. A vectored exception handler relocates the instruction pointer of a thread that *faults* on that page. A thread already inside the trampoline or the detour body is not relocated. Removal is therefore safe only when the hooked function is quiescent.

A fixed sleep cannot prove quiescence. `Shutdown()` must return false while any consumer-owned worker, subscription, hook caller, or other callback source can still run. The loader must keep the DLL mapped and retry later.

### A retained hook pins the old image

Every hook holds a counted module reference on the module that hosts DetourModKit. In the default topology that module is the logic DLL itself. A handle that outlives `FreeLibrary` keeps the hook installed and keeps the old image mapped, so the next `LoadLibrary` returns the stale image instead of the new build.

A destructor that cannot prove it restored the prologue pins the backend on purpose rather than free a trampoline the target can still enter. It records an intentional leak and logs a warning. Read `diagnostics::intentional_leak_count(LeakSubsystem::HookManager)` before you conclude that a handle was missed.

### Layered hooks unwind newest-first

When several handles target the same address, destroy them newest-first. `hook::HookStack` owns the handles and drains them newest-first in its destructor, its move-assignment, and `clear()`. Prefer it to a bare `std::vector<Hook>`, which carries no such order. Out-of-order teardown is contained, not corrupting: the older backend is retained instead of restored over the newer layer. The retention is permanent, so only newest-first returns the pristine prologue.

### Session teardown owns the process-wide subsystems

`~Session` runs the ordered teardown: config auto-reload watcher, input, memory cache, config registry, then the logger last. The process-default logger storage is process-lifetime on purpose, so CRT static destructors never touch it. The teardown flushes and closes the sink instead. The logger truncates its file whenever it opens the sink, so each reload starts a clean log.

Destroy the `Session` before `FreeLibrary`. Skipping it can leave the old sink and the async writer alive after the image is gone.

### What does not reset

- Game memory. Direct `memory::patch_code` and `memory::write_bytes` changes survive the reload. Track them and revert them in `Shutdown()`.
- The config file on disk. Edit the INI, reload, and the new values take effect.
- State you want to keep. Store it in the loader, which is never unloaded.

Global and static variables in the logic DLL reset on every cycle. The profiler ring buffer lives in logic-DLL memory, so export it before `Shutdown()` if you need the samples.

### Threads, TLS, and static constructors

Join every consumer-owned thread in `Shutdown()`, before the `Session` teardown. A thread that outlives `FreeLibrary` executes unmapped code.

Use [`dmk::StoppableWorker`](../../../include/DetourModKit/detail/worker.hpp). Normal destruction requests stop and joins. When the loader lock forbids a blocking teardown it detaches instead, without running stop callbacks, and leaves its counted module reference outstanding so the code pages stay mapped. That branch requests no stop at all, so an abandoned body never observes `stop_requested()`. Publish your own cancellation flag beside the stop token when the body must terminate on that path.

`FreeLibrary` does not run `thread_local` destructors for threads the DLL did not create. Avoid `thread_local` in a logic DLL, or clean it up in `Shutdown()`. Prefer explicit `Init` and `Shutdown` functions to file-scope static constructors.

Build the loader and the logic DLL with the same compiler and C runtime. A mixed pair crashes on the ABI boundary.

## Topology: DetourModKit in the logic DLL

This is the default. Each cycle destroys the `Session` and the next `Init()` builds a fresh one.

```cpp
// mod_logic/dllmain.cpp
static std::unique_ptr<dmk::Session> s_session;
static dmk::hook::HookStack s_hooks;
static std::unique_ptr<dmk::StoppableWorker> s_scan_worker;

extern "C" __declspec(dllexport) bool Init()
{
    s_session = std::make_unique<dmk::Session>(/* ModInfo */);
    // install hooks into s_hooks, bind config, register input
    return true;
}

extern "C" __declspec(dllexport) bool Shutdown()
{
    s_scan_worker.reset();   // request stop and join, off the loader lock
    revert_all_patches();    // your own raw byte patches
    s_hooks.clear();         // newest-first, while the code pages are mapped
    s_session.reset();       // ordered process-wide teardown
    return true;
}
```

## Topology: DetourModKit in a persistent host

Static-link DetourModKit into the loader when one host loads several logic DLLs, or when the logger and the warmed memory cache must survive every unload. The logic DLL then owns no `Session`. It drops only what it owns and asks for a typed verdict.

```cpp
extern "C" __declspec(dllexport) bool Shutdown()
{
    s_workers.clear();
    s_subscriptions.clear();
    s_hooks.clear();

    static constexpr std::string_view binding_names[] = {"ToggleEquip_Chest", "ShowEquip_Chest"};
    return dmk::prepare_logic_dll_unload(binding_names) == dmk::LogicDllUnloadStatus::SafeToUnload;
}
```

`prepare_logic_dll_unload` is the safe-unmap transaction. It retires the named input bindings, closes callback staging, requests the watcher and the reload servicer to stop without joining, and waits to one end-to-end deadline. `SafeToUnload` means that no selected input callable copy, config setter, user reload callback, or DetourModKit worker callable remains.

`TimedOut`, `LoaderLock`, `SelfDelivery`, `InProgress`, and `RetireFailed` are refusals. Do not call `FreeLibrary` for any of them. Keep the DLL mapped and retry from an off-loader-lock control thread. A timed-out attempt keeps callback admission closed, so it cannot authorize new callback work while the retry is pending.

`prepare_logic_dll_unload_all()` clears every input binding but keeps the poll thread alive. Use it only when the unloading DLL owns the whole process-wide input and config surface. The registry is process-scoped, so the all-bindings form also retires a sibling DLL's bindings. Prefer the named-list overload when several logic DLLs share one instance.

The legacy void `on_logic_dll_unload*` functions are source-compatible abandon wrappers. They never authorize `FreeLibrary`.

[`[B-74]` in the lifecycle note](../../design/lifecycle.md) owns the full transaction contract, including the binding-guard rules below.

### Binding guards during the drain

Drop a consumer-owned `BindingGuard` before, during, or after the drain. Retirement reaches the callback through the binding's delivery gate, so a guard you keep cannot hold a callable alive. A Hold binding still held when the drain runs receives its balancing `on_state_change(false)` there, while your module is still mapped.

Drop a guard without holding a lock, and without owning a join, that your balancing callback or your captures' destructors can wait on. Otherwise the drain thread and the releasing thread wait on each other.

The strongest arrangement is the one the proofs use. The host links DetourModKit and owns every hook, binding, and config registration. The logic DLL contributes callables only and links no copy of the library.

## Idempotency on a second `Init()`

In a persistent host, every call into a process-wide singleton from `Init()` is the second or later call in the process.

| API                                        | Second-call behavior                                  | Do first                                |
|--------------------------------------------|-------------------------------------------------------|-----------------------------------------|
| `Logger::configure`                        | Replaces the config and rotates the file under lock   | Nothing                                 |
| `hook::inline_at` / `mid_at` (per address) | `TargetAlreadyHookedByThisKit` under strict refusal   | Drop the prior `Hook` handle            |
| `config::bind_*`                           | Replaces the item and its setter in place             | Nothing                                 |
| `config::press_combo` / `hold_combo`       | Replaces the config item, appends the input binding   | `input::Input::remove_bindings_by_name` |
| `input::register_combo`                    | Appends a second binding under the same name          | `input::Input::remove_bindings_by_name` |
| `input::Input::start`                      | No-op, and the new `poll_interval` is ignored         | `shutdown()`, to change the interval    |
| `bootstrap_attach` / `bootstrap`           | Returns a failed `Result` while a session is attached | `bootstrap_detach`                      |

`input::register_combo` is append-only. The engine treats `name` as a label, not a key. That is the most common surprise across reloads.

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

## Related documentation

- [Config hot-reload](config-hot-reload.md) contains the INI reload API and its thread-safety contract.
- [The lifecycle note](../../design/lifecycle.md) contains `[B-44]`, `[B-73]`, and `[B-74]`.
- [The config note](../../design/config.md) contains the combo string syntax, including the opt-out sentinel.
- [`worker.hpp`](../../../include/DetourModKit/detail/worker.hpp) contains `dmk::StoppableWorker`.
