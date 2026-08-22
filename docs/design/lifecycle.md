# Process and DLL lifecycle design

This note explains process and DLL lifecycle. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-44]`, `[B-47]`, `[B-48]`, `[B-49]`, `[B-73]`, `[B-74]`, `[B-90]`, `[B-91]`.

## Leak-on-purpose RAII exception

RAII applies everywhere: `std::unique_ptr`, `std::shared_ptr`, `std::lock_guard`, `std::scoped_lock`. Application code uses no naked `new` or `delete`. The only permitted exception is leak-on-purpose state that avoids a teardown hazard. The hazards are the static destruction order fiasco and a deadlock when destruction runs under the Windows loader lock.

Every such leak must meet these terms:

- A comment documents why the leak exists.
- The leak uses `new (std::nothrow)` so the enclosing `noexcept` path stays honest.
- When the leaked state includes a thread or callback that keeps library code live, the leak holds a counted module reference (`detail::acquire_module_ref()`). Take it while the module is still mapped: before the thread can run, or before the hook or callback is published. Those code pages then stay mapped.
- The reference releases after a clean off-loader-lock join (`detail::release_module_ref`, or `FreeLibraryAndExitThread` for the raw bootstrap worker). On a loader-lock detach it is left outstanding.
- Do not take the reference from the detach path itself. The loader refuses to reference a module whose refcount already reached zero and unloads. See the `Hook` / `VmtHook` handle destructors, the bootstrap worker in `session.cpp`, and `Logger::shutdown_internal`.

## Loader-lock proof inventory

`[B-100]` owns the public loader-lock contract. These proof families pin its boundaries:

- `HookLoaderLock.*` pins the hook boundary.
- `InputLoaderLock.*` pins the input boundary.
- `ConfigWatcherLoaderLockTest.*` pins the config watcher boundary.
- `LoggerTest.LoaderLock*` pins the logger boundary.
- `AsyncLoggerTest.*LoaderLock*` pins the asynchronous logger boundary.
- `WheelHostProof.*` pins the WheelHost install, drain, and stop boundary.
- `Lifecycle.FullLifecycleExit` pins process exit with every subsystem live.
- `Lifecycle.XInputActivePairSurvivesProcessExitStaticDestruction` pins the XInput exit boundary.

## Rules

### [B-44]

A reference requested from a `DLL_PROCESS_DETACH` or unload path is a no-op. After `FreeLibrary` drives the refcount to zero, the loader commits to the unmap and refuses to pin or reference the module.

- Take the reference before the thread can run: `detail::acquire_module_ref(reason)` in `StoppableWorker`, the input poller, the async-logger writer, the memory-cache cleanup thread, and the bootstrap worker. For a hook or callback (`Hook` / `VmtHook`), take it before publication.
- On a clean off-loader-lock teardown, release it after the join (`detail::release_module_ref(module, reason)`, or `FreeLibraryAndExitThread` for the raw bootstrap worker, so no code runs after the release).
- On a loader-lock detach, leave it outstanding so the module stays mapped for the leaked thread.
- Every acquire and release carries a `diagnostics::ModulePinReason`, so `diagnostics::module_pin_count` reports the open references per reason. A `FreeLibraryAndExitThread` self-release decrements its reason first. The pin tests listed in [docs/tests/README.md](../tests/README.md) prove the routed reasons.

One consequence to design around: a background thread's held reference means a bare `FreeLibrary` no longer drives the count to zero. The call then no longer fires the detach teardown. A drained unload runs through `shutdown_and_wait()` off the loader lock, the documented graceful-unload path. `request_shutdown()` only signals and returns, so it cannot be the last step before `FreeLibrary`. A cleared data pointer (for example `s_module`) does not cover the code pages that the thread runs.

Use a counted reference rather than a process-lifetime pin. A pin is both too late from a detach path and permanent. A counted reference is takeable while live and releasable.

### [B-47]

Construct a teardown-surviving singleton with placement-new into never-destroyed static storage, so its destructor never runs and the object outlives every late caller (`StringPool::instance()`, `Profiler::get_instance()`). The OS reclaims the bounded storage at process exit. Make the invariant structural when the type permits it: `StringPool` declares its destructor `= delete`, and `scripts/check_header_hygiene.py` rejects a missing sentinel or any teardown declaration elsewhere.

The process-default `input::scope()` uses this storage because its guard teardown can invoke consumer code. During ordinary unload, call `input::scope().clear()` off the loader lock.

A namespace-scope `Hook` or `VmtHook` can outlive each hook static that first use constructs after the owner. The hook translation units therefore register no exit-time destructor. The process VMT object gate is one such singleton.

The emitted registration determines compliance, not the source spelling. For example, `static std::mutex gate` looks like an ordinary singleton. Current MSVC treats that mutex as trivially destructible. MinGW registers `atexit(pthread_mutex_destroy)`. The MinGW archive gate reads symbols with `scripts/check_hook_exit_destructors.py`. `Lifecycle.LateVmtOwnerOutlivesTheObjectGate` verifies late-owner teardown end to end.

A Meyers singleton whose destructor DOES run at static teardown (for example `Input::instance()`) must instead route that destructor through the subsystem's own idempotent `shutdown()`. That path requests the worker's stop, detaches it when the loader lock forbids a join, and records the leak. The owner stays reachable through the keepalive precommitted before publication. A defaulted destructor performs none of those steps and leaves the worker to run for the rest of the process.

### [B-48]

Some classes detach a thread that keeps the pimpl's members in use on the loader-lock teardown: `AsyncLogger`'s writer reads `m_queue`, `m_flush_cv`, and `m_file_stream`. There, a defaulted `~Class` lets `~Impl` free those members out from under the detached thread. Every owner then has to leak the handle to stay safe ( `Logger::leak_async_logger_handle`), and any direct owner is a latent UAF.

Instead, `~Class` must observe whether its own teardown detached. Use a latched flag (`m_writer_detached`), NOT a re-query of `is_loader_lock_held()`, which TOCTOUs against the detach decision. If the flag is set, abandon the already-heap-allocated `Impl` in place with `m_impl.release()` so `~Impl` never runs. No tiered leak cell is needed when the leaked object is itself already heap-allocated: `unique_ptr::release` leaks with zero allocation, so it cannot fail. Reserve the `new(nothrow)` -> `VirtualAlloc` -> static-slot ladder for a leaked `shared_ptr` that needs a fresh home. The owner-side leak, which keeps the handle alive so the destructor never runs, and the self-safe destructor are complementary belt-and-suspenders, never a double free.

Relatedly, a subsystem must refuse to RESURRECT itself after shutdown. `Logger::enable_async_mode` gates on `m_shutdown_called` UNDER `m_async_mutex`, not before it the way `reconfigure` does. A call can land in `shutdown_internal`'s dropped-mutex window, with async already disabled and the stream not yet closed. Even there, it cannot spin up a fresh writer thread that outlives teardown.

### [B-49]

`request_shutdown()` can `SetEvent(s_shutdown_event)` from any consumer thread at any moment. A plain `HANDLE` read that races a `CloseHandle` -plus-null elsewhere is both a data race and a signal on a closed or kernel-recycled handle. Make the handle `std::atomic<HANDLE>`: a load-then-use reader, a release store on publish.

A path that cannot observe the racing readers must retire the handle to null and LEAK the one small kernel object rather than close it. A concurrent load then gets either a still-valid handle or null, never a closed one. That covers two paths. The loader-lock detach cannot wait for anything. The setup-failure unwind publishes the handle before the `acquire_module_ref` / `CreateThread` steps that fail into it.

A close is legal only once no live thread can still be inside the use. That is either structural (the process-death detach: the OS already terminated every other thread) or observed. For the observed case, guard the handle with an admission word. Its high bit closes admission, and its low bits count callers that can still hold the loaded handle. Close only after a bounded spin sees that count reach zero. Retain plus `record_intentional_leak` when it does not. Every retention is recorded, so a test can assert which branch ran instead of a probe of a handle value that the OS can recycle.

**Both ends of that word must be a compare-exchange, never a load-then-increment or a blind store.** The read of "not retired" and the registration as a caller must be ONE atomic step. The reopen for a new generation must CLAIM the word from exactly the retired-with-zero-readers value. Otherwise a caller preempted between its read and its increment registers on a generation that was retired and reopened meanwhile. The reopen discards that registration, and the caller's matching decrement underflows the word to all-ones. That value has the closed bit set. The new generation is then unsignalable for the rest of the process and any wait on it never returns. The reopen fails closed (it refuses the new generation) whenever a straggler is still counted.

### [B-73]

- If a bounded quiesce expires, leak the guarded resource.
- If a bounded drain expires, leak the guarded resource.
- If a bounded join expires, leak the guarded resource.
- If a bounded layered teardown expires, leak the guarded resource.
- Leak it when a live user can remain inside it.
- Keep its counted module reference so its code pages remain mapped.
- Never free it with a nonzero in-flight count.
- Never join under a control-plane mutex.
- Never restore a prologue when a newer layer still chains through it.
- Check `HookLedger::newer_live_count` before `Hook::~Hook` touches backend memory.
- If a newer layer remains live, retain the older backend and keep the target tracked as hooked.
- Preallocate the aligned XInput retention cell before hook publication.
- If the 10 ms XInput drain expires, transfer the hooks and keepalives into that cell.
- Use the same transfer when either restore lacks an `Original` witness.
- Republish the required trampoline chain after that transfer.
- Leave logical XInput interception disarmed after that transfer.
- If the 5 s start handshake expires, retain the complete `ConfigWatcher::Impl`.
- Clean-join a failed worker after it reports failure and starts its return.
- Restore a newest-first hook layer normally.
- Record each leak on its `diagnostics::LeakSubsystem` counter.
- Limit each event to one retention cell.
- Bound every teardown wait or prove that it drains a closed set.
- Pace event drains through `detail::DrainBackoff`.
- Pace hook drains through `detail::DrainBackoff`.
- Pace input-admission drains through `detail::DrainBackoff`.
- Pace staged-callback drains through `detail::DrainBackoff`.
- Pace binding-rundown drains through `detail::DrainBackoff`.
- Keep the separate 10 ms XInput quiesce on its fixed bounded yield loop.
- On mid-hook callback or adapter-entry expiry, pin the stub and slot (`MidHookDrainTest`).

### [B-74]

DMK's worker module references pin DMK, not consumer callbacks. Before the drain, the caller stops and joins its workers and drops every dispatcher subscription and hook handle. Input guards are not part of that ordering. Retirement reaches the callback through the binding's delivery gate, so a retained `BindingGuard` cannot keep one alive. The drain itself balances a binding still held while the provider is mapped.

`prepare_logic_dll_unload*` owns one end-to-end deadline. It performs these steps in order:

1. It closes reload admission.
2. It requests watcher and servicer stop without a join.
3. It retires input bindings when it destroys their gate-owned callables.
4. It waits for input staged-storage and body leases, plus reload bodies and worker-body exit.
5. It joins and destroys callable storage only after exit is observed.

A binding still inside its callback at the deadline is reported `TimedOut` with the callable deliberately intact. A destroyed callable that a poll thread still runs frees the code out from under it.

With those preconditions met, `SafeToUnload` means that no selected input callable copy, config setter, user reload callback, or DMK worker callable remains. `TimedOut`, `LoaderLock`, `SelfDelivery`, `InProgress`, and `RetireFailed` never authorize `FreeLibrary`.

The legacy void `on_logic_dll_unload*` functions are best-effort abandon wrappers only. Under the loader lock they close admission without a wait, a join, or a destroy of consumer callable storage. A timed-out transaction leaves input admission closed but releases transaction ownership, so an off-loader retry can finish. Only complete session-level finalization reopens it.

### [B-90]

A `join()` from the joined thread raises `std::system_error`, which terminates the host out of the surrounding `noexcept`. An owner destroyed there frees state that the still-running body reads. A bare detach loses the rundown that the teardown was supposed to perform.

Instead, take these steps:

1. Detect the self case and request stop.
2. Publish the observable "no longer running" state.
3. Precommit a self-keepalive before worker publication.
4. Hand the facade's external reference to the process-lifetime reaper (`src/internal/lifecycle_reaper.hpp`). The reaper must invoke the ordinary shutdown while the owner is still alive and wait for the body to return. It clears the self-keepalive only after the complete rundown, and only then releases its reference. A destructor that joins from inside itself ends the owner's lifetime while the body can still read its members.

Such a call is asynchronous by contract. Say so in the public documentation, because a caller must not assume that the rundown finished when the call returns.

The queue must not depend on the heap. The reaper reserves its queue nodes up front, since the retirements that most need it happen under memory pressure. A queue that still refuses leaves the precommitted owner retention intact. A retirement with no rundown callback is refused rather than queued, because an owner whose worker cannot be run down must never be released.

The precommit creates one corollary. The keepalive is a deliberate self-reference, so shutdown must also clear it on the path with nothing to run down at all. Otherwise an owner that never started its worker is retained forever. That clear stays conditional on the abandonment flag. A detached thread leaves the worker non-joinable while its body still reads the owner. A later idempotent shutdown must not read that as permission to release.

The join itself stays wrapped. A join that fails for any other reason is contained, the thread detached, and the whole owner plus its module reference remain reachable. They are never released into a thread that can still run.

### [B-91]

First-use construction allocates, and `noexcept` turns that failure into host death. Give the accessor a no-fail path: construct with the failure caught, then publish an explicitly inert state (a null pimpl, fixed static storage). Every public operation on that state fails closed. Registration and start report `OutOfMemory`, queries read inactive, and mutators and teardown are no-ops.

The failure latches for the process generation. Do not rely on a throwing local static to retry, because the retry re-runs the same allocation under the same pressure with no return channel. Where the singleton's destructor is load-bearing, keep the function-local static object and make its constructor `noexcept`, rather than the never-destroyed leaked-pointer form that `log()` uses. `~Input` is that case: it is the only teardown on a bare `FreeLibrary`. Prove each accessor in a fresh process with every allocation set to fail, also with concurrent first callers, and include a successful control.
