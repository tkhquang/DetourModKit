# Process and DLL lifecycle design

This note explains process and DLL lifecycle. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

## Leak-on-purpose RAII exception

**RAII everywhere:** `std::unique_ptr`, `std::shared_ptr`, `std::lock_guard`, `std::scoped_lock`. No naked `new`/`delete` in application code. The only permitted exception is leak-on-purpose state to avoid teardown hazards -- specifically the static destruction order fiasco or deadlock when destruction would run under the Windows loader lock. Any such leak must be documented with a comment explaining why, must use `new (std::nothrow)` so the enclosing `noexcept` path stays honest, and -- when the leaked state includes a thread or callback that keeps running library code -- must hold a counted module reference (`detail::acquire_module_ref()`, taken while the module is still mapped, before the thread can run or before the hook/callback is published) so those code pages stay mapped. That reference is released after a clean off-loader-lock join (`detail::release_module_ref`, or `FreeLibraryAndExitThread` for the raw bootstrap worker) and simply left outstanding on a loader-lock detach. Do not try to take it from the detach path itself: the loader refuses to reference a module whose refcount has already reached zero and is unloading (see the `Hook`/`VmtHook` handle destructors, the bootstrap worker in `session.cpp`, and `Logger::shutdown_internal`).

## Loader-lock proof inventory

`[B-100]` owns the public loader-lock contract. These proof families pin its boundaries:

- `HookLoaderLock.*` pins the hook boundary.
- `InputLoaderLock.*` pins the input boundary.
- `ConfigWatcherLoaderLockTest.*` pins the config watcher boundary.
- `LoggerTest.LoaderLock*` pins the logger boundary.
- `AsyncLoggerTest.*LoaderLock*` pins the asynchronous logger boundary.
- `Lifecycle.FullLifecycleExit` pins process exit with every subsystem live.
- `Lifecycle.XInputActivePairSurvivesProcessExitStaticDestruction` pins the XInput exit boundary.

## Rules

### [B-44]

A reference requested from a `DLL_PROCESS_DETACH` / unload path is a no-op: once `FreeLibrary` has driven the refcount to zero the loader has committed to unmapping and refuses to pin or reference the module. Take the reference before the thread can run (`detail::acquire_module_ref()` in `StoppableWorker`, the input poller, the async-logger writer, the memory-cache cleanup thread, and the bootstrap worker) or before a hook/callback is published (`Hook`/`VmtHook`). On a clean off-loader-lock teardown it is released after the join (`detail::release_module_ref`, or `FreeLibraryAndExitThread` for the raw bootstrap worker, so no code runs after the release); on a loader-lock detach it is simply left outstanding so the module stays mapped for the leaked thread. One consequence to design around: a background thread's held reference means a bare `FreeLibrary` no longer drives the count to zero, so it no longer fires the detach teardown -- a drained unload runs through `shutdown_and_wait()` off the loader lock (the documented graceful-unload path; `request_shutdown()` only signals and returns, so it cannot be the last step before `FreeLibrary`). Clearing a data pointer (e.g. `s_module`) does not cover the code pages the thread runs. Use a counted reference rather than a process-lifetime pin: pinning is both too late from a detach path and permanent, whereas a counted reference is takeable while live and releasable.

### [B-47]

Construct such a teardown-surviving singleton with placement-new into never-destroyed static storage so its destructor never runs and the object outlives every late caller (`StringPool::instance()`, `Profiler::get_instance()`); the bounded storage is reclaimed by the OS at process exit. Make the invariant structural when the type permits it: `StringPool` declares its destructor `= delete`, and `scripts/check_header_hygiene.py` rejects a missing sentinel or any teardown declaration/definition elsewhere. A Meyers singleton whose destructor DOES run at static teardown (for example `Input::instance()`) must instead route that destructor through the subsystem's own idempotent `shutdown()`, which requests the worker's stop, detaches it when the loader lock forbids a join, and records the leak; the owner stays reachable through the keepalive precommitted before publication. A defaulted destructor performs none of those steps and leaves the worker running for the rest of the process.

### [B-48]

If a class detaches a thread that keeps reading its pimpl's members on the loader-lock teardown (`AsyncLogger`'s writer reads `m_queue` / `m_flush_cv` / `m_file_stream`), a defaulted `~Class` lets `~Impl` free those members out from under the detached thread -- so every owner would have to leak the handle to stay safe (`Logger::leak_async_logger_handle`), and any direct owner is a latent UAF. Instead have `~Class` observe whether its own teardown detached -- a latched flag (`m_writer_detached`), NOT a re-query of `is_loader_lock_held()` (that TOCTOUs against the detach decision) -- and, if so, abandon the already-heap-allocated `Impl` in place with `m_impl.release()` so `~Impl` never runs. No tiered leak cell is needed when the leaked object is itself already heap-allocated (`unique_ptr::release` leaks with zero allocation, so it cannot fail); reserve the `new(nothrow)` -> `VirtualAlloc` -> static-slot ladder for leaking a `shared_ptr` that needs a fresh home. The owner-side leak (which keeps the handle alive so the destructor never runs) and the self-safe destructor are complementary belt-and-suspenders, never a double free. Relatedly, a subsystem must refuse to RESURRECT itself after shutdown: `Logger::enable_async_mode` gates on `m_shutdown_called` UNDER `m_async_mutex` (not before it, the way `reconfigure` may), so a call landing in `shutdown_internal`'s dropped-mutex window -- async already disabled, the stream not yet closed -- cannot spin up a fresh writer thread that outlives teardown.

### [B-49]

`request_shutdown()` may `SetEvent(s_shutdown_event)` from any consumer thread at any moment; a plain `HANDLE` read racing a `CloseHandle`+null elsewhere is both a data race and a signal on a closed or kernel-recycled handle. Make it `std::atomic<HANDLE>` (a load-then-use reader, a release store on publish). A path that cannot observe the racing readers must retire it to null and LEAK the one small kernel object rather than close it, so a concurrent load gets either a still-valid handle or null, never a closed one; that covers the loader-lock detach (which may not wait for anything) and the setup-failure unwind, which publishes the handle before the `acquire_module_ref` / `CreateThread` steps that fail into it. Closing is legal only once no live thread can still be inside the use, which is either structural (the process-death detach: the OS has already terminated every other thread) or *observed*: guard the handle with an admission word whose high bit closes admission and whose low bits count callers that may already have loaded it, then close only after a bounded spin sees that count reach zero, and retain plus `record_intentional_leak` when it does not. Every retention is recorded, so a test can assert which branch ran instead of probing a handle value the OS may have recycled. **Both ends of that word must be a compare-exchange, never a load-then-increment or a blind store.** Reading "not retired" and registering as a caller has to be ONE atomic step, and reopening the word for a new generation has to CLAIM it from exactly the retired-with-zero-readers value; otherwise a caller preempted between its read and its increment registers on a generation that was retired and reopened meanwhile, the reopen discards that registration, and the caller's matching decrement underflows the word to all-ones -- which has the closed bit set, so the new generation is unsignalable for the rest of the process and any wait on it never returns. The reopen fails closed (refuse the new generation) whenever a straggler is still counted.

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

DMK's worker module references pin DMK, not consumer callbacks. Before the drain, the caller stops and joins its workers and drops every dispatcher subscription and hook handle. Input guards are not part of that ordering: retirement reaches the callback through the binding's delivery gate, so a retained `BindingGuard` cannot keep one alive, and a binding still held is balanced by the drain itself while the provider is mapped. `prepare_logic_dll_unload*` owns one end-to-end deadline: it closes reload admission, requests watcher and servicer stop without joining, retires input bindings by destroying their gate-owned callables, waits for input staged-storage/body leases plus reload bodies and worker-body exit, and joins/destroys callable storage only after exit is observed. A binding still executing its callback at the deadline is reported `TimedOut` with the callable deliberately intact, because destroying a callable a poll thread is running would free the code out from under it. With those preconditions met, `SafeToUnload` means no selected input callable copy, config setter, user reload callback, or DMK worker callable remains. `TimedOut`, `LoaderLock`, `SelfDelivery`, `InProgress`, and `RetireFailed` never authorize `FreeLibrary`. The legacy void `on_logic_dll_unload*` functions are best-effort abandon wrappers only; under the loader lock they close admission without waiting, joining, or destroying consumer callable storage. A timed-out transaction leaves input admission closed but releases transaction ownership so an off-loader retry can finish; only complete session-level finalization reopens it.

### [B-90]

A `join()` from the joined thread raises `std::system_error`, which terminates the host out of the surrounding `noexcept`; destroying the owner there frees state the still-running body is reading; and detaching alone loses the rundown the teardown was supposed to perform. Detect the self case, request stop, publish the observable "no longer running" state, precommit a self-keepalive before worker publication, and hand the facade's external reference to the process-lifetime reaper (`src/internal/lifecycle_reaper.hpp`). The reaper must invoke the ordinary shutdown while the owner is still alive, wait for the body to return, clear the self-keepalive only after the complete rundown, and only then release its reference; beginning the destructor and joining from inside it ends the owner's lifetime while the body can still read its members. Such a call is asynchronous by contract: say so in the public documentation, because a caller may not assume the rundown finished when it returns. Queuing must not depend on the heap -- the reaper reserves its queue nodes up front, since the retirements that most need it happen under memory pressure -- and a queue that still refuses leaves the precommitted owner retention intact. A retirement it has no rundown callback for is refused rather than queued, because an owner whose worker cannot be run down must never be released. Note the corollary the precommit creates: the keepalive is a deliberate self-reference, so shutdown must also clear it on the path where there is nothing to run down at all, or an owner that never started its worker is retained forever; that clear stays conditional on the abandonment flag, because a detached thread leaves the worker non-joinable while its body is still reading the owner, and a later idempotent shutdown must not read that as permission to release. The join itself stays wrapped: a join that fails for any other reason is contained, the thread detached, and the whole owner plus its module reference remain reachable, never released into a thread that may still be running.

### [B-91]

First-use construction allocates, and `noexcept` turns that failure into host death. Give the accessor a no-fail path: construct with the failure caught and publish an explicitly inert state (a null pimpl, fixed static storage) whose every public operation fails closed -- registration and start report `OutOfMemory`, queries read inactive, mutators and teardown are no-ops. The failure latches for the process generation; do not rely on a throwing local static to retry, because the retry re-runs the same allocation under the same pressure with no return channel. Where the singleton's destructor is load-bearing (`~Input` is the only teardown on a bare `FreeLibrary`), keep the function-local static object and make its constructor `noexcept`, rather than adopting the never-destroyed leaked-pointer form `log()` uses. Prove each accessor in a fresh process with every allocation failing, including concurrent first callers, and include a successful control.
