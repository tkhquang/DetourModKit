# Input subsystem design

This note explains the input subsystem. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-25]`, `[B-26]`, `[B-27]`, `[B-29]`, `[B-30]`, `[B-31]`, `[B-35]`, `[B-86]`, `[B-92]`, `[B-95]`, `[B-96]`, `[B-98]`.

## Concurrency model

### input::Input

Lifecycle takes a `mutex`. Reads go through an `atomic<shared_ptr<detail::InputPoller>>`.

- When first-use allocation fails, `instance()` publishes an inert singleton: a null pimpl whose every operation fails closed. The function-local static stays, so `~Input` still runs the bare- `FreeLibrary` teardown.
- Each started poller precommits a self-keepalive before publication and clears it only after a clean join and rundown. Loader-lock, failed-join, and failed-reaper paths therefore retain the complete owner without an allocation.
- A `shutdown()` reached from a binding callback requests stop, publishes not-running, and hands its external reference to the off-thread reaper (`src/internal/lifecycle_reaper.hpp`). The reaper invokes shutdown while the owner remains alive, then releases it only after the join, the detour uninstall, and the final `on_state_change(false)` complete. The method documents that asynchronous contract.

Hot-path mechanism: The read is an `atomic<shared_ptr<detail::InputPoller>>` acquire-load, then the engine's `shared_lock` plus a relaxed load. The path is not lock-free.

### detail::InputPoller

State lives in an atomic `m_active_states[]` array.

- The poll thread re-reserves its deferred-callback staging vector to the live binding count each cycle and stages under one catch. Runtime binding growth past the startup reserve therefore cannot reallocate-then-throw out of the `jthread` body.
- The cycle is a transaction. Each staged edge carries its own `m_active_states` transition, and a non-throwing store loop commits the whole batch after the pass. The drained wheel backlog rolls back, and the accumulated consume masks clear. A failed pass therefore owes no callback whose state it already consumed. The next cycle re-derives every such edge from the unchanged physical input, with no physical release and repress needed.
- The derived name/modifier caches rebuild build-then-swap. A rebuild driven by a flag-only change (`set_consume`) retains those caches on allocation failure. It does not clear an index that still describes the binding set. It still disarms gamepad consume suppression, because the flag change can be a retirement and a retained rule list outlives its binding.

The `input::BindingGuard` owns a per-binding teardown gate (`src/internal/input_binding_gate.hpp`): a `HoldGate` for a hold combo, a `PressGate` for a press combo.

- Each gate runs the consumer callback OUTSIDE its `std::mutex`, bracketed by an in-flight count that the mutex protects. The control-plane `release()` therefore runs down any in-flight delivery before it returns.
- A self-release from inside the callback defers its balancing edge to that delivery's unwind when the gate has a delivery in flight. When it has none, the release runs the edge inline.
- A repeated depth-zero guard release waits for a claimant already inside a balancing edge or callable disposal. Retirement waits only to its deadline and refuses if the gate remains claimed.
- Those waits run through consumer code. The unlocked callback buys one guarantee: no wait chain CLOSES on the thread that runs it, since the delivery-depth escape is per-thread.

That escape has two mechanisms, because its two callers differ in what they can do when the record fails:

- An ordinary delivery is marked by a reserved-TLS depth and is REFUSED outright when the depth cannot be stored.
- Teardown consumer code (a hold's balancing edge, and retirement's edge plus the destruction of the retired callable's captures) cannot be declined. It carries a `MandatoryDeliveryScope`, which additionally records the calling thread in an intrusive registry of stack-local nodes behind a statically initialized SRW lock. That registration allocates nothing, throws nothing, nests, and is keyed by native thread id. It holds its lock only across pointer surgery, so no consumer runs under it.

Both halves are load-bearing. Without the registry, two threads each inside a teardown callback that releases the other's gate read as depth-zero control plane. Each then waits on the other's claim. A process-wide marker instead lets an unrelated control-plane release skip the rundown that its public contract promises. The per-gate `teardown_owner` stays as the same-gate recursion guard and is not a substitute for either mechanism.

A cancelled hold delivers exactly one balancing `on_state_change(false)` and never a stale `true` after it. The `HoldGate` reference-counts the N exploded entries of a multi-combo hold, so overlapping combos forward only the aggregate held/released transitions.

Hot-path mechanism: A `shared_lock` (uncontended SRWLOCK reader) guards the `m_active_states` pointer swap, with one `memory_order_relaxed` load per binding. Keyboard and mouse reads route through a poll-thread-private per-cycle `KeyStateCache`. Each distinct VK therefore gets one coherent `GetAsyncKeyState` sample per cycle, not one call per binding reference.

### InputIntercept

File-scope atomics are shared between the poll thread and the game's threads (XInput callers, the window message thread). The layer owns its safetyhook InlineHooks directly, not through a DMK Hook handle. The poll thread reads the trampoline, and the hook lifetime is coupled to the poll thread. The consume-until-release latch and wheel-pulse state are poll-thread-private.

- `install_xinput` takes both keepalives and constructs the never-destroyed retention cell before any prologue is patched. It contains allocator, create, and toggle exceptions, and it reconciles toggles through `hook_patch_witness.hpp`.
- Complete pair coverage is published only after a FINAL witness reads both prologues back, immediately before the store that makes masking possible. It is never published on the strength of the arm results alone. A member that a competing writer restored during the other member's arm window then degrades the pair. The alternative masks one entry point while the other bypasses.
- The same witness runs on every maintenance call rather than a short-circuit on the published flag, so a post-publication loss is detected rather than hidden.
- Degradation is symmetric and fail-open. Either member can be the missing one, both detours go pass-through, and both forwarding chains stay published for already-admitted callers. Recovery re-arms the missing member through that member's OWN existing hook object. It never layers a new hook over a prologue that the pair already patched.
- Teardown retires and drains, classifies both raw hooks before either restore, and frees only after both witness `Original`. Otherwise it moves the pair and keepalives into the reserved cell, so a newer layer and its original chain stay callable.
- WndProc removal adopts the procedure that its exchange displaced and compensates when a foreign subclass lands after observation.
- Teardown is skipped under loader lock.

Hot-path mechanism: Each detour runs lock-free atomic loads with an allocation-free, non-throwing body.

### Wheel-capture backend

The wheel source is selectable through `input::Input::Settings::wheel_backend`. WndProc sees window delivery. MessageHook and ExternalHost see queue retrieval on one UI thread. The local backends share the interception plane. ExternalHost uses the equivalent resident plane behind `wheel_host.h`.

- `WndProc` (default): the window-procedure subclass. Takes a permanent `WndprocKeepalive`. The staged-generation pattern.
- `MessageHook`: a thread-scoped `WH_GETMESSAGE` hook compiled into this image. It folds on `PM_REMOVE` and takes a permanent `MessageHookKeepalive` after publication.
- `ExternalHost`: the loader's resident host behind the `wheel_host.h` C ABI. `Input::start()` validates the table and opens the lease before it starts the poll thread. The poller publishes capture, drains counts, and closes with its owner and generation.

`Input::start()` resolves the backend once. Required mode rejects an invalid table with `ErrorCode::InvalidArg` and a failed lease with `ErrorCode::SystemCallFailed`. Optional mode selects MessageHook for either failure. Host function pointers run outside DMK locks. The C ABI direction order matches `WheelDirection`. A successful host close proves only that resident state holds no logic pointer. The typed drain, complete pin verdict, loader lease probe, `FreeLibrary`, and address probe still decide unload.

Proofs: `InterceptMessageHookPinProof.*` (local keepalive), `WheelHostLoader.*` (external client, validation, downgrade), `DetourModKit_wheel_host_tests` (standalone host), and `Lifecycle.StagedGenerationSoakReloadsWithFreshBytes` (100 logic unmaps over one host).

## Rules

### [B-25]

The raw wheel counter saturates at `MAX_WHEEL_NOTCHES` at its write site. `InterceptWndProcTest.WheelCounterSaturatesWhenNotDrained` checks that mechanism when its window fixture is available. A skip does not qualify as release evidence under `[B-99]`.

### [B-26]

The per-direction wheel-consume mask (`publish_wheel_consume`) and the gamepad reactive mask both work this way. A `Ctrl+WheelUp` consume binding masks only the Up direction while Ctrl is held, never a bare WheelDown.

Disarm on the arm-to-disarm transition too, not only through the TTL. When the last consume binding is removed, the poll loop must publish an empty mask on the next cycle. The same applies when focus or the controller is lost. Otherwise the game stays masked until the deadline lapses (~2 s). The wheel path publishes its mask every cycle. The gamepad path tracks a was-armed edge and disarms on it. A gamepad publish gated on `m_has_consume_gamepad_bindings` alone skips the disarm exactly when that flag flips false on removal.

The TTL only self-heals a poll thread that stopped. A loop still in its cycle refreshes the deadline itself. An arming condition must therefore also be tied to the loop's ability to DELIVER what it swallows. The wheel mask is armed only for a cycle that also drained the detour's counters. A failed cache rebuild stops the drain while the consume binding stays registered and the subclass stays installed. An armed mask then latches the direction away from both the game and the mod for the rest of the process.

### [B-27]

Suppression is enforced off the engine entry's `consume` flag. The poll loop's `gamepad_owned` / `wheel_owned` pass and the detour-side rules read that flag, NOT the guard's callback-enable flag. A released `BindingGuard` therefore gates the callback but leaves the game deprived of the chord for the rest of the process. A consume binding's guard teardown must therefore also clear the `consume` bit and republish (through `recompute_modifier_caches_locked`). Suppression then lasts exactly as long as the guard is held.

Clear it by binding IDENTITY, not by name: `set_consume_by_owner` keyed on the per-registration `consume_owner`, NOT `set_consume(name, false)`. An empty name is legal but is skipped when the poller's name index is built. A name-keyed clear therefore silently misses an empty-name consume binding and leaves suppression armed for the process lifetime.

Reach the facade from the guard's release action in a lifetime-safe way. `input::Input` is a strict process singleton, and the action holds a `weak_ptr` to an `Impl` -owned liveness token. A guard released after that singleton's own static teardown therefore no-ops instead of a touch on a destroyed `Impl`.

The composed teardown runs the gate release before the consume clear. A still-held hold's balancing `on_state_change(false)` is user code that can throw, and `HoldGate::release()` invokes it unwrapped. Wrap the gate release and run the consume clear on the throw path too, then re-raise so the guard's own catch still logs. Otherwise a release edge that throws strands the suppression that the clear exists to lift.

### [B-29]

A multi-combo Hold (`X = A | B`) explodes into N `InputBinding` entries that all share one `HoldGate`, and the poll loop fires each entry's press/release edge independently. Forwarded individually, those edges raise a duplicate `on_state_change(true)` when the second combo comes down. They deliver a premature `false` when the first lifts while the other is still held. `HoldGate` keeps an `active_entries` count and forwards only the 0->1 raise and the 1->0 release. A surplus false while the count is zero is swallowed, so the count can never go negative. A guard release on a still-held multi-combo hold still synthesizes exactly one balancing false. Drive and test any primitive shared across N-exploded entries (a gate, a consume flag, a module-ref cell) with two or more concurrent owners, never one.

### [B-30]

A `BindingGuard::release()` that only clears a flag lets an in-flight `on_press` / `on_state_change` keep its run on the poll thread. A caller that destroys captured state the instant release returns races that call. Route delivery through a per-binding gate (`PressGate` / `HoldGate` in `input_binding_gate.hpp`). The gate invokes the user callback OUTSIDE its mutex, bracketed by an in-flight count that the mutex protects. `release()` waits that count to zero and so cannot return while a delivery is still inside consumer code.

The unlocked callback keeps the wait chain off the thread that runs user code. Two bindings whose teardown callbacks release each other therefore cannot form an ABBA cycle. Do not collapse this back to a gate lock held across the callback, with a `recursive_mutex` or otherwise.

A release reached at delivery depth > 0 must not wait at all. That case is a one-shot binding that destroys its own guard, or one binding's callback that releases another's. It marks the gate released and defers any balancing edge to the in-flight delivery's unwind. When the gate it releases has no delivery in flight, it runs that edge inline.

The promise belongs to each CALLER, not to the gate. A teardown that finds the gate already released still waits out the claimant's consumer-code span before it returns. Its own caller is equally about to destroy captured state. Retirement's span includes callable disposal, while a release's span ends after its balancing edge. Claim that span under the mutex at the same moment the gate is marked released. A claimant drops the mutex to wait for deliveries to drain. An in-flight count alone therefore leaves a window in which a second teardown reads a quiesced gate and returns early. The same claim makes the unload drain's retirement and a retained guard's release exclude each other in both directions.

Say plainly on the public contract what that costs, because the depth escape is per-thread and cannot break a cycle that closes across threads. A depth-0 release waits, untimed, for whatever consumer code the claimant runs, and retirement's span includes the destruction of the callable's captures. A caller must release a guard without a held lock, or an owned join, that any of that code can wait on. Prefer a bounded wait wherever the caller has a deadline to give: `retire()` has one and refuses at it, `release()` has none.

### [B-31]

`uninstall_wndproc()`'s restore removes the detour from the chain through `SetWindowLongPtrW`. A `wndproc_detour` frame already dispatched on the window thread loads `s_prev_wndproc` at the top of the detour and forwards there. A zeroed pointer races that in-flight frame and routes its message to `DefWindowProcW`, which silently drops, for example, WM_CLOSE and WM_ACTIVATE at every teardown. Clear only the install-state flags (`s_hwnd` / `s_wndproc_installed`). A later re-install overwrites the predecessor. Zero the pointer only when there is genuinely no procedure to point at, that is, when the window is already destroyed.

### [B-35]

The two off-table forms reconstruct through different readers. A source-tagged token round-trips through `parse_input_name`. A bare-hex keyboard token (`0xNN`) round-trips only through the config combo parser behind `config::bind_combos`, whose untagged-hex fallback defaults to Keyboard. `parse_input_name` returns `nullopt` for a bare-hex token by design. A doc or test that names the keyboard round-trip must therefore name the config parser, not `parse_input_name`.

### [B-86]

MinGW lowers `thread_local` to `__emutls_get_address`, which allocates on each thread's first touch and serializes on a process-wide mutex to do it. A detour entered from a game thread runs both inside a hooked function. Worse than either, libgcc's `emutls.c` calls `abort()` when that allocation fails. SIGABRT is not interceptable by a catch frame, so an enclosing `noexcept` boundary contains nothing. First-touch OOM is host death, not a reportable error. Reserve a Win32 TLS index at install time and read it from the callback instead.

That primitive is not infallible either. An index past the TEB's inline slots is backed by a lazily heap-allocated expansion array, so a store can fail under memory pressure. Treat a failed store as unknown state rather than absence, and resolve that unknown where the record is read:

- When the record only decides whether storage stays alive, pin it. `mid_hook_adapter.hpp` counts the unrecorded entry, so a rundown retains the stub instead of a conclusion that the thread is elsewhere and a free.
- When the record answers a per-thread question that another thread acts on, refuse the operation instead. The input delivery marker (`input_delivery_scope.hpp`) declines a callback whose frame it cannot record. A wider "some thread is possibly in a callback" answer lets an unrelated control-plane release skip the rundown that its public contract promises.

Either way the failure needs an allocation-free identity to fall back on. Use `GetCurrentThreadId` and not `std::this_thread::get_id`, whose winpthreads `pthread_self` path allocates on a foreign thread.

This rule governs the mechanism, not the spelling, and the spellings are not interchangeable here. On the toolchain the presets select (`x86_64-w64-mingw32`, thread model posix), function-local `thread_local`, namespace-scope `thread_local`, and `__thread` all lower to emutls. `__declspec(thread)` is ignored with only a `-Wattributes` warning and silently degrades to a plain shared global. Source review therefore cannot establish compliance. Prove it from the emitted symbols, per compiler: `scripts/check_emit_tls.py` scans the dispatcher, input-delivery marker, and routed-retention backend objects.

### [B-92]

An edge state advanced (or a one-shot input backlog drained) as each item is evaluated invites a mid-pass allocation failure. That failure destroys the callbacks it already staged while the state says they fired. The edge is consumed, never delivered, and never re-derived. Carry each item's state transition in the staged record. Apply it in a non-throwing loop after the pass, still under the lock that keeps the indices stable. Roll back any source the pass consumed destructively. `detail::InputPoller::poll_loop` does this for `m_active_states` and for the wheel-notch backlog, whose notches have no physical repress a user can repeat.

The rule extends to anything the pass publishes from partial work. Reset the accumulated consume masks on the rollback path, so suppression disarms wholly rather than in an index-dependent fragment. That is the fail-open direction `[B-26]` already requires.

### [B-95]

- Require each `InputPoller` to present its nonzero owner id for every control-plane and data-plane operation.
- Serialize owner publication on the data-plane lock.
- Serialize owner revocation on the data-plane lock.
- Serialize all five data-plane operations on the data-plane lock.
- Acquire `s_intercept_mutex` before the data-plane lock.
- Authorize an operation only when the live owner matches exactly.
- Never treat an unowned layer as permission to mutate shared state.
- Clear rules before the bounded detour drain.
- Clear masks before the bounded detour drain.
- Clear gates before the bounded detour drain.
- Clear wheel counts before the bounded detour drain.
- Release the data-plane lock before that drain waits.
- Refuse every write or drain from a stale owner after revocation.

### [B-96]

A staging lease is acquired before a callback is copied into poll-cycle storage and is declared before the copied `std::function` members. Reverse member destruction therefore releases the lease only after their callable managers and captures are destroyed. The lease remains held across dispatch, even for a callback refused by a later tombstone or generation advance. Registration uses the same close-and-recheck handshake: a commit admitted before the close finishes before named retirement begins, while a later registration is refused. Teardown then waits for every staged lease that it possibly raced. Self-delivery refuses instead of a wait on its own lease.

### [B-98]

A `GetWindowLongPtrW` observation that DMK is top can become stale before `SetWindowLongPtrW`. The exchange's returned displaced procedure is the authoritative winner. Publish uninstalled only when the exchange displaced DMK. If it displaced a foreign subclass, immediately put that returned procedure back on top and retain DMK as the predecessor it already captured. If another writer wins the compensation gap, restore that latest returned writer rather than clobber it, and keep state conservative. The same returned-predecessor rule applies on install. A pre-check alone only shrinks the race and never authorizes an overwrite of the slot.
