# Input subsystem design

This note explains the input subsystem. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-25]`, `[B-26]`, `[B-27]`, `[B-29]`, `[B-30]`, `[B-35]`, `[B-86]`, `[B-92]`, `[B-95]`, `[B-96]`, `[B-103]`. `[B-31]` and `[B-98]` stay reserved.

## Concurrency model

### input::Input

Lifecycle takes a `mutex`. Reads go through an `atomic<shared_ptr<detail::InputPoller>>`.

- When first-use allocation fails, `instance()` publishes an inert singleton: a null pimpl whose every operation fails closed. The function-local static stays, so `~Input` still runs the bare- `FreeLibrary` teardown.
- Each started poller precommits a self-keepalive before publication and clears it only after a clean join and rundown. Loader-lock, failed-join, and failed-reaper paths therefore retain the complete owner without an allocation.
- A `shutdown()` reached from a binding callback requests stop, publishes not-running, and hands its external reference to the off-thread reaper (`src/internal/lifecycle_reaper.hpp`). The reaper invokes shutdown while the owner remains alive, then releases it only after the join, the detour uninstall, and the final `on_state_change(false)` complete. The method documents that asynchronous contract.

- See `InputBinding` for the unlocked retirement contract. The seven `InputLifecycleProof.*DestroysCallablesOutside*` modes verify both lock domains.
- The process-default Scope follows `[B-47]`. `Lifecycle.InputLoaderDetachRetainsCompleteOwner` verifies its loader-detach lifetime.
- See `Scope::clear()` for its reentrant add contract. `InputTest.ScopeClearKeepsAGuardAddedFromAReleaseCallback` verifies batch isolation.

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
- The wheel hook removes itself with `UnhookWindowsHookEx`. The poll thread installs it, so the OS reclaims the thread-owned hook when that thread exits. A later control-thread removal that reports an invalid handle is a successful removal, not a live-thread cleanup failure.
- Teardown is skipped under loader lock.

Hot-path mechanism: Each detour runs lock-free atomic loads with an allocation-free, non-throwing body.

### Gamepad backend

XInput is the only gamepad backend. Two properties of the flat XInput API carry that decision:

- The poll model matches. `XInputGetState` returns a stateless snapshot from any thread, with no window, message pump, device acquisition, or COM object. The poll thread samples it exactly like `GetAsyncKeyState`.
- Consume needs a patchable entry point. Gamepad suppression detours the exported `XInputGetState` and the ordinal export `XInputGetStateEx`, then masks owned buttons in the game's own reads. DirectInput and GameInput deliver state through per-device COM methods, so no stable exported prologue exists to patch. Raw input needs a window registration on the game's UI thread.

The subsystem targets mod hotkeys and toggles. The XInput limits (four controllers, digital treatment of analog inputs) fit that scope, and controller translators (Steam Input, DS4Windows) present an XInput device.

### Wheel-capture backend

The wheel source is selectable through `input::Input::Settings::wheel_backend`. Both backends see `WM_MOUSEWHEEL` and `WM_MOUSEHWHEEL` records retrieved from one selected UI-thread queue. Direct sent delivery, later `DefWindowProc` parent delivery, raw-input-only paths, and other UI-thread queues stay outside support. Physical origin is not authenticated. Enum value 0 stays reserved and is rejected at runtime.

- `MessageHook` (default): a thread-scoped `WH_GETMESSAGE` hook compiled into this image. It folds on `PM_REMOVE` and takes a permanent `MessageHookKeepalive` after publication. The single-DLL path.
- `ExternalHost`: the loader's resident host behind the `wheel_host.h` C ABI. `Input::start()` validates the table and opens the lease before it starts the poll thread. The poller publishes capture, drains counts, reads the route status, drives retarget, and closes with its owner and generation.

Route identity and migration: the poll loop resolves the target UI thread each cycle. An explicit `Input::Settings::wheel_target_thread_id` pins the route. Zero selects the current process-owned foreground window and migrates when foreground returns on a different thread of this process. Readiness derives from the live target-thread handle, never a sticky flag. A dead target retires the route to a retryable state. `Input::wheel_source_health()` exposes the typed state, and a latched backend error is logged rather than turned into silent zero input.

External route status: `route_status` returns one `WheelHostRouteStatus` snapshot. `route_state` reports physical mount health. `control_state` reports the active control transaction or idle state. A mounted and ready route can still owe a retarget retry.

The host sets `capture_armable` only when all conditions hold:

- The host is started.
- No Stop request is active.
- The control state is idle.
- The snapshot qualifies the current lease.
- The route is ready.

Clients must not duplicate this predicate.

`route_status` can settle physical mount health after a target liveness check. It must never end a control transaction. Quiescence alone cannot expire, cancel, or complete one.

A retarget retry uses its latest thread argument. It does not reuse the destination from the first failed call. `wheel_host_stop` can replace a pending Close transaction. This operation lets the loader recover after the lease owner exits.

Callback order (both backends): count admission folds and counts on `PM_REMOVE` before `CallNextHookEx` with no message mutation, so older hooks see the original record. `CallNextHookEx` runs exactly once. Consume finalization writes `WM_NULL` after it returns, only while the entry epoch, consume mask, TTL, and focus gate all remain current. Each admitted phase is counted so a close, retarget, or Stop drains admitted decisions, bounded. Consume stays best effort: a newer hook can rewrite the message after DMK returns.

`Input::start()` resolves the backend once. Reserved value 0 and every other unknown value are rejected with `ErrorCode::InvalidArg`. Required mode rejects an invalid table with `ErrorCode::InvalidArg` and a failed lease with `ErrorCode::SystemCallFailed`. Optional mode selects the local MessageHook for either failure. Host function pointers run outside DMK locks. The wheel-host C ABI is version 2. A version mismatch or a missing v2 function refuses the table. The C ABI direction order matches `WheelDirection`. A successful host close proves only that resident state holds no logic pointer. The typed drain, complete pin verdict, loader lease probe, `FreeLibrary`, and address probe still decide unload.

These proofs cover the wheel routes:

- `InterceptMessageHookTest.*` and `InterceptMessageHookPollerTest.*` prove local mount, capture, consume, focus, migration, route health, and drain behavior.
- `InterceptMessageHookPinProof.*` proves local keepalive.
- `WheelHostLoader.*` proves external validation, route status, retarget convergence, typed health, and downgrade.
- `DetourModKit_wheel_host_tests` proves standalone ABI layout, transaction visibility, and Stop over a pending Close transaction.
- `Lifecycle.StagedGenerationLocalWheelRetentionStaysMapped` proves retention for a local wheel route.
- `Lifecycle.StagedGenerationSoakReloadsWithFreshBytes` proves 100 logic unmaps over one host.

## Rules

### [B-25]

The raw wheel counter saturates at `MAX_WHEEL_NOTCHES` at its write site. `InterceptMessageHookTest.WheelCounterSaturatesWhenNotDrained` checks that mechanism when its window fixture is available. A skip does not qualify as release evidence under `[B-99]`.

### [B-26]

The per-direction wheel-consume mask (`publish_wheel_consume`) and the gamepad reactive mask both work this way. A `Ctrl+WheelUp` consume binding masks only the Up direction while Ctrl is held, never a bare WheelDown.

Disarm on the arm-to-disarm transition too, not only through the TTL. When the last consume binding is removed, the poll loop must publish an empty mask on the next cycle. The same applies when focus or the controller is lost. Otherwise the game stays masked until the deadline lapses (~2 s). The wheel path publishes its mask every cycle. The gamepad path tracks a was-armed edge and disarms on it. A gamepad publish gated on `m_has_consume_gamepad_bindings` alone skips the disarm exactly when that flag flips false on removal.

The TTL only self-heals a poll thread that stopped. A loop still in its cycle refreshes the deadline itself. An arming condition must therefore also be tied to the loop's ability to DELIVER what it swallows. The wheel mask is armed only for a cycle that also drained the wheel counters. A failed cache rebuild stops the drain while the consume binding stays registered and the wheel hook stays mounted. An armed mask then latches the direction away from both the game and the mod for the rest of the process.

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

Reserved. Never reuse this ID.

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

Reserved. Never reuse this ID.

### [B-103]

`route_state` describes physical mount health. `control_state` describes an active control transaction. A route can remain ready while a failed drain leaves a transaction active.

A target liveness check can settle physical health. It cannot prove that the caller abandoned a target. A query must therefore preserve every active transaction. Otherwise, capture can resume on the old thread.

The host derives `capture_armable` from lifecycle state, both snapshot states, and the current lease. This field gives every client one authoritative predicate.
