# Hook engine and backend design

This note explains the hook subsystem. Rulebook entries with the same `[B-nn]` IDs live in
[AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-01]`, `[B-16]`, `[B-41]`, `[B-42]`, `[B-43]`, `[B-66]`, `[B-81]`, `[B-83]`, `[B-84]`,
`[B-85]`, `[B-89]`, `[B-97]`.

## Concurrency model

### hook (free functions + RAII Hook/VmtHook)

There is no central registry.

The call gate:

- Each `Hook` pins a refcounted per-hook call gate: a `std::recursive_mutex` plus the currently-callable trampoline,
  published under that mutex.
- `call()` copies the gate into a strong reference BEFORE the lock. `enable()`, `disable()`, `~Hook`, and
  `operator=(Hook&&)` can therefore run concurrently with a guarded call, without reclamation of backend storage still
  in use.
- A late caller that only pinned the gate before teardown reads a null callable and fails closed.
- `enable()` and `disable()` drive an atomic CAS status machine and publish or clear the gate's callable under the
  gate mutex.

The ledger:

- The per-linked-instance `src/internal/hook_ledger.hpp` is a small mutex over target/vptr sets, not a public
  registry. DMK is a static archive, so two DLLs that each link it get two independent ledgers.
- The ledger backs exact duplicate detection (`fail_if_already_hooked`) through an atomic check-and-reserve (
  `try_reserve_hook`). The reservation commits only after backend create and fallible setup succeed, and it rolls
  back on any create failure.
- The two refusal mechanisms carry two codes, because the caller's correct response differs.
  `ErrorCode::TargetAlreadyHookedByThisKit` comes from the ledger. `ErrorCode::TargetAlreadyHookedByAnotherModule`
  comes from the foreign-prologue decode that runs only when the ledger has no record.
- Same-target backend creates proceed through the ledger's pending queue in reservation order, so permissive layering
  cannot patch concurrently or invert the trampoline chain.
- Only the newest live layer on a target writes its bytes. `enable()` and `disable()` claim the target's ledger slot
  and refuse with `ErrorCode::LayerConflict` from underneath a newer layer.
- The ledger's state is never-destroyed storage, so a hook owned by a namespace-scope object can still tear down at
  static-destruction time.

VmtHook and teardown:

- `VmtHook` serializes object-vptr create/apply/remove/teardown transitions through a setup-time object gate, with
  per-method state still protected by its SRWLOCK.
- The destructor applies the loader-lock leaf discipline. Under the loader lock it leaks the backend and
  `record_intentional_leak`s instead of a restore. It keeps the counted module reference it took at install, which
  maps the trampoline/detour code.
- It restores only on a positive byte witness. Otherwise it pins the whole backend and keeps the ledger entry.
- Clean x64 mid teardown is a separate bounded retention case. Public `mid_at` automatically reserves route capacity
  before publication. Backend destruction leaves the published gateway, inline trampoline, allocator backing, and
  unwind metadata mapped for process lifetime, while the mid stub/adapter can be retired.
- A retained id still counts in newer-layer counting for the process lifetime. The pinned backend is still installed,
  so a layer underneath it must stay refused. Ids append newest-last, so a layer installed after a pin still tears
  down normally.
- `Hook::release()` and `VmtHook::release()` are the caller-requested form of the same pin and book their leak
  identically.

Hot-path mechanism: None. Install and teardown are setup/control-plane. The per-hook gate mutex serializes `call()`,
and the handle's own storage must outlive a concurrent call.

## Backend confinement

The public hook island has these members:

- `src/hook.cpp` belongs to the island.
- `src/hook_toggle.cpp` belongs to the island.
- `src/hook_mid_context.cpp` belongs to the island.
- `src/internal/hook_backend.hpp` belongs to the island.
- `src/internal/hook_backend_visit.hpp` belongs to the island.
- `src/internal/mid_hook_adapter.hpp` belongs to the island.
- `src/internal/mid_hook_adapter.cpp` belongs to the island.

The active input island contains `src/internal/input_intercept.cpp`. Other library sources must not include
SafetyHook or name `safetyhook::`.

The library links SafetyHook as a private build dependency. CMake keeps static link requirements behind
`$<LINK_ONLY:...>`.

These sources prove the boundaries:

- `scripts/check_header_hygiene.py` proves the source boundary.
- `scripts/check_install_prefix.py` proves the install boundary.
- `tests/package_build_tree` proves the consumer boundary.

The root CMake file declares Zydis before SafetyHook and uses commit `569320ad3c4856da13b9dbf1f0d9e20bda63870e`. The
commit cannot move like a tag. Zycore follows the Zydis submodule gitlink.

## Rules

### [B-01]

Files under `external/` are git submodules. A verified backend prerequisite can change them only as an isolated,
upstreamable commit inside that submodule, followed by an explicit parent gitlink pin. Keep DetourModKit integration
and tracking changes in the parent repository.

Backend sourcing. `external/safetyhook` is pinned to the upstream-served commit `f44cc07` (`cursey/safetyhook`
`main`). DMK's backend fixes that no upstream ref carries are re-applied from `cmake/safetyhook_patches/` at
configure time by `cmake/DMKBackendPatch.cmake` (idempotent, fail-closed). Those fixes are:

- trap-transaction status reporting,
- post-static-destruction teardown,
- a logical enabled flag that follows committed or exactly witnessed reachability, with explicit emitted-patch
  provenance,
- a retry for an execute fault whose protection window closed before the fault reached the trap handler.

The patch also carries address-scoped reported-failure and exception test seams gated behind
`SAFETYHOOK_ENABLE_TEST_SEAMS`. That definition is directory-scoped, because a target-scoped one does not reach the
backend's own translation units. The release lane scans the shipped backend archive for them alongside DMK's own. A
fresh `git submodule update --init` resolves from the configured remote and builds.

When you re-pin the backend, pin only to a commit that the configured upstream remote serves. ALSO regenerate the
vendored patch so it still reconstructs the reviewed tree (`git -C external/safetyhook diff <base> <reviewed>`). A
re-pin without the patch silently drops the fix. Never repoint `.gitmodules` at a fork to carry the delta.

`scripts/check_backend_patch.py` fails closed if the model drifts. It validates the upstream URL and the frozen patch
hash and fix markers. It validates the pinned base commit against both the parent gitlink and the checked-out
submodule HEAD, and it validates the submodule working tree itself. That tree can be in exactly two source states: the
pristine pinned base before any configure, or byte-exactly the reviewed patch output after one. Each of these is
refused:

- staged content, or index visibility flags,
- an ordinary untracked path other than the configure-time `.dmk_patch.lock` marker,
- ignored content outside the frozen non-source build/IDE/generated-output roots,
- a tracked edit outside the patch's file set,
- an incompletely applied patch,
- a patched file whose bytes are not the reconstruction of base plus patch,
- any failed state query.

`--expect-state pristine|patched` pins which state a phase requires. The blocking `backend-patch` quality job proves
the fresh checkout, applies the patch through `cmake -P cmake/DMKBackendPatch.cmake`, and proves the result.
`dmk_verify_backend_state` in that module decides the changed-file set, ignored-output boundary, and index visibility
flags at configure time as well. A configure therefore aborts rather than compiles a backend nobody reviewed.

The configure-time verdict is byte equality, not a path set, and that is frozen. An edit inside a target the patch
already owns leaves the changed-path set identical. Once the patch's lines are present, the idempotence reverse-apply
stays clean too. A ruling on either signal alone lets configure compile unreviewed bytes.
`dmk_reconstruct_backend_targets` therefore rebuilds every owned target from the pinned base blob plus the patch in a
scratch tree and compares each file. The scratch tree is anchored as its own git worktree root, because `git apply`
otherwise resolves the patch against whatever repository it discovers. It sits inside the submodule's git directory,
so backend-state enumeration can never see it.

Python and CMake implement one model with two spellings of the same normalization: `lf()` and
`git diff --ignore-cr-at-eol`. `scripts/test_check_backend_patch.py` asserts that they accept and refuse the same
states. It does not trust the spellings to stay equivalent. A fixture for this defect must put the smuggled bytes
outside every hunk, or the reverse-apply catches them first and the test proves nothing.

A configured build tree leaves the submodule working tree dirty, because the patch is applied in place. It can also
leave ignored generated build output under its reviewed roots. That is expected.

`EXPECTED_PATCH_SHA256` is a computed value. Never substitute a literal for it without the recompute command in the
comment above it and the checker's own verdict. Any change to the patch content, a new backend test scenario included,
requires a regenerated patch and a re-pinned hash. It also requires a re-run of forward apply, reverse apply, and
configured-tree equality. Such a change belongs in a backend batch.

### [B-16]

`disable()` writes a hook's saved prologue back over the target. A hook created on an already-hooked address saved a
jump to the older detour as its prologue. An oldest-first restore therefore rewrites the entry into the older hook's
freed trampoline, a use-after-free. `src/internal/hook_ledger.hpp` tracks per-target layer order and closes both
halves. A non-top-layer `enable()` / `disable()` is REFUSED with `ErrorCode::LayerConflict` and writes nothing. An
out-of-order destructor leaks the older backend rather than restores it. The rule below is therefore about clean
teardown rather than crash avoidance. It still matters: the leak is permanent, and only newest-first restores the
pristine prologue.

Reverse-order destruction is automatic for stack locals and array or aggregate members. A `std::vector<Hook>` (or any
container) does not provide the required newest-first teardown contract. Code that holds layered same-target handles
in a container must not rely on a container drop for rollback. Tear them down back-to-front (`pop_back`) or use a
commit-on-success transaction, never `~vector`. This is the `install_all` rollback trap, fixed by its internal
`InstallRollback` guard.

For caller-held sets of hooks, prefer `hook::HookStack`: a move-only owner that drains newest-first in its
destructor, move-assignment, and `clear()`. The safe order is then guaranteed by construction rather than by caller
discipline. Do not reach for a bare `std::vector<Hook>` when the hooks can be layered.

### [B-41]

DMK's coverage is deliberately inline (`inline_at`), mid-function (`mid_at`), and VMT object / per-method (
`vmt_for`), which reach the internal AOB / RTTI-resolved game functions DMK targets. The excluded families are scope
decisions, not gaps:

- IAT / EAT redirection only intercepts calls routed through an import or export thunk, never an internal call reached
  by pointer. It therefore cannot reach DMK's targets.
- An INT3 software-breakpoint hook still modifies `.text` like the inline JMP. It adds a process-wide
  exception-handler dependency and a single-step re-arm race for no new capability.
- A debug-register hardware-breakpoint hook touches no code bytes. It is limited to four per-thread `DR` slots and
  belongs to the anti-cheat-evasion problem DMK does not solve.
- Dynamic binary instrumentation is a whole recompilation runtime, which DMK is not.

An added family is a change to the product scope, not a bug fix. Make that decision deliberately, and see
[hook-type-coverage.md](../guides/hooking/hook-type-coverage.md). PolyHook 2 is the hook-breadth reference. Frida
Stalker is the DBI ceiling.

### [B-42]

Retire the published trampoline pointer first, wrap the detour body in an in-flight counter, and drain it (bounded)
before teardown. Run the drain off the loader lock, after the thread that installed the hook is joined.
`input_intercept::uninstall` clears the XInput trampoline pointers, then drains `s_xinput_inflight`. A zero in-flight
count is necessary but not sufficient. Witness the target bytes before the backend restore and again afterwards. A
newer layer can still reach the trampoline while no DMK detour body is active. The drain is bounded so a thread wedged
in the game's own code cannot hang teardown. Safetyhook's own mid-prologue relocation covers that residual instant, so
the counter shrinks the window rather than replaces that mechanism.

### [B-43]

The teardown side retires (stores the trampoline pointer to null) and drains (loads the in-flight counter). Together
with the detour's own increment-then-load-trampoline, that forms a store-buffering / Dekker litmus. Each thread stores
one atomic then loads a different one, and the single reordering that acquire/release does NOT forbid is exactly that
StoreLoad. Under acquire/release, the teardown can observe a zero count while a detour still holds the stale non-null
trampoline, and then free it.

Make ALL FOUR participating operations `seq_cst`: the two retire stores, the drain load, the
`InflightGuard::fetch_add` increment, and the detour's trampoline loads. Or place a `seq_cst` fence between the store
and load on each side. Nothing less puts them in the one total order the litmus requires. On the x86-64 target this is
free: a `seq_cst` load is a plain MOV, and a locked RMW is already a full barrier. The decrement stays release. It is
not part of the StoreLoad pair. It only publishes the detour's completion to the drain. Grep every
`store(..., release)` immediately followed by a sibling-atomic `load(..., acquire)` in a teardown for this shape.

### [B-66]

A VMT clone includes the ABI prefix below the address point as well as callable slots above it. Guard-copy that
complete span into owned memory, terminate the snapshot with a private sentinel, and let the backend clone only an
owned surrogate. Detach the backend before any host object is published.

Publish and restore real object words through a range-confined, fault-contained atomic compare-exchange. A
displacement, protection change, or unmap then returns normally, without abandoned C++ locks or destructors. The
backend must retain no host object pointer. A guarded read followed by a guarded store is not equivalent: a foreign
writer that displaces the word between the two is silently overwritten. Carry the expected value into one instruction
and reject a losing comparison. Refuse an unaligned word rather than split-lock it, since alignment is what makes the
exchange atomic. These checks are unconditional and independent of policy options.

A swap of foreign access for an owned snapshot moves the trap rather than removes it. Any fact derived BEFORE the
capture (a slot count, a size, an offset) describes different memory than the backend acts on. Even a re-walk of
captured pointer words is insufficient when the backend re-queries mutable metadata, such as the target pages' execute
permission. `Impl::method_count` is the worked example. It is the only bound between a caller's index and `VmHook`'s
unchecked slot write. A count larger than SafetyHook's allocation therefore corrupts an adjacent RWX allocation
without a fault. Demote the pre-capture walk to a capture budget, and derive the published count from captured words.
Normalize the backend surrogate's counted run to a DMK-owned executable marker, so its allocation has exactly that
count. Then copy the captured targets into the detached clone before publication. More generally, validate the
backend's complete footprint, or replace its foreign access with an owned snapshot or guarded transaction. C++
`try/catch` does not contain a foreign SEH fault.

### [B-81]

The record exists only while the target and trampoline pages are temporarily non-executable during one patch
transaction. While that transaction is active, an execute fault elsewhere on either affected page must retry until
protection returns. A continued exception search exposes an artificial backend-created fault to the host. After every
success or failure path, remove the record before the return. Otherwise later reuse of the same virtual address turns
an unrelated fault into an infinite retry loop. Query and protection failures must return a status, restore only the
protections acquired, and never run the patch callback after a failed acquisition. DMK still independently witnesses
target bytes before it publishes Active or Disabled state.

### [B-83]

`inline_at`, `mid_at`, and `install_all` return disabled hooks. Publish the handle and callback context before the
`Hook::enable()` call. A byte witness verifies the arm. A rejected witness publishes `Disabled` only when the
compensating disable leaves the prologue witnessed original. If that rollback cannot prove it, the handle stays
truthfully active and returns `DisableFailed`. This rule is specific to the inline/mid transaction: `hook::vmt_for`
is intentionally live on creation and has no `enable()` step. It stays safe by construction because it publishes the
real object's vptr last, after the private clone is fully built. No window exists where a caller can observe a
half-published clone.

### [B-84]

A throw can cross generated code that does publish valid records, and the routed gateway, wrapper, and exit thunk are
exactly that case. A native exception raised in a routed destination is required to reach its caller's handler.
Windows x64 unwinds a frame with no registered `RUNTIME_FUNCTION` as a leaf. An escaping throw then walks garbage and
terminates the host instead of a report.

Code that DMK's backend generates, and that a destination call can raise through, registers its records before the
route can be published. That code (the routed gateway, wrapper, and exit thunk) never modifies RSP anywhere its
records do not describe. The gateway and exit save with `push rbx; pushfq`, restore with `popfq; pop rbx`, and then
jump or return. Both intercepted RFLAGS and callback-written RFLAGS therefore survive, while the final pop/jump or
pop/ret remains a recognized epilogue. The wrapper uses the ordinary fixed `sub rsp, 40` / `add rsp, 40` frame.
Registration failure fails the create. Failed unregistration conservatively retains the referenced storage.
Publication retains code and records together for the process lifetime.

Generated code that adjusts RSP dynamically cannot be described this way (SafetyHook's mid stub), so a throw must
still never reach it. A DMK-managed callback adapter must preserve the exact backend signature, contain every user
exception, and own an enter/recheck/leave rundown. It reaches the user callback from a real DMK frame, which is the
only place containment and in-flight accounting can live. A raw arbitrary-signature detour (`hook::inline_at`)
cannot be wrapped that way, because the erased form does not know the target's signature. It carries a documented
no-throw contract and caller-owned quiescence instead. Document that requirement rather than encode it as a `noexcept`
function type. The header already accepts ordinary function pointers, so the tightened type is a compatibility break.

### [B-85]

Flip the allocation-free tombstone before any teardown decision. Every later branch, even one that leaks the backend,
then goes inert rather than keeps a call path into a destroyed owner. Off loader lock, drain callbacks committed
before the tombstone on every branch. A second live recheck lets new entries through a pinned backend back out without
a join on that callback count. The drain therefore has a deterministic end. Destroy the backend only after physical
entry stops and every adapter body leaves. Never wait on the calling thread: a teardown reached from inside its own
callback must detect that and pin instead. A timeout is not a drain.

### [B-89]

A detour, subclass, or worker becomes reachable the instant it is published. From then on, teardown can find a host
thread inside it that a bounded drain cannot evict. The only memory-safe response is retention, so the resources
retention needs must already be held when publication happens. Those are:

- the counted module reference on the code,
- the counted reference on any foreign module whose bytes were patched,
- the storage that the retained objects will live in.

Acquisition at teardown is not equivalent. Teardown is exactly the moment the process can be out of memory or unable
to reference a module. The fallback branch that discovers this has only one move left: free the trampoline a live
thread runs through. Fail the install instead when a prerequisite cannot be taken. The caller retries. A drained
teardown releases the pair it took, so install/uninstall cycles stay balanced. The balance itself is a permanent gate
rather than an OS-refcount assertion that the host can invalidate with a pinned DLL.

### [B-97]

The backend commits its mutation inside a thread-trapping transaction that can still fail or throw during cleanup. A
failure can therefore sit over a live patch or a completed restore. `Hook::enable`, `Hook::disable`, rollback, and
`~Hook` contain backend exceptions and then classify the patch window as `Original`, exact `OwnedPatch`, `Foreign`,
or `Indeterminate`. `OwnedPatch` requires persistent provenance that the backend completed its emitted-byte capture.
A pre-sized or default-filled buffer is not evidence.

Never short-circuit the witness on a backend failure. A committed restore makes the target unable to enter this hook
and authorizes backend destruction, while a committed exact patch publishes `Active` with `BackendFailed`.
Destruction still retains any x64 routed chain that was previously published. That process-lifetime retention is
capacity-accounted and independent of the byte witness.

A committed restore followed by `Foreign` or `Indeterminate` remains conservatively `Active` with `DisableFailed`. A
newer layer can chain through the trampoline, and unreadable bytes prove no absence. Reassert the backend's retained
state before that publication, so `is_enabled()` and a later owned-patch retry agree. Conversely, `Original` clears a
stale backend flag before backend destruction, so a contained exception is never retried from SafetyHook's noexcept
destructor. Both toggles write unconditionally, so `Foreign` and `Indeterminate` are refused before the call. Teardown
pins them.

The vendored patch makes the backend's enabled flag change at the byte-mutation callback, supports witness-backed
reconciliation, and preserves patch provenance across disable/re-enable (see `[B-01]`). A re-pin that drops any of
those properties silently re-opens this class.
