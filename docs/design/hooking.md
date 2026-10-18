# Hook engine and backend design

This note explains the hook subsystem. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-01]`, `[B-16]`, `[B-41]`, `[B-42]`, `[B-43]`, `[B-66]`, `[B-81]`, `[B-83]`, `[B-84]`, `[B-85]`, `[B-89]`, `[B-97]`, `[B-104]`, `[B-105]`, `[B-106]`, `[B-107]`, `[B-108]`.

## Concurrency model

### hook (free functions + RAII Hook/VmtHook)

The process coordinator owns route order across participants. The local ledger owns DMK handle identities.

The call gate:

- Each `Hook` pins a refcounted per-hook call gate: a `std::recursive_mutex` plus the currently-callable trampoline, published under that mutex.
- `call()` copies the gate into a strong reference BEFORE the lock. `enable()`, `disable()`, `~Hook`, and `operator=(Hook&&)` can therefore run concurrently with a guarded call, without reclamation of backend storage still in use.
- A late caller that only pinned the gate before teardown reads a null callable and fails closed.
- The gate word lives in never-destroyed storage inside the handle (`[B-47]`). `~Hook` runs no member destructor over it, so a `call()` that races teardown on retained storage reads a null word instead of a destroyed atomic. `HookConcurrency.CallRacesDestructorOnRetainedStorage` pins the race.
- `enable()` and `disable()` drive an atomic CAS status machine and publish or clear the gate's callable under the gate mutex. `is_enabled()` takes the same mutex, because the backend's enabled flag is not atomic.

The ledger:

- The per-linked-instance `src/internal/hook_ledger.hpp` is a small mutex over target/vptr sets, not a public registry. DMK is a static archive, so two DLLs that each link it get two independent ledgers.
- The ledger backs exact duplicate detection (`fail_if_already_hooked`) through an atomic check-and-reserve ( `try_reserve_hook`). The reservation commits only after backend create and fallible setup succeed, and it rolls back on any create failure.
- The two refusal mechanisms carry two codes, because the caller's correct response differs. `ErrorCode::TargetAlreadyHookedByThisKit` comes from the ledger. `ErrorCode::TargetAlreadyHookedByAnotherModule` comes from the foreign-prologue decode that runs only when the ledger has no record.
- The local ledger serializes same-target reservations. The process coordinator serializes backend create, patch, and reclaim transactions across participants.
- Only the newest live layer on a target writes its bytes. `enable()` and `disable()` claim the target's ledger slot. Under a newer local layer, an Active hook bypasses in place of a write, and a restored hook gets `ErrorCode::LayerConflict` (`[B-16]`).
- The ledger's state is never-destroyed storage, so a hook owned by a namespace-scope object can still tear down at static-destruction time.

VmtHook and teardown:

- `VmtHook` serializes object-vptr create/apply/remove/teardown transitions through a setup-time object gate, with per-method state still protected by its SRWLOCK.
- The destructor applies the loader-lock leaf discipline. Under the loader lock it leaks the backend and `record_intentional_leak`s instead of a restore. It keeps the counted module reference it took at install, which maps the trampoline/detour code.
- Inline and mid `Hook` teardown restores only on an `OwnedPatch` witness. A `Foreign` or `Indeterminate` witness retires the hook as residue (`[B-104]`), and a failed restore over its own patch pins the whole backend. Both keep the ledger entry. `VmtHook` teardown restores an object word only through the compare-exchange in `[B-66]`, and a rejected exchange pins the clone.
- Clean x64 mid teardown reclaims the published route after the backend proves that it is idle. Public `mid_at` reserves route capacity before publication. An idle chain returns its gateway, trampoline, allocator block, and unwind records, and refunds its charge. A failed proof retains the chain and its charge. `Hook::~Hook` records that retention as a `LeakSubsystem::HookManager` leak with a warning, or as `HookResidue` when no thread can reach the stub (`[B-108]`).

  The proof requires a restored target, zero route entries, and a closed route. Each pass suspends every other thread once (`[B-107]`), and each instruction pointer must be outside the gateway and trampoline. Each suspended thread's committed stack is checked for relocated-call return addresses. The current thread's stack receives the same check. The scan excludes dormant fiber stacks. Counted displaced execution covers their route lifetime.

  After the first scan, the backend checks every route count and dependent count again. A second scan precedes release under the same coordinator acquisition. `Lifecycle.MidRouteBypassDuringIdleScanRetains` verifies admission during the first scan. `InlineHook.ClosedNonMidBypassHasAStackOnlyWitness` isolates the stack-read witness.

  Every patch transaction excludes the trampoline and gateway pages of each registered route after page normalization. A target on an excluded page fails with `NON_EXECUTABLE_TRANSACTION_UNAVAILABLE`. `Lifecycle.RoutedChainExceptionPreservesLifetime` verifies saved-context safety and clean release when no fault occurs. `InlineHook.TransactionsKeepSharedRoutedChainsExecutable` verifies a chain that shares a page with another hook's trampoline.

  A non-mid closed bypass uses its own counted wrapper through the complete provider call. Ordinary `original()` calls retain the destination wrapper's existing ownership. `Lifecycle.RoutedBypassSurvivesDormantFiber` verifies the route and provider after the host releases its module reference.

  A mid window fails with `UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE` when an instruction after a displaced call has RSP as an explicit destination. An `ADD` of a nonnegative immediate is the exception. Without the refusal, an exit reads the stale return word of the completed call as a live internal return and keeps its route entry. `Lifecycle.MidRouteStaleSlotRefusesCreation` verifies unchanged target bytes and balanced capacity after refusal.

  Mid ownership extends through displaced instructions and callees. Ordinary exits preserve registers and flags. An exit preserves ownership when its top stack slot points into the displaced window or its epilogue. Each generated exit has unwind records for its temporary frame.

  A selected resume inside the displaced window or at its epilogue preserves ownership. An external resume releases it. Enable redirects acquire ownership. Disable leaves counted mid execution in the trampoline until its normal exit. Closed gateways acquire ownership before bypass execution.

  A mid gateway requests 1,920 bytes for its control, exits, and unwind records. The reservation allows 4,096 logical bytes and three allocation granules per complete chain. Idle teardown refunds that reservation and charge. `Lifecycle.MidRouteAccountingIncludesGeneratedStub` verifies the requested bytes and complete capacity charge.

  An exception continuation preserves its entry until normal execution exits. Exception unwind and nonlocal exits can abandon an entry. The bounded drain then retains the whole backend, adapter, and module references with an explicit warning. The saved-context quiescence contract resides in `mid_at`.

  `Lifecycle.MidRouteSurvivesDormantFiber` and `Lifecycle.MidRouteSurvivesExceptionContinuation` verify saved execution after teardown. `Lifecycle.MidRouteUnwindSettlesRouteOwnership` verifies permanent retention after unwind. The other `Lifecycle.MidRoute*` cases verify normal exits, selected resumes, bypass execution, register preservation, unwind records, and idle reclamation.

  The [process route coordinator](#process-route-coordinator) owns dependencies across participants. `Lifecycle.RouteCopiesRetainLayeredDependencies`, `Lifecycle.RouteCopiesRetainInlineDependencies`, and `Lifecycle.RouteCopiesRetainOverlappingDependencies` verify that contract after both loader references drop. The local idle proof remains under `Lifecycle.PublishedMidRouteReclaimsUnlessParked`.
- A retained id still counts in newer-layer counting for the process lifetime, and so does a residue id. Both positions stay in the target chain, so a layer underneath either one never writes the target. An Active layer there bypasses, and teardown retires it as residue. Ids append newest-last, so a layer installed after a pin still tears down normally.
- `Hook::release()` and `VmtHook::release()` are the caller-requested form of the same pin and book their leak identically.

Hot-path mechanism: None. Install and teardown are setup/control-plane. The per-hook gate mutex serializes `call()`, and the handle's own storage must outlive a concurrent call.

## Process route coordinator

Participants are the Windows x64 copies that share version 1 of a private data protocol. A named mapping identifies one canonical view. Its name includes the process ID and process creation time. A participant accepts an existing mapping only when its canonical address is a view of the same section in this process. A mapping that another process created first therefore refuses coordination.

The process owns one 49,152-byte non-executable mapping and two handles. The payload occupies 45,112 bytes and holds 512 bounded records. It contains no callable address or allocator state. The owner remains after every participant unloads. `Lifecycle.StagedGenerationResourcesStayWithinBudget` verifies one view and two handles after each generation.

`safetyhook::ProcessCoordinator` in `external/safetyhook/include/safetyhook/os.hpp` owns the lock order, the acquisition limit, owner reacquisition, and the shared layer order. Create holds the coordinator through the original-byte snapshot and record publication. Patch transactions and reclamation scans acquire it before any protection change or thread suspension. DMK teardown acquires it before a route closes, because the coordinator wait export can be that route.

Each record identifies a target, its patched byte count, creation order, generated ranges, enable state, and continuation state. A live newer record blocks a target write by an older layer. A retained newer record permanently preserves older dependencies. Teardown records a reconciled enable state before the idle proof. Clean teardown removes its record before storage release. An exhausted registry refuses creation before publication.

Every x64 trampoline that the patched backend emits ends with a relay cell, which other participants read under the coordinator. A 16-byte footer fills the last bytes of the trampoline allocation: the body offset, the layout `RELAY_CELL_LAYOUT` (1), the hook kind, and a seal. The seal is a fixed value XOR the address of the seal word. The 8-aligned body holds the state (Owned or Vacant), a 64-bit FNV-1a identity of the hook name, and the target. It also holds the switch word and route word addresses and up to 32 saved original bytes. The format is frozen, and a reader treats a footer that fails the seal or the layout as an opaque layer (`[B-105]`).

A layer that retires without a restore switches off, drains, and marks its cell Vacant under the coordinator. Its record stays live, enabled, and unretained, and nothing frees its trampoline. The switch word is the relay slot of an inline hook, or the route state of a mid or routed hook. Inside its create hold and before any allocation, a create claims the newest record on its target that passes every check:

- The record is enabled and not retained.
- The footer seal and layout match. The kind matches the request: E9 or FF for an inline request, mid for a mid request, and routed for a routed request.
- The state is Vacant, the identity matches the request hook name, and the body target equals the record target.
- The saved byte count equals the patch size of the record.
- The switch word lies inside a range that the record names and holds the trampoline start, or the route state is CLOSED.
- The target window differs from the saved original bytes.

The claim changes the state from Vacant to Owned with one compare-exchange. It writes no target byte and adds no record. A mid or routed claim writes its destination into the route word while the route stays CLOSED. The claimed hook starts bypassed, never restores, and vacates at teardown. When no cell passes, the create installs fresh on top.

Timeout, missing state, incompatible state, or abandoned ownership refuses unsafe work. Abandoned ownership permanently poisons the coordinator. A refused teardown retains storage and reports its cause after the local ledger releases. A later acquisition marks its record retained. A record that no acquisition marks stays live and refuses a target write by an older layer.

When another thread holds the coordinator throughout teardown, DMK makes at most four acquisitions per disarmed mid hook and two per armed hook. The coordinator timeout budgets total eight and four seconds, respectively, apart from scheduler delay.

The [refusal measurements](../analysis/coordinator_refusal_v4/README.md) record both paths. `Lifecycle.RouteCopiesRetryArmedTeardownAfterCoordinatorRefusal` and `Lifecycle.RouteCopiesRetryDisarmedTeardownAfterCoordinatorRefusal` verify clean reclamation after one refused DMK acquisition.

Retained DMK routes also preserve their adapter and counted module reference. A DMK drain failure or a destroy lock failure records its leaked route as retained.

Foreign libraries outside this protocol remain outside its guarantee. A DMK layer under foreign bytes never writes over them, and an Active one bypasses (`[B-97]`). The existing target-lifetime and saved-context contracts still apply. No public coordinator API or package target exists.

`Lifecycle.RouteCopies*` verifies these contracts:

- serialization and layered dependencies,
- retention after a callback or adapter drain failure,
- targets on the wait stub page, on the wait export, and on a page that holds a TLS lookup export,
- refusals and their reported causes,
- registration capacity, acquisition timeout, and a retried first connection,
- refusal of a foreign or incompatible mapping.

`Lifecycle.RouteCoordinatorSurvivesParticipantUnload` verifies a stable owner after the first participant unmaps. `Lifecycle.DestroyLockFailureRetainsRoute` and `Lifecycle.ReconciledRouteReleasesProcessRecord` verify the lock-failure and reconciled record states. `Lifecycle.RefusedTeardownNamesCoordinator` verifies the retention cause after a refused restore. `Lifecycle.RefusedTeardownCompletesRetention` verifies the charge and the retained record after a refused teardown acquisition.

## Backend confinement

The public hook island is `src/hook.cpp`, `src/hook_toggle.cpp`, `src/hook_mid_context.cpp`, `src/hook_retirement.cpp`, `src/internal/hook_backend.hpp`, `src/internal/hook_backend_visit.hpp`, `src/internal/mid_hook_adapter.hpp`, and `src/internal/mid_hook_adapter.cpp`.

The active input island contains `src/internal/input_intercept.cpp`. Other library sources must not include SafetyHook or name `safetyhook::`.

The library links SafetyHook as a private build dependency. CMake keeps static link requirements behind `$<LINK_ONLY:...>`.

These sources prove the boundaries:

- `scripts/check_header_hygiene.py` proves the source boundary and owns the island list as `BACKEND_SOURCE_ISLANDS`.
- `scripts/check_install_prefix.py` proves the install boundary.
- `tests/package_build_tree` proves the consumer boundary.

The root CMake file declares Zydis before SafetyHook and uses commit `569320ad3c4856da13b9dbf1f0d9e20bda63870e`. The commit cannot move like a tag. Zycore follows the Zydis submodule gitlink.

## Rules

### [B-01]

Files under `external/` are git submodules. A verified backend prerequisite can change them only as an isolated, upstreamable commit inside that submodule, followed by an explicit parent gitlink pin. Keep DetourModKit integration and tracking changes in the parent repository.

Backend sourcing. `external/safetyhook` is pinned to the upstream-served commit `f44cc07` (`cursey/safetyhook` `main`). DMK's backend fixes that no upstream ref carries are re-applied from `cmake/safetyhook_patches/` at configure time by `cmake/DMKBackendPatch.cmake` (idempotent, fail-closed). Those fixes are:

- trap-transaction status reporting,
- post-static-destruction teardown,
- a logical enabled flag that follows committed or exactly witnessed reachability, with explicit emitted-patch provenance,
- a retry for an execute fault whose protection window closed before the fault reached the trap handler,
- instruction-cache maintenance for generated code and target patch commits,
- instruction-boundary relocation and trap redirection for widened branches,
- refusal before multi-byte writes when a required transaction code page must stay executable,
- a VMT move constructor that propagates allocation failure,
- reclamation of a published routed chain after an idle proof, with retention recorded for later proofs on the same target,
- mid-route ownership through displaced execution, terminal exits, and transaction redirects,
- preservation of the first E9 failure when the FF fallback fails without an allocation error,
- process coordination for patch order, route records, and reclamation across participants,
- an 8-aligned relay slot in every x64 trampoline, which one atomic store can retarget,
- a relay in the far-hook trampoline, so the target holds the relay address and never the detour,
- a bypass API (`bypass_supported()`, `bypass()`, `resume()`, `bypassed()`) that stores the relay slot or the route state with no target write,
- read-only coordinator layer queries (`layer_count()`, `free_record_count()`, `records_at()`) over version 1 records,
- an idle proof before a non-routed trampoline free, which retains the trampoline with `RouteRetentionReason::IdleProofFailed` on failure,
- a route-local test control word, so a retained gateway in a seam build reads no image data,
- a sealed relay cell at the end of every x64 trampoline,
- `vacate()` on inline and mid hooks, which marks a bypassed position Vacant and leaves the object inert,
- a `PositionClaim` create argument that claims a Vacant position of the same hook name,
- a claimed mode that writes no target byte and no record field and frees nothing,
- an idle pass that walks only this process's threads and suspends them together, and one deferred proof for every restored trampoline,
- a mid stub that frees only when no thread can reach it, and a restored route proof that a retirement can defer and repeat,
- an idle-pass refusal record that names the refused thread and check.

The patch also carries address-scoped reported-failure and exception test seams gated behind `SAFETYHOOK_ENABLE_TEST_SEAMS`. That definition is directory-scoped, because a target-scoped one does not reach the backend's own translation units. The release lane scans the shipped backend archive for them alongside DMK's own. A fresh `git submodule update --init` resolves from the configured remote and builds.

When you re-pin the backend, pin only to a commit that the configured upstream remote serves. ALSO regenerate the vendored patch so it still reconstructs the reviewed tree (`git -C external/safetyhook diff <base> <reviewed>`). A re-pin without the patch silently drops the fix. Never repoint `.gitmodules` at a fork to carry the delta.

`scripts/check_backend_patch.py` fails closed if the model drifts, and its docstring owns the refused states. The submodule working tree has exactly two source states: the pristine pinned base before any configure, or byte-exactly the reviewed patch output after one. `--expect-state pristine|patched` pins which state a phase requires. The blocking `backend-patch` quality job proves the fresh checkout, applies the patch through `cmake -P cmake/DMKBackendPatch.cmake`, and proves the result.

The configure-time verdict is byte equality, not a path set. `dmk_reconstruct_backend_targets` rebuilds every owned target from the pinned base blob plus the patch in a scratch git worktree and compares each file. The worktree sits inside the submodule's git directory, so backend-state enumeration never sees it. An edit inside a target the patch already owns therefore fails on bytes, not on the path set or the reverse-apply.

Python and CMake spell one normalization two ways, `lf()` and `git diff --ignore-cr-at-eol`. `scripts/test_check_backend_patch.py` asserts that they accept and refuse the same states. A fixture for that defect must put the smuggled bytes outside every hunk, or the reverse-apply catches them first and the test proves nothing.

A configured build tree leaves the submodule working tree dirty, because the patch is applied in place. It can also leave ignored generated build output under its reviewed roots. That is expected. `.gitmodules` sets `ignore = dirty`, so the parent's `git status` and `git diff` do not report it.

`EXPECTED_PATCH_SHA256` is a computed value. Never substitute a literal for it without the recompute command in the comment above it and the checker's own verdict. Any change to the patch content, a new backend test scenario included, requires a regenerated patch and a re-pinned hash. It also requires a re-run of forward apply, reverse apply, and configured-tree equality. Such a change belongs in a backend batch.

### [B-16]

A restore writes the saved prologue over the target. Below a newer layer that write clobbers the newer layer, and a layered prologue can reference an older route. Only the newest unclaimed layer over its own patch therefore restores. Every other Active layer bypasses (`[B-104]`), and teardown vacates its position (`[B-105]`). The local ledger finds a newer local layer, and a coordinator refusal of the restore finds a newer participant. `Hook::enable()` and `Hook::disable()` own the error codes, and `Lifecycle.RouteCopiesReportLayerConflict` verifies that an arm over restored bytes stays refused.

Reverse-order destruction is automatic for stack locals and array or aggregate members. A `std::vector<Hook>` (or any container) gives no newest-first order, so a lower layer then retires as residue instead of a restore. The `install_all` rollback therefore tears its rows down back-to-front through its internal `InstallRollback` guard.

For caller-held sets of hooks, prefer `hook::HookStack`. This move-only owner drains newest-first in its destructor, move-assignment, and `clear()`, so each of its layers can restore. `HookStack::retire` switches every relay off and drains every counted detour and mid route before its newest-first commit (`[B-106]`).

### [B-41]

DMK's coverage is deliberately inline (`inline_at`), mid-function (`mid_at`), and VMT object / per-method ( `vmt_for`), which reach the internal AOB / RTTI-resolved game functions DMK targets. The excluded families are scope decisions, not gaps:

- IAT / EAT redirection only intercepts calls routed through an import or export thunk, never an internal call reached by pointer. It therefore cannot reach DMK's targets.
- An INT3 software-breakpoint hook still modifies `.text` like the inline JMP. It adds a process-wide exception-handler dependency and a single-step re-arm race for no new capability.
- A debug-register hardware-breakpoint hook touches no code bytes. It is limited to four per-thread `DR` slots and belongs to the anti-cheat-evasion problem DMK does not solve.
- Dynamic binary instrumentation is a whole recompilation runtime, which DMK is not.

An added family is a change to the product scope, not a bug fix. Make that decision deliberately, and see [hook-type-coverage.md](../guides/hooking/hook-type-coverage.md). PolyHook 2 is the hook-breadth reference. Frida Stalker is the DBI ceiling.

### [B-42]

Retire the published trampoline pointer first, wrap the detour body in an in-flight counter, and drain it (bounded) before teardown. Run the drain off the loader lock, after the thread that installed the hook is joined. `input_intercept::uninstall` clears the XInput trampoline pointers, then drains `s_xinput_inflight`. A zero in-flight count is necessary but not sufficient. Witness the target bytes before the backend restore and again afterwards. A newer layer can still reach the trampoline while no DMK detour body is active. The drain is bounded so a thread wedged in the game's own code cannot hang teardown. Safetyhook's own mid-prologue relocation covers that residual instant, so the counter shrinks the window rather than replaces that mechanism.

### [B-43]

The teardown side retires (stores the trampoline pointer to null) and drains (loads the in-flight counter). Together with the detour's own increment-then-load-trampoline, that forms a store-buffering / Dekker litmus. Each thread stores one atomic then loads a different one, and the single reordering that acquire/release does NOT forbid is exactly that StoreLoad. Under acquire/release, the teardown can observe a zero count while a detour still holds the stale non-null trampoline, and then free it.

Make ALL FOUR participating operations `seq_cst`: the two retire stores, the drain load, the `InflightGuard::fetch_add` increment, and the detour's trampoline loads. Or place a `seq_cst` fence between the store and load on each side. Nothing less puts them in the one total order the litmus requires. On the x86-64 target this is free: a `seq_cst` load is a plain MOV, and a locked RMW is already a full barrier. The decrement stays release. It is not part of the StoreLoad pair. It only publishes the detour's completion to the drain. Grep every `store(..., release)` immediately followed by a sibling-atomic `load(..., acquire)` in a teardown for this shape.

### [B-66]

A VMT clone includes the ABI prefix below the address point as well as callable slots above it. Guard-copy that complete span into owned memory, terminate the snapshot with a private sentinel, and let the backend clone only an owned surrogate. Detach the backend before any host object is published.

Publish and restore real object words through a range-confined, fault-contained atomic compare-exchange. A displacement, protection change, or unmap then returns normally, without abandoned C++ locks or destructors, unless the guard-page re-arm in `[B-20]` fails. The backend must retain no host object pointer.

A guarded read followed by a guarded store is not equivalent: a foreign writer that displaces the word between the two is silently overwritten. Carry the expected value into one instruction. When the observed word differs from the expected value, reject the exchange. Refuse an unaligned word rather than split-lock it, since alignment is what makes the exchange atomic. These checks are unconditional and independent of policy options.

A swap of foreign access for an owned snapshot moves the trap rather than removes it. Any fact derived BEFORE the capture (a slot count, a size, an offset) describes different memory than the backend acts on. Even a re-walk of captured pointer words is insufficient when the backend re-queries mutable metadata, such as the target pages' execute permission. `Impl::method_count` is the worked example. It is the only bound between a caller's index and `VmHook`'s unchecked slot write. A count larger than SafetyHook's allocation therefore corrupts an adjacent RWX allocation without a fault. Demote the pre-capture walk to a capture budget, and derive the published count from captured words. Normalize the backend surrogate's counted run to a DMK-owned executable marker, so its allocation has exactly that count. Then copy the captured targets into the detached clone before publication. More generally, validate the backend's complete footprint, or replace its foreign access with an owned snapshot or guarded transaction. C++ `try/catch` does not contain a foreign SEH fault.

A page classification taken outside the process coordinator carries the same trap. A backend trap window holds a method page at `PAGE_READWRITE`, so a slot walk inside that window ends early and the clone is truncated. `vmt_for` therefore holds the coordinator across the walk and the clone, and refuses the create with `BackendFailed` when the coordinator is unavailable. `HookBackendTrapWindow.VmtForWaitsForTheBackendTrapWindow` pins the exclusion. `detail::BackendCoordinatorHold` (`src/internal/hook_coordinator.hpp`) gives translation units outside the hook island the same hold, which `[B-18]` uses for protection transactions.

`hook_method` allocates its map node and records the original slot pointer before the backend stores the slot. No allocation failure then sits over a live detour, and `original()` resolves from the instant the slot changes. `VmtHookFaultProof.MethodMapNodeAllocatesBeforeSlotStore` pins the order.

### [B-81]

The record exists only while the target and trampoline pages are temporarily non-executable during one patch transaction. While that transaction is active, an execute fault elsewhere on either affected page must retry until protection returns. A continued exception search exposes an artificial backend-created fault to the host. After every success or failure path, remove the record before the return. Otherwise later reuse of the same virtual address turns an unrelated fault into an infinite retry loop.

The transaction thread must not execute other code on either affected page before the restore, because that thread then retries its own fault forever. The backend refuses a multi-byte window that covers its own transaction code. Its test seams do not use MinGW emulated TLS, because each emulated access calls kernel32. `Lifecycle.RouteCopiesToggleOnTlsLookupPage` and `EmitPathHasNoEmulatedTls` verify the TLS part.

Query and protection failures must return a status, restore only the protections acquired, and never run the patch callback after a failed acquisition. DMK still independently witnesses target bytes before it publishes Active or Disabled state.

### [B-83]

`inline_at`, `mid_at`, and `install_all` return disabled hooks. Publish the handle and callback context before the `Hook::enable()` call. A byte witness verifies the arm. A rejected witness publishes `Disabled` only when the compensating disable leaves the prologue witnessed original. If that rollback cannot prove it, the handle stays truthfully active and returns `DisableFailed`. This rule is specific to the inline/mid transaction: `hook::vmt_for` is intentionally live on creation and has no `enable()` step. It stays safe by construction because it publishes the real object's vptr last, after the private clone is fully built. No window exists where a caller can observe a half-published clone.

### [B-84]

A throw can cross generated code that does publish valid records, and the routed gateway, wrappers, and exit thunk are exactly that case. A native exception raised in a routed destination is required to reach its caller's handler. Windows x64 unwinds a frame with no registered `RUNTIME_FUNCTION` as a leaf. An escaping throw then walks garbage and terminates the host instead of a report.

Code that DMK's backend generates, and that a destination call can raise through, registers its records before the route can be published. That code (the routed gateway, wrappers, and exit thunk) never modifies RSP anywhere its records do not describe. The gateway and exit save with `push rbx; pushfq`, restore with `popfq; pop rbx`, and then jump or return. Both intercepted RFLAGS and callback-written RFLAGS therefore survive, while the final pop/jump or pop/ret remains a recognized epilogue. Each wrapper uses the ordinary fixed `sub rsp, 40` / `add rsp, 40` frame. Registration failure fails the create. Failed unregistration conservatively retains the referenced storage. A published route keeps its code and records together until the idle proof at teardown withdraws both ("Clean x64 mid teardown"). A chain that fails the proof keeps both for the process lifetime.

Generated code that adjusts RSP dynamically cannot be described this way (SafetyHook's mid stub), so a throw must still never reach it. A DMK-managed callback adapter must preserve the exact backend signature, contain every user exception, and own an enter/recheck/leave rundown. It reaches the user callback from a real DMK frame, which is the only place containment and in-flight accounting can live. The backend signature carries no user-data parameter, so each mid hook takes a distinct adapter function from a fixed pool to carry its identity.

DMK cannot wrap a raw arbitrary-signature detour (`hook::inline_at(request, detour)`) that way, because `detail::inline_at_raw` receives it as an erased `void *` without the target's signature. It carries a documented no-throw contract and caller-owned quiescence instead. Document that requirement rather than encode it as a `noexcept` function type. The header already accepts ordinary function pointers, so the tightened type is a compatibility break. The counted `hook::inline_at<Detour>` keeps the signature, so it requires a `noexcept` detour and counts its calls (`[B-106]`).

### [B-85]

Flip the allocation-free tombstone before any teardown decision. Off loader lock, drain callbacks committed before the tombstone on every branch. Destroy the backend only after physical entry stops and every adapter body leaves. For teardown inside the hook's own callback or a displaced callee, retain the resources without a wait.

Every later branch preserves the tombstone, even when it retains the backend. The second live check rejects later callback entries. A timeout is not a drain. `Lifecycle.PublishedMidRouteReclaimsUnlessParked` verifies the displaced-callee case.

### [B-89]

A detour, subclass, or worker becomes reachable the instant it is published. From then on, teardown can find a host thread inside it that a bounded drain cannot evict. The only memory-safe response is retention, so the resources retention needs must already be held when publication happens. Those are:

- the counted module reference on the code,
- the counted reference on any foreign module whose bytes were patched,
- the storage that the retained objects will live in.

Acquisition at teardown is not equivalent. Teardown is exactly the moment the process can be out of memory or unable to reference a module. The fallback branch that discovers this has only one move left: free the trampoline a live thread runs through. Fail the install instead when a prerequisite cannot be taken. The caller retries. A drained teardown releases the pair it took, so install/uninstall cycles stay balanced. The balance itself is a permanent gate rather than an OS-refcount assertion that the host can invalidate with a pinned DLL.

### [B-97]

The backend commits its mutation inside a thread-trapping transaction that can still fail or throw during cleanup. A failure can therefore sit over a live patch or a completed restore. `Hook::enable`, `Hook::disable`, rollback, and `~Hook` contain backend exceptions and then classify the patch window as `Original`, exact `OwnedPatch`, `Foreign`, or `Indeterminate`. `OwnedPatch` requires persistent provenance that the backend completed its emitted-byte capture. A pre-sized or default-filled buffer is not evidence.

Never short-circuit the witness on a backend failure. A committed restore makes the target unable to enter this hook and authorizes backend destruction, while a committed exact patch publishes `Active` with `BackendFailed`. Destruction frees a previously published x64 routed chain only after the idle proof ("Clean x64 mid teardown"). A retained chain stays capacity-accounted and is independent of the byte witness.

A committed restore followed by `Foreign` or `Indeterminate` remains conservatively `Active` with `DisableFailed`. A newer layer can chain through the trampoline, and unreadable bytes prove no absence. Reassert the backend's retained state before that publication, so `is_enabled()` and a later owned-patch retry agree. Conversely, `Original` clears a stale backend flag before backend destruction, so a contained exception is never retried from SafetyHook's noexcept destructor. Both toggles write unconditionally, so neither runs over `Foreign` or `Indeterminate`. An Active hook bypasses in place of that write (`[B-104]`), and a restored hook refuses.

An idempotent toggle accepts only the witness its published state claims. Active requires exact `OwnedPatch`. Disabled requires `Original`, except for a bypassed hook, whose patch stays in the chain. The opposite exact witness proves external byte drift. The toggle rewrites state, population, gate callable, and backend flag before the ordinary transition. `Foreign` and `Indeterminate` remain refusals.

The internal rewrite emits no event, while the completed transition emits one. `HookBackendOwnership.IdempotentEnableReconcilesOriginal` and `HookBackendOwnership.IdempotentDisableReconcilesOwnedPatch` verify both polarities.

The vendored patch makes the backend's enabled flag change at the byte-mutation callback, supports witness-backed reconciliation, and preserves patch provenance across disable/re-enable (see `[B-01]`). A re-pin that drops any of those properties silently re-opens this class.

### [B-104]

A non-routed x64 hook writes `E9 rel32`, or a far `FF 25` jump, at the target. Both land on the relay at the end of its trampoline: `jmp qword ptr [rip+disp32]` over an 8-aligned slot that holds the detour. A newer layer relocates the lower jump to the same absolute relay, so every path into the lower detour crosses that slot. A retirement stores the trampoline start into the slot with one `seq_cst` store. The chain then runs the newer layer, the lower relay, the lower trampoline, and the rest of the target. That path holds jumps only, so the caller frame, the return address, and the unwind state stay unchanged.

The store needs no trap, no protection change, and no instruction-cache flush, because the relay reads the slot as data. A thread at the relay reads either the old detour or the trampoline start, and both stay mapped. A mid or routed layer closes its route in place of the store. The bypass is correct under a newer layer that chains and under a hijack that does not chain. The byte witness therefore does not have to tell the two apart.

`~Hook` of a layer that cannot restore drains a mid route while it is CLOSING, then switches off and vacates its position (`[B-105]`). The residue keeps its ledger creation-order entry and books `LeakSubsystem::HookResidue` once. After the switch, no new call enters its detour, so it releases its module reference (`[B-44]`). A counted detour drains before that point (`[B-106]`). A thread already inside a raw detour stays under caller-owned quiescence, as for a top restore.

An unclaimed layer that exceeds the residue budget of the `~Hook` contract keeps the pin and books `HookManager`. A full registry fails every inline and mid create that claims no Vacant position, in every copy, so the guard stops a reload loop first. A claimed layer skips the guard, because its vacate adds no position. The `~Hook` contract lists every other cause that keeps the pin.

### [B-105]

A position claim keeps the chain depth constant across reloads. Without it, each lower retirement leaves a position and each successor stacks a new one, so alternate reloads of two copies reach the residue budget. The claim is memory-safe for these reasons:

- A thread at a relay reads one aligned word. Every value stored there is mapped code: the trampoline start, the old detour before the bypass, or the new detour.
- Nobody frees a Vacant cell or removes its record. The creator object is inert, the claimant holds an unowned view, and the creator allocator is never destroyed.
- A mid or routed cell turns Vacant only after its route drained while CLOSING, so no thread reads the route word during a claim.
- An inline cell turns Vacant after the switch store. A counted detour drained before it (`[B-106]`), and a thread still inside a raw detour stays under caller-owned quiescence (`[B-104]`). The claim writes no relay slot, and the slot keeps the trampoline start until the claimed hook enables.
- The record range covers the whole trampoline allocation, so a live record locates its cell. A read inside that range under the coordinator needs no fault guard.
- Vacate and claim write no record field, so `top()` and `dependencies()` answer as they do for any residue.

The target-window check refuses a cell whose target is back at its original bytes, because no chain reaches that position. A claim keeps the chain position. Under a layer that does not chain, the successor stays unreachable, as its predecessor was. A claimed cell can sit below an unclaimed hook that the same copy created earlier. The ledger counts the claimed hook as newer, so the unclaimed hook vacates in place of a restore, and its own successor claims it.

A change to the cell format must bump `RELAY_CELL_LAYOUT`, because a reader claims only a layout that it implements. `HookBackendRelayCell.SealRejectsALegacyTrampoline` verifies that a trampoline without a sealed cell stays an opaque layer.

### [B-106]

A raw detour leaves quiescence to the caller, and a caller counter misses a thread that passed the relay before its own entry. The counted form puts a DMK thunk between the relay and the detour. The thunk lives in the consumer image and runs on the stack of the game caller. The detour therefore sees the stack arguments of the caller, and `CallerFrame` names the return slot. The thunk increments a striped enter count, calls the detour through a volatile pointer, and then increments an exit count. Each increment is a `seq_cst` locked add (`[B-43]`).

The drain proof runs after the relay sends every caller past the thunk. No thread enters the thunk after that store, so the stale entrants form a fixed set that only moves forward. One observation of each thread per pass therefore suffices, and a pass observes every thread at one instant (`[B-107]`):

- Pass 1 sees each stale entrant before its enter count, because its instruction pointer lies in the thunk.
- Equal sums of exits read before enters prove an instant at which no counted call sat between enter and exit.
- Pass 2 sees a thread that still runs the tail after its exit count.
- A call that waits in a dormant fiber keeps the sums unequal, so the result is Busy, never an unmap.
- Neither pass reads a saved thread context. A special user APC or an exception that interrupts uncounted thunk code therefore escapes the proof until the thread resumes. Only a tool that interrupts game threads at an arbitrary instruction can cause that.

The proof holds only for straight-line thunk code inside one unchained `RUNTIME_FUNCTION`. The install therefore decodes the thunk and refuses a branch, a trap, or a shape without exactly two locked increments around a call. An unoptimized consumer build can call a runtime-check helper outside the counted window. The decode records the return of each such call, so the passes also read thread stacks for it. A stale stack word equal to such a return keeps the result Busy, and the install logs a warning for such a thunk. `CallerFrame` holds one pointer, because `/RTC1` checks a 16-byte frame temporary with a helper call after the exit count.

`~Hook` runs the same proof with the 1 s route bound and keeps the pin on expiry. `HookStack::retire` switches every relay off first and then proves the counted detours. It then drains each mid route alone while it is CLOSING, so a callback of one route can still call through another. The commit runs last, which keeps a Busy or Refused result transactional. The commit runs no second counted drain, and one pass proves its restored trampolines (`[B-107]`). `HookCounted.*` and `HookStackTest.Retire*` prove the rule.

### [B-107]

A thread snapshot lists every thread of the machine, so its cost follows the machine, not the game. The pass therefore opens only the threads of this process through `NtGetNextThread`. That export is undocumented, so the backend resolves it at run time and walks the snapshot when the export is absent. The walk opens each thread with `THREAD_QUERY_LIMITED_INFORMATION`, because `GetThreadId` needs it to skip the current thread. Without it the pass suspends its own thread. The walk also returns a thread that exited while a handle stays open, so a failed suspension on a signaled handle skips that thread.

A thread that waits for a core runs its suspension and context requests only when it gets one. With every core busy, one suspension at a time therefore costs about one scheduler quantum per thread. The pass suspends every other thread before its first read instead, so each stopped thread gives up its core at once. Nothing allocates, takes a lock, or calls back until the resume, because a stopped thread can hold the heap lock. The process stops for the length of one pass, 8 to 25 ms with 166 threads on the measured host.

`HookStack::retire` runs two passes for its counted drain and one for its restored trampolines, so the count does not grow with its inline hooks. The commit tears each counted hook down with no drain of its own, because the retire drain covered it and its relay stayed off. Each restored trampoline then waits for one pass over all of them. No thread can enter a restored trampoline, and a layer installed after the restore relocates the restored bytes, so it never reaches one.

A restored hook that shares its patch window with another record frees its trampoline at once. A live record of a restored layer refuses the restore of every older layer on the window. Each mid hook keeps the two passes of its published route, and a refused route proof repeats (`[B-108]`). A refused pass falls back to the proof of each hook, so every outcome, leak bucket, and module reference matches the proof of one hook. `HookBackendIdleProof.*`, `HookStackTest.RetireRunsNoRepeatedCountedDrain`, `HookStackTest.RetireRunsAConstantNumberOfIdlePasses`, and `HookStackTest.RetireBatchProofFallsBackPerHook` prove the rule.

### [B-108]

A mid hook reaches image code only through its stub, which calls the DMK adapter and the callback. Only the LIVE gateway path jumps to the stub. A closed route sends each entrant to the trampoline, which runs relocated target code and continuation exits back to the target. A retained chain with an unreachable stub therefore reaches no image code, as a raw residue does (`[B-44]`).

A caller holds a route entry from its gateway increment until it leaves the stub. An entrant increments before it reads the state. A zero entry read while the route is not LIVE therefore proves that no thread is in the stub. No thread can enter the stub until the next LIVE store. `observe_route_entries()` records such a read with the count of LIVE stores, so a later LIVE store ends the proof. Both DMK route drains read through it.

`MidHook` frees its stub when the hook is disabled and either no caller holds an entry or the recorded read still holds. A thread that leaves an uncounted window after the drain takes a closed entry and runs the trampoline, so it never reaches the freed stub. `Hook` teardown retires a restored mid hook with a freed stub as `HookResidue`, when a thread scan or a held entry refused its proof. A failed restore, an unavailable coordinator, a dependent route, unwind records, and the owner lock keep the pin.

`HookStack::retire` defers a restored route that is alone on its patch window, as it defers a trampoline (`[B-107]`). No thread enters a restored route, and the threads inside it only move forward. The commit therefore repeats a refused route proof until the retire deadline, and an expired deadline leaves one attempt. Each refused pass records its first thread and check, and the pin or residue line names them after the threads resume. `HookBackendRelay.MidRouteEntryAfterTheIdleReadFreesTheStub`, `HookBackendIdleProof.RefusalNamesTheThreadAndTheCheck`, and `HookStackTest.RetireMid*` prove the rule.
