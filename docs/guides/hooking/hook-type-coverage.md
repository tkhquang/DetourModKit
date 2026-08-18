# Hook Type Coverage

DetourModKit ships three families of code-interception primitives: inline, mid-function, and virtual-method-table. Inline and mid hooks use SafetyHook's live-patching backend. VMT hooks clone a table and swap object vptrs without a `.text` write. This guide states what those families cover, which hook types DMK does not ship, and why. The exclusions are scope decisions, not oversights. A missing primitive is one DMK judged not worth its distinct engineering and anti-detection surface. The target use case is redirection of internal game functions located by AOB / RTTI signatures on Win64.

## Contents

1. [Supported hook types](#1-supported-hook-types)
2. [The install model and its one honest limitation](#2-the-install-model-and-its-one-honest-limitation)
3. [Intentionally excluded hook types](#3-intentionally-excluded-hook-types)
4. [Reference frameworks and where DMK sits](#4-reference-frameworks-and-where-dmk-sits)
5. [If you need an excluded primitive](#5-if-you-need-an-excluded-primitive)
6. [Further reading](#6-further-reading)

---

## 1. Supported hook types

All four surfaces are declared in [`hook.hpp`](../../../include/DetourModKit/hook.hpp). Each hands back a move-only RAII handle whose lifetime is the hook's lifetime: a dropped handle restores the target, unless the handle was released. `Hook::release()` and `VmtHook::release()` both disengage the handle and retain what it owned for the process lifetime. An armed inline or mid backend stays patched and keeps its dispatch live. A hook released while still disabled keeps its backend and its ledger record without an armed target. A released VMT clone stays applied with no vptr restored.

The handle's lifetime is the hook's lifetime, but a Logic-DLL detour adds a callback-provider lifetime on top. `mid_at` reaches its callback through a DetourModKit adapter. Ordinary off-loader-lock destruction from outside the callback refuses new entry and waits for admitted callbacks. A backend that stays patched after that rundown is inert. Loader-lock teardown, self-destruction, and an entrant the adapter did not record all tombstone without a wait, and `Hook::release()` bypasses the tombstone step. None of those paths authorizes immediate unmapping. `inline_at` has no adapter, because the detour *is* the target. Quiescence there is caller-owned: stop every thread that can reach the target, join it, destroy the handle, then unmap. The callback-only Logic-DLL hosts in [`tests/lifecycle/test_logic_dll_unload.cpp`](../../../tests/lifecycle/test_logic_dll_unload.cpp) prove the ordinary managed-mid and caller-quiesced inline paths.

The install step and the arm step are separate. `inline_at`, `mid_at`, and `install_all` return a hook whose target is untouched. `Hook::enable()` arms it. Publish the handle where the detour will look for it before you arm, because a detour typically reaches the original through the handle itself. A hook armed inside the install verb is reachable before that verb returns.

**Inline.** `hook::inline_at(request, detour)` returns a `Hook`. `Hook::enable()` then rewrites the target function's prologue to a JMP into a trampoline and lets the detour call the original through the typed trampoline. `hook::install_all(table)` is the declarative batch form over the same mechanism.

**Mid-function.** `hook::mid_at(request, detour)` returns a `Hook`. `Hook::enable()` then plants a JMP at an arbitrary instruction boundary into a detour that receives the captured CPU register / stack / XMM state through the opaque `hook::MidContext`, then resumes. Use it to observe or rewrite register state at a point that is not a function entry.

**VMT, per object.** `hook::vmt_for(name, object)` returns a `VmtHook`. It clones the object's virtual table and swaps the object's vptr to the clone. No `.text` byte is touched: the original method bodies are unchanged, and only virtual dispatch through that object is redirected.

**VMT, per method.** `VmtHook::hook_method<Fn>(index, detour)` rewrites individual virtual slots inside the clone. `original<Fn>(index)` snapshots the pre-hook slot. `remove_method(index)` restores the slot. See [VMT Hook Configuration](vmt-hook-config.md) for the full policy and index-counting rules.

Together these cover the two dominant interception needs in game modding: redirection of a concrete internal function (inline / mid) and redirection of virtual dispatch (VMT).

`inline_at` and `mid_at` require the target to be readable, committed, executable memory across the whole span the backend decodes. They refuse it with a typed `Error` otherwise, under every `Options::prologue` policy, because relocation of a prologue that is not code is never valid. A target that begins with a relative call is not refused by the pre-flight. Whether the backend can relocate it is left to the backend rather than guessed from its first byte, and only a breakpoint prologue is subject to `Options::prologue`. A target the backend cannot relocate fails with `ErrorCode::BackendFailed`. The backend distinguishes causes such as an undecodable instruction, an out-of-range relative operand, or a trampoline allocation failure. Callers receive the single generic code, and the specific reason is written to the log rather than returned.

The pre-flight also refuses a target whose unwind metadata declares a function too short for the backend's larger patch form. The backend picks the patch form after the pre-flight. The pre-flight therefore refuses a function that only the smaller form can hook, rather than risk a larger-form write over the code that follows it.

## 2. The install model and its one honest limitation

The inline and mid paths run on the SafetyHook backend. The backend guards every create and delete: it removes execute access from the pages that hold the target and trampoline bytes. A process-global vectored exception handler (registered on first use) fixes up the instruction pointer of any thread that faults inside the region under rewrite. No thread is suspended. This trap-plus-IP-fixup model is a correct one for install and removal of inline patches in a live process. It reaches the same safety goal as the suspend-and-fixup discipline of Microsoft Detours and MinHook without a stop of the world.

That patch transaction is not atomic with its own outcome, which is why DMK does not trust the backend's return value on its own. The bytes are written inside the trap window, and the transaction can still fail or throw afterwards during protection restore. A failure can therefore sit over a fully committed patch or restore. `Hook::enable`, `Hook::disable`, rollback, and `~Hook` contain backend exceptions, then read the patch window back and classify it as Original, exact OwnedPatch, Foreign, or Indeterminate. OwnedPatch additionally requires persistent provenance that the backend completed its emitted-byte capture. The backend's pre-sized zero buffer is not evidence, so a foreign zero-filled target before first enable is refused.

The classification decides what gets published:

- A hook whose exact patch committed under a failed transaction reports `is_enabled() == true` and returns `ErrorCode::BackendFailed`, never a false Disabled over a live detour.
- A committed restore publishes Disabled and closes the call gate.
- A committed restore followed by Foreign or Indeterminate remains conservatively Active with `DisableFailed`, because a newer layer can chain through its trampoline and unreadable bytes prove no absence. DMK reasserts the backend's retained state in that case, so `is_enabled()` remains true, and a restore of the exact OwnedPatch bytes permits a real retry.
- Original clears any stale backend flag before destruction and authorizes backend destruction. A published x64 mid hook still retains its routed gateway, inline trampoline, allocator backing, and unwind metadata for the process lifetime. Clean teardown reclaims only the mid stub and adapter portion.
- Foreign and Indeterminate are refused before either unconditional backend write, and teardown pins the whole backend.

Some routes dispatch through generated code rather than a straight jump to the destination:

- a gateway that counts the callers admitted before a teardown,
- a wrapper that calls the destination and decrements on return, and
- an exit thunk that a mid stub returns through.

Windows x64 has no frame pointer to fall back on. The backend therefore registers `RUNTIME_FUNCTION` and `UNWIND_INFO` records for those three regions before it publishes the route. The gateway and exit use a flag-transparent `push rbx; pushfq` frame and restore with `popfq; pop rbx` before their jump or return. The wrapper uses a fixed 40-byte frame. A native exception raised inside a routed destination therefore unwinds correctly. A stack walk taken while a thread sits in any generated region reports the real caller. Mid-hook callbacks can observe and replace the intercepted arithmetic flags. Registration failure fails the create. A failed unregistration conservatively retains the referenced arena. Publication makes the code and its records process-lifetime storage together. A thread that faults in a retained route after its handle is gone still finds its records. SafetyHook's dynamic-RSP mid stub is the one exception: it is not described, which is why a mid-hook callback must not let an exception escape.

Routes are never reclaimed once published, so the storage they retain is bounded rather than unlimited. Each route uses an isolated allocator arena. The backend counts the whole retained chain both as requested logical bytes and as the complete allocator blocks that back those requests. The chain is the gateway and its unwind records, the trampoline, and the optional mid stub. Separate reserved, charged, capacity, and monotonic high-water totals bound both dimensions. A complete x64 mid chain has a compile-proved 1,024-byte logical slot and at most three allocation-granularity blocks. Creation reserves that worst case before publication. Publication charges the actual chain and refunds the remainder. Never-published destruction releases the slot. Public `mid_at` obtains that reservation automatically. XInput interception explicitly reserves two credits before either pair member can publish. A ceiling that cannot hold both installs nothing rather than strand primary-only coverage.

Gamepad interception treats the primary `XInputGetState` export and every distinct ordinal-100 `XInputGetStateEx` target as one coverage transaction. Both hooks are created disabled before either prologue is patched, so a creation failure rolls the pair back and leaves both entries open. A proxy-forwarded ordinal target receives its own pre-acquired module keepalive before either hook is published. An absent or aliased ordinal-100 export is complete coverage, because there is no second entry point to mask.

Coverage is decided by a final witness rather than by the arm transactions that preceded it. Immediately before the store that makes suppression possible, both prologues are read back, and a member whose owned patch is gone degrades the pair. That closes the window where a competing writer restores one export during the arm of the other. A per-arm verdict alone reports that case as success while the restored entry point bypasses the layer entirely. Health maintenance then repeats the same witness every poll cycle rather than short-circuit on the published flag. An export handed back long after publication therefore degrades the pair rather than stay hidden behind it.

Degradation is symmetric and fails open. Whichever member is missing, suppression stops on both entries and both detours pass through unchanged. The game never loses a button on one entry point while it keeps it on another. Both forwarding chains stay published, because a caller admitted before the loss still has to reach one. Recovery re-arms the missing member (primary or ordinal-100, live storage or retained) through that member's own existing hook object, never through a new hook layered over a prologue the pair already patched. It republishes only after the final witness passes again. Each failed re-arm grows a delay toward a cap and never stops the retry loop. A change of target module, layer owner, or either export's own bytes resets the delay, so the next attempt is immediate.

One honest limitation decides which primitive fits a given threat model. An inline or mid hook writes a JMP into the target module's `.text`, which is a visible modification of the code section. A `.text`-integrity check (a checksum or CRC over the code pages, a common anti-cheat technique) can observe that change. A VMT hook touches no `.text` at all. It changes only the object's vptr and a heap-allocated clone, so it is invisible to a `.text` checksum. A routine that validates an object's vptr or vtable contents can still see it. DMK does not attempt to hide either modification. Anti-detection is out of scope (see section 3).

## 3. Intentionally excluded hook types

DMK does not ship the primitives below. Each is a deliberate scope decision. Each excluded type is a distinct install / teardown path with its own thread-safety and detection story, and that story's value does not clear the bar for DMK's target use case. Each entry states the mechanism, the reason for the exclusion, and where to find it if a mod genuinely needs it.

### 3.1 IAT / EAT redirection

The Import Address Table hook patches a module's import thunk so a call to an imported, cross-module function routes to a detour. The Export Address Table hook patches a module's export table so future symbol resolution (the loader, `GetProcAddress`) hands back a detour address.

Both are excluded because they intercept only calls that travel through the table. An IAT hook catches a call from module A into an imported function in module B, and only at the call sites that read the IAT entry. It cannot touch a function called directly within its own module or reached through an already-resolved pointer. DMK's targets are internal game functions located by AOB / RTTI signatures. Those are exactly the calls that do not pass through any import thunk, so an IAT hook never reaches them. EAT additionally affects only resolutions performed after the patch, not call sites that already bound the address. For DMK's use case the inline and VMT primitives reach the same targets directly and unconditionally. The import / export table indirection therefore adds a surface with no matching capability.

### 3.2 Software breakpoint (INT3 + vectored exception handler)

Overwrite the target's first byte with `0xCC` (INT3). A vectored or structured exception handler catches the resulting breakpoint exception, runs the detour, restores the original byte, single-steps over it, and re-arms.

The INT3 hook is excluded because it still modifies `.text` (one byte), so it buys no stealth over the inline JMP against a `.text`-integrity check. It adds an exception-handler round trip and a single-step-then-re-arm race on every hit. It also conflicts directly with any real debugger or anti-debug layer that owns the INT3 / `#BP` path. The SafetyHook backend does register a process-wide vectored handler, but lazily and only for install and teardown patch windows. That handler is removed when the process-wide manager shuts down and is never on the hit path. The INT3 hook trades the inline hook's clean trampoline for a slower, more fragile trap and adds no capability the inline path lacks.

### 3.3 Hardware breakpoint (debug registers + vectored exception handler)

Program a debug register (`DR0`-`DR3`) with the target address and an execute condition. A vectored handler catches the resulting debug exception (`#DB`) and runs the detour.

This is the one excluded primitive with a real capability the others lack. It modifies no code or data bytes, so it survives a `.text`-integrity checksum that detects DMK's inline JMP. It is excluded anyway because it is strictly limited and belongs to a different problem than DMK solves. Only four addresses can be armed at once (four DR slots). The registers are per-thread, so every current and future game thread must be programmed and re-programmed, and that races thread creation. The DR path collides with debuggers and with anti-cheat that watches or clears the debug registers. The exception round trip is far slower than a JMP. It is a specialized anti-detection tool, and DMK's scope is the correctness and host-safety of general interception rather than the anti-cheat-evasion arms race. A mod that specifically needs a code-invisible hook can use a framework built around it (section 4).

### 3.4 Non-modifying trace / dynamic binary instrumentation

A dynamic binary instrumentation (DBI) engine JIT-recompiles the target's instruction stream into an instrumented copy and runs the copy. The original bytes stay untouched. That enables non-modifying tracing and per-instruction instrumentation with no patch to the target at all.

The DBI engine is excluded because it is a whole dynamic-recompilation runtime: a code cache, a per-thread execution engine, and the overhead that comes with them. That is an order of magnitude more machinery than a detour library. It is the deliberate ceiling DMK does not chase: DMK is a focused, statically linked detour toolkit, not a DBI framework.

## 4. Reference frameworks and where DMK sits

- **PolyHook 2** is the near-term hook-breadth map. It presents inline, IAT, EAT, virtual-function swap, software-breakpoint, and hardware-breakpoint hooks under one `IHook` interface. That makes it the reference for the primitives DMK does not ship (IAT / EAT in 3.1, the breakpoint hooks in 3.2 and 3.3). <https://github.com/stevemk14ebr/PolyHook_2_0>
- **Frida Stalker** is the DBI ceiling: per-thread dynamic recompilation for non-modifying tracing, the class of tool DMK deliberately does not become (3.4). <https://frida.re/docs/stalker/>

DMK's position is intentional. It does not offer a broad menu of primitives. It offers a small, RAII, host-safe surface over the two interception needs that cover the large majority of internal-function game mods: concrete-function (inline / mid) and virtual dispatch (VMT). Its differentiated engineering goes into fail-closed signature resolution and post-patch drift diffs instead of into hook breadth or anti-detection.

## 5. If you need an excluded primitive

One of the excluded hook types enters DMK only as a deliberate product-scope decision, never as a bug fix or a patched-over omission. For an immediate need, use a framework that already ships the primitive alongside DMK: PolyHook 2 for IAT / EAT or breakpoint hooks, or a DBI engine such as Frida for non-modifying tracing. That composes fine, because DMK owns only the hooks it installs. The scope boundary is also recorded as a rule in [`AGENTS.md`](../../../AGENTS.md), so a contribution does not add one of these paths before that decision is made.

## 6. Further reading

- [`hook.hpp`](../../../include/DetourModKit/hook.hpp): the `inline_at` / `mid_at` / `install_all` / `vmt_for` verbs and the `Hook` / `VmtHook` handles.
- [VMT Hook Configuration](vmt-hook-config.md): the VMT object and per-method surface and its pre-flight safety knobs.
