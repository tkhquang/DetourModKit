# Hook Type Coverage

DetourModKit ships three families of code-interception primitives -- inline, mid-function, and virtual-method-table. Inline and mid hooks use SafetyHook's live-patching backend; VMT hooks clone a table and swap object vptrs without touching `.text`. This guide states what those families cover, and, just as deliberately, which hook types DMK does not ship and why. The exclusions are scope decisions, not oversights: a missing primitive is one DMK judged not worth its distinct engineering and anti-detection surface for the target use case, which is redirecting internal game functions located by AOB / RTTI signatures on Win64.

## Contents

1. [Supported hook types](#1-supported-hook-types)
2. [The install model and its one honest limitation](#2-the-install-model-and-its-one-honest-limitation)
3. [Intentionally excluded hook types](#3-intentionally-excluded-hook-types)
4. [Reference frameworks and where DMK sits](#4-reference-frameworks-and-where-dmk-sits)
5. [If you need an excluded primitive](#5-if-you-need-an-excluded-primitive)
6. [Further reading](#6-further-reading)

---

## 1. Supported hook types

All four surfaces are declared in [`hook.hpp`](../../../include/DetourModKit/hook.hpp) and hand back a move-only RAII handle whose lifetime is the hook's lifetime (dropping the handle restores the target).

- **Inline** -- `hook::inline_at(request, detour)` returns a `Hook`. It rewrites the target function's prologue to a JMP into a trampoline and lets the detour call the original through the typed trampoline. `hook::install_all(table)` is the declarative batch form over the same mechanism.
- **Mid-function** -- `hook::mid_at(request, detour)` returns a `Hook`. It plants a JMP at an arbitrary instruction boundary into a detour that receives the captured CPU register / stack / XMM state through the opaque `hook::MidContext`, then resumes. Use it to observe or rewrite register state at a point that is not a function entry.
- **VMT, per object** -- `hook::vmt_for(name, object)` returns a `VmtHook`. It clones the object's virtual table and swaps the object's vptr to the clone, so no `.text` byte is touched; the original method bodies are unchanged and only virtual dispatch through that object is redirected.
- **VMT, per method** -- `VmtHook::hook_method<Fn>(index, detour)` rewrites individual virtual slots inside the clone; `original<Fn>(index)` snapshots the pre-hook slot; `remove_method(index)` restores the slot. See [VMT Hook Configuration](vmt-hook-config.md) for the full policy and index-counting rules.

Together these cover the two dominant interception needs in game modding: redirecting a concrete internal function (inline / mid) and redirecting virtual dispatch (VMT).

## 2. The install model and its one honest limitation

The inline and mid paths run on the SafetyHook backend, which guards every create and delete by removing execute access from the pages holding the target and trampoline bytes and letting a process-global vectored exception handler (registered on first use) fix up the instruction pointer of any thread that faults inside the region being rewritten -- no thread is suspended. This trap-plus-IP-fixup model is a correct one for installing and removing inline patches in a live process, achieving the same safety goal as the suspend-and-fixup discipline of Microsoft Detours and MinHook without stopping the world.

The honest limitation is worth stating so a consumer picks the right primitive for its threat model: an inline or mid hook writes a JMP into the target module's `.text`, which is a visible modification of the code section. A `.text`-integrity check (a checksum or CRC over the code pages, a common anti-cheat technique) can observe that change. A VMT hook touches no `.text` at all -- it changes only the object's vptr and a heap-allocated clone -- so it is invisible to a `.text` checksum, though a routine that validates an object's vptr or vtable contents can still see it. DMK does not attempt to hide either modification; anti-detection is out of scope (see section 3).

## 3. Intentionally excluded hook types

DMK does not ship the primitives below. Each is a deliberate scope decision: a distinct install / teardown path with its own thread-safety and detection story whose value does not clear the bar for DMK's target use case. Each is listed with the mechanism, the reason it is excluded, and where to find it if a mod genuinely needs it.

### 3.1 IAT / EAT redirection

The Import Address Table hook patches a module's import thunk so a call to an imported, cross-module function routes to a detour. The Export Address Table hook patches a module's export table so future symbol resolution (the loader, `GetProcAddress`) hands back a detour address.

Excluded because both intercept only calls that travel through the table. An IAT hook catches a call from module A into an imported function in module B, and only at the call sites that read the IAT entry; it cannot touch a function called directly within its own module or reached through an already-resolved pointer. DMK's targets are internal game functions located by AOB / RTTI signatures, which are exactly the calls that do not pass through any import thunk, so an IAT hook would never reach them. EAT additionally affects only resolutions performed after the patch, not call sites that already bound the address. For DMK's use case the inline and VMT primitives reach the same targets directly and unconditionally, so the import / export table indirection adds a surface with no matching capability.

### 3.2 Software breakpoint (INT3 + vectored exception handler)

Overwrite the target's first byte with `0xCC` (INT3). A vectored or structured exception handler catches the resulting breakpoint exception, runs the detour, restores the original byte, single-steps over it, and re-arms.

Excluded because it still modifies `.text` (one byte), so it buys no stealth over the inline JMP against a `.text`-integrity check, while adding an exception-handler round-trip and a single-step-then-re-arm race on every hit (the SafetyHook backend also registers a process-wide vectored handler, lazily on the first hook operation and left in place thereafter, but it is exercised only during install / teardown patch windows, never on a hit), and a direct conflict with any real debugger or anti-debug layer that owns the INT3 / `#BP` path. It trades the inline hook's clean trampoline for a slower, more fragile trap and adds no capability the inline path lacks.

### 3.3 Hardware breakpoint (debug registers + vectored exception handler)

Program a debug register (`DR0`-`DR3`) with the target address and an execute condition. The resulting debug exception (`#DB`) is caught by a vectored handler that runs the detour.

This is the one excluded primitive with a real capability the others lack: it modifies no code or data bytes, so it survives a `.text`-integrity checksum that would detect DMK's inline JMP. It is excluded anyway because it is strictly limited and belongs to a different problem than DMK solves. Only four addresses can be armed at once (four DR slots); the registers are per-thread, so every current and future game thread must be programmed and re-programmed, racing thread creation; the DR path collides with debuggers and with anti-cheat that watches or clears the debug registers; and the exception round-trip is far slower than a JMP. It is a specialized anti-detection tool, and DMK's scope is the correctness and host-safety of general interception rather than the anti-cheat-evasion arms race. A mod that specifically needs a code-invisible hook should reach for a framework built around it (section 4).

### 3.4 Non-modifying trace / dynamic binary instrumentation

A dynamic binary instrumentation (DBI) engine JIT-recompiles the target's instruction stream into an instrumented copy and runs the copy, leaving the original bytes untouched. That enables non-modifying tracing and per-instruction instrumentation with no patch to the target at all.

Excluded because it is a whole dynamic-recompilation runtime -- a code cache, a per-thread execution engine, and the overhead that comes with them -- an order of magnitude more machinery than a detour library. It is the deliberate ceiling DMK does not chase: DMK is a focused, statically-linked detour toolkit, not a DBI framework.

## 4. Reference frameworks and where DMK sits

- **PolyHook 2** is the near-term hook-breadth map. It presents inline, IAT, EAT, virtual-function swap, software-breakpoint, and hardware-breakpoint hooks under one `IHook` interface, so it is the reference for the primitives DMK does not ship (IAT / EAT in 3.1, the breakpoint hooks in 3.2 and 3.3). <https://github.com/stevemk14ebr/PolyHook_2_0>
- **Frida Stalker** is the DBI ceiling: per-thread dynamic recompilation for non-modifying tracing, the class of tool DMK deliberately does not become (3.4). <https://frida.re/docs/stalker/>

DMK's position is intentional. Rather than a broad menu of primitives, it offers a small, RAII, host-safe surface over the two interception needs that cover the large majority of internal-function game mods -- concrete-function (inline / mid) and virtual dispatch (VMT) -- and puts its differentiated engineering into fail-closed signature resolution and post-patch drift diffing instead of into hook breadth or anti-detection.

## 5. If you need an excluded primitive

Adding one of the excluded hook types is a deliberate change to DMK's product scope, not a bug fix, so it is a decision made on purpose rather than an omission to be patched over. For an immediate need, use a framework that already ships the primitive (PolyHook 2 for IAT / EAT or breakpoint hooks; a DBI engine such as Frida for non-modifying tracing) alongside DMK, which composes fine because DMK owns only the hooks it installs. The scope boundary is also recorded as a rule in [`AGENTS.md`](../../../AGENTS.md) so a contribution does not add one of these paths without that decision being made first.

## 6. Further reading

- [`hook.hpp`](../../../include/DetourModKit/hook.hpp): the `inline_at` / `mid_at` / `install_all` / `vmt_for` verbs and the `Hook` / `VmtHook` handles.
- [VMT Hook Configuration](vmt-hook-config.md): the VMT object and per-method surface and its pre-flight safety knobs.
