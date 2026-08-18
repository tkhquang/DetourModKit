# VMT Hook Configuration Guide

Reference for `DetourModKit::hook::VmtOptions`, the object-level VMT hook surface (`hook::vmt_for`, `VmtHook::apply_to`, `VmtHook::remove_from`), and the per-method typed surface (`VmtHook::hook_method`, `VmtHook::original`, `VmtHook::remove_method`) declared in [`hook.hpp`](../../../include/DetourModKit/hook.hpp). It covers the operational policy knobs that mirror the inline path's `hook::Options`.

## Contents

1. [Why the VMT path needs a policy struct](#1-why-the-vmt-path-needs-a-policy-struct)
2. [`VmtOptions` fields](#2-vmtoptions-fields)
3. [`fail_if_already_hooked` semantics](#3-fail_if_already_hooked-semantics)
4. [`fail_on_non_function_pointer` semantics](#4-fail_on_non_function_pointer-semantics)
5. [Removal: dropping the handle vs `remove_from`](#5-removal-dropping-the-handle-vs-remove_from)
6. [Interaction with `apply_to`](#6-interaction-with-apply_to)
7. [Per-method typed hooking](#7-per-method-typed-hooking)
8. [Worked examples](#8-worked-examples)
9. [Further reading](#9-further-reading)

---

## 1. Why the VMT path needs a policy struct

The inline hook path accepts an `Options` that exposes `fail_if_already_hooked`. The pre-flight check rejects a target whose prologue already encodes a JMP outside the target's module. That JMP is the canonical "another mod already hooked this" signal. The VMT path has the symmetric `VmtOptions`. Without `fail_if_already_hooked`, the permissive default proceeds rather than refuse. A second mod that called `vmt_for` on an object already on a clone therefore still layers a second clone on top of the first. The condition is no longer invisible. `vmt_for` and `apply_to` guard-read the current vptr. When it is a clone base owned by another VMT hook of this kit, they log a warning so the silent double-hook is diagnosable. Opt into `fail_if_already_hooked` to refuse it outright.

A second motivation is a defensive pre-flight against pathological VMT slot contents: an `int3` padding byte, a `__debugbreak` left by a debugging session, or a same-module jump stub. The pre-flight catches these at create or apply time instead of at the first dispatch through the cloned vtable.

Independently of `VmtOptions`, `vmt_for` guard-copies the callable slots and ABI RTTI prefix into a private snapshot. It derives the public method bound from the captured words and freezes SafetyHook's allocation count with a DMK-owned executable marker before it restores the captured targets into the detached clone. SafetyHook never retains the host object pointer. DMK publishes the clone with a fault-contained, alignment-checked atomic compare-exchange, so an unaligned object word, unreadable prefix, displacement, protection change, or unmap returns `InvalidObject` without abandonment of the VMT object gate. A foreign writer that replaces the captured vptr before publication keeps its newer value. The policy knobs only add the slot-0 checks above.

## 2. `VmtOptions` fields

```cpp
struct VmtOptions
{
    bool fail_if_already_hooked = false;
    bool fail_on_non_function_pointer = false;
};
```

Both fields default to `false`, and they do not disable memory safety checks. `vmt_for` and `apply_to` always reject an unreadable or non-writable object word, and their guarded publication fails closed if the mapping changes afterward. `vmt_for` also requires a readable RTTI prefix and at least one callable slot. `apply_to` installs an existing clone, so only `fail_on_non_function_pointer` inspects the displaced table. The knobs decide whether otherwise valid but suspicious inputs are refused.

A non-writable object word is reported, never acquired. DetourModKit does not `VirtualProtect` an object writable to force a clone onto it. The protection belongs to the object's owner, and a widening of it outlives the hook.

## 3. `fail_if_already_hooked` semantics

When `true`, `vmt_for` (and `VmtHook::apply_to`) checks the object's current vptr against the cloned vtables tracked by this kit. A match means this object's vptr already points at a clone installed by this kit, and a second `vmt_for` silently layers another clone on top of the first. The guard returns `ErrorCode::HookAlreadyExists` for `vmt_for`. For `apply_to` it fails when the clone belongs to a different VMT hook of this kit. An `apply_to` whose object this hook applied and left on the clone is a no-op success under every option value, because the desired post-state already holds. It is not a behavior of this knob. An object that carries this hook's clone but this hook never applied is refused under every option value too. See section 6.

The detection is local to this statically linked DMK kit. A VMT hook installed by another DMK consumer in the same process is not visible to this check, which is the same scoping rule as the inline hook's `is_target_hooked`.

Example:

```cpp
DetourModKit::hook::VmtOptions opts;
opts.fail_if_already_hooked = true;

auto r1 = DetourModKit::hook::vmt_for("MyClassVmt", object, opts);
if (!r1)
{
    return r1.error();
}

auto r2 = DetourModKit::hook::vmt_for("OtherNameVmt", object, opts);
// likely Error{ErrorCode::HookAlreadyExists}: object is already on the first clone.
```

## 4. `fail_on_non_function_pointer` semantics

When `true`, the create or apply path pre-flight-decodes the first byte of the original vtable slot and refuses to clone when the byte is:

- `0x00` (uninitialised page / zero-fill BSS / null page sentinel)
- `0xCC` (int3 breakpoint / alignment pad / debugger trap)
- `0xCD` (int)
- `0xC2`, `0xC3` (bare RET, a stub rather than a callable body)

If the first byte is `0xEB` (jmp rel8) or `0xE9` (jmp rel32), the decoder resolves the jump target and rejects the slot when the target is in the same module as the slot. A slot whose first instruction is a same-module jump is a jump stub (an incremental-link ILT entry or a patched slot, for example), not a function body. MSVC adjustor thunks for multiple-inheritance vtables start with the this-adjust instruction and pass. Known false positive: consumer binaries built with `/INCREMENTAL` route every function through an ILT jump stub, which this check rejects. Real functions and tail-calls to a foreign module (`mov reg,reg; jmp <external>`) pass.

The decoder is allocation-free and no-throw, and every read goes through the guarded memory read. The classification reads one byte. Resolution of an `0xEB` or `0xE9` jump target reads the opcode plus its full displacement (two or five bytes). A slot whose bytes are unreadable fails the check (no proof of function).

The pre-flight decodes slot 0 only.

The pre-flight is intentionally conservative. A real function whose first byte is `0x90` (NOP padding before a real prologue) passes the byte check. A same-module thunk that happens to be a valid function (rare) is also accepted, because the byte check passes the decoder.

## 5. Removal: dropping the handle vs `remove_from`

`vmt_for` returns a move-only RAII `VmtHook`. There are two ways to undo a VMT hook:

- **Drop the handle.** `~VmtHook` restores every applied vptr automatically. This is the normal teardown path: let the handle go out of scope, or `reset()` the owning `std::unique_ptr`.
- **`vh.remove_from(object)`** -> `Result<void>` restores a single object's vptr to its original vtable while it keeps the `VmtHook` alive (and still applied to any other objects). Use this to detach one object early without a teardown of the whole hook.

`vh.release()` detaches the handle. The clone stays installed for the process lifetime, and the destructor no longer restores it. Use it only when you intend the VMT hook to outlive its owner.

### Destroy stacked VMT hooks newest-first

When two hooks are layered on one object, the second clones the first's clone and records it as the table it will put back. Destruction newest-first unwinds that cleanly, and the object ends on its real vtable.

Destruction oldest-first cannot. The older hook's table is still the newer hook's recorded original, so a free of it leaves the newer hook to restore released memory, and the object dispatches through it. DetourModKit detects this at teardown. It restores other objects that still point directly at the older clone, leaks the outranked clone rather than free it, counts the leak on `diagnostics::LeakSubsystem::HookManager`, and logs a warning that names the hook. The stacked object then stays on the leaked clone. It still dispatches correctly, but it never returns to its original table. That is the deliberate trade: a permanent leak of one vtable-sized allocation instead of a use-after-free. Order your teardown to avoid it. The same rule and the same reasoning apply to stacked inline hooks on one target.

`remove_from` on an outranked object follows the same rule. It reports success but leaves the object on the newer hook's clone and keeps the restoration dependency. The object is restored later if the newer hook unwinds first. The clone is leaked if it does not.

## 6. Interaction with `apply_to`

`vh.apply_to(object, opts)` installs the existing clone on an additional object and re-runs both checks against the vptr currently on that object:

- `fail_if_already_hooked` fails when the object is on a clone owned by a different VMT hook of this kit. It does not decide the already-applied case: an object this hook applied and left on the clone is a no-op success under every option value.
- `fail_on_non_function_pointer` decodes the first slot of the vtable currently on the object (the one about to be replaced). It refuses to install the cloned vptr when the slot is not a real function pointer.

The `apply_to` "no-op when already applied" rule is a deliberate difference from the `vmt_for` "refuse with HookAlreadyExists" rule. `vmt_for` is the path that establishes a clone, and a re-create on the same vptr is always wrong. `apply_to` is the path that installs an existing clone on additional objects, and a second call on the same object is a no-op the caller can legitimately want to express.

Independently of the policy knobs, `apply_to` returns `HookAlreadyExists` whenever the hook cannot name the vptr it displaces. Two cases trip it. The object already carries this clone but was never applied through this handle. Or the object has since moved off the vptr this hook recorded for it, usually because a newer VMT hook layered on it. The check is on the recorded vptr, not on who moved it, so a foreign hooking library or the host itself trips it too. Both are refused under every `VmtOptions` value, because the hook restores from what it recorded. To admit either leaves it holding a vptr the object never had, and a write of that value at teardown is the use-after-free the newest-first rule above exists to avoid. Where the mover was a newer VMT hook, a re-install of the older clone over it also silently discards that hook's slots, because the older clone was copied before it existed.

## 7. Per-method typed hooking

`vmt_for` gives you the cloned vtable. Three handle methods redirect the individual virtual slots inside it:

```cpp
template <detail::FunctionPointer Fn> Result<void> VmtHook::hook_method(std::size_t index, Fn detour);
template <detail::FunctionPointer Fn> Fn           VmtHook::original(std::size_t index) const noexcept;
Result<void>                                VmtHook::remove_method(std::size_t index);
```

- **`hook_method<Fn>(index, detour)`** patches the vtable slot at `index` in the clone to `detour`. Because the redirect lives in the one clone, it fires on every object the clone is applied to, and on objects added later with `apply_to`. The function-to-`void*` cast happens once inside the template behind a word-size `static_assert`, so the call site never writes a `reinterpret_cast`. Errors: `InvalidHookState` (disengaged handle), `InvalidArg` (null detour or an out-of-range index), `MethodAlreadyHooked` (the slot is already hooked on this handle), `BackendFailed` / `OutOfMemory`.
- **`original<Fn>(index)`** returns the typed pre-hook function pointer for the slot, so the detour can call the original. It returns `nullptr` for an unhooked index or a disengaged handle.
- **`remove_method(index)`** rewrites the clone slot back to the original, which lifts one method hook while the clone stays applied. Errors: `InvalidHookState` (disengaged handle), `MethodNotFound` (the slot is not hooked).

**Index counting.** `index` is the zero-based position among *virtual functions*. The ABI vtable header (Itanium offset-to-top + RTTI pointers, or the MSVC RTTI locator) is not part of the index, and DetourModKit skips it internally. The vtable order otherwise follows the source, so the index depends on the class shape. In particular, destructor slots count only when the class has a *virtual destructor*. With one, the Itanium ABI (GCC / MinGW) places two destructor entries (complete + deleting) ahead of the first declared method and MSVC places one. A class whose first declared member after the destructor is `foo()` therefore reaches it at index 2 under Itanium and index 1 under MSVC. A class with *no* virtual destructor has no such prefix, and its first declared virtual method is index 0 on both ABIs. When the layout is not obvious, check the index against the target's real vtable rather than an assumption about the destructor offset.

**Detour ABI.** The detour is installed straight into a vtable slot, so its signature must match the virtual method's real ABI. The object pointer arrives as the first integer argument (`this` in `rcx` under the Win64 ABI), followed by the declared parameters. Win64 has a single calling convention, so a free function `Ret (*)(void* self, ...)` is the correct detour shape for both MSVC and MinGW, and no `__thiscall` decoration is needed. `hook_method` cannot validate that signature. A mismatch is silent ABI corruption, the same caveat `Hook::call` carries.

**Concurrency.** Object-vptr transitions in `vmt_for`, `apply_to`, `remove_from`, and handle teardown are serialized by a setup-time object gate, so duplicate create or apply checks and swaps are one ordered operation. `original` copies the pre-hook slot pointer out under a shared-read lock and returns it, and the detour then invokes that pointer lock-free. `hook_method`, `remove_method`, `apply_to`, and `remove_from` take the matching exclusive write, so a snapshot never observes a torn mutation. The lock guards the snapshot, not the call. The caller still owns the hook-outlives-the-call guarantee, exactly as with `Hook::original`. Install and remove method hooks during setup, not from inside a hooked method's detour.

```cpp
using ComputeFn = int (*)(void *self, int a, int b);

int detour_compute(void *self, int a, int b)
{
    // Reach the original through the handle, then adjust the result.
    return g_vmt->original<ComputeFn>(kComputeIndex)(self, a, b) + 1000;
}

auto r = DetourModKit::hook::vmt_for("MyVmt", object);
if (!r) { return r.error(); }
DetourModKit::hook::VmtHook vh = std::move(*r);
if (auto h = vh.hook_method(kComputeIndex, &detour_compute); !h) { return h.error(); }
g_vmt = &vh;                                        // publish AFTER the hook installs, for the detour to reach original()
// ... object->compute(...) now routes through detour_compute ...

// Teardown: g_vmt and vh must share a lifetime. Clear the published pointer BEFORE vh is destroyed so a late
// dispatch can never read a dangling handle. Keep both for the process, or drop them together; a scoped guard that
// nulls g_vmt on exit (like the tests' MethodVmtScope) makes this exception-safe.
g_vmt = nullptr;
// vh.remove_method(kComputeIndex);                // (optional) lift just this method; dropping vh restores everything
```

## 8. Worked examples

### Default policy

```cpp
auto r = DetourModKit::hook::vmt_for("MyVmt", object); // VmtOptions{} -- both knobs off
```

### Strict policy (refuse double-create, refuse non-function first slot)

```cpp
DetourModKit::hook::VmtOptions opts;
opts.fail_if_already_hooked = true;
opts.fail_on_non_function_pointer = true;

auto r = DetourModKit::hook::vmt_for("MyVmt", object, opts);
if (r)
{
    DetourModKit::hook::VmtHook vh = std::move(*r);
    // The clone is live as soon as vmt_for succeeds; redirect individual slots with
    // vh.hook_method<Fn>(index, detour) (see section 7).
}
```

### Apply with safety net (refuse non-function on a freshly-discovered object)

```cpp
auto seed = DetourModKit::hook::vmt_for("MyVmt", first_object, /* opts */ {});
if (!seed)
{
    return seed.error();
}
DetourModKit::hook::VmtHook vh = std::move(*seed);

DetourModKit::hook::VmtOptions opts;
opts.fail_on_non_function_pointer = true;
for (auto *obj : candidate_objects)
{
    if (!vh.apply_to(obj, opts))
    {
        // unreadable, non-writable, unaligned, or raced object word, or a non-function first slot; skip it.
    }
}
```

## 9. Further reading

- [`hook.hpp`](../../../include/DetourModKit/hook.hpp): `VmtOptions`, `vmt_for`, `VmtHook::apply_to`, `VmtHook::remove_from`, `VmtHook::hook_method`, `VmtHook::original`, `VmtHook::remove_method`, and `Options` for the inline-side equivalent.
- `tests/test_hook.cpp`: the `HookVmt` tests pin the default-off behavior, the double-create guard, the pre-flight on `int3` slots, and the apply no-op. The `HookVmtMethod` tests pin per-method redirect + `original`, duplicate-slot refusal, single-method removal, drop-restores-method, and the apply-inherits-the-method-hook case.
