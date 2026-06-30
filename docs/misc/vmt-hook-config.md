# VMT Hook Configuration Guide

Reference for `DetourModKit::hook::VmtOptions` and the object-level VMT hook surface (`hook::vmt_for`, `VmtHook::apply_to`, `VmtHook::remove_from`) declared in [`hook.hpp`](../../include/DetourModKit/hook.hpp). Covers the operational policy knobs that mirror the inline path's `hook::Options`.

> **v4.0.0 note:** Per-method VMT hooking (a `hook_method<Fn>` layer) is deferred to a later VMT release. The object-level clone / apply / remove API and the `VmtOptions` knobs documented here ship in 4.0.0.

## Contents

1. [Why the VMT path needs a policy struct](#1-why-the-vmt-path-needs-a-policy-struct)
2. [`VmtOptions` fields](#2-vmtoptions-fields)
3. [`fail_if_already_hooked` semantics](#3-fail_if_already_hooked-semantics)
4. [`fail_on_non_function_pointer` semantics](#4-fail_on_non_function_pointer-semantics)
5. [Removal: dropping the handle vs `remove_from`](#5-removal-dropping-the-handle-vs-remove_from)
6. [Interaction with `apply_to`](#6-interaction-with-apply_to)
7. [Worked examples](#7-worked-examples)
8. [Further reading](#8-further-reading)

---

## 1. Why the VMT path needs a policy struct

The inline hook path accepts an `Options` that exposes `fail_if_already_hooked`. The pre-flight check rejects a target whose prologue already encodes a JMP outside the target's module, which is the canonical "another mod already hooked this" signal. The VMT path has the symmetric `VmtOptions`: without `fail_if_already_hooked`, a second mod that called `vmt_for` on an object whose vptr was already on a clone would silently layer a second clone on top of the first, with no visible failure.

A second motivation is a defensive pre-flight against pathological VMT slot contents: an `int3` padding byte, a `__debugbreak` left by a debugging session, or a same-module jump stub. The pre-flight catches these at create/apply time instead of at the first dispatch through the cloned vtable.

## 2. `VmtOptions` fields

```cpp
struct VmtOptions
{
    bool fail_if_already_hooked = false;
    bool fail_on_non_function_pointer = false;
};
```

Both fields default to `false` to keep the permissive baseline: no pre-flight checks, while pre-existing failures (null object, duplicate name, backend errors) still apply. Opt in to the safety net on mods that exclusively target well-formed C++ vtables. `vmt_for(name, object)` with the options argument omitted uses a default-constructed `VmtOptions{}` (both knobs off).

## 3. `fail_if_already_hooked` semantics

When `true`, `vmt_for` (and `VmtHook::apply_to`) checks the object's current vptr against the cloned vtables tracked by this kit. A match means "this object's vptr already points at a clone installed by us"; a second `vmt_for` would silently layer another clone on top of the first. The guard returns `ErrorCode::HookAlreadyExists` for `vmt_for`; for `apply_to` it is a no-op success when the clone belongs to the named hook (the desired post-state already holds) and a failure when the clone belongs to a different VMT hook of this kit.

The detection is local to this statically-linked DMK kit. A VMT hook installed by another DMK consumer in the same process is not visible to this check, exactly the same scoping rule as the inline hook's `is_target_hooked`.

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

When `true`, the create/apply path pre-flight-decodes the first byte of the original vtable slot and refuses to clone when the byte is:

- `0x00` (uninitialised page / zero-fill BSS / null page sentinel)
- `0xCC` (int3 breakpoint / alignment pad / debugger trap)
- `0xCD` (int)
- `0xC2`, `0xC3` (bare RET -- a stub, not a callable body)

If the first byte is `0xEB` (jmp rel8) or `0xE9` (jmp rel32), the decoder resolves the jump target and rejects the slot when the target is in the same module as the slot. A slot whose first instruction is a same-module jump is a jump stub (e.g. an incremental-link ILT entry or a patched slot), not a function body; MSVC adjustor thunks for multiple-inheritance vtables start with the this-adjust instruction and pass. Known false positive: consumer binaries built with `/INCREMENTAL` route every function through an ILT jump stub, which this check rejects. Real functions and tail-calls to a foreign module (`mov reg,reg; jmp <external>`) pass.

The decoder is allocation-free, no-throw, and uses the guarded memory read for the single byte it needs. A slot whose first byte is unreadable fails the check (no proof of function).

The pre-flight decodes slot 0 only.

The pre-flight is intentionally conservative: a real function whose first byte is `0x90` (NOP padding before a real prologue) passes the byte check, and a same-module thunk that happens to be a valid function (rare) is also accepted because the byte check passes the decoder.

## 5. Removal: dropping the handle vs `remove_from`

`vmt_for` returns a move-only RAII `VmtHook`. There are two ways to undo a VMT hook:

- **Drop the handle.** `~VmtHook` restores every applied vptr automatically. This is the normal teardown path: let the handle go out of scope (or `reset()` the owning `std::unique_ptr`).
- **`vh.remove_from(object)`** -> `Result<void>` restores a single object's vptr to its original vtable while keeping the `VmtHook` alive (and still applied to any other objects). Use this to detach one object early without tearing down the whole hook.

`vh.release()` detaches the handle: the clone stays installed for the process lifetime and the destructor no longer restores it. Use it only when you intend the VMT hook to outlive its owner.

## 6. Interaction with `apply_to`

`vh.apply_to(object, opts)` installs the existing clone on an additional object and re-runs both checks against the vptr currently on that object:

- `fail_if_already_hooked` short-circuits to a no-op success when the object is already on this hook's clone (the desired post-state already holds), and fails when the object is on a clone owned by a different VMT hook of this kit.
- `fail_on_non_function_pointer` decodes the first slot of the vtable currently on the object (the one about to be replaced) and refuses to install the cloned vptr when the slot is not a real function pointer.

`apply_to`'s "no-op when already applied" is a deliberate difference from `vmt_for`'s "refuse with HookAlreadyExists". `vmt_for` is the path that establishes a clone; re-creating on the same vptr is always wrong. `apply_to` is the path that installs an existing clone on additional objects; calling it twice on the same object is a no-op the caller may legitimately want to express.

## 7. Worked examples

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
    // Per-method VMT hooking is deferred (see the note at the top of this file);
    // the object-level clone is live as soon as vmt_for succeeds.
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
        // either already on the clone (no-op success would not reach here)
        // or its vtable is pathological; skip it.
    }
}
```

## 8. Further reading

- [`hook.hpp`](../../include/DetourModKit/hook.hpp): `VmtOptions`, `vmt_for`, `VmtHook::apply_to`, `VmtHook::remove_from`, and `Options` for the inline-side equivalent.
- `tests/test_hook.cpp`: the VMT tests pin the default-off behavior, the double-create guard, the pre-flight on `int3` slots, and the apply no-op.
