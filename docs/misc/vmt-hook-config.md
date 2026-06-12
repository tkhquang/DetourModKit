# VMT Hook Configuration Guide

Reference for `DetourModKit::VmtHookConfig` and the configurable VMT hook creation and apply overloads in [`hook_manager.hpp`](../../include/DetourModKit/hook_manager.hpp). Covers the operational policy knobs that mirror `HookConfig` for the inline path.

## Contents

1. [Why the VMT path needed a config struct](#1-why-the-vmt-path-needed-a-config-struct)
2. [`VmtHookConfig` fields](#2-vmthookconfig-fields)
3. [`fail_if_already_hooked` semantics](#3-fail_if_already_hooked-semantics)
4. [`fail_on_non_function_pointer` semantics](#4-fail_on_non_function_pointer-semantics)
5. [Backwards compatibility with the single-argument overloads](#5-backwards-compatibility-with-the-single-argument-overloads)
6. [Interaction with `apply_vmt_hook`](#6-interaction-with-apply_vmt_hook)
7. [Worked examples](#7-worked-examples)
8. [Further reading](#8-further-reading)

---

## 1. Why the VMT path needed a config struct

The inline hook path accepts a `HookConfig` that exposes `fail_if_already_hooked`. The pre-flight check rejects a target whose prologue already encodes a JMP outside the target's module, which is the canonical "another mod already hooked this" signal. The VMT path had no equivalent, so a second mod that called `create_vmt_hook` on an object whose vptr was already on a clone silently layered a second clone on top of the first, with no visible failure. The new `VmtHookConfig` closes that gap.

A second motivation is a defensive pre-flight against pathological VMT slot contents: an `int3` padding byte, a `__debugbreak` left by a debugging session, or a same-module jump stub. The pre-flight catches these at create/apply time instead of at the first dispatch through the cloned vtable.

## 2. `VmtHookConfig` fields

```cpp
struct VmtHookConfig
{
    bool fail_if_already_hooked = false;
    bool fail_on_non_function_pointer = false;
};
```

Both fields default to `false` to preserve the historical permissive semantics of the single-argument overloads: no pre-flight checks, while pre-existing failures (null object, duplicate name, shutdown in progress, SafetyHook errors) still apply. Opt in to the safety net on mods that exclusively target well-formed C++ vtables.

## 3. `fail_if_already_hooked` semantics

When `true`, `create_vmt_hook` (and `apply_vmt_hook`) checks the object's current vptr against the registry of cloned vtables owned by this `HookManager`. A match means "this object's vptr already points at a clone installed by us"; a second `create` would silently layer another clone on top of the first. The guard returns `HookError::HookAlreadyExists` for `create`; for `apply` it is a no-op success when the clone belongs to the named hook (the desired post-state already holds) and a `false` failure when the clone belongs to a different hook of this manager.

The detection is local to the `HookManager` instance. A VMT hook installed by another statically-linked DMK consumer in the same process is not visible to this check, exactly the same scoping rule as the inline hook's `is_target_already_hooked`.

Example:

```cpp
DetourModKit::VmtHookConfig cfg;
cfg.fail_if_already_hooked = true;
auto r1 = HookManager::get_instance().create_vmt_hook("MyClassVmt", object, cfg);
if (!r1)
{
    return r1.error();
}
auto r2 = HookManager::get_instance().create_vmt_hook("OtherNameVmt", object, cfg);
// likely HookError::HookAlreadyExists: object is already on the first clone.
```

## 4. `fail_on_non_function_pointer` semantics

When `true`, the create/apply path pre-flight-decodes the first byte of the original vtable slot and refuses to clone when the byte is:

- `0x00` (uninitialised page / zero-fill BSS / null page sentinel)
- `0xCC` (int3 breakpoint / alignment pad / debugger trap)
- `0xCD` (int)
- `0xC2`, `0xC3` (bare RET -- a stub, not a callable body)

If the first byte is `0xEB` (jmp rel8) or `0xE9` (jmp rel32), the decoder resolves the jump target through the existing `x86_decode` helpers and rejects the slot when the target is in the same module as the slot. A slot whose first instruction is a same-module jump is a jump stub (e.g. an incremental-link ILT entry or a patched slot), not a function body; MSVC adjustor thunks for multiple-inheritance vtables start with the this-adjust instruction and pass. Known false positive: consumer binaries built with `/INCREMENTAL` route every function through an ILT jump stub, which this check rejects. Real functions and tail-calls to a foreign module (`mov reg,reg; jmp <external>`) pass.

The decoder is allocation-free, no-throw, and uses `Memory::seh_read_bytes` for the single byte it needs. A slot whose first byte is unreadable fails the check (no proof of function).

The pre-flight decodes slot 0 only; `hook_vmt_method` does not re-check the slot it replaces.

The pre-flight is intentionally conservative: a real function whose first byte is `0x90` (NOP padding before a real prologue) passes the byte check, and a same-module thunk that happens to be a valid function (rare) is also accepted because the byte check passes the decoder.

## 5. Backwards compatibility with the single-argument overloads

The single-argument overloads are preserved as thin delegating wrappers around the configurable overloads:

```cpp
// Equivalent to the legacy call:
auto r = HookManager::get_instance().create_vmt_hook("MyVmt", object);
// is exactly:
auto r = HookManager::get_instance().create_vmt_hook("MyVmt", object, VmtHookConfig{});
```

Existing call sites that build a default `VmtHookConfig` or call the single-arg overloads compile and behave exactly as before. The defaults (`fail_if_already_hooked = false`, `fail_on_non_function_pointer = false`) match the historical permissive behavior.

## 6. Interaction with `apply_vmt_hook`

`apply_vmt_hook(name, object, cfg)` re-runs both checks against the vptr that is currently on the object:

- `fail_if_already_hooked` short-circuits with a debug log line and returns `true` when the object is already on the named hook's clone (the desired post-state already holds; the call is a no-op for SafetyHook's `VmtHook::apply`), and returns `false` with an error log when the object is on a clone owned by a different hook of this manager.
- `fail_on_non_function_pointer` decodes the first slot of the vtable currently on the object (the one about to be replaced) and refuses to install the cloned vptr on the object when the slot is not a real function pointer.

The `apply` overload's "no-op when already applied" is a deliberate difference from the `create` overload's "refuse with HookAlreadyExists". `create` is the path that establishes a clone; re-creating on the same vptr is always wrong. `apply` is the path that installs an existing clone on additional objects; calling it twice on the same object is a no-op the caller may legitimately want to express.

## 7. Worked examples

### Default policy (no change from before)

```cpp
DetourModKit::VmtHookConfig cfg; // both fields default to false
auto r = HookManager::get_instance().create_vmt_hook("MyVmt", object, cfg);
```

### Strict policy (refuse double-create, refuse non-function first slot)

```cpp
DetourModKit::VmtHookConfig cfg;
cfg.fail_if_already_hooked = true;
cfg.fail_on_non_function_pointer = true;
auto r = HookManager::get_instance().create_vmt_hook("MyVmt", object, cfg);
if (r)
{
    HookManager::get_instance().hook_vmt_method("MyVmt", method_index, &MyClass::detour);
}
```

### Apply with safety net (refuse non-function on a freshly-discovered object)

```cpp
DetourModKit::VmtHookConfig cfg;
cfg.fail_on_non_function_pointer = true;
for (auto *obj : candidate_objects)
{
    if (!HookManager::get_instance().apply_vmt_hook("MyVmt", obj, cfg))
    {
        // either the object is not yet on the clone (impossible here, we
        // are inside the same loop) or its vtable is pathological; skip it.
    }
}
```

## 8. Further reading

- [`hook_manager.hpp`](../../include/DetourModKit/hook_manager.hpp): `VmtHookConfig`, `create_vmt_hook`, `apply_vmt_hook`, `HookConfig` for the inline-side equivalent.
- `tests/test_hook_manager.cpp`: the `VmtHookConfig_*` tests pin the default-off behavior, the double-create guard, the pre-flight on `int3` slots, and the apply no-op.
- `safetyhook::VmtHook`: the underlying primitive; `VmtHook::apply` is the void function that performs the vptr swap, and `VmtHook::create` is the factory that clones the vtable.
