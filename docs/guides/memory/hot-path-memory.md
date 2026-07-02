# Reading Game Memory in Hot Paths

This guide explains how to read and write game memory from code that runs at high frequency (per-frame render hooks, per-input-event detours, per-object apply loops) without paying the cost that the validation predicates carry. It is the reference for the guarded `memory::read` / `memory::write` / `memory::walk` primitives and the raw `memory::unchecked::read` fast path in [`memory.hpp`](../../../include/DetourModKit/memory.hpp) and explains when to use each one.

## The rule

> Do not put `memory::is_readable` or `memory::is_writable` in front of every
> dereference on a hot path. Read directly through a guarded `memory::read`,
> optionally pre-screened by a cheap arithmetic guard.

`is_readable` / `is_writable` exist for one-shot setup validation and diagnostics. They are correct there and cheap when called a handful of times. They are the wrong tool for a path that runs hundreds or thousands of times per frame.

## Why the predicate is the wrong tool on a hot path

`is_readable(Region{addr, size})` does two things that do not belong in a tight loop:

1. **It is not free, even on a cache hit.** A hit takes a per-shard reader lock and a cache lookup. A miss issues a `VirtualQuery` syscall and rebuilds the cache entry under an exclusive lock. When the addresses you check keep changing (a new game object each iteration), almost every lookup misses, so the cost is dominated by syscalls and lock traffic.

2. **It is a time-of-check to time-of-use illusion.** The page state it reports can change between the check returning `true` and your dereference. A pointer that passes the predicate can still fault, so you need a fault guard around the read anyway. Once the read is inside a fault guard, the predicate adds no safety, only cost.

Concretely: a hook that resolves an object and reads eight dependent fields off it across a few distinct (cache-missing) objects can cost one to two orders of magnitude more per call when each read is gated than when the reads run directly under one fault guard. The multiplier is dominated by `VirtualQuery` latency on cache misses, the cache-miss rate, and shard-lock contention, so it varies by CPU, Windows build, and address-space size. At a few hundred such calls per frame that is the difference between imperceptible and a multi-millisecond frame spike. Build with `-DDMK_BUILD_BENCHMARKS=ON`, run the `DetourModKit_bench_memory` target (Phase 6 of `tests/bench_memory.cpp`), and read the `probe_gated_over_direct` value to measure it on your target. Recorded numbers and methodology are in [the memory benchmark notes](../../analysis/memory_bench_v3.x/README.md).

## The pattern

Validate structure cheaply, read under one fault guard, sanity-check the result.

```cpp
namespace mem = DetourModKit::memory;
using DetourModKit::Address;

// Cheap, syscall-free structural guards. Capture the module range once so the
// per-call check is a branch comparison, not a GetModuleHandleEx lookup.
static const auto g_host = DetourModKit::Region::host();

bool probe_object(uintptr_t obj, ObjectFields &out) noexcept
{
    // 1. Reject obviously bad pointers with no memory access and no syscall.
    if (!mem::is_plausible_ptr(Address{obj}))
    {
        return false;
    }

    // 2. Read every field under the engine's fault guard. On MSVC this is one
    //    __try frame; on MinGW it uses the vectored fault guard. Either way a
    //    fault returns a Result error instead of crashing.
    const auto vtable = mem::read<uintptr_t>(Address{obj});
    if (!vtable || !g_host.contains(Address{*vtable}))
    {
        // 3. A live object's vtable points into the game image. A value that
        //    does not is a stale or reallocated pointer; reject it.
        return false;
    }

    const auto id = mem::read<uint32_t>(Address{obj}.offset(k_offId));
    if (!id)
    {
        return false;
    }

    out.vtable = *vtable;
    out.id = *id;
    return true;
}
```

For frame hooks, keep the hook body limited to cached state, branch-only guards, and one guarded read path. Resolve signatures, RTTI identities, and offsets outside the hook.

```cpp
namespace mem = DetourModKit::memory;
using DetourModKit::Address;

namespace
{
    std::atomic<std::uintptr_t> g_player_state{0};
    constexpr std::array<std::ptrdiff_t, 3> PLAYER_HEALTH_CHAIN{0x18, 0x30, 0x8};
}

void camera_update_hook(void *camera, float delta_time)
{
    const std::uintptr_t player_state = g_player_state.load(std::memory_order_relaxed);
    if (mem::is_plausible_ptr(Address{player_state}))
    {
        // Resolve the chain under one fault guard, then read the leaf.
        if (const auto slot = mem::walk(Address{player_state}, PLAYER_HEALTH_CHAIN))
        {
            if (const auto health = mem::read<float>(*slot))
            {
                apply_camera_rules(camera, *health);
            }
        }
    }

    original_camera_update(camera, delta_time);
}
```

For a multi-level pointer chain, resolve the whole chain under one fault guard with `walk` rather than reading link by link. The walk is one out-of-line call instead of N, gates each hop against its plausibility floor, and validates its arguments once. On failure it reports the failing hop index in `Error::detail`, so you can see how far the chain got. (It does not save SEH-frame setup: on MSVC/x64 a `__try` success path is table-driven and free, so N of them cost nothing extra either.)

```cpp
// Resolve (*(*(base + 0x10) + 0x28)) + 0x8 under one guard, then read a float.
if (const auto slot = mem::walk(Address{base}, std::array<std::ptrdiff_t, 3>{0x10, 0x28, 0x8}))
{
    if (const auto value = mem::read<float>(*slot))
    {
        use(*value);
    }
}
```

## Writing in hot paths

Writes follow the same rule as reads. A pointer the hook was handed is live by definition, so write through it directly (the anti-patterns below show why gating that write is pointless). But a value written through a *resolved* address -- a scanned base plus a pointer chain that can go stale between frames -- needs the same fault guard a read does, because the terminal slot can be unmapped the instant the chain is wrong.

There are two guarded write families, split by what should happen when the target is not already writable.

`memory::write_in_place<T>` / `memory::write_in_place(Address, std::span<const std::byte>)` is the per-frame data write. It is a guarded copy that changes **no** page protection and fails closed with `ErrorCode::WriteFaulted` if the target is not already writable. Use it for the common case, a value written every frame to memory the target keeps writable (a camera transform, a player field): it stays on the cheap no-`VirtualProtect` path, and if a stale or mistargeted chain drifts onto a read-only page it reports the fault instead of silently unprotecting and corrupting that page.

```cpp
namespace mem = DetourModKit::memory;
using DetourModKit::Address;

// Write a camera transform every frame through a resolved chain. Fault-guarded: a stale chain fails closed
// instead of faulting the host, and a slot that is not writable (the chain drifted onto a protected page) is
// rejected rather than reprotected.
const Matrix4x4 next = compute_camera(...);
if (const auto slot = mem::walk(Address{camera_base}, CAMERA_TRANSFORM_CHAIN))
{
    if (!mem::write_in_place<Matrix4x4>(*slot, next))
    {
        // Faulted or not writable this frame -- skip it, do not crash.
    }
}
// else: chain went stale this frame -- skip the write.
```

`memory::write<T>` / `memory::write_bytes` are the escalating write: they first try the same no-reprotect copy, then fall back to flipping protection (write, flush the instruction cache, restore) when that fast write faults because the page is read-only or executable. Reach for them when escalation is the intent, a one-shot CODE patch on a protected page, not for a per-frame data write where a non-writable target signals a bug you want surfaced rather than papered over.

When you repeatedly write to a page the target keeps protected, do not pay a protection flip per write. Hold a `memory::ProtectGuard` over the region for the lifetime of the loop: it makes the page writable once, so each `write_in_place` inside the guarded window sees a writable page and stays on the cheap path. The guard restores the original protection on scope exit. Note this is a DATA pattern: `write_in_place` does not flush the instruction cache, so to patch executable CODE use `write_bytes` (which flushes when it changes protection) rather than a guarded `write_in_place` loop.

```cpp
namespace mem = DetourModKit::memory;
using DetourModKit::Region;
using DetourModKit::Prot;

// Make a protected region writable once across the whole loop, so each per-frame write stays cheap instead of
// flipping protection every time.
auto guard = mem::ProtectGuard::make(Region{slot, sizeof(Matrix4x4)}, Prot::RW);
if (guard)
{
    while (running)
    {
        (void)mem::write_in_place<Matrix4x4>(slot, compute_camera(...)); // page already writable under the guard
    }
} // guard restores the original protection on scope exit
```

A one-shot CODE patch on a read-only / executable page is `memory::write_bytes`, which auto-unprotects on its own: change protection to writable, write, flush the instruction cache, restore protection, and invalidate the affected cache range. That is exactly what a code patch needs and exactly the overhead you do not want once per frame, which is why a per-frame writer uses `write_in_place` and a repeated writer to a protected page holds a `ProtectGuard`.

## Primitive selection

| You have | You want | Use |
|----------|----------|-----|
| A pointer the hook was handed (the engine is using it now) | To read or write it | Direct access. It is live by definition. Use a guarded `memory::read` only if it may be stale by the time you run. |
| A single address that may be stale or unmapped | One typed read that cannot fault | `memory::read<T>(Address{addr})` |
| A single address, a raw byte range | One range read that cannot fault | `memory::read_into(Address{addr}, std::span<std::byte>{...})` |
| A multi-level pointer chain | The final address only | `memory::walk(Address{base}, {offsets...})` |
| A multi-level pointer chain | A typed value at the end | `memory::walk(...)` then `memory::read<T>(*slot)` |
| A pointer you can prove is alive this frame | The fastest possible read, no syscall, no SEH | `memory::unchecked::read<T>(Address{...})` |
| A resolved address on a page the target keeps writable | A per-frame write that fails closed if the page is not writable (no reprotect) | `memory::write_in_place<T>(Address{addr}, value)` / `write_in_place(Address{addr}, span)` |
| A multi-level pointer chain | A guarded per-frame write at its terminal slot | `memory::walk(...)` then `memory::write_in_place<T>(*slot, value)` |
| To patch CODE on a read-only / executable page, or write and have protection changed for you | An auto-unprotecting write | `memory::write_bytes(Address{target}, span)` / `memory::write<T>(...)` -- changes protection on fault; the setup/patch case |
| To write a protected page repeatedly without flipping protection each time | A held page-protection guard | `memory::ProtectGuard::make(Region{...}, Prot::RW)` (hold it across the loop) |
| To screen a candidate pointer before any read | A pure arithmetic plausibility test | `memory::is_plausible_ptr(Address{p})` |
| To confirm a pointer lives in a known module | A branch-only range test | `Region::own().contains(Address{p})` (capture the range once) |
| To validate an address once at setup | A readability or writability check | `memory::is_readable(Region{...})` / `memory::is_writable(Region{...})` |

## Toolchain note

The guarded primitives use real `__try` / `__except` on MSVC, where the success path is table-driven and costs nothing extra. On MinGW (which has no frame-based SEH) a 64-bit build installs a process-wide vectored exception handler once and runs reads or writes through a guarded access path with no `VirtualQuery` on the success path, recovering a fault as a `Result` error instead of crashing. The Structured Exception Handling is confined entirely to the engine translation unit, so the installed `memory.hpp` pulls in no `<windows.h>` and no SEH. `init_cache` installs the MinGW vectored fault handler, so a guarded read never has to fall back to a per-call `VirtualQuery`. `memory::unchecked::read` is still the fastest choice when you can prove the pointer is live for the current frame; otherwise prefer the guarded `memory::read` / `memory::walk` for stale or unmapped pointers. Shipping mod builds target MSVC, so the zero-cost path is the normal case.

## Anti-patterns to remove

```cpp
// WRONG: predicate before every read on a hot path. Lock plus possible syscall
// per field, and the page can still change before the dereference.
if (mem::is_readable(Region{Address{addr}, sizeof(uint64_t)}))
{
    value = *reinterpret_cast<uint64_t *>(addr);
}

// WRONG: gating a write to a pointer the engine just wrote through. If the
// engine could write it, it is writable; the predicate adds a lock for nothing.
if (mem::is_writable(Region{Address{positionPtr}, sizeof(Vector3)}))
{
    *positionPtr = newPosition;
}

// WRONG: module_of in a loop. Every call is a loader lookup. Capture the range
// once and use Region::contains().
for (auto p : candidates)
{
    if (mem::module_of(Address{p}).size != 0)
    {
        ...
    }
}
```

```cpp
// RIGHT: capture the range once, screen cheaply, read under one guard.
static const auto host = DetourModKit::Region::host();
for (auto p : candidates)
{
    if (mem::is_plausible_ptr(Address{p}) && host.contains(Address{p}))
    {
        const auto v = mem::read<uint64_t>(Address{p});
        if (v)
        {
            use(*v);
        }
    }
}
```
