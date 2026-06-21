# Reading Game Memory in Hot Paths

This guide explains how to read and write game memory from code that runs at high frequency (per-frame render hooks, per-input-event detours, per-object apply loops) without paying the cost that the validation predicates carry. It is the reference for the `seh_*` and `read_ptr_*` primitives in [`memory.hpp`](../../include/DetourModKit/memory.hpp) and explains when to use each one.

## The rule

> Do not put `Memory::is_readable` or `Memory::is_writable` in front of every
> dereference on a hot path. Read directly under a single SEH frame, optionally
> pre-screened by a cheap arithmetic guard.

`is_readable` / `is_writable` exist for one-shot setup validation and diagnostics. They are correct there and cheap when called a handful of times. They are the wrong tool for a path that runs hundreds or thousands of times per frame.

## Why the predicate is the wrong tool on a hot path

`is_readable(addr, size)` does two things that do not belong in a tight loop:

1. **It is not free, even on a cache hit.** A hit takes a per-shard reader lock and a cache lookup. A miss issues a `VirtualQuery` syscall and rebuilds the cache entry under an exclusive lock. When the addresses you check keep changing (a new game object each iteration), almost every lookup misses, so the cost is dominated by syscalls and lock traffic.

2. **It is a time-of-check to time-of-use illusion.** The page state it reports can change between the check returning `true` and your dereference. A pointer that passes the predicate can still fault, so you need a fault guard around the read anyway. Once the read is inside a fault guard, the predicate adds no safety, only cost.

Concretely: a hook that resolves an object and reads eight dependent fields off it across a few distinct (cache-missing) objects can cost one to two orders of magnitude more per call when each read is gated than when the reads run directly under one fault guard. The multiplier is dominated by `VirtualQuery` latency on cache misses, the cache-miss rate, and shard-lock contention, so it varies by CPU, Windows build, and address-space size. At a few hundred such calls per frame that is the difference between imperceptible and a multi-millisecond frame spike. Build with `-DDMK_BUILD_BENCHMARKS=ON`, run the `DetourModKit_bench_memory` target (Phase 6 of `tests/bench_memory.cpp`), and read the `probe_gated_over_direct` value to measure it on your target. Recorded numbers and methodology are in [the memory benchmark notes](../analysis/memory_bench_v3.x/README.md).

## The pattern

Validate structure cheaply, read under one fault guard, sanity-check the result.

```cpp
namespace Mem = DetourModKit::Memory;

// Cheap, syscall-free structural guards. Capture the module range once so the
// per-call check is a branch comparison, not a GetModuleHandleEx lookup.
static const Mem::ModuleRange g_host = Mem::host_module_range();

bool probe_object(uintptr_t obj, ObjectFields &out) noexcept
{
    // 1. Reject obviously bad pointers with no memory access and no syscall.
    if (!Mem::plausible_userspace_ptr(obj))
    {
        return false;
    }

    // 2. Read every field under a single SEH-guarded chain walk. On MSVC this
    //    is one __try frame; on MinGW it uses the vectored fault guard. Either
    //    way a fault anywhere in the walk returns nullopt instead of crashing.
    const auto vtable = Mem::seh_read<uintptr_t>(obj);
    if (!vtable || !Mem::contains(g_host, *vtable))
    {
        // 3. A live object's vtable points into the game image. A value that
        //    does not is a stale or reallocated pointer; reject it.
        return false;
    }

    const auto id = Mem::seh_read<uint32_t>(obj + k_offId);
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
namespace Mem = DetourModKit::Memory;

namespace
{
    std::atomic<std::uintptr_t> g_player_state{0};
    constexpr std::array<std::ptrdiff_t, 3> PLAYER_HEALTH_CHAIN{0x18, 0x30, 0x8};
}

void camera_update_hook(void *camera, float delta_time)
{
    const std::uintptr_t player_state = g_player_state.load(std::memory_order_relaxed);
    if (Mem::plausible_userspace_ptr(player_state))
    {
        const auto health = Mem::seh_read_chain<float>(player_state, PLAYER_HEALTH_CHAIN);
        if (health)
        {
            apply_camera_rules(camera, *health);
        }
    }

    original_camera_update(camera, delta_time);
}
```

For a multi-level pointer chain, resolve the whole chain under one fault guard rather than calling `seh_read` once per link. The combined walk is one out-of-line call instead of N, keeps each link in a register instead of round-tripping it through `std::optional`, and validates its arguments once. (It does not save SEH-frame setup: on MSVC/x64 a `__try` success path is table-driven and free, so N of them cost nothing extra either.)

```cpp
// (*(*(base + 0x10) + 0x28)) + 0x8, read as a float, all under one guard.
const auto value = Mem::seh_read_chain<float>(base, {0x10, 0x28, 0x8});
if (value)
{
    use(*value);
}
```

## Writing in hot paths

Writes follow the same rule as reads. A pointer the hook was handed is live by definition, so write through it directly (the anti-patterns below show why gating that write is pointless). But a value written through a *resolved* address -- a scanned base plus a pointer chain that can go stale between frames -- needs the same fault guard a read does, because the terminal slot can be unmapped the instant the chain is wrong.

Use the guarded write primitives for that. They write to memory the target already keeps writable (a camera transform, a player field) under one fault guard, changing no page protection:

```cpp
namespace Mem = DetourModKit::Memory;

// Write a camera transform every frame through a resolved chain. Fault-guarded:
// a stale chain fails closed (returns false) instead of faulting the host.
const Matrix4x4 next = compute_camera(...);
if (!Mem::seh_write_chain<Matrix4x4>(camera_base, CAMERA_TRANSFORM_CHAIN, next))
{
    // Chain went stale this frame -- skip the write, do not crash.
}
```

`seh_write_bytes` / `seh_write<T>` are the single-address forms; `seh_write_chain_bytes` / `seh_write_chain<T>` resolve a chain and write its terminal slot through the guarded write path. None of them change page protection, flush the instruction cache, or invalidate the readability cache -- they are the write counterpart of `seh_read_*`.

`write_bytes` is a different tool: it flips page protection to writable, writes, restores protection, flushes the instruction cache, and invalidates the cache range. That is exactly what a one-shot CODE patch on a read-only / executable page needs, and exactly the overhead you do not want per frame. Use `write_bytes` for setup-time patches; use `seh_write_*` for per-frame data writes.

## Primitive selection

| You have | You want | Use |
|----------|----------|-----|
| A pointer the hook was handed (the engine is using it now) | To read or write it | Direct access. It is live by definition. Wrap in `__try` (or `seh_read`) only if it may be stale by the time you run. |
| A single address that may be stale or unmapped | One typed read that cannot fault | `seh_read<T>(addr)` |
| A single address, a raw byte range | One range read that cannot fault | `seh_read_bytes(addr, out, n)` |
| A multi-level pointer chain | The final address only | `seh_resolve_chain(base, {offsets...})` |
| A multi-level pointer chain | A typed value at the end | `seh_read_chain<T>(base, {offsets...})` |
| A pointer chain you can prove is structurally valid this frame | The fastest possible read, no syscall, no SEH | `read_ptr_unchecked(base, offset)` |
| A resolved address that may be stale | One typed / range write that fails closed instead of faulting | `seh_write<T>(addr, value)` / `seh_write_bytes(addr, src, n)` |
| A multi-level pointer chain | A guarded write at its terminal slot | `seh_write_chain<T>(base, {offsets...}, value)` / `seh_write_chain_bytes(...)` |
| To patch CODE on a read-only / executable page once | A protection-flipping, i-cache-flushing write | `write_bytes(target, src, n)` -- setup/patch-only, never per frame |
| To screen a candidate pointer before any read | A pure arithmetic plausibility test | `plausible_userspace_ptr(p)` |
| To confirm a pointer lives in a known module | A branch-only range test | `contains(own_module_range(), p)` (capture the range once) |
| To validate an address once at setup | A readability or writability check | `is_readable` / `is_writable` |

## Toolchain note

The `seh_*` primitives use real `__try` / `__except` on MSVC, where the success path is table-driven and costs nothing extra. On MinGW (which has no frame-based SEH) a 64-bit build installs a process-wide vectored exception handler once and runs reads or writes through a guarded access path with no `VirtualQuery` on the success path, recovering a fault as `std::nullopt` / `false` instead of crashing. This is best-effort: the VEH path is used only when handler installation succeeded (`s_veh_handle` is non-null); if `ensure_veh_installed()` failed, or on a 32-bit MinGW build (`!_WIN64`), byte reads fall back to `VirtualQuery` plus `ReadProcessMemory` and byte writes fall back to `VirtualQuery` plus `WriteProcessMemory` after confirming the destination is currently writable. Bulk in-place region scans do not have a kernel-mediated byte-copy fallback, so they fail closed if the MinGW x64 handler is unavailable. `read_ptr_unchecked` is still the fastest choice when you can prove the pointer is live for the current frame; otherwise prefer `seh_read` / `seh_read_chain` for stale or unmapped pointers. Shipping mod builds target MSVC, so the zero-cost path is the normal case.

## Anti-patterns to remove

```cpp
// WRONG: predicate before every read on a hot path. Lock plus possible syscall
// per field, and the page can still change before the dereference.
if (Mem::is_readable(reinterpret_cast<void *>(addr), sizeof(uint64_t)))
{
    value = *reinterpret_cast<uint64_t *>(addr);
}

// WRONG: gating a write to a pointer the engine just wrote through. If the
// engine could write it, it is writable; the predicate adds a lock for nothing.
if (Mem::is_writable(positionPtr, sizeof(Vector3)))
{
    *positionPtr = newPosition;
}

// WRONG: module_range_for in a loop. Every call is a GetModuleHandleEx lookup,
// even on a cache hit. Capture the range once and use contains().
for (auto p : candidates)
{
    if (Mem::module_range_for(reinterpret_cast<void *>(p)))
    {
        ...
    }
}
```

```cpp
// RIGHT: capture the range once, screen cheaply, read under one guard.
static const Mem::ModuleRange host = Mem::host_module_range();
for (auto p : candidates)
{
    if (Mem::plausible_userspace_ptr(p) && Mem::contains(host, p))
    {
        const auto v = Mem::seh_read<uint64_t>(p);
        if (v)
        {
            use(*v);
        }
    }
}
```
