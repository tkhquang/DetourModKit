# Reading Game Memory in Hot Paths

This guide explains how to read and write game memory from code that runs at high frequency (per-frame render hooks, per-input-event detours, per-object apply loops) without the cost that the validation predicates carry. It is the reference for the guarded `memory::read` / `memory::write` / `memory::walk` primitives and the raw `memory::unchecked::read` fast path in [`memory.hpp`](../../../include/DetourModKit/memory.hpp), and it explains when to use each one.

## The rule

> Do not put `memory::is_readable` or `memory::is_writable` in front of every dereference on a hot path. Read directly through a guarded `memory::read`, optionally pre-screened by a cheap arithmetic guard.

`is_readable` / `is_writable` exist for one-shot setup validation and diagnostics. They are correct there and cheap when called a handful of times. They are the wrong tool for a path that runs hundreds or thousands of times per frame.

## Why the predicate is the wrong tool on a hot path

`is_readable(Region{addr, size})` does two things that do not belong in a tight loop:

1. **It is not free, even on a cache hit.** A hit takes a per-shard reader lock and a cache lookup. A miss issues a `VirtualQuery` syscall and rebuilds the cache entry under an exclusive lock. When the addresses you check keep changing (a new game object each iteration), almost every lookup misses, so the cost is dominated by syscalls and lock traffic.
2. **It is a time-of-check to time-of-use illusion.** The page state it reports can change between the check returning `true` and your dereference. A pointer that passes the predicate can still fault, so you need a fault guard around the read anyway. Once the read is inside a fault guard, the predicate adds no safety, only cost.

Concretely: a hook resolves an object and reads eight dependent fields off it across a few distinct (cache-missing) objects. Gated per read, that call can cost one to two orders of magnitude more than under one fault guard. The multiplier is dominated by `VirtualQuery` latency on cache misses, the cache-miss rate, and shard-lock contention, so it varies by CPU, Windows build, and address-space size. At a few hundred such calls per frame that is the difference between imperceptible and a multi-millisecond frame spike. Build with `-DDMK_BUILD_BENCHMARKS=ON`, run the `DetourModKit_bench_memory` target (Phase 6 of `tests/bench_memory.cpp`), and read the `probe_gated_over_direct` value to measure it on your target. Recorded numbers and methodology are in [the memory benchmark notes](../../analysis/memory_bench_v3.x/README.md).

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
        // Resolve the chain in one walk, then read the leaf.
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

For a multi-level pointer chain, use `walk` instead of separate reads.

`walk` uses one out-of-line call and validates its arguments once. It issues one guarded read for each intermediate hop. Each dereferenced link must meet that hop's `min_valid` floor and the user-mode ceiling. The function does not dereference the leaf. It screens the leaf against the canonical user-mode range. A failure reports the hop index in `Error::detail`.

MSVC/x64 uses table-driven `__try` success paths, so repeated guard frames add no setup cost. The bare-offset overload stores up to 32 steps on the stack and never allocates. It returns `ErrorCode::SizeTooLarge` past that limit.

For a longer chain, use the `ChainStep` overload. The caller owns its step storage.

```cpp
// Resolve (*(*(base + 0x10) + 0x28)) + 0x8 in one walk, then read a float.
if (const auto slot = mem::walk(Address{base}, std::array<std::ptrdiff_t, 3>{0x10, 0x28, 0x8}))
{
    if (const auto value = mem::read<float>(*slot))
    {
        use(*value);
    }
}
```

## Writing in hot paths

Writes follow the same rule as reads. A pointer the hook was handed is live for the duration of that callback invocation, so write through it directly (the anti-patterns below show why a gate on that write is pointless). A value written through a *resolved* address needs the same fault guard a read does. Such an address is a scanned base plus a pointer chain that can go stale between frames, and the terminal slot can be unmapped the instant the chain is wrong.

There are two guarded write families, split by what happens when the target is not already writable.

`memory::write_in_place<T>` / `memory::write_in_place(Address, std::span<const std::byte>)` is the per-frame data write. It is a guarded copy that changes **no** page protection and fails closed with `ErrorCode::WriteFaulted` if the target's first byte is not writable (nothing is written). Use it for the common case, a value written every frame to memory the target keeps writable (a camera transform, a player field). It stays on the cheap no-`VirtualProtect` path, and if a stale or mistargeted chain drifts onto a read-only page it reports the fault instead of a silent unprotect and corruption of that page. The copy is not atomic across a writability seam. A span that straddles a writable page and an adjacent unwritable one faults and returns `ErrorCode::WriteMayBePartial`, whose changed prefix is indeterminate. Size a per-frame store so it cannot straddle a protection boundary.

```cpp
namespace mem = DetourModKit::memory;
using DetourModKit::Address;
using DetourModKit::ErrorCode;

// Write a camera transform every frame through a resolved chain. Fault-guarded: a stale chain fails closed
// instead of faulting the host, and a slot that is not writable (the chain drifted onto a protected page) is
// rejected rather than reprotected.
const Matrix4x4 next = compute_camera(...);
if (const auto slot = mem::walk(Address{camera_base}, CAMERA_TRANSFORM_CHAIN))
{
    if (const auto written = mem::write_in_place<Matrix4x4>(*slot, next); !written)
    {
        // WriteFaulted changed nothing, so skip this frame. WriteMayBePartial leaves the transform
        // indeterminate, so stop writing through this slot and re-resolve the chain first.
        camera_slot_usable = written.error().code != ErrorCode::WriteMayBePartial;
    }
}
// else: chain went stale this frame, so skip the write.
```

`memory::write<T>` / `memory::write_bytes` are the escalating data write. They first try the same no-reprotect copy, then fall back to a flip of protection (write, restore) when that fast write faults because the page is read-only or executable. Reach for them when data-write escalation is the intent, not for a per-frame write where a non-writable target signals a bug you want surfaced rather than papered over. They do not provide the instruction-cache maintenance executable patches require. Use `memory::patch_code` for code, because it checks a flush on every path that can modify code, including an already-writable target or a partially changed prefix.

When you repeatedly write to a page the target keeps protected, do not pay a protection flip per write. Hold a `memory::ProtectGuard` over the region for the lifetime of the loop. It makes the page writable once, so each `write_in_place` inside the guarded window sees a writable page and stays on the cheap path. The guard restores the original protection on scope exit. This is a DATA pattern. `write_in_place` does not flush the instruction cache, so patch executable CODE with `memory::patch_code` rather than a guarded `write_in_place` loop.

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

A one-shot CODE patch is `memory::patch_code`. It derives writable protection from the page's own execute semantics (a data page never gains execute). It writes, then checks the instruction-cache flush even when the page was already writable. It then restores protection and invalidates the affected protection-query cache range. If a guarded copy changes only a prefix, it attempts a flush over the full request before fallback setup can fail. `WriteMayBePartial` remains more truthful than a later no-write retry or flush-only error. Use `write_bytes` / `write<T>` for data that can need a protection change, and `patch_code` whenever the target bytes are executed as code.

Every byte-copy surface (`read_into`, `write_bytes`, `patch_code`, `write_in_place`) requires the caller's span and the target range to be disjoint. An intersecting pair in either direction is refused with `ErrorCode::OverlappingRanges` before any byte moves.

## Which types a typed read accepts

`memory::read<T>` reinterprets foreign bytes as a `T`, so it participates only for a `T` whose every bit pattern is a valid object representation. That domain is an explicit allowlist, not "every scalar", and a type outside it is a compile error rather than a runtime hazard:

| Accepted | Rejected |
| --- | --- |
| Every integral type except `bool` | `bool` (use `memory::read_bool`) |
| `float`, `double`, and `long double` only where it is `double` (MSVC) | A float format with padding bits, notably MinGW's 16-byte x87 `long double` |
| An enumeration with a fixed, accepted underlying type (every scoped enum over an integer, `std::byte`) | An unscoped enumeration with no fixed base, and any enumeration over `bool` |
| Object and function pointers under the Windows x64 ABI, and `dmk::Address` | `std::nullptr_t`, pointer-to-member-object, pointer-to-member-function |
| Bounded built-in arrays and `std::array` of accepted elements, recursively | An unbounded array, or an array of any rejected element |
| A class or union opted in through `detail::enable_representation_safe_aggregate` | Any other class or union |

The C++ standard leaves pointer value representations implementation-defined. It does not make every object-representation bit pattern portable. Pointer participation is therefore an explicit Windows x64 ABI concession, not a portable guarantee. The supported compilers use one flat pointer-sized word and tolerate a hold of a non-canonical value. Provenance is not recovered. Screen the result with `memory::is_plausible_ptr` and read through it with a guarded call. Never dereference it directly.

A top-level built-in array request returns the equivalent nested `std::array`, because C++ functions cannot return a built-in array by value. For example, `memory::read<int[2][3]>` returns `Result<std::array<std::array<int, 3>, 2>>`.

`memory::read_bool(Address{addr})` is the checked decode for a single foreign byte. It validates the byte before it forms the value and returns `ErrorCode::InvalidRepresentation` for anything but 0 or 1. For everything else outside the domain, copy raw bytes with `memory::read_into` and decode them yourself.

## Primitive selection

| You have | You want | Use |
|----------|----------|-----|
| A pointer the hook was handed | To read or write it | Direct access. It is live for the current invocation. Use a guarded `memory::read` only if it can be stale by the time you run. |
| A single address that can be stale or unmapped | One typed read that cannot fault | `memory::read<T>(Address{addr})` |
| A single address, a raw byte range | One range read that cannot fault | `memory::read_into(Address{addr}, std::span<std::byte>{...})` |
| A single foreign byte to read as a `bool` | A validated decode (raw `read<bool>` is ill-formed) | `memory::read_bool(Address{addr})`. `InvalidRepresentation` for a byte other than 0/1 |
| A multi-level pointer chain | The final address only | `memory::walk(Address{base}, {offsets...})` |
| A multi-level pointer chain | A typed value at the end | `memory::walk(...)` then `memory::read<T>(*slot)` |
| A pointer you can prove is alive this frame | The fastest possible read, no syscall, no SEH | `memory::unchecked::read<T>(Address{...})` |
| A resolved address on a writable page | A per-frame write, fails closed if not writable (no reprotect) | `memory::write_in_place<T>(Address{addr}, value)` / `write_in_place(Address{addr}, span)` |
| A multi-level pointer chain | A guarded per-frame write at its terminal slot | `memory::walk(...)` then `memory::write_in_place<T>(*slot, value)` |
| To write DATA, with protection changed for you if not writable | An auto-unprotecting data write | `memory::write_bytes(Address{target}, span)` / `memory::write<T>(...)` |
| To patch CODE (bytes that are executed) | An auto-unprotecting write with instruction-cache maintenance | `memory::patch_code(Address{target}, span)` |
| To write a protected page repeatedly without a protection flip each time | A held page-protection guard | `memory::ProtectGuard::make(Region{...}, Prot::RW)` (hold it across the loop) |
| To screen a candidate pointer before any read | A pure arithmetic plausibility test | `memory::is_plausible_ptr(Address{p})` |
| To check that a pointer lives in a known module | A branch-only range test | `Region::own().contains(Address{p})` (capture the range once) |
| To validate an address once at setup | A readability or writability check | `memory::is_readable(Region{...})` / `memory::is_writable(Region{...})` |

## Toolchain note

The guarded primitives use real `__try` / `__except` on MSVC, where the success path is table-driven and costs nothing extra. On MinGW (which has no frame-based SEH) a 64-bit build installs a process-wide vectored exception handler once. Reads and writes run through a guarded access path with no `VirtualQuery` on the success path. It recovers a fault as a `Result` error instead of a crash. The Structured Exception Handling is confined entirely to the engine translation unit, so the installed `memory.hpp` pulls in no `<windows.h>` and no SEH. `init_cache` installs the MinGW vectored fault handler, so a guarded read never has to fall back to a per-call `VirtualQuery`. `memory::unchecked::read` is still the fastest choice when you can prove the pointer is live for the current frame. Otherwise prefer the guarded `memory::read` / `memory::walk` for stale or unmapped pointers. Shipping mod builds target MSVC, so the zero-cost path is the normal case.

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

// WRONG: module_of in a loop. Every call is a loader lookup plus a guarded read
// of the image's PE headers, because it always reports the module's current
// extent rather than a memoized one. Capture the range once and use
// Region::contains(); re-resolve only when you need to observe a replacement.
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
