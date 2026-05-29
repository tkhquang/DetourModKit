# MSVC RTTI walker (`rtti.hpp`)

DetourModKit ships a small RTTI introspection module for MSVC-built x64 targets. It recovers an object's concrete type from a runtime vtable pointer by walking the RTTICompleteObjectLocator (COL) and TypeDescriptor structures the Visual C++ compiler emits for every polymorphic class. The walker operates on raw addresses, never invokes `typeid()` or `dynamic_cast`, and works across DLL boundaries against third-party MSVC binaries that ship without symbols (game engines, middleware).

The walker is the right tool when you need to:

- Verify that a freshly resolved pointer is of the expected concrete class before chasing further offsets (`vtable_is_type`).
- Identify what an opaque pointer table actually contains so you can target a specific subsystem by RTTI name rather than by an AOB-resolved vtable address (`find_in_pointer_table`).
- Log mangled type names for diagnostic dumps (`type_name_of` / `type_name_into`).

Names are returned in MSVC mangled form, for example `.?AVMyClass@ns@@`. Compare byte-for-byte rather than demangling; the walker never invokes `UnDecorateSymbolName`.

## ABI layout

The walker treats the following layout as a long-term contract. It has been stable across every Visual C++ release since VS 2010 and is what IDA Pro, Ghidra, Binary Ninja, MinHook, SafetyHook, Detours, and EasyHook all rely on:

```text
vtable[0]   --> first virtual method                  (the qword Memory::seh_read returns when reading *obj)
vtable[-1]  --> RTTICompleteObjectLocator *col        (qword stored immediately before the vtable)

col + 0x00  : DWORD signature           (1 on x64, 0 on x86)
col + 0x04  : DWORD offset              (offset of this vftable in the complete class)
col + 0x08  : DWORD cdOffset            (constructor displacement)
col + 0x0C  : DWORD pTypeDescriptor     (RVA to TypeDescriptor)
col + 0x10  : DWORD pClassDescriptor    (RVA to RTTIClassHierarchyDescriptor)
col + 0x14  : DWORD pSelf               (x64 only, signature == 1: RVA back to col)

td  + 0x00  : void* pVFTable            (vtable of type_info)
td  + 0x08  : void* spare               (always 0 in practice)
td  + 0x10  : char  name[]              (NUL-terminated mangled name)
```

RVAs are 32-bit unsigned offsets relative to the **owning module's** image base, not the calling DLL. For DetourModKit this distinction matters because consumer mods are usually statically linked into a mod DLL while game vtables live in the host EXE, so `GetModuleHandleW(nullptr)` would be wrong on principle. The walker recovers the image base from `col.pSelf` whenever the x64 signature is set (the canonical IDA/Ghidra approach); only the x86 signature path falls back to `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, vtable)`.

## API at a glance

| Function | Use when |
|----------|----------|
| `Rtti::type_name_of(vtable, max_len)` | You want the name as a `std::string` for logging or one-shot inspection. One heap allocation per call. |
| `Rtti::type_name_into(vtable, buf, len)` | You want the same answer with zero allocation. Returns bytes written; output is always NUL-terminated when `len > 0`. |
| `Rtti::vtable_is_type(vtable, expected)` | You only need a yes/no identity probe. Reads `expected.size() + 1` bytes and short-circuits. No allocation. |
| `Rtti::find_in_pointer_table(table, n, expected, vtable_cache?, stride?)` | You need the first object in a pointer table whose vtable matches a given mangled name. The optional caller-owned `std::atomic<uintptr_t>` cache slot reduces steady-state cost to a single qword compare per slot. |

All entry points are noexcept and SEH-guarded; an unmapped page, missing COL, or zero RVA produces a failure return rather than a fault.

## Common patterns

### Identity probe

```cpp
#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"

constexpr std::string_view k_actor_rtti = ".?AVActorComponent@engine@@";

bool actor_is_ready(std::uintptr_t actor_ptr) noexcept
{
    const auto vt_opt = DMK::Memory::seh_read<std::uintptr_t>(actor_ptr);
    if (!vt_opt)
        return false;
    return DMK::Rtti::vtable_is_type(*vt_opt, k_actor_rtti);
}
```

### Pointer-table lookup with steady-state caching

```cpp
namespace
{
    std::atomic<std::uintptr_t> g_camera_vt_cache{0};
}

std::uintptr_t find_camera_component(std::uintptr_t table) noexcept
{
    constexpr std::size_t k_component_slots = 64;
    constexpr std::string_view k_camera_rtti = ".?AVCameraComponent@engine@@";

    return DMK::Rtti::find_in_pointer_table(
               table, k_component_slots, k_camera_rtti, &g_camera_vt_cache)
        .value_or(0);
}
```

The first successful call walks RTTI for every non-null slot and caches the matching vtable address. Every subsequent call reads the cache once with `memory_order_relaxed` and only compares qwords; slots whose vtable differs from the cached value are skipped without a RTTI walk. The cache assumes one canonical vtable per mangled name, which is correct for MSVC RTTI because mangled names encode the most-derived class.

To disable caching, pass `nullptr` for `vtable_cache`. To support tables that interleave per-slot metadata between pointers, pass a `stride` larger than `sizeof(std::uintptr_t)`.

### Zero-allocation logging

```cpp
char rtti_buf[128];
const std::size_t n = DMK::Rtti::type_name_into(vt, rtti_buf, sizeof(rtti_buf));
if (n > 0)
    DMK::Logger::get_instance().log(DMK::LogLevel::Debug, "vtable type = {}", rtti_buf);
```

`type_name_into` is the right choice for per-frame probes or diagnostic captures that must not allocate. The buffer is always NUL-terminated when `out_len > 0`, and the failure path sets `out[0] = '\0'` so misuse cannot leak stale stack contents.

### Resolving a vtable from a type name (reverse direction)

The walker runs vtable to name. The inverse, name to vtable, is the natural way to bootstrap a class marker at init: you know the mangled name but not yet the vtable address. Because the `TypeDescriptor` name string lives in `.rdata`, this direction needs a data-section scan, which the executable-only sweep cannot do. `Scanner::scan_readable_regions` (see [aob-signatures.md](aob-signatures.md), section 4.7) provides it.

The flow inverts the [ABI layout](#abi-layout) above:

1. `scan_readable_regions` for the mangled name string (for example `.?AVMyClass@ns@@`, including the trailing NUL) to land on `td + 0x10`. The name is plain ASCII and fully ASLR-invariant, so it is a far stronger anchor than the vtable header, whose entries are relocated pointers that shift with the ASLR slide.
2. Subtract `0x10` to reach the `TypeDescriptor` base, then locate the COL whose `pTypeDescriptor` RVA points back at it and read `vtable = col_address + ...` via the same self-RVA / image-base arithmetic the walker uses internally.

This is the recommended path for "find the one vtable for a known class" because it does not depend on a volatile constructor or on the per-launch byte values of relocated vtable pointers.

## Performance notes

- The walker issues two SEH-guarded reads per call on the cold path: one for the COL pointer at `vtable - 8`, one batched read of the 24-byte `ColHead`. On MSVC each `__try` frame is essentially free on the success path. On MinGW each read goes through `VirtualQuery`, which is microseconds-class; the batched ColHead read keeps the MinGW cost down to two syscalls instead of four.
- `vtable_is_type` reads `expected.size() + 1` name bytes in a single SEH frame and compares with `memcmp`. There is no heap allocation, no string construction, and no demangle pass.
- `type_name_of` allocates one `std::string` per call. Prefer `type_name_into` or `vtable_is_type` on hot paths.
- `find_in_pointer_table` on a cold cache scans every non-null slot with the full walker. With a warm cache it touches each slot exactly once with a qword compare. For a sparse table of 256 slots and a unique target, the warm-path cost is dominated by the slot dereference, not the RTTI machinery.

## When the walker returns nothing

The walker returns `std::nullopt` / `false` / `0` (depending on the call) for every recoverable failure:

- The vtable pointer is null or in the Windows reserved low-address range (`< 0x10000`).
- The vtable's COL pointer at `vtable - 8` is null, low, or unreadable.
- The COL's `pTypeDescriptor` RVA is zero.
- Image-base recovery from `pSelf` underflows AND `GetModuleHandleExW` fails (only possible when the vtable address does not fall inside any loaded module).
- The mangled-name buffer at the resolved address faults on the first page.

None of these raise an exception; the caller can treat all failure modes uniformly through the optional / bool return.

## MinGW support

The walker works correctly on both MSVC and MinGW builds of DetourModKit when targeting MSVC-compiled binaries (the typical use case for game mods). The underlying `Memory::seh_read_bytes` primitive uses `__try` / `__except` on MSVC and a `VirtualQuery`-based region validation loop on MinGW. The MinGW path is race-prone against concurrent `VirtualProtect` and slower (one syscall per region), but produces identical results for stable game state.

Note: the walker reads the MSVC RTTI ABI. If the target object was compiled by GCC or Clang for the Itanium C++ ABI, the layout at `vtable - 8` is different and the walker will fail. This is by design; DetourModKit consumers building mods for MSVC-compiled games (every major Windows game engine since 2010) will not encounter Itanium RTTI in their target processes.
