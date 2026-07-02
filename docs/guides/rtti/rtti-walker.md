# MSVC RTTI walker (`rtti.hpp`)

DetourModKit ships a small RTTI introspection module (namespace `DetourModKit::rtti`) for MSVC-built x64 targets. It recovers an object's concrete type from a runtime vtable pointer by walking the RTTICompleteObjectLocator (COL) and TypeDescriptor structures the Visual C++ compiler emits for every polymorphic class. The walker operates on value-typed `DetourModKit::Address` handles, never invokes `typeid()` or `dynamic_cast`, and works across DLL boundaries against third-party MSVC binaries that ship without symbols (game engines, middleware).

The walker is the right tool when you need to:

- Verify that a freshly resolved pointer is of the expected concrete class before chasing further offsets (`vtable_is_type`).
- Identify what an opaque pointer table actually contains so you can target a specific subsystem by RTTI name rather than by an AOB-resolved vtable address (`find_in_pointer_table`).
- Log mangled type names for diagnostic dumps (`type_name_of` / `type_name_into`).

Names are returned in MSVC mangled form, for example `.?AVMyClass@ns@@`. Compare byte-for-byte rather than demangling; the walker never invokes `UnDecorateSymbolName`.

## ABI layout

The walker treats the following layout as a long-term contract. It has been stable across every Visual C++ release since VS 2010 and is what IDA Pro, Ghidra, Binary Ninja, MinHook, SafetyHook, Detours, and EasyHook all rely on:

```text
vtable[0]   --> first virtual method                  (the qword memory::read returns when reading *obj)
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
| `rtti::type_name_of(vtable, max_len)` | You want the name as a `std::string` for logging or one-shot inspection. One heap allocation per call. |
| `rtti::type_name_into(vtable, buf, len)` | You want the same answer with zero allocation. Returns bytes written; output is always NUL-terminated when `len > 0`. |
| `rtti::vtable_is_type(vtable, expected)` | You only need a yes/no identity probe. Reads `expected.size() + 1` bytes and short-circuits. No allocation. |
| `rtti::find_in_pointer_table(table, n, expected, vtable_cache?, stride?)` | You need the first object in a pointer table whose vtable matches a given mangled name. The optional caller-owned `std::atomic<Address>` cache slot reduces steady-state cost to a single qword compare per slot. |
| `rtti::vtable_for_type(mangled, range?)` | You know a stable class name and want its primary (most-derived) vtable address, scoped to one module. The name-keyed inverse of `vtable_is_type`. |
| `rtti::vtables_for_type(mangled, out, cap, range?)` | The class may be multiply/virtually inherited and you want every sub-object vtable that shares the name, not just the primary. |
| `rtti::TypeIdentity(mangled, range?)` | You want a cached, name-keyed identity handle: resolve the primary vtable once, then `matches(vtable)` is a single qword compare. |

The forward entry points are noexcept and SEH-guarded; an unmapped page, missing COL, or zero RVA produces a failure return rather than a fault. The reverse resolvers (`vtable_for_type`, `vtables_for_type`) and `TypeIdentity` are SEH-guarded as well and return `std::nullopt` / a zero count on any failure.

## Common patterns

### Identity probe

```cpp
#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"

constexpr std::string_view k_actor_rtti = ".?AVActorComponent@engine@@";

bool actor_is_ready(DMK::Address actor_ptr) noexcept
{
    const auto vt_opt = DMK::memory::read<DMK::Address>(actor_ptr);
    if (!vt_opt)
        return false;
    return DMK::rtti::vtable_is_type(*vt_opt, k_actor_rtti);
}
```

### Pointer-table lookup with steady-state caching

```cpp
namespace
{
    std::atomic<DMK::Address> g_camera_vt_cache{DMK::Address{}};
}

std::optional<DMK::Address> find_camera_component(DMK::Address table) noexcept
{
    constexpr std::size_t k_component_slots = 64;
    constexpr std::string_view k_camera_rtti = ".?AVCameraComponent@engine@@";

    return DMK::rtti::find_in_pointer_table(
        table, k_component_slots, k_camera_rtti, &g_camera_vt_cache);
}
```

The first successful call walks RTTI for every non-null slot and caches the matching vtable address. Every subsequent call reads the cache once with `memory_order_relaxed` and only compares qwords; slots whose vtable differs from the cached value are skipped without a RTTI walk. The cache assumes one canonical vtable per mangled name, which is correct for MSVC RTTI because mangled names encode the most-derived class.

To disable caching, pass `nullptr` for `vtable_cache`. To support tables that interleave per-slot metadata between pointers, pass a `stride` larger than `sizeof(std::uintptr_t)`.

### Zero-allocation logging

```cpp
char rtti_buf[128];
const std::size_t n = DMK::rtti::type_name_into(vt, rtti_buf, sizeof(rtti_buf));
if (n > 0)
    DMK::log().log(DMK::LogLevel::Debug, "vtable type = {}", rtti_buf);
```

`type_name_into` is the right choice for per-frame probes or diagnostic captures that must not allocate. The buffer is always NUL-terminated when `out_len > 0`, and the failure path sets `out[0] = '\0'` so misuse cannot leak stale stack contents.

### Resolving a vtable from a type name (reverse direction)

The walker runs vtable to name. The inverse, name to vtable, is the natural way to bootstrap a class marker at init: you know the mangled name but not yet the vtable address. `rtti::vtable_for_type` does this directly.

```cpp
// Resolve once at init; key on the stable class name, not a vtable literal.
const auto vt = DMK::rtti::vtable_for_type(".?AVGameAudioEffect@engine@@");
if (vt)
    g_audio_effect_vtable = *vt;
```

It sweeps the module's readable, non-executable sections -- where MSVC keeps vtables and their RTTI meta-pointers (`.rdata` for a normal `/GR` image, `.data` for a packed or section-merged one) -- for the COL whose `TypeDescriptor` name matches, then returns the vtable whose `vtable[-1]` meta-slot points back at that COL. Every candidate is re-validated through the same COL prelude the forward walker uses, so a coincidental pointer-shaped match is rejected, not returned.

Keying on the name rather than the vtable header is deliberate: the `TypeDescriptor` name string is plain ASCII and fully ASLR-invariant, a far stronger anchor than a vtable whose entries are relocated pointers that shift with the ASLR slide and whose bytes change per launch.

Multiple inheritance and `/OPT:ICF`:

- `vtable_for_type` returns the **primary** vtable (the COL whose `offset` is 0), which is the value an object pointer's first qword holds for a most-derived instance. A class used only as a secondary or virtual base has its first qword pointing at a `COL.offset != 0` sub-object vtable; use `vtables_for_type` to get every sub-object vtable. An ambiguous primary (the same name with two distinct offset-0 vtables, for example a type linked into the image twice) fails closed and returns `std::nullopt`.
- Take identity from the returned vtable **address** (the `[-1]`-COL-anchored value), never from the vtable's slot contents: under the linker's identical-COMDAT folding (`/OPT:ICF`) two distinct classes can share folded function-pointer slots, so a slot-content comparison is not class-unique.

For a cached per-frame identity check, wrap it in `rtti::TypeIdentity`. `TypeIdentity` owns its mangled name (it copies the `std::string_view` into an internal `std::string`), so the handle is self-contained and any string source -- including a temporary -- is safe to pass:

```cpp
namespace { DMK::rtti::TypeIdentity g_camera_id{".?AVCameraCombat@engine@@"}; }

bool is_combat_camera(DMK::Address obj) noexcept
{
    const auto vt = DMK::memory::read<DMK::Address>(obj);
    return vt && g_camera_id.matches(*vt); // resolves once, then a qword compare
}
```

Scoping to one `Region` (the default is the host EXE) is load-bearing for correctness, not just ergonomics: the same mangled name can appear in several loaded modules. Pass the game module's range explicitly when the target type lives in a separate DLL.

## Performance notes

- The walker issues two SEH-guarded reads per call on the cold path: one for the COL pointer at `vtable - 8`, one batched read of the 24-byte `ColHead`. On MSVC each `__try` frame is essentially free on the success path. On MinGW each read uses the vectored fault guard, so the success path avoids the per-read `VirtualQuery` syscall; the batched ColHead read still matters because it keeps the walker to two guarded calls instead of four.
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

The walker works correctly on both MSVC and MinGW builds of DetourModKit when targeting MSVC-compiled binaries (the typical use case for game mods). The underlying guarded read engine behind `memory::read_into` uses `__try` / `__except` on MSVC and the process-wide vectored fault guard on MinGW. Both toolchains fail closed on unreadable RTTI pages and produce identical results for stable game state; MSVC remains faster because its x64 SEH tables add no success-path setup.

Note: the walker reads the MSVC RTTI ABI. If the target object was compiled by GCC or Clang for the Itanium C++ ABI, the layout at `vtable - 8` is different and the walker will fail. This is by design; DetourModKit consumers building mods for MSVC-compiled games (every major Windows game engine since 2010) will not encounter Itanium RTTI in their target processes.
