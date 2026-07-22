# MSVC RTTI walker (`rtti.hpp`)

DetourModKit ships a small RTTI introspection module (namespace `DetourModKit::rtti`) for MSVC-built x64 targets. It recovers an object's concrete type from a runtime vtable pointer by walking the RTTICompleteObjectLocator (COL) and TypeDescriptor structures the Visual C++ compiler emits for every polymorphic class. The walker operates on value-typed `DetourModKit::Address` handles, never invokes `typeid()` or `dynamic_cast`, and works across DLL boundaries against third-party MSVC binaries that ship without symbols (game engines, middleware).

The walker is the right tool when you need to:

- Verify that a freshly resolved pointer is of the expected concrete class before chasing further offsets (`vtable_is_type`).
- Identify what an opaque pointer table actually contains so you can target a specific subsystem by RTTI name rather than by an AOB-resolved vtable address (`find_in_pointer_table`).
- Log mangled type names for diagnostic dumps (`type_name_of` / `type_name_into`).

Names are returned in MSVC mangled form, for example `.?AVMyClass@ns@@`. Compare byte-for-byte rather than demangling; the walker never invokes `UnDecorateSymbolName`.

## ABI layout

The walker treats the supported MSVC x64 layout below as its ABI contract:

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

RVAs are 32-bit unsigned offsets relative to the **owning module's** image base, not the calling DLL. For DetourModKit this distinction matters because consumer mods are usually statically linked into a mod DLL while game vtables live in the host EXE, so `GetModuleHandleW(nullptr)` would be wrong on principle. The walker takes the image base from the loader-reported range of the module that owns the vtable (`memory::module_of`), then on x64 cross-checks it against the COL's `pSelf` RVA: the canonical IDA/Ghidra computation `col_addr - pSelf` must reconstruct that same loader base, or the structure is treated as forged or relocated and rejected. Any COL signature other than the x64 value (`1`) is rejected outright -- it carries no `pSelf` to cross-check -- so there is no x86 signature path and no `GetModuleHandleExW` fallback.

## API at a glance

| Function | Use when |
|----------|----------|
| `rtti::type_name_of(vtable, max_len)` | You want the name as a `std::string` for logging or one-shot inspection. One heap allocation per call. |
| `rtti::type_name_into(vtable, buf, len)` | You want the same answer with zero allocation. Returns bytes written; output is always NUL-terminated when `len > 0`. |
| `rtti::vtable_is_type(vtable, expected)` | You only need a yes/no identity probe. Reads `expected.size() + 1` bytes and short-circuits. No allocation. |
| `rtti::find_in_pointer_table(table, n, expected, vtable_cache?, stride?)` | You need the first object in a pointer table whose vtable matches a given mangled name. The optional caller-owned `std::atomic<Address>` cache slot reduces steady-state cost to a single qword compare per slot and cold-falls back when stale. |
| `rtti::vtable_for_type(mangled, range?)` | You know a stable class name and want its primary (most-derived) vtable address, scoped to one module. The name-keyed inverse of `vtable_is_type`. |
| `rtti::vtables_for_type(mangled, out, cap, range?)` | The class may be multiply/virtually inherited and you want every sub-object vtable that shares the name, not just the primary. |
| `rtti::region_has_rtti(range?)` | You need to tell a type-name miss from a module that has no resolvable MSVC RTTI records at all. |
| `rtti::TypeIdentity(mangled, range?)` | You want a cached, name-keyed identity handle with per-call image-generation validation. |

The forward entry points are noexcept and SEH-guarded; an unmapped page, missing COL, or zero RVA produces a failure return rather than a fault. The reverse resolvers (`vtable_for_type`, `vtables_for_type`) and `TypeIdentity` are SEH-guarded as well and return `std::nullopt` / a zero count on any failure.

## Common patterns

### Identity probe

```cpp
#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"

constexpr std::string_view k_actor_rtti = ".?AVActorComponent@engine@@";

bool actor_is_ready(dmk::Address actor_ptr) noexcept
{
    const auto vt_opt = dmk::memory::read<dmk::Address>(actor_ptr);
    if (!vt_opt)
        return false;
    return dmk::rtti::vtable_is_type(*vt_opt, k_actor_rtti);
}
```

### Pointer-table lookup with steady-state caching

```cpp
namespace
{
    dmk::rtti::PointerTableCache s_camera_vtable_cache;
}

std::optional<dmk::Address> find_camera_component(dmk::Address table) noexcept
{
    constexpr std::size_t k_component_slots = 64;
    constexpr std::string_view k_camera_rtti = ".?AVCameraComponent@engine@@";

    return dmk::rtti::find_in_pointer_table(
        table, k_component_slots, k_camera_rtti, s_camera_vtable_cache);
}
```

The first successful call walks RTTI for every non-null slot and caches the matching vtable address and image generation. A warm call validates that generation and compares qwords first. If the image changed or no slot carries the cached vtable, the function clears the stale identity, performs one cold RTTI pass, and refreshes the cache on a match. Dedicate each cache instance to one expected name and call `reset()` when the owner already knows its module lifecycle changed.

The raw `std::atomic<Address>*` overload remains source-compatible, but it cannot carry an image generation; clear that atomic at lifecycle boundaries. To disable caching, pass `nullptr`. To support tables that interleave per-slot metadata between pointers, pass a larger `stride`.

### Zero-allocation logging

```cpp
char rtti_buf[128];
const std::size_t n = dmk::rtti::type_name_into(vt, rtti_buf, sizeof(rtti_buf));
if (n > 0)
    dmk::log().log(dmk::LogLevel::Debug, "vtable type = {}", rtti_buf);
```

`type_name_into` is the right choice for diagnostic captures that must not allocate. It still pays the loader-querying COL prelude on every call, so for a per-frame identity check on a known type cache a `rtti::TypeIdentity` instead. The buffer is always NUL-terminated when `out_len > 0`, and the failure path sets `out[0] = '\0'` so misuse cannot leak stale stack contents.

### Resolving a vtable from a type name (reverse direction)

The walker runs vtable to name. The inverse, name to vtable, is the natural way to bootstrap a class marker at init: you know the mangled name but not yet the vtable address. `rtti::vtable_for_type` does this directly.

```cpp
// Resolve once at init; key on the stable class name, not a vtable literal.
const auto vt = dmk::rtti::vtable_for_type(".?AVGameAudioEffect@engine@@");
if (vt)
    g_audio_effect_vtable = *vt;
```

It sweeps the module's readable, non-executable sections -- where MSVC keeps vtables and their RTTI meta-pointers (`.rdata` for a normal `/GR` image, `.data` for a packed or section-merged one) -- for the COL whose `TypeDescriptor` name matches, then returns the vtable whose `vtable[-1]` meta-slot points back at that COL. Every candidate is re-validated through the same COL prelude the forward walker uses, so a coincidental pointer-shaped match is rejected, not returned.

Keying on the name rather than the vtable header is deliberate: the `TypeDescriptor` name string is plain ASCII and fully ASLR-invariant, a far stronger anchor than a vtable whose entries are relocated pointers that shift with the ASLR slide and whose bytes change per launch.

Multiple inheritance and `/OPT:ICF`:

- `vtable_for_type` returns the **primary** vtable (the COL whose `offset` is 0), which is the value an object pointer's first qword holds for a most-derived instance. A class used only as a secondary or virtual base has its first qword pointing at a `COL.offset != 0` sub-object vtable; use `vtables_for_type` to get every sub-object vtable. An ambiguous primary (the same name with two distinct offset-0 vtables, for example a type linked into the image twice) fails closed and returns `std::nullopt`.
- A unique or absent verdict is trustworthy only across a **complete** sweep. If a section header faults after a valid prefix, a page inside a swept section is unreadable, or the scan saturates its internal buffers, a second primary could hide in the region that was not read, so `vtable_for_type` fails closed rather than authorize a unique vtable from a partial sweep. When you must distinguish an authoritative absence from a sweep that could not finish, use the statusful forms: `vtables_for_type_checked` returns a `{count, completeness}` where `completeness` is `Traversal::{Complete, Incomplete, Saturated}`, and `region_rtti_presence` returns `RttiPresence::{Present, Absent, Incomplete}`.
- Take identity from the returned vtable **address** (the `[-1]`-COL-anchored value), never from the vtable's slot contents: under the linker's identical-COMDAT folding (`/OPT:ICF`) two distinct classes can share folded function-pointer slots, so a slot-content comparison is not class-unique.

For a cached per-frame identity check, wrap it in `rtti::TypeIdentity`. `TypeIdentity` owns its mangled name (it copies the `std::string_view` into an internal `std::string`), so the handle is self-contained and any string source -- including a temporary -- is safe to pass:

```cpp
namespace { dmk::rtti::TypeIdentity g_camera_id{".?AVCameraCombat@engine@@"}; }

bool is_combat_camera(dmk::Address obj) noexcept
{
    const auto vt = dmk::memory::read<dmk::Address>(obj);
    return vt && g_camera_id.matches(*vt);
}
```

Scoping to one `Region` (the default is the host EXE) is load-bearing for correctness, not just ergonomics: the same mangled name can appear in several loaded modules. Pass the game module's range explicitly when the target type lives in a separate DLL.

A successful resolve is cached and stamped with the resolving module's image generation (`rtti::image_generation`, derived from its base, `SizeOfImage`, and PE timestamp). Publication checks the generation before and after the sweep, so a mapping transition cannot attach a new stamp to an old result. Every warm call re-validates that stamp; a changed image drops the stale value, refreshes the full module extent, and re-resolves against the current mapping. Call `invalidate()` to force a cold resolve immediately. A private-buffer scope carries generation `0` and must be reset explicitly. Misses are not latched, but retries are throttled so polling an absent type does not re-sweep the module every frame.

`TypeIdentity` is a concrete public type whose private atomic cache is embedded in the object. DetourModKit does not promise a stable binary layout for it across library releases; clean-rebuild the static library and every consumer object whenever updating the installed headers/archive pair.

## Performance notes

- The walker issues two SEH-guarded reads per call on the cold path: one for the COL pointer at `vtable - 8`, one batched read of the 24-byte `ColHead`. On MSVC each `__try` frame is essentially free on the success path. On MinGW each read uses the vectored fault guard, so the success path avoids the per-read `VirtualQuery` syscall; the batched ColHead read still matters because it keeps the walker to two guarded calls instead of four.
- `vtable_is_type` reads `expected.size() + 1` name bytes in a single SEH frame and compares with `memcmp`. There is no heap allocation, no string construction, and no demangle pass.
- `type_name_of` allocates one `std::string` per call. Prefer `type_name_into` or `vtable_is_type` when the allocation matters; on genuinely hot paths cache a `rtti::TypeIdentity`, since every walker call still runs the loader-querying COL prelude.
- `find_in_pointer_table` on a cold or stale cache scans every non-null slot with the full walker. With a valid warm cache it touches each slot once with a qword compare.

## When the walker returns nothing

The walker returns `std::nullopt` / `false` / `0` (depending on the call) for every recoverable failure:

- The vtable pointer is null or in the Windows reserved low-address range (`< 0x10000`).
- The vtable's COL pointer at `vtable - 8` is null, low, or unreadable.
- The COL's `pTypeDescriptor` RVA is zero.
- The vtable does not fall inside any loaded module (the loader lookup yields an invalid range), or the image base recovered from the COL (`col_addr - pSelf`) disagrees with the loader-reported module base -- the signature of a forged or relocated structure.
- The mangled-name buffer at the resolved address faults on the first page.

None of these raise an exception; the caller can treat all failure modes uniformly through the optional / bool return.

To tell a genuine miss from a module that simply has no MSVC RTTI to search (a `/GR-` host, a still-packed image, or a data-only module), call `rtti::region_has_rtti(range)`. A `true` means the module carries at least one record, not that your specific type resolves: a `/GR-` executable that links a `/GR` CRT or middleware returns `true` off those library COLs while an executable-owned type still needs the raw-byte fallback. A `false` is the "no resolvable RTTI record was found, fall back to `scan::find_string_xref` / `scan::read_code_constant`" signal, and it is safe to act on -- but it is not by itself proof of absence: if the sweep could not complete (a faulted section header or an unreadable page), a record may exist in the un-swept region. When that distinction matters, call `rtti::region_rtti_presence(range)`, which returns `RttiPresence::Incomplete` for a truncated sweep instead of collapsing it into a bare `false`. It is a setup/control-plane sweep like `vtable_for_type`, so call it once after a miss, never per frame.

## MinGW support

The walker works correctly on both MSVC and MinGW builds of DetourModKit when targeting MSVC-compiled binaries (the typical use case for game mods). The underlying guarded read engine behind `memory::read_into` uses `__try` / `__except` on MSVC and the process-wide vectored fault guard on MinGW. Both toolchains fail closed on unreadable RTTI pages and produce identical results for stable game state; MSVC remains faster because its x64 SEH tables add no success-path setup.

Note: the walker reads the MSVC RTTI ABI. If the target object uses the Itanium C++ ABI, the layout at `vtable - 8` differs and the walker fails closed.
