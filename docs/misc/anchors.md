# Anchor Registry (`anchors.hpp`)

A mod against a fast-patching game accumulates a wall of patch-fragile constants: a vtable matched by literal, a global resolved by AOB, a struct stride read out of a dispatch loop, the occasional pinned offset. The Anchor Registry collapses that wall into one declarative table. Each constant is declared once with the kind of anchor it is and the inputs its backend needs; the whole table is resolved at init and reported uniformly, so "this mod is broken on the new patch" becomes a precise, machine-readable diff instead of a debugging session.

The registry unifies the self-healing backends that resolve from a module range alone. It is the consolidation layer over the primitives documented in [aob-signatures.md](aob-signatures.md), [rtti-walker.md](rtti-walker.md), and [rtti-self-heal.md](rtti-self-heal.md).

## Anchor kinds

| `AnchorKind` | Backend | Resolves to |
|--------------|---------|-------------|
| `VtableIdentity` | `Rtti::vtable_for_type` | A class vtable address, keyed on its mangled name |
| `RipGlobal` | `Scanner::resolve_cascade_in_module` | An absolute address (Direct or RIP-relative candidates) |
| `CodeOperand` | `Scanner::read_code_constant` | An in-code immediate or `[reg + disp]` displacement |
| `Manual` | none (pinned literal) | The literal, flagged as at-risk in a report |
| `CallArgHome` | reserved | Not yet resolvable (reports `Unsupported`) |

`CallArgHome` is a reserved enumerator for a future prologue-dataflow backend (mapping a call argument to its current register or stack home); declaring it now keeps a registry table forward-compatible.

RTTI pointer-field offset healing (`Rtti::heal_landmark`) is intentionally **not** a registry kind: it needs a runtime struct base that is itself resolved from another anchor, so it is driven directly once that base is known (see [rtti-self-heal.md](rtti-self-heal.md)).

## Declaring and resolving a table

```cpp
#include "DetourModKit/anchors.hpp"

namespace an = DetourModKit::Anchors;
namespace sc = DetourModKit::Scanner;

// One declarative table, typically static.
static constexpr sc::AddrCandidate k_world_sys[] = {
    {"world-sys", "48 8B 0D ?? ?? ?? ??", sc::ResolveMode::RipRelative, 3, 7},
};
static constexpr sc::AddrCandidate k_equip_stride[] = {
    {"equip-stride", "48 6B C0 ?? 48 03 ...", sc::ResolveMode::Direct, 0, 0},
};

const an::Anchor k_anchors[] = {
    {.label = "audio_vtable", .kind = an::AnchorKind::VtableIdentity,
     .mangled = ".?AVGameAudioEffect@engine@@"},
    {.label = "world_system", .kind = an::AnchorKind::RipGlobal, .site = k_world_sys},
    {.label = "equip_stride", .kind = an::AnchorKind::CodeOperand, .site = k_equip_stride,
     .operand_kind = sc::OperandKind::Immediate, .operand_index = 1},
    {.label = "fallback_off", .kind = an::AnchorKind::Manual, .manual_value = 0x1C8},
};

an::ResolvedAnchor report[std::size(k_anchors)];
const std::size_t n = an::resolve_all(k_anchors, report);
```

`resolve_all` writes one `ResolvedAnchor` per input (`{label, kind, status, value}`) and returns the count written. `value` carries the resolved quantity interpreted per kind (a vtable or global address cast to `uintptr_t`, an in-code constant, or the manual literal) and is meaningful only when `status == AnchorStatus::Resolved`.

## The drift report

The `ResolvedAnchor[]` array *is* the drift report. Walk it once at init to log what resolved, what failed, and what is pinned and therefore at risk:

```cpp
for (std::size_t i = 0; i < n; ++i)
{
    const auto &r = report[i];
    if (r.status != an::AnchorStatus::Resolved)
        log.warning("anchor {}: {}", r.label, an::anchor_status_to_string(r.status));
    else if (r.kind == an::AnchorKind::Manual)
        log.warning("anchor {}: pinned literal {:#x} (cannot self-heal)", r.label, r.value);
    else
        log.info("anchor {}: {:#x}", r.label, r.value);
}
```

Every backend already fails closed, so a missing constant surfaces as `AnchorStatus::Failed` (no value invented), and `Manual` anchors stand out as the ones a future patch can silently break.

## Re-heal on a validation miss

Resolution is idempotent and side-effect-free, so the registry keeps no hidden state: the resolved value lives in the `ResolvedAnchor` you hold. When a later sanity check shows a cached value has gone stale, re-run `resolve` on just that anchor:

```cpp
if (!still_valid(cached.value))
    cached = an::resolve(k_anchors[idx]); // fresh resolve; fail closed on miss
```

## Scope

Like the underlying resolvers, the registry defaults to the host EXE and accepts an explicit `Memory::ModuleRange`. Scoping is load-bearing for correctness, not just ergonomics: the same vtable name or instruction shape can exist in several loaded modules. Pass the game module's range when the target lives in a separate DLL.
