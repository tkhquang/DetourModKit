# Anchor Registry (`anchors.hpp`)

A mod against a fast-patching game accumulates a wall of patch-fragile constants: a vtable matched by literal, a global resolved by AOB, a struct stride read out of a dispatch loop, the occasional pinned offset. The Anchor Registry collapses that wall into one declarative table. Each constant is declared once with the kind of anchor it is and the inputs its backend needs; the whole table is resolved at init and reported uniformly, so "this mod is broken on the new patch" becomes a precise, machine-readable diff instead of a debugging session.

The registry unifies the self-healing backends that resolve from a module range alone. It is the consolidation layer over the primitives documented in [aob-signatures.md](aob-signatures.md), [rtti-walker.md](rtti-walker.md), and [rtti-self-heal.md](rtti-self-heal.md).

## Anchor kinds

| `AnchorKind` | Backend | Resolves to |
|--------------|---------|-------------|
| `VtableIdentity` | `Rtti::vtable_for_type` | A class vtable address, keyed on its mangled name |
| `RipGlobal` | `Scanner::resolve_cascade_in_module` | An absolute address (Direct or RIP-relative candidates) |
| `CodeOperand` | `Scanner::read_code_constant` | An in-code immediate or `[reg + disp]` displacement |
| `StringXref` | `Scanner::find_string_xref` | The instruction (or enclosing function) that references an immutable string literal |
| `Manual` | none (pinned literal) | The literal, flagged as at-risk in a report |
| `CallArgHome` | reserved | Not yet resolvable (reports `Unsupported`) |
| `Quorum` | two sub-anchors via `resolve` | The corroborated value, accepted only when both independent signals resolve and agree |

A `StringXref` anchor is the most update-resilient kind: it locates an immutable string literal in the image's read-only data and resolves the unique RIP-relative `lea` / `mov` that references it, returning that instruction (or, with `xref_return = XrefReturn::EnclosingFunction`, a best-effort prologue back-scan to the function that uses it). Strings survive game patches far better than the code bytes around them. It fails closed on a missing, duplicated (linker-pooled), or unreferenced string, so pick a long, specific literal that occurs and is referenced exactly once. Set `xref_encoding = StringEncoding::Utf16le` for `wchar_t` literals; `xref_require_terminator` (default true) keeps a prefix of a longer literal from matching ("Player" inside "PlayerController"). `xref_broad_match` (default false) selects the phase-2 reference scan: the default shape scan matches only `REX.W lea` / `mov reg, [rip+disp32]`, while `xref_broad_match = true` keeps that scan and adds a Zydis-verified sweep for rarer shapes (`cmp [rip+d], imm`, `push [rip+d]`, a no-REX `lea` / `mov`). Reach for it only when the default reports a miss for a string you know is referenced. See [String-reference anchors](aob-signatures.md) for the full two-mode model.

`CallArgHome` is a reserved enumerator for a future prologue-dataflow backend (mapping a call argument to its current register or stack home); declaring it now keeps a registry table forward-compatible.

### Corroborating a critical target (`Quorum`)

For a target whose breakage would be costly, a single signal can be too weak: one AOB or code constant might resolve to a coincidental match after a patch. A `Quorum` anchor requires two independent sub-anchors to resolve *and agree* before it accepts a value, so a coincidental match has to fool both signals at once. Point `quorum_a` and `quorum_b` at two sub-anchors of any resolvable kind (the canonical pair is a `StringXref` plus a `CodeOperand`) and pick the agreement policy:

```cpp
// Corroborate a struct stride: two independent code sites must agree on it.
const an::Anchor stride_code = {.kind = an::AnchorKind::CodeOperand,
                                .site = k_equip_stride, .operand_index = 1};
const an::Anchor stride_alt = {.kind = an::AnchorKind::CodeOperand,
                               .site = k_equip_stride_alt, .operand_index = 1};
const an::Anchor stride = {
    .label = "equip_stride",
    .kind = an::AnchorKind::Quorum,
    .quorum_a = &stride_code,
    .quorum_b = &stride_alt,
    .quorum_match = an::QuorumMatch::ExactValue, // or WithinTolerance + quorum_tolerance
};
```

`quorum_a` / `quorum_b` are non-owning pointers into your own anchor storage, so keep the sub-anchors alive across the `resolve` call. `QuorumMatch::ExactValue` (the default) requires the two resolved values to be identical; `QuorumMatch::WithinTolerance` accepts a gap of at most `quorum_tolerance` (a negative tolerance fails closed, never accepts). On success `value` carries the first sub-anchor's value, which by construction equals the second under the policy. It fails closed -- to `AnchorStatus::Failed` -- when either signal fails, the two disagree, a sub-anchor pointer is null, or a sub-anchor is itself a `Quorum` (nesting is bounded to one level).

### Post-resolve validators

Any backend-resolved anchor (not `Manual` or `CallArgHome`) may carry an optional `validator`: a `bool(*)(std::int64_t value, const void* context) noexcept` predicate run on the resolved value just before it is accepted. Returning `false` fails the anchor closed (`Failed`, value reset to 0), identical to a backend miss, so the caller re-heals by re-running `resolve`. Use it to assert a domain invariant a generic backend cannot know -- the target lies in an expected sub-range, a displacement points into `.rdata`, or the site begins with a plausible prologue (`Scanner::is_likely_function_prologue`). `validator_context` is an opaque pointer forwarded verbatim to the predicate (nullptr if unused). For a `Quorum`, the validator runs once on the corroborated value after both sub-anchors agree.

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
