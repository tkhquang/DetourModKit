# Anchor Registry (`anchor.hpp`)

The Anchor Registry (`anchor.hpp`, `DetourModKit::anchor`) collapses patch-fragile constants into one declarative table that resolves at init and reports uniformly. It composes the existing self-healing backends documented in [aob-signatures.md](../../misc/aob-signatures.md), [rtti-walker.md](../rtti/rtti-walker.md), and [rtti-self-heal.md](../rtti/rtti-self-heal.md): `scan::resolve`, `scan::read_code_constant`, `scan::find_string_xref`, `scan::resolve_export`, and `rtti::vtable_for_type`. The module adds no scanner of its own; it adds the table, quorum corroboration, validators, and drift report.

## Anchor kinds

| `AnchorKind` | Backend | Resolves to |
|--------------|---------|-------------|
| `VtableIdentity` | `rtti::vtable_for_type` | A class vtable address, keyed on its mangled name |
| `RipGlobal` | `scan::resolve` | An absolute address (Direct or RIP-relative candidates) |
| `CodeOperand` | `scan::read_code_constant` | An in-code immediate or `[reg + disp]` displacement |
| `StringXref` | `scan::find_string_xref` | The instruction (or enclosing function) that references an immutable string literal |
| `ExportName` | `scan::resolve_export` | A named export, resolved by walking its module's PE Export Address Table (the most update-resilient kind) |
| `Manual` | none (pinned literal) | The literal, flagged as at-risk in a report |
| `CallArgHome` | reserved | Not yet resolvable (reports `Unsupported`) |
| `Quorum` | N-of-M vote across sub-anchors via `resolve` | The corroborated value, accepted only when at least N of M independent signals resolve and agree |
| `Unset` | none (fail-closed) | The default for an anchor whose `kind` was never set; always reports `Failed` |

`Anchor::kind` defaults to `Unset`, so a designated-initializer table entry that forgets to set `kind` fails closed (`AnchorStatus::Failed`) rather than silently resolving as a trusted `Manual` address 0. Declaring `Unset` is always a mistake; it exists so the mistake fails safe. Always set `kind` explicitly.

A `StringXref` anchor is the most update-resilient kind that anchors on in-image content (an `ExportName` is more resilient still when the target is a named export -- see below): it locates an immutable string literal in the image's read-only data and resolves the unique RIP-relative `lea` / `mov` that references it, returning that instruction (or, with `xref_return = scan::XrefReturn::EnclosingFunction`, the enclosing function's entry -- authoritative x64 `.pdata` bounds via `RtlLookupFunctionEntry`, with a heuristic prologue back-scan fallback -- or with `xref_return = scan::XrefReturn::StringPointerSlot`, the global data slot that a `mov [rip+slot], reg` caches the loaded pointer into -- see [String-reference anchors](../../misc/aob-signatures.md)). Strings survive game patches far better than the code bytes around them. It fails closed on a missing, duplicated (linker-pooled), or unreferenced string, so pick a long, specific literal that occurs and is referenced exactly once. Set `xref_encoding = scan::StringEncoding::Utf16le` for `wchar_t` literals; `xref_require_terminator` (default true) keeps a prefix of a longer literal from matching ("Player" inside "PlayerController"). `xref_broad_match` (default false) selects the phase-2 reference scan: the default shape scan matches only `REX.W lea` / `mov reg, [rip+disp32]`, while `xref_broad_match = true` keeps that scan and adds a Zydis-verified sweep for rarer shapes (`cmp [rip+d], imm`, `push [rip+d]`, a no-REX `lea` / `mov`). Use broad mode when the default reports a miss for a string you know is referenced, or when uniqueness must account for those rarer shapes before returning an enclosing function. See [String-reference anchors](../../misc/aob-signatures.md) for the full two-mode model.

An `ExportName` anchor is the most update-resilient kind of all: it resolves a named export by walking the target module's PE Export Address Table (`scan::resolve_export`). An export name is a module's documented ABI, so it survives a game patch far better than the code bytes, string literals, or absolute addresses the other backends key on -- an internal function may move or be rewritten every build, but an exported entry point keeps its name. Set `export_name` to the exact, case-sensitive symbol (no decoration), and `export_module` to the owning module's basename (e.g. `"engine.dll"`) when the export lives in a module other than the one the anchor is resolved against; an empty `export_module` resolves the export within the resolve scope, so an anchor on the scanned module's own export needs no module name. The walk is deterministic and loader-free (it parses the mapped image directly, never calling `GetProcAddress` or triggering a `DllMain`) and fails closed at every step: a missing export directory, an absent or ordinal-only name, an out-of-image RVA, or an unloaded module all report `Failed` with no invented address, and a *forwarded* export (one whose entry names another DLL's symbol as an ASCII string rather than code in this image) fails closed rather than returning the address of a string. This is export ANCHORING (reading the EAT to resolve an address); it is distinct from EAT HOOKING (patching the export table to redirect calls), which DetourModKit deliberately does not do.

`CallArgHome` is a reserved enumerator for a future prologue-dataflow backend (mapping a call argument to its current register or stack home); declaring it now keeps a registry table forward-compatible.

### Corroborating a critical target (`Quorum`)

For a target whose breakage would be costly, a single signal can be too weak: one AOB or code constant might resolve to a coincidental match after a patch. A `Quorum` anchor votes across `M` independent sub-anchors and accepts only when at least `N` of them resolve *and agree* (N-of-M voting), so a coincidental match has to fool a whole cluster at once -- and, unlike a strict pair, the target still corroborates when a game patch breaks some of the signals, as long as `N` of the rest still agree. List the members in `quorum_members` (non-owning pointers into your own anchor storage, kept alive across the `resolve` call), set `quorum_threshold` to `N`, and pick the agreement policy:

```cpp
// Corroborate a struct stride read from three independent code sites; any two agreeing is enough,
// so the stride still resolves when a patch shifts one of the three call sites.
const an::Anchor stride_a = {.kind = an::AnchorKind::CodeOperand, .site = k_equip_stride_a, .operand_index = 1};
const an::Anchor stride_b = {.kind = an::AnchorKind::CodeOperand, .site = k_equip_stride_b, .operand_index = 1};
const an::Anchor stride_c = {.kind = an::AnchorKind::CodeOperand, .site = k_equip_stride_c, .operand_index = 1};
const an::Anchor *stride_votes[] = {&stride_a, &stride_b, &stride_c};
const an::Anchor stride = {
    .label = "equip_stride",
    .kind = an::AnchorKind::Quorum,
    .quorum_members = stride_votes,
    .quorum_threshold = 2, // 2-of-3; the default 0 means unanimous (all members)
    .quorum_match = an::QuorumMatch::ExactValue, // or WithinTolerance + quorum_tolerance
};
```

`quorum_members` are non-owning pointers into your own anchor storage, so keep the members alive across the `resolve` call. `quorum_threshold` is `N`: `0` (the default) means unanimous, so a two-member quorum with the default is the strict 2-of-2 corroboration; a quorum is corroboration, so an explicit `N` below 2 or above the member count is a malformed vote and fails closed. `QuorumMatch::ExactValue` (the default) counts two member values as agreeing only when identical; `QuorumMatch::WithinTolerance` counts them as agreeing when their gap is at most `quorum_tolerance` (a negative tolerance fails closed, never accepts). On success `value` carries the accepting cluster's center -- the first member value, in declaration order, that at least `N` members agree with (under `ExactValue` every member of that cluster shares the value; under `WithinTolerance` the rest are within `quorum_tolerance` of it). It fails closed -- to `AnchorStatus::Failed` -- when fewer than `N` members agree, a member pointer is null, a member is itself a `Quorum` (nesting is bounded to one level), or fewer than two members are declared.

Before resolving, the members are checked for independence pairwise: corroboration only means something if every signal is genuinely separate evidence. If any pair is the same `Anchor` object used twice (pointer-equal), two pinned `Manual` literals (an author typing the same number twice is not live evidence), or the same backend with the same inputs (the same site decoded twice), the whole quorum reports `AnchorStatus::QuorumNotIndependent` instead of voting. The "same inputs" test compares by evidence CONTENT (the same address-independent fingerprint `anchor_fingerprint` folds -- compiled pattern bytes, wildcard mask, decode parameters, mangled name, or literal plus shape), not by view/span storage identity, so two *separately authored* candidate arrays that encode the same pattern DO trip the gate: they decode one identical site, so they are the same evidence twice, not two independent signals. Only genuinely different signals corroborate. Because a `WithinTolerance` near-match is looser than an exact one, this pairwise gate is what keeps it honest: it confines a tolerance vote to content-independent members, so a cluster of near values can never be an artifact of two members decoding adjacent bytes of one site.

### Post-resolve validators

Any backend-resolved anchor (not `Manual` or `CallArgHome`) may carry an optional `validator`: a `bool(*)(std::int64_t value, const void* context) noexcept` predicate run on the resolved value just before it is accepted. Returning `false` fails the anchor closed (`Failed`, value reset to 0), identical to a backend miss, so the caller re-heals by re-running `resolve`. Use it to assert a domain invariant a generic backend cannot know -- the target lies in an expected sub-range, a displacement points into `.rdata`, or the site begins with a plausible prologue (`scan::is_likely_function_prologue`). `validator_context` is an opaque pointer forwarded verbatim to the predicate (nullptr if unused). For a `Quorum`, the validator runs once on the corroborated value after the members vote.

Two opt-in policy flags harden this further (both default to preserving the existing behaviour):

- `validate_manual = true` runs the `validator` on a `Manual` anchor too, instead of taking the pinned literal unchecked -- so you can assert a domain invariant on a hand-pinned constant.
- `require_validator = true` rejects a backend-resolvable anchor that carries no `validator` at all (status `Failed`): a function/global target with no domain check is treated as unverified. A `Quorum` is exempt, because its N-of-M corroboration already is the verification.

When a target can be expressed more than one way, prefer the most update-resilient backend: `ExportName` > `StringXref` > `VtableIdentity` > `RipGlobal` > `CodeOperand`, with a `Quorum` voting over several of those raising confidence further and `Manual` as the last resort.

RTTI pointer-field offset healing (`rtti::heal_landmark`) is intentionally **not** a registry kind: it needs a runtime struct base that is itself resolved from another anchor, so it is driven directly once that base is known (see [rtti-self-heal.md](../rtti/rtti-self-heal.md)).

## Declaring and resolving a table

```cpp
#include "DetourModKit/anchor.hpp"

namespace an = DetourModKit::anchor;
namespace sc = DetourModKit::scan;

// One declarative candidate ladder per cascade-backed anchor. scan::Candidate owns its name and compiled Pattern, so
// these are `const` (not constexpr) arrays; Pattern::literal keeps the signature a compile-time-checked value.
const sc::Candidate k_world_sys[] = {
    sc::Candidate::rip_relative("world-sys", sc::Pattern::literal("48 8B 0D ?? ?? ?? ??"), 3, 7),
};
const sc::Candidate k_equip_stride[] = {
    sc::Candidate::direct("equip-stride", sc::Pattern::literal("48 6B C0 ?? 48 03 ??")),
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

A `RipGlobal` anchor scans `Pages::Readable` by default, which reaches a `Direct` rung that resolves a plain global address in `.rdata` / `.data`. When every rung of a `RipGlobal` ladder anchors on an in-image instruction (a RIP-relative reference whose pattern is code), set `.pages = sc::Pages::Executable` on the anchor so a coincidental byte twin in a data page cannot alias the site and demote a unique resolve to a fail-closed ambiguity. A manifest persists this non-default policy as `pages = executable`; an absent key remains `Readable` for compatibility. `CodeOperand` needs no such knob: `read_code_constant` scans code bytes and verifies that its final resolved site is execute-readable before decoding.

`resolve_all` writes one `ResolvedAnchor` per input (`{label, kind, status, value}`) and returns the count written. `value` carries the resolved quantity interpreted per kind (a vtable or global address cast to `std::int64_t`, an in-code constant, or the manual literal) and is meaningful only when `status == AnchorStatus::Resolved`. The scope defaults to `Region::host()`; pass an explicit `Region` (for example `Region::module_named("engine.dll")`) when the targets live in a separate module.

For startup tables whose anchors are independent, `resolve_all_parallel` resolves the same report through a fork-join worker pool:

```cpp
const std::size_t n = an::resolve_all_parallel(k_anchors, report, game_region, /*max_workers=*/4);
```

Each anchor still goes through the single-anchor `resolve` path, so backend failures, validators, quorum checks, and result ordering match `resolve_all`. The parallel resolver is opt-in because validators may run concurrently; use the serial `resolve_all` when a validator context is order-dependent or must be externally serialized.

## The drift report

The `ResolvedAnchor[]` array *is* the drift report. Walk it once at init to log what resolved, what failed, and what is pinned and therefore at risk:

```cpp
for (std::size_t i = 0; i < n; ++i)
{
    const auto &r = report[i];
    if (r.status != an::AnchorStatus::Resolved)
        log().warning("anchor {}: {}", r.label, an::anchor_status_to_string(r.status));
    else if (r.kind == an::AnchorKind::Manual)
        log().warning("anchor {}: pinned literal {:#x} (cannot self-heal)", r.label, r.value);
    else
        log().info("anchor {}: {:#x}", r.label, r.value);
}
```

Every backend already fails closed, so a missing constant surfaces as `AnchorStatus::Failed` (no value invented), and `Manual` anchors stand out as the ones a future patch can silently break.

`anchor::assess_quality(report)` rolls the same `ResolvedAnchor[]` into an `AnchorQuality` summary in one pass (no re-resolve): how many resolved, failed, are pinned `Manual` literals that cannot self-heal (`manual_at_risk`), or are corroborated quorums (the strongest evidence). It is a cheap, allocation-free way to gate "is this manifest healthy enough to run?" or to log a one-line robustness snapshot per build. The same summary is what `diagnostics::collect(drift_report, anchor_report)` folds into its `Snapshot.anchor_quality` field.

## Gating a feature on drift quality

Telemetry alone only describes health. `anchor::evaluate_gate` turns it into a decision, so startup can safe-disable a feature when its anchors did not resolve well enough instead of patching the game on addresses the manifest could not verify:

```cpp
// Resolve only the anchors this one feature depends on into its own report...
an::ResolvedAnchor report[std::size(camera_anchors)]{};
const std::size_t n = an::resolve_all(camera_anchors, report);

// ...then gate it. The default policy fails closed: every resolvable anchor must heal, zero failures.
switch (an::evaluate_gate(std::span{report, n}))
{
case an::GateVerdict::Pass:
    enable_camera_tweak();
    break;
case an::GateVerdict::Degraded:
    log().warning("camera tweak: pinned offset at risk");
    enable_camera_tweak();
    break;
case an::GateVerdict::Fail:
    log().error("camera tweak disabled: signatures drifted");
    break;
}
```

Because the gate reads a report (or a sub-span of one), feature-granular gating is just a matter of which anchors you resolve into which report: one primitive serves both a whole-manifest health check and a per-feature kill switch. A `GatePolicy` tunes the thresholds -- `min_resolved_ratio` (the fraction of *resolvable* anchors that must resolve; the unsupported `CallArgHome` kind is excluded from the denominator so a forward-compatible declaration never drags the score down), `max_failed` (a hard cap on `Failed` + `QuorumNotIndependent`), and `manual_at_risk_degrades` (whether a resolved-but-pinned `Manual` literal downgrades `Pass` to `Degraded`). A cosmetic overlay can afford a lower ratio than a frame-time camera patch that writes a live pointer, so hold one policy per feature. An empty report or a report with only unsupported anchors has nothing assessable and returns `Degraded`, never a false `Pass`.

## Anchor fingerprints

`anchor::anchor_fingerprint(anchor)` hashes only an anchor's *resolution evidence* -- its `AnchorKind` plus the inputs that backend uses (the `VtableIdentity` mangled name, the `RipGlobal` / `CodeOperand` compiled-Pattern bytes plus wildcard mask and decode parameters, the non-default `RipGlobal` page class, the `StringXref` literal and shape flags, the `ExportName` module and export name, or the `Manual` literal) -- and deliberately excludes the resolved address. `Pages::Readable` is omitted from a `RipGlobal` fingerprint to preserve existing baselines; `Pages::Executable` is folded because it changes the resolution policy. A candidate's cosmetic `name` and the anchor's `label` are excluded too, because neither changes which address resolves. Because `scan::Pattern` compiles the signature and does not retain its source AOB text, the cascade evidence is derived from the compiled content (the byte and wildcard-mask spans plus the result offset), which is equally stable across a diff and needs no re-parse.

The point is a diffable identity that is stable when only the address drifts. Persist a fingerprint next to each resolved value, and on the next game version a manifest diff can tell two cases apart:

- **Same evidence, new address** -- the fingerprint matches but the resolved value moved. This is expected drift the anchor self-healed; nothing to do.
- **New evidence path** -- the fingerprint changed, so the signature itself was rewritten (a new pattern, a renamed type, a different string). This is the entry to re-review.

A `Quorum` combines all member fingerprints order-independently (reordering `quorum_members` does not change the result) and folds in the effective vote threshold, agreement mode, and tolerance; a null member contributes a fixed sentinel. `CallArgHome` has no resolvable evidence yet, so its fingerprint reflects only the kind. The result is a 64-bit FNV-1a hash, stable across runs and builds on a given platform -- a diff key, not a cryptographic digest. The function reads only the anchor's declarative views, resolves nothing, and allocates nothing.

## Per-game scan profile

A `ScanProfile` (also in `anchor.hpp`) bundles a few setup-only, per-game scan-tuning defaults as a plain value -- no hidden global state. It supplies *defaults* only: an explicit per-call option (a query's `broad_match`, a request's candidate order) still wins, so wiring a profile never overrides an explicit choice.

- `default_broad_string_xref` widens the broad string-xref sweep on for `StringXref` anchors (it can only widen, never force off; a per-anchor `xref_broad_match` still wins). `anchor::apply_profile` folds this into a `scan::StringRefQuery`.
- `candidate_order` is a `scan::CandidateOrder`, reusing the scan module's ordering policy. `UniqueFirst` promotes the unique-only text tiers (RTTI and string xref) and anchored byte patterns ahead of looser byte fallbacks. `anchor::resolve_with_profile` applies it to `RipGlobal` (through the request's `order` field) and to `CodeOperand` (by building a local reordered ladder via `scan::order_candidates`), so the caller's static candidate table is never mutated.
- `deny_backend` is a per-`AnchorKind` deny-list.

Resolve a profile-aware table with `anchor::resolve_with_profile` / `resolve_all_with_profile`; use `resolve_all_with_profile_parallel` when the profile-aware table is safe to dispatch concurrently. A denied backend fails *closed* (status `Failed`, value 0) -- it is never silently replaced by a different, possibly-wrong backend -- and the profile threads into `Quorum` sub-anchors, so a denied sub-anchor kind fails the quorum closed and candidate-order / broad-string defaults stay uniform. The plain `resolve` / `resolve_all` are unchanged and equivalent to resolving with an empty profile.

## Re-heal on a validation miss

Resolution is idempotent and side-effect-free, so the registry keeps no hidden state: the resolved value lives in the `ResolvedAnchor` you hold. When a later sanity check shows a cached value has gone stale, re-run `resolve` on just that anchor:

```cpp
if (!still_valid(cached.value))
    cached = an::resolve(k_anchors[idx]); // fresh resolve; fail closed on miss
```

## Scope

Like the underlying resolvers, the registry defaults to the host EXE and accepts an explicit `Region`. Scoping is load-bearing for correctness, not just ergonomics: the same vtable name or instruction shape can exist in several loaded modules. Pass the game module's range when the target lives in a separate DLL.
