# RTTI self-heal (`rtti_dissect.hpp`)

The [RTTI walker](rtti-walker.md) answers the forward question: *given a vtable, what type is the object?* This module answers the inverse, slot-first questions a mod actually asks against a game binary that drifts across patches:

- **What object does this pointer slot refer to, and what is its type?** (`identify_pointee_type`)
- **Label every pointer field in this struct by RTTI type.** (`reverse_scan_block`)
- **A patch shifted the layout; where did the field of type `T` move to?** (`heal_landmark` / `heal_offset`)
- **Several fields co-moved; what single shift fits them all?** (`solve_fingerprint`)

It reuses the walker's verified COL prelude (module-bound-checked, SEH-guarded) rather than duplicating it, so every guarantee the walker makes carries over: every entry point is `noexcept`, every derived address is range-checked against its owning module before a read, and matching compares MSVC mangled bytes exactly (no `UnDecorateSymbolName`). Scope is x64 MSVC.

Everything here fails **closed**. Zero matches, an irreducible ambiguity, a forged COL, or an unmapped page is a clean error return -- never a fault, and never a silently-wrong offset.

## Why a mod wants this

A mod resolves a struct base once (typically via a `Scanner` cascade or an AOB anchor), then walks fixed field offsets inside it. A game patch that inserts or removes a member shifts every field after it by a few bytes, and the mod's hard-coded offset now reads garbage. Re-deriving the offset by hand and shipping a new build is the usual fix.

Self-heal automates that recovery. Record a landmark once:

> *"At offset `O` within struct `S` there is a pointer to an object of mangled type `T`."*

After a patch moves the pointer to `O' = O +/- delta`, `heal_landmark` scans a window of pointer-sized slots around `base + O`, reverse-RTTI-identifies each, and returns the slot whose pointee type equals `T`. The matched slot's offset is the healed `O'`. The mod caches the healed **offset** (a `std::ptrdiff_t`), never an absolute address, so the cached delta stays valid across instances and sessions.

The one constraint: `T` must be a type that is **stable across patches** (a base/engine type, not a game-specific most-derived subtype), because matching is byte-exact on the most-derived mangled name. A subtype rename defeats healing and fails closed via `NoMatch`.

## The four layers

| Layer | Symbol | Role | Allocates | Hot-path |
|-------|--------|------|-----------|----------|
| L1 | `identify_pointee_type` | Reverse-identify one slot | no | init-time contract |
| L2 | `reverse_scan_block[_bytes]` | RTTI-label a block of slots | yes | no (tooling/init) |
| L3 | `heal_landmark` / `heal_offset` | Self-heal one field offset | no | init / re-heal-on-miss |
| L4 | `solve_fingerprint` | Rigid multi-field drift recovery | no | init-time |

L3 is the primary deliverable. L4 degenerates exactly to L3 when given a single landmark.

## L1 -- `identify_pointee_type`

```cpp
Rtti::PointeeType pt;
if (Rtti::identify_pointee_type(slot_addr, pt))
{
    // pt.name()        -> the mangled type, e.g. ".?AVHealthComponent@game@@"
    // pt.was_pointer   -> true if the slot held a pointer-to-object
    // pt.object_base   -> the (sub)object base
    // pt.complete_obj  -> object_base - COL.offset (the most-derived object)
    // pt.vtable / pt.col_addr / pt.td_addr / pt.col_offset
}
```

It reads the qword at `slot_addr`, then accepts whichever of two shapes resolves through the verified prelude:

1. **Pointer-to-object** (tried first): the slot value is a pointer to an object; dereference once and resolve the pointee's vtable. `was_pointer` is set and `object_base` is the pointee.
2. **Direct object base**: the slot itself is the object, its value is the vtable. `was_pointer` is clear and `object_base` is `slot_addr`.

A classifier keyed on **module membership** of the slot value gives a false negative when an object's vtable lives in a different DLL than the struct (common for engine objects embedded in game structs). This module instead classifies by **resolvability** -- it tries the dereference and accepts whichever form resolves -- so a cross-DLL vtable still identifies. `was_pointer` is then a report, not a gate, and the policy layer (L3) decides whether a particular shape is required.

## L2 -- `reverse_scan_block`

```cpp
std::vector<Rtti::LabeledSlot> slots;
// reverse_scan_block returns the count appended; the dump loop iterates the
// vector instead, so the count is intentionally discarded.
(void)Rtti::reverse_scan_block(struct_base, 64, slots); // 64 pointer-sized slots
for (const auto &s : slots)
    Logger::get_instance().log(LogLevel::Debug, "[+{:#x}] {} {}",
        s.slot_index * sizeof(void *),
        s.type.was_pointer ? "->" : "(direct)",
        s.type.name());
```

The dump/triage face: *"tell me the RTTI type of every pointer field in this struct."* It **allocates** (grows the vector) and runs the syscall-heavy prelude per slot, so it is init-time / tooling only -- never the hot path. The `byte_len` overload divides by `stride` for you.

## L3 -- the self-healing resolver

```cpp
// Recorded once, lives in config (the in-code form is a static constexpr with a
// mangled string literal, mirroring the Scanner cascade tables):
static constexpr Rtti::Landmark k_health_ptr{
    .nominal_offset   = 0x2A0,
    .window           = 0x40,
    .expected_mangled = ".?AVHealthComponent@game@@",
};

// At init, or after a field read returns garbage:
Rtti::Landmark lm = k_health_ptr;
lm.base = resolved_player_struct;          // from a Scanner cascade / AOB anchor
if (const auto off = Rtti::heal_offset(lm))
    player_health_offset = *off;           // healed; feed into the pointer chain
else
    Logger::get_instance().log(LogLevel::Warning,
        "health landmark lost; binary changed too much -- re-author it");
```

`heal_landmark` returns the full `HealHit` (offset plus the matched slot, object, and vtable); `heal_offset` is the convenience wrapper returning just the offset that feeds straight into a `std::span<const std::ptrdiff_t>` pointer chain.

`HealHit::healed_offset` is the field's offset **within the struct base** (`slot_addr - base`) -- the value to feed into the chain. It equals `nominal_offset` when the layout did not drift, and `nominal_offset +/- delta` after a shift.

The algorithm:

1. **Descriptor validation** (`BadDescriptor`): low `base`, empty/oversized `expected_mangled`, unknown `indirection`, a `window` over `MAX_HEAL_WINDOW` (4096), or a nominal address outside the canonical user-mode window. No memory is touched.
2. **Nominal slot first.** If `base + nominal_offset` already resolves to `T` with the required shape, return immediately with `healed_offset == nominal_offset`. An unchanged offset -- or one with a same-typed neighbour in the window -- never reaches the ambiguity test.
3. **Widened grid scan, nearest first.** Step out by `stride` (default 8) within `[base + offset - window, base + offset + window]`. Candidate slots are congruent to the nominal slot modulo `stride`, so probes are always pointer-aligned. The nearest matching distance wins.
4. **Fail closed on ambiguity.** Zero matches -> `NoMatch`. A uniquely nearest match heals. Both the `+d` and `-d` slots matching at the nearest distance -> `Ambiguous`. A tie never guesses.

### Shape filter

`Landmark::indirection` is a soft policy filter over L1's resolvability result:

| Value | Matches |
|-------|---------|
| `PointerToObject` (default) | slots that held a pointer-to-object |
| `ObjectBase` | slots that were a direct object base |
| `Any` | either shape -- use when capture and heal may straddle a DLL boundary |

### The unique-match guard

This mirrors the module-scoped cascade's `require_unique` philosophy (`AddrCandidate::require_unique`, which fails closed when a second match exists), transplanted from an AOB pattern scan to a slot scan. Three refinements adapt it from code-address resolution (where patterns are intentionally specific) to data-layout healing (where same-typed neighbours are common):

1. The exact nominal slot is checked first and short-circuits, so an unchanged offset never reaches the ambiguity test.
2. On a widened scan, matches are probed nearest-to-nominal first; a uniquely nearest match heals, so a single far-away same-typed neighbour does not produce a dead mod.
3. Only an equidistant `+d` / `-d` pair latches `Ambiguous`.

Consumers see one consistent failure story: `Scanner::ResolveError::NoMatch` and `Rtti::HealError::NoMatch` / `Ambiguous` all mean "the binary changed too much, re-author the landmark," never a silent wrong heal.

## L4 -- `solve_fingerprint`

When several fields co-move and the window is dense with same-typed neighbours, a single landmark can go `Ambiguous`. A fingerprint records several `(offset, type)` landmarks captured once and demands that **one** uniform delta fit the whole template, which structurally disambiguates dense regions.

```cpp
static constexpr std::array<Rtti::Landmark, 3> k_player_fp{{
    {.nominal_offset = 0x2A0, .expected_mangled = ".?AVHealthComponent@game@@"},
    {.nominal_offset = 0x2C0, .expected_mangled = ".?AVInventory@game@@"},
    {.nominal_offset = 0x300, .expected_mangled = ".?AVStats@game@@"},
}};

if (const auto fit = Rtti::solve_fingerprint(player_base, k_player_fp, 0x40))
{
    // fit->delta -- the uniform byte shift; add it to each nominal offset.
    health_offset    = 0x2A0 + fit->delta;
    inventory_offset = 0x2C0 + fit->delta;
    stats_offset     = 0x300 + fit->delta;
}
```

It searches deltas in `[-window, +window]` stepping by pointer size, requires **every** landmark whose `required` flag is set (the default) to match at the shifted offset, and uses optional landmarks only to break ties. It fails closed: `NoMatch` when no delta fits, `Ambiguous` when two deltas tie for the most optional matches. `delta` is the drift to add to each landmark's `nominal_offset`. Given a single landmark it degenerates to `heal_landmark`.

## Drift telemetry -- `heal_report`

`heal_report(landmarks, out)` heals a whole set in one pass and writes a `DriftEntry` per landmark, so a patch's re-layout becomes a machine-readable diff for a changelog instead of a debugging session. It is a thin aggregation over `heal_landmark`: no extra reads, no allocation.

```cpp
Rtti::DriftEntry report[k_landmarks.size()];
const std::size_t n = Rtti::heal_report(k_landmarks, report);
for (std::size_t i = 0; i < n; ++i)
{
    const auto &e = report[i];
    if (!e.ok)
        log.warning("{}: heal failed ({})", e.name, Rtti::heal_error_to_string(e.error));
    else if (e.delta != 0)
        log.info("{}: moved {:+#x} ({:#x} -> {:#x})", e.name, e.delta, e.nominal_offset, e.healed_offset);
}
```

Each entry carries `{name, nominal_offset, healed_offset, delta, ok, error}`; `delta` (`healed_offset - nominal_offset`) is the headline number. The landmarks must already have their `base` filled in, exactly as for a direct `heal_landmark` call.

A drift report is the signal that a patch moved a layout. When it shows a field the heal could not recover (`ok == false`, for example a type that was renamed across the patch and so no longer matches by name), that is a job for a mod update by someone who understands the engine, not something to paper over with a hand-edited offset: a wrong offset reads the wrong memory just as confidently as a right one. DetourModKit deliberately ships no persisted, user-editable heal file for that reason; the recipe (the `Landmark` set) lives in mod code.

## Performance and the init-time contract

`Memory::module_range_for` issues a `GetModuleHandleEx` lookup on **every** call, even a cache hit. `identify_pointee_type` calls it up to twice per slot, so a naive window scan is thousands of syscalls. Therefore `heal_landmark`, `solve_fingerprint`, and `reverse_scan_block` are documented **init-time / re-heal-on-miss**, not per-frame. The `window` is capped at `MAX_HEAL_WINDOW` (4096 bytes, 512 slots per side) so the worst case is bounded, and `heal_landmark` reuses one stack `PointeeType` so the heal path allocates nothing.

## Failure modes (all fail closed)

| Mode | Handling |
|------|----------|
| `slot` / `base` below `0x10000` | L1 `false`; L3 `BadDescriptor`. No memory touched. |
| Unmapped page at a slot | the SEH-guarded read returns nothing -> non-match, never a fault. |
| Slot is neither a pointer-to-object nor a direct vtable | both resolve attempts fail -> slot skipped. |
| Forged COL / non-x64 signature / `pSelf` mismatch / out-of-range RVA | the prelude's bound-check + cross-check guards reject it -> slot skipped. |
| Empty/oversized name, bad enum, `window` over the cap | `BadDescriptor` before any read. |
| No drift (nominal still matches) | nominal-first short-circuit returns before the scan. |
| Zero matching slots | `NoMatch` -- never the nominal offset as a guess. |
| Equidistant `+d` / `-d` matches | `Ambiguous`. |
| Cross-DLL vtable | classification by resolvability still resolves; record `Indirection::Any` when straddling a DLL boundary. |
| Subtype rename across a patch | `NoMatch`. Key the landmark on a stable base type instead. |

## Relation to the walker

The walker runs vtable -> name; this module runs slot -> object -> name and adds the offset-recovery policy on top. Both share the same `resolve_col_site` prelude internally, so the two compose into one fail-closed resilience story: resolve the struct base via a module-scoped `Scanner::resolve_cascade`, then heal field offsets inside it via `heal_landmark` -- one contract across both code-address and data-layout drift.

## Prior art and acknowledgements

The reverse-direction design here -- identifying an object from its vtable, RTTI-labelling a block of pointer slots (`reverse_scan_block`), and the `COL.offset` handling for multiple-inheritance secondary subobjects -- was inspired by the **CERTTIExplorer** Cheat Engine script in [Frans Bouma](https://github.com/FransBouma)'s (Otis_Inf) [InjectableGenericCameraSystem](https://github.com/FransBouma/InjectableGenericCameraSystem/tree/master/Tools/CERTTIExplorer) (BSD-2-Clause). That tool was originally written by [**GhostInTheCamera**](https://github.com/ghostinthecamera) from the [FramedSC RTTI guide](https://framedsc.com/GeneralGuides/using_rtti.htm) (distilled from Hatti's video), with COL-validation refinements credited to **etra**.

No code was copied: this is an independent C++ reimplementation of the same MSVC RTTI techniques (a widely documented walk: COL -> TypeDescriptor -> mangled name, and its inverse). The credit is for the design ideas and for the nudge to add the block/reverse-range lookup and multiple-inheritance offset handling. Thanks to Otis for sharing the script.
