# RTTI self-heal (`rtti_dissect.hpp`)

The [RTTI walker](rtti-walker.md) answers the forward question: *given a vtable, what type is the object?* This module answers the inverse, slot-first questions a mod actually asks against a game binary that drifts across patches:

- **What object does this pointer slot refer to, and what is its type?** (`identify_pointee_type`)
- **Label every pointer field in this struct by RTTI type.** (`reverse_scan_block`)
- **A patch shifted the layout; where did the field of type `T` move to?** (`heal_landmark`)
- **Several fields co-moved; what single shift fits them all?** (`solve_fingerprint`)
- **Run those heals on a frame cadence, latch each group once it resolves, and warn once when the layout actually drifted.** (`HealScheduler`)

It reuses the walker's verified COL prelude (module-bound-checked, SEH-guarded) rather than duplicating it, so every guarantee the walker makes carries over: every non-scheduler entry point is `noexcept` (of the scheduler surface, only the setup call `add_group` may allocate and throw), every derived address is range-checked against its owning module before a read, and matching compares MSVC mangled bytes exactly (no `UnDecorateSymbolName`). Scope is x64 MSVC.

Everything here fails **closed** on zero matches, an irreducible ambiguity, a forged COL, or an unmapped page -- a clean error return, never a fault. One documented fail-wrong hazard remains: a single-landmark heal resolves to the uniquely *nearest* type+shape match, so a strictly-nearer same-typed decoy field (or, under `ObjectBase` / `Any`, a nearer multiple-inheritance secondary base) wins silently and returns a confidently-wrong offset; `HealAmbiguous` fires only for an exact `+d` / `-d` distance tie. When the window may hold more than one field of the landmark type, prefer `solve_fingerprint` (one uniform delta must fit every field), narrow the `window`, or tighten the type.

## Why a mod wants this

A mod resolves a struct base once (typically via a `scan::resolve` cascade or an AOB anchor), then walks fixed field offsets inside it. A game patch that inserts or removes a member shifts every field after it by a few bytes, and the mod's hard-coded offset now reads garbage. Re-deriving the offset by hand and shipping a new build is the usual fix.

Self-heal automates that recovery. Record a landmark once:

> *"At offset `O` within struct `S` there is a pointer to an object of mangled type `T`."*

After a patch moves the pointer to `O' = O +/- delta`, `heal_landmark` scans a window of pointer-sized slots around `base + O`, reverse-RTTI-identifies each, and returns the slot whose pointee type equals `T`. The matched slot's offset is the healed `O'`. The mod caches the healed **offset** (a `std::ptrdiff_t`), never an absolute address, so the cached delta stays valid across instances and sessions.

The one constraint: `T` must be a type that is **stable across patches** (a base/engine type, not a game-specific most-derived subtype), because matching is byte-exact on the most-derived mangled name. A subtype rename defeats healing and fails closed via `HealNoMatch`.

All addresses on this surface are the value-typed `Address` (from `address.hpp`). The typed resolvers (`identify_pointee_typed`, `heal_landmark`, `solve_fingerprint`) return `Result<T>` over the unified `ErrorCode`; the boolean `identify_pointee_type` and the count-returning `reverse_scan_block` keep their lightweight shapes rather than a `Result`. RTTI failures use the `ErrorCategory::Rtti` block: `BadSlotAddress` / `UnreadableSlot` / `NoRtti` / `BadDescriptor` / `HealNoMatch` / `HealAmbiguous`.

## The layers

| Layer | Symbol | Role | Allocates | Hot-path |
|-------|--------|------|-----------|----------|
| L1 | `identify_pointee_type` | Reverse-identify one slot | no | init-time contract |
| L2 | `reverse_scan_block[_bytes]` | RTTI-label a block of slots | yes | no (tooling/init) |
| L3 | `heal_landmark` | Self-heal one field offset | no | init / re-heal-on-miss |
| L4 | `solve_fingerprint` | Rigid multi-field drift recovery | no | init-time |
| L5 | `HealScheduler` | Drive the heals on a frame cadence, latch per group, warn once | no | per-frame `tick()` (gated) |

L3 is the primary deliverable. L4 degenerates to a single-field solve when given one landmark -- stricter than L3: there is no nominal short-circuit, and any second matching delta in the window (not just an equidistant pair) fails `HealAmbiguous`, unless the zero-drift delta itself matches. `solve_fingerprint` prefers `delta == 0` on a tie: when the caller's anchor still validates every required landmark, the object is exactly where the caller anchored (the no-drift reading, which also resolves an array of same-typed objects to element 0), so it wins outright over a tied non-zero shift. Ambiguity is reserved for a tie between two non-zero deltas, where neither candidate is the anchor. L5 is the render-loop driver that ties them into a fixed-cadence, fail-closed retry loop.

## L1 -- `identify_pointee_type`

```cpp
rtti::PointeeType pt;
if (rtti::identify_pointee_type(slot_addr, pt)) // slot_addr is an Address
{
    // pt.name()        -> the mangled type, e.g. ".?AVHealthComponent@game@@"
    // pt.was_pointer   -> true if the slot held a pointer-to-object
    // pt.object_base   -> the (sub)object base (an Address)
    // pt.complete_obj  -> object_base - COL.offset (the most-derived object)
    // pt.vtable / pt.col_addr / pt.td_addr / pt.col_offset
}
```

The typed form `identify_pointee_typed` returns `Result<void>` with the specific fail-closed reason (`BadSlotAddress` / `UnreadableSlot` / `NoRtti`); the `bool` form above is exactly `has_value()` over it.

It reads the qword at `slot_addr`, then accepts whichever of two shapes resolves through the verified prelude:

1. **Pointer-to-object** (tried first): the slot value is a pointer to an object; dereference once and resolve the pointee's vtable. `was_pointer` is set and `object_base` is the pointee.
2. **Direct object base**: the slot itself is the object, its value is the vtable. `was_pointer` is clear and `object_base` is `slot_addr`.

A classifier keyed on **module membership** of the slot value gives a false negative when an object's vtable lives in a different DLL than the struct (common for engine objects embedded in game structs). This module instead classifies by **resolvability** -- it tries the dereference and accepts whichever form resolves -- so a cross-DLL vtable still identifies. `was_pointer` is then a report, not a gate, and the policy layer (L3) decides whether a particular shape is required.

## L2 -- `reverse_scan_block`

```cpp
std::vector<rtti::LabeledSlot> slots;
// reverse_scan_block returns the count appended; the dump loop iterates the
// vector instead, so the count is intentionally discarded.
(void)rtti::reverse_scan_block(struct_base, 64, slots); // 64 pointer-sized slots
for (const auto &s : slots)
    log().log(LogLevel::Debug, "[+{:#x}] {} {}",
        s.slot_index * sizeof(void *),
        s.type.was_pointer ? "->" : "(direct)",
        s.type.name());
```

The dump/triage face: *"tell me the RTTI type of every pointer field in this struct."* It **allocates** (grows the vector) and runs the syscall-heavy prelude per slot, so it is init-time / tooling only -- never the hot path. The `byte_len` overload divides by `stride` for you.

## L3 -- the self-healing resolver

```cpp
// Recorded once, lives in mod code (the Landmark OWNS its mangled name, so it is
// self-contained and safe to build from a literal, a config value, or a view):
const rtti::Landmark k_health_ptr{
    .nominal_offset   = 0x2A0,
    .window           = 0x40,
    .expected_mangled = ".?AVHealthComponent@game@@",
};

// At init, or after a field read returns garbage:
rtti::Landmark lm = k_health_ptr;
lm.base = resolved_player_struct;          // an Address from a scan::resolve ladder / AOB anchor
if (const auto hit = rtti::heal_landmark(lm))
    player_health_offset = hit->healed_offset; // healed; feed into the pointer chain
else
    log().warning("health landmark lost ({}); binary changed too much -- re-author it",
                  hit.error().message());
```

`heal_landmark` returns the full `HealHit` (offset plus the matched slot, object, and vtable) as a `Result`, so a caller that only needs the offset takes `hit->healed_offset` and one that needs to diagnose a miss reads `hit.error()`. Because `HealScheduler` (L5) publishes the healed offset to a caller-owned atomic slot on success and keeps the nominal on a miss, a mod that heals on the render loop rarely calls `heal_landmark` directly.

`HealHit::healed_offset` is the field's offset **within the struct base** (`slot_addr - base`) -- the value to feed into the chain. It equals `nominal_offset` when the layout did not drift, and `nominal_offset +/- delta` after a shift.

The algorithm:

1. **Descriptor validation** (`BadDescriptor`): low `base`, empty/oversized `expected_mangled`, unknown `indirection`, a `window` over `MAX_HEAL_WINDOW` (4096), or a nominal address outside the canonical user-mode window. No memory is touched.
2. **Nominal slot first.** If `base + nominal_offset` already resolves to `T` with the required shape, return immediately with `healed_offset == nominal_offset`. An unchanged offset -- or one with a same-typed neighbour in the window -- never reaches the ambiguity test.
3. **Widened grid scan, nearest first.** Step out by `stride` (default 8) within `[base + offset - window, base + offset + window]`. Candidate slots are congruent to the nominal slot modulo `stride`, so probes are always pointer-aligned. The nearest matching distance wins.
4. **Fail closed on ambiguity.** Zero matches -> `HealNoMatch`. A uniquely nearest match heals. Both the `+d` and `-d` slots matching at the nearest distance -> `HealAmbiguous`. A tie never guesses.

### Shape filter

`Landmark::indirection` is a soft policy filter over L1's resolvability result:

| Value | Matches |
|-------|---------|
| `PointerToObject` (default) | slots that held a pointer-to-object |
| `ObjectBase` | a direct object base (any subobject, including a multiple-inheritance secondary) |
| `CompleteObject` | a direct object base that is the primary subobject (`COL.offset == 0`) -- the multiple-inheritance-safe `ObjectBase` |
| `Any` | either shape -- use when capture and heal may straddle a DLL boundary |

### Multiple inheritance and the complete object

Under multiple inheritance each base subobject has its own vtable, and every one of those vtables' COLs names the *same* most-derived type -- only `COL.offset` differs (it is the subobject's byte offset within the complete object, `0` for the primary). A direct-object heal keyed on `ObjectBase` (or `Any`) compares only the mangled name, so it can match a *secondary* base's vtable and report an offset shifted by that subobject delta. The most dangerous form is through the nominal-first short-circuit: an upstream member removal can land a secondary vtable exactly on the old offset, and the heal then reports `delta == 0` ("did not move") while pointing `COL.offset` bytes into the object -- silent and confidently wrong.

`CompleteObject` closes this. It matches only the primary subobject (`COL.offset == 0`), so the healed offset is always the true complete-object base; prefer it for any embedded object that may use multiple inheritance. Consumers that stay on `ObjectBase` / `Any` can still detect the direct-object case after the fact: `HealHit::col_offset` reports the matched subobject delta, and when `was_pointer == false`, a nonzero value means the slot was a secondary base.

### The unique-match guard

This mirrors the scan resolver's `require_unique` philosophy (`ScanRequest::require_unique`, which fails closed when a second match exists), transplanted from an AOB pattern scan to a slot scan. Three refinements adapt it from code-address resolution (where patterns are intentionally specific) to data-layout healing (where same-typed neighbours are common):

1. The exact nominal slot is checked first and short-circuits, so an unchanged offset never reaches the ambiguity test.
2. On a widened scan, matches are probed nearest-to-nominal first; a uniquely nearest match heals, so a single far-away same-typed neighbour does not produce a dead mod.
3. Only an equidistant `+d` / `-d` pair latches `Ambiguous`.

Consumers see one consistent failure story: `ErrorCode::NoMatch` (from a `scan::resolve` cascade) and `ErrorCode::HealNoMatch` / `HealAmbiguous` (from a heal) all mean "the binary changed too much, re-author the landmark." Refinement 2 is also the residual fail-wrong hazard: a strictly-nearer same-typed decoy wins silently over the intended field, and `HealAmbiguous` fires only for the exact equidistant tie -- a window that may hold several fields of the landmark type belongs to `solve_fingerprint`.

## L4 -- `solve_fingerprint`

When several fields co-move and the window is dense with same-typed neighbours, a single landmark can go `Ambiguous`. A fingerprint records several `(offset, type)` landmarks captured once and demands that **one** uniform delta fit the whole template, which structurally disambiguates dense regions.

```cpp
const std::array<rtti::Landmark, 3> k_player_fp{{
    {.nominal_offset = 0x2A0, .expected_mangled = ".?AVHealthComponent@game@@"},
    {.nominal_offset = 0x2C0, .expected_mangled = ".?AVInventory@game@@"},
    {.nominal_offset = 0x300, .expected_mangled = ".?AVStats@game@@"},
}};

if (const auto fit = rtti::solve_fingerprint(player_base, k_player_fp, 0x40))
{
    // fit->delta -- the uniform byte shift; add it to each nominal offset.
    health_offset    = 0x2A0 + fit->delta;
    inventory_offset = 0x2C0 + fit->delta;
    stats_offset     = 0x300 + fit->delta;
}
```

It searches deltas in `[-window, +window]` stepping by pointer size, requires **every** landmark whose `required` flag is set (the default) to match at the shifted offset, and uses optional landmarks only to break ties. It fails closed: `HealNoMatch` when no delta fits, `HealAmbiguous` when two deltas tie for the most optional matches. `delta` is the drift to add to each landmark's `nominal_offset`. Given a single landmark it degenerates to a single-field solve that is stricter than `heal_landmark`: there is no nominal short-circuit, and any second matching delta in the window (not just an equidistant `+d` / `-d` pair) fails `HealAmbiguous`.

## L5 -- `HealScheduler` (the render-loop driver)

L1-L4 answer *where did the field move?* once. `HealScheduler` answers the render-loop question on top of them: *when do I re-check, and how do I not spam the log while a target is still loading?* It captures the discipline every self-healing offset cache hand-rolls -- a fixed retry interval, a per-group success latch, and a one-shot "the layout drifted" warning -- into one reusable primitive so a mod's heal code shrinks to a table of landmarks plus a `tick()` on the render thread.

```cpp
// One process-wide cache slot per offset (the render thread reads these every frame; the heal writes them once).
rtti::HealedSlot s_health_off;

auto healer = rtti::HealScheduler::start({.interval_frames = 30}); // 0 -> ErrorCode::InvalidArg
// ... check healer, then:
rtti::HealScheduler &sched = *healer;
s_health_off.seed_nominal(0x2A0);

sched.add_group(
    // work: heal from the live base; return true to latch the group.
    [&](rtti::HealRun &run) noexcept
    {
        return run.heal_into("health", k_health_ptr, resolved_player_base, s_health_off).has_value();
    },
    // gate (optional): a cheap per-frame precondition. false -> skip silently, do NOT spend the interval.
    []() noexcept { return player_is_seated(); });

// On the render thread, once per frame:
sched.tick();
```

- **Fixed interval, not backoff.** An un-latched group re-scans every `interval_frames` frames (default 30, ~0.5s at 60 FPS) with **no attempt cap**: however long a load or a menu takes, it keeps retrying, then latches once it resolves. The scan frame itself does not consume a countdown tick, so scans land on frames `0`, `interval + 1`, `2*(interval) + 2`, ... exactly.
- **Per-group latch.** Each `add_group` is independent. A group that resolves stops being scanned; a sibling that has not keeps retrying. `all_resolved()` reports whether every group has latched.
- **Silent pre-gate.** A group's optional `gate` runs *before* the interval countdown, so a target that is not constructed yet is polled cheaply every frame and skipped without spending the retry budget -- the moment the gate opens, the group scans immediately.
- **`heal_into` is fail-closed.** On a hit it publishes `healed_offset` to the caller-owned slot and logs the recovery (a moved field at Info; a confirmation at nominal at Debug). On a miss it leaves the slot's value untouched (its seeded nominal, never a guess) and logs per the config's `escalate` policy and the call's `required` flag.
- **Consume through a `HealedSlot`, not a raw atomic, when the offset authorizes a write.** The raw `std::atomic<std::ptrdiff_t>` overload carries only the value: after a required miss it holds the seeded, possibly dangerous nominal with no in-band failure signal. It remains for read-only compatibility use. The `HealedSlot` overload publishes `{value, generation, validity}`: a resolve is `Confirmed` and carries the resolved vtable image's generation; a **required** miss is `Invalid` with generation `0`; an **optional** miss is `Unverified` with generation `0`. `authorized()` checks validity, while `authorized(current_generation)` also rejects a stale or zero generation; obtain the current value from a live vtable in the target image. Seed the slot so reads before the first heal are explicitly `Unverified`.
- **Warn once.** The first realised drift across all groups whose `|delta|` exceeds `HealConfig::drift_warn_threshold` (default `0` == any nonzero drift) fires a single process-wide Warning (a CAS one-shot). The recovered pointer offsets self-healed, but non-healable scalar/flag offsets in the same structs silently rode the same shift and need a human to re-verify -- that is the actionable headline the one line carries. A corroborated bracket that writes its own slots (via `solve_fingerprint`) reports its moves through `HealRun::note_drift` so the same one-shot fires consistently.

The scheduler is move-only and render-thread only; the offset slots are the cross-thread channel, not the scheduler itself. `tick()` is non-reentrant: a work or gate callback that calls `tick()` again on the same scheduler is rejected as a no-op, so it cannot corrupt the in-flight scan.

## Drift telemetry -- `heal_report`

`heal_report(landmarks, out)` heals a whole set in one pass and writes a `DriftEntry` per landmark, so a patch's re-layout becomes a machine-readable diff for a changelog instead of a debugging session. It is a thin aggregation over `heal_landmark`: no extra reads, no allocation.

```cpp
rtti::DriftEntry report[k_landmarks.size()];
const std::size_t n = rtti::heal_report(k_landmarks, report);
for (std::size_t i = 0; i < n; ++i)
{
    const auto &e = report[i];
    if (!e.ok)
        log().warning("{}: heal failed ({})", e.name, DetourModKit::to_string(e.error));
    else if (e.delta != 0)
        log().info("{}: moved {:+#x} ({:#x} -> {:#x})", e.name, e.delta, e.nominal_offset, e.healed_offset);
}
```

Each entry carries `{name, nominal_offset, healed_offset, delta, ok, error}`; `error` is an `ErrorCode` (meaningful only when `!ok`), and `delta` (`healed_offset - nominal_offset`) is the headline number. The landmarks must already have their `base` filled in, exactly as for a direct `heal_landmark` call.

### Persisting the report -- `detail/drift_manifest.hpp`

`heal_report` produces the live report; `detail/drift_manifest.hpp` makes it durable so two runs against two game versions can be diffed offline. `serialize_drift_report(entries)` renders a versioned, line-oriented manifest, `parse_drift_report` / `read_drift_report_from_file` read it back into owning `DriftRecord`s (the parsed records copy the name, so they outlive the source buffer), and `write_drift_report_to_file` saves it, returning `Result<void>` (`ErrorCode::FileOpenFailed` if the destination cannot be opened for writing, `ErrorCode::FileWriteFailed` if it opened but the write was truncated). Parsing returns `Result<std::vector<DriftRecord>>`; check failures via `.error().code` -- `ErrorCode::MissingHeader` / `ErrorCode::MalformedLine` for corrupt-or-empty content, `ErrorCode::FileOpenFailed` for a missing path. This is a report **archive for analysis**, not a heal input: nothing reads a manifest back to drive resolution, so it does not reintroduce the hand-edited-offset hazard the next paragraph warns about. The recipe (the `Landmark` set) still lives only in mod code.

A drift report is the signal that a patch moved a layout. When it shows a field the heal could not recover (`ok == false`, for example a type that was renamed across the patch and so no longer matches by name), that is a job for a mod update by someone who understands the engine, not something to paper over with a hand-edited offset: a wrong offset reads the wrong memory just as confidently as a right one. DetourModKit deliberately ships no persisted, user-editable heal file for that reason; the recipe (the `Landmark` set) lives in mod code.

## Performance and the init-time contract

`memory::module_of` issues a `GetModuleHandleEx` lookup on **every** call, even a cache hit. `identify_pointee_type` calls it up to twice per slot, so a naive window scan is thousands of syscalls. Therefore `heal_landmark`, `solve_fingerprint`, and `reverse_scan_block` are documented **init-time / re-heal-on-miss**, not per-frame. The `window` is capped at `MAX_HEAL_WINDOW` (4096 bytes, 512 slots per side) so the worst case is bounded, and `heal_landmark` reuses one stack `PointeeType` so the heal path allocates nothing.

## Failure modes (all fail closed)

| Mode | Handling |
|------|----------|
| `slot` / `base` below `0x10000` | L1 `false`; L3 `BadDescriptor`. No memory touched. |
| Unmapped page at a slot | the SEH-guarded read returns nothing -> non-match, never a fault. |
| Slot is neither a pointer-to-object nor a direct vtable | both resolve attempts fail -> slot skipped. |
| Forged COL / non-x64 signature / `pSelf` mismatch / out-of-range RVA | the prelude's bound-check + cross-check guards reject it -> slot skipped. |
| Empty/oversized name, bad enum, `window` over the cap | `BadDescriptor` before any read. |
| No drift (nominal still matches) | nominal-first short-circuit returns before the scan. |
| Zero matching slots | `HealNoMatch` -- never the nominal offset as a guess. |
| Equidistant `+d` / `-d` matches | `HealAmbiguous`. |
| Cross-DLL vtable | classification by resolvability still resolves; record `Indirection::Any` when straddling a DLL boundary. |
| Subtype rename across a patch | `HealNoMatch`. Key the landmark on a stable base type instead. |

## Relation to the walker

The walker runs vtable -> name; this module runs slot -> object -> name and adds the offset-recovery policy on top. Both share the same `resolve_col_site` prelude internally, so the two compose into one fail-closed resilience story: resolve the struct base via a module-scoped `scan::resolve` call, then heal field offsets inside it via `heal_landmark` -- one contract across both code-address and data-layout drift.

## Prior art and acknowledgements

The reverse-direction design here -- identifying an object from its vtable, RTTI-labelling a block of pointer slots (`reverse_scan_block`), and the `COL.offset` handling for multiple-inheritance secondary subobjects -- was inspired by the **CERTTIExplorer** Cheat Engine script in [Frans Bouma](https://github.com/FransBouma)'s (Otis_Inf) [InjectableGenericCameraSystem](https://github.com/FransBouma/InjectableGenericCameraSystem/tree/master/Tools/CERTTIExplorer) (BSD-2-Clause). That tool was originally written by [**GhostInTheCamera**](https://github.com/ghostinthecamera) from the [FramedSC RTTI guide](https://framedsc.com/GeneralGuides/using_rtti.htm) (distilled from Hatti's video), with COL-validation refinements credited to **etra**.

No code was copied: this is an independent C++ reimplementation of the same MSVC RTTI techniques (a widely documented walk: COL -> TypeDescriptor -> mangled name, and its inverse). The credit is for the design ideas and for the nudge to add the block/reverse-range lookup and multiple-inheritance offset handling. Thanks to Otis for sharing the script.
