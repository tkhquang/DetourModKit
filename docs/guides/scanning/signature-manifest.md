# Signature Manifest (`manifest.hpp`)

The Signature Manifest (`manifest.hpp`, `DetourModKit::manifest`) makes a resolved patch-fragile contract editable data, so a game update that breaks a mod becomes a text edit to a `.signatures.ini` instead of a recompiled DLL. It is a thin serialization-and-gate layer over the [Anchor Registry](anchors.md): every backend and every resolve rule is the anchor module's; the manifest adds only an owning, file-loadable record, the ABI binding a mod reads at the resolved site, and a resolve-time trust gate.

## The four ways a patch breaks a mod

A signature system is only worth building if it names which breakages it repairs:

1. **Relocation** -- same bytes, new address. Already solved: every backend scans each launch and hardcodes no address.
2. **Pattern drift** -- the AOB bytes shifted, the function is unchanged. Repaired by editing a `pattern`.
3. **Register / ABI / offset drift** -- the address is fine, but the value moved `rcx -> rax`, or a field moved `+0x1C8 -> +0x1D0`. The AOB may still match; a byte-pattern database does nothing here. Repaired by editing a `read_register` or an `offsets` chain.
4. **Structural change** -- the function was inlined, split, or rewritten. No data repairs this; it is a recompile.

The manifest covers classes 2 and 3 by making the resolved *contract* -- the located address plus the binding the mod reads -- the unit of data. Class 1 is already handled by the anchor backends; class 4 is out of scope, and the gate safe-disables it.

## The file format

A separate INI file (never the settings INI), parsed by the already-linked simpleini. A `[manifest]` header pins the schema; one `[sig.<label>]` section per contract carries the anchor and its binding; and, for the byte-scanned kinds, an ordered `[sig.<label>.rung.<N>]` sub-section per candidate-ladder tier. Rungs are uniform sub-sections (never an inline first rung) so a section-level key is never ambiguous, and the ladder must be contiguous from `rung.0` -- an orphan or gapped rung fails the parse closed.

```ini
[manifest]
schema = 1

; A mid-hook site where the value lives in a register (the class-3 rcx -> rax repair).
[sig.camera.fov_write]
kind = rip_global
binding = mid_hook_register
read_register = rcx                  ; the callback reads gpr(ctx, rcx); edit to rax after a rebuild
fingerprint = 0x41BB02C9DE7715A0     ; captured from a known-good build; the gate distrusts a changed shape

[sig.camera.fov_write.rung.0]
mode = rip_relative
pattern = F3 0F 11 8D ?? ?? ?? ?? 48 8B
displacement_at = 0x4
instruction_length = 8

; A data pointer read through a chain (offsets are data, so a field move is a file edit).
[sig.player.health]
kind = code_operand
operand_kind = memory_displacement
operand_index = 1
byte_width = 4
binding = pointer_chain
offsets = 0x1C8, 0x40                 ; resolved base -> walk(offsets) -> leaf
value_width = 4                       ; read a float at the leaf

[sig.player.health.rung.0]
mode = direct
pattern = 48 8B 05 ?? ?? ?? ?? 48 85 C0

; A vtable-identity target (register churn cannot move it; locate is content-independent).
[sig.ai.think_vmethod]
kind = vtable_identity
mangled = .?AVCAIController@@
binding = vmt_method
vmt_index = 7
```

The `kind` token is one of the five serializable anchor kinds (`rip_global`, `code_operand`, `vtable_identity`, `string_xref`, `manual`); the composite `quorum` / `call_arg_home` kinds compose or lack a resolver and stay in-code (see [Boundaries](#boundaries)). The `binding` token is `address` (the resolved value IS the address), `pointer_chain`, `mid_hook_register`, or `vmt_method`. Tokens are accepted case-insensitively; integers accept `0x`-prefixed hex or decimal with an optional sign. A `module = engine.dll` key resolves the signature within a named module instead of the host EXE.

### Casing and naming conventions

The reserved grammar -- the keys (`kind`, `binding`, `pattern`, ...) and their enum-token values (`rip_global`, `mid_hook_register`, `rip_relative`) -- is lowercase snake_case, and the parser accepts it case-insensitively, so `kind = RipGlobal` reads the same as `kind = rip_global`; only the form `serialize` writes back is fixed to lowercase. Everything else is payload taken verbatim: the `<label>`, the `mangled` type name (`.?AVCAIController@@`), and the `pattern` bytes (`F3 0F 11`) keep their original casing because they come from your code or the game binary, not from DetourModKit's vocabulary. Keeping the grammar lowercase and the payload verbatim is deliberate -- it lets a reader tell a DetourModKit keyword from their own data at a glance.

This is a different file from the settings INI a mod loads through `config.hpp` (`session.ini().load(...)`), whose section and key names are the mod author's own vocabulary and are conventionally PascalCase. The two files read differently because they are owned differently: the manifest's tokens are DetourModKit's controlled grammar, the settings file's keys are yours. The manifest is named `<Mod>.signatures.ini` by convention -- the `.ini` tail keeps editor syntax highlighting and hand-editability, the `signatures` infix separates it from the settings file -- but `manifest::load` accepts any path, so the name is a convention, not a requirement.

## Consumer side: load, gate, then use the bindings

The gate is the whole point: a wrong register or offset read is silent corruption, not a clean miss, so anything the gate does not trust is safe-disabled and never acted on.

```cpp
#include "DetourModKit/manifest.hpp"

namespace mf = DetourModKit::manifest;
namespace hook = DetourModKit::hook;
using namespace DetourModKit;

// Startup: a missing file is a clean FileOpenFailed, not a crash. load() returns a Manifest (header + records).
auto loaded = mf::load("MyMod.signatures.ini");
if (!loaded)
{
    log().error("signatures: {}", loaded.error().message());
    return;
}

// Compile each record into a resolvable Signature (fail-closed on a bad pattern or empty ladder).
std::vector<mf::Signature> sigs;
for (auto &record : loaded->records)
    if (auto sig = mf::Signature::compile(std::move(record)))
        sigs.push_back(std::move(*sig));

// Resolve + gate. reject_on_fingerprint_drift (the default) safe-disables a rewritten signature.
const mf::GateResult gate = mf::resolve_and_gate(sigs, {.reject_on_fingerprint_drift = true});
log().info("signatures: {} trusted, {} disabled ({} resolved of {})", gate.trusted.size(),
           gate.rejected.size(), gate.quality.resolved, gate.quality.total);
for (const auto &r : gate.rejected)
    log().warning("feature disabled: {} ({})", r.label, mf::fingerprint_state_to_string(r.fingerprint));
```

A trusted signature carries its resolved `address` and a pointer to its `binding`; the mod reads the value the binding describes. The bindings are *data*; the code that consumes them stays code.

```cpp
// A mid-hook site: the register is DATA. A rcx -> rax rebuild is an .ini edit, not a recompile.
static hook::Gpr g_fov_register = hook::Gpr::Rcx;      // overwritten from the trusted binding below
if (const mf::GatedSignature *fov = gate.find("camera.fov_write"))
{
    g_fov_register = fov->binding->read_register;
    // ... install a mid hook at fov->address and keep the Hook handle alive ...
}

void on_fov_write(hook::MidContext &ctx)
{
    std::uintptr_t raw = hook::gpr(ctx, g_fov_register);   // reads rcx today, rax after a repair
    // ... what to do with the value stays code; only the register binding is data ...
}

// A pointer-chain data read: the offsets are DATA. A field move is an .ini edit.
if (const mf::GatedSignature *hp = gate.find("player.health"))
    if (auto leaf = memory::walk(hp->address, hp->binding->offsets))
        if (auto health = memory::read<float>(*leaf))
            log().debug("health = {}", *health);
```

`gate.find()` returns `nullptr` for a signature that was rejected or never present, so a consumer that safe-disables a feature simply finds nothing and does not act. The `GateResult` borrows each label and binding from the `Signature` objects, so keep the `sigs` vector alive as long as you hold the result.

## Overlay: a file that only repairs what broke

The manifest is an optional *overlay* over a mod's in-code anchors, not a replacement. `manifest::overlay` merges an in-code `anchor::Anchor` baseline with the file records by label, following the same fail-soft discipline `config::bind` uses for settings: the in-code default is the source of truth, an entry in the file overrides it, and a malformed entry falls back to the default.

```cpp
std::span<const anchor::Anchor> defaults = my_mod_anchors();   // the in-code baseline, always present

// A missing file yields no overrides, so the defaults pass through untouched.
std::vector<mf::SignatureRecord> overrides;
if (auto loaded = mf::load("MyMod.signatures.ini"))
    overrides = std::move(loaded->records);

// File wins where it speaks; the rest keep their in-code form. Then gate the merged result.
if (auto merged = mf::overlay(defaults, overrides))
{
    const mf::GateResult gate = mf::resolve_and_gate(*merged);
    // ... use gate.find(...) exactly as above ...
}
```

So if a game update broke two of a mod's twenty signatures, the shipped file needs only those two `[sig.<label>]` entries; the other eighteen keep their in-code defaults. Adopt nothing and nothing changes; adopt anchors and an optional repair file sits on top.

## Author side: capture the fingerprints once

Write the `.ini` by hand, or capture it from a working build so the drift baselines are filled in. The fingerprint is an address-independent hash of a signature's resolution evidence (its compiled pattern bytes, mangled name, or xref text -- see [Anchor fingerprints](anchors.md#anchor-fingerprints)); `recapture_fingerprint()` adopts the live value as the trusted baseline.

```cpp
// From a known-good build: adopt each live fingerprint, then serialize the records.
for (auto &sig : sigs)
    sig.recapture_fingerprint();

std::vector<mf::SignatureRecord> to_save;
for (const auto &sig : sigs)
    to_save.push_back(sig.record());
if (auto saved = mf::save("MyMod.signatures.ini", mf::Manifest{.records = std::move(to_save)}); !saved)
    log().warning("could not write manifest: {}", saved.error().message());
```

`save` emits the canonical form of every record; hand-written `;` comments are not preserved across a programmatic re-save (they survive manual editing). For a filesystem-free path -- unit tests, an embedded default -- `manifest::serialize` / `parse` round-trip the same `Manifest` through a `std::string`.

## Repair side: after a game update

The game shifts the health field and moves the fov write's register. The user (or author) edits the `.ini`, no rebuild:

```ini
[sig.player.health]
offsets = 0x1D0, 0x40        ; was 0x1C8, 0x40

[sig.camera.fov_write]
read_register = rax          ; was rcx
```

If a pattern itself broke, they edit the rung's `pattern`. Once the edit is verified correct, re-capture the fingerprint (the one-line `recapture_fingerprint()` above, or an offline tool) so the gate trusts the repaired signature again. Until then, a signature whose located code changed shape enough that its fingerprint no longer matches is safe-disabled and logged, while the rest of the mod keeps working.

## Versioning across mod releases

The overlay merges *file over code by label*, so a stale `.signatures.ini` a user still has on disk silently overrides a same-label default your new build corrected. The per-signature fingerprint gate does not catch this, because it only sees changes to the located *game* code, not a change to how your own build interprets it.

The `[manifest]` header carries an optional `revision` for exactly this: an integer contract epoch you bump **only when an in-code change makes older manifests incompatible** (a renamed label, a re-meaning of a binding, a dropped signature). A routine mod update keeps the same revision, so still-valid repair files keep working; only a genuinely breaking change trips the gate. Keep it distinct from your mod's marketing version, which would otherwise invalidate every repair file on every release.

```ini
[manifest]
schema = 1
revision = 2      ; the signature-contract epoch this file targets
```

Carry your build's current epoch and gate on it with `manifest::revision_compatible`, falling back to your in-code defaults when the file is stale:

```cpp
constexpr std::uint32_t BUILD_REVISION = 2;   // bump only on a breaking signature-contract change

std::vector<mf::SignatureRecord> overrides;
if (auto loaded = mf::load("MyMod.signatures.ini"))
{
    if (mf::revision_compatible(loaded->header, BUILD_REVISION))
        overrides = std::move(loaded->records);
    else
        log().warning("MyMod.signatures.ini targets revision {} but this build is {}; ignoring it. Delete it, "
                      "or set revision = {} only after re-verifying every entry.",
                      loaded->header.revision, BUILD_REVISION, BUILD_REVISION);
}
auto merged = mf::overlay(my_mod_anchors(), overrides);
```

`revision_compatible` returns true when `BUILD_REVISION` is 0 (you opt out of gating) or the file's `revision` equals it; any other value -- an older file, or an unversioned file under a versioned build -- is safe-ignored so your in-code defaults stand. This axis is independent of `schema` (whether DetourModKit can parse the file at all) and of the fingerprint gate (whether the located code still matches). Letting a *user* raise the file's `revision` to silence the warning re-enables a file you declared incompatible, so keep "delete" the obvious remedy and treat "bump" as a deliberate expert action.

## The gate, precisely

`manifest::resolve_and_gate` rejects a signature when any of:

- `resolve()` does not return a unique `anchor::AnchorStatus::Resolved` (the locate missed or was ambiguous), or
- its fingerprint drifted and `GatePolicy::reject_on_fingerprint_drift` is set (the located code's shape changed, so the binding can no longer be trusted), or
- with `GatePolicy::reject_unset_fingerprint`, it carries no captured baseline at all, or
- the whole-manifest trusted fraction falls below `GatePolicy::min_resolved_fraction` (a global health floor: if too little of the manifest is trustworthy, none of it is).

The defaults reject drift but tolerate an unset baseline, so an author who has not captured fingerprints yet is not blocked. A rejected feature does not install its hook or read its pointer; it stays off.

## Boundaries

- **Structural change (class 4).** If the function was inlined away, split, or removed, there is no site to bind and no data fixes it. The gate safe-disables; the fix is code.
- **Composite anchor kinds.** `Quorum` composes voting members by pointer and `CallArgHome` has no resolver, so neither is file-serializable. Keep them as in-code anchors and gate them directly with [`anchor::evaluate_gate`](anchors.md#gating-a-feature-on-drift-quality); `overlay` skips a composite default rather than mis-adopting it.
- **Callback logic is code.** Only the bindings -- the register, the offset chain, the vtable slot, the pattern -- are data. What the mod does with the resolved value is always code.
- **Fingerprints are per game build and platform.** The evidence hash is stable across runs and rebuilds on one platform, not across compilers, which matches how a mod ships one manifest per game version.
