# Offline Signature Health (`sighealth.hpp`)

Offline signature health (`sighealth.hpp`, `DetourModKit::sighealth`) grades how strong a signature is **before it ever runs against a game**. The [Anchor Registry](anchors.md) and the [Signature Manifest](signature-manifest.md) answer "did this signature resolve, and does its shape still match?", but only at runtime, against a live image. A brittle signature (three common bytes, a wall of wildcards, a two-character string) still resolves uniquely today and only breaks silently on the next game patch, when the author is no longer looking. This module closes that gap. It reads the declarative bytes of a `scan::Pattern` or a `manifest::SignatureRecord` and returns a report. A weak anchor is therefore caught at authoring time, or in a CI lane, rather than in a bug report.

Everything here is offline and side-effect-free. It touches no process memory, spawns no worker, and needs no game running. That makes it the natural companion to the manifest module. Once a signature contract is editable data, its quality becomes checkable data too, and you can lint a `.signatures.ini` the same way you lint source.

## The three quality axes

### Atom rarity

See `PatternHealth::atom_count` for the atom boundary contract. `SigHealthPattern.EveryBoundedJumpSplitsTheFixedAtoms` supplies T-SIGHEALTH-STRUCT. Long rare-byte atoms give strong anchors. Common opcodes or padding give weak anchors. Health uses `DetourModKit::detail::byte_frequency_class`.

`CommonBytesOnly` identifies a pattern whose fixed bytes are all common. `ShortestAnchorRun` identifies a short longest atom. `NoFixedAnchor` identifies a pattern with no fully known byte.

### Byte entropy

A run of identical bytes (`90 90 90 90`) is long but carries almost no distinguishing information. Shannon entropy over the fully-known byte *values* catches that low-information shape a raw byte count misses. A repetitive pattern with enough fixed bytes to judge trips `LowByteEntropy`.

### Expected ambiguity

Per-position selectivity combines into an estimate of how many false matches a pattern draws in a nominal module (`HealthPolicy::nominal_haystack_bytes`, default 64 MiB). That estimate turns "is this unique?" into a number you can act on. Each fully-known byte contributes up to 8 bits of selectivity (discounted for common bytes), each fixed nibble 4 bits, each wildcard nothing. The estimate is `nominal_haystack_bytes * 2^(-selectivity_bits)`. A bounded `[min-max]` jump then multiplies the estimate by its `(max - min + 1)` width, because the following segment can sit at any of those offsets. A variable-gap signature is therefore not scored as if its segments were adjacent. A high estimate trips `WeakSelectivity`: a `Warning` past `warn_expected_matches` (default 1), and a `Critical` past `fail_expected_matches` (default 32).

It is a heuristic order-of-magnitude figure under an independent-byte model, not a guarantee. The runtime resolver still verifies uniqueness and fails closed on ambiguity. The estimate exists to catch a weak signature earlier, and it reliably separates a five-rare-byte anchor (effectively unique) from a three-common-byte one (thousands of hits).

## Grading: Robust, Fragile, Unusable

Every level of analysis produces a `Grade` from the worst `Severity` present:

- **Robust.** No findings at all. Ship it.
- **Fragile.** At least one `Warning`. It resolves today but is brittle or weakly selective. Review before shipping.
- **Unusable.** At least one `Critical`. It cannot anchor reliably (no fixed byte, empty text, will not compile, or an expected-match count so high it is effectively non-unique).

A byte **record** starts from its first declared rung. Static lint cannot know whether a weak but compilable pattern will be unique in the live scope, so a stronger fallback cannot raise the record grade before resolution proves the first rung missed. That first-rung verdict is only the starting point. Record-level findings and the whole-record compilability check (`Signature::compile`) can only worsen it, and floor a record that will not compile to `Unusable`, never raise it. Every rung remains visible in the report, and the numeric selectivity summary still identifies the strongest byte rung. A **manifest** grades by its weakest record.

## The API, in four layers

The analysis layers over the manifest surface the same way the manifest layers over the anchor registry:

```cpp
#include "DetourModKit/sighealth.hpp"
namespace sh = DetourModKit::sighealth;
namespace sc = DetourModKit::scan;

// One compiled pattern.
sh::PatternHealth  p = sh::analyze_pattern(*sc::Pattern::compile("F3 0F 11 8D ?? ?? ?? ?? 48 8B"));

// One candidate-ladder rung (compiles the AOB, or measures the text anchor by tier).
sh::CandidateHealth c = sh::analyze_candidate(rung_spec);

// One whole signature record (its ladder, or its string / vtable / manual anchor, per kind).
sh::RecordHealth   r = sh::analyze_record(record);

// A whole manifest, rolled up to a grade tally.
sh::ManifestHealth m = sh::analyze_manifest(manifest);
```

Every report carries a `grade`. Every level except the manifest roll-up also carries a `findings` list, and the pattern-level `PatternHealth` additionally carries the measured quantities (`length`, `fixed_bytes`, `longest_atom`, `byte_entropy_bits`, `selectivity_bits`, `expected_matches`, ...). The `format_report` overloads render a `PatternHealth`, `RecordHealth`, or `ManifestHealth` as a human-readable lint report:

```cpp
DetourModKit::log().info("{}", sh::format_report(m));
```

## Example: linting a manifest in a pre-ship check

```cpp
#include "DetourModKit/manifest.hpp"
#include "DetourModKit/sighealth.hpp"

#include <expected>
#include <filesystem>
#include <iostream>

namespace mf = DetourModKit::manifest;
namespace sh = DetourModKit::sighealth;

DetourModKit::Result<void> lint_signatures(const std::filesystem::path &path)
{
    DMK_TRY(loaded, mf::load(path));

    sh::HealthPolicy policy;
    policy.nominal_haystack_bytes = 96u * 1024u * 1024u; // size it to the target game's code pages

    const sh::ManifestHealth health = sh::analyze_manifest(loaded, policy);
    std::cout << sh::format_report(health);

    // Fail the check when any signature is Unusable; treat Fragile as an advisory.
    return (health.unusable == 0) ? DetourModKit::Result<void>{}
                                  : std::unexpected(DetourModKit::Error{DetourModKit::ErrorCode::InvalidArg,
                                                                        "sighealth"});
}
```

## Resolver templates and their expected ambiguity

These are the common resolver shapes and the selectivity each aims for. The expected-ambiguity figures are the default estimate (64 MiB nominal module) for a representative pattern of that shape. Treat them as order-of-magnitude targets, and re-run `analyze_pattern` on your own bytes for the exact figure.

| Template | Shape | Resolves | Aim for | Expected ambiguity (64 MiB) |
| --- | --- | --- | --- | --- |
| Direct prologue | a distinctive function-entry byte run, `40 55 48 83 EC ?? 48 8B` for example | an inline-hook target at the match | >= 5 rare fully-known bytes | ~0 (unique) |
| RIP-relative global | scan then read a `disp32`, `F3 0F 11 8D ?? ?? ?? ?? 48 8B` for example | an absolute global address | >= 6 fully-known bytes around the operand | ~0.01 |
| Under-anchored RIP read | the bare instruction, `48 8B 05 ?? ?? ?? ??` | (intended) a global address | this is the anti-pattern. Add surrounding context | ~5,800 (Unusable) |
| String-xref to function | anchor on an immutable literal, return the enclosing function | a function address, patch-resilient | a literal >= 5 characters (longer is rarer) | text tier: unique-only |
| Vtable by name | resolve an MSVC mangled type name through the reverse-RTTI walk | a class vtable address | any non-empty mangled name | text tier: unique by construction |

The two text tiers (string-xref, vtable) are graded by anchor-text length rather than a byte estimate. Their uniqueness is guaranteed by the backend (a pooled literal or a second reference fails closed) rather than by byte selectivity. A mangled type name is unique by construction, so only an empty name is a defect. A string literal can genuinely collide when short (the linker pools identical literals), so a length floor applies to strings but not to type names.

The under-anchored RIP example has only three fixed bytes. Two are common opcodes. Its four `disp32` wildcards constrain nothing. The shape can match thousands of RIP-relative loads.

Extend the pattern with distinctive instructions until the estimate falls below one. See `FindingKind::VolatileDisplacementBytes` for the `disp32` contract. T-SIGHEALTH-STRUCT supplies the permanent proof.

## Tuning the policy

`HealthPolicy` is a plain value with no global state, so you can hold one policy per game or per feature. The knobs, with defaults:

- `nominal_haystack_bytes` (64 MiB). The module size the expected-ambiguity estimate models. Larger is stricter. Size it to the target game's executable pages.
- `min_pattern_bytes` (5), `min_longest_atom` (4), `min_anchor_text_bytes` (5). The structural floors.
- `max_wildcard_ratio` (0.6). The full-wildcard fraction above which `HighWildcardRatio` fires.
- `min_byte_entropy_bits` (1.5). The entropy floor (only judged once there are enough fixed bytes).
- `warn_expected_matches` (1) and `fail_expected_matches` (32). The `Warning` and `Critical` thresholds for the ambiguity estimate.

## What the estimate does and does not promise

The estimate is a static heuristic that catches weak signatures early. It assumes independent bytes and uses a coarse frequency model, so it is an order-of-magnitude figure, not a match count. It cannot see run-time facts the resolver can: the actual byte distribution of a specific module, whether a string literal is pooled, or whether a second cross-reference exists. Those are the runtime resolver's job, and it fails closed on all of them. Signature health is the pre-flight lint that keeps a brittle signature from reaching that runtime check in the first place.
