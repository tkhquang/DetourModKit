# Offline Signature Health (`sighealth.hpp`)

Offline signature health (`sighealth.hpp`, `DetourModKit::sighealth`) grades how robust a signature is **before it ever runs against a game**. The [Anchor Registry](anchors.md) and the [Signature Manifest](signature-manifest.md) answer "did this signature resolve, and does its shape still match?" -- but only at runtime, against a live image. A brittle signature (three common bytes, a wall of wildcards, a two-character string) still resolves uniquely today and only breaks silently on the next game patch, when the author is no longer looking. This module closes that gap: it reads the declarative bytes of a `scan::Pattern` or a `manifest::SignatureRecord` and returns a report, so a weak anchor is caught at authoring time -- or in a CI lane -- rather than in a bug report.

Everything here is offline and side-effect-free. It touches no process memory, spawns no worker, and needs no game running. That makes it the natural companion to the manifest module: once a signature contract is editable data, its quality becomes checkable data too, and you can lint a `.signatures.ini` the same way you lint source.

## The three quality axes

### Atom rarity

An **atom** is a maximal run of fully-known bytes -- the only thing a byte prefilter can `memchr` for. A long atom of *rare* bytes is a strong anchor; a long atom of padding or common opcodes (`00`, `CC`, `48`, `8B`) barely narrows the search. Health uses the scan engine's own frequency-class table (`DetourModKit::detail::byte_frequency_class`), so its judgement of "rare" matches the byte the engine would actually anchor on. A pattern whose fully-known bytes are *all* common trips `CommonBytesOnly`; a pattern whose longest fully-known run is short trips `ShortestAnchorRun`; a pattern with no fully-known byte at all trips `NoFixedAnchor` (it can only be matched by a masked compare at every position).

### Byte entropy

A run of identical bytes (`90 90 90 90`) is long but carries almost no distinguishing information. Shannon entropy over the fully-known byte *values* catches that low-information shape a raw byte count misses. A repetitive pattern with enough fixed bytes to judge trips `LowByteEntropy`.

### Expected ambiguity

Combining per-position selectivity into an estimate of how many false matches a pattern would draw in a nominal module (`HealthPolicy::nominal_haystack_bytes`, default 64 MiB) turns "is this unique?" into a number you can act on. Each fully-known byte contributes up to 8 bits of selectivity (discounted for common bytes), each fixed nibble 4 bits, each wildcard nothing; the estimate is `nominal_haystack_bytes * 2^(-selectivity_bits)`. A high estimate trips `WeakSelectivity` -- a `Warning` past `warn_expected_matches` (default 1), escalating to `Critical` past `fail_expected_matches` (default 32).

It is a heuristic order-of-magnitude figure under an independent-byte model, not a guarantee. The runtime resolver still verifies uniqueness and fails closed on ambiguity; the estimate exists to catch a weak signature earlier, and it reliably separates a five-rare-byte anchor (effectively unique) from a three-common-byte one (thousands of hits).

## Grading: Robust, Fragile, Unusable

Every level of analysis produces a `Grade` from the worst `Severity` present:

- **Robust** -- no findings at all. Ship it.
- **Fragile** -- at least one `Warning`. It resolves today but is brittle or weakly selective; review before shipping.
- **Unusable** -- at least one `Critical`. It cannot anchor reliably (no fixed byte, empty text, will not compile, or an expected-match count so high it is effectively non-unique).

A **record** grades by its *strongest* rung: the resolver tries the ladder in order until one rung resolves uniquely, so a record is as strong as its best tier (the weaker fallbacks are still reported per rung for review). A **manifest** grades by its *weakest* record: each signature gates its own feature, so the file is only as trustworthy as its weakest signature.

## The API, in four layers

The analysis layers over the manifest surface the same way the manifest layers over the anchor registry:

```cpp
#include "DetourModKit/sighealth.hpp"
namespace sh = DetourModKit::sighealth;

// One compiled pattern.
sh::PatternHealth  p = sh::analyze_pattern(*scan::Pattern::compile("F3 0F 11 8D ?? ?? ?? ?? 48 8B"));

// One candidate-ladder rung (compiles the AOB, or measures the text anchor by tier).
sh::CandidateHealth c = sh::analyze_candidate(rung_spec);

// One whole signature record (its ladder, or its string / vtable / manual anchor, per kind).
sh::RecordHealth   r = sh::analyze_record(record);

// A whole manifest, rolled up to a grade tally.
sh::ManifestHealth m = sh::analyze_manifest(manifest);
```

Each report carries a `grade`, a `findings` list, and the measured quantities (`length`, `fixed_bytes`, `longest_atom`, `byte_entropy_bits`, `selectivity_bits`, `expected_matches`, ...). The `format_report` overloads render any of them as a human-readable lint report:

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

These are the common resolver shapes and the selectivity each should aim for. The expected-ambiguity figures are the default estimate (64 MiB nominal module) for a representative pattern of that shape; treat them as order-of-magnitude targets, and re-run `analyze_pattern` on your own bytes for the exact figure.

| Template | Shape | Resolves | Aim for | Expected ambiguity (64 MiB) |
| --- | --- | --- | --- | --- |
| Direct prologue | a distinctive function-entry byte run, e.g. `40 55 48 83 EC ?? 48 8B` | an inline-hook target at the match | >= 5 rare fully-known bytes | ~0 (unique) |
| RIP-relative global | scan then read a `disp32`, e.g. `F3 0F 11 8D ?? ?? ?? ?? 48 8B` | an absolute global address | >= 6 fully-known bytes around the operand | ~0.01 |
| Under-anchored RIP read | the bare instruction, `48 8B 05 ?? ?? ?? ??` | (would-be) a global address | this is the anti-pattern -- add surrounding context | ~5,800 (Unusable) |
| String-xref to function | anchor on an immutable literal, return the enclosing function | a function address, patch-resilient | a literal >= 5 characters (longer is rarer) | text tier: unique-only by the resolver |
| Vtable by name | resolve an MSVC mangled type name through the reverse-RTTI walk | a class vtable address | any non-empty mangled name | text tier: unique by construction |

The two text tiers (string-xref, vtable) are graded by anchor-text length rather than a byte estimate, because their uniqueness is guaranteed by the backend (a pooled literal or a second reference fails closed) rather than by byte selectivity. A mangled type name is unique by construction, so only an empty name is a defect; a string literal can genuinely collide when short (the linker pools identical literals), so a length floor applies to strings but not to type names.

The lesson the "under-anchored RIP read" row makes concrete: a signature is only as unique as its fully-known bytes, weighted by their rarity. `48 8B 05` reads well but is three common bytes; the four wildcards that follow are the `disp32` and constrain nothing, so the shape matches thousands of RIP-relative loads. Extend the pattern with the surrounding instructions (a distinctive prologue before it, or a following opcode) until the estimate drops below one.

## Tuning the policy

`HealthPolicy` is a plain value with no global state, so you can hold one policy per game or per feature. The knobs, with defaults:

- `nominal_haystack_bytes` (64 MiB) -- the module size the expected-ambiguity estimate models. Larger is stricter; size it to the target game's executable pages.
- `min_pattern_bytes` (5), `min_longest_atom` (4), `min_anchor_text_bytes` (5) -- the structural floors.
- `max_wildcard_ratio` (0.6) -- the full-wildcard fraction above which `HighWildcardRatio` fires.
- `min_byte_entropy_bits` (1.5) -- the entropy floor (only judged once there are enough fixed bytes).
- `warn_expected_matches` (1) and `fail_expected_matches` (32) -- the `Warning` and `Critical` thresholds for the ambiguity estimate.

## What the estimate does and does not promise

The estimate is a static heuristic for catching weak signatures early. It assumes independent bytes and uses a coarse frequency model, so it is an order-of-magnitude figure, not a match count. It cannot see run-time facts the resolver can: the actual byte distribution of a specific module, whether a string literal is pooled, or whether a second cross-reference exists. Those are the runtime resolver's job, and it fails closed on all of them. Signature health is the pre-flight lint that keeps a brittle signature from reaching that runtime check in the first place.
