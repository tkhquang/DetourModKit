# Signature-health corpus report: estimate vs ground truth over real x64 .text (T-SIGHEALTH-CORPUS)

> Archived benchmark snapshot; record new measurements in a new folder rather than editing existing results.

This directory captures the P1-9 corpus half: the report that must exist before any sighealth rarity/grade threshold change or any generic prologue/movabs/immediate heuristic. The producer is `tests/corpus_sighealth.cpp` (`DetourModKit_corpus_sighealth`): it loads a representative corpus of x64 system images plus its own statically linked DMK executable, counts ground-truth matches for each probe with a naive masked matcher (the oracle, independent of the scan engine), and compares them with `sighealth::analyze_pattern`'s expected-match estimate at the default `HealthPolicy`.

## Corpus

19 modules, 28.8 MiB of executable bytes (MinGW build; 28.3 MiB under the MSVC build): ntdll, kernel32, kernelbase, user32, gdi32, gdi32full, msvcrt, ucrtbase, ole32, combase, rpcrt4, advapi32, oleaut32, setupapi, shell32, d3d11, dwrite, windows.storage, and the tool's own image. Host: Windows 11 (10.0.26200). Actual counts below are normalized to the model's nominal 64 MiB haystack.

## Results (MinGW run; the MSVC run agrees within a few percent)

| Probe | Category | Grade | est/64MiB | actual/64MiB |
|---|---|---|---|---|
| `40 53 48 83 EC 20` | canonical-prologue | Robust | 0.000 | 26,643 |
| `48 89 5C 24 08` | canonical-prologue | Robust | 0.088 | 59,563 |
| `48 89 5C 24 08 48 89 74 24 10 57` | canonical-prologue | Robust | 0.000 | 11,699 |
| `48 83 EC 28` | canonical-prologue | Fragile | 13.9 | 20,000 |
| `CC` x8 padding | canonical-prologue | Unusable | 5,405 | 1,358,226 |
| `48 8B 05 ?? ?? ?? ??` | unmasked-operand | Unusable | 5,793 | 73,822 |
| `48 8B 05` + frozen live disp32 | unmasked-operand | Robust | 0.000 | 2.2 (1 raw hit) |
| `48 B8` + invented imm64 | synthetic-unique | Robust | 0.000 | 0 |
| `48 ?? ?? ?? 24 ?? ?? 89` | wildcard | Unusable | 5,793 | 7,466 |

## Findings

- **False negatives are real and structural.** The independent-byte model underestimates canonical MSVC prologues by at least ~2.7e7x (`corpus.prologue_underestimate_ratio`). The probe's estimate is 0.000, so the published ratio divides the 26,643 actual hits per 64 MiB by the tool's 0.001 divisor floor; it is a lower bound on the true underestimate, not a measured model output. x64 code is highly correlated, so a 6-11 byte prologue that the model grades Robust matches tens of thousands of times per 64 MiB. The common-byte frequency classes soften but cannot close this gap.
- **The model's warning directions are correct where it fires.** Padding, masked RIP loads, and wildcard-heavy shapes all grade Unusable and are genuinely non-selective; the wildcard estimate is even conservative (5,793 predicted vs 7,466 actual is the right order).
- **Unmasked operands are a volatility hazard, not a selectivity one.** A RIP load with its disp32 frozen from a live site is unique today (1 hit) and graded Robust, which is exactly the "resolves today, breaks on relink" case. The pattern-level model cannot see volatility; the rung-level `VolatileDisplacementBytes` finding (T-SIGHEALTH-STRUCT) covers declared RipRelative rungs, and the runtime resolver's uniqueness verification remains the authority.

## Decision (frozen behavior)

**Thresholds and heuristics stay as they are; this report and its tool become the permanent gate for changing them.** Rationale: sighealth is authoring-time lint, not a runtime gate; the runtime resolver still verifies uniqueness, so a false Robust cannot resolve to a wrong address, it can only under-warn. Correcting the prologue false negative honestly requires a correlation-aware model (n-gram or corpus-frequency), which is a new heuristic class that P1-9 forbids adopting without this report and which carries its own false-positive risk on non-Windows-like game code. The corpus tool runs in the release benchmark-evidence route with deterministic gates (`corpus.canonical_prologue_exceeds_fail_threshold`, `corpus.synthetic_unique_absent`), so the demonstrated facts stay pinned; any future threshold or heuristic change must reproduce this report on the same probe families and show the false-negative gap closing without breaking the correct directions above.
