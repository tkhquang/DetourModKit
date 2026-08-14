# Build, CI, and release design

This note explains the build and release system. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

## Benchmark gate records

Each executable also emits the gate records defined in [tests/bench_gate.hpp](../../tests/bench_gate.hpp) and exits nonzero when a deterministic gate fails, when it refuses an identity, or when it closes without a gate, so a benchmark whose pattern did not compile, whose page was never committed, or whose chain resolved to the wrong cell fails instead of printing a shorter table. `scripts/check_benchmark_results.py` reads the captures and refuses missing, malformed, non-finite, duplicated, spliced, unclosed, or internally contradictory evidence, failed deterministic gates (including a comparison baseline), and any `--require`d deterministic gate that stopped being emitted. Every record is a (suite, name) pair whose dot-free suite is nonempty and whose name is qualified with its own suite, refused at production time by the ledger and again at parse time; `--require` and `--metric-ratio` take the suite-qualified spelling and bind the exact pair, so one suite can never answer for another's gate or metric. Wall-clock thresholds and `--metric-ratio` comparisons are recorded everywhere but enforced only under `--stable-host`; the release workflow's `benchmark-evidence` job runs without it, because a shared runner cannot tell a regression from a noisy neighbour.

## AVX-512 verify tier

The opt-in AVX-512 verify tier is gated behind the `DMK_ENABLE_AVX512` CMake option (default OFF). When off it compiles out entirely; when on it is still selected only behind a runtime CPUID + XGETBV check (AVX-512F + AVX-512BW, since the byte-wise masked compare is a BW instruction), so the produced library still runs on CPUs without AVX-512 (it simply falls back to AVX2). The intrinsics are confined to that one tier via a per-function `target` attribute, so enabling the option never bumps the baseline ISA of the rest of the library. Its `>= 30%` verify-throughput gate can only be measured on real AVX-512 hardware. Per-tier correctness (including AVX-512, under Intel SDE) is validated on pushes to `main` and `release/v4.0.0-*` by `.github/workflows/simd-tier-correctness.yml`. Each leg fails rather than skips when the emulator cannot be set up or when the run produced no tier banner, because both are absences of coverage rather than evidence of it. The throughput gate compares an AVX-512 build against an AVX2 build on one identified real AVX-512 host. Set the same nonempty `DMK_BENCH_HOST_ID` for both runs; the scanner publishes it as `#HOST`, plus intrinsic `#BUILD` and runtime `#TIER` provenance. Enforce `scanner.verify_gib_per_s` with `check_benchmark_results.py --baseline <avx2.txt> --metric-ratio scanner.verify_gib_per_s:1.30 --current-tier AVX-512 --baseline-tier AVX2 --current-build AVX512 --baseline-build AVX2 --require scanner.verify_workload_no_match --stable-host` (see `docs/analysis/avx512_verify_icount`).

## Sanitizer and coverage lanes

AddressSanitizer is the only sanitizer that links on Windows: GCC and Clang on mingw-w64 ship no ASan/UBSan runtime for the Windows target, so the sanitizer build links only under MSVC, and ASan is the only sanitizer there (no UBSan or LSan). MSVC ASan needs `clang_rt.asan_dynamic-x86_64.dll` on `PATH` at run time; a Developer Command Prompt provides it. Coverage is separate and works on MinGW via gcov. The blocking `.github/workflows/sanitizers.yml` lane builds and runs the MSVC ASan preset on pull requests, pushes to `main` and `release/v4.0.0-*`, and manual dispatch. The blocking clang-format and clang-tidy routes live in `.github/workflows/quality.yml`; the uninstrumented build/test gate for both toolchains is `.github/workflows/pr-check.yml`.

## Contributor quality proofs

The `.clang-tidy` file leaves `WarningsAsErrors` empty, so it does not gate local builds. The required route supplies `--warnings-as-errors='*'` for tidy findings. It also supplies `--extra-arg=-Werror` for compiler diagnostics. The tooling database disables the cached GCC-only `-Wdangling-reference` flag.

The route pins `--target=x86_64-w64-windows-gnu`. Without that target, Windows clang analyzes the MSVC branch and misses required GNU-only includes.

The repository prohibits baseline counts and blanket suppressions. A permitted exception uses a narrow `NOLINTNEXTLINE` with the check name and reason. Review checks that source-local exception.

Build outputs depend on the local compiler and configuration, so they are not reviewable source evidence. The repository ignore rules keep normal output paths outside commits. A forced `std::endl` flush adds work that a newline does not require. Boundary rules `[B-10]` and `[B-14]` own those contracts.

A manual sanitizer dispatch requires the exact 40-character candidate SHA. Its `deliberate_asan_red` mode first runs the full suite green, then explicitly builds and runs `dmk_asan_failure_probe`; that probe is excluded from ordinary builds and is never registered with CTest. The capability proof is a workflow conclusion of Failure with a real `heap-buffer-overflow` diagnostic. Record that run ID, then dispatch the same SHA with the mode off for the blocking green result. Never add `continue-on-error` or invert the probe's exit.

## Release workflow

The release workflow likewise requires the exact candidate SHA, and dispatches in one of two modes. `preflight`, the default, runs the whole producer, package, soak and benchmark-evidence graph and stops: it holds no release credential, creates no tag, and publishes nothing, so the final audit can run against a candidate that has already been through every job it will face. `publish` adds `create-release`, the only job that holds `RELEASE_TOKEN`, and that job still refuses anything but `refs/heads/main` at the exact dispatched SHA. Its `create-release` job is what creates the annotated tag and the GitHub Release; there is no manual tag step after it. Each Release producer additionally runs the `tests/package_build_tree` consumer at the configuration it packages and asserts through `scripts/check_gtest_execution.py` that the fixed-base module-replacement case executed rather than skipped on that host. `scripts/check_workflow_topology.py` fails a PR that reintroduces an advisory marker on a required route, empties or gates a required job, swallows a step's exit status, drops either producer proof, lets a preflight run publish, or moves the release credential into another job.

## Workflow contract

**The workflows are decided against a canonical contract, never by fragment presence.** `scripts/workflow_contract.py` holds the reviewed shape of all seven workflows as data outside the parser: triggers, jobs, runners, dependencies, the complete ordered step list of every job, each step's shell, reviewed condition and material environment, and the exact ordered program of every load-bearing step. Its normalized-source digest additionally pins every action reference and input, trigger value, matrix, permission, default, output and otherwise-unlisted run body. `scripts/check_workflow_topology.py` compares against both layers. This is not a stylistic preference: a presence check answers "is the reviewed line still here?", which stays yes after an inserted assignment shadows the value that line reads, after the single success exit moves to the front of a guard, and after a wrapper shell rewrites the status the guard computed. **Never accept fragment presence as evidence for publication identity or status propagation.** The comparison is bidirectional -- an unreviewed source byte, job, step, shell or condition is refused, and a reviewed one that was deleted or renamed is refused -- so changing a workflow means changing the contract in the same review. When a reviewed workflow change moves a digest, `python scripts/check_workflow_topology.py --print-source-identities` prints the replacement values under the same normalization the gate applies, and the refusal reports the observed digest beside the reviewed one. Neither is a reason to accept the diff that produced it: read the workflow diff first, then move the identity.

**Identity contexts enter only as quoted data.** Each workflow binds the dispatch input, event commit and publication ref through the exact step environment the contract records; its one exactly reviewed command expands each value once inside quotes, so shell-significant context text is never evaluated as Bash source. `scripts/check_release_identity.py` compares those arguments, resolves the checkout with inherited `GIT_*` repository redirects removed, and optionally requires one exact ref. `release.yml` runs it with `--verify-checkout` in both `validate-version` and `create-release`, where the second guard also requires `refs/heads/main`; the publish boundary therefore re-decides identity rather than trusting an earlier job. `arch-gate.yml`, `sanitizers.yml`, `simd-tier-correctness.yml`, and `coverage-pages.yml` run the same helper on manual dispatch and each declare `expected_sha` as a required string input. Never interpolate a GitHub context directly into `run`, and do not re-implement this comparison inline in a workflow.

Three rules make that fail closed rather than merely thorough, and all are frozen. **A required step is unconditional.** A step that does not run cannot fail, so a step-level `if` on a required command is a skipped guard reporting green. The only exception is the exact condition the contract records for that step, which either strengthens it (`!cancelled()`), guards a diagnostics upload, binds a leg to a manual dispatch, or selects a matrix route. Adding a condition means adding it to the contract, not relaxing the rule. **Exit status must reach the job.** `|| true` was never the only spelling: any fallback that exits zero normalizes a failure, and `|| echo ignored` is exactly as green, so `||` is refused by construction -- on the raw line as well as the token stream, because an operator inside quoting or a command substitution is still evaluated while a token scan sees one opaque word. The one carve-out decides nothing: shell test compounds joined inside a conditional head, every operand a `[`/`[[` test. The same rule refuses `set +e`, `set +o errexit`, `set +o pipefail`, `eval`, a CMD `&` chain or pipeline, a negated command, and a PowerShell `Write-Warning` that leaves a detected breakage green (report with `Write-Error` and a nonzero exit). The three `TEST_MAJOR`/`TEST_MINOR`/`TEST_PATCH` captures stay allowlisted by exact line because their failure becomes an empty value the next guard rejects with a useful diagnostic. **A shell is chosen from the allowlist.** Only `bash`, `cmd`, `pwsh`, and `powershell` may be declared, and each step must declare the one the contract records. A custom template such as `shell: bash {0} || true` is a status rewrite applied to every command in the step without touching a line a reviewer reads, and `sh` is excluded because GitHub runs it without pipefail. Do not add a retry policy to a required route either: `--repeat until-pass` reports green on a second attempt, which makes the context's conclusion evidence of nothing.

## Lifecycle soak and trigger policy

Each Release-with-tests job runs `scripts/run_lifecycle_soak.py` before producing its package: the script proves per-executable WER LocalDumps capture with a native fail-fast control, asserted through an owned process handle to have terminated with `STATUS_FAIL_FAST_EXCEPTION` rather than merely nonzero, repeats every `InputLifecycleProof` 200 times serially, runs `Lifecycle.FullLifecycleExit` 100 times serially through `scripts/run_lifecycle_proofs.sh`, then runs the full lifecycle label 20 times at parallelism four. It restores pre-existing WER values and retains only real failure minidumps, which the workflow uploads for five days. Dumps can still contain host process memory; never publish them as release assets. The PR Check, Architecture, and Quality workflow triggers are intentionally path-unconditional because their job contexts are the ones a repository ruleset is meant to require; that ruleset is not configured yet, so the contexts are advisory until it is. Do not reintroduce a trigger-level `paths` filter that can leave a pull request waiting for a context GitHub never creates; the topology checker refuses one, and permits a filter only on `coverage-pages.yml`'s push route, which republishes what `main` already is.

## Rules

### [B-08]

The release version is single-sourced from there: the generated `DetourModKitConfigVersion.cmake` and the `DMK_VERSION_*` macros derive from it, so a tag that disagrees would ship a package whose `find_package` version check and `DMK_VERSION_AT_LEAST` contradict the tag. The `validate-version` job in `.github/workflows/release.yml` fails closed when the dispatch `version` input does not match, and also cross-checks the one literal version assertion in `tests/test_version.cpp` (`VersionTest.MacrosMatchProjectVersion`) against `project(VERSION)`, so a bump that forgets that test is caught at validate time rather than only at `ctest`. Bump both `project(VERSION)` and the test literal together.

### [B-40]

The library targets x86-64 (Win64) only, enforced by the single `#error` gate in `defines.hpp` (`DMK_ARCH_X64`): a 32-bit or non-x86 configure fails immediately with one clear message, before the pointer-width / ABI-layout `static_assert`s in the x86 decoder (`x86_decode.hpp`) and RTTI layout (`rtti_shared.hpp`) would cascade as opaque backstops. New guarded code follows the scanner fault guards (page-scan, string-xref): only the MSVC-SEH and MinGW-x64-VEH arms, no 32-bit `#else`, so architecture dependence rides on the global gate rather than a local `static_assert`. The MinGW fault-guard engine (`memory_guarded.cpp`) follows the same shape -- its VEH machinery is x64-only and it carries no 32-bit degraded arm, so a non-x64 configure fails at the global gate rather than compiling a fallback.

### [B-71]

MSVC is the primary shipping toolchain and diverges from MinGW on axes a MinGW-only gate cannot see: structured-exception handling vs the vectored-handler fault paths, `/W4`-only diagnostics, and STL behavior (the debug-iterator allocation model, `atomic<shared_ptr>` backing). `pr-check.yml` must build and run `ctest` for BOTH `msvc-debug` and `mingw-debug`, with `/WX` / `-Werror` enabled through `-DDMK_WARNINGS_AS_ERRORS=ON` on both legs. The pull-request `paths` filter that decides whether the gate runs must include `scripts/**`, `cmake/**`, and `Makefile`, or a build-system-only change can slip through ungated.

### [B-72]

An installed or released static archive must not contain toolset-locked intermediate code -- MSVC `/GL` LTCG IL or GCC LTO GIMPLE bytecode -- because that IL is excluded from the toolchain's binary-compatibility guarantee and fails a consumer whose toolset revision differs from the one that built it (`C1047` / `LNK1257` on MSVC even across a 17.x point update; an `lto1` "two or more sections for .gnu.lto_*" mis-link on GCC 15). A shipped archive must be plain objects. Keep IPO OFF for any install-destined build: `DMK_ENABLE_LTO` defaults OFF when DetourModKit is the top-level project (the standalone build that gets installed and packaged) and ON only for an `add_subdirectory` consumer who recompiles DMK from source, where the lock hazard cannot arise. If a package ever must ship LTO objects, document the exact toolchain match requirement (VS toolset version, GCC major) in the README so a consumer knows the archive is toolset-locked. Embedded CodeView (`/Z7`) debug info is NOT toolset-locked IL and is fine to ship.

### [B-93]


- Keep `DMK_BUILD_TESTS` and other build-only options out of exported requirements.
- Keep those options out of installed headers.
- Keep those options out of package files.
- Never override `_ITERATOR_DEBUG_LEVEL`.
- Never export `NOMINMAX`.
- Never export backend macros.
- Never export platform-version defines.
- Keep public headers compatible with `<windows.h>` without `NOMINMAX` through macro-proof spellings.
- Prove that contract with `windows_macro_probe` and `scripts/check_header_hygiene.py`.
- Install release prefixes from tests-OFF producer trees.
- Compare shipped and tested consumer contracts with `scripts/check_export_equality.py`.
- Prove Debug and Release consumer links from one prefix with `tests/package_dual_config`.
- Record the compiler fact in `DetourModKitAbi.cmake`.
- Record the STL fact in `DetourModKitAbi.cmake`.
- Record the CRT fact in `DetourModKitAbi.cmake`.
- Record the iterator-debug fact in `DetourModKitAbi.cmake`.
- Record the target-system fact in `DetourModKitAbi.cmake`.
- Record the target-architecture fact in `DetourModKitAbi.cmake`.
- Record the pointer-size fact in `DetourModKitAbi.cmake`.
- Record the configuration fact in `DetourModKitAbi.cmake`.
- Derive those facts from the producer configure and keep them single-sourced under `[B-08]`.
- Keep policy out of the ABI record.
- Reject compiler-family mismatches in `DetourModKitConfig.cmake`.
- Reject standard-library mismatches in `DetourModKitConfig.cmake`.
- Reject target-system mismatches in `DetourModKitConfig.cmake`.
- Reject normalized-architecture mismatches in `DetourModKitConfig.cmake`.
- Reject pointer-size mismatches in `DetourModKitConfig.cmake`.
- Warn on a compiler major-version difference within one ABI family.
- Permit explicit risk acceptance through `DetourModKit_ALLOW_INCOMPATIBLE_ABI`.
- Reject a non-Windows system at root CMake configure.
- Require native x86-64 Windows in `defines.hpp` and reject ARM64EC.
- Prove platform rejection with `scripts/check_arch_gate.sh` and `scripts/check_abi_reject.py`.
- Give dependency archives the library's `d` debug postfix.
- Select the correct dependency set for each consumer configuration through `DetourModKit::deps`.
- Gate dual-config coexistence with `scripts/check_package_matrix.py`.

### [B-94]

`scripts/check_mechanical_style.py` reads every tracked C/C++ source without exclusions in the blocking `mechanical-style` quality job and rejects three machine-decidable violations: a unicode em (U+2014) or en (U+2013) dash where the house replacement is `--`, an object- or function-like macro whose name is not `UPPER_SNAKE_CASE`, and a namespace-closer comment that names a namespace but matches no house form (a named `} // namespace <Qualified::Name>`, or an anonymous `} // namespace` / `} // anonymous namespace`). The probe decides nothing that needs brace matching, scope analysis, or aesthetic judgement: local `const` / `constexpr` naming, over-120-column lines, mandatory braces, and normalization between the two anonymous forms stay outside this gate. `scripts/test_check_mechanical_style.py` (the `MechanicalStyleCheckerSelfTest` ctest, `script-lint` label) pins each rule with a positive fixture and negative controls, mirroring `[B-86]`'s emit-TLS gate.

### [B-99]

Both are refused mechanically rather than trusted. `scripts/check_workflow_topology.py` holds `validate-version`, `build-mingw`, `build-msvc`, `benchmark-evidence`, and `create-release` to one policy: a readable nonempty body, no `continue-on-error` at job or step level, no swallowed exit status, and no job-level condition beyond the single publish-mode gate `create-release` carries. Two shapes are deliberately not swept up, because a blanket textual ban would force a correct construct out of the workflow: `X="$(cmd || true)"` converts a failure into an empty VALUE that the script must still decide on (a swallow on a bare statement has no such successor and stays refused), and a bare `exit 0` is refused in every job that runs gates but not in `create-release`, whose reviewed outcome includes returning success when the annotated tag already resolves to the exact candidate. Both producers must additionally run the `tests/package_build_tree` consumer and the same-base execution check, and `scripts/test_check_workflow_topology.py` applies each shape to each required job in turn, because a shape covered for four jobs is a shape the fifth can regress through. Every load-bearing step is held to its complete ordered program from `scripts/workflow_contract.py`, so a mutation that keeps each reviewed line while inserting, moving, or wrapping one is refused for not being the reviewed program rather than accepted for still containing the lines somebody grepped for. On the case side, a proof that can `GTEST_SKIP()` publishes an XML property as its LAST statement, after the observation that makes it evidence, and `scripts/check_gtest_execution.py` reads that record back: locally with `--skip-exit-code` so an unqualified host reports Skipped, and in release preflight without it, where an unavailable precondition is a red candidate host. Do not satisfy either gate by naming a checker's own self-test in place of the checker; the pins exclude the `test_` spelling for exactly that reason.
