# AGENTS.md - DetourModKit

This file is the normative rulebook. Each boundary rule states one invariant. It also states a severity tier and a
proof pointer. A proof pointer names one repository proof source.

Follow a rule's `[B-nn]` pointer to the rationale that supports it.

## Project overview

DetourModKit is a C++23 static library for Windows game mods. Mod DLLs use the library inside game processes.

The library provides AOB scans, SafetyHook function hooks, asynchronous logs, INI configuration, input polls, and
memory utilities.

The tool stack is C++23, CMake 3.28 or later, Ninja, and GoogleTest. The project targets MinGW GCC 13 or later and
MSVC 2022 or later.

Key dependencies are git submodules:

- `external/safetyhook` provides inline and mid-function hooks that link Zydis and Zycore. The [hook
  note](docs/design/hooking.md) names its two internal islands and boundary proofs. `[B-01]` defines its source-change
  contract.
- `external/DirectXMath` provides header-only math. Consumers receive it by default through `find_package`. A
  consumer can set `-DDMK_INSTALL_DIRECTXMATH=OFF` to ship only DetourModKit headers.
- `external/simpleini` provides a header-only INI parser.

## Build and test commands

Always initialize submodules first:

```bash
git submodule update --init --recursive
```

`[B-01]` defines the SafetyHook source and configure-time patch contract.

The [hook note](docs/design/hooking.md) records the immutable Zydis commit and expected configured-tree state.

### MinGW (MSYS2 shell)

```bash
cmake --preset mingw-debug
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-debug --parallel
PATH="/c/msys64/mingw64/bin:$PATH" ./build/mingw-debug/tests/DetourModKit_tests.exe
PATH="/c/msys64/mingw64/bin:$PATH" ./build/mingw-debug/tests/DetourModKit_tests.exe --gtest_filter="LoggerTest.*"

# Release (shipping shape: tests OFF)
cmake --preset mingw-release
cmake --build build/mingw-release --parallel

# Release WITH tests, for an optimizer-sensitive gate
cmake --preset mingw-release-tests
cmake --build --preset mingw-release-tests --parallel
ctest --preset mingw-release-tests
```

### MSVC (Developer Command Prompt)

```bash
cmake --preset msvc-debug
cmake --build build/msvc-debug --parallel
ctest --preset msvc-debug

cmake --preset msvc-release
cmake --build build/msvc-release --parallel

cmake --preset msvc-release-tests
cmake --build --preset msvc-release-tests --parallel
ctest --preset msvc-release-tests
```

The `*-release` presets keep tests off. They produce the release archive for the seam scan and package matrix. The
`*-release-tests` presets run the suite under optimization.

ABI, representation, scanner, hook, and arithmetic changes require the release-test lane.

### Installed package smoke test

After you install either release preset, check the export with the checked-in consumer:

```bash
cmake -S tests/package_smoke -B build/package-smoke-mingw -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DDetourModKit_DIR="$PWD/build/install/lib/cmake/DetourModKit" \
    -DCMAKE_CXX_COMPILER=g++
cmake --build build/package-smoke-mingw --parallel
ctest --test-dir build/package-smoke-mingw --output-on-failure
```

### Build-tree consumer proof

`tests/package_build_tree` consumes the repository through `add_subdirectory` with tests off. It checks the consumer
command line for four forbidden leaks: backend include paths, backend macros, `NOMINMAX`, and test-only STL pins.

```bash
cmake -S tests/package_build_tree -B build/package-build-tree-mingw -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
cmake --build build/package-build-tree-mingw --parallel
ctest --test-dir build/package-build-tree-mingw --output-on-failure
```

### Dual-configuration package matrix

```bash
cmake --preset mingw-multi
cmake --build --preset mingw-multi-debug --parallel
cmake --build --preset mingw-multi-release --parallel
cmake --install build/mingw-multi --config Debug --prefix "$PWD/build/install-matrix"
cmake --install build/mingw-multi --config Release --prefix "$PWD/build/install-matrix"
python scripts/check_package_matrix.py "$PWD/build/install-matrix" --configs Debug Release
python scripts/check_abi_reject.py "$PWD/build/install-matrix"
```

`tests/package_dual_config` links and runs Debug and Release consumers from the shared prefix.

### Profiling and benchmarks

```bash
cmake --preset mingw-debug -DDMK_ENABLE_PROFILING=ON
cmake --build build/mingw-debug --parallel

PATH="/c/msys64/mingw64/bin:$PATH" cmake -S . -B build/mingw-release \
    -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-release \
    --target DetourModKit_bench_scanner --parallel
./build/mingw-release/tests/DetourModKit_bench_scanner.exe
```

The benchmark suite has these targets:

- `DetourModKit_bench` covers the dispatcher.
- `DetourModKit_bench_scanner` covers scans.
- `DetourModKit_bench_memory` covers memory access and the protection-cache comparison.
- `DetourModKit_bench_logger` covers asynchronous logs.
- `DetourModKit_bench_footprint` covers logger/profiler resident bytes and high-water.
- `DetourModKit_corpus_sighealth` covers the signature-health estimate against a real x64 corpus.

The [build note](docs/design/build-ci.md) contains the methods and gate records. It also defines the AVX-512 verify
tier. The latest numbers live under `docs/analysis/`.

### Sanitizers (MSVC) and coverage (MinGW)

```bash
cmake --preset msvc-debug-asan
cmake --build --preset msvc-debug-asan --parallel
ctest --preset msvc-debug-asan

cmake --preset mingw-debug-coverage
cmake --build --preset mingw-debug-coverage --parallel
ctest --preset mingw-debug-coverage
```

AddressSanitizer is the only sanitizer that links on Windows, and only under MSVC. It needs
`clang_rt.asan_dynamic-x86_64.dll` on `PATH` at run time. ASan reports false overflows when the scanner and
SEH-guarded probe read arbitrary mapped memory. The [memory guide](docs/guides/memory/asan-memory-scanner.md) contains
the mechanism and extension pattern. The [build note](docs/design/build-ci.md) contains the lane rationale.

### Makefile wrapper

```bash
make              # Build mingw-release
make test         # Build mingw-debug + run tests
make test_msvc    # Build msvc-debug + run tests
make install      # Install to build/install/
make clean        # Remove all build directories
```

## Project layout

The project builds one static-library target. A file location depends on its role, not its module.
`scripts/check_header_hygiene.py` and `scripts/check_install_prefix.py` enforce the placement rules. Each module
documents its API in its header.

- `include/DetourModKit/` contains one public header per module. Each header forms part of the installed API contract.
- `include/DetourModKit/detail/` contains compile-visible support for installed headers. Only files on the allowlist
  belong there. Each file must exclude backends and Win32. The [public API note](docs/design/public-api.md) explains
  the boundary.
- `include/DetourModKit.hpp` is the umbrella header. `include/DetourModKit/session.hpp` contains the process-lifecycle
  API.
- `src/` contains implementation TUs. Each module uses one `.cpp` by default. A cohesive module can use sibling TUs
  over one private engine.
- `src/internal/` contains private engines and backend bridges. Platform code also belongs there. The install excludes
  this directory.
- `tests/` contains one GoogleTest `test_*.cpp` per module. CMake owns the proof targets under `tests/fault/` and
  `tests/lifecycle/`. The [test note](docs/design/testing.md) explains their roles.
- `external/` contains submodules.
- `scripts/` contains tools and CI gates.
- `docs/` contains guides that [docs/README.md](docs/README.md) indexes.

Use this header-placement decision:

1. Put consumer API in `include/DetourModKit/<module>.hpp`.
2. If an installed header needs backend-free, Win32-free support, put that support in `include/DetourModKit/detail/`.
   Add it to the allowlist.
3. Put all other support in `src/internal/`.

A `.cpp` must live beside the kind of header it implements. A TU for an installed header must reside in `src/`. A TU
for `src/internal/*.hpp` must reside in `src/internal/`. The [public API note](docs/design/public-api.md) contains
the rationale.

## Code style

### C++ conventions

- The project uses C++23 with `-std=c++23`. The project prohibits compiler extensions.
- Apply these rules to names:
- Functions, variables, file names, and function-local constants use `snake_case`.
- Use `PascalCase` for types.
- Use `UPPER_SNAKE_CASE` for macros and namespace- or class-scope protocol constants.
- Prefix file-scope statics with `s_` and private or protected members with `m_`.
- Use plain field names for POD structs without invariants.
- Do not put `_` at the end of a name.
- Keep the OS spelling for each Win32-mirror identifier, for example `wButtons`, `dwPacketNumber`, and `hMod`.
- Use descriptive names. Name the value so a reader does not track its contents: `anchor`, not `a`, and `candidate`
  , not `c`. Use `i` through `k` for loop counters and `n` for a count that changes. A small fixed set, a
  conventional math quantity, or a file that already uses a short abbreviation can use single letters. Follow the
  current file.
- Braces must use Allman style. `InsertBraces` remains unset, so a guard clause can omit braces. Every multi-line or
  non-obvious body must have braces.
- Use 4 spaces for indentation. Do not use tabs.
- Apply these namespace rules:
- Put all public API in `namespace DetourModKit`.
- Do not use `using namespace` in headers.
- Wrap `.cpp` definitions in an explicit `namespace DetourModKit { ... }` block.
- Use `namespace DetourModKit::detail { ... }` for a small sibling `detail` scope.
- Use lowercase module namespaces.
- Add a comment after the final brace of each namespace.
- Put implementation-only statics in an anonymous namespace.
- Use `#ifndef DETOURMODKIT_<MODULE>_HPP` include guards. Do not use `#pragma once`.
- Use `"DetourModKit/header.hpp"` for project headers.
- Use angle brackets for external headers.
- Order include groups: project headers, then external headers, then standard headers.

### Comment conventions

Use each comment marker for one purpose:

- Use `/** */` for Doxygen declaration documentation.
- Use `///` for one-line Doxygen declaration documentation.
- Use `//` for implementation explanations.

Document interfaces with declaration comments. Explain implementations with implementation comments.

- Every public class, struct, function, method, or enum declaration requires a Doxygen `/** */` block. Each documented
  internal helper also requires one.
- Every Doxygen block must contain `@brief`. Add `@details`, `@param`, `@return`, `@note`, or `@warning` when the
  content needs the tag.
- If documentation spans multiple lines or uses a structural tag, use a `/** */` block.
- Use `///` as the one-line form of `/** @brief */`. Reserve it for a trivial declaration, write one complete
  sentence, and do not use a structural tag.
- Put member documentation above the member. Do not put `///<` after a member.
- Use `//` inside function bodies to explain why. Do not use it to document a declaration.
- A comment must not use a `// ---` ruler or a boxed label header. `scripts/check_comment_style.py` rejects three or
  more consecutive dashes.
- Every comment must follow the Documentation diet section below. Each comment must earn its space.

### Formatting and tooling

The root `.clang-format` and `.clang-tidy` files define C++ style. Each commit must format its changed `*.cpp` and
`*.hpp` files.

`.github/workflows/quality.yml` runs these checks:

- clang-format 20 checks format.
- clang-tidy checks C++ diagnostics.
- `scripts/check_comment_style.py` checks comment style.
- `scripts/check_mechanical_style.py` checks mechanical style.

Each check fails a PR. The hard column limit is 120. The formatter and analyzer exclude submodules under `external/`.
The [build note](docs/design/build-ci.md) defines the clang-tidy target and suppression policy.

Handle these formatter exclusions by hand:

- Handle doc-blocks with these steps:
- Wrap each doc-block by hand.
- Keep each doc-block within 120 columns.
- Change only line breaks.
- Put each `@tag` on the first line of its paragraph.
- Align each continuation with its text.
- Allow clang-format to reflow plain `//` comments.
- These rules apply to long string literals:
- Split long string literals by hand.
- Use adjacent concatenation at a clause boundary.
- Do not change `BreakStringLiterals: false`.
- Keep the distinctive lead phrase whole.
- Preserve a space at each seam.
- These rules preserve CRLF line endings:
- Keep CRLF line endings.
- If an LF flip occurs, restore it with `unix2dos`.
- After restoration, check the bytes.
- Do not use `-m` because it adds a BOM.
- CRLF applies to the working-tree checkout. `.gitattributes` stores text as LF, so judge a blob's line endings
  and any stored-content digest (for example `WORKFLOW_SOURCE_SHA256`) against the LF-normalized bytes, never
  against checkout bytes.
- Apply these Markdown rules:
- Wrap Markdown prose at 120 columns. A table row or a link-dense line can exceed the limit when its content does not
  fit.
- Do not use an em dash, an en dash, or the superseded `--` pair. Write a single `-` for a true appositive, or split
  the sentence. `scripts/check_mechanical_style.py` gates the Unicode dashes. The `--` pair is review-enforced.

### Type safety and const-correctness

- Use `const` by default. Use `const auto &` in a range-for over containers.
- Use `constexpr` where possible.
- Use `inline constexpr` for namespace-scope header constants.
- Use `static constexpr` for class-scope constants.
- Apply `noexcept` as follows:
- Destructors, shutdown methods, and every function that cannot throw must use `noexcept`.
- Mark each `const` getter that does not allocate as `noexcept`.
- A `const` member that formats or allocates is not a getter under this rule.
- Within a `noexcept` function, wrap every step that can throw in a local `try` / `catch`.
- Fallible work must allocate before a state commit. A failure must leave state unchanged.
- On failure, return a failure or no-op result. Log only through `Logger::log_noexcept` or `Logger::try_log`.
- If an allocation can fail under load, prefer `new (std::nothrow)`.
- If a discarded return value is a likely bug, apply `[[nodiscard]]`.
- Single-argument conversion constructors must use `explicit`. This rule exempts copy and move constructors. It also
  exempts allowlisted vocabulary conversions.
- Apply these cast rules:
- Use C++ casts only.
- Use `(void)expr;` only to discard a `[[nodiscard]]` return.
- Use `reinterpret_cast` only at system boundaries.
- Always use `enum class`. Use `PascalCase` for enumerator names.
- Brace-initialize member defaults. If braces narrow or are ambiguous, use `=` or parentheses.
- Use `nullptr`, never `0` or `NULL`.
- Use `std::string_view` for string parameters that do not own data.

### Resource management and patterns

- Use RAII everywhere. Do not use naked `new` or `delete` in application code. See the [lifecycle
  note](docs/design/lifecycle.md) for the `[B-44]` and `[B-47]` exception.
- If custom resource management is necessary, use the Rule of Five. Otherwise, prefer the Rule of Zero.
- Use the weakest correct atomic order. If the order is not obvious, document the reason. See `[B-04]` and `[B-43]`.
- Code that takes multiple locks must document the order in the class header. `[B-03]` governs compliance.
- Use this two-phase shutdown order:
1. Disable under a shared lock.
2. Drain under the shared lock.
3. Clear under an exclusive lock.
- Use this deferred-log order:
1. Collect each critical-section message in a local.
2. Release the lock.
3. Emit the messages.
- Keep these operations off callback paths:
- Do not take an exclusive lock, perform I/O that can wait, create or remove hooks, or reload configuration.
- Follow `[B-02]` for allocation limits and `[B-15]` for handler exceptions.
- Log through `Logger::log_noexcept` or `try_log`.
- Public docblocks use API-discipline labels (`Callback-safe`, `Setup/control-plane only`, `Best-effort`).
  [docs/design/public-api.md](docs/design/public-api.md) defines each label and owns the scope rule that says
  which docblocks must carry one.
- Use two error-return tiers:
- Return `Result<T>` (`std::expected<T, Error>`) from fallible operations that mutate state.
- Propagate the result through `DMK_TRY` or `DMK_TRY_VOID`.
- Best-effort and query surfaces can return a simple status type: `bool`, `std::optional`, or `void`.
- Document each non- `Result` return. See [docs/design/public-api.md](docs/design/public-api.md).
- Preserve consumer security flags: ASLR, DEP, CFG on MSVC, and the equivalent MinGW flags. Propagate the flags to
  consumers.

### Lambda conventions

- Use `[&]` for immediate lambdas that return into structured bindings.
- Use explicit capture lists when a thread or another object retains a lambda.
- Always specify the return type after the parameter list for a non-trivial lambda.

### Example - good hook install pattern

```cpp
auto r = hook::inline_at({.name = "camera_update", .target = Address{addr}}, &detour);
if (r)
{
    Hook h = std::move(*r);
    auto original = h.original<CameraUpdateFn>();
    // Install verbs return a DISABLED hook: publish everything the detour
    // needs, THEN arm it. Nothing can enter the detour before enable().
    if (!h.enable())
    {
        return;
    }
    original(camera_ptr);
}
```

`[B-15]` governs hook callbacks. The [memory note](docs/design/memory-scanning.md) and [hot-path
guide](docs/guides/memory/hot-path-memory.md) cover per-frame game pointers.

## Documentation diet (HARD RULES)

These rules control volume and placement. The Technical prose rules control wording. Both sets apply to all repository
prose. A review rejects a violation as it rejects a failed test.

1. State each invariant once at the declaration or rule that owns it.
- Use a test name or rule ID as the pointer elsewhere.
2. Keep only the contract and non-obvious reason in a code comment.
- Delete a declaration restatement.
- Delete a step narrative.
- Delete an obvious RAII description.
- Delete policy that another owner states.
3. Exclude prohibited narrative from production code and public docs.
- Do not add narrative essays or historical walkthroughs.
- Do not add rollout or migration history.
- Do not add audit references.
- Do not add prompt commentary.
- Do not add AI commentary.
- Do not add meta commentary.
4. Prefer deletion or an available guide pointer over these additions.
- Do not add a rule without need.
- Do not add a checker without need.
- Do not add an abstraction without need.
- Do not add an essay without need.
5. Collapse duplicate code into one local helper with one proof.
- If code publishes a genuinely different order, keep it separate.
6. Preserve every contract or fact that a caller cannot derive.
- Preserve behavior contracts.
- Preserve ownership and lifetime rules.
- Preserve thread and loader restrictions.
- Preserve error semantics.
- Preserve security warnings.
- Preserve required Doxygen tags.
7. Do not use the em dash or en dash character, and do not use the superseded `--` pair. During the work, replace each
   one with a single `-`, or split the sentence.

### Technical prose

- Classify each sentence as a procedure or a description.
- Write procedures in the imperative mood with one instruction and no more than 20 words.
- Write descriptions in simple present or simple past tense with no more than 25 words.
- Keep one topic in each descriptive paragraph and no more than six sentences.
- Use active voice and complete grammar.
- Put a condition before its command.
- Use a vertical list for more than two items that a reader looks up individually. Collapse a run of same-shape
  fragments into one sentence with an inline enumeration.
- Do not use `-ing` verb forms, present perfect, contractions, or semicolons.
- Use `must` for requirements and `can` for capability.
- Use `may` only for precise permission in a public API contract.
- Do not use `should`, `would`, `might`, or `could`.
- Use one term for one meaning and keep noun groups to three nouns.
- Use `check` for a read of current state. Use `verify` for an empirical proof by a test or gate. Do not use `confirm`
  or `ensure` where one of those two meanings applies.
- Use American English and delete filler words.
- Put a warning's command or condition before its consequence.
- Preserve code blocks, identifiers, CLI forms, paths, and quoted errors exactly.

## Testing

- GoogleTest uses `tests/main.cpp` as its entry point.
- `DMK_BUILD_TESTS=ON` enables tests.
- Debug presets enable tests by default.
- Use `ctest` as the canonical runner.
- Treat each separate test process as the real verdict.
- Also run the unit binary whole. A case that mutates a process-wide singleton restores it or owns its own proof host.
  See [docs/design/testing.md](docs/design/testing.md).
- For fast iteration, use the standalone executable with `--gtest_filter`.
- After fast iteration, run `ctest` as the final check.
- Make test files mirror the surface they test. Split a large module by one owned seam:
- A fault-frame state can define the seam.
- A backend surface can define the seam.
- An integration boundary can define the seam.
- Include `_getpid()` and a counter in each temporary file name for a test. See
  [docs/design/testing.md](docs/design/testing.md).
- Maintain at least 80% line coverage in CI.

The [test note](docs/design/testing.md) contains every non-obvious test rule.
[docs/tests/README.md](docs/tests/README.md) contains full per-suite coverage.

## Git workflow

- Use Conventional Commits (`type(scope): description`) for commit messages. The allowed types are `feat`, `fix`,
  `perf`, `refactor`, `test`, `docs`, and `chore`. Use a module name for the scope, and omit the scope for a
  cross-module change.
- Use `main` as the default branch and PR target.
- Prefer a squash merge for PRs. Use the commit format for each PR title.

## Architecture notes

- `config` depends on `input`. `input` must not depend on `config`.
- The [design-note index](docs/README.md#design-notes) lists each subsystem concurrency model and hot-path mechanism.

These paths run at 60 fps or more from game callbacks. `[B-02]` governs allocation. Each listed lock is the only
permitted synchronization.

- `detail::InputPoller::is_binding_active(index/name/token)` uses a `shared_lock` and a relaxed load.
- The `Logger::log()` level check and `is_enabled()` use one atomic load.
- The `Logger::log()` asynchronous enqueue uses an atomic shared-pointer snapshot and a lock-free queue push. The
  snapshot uses a bounded internal lock.
- `memory::is_readable(Region)` uses a sharded SRWLOCK reader and a cache lookup.
- `memory::is_readable_nonblocking(Region)` uses a shared try-lock and a cache lookup. It returns `Unknown` after
  contention or an unpublished cache result.
- `memory::walk(base, {offsets})` uses one walk and one out-of-line call. It issues one `guarded_read_bytes` for each
  intermediate hop and screens the leaf without a copy. The walk screens each hop against that hop's `min_valid` floor
  and `USERSPACE_PTR_MAX`. The bare-offset overload uses a 32-entry stack buffer and returns `SizeTooLarge` past it.
- `memory::read<T>()`, `memory::read_into()`, `memory::write_in_place<T>()`, and each `memory::walk()` hop are
  guarded paths. They use SEH under MSVC and a vectored handler under MinGW x64. The normal path does not call
  `VirtualQuery` for each operation. If MinGW cannot install the vectored handler, byte copies use `VirtualQuery` and
  process-memory APIs.
- `memory::unchecked::read<T>()` uses a raw copy without validation. The caller must prove that the range is committed
  and readable.
- `memory::is_plausible_ptr(Address)` and `Region::contains(Address)` use constant expression arithmetic without a
  system call.
- `rtti::vtable_is_type(vt, expected)` uses a module-region lookup and three guarded reads. The reads are the `[-1]`
  meta-slot qword, the 24-byte COL, and `expected.size() + 1` name bytes. It does not allocate.
- The `find_in_pointer_table` warm path reads each slot's object and vtable qwords, then compares against the cached
  vtable. It runs no RTTI walk. The generation-checked `PointerTableCache` overload also reads the image-generation
  token twice for each call.
- The `TypeIdentity::matches` warm path reads the image-generation token once, then compares the cached vtable qword.
  It runs no RTTI walk. A changed token drops the cache and forces a cold resolve.

## Boundaries

Each rule has a stable, greppable ID from `B-01` through `B-NN`. A review or commit can cite that ID. The command
`grep '\[B-42\]' AGENTS.md docs/design/*` finds an example.

A new rule must use the next free ID. No rule can reuse an ID.

Severity tiers have these meanings:

- `[SAFETY]` marks host-safety and memory-safety hazards.
- `[CORRECTNESS]` marks incorrect or fail-open results. It also marks silent errors.
- `[CONVENTION]` marks repository policy.

A same-ID design-note pointer owns the complete rationale for that rule. A generic note link supplies evidence or
context but does not transfer ownership. A short rule contains its complete contract.

- `[B-01]` `[CONVENTION]` **Backend edits must not share an ordinary DetourModKit change.** Files under `external/`
  are submodules. A backend fix must have an isolated upstreamable commit and a gitlink pin. DMK reapplies the
  vendored patch at configure time. `scripts/check_backend_patch.py` proves byte equality.
  [docs/design/hooking.md](docs/design/hooking.md) `[B-01]` owns the rationale.
- `[B-02]` `[CONVENTION]` **The listed 60+ fps callback paths must not add heap allocations.** The [hot-path proof
  inventory](docs/design/testing.md#hot-path-proof-inventory) identifies the evidence.
- `[B-03]` `[SAFETY]` **Code must preserve each lock order documented in a class header.** The [lock-order proof
  locations](docs/design/testing.md#lock-order-proof-locations) identify the evidence.
- `[B-04]` `[SAFETY]` **Code must not weaken an atomic memory order without a correctness proof.**
  [docs/design/hooking.md](docs/design/hooking.md) `[B-43]` supplies related proof.
- `[B-05]` `[CORRECTNESS]` **Cache reads and stores must derive the same key.**
  [docs/design/memory-scanning.md](docs/design/memory-scanning.md) `[B-05]` owns the rationale for `find_in_shard` and
  `check_memory_permission`.
- `[B-06]` `[CONVENTION]` **The test suite must run before each commit.**
  [docs/design/testing.md](docs/design/testing.md) supplies the test policy.
- `[B-07]` `[CONVENTION]` **Debug tests and release builds must pass on both toolchains.** Each installed-package
  smoke test must also pass before publication. [docs/design/build-ci.md](docs/design/build-ci.md) defines the gates.
- `[B-08]` `[CONVENTION]` **A release tag must match the `project(VERSION ...)` value in `CMakeLists.txt`.** The
  `validate-version` job and `VersionTest.MacrosMatchProjectVersion` cross-check the single source.
  [docs/design/build-ci.md](docs/design/build-ci.md) `[B-08]` owns the rationale.
- `[B-09]` `[CONVENTION]` **Header code that calls a Windows API must use an `#ifdef _WIN32` guard.** Implementation
  files are Windows-only. The [Windows header boundary](docs/design/public-api.md#windows-header-boundary) defines
  this scope.
- `[B-10]` `[CONVENTION]` **Generated build artifacts must not enter commits.**
  [docs/design/build-ci.md](docs/design/build-ci.md) supplies related evidence.
- `[B-11]` `[CONVENTION]` **A change must not remove or weaken current tests.** New code must have new tests.
  [docs/design/testing.md](docs/design/testing.md) supplies the test policy.
- `[B-12]` `[CONVENTION]` **Top-level public API must not expose implementation-only container or entry types.** Such
  types must remain in `namespace detail` or an internal header. A backend type must stay behind a forward-declared
  `Impl`. [docs/design/public-api.md](docs/design/public-api.md) `[B-12]` owns the rationale.
- `[B-13]` `[CONVENTION]` **If one listed trigger applies, a public function must use a request or options struct.**
  The struct must default-initialize its fields for designated initialization. Each new field must follow all
  established fields. [docs/design/public-api.md](docs/design/public-api.md) `[B-13]` owns the rationale. The triggers
  are adjacent parameters of the same type, more than about five parameters, or at least three counted knobs.
  Optional, policy, and configuration knobs all contribute to the count.
- `[B-14]` `[CONVENTION]` **Output code must use `'\n'` instead of `std::endl`.** `std::endl` forces a flush.
  [docs/design/build-ci.md](docs/design/build-ci.md) supplies related evidence.
- `[B-15]` `[SAFETY]` **Hook callbacks must use `EventDispatcher::emit_safe()`.** It contains handler exceptions.
  `EventDispatcherTest.EmitSafe_CatchesHandlerExceptions` proves the contract.
- `[B-16]` `[SAFETY]` **Teardown must destroy layered hooks on one target newest-first.** `hook::HookStack` enforces
  this order. [docs/design/hooking.md](docs/design/hooking.md) `[B-16]` owns the rationale.
- `[B-17]` `[SAFETY]` **After byte modification starts, a write helper must complete post-write cache maintenance.**
  Cache flush and invalidation have separate triggers. Failure precedence must remain truthful.
  [docs/design/memory-scanning.md](docs/design/memory-scanning.md) `[B-17]` owns the rationale.
- `[B-18]` `[SAFETY]` **Protection changes and restoration must process one `VirtualQuery` region at a time.** One
  protection value must not span a protection seam. [docs/design/memory-scanning.md](docs/design/memory-scanning.md)
  `[B-18]` owns the rationale for `detail::protect_across_regions`.
- `[B-19]` `[CORRECTNESS]` **A range permission query that can cross a protection seam must inspect every touched
  `VirtualQuery` region.** [docs/design/memory-scanning.md](docs/design/memory-scanning.md) `[B-19]` owns the
  rationale for `range_permission_uncached`.
- `[B-20]` `[SAFETY]` **After a claimed `PAGE_GUARD` fault, a guarded read must re-arm the page through the shared
  filter.** [docs/design/memory-scanning.md](docs/design/memory-scanning.md) `[B-20]` owns the rationale.
- `[B-21]` `[SAFETY]` **A typed `write<T>` or `write_in_place<T>` template in an overload set with a byte-span sink
  must exclude borrowed views.** The constraint must use `!detail::is_non_owning_view_v<...>`, so a view causes a
  compile error instead of a bit-copy. [docs/design/memory-scanning.md](docs/design/memory-scanning.md) `[B-21]` owns
  the rationale.
- `[B-22]` `[CONVENTION]` **Public documentation must match implementation behavior.** A test is the preferred proof
  for lifecycle and ordering claims. [docs/design/public-api.md](docs/design/public-api.md) supplies related evidence.
- `[B-23]` `[CONVENTION]` **Header comments must state only measured atomicity claims.** An `is_lock_free()` probe
  must support a lock-free claim. Otherwise, the comment must state the honest bound.
  `std::atomic<std::shared_ptr<T>>` is not lock-free on either toolchain.
  `EventDispatcherTest.AtomicSharedPtrIsNotLockFree` proves that bound. [docs/design/events.md](docs/design/events.md)
  `[B-23]` owns the rationale.
- `[B-24]` `[CORRECTNESS]` **Every cache operation must use one key model.** `memory::invalidate_range` scans every
  shard because query addresses select storage. `MemoryTest.InvalidateRangeEvictsMultiPageRegionInterior` proves
  interior eviction. The model defines the canonical key, the shard-selection function, and the containment lookup.
  Cache reads, storage, invalidation, and eviction must all use that one model.
- `[B-25]` `[SAFETY]` **Each queue or backlog that external events drive must have a bound.**
  `WheelPulseTest.AddWheelNotchesClampsRunawayBacklog` proves the wheel-queue bound.
  [docs/design/input.md](docs/design/input.md) `[B-25]` owns the raw-counter mechanism and its conditional evidence.
- `[B-26]` `[CORRECTNESS]` **Intercepted chord suppression must use the complete owned chord and current modifier
  state, not one global flag.** Each poll cycle must publish it with a TTL. The arm-to-disarm edge must disarm it.
  [docs/design/input.md](docs/design/input.md) `[B-26]` owns the rationale.
- `[B-27]` `[CORRECTNESS]` **After its source retires, passthrough suppression must not remain active.**
  `set_consume_by_owner` must clear `consume` by identity and republish. [docs/design/input.md](docs/design/input.md)
  `[B-27]` owns the rationale.
- `[B-28]` `[CORRECTNESS]` **All entries for one consume registration must publish as one batch.** A partial append
  can retain `consume=true` after an OOM.
  `InputPollerTest.AddBindingsReturnsFalseWithoutPartialBatchWhenGrowthAllocationFails` proves atomic publication.
- `[B-29]` `[CORRECTNESS]` **Exploded entries that share one teardown gate must use a reference count.** They must
  forward only the aggregate transition. [docs/design/input.md](docs/design/input.md) `[B-29]` owns the rationale for
  `HoldGate` and `active_entries`.
- `[B-30]` `[SAFETY]` **RAII cancellation must not complete before the gated callback exits.** Delivery must use a
  per-registration gate. Callback invocation must occur outside the gate mutex. An in-flight count must bracket the
  invocation. [docs/design/input.md](docs/design/input.md) `[B-30]` owns the rationale.
- `[B-31]` `[CORRECTNESS]` **Window-procedure detour removal must preserve the saved predecessor at the real
  procedure.** It must clear only the install-state flags. [docs/design/input.md](docs/design/input.md) `[B-31]` owns
  the rationale.
- `[B-32]` `[CORRECTNESS]` **An asynchronous or deferred sink must not diverge from its synchronous counterpart's
  configuration.** The contract includes timestamp format and level. `Logger::enable_async_mode` carries timestamp
  format. The facade applies the level before either path. `LoggerTest.ReconfigureFormatReachesLiveAsyncWriter` proves
  only live format updates.
- `[B-33]` `[CORRECTNESS]` **A shared append file must open with `FILE_APPEND_DATA`.** The OS positions each write at
  the current end atomically. `WinFileStreamBufTest.AppendMode_ConcurrentAppendersPreserveEveryByte` proves the
  contract. Truncation must use `GENERIC_WRITE` with `CREATE_ALWAYS`.
- `[B-34]` `[CORRECTNESS]` **A `WriteFile` request must loop until it drains the complete request or fails.** A failed
  drain must retain the recoverable tail. `close()` must report a failed drain or `CloseHandle` failure.
  [docs/design/logging.md](docs/design/logging.md) `[B-34]` owns the rationale and names `WinFileStreamBufTest`.
- `[B-35]` `[CORRECTNESS]` **An off-table input code must preserve its device source.** A non-keyboard code must use
  source-tagged hex form, such as `Mouse:0xNN`. `parse_input_name` reads that form.
  [docs/design/input.md](docs/design/input.md) `[B-35]` owns the rationale.
- `[B-36]` `[SAFETY]` **Each invocation site must contain exceptions from a user callback with a no-throw contract.**
  An escaped exception can free a resource that a live kernel IRP references.
  [docs/design/config.md](docs/design/config.md) `[B-36]` owns the rationale for `ConfigWatcher::fire_reload`.
- `[B-37]` `[CORRECTNESS]` **Config and input resolution paths must use locale-independent parses.** They must use
  `std::from_chars` and an ASCII case-fold. An invalid value must fall back with a `Warning`, never silently.
  [docs/design/config.md](docs/design/config.md) `[B-37]` owns the rationale.
- `[B-38]` `[CORRECTNESS]` **After a config read failure, the load path must clear the cached hash and return before
  the setter pass.** It must remember the target path after every outcome.
  [docs/design/config.md](docs/design/config.md) `[B-38]` owns the rationale.
- `[B-39]` `[CORRECTNESS]` **An incomplete guarded sweep or bounded matcher must produce an ambiguous uniqueness
  result.** The implementation must honor the `incomplete` signal.
  [docs/design/resolution.md](docs/design/resolution.md) `[B-39]` owns the rationale.
- `[B-40]` `[CONVENTION]` **Each architecture-dependent engine must use the single x86-64 gate in `defines.hpp`.** It
  must not add a 32-bit fallback or another architecture guard. [docs/design/build-ci.md](docs/design/build-ci.md)
  `[B-40]` owns the rationale.
- `[B-41]` `[CONVENTION]` **The hook surface must remain limited to SafetyHook-backed hooks and VMT hooks.** The
  backend family includes inline and mid-function hooks. Excluded families remain outside project scope.
  [docs/design/hooking.md](docs/design/hooking.md) `[B-41]` owns the rationale. [The hook type
  guide](docs/guides/hooking/hook-type-coverage.md) supplies context.
- `[B-42]` `[SAFETY]` **A live detour must retain its inline-hook object until no game thread can execute the detour
  body.** Teardown must retire the trampoline pointer and drain the bounded in-flight counter after the install thread
  joins. It must then witness target bytes. [docs/design/hooking.md](docs/design/hooking.md) `[B-42]` owns the
  rationale.
- `[B-43]` `[SAFETY]` **All four operations in a retire-then-drain teardown must use the `seq_cst` total order.**
  [docs/design/hooking.md](docs/design/hooking.md) `[B-43]` owns the rationale.
- `[B-44]` `[SAFETY]` **A detach-and-leak path must hold a counted module reference acquired while the module is
  live.** A request from a detach path must remain a no-op. [docs/design/lifecycle.md](docs/design/lifecycle.md)
  `[B-44]` owns the rationale for `detail::acquire_module_ref`.
- `[B-45]` `[SAFETY]` **Code must not drop final worker ownership while it holds a mutex that the worker needs to
  exit.** A worker-touched control block is part of that ownership. Code must move the owner to a local before lock
  release. `ConfigTest.ClearDisposesReloadHotkeyGuardsOutsideTheWatcherMutex` proves this order. After all relevant
  locks release, code can reset the owner, join the worker, or leak the owner.
- `[B-46]` `[SAFETY]` **The `[B-87]` handler-retirement contract governs every `[B-46]` citation.**
  [docs/design/events.md](docs/design/events.md) `[B-46]` records the supersession rationale.
- `[B-47]` `[SAFETY]` **State reachable after its static destruction must not use a function-local Meyers singleton.**
  Such state must use placement-new in never-destroyed storage or an idempotent `shutdown()` destructor path.
  [docs/design/lifecycle.md](docs/design/lifecycle.md) `[B-47]` owns the rationale.
- `[B-48]` `[SAFETY]` **Each pimpl destructor must remain safe under the loader lock.** It must not depend on every
  owner to leak its handle. If teardown detaches a thread that still reads `Impl`, the destructor must latch a detach
  flag. It must then call `m_impl.release()`. The subsystem must refuse resurrection after shutdown.
  [docs/design/lifecycle.md](docs/design/lifecycle.md) `[B-48]` owns the rationale.
- `[B-49]` `[SAFETY]` **A raceable teardown handle must remain atomic and open.** This rule covers APIs callable from
  any thread after teardown. A raceable path must not close the handle. Both ends of the admission word must use
  compare-exchange. [docs/design/lifecycle.md](docs/design/lifecycle.md) `[B-49]` owns the rationale.
- `[B-50]` `[CORRECTNESS]` **A worker snapshot must receive every update to a runtime-mutable configuration field.**
  The update must use the mutex that protects worker reads. The caller must hold the shared log mutex before
  `AsyncLogger::set_timestamp_format` assigns. [docs/design/logging.md](docs/design/logging.md) `[B-50]` owns the
  rationale.
- `[B-51]` `[CORRECTNESS]` **Logged drift telemetry must not enable a patch-fragile feature.** The feature must use
  `anchor::evaluate_gate` with its fail-closed default. [docs/design/resolution.md](docs/design/resolution.md)
  `[B-51]` owns the rationale.
- `[B-52]` `[CORRECTNESS]` **A critical target must use N-of-M corroboration with pairwise-independent evidence.** The
  implementation must compare that evidence by content. [docs/design/resolution.md](docs/design/resolution.md)
  `[B-52]` owns the rationale.
- `[B-53]` `[CORRECTNESS]` **A recovered hooked prologue must use `FallbackPolicy::RequireIdentity` and a witness
  before code trusts it.** The `WarnOnly` default of `scan::borrow_code_target` is the read tier for a recovered
  site that code does not yet trust. [docs/design/resolution.md](docs/design/resolution.md) `[B-53]` owns the
  rationale.
- `[B-54]` `[CONVENTION]` **A patch-fragile contract must ship as editable data, not only code.** The `manifest`
  module must serialize the resolved anchor and its `binding`. Mutation authorization must require the complete
  baseline set. [docs/design/resolution.md](docs/design/resolution.md) `[B-54]` owns the rationale.
- `[B-55]` `[CORRECTNESS]` **When gap size can shift, a signature must use a bounded jump instead of a fixed wildcard
  run.** The extension must remain a faithful bounded subset with its anchor in segment 0.
  [docs/design/resolution.md](docs/design/resolution.md) `[B-55]` owns the rationale.
- `[B-56]` `[CORRECTNESS]` **Bounded-jump carry must use the maximum span, and match counts must use the end
  position.** A bounded-jump match has a variable span. [docs/design/resolution.md](docs/design/resolution.md)
  `[B-56]` owns the rationale for `RawMatch{start, end, point}`.
- `[B-57]` `[CONVENTION]` **Each patch-fragile signature must pass offline lint before release.** Health must not gate
  runtime behavior. [docs/design/resolution.md](docs/design/resolution.md) `[B-57]` owns the rationale.
- `[B-58]` `[CORRECTNESS]` **An unset anchor kind or mandatory evidence must fail closed instead of produce a trusted
  zero.** Each rung or record entry must enforce mode-dependent keys.
  [docs/design/resolution.md](docs/design/resolution.md) `[B-58]` owns the rationale.
- `[B-59]` `[CORRECTNESS]` **Manifest overlays must follow the `manifest::overlay` contract.** `ManifestOverlayTest`
  (T-MANIFEST-POLICY) supplies proof. [docs/design/resolution.md](docs/design/resolution.md) `[B-54]` supplies related
  rationale.
- `[B-60]` `[CORRECTNESS]` **A prefix scan must skip every prefix that does not resolve and return the first
  resolvable prefix.** An implausible or unreadable target is a decoy. After exhaustion, the scan must report the last
  concrete decode failure. [docs/design/resolution.md](docs/design/resolution.md) `[B-60]` owns the rationale.
- `[B-61]` `[CORRECTNESS]` **A phase-2 window scan must use the same cross-window back-carry as its phase-1 peer.**
  [docs/design/resolution.md](docs/design/resolution.md) `[B-61]` owns the rationale for `find_string_xref`.
- `[B-62]` `[CORRECTNESS]` **Code must not rebuild a bounded-jump pattern through flat byte and mask concatenation.**
  `build_rebuilt_prologue` must fail closed when `original.has_jumps()`.
  [docs/design/resolution.md](docs/design/resolution.md) `[B-62]` owns the rationale.
- `[B-63]` `[CORRECTNESS]` **Phase-2 `string-xref` uniqueness must identify the certified shapes.** A derived return
  must run the broad Zydis sweep as a second check. [docs/design/resolution.md](docs/design/resolution.md) `[B-63]`
  owns the rationale.
- `[B-64]` `[CORRECTNESS]` **Function boundary recovery must use authoritative `.pdata`.** `enclosing_function_start`
  must call `RtlLookupFunctionEntry` first. The RET/INT3 back-scan must serve only as the leaf or no-unwind fallback.
  [docs/design/resolution.md](docs/design/resolution.md) `[B-64]` owns the rationale.
- `[B-65]` `[SAFETY]` **The segmented matcher must stay bounded, and allocation failures must remain recoverable.**
  `SEGMENT_MATCH_STEP_BUDGET` defines the work bound. [docs/design/resolution.md](docs/design/resolution.md) `[B-65]`
  owns the rationale.
- `[B-66]` `[SAFETY]` **Unchecked backends must not enter foreign-memory fault paths, and allocation-size facts must
  become immutable before backend use.** Code must guard-copy the complete span and detach the backend. Its atomic
  compare-exchange must stay within that span. [docs/design/hooking.md](docs/design/hooking.md) `[B-66]` owns the
  rationale.
- `[B-67]` `[CONVENTION]` **Each per-frame resolve that does not latch a miss must use a throttle.** The miss must
  remain unlatchable. `RESOLVE_RETRY_COOLDOWN_MS` must gate each new sweep.
  [docs/design/resolution.md](docs/design/resolution.md) `[B-67]` owns the rationale.
- `[B-68]` `[CORRECTNESS]` **A hot loop must resolve the module that owns its target once.** Each candidate validator
  must receive that module, not the scan scope. [docs/design/resolution.md](docs/design/resolution.md) `[B-68]` owns
  the rationale for `resolve_col_site`.
- `[B-69]` `[CORRECTNESS]` **A `SystemCallFailed` site must set `Error::detail` from `GetLastError()` before another
  operation can replace the value.** [docs/design/public-api.md](docs/design/public-api.md) `[B-69]` owns the
  rationale.
- `[B-70]` `[SAFETY]` **A `weak_ptr` teardown guard contract must cover ordered destruction only, not concurrent
  destruction.** [docs/design/events.md](docs/design/events.md) `[B-70]` owns the rationale for
  `EventDispatcher::Subscription::reset`.
- `[B-71]` `[CONVENTION]` **Every PR must pass both toolchains.** `pr-check.yml` must build and run `ctest` for
  `msvc-debug` and `mingw-debug` with `warnings-as-errors` on both legs.
  [docs/design/build-ci.md](docs/design/build-ci.md) `[B-71]` owns the rationale.
- `[B-72]` `[CONVENTION]` **A release archive must remain portable and contain no toolset-locked intermediate code.**
  IPO must stay off for each install-destined build. `DMK_ENABLE_LTO` defaults off at top level.
  [docs/design/build-ci.md](docs/design/build-ci.md) `[B-72]` owns the rationale.
- `[B-73]` `[SAFETY]` **A timeout or lock inversion must retain every undrained teardown resource.** Each teardown
  wait must have a finite bound or proof that it drains a closed set. The counted module reference must remain held.
  Each leak must increment its `diagnostics::LeakSubsystem` counter.
  [docs/design/lifecycle.md](docs/design/lifecycle.md) `[B-73]` owns the rationale and names `MidHookDrainTest`.
- `[B-74]` `[SAFETY]` **Logic-DLL unmap authorization must require a typed off-loader drain.**
  `prepare_logic_dll_unload*` must own one end-to-end deadline. Only `SafeToUnload` can authorize `FreeLibrary`.
  [docs/design/lifecycle.md](docs/design/lifecycle.md) `[B-74]` owns the rationale.
- `[B-75]` `[CORRECTNESS]` **Instruction selectors must follow the decode-epoch contract.** `scan::read_code_constant`
  and `CodeConstantEpochTest` (T-CODE-EPOCH) define and prove the contract.
- `[B-76]` `[CORRECTNESS]` **Forward value-attribution scans must stop at every non-fall-through boundary.**
  Conditional branches must not stop the scan. [docs/design/resolution.md](docs/design/resolution.md) `[B-76]` owns
  the rationale for `scan_store_slot_after_lea`.
- `[B-77]` `[CORRECTNESS]` **Uniqueness and independence verdicts must use content identity.** A shape subset or
  policy-flag difference must not certify either verdict. [docs/design/resolution.md](docs/design/resolution.md)
  `[B-77]` owns the rationale.
- `[B-78]` `[CONVENTION]` **A public header must not inject a global-namespace identifier without a documented opt-out
  macro.** `defines.hpp` must wrap the `dmk` and `DMK` aliases in `#if !defined(DMK_NO_NAMESPACE_ALIASES)`.
  [docs/design/public-api.md](docs/design/public-api.md) `[B-78]` owns the rationale.
- `[B-79]` `[SAFETY]` **Code must revalidate each dropped-lock teardown decision under its lock before the
  irreversible step.** [docs/design/config.md](docs/design/config.md) `[B-79]` owns the rationale for
  `HookLedger::acquire_target_slot` and the watcher re-point.
- `[B-80]` `[SAFETY]` **Every callback worker must have self-join and self-invocation guards.** This requirement
  covers the watcher worker and reload-servicer worker. [docs/design/config.md](docs/design/config.md) `[B-80]` owns
  the rationale.
- `[B-81]` `[SAFETY]` **Each execution-trap record must remain transaction-scoped.** Every path must remove the
  record. An execute fault on either affected page must retry until protection returns.
  [docs/design/hooking.md](docs/design/hooking.md) `[B-81]` owns the rationale.
- `[B-82]` `[CONVENTION]` **A submodule SHA must be available from its configured URL.** An upstream Git reference
  must publish it. The remote must permit a fetch. `scripts/check_backend_patch.py` checks the SafetyHook pin and URL.
- `[B-83]` `[SAFETY]` **An inline or mid hook install verb must not arm the hook.** Code must publish the handle and
  context before `Hook::enable()`. `vmt_for` is live at creation. [docs/design/hooking.md](docs/design/hooking.md)
  `[B-83]` owns the rationale.
- `[B-84]` `[SAFETY]` **C++ exceptions must stop before each non-unwindable frame.** DMK-generated routed code must
  register unwind records before publication. A raw arbitrary-signature detour must document a no-throw contract.
  [docs/design/hooking.md](docs/design/hooking.md) `[B-84]` owns the rationale.
- `[B-85]` `[SAFETY]` **Each callback must retire before rundown, and each undrained resource must remain pinned.**
  Teardown must never wait on the caller thread. A timeout must not count as a drain.
  [docs/design/hooking.md](docs/design/hooking.md) `[B-85]` owns the rationale.
- `[B-86]` `[SAFETY]` **Code on arbitrary host threads must not access `thread_local`.** MinGW lowers it to emutls,
  which calls `abort()` after first-touch OOM. Install code must reserve a Win32 TLS index.
  `scripts/check_emit_tls.py` proves compliance. [docs/design/input.md](docs/design/input.md) `[B-86]` owns the
  rationale.
- `[B-87]` `[SAFETY]` **Logical death must not depend on allocation.** A preallocated tombstone must retire each
  callable entry. Physical compaction must remain a separate best-effort step.
  [docs/design/events.md](docs/design/events.md) `[B-87]` owns the rationale.
- `[B-88]` `[SAFETY]` **A callback-safe writer wake must occur outside control-plane mutexes.** Only an inline
  `DropNewest` producer is callback-safe. The producer must signal a parked writer through the auto-reset Win32 event.
  The parked flag must gate that signal. [docs/design/logging.md](docs/design/logging.md) `[B-88]` owns the rationale.
- `[B-89]` `[SAFETY]` **When teardown cannot drain, installation must acquire teardown prerequisites before
  publication.** The prerequisites include both required module references and retention storage. Installation must
  fail when any prerequisite is unavailable. [docs/design/hooking.md](docs/design/hooking.md) `[B-89]` owns the
  rationale.
- `[B-90]` `[SAFETY]` **Self-thread teardown must transfer ownership to another thread.** The worker must neither
  dispose of nor abandon the owner. It must hand the reference to the process-lifetime reaper. The call remains
  asynchronous. [docs/design/lifecycle.md](docs/design/lifecycle.md) `[B-90]` owns the rationale.
- `[B-91]` `[SAFETY]` **After construction failure, each `noexcept` singleton accessor must publish one complete
  fail-closed object and latch the failure for the process.** [docs/design/lifecycle.md](docs/design/lifecycle.md)
  `[B-91]` owns the rationale.
- `[B-92]` `[CORRECTNESS]` **Consumed state must commit only after the complete callback stage pass succeeds.** Each
  staged record must carry its transition. A no-throw loop must apply the records. Code must restore a destructively
  consumed source after failure. [docs/design/input.md](docs/design/input.md) `[B-92]` owns the rationale.
- `[B-93]` `[CONVENTION]` **Installed package contracts must exclude build options and record each ABI axis as data.**
  They must not export build-only macros or STL configuration. Consumers must reject mismatches.
  `tests/package_dual_config` proves Debug and Release consumers from one prefix.
  [docs/design/build-ci.md](docs/design/build-ci.md) `[B-93]` owns the rationale.
- `[B-94]` `[CONVENTION]` **Each mechanically decidable naming, namespace-comment, or Unicode-dash rule must use a
  gate.**
  `scripts/check_mechanical_style.py` proves the contract. [docs/design/build-ci.md](docs/design/build-ci.md) `[B-94]`
  owns the rationale.
- `[B-95]` `[SAFETY]` **Each linked DMK instance must have one interception layer and one owner epoch.** Each
  `InputPoller` must present its nonzero owner ID. Authorization must require an exact live-owner match. Teardown must
  clear all interception state before the bounded detour drain. [docs/design/input.md](docs/design/input.md) `[B-95]`
  owns the rationale.
- `[B-96]` `[SAFETY]` **Input callback rundown must protect staged callable lifetime and registration commits.** A
  lease must span dispatch and end after destruction of the copied callable. Self-delivery must fail instead of wait.
  [docs/design/input.md](docs/design/input.md) `[B-96]` owns the rationale.
- `[B-97]` `[SAFETY]` **Target bytes must determine a hook's published state.** Code must never write over
  unattributed bytes. The patch model has four states: `Original`, `OwnedPatch`, `Foreign`, and `Indeterminate`. A
  toggle must refuse `Foreign` and `Indeterminate`. [docs/design/hooking.md](docs/design/hooking.md) `[B-97]` owns
  the rationale.
- `[B-98]` `[SAFETY]` **Each WndProc uninstall exchange must act as a reconciliation transaction.** Its returned
  displaced procedure is authoritative. If the exchange does not displace DMK, code must not publish the uninstalled
  state. [docs/design/input.md](docs/design/input.md) `[B-98]` owns the rationale.
- `[B-99]` `[CORRECTNESS]` **Job presence and host-conditional success must not count as required release evidence.**
  `scripts/check_workflow_topology.py` and `scripts/check_gtest_execution.py` reject both cases.
  [docs/design/build-ci.md](docs/design/build-ci.md) `[B-99]` owns the rationale.
- `[B-100]` `[SAFETY]` **Each public module contract must state its loader-lock boundary.** The module header must own
  that boundary. A named loader proof must pin the contract. The [loader-lock proof
  inventory](docs/design/lifecycle.md#loader-lock-proof-inventory) maps the proofs.
- `[B-101]` `[SAFETY]` **All operations on consumer callables must run outside DMK-owned locks.** `DispatchCow.*` and
  `Lifecycle.Dispatcher*` prove dispatcher behavior. `HookLifecycleName.*` proves hook event names. `[B-30]` covers
  `HoldGate` and `PressGate`. This rule covers callable invocation, copy, and destruction.
- `[B-102]` `[CORRECTNESS]` **Public byte movement must use an explicit, wrap-safe overlap rule.** Each public
  guarded-copy surface must reject a caller span that intersects the target. It must return
  `ErrorCode::OverlappingRanges` before any byte moves. `MemoryTest.Overlap_*` and T-OVERLAP prove the contract.
