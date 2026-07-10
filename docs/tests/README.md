# Test Coverage Guide

## Overview

This guide documents the testing strategy for DetourModKit, including how to build with coverage, run tests, interpret reports, and address common obstacles.

## Quick Commands

### Build with Coverage

```bash
# Using CMake presets (recommended)
PATH="/c/msys64/mingw64/bin:$PATH"
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
cmake --build build/mingw-debug --parallel
```

### Run Tests

`ctest` is the canonical runner. `gtest_discover_tests` registers each test case as its own ctest test, so ctest runs each case in a separate process. Prefer it -- some suites drive process-global state (the `ConfigTest` log-capture cases reconfigure the one `log()` sink) and can interleave when many cases share a single monolithic process. The standalone `DetourModKit_tests.exe` is for fast local iteration and `--gtest_filter` debugging, not the canonical green/red signal.

```bash
PATH="/c/msys64/mingw64/bin:$PATH"

# Canonical: per-case process isolation
ctest --preset mingw-debug --output-on-failure

# Fast local iteration (single process -- log-capture cases may interleave)
./build/mingw-debug/tests/DetourModKit_tests.exe
./build/mingw-debug/tests/DetourModKit_tests.exe --gtest_filter="LoggerTest.*"
```

### Generate Coverage Report

```bash
# Summary report
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --print-summary

# HTML report (output to docs/tests/coverage/, gitignored)
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --html-details docs/tests/coverage/index.html
```

## Coverage Analysis Workflow

### 1. Identify Low-Coverage Files

Run the full coverage report and look for files below the 80% gate:

```bash
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --print-summary
```

### 2. Check Specific File Coverage

```bash
python -m gcovr --root . --filter "src/hook.cpp" --txt
```

### 3. Analyze Uncovered Lines

Look at the "Missing" column for specific line numbers, then categorize by reason:

| Reason | Examples | Solution |
| ------ | -------- | -------- |
| **Invalid memory addresses** | Hook functions requiring valid function pointers | Use real function addresses with `DMK_TEST_NOINLINE` |
| **Error paths** | Exception handlers, error returns | Test with invalid inputs that trigger errors |
| **Windows API errors** | `GetModuleHandleExA`, `VirtualQuery` failures | Accept limitation or mock |
| **Template instantiation** | Template methods only instantiated with specific types | Add tests calling with those types |
| **Threading race conditions** | Lock-free CAS retry loops | Difficult to cover deterministically |
| **Cross-module paths** | DLL hooking, module scanning | Use integration tests with `hook_target_lib.dll` |

## Test Architecture

### Unit Tests

Each module has a corresponding test file that tests the module in isolation:

```text
src/<module>.cpp  →  tests/test_<module>.cpp
```

Unit tests use `DMK_TEST_NOINLINE` static functions as hook targets within the test binary itself. This validates the hooking mechanics without cross-module complexity.

### Integration Tests

`tests/test_hook_integration.cpp` tests the real-world DLL hooking workflow against `tests/fixtures/hook_target_lib.cpp` (built as a shared library):

1. `LoadLibrary` the fixture DLL
2. `GetProcAddress` to resolve exports
3. Hook exported functions via `hook::inline_at` (by address and AOB scan)
4. Verify behavioral changes (altered return values)
5. Drop the `Hook` handles and verify original behavior is restored

The fixture DLL exports `extern "C"` functions with volatile magic constants for stable AOB patterns across builds.

## Hook Testing

The hook surface is exercised by four test files:

- `tests/test_hook.cpp` -- the free-function / RAII surface (`hook::inline_at`, `hook::mid_at`, `hook::vmt_for`, `hook::install_all`): inline / mid / vmt installs, `Hook` lifecycle (enable / disable / release / destructor unhook), duplicate detection, prologue policy, `Hook::call`, `install_all` batch outcomes, and `install_all`'s `noexcept` out-of-memory degradation (via the `dmk_test::AllocFailScope` injector). This file replaces the former `tests/test_hook_manager.cpp`.
- `tests/test_mid_hook_context.cpp` -- `hook::MidContext` accessors (`gpr` / `stack_pointer` / `resume_stack_pointer` / `instruction_pointer` / `flags` / `xmm`).
- `tests/test_hook_integration.cpp` -- real-DLL cross-module hooking against the `hook_target_lib.dll` fixture.
- `tests/test_diagnostics.cpp` -- covers hook-lifecycle diagnostic events (install / enable / disable / teardown) emitted through the diagnostics surface.

### Using Real Function Addresses

```cpp
#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

// Test-local functions marked noinline to prevent the compiler
// from optimizing away the function body.
DMK_TEST_NOINLINE static int real_hook_target_add(int a, int b)
{
    return a + b;
}

DMK_TEST_NOINLINE static int real_hook_detour_add(int a, int b)
{
    return a + b + 100;
}

// Create a hook on a real, callable function. The returned Hook is a
// move-only RAII handle; its destructor unhooks.
auto result = DetourModKit::hook::inline_at(
    {.name = "TestHook",
     .target = DetourModKit::Address{reinterpret_cast<uintptr_t>(&real_hook_target_add)}},
    &real_hook_detour_add);
ASSERT_TRUE(result.has_value());
DetourModKit::hook::Hook hook = std::move(*result);
```

### Cross-Module Hooking (Integration Tests)

```cpp
// Load the fixture DLL and hook its exports
HMODULE dll = LoadLibraryA("hook_target_lib.dll");
auto fn = reinterpret_cast<ComputeDamageFn>(GetProcAddress(dll, "compute_damage"));

auto result = DetourModKit::hook::inline_at(
    {.name = "DamageHook",
     .target = DetourModKit::Address{reinterpret_cast<uintptr_t>(fn)}},
    &detour_compute_damage);
```

### AOB Scan + Hook Pipeline

```cpp
// Build a signature from the export's first 16 bytes
auto *bytes = reinterpret_cast<const unsigned char *>(fn);
std::string aob = build_aob_from_bytes(bytes, 16);

// Scan the DLL's memory region for the pattern
auto pattern_result = DetourModKit::scan::Pattern::compile(aob);
const auto found = DetourModKit::scan::scan(
    *pattern_result,
    DetourModKit::Region::module_named(module_name),
    1, DetourModKit::scan::Pages::Executable);

// Verify it found the exact export address, then hook it
EXPECT_EQ(found->raw(), reinterpret_cast<uintptr_t>(fn));
```

### What Can Be Tested

- **Pre-flight validation**: Invalid addresses, null pointers, duplicate names, unsafe prologues
- **Hook lifecycle**: Install, enable, disable, release, RAII destructor unhook, re-enable
- **Original invocation**: `Hook::original<Fn>()` (typed trampoline) and `Hook::call<Ret>(Args...)` (guarded by the per-hook mutex)
- **Batch install**: `hook::install_all` Mandatory / BestEffort severities and per-row `InstallOutcome`
- **noexcept-batch degradation**: `scan::resolve_batch` and `hook::install_all` degrade rather than terminate under injected out-of-memory (the thread-local `dmk_test::AllocFailScope` injector): a `resolve_batch` container-allocation failure is signalled by the outer `Result<...>` as `Error{OutOfMemory}`, and a per-request `bad_alloc` degrades only that slot, with no throw escaping the `noexcept` boundary
- **Concurrent access**: Multi-threaded hook creation stress tests
- **Cross-module hooking**: DLL exports hooked and verified via integration tests
- **AOB scan pipeline**: `scan::scan` / `scan::resolve` finds patterns in loaded DLLs, hooks the result via `hook::inline_at(InlineRequest{.target = scan::OwnedScanRequest{...}})`
- **Mid hooks**: Argument inspection and modification via `hook::MidContext` (the DMK accessors `gpr()` / `stack_pointer()` / `instruction_pointer()` / `xmm()`)

### Platform-Specific Tests

Mid hook tests that modify registers (`gpr(ctx, Gpr::Rcx)`, `gpr(ctx, Gpr::Rdx)`) are x86-64 specific. Guard with:

```cpp
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "Requires x86-64 calling convention";
#endif
```

### Fault-injection tests (`tests/fault/`, standalone runner)

A test that must observe a guarded primitive contain a real hardware fault needs a committed `PAGE_NOACCESS` page held until process teardown (never `MEM_RELEASE`d, so a recycled virtual address cannot flake the fault onto live memory). These fixtures do **not** join the `tests/test_*.cpp` glob: adding a file there forces a `CONFIGURE_DEPENDS` reconfigure that rebuilds the main C++23 test target. Instead:

- Reusable fixtures live in [`tests/fixtures/fault_injection.hpp`](../../tests/fixtures/fault_injection.hpp): `dmk_test::NoAccessPage` (a leaked-on-purpose committed no-access page) and `dmk_test::ProtectedPage` (a page pinned to a chosen protection, with `current_protection()` for asserting a fault path restored it).
- Fault TUs live in `tests/fault/test_*.cpp` and are built + run by [`scripts/run_fault_tests.sh`](../../scripts/run_fault_tests.sh): `bash scripts/run_fault_tests.sh`. The runner standalone-links a fault-test executable against the prebuilt archive (`libDetourModKitd.a` in a Debug tree, preferred by the script when present; `libDetourModKit.a` in a Release tree) -- rebuild just that target with `cmake --build build/mingw-debug --target DetourModKit` after any `src/` change. On a MinGW Debug tree the runner is also registered as the `FaultContainmentStandalone` ctest test (label `standalone-harness`), so `ctest` drives it in the normal flow. A new fault TU is picked up automatically -- no reconfigure.
- Inject the fault into the **foreign target** a guard actually arms (the target of a read / walk / in-place write), not a write's caller-owned source: the MinGW vectored guard confines its claim to the target range and lets a fault outside it reach the host, so a faulting source is a caller-contract violation that crashes rather than failing closed (MSVC's whole-copy `__try` catches it only incidentally). This is also why the escalating write slow-path copy-fault arm is not deterministic single-threaded -- once the slow path has made the target writable, only a concurrent reprotect can fault the copy.

`tests/fault/test_fault_containment.cpp` proves guarded read, pointer-chain walk, and `write_in_place` all fail closed against a no-access page, plus the deterministic escalating write slow-path protection restore.

### Lifecycle proofs (`tests/lifecycle/`, standalone runner)

A proof that needs a real loader transition (`LoadLibrary`/`FreeLibrary` reference-count behavior, `DLL_PROCESS_DETACH`) or a controlled static-teardown ordering cannot run inside the monolithic GoogleTest process, and one of them replaces the global allocation operators for its whole process. These live in `tests/lifecycle/` and are built + run by [`scripts/run_lifecycle_proofs.sh`](../../scripts/run_lifecycle_proofs.sh): `bash scripts/run_lifecycle_proofs.sh`. On a MinGW Debug tree the runner is also registered as the `LifecycleHostSafetyStandalone` ctest test (label `standalone-harness`). Each proof is a standalone artifact with the process exit code as the verdict (0 = pass, 1 = proof failure, 2 = setup failure):

- `bootstrap_probe_dll.cpp` -- a minimal mod-shaped DLL whose `DllMain` forwards attach/detach into `bootstrap()`/`bootstrap_detach()`, linked against the prebuilt archive (`libDetourModKitd.a` in a Debug tree, preferred by the script when present; rebuild that target first after any `src/` change).
- `test_bootstrap_module_ref.cpp` -- the loader host. Proves the bootstrap worker's counted module reference in both directions: the module stays mapped across a bare `FreeLibrary` ("mapped"), and a drained `request_shutdown()` releases the reference so a following `FreeLibrary` genuinely unloads it ("unload").
- `test_profiler_late_uaf.cpp` -- compiles `src/profiler.cpp` directly and replaces global `operator new`/`delete` with a size-targeted poisoning allocator, so a `ScopedProfile` record that outlives ordinary static teardown faults deterministically if the profiler singleton were ever destroyed early.

### Header-hygiene stripper self-test (`scripts/`, Python)

`scripts/check_header_hygiene.py`'s legacy-token and backend-confinement gates only inspect real code because the script blanks comments before scanning. A regression in that comment stripper -- for example mistracking a C++14 digit separator such as `1'000'000'000ULL` as a char literal, which would leave the scanner stuck in char state and pass later comments through unstripped -- could fail a PR on a legacy spelling that appears only in prose. [`scripts/test_check_header_hygiene.py`](../../scripts/test_check_header_hygiene.py) pins the stripper behavior and is registered as the `HeaderHygieneStripperSelfTest` ctest (label `script-lint`) whenever a Python interpreter is found, so `ctest` runs it alongside the C++ suite on both toolchains.

## Test Naming Conventions

```cpp
// Pattern: Subject_ConditionOrScenario
TEST_F(ClassName, Method_ExpectedBehavior)
TEST_F(HookTest, InlineAt_InvalidAddress)
TEST_F(HookIntegrationTest, AOBScan_InlineAt_EndToEnd)
```

## Adding New Tests

### For Error Paths

```cpp
TEST_F(SomeTest, Method_ErrorCondition)
{
    auto result = object->method(invalid_input);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ExpectedError::Value);
}
```

### For Template Methods

```cpp
// Template methods only get coverage when instantiated with specific types.
// Hook::original<Fn>() and Hook::call<Ret>(Args...) are templates, so a test
// that instantiates them with the target signature drives that coverage.
auto result = DetourModKit::hook::inline_at(
    {.name = "HookName",
     .target = DetourModKit::Address{reinterpret_cast<uintptr_t>(&target)}},
    &detour);
ASSERT_TRUE(result.has_value());
DetourModKit::hook::Hook hook = std::move(*result);

auto orig = hook.original<int (*)(int, int)>();
EXPECT_NE(orig, nullptr);
EXPECT_EQ(hook.call<int>(2, 3), /* original result */ 5);
```

### For Config Parsing

```cpp
// Comments are stripped per-token, not per-line
ini_file << "Keys=0x10, 0x20 ; comment at end\n";
```

## Common Issues and Fixes

### Duplicate Test Name

```text
error: 'TestName' is defined twice
```

**Fix**: Use distinct, descriptive names. Never append numeric suffixes.

### std::byte Array Initialization

```text
error: cannot initialize 'std::byte' with 'int'
```

**Fix**: Use explicit casts:

```cpp
std::byte data[] = {static_cast<std::byte>(0x48), static_cast<std::byte>(0x8B)};
```

### g++ Coverage Tool Bug

```text
Got negative hit value in: ...
```

**Fix**: Add `--gcov-ignore-parse-errors negative_hits.warn` to the gcovr command.

### GetProcAddress Cast Warning

```text
warning: cast between incompatible function types [-Wcast-function-type]
```

This is expected when casting `FARPROC` from `GetProcAddress` to a typed function pointer. The warning is harmless for integration tests.

## Coverage Targets

| Target | Difficulty | Notes |
| ------ | ---------- | ----- |
| 80% | Baseline | Error path testing, basic happy paths. CI gate. |
| 85% | Medium | Template instantiation, more error paths |
| 90% | Hard | Integration tests, edge cases in threading |
| 95%+ | Very Hard | Requires mocking Windows API or refactoring |

## Testing Internal and Hard-to-Reach Code

Most suites are ordinary black-box unit tests over a public header. A few need techniques worth documenting; the individual cases live in the named files.

- **Lock-free structures, verified through a test-only accessor.** `test_event_dispatcher.cpp` proves the copy-on-write dispatcher's snapshot invariants (the zero-subscriber fast path never loads the snapshot, an in-flight `emit()` iterates its own snapshot while a concurrent `subscribe()` publishes a new one via CAS, and subscribe/unsubscribe churn leaks no snapshot references) through `debug_snapshot_use_count()`, gated behind `#define DMK_EVENT_DISPATCHER_INTERNAL_TESTING 1`. That accessor is not public API and must not be defined in consumer code.
- **Non-installed internal headers, driven white-box.** `test_x86_decode.cpp` (`src/x86_decode.hpp`, the RIP-relative jump/call decoders the scan engine uses) and `test_input_intercept.cpp` (`src/internal/input_intercept.hpp`, the active-input layer) add `src/` to their include path and call `DetourModKit::detail::` directly. The decoders and the two interception state machines (the wheel-pulse stepper and the gamepad consume-until-release latch) are pure, so each branch is driven by a hand-crafted byte buffer or hand-supplied state rather than real input.
- **Poll-loop hot-path helpers, tested in isolation.** `test_input.cpp` covers the pieces the live poll loop would otherwise hide behind real process input state: the per-cycle `KeyStateCache` (one probe per distinct VK per cycle, re-armed on `reset()`, failing closed on an out-of-range VK) and the reshape-generation `BindingToken` (a stale token fails closed after a `consume` toggle).
- **Live OS hooks, exercised against a throwaway window and skipped when headless.** The window-procedure subclass and the `XInputGetState` inline hook in `test_input_intercept.cpp` stand up a top-level window the test process owns and load an `xinput` runtime; each case skips itself when the host has no window station or XInput runtime, so a headless CI runner stays green. The one path with no automated coverage is clearing a live controller's `wButtons` (it needs a physically connected pad), covered indirectly by the `GamepadSuppressTest` state-machine cases plus manual play-testing.

## Benchmark Harness

`DMK_BUILD_BENCHMARKS=ON` builds three standalone microbenchmark executables. Each is deliberately not a gtest binary, so it runs under any build configuration (release, release+PGO, ASan, etc.) without dragging in the gtest runtime, and each prints a tab-separated table on stdout:

- `DetourModKit_bench` (`bench_event_dispatcher.cpp`) -- EventDispatcher emit / subscribe throughput.
- `DetourModKit_bench_scanner` (`bench_scanner.cpp`) -- `scan::scan` / `scan::unchecked::find_pattern`, rare-byte anchor vs a naive first-byte anchor, prefilter and verify isolation rows, and serial cascade resolution vs `scan::resolve_batch`.
- `DetourModKit_bench_memory` (`bench_memory.cpp`) -- the cost of each way to read game memory from a hot path: validation predicate (warm hit / cold miss) vs direct SEH-guarded read vs the pointer-chain primitives, plus per-probe tail-latency and per-frame budget studies.

The option is independent of `DMK_BUILD_TESTS`, so the benches build alone:

```bash
PATH="/c/msys64/mingw64/bin:$PATH"
cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON
cmake --build build/mingw-release --parallel
./build/mingw-release/tests/DetourModKit_bench.exe > bench.tsv
```

`DetourModKit_bench` output has columns `scenario, subscribers, iterations, median_ns_per_op, total_ms`. Covered scenarios:

- `emit` / `emit_safe` at 0, 1, 8, 64 subscribers (the 0-subscriber rows measure the fast path).
- `subscribe_unsub_roundtrip` (single-thread RAII churn).
- `emit_concurrent_4_threads` (contention stress on the copy-on-write read path).
- `reentrancy_rejection` (cost of the guard's reject-during-handler path).

`DetourModKit_bench_memory` is documented in [../guides/memory/hot-path-memory.md](../guides/memory/hot-path-memory.md); read the `probe_gated_over_direct` TSV row for the gated-vs-direct multiplier on your machine.

## Installed Package Smoke Test

`tests/package_smoke` is a minimal consumer project for validating installed release packages. It uses `find_package(DetourModKit REQUIRED)`, links `DetourModKit::DetourModKit`, and touches `hook::is_target_hooked` so the static dependency archives are required by the final link.

```bash
cmake -S tests/package_smoke -B build/package-smoke-mingw -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DDetourModKit_DIR="$PWD/install_package/mingw/lib/cmake/DetourModKit" \
    -DCMAKE_CXX_COMPILER=g++
cmake --build build/package-smoke-mingw --parallel
ctest --test-dir build/package-smoke-mingw --output-on-failure
```

The release workflow runs this smoke project for both MinGW and MSVC after installing the package and before uploading release artifacts.

## Project Structure

Test files are named by the surface they verify and live under `tests/`; that directory is the authoritative list. Most modules have one `test_<module>.cpp`, while large modules split by API surface, fault-frame state, or integration boundary. The files worth calling out, because their role is not obvious from the name:

- **Deliberate same-module splits** -- `test_memory_chain.cpp` (pointer-chain and plausibility primitives) is split from `test_memory.cpp`, and `test_string.cpp` (the `string::trim` cases) shares `format.hpp` with `test_format.cpp`; scanner and RTTI have several focused suites for resolver tiers, string xrefs, parallel scanning, reverse dissection, and heal scheduling.
- **Internal white-box tests** -- `test_input_intercept.cpp` and `test_x86_decode.cpp` add `src/` to their include path to drive non-installed headers directly (`src/x86_decode.hpp` and `src/internal/input_intercept.hpp`).
- **Integration and lifecycle** -- `test_hook_integration.cpp` (cross-module hooking against the fixture DLL), `test_session.cpp` (`Session` / bootstrap / ordered `~Session` teardown), and `test_mid_hook_context.cpp` (`hook::MidContext` accessors).
- **Non-`test_*` support** -- `main.cpp` (GoogleTest entry point), `CMakeLists.txt` (test discovery, fixture DLL build, bench wiring), `fixtures/hook_target_lib.cpp` (the exported-function fixture DLL), `package_smoke/` (the installed-package consumer), and the `bench_*.cpp` microbenches (built under `DMK_BUILD_BENCHMARKS`).

The `docs/tests/` directory holds this guide plus the coverage tooling:

```text
docs/tests/
├── README.md          # This guide
├── parse_coverage.py  # Coverage JSON parser script
├── test_compile.cpp   # Minimal toolchain verification stub
└── coverage/          # Generated HTML reports (gitignored)
    └── index.html     # Entry point for HTML coverage report
```

## Helper Scripts

### parse_coverage.py

Parses `coverage.json` to display per-file coverage statistics:

```bash
# Generate coverage.json into the coverage subdirectory
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --json docs/tests/coverage/coverage.json

# Run the parser
python docs/tests/parse_coverage.py docs/tests/coverage/coverage.json
```

### test_compile.cpp

A minimal stub (`int main() { return 0; }`) for verifying the toolchain works:

```bash
g++ -o test_compile.exe docs/tests/test_compile.cpp
```

## Best Practices

1. **Start with error paths**: Test invalid inputs first (easy coverage gains).
2. **Use real addresses**: For hook tests, use `DMK_TEST_NOINLINE` functions or DLL exports.
3. **Use `ASSERT_*` for preconditions**: Stop the test immediately if setup fails.
4. **Use `EXPECT_*` for verifications**: Continue testing even if one check fails.
5. **Guard platform-specific tests**: Use `GTEST_SKIP()` for architecture-dependent logic.
6. **Clean rebuild for coverage**: After major changes, delete `.gcda` files or rebuild from scratch.
7. **Follow naming conventions**: `s_` for file-scope statics, `m_` for members, `snake_case` for functions.
