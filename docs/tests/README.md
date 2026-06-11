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

```bash
PATH="/c/msys64/mingw64/bin:$PATH"
./build/mingw-debug/tests/DetourModKit_tests.exe

# Run a specific test suite
./build/mingw-debug/tests/DetourModKit_tests.exe --gtest_filter="LoggerTest.*"

# Run via CTest
ctest --preset mingw-debug --output-on-failure
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
python -m gcovr --root . --filter "src/hook_manager.cpp" --txt
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
3. Hook exported functions via `HookManager` (by address and AOB scan)
4. Verify behavioral changes (altered return values)
5. Remove hooks and verify original behavior is restored

The fixture DLL exports `extern "C"` functions with volatile magic constants for stable AOB patterns across builds.

## Hook Manager Testing

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

// Create a hook on a real, callable function
void *trampoline = nullptr;
auto result = hook_manager_->create_inline_hook(
    "TestHook",
    reinterpret_cast<uintptr_t>(&real_hook_target_add),
    reinterpret_cast<void *>(&real_hook_detour_add),
    &trampoline);
ASSERT_TRUE(result.has_value());
```

### Cross-Module Hooking (Integration Tests)

```cpp
// Load the fixture DLL and hook its exports
HMODULE dll = LoadLibraryA("hook_target_lib.dll");
auto fn = reinterpret_cast<ComputeDamageFn>(GetProcAddress(dll, "compute_damage"));

void *trampoline = nullptr;
auto result = m_hook_manager->create_inline_hook(
    "DamageHook",
    reinterpret_cast<uintptr_t>(fn),
    reinterpret_cast<void *>(&detour_compute_damage),
    &trampoline);
```

### AOB Scan + Hook Pipeline

```cpp
// Build a signature from the export's first 16 bytes
auto *bytes = reinterpret_cast<const unsigned char *>(fn);
std::string aob = build_aob_from_bytes(bytes, 16);

// Scan the DLL's memory region for the pattern
auto pattern = Scanner::parse_aob(aob);
const auto *found = Scanner::find_pattern(
    reinterpret_cast<const std::byte *>(module_base),
    module_size, pattern.value());

// Verify it found the exact export address, then hook it
EXPECT_EQ(reinterpret_cast<uintptr_t>(found), reinterpret_cast<uintptr_t>(fn));
```

### What Can Be Tested

- **Pre-flight validation**: Invalid addresses, null pointers, duplicate names, shutdown state
- **Hook lifecycle**: Create, enable, disable, remove, re-enable
- **Callback execution**: `with_inline_hook`, `with_mid_hook`, `try_with_*` variants
- **Concurrent access**: Multi-threaded hook creation stress tests
- **Cross-module hooking**: DLL exports hooked and verified via integration tests
- **AOB scan pipeline**: Scanner finds patterns in loaded DLLs, hooks the result
- **Mid hooks**: Argument inspection and modification via `safetyhook::Context`

### Platform-Specific Tests

Mid hook tests that modify registers (`ctx.rcx`, `ctx.rdx`) are x86-64 specific. Guard with:

```cpp
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "Requires x86-64 calling convention";
#endif
```

## Test Naming Conventions

```cpp
// Pattern: Subject_ConditionOrScenario
TEST_F(ClassName, Method_ExpectedBehavior)
TEST_F(HookManagerTest, CreateInlineHook_InvalidAddress)
TEST_F(HookIntegrationTest, AOBScan_HookManager_EndToEnd)
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
// Template methods only get coverage when instantiated with specific types
auto hook_result = hook_manager_->with_inline_hook(
    "HookName",
    [](InlineHook &hook) -> bool
    {
        auto orig = hook.get_original<int (*)(int, int)>();
        return orig != nullptr;
    });
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

## Event Dispatcher Tests

`tests/test_event_dispatcher.cpp` exercises the lock-free copy-on-write dispatcher. Beyond the basic subscribe/emit/RAII coverage, three tests target the optimized hot path specifically:

| Test | What it proves |
| ---- | -------------- |
| `EmptyFastPath_SkipsLock` | With zero subscribers, `emit()` / `emit_safe()` return via the atomic handler-count check without touching the snapshot `shared_ptr`. Asserted by `debug_snapshot_use_count()` remaining at 1 (dispatcher-only) after 1000 emits. |
| `SnapshotStability_DuringEmit` | An in-flight emit holds its own snapshot reference. A concurrent `subscribe()` publishes a new snapshot via CAS; the emitter's iteration continues over the old snapshot and the newly subscribed handler is not invoked. Next emit sees both. Exercises the COW publish invariant. |
| `SnapshotReclamation_NoLeak` | After 10,000 subscribe/unsubscribe churn iterations with interleaved emits, `debug_snapshot_use_count()` returns to 1, proving no leaked `shared_ptr` references to stale snapshots. |

These tests enable the test-only `debug_snapshot_use_count()` accessor via `#define DMK_EVENT_DISPATCHER_INTERNAL_TESTING 1` at the top of the translation unit. The macro is not part of the public API and must not be defined in consumer code.

## x86 Control-Flow Decoder Tests

`tests/test_x86_decode.cpp` exercises the internal header `src/x86_decode.hpp`, which is consumed by `Scanner` for RIP-relative jump/call resolution. The decoders are small and pure, so each branch is driven by crafting a byte buffer and calling the decoder directly:

| Test | What it proves |
| ---- | -------------- |
| `DecodeE9Rel32_WrongOpcodeRejected` / `DecodeEbRel8_WrongOpcodeRejected` | Opcode-mismatch short-circuit returns `std::nullopt` without reading the displacement. |
| `DecodeE9Rel32_ValidForwardDisplacement` / `DecodeE9Rel32_ValidBackwardDisplacement` | `base + 5 + disp32` is computed for both positive and negative displacements. |
| `DecodeEbRel8_NegativeDisplacementSignExtended` | `0xFE` on the displacement byte decodes as `-2`, proving the `std::int8_t` cast sign-extends correctly. |
| `DecodeFf25Indirect_WrongFirstByteRejected` / `DecodeFf25Indirect_WrongSecondByteRejected` | Both halves of the compound `FF 25` opcode predicate are rejected independently. |
| `DecodeFf25Indirect_UnreadableSlotRejected` | A displacement that places the indirect slot outside the user address range returns `std::nullopt`. |
| `DecodeFf25Indirect_SlotProducesDestination` | Happy path: the slot pointer is materialised and returned verbatim. An aligned struct lays out the instruction and slot so the RIP-relative displacement is independent of padding. |

The decoder header lives under `src/` (not the public include tree), so the test file adds `src/` to its include path and uses `DetourModKit::detail::` directly.

## Input Interception Tests

`tests/test_input_intercept.cpp` exercises the internal header `src/input_intercept.hpp`, the opt-in active-input layer that backs mouse-wheel capture and gamepad passthrough suppression for `InputPoller`. It uses the same `src/`-on-include-path pattern as the decoder tests. The unit tests target the two pure state machines that carry no Win32 dependency, so each is driven by direct calls with hand-supplied state:

| Test | What it proves |
| ---- | -------------- |
| `WheelPulseTest.IdleProducesNoPulse` | A wheel with no pending notches emits an all-zero mask every cycle. |
| `WheelPulseTest.SingleNotchPulsesThenGoesLow` | One queued notch reads pressed for exactly one cycle, then is forced low so the edge detector re-arms. |
| `WheelPulseTest.TwoNotchesProduceTwoSeparatedPulses` | Two queued notches fire as two distinct Press edges separated by a forced low cycle, never one fused press. |
| `WheelPulseTest.DirectionsAreIndependent` | Pending notches in different directions pulse on the same cycle without interfering. |
| `GamepadSuppressTest.BarePressIsNotSuppressed` | A trigger physically down with no active chord (`owned_now == 0`) is left untouched so the game still sees it. |
| `GamepadSuppressTest.ActiveChordSuppressesTrigger` | A trigger claimed by an active chord is added to the clear mask. |
| `GamepadSuppressTest.ModifierReleasedBeforeTriggerKeepsSuppressing` | Releasing the modifier a frame before the trigger does not leak a bare trigger: suppression latches to the trigger button's own lifetime. |
| `GamepadSuppressTest.TriggerReleaseSuppressesThroughGraceThenStops` | After the trigger is released the latch keeps masking through the grace window, then disarms and returns the button to the game. |
| `GamepadSuppressTest.RepressDuringGraceReHolds` | A re-press during the release grace re-holds the suppression and restarts the grace on the next release. |
| `InterceptControlTest.AccessorsAndSettersWithNothingInstalled` | With no hook installed (the unit-test process), the accessors report "off" and the setters / `uninstall()` are safe no-ops over atomics. |

The window-procedure subclass and the `XInputGetState` inline hook are exercised by integration tests that stand up a throwaway top-level window owned by the test process (and load an `xinput` runtime). Each skips itself when the host has no window station or no XInput runtime, so a headless runner stays green:

| Test | What it proves |
| ---- | -------------- |
| `InterceptWndProcTest.InstallCapturesWheelNotchesPerDirection` | After the subclass installs, `WM_MOUSEWHEEL` / `WM_MOUSEHWHEEL` notches accumulate into the correct per-direction counters (Up/Down vertical, Left/Right horizontal) by wheel-delta sign. |
| `InterceptWndProcTest.ConsumeSwallowsOwnedWheelMessages` | With consume off the notch is latched and forwarded to the game's predecessor procedure; with consume on it is still latched but swallowed so the game never sees it. |
| `InterceptWndProcTest.WmNcDestroySelfHealsAndAllowsResubclass` | Destroying the subclassed window marks the subclass uninstalled via `WM_NCDESTROY`, so a recreated window (the fullscreen-toggle case) can be re-subclassed. |
| `InterceptWndProcTest.UninstallRestoresPredecessorAtTopOfChain` | When the detour is still the top of the window-procedure chain, `uninstall()` restores the exact saved predecessor. |
| `InterceptXInputTest.InstallHooksExportAndTrampolineRoundTrips` | Installing hooks the real `XInputGetState` export, publishes a non-null trampoline, is idempotent, routes a call through the detour into the trampoline, and restores the prologue on `uninstall()`. |
| `InterceptDisarmTest.PollerDisarmsWheelConsumeAfterClearBindings` | A standalone `InputPoller` with a consume wheel binding arms the swallow flag; `clear_bindings(false)` (the loader-lock-safe hot-reload reset) lets the poll loop disarm it on a later cycle so the game regains its wheel. |

The one path still validated manually is the gamepad button masking itself: clearing `wButtons` from a live controller's state requires a physically connected controller, so `apply_suppress` is covered indirectly by the `GamepadSuppressTest` state-machine suite plus manual play-testing.

## Benchmark Harness

`DMK_BUILD_BENCHMARKS=ON` builds three standalone microbenchmark executables. Each is deliberately not a gtest binary, so it runs under any build configuration (release, release+PGO, ASan, etc.) without dragging in the gtest runtime, and each prints a tab-separated table on stdout:

- `DetourModKit_bench` (`bench_event_dispatcher.cpp`) -- EventDispatcher emit / subscribe throughput.
- `DetourModKit_bench_scanner` (`bench_scanner.cpp`) -- `Scanner::find_pattern`, rare-byte anchor vs a naive first-byte anchor.
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
- `emit_concurrent_4_threads` (contention stress on the lock-free read path).
- `reentrancy_rejection` (cost of the guard's reject-during-handler path).

`DetourModKit_bench_memory` is documented in [../misc/hot-path-memory.md](../misc/hot-path-memory.md); read the `probe_gated_over_direct` TSV row for the gated-vs-direct multiplier on your machine.

## Installed Package Smoke Test

`tests/package_smoke` is a minimal consumer project for validating installed release packages. It uses `find_package(DetourModKit REQUIRED)`, links `DetourModKit::DetourModKit`, and touches `HookManager` so the static dependency archives are required by the final link.

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

```text
tests/
├── CMakeLists.txt              # Test discovery, fixture DLL build, bench wiring
├── main.cpp                    # GoogleTest entry point
├── bench_event_dispatcher.cpp  # EventDispatcher emit/subscribe microbench (DMK_BUILD_BENCHMARKS)
├── bench_memory.cpp            # Hot-path memory bench: validation predicate vs SEH-guarded read / chain primitives (DMK_BUILD_BENCHMARKS)
├── bench_scanner.cpp           # Scanner::find_pattern rare-byte-anchor bench (DMK_BUILD_BENCHMARKS)
├── fixtures/
│   └── hook_target_lib.cpp     # Fixture DLL (exported functions for integration tests)
├── package_smoke/
│   ├── CMakeLists.txt          # Minimal installed-package consumer project
│   └── main.cpp                # Smoke executable that forces a DetourModKit link
├── test_async_logger.cpp       # Async logger tests
├── test_bootstrap.cpp          # DllMain lifecycle and instance-gate tests
├── test_config.cpp             # Configuration tests
├── test_config_watcher.cpp     # INI hot-reload watcher tests
├── test_event_dispatcher.cpp   # Event dispatcher tests (incl. fast-path and snapshot stability)
├── test_filesystem.cpp         # Filesystem tests
├── test_format.cpp             # Format utilities tests
├── test_hook_integration.cpp   # Cross-module hook integration tests
├── test_hook_manager.cpp       # Hook manager unit tests
├── test_input.cpp              # Input system and input code tests
├── test_input_intercept.cpp    # Active-input layer state machines (internal)
├── test_logger.cpp             # Logger tests
├── test_math.cpp               # Math utilities tests
├── test_memory.cpp             # Memory utilities tests (cache, read/write, SEH reads, module range)
├── test_memory_chain.cpp       # Pointer-chain / plausibility primitives (seh_resolve_chain, seh_read_chain)
├── test_platform.cpp           # Platform detection and version macro tests
├── test_profiler.cpp           # Profiler tests
├── test_scanner.cpp            # AOB scanner tests
├── test_shutdown.cpp           # DMK_Shutdown orchestration tests
├── test_string.cpp             # String utilities tests
├── test_win_file_stream.cpp    # Win32 file stream tests
├── test_worker.cpp             # StoppableWorker jthread RAII tests
└── test_x86_decode.cpp         # x86 control-flow instruction decoders (internal)

docs/tests/
├── README.md                   # This guide
├── parse_coverage.py           # Coverage JSON parser script
├── test_compile.cpp            # Minimal toolchain verification stub
└── coverage/                   # Generated HTML reports (gitignored)
    └── index.html              # Entry point for HTML coverage report
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
