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
| **Invalid memory addresses** | Hook functions requiring valid function pointers | Use real function addresses with `[[gnu::noinline]]` |
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

Unit tests use `[[gnu::noinline]]` static functions as hook targets within the test binary itself. This validates the hooking mechanics without cross-module complexity.

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
// Test-local functions marked noinline to prevent the compiler
// from optimizing away the function body
[[gnu::noinline]] static int real_hook_target_add(int a, int b)
{
    return a + b;
}

[[gnu::noinline]] static int real_hook_detour_add(int a, int b)
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

## Benchmark Harness

`tests/bench_event_dispatcher.cpp` is a standalone microbenchmark executable. It is deliberately not a gtest binary so it can run under any build configuration (release, release+PGO, ASAN, etc.) without dragging in the gtest runtime.

Build it by adding `-DDMK_BUILD_BENCHMARKS=ON` to the configure step:

```bash
PATH="/c/msys64/mingw64/bin:$PATH"
cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON
cmake --build build/mingw-release --parallel
./build/mingw-release/tests/DetourModKit_bench.exe > bench.tsv
```

The option is independent of `DMK_BUILD_TESTS`, so you can build the bench alone. Output is a tab-separated table on stdout with columns `scenario, subscribers, iterations, median_ns_per_op, total_ms`. Covered scenarios:

- `emit` / `emit_safe` at 0, 1, 8, 64 subscribers (the 0-subscriber rows measure the fast path).
- `subscribe_unsub_roundtrip` (single-thread RAII churn).
- `emit_concurrent_4_threads` (contention stress on the lock-free read path).
- `reentrancy_rejection` (cost of the guard's reject-during-handler path).

## Project Structure

```text
tests/
├── CMakeLists.txt              # Test discovery, fixture DLL build, bench wiring
├── main.cpp                    # GoogleTest entry point
├── bench_event_dispatcher.cpp  # Standalone microbench (DMK_BUILD_BENCHMARKS)
├── fixtures/
│   └── hook_target_lib.cpp     # Fixture DLL (exported functions for integration tests)
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
├── test_logger.cpp             # Logger tests
├── test_math.cpp               # Math utilities tests
├── test_memory.cpp             # Memory utilities tests
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
2. **Use real addresses**: For hook tests, use `[[gnu::noinline]]` functions or DLL exports.
3. **Use `ASSERT_*` for preconditions**: Stop the test immediately if setup fails.
4. **Use `EXPECT_*` for verifications**: Continue testing even if one check fails.
5. **Guard platform-specific tests**: Use `GTEST_SKIP()` for architecture-dependent logic.
6. **Clean rebuild for coverage**: After major changes, delete `.gcda` files or rebuild from scratch.
7. **Follow naming conventions**: `s_` for file-scope statics, `m_` for members, `snake_case` for functions.
