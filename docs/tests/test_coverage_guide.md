# Test Coverage Improvement Guide

## Overview
This guide documents lessons learned from improving code coverage for DetourModKit, including how to create tests, run coverage analysis, identify uncovered areas, and address common obstacles.

## Quick Commands

### Build with Coverage
```bash
# Clean rebuild with coverage flags
set "PATH=C:\msys64\mingw64\bin;%PATH%"
rm -rf build/mingw-debug
cmake -S . -B build/mingw-debug -G "Ninja" ^
    -DCMAKE_BUILD_TYPE=Debug -DDMK_BUILD_TESTS=ON ^
    -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ ^
    -DCMAKE_C_FLAGS="-fprofile-arcs -ftest-coverage" ^
    -DCMAKE_CXX_FLAGS="-fprofile-arcs -ftest-coverage"
cmake --build build/mingw-debug --parallel
```

### Run Tests
```bash
cd build/mingw-debug
ctest --output-on-failure
```

### Generate Coverage Report
```bash
# Full report
python -m gcovr --root . --filter "src/" --filter "include/DetourModKit/" ^
    --exclude "external/" --exclude "build/" --exclude "tests/" ^
    --gcov-ignore-parse-errors negative_hits.warn ^
    --print-summary

# Detailed HTML report (saved to docs/tests/)
python -m gcovr --root . --filter "src/" --filter "include/DetourModKit/" ^
    --exclude "external/" --exclude "build/" --exclude "tests/" ^
    --html-details docs/tests/coverage_details.html
```

## Coverage Analysis Workflow

### 1. Identify Low-Coverage Files
Run the full coverage report and look for files with <90% coverage:
```
TOTAL                                       1935     1585    81%
```

### 2. Check Specific File Coverage
```bash
python -m gcovr --root . --filter "src/hook_manager.cpp" --txt
```

### 3. Identify Uncovered Lines
Look at the "Missing" column for specific line numbers that aren't covered.

### 4. Analyze Why Lines Are Uncovered

#### Common Reasons for Uncovered Code:

| Reason | Examples | Solution |
|--------|----------|----------|
| **Invalid memory addresses** | Hook functions requiring valid function pointers | Use real function addresses (see below) |
| **Error paths** | Exception handlers, error returns | Test with invalid inputs that trigger errors |
| **Windows API errors** | GetModuleHandleExA, VirtualQuery failures | Mock or accept limitation |
| **Template instantiation** | Template methods only instantiated with specific types | Add tests using those types |
| **Threading race conditions** | Lock-free CAS retry loops | Extremely difficult to cover in unit tests |
| **SEGFAULT risks** | Invalid addresses causing crashes | Use valid addresses, not 0x12345678 |

## Hook Manager Testing

### The SEGFAULT Problem
Early tests used invalid addresses like `0x12345678` which cause SEGFAULT:
```cpp
// BAD - causes SEGFAULT
auto result = hook_manager_->create_inline_hook("Test", 0x12345678, detour, &tramp);
// GOOD - use real function address
auto result = hook_manager_->create_inline_hook("Test",
    reinterpret_cast<uintptr_t>(&real_hook_target_add), detour, &tramp);
```

### Using Real Function Addresses
```cpp
#include <windows.h>

// Use Windows API functions that are guaranteed to exist
void *api_func = reinterpret_cast<void *>(&GetTickCount);
void *detour_fn = reinterpret_cast<void *>(&real_hook_detour_add);

// Or use test-local functions
[[gnu::noinline]] static int real_hook_target_add(int a, int b) {
    return a + b;
}
```

### What Can Be Tested
- **Pre-flight checks**: Invalid addresses, null pointers, duplicate names
- **Hook existence**: Create hooks, check status, remove hooks
- **Template methods**: getOriginal<T>(), with_inline_hook<T>()

### What Cannot Be Tested (Without Integration)
- Actual hook installation success paths (requires valid memory)
- safetyhook library internals
- Runtime memory protection behaviors

## Test Naming Conventions

```cpp
// Pattern: Subject_ConditionOrScenario
TEST_F(ClassName, Method_ExpectedBehavior)
TEST_F(HookManagerTest, CreateInlineHook_InvalidAddress)
TEST_F(HookManagerTest, DISABLED_SafetyHookError_Path)  // Prefix disabled tests with DISABLED_
```

## Adding New Tests

### 1. For Error Paths
```cpp
TEST_F(SomeTest, Method_ErrorCondition)
{
    // Set up invalid input
    auto result = object->method(invalid_input);
    // Should return error
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ExpectedError::Value);
}
```

### 2. For Template Methods
```cpp
// Template methods only get coverage when instantiated
// Make sure to call them with the right types
auto hook_result = hook_manager_->with_inline_hook("Name",
    [](auto &orig) -> decltype(orig) { return orig(); });
```

### 3. For Config Parsing
```cpp
// Test INI file contents carefully
ini_file << "Keys=0x10, 0x20 ; comment at end\n";
// Note: Comment stripping happens per-token, not per-line
```

## Common Issues and Fixes

### Issue: Duplicate Test Name
```
error: 'TestName' is defined twice
```
**Fix**: Rename one of the tests:
```cpp
TEST_F(MemoryUtilsTest, CacheBehavior)      // Original
TEST_F(MemoryUtilsTest, CacheBehavior2)     // Rename duplicate
```

### Issue: std::byte Array Initialization
```
error: cannot initialize 'std::byte' with 'int'
```
**Fix**: Use explicit casts:
```cpp
std::byte data[] = {static_cast<std::byte>(0x48), static_cast<std::byte>(0x8B)};
```

### Issue: g++ Coverage Tool Bug
```
Got negative hit value in: ...
```
**Fix**: Add `--gcov-ignore-parse-errors negative_hits.warn` to gcovr command

### Issue: Test Causes SEGFAULT
**Fix**: Disable the test and document why:
```cpp
TEST_F(HookManagerTest, DISABLED_SafetyHookError_Path)
// Reason: safetyhook::create() with invalid address causes SEGFAULT
// Would require mocking safetyhook or valid memory address
```

## Coverage Targets

### Achievable Targets
| Target | Difficulty | Notes |
|--------|------------|-------|
| 80% | Easy | Basic error path testing |
| 85% | Medium | Template instantiation, more error paths |
| 90% | Hard | Requires integration tests or mocking |
| 95%+ | Very Hard | Requires refactoring for testability |

### When 90% Is Not Achievable
If coverage is stuck below 90% due to:
- **External library calls** (safetyhook): Mock or accept limitation
- **Windows API errors**: Mock or accept limitation
- **SEGFAULT risks**: Keep tests disabled, document reason

Document the limitation:
```cpp
// Coverage limitation: This code path requires valid hook installation
// which cannot be tested in unit tests without mocking safetyhook.
// Integration tests with real game modules would be needed.
```

## Project Structure

```
DetourModKit/
├── src/                    # Source code (libDetourModKit.a)
├── include/DetourModKit/    # Public headers
├── tests/                  # Unit tests (gtest-based)
│   ├── CMakeLists.txt       # Test discovery configuration
│   ├── main.cpp            # Test entry point
│   ├── test_hook_manager.cpp # Hook tests (~1385 lines)
│   ├── test_logger.cpp     # Logger tests (~1450 lines)
│   ├── test_config.cpp     # Config tests (~620 lines)
│   ├── test_memory_utils.cpp # Memory tests (~410 lines)
│   ├── test_aob_scanner.cpp # Scanner tests (~500 lines)
│   └── ...                 # Other test files
├── docs/tests/             # Test documentation and coverage reports
│   ├── test_coverage_guide.md  # This guide
│   ├── parse_coverage.py       # Coverage JSON parser script
│   ├── test_compile.cpp        # Minimal compile test stub
│   ├── coverage_details.html   # HTML coverage report
│   ├── coverage_details.*.html # Per-file coverage details
│   ├── coverage.xml            # XML coverage data (gcovr)
│   ├── coverage.json           # JSON coverage data (gcovr)
│   ├── coverage_details.css    # HTML styles
│   └── coverage_details.js     # HTML scripts
└── build/                  # Build output (gitignored)
```

## Coverage Report Interpretation

### Line Coverage
- **Percentage**: Lines executed / Total lines
- **Uncovered lines**: Listed in "Missing" column

### Function Coverage
- **Percentage**: Functions called / Total functions
- **Lower than line coverage**: Indicates some functions never called at all

### Branch Coverage
- **Percentage**: Branches taken / Total branches
- **Low branch coverage**: Indicates many if/else paths not exercised

## Best Practices

1. **Start with error paths**: Test invalid inputs first (easy coverage)
2. **Use real addresses**: For hook tests, use valid function addresses
3. **Disable, don't remove**: Keep SEGFAULTing tests disabled with documentation
4. **Test templates explicitly**: Ensure template methods are instantiated
5. **Watch for duplicate names**: gcov shows errors but tests may still compile
6. **Clean rebuild**: After major changes, clean and rebuild for accurate coverage

## Integration Testing Recommendations

For coverage >90%, consider:

1. **Game Module Integration Tests**
   - Load actual game DLLs
   - Hook real game functions
   - Test in actual game environment

2. **Mocking Framework**
   - Mock safetyhook library
   - Mock Windows API calls
   - Use GMock for expectations

3. **Code Refactoring**
   - Extract hard-to-test code into interfaces
   - Use dependency injection
   - Add test seams for mocking

## Helper Scripts and Tools

### parse_coverage.py
A lightweight Python script for parsing `coverage.json` to display per-file coverage statistics.

**Usage:**
```bash
# First generate coverage.json
python -m gcovr --root . --filter "src/" --filter "include/DetourModKit/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --json coverage.json

# Run the parser
python docs/tests/parse_coverage.py
```

**Output:**
```
src/hook_manager.cpp
  Lines: 150/200 (75.0%)
  Funcs: 10/12 (83.3%)
src/logger.cpp
  Lines: 300/350 (85.7%)
  Funcs: 25/25 (100.0%)

Total Lines: 450/550 (81.8%)
Total Funcs: 35/37 (94.6%)
```

### test_compile.cpp
A minimal stub file (`int main() { return 0; }`) used for basic compilation testing. Can be compiled standalone to verify the toolchain works:

```bash
g++ -o test_compile.exe docs/tests/test_compile.cpp
```

## Contact
For questions about testing strategy, refer to the project maintainers.
