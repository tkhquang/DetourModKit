# AGENTS.md — DetourModKit

## Project overview

DetourModKit is a C++23 static library for Windows game modding. It provides AOB scanning, function hooking (via SafetyHook), async logging, INI configuration, input polling, and memory utilities. The library is consumed by mod DLLs injected into game processes.

**Stack:** C++23, CMake 3.25+, Ninja, GoogleTest. Targets MinGW (GCC 12+) and MSVC 2022+.

**Key dependencies (git submodules):**

- `external/safetyhook` — inline/mid-function hooking (links Zydis/Zycore)
- `external/DirectXMath` — header-only math library
- `external/simpleini` — INI file parser (header-only)

## Build and test commands

Always initialize submodules first:

```bash
git submodule update --init --recursive
```

### MinGW (MSYS2 shell)

```bash
# Configure
cmake --preset mingw-debug

# Build
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-debug --parallel

# Run all tests
PATH="/c/msys64/mingw64/bin:$PATH" ./build/mingw-debug/tests/DetourModKit_tests.exe

# Run a specific test suite
PATH="/c/msys64/mingw64/bin:$PATH" ./build/mingw-debug/tests/DetourModKit_tests.exe --gtest_filter="LoggerTest.*"

# Build release
cmake --preset mingw-release
cmake --build build/mingw-release --parallel
```

### MSVC (Developer Command Prompt)

```bash
cmake --preset msvc-debug
cmake --build build/msvc-debug --parallel
ctest --preset msvc-debug
```

### Sanitizers and coverage (MinGW only)

```bash
cmake --preset mingw-debug -DDMK_ENABLE_SANITIZERS=ON
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
```

### Makefile wrapper

```bash
make              # Build mingw-release
make test         # Build mingw-debug + run tests
make test_msvc    # Build msvc-debug + run tests
make install      # Install to build/install/
make clean        # Remove all build directories
```

## Project structure

```text
include/DetourModKit/    # Public headers — one per module
  scanner.hpp            # AOB pattern scanning with SSE2
  hook_manager.hpp       # SafetyHook wrapper (inline + mid hooks)
  async_logger.hpp       # Lock-free MPMC queue logger
  logger.hpp             # Synchronous singleton logger
  config.hpp             # INI configuration with callback setters
  input.hpp              # Input polling (keyboard/mouse/XInput)
  input_codes.hpp        # Unified InputCode type and named key tables
  memory.hpp             # Memory read/write, sharded region cache
  format.hpp             # std::format utilities (header-only)
  math.hpp               # Angle conversions (header-only)
  filesystem.hpp         # Module directory resolution
  string.hpp             # String trim (header-only)
src/                     # Implementation files (one .cpp per module)
tests/                   # GoogleTest suites (one test_*.cpp per module)
  fixtures/              # Test support files (hook_target_lib DLL source)
external/                # Git submodules (safetyhook, DirectXMath, simpleini)
CMakeLists.txt           # Single CMakeLists — static library target
CMakePresets.json        # Build presets (mingw-debug/release, msvc-debug/release)
```

## Code style

### C++ conventions

- **Standard:** C++23 with `-std=c++23`. No compiler extensions (`CMAKE_CXX_EXTENSIONS OFF`).
- **Naming:** `snake_case` for functions, variables, and file names. `PascalCase` for types and classes. `UPPER_SNAKE_CASE` for constants and macros. Prefix `m_` for class member variables. Prefix `s_` for file-scope statics.
- **Braces:** Allman style — opening brace on its own line for functions and classes, same line for control flow within a function body using K&R-style indented blocks.
- **Indentation:** 4 spaces, no tabs.
- **Namespaces:** All public API lives in `namespace DetourModKit`. No `using namespace` in headers.
- **Includes:** Project headers use `"DetourModKit/header.hpp"`. System/external headers use `<angle brackets>`. Group: project headers, then external, then standard library.

### Patterns used throughout

- **RAII everywhere:** `std::unique_ptr`, `std::shared_ptr`, `std::lock_guard`, `std::scoped_lock`. No naked `new`/`delete` in application code.
- **Atomic memory orderings:** Use the weakest correct ordering. `memory_order_relaxed` for counters and non-critical flags. `acquire`/`release` pairs for synchronization. Document why in comments only when the ordering is non-obvious.
- **Lock ordering:** When acquiring multiple locks, document the order in the class header and follow it strictly. Example from `logger.hpp`: `1. async_mutex_` → `2. *log_mutex_ptr_`.
- **Deferred logging:** When logging inside a critical section, collect messages into a local vector and emit after releasing the lock. This prevents deadlocks when Logger acquires its own locks.
- **Error returns:** `std::expected` for memory operations, `std::optional` for scanner results. Reserve exceptions for construction failures and truly exceptional conditions.

### Example — good function style

```cpp
[[nodiscard]] bool InputPoller::is_binding_active(size_t index) const noexcept
{
    if (index >= bindings_.size())
    {
        return false;
    }
    return active_states_[index].load(std::memory_order_relaxed) != 0;
}
```

### Example — good hook callback pattern

```cpp
hook_manager.with_inline_hook("camera_update", [](const safetyhook::InlineHook &hook) {
    // shared_lock held — safe to read hook state
    // Do NOT call create_hook/remove_hook from here (deadlock)
    auto original = hook.original<CameraUpdateFn>();
    original(camera_ptr);
});
```

## Testing

- **Framework:** GoogleTest. Test entry point is `tests/main.cpp`.
- **One test file per module:** `tests/test_<module>.cpp` mirrors `src/<module>.cpp`.
- **Integration tests:** `tests/test_hook_integration.cpp` tests cross-module hooking against `tests/fixtures/hook_target_lib.cpp` (built as a DLL). The DLL exports `extern "C"` functions with volatile magic constants for stable AOB patterns.
- **Test fixture pattern:** Each suite uses a `::testing::Test` subclass with `SetUp()`/`TearDown()` for temp file cleanup.
- **Coverage gate:** 80% minimum line coverage enforced in CI. All PRs must pass.
- **Concurrency tests:** Use `std::atomic<bool> stop` flag pattern with multiple threads. See `AsyncMode_ConcurrentLogAndDisable` in `test_logger.cpp` for the reference pattern.
- **Build flag:** Tests are enabled with `DMK_BUILD_TESTS=ON` (on by default in debug presets).

After any code change, build and run the full test suite before committing:

```bash
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-debug --parallel && \
PATH="/c/msys64/mingw64/bin:$PATH" ./build/mingw-debug/tests/DetourModKit_tests.exe
```

## Git workflow

- **Commit messages:** Conventional Commits format — `type(scope): description`.
  - Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`.
  - Scopes: module names (`logger`, `scanner`, `hook_manager`, `input`, `memory`, `config`, `filesystem`). Omit scope for cross-cutting changes.
  - Examples: `feat(input): add XInput gamepad support`, `fix(memory): resolve data race in cache`, `perf(logger): lock-free async hot path`.
- **Branch:** `main` is the default and PR target branch.
- **PRs:** Squash merge preferred. Title follows the same conventional commit format.

## Architecture notes

### Thread safety model

| Module | Thread safety | Hot-path mechanism |
|--------|--------------|-------------------|
| Scanner | Stateless — inherently safe | N/A (startup only) |
| HookManager | `shared_mutex` (readers) / `unique_lock` (writers) | `shared_lock` for `with_inline_hook()` |
| Logger | `atomic<shared_ptr>` for lock-free async reads | Single atomic load on log level check |
| AsyncLogger | Lock-free MPMC queue (Vyukov-style) | Atomic sequence numbers per slot |
| InputPoller | Atomic `active_states_[]` array | `memory_order_relaxed` load per binding |
| InputManager | `mutex` for lifecycle, `atomic<InputPoller*>` for reads | Lock-free `is_binding_active()` |
| Memory cache | Sharded `SRWLOCK` + epoch-based shutdown | Shared reader locks per shard |
| Config | `mutex` for registration, deferred setter invocation | N/A (startup only) |

### Performance-critical paths

These are called at 60+ fps from game hook callbacks. Never add allocations, locks, or blocking I/O to them:

- `InputPoller::is_binding_active(index)` — single atomic load
- `InputPoller::is_binding_active(name)` — hash lookup + atomic load per binding (typically 1–3)
- `HookManager::with_inline_hook()` — shared_lock read
- `Logger::log()` level check — single atomic load
- `Logger::log()` async enqueue — atomic shared_ptr load + lock-free queue push
- `Memory::is_memory_readable()` — sharded SRWLOCK reader + cache lookup

## Boundaries

- **Do not modify** files under `external/` — these are git submodules.
- **Do not add** `using namespace` directives in header files.
- **Do not add** heap allocations on hot paths (see list above).
- **Do not break** the lock ordering documented in class headers.
- **Do not weaken** atomic memory orderings without proving correctness.
- **Do not skip** running the test suite before committing.
- **Do not add** Windows API calls without `#ifdef _WIN32` guards in headers (implementation files are Windows-only, but headers should remain clean).
- **Do not commit** build artifacts, `.exe`, `.a`, `.lib`, `.obj`, or `.pdb` files.
- **Do not remove** or weaken existing tests. Add new tests for new code.
