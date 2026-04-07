# AGENTS.md -- DetourModKit

## Project overview

DetourModKit is a C++23 static library for Windows game modding. It provides AOB scanning, function hooking (via SafetyHook), async logging, INI configuration, input polling, and memory utilities. The library is consumed by mod DLLs injected into game processes.

**Stack:** C++23, CMake 3.25+, Ninja, GoogleTest. Targets MinGW (GCC 12+) and MSVC 2022+.

**Key dependencies (git submodules):**

- `external/safetyhook` -- inline/mid-function hooking (links Zydis/Zycore)
- `external/DirectXMath` -- header-only math library
- `external/simpleini` -- INI file parser (header-only)

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
# Dedicated sanitizer preset (ASan + UBSan)
cmake --preset mingw-debug-asan
cmake --build --preset mingw-debug-asan --parallel

# Or manually
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
include/DetourModKit/    # Public headers -- one per module
  scanner.hpp            # AOB pattern scanning with SSE2
  hook_manager.hpp       # SafetyHook wrapper (inline, mid, and VMT hooks)
  async_logger.hpp       # Lock-free MPMC queue logger
  logger.hpp             # Synchronous singleton logger
  win_file_stream.hpp    # Win32 shared-access file stream (CreateFile backend)
  config.hpp             # INI configuration with callback setters
  input.hpp              # Input polling (keyboard/mouse/XInput)
  input_codes.hpp        # Unified InputCode type and named key tables
  memory.hpp             # Memory read/write, sharded region cache
  format.hpp             # std::format utilities (header-only)
  math.hpp               # Angle conversions (header-only)
  filesystem.hpp         # Module directory resolution (wide-string API)
  string.hpp             # String trim (header-only)
src/                     # Implementation files (one .cpp per module)
tests/                   # GoogleTest suites (one test_*.cpp per module)
  fixtures/              # Test support files (hook_target_lib DLL source)
external/                # Git submodules (safetyhook, DirectXMath, simpleini)
CMakeLists.txt           # Single CMakeLists -- static library target
CMakePresets.json        # Build presets (mingw-debug/release, mingw-debug-asan, msvc-debug/release)
```

## Code style

### C++ conventions

- **Standard:** C++23 with `-std=c++23`. No compiler extensions (`CMAKE_CXX_EXTENSIONS OFF`).
- **Naming:** `snake_case` for functions, variables, and file names. `PascalCase` for types and classes. `UPPER_SNAKE_CASE` for constants and macros. Prefix `s_` for file-scope statics. Private/protected class member variables use `m_` prefix (e.g. `m_hooks`, `m_logger`). Exception: POD-like internal structs without invariants (plain data holders, no public API) may use trailing `_` suffix instead (e.g. `capacity_`, `mask_`, `enqueue_pos_`). When in doubt, use `m_`.
- **Braces:** Allman style -- opening brace on its own line for functions and classes, same line for control flow within a function body using K&R-style indented blocks.
- **Indentation:** 4 spaces, no tabs.
- **Namespaces:** All public API lives in `namespace DetourModKit`. No `using namespace` in headers. Every closing namespace brace must have a trailing comment: `} // namespace DetourModKit`. Implementation-only statics in `.cpp` files must be in an anonymous namespace (not a named internal namespace) to guarantee internal linkage.
- **Include guards:** All headers use `#ifndef DETOURMODKIT_<MODULE>_HPP` / `#define` / `#endif` guards (not `#pragma once`). Guard names must be prefixed with `DETOURMODKIT_` to avoid collisions with consumer projects.
- **Includes:** Project headers use `"DetourModKit/header.hpp"`. System/external headers use `<angle brackets>`. Group: project headers, then external, then standard library.

### Comment conventions

Two comment styles are used, each for a distinct purpose:

**Doxygen doc-blocks (`/** */`):** Required on all public class/struct/function/method declarations in headers. Always include `@brief`. Add `@details` when behavior is non-trivial. Add `@param`, `@return`, `@note`, `@warning` as applicable. Indent continuation lines with `*` aligned to the first `*`.

```cpp
/**
 * @brief Finds and validates a cache entry in a shard.
 * @param shard The cache shard to search.
 * @param address Address to look up.
 * @param size Size of the query range.
 * @return Pointer to the matching entry, or nullptr if not found or expired.
 * @note Must be called with shard mutex held (shared or exclusive).
 */
```

**Single-line `///` exception:** Permitted only for trivial self-evident members where a full `/** */` block would be noise (e.g. simple getters, size queries). Must still be a complete sentence. Use sparingly.

```cpp
/// Returns the approximate number of items in the queue.
size_t size() const noexcept;
```

If the member needs `@param`, `@return`, `@note`, or multi-line description, use `/** */` instead.

**Inline comments (`//`):** Used inside function bodies to explain *why*, not *what*. Place on the line above the code they describe. Multi-line explanations use consecutive `//` lines.

```cpp
// Increment before push so flush cannot observe zero while a message
// is already in the queue but not yet counted.
pending_messages_.fetch_add(1, std::memory_order_acq_rel);
```

### Type safety and const-correctness

- **`const` by default:** Declare local variables `const` unless mutation is required. Use `const auto &` in range-for loops over containers.
- **`constexpr` where possible:** Prefer `constexpr` for functions evaluable at compile time. Use `inline constexpr` for namespace-scope constants in headers. Use `static constexpr` for class-scope constants.
- **`noexcept`:** Mark all destructors, shutdown methods, accessors, and functions that provably never throw. All `const` getters must be `noexcept`.
- **`[[nodiscard]]`:** Apply to all functions where ignoring the return value is a likely bug: factory functions, status queries, `bool` success/failure returns, `std::expected`/`std::optional` returns.
- **`explicit`:** All single-argument constructors must be `explicit`.
- **Casts:** Use C++ casts exclusively (`static_cast`, `reinterpret_cast`, `const_cast`). Never use C-style casts. Use `reinterpret_cast` only for pointer/address conversions at system boundaries. When intentionally discarding a `[[nodiscard]]` return value, cast to void explicitly: `(void)expr;`. This suppresses the compiler warning and signals deliberate intent.
- **Enums:** Always `enum class` (C++ Core Guidelines Enum.3). Enumerator names use `PascalCase` (e.g. `HookStatus::Active`, `OverflowPolicy::DropNewest`).
- **Initialization:** Use brace initialization `{value}` for member variable default values in class declarations (e.g. `std::atomic<bool> running_{false};`). Use parenthesized or `=` initialization only when brace initialization causes narrowing or ambiguity.
- **`nullptr`:** Always use `nullptr`, never `0` or `NULL`.
- **`std::string_view`:** Prefer `std::string_view` for non-owning string parameters. Use `std::string` only when ownership is required.

### Resource management and patterns

- **RAII everywhere:** `std::unique_ptr`, `std::shared_ptr`, `std::lock_guard`, `std::scoped_lock`. No naked `new`/`delete` in application code. The only permitted exception is leak-on-purpose singletons to avoid the static destruction order fiasco (must be documented with a comment explaining why).
- **Rule of Zero/Five:** Prefer Rule of Zero (let compiler generate special members). When custom resource management is needed, implement all five special members. Delete copy/move when the type is non-copyable/non-movable.
- **Atomic memory orderings:** Use the weakest correct ordering. `memory_order_relaxed` for counters and non-critical flags. `acquire`/`release` pairs for synchronization. Document why in comments only when the ordering is non-obvious.
- **Lock ordering:** When acquiring multiple locks, document the order in the class header and follow it strictly. Example from `logger.hpp`: `1. async_mutex_` then `2. *log_mutex_ptr_`.
- **Two-phase shutdown:** When destroying or shutting down objects that manage hooks or callbacks, disable/drain under a shared/reader lock first, then clear state under an exclusive/writer lock. This prevents deadlock with in-flight callbacks.
- **Deferred logging:** When logging inside a critical section, collect messages into a local vector and emit after releasing the lock. This prevents deadlocks when Logger acquires its own locks.
- **Error returns:** `std::expected` for memory operations, `std::optional` for scanner results. Reserve exceptions for construction failures and truly exceptional conditions.
- **Security hardening:** The build enables ASLR (`/DYNAMICBASE`), DEP (`/NXCOMPAT`), and Control Flow Guard (`/GUARD:CF`) on MSVC, and equivalent flags (`--dynamicbase`, `--nxcompat`) on MinGW. Do not remove these.

### Lambda conventions

- Use `[&]` capture for immediately-invoked lambdas that return into structured bindings (deferred logging pattern).
- Use explicit capture lists (`[this, &var1, &var2]`) for lambdas passed to threads or stored.
- Always specify the trailing return type (`-> ReturnType`) for non-trivial lambdas.

### Example -- good function style

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

### Example -- good hook callback pattern

```cpp
hook_manager.with_inline_hook("camera_update", [](InlineHook &hook) {
    // shared_lock held -- safe to read hook state
    // Do NOT call create_hook/remove_hook from here (deadlock)
    auto original = hook.get_original<CameraUpdateFn>();
    original(camera_ptr);
});
```

## Testing

- **Framework:** GoogleTest. Test entry point is `tests/main.cpp`.
- **One test file per module:** `tests/test_<module>.cpp` mirrors `src/<module>.cpp`.
- **Integration tests:** `tests/test_hook_integration.cpp` tests cross-module hooking against `tests/fixtures/hook_target_lib.cpp` (built as a DLL). The DLL exports `extern "C"` functions with volatile magic constants for stable AOB patterns. Includes hot-reload integration tests that exercise full hook/teardown/re-hook cycles, multi-type reload, enable/disable toggling, and repeated cycle stress.
- **Platform tests:** `tests/test_platform.cpp` tests internal loader-lock detection and module pinning utilities from `src/platform.hpp`.
- **Test fixture pattern:** Each suite uses a `::testing::Test` subclass with `SetUp()`/`TearDown()` for temp file cleanup. Temp file paths must include the process ID (`_getpid()`) and a counter to avoid collisions when CTest runs tests in parallel as separate processes.
- **VMT hook test lifetime:** GoogleTest destroys test-body locals *before* calling `TearDown()`. VMT tests must explicitly call `remove_all_vmt_hooks()` (or `remove_vmt_hook`) before target objects go out of scope. Do not rely on `TearDown()` for VMT cleanup when the hooked object is a test-body local.
- **Coverage gate:** 80% minimum line coverage enforced in CI. All PRs must pass.
- **Concurrency tests:** Use `std::atomic<bool> stop` flag pattern with multiple threads. See `AsyncMode_ConcurrentLogAndDisable` in `test_logger.cpp` for the reference pattern.
- **Build flag:** Tests are enabled with `DMK_BUILD_TESTS=ON` (on by default in debug presets).

After any code change, build and run the full test suite before committing:

```bash
PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-debug --parallel && \
PATH="/c/msys64/mingw64/bin:$PATH" ./build/mingw-debug/tests/DetourModKit_tests.exe
```

## Git workflow

- **Commit messages:** Conventional Commits format -- `type(scope): description`.
  - Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`.
  - Scopes: module names (`logger`, `scanner`, `hook_manager`, `input`, `memory`, `config`, `filesystem`). Omit scope for cross-cutting changes.
  - Examples: `feat(input): add XInput gamepad support`, `fix(memory): resolve data race in cache`, `perf(logger): lock-free async hot path`.
- **Branch:** `main` is the default and PR target branch.
- **PRs:** Squash merge preferred. Title follows the same conventional commit format.

## Architecture notes

### Thread safety model

| Module | Thread safety | Hot-path mechanism |
|--------|--------------|-------------------|
| Scanner | Stateless -- inherently safe | N/A (startup only) |
| HookManager | `shared_mutex` (readers) / `unique_lock` (writers); two-phase shutdown (disable under shared lock, clear under exclusive lock) | `shared_lock` for `with_inline_hook()` |
| Logger | `atomic<shared_ptr>` for lock-free async reads | Single atomic load on log level check |
| AsyncLogger | Lock-free MPMC queue (Vyukov-style); post-join drain on shutdown (at most one message per producer can be lost in the nanosecond race between drain and force-zero -- accepted trade-off to avoid atomic overhead on every enqueue); timestamp caching in write batches | Atomic sequence numbers per slot |
| InputPoller | Atomic `active_states_[]` array | `memory_order_relaxed` load per binding |
| InputManager | `mutex` for lifecycle, `atomic<InputPoller*>` for reads | Lock-free `is_binding_active()` |
| Memory cache | Sharded `SRWLOCK` + epoch-based shutdown | Shared reader locks per shard |
| Config | `mutex` for registration; deferred setter invocation outside lock (no reentrancy guard needed -- setters may call back into Config) | N/A (startup only) |

### Performance-critical paths

These are called at 60+ fps from game hook callbacks. Never add allocations, locks, or blocking I/O to them:

- `InputPoller::is_binding_active(index)` -- single atomic load
- `InputPoller::is_binding_active(name)` -- hash lookup + atomic load per binding (typically 1–3)
- `HookManager::with_inline_hook()` -- shared_lock read
- `Logger::log()` level check -- single atomic load
- `Logger::log()` async enqueue -- atomic shared_ptr load + lock-free queue push
- `Memory::is_readable()` -- sharded SRWLOCK reader + cache lookup
- `Memory::is_readable_nonblocking()` -- try_lock_shared + cache lookup (returns Unknown on contention)
- `Memory::read_ptr_unsafe()` -- SEH-protected raw dereference (MSVC), cache-accelerated with VirtualQuery fallback (MinGW)
- `Memory::read_ptr_unchecked()` -- inline pointer dereference with source and result low-address guards, no SEH (caller must guarantee structural pointer validity)
- `Logger::is_enabled()` -- single atomic load (gate expensive trace-only work)

## Boundaries

- **Do not modify** files under `external/` -- these are git submodules.
- **Do not add** `using namespace` directives in header files.
- **Do not add** heap allocations on hot paths (see list above).
- **Do not break** the lock ordering documented in class headers.
- **Do not weaken** atomic memory orderings without proving correctness.
- **Do not skip** running the test suite before committing.
- **Do not add** Windows API calls without `#ifdef _WIN32` guards in headers (implementation files are Windows-only, but headers should remain clean).
- **Do not commit** build artifacts, `.exe`, `.a`, `.lib`, `.obj`, or `.pdb` files.
- **Do not remove** or weaken existing tests. Add new tests for new code.
- **Do not use** C-style casts, `NULL`, or `0` as a pointer constant.
- **Do not use** plain `enum` -- always use `enum class`.
- **Do not use** `///` multi-line doc comments in headers -- use `/** @brief ... */` Doxygen blocks.
- **Do not use** named internal namespaces in `.cpp` files -- use anonymous namespaces for internal linkage.
- **Do not omit** `noexcept` on destructors, shutdown methods, and const accessors.
- **Do not omit** `[[nodiscard]]` on functions returning `std::expected`, `std::optional`, or success/failure `bool`.
- **Do not omit** `explicit` on single-argument constructors.
- **Do not add** uninitialized variables -- always initialize at declaration with brace syntax or assignment.
- **Do not use** `std::endl` -- use `'\n'`. `std::endl` forces a flush.
- **Do not use** `#pragma once` -- use `#ifndef`/`#define`/`#endif` include guards.
