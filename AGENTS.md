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

### Installed package smoke test

After installing either release preset, verify the exported CMake package with the checked-in consumer smoke project:

```bash
cmake -S tests/package_smoke -B build/package-smoke-mingw -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DDetourModKit_DIR="$PWD/build/install/lib/cmake/DetourModKit" \
    -DCMAKE_CXX_COMPILER=g++
cmake --build build/package-smoke-mingw --parallel
ctest --test-dir build/package-smoke-mingw --output-on-failure
```

### Profiling

```bash
cmake --preset mingw-debug -DDMK_ENABLE_PROFILING=ON
cmake --build build/mingw-debug --parallel
```

### Microbenchmarks

```bash
# Configure release build with bench targets
PATH="/c/msys64/mingw64/bin:$PATH" cmake -S . -B build/mingw-release \
    -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DDMK_BUILD_BENCHMARKS=ON -DDMK_BUILD_TESTS=OFF

# Available bench executables (standalone, no gtest runtime):
#   DetourModKit_bench           -- EventDispatcher emit / subscribe throughput
#   DetourModKit_bench_scanner   -- Scanner::find_pattern, rare-byte anchor vs naive
#   DetourModKit_bench_memory    -- validation predicate vs direct SEH-guarded read / chain primitives (hot-path cost)

PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-release \
    --target DetourModKit_bench_scanner --parallel
./build/mingw-release/tests/DetourModKit_bench_scanner.exe
```

Latest scanner bench numbers and methodology live in [docs/analysis/scanner_bench_v3.x/README.md](docs/analysis/scanner_bench_v3.x/README.md). Memory validation-vs-direct-read numbers live in [docs/analysis/memory_bench_v3.x/README.md](docs/analysis/memory_bench_v3.x/README.md).

### Sanitizers (MSVC) and coverage (MinGW)

```bash
# AddressSanitizer -- MSVC only. Run from a Developer Command Prompt / VS DevShell.
cmake --preset msvc-debug-asan
cmake --build --preset msvc-debug-asan --parallel
ctest --preset msvc-debug-asan

# Coverage (gcov instrumentation) -- MinGW GCC.
cmake --preset mingw-debug-coverage
cmake --build --preset mingw-debug-coverage --parallel
ctest --preset mingw-debug-coverage

# Or enable either flag on its matching debug preset manually
cmake --preset msvc-debug -DDMK_ENABLE_SANITIZERS=ON
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
```

AddressSanitizer is the only sanitizer that links on Windows: GCC and Clang on mingw-w64 ship no ASan/UBSan runtime for the Windows target, so the sanitizer build links only under MSVC, and ASan is the only sanitizer there (no UBSan or LSan). MSVC ASan needs `clang_rt.asan_dynamic-x86_64.dll` on `PATH` at run time; a Developer Command Prompt provides it. Coverage is separate and works on MinGW via gcov. A non-blocking CI probe in `.github/workflows/quality.yml` builds and runs the MSVC ASan preset (alongside an advisory clang-format check) so regressions in that wiring surface without gating PRs.

The AOB scanner and the SEH-guarded probe read deliberately read arbitrary mapped process memory, which ASan reports as false-positive overflows when it scans this process's own poisoned shadow. The AOB prefilter routes through a self-provided `dmk_memchr` in all builds, which is immune to libc interceptors by construction; the remaining ASan-only treatment is the `no_sanitize_address` attribute and the `__movsb` copy path under `#if defined(__SANITIZE_ADDRESS__)`. See [docs/misc/asan-memory-scanner.md](docs/misc/asan-memory-scanner.md) for the mechanism and the pattern for any new foreign-memory primitive.

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
  scanner.hpp            # AOB pattern scanning (whole-process executable/readable regions + module-scoped and host-EXE cascade) with AVX2/SSE2; in-code constant extraction (read_code_constant, Zydis-backed); string-reference xref resolver (find_string_xref: locate an immutable literal, then its unique RIP-relative reference -- a fast lea/mov shape scan by default, or that scan plus an opt-in Zydis broad sweep for cmp/push/no-REX shapes)
  hook_manager.hpp       # SafetyHook wrapper (inline, mid, and VMT hooks)
  async_logger.hpp       # Lock-free MPMC queue logger
  logger.hpp             # Synchronous singleton logger
  win_file_stream.hpp    # Win32 shared-access file stream (CreateFile backend)
  config.hpp             # INI configuration with callback setters
  config_watcher.hpp     # Filesystem watcher (ReadDirectoryChangesW) for INI hot-reload
  input.hpp              # Input polling (keyboard/mouse/XInput) + opt-in mouse-wheel capture and gamepad passthrough suppression
  input_codes.hpp        # Unified InputCode type and named key tables (incl. WheelUp/Down/Left/Right)
  srw_shared_mutex.hpp   # Opaque Windows SRWLOCK SharedLockable wrapper; use for reader/writer locks that need native Windows semantics without exposing Windows headers
  memory.hpp             # Memory read/write, sharded region cache, seh_read<T>, seh_resolve_chain/seh_read_chain<T>, plausible_userspace_ptr, PE module range
  rtti.hpp               # MSVC RTTI walker (type_name_of, vtable_is_type, find_in_pointer_table) + reverse name-to-vtable (vtable_for_type, vtables_for_type, TypeIdentity)
  rtti_dissect.hpp       # Reverse RTTI dissection + self-healing offsets (identify_pointee_type, reverse_scan_block, heal_landmark/heal_offset, solve_fingerprint) + drift-telemetry report (heal_report, DriftEntry)
  drift_manifest.hpp     # Durable serialize/parse of the self-heal drift report (DriftEntry) so drift can be saved and diffed across game versions
  anchors.hpp            # Declarative self-healing anchor registry over the vtable / cascade / code-constant / string-xref / manual backends, plus two-signal quorum corroboration and optional post-resolve validators (Anchors::resolve, resolve_all)
  event_dispatcher.hpp   # Typed pub/sub with RAII subscriptions (header-only)
  profiler.hpp           # Opt-in scoped timing (zero-cost when disabled)
  version.hpp            # Version macros (generated by CMake from version.hpp.in)
  format.hpp             # std::format utilities + string trim (header-only)
  math.hpp               # Angle conversions (header-only)
  filesystem.hpp         # Module directory resolution (wide-string and UTF-8 APIs)
  bootstrap.hpp          # DllMain lifecycle (worker thread, mutex, process gate)
  worker.hpp             # StoppableWorker RAII std::jthread wrapper
  diagnostics.hpp        # Consumer-queryable counters for intentional loader-lock leak/detach events, per subsystem
src/                     # Implementation files. One .cpp per module, except a
                         # cohesive module may split into sibling TUs sharing one
                         # public header: scanner.cpp (scan engine) +
                         # scanner_cascade.cpp (cascade resolver) +
                         # code_constant.cpp (Zydis decode) +
                         # string_xref.cpp (string-reference resolver; confines its
                         # Zydis broad sweep like code_constant.cpp) via
                         # scanner_internal.hpp;
                         # rtti.cpp + rtti_dissect.cpp via rtti_internal.hpp
tests/                   # GoogleTest suites (one test_*.cpp per module)
  fixtures/              # Test support files (hook_target_lib DLL source)
  package_smoke/         # Minimal installed-package consumer used by release CI
external/                # Git submodules (safetyhook, DirectXMath, simpleini)
CMakeLists.txt           # Single CMakeLists -- static library target
CMakePresets.json        # Build presets (mingw-debug/release/coverage, msvc-debug/release/asan)
scripts/                 # Repo tooling (check_comment_style.py: advisory comment-marker lint)
```

## Code style

### C++ conventions

- **Standard:** C++23 with `-std=c++23`. No compiler extensions (`CMAKE_CXX_EXTENSIONS OFF`).
- **Naming:** `snake_case` for functions, variables, and file names. `PascalCase` for types and classes. `UPPER_SNAKE_CASE` for constants and macros. Prefix `s_` for file-scope statics. Private/protected member variables of named classes use the `m_` prefix (e.g. `m_hooks`, `m_logger`, `m_bindings`), uniformly across every module. POD-like plain-data structs without invariants (no public API, no maintained invariant; e.g. `InputBinding`, the Vyukov queue `Slot`, `ProfileSample`) use plain field names with no prefix or suffix (`name`, `sequence`, `start_ticks`). A trailing `_` suffix on member variables is not used. Constants stay `UPPER_SNAKE_CASE`; the `k`-prefixed Google dialect (`kBufferBytes`) is not used. Win32-mirror identifiers that match an OS struct field or parameter name (`wButtons`, `dwPacketNumber`, `hMod`) keep the OS spelling and are exempt from `snake_case`.
- **Descriptive variable names:** Avoid one-character names in general; name the value so a reader does not have to track what it holds (`anchor` not `a`, `candidate` not `c`, `result` not `r`, `operand` not `op`, `match_count` not `n` when it aids clarity). Single- and short-letter names are reserved for the cases where they are the idiom and read unambiguously:
  - loop counters `i`, `j`, `k` and a running count `n` (the house loop idiom is `for (size_t i = 0; ...)`; keep it, do not rename counters);
  - a small fixed set being compared or paired (`a`, `b`, `c` for two or three like items, e.g. two `SyntheticVtable`s under test);
  - conventional math or geometry quantities (`x`, `y`, `z`, `lo`, `hi`, `dx`, `coords`);
  - a short abbreviation a file already uses consistently for a local fixture or concept (e.g. a `SyntheticVtable v` in a test built around a single one).

  Follow the file you are in: match its established short-name convention rather than introducing a lone outlier, and do not leave a cryptic domain `a`/`r`/`c` in new code whose neighbours are spelled out.
- **Braces:** Allman style -- opening brace on its own line for functions and classes, same line for control flow within a function body using K&R-style indented blocks.
- **Indentation:** 4 spaces, no tabs.
- **Namespaces:** All public API lives in `namespace DetourModKit`. No `using namespace` in headers. Every closing namespace brace must have a trailing comment: `} // namespace DetourModKit`. Implementation-only statics in `.cpp` files must be in an anonymous namespace (not a named internal namespace) to guarantee internal linkage.
- **Include guards:** All headers use `#ifndef DETOURMODKIT_<MODULE>_HPP` / `#define` / `#endif` guards (not `#pragma once`). Guard names must be prefixed with `DETOURMODKIT_` to avoid collisions with consumer projects.
- **Includes:** Project headers use `"DetourModKit/header.hpp"`. System/external headers use `<angle brackets>`. Group: project headers, then external, then standard library.

### Comment conventions

Three comment markers are used, each for a distinct purpose. The choice is by *what* is being commented, not by length: `/** */` and `///` document a declaration; `//` explains implementation. Put another way, document the interface and comment the implementation -- a documented or public declaration's contract uses `///` or `/** */` (Doxygen extracts it), while a private or implementation-only member carries at most a plain `//` rationale (ownership, alignment, immutability) and is not given a `///`. A trailing `///<` is never used.

**Doxygen doc-blocks (`/** */`):** The doc-comment form for declarations. Required on all public class/struct/function/method/enum declarations in headers, and used for any documented internal helper, constant, or anonymous-namespace function in `.cpp` files. Always include `@brief`. Add `@details` when behavior is non-trivial. Add `@param`, `@return`, `@note`, `@warning` as applicable. Use a `/** */` block whenever the documentation spans more than one line or carries any structural Doxygen tag. Indent continuation lines with `*` aligned to the first `*`.

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

**Single-line `///` exception:** A shorthand for a one-line `/** @brief */`, permitted only for a trivial self-evident declaration where a full block would be noise (e.g. simple getters, size queries, a single named constant). It must be exactly one line -- two consecutive `///` lines are a multi-line doc and belong in a `/** */` block -- and a complete sentence. It may carry inline Doxygen markup that is a link rather than structure (`@ref`, `@c`, `@p`, `@a`), but must not carry a structural/block tag (`@brief`, `@param`, `@tparam`, `@return`, `@retval`, `@note`, `@warning`, `@details`, `@throws`, `@pre`, `@post`, `@name`, `@{`, `@}`); the moment one is needed, switch to a `/** */` block. Place it on the line above the declaration.

```cpp
/// Returns the approximate number of items in the queue.
size_t size() const noexcept;
```

**No trailing `///<`:** Member documentation goes on the line(s) above the member as a `///` line or a `/** */` block, never as a trailing `///<` on the same line. Trailing docs push lines past the 120-column limit and read inconsistently next to above-the-member docs.

**Inline comments (`//`):** Used inside function bodies and implementation logic to explain *why*, not *what*. This is the only non-documentation marker: a `//` never documents a declaration (use `///` or `/** */` for that). Place on the line above the code it describes. Multi-line explanations use consecutive `//` lines.

```cpp
// Increment before push so flush cannot observe zero while a message
// is already in the queue but not yet counted.
m_pending_messages.fetch_add(1, std::memory_order_acq_rel);
```

### Formatting and tooling

C++ formatting is codified in the root `.clang-format` (LLVM base, Allman braces for functions/classes, 4-space indent, east-side pointers, includes never reordered). Run clang-format over the changed `*.cpp`/`*.hpp` before committing. CI runs an advisory check in `.github/workflows/quality.yml` (clang-format 20, the version pinned there) over the tracked project sources; submodules under `external/` are never formatted. The hard column limit is 120 (`ColumnLimit: 120`): code and comments must fit within it, and the formatter reflows plain `//` comment text that runs past it (`ReflowComments: Always`), while `/** */` Doxygen doc-blocks are exempted from reflow via `CommentPragmas` (see the next paragraph). String literals are the one sanctioned exception: `BreakStringLiterals: false` keeps long log and error messages as single greppable literals, so a line whose excess sits inside one literal is left alone rather than split. When a message line still exceeds 120 columns, split the literal by hand at sentence or clause boundaries using adjacent string-literal concatenation (the compiler fuses the fragments back into one literal at compile time): keep the distinctive lead phrase whole in its own fragment so it stays greppable, and mind the space at each seam -- a missing seam space silently corrupts the message. Do not work around the limit with trailing comments -- keep a member's documentation on the line(s) above it (per the comment conventions) instead of letting a trailing comment push the line out. The comment-marker rules above are guarded by an advisory CI step, `scripts/check_comment_style.py` (no trailing `///<`, no multi-line `///`, no block tag on a `///` line).

`ReflowComments: Always` re-wraps plain `//` comment text that overflows 120, but `CommentPragmas: '^ IWYU pragma:|^ {3,}'` exempts `/** */` Doxygen doc-blocks from reflow: it marks any comment line indented three or more spaces -- the hang under a Doxygen `@tag` -- as un-reflowable, and a single protected continuation line inhibits reflow of the whole block. So the formatter never re-wraps, re-fills, or mangles a doc-block; doc-blocks are hand-maintained (without the pragma, `ReflowComments: Always` collapses the hang-alignment of a re-wrapped block and can emit a stray `* *`). The clang-format check is advisory regardless. Reflow doc-blocks by hand to fill the column, changing only line breaks (never wording): keep CRLF line endings (a text-mode read/write that flips them to LF rewrites the whole file); keep each `@tag` on the first line of its paragraph with continuations hanging-aligned under the tag content (the `@note`/`@return` style used throughout `hook_manager.hpp`); leave `@param`/`@tparam` description-aligned and single-line `/** ... */` untouched. Because the formatter will not wrap a doc-block for you, verify length by hand with `awk 'length>120'` (empty) and confirm the comment text is unchanged token-for-token.

Markdown files (`*.md`) are **not** hard-wrapped at 80 columns. Write one logical line per paragraph, list item, and blockquote line and let editors soft-wrap; do not insert manual line breaks mid-paragraph. Fenced code blocks, tables, and any line indented four or more spaces (indented code, nested list sub-paragraphs) are kept verbatim. As in code, use `--` rather than an em-dash or en-dash.

### Type safety and const-correctness

- **`const` by default:** Declare local variables `const` unless mutation is required. Use `const auto &` in range-for loops over containers.
- **`constexpr` where possible:** Prefer `constexpr` for functions evaluable at compile time. Use `inline constexpr` for namespace-scope constants in headers. Use `static constexpr` for class-scope constants.
- **`noexcept`:** Mark all destructors, shutdown methods, accessors, and functions that provably never throw. All `const` getters must be `noexcept`. A `noexcept` function must not perform a potentially-throwing allocation (vector/string growth, `make_unique`, plain `operator new`, `std::format`) unless every throwing step is wrapped in a local `try/catch` that preserves the no-throw contract -- fail closed: leave state unchanged (allocate before committing), return a failure/no-op result, and log best-effort through `Logger::log_noexcept` / `Logger::try_log`. For allocation that can genuinely fail under load, prefer `new (std::nothrow)` / the nothrow `operator new` and drop the work rather than terminate. See the `InputPoller` reshape APIs, `StringPool` growth, and the bootstrap helpers.
- **`[[nodiscard]]`:** Apply to all functions where ignoring the return value is a likely bug: factory functions, status queries, `bool` success/failure returns, `std::expected`/`std::optional` returns.
- **`explicit`:** All single-argument constructors must be `explicit`.
- **Casts:** Use C++ casts exclusively (`static_cast`, `reinterpret_cast`, `const_cast`). Never use C-style casts. Use `reinterpret_cast` only for pointer/address conversions at system boundaries. When intentionally discarding a `[[nodiscard]]` return value, cast to void explicitly: `(void)expr;`. This suppresses the compiler warning and signals deliberate intent.
- **Enums:** Always `enum class` (C++ Core Guidelines Enum.3). Enumerator names use `PascalCase` (e.g. `HookStatus::Active`, `OverflowPolicy::DropNewest`).
- **Initialization:** Use brace initialization `{value}` for member variable default values in class declarations (e.g. `std::atomic<bool> m_running{false};`). Use parenthesized or `=` initialization only when brace initialization causes narrowing or ambiguity.
- **`nullptr`:** Always use `nullptr`, never `0` or `NULL`.
- **`std::string_view`:** Prefer `std::string_view` for non-owning string parameters. Use `std::string` only when ownership is required.

### Resource management and patterns

- **RAII everywhere:** `std::unique_ptr`, `std::shared_ptr`, `std::lock_guard`, `std::scoped_lock`. No naked `new`/`delete` in application code. The only permitted exception is leak-on-purpose state to avoid teardown hazards -- specifically the static destruction order fiasco or deadlock when destruction would run under the Windows loader lock. Any such leak must be documented with a comment explaining why, must use `new (std::nothrow)` so the enclosing `noexcept` path stays honest, and must pin the current module so code pages referenced by the leaked state stay mapped (see `HookManager::~HookManager` and `Logger::shutdown_internal`).
- **Rule of Zero/Five:** Prefer Rule of Zero (let compiler generate special members). When custom resource management is needed, implement all five special members. Delete copy/move when the type is non-copyable/non-movable.
- **Atomic memory orderings:** Use the weakest correct ordering. `memory_order_relaxed` for counters and non-critical flags. `acquire`/`release` pairs for synchronization. Document why in comments only when the ordering is non-obvious.
- **Lock ordering:** When acquiring multiple locks, document the order in the class header and follow it strictly. Example from `logger.hpp`: `1. m_async_mutex` then `2. *m_log_mutex_ptr`.
- **Two-phase shutdown:** When destroying or shutting down objects that manage hooks or callbacks, disable/drain under a shared/reader lock first, then clear state under an exclusive/writer lock. This prevents deadlock with in-flight callbacks.
- **Deferred logging:** When logging inside a critical section, collect messages into a local vector and emit after releasing the lock. This prevents deadlocks when Logger acquires its own locks.
- **Re-check shutdown after a gate:** A mutator that fast-fails on a global shutdown/teardown flag before acquiring a serializing gate must re-check the same flag after acquiring it. A thread can observe the flag as false, then block behind a teardown that holds the gate exclusively and resets reusable state; the post-gate re-check keeps every mutator uniform and prevents stale operations against a freshly reset generation (see the `HookManager` create/enable/disable/remove and VMT mutators).
- **Callbacks are host-critical:** Hook callbacks and input callbacks run on the game's threads. Do not perform unbounded allocation, blocking I/O, hook creation/removal, or config reload directly inside them; defer that work to a worker or queue. Logging from a callback must use the no-throw `Logger::log_noexcept` / `Logger::try_log` so a formatting or sink failure cannot escape into the host.
- **Error returns:** `std::expected` for memory operations, `std::optional` for scanner results. Reserve exceptions for construction failures and truly exceptional conditions.
- **Security hardening:** The build enables ASLR (`/DYNAMICBASE`), DEP (`/NXCOMPAT`), and Control Flow Guard (`/GUARD:CF`) on MSVC, and equivalent flags (`--dynamicbase`, `--nxcompat`) on MinGW. Because DetourModKit is a static archive (the consumer performs the final link of the mod DLL/EXE), these switches are also propagated to `find_package` / `add_subdirectory` consumers via `target_link_options(DetourModKit INTERFACE ...)`, selected from the linker frontend detected at configure time so the right spelling reaches MSVC/clang-cl and MinGW/Clang while preserving the CMake 3.25 minimum. Do not remove these.

### Lambda conventions

- Use `[&]` capture for immediately-invoked lambdas that return into structured bindings (deferred logging pattern).
- Use explicit capture lists (`[this, &var1, &var2]`) for lambdas passed to threads or stored.
- Always specify the trailing return type (`-> ReturnType`) for non-trivial lambdas.

### Example -- good function style

```cpp
[[nodiscard]] bool InputPoller::is_binding_active(size_t index) const noexcept
{
    // Uncontended SRWLOCK reader; guards the m_active_states pointer swap that a
    // concurrent reshape (add/remove bindings) performs under the writer lock.
    std::shared_lock lock(m_bindings_rw_mutex);
    if (index >= m_bindings.size())
    {
        return false;
    }
    return m_active_states[index].load(std::memory_order_relaxed) != 0;
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

### Example -- emitting events from hook callbacks

```cpp
// Use emit_safe() from hook callbacks to prevent unhandled handler
// exceptions from crashing the host process. emit() propagates
// exceptions directly, which terminates the game if uncaught.
dispatcher.emit_safe(PlayerStateChanged{.health = player->health});
```

### Memory access in hook callbacks

Do not add `Memory::is_readable()` or `Memory::is_writable()` before every field read in hook callbacks. Use those predicates for setup validation and diagnostics. Use `seh_read_chain` for unstable live game pointers, and use `read_ptr_unchecked` only when the caller can prove the pointer chain is live for the current frame. The full pattern -- worked examples, the primitive selection table, and the anti-patterns to remove -- lives in [docs/misc/hot-path-memory.md](docs/misc/hot-path-memory.md).

### Scanning process memory

The raw `Scanner::find_pattern(start_address, region_size, pattern)` overloads do no page filtering: they read the whole span with `memchr`/SIMD, so the caller must guarantee `[start_address, start_address + region_size)` is committed and readable, or the host faults. Use them only on byte buffers or module sections whose readability is already known. To scan arbitrary process or module memory, prefer the page-filtered helpers (`scan_executable_regions`, `scan_readable_regions`), which walk `VirtualQuery` and skip guard, no-access, and non-readable pages. The per-region `VirtualQuery` gate proves readability only at gate time; on MSVC each region read additionally runs inside a structured-exception guard, so a region decommitted or reprotected concurrently between the gate and the read is skipped (and counted at `Debug`) rather than faulting the host. On MinGW the gate is the only guard, so that narrow TOCTOU window can still fault until the VEH-based handler lands. The same guard wraps the per-window reads behind `find_string_xref`.

## Testing

- **Framework:** GoogleTest. Test entry point is `tests/main.cpp`.
- **One test file per module:** `tests/test_<module>.cpp` mirrors `src/<module>.cpp`.
- **Shutdown orchestration tests:** `tests/test_shutdown.cpp` tests the `DMK_Shutdown()` function from `DetourModKit.hpp`, verifying idempotent shutdown, hot-reload re-initialization, and correct teardown ordering across all subsystems.
- **Integration tests:** `tests/test_hook_integration.cpp` tests cross-module hooking against `tests/fixtures/hook_target_lib.cpp` (built as a DLL). The DLL exports `extern "C"` functions with volatile magic constants for stable AOB patterns. Includes hot-reload integration tests that exercise full hook/teardown/re-hook cycles, multi-type reload, enable/disable toggling, and repeated cycle stress.
- **Platform tests:** `tests/test_platform.cpp` tests internal loader-lock detection and module pinning utilities from `src/platform.hpp`.
- **Decoder tests:** `tests/test_x86_decode.cpp` tests the internal header `src/x86_decode.hpp` (RIP-relative E9 / EB / FF25 resolvers consumed by `Scanner`). The test file adds `src/` to its include path and drives each decoder with hand-crafted byte buffers.
- **Input interception tests:** `tests/test_input_intercept.cpp` tests the internal header `src/input_intercept.hpp` (same `src/`-on-include-path pattern as the decoder tests). It covers the two pure state machines that back the active-input layer: the wheel-pulse stepper (one notch maps to one Press edge with a forced low cycle) and the gamepad consume-until-release latch (modifier-released-before-trigger does not leak, release grace expiry, re-press during grace). The live hooks are exercised by integration tests against a throwaway top-level window the test process creates: the window-procedure subclass install/uninstall, per-direction wheel-notch capture, the consume-swallow versus forward decision (observed through a recording predecessor procedure), and the `WM_NCDESTROY` self-heal that lets a recreated window be re-subclassed. The XInput inline hook is exercised against a loaded `xinput` runtime (install, trampoline publish, idempotent re-install, teardown), and a standalone `InputPoller` test drives the full hot-reload disarm path (a consume wheel binding arms the swallow flag; `clear_bindings(false)` lets the poll loop disarm it on a later cycle). These live-hook tests skip themselves when the host has no window station or no XInput runtime, so a headless runner stays green. The one path still validated manually is the gamepad button masking itself, which requires a physically connected controller.
- **Worker tests:** `tests/test_worker.cpp` covers the `StoppableWorker` RAII `std::jthread` wrapper, including the empty-body early return, swallowed `std::exception` and unknown-exception paths, and idempotent `request_stop()` / `shutdown()`. The loader-lock detach arm is untestable from user code (only reached under DllMain) and is accepted as such.
- **SRW shared mutex tests:** `tests/test_srw_shared_mutex.cpp` covers the opaque Windows SRWLOCK SharedLockable wrapper used by DetourModKit reader/writer locks: shared-reader overlap, exclusive try-lock failure while readers are held, shared try-lock failure while a writer is held, a single-threaded try-lock/unlock sequence that proves both unlock paths actually release, and a blocked-writer handoff (a writer blocked in `lock()` cannot complete while a shared owner is live and acquires once the reader releases). File-scope static_asserts pin the deleted copy/move members (SRWLOCK owners and waiters reference the lock by address).
- **Pointer-chain tests:** `tests/test_memory_chain.cpp` is a deliberate second suite for the public `memory.hpp` surface, kept separate from `test_memory.cpp` because the single-fault-frame pointer-chain primitives (`plausible_userspace_ptr`, `seh_resolve_chain`, `seh_read_chain`, `seh_read_chain_bytes`) walk in-process pointer chains and need no cache or game-memory state, whereas `test_memory.cpp` drives the sharded cache, read/write, and module-range paths. Both suites bind to the same header; this is the only same-module split and is intentional for state isolation.
- **Reverse-RTTI / self-heal tests:** `tests/test_rtti_dissect.cpp` covers the `rtti_dissect.hpp` surface (L1 `identify_pointee_type` through L4 `solve_fingerprint`). It rebuilds the `SyntheticVtable` COL/TD/vtable fixture in the test exe's PE range (so the shared prelude's module bound-check accepts it) and adds a `syn_heap_object` helper that `VirtualAlloc`s an object outside every module range, exercising the pointer-to-object branch and the cross-DLL resolvability case. The suite replaces the throwing global `operator new`/`delete` with a malloc/free pair plus a counter so the `_AllocatesNothing` tests can assert the heal and fingerprint paths are allocation-free (each warms the module-range cache first, then measures a second call; the heal case is measured on the window-scan path, not just the nominal short-circuit); the aligned `operator new` forms are left at their defaults so over-aligned allocations never cross-free. This replacement is process-wide for the test binary but harmless to other suites (malloc/free is a valid implementation and only this suite reads the counter).
- **Reverse-RTTI by-name tests:** `tests/test_rtti_reverse.cpp` covers `rtti.hpp`'s reverse resolvers (`vtable_for_type`, `vtables_for_type`, `TypeIdentity`). It builds synthetic COL/TypeDescriptor/vtable fixtures in the test exe's data segment (so the prelude's module bound-check accepts them) and resolves them through a tight pool range for speed, with one case driving the real PE-section walk via `host_module_range()`. It exercises single- and multiple-inheritance (one name -> many sub-object vtables), the `COL.offset == 0` primary selection, ambiguous-name fail-closed, and the warm-cache identity path.
- **Code-constant tests:** `tests/test_code_constant.cpp` covers `Scanner::read_code_constant`. It plants known x86-64 encodings (immediate, `[reg+disp]`, negative disp8, RIP-relative) into a committed page and a `ModuleRange` over it, asserting the decoded value, narrowing, RIP-relative absolute resolution, the always-decode (never the stale `nominal`) contract, and the typed failures (`DecodeFailed` / `UnexpectedShape` / `OperandOutOfRange`).
- **String-reference xref tests:** `tests/test_string_xref.cpp` covers `Scanner::find_string_xref` across both phase-2 modes. It builds three synthetic images: a single RWX page (`SyntheticImage`) for the default narrow shape scan; a split code/data image (`SplitImage`: an execute-readable code page plus a readable `PAGE_READWRITE` data page) so the broad Zydis sweep only ever decodes the code page; and a four-page `GappedCodeImage` whose executable region is split by a reserved interior page, the only fixture that makes `collect_executable_windows` return more than one window. Cases cover the narrow `lea` / `mov` resolves, the broad-only shapes (`cmp [rip+d], imm`, `push [rip+d]`, a no-REX `lea`, and the REX `lea` superset), the invariant that broad mode keeps default all-offset shape-scan coverage, the decode-failure byte-restart recovery, the `Utf16le` widening and the `require_terminator` prefix guard, the `EnclosingFunction` prologue back-scan (hit and miss), cross-window resolve and ambiguity accumulation, the invariant that the non-executable data page is never swept as code, and every fail-closed error (`EmptyQuery` / `InvalidRange` / `StringNotFound` / `StringAmbiguous` / `NoReference` / `AmbiguousReference` / `FunctionNotFound`) plus the `constexpr noexcept` totality of `string_xref_error_to_string`.
- **Anchor registry tests:** `tests/test_anchors.cpp` covers `anchors.hpp` (`resolve`, `resolve_all`, `anchor_status_to_string`), one case per resolvable kind (Manual literal, CodeOperand, RipGlobal, VtableIdentity fail-closed) plus the `CallArgHome` `Unsupported` path and the parallel-report capacity behaviour. It also covers the optional post-resolve validator (accept, reject-fails-closed, context pass-through both ways, and the Manual / CallArgHome exemptions) and the `Quorum` kind (agreement, disagreement, one-signal-fails, null sub-anchor, rejected nesting, within-tolerance accept and reject, negative-tolerance fail-closed, the quorum's own validator applied to the corroborated value, and quorum propagation through `resolve_all`).
- **Test fixture pattern:** Each suite uses a `::testing::Test` subclass with `SetUp()`/`TearDown()` for temp file cleanup. Temp file paths must include the process ID (`_getpid()`) and a counter to avoid collisions when CTest runs tests in parallel as separate processes.
- **VMT hook test lifetime:** GoogleTest destroys test-body locals *before* calling `TearDown()`. VMT tests must explicitly call `remove_all_vmt_hooks()` (or `remove_vmt_hook`) before target objects go out of scope. Do not rely on `TearDown()` for VMT cleanup when the hooked object is a test-body local.
- **VMT hook pre-flight symmetry:** The VMT hook path exposes the same operational policy knobs the inline hook does via `VmtHookConfig`: `fail_if_already_hooked` refuses a create/apply whose vptr already points at a clone owned by this HookManager (a silent double-clone on a layered mod is a real bug class), and `fail_on_non_function_pointer` pre-flight-decodes the first byte of the original vtable slot and refuses 0xCC/0xCD/0xC2/0xC3/0x00 plus same-module jump-stub slots. Both default to off; the legacy single-arg `create_vmt_hook(name, object)` and `apply_vmt_hook(name, object)` overloads are preserved as thin delegating wrappers around the configurable overloads so existing call sites compile unchanged. Tests in `tests/test_hook_manager.cpp` (`VmtHookConfig_*`) pin both knobs.
- **Layered inline/mid hook teardown order:** Inline and mid hooks layered on one target address must be unwound newest-first, the same invariant the VMT path enforces. SafetyHook's `disable()` copies a hook's saved prologue bytes back over the target, and a hook created on an already-hooked address saves the live prologue (a jump to the first detour) as *its* original; restoring oldest-first would rewrite the entry to jump into the older hook's about-to-be-freed trampoline (a use-after-free). `HookManager` records creation order in `m_hook_creation_order` (alongside `m_vmt_creation_order`) and walks it in reverse in both teardown phases via `disable_hooks_reverse_order_locked()` / `clear_hooks_locked()`, so a single global reverse walk yields correct per-address LIFO. A same-address create is refused under `HookConfig::fail_if_already_hooked` by the exact registry check `find_hook_owner_of_target_locked` (the prologue-byte heuristic still covers foreign-module hooks). Bulk teardown is ordered automatically; explicit single `remove_hook` does not reorder for the caller, so layered hooks must be removed newest-first. Tests in `tests/test_hook_manager.cpp` pin this (`InlineHook_RemoveAllUnwindsLayeredHooksInReverseCreationOrder`, `InlineHook_StrictModeRefusesLayeringByRegistry`, `MidHook_StrictModeRefusesLayeringByRegistry`, `InlineMidHook_StrictModeRefusesCrossTypeLayering`).
- **Drift manifest tests:** `tests/test_drift_manifest.cpp` covers `drift_manifest.hpp`: round-trip of a DriftEntry report through serialize/parse (including negative offsets and the owned-name-survives-source-destruction guarantee), the empty-report header-only case, file round-trip, and the fail-closed parse errors (missing header, wrong field count, non-numeric offset, missing file).
- **Diagnostics tests:** `tests/test_diagnostics.cpp` covers `diagnostics.hpp` (the per-subsystem intentional-leak counters): per-subsystem increment isolation, accumulation, the cross-subsystem total, the out-of-range `LeakSubsystem::Count` no-op, and reset. The instrumented loader-lock teardown sites themselves are not reachable from a normal test run; the counter contract is verified directly.
- **Coverage gate:** 80% minimum line coverage enforced in CI. All PRs must pass.
- **Concurrency tests:** Use `std::atomic<bool> stop` flag pattern with multiple threads. See `AsyncMode_ConcurrentLogAndDisable` in `test_logger.cpp` for the reference pattern.
- **Build flag:** Tests are enabled with `DMK_BUILD_TESTS=ON` (on by default in debug presets).

For detailed coverage analysis, see [docs/tests/README.md](docs/tests/README.md). For hot-reload testing patterns, see [docs/hot-reload/README.md](docs/hot-reload/README.md). For INI hot-reload (filesystem watcher and reload hotkey), see [docs/config-hot-reload/README.md](docs/config-hot-reload/README.md). For AOB signature construction, the Scanner API, and RIP-relative resolution, see [docs/misc/aob-signatures.md](docs/misc/aob-signatures.md). For the MSVC RTTI walker and the typed SEH read primitives it builds on, see [docs/misc/rtti-walker.md](docs/misc/rtti-walker.md). For the reverse RTTI dissector and the self-healing offset resolver built on the same prelude, see [docs/misc/rtti-self-heal.md](docs/misc/rtti-self-heal.md). For the declarative anchor registry that unifies the vtable / cascade / code-constant / manual backends, see [docs/misc/anchors.md](docs/misc/anchors.md).

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
| HookManager | SRWLOCK-backed reader/writer locks; two-phase shutdown (disable under shared lock, clear under exclusive lock), both phases walking `m_hook_creation_order` in reverse so inline/mid hooks layered on one address unwind newest-first instead of in bucket order; `m_mutator_gate` blocks new mutators (including all VMT operations) during teardown; CAS on `m_shutdown_called` serializes shutdown/remove_all_hooks; double-checked fast-fail on `m_shutdown_called` in all mutators; every public mutation or teardown entry point also fails closed (`HookError::ReentrantCallRejected`, a false/zero result, or a logged no-op for void lifecycle calls) when the per-thread reentrancy guard is set, so a call from inside a `with_*` callback returns or no-ops instead of recursively acquiring the non-recursive lock; the batch toggles (`enable_hooks`/`disable_hooks`/`*_all`) collect their log lines under the lock and emit them after release so a synchronous sink flush or a blocking async overflow never stalls an exclusive acquirer; destructor fallback (when `DMK_Shutdown()` was not called) acquires `m_mutator_gate` exclusively, flips `m_shutdown_called`, drains readers via exclusive `m_hooks_mutex`, then clears the maps -- under loader lock it pins the module and swaps each map's contents into heap storage allocated via `new (std::nothrow)` so the storage outlives the destructor without ever draining, mirroring the leak-on-loader-lock discipline used in `Logger::shutdown_internal` and `ConfigWatcher::~ConfigWatcher` | `shared_lock` SRWLOCK reader for `with_inline_hook()` |
| Logger | `atomic<shared_ptr>` for lock-free async reads; `shutdown_internal` and `disable_async_mode` are safe across repeated shutdown / enable_async_mode cycles: when the writer thread has to be detached under loader lock, the module is pinned and the `shared_ptr<AsyncLogger>` is moved into a per-call permanent cell (normal path: `new (std::nothrow)`; fallback path: non-CRT permanent storage), so a heap allocation failure cannot drop the last handle while the writer may still be running | Single atomic load on log level check |
| AsyncLogger | Lock-free MPMC queue (Vyukov-style); post-join drain on shutdown (at most one message per producer can be lost in the nanosecond race between drain and force-zero -- accepted trade-off to avoid atomic overhead on every enqueue); a producer wakes a parked writer through a seq_cst pending-count/flag handshake (`m_pending_messages` is made non-zero before the queue slot is published, the writer publishes `m_writer_waiting` before checking that count and blocking, and the producer notifies under `m_flush_mutex` only when the flag is set), so the busy-writer hot path stays lock-free and syscall-free yet a push can never strand a message until the flush-interval timeout; timestamp caching in write batches | Atomic sequence numbers per slot; flag-gated writer wakeup |
| InputPoller | Atomic `m_active_states[]` array; the poll thread re-reserves its deferred-callback staging vector to the live binding count each cycle and stages it under a catch, so a runtime binding growth past the startup reserve cannot reallocate-then-throw out of the `jthread` body; a failed callback batch is dropped, not fatal | `shared_lock` (uncontended SRWLOCK reader) guarding the `m_active_states` pointer swap + `memory_order_relaxed` load per binding; keyboard/mouse reads route through a poll-thread-private per-cycle `KeyStateCache` so each distinct VK gets one coherent `GetAsyncKeyState` sample per cycle, not one call per binding reference |
| InputManager | `mutex` for lifecycle, `atomic<shared_ptr<InputPoller>>` for reads | `atomic<shared_ptr<InputPoller>>` acquire-load, then the poller's `shared_lock` + relaxed load (not lock-free) |
| InputIntercept (internal `src/input_intercept.*`) | File-scope atomics shared between the poll thread and the game's threads (XInput callers, window message thread); owns its safetyhook InlineHooks directly (not via HookManager) because the poll thread reads the trampoline and the hook lifetime is coupled to the poll thread; consume-until-release latch and wheel-pulse state are poll-thread-private; teardown skipped under loader lock (detours left installed against the pinned module) | Lock-free atomic loads in each detour; allocation-free, non-throwing detour bodies |
| Memory cache | Sharded `SRWLOCK` + epoch-based shutdown | Shared reader locks per shard |
| Config | `mutex` for registration; deferred setter invocation outside lock (no reentrancy guard needed -- setters may call back into Config); `reload()` re-runs the registered items against the stashed INI path using the same deferred pattern and short-circuits on FNV-1a 64 hash match of the on-disk bytes to skip no-op reloads; bytes are read once per load/reload and fed to `CSimpleIniA::LoadData`, so the cached hash and the parsed INI state are guaranteed to reflect the same file snapshot (no TOCTOU between hash and parse); `enable_auto_reload()` owns a `ConfigWatcher` behind a separate `std::mutex` so start/stop transitions do not contend with registration traffic; setters invoked by the watcher run on the watcher thread, setters invoked by the reload hotkey run on a dedicated `ReloadServicer` thread (lazily started on first `register_reload_hotkey`, torn down in `clear_registered_items()`) so the `InputManager` poll thread never blocks on INI parsing; the servicer's press-request path takes its internal `m_mutex` around the predicate store before `cv.notify_one` to close the lost-wakeup window; all setters must be reentrant and thread-safe | N/A (startup only) |
| ConfigWatcher | One `StoppableWorker` per instance; worker opens the parent directory with `FILE_FLAG_BACKUP_SEMANTICS` and `FILE_FLAG_OVERLAPPED`, then pumps `ReadDirectoryChangesW` via `GetOverlappedResultEx` with a 100 ms timeout so `stop_token` is observed promptly; on stop the in-flight read is cancelled and drained with a bounded, escalating wait (timed `GetOverlappedResultEx`, then directory-handle close to force the orphaned IRP to complete, then leak the heap-bundled I/O buffer if completion still cannot be confirmed) so a deleted watched directory cannot hang teardown; debounce uses `steady_clock`; filename match is case-insensitive; `start()` and `stop()` are idempotent and serialized by an internal `std::mutex`; under loader lock the destructor pins the module, requests stop on the worker, and moves `Impl` into a per-call heap cell allocated via `new (std::nothrow)` (with a `release()` fallback on OOM that leaks the raw pointer instead of running `~Impl`) so the noexcept destructor stays honest, mirroring the `Logger::shutdown_internal` discipline | 100 ms `GetOverlappedResultEx` pump; idle CPU ~0 |
| EventDispatcher | Lock-free `emit()` / `emit_safe()` via `std::atomic<std::shared_ptr<const std::vector<Entry>>>` snapshot (copy-on-write publish, acquire-load on read); zero-subscriber fast path skips the snapshot load via an atomic handler counter; writers serialize on a small `std::mutex` that never touches the emit hot path; thread-local reentrancy guard rejects subscribe/unsubscribe from within handlers so the no-mutation-during-emit invariant holds; `emit()` propagates handler exceptions, `emit_safe()` catches and skips them | Atomic acquire-load of a `shared_ptr` snapshot plus linear iteration over a contiguous vector; no reader lock |
| Profiler | Lock-free ring buffer via atomic `fetch_add` on write position; odd/even sequence counter per sample slot prevents torn reads during concurrent export: `record()` opens and closes the slot with unconditional `fetch_add` (never a load-then-store) so concurrent producers racing on the same slot cannot roll the counter backwards, and the cold export path is a seqlock reader (load the sequence, copy the fields into locals, re-load the sequence behind an acquire fence, and drop the sample if it changed or is odd); `DMK_PROFILE_SCOPE(name)` requires `name` to be a string literal, enforced at compile time by a `ScopedProfile` constructor that only binds to `const char (&)[N]` | Single atomic increment + sequence-guarded field writes per sample |

### Performance-critical paths

These are called at 60+ fps from game hook callbacks. Never add allocations, exclusive locks, or blocking I/O to them. Some entries take an uncontended SRWLOCK shared (reader) lock; that is cheap, non-blocking among readers, and syscall-free, so it is the one tolerated synchronization on these paths -- do not escalate it to an exclusive lock or add new locking:

- `InputPoller::is_binding_active(index)` -- `shared_lock` (uncontended SRWLOCK reader, guards the `m_active_states` pointer swap on reshape) + single `memory_order_relaxed` load
- `InputPoller::is_binding_active(name)` -- `shared_lock` + hash lookup + `memory_order_relaxed` load per matching binding (typically 1-3)
- `HookManager::with_inline_hook()` -- `shared_lock` SRWLOCK reader
- `Logger::log()` level check -- single atomic load
- `Logger::log()` async enqueue -- atomic shared_ptr load + lock-free queue push
- `Memory::is_readable()` -- sharded SRWLOCK reader + cache lookup
- `Memory::is_readable_nonblocking()` -- try_lock_shared + cache lookup (returns Unknown on contention)
- `Memory::read_ptr_unsafe()` -- SEH-protected raw dereference (MSVC), cache-accelerated with VirtualQuery fallback (MinGW)
- `Memory::read_ptr_unchecked()` -- inline pointer dereference with source and result user-mode range guards (a low-address floor plus a `USERSPACE_PTR_MAX` ceiling that rejects kernel-range and non-canonical values, which also subsumes pointer-arithmetic wraparound), no SEH (caller must guarantee structural pointer validity); debug builds add an `is_readable` assert that catches a stale or unmapped source pointer, compiled out in release so the hot path stays a single guarded memcpy
- `Memory::seh_read<T>()` / `seh_read_bytes()` -- typed and raw SEH-guarded reads; single `__try` frame on MSVC, VirtualQuery loop across regions on MinGW. The MSVC `__except` filter swallows the foreign-read fault set -- `EXCEPTION_ACCESS_VIOLATION`, `STATUS_GUARD_PAGE_VIOLATION`, and `EXCEPTION_IN_PAGE_ERROR` (a file-backed or image-mapped page failing to page in, e.g. during an RTTI / section walk) -- and lets any other code continue the handler search; the predicate (`Memory::detail::is_guarded_read_fault`) is shared by every guarded read so the set stays uniform. Used by `Rtti` for chained RTTI walks
- `Memory::seh_resolve_chain()` / `seh_read_chain<T>()` -- resolves or reads a whole multi-level pointer chain under one fault guard: one out-of-line call instead of N separate `seh_read` calls, with each intermediate link kept in a register and pre-screened by `plausible_userspace_ptr` (a faulting or implausible link aborts the walk and returns nullopt/false). VirtualQuery-guarded per link on MinGW
- `Memory::plausible_userspace_ptr(p)` -- `inline constexpr` user-mode pointer plausibility test; pure arithmetic with no syscall and no memory access (early-rejects stale/sentinel/torn pointers before an SEH-guarded read)
- `Memory::contains(range, p)` -- constexpr point-in-range test for module bounds checks
- `Memory::own_module_range()` / `host_module_range()` -- magic-static cached, single atomic load on the fast path
- `Rtti::vtable_is_type(vt, expected)` -- one batched COL read (24 bytes) plus `expected.size() + 1` bytes of name comparison; no allocation
- `Rtti::find_in_pointer_table(..., vtable_cache)` warm-cache path -- single qword compare per slot, no RTTI walk
- `Rtti::TypeIdentity::matches(vtable)` after first resolve -- single qword compare, no RTTI walk (the reverse `vtable_for_type` scan is init-time only, run once and cached)
- `Logger::is_enabled()` -- single atomic load (gate expensive trace-only work)

## Boundaries

- **Do not modify** files under `external/` -- these are git submodules.
- **Do not add** `using namespace` directives in header files.
- **Do not add** heap allocations on hot paths (see list above).
- **Do not break** the lock ordering documented in class headers.
- **Do not weaken** atomic memory orderings without proving correctness.
- **Do not skip** running the test suite before committing.
- **Do not publish** release packages before debug tests, release builds, and installed-package smoke tests pass for both MinGW and MSVC.
- **Do not add** Windows API calls without `#ifdef _WIN32` guards in headers (implementation files are Windows-only, but headers should remain clean).
- **Do not commit** build artifacts, `.exe`, `.a`, `.lib`, `.obj`, or `.pdb` files.
- **Do not remove** or weaken existing tests. Add new tests for new code.
- **Do not use** C-style casts, `NULL`, or `0` as a pointer constant.
- **Do not use** plain `enum` -- always use `enum class`.
- **Do not use** `///` multi-line doc comments in headers -- use `/** @brief ... */` Doxygen blocks.
- **Do not use** named internal namespaces in `.cpp` files -- use anonymous namespaces for internal linkage.
- **Do not expose** implementation-only container or entry types as top-level public API in public headers -- place them in `namespace detail` (e.g. `detail::VmtHookEntry`) or an internal header so they stay out of the documented API surface.
- **Do not omit** `noexcept` on destructors, shutdown methods, and const accessors.
- **Do not omit** `[[nodiscard]]` on functions returning `std::expected`, `std::optional`, or success/failure `bool`.
- **Do not omit** `explicit` on single-argument constructors.
- **Do not add** uninitialized variables -- always initialize at declaration with brace syntax or assignment.
- **Do not use** `std::endl` -- use `'\n'`. `std::endl` forces a flush.
- **Do not use** `#pragma once` -- use `#ifndef`/`#define`/`#endif` include guards.
- **Do not use** `EventDispatcher::emit()` from hook callbacks -- use `emit_safe()` instead to prevent unhandled handler exceptions from crashing the host process.
- **Do not return** from a memory-writing helper before its post-write cache maintenance (instruction-cache flush and cache-range invalidation) once bytes have been modified -- run the cleanup on every exit path, even when a later step such as restoring page protection fails.
- **Do not let** a public doc comment describe behavior the implementation no longer has -- lifecycle and ordering claims must match the code, and are best pinned by a test.
- **Do not take** a shared lock in a const query/accessor that can be called from inside a `with_*`/`try_with_*` callback without first making it reentrancy-guard-aware (skip the lock when the per-thread guard is non-zero, since the callback already holds it). Recursive shared acquisition of a non-recursive reader/writer lock on one thread is undefined behavior and deadlocks if a writer is queued between the two acquisitions (see `HookManager::lock_hooks_shared_reentrant`).
- **Do not call** a HookManager mutation or teardown entry point (`create_inline_hook` / `create_inline_hook_aob` / `create_mid_hook` / `create_mid_hook_aob` / `create_vmt_hook` / `hook_vmt_method` / `apply_vmt_hook` / `enable_hook` / `disable_hook` / `remove_hook` / `remove_vmt_hook` / `remove_vmt_method` / `remove_vmt_from_object`, the `enable_hooks` / `disable_hooks` / `enable_all_hooks` / `disable_all_hooks` batch toggles, or the `shutdown` / `remove_all_hooks` / `remove_all_vmt_hooks` bulk teardown calls) from inside a `with_*`/`try_with_*` callback. The callback already holds `m_hooks_mutex` shared and the per-thread reentrancy guard is non-zero, so re-acquiring that non-recursive lock (shared for the toggles, exclusive for the create/remove/teardown paths) is undefined behavior and deadlocks. Every such public entry point now checks the guard on entry and fails closed -- `HookError::ReentrantCallRejected` for the `std::expected` mutators, `false` or a zero count for the bool/count mutators, and a logged no-op for void lifecycle calls -- so the misuse is a visible error, not a hang. Defer the mutation until after the callback returns (queue it to a worker).
- **Do not key** a cache store and its invalidation/eviction by different addresses or shard-selection functions. Eviction must use the same canonical key and the same containment lookup as insertion and read, or entries silently survive invalidation (see `Memory::invalidate_range`, which scans every shard because storage is sharded by query address, not region base).
- **Do not let** a queue or backlog fed at an external event rate grow without bound -- clamp the pending count to a documented ceiling (see `Input` wheel-notch `MAX_WHEEL_PENDING`).
- **Do not let** an async/deferred sink diverge from its synchronous counterpart's configuration (timestamp format, level, etc.) -- carry the same settings through, as `Logger::enable_async_mode` does for the timestamp format.
- **Do not open** a shared append-mode file with `GENERIC_WRITE` plus a one-time `SetFilePointer(FILE_END)` seek -- request `FILE_APPEND_DATA` so the OS positions every write at the current end of file atomically and concurrent appenders cannot interleave or overwrite each other (see `WinFileStreamBuf::open`). Truncating (`out`) mode keeps `GENERIC_WRITE` + `CREATE_ALWAYS`.
- **Do not drop** the device source when formatting an off-table input code -- a non-keyboard code must serialize in the source-tagged hex form (`Mouse:0xNN`) that `parse_input_name` reads back, or it silently round-trips to a keyboard key (see `format_input_code` / `parse_input_name`).
