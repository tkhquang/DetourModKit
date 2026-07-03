# AGENTS.md -- DetourModKit

## Project overview

DetourModKit is a C++23 static library for Windows game modding. It provides AOB scanning, function hooking (via SafetyHook), async logging, INI configuration, input polling, and memory utilities. The library is consumed by mod DLLs injected into game processes.

**Stack:** C++23, CMake 3.28+, Ninja, GoogleTest. Targets MinGW (GCC 13+) and MSVC 2022+.

**Key dependencies (git submodules):**

- `external/safetyhook` -- inline/mid-function hooking (links Zydis/Zycore). It is confined to two internal islands: the public `hook::` surface's pimpl (`src/hook.cpp` + `src/internal/hook_backend.hpp`) and the active-input layer (`src/internal/input_intercept.cpp`). No public header names it, so a consumer that includes `hook.hpp` builds with SafetyHook off its include path and only its static archive ships. `scripts/check_header_hygiene.py` and `scripts/check_install_prefix.py` enforce the confinement
- `external/DirectXMath` -- header-only math library, re-exported to `find_package` consumers by default (so a mod can `#include <DirectXMath.h>` transitively); set `-DDMK_INSTALL_DIRECTXMATH=OFF` for a prefix that ships only DetourModKit's own headers
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

# Standalone bench executables (no gtest runtime); methodology and numbers live under docs/analysis/:
#   DetourModKit_bench           -- EventDispatcher emit / subscribe throughput
#   DetourModKit_bench_scanner   -- find_pattern, rare-byte anchor, prefilter, and resolver-batch
#   DetourModKit_bench_memory    -- validation predicate vs direct SEH-guarded read / chain primitives

PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-release \
    --target DetourModKit_bench_scanner --parallel
./build/mingw-release/tests/DetourModKit_bench_scanner.exe
```

Latest scanner bench numbers and methodology live in [docs/analysis/scanner_bench_v3.x/README.md](docs/analysis/scanner_bench_v3.x/README.md). Memory validation-vs-direct-read numbers live in [docs/analysis/memory_bench_v3.x/README.md](docs/analysis/memory_bench_v3.x/README.md).

The opt-in AVX-512 verify tier is gated behind the `DMK_ENABLE_AVX512` CMake option (default OFF). When off it compiles out entirely; when on it is still selected only behind a runtime CPUID + XGETBV check (AVX-512F + AVX-512BW, since the byte-wise masked compare is a BW instruction), so the produced library still runs on CPUs without AVX-512 (it simply falls back to AVX2). The intrinsics are confined to that one tier via a per-function `target` attribute, so enabling the option never bumps the baseline ISA of the rest of the library. Its `>= 30%` verify-throughput gate can only be measured on real AVX-512 hardware. Per-tier correctness (including AVX-512, under Intel SDE) is validated on every push to main by `.github/workflows/simd-tier-correctness.yml`; the throughput gate itself is measured on an AVX-512 host (see `docs/analysis/avx512_verify_icount`).

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

The AOB scanner and the SEH-guarded probe read deliberately read arbitrary mapped process memory, which ASan reports as false-positive overflows when it scans this process's own poisoned shadow. The AOB prefilter routes through a self-provided `dmk_memchr` in all builds, which is immune to libc interceptors by construction; the remaining ASan-only treatment is the `no_sanitize_address` attribute and the `__movsb` copy path under `#if defined(__SANITIZE_ADDRESS__)`. See [docs/guides/memory/asan-memory-scanner.md](docs/guides/memory/asan-memory-scanner.md) for the mechanism and the pattern for any new foreign-memory primitive.

### Makefile wrapper

```bash
make              # Build mingw-release
make test         # Build mingw-debug + run tests
make test_msvc    # Build msvc-debug + run tests
make install      # Install to build/install/
make clean        # Remove all build directories
```

## Project layout

Single static-library target. Where a file goes is determined by role, not by module. These rules are CI-enforced (`scripts/check_header_hygiene.py` and `scripts/check_install_prefix.py`), not honor-system. Each module's full API lives in its own header doc-comments; this section is only about placement.

- `include/DetourModKit/` -- public headers, one per module. Installed API contract; anything here is a compatibility promise.
- `include/DetourModKit/detail/` -- compile-visible support a public header or the umbrella must include (templates, constexpr, public object layout). Allowlisted only, and must be backend-free (no SafetyHook/Zydis) and Win32-free: anything that touches a backend or Win32 belongs in `src/internal/`. Membership is gated on compile-visibility, not purity -- a `detail/` header may use the heap or the logger when the installed header it supports genuinely needs it at compile time. Prefer to keep such a header logger-free and heap-free where the support allows, but never push a header an installed header must include down to `src/internal/` (where it could no longer be included) merely to satisfy that preference.
- `include/DetourModKit.hpp` -- umbrella header plus the `Session` process lifecycle, at the include root so consumers write `<DetourModKit.hpp>`.
- `src/` -- implementation TUs. One `.cpp` per module; a cohesive module may split into sibling TUs that share one public header (for example the `scan_*` TUs over the private engine).
- `src/internal/` -- true-private headers and TUs: engines, backend bridges, and anything touching Win32, SafetyHook, or Zydis. Never installed.
- `tests/` -- GoogleTest, one `test_*.cpp` per module (`fixtures/`, `package_smoke/`). Fault-injection fixtures that need a committed `PAGE_NOACCESS` page live in `tests/fault/` and are built by `bash scripts/run_fault_tests.sh` (standalone-linked against the prebuilt archive), NOT the `tests/test_*.cpp` glob -- see Testing.
- `external/` holds git submodules, `scripts/` repo tooling and CI gates, `docs/` the guides (indexed by `docs/README.md`).

Header-placement decision:

1. Consumer-facing API? Put it in `include/DetourModKit/<module>.hpp`.
2. Otherwise, if an installed header must include it at compile time and it is backend-free and Win32-free, put it in `include/DetourModKit/detail/` and add it to the allowlist. Compile-visibility, not purity, is what forces `detail/` over `src/internal/`: the support header may use the heap or the logger when its installed header needs it, though logger-free and heap-free is preferable where feasible. A header that touches a backend or Win32 does not belong in `detail/`.
3. Otherwise (engine, backend bridge, pimpl internals, Win32) put it in `src/internal/`, never installed.

Demote test: a header lives in `detail/` only while something installed still includes it. The moment no public header does, it moves to `src/internal/`.

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
- **Braces:** Allman style -- opening brace on its own line for functions and classes, same line for control flow within a function body using K&R-style indented blocks. Single-statement control bodies are not required to be braced: the formatter's `InsertBraces` is intentionally left unset, so a brace-less guard clause (`if (cond) return;`) is fine; brace any multi-line or non-obvious body.
- **Indentation:** 4 spaces, no tabs.
- **Namespaces:** All public API lives in `namespace DetourModKit`. No `using namespace` in headers. In `.cpp` files, wrap the library's own definitions in an explicit `namespace DetourModKit { ... }` block rather than a file-scope `using namespace DetourModKit;`; the block form is the house default and is used by every `.cpp` in the library; no translation unit opens with a file-scope `using namespace DetourModKit;`. Every closing namespace brace must have a trailing comment: `} // namespace DetourModKit`. Implementation-only statics in `.cpp` files must be in an anonymous namespace (not a named internal namespace) to guarantee internal linkage.
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

C++ style is codified in the root `.clang-format` and `.clang-tidy`, not in prose here. Run clang-format over the changed `*.cpp` / `*.hpp` before committing; `.github/workflows/quality.yml` runs the advisory clang-format check (pinned to clang-format 20) plus a non-gating clang-tidy lane over the library's own sources, and `scripts/check_comment_style.py` guards the comment-marker rules. Submodules under `external/` are never formatted or analysed. The hard column limit is 120.

What the formatter does not do for you, and you must handle by hand:

- **Doc-blocks are hand-wrapped.** `/** */` Doxygen blocks are exempt from reflow (via `CommentPragmas`), so the formatter never re-wraps them: reflow them yourself to fit 120, changing only line breaks and never wording, and keep each `@tag` on the first line of its paragraph with continuations hanging-aligned. Plain `//` comment text is reflowed for you.
- **Long string literals split by hand.** `BreakStringLiterals: false` keeps log and error messages as single greppable literals; when one exceeds 120, split it at a clause boundary with adjacent string-literal concatenation, keeping the distinctive lead phrase whole and minding the space at each seam.
- **CRLF line endings.** Keep them. A text-mode rewrite (or a tool such as `sed`) that flips a file to LF rewrites the whole file; restore with `unix2dos` (never `-m`, which adds a BOM) and verify at byte level, since msys `grep` / `tr` misreport line endings.
- **Markdown.** `*.md` files are not hard-wrapped: write one logical line per paragraph, list item, and blockquote line and let editors soft-wrap. As in code, use `--` rather than an em-dash or en-dash.

### Type safety and const-correctness

- **`const` by default:** Declare local variables `const` unless mutation is required. Use `const auto &` in range-for loops over containers.
- **`constexpr` where possible:** Prefer `constexpr` for functions evaluable at compile time. Use `inline constexpr` for namespace-scope constants in headers. Use `static constexpr` for class-scope constants.
- **`noexcept`:** Mark all destructors, shutdown methods, accessors, and functions that provably never throw. All `const` getters must be `noexcept`. A `noexcept` function must not perform a potentially-throwing allocation (vector/string growth, `make_unique`, plain `operator new`, `std::format`) unless every throwing step is wrapped in a local `try/catch` that preserves the no-throw contract -- fail closed: leave state unchanged (allocate before committing), return a failure/no-op result, and log best-effort through `Logger::log_noexcept` / `Logger::try_log`. For allocation that can genuinely fail under load, prefer `new (std::nothrow)` / the nothrow `operator new` and drop the work rather than terminate. See the `detail::InputPoller` reshape APIs, `StringPool` growth, and the bootstrap helpers.
- **`[[nodiscard]]`:** Apply to all functions where ignoring the return value is a likely bug: factory functions, status queries, `bool` success/failure returns, `std::expected`/`std::optional` returns.
- **`explicit`:** All single-argument constructors must be `explicit`.
- **Casts:** Use C++ casts exclusively (`static_cast`, `reinterpret_cast`, `const_cast`). Never use C-style casts, with one sanctioned exception: when intentionally discarding a `[[nodiscard]]` return value, write the C-style `(void)expr;` (not `static_cast<void>(expr)`) -- this is the canonical discard spelling, it suppresses the warning and signals deliberate intent. Use `reinterpret_cast` only for pointer/address conversions at system boundaries.
- **Enums:** Always `enum class` (C++ Core Guidelines Enum.3). Enumerator names use `PascalCase` (e.g. `hook::Prologue::Fail`, `OverflowPolicy::DropNewest`).
- **Initialization:** Use brace initialization `{value}` for member variable default values in class declarations (e.g. `std::atomic<bool> m_running{false};`). Use parenthesized or `=` initialization only when brace initialization causes narrowing or ambiguity.
- **`nullptr`:** Always use `nullptr`, never `0` or `NULL`.
- **`std::string_view`:** Prefer `std::string_view` for non-owning string parameters. Use `std::string` only when ownership is required.

### Resource management and patterns

- **RAII everywhere:** `std::unique_ptr`, `std::shared_ptr`, `std::lock_guard`, `std::scoped_lock`. No naked `new`/`delete` in application code. The only permitted exception is leak-on-purpose state to avoid teardown hazards -- specifically the static destruction order fiasco or deadlock when destruction would run under the Windows loader lock. Any such leak must be documented with a comment explaining why, must use `new (std::nothrow)` so the enclosing `noexcept` path stays honest, and must pin the current module so code pages referenced by the leaked state stay mapped (see the v4 `Hook`/`VmtHook` handle destructor, which pins + leaks under the loader lock, and `Logger::shutdown_internal`).
- **Rule of Zero/Five:** Prefer Rule of Zero (let compiler generate special members). When custom resource management is needed, implement all five special members. Delete copy/move when the type is non-copyable/non-movable.
- **Atomic memory orderings:** Use the weakest correct ordering. `memory_order_relaxed` for counters and non-critical flags. `acquire`/`release` pairs for synchronization. Document why in comments only when the ordering is non-obvious.
- **Lock ordering:** When acquiring multiple locks, document the order in the class header and follow it strictly. Example from `logger.hpp`: `1. m_async_mutex` then `2. *m_log_mutex_ptr`.
- **Two-phase shutdown:** When destroying or shutting down objects that manage hooks or callbacks, disable/drain under a shared/reader lock first, then clear state under an exclusive/writer lock. This prevents deadlock with in-flight callbacks.
- **Deferred logging:** When logging inside a critical section, collect messages into a local vector and emit after releasing the lock. This prevents deadlocks when Logger acquires its own locks.
- **Callbacks are host-critical:** Hook callbacks and input callbacks run on the game's threads. Do not perform unbounded allocation, blocking I/O, hook creation/removal, or config reload directly inside them; defer that work to a worker or queue. Logging from a callback must use the no-throw `Logger::log_noexcept` / `Logger::try_log` so a formatting or sink failure cannot escape into the host.
- **API-discipline labels:** Public docblocks classify a function's call-site safety with one of three labels, applied as a `@note` and kept alongside (never replacing) any existing more-specific caveat. *Callback-safe* -- non-blocking, no unbounded allocation, no blocking I/O, no lock escalation; safe to call from a hook or input callback on a game thread (the hot-path reads and status queries). *Setup/control-plane only* -- may block, allocate, take exclusive locks, or do I/O; call from init/shutdown or a worker thread, never from a hook or input callback (create/remove/enable/disable, start/stop/shutdown, config load/reload, cache init). *Best-effort* -- on failure it fails closed (no-op / false / dropped) and never throws or terminates the host (logging, diagnostics counters, `emit_safe`, noexcept fail-closed paths).
- **Error returns:** `std::expected` for memory operations, `std::optional` for scanner results. Reserve exceptions for construction failures and truly exceptional conditions.
- **Security hardening:** The build enables ASLR (`/DYNAMICBASE`), DEP (`/NXCOMPAT`), and Control Flow Guard (`/GUARD:CF`) on MSVC, and equivalent flags (`--dynamicbase`, `--nxcompat`) on MinGW. Because DetourModKit is a static archive (the consumer performs the final link of the mod DLL/EXE), these switches are also propagated to `find_package` / `add_subdirectory` consumers via `target_link_options(DetourModKit INTERFACE ...)`, selected from the linker frontend detected at configure time so the right spelling reaches MSVC/clang-cl and MinGW/Clang while preserving the CMake 3.28 minimum. Do not remove these.

### Lambda conventions

- Use `[&]` capture for immediately-invoked lambdas that return into structured bindings (deferred logging pattern).
- Use explicit capture lists (`[this, &var1, &var2]`) for lambdas passed to threads or stored.
- Always specify the trailing return type (`-> ReturnType`) for non-trivial lambdas.

### Example -- good function style

```cpp
[[nodiscard]] bool detail::InputPoller::is_binding_active(size_t index) const noexcept
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

### Example -- good hook install pattern

```cpp
auto r = hook::inline_at({.name = "camera_update", .target = Address{addr}}, &detour);
if (r)
{
    Hook h = std::move(*r);
    // Typed trampoline (UNGUARDED, inline-only); original<Fn>() already returns the Fn function-pointer type, so
    // plain auto reads clearer than auto*. The RAII handle unhooks on drop.
    auto original = h.original<CameraUpdateFn>();
    original(camera_ptr);
}
```

### Example -- emitting events from hook callbacks

```cpp
// Use emit_safe() from hook callbacks to prevent unhandled handler
// exceptions from crashing the host process. emit() propagates
// exceptions directly, which terminates the game if uncaught.
dispatcher.emit_safe(PlayerStateChanged{.health = player->health});
```

### Memory access in hook callbacks

Do not add `memory::is_readable()` or `memory::is_writable()` before every field read in hook callbacks. Use those predicates for setup validation and diagnostics. Use `memory::walk` for unstable live game pointers, and use `memory::unchecked::read` only when the caller can prove the pointer chain is live for the current frame. For per-frame WRITES through a resolved address or pointer chain, use `memory::write_in_place` (or `memory::walk` then `write_in_place` at a chain's leaf): it changes no protection and fails closed if the target is not already writable, so a drifted pointer is rejected rather than silently mutating a read-only page. Reach for the escalating `memory::write<T>` / `write_bytes` (which auto-unprotect on a fault, then flip protection and flush the i-cache) for a one-shot code patch, and hold a `memory::ProtectGuard` to write a protected page repeatedly. The full pattern -- worked examples, the primitive selection table, and the anti-patterns to remove -- lives in [docs/guides/memory/hot-path-memory.md](docs/guides/memory/hot-path-memory.md).

### Scanning process memory

The raw `find_pattern(start_address, region_size, pattern)` overloads do no page filtering: they read the whole span with `memchr`/SIMD, so the caller must guarantee `[start_address, start_address + region_size)` is committed and readable, or the host faults. Use them only on byte buffers or module sections whose readability is already known. To scan arbitrary process or module memory, prefer the page-filtered helpers (`scan_executable_regions`, `scan_readable_regions`), which walk `VirtualQuery` and skip guard, no-access, and non-readable pages. The per-region `VirtualQuery` gate proves readability only at gate time; on MSVC each region read additionally runs inside a structured-exception guard, so a region decommitted or reprotected concurrently between the gate and the read is skipped (and counted at `Debug`) rather than faulting the host. On MinGW x64 the bulk `find_pattern_raw` reads run through the same process-wide vectored fault guard the `memory::read` copy primitives use (`scan_region_guarded` routes the per-region sweep through `memory::detail::run_guarded_region`), so a region reprotected or decommitted in that TOCTOU window is skipped and counted rather than faulting the host, matching the MSVC behaviour. The same guard wraps the per-window reads behind `find_string_xref`. A 32-bit build is rejected by the global architecture gate in `defines.hpp`, so guarded scanner code carries only the MSVC SEH and MinGW x64 VEH arms.

## Testing

- **Framework:** GoogleTest; entry point `tests/main.cpp`. Enable with `DMK_BUILD_TESTS=ON` (on by default in debug presets).
- **The canonical runner is `ctest`.** `gtest_discover_tests(... DISCOVERY_MODE PRE_TEST)` registers each case as its own ctest test, so `ctest` runs every case in a separate process. That per-case isolation is the real green/red signal: a few suites drive process-global state (the `ConfigTest` log-capture cases reconfigure the one `log()` sink) and interleave when many cases share the monolithic `DetourModKit_tests.exe`. Use the standalone exe with `--gtest_filter` for fast local iteration, but validate with `ctest`.
- **Test files mirror the surface they verify.** Use one `test_<module>.cpp` for a single-surface module; split large modules by fault-frame state, resolver/backend surface, or integration boundary (for example `test_memory` / `test_memory_chain`, the scanner resolver/string-xref/parallel suites, the RTTI dissect/reverse/heal suites, and hook integration / `MidContext`).
- **Coverage gate:** 80% minimum line coverage in CI.

Test-writing rules that are not obvious from a passing run:

- **Temp files need a unique name** -- include `_getpid()` plus a counter, because `ctest` runs cases as parallel separate processes.
- **A "must fault" test needs a committed `PAGE_NOACCESS` page held until teardown, never a `MEM_RELEASE`d region:** a released VA can be recycled and remapped by allocations the spawning threads trigger (stacks / TEBs, more so under ASan), so the read lands on live memory and flakes. See `AsyncMode_ConcurrentLogAndDisable` in `test_logger.cpp` for the concurrent-test pattern. The reusable `tests/fixtures/fault_injection.hpp` provides `dmk_test::NoAccessPage` (a leaked-on-purpose committed no-access page) and `ProtectedPage` (a page pinned to a chosen protection, for asserting a fault path restored it).
- **Fault-injection fixtures do NOT go in the `tests/test_*.cpp` glob.** Adding a source there forces a `CONFIGURE_DEPENDS` reconfigure that rebuilds the main C++23 test target. Put them in `tests/fault/test_*.cpp` and run them with `bash scripts/run_fault_tests.sh`, which compiles a standalone fault-test executable and links it against the prebuilt `libDetourModKit.a` (rebuild just that target with `cmake --build build/mingw-debug --target DetourModKit` after a `src/` change). A new `tests/fault/test_*.cpp` is picked up automatically with no reconfigure.
- **Inject a fault into the FOREIGN target the guard arms, not a write's source.** The MinGW vectored guard confines its claim to the range an operation explicitly touches -- the target of a read / walk / in-place write -- and lets a fault outside it reach the host (so a genuine out-of-range bug is not swallowed). A guarded write's SOURCE span is caller-owned and trusted: a faulting source is a caller-contract violation, uncontained on MinGW (MSVC's whole-copy `__try` catches it only incidentally), so a source-fault test crashes rather than failing closed. This is also why the escalating write slow-path copy-fault arm is not deterministic single-threaded -- once the slow path has made the target writable, only a concurrent reprotect can fault the copy.
- **A `VmtHook` restores the object's vptr in its destructor,** so declare the handle AFTER the target it clones (`auto target = ...; VmtHook vh = ...`) so reverse-order destruction restores the vptr first, and clear any global the detour reaches (for example a live `VmtHook*`) before the handle drops.
- **White-box internal suites** (`test_x86_decode` over `src/x86_decode.hpp`, `test_input_intercept` over `src/internal/input_intercept.hpp`) add `src/` to their include path and call `DetourModKit::detail::` directly.

Full per-suite coverage and test architecture live in [docs/tests/README.md](docs/tests/README.md); topic guides (scanning, RTTI, hot-reload, memory) are indexed in the [documentation index](docs/README.md).

## Git workflow

- **Commit messages:** Conventional Commits format -- `type(scope): description`.
  - Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`.
  - Scopes: module names (`logger`, `scanner`, `hook`, `input`, `memory`, `config`, `filesystem`). Omit scope for cross-cutting changes.
  - Examples: `feat(input): add XInput gamepad support`, `fix(memory): resolve data race in cache`, `perf(logger): lock-free async hot path`.
- **Branch:** `main` is the default and PR target branch.
- **PRs:** Squash merge preferred. Title follows the same conventional commit format.

## Architecture notes

### Module dependencies

- `config` depends on `input`, never the reverse: the combo fusions (`press_combo` / `hold_combo` / `reload_hotkey`) live in `config` and drive `input`'s binding API, so `input` never includes `config`.

### Thread safety model

| Module | Thread safety | Hot-path mechanism |
|--------|--------------|-------------------|
| scan | Stateless -- inherently safe; the internal batch scanner (`scan_regions_batch` / `scan_module_batch`) shares immutable `EnginePattern`s read-only across a transient fork-join worker pool (no per-pattern mutation; `compile_anchor()` must precede the batch), and `scan::resolve_batch` shares caller-owned candidate ladders read-only while dispatching each request through the existing serial resolver. Both write each result slot from one worker via an atomic cursor and join before returning | N/A (startup only; the batch scanner and batch resolver are setup/control-plane, never callback-safe) |
| hook (free functions + RAII Hook/VmtHook) | No central registry. Each `Hook` pins a refcounted per-hook call gate (a `std::recursive_mutex` plus the currently-callable trampoline, published under that mutex) that `call()` copies into a strong reference BEFORE locking, so `enable()` / `disable()` / `~Hook` / `operator=(Hook&&)` can run concurrently with a guarded call without freeing the trampoline under it: a late caller that only pinned the gate before teardown reads a null callable and fails closed instead of dispatching through a freed trampoline. `enable()`/`disable()` drive an atomic CAS status machine and publish/clear the gate's callable under the gate mutex. A process-wide `src/internal/hook_ledger.hpp` (a small mutex over target/vptr sets, not a public registry) backs exact duplicate detection (`fail_if_already_hooked`) via an atomic check-and-reserve (`try_reserve_hook`, committed only after backend create and fallible setup succeed, rolled back on any create failure) and layered-same-target teardown-order tracking; same-target backend creates proceed through the ledger's pending queue in reservation order so permissive layering cannot patch concurrently or invert the trampoline chain. `VmtHook` serializes object-vptr create/apply/remove/teardown transitions through a setup-time object gate, with per-method state still protected by its SRWLOCK. The destructor applies the loader-lock leaf discipline: under the loader lock it pins the module and `record_intentional_leak`s instead of restoring | N/A (install/teardown is setup/control-plane; `call()` is serialized by the per-hook gate mutex, and the handle's own storage must outlive a concurrent call) |
| Logger | `atomic<shared_ptr>` for lock-free async reads; `shutdown_internal` and `disable_async_mode` are safe across repeated shutdown / enable_async_mode cycles: when the writer thread has to be detached under loader lock, the module is pinned and the `shared_ptr<AsyncLogger>` is moved into a per-call permanent cell (normal path: `new (std::nothrow)`; fallback path: non-CRT permanent storage), so a heap allocation failure cannot drop the last handle while the writer may still be running | Single atomic load on log level check |
| AsyncLogger | Lock-free MPMC queue (Vyukov-style); post-join drain on shutdown (at most one message per producer can be lost in the nanosecond race between drain and force-zero -- accepted trade-off to avoid atomic overhead on every enqueue); a producer wakes a parked writer through a seq_cst pending-count/flag handshake (`m_pending_messages` is made non-zero before the queue slot is published, the writer publishes `m_writer_waiting` before checking that count and blocking, and the producer notifies under `m_flush_mutex` only when the flag is set), so the busy-writer hot path stays lock-free and syscall-free yet a push can never strand a message until the flush-interval timeout; timestamp caching in write batches | Atomic sequence numbers per slot; flag-gated writer wakeup |
| input::Input | `mutex` for lifecycle, `atomic<shared_ptr<detail::InputPoller>>` for reads | `atomic<shared_ptr<detail::InputPoller>>` acquire-load, then the engine's `shared_lock` + relaxed load (not lock-free) |
| detail::InputPoller (internal `src/internal/input_poller.hpp`, white-box-tested) | Atomic `m_active_states[]` array; the poll thread re-reserves its deferred-callback staging vector to the live binding count each cycle and stages it under a catch, so a runtime binding growth past the startup reserve cannot reallocate-then-throw out of the `jthread` body; a failed callback batch is dropped, not fatal | `shared_lock` (uncontended SRWLOCK reader) guarding the `m_active_states` pointer swap + `memory_order_relaxed` load per binding; keyboard/mouse reads route through a poll-thread-private per-cycle `KeyStateCache` so each distinct VK gets one coherent `GetAsyncKeyState` sample per cycle, not one call per binding reference |
| InputIntercept (internal `src/internal/input_intercept.*`) | File-scope atomics shared between the poll thread and the game's threads (XInput callers, window message thread); owns its safetyhook InlineHooks directly (not via a DMK Hook handle) because the poll thread reads the trampoline and the hook lifetime is coupled to the poll thread; consume-until-release latch and wheel-pulse state are poll-thread-private; teardown skipped under loader lock (detours left installed against the pinned module) | Lock-free atomic loads in each detour; allocation-free, non-throwing detour bodies |
| Memory cache | Sharded `SRWLOCK` + epoch-based shutdown. Each shard is `alignas(64)` with its `SrwSharedMutex` and stampede `in_flight` flag stored inline (no per-shard heap allocation, so the shard array is a fixed-size `unique_ptr<CacheShard[]>` that never relocates), keeping one shard's lock word and flag off another shard's cache line. Reader liveness is tracked in cache-line-padded per-thread stripes summed at shutdown rather than one global counter, so concurrent readers do not re-serialize on a single line; the seq_cst stripe increment still Dekker-pairs with the `s_cache_initialized` load so the shutdown drain is exact | Shared reader locks per shard; one striped reader-count increment per call |
| config | `mutex` for registration; deferred setter invocation outside lock (no reentrancy guard needed -- setters may call back into config); `reload()` re-runs the registered items against the stashed INI path using the same deferred pattern and short-circuits on FNV-1a 64 hash match of the on-disk bytes to skip no-op reloads; bytes are read once per load/reload and fed to `CSimpleIniA::LoadData`, so the cached hash and the parsed INI state are guaranteed to reflect the same file snapshot (no TOCTOU between hash and parse); `enable_auto_reload()` owns the internal `detail::ConfigWatcher` (`src/internal/config_watcher.hpp`) behind a separate `std::mutex` so start/stop transitions do not contend with registration traffic; setters invoked by the watcher run on the watcher thread, setters invoked by the reload hotkey run on a dedicated `ReloadServicer` thread (lazily started on first `reload_hotkey`, torn down in `clear()`) so the `input::Input` poll thread never blocks on INI parsing; the servicer's press-request path takes its internal `m_mutex` around the predicate store before `cv.notify_one` to close the lost-wakeup window; all setters must be reentrant and thread-safe. The folded-in watcher is one `StoppableWorker`: it opens the parent directory with `FILE_FLAG_BACKUP_SEMANTICS` and `FILE_FLAG_OVERLAPPED`, then pumps `ReadDirectoryChangesW` via `GetOverlappedResultEx` with a 100 ms timeout so `stop_token` is observed promptly; on stop the in-flight read is cancelled and drained with a bounded, escalating wait (timed `GetOverlappedResultEx`, then directory-handle close to force the orphaned IRP to complete, then leak the heap-bundled I/O buffer if completion still cannot be confirmed) so a deleted watched directory cannot hang teardown; debounce uses `steady_clock`; filename match is case-insensitive; `enable_auto_reload()` / `disable_auto_reload()` are idempotent and serialized by an internal `std::mutex`; under loader lock the watcher destructor pins the module, requests stop on the worker, and moves `Impl` into a per-call heap cell allocated via `new (std::nothrow)` (with a `release()` fallback on OOM that leaks the raw pointer instead of running `~Impl`) so the noexcept destructor stays honest, mirroring the `Logger::shutdown_internal` discipline. The hold-combo `input::BindingGuard` owns a per-binding `HoldGate` (`src/internal/input_hold_gate.hpp`) whose `recursive_mutex` serializes the poll-thread callback wrapper against the control-plane `release()`, so a cancelled hold delivers exactly one balancing `on_state_change(false)` and never a stale `true` after it (a re-entrant self-release from inside the callback recurses without deadlock and defers its balancing edge to the wrapper's unwind) | N/A (startup only; 100 ms `GetOverlappedResultEx` watcher pump, idle CPU ~0) |
| EventDispatcher | `emit()` / `emit_safe()` with no user-visible mutex on the read path via `std::atomic<std::shared_ptr<const std::vector<Entry>>>` snapshot (copy-on-write publish, acquire-load on read); zero-subscriber fast path skips the snapshot load via an atomic handler counter; writers serialize on a small `std::mutex` that never touches the emit hot path; thread-local reentrancy guard rejects subscribe/unsubscribe from within handlers so the no-mutation-during-emit invariant holds; `emit()` propagates handler exceptions, `emit_safe()` catches and skips them | Atomic acquire-load of a `shared_ptr` snapshot plus linear iteration over a contiguous vector; no reader lock |
| Profiler | Lock-free ring buffer via atomic `fetch_add` on write position; odd/even sequence counter per sample slot prevents torn reads during concurrent export: `record()` opens and closes the slot with unconditional `fetch_add` (never a load-then-store) so concurrent producers racing on the same slot cannot roll the counter backwards, and the cold export path is a seqlock reader (load the sequence, copy the fields into locals, re-load the sequence behind an acquire fence, and drop the sample if it changed or is odd); `DMK_PROFILE_SCOPE(name)` requires `name` to be a string literal, enforced at compile time by a `ScopedProfile` constructor that only binds to `const char (&)[N]` | Single atomic increment + sequence-guarded field writes per sample |

### Performance-critical paths

These are called at 60+ fps from game hook callbacks. Never add allocations, exclusive locks, or blocking I/O to them. Some entries take an uncontended SRWLOCK shared (reader) lock; that is cheap, non-blocking among readers, and syscall-free, so it is the one tolerated synchronization on these paths -- do not escalate it to an exclusive lock or add new locking:

- `detail::InputPoller::is_binding_active(index)` -- `shared_lock` (uncontended SRWLOCK reader, guards the `m_active_states` pointer swap on reshape) + single `memory_order_relaxed` load
- `detail::InputPoller::is_binding_active(name)` -- `shared_lock` + hash lookup + `memory_order_relaxed` load per matching binding (typically 1-3)
- `detail::InputPoller::is_binding_active(token)` -- `shared_lock` + generation compare + `memory_order_relaxed` load per cached binding index (no name hash); a stale token (generation mismatch after a reshape) fails closed before any index read. `acquire_binding_token(name)` itself is setup/control-plane (it copies the index set and may allocate); mint once, query per frame
- `Logger::log()` level check -- single atomic load
- `Logger::log()` async enqueue -- atomic shared_ptr load + lock-free queue push
- `memory::is_readable(Region)` -- sharded SRWLOCK reader + cache lookup
- `memory::is_readable_nonblocking(Region)` -- try_lock_shared + cache lookup (returns Unknown on lock contention, a cache miss, or the init-publication window; falls back to a blocking VirtualQuery before `init_cache()`)
- `memory::read<std::uintptr_t>(addr)` -- SEH-protected raw dereference (MSVC), vectored-handler-guarded read on MinGW (no per-call VirtualQuery; the fault guard also closes the stale-cache dereference)
- `memory::unchecked::read<std::uintptr_t>(addr)` -- inline pointer dereference with source and result user-mode range guards (a low-address floor plus a `USERSPACE_PTR_MAX` ceiling that rejects kernel-range and non-canonical values, which also subsumes pointer-arithmetic wraparound), no SEH (caller must guarantee structural pointer validity); debug builds add an `is_readable` assert that catches a stale or unmapped source pointer, compiled out in release so the hot path stays a single guarded memcpy
- `memory::read<T>()` / `read_into()` -- typed and raw SEH-guarded reads; single `__try` frame on MSVC, and on MinGW a single `rep movsb` copy under a process-wide vectored exception handler (installed lazily / by `init_cache`, removed by `shutdown_cache`) that recovers via a non-unwinding `__builtin_setjmp`/`__builtin_longjmp`, so the success path runs no syscall. Both toolchains swallow the same foreign-read fault set -- `EXCEPTION_ACCESS_VIOLATION`, `STATUS_GUARD_PAGE_VIOLATION`, and `EXCEPTION_IN_PAGE_ERROR` (a file-backed or image-mapped page failing to page in, e.g. during an RTTI / section walk) -- via the shared predicate `memory::detail::is_guarded_read_fault`, and let any other fault continue the handler search; the MinGW handler additionally claims only faults whose address lies in the foreign range being read. A guarded read uses a single per-thread guard, so it must not nest on one thread (DMK reads are synchronous, so it does not); if `AddVectoredExceptionHandler` ever fails the byte-copy reads fall back to VirtualQuery plus ReadProcessMemory, while bulk region scans fail closed. Used by `rtti` for chained RTTI walks
- `memory::walk(base, {offsets})` -- resolves a whole multi-level pointer chain under one fault guard: one out-of-line call instead of N separate `read` calls, with each intermediate link kept in a register and pre-screened by `is_plausible_ptr` (a faulting or implausible link aborts the walk and reports the failing hop index in `Error::detail`). On MinGW each link read is guarded by the vectored handler
- `memory::write_in_place<T>()` -- the guarded per-frame WRITE to game memory (a camera transform, a player field): it changes no protection and fails closed (`WriteFaulted`) if the target is not already writable. `memory::write<T>()` / `write_bytes()` are the escalating counterpart that auto-unprotect on a fault (a write to a read-only page succeeds), for a one-shot code patch; hold a `memory::ProtectGuard` for repeated writes to a protected page. MSVC guards with one `__try` frame, MinGW x64 with the vectored-handler copy path (fallback through VirtualQuery plus WriteProcessMemory), returning `Result<void>` so a stale address fails closed instead of faulting the host
- `memory::is_plausible_ptr(Address)` -- `inline constexpr` user-mode pointer plausibility test; pure arithmetic with no syscall and no memory access (early-rejects stale/sentinel/torn pointers before an SEH-guarded read)
- `Region::contains(Address)` -- constexpr point-in-range test for module bounds checks
- `Region::own()` / `Region::host()` -- setup/control-plane, not a per-frame path: a loader handle lookup plus a shared-lock hit in the per-handle module-range cache (the first call walks the PE headers and caches the image span; later calls skip the walk)
- `rtti::vtable_is_type(vt, expected)` -- one batched COL read (24 bytes) plus `expected.size() + 1` bytes of name comparison; no allocation
- `rtti::find_in_pointer_table(..., vtable_cache)` warm-cache path (the cache is a caller-owned `std::atomic<Address>`) -- single qword compare per slot, no RTTI walk
- `rtti::TypeIdentity::matches(vtable)` after first resolve -- single qword compare, no RTTI walk (the reverse `vtable_for_type` scan is init-time only, run once and cached)
- `Logger::is_enabled()` -- single atomic load (gate expensive trace-only work)

## Boundaries

- **Do not modify** files under `external/` -- these are git submodules.
- **Do not add** heap allocations on hot paths (see list above).
- **Do not break** the lock ordering documented in class headers.
- **Do not weaken** atomic memory orderings without proving correctness.
- **Do not** let a keyed cache's read-side key derivation diverge from its store-side key. A direct-lookup cache hits only when the key computed on read equals the key an entry was stored under. The protection cache stores an entry by its VirtualQuery region base but a read derives the query's page base, so the direct `unordered_map` probe hits only for an address in a region's first page. A deeper-page query misses that probe and is served by the O(log n) containment search over the *same shard's* `sorted_ranges` when the region is already cached there, otherwise it misses entirely and the caller re-queries via `VirtualQuery`, seeding that shard (see `find_in_shard` and `check_memory_permission`). When adding or changing a keyed cache, keep the two key derivations equal, or document the fallback as the real path instead of advertising an O(1) fast path.
- **Do not skip** running the test suite before committing.
- **Do not publish** release packages before debug tests, release builds, and installed-package smoke tests pass for both MinGW and MSVC.
- **Do not tag** a release whose version differs from `CMakeLists.txt` `project(VERSION ...)`. The release version is single-sourced from there: the generated `DetourModKitConfigVersion.cmake` and the `DMK_VERSION_*` macros derive from it, so a tag that disagrees would ship a package whose `find_package` version check and `DMK_VERSION_AT_LEAST` contradict the tag. The `validate-version` job in `.github/workflows/release.yml` fails closed when the dispatch `version` input does not match, and also cross-checks the one literal version assertion in `tests/test_version.cpp` (`VersionTest.MacrosMatchProjectVersion`) against `project(VERSION)`, so a bump that forgets that test is caught at validate time rather than only at `ctest`. Bump both `project(VERSION)` and the test literal together.
- **Do not add** Windows API calls without `#ifdef _WIN32` guards in headers (implementation files are Windows-only, but headers should remain clean).
- **Do not commit** build artifacts, `.exe`, `.a`, `.lib`, `.obj`, or `.pdb` files.
- **Do not remove** or weaken existing tests. Add new tests for new code.
- **Do not expose** implementation-only container or entry types as top-level public API in public headers -- place them in `namespace detail` (e.g. `detail::VmtHookEntry`, and the async-logger `detail::StringPool` / `detail::LogMessage` / `detail::DynamicMPMCQueue` in the non-installed `src/internal/async_logger_queue.hpp`) or an internal header so they stay out of the documented API surface. A third-party backend type that a public signature would otherwise name is pimpl'd behind a forward-declared `Impl` whose definition lives in a non-installed `src/internal/` header included only by the owning `.cpp` (the SafetyHook objects behind `src/internal/hook_backend.hpp`); a backend value the API must hand to a callback is surfaced as an opaque pass-through type plus free accessors (`hook::MidContext` with `gpr()` / `stack_pointer()` / `instruction_pointer()` / `xmm()`), never by leaking the backend type into the header.
- **Do not use** `std::endl` -- use `'\n'`. `std::endl` forces a flush.
- **Do not use** `EventDispatcher::emit()` from hook callbacks -- use `emit_safe()` instead to prevent unhandled handler exceptions from crashing the host process.
- **Do not tear down** layered same-target hooks oldest-first -- destroy newest-first (natural reverse-order destruction of stack / member handles does this). `disable()` writes a hook's saved prologue back over the target, and a hook created on an already-hooked address saved a jump to the older detour as its prologue, so restoring oldest-first rewrites the entry into the older hook's freed trampoline (a use-after-free). `src/internal/hook_ledger.hpp` tracks per-target install order and flags an out-of-order release. Reverse-order destruction is automatic for stack locals and array / aggregate members, but a `std::vector<Hook>` (or any container) destroys its elements oldest-first (forward), so code that holds layered same-target handles in a container and relies on dropping the container for rollback must tear them down back-to-front (`pop_back`) or use a commit-on-success transaction -- never rely on `~vector` (this is the `install_all` rollback trap, fixed by its internal `InstallRollback` guard).
- **Do not return** from a memory-writing helper before its post-write cache maintenance (instruction-cache flush and cache-range invalidation) once bytes have been modified -- run the cleanup on every exit path, even when a later step such as restoring page protection fails.
- **Do not let** a public doc comment describe behavior the implementation no longer has -- lifecycle and ordering claims must match the code, and are best pinned by a test.
- **Do not key** a cache store and its invalidation/eviction by different addresses or shard-selection functions. Eviction must use the same canonical key and the same containment lookup as insertion and read, or entries silently survive invalidation (see `memory::invalidate_range`, which scans every shard because storage is sharded by query address, not region base).
- **Do not let** a queue or backlog fed at an external event rate grow without bound -- clamp the pending count to a documented ceiling (the poll-thread pulse backlog `MAX_WHEEL_PENDING`), and saturate the raw event counter at its write site too (`MAX_WHEEL_NOTCHES`). A subclass/detour that keeps counting after its consumer stops draining (the WndProc wheel counter once the last wheel binding is gone) would otherwise wrap a signed int -- bound it where it is written, not only where it is drained, so a stalled or absent drainer cannot make it overflow.
- **Do not suppress** an intercepted input with a single global on/off flag when the binding that owns it is a chord -- gate suppression by the specific owned key/direction and its live modifier state, published fresh each poll cycle behind a time-to-live, so an unrelated input still reaches the game and a stalled poll thread self-heals. The per-direction wheel-consume mask (`publish_wheel_consume`) and the gamepad reactive mask both work this way: a `Ctrl+WheelUp` consume binding masks only the Up direction while Ctrl is held, never a bare WheelDown.
- **Do not let** an async/deferred sink diverge from its synchronous counterpart's configuration (timestamp format, level, etc.) -- carry the same settings through, as `Logger::enable_async_mode` does for the timestamp format.
- **Do not open** a shared append-mode file with `GENERIC_WRITE` plus a one-time `SetFilePointer(FILE_END)` seek -- request `FILE_APPEND_DATA` so the OS positions every write at the current end of file atomically and concurrent appenders cannot interleave or overwrite each other (see `WinFileStreamBuf::open`). Truncating (`out`) mode keeps `GENERIC_WRITE` + `CREATE_ALWAYS`.
- **Do not assume** a single `WriteFile` drains the whole request -- it can report success with `bytes_written < count` (a short write on a pipe, a near-full volume, or an interrupted write). Loop over the unwritten remainder so a buffered tail is never silently dropped, resetting the put area only after the buffer fully drains or the write hard-fails (see `WinFileStreamBuf::flush_buffer`).
- **Do not drop** the device source when formatting an off-table input code -- a non-keyboard code must serialize in the source-tagged hex form (`Mouse:0xNN`) that `parse_input_name` reads back, or it silently round-trips to a keyboard key (see `format_input_code` / `parse_input_name`). The two off-table forms reconstruct through different readers: a source-tagged token round-trips through `parse_input_name`, but a bare-hex keyboard token (`0xNN`) round-trips only through the config combo parser behind `config::bind_combos` (whose untagged-hex fallback defaults to Keyboard). `parse_input_name` returns `nullopt` for a bare-hex token by design, so a doc or test that names the keyboard round-trip must name the config parser, not `parse_input_name`.
- **Do not report** a uniqueness or single-reference verdict as final when a page-gated or fault-guarded sweep skipped a window that faulted mid-scan. A skipped window makes any occurrence count a lower bound -- a hidden match (a duplicate string literal, a second cross-reference) could live in the unread bytes -- so a would-be-unique result must fail closed to ambiguous. Every `detail::MatchResult` consumer that gates on uniqueness honors `incomplete` this way (`scan()`, `scan_resolution`, `scan_matching`, `scan_prologue_recovery`), and `find_string_xref` maps `incomplete` (phase-1 readable sweep) and any faulted phase-2 window to `StringAmbiguous` / `AmbiguousReference` at all three of its uniqueness gates. The intentional exception is the batch scanners, which are first-occurrence finders with no uniqueness contract. A new uniqueness path over guarded memory must thread and honor the same faulted-window signal.
- **Do not** add a new 32-bit fallback arm or a second architecture guard to the scan / hook / memory engines. The library targets x86-64 (Win64) only, enforced by the single `#error` gate in `defines.hpp` (`DMK_ARCH_X64`): a 32-bit or non-x86 configure fails immediately with one clear message, before the pointer-width / ABI-layout `static_assert`s in the x86 decoder (`x86_decode.hpp`) and RTTI layout (`rtti_internal.hpp`) would cascade as opaque backstops. New guarded code follows the scanner fault guards (page-scan, string-xref): only the MSVC-SEH and MinGW-x64-VEH arms, no 32-bit `#else`, so architecture dependence rides on the global gate rather than a local `static_assert`. (`memory_guarded.cpp` still carries a pre-gate 32-bit MinGW degraded arm that the global gate now makes unreachable -- a cleanup candidate, not a pattern to extend.)
- **Do not destroy** an inline-hook object while a game thread may still be executing its detour body -- the detour reads through the trampoline the hook owns, so freeing it mid-call is a use-after-free. Retire the published trampoline pointer first, wrap the detour body in an in-flight counter, and drain it (bounded) before teardown, off the loader lock, after the thread that installed the hook is joined (`input_intercept::uninstall` clears the XInput trampoline pointers, then drains `s_xinput_inflight` before destroying the hooks). The drain is bounded so a thread wedged in the game's own code cannot hang teardown; safetyhook's own mid-prologue relocation covers that residual instant, so the counter shrinks the window rather than replacing that mechanism.
- **Do not detach-and-leak** a thread that keeps executing library code without first pinning the module. Every loader-lock teardown path that leaks a worker instead of joining it (`StoppableWorker::shutdown`, `~ConfigWatcher`, the logger, the memory cache, the XInput poller, and `bootstrap_detach`'s explicit-`FreeLibrary`-under-loader-lock branch) calls `detail::pin_current_module()` before the leak. A consumer's `FreeLibrary` can drop the module refcount to zero and unmap the DLL while the leaked thread is still running code in its `.text`; a `GET_MODULE_HANDLE_EX_FLAG_PIN` reference holds the mapping alive for the rest of the process. Clearing a data pointer (e.g. `s_module`) does not cover the code pages the thread runs -- pin first, then leak.
- **Do not complete** an RAII unsubscribe / removal synchronously when the dispatcher being removed from is already in-flight on the current thread -- rebuilding the published handler snapshot mid-emit breaks the no-mutation-during-emit invariant the in-flight iteration relies on. Queue that removal on the dispatcher and drain it when *that dispatcher's own* emit unwinds (`EventDispatcher::drain_pending_removals`, driven by each `EmitGuard` on its own `owner`, gated by a lock-free `m_has_pending_removals` flag). Do NOT gate the drain on a shared per-thread emit-depth reaching zero: `emitting_depth()` is shared across every same-type dispatcher on the thread, so a depth==0 gate drains whichever instance owns the outermost emit and strands a nested same-type instance's queued removals (a re-fire, or a use-after-free if the handler destroyed its owner). Also do NOT defer a removal for dispatcher B merely because dispatcher A of the same event type is currently emitting on the same thread; B has no active guard to drain that queue, so the removal must run immediately. A reentrancy guard that merely *rejects* the removal and leans on a later out-of-emit retry leaves the handler firing on subsequent emits. Keep the retry path only as a best-effort fallback for when the deferred drain cannot allocate.
- **Do not use** a function-local (Meyers) singleton for state reachable *after* its own static destruction -- a late destructor or callback (for example `Profiler::get_instance()` from `~ScopedProfile` on a static / thread_local scope, or on a thread still live at teardown) would dereference the freed object. Construct such a teardown-surviving singleton with placement-new into never-destroyed static storage so its destructor never runs and the object outlives every late caller (`StringPool::instance()`, `Profiler::get_instance()`); the bounded storage is reclaimed by the OS at process exit.
- **Do not run** a patch-fragile feature on drift telemetry you only logged -- gate it. `anchor::evaluate_gate` rolls a resolved-anchor report (or its `AnchorQuality` summary) into a `GateVerdict` (Pass / Degraded / Fail) under a `GatePolicy` that defaults to fail-closed (every resolvable anchor must heal, zero failures). Safe-disable a feature on `Fail` rather than patching the game on addresses the manifest could not verify, and treat `Degraded` (a resolved-but-pinned `Manual` literal, or nothing assessable) as enable-with-caution. Per-feature gating falls out of resolving only that feature's anchors into their own report, so one primitive serves both a whole-manifest health check and a per-feature kill switch. The unsupported `CallArgHome` kind is excluded from the ratio denominator so declaring a forward-compatible kind never drags a healthy manifest below threshold; a `QuorumNotIndependent` outcome counts as a hard failure (it committed no value).
- **Corroborate a critical target by N-of-M voting, not a single signal, and never let dependent evidence pass for corroboration.** An `anchor::AnchorKind::Quorum` lists `M` sub-anchors in `quorum_members` and accepts only when at least `N` (`quorum_threshold`; `0` means unanimous) resolve and agree; a member that fails to resolve casts no vote rather than vetoing, so the target survives a patch that breaks some signals as long as `N` of the rest still agree. Enforce the invariants fail-closed: at least two members, no null member and no nested `Quorum` (recursion is bounded to one level), an effective `N` in `[2, M]` (a quorum is corroboration, so `N` is never 1), and -- critically -- EVERY pair of members must be independent evidence (`quorum_members_pairwise_independent`: not the same object, not two `Manual` literals, not the same backend + inputs by view/span identity). The all-pairs independence gate is what confines a `WithinTolerance` vote -- whose members need only be near, not equal -- to content-independent anchors, so a near-value cluster can never be an artifact of two members decoding adjacent bytes of one site. Fold the member evidence order-independently (sorted) plus the threshold, match mode, and tolerance into `anchor_fingerprint` so a changed corroboration contract is a fingerprint diff.
- **Ship a patch-fragile contract as editable data, not just code.** The `manifest` module turns a resolved anchor plus its consumer binding (register / offset chain / vtable slot) into a serializable `SignatureRecord`, so a class-2 (the AOB bytes shifted) or class-3 (the value moved `rcx -> rax`, or a field moved `+0x1C8 -> +0x1D0`) breakage after a game patch is a text edit to a `.signatures.ini`, not a recompiled DLL. Keep the owning/borrowing split the scan surface uses: a `Signature` owns its compiled `scan::Candidate` ladder and rebuilds an `anchor::Anchor` view on demand (never caches one), the same discipline as `OwnedScanRequest::view`, so no stored view dangles across a move. `manifest::overlay` merges file overrides over in-code `anchor::Anchor` defaults by label and is fail-soft like `config::bind` (a malformed override falls back to the in-code default rather than dropping the feature); `manifest::resolve_and_gate` then partitions the merged set into trusted vs safe-disabled by resolve status, fingerprint drift (a rewritten signature is distrusted even when something still resolves at the address -- the worst failure mode is a silent wrong-register/offset read, so it must safe-disable, not act), and a whole-manifest health floor, carrying the `anchor::evaluate_gate` fail-safe intent onto the file-loaded surface. The composite `Quorum` / `CallArgHome` anchor kinds are not file-serializable (a Quorum composes its M voting sub-anchors by pointer); they stay in-code and gate through `anchor::evaluate_gate`. The INI keeps each candidate rung in its own ordered `[sig.<label>.rung.<N>]` sub-section rather than inlining the first rung, so a section-level key never doubles as both an anchor field and a candidate field and round-trip stays mechanical. The optional `[manifest] revision` is the author's signature-contract epoch, separate from `schema` (the file-format version DetourModKit parses) and from the per-signature fingerprint gate (which only sees changes to the located game code). A consumer gates the file through `manifest::revision_compatible(header, BUILD_REVISION)`, treating a stale or unversioned file as no overrides so a renamed label or a re-meaning of a binding is a manifest bump, not a silent misread; bump `BUILD_REVISION` only on a breaking in-code change, so a routine mod update keeps still-valid repair files working.
- **Lint a patch-fragile signature offline before it ships, not only at runtime.** The `sighealth` module grades a `scan::Pattern` / `manifest::SignatureRecord` / `manifest::Manifest` from its declarative bytes alone (no process, no game) on three axes: atom rarity (the longest fully-known run and whether its bytes are rare, reusing the scan engine's `detail::byte_frequency_class` so the offline estimate anchors on the same rarity model the prefilter uses), byte entropy (a repetitive run is long but low-information), and expected ambiguity (`nominal_haystack_bytes * 2^(-selectivity_bits)`, an order-of-magnitude estimate of false matches, never a promise). It returns a `Grade` (Robust / Fragile / Unusable) plus `Finding`s naming each weakness. A record grades by its STRONGEST rung (the resolver tries the ladder until one resolves uniquely, so the record is as strong as its best tier); a manifest grades by its WEAKEST record (each signature gates its own feature). It is a pre-flight lint only: health never gates behavior -- the runtime resolver still verifies uniqueness and fails closed -- it just catches a brittle signature earlier. Keep the byte-rarity model single-sourced in `detail::byte_frequency_class`; do not fork a second frequency table for the offline estimate.
