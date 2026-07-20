# DetourModKit

[![Coverage Report ≥ 80%](https://github.com/tkhquang/DetourModKit/actions/workflows/coverage-pages.yml/badge.svg)](https://tkhquang.github.io/DetourModKit/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Features](#features) | [Building](#building-detourmodkit-static-library-via-cmake) | [Testing](#running-unit-tests) | [Guides](#guides) | [Integration](#using-detourmodkit-in-your-mod-project) | [Example](#code-example)

DetourModKit is a full-featured C++23 toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, input handling, configuration management, and DLL lifecycle orchestration. It targets Windows x64 and builds under both MSVC 2022+ and MinGW (GCC 13+).

## Features

DetourModKit is organized into focused modules. Each module's full API is documented in its own header's Doxygen comments (the source of truth); expand any module below for a capability summary and its header, and task-oriented guides live in the [documentation index](docs/README.md).

### Foundation

<details>
<summary><b>Core Vocabulary</b> - typed <strong>Address</strong> / <strong>Region</strong> values, <strong>Prot</strong> flags, and the <strong>Result&lt;T&gt;</strong> error idiom</summary>

The shared value vocabulary every other DetourModKit module speaks, so a location, span, or failure is never a bare integer or a per-subsystem enum. `Address` is a pointer-wide strong type with constexpr `offset` / `align_up` arithmetic and the `rip` displacement resolver plus the audited `as<T>` / `ptr<T>` casts; `Region` folds a base and size into scope factories (`host`, `own`, `module_named`, `whole_process`) and offers `contains` and `sub`. `Prot` composes read/write/execute flags (`RW`, `RWX`), and every fallible call returns `Result<T>` carrying an `ErrorCode`-tagged `Error`, propagated with `DMK_TRY` / `DMK_TRY_VOID`.

Header: [`address.hpp`](include/DetourModKit/address.hpp), [`region.hpp`](include/DetourModKit/region.hpp), [`error.hpp`](include/DetourModKit/error.hpp), [`defines.hpp`](include/DetourModKit/defines.hpp)
</details>

### Find, read & patch game code

<details>
<summary><b>AOB Scanner</b> - pattern matching and candidate ladders that resolve signatures to live addresses</summary>

Locates a target in process memory from an update-resilient byte signature and turns that evidence into a confident absolute address. A value-semantic `Pattern` (built by `compile` or `literal`, with wildcards, per-nibble masks, and bounded jumps `[X-Y]`) feeds a `Candidate` ladder assembled from the `direct`, `rip_relative`, `rtti_vtable`, and `string_xref` factories; `resolve` and `resolve_batch` try each tier until one resolves uniquely, with an optional fail-closed `FallbackPolicy` identity gate for hooked-prologue recovery. Page-gated `scan`, the standalone `find_string_xref` / `read_code_constant` / `resolve_rip_relative` resolvers, and raw `unchecked::find_pattern` round out the surface over a runtime-selected SIMD engine.

Header: [`scan.hpp`](include/DetourModKit/scan.hpp)
</details>

<details>
<summary><b>Memory Utilities</b> - fault-guarded reads/writes, pointer-chain walks, and page-protection guards</summary>

Touches live process memory without crashing the host: a faulting access -- an unmapped page, a guard page, or a pointer reprotected out from under you -- becomes a `Result` error instead of terminating. Guarded `read` / `read_into` and `write` / `write_bytes` / `write_in_place` do typed and byte-span transfers, `walk` resolves multi-level pointer chains (one `ChainStep` per hop) capturing every intermediate, and the RAII `ProtectGuard` holds a `Region` writable so repeated patches stay on the cheap path. `is_plausible_ptr`, the sharded-cache `is_readable` / `is_writable` predicates, and `module_of` / `is_module_loaded` answer setup-time validation questions, with `unchecked::read` as the raw fast path.

Header: [`memory.hpp`](include/DetourModKit/memory.hpp)
</details>

<details>
<summary><b>Hook</b> - free verbs returning move-only RAII <strong>Hook</strong> / <strong>VmtHook</strong> handles, backend hidden</summary>

Installs and owns inline, mid-function, and vtable detours whose lifetime is bound to the RAII handle you hold rather than to a hidden registry. The free verbs `inline_at`, `mid_at`, the declarative `install_all` (each row carries its own install `Options`), and `vmt_for` return move-only `Hook` / `VmtHook` handles; a `Hook` exposes `enable`, `disable`, the typed `original` trampoline and its guarded `call` twin (`try_call` returns a `Result` so a suppressed call is distinguishable from a genuine value-initialized return), while `VmtHook` adds `apply_to`, `hook_method`, and `remove_method`. `HookStack` guarantees newest-first teardown of layered hooks, and a mid-hook detour reads the captured register file through an opaque `MidContext`, so the SafetyHook backend never leaks into your headers.

Header: [`hook.hpp`](include/DetourModKit/hook.hpp)
</details>

<details>
<summary><b>MSVC RTTI Walker</b> - recover mangled type names from live vtables without <strong>typeid</strong></summary>

Recovers the MSVC RTTI mangled type name for the object behind a runtime vtable, walking the COL/TypeDescriptor ABI directly without `typeid` or `dynamic_cast` so it works across DLL boundaries. Forward calls -- `type_name_of`, the zero-allocation `type_name_into`, the exact-match `vtable_is_type`, and the `find_in_pointer_table` slot scan -- take a caller-owned vtable cache; `vtable_for_type` and `vtables_for_type` run the reverse name-to-vtable resolve. `region_has_rtti` probes whether a module carries any records at all, and `TypeIdentity::matches` caches a per-frame identity check that survives a patch relocating the vtable.

Header: [`rtti.hpp`](include/DetourModKit/rtti.hpp)
</details>

<details>
<summary><b>RTTI Self-Heal</b> - reverse-identify a pointer's object and self-heal field offsets after a patch</summary>

Reverse-resolves the RTTI type of the object a pointer slot refers to, then recovers a struct field's offset after a game patch shifts the layout. `identify_pointee_type` is the per-slot primitive and `reverse_scan_block` RTTI-labels a whole struct; `heal_landmark` finds where one typed field moved, while `solve_fingerprint` recovers the single uniform delta that fits several co-moved fields at once. A frame-driven `HealScheduler` (drive `add_group` then `tick`) latches each group once it resolves, and `serialize_drift_report` / `parse_drift_report` persist a diffable drift manifest across game versions.

Header: [`rtti_dissect.hpp`](include/DetourModKit/rtti_dissect.hpp), [`detail/drift_manifest.hpp`](include/DetourModKit/detail/drift_manifest.hpp)
</details>

### Keep signatures alive across patches

<details>
<summary><b>Anchor Registry</b> - one declarative table over the self-healing backends with a startup drift gate</summary>

Collapses a mod's wall of patch-fragile constants -- vtable literals, AOB/RIP globals, code operands, string xrefs, named exports (via the module Export Address Table), pinned values -- into one declarative `Anchor` table, each entry tagged with an `AnchorKind` and resolved through the self-healing backend that fits. `resolve_all` (or `resolve_all_parallel`) writes a `ResolvedAnchor` drift report; `AnchorKind::Quorum` corroborates a target by N-of-M voting, an optional `AnchorValidator` fails a suspect value closed, and `anchor_fingerprint` yields an address-independent diff key. `assess_quality` and `evaluate_gate` roll the report into a `GateVerdict` that safe-disables a feature when anchor quality drops below threshold.

Header: [`anchor.hpp`](include/DetourModKit/anchor.hpp)
</details>

<details>
<summary><b>Signature Manifest</b> - the resolved contract as serializable data, gated trusted vs safe-disabled</summary>

Turns a mod's patch-fragile signature contracts into editable, serializable data, so a game update is repaired by a text edit instead of a recompiled DLL. A `SignatureRecord` bundles an anchor's locate half with a consumer `Binding` (`BindingKind::Address`, `PointerChain`, `MidHookRegister`, or `VmtMethod`); `parse` / `serialize` and `load` / `save` round-trip it through a versioned INI, and `overlay` merges file overrides onto in-code defaults by label. `Signature::compile` and `resolve_and_gate` then resolve each contract and partition it into trusted `GatedSignature`s versus safe-disabled ones, so a drifted signature disables its feature rather than acting on a wrong address.

Header: [`manifest.hpp`](include/DetourModKit/manifest.hpp)
</details>

<details>
<summary><b>Offline Signature Health</b> - statically grade a pattern, record, or manifest with no game running</summary>

Grades a signature's robustness statically, from its declarative bytes alone, so a brittle anchor is caught at authoring time or in a CI lane rather than in a bug report after the next game patch. `analyze_pattern`, `analyze_candidate`, `analyze_record`, and `analyze_manifest` score atom rarity, byte entropy, and expected ambiguity against a tunable `HealthPolicy`, yielding a `Grade` (`Robust` / `Fragile` / `Unusable`) plus a list of `Finding` values (`FindingKind`, `Severity`) naming exactly what is weak. `format_report` renders any level as a human-readable lint report. Everything is side-effect-free: it touches no process memory and needs no game running.

Header: [`sighealth.hpp`](include/DetourModKit/sighealth.hpp)
</details>

### Runtime subsystems

<details>
<summary><b>Input System</b> - background-polled hotkey and gamepad combos with opt-in suppression</summary>

Monitors keyboard, mouse, gamepad, and mouse-wheel combos on a single background poll thread owned by `Input::instance()`. Describe a binding with a `ComboBinding` (its `Trigger::Press` or `Trigger::Hold` edge model and `consume` suppression opt-in), register it through `register_combo` (or the free `input::register_combo`) to receive a move-only `BindingGuard`, batch guards in a `Scope`, and launch polling with `Input::instance().start()`. Query state with `is_active`, or resolve an `acquire_token` `BindingToken` for a per-frame hot path; `rebind`, `set_consume`, and `set_require_focus` reshape live bindings, while `parse_input_name` / `format_input_code` map names to codes. Same-frame gamepad suppression comes from a fixed-size table, so `consume_capacity` reports how many chord shapes that table currently holds.

Header: [`input.hpp`](include/DetourModKit/input.hpp), [`input_codes.hpp`](include/DetourModKit/input_codes.hpp)
</details>

<details>
<summary><b>Configuration</b> - INI binding registry with key-combo fusions and fail-soft hot-reload</summary>

Binds INI keys to atomics, callbacks, and the logger, then loads and hot-reloads the file, all fail-soft: a missing or malformed key falls back to its registered default and is logged, never surfaced as an error. Register scalars and lists with `bind` / `bind_int` / `bind_bool` / `bind_string` / `bind_combos` / `bind_parsed`, fuse an INI key straight to a live input binding via `press_combo` / `hold_combo` / `consume_flag`, and add a reload key with `reload_hotkey`. `load` applies the file (and re-points an active watcher if it names a different file), `reload` re-applies it (concurrent reloads are serialized so a slower stale pass cannot pin outdated values), and `enable_auto_reload` / `disable_auto_reload` drive the folded-in watcher; `SectionBinder` and the `Ini` handle drop the repeated section argument.

Header: [`config.hpp`](include/DetourModKit/config.hpp)
</details>

<details>
<summary><b>Logger</b> - value-facade logger with compile-checked format strings and opt-in async writes</summary>

A constructible value facade rather than a singleton: the free `log()` returns the process-default `Logger`, so the common path reads `log().info(...)`, with `trace` / `debug` / `warning` / `error` and the variadic `log` / `try_log` forms all taking a `LocatedFormat` that auto-stamps `[file:line]` and validates the format string at compile time. `Logger::configure` publishes the process default, `set_log_level` and the `LogLevel` enum filter records before formatting, and `enable_async_mode` (tuned by `AsyncLoggerConfig` and its `OverflowPolicy`) hands writes to a lock-free bounded queue drained by a batched writer thread. `log_noexcept` and `try_log` are the fail-soft, noexcept-boundary forms for hook callbacks.

Header: [`logger.hpp`](include/DetourModKit/logger.hpp)
</details>

### Process lifecycle

<details>
<summary><b>Session and Bootstrap</b> - RAII process lifetime with ordered teardown and DllMain scaffolding</summary>

Owns a mod's entire process lifetime and its correctly ordered teardown from one place. `Session::start(ModInfo)` is the synchronous path (running the process gate, single-instance mutex, and logger configuration named in `ModInfo`), while `bootstrap(info, on_ready)` is the DllMain path that hands the `Session` to a worker thread running off the loader lock; pair it with `bootstrap_detach` in `DLL_PROCESS_DETACH` and `request_shutdown` to drain cleanly before `FreeLibrary`. Reach subsystems through `session.ini()`, `.log()`, `.input()`, and `.scope()`; `abandon`, `module_handle`, and `on_logic_dll_unload` handle the process-termination and hot-reload edge cases.

Header: [`DetourModKit.hpp`](include/DetourModKit.hpp)
</details>

<details>
<summary><b>Stoppable Worker</b> - RAII named <strong>std::jthread</strong> wrapper with loader-lock-safe teardown</summary>

An RAII-owned, named background thread built on `std::jthread` for polling or watcher loops that must shut down cleanly. Construct a `StoppableWorker` with a name and a body invocable that receives a `std::stop_token` and polls it cooperatively; the destructor requests stop and joins automatically. Call `request_stop()` to signal, `shutdown()` to stop and join eagerly, and query `is_running()` or `name()`. Under the Windows loader lock, teardown detaches instead of joining to avoid deadlock. The type is non-copyable and non-movable.

Header: [`detail/worker.hpp`](include/DetourModKit/detail/worker.hpp)
</details>

### Observability & messaging

<details>
<summary><b>Diagnostics</b> - leak counters, scanner-fault and hook-lifecycle event buses, and a Snapshot</summary>

Surfaces DMK's internal health without scraping logs. `record_intentional_leak` and `intentional_leak_count` tally the loader-lock-safe leak/detach paths per `LeakSubsystem`, while `scanner_faults()` and `hook_lifecycle()` return never-destroyed per-linked-instance `EventDispatcher`s streaming `ScannerFaultEvent` (regions skipped mid-scan) and `HookLifecycleEvent` (`HookKind`, `HookTransition`) transitions. `collect` rolls all of it -- plus a caller-supplied drift report and anchor report -- into one plain-value `Snapshot` (leak counts, live hook population, drift healed/failed, anchor quality) that re-resolves nothing, so you run it from init, a worker, or a diagnostics command.

Header: [`diagnostics.hpp`](include/DetourModKit/diagnostics.hpp)
</details>

<details>
<summary><b>Profiler</b> - scoped timing to a lock-free ring buffer, Chrome-Tracing export, zero-cost when off</summary>

Measures hook and subsystem timing with zero overhead when disabled: the `DMK_PROFILE_SCOPE` and `DMK_PROFILE_FUNCTION` macros compile to nothing unless `DMK_ENABLE_PROFILING` is defined. When enabled, each `ScopedProfile` records a sample into the singleton `Profiler`'s lock-free ring buffer on scope exit; steady-state recording does not allocate and is safe from any thread. Retrieve results through `Profiler::get_instance()` and `export_to_file` or `export_chrome_json`, producing Chrome Trace Event JSON you open in chrome://tracing or Perfetto. `total_samples_recorded`, `available_samples`, and `dropped_samples` report buffer state, and `reset` clears it between sessions. A record whose slot is still owned by another writer is dropped and counted rather than overwriting it, so an export never carries a torn sample; if the ring cannot be allocated at first use, the profiler publishes a disabled instance (`capacity() == 0`) that counts records as drops and exports an empty trace instead of terminating.

Header: [`profiler.hpp`](include/DetourModKit/profiler.hpp)
</details>

<details>
<summary><b>Event Dispatcher</b> - typed pub/sub with RAII auto-unsubscribe and a callback-safe emit path</summary>

A typed publish/subscribe channel for decoupling subsystems: one `EventDispatcher<Event>` per event type, emitted to from hook callbacks and other threads. `subscribe` returns a move-only RAII `Subscription` that auto-unsubscribes on destruction; `emit` invokes every handler synchronously, and `emit_safe` swallows handler exceptions so an unhandled throw cannot crash the host. The read path takes no reader lock of yours -- a zero-subscriber emit is wait-free, and subscribers are held in a copy-on-write snapshot -- so emitting stays callback-safe. `subscriber_count`, `empty`, and `clear` round out the surface.

Header: [`detail/event_dispatcher.hpp`](include/DetourModKit/detail/event_dispatcher.hpp)
</details>

### Small utilities

<details>
<summary><b>Format Utilities</b> - header-only <strong>std::format</strong> helpers for addresses, bytes, and VK codes</summary>

Turns raw modding values into readable, log-friendly hex strings. The `format` namespace offers `format_address` for pointers, overloaded `format_hex` for signed, unsigned, and `ptrdiff_t` inputs, `format_byte` for single bytes, and `format_vkcode` / `format_vkcode_list` / `format_int_vector` for key codes and integer lists. The separate `string::trim` strips leading and trailing whitespace. Every function is header-only and `[[nodiscard]]`, built on `std::format`.

Header: [`format.hpp`](include/DetourModKit/format.hpp)
</details>

<details>
<summary><b>Filesystem Utilities</b> - cached module-directory resolution with wide-string and UTF-8 APIs</summary>

Resolves the on-disk directory of the currently loaded module (DLL or EXE) so a mod can locate its own config and asset files regardless of the game's working directory. Call `get_runtime_directory()` for a wide-string path that preserves full Unicode fidelity, or `get_runtime_directory_utf8()` for a UTF-8 encoding of the same path. Both results are cached after first resolution, making repeat calls allocation-free, and both fall back gracefully if module detection fails.

Header: [`filesystem.hpp`](include/DetourModKit/filesystem.hpp)
</details>

<details>
<summary><b>Math Utilities</b> - header-only <strong>constexpr</strong> <strong>noexcept</strong> angle conversions</summary>

A minimal, header-only pair of angle conversions for camera, FOV, and rotation math. `degrees_to_radians` and `radians_to_degrees` are both `constexpr` and `noexcept`, operating on `float` and backed by `std::numbers::pi_v`, so they fold to constants at compile time when given constant inputs and add no runtime cost when they cannot.

Header: [`math.hpp`](include/DetourModKit/math.hpp)
</details>

<details>
<summary><b>Version Macros</b> - compile-time version macros generated from CMake</summary>

Lets a mod assert the DetourModKit version it was built against at compile time. CMake generates `version.hpp` from the template, defining `DMK_VERSION_MAJOR`, `DMK_VERSION_MINOR`, `DMK_VERSION_PATCH`, and the human-readable `DMK_VERSION_STRING`. `DMK_MAKE_VERSION` packs a major.minor.patch triple into one comparable integer (also exposed as `DMK_VERSION`), and `DMK_VERSION_AT_LEAST(major, minor, patch)` guards feature use behind an `#if` for a minimum required version.

Header: [`version.hpp`](include/DetourModKit/version.hpp.in)
</details>

## Test Suite

- **Comprehensive Test Suite:** Full unit test coverage for all modules using GoogleTest.
- **Code Coverage:** Automated coverage analysis with 80% minimum line coverage gate in CI.
- **Coverage Tools:** Built-in scripts for parsing and analyzing coverage reports.

For detailed coverage analysis and test architecture, see the [Test Coverage Guide](docs/tests/README.md).

## Guides

New to DetourModKit? [The Minimal Core](docs/guides/minimal-core.md) walks the five-header core set and the shortest path from process attach to reading, patching, and hooking game code. Task-oriented guides live in the [documentation index](docs/README.md): AOB signature scanning, hooking, the MSVC RTTI walker and self-heal, hot-path memory, and the two-DLL hot-reload workflow. Upgrading from v3.x? See [Migrating from v3.x to v4.0.0](docs/migration/migrating-v3-to-v4.md).

## Prerequisites

- A C++ compiler **and standard library** supporting C++23 (e.g., MinGW g++ 13+ or MSVC 2022 17.4+). The
  library needs `std::expected`, `std::move_only_function`, and `std::format`; g++ 13 is the first GCC with all
  three, and configure probes for them and fails early on an older standard library.
- [CMake](https://cmake.org/) 3.28 or newer.
- [Ninja](https://ninja-build.org/) build system (ships with Visual Studio; for MSYS2: `pacman -S ninja`).
- `make` (optional, for the Makefile wrapper -- e.g., `mingw32-make` for MinGW environments).
- Git (for cloning and managing submodules).

## Building DetourModKit (Static Library via CMake)

This project uses CMake with [CMake Presets](https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html) and Ninja to orchestrate its build. A thin Makefile wrapper is provided for convenience.

1. **Clone the repository (with submodules):**

    ```bash
    git clone --recursive https://github.com/tkhquang/DetourModKit.git
    cd DetourModKit
    ```

    If you've already cloned without `--recursive`:

    ```bash
    git submodule update --init --recursive
    ```

    To update submodules to the latest upstream version (when not pinned to a specific commit):

    ```bash
    git submodule update --init --recursive --remote
    ```

2. **Build & Package for Distribution:**

   ### Using the Makefile wrapper (Recommended)

    ```bash
    # Build the library (MinGW Release by default)
    make

    # Install to build/install/
    make install

    # Build with a different preset
    make PRESET=msvc-release
    make install PRESET=msvc-release
    ```

   ### Using CMake presets directly

    ```bash
    # MinGW
    cmake --preset mingw-release
    cmake --build --preset mingw-release --parallel
    cmake --install build/mingw-release --prefix ./install_package/mingw

    # MSVC (run from a Visual Studio Developer Command Prompt)
    cmake --preset msvc-release
    cmake --build --preset msvc-release --parallel
    cmake --install build/msvc-release --prefix ./install_package/msvc
    ```

   ### Available presets

    | Preset | Compiler | Build Type | Tests | Notes |
    | --- | --- | --- | --- | --- |
    | `mingw-debug` | GCC (MinGW) | Debug | ON | |
    | `mingw-debug-coverage` | GCC (MinGW) | Debug | ON | gcov coverage |
    | `mingw-release` | GCC (MinGW) | Release | OFF | |
    | `msvc-debug` | MSVC (cl) | Debug | ON | |
    | `msvc-debug-asan` | MSVC (cl) | Debug | ON | AddressSanitizer (the only sanitizer on Windows) |
    | `msvc-release` | MSVC (cl) | Release | OFF | |

   ### Installed package smoke test

    ```bash
    cmake -S tests/package_smoke -B build/package-smoke-mingw -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DDetourModKit_DIR="$PWD/install_package/mingw/lib/cmake/DetourModKit" \
        -DCMAKE_CXX_COMPILER=g++
    cmake --build build/package-smoke-mingw --parallel
    ctest --test-dir build/package-smoke-mingw --output-on-failure
    ```

    The package smoke project includes the installed headers, links the
    installed `DetourModKit::DetourModKit` target, touches `hook::is_target_hooked`, and runs a full `Session::start` / `~Session` cycle so the static dependency chain is pulled into the consumer link.

> [!NOTE]
> Standalone Release builds default to portable, non-LTO archives. Dead code elimination still applies (`/Gy /Gw` on MSVC, `-ffunction-sections -fdata-sections` with `--gc-sections` on GCC/Clang), and `--gc-sections` propagates to consumers via INTERFACE linkage so unused DetourModKit symbols are stripped at final link time. `DMK_ENABLE_LTO` defaults ON only when DetourModKit is pulled in with `add_subdirectory`, where the consumer recompiles the library with the same toolchain; a standalone installed archive should keep it OFF unless the package deliberately documents the exact toolchain match. MinGW Release builds keep CMake's default `-O3`; only the hand-tuned SIMD scan engine TU is downgraded per-source to `-O2`, because `-O3`'s aggressive unrolling regresses its hand-optimized verifier. MSVC builds embed CodeView debug info (`/Z7`) in every config so a static archive carries its own symbols.

---

> [!TIP]
> You can create a `CMakeUserPresets.json` file (git-ignored) to define your own local presets that inherit from the ones above.

   After running the install command, the install directory (`build/install/` for the Makefile wrapper, or whichever `--prefix` you passed to `cmake --install`) will contain:

    ```text
    <install_prefix>/
    ├── include/
    │   ├── DetourModKit.hpp       <-- Umbrella header; include this for the whole kit
    │   ├── DetourModKit/          <-- Public module headers (one per module in the Features list above)
    │   │   └── detail/            <-- Installed compile-visible support; never included directly
    │   └── DirectXMath/           <-- Re-exported by default (-DDMK_INSTALL_DIRECTXMATH=OFF omits); no safetyhook headers
    ├── lib/
    │   ├── libDetourModKit.a      <-- Static library (.a for MinGW, .lib for MSVC)
    │   └── libsafetyhook.a, ...   <-- Backend archives (Zydis, Zycore) for the transitive link only; headers not installed
    └── lib/cmake/DetourModKit/    <-- find_package(DetourModKit) config files
    ```

    Every public header maps to an entry in the [Features](#features) list above, which carries the per-module
    description and a link to the header itself (whose Doxygen comments are the source of truth).

## Running Unit Tests

DetourModKit includes a comprehensive unit test suite using GoogleTest. The debug presets (`mingw-debug`, `msvc-debug`) have tests enabled by default.

### Using the Makefile wrapper

```bash
# Build and run tests (MinGW by default)
make test

# Run tests with MSVC (requires VS Developer Command Prompt)
make test_msvc

# Clean all build directories
make clean
```

### Using CMake presets for tests

```bash
# MinGW
cmake --preset mingw-debug
cmake --build --preset mingw-debug --parallel
ctest --preset mingw-debug

# MSVC
cmake --preset msvc-debug
cmake --build --preset msvc-debug --parallel
ctest --preset msvc-debug
```

### Running host-safety proofs only

Fault-containment fixtures, loader lifecycle hosts, and the CTest timeout control are CMake-owned targets outside the monolithic unit-test executable. The fault and lifecycle behavior proofs are MinGW-specific; the timeout control runs on both toolchains.

```bash
cmake --preset mingw-debug
cmake --build build/mingw-debug --target fault_tests bootstrap_module_ref profiler_late_uaf dmk_timeout_probe --parallel 4
ctest --test-dir build/mingw-debug -L "fault-proof|lifecycle-proof|timeout-control" --output-on-failure
```

The compatibility wrappers build and run the same labelled cases:

```bash
bash scripts/run_fault_tests.sh
bash scripts/run_lifecycle_proofs.sh
```

The wrappers select the MinGW runtime beside the compiler recorded in the build tree, so another MinGW installation earlier on `PATH` cannot supply an incompatible runtime DLL.

> [!TIP]
> If the MSVC build is failing due to a PDB file locking issue, kill stale compiler processes:
>
> ```bash
> taskkill /F /IM cl.exe 2>nul || echo No cl.exe processes found
> ```

### Warnings as Errors

To treat compiler warnings as errors (enabled by default in CI):

```bash
cmake --preset mingw-debug -DDMK_WARNINGS_AS_ERRORS=ON
cmake --build --preset mingw-debug --parallel
```

### Enabling Profiling

To enable the opt-in profiler instrumentation (`DMK_PROFILE_SCOPE` / `DMK_PROFILE_FUNCTION` macros):

```bash
cmake --preset mingw-debug -DDMK_ENABLE_PROFILING=ON
cmake --build --preset mingw-debug --parallel
```

When `DMK_ENABLE_PROFILING` is OFF (the default), all profiling macros expand to `((void)0)` with zero overhead. The `Profiler` class and `ScopedProfile` are still compiled into the library (so tests always work), but the macros that instrument user code are no-ops.

### Enabling the AVX-512 verify tier

The scanner ships an opt-in AVX-512F + AVX-512BW pattern-verification tier (64 bytes per iteration), off by default:

```bash
cmake --preset mingw-debug -DDMK_ENABLE_AVX512=ON
cmake --build --preset mingw-debug --parallel
```

When `DMK_ENABLE_AVX512` is OFF (the default) the tier compiles out entirely. When ON, the AVX-512 intrinsics are confined to that single function via a per-function `target` attribute (no global `/arch:AVX512` or `-mavx512`), so the rest of the library keeps its AVX2 baseline and the produced binary still runs on CPUs without AVX-512: the tier is selected only when a runtime `CPUID` + `XGETBV` check confirms both the CPU and OS support AVX-512F and AVX-512BW, otherwise the scanner falls back to AVX2. `scan::active_simd_level()` reports the tier actually in use. The tier's `>= 30%` throughput gate is hardware-specific and can only be measured on a real AVX-512 host. Per-tier correctness (including AVX-512) runs under Intel SDE on every push to main via `.github/workflows/simd-tier-correctness.yml`.

### Enabling Sanitizers

AddressSanitizer is available on Windows through **MSVC only**. GCC and Clang on mingw-w64 ship no ASan/UBSan runtime for the Windows target, so a MinGW sanitizer build cannot link here; UndefinedBehaviorSanitizer is not available on Windows.

```bash
# AddressSanitizer via MSVC -- run from a Developer Command Prompt.
cmake --preset msvc-debug-asan
cmake --build --preset msvc-debug-asan --parallel
ctest --preset msvc-debug-asan
```

> [!NOTE]
> MSVC ASan needs `clang_rt.asan_dynamic-x86_64.dll` on `PATH` at run time; a Developer Command Prompt (or `Enter-VsDevShell`) provides it. ASan only -- there is no UBSan or LeakSanitizer on MSVC. The GCC/Clang `-fsanitize=address,undefined` path only links where the runtimes exist (a Linux toolchain), which does not apply to this Windows-only library. Setting `DMK_ENABLE_SANITIZERS=ON` under a non-MSVC Windows toolchain (e.g. MinGW) fails fast at configure time with a `FATAL_ERROR` pointing to the MSVC route.

### Enabling Code Coverage

To generate code coverage reports (requires GCC/Clang), pass the coverage option when configuring:

```bash
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
cmake --build --preset mingw-debug --parallel
```

All pull requests to `main` are automatically tested via CI with an **80% minimum line coverage** gate. See the [PR Check workflow](.github/workflows/pr-check.yml) for details. The latest coverage report is published to [GitHub Pages](https://tkhquang.github.io/DetourModKit/) on every push to `main`.

## Using DetourModKit in Your Mod Project

There are two main approaches to integrate DetourModKit into your project:

> **ABI / toolchain compatibility (read this first).** DetourModKit is a C++23 **static** library whose entire public surface is C++ -- there is no `extern "C"` boundary anywhere. The archive bakes in the compiler's name mangling, its exception model, and the exact layout of every standard-library type that crosses the API (`std::string`, `std::vector`, `std::expected`, `std::move_only_function`, and the containers inside `Result<T>`). None of that is stable across toolchains, so link DetourModKit only from a build that matches on every axis:
>
> - **Same compiler family and ABI.** MinGW-GCC and MSVC archives are not interchangeable; a release is compiler-specific by construction. Rebuild from source (Method 1) if you switch compilers.
> - **Same C++ standard library, at C++23 or newer.** The library requires `<expected>`, `std::move_only_function`, and `<format>`; the CMake configure step probes for these and fails early with a clear message if the standard library is too old.
> - **Matching CRT / iterator-debug settings on MSVC.** `_ITERATOR_DEBUG_LEVEL` and the `/MD` vs `/MDd` runtime must agree with the archive. A mismatch changes container layout and shows up as `LNK2038` at best, or silent ODR undefined behaviour at worst. (This is why the shipped Debug preset pins `_ITERATOR_DEBUG_LEVEL=0`.)
>
> There is no ABI shim: consume the package from the same toolchain that produced it.

### Method 1: Using DetourModKit as a Submodule (Recommended)

This method is ideal for active development and ensures you always have the latest compatible version.

1. **Add DetourModKit as a submodule:**

    ```bash
    # In your project root
    git submodule add https://github.com/tkhquang/DetourModKit.git external/DetourModKit
    git submodule update --init --recursive
    ```

    To pin a specific release version:

    ```bash
    cd external/DetourModKit
    git checkout v4.0.0          # or an earlier release tag, e.g. v3.9.0
    cd ../..
    git add external/DetourModKit
    git commit -m "pin DetourModKit to v4.0.0"
    ```

    To upgrade to a newer version later:

    ```bash
    cd external/DetourModKit
    git fetch --tags
    git checkout v4.1.0          # desired version
    cd ../..
    git add external/DetourModKit
    git commit -m "upgrade DetourModKit to v4.1.0"
    ```

2. **Configure your CMakeLists.txt:**

    ```cmake
    cmake_minimum_required(VERSION 3.28)
    project(MyMod VERSION 1.0.0 LANGUAGES CXX)

    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    # Add DetourModKit as subdirectory
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/DetourModKit/CMakeLists.txt")
      message(STATUS "Configuring DetourModKit from: external/DetourModKit")
      add_subdirectory(external/DetourModKit)

      if(TARGET DetourModKit)
        set(DETOURMODKIT_TARGET DetourModKit)
        message(STATUS "DetourModKit target found: ${DETOURMODKIT_TARGET}")
      else()
        message(FATAL_ERROR "DetourModKit target not created by subdirectory")
      endif()
    else()
      message(FATAL_ERROR "DetourModKit not found at 'external/DetourModKit'. "
        "Please ensure the submodule is initialized: "
        "'git submodule update --init --recursive'")
    endif()

    # Create your mod target
    add_library(MyMod SHARED src/main.cpp)

    # Link against DetourModKit (all dependencies are transitively linked).
    # user32 and xinput1_4 propagate automatically via DetourModKit's INTERFACE linkage.
    target_link_libraries(MyMod PRIVATE DetourModKit)

    # Add any extra system libraries your own mod code needs (Windows)
    if(WIN32)
        target_link_libraries(MyMod PRIVATE psapi kernel32)
    endif()
    ```

3. **In your GitHub Actions workflow (if using CI):**

    ```yaml
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        submodules: "recursive"  # This ensures DetourModKit is pulled
    ```

### Method 2: Using Pre-built DetourModKit Package

This method uses a pre-built and installed version of DetourModKit.

1. **Download a release package:**

    Pre-built packages for MinGW and MSVC are available on the [Releases](https://github.com/tkhquang/DetourModKit/releases) page. Download the zip matching your toolchain and version (e.g., `DetourModKit_MinGW_v4.0.0.zip` or `DetourModKit_MSVC_v4.0.0.zip`).

    > **Toolchain match.** A pre-built static archive is compiled objects, so its toolchain must be compatible with yours. The release archives are built **without** link-time optimization (no MSVC `/GL` LTCG IL, no GCC LTO GIMPLE), so they are portable within each toolchain family rather than pinned to one exact toolset:
    >
    > - **MSVC zip:** linkable by any Visual Studio 2015--2022 toolset (v140--v143). Shipping non-LTO objects is what keeps this true -- an LTCG (`/GL`) archive would be excluded from that binary-compatibility guarantee and fail a differing toolset with `C1047`/`LNK1257`. Match the CRT (`/MD` Release, `/MDd` Debug), which DetourModKit's exported target already drives.
    > - **MinGW zip:** built with a specific GCC major (the release toolchain, currently GCC 13.x). Link it with a **compatible GCC major**; libstdc++ ABI can differ across majors, so a far-newer or far-older g++ may not link cleanly. If your GCC major differs, build DetourModKit from source instead (Method 1).
    >
    > If you build DetourModKit yourself and want cross-translation-unit optimization in a from-source consumer build, opt in with `-DDMK_ENABLE_LTO=ON` (default OFF for a standalone/installed build so the archive stays portable; default ON when DetourModKit is pulled in via `add_subdirectory`, where the consumer recompiles it anyway).

    To upgrade, download the newer release zip and replace the contents of your `external/DetourModKit/` directory.

2. **Integrate DetourModKit:**
    - Extract the downloaded zip into your mod project (e.g., into an `external/DetourModKit/` subdirectory).
    - Alternatively, build from source and run `cmake --install` to produce the same directory layout (see [Building](#building-detourmodkit-static-library-via-cmake)).

3. **Configure Your Mod's Build System:**

   #### CMake

    ```cmake
    # In your mod's CMakeLists.txt
    cmake_minimum_required(VERSION 3.28)
    project(MyMod)

    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    # Find DetourModKit
    set(DetourModKit_DIR "external/DetourModKit/lib/cmake/DetourModKit")
    find_package(DetourModKit REQUIRED)

    # Create your mod target
    add_library(MyMod SHARED src/main.cpp)

    # Link against DetourModKit.
    # user32 and xinput1_4 propagate automatically via DetourModKit's INTERFACE linkage. An MSVC Debug consumer also
    # inherits the _ITERATOR_DEBUG_LEVEL=0 pin the library is built with, so a /MDd Debug build links without the
    # _ITERATOR_DEBUG_LEVEL LNK2038 mismatch -- no manual definition required.
    target_link_libraries(MyMod PRIVATE DetourModKit::DetourModKit)

    # Add any extra system libraries your own mod code needs (Windows)
    if(WIN32)
        target_link_libraries(MyMod PRIVATE psapi kernel32)
    endif()
    ```

   #### Makefile (Example for g++ MinGW)

    ```makefile
    # In your mod's Makefile
    DETOURMODKIT_DIR := external/DetourModKit

    CXXFLAGS += -I$(DETOURMODKIT_DIR)/include
    LDFLAGS += -L$(DETOURMODKIT_DIR)/lib
    LIBS += -lDetourModKit -lsafetyhook -lZydis -lZycore
    # Add system libs: -luser32 -lxinput1_4 are required by DetourModKit.
    # Add -lpsapi -lkernel32 etc. if your own mod code uses them.
    LIBS += -luser32 -lxinput1_4 -static-libgcc -static-libstdc++

    # Example link command:
    # $(CXX) $(YOUR_OBJECTS) -o YourMod.asi -shared $(LDFLAGS) $(LIBS)
    ```

## Code Example

> **The `dmk` / `DMK` namespace aliases:** the umbrella `<DetourModKit.hpp>` and most module headers pull in both `namespace dmk = DetourModKit` and `namespace DMK = DetourModKit` (defined in `defines.hpp`), so mod code can write `dmk::hook`, `dmk::scan`, `dmk::config`, `dmk::Logger`, and so on in place of the fully spelled `DetourModKit::`. A few self-contained headers (`logger.hpp`, `format.hpp`, `filesystem.hpp`, `math.hpp`, `input_codes.hpp`, `profiler.hpp`, `async_logger_config.hpp`) do not include `defines.hpp`, so include it (or the umbrella) yourself if you use the aliases with only those. They are the same alias in two casings; the examples below use `dmk`. Pick one and stay consistent, or ignore both and use the fully qualified `DetourModKit::` names. There is no flat `DMKConfig` / `DMKSession` alias set; the only global-namespace names DetourModKit publishes are the two namespace aliases `dmk` and `DMK` themselves. If either collides with a name your own code already owns -- or you simply prefer the full `DetourModKit::` spelling -- define `DMK_NO_NAMESPACE_ALIASES` before the first DetourModKit include and both aliases are suppressed, while the primary `DetourModKit` namespace stays available so nothing else changes.

<details>
<summary>Show the full example mod (<strong>MyMod/src/main.cpp</strong>)</summary>

```cpp
// MyMod/src/main.cpp
#include <windows.h>
#include <Psapi.h>

#include <optional>   // the RAII Hook handle is stored in an std::optional global

// Single include for all DetourModKit functionality (umbrella + Session / bootstrap lifecycle)
#include <DetourModKit.hpp>

// The v4 hooking surface lives in hook.hpp (pulled in by the umbrella above): hook::inline_at / mid_at install a hook
// and hand back a move-only RAII DetourModKit::hook::Hook whose destructor restores the prologue. A mid-hook detour
// takes an opaque DetourModKit::hook::MidContext, so a detour body no longer needs SafetyHook on the include path.
// The backend is confined: SafetyHook's headers are not installed with DetourModKit (only its static archive ships, for
// the transitive link), so `#include <safetyhook.hpp>` is not reachable from a find_package consumer; vendor SafetyHook
// yourself if you must call it directly. SimpleIni is an internal build-time dependency and is likewise NOT installed;
// do not include <SimpleIni.h> from a find_package consumer. Use the DetourModKit::config API for INI access instead.

// Global variables for your mod's configuration
struct ModConfiguration
{
    bool enable_greeting_hook = true;
    std::string log_level_setting = "INFO";
    dmk::input::KeyComboList toggle_combo;
    dmk::input::KeyComboList hold_scroll_combo;
} g_mod_config;

// Example Hook: Target function signature
using OriginalGameFunction_PrintMessage_t = void (__stdcall *)(const char *message, int type);

// The hook is owned by its RAII handle. Hook is move-only with no default constructor, so a global one lives in an
// std::optional that InitializeMyMod engages via std::optional::emplace; dropping it (or letting it leave scope)
// restores the original prologue.
std::optional<dmk::hook::Hook> g_print_hook;

// Detour function
void __stdcall Detour_GameFunction_PrintMessage(const char *message, int type)
{
    auto &logger = dmk::log();
    logger.info("Detour_GameFunction_PrintMessage CALLED! Original message: \"{}\", type: {}", message, type);

    // original<Fn>() is the typed trampoline to the un-hooked function (UNGUARDED fast path). It is non-null only
    // while the hook is engaged; use call<Ret>(args...) instead if a teardown can race this detour.
    const auto call_original =
        g_print_hook ? g_print_hook->original<OriginalGameFunction_PrintMessage_t>() : nullptr;
    if (!call_original)
    {
        return;
    }

    if (g_mod_config.enable_greeting_hook)
    {
        logger.debug("Modifying message because greeting hook is enabled.");
        call_original("Hello from DetourModKit! Hooked!", type + 100);
        return;
    }

    call_original(message, type);
}

// Mod init callback (runs on the bootstrap worker thread, off the loader lock). It receives the live Session and
// returns a Result<void>, so an init failure is a value logged on the worker, never a throw across the loader lock.
dmk::Result<void> InitializeMyMod(dmk::Session &session)
{
    // Logger + async mode are already configured by bootstrap() using the ModInfo passed into the attach call below.
    // session.log() is the same process-default logger dmk::log() returns.
    auto &logger = session.log();

    // Bind your configuration variables (callback-store API; config::bind<T> is the atomic hot path)
    dmk::config::bind_bool("Hooks", "EnableGreetingHook", "Enable Greeting Hook",
        [](bool v) { g_mod_config.enable_greeting_hook = v; }, true);
    dmk::config::bind_string("Debug", "LogLevel", "Log Level",
        [](std::string_view v) { g_mod_config.log_level_setting = std::string{v}; }, "INFO");

    // Bind hotkey combos from INI (modifier+trigger format)
    // Comma separates independent combos: "F3,Gamepad_LT+Gamepad_B" (F3 OR LT+B)
    // Plus separates modifiers from trigger: "Ctrl+Shift+F3" (AND for modifiers, last = trigger)
    // Hex VK codes still work: "0x72", "0x11+0x72"
    // Mouse: "Mouse4", "Ctrl+Mouse1"
    // Gamepad: "Gamepad_A", "Gamepad_LB+Gamepad_A"
    dmk::config::bind_combos("Hotkeys", "ToggleKey", "Toggle Keys",
        [](const dmk::input::KeyComboList &c) { g_mod_config.toggle_combo = c; }, "F3");
    dmk::config::bind_combos("Hotkeys", "HoldScrollKey", "Hold Scroll Keys",
        [](const dmk::input::KeyComboList &c) { g_mod_config.hold_scroll_combo = c; }, "");

    // Load configuration from INI file (after the binds above, so load() applies file values to them). session.ini()
    // is a thin handle to the same process config registry the free config:: functions act on.
    session.ini().load("MyMod.ini");

    // Apply LogLevel from loaded configuration
    logger.set_log_level(dmk::string_to_log_level(g_mod_config.log_level_setting));

    // Log the loaded configuration
    logger.info("MyMod configuration loaded and applied.");
    dmk::config::log_all();

    // Initialize Hooks (v4: free verbs returning a move-only RAII Hook handle).
    // dmk::scan is the alias for DetourModKit::scan (from scan.hpp); dmk::hook for DetourModKit::hook.

    // The hook target is a scan::OwnedScanRequest: hook::inline_at resolves it at install time (resolve-on-install)
    // and never carries a dangling pattern span. The executable page and final-address checks keep the hook target
    // in code even if a byte match or another resolver backend transforms to data. A one-candidate ladder is the
    // simplest form; ship a fallback ladder for a long-lived mod (see the AOB Signature Scanning Guide).
    dmk::scan::OwnedScanRequest target{
        .ladder = {dmk::scan::Candidate::direct("GameFunction_PrintMessage",
                                              dmk::scan::Pattern::literal("48 89 ?? ?? 57"))},
        .label = "GameFunction_PrintMessage",
        .scope = DetourModKit::Region::host(),   // the host EXE; defaults here too
        .pages = dmk::scan::Pages::Executable,
        .require_executable_result = true,
    };

    // inline_at performs the function-to-void* cast internally; the call site writes no reinterpret_cast.
    // Options::prologue defaults to Prologue::Fail: a CC/CD breakpoint prologue is refused with
    // ErrorCode::TargetPrologueUnsafe. Pass Options{.prologue = dmk::hook::Prologue::Relocate} to install anyway.
    // The hook comes back DISABLED: the target is not patched until you call enable() below.
    auto result = dmk::hook::inline_at(
        dmk::hook::InlineRequest{
            .name = "GameFunction_PrintMessage_Hook",
            .target = std::move(target),
        },
        &Detour_GameFunction_PrintMessage);

    if (result.has_value())
    {
        // Take ownership of the RAII handle for the hook's lifetime; dropping it restores the prologue.
        // This ordering is the point of the two-step install: the detour reaches the original through
        // g_print_hook->original<Fn>(), so g_print_hook must be published BEFORE the target is armed. Arming
        // inside inline_at would let the game call the detour while g_print_hook was still empty.
        g_print_hook.emplace(std::move(*result));

        if (auto armed = g_print_hook->enable(); armed.has_value())
        {
            logger.info("Successfully installed hook: {}", g_print_hook->name());
        }
        else
        {
            logger.error("Installed but could not arm hook: {}", armed.error().message());
            g_print_hook.reset();
        }
    }
    else
    {
        logger.error("Failed to install hook: {}", result.error().message());
        return std::unexpected(result.error());
    }

    // Register hotkey bindings with the input system (after hooks are ready).
    // register_combo takes a ComboBinding aggregate carrying the KeyComboList
    // directly. One engine entry is created per combo, all sharing the binding
    // name for OR-logic queries. It returns a Result<BindingGuard>; on success,
    // park the move-only guard in the process-default scope so it lives for the
    // process. (config::press_combo / hold_combo wrap this with INI parsing and
    // hand back the guard directly, no Result to unwrap.)
    if (auto toggle = dmk::input::register_combo({
            .name = "toggle_view",
            .trigger = dmk::input::Trigger::Press,
            .combos = g_mod_config.toggle_combo,
            .on_press = []() { dmk::log().info("Toggle key pressed!"); },
        }))
    {
        // Park the guard in the Session's scope: ~Session clears it first, in reverse insertion order.
        session.scope().add(std::move(*toggle));
    }

    if (auto scroll = dmk::input::register_combo({
            .name = "hold_scroll",
            .trigger = dmk::input::Trigger::Hold,
            .combos = g_mod_config.hold_scroll_combo,
            .on_state_change = [](bool held)
            { dmk::log().info("Hold scroll: {}", held ? "active" : "released"); },
        }))
    {
        session.scope().add(std::move(*scroll));
    }

    // Start the input polling thread (focus-aware by default)
    (void)dmk::input::Input::instance().start();

    logger.info("MyMod Initialized using DetourModKit!");
    return {}; // success
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        dmk::ModInfo info{
            .name = "MyMod",                            // logger prefix + mod identity
            .log_file = "MyMod.log",
            .game_process_name = "MyGame.exe",          // optional -- set "" to disable
            .instance_mutex_prefix = "MyMod_Instance",  // optional -- set "" to disable
        };
        info.log.queue_capacity = 8192;
        info.log.batch_size = 64;

        // bootstrap() spawns the worker, runs InitializeMyMod(session) off the loader lock, and hosts the Session until
        // detach. It returns Result<void>; a failure (process gate / instance mutex / worker spawn) declines the load.
        return dmk::bootstrap(info, &InitializeMyMod).has_value() ? TRUE : FALSE;
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        // Drop caller-owned hooks to restore prologues on an explicit FreeLibrary (lpReserved == NULL). On process exit
        // (lpReserved != NULL) leave them: the OS reclaims a dying process and touching patched pages is a UAF.
        if (lpReserved == nullptr)
        {
            g_print_hook.reset();
        }
        // NULL -> the ordered ~Session teardown; non-NULL -> abandon (do nothing).
        dmk::bootstrap_detach(lpReserved);
    }
    return TRUE;
}
```

</details>

> [!WARNING]
> `dmk::bootstrap()` runs your init callback on a dedicated worker thread, so it executes off the loader lock, and `~Session` runs the ordered teardown there too. The worker holds a counted reference on your module while it runs, so a bare `FreeLibrary` will **not** unload the DLL or fire `DLL_PROCESS_DETACH`. For a dynamic unload, call `dmk::request_shutdown()` (off the loader lock) *before* issuing `FreeLibrary`: the worker drains the ordered teardown, flushes logging, releases its reference via `FreeLibraryAndExitThread`, and only then can the `FreeLibrary` actually unmap the DLL. Drop your caller-owned `Hook` handles during that teardown so prologues are restored while the code pages are still mapped. See the [Hot-Reload Guide](docs/guides/hot-reload/README.md) for the recommended two-DLL architecture.

## Configuration File Example

Create a `MyMod.ini` file alongside your DLL:

<details>
<summary>Show the example <strong>MyMod.ini</strong></summary>

```ini
[Hooks]
EnableGreetingHook=true

[Debug]
LogLevel=INFO

[Hotkeys]
; Named keys (recommended)
ToggleKey=F3                 ; Single key
HoldScrollKey=LShift         ; Left Shift
DebugCombo=Ctrl+Shift+D      ; Ctrl AND Shift AND D (plus = AND for modifiers, last = trigger)

; Multiple independent combos (comma = OR between combos)
DualInput=F3,Gamepad_LT+Gamepad_B     ; F3 alone OR (hold LT + press B)
MultiCombo=Ctrl+F3,Ctrl+F4            ; Ctrl+F3 OR Ctrl+F4

; Mouse buttons
AimToggle=Mouse4             ; Mouse button 4 (side button)
QuickAction=Ctrl+Mouse1      ; Ctrl + Left click

; Gamepad buttons (XInput)
GamepadToggle=Gamepad_A                ; A button
GamepadCombo=Gamepad_LB+Gamepad_A      ; LB (modifier) + A (trigger)
GamepadTrigger=Gamepad_LT              ; Left trigger (digital, configurable deadzone)

; Hex VK codes still supported
LegacyKey=0x72               ; F3 by hex code
LegacyCombo=0x11+0x10+0x44   ; Ctrl+Shift+D by hex codes

; Opt-out sentinels (silent, no warning)
DisabledHotkey=               ; empty value -> binding registered but unbound
AlsoDisabled=NONE             ; literal NONE (case-insensitive) -> same effect
```

</details>

## Supported Input Names

The accepted names are defined in [`input_codes.hpp`](include/DetourModKit/input_codes.hpp); the tables below mirror them for quick reference.

The configuration system recognizes the following named input codes (case-insensitive):

| Category | Names |
| --- | --- |
| **Modifiers** | `Ctrl`, `LCtrl`, `RCtrl`, `Shift`, `LShift`, `RShift`, `Alt`, `LAlt`, `RAlt` |
| **Letters** | `A`-`Z` |
| **Digits** | `0`-`9` |
| **Function keys** | `F1`-`F24` |
| **Navigation** | `Left`, `Right`, `Up`, `Down`, `Home`, `End`, `PageUp`, `PageDown`, `Insert`, `Delete` |
| **Common** | `Space`, `Enter`, `Escape`, `Tab`, `Backspace`, `CapsLock`, `NumLock`, `ScrollLock`, `PrintScreen`, `Pause` |
| **Windows / Menu** | `LWin`, `RWin`, `Apps` (alias `Menu`) |
| **OEM punctuation** | `Semicolon`, `Equals`, `Comma`, `Minus`, `Period`, `Slash`, `Grave` (aliases `Backtick`, `Tilde`; the usual console hotkey), `LBracket`, `Backslash`, `RBracket`, `Apostrophe` (alias `Quote`) |
| **Numpad** | `Numpad0`-`Numpad9`, `NumpadAdd`, `NumpadSubtract`, `NumpadMultiply`, `NumpadDivide`, `NumpadDecimal` |
| **Mouse** | `Mouse1` (left), `Mouse2` (right), `Mouse3` (middle), `Mouse4`, `Mouse5` |
| **Mouse wheel** | `WheelUp`, `WheelDown`, `WheelLeft`, `WheelRight` (trigger-only, Press mode) |
| **Gamepad** | `Gamepad_A`, `Gamepad_B`, `Gamepad_X`, `Gamepad_Y`, `Gamepad_LB`, `Gamepad_RB`, `Gamepad_LT`, `Gamepad_RT`, `Gamepad_Start`, `Gamepad_Back`, `Gamepad_LS`, `Gamepad_RS`, `Gamepad_DpadUp`, `Gamepad_DpadDown`, `Gamepad_DpadLeft`, `Gamepad_DpadRight` |
| **Gamepad sticks** | `Gamepad_LSUp`, `Gamepad_LSDown`, `Gamepad_LSLeft`, `Gamepad_LSRight`, `Gamepad_RSUp`, `Gamepad_RSDown`, `Gamepad_RSLeft`, `Gamepad_RSRight` |

Hex VK codes with `0x` prefix (e.g., `0x72` for F3) are also accepted and default to keyboard input. A code that has no table name but is not a keyboard code is written back to the INI in a source-tagged hex form (`Mouse:0xFE`, `Gamepad:0x800`, `MouseWheel:0x9`) and parsed back to the same device source, so a non-keyboard code survives a config round-trip instead of decaying to a keyboard key.

## Gamepad Compatibility

Gamepad support uses the **XInput** API. The following controllers are supported natively:

| Controller | Supported |
| --- | --- |
| Xbox 360 | Yes (native XInput) |
| Xbox One / Series X\|S | Yes (native XInput) |
| GameSir (XInput mode) | Yes (switch controller to XInput mode) |
| PS4 DualShock 4 | Via [DS4Windows](https://github.com/ds4windowsapp/DS4Windows) or Steam Input |
| PS5 DualSense | Via [DualSenseX](https://github.com/Paliverse/DualSenseX) or Steam Input |
| Nintendo Switch Pro | Via [BetterJoy](https://github.com/Davidobot/BetterJoy) or Steam Input |
| Generic USB gamepads | Only if the controller exposes an XInput interface |

**Why XInput only?** DetourModKit's input system is designed for mod hotkeys and toggles, not for replacing a game's primary input handling. XInput covers Xbox controllers natively, and the vast majority of PC players using non-Xbox controllers already use Steam Input or similar remapping tools that present their controller as XInput. Adding DirectInput or Windows.Gaming.Input would significantly increase complexity for a use case where XInput + keyboard/mouse covers nearly all real users.

**Limitations:**

- Maximum 4 controllers (XInput hard limit, indices 0-3).
- Analog triggers (LT/RT) and thumbstick axes are treated as digital buttons with configurable deadzone thresholds.
- No event-driven hot-plug detection; controller connection is checked via polling (reconnection attempts are throttled to every 2 seconds when disconnected).
- **Shift + Numpad keys:** When Shift is held, Windows translates numpad keys to their navigation equivalents (e.g., `Numpad5` becomes `VK_CLEAR` instead of `VK_NUMPAD5`). This means combos like `LShift+Numpad5` will never fire because `GetAsyncKeyState` sees the translated VK code, not the original numpad code. **Workaround:** use `Ctrl` or `Alt` instead of `Shift` for numpad combos, or use non-numpad keys. ([More info](https://learn.microsoft.com/en-us/answers/questions/3935239/how-to-make-it-so-left-shift-doesnt-affect-number))

## Projects Using DetourModKit

For practical reference and real-world usage examples:

- **OBR-NoCarryWeight**: [https://github.com/tkhquang/OBRTools/tree/main/NoCarryWeight](https://github.com/tkhquang/OBRTools/tree/main/NoCarryWeight)
- **KCD1-TPVToggle**: [https://github.com/tkhquang/KCD1Tools/tree/main/TPVToggle](https://github.com/tkhquang/KCD1Tools/tree/main/TPVToggle)
- **KCD1-TPVCamera**: [https://github.com/tkhquang/KCD1Tools/tree/main/TPVCamera](https://github.com/tkhquang/KCD1Tools/tree/main/TPVCamera)
- **KCD2-TPVToggle**: [https://github.com/tkhquang/KCD2Tools/tree/main/TPVToggle](https://github.com/tkhquang/KCD2Tools/tree/main/TPVToggle)
- **KCD2-TPVCamera**: [https://github.com/tkhquang/KCD2Tools/tree/main/TPVCamera](https://github.com/tkhquang/KCD2Tools/tree/main/TPVCamera)
- **CrimsonDesert-EquipHide**: [https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertEquipHide](https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertEquipHide)
- **CrimsonDesert-LiveTransmog**: [https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertLiveTransmog](https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertLiveTransmog)

## Acknowledgements

DetourModKit incorporates components from other open-source projects. See [DetourModKit_Acknowledgements.txt](DetourModKit_Acknowledgements.txt) for full details.

- [SafetyHook](https://github.com/cursey/safetyhook) (Boost Software License 1.0)
- [SimpleIni](https://github.com/brofield/simpleini) (MIT)
- [DirectXMath](https://github.com/microsoft/DirectXMath) (MIT)
- [Zydis & Zycore](https://github.com/zyantific/zydis) (MIT)

The RTTI self-heal / reverse-dissection design was **inspired by** (no code incorporated) the [CERTTIExplorer](https://github.com/FransBouma/InjectableGenericCameraSystem/tree/master/Tools/CERTTIExplorer) Cheat Engine script ([GhostInTheCamera](https://github.com/ghostinthecamera), with improvements by [Frans Bouma](https://github.com/FransBouma) / Otis_Inf; BSD-2-Clause) and the [FramedSC RTTI guide](https://framedsc.com/GeneralGuides/using_rtti.htm). See [docs/guides/rtti/rtti-self-heal.md](docs/guides/rtti/rtti-self-heal.md#prior-art-and-acknowledgements) for the full credit.
