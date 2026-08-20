# DetourModKit

[![C++23](https://img.shields.io/badge/C%2B%2B-23-f34b7d.svg)](#prerequisites) [![Coverage Report ≥ 80%](https://github.com/tkhquang/DetourModKit/actions/workflows/coverage-pages.yml/badge.svg)](https://tkhquang.github.io/DetourModKit/)

DetourModKit is a C++23 toolkit for Windows game modding. It provides memory scanning, function and vtable hooking, foreign-memory access, input handling, configuration, and DLL lifecycle management. It targets Windows x64 and builds under MSVC 2022+ and MinGW GCC 14+.

## Prerequisites

| Requirement | Version | Notes |
| --- | --- | --- |
| C++ compiler and standard library | C++23 | MinGW g++ 14+ or MSVC 2022 17.4+. The library needs `std::expected`, `std::move_only_function`, and `std::format`. GCC 13 has all three, but its `std::format_to_n` returns a wrong iterator (GCC PR110990, fixed only in 13.3, which has no MinGW binary release). The logging paths corrupt the stack through that iterator, so configure refuses GCC below 14. |
| [CMake](https://cmake.org/) | 3.28+ | |
| [Ninja](https://ninja-build.org/) | any | Ships with Visual Studio. For MSYS2, run `pacman -S ninja`. |
| `make` | any | Optional, for the Makefile wrapper. Use `mingw32-make` in a MinGW environment. |
| Git | any | For cloning and for submodules. |

## Using DetourModKit in Your Mod Project

Two integration methods exist. Method 1 builds from source as a submodule. Method 2 links a pre-built package.

### ABI compatibility

Read this before you choose a method. DetourModKit is a C++23 **static** library whose entire public surface is C++. There is no `extern "C"` boundary anywhere. The archive bakes in the compiler's name mangling, its exception model, and the layout of every standard-library type that crosses the API. That set covers `std::string`, `std::vector`, `std::expected`, `std::move_only_function`, and the containers inside `Result<T>`. None of it is stable across toolchains.

| Axis | Requirement | Failure mode |
| --- | --- | --- |
| Compiler family | Match exactly. MinGW-GCC and MSVC archives are not interchangeable | A release is compiler-specific by construction. Rebuild from source (Method 1) after a compiler switch |
| Standard library | C++23 or newer, with `<expected>`, `std::move_only_function`, and `<format>` | Configure fails early with a clear message |
| MSVC CRT | `/MD` for Release, `/MDd` for Debug | `LNK2038` at best, silent ODR undefined behavior at worst |
| MSVC `_ITERATOR_DEBUG_LEVEL` | Match the archive | Container layout differs |
| Target system, compiler-target architecture, pointer size | Match exactly | `find_package` fails at configure time |

`find_package(DetourModKit)` checks all five axes. A mismatch fails at configure time. Common x64 and ARM64 spellings compare equal. A compiler major-version difference within one ABI family produces a warning instead.

DetourModKit never overrides `_ITERATOR_DEBUG_LEVEL`. A Debug archive sits at the debug STL's own default, so a stock `/MDd` Debug consumer matches with no extra define. The installed prefix records every ABI axis in `lib/cmake/DetourModKit/DetourModKitAbi.cmake`.

Set `DetourModKit_ALLOW_INCOMPATIBLE_ABI=ON` to convert a hard ABI failure into a warning. The consumer then accepts the mismatch risk explicitly.

One multi-config prefix can hold Debug and Release archives. Each consumer configuration selects its correct archive set.

### Method 1: Using DetourModKit as a Submodule (Recommended)

This method suits active development. Your own toolchain compiles the library, so the ABI matches by construction.

1. **Add the submodule:**

    ```bash
    git submodule add https://github.com/tkhquang/DetourModKit.git external/DetourModKit
    git submodule update --init --recursive
    ```

2. **Pin a release tag, or move to a newer one later:**

    ```bash
    cd external/DetourModKit
    git fetch --tags
    git checkout v4.0.0          # any release tag
    cd ../..
    git add external/DetourModKit
    git commit -m "pin DetourModKit to v4.0.0"
    ```

3. **Configure your CMakeLists.txt:**

    ```cmake
    cmake_minimum_required(VERSION 3.28)
    project(MyMod VERSION 1.0.0 LANGUAGES CXX)

    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    add_subdirectory(external/DetourModKit)

    add_library(MyMod SHARED src/main.cpp)

    # All dependencies link transitively. user32 and xinput1_4 propagate
    # automatically through DetourModKit's INTERFACE linkage.
    target_link_libraries(MyMod PRIVATE DetourModKit)

    # Add any extra system libraries your own mod code needs.
    if(WIN32)
        target_link_libraries(MyMod PRIVATE psapi kernel32)
    endif()
    ```

4. **Check out submodules in GitHub Actions:**

    ```yaml
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        submodules: "recursive"
    ```

### Method 2: Using Pre-built DetourModKit Package

This method links a pre-built and installed version of DetourModKit.

1. **Download a release package.**

    Pre-built packages for MinGW and MSVC are on the [Releases](https://github.com/tkhquang/DetourModKit/releases) page. Download the zip that matches your toolchain and version, for example `DetourModKit_MinGW_v4.0.0.zip` or `DetourModKit_MSVC_v4.0.0.zip`. Extract it into your mod project, for example into `external/DetourModKit/`.

    A pre-built archive is compiled objects, so its toolchain must be compatible with yours. The release archives carry no link-time optimization, no MSVC `/GL` LTCG IL and no GCC LTO GIMPLE. That keeps them portable within each toolchain family instead of pinned to one exact toolset:

    - **MSVC zip:** consuming the headers needs Visual Studio 2022 17.4 or newer, because the public surface is C++23. The non-LTO archive itself stays link-compatible across the v140 to v143 toolsets. That is archive-level linker compatibility, not a supported consumer configuration. An LTCG (`/GL`) archive falls outside even that guarantee and fails a differing toolset with `C1047` or `LNK1257`. Match the CRT, which the exported target already drives.
    - **MinGW zip:** built with one specific GCC major, currently GCC 14.x. Link it with a compatible GCC major. The libstdc++ ABI differs across majors, so a far-newer or far-older g++ can fail to link. Build from source (Method 1) when your GCC major differs.

    To upgrade, download the newer zip and replace the contents of `external/DetourModKit/`.

    Building from source and running `cmake --install` produces the same directory layout. See [Building](#building-detourmodkit-static-library-via-cmake).

2. **Configure your build system.**

#### CMake

```cmake
cmake_minimum_required(VERSION 3.28)
project(MyMod)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(DetourModKit_DIR "external/DetourModKit/lib/cmake/DetourModKit")
find_package(DetourModKit REQUIRED)

add_library(MyMod SHARED src/main.cpp)

# user32 and xinput1_4 propagate automatically. The library imposes no macros
# on your translation units: it does not define NOMINMAX for you.
target_link_libraries(MyMod PRIVATE DetourModKit::DetourModKit)

if(WIN32)
    target_link_libraries(MyMod PRIVATE psapi kernel32)
endif()
```

#### Makefile (g++ MinGW)

```makefile
DETOURMODKIT_DIR := external/DetourModKit

CXXFLAGS += -I$(DETOURMODKIT_DIR)/include
LDFLAGS += -L$(DETOURMODKIT_DIR)/lib
LIBS += -lDetourModKit -lsafetyhook -lZydis -lZycore
# user32 and xinput1_4 are required by DetourModKit itself.
# Add -lpsapi -lkernel32 and others if your own mod code uses them.
LIBS += -luser32 -lxinput1_4 -static-libgcc -static-libstdc++

# Example link command:
# $(CXX) $(YOUR_OBJECTS) -o YourMod.asi -shared $(LDFLAGS) $(LIBS)
```

## Code Example

The umbrella `<DetourModKit.hpp>` and most module headers define `namespace dmk = DetourModKit` and `namespace DMK = DetourModKit`. Both aliases name the same namespace. Define `DMK_NO_NAMESPACE_ALIASES` before the first include to suppress them. See [Public API](docs/design/public-api.md) for the full alias rules.

This example attaches to a process, resolves one function by signature, hooks it, and tears down safely. For config binding, hotkeys, and the leaner include set, see [The Minimal Core](docs/guides/minimal-core.md).

```cpp
// MyMod/src/main.cpp
#include <optional>
#include <windows.h>

#include <DetourModKit.hpp>

using PrintMessage_t = void(__stdcall *)(const char *message, int type);

bool g_greeting_enabled = true;

// hook::Hook is move-only with no default constructor, so a global lives in an optional.
std::optional<dmk::hook::Hook> g_print_hook;

void __stdcall Detour_PrintMessage(const char *message, int type)
{
    // original<Fn>() is the unguarded fast path. It is non-null only while the hook is engaged.
    // Use call<Ret>(args...) instead when a teardown can race this detour.
    const auto call_original = g_print_hook ? g_print_hook->original<PrintMessage_t>() : nullptr;
    if (!call_original)
    {
        return;
    }
    call_original(g_greeting_enabled ? "Hello from DetourModKit!" : message, type);
}

// Runs on the bootstrap worker thread, off the loader lock. An init failure is a returned
// value logged on the worker, never a throw across the loader lock.
dmk::Result<void> InitializeMyMod(dmk::Session &session)
{
    dmk::config::bind_bool("Hooks", "EnableGreetingHook", "Enable Greeting Hook",
                           [](bool v) { g_greeting_enabled = v; }, true);
    session.ini().load("MyMod.ini");   // load after the binds, so file values reach them

    // inline_at resolves the ladder at install time and performs the function cast internally.
    // The hook comes back DISABLED. The target is not patched until enable() below.
    auto installed = dmk::hook::inline_at(
        dmk::hook::InlineRequest{
            .name = "PrintMessage_Hook",
            .target = dmk::scan::OwnedScanRequest{
                .ladder = {dmk::scan::Candidate::direct(
                    "PrintMessage", dmk::scan::Pattern::literal("48 89 ?? ?? 57"))},
                .label = "PrintMessage",
                .scope = dmk::Region::host(),
                .pages = dmk::scan::Pages::Executable,
                .require_executable_result = true,
            },
        },
        &Detour_PrintMessage);
    if (!installed)
    {
        session.log().error("Install failed: {}", installed.error().message());
        return std::unexpected(installed.error());
    }

    // Publish the handle BEFORE arming. The detour reaches the original through g_print_hook,
    // so arming inside inline_at can let the game call the detour while the global is empty.
    g_print_hook.emplace(std::move(*installed));
    if (auto armed = g_print_hook->enable(); !armed)
    {
        // enable() can fail with the hook still live (BackendFailed, DisableFailed).
        // Drop the handle only once the target is confirmed unpatched.
        if (!g_print_hook->is_enabled())
        {
            g_print_hook.reset();
        }
        return std::unexpected(armed.error());
    }

    session.log().info("MyMod initialized.");
    return {};
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        const dmk::ModInfo info{
            .name = "MyMod",                            // logger prefix and mod identity
            .log_file = "MyMod.log",
            .game_process_name = "MyGame.exe",          // optional, "" disables the check
            .instance_mutex_prefix = "MyMod_Instance",  // optional, "" disables the check
        };
        return dmk::bootstrap_attach(info, &InitializeMyMod).has_value() ? TRUE : FALSE;
    }
    if (reason == DLL_PROCESS_DETACH)
    {
        // reserved == NULL is an explicit FreeLibrary. ~Hook under the loader lock pins the backend and
        // leaves the target patched, so call dmk::shutdown_and_wait() from an off-loader-lock path before
        // FreeLibrary when the prologue must actually be restored.
        // reserved != NULL is process exit. Leave the handle. Touching patched pages there is a UAF.
        if (reserved == nullptr)
        {
            g_print_hook.reset();
        }
        dmk::bootstrap_detach(reserved);   // signals the worker, never waits
    }
    return TRUE;
}
```

> [!WARNING]
> See the [Hot-Reload Guide](docs/guides/hot-reload/README.md) for dynamic unload and caller-owned hook order.

## Configuration File Example

Create a `MyMod.ini` file alongside your DLL.

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

## Features

Each header's Doxygen comments are the API source of truth. Task-oriented guides live in the [documentation index](docs/README.md).

### Foundation

| Module | Purpose | Header | Guide |
| --- | --- | --- | --- |
| **Core Vocabulary** | Typed `Address` / `Region` values, `Prot` flags, and the `Result<T>` error idiom every module speaks | [`address.hpp`](include/DetourModKit/address.hpp), [`region.hpp`](include/DetourModKit/region.hpp), [`error.hpp`](include/DetourModKit/error.hpp), [`defines.hpp`](include/DetourModKit/defines.hpp) | |

### Find, read & patch game code

| Module | Purpose | Header | Guide |
| --- | --- | --- | --- |
| **AOB Scanner** | Pattern matching and candidate ladders that resolve signatures to live addresses | [`scan.hpp`](include/DetourModKit/scan.hpp) | [AOB Signature Scanning](docs/misc/aob-signatures.md) |
| **Memory Utilities** | Fault-guarded reads and writes, pointer-chain walks, and page-protection guards | [`memory.hpp`](include/DetourModKit/memory.hpp) | [Hot-Path Memory](docs/guides/memory/hot-path-memory.md) |
| **Hook** | Free verbs returning move-only RAII `Hook` / `VmtHook` handles, backend hidden | [`hook.hpp`](include/DetourModKit/hook.hpp) | [Hook Type Coverage](docs/guides/hooking/hook-type-coverage.md) |
| **MSVC RTTI Walker** | Recover mangled type names from live vtables without `typeid` | [`rtti.hpp`](include/DetourModKit/rtti.hpp) | [MSVC RTTI Walker](docs/guides/rtti/rtti-walker.md) |
| **RTTI Self-Heal** | Reverse-identify a pointer's object and self-heal field offsets after a patch | [`rtti_dissect.hpp`](include/DetourModKit/rtti_dissect.hpp) | [RTTI Self-Heal](docs/guides/rtti/rtti-self-heal.md) |

### Keep signatures alive across patches

| Module | Purpose | Header | Guide |
| --- | --- | --- | --- |
| **Anchor Registry** | One declarative table over the self-healing backends with a startup drift gate | [`anchor.hpp`](include/DetourModKit/anchor.hpp) | [Anchor Registry](docs/guides/scanning/anchors.md) |
| **Signature Manifest** | The resolved contract as serializable data, gated trusted vs safe-disabled | [`manifest.hpp`](include/DetourModKit/manifest.hpp) | [Signature Manifest](docs/guides/scanning/signature-manifest.md) |
| **Offline Signature Health** | Statically grade a pattern, record, or manifest with no game running | [`sighealth.hpp`](include/DetourModKit/sighealth.hpp) | [Offline Signature Health](docs/guides/scanning/signature-health.md) |

### Runtime subsystems

| Module | Purpose | Header | Guide |
| --- | --- | --- | --- |
| **Input System** | Background-polled hotkey and gamepad combos with opt-in suppression | [`input.hpp`](include/DetourModKit/input.hpp), [`input_codes.hpp`](include/DetourModKit/input_codes.hpp) | |
| **Configuration** | INI binding registry with key-combo fusions and fail-soft hot-reload | [`config.hpp`](include/DetourModKit/config.hpp) | [Config Hot-Reload](docs/guides/hot-reload/config-hot-reload.md) |
| **Logger** | Value-facade logger with compile-checked format strings and opt-in async writes | [`logger.hpp`](include/DetourModKit/logger.hpp) | |

### Process lifecycle

| Module | Purpose | Header | Guide |
| --- | --- | --- | --- |
| **Session and Bootstrap** | RAII process lifetime with ordered teardown and DllMain scaffolding | [`DetourModKit.hpp`](include/DetourModKit.hpp), [`session.hpp`](include/DetourModKit/session.hpp) | [Hot-Reload](docs/guides/hot-reload/README.md) |
| **Stoppable Worker** | RAII named `std::jthread` wrapper with loader-lock-safe teardown | [`detail/worker.hpp`](include/DetourModKit/detail/worker.hpp) | |

### Observability & messaging

| Module | Purpose | Header | Guide |
| --- | --- | --- | --- |
| **Diagnostics** | Leak counters, per-reason module-pin counts, scanner-fault and hook-lifecycle event buses, and a Snapshot | [`diagnostics.hpp`](include/DetourModKit/diagnostics.hpp) | |
| **Profiler** | Scoped timing to a lock-free ring buffer, Chrome-Tracing export, zero-cost when off | [`profiler.hpp`](include/DetourModKit/profiler.hpp) | |
| **Event Dispatcher** | Typed pub/sub with RAII auto-unsubscribe and a callback-safe emit path | [`detail/event_dispatcher.hpp`](include/DetourModKit/detail/event_dispatcher.hpp) | |

### Small utilities

| Module | Purpose | Header | Guide |
| --- | --- | --- | --- |
| **Format Utilities** | Header-only `std::format` helpers for addresses, bytes, and VK codes | [`format.hpp`](include/DetourModKit/format.hpp) | |
| **Filesystem Utilities** | Cached module-directory resolution with wide-string and UTF-8 APIs | [`filesystem.hpp`](include/DetourModKit/filesystem.hpp) | |
| **Math Utilities** | Header-only `constexpr` `noexcept` angle conversions | [`math.hpp`](include/DetourModKit/math.hpp) | |
| **Version Macros** | Compile-time version macros generated from CMake | [`version.hpp`](include/DetourModKit/version.hpp.in) | |

## Guides

Start with [The Minimal Core](docs/guides/minimal-core.md) for the five-header core set and the shortest path from process attach to reading, patching, and hooking game code. Every task-oriented guide, design note, and benchmark is indexed in the [documentation index](docs/README.md). Upgrading from v3.x? See [Migrating from v3.x to v4.0.0](docs/migration/migrating-v3-to-v4.md).

## Building DetourModKit (Static Library via CMake)

This project uses CMake with [CMake Presets](https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html) and Ninja. A thin Makefile wrapper is provided for convenience.

1. **Clone the repository with submodules:**

    ```bash
    git clone --recursive https://github.com/tkhquang/DetourModKit.git
    cd DetourModKit

    # If you already cloned without --recursive:
    git submodule update --init --recursive
    ```

2. **Build and install:**

    ```bash
    # Makefile wrapper (recommended). MinGW Release by default.
    make
    make install                    # installs to build/install/
    make PRESET=msvc-release
    make install PRESET=msvc-release
    ```

    ```bash
    # CMake presets directly
    cmake --preset mingw-release
    cmake --build --preset mingw-release --parallel
    cmake --install build/mingw-release --prefix ./install_package/mingw

    # MSVC. Run from a Visual Studio Developer Command Prompt.
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

> [!TIP]
> Create a git-ignored `CMakeUserPresets.json` to define local presets that inherit from these.

### Release build characteristics

- Standalone Release builds produce portable, non-LTO archives.
- Dead code elimination still applies: `/Gy /Gw` on MSVC, `-ffunction-sections -fdata-sections` with `--gc-sections` on GCC and Clang.
- `--gc-sections` propagates to consumers through INTERFACE linkage, so unused DetourModKit symbols are stripped at final link.
- `DMK_ENABLE_LTO` defaults ON only under `add_subdirectory`, where the consumer recompiles the library with the same toolchain. Keep it OFF for a standalone installed archive unless the package documents the exact toolchain match.
- MinGW Release keeps CMake's default `-O3`. Only the hand-tuned SIMD scan engine TU drops to `-O2`, because the unrolling in `-O3` regresses its hand-optimized verifier.
- MSVC embeds CodeView debug info (`/Z7`) in every config, so a static archive carries its own symbols.

### Installed package layout

```text
<install_prefix>/
├── include/
│   ├── DetourModKit.hpp       <-- Umbrella header; include this for the whole kit
│   ├── DetourModKit/          <-- Public module headers (one per module in the Features list)
│   │   └── detail/            <-- Installed compile-visible support; never included directly
│   └── DirectXMath/           <-- Re-exported by default (-DDMK_INSTALL_DIRECTXMATH=OFF omits); no safetyhook headers
├── lib/
│   ├── libDetourModKit.a      <-- Static library (.a for MinGW, .lib for MSVC; Debug adds a `d` postfix)
│   └── libsafetyhook.a, ...   <-- Backend archives (Zydis, Zycore) for the transitive link only; headers not installed
└── lib/cmake/DetourModKit/    <-- find_package(DetourModKit) config files
```

Every public header maps to an entry in the [Features](#features) list above.

### Installed package smoke test

```bash
cmake -S tests/package_smoke -B build/package-smoke-mingw -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DDetourModKit_DIR="$PWD/install_package/mingw/lib/cmake/DetourModKit" \
    -DCMAKE_CXX_COMPILER=g++
cmake --build build/package-smoke-mingw --parallel
ctest --test-dir build/package-smoke-mingw --output-on-failure
```

The smoke project includes the installed headers and links the installed `DetourModKit::DetourModKit` target. It touches `hook::is_target_hooked` and runs a full `Session::start` / `~Session` cycle. That pulls the whole static dependency chain into the consumer link.

## Test Suite

Every module has unit test coverage under GoogleTest, gated in CI at 80% minimum line coverage. See the [Test Coverage Guide](docs/tests/README.md) for suite layout and test architecture.

## Running Unit Tests

The debug presets (`mingw-debug`, `msvc-debug`) enable tests by default.

```bash
# Makefile wrapper
make test          # MinGW
make test_msvc     # MSVC, requires a VS Developer Command Prompt
make clean         # remove all build directories
```

```bash
# CMake presets
cmake --preset mingw-debug
cmake --build --preset mingw-debug --parallel
ctest --preset mingw-debug          # swap mingw-debug for msvc-debug under MSVC
```

### Running host-safety proofs only

Fault-containment fixtures, loader lifecycle hosts, and the CTest timeout control are CMake-owned targets outside the monolithic unit-test executable. All of them run on both toolchains. A case whose subject is the fault frame itself carries a per-compiler arm. MSVC contains a fault in a frame-based `__try`/`__except`. MinGW x64 contains it in a process-wide vectored handler.

The wrappers own the authoritative host list. Use them rather than a target list that drifts as hosts are added:

```bash
cmake --preset mingw-debug
bash scripts/run_fault_tests.sh
bash scripts/run_lifecycle_proofs.sh          # pass a build dir to run another tree, e.g. build/msvc-debug
```

Each wrapper builds its hosts and then runs its own label. To re-run an already-built tree without rebuilding, filter by label directly:

```bash
ctest --test-dir build/mingw-debug -L "fault-proof|lifecycle-proof|timeout-control" --output-on-failure
```

On a MinGW tree the wrappers select the runtime beside the compiler recorded in the build tree. Another MinGW installation earlier on `PATH` therefore cannot supply an incompatible runtime DLL. An MSVC tree gets no such prepend. The compiler directory carries private CRT copies, and those copies shadow the system CRT for every proof process.

> [!TIP]
> If the MSVC build fails on a locked PDB file, kill stale compiler processes:
>
> ```bash
> taskkill /F /IM cl.exe 2>nul || echo No cl.exe processes found
> ```

### Build options

Add any option to the configure line:

```bash
cmake --preset mingw-debug -DDMK_ENABLE_PROFILING=ON
cmake --build --preset mingw-debug --parallel
```

| Option | Default | Effect |
| --- | --- | --- |
| `DMK_WARNINGS_AS_ERRORS` | OFF, ON in CI | Treats compiler warnings as errors. |
| `DMK_ENABLE_PROFILING` | OFF | Expands the `DMK_PROFILE_SCOPE` and `DMK_PROFILE_FUNCTION` macros. When OFF they expand to `((void)0)`. The `Profiler` class and `ScopedProfile` compile in either way, so tests always work. |
| `DMK_ENABLE_AVX512` | OFF | Adds the AVX-512F and AVX-512BW pattern-verification tier, 64 bytes per iteration. |
| `DMK_ENABLE_SANITIZERS` | OFF | AddressSanitizer. MSVC only. Prefer the `msvc-debug-asan` preset. |
| `DMK_ENABLE_COVERAGE` | OFF | gcov instrumentation. Requires GCC or Clang. |

**AVX-512 tier.** The intrinsics are confined to one function by a per-function `target` attribute, with no global `/arch:AVX512` or `-mavx512`. The rest of the library keeps its AVX2 baseline, and the produced binary still runs on a CPU without AVX-512. The tier is selected only when a runtime `CPUID` and `XGETBV` check confirms CPU and OS support for AVX-512F and AVX-512BW. Otherwise the scanner falls back to AVX2. `scan::active_simd_level()` reports the tier in use. The `>= 30%` throughput gate is hardware-specific and can only be measured on a real AVX-512 host. Per-tier correctness runs under Intel SDE on pull requests to `main` via [simd-tier-correctness.yml](.github/workflows/simd-tier-correctness.yml).

**Sanitizers.** AddressSanitizer is available on Windows through MSVC only. GCC and Clang on mingw-w64 ship no ASan or UBSan runtime for the Windows target, so a MinGW sanitizer build cannot link. There is no UBSan and no LeakSanitizer on MSVC either. Setting `DMK_ENABLE_SANITIZERS=ON` under a non-MSVC Windows toolchain fails at configure time with a `FATAL_ERROR` that points to the MSVC route.

```bash
# Run from a Developer Command Prompt, which supplies clang_rt.asan_dynamic-x86_64.dll on PATH.
cmake --preset msvc-debug-asan
cmake --build --preset msvc-debug-asan --parallel
ctest --preset msvc-debug-asan
```

**Coverage.** Every pull request to `main` runs the [PR Check workflow](.github/workflows/pr-check.yml) with an 80% minimum line coverage gate. The latest report is published to [GitHub Pages](https://tkhquang.github.io/DetourModKit/) on every push to `main`.

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

The input system targets mod hotkeys and toggles, not a replacement for a game's primary input handling. See [Input subsystem](docs/design/input.md) for why XInput is the only backend.

**Limitations:**

- Maximum 4 controllers (XInput hard limit, indices 0-3).
- Analog triggers (LT/RT) and thumbstick axes are treated as digital buttons with configurable deadzone thresholds.
- No event-driven hot-plug detection. Controller connection is checked by polling, and reconnection attempts are throttled to every 2 seconds while disconnected.
- **Shift + Numpad keys:** When Shift is held, Windows translates numpad keys to their navigation equivalents. `Numpad5` becomes `VK_CLEAR` instead of `VK_NUMPAD5`. A combo like `LShift+Numpad5` never fires, because `GetAsyncKeyState` sees the translated VK code. **Workaround:** use `Ctrl` or `Alt` instead of `Shift` for numpad combos, or use non-numpad keys. ([More info](https://learn.microsoft.com/en-us/answers/questions/3935239/how-to-make-it-so-left-shift-doesnt-affect-number))

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
