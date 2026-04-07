# DetourModKit

[![Coverage Report ≥ 80%](https://github.com/tkhquang/DetourModKit/actions/workflows/coverage-pages.yml/badge.svg)](https://tkhquang.github.io/DetourModKit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Features](#features) | [Building](#building-detourmodkit-static-library-via-cmake) | [Testing](#running-unit-tests) | [Integration](#using-detourmodkit-in-your-mod-project) | [Example](#code-example)

DetourModKit is a lightweight C++ toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, and configuration management. It is built with MinGW in mind but aims for general C++ compatibility.

## Features

* **AOB Scanner:** Find array-of-bytes (signatures) in memory with wildcard support and SIMD-accelerated pattern verification: AVX2 (32 bytes/iteration, runtime-detected on Haswell+ CPUs) with SSE2 fallback (16 bytes/iteration) for patterns >= 16 bytes. Supports `|` offset markers for targeting a specific instruction within a wider pattern (e.g., `"48 8B 88 B8 00 00 00 | 48 89 4C 24 68"` sets the offset to byte 7) and nth-occurrence matching (1-based) for patterns that hit multiple locations. Includes RIP-relative instruction resolution for extracting absolute addresses from x86-64 code (returns `std::expected` with typed `RipResolveError` for actionable diagnostics on failure). Provides `scan_executable_regions()` for scanning all committed executable pages in the process -- useful for games with packed or protected binaries that unpack code into anonymous memory outside any loaded module.
* **Hook Manager:** A C++ wrapper around [SafetyHook](https://github.com/cursey/safetyhook) for creating and managing inline hooks, mid-function hooks, and VMT (virtual method table) hooks. Inline and mid hooks target functions by direct address or AOB scan. VMT hooks clone an object's vtable and replace individual method slots by index, enabling per-object interception of virtual calls (e.g., D3D device methods, game AI interfaces). Supports applying a single hooked vtable to multiple objects and safe callback-based access to hooked methods via `with_vmt_method()`.
* **Configuration System:** Load settings from INI files. Mods register their configuration variables (defined in the mod's code) and the kit handles parsing and value assignment. Supports key combos with modifier keys via `register_key_combo` (format: `modifier+trigger`, e.g., `Ctrl+Shift+F3`). Multiple independent combos can be comma-separated (e.g., `F3,Gamepad_LT+Gamepad_B`). Named keys (`Ctrl`, `F3`, `Mouse1`, `Gamepad_A`), hex VK codes (`0x72`), and mixed formats are all supported. (Powered by [SimpleIni](https://github.com/brofield/simpleini)).
* **Logger:** A flexible singleton logger for outputting messages to a log file. Supports configurable log levels, timestamps, and prefixes. Features **async logging** for high-throughput scenarios, **format string placeholders** for concise log messages, **concurrent file access** via Win32 shared-access file handles (log files can be read by external tools while logging is active), and `is_enabled(LogLevel)` for gating expensive trace-only work.
* **Async Logger:** A lock-free, bounded queue-based async logger that decouples log message production from file I/O. Designed for minimal latency on the producer side with batched writes on the consumer thread. Features configurable overflow policies (DropNewest/DropOldest/Block/SyncFallback), bounded Block policy with 16 ms default timeout (one frame at 60 fps) to prevent thread starvation, inline buffer optimization for messages of size <= 512 bytes (inclusive), and message size validation with truncation for messages larger than 16 MB (messages > 16 MB are truncated to 16 MB rather than rejected).
* **Memory Utilities:** Functions for checking memory readability/writability and writing bytes to memory. Includes an optional memory region cache with sharded SRWLOCK concurrency, LRU eviction, and stampede coalescing. Provides `is_readable_nonblocking()` (tri-state: readable/not-readable/unknown) for latency-sensitive threads, `read_ptr_unsafe()` for safe pointer reads in hot paths (SEH-protected on MSVC, cache-accelerated with VirtualQuery fallback on MinGW), and `read_ptr_unchecked()` -- an inline header-only variant with a configurable low-address validity guard for pointer chain traversal without per-call SEH overhead (caller must guarantee structural pointer validity).
* **Event Dispatcher:** A typed pub/sub event system with RAII subscription management. Each `EventDispatcher<Event>` manages a single event type with `shared_mutex` concurrency (concurrent `emit()` via shared lock, exclusive lock for subscribe/unsubscribe). Subscriptions auto-unsubscribe on destruction. Compose multiple dispatchers for multi-event architectures. Includes `emit_safe()` for exception-tolerant dispatch. Safe when the dispatcher is destroyed before its subscriptions (weak_ptr guard).
* **Profiler:** Opt-in scoped timing instrumentation with zero overhead when disabled. Compile-time gated via `DMK_ENABLE_PROFILING`. When enabled, records lock-free timing samples (~50 ns per scope) into a fixed-size ring buffer (64K samples, ~1.5 MB). Exports to [Chrome Tracing JSON](https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/preview) format viewable in `chrome://tracing` or [Perfetto](https://ui.perfetto.dev). Use `DMK_PROFILE_SCOPE("name")` or `DMK_PROFILE_FUNCTION()` macros to instrument code paths; use `Profiler::export_to_file()` to dump results after a profiling session.
* **String Utilities:** Whitespace trimming for string cleanup.
* **Format Utilities:** Inline formatting helpers for memory addresses, byte values, VK codes, and hex integer vectors using `std::format`.
* **Filesystem Utilities:** Basic filesystem operations, notably getting the current module's runtime directory.
* **Math Utilities:** Provides basic mathematical utility functions (e.g., angle conversions).
* **Input System:** Hotkey monitoring with a background polling thread.
  * **Input sources & modes:** Supports keyboard, mouse, and XInput gamepad input via a unified `InputCode` tagged type (`InputSource` + button code). Press (edge-triggered) and hold (level-triggered) input modes with modifier combinations (AND logic for modifiers, OR logic between independent combos). **Strict modifier matching** ensures that a binding only fires when exactly its declared modifiers are held -- pressing `Shift+V` will never trigger a plain `V` binding. Multiple independent combos can share a single binding name for cross-device hotkeys (e.g., keyboard F3 OR gamepad LT+B). Gamepad analog triggers (LT/RT) and thumbstick axes are treated as digital buttons with configurable deadzone thresholds. Focus-aware by default -- input events are ignored when the process does not own the foreground window.
  * **Threading & lifecycle:** Available as an RAII `InputPoller` building block or via the thread-safe `InputManager` singleton for convenience. Two-phase initialization (construct then start) for safe thread launching. `condition_variable_any` with `stop_token` for responsive cooperative shutdown. Exception-safe callback invocation. Automatic hold release on shutdown. Loader-lock-aware shutdown: background threads are safely detached instead of joined when called from `DllMain` or `FreeLibrary` context.
  * **Performance:** Hash-map-backed `is_binding_active()` query for lock-free cross-thread state reads (e.g., from render hooks at 60+ fps). Supports multiple bindings per name for multi-combo hotkeys. Lock-free `is_running()` via atomic flag. O(1) reverse name lookup for `input_code_to_name()`.
  * **Gamepad & polling:** XInput is polled once per cycle and skipped entirely when no gamepad bindings are registered. Reconnection attempts are throttled to every 2 seconds when no controller is connected, avoiding the per-cycle overhead of `XInputGetState` on disconnected slots.
  * **Configuration integration:** Loading input codes from INI files (named keys, hex VK codes, or mixed). Named key resolution uses binary search for efficient lookup. `register_press` and `register_hold` accept `KeyComboList` directly for zero-boilerplate binding of config-parsed key combos.

## Testing

* **Comprehensive Test Suite:** Full unit test coverage for all modules using GoogleTest.
* **Code Coverage:** Automated coverage analysis with 80% minimum line coverage gate in CI.
* **Coverage Tools:** Built-in scripts for parsing and analyzing coverage reports.

## Prerequisites

* A C++ compiler supporting C++23 (e.g., MinGW g++ 12+ or newer, MSVC 2022+).
* [CMake](https://cmake.org/) 3.25 or newer.
* [Ninja](https://ninja-build.org/) build system (ships with Visual Studio; for MSYS2: `pacman -S ninja`).
* `make` (optional, for the Makefile wrapper -- e.g., `mingw32-make` for MinGW environments).
* Git (for cloning and managing submodules).

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
    | `mingw-debug-asan` | GCC (MinGW) | Debug | ON | ASan + UBSan enabled |
    | `mingw-release` | GCC (MinGW) | Release | OFF | |
    | `msvc-debug` | MSVC (cl) | Debug | ON | |
    | `msvc-release` | MSVC (cl) | Release | OFF | |

> [!NOTE]
> Release builds enable Link-Time Optimization (LTO) when supported by the compiler,
> along with dead code elimination (`/Gy /Gw` on MSVC, `-ffunction-sections -fdata-sections`
> with `--gc-sections` on GCC/Clang). `--gc-sections` propagates to consumers via INTERFACE
> linkage so unused DetourModKit symbols are stripped at final link time. MinGW Release builds
> use `-O2` (overriding CMake's default `-O3`) for a better code-size/performance tradeoff.
> MSVC Debug builds embed CodeView debug info (`/Z7`) for parallel build compatibility;
> Release builds omit debug info entirely to minimize binary size.

---

> [!TIP]
> You can create a `CMakeUserPresets.json` file (git-ignored) to define your own local presets that inherit from the ones above.

   After running the install command, the install directory (`build/install/` for the Makefile wrapper, or whichever `--prefix` you passed to `cmake --install`) will contain:

    ```text
    <install_prefix>/
    ├── include/
    │   ├── DetourModKit/             <-- DetourModKit public headers
    │   │   ├── scanner.hpp           <-- AOB scanner
    │   │   ├── async_logger.hpp      <-- Async logging system
    │   │   ├── config.hpp
    │   │   ├── format.hpp            <-- String & format utilities
    │   │   ├── math.hpp              <-- Math utilities (angle conversions)
    │   │   ├── memory.hpp            <-- Memory utilities
    │   │   ├── filesystem.hpp        <-- Filesystem utilities
    │   │   ├── hook_manager.hpp      <-- Hook management
    │   │   ├── input.hpp             <-- Input/hotkey system
    │   │   ├── input_codes.hpp       <-- Unified input codes (keyboard/mouse/gamepad)
    │   │   ├── logger.hpp            <-- Synchronous logger
    │   │   ├── win_file_stream.hpp   <-- Win32 shared-access file stream
    │   │   └── ...
    │   ├── DetourModKit.hpp          <-- Main DetourModKit include
    │   ├── DirectXMath/              <-- DirectXMath headers
    │   │   ├── DirectXMath.h
    │   │   ├── DirectXMathVector.inl
    │   │   └── ...
    │   ├── safetyhook/               <-- SafetyHook detail headers
    │   │   ├── common.hpp
    │   │   ├── inline_hook.hpp
    │   │   └── ...
    │   ├── safetyhook.hpp            <-- Main SafetyHook include
    │   └── SimpleIni.h               <-- SimpleIni header
    ├── lib/
    │   ├── libDetourModKit.a         <-- Static libraries (.a for MinGW, .lib for MSVC)
    │   ├── libsafetyhook.a
    │   ├── libZydis.a
    │   └── libZycore.a
    └── lib/cmake/DetourModKit/       <-- CMake config files
        ├── DetourModKitConfig.cmake
        ├── DetourModKitConfigVersion.cmake
        └── DetourModKitTargets.cmake
    ```

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

### Enabling Sanitizers

To enable AddressSanitizer and UndefinedBehaviorSanitizer (requires GCC/Clang):

```bash
# Using the dedicated preset
cmake --preset mingw-debug-asan
cmake --build --preset mingw-debug-asan --parallel

# Or manually with any debug preset
cmake --preset mingw-debug -DDMK_ENABLE_SANITIZERS=ON
cmake --build --preset mingw-debug --parallel
```

> [!NOTE]
> Sanitizer support on MinGW requires `libasan` and `libubsan` runtime libraries.
> Not all MSYS2 MinGW GCC builds ship these. If linking fails with
> `cannot find -lasan`, install the sanitizer package or use Clang instead.

### Enabling Code Coverage

To generate code coverage reports (requires GCC/Clang), pass the coverage option when configuring:

```bash
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
cmake --build --preset mingw-debug --parallel
```

All pull requests to `main` are automatically tested via CI with an **80% minimum line coverage** gate. See the [PR Check workflow](.github/workflows/pr-check.yml) for details. The latest coverage report is published to [GitHub Pages](https://tkhquang.github.io/DetourModKit/) on every push to `main`.

## Using DetourModKit in Your Mod Project

There are two main approaches to integrate DetourModKit into your project:

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
    git checkout v2.0.0          # or v1.0.1, v1.0.0, etc.
    cd ../..
    git add external/DetourModKit
    git commit -m "pin DetourModKit to v2.0.0"
    ```

    To upgrade to a newer version later:

    ```bash
    cd external/DetourModKit
    git fetch --tags
    git checkout v2.1.0          # desired version
    cd ../..
    git add external/DetourModKit
    git commit -m "upgrade DetourModKit to v2.1.0"
    ```

2. **Configure your CMakeLists.txt:**

    ```cmake
    cmake_minimum_required(VERSION 3.25)
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

    Pre-built packages for MinGW and MSVC are available on the [Releases](https://github.com/tkhquang/DetourModKit/releases) page. Download the zip matching your toolchain and version (e.g., `DetourModKit_MinGW_v2.0.0.zip` or `DetourModKit_MSVC_v2.0.0.zip`).

    To upgrade, download the newer release zip and replace the contents of your `external/DetourModKit/` directory.

2. **Integrate DetourModKit:**
    * Extract the downloaded zip into your mod project (e.g., into an `external/DetourModKit/` subdirectory).
    * Alternatively, build from source and run `cmake --install` to produce the same directory layout (see [Building](#building-detourmodkit-static-library-via-cmake)).

3. **Configure Your Mod's Build System:**

   #### CMake

    ```cmake
    # In your mod's CMakeLists.txt
    cmake_minimum_required(VERSION 3.25)
    project(MyMod)

    set(CMAKE_CXX_STANDARD 23)

    # Find DetourModKit
    set(DetourModKit_DIR "external/DetourModKit/lib/cmake/DetourModKit")
    find_package(DetourModKit REQUIRED)

    # Create your mod target
    add_library(MyMod SHARED src/main.cpp)

    # Link against DetourModKit.
    # user32 and xinput1_4 propagate automatically via DetourModKit's INTERFACE linkage.
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

```c++
// MyMod/src/main.cpp
#include <windows.h>
#include <Psapi.h>

// Single include for all DetourModKit functionality
#include <DetourModKit.hpp>

// SafetyHook and SimpleIni are transitively available
#include <safetyhook.hpp>
#include <SimpleIni.h>

// Global variables for your mod's configuration
struct ModConfiguration {
    bool enable_greeting_hook = true;
    std::string log_level_setting = "INFO";
    DMKKeyComboList toggle_combo;
    DMKKeyComboList hold_scroll_combo;
} g_mod_config;

// Example Hook: Target function signature
typedef void (__stdcall *OriginalGameFunction_PrintMessage_t)(const char* message, int type);
OriginalGameFunction_PrintMessage_t original_GameFunction_PrintMessage = nullptr;

// Detour function
void __stdcall Detour_GameFunction_PrintMessage(const char* message, int type) {
    DMKLogger& logger = DMKLogger::get_instance();
    // Using format string placeholders for concise logging
    logger.info("Detour_GameFunction_PrintMessage CALLED! Original message: \"{}\", type: {}", message, type);

    if (g_mod_config.enable_greeting_hook) {
        logger.debug("Modifying message because greeting hook is enabled.");
        if (original_GameFunction_PrintMessage) {
            original_GameFunction_PrintMessage("Hello from DetourModKit! Hooked!", type + 100);
        }
        return;
    }

    if (original_GameFunction_PrintMessage) {
        original_GameFunction_PrintMessage(message, type);
    }
}

// Mod Initialization Function
void InitializeMyMod() {
    // Configure the Logger
    DMKLogger::configure("MyMod", "MyMod.log", "%Y-%m-%d %H:%M:%S");
    DMKLogger& logger = DMKLogger::get_instance();

    // Enable async logging for high-throughput scenarios.
    // Optional: remove the block below if synchronous logging is preferred.
    DMKAsyncLoggerConfig async_config;
    async_config.queue_capacity = 8192;
    async_config.batch_size = 64;
    logger.enable_async_mode(async_config);

    // Register your configuration variables (using callback-based API)
    DMKConfig::register_bool("Hooks", "EnableGreetingHook", "Enable Greeting Hook",
        [](bool v) { g_mod_config.enable_greeting_hook = v; }, true);
    DMKConfig::register_string("Debug", "LogLevel", "Log Level",
        [](const std::string& v) { g_mod_config.log_level_setting = v; }, "INFO");

    // Register hotkey bindings from INI (modifier+trigger format)
    // Comma separates independent combos: "F3,Gamepad_LT+Gamepad_B" (F3 OR LT+B)
    // Plus separates modifiers from trigger: "Ctrl+Shift+F3" (AND for modifiers, last = trigger)
    // Hex VK codes still work: "0x72", "0x11+0x72"
    // Mouse: "Mouse4", "Ctrl+Mouse1"
    // Gamepad: "Gamepad_A", "Gamepad_LB+Gamepad_A"
    DMKConfig::register_key_combo("Hotkeys", "ToggleKey", "Toggle Keys",
        [](const DMKKeyComboList& c) { g_mod_config.toggle_combo = c; }, "F3");
    DMKConfig::register_key_combo("Hotkeys", "HoldScrollKey", "Hold Scroll Keys",
        [](const DMKKeyComboList& c) { g_mod_config.hold_scroll_combo = c; }, "");

    // Load configuration from INI file
    DMKConfig::load("MyMod.ini");

    // Apply LogLevel from loaded configuration
    logger.set_log_level(DMKLogger::string_to_log_level(g_mod_config.log_level_setting));

    // Log the loaded configuration
    logger.info("MyMod configuration loaded and applied.");
    DMKConfig::log_all();

    // Initialize Hooks
    DMKHookManager& hook_manager = DMKHookManager::get_instance();

    uintptr_t target_function_address = 0;

    // Example: AOB Scan
    HMODULE game_module = GetModuleHandleA(NULL);
    if (game_module) {
        MODULEINFO module_info = {0};
        if (GetModuleInformation(GetCurrentProcess(), game_module, &module_info, sizeof(module_info))) {
            logger.debug("Scanning module at {} size {}",
                         DMKFormat::format_address(reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll)),
                         module_info.SizeOfImage);

            // Replace with actual AOB pattern from your target game
            std::string aob_sig_str = "48 89 ?? ?? 57";
            ptrdiff_t pattern_offset = 0;

            auto pattern = DMKScanner::parse_aob(aob_sig_str);
            if (pattern.has_value()) {
                const std::byte* found_pattern = DMKScanner::find_pattern(
                    reinterpret_cast<const std::byte*>(module_info.lpBaseOfDll),
                    module_info.SizeOfImage,
                    *pattern
                );
                if (found_pattern) {
                    target_function_address = reinterpret_cast<uintptr_t>(found_pattern) + pattern_offset;
                    logger.info("Pattern found at: {}, target address: {}",
                                DMKFormat::format_address(reinterpret_cast<uintptr_t>(found_pattern)),
                                DMKFormat::format_address(target_function_address));
                } else {
                    logger.error("AOB pattern not found in target module.");
                }
            } else {
                logger.error("Failed to parse AOB pattern: {}", aob_sig_str);
            }
        } else {
            logger.error("GetModuleInformation failed: {}", GetLastError());
        }
    } else {
        logger.error("Failed to get game module handle.");
    }

    if (target_function_address != 0) {
        DMKHookConfig hook_cfg;
        auto result = hook_manager.create_inline_hook(
            "GameFunction_PrintMessage_Hook",
            target_function_address,
            reinterpret_cast<void*>(Detour_GameFunction_PrintMessage),
            reinterpret_cast<void**>(&original_GameFunction_PrintMessage),
            hook_cfg
        );

        if (result.has_value()) {
            logger.info("Successfully created hook: {}", result.value());
        } else {
            logger.error("Failed to create hook: {}",
                         DMK::Hook::error_to_string(result.error()));
        }
    } else {
        logger.warning("Target address is 0 or not found. Hook not created.");
    }

    // Register hotkey bindings with the InputManager (after hooks are ready).
    // register_press/register_hold accept a KeyComboList directly -- one binding
    // is created per combo, all sharing the same name for OR-logic queries.
    DMKInputManager& input_mgr = DMKInputManager::get_instance();

    input_mgr.register_press("toggle_view", g_mod_config.toggle_combo, []() {
        DMKLogger::get_instance().info("Toggle key pressed!");
    });

    input_mgr.register_hold("hold_scroll", g_mod_config.hold_scroll_combo, [](bool held) {
        DMKLogger::get_instance().info("Hold scroll: {}", held ? "active" : "released");
    });

    // Start the input polling thread (focus-aware by default)
    input_mgr.start();

    logger.info("MyMod Initialized using DetourModKit!");
}

// Mod Shutdown Function
void ShutdownMyMod() {
    DMKLogger::get_instance().info("MyMod Shutting Down...");

    // Shuts down all singletons in correct dependency order:
    // InputManager -> HookManager -> Memory cache -> Config -> Logger
    DMK_Shutdown();
}

// IMPORTANT: Offload initialization to a worker thread so start() runs
// outside DllMain, and call DMK_Shutdown() before DLL_PROCESS_DETACH.

static DWORD WINAPI InitThread(LPVOID) {
    InitializeMyMod();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CloseHandle(CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr));
    }
    return TRUE;
}
```

> [!WARNING]
> Calling `DMK_Shutdown()` before `DLL_PROCESS_DETACH` is the recommended practice for a clean orderly shutdown. Each subsystem detects if it is running under the Windows loader lock and will detach background threads instead of joining them to avoid deadlock, but calling shutdown early ensures all log messages are flushed and hooks are cleanly removed.

## Configuration File Example

Create a `MyMod.ini` file alongside your DLL:

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
```

## Supported Input Names

The configuration system recognizes the following named input codes (case-insensitive):

| Category | Names |
| --- | --- |
| **Modifiers** | `Ctrl`, `LCtrl`, `RCtrl`, `Shift`, `LShift`, `RShift`, `Alt`, `LAlt`, `RAlt` |
| **Letters** | `A`–`Z` |
| **Digits** | `0`–`9` |
| **Function keys** | `F1`–`F24` |
| **Navigation** | `Left`, `Right`, `Up`, `Down`, `Home`, `End`, `PageUp`, `PageDown`, `Insert`, `Delete` |
| **Common** | `Space`, `Enter`, `Escape`, `Tab`, `Backspace`, `CapsLock`, `NumLock`, `ScrollLock`, `PrintScreen`, `Pause` |
| **Numpad** | `Numpad0`–`Numpad9`, `NumpadAdd`, `NumpadSubtract`, `NumpadMultiply`, `NumpadDivide`, `NumpadDecimal` |
| **Mouse** | `Mouse1` (left), `Mouse2` (right), `Mouse3` (middle), `Mouse4`, `Mouse5` |
| **Gamepad** | `Gamepad_A`, `Gamepad_B`, `Gamepad_X`, `Gamepad_Y`, `Gamepad_LB`, `Gamepad_RB`, `Gamepad_LT`, `Gamepad_RT`, `Gamepad_Start`, `Gamepad_Back`, `Gamepad_LS`, `Gamepad_RS`, `Gamepad_DpadUp`, `Gamepad_DpadDown`, `Gamepad_DpadLeft`, `Gamepad_DpadRight` |
| **Gamepad sticks** | `Gamepad_LSUp`, `Gamepad_LSDown`, `Gamepad_LSLeft`, `Gamepad_LSRight`, `Gamepad_RSUp`, `Gamepad_RSDown`, `Gamepad_RSLeft`, `Gamepad_RSRight` |

Hex VK codes with `0x` prefix (e.g., `0x72` for F3) are also accepted and default to keyboard input.

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

* Maximum 4 controllers (XInput hard limit, indices 0-3).
* Analog triggers (LT/RT) and thumbstick axes are treated as digital buttons with configurable deadzone thresholds.
* No event-driven hot-plug detection; controller connection is checked via polling (reconnection attempts are throttled to every 2 seconds when disconnected).
* **Shift + Numpad keys:** When Shift is held, Windows translates numpad keys to their navigation equivalents (e.g., `Numpad5` becomes `VK_CLEAR` instead of `VK_NUMPAD5`). This means combos like `LShift+Numpad5` will never fire because `GetAsyncKeyState` sees the translated VK code, not the original numpad code. **Workaround:** use `Ctrl` or `Alt` instead of `Shift` for numpad combos, or use non-numpad keys. ([More info](https://learn.microsoft.com/en-us/answers/questions/3935239/how-to-make-it-so-left-shift-doesnt-affect-number))

## Projects Using DetourModKit

For practical reference and real-world usage examples:

* **OBR-NoCarryWeight**: [https://github.com/tkhquang/OBRTools/tree/main/NoCarryWeight](https://github.com/tkhquang/OBRTools/tree/main/NoCarryWeight)
* **KCD1-TPVToggle**: [https://github.com/tkhquang/KCD1Tools/tree/main/TPVToggle](https://github.com/tkhquang/KCD1Tools/tree/main/TPVToggle)
* **KCD2-TPVToggle**: [https://github.com/tkhquang/KCD2Tools/tree/main/TPVToggle](https://github.com/tkhquang/KCD2Tools/tree/main/TPVToggle)
* **CrimsonDesert-EquipHide**: [https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertEquipHide](https://github.com/tkhquang/CrimsonDesertTools/tree/main/CrimsonDesertEquipHide)

## Acknowledgements

DetourModKit incorporates components from other open-source projects. See [DetourModKit_Acknowledgements.txt](DetourModKit_Acknowledgements.txt) for full details.

* [SafetyHook](https://github.com/cursey/safetyhook) (Boost Software License 1.0)
* [SimpleIni](https://github.com/brofield/simpleini) (MIT)
* [DirectXMath](https://github.com/microsoft/DirectXMath) (MIT)
* [Zydis & Zycore](https://github.com/zyantific/zydis) (MIT)
