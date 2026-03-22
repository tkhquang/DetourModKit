# DetourModKit

[![CI - Tests & Coverage](https://github.com/tkhquang/DetourModKit/actions/workflows/ci.yml/badge.svg)](https://github.com/tkhquang/DetourModKit/actions/workflows/ci.yml)
![Coverage: 80%+](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen)

DetourModKit is a lightweight C++ toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, and configuration management. It is built with MinGW in mind but aims for general C++ compatibility.

## Features

* **AOB Scanner:** Find array-of-bytes (signatures) in memory with wildcard support. Includes RIP-relative instruction resolution for extracting absolute addresses from x86-64 code.
* **Hook Manager:** A C++ wrapper around [SafetyHook](https://github.com/cursey/safetyhook) for creating and managing inline and mid-function hooks, by direct address or AOB scan.
* **Configuration System:** Load settings from INI files. Mods register their configuration variables (defined in the mod's code) and the kit handles parsing and value assignment. Supports key combos with modifier keys via `register_key_combo` (format: `modifier+trigger`, e.g., `Ctrl+Shift+F3`). Named keys (`Ctrl`, `F3`, `Mouse1`, `Gamepad_A`), hex VK codes (`0x72`), and mixed formats are all supported. (Powered by [SimpleIni](https://github.com/brofield/simpleini)).
* **Logger:** A flexible singleton logger for outputting messages to a log file. Supports configurable log levels, timestamps, and prefixes. Features **async logging** for high-throughput scenarios and **format string placeholders** for concise log messages.
* **Async Logger:** A lock-free, bounded queue-based async logger that decouples log message production from file I/O. Designed for minimal latency on the producer side with batched writes on the consumer thread. Features configurable overflow policies (DropNewest/DropOldest/Block/SyncFallback), bounded Block policy with 16 ms default timeout (one frame at 60 fps) to prevent thread starvation, inline buffer optimization for messages of size <= 256 bytes (inclusive), and message size validation with truncation for messages larger than 16 MB (messages > 16 MB are truncated to 16 MB rather than rejected).
* **Memory Utilities:** Functions for checking memory readability/writability and writing bytes to memory. Includes an optional memory region cache.
* **String Utilities:** Helper functions for formatting addresses, hexadecimal values, virtual key codes, etc.
* **Format Utilities:** Custom formatters for game modding types (memory addresses, byte values, VK codes) with C++20 `std::format` support.
* **Filesystem Utilities:** Basic filesystem operations, notably getting the current module's runtime directory.
* **Math Utilities:** Provides basic mathematical utility functions (e.g., angle conversions).
* **Input System:** Hotkey monitoring with a background polling thread.
  * **Input sources & modes:** Supports keyboard, mouse, and XInput gamepad input via a unified `InputCode` tagged type (`InputSource` + button code). Press (edge-triggered) and hold (level-triggered) input modes with modifier combinations (AND logic for modifiers, OR logic for trigger keys). Gamepad analog triggers (LT/RT) and thumbstick axes are treated as digital buttons with configurable deadzone thresholds. Focus-aware by default — input events are ignored when the process does not own the foreground window.
  * **Threading & lifecycle:** Available as an RAII `InputPoller` building block or via the thread-safe `InputManager` singleton for convenience. Two-phase initialization (construct then start) for safe thread launching. `condition_variable_any` with `stop_token` for responsive cooperative shutdown. Exception-safe callback invocation. Automatic hold release on shutdown. DLL-safe when used with `DMK_Shutdown()` before `DLL_PROCESS_DETACH`.
  * **Performance:** O(1) hash-map-backed `is_binding_active()` query for lock-free cross-thread state reads (e.g., from render hooks at 60+ fps). Lock-free `is_running()` via atomic flag. O(1) reverse name lookup for `input_code_to_name()`.
  * **Gamepad & polling:** XInput is polled once per cycle and skipped entirely when no gamepad bindings are registered. Reconnection attempts are throttled to every 2 seconds when no controller is connected, avoiding the per-cycle overhead of `XInputGetState` on disconnected slots.
  * **Configuration integration:** Loading input codes from INI files (named keys, hex VK codes, or mixed). Named key resolution uses binary search for efficient lookup.

## Testing

* **Comprehensive Test Suite:** Full unit test coverage for all modules using GoogleTest.
* **Code Coverage:** Automated coverage analysis with 80% minimum line coverage gate in CI.
* **Coverage Tools:** Built-in scripts for parsing and analyzing coverage reports.

## Prerequisites

* A C++ compiler supporting C++23 (e.g., MinGW g++ 12+ or newer, MSVC 2022+).
* [CMake](https://cmake.org/) 3.25 or newer.
* [Ninja](https://ninja-build.org/) build system (ships with Visual Studio; for MSYS2: `pacman -S ninja`).
* `make` (optional, for the Makefile wrapper — e.g., `mingw32-make` for MinGW environments).
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

    | Preset | Compiler | Build Type | Tests |
    | --- | --- | --- | --- |
    | `mingw-debug` | GCC (MinGW) | Debug | ON |
    | `mingw-release` | GCC (MinGW) | Release | OFF |
    | `msvc-debug` | MSVC (cl) | Debug | ON |
    | `msvc-release` | MSVC (cl) | Release | OFF |

    You can create a `CMakeUserPresets.json` file (git-ignored) to define your own local presets that inherit from the ones above.

    After running the install command, the install directory will contain a structure ready for consumption:

    ```text
    install_package/mingw/
    ├── include/
    │   ├── DetourModKit/             <-- DetourModKit public headers
    │   │   ├── scanner.hpp           <-- AOB scanner
    │   │   ├── async_logger.hpp      <-- Async logging system
    │   │   ├── config.hpp
    │   │   ├── format.hpp            <-- Format utilities
    │   │   ├── math.hpp              <-- Math utilities (angle conversions)
    │   │   ├── memory.hpp            <-- Memory utilities
    │   │   ├── filesystem.hpp        <-- Filesystem utilities
    │   │   ├── hook_manager.hpp      <-- Hook management
    │   │   ├── input.hpp             <-- Input/hotkey system
    │   │   ├── input_codes.hpp       <-- Unified input codes (keyboard/mouse/gamepad)
    │   │   ├── logger.hpp            <-- Synchronous logger
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
    │   ├── libDetourModKit.a         <-- MinGW: .a files
    │   ├── libsafetyhook.a           <-- MSVC: .lib files
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

### If the build is failing due to a PDB file locking issue

```bash
taskkill /F /IM cl.exe 2>nul || echo No cl.exe processes found
```

### Enabling Code Coverage

To generate code coverage reports (requires GCC/Clang), pass the coverage option when configuring:

```bash
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
cmake --build --preset mingw-debug --parallel
```

All pull requests to `main` are automatically tested via CI with a **80% minimum line coverage** gate. See the [CI workflow](.github/workflows/ci.yml) for details.

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

    # Link against DetourModKit (all dependencies are transitively linked)
    target_link_libraries(MyMod PRIVATE DetourModKit)

    # Add system libraries (Windows)
    if(WIN32)
        target_link_libraries(MyMod PRIVATE psapi user32 kernel32)
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

1. **Integrate DetourModKit:**
    * After building DetourModKit, copy the entire `install_package/mingw/` or `install_package/msvc/` directory into your mod project (e.g., into an `external/DetourModKit/` subdirectory).
    * Alternatively, adjust your mod's build system to point to DetourModKit's install directory directly.

2. **Configure Your Mod's Build System:**

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

    # Link against DetourModKit
    target_link_libraries(MyMod PRIVATE DetourModKit::DetourModKit)

    # Add system libraries (Windows)
    if(WIN32)
        target_link_libraries(MyMod PRIVATE psapi user32 kernel32)
    endif()
    ```

   #### Makefile (Example for g++ MinGW)

    ```makefile
    # In your mod's Makefile
    DETOURMODKIT_DIR := external/DetourModKit

    CXXFLAGS += -I$(DETOURMODKIT_DIR)/include
    LDFLAGS += -L$(DETOURMODKIT_DIR)/lib
    LIBS += -lDetourModKit -lsafetyhook -lZydis -lZycore
    # Add system libs like: -lpsapi -luser32 -lkernel32 -lshlwapi -static-libgcc -static-libstdc++

    # Example link command:
    # $(CXX) $(YOUR_OBJECTS) -o YourMod.asi -shared $(LDFLAGS) $(LIBS)
    ```

## Code Example

```c++
// MyMod/src/main.cpp
#include <windows.h>

// Single include for all DetourModKit functionality
#include <DetourModKit.hpp>

// SafetyHook and SimpleIni are transitively available
#include <safetyhook.hpp>
#include <SimpleIni.h>

// Global variables for your mod's configuration
struct ModConfiguration {
    bool enable_greeting_hook = true;
    std::string log_level_setting = "INFO";
    DMKKeyCombo toggle_combo;
    DMKKeyCombo hold_scroll_combo;
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
    // Named keys: "F3" or "F3,F1" (comma = OR for multiple trigger keys)
    // With modifiers: "Ctrl+Shift+F3" (plus = AND for modifiers, last segment = triggers)
    // Hex VK codes still work: "0x72", "0x11+0x72"
    // Mouse: "Mouse4", "Ctrl+Mouse1"
    // Gamepad: "Gamepad_A", "Gamepad_LB+Gamepad_A"
    DMKConfig::register_key_combo("Hotkeys", "ToggleKey", "Toggle Keys",
        [](const DMKKeyCombo& c) { g_mod_config.toggle_combo = c; }, "F3");
    DMKConfig::register_key_combo("Hotkeys", "HoldScrollKey", "Hold Scroll Keys",
        [](const DMKKeyCombo& c) { g_mod_config.hold_scroll_combo = c; }, "");

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

    // Register hotkey bindings with the InputManager (after hooks are ready)
    DMKInputManager& input_mgr = DMKInputManager::get_instance();

    if (!g_mod_config.toggle_combo.keys.empty()) {
        input_mgr.register_press("toggle_view", g_mod_config.toggle_combo.keys,
            g_mod_config.toggle_combo.modifiers, []() {
                DMKLogger::get_instance().info("Toggle key pressed!");
            });
    }

    if (!g_mod_config.hold_scroll_combo.keys.empty()) {
        input_mgr.register_hold("hold_scroll", g_mod_config.hold_scroll_combo.keys,
            g_mod_config.hold_scroll_combo.modifiers, [](bool held) {
                DMKLogger::get_instance().info("Hold scroll: {}", held ? "active" : "released");
            });
    }

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

// WARNING: Calling join() on a thread inside DllMain can deadlock due to the
// loader lock. Offload initialization to a worker thread so start() runs
// outside DllMain, and call DMK_Shutdown() before DLL_PROCESS_DETACH
// (e.g., from a game shutdown hook or an explicit trigger).

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

## Configuration File Example

Create a `MyMod.ini` file alongside your DLL:

```ini
[Hooks]
EnableGreetingHook=true

[Debug]
LogLevel=INFO

[Hotkeys]
; Named keys (recommended)
ToggleKey=F3,F1              ; F3 or F1 (comma = OR)
HoldScrollKey=LShift         ; Left Shift
DebugCombo=Ctrl+Shift+D      ; Ctrl AND Shift AND D (plus = AND for modifiers, last = trigger)

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
| PS4 DualShock 4 | Via [DS4Windows](https://github.com/Ryochan7/DS4Windows) or Steam Input |
| PS5 DualSense | Via [DualSenseX](https://github.com/Jehan-HENRY/DualSenseX) or Steam Input |
| Nintendo Switch Pro | Via [BetterJoy](https://github.com/Davidobot/BetterJoy) or Steam Input |
| Generic USB gamepads | Only if the controller exposes an XInput interface |

**Why XInput only?** DetourModKit's input system is designed for mod hotkeys and toggles, not for replacing a game's primary input handling. XInput covers Xbox controllers natively, and the vast majority of PC players using non-Xbox controllers already use Steam Input or similar remapping tools that present their controller as XInput. Adding DirectInput or Windows.Gaming.Input would significantly increase complexity for a use case where XInput + keyboard/mouse covers nearly all real users.

**Limitations:**

* Maximum 4 controllers (XInput hard limit, indices 0-3).
* Analog triggers (LT/RT) and thumbstick axes are treated as digital buttons with configurable deadzone thresholds.
* No event-driven hot-plug detection; controller connection is checked via polling (reconnection attempts are throttled to every 2 seconds when disconnected).

## Projects Using DetourModKit

For practical reference and real-world usage examples:

* **OBR-NoCarryWeight**: [https://github.com/tkhquang/OBRTools/tree/main/NoCarryWeight](https://github.com/tkhquang/OBRTools/tree/main/NoCarryWeight)
* **KCD1-TPVToggle**: [https://github.com/tkhquang/KCD1Tools/tree/main/TPVToggle](https://github.com/tkhquang/KCD1Tools/tree/main/TPVToggle)
* **KCD2-TPVToggle**: [https://github.com/tkhquang/KCD2Tools/tree/main/TPVToggle](https://github.com/tkhquang/KCD2Tools/tree/main/TPVToggle)

## License

DetourModKit is licensed under the **MIT License**. See the `LICENSE` file in the repository for full details.

This project incorporates components from other open-source projects. Please refer to the [DetourModKit_Acknowledgements.txt](/DetourModKit_Acknowledgements.txt) file for a list of these components and their respective licenses:

* **SafetyHook:** Boost Software License 1.0
* **SimpleIni:** MIT License
* **DirectXMath:** MIT License
* **Zydis & Zycore (dependencies of SafetyHook):** MIT License

Users of DetourModKit are responsible for ensuring compliance with all included licenses.

## Contributing

Contributions to DetourModKit are welcome! If you have bug fixes, feature enhancements, or other improvements, please feel free to open an issue to discuss or submit a pull request.
