# DetourModKit

[![CI - Tests & Coverage](https://github.com/tkhquang/DetourModKit/actions/workflows/ci.yml/badge.svg)](https://github.com/tkhquang/DetourModKit/actions/workflows/ci.yml)
![Coverage: 80%+](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen)

DetourModKit is a lightweight C++ toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, and configuration management. It is built with MinGW in mind but aims for general C++ compatibility.

## Features

* **AOB Scanner:** Find array-of-bytes (signatures) in memory with wildcard support.
* **Hook Manager:** A C++ wrapper around [SafetyHook](https://github.com/cursey/safetyhook) for creating and managing inline and mid-function hooks, by direct address or AOB scan.
* **Configuration System:** Load settings from INI files. Mods register their configuration variables (defined in the mod's code) and the kit handles parsing and value assignment. (Powered by [SimpleIni](https://github.com/brofield/simpleini)).
* **Logger:** A flexible singleton logger for outputting messages to a log file. Supports configurable log levels, timestamps, and prefixes. Features **async logging** for high-throughput scenarios and **format string placeholders** for concise log messages.
* **Async Logger:** A lock-free, bounded queue-based async logger that decouples log message production from file I/O. Designed for minimal latency on the producer side with batched writes on the consumer thread.
* **Memory Utilities:** Functions for checking memory readability/writability and writing bytes to memory. Includes an optional memory region cache.
* **String Utilities:** Helper functions for formatting addresses, hexadecimal values, virtual key codes, etc.
* **Format Utilities:** Custom formatters for game modding types (memory addresses, byte values, VK codes) with C++20 `std::format` support.
* **Filesystem Utilities:** Basic filesystem operations, notably getting the current module's runtime directory.
* **Math Utilities:** Provides basic mathematical utility functions (e.g., angle conversions).

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
    │   │   ├── math.hpp              <-- DirectXMath-powered math utilities
    │   │   ├── memory.hpp            <-- Memory utilities
    │   │   ├── filesystem.hpp        <-- Filesystem utilities
    │   │   ├── hook_manager.hpp      <-- Hook management
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

    // Register your configuration variables
    DMKConfig::register_bool("Hooks", "EnableGreetingHook", "Enable Greeting Hook", g_mod_config.enable_greeting_hook, true);
    DMKConfig::register_string("Debug", "LogLevel", "Log Level", g_mod_config.log_level_setting, "INFO");

    // Load configuration from INI file
    DMKConfig::load("MyMod.ini");

    // Apply LogLevel from loaded configuration
    logger.set_log_level(DMKLogger::string_to_log_level(g_mod_config.log_level_setting));

    // Log the loaded configuration using format string placeholders
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
            // Using format string placeholders with custom formatters
            logger.debug("Scanning module at {} size {}",
                         DMKFormat::format_address(reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll)),
                         module_info.SizeOfImage);

            // Replace with actual AOB pattern from your target game
            std::string aob_sig_str = "48 89 ?? ?? 57";
            ptrdiff_t pattern_offset = 0;

            std::vector<std::byte> pattern_bytes = DMKScanner::parse_aob(aob_sig_str);
            if (!pattern_bytes.empty()) {
                std::byte* found_pattern = DMKScanner::find_pattern(
                    reinterpret_cast<std::byte*>(module_info.lpBaseOfDll),
                    module_info.SizeOfImage,
                    pattern_bytes
                );
                if (found_pattern) {
                    target_function_address = reinterpret_cast<uintptr_t>(found_pattern) + pattern_offset;
                    logger.info("Pattern for GameFunction_PrintMessage found at: {}, target address: {}",
                                DMKFormat::format_address(reinterpret_cast<uintptr_t>(found_pattern)),
                                DMKFormat::format_address(target_function_address));
                } else {
                    logger.error("AOB pattern for GameFunction_PrintMessage not found in target module.");
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
        std::string hook_id = hook_manager.create_inline_hook(
            "GameFunction_PrintMessage_Hook",
            target_function_address,
            reinterpret_cast<void*>(Detour_GameFunction_PrintMessage),
            reinterpret_cast<void**>(&original_GameFunction_PrintMessage),
            hook_cfg
        );

        if (!hook_id.empty()) {
            logger.info("Successfully created hook: {}", hook_id);
        } else {
            logger.error("Failed to create hook for GameFunction_PrintMessage.");
        }
    } else {
        logger.warning("Target address for GameFunction_PrintMessage is 0 or not found. Hook not created.");
    }

    logger.info("MyMod Initialized using DetourModKit!");
}

// Mod Shutdown Function (optional)
void ShutdownMyMod() {
    DMKLogger& logger = DMKLogger::get_instance();
    logger.info("MyMod Shutting Down...");

    DMKHookManager::get_instance().remove_all_hooks();
    DMKConfig::clear_registered_items();

    // Flush any pending async log messages
    logger.flush();

    logger.info("MyMod Shutdown Complete.");
}

// DLL Main or equivalent entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeMyMod();
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        ShutdownMyMod();
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
ToggleKey=0x72,0x70  # F3, F1 (hex VK codes)
```

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
