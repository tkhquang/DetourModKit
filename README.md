# DetourModKit

DetourModKit is a lightweight C++ toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, and configuration management. It is built with MinGW in mind but aims for general C++ compatibility.

## Features

*   **AOB Scanner:** Find array-of-bytes (signatures) in memory with wildcard support.
*   **Hook Manager:** A C++ wrapper around [SafetyHook](https://github.com/cursey/safetyhook) for creating and managing inline and mid-function hooks, by direct address or AOB scan.
*   **Configuration System:** Load settings from INI files. Mods register their configuration variables and the kit handles parsing and value assignment. (Powered by [SimpleIni](https://github.com/brofield/simpleini)).
*   **Logger:** A flexible singleton logger for outputting messages to a log file. Supports configurable log levels, timestamps, and prefixes.
*   **Memory Utilities:** Functions for checking memory readability/writability and writing bytes to memory. Includes an optional memory region cache.
*   **String Utilities:** Helper functions for formatting addresses, hexadecimal values, virtual key codes, etc.
*   **Filesystem Utilities:** Basic filesystem operations, notably getting the current module's runtime directory.
*   **Math Utilities:** Provides basic mathematical utility functions (e.g., angle conversions).

## Prerequisites

*   A C++ compiler supporting C++23:
    *   MinGW g++ 12+ (recommended for cross-platform compatibility)
    *   Microsoft Visual Studio 2022 (MSVC v143)
*   CMake 3.16 or newer
*   Git (for cloning and managing submodules)

## Building DetourModKit

This project uses CMake as the primary build system to ensure cross-compiler compatibility and proper dependency management.

### 1. Clone the Repository

```bash
git clone --recursive https://github.com/tkhquang/DetourModKit.git
cd DetourModKit
```

If you've already cloned without `--recursive`:
```bash
git submodule update --init --recursive
```

### 2. Build with CMake

#### Option A: MinGW (Recommended)

```bash
# Configure
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release --parallel

# Install to build/install directory
cmake --install build --config Release
```

#### Option B: Visual Studio (MSVC)

```bash
# Configure
cmake -S . -B build -G "Visual Studio 17 2022" -A x64

# Build
cmake --build build --config Release --parallel

# Install to build/install directory
cmake --install build --config Release
```

#### Option C: Custom Install Location

```bash
# Configure with custom install prefix
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="C:/MyLibraries/DetourModKit"

# Build and install
cmake --build build --config Release --parallel
cmake --install build --config Release
```

### 3. Build Output

After running `cmake --install`, you'll find the following structure in your install directory:

```
install/
├── include/
│   ├── DetourModKit/             # DetourModKit public headers
│   │   ├── aob_scanner.hpp
│   │   ├── config.hpp
│   │   ├── hook_manager.hpp
│   │   ├── logger.hpp
│   │   ├── memory_utils.hpp
│   │   ├── string_utils.hpp
│   │   ├── filesystem_utils.hpp
│   │   └── math_utils.hpp
│   ├── safetyhook/               # SafetyHook headers
│   ├── safetyhook.hpp
│   └── SimpleIni.h
├── lib/
│   ├── libDetourModKit.a/.lib    # Main library
│   ├── libsafetyhook.a/.lib      # SafetyHook library
│   ├── libZydis.a/.lib           # Zydis disassembler
│   └── libZycore.a/.lib          # Zycore utilities
├── lib/cmake/DetourModKit/       # CMake package config
└── share/doc/DetourModKit/       # Documentation
```

## Using DetourModKit in Your Project

### CMake Integration (Recommended)

1. **Using find_package (after installation):**

```cmake
# In your CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(MyMod)

set(CMAKE_CXX_STANDARD 23)

# Find DetourModKit
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

2. **Using as a subdirectory:**

```cmake
# Add DetourModKit as a subdirectory
add_subdirectory(external/DetourModKit)

# Link against it
target_link_libraries(MyMod PRIVATE DetourModKit)
```

### Manual Integration

If not using CMake, copy the installed files to your project and configure your build system:

```makefile
# Example Makefile
CXX = g++
CXXFLAGS = -std=c++23 -I./external/DetourModKit/include
LDFLAGS = -L./external/DetourModKit/lib
LIBS = -lDetourModKit -lsafetyhook -lZydis -lZycore -lpsapi -luser32 -lkernel32

MyMod.asi: src/main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ -shared $(LDFLAGS) $(LIBS)
```

## Usage Example

```cpp
#include <windows.h>
#include <DetourModKit/logger.hpp>
#include <DetourModKit/config.hpp>
#include <DetourModKit/hook_manager.hpp>
#include <DetourModKit/aob_scanner.hpp>
#include <DetourModKit/filesystem_utils.hpp>

namespace DMK = DetourModKit;

struct ModConfig {
    bool enable_hook = true;
    std::string log_level = "INFO";
} g_config;

// Example hook target
typedef void (__stdcall *OriginalFunction_t)(const char* message);
OriginalFunction_t original_function = nullptr;

void __stdcall DetourFunction(const char* message) {
    DMK::Logger::getInstance().log(DMK::LOG_INFO, "Hook called with: " + std::string(message));

    if (original_function) {
        original_function("Modified by DetourModKit!");
    }
}

void InitializeMod() {
    // Configure logger
    DMK::Logger::configure("MyMod", "MyMod.log", "%Y-%m-%d %H:%M:%S");
    auto& logger = DMK::Logger::getInstance();

    // Register configuration
    DMK::Config::registerBool("General", "EnableHook", "Enable Hook", g_config.enable_hook, true);
    DMK::Config::registerString("Debug", "LogLevel", "Log Level", g_config.log_level, "INFO");

    // Load configuration
    DMK::Config::load("MyMod.ini");
    logger.setLogLevel(DMK::Logger::stringToLogLevel(g_config.log_level));

    // Create hooks
    auto& hook_manager = DMK::HookManager::getInstance();

    // Example: Hook via AOB scan
    HMODULE module = GetModuleHandleA(nullptr);
    MODULEINFO module_info;
    GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(module_info));

    std::string hook_id = hook_manager.create_inline_hook_aob(
        "ExampleHook",
        reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll),
        module_info.SizeOfImage,
        "48 89 5C 24 ?? 57 48 83 EC 20",  // Assume unique
        0,  // Pattern offset
        reinterpret_cast<void*>(DetourFunction),
        reinterpret_cast<void**>(&original_function)
    );

    if (!hook_id.empty()) {
        logger.log(DMK::LOG_INFO, "Successfully created hook: " + hook_id);
    }

    logger.log(DMK::LOG_INFO, "Mod initialization complete!");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeMod();
    }
    return TRUE;
}
```

## Configuration File Example

Create a `MyMod.ini` file alongside your DLL:

```ini
[General]
EnableHook=true

[Debug]
LogLevel=INFO

[Hotkeys]
ToggleKey=0x72,0x70  # F3, F1 (hex VK codes)
```

## Development and Releases

This project uses GitHub Actions for automated building and releasing:

- **Pull Requests:** Automatically build and test on both MinGW and MSVC
- **Releases:** Manual workflow dispatch creates releases for both compiler environments
- **Artifacts:** Each release includes packages for MinGW and MSVC with all necessary libraries and headers

## License

DetourModKit is licensed under the **MIT License**. See the `LICENSE` file for full details.

This project incorporates components from other open-source projects. Please refer to `DetourModKit_Acknowledgements.txt` for a list of these components and their respective licenses:

*   **SafetyHook:** Boost Software License 1.0
*   **SimpleIni:** MIT License
*   **Zydis & Zycore:** MIT License

## Contributing

Contributions to DetourModKit are welcome! Please feel free to open issues for bug reports or feature requests, and submit pull requests for improvements.

### Building for Development

For development, you can use the same CMake commands but with debug configuration:

```bash
# Debug build
cmake -S . -B build_debug -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug
cmake --build build_debug --config Debug
```

This enables additional debugging features like memory cache statistics and verbose logging.
