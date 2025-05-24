# DetourModKit

DetourModKit is a lightweight C++ toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, and configuration management. It is built with MinGW in mind but aims for general C++ compatibility.

## Features

*   **AOB Scanner:** Find array-of-bytes (signatures) in memory with wildcard support.
*   **Hook Manager:** A C++ wrapper around [SafetyHook](https://github.com/cursey/safetyhook) for creating and managing inline and mid-function hooks, by direct address or AOB scan.
*   **Configuration System:** Load settings from INI files. Mods register their configuration variables (defined in the mod's code) and the kit handles parsing and value assignment. (Powered by [SimpleIni](https://github.com/brofield/simpleini)).
*   **Logger:** A flexible singleton logger for outputting messages to a log file. Supports configurable log levels, timestamps, and prefixes.
*   **Memory Utilities:** Functions for checking memory readability/writability and writing bytes to memory. Includes an optional memory region cache.
*   **String Utilities:** Helper functions for formatting addresses, hexadecimal values, virtual key codes, etc.
*   **Filesystem Utilities:** Basic filesystem operations, notably getting the current module's runtime directory.
*   **Math Utilities:** Provides basic mathematical utility functions (e.g., angle conversions).

## Prerequisites

*   A C++ compiler supporting C++23 (e.g., MinGW g++ 12+ or newer). The Makefile defaults to g++.
*   `make` (e.g., `mingw32-make` for MinGW environments).
*   CMake (version 3.16 or newer recommended, required to build the SafetyHook dependency).
*   Git (for cloning and managing submodules).

## Building DetourModKit (Static Library via CMake)

This project uses CMake to orchestrate its build and the build of its SafetyHook dependency.

1.  **Clone the repository (with submodules):**
    ```bash
    git clone --recursive https://github.com/tkhquang/DetourModKit.git
    cd DetourModKit
    ```
    If you've already cloned without `--recursive`:
    ```bash
    git submodule update --init --recursive
    ```

2.  **Build & Package for Distribution:**

    ### MinGW (Recommended)
    ```bash
    # Configure
    cmake -S . -B build_mingw -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="./install_package_mingw"

    # Build
    cmake --build build_mingw --config Release --parallel

    # Install
    cmake --install build_mingw --config Release
    ```

    ### Visual Studio (MSVC)
    ```bash
    # Configure
    cmake -S . -B build_msvc -G "Visual Studio 17 2022" -A x64 -DCMAKE_INSTALL_PREFIX="./install_package_msvc"

    # Build
    cmake --build build_msvc --config Release --parallel

    # Install
    cmake --install build_msvc --config Release
    ```

    After running the install command, the `install_package_mingw/` or `install_package_msvc/` directory will contain a structure ready for consumption:
    ```
    install_package_mingw/
    ├── include/
    │   ├── DetourModKit/             <-- DetourModKit public headers
    │   │   ├── aob_scanner.hpp
    │   │   ├── config.hpp
    │   │   ├── ...
    │   │   └── string_utils.hpp
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

## Using DetourModKit in Your Mod Project

1.  **Integrate DetourModKit:**
    *   After building DetourModKit, copy the entire `install_package_mingw/` or `install_package_msvc/` directory into your mod project (e.g., into an `external/DetourModKit/` subdirectory).
    *   Alternatively, adjust your mod's build system to point to DetourModKit's install directory directly.

2.  **Configure Your Mod's Build System:**

    ### CMake (Recommended)
    ```cmake
    # In your mod's CMakeLists.txt
    cmake_minimum_required(VERSION 3.16)
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

    ### Makefile (Example for g++ MinGW)
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

3.  **Using Kit Components in Your Mod:**

    ```c++
    // MyMod/src/main.cpp
    #include <windows.h>

    #include <DetourModKit/logger.hpp>
    #include <DetourModKit/config.hpp>
    #include <DetourModKit/hook_manager.hpp>
    #include <DetourModKit/aob_scanner.hpp>
    #include <DetourModKit/string_utils.hpp>
    #include <DetourModKit/filesystem_utils.hpp>

    #include <safetyhook.hpp>
    #include <SimpleIni.h>

    // Using convenience aliases for DetourModKit namespaces if desired
    namespace DMK = DetourModKit;
    namespace DMKConfig = DetourModKit::Config;
    namespace DMKAOB = DetourModKit::AOB;
    namespace DMKString = DetourModKit::String;

    // --- Global variables for your mod's configuration ---
    struct ModConfiguration {
        bool enable_greeting_hook = true;
        std::string log_level_setting = "INFO";
    } g_mod_config;

    // --- Example Hook: Target function signature ---
    typedef void (__stdcall *OriginalGameFunction_PrintMessage_t)(const char* message, int type);
    OriginalGameFunction_PrintMessage_t original_GameFunction_PrintMessage = nullptr;

    // Detour function
    void __stdcall Detour_GameFunction_PrintMessage(const char* message, int type) {
        DMK::Logger& logger = DMK::Logger::getInstance();
        logger.log(DMK::LOG_INFO, "Detour_GameFunction_PrintMessage CALLED! Original message: \"" + std::string(message) + "\", type: " + std::to_string(type));

        if (g_mod_config.enable_greeting_hook) {
            logger.log(DMK::LOG_DEBUG, "Modifying message because greeting hook is enabled.");
            if (original_GameFunction_PrintMessage) {
                original_GameFunction_PrintMessage("Hello from DetourModKit! Hooked!", type + 100);
            }
            return;
        }

        if (original_GameFunction_PrintMessage) {
            original_GameFunction_PrintMessage(message, type);
        }
    }

    // --- Mod Initialization Function ---
    void InitializeMyMod() {
        // 1. Configure the Logger
        DMK::Logger::configure("MyMod", "MyMod.log", "%Y-%m-%d %H:%M:%S.%f");
        DMK::Logger& logger = DMK::Logger::getInstance();

        // 2. Register your configuration variables
        DMKConfig::registerBool("Hooks", "EnableGreetingHook", "Enable Greeting Hook", g_mod_config.enable_greeting_hook, true);
        DMKConfig::registerString("Debug", "LogLevel", "Log Level", g_mod_config.log_level_setting, "INFO");

        // 3. Load configuration from INI file
        DMKConfig::load("MyMod.ini");

        // 4. Apply LogLevel from loaded configuration
        logger.setLogLevel(DMK::Logger::stringToLogLevel(g_mod_config.log_level_setting));

        // 5. Log the loaded configuration
        logger.log(DMK::LOG_INFO, "MyMod configuration loaded and applied.");
        DMKConfig::logAll();

        // 6. Initialize Hooks
        DMK::HookManager& hook_manager = DMK::HookManager::getInstance();

        uintptr_t target_function_address = 0;

        // Example: AOB Scan
        HMODULE game_module = GetModuleHandleA(NULL); // Base executable
        if (game_module) {
            MODULEINFO module_info = {0};
            if (GetModuleInformation(GetCurrentProcess(), game_module, &module_info, sizeof(module_info))) {
                logger.log(DMK::LOG_DEBUG, "Scanning module at " + DMKString::format_address(reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll)) +
                                          " size " + std::to_string(module_info.SizeOfImage));

                // Replace with actual AOB pattern from your target game
                std::string aob_sig_str = "48 89 ?? ?? 57";
                ptrdiff_t pattern_offset = 0; // Offset from pattern start to function start

                std::vector<std::byte> pattern_bytes = DMKAOB::parseAOB(aob_sig_str);
                if (!pattern_bytes.empty()) {
                    std::byte* found_pattern = DMKAOB::FindPattern(
                        reinterpret_cast<std::byte*>(module_info.lpBaseOfDll),
                        module_info.SizeOfImage,
                        pattern_bytes
                    );
                    if (found_pattern) {
                        target_function_address = reinterpret_cast<uintptr_t>(found_pattern) + pattern_offset;
                        logger.log(DMK::LOG_INFO, "Pattern for GameFunction_PrintMessage found at: " +
                                                  DMKString::format_address(reinterpret_cast<uintptr_t>(found_pattern)) +
                                                  ", target address: " + DMKString::format_address(target_function_address));
                    } else {
                        logger.log(DMK::LOG_ERROR, "AOB pattern for GameFunction_PrintMessage not found in target module.");
                    }
                } else {
                     logger.log(DMK::LOG_ERROR, "Failed to parse AOB pattern: " + aob_sig_str);
                }
            } else {
                logger.log(DMK::LOG_ERROR, "GetModuleInformation failed: " + std::to_string(GetLastError()));
            }
        } else {
             logger.log(DMK::LOG_ERROR, "Failed to get game module handle.");
        }

        if (target_function_address != 0) {
            DMK::HookConfig hook_cfg; // Use default config (autoEnable = true)
            std::string hook_id = hook_manager.create_inline_hook(
                "GameFunction_PrintMessage_Hook",
                target_function_address,
                reinterpret_cast<void*>(Detour_GameFunction_PrintMessage),
                reinterpret_cast<void**>(&original_GameFunction_PrintMessage),
                hook_cfg
            );

            if (!hook_id.empty()) {
                logger.log(DMK::LOG_INFO, "Successfully created hook: " + hook_id);
            } else {
                logger.log(DMK::LOG_ERROR, "Failed to create hook for GameFunction_PrintMessage.");
            }
        } else {
            logger.log(DMK::LOG_WARNING, "Target address for GameFunction_PrintMessage is 0 or not found. Hook not created.");
        }

        logger.log(DMK::LOG_INFO, "MyMod Initialized using DetourModKit!");
    }

    // --- Mod Shutdown Function (optional) ---
    void ShutdownMyMod() {
        DMK::Logger& logger = DMK::Logger::getInstance();
        logger.log(DMK::LOG_INFO, "MyMod Shutting Down...");

        DMK::HookManager::getInstance().remove_all_hooks();
        DMKConfig::clearRegisteredItems();

        logger.log(DMK::LOG_INFO, "MyMod Shutdown Complete.");
    }

    // --- DLL Main or equivalent entry point ---
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

## License

DetourModKit is licensed under the **MIT License**. See the `LICENSE` file in the repository for full details.

This project incorporates components from other open-source projects. Please refer to the [DetourModKit_Acknowledgements.txt](/DetourModKit_Acknowledgements.txt) file for a list of these components and their respective licenses:
*   **SafetyHook:** Boost Software License 1.0
*   **SimpleIni:** MIT License
*   **Zydis & Zycore (dependencies of SafetyHook):** MIT License

Users of DetourModKit are responsible for ensuring compliance with all included licenses.

## Contributing

Contributions to DetourModKit are welcome! If you have bug fixes, feature enhancements, or other improvements, please feel free to open an issue to discuss or submit a pull request.
