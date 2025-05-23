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
*   **Math Utilities:** Provides basic mathematical utility functions.

## Prerequisites

*   A C++ compiler supporting C++23 (e.g., MinGW g++ 12+ or newer, MSVC latest). The Makefile defaults to g++.
*   `make` (e.g., `mingw32-make` for MinGW environments).
*   CMake (version 3.15 or newer recommended, required to build the SafetyHook dependency).
*   Git (for cloning and managing submodules).

## Building DetourModKit (Static Library)

1.  **Clone the repository (with submodules):**
    ```bash
    git clone --recursive https://github.com/tkhquang/DetourModKit.git
    cd DetourModKit
    ```
    If you've already cloned without `--recursive`:
    ```bash
    git submodule update --init --recursive
    ```

2.  **Build the Kit & Install:**
    The primary way to build DetourModKit is using the `install` target, which prepares it for consumption by other projects.
    ```bash
    make install
    ```
    This command will:
    *   Attempt to build the **SafetyHook** dependency (and its own dependencies like Zydis/Zycore) using CMake if its main library (`libsafetyhook.a`) is not found in `external/safetyhook/build/`. This typically creates Release builds of these libraries.
    *   Compile DetourModKit source files from the `src/` directory.
    *   Create the static library `libDetourModKit.a`.
    *   Copy `libDetourModKit.a` and the dependency libraries (`libsafetyhook.a`, `libZydis.a`, `libZycore.a`) to `build/install/lib/`.
    *   Copy public DetourModKit header files (from `include/DetourModKit/`) to `build/install/include/DetourModKit/`.

    After `make install`, the `build/install/` directory will contain:
    ```
    build/install/
    ├── include/
    │   └── DetourModKit/
    │       ├── aob_scanner.hpp
    │       ├── config.hpp
    │       ├── filesystem_utils.hpp
    │       ├── hook_manager.hpp
    │       ├── logger.hpp
    │       ├── math_utils.hpp
    │       ├── memory_utils.hpp
    │       └── string_utils.hpp
    └── lib/
        ├── libDetourModKit.a
        ├── libsafetyhook.a
        ├── libZydis.a
        └── libZycore.a
    ```

    *   **Note on SafetyHook Build:** The paths to SafetyHook's built libraries (`BUILT_SAFETYHOOK_LIB`, etc. in the Makefile) are based on a common CMake output structure. If SafetyHook (or its dependencies Zydis/Zycore) builds its libraries to different subdirectories within `external/safetyhook/build/`, you might need to adjust these paths in the Makefile.

## Using DetourModKit in Your Mod Project

1.  **Integrate DetourModKit:**
    *   After running `make install` in the DetourModKit project, copy the entire `build/install/` directory into your mod project (e.g., into an `external/DetourModKit_Installed/` subdirectory).
    *   Alternatively, configure your mod's build system to find headers and libraries directly from DetourModKit's `build/install/` path.

2.  **Configure Your Mod's Build System (Example using g++):**
    *   **Include Paths:** Add `-Ipath/to/your/DetourModKit_Installed/include` to your compiler flags.
    *   **Library Paths:** Add `-Lpath/to/your/DetourModKit_Installed/lib` to your linker flags.
    *   **Link Libraries:** Link your mod against the following (order can matter for static libs):
        *   `-lDetourModKit`
        *   `-lsafetyhook`
        *   `-lZydis`
        *   `-lZycore`
        *   Necessary system libraries (e.g., on MinGW: `-lpsapi`, `-luser32`, `-lkernel32`, `-lshell32`, `-lole32`, `-lshlwapi`). `-static-libgcc -static-libstdc++` are also common if distributing standalone.

    Example linker command fragment for a g++ MinGW project:
    ```bash
    g++ your_mod_objects.o -o YourMod.asi -shared \
        -Lpath/to/DetourModKit_Installed/lib \
        -lDetourModKit -lsafetyhook -lZydis -lZycore \
        -lpsapi -luser32 -lkernel32 -lshlwapi \
        -static-libgcc -static-libstdc++
    ```

3.  **Using Kit Components (Conceptual Example):**

    ```c++
    // MyMod/src/main.cpp
    #include <DetourModKit/logger.hpp>
    #include <DetourModKit/config.hpp>
    #include <DetourModKit/hook_manager.hpp>
    #include <DetourModKit/aob_scanner.hpp>
    #include <DetourModKit/memory_utils.hpp>
    #include <DetourModKit/string_utils.hpp>

    // Your mod's configuration structure
    struct ModConfig {
        bool feature_enabled = true;
        float some_float_value = 1.23f;
        std::string log_level_str = "INFO";
        std::vector<int> hotkeys; // e.g. for VK_F1, VK_CONTROL
    } g_my_config;

    void InitializeMyMod() {
        // 1. Configure logger (optional, call before first getInstance() for custom defaults)
        Logger::configure("MyCoolMod", "MyCoolMod.log", "%Y-%m-%d %H:%M:%S.%f"); // Example with ms
        Logger& logger = Logger::getInstance();

        // 2. Register your mod's configuration variables
        //    Provide: INI section, INI key, logging name, your variable, default value
        DetourModKit::Config::registerBool("Main", "EnableCoolFeature", "Cool Feature Enabled", g_my_config.feature_enabled, true);
        DetourModKit::Config::registerFloat("Values", "MyFloat", "My Float Value", g_my_config.some_float_value, 1.23f);
        DetourModKit::Config::registerString("Debug", "LogLevel", "Log Level", g_my_config.log_level_str, "INFO");
        DetourModKit::Config::registerKeyList("Hotkeys", "ToggleView", "Toggle View Hotkeys", g_my_config.hotkeys, "0x71,0x11"); // Default: F2 + Ctrl

        // 3. Load config from INI file (e.g., MyCoolMod.ini)
        DetourModKit::Config::load("MyCoolMod.ini"); // Assumes INI is next to the mod DLL

        // 4. Apply loaded settings (e.g., log level)
        logger.setLogLevel(Logger::stringToLogLevel(g_my_config.log_level_str));

        // 5. Log loaded config for verification
        logger.log(LOG_INFO, "MyCoolMod configuration loaded and applied.");
        DetourModKit::Config::logAll(); // Logs all registered values

        // Example usage:
        if (g_my_config.feature_enabled) {
            logger.log(LOG_INFO, "Cool feature is active! Float value: " + std::to_string(g_my_config.some_float_value));
            logger.log(LOG_INFO, "Hotkeys to toggle view: " + format_vkcode_list(g_my_config.hotkeys));
        }

        // 6. Use other DetourModKit features...
        // HookManager& hm = HookManager::getInstance();
        // ...
    }

    // Optional shutdown logic
    void ShutdownMyMod() {
        Logger::getInstance().log(LOG_INFO, "MyCoolMod shutting down.");
        HookManager::getInstance().remove_all_hooks();
        DetourModKit::Config::clearRegisteredItems(); // Good practice if re-initialization is possible
    }

    // Example DllMain for an ASI mod
    // #include <windows.h>
    // BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    //     if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    //         DisableThreadLibraryCalls(hModule); // Optional: For ASI plugins to prevent DllMain calls on thread attach/detach
    //         InitializeMyMod();
    //     } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
    //         ShutdownMyMod();
    //     }
    //     return TRUE;
    // }
    ```

## License

DetourModKit is licensed under the **MIT License**. See the `LICENSE` file in the repository for full details.

This project incorporates components from other open-source projects. Please refer to the [DetourModKit_Acknowledgements.txt](/docs/DetourModKit_Acknowledgements.txt) file for a list of these components and their respective licenses:
*   **SafetyHook:** Boost Software License 1.0
*   **SimpleIni:** MIT License
*   **Zydis & Zycore (dependencies of SafetyHook):** MIT License

Users of DetourModKit are responsible for ensuring compliance with all included licenses.

## Contributing

Contributions to DetourModKit are welcome! If you have bug fixes, feature enhancements, or other improvements, please feel free to open an issue to discuss or submit a pull request.
