# DetourModKit (WIP)

DetourModKit is a lightweight C++ toolkit designed to simplify common tasks in game modding, particularly for creating mods that involve memory scanning, hooking, and configuration management. It is built with MinGW in mind but aims for general C++ compatibility.

## Features

*   **AOB Scanner:** Find array-of-bytes (signatures) in memory.
*   **Hook Manager:** A wrapper around [SafetyHook](https://github.com/cursey/safetyhook) for creating and managing inline and mid-function hooks.
*   **Configuration Loader:** Simple INI file parsing using X-Macros for easy definition of configuration variables (powered by [SimpleIni](https://github.com/brofield/simpleini)).
*   **Logger:** A basic singleton logger for outputting messages to a file and/or console.
*   **Memory Utilities:** Functions for checking memory readability/writability and writing bytes, with an optional memory region cache.
*   **String Utilities:** Helpers for formatting addresses, hex values, etc.
*   **Filesystem Utilities:** Basic filesystem operations like getting the module's runtime directory.
*   **Math Utilities:** Simple Vector3 and Quaternion structures (leveraging DirectXMath).

## Prerequisites

*   A C++ compiler supporting C++23 (e.g., MinGW g++).
*   `make` (e.g., mingw32-make).
*   CMake (required to build the SafetyHook dependency).
*   Git (for cloning and managing submodules).

## Building DetourModKit

1.  **Clone the repository (with submodules):**
    ```bash
    git clone --recursive https://github.com/tkhquang/DetourModKit.git
    cd DetourModKit
    ```
    If you've already cloned without `--recursive`:
    ```bash
    git submodule update --init --recursive
    ```

2.  **Build the kit (creates `libDetourModKit.a` and installs headers):**
    ```bash
    make install
    ```
    This will build the static library and place it along with public headers into the `build/install/` directory.

## Using DetourModKit in Your Mod Project

1.  **Include DetourModKit:**
    *   Copy the `build/install/` directory (or its contents) from DetourModKit into your mod project (e.g., into an `external/DetourModKit_Installed/` directory).
    *   Alternatively, if using DetourModKit as a submodule, you can point your build system to its `build/install/` path after building it.

2.  **Configure Your Mod's Build System (Makefile/CMake):**
    *   **Include Paths:** Add `path/to/your/DetourModKit_Installed/include` to your compiler's include paths.
    *   **Link Libraries:** Link your mod against:
        *   `path/to/your/DetourModKit_Installed/lib/libDetourModKit.a`
        *   The SafetyHook, Zydis, and Zycore static libraries (these should ideally also be copied to `DetourModKit_Installed/lib/` by the kit's `make install` for convenience, or you'll need to locate them in DetourModKit's `external/safetyhook/build/` structure).
        *   Necessary system libraries (e.g., `-lpsapi`, `-lkernel32`).

3.  **Define Your Configuration (`config_entries.h`):**
    *   Create a `config_entries.h` file in your mod's source directory. This file will define your mod-specific configuration variables using the macros provided by DetourModKit.
    *   Example `config_entries.h`:
        ```c++
        // MyMod/src/config_entries.h
        #ifndef MY_MOD_CONFIG_ENTRIES_H
        #define MY_MOD_CONFIG_ENTRIES_H

        //      SECTION         INI_KEY             VAR_NAME                DEFAULT_VALUE
        CONFIG_BOOL("Main",     "EnableFeatureX",   enable_feature_x,       true)
        CONFIG_INT("Settings",  "UpdateInterval",   update_interval_ms,     100)
        CONFIG_STRING("General", "Greeting",        greeting_message,       "Hello from MyMod!")
        CONFIG_KEY_LIST("Hotkeys","ToggleKey",      toggle_keys,            "0x70") // F1

        // This indicates to the kit's config.cpp that log_level is a defined member.
        // Make sure the actual std::string log_level; is also defined via CONFIG_STRING.
        // This line could be replaced by more advanced C++ techniques (SFINAE, concepts) in the kit if desired.
        #define CONFIG_HAS_LOG_LEVEL_MEMBER true
        CONFIG_STRING("Debug",   "LogLevel",        log_level,              "INFO")


        #endif // MY_MOD_CONFIG_ENTRIES_H
        ```

4.  **Using Kit Components:**
    ```c++
    #include <DetourModKit/logger.h>
    #include <DetourModKit/config.h> // This will include your mod's config_entries.h
    // ... other kit headers

    // In your mod's main.cpp or dllmain.cpp
    // Assuming 'Config' struct comes from DetourModKit/config.h
    Config g_modConfig;

    void InitializeMod() {
        DetourModKit::Logger::configure("MyMod", "MyMod.log", "%Y-%m-%d %H:%M:%S");
        DetourModKit::Logger& logger = DetourModKit::Logger::getInstance();

        // If DetourModKit's config.cpp is compiled by your mod:
        g_modConfig = DetourModKit::loadConfig("MyMod.ini");
        DetourModKit::logConfig(g_modConfig);

        // If g_modConfig.log_level string exists (due to your config_entries.h):
        // DetourModKit::LogLevel level = ... convert g_modConfig.log_level to enum ...;
        // logger.setLogLevel(level);

        logger.log(DetourModKit::LOG_INFO, "MyMod Initialized using DetourModKit!");
        logger.log(DetourModKit::LOG_INFO, g_modConfig.greeting_message); // Accessing your specific config
    }
    ```
    *Remember to compile `DetourModKit/src/config.cpp` as part of your mod's build process if using the X-Macro approach for configuration where `config.cpp` needs to see your mod's `config_entries.h`.*

## License

DetourModKit is licensed under the **MIT License**. See `LICENSE` file for details.

This project utilizes several third-party libraries. Their respective licenses can be found in the `DetourModKit_Acknowledgements.txt`:
*   **SafetyHook:** Boost Software License 1.0
*   **SimpleIni:** MIT License
*   **DirectXMath:** MIT License
*   **Zydis & Zycore (via SafetyHook):** MIT License

Please ensure compliance with all included licenses when using DetourModKit.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
