# Hot-Reload Development Guide for DetourModKit Mods

## Problem Statement

The standard game mod development cycle requires restarting the game after every DLL rebuild:

```text
RE / Code Change → Build DLL → Kill Game → Relaunch Game → Wait for Load → Test → Repeat
```

For large games with 30s-2min+ load times, this creates significant dead time. A single day of active development can involve 30-50+ restarts, wasting 1-3 hours just on loading screens.

## Solution: Two-DLL Hot-Reload Architecture

Split your mod into two binaries:

| Binary           | Role                                   | Lifetime                      | Rebuild Frequency                       |
|------------------|----------------------------------------|-------------------------------|-----------------------------------------|
| `mod_loader.asi` | Thin loader stub                       | Lives for entire game session | Rarely (only when loader logic changes) |
| `mod_logic.dll`  | All mod code (hooks, features, config) | Loaded/unloaded on demand     | Every iteration                         |

The loader watches for a reload hotkey. When pressed, it tears down the logic DLL and reloads it from disk — **no game restart required**.

### Architecture Diagram

```text
game.exe (target process)
  │
  ├── mod_loader.asi            ← ASI loader injects this once at startup
  │     │
  │     ├── DllMain()           ← Spawns init thread, then returns
  │     ├── InitThread()        ← LoadLibrary("mod_logic.dll"), calls Init()
  │     ├── ReloadLogic()       ← Shutdown() → FreeLibrary → LoadLibrary → Init()
  │     └── Hotkey watcher      ← Polls for reload key (e.g., Numpad 0)
  │           │
  │           ▼
  │     mod_logic.dll           ← Unloaded and reloaded without restarting game
  │           │
  │           ├── Init()        ← Sets up hooks, config, input bindings
  │           ├── Shutdown()    ← Calls DMK_Shutdown(), cleans up all state
  │           └── (mod code)    ← Your actual features, hook callbacks, etc.
  │
  └── game modules...
```

### Data Flow: Reload Sequence

```text
User presses Numpad 0
        │
        ▼
  ┌─────────────────────┐
  │ 1. Disable hotkey    │  Prevent double-reload
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 2. Call Shutdown()   │  mod_logic.dll exported function
  │    └─ DMK_Shutdown() │  InputManager → HookManager → Memory → Config → Logger
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 3. FreeLibrary()     │  Unloads mod_logic.dll from process
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 4. LoadLibrary()     │  Loads fresh mod_logic.dll from disk
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 5. GetProcAddress()  │  Resolve Init / Shutdown exports
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 6. Call Init()       │  Re-create hooks, reload config, rebind inputs
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 7. Re-enable hotkey  │  Ready for next reload cycle
  └─────────────────────┘
```

---

## Implementation Guide

### Step 1: Define the Logic DLL Interface

The logic DLL exports exactly two C functions. Keep the interface minimal and stable so the loader rarely needs rebuilding.

**mod_logic/exports.hpp** (shared between loader and logic):

```cpp
#pragma once

// These are the only exported symbols from mod_logic.dll.
// Both use C linkage to avoid name mangling across compilers.

// Called after LoadLibrary. Sets up all hooks, config, input bindings.
// Returns true on success, false on initialization failure.
using InitFn = bool (__cdecl *)();

// Called before FreeLibrary. Tears down everything cleanly.
// Must be safe to call even if Init() partially failed.
using ShutdownFn = void (__cdecl *)();

// Export names used by GetProcAddress
constexpr const char* INIT_EXPORT     = "Init";
constexpr const char* SHUTDOWN_EXPORT = "Shutdown";
```

### Step 2: Implement the Logic DLL

This is where your actual mod code lives. It links against DetourModKit as a static library.

**mod_logic/dllmain.cpp:**

```cpp
#include "exports.hpp"
#include <DetourModKit.hpp>
#include <windows.h>

// ─── Forward declarations ───────────────────────────────────────────
static bool setup_hooks();
static void setup_config();
static void setup_input();

// ─── State ──────────────────────────────────────────────────────────
// All mod state lives here. It is reset on every reload.
static HMODULE s_this_module = nullptr;

// ─── Exported functions ─────────────────────────────────────────────

extern "C" __declspec(dllexport) bool Init()
{
    try
    {
        DMKLogger::configure("MyMod", "mod_logic.log", "%Y-%m-%d %H:%M:%S");
        auto& logger = DMKLogger::get_instance();
        logger.set_log_level(DMKLogLevel::Debug);
        logger.info("mod_logic: Init() called");

        setup_config();

        if (!setup_hooks())
        {
            logger.error("mod_logic: Hook setup failed — rolling back");
            DMK_Shutdown();
            return false;
        }

        setup_input();

        logger.info("mod_logic: Initialization complete");
        return true;
    }
    catch (const std::exception& e)
    {
        // C functions must not propagate exceptions across DLL boundaries.
        // Log to debugger output since Logger may not be initialized.
        std::string msg = std::string("mod_logic Init() exception: ") + e.what();
        OutputDebugStringA(msg.c_str());
        DMK_Shutdown();
        return false;
    }
    catch (...)
    {
        OutputDebugStringA("mod_logic Init() unknown exception");
        DMK_Shutdown();
        return false;
    }
}

extern "C" __declspec(dllexport) void Shutdown()
{
    auto& logger = DMKLogger::get_instance();
    logger.info("mod_logic: Shutdown() called");

    // DMK_Shutdown handles the correct teardown order:
    // InputManager → HookManager → Memory cache → Config → Logger
    DMK_Shutdown();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        s_this_module = hModule;
        // Do NOT initialize here — Init() is called explicitly by the loader
    }
    return TRUE;
}

// ─── Setup functions ────────────────────────────────────────────────

static bool setup_hooks()
{
    auto& hm = DMKHookManager::get_instance();

    // Example: hook a game function by AOB pattern
    // auto result = hm.create_inline_hook_aob(
    //     "camera_update",
    //     game_base, game_size,
    //     "48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? F3 0F",
    //     0,
    //     &detour_camera_update,
    //     reinterpret_cast<void**>(&original_camera_update)
    // );
    // return result.has_value();

    return true;
}

static void setup_config()
{
    // DMKConfig::register_float("Camera", "FOV", "Field of View",
    //     [](float val) { g_fov = val; }, 90.0f);
    // DMKConfig::load("mod_config.ini");
}

static void setup_input()
{
    // auto& input = DMKInputManager::get_instance();
    // input.start(...);
}
```

### Step 3: Implement the Loader ASI

The loader is intentionally minimal. It should almost never need rebuilding.

**mod_loader/dllmain.cpp:**

```cpp
#include <windows.h>
#include <string>
#include <atomic>

// ─── Configuration ──────────────────────────────────────────────────

// Reload hotkey — VK_NUMPAD0 (Numpad 0). Change as needed.
// Numpad keys are unlikely to conflict with game controls or InputManager bindings.
constexpr int RELOAD_KEY = VK_NUMPAD0;

// Name of the logic DLL (must be in same directory as the loader ASI)
constexpr const char* LOGIC_DLL_NAME = "mod_logic.dll";

// Polling interval for hotkey detection (milliseconds)
constexpr DWORD POLL_INTERVAL_MS = 100;

// Sleep durations (milliseconds)
constexpr DWORD CALLBACK_DRAIN_MS = 100;   // After Shutdown(): let in-flight callbacks return
constexpr DWORD FILE_SETTLE_MS    = 200;   // After FreeLibrary(): let file locks release

// ─── Types ──────────────────────────────────────────────────────────

using InitFn     = bool (__cdecl *)();
using ShutdownFn = void (__cdecl *)();

// ─── State ──────────────────────────────────────────────────────────

static HMODULE       s_loader_module  = nullptr;
static HMODULE       s_logic_module   = nullptr;
static InitFn        s_init_fn        = nullptr;
static ShutdownFn    s_shutdown_fn    = nullptr;
static std::string   s_logic_dll_path;
static std::atomic<bool> s_running{true};
static std::atomic<bool> s_reloading{false};

// ─── Helpers ────────────────────────────────────────────────────────

// Resolve the full path to mod_logic.dll relative to the loader ASI location
static std::string resolve_logic_dll_path()
{
    char path[MAX_PATH]{};
    GetModuleFileNameA(s_loader_module, path, MAX_PATH);

    std::string dir(path);
    const auto last_sep = dir.find_last_of("\\/");
    if (last_sep != std::string::npos)
    {
        dir = dir.substr(0, last_sep + 1);
    }

    return dir + LOGIC_DLL_NAME;
}

// Write to debugger output (always available, no logger dependency).
// Single OutputDebugStringA call prevents interleaving with other threads.
static void loader_log(const char* msg)
{
    char buf[512];
    const int len = snprintf(buf, sizeof(buf), "[mod_loader] %s\n", msg);
    if (len > 0 && static_cast<size_t>(len) < sizeof(buf))
        OutputDebugStringA(buf);
    else
        OutputDebugStringA("[mod_loader] (message truncated)\n");
}

// ─── Load / Unload logic DLL ────────────────────────────────────────

static bool load_logic_dll()
{
    loader_log("Loading logic DLL...");

    s_logic_module = LoadLibraryA(s_logic_dll_path.c_str());
    if (!s_logic_module)
    {
        DWORD err = GetLastError();
        std::string msg = "ERROR: LoadLibrary failed (error " + std::to_string(err) + "): "
                        + s_logic_dll_path;
        loader_log(msg.c_str());
        return false;
    }

    s_init_fn = reinterpret_cast<InitFn>(
        GetProcAddress(s_logic_module, "Init"));
    s_shutdown_fn = reinterpret_cast<ShutdownFn>(
        GetProcAddress(s_logic_module, "Shutdown"));

    if (!s_init_fn || !s_shutdown_fn)
    {
        loader_log("ERROR: Failed to resolve Init/Shutdown exports");
        FreeLibrary(s_logic_module);
        s_logic_module = nullptr;
        s_init_fn = nullptr;
        s_shutdown_fn = nullptr;
        return false;
    }

    if (!s_init_fn())
    {
        loader_log("ERROR: Init() returned false");
        FreeLibrary(s_logic_module);
        s_logic_module = nullptr;
        s_init_fn = nullptr;
        s_shutdown_fn = nullptr;
        return false;
    }

    loader_log("Logic DLL loaded and initialized successfully");
    return true;
}

static void unload_logic_dll()
{
    if (!s_logic_module)
    {
        return;
    }

    loader_log("Unloading logic DLL...");

    if (s_shutdown_fn)
    {
        s_shutdown_fn();
    }

    // Brief sleep to allow any in-flight hook callbacks to complete.
    // SafetyHook freezes threads during hook removal, but callbacks
    // that were already past the hook entry point need time to return.
    Sleep(CALLBACK_DRAIN_MS);

    FreeLibrary(s_logic_module);
    s_logic_module = nullptr;
    s_init_fn = nullptr;
    s_shutdown_fn = nullptr;

    loader_log("Logic DLL unloaded");
}

static void reload_logic_dll()
{
    // Guard against double-reload
    bool expected = false;
    if (!s_reloading.compare_exchange_strong(expected, true))
    {
        return;
    }

    loader_log("=== HOT RELOAD TRIGGERED ===");

    unload_logic_dll();

    // Brief delay to ensure file locks are released (build system may
    // still be writing the DLL when the hotkey is pressed)
    Sleep(FILE_SETTLE_MS);

    load_logic_dll();

    s_reloading.store(false);
    loader_log("=== HOT RELOAD COMPLETE ===");
}

// ─── Main thread ────────────────────────────────────────────────────

static DWORD WINAPI LoaderThread(LPVOID /*param*/)
{
    s_logic_dll_path = resolve_logic_dll_path();

    // Initial load — do NOT exit if this fails.
    // The thread must stay alive so the reload hotkey can retry
    // (e.g., logic DLL not yet built on first launch).
    if (!load_logic_dll())
        loader_log("Initial load failed — press reload key to retry");

    // Poll for reload hotkey
    while (s_running.load())
    {
        if ((GetAsyncKeyState(RELOAD_KEY) & 0x8000) != 0)
        {
            reload_logic_dll();

            // Wait for key release to prevent rapid re-triggers
            while (GetAsyncKeyState(RELOAD_KEY) & 0x8000)
            {
                Sleep(50);
            }
        }

        Sleep(POLL_INTERVAL_MS);
    }

    // Final cleanup on game exit
    unload_logic_dll();

    return 0;
}

// ─── Entry point ────────────────────────────────────────────────────

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        s_loader_module = hModule;

        // Spawn loader thread to avoid Windows loader lock deadlock
        // Pass hModule so the thread can resolve paths relative to the ASI.
        HANDLE thread = CreateThread(nullptr, 0, LoaderThread, hModule, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        s_running.store(false);
        // Note: unload_logic_dll() is called by LoaderThread when it exits.
        // We do NOT call it here because DllMain(DETACH) holds the loader
        // lock, and Shutdown() may need threads to exit (which requires
        // the loader lock → deadlock).
    }
    return TRUE;
}
```

### Step 4: CMake Build Configuration

You need two separate CMake targets. Here is a reference structure:

```text
my_mod/
├── CMakeLists.txt              ← Top-level, defines both targets
├── external/
│   └── DetourModKit/           ← Git submodule
├── mod_loader/
│   └── dllmain.cpp             ← Loader ASI source
├── mod_logic/
│   ├── dllmain.cpp             ← Logic DLL source
│   ├── exports.hpp             ← Shared Init/Shutdown typedefs
│   └── features/               ← Your mod feature code
│       ├── camera.cpp
│       └── camera.hpp
└── config/
    └── mod_config.ini           ← Runtime configuration
```

**CMakeLists.txt:**

```cmake
cmake_minimum_required(VERSION 3.25)
project(MyMod LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── DetourModKit ────────────────────────────────────────────────────
add_subdirectory(external/DetourModKit)

# ─── Loader ASI (thin stub, rarely rebuilt) ──────────────────────────
add_library(mod_loader SHARED
    mod_loader/dllmain.cpp
)
set_target_properties(mod_loader PROPERTIES
    OUTPUT_NAME "mod_loader"
    SUFFIX ".asi"
    # Output directly to game directory for convenience
    # RUNTIME_OUTPUT_DIRECTORY "D:/Games/SteamLibrary/steamapps/common/YourGame/bin64"
)

# ─── Logic DLL (rebuilt frequently, hot-reloaded) ────────────────────
add_library(mod_logic SHARED
    mod_logic/dllmain.cpp
    mod_logic/features/camera.cpp
    # Add more source files as needed
)
target_link_libraries(mod_logic PRIVATE DetourModKit)
target_include_directories(mod_logic PRIVATE
    ${CMAKE_SOURCE_DIR}/mod_logic
)
set_target_properties(mod_logic PROPERTIES
    OUTPUT_NAME "mod_logic"
    # Output to same directory as the loader ASI
    # RUNTIME_OUTPUT_DIRECTORY "D:/Games/SteamLibrary/steamapps/common/YourGame/bin64"
)
```

### Step 5: Build and Deploy

```bash
# One-time: build and deploy the loader
cmake --build build --target mod_loader --parallel
cp build/mod_loader.asi /path/to/game/bin64/

# Iterative: rebuild only the logic DLL
cmake --build build --target mod_logic --parallel
cp build/mod_logic.dll /path/to/game/bin64/

# In-game: press Numpad 0 to hot-reload (no restart needed)
```

For maximum convenience, set `RUNTIME_OUTPUT_DIRECTORY` in CMake to output directly to the game directory:

```cmake
set_target_properties(mod_logic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "D:/Games/SteamLibrary/steamapps/common/YourGame/bin64"
)
```

Then the workflow becomes:

```bash
# Build → file appears in game dir → press Numpad 0 in-game
cmake --build build --target mod_logic --parallel
```

---

## Critical Safety Considerations

### 1. Thread Safety During Reload

**Problem:** A hook callback may be executing on the game's thread when you trigger a reload. If the logic DLL is unloaded while a callback is mid-execution, the game crashes (code page unmapped → access violation).

**How DMK handles this:** SafetyHook's `remove_all_hooks()` freezes all threads, patches the original bytes back, then resumes threads. Any thread that was inside a hook trampoline will now execute the original function code. This is safe as long as:

- The hook callback does not store persistent pointers into the logic DLL's code/data segments.
- The hook callback does not spawn threads that outlive the DLL.

**The `CALLBACK_DRAIN_MS` sleep** after `Shutdown()` in the loader provides additional margin for any callbacks that were past the hook entry check but haven't returned yet.

### 2. Global State Reset

**Every `FreeLibrary` + `LoadLibrary` cycle resets all global/static variables** in the logic DLL. This is usually desirable (clean slate), but be aware:

**Global variables in logic DLL:**
Reset to initial values on reload. This is expected — design for it.

**DMK singletons (Logger, HookManager, etc.):**
**Destroyed** during `FreeLibrary` (static-local destructors run), then **reconstructed** on first `get_instance()` call after `LoadLibrary`. The new instance starts with default state. `Init()` must re-configure them (e.g., `Logger::configure()`, `set_log_level()`). `Shutdown()` must be called *before* `FreeLibrary` so destruction order is controlled, not random.

**Game memory (patched bytes, written values):**
**Persists** — the game doesn't know about reload. Hooks restore original bytes via SafetyHook; direct `Memory::write_bytes()` patches must be manually reverted in `Shutdown()`.

**Config file on disk:**
**Persists** across reloads. Edit the INI, press reload, and new values take effect.

**If you need state to survive reloads** (e.g., a toggle that should stay on), store it in the loader:

```cpp
// In mod_loader — survives reload
struct PersistentState
{
    bool camera_unlocked = false;
    float custom_fov = 90.0f;
};
static PersistentState s_persistent;

// Variant: change the InitFn signature to accept persistent state.
// Both loader and logic DLL must agree on this signature.
// Update exports.hpp accordingly:
//   using InitFn = bool (__cdecl *)(void* persistent_state);
//
// Then in Init():
//   extern "C" __declspec(dllexport) bool Init(void* persistent_state) { ... }
```

### 3. Direct Memory Patches

If your mod writes raw bytes to game memory (not via hooks), those patches are **not automatically reverted** on reload. You must track and revert them manually:

```cpp
// In your mod code
struct BytePatch
{
    std::byte* address;
    std::vector<std::byte> original_bytes;
};
static std::vector<BytePatch> s_active_patches;

void apply_patch(std::byte* addr, const std::byte* new_bytes, size_t len)
{
    BytePatch patch{addr, {}};
    patch.original_bytes.resize(len);
    std::copy_n(addr, len, patch.original_bytes.data());

    auto& logger = DMKLogger::get_instance();
    auto result = DMKMemory::write_bytes(addr, new_bytes, len, logger);
    if (!result) {
        logger.error("apply_patch: write_bytes failed");
        return;
    }
    s_active_patches.push_back(std::move(patch));
}

void revert_all_patches()
{
    auto& logger = DMKLogger::get_instance();
    for (auto it = s_active_patches.rbegin(); it != s_active_patches.rend(); ++it)
    {
        auto result = DMKMemory::write_bytes(
            it->address, it->original_bytes.data(), it->original_bytes.size(), logger);
        if (!result) {
            logger.error("revert_all_patches: write_bytes failed");
        }
    }
    s_active_patches.clear();
}

// Call revert_all_patches() in Shutdown() BEFORE DMK_Shutdown()
```

### 4. Logger File Handles

The DMK Logger opens a file handle when the singleton is constructed (configured via `Logger::configure()`). On reload, `Shutdown()` closes the file, and the new `Init()` call to `Logger::configure()` reopens it. The logger appends by default via `WinFileStream`, so logs accumulate across reloads. If you need a clean log per session, delete the log file in `Init()` before calling `configure()`.

### 5. Build System File Locking

On Windows, the game process holds a file lock on `mod_logic.dll` while it's loaded. You **cannot overwrite the DLL while it's loaded**. The workflow must be:

```text
1. Press Numpad 0 → FreeLibrary releases the file lock
2. Build → compiler writes new mod_logic.dll (now possible)
3. Press Numpad 0 again → LoadLibrary picks up the new binary
```

**Recommended approach:** configure the build system to output to a **staging directory**, and have the loader copy from staging before `LoadLibrary`. This lets you rebuild at any time without touching the game:

```cmake
# CMakeLists.txt — build to staging/ so the linker never hits a locked file
set(GAME_BIN_DIR "D:/Games/.../bin64")
set(GAME_STAGING_DIR "${GAME_BIN_DIR}/staging")

set_target_properties(mod_logic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${GAME_STAGING_DIR}"
    PDB_OUTPUT_DIRECTORY "${GAME_STAGING_DIR}"
    # For multi-config generators (Visual Studio), set per-config too:
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${GAME_STAGING_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${GAME_STAGING_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${GAME_STAGING_DIR}"
    PDB_OUTPUT_DIRECTORY_DEBUG "${GAME_STAGING_DIR}"
    PDB_OUTPUT_DIRECTORY_RELEASE "${GAME_STAGING_DIR}"
    PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${GAME_STAGING_DIR}"
)
```

```cpp
// In the loader, before LoadLibrary in both initial load and reload paths.
// Derives the directory from s_logic_dll_path (already resolved at startup).

// Resolve the loader's directory (cached once at startup alongside s_logic_dll_path).
static std::string s_loader_dir;  // e.g., "D:/Games/.../bin64/"

// Move a single file from staging/ to the loader directory.
// Silently skips if the source does not exist.
static void move_staged_file(const char* filename)
{
    std::string src = s_loader_dir + "staging\\" + filename;
    std::string dst = s_loader_dir + filename;

    if (GetFileAttributesA(src.c_str()) == INVALID_FILE_ATTRIBUTES)
        return;

    if (CopyFileA(src.c_str(), dst.c_str(), FALSE))
        DeleteFileA(src.c_str());
}

static bool copy_from_staging()
{
    std::string staging = s_loader_dir + "staging\\" + LOGIC_DLL_NAME;
    if (GetFileAttributesA(staging.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;  // No staged build available

    if (!CopyFileA(staging.c_str(), s_logic_dll_path.c_str(), FALSE))
    {
        loader_log("ERROR: Failed to copy from staging");
        return false;
    }

    // Delete staged DLL only after copy succeeds.
    DeleteFileA(staging.c_str());

    // Move companion PDB so staging/ stays clean
    move_staged_file("mod_logic.pdb");

    loader_log("Copied logic DLL from staging");
    return true;
}
```

To integrate staging, make the following changes to the loader code from Step 3:

1. Add `s_loader_dir` initialization in `LoaderThread`, right after `s_logic_dll_path`:

```cpp
s_logic_dll_path = resolve_logic_dll_path();
s_loader_dir = s_logic_dll_path.substr(0, s_logic_dll_path.find_last_of("\\/") + 1);
```

1. Call `copy_from_staging()` in `load_logic_dll()`, before the `LoadLibraryA` call:

```cpp
static bool load_logic_dll()
{
    loader_log("Loading logic DLL...");

    copy_from_staging();  // Copy new build from staging/ if available

    s_logic_module = LoadLibraryA(s_logic_dll_path.c_str());
    // ... rest unchanged
```

With staging, the workflow becomes: **build → press reload key** (one step, not two). The loader handles the copy internally.

Alternatively, use a **two-press workflow**: Numpad 0 to unload, rebuild, Numpad 0 to reload. This is simpler but requires manual sequencing.

### 6. Compiler/Linker Compatibility

The loader and logic DLL must be built with the **same compiler and C runtime**. Mixing MinGW-built loader with MSVC-built logic (or vice versa) will crash due to CRT/ABI incompatibilities.

Both DLLs should use the same CMake preset (e.g., both `mingw-release` or both `msvc-release`).

### 7. PDB / Debug Symbols

When debugging hot-reloaded DLLs with x64dbg or Visual Studio:

- **MSVC:** The linker locks the `.pdb` file while the DLL is loaded. Use `/pdbaltpath:%_PDB%` or the `/Fd` flag to generate uniquely-named PDBs (e.g., `mod_logic_<timestamp>.pdb`), or unload before rebuilding. Set `PDB_OUTPUT_DIRECTORY` alongside `RUNTIME_OUTPUT_DIRECTORY` in CMake so PDBs are staged with the DLL (see Section 5).
- **PDB copy on reload:** If your loader copies the DLL from a staging directory, copy the `.pdb` alongside it. Without the matching PDB next to the loaded DLL, debuggers lose source-level mapping after a hot reload.
- **MinGW:** Debug info is embedded in the DLL (DWARF), so no separate PDB locking issue. However, GDB/x64dbg may cache the old symbol table — after reload, re-run `symload` or detach and reattach.
- **After reload:** x64dbg will not automatically pick up new symbols. Use `Debug → Symbols → Reload module` or the `symload` command on the reloaded `mod_logic.dll`.

### 8. Thread-Local Storage (TLS) and Static Constructors

**TLS (`thread_local` variables):** If your logic DLL declares `thread_local` variables, be aware that `FreeLibrary` does **not** run TLS destructors for threads that were not created by the DLL. This can leak resources. Avoid `thread_local` in logic DLLs, or ensure cleanup runs in `Shutdown()`.

**Static constructors/destructors:** `FreeLibrary` runs destructors for file-scope `static` objects in the logic DLL. If those destructors depend on external state (game memory, other DLLs), they may crash. Prefer explicit init/shutdown functions over static constructors. DetourModKit singletons are safe because `DMK_Shutdown()` runs them in controlled order *before* `FreeLibrary`.

### 9. Background Thread Lifecycle

If your logic DLL spawns background threads (e.g., for deferred scanning, periodic polling, or async I/O), you **must** join them in `Shutdown()` before calling `DMK_Shutdown()`. A thread that outlives `FreeLibrary` will execute unmapped code and crash.

```cpp
// In Shutdown():
void Shutdown()
{
    // 1. Signal threads to stop
    s_scan_thread_running.store(false, std::memory_order_release);
    s_scan_cv.notify_one();

    // 2. Join with a bounded timeout to avoid blocking the reload indefinitely
    if (s_scan_thread.joinable())
    {
        // Use a future to implement a timed join (std::thread has no native timeout)
        auto join_future = std::async(std::launch::async, [&] { s_scan_thread.join(); });
        if (join_future.wait_for(std::chrono::seconds(2)) == std::future_status::timeout)
        {
            Logger::get_instance().warning("Shutdown: background thread did not exit within 2s");
            // Thread is stuck — detach as last resort so FreeLibrary can proceed.
            // The thread will crash when it touches unmapped code, but that is
            // preferable to deadlocking the reload cycle.
            s_scan_thread.detach();
        }
    }

    // 3. Now safe to tear down DMK
    DMK_Shutdown();
}
```

**Rules:**

- Never `detach()` threads in a reloadable DLL — detached threads cannot be joined. The `detach()` above is a last-resort fallback when a thread is stuck, not normal practice.
- Use `std::atomic<bool>` flags and `condition_variable::notify_one()` for cooperative shutdown.
- Prefer a bounded join timeout (as shown above) when threads perform blocking I/O or long operations. For cooperative-shutdown threads with short poll intervals (e.g., `condition_variable::wait_for` with a 1-second timeout), an unbounded `join()` is acceptable since the thread will observe the stop flag promptly.

### 10. Preprocessor Guards for Dev Builds

When using the two-DLL architecture, the logic DLL should skip its `DllMain` initialization when loaded by the dev loader (which calls `Init()` directly). Use a preprocessor guard:

```cpp
// dllmain.cpp
#ifndef MY_MOD_DEV_BUILD
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        // Spawn init thread for production ASI loading
    }
    return TRUE;
}
#endif
// When MY_MOD_DEV_BUILD is defined, DllMain is omitted entirely.
// The dev loader calls Init()/Shutdown() via GetProcAddress.
```

Toggle this in CMake:

```cmake
option(MY_MOD_DEV_BUILD "Two-DLL hot-reload configuration" OFF)
if(MY_MOD_DEV_BUILD)
    target_compile_definitions(mod_logic PRIVATE MY_MOD_DEV_BUILD)
endif()
```

This prevents double-initialization (once from `DllMain`, once from the loader's `Init()` call) and avoids spawning orphaned init threads during hot-reload.

---

## Debugging Hot-Reload Issues

### Common Crashes and Their Causes

**Crash on reload (access violation at 0x00000000):**
`GetProcAddress` returned null — export name mismatch. Verify `extern "C"` on exports, check with `dumpbin /exports mod_logic.dll`.

**Crash during hook callback after reload:**
Old function pointer stored somewhere. Ensure all hook callbacks reference only data within mod_logic.dll.

**Crash on `FreeLibrary`:**
Thread still executing code in mod_logic.dll. Increase `CALLBACK_DRAIN_MS` after `Shutdown()`.

**Hang on reload:**
Deadlock in `DMK_Shutdown` (Logger waiting for async thread). Ensure no logging calls are in-flight during shutdown.

**Hooks don't take effect after reload:**
AOB pattern scan finds wrong address. Game may have moved memory; verify base address hasn't changed.

**Config values reset unexpectedly:**
Global state reset on DLL reload. Use persistent state in loader (see Section 2 above).

**Build fails: "cannot open mod_logic.dll for writing":**
Game still has DLL loaded. Unload first (Numpad 0), then build.

### Diagnostic Tools

- **DebugView (Sysinternals):** Captures `OutputDebugStringA` messages from the loader. Filter for `[mod_loader]`.
- **x64dbg:** Attach to game process. Set breakpoints on `LoadLibraryA` / `FreeLibrary` to verify load/unload cycle.
- **Process Explorer:** Verify which DLLs are loaded in the game process. Check if `mod_logic.dll` appears/disappears on reload.
- **dumpbin:** Verify exports: `dumpbin /exports mod_logic.dll` should show `Init` and `Shutdown`.

---

## Advanced Patterns

### Auto-Reload on Build (File Watcher)

Instead of manually pressing the reload key, the loader can watch for file changes:

```cpp
// In LoaderThread, replace hotkey polling with:
static DWORD WINAPI LoaderThread(LPVOID /*param*/)
{
    s_logic_dll_path = resolve_logic_dll_path();
    load_logic_dll();

    // Watch the directory containing the logic DLL
    std::string watch_dir = s_logic_dll_path.substr(0, s_logic_dll_path.find_last_of("\\/"));
    HANDLE dir_handle = FindFirstChangeNotificationA(
        watch_dir.c_str(),
        FALSE,
        FILE_NOTIFY_CHANGE_LAST_WRITE
    );

    constexpr DWORD DEBOUNCE_MS = 500;

    if (dir_handle == INVALID_HANDLE_VALUE)
    {
        loader_log("WARNING: File watcher failed — falling back to hotkey-only mode");
    }

    while (s_running.load())
    {
        // Always check hotkey for manual reload
        if ((GetAsyncKeyState(RELOAD_KEY) & 0x8000) != 0)
        {
            reload_logic_dll();
            while ((GetAsyncKeyState(RELOAD_KEY) & 0x8000) != 0) { Sleep(50); }
            continue;
        }

        // Check for file changes if watcher is valid (non-blocking, 100ms timeout)
        if (dir_handle != INVALID_HANDLE_VALUE)
        {
            DWORD wait = WaitForSingleObject(dir_handle, POLL_INTERVAL_MS);
            if (wait == WAIT_OBJECT_0)
            {
                Sleep(DEBOUNCE_MS);
                FindNextChangeNotification(dir_handle);

                loader_log("File change detected — reloading");
                reload_logic_dll();
            }
        }
        else
        {
            Sleep(POLL_INTERVAL_MS);
        }
    }

    if (dir_handle != INVALID_HANDLE_VALUE)
        FindCloseChangeNotification(dir_handle);
    unload_logic_dll();
    return 0;
}
```

**Caveat:** File watchers can trigger during partial writes. The 500ms debounce helps, but a more robust approach is to watch for a sentinel file (e.g., `.reload_ready`) that your build script creates after the DLL is fully written.

### Persistent State via Shared Memory

For complex state that must survive reloads, use a named shared memory section:

```cpp
// In the loader
struct SharedModState
{
    bool camera_unlocked;
    float fov;
    float position[3];
    // Add fields as needed — keep it POD (no pointers, no std:: types)
};

static SharedModState* s_shared_state = nullptr;
static HANDLE s_mapping = nullptr;

static void init_shared_state()
{
    s_mapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        0, sizeof(SharedModState), "MyMod_SharedState"
    );
    if (s_mapping)
    {
        s_shared_state = static_cast<SharedModState*>(
            MapViewOfFile(s_mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedModState))
        );
    }
}

static void cleanup_shared_state()
{
    if (s_shared_state)
    {
        UnmapViewOfFile(s_shared_state);
        s_shared_state = nullptr;
    }
    if (s_mapping)
    {
        CloseHandle(s_mapping);
        s_mapping = nullptr;
    }
}
// Call init_shared_state() in LoaderThread startup.
// Call cleanup_shared_state() in LoaderThread cleanup (after unload_logic_dll).

// Pass to Init:
using InitFn = bool (__cdecl *)(SharedModState* state);
```

### Multiple Logic DLLs (Feature Modules)

For large mods, split features into separate logic DLLs that can be reloaded independently:

```text
mod_loader.asi
  ├── mod_camera.dll    ← Reload with Numpad 0
  ├── mod_ui.dll        ← Reload with Numpad 1
  └── mod_gameplay.dll  ← Reload with Numpad 2
```

Each DLL exports its own `Init()` / `Shutdown()` pair. The loader manages them as an array of modules.

---

## Workflow Comparison

### Before (Cold Restart)

```text
Time per iteration: 1-3 minutes
  Code change:      5 seconds
  Build:           10 seconds
  Kill game:        5 seconds
  Relaunch:        60-120 seconds  ← bottleneck
  Navigate to test: 30 seconds
  Test:            variable
```

### After (Hot Reload)

```text
Time per iteration: 15-20 seconds
  Code change:      5 seconds
  Build:           10 seconds
  Press Numpad 0:   < 1 second     ← no restart
  Test:            variable        ← game state preserved
```

**Estimated time saved:** 70-90% reduction in iteration time. For 40 iterations/day, this saves **1-2 hours of loading screens**.

---

## Checklist: Implementing Hot-Reload for Your Mod

- [ ] Split mod into `mod_loader` (ASI) and `mod_logic` (DLL)
- [ ] Logic DLL exports `extern "C" Init()` and `Shutdown()`
- [ ] `Shutdown()` calls `DMK_Shutdown()` for clean teardown
- [ ] `Init()` is fully self-contained (sets up everything from scratch)
- [ ] No persistent pointers from game code into logic DLL data segments
- [ ] No threads spawned by logic DLL that outlive `Shutdown()`
- [ ] Direct memory patches (non-hook) are tracked and reverted in `Shutdown()`
- [ ] Both DLLs built with same compiler toolchain
- [ ] CMake outputs logic DLL to game directory (or staging + copy)
- [ ] Test reload cycle: load → use mod → rebuild → Numpad 0 → verify mod works
- [ ] Test edge case: reload during active hook callback (should not crash)
- [ ] Test edge case: reload with no logic DLL on disk (loader should log error, not crash)

---

## FAQ

**Q: Can I hot-reload the loader ASI itself?**
A: No. The ASI is loaded by the game's ASI loader at startup and cannot be unloaded. But you should rarely need to change the loader — it's just a thin stub.

**Q: What if the game crashes during reload?**
A: Attach a debugger (x64dbg) and check the crash address. If it's in unmapped memory (the old logic DLL's address space), a callback was still executing during `FreeLibrary`. Increase the sleep duration or add a reference-counting mechanism to wait for all callbacks to complete.

**Q: Can I use this with ASI loaders like Ultimate ASI Loader?**
A: Yes. The ASI loader loads `mod_loader.asi` normally. The loader then manages `mod_logic.dll` via `LoadLibrary`/`FreeLibrary`. The ASI loader is not involved in the reload cycle.

**Q: Does this work with anti-cheat?**
A: If the game has anti-cheat that monitors `LoadLibrary` calls, hot-reload may trigger detection. This approach is intended for single-player modding and development environments only.

**Q: Can I reload while a game menu/pause screen is open?**
A: Yes — this is actually the safest time to reload, since fewer game systems are actively calling hooked functions. The pause screen reduces the chance of a callback being mid-execution during teardown.

**Q: What about C++ exceptions thrown during Init()?**
A: If `Init()` throws, the loader catches nothing (C functions shouldn't throw across DLL boundaries). Use `try/catch` inside `Init()` and return `false` on failure. The loader will log the error and leave the logic DLL unloaded until the next reload attempt.

---

## Hot-Reload Safety Guarantees

DetourModKit's core systems are designed to be safe across DLL reload cycles:

**HookManager:** `shutdown()` removes all hooks and resets its internal state, allowing subsequent `create_*_hook()` calls to succeed. The same applies to `remove_all_hooks()`. Both methods leave the singleton in a clean, reusable state for the next `Init()` cycle. There is no need to call both — either one prepares the HookManager for reuse.

**Config:** `register_*()` functions use replace-on-duplicate semantics. If a new DLL registers a config item with the same section and INI key as an existing entry, the old registration is replaced rather than appended. This prevents doubled registrations across reload cycles without requiring an explicit `clear_registered_items()` call. Calling `clear_registered_items()` before re-registration is still supported but no longer required.
