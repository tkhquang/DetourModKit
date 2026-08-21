# Examples

This directory contains reference samples as source. CI compiles them on both toolchains to detect public API drift. The project does not install them or register runtime tests.

Copy a sample into your mod project and own the copy.

A sample carries no compatibility promise.

## staged_reload

This pair implements the staged-generation development loader and resident wheel host from the [hot-reload guide](../docs/guides/hot-reload/README.md).

`DMK_EXAMPLE_MOD_NAME` in [CMakeLists.txt](CMakeLists.txt) names the deployed pair and every derived file: `ModName.asi`, `ModName.logic.dll`, staged copies `ModName.genXXXX.logic.dll`, the INI, and both logs. Rename the mod in that one line.

| File | Role |
| --- | --- |
| `mod_loader.cpp` | It owns one process-lifetime wheel host, creates unique staged names, probes lease release, calls `FreeLibrary`, and checks address unmap. It links only `DetourModKit::WheelHost`. |
| `mod_logic.cpp` | It owns one generation, selects required `ExternalHost`, and implements the typed `Shutdown()` refusal boundary. It links the full archive. |
| `protocol.h` | It defines the fixed-width request that carries the host table, host identity, and generation id across the DLL boundary. |

The loader starts the wheel host once before the first logic load. Each logic shutdown closes its lease and reports zero logic-side module pins. The loader opens and closes a probe lease before `FreeLibrary`, then waits for an exported code address to become unmapped. A failed lease probe or unmap check stops later reloads and requests a game restart. Unique staged names reject stale-image reuse. The [hot-reload guide](../docs/guides/hot-reload/README.md) owns the pin rules.

Build with a Debug preset (`DMK_BUILD_EXAMPLES` is ON there), or pass `-DDMK_BUILD_EXAMPLES=ON` to any configure:

```bash
cmake --preset msvc-debug
cmake --build build/msvc-debug --target dmk_example_staged_loader dmk_example_staged_logic
```

Deploy the pair with these steps:

1. Build each DLL with its supported compiler and C runtime.
2. If an ASI host loads the pair, rename `StagedExample.dll` to `StagedExample.asi`.
3. Put `StagedExample.logic.dll` beside the loader.

The CMake gate rejects a full archive edge on the loader. The fixed-width C ABI permits mixed-toolchain pairs, but the mixed MSVC and MinGW lifecycle gate remains required.
