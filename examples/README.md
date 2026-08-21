# Examples

This directory contains compiled reference samples. CI compiles them on both toolchains to detect public API drift. The project does not install them or register runtime tests.

Copy a sample into your mod project and own the copy.

A sample carries no compatibility promise.

## staged_reload

This pair implements the staged-generation development loader from the [hot-reload guide](../docs/guides/hot-reload/README.md).

`DMK_EXAMPLE_MOD_NAME` in [CMakeLists.txt](CMakeLists.txt) names the deployed pair and every derived file: `ModName.asi`, `ModName.logic.dll`, staged copies `ModName.genXXXX.logic.dll`, the INI, and both logs. Rename the mod in that one line.

| File | Role |
| --- | --- |
| `mod_loader.cpp` | It creates unique staged names, calls `FreeLibrary` once, applies the retained-generation budget, and writes the loader log. It links no DetourModKit code. |
| `mod_logic.cpp` | It owns one generation and implements the guide's `Shutdown()` refusal boundary. It links the archive. |

Under a rival XInput writer such as the Steam overlay, the first generation keeps its XInput hooks and stays mapped as a forwarding link. Later generations hook topmost, prove their restore, and unload. Unique staged names keep the reload repeatable beside the pinned image. A staged copy that backs a mapped generation stays locked on disk for the session. The loader deletes every stale copy at the next start. The [hot-reload guide](../docs/guides/hot-reload/README.md) owns the pin rules.

Build with a Debug preset (`DMK_BUILD_EXAMPLES` is ON there), or pass `-DDMK_BUILD_EXAMPLES=ON` to any configure:

```bash
cmake --preset msvc-debug
cmake --build build/msvc-debug --target dmk_example_staged_loader dmk_example_staged_logic
```

Deploy the pair with these steps:

1. Build the loader and logic DLL with the same compiler and C runtime.
2. If an ASI host loads the pair, rename `StagedExample.dll` to `StagedExample.asi`.
3. Put `StagedExample.logic.dll` beside the loader.
