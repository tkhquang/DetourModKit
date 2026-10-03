# Examples

This directory contains reference samples as source. CI compiles them on both toolchains to detect public API drift. The project does not install them. DMK-owned lifecycle fixtures exercise the staged pair.

Copy a sample into your mod project and own the copy.

A sample carries no compatibility promise.

## staged_reload

> [!IMPORTANT]
> **INI bindings and Consume settings require no loader-policy edits.**
>
> The default development policy retains retired DLLs within budgets and loads fresh staged images. It never falls back to old-image `Init()`.
>
> A failed callback drain, worker join, or hook teardown blocks replacement. Follow the [hot-reload guide](../docs/guides/hot-reload/README.md).

This pair implements the default development policy and resident wheel host from the guide.

`DMK_EXAMPLE_MOD_NAME` in [CMakeLists.txt](CMakeLists.txt) names the deployed pair and every derived file: `ModName.asi`, `ModName.logic.dll`, staged copies `ModName.genXXXX.logic.dll`, the INI, and both logs. Rename the mod in that one line.

| File | Role |
| --- | --- |
| `mod_loader.cpp` | It owns one process-lifetime wheel host, creates unique staged names, probes lease release, and releases or retains retired images. It links only `DetourModKit::WheelHost`. |
| `mod_logic.cpp` | It owns one generation, selects required `ExternalHost`, and implements the typed `Shutdown()` refusal boundary. It links the full archive. |
| `protocol.h` | It defines the fixed-width request that carries the host table, host identity, and generation id across the DLL boundary. |

The loader starts the wheel host once before the first logic load. An accepted logic shutdown closes its lease and retires feature state.

The [retention policy](../docs/guides/hot-reload/README.md#define-a-retained-generation-policy) defines the shutdown verdicts and loader-reference ownership. Unique staged names prevent old-image reuse.

Build with a Debug preset (`DMK_BUILD_EXAMPLES` is ON there), or pass `-DDMK_BUILD_EXAMPLES=ON` to any configure:

```bash
cmake --preset msvc-debug
cmake --build build/msvc-debug --target dmk_example_staged_loader dmk_example_staged_logic
```

Deploy the pair with these steps:

1. Build each DLL with its supported compiler and C runtime.
2. If an ASI host loads the pair, rename `StagedExample.dll` to `StagedExample.asi`.
3. Put `StagedExample.logic.dll` beside the loader.

The CMake gate rejects a direct full-archive dependency on the loader. The fixed-width C ABI permits mixed-toolchain pairs. The lifecycle fixtures use one toolchain per pair. Before deployment, verify a mixed pair with a lifecycle host.

Apply the guide's [thread and TLS preconditions](../docs/guides/hot-reload/README.md#threads-tls-and-static-constructors) to the deployed pair. The MinGW examples and proof DLLs use different runtime linkage.
