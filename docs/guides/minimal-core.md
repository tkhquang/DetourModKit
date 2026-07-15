# The Minimal Core

DetourModKit ships one umbrella header, `DetourModKit.hpp`, that pulls in every public module. That is the right include for a first mod: one line and everything is reachable. This guide is for the opposite case -- a mod, or a single translation unit inside one, that wants the smallest possible include set and the shortest path from "attached to the process" to "reading, patching, and hooking game code".

The core is five headers. Everything else -- config binding, the input engine, RTTI walking, signature manifests, the event dispatcher, the profiler -- is optional and layers on top.

## The core header set

| Capability | Header | Key entry points |
|------------|--------|------------------|
| Process lifetime | [`DetourModKit/session.hpp`](../../include/DetourModKit/session.hpp) | `Session::start`, `bootstrap`, `ModInfo` |
| Pattern scanning | [`DetourModKit/scan.hpp`](../../include/DetourModKit/scan.hpp) | `scan::scan`, `scan::resolve` |
| Guarded memory | [`DetourModKit/memory.hpp`](../../include/DetourModKit/memory.hpp) | `memory::read`, `memory::write`, `memory::walk` |
| Function hooking | [`DetourModKit/hook.hpp`](../../include/DetourModKit/hook.hpp) | `hook::inline_at`, `hook::mid_at` |
| Logging | [`DetourModKit/logger.hpp`](../../include/DetourModKit/logger.hpp) | `log()`, `Logger` |

```cpp
#include <cstdint>
#include <optional>
#include <utility>

#include <DetourModKit/session.hpp>   // Session / ModInfo / bootstrap -- the process-lifecycle surface
#include <DetourModKit/scan.hpp>      // pattern scanning and candidate ladders
#include <DetourModKit/memory.hpp>    // guarded read / write / pointer-chain walk
#include <DetourModKit/hook.hpp>      // inline / mid hooks (move-only RAII Hook handle)
#include <DetourModKit/logger.hpp>    // the process-default logger
```

The foundation vocabulary these speak -- `Address`, `Region`, `Result<T>` / `Error` / `ErrorCode`, and the `dmk::` / `DMK::` namespace aliases -- arrives transitively (`address.hpp`, `region.hpp`, `error.hpp`, and `defines.hpp` are pulled in by the value headers above), so you never include them by hand.

> [!NOTE]
> The `dmk::` alias is defined in `defines.hpp`, which the core value headers (`error.hpp`, `scan.hpp`, `memory.hpp`) pull in. A few leaf headers -- `logger.hpp`, `format.hpp`, `input_codes.hpp`, `profiler.hpp`, `async_logger_config.hpp` -- do not, so a translation unit that includes *only* one of those must add `#include <DetourModKit/defines.hpp>` or spell the namespace `DetourModKit::` in full.

## A minimal Session

A `Session` owns your mod's process lifetime: the single-instance guard, the logger configuration, and the correctly ordered teardown of every process-wide subsystem. The leanest way in is the synchronous factory, `Session::start`, which returns a move-only `Session` by value. When that value drops, `~Session` runs the ordered teardown.

```cpp
auto opened = dmk::Session::start(dmk::ModInfo{
    .name = "MyMod",         // logger prefix and mod identity
    .log_file = "MyMod.log",
});
if (!opened)
{
    // ProcessMismatch (wrong executable), InstanceAlreadyRunning, SessionAlreadyActive, SystemCallFailed, OutOfMemory.
    return; // opened.error().code carries the reason
}
dmk::Session &session = *opened; // ~Session runs the ordered teardown when `opened` leaves scope

session.log().info("MyMod attached");
```

`Session::start` is `noexcept`: every failure is a value in the returned `Result`, never a throw. For a DLL that attaches from `DllMain`, use `dmk::bootstrap(info, on_ready)` instead -- it runs the same setup under the loader lock, then hands the `Session` to a worker thread that runs your init callback (and the eventual teardown) off the loader lock. The full `DllMain` + `bootstrap` flow is in the [root README example](../../README.md#code-example).

## Find, read, and patch

`scan::scan` resolves an AOB pattern to an `Address` inside a `Region`. When the match is an x86-64 RIP-relative instruction, `scan::resolve_rip_relative` decodes its signed `disp32` into the referenced address. `memory::read<T>` and `memory::write_in_place<T>` then access that address without changing page protection; a faulting read or non-writable target fails closed with an `ErrorCode` rather than crashing the game.

```cpp
// Locate a signature in the host executable.
const auto instruction = dmk::scan::scan(
    dmk::scan::Pattern::literal("8B 05 ?? ?? ?? ??"),
    dmk::Region::host(),
    1,
    dmk::scan::Pages::Executable);
if (!instruction)
{
    session.log().warning("health instruction not found: {}", instruction.error().message());
    return;
}

// `8B 05 disp32` is six bytes: the displacement starts at byte 2 and names the global int32_t being loaded.
const auto health_address = dmk::scan::resolve_rip_relative(*instruction, 2, 6);
if (!health_address)
{
    session.log().warning("health address did not resolve: {}", health_address.error().message());
    return;
}

if (const auto health = dmk::memory::read<std::int32_t>(*health_address))
{
    session.log().info("player health = {}", *health);

    // Patch only if the data page is already writable; a drifted read-only target fails closed.
    (void)dmk::memory::write_in_place<std::int32_t>(*health_address, *health + 100);
}
```

A bare `scan::scan` is fine for prototyping, but a signature that must survive game patches belongs in a candidate ladder or an anchored signature -- see the [AOB Signature Scanning](../misc/aob-signatures.md) guide. For reads on a per-frame hot path, see [Reading Game Memory in Hot Paths](memory/hot-path-memory.md).

## Install one hook

`hook::inline_at` installs an inline detour and hands back a move-only RAII `Hook`. While the handle lives, the detour is engaged; drop it and the original prologue is restored. The hook target is a `scan::OwnedScanRequest` resolved at install time, so the handle never carries a dangling pattern span.

```cpp
using PrintFn = void(__stdcall *)(const char *message, int type);

// A global handle keeps the hook engaged. Reset it during orderly shutdown before the Session tears down the logger
// and other process-wide services.
std::optional<dmk::hook::Hook> g_print_hook;

void __stdcall print_detour(const char *message, int type)
{
    // original<Fn>() is the typed trampoline to the un-hooked function; it is non-null only while the hook is engaged.
    if (const auto original = g_print_hook ? g_print_hook->original<PrintFn>() : nullptr)
    {
        original("Hooked!", type);
    }
}

// ... inside your init, after the Session exists:
auto installed = dmk::hook::inline_at(
    dmk::hook::InlineRequest{
        .name = "print_hook",
        .target = dmk::scan::OwnedScanRequest{
            .ladder = {dmk::scan::Candidate::direct("print", dmk::scan::Pattern::literal("48 89 ?? ?? 57"))},
            .label = "print",
            .pages = dmk::scan::Pages::Executable,
            .require_executable_result = true,
        },
    },
    &print_detour);
if (installed)
{
    g_print_hook.emplace(std::move(*installed)); // take ownership for the hook's lifetime
}
```

`inline_at` performs the function-to-`void*` cast internally, so the call site writes no `reinterpret_cast`. By default a breakpoint prologue (a `CC` / `CD` first byte) is refused with `ErrorCode::TargetPrologueUnsafe`; pass `Options{.prologue = dmk::hook::Prologue::Relocate}` to install anyway. A target whose bytes are not readable executable committed memory is refused under both policies, and a relative call prologue is relocated by the backend rather than refused. The mid-function, VMT, and per-method hook shapes are covered in the [Hook Type Coverage](hooking/hook-type-coverage.md) guide.

## Where to go next

- The full end-to-end mod (config binding, hotkeys, `DllMain` bootstrap, hot-reload-safe teardown) is the [root README example](../../README.md#code-example).
- [AOB Signature Scanning](../misc/aob-signatures.md) -- candidate ladders, pattern syntax, and signatures that survive game patches.
- [Anchor Registry](scanning/anchors.md) -- the declarative anchor table with quorum corroboration and drift reporting.
- [Reading Game Memory in Hot Paths](memory/hot-path-memory.md) -- the guarded and unchecked read fast paths.
- [Hook Type Coverage](hooking/hook-type-coverage.md) -- inline, mid, VMT, and per-method hooks.
- [Hot-Reload Guide](hot-reload/README.md) -- the two-DLL architecture for iterating without restarting the game.
- The complete module list and feature matrix is in the [documentation index](../README.md) and the [root README](../../README.md#features).
