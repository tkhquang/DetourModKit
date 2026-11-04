# The Minimal Core

DetourModKit ships one umbrella header, `DetourModKit.hpp`, that pulls in every public module. That is the right include for a first mod: one line and everything is reachable. This guide is for the opposite case. A mod, or a single translation unit inside one, wants the smallest possible include set. It wants the shortest path from "attached to the process" to "read, patch, and hook game code".

The core is five headers. Everything else is optional and layers on top: config binding, the input engine, RTTI walking, signature manifests, the event dispatcher, and the profiler.

## The core header set

| Capability | Header | Key entry points |
|------------|--------|------------------|
| Process lifetime | [`DetourModKit/session.hpp`](../../include/DetourModKit/session.hpp) | `Session::start`, `bootstrap_attach`, `ModInfo` |
| Pattern scanning | [`DetourModKit/scan.hpp`](../../include/DetourModKit/scan.hpp) | `scan::scan`, `scan::resolve` |
| Guarded memory | [`DetourModKit/memory.hpp`](../../include/DetourModKit/memory.hpp) | `memory::read`, `memory::write`, `memory::walk` |
| Function hooking | [`DetourModKit/hook.hpp`](../../include/DetourModKit/hook.hpp) | `hook::HookStack::install`, `hook::inline_at`, `hook::mid_at` |
| Logging | [`DetourModKit/logger.hpp`](../../include/DetourModKit/logger.hpp) | `log()`, `Logger` |

```cpp
#include <atomic>
#include <cstdint>

#include <DetourModKit/session.hpp>   // Session / ModInfo / bootstrap_attach: the process-lifecycle surface
#include <DetourModKit/scan.hpp>      // pattern scanning and candidate ladders
#include <DetourModKit/memory.hpp>    // guarded read / write / pointer-chain walk
#include <DetourModKit/hook.hpp>      // inline / mid hooks (move-only RAII Hook handle)
#include <DetourModKit/logger.hpp>    // the process-default logger
```

The foundation vocabulary these speak arrives transitively: `Address`, `Region`, `Result<T>` / `Error` / `ErrorCode`, and the `dmk::` / `DMK::` namespace aliases. `address.hpp`, `region.hpp`, `error.hpp`, and `defines.hpp` are pulled in by the value headers above, so you never include them by hand.

> [!NOTE]
> The `dmk::` alias is defined in `defines.hpp`, which the core value headers (`error.hpp`, `scan.hpp`, `memory.hpp`) pull in. A few leaf headers do not: `logger.hpp`, `format.hpp`, `input_codes.hpp`, `profiler.hpp`, `async_logger_config.hpp`. A translation unit that includes *only* one of those must add `#include <DetourModKit/defines.hpp>` or spell the namespace `DetourModKit::` in full.

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

`Session::start` is `noexcept`. It returns every failure as a `Result` value. The [session contract](../../include/DetourModKit/session.hpp) defines the DllMain boundary.

See the [root README example](../../README.md#code-example) for the `DllMain` bootstrap boundary, which this guide does not cover.

## Find, read, and patch

`scan::scan` resolves an AOB pattern to an `Address` inside a `Region`. When the match is an x86-64 RIP-relative instruction, `scan::resolve_rip_relative` decodes its signed `disp32` into the referenced address. `memory::read<T>` and `memory::write_in_place<T>` then access that address without a change to page protection. A read that faults, or a target that is not writable, fails closed with an `ErrorCode`, unless the guard-page re-arm in [`[B-20]`](../design/memory-scanning.md) fails.

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

A bare `scan::scan` is fine for prototyping, but a signature that must survive game patches belongs in a candidate ladder or an anchored signature. See the [AOB Signature Scanning](../misc/aob-signatures.md) guide. For reads on a per-frame hot path, see [Reading Game Memory in Hot Paths](memory/hot-path-memory.md).

## Install one hook

`HookStack::install` installs an inline detour and arms it. The stack owns the move-only RAII `Hook` and restores the original prologue at teardown. The hook target is a `scan::OwnedScanRequest` resolved at install time, so the handle never carries a dangling pattern span.

The detour reaches the original through `g_print_original`. The install stores the trampoline there before the arm, so no call enters the detour before the original exists. DMK mods that hook the same function arm in any order.

```cpp
using PrintFn = void (*)(const char *message, int type);

// The stack keeps the hook engaged. Clear it during orderly shutdown before the Session tears down the logger and
// other process-wide services.
dmk::hook::HookStack g_hooks;
std::atomic<PrintFn> g_print_original{nullptr};

void print_detour(const char *, int type) noexcept
{
    g_print_original.load(std::memory_order_acquire)("Hooked!", type);
}

// ... inside your init, after the Session exists:
const auto installed = g_hooks.install<&print_detour>(dmk::hook::InlineInstallRequest{
    .name = "print_hook",
    .target = dmk::scan::OwnedScanRequest{
        .ladder = {
            dmk::scan::Candidate::direct("print_prologue", dmk::scan::Pattern::literal("48 89 5C 24 08 57 48 83 EC 20")),
            // An inline hook overwrites the prologue. This landmark sits past the longest stolen span, so the scan also
            // resolves the function after another mod hooks it.
            dmk::scan::Candidate::direct("print_body", dmk::scan::Pattern::literal("81 FF 00 01 00 00 77"), -15),
        },
        .label = "print",
        .pages = dmk::scan::Pages::Executable,
        .require_executable_result = true,
    },
    .original = &g_print_original,
});
if (!installed)
{
    // A failed create or arm leaves g_hooks unchanged.
    session.log().warning("print_hook: {}", installed.error().message());
}
```

The counted form takes the detour as a template argument and counts its calls, so `HookStack::retire` can prove the detour idle. `hook::inline_at` returns a disabled hook for code that publishes more state before `enable()`. The arm makes the hook the newest layer of its target, so it chains to a hook that another mod armed first.

By default a breakpoint prologue (a `CC` / `CD` first byte) is refused with `ErrorCode::TargetPrologueUnsafe`. Pass `Options{.prologue = dmk::hook::Prologue::Relocate}` to install anyway. DMK classifies the target under the process coordinator, so an install waits out a patch that another mod has in flight on the same function.

A target whose bytes stay outside readable executable committed memory is refused under both policies. The pre-flight does not reject a relative call prologue on sight. The backend decides whether it can relocate the prologue. The install can therefore still fail with `ErrorCode::BackendFailed`, and the log names the backend reason.

The mid-function, VMT, and per-method hook shapes are covered in the [Hook Type Coverage](hooking/hook-type-coverage.md) guide.

## Where to go next

- The end-to-end mod (config binding, `DllMain` bootstrap, hot-reload-safe teardown) is the [root README example](../../README.md#code-example).
- [AOB Signature Scanning](../misc/aob-signatures.md). Candidate ladders, pattern syntax, and signatures that survive game patches.
- [Anchor Registry](scanning/anchors.md). The declarative anchor table with quorum corroboration and drift reporting.
- [Reading Game Memory in Hot Paths](memory/hot-path-memory.md). The guarded and unchecked read fast paths.
- [Hook Type Coverage](hooking/hook-type-coverage.md). Inline, mid, VMT, and per-method hooks.
- [Hot-Reload Guide](hot-reload/README.md). The two-DLL architecture for iteration without a game restart.
- The complete module list is in the [documentation index](../README.md) and the [root README](../../README.md#features).
