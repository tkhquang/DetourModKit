/**
 * @file bootstrap_probe_dll.cpp
 * @brief Minimal mod-shaped DLL used by the bootstrap-worker module-reference proofs.
 *
 * @details It reproduces the exact runtime shape DetourModKit's async bootstrap path is built for: a DLL whose DllMain
 *          forwards DLL_PROCESS_ATTACH into bootstrap() (which stages a Session and spawns the lifecycle worker) and
 *          forwards DLL_PROCESS_DETACH into bootstrap_detach(). The bootstrap path takes a counted reference on this
 *          module before creating the worker, so its code cannot be unmapped before the worker runs or while it runs.
 *
 *          A consequence the proofs rely on: because the worker holds that reference, a bare FreeLibrary does NOT drive
 *          the module reference count to zero, so DLL_PROCESS_DETACH does not fire on it -- the module simply stays
 *          mapped. DETACH fires only after the worker has been drained (via the exported request_shutdown forwarder)
 *          and released its reference, or at process termination.
 *
 *          This is a separate build artifact (a DLL, not a test translation unit), so it lives outside the in-tree test
 *          glob and is compiled and driven by scripts/run_lifecycle_proofs.sh against the prebuilt library archive.
 */

#include "DetourModKit.hpp"

#include <windows.h>

#include <atomic>

namespace
{
    std::atomic<bool> g_worker_ready{false};
}

// A named, exported anchor whose ADDRESS lands in this DLL's .text. The host resolves it once while the DLL is loaded,
// then, after FreeLibrary, asks the loader which module owns that address. A still-mapped module owns it; an unmapped
// one does not. A dedicated exported symbol makes the check independent of the DLL's file name and points at the exact
// kind of memory the worker's reference protects: executable code the worker keeps running.
extern "C" __declspec(dllexport) void dmk_probe_marker() noexcept {}

// Exported readiness flag for the drained-unload proof. The bootstrap worker sets it from on_ready, which proves it has
// adopted the Session and is parked on the shutdown event before the host requests teardown.
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_probe_worker_ready() noexcept
{
    return g_worker_ready.load(std::memory_order_acquire) ? TRUE : FALSE;
}

// Exported forwarder for the host's drained-unload proof: request a graceful, off-loader-lock shutdown of the lifecycle
// worker. This runs the worker's ordered teardown and makes it release its module self-reference and exit, after which
// a matching FreeLibrary can drive the count to zero and complete a clean unmap.
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_probe_request_shutdown() noexcept
{
    DetourModKit::request_shutdown();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Mirror a real mod's attach with the least setup that still spawns the worker: an empty game_process_name
        // always matches the running executable and an empty instance_mutex_prefix installs no single-instance guard,
        // so start() cannot decline. bootstrap() stages the Session, takes the worker's module reference, and creates
        // the worker thread; the worker then parks on the shutdown event until drained.
        g_worker_ready.store(false, std::memory_order_release);
        DetourModKit::ModInfo info{};
        info.name = "DMKBootstrapProbe";
        info.log_file = "dmk_bootstrap_probe.log";
        (void)DetourModKit::bootstrap(info,
                                      [](DetourModKit::Session &) -> DetourModKit::Result<void>
                                      {
                                          g_worker_ready.store(true, std::memory_order_release);
                                          return {};
                                      });
        break;
    }
    case DLL_PROCESS_DETACH:
        // Forward exactly as a real mod's DllMain would. Because the worker holds its own module reference, a bare
        // FreeLibrary does not fire this DETACH; it fires only after the worker has been drained and released that
        // reference (the clean-unload path) or at process termination (reserved != nullptr).
        DetourModKit::bootstrap_detach(reserved);
        break;
    default:
        break;
    }
    return TRUE;
}
