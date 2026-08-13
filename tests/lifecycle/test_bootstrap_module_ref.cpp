/**
 * @file test_bootstrap_module_ref.cpp
 * @brief Hosts the T-BOOTSTRAP module-reference lifecycle proof.
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iterator>

namespace
{
    // The drained-unload scenario polls for worker readiness and then for the final unmap instead of guessing fixed
    // sleeps. A few seconds is far more than the teardown needs and keeps the proof non-flaky.
    constexpr DWORD READY_POLL_BUDGET_MS = 3000;
    constexpr DWORD READY_POLL_STEP_MS = 10;
    constexpr DWORD UNLOAD_POLL_BUDGET_MS = 3000;
    constexpr DWORD UNLOAD_POLL_STEP_MS = 10;

    using WorkerReadyFn = FARPROC;
    using DrainFn = FARPROC;
    using AttachAllocationsFn = std::uint64_t(WINAPI *)();
    using AttachSucceededFn = INT_PTR(WINAPI *)();
    using ReloadMutexOwnedFn = INT_PTR(WINAPI *)();

    void make_worker_release_event_name(wchar_t (&name)[96]) noexcept
    {
        (void)std::swprintf(name, std::size(name), L"Local\\DMK_Bootstrap_SelfDrain_%lu", GetCurrentProcessId());
    }

    void make_reload_mutex_exit_event_name(wchar_t (&name)[96]) noexcept
    {
        (void)std::swprintf(name, std::size(name), L"Local\\DMK_ReloadMutex_ProcessExit_%lu", GetCurrentProcessId());
    }

    // Resolves a required probe export. On failure it logs the setup error, unloads the DLL, and returns nullptr so
    // the caller can bail with the setup-failure code; every scenario shares this resolve/log/unload sequence.
    FARPROC resolve_required(HMODULE dll, const char *symbol, const char *mode) noexcept
    {
        const FARPROC fn = GetProcAddress(dll, symbol);
        if (fn == nullptr)
        {
            std::fprintf(stderr, "FAIL[%s]: GetProcAddress('%s') failed (error %lu)\n", mode, symbol, GetLastError());
            FreeLibrary(dll);
        }
        return fn;
    }

    bool wait_for_worker_ready(WorkerReadyFn worker_ready) noexcept
    {
        DWORD waited = 0;
        while (worker_ready() == 0 && waited < READY_POLL_BUDGET_MS)
        {
            Sleep(READY_POLL_STEP_MS);
            waited += READY_POLL_STEP_MS;
        }
        return worker_ready() != 0;
    }

    // Asks the loader whether any module still owns @p addr. FROM_ADDRESS is safe even if the address is now unmapped
    // (it simply reports no owning module); UNCHANGED_REFCOUNT so the query does not perturb the count.
    bool module_owns(void *addr) noexcept
    {
        HMODULE owner = nullptr;
        const BOOL ok =
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(addr), &owner);
        return ok != FALSE && owner != nullptr;
    }

    int run_stays_mapped(const wchar_t *wide_path)
    {
        wchar_t release_event_name[96]{};
        make_worker_release_event_name(release_event_name);
        const HANDLE release_worker = CreateEventW(nullptr, TRUE, FALSE, release_event_name);
        if (release_worker == nullptr)
        {
            std::fprintf(stderr, "FAIL[mapped]: CreateEventW failed (error %lu)\n", GetLastError());
            return 2;
        }
        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[mapped]: LoadLibraryW failed (error %lu)\n", GetLastError());
            CloseHandle(release_worker);
            return 2;
        }
        void *marker = reinterpret_cast<void *>(resolve_required(dll, "dmk_probe_marker", "mapped"));
        if (marker == nullptr)
        {
            CloseHandle(release_worker);
            return 2;
        }
        WorkerReadyFn worker_ready = resolve_required(dll, "dmk_probe_worker_ready", "mapped");
        if (worker_ready == nullptr)
        {
            CloseHandle(release_worker);
            return 2;
        }
        // Balanced single FreeLibrary immediately after LoadLibrary, with no wait for the worker: the assertion is
        // that a counted reference taken during attach outlives the caller's own, even before the worker has executed
        // its first instruction. Not waiting keeps that the strongest form of the claim.
        if (FreeLibrary(dll) == FALSE)
        {
            std::fprintf(stderr, "FAIL[mapped]: FreeLibrary failed (error %lu)\n", GetLastError());
            CloseHandle(release_worker);
            return 2;
        }

        if (!module_owns(marker))
        {
            std::fprintf(stderr, "FAIL[mapped]: the DLL unmapped after a bare FreeLibrary; the worker reference was "
                                 "not acquired before the caller could unload the module\n");
            CloseHandle(release_worker);
            return 1;
        }

        // Let the worker release the remaining reference itself so the proof exits through an ordinary drained unload
        // instead of relying on process-exit thread termination for cleanup. Readiness guarantees the worker has opened
        // the named event before the host closes its last event handle.
        if (!wait_for_worker_ready(worker_ready))
        {
            std::fprintf(stderr, "FAIL[mapped]: worker did not report readiness within %lu ms\n", READY_POLL_BUDGET_MS);
            CloseHandle(release_worker);
            return 1;
        }
        if (SetEvent(release_worker) == FALSE)
        {
            std::fprintf(stderr, "FAIL[mapped]: SetEvent failed (error %lu)\n", GetLastError());
            CloseHandle(release_worker);
            return 2;
        }
        CloseHandle(release_worker);

        DWORD waited = 0;
        while (module_owns(marker) && waited < UNLOAD_POLL_BUDGET_MS)
        {
            Sleep(UNLOAD_POLL_STEP_MS);
            waited += UNLOAD_POLL_STEP_MS;
        }
        if (module_owns(marker))
        {
            std::fprintf(stderr, "FAIL[mapped]: cleanup did not unload the DLL within %lu ms\n", waited);
            return 1;
        }

        std::printf(
            "PASS[mapped]: the worker's counted module reference kept the DLL mapped across a bare FreeLibrary\n");
        return 0;
    }

    int run_attach_is_leaf(const wchar_t *wide_path)
    {
        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[leaf]: LoadLibraryW failed (error %lu)\n", GetLastError());
            return 2;
        }
        const auto attach_allocations =
            reinterpret_cast<AttachAllocationsFn>(resolve_required(dll, "dmk_probe_attach_allocations", "leaf"));
        if (attach_allocations == nullptr)
        {
            return 2;
        }
        const auto selftest_allocations =
            reinterpret_cast<AttachAllocationsFn>(resolve_required(dll, "dmk_probe_selftest_allocations", "leaf"));
        if (selftest_allocations == nullptr)
        {
            return 2;
        }
        const auto attach_succeeded =
            reinterpret_cast<AttachSucceededFn>(resolve_required(dll, "dmk_probe_attach_succeeded", "leaf"));
        if (attach_succeeded == nullptr)
        {
            return 2;
        }
        DrainFn shutdown_and_wait = resolve_required(dll, "dmk_probe_shutdown_and_wait", "leaf");
        if (shutdown_and_wait == nullptr)
        {
            return 2;
        }

        const bool bootstrap_ok = attach_succeeded() != FALSE;
        const std::uint64_t allocation_count = attach_allocations();
        const std::uint64_t selftest_count = selftest_allocations();
        const bool drain_ok = shutdown_and_wait() != FALSE;
        if (FreeLibrary(dll) == FALSE)
        {
            std::fprintf(stderr, "FAIL[leaf]: FreeLibrary failed (error %lu)\n", GetLastError());
            return 2;
        }
        if (!bootstrap_ok)
        {
            std::fprintf(stderr, "FAIL[leaf]: bootstrap_attach rejected the attach request\n");
            return 1;
        }
        // The control first: a zero attach count means nothing unless the probe's own operator-new replacement is
        // demonstrably the one this module binds.
        if (selftest_count == 0)
        {
            std::fprintf(stderr, "FAIL[leaf]: the probe's operator new replacement did not interpose, so the "
                                 "attach-allocation measurement proves nothing\n");
            return 1;
        }
        if (allocation_count != 0)
        {
            std::fprintf(stderr, "FAIL[leaf]: bootstrap_attach made %llu attach-thread heap allocation(s)\n",
                         static_cast<unsigned long long>(allocation_count));
            return 1;
        }
        if (!drain_ok)
        {
            std::fprintf(stderr, "FAIL[leaf]: shutdown_and_wait reported failure\n");
            return 1;
        }

        std::printf("PASS[leaf]: bootstrap_attach published the worker without attach-thread heap allocation\n");
        return 0;
    }

    int run_bare_free_library_self_drain(const wchar_t *wide_path)
    {
        wchar_t release_event_name[96]{};
        make_worker_release_event_name(release_event_name);
        const HANDLE release_worker = CreateEventW(nullptr, TRUE, FALSE, release_event_name);
        if (release_worker == nullptr)
        {
            std::fprintf(stderr, "FAIL[bare]: CreateEventW failed (error %lu)\n", GetLastError());
            return 2;
        }
        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[bare]: LoadLibraryW failed (error %lu)\n", GetLastError());
            CloseHandle(release_worker);
            return 2;
        }
        void *marker = reinterpret_cast<void *>(resolve_required(dll, "dmk_probe_marker", "bare"));
        if (marker == nullptr)
        {
            CloseHandle(release_worker);
            return 2;
        }
        WorkerReadyFn worker_ready = resolve_required(dll, "dmk_probe_worker_ready", "bare");
        if (worker_ready == nullptr)
        {
            CloseHandle(release_worker);
            return 2;
        }
        if (!wait_for_worker_ready(worker_ready))
        {
            std::fprintf(stderr, "FAIL[bare]: worker did not report readiness within %lu ms\n", READY_POLL_BUDGET_MS);
            FreeLibrary(dll);
            CloseHandle(release_worker);
            return 1;
        }

        // Drop the host's reference while on_ready is paused. Only the worker reference remains, so the DLL must stay
        // mapped until that worker performs its terminal FreeLibraryAndExitThread.
        if (FreeLibrary(dll) == FALSE)
        {
            std::fprintf(stderr, "FAIL[bare]: FreeLibrary failed (error %lu)\n", GetLastError());
            CloseHandle(release_worker);
            return 2;
        }
        if (!module_owns(marker))
        {
            std::fprintf(stderr, "FAIL[bare]: the DLL unmapped while its worker was paused\n");
            CloseHandle(release_worker);
            return 1;
        }

        if (SetEvent(release_worker) == FALSE)
        {
            std::fprintf(stderr, "FAIL[bare]: SetEvent failed (error %lu)\n", GetLastError());
            CloseHandle(release_worker);
            return 2;
        }
        CloseHandle(release_worker);

        DWORD waited = 0;
        while (module_owns(marker) && waited < UNLOAD_POLL_BUDGET_MS)
        {
            Sleep(UNLOAD_POLL_STEP_MS);
            waited += UNLOAD_POLL_STEP_MS;
        }
        if (module_owns(marker))
        {
            std::fprintf(stderr,
                         "FAIL[bare]: the worker's terminal release did not complete the real detach within %lu ms\n",
                         waited);
            return 1;
        }

        std::printf("PASS[bare]: the captureless worker self-drained through real detach without a loader-lock wait\n");
        return 0;
    }

    int run_drained_unloads(const wchar_t *wide_path)
    {
        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[unload]: LoadLibraryW failed (error %lu)\n", GetLastError());
            return 2;
        }
        void *marker = reinterpret_cast<void *>(resolve_required(dll, "dmk_probe_marker", "unload"));
        if (marker == nullptr)
        {
            return 2;
        }
        WorkerReadyFn worker_ready = resolve_required(dll, "dmk_probe_worker_ready", "unload");
        if (worker_ready == nullptr)
        {
            return 2;
        }
        DrainFn shutdown_and_wait = resolve_required(dll, "dmk_probe_shutdown_and_wait", "unload");
        if (shutdown_and_wait == nullptr)
        {
            return 2;
        }

        if (!wait_for_worker_ready(worker_ready))
        {
            std::fprintf(stderr, "FAIL[unload]: worker did not report readiness within %lu ms\n", READY_POLL_BUDGET_MS);
            FreeLibrary(dll);
            return 1;
        }

        // The synchronous drain returns after the worker's ordered teardown and module-reference release. The matching
        // FreeLibrary then drops the consumer's reference and lets the loader unmap the DLL.
        if (shutdown_and_wait() == FALSE)
        {
            std::fprintf(stderr, "FAIL[unload]: shutdown_and_wait reported failure\n");
            FreeLibrary(dll);
            return 1;
        }
        if (FreeLibrary(dll) == FALSE)
        {
            std::fprintf(stderr, "FAIL[unload]: FreeLibrary failed (error %lu)\n", GetLastError());
            return 2;
        }

        DWORD waited = 0;
        while (module_owns(marker) && waited < UNLOAD_POLL_BUDGET_MS)
        {
            Sleep(UNLOAD_POLL_STEP_MS);
            waited += UNLOAD_POLL_STEP_MS;
        }

        if (module_owns(marker))
        {
            std::fprintf(stderr,
                         "FAIL[unload]: the DLL is still mapped %lu ms after a drained FreeLibrary; the worker's "
                         "reference was not released (a permanent pin would leave it mapped like this)\n",
                         waited);
            return 1;
        }

        std::printf("PASS[unload]: draining the worker released its module reference; the DLL unloaded after %lu ms\n",
                    waited);
        return 0;
    }

    int run_process_exit(const wchar_t *wide_path)
    {
        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[exit]: LoadLibraryW failed (error %lu)\n", GetLastError());
            return 2;
        }
        WorkerReadyFn worker_ready = resolve_required(dll, "dmk_probe_worker_ready", "exit");
        if (worker_ready == nullptr)
        {
            return 2;
        }
        const auto attach_succeeded =
            reinterpret_cast<AttachSucceededFn>(resolve_required(dll, "dmk_probe_attach_succeeded", "exit"));
        if (attach_succeeded == nullptr)
        {
            return 2;
        }
        if (attach_succeeded() == FALSE)
        {
            std::fprintf(stderr, "FAIL[exit]: bootstrap_attach rejected the attach request\n");
            FreeLibrary(dll);
            return 1;
        }
        if (!wait_for_worker_ready(worker_ready))
        {
            std::fprintf(stderr, "FAIL[exit]: worker did not report readiness within %lu ms\n", READY_POLL_BUDGET_MS);
            FreeLibrary(dll);
            return 1;
        }

        // Leave both the host and worker references live. Returning from main drives the operating system's
        // process-exit detach path, including the reserved != nullptr abandonment branch in the probe's DllMain.
        std::printf("PASS[exit]: returning with the probe DLL and bootstrap worker live\n");
        return 0;
    }

    int run_reload_mutex_process_exit(const wchar_t *wide_path)
    {
        wchar_t event_name[96]{};
        make_reload_mutex_exit_event_name(event_name);
        const HANDLE requested = CreateEventW(nullptr, TRUE, FALSE, event_name);
        if (requested == nullptr)
        {
            std::fprintf(stderr, "FAIL[reload-exit]: CreateEventW failed (error %lu)\n", GetLastError());
            return 2;
        }

        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[reload-exit]: LoadLibraryW failed (error %lu)\n", GetLastError());
            CloseHandle(requested);
            return 2;
        }
        WorkerReadyFn worker_ready = resolve_required(dll, "dmk_probe_worker_ready", "reload-exit");
        if (worker_ready == nullptr)
        {
            CloseHandle(requested);
            return 2;
        }
        const auto attach_succeeded =
            reinterpret_cast<AttachSucceededFn>(resolve_required(dll, "dmk_probe_attach_succeeded", "reload-exit"));
        if (attach_succeeded == nullptr)
        {
            CloseHandle(requested);
            return 2;
        }
        const auto reload_mutex_owned =
            reinterpret_cast<ReloadMutexOwnedFn>(resolve_required(dll, "dmk_probe_reload_mutex_owned", "reload-exit"));
        if (reload_mutex_owned == nullptr)
        {
            CloseHandle(requested);
            return 2;
        }
        // The three checks below deliberately do NOT FreeLibrary before returning, unlike every other scenario in this
        // file. Past the attach the reload worker may already be parked inside Channel::mutex, and FreeLibrary would
        // run static teardown on THIS live thread while that owner is still running, which is the blocking shape the
        // scenario exists to detect. Returning instead lets Windows terminate the parked worker first, so a genuine
        // setup failure reports its own diagnostic rather than surfacing as the watchdog timeout.
        if (attach_succeeded() == FALSE)
        {
            std::fprintf(stderr, "FAIL[reload-exit]: bootstrap_attach rejected the attach request\n");
            CloseHandle(requested);
            return 1;
        }
        if (!wait_for_worker_ready(worker_ready))
        {
            std::fprintf(stderr, "FAIL[reload-exit]: worker did not report readiness within %lu ms\n",
                         READY_POLL_BUDGET_MS);
            CloseHandle(requested);
            return 1;
        }
        if (reload_mutex_owned() == FALSE)
        {
            std::fprintf(stderr, "FAIL[reload-exit]: reload worker was not parked while owning its channel mutex\n");
            CloseHandle(requested);
            return 1;
        }

        CloseHandle(requested);
        // The probe owns the mutex when main returns. Windows terminates that worker before process-detach callbacks,
        // so any static teardown that waits for the mutex or invokes its locking stop callback hangs under the loader
        // lock. CTest's timeout is the watchdog for that regression.
        std::printf("PASS[reload-exit]: returning with the reload worker parked inside its channel mutex\n");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    const char *mode = (argc >= 2) ? argv[1] : "mapped";
    // Default to the bare DLL name so the loader resolves it from the application directory, which is always first in
    // the DLL search order and holds the companion DLL the runner builds alongside this executable.
    const char *dll_path = (argc >= 3) ? argv[2] : "bootstrap_probe.dll";

    wchar_t wide_path[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, dll_path, -1, wide_path, MAX_PATH) <= 0)
    {
        std::fprintf(stderr, "FAIL: could not widen DLL path '%s'\n", dll_path);
        return 2;
    }

    if (std::strcmp(mode, "mapped") == 0)
    {
        return run_stays_mapped(wide_path);
    }
    if (std::strcmp(mode, "unload") == 0)
    {
        return run_drained_unloads(wide_path);
    }
    if (std::strcmp(mode, "leaf") == 0)
    {
        return run_attach_is_leaf(wide_path);
    }
    if (std::strcmp(mode, "bare") == 0)
    {
        return run_bare_free_library_self_drain(wide_path);
    }
    if (std::strcmp(mode, "exit") == 0)
    {
        return run_process_exit(wide_path);
    }
    if (std::strcmp(mode, "reload-exit") == 0)
    {
        return run_reload_mutex_process_exit(wide_path);
    }

    std::fprintf(stderr, "usage: %s <mapped|leaf|unload|bare|exit|reload-exit> [path-to-bootstrap_probe.dll]\n",
                 argv[0]);
    return 2;
}
