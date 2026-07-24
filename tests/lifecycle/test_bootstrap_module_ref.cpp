/**
 * @file test_bootstrap_module_ref.cpp
 * @brief Module-reference lifecycle proofs for the async bootstrap worker.
 *
 * @details The bootstrap path takes a counted reference on its own module before creating the lifecycle worker, so a
 *          consumer's later FreeLibrary cannot unmap the worker's code before the worker runs or while it is still
 *          running. The worker releases that reference with FreeLibraryAndExitThread when it exits, so no return
 *          address lives in code the release may unmap.
 *
 *          Five scenarios, selected by argv[1] and each run in its own process (the bootstrap statics are
 *          process-global, so a single process hosts exactly one session):
 *
 *          - "mapped": LoadLibrary -> a single balanced FreeLibrary -> the module is still mapped by an attach-time
 *            counted reference, asserted without waiting for the worker so it holds even before the worker has
 *            executed.
 *
 *          - "leaf": LoadLibrary -> inspect attach telemetry -> synchronous drain -> FreeLibrary. The attach thread
 *            must publish the worker without performing heap-backed logger or Session setup.
 *
 *          - "unload": LoadLibrary -> wait for worker readiness -> synchronous drain -> FreeLibrary -> the module
 *            unloads. This proves the reference is counted and releasable, not a permanent process-lifetime pin.
 *
 *          - "bare": a host event pauses on_ready, then the host drops its LoadLibrary reference before releasing the
 *            worker. The worker requests its own shutdown and its terminal reference release drives a real
 *            DLL_PROCESS_DETACH. The module must unmap without a loader-lock wait or consumer-state destruction.
 *
 *          - "exit": LoadLibrary -> wait for worker readiness -> return from main with the DLL still loaded. Process
 *            termination must deliver DLL_PROCESS_DETACH with a live worker without hanging or faulting.
 *
 *          Built and run as a standalone executable (no test framework) by scripts/run_lifecycle_proofs.sh; the exit
 *          code is the verdict.
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

    void make_worker_release_event_name(wchar_t (&name)[96]) noexcept
    {
        (void)std::swprintf(name, std::size(name), L"Local\\DMK_Bootstrap_SelfDrain_%lu", GetCurrentProcessId());
    }

    void make_capture_destroyed_event_name(wchar_t (&name)[96]) noexcept
    {
        (void)std::swprintf(name, std::size(name), L"Local\\DMK_Bootstrap_CaptureDestroyed_%lu", GetCurrentProcessId());
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
        wchar_t capture_event_name[96]{};
        make_capture_destroyed_event_name(capture_event_name);
        const HANDLE capture_destroyed = CreateEventW(nullptr, TRUE, FALSE, capture_event_name);
        if (capture_destroyed == nullptr)
        {
            std::fprintf(stderr, "FAIL[mapped]: capture CreateEventW failed (error %lu)\n", GetLastError());
            CloseHandle(release_worker);
            return 2;
        }

        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[mapped]: LoadLibraryW failed (error %lu)\n", GetLastError());
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 2;
        }
        void *marker = reinterpret_cast<void *>(resolve_required(dll, "dmk_probe_marker", "mapped"));
        if (marker == nullptr)
        {
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 2;
        }
        WorkerReadyFn worker_ready = resolve_required(dll, "dmk_probe_worker_ready", "mapped");
        if (worker_ready == nullptr)
        {
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 2;
        }
        // Balanced single FreeLibrary immediately after LoadLibrary, with no wait for the worker: the assertion is
        // that a counted reference taken during attach outlives the caller's own, even before the worker has executed
        // its first instruction. Not waiting keeps that the strongest form of the claim.
        if (FreeLibrary(dll) == FALSE)
        {
            std::fprintf(stderr, "FAIL[mapped]: FreeLibrary failed (error %lu)\n", GetLastError());
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 2;
        }

        if (!module_owns(marker))
        {
            std::fprintf(stderr, "FAIL[mapped]: the DLL unmapped after a bare FreeLibrary; the worker reference was "
                                 "not acquired before the caller could unload the module\n");
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 1;
        }

        // Let the worker release the remaining reference itself so the proof exits through an ordinary drained unload
        // instead of relying on process-exit thread termination for cleanup. Readiness guarantees the worker has opened
        // the named event before the host closes its last event handle.
        if (!wait_for_worker_ready(worker_ready))
        {
            std::fprintf(stderr, "FAIL[mapped]: worker did not report readiness within %lu ms\n", READY_POLL_BUDGET_MS);
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 1;
        }
        if (SetEvent(release_worker) == FALSE)
        {
            std::fprintf(stderr, "FAIL[mapped]: SetEvent failed (error %lu)\n", GetLastError());
            CloseHandle(capture_destroyed);
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
        CloseHandle(capture_destroyed);
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
            std::fprintf(stderr, "FAIL[leaf]: bootstrap rejected the attach request\n");
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
            std::fprintf(stderr, "FAIL[leaf]: bootstrap made %llu attach-thread heap allocation(s)\n",
                         static_cast<unsigned long long>(allocation_count));
            return 1;
        }
        if (!drain_ok)
        {
            std::fprintf(stderr, "FAIL[leaf]: shutdown_and_wait reported failure\n");
            return 1;
        }

        std::printf("PASS[leaf]: bootstrap published the worker without attach-thread heap allocation\n");
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
        wchar_t capture_event_name[96]{};
        make_capture_destroyed_event_name(capture_event_name);
        const HANDLE capture_destroyed = CreateEventW(nullptr, TRUE, FALSE, capture_event_name);
        if (capture_destroyed == nullptr)
        {
            std::fprintf(stderr, "FAIL[bare]: capture CreateEventW failed (error %lu)\n", GetLastError());
            CloseHandle(release_worker);
            return 2;
        }

        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[bare]: LoadLibraryW failed (error %lu)\n", GetLastError());
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 2;
        }
        void *marker = reinterpret_cast<void *>(resolve_required(dll, "dmk_probe_marker", "bare"));
        if (marker == nullptr)
        {
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 2;
        }
        WorkerReadyFn worker_ready = resolve_required(dll, "dmk_probe_worker_ready", "bare");
        if (worker_ready == nullptr)
        {
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 2;
        }
        if (!wait_for_worker_ready(worker_ready))
        {
            std::fprintf(stderr, "FAIL[bare]: worker did not report readiness within %lu ms\n", READY_POLL_BUDGET_MS);
            FreeLibrary(dll);
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 1;
        }

        // Drop the host's reference while on_ready is paused. Only the worker reference remains, so the DLL must stay
        // mapped until that worker performs its terminal FreeLibraryAndExitThread.
        if (FreeLibrary(dll) == FALSE)
        {
            std::fprintf(stderr, "FAIL[bare]: FreeLibrary failed (error %lu)\n", GetLastError());
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 2;
        }
        if (!module_owns(marker))
        {
            std::fprintf(stderr, "FAIL[bare]: the DLL unmapped while its worker was paused\n");
            CloseHandle(capture_destroyed);
            CloseHandle(release_worker);
            return 1;
        }

        if (SetEvent(release_worker) == FALSE)
        {
            std::fprintf(stderr, "FAIL[bare]: SetEvent failed (error %lu)\n", GetLastError());
            CloseHandle(capture_destroyed);
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
            CloseHandle(capture_destroyed);
            return 1;
        }
        const DWORD capture_state = WaitForSingleObject(capture_destroyed, 0);
        if (capture_state == WAIT_OBJECT_0)
        {
            std::fprintf(stderr, "FAIL[bare]: real detach destroyed the retained callback capture\n");
            CloseHandle(capture_destroyed);
            return 1;
        }
        if (capture_state != WAIT_TIMEOUT)
        {
            std::fprintf(stderr, "FAIL[bare]: capture witness wait failed (error %lu)\n", GetLastError());
            CloseHandle(capture_destroyed);
            return 2;
        }
        CloseHandle(capture_destroyed);

        std::printf(
            "PASS[bare]: the worker self-drained through real detach without destroying its callback capture\n");
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
            std::fprintf(stderr, "FAIL[exit]: bootstrap rejected the attach request\n");
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

    std::fprintf(stderr, "usage: %s <mapped|leaf|unload|bare|exit> [path-to-bootstrap_probe.dll]\n", argv[0]);
    return 2;
}
