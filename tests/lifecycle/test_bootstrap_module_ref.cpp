/**
 * @file test_bootstrap_module_ref.cpp
 * @brief Module-reference lifecycle proofs for the async bootstrap worker.
 *
 * @details The bootstrap path takes a counted reference on its own module before creating the lifecycle worker, so a
 *          consumer's later FreeLibrary cannot unmap the worker's code before the worker runs or while it is still
 *          running. The worker releases that reference with FreeLibraryAndExitThread when it exits, so no return
 *          address lives in code the release may unmap.
 *
 *          Two scenarios, selected by argv[1] and each run in its own process (the bootstrap statics are
 *          process-global, so a single process hosts exactly one session):
 *
 *          - "mapped": LoadLibrary -> a single balanced FreeLibrary -> the module is still mapped. The worker reference
 *            is acquired before CreateThread, so this remains true even if the worker has not started executing yet.
 *
 *          - "unload": LoadLibrary -> wait for worker readiness -> request_shutdown (drains the worker off the loader
 *            lock, so it runs its ordered teardown, releases its reference, and exits) -> FreeLibrary -> the module
 *            unloads. This proves the reference is counted and releasable, not a permanent process-lifetime pin.
 *
 *          Built and run as a standalone executable (no test framework) by scripts/run_lifecycle_proofs.sh; the exit
 *          code is the verdict.
 */

#include <windows.h>

#include <cstdio>
#include <cstring>

namespace
{
    // The drained-unload scenario polls for worker readiness and then for the final unmap instead of guessing fixed
    // sleeps. A few seconds is far more than the teardown needs and keeps the proof non-flaky.
    constexpr DWORD READY_POLL_BUDGET_MS = 3000;
    constexpr DWORD READY_POLL_STEP_MS = 10;
    constexpr DWORD UNLOAD_POLL_BUDGET_MS = 3000;
    constexpr DWORD UNLOAD_POLL_STEP_MS = 10;

    using WorkerReadyFn = FARPROC;
    using RequestShutdownFn = FARPROC;

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
        const HMODULE dll = LoadLibraryW(wide_path);
        if (dll == nullptr)
        {
            std::fprintf(stderr, "FAIL[mapped]: LoadLibraryW failed (error %lu)\n", GetLastError());
            return 2;
        }
        void *marker = reinterpret_cast<void *>(resolve_required(dll, "dmk_probe_marker", "mapped"));
        if (marker == nullptr)
        {
            return 2;
        }

        // Balanced single FreeLibrary immediately after LoadLibrary. The worker's counted reference was acquired before
        // CreateThread, so the module stays mapped even if the worker has not started executing yet.
        if (FreeLibrary(dll) == FALSE)
        {
            std::fprintf(stderr, "FAIL[mapped]: FreeLibrary failed (error %lu)\n", GetLastError());
            return 2;
        }

        if (!module_owns(marker))
        {
            std::fprintf(stderr, "FAIL[mapped]: the DLL unmapped after a bare FreeLibrary; the worker reference was "
                                 "not acquired before the caller could unload the module\n");
            return 1;
        }

        std::printf(
            "PASS[mapped]: the worker's counted module reference kept the DLL mapped across a bare FreeLibrary\n");
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
        RequestShutdownFn request_shutdown = resolve_required(dll, "dmk_probe_request_shutdown", "unload");
        if (request_shutdown == nullptr)
        {
            return 2;
        }

        if (!wait_for_worker_ready(worker_ready))
        {
            std::fprintf(stderr, "FAIL[unload]: worker did not report readiness within %lu ms\n", READY_POLL_BUDGET_MS);
            FreeLibrary(dll);
            return 1;
        }

        // Drain the worker off the loader lock: it runs its ordered teardown, releases its module reference via
        // FreeLibraryAndExitThread, and exits. Then a matching FreeLibrary drops the consumer's own reference. Once
        // both are gone the count reaches zero and the loader unmaps the DLL.
        request_shutdown();
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

    std::fprintf(stderr, "usage: %s <mapped|unload> [path-to-bootstrap_probe.dll]\n", argv[0]);
    return 2;
}
