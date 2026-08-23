/**
 * @file test_input_loader_detach.cpp
 * @brief Hosts the bare-FreeLibrary T-INPUT-LOADER proof.
 */

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iterator>

namespace
{
    constexpr DWORD UNLOAD_POLL_BUDGET_MS = 3000;
    constexpr DWORD UNLOAD_POLL_STEP_MS = 10;

    using ProbeFlagFn = INT_PTR(WINAPI *)();
    using ProbeVoidFn = void(WINAPI *)();

    void make_capture_destroyed_event_name(wchar_t (&name)[96]) noexcept
    {
        (
            void
        )std::swprintf(name, std::size(name), L"Local\\DMK_InputLoader_CaptureDestroyed_%lu", GetCurrentProcessId());
    }

    FARPROC resolve_required(HMODULE dll, const char *symbol) noexcept
    {
        const FARPROC fn = GetProcAddress(dll, symbol);
        if (fn == nullptr)
        {
            std::fprintf(stderr, "FAIL: GetProcAddress('%s') failed (error %lu)\n", symbol, GetLastError());
            FreeLibrary(dll);
        }
        return fn;
    }

    bool module_owns(void *addr) noexcept
    {
        HMODULE owner = nullptr;
        const BOOL ok = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(addr),
            &owner
        );
        return ok != FALSE && owner != nullptr;
    }
} // namespace

int main(int argc, char **argv)
{
    // The companion DLL sits beside this executable.
    const char *dll_path = (argc >= 2) ? argv[1] : "input_loader_probe.dll";
    wchar_t wide_path[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, dll_path, -1, wide_path, MAX_PATH) <= 0)
    {
        std::fprintf(stderr, "FAIL: could not widen DLL path '%s'\n", dll_path);
        return 2;
    }

    wchar_t event_name[96]{};
    make_capture_destroyed_event_name(event_name);
    const HANDLE capture_destroyed = CreateEventW(nullptr, TRUE, FALSE, event_name);
    if (capture_destroyed == nullptr)
    {
        std::fprintf(stderr, "FAIL: CreateEventW failed (error %lu)\n", GetLastError());
        return 2;
    }

    const HMODULE dll = LoadLibraryW(wide_path);
    if (dll == nullptr)
    {
        std::fprintf(stderr, "FAIL: LoadLibraryW failed (error %lu)\n", GetLastError());
        CloseHandle(capture_destroyed);
        return 2;
    }

    const auto stage = reinterpret_cast<ProbeFlagFn>(resolve_required(dll, "dmk_input_probe_stage"));
    if (stage == nullptr)
    {
        CloseHandle(capture_destroyed);
        return 2;
    }
    const auto selftest = reinterpret_cast<ProbeFlagFn>(resolve_required(dll, "dmk_input_probe_selftest_witness"));
    if (selftest == nullptr)
    {
        CloseHandle(capture_destroyed);
        return 2;
    }
    const auto arm = reinterpret_cast<ProbeVoidFn>(resolve_required(dll, "dmk_input_probe_arm_witness"));
    if (arm == nullptr)
    {
        CloseHandle(capture_destroyed);
        return 2;
    }
    const auto hold_mutex = reinterpret_cast<ProbeVoidFn>(resolve_required(dll, "dmk_input_probe_hold_facade_mutex"));
    if (hold_mutex == nullptr)
    {
        CloseHandle(capture_destroyed);
        return 2;
    }
    const auto park_scope_guard =
        reinterpret_cast<ProbeFlagFn>(resolve_required(dll, "dmk_input_probe_park_scope_guard"));
    if (park_scope_guard == nullptr)
    {
        CloseHandle(capture_destroyed);
        return 2;
    }
    void *const marker = reinterpret_cast<void *>(GetProcAddress(dll, "dmk_input_probe_marker"));
    if (marker == nullptr)
    {
        std::fprintf(stderr, "FAIL: GetProcAddress('dmk_input_probe_marker') failed (error %lu)\n", GetLastError());
        FreeLibrary(dll);
        CloseHandle(capture_destroyed);
        return 2;
    }

    if (stage() == FALSE)
    {
        std::fprintf(stderr, "FAIL: the probe could not stage its witness binding\n");
        FreeLibrary(dll);
        CloseHandle(capture_destroyed);
        return 2;
    }

    if (selftest() == FALSE)
    {
        std::fprintf(stderr, "FAIL: the witness self-test could not resolve the event\n");
        FreeLibrary(dll);
        CloseHandle(capture_destroyed);
        return 2;
    }
    if (WaitForSingleObject(capture_destroyed, 0) != WAIT_OBJECT_0)
    {
        std::fprintf(stderr, "FAIL: the armed witness control did not signal, so the oracle is vacuous\n");
        FreeLibrary(dll);
        CloseHandle(capture_destroyed);
        return 1;
    }
    if (ResetEvent(capture_destroyed) == FALSE)
    {
        std::fprintf(stderr, "FAIL: ResetEvent failed (error %lu)\n", GetLastError());
        FreeLibrary(dll);
        CloseHandle(capture_destroyed);
        return 2;
    }

    // Until the parked guard becomes the sole capture owner, keep the witness inactive.
    if (park_scope_guard() == FALSE)
    {
        std::fprintf(stderr, "FAIL: the probe failed to park a sole-owner guard in the process-default Scope\n");
        FreeLibrary(dll);
        CloseHandle(capture_destroyed);
        return 2;
    }

    arm();

    // Any shutdown path that takes it stalls until the CTest timeout.
    hold_mutex();

    if (FreeLibrary(dll) == FALSE)
    {
        std::fprintf(stderr, "FAIL: FreeLibrary failed (error %lu)\n", GetLastError());
        CloseHandle(capture_destroyed);
        return 1;
    }

    DWORD waited = 0;
    while (module_owns(marker) && waited < UNLOAD_POLL_BUDGET_MS)
    {
        Sleep(UNLOAD_POLL_STEP_MS);
        waited += UNLOAD_POLL_STEP_MS;
    }
    if (module_owns(marker))
    {
        std::fprintf(stderr, "FAIL: the probe DLL did not unmap within %lu ms\n", waited);
        CloseHandle(capture_destroyed);
        return 1;
    }

    const DWORD witness_state = WaitForSingleObject(capture_destroyed, 0);
    if (witness_state == WAIT_OBJECT_0)
    {
        std::fprintf(
            stderr,
            "FAIL: loader-lock static destruction destroyed a staged or Scope-parked consumer "
            "capture\n"
        );
        CloseHandle(capture_destroyed);
        return 1;
    }
    if (witness_state != WAIT_TIMEOUT)
    {
        std::fprintf(stderr, "FAIL: witness wait failed (error %lu)\n", GetLastError());
        CloseHandle(capture_destroyed);
        return 2;
    }

    CloseHandle(capture_destroyed);
    std::printf("PASS: bare FreeLibrary retained the complete input facade owner with no capture destruction\n");
    return 0;
}
