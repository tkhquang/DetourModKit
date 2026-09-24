/** @file process_exit_release_dll.cpp
 * @brief Holds teardown resources across actual process termination.
 */

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/memory.hpp"

#include "internal/lifecycle_context.hpp"
#include "internal/memory_fault.hpp"
#include "internal/memory_guarded.hpp"

#include <windows.h>

#include <cstdint>

namespace
{
    HANDLE s_ready = nullptr;
    HANDLE s_marker = INVALID_HANDLE_VALUE;
    int s_schedule = 0;
    std::uint64_t s_value = 42;

    void park(void *) noexcept
    {
        SetEvent(s_ready);
        Sleep(INFINITE);
    }

    DWORD WINAPI hold_resource(void *) noexcept
    {
        using namespace DetourModKit;
        if (s_schedule == 2)
        {
            diagnostics::hook_lifecycle().emit_safe({});
        }
#if !defined(_MSC_VER) && defined(_WIN64)
        else if (s_schedule == 1)
        {
            detail::with_guarded_engine_lock_for_test(&park, nullptr);
        }
        else
        {
            const auto address = reinterpret_cast<std::uintptr_t>(&s_value);
            (void)detail::run_guarded_region(address, address + sizeof(s_value), &park, nullptr);
        }
#endif
        return 0;
    }
} // namespace

/** @brief Parks the selected resource until process termination and prepares the result marker. */
extern "C" __declspec(dllexport) int dmk_prepare_process_exit(int schedule, const wchar_t *marker)
{
    using namespace DetourModKit;
    s_schedule = schedule;
    s_marker = CreateFileW(marker, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    s_ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (s_marker == INVALID_HANDLE_VALUE || s_ready == nullptr)
        return 1;

    Subscription subscription;
    if (schedule == 2)
    {
        subscription = diagnostics::hook_lifecycle().subscribe([](const diagnostics::HookLifecycleEvent &) noexcept
                                                               { park(nullptr); });
        if (!subscription.active())
            return 2;
    }
    else
    {
        std::uint64_t copy = 0;
        if (!detail::guarded_read_bytes(reinterpret_cast<std::uintptr_t>(&s_value), &copy, sizeof(copy)) ||
            copy != s_value)
            return 3;
    }

    const HANDLE worker = CreateThread(nullptr, 0, &hold_resource, nullptr, 0, nullptr);
    if (worker == nullptr)
        return 4;
    CloseHandle(worker);
    if (WaitForSingleObject(s_ready, 5000) != WAIT_OBJECT_0)
        return 5;
    // The emit retains its snapshot after the subscription retires.
    subscription.reset();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved) noexcept
{
    if (reason == DLL_PROCESS_DETACH && reserved != nullptr && s_marker != INVALID_HANDLE_VALUE)
    {
        using namespace DetourModKit;
        if (detail::lifecycle().loader_context() != detail::LoaderContext::Normal)
            return TRUE;
        memory::shutdown_cache();
        if (diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Diagnostics) == 0)
        {
            constexpr char marker[] = "EXIT_RELEASE_RETURNED";
            DWORD written = 0;
            (void)WriteFile(s_marker, marker, sizeof(marker), &written, nullptr);
        }
        CloseHandle(s_marker);
    }
    return TRUE;
}
