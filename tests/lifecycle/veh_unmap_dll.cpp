/**
 * @file veh_unmap_dll.cpp
 * @brief Logic-DLL fixture for the guarded-read handler lifetime proof: one hook generation under a selected teardown.
 * @details Links the DetourModKit archive the way a mod DLL does. The host (veh_survives_unmap.cpp) selects the
 *          teardown shape, unloads this image, and then dispatches exceptions. It owns the claim and the oracle.
 */

#include "DetourModKit/hook.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/session.hpp"

#include <windows.h>

#include <cstdint>
#include <optional>
#include <utility>

namespace
{
    using TargetFn = int (*)(int) noexcept;

    // A no-op detour. The proof needs an install, whose preflight performs the guarded read that installs the handler,
    // not hooked behavior. The host target returns amount + 1, so a call that reaches this body is distinguishable.
    int veh_unmap_detour(int amount) noexcept
    {
        return amount;
    }
} // namespace

extern "C"
{
    /**
     * @brief Runs one hook generation under the teardown the host selected.
     * @param teardown 0 runs the hook under Session::start with no init_cache. 1 runs it with no Session and calls
     *        memory::shutdown_cache() afterwards. 2 runs it under Session::start plus memory::init_cache().
     * @param target Address of the host function to hook.
     * @param log_file NUL-terminated log path for the Session.
     * @return 0 on success, or the failed step's code for the host to report.
     */
    __declspec(dllexport) int dmk_veh_run_generation(int teardown, std::uintptr_t target, const char *log_file) noexcept
    {
        using namespace DetourModKit;

        std::optional<Session> session;
        if (teardown != 1)
        {
            Result<Session> started = Session::start(
                ModInfo{
                    .name = "VEH_UNMAP",
                    .log_file = log_file,
                }
            );
            if (!started)
            {
                return 10;
            }
            session.emplace(std::move(*started));
            if (teardown == 2 && !memory::init_cache())
            {
                return 11;
            }
        }

        {
            Result<hook::Hook> installed = hook::inline_at(
                hook::InlineRequest{
                    .name = "veh_unmap_target",
                    .target = Address{target},
                },
                &veh_unmap_detour
            );
            if (!installed)
            {
                return 12;
            }
            if (Result<void> armed = installed->enable(); !armed)
            {
                return 13;
            }
            TargetFn volatile call = reinterpret_cast<TargetFn>(target);
            if (call(7) != 7)
            {
                return 14;
            }
        }

        if (teardown == 1)
        {
            memory::shutdown_cache();
        }
        session.reset();
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}
