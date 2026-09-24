/**
 * @file veh_unmap_dll.cpp
 * @brief Runs hook and guarded-engine epochs before the host unmaps this fixture.
 */

#include "DetourModKit/hook.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/session.hpp"

#include "internal/memory_fault.hpp"
#include "internal/memory_guarded.hpp"

#include <windows.h>

#include <cstdint>
#include <optional>
#include <utility>

namespace
{
    using TargetFn = int (*)(int) noexcept;

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
     *        memory::shutdown_cache() afterwards. 2 also initializes the cache. 3 drops the Session before the Hook.
     *        4 then restarts the Session. 5 instead initializes the cache.
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
            if (teardown >= 3)
            {
                session.reset();
            }
        }

#if !defined(_MSC_VER) && defined(_WIN64)
        if (teardown >= 3)
        {
            const std::uint64_t value = 42;
            const auto address = reinterpret_cast<std::uintptr_t>(&value);
            const auto read = memory::read<std::uint64_t>(Address{address});
            if (!read || *read != value || detail::guarded_engine_tls_index_for_test() != TLS_OUT_OF_INDEXES)
                return 15;
            bool called = false;
            const auto mark = [](void *context) noexcept { *static_cast<bool *>(context) = true; };
            if (detail::run_guarded_region(address, address + sizeof(value), mark, &called) || called)
                return 16;
            if (teardown == 4)
            {
                auto restarted = Session::start(
                    ModInfo{
                        .name = "VEH_RESTART",
                        .log_file = log_file,
                    }
                );
                if (!restarted)
                    return 17;
                session.emplace(std::move(*restarted));
            }
            if (teardown == 5 && !memory::init_cache())
                return 18;
            if (teardown >= 4 && (!detail::run_guarded_region(address, address + sizeof(value), mark, &called) ||
                                  !called || detail::guarded_engine_tls_index_for_test() == TLS_OUT_OF_INDEXES))
                return 19;
        }
#endif

        if (teardown == 1 || teardown == 5)
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
