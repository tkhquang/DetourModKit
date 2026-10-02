/**
 * @file routed_bypass_continuation.cpp
 * @brief Verifies non-mid bypass ownership, the teardown drain, and provider lifetime across dormant fibers.
 */

#include "internal/input_intercept.hpp"

#include <safetyhook.hpp>
#include <safetyhook/os.hpp>

#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string_view>
#include <thread>

namespace
{
    using TargetFn = DWORD(WINAPI *)(DWORD, void *);
    constexpr DWORD EXPECTED_VALUE = 37;
    constexpr DWORD WAIT_MS = 10000;
    void *s_driver = nullptr;
    TargetFn s_target = nullptr;
    DWORD s_result = 0;
    std::atomic<bool> s_dormant{false};
    std::atomic<bool> s_resume{false};
    std::atomic<bool> s_hold_callee{false};
    std::atomic<bool> s_in_callee{false};
    std::atomic<bool> s_callee_release{false};
    std::atomic<bool> s_caller_returned{false};
    std::atomic<bool> s_workers_may_exit{false};
    std::atomic<bool> s_exit_during_scan{false};
    std::atomic<bool> s_exit_released{false};
    std::atomic<bool> s_suspend_refused{false};
    std::atomic<DWORD> s_caller_thread_id{0};
    HANDLE s_caller_thread = nullptr;

    DWORD WINAPI suspend_thread(HANDLE thread) noexcept
    {
        using SuspendFn = DWORD(WINAPI *)(HANDLE);
        const auto suspend = reinterpret_cast<SuspendFn>(
            reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SuspendThread"))
        );
        if (s_exit_during_scan.load(std::memory_order_acquire) && s_caller_returned.load(std::memory_order_acquire) &&
            !s_exit_released.exchange(true))
        {
            // The backend opens its complete handle set before the first suspension.
            s_workers_may_exit.store(true, std::memory_order_release);
            if (WaitForSingleObject(s_caller_thread, WAIT_MS) != WAIT_OBJECT_0)
            {
                std::fputs("FAIL: the scan control did not observe native thread exit\n", stderr);
                ExitProcess(10);
            }
        }
        const DWORD result = suspend(thread);
        if (result == static_cast<DWORD>(-1) && s_exit_released.load())
        {
            const DWORD error = GetLastError();
            s_suspend_refused.store(true);
            std::fprintf(stderr, "SCAN_THREAD_EXIT_NATIVE_REFUSAL error=%lu\n", error);
            SetLastError(error);
        }
        return result;
    }

    void park_worker_until_reclaim() noexcept
    {
        // The clean case keeps native threads alive through both idle scans.
        while (!s_workers_may_exit.load(std::memory_order_acquire))
            YieldProcessor();
    }

    enum class Scenario
    {
        Fiber,
        Clean,
        Drain,
        ThreadExit,
    };

    template <class Predicate> void wait_until(Predicate predicate) noexcept
    {
        const auto deadline = GetTickCount64() + WAIT_MS;
        while (!predicate())
        {
            if (GetTickCount64() >= deadline)
            {
                std::fputs("FAIL: bypass schedule timed out\n", stderr);
                ExitProcess(9);
            }
            Sleep(1);
        }
    }

    DWORD provider_callee() noexcept
    {
        if (s_hold_callee.load())
        {
            s_in_callee.store(true);
            wait_until([]() noexcept -> bool { return s_callee_release.load(); });
        }
        if (s_driver != nullptr)
        {
            SwitchToFiber(s_driver);
        }
        return EXPECTED_VALUE;
    }

    void call_target() noexcept
    {
        s_caller_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
        const TargetFn volatile target = s_target;
        s_result = target(0, nullptr);
    }

    void drain_caller() noexcept
    {
        call_target();
        s_caller_returned.store(true, std::memory_order_release);
        park_worker_until_reclaim();
    }

    void WINAPI fiber_body(void *)
    {
        call_target();
        SwitchToFiber(s_driver);
    }

    // The clean-release seam runs after the restore. The released caller holds a counted bypass entry on return.
    void release_parked_caller() noexcept
    {
        safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
        wait_until([]() noexcept -> bool { return s_in_callee.load(); });
    }

    void release_callee_later() noexcept
    {
        wait_until([]() noexcept -> bool { return s_in_callee.load(); });
        Sleep(50);
        s_callee_release.store(true);
        park_worker_until_reclaim();
    }

    bool is_mapped(const void *address) noexcept
    {
        MEMORY_BASIC_INFORMATION region{};
        return VirtualQuery(address, &region, sizeof(region)) == sizeof(region) && region.State == MEM_COMMIT;
    }

    int run(Scenario scenario)
    {
        using namespace DetourModKit::detail;
        const bool drain = scenario == Scenario::Drain || scenario == Scenario::ThreadExit;
        s_exit_during_scan.store(scenario == Scenario::ThreadExit, std::memory_order_release);
        const int cycles = scenario == Scenario::Clean ? 10 : 1;
        for (int i = 0; i < cycles; ++i)
        {
            const HMODULE provider = LoadLibraryW(L"dmk_routed_bypass_provider.dll");
            auto *const page = reinterpret_cast<std::uint8_t *>(GetProcAddress(provider, "XInputGetState"));
            DWORD previous = 0;
            if (provider == nullptr || page == nullptr ||
                !VirtualProtect(page, 4096, PAGE_EXECUTE_READWRITE, &previous))
            {
                std::fprintf(stderr, "FAIL: provider load or page protection failed: error=%lu\n", GetLastError());
                return 2;
            }
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
            if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)))
            {
                std::fprintf(stderr, "FAIL: CFG policy query failed: error=%lu\n", GetLastError());
                return 2;
            }
            if (cfg.EnableControlFlowGuard)
            {
                // A generated entry in an image data page needs an explicit CFG target.
                CFG_CALL_TARGET_INFO target_info{
                    .Offset = 0,
                    .Flags = CFG_CALL_TARGET_VALID,
                };
                if (!SetProcessValidCallTargets(GetCurrentProcess(), page, 4096, 1, &target_info))
                {
                    std::fprintf(stderr, "FAIL: CFG target registration failed: error=%lu\n", GetLastError());
                    return 2;
                }
            }
            // The displaced call returns through generated code into a separately unloadable provider.
            constexpr std::uint8_t code[] = {
                0x48,
                0x83,
                0xEC,
                0x28,
                0xFF,
                0x15,
                0x06,
                0x00,
                0x00,
                0x00,
                0x48,
                0x83,
                0xC4,
                0x28,
                0xC3,
                0xCC,
            };
            std::memcpy(page, code, sizeof(code));
            const auto callee = &provider_callee;
            std::memcpy(page + sizeof(code), &callee, sizeof(callee));
            if (!FlushInstructionCache(GetCurrentProcess(), page, 4096))
            {
                std::fprintf(stderr, "FAIL: provider instruction cache flush failed: error=%lu\n", GetLastError());
                return 3;
            }
            s_target = reinterpret_cast<TargetFn>(page);
            const TargetFn volatile target = s_target;
            if (target(0, nullptr) != EXPECTED_VALUE)
            {
                std::fputs("FAIL: the original provider returned an unexpected value\n", stderr);
                return 4;
            }
            set_xinput_module_override_for_test(provider);
            const auto before = safetyhook::route_retention_stats();
            if (!install_xinput(0) || target(0, nullptr) != EXPECTED_VALUE)
            {
                std::fputs("FAIL: the routed provider install or call failed\n", stderr);
                return 5;
            }
            const auto trampoline = reinterpret_cast<const void *>(xinput_trampoline());
            if (scenario != Scenario::Fiber)
            {
                std::thread caller;
                std::thread releaser;
                std::unique_ptr<void, decltype(&CloseHandle)> caller_thread{nullptr, &CloseHandle};
                if (drain)
                {
                    s_hold_callee.store(true);
                    safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::AT_ENTRY);
                    caller = std::thread{&drain_caller};
                    wait_until([]() noexcept -> bool { return safetyhook::route_park_reached_for_test(); });
                    caller_thread.reset(
                        OpenThread(SYNCHRONIZE, FALSE, s_caller_thread_id.load(std::memory_order_acquire))
                    );
                    s_caller_thread = caller_thread.get();
                    if (s_caller_thread == nullptr)
                    {
                        std::fputs("FAIL: the proof could not open its caller thread\n", stderr);
                        ExitProcess(11);
                    }
                    releaser = std::thread{&release_callee_later};
                    set_xinput_clean_release_seam(&release_parked_caller);
                }
                uninstall();
                set_xinput_clean_release_seam(nullptr);
                if (drain)
                    wait_until([]() noexcept -> bool { return s_caller_returned.load(std::memory_order_acquire); });
                const bool provider_released = FreeLibrary(provider) != FALSE;
                const auto after = safetyhook::route_retention_stats();
                const bool provider_mapped = is_mapped(page);
                const bool trampoline_mapped = is_mapped(trampoline);
                const bool native_caller_live = !drain || WaitForSingleObject(s_caller_thread, 0) == WAIT_TIMEOUT;
                const bool expected_retention = scenario == Scenario::ThreadExit;
                const bool reclaimed = after.logical_charged == before.logical_charged &&
                                       after.committed_charged == before.committed_charged;
                const bool retained = after.logical_charged > before.logical_charged &&
                                      after.committed_charged > before.committed_charged;
                const bool valid =
                    provider_released && xinput_module_refs_held() == 0 && (!drain || s_result == EXPECTED_VALUE) &&
                    (expected_retention ? provider_mapped && trampoline_mapped && retained &&
                                              s_suspend_refused.load() && !native_caller_live
                                        : !provider_mapped && !trampoline_mapped && reclaimed && native_caller_live);
                if (drain)
                {
                    s_workers_may_exit.store(true, std::memory_order_release);
                    caller.join();
                    releaser.join();
                    s_caller_thread = nullptr;
                }
                if (!valid)
                {
                    std::fprintf(
                        stderr,
                        "FAIL: bypass reclaim verdict: provider=%d trampoline=%d native_caller_live=%d "
                        "logical=%llu committed=%llu refs=%zu result=%lu expected_retention=%d\n",
                        provider_mapped,
                        trampoline_mapped,
                        native_caller_live,
                        static_cast<unsigned long long>(after.logical_charged - before.logical_charged),
                        static_cast<unsigned long long>(after.committed_charged - before.committed_charged),
                        static_cast<std::size_t>(xinput_module_refs_held()),
                        s_result,
                        expected_retention
                    );
                    return 6;
                }
                continue;
            }
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::AT_ENTRY);
            std::thread caller{
                []() -> void
                {
                    s_driver = ConvertThreadToFiber(nullptr);
                    void *const child = CreateFiber(0, &fiber_body, nullptr);
                    if (s_driver == nullptr || child == nullptr)
                        ExitProcess(7);
                    SwitchToFiber(child);
                    s_dormant.store(true);
                    wait_until([]() noexcept -> bool { return s_resume.load(); });
                    SwitchToFiber(child);
                    DeleteFiber(child);
                    ConvertFiberToThread();
                    s_driver = nullptr;
                }
            };
            wait_until([]() noexcept -> bool { return safetyhook::route_park_reached_for_test(); });
            safetyhook::g_route_scan_reached.store(false);
            safetyhook::g_route_scan_hold.store(true);
            std::thread teardown{[]() -> void { uninstall(); }};
            wait_until([]() noexcept -> bool { return safetyhook::g_route_scan_reached.load(); });
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
            wait_until([]() noexcept -> bool { return s_dormant.load(); });
            safetyhook::g_route_scan_hold.store(false);
            teardown.join();
            FreeLibrary(provider);
            if (!is_mapped(page) || !is_mapped(trampoline))
            {
                std::fputs("FAIL: dormant bypass lost its route or provider reference\n", stderr);
                ExitProcess(1);
            }
            s_resume.store(true);
            caller.join();
            if (s_result != EXPECTED_VALUE)
                return 8;
        }
        return 0;
    }
} // namespace

extern "C"
{
    // The control delays suspension until native exit, then calls the real Win32 API.
    decltype(&SuspendThread) __imp_SuspendThread = &suspend_thread;
} // extern "C"

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    const std::string_view scenario{argv[1]};
    if (scenario == "fiber")
        return run(Scenario::Fiber);
    if (scenario == "clean")
        return run(Scenario::Clean);
    if (scenario == "drain")
        return run(Scenario::Drain);
    if (scenario == "thread-exit")
        return run(Scenario::ThreadExit);
    return 2;
}
