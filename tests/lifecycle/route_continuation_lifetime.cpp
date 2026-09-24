/**
 * @file route_continuation_lifetime.cpp
 * @brief Verifies mid-route lifetime across dormant fibers and exception continuation.
 */

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"

#include <safetyhook/inline_hook.hpp>
#include <safetyhook/os.hpp>

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string_view>
#include <thread>

namespace DetourModKit::detail
{
    extern void (*g_logger_record_probe)(LogLevel, std::string_view) noexcept;
} // namespace DetourModKit::detail

namespace
{
    using TargetFn = int (*)();
    constexpr DWORD WAIT_MS = 10000;
    constexpr int EXPECTED_VALUE = 37;

    std::atomic<std::uintptr_t> s_resume{0};
    std::atomic<unsigned> s_callbacks{0};
    void *s_driver_fiber = nullptr;
    TargetFn s_target = nullptr;
    int s_observed = 0;
    bool s_throw_from_callee = false;
    std::uintptr_t s_redirect = 0;
    unsigned s_resume_offset = 0;
    bool s_set_state = false;
    std::uintptr_t s_indirect_target = 0;
    HANDLE s_fault_entered = nullptr;
    HANDLE s_fault_release = nullptr;
    int s_readable_value = EXPECTED_VALUE;
    unsigned s_continuation_warnings = 0;
    unsigned s_retention_warnings = 0;
    std::atomic<bool> s_fiber_dormant{false};
    std::atomic<bool> s_fiber_resume{false};

    void observe_warning(DetourModKit::LogLevel level, std::string_view message) noexcept
    {
        if (level == DetourModKit::LogLevel::Warning && message.find("retained") != std::string_view::npos)
        {
            ++s_retention_warnings;
        }
        if (level == DetourModKit::LogLevel::Warning &&
            message.find("unresolved continuation or nonlocal exit") != std::string_view::npos)
        {
            ++s_continuation_warnings;
        }
    }

    struct PageDeleter
    {
        void operator()(std::uint8_t *page) const noexcept
        {
            if (page != nullptr)
            {
                if (page[64] == 1)
                {
                    RtlDeleteFunctionTable(reinterpret_cast<RUNTIME_FUNCTION *>(page + 80));
                }
                VirtualFree(page, 0, MEM_RELEASE);
            }
        }
    };

    using Page = std::unique_ptr<std::uint8_t, PageDeleter>;

    int fail(const char *message) noexcept
    {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return 1;
    }

    void callback(DetourModKit::hook::MidContext &context) noexcept
    {
        s_resume.store(DetourModKit::hook::instruction_pointer(context));
        s_callbacks.fetch_add(1);
        if (s_set_state)
        {
            DetourModKit::hook::gpr(context, DetourModKit::hook::Gpr::Rax) = EXPECTED_VALUE;
            DetourModKit::hook::flags(context) |= 1;
        }
        if (s_indirect_target != 0)
        {
            DetourModKit::hook::gpr(context, DetourModKit::hook::Gpr::Rax) = s_indirect_target;
        }
        if (s_redirect != 0)
        {
            DetourModKit::hook::instruction_pointer(context) = s_redirect;
        }
        else if (s_resume_offset != 0)
        {
            DetourModKit::hook::instruction_pointer(context) += s_resume_offset;
        }
    }

    int yield_from_callee()
    {
        if (s_throw_from_callee)
        {
            throw EXPECTED_VALUE;
        }
        if (s_driver_fiber != nullptr)
        {
            SwitchToFiber(s_driver_fiber);
        }
        return EXPECTED_VALUE;
    }

    Page make_target(bool fault, bool tail_call)
    {
        Page page{
            static_cast<std::uint8_t *>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
        };
        if (!page)
        {
            return page;
        }
        if (fault)
        {
            // The five-byte window faults at its third byte and has no relocated call return site.
            constexpr std::uint8_t code[] = {
                0x31,
                0xC0,
                0x8B,
                0x00,
                0x90,
                0xC3,
            };
            std::memcpy(page.get(), code, sizeof(code));
        }
        else
        {
            // The call uses the Windows x64 shadow space and lies in the displaced window.
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
            std::memcpy(page.get(), code, sizeof(code));
            const auto callee = reinterpret_cast<std::uintptr_t>(&yield_from_callee);
            std::memcpy(page.get() + sizeof(code), &callee, sizeof(callee));
            if (tail_call)
            {
                // The internal call tail-jumps to the callee, which returns into the displaced window.
                constexpr std::uint8_t tail_code[] = {
                    0xEB,
                    2,
                    0xEB,
                    28,
                    0xE8,
                    0xF9,
                    0xFF,
                    0xFF,
                    0xFF,
                    0x48,
                    0x83,
                    0xC4,
                    0x28,
                    0xC3,
                };
                std::memcpy(page.get() + 4, tail_code, sizeof(tail_code));
                page.get()[36] = 0x48;
                page.get()[37] = 0xB8;
                std::memcpy(page.get() + 38, &callee, sizeof(callee));
                page.get()[46] = 0xFF;
                page.get()[47] = 0xE0;
            }
            constexpr std::uint8_t unwind[] = {
                1,
                4,
                1,
                0,
                4,
                0x42,
                0,
                0,
            };
            std::memcpy(page.get() + 64, unwind, sizeof(unwind));
            auto *const function = std::construct_at(
                reinterpret_cast<RUNTIME_FUNCTION *>(page.get() + 80),
                RUNTIME_FUNCTION{
                    .BeginAddress = 0,
                    .EndAddress = tail_call ? 18u : 15u,
                    .UnwindData = 64,
                }
            );
            if (RtlAddFunctionTable(function, 1, reinterpret_cast<DWORD64>(page.get())) == FALSE)
            {
                page.reset();
                return page;
            }
        }
        if (FlushInstructionCache(GetCurrentProcess(), page.get(), 4096) == FALSE)
        {
            page.reset();
        }
        return page;
    }

    bool install(std::uint8_t *target, DetourModKit::hook::HookStack &stack)
    {
        auto created = DetourModKit::hook::mid_at(
            {
                .name = "continuation lifetime",
                .target = DetourModKit::Address{reinterpret_cast<std::uintptr_t>(target)},
            },
            &callback
        );
        if (!created)
        {
            return false;
        }
        return stack.push(std::move(*created)).enable().has_value();
    }

    bool route_is_mapped() noexcept
    {
        MEMORY_BASIC_INFORMATION region{};
        return VirtualQuery(reinterpret_cast<void *>(s_resume.load()), &region, sizeof(region)) == sizeof(region) &&
               region.State == MEM_COMMIT;
    }

    void WINAPI fiber_body(void *)
    {
        const TargetFn volatile indirect = s_target;
        s_observed = indirect();
        SwitchToFiber(s_driver_fiber);
    }

    LONG CALLBACK fault_handler(EXCEPTION_POINTERS *exception) noexcept
    {
        const auto resume = s_resume.load();
        if (exception->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
            exception->ContextRecord->Rip != resume + 2 || exception->ExceptionRecord->NumberParameters < 2 ||
            exception->ExceptionRecord->ExceptionInformation[0] != 0 ||
            exception->ExceptionRecord->ExceptionInformation[1] != 0)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        SetEvent(s_fault_entered);
        if (WaitForSingleObject(s_fault_release, WAIT_MS) != WAIT_OBJECT_0)
        {
            ExitProcess(3);
        }
        exception->ContextRecord->Rax = reinterpret_cast<DWORD64>(&s_readable_value);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    int run(std::string_view scenario)
    {
        const bool unwind = scenario == "unwind";
        s_throw_from_callee = unwind;
        const bool fault = scenario == "exception";
        const bool benchmark = scenario == "benchmark";
        const bool idle = scenario == "idle" || benchmark;

        const bool tail_call = scenario == "tail-fiber";
        Page page = make_target(fault, tail_call);
        if (!page)
        {
            return fail("target allocation failed");
        }
        DetourModKit::hook::HookStack stack;
        if (!install(page.get() + (tail_call ? 4 : 0), stack))
        {
            return fail("mid hook creation failed");
        }

        s_target = reinterpret_cast<TargetFn>(page.get());
        const auto leaks_before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        const auto previous_probe = DetourModKit::detail::g_logger_record_probe;
        DetourModKit::detail::g_logger_record_probe = &observe_warning;
        if (idle)
        {
            const TargetFn volatile indirect = s_target;
            if (benchmark)
            {
                for (int repetition = 0; repetition < 5; ++repetition)
                {
                    const auto start = std::chrono::steady_clock::now();
                    for (int i = 0; i < 100000; ++i)
                    {
                        s_observed = indirect();
                    }
                    const auto elapsed = std::chrono::steady_clock::now() - start;
                    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
                    std::fprintf(stderr, "mid route repetition %d: %.2f ns/call\n", repetition, nanoseconds / 100000.0);
                }
            }
            else
            {
                s_observed = indirect();
            }
            stack.clear();
        }
        else if (unwind)
        {
            try
            {
                const TargetFn volatile indirect = s_target;
                s_observed = indirect();
                return fail("the relocated call did not throw");
            }
            catch (int value)
            {
                s_observed = value;
            }
            stack.clear();
        }
        else if (fault)
        {

            s_fault_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            s_fault_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            void *const handler = AddVectoredExceptionHandler(1, &fault_handler);
            if (s_fault_entered == nullptr || s_fault_release == nullptr || handler == nullptr)
            {
                return fail("exception fixture setup failed");
            }
            std::thread caller{
                []() -> void
                {
                    const TargetFn volatile indirect = s_target;
                    s_observed = indirect();
                }
            };
            if (WaitForSingleObject(s_fault_entered, WAIT_MS) != WAIT_OBJECT_0)
            {
                ExitProcess(4);
            }

            stack.clear();
            std::fprintf(stderr, "exception route mapped after teardown: %d\n", route_is_mapped());
            SetEvent(s_fault_release);
            caller.join();
            RemoveVectoredExceptionHandler(handler);
            CloseHandle(s_fault_release);
            CloseHandle(s_fault_entered);
        }
        else
        {

            s_driver_fiber = ConvertThreadToFiber(nullptr);

            void *const fiber = CreateFiber(0, &fiber_body, nullptr);
            if (s_driver_fiber == nullptr || fiber == nullptr)
            {
                return fail("fiber fixture setup failed");
            }

            SwitchToFiber(fiber);

            stack.clear();
            std::fprintf(stderr, "dormant fiber route mapped after teardown: %d\n", route_is_mapped());
            SwitchToFiber(fiber);
            DeleteFiber(fiber);
            ConvertFiberToThread();
            s_driver_fiber = nullptr;
        }
        const auto leaks_after =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        DetourModKit::detail::g_logger_record_probe = previous_probe;
        if (s_observed != EXPECTED_VALUE || s_callbacks.load() != (benchmark ? 500000u : 1u))
        {
            return fail("the continuation did not return through the exercised route");
        }
        if (route_is_mapped() == idle || leaks_after - leaks_before != (idle ? 0u : 1u) ||
            s_continuation_warnings != (idle ? 0u : 1u))
        {
            return fail("route memory or retention attribution differs from the lifetime contract");
        }
        std::fprintf(stderr, "OK: %.*s\n", static_cast<int>(scenario.size()), scenario.data());
        return 0;
    }

    int run_scan_race()
    {
        Page page = make_target(false, false);
        DetourModKit::hook::HookStack stack;
        if (!page || !install(page.get(), stack))
        {
            return fail("scan race fixture setup failed");
        }
        s_target = reinterpret_cast<TargetFn>(page.get());
        const TargetFn volatile target = s_target;
        if (target() != EXPECTED_VALUE)
        {
            return fail("scan race control call failed");
        }
        const auto before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        DetourModKit::detail::g_logger_record_probe = &observe_warning;
        safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::AT_ENTRY);
        std::thread caller{
            []() -> void
            {
                s_driver_fiber = ConvertThreadToFiber(nullptr);
                void *const fiber = CreateFiber(0, &fiber_body, nullptr);
                if (s_driver_fiber == nullptr || fiber == nullptr)
                {
                    ExitProcess(3);
                }
                SwitchToFiber(fiber);
                s_fiber_dormant.store(true);
                const auto deadline = GetTickCount64() + WAIT_MS;
                while (!s_fiber_resume.load())
                {
                    if (GetTickCount64() >= deadline)
                    {
                        ExitProcess(4);
                    }
                    Sleep(1);
                }
                SwitchToFiber(fiber);
                DeleteFiber(fiber);
                ConvertFiberToThread();
                s_driver_fiber = nullptr;
            }
        };
        const auto deadline = GetTickCount64() + WAIT_MS;
        while (!safetyhook::route_park_reached_for_test())
        {
            if (GetTickCount64() >= deadline)
            {
                ExitProcess(5);
            }
            Sleep(1);
        }
        safetyhook::g_route_scan_reached.store(false);
        safetyhook::g_route_scan_hold.store(true);
        std::thread teardown{[&stack]() -> void { stack.clear(); }};
        while (!safetyhook::g_route_scan_reached.load())
        {
            if (GetTickCount64() >= deadline)
            {
                ExitProcess(6);
            }
            Sleep(1);
        }
        safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
        while (!s_fiber_dormant.load())
        {
            if (GetTickCount64() >= deadline)
            {
                ExitProcess(7);
            }
            Sleep(1);
        }
        safetyhook::g_route_scan_hold.store(false);
        teardown.join();
        if (!route_is_mapped())
        {
            std::fputs("FAIL: idle scan freed a dormant bypass continuation\n", stderr);
            ExitProcess(8);
        }
        s_fiber_resume.store(true);
        caller.join();
        DetourModKit::detail::g_logger_record_probe = nullptr;
        if (s_observed != EXPECTED_VALUE || s_callbacks.load() != 1 || s_retention_warnings != 1 ||
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager) !=
                before + 1)
        {
            return fail("scan race lost its bypass result or retention attribution");
        }
        return 0;
    }

    int run_exit(std::string_view scenario)
    {
        Page page{
            static_cast<std::uint8_t *>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
        };
        if (!page)
        {
            return fail("exit fixture allocation failed");
        }
        std::memset(page.get(), 0x90, 64);
        const std::uint8_t leaf[] = {
            0xB8,
            37,
            0,
            0,
            0,
            0xC3,
        };
        std::memcpy(page.get() + 32, leaf, sizeof(leaf));
        std::memcpy(page.get() + 5, leaf, sizeof(leaf));
        if (scenario == "return")
        {
            const std::uint8_t code[] = {
                0x6A,
                37,
                0x58,
                0xC3,
            };
            std::memcpy(page.get(), code, sizeof(code));
        }
        else if (scenario == "branch")
        {
            page.get()[0] = 0xEB;
            page.get()[1] = 30;
        }
        else if (scenario == "conditional")
        {
            const std::uint8_t code[] = {
                0x31,
                0xC0,
                0x74,
                28,
            };
            std::memcpy(page.get(), code, sizeof(code));
        }
        else if (scenario == "indirect")
        {
            const std::uint8_t code[] = {
                0xFF,
                0x25,
                10,
                0,
                0,
                0,
            };
            std::memcpy(page.get(), code, sizeof(code));
            const auto destination = page.get() + 32;
            std::memcpy(page.get() + 16, &destination, sizeof(destination));
        }
        else if (scenario == "internal")
        {
            page.get()[0] = 0xEB;
            page.get()[1] = 0;
        }
        else if (scenario == "internal-return" || scenario == "internal-return-pop")
        {
            if (scenario == "internal-return")
            {
                const std::uint8_t code[] = {
                    0xEB,
                    1,
                    0xC3,
                    0xE8,
                    0xFA,
                    0xFF,
                    0xFF,
                    0xFF,
                };
                std::memcpy(page.get(), code, sizeof(code));
                std::memcpy(page.get() + sizeof(code), leaf, sizeof(leaf));
            }
            else
            {
                s_resume_offset = 5;
                const std::uint8_t code[] = {
                    0xC2,
                    0,
                    0,
                    0xE8,
                    0xF8,
                    0xFF,
                    0xFF,
                    0xFF,
                };
                std::memcpy(page.get(), code, sizeof(code));
                std::memcpy(page.get() + sizeof(code), leaf, sizeof(leaf));
            }
        }
        else if (scenario == "internal-tail-branch" || scenario == "internal-tail-conditional" ||
                 scenario == "internal-tail-indirect")
        {
            const std::uint8_t code[] = {
                0xEB,
                2,
                0xEB,
                28,
                0xE8,
                0xF9,
                0xFF,
                0xFF,
                0xFF,
            };
            std::memcpy(page.get(), code, sizeof(code));
            std::memcpy(page.get() + sizeof(code), leaf, sizeof(leaf));
            if (scenario == "internal-tail-conditional")
            {
                page.get()[2] = 0x72;
                s_set_state = true;
            }
            else if (scenario == "internal-tail-indirect")
            {
                page.get()[2] = 0xFF;
                page.get()[3] = 0xE0;
                s_indirect_target = reinterpret_cast<std::uintptr_t>(page.get() + 32);
            }
        }
        else if (scenario == "redirect")
        {
            s_redirect = reinterpret_cast<std::uintptr_t>(page.get() + 32);
        }
        else if (scenario == "resume" || scenario == "resume-end")
        {
            s_resume_offset = scenario == "resume" ? 2 : 5;
        }
        else if (scenario == "ff")
        {
            std::memset(page.get(), 0x90, 14);
            std::memcpy(page.get() + 14, leaf, sizeof(leaf));
            safetyhook::force_ff_hook_for_test(true);
        }
        else if (scenario == "state")
        {
            s_set_state = true;
            const std::uint8_t code[] = {
                0x8D,
                0x40,
                1,
                0x83,
                0xD0,
                0,
                0xC3,
            };
            std::memcpy(page.get() + 5, code, sizeof(code));
        }
        if (FlushInstructionCache(GetCurrentProcess(), page.get(), 64) == FALSE)
        {
            return fail("exit fixture cache flush failed");
        }
        const auto before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        DetourModKit::hook::HookStack stack;
        if (!install(page.get(), stack))
        {
            return fail("exit fixture hook creation failed");
        }
        const TargetFn volatile target = reinterpret_cast<TargetFn>(page.get());
        const int observed = target();
        int bypass_observed = 0;
        if (scenario == "bypass")
        {
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::AT_ENTRY);
            std::thread caller{[target, &bypass_observed]() -> void { bypass_observed = target(); }};
            const auto deadline = GetTickCount64() + WAIT_MS;
            while (!safetyhook::route_park_reached_for_test() && GetTickCount64() < deadline)
            {
                std::this_thread::yield();
            }
            if (!safetyhook::route_park_reached_for_test())
            {
                ExitProcess(5);
            }
            stack.clear();
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
            caller.join();
        }
        if (scenario == "metadata")
        {
            const auto *const epilogue = reinterpret_cast<const std::uint8_t *>(s_resume.load()) + 5;
            std::int32_t displacement = 0;
            std::memcpy(&displacement, epilogue + 1, sizeof(displacement));
            const auto *const exit = epilogue + 5 + displacement;
            if (*epilogue != 0xE9)
            {
                return fail("metadata fixture did not use the near continuation exit");
            }
            for (const unsigned offset : {0u, 1u, 2u, 7u, 14u, 16u, 23u, 25u, 32u, 33u, 34u})
            {
                constexpr DWORD64 saved_rbx = 0x1234;
                const auto caller = reinterpret_cast<DWORD64>(&run_exit);
                DWORD64 frame[] = {0x203, saved_rbx, caller};
                CONTEXT context{};
                context.Rip = reinterpret_cast<DWORD64>(exit + offset);
                context.Rsp = reinterpret_cast<DWORD64>(
                    frame + (offset == 0 || offset == 34   ? 2
                             : offset == 1 || offset == 33 ? 1
                                                           : 0)
                );
                context.Rbx = offset <= 2 || offset == 34 ? saved_rbx : 0x4321;
                DWORD64 image_base = 0;
                auto *const function = RtlLookupFunctionEntry(context.Rip, &image_base, nullptr);
                if (function == nullptr)
                {
                    return fail("continuation exit lacks registered unwind metadata");
                }
                void *handler_data = nullptr;
                DWORD64 establisher = 0;
                RtlVirtualUnwind(
                    UNW_FLAG_NHANDLER,
                    image_base,
                    context.Rip,
                    function,
                    &context,
                    &handler_data,
                    &establisher,
                    nullptr
                );
                if (context.Rip != caller || context.Rsp != reinterpret_cast<DWORD64>(frame + 3) ||
                    context.Rbx != saved_rbx)
                {
                    return fail("continuation unwind lost the caller frame or nonvolatile register");
                }
            }
        }
        stack.clear();
        const int expected = scenario == "state" ? EXPECTED_VALUE + 2 : EXPECTED_VALUE;
        const bool retained = scenario == "bypass";
        if (observed != expected || s_callbacks.load() != 1 || route_is_mapped() != retained ||
            (retained && bypass_observed != EXPECTED_VALUE) ||
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager) !=
                before + (retained ? 1u : 0u))
        {
            return fail("ordinary exit did not balance ownership and reclaim its route");
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc != 2)
    {
        return 2;
    }
    const std::string_view scenario{argv[1]};
    if (scenario == "scan-race")
    {
        return run_scan_race();
    }
    if (scenario == "return" || scenario == "branch" || scenario == "conditional" || scenario == "indirect" ||
        scenario == "internal" || scenario == "redirect" || scenario == "resume" || scenario == "ff" ||
        scenario == "state" || scenario == "metadata" || scenario == "resume-end" || scenario == "bypass" ||
        scenario == "internal-return" || scenario == "internal-return-pop" || scenario == "internal-tail-branch" ||
        scenario == "internal-tail-conditional" || scenario == "internal-tail-indirect")
    {
        return run_exit(scenario);
    }
    if (scenario != "fiber" && scenario != "exception" && scenario != "idle" && scenario != "benchmark" &&
        scenario != "unwind" && scenario != "tail-fiber")
    {
        return 2;
    }
    return run(scenario);
}
