// Fresh-process proofs for the lifecycle reaper accessor. The OOM arms require a first-use allocation failure to latch
// a refused reaper, so every retirement takes its retain-and-detach path for the process without termination. The
// success arm requires a live reaper that joins the worker off-thread and releases its module reference. Exit status
// is the oracle.
//
// The oom arm refuses the reaper's own storage. The constructor arm grants that storage and refuses the constructor's
// first allocation. The MSVC STL performs that allocation for an empty std::list member, and libstdc++ for the parcel
// reserve.

#include "DetourModKit/diagnostics.hpp"

#include "internal/lifecycle_reaper.hpp"
#include "platform.hpp"

#include "first_use_oom_poison.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string_view>
#include <thread>

namespace
{
    constexpr std::string_view OOM_CASE{"oom"};
    constexpr std::string_view CONSTRUCTOR_OOM_CASE{"constructor-oom"};
    constexpr std::string_view SUCCESS_CASE{"success"};

    int fail(const char *what)
    {
        std::fprintf(stderr, "FAIL: %s\n", what);
        return 2;
    }

    struct Worker
    {
        std::atomic<bool> release{false};
        std::atomic<bool> exited{false};

        [[nodiscard]] std::unique_ptr<std::jthread> start()
        {
            return std::make_unique<std::jthread>(
                [this]
                {
                    while (!release.load(std::memory_order_acquire))
                    {
                        std::this_thread::yield();
                    }
                    exited.store(true, std::memory_order_release);
                }
            );
        }

        void run_down() noexcept
        {
            release.store(true, std::memory_order_release);
            while (!exited.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }
    };

    [[nodiscard]] bool wait_for_pin_count(DetourModKit::diagnostics::ModulePinReason reason, std::size_t expected)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (DetourModKit::diagnostics::module_pin_count(reason) != expected)
        {
            if (std::chrono::steady_clock::now() > deadline)
            {
                return false;
            }
            std::this_thread::yield();
        }
        return true;
    }

    int run_oom_case(long long allow)
    {
        using DetourModKit::diagnostics::LeakSubsystem;
        const std::size_t leaks_before = DetourModKit::diagnostics::intentional_leak_count(LeakSubsystem::Worker);

        Worker first;
        std::unique_ptr<std::jthread> first_thread = first.start();
        dmk_first_use::arm(allow);
        DetourModKit::detail::reap_worker_thread(
            std::move(first_thread),
            nullptr,
            DetourModKit::diagnostics::ModulePinReason::Worker
        );
        dmk_first_use::disarm();
        first.run_down();

        if (DetourModKit::diagnostics::lifecycle_counters().reaper_started != 0)
        {
            return fail("the reaper started although its first-use allocation was refused");
        }
        if (DetourModKit::diagnostics::intentional_leak_count(LeakSubsystem::Worker) != leaks_before + 1)
        {
            return fail("the refused reaper did not record the detached worker");
        }

        // The refusal latches: a retirement after the poisoned window still detaches.
        Worker second;
        DetourModKit::detail::reap_worker_thread(
            second.start(),
            nullptr,
            DetourModKit::diagnostics::ModulePinReason::Worker
        );
        second.run_down();
        if (DetourModKit::diagnostics::lifecycle_counters().reaper_started != 0)
        {
            return fail("the refused reaper started past the poisoned window");
        }
        if (DetourModKit::diagnostics::intentional_leak_count(LeakSubsystem::Worker) != leaks_before + 2)
        {
            return fail("the latched refusal did not record the second detached worker");
        }
        return 0;
    }

    int run_success_case()
    {
        using DetourModKit::diagnostics::LeakSubsystem;
        using DetourModKit::diagnostics::ModulePinReason;
        const std::size_t leaks_before = DetourModKit::diagnostics::intentional_leak_count(LeakSubsystem::Worker);
        const std::size_t pins_before = DetourModKit::diagnostics::module_pin_count(ModulePinReason::Worker);

        // The reaper releases the reference only after its join, so the pin count observes the join.
        HMODULE const module_ref = DetourModKit::detail::acquire_module_ref(ModulePinReason::Worker);
        if (module_ref == nullptr)
        {
            return fail("acquire_module_ref for the worker");
        }
        Worker worker;
        DetourModKit::detail::reap_worker_thread(worker.start(), module_ref, ModulePinReason::Worker);
        if (DetourModKit::diagnostics::lifecycle_counters().reaper_started != 1)
        {
            return fail("first use did not start the reaper");
        }
        worker.run_down();
        if (!wait_for_pin_count(ModulePinReason::Worker, pins_before))
        {
            return fail("the reaper did not join the worker and release its module reference");
        }
        if (DetourModKit::diagnostics::intentional_leak_count(LeakSubsystem::Worker) != leaks_before)
        {
            return fail("a live reaper recorded a worker leak");
        }
        if (DetourModKit::diagnostics::lifecycle_counters().abandoned_owners != 0)
        {
            return fail("a live reaper abandoned the parcel");
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: reaper_first_use_oom <oom|constructor-oom|success>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == SUCCESS_CASE)
    {
        return run_success_case();
    }
    if (dmk_first_use::debug_stl_proxies())
    {
        // The release-STL lane proves this contract on MSVC.
        return dmk_first_use::SKIP_RETURN_CODE;
    }
    if (selected_case == OOM_CASE)
    {
        return run_oom_case(0);
    }
    if (selected_case == CONSTRUCTOR_OOM_CASE)
    {
        return run_oom_case(1);
    }

    std::fprintf(stderr, "unknown reaper first-use case\n");
    return 1;
}
