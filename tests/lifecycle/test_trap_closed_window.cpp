/**
 * @file test_trap_closed_window.cpp
 * @brief Proves the backend rescues an execute fault whose protection window closed before the fault was dispatched.
 * @details A thread can fault inside a hook's protection window and not reach the backend's vectored handler before
 *          `trap_threads` restores the page and removes the trap. The lookup then finds nothing. Before the fix that
 *          fault escaped as an unhandled access violation and killed the host, which is what the MSVC Release
 *          mid-teardown soak was hitting at roughly one run in four hundred.
 *
 *          The race itself is probabilistic, so this proof does not race. It builds the exact state the handler must
 *          survive: a real execute fault on a page that is executable and committed by the time any handler looks.
 *          A local vectored handler registered ahead of the backend's restores the page and passes the fault on,
 *          which is precisely the ordering the crash produced. The oracle is the process exit status, because the
 *          regression's failure mode is an unhandled exception rather than a false assertion.
 */

#include "DetourModKit/hook.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>
#include <thread>

#include <windows.h>

namespace DetourModKit::detail
{
    void set_backend_trap_transaction_hold_for_test(bool hold) noexcept;
    [[nodiscard]] bool backend_trap_transaction_reached_for_test() noexcept;
    [[nodiscard]] std::size_t backend_trap_protect_calls_for_test() noexcept;
    void retire_backend_trap_runtime_for_test() noexcept;
} // namespace DetourModKit::detail

namespace
{
    constexpr int SETUP_FAILURE = 2;
    constexpr int NOT_RESCUED = 3;

    /// The page the synthetic fault is taken on. Only faults inside it are touched, so no unrelated fault is altered.
    std::uint8_t *g_page = nullptr;
    LONG g_faults_seen = 0;

    /// A hook target with a body large enough for any backend patch length.
    __declspec(noinline) int hook_target(int value) noexcept
    {
        volatile int accumulated = value;
        for (int i = 0; i < 4; ++i)
        {
            accumulated += i;
        }
        return accumulated;
    }

    void mid_detour(DetourModKit::hook::MidContext &) noexcept {}

    /**
     * @brief Turns a live execute fault into a closed-window one, then hands it to the backend.
     * @details `AddVectoredExceptionHandler` with a nonzero first argument inserts at the HEAD of the chain, so this
     *          handler, added after the backend's, is the one that runs first. Making the page executable here is
     *          what the patching thread does in the real race between the fault and its dispatch.
     */
    LONG CALLBACK restore_then_forward(PEXCEPTION_POINTERS exception) noexcept
    {
        const EXCEPTION_RECORD &record = *exception->ExceptionRecord;
        if (record.ExceptionCode != EXCEPTION_ACCESS_VIOLATION || record.NumberParameters < 2 ||
            record.ExceptionInformation[0] != 8)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        auto *const address = reinterpret_cast<std::uint8_t *>(record.ExceptionInformation[1]);
        if (g_page == nullptr || address < g_page || address >= g_page + 0x1000)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        ::InterlockedIncrement(&g_faults_seen);
        DWORD previous = 0;
        (void)::VirtualProtect(g_page, 0x1000, PAGE_EXECUTE_READ, &previous);
        // Passing this on is the point: the backend's handler must be the one that decides to retry.
        return EXCEPTION_CONTINUE_SEARCH;
    }
} // namespace

namespace
{
    int run_closed_window()
    {

        // The backend registers its trap handler lazily, on the first hook that opens a protection window. Without a
        // live hook there is no handler to prove anything about.
        auto created = DetourModKit::hook::mid_at(
            DetourModKit::hook::MidRequest{
                .name = "trap-closed-window",
                .target = DetourModKit::Address{&hook_target},
            },
            &mid_detour);
        if (!created)
        {
            std::fprintf(stderr, "SETUP: mid_at failed\n");
            return SETUP_FAILURE;
        }
        if (auto enabled = created->enable(); !enabled)
        {
            std::fprintf(stderr, "SETUP: enable failed\n");
            return SETUP_FAILURE;
        }
        (void)hook_target(1);

        g_page = static_cast<std::uint8_t *>(
            ::VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (g_page == nullptr)
        {
            std::fprintf(stderr, "SETUP: VirtualAlloc failed (error %lu)\n", ::GetLastError());
            return SETUP_FAILURE;
        }
        g_page[0] = 0xC3; // ret

        PVOID const handler = ::AddVectoredExceptionHandler(1, &restore_then_forward);
        if (handler == nullptr)
        {
            std::fprintf(stderr, "SETUP: AddVectoredExceptionHandler failed\n");
            return SETUP_FAILURE;
        }

        // Drop execute so the call below takes a real DEP fault rather than a synthesized exception record.
        DWORD previous = 0;
        if (::VirtualProtect(g_page, 0x1000, PAGE_READWRITE, &previous) == FALSE)
        {
            std::fprintf(stderr, "SETUP: VirtualProtect failed (error %lu)\n", ::GetLastError());
            return SETUP_FAILURE;
        }

        // Against a backend that gives up on a fault it has no trap for, this call never returns: the fault reaches no
        // handler that continues execution and the process dies with 0xC0000005.
        reinterpret_cast<void (*)()>(g_page)();

        ::RemoveVectoredExceptionHandler(handler);

        if (g_faults_seen == 0)
        {
            std::fprintf(stderr, "FAIL[trap-closed-window]: no execute fault was taken; the proof asserted nothing\n");
            return NOT_RESCUED;
        }

        std::printf("PASS[trap-closed-window]: the backend retried a closed-window execute fault (%ld seen)\n",
                    g_faults_seen);
        std::fflush(stdout);
        return 0;
    }

    int run_late_static()
    {
        auto created = DetourModKit::hook::mid_at(
            DetourModKit::hook::MidRequest{
                .name = "trap-late-static",
                .target = DetourModKit::Address{&hook_target},
            },
            &mid_detour);
        if (!created || !created->enable() || !created->disable())
        {
            std::fputs("SETUP: could not initialize the backend trap runtime\n", stderr);
            return SETUP_FAILURE;
        }

        DetourModKit::detail::set_backend_trap_transaction_hold_for_test(true);
        std::atomic<bool> enable_succeeded{false};
        // enable() can throw: trap_threads rethrows whatever its mutation callback raised. An exception escaping a
        // std::thread callable terminates the process, which would report as a crash rather than as this proof's own
        // failure, so contain it and let the enable_succeeded check below own the verdict.
        std::thread transaction(
            [&]
            {
                try
                {
                    enable_succeeded.store(created->enable().has_value(), std::memory_order_release);
                }
                catch (...)
                {
                    enable_succeeded.store(false, std::memory_order_release);
                }
            });

        const ULONGLONG deadline = ::GetTickCount64() + 5000;
        while (!DetourModKit::detail::backend_trap_transaction_reached_for_test() && ::GetTickCount64() < deadline)
        {
            std::this_thread::yield();
        }
        if (!DetourModKit::detail::backend_trap_transaction_reached_for_test())
        {
            DetourModKit::detail::set_backend_trap_transaction_hold_for_test(false);
            transaction.join();
            std::fputs("FAIL[trap-late-static]: transaction never reached its pre-protection park\n", stderr);
            return 4;
        }

        std::atomic<bool> retirement_returned{false};
        std::thread retirement(
            [&]
            {
                DetourModKit::detail::retire_backend_trap_runtime_for_test();
                retirement_returned.store(true, std::memory_order_release);
            });

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        if (retirement_returned.load(std::memory_order_acquire))
        {
            DetourModKit::detail::set_backend_trap_transaction_hold_for_test(false);
            transaction.join();
            retirement.join();
            std::fputs("FAIL[trap-late-static]: handler retirement raced a live protection transaction\n", stderr);
            return 5;
        }

        DetourModKit::detail::set_backend_trap_transaction_hold_for_test(false);
        transaction.join();
        retirement.join();
        // retirement_returned is necessarily true after the join above, so only the transaction's own outcome is
        // still open: it had to complete under the registered gateway rather than be refused.
        if (!enable_succeeded.load(std::memory_order_acquire))
        {
            std::fputs("FAIL[trap-late-static]: the serialized transaction did not complete\n", stderr);
            return 6;
        }

        const std::size_t protects_before = DetourModKit::detail::backend_trap_protect_calls_for_test();
        if (created->disable().has_value())
        {
            std::fputs("FAIL[trap-late-static]: a transaction succeeded after handler retirement\n", stderr);
            return 7;
        }
        const std::size_t protects_after = DetourModKit::detail::backend_trap_protect_calls_for_test();
        if (protects_after != protects_before)
        {
            std::fputs("FAIL[trap-late-static]: refused transaction changed page protection\n", stderr);
            return 8;
        }

        std::fputs("PASS[trap-late-static]: retirement serialized and later mutation was refused before protection\n",
                   stdout);
        // Flush before the hook and the retired runtime tear down: a refused restore pins the backend and logs on the
        // way out, and an unflushed verdict would be lost if anything in that teardown took the process down.
        std::fflush(stdout);
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    // MSVC only, matching the other raw proofs: it suppresses the modal CRT fault box that nothing would dismiss in a
    // headless run. Deliberately not extended to MinGW, because this proof carries the lifecycle-proof label and the
    // release soak arms WER LocalDumps for it, and SEM_NOGPFAULTERRORBOX would stop WER capturing a real regression.
#if defined(_MSC_VER)
    ::SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#endif

    if (argc != 2)
    {
        std::fputs("usage: test_trap_closed_window <closed-window|late-static>\n", stderr);
        return 1;
    }
    const std::string_view mode{argv[1]};
    if (mode == "closed-window")
    {
        return run_closed_window();
    }
    if (mode == "late-static")
    {
        return run_late_static();
    }
    std::fputs("unknown trap proof mode\n", stderr);
    return 1;
}
