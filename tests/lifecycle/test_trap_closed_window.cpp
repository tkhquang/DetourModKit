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

#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <windows.h>

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

int main()
{
#if defined(_MSC_VER)
    ::SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#endif

    // The backend registers its trap handler lazily, on the first hook that opens a protection window. Without a
    // live hook there is no handler to prove anything about.
    auto created = DetourModKit::hook::mid_at(
        DetourModKit::hook::MidRequest{.name = "trap-closed-window", .target = DetourModKit::Address{&hook_target}},
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

    g_page =
        static_cast<std::uint8_t *>(::VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
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
