// Fresh-process proofs for two `[B-47]` storage forms. Exit status is the oracle.
//
// exit-during-shutdown: shutdown_cache parks on a second thread between its Stopping publication and its
// cleanup-thread join. The main thread suspends every other thread, as ExitProcess does, and exits through the CRT, so
// this image's static destruction meets the joinable handle. A std::thread destructor over a joinable handle
// terminates the process, so the handle must live in never-destroyed storage. ExitProcess is not the oracle: on MSVC
// it skips an EXE's static destructors, and on MinGW a terminate inside it keeps exit status 0.
//
// configure-after-static-destruction: a namespace-scope object constructed at load is destroyed after the module
// directory cache, which main constructs later. Its destructor reads the directory and reconfigures the process
// default logger onto a relative file name, which the logger resolves through that cache. The working directory is
// moved away first, so a cache that died resolves the file somewhere else.

#include "DetourModKit/address.hpp"
#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <thread>

namespace DetourModKit::detail
{
    extern void (*g_memory_cache_shutdown_window_test_hook)();
} // namespace DetourModKit::detail

namespace
{
    constexpr std::string_view EXIT_CASE{"exit-during-shutdown"};
    constexpr std::string_view CONFIGURE_CASE{"configure-after-static-destruction"};
    constexpr const wchar_t *LATE_LOG_NAME = L"never_destroyed_storage_late.log";

    int fail(const char *what)
    {
        std::fprintf(stderr, "FAIL: %s\n", what);
        return 2;
    }

    // Stops every other thread, as ExitProcess does before detach code runs. The cleanup thread then cannot wake into
    // a static destructor that freed the shard array. No exit step needs a lock that a stopped thread holds. The
    // stopper sleeps, and the cleanup thread waits or walks empty shards without an allocation.
    [[nodiscard]] bool suspend_other_threads() noexcept
    {
        const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        const DWORD self_process = ::GetCurrentProcessId();
        const DWORD self_thread = ::GetCurrentThreadId();
        bool suspended_all = true;
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        for (BOOL more = ::Thread32First(snapshot, &entry); more != FALSE; more = ::Thread32Next(snapshot, &entry))
        {
            if (entry.th32OwnerProcessID != self_process || entry.th32ThreadID == self_thread)
            {
                continue;
            }
            const HANDLE thread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
            if (thread == nullptr)
            {
                continue;
            }
            if (::SuspendThread(thread) == static_cast<DWORD>(-1))
            {
                suspended_all = false;
            }
            ::CloseHandle(thread);
        }
        ::CloseHandle(snapshot);
        return suspended_all;
    }

    std::atomic<bool> s_in_shutdown_window{false};

    void park_in_shutdown_window()
    {
        s_in_shutdown_window.store(true, std::memory_order_release);
        for (;;)
        {
            std::this_thread::sleep_for(std::chrono::seconds{1});
        }
    }

    int run_exit_case()
    {
        if (!DetourModKit::memory::init_cache(32, 5000))
        {
            return fail("init_cache refused a fresh start");
        }
        DetourModKit::detail::g_memory_cache_shutdown_window_test_hook = &park_in_shutdown_window;
        std::thread stopper([] { DetourModKit::memory::shutdown_cache(); });
        stopper.detach();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        while (!s_in_shutdown_window.load(std::memory_order_acquire))
        {
            if (std::chrono::steady_clock::now() > deadline)
            {
                return fail("shutdown_cache did not reach its window");
            }
            std::this_thread::yield();
        }
        // The stopper stays parked inside the window with the cleanup handle still joinable. The other threads stop,
        // and the CRT exit runs static destruction over that handle.
        if (!suspend_other_threads())
        {
            return fail("suspend the other threads before exit");
        }
        std::fflush(stdout);
        std::exit(0);
    }

    // Captured in main before the cache exists, compared after the cache's destruction.
    std::wstring s_expected_directory;
    bool s_configure_armed = false;

    [[nodiscard]] std::wstring late_log_path()
    {
        return s_expected_directory + L"\\" + LATE_LOG_NAME;
    }

    struct LateConfigure
    {
        ~LateConfigure()
        {
            if (!s_configure_armed)
            {
                return;
            }
            int verdict = 0;
            const std::wstring late = DetourModKit::filesystem::get_runtime_directory();
            if (late != s_expected_directory)
            {
                std::fprintf(stderr, "FAIL: the directory cache changed after static destruction\n");
                verdict = 3;
            }
            DetourModKit::Logger::configure("LateStatic", "never_destroyed_storage_late.log");
            DetourModKit::Logger &logger = DetourModKit::log();
            (void)logger.log(DetourModKit::LogLevel::Info, "late static configure");
            logger.flush();
            logger.shutdown();
            const std::wstring expected_file = late_log_path();
            if (::GetFileAttributesW(expected_file.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                std::fprintf(stderr, "FAIL: the late configure did not resolve beside the module\n");
                verdict = verdict != 0 ? verdict : 4;
            }
            (void)::DeleteFileW(expected_file.c_str());
            std::fflush(stderr);
            std::_Exit(verdict);
        }
    };

    LateConfigure s_late_configure;

    int run_configure_case()
    {
        wchar_t temp_directory[MAX_PATH]{};
        if (::GetTempPathW(MAX_PATH, temp_directory) == 0 || !::SetCurrentDirectoryW(temp_directory))
        {
            return fail("move the working directory away from the module");
        }
        s_expected_directory = DetourModKit::filesystem::get_runtime_directory();
        if (s_expected_directory.empty() || s_expected_directory == L".")
        {
            return fail("resolve the module directory");
        }
        (void)::DeleteFileW(late_log_path().c_str());
        // Create the process default logger now, so the late configure reopens it through the directory cache.
        DetourModKit::Logger::configure("Early", "never_destroyed_storage_early.log");
        (void)DetourModKit::log().log(DetourModKit::LogLevel::Info, "early record");
        DetourModKit::log().flush();
        s_configure_armed = true;
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(
            stderr,
            "usage: never_destroyed_storage <exit-during-shutdown|configure-after-static-destruction>\n"
        );
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == EXIT_CASE)
    {
        return run_exit_case();
    }
    if (selected_case == CONFIGURE_CASE)
    {
        return run_configure_case();
    }

    std::fprintf(stderr, "unknown never-destroyed storage case\n");
    return 1;
}
