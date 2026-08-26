#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

#include <process.h>
#include <windows.h>

#include "DetourModKit.hpp"

#include "test_alloc_probe.hpp"

#include "internal/input_intercept.hpp"
#include "internal/input_delivery_scope.hpp"
#include "internal/input_test_seams.hpp"
#include "internal/lifecycle_context.hpp"
#include "platform.hpp"
#include "fixtures/intercept_lease.hpp"
#include "fixtures/loader_lock_scope.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace std::chrono_literals;
using DetourModKit::keyboard_key;

namespace DetourModKit::detail
{
    bool request_servicer_reload_for_test() noexcept;
    extern void (*g_config_watcher_prehandshake_seam)();
    extern void (*g_logger_publication_probe)();
    extern void (*g_logger_post_publication_probe)();
} // namespace DetourModKit::detail

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

namespace
{
    constexpr auto kTestTimeout = 5s;
    std::atomic<std::uint32_t> s_session_log_counter{0};

    [[nodiscard]] std::filesystem::path unique_session_log_path(std::string_view stem)
    {
        const std::uint32_t counter = s_session_log_counter.fetch_add(1, std::memory_order_relaxed);
        return std::filesystem::temp_directory_path() /
               (std::string(stem) + "_" + std::to_string(_getpid()) + "_" + std::to_string(counter) + ".log");
    }

    std::string current_exe_basename()
    {
        char exe_path[MAX_PATH]{};
        const DWORD len = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
        {
            return {};
        }
        const char *name = std::strrchr(exe_path, '\\');
        return name ? std::string(name + 1) : std::string(exe_path);
    }

    // Reconstructs the per-PID mutex name exactly as Session::start builds it (each prefix byte widened, then the
    // decimal PID), so a test can pre-own the name and force an InstanceAlreadyRunning collision.
    std::wstring instance_mutex_name(std::string_view prefix)
    {
        std::wstring name;
        name.reserve(prefix.size() + 10);
        for (char c : prefix)
        {
            name.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
        }
        name += std::to_wstring(GetCurrentProcessId());
        return name;
    }

    // Builds a Session for the current process with no single-instance guard. Used by the teardown-ordering tests,
    // which drive the ordered ~Session teardown by exercising subsystems inside the Session's scope and then destroying
    // it. ASSERTs on failure via the returned Result being checked at the call site.
    [[nodiscard]] Result<Session> start_local_session(std::string_view name, std::string_view log_file)
    {
        return Session::start(
            ModInfo{
                .name = name,
                .log_file = log_file,
            }
        );
    }

    struct CallbackSignals
    {
        std::mutex m;
        std::condition_variable cv;
        std::atomic<int> ready_calls{0};
        std::atomic<bool> ready_done{false};

        bool wait_for_ready(std::chrono::steady_clock::duration timeout)
        {
            std::unique_lock lock(m);
            return cv.wait_for(lock, timeout, [this] { return ready_done.load(std::memory_order_acquire); });
        }

        void signal_ready()
        {
            ready_calls.fetch_add(1, std::memory_order_relaxed);
            {
                std::lock_guard lock(m);
                ready_done.store(true, std::memory_order_release);
            }
            cv.notify_all();
        }
    };
} // namespace

// The session.hpp `[B-100]` warning owns the teardown route. An exception from host teardown terminates the process.
// This assertion pins the no-throw destructor.
static_assert(std::is_nothrow_destructible_v<Session>, "~Session must stay noexcept during host teardown.");
static_assert(!std::is_copy_constructible_v<Session>, "Session is move-only.");
static_assert(std::is_nothrow_move_constructible_v<Session>, "Session move must be noexcept for the RAII contract.");
static_assert(std::is_nothrow_move_assignable_v<Session>, "Session move-assign must be noexcept.");

// ModInfo + free-function preconditions

TEST(SessionModInfo, Defaults)
{
    const ModInfo info{};
    EXPECT_TRUE(info.name.empty());
    EXPECT_TRUE(info.log_file.empty());
    EXPECT_TRUE(info.game_process_name.empty());
    EXPECT_TRUE(info.instance_mutex_prefix.empty());
    EXPECT_TRUE(info.log.timestamp_format.empty());
}

TEST(SessionFreeFunctions, RequestShutdownBeforeBootstrapIsNoOp)
{
    EXPECT_NO_THROW(request_shutdown());
    EXPECT_NO_THROW(request_shutdown());
}

TEST(SessionFreeFunctions, ModuleHandleNullBeforeBootstrap)
{
    EXPECT_EQ(module_handle(), nullptr);
}

// Session::start gating

TEST(SessionStart, ProcessGateMismatchReturnsProcessMismatch)
{
    Result<Session> r = Session::start(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = "sess_test_procgate.log",
            .game_process_name = "DefinitelyNotTheCurrentProcess_xyz.exe",
            .instance_mutex_prefix = "Sess_Test_Mutex_ProcGate_",
        }
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::ProcessMismatch);
}

// Async activation is fail-soft inside Session::start: a refused activation must not fail the start, and a committed
// activation must never coexist with a returned failure. Both probes model the two halves of that boundary.
TEST(SessionStartAsyncActivation, RefusedActivationDoesNotFailStart)
{
    const std::filesystem::path log_path = unique_session_log_path("sess_test_async_soft");
    DetourModKit::detail::g_logger_publication_probe = []() { throw std::runtime_error("publication refused"); };
    {
        Result<Session> r = Session::start(
            ModInfo{
                .name = "SESS_ASYNC_SOFT",
                .log_file = log_path.string(),
            }
        );
        DetourModKit::detail::g_logger_publication_probe = nullptr;

        EXPECT_TRUE(r.has_value()) << "a contained async activation failure must not fail Session::start";
        EXPECT_FALSE(DetourModKit::log().is_async_mode_enabled())
            << "a refused activation must leave the session on synchronous logging";
    }
    std::error_code error_code;
    std::filesystem::remove(log_path, error_code);
}

TEST(SessionStartAsyncActivation, PostPublicationThrowLeavesWriterSessionOwned)
{
    const std::filesystem::path log_path = unique_session_log_path("sess_test_async_owned");
    DetourModKit::detail::g_logger_post_publication_probe = []() { throw std::runtime_error("diagnostic refused"); };
    {
        Result<Session> r = Session::start(
            ModInfo{
                .name = "SESS_ASYNC_OWNED",
                .log_file = log_path.string(),
            }
        );
        DetourModKit::detail::g_logger_post_publication_probe = nullptr;

        // A typed failure with a live writer leaves no Session owner. Containment keeps the writer owned until
        // teardown.
        EXPECT_TRUE(r.has_value()) << "start must not return failure while the activated writer is live";
        EXPECT_TRUE(DetourModKit::log().is_async_mode_enabled());
    }
    std::error_code error_code;
    std::filesystem::remove(log_path, error_code);
}

// The child executable supplies the long basename that the process gate reads. The parent starts the exact child case
// and checks its proof marker.
namespace
{
    constexpr DWORD CHILD_PROCESS_TIMEOUT_MS = 60000;
    constexpr DWORD CHILD_ARTIFACT_CLEANUP_TIMEOUT_MS = 5000;
    constexpr DWORD CHILD_ARTIFACT_CLEANUP_RETRY_MS = 20;
    constexpr std::string_view CHILD_EXECUTION_MARKER =
        "SessionStart.DISABLED_ChildProcessGateMatchesOwnBasename:complete";
    std::atomic<std::uint32_t> s_child_image_counter{0};

    // The 100 U+65E5 code points use 300 UTF-8 bytes and 100 UTF-16 code units. The PID and counter make the child
    // image name unique, while the complete component stays below the 255-code-unit limit.
    [[nodiscard]] std::wstring unique_long_multibyte_stem()
    {
        const std::uint32_t counter = s_child_image_counter.fetch_add(1, std::memory_order_relaxed);
        return std::wstring(100, L'\u65e5') + L"_" + std::to_wstring(_getpid()) + L"_" + std::to_wstring(counter);
    }

    [[nodiscard]] std::wstring current_exe_path_wide()
    {
        std::wstring path(32768, L'\0');
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0 || length >= path.size())
        {
            return {};
        }
        path.resize(length);
        return path;
    }

    [[nodiscard]] std::string to_utf8(std::wstring_view text)
    {
        if (text.empty())
        {
            return {};
        }
        const int needed =
            WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
        {
            return {};
        }
        std::string out(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(
            CP_UTF8,
            0,
            text.data(),
            static_cast<int>(text.size()),
            out.data(),
            needed,
            nullptr,
            nullptr
        );
        return out;
    }

    [[nodiscard]] std::filesystem::path child_execution_marker_path(const std::filesystem::path &image)
    {
        std::filesystem::path marker = image;
        marker += L".session-child-proof";
        return marker;
    }

    [[nodiscard]] std::filesystem::path child_log_path(const std::filesystem::path &image)
    {
        std::filesystem::path log = image;
        log += L".session.log";
        return log;
    }

    /**
     * @class ChildArtifactCleanup
     * @brief Owns cleanup for a child image, proof marker, and log.
     */
    class ChildArtifactCleanup final
    {
    public:
        /**
         * @brief Copies the artifact paths into the cleanup owner.
         * @param image Temporary child image path.
         * @param marker Temporary proof marker path.
         * @param log Temporary child log path.
         */
        ChildArtifactCleanup(
            const std::filesystem::path &image,
            const std::filesystem::path &marker,
            const std::filesystem::path &log
        )
            : m_image(image), m_marker(marker), m_log(log)
        {
        }

        /** @brief Retries bounded cleanup on scope exit. */
        ~ChildArtifactCleanup() noexcept
        {
            std::error_code error;
            (void)cleanup(error);
        }

        /**
         * @brief Removes each artifact after a bounded retry for transient Windows locks.
         * @param error Receives the first file-system error.
         * @return True when all three removal operations report no error.
         */
        [[nodiscard]] bool cleanup(std::error_code &error) noexcept
        {
            const ULONGLONG deadline = GetTickCount64() + CHILD_ARTIFACT_CLEANUP_TIMEOUT_MS;
            const std::error_code marker_error = remove_artifact(m_marker, deadline);
            const std::error_code log_error = remove_artifact(m_log, deadline);
            const std::error_code image_error = remove_artifact(m_image, deadline);
            error = marker_error ? marker_error : (log_error ? log_error : image_error);
            return !error;
        }

    private:
        /** @brief Removes one file and retries only transient Windows lock failures until @p deadline. */
        [[nodiscard]] static std::error_code
        remove_artifact(const std::filesystem::path &path, ULONGLONG deadline) noexcept
        {
            for (;;)
            {
                if (DeleteFileW(path.c_str()) != FALSE)
                {
                    return {};
                }
                const DWORD error = GetLastError();
                if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                {
                    return {};
                }
                if ((error != ERROR_ACCESS_DENIED && error != ERROR_SHARING_VIOLATION) || GetTickCount64() >= deadline)
                {
                    return {static_cast<int>(error), std::system_category()};
                }
                Sleep(CHILD_ARTIFACT_CLEANUP_RETRY_MS);
            }
        }

        ChildArtifactCleanup(const ChildArtifactCleanup &) = delete;
        ChildArtifactCleanup &operator=(const ChildArtifactCleanup &) = delete;
        ChildArtifactCleanup(ChildArtifactCleanup &&) = delete;
        ChildArtifactCleanup &operator=(ChildArtifactCleanup &&) = delete;

        std::filesystem::path m_image;
        std::filesystem::path m_marker;
        std::filesystem::path m_log;
    };
} // namespace

TEST(SessionStart, ChildArtifactCleanupRetriesTransientLocks)
{
    const std::filesystem::path locked_path = unique_session_log_path("session_child_cleanup_lock");
    const HANDLE locked = CreateFileW(
        locked_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    ASSERT_NE(locked, INVALID_HANDLE_VALUE) << "failed to create the locked cleanup fixture";
    std::unique_ptr<void, decltype(&CloseHandle)> locked_guard{locked, &CloseHandle};

    std::jthread release_lock(
        [locked_guard = std::move(locked_guard)]() mutable noexcept -> void
        {
            Sleep(100);
            locked_guard.reset();
        }
    );
    const std::filesystem::path marker_path{locked_path.wstring() + L".marker"};
    const std::filesystem::path log_path{locked_path.wstring() + L".log"};
    ChildArtifactCleanup artifacts{locked_path, marker_path, log_path};
    std::error_code cleanup_error;
    ASSERT_TRUE(artifacts.cleanup(cleanup_error)) << cleanup_error.message();
    EXPECT_FALSE(std::filesystem::exists(locked_path));
}

TEST(SessionStart, DISABLED_ChildProcessGateMatchesOwnBasename)
{
    const std::wstring own = current_exe_path_wide();
    ASSERT_FALSE(own.empty());
    const std::filesystem::path own_path{own};
    const std::wstring basename_wide = own_path.filename().wstring();
    const std::string basename = to_utf8(basename_wide);
    ASSERT_GE(basename.size(), static_cast<size_t>(MAX_PATH)) << "the child image lacks the required long basename";

    ASSERT_FALSE(basename_wide.empty());
    ASSERT_EQ(basename_wide.front(), L'\u65e5');
    std::wstring mismatch_wide = basename_wide;
    mismatch_wide.front() = L'\u65e6';
    const std::string mismatch = to_utf8(mismatch_wide);
    ASSERT_EQ(mismatch_wide.size(), basename_wide.size());
    ASSERT_EQ(mismatch.size(), basename.size());
    ASSERT_NE(mismatch, basename);

    const std::string log_file = to_utf8(child_log_path(own_path).filename().wstring());
    ASSERT_FALSE(log_file.empty());

    Result<Session> rejected = Session::start(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = log_file,
            .game_process_name = mismatch,
        }
    );
    ASSERT_FALSE(rejected.has_value());
    ASSERT_EQ(rejected.error().code, ErrorCode::ProcessMismatch);

    Result<Session> started = Session::start(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = log_file,
            .game_process_name = basename,
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();

    std::ofstream marker_stream(child_execution_marker_path(own_path), std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(marker_stream.is_open()) << "the child failed to create its proof marker";
    marker_stream << CHILD_EXECUTION_MARKER;
    marker_stream.close();
    ASSERT_TRUE(marker_stream) << "the child failed to commit its proof marker";
}

TEST(SessionStart, ProcessGateAcceptsLongMultibyteBasename)
{
    const std::wstring own = current_exe_path_wide();
    ASSERT_FALSE(own.empty());

    // Place the child image beside the original so it resolves the same fixture DLLs. A hard link avoids a copy of the
    // large test binary. A file system without hard links uses a copy.
    const std::filesystem::path directory = std::filesystem::path(own).parent_path();
    const std::filesystem::path renamed = directory / (unique_long_multibyte_stem() + L".exe");
    const std::filesystem::path marker = child_execution_marker_path(renamed);
    const std::filesystem::path child_log = child_log_path(renamed);
    ChildArtifactCleanup artifacts{renamed, marker, child_log};

    std::error_code cleanup_error;
    ASSERT_TRUE(artifacts.cleanup(cleanup_error))
        << "failed to clear prior child artifacts: " << cleanup_error.message();

    std::error_code create_error;
    std::filesystem::create_hard_link(own, renamed, create_error);
    if (create_error)
    {
        create_error.clear();
        std::filesystem::copy_file(own, renamed, create_error);
    }
    ASSERT_FALSE(create_error) << "failed to create the child image: " << create_error.message();

    std::wstring command = L"\"" + renamed.wstring() +
                           L"\" --gtest_also_run_disabled_tests"
                           L" --gtest_filter=SessionStart.DISABLED_ChildProcessGateMatchesOwnBasename";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        renamed.c_str(),
        command.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        directory.c_str(),
        &startup,
        &process
    );
    if (!created)
    {
        const DWORD launch_error = GetLastError();
        FAIL() << "CreateProcessW failed with " << launch_error;
    }

    const DWORD wait_result = WaitForSingleObject(process.hProcess, CHILD_PROCESS_TIMEOUT_MS);
    const DWORD wait_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
    BOOL terminate_result = TRUE;
    DWORD terminate_error = ERROR_SUCCESS;
    DWORD terminate_wait_result = WAIT_OBJECT_0;
    if (wait_result != WAIT_OBJECT_0)
    {
        terminate_result = TerminateProcess(process.hProcess, 1);
        if (!terminate_result)
        {
            terminate_error = GetLastError();
        }
        terminate_wait_result = WaitForSingleObject(process.hProcess, CHILD_PROCESS_TIMEOUT_MS);
    }

    DWORD exit_code = STILL_ACTIVE;
    BOOL exit_code_read = FALSE;
    DWORD exit_code_error = ERROR_SUCCESS;
    if (wait_result == WAIT_OBJECT_0)
    {
        exit_code_read = GetExitCodeProcess(process.hProcess, &exit_code);
        if (!exit_code_read)
        {
            exit_code_error = GetLastError();
        }
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    if (wait_result != WAIT_OBJECT_0)
    {
        std::error_code failure_cleanup_error;
        EXPECT_TRUE(artifacts.cleanup(failure_cleanup_error))
            << "failed to remove child artifacts: " << failure_cleanup_error.message();
    }
    ASSERT_EQ(wait_result, static_cast<DWORD>(WAIT_OBJECT_0))
        << "child wait result " << wait_result << ", Win32 error " << wait_error << ", terminate result "
        << terminate_result << ", terminate error " << terminate_error << ", final wait result "
        << terminate_wait_result;
    ASSERT_NE(exit_code_read, FALSE) << "GetExitCodeProcess failed with " << exit_code_error;
    ASSERT_EQ(exit_code, 0u) << "the child process reported a failed Session proof";

    std::string observed_marker;
    {
        std::ifstream marker_stream(marker, std::ios::binary);
        ASSERT_TRUE(marker_stream.is_open()) << "the child produced no proof marker";
        observed_marker.assign(std::istreambuf_iterator<char>{marker_stream}, std::istreambuf_iterator<char>{});
    }
    ASSERT_EQ(observed_marker, CHILD_EXECUTION_MARKER);

    cleanup_error.clear();
    ASSERT_TRUE(artifacts.cleanup(cleanup_error)) << "failed to remove child artifacts: " << cleanup_error.message();
}

TEST(SessionStart, EmptyProcessNamePassesGateButMutexCollisionFails)
{
    const std::string_view prefix = "Sess_Test_Mutex_EmptyGate_";
    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, instance_mutex_name(prefix).c_str());
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u);

    Result<Session> r = Session::start(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = "sess_test_emptygate.log",
            .instance_mutex_prefix = prefix,
        }
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InstanceAlreadyRunning);

    CloseHandle(pre_owned);
}

TEST(SessionStart, InstanceMutexCollisionReturnsAlreadyRunning)
{
    const std::string_view prefix = "Sess_Test_Mutex_Collision_";
    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, instance_mutex_name(prefix).c_str());
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u) << "Mutex name collided with an existing one before the test";

    const std::string exe_name = current_exe_basename();
    Result<Session> r = Session::start(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = "sess_test_mutex.log",
            .game_process_name = exe_name,
            .instance_mutex_prefix = prefix,
        }
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InstanceAlreadyRunning);

    CloseHandle(pre_owned);
}

TEST(SessionStart, InstanceMutexLongPrefixDoesNotOverflow)
{
    // A prefix far longer than any fixed-size formatting buffer must be formed intact, not truncated or overflowed.
    // Pre-own the name built exactly as Session::start builds it; a clean InstanceAlreadyRunning proves the long name
    // matched the one Session::start produced.
    const std::string prefix(200, 'A');
    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, instance_mutex_name(prefix).c_str());
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u) << "Long mutex name collided with an existing one before the test";

    const std::string exe_name = current_exe_basename();
    Result<Session> r = Session::start(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = "sess_test_mutex_long.log",
            .game_process_name = exe_name,
            .instance_mutex_prefix = prefix,
        }
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InstanceAlreadyRunning);

    CloseHandle(pre_owned);
}

TEST(SessionStart, SecondStartWhileActiveReturnsSessionAlreadyActive)
{
    Result<Session> first = start_local_session("SESS_TEST", "sess_test_double.log");
    ASSERT_TRUE(first.has_value()) << first.error().message();

    Result<Session> second = start_local_session("SESS_TEST", "sess_test_double_2.log");
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::SessionAlreadyActive);

    // `first` destructs here: the ordered teardown runs and releases the single-session guard, so the next test can
    // start cleanly.
}

TEST(SessionStart, StartDestroyCyclesReleaseTheGuard)
{
    // Reentrancy of the synchronous path: each ~Session must release the single-session guard AND the instance mutex so
    // the next start succeeds. Drive several full cycles and require each start to succeed.
    for (int cycle = 0; cycle < 3; ++cycle)
    {
        Result<Session> r = Session::start(
            ModInfo{
                .name = "SESS_TEST",
                .log_file = "sess_test_cycle.log",
                .game_process_name = current_exe_basename(),
                .instance_mutex_prefix = "Sess_Test_Mutex_Cycle_",
            }
        );
        ASSERT_TRUE(r.has_value()) << "cycle " << cycle << ": " << r.error().message();
        // Destroyed at loop-end: teardown releases the guard + mutex for the next cycle.
    }
}

// Move + inertness

TEST(SessionMove, MovedFromSessionIsInert)
{
    Result<Session> r = start_local_session("SESS_TEST", "sess_test_move.log");
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Session a = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(a));

    Session b = std::move(a);
    EXPECT_FALSE(static_cast<bool>(a)) << "a moved-from Session must be inert";
    EXPECT_TRUE(static_cast<bool>(b)) << "the moved-to Session carries the live teardown";

    // Both destruct at scope end: a (inert) is a no-op, b runs the single teardown. No double-release of the guard or
    // the mutex. The next start proves the guard was cleared exactly once.
    // (b destructs here)
}

TEST(SessionMove, StartSucceedsAfterAMovedThenDroppedSession)
{
    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_move2.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session a = std::move(*r);
        Session b = std::move(a);
        (void)b;
    }
    Result<Session> again = start_local_session("SESS_TEST", "sess_test_move2b.log");
    EXPECT_TRUE(again.has_value()) << again.error().message();
}

TEST(SessionMove, MoveAssignEndsTheOverwrittenSession)
{
    // Move-assigning over an ACTIVE Session must run its FULL ordered teardown (releasing the single-session guard),
    // not merely drop its handles. Build one live Session, move it so the source becomes inert, then move-assign the
    // inert source back over the still-live target: the target's session must end and the guard clear.
    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_moveassign.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session live = std::move(*r);
        Session inert = std::move(live); // inert is now the live one; `live` is inert
        EXPECT_TRUE(static_cast<bool>(inert));

        inert = std::move(live); // move-assign the inert source over the live target: release() must end the session
        EXPECT_FALSE(static_cast<bool>(inert)) << "the overwritten Session must be ended, not left live";
        EXPECT_FALSE(static_cast<bool>(live));
    }

    // If the move-assign had failed to clear the single-session guard, this fresh start would report
    // SessionAlreadyActive.
    Result<Session> again = start_local_session("SESS_TEST", "sess_test_moveassign_2.log");
    EXPECT_TRUE(again.has_value()) << again.error().message();
}

// Ordered teardown (the ~Session body)

TEST(SessionTeardown, TeardownWithNoSubsystemsInitialized)
{
    Result<Session> r = start_local_session("SESS_TEST", "sess_test_empty.log");
    ASSERT_TRUE(r.has_value()) << r.error().message();
    EXPECT_NO_THROW({
        Session s = std::move(*r);
        (void)s;
    });
}

TEST(SessionTeardown, ClearsConfigRegistryAllowingHotReload)
{
    int call_count_a = 0;
    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_hotreload.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);
        config::bind_int("Section", "Key", "hot_reload_a", [&call_count_a](int) { ++call_count_a; }, 10);
        EXPECT_EQ(call_count_a, 1); // Default applied once
        // s destructs here: teardown clears the registry.
    }

    // After teardown the old registration is cleared. Re-register for a "second load".
    int call_count_b = 0;
    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_hotreload_2.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);
        config::bind_int("Section", "Key", "hot_reload_b", [&call_count_b](int) { ++call_count_b; }, 20);
        EXPECT_EQ(call_count_b, 1);

        call_count_a = 0;
        call_count_b = 0;

        auto ini_path = std::filesystem::temp_directory_path() /
                        ("test_session_hotreload_" + std::to_string(GetCurrentProcessId()) + ".ini");
        EXPECT_NO_THROW(config::load(ini_path.string()));

        // Old callback must not fire (its registry entry was cleared by the prior teardown); new one fires with
        // default.
        EXPECT_EQ(call_count_a, 0);
        EXPECT_EQ(call_count_b, 1);

        if (std::filesystem::exists(ini_path))
        {
            std::filesystem::remove(ini_path);
        }
    }
}

TEST(SessionTeardown, StopsAutoReloadWatcherFirst)
{
    // ~Session must stop the config auto-reload watcher before clearing state a watcher callback might touch. Prove it
    // deterministically: after teardown, re-enabling must return Started, not AlreadyRunning.
    const auto ini_path = std::filesystem::temp_directory_path() /
                          ("test_session_autoreload_" + std::to_string(GetCurrentProcessId()) + ".ini");
    {
        std::ofstream ofs(ini_path);
        ofs << "[Section]\nKey=1\n";
    }

    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_watcher.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);

        config::bind_int("Section", "Key", "autoreload_watcher", [](int) {}, 1);
        ASSERT_NO_THROW(config::load(ini_path.string()));
        ASSERT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started);
        ASSERT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::AlreadyRunning);
        // s destructs here: teardown must stop the watcher.
    }

    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_watcher_2.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);
        config::bind_int("Section", "Key", "autoreload_watcher_2", [](int) {}, 1);
        ASSERT_NO_THROW(config::load(ini_path.string()));
        EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started)
            << "~Session must stop the auto-reload watcher; a survivor would report AlreadyRunning";
        config::disable_auto_reload();
    }

    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
}

TEST(SessionTeardown, FlushesConfiguredLogger)
{
    // Temp files here are named with the PID: under ctest PRE_TEST discovery each case runs in its own process, so the
    // PID makes the path unique across parallel cases (which never share a process) and repeated runs (each cleans up).
    const auto log_path = std::filesystem::temp_directory_path() /
                          ("test_session_logger_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::filesystem::remove(log_path); // start clean so the read-back sees only this run's line

    constexpr std::string_view kMarker = "Session teardown test message";
    {
        Result<Session> r = Session::start(
            ModInfo{
                .name = "SESS_TEST",
                .log_file = log_path.string(),
            }
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);
        s.log().set_log_level(LogLevel::Info); // deterministic: do not depend on a prior test's level
        s.log().log(LogLevel::Info, kMarker);
        // Destroying the Session must run log().shutdown(), which flushes the async queue and closes the sink.
        Session moved = std::move(s);
        (void)moved;
    }

    // Prove teardown actually FLUSHED the logger (not merely that it did not throw): the line must now be on disk.
    std::ifstream in(log_path);
    ASSERT_TRUE(in.is_open()) << "teardown should have created and flushed the log file";
    bool found = false;
    for (std::string line; std::getline(in, line);)
    {
        if (line.find(kMarker) != std::string::npos)
        {
            found = true;
            break;
        }
    }
    in.close();
    EXPECT_TRUE(found) << "~Session must flush the configured logger; the logged line was not on disk";

    if (std::filesystem::exists(log_path))
    {
        std::filesystem::remove(log_path);
    }
}

TEST(SessionTeardown, ResetsMemoryCache)
{
    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_memcache.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);
        ASSERT_TRUE(memory::init_cache());
        // s destructs here: teardown shuts the cache down.
    }

    // After teardown, re-init succeeds and stats reflect a fresh cache.
    ASSERT_TRUE(memory::init_cache());
    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("Hits: 0"), std::string::npos);
    EXPECT_NE(stats.find("Misses: 0"), std::string::npos);
    memory::shutdown_cache();
}

TEST(SessionTeardown, ClearsInputBindings)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown(); // reset any residual bindings so the count assertions are deterministic
    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_input.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);
        (void)input::register_combo(
            input::ComboBinding{
                .name = std::string{"session_test_key"},
                .trigger = input::Trigger::Press,
                .combos = {{{keyboard_key(0x41)}, {}}},
                .on_press = []() {},
                .on_state_change = {},
            }
        );
        EXPECT_EQ(mgr.binding_count(), 1u);
        // s destructs here: teardown shuts the input subsystem down.
    }
    EXPECT_EQ(mgr.binding_count(), 0u);
}

// abandon() neutralizes the Session so ~Session does NOTHING: for process-exit only, it skips the ordered teardown.
// Prove it: a config item registered before abandon() survives the (inert) destructor.
TEST(SessionTeardown, AbandonSkipsOrderedTeardown)
{
    input::Input::instance().shutdown();
    config::clear();

    auto sentinel = std::make_shared<int>(0);
    ASSERT_EQ(sentinel.use_count(), 1L);

    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_abandon.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);
        config::bind_string(
            "SessionAbandonCfg",
            "Key",
            "session abandon key",
            [sentinel](std::string_view) { /* keeps it alive */ },
            "default"
        );
        EXPECT_GE(sentinel.use_count(), 2L);

        s.abandon();
        EXPECT_FALSE(static_cast<bool>(s)) << "abandon() must neutralize the Session";
        // s destructs here: inert, so config::clear() is NOT run and the registry entry survives.
    }

    EXPECT_GE(sentinel.use_count(), 2L) << "abandon() must skip the ordered teardown; the registry entry must survive";

    // Clean up the surviving entry explicitly so it does not leak into other tests.
    config::clear();
    EXPECT_EQ(sentinel.use_count(), 1L);
}

// Session::abandon() must neutralize m_scope so ~Session runs no guard release. A held Hold binding cannot be driven
// from a unit test (no GetAsyncKeyState seam), so a consume binding stands in: its release lifts suppression, which
// is the observable "release ran" signal. abandon() must leave that suppression armed.
TEST(SessionTeardown, AbandonLeavesScopeGuardReleaseUnrun)
{
    input::Input::instance().shutdown();
    config::clear();
    dmk_test::reset_published_consume_rules();

    const std::uint16_t button = static_cast<std::uint16_t>(GamepadCode::A);

    {
        Result<Session> r = start_local_session("SESS_TEST", "sess_test_abandon_scope.log");
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);

        auto guard = input::register_combo(
            input::ComboBinding{
                .name = "session_abandon_consume",
                .trigger = input::Trigger::Press,
                .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                .consume = true,
                .on_press = [] {},
            }
        );
        ASSERT_TRUE(guard.has_value());
        s.scope().add(std::move(*guard));

        (void)input::Input::instance().start(
            input::Input::Settings{
                .poll_interval = std::chrono::milliseconds{1000},
            }
        );
        // The engine publishes its consume rules only while it owns the interception layer, which a headless test
        // host cannot reach by installing. Grant it explicitly so the published table reflects this engine.
        ASSERT_TRUE(DetourModKit::detail::InputTestSeams::adopt_intercept_owner_for_test());
        ASSERT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button);

        s.abandon();
        // s destructs here; the member ~Scope is inert because abandon() retained the complete guard container.
    }

    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button)
        << "Session::abandon() must leave the scope's guard release unrun; suppression stays armed";

    input::Input::instance().shutdown();
    dmk_test::reset_published_consume_rules();
}

// The full reverse-dependency teardown as one integration test. The per-leaf SessionTeardown cases each exercise a
// single subsystem in isolation; this activates ALL of them in one Session (the config registry and its auto-reload
// watcher, an input binding, the memory cache, and the logger), then destroys the Session and asserts every leaf shut
// down. It pins that ~Session runs the WHOLE ordered sequence (config watcher -> input -> memory cache -> config
// registry -> logger, logger last) to completion when the entire stack coexists, so no leaf is skipped or
// short-circuited by another's teardown.
TEST(SessionTeardown, FullStackTeardownShutsEveryLeafDown)
{
    input::Input::instance().shutdown(); // deterministic input baseline
    config::clear();

    const auto ini_path = std::filesystem::temp_directory_path() /
                          ("test_session_fullstack_" + std::to_string(GetCurrentProcessId()) + ".ini");
    {
        std::ofstream ofs(ini_path);
        ofs << "[Section]\nKey=1\n";
    }
    const auto log_path = std::filesystem::temp_directory_path() /
                          ("test_session_fullstack_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::filesystem::remove(log_path);

    auto registry_sentinel = std::make_shared<int>(0);
    constexpr std::string_view kMarker = "full-stack teardown marker";

    {
        Result<Session> r = Session::start(
            ModInfo{
                .name = "SESS_TEST",
                .log_file = log_path.string(),
            }
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Session s = std::move(*r);
        s.log().set_log_level(LogLevel::Info);

        // Config registry: a bound setter that captures the sentinel, so releasing it proves config::clear() ran.
        config::bind_int("Section", "Key", "fullstack_registry", [registry_sentinel](int) {}, 1);
        // Auto-reload watcher: load then enable so a background poll thread is live.
        ASSERT_NO_THROW(config::load(ini_path.string()));
        ASSERT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started);
        // Input: one live binding.
        (void)input::register_combo(
            input::ComboBinding{
                .name = std::string{"fullstack_key"},
                .trigger = input::Trigger::Press,
                .combos = {{{keyboard_key(0x42)}, {}}},
                .on_press = []() {},
                .on_state_change = {},
            }
        );
        EXPECT_EQ(input::Input::instance().binding_count(), 1u);
        // Memory cache: live.
        ASSERT_TRUE(memory::init_cache());
        // Logger: a line that must survive the flush the teardown performs last.
        s.log().log(LogLevel::Info, kMarker);
        EXPECT_GE(registry_sentinel.use_count(), 2L);
        // s destructs here: the full ordered teardown runs across the whole stack.
    }

    // Input subsystem down.
    EXPECT_EQ(input::Input::instance().binding_count(), 0u) << "input subsystem must be shut down";
    // Config registry cleared (the bound setter, and its sentinel capture, released).
    EXPECT_EQ(registry_sentinel.use_count(), 1L) << "config registry must be cleared";

    // Memory cache reset: a fresh re-init reports zeroed stats.
    ASSERT_TRUE(memory::init_cache());
    const std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("Hits: 0"), std::string::npos) << "memory cache must be reset";
    memory::shutdown_cache();

    // Logger flushed last: the marker reached disk before the sink closed.
    std::ifstream in(log_path);
    ASSERT_TRUE(in.is_open()) << "teardown must have flushed and closed the logger";
    bool found = false;
    for (std::string line; std::getline(in, line);)
    {
        if (line.find(kMarker) != std::string::npos)
        {
            found = true;
            break;
        }
    }
    in.close();
    EXPECT_TRUE(found) << "logger must flush last, capturing lines logged during the session";

    // Auto-reload watcher stopped: re-enabling in a fresh Session returns Started, not AlreadyRunning.
    {
        Result<Session> r2 = start_local_session("SESS_TEST", "sess_test_fullstack_2.log");
        ASSERT_TRUE(r2.has_value()) << r2.error().message();
        Session s2 = std::move(*r2);
        config::bind_int("Section", "Key", "fullstack_watcher_2", [](int) {}, 1);
        ASSERT_NO_THROW(config::load(ini_path.string()));
        EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started)
            << "the prior teardown must have stopped the auto-reload watcher";
        config::disable_auto_reload();
    }

    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
    if (std::filesystem::exists(log_path))
    {
        std::filesystem::remove(log_path);
    }
}

// The ordered teardown must NOT touch hooks: each hook is owned by the caller's Hook handle. Prove a Hook dropped
// before teardown is already unhooked, and teardown still runs its non-hook steps cleanly.
namespace
{
    DMK_TEST_NOINLINE int session_raii_target(int x)
    {
        volatile int r = x + 1;
        return r;
    }
    int session_raii_detour(int x)
    {
        return x + 2;
    }
} // namespace

TEST(SessionTeardown, HookLifetimeIsCallerOwned)
{
    const Address target{reinterpret_cast<std::uintptr_t>(&session_raii_target)};

    Result<Session> rs = start_local_session("SESS_TEST", "sess_test_hooklife.log");
    ASSERT_TRUE(rs.has_value()) << rs.error().message();
    Session s = std::move(*rs);

    {
        Result<Hook> r = inline_at(
            InlineRequest{
                .name = "session_raii_hook",
                .target = target,
            },
            &session_raii_detour
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        ASSERT_TRUE(h.enable().has_value()) << "hook enable failed";

        EXPECT_TRUE(is_target_hooked(target)) << "ledger must record the live hook";
        EXPECT_EQ(session_raii_target(10), 12) << "the installed detour is active";
        EXPECT_EQ(h.call<int>(10), 11) << "call<>() reaches the original through the guarded trampoline";
    }

    // The handle dropped: RAII already unhooked it, with no help from the Session.
    EXPECT_FALSE(is_target_hooked(target)) << "dropping the Hook handle must unhook, independent of the Session";

    // Destroying the Session runs its non-hook teardown; the caller-owned hook is neither resurrected nor re-touched.
    EXPECT_NO_THROW({
        Session moved = std::move(s);
        (void)moved;
    });
    EXPECT_FALSE(is_target_hooked(target));
}

// Async bootstrap / bootstrap_detach

class SessionBootstrapTest : public ::testing::Test
{
protected:
    CallbackSignals m_sig;
    bool m_bootstrapped{false};

    void TearDown() override
    {
        if (m_bootstrapped)
        {
            Result<void> drained = shutdown_and_wait();
            EXPECT_TRUE(drained.has_value()) << (drained ? "" : drained.error().message());
        }
    }
};

TEST_F(SessionBootstrapTest, HappyPathBootstrapRunsOnReady)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Result<void> started = bootstrap(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = "sess_test_happy.log",
            .game_process_name = exe_name,
            .instance_mutex_prefix = "Sess_Test_Mutex_Happy_",
        },
        [this](Session &) -> Result<void>
        {
            m_sig.signal_ready();
            return {};
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;

    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout)) << "on_ready did not complete within timeout";
    EXPECT_EQ(m_sig.ready_calls.load(), 1);
    EXPECT_NE(module_handle(), nullptr);

    // The auto-captured handle must be the module that owns the DetourModKit code (here the test executable, which
    // links DetourModKit statically). Resolve it independently with the identity-only UNCHANGED_REFCOUNT flavor (the
    // same non-owning capture bootstrap uses, which must not take a reference on the module) and require a match.
    constexpr DWORD identity_flags =
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    HMODULE expected_module = nullptr;
    ASSERT_TRUE(GetModuleHandleExW(identity_flags, reinterpret_cast<LPCWSTR>(&current_exe_basename), &expected_module));
    EXPECT_EQ(module_handle(), expected_module);

    // A second bootstrap while the worker is live is rejected.
    Result<void> second = bootstrap(
        ModInfo{
            .name = "SESS_TEST",
        },
        [](Session &) -> Result<void> { return {}; }
    );
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::SessionAlreadyActive);
    EXPECT_EQ(m_sig.ready_calls.load(), 1);
}

TEST_F(SessionBootstrapTest, ProcessGateMismatchDoesNotSpawnWorker)
{
    Result<void> started = bootstrap(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = "sess_test_bootstrap_gate.log",
            .game_process_name = "DefinitelyNotTheCurrentProcess_boot.exe",
            .instance_mutex_prefix = "Sess_Test_Mutex_BootGate_",
        },
        [this](Session &) -> Result<void>
        {
            m_sig.signal_ready();
            return {};
        }
    );
    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error().code, ErrorCode::ProcessMismatch);
    EXPECT_EQ(module_handle(), nullptr) << "a failed bootstrap must roll back the captured module";
    EXPECT_EQ(m_sig.ready_calls.load(), 0) << "on_ready must not run when the gate rejects the process";
}

TEST(SessionBootstrapReentrancy, BootstrapDrainCyclesRepeat)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    for (int cycle = 1; cycle <= 2; ++cycle)
    {
        CallbackSignals sig;
        Result<void> started = bootstrap(
            ModInfo{
                .name = "SESS_TEST",
                .log_file = "sess_test_reentrant.log",
                .game_process_name = exe_name,
                .instance_mutex_prefix = "Sess_Test_Mutex_Reentrant_",
            },
            [&sig](Session &) -> Result<void>
            {
                sig.signal_ready();
                return {};
            }
        );
        ASSERT_TRUE(started.has_value()) << "cycle " << cycle << ": " << started.error().message();
        ASSERT_TRUE(sig.wait_for_ready(kTestTimeout)) << "cycle " << cycle << ": on_ready did not complete";
        EXPECT_EQ(sig.ready_calls.load(), 1) << "cycle " << cycle;

        Result<void> drained = shutdown_and_wait();
        ASSERT_TRUE(drained.has_value()) << drained.error().message();
        EXPECT_EQ(module_handle(), nullptr) << "cycle " << cycle << ": detach must clear the module handle";
    }
}

TEST_F(SessionBootstrapTest, OnReadyExceptionIsCaught)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Result<void> started = bootstrap(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = "sess_test_throws.log",
            .game_process_name = exe_name,
            .instance_mutex_prefix = "Sess_Test_Mutex_Throws_",
        },
        [this](Session &) -> Result<void>
        {
            m_sig.signal_ready();
            throw std::runtime_error("on_ready failure");
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;

    // The worker catches the throw; the process survives and teardown still runs at detach.
    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout));
    EXPECT_EQ(m_sig.ready_calls.load(), 1);
}

// T-BOOTSTRAP

namespace DetourModKit
{
    extern void bootstrap_fail_worker_launch_for_test(bool fail) noexcept;
} // namespace DetourModKit

namespace
{
    static_assert(std::is_trivially_copyable_v<BootstrapReadyFn> && std::is_trivially_destructible_v<BootstrapReadyFn>);

    struct DestructibleAttachCallback
    {
        ~DestructibleAttachCallback() noexcept {}

        Result<void> operator()(Session &) const { return {}; }
    };

    static_assert(!std::is_trivially_destructible_v<DestructibleAttachCallback>);
    static_assert(!std::is_convertible_v<DestructibleAttachCallback, BootstrapReadyFn>);

    std::atomic<int> s_attach_ready_calls{0};

    Result<void> attach_entry_on_ready(Session &)
    {
        s_attach_ready_calls.fetch_add(1, std::memory_order_acq_rel);
        return {};
    }

    Result<void> attach_entry_noop(Session &)
    {
        return {};
    }

    [[nodiscard]] bool wait_for_attach_ready(int expected, std::chrono::milliseconds budget)
    {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (s_attach_ready_calls.load(std::memory_order_acquire) < expected)
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }
            std::this_thread::yield();
        }
        return true;
    }
} // namespace

TEST_F(SessionBootstrapTest, AttachEntryPublishesWorkerWithoutCallerThreadAllocation)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());
    s_attach_ready_calls.store(0, std::memory_order_release);

    const ModInfo info{
        .name = "SESS_TEST",
        .log_file = "sess_attach_happy.log",
        .game_process_name = exe_name,
        .instance_mutex_prefix = "Sess_Attach_Mutex_Happy_",
    };
    Result<void> started;
    {
        dmk_test::AllocFailScope no_alloc{0};
        started = bootstrap_attach(info, &attach_entry_on_ready);
    }
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;

    ASSERT_TRUE(wait_for_attach_ready(1, kTestTimeout)) << "on_ready did not run on the worker";
    EXPECT_EQ(s_attach_ready_calls.load(std::memory_order_acquire), 1);
    EXPECT_NE(module_handle(), nullptr);

    // Build ModInfo before the probe because an MSVC debug string can allocate a proxy.
    const ModInfo second_info{
        .name = "SESS_TEST",
    };
    Result<void> second;
    {
        dmk_test::AllocFailScope no_alloc{0};
        second = bootstrap_attach(second_info, &attach_entry_on_ready);
    }
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::SessionAlreadyActive);
    EXPECT_EQ(s_attach_ready_calls.load(std::memory_order_acquire), 1);
}

TEST_F(SessionBootstrapTest, AttachEntryPrePublicationFailuresAllocateAndDestroyNothing)
{
    s_attach_ready_calls.store(0, std::memory_order_release);

    {
        const ModInfo mismatch{
            .name = "SESS_TEST",
            .log_file = "sess_attach_gate.log",
            .game_process_name = "DefinitelyNotTheCurrentProcess_attach.exe",
        };
        Result<void> started;
        {
            dmk_test::AllocFailScope no_alloc{0};
            started = bootstrap_attach(mismatch, &attach_entry_on_ready);
        }
        ASSERT_FALSE(started.has_value());
        EXPECT_EQ(started.error().code, ErrorCode::ProcessMismatch);
        EXPECT_EQ(module_handle(), nullptr) << "a failed attach must roll back the captured module";
    }

    {
        const std::string_view prefix = "Sess_Attach_Mutex_Held_";
        HANDLE pre_owned = CreateMutexW(nullptr, FALSE, instance_mutex_name(prefix).c_str());
        ASSERT_NE(pre_owned, nullptr);
        const ModInfo held{
            .name = "SESS_TEST",
            .log_file = "sess_attach_held.log",
            .instance_mutex_prefix = prefix,
        };
        Result<void> started;
        {
            dmk_test::AllocFailScope no_alloc{0};
            started = bootstrap_attach(held, &attach_entry_on_ready);
        }
        CloseHandle(pre_owned);
        ASSERT_FALSE(started.has_value());
        EXPECT_EQ(started.error().code, ErrorCode::InstanceAlreadyRunning);
    }

    {
        const std::string oversize(40000, 'x');
        const ModInfo oversized{
            .name = oversize,
            .log_file = "sess_attach_oversize.log",
        };
        Result<void> started;
        {
            dmk_test::AllocFailScope no_alloc{0};
            started = bootstrap_attach(oversized, &attach_entry_on_ready);
        }
        ASSERT_FALSE(started.has_value());
        EXPECT_EQ(started.error().code, ErrorCode::InvalidArg);
    }

    // Worker-launch failure reaches the complete unwind, and the slot admits a retry afterwards.
    {
        DetourModKit::bootstrap_fail_worker_launch_for_test(true);
        const ModInfo launch{
            .name = "SESS_TEST",
            .log_file = "sess_attach_launch.log",
        };
        Result<void> started;
        {
            dmk_test::AllocFailScope no_alloc{0};
            started = bootstrap_attach(launch, &attach_entry_on_ready);
        }
        DetourModKit::bootstrap_fail_worker_launch_for_test(false);
        ASSERT_FALSE(started.has_value());
        EXPECT_EQ(started.error().code, ErrorCode::SystemCallFailed);
        EXPECT_EQ(module_handle(), nullptr) << "unwind_bootstrap must retire the module identity";
    }

    EXPECT_EQ(s_attach_ready_calls.load(std::memory_order_acquire), 0)
        << "a pre-publication failure must not reach the callback";

    Result<void> retry = bootstrap_attach(
        ModInfo{
            .name = "SESS_TEST",
            .log_file = "sess_attach_retry.log",
        },
        &attach_entry_on_ready
    );
    ASSERT_TRUE(retry.has_value()) << retry.error().message();
    m_bootstrapped = true;
    ASSERT_TRUE(wait_for_attach_ready(1, kTestTimeout));
}

// Hot-reload helpers

namespace
{
    DMK_TEST_NOINLINE int logic_unload_target_add(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }
    DMK_TEST_NOINLINE int logic_unload_detour_add(int a, int b)
    {
        return a + b + 1;
    }
    DMK_TEST_NOINLINE int logic_unload_target_sub(int a, int b)
    {
        volatile int r = a - b;
        return r;
    }
    DMK_TEST_NOINLINE int logic_unload_detour_sub(int a, int b)
    {
        return a - b - 1;
    }

    std::atomic<bool> s_watcher_startup_parked{false};
    std::atomic<bool> s_release_watcher_startup{false};

    void park_watcher_startup()
    {
        s_watcher_startup_parked.store(true, std::memory_order_release);
        while (!s_release_watcher_startup.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }
} // namespace

// on_logic_dll_unload tears down the named bindings and the config registry; it does NOT touch hooks (caller-owned).
TEST(SessionHotReload, UnloadTearsDownBindingsButHooksAreCallerOwned)
{
    input::Input::instance().shutdown();

    const Address target{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "logic_unload_hook",
            .target = target,
        },
        &logic_unload_detour_add
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "hook enable failed";
    ASSERT_TRUE(is_target_hooked(target));

    (void)input::register_combo(
        input::ComboBinding{
            .name = std::string{"logic_unload_binding"},
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
            .on_state_change = {},
        }
    );
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    const std::string_view bindings[] = {"logic_unload_binding"};
    EXPECT_EQ(prepare_logic_dll_unload(bindings), LogicDllUnloadStatus::SafeToUnload);

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_TRUE(static_cast<bool>(h)) << "the caller still owns the hook";
    EXPECT_TRUE(h.is_enabled());
    EXPECT_TRUE(is_target_hooked(target));

    // h drops here: RAII unhooks, proving lifetime is the caller's, not the unload helper's.
}

TEST(SessionHotReload, UnloadIsIdempotent)
{
    input::Input::instance().shutdown();

    const Address target{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "logic_unload_idem",
            .target = target,
        },
        &logic_unload_detour_add
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    (void)input::register_combo(
        input::ComboBinding{
            .name = std::string{"logic_unload_idem_bind"},
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
            .on_state_change = {},
        }
    );

    const std::string_view bindings[] = {"logic_unload_idem_bind"};
    on_logic_dll_unload(bindings);
    on_logic_dll_unload(bindings);

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_TRUE(is_target_hooked(target));
}

TEST(SessionHotReload, UnloadAllClearsEveryBindingButHooksAreCallerOwned)
{
    input::Input::instance().shutdown();

    const Address target_add{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    const Address target_sub{reinterpret_cast<std::uintptr_t>(&logic_unload_target_sub)};

    Result<Hook> r_add = inline_at(
        InlineRequest{
            .name = "logic_unload_all_add",
            .target = target_add,
        },
        &logic_unload_detour_add
    );
    ASSERT_TRUE(r_add.has_value()) << r_add.error().message();
    Hook h_add = std::move(*r_add);

    Result<Hook> r_sub = inline_at(
        InlineRequest{
            .name = "logic_unload_all_sub",
            .target = target_sub,
        },
        &logic_unload_detour_sub
    );
    ASSERT_TRUE(r_sub.has_value()) << r_sub.error().message();
    Hook h_sub = std::move(*r_sub);

    (void)input::register_combo(
        input::ComboBinding{
            .name = std::string{"logic_unload_all_bind_a"},
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x43)}, {}}},
            .on_press = []() {},
            .on_state_change = {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = std::string{"logic_unload_all_bind_b"},
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x44)}, {}}},
            .on_press = []() {},
            .on_state_change = {},
        }
    );
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(2));

    on_logic_dll_unload_all();

    EXPECT_TRUE(static_cast<bool>(h_add));
    EXPECT_TRUE(static_cast<bool>(h_sub));
    EXPECT_TRUE(is_target_hooked(target_add));
    EXPECT_TRUE(is_target_hooked(target_sub));
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
}

TEST(SessionHotReload, UnloadAllIsIdempotent)
{
    input::Input::instance().shutdown();

    (void)input::register_combo(
        input::ComboBinding{
            .name = std::string{"logic_unload_all_idem_bind"},
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x45)}, {}}},
            .on_press = []() {},
            .on_state_change = {},
        }
    );

    on_logic_dll_unload_all();
    on_logic_dll_unload_all();

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
}

TEST(SessionHotReload, UnloadAllEmptyRegistriesIsNoOp)
{
    input::Input::instance().shutdown();
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    on_logic_dll_unload_all();
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
}

TEST(SessionHotReload, UnloadSuppressesHoldReleaseCallbacks)
{
    input::Input::instance().shutdown();

    auto release_count = std::make_shared<std::atomic<int>>(0);
    auto press_count = std::make_shared<std::atomic<int>>(0);

    (void)input::register_combo(
        input::ComboBinding{
            .name = std::string{"loader_lock_hold"},
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x48)}, {}}},
            .on_press = {},
            .on_state_change = [release_count, press_count](bool pressed) noexcept
            {
                if (pressed)
                {
                    press_count->fetch_add(1, std::memory_order_relaxed);
                }
                else
                {
                    release_count->fetch_add(1, std::memory_order_relaxed);
                }
            },
        }
    );
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    const std::string_view bindings[] = {"loader_lock_hold"};
    on_logic_dll_unload(bindings);

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_EQ(release_count->load(), 0)
        << "hot-reload helpers must not invoke user release callbacks under a loader lock";
    EXPECT_EQ(press_count->load(), 0);
}

TEST(SessionHotReload, TypedPreparationRefusesSelfDelivery)
{
    const DetourModKit::detail::DeliveryScope delivery;
    EXPECT_EQ(prepare_logic_dll_unload({}), LogicDllUnloadStatus::SelfDelivery);
}

TEST(SessionHotReload, ParkedConfigCallbackHonorsTheTypedDeadlineWithoutHiddenJoin)
{
    input::Input::instance().shutdown();
    config::clear();

    // Process-scoped leaf: two test processes running this case concurrently would otherwise share one INI and race
    // each other's writes into the watcher under test.
    const std::filesystem::path ini_path =
        std::filesystem::temp_directory_path() /
        ("dmk_session_typed_drain_" + std::to_string(GetCurrentProcessId()) + ".ini");
    {
        std::ofstream file(ini_path);
        file << "[Drain]\nValue=1\n";
    }

    std::atomic<bool> setter_parked{false};
    std::atomic<bool> release_setter{false};
    config::bind_int(
        "Drain",
        "Value",
        "typed drain",
        [&](int value)
        {
            if (value == 2)
            {
                setter_parked.store(true, std::memory_order_release);
                while (!release_setter.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
            }
        },
        1
    );
    ASSERT_NO_THROW(config::load(ini_path.string()));
    ASSERT_TRUE(config::reload_hotkey("Reload", "F12"));

    {
        std::ofstream file(ini_path);
        file << "[Drain]\nValue=2\n";
    }
    ASSERT_TRUE(DetourModKit::detail::request_servicer_reload_for_test());
    for (int i = 0; i < 1000 && !setter_parked.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(setter_parked.load(std::memory_order_acquire));

    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(prepare_logic_dll_unload({}, std::chrono::milliseconds{40}), LogicDllUnloadStatus::TimedOut);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, std::chrono::milliseconds{500});

    auto rejected = input::register_combo(
        input::ComboBinding{
            .name = "must_not_register_during_session_retry",
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x41)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, ErrorCode::ShutdownInProgress);

    LogicDllUnloadStatus primary_status = LogicDllUnloadStatus::TimedOut;
    std::atomic<bool> primary_started{false};
    std::thread primary(
        [&]
        {
            primary_started.store(true, std::memory_order_release);
            primary_status = prepare_logic_dll_unload({}, std::chrono::seconds{2});
        }
    );
    while (!primary_started.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
    EXPECT_EQ(prepare_logic_dll_unload({}, std::chrono::milliseconds{40}), LogicDllUnloadStatus::InProgress);

    release_setter.store(true, std::memory_order_release);
    primary.join();
    EXPECT_EQ(primary_status, LogicDllUnloadStatus::SafeToUnload);

    auto registration = input::register_combo(
        input::ComboBinding{
            .name = "register_after_safe_drain",
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x42)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_TRUE(registration.has_value());
    EXPECT_EQ(input::Input::instance().remove_bindings_by_name("register_after_safe_drain", false), 1u);
    input::Input::instance().shutdown();

    std::error_code ec;
    std::filesystem::remove(ini_path, ec);
}

TEST(SessionHotReload, ParkedWatcherStartupCannotConsumeTheTypedDrainDeadline)
{
    input::Input::instance().shutdown();
    config::disable_auto_reload();
    config::clear();

    const std::filesystem::path ini_path =
        std::filesystem::temp_directory_path() /
        ("dmk_session_watcher_startup_drain_" + std::to_string(GetCurrentProcessId()) + ".ini");
    {
        std::ofstream file(ini_path);
        file << "[Drain]\nValue=1\n";
    }
    config::bind_int("Drain", "Value", "watcher startup drain", [](int) {}, 1);
    ASSERT_NO_THROW(config::load(ini_path.string()));

    s_watcher_startup_parked.store(false, std::memory_order_release);
    s_release_watcher_startup.store(false, std::memory_order_release);
    DetourModKit::detail::g_config_watcher_prehandshake_seam = &park_watcher_startup;

    config::AutoReloadStatus enable_status = config::AutoReloadStatus::StartFailed;
    std::thread enabler([&] { enable_status = config::enable_auto_reload(std::chrono::milliseconds{50}); });
    for (int i = 0; i < 1000 && !s_watcher_startup_parked.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    if (!s_watcher_startup_parked.load(std::memory_order_acquire))
    {
        s_release_watcher_startup.store(true, std::memory_order_release);
        enabler.join();
        DetourModKit::detail::g_config_watcher_prehandshake_seam = nullptr;
        config::disable_auto_reload();
        config::clear();
        std::error_code ec;
        std::filesystem::remove(ini_path, ec);
        FAIL() << "the watcher must reach the parked startup seam";
    }

    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(prepare_logic_dll_unload({}, std::chrono::milliseconds{40}), LogicDllUnloadStatus::TimedOut);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, std::chrono::milliseconds{500});

    s_release_watcher_startup.store(true, std::memory_order_release);
    enabler.join();
    DetourModKit::detail::g_config_watcher_prehandshake_seam = nullptr;
    EXPECT_EQ(enable_status, config::AutoReloadStatus::Started);

    EXPECT_EQ(prepare_logic_dll_unload({}, std::chrono::seconds{2}), LogicDllUnloadStatus::SafeToUnload);

    config::clear();
    std::error_code ec;
    std::filesystem::remove(ini_path, ec);
}

TEST(SessionHotReload, UnloadClearsConfigRegisteredItems)
{
    input::Input::instance().shutdown();
    config::clear();

    auto sentinel = std::make_shared<int>(0);
    EXPECT_EQ(sentinel.use_count(), 1L);

    config::bind_string(
        "SessionUnloadCfgClear",
        "Key",
        "session unload key",
        [sentinel](std::string_view) { /* keeps it alive */ },
        "default"
    );
    EXPECT_GE(sentinel.use_count(), 2L);

    on_logic_dll_unload({});

    EXPECT_EQ(sentinel.use_count(), 1L) << "the unload helper must drop the registry's captured setter copy";
}

TEST(SessionHotReload, UnloadStopsAutoReloadWatcher)
{
    input::Input::instance().shutdown();
    config::clear();
    config::disable_auto_reload();

    const auto ini_path = std::filesystem::temp_directory_path() /
                          ("test_session_unload_watcher_" + std::to_string(GetCurrentProcessId()) + ".ini");
    {
        std::ofstream ofs(ini_path);
        ofs << "[Section]\nKey=1\n";
    }
    config::bind_int("Section", "Key", "session_unload_watcher", [](int) {}, 1);
    EXPECT_NO_THROW(config::load(ini_path.string()));
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started);

    on_logic_dll_unload({});

    config::bind_int("Section", "Key", "session_unload_watcher_2", [](int) {}, 1);
    EXPECT_NO_THROW(config::load(ini_path.string()));
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started)
        << "on_logic_dll_unload must stop the auto-reload watcher; a survivor would report AlreadyRunning";

    config::disable_auto_reload();
    config::clear();
    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
}

// The catch-all overload drains bindings through a DIFFERENT engine path (clear_bindings) than the named overload
// (remove_bindings_by_name), so its config-clear, hold-release suppression, and watcher-stop need their own coverage.

TEST(SessionHotReload, UnloadAllSuppressesHoldReleaseCallbacks)
{
    input::Input::instance().shutdown();

    auto release_count = std::make_shared<std::atomic<int>>(0);

    (void)input::register_combo(
        input::ComboBinding{
            .name = std::string{"loader_lock_hold_all"},
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x49)}, {}}},
            .on_press = {},
            .on_state_change = [release_count](bool pressed) noexcept
            {
                if (!pressed)
                {
                    release_count->fetch_add(1, std::memory_order_relaxed);
                }
            },
        }
    );

    on_logic_dll_unload_all();

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_EQ(release_count->load(), 0)
        << "the catch-all helper must not invoke user release callbacks under a loader lock";
}

TEST(SessionHotReload, UnloadAllClearsConfigRegisteredItems)
{
    input::Input::instance().shutdown();
    config::clear();

    auto sentinel = std::make_shared<int>(0);
    EXPECT_EQ(sentinel.use_count(), 1L);

    config::bind_string(
        "SessionUnloadAllCfgClear",
        "Key",
        "session unload-all key",
        [sentinel](std::string_view) { /* keeps it alive */ },
        "default"
    );
    EXPECT_GE(sentinel.use_count(), 2L);

    on_logic_dll_unload_all();

    EXPECT_EQ(sentinel.use_count(), 1L) << "the catch-all helper must drop the registry's captured setter copy";
}

TEST(SessionHotReload, UnloadAllStopsAutoReloadWatcher)
{
    input::Input::instance().shutdown();
    config::clear();
    config::disable_auto_reload();

    const auto ini_path = std::filesystem::temp_directory_path() /
                          ("test_session_unload_all_watcher_" + std::to_string(GetCurrentProcessId()) + ".ini");
    {
        std::ofstream ofs(ini_path);
        ofs << "[Section]\nKey=1\n";
    }
    config::bind_int("Section", "Key", "session_unload_all_watcher", [](int) {}, 1);
    EXPECT_NO_THROW(config::load(ini_path.string()));
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started);

    on_logic_dll_unload_all();

    config::bind_int("Section", "Key", "session_unload_all_watcher_2", [](int) {}, 1);
    EXPECT_NO_THROW(config::load(ini_path.string()));
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started)
        << "on_logic_dll_unload_all must stop the auto-reload watcher; a survivor would report AlreadyRunning";

    config::disable_auto_reload();
    config::clear();
    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
}

// Drives on_logic_dll_unload through a real LoadLibrary / FreeLibrary cycle: the helper tears down bindings + config;
// hooks are caller-owned (a Hook handle unhooks when dropped), so a reloaded fixture can be strictly re-hooked.
namespace
{
    using ComputeDamageFn = int(__cdecl *)(int, int);
    using ComputeArmorFn = int(__cdecl *)(int, int);

    struct LoadedFixtureModule
    {
        HMODULE handle{nullptr};
        ComputeDamageFn compute_damage{nullptr};
        ComputeArmorFn compute_armor{nullptr};

        bool load()
        {
            handle = LoadLibraryA("hook_target_lib.dll");
            if (!handle)
            {
                return false;
            }
            compute_damage =
                reinterpret_cast<ComputeDamageFn>(reinterpret_cast<void *>(GetProcAddress(handle, "compute_damage")));
            compute_armor =
                reinterpret_cast<ComputeArmorFn>(reinterpret_cast<void *>(GetProcAddress(handle, "compute_armor")));
            return compute_damage != nullptr && compute_armor != nullptr;
        }

        void unload()
        {
            if (handle)
            {
                FreeLibrary(handle);
                handle = nullptr;
                compute_damage = nullptr;
                compute_armor = nullptr;
            }
        }

        ~LoadedFixtureModule() { unload(); }
    };

    int __cdecl fixture_detour_compute_damage(int, int)
    {
        return 0xC0DE;
    }
} // namespace

TEST(SessionHotReload, UnloadFixtureDllRoundTrip)
{
    input::Input::instance().shutdown();

    LoadedFixtureModule mod;
    ASSERT_TRUE(mod.load()) << "hook_target_lib.dll must be loadable";

    const Address target_damage{reinterpret_cast<std::uintptr_t>(mod.compute_damage)};

    {
        Result<Hook> r_damage = inline_at(
            InlineRequest{
                .name = "fixture_dll_damage",
                .target = target_damage,
            },
            &fixture_detour_compute_damage
        );
        ASSERT_TRUE(r_damage.has_value()) << r_damage.error().message();
        Hook h_damage = std::move(*r_damage);

        (void)input::register_combo(
            input::ComboBinding{
                .name = std::string{"fixture_dll_bind"},
                .trigger = input::Trigger::Press,
                .combos = {{{keyboard_key(0x4A)}, {}}},
                .on_press = []() {},
                .on_state_change = {},
            }
        );
        EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));
        ASSERT_TRUE(is_target_hooked(target_damage));

        const std::string_view bindings[] = {"fixture_dll_bind"};
        on_logic_dll_unload(bindings);

        EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
        EXPECT_TRUE(static_cast<bool>(h_damage));
        EXPECT_TRUE(is_target_hooked(target_damage));

        // The Hook handle drops here: RAII restores the fixture's prologue.
    }
    EXPECT_FALSE(is_target_hooked(target_damage)) << "dropping the handle must unhook the fixture export";

    // Reload and strictly re-hook: either already-hooked refusal would mean the prologue was not restored.
    mod.unload();
    ASSERT_TRUE(mod.load()) << "hook_target_lib.dll must reload cleanly";
    Result<Hook> reload = inline_at(
        InlineRequest{
            .name = "fixture_dll_damage_reloaded",
            .target = Address{reinterpret_cast<std::uintptr_t>(mod.compute_damage)},
            .options = Options{.fail_if_already_hooked = true},
        },
        &fixture_detour_compute_damage
    );
    EXPECT_TRUE(reload.has_value()) << "fresh strict hook on the reloaded fixture must succeed";
}

namespace DetourModKit
{
    // Defined in src/session.cpp; returns the current bootstrap shutdown event handle (the atomic load). Test-only, not
    // in any public header.
    extern HANDLE bootstrap_shutdown_event_for_test() noexcept;
    // Defined in src/session.cpp; arms a worker-launch failure before consumer state is published. Test-only.
    extern void bootstrap_fail_worker_launch_for_test(bool fail) noexcept;
    // Defined in src/session.cpp; runs the installed probe on the worker immediately before Session setup. Test-only.
    extern void bootstrap_pre_setup_probe_for_test(void (*probe)() noexcept) noexcept;
    // Defined in src/session.cpp; process-monotonic count of signals that reached SetEvent on an invalidated handle.
    extern std::uint64_t bootstrap_signals_on_invalid_event_for_test() noexcept;
} // namespace DetourModKit

namespace
{
    std::atomic<bool> s_pre_setup_entered{false};
    std::atomic<bool> s_release_pre_setup{false};

    void hold_bootstrap_before_setup() noexcept
    {
        s_pre_setup_entered.store(true, std::memory_order_release);
        while (!s_release_pre_setup.load(std::memory_order_acquire))
        {
            SwitchToThread();
        }
    }

    class BootstrapSetupHold
    {
    public:
        BootstrapSetupHold() noexcept
        {
            s_pre_setup_entered.store(false, std::memory_order_relaxed);
            s_release_pre_setup.store(false, std::memory_order_relaxed);
            DetourModKit::bootstrap_pre_setup_probe_for_test(&hold_bootstrap_before_setup);
        }

        ~BootstrapSetupHold() noexcept { release(); }

        BootstrapSetupHold(const BootstrapSetupHold &) = delete;
        BootstrapSetupHold &operator=(const BootstrapSetupHold &) = delete;
        BootstrapSetupHold(BootstrapSetupHold &&) = delete;
        BootstrapSetupHold &operator=(BootstrapSetupHold &&) = delete;

        [[nodiscard]] bool wait_until_entered(std::chrono::steady_clock::duration timeout) const noexcept
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (!s_pre_setup_entered.load(std::memory_order_acquire))
            {
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    return false;
                }
                std::this_thread::yield();
            }
            return true;
        }

        void release() noexcept
        {
            s_release_pre_setup.store(true, std::memory_order_release);
            DetourModKit::bootstrap_pre_setup_probe_for_test(nullptr);
        }
    };
} // namespace

// request_shutdown() may fire from any thread while a synchronous drain retires the shutdown event. Retirement closes
// admission and drains admitted signalers before closing the handle.
TEST(SessionShutdownEventRace, RequestShutdownRacingSynchronousDrainClosesRetiredEventSafely)
{
    Result<void> started = bootstrap(
        ModInfo{
            .name = "SESS_EVENT_RACE",
            .log_file = "sess_shutdown_event_race.log",
            .instance_mutex_prefix = "Sess_Shutdown_Event_Race_",
        },
        [](Session &) -> Result<void> { return {}; }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();

    // Capture the live event handle before the drain so closure can be checked after every admitted signaler exits.
    const HANDLE captured_event = bootstrap_shutdown_event_for_test();
    ASSERT_NE(captured_event, nullptr) << "bootstrap must have created the shutdown event";

    std::vector<std::jthread> hammerers;
    for (int t = 0; t < 4; ++t)
    {
        hammerers.emplace_back(
            [](std::stop_token stop_token) -> void
            {
                while (!stop_token.stop_requested())
                {
                    request_shutdown();
                }
            }
        );
    }

    std::this_thread::sleep_for(std::chrono::milliseconds{5});

    // The synchronous drain closes admission, joins the worker, waits for admitted signalers, and closes the event.
    const std::size_t leaks_before_drain = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Bootstrap);
    const std::uint64_t bad_signals_before = bootstrap_signals_on_invalid_event_for_test();
    Result<void> drained = shutdown_and_wait();
    ASSERT_TRUE(drained.has_value()) << drained.error().message();

    // Retirement has exactly two safe outcomes: it closes the handle only after observing every admitted signaler
    // leave SetEvent, or it gives up on the bounded spin and RETAINS the handle, recording the leak. A signaler
    // preempted between its admission and its fetch_sub can outlast the spin bound on a loaded machine, which is
    // precisely why the retain branch exists, so this case cannot demand "closed".
    //
    // Branch-independent watchdog for the use-after-close this whole mechanism exists to prevent: a signaler that
    // reaches SetEvent on an invalidated handle records it, so the hammer failing this way is caught whichever
    // retirement branch ran. It is a watchdog, not a discriminator: the unsafe window is a signaler's load-to-SetEvent
    // gap, which stress does not reliably hit, so a zero count is not by itself proof the close was ordered.
    EXPECT_EQ(bootstrap_signals_on_invalid_event_for_test(), bad_signals_before)
        << "the event was closed while an admitted request_shutdown() caller was still inside SetEvent";

    // Which branch ran is read from the leak counter, NOT GetHandleInformation on the captured value. Probing a handle
    // after a close is only meaningful while no other thread has allocated one: this process runs the whole GoogleTest
    // suite, and a peer test creating any kernel object can recycle the freed slot, so the probe reports a live handle
    // for a value this drain genuinely closed. Whether the close itself happens is pinned deterministically by
    // UncontendedDrainClosesTheShutdownEvent below, where the reader count is provably zero.
    const bool retained =
        diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Bootstrap) > leaks_before_drain;
    if (retained)
    {
        DWORD handle_flags = 0;
        EXPECT_TRUE(GetHandleInformation(captured_event, &handle_flags))
            << "retirement recorded a retained event but closed the handle anyway (GetLastError=" << GetLastError()
            << ")";
    }

    // The atomic was retired to null, so request_shutdown() is now a safe no-op, and the module handle was cleared.
    EXPECT_EQ(bootstrap_shutdown_event_for_test(), nullptr) << "drain must retire the event pointer to null";
    EXPECT_EQ(module_handle(), nullptr) << "drain must clear the module handle";
}

// The racing case above can legitimately take either retirement branch, so the close itself is pinned here with no
// concurrent signaler: the reader count is provably zero, so the bounded spin must observe it on its first look and
// close. A regression that always retained (or never retired the pointer) fails deterministically.
TEST(SessionShutdownEventRace, UncontendedDrainClosesTheShutdownEvent)
{
    Result<void> started = bootstrap(
        ModInfo{
            .name = "SESS_EVENT_QUIET",
            .log_file = "sess_shutdown_event_quiet.log",
            .instance_mutex_prefix = "Sess_Shutdown_Event_Quiet_",
        },
        [](Session &) -> Result<void> { return {}; }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();

    const HANDLE captured_event = bootstrap_shutdown_event_for_test();
    ASSERT_NE(captured_event, nullptr) << "bootstrap must have created the shutdown event";
    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Bootstrap);

    Result<void> drained = shutdown_and_wait();
    ASSERT_TRUE(drained.has_value()) << drained.error().message();

    DWORD handle_flags = 0;
    SetLastError(ERROR_SUCCESS);
    EXPECT_FALSE(GetHandleInformation(captured_event, &handle_flags))
        << "an uncontended drain must close the retired event rather than retain it";
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Bootstrap), leaks_before)
        << "an uncontended drain has nothing to retain, so it must record no leak";
    EXPECT_EQ(bootstrap_shutdown_event_for_test(), nullptr) << "drain must retire the event pointer to null";
}

// Repeated generations cross the retire-then-reopen boundary under a continuous request_shutdown() hammer. A
// straggling signaler may legitimately defer admission with SessionShutdownInProgress, but every generation must
// eventually start and drain. This stress case does not claim deterministic coverage of a signaler suspended inside
// the admission window; a corrupted access word instead manifests as a timeout at the test-process boundary.
TEST(SessionShutdownEventRace, ReBootstrapAcrossAHammeredDrainStaysSignalable)
{
    constexpr int GENERATIONS = 8;
    const ModInfo attach_info{
        .name = "SESS_EVENT_REBOOT",
        .log_file = "sess_shutdown_event_reboot.log",
    };

    std::vector<std::jthread> hammerers;
    for (int t = 0; t < 4; ++t)
    {
        hammerers.emplace_back(
            [](std::stop_token stop_token) -> void
            {
                while (!stop_token.stop_requested())
                {
                    request_shutdown();
                }
            }
        );
    }

    for (int generation = 0; generation < GENERATIONS; ++generation)
    {
        // A straggling signaler still registered on the retired word legitimately refuses the next attach, so retry
        // that one code rather than treating it as a failure.
        Result<void> started = std::unexpected(Error{ErrorCode::SessionShutdownInProgress, "test"});
        const auto admission_deadline = std::chrono::steady_clock::now() + kTestTimeout;
        while (std::chrono::steady_clock::now() < admission_deadline && !started)
        {
            {
                dmk_test::AllocFailScope no_alloc{0};
                started = bootstrap_attach(attach_info, &attach_entry_noop);
            }
            if (!started)
            {
                ASSERT_EQ(started.error().code, ErrorCode::SessionShutdownInProgress)
                    << "generation " << generation << ": " << started.error().message();
                std::this_thread::yield();
            }
        }
        ASSERT_TRUE(started.has_value()) << "generation " << generation
                                         << ": every attach attempt was refused: " << started.error().message();

        // The hammer may already have signalled this generation, so the worker can be gone; the drain still has to
        // report success and retire the slot for the next attach.
        Result<void> drained = shutdown_and_wait();
        ASSERT_TRUE(drained.has_value()) << "generation " << generation << ": " << drained.error().message();
    }

    EXPECT_EQ(bootstrap_shutdown_event_for_test(), nullptr) << "the last drain must retire the event pointer to null";
}

// A stress run cannot prove race freedom, so the runtime checks are paired with a compile-time lock-free requirement.
static_assert(std::atomic<ModuleHandle>::is_always_lock_free, "module identity must be a lock-free atomic pointer.");

class SessionLifecycleContext : public SessionBootstrapTest
{
};

TEST_F(SessionLifecycleContext, ModuleIdentityIsLockFreeAtomic)
{
    // Runtime companion to the static gate above, following the AGENTS.md is_lock_free() probe convention.
    std::atomic<ModuleHandle> probe{nullptr};
    EXPECT_TRUE(probe.is_lock_free());
}

TEST_F(SessionLifecycleContext, GenerationAdvancesOnlyOnAdmittedStart)
{
    const std::uint64_t before = DetourModKit::detail::lifecycle().generation();

    {
        Result<Session> first = Session::start(
            ModInfo{
                .name = "GEN_A",
                .log_file = "sess_ctx_gen.log",
            }
        );
        ASSERT_TRUE(first.has_value()) << first.error().message();
        EXPECT_EQ(DetourModKit::detail::lifecycle().generation(), before + 1) << "an admitted start opens a new epoch";
        EXPECT_EQ(DetourModKit::detail::lifecycle().state(), DetourModKit::detail::LifecycleState::Running);

        // A second start while one is Running is rejected and must not advance the generation.
        Result<Session> second = Session::start(
            ModInfo{
                .name = "GEN_B",
            }
        );
        ASSERT_FALSE(second.has_value());
        EXPECT_EQ(second.error().code, ErrorCode::SessionAlreadyActive);
        EXPECT_EQ(DetourModKit::detail::lifecycle().generation(), before + 1) << "a rejected start opens no epoch";
    }

    // ~Session ran the ordered teardown, so the slot is Stopped again and a fresh start opens the next epoch.
    EXPECT_EQ(DetourModKit::detail::lifecycle().state(), DetourModKit::detail::LifecycleState::Stopped);
    Result<Session> third = Session::start(
        ModInfo{
            .name = "GEN_C",
            .log_file = "sess_ctx_gen.log",
        }
    );
    ASSERT_TRUE(third.has_value()) << third.error().message();
    EXPECT_EQ(DetourModKit::detail::lifecycle().generation(), before + 2);
}

TEST_F(SessionLifecycleContext, SynchronousStartLeavesLoaderContextNormal)
{
    Result<Session> session = Session::start(
        ModInfo{
            .name = "CTX_SYNC",
            .log_file = "sess_ctx_sync.log",
        }
    );
    ASSERT_TRUE(session.has_value()) << session.error().message();
    // A synchronously-hosted session was never inside a loader callback, whatever a prior bootstrap cycle left behind.
    EXPECT_EQ(DetourModKit::detail::lifecycle().loader_context(), DetourModKit::detail::LoaderContext::Normal);
}

TEST_F(SessionLifecycleContext, BootstrapRetiresAttachOnTheWorkerAndRetiresTheDrainPhaseAfterward)
{
    CallbackSignals sig;
    Result<void> started = bootstrap(
        ModInfo{
            .name = "CTX_BOOT",
            .log_file = "sess_ctx_boot.log",
        },
        [&sig](Session &) -> Result<void>
        {
            sig.signal_ready();
            return {};
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;
    ASSERT_TRUE(sig.wait_for_ready(kTestTimeout));

    // The worker runs off the loader lock by construction, so it retires the Attach phase to Normal before adopting
    // the Session. Any leaf teardown it reaches is therefore authorized to block rather than inheriting the attach
    // veto. Observing Attach itself requires a real DllMain and belongs to the subprocess loader host.
    EXPECT_EQ(DetourModKit::detail::lifecycle().loader_context(), DetourModKit::detail::LoaderContext::Normal);
    EXPECT_TRUE(DetourModKit::detail::blocking_teardown_permitted())
        << "the worker's own teardown must be authorized to join its subsystem threads";

    // The synchronous control-plane handshake publishes the one unload phase permitted to block, then retires it with
    // everything else the drain retires. Leaving ExplicitDrain published would outlive its drainer and let a later
    // static destructor treat a false loader-lock probe as permission to block. A real DllMain FreeLibrary publishes
    // LoaderDetach instead; ProcessExit requires subprocess isolation because Windows terminates the peer worker
    // before issuing that notification.
    Result<void> drained = shutdown_and_wait();
    ASSERT_TRUE(drained.has_value()) << drained.error().message();
    m_bootstrapped = false;
    EXPECT_EQ(DetourModKit::detail::lifecycle().loader_context(), DetourModKit::detail::LoaderContext::Normal)
        << "a completed drain must retire the phase it published";
    EXPECT_EQ(module_handle(), nullptr);
}

// The published phase is one process-global word that gates every later teardown, so an attach that did not survive
// must not leave a non-blocking phase behind. A consumer whose DllMain declines the load and returns TRUE keeps using
// the library off the loader lock, and a stranded Attach would silently turn every subsequent join into an
// abandon-and-leak: no cache cleanup thread, hooks released with their detours still installed, and an abandoned async
// writer. This covers the gate rollback; the worker-launch failure that reaches unwind_bootstrap is covered by
// AttachFailureBeforePublicationRollsBackCompletelyAndPermitsRetry.
TEST_F(SessionLifecycleContext, FailedAttachGateLeavesNoNonBlockingPhasePublished)
{
    const std::string_view prefix = "Sess_Ctx_Failed_Attach_";
    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, instance_mutex_name(prefix).c_str());
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u) << "the instance name collided before the test could pre-own it";

    Result<void> started = bootstrap(
        ModInfo{
            .name = "CTX_FAILED_ATTACH",
            .log_file = "sess_ctx_failed_attach.log",
            .instance_mutex_prefix = prefix,
        },
        [](Session &) -> Result<void> { return {}; }
    );
    CloseHandle(pre_owned);

    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error().code, ErrorCode::InstanceAlreadyRunning);

    EXPECT_EQ(DetourModKit::detail::lifecycle().loader_context(), DetourModKit::detail::LoaderContext::Normal);
    EXPECT_TRUE(DetourModKit::detail::blocking_teardown_permitted())
        << "a failed attach must not fail-close teardown for the rest of the process";
}

TEST_F(SessionLifecycleContext, BootstrapDefersLoggerAndSessionSetupToTheWorker)
{
    const std::filesystem::path log_path{"sess_ctx_deferred_setup.log"};
    std::error_code remove_error;
    (void)std::filesystem::remove(log_path, remove_error);

    BootstrapSetupHold setup_hold;
    Result<void> started = bootstrap(
        ModInfo{
            .name = "CTX_DEFERRED",
            .log_file = log_path.string(),
        },
        [this](Session &) -> Result<void>
        {
            m_sig.signal_ready();
            return {};
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;
    ASSERT_TRUE(setup_hold.wait_until_entered(kTestTimeout));

    EXPECT_EQ(DetourModKit::detail::lifecycle().state(), DetourModKit::detail::LifecycleState::Starting);
    EXPECT_EQ(DetourModKit::detail::lifecycle().loader_context(), DetourModKit::detail::LoaderContext::Attach);
    EXPECT_FALSE(std::filesystem::exists(log_path)) << "logger/file setup ran in bootstrap instead of the held worker";

    setup_hold.release();
    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout));
    EXPECT_EQ(DetourModKit::detail::lifecycle().state(), DetourModKit::detail::LifecycleState::Running);
}

TEST_F(SessionLifecycleContext, TypedLogicDllPreparationCannotAuthorizeUnderLoaderLock)
{
    const dmk_test::ForcedLoaderProbe probe{&dmk_test::loader_lock_always_held};
    DetourModKit::detail::lifecycle().set_loader_context(DetourModKit::detail::LoaderContext::Normal);
    EXPECT_EQ(prepare_logic_dll_unload({}), LogicDllUnloadStatus::LoaderLock);
}

// The heuristic may only ever veto blocking teardown. Neither half authorizes on its own, so all combinations are
// pinned. The forced-false + LoaderDetach row is the discriminator: using a bare `!is_loader_lock_held()` decision
// would let a loader-callback teardown join and deadlock the host.
TEST_F(SessionLifecycleContext, LoaderLockHeuristicVetoesButNeverAuthorizesBlockingTeardown)
{
    using DetourModKit::detail::blocking_teardown_permitted;
    using DetourModKit::detail::lifecycle;
    using DetourModKit::detail::LoaderContext;

    {
        const dmk_test::ForcedLoaderProbe probe{&dmk_test::loader_lock_never_held};
        lifecycle().set_loader_context(LoaderContext::Normal);
        EXPECT_TRUE(blocking_teardown_permitted()) << "an authorizing context with no veto must permit blocking";

        lifecycle().set_loader_context(LoaderContext::ExplicitDrain);
        EXPECT_TRUE(blocking_teardown_permitted()) << "the off-loader drain handshake is the one unload phase that may "
                                                      "block";

        // The discriminating rows: a false probe must NOT rescue a context that forbids blocking.
        lifecycle().set_loader_context(LoaderContext::LoaderDetach);
        EXPECT_FALSE(blocking_teardown_permitted())
            << "a heuristic false authorized blocking teardown inside a loader callback";

        lifecycle().set_loader_context(LoaderContext::Attach);
        EXPECT_FALSE(blocking_teardown_permitted()) << "attach must not permit blocking even with a free probe";

        lifecycle().set_loader_context(LoaderContext::ProcessExit);
        EXPECT_FALSE(blocking_teardown_permitted()) << "process exit must not permit blocking even with a free probe";
    }

    {
        // The veto direction: an authorizing context is still overridden by a held/indeterminate probe.
        const dmk_test::ForcedLoaderProbe probe{&dmk_test::loader_lock_always_held};
        lifecycle().set_loader_context(LoaderContext::Normal);
        EXPECT_FALSE(blocking_teardown_permitted()) << "a held probe must veto an otherwise authorizing context";

        lifecycle().set_loader_context(LoaderContext::ExplicitDrain);
        EXPECT_FALSE(blocking_teardown_permitted()) << "a held probe must veto the drain handshake too";
    }

    // The seam is cleared, so the real probe governs again and an ordinary test thread may block.
    EXPECT_EQ(DetourModKit::detail::g_loader_lock_override, nullptr);
}

// The loader context is one process-global word describing the DllMain thread's phase, but a bare FreeLibrary
// publishes LoaderDetach and RETURNS: the worker then runs the ordered teardown it was created to run, on a thread in
// no loader callback that still holds a counted module reference. session.hpp promises that teardown joins cleanly, so
// the worker carries its own authorization. Without it, the misuse path abandons every leaf instead of joining, and a
// load/unload cycle strands a poll thread, a watcher, a cleanup thread, and an open log file each time.
//
// The paired negative row lives in LoaderLockHeuristicVetoesButNeverAuthorizesBlockingTeardown, which pins the same
// LoaderDetach + free-probe combination to false on a non-worker thread. Together they show the clause admits the
// worker and nothing else.
TEST_F(SessionLifecycleContext, TheBootstrapWorkerStaysAuthorizedThroughAnUnloadPhase)
{
    std::atomic<std::uint32_t> observed_worker_tid{0};
    std::atomic<bool> identity_published{false};
    std::atomic<bool> worker_authorized{false};

    Result<void> started = bootstrap(
        ModInfo{
            .name = "CTX_WORKER_AUTH",
            .log_file = "sess_ctx_worker_auth.log",
        },
        [&](Session &) -> Result<void>
        {
            // Close the forced-probe seam before releasing the control thread. The
            // override is a plain pointer the seam requires to be set and cleared while
            // no peer thread reads it, and the control thread's shutdown_and_wait() reads
            // it through is_loader_lock_held().
            {
                const dmk_test::ForcedLoaderProbe probe{&dmk_test::loader_lock_never_held};
                DetourModKit::detail::lifecycle().set_loader_context(DetourModKit::detail::LoaderContext::LoaderDetach);
                observed_worker_tid.store(static_cast<std::uint32_t>(GetCurrentThreadId()), std::memory_order_relaxed);
                identity_published.store(
                    DetourModKit::detail::lifecycle().is_worker_thread(),
                    std::memory_order_relaxed
                );
                worker_authorized.store(DetourModKit::detail::blocking_teardown_permitted(), std::memory_order_relaxed);
            }
            m_sig.signal_ready();
            return {};
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;
    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout));

    EXPECT_TRUE(identity_published.load(std::memory_order_acquire))
        << "the worker must publish its identity before any consumer code runs on it";
    EXPECT_TRUE(worker_authorized.load(std::memory_order_acquire))
        << "a DllMain-thread unload phase revoked the worker's authorization to drain its own subsystems";
    // The negative half: authorization is an identity, not a process-global flag. This row fails if is_worker_thread()
    // ever stops comparing against the calling thread.
    EXPECT_FALSE(DetourModKit::detail::lifecycle().is_worker_thread())
        << "the control thread must never inherit the worker's authorization";

    Result<void> drained = shutdown_and_wait();
    ASSERT_TRUE(drained.has_value()) << drained.error().message();
    m_bootstrapped = false;

    // Read the published word rather than is_worker_thread(): the latter compares against the CALLING thread, so on
    // this thread it is false whether or not the identity was ever retired. Only the word itself shows the retirement,
    // and it must be retired because the OS recycles thread ids: an unrelated consumer thread handed the dead worker's
    // id would inherit both its blocking authorization and its refused self-drain.
    EXPECT_NE(observed_worker_tid.load(std::memory_order_acquire), 0u);
    EXPECT_EQ(DetourModKit::detail::lifecycle().worker_thread_id(), 0u)
        << "the retired identity must not survive its worker, whose id the OS may recycle";
}

TEST_F(SessionLifecycleContext, SynchronousDrainHonorsTheLoaderLockVeto)
{
    Result<void> started = bootstrap(
        ModInfo{
            .name = "CTX_DRAIN_VETO",
            .log_file = "sess_ctx_drain_veto.log",
        },
        [this](Session &) -> Result<void>
        {
            m_sig.signal_ready();
            return {};
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;
    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout));

    {
        const dmk_test::ForcedLoaderProbe probe{&dmk_test::loader_lock_always_held};
        Result<void> refused = shutdown_and_wait();
        ASSERT_FALSE(refused.has_value());
        EXPECT_EQ(refused.error().code, ErrorCode::SessionShutdownWouldBlock);
        EXPECT_NE(module_handle(), nullptr) << "a refused drain must leave the active bootstrap reachable for retry";
    }

    Result<void> drained = shutdown_and_wait();
    ASSERT_TRUE(drained.has_value()) << drained.error().message();
    m_bootstrapped = false;
    EXPECT_EQ(module_handle(), nullptr);
}

// shutdown_and_wait() waits on the bootstrap worker's thread handle, so a call made ON that worker (the natural place
// for a mod to retire itself: from on_ready, or from a hook/config callback the worker's own teardown reaches) would
// wait for the calling thread to exit and hang forever. It must recognize its own thread and refuse instead.
TEST_F(SessionLifecycleContext, SynchronousDrainFromTheWorkerThreadIsRefusedInsteadOfSelfWaiting)
{
    std::atomic<bool> refused_correctly{false};
    std::atomic<int> observed_code{-1};

    Result<void> started = bootstrap(
        ModInfo{
            .name = "CTX_SELF_DRAIN",
            .log_file = "sess_ctx_self_drain.log",
        },
        [this, &refused_correctly, &observed_code](Session &) -> Result<void>
        {
            // Runs on the bootstrap worker. A self-wait here would never return.
            Result<void> self = shutdown_and_wait();
            refused_correctly.store(!self.has_value(), std::memory_order_release);
            if (!self)
            {
                observed_code.store(static_cast<int>(self.error().code), std::memory_order_release);
            }
            m_sig.signal_ready();
            return {};
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;

    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout))
        << "on_ready never completed: shutdown_and_wait() self-waited on the worker thread";
    EXPECT_TRUE(refused_correctly.load()) << "a drain requested from the worker thread must fail, not succeed";
    EXPECT_EQ(observed_code.load(), static_cast<int>(ErrorCode::SessionShutdownWouldBlock));

    // The refusal must leave the bootstrap intact, so an ordinary control thread can still drain it.
    Result<void> drained = shutdown_and_wait();
    ASSERT_TRUE(drained.has_value()) << drained.error().message();
    m_bootstrapped = false;
    EXPECT_EQ(module_handle(), nullptr);
}

// A drain nulls the worker handle and the shutdown event well before it has finished retiring the init callback and
// the module identity, so admission cannot be decided from those handles: a bootstrap admitted in that tail publishes
// a whole new generation that the still-running drainer then destroys: it frees the new callback while the new
// worker may be invoking it, nulls the identity of a live session, and overwrites the new Ready with Drained, leaving
// that worker parked forever. The bootstrap state is therefore the sole admission authority, and it names the entire
// drain. Held here at its widest point (the drainer blocked on a worker parked inside on_ready) because that is the
// only part of the window a test can pin deterministically; the tail is the same state.
TEST_F(SessionLifecycleContext, BootstrapDuringADrainIsRefusedRatherThanAdmittedIntoTheRetirement)
{
    CallbackSignals release_worker;
    Result<void> started = bootstrap(
        ModInfo{
            .name = "CTX_ADMIT",
            .log_file = "sess_ctx_admit.log",
        },
        [this, &release_worker](Session &) -> Result<void>
        {
            m_sig.signal_ready();
            // Park the worker so the drainer below is certainly still inside its drain
            // while the racing bootstrap is attempted.
            (void)release_worker.wait_for_ready(kTestTimeout);
            return {};
        }
    );
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;
    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout));

    std::thread drainer{[]() -> void { (void)shutdown_and_wait(); }};

    // The drainer publishes ExplicitDrain immediately after claiming the state, so this is an observable "the drain
    // owns the slot" edge rather than a sleep. Every check below is non-fatal and the worker is released
    // unconditionally, because returning early here would destroy a joinable thread and abort the whole binary
    // instead of reporting a failure.
    const auto deadline = std::chrono::steady_clock::now() + kTestTimeout;
    bool drain_claimed_slot{false};
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (DetourModKit::detail::lifecycle().loader_context() == DetourModKit::detail::LoaderContext::ExplicitDrain)
        {
            drain_claimed_slot = true;
            break;
        }
        std::this_thread::yield();
    }
    EXPECT_TRUE(drain_claimed_slot) << "the drain never claimed the bootstrap state";

    const ModInfo racing_info{
        .name = "CTX_ADMIT_2",
    };
    Result<void> racing;
    {
        dmk_test::AllocFailScope no_alloc{0};
        racing = bootstrap_attach(racing_info, &attach_entry_noop);
    }
    EXPECT_FALSE(racing.has_value()) << "a bootstrap admitted during a drain publishes a generation the drainer frees";
    if (!racing)
    {
        EXPECT_EQ(racing.error().code, ErrorCode::SessionShutdownInProgress)
            << "admission was decided from the bootstrap handles, which the drain clears before it is done with them";
    }

    release_worker.signal_ready();
    drainer.join();
    m_bootstrapped = false;
    EXPECT_EQ(module_handle(), nullptr);

    // The refusal released nothing: the slot is free again for the next generation.
    Result<void> next = bootstrap(
        ModInfo{
            .name = "CTX_ADMIT_3",
            .log_file = "sess_ctx_admit.log",
        },
        [this](Session &) -> Result<void>
        {
            m_sig.signal_ready();
            return {};
        }
    );
    ASSERT_TRUE(next.has_value()) << next.error().message();
    m_bootstrapped = true;
}

// Worker launch is the last fallible attach operation. A failure must close the preflight mutex and release both state
// machines without publishing the Session or callback, so the same instance prefix can be retried immediately.
TEST_F(SessionLifecycleContext, AttachFailureBeforePublicationRollsBackCompletelyAndPermitsRetry)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    DetourModKit::bootstrap_fail_worker_launch_for_test(true);
    Result<void> failed = bootstrap(
        ModInfo{
            .name = "ATTACH_ROLLBACK",
            .game_process_name = exe_name,
            .instance_mutex_prefix = "Sess_Attach_Rollback_",
        },
        [](Session &) -> Result<void> { return {}; }
    );
    DetourModKit::bootstrap_fail_worker_launch_for_test(false);

    ASSERT_FALSE(failed.has_value()) << "the seam must have failed worker launch";
    EXPECT_EQ(failed.error().code, ErrorCode::SystemCallFailed);
    EXPECT_EQ(module_handle(), nullptr) << "a failed attach must not leave the module identity published";
    EXPECT_EQ(DetourModKit::detail::lifecycle().state(), DetourModKit::detail::LifecycleState::Stopped)
        << "the failed generation must release the single-session slot";
    EXPECT_EQ(DetourModKit::detail::lifecycle().loader_context(), DetourModKit::detail::LoaderContext::Normal)
        << "the unwound attach must retire the phase it published, or every later teardown fail-closes";

    // A retained mutex reports InstanceAlreadyRunning; a terminal bootstrap slot reports SessionShutdownUnavailable.
    // Only a complete pre-publication rollback lets the same prefix load again.
    Result<void> retried = bootstrap(
        ModInfo{
            .name = "ATTACH_ROLLBACK",
            .log_file = "sess_attach_rollback.log",
            .game_process_name = exe_name,
            .instance_mutex_prefix = "Sess_Attach_Rollback_",
        },
        [this](Session &) -> Result<void>
        {
            m_sig.signal_ready();
            return {};
        }
    );
    ASSERT_TRUE(retried.has_value()) << "a failed attach left the process unable to load: "
                                     << retried.error().message();
    m_bootstrapped = true;
    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout));
    EXPECT_NE(module_handle(), nullptr);
}

// bootstrap_detach(nullptr) moves the process-wide bootstrap slot to the terminal Detached state, which nothing
// reverses. That case cannot share this process, so it owns its own proof host:
// Lifecycle.DetachAfterDrainRevokesBlockingAuthorization in tests/lifecycle/session_detach_terminal.cpp.

TEST_F(SessionLifecycleContext, ConcurrentModuleHandleReadsDuringDetachSeeCurrentOrNull)
{
    // The one identity module_handle() may ever publish here: the test binary that links DetourModKit statically.
    HMODULE expected = nullptr;
    ASSERT_TRUE(GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&current_exe_basename),
        &expected
    ));
    ASSERT_NE(expected, nullptr);

    std::atomic<bool> saw_bad{false};
    std::vector<std::jthread> readers;
    for (int i = 0; i < 4; ++i)
    {
        readers.emplace_back(
            [&saw_bad, expected](std::stop_token stop_token) -> void
            {
                while (!stop_token.stop_requested())
                {
                    const ModuleHandle handle = module_handle();
                    if (handle != nullptr && handle != expected)
                    {
                        saw_bad.store(true, std::memory_order_release);
                    }
                }
            }
        );
    }

    // Drive repeated bootstrap generations while the readers hammer the getter across each synchronous drain.
    for (int cycle = 0; cycle < 8; ++cycle)
    {
        CallbackSignals sig;
        Result<void> started = bootstrap(
            ModInfo{
                .name = "CTX_RACE",
                .log_file = "sess_ctx_race.log",
            },
            [&sig](Session &) -> Result<void>
            {
                sig.signal_ready();
                return {};
            }
        );
        ASSERT_TRUE(started.has_value()) << "cycle " << cycle << ": " << started.error().message();
        m_bootstrapped = true;
        ASSERT_TRUE(sig.wait_for_ready(kTestTimeout)) << "cycle " << cycle;
        EXPECT_EQ(module_handle(), expected) << "cycle " << cycle;
        Result<void> drained = shutdown_and_wait();
        ASSERT_TRUE(drained.has_value()) << "cycle " << cycle << ": " << drained.error().message();
        m_bootstrapped = false;
        EXPECT_EQ(module_handle(), nullptr) << "cycle " << cycle;
    }

    for (auto &reader : readers)
    {
        reader.request_stop();
    }
    readers.clear();

    EXPECT_FALSE(saw_bad.load()) << "a module_handle() reader observed a value that was neither the current identity "
                                    "nor null";
    EXPECT_EQ(module_handle(), nullptr);
    EXPECT_EQ(DetourModKit::detail::lifecycle().state(), DetourModKit::detail::LifecycleState::Stopped);
}
