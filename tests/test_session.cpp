#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <type_traits>

#include <windows.h>

#include "DetourModKit/dmk.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace std::chrono_literals;
using DetourModKit::keyboard_key;

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
        return Session::start(ModInfo{.name = name, .log_file = log_file});
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

// ~Session runs the ordered teardown from loader-lock / DLL_PROCESS_DETACH paths where an escaping exception would
// terminate the host. Every subsystem teardown it invokes is noexcept, so pin the no-throw destructor at compile time.
static_assert(std::is_nothrow_destructible_v<Session>,
              "~Session must be noexcept so teardown cannot throw into a host unwinding under the loader lock.");
static_assert(!std::is_copy_constructible_v<Session>, "Session is move-only.");
static_assert(std::is_nothrow_move_constructible_v<Session>, "Session move must be noexcept for the RAII contract.");
static_assert(std::is_nothrow_move_assignable_v<Session>, "Session move-assign must be noexcept.");

// --- ModInfo + free-function preconditions ------------------------------------------------------------------------

TEST(SessionModInfo, Defaults)
{
    const ModInfo info{};
    EXPECT_TRUE(info.name.empty());
    EXPECT_TRUE(info.log_file.empty());
    EXPECT_TRUE(info.game_process_name.empty());
    EXPECT_TRUE(info.instance_mutex_prefix.empty());
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

// --- Session::start gating ----------------------------------------------------------------------------------------

TEST(SessionStart, ProcessGateMismatchReturnsProcessMismatch)
{
    Result<Session> r = Session::start(ModInfo{.name = "SESS_TEST",
                                               .log_file = "sess_test_procgate.log",
                                               .game_process_name = "DefinitelyNotTheCurrentProcess_xyz.exe",
                                               .instance_mutex_prefix = "Sess_Test_Mutex_ProcGate_"});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::ProcessMismatch);
}

TEST(SessionStart, EmptyProcessNamePassesGateButMutexCollisionFails)
{
    const std::string_view prefix = "Sess_Test_Mutex_EmptyGate_";
    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, instance_mutex_name(prefix).c_str());
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u);

    Result<Session> r = Session::start(
        ModInfo{.name = "SESS_TEST", .log_file = "sess_test_emptygate.log", .instance_mutex_prefix = prefix});
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
    Result<Session> r = Session::start(ModInfo{.name = "SESS_TEST",
                                               .log_file = "sess_test_mutex.log",
                                               .game_process_name = exe_name,
                                               .instance_mutex_prefix = prefix});
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
    Result<Session> r = Session::start(ModInfo{.name = "SESS_TEST",
                                               .log_file = "sess_test_mutex_long.log",
                                               .game_process_name = exe_name,
                                               .instance_mutex_prefix = prefix});
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
        Result<Session> r = Session::start(ModInfo{.name = "SESS_TEST",
                                                   .log_file = "sess_test_cycle.log",
                                                   .game_process_name = current_exe_basename(),
                                                   .instance_mutex_prefix = "Sess_Test_Mutex_Cycle_"});
        ASSERT_TRUE(r.has_value()) << "cycle " << cycle << ": " << r.error().message();
        // Destroyed at loop-end: teardown releases the guard + mutex for the next cycle.
    }
}

// --- Move + inertness ---------------------------------------------------------------------------------------------

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

// --- Ordered teardown (the ~Session body) -------------------------------------------------------------------------

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
        Result<Session> r = Session::start(ModInfo{.name = "SESS_TEST", .log_file = log_path.string()});
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
        (void)input::register_combo(input::ComboBinding{.name = std::string{"session_test_key"},
                                                        .trigger = input::Trigger::Press,
                                                        .combos = {{{keyboard_key(0x41)}, {}}},
                                                        .on_press = []() {},
                                                        .on_state_change = {}});
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
            "SessionAbandonCfg", "Key", "session abandon key", [sentinel](std::string_view) { /* keeps it alive */ },
            "default");
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
        Result<Hook> r = inline_at(InlineRequest{.name = "session_raii_hook", .target = target}, &session_raii_detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);

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

// --- Async bootstrap / bootstrap_detach ---------------------------------------------------------------------------

class SessionBootstrapTest : public ::testing::Test
{
protected:
    CallbackSignals m_sig;
    bool m_bootstrapped{false};

    void TearDown() override
    {
        if (m_bootstrapped)
        {
            // Off the loader lock, bootstrap_detach(NULL) joins the worker and runs the ordered teardown, leaving a
            // clean slate for the next test.
            request_shutdown();
            bootstrap_detach(nullptr);
        }
    }
};

TEST_F(SessionBootstrapTest, HappyPathBootstrapRunsOnReady)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Result<void> started = bootstrap(ModInfo{.name = "SESS_TEST",
                                             .log_file = "sess_test_happy.log",
                                             .game_process_name = exe_name,
                                             .instance_mutex_prefix = "Sess_Test_Mutex_Happy_"},
                                     [this](Session &) -> Result<void>
                                     {
                                         m_sig.signal_ready();
                                         return {};
                                     });
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;

    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout)) << "on_ready did not complete within timeout";
    EXPECT_EQ(m_sig.ready_calls.load(), 1);
    EXPECT_NE(module_handle(), nullptr);

    // The auto-captured handle must be the module that owns the DetourModKit code (here the test executable, which
    // links DetourModKit statically). Resolve it independently with the identity-only UNCHANGED_REFCOUNT flavor -- the
    // same non-owning capture bootstrap uses, which must not take a reference on the module -- and require a match.
    constexpr DWORD identity_flags =
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    HMODULE expected_module = nullptr;
    ASSERT_TRUE(GetModuleHandleExW(identity_flags, reinterpret_cast<LPCWSTR>(&current_exe_basename), &expected_module));
    EXPECT_EQ(module_handle(), expected_module);

    // A second bootstrap while the worker is live is rejected.
    Result<void> second = bootstrap(ModInfo{.name = "SESS_TEST"}, [](Session &) -> Result<void> { return {}; });
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::SessionAlreadyActive);
    EXPECT_EQ(m_sig.ready_calls.load(), 1);
}

TEST_F(SessionBootstrapTest, ProcessGateMismatchDoesNotSpawnWorker)
{
    Result<void> started = bootstrap(ModInfo{.name = "SESS_TEST",
                                             .log_file = "sess_test_bootstrap_gate.log",
                                             .game_process_name = "DefinitelyNotTheCurrentProcess_boot.exe",
                                             .instance_mutex_prefix = "Sess_Test_Mutex_BootGate_"},
                                     [this](Session &) -> Result<void>
                                     {
                                         m_sig.signal_ready();
                                         return {};
                                     });
    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error().code, ErrorCode::ProcessMismatch);
    EXPECT_EQ(module_handle(), nullptr) << "a failed bootstrap must roll back the captured module";
    EXPECT_EQ(m_sig.ready_calls.load(), 0) << "on_ready must not run when the gate rejects the process";
}

TEST(SessionBootstrapReentrancy, BootstrapDetachCyclesRepeat)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    for (int cycle = 1; cycle <= 2; ++cycle)
    {
        CallbackSignals sig;
        Result<void> started = bootstrap(ModInfo{.name = "SESS_TEST",
                                                 .log_file = "sess_test_reentrant.log",
                                                 .game_process_name = exe_name,
                                                 .instance_mutex_prefix = "Sess_Test_Mutex_Reentrant_"},
                                         [&sig](Session &) -> Result<void>
                                         {
                                             sig.signal_ready();
                                             return {};
                                         });
        ASSERT_TRUE(started.has_value()) << "cycle " << cycle << ": " << started.error().message();
        ASSERT_TRUE(sig.wait_for_ready(kTestTimeout)) << "cycle " << cycle << ": on_ready did not complete";
        EXPECT_EQ(sig.ready_calls.load(), 1) << "cycle " << cycle;

        // Off the loader lock: bootstrap_detach joins the worker and runs the ordered teardown, clearing the statics so
        // the next cycle's bootstrap succeeds.
        bootstrap_detach(nullptr);
        EXPECT_EQ(module_handle(), nullptr) << "cycle " << cycle << ": detach must clear the module handle";
    }
}

TEST_F(SessionBootstrapTest, OnReadyExceptionIsCaught)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Result<void> started = bootstrap(ModInfo{.name = "SESS_TEST",
                                             .log_file = "sess_test_throws.log",
                                             .game_process_name = exe_name,
                                             .instance_mutex_prefix = "Sess_Test_Mutex_Throws_"},
                                     [this](Session &) -> Result<void>
                                     {
                                         m_sig.signal_ready();
                                         throw std::runtime_error("on_ready failure");
                                     });
    ASSERT_TRUE(started.has_value()) << started.error().message();
    m_bootstrapped = true;

    // The worker catches the throw; the process survives and teardown still runs at detach.
    ASSERT_TRUE(m_sig.wait_for_ready(kTestTimeout));
    EXPECT_EQ(m_sig.ready_calls.load(), 1);
}

// --- Hot-reload helpers -------------------------------------------------------------------------------------------

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
} // namespace

// on_logic_dll_unload tears down the named bindings and the config registry; it does NOT touch hooks (caller-owned).
TEST(SessionHotReload, UnloadTearsDownBindingsButHooksAreCallerOwned)
{
    input::Input::instance().shutdown();

    const Address target{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    Result<Hook> r = inline_at(InlineRequest{.name = "logic_unload_hook", .target = target}, &logic_unload_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(is_target_hooked(target));

    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_binding"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    const std::string_view bindings[] = {"logic_unload_binding"};
    on_logic_dll_unload(bindings);

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
    Result<Hook> r = inline_at(InlineRequest{.name = "logic_unload_idem", .target = target}, &logic_unload_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_idem_bind"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});

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

    Result<Hook> r_add =
        inline_at(InlineRequest{.name = "logic_unload_all_add", .target = target_add}, &logic_unload_detour_add);
    ASSERT_TRUE(r_add.has_value()) << r_add.error().message();
    Hook h_add = std::move(*r_add);

    Result<Hook> r_sub =
        inline_at(InlineRequest{.name = "logic_unload_all_sub", .target = target_sub}, &logic_unload_detour_sub);
    ASSERT_TRUE(r_sub.has_value()) << r_sub.error().message();
    Hook h_sub = std::move(*r_sub);

    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_all_bind_a"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x43)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});
    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_all_bind_b"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x44)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});
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

    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_all_idem_bind"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x45)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});

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
        input::ComboBinding{.name = std::string{"loader_lock_hold"},
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
                            }});
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    const std::string_view bindings[] = {"loader_lock_hold"};
    on_logic_dll_unload(bindings);

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_EQ(release_count->load(), 0)
        << "hot-reload helpers must not invoke user release callbacks under a loader lock";
    EXPECT_EQ(press_count->load(), 0);
}

TEST(SessionHotReload, UnloadClearsConfigRegisteredItems)
{
    input::Input::instance().shutdown();
    config::clear();

    auto sentinel = std::make_shared<int>(0);
    EXPECT_EQ(sentinel.use_count(), 1L);

    config::bind_string(
        "SessionUnloadCfgClear", "Key", "session unload key", [sentinel](std::string_view) { /* keeps it alive */ },
        "default");
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

    (void)input::register_combo(input::ComboBinding{.name = std::string{"loader_lock_hold_all"},
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{keyboard_key(0x49)}, {}}},
                                                    .on_press = {},
                                                    .on_state_change = [release_count](bool pressed) noexcept
                                                    {
                                                        if (!pressed)
                                                        {
                                                            release_count->fetch_add(1, std::memory_order_relaxed);
                                                        }
                                                    }});

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
        "SessionUnloadAllCfgClear", "Key", "session unload-all key",
        [sentinel](std::string_view) { /* keeps it alive */ }, "default");
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
        Result<Hook> r_damage = inline_at(InlineRequest{.name = "fixture_dll_damage", .target = target_damage},
                                          &fixture_detour_compute_damage);
        ASSERT_TRUE(r_damage.has_value()) << r_damage.error().message();
        Hook h_damage = std::move(*r_damage);

        (void)input::register_combo(input::ComboBinding{.name = std::string{"fixture_dll_bind"},
                                                        .trigger = input::Trigger::Press,
                                                        .combos = {{{keyboard_key(0x4A)}, {}}},
                                                        .on_press = []() {},
                                                        .on_state_change = {}});
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

    // Reload and strictly re-hook: TargetAlreadyHookedInProcess would mean the prologue was not restored.
    mod.unload();
    ASSERT_TRUE(mod.load()) << "hook_target_lib.dll must reload cleanly";
    Result<Hook> reload =
        inline_at(InlineRequest{.name = "fixture_dll_damage_reloaded",
                                .target = Address{reinterpret_cast<std::uintptr_t>(mod.compute_damage)},
                                .options = Options{.fail_if_already_hooked = true}},
                  &fixture_detour_compute_damage);
    EXPECT_TRUE(reload.has_value()) << "fresh strict hook on the reloaded fixture must succeed";
}
