#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>

#include <windows.h>

#include "DetourModKit/bootstrap.hpp"

using namespace DetourModKit;
using namespace std::chrono_literals;

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

    struct CallbackSignals
    {
        std::mutex m;
        std::condition_variable cv;
        std::atomic<int> init_calls{0};
        std::atomic<int> shutdown_calls{0};
        std::atomic<bool> init_done{false};
        std::atomic<bool> shutdown_done{false};

        bool wait_for_init(std::chrono::steady_clock::duration timeout)
        {
            std::unique_lock lock(m);
            return cv.wait_for(lock, timeout, [this]
                               { return init_done.load(std::memory_order_acquire); });
        }

        bool wait_for_shutdown(std::chrono::steady_clock::duration timeout)
        {
            std::unique_lock lock(m);
            return cv.wait_for(lock, timeout, [this]
                               { return shutdown_done.load(std::memory_order_acquire); });
        }
    };
} // namespace

TEST(BootstrapUnitTest, ModInfoDefaults)
{
    const Bootstrap::ModInfo info{};
    EXPECT_TRUE(info.prefix.empty());
    EXPECT_TRUE(info.log_file.empty());
    EXPECT_TRUE(info.game_process_name.empty());
    EXPECT_TRUE(info.instance_mutex_prefix.empty());
}

TEST(BootstrapUnitTest, RequestShutdownBeforeAttachIsNoOp)
{
    EXPECT_NO_THROW(Bootstrap::request_shutdown());
    EXPECT_NO_THROW(Bootstrap::request_shutdown());
}

TEST(BootstrapUnitTest, ModuleHandleReturnsNullBeforeAttach)
{
    EXPECT_EQ(Bootstrap::module_handle(), nullptr);
}

TEST(BootstrapUnitTest, NullHModuleSkipsDisableThreadLibraryCalls)
{
    CallbackSignals sig;
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_nullmod.log";
    info.game_process_name = "DefinitelyNotTheCurrentProcess_null.exe";
    info.instance_mutex_prefix = "BS_Test_Mutex_NullMod_";

    const BOOL result = Bootstrap::on_dll_attach(
        nullptr,
        info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);
}

TEST(BootstrapUnitTest, EmptyProcessNamePassesGateButMutexCollisionStillFails)
{
    // Pre-own the mutex name so the attach still fails without arming the
    // shutdown event or the worker thread.
    const std::string_view prefix = "BS_Test_Mutex_EmptyGate_";

    wchar_t expected_name[128]{};
    std::wstring wprefix;
    wprefix.reserve(prefix.size());
    for (char c : prefix)
    {
        wprefix.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    const int n = wsprintfW(expected_name, L"%s%lu", wprefix.c_str(),
                            GetCurrentProcessId());
    ASSERT_GT(n, 0);

    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, expected_name);
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u);

    CallbackSignals sig;
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_emptygate.log";
    info.game_process_name = "";
    info.instance_mutex_prefix = prefix;

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr),
        info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    CloseHandle(pre_owned);
}

TEST(BootstrapUnitTest, ProcessGateMismatchReturnsFalse)
{
    CallbackSignals sig;
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_procgate.log";
    info.game_process_name = "DefinitelyNotTheCurrentProcess_xyz.exe";
    info.instance_mutex_prefix = "BS_Test_Mutex_ProcGate_";

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr),
        info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);
}

TEST(BootstrapUnitTest, InstanceMutexCollisionReturnsFalse)
{
    const std::string_view prefix = "BS_Test_Mutex_Collision_";

    wchar_t expected_name[128]{};
    std::wstring wprefix;
    wprefix.reserve(prefix.size());
    for (char c : prefix)
    {
        wprefix.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    const int n = wsprintfW(expected_name, L"%s%lu", wprefix.c_str(), GetCurrentProcessId());
    ASSERT_GT(n, 0);

    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, expected_name);
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u) << "Mutex name collided with an existing one before the test";

    CallbackSignals sig;
    const std::string exe_name = current_exe_basename();
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_mutex.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = prefix;

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr),
        info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);

    CloseHandle(pre_owned);
}

class BootstrapIntegrationTest : public ::testing::Test
{
protected:
    CallbackSignals sig;
    bool attached{false};

    void TearDown() override
    {
        if (attached)
        {
            Bootstrap::request_shutdown();
            sig.wait_for_shutdown(kTestTimeout);
            Bootstrap::on_dll_detach(FALSE);
        }
    }
};

TEST_F(BootstrapIntegrationTest, HappyPathAttachInitShutdown)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_happy.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = "BS_Test_Mutex_Happy_";

    auto init_fn = [this]() noexcept
    {
        sig.init_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(sig.m);
            sig.init_done.store(true, std::memory_order_release);
        }
        sig.cv.notify_all();
        return true;
    };

    auto shutdown_fn = [this]() noexcept
    {
        sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(sig.m);
            sig.shutdown_done.store(true, std::memory_order_release);
        }
        sig.cv.notify_all();
    };

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info, init_fn, shutdown_fn);
    ASSERT_EQ(result, TRUE);
    attached = true;

    ASSERT_TRUE(sig.wait_for_init(kTestTimeout)) << "init_fn did not complete within timeout";
    EXPECT_EQ(sig.init_calls.load(), 1);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);

    EXPECT_NE(Bootstrap::module_handle(), nullptr);

    const BOOL second = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info,
        [this]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [this]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });
    EXPECT_EQ(second, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 1);

    const auto signal_start = std::chrono::steady_clock::now();
    Bootstrap::request_shutdown();

    ASSERT_TRUE(sig.wait_for_shutdown(kTestTimeout)) << "shutdown_fn did not complete within timeout";
    const auto elapsed = std::chrono::steady_clock::now() - signal_start;

    EXPECT_EQ(sig.init_calls.load(), 1);
    EXPECT_EQ(sig.shutdown_calls.load(), 1);
    EXPECT_LT(elapsed, 2s);

    attached = false;
}

TEST_F(BootstrapIntegrationTest, InitAndShutdownExceptionsAreCaught)
{
    // Drain any globals left set by a prior successful attach (HappyPath
    // leaves g_shutdown_event / g_worker_thread non-null for its design);
    // this is the first on_dll_detach call in the process and will win
    // the CAS and clear the static handles.
    Bootstrap::on_dll_detach(FALSE);

    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_throws.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = "BS_Test_Mutex_Throws_";

    auto init_fn = [this]() -> bool
    {
        sig.init_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(sig.m);
            sig.init_done.store(true, std::memory_order_release);
        }
        sig.cv.notify_all();
        throw std::runtime_error("init failure");
    };

    auto shutdown_fn = [this]()
    {
        sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(sig.m);
            sig.shutdown_done.store(true, std::memory_order_release);
        }
        sig.cv.notify_all();
        throw std::runtime_error("shutdown failure");
    };

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info, init_fn, shutdown_fn);
    ASSERT_EQ(result, TRUE);
    attached = true;

    ASSERT_TRUE(sig.wait_for_init(kTestTimeout));
    EXPECT_EQ(sig.init_calls.load(), 1);

    Bootstrap::request_shutdown();
    ASSERT_TRUE(sig.wait_for_shutdown(kTestTimeout));
    EXPECT_EQ(sig.shutdown_calls.load(), 1);
}
