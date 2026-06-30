#include <gtest/gtest.h>
#include <chrono>
#include <fstream>
#include <string>
#include <filesystem>
#include <process.h>

#include "DetourModKit/config.hpp"
#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit.hpp"

using namespace DetourModKit;
using DetourModKit::keyboard_key;

// DMK_Shutdown() is the documented teardown entry point and runs from loader-lock / DLL_PROCESS_DETACH paths where an
// escaping exception would terminate the host. Every subsystem teardown it invokes is noexcept, so the wrapper is too;
// pin that no-throw contract at compile time.
static_assert(noexcept(DMK_Shutdown()),
              "DMK_Shutdown() must be noexcept so teardown cannot throw into a host unwinding under the loader lock.");

class DMKShutdownTest : public ::testing::Test
{
protected:
    void SetUp() override { DMK_Shutdown(); }

    void TearDown() override { DMK_Shutdown(); }
};

TEST_F(DMKShutdownTest, IdempotentShutdown)
{
    DMK_Shutdown();
    EXPECT_NO_THROW(DMK_Shutdown());
}

TEST_F(DMKShutdownTest, ShutdownWithNoSubsystemsInitialized)
{
    EXPECT_NO_THROW(DMK_Shutdown());
}

TEST_F(DMKShutdownTest, HotReloadScenario)
{
    int call_count_a = 0;
    Config::register_int("Section", "Key", "hot_reload_a", [&call_count_a](int) { ++call_count_a; }, 10);
    EXPECT_EQ(call_count_a, 1); // Default applied once

    DMK_Shutdown();

    // After shutdown, old registrations are cleared. Re-register with new items for the "second load".
    int call_count_b = 0;
    Config::register_int("Section", "Key", "hot_reload_b", [&call_count_b](int) { ++call_count_b; }, 20);
    EXPECT_EQ(call_count_b, 1); // Default applied once

    // Reset counters before load
    call_count_a = 0;
    call_count_b = 0;

    auto ini_path =
        std::filesystem::temp_directory_path() / ("test_shutdown_hotreload_" + std::to_string(_getpid()) + ".ini");
    EXPECT_NO_THROW(Config::load(ini_path.string()));

    // Old callback must not fire; new callback fires with default
    EXPECT_EQ(call_count_a, 0);
    EXPECT_EQ(call_count_b, 1);

    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
}

TEST_F(DMKShutdownTest, DisablesAutoReloadWatcher)
{
    // DMK_Shutdown() must stop the Config auto-reload watcher first, before any consumer state a watcher on_reload
    // callback might touch is torn down. Prove it deterministically by re-enabling after shutdown: a watcher that
    // survived would report AlreadyRunning, while a fresh Started proves the prior watcher was stopped.
    const auto ini_path =
        std::filesystem::temp_directory_path() / ("test_shutdown_autoreload_" + std::to_string(_getpid()) + ".ini");
    {
        std::ofstream ofs(ini_path);
        ofs << "[Section]\nKey=1\n";
    }

    Config::register_int("Section", "Key", "autoreload_watcher", [](int) {}, 1);
    ASSERT_NO_THROW(Config::load(ini_path.string()));

    ASSERT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{50}), Config::AutoReloadStatus::Started);
    ASSERT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{50}), Config::AutoReloadStatus::AlreadyRunning);

    DMK_Shutdown();

    // Re-establish a load path (shutdown cleared the registry) and re-enable. A fresh Started proves DMK_Shutdown
    // disabled the watcher; AlreadyRunning would mean the watcher leaked past shutdown.
    Config::register_int("Section", "Key", "autoreload_watcher_2", [](int) {}, 1);
    ASSERT_NO_THROW(Config::load(ini_path.string()));
    EXPECT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{50}), Config::AutoReloadStatus::Started)
        << "DMK_Shutdown() must stop the auto-reload watcher; a surviving watcher would report AlreadyRunning";

    Config::disable_auto_reload();
    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
}

TEST_F(DMKShutdownTest, ShutdownWithLoggerConfigured)
{
    auto log_path = std::filesystem::temp_directory_path() / "test_shutdown_logger.log";
    Logger::get_instance().configure("DMK_TEST", log_path.string(), "%Y-%m-%d %H:%M:%S");
    Logger::get_instance().log(LogLevel::Info, "Shutdown test message");

    EXPECT_NO_THROW(DMK_Shutdown());

    if (std::filesystem::exists(log_path))
    {
        std::filesystem::remove(log_path);
    }
}

TEST_F(DMKShutdownTest, ShutdownWithMemoryCacheInitialized)
{
    bool init_ok = memory::init_cache();
    ASSERT_TRUE(init_ok);

    DMK_Shutdown();

    // After shutdown, re-init should succeed and stats should reflect a fresh cache
    bool reinit_ok = memory::init_cache();
    ASSERT_TRUE(reinit_ok);

    std::string stats = memory::get_cache_stats();
    EXPECT_NE(stats.find("Hits: 0"), std::string::npos);
    EXPECT_NE(stats.find("Misses: 0"), std::string::npos);
}

TEST_F(DMKShutdownTest, ShutdownWithInputManagerRegistered)
{
    auto &mgr = InputManager::get_instance();
    mgr.register_press("shutdown_test_key", {keyboard_key(0x41)}, []() {});
    EXPECT_EQ(mgr.binding_count(), 1u);

    DMK_Shutdown();

    EXPECT_EQ(mgr.binding_count(), 0u);
}

TEST_F(DMKShutdownTest, ShutdownWithHookManager)
{
    DMK_Shutdown();

    auto counts = HookManager::get_instance().get_hook_counts();
    for (const auto &[status, count] : counts)
    {
        EXPECT_EQ(count, 0u);
    }
}
