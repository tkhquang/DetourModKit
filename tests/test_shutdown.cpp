#include <gtest/gtest.h>
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

class DMKShutdownTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        DMK_Shutdown();
    }

    void TearDown() override
    {
        DMK_Shutdown();
    }
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
    Config::register_int("Section", "Key", "hot_reload_a", [&call_count_a](int)
                         { ++call_count_a; }, 10);
    EXPECT_EQ(call_count_a, 1); // Default applied once

    DMK_Shutdown();

    // After shutdown, old registrations are cleared.
    // Re-register with new items for the "second load".
    int call_count_b = 0;
    Config::register_int("Section", "Key", "hot_reload_b", [&call_count_b](int)
                         { ++call_count_b; }, 20);
    EXPECT_EQ(call_count_b, 1); // Default applied once

    // Reset counters before load
    call_count_a = 0;
    call_count_b = 0;

    auto ini_path = std::filesystem::temp_directory_path() /
                    ("test_shutdown_hotreload_" + std::to_string(_getpid()) + ".ini");
    EXPECT_NO_THROW(Config::load(ini_path.string()));

    // Old callback must not fire; new callback fires with default
    EXPECT_EQ(call_count_a, 0);
    EXPECT_EQ(call_count_b, 1);

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
    bool init_ok = Memory::init_cache();
    ASSERT_TRUE(init_ok);

    DMK_Shutdown();

    // After shutdown, re-init should succeed and stats should reflect a fresh cache
    bool reinit_ok = Memory::init_cache();
    ASSERT_TRUE(reinit_ok);

    std::string stats = Memory::get_cache_stats();
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
