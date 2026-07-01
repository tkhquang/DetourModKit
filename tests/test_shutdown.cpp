#include <gtest/gtest.h>
#include <chrono>
#include <fstream>
#include <string>
#include <filesystem>
#include <process.h>

#include "DetourModKit/address.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using DetourModKit::keyboard_key;

// Portable "do not inline" attribute: MSVC silently ignores [[gnu::noinline]], which would let the target below inline
// and defeat the patch, so route through the same per-file macro the other hook tests use.
#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

namespace
{
    // A trivial in-process target/detour pair so the RAII shutdown test can install a real inline hook without a
    // fixture DLL. DMK_TEST_NOINLINE keeps the target a distinct, patchable function body across compilers.
    DMK_TEST_NOINLINE int shutdown_raii_target(int x)
    {
        volatile int r = x + 1;
        return r;
    }

    int shutdown_raii_detour(int x)
    {
        return x + 2;
    }
} // namespace

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
    config::bind_int("Section", "Key", "hot_reload_a", [&call_count_a](int) { ++call_count_a; }, 10);
    EXPECT_EQ(call_count_a, 1); // Default applied once

    DMK_Shutdown();

    // After shutdown, old registrations are cleared. Re-register with new items for the "second load".
    int call_count_b = 0;
    config::bind_int("Section", "Key", "hot_reload_b", [&call_count_b](int) { ++call_count_b; }, 20);
    EXPECT_EQ(call_count_b, 1); // Default applied once

    // Reset counters before load
    call_count_a = 0;
    call_count_b = 0;

    auto ini_path =
        std::filesystem::temp_directory_path() / ("test_shutdown_hotreload_" + std::to_string(_getpid()) + ".ini");
    EXPECT_NO_THROW(config::load(ini_path.string()));

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

    config::bind_int("Section", "Key", "autoreload_watcher", [](int) {}, 1);
    ASSERT_NO_THROW(config::load(ini_path.string()));

    ASSERT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started);
    ASSERT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::AlreadyRunning);

    DMK_Shutdown();

    // Re-establish a load path (shutdown cleared the registry) and re-enable. A fresh Started proves DMK_Shutdown
    // disabled the watcher; AlreadyRunning would mean the watcher leaked past shutdown.
    config::bind_int("Section", "Key", "autoreload_watcher_2", [](int) {}, 1);
    ASSERT_NO_THROW(config::load(ini_path.string()));
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started)
        << "DMK_Shutdown() must stop the auto-reload watcher; a surviving watcher would report AlreadyRunning";

    config::disable_auto_reload();
    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
}

TEST_F(DMKShutdownTest, ShutdownWithLoggerConfigured)
{
    auto log_path = std::filesystem::temp_directory_path() / "test_shutdown_logger.log";
    Logger::configure("DMK_TEST", log_path.string(), "%Y-%m-%d %H:%M:%S");
    log().log(LogLevel::Info, "Shutdown test message");

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

TEST_F(DMKShutdownTest, ShutdownWithInputRegistered)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(input::ComboBinding{.name = std::string{"shutdown_test_key"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});
    EXPECT_EQ(mgr.binding_count(), 1u);

    DMK_Shutdown();

    EXPECT_EQ(mgr.binding_count(), 0u);
}

// DMK_Shutdown() does not manage hooks: each hook is owned by the caller's Hook handle and
// is unhooked when that handle is dropped. Prove the lifetimes are now orthogonal -- a Hook dropped before
// DMK_Shutdown() is already unhooked (so shutdown has nothing to tear down), and DMK_Shutdown() still runs its
// non-hook teardown cleanly afterwards.
TEST_F(DMKShutdownTest, HookLifetimeIsCallerOwnedNotShutdownManaged)
{
    const Address target{reinterpret_cast<std::uintptr_t>(&shutdown_raii_target)};

    {
        Result<Hook> r =
            inline_at(InlineRequest{.name = "shutdown_raii_hook", .target = target}, &shutdown_raii_detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);

        EXPECT_TRUE(static_cast<bool>(h));
        EXPECT_TRUE(h.is_enabled());
        EXPECT_TRUE(is_target_hooked(target)) << "ledger must record the live hook";
        // Calling the hooked target directly runs the detour (x + 2); call<>() reaches the ORIGINAL (x + 1) through
        // the guarded trampoline, so the two return values differ -- both prove the hook is live.
        EXPECT_EQ(shutdown_raii_target(10), 12) << "the installed detour is active when the target is called";
        EXPECT_EQ(h.call<int>(10), 11) << "call<>() reaches the original through the guarded trampoline";
    }

    // The handle dropped at the end of the block: RAII already unhooked it, with no help from DMK_Shutdown().
    EXPECT_FALSE(is_target_hooked(target)) << "dropping the Hook handle must unhook before any DMK_Shutdown()";

    // DMK_Shutdown() owns the input poller, memory cache, config registry, and logger -- never hooks. With the hook
    // already gone, shutdown must still complete its non-hook teardown without throwing.
    EXPECT_NO_THROW(DMK_Shutdown());
    EXPECT_FALSE(is_target_hooked(target)) << "shutdown must not resurrect or re-touch a caller-owned hook";
}
