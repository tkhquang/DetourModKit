#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <process.h>
#include <string>
#include <thread>

#include "DetourModKit/config.hpp"

#include "internal/config_reload_gate.hpp"

using namespace DetourModKit;
using namespace std::chrono_literals;

// Exercises the background-reload quiesce gate that on_logic_dll_unload* uses to keep a detached watcher/servicer
// thread from firing config setters into a Logic DLL whose pages the loader is reclaiming. The gate has three seams
// (config::detail::disable_reloads_for_unload / await_reloads_quiesced / rearm_reloads) driven against a real
// enable_auto_reload watcher so the guarded reload lambda (the actual production path) is what runs.
namespace
{
    class ReloadQuiesceTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            static int s_counter = 0;
            const std::string leaf =
                "dmk_reload_quiesce_" + std::to_string(_getpid()) + "_" + std::to_string(++s_counter);
            m_dir = std::filesystem::temp_directory_path() / leaf;
            std::filesystem::create_directories(m_dir);
            m_ini = m_dir / "watched.ini";
            // Start from a clean config registry and armed reload gate.
            config::clear();
            config::detail::rearm_reloads();
            write_ini("[S]\nV=1\n");
        }

        void TearDown() override
        {
            // Stop the watcher first, then re-arm the process-wide reload gate so a test that latched it off cannot
            // silently disable reloads for every later test in this process. clear() last to drop the registry.
            config::disable_auto_reload();
            config::detail::rearm_reloads();
            config::clear();
            std::error_code ec;
            std::filesystem::remove_all(m_dir, ec);
        }

        // Atomic replace: write the new bytes to a sibling temp file and rename it over the watched INI. A rename is a
        // single directory-change event, which avoids the partial-write / multi-notification churn a truncating rewrite
        // in the watched directory can produce.
        void write_ini(const std::string &content) const
        {
            const std::filesystem::path tmp = m_dir / "watched.ini.tmp";
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                out << content;
            }
            std::error_code ec;
            std::filesystem::rename(tmp, m_ini, ec);
            if (ec)
            {
                // Fallback for the rare rename failure: overwrite in place.
                std::ofstream out(m_ini, std::ios::binary | std::ios::trunc);
                out << content;
            }
        }

        template <class Pred> static bool wait_until(Pred pred, std::chrono::milliseconds timeout)
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (pred())
                {
                    return true;
                }
                std::this_thread::sleep_for(5ms);
            }
            return pred();
        }

        std::filesystem::path m_dir;
        std::filesystem::path m_ini;
    };

    // A reload pass already running consumer setters when the unload latch is set must be waited for, not abandoned. A
    // setter that parks on a gate holds the pass in flight; await_reloads_quiesced must time out while it is parked and
    // succeed once it is released.
    TEST_F(ReloadQuiesceTest, AwaitWaitsForInFlightReload)
    {
        std::atomic<int> applied{-1};
        std::atomic<bool> setter_parked{false};
        std::atomic<bool> release_gate{false};

        config::bind_int(
            "S", "V", "v",
            [&](int val)
            {
                applied.store(val, std::memory_order_release);
                if (val == 42)
                {
                    setter_parked.store(true, std::memory_order_release);
                    while (!release_gate.load(std::memory_order_acquire))
                    {
                        std::this_thread::sleep_for(1ms);
                    }
                }
            },
            0);

        config::load(m_ini.string());
        ASSERT_EQ(applied.load(std::memory_order_acquire), 1);
        ASSERT_EQ(config::enable_auto_reload(30ms), config::AutoReloadStatus::Started);

        // Trigger the blocking value and wait until the watcher-driven reload has the setter parked in flight.
        write_ini("[S]\nV=42\n");
        ASSERT_TRUE(wait_until([&] { return setter_parked.load(std::memory_order_acquire); }, 5s))
            << "watcher never drove the reload into the parked setter";

        // The setter is parked => exactly one reload pass is in flight. Latch reloads off (as unload does) and confirm
        // the quiesce does NOT report drained while the pass is still running.
        config::detail::disable_reloads_for_unload();
        EXPECT_FALSE(config::detail::await_reloads_quiesced(50ms))
            << "await must not report quiesced while a reload pass is still running a setter";

        // Release the setter; the in-flight count drains and the quiesce now succeeds.
        release_gate.store(true, std::memory_order_release);
        EXPECT_TRUE(config::detail::await_reloads_quiesced(3s))
            << "await must report quiesced once the in-flight reload finishes";
    }

    // The latch drops NEW background reload passes at their entry gate: after disable_reloads_for_unload, a file edit
    // does not run the setter; rearm_reloads restores normal reloading.
    TEST_F(ReloadQuiesceTest, LatchDropsBackgroundReloadAndRearmRestoresIt)
    {
        std::atomic<int> applied{-1};
        config::bind_int("S", "V", "v", [&](int val) { applied.store(val, std::memory_order_release); }, 0);

        config::load(m_ini.string());
        ASSERT_EQ(applied.load(std::memory_order_acquire), 1);
        ASSERT_EQ(config::enable_auto_reload(30ms), config::AutoReloadStatus::Started);

        // Positive control: a normal edit reloads and applies through the watcher.
        write_ini("[S]\nV=2\n");
        ASSERT_TRUE(wait_until([&] { return applied.load(std::memory_order_acquire) == 2; }, 5s))
            << "watcher-driven reload never applied the first edit";

        // Latch reloads off, then edit again: the background pass must be dropped, so the value stays at 2.
        config::detail::disable_reloads_for_unload();
        write_ini("[S]\nV=3\n");
        std::this_thread::sleep_for(400ms);
        EXPECT_EQ(applied.load(std::memory_order_acquire), 2)
            << "a background reload must be dropped while reloads are latched off for unload";

        // Re-arm and confirm reloading resumes.
        config::detail::rearm_reloads();
        write_ini("[S]\nV=4\n");
        EXPECT_TRUE(wait_until([&] { return applied.load(std::memory_order_acquire) == 4; }, 5s))
            << "reloading must resume after the gate is re-armed";
    }

    // A pass already applying setters when the unload latch is set must ABORT its remaining setters and SKIP the user
    // on_reload callback, not run the rest of the unloading module's code into pages the loader is reclaiming. The
    // reload's setter loop re-checks the latch before each setter and the watcher lambda re-checks it before on_reload;
    // both re-checks are exercised here by parking the first-registered setter mid-pass, latching reloads off while it
    // is parked, then releasing it.
    TEST_F(ReloadQuiesceTest, MidPassLatchAbortsRemainingSettersAndSkipsCallback)
    {
        std::atomic<int> applied_first{-1};
        std::atomic<int> applied_second{-1};
        std::atomic<bool> first_parked{false};
        std::atomic<bool> release_gate{false};
        std::atomic<int> on_reload_calls{0};

        // Setters apply in registration order, so the first-registered setter runs first and parks the pass in flight;
        // the second-registered setter is the one the mid-pass abort must skip.
        config::bind_int(
            "S", "V", "v",
            [&](int val)
            {
                applied_first.store(val, std::memory_order_release);
                if (val == 42)
                {
                    first_parked.store(true, std::memory_order_release);
                    while (!release_gate.load(std::memory_order_acquire))
                    {
                        std::this_thread::sleep_for(1ms);
                    }
                }
            },
            0);
        config::bind_int("S", "W", "w", [&](int val) { applied_second.store(val, std::memory_order_release); }, 0);

        write_ini("[S]\nV=1\nW=1\n");
        config::load(m_ini.string());
        ASSERT_EQ(applied_first.load(std::memory_order_acquire), 1);
        ASSERT_EQ(applied_second.load(std::memory_order_acquire), 1);
        ASSERT_EQ(
            config::enable_auto_reload(30ms, [&](bool) { on_reload_calls.fetch_add(1, std::memory_order_acq_rel); }),
            config::AutoReloadStatus::Started);

        // Change BOTH values so each setter has a deferred apply queued; the first parks the pass between its two
        // setters.
        write_ini("[S]\nV=42\nW=99\n");
        ASSERT_TRUE(wait_until([&] { return first_parked.load(std::memory_order_acquire); }, 5s))
            << "watcher never drove the reload into the parked first setter";

        // Latch reloads off while the pass is parked, exactly as on_logic_dll_unload* does, then release the setter.
        // The latch store is sequenced before the release-store the setter is spinning on, so once the setter wakes,
        // both the setter loop's next latch re-check and the watcher lambda's post-reload re-check are guaranteed to
        // observe the latch set: the second setter breaks out and on_reload is skipped.
        config::detail::disable_reloads_for_unload();
        release_gate.store(true, std::memory_order_release);

        // The parked setter returns, the guard drops the in-flight count, and the pass quiesces.
        EXPECT_TRUE(config::detail::await_reloads_quiesced(3s))
            << "the in-flight pass must finish once the parked setter is released";

        EXPECT_EQ(applied_first.load(std::memory_order_acquire), 42) << "the first setter ran before the abort";
        EXPECT_EQ(applied_second.load(std::memory_order_acquire), 1)
            << "the mid-pass unload latch must abort the remaining setters, leaving W at its loaded value";
        EXPECT_EQ(on_reload_calls.load(std::memory_order_acquire), 0)
            << "on_reload must not fire for a pass the unload latched off mid-flight";
    }
} // namespace
