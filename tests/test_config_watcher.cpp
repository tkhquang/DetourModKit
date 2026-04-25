#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <process.h>
#include <string>
#include <thread>

#include <windows.h>

#include "DetourModKit/config_watcher.hpp"

using namespace DetourModKit;
using namespace std::chrono_literals;

namespace
{
    class ConfigWatcherTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            static int s_test_counter = 0;
            const std::string name = "dmk_watcher_" +
                                     std::to_string(_getpid()) + "_" +
                                     std::to_string(++s_test_counter);
            m_temp_dir = std::filesystem::temp_directory_path() / name;
            std::filesystem::create_directories(m_temp_dir);
            m_ini_path = m_temp_dir / "watched.ini";

            write_ini("[S]\nK=1\n");
        }

        void TearDown() override
        {
            std::error_code ec;
            std::filesystem::remove_all(m_temp_dir, ec);
        }

        void write_ini(const std::string &content) const
        {
            std::ofstream out(m_ini_path, std::ios::binary | std::ios::trunc);
            out << content;
        }

        // Waits until @p pred is true or @p timeout expires. Returns pred().
        template <class Pred>
        static bool wait_until(Pred pred, std::chrono::milliseconds timeout)
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (pred())
                {
                    return true;
                }
                std::this_thread::sleep_for(10ms);
            }
            return pred();
        }

        std::filesystem::path m_temp_dir;
        std::filesystem::path m_ini_path;
    };

    // --- Basic lifecycle ---

    TEST_F(ConfigWatcherTest, NoStartDestructIsSafe)
    {
        std::atomic<int> hits{0};
        {
            ConfigWatcher watcher(m_ini_path.string(), 50ms,
                                  [&hits]()
                                  { hits.fetch_add(1); });
            EXPECT_FALSE(watcher.is_running());
        }
        EXPECT_EQ(hits.load(), 0);
    }

    TEST_F(ConfigWatcherTest, StartThenStopIdempotent)
    {
        ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});

        EXPECT_TRUE(watcher.start());
        EXPECT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));

        EXPECT_TRUE(watcher.start()); // second call is a no-op
        EXPECT_TRUE(watcher.is_running());

        watcher.stop();
        EXPECT_FALSE(watcher.is_running());
        EXPECT_NO_THROW(watcher.stop());
    }

    TEST_F(ConfigWatcherTest, Accessors)
    {
        ConfigWatcher watcher(m_ini_path.string(), 173ms, []() {});
        EXPECT_EQ(watcher.ini_path(), m_ini_path.string());
        EXPECT_EQ(watcher.debounce(), 173ms);
    }

    TEST_F(ConfigWatcherTest, StartFailsOnEmptyIniPath)
    {
        ConfigWatcher watcher("", 50ms, []() {});
        EXPECT_FALSE(watcher.start());
        EXPECT_FALSE(watcher.is_running());
        EXPECT_NO_THROW(watcher.stop());
    }

    TEST_F(ConfigWatcherTest, IsWorkerThreadFalseFromMainBeforeStart)
    {
        ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});
        EXPECT_FALSE(watcher.is_worker_thread(std::this_thread::get_id()));
    }

    TEST_F(ConfigWatcherTest, IsWorkerThreadTrueFromCallback)
    {
        std::atomic<bool> observed{false};
        std::atomic<std::thread::id> cb_tid{};
        ConfigWatcher watcher(m_ini_path.string(), 50ms,
                              [&]()
                              {
                                  cb_tid.store(std::this_thread::get_id(),
                                               std::memory_order_release);
                                  observed.store(true,
                                                 std::memory_order_release);
                              });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=2\n");

        ASSERT_TRUE(wait_until([&]()
                               { return observed.load(std::memory_order_acquire); },
                               3s));
        EXPECT_TRUE(watcher.is_worker_thread(
            cb_tid.load(std::memory_order_acquire)));
        EXPECT_FALSE(watcher.is_worker_thread(std::this_thread::get_id()));
        watcher.stop();
    }

    TEST_F(ConfigWatcherTest, StopWithoutStartIsSafe)
    {
        ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});
        EXPECT_NO_THROW(watcher.stop());
        EXPECT_NO_THROW(watcher.stop());
        EXPECT_FALSE(watcher.is_running());
    }

    TEST_F(ConfigWatcherTest, DestructorStopsRunningWatcher)
    {
        std::atomic<int> hits{0};
        {
            ConfigWatcher watcher(m_ini_path.string(), 50ms,
                                  [&hits]()
                                  { hits.fetch_add(1); });
            ASSERT_TRUE(watcher.start());
            ASSERT_TRUE(wait_until([&]()
                                   { return watcher.is_running(); },
                                   1s));
            std::this_thread::sleep_for(80ms);
        }
        SUCCEED();
    }

    TEST_F(ConfigWatcherTest, PendingChangeFlushedOnStop)
    {
        std::atomic<int> hits{0};
        ConfigWatcher watcher(m_ini_path.string(),
                              std::chrono::seconds(2),
                              [&hits]()
                              { hits.fetch_add(1, std::memory_order_relaxed); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=9\n");

        // Stop well before the 2-second debounce elapses so the pending
        // flag must still be true when stop() cancels the I/O.
        std::this_thread::sleep_for(200ms);
        watcher.stop();

        EXPECT_GE(hits.load(std::memory_order_relaxed), 1);
    }

    // --- Basic fire ---

    TEST_F(ConfigWatcherTest, BasicFire_CallbackInvokedOnWrite)
    {
        std::atomic<int> hits{0};
        ConfigWatcher watcher(m_ini_path.string(), 100ms,
                              [&hits]()
                              { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));

        // Let ReadDirectoryChangesW issue its first I/O request before we write.
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=2\n");

        EXPECT_TRUE(wait_until([&]()
                               { return hits.load() >= 1; },
                               2s));

        watcher.stop();
        EXPECT_EQ(hits.load(), 1) << "Expected exactly one debounced fire";
    }

    // --- Debounce ---

    TEST_F(ConfigWatcherTest, Debounce_BurstyWritesCollapseToOneFire)
    {
        std::atomic<int> hits{0};
        ConfigWatcher watcher(m_ini_path.string(), 200ms,
                              [&hits]()
                              { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        // Five rapid writes within ~100 ms; a 200 ms debounce must collapse them.
        for (int i = 0; i < 5; ++i)
        {
            write_ini("[S]\nK=" + std::to_string(10 + i) + "\n");
            std::this_thread::sleep_for(15ms);
        }

        EXPECT_TRUE(wait_until([&]()
                               { return hits.load() >= 1; },
                               2s));

        // Give the watcher enough idle time for any spurious second fire to surface.
        std::this_thread::sleep_for(400ms);

        watcher.stop();
        EXPECT_EQ(hits.load(), 1)
            << "Debounce should collapse the burst into a single callback";
    }

    // --- Rename-swap-save (Notepad++, VSCode) ---

    TEST_F(ConfigWatcherTest, RenameSwapSave_TriggersReload)
    {
        std::atomic<int> hits{0};
        ConfigWatcher watcher(m_ini_path.string(), 100ms,
                              [&hits]()
                              { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        // Write sibling .tmp then MoveFileExW over the target -- the atomic
        // save pattern used by Notepad++ and VSCode.
        const std::filesystem::path tmp = m_temp_dir / "watched.ini.tmp";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out << "[S]\nK=99\n";
        }
        const BOOL ok = ::MoveFileExW(
            tmp.wstring().c_str(),
            m_ini_path.wstring().c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        ASSERT_TRUE(ok) << "MoveFileExW failed, GLE=" << ::GetLastError();

        EXPECT_TRUE(wait_until([&]()
                               { return hits.load() >= 1; },
                               2s));

        watcher.stop();
    }

    // --- Stop bound ---

    TEST_F(ConfigWatcherTest, Stop_ReturnsWithinBound)
    {
        ConfigWatcher watcher(m_ini_path.string(), 100ms, []() {});
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));

        // Stop must return within ~200 ms (pump timeout is 100 ms; we give
        // a generous 1 s ceiling to avoid flakiness on loaded CI machines).
        const auto t0 = std::chrono::steady_clock::now();
        watcher.stop();
        const auto elapsed = std::chrono::steady_clock::now() - t0;

        EXPECT_FALSE(watcher.is_running());
        EXPECT_LT(elapsed, 1s);
    }

    // --- Empty callback is accepted ---

    TEST_F(ConfigWatcherTest, EmptyCallback_DoesNotCrashOnEvent)
    {
        ConfigWatcher watcher(m_ini_path.string(), 50ms, {});
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=3\n");
        std::this_thread::sleep_for(300ms);

        EXPECT_NO_THROW(watcher.stop());
    }

    TEST_F(ConfigWatcherTest, Stop_WithIoInFlight_NoCrash)
    {
        // Tight start/stop loop. start() only returns once the first
        // ReadDirectoryChangesW is posted, so I/O is in flight before
        // every stop().
        for (int i = 0; i < 100; ++i)
        {
            ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});
            ASSERT_TRUE(watcher.start());
            watcher.stop();
            EXPECT_FALSE(watcher.is_running());
        }
    }

    TEST_F(ConfigWatcherTest, Overflow_ActuallyExceedsBuffer_CallbackStillFires)
    {
        // 600 siblings with >70-char names push each FILE_NOTIFY_INFORMATION
        // entry past 100 bytes, overflowing the 16 KB kernel buffer and
        // driving the ERROR_NOTIFY_ENUM_DIR / zero-byte-completion paths.
        std::atomic<int> hits{0};
        ConfigWatcher watcher(m_ini_path.string(), 100ms,
                              [&hits]()
                              { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        for (int i = 0; i < 600; ++i)
        {
            const std::filesystem::path sibling =
                m_temp_dir / ("overflow_test_" + std::to_string(i) +
                              "_with_a_fairly_long_padding_string.dat");
            std::ofstream out(sibling, std::ios::binary | std::ios::trunc);
            out << "x";
        }
        // Target write so the debounced callback fires even if every
        // sibling event was dropped during overflow.
        write_ini("[S]\nK=999\n");

        EXPECT_TRUE(wait_until([&]()
                               { return hits.load() >= 1; },
                               3s));

        watcher.stop();
        EXPECT_GE(hits.load(), 1)
            << "Watcher must survive buffer overflow and still fire "
               "the debounced callback for the target write.";
    }

    TEST_F(ConfigWatcherTest, ParentDirectoryRemoved_WatcherExitsCleanly)
    {
        // Parent-dir removal surfaces as ERROR_OPERATION_ABORTED from
        // GetOverlappedResultEx. The worker must break the pump loop and
        // the destructor must still run cleanly.
        const std::filesystem::path temp_parent =
            std::filesystem::temp_directory_path() /
            ("dmk_watcher_removetest_" + std::to_string(_getpid()) + "_" +
             std::to_string(::GetCurrentThreadId()));
        std::filesystem::create_directories(temp_parent);
        const std::filesystem::path ini = temp_parent / "watched.ini";
        {
            std::ofstream out(ini, std::ios::binary | std::ios::trunc);
            out << "[S]\nK=1\n";
        }

        {
            ConfigWatcher watcher(ini.string(), 50ms, []() {});
            ASSERT_TRUE(watcher.start());
            ASSERT_TRUE(wait_until([&]()
                                   { return watcher.is_running(); },
                                   1s));
            std::this_thread::sleep_for(100ms);

            std::error_code ec;
            std::filesystem::remove_all(temp_parent, ec);
            // remove_all may fail because the watcher holds the directory
            // open with FILE_LIST_DIRECTORY + SHARE_DELETE; either outcome
            // is acceptable.

            std::this_thread::sleep_for(300ms);
        }

        // Best-effort cleanup if the directory outlived the watcher.
        std::error_code ec;
        std::filesystem::remove_all(temp_parent, ec);
    }

    TEST_F(ConfigWatcherTest, Stop_FlushesPendingDebounce)
    {
        std::atomic<int> hits{0};
        // 2 s debounce, stop after 200 ms: the pending callback must be
        // flushed during stop() rather than waiting for the timer.
        ConfigWatcher watcher(m_ini_path.string(), 2000ms,
                              [&hits]()
                              { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=42\n");

        std::this_thread::sleep_for(200ms);

        watcher.stop();
        EXPECT_EQ(hits.load(), 1)
            << "stop() must flush the pending debounced callback exactly once";
    }

    TEST_F(ConfigWatcherTest, Construct_InvalidPath_StartReturnsFalse)
    {
        const std::filesystem::path missing =
            m_temp_dir / "nonexistent_subdir" / "file.ini";

        ConfigWatcher watcher(missing.string(), 100ms, []() {});
        EXPECT_FALSE(watcher.start());
        EXPECT_FALSE(watcher.is_running());
    }
} // namespace
