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
        // Tight start/stop loop with no event delivery. Under ASan this
        // catches regressions where the worker releases its OVERLAPPED or
        // buffer before the cancelled ReadDirectoryChangesW completes.
        for (int i = 0; i < 100; ++i)
        {
            ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});
            ASSERT_TRUE(watcher.start());
            // start() returns only after the first ReadDirectoryChangesW
            // is posted, so I/O is guaranteed to be in flight by the
            // time stop() runs. This test exists to prove stop() handles
            // that window cleanly every iteration.
            watcher.stop();
            EXPECT_FALSE(watcher.is_running());
        }
    }

    TEST_F(ConfigWatcherTest, Overflow_ActuallyExceedsBuffer_CallbackStillFires)
    {
        // The previous overflow test created 200 sibling files with 8-char
        // names. Each FILE_NOTIFY_INFORMATION entry was ~50 bytes, so the
        // burst totalled ~10 KB -- comfortably inside the 16 KB buffer,
        // which meant the test never actually exercised the overflow path
        // it claimed to cover.
        //
        // This version writes 600 siblings with long padding strings to
        // push each entry over 100 bytes (sizeof(FILE_NOTIFY_INFORMATION) +
        // 2 bytes per UTF-16 filename char). At 600 x 100+ = 60+ KB of
        // events, we're well past the 16 KB buffer boundary -- both
        // zero-byte-completion and ERROR_NOTIFY_ENUM_DIR paths should be
        // exercised on typical Windows kernels.
        std::atomic<int> hits{0};
        ConfigWatcher watcher(m_ini_path.string(), 100ms,
                              [&hits]()
                              { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        // 600 files with names over 70 chars each -- each
        // FILE_NOTIFY_INFORMATION entry becomes well over 100 bytes.
        for (int i = 0; i < 600; ++i)
        {
            const std::filesystem::path sibling =
                m_temp_dir / ("overflow_test_" + std::to_string(i) +
                              "_with_a_fairly_long_padding_string.dat");
            std::ofstream out(sibling, std::ios::binary | std::ios::trunc);
            out << "x";
        }
        // And a write to the actual target, so the callback has something
        // to match even if every sibling event got dropped.
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
        // The parent directory being removed surfaces as
        // ERROR_OPERATION_ABORTED from GetOverlappedResultEx. The worker
        // must log a warning, break out of the pump loop, and exit the
        // thread cleanly -- no crash, no hang, is_running() must
        // eventually go false.
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
            // remove_all may fail because the watcher holds the
            // directory open (FILE_LIST_DIRECTORY with SHARE_DELETE).
            // That is acceptable here -- we just need the watcher's
            // destructor to shut down cleanly regardless.

            std::this_thread::sleep_for(300ms);

            // Whether the kernel tore the handle down or not, the
            // destructor (~ConfigWatcher) must run without crashing.
        }

        // Best-effort cleanup if the directory outlived the watcher.
        std::error_code ec;
        std::filesystem::remove_all(temp_parent, ec);
    }

    // Optional Start_HandshakeTimeout_ReturnsFalse test intentionally
    // omitted: there is no in-process hook for pausing CreateFileW, and
    // the only faithful reproduction would require a dedicated mocking
    // layer that does not exist in this codebase. The handshake-timeout
    // path is exercised indirectly by Construct_InvalidPath_StartReturnsFalse
    // (which takes the broken-promise exit via set_value(false)) and by
    // code review against the 5-second wait_for boundary.

    TEST_F(ConfigWatcherTest, Stop_FlushesPendingDebounce)
    {
        std::atomic<int> hits{0};
        // Deliberately long debounce: the single write below will NOT
        // have elapsed its debounce window by the time stop() is called.
        // The worker must still flush the pending callback on exit.
        ConfigWatcher watcher(m_ini_path.string(), 2000ms,
                              [&hits]()
                              { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]()
                               { return watcher.is_running(); },
                               1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=42\n");

        // Short wait so the worker has time to observe the event and
        // mark `pending = true`, but much less than the debounce window.
        std::this_thread::sleep_for(200ms);

        watcher.stop();
        EXPECT_EQ(hits.load(), 1)
            << "stop() must flush the pending debounced callback exactly once";
    }

    TEST_F(ConfigWatcherTest, Construct_InvalidPath_StartReturnsFalse)
    {
        // Parent directory does not exist. CreateFileW must fail and
        // start() must return false without spawning the worker.
        const std::filesystem::path missing =
            m_temp_dir / "nonexistent_subdir" / "file.ini";

        ConfigWatcher watcher(missing.string(), 100ms, []() {});
        EXPECT_FALSE(watcher.start());
        EXPECT_FALSE(watcher.is_running());
    }
} // namespace
