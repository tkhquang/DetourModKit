#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <process.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>

#include <windows.h>

#include "DetourModKit/diagnostics.hpp"

#include "internal/config_watcher.hpp"

using namespace DetourModKit;
using namespace std::chrono_literals;

// The loader-lock fallback in ~ConfigWatcher heap-allocates a std::unique_ptr<Impl> via new (std::nothrow) and leaks
// the cell to outlive the destructor. Impl is a private nested type, so this assertion guards the unique_ptr leak-cell
// pattern at the type level rather than referencing Impl directly: if std::unique_ptr ever ceased to be
// nothrow-move-constructible, the leak cell could no longer be constructed from a noexcept context without risking
// std::terminate.
static_assert(std::is_nothrow_move_constructible_v<std::unique_ptr<int>>,
              "std::unique_ptr must remain nothrow-move-constructible for the "
              "ConfigWatcher loader-lock leak path to keep ~ConfigWatcher noexcept honest.");

namespace
{
    class ConfigWatcherTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            static int s_test_counter = 0;
            const std::string name =
                "dmk_watcher_" + std::to_string(_getpid()) + "_" + std::to_string(++s_test_counter);
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
        template <class Pred> static bool wait_until(Pred pred, std::chrono::milliseconds timeout)
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

    // Basic lifecycle

    TEST_F(ConfigWatcherTest, NoStartDestructIsSafe)
    {
        std::atomic<int> hits{0};
        {
            DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, [&hits]() { hits.fetch_add(1); });
            EXPECT_FALSE(watcher.is_running());
        }
        EXPECT_EQ(hits.load(), 0);
    }

    TEST_F(ConfigWatcherTest, StartThenStopIdempotent)
    {
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});

        EXPECT_TRUE(watcher.start());
        EXPECT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));

        EXPECT_TRUE(watcher.start()); // second call is a no-op
        EXPECT_TRUE(watcher.is_running());

        watcher.stop();
        EXPECT_FALSE(watcher.is_running());
        EXPECT_NO_THROW(watcher.stop());
    }

    TEST_F(ConfigWatcherTest, Accessors)
    {
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 173ms, []() {});
        EXPECT_EQ(watcher.ini_path(), m_ini_path.string());
        EXPECT_EQ(watcher.debounce(), 173ms);
    }

    TEST_F(ConfigWatcherTest, StartFailsOnEmptyIniPath)
    {
        DetourModKit::detail::ConfigWatcher watcher("", 50ms, []() {});
        EXPECT_FALSE(watcher.start());
        EXPECT_FALSE(watcher.is_running());
        EXPECT_NO_THROW(watcher.stop());
    }

    // A benign start failure -- the worker's CreateFileW fails fast because the parent directory does not exist -- must
    // NOT take the leak-on-timeout path. That path (leak the whole Impl instead of joining) exists only for a worker
    // genuinely wedged past the 5 s handshake; a worker that reported failure is already returning, so start() joins it
    // cleanly, leaks nothing, and leaves the watcher reusable.
    TEST_F(ConfigWatcherTest, BenignStartFailureDoesNotLeakAndStaysReusable)
    {
        const std::filesystem::path missing = m_temp_dir / "no_such_subdir" / "watched.ini";
        DetourModKit::detail::ConfigWatcher watcher(missing.string(), 50ms, []() {});

        const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::ConfigWatcher);
        EXPECT_FALSE(watcher.start());
        EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::ConfigWatcher), before)
            << "a non-timeout start failure must not take the leak-on-timeout path";

        // Not husked: still reusable, and stop() is safe.
        EXPECT_FALSE(watcher.is_running());
        EXPECT_FALSE(watcher.start());
        EXPECT_NO_THROW(watcher.stop());
    }

    TEST_F(ConfigWatcherTest, IsWorkerThreadFalseFromMainBeforeStart)
    {
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});
        EXPECT_FALSE(watcher.is_worker_thread(std::this_thread::get_id()));
    }

    TEST_F(ConfigWatcherTest, IsWorkerThreadTrueFromCallback)
    {
        std::atomic<bool> observed{false};
        std::atomic<std::thread::id> cb_tid{};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms,
                                                    [&]()
                                                    {
                                                        cb_tid.store(std::this_thread::get_id(),
                                                                     std::memory_order_release);
                                                        observed.store(true, std::memory_order_release);
                                                    });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=2\n");

        ASSERT_TRUE(wait_until([&]() { return observed.load(std::memory_order_acquire); }, 3s));
        EXPECT_TRUE(watcher.is_worker_thread(cb_tid.load(std::memory_order_acquire)));
        EXPECT_FALSE(watcher.is_worker_thread(std::this_thread::get_id()));
        watcher.stop();
    }

    TEST_F(ConfigWatcherTest, IsWorkerThreadFalseAfterStop)
    {
        // The worker publishes its thread id on entry and must clear it again as it exits. Otherwise the stored id
        // outlives the worker, and a later OS-recycled thread id reusing that value would make is_worker_thread()
        // return a false positive, suppressing a genuine stop request as a self-call.
        std::atomic<bool> observed{false};
        std::atomic<std::thread::id> cb_tid{};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms,
                                                    [&]()
                                                    {
                                                        cb_tid.store(std::this_thread::get_id(),
                                                                     std::memory_order_release);
                                                        observed.store(true, std::memory_order_release);
                                                    });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=2\n");
        ASSERT_TRUE(wait_until([&]() { return observed.load(std::memory_order_acquire); }, 3s));

        const std::thread::id worker_tid = cb_tid.load(std::memory_order_acquire);
        ASSERT_NE(worker_tid, std::thread::id{});
        EXPECT_TRUE(watcher.is_worker_thread(worker_tid)) << "the worker id must match while the watcher is running";

        watcher.stop();
        ASSERT_FALSE(watcher.is_running());

        // stop() joins the worker, so by the time it returns the worker has run its exit guard and reset the slot to
        // the no-thread id. The captured worker id must therefore no longer match.
        EXPECT_FALSE(watcher.is_worker_thread(worker_tid))
            << "the stored worker id must reset on worker exit so a recycled thread id cannot suppress a stop";
        EXPECT_FALSE(watcher.is_worker_thread(std::thread::id{}))
            << "a default (no-thread) id must never be reported as the worker";
    }

    TEST_F(ConfigWatcherTest, IsWorkerThreadFalseAfterEarlyExit)
    {
        // Covers the worker's early-return path: the id is published on entry, then CreateFileW fails for a
        // non-existent parent directory and the worker returns before the pump loop. The same scope guard must clear
        // the id on that return, and start()'s failure path joins the worker before returning, so by the time start()
        // reports false the slot is back to the no-thread id. Complements IsWorkerThreadFalseAfterStop, which covers
        // the normal-exit reset with a captured worker id.
        DetourModKit::detail::ConfigWatcher watcher((m_temp_dir / "nonexistent_subdir" / "file.ini").string(), 50ms,
                                                    []() {});

        EXPECT_FALSE(watcher.start());
        EXPECT_FALSE(watcher.is_running());
        EXPECT_FALSE(watcher.is_worker_thread(std::this_thread::get_id()));
        EXPECT_FALSE(watcher.is_worker_thread(std::thread::id{}));
    }

    TEST_F(ConfigWatcherTest, StopWithoutStartIsSafe)
    {
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});
        EXPECT_NO_THROW(watcher.stop());
        EXPECT_NO_THROW(watcher.stop());
        EXPECT_FALSE(watcher.is_running());
    }

    TEST_F(ConfigWatcherTest, DestructorStopsRunningWatcher)
    {
        std::atomic<int> hits{0};
        {
            DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, [&hits]() { hits.fetch_add(1); });
            ASSERT_TRUE(watcher.start());
            ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
            std::this_thread::sleep_for(80ms);
        }
        SUCCEED();
    }

    // Basic fire

    TEST_F(ConfigWatcherTest, BasicFire_CallbackInvokedOnWrite)
    {
        std::atomic<int> hits{0};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 100ms, [&hits]() { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));

        // Let ReadDirectoryChangesW issue its first I/O request before we write.
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=2\n");

        EXPECT_TRUE(wait_until([&]() { return hits.load() >= 1; }, 2s));

        watcher.stop();
        EXPECT_EQ(hits.load(), 1) << "Expected exactly one debounced fire";
    }

    // Debounce

    TEST_F(ConfigWatcherTest, Debounce_BurstyWritesCollapseToOneFire)
    {
        std::atomic<int> hits{0};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 200ms, [&hits]() { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        // Five rapid writes within ~100 ms; a 200 ms debounce must collapse them.
        for (int i = 0; i < 5; ++i)
        {
            write_ini("[S]\nK=" + std::to_string(10 + i) + "\n");
            std::this_thread::sleep_for(15ms);
        }

        EXPECT_TRUE(wait_until([&]() { return hits.load() >= 1; }, 2s));

        // Idle time for any further notification to surface before we stop.
        std::this_thread::sleep_for(400ms);

        watcher.stop();

        // The debounce guarantees consecutive fires are at least debounce_ms (200 ms) apart, so the five sub-100 ms
        // writes provably collapse into a single fire -- they cannot each produce a callback. A second fire is
        // therefore never a debounce-collapse failure: it can only be a distinct, later filesystem notification. The
        // common straggler on NTFS is the lazy writer flushing the file's last-write timestamp to the directory entry
        // well after the write, which surfaces as a separate FILE_NOTIFY_CHANGE_LAST_WRITE outside the burst window
        // (the production Config consumer dedupes that no-op via its content-hash short-circuit). Tolerate that one
        // delayed metadata event while still proving the burst collapsed: one fire, not five.
        const int fires = hits.load();
        EXPECT_GE(fires, 1) << "the debounced burst should fire at least once";
        EXPECT_LE(fires, 2) << "the five rapid writes must collapse; a 2nd fire is at most one delayed filesystem "
                               "metadata notification (e.g. the NTFS lazy-writer last-write flush), not a per-write "
                               "fire";
    }

    // The debounce deadline must be evaluated every pump iteration, not only on the idle WAIT_TIMEOUT branch. A
    // rotating log file typically shares the watched directory, so its sub-debounce writes keep GetOverlappedResultEx
    // completing with non-matching events and the loop never idles. This test keeps a sibling file churning for the
    // whole wait and asserts the single target write still fires.
    TEST_F(ConfigWatcherTest, Debounce_FiresUnderSustainedForeignChurn)
    {
        std::atomic<int> hits{0};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 100ms, [&hits]() { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        std::atomic<bool> stop_churn{false};
        std::thread churn(
            [&]()
            {
                const auto sibling = m_temp_dir / "churn.log";
                int n = 0;
                while (!stop_churn.load(std::memory_order_acquire))
                {
                    std::ofstream out(sibling, std::ios::binary | std::ios::trunc);
                    out << "line " << n++ << "\n";
                    out.close();
                    std::this_thread::sleep_for(15ms);
                }
            });

        // One target write. With the deadline evaluated every iteration, it must fire ~debounce after this write even
        // while the sibling churn keeps the pump continuously busy.
        write_ini("[S]\nK=2\n");

        const bool fired = wait_until([&]() { return hits.load() >= 1; }, 3s);

        stop_churn.store(true, std::memory_order_release);
        churn.join();
        watcher.stop();

        EXPECT_TRUE(fired)
            << "the target reload must fire under sustained foreign-file churn, not be starved until the churn stops";
    }

    // Filename matching must be case-insensitive (ordinal fold, matching NTFS/exFAT semantics). The watcher is
    // configured for an upper-case spelling of the file whose real on-disk name is lower-case; a write to the real
    // file must still fire.
    TEST_F(ConfigWatcherTest, FilenameMatchIsCaseInsensitive)
    {
        std::atomic<int> hits{0};
        const std::string upper_path = (m_temp_dir / "WATCHED.INI").string();
        DetourModKit::detail::ConfigWatcher watcher(upper_path, 100ms, [&hits]() { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=2\n"); // writes m_ini_path == ".../watched.ini"

        EXPECT_TRUE(wait_until([&]() { return hits.load() >= 1; }, 2s))
            << "a write to 'watched.ini' must fire a watcher configured for 'WATCHED.INI' (case-insensitive match)";

        watcher.stop();
    }

    // Rename-swap-save (Notepad++, VSCode)

    TEST_F(ConfigWatcherTest, RenameSwapSave_TriggersReload)
    {
        std::atomic<int> hits{0};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 100ms, [&hits]() { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        // Write sibling .tmp then MoveFileExW over the target -- the atomic save pattern used by Notepad++ and VSCode.
        const std::filesystem::path tmp = m_temp_dir / "watched.ini.tmp";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out << "[S]\nK=99\n";
        }
        const BOOL ok = ::MoveFileExW(tmp.wstring().c_str(), m_ini_path.wstring().c_str(),
                                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        ASSERT_TRUE(ok) << "MoveFileExW failed, GLE=" << ::GetLastError();

        EXPECT_TRUE(wait_until([&]() { return hits.load() >= 1; }, 2s));

        watcher.stop();
    }

    // Stop bound

    TEST_F(ConfigWatcherTest, Stop_ReturnsWithinBound)
    {
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 100ms, []() {});
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));

        // Stop must return within ~200 ms (pump timeout is 100 ms; we give a generous 1 s ceiling to avoid flakiness on
        // loaded CI machines).
        const auto t0 = std::chrono::steady_clock::now();
        watcher.stop();
        const auto elapsed = std::chrono::steady_clock::now() - t0;

        EXPECT_FALSE(watcher.is_running());
        EXPECT_LT(elapsed, 1s);
    }

    // Empty callback is accepted

    TEST_F(ConfigWatcherTest, EmptyCallback_DoesNotCrashOnEvent)
    {
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, {});
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=3\n");
        std::this_thread::sleep_for(300ms);

        EXPECT_NO_THROW(watcher.stop());
    }

    TEST_F(ConfigWatcherTest, Stop_WithIoInFlight_NoCrash)
    {
        // Tight start/stop loop. start() only returns once the first
        // ReadDirectoryChangesW is posted, so I/O is in flight before every stop().
        for (int i = 0; i < 100; ++i)
        {
            DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});
            ASSERT_TRUE(watcher.start());
            watcher.stop();
            EXPECT_FALSE(watcher.is_running());
        }
    }

    TEST_F(ConfigWatcherTest, Overflow_ActuallyExceedsBuffer_CallbackStillFires)
    {
        // 600 siblings with >70-char names push each FILE_NOTIFY_INFORMATION entry past 100 bytes, overflowing the 16
        // KB kernel buffer and driving the ERROR_NOTIFY_ENUM_DIR / zero-byte-completion paths.
        std::atomic<int> hits{0};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 100ms, [&hits]() { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        for (int i = 0; i < 600; ++i)
        {
            const std::filesystem::path sibling =
                m_temp_dir / ("overflow_test_" + std::to_string(i) + "_with_a_fairly_long_padding_string.dat");
            std::ofstream out(sibling, std::ios::binary | std::ios::trunc);
            out << "x";
        }
        // Target write so the debounced callback fires even if every sibling event was dropped during overflow.
        write_ini("[S]\nK=999\n");

        EXPECT_TRUE(wait_until([&]() { return hits.load() >= 1; }, 3s));

        watcher.stop();
        EXPECT_GE(hits.load(), 1) << "Watcher must survive buffer overflow and still fire "
                                     "the debounced callback for the target write.";
    }

    TEST_F(ConfigWatcherTest, ParentDirectoryRemoved_WatcherExitsCleanly)
    {
        // Parent-dir removal surfaces as ERROR_OPERATION_ABORTED from
        // GetOverlappedResultEx. The worker must break the pump loop and the destructor must still run cleanly.
        const std::filesystem::path temp_parent =
            std::filesystem::temp_directory_path() /
            ("dmk_watcher_removetest_" + std::to_string(_getpid()) + "_" + std::to_string(::GetCurrentThreadId()));
        std::filesystem::create_directories(temp_parent);
        const std::filesystem::path ini = temp_parent / "watched.ini";
        {
            std::ofstream out(ini, std::ios::binary | std::ios::trunc);
            out << "[S]\nK=1\n";
        }

        {
            DetourModKit::detail::ConfigWatcher watcher(ini.string(), 50ms, []() {});
            ASSERT_TRUE(watcher.start());
            ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
            std::this_thread::sleep_for(100ms);

            std::error_code ec;
            std::filesystem::remove_all(temp_parent, ec);
            // remove_all may fail because the watcher holds the directory open with FILE_LIST_DIRECTORY + SHARE_DELETE;
            // either outcome is acceptable.

            std::this_thread::sleep_for(300ms);
        }

        // Best-effort cleanup if the directory outlived the watcher.
        std::error_code ec;
        std::filesystem::remove_all(temp_parent, ec);
    }

    TEST_F(ConfigWatcherTest, Stop_FlushesPendingDebounce)
    {
        std::atomic<int> hits{0};
        // 2 s debounce, stop after 200 ms: the pending callback must be flushed during stop() rather than waiting for
        // the timer.
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 2000ms, [&hits]() { hits.fetch_add(1); });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        write_ini("[S]\nK=42\n");

        std::this_thread::sleep_for(200ms);

        watcher.stop();
        EXPECT_EQ(hits.load(), 1) << "stop() must flush the pending debounced callback exactly once";
    }

    TEST_F(ConfigWatcherTest, Construct_InvalidPath_StartReturnsFalse)
    {
        DetourModKit::detail::ConfigWatcher watcher((m_temp_dir / "nonexistent_subdir" / "file.ini").string(), 100ms,
                                                    []() {});
        EXPECT_FALSE(watcher.start());
        EXPECT_FALSE(watcher.is_running());
    }

    // A reload callback that throws must be contained at the invocation site so the throw never unwinds the worker
    // body. Otherwise WatchIoState's destructor would free the OVERLAPPED and notification buffer while the in-flight
    // ReadDirectoryChangesW notify IRP still references them. The deterministic proof that the throw was caught rather
    // than allowed to unwind the loop is that a second edit still fires the callback: had the exception escaped, it
    // would have torn down the whole pump loop, so no further callback could arrive.
    TEST_F(ConfigWatcherTest, ThrowingCallbackIsContainedAndWatcherKeepsPumping)
    {
        std::atomic<int> fires{0};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms,
                                                    [&fires]()
                                                    {
                                                        fires.fetch_add(1);
                                                        throw std::runtime_error("reload callback boom");
                                                    });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));

        write_ini("[S]\nK=2\n");
        ASSERT_TRUE(wait_until([&]() { return fires.load() >= 1; }, 2s)) << "first throwing fire never arrived";

        // Reachable only if the first throw did not unwind (and thereby destroy) the pump loop.
        write_ini("[S]\nK=3\n");
        EXPECT_TRUE(wait_until([&]() { return fires.load() >= 2; }, 2s))
            << "watcher stopped pumping after a throwing callback -- the exception escaped the invocation site";

        // Still alive, and it tears down cleanly on scope exit (the drain runs; no crash from a skipped CancelIoEx).
        EXPECT_TRUE(watcher.is_running());
    }

    // The worker invokes the callback from two sites: the debounce-timeout fire above, and the final flush when it
    // exits with a pending change (stop() / destruction). This covers the flush site: a long debounce means the change
    // is still pending when stop() drives the worker out, so the pending edit flushes through the same guarded
    // fire_reload at the end of the worker body. A throw there must stay contained so stop() joins cleanly rather than
    // letting the exception unwind past the IRP drain.
    TEST_F(ConfigWatcherTest, ThrowingCallbackIsContainedOnStopTimeFlush)
    {
        std::atomic<int> fires{0};
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 2000ms,
                                                    [&fires]()
                                                    {
                                                        fires.fetch_add(1);
                                                        throw std::runtime_error("stop-flush boom");
                                                    });
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        std::this_thread::sleep_for(100ms);

        // Mark a change pending; the 2 s debounce guarantees the timeout fire cannot run before stop().
        write_ini("[S]\nK=9\n");
        std::this_thread::sleep_for(200ms);

        // stop() drives the worker's exit, which flushes the pending change through the guarded fire_reload and then
        // joins. A contained throw means stop() returns without crashing or hanging.
        watcher.stop();

        EXPECT_EQ(fires.load(), 1) << "stop() must flush the pending change exactly once through the guarded callback";
        EXPECT_FALSE(watcher.is_running());
    }

    // is_running() must not read the non-atomic m_impl->worker unique_ptr while start() assigns it and stop() moves it
    // out under start_mutex. Hammer is_running() from one thread while another churns start()/stop(); the accessor uses
    // the atomic worker-thread id, so this must neither crash nor hang.
    TEST_F(ConfigWatcherTest, IsRunningConcurrentWithStartStopIsRaceFree)
    {
        DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});

        std::atomic<bool> stop_reader{false};
        std::thread reader(
            [&]()
            {
                while (!stop_reader.load(std::memory_order_relaxed))
                {
                    (void)watcher.is_running();
                }
            });

        for (int i = 0; i < 20; ++i)
        {
            (void)watcher.start();
            watcher.stop();
        }

        stop_reader.store(true, std::memory_order_relaxed);
        reader.join();

        EXPECT_FALSE(watcher.is_running());
    }
} // namespace

// Loader-lock detach tests. The real loader-lock branch (detected by reading the PEB inside DllMain) cannot be reached
// from user code in a normal test process, so the runtime exposes a test-only function pointer override that reports
// "loader lock held" on demand. These tests exercise the leak-on-loader-lock branch in ~ConfigWatcher: the worker is
// detached instead of joined, the Impl is moved into a per-call heap cell allocated via new (std::nothrow) that
// outlives the destructor, and the watcher does not deadlock.
namespace DetourModKit::detail
{
    extern bool (*g_config_watcher_loader_lock_override)() noexcept;
} // namespace DetourModKit::detail

namespace
{
    using DetourModKit::detail::g_config_watcher_loader_lock_override;

    bool always_true_loader_lock() noexcept
    {
        return true;
    }

    class ConfigWatcherLoaderLockTest : public ConfigWatcherTest
    {
    protected:
        void TearDown() override
        {
            g_config_watcher_loader_lock_override = nullptr;
            ConfigWatcherTest::TearDown();
        }
    };

    TEST_F(ConfigWatcherLoaderLockTest, DestructorWithoutLoaderLockJoinsCleanly)
    {
        std::atomic<int> hits{0};
        const auto t_start = std::chrono::steady_clock::now();
        {
            DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, [&hits]() { hits.fetch_add(1); });
            ASSERT_TRUE(watcher.start());
            ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
        }
        const auto elapsed = std::chrono::steady_clock::now() - t_start;

        // Without the loader-lock override the destructor takes the normal join path. A clean join completes well under
        // a second; a hang (e.g. a regression that joined under loader lock) would blow past the GetOverlappedResultEx
        // pump timeout repeatedly.
        EXPECT_LT(elapsed, std::chrono::seconds(3));
    }

    TEST_F(ConfigWatcherLoaderLockTest, DestructorUnderLoaderLockDoesNotHang)
    {
        std::atomic<int> hits{0};
        const auto t_start = std::chrono::steady_clock::now();
        {
            DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, [&hits]() { hits.fetch_add(1); });
            ASSERT_TRUE(watcher.start());
            ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));

            // Flip the override on so ~ConfigWatcher takes the leak branch. The detach path must not block, must not
            // call join(), and must keep the worker's captured pointers valid by leaking the Impl into a static vector.
            g_config_watcher_loader_lock_override = &always_true_loader_lock;
        }
        const auto elapsed = std::chrono::steady_clock::now() - t_start;

        // Under loader lock the destructor returns essentially immediately:
        // request_stop on the worker, detach, leak. The OS thread continues running but no longer blocks the
        // destructor.
        EXPECT_LT(elapsed, std::chrono::seconds(2)) << "Loader-lock detach branch must not join the worker";
    }

    TEST_F(ConfigWatcherLoaderLockTest, MultipleLoaderLockTeardownsAreSafe)
    {
        // Confirms the per-call heap leak path accepts multiple invocations without tripping the single-slot overwrite
        // hazard that the
        // Logger::shutdown_internal per-call-cell discipline avoids. Each teardown allocates its own cell via new
        // (std::nothrow), so prior leaked Impls are never overwritten.
        for (int i = 0; i < 3; ++i)
        {
            DetourModKit::detail::ConfigWatcher watcher(m_ini_path.string(), 50ms, []() {});
            ASSERT_TRUE(watcher.start());
            ASSERT_TRUE(wait_until([&]() { return watcher.is_running(); }, 1s));
            g_config_watcher_loader_lock_override = &always_true_loader_lock;
            // Watcher destructor on scope exit takes the leak path.
        }
        SUCCEED();
    }
} // namespace
