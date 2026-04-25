#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <stop_token>
#include <thread>

#include "DetourModKit/worker.hpp"

using namespace DetourModKit;

TEST(StoppableWorker, RunsAndStops)
{
    std::atomic<int> counter{0};
    {
        StoppableWorker w("unit-worker",
                          [&counter](std::stop_token st)
                          {
                              while (!st.stop_requested())
                              {
                                  counter.fetch_add(1, std::memory_order_relaxed);
                                  std::this_thread::sleep_for(std::chrono::milliseconds(5));
                              }
                          });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        EXPECT_TRUE(w.is_running());
    }
    EXPECT_GT(counter.load(), 0);
}

TEST(StoppableWorker, RequestStopSignalsButDoesNotJoin)
{
    std::atomic<bool> observed_stop{false};
    StoppableWorker w("unit-worker-2",
                      [&observed_stop](std::stop_token st)
                      {
                          while (!st.stop_requested())
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(5));
                          }
                          observed_stop.store(true, std::memory_order_release);
                      });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    w.request_stop();
    w.shutdown();
    EXPECT_TRUE(observed_stop.load());
}

TEST(StoppableWorker, ExceptionFirewallDoesNotPropagateFromBody)
{
    std::atomic<int> invocations{0};
    auto make_worker = [&]()
    {
        StoppableWorker w("unit-worker-throws",
                          [&invocations](std::stop_token)
                          {
                              invocations.fetch_add(1, std::memory_order_relaxed);
                              throw std::runtime_error("simulated body failure");
                          });
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    };

    EXPECT_NO_THROW(make_worker());
    EXPECT_GE(invocations.load(), 1);
}

TEST(StoppableWorker, DestructorOfRunningWorkerDoesNotThrow)
{
    std::atomic<bool> saw_stop{false};
    EXPECT_NO_THROW({
        StoppableWorker w("unit-worker-destroy-running",
                          [&saw_stop](std::stop_token st)
                          {
                              while (!st.stop_requested())
                              {
                                  std::this_thread::sleep_for(std::chrono::milliseconds(2));
                              }
                              saw_stop.store(true, std::memory_order_release);
                          });
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    });
    EXPECT_TRUE(saw_stop.load());
}

TEST(StoppableWorker, EmptyBodyDoesNotStartThreadAndIsNotRunning)
{
    StoppableWorker w("unit-worker-empty", std::function<void(std::stop_token)>{});
    EXPECT_FALSE(w.is_running());
    EXPECT_EQ(w.name(), "unit-worker-empty");

    EXPECT_NO_THROW(w.request_stop());
    EXPECT_NO_THROW(w.shutdown());
    EXPECT_NO_THROW(w.shutdown());
    EXPECT_FALSE(w.is_running());
}

TEST(StoppableWorker, UnknownExceptionFromBodyIsSwallowed)
{
    // Raw `throw 42` must land in the catch-all arm; escaping it would
    // call std::terminate before the test can finish.
    std::atomic<bool> entered{false};
    EXPECT_NO_THROW({
        StoppableWorker w("unit-worker-unknown-throw",
                          [&entered](std::stop_token)
                          {
                              entered.store(true, std::memory_order_release);
                              throw 42;
                          });
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    });
    EXPECT_TRUE(entered.load());
}

TEST(StoppableWorker, ShutdownThenRequestStopIsNoOp)
{
    std::atomic<int> ticks{0};
    StoppableWorker w("unit-worker-shutdown-then-stop",
                      [&ticks](std::stop_token st)
                      {
                          while (!st.stop_requested())
                          {
                              ticks.fetch_add(1, std::memory_order_relaxed);
                              std::this_thread::sleep_for(std::chrono::milliseconds(2));
                          }
                      });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    w.shutdown();
    EXPECT_FALSE(w.is_running());
    EXPECT_NO_THROW(w.request_stop());
    EXPECT_NO_THROW(w.shutdown());
}

TEST(StoppableWorker, RequestStopIsIdempotent)
{
    std::atomic<bool> observed{false};
    StoppableWorker w("unit-worker-idempotent-stop",
                      [&observed](std::stop_token st)
                      {
                          while (!st.stop_requested())
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(2));
                          }
                          observed.store(true, std::memory_order_release);
                      });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    w.request_stop();
    w.request_stop();
    w.request_stop();
    w.shutdown();
    EXPECT_TRUE(observed.load());
}

TEST(StoppableWorker, NameSurvivesMoveIntoBody)
{
    StoppableWorker w("unit-worker-named", [](std::stop_token st)
                      {
                          while (!st.stop_requested())
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(2));
                          } });
    EXPECT_EQ(w.name(), "unit-worker-named");
}
