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
