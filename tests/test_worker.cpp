#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <latch>
#include <memory>
#include <stdexcept>
#include <stop_token>
#include <system_error>
#include <thread>
#include <vector>

#include "DetourModKit/detail/worker.hpp"
#include "DetourModKit/diagnostics.hpp"

// Neither header is seam-gated, and the reaper cases below are not either: the reaper is ordinary library code and
// the allocation probe is a plain test helper. Only the StoppableWorker seam probes further down need the gate.
#include "internal/lifecycle_reaper.hpp"
#include "test_alloc_probe.hpp"

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

// Tearing a worker down from inside its own body is a self-join. shutdown() must detect that the current thread is the
// worker thread and hand the thread to the off-thread reaper rather than std::thread::join() itself, which raises
// std::system_error(resource_deadlock_would_occur) out of a noexcept path and terminates the process. The reaper joins
// off-thread and releases the module reference, so the self-shutdown records NO permanent Worker leak on its success
// path. The sync flags are shared_ptr so they outlive the reaped worker thread past the end of the test.
TEST(StoppableWorker, SelfShutdownFromBodyReapsOffThreadInsteadOfTerminating)
{
    using namespace DetourModKit::diagnostics;
    const std::size_t before = intentional_leak_count(LeakSubsystem::Worker);

    auto self = std::make_shared<std::atomic<StoppableWorker *>>(nullptr);
    auto did_shutdown = std::make_shared<std::atomic<bool>>(false);

    auto worker = std::make_unique<StoppableWorker>("unit-worker-self-join",
                                                    [self, did_shutdown](std::stop_token)
                                                    {
                                                        StoppableWorker *me = nullptr;
                                                        while ((me = self->load(std::memory_order_acquire)) == nullptr)
                                                        {
                                                            std::this_thread::yield();
                                                        }
                                                        // Self-teardown from inside the body. After this returns the
                                                        // body touches nothing owned by the worker, so the outer
                                                        // worker.reset() below is safe even though the reaper may still
                                                        // be joining this thread.
                                                        me->shutdown();
                                                        did_shutdown->store(true, std::memory_order_release);
                                                    });

    self->store(worker.get(), std::memory_order_release);

    while (!did_shutdown->load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // The self-shutdown handed the thread to the reaper; the outer destruction is an idempotent no-op (state latched
    // Stopped, and m_thread was moved out). No terminate, and no permanent Worker leak was recorded.
    EXPECT_NO_THROW(worker.reset());
    EXPECT_EQ(intentional_leak_count(LeakSubsystem::Worker), before)
        << "a self-shutdown must reap off-thread (no permanent leak), not detach-and-leak";
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
    // Raw `throw 42` must land in the catch-all arm; escaping it would call std::terminate before the test can finish.
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

TEST(StoppableWorker, NameAccessorReturnsConstructionName)
{
    StoppableWorker w("unit-worker-named",
                      [](std::stop_token st)
                      {
                          while (!st.stop_requested())
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(2));
                          }
                      });
    EXPECT_EQ(w.name(), "unit-worker-named");
}

TEST(StoppableWorker, ConcurrentIsRunningAndRequestStopWithShutdown)
{
    // is_running() reads liveness from atomics, and request_stop() signals the copied stop_source instead of the
    // std::jthread handle that shutdown() mutates via join()/detach(). Poll both from spawned threads while the main
    // thread tears the worker down: the interleaving must stay race-free, and is_running() must report false once
    // shutdown() completes.
    std::atomic<bool> body_entered{false};
    StoppableWorker w("unit-worker-race",
                      [&body_entered](std::stop_token st)
                      {
                          body_entered.store(true, std::memory_order_release);
                          while (!st.stop_requested())
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(1));
                          }
                      });

    while (!body_entered.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    constexpr int poller_count = 3;
    std::atomic<bool> poll_stop{false};
    std::latch pollers_ready(poller_count);
    std::vector<std::thread> pollers;
    for (int i = 0; i < poller_count; ++i)
    {
        pollers.emplace_back(
            [&w, &poll_stop, &pollers_ready]()
            {
                // Signal readiness, then keep polling so every poller is actively observing the worker while the main
                // thread runs shutdown() (the race window this test guards).
                pollers_ready.count_down();
                while (!poll_stop.load(std::memory_order_acquire))
                {
                    (void)w.is_running();
                    w.request_stop();
                }
            });
    }

    // Do not tear the worker down until all pollers have started, so the concurrency is actually exercised.
    pollers_ready.wait();
    w.shutdown();
    EXPECT_FALSE(w.is_running());

    poll_stop.store(true, std::memory_order_release);
    for (auto &t : pollers)
    {
        t.join();
    }
}

// A body that returns on its own is no longer live even though its thread handle still needs joining.
TEST(StoppableWorker, HasExitedAfterBodyReturnsOnItsOwn)
{
    std::atomic<bool> release{false};
    StoppableWorker w("exit-test",
                      [&release](std::stop_token)
                      {
                          while (!release.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(1));
                          }
                          // Body returns on its own, not because stop was requested.
                      });

    EXPECT_TRUE(w.is_running());

    release.store(true, std::memory_order_release);
    for (int i = 0; i < 1000 && w.is_running(); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    EXPECT_FALSE(w.is_running()) << "an exited worker must not report running";

    // shutdown() joins the already-exited thread cleanly (off the worker's own thread).
    EXPECT_NO_THROW(w.shutdown());
    EXPECT_FALSE(w.is_running());
}

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    // These throwing probes exist only in test-enabled builds.
    extern void (*g_worker_post_thread_start_seam)();
    extern void (*g_worker_join_fail_seam)();
} // namespace DetourModKit::detail

namespace
{
    class StoppableWorkerProof : public ::testing::Test
    {
    protected:
        void TearDown() override
        {
            DetourModKit::detail::g_worker_post_thread_start_seam = nullptr;
            DetourModKit::detail::g_worker_join_fail_seam = nullptr;
        }
    };

    // Mirrors ReloadServicer::Channel: the state the still-running body reads lives in a member declared BEFORE the
    // worker, so ~ReapableOwner destroys the worker (joining the body) first and only then ends that member's
    // lifetime. The body may therefore read `canary` for as long as it runs, and live_count returning to baseline is
    // a signal that the off-thread join already completed rather than merely that destruction started.
    struct ReapableOwner
    {
        static constexpr int CANARY = 0x0FF1CE;
        static std::atomic<int> live_count;

        struct Canary
        {
            std::atomic<int> value{CANARY};

            Canary() { live_count.fetch_add(1, std::memory_order_acq_rel); }

            ~Canary()
            {
                value.store(0, std::memory_order_release);
                live_count.fetch_sub(1, std::memory_order_acq_rel);
            }

            Canary(const Canary &) = delete;
            Canary &operator=(const Canary &) = delete;
        };

        Canary canary;
        std::unique_ptr<StoppableWorker> worker;
    };
    std::atomic<int> ReapableOwner::live_count{0};
} // namespace

TEST_F(StoppableWorkerProof, PostStartFailureAndSelfRetirementPreserveOwnership)
{
    using namespace DetourModKit::diagnostics;

    // Verify that a post-thread-start construction failure balances the module reference.
    const std::size_t leaks_before = intentional_leak_count(LeakSubsystem::Worker);
    DetourModKit::detail::g_worker_post_thread_start_seam = []
    { throw std::runtime_error("post-thread-start inject"); };

    EXPECT_THROW(
        {
            StoppableWorker doomed("post-start-failure",
                                   [](std::stop_token st)
                                   {
                                       while (!st.stop_requested())
                                       {
                                           std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                       }
                                   });
        },
        std::runtime_error);

    DetourModKit::detail::g_worker_post_thread_start_seam = nullptr;
    EXPECT_EQ(intentional_leak_count(LeakSubsystem::Worker), leaks_before)
        << "a post-thread-start construction failure must release the module reference, not leak it";

    // Then verify that self-retirement preserves the owning object's lifetime.
    const int owners_before = ReapableOwner::live_count.load(std::memory_order_acquire);
    auto trigger = std::make_shared<std::atomic<bool>>(false);
    auto alive_at_retire = std::make_shared<std::atomic<bool>>(false);
    auto alive_after_retire = std::make_shared<std::atomic<bool>>(false);

    auto owner_holder = std::make_shared<std::unique_ptr<ReapableOwner>>(std::make_unique<ReapableOwner>());
    ReapableOwner *const owner = owner_holder->get();
    owner->worker = std::make_unique<StoppableWorker>(
        "self-retiring-owner",
        [owner, owner_holder, trigger, alive_at_retire, alive_after_retire](std::stop_token st)
        {
            while (!trigger->load(std::memory_order_acquire) && !st.stop_requested())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            if (st.stop_requested())
            {
                return;
            }
            alive_at_retire->store(owner->canary.value.load(std::memory_order_acquire) == ReapableOwner::CANARY,
                                   std::memory_order_release);
            DetourModKit::detail::reap_owner(std::move(*owner_holder));
            // The reaper is now blocked joining this thread, so the canary member is still within its lifetime.
            alive_after_retire->store(owner->canary.value.load(std::memory_order_acquire) == ReapableOwner::CANARY,
                                      std::memory_order_release);
        });

    trigger->store(true, std::memory_order_release);

    // Wait for the reaper to join the worker and finish destroying the owner. The canary is destroyed after the
    // worker member, so live_count returning to baseline happens strictly after the off-thread join.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (ReapableOwner::live_count.load(std::memory_order_acquire) != owners_before &&
           std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    EXPECT_TRUE(alive_at_retire->load(std::memory_order_acquire)) << "owner must be alive when the body self-retires";
    EXPECT_TRUE(alive_after_retire->load(std::memory_order_acquire))
        << "owner must stay alive after reap_owner, until the off-thread join completes";
    EXPECT_EQ(ReapableOwner::live_count.load(std::memory_order_acquire), owners_before)
        << "the reaper must destroy the owner exactly once, off the worker thread";
}

namespace
{
    // Drives one shutdown() whose retirement operations are made to fail, and returns the recorded leak delta. The
    // seam fires once before join() and again before the containment detach(), so `throws` selects which of the two
    // failure shapes is exercised.
    std::size_t run_contained_shutdown_failure(int throws)
    {
        using namespace DetourModKit::diagnostics;
        static std::atomic<int> s_remaining{0};
        s_remaining.store(throws, std::memory_order_release);

        DetourModKit::detail::g_worker_join_fail_seam = []
        {
            if (s_remaining.fetch_sub(1, std::memory_order_acq_rel) > 0)
            {
                throw std::system_error(std::make_error_code(std::errc::no_such_process));
            }
        };

        const std::size_t leaks_before = intentional_leak_count(LeakSubsystem::Worker);
        {
            StoppableWorker w("join-failure",
                              [](std::stop_token st)
                              {
                                  while (!st.stop_requested())
                                  {
                                      std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                  }
                              });
            // Let the body reach Running before tearing down. The destruction that follows the explicit shutdown is a
            // Stopped no-op and must not retry either failed operation.
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            EXPECT_NO_THROW(w.shutdown());
            EXPECT_FALSE(w.is_running());
        }
        DetourModKit::detail::g_worker_join_fail_seam = nullptr;
        return intentional_leak_count(LeakSubsystem::Worker) - leaks_before;
    }
} // namespace

// Join and detach failures must not escape shutdown's noexcept boundary or release the worker's module reference.
TEST_F(StoppableWorkerProof, ShutdownContainsJoinFailure)
{
    // One throw: join() fails and the containment detach() succeeds, which is the documented recovery. The module
    // reference is abandoned rather than released into a thread of uncertain completion.
    EXPECT_EQ(run_contained_shutdown_failure(1), 1u)
        << "a contained join failure must detach, abandon the module reference, and record it";

    // Two throws: the containment detach() fails as well, so the still-joinable jthread is retained instead of being
    // destroyed (which would re-run the failed join from a noexcept destructor and terminate).
    EXPECT_EQ(run_contained_shutdown_failure(2), 1u)
        << "a contained join AND detach failure must retain the thread and record exactly one abandoned reference";
}
#endif // DMK_ENABLE_TEST_SEAMS

// A self-retiring poller can reach the reaper under host OOM, so queuing must not need the heap. The reserve is filled
// at reaper construction; this proves an enqueue still lands with every allocation failing, and that retirement runs
// before destruction rather than beginning the destructor while the worker body can still access the owner.
TEST(LifecycleReaperTest, SharedOwnerRetirementNeedsNoAllocation)
{
    struct Sentinel
    {
        std::atomic<int> *destroyed;
        std::atomic<int> *destroyed_before_retire;
        std::atomic<bool> retired{false};

        ~Sentinel()
        {
            if (!retired.load(std::memory_order_acquire))
            {
                destroyed_before_retire->fetch_add(1, std::memory_order_release);
            }
            destroyed->fetch_add(1, std::memory_order_release);
        }
    };

    // Process-lifetime counters: a parcel the reaper has not finished with still points at them, and a sentinel
    // outliving this frame would otherwise write into reclaimed stack of the shared test binary.
    static std::atomic<int> destroyed{0};
    static std::atomic<int> destroyed_before_retire{0};
    const auto retire = [](void *raw_owner) noexcept -> bool
    {
        static_cast<Sentinel *>(raw_owner)->retired.store(true, std::memory_order_release);
        return true;
    };

    // Warm the process-lifetime reaper (and its reserve) while allocation still works.
    {
        auto warm = std::make_shared<Sentinel>(&destroyed, &destroyed_before_retire);
        std::shared_ptr<void> owner = warm;
        warm.reset();
        ASSERT_TRUE(detail::reap_shared_owner(owner, retire));
        EXPECT_EQ(owner, nullptr);
    }

    auto sentinel = std::make_shared<Sentinel>(&destroyed, &destroyed_before_retire);
    std::shared_ptr<void> owner = sentinel;
    sentinel.reset();

    bool queued = false;
    {
        dmk_test::AllocFailScope fail(0);
        queued = detail::reap_shared_owner(owner, retire);
    }
    EXPECT_TRUE(queued) << "the reserved queue node must absorb a retirement requested under total OOM";
    EXPECT_EQ(owner, nullptr) << "a queued retirement transfers the caller's reference";

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (destroyed.load(std::memory_order_acquire) < 2 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    // ASSERT, not EXPECT: the ordering check below is vacuous until both sentinels have actually been destroyed.
    ASSERT_EQ(destroyed.load(std::memory_order_acquire), 2) << "the reaper must drop both references";
    EXPECT_EQ(destroyed_before_retire.load(std::memory_order_acquire), 0)
        << "the reaper must complete retirement while the owner is still alive";
}

// The reaper cannot run down a worker it was given no callback for, and releasing the reference anyway would destroy
// an owner whose body may still be running. A missing callback must therefore be refused at the door, leaving the
// caller's reference intact so its own retention takes over.
TEST(LifecycleReaperTest, RetirementWithoutARundownCallbackIsRefused)
{
    struct Sentinel
    {
        std::atomic<int> *destroyed;
        ~Sentinel() { destroyed->fetch_add(1, std::memory_order_release); }
    };

    std::atomic<int> destroyed{0};
    auto sentinel = std::make_shared<Sentinel>(&destroyed);
    std::shared_ptr<void> owner = sentinel;

    EXPECT_FALSE(detail::reap_shared_owner(owner, nullptr))
        << "a retirement with no rundown callback must be refused, not queued";
    EXPECT_NE(owner, nullptr) << "a refused retirement leaves the caller's reference untouched";
    EXPECT_EQ(destroyed.load(std::memory_order_acquire), 0) << "a refused retirement must not release the owner";

    owner.reset();
    sentinel.reset();
    EXPECT_EQ(destroyed.load(std::memory_order_acquire), 1);
}
