#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "DetourModKit/input.hpp"

#include "internal/input_binding_gate.hpp"
#include "internal/input_delivery_scope.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;

// tests/lifecycle/test_input_gate_abba.cpp covers the unbounded two-gate composition. This case isolates the marker
// that identifies a mandatory consumer span.
TEST(BindingGateTest, TeardownConsumerCodeIsIdentifiedWhenTheDepthStoreRefuses)
{
    const detail::DeliveryTlsOwner delivery_tls;
    ASSERT_TRUE(delivery_tls.reserved());
    ASSERT_TRUE(detail::set_delivery_scope_store_failure_for_test(true));

    std::atomic<int> balancing{0};
    std::atomic<bool> marked_inside{false};
    detail::HoldGate gate;
    gate.active_entries = 1;
    gate.forwarded_active = true;
    gate.on_state_change = [&](bool active)
    {
        balancing.fetch_add(1, std::memory_order_relaxed);
        marked_inside.store(detail::current_thread_in_delivery(), std::memory_order_release);
        if (!active)
        {
            // The frame owns this mandatory span. A nested release must defer its claim instead of wait on itself.
            gate.release();
        }
    };
    gate.release();
    (void)detail::set_delivery_scope_store_failure_for_test(false);

    EXPECT_EQ(balancing.load(std::memory_order_relaxed), 1);
    EXPECT_TRUE(marked_inside.load(std::memory_order_acquire))
        << "a teardown span whose depth store refused must still identify its own thread";
    EXPECT_FALSE(detail::current_thread_in_delivery()) << "the span must be unrecorded once it ends";
}

// The unrelated release must drain before its caller destroys captured state. A process-wide callback marker cannot
// authorize that thread to skip rundown.
TEST(BindingGateTest, UnrelatedThreadStillWaitsOutAnotherThreadsTeardownSpan)
{
    const detail::DeliveryTlsOwner delivery_tls;
    ASSERT_TRUE(delivery_tls.reserved());

    std::atomic<bool> inside_callback{false};
    std::atomic<bool> unrelated_saw_itself_in_delivery{true};
    std::atomic<bool> release_callback{false};
    std::atomic<bool> waiter_returned{false};

    detail::HoldGate gate;
    gate.active_entries = 1;
    gate.forwarded_active = true;
    gate.on_state_change = [&](bool)
    {
        inside_callback.store(true, std::memory_order_release);
        while (!release_callback.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    // The owner thread arms its own seam. An atomic reports the outcome because a fatal worker assertion skips the
    // required balance edge.
    std::atomic<bool> store_failure_armed{false};
    std::thread owner(
        [&]
        {
            store_failure_armed.store(
                detail::set_delivery_scope_store_failure_for_test(true),
                std::memory_order_release
            );
            if (!store_failure_armed.load(std::memory_order_acquire))
            {
                return;
            }
            gate.release();
            (void)detail::set_delivery_scope_store_failure_for_test(false);
        }
    );

    // The bounded wait detects a registration-slot failure without a permanent spin.
    const auto callback_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!inside_callback.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < callback_deadline)
    {
        std::this_thread::yield();
    }
    if (!inside_callback.load(std::memory_order_acquire))
    {
        // Open the callback barrier before joining so the owner exits whichever side of it it is on.
        release_callback.store(true, std::memory_order_release);
        owner.join();
        FAIL() << "the owner thread never reached its teardown callback; store-failure seam armed: "
               << store_failure_armed.load(std::memory_order_acquire);
    }
    unrelated_saw_itself_in_delivery.store(detail::current_thread_in_delivery(), std::memory_order_release);

    std::thread waiter(
        [&]
        {
            gate.release();
            waiter_returned.store(true, std::memory_order_release);
        }
    );

    std::this_thread::sleep_for(std::chrono::milliseconds{40});
    const bool returned_early = waiter_returned.load(std::memory_order_acquire);

    release_callback.store(true, std::memory_order_release);
    waiter.join();
    owner.join();

    EXPECT_FALSE(unrelated_saw_itself_in_delivery.load(std::memory_order_acquire))
        << "another thread's teardown span must not make this thread read as callback-entrant";
    EXPECT_FALSE(
        returned_early
    ) << "a control-plane release on an unrelated thread must wait out the other thread's consumer span";
    EXPECT_TRUE(waiter_returned.load(std::memory_order_acquire));
}

// Several combo entries share one HoldGate. Only aggregate 0->1 and 1->0 transitions reach the consumer.
TEST(BindingGateTest, HoldGateMultiComboForwardsOnlyAggregateEdges)
{
    std::vector<bool> seq;
    detail::HoldGate gate;
    gate.on_state_change = [&](bool active) { seq.push_back(active); };

    gate.deliver(true);  // combo A pressed           -> 0->1: one held edge
    gate.deliver(true);  // combo B pressed (A held)  -> 1->2: no forward (no duplicate raise)
    gate.deliver(false); // combo A released (B held) -> 2->1: no forward (still held via B)
    ASSERT_EQ(seq.size(), 1u);
    EXPECT_TRUE(seq[0]);

    gate.deliver(false); // combo B released          -> 1->0: one released edge
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_FALSE(seq[1]);
}

// Control: a single-combo Hold still delivers exactly one true then one false, unchanged by the refcount.
TEST(BindingGateTest, HoldGateSingleComboDeliversBalancedPair)
{
    std::vector<bool> seq;
    detail::HoldGate gate;
    gate.on_state_change = [&](bool active) { seq.push_back(active); };
    gate.deliver(true);
    gate.deliver(false);
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_TRUE(seq[0]);
    EXPECT_FALSE(seq[1]);
}

// The zero active count must absorb a duplicate false edge. A negative count suppresses the next legitimate raise.
TEST(BindingGateTest, HoldGateSurplusFalseIsSwallowed)
{
    std::vector<bool> seq;
    detail::HoldGate gate;
    gate.on_state_change = [&](bool active) { seq.push_back(active); };
    gate.deliver(false); // no outstanding true -> swallowed
    EXPECT_TRUE(seq.empty());
    gate.deliver(true);  // 0->1 still raises correctly
    gate.deliver(false); // 1->0
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_TRUE(seq[0]);
    EXPECT_FALSE(seq[1]);
}

// Two active combos need one terminal false edge on guard release. The released latch then absorbs every later edge.
TEST(BindingGateTest, HoldGateReleaseWhileMultiComboHeldSynthesizesOneFalse)
{
    std::vector<bool> seq;
    detail::HoldGate gate;
    gate.on_state_change = [&](bool active) { seq.push_back(active); };
    gate.deliver(true); // A
    gate.deliver(true); // B (no forward)
    ASSERT_EQ(seq.size(), 1u);
    gate.release(); // still held via both entries -> one balancing false
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_FALSE(seq[1]);
    gate.deliver(false); // post-release edges swallowed
    gate.deliver(true);
    EXPECT_EQ(seq.size(), 2u);
}

// The release caller can destroy callback captures after rundown. Its thread cannot return while this callback stays
// parked.
TEST(BindingGateTest, PressGateReleaseWaitsOutInFlightDelivery)
{
    detail::PressGate gate;
    std::atomic<int> calls{0};
    std::atomic<bool> in_callback{false};
    std::atomic<bool> may_finish{false};
    gate.on_press = [&]()
    {
        calls.fetch_add(1, std::memory_order_relaxed);
        in_callback.store(true, std::memory_order_release);
        while (!may_finish.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    std::thread deliverer([&]() { gate.deliver(); });
    while (!in_callback.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::atomic<bool> release_returned{false};
    std::thread releaser(
        [&]()
        {
            gate.release();
            release_returned.store(true, std::memory_order_release);
        }
    );

    // While the callback is parked, release() must be blocked behind it.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_FALSE(release_returned.load(std::memory_order_acquire))
        << "release() must not return while on_press is still executing";

    may_finish.store(true, std::memory_order_release);
    releaser.join();
    deliverer.join();
    EXPECT_TRUE(release_returned.load(std::memory_order_acquire));
    EXPECT_EQ(calls.load(std::memory_order_relaxed), 1);

    gate.deliver(); // post-release: swallowed
    EXPECT_EQ(calls.load(std::memory_order_relaxed), 1);
}

// The callback releases its own gate. Rundown must defer until delivery ends, and later deliveries must stay
// suppressed.
TEST(BindingGateTest, PressGateSelfReleaseFromCallbackDoesNotDeadlock)
{
    detail::PressGate gate;
    int calls = 0;
    gate.on_press = [&]()
    {
        ++calls;
        gate.release(); // self-release on the delivering thread
    };
    gate.deliver(); // must return (no deadlock)
    EXPECT_EQ(calls, 1);
    gate.deliver(); // released -> swallowed
    EXPECT_EQ(calls, 1);
}

// Only the current thread can claim callback admission. An unrelated release still owes rundown of the captured state.
TEST(BindingGateTest, DeliveryMarkerIsExactPerThread)
{
    const detail::DeliveryTlsOwner delivery_tls;
    ASSERT_TRUE(delivery_tls.reserved());
    EXPECT_FALSE(detail::current_thread_in_delivery());

    std::atomic<bool> scope_open{false};
    std::atomic<bool> may_finish{false};
    std::atomic<bool> observed_in_delivery{true};
    std::thread observer(
        [&]()
        {
            while (!scope_open.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            observed_in_delivery.store(detail::current_thread_in_delivery(), std::memory_order_release);
            may_finish.store(true, std::memory_order_release);
        }
    );

    {
        const detail::DeliveryScope scope;
        EXPECT_TRUE(scope.admitted()) << "a healthy process must be able to record a delivery frame";
        EXPECT_TRUE(detail::current_thread_in_delivery());
        scope_open.store(true, std::memory_order_release);
        while (!may_finish.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    observer.join();
    EXPECT_FALSE(observed_in_delivery.load(std::memory_order_acquire))
        << "a frame open on one thread must not make another thread read as callback-entrant";
    EXPECT_FALSE(detail::current_thread_in_delivery());
}

// A nested delivery (a callback that drives a second gate) must not clear the outer frame when it unwinds.
TEST(BindingGateTest, DeliveryMarkerNestsWithoutLosingDepth)
{
    const detail::DeliveryTlsOwner delivery_tls;
    ASSERT_TRUE(delivery_tls.reserved());
    {
        const detail::DeliveryScope outer;
        ASSERT_TRUE(outer.admitted());
        {
            const detail::DeliveryScope inner;
            EXPECT_TRUE(inner.admitted());
            EXPECT_TRUE(detail::current_thread_in_delivery());
        }
        EXPECT_TRUE(detail::current_thread_in_delivery());
    }
    EXPECT_FALSE(detail::current_thread_in_delivery());
}

// The span's own thread cannot wait for its balancing callback. A second control-plane release still waits for that
// span to end.
TEST(BindingGateTest, HoldGateReleaseReentryFromItsOwnBalancingEdgeReturns)
{
    detail::HoldGate gate;
    std::atomic<int> calls{0};
    gate.on_state_change = [&](bool active)
    {
        calls.fetch_add(1, std::memory_order_relaxed);
        if (!active)
        {
            gate.release(); // re-entrant, on the thread that owns the teardown claim
        }
    };

    gate.deliver(true);
    ASSERT_EQ(calls.load(std::memory_order_relaxed), 1);

    std::atomic<bool> returned{false};
    std::thread releaser(
        [&]()
        {
            gate.release();
            returned.store(true, std::memory_order_release);
        }
    );
    releaser.join();

    EXPECT_TRUE(returned.load(std::memory_order_acquire));
    EXPECT_EQ(calls.load(std::memory_order_relaxed), 2) << "exactly one balancing edge, emitted once";
    EXPECT_FALSE(gate.forwarded_active);
    EXPECT_FALSE(gate.teardown_active);
}

// The shared enabled flag gates PressGate delivery, matching BindingGuard::is_active() (the guard clears it on
// release).
TEST(BindingGateTest, PressGateEnabledFlagGatesDelivery)
{
    detail::PressGate gate;
    auto enabled = std::make_shared<std::atomic<bool>>(true);
    gate.enabled = enabled;
    int calls = 0;
    gate.on_press = [&]() { ++calls; };
    gate.deliver();
    EXPECT_EQ(calls, 1);
    enabled->store(false, std::memory_order_release);
    gate.deliver();
    EXPECT_EQ(calls, 1);
}

// release() propagates a balance-edge exception after it clears forwarded_active. A repeated release stays inert, and
// the composed guard still removes consume suppression.
TEST(BindingGateTest, HoldGateReleaseIsExceptionSafeWhenBalancingCallbackThrows)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);
    int falses = 0;
    gate.on_state_change = [&falses](bool active)
    {
        if (!active)
        {
            ++falses;
            throw std::runtime_error("release-edge callback");
        }
    };
    gate.deliver(true); // held: a true edge is outstanding

    EXPECT_THROW(gate.release(), std::runtime_error);
    EXPECT_EQ(falses, 1); // the balancing false was attempted exactly once

    // The failed callback leaves released set and forwarded_active clear. Repeated release and later delivery stay
    // inert.
    EXPECT_NO_THROW(gate.release());
    gate.deliver(false);
    gate.deliver(true);
    EXPECT_EQ(falses, 1);
}

// A false edge inside another gate's callback must defer behind the true edge. Decision order prevents a stranded held
// state.
TEST(BindingGateTest, HoldGateTeardownFalseDefersBehindInflightTrue)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);
    std::mutex seq_mutex;
    std::vector<bool> seq;
    std::atomic<bool> true_running{false};
    std::atomic<bool> may_finish_true{false};
    gate.on_state_change = [&](bool active)
    {
        {
            std::lock_guard<std::mutex> lock(seq_mutex);
            seq.push_back(active);
        }
        if (active)
        {
            true_running.store(true, std::memory_order_release);
            while (!may_finish_true.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }
    };

    // Thread A parks inside the held(true) delivery so it is provably in flight.
    std::thread a([&] { gate.deliver(true); });
    while (!true_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // Thread B delivers the teardown false to `gate` from inside a scratch gate's callback (depth > 0).
    detail::HoldGate scratch;
    scratch.enabled = std::make_shared<std::atomic<bool>>(true);
    scratch.on_state_change = [&](bool active)
    {
        if (!active)
        {
            gate.deliver(false);
        }
    };
    scratch.deliver(true);
    std::atomic<bool> b_delivered{false};
    std::thread b(
        [&]
        {
            scratch.deliver(false);
            b_delivered.store(true, std::memory_order_release);
        }
    );

    // Thread b returns while the true edge stays parked. seq distinguishes a deferred false edge from concurrent
    // delivery without a fixed sleep.
    for (int i = 0; i < 2000 && !b_delivered.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    // An expired wait cannot prove a defer. Nonfatal assertions preserve both joins on that failure path.
    EXPECT_TRUE(b_delivered.load(std::memory_order_acquire))
        << "thread b must return from delivering the teardown false before the sequence is validated";
    {
        std::lock_guard<std::mutex> lock(seq_mutex);
        EXPECT_EQ(seq.size(), 1u) << "the teardown false must defer behind the in-flight true, not run concurrently";
        if (!seq.empty())
        {
            EXPECT_TRUE(seq[0]);
        }
    }

    // Releasing the parked true lets its unwind emit the deferred balancing false, in order.
    may_finish_true.store(true, std::memory_order_release);
    a.join();
    b.join();
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_TRUE(seq[0]);
    EXPECT_FALSE(seq[1]) << "consumer must end observing released, not stranded held";
}

// release() stops delivery but leaves the shared callable in the gate. retire() must remove that callable before unload
// authorization.

namespace
{
    constexpr auto GATE_RETIRE_DEADLINE = std::chrono::seconds(5);

    // One destructor balances one in_flight increment. Copy or move creates a negative count that defeats both
    // zero-count teardown waits.
    static_assert(!std::is_copy_constructible_v<detail::HoldGate::InFlightSlot>);
    static_assert(!std::is_copy_assignable_v<detail::HoldGate::InFlightSlot>);
    static_assert(!std::is_move_constructible_v<detail::HoldGate::InFlightSlot>);
    static_assert(!std::is_move_assignable_v<detail::HoldGate::InFlightSlot>);

    // A copied TeardownScope clears the claim before the first copy ends its balance edge. The count alone does not
    // protect that interval.
    static_assert(!std::is_copy_constructible_v<detail::HoldGate::TeardownScope>);
    static_assert(!std::is_copy_assignable_v<detail::HoldGate::TeardownScope>);
    static_assert(!std::is_move_constructible_v<detail::HoldGate::TeardownScope>);
    static_assert(!std::is_move_assignable_v<detail::HoldGate::TeardownScope>);

    // The shared capture has one slow destructor despite callback copies. Its park exposes concurrent teardown during
    // callable disposal.
    struct BlockingDisposal
    {
        std::atomic<bool> &running;
        std::atomic<bool> &may_finish;

        ~BlockingDisposal()
        {
            running.store(true, std::memory_order_release);
            while (!may_finish.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }
    };
} // namespace

TEST(BindingGateTest, PressGateRetireDestroysTheConsumerCallable)
{
    detail::PressGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<int> calls{0};
    auto token = std::make_shared<int>(0);
    const std::weak_ptr<int> observer = token;
    // The captured token stands in for a Logic DLL's callable state: its liveness is observable from outside.
    gate.on_press = [&calls, keep = std::move(token)] { calls.fetch_add(1, std::memory_order_relaxed); };
    ASSERT_FALSE(observer.expired());

    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    EXPECT_TRUE(observer.expired()) << "retire must destroy the callable, not merely stop delivering to it";

    gate.deliver();
    EXPECT_EQ(calls.load(std::memory_order_relaxed), 0);
    // Idempotent: the guard's later release, and a repeat for another exploded combo sharing this gate.
    gate.release();
    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
}

TEST(BindingGateTest, HoldGateRetireDeliversTheHeldBalancingEdgeAndDestroysTheCallable)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::vector<bool> seq;
    auto token = std::make_shared<int>(0);
    const std::weak_ptr<int> observer = token;
    gate.on_state_change = [&seq, keep = std::move(token)](bool active) { seq.push_back(active); };

    gate.deliver(true);
    ASSERT_EQ(seq.size(), 1u);

    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    ASSERT_EQ(seq.size(), 2u) << "a still-held binding must be balanced by retirement, while its code is mapped";
    EXPECT_FALSE(seq[1]);
    EXPECT_TRUE(observer.expired());

    // The guard's later release must not re-enter a callback the drain already balanced and destroyed.
    gate.release();
    EXPECT_EQ(seq.size(), 2u);
}

TEST(BindingGateTest, HoldGateRetireAfterGuardReleaseAddsNoSecondBalancingEdge)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::vector<bool> seq;
    auto token = std::make_shared<int>(0);
    const std::weak_ptr<int> observer = token;
    gate.on_state_change = [&seq, keep = std::move(token)](bool active) { seq.push_back(active); };

    gate.deliver(true);
    gate.release();
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_FALSE(observer.expired()) << "release leaves the callable owned by the gate; only retire takes it";

    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    EXPECT_EQ(seq.size(), 2u) << "the balancing edge is owed once, not once per teardown path";
    EXPECT_TRUE(observer.expired());
}

TEST(BindingGateTest, RetireRefusesAndKeepsTheCallableWhileADeliveryIsInFlight)
{
    detail::PressGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> in_callback{false};
    std::atomic<bool> may_finish{false};
    auto token = std::make_shared<int>(0);
    const std::weak_ptr<int> observer = token;
    gate.on_press = [&in_callback, &may_finish, keep = std::move(token)]
    {
        in_callback.store(true, std::memory_order_release);
        while (!may_finish.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    std::thread delivering([&gate] { gate.deliver(); });
    while (!in_callback.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // A missed deadline must retain the live callable and report TimedOut to the drain.
    EXPECT_FALSE(gate.retire(std::chrono::steady_clock::now() + std::chrono::milliseconds(50)));
    EXPECT_FALSE(observer.expired());

    may_finish.store(true, std::memory_order_release);
    delivering.join();

    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    EXPECT_TRUE(observer.expired());
}

// The hold claim is clear while delivery remains in flight. Only the in-flight count protects the callable and its
// Logic-DLL code.
TEST(BindingGateTest, HoldGateRetireRefusesAndKeepsTheCallableWhileADeliveryIsInFlight)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> in_callback{false};
    std::atomic<bool> may_finish{false};
    auto token = std::make_shared<int>(0);
    const std::weak_ptr<int> observer = token;
    gate.on_state_change = [&in_callback, &may_finish, keep = std::move(token)](bool active)
    {
        // Only the held edge parks. The balancing false edge runs here during retire(), so it cannot share that park.
        if (!active)
        {
            return;
        }
        in_callback.store(true, std::memory_order_release);
        while (!may_finish.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    std::thread delivering([&gate] { gate.deliver(true); });
    while (!in_callback.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    EXPECT_FALSE(gate.retire(std::chrono::steady_clock::now() + std::chrono::milliseconds(50)))
        << "retire() authorized teardown while the poll thread was still inside the hold callback";
    EXPECT_FALSE(observer.expired());

    may_finish.store(true, std::memory_order_release);
    delivering.join();

    // The balancing false runs through the retired copy, so the callable outlives the call and dies with it.
    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    EXPECT_TRUE(observer.expired());
}

// A deferred false edge runs after ordinary delivery. Its lease must still cover that edge, or both teardown waits
// report quiescence during live consumer code.
TEST(BindingGateTest, TeardownWaitsOutTheDeferredBalancingEdge)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> deferred_armed{false};
    std::atomic<bool> may_finish_true{false};
    std::atomic<bool> false_running{false};
    std::atomic<bool> may_finish_false{false};
    std::atomic<bool> release_returned{false};

    gate.on_state_change = [&](bool active)
    {
        if (active)
        {
            // Depth > 0, so this teardown false cannot block and defers to this delivery's unwind.
            gate.deliver(false);
            deferred_armed.store(true, std::memory_order_release);
            while (!may_finish_true.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            return;
        }
        false_running.store(true, std::memory_order_release);
        while (!may_finish_false.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    std::thread delivering([&gate] { gate.deliver(true); });
    while (!deferred_armed.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // The control-plane release arrives after the defer is armed, so it must wait rather than latch the gate closed
    // ahead of it.
    std::thread releasing(
        [&]
        {
            gate.release();
            release_returned.store(true, std::memory_order_release);
        }
    );

    may_finish_true.store(true, std::memory_order_release);
    while (!false_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // Repeated samples detect a waiter that returns early. One sample can miss the faulty interval.
    for (int i = 0; i < 200 && !release_returned.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(release_returned.load(std::memory_order_acquire))
        << "release() returned while the deferred balancing callback was still running";

    may_finish_false.store(true, std::memory_order_release);
    delivering.join();
    releasing.join();
    EXPECT_TRUE(release_returned.load(std::memory_order_acquire));
}

TEST(BindingGateTest, RetireRefusesWhileTheControlPlaneReleaseBalancingEdgeIsRunning)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> false_running{false};
    std::atomic<bool> may_finish_false{false};
    gate.on_state_change = [&](bool active)
    {
        if (active)
        {
            return;
        }
        false_running.store(true, std::memory_order_release);
        while (!may_finish_false.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    gate.deliver(true);
    std::thread releasing([&gate] { gate.release(); });
    while (!false_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // The balance edge stays inside consumer code. Retirement must retain its in-flight lease before callable disposal
    // or unload authorization.
    EXPECT_FALSE(gate.retire(std::chrono::steady_clock::now() + std::chrono::milliseconds(50)))
        << "retire() authorized teardown while the guard-release balancing callback was still running";

    may_finish_false.store(true, std::memory_order_release);
    releasing.join();
    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
}

// A repeated release owes quiescence to its own caller. The released latch alone cannot prove that the first balance
// edge ended.
TEST(BindingGateTest, ReleaseWaitsOutAConcurrentReleaseBalancingEdge)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> false_running{false};
    std::atomic<bool> may_finish_false{false};
    std::atomic<bool> second_returned{false};

    gate.on_state_change = [&](bool active)
    {
        if (active)
        {
            return;
        }
        false_running.store(true, std::memory_order_release);
        while (!may_finish_false.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    gate.deliver(true);
    std::thread first([&gate] { gate.release(); });
    while (!false_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::thread second(
        [&]
        {
            gate.release();
            second_returned.store(true, std::memory_order_release);
        }
    );

    // Repeated samples detect an early second release despite scheduler timing.
    for (int i = 0; i < 200 && !second_returned.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(second_returned.load(std::memory_order_acquire))
        << "release() returned on an already-released gate while another teardown's balancing callback was still "
           "running, so its caller may destroy state that callback is still reading";

    may_finish_false.store(true, std::memory_order_release);
    first.join();
    second.join();
    EXPECT_TRUE(second_returned.load(std::memory_order_acquire));
}

// Retirement runs the false edge through its moved-out callable copy. Guard rundown must span that copy too.
TEST(BindingGateTest, ReleaseWaitsOutTheRetireBalancingEdge)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> false_running{false};
    std::atomic<bool> may_finish_false{false};
    std::atomic<bool> release_returned{false};

    gate.on_state_change = [&](bool active)
    {
        if (active)
        {
            return;
        }
        false_running.store(true, std::memory_order_release);
        while (!may_finish_false.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    gate.deliver(true);
    std::thread retiring([&gate]
                         { EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE)); });
    while (!false_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::thread releasing(
        [&]
        {
            gate.release();
            release_returned.store(true, std::memory_order_release);
        }
    );

    for (int i = 0; i < 200 && !release_returned.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(release_returned.load(std::memory_order_acquire))
        << "release() reported a quiesced gate while retirement was still invoking the consumer's balancing edge";

    may_finish_false.store(true, std::memory_order_release);
    retiring.join();
    releasing.join();
    EXPECT_TRUE(release_returned.load(std::memory_order_acquire));
}

// Self-release returns its claim and defers the false edge. The in-flight count alone protects consumer code while that
// edge runs.
TEST(BindingGateTest, ReleaseWaitsOutADeferredBalancingEdgeOnAnAlreadyReleasedGate)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> false_running{false};
    std::atomic<bool> may_finish_false{false};
    std::atomic<bool> release_returned{false};

    gate.on_state_change = [&](bool active)
    {
        if (active)
        {
            // At depth > 0, this release defers the false edge to unwind and returns its claim.
            gate.release();
            return;
        }
        false_running.store(true, std::memory_order_release);
        while (!may_finish_false.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    std::thread delivering([&gate] { gate.deliver(true); });
    while (!false_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // Self-release already set the released latch and returned its claim. Only the deferred callback remains live.
    std::thread releasing(
        [&]
        {
            gate.release();
            release_returned.store(true, std::memory_order_release);
        }
    );

    for (int i = 0; i < 200 && !release_returned.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(release_returned.load(std::memory_order_acquire))
        << "release() returned on an already-released gate while its deferred balancing callback was still running";

    may_finish_false.store(true, std::memory_order_release);
    delivering.join();
    releasing.join();
    EXPECT_TRUE(release_returned.load(std::memory_order_acquire));
}

// A balancing callback can drop another guard at depth > 0. That release cannot wait for its own callback to finish.
TEST(BindingGateTest, ReleaseFromInsideTheBalancingEdgeDoesNotWaitOnItsOwnTeardown)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<int> nested_returns{0};
    gate.on_state_change = [&](bool active)
    {
        if (active)
        {
            return;
        }
        gate.release();
        nested_returns.fetch_add(1, std::memory_order_relaxed);
    };

    gate.deliver(true);
    gate.release();
    EXPECT_EQ(nested_returns.load(std::memory_order_relaxed), 1)
        << "a release reached from inside the balancing edge must fall through, not wait on the teardown running it";
}

// Press retirement has no false edge but still runs capture destructors. Guard rundown must span that Logic-DLL code.
TEST(BindingGateTest, PressGateReleaseWaitsOutTheRetiredCallableDestruction)
{
    detail::PressGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> disposal_running{false};
    std::atomic<bool> may_finish_disposal{false};
    std::atomic<bool> release_returned{false};

    auto blocker = std::make_shared<BlockingDisposal>(disposal_running, may_finish_disposal);
    gate.on_press = [keep = std::move(blocker)] {};

    std::thread retiring([&gate]
                         { EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE)); });
    while (!disposal_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::thread releasing(
        [&]
        {
            gate.release();
            release_returned.store(true, std::memory_order_release);
        }
    );

    for (int i = 0; i < 200 && !release_returned.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(release_returned.load(std::memory_order_acquire))
        << "release() reported a quiesced gate while the retired callable's destructor was still running";

    may_finish_disposal.store(true, std::memory_order_release);
    retiring.join();
    releasing.join();
    EXPECT_TRUE(release_returned.load(std::memory_order_acquire));
}

// The callable lives inside TeardownScope, so its capture destructors run before the claim ends. An early claim release
// admits concurrent teardown of live Logic-DLL captures.
TEST(BindingGateTest, HoldGateReleaseWaitsOutTheRetiredCallableDestruction)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> disposal_running{false};
    std::atomic<bool> may_finish_disposal{false};
    std::atomic<bool> release_returned{false};

    auto blocker = std::make_shared<BlockingDisposal>(disposal_running, may_finish_disposal);
    gate.on_state_change = [keep = std::move(blocker)](bool) {};

    std::thread retiring([&gate]
                         { EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE)); });
    while (!disposal_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::thread releasing(
        [&]
        {
            gate.release();
            release_returned.store(true, std::memory_order_release);
        }
    );

    for (int i = 0; i < 200 && !release_returned.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(release_returned.load(std::memory_order_acquire))
        << "release() reported a quiesced gate while the retired hold callable's capture destructors were still "
           "running";

    may_finish_disposal.store(true, std::memory_order_release);
    retiring.join();
    releasing.join();
    EXPECT_TRUE(release_returned.load(std::memory_order_acquire));
}

// The teardown claim must precede the in-flight wait. An early wake otherwise lets retirement remove the callable
// before the release caller can destroy its state.
//
// The mutex probe observes that order directly. Other cases start teardown at zero in_flight and do not reach this
// wait.
TEST(BindingGateTest, ReleaseClaimsTheGateBeforeWaitingForDeliveriesToDrain)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    std::atomic<bool> delivery_running{false};
    std::atomic<bool> may_finish_delivery{false};

    gate.on_state_change = [&](bool active)
    {
        if (!active)
        {
            return;
        }
        delivery_running.store(true, std::memory_order_release);
        while (!may_finish_delivery.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    // The parked callback forces the control-plane release into the drain wait.
    std::thread delivery([&gate] { gate.deliver(true); });
    while (!delivery_running.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::thread releasing([&gate] { gate.release(); });

    bool claimed_while_waiting = false;
    for (int i = 0; i < 2'000 && !claimed_while_waiting; ++i)
    {
        {
            std::lock_guard<std::mutex> probe(gate.mutex);
            claimed_while_waiting = gate.released && gate.teardown_active;
        }
        if (!claimed_while_waiting)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    EXPECT_TRUE(
        claimed_while_waiting
    ) << "release() marked the gate released but left it unclaimed while it waited for the delivery to drain, so a "
         "retire() woken by that same drain can take the callable out from under the balancing edge this release is "
         "about to run";

    may_finish_delivery.store(true, std::memory_order_release);
    delivery.join();
    releasing.join();
}

// Both exits without consumer code must return their claim. retire() turns a stranded claim into bounded failure rather
// than an unbounded release wait.
TEST(BindingGateTest, DeferredSelfReleaseClearsItsTeardownClaim)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);

    // Self-release defers consumer teardown to this delivery's unwind.
    gate.on_state_change = [&gate](bool active)
    {
        if (active)
        {
            gate.release();
        }
    };

    gate.deliver(true);
    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE))
        << "release()'s deferred exit left its teardown claim set, so every later teardown waits out a gate that has "
           "been idle since the delivery unwound";
}

TEST(BindingGateTest, ReleaseWithNothingToBalanceClearsItsTeardownClaim)
{
    // Never held, so there is no balancing edge to emit.
    detail::HoldGate unheld;
    unheld.enabled = std::make_shared<std::atomic<bool>>(true);
    unheld.on_state_change = [](bool) {};

    unheld.release();
    EXPECT_TRUE(unheld.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE))
        << "release() over a gate with nothing to balance left its teardown claim set";

    // Held, but with no callable to emit through: the same exit, reached on its other disjunct.
    detail::HoldGate held_without_callback;
    held_without_callback.enabled = std::make_shared<std::atomic<bool>>(true);

    held_without_callback.deliver(true);
    held_without_callback.release();
    EXPECT_TRUE(held_without_callback.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE))
        << "release() over a held gate with no callback left its teardown claim set";
}

// Several combo entries share one gate. A repeated retire() must return its claim even after the callable leaves the
// first time.
TEST(BindingGateTest, RepeatedHoldGateRetireWithNothingToDisposeTakesNoTeardownClaim)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);
    gate.on_state_change = [](bool) {};

    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE))
        << "a repeat retire() with nothing left to dispose took a teardown claim no scope hands back";
}

// The press side of the same repeat, where the claim is the in-flight count instead.
TEST(BindingGateTest, RepeatedPressGateRetireWithNothingToDisposeCountsNoDisposal)
{
    detail::PressGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);
    gate.on_press = [] {};

    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE));
    EXPECT_TRUE(gate.retire(std::chrono::steady_clock::now() + GATE_RETIRE_DEADLINE))
        << "a repeat retire() with nothing left to dispose counted a disposal it never performs";
}
