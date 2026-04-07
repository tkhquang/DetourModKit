#include <gtest/gtest.h>

#include "DetourModKit/event_dispatcher.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace DetourModKit;

// --- Test event types ---

struct SimpleEvent
{
    int value{0};
};

struct StringEvent
{
    std::string message;
};

// --- Basic subscribe/emit ---

TEST(EventDispatcherTest, EmitWithNoSubscribers_DoesNothing)
{
    EventDispatcher<SimpleEvent> dispatcher;
    dispatcher.emit(SimpleEvent{42}); // Must not crash
    EXPECT_TRUE(dispatcher.empty());
}

TEST(EventDispatcherTest, Subscribe_IncreasesCount)
{
    EventDispatcher<SimpleEvent> dispatcher;
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);

    auto sub = dispatcher.subscribe([](const SimpleEvent &) {});
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);
}

TEST(EventDispatcherTest, EmitCallsHandler)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int received = 0;

    auto sub = dispatcher.subscribe([&received](const SimpleEvent &e) {
        received = e.value;
    });

    dispatcher.emit(SimpleEvent{99});
    EXPECT_EQ(received, 99);
}

TEST(EventDispatcherTest, EmitCallsMultipleHandlers)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count = 0;

    auto sub1 = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });
    auto sub2 = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });
    auto sub3 = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(count, 3);
}

TEST(EventDispatcherTest, EmitPassesEventByConstRef)
{
    EventDispatcher<StringEvent> dispatcher;
    std::string captured;

    auto sub = dispatcher.subscribe([&captured](const StringEvent &e) {
        captured = e.message;
    });

    dispatcher.emit(StringEvent{"hello world"});
    EXPECT_EQ(captured, "hello world");
}

// --- RAII Subscription ---

TEST(EventDispatcherTest, SubscriptionUnsubscribesOnDestruction)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count = 0;

    {
        auto sub = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });
        dispatcher.emit(SimpleEvent{1});
        EXPECT_EQ(count, 1);
        EXPECT_EQ(dispatcher.subscriber_count(), 1u);
    }
    // sub destroyed -- handler removed

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(count, 1); // Not called again
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, SubscriptionReset_Unsubscribes)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count = 0;

    auto sub = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });
    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(count, 1);

    sub.reset();
    EXPECT_FALSE(sub.active());

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(count, 1);
}

TEST(EventDispatcherTest, SubscriptionResetTwice_IsSafe)
{
    EventDispatcher<SimpleEvent> dispatcher;
    auto sub = dispatcher.subscribe([](const SimpleEvent &) {});
    sub.reset();
    sub.reset(); // Must not crash or double-unsubscribe
    EXPECT_FALSE(sub.active());
}

TEST(EventDispatcherTest, SubscriptionMoveConstructor)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count = 0;

    auto sub1 = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });
    auto sub2 = std::move(sub1);

    EXPECT_FALSE(sub1.active()); // NOLINT: testing moved-from state
    EXPECT_TRUE(sub2.active());

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(count, 1);
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);
}

TEST(EventDispatcherTest, SubscriptionMoveAssignment)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count_a = 0;
    int count_b = 0;

    auto sub_a = dispatcher.subscribe([&count_a](const SimpleEvent &) { ++count_a; });
    auto sub_b = dispatcher.subscribe([&count_b](const SimpleEvent &) { ++count_b; });
    EXPECT_EQ(dispatcher.subscriber_count(), 2u);

    // Move-assign sub_b over sub_a. sub_a's old handler is unsubscribed.
    sub_a = std::move(sub_b);
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(count_a, 0); // Old handler removed
    EXPECT_EQ(count_b, 1); // New handler still active
}

TEST(EventDispatcherTest, DefaultConstructedSubscription_IsInactive)
{
    Subscription sub;
    EXPECT_FALSE(sub.active());
    sub.reset(); // Must not crash
}

// --- Selective unsubscribe ---

TEST(EventDispatcherTest, UnsubscribeOne_LeavesOthers)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count_a = 0;
    int count_b = 0;

    auto sub_a = dispatcher.subscribe([&count_a](const SimpleEvent &) { ++count_a; });
    auto sub_b = dispatcher.subscribe([&count_b](const SimpleEvent &) { ++count_b; });

    sub_a.reset();

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(count_a, 0);
    EXPECT_EQ(count_b, 1);
}

// --- Clear ---

TEST(EventDispatcherTest, Clear_RemovesAllSubscribers)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count = 0;

    auto sub1 = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });
    auto sub2 = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });

    dispatcher.clear();
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(count, 0);
}

// --- emit_safe ---

TEST(EventDispatcherTest, EmitSafe_CatchesHandlerExceptions)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count = 0;

    auto sub1 = dispatcher.subscribe([](const SimpleEvent &) {
        throw std::runtime_error("handler error");
    });
    auto sub2 = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });

    // emit_safe should not propagate exceptions; sub2 should still run
    dispatcher.emit_safe(SimpleEvent{1});
    EXPECT_EQ(count, 1);
}

// --- Dispatcher destruction before Subscription ---

TEST(EventDispatcherTest, DispatcherDestroyedBeforeSubscription_SafeReset)
{
    Subscription sub;
    {
        EventDispatcher<SimpleEvent> dispatcher;
        sub = dispatcher.subscribe([](const SimpleEvent &) {});
        EXPECT_TRUE(sub.active());
    }
    // Dispatcher destroyed. sub.reset() must not crash.
    EXPECT_FALSE(sub.active());
    sub.reset(); // Safe: weak_ptr expired
}

// --- Multiple event types ---

TEST(EventDispatcherTest, IndependentDispatchers_DoNotInterfere)
{
    EventDispatcher<SimpleEvent> int_dispatcher;
    EventDispatcher<StringEvent> str_dispatcher;

    int int_count = 0;
    int str_count = 0;

    auto sub1 = int_dispatcher.subscribe([&int_count](const SimpleEvent &) { ++int_count; });
    auto sub2 = str_dispatcher.subscribe([&str_count](const StringEvent &) { ++str_count; });

    int_dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(int_count, 1);
    EXPECT_EQ(str_count, 0);

    str_dispatcher.emit(StringEvent{"test"});
    EXPECT_EQ(int_count, 1);
    EXPECT_EQ(str_count, 1);
}

// --- Concurrent emit ---

TEST(EventDispatcherTest, ConcurrentEmit_NoDataRace)
{
    EventDispatcher<SimpleEvent> dispatcher;
    std::atomic<int> total{0};

    auto sub = dispatcher.subscribe([&total](const SimpleEvent &e) {
        total.fetch_add(e.value, std::memory_order_relaxed);
    });

    constexpr int threads = 8;
    constexpr int emits_per_thread = 1000;
    std::vector<std::thread> workers;
    workers.reserve(threads);

    for (int t = 0; t < threads; ++t)
    {
        workers.emplace_back([&dispatcher]() {
            for (int i = 0; i < emits_per_thread; ++i)
            {
                dispatcher.emit(SimpleEvent{1});
            }
        });
    }

    for (auto &w : workers)
    {
        w.join();
    }

    EXPECT_EQ(total.load(), threads * emits_per_thread);
}

TEST(EventDispatcherTest, ConcurrentEmitAndSubscribe_NoDataRace)
{
    EventDispatcher<SimpleEvent> dispatcher;
    std::atomic<bool> stop{false};
    std::atomic<int> emit_count{0};

    // Emitter threads
    std::vector<std::thread> emitters;
    for (int t = 0; t < 4; ++t)
    {
        emitters.emplace_back([&dispatcher, &stop, &emit_count]() {
            while (!stop.load(std::memory_order_relaxed))
            {
                dispatcher.emit_safe(SimpleEvent{1});
                emit_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    // Subscribe/unsubscribe churn on main thread while emitters run
    for (int i = 0; i < 200; ++i)
    {
        auto sub = dispatcher.subscribe([](const SimpleEvent &) {});
        std::this_thread::yield();
        // sub destroyed -- unsubscribe
    }

    // Let emitters run briefly to ensure they have time to execute
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    stop.store(true, std::memory_order_relaxed);
    for (auto &w : emitters)
    {
        w.join();
    }

    // If we get here without deadlock or crash, the test passes.
    // emit_count may be zero on extremely slow machines, so we only
    // assert no crash/deadlock occurred.
    (void)emit_count;
}

// --- Reentrancy guard ---

TEST(EventDispatcherTest, SubscribeInsideHandler_IsRejected)
{
    EventDispatcher<SimpleEvent> dispatcher;
    Subscription inner_sub;
    bool handler_ran = false;

    auto sub = dispatcher.subscribe([&](const SimpleEvent &) {
        // Attempting to subscribe from within a handler must be rejected
        // to prevent deadlock (exclusive lock inside shared lock).
        inner_sub = dispatcher.subscribe([&](const SimpleEvent &) {
            handler_ran = true;
        });
    });

    dispatcher.emit(SimpleEvent{1});

    // The inner subscription must be inactive (rejected)
    EXPECT_FALSE(inner_sub.active());
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);

    // Emit again to confirm inner handler was never registered
    dispatcher.emit(SimpleEvent{2});
    EXPECT_FALSE(handler_ran);
}

TEST(EventDispatcherTest, UnsubscribeInsideHandler_IsRejected)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int call_count = 0;

    Subscription held_sub;
    held_sub = dispatcher.subscribe([&](const SimpleEvent &) {
        ++call_count;
        // Attempting to unsubscribe from within a handler is silently
        // skipped to prevent deadlock.
        held_sub.reset();
    });

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(call_count, 1);
    // The subscription should still be active because reset() was
    // rejected inside the handler.
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);

    // Now unsubscribe outside the handler (must work)
    held_sub.reset();
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, EmitSafe_ReentrancyGuardAlsoApplies)
{
    EventDispatcher<SimpleEvent> dispatcher;
    Subscription inner_sub;

    auto sub = dispatcher.subscribe([&](const SimpleEvent &) {
        inner_sub = dispatcher.subscribe([](const SimpleEvent &) {});
    });

    dispatcher.emit_safe(SimpleEvent{1});
    EXPECT_FALSE(inner_sub.active());
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);
}

// --- Subscription order preserved after unsubscribe ---

TEST(EventDispatcherTest, UnsubscribeMiddle_PreservesOrder)
{
    EventDispatcher<SimpleEvent> dispatcher;
    std::vector<int> order;

    auto sub_a = dispatcher.subscribe([&order](const SimpleEvent &) { order.push_back(1); });
    auto sub_b = dispatcher.subscribe([&order](const SimpleEvent &) { order.push_back(2); });
    auto sub_c = dispatcher.subscribe([&order](const SimpleEvent &) { order.push_back(3); });

    // Remove the middle subscriber
    sub_b.reset();

    dispatcher.emit(SimpleEvent{1});

    // Order must be preserved: [1, 3], not [1, 3] or [3, 1]
    ASSERT_EQ(order.size(), 2u);
    EXPECT_EQ(order[0], 1);
    EXPECT_EQ(order[1], 3);
}

// --- Subscription vector in container ---

TEST(EventDispatcherTest, SubscriptionsInVector_CleanupOnClear)
{
    EventDispatcher<SimpleEvent> dispatcher;
    std::vector<Subscription> subs;
    int count = 0;

    for (int i = 0; i < 10; ++i)
    {
        subs.push_back(dispatcher.subscribe([&count](const SimpleEvent &) { ++count; }));
    }
    EXPECT_EQ(dispatcher.subscriber_count(), 10u);

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(count, 10);

    subs.clear();
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}
