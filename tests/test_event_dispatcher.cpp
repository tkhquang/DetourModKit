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
