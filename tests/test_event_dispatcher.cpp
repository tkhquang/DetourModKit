#include <gtest/gtest.h>

// Opts this translation unit into the test-only debug_snapshot_use_count() diagnostic on the dispatcher. The seam also
// requires DMK_ENABLE_TEST_SEAMS, which the DetourModKit_tests target defines; both must be set, so the installed
// header never exposes the seam to a consumer build. Defined before the header include so it affects only this TU.
#define DMK_EVENT_DISPATCHER_INTERNAL_TESTING 1

#include "DetourModKit/detail/event_dispatcher.hpp"

#include "test_alloc_probe.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace DetourModKit;

// Test event types

struct SimpleEvent
{
    int value{0};
};

struct StringEvent
{
    std::string message;
};

// Basic subscribe/emit

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

    auto sub = dispatcher.subscribe([&received](const SimpleEvent &e) { received = e.value; });

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

    auto sub = dispatcher.subscribe([&captured](const StringEvent &e) { captured = e.message; });

    dispatcher.emit(StringEvent{"hello world"});
    EXPECT_EQ(captured, "hello world");
}

// RAII Subscription

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

// Selective unsubscribe

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

// Clear

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

// emit_safe

TEST(EventDispatcherTest, EmitSafe_CatchesHandlerExceptions)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int count = 0;

    auto sub1 = dispatcher.subscribe([](const SimpleEvent &) { throw std::runtime_error("handler error"); });
    auto sub2 = dispatcher.subscribe([&count](const SimpleEvent &) { ++count; });

    // emit_safe should not propagate exceptions; sub2 should still run
    dispatcher.emit_safe(SimpleEvent{1});
    EXPECT_EQ(count, 1);
}

// Dispatcher destruction before Subscription -- the ordered-teardown case the weak_ptr guard covers.

TEST(EventDispatcherTest, DispatcherDestroyedBeforeSubscription_SafeReset)
{
    // This is the supported lifetime overlap in the Subscription contract: the dispatcher is destroyed FIRST, on this
    // thread (the closing brace below is the happens-before edge), and only then is the Subscription reset. The
    // concurrent case -- a ~EventDispatcher racing a reset() on another thread -- is explicitly a caller lifetime
    // violation the guard does not cover, so there is nothing safe to assert for it here.
    //
    // active() is answered by the gate, which the Subscription co-owns and which therefore outlives the dispatcher.
    // ~EventDispatcher retires it, which is what keeps that report truthful; reset() then skips compaction because
    // the weak_ptr is expired.
    Subscription sub;
    {
        EventDispatcher<SimpleEvent> dispatcher;
        sub = dispatcher.subscribe([](const SimpleEvent &) {});
        EXPECT_TRUE(sub.active());
    }
    EXPECT_FALSE(sub.active()) << "~EventDispatcher must retire the gate a surviving Subscription reads";
    sub.reset(); // Safe: weak_ptr expired, so no call into the destroyed dispatcher
}

// Multiple event types

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

// Concurrent emit

TEST(EventDispatcherTest, ConcurrentEmit_NoDataRace)
{
    EventDispatcher<SimpleEvent> dispatcher;
    std::atomic<int> total{0};

    auto sub =
        dispatcher.subscribe([&total](const SimpleEvent &e) { total.fetch_add(e.value, std::memory_order_relaxed); });

    constexpr int threads = 8;
    constexpr int emits_per_thread = 1000;
    std::vector<std::thread> workers;
    workers.reserve(threads);

    for (int t = 0; t < threads; ++t)
    {
        workers.emplace_back(
            [&dispatcher]()
            {
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
        emitters.emplace_back(
            [&dispatcher, &stop, &emit_count]()
            {
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

    // If we get here without deadlock or crash, the test passes. emit_count may be zero on extremely slow machines, so
    // we only assert no crash/deadlock occurred.
    (void)emit_count;
}

// Reentrancy guard

TEST(EventDispatcherTest, SubscribeInsideHandler_IsRejected)
{
    EventDispatcher<SimpleEvent> dispatcher;
    Subscription inner_sub;
    bool handler_ran = false;

    auto sub = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            // Attempting to subscribe from within a handler must be rejected to prevent deadlock (exclusive lock inside
            // shared lock).
            inner_sub = dispatcher.subscribe([&](const SimpleEvent &) { handler_ran = true; });
        });

    dispatcher.emit(SimpleEvent{1});

    // The inner subscription must be inactive (rejected)
    EXPECT_FALSE(inner_sub.active());
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);

    // Emit again to confirm inner handler was never registered
    dispatcher.emit(SimpleEvent{2});
    EXPECT_FALSE(handler_ran);
}

TEST(EventDispatcherTest, SubscribeEmptyHandler_IsRejected)
{
    EventDispatcher<SimpleEvent> dispatcher;
    EventDispatcher<SimpleEvent>::Handler empty_handler; // a default-constructed std::function has no target

    auto sub = dispatcher.subscribe(std::move(empty_handler));

    // An empty handler must be rejected at registration: the returned Subscription is inactive and nothing is
    // installed, so the empty target can never reach emit().
    EXPECT_FALSE(sub.active());
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);

    // A rejected empty handler is never installed, so emit()/emit_safe() stay clean no-ops and cannot reach a
    // std::bad_function_call.
    EXPECT_NO_THROW(dispatcher.emit(SimpleEvent{1}));
    EXPECT_NO_THROW(dispatcher.emit_safe(SimpleEvent{1}));
}

TEST(EventDispatcherTest, SubscribeFailsClosedWhileAnEmitFrameIsUntracked)
{
    // An emit whose frame could not be recorded (a TLS store failure) is invisible to the reentrancy chain walk, so a
    // same-type reentrant subscribe from inside it would slip past thread_is_emitting_type. subscribe must fail closed
    // on any untracked emit rather than admit a possibly-reentrant handler. Driven directly through the process-wide
    // counter, since a real TLS store failure needs memory pressure that cannot be arranged deterministically.
    EventDispatcher<SimpleEvent> dispatcher;

    detail::untracked_emit_frames().fetch_add(1, std::memory_order_seq_cst);
    Subscription rejected = dispatcher.subscribe([](const SimpleEvent &) {});
    detail::untracked_emit_frames().fetch_sub(1, std::memory_order_seq_cst);

    EXPECT_FALSE(rejected.active()) << "an untracked emit in flight must conservatively reject subscribe";
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);

    // Once no untracked emit is outstanding, subscribe admits normally again.
    Subscription ok = dispatcher.subscribe([](const SimpleEvent &) {});
    EXPECT_TRUE(ok.active());
}

TEST(EventDispatcherTest, EmitSafe_SwallowsNonStdException)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int later_ran = 0;

    // Throw a non-std type to exercise the catch(...) arm (the std::exception arm handles the common case). emit_safe
    // must still contain it and run the remaining handlers.
    auto sub1 = dispatcher.subscribe([](const SimpleEvent &) { throw 42; });
    auto sub2 = dispatcher.subscribe([&](const SimpleEvent &) { later_ran = 1; });

    EXPECT_NO_THROW(dispatcher.emit_safe(SimpleEvent{1}));
    EXPECT_EQ(later_ran, 1);
}

TEST(EventDispatcherTest, UnsubscribeInsideHandler_TakesEffectImmediately)
{
    // Every later invocation rechecks the tombstone, including nested emits from this handler.
    EventDispatcher<SimpleEvent> dispatcher;
    int call_count = 0;

    Subscription held_sub;
    held_sub = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            ++call_count;
            held_sub.reset();
        });

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(call_count, 1);
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
    EXPECT_FALSE(held_sub.active());

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(call_count, 1) << "handler must not fire again after its in-handler unsubscribe took effect";

    held_sub.reset(); // idempotent
    EXPECT_FALSE(held_sub.active());
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, EmitSafe_ReentrancyGuardAlsoApplies)
{
    EventDispatcher<SimpleEvent> dispatcher;
    Subscription inner_sub;

    auto sub = dispatcher.subscribe([&](const SimpleEvent &)
                                    { inner_sub = dispatcher.subscribe([](const SimpleEvent &) {}); });

    dispatcher.emit_safe(SimpleEvent{1});
    EXPECT_FALSE(inner_sub.active());
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);
}

// Subscription order preserved after unsubscribe

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

    // Order must be preserved: [1, 3], not [3, 1]
    ASSERT_EQ(order.size(), 2u);
    EXPECT_EQ(order[0], 1);
    EXPECT_EQ(order[1], 3);
}

// Subscription vector in container

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

TEST(EventDispatcherTest, Emit_PropagatesHandlerException)
{
    EventDispatcher<SimpleEvent> dispatcher;

    auto sub = dispatcher.subscribe([](const SimpleEvent &) { throw std::runtime_error("handler error"); });

    EXPECT_THROW(dispatcher.emit(SimpleEvent{1}), std::runtime_error);
}

TEST(EventDispatcherTest, EmitSafe_AllHandlersRunDespiteMultipleExceptions)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int success_count = 0;

    auto sub1 = dispatcher.subscribe([](const SimpleEvent &) { throw std::runtime_error("error 1"); });
    auto sub2 = dispatcher.subscribe([&success_count](const SimpleEvent &) { ++success_count; });
    auto sub3 = dispatcher.subscribe([](const SimpleEvent &) { throw std::logic_error("error 2"); });
    auto sub4 = dispatcher.subscribe([&success_count](const SimpleEvent &) { ++success_count; });

    // emit_safe must not propagate; all non-throwing handlers must execute
    dispatcher.emit_safe(SimpleEvent{1});
    EXPECT_EQ(success_count, 2);
}

TEST(EventDispatcherTest, UnsubscribeInsideHandler_SucceedsOnDestruction)
{
    // Destroying a Subscription after its handler reset it remains an idempotent no-op.
    EventDispatcher<SimpleEvent> dispatcher;
    int call_count = 0;

    {
        Subscription held_sub;
        held_sub = dispatcher.subscribe(
            [&](const SimpleEvent &)
            {
                ++call_count;
                held_sub.reset();
            });

        dispatcher.emit(SimpleEvent{1});
        EXPECT_EQ(call_count, 1);
        EXPECT_EQ(dispatcher.subscriber_count(), 0u);
    }

    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, DestroyOwnerInHandler_NoReinvokeAfterUnwind)
{
    // The tombstone must prevent a later emit from reaching the destroyed owner through the stale snapshot entry.
    EventDispatcher<SimpleEvent> dispatcher;

    struct Owner
    {
        int fired = 0;
        Subscription sub;
    };

    auto owner = std::make_unique<Owner>();
    Owner *owner_ptr = owner.get();
    int destroyed_in_handler = 0;

    owner->sub = dispatcher.subscribe(
        [&owner, &destroyed_in_handler, owner_ptr](const SimpleEvent &)
        {
            // Safe on the first (and only intended) invocation: the owner is still alive here. Touch it before the
            // reset so a hypothetical re-invocation after destruction would be a clear use-after-free.
            owner_ptr->fired += 1;
            if (owner)
            {
                ++destroyed_in_handler;
                owner.reset();
            }
        });

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(destroyed_in_handler, 1);
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);

    // Must not re-invoke the (now destroyed) owner's handler.
    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, UnsubscribeInHandler_NestedSameTypeDispatcher_TakesEffect)
{
    // Nested same-type dispatchers must keep their subscription state independent.
    EventDispatcher<SimpleEvent> outer;
    EventDispatcher<SimpleEvent> inner;

    int inner_calls = 0;
    Subscription inner_sub;
    inner_sub = inner.subscribe(
        [&](const SimpleEvent &)
        {
            ++inner_calls;
            inner_sub.reset();
        });

    auto outer_sub = outer.subscribe([&](const SimpleEvent &) { inner.emit(SimpleEvent{2}); });

    outer.emit(SimpleEvent{1});
    EXPECT_EQ(inner_calls, 1);
    EXPECT_EQ(inner.subscriber_count(), 0u);

    // A subsequent emit of the inner dispatcher must not re-invoke the handler.
    inner.emit(SimpleEvent{3});
    EXPECT_EQ(inner_calls, 1) << "handler must not re-fire on the inner dispatcher's next emit";
}

TEST(EventDispatcherTest, UnsubscribeInHandler_SeparateSameTypeDispatcher_RemovesImmediately)
{
    // A handler on dispatcher A destroys a Subscription owned by dispatcher B, with both dispatchers using the same
    // Event type. reset() retires B's handler with a synchronous tombstone store and then compacts B's list under B's
    // own writer mutex, independent of A's in-flight emit, so B's handler is dead the instant the destruction returns
    // and cannot fire on B's next emit.
    EventDispatcher<SimpleEvent> outer;
    EventDispatcher<SimpleEvent> other;

    int other_calls = 0;
    struct Owner
    {
        Subscription sub;
    };

    auto owner = std::make_unique<Owner>();
    owner->sub = other.subscribe([&](const SimpleEvent &) { ++other_calls; });

    auto outer_sub = outer.subscribe([&](const SimpleEvent &) { owner.reset(); });

    outer.emit(SimpleEvent{1});
    EXPECT_FALSE(owner);
    EXPECT_EQ(other.subscriber_count(), 0u)
        << "a non-emitting same-type dispatcher must not strand its removal behind another dispatcher's emit";

    other.emit(SimpleEvent{2});
    EXPECT_EQ(other_calls, 0) << "the removed handler must not fire on the other dispatcher's next emit";
}

TEST(EventDispatcherTest, ConcurrentEmitWithInHandlerUnsubscribe_RemovedOnceNoStaleCallback)
{
    // Concurrent counterpart to the single-threaded in-handler unsubscribe tests: two threads emit the SAME dispatcher
    // instance in a tight loop while one subscription unsubscribes itself from inside its own handler. reset() flips
    // the entry's tombstone with one seq_cst store (synchronous logical death) and then best-effort compacts the list
    // under the writer mutex, while the peer emitter keeps iterating its own copy-on-write snapshot. It must retire the
    // subscription exactly once (the tombstone store is idempotent) and leave no stranded live entry and no torn state.
    // Run under TSan to also prove the gate and snapshot accesses are race-free; single-threaded coverage cannot.
    EventDispatcher<SimpleEvent> dispatcher;

    std::atomic<int> self_calls{0};
    std::atomic<bool> unsub_requested{false};
    Subscription self_sub;
    self_sub = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            self_calls.fetch_add(1, std::memory_order_relaxed);
            // Exactly one handler invocation (whichever thread wins the CAS) resets the shared Subscription, so it is
            // never reset() from two threads at once. reset() retires the entry synchronously: the tombstone store
            // takes effect at once, and the peer emitter's in-flight snapshot rejects the entry at its liveness check.
            bool expected = false;
            if (unsub_requested.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
            {
                self_sub.reset();
            }
        });

    // A permanent second subscription so the dispatcher is never empty and the removal shows up as a count drop.
    std::atomic<int> keeper_calls{0};
    auto keeper =
        dispatcher.subscribe([&](const SimpleEvent &) { keeper_calls.fetch_add(1, std::memory_order_relaxed); });

    constexpr int per_thread = 20000;
    std::atomic<bool> go{false};
    const auto emitter = [&]
    {
        while (!go.load(std::memory_order_acquire))
        {
        }
        for (int i = 0; i < per_thread; ++i)
        {
            dispatcher.emit(SimpleEvent{i});
        }
    };

    std::thread t1(emitter);
    std::thread t2(emitter);
    go.store(true, std::memory_order_release);
    t1.join();
    t2.join();

    // The self subscription must have been retired and compacted away (only the permanent keeper remains) -- not
    // stranded behind the concurrent emits, and retired exactly once even though both threads emit it concurrently.
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);

    // After the threads join, a fresh single-threaded emit must not invoke the removed handler again (no stale
    // callback).
    const int calls_after_join = self_calls.load(std::memory_order_relaxed);
    dispatcher.emit(SimpleEvent{-1});
    EXPECT_EQ(self_calls.load(std::memory_order_relaxed), calls_after_join)
        << "the removed handler must not fire once its unsubscribe has taken effect";
    EXPECT_GT(keeper_calls.load(std::memory_order_relaxed), 0);

    keeper.reset();
}

// Lock-free empty fast path

TEST(EventDispatcherTest, EmptyFastPath_SkipsLock)
{
    // A freshly-constructed dispatcher holds exactly one snapshot reference internally. With no subscribers, emit()
    // must be observably a no-op and subscriber_count()/empty() must report zero without mutating state.
    EventDispatcher<SimpleEvent> dispatcher;

    EXPECT_TRUE(dispatcher.empty());
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);

    // Record the dispatcher's own reference to its handler snapshot before any emit. If the fast path really skips the
    // snapshot load, emit() should not leave any residual references alive afterwards.
    const long use_count_before = dispatcher.debug_snapshot_use_count();
    EXPECT_EQ(use_count_before, 1);

    for (int i = 0; i < 1000; ++i)
    {
        dispatcher.emit(SimpleEvent{i});
        dispatcher.emit_safe(SimpleEvent{i});
    }

    EXPECT_TRUE(dispatcher.empty());
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
    EXPECT_EQ(dispatcher.debug_snapshot_use_count(), use_count_before);
}

// Snapshot stability: in-flight emit sees pre-subscribe snapshot

TEST(EventDispatcherTest, SnapshotStability_DuringEmit)
{
    EventDispatcher<SimpleEvent> dispatcher;

    std::mutex gate_mtx;
    std::condition_variable handler_started;
    std::condition_variable handler_may_finish;
    bool started{false};
    bool may_finish{false};

    std::atomic<int> old_calls{0};
    std::atomic<int> new_calls{0};

    // Pre-subscribed handler signals when the emit has begun, then blocks until the main thread allows it to continue.
    auto old_sub = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            {
                std::lock_guard lk{gate_mtx};
                started = true;
            }
            handler_started.notify_one();

            std::unique_lock lk{gate_mtx};
            handler_may_finish.wait(lk, [&] { return may_finish; });
            old_calls.fetch_add(1, std::memory_order_relaxed);
        });

    // Launch an emitter thread; it will block inside the pre-subscribed handler holding a shared_ptr snapshot of the
    // current handler list.
    std::thread emitter([&] { dispatcher.emit(SimpleEvent{0}); });

    {
        std::unique_lock lk{gate_mtx};
        handler_started.wait(lk, [&] { return started; });
    }

    // Subscribe a new handler while the emit is still in flight.
    auto new_sub =
        dispatcher.subscribe([&](const SimpleEvent &) { new_calls.fetch_add(1, std::memory_order_relaxed); });

    // The freshly-subscribed handler must not be visible to the in-flight emit, which captured its snapshot before
    // new_sub was published.
    EXPECT_EQ(new_calls.load(), 0);

    // Release the blocked handler and let the emit complete.
    {
        std::lock_guard lk{gate_mtx};
        may_finish = true;
    }
    handler_may_finish.notify_one();
    emitter.join();

    EXPECT_EQ(old_calls.load(), 1);
    EXPECT_EQ(new_calls.load(), 0);

    // The next emit publishes a snapshot that includes both handlers.
    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(old_calls.load(), 2);
    EXPECT_EQ(new_calls.load(), 1);
}

// Snapshot reclamation: no leaked shared_ptr references after churn

TEST(EventDispatcherTest, SnapshotReclamation_NoLeak)
{
    EventDispatcher<SimpleEvent> dispatcher;

    // Heavy subscribe + unsubscribe churn with interleaved emits. Each subscribe allocates a new snapshot; each
    // unsubscribe does the same. Once every subscription's RAII guard is destroyed and no emit is in flight, only the
    // dispatcher's own reference to the latest (empty) snapshot should remain.
    constexpr int iterations = 10000;
    for (int i = 0; i < iterations; ++i)
    {
        auto sub = dispatcher.subscribe([](const SimpleEvent &) {});
        if ((i & 0xFF) == 0)
        {
            dispatcher.emit(SimpleEvent{i});
        }
        // sub destroyed here -- handler removed, new snapshot published
    }

    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
    EXPECT_TRUE(dispatcher.empty());
    EXPECT_EQ(dispatcher.debug_snapshot_use_count(), 1)
        << "Dispatcher should hold exactly one reference to its snapshot "
           "after all subscriptions are released";
}

// std::atomic<std::shared_ptr<T>> is NOT lock-free on either shipped toolchain: libstdc++ (MinGW) and the MSVC STL
// both back it with an internal lock. The dispatcher's emit snapshot, the async-logger writer handle, and the
// Hook::call gate all read such an atomic, so any "lock-free" claim about those reads would be wrong. This test pins
// the property empirically so a future doc or code change that assumes lock-freedom is caught by a red test rather
// than surviving as a stale comment.
TEST(EventDispatcherTest, AtomicSharedPtrIsNotLockFree)
{
    std::atomic<std::shared_ptr<int>> probe{};
    EXPECT_FALSE(probe.is_lock_free());
    EXPECT_FALSE(std::atomic<std::shared_ptr<int>>::is_always_lock_free);
}

TEST(EventDispatcherTest, NestedSameInstanceEmitCannotInvokeTombstonedOuterEntry)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    // Forced compaction failure leaves B in the published list, making the tombstone recheck the only mechanism that
    // can reject it when A emits the same dispatcher recursively.
    EventDispatcher<SimpleEvent> dispatcher;
    int b_calls = 0;
    bool nested = false;

    Subscription sub_b = dispatcher.subscribe([&](const SimpleEvent &) { ++b_calls; });
    Subscription sub_a = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            if (nested)
            {
                return;
            }
            nested = true;
            {
                dmk_test::AllocFailScope fail{0}; // compaction cannot rebuild the snapshot
                sub_b.reset();
            }
            ASSERT_EQ(dispatcher.subscriber_count(), 2u) << "the test needs B still in the list to prove anything";
            dispatcher.emit(SimpleEvent{2}); // nested, same instance, B retired but still published
        });

    dispatcher.emit(SimpleEvent{1});

    EXPECT_EQ(b_calls, 1) << "B may fire only in the outer emit, before it was retired; the nested emit must refuse it";
    EXPECT_FALSE(sub_b.active());
}

TEST(EventDispatcherTest, StaleOuterSnapshotCannotInvokeTombstonedEntry)
{
    // Republishing cannot retract an entry from a snapshot already being iterated, so the invocation-site liveness
    // check must reject B after A retires it.
    EventDispatcher<SimpleEvent> dispatcher;
    int b_calls = 0;

    Subscription sub_b;
    Subscription sub_a = dispatcher.subscribe([&](const SimpleEvent &) { sub_b.reset(); });
    sub_b = dispatcher.subscribe([&](const SimpleEvent &) { ++b_calls; });

    dispatcher.emit(SimpleEvent{1});

    EXPECT_EQ(b_calls, 0) << "A retired B earlier in the same emit; the already-captured snapshot must not invoke it";
}

TEST(EventDispatcherTest, RemovalSurvivesAllocationFailureAndIsNeverLost)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    // Logical removal must survive even when every allocation needed for physical compaction fails.
    EventDispatcher<SimpleEvent> dispatcher;
    int calls = 0;

    {
        Subscription sub = dispatcher.subscribe([&](const SimpleEvent &) { ++calls; });
        dispatcher.emit(SimpleEvent{1});
        ASSERT_EQ(calls, 1);

        // Fail every allocation across the whole of reset(), including the destructor's compaction attempt.
        dmk_test::AllocFailScope fail{0};
        sub.reset();
    } // ~Subscription runs here, still under no special allocation guarantee

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(calls, 1) << "the handler must be dead even though every allocation during its removal failed";
}

TEST(EventDispatcherTest, ClearRetiresHandlersEvenWhenTheEmptySnapshotCannotAllocate)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    // clear() retires every handler before it publishes the empty snapshot, so a failure to allocate that snapshot
    // still leaves the handlers dead. The list keeps the tombstoned entries until a later mutation reclaims them, but
    // none of them can run.
    EventDispatcher<SimpleEvent> dispatcher;
    int calls = 0;
    Subscription a = dispatcher.subscribe([&](const SimpleEvent &) { ++calls; });
    Subscription b = dispatcher.subscribe([&](const SimpleEvent &) { ++calls; });
    dispatcher.emit(SimpleEvent{1});
    ASSERT_EQ(calls, 2);

    {
        dmk_test::AllocFailScope fail{0}; // fail the empty-snapshot make_shared
        dispatcher.clear();
    }

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(calls, 2) << "handlers retired by clear() must not run even though the empty-snapshot publish failed";
    EXPECT_FALSE(a.active());
    EXPECT_FALSE(b.active());
}

TEST(EventDispatcherTest, TombstoneIsAllocationFree)
{
    EventDispatcher<SimpleEvent> dispatcher;
    Subscription sub = dispatcher.subscribe([](const SimpleEvent &) {});

    const long long before = dmk_test::thread_new_calls();
    sub.tombstone();
    const long long after = dmk_test::thread_new_calls();

    EXPECT_EQ(after - before, 0) << "retiring a handler must not allocate";
    EXPECT_FALSE(sub.active());
    EXPECT_EQ(dispatcher.subscriber_count(), 1u) << "tombstone must not perform physical compaction";

    sub.reset();
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, TombstoneAndWaitDrainsInFlightHandler)
{
    // The rundown contract: once tombstone_and_wait returns Drained, no invocation is running and none can begin, so
    // the handler's captures may be destroyed. A bare pre-call liveness check would not give this -- the wait is what
    // covers an invocation that passed the check before the tombstone landed.
    EventDispatcher<SimpleEvent> dispatcher;
    std::atomic<bool> inside{false};
    std::atomic<bool> release{false};
    std::atomic<bool> returned{false};

    Subscription sub = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            inside.store(true, std::memory_order_release);
            while (!release.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            returned.store(true, std::memory_order_release);
        });

    std::thread emitter{[&] { dispatcher.emit(SimpleEvent{1}); }};
    while (!inside.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::thread waiter{[&]
                       {
                           const Rundown result = sub.tombstone_and_wait();
                           EXPECT_EQ(result, Rundown::Drained);
                           EXPECT_TRUE(returned.load(std::memory_order_acquire))
                               << "Drained must not be reported while the handler is still running";
                       }};

    // The waiter must still be blocked: the handler has not returned.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(returned.load(std::memory_order_acquire));

    release.store(true, std::memory_order_release);
    waiter.join();
    emitter.join();
}

TEST(EventDispatcherTest, TombstoneAndWaitFromInsideOwnHandlerIsUnwaitableNotDeadlock)
{
    // Self-rundown. A handler that runs down its own subscription cannot be waited for: it IS the in-flight
    // invocation. The emit chain is what lets this be detected exactly, so the call refuses instead of waiting on the
    // calling thread forever. The handler is still retired -- only the wait is declined.
    EventDispatcher<SimpleEvent> dispatcher;
    Rundown observed = Rundown::Drained;
    int calls = 0;

    Subscription sub;
    sub = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            ++calls;
            observed = sub.tombstone_and_wait();
        });

    dispatcher.emit(SimpleEvent{1}); // must return rather than hang

    EXPECT_EQ(observed, Rundown::Unwaitable);
    EXPECT_EQ(calls, 1);

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(calls, 1) << "a refused wait must still leave the handler retired";
}

TEST(EventDispatcherTest, TombstoneAndWaitFromDifferentInstanceHandlerStillDrains)
{
    // The refusal must be keyed on the dispatcher INSTANCE being run down, not on its Event type or on "some emit is in
    // progress". target and driver share the Event type, so driver's emit puts a same-type frame on this thread's
    // chain; but target is a different instance, so it is not in the chain and its wait is provably bounded. A
    // type-keyed refusal would wrongly return Unwaitable here.
    EventDispatcher<SimpleEvent> target;
    EventDispatcher<SimpleEvent> driver;

    Subscription target_sub = target.subscribe([](const SimpleEvent &) {});
    Rundown observed = Rundown::Unwaitable;
    Subscription driver_sub =
        driver.subscribe([&](const SimpleEvent &) { observed = target_sub.tombstone_and_wait(); });

    driver.emit(SimpleEvent{1});

    EXPECT_EQ(observed, Rundown::Drained);
}

TEST(EventDispatcherTest, DispatcherTombstoneAndWaitRetiresEveryHandler)
{
    EventDispatcher<SimpleEvent> dispatcher;
    int a = 0;
    int b = 0;
    Subscription sub_a = dispatcher.subscribe([&](const SimpleEvent &) { ++a; });
    Subscription sub_b = dispatcher.subscribe([&](const SimpleEvent &) { ++b; });

    dispatcher.emit(SimpleEvent{1});
    ASSERT_EQ(a, 1);
    ASSERT_EQ(b, 1);

    EXPECT_EQ(dispatcher.tombstone_and_wait(), Rundown::Drained);
    EXPECT_FALSE(sub_a.active());
    EXPECT_FALSE(sub_b.active());

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(a, 1);
    EXPECT_EQ(b, 1);
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, TombstoneAndWaitClosesTheDispatcherToLaterSubscribes)
{
    // Closing the set before draining prevents a concurrent subscription from publishing a live handler outside the
    // snapshot covered by the rundown.
    EventDispatcher<SimpleEvent> dispatcher;
    int calls = 0;

    Subscription before = dispatcher.subscribe([&](const SimpleEvent &) { ++calls; });
    dispatcher.emit(SimpleEvent{1});
    ASSERT_EQ(calls, 1);

    ASSERT_EQ(dispatcher.tombstone_and_wait(), Rundown::Drained);

    Subscription after = dispatcher.subscribe([&](const SimpleEvent &) { ++calls; });
    EXPECT_FALSE(after.active()) << "a closed dispatcher must refuse a subscribe, not admit an undrainable handler";
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(calls, 1) << "no handler may run on a dispatcher that has been run down";
}

TEST(EventDispatcherTest, EmitDoesNotAllocate)
{
    // emit_safe() is the hook-callback entry point, so its successful subscribed path must not allocate.
    EventDispatcher<SimpleEvent> dispatcher;
    Subscription sub = dispatcher.subscribe([](const SimpleEvent &) {});

    dispatcher.emit_safe(SimpleEvent{0}); // warm any one-time state

    const long long before = dmk_test::thread_new_calls();
    for (int i = 0; i < 64; ++i)
    {
        dispatcher.emit_safe(SimpleEvent{i});
        dispatcher.emit(SimpleEvent{i});
    }
    const long long after = dmk_test::thread_new_calls();

    EXPECT_EQ(after - before, 0) << "emit must not allocate on the subscribed path";
}

// The allocation probe replaces operator new, not libgcc's calloc/malloc, so these runtime cases prove the public
// allocation-freedom contract while EmitPathHasNoEmulatedTls checks the compiler-emitted TLS mechanism.

namespace
{
    struct FreshThreadArgs
    {
        EventDispatcher<SimpleEvent> *dispatcher{nullptr};
        std::atomic<bool> handler_ran{false};
        long long allocations{0};
    };

    /**
     * @brief The thread body: a raw Win32 thread rather than std::thread.
     * @details std::thread routes through winpthreads, whose own startup would touch (and so warm) TLS before the
     *          code under test runs, destroying the first-touch condition this proof exists to preserve.
     */
    DWORD WINAPI fresh_thread_emit(LPVOID raw) noexcept
    {
        auto *args = static_cast<FreshThreadArgs *>(raw);
        const long long before = dmk_test::thread_new_calls();
        {
            dmk_test::AllocFailScope fail{0};
            args->dispatcher->emit_safe(SimpleEvent{7});
        }
        args->allocations = dmk_test::thread_new_calls() - before;
        return 0;
    }

    void run_fresh_thread(FreshThreadArgs &args)
    {
        const HANDLE thread = ::CreateThread(nullptr, 0, &fresh_thread_emit, &args, 0, nullptr);
        ASSERT_NE(thread, nullptr);
        if (::WaitForSingleObject(thread, 30000) != WAIT_OBJECT_0)
        {
            // The raw thread still holds &args, which lives in the caller's stack frame. Returning would let the caller
            // run its assertions and then destroy args and its dispatcher while the thread may still touch them, so a
            // proof that cannot confirm the thread exited ends the process rather than race that use-after-free. The
            // leaked handle does not matter once the process is going down.
            ADD_FAILURE() << "fresh-thread emit did not return";
            std::abort();
        }
        ::CloseHandle(thread);
    }
} // namespace

TEST(EventDispatcherProcessProof, MinGWFreshThreadEmitDoesNotAllocateOrTerminate)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    EventDispatcher<SimpleEvent> dispatcher;
    FreshThreadArgs args;
    args.dispatcher = &dispatcher;

    // One allocation-free subscriber: no captures to copy, so nothing but the dispatcher itself can allocate.
    Subscription sub =
        dispatcher.subscribe([&args](const SimpleEvent &) { args.handler_ran.store(true, std::memory_order_release); });

    run_fresh_thread(args);

    EXPECT_TRUE(args.handler_ran.load(std::memory_order_acquire))
        << "the handler must run on a thread whose first subscribed emit had every allocation failing";
    EXPECT_EQ(args.allocations, 0) << "a fresh thread's first subscribed emit must not allocate";
}

TEST(EventDispatcherProcessProof, FreshThreadZeroSubscriberControl)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    // Control: the zero-subscriber fast path was always free of the defect (it returns before any TLS access), so it
    // must stay green and cannot be what makes the case above pass.
    EventDispatcher<SimpleEvent> dispatcher;
    FreshThreadArgs args;
    args.dispatcher = &dispatcher;

    run_fresh_thread(args);

    EXPECT_FALSE(args.handler_ran.load(std::memory_order_acquire));
    EXPECT_EQ(args.allocations, 0);
}

TEST(EventDispatcherProcessProof, WarmedThreadControl)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    EventDispatcher<SimpleEvent> dispatcher;
    int calls = 0;
    Subscription sub = dispatcher.subscribe([&](const SimpleEvent &) { ++calls; });

    dispatcher.emit_safe(SimpleEvent{1});
    ASSERT_EQ(calls, 1);
    const long long before = dmk_test::thread_new_calls();
    {
        dmk_test::AllocFailScope fail{0};
        dispatcher.emit_safe(SimpleEvent{2});
    }
    EXPECT_EQ(calls, 2);
    EXPECT_EQ(dmk_test::thread_new_calls() - before, 0);
}
