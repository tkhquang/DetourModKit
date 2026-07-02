#include <gtest/gtest.h>

// Enables the test-only debug_snapshot_use_count() diagnostic on the dispatcher. Defined here (before the header
// include) so it affects only this translation unit.
#define DMK_EVENT_DISPATCHER_INTERNAL_TESTING 1

#include "DetourModKit/detail/event_dispatcher.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
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

    auto sub1 = dispatcher.subscribe([](const SimpleEvent &) { throw std::runtime_error("handler error"); });
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

// --- Reentrancy guard ---

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

TEST(EventDispatcherTest, UnsubscribeInsideHandler_TakesEffectAtEmitUnwind)
{
    // An unsubscribe requested from inside a handler is deferred -- the published snapshot cannot be mutated mid-emit
    // -- and completed when that dispatcher's emit unwinds. The handler therefore fires exactly once (during the emit
    // that unsubscribed it) and never again. Before the deferred-removal drain landed, the entry survived and the
    // handler re-fired on every subsequent emit.
    EventDispatcher<SimpleEvent> dispatcher;
    int call_count = 0;

    Subscription held_sub;
    held_sub = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            ++call_count;
            held_sub.reset(); // deferred mid-emit; drained when emit() unwinds
        });

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(call_count, 1);
    // The deferred unsubscribe drains on unwind, so the entry is already gone. held_sub still reports active() because
    // it retains its retry lambda until an out-of-emit reset(); subscriber_count() is the authoritative signal.
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
    EXPECT_TRUE(held_sub.active());

    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(call_count, 1) << "handler must not fire again after its in-handler unsubscribe took effect";

    // An out-of-emit reset() now finds the entry already removed: a harmless idempotent no-op that also clears the
    // Subscription's retained lambda.
    held_sub.reset();
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

    // Order must be preserved: [1, 3], not [3, 1]
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
    // A subscription whose reset() was deferred during emit is drained when the emit unwinds; destroying the
    // Subscription afterwards is a clean, idempotent no-op (its retained retry lambda finds the entry already gone).
    EventDispatcher<SimpleEvent> dispatcher;
    int call_count = 0;

    {
        Subscription held_sub;
        held_sub = dispatcher.subscribe(
            [&](const SimpleEvent &)
            {
                ++call_count;
                held_sub.reset(); // deferred mid-emit; drained on unwind
            });

        dispatcher.emit(SimpleEvent{1});
        EXPECT_EQ(call_count, 1);
        EXPECT_EQ(dispatcher.subscriber_count(), 0u); // drained when emit() unwound
        // held_sub destroyed here -- its retained retry lambda is a no-op since the entry is already removed
    }

    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, DestroyOwnerInHandler_NoReinvokeAfterUnwind)
{
    // The memory-unsafe variant of the deferred-removal gap: a handler destroys its own owner (which holds the
    // Subscription) mid-emit. The in-handler ~Subscription defers its unsubscribe, and the drain on emit unwind
    // removes the entry, so a later emit does NOT re-invoke the handler -- which would dereference the freed owner.
    // Before the fix the entry survived and re-fired on the next emit, touching freed storage (an ASan use-after-free;
    // here it is observable as the handler running a second time against a destroyed owner).
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
                owner.reset(); // ~Owner -> ~Subscription -> unsubscribe deferred (emitting_depth > 0)
            }
        });

    dispatcher.emit(SimpleEvent{1});
    EXPECT_EQ(destroyed_in_handler, 1);
    EXPECT_EQ(dispatcher.subscriber_count(), 0u) << "the in-handler unsubscribe must be drained on emit unwind";

    // Must not re-invoke the (now destroyed) owner's handler.
    dispatcher.emit(SimpleEvent{2});
    EXPECT_EQ(dispatcher.subscriber_count(), 0u);
}

TEST(EventDispatcherTest, UnsubscribeInHandler_NestedSameTypeDispatcher_TakesEffect)
{
    // Two dispatchers of the SAME event type nest emits on one thread; the inner dispatcher's handler unsubscribes.
    // emitting_depth() is a per-template-instantiation thread_local shared by BOTH dispatchers, so gating the drain on
    // "depth back to 0" would drain whichever instance owns the OUTER emit and strand the inner instance's deferred
    // removal until the inner dispatcher next emits (a re-fire, or a use-after-free in the destroy-owner variant).
    // Because each EmitGuard drains its OWN dispatcher, the inner unsubscribe must take effect when the inner emit
    // unwinds -- inside the still-running outer emit.
    EventDispatcher<SimpleEvent> outer;
    EventDispatcher<SimpleEvent> inner;

    int inner_calls = 0;
    Subscription inner_sub;
    inner_sub = inner.subscribe(
        [&](const SimpleEvent &)
        {
            ++inner_calls;
            inner_sub.reset(); // deferred; must drain when inner.emit (nested in outer.emit) unwinds, not later
        });

    auto outer_sub = outer.subscribe([&](const SimpleEvent &) { inner.emit(SimpleEvent{2}); });

    outer.emit(SimpleEvent{1});
    EXPECT_EQ(inner_calls, 1);
    EXPECT_EQ(inner.subscriber_count(), 0u)
        << "the inner unsubscribe must take effect at the inner emit unwind, not be stranded by the shared depth";

    // A subsequent emit of the inner dispatcher must not re-invoke the handler.
    inner.emit(SimpleEvent{3});
    EXPECT_EQ(inner_calls, 1) << "handler must not re-fire on the inner dispatcher's next emit";
}

TEST(EventDispatcherTest, UnsubscribeInHandler_SeparateSameTypeDispatcher_RemovesImmediately)
{
    // A handler on dispatcher A destroys a Subscription owned by dispatcher B, with both dispatchers using the same
    // Event type. The shared same-type emit depth is non-zero, but B itself is not emitting, so B has no EmitGuard that
    // could drain a deferred removal. The unsubscribe must therefore run immediately; otherwise B would keep the dead
    // subscription until its next emit and invoke it once more.
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
    // Concurrent counterpart to the single-threaded deferred-removal tests: two threads emit the SAME dispatcher
    // instance in a tight loop while one subscription unsubscribes itself from inside its own handler. This drives the
    // deferred-removal path under contention -- is_emitting_this_dispatcher() and enqueue_pending_removal() under one
    // thread's guard, and drain_pending_removals() reached via the m_has_pending_removals flag by EITHER thread's
    // EmitGuard, with both drains serialized on the writer mutex. It must remove the subscription exactly once
    // (idempotent drain) and leave no stranded entry and no torn state. Run under TSan to also prove the flag and
    // snapshot accesses are race-free; single-threaded coverage cannot.
    EventDispatcher<SimpleEvent> dispatcher;

    std::atomic<int> self_calls{0};
    std::atomic<bool> unsub_requested{false};
    Subscription self_sub;
    self_sub = dispatcher.subscribe(
        [&](const SimpleEvent &)
        {
            self_calls.fetch_add(1, std::memory_order_relaxed);
            // Exactly one handler invocation (whichever thread wins the CAS) requests the unsubscribe, so the shared
            // Subscription object is never reset() from two threads at once. The request is deferred (this thread is
            // mid-emit on this dispatcher) and drained by an EmitGuard on either thread.
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

    // The self subscription must have been drained (only the permanent keeper remains) -- not stranded behind the
    // concurrent emits, and removed exactly once despite both threads' guards racing to drain the flag.
    EXPECT_EQ(dispatcher.subscriber_count(), 1u);

    // After the drain, a fresh single-threaded emit must not invoke the removed handler again (no stale callback).
    const int calls_after_join = self_calls.load(std::memory_order_relaxed);
    dispatcher.emit(SimpleEvent{-1});
    EXPECT_EQ(self_calls.load(std::memory_order_relaxed), calls_after_join)
        << "the removed handler must not fire once its unsubscribe has been drained";
    EXPECT_GT(keeper_calls.load(std::memory_order_relaxed), 0);

    keeper.reset();
}

// --- Lock-free empty fast path ---

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

// --- Snapshot stability: in-flight emit sees pre-subscribe snapshot ---

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

// --- Snapshot reclamation: no leaked shared_ptr references after churn ---

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
