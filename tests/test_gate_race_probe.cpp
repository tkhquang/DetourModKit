/**
 * @file test_gate_race_probe.cpp
 * @brief Concurrency-stress harness over DetourModKit's two header-only synchronization primitives.
 * @details The hook install/teardown ledger (@ref DetourModKit::detail::HookLedger) and the input binding hold/press
 *          gates (@ref DetourModKit::detail::HoldGate, @ref DetourModKit::detail::PressGate) are the load-bearing
 *          cross-thread state in the library: the ledger serializes concurrent installs and teardowns on a shared
 *          target, and the gates serialize edge delivery against a control-plane teardown. Both are pure
 *          <atomic>/<mutex> logic with no Windows dependency.
 *
 *          Each case drives real cross-thread contention with bounded repetition. A synchronization defect surfaces as
 *          an inconsistent ledger, an unbalanced hold state, a post-release callback, or a hang. The translation unit
 *          depends only on the two internal headers, which keeps the synchronization checks independent of Windows
 *          runtime components and the library's compiled surface.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include "internal/hook_ledger.hpp"
#include "internal/input_binding_gate.hpp"

using DetourModKit::detail::HoldGate;
using DetourModKit::detail::HookLedger;
using DetourModKit::detail::PressGate;

namespace
{
    // Every case in this binary shares one ledger, so each keys on a distinct synthetic target base to keep one case's
    // entries from aliasing another's. Real targets are code pointers, but the ledger only compares the integer, so any
    // disjoint set of values exercises the same paths.
    constexpr std::uintptr_t TARGET_BASE = 0x40000000;

    // Enough contention to interleave the locked regions while keeping each case a fast unit test.
    constexpr int STRESS_THREADS = 8;
    constexpr int STRESS_ITERATIONS = 300;
} // namespace

// Distinct-target churn: every worker hammers its OWN target through the full reserve -> commit -> release lifecycle,
// so the threads mutate the ledger's shared map concurrently on disjoint keys. A missing or mis-scoped lock corrupts
// the map (a lost erase leaves a phantom hook, a torn insert drops one), which shows up as a reserve failure or a
// target that stays hooked after teardown. The concurrent unordered_map insert/erase is also the primary race-detection
// site.
TEST(GateRaceProbe, HookLedgerConcurrentDistinctTargetsStayConsistent)
{
    HookLedger &ledger = HookLedger::instance();
    std::atomic<int> reserve_failures{0};

    std::vector<std::thread> workers;
    workers.reserve(STRESS_THREADS);
    for (int t = 0; t < STRESS_THREADS; ++t)
    {
        workers.emplace_back(
            [&ledger, &reserve_failures, t]
            {
                const std::uintptr_t target = TARGET_BASE + static_cast<std::uintptr_t>((t + 1) * 0x1000);
                for (int i = 0; i < STRESS_ITERATIONS; ++i)
                {
                    const auto reservation = ledger.try_reserve_hook(target, /*refuse_if_hooked=*/false);
                    if (reservation.status != HookLedger::ReserveStatus::Reserved)
                    {
                        // An uncontended distinct target has nothing to layer against, so the only non-Reserved outcome
                        // is a bookkeeping OOM -- never expected here, so record it and skip the bad id.
                        reserve_failures.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    EXPECT_TRUE(ledger.commit_hook(target, reservation.id));
                    (void)ledger.release_hook(target, reservation.id);
                }
            });
    }
    for (auto &worker : workers)
    {
        worker.join();
    }

    EXPECT_EQ(reserve_failures.load(std::memory_order_relaxed), 0)
        << "every reserve on an uncontended distinct target must succeed";
    for (int t = 0; t < STRESS_THREADS; ++t)
    {
        const std::uintptr_t target = TARGET_BASE + static_cast<std::uintptr_t>((t + 1) * 0x1000);
        EXPECT_FALSE(ledger.is_target_hooked(target)) << "target index " << t << " must be unhooked after teardown";
    }
}

// Same-target layering: every worker layers ONE hook on a single shared target and commits it (leaving it live). The
// ledger makes reservations wait their turn in creation order, so the concurrent enqueue-then-wait handoff must still
// produce exactly one distinct id per worker and leave the target hooked; tearing every layer down must then leave it
// fully unhooked. A broken serialization double-books an id or inverts the order, which this catches as a duplicate id
// or a residual hook.
TEST(GateRaceProbe, HookLedgerConcurrentSameTargetLayeringSerializes)
{
    HookLedger &ledger = HookLedger::instance();
    const std::uintptr_t target = TARGET_BASE + 0x9000;

    std::mutex ids_mutex;
    std::vector<std::uint64_t> ids;

    std::vector<std::thread> workers;
    workers.reserve(STRESS_THREADS);
    for (int t = 0; t < STRESS_THREADS; ++t)
    {
        workers.emplace_back(
            [&]
            {
                const auto reservation = ledger.try_reserve_hook(target, /*refuse_if_hooked=*/false);
                if (reservation.status != HookLedger::ReserveStatus::Reserved)
                {
                    return;
                }
                EXPECT_TRUE(ledger.commit_hook(target, reservation.id));
                const std::lock_guard<std::mutex> lock(ids_mutex);
                ids.push_back(reservation.id);
            });
    }
    for (auto &worker : workers)
    {
        worker.join();
    }

    EXPECT_TRUE(ledger.is_target_hooked(target)) << "the fully-committed layering must leave the target hooked";
    EXPECT_EQ(ids.size(), static_cast<std::size_t>(STRESS_THREADS)) << "every worker must obtain a reservation";

    std::sort(ids.begin(), ids.end());
    EXPECT_EQ(std::unique(ids.begin(), ids.end()), ids.end()) << "every layered reservation id must be distinct";

    for (const std::uint64_t id : ids)
    {
        (void)ledger.release_hook(target, id);
    }
    EXPECT_FALSE(ledger.is_target_hooked(target)) << "removing every layer must leave the target unhooked";
}

// Teardown-vs-install serialization: a held teardown slot (the counterpart an inline-hook teardown claims to measure
// its newer-live count atomically against installs) must block a concurrent install on the same target until the slot
// is released. The teardown thread holds the slot for a bounded window; the install started while it is held must not
// obtain its reservation until the slot is dropped. Without the shared front-of-pending serialization the install would
// return immediately and race the teardown's decide-vs-act window.
TEST(GateRaceProbe, HookLedgerTargetSlotBlocksConcurrentInstall)
{
    HookLedger &ledger = HookLedger::instance();
    const std::uintptr_t target = TARGET_BASE + 0xA000;

    const auto first = ledger.try_reserve_hook(target, /*refuse_if_hooked=*/false);
    ASSERT_EQ(first.status, HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, first.id));

    std::atomic<bool> slot_held{false};
    std::atomic<bool> slot_released{false};

    std::thread teardown(
        [&]
        {
            (void)ledger.acquire_target_slot(target, first.id);
            slot_held.store(true, std::memory_order_release);
            // Hold the slot long enough for the install below to enqueue behind it and park on the condition variable.
            std::this_thread::sleep_for(std::chrono::milliseconds{120});
            slot_released.store(true, std::memory_order_release);
            ledger.release_target_slot(target, first.id);
        });

    while (!slot_held.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // This reservation enqueues behind the held teardown slot and must not return until the slot is released.
    const auto second = ledger.try_reserve_hook(target, /*refuse_if_hooked=*/false);
    EXPECT_TRUE(slot_released.load(std::memory_order_acquire))
        << "a concurrent install must not obtain its reservation until the teardown slot is released";
    EXPECT_EQ(second.status, HookLedger::ReserveStatus::Reserved);

    teardown.join();
    if (second.status == HookLedger::ReserveStatus::Reserved)
    {
        EXPECT_TRUE(ledger.commit_hook(target, second.id));
        (void)ledger.release_hook(target, second.id);
    }
    (void)ledger.release_hook(target, first.id);
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// HoldGate aggregate balance: many threads deliver overlapping press/release edges into one shared gate (the
// multi-combo hold shape, where N exploded entries share ONE gate). The gate must forward only the aggregate 0->1 held
// and 1->0 released crossings, so the consumer-visible depth the callback drives must stay within [0, 1] throughout and
// settle at 0 once every edge is balanced. A dropped or duplicated lock lets a redundant edge through, which pushes the
// observed depth to 2 or -1. on_state_change runs under the gate's own recursive_mutex, so the counters it touches are
// serialized; the atomics exist only to publish the extremes to the post-join reader.
TEST(GateRaceProbe, HoldGateConcurrentDeliverStaysBalanced)
{
    HoldGate gate;
    std::atomic<int> observed_depth{0};
    std::atomic<int> max_observed{0};
    std::atomic<int> min_observed{0};

    gate.on_state_change = [&](bool active)
    {
        const int depth = active ? observed_depth.fetch_add(1, std::memory_order_relaxed) + 1
                                 : observed_depth.fetch_sub(1, std::memory_order_relaxed) - 1;

        int prev_max = max_observed.load(std::memory_order_relaxed);
        while (depth > prev_max && !max_observed.compare_exchange_weak(prev_max, depth, std::memory_order_relaxed))
        {
        }
        int prev_min = min_observed.load(std::memory_order_relaxed);
        while (depth < prev_min && !min_observed.compare_exchange_weak(prev_min, depth, std::memory_order_relaxed))
        {
        }
    };

    std::vector<std::thread> workers;
    workers.reserve(STRESS_THREADS);
    for (int t = 0; t < STRESS_THREADS; ++t)
    {
        workers.emplace_back(
            [&]
            {
                for (int i = 0; i < STRESS_ITERATIONS; ++i)
                {
                    gate.deliver(true);
                    gate.deliver(false);
                }
            });
    }
    for (auto &worker : workers)
    {
        worker.join();
    }

    EXPECT_EQ(observed_depth.load(std::memory_order_relaxed), 0)
        << "every forwarded held edge must be balanced by a released edge";
    EXPECT_LE(max_observed.load(std::memory_order_relaxed), 1)
        << "the gate must forward only the aggregate 0->1 held transition, never a nested double-true";
    EXPECT_GE(min_observed.load(std::memory_order_relaxed), 0)
        << "the gate must never forward an unbalanced released edge";
}

// Many threads deliver press edges while the control thread closes the gate. release() serializes against delivery and
// marks the gate closed, so every edge submitted after release returns must be swallowed. The deterministic in-flight
// run-down contract is covered separately by BindingGateTest.PressGateReleaseWaitsOutInFlightDelivery.
TEST(GateRaceProbe, PressGateConcurrentReleaseClosesDelivery)
{
    PressGate gate;
    std::atomic<int> press_count{0};
    gate.on_press = [&] { press_count.fetch_add(1, std::memory_order_relaxed); };

    std::atomic<bool> stop{false};
    std::vector<std::thread> workers;
    workers.reserve(STRESS_THREADS);
    for (int t = 0; t < STRESS_THREADS; ++t)
    {
        workers.emplace_back(
            [&]
            {
                for (int i = 0; i < STRESS_ITERATIONS && !stop.load(std::memory_order_acquire); ++i)
                {
                    gate.deliver();
                }
            });
    }

    // Release from this thread while deliveries are in flight; it must run any in-flight on_press down to completion
    // and close the gate without a crash or a torn read.
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
    gate.release();
    stop.store(true, std::memory_order_release);
    for (auto &worker : workers)
    {
        worker.join();
    }

    const int after_release = press_count.load(std::memory_order_acquire);
    gate.deliver();
    EXPECT_EQ(press_count.load(std::memory_order_acquire), after_release)
        << "a press edge delivered after release() must be swallowed";
}
