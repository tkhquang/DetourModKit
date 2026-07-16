#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include "DetourModKit/address.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"

using namespace DetourModKit;
using DetourModKit::diagnostics::LeakSubsystem;
namespace diag = DetourModKit::diagnostics;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

namespace
{
    // Distinct real targets so the lifecycle cases install a genuine hook (the event source the dispatcher reports on).
    DMK_TEST_NOINLINE int lifecycle_target_add(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int lifecycle_target_mul(int a, int b)
    {
        volatile int r = a * b;
        return r;
    }

    DMK_TEST_NOINLINE int lifecycle_detour_add(int a, int b)
    {
        return a + b + 1;
    }

    [[nodiscard]] Address target_address(int (*fn)(int, int)) noexcept
    {
        return Address{reinterpret_cast<std::uintptr_t>(fn)};
    }

    // A small polymorphic object so vmt_for has a real vtable to clone.
    class VmtTestInterface
    {
    public:
        virtual ~VmtTestInterface() = default;
        virtual int compute(int a, int b) = 0;
    };

    class VmtTestTarget : public VmtTestInterface
    {
    public:
        int compute(int a, int b) override { return a + b; }
    };

    struct CapturedLifecycle
    {
        std::string name;
        diag::HookKind kind;
        diag::HookTransition transition;
    };
} // namespace

// The counters are process-global. ctest runs each test in its own process, and the instrumented loader-lock paths
// never fire under a normal test run, so a reset in SetUp gives each case a clean, deterministic starting point.
class DiagnosticsTest : public ::testing::Test
{
protected:
    void SetUp() override { diag::reset_intentional_leaks(); }

    void TearDown() override { diag::reset_intentional_leaks(); }
};

TEST_F(DiagnosticsTest, StartsZeroAfterReset)
{
    EXPECT_EQ(diag::total_intentional_leaks(), 0u);
    EXPECT_EQ(diag::intentional_leak_count(LeakSubsystem::HookManager), 0u);
}

TEST_F(DiagnosticsTest, RecordIncrementsOnlyTheNamedSubsystem)
{
    diag::record_intentional_leak(LeakSubsystem::Logger);
    EXPECT_EQ(diag::intentional_leak_count(LeakSubsystem::Logger), 1u);
    EXPECT_EQ(diag::intentional_leak_count(LeakSubsystem::HookManager), 0u);
    EXPECT_EQ(diag::total_intentional_leaks(), 1u);
}

TEST_F(DiagnosticsTest, RecordAccumulates)
{
    diag::record_intentional_leak(LeakSubsystem::Worker);
    diag::record_intentional_leak(LeakSubsystem::Worker);
    diag::record_intentional_leak(LeakSubsystem::Worker);
    EXPECT_EQ(diag::intentional_leak_count(LeakSubsystem::Worker), 3u);
    EXPECT_EQ(diag::total_intentional_leaks(), 3u);
}

TEST_F(DiagnosticsTest, TotalSumsAcrossSubsystems)
{
    diag::record_intentional_leak(LeakSubsystem::HookManager);
    diag::record_intentional_leak(LeakSubsystem::Logger);
    diag::record_intentional_leak(LeakSubsystem::MemoryCache);
    EXPECT_EQ(diag::total_intentional_leaks(), 3u);
}

TEST_F(DiagnosticsTest, OutOfRangeSubsystemIsIgnored)
{
    // The Count sentinel (and any value at or beyond it) must be a no-op, never an out-of-bounds write into the counter
    // array.
    diag::record_intentional_leak(LeakSubsystem::Count);
    EXPECT_EQ(diag::total_intentional_leaks(), 0u);
    EXPECT_EQ(diag::intentional_leak_count(LeakSubsystem::Count), 0u);
}

TEST_F(DiagnosticsTest, ResetZeroesEverySubsystem)
{
    diag::record_intentional_leak(LeakSubsystem::Input);
    diag::record_intentional_leak(LeakSubsystem::Bootstrap);
    diag::reset_intentional_leaks();
    EXPECT_EQ(diag::total_intentional_leaks(), 0u);
    EXPECT_EQ(diag::intentional_leak_count(LeakSubsystem::Input), 0u);
    EXPECT_EQ(diag::intentional_leak_count(LeakSubsystem::Bootstrap), 0u);
}

// Diagnostic event bus: scanner-fault / hook-lifecycle dispatchers

TEST(DiagnosticsEventBusTest, ScannerFaultDispatcherIsStable)
{
    // The process-wide dispatcher must be the same instance on every call so the stateless scanner and a consumer share
    // one subscriber set.
    EXPECT_EQ(&diag::scanner_faults(), &diag::scanner_faults());
}

TEST(DiagnosticsEventBusTest, HookLifecycleDispatcherIsStable)
{
    EXPECT_EQ(&diag::hook_lifecycle(), &diag::hook_lifecycle());
}

TEST(DiagnosticsEventBusTest, ScannerFaultEmitReachesSubscriber)
{
    diag::ScannerFaultEvent received{};
    int hits = 0;
    auto sub = diag::scanner_faults().subscribe(
        [&received, &hits](const diag::ScannerFaultEvent &e)
        {
            received = e;
            ++hits;
        });

    diag::scanner_faults().emit_safe(
        diag::ScannerFaultEvent{.faulted_regions = 5, .window_low = 0x1000, .window_high = 0x2000});

    EXPECT_EQ(hits, 1);
    EXPECT_EQ(received.faulted_regions, 5u);
    EXPECT_EQ(received.window_low, 0x1000u);
    EXPECT_EQ(received.window_high, 0x2000u);
}

TEST(DiagnosticsEventBusTest, HookLifecycleEmitReachesSubscriber)
{
    diag::HookLifecycleEvent received{};
    int hits = 0;
    {
        auto sub = diag::hook_lifecycle().subscribe(
            [&received, &hits](const diag::HookLifecycleEvent &e)
            {
                received = e;
                ++hits;
            });

        diag::hook_lifecycle().emit_safe(diag::HookLifecycleEvent{.name = "camera",
                                                                  .ledger_id = 42,
                                                                  .kind = diag::HookKind::Mid,
                                                                  .transition = diag::HookTransition::Enabled});

        EXPECT_EQ(hits, 1);
        EXPECT_EQ(received.name, "camera");
        EXPECT_EQ(received.ledger_id, 42u);
        EXPECT_EQ(received.kind, diag::HookKind::Mid);
        EXPECT_EQ(received.transition, diag::HookTransition::Enabled);
    }

    // If the population subscriber is active because tests are shuffled, pair the synthetic Enabled event so it cannot
    // leave a live slot behind.
    diag::hook_lifecycle().emit_safe(diag::HookLifecycleEvent{
        .name = "camera", .ledger_id = 42, .kind = diag::HookKind::Mid, .transition = diag::HookTransition::Removed});
}

TEST(DiagnosticsEventBusTest, UnsubscribeStopsDelivery)
{
    int hits = 0;
    {
        auto sub = diag::scanner_faults().subscribe([&hits](const diag::ScannerFaultEvent &) { ++hits; });
        diag::scanner_faults().emit_safe(diag::ScannerFaultEvent{.faulted_regions = 1});
    }
    // The RAII subscription is destroyed at the block exit; a later emit must not reach the handler.
    diag::scanner_faults().emit_safe(diag::ScannerFaultEvent{.faulted_regions = 1});
    EXPECT_EQ(hits, 1);
}

// Hook lifecycle events: typed transitions sourced from the hook verbs
//
// The event API (hook_lifecycle / HookLifecycleEvent / HookKind / HookTransition) is unchanged; only the SOURCE moved
// from the dropped HookManager registry to caller-owned RAII handles. An inline_at / mid_at / vmt_for emits Created;
// Hook::enable / disable emit Enabled / Disabled on a real transition; dropping a live Hook handle emits Removed; a
// VmtHook emits the Vmt-kind Created / Removed pair.

TEST(DiagnosticsHookLifecycleTest, InlineHookEmitsCreatedThenEnableDisableEnableThenRemoved)
{
    std::vector<CapturedLifecycle> events;
    auto sub = diag::hook_lifecycle().subscribe([&events](const diag::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    {
        Result<hook::Hook> r = hook::inline_at(
            hook::InlineRequest{.name = "LifecycleHook", .target = target_address(&lifecycle_target_add)},
            &lifecycle_detour_add);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        hook::Hook h = std::move(*r);

        // inline_at returns the hook disabled, so the arming enable is a real Enabled; disable then enable produce a
        // further Disabled / Enabled transition pair.
        ASSERT_TRUE(h.enable().has_value());
        ASSERT_TRUE(h.disable().has_value());
        ASSERT_TRUE(h.enable().has_value());
        // Drop the handle (block exit) to emit Removed.
    }

    ASSERT_EQ(events.size(), 5u);
    EXPECT_EQ(events[0].transition, diag::HookTransition::Created);
    EXPECT_EQ(events[1].transition, diag::HookTransition::Enabled);
    EXPECT_EQ(events[2].transition, diag::HookTransition::Disabled);
    EXPECT_EQ(events[3].transition, diag::HookTransition::Enabled);
    EXPECT_EQ(events[4].transition, diag::HookTransition::Removed);
    for (const auto &e : events)
    {
        EXPECT_EQ(e.name, "LifecycleHook");
        EXPECT_EQ(e.kind, diag::HookKind::Inline);
    }
}

TEST(DiagnosticsHookLifecycleTest, MidHookEmitsMidKindCreated)
{
    std::vector<CapturedLifecycle> events;
    auto sub = diag::hook_lifecycle().subscribe([&events](const diag::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    auto detour = [](hook::MidContext &) {};
    Result<hook::Hook> r = hook::mid_at(
        hook::MidRequest{.name = "MidLifecycleHook", .target = target_address(&lifecycle_target_mul)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    hook::Hook h = std::move(*r);

    ASSERT_GE(events.size(), 1u);
    EXPECT_EQ(events[0].name, "MidLifecycleHook");
    EXPECT_EQ(events[0].transition, diag::HookTransition::Created);
    EXPECT_EQ(events[0].kind, diag::HookKind::Mid);
}

TEST(DiagnosticsHookLifecycleTest, NoEventOnNoOpDisableTransition)
{
    std::vector<CapturedLifecycle> events;
    auto sub = diag::hook_lifecycle().subscribe([&events](const diag::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    Result<hook::Hook> r = hook::inline_at(
        hook::InlineRequest{.name = "NoOpLifecycleHook", .target = target_address(&lifecycle_target_add)},
        &lifecycle_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    hook::Hook h = std::move(*r);
    ASSERT_EQ(events.size(), 1u);

    // The hook is created disabled; a redundant disable is an idempotent no-op and emits no transition.
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(events.size(), 1u);
}

TEST(DiagnosticsHookLifecycleTest, VmtHookEmitsVmtKindCreatedRemoved)
{
    auto object = std::make_unique<VmtTestTarget>();
    std::vector<CapturedLifecycle> events;
    auto sub = diag::hook_lifecycle().subscribe([&events](const diag::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    {
        Result<hook::VmtHook> v = hook::vmt_for("VmtLifecycleHook", object.get());
        ASSERT_TRUE(v.has_value()) << v.error().message();
        hook::VmtHook vh = std::move(*v);
        // Drop the handle (block exit) to restore the vptr and emit the Vmt Removed event.
    }

    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[0].name, "VmtLifecycleHook");
    EXPECT_EQ(events[0].kind, diag::HookKind::Vmt);
    EXPECT_EQ(events[0].transition, diag::HookTransition::Created);
    EXPECT_EQ(events[1].name, "VmtLifecycleHook");
    EXPECT_EQ(events[1].kind, diag::HookKind::Vmt);
    EXPECT_EQ(events[1].transition, diag::HookTransition::Removed);
}

// Runtime-diagnostics Snapshot: the one-call aggregator folded in from diagnostics_dump

class DiagnosticsSnapshotTest : public ::testing::Test
{
protected:
    void SetUp() override { diag::reset_intentional_leaks(); }

    void TearDown() override { diag::reset_intentional_leaks(); }
};

TEST_F(DiagnosticsSnapshotTest, EmptyInputsProduceZeroes)
{
    const diag::Snapshot snapshot = diag::collect();

    EXPECT_EQ(snapshot.total_intentional_leaks, 0u);
    EXPECT_EQ(snapshot.drift_total, 0u);
    EXPECT_EQ(snapshot.drift_healed, 0u);
    EXPECT_EQ(snapshot.drift_failed, 0u);
    // No anchor report was passed, so the quality roll-up is empty.
    EXPECT_EQ(snapshot.anchor_quality.total, 0u);
}

TEST_F(DiagnosticsSnapshotTest, AggregatesLeakCounters)
{
    diag::record_intentional_leak(LeakSubsystem::Logger);
    diag::record_intentional_leak(LeakSubsystem::Logger);
    diag::record_intentional_leak(LeakSubsystem::Worker);

    const diag::Snapshot snapshot = diag::collect();

    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(LeakSubsystem::Logger)], 2u);
    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(LeakSubsystem::Worker)], 1u);
    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(LeakSubsystem::HookManager)], 0u);
    EXPECT_EQ(snapshot.total_intentional_leaks, 3u);
}

TEST_F(DiagnosticsSnapshotTest, AggregatesDriftSummary)
{
    const std::array<rtti::DriftEntry, 3> drift{{
        {"L0", 0x10, 0x10, 0, true, {}},
        {"L1", 0x20, 0x28, 8, true, {}},
        {"L2", 0x30, 0, 0, false, {}},
    }};

    const diag::Snapshot snapshot = diag::collect(drift);

    EXPECT_EQ(snapshot.drift_total, 3u);
    EXPECT_EQ(snapshot.drift_healed, 2u);
    EXPECT_EQ(snapshot.drift_failed, 1u);
}

TEST_F(DiagnosticsSnapshotTest, AggregatesAnchorQuality)
{
    const std::array<anchor::ResolvedAnchor, 4> report{{
        {"a", anchor::AnchorKind::RipGlobal, anchor::AnchorStatus::Resolved, 1},
        {"b", anchor::AnchorKind::CodeOperand, anchor::AnchorStatus::Failed, 0},
        {"c", anchor::AnchorKind::Manual, anchor::AnchorStatus::Resolved, 2},
        {"d", anchor::AnchorKind::Quorum, anchor::AnchorStatus::Resolved, 3},
    }};

    const diag::Snapshot snapshot = diag::collect({}, report);

    EXPECT_EQ(snapshot.anchor_quality.total, 4u);
    EXPECT_EQ(snapshot.anchor_quality.resolved, 3u);
    EXPECT_EQ(snapshot.anchor_quality.failed, 1u);
    EXPECT_EQ(snapshot.anchor_quality.manual_at_risk, 1u); // the Manual entry
    EXPECT_EQ(snapshot.anchor_quality.corroborated, 1u);   // the resolved Quorum
}

TEST_F(DiagnosticsSnapshotTest, CountsLiveHookPopulation)
{
    // The population is derived from the process-wide hook-lifecycle stream, so assert on DELTAS around one hook rather
    // than absolute counts. The lifecycle emit is synchronous on the installing thread, so the tally is up to date by
    // the time inline_at / disable() returns.
    const diag::Snapshot before = diag::collect();

    {
        Result<hook::Hook> r = hook::inline_at(
            hook::InlineRequest{.name = "PopulationHook", .target = target_address(&lifecycle_target_add)},
            &lifecycle_detour_add);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        hook::Hook h = std::move(*r);

        const diag::Snapshot created = diag::collect();
        EXPECT_EQ(created.hooks_total, before.hooks_total + 1);       // created live
        EXPECT_EQ(created.hooks_active, before.hooks_active);         // but not armed on install
        EXPECT_EQ(created.hooks_disabled, before.hooks_disabled + 1); // counted disabled until enabled

        ASSERT_TRUE(h.enable().has_value());
        const diag::Snapshot armed = diag::collect();
        EXPECT_EQ(armed.hooks_total, before.hooks_total + 1);   // still live
        EXPECT_EQ(armed.hooks_active, before.hooks_active + 1); // now armed
        EXPECT_EQ(armed.hooks_disabled, before.hooks_disabled);

        ASSERT_TRUE(h.disable().has_value());
        const diag::Snapshot disabled = diag::collect();
        EXPECT_EQ(disabled.hooks_total, before.hooks_total + 1);       // still live
        EXPECT_EQ(disabled.hooks_active, before.hooks_active);         // no longer armed
        EXPECT_EQ(disabled.hooks_disabled, before.hooks_disabled + 1); // now counted disabled
        // Drop the handle (block exit) to emit Removed.
    }

    const diag::Snapshot after = diag::collect();
    EXPECT_EQ(after.hooks_total, before.hooks_total); // back to baseline
    EXPECT_EQ(after.hooks_active, before.hooks_active);
    EXPECT_EQ(after.hooks_disabled, before.hooks_disabled);
}

TEST_F(DiagnosticsSnapshotTest, SameNamedHooksOnDistinctTargetsEachCountAndSurviveRemoval)
{
    // The population tally keys on each hook's process-unique ledger id rather than on the hook name. Two hooks may
    // legitimately share a name (here "SharedName" on two distinct targets). If the tally keyed on the name, both would
    // fold into one map entry, the active/disabled split would be corrupted, and a single Removed would erase the
    // shared entry and drop the still-live survivor from the count as well. Deltas are taken around the pair because
    // the population is process-global.
    const diag::Snapshot before = diag::collect();

    {
        // The survivor lives in the outer scope; both hooks carry the same name on distinct targets. The detour only
        // has to match the target signature (the hooks are never invoked here), so the add detour serves both.
        Result<hook::Hook> survivor =
            hook::inline_at(hook::InlineRequest{.name = "SharedName", .target = target_address(&lifecycle_target_mul)},
                            &lifecycle_detour_add);
        ASSERT_TRUE(survivor.has_value()) << survivor.error().message();
        hook::Hook h_survivor = std::move(*survivor);
        ASSERT_TRUE(h_survivor.enable().has_value());

        {
            Result<hook::Hook> doomed = hook::inline_at(
                hook::InlineRequest{.name = "SharedName", .target = target_address(&lifecycle_target_add)},
                &lifecycle_detour_add);
            ASSERT_TRUE(doomed.has_value()) << doomed.error().message();
            hook::Hook h_doomed = std::move(*doomed);
            ASSERT_TRUE(h_doomed.enable().has_value());

            // Both live and armed. A name-keyed tally would have collapsed the shared name and reported only +1 here.
            const diag::Snapshot both = diag::collect();
            EXPECT_EQ(both.hooks_total, before.hooks_total + 2);
            EXPECT_EQ(both.hooks_active, before.hooks_active + 2);
            EXPECT_EQ(both.hooks_disabled, before.hooks_disabled);

            // Disabling one must move exactly one hook to disabled, not flip a shared entry and mis-split both.
            ASSERT_TRUE(h_doomed.disable().has_value());
            const diag::Snapshot split = diag::collect();
            EXPECT_EQ(split.hooks_total, before.hooks_total + 2);
            EXPECT_EQ(split.hooks_active, before.hooks_active + 1);
            EXPECT_EQ(split.hooks_disabled, before.hooks_disabled + 1);
            // Inner block exit destroys h_doomed, emitting Removed for its ledger id only.
        }

        // The survivor's slot is untouched by the other hook's removal: still live and still armed.
        const diag::Snapshot after_removal = diag::collect();
        EXPECT_EQ(after_removal.hooks_total, before.hooks_total + 1);
        EXPECT_EQ(after_removal.hooks_active, before.hooks_active + 1);
        EXPECT_EQ(after_removal.hooks_disabled, before.hooks_disabled);
        // Outer block exit destroys h_survivor, returning the population to baseline.
    }

    const diag::Snapshot restored = diag::collect();
    EXPECT_EQ(restored.hooks_total, before.hooks_total);
    EXPECT_EQ(restored.hooks_active, before.hooks_active);
    EXPECT_EQ(restored.hooks_disabled, before.hooks_disabled);
}
