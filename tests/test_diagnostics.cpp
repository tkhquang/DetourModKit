#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "DetourModKit/address.hpp"
#include "DetourModKit/detail/worker.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"

#include "internal/diagnostics_population.hpp"
#include "internal/lifecycle_reaper.hpp"
#include "platform.hpp"

#include "fixtures/loader_lock_scope.hpp"
#include "test_alloc_probe.hpp"

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
    /** @brief Holds one counted test reference and balances its typed count at scope exit. */
    class ScopedModuleRef
    {
    public:
        explicit ScopedModuleRef(diag::ModulePinReason reason) noexcept
            : m_reason(reason), m_module(detail::acquire_module_ref(reason))
        {
        }

        ~ScopedModuleRef() noexcept { detail::release_module_ref(m_module, m_reason); }

        ScopedModuleRef(const ScopedModuleRef &) = delete;
        ScopedModuleRef &operator=(const ScopedModuleRef &) = delete;
        ScopedModuleRef(ScopedModuleRef &&) = delete;
        ScopedModuleRef &operator=(ScopedModuleRef &&) = delete;

        [[nodiscard]] bool acquired() const noexcept { return m_module != nullptr; }

    private:
        diag::ModulePinReason m_reason;
        HMODULE m_module;
    };

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

    DMK_TEST_NOINLINE int lifecycle_target_layered(int a, int b)
    {
        volatile int r = a - b;
        return r;
    }

    DMK_TEST_NOINLINE int lifecycle_target_mid(int a, int b)
    {
        volatile int r = a / (b != 0 ? b : 1);
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

// These resets isolate the intentional-leak counters for each DiagnosticsTest case.
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

// [B-100] Diagnostics boundary. Counter queries and recorders touch only static atomics, so they stay heap-free under
// the loader lock, while dispatcher subscription allocates and stays setup-tier.
class DiagnosticsLoaderBoundary : public DiagnosticsTest
{
};

TEST_F(DiagnosticsLoaderBoundary, CounterSurfaceIsAllocationFreeWhileSubscriptionIsSetupTier)
{
    (void)diag::scanner_faults();
    (void)diag::hook_lifecycle();

    long long counter_allocations = -1;
    {
        const dmk_test::ForcedLoaderProbe held;
        const long long before = dmk_test::thread_new_calls();
        diag::record_intentional_leak(LeakSubsystem::Logger);
        (void)diag::intentional_leak_count(LeakSubsystem::Logger);
        (void)diag::total_intentional_leaks();
        (void)diag::module_pin_count(diag::ModulePinReason::Bootstrap);
        (void)diag::total_module_pins();
        (void)diag::lifecycle_counters();
        counter_allocations = dmk_test::thread_new_calls() - before;
    }
    EXPECT_EQ(counter_allocations, 0LL) << "counters and recorders must stay heap-free under the loader lock";

    const long long before_subscribe = dmk_test::thread_new_calls();
    auto subscription = diag::scanner_faults().subscribe([](const diag::ScannerFaultEvent &) {});
    const long long subscribe_allocations = dmk_test::thread_new_calls() - before_subscribe;
    EXPECT_GT(subscribe_allocations, 0LL) << "subscription allocates, so it stays setup-tier";
}

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
        }
    );

    diag::scanner_faults().emit_safe(
        diag::ScannerFaultEvent{
            .faulted_regions = 5,
            .window_low = 0x1000,
            .window_high = 0x2000,
        }
    );

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
            }
        );

        diag::hook_lifecycle().emit_safe(
            diag::HookLifecycleEvent{
                .name = "camera",
                .ledger_id = 42,
                .kind = diag::HookKind::Mid,
                .transition = diag::HookTransition::Enabled,
            }
        );

        EXPECT_EQ(hits, 1);
        EXPECT_EQ(received.name, "camera");
        EXPECT_EQ(received.ledger_id, 42u);
        EXPECT_EQ(received.kind, diag::HookKind::Mid);
        EXPECT_EQ(received.transition, diag::HookTransition::Enabled);
    }
}

TEST(DiagnosticsEventBusTest, UnsubscribeStopsDelivery)
{
    int hits = 0;
    {
        auto sub = diag::scanner_faults().subscribe([&hits](const diag::ScannerFaultEvent &) { ++hits; });
        diag::scanner_faults().emit_safe(
            diag::ScannerFaultEvent{
                .faulted_regions = 1,
            }
        );
    }
    // The RAII subscription is destroyed at the block exit; a later emit must not reach the handler.
    diag::scanner_faults().emit_safe(
        diag::ScannerFaultEvent{
            .faulted_regions = 1,
        }
    );
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
            hook::InlineRequest{
                .name = "LifecycleHook",
                .target = target_address(&lifecycle_target_add),
            },
            &lifecycle_detour_add
        );
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
        hook::MidRequest{
            .name = "MidLifecycleHook",
            .target = target_address(&lifecycle_target_mul),
        },
        detour
    );
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
        hook::InlineRequest{
            .name = "NoOpLifecycleHook",
            .target = target_address(&lifecycle_target_add),
        },
        &lifecycle_detour_add
    );
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
    // The population is process-wide, so assert on DELTAS around one hook rather than absolute counts. The tally is
    // updated by the hook surface on the transitioning thread, so it is current by the time inline_at / disable()
    // returns.
    const diag::Snapshot before = diag::collect();
    const std::size_t hook_pins_before = diag::module_pin_count(diag::ModulePinReason::Hook);

    {
        Result<hook::Hook> r = hook::inline_at(
            hook::InlineRequest{
                .name = "PopulationHook",
                .target = target_address(&lifecycle_target_add),
            },
            &lifecycle_detour_add
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        hook::Hook h = std::move(*r);

        const diag::Snapshot created = diag::collect();
        EXPECT_EQ(created.hooks_total, before.hooks_total + 1);       // created live
        EXPECT_EQ(created.hooks_active, before.hooks_active);         // but not armed on install
        EXPECT_EQ(created.hooks_disabled, before.hooks_disabled + 1); // counted disabled until enabled
        EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::Hook), hook_pins_before + 1);

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
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::Hook), hook_pins_before);
}

TEST_F(DiagnosticsSnapshotTest, SameNamedHooksOnDistinctTargetsEachCountAndSurviveRemoval)
{
    // Hook names are caller-chosen and may repeat: two hooks can share one name on distinct targets (here
    // "SharedName"). Each must count on its own. A tally that folded them by identity would report one hook where two
    // are live, and one removal would drop the still-live survivor as well. Deltas are taken around the pair because
    // the population is process-global.
    const diag::Snapshot before = diag::collect();

    {
        // The survivor lives in the outer scope; both hooks carry the same name on distinct targets. The detour only
        // has to match the target signature (the hooks are never invoked here), so the add detour serves both.
        Result<hook::Hook> survivor = hook::inline_at(
            hook::InlineRequest{
                .name = "SharedName",
                .target = target_address(&lifecycle_target_mul),
            },
            &lifecycle_detour_add
        );
        ASSERT_TRUE(survivor.has_value()) << survivor.error().message();
        hook::Hook h_survivor = std::move(*survivor);
        ASSERT_TRUE(h_survivor.enable().has_value());

        {
            Result<hook::Hook> doomed = hook::inline_at(
                hook::InlineRequest{
                    .name = "SharedName",
                    .target = target_address(&lifecycle_target_add),
                },
                &lifecycle_detour_add
            );
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

TEST_F(DiagnosticsSnapshotTest, VmtHookIsCountedArmedFromCreation)
{
    // A VMT hook has no enable verb: swapping the vptr arms it, so it is live the instant vmt_for returns. An inline or
    // mid hook is the opposite and stays disabled until enable(). Counting a fresh VMT hook as disabled would report an
    // armed target as inert for its whole lifetime, since no later transition would ever correct it.
    const diag::Snapshot before = diag::collect();
    auto object = std::make_unique<VmtTestTarget>();

    {
        Result<hook::VmtHook> v = hook::vmt_for("VmtPopulationHook", object.get());
        ASSERT_TRUE(v.has_value()) << v.error().message();
        hook::VmtHook vh = std::move(*v);

        const diag::Snapshot armed = diag::collect();
        EXPECT_EQ(armed.hooks_total, before.hooks_total + 1);
        EXPECT_EQ(armed.hooks_active, before.hooks_active + 1);
        EXPECT_EQ(armed.hooks_disabled, before.hooks_disabled);
        // Drop the handle (block exit) to restore the vptr and leave the population.
    }

    const diag::Snapshot after = diag::collect();
    EXPECT_EQ(after.hooks_total, before.hooks_total);
    EXPECT_EQ(after.hooks_active, before.hooks_active);
    EXPECT_EQ(after.hooks_disabled, before.hooks_disabled);
}

TEST_F(DiagnosticsSnapshotTest, DestroyingAnArmedHookReleasesBothFigures)
{
    // Teardown forces its own status to Disabled without publishing a Disabled transition, so the armed state has to be
    // captured before that store. Reading it afterwards would leave the unit the enable added on the tally forever:
    // total returns to baseline while active does not, and the derived disabled figure underflows.
    const diag::Snapshot before = diag::collect();

    {
        Result<hook::Hook> r = hook::inline_at(
            hook::InlineRequest{
                .name = "ArmedTeardownHook",
                .target = target_address(&lifecycle_target_add),
            },
            &lifecycle_detour_add
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        hook::Hook h = std::move(*r);
        ASSERT_TRUE(h.enable().has_value());

        const diag::Snapshot armed = diag::collect();
        ASSERT_EQ(armed.hooks_active, before.hooks_active + 1);
        // Destroy while still armed, without an intervening disable().
    }

    const diag::Snapshot after = diag::collect();
    EXPECT_EQ(after.hooks_total, before.hooks_total);
    EXPECT_EQ(after.hooks_active, before.hooks_active);
    EXPECT_EQ(after.hooks_disabled, before.hooks_disabled);
}

TEST_F(DiagnosticsSnapshotTest, PinnedLayerRemainsInTheLivePopulation)
{
    // An inverted teardown leaves the older target patch and ledger record live. The Removed event retires the handle,
    // but the population must retain the hook while DMK still conservatively reports its target as hooked.
    const diag::Snapshot before = diag::collect();

    Result<hook::Hook> older_result = hook::inline_at(
        hook::InlineRequest{
            .name = "PinnedPopulationBase",
            .target = target_address(&lifecycle_target_layered),
        },
        &lifecycle_detour_add
    );
    ASSERT_TRUE(older_result.has_value()) << older_result.error().message();
    std::optional<hook::Hook> older{std::move(*older_result)};
    ASSERT_TRUE(older->enable().has_value());

    Result<hook::Hook> newer_result = hook::inline_at(
        hook::InlineRequest{
            .name = "PinnedPopulationTop",
            .target = target_address(&lifecycle_target_layered),
        },
        &lifecycle_detour_add
    );
    ASSERT_TRUE(newer_result.has_value()) << newer_result.error().message();
    std::optional<hook::Hook> newer{std::move(*newer_result)};

    const diag::Snapshot layered = diag::collect();
    ASSERT_EQ(layered.hooks_total, before.hooks_total + 2);
    ASSERT_EQ(layered.hooks_active, before.hooks_active + 1);
    ASSERT_EQ(layered.hooks_disabled, before.hooks_disabled + 1);

    older.reset();

    const diag::Snapshot retained = diag::collect();
    EXPECT_EQ(retained.hooks_total, layered.hooks_total);
    EXPECT_EQ(retained.hooks_active, layered.hooks_active);
    EXPECT_EQ(retained.hooks_disabled, layered.hooks_disabled);

    // The newer disabled backend is also deliberately retained so it cannot restore over the pinned older patch.
    // release() abandons the handle without emitting, and the destructor it disarms must not subtract either: an
    // abandoned hook stays installed, so subtracting once would under-report and twice would underflow the tally.
    newer->release();
    const diag::Snapshot released = diag::collect();
    EXPECT_EQ(released.hooks_total, layered.hooks_total);
    EXPECT_EQ(released.hooks_active, layered.hooks_active);
    EXPECT_EQ(released.hooks_disabled, layered.hooks_disabled);

    newer.reset();

    const diag::Snapshot after_handle_destroyed = diag::collect();
    EXPECT_EQ(after_handle_destroyed.hooks_total, layered.hooks_total);
    EXPECT_EQ(after_handle_destroyed.hooks_active, layered.hooks_active);
    EXPECT_EQ(after_handle_destroyed.hooks_disabled, layered.hooks_disabled);
}

TEST_F(DiagnosticsSnapshotTest, MidHookIsCountedDisabledFromCreation)
{
    // Created-armed is decided per kind, and only a VMT hook qualifies. A mid hook patches its target no earlier than
    // an inline one does, so counting it armed on creation would report an unarmed detour as live until enable().
    const diag::Snapshot before = diag::collect();

    {
        auto detour = [](hook::MidContext &) {};
        Result<hook::Hook> r = hook::mid_at(
            hook::MidRequest{
                .name = "MidPopulationHook",
                .target = target_address(&lifecycle_target_mid),
            },
            detour
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        hook::Hook h = std::move(*r);

        const diag::Snapshot created = diag::collect();
        EXPECT_EQ(created.hooks_total, before.hooks_total + 1);
        EXPECT_EQ(created.hooks_active, before.hooks_active);
        EXPECT_EQ(created.hooks_disabled, before.hooks_disabled + 1);
    }

    const diag::Snapshot after = diag::collect();
    EXPECT_EQ(after.hooks_total, before.hooks_total);
    EXPECT_EQ(after.hooks_active, before.hooks_active);
    EXPECT_EQ(after.hooks_disabled, before.hooks_disabled);
}

TEST_F(DiagnosticsSnapshotTest, PopulationStaysExactUnderConcurrentTransitions)
{
    // The three figures share one atomic word so a reader observes them from a single load. This drives the tally
    // directly because the interleaving that matters cannot be produced through the hook surface: installing thousands
    // of real hooks would need thousands of distinct targets. Every thread runs a balanced create/enable/disable/remove
    // cycle, so an exact tally must return to its exact starting value.
    namespace population = DetourModKit::detail::hook_population;

    std::size_t start_total = 0;
    std::size_t start_active = 0;
    std::size_t start_disabled = 0;
    population::read(start_total, start_active, start_disabled);

    constexpr int thread_count = 8;
    constexpr int cycles_per_thread = 2000;
    std::atomic<bool> go{false};
    std::atomic<int> split_violations{0};
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (int i = 0; i < thread_count; ++i)
    {
        workers.emplace_back(
            [&go, &split_violations]
            {
                while (!go.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                for (int cycle = 0; cycle < cycles_per_thread; ++cycle)
                {
                    population::record_created(false);
                    population::record_enabled();

                    // Sampled mid-flight from another thread's updates: active can never exceed total, because every
                    // transition moves both fields in one read-modify-write. Splitting them across two words would
                    // let a reader land between a peer's two stores and see an armed hook that is not yet counted
                    // live. The derived disabled figure is not sampled here; the delta cases above pin it exactly.
                    std::size_t total = 0;
                    std::size_t active = 0;
                    std::size_t disabled = 0;
                    population::read(total, active, disabled);
                    if (active > total)
                    {
                        split_violations.fetch_add(1, std::memory_order_relaxed);
                    }

                    population::record_disabled();
                    population::record_removed(false);
                }
            }
        );
    }

    go.store(true, std::memory_order_release);
    for (std::thread &worker : workers)
    {
        worker.join();
    }

    EXPECT_EQ(split_violations.load(std::memory_order_relaxed), 0);

    std::size_t end_total = 0;
    std::size_t end_active = 0;
    std::size_t end_disabled = 0;
    population::read(end_total, end_active, end_disabled);
    EXPECT_EQ(end_total, start_total);
    EXPECT_EQ(end_active, start_active);
    EXPECT_EQ(end_disabled, start_disabled);
}

TEST(LifecycleCounters, ReaperStartRecordsThePermanentPin)
{
    // These counters are monotonic and process-wide. The start and pin counts stay absolute because the reaper is a
    // process-lifetime singleton: exactly one start, whichever case in this process caused it. The abandonment count
    // is a delta, because an earlier case can already have recorded one.
    const diagnostics::LifecycleCounters before = diagnostics::lifecycle_counters();

    // Any retirement builds the reaper on first use. Completed destruction proves the thread ran.
    static std::atomic<bool> s_destroyed{false};
    s_destroyed.store(false);
    struct Probe
    {
        ~Probe() { s_destroyed.store(true, std::memory_order_release); }
    };
    detail::reap_owner(std::make_unique<Probe>());

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!s_destroyed.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::yield();
    }
    ASSERT_TRUE(s_destroyed.load(std::memory_order_acquire)) << "the reaper never destroyed the queued owner";

    const diagnostics::LifecycleCounters after = diagnostics::lifecycle_counters();
    EXPECT_EQ(after.reaper_started, 1u) << "one process-lifetime reaper start must be recorded";
    EXPECT_EQ(after.permanent_pins, 1u) << "the reaper start must record its permanent module pin";
    EXPECT_EQ(after.abandoned_owners, before.abandoned_owners) << "a completed retirement is not an abandonment";
}

TEST(LifecycleCounters, RefusedSharedOwnerRundownCountsAnAbandonedOwner)
{
    const diagnostics::LifecycleCounters before = diagnostics::lifecycle_counters();

    // A retire callback that reports the rundown unsafe forces the reaper to retain the parcel permanently.
    std::shared_ptr<void> owner = std::make_shared<int>(7);
    const std::weak_ptr<void> observed = owner;
    ASSERT_TRUE(detail::reap_shared_owner(owner, [](void *) noexcept { return false; }));
    EXPECT_EQ(owner, nullptr) << "a queued retirement must consume the caller's reference";

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (diagnostics::lifecycle_counters().abandoned_owners == before.abandoned_owners &&
           std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::yield();
    }
    EXPECT_EQ(diagnostics::lifecycle_counters().abandoned_owners, before.abandoned_owners + 1)
        << "a refused rundown must count as an abandoned owner";
    EXPECT_FALSE(observed.expired()) << "an abandoned owner must stay retained, never released";
}

TEST(LifecycleCounters, SnapshotCarriesTheLifecycleCounters)
{
    const diagnostics::LifecycleCounters before = diagnostics::lifecycle_counters();
    const std::size_t expected_reaper_started = before.reaper_started == 0 ? 1 : before.reaper_started;
    const std::size_t expected_permanent_pins = before.permanent_pins == 0 ? 1 : before.permanent_pins;
    const std::size_t expected_abandoned_owners = before.abandoned_owners + 2;

    std::shared_ptr<void> first_owner = std::make_shared<int>(11);
    std::shared_ptr<void> second_owner = std::make_shared<int>(13);
    const std::weak_ptr<void> first_observed = first_owner;
    const std::weak_ptr<void> second_observed = second_owner;
    ASSERT_TRUE(detail::reap_shared_owner(first_owner, [](void *) noexcept { return false; }));
    ASSERT_TRUE(detail::reap_shared_owner(second_owner, [](void *) noexcept { return false; }));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (diagnostics::lifecycle_counters().abandoned_owners != expected_abandoned_owners &&
           std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::yield();
    }

    const diagnostics::LifecycleCounters direct = diagnostics::lifecycle_counters();
    ASSERT_EQ(direct.reaper_started, expected_reaper_started);
    ASSERT_EQ(direct.permanent_pins, expected_permanent_pins);
    ASSERT_EQ(direct.abandoned_owners, expected_abandoned_owners);

    const diagnostics::Snapshot snapshot = diagnostics::collect();
    EXPECT_EQ(snapshot.lifecycle.reaper_started, direct.reaper_started);
    EXPECT_EQ(snapshot.lifecycle.permanent_pins, direct.permanent_pins);
    EXPECT_EQ(snapshot.lifecycle.abandoned_owners, direct.abandoned_owners);
    EXPECT_FALSE(first_observed.expired());
    EXPECT_FALSE(second_observed.expired());
}

// These tests use deltas because process-lifetime reasons can already have nonzero counts.

TEST(ModulePins, ReasonNumbersRemainStable)
{
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::Hook), 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::Worker), 1u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::Bootstrap), 2u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::AsyncLogger), 3u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::MemoryCache), 4u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::InputPoller), 5u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::LifecycleReaper), 6u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::WndprocKeepalive), 7u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::XInputKeepalive), 8u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::XInputTarget), 9u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::MessageHookKeepalive), 10u);
    EXPECT_EQ(static_cast<std::uint8_t>(diag::ModulePinReason::Count), 11u);
}

TEST(ModulePins, OutOfRangeReasonReadsZero)
{
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::Count), 0u);
    EXPECT_EQ(diag::module_pin_count(static_cast<diag::ModulePinReason>(0xFF)), 0u);
}

TEST(ModulePins, AcquiresBookOnlyTheirReasonsAndReleasesBalanceThem)
{
    std::array<std::size_t, static_cast<std::size_t>(diag::ModulePinReason::Count)> before{};
    for (std::size_t i = 0; i < before.size(); ++i)
    {
        before[i] = diag::module_pin_count(static_cast<diag::ModulePinReason>(i));
    }
    const std::size_t total_before = diag::total_module_pins();

    {
        const ScopedModuleRef worker_ref{diag::ModulePinReason::Worker};
        const ScopedModuleRef logger_ref{diag::ModulePinReason::AsyncLogger};
        ASSERT_TRUE(worker_ref.acquired());
        ASSERT_TRUE(logger_ref.acquired());
        for (std::size_t i = 0; i < before.size(); ++i)
        {
            const auto reason = static_cast<diag::ModulePinReason>(i);
            const bool acquired =
                reason == diag::ModulePinReason::Worker || reason == diag::ModulePinReason::AsyncLogger;
            const std::size_t expected = acquired ? before[i] + 1 : before[i];
            EXPECT_EQ(diag::module_pin_count(reason), expected) << "reason index " << i;
        }
        EXPECT_EQ(diag::total_module_pins(), total_before + 2);
    }

    EXPECT_EQ(
        diag::module_pin_count(diag::ModulePinReason::Worker),
        before[static_cast<std::size_t>(diag::ModulePinReason::Worker)]
    );
    EXPECT_EQ(
        diag::module_pin_count(diag::ModulePinReason::AsyncLogger),
        before[static_cast<std::size_t>(diag::ModulePinReason::AsyncLogger)]
    );
    EXPECT_EQ(diag::total_module_pins(), total_before);
}

// A live StoppableWorker holds one Worker pin. A joined shutdown releases it.
TEST(ModulePins, StoppableWorkerBooksWorkerWhileRunningAndReleasesOnJoinedShutdown)
{
    const std::size_t before = diag::module_pin_count(diag::ModulePinReason::Worker);
    {
        StoppableWorker worker(
            "module-pin-proof",
            [](const std::stop_token &st)
            {
                while (!st.stop_requested())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        );
        EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::Worker), before + 1);
        worker.shutdown();
    }
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::Worker), before);
}

TEST(ModulePins, SnapshotCarriesThePinBreakdownAndDerivesTheTotalFromIt)
{
    const ScopedModuleRef worker_ref{diag::ModulePinReason::Worker};
    const ScopedModuleRef logger_ref{diag::ModulePinReason::AsyncLogger};
    ASSERT_TRUE(worker_ref.acquired());
    ASSERT_TRUE(logger_ref.acquired());

    const diagnostics::Snapshot snapshot = diagnostics::collect();
    EXPECT_GE(snapshot.module_pins[static_cast<std::size_t>(diag::ModulePinReason::Worker)], 1u);
    std::size_t sum = 0;
    for (std::size_t i = 0; i < snapshot.module_pins.size(); ++i)
    {
        const auto reason = static_cast<diag::ModulePinReason>(i);
        EXPECT_EQ(snapshot.module_pins[i], diag::module_pin_count(reason)) << "reason index " << i;
        sum += snapshot.module_pins[i];
    }
    EXPECT_EQ(snapshot.total_module_pins, sum);
    EXPECT_EQ(diag::total_module_pins(), sum);
}
