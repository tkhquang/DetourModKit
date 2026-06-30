#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include "DetourModKit/diagnostics_dump.hpp"

using namespace DetourModKit;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

namespace
{
    // Distinct real targets so two inline hooks can coexist (layering one address would be refused).
    DMK_TEST_NOINLINE int dump_target_a(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int dump_target_b(int a, int b)
    {
        volatile int r = a - b;
        return r;
    }

    DMK_TEST_NOINLINE int dump_detour_a(int a, int b)
    {
        return a + b + 1;
    }

    DMK_TEST_NOINLINE int dump_detour_b(int a, int b)
    {
        return a - b - 1;
    }
} // namespace

class DiagnosticsDumpTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Diagnostics::reset_intentional_leaks();
        HookManager::get_instance().remove_all_hooks();
    }

    void TearDown() override
    {
        HookManager::get_instance().remove_all_hooks();
        Diagnostics::reset_intentional_leaks();
    }
};

TEST_F(DiagnosticsDumpTest, EmptyInputsProduceZeroes)
{
    const Diagnostics::Snapshot snapshot = Diagnostics::collect(HookManager::get_instance());

    EXPECT_EQ(snapshot.total_intentional_leaks, 0u);
    EXPECT_EQ(snapshot.hooks_active, 0u);
    EXPECT_EQ(snapshot.hooks_disabled, 0u);
    EXPECT_EQ(snapshot.hooks_total, 0u);
    EXPECT_EQ(snapshot.drift_total, 0u);
    EXPECT_EQ(snapshot.drift_healed, 0u);
    EXPECT_EQ(snapshot.drift_failed, 0u);
}

TEST_F(DiagnosticsDumpTest, AggregatesLeakCounters)
{
    Diagnostics::record_intentional_leak(Diagnostics::LeakSubsystem::Logger);
    Diagnostics::record_intentional_leak(Diagnostics::LeakSubsystem::Logger);
    Diagnostics::record_intentional_leak(Diagnostics::LeakSubsystem::Worker);

    const Diagnostics::Snapshot snapshot = Diagnostics::collect(HookManager::get_instance());

    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(Diagnostics::LeakSubsystem::Logger)], 2u);
    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(Diagnostics::LeakSubsystem::Worker)], 1u);
    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(Diagnostics::LeakSubsystem::HookManager)], 0u);
    EXPECT_EQ(snapshot.total_intentional_leaks, 3u);
}

TEST_F(DiagnosticsDumpTest, AggregatesHookCounts)
{
    HookManager &hooks = HookManager::get_instance();
    void *trampoline_a = nullptr;
    void *trampoline_b = nullptr;
    HookConfig disabled_config;
    disabled_config.auto_enable = false;

    ASSERT_TRUE(hooks
                    .create_inline_hook("DumpActiveHook", reinterpret_cast<std::uintptr_t>(&dump_target_a),
                                        reinterpret_cast<void *>(&dump_detour_a), &trampoline_a)
                    .has_value());
    ASSERT_TRUE(hooks
                    .create_inline_hook("DumpDisabledHook", reinterpret_cast<std::uintptr_t>(&dump_target_b),
                                        reinterpret_cast<void *>(&dump_detour_b), &trampoline_b, disabled_config)
                    .has_value());

    const Diagnostics::Snapshot snapshot = Diagnostics::collect(hooks);

    EXPECT_EQ(snapshot.hooks_active, 1u);
    EXPECT_EQ(snapshot.hooks_disabled, 1u);
    EXPECT_EQ(snapshot.hooks_total, 2u);
}

TEST_F(DiagnosticsDumpTest, AggregatesDriftSummary)
{
    const std::array<Rtti::DriftEntry, 3> drift{{
        {"L0", 0x10, 0x10, 0, true, {}},
        {"L1", 0x20, 0x28, 8, true, {}},
        {"L2", 0x30, 0, 0, false, {}},
    }};

    const Diagnostics::Snapshot snapshot = Diagnostics::collect(HookManager::get_instance(), drift);

    EXPECT_EQ(snapshot.drift_total, 3u);
    EXPECT_EQ(snapshot.drift_healed, 2u);
    EXPECT_EQ(snapshot.drift_failed, 1u);
}
