#include <gtest/gtest.h>

#include <array>
#include <cstddef>

#include "DetourModKit/diagnostics_dump.hpp"

using namespace DetourModKit;

class DiagnosticsDumpTest : public ::testing::Test
{
protected:
    void SetUp() override { Diagnostics::reset_intentional_leaks(); }

    void TearDown() override { Diagnostics::reset_intentional_leaks(); }
};

TEST_F(DiagnosticsDumpTest, EmptyInputsProduceZeroes)
{
    const Diagnostics::Snapshot snapshot = Diagnostics::collect();

    EXPECT_EQ(snapshot.total_intentional_leaks, 0u);
    EXPECT_EQ(snapshot.drift_total, 0u);
    EXPECT_EQ(snapshot.drift_healed, 0u);
    EXPECT_EQ(snapshot.drift_failed, 0u);
}

TEST_F(DiagnosticsDumpTest, AggregatesLeakCounters)
{
    Diagnostics::record_intentional_leak(Diagnostics::LeakSubsystem::Logger);
    Diagnostics::record_intentional_leak(Diagnostics::LeakSubsystem::Logger);
    Diagnostics::record_intentional_leak(Diagnostics::LeakSubsystem::Worker);

    const Diagnostics::Snapshot snapshot = Diagnostics::collect();

    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(Diagnostics::LeakSubsystem::Logger)], 2u);
    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(Diagnostics::LeakSubsystem::Worker)], 1u);
    EXPECT_EQ(snapshot.intentional_leaks[static_cast<std::size_t>(Diagnostics::LeakSubsystem::HookManager)], 0u);
    EXPECT_EQ(snapshot.total_intentional_leaks, 3u);
}

TEST_F(DiagnosticsDumpTest, AggregatesDriftSummary)
{
    const std::array<Rtti::DriftEntry, 3> drift{{
        {"L0", 0x10, 0x10, 0, true, {}},
        {"L1", 0x20, 0x28, 8, true, {}},
        {"L2", 0x30, 0, 0, false, {}},
    }};

    const Diagnostics::Snapshot snapshot = Diagnostics::collect(drift);

    EXPECT_EQ(snapshot.drift_total, 3u);
    EXPECT_EQ(snapshot.drift_healed, 2u);
    EXPECT_EQ(snapshot.drift_failed, 1u);
}
