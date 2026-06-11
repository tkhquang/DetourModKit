#include <gtest/gtest.h>

#include "DetourModKit/diagnostics.hpp"

using DetourModKit::Diagnostics::LeakSubsystem;
namespace diag = DetourModKit::Diagnostics;

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
