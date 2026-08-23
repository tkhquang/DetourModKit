/**
 * @file test_drain_backoff.cpp
 * @brief Pins the count, deadline, and pause order in detail::drain_until_zero.
 */

#include "internal/drain_backoff.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace
{
    namespace detail = DetourModKit::detail;

    struct NothrowDrainCount
    {
        [[nodiscard]] std::size_t operator()() const noexcept { return 0; }
    };

    struct ThrowingDrainCount
    {
        [[nodiscard]] std::size_t operator()() const { return 0; }
    };

    template <class CountFn>
    concept DrainCountAccepted =
        requires(CountFn &count) { detail::drain_until_zero(count, std::chrono::steady_clock::time_point{}); };

    static_assert(DrainCountAccepted<NothrowDrainCount>);
    static_assert(!DrainCountAccepted<ThrowingDrainCount>);

#if defined(DMK_ENABLE_TEST_SEAMS)
    [[nodiscard]] std::uint64_t yield_tier_count() noexcept
    {
        return detail::g_drain_backoff_yields.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::uint64_t sleep_tier_count() noexcept
    {
        return detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
    }
#endif

    TEST(DrainUntilZeroTest, ZeroCountReturnsTrueWithoutPausing)
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        const std::uint64_t yields_before = yield_tier_count();
        const std::uint64_t sleeps_before = sleep_tier_count();
#endif
        const bool drained = detail::drain_until_zero(
            []() noexcept -> std::size_t { return 0; },
            std::chrono::steady_clock::now() + std::chrono::seconds{60}
        );
        EXPECT_TRUE(drained);
#if defined(DMK_ENABLE_TEST_SEAMS)
        EXPECT_EQ(yield_tier_count(), yields_before);
        EXPECT_EQ(sleep_tier_count(), sleeps_before);
#endif
    }

    TEST(DrainUntilZeroTest, ExpiredDeadlineReportsFalseBeforeAnyPause)
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        const std::uint64_t yields_before = yield_tier_count();
        const std::uint64_t sleeps_before = sleep_tier_count();
#endif
        std::size_t polls = 0;
        const bool drained = detail::drain_until_zero(
            [&polls]() noexcept -> std::size_t
            {
                ++polls;
                return 1;
            },
            std::chrono::steady_clock::now() - std::chrono::seconds{1}
        );
        EXPECT_FALSE(drained);
        // The deadline check runs between the poll and the pause, so an expired drain polls once and never pauses.
        EXPECT_EQ(polls, 1U);
#if defined(DMK_ENABLE_TEST_SEAMS)
        EXPECT_EQ(yield_tier_count(), yields_before);
        EXPECT_EQ(sleep_tier_count(), sleeps_before);
#endif
    }

    TEST(DrainUntilZeroTest, LongCountdownDrainsThroughTheSleepTier)
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        const std::uint64_t sleeps_before = sleep_tier_count();
#endif
        // More polls than the 64-yield burst, so the drain must escalate to the sleep tier before it completes.
        std::size_t remaining = 80;
        const bool drained = detail::drain_until_zero(
            [&remaining]() noexcept -> std::size_t
            {
                if (remaining > 0)
                {
                    --remaining;
                }
                return remaining;
            },
            std::chrono::steady_clock::now() + std::chrono::seconds{60}
        );
        EXPECT_TRUE(drained);
        EXPECT_EQ(remaining, 0U);
#if defined(DMK_ENABLE_TEST_SEAMS)
        EXPECT_GT(sleep_tier_count(), sleeps_before);
#endif
    }
} // namespace
