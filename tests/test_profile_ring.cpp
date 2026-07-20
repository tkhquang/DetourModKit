#include <gtest/gtest.h>

#include "DetourModKit/detail/profile_ring.hpp"

#include <cstdint>
#include <string>
#include <vector>

using DetourModKit::detail::ProfileRing;
using DetourModKit::detail::ticks_to_microseconds;

namespace
{
    struct Recovered
    {
        std::string name;
        std::int64_t start_ticks;
        std::uint32_t duration_us;
        std::uint32_t thread_id;
    };

    [[nodiscard]] std::vector<Recovered> collect(const ProfileRing &ring)
    {
        std::vector<Recovered> out;
        ring.visit_committed(
            [&out](const char *name, std::int64_t start_ticks, std::uint32_t duration_us, std::uint32_t thread_id)
            { out.push_back(Recovered{name, start_ticks, duration_us, thread_id}); });
        return out;
    }
} // namespace

TEST(ProfileRingTest, ConversionRejectsNonIncreasingAndInvalidInputs)
{
    EXPECT_EQ(ticks_to_microseconds(100, 100, 10'000'000), 0u);
    EXPECT_EQ(ticks_to_microseconds(100, 50, 10'000'000), 0u);
    EXPECT_EQ(ticks_to_microseconds(0, 1'000'000, 0), 0u);
    EXPECT_EQ(ticks_to_microseconds(0, 1'000'000, -1), 0u);
}

TEST(ProfileRingTest, ConversionIsExactBelowSaturation)
{
    EXPECT_EQ(ticks_to_microseconds(0, 10'000'000, 10'000'000), 1'000'000u);
    EXPECT_EQ(ticks_to_microseconds(0, 25, 10'000'000), 2u); // truncating, not rounding
    EXPECT_EQ(ticks_to_microseconds(-1'000, -990, 10'000'000), 1u);
    EXPECT_EQ(ticks_to_microseconds(0, 3, 3), 1'000'000u);
    EXPECT_EQ(ticks_to_microseconds(0, INT64_MAX - 1, INT64_MAX), 999'999u);
}

// The sub-second remainder of a tick frequency above ~1.8e13 Hz cannot be scaled by 1'000'000 in 64 bits, so
// ticks_to_microseconds routes it through multiply_fraction. These expectations are exact rational quotients: the
// cheaper "divide the frequency down first" approximation reports 1000000 for the first two, which is not merely
// imprecise but a full microsecond above the true value, and rounds a sub-microsecond interval up past its own bound.
TEST(ProfileRingTest, ExtremeFrequencyFractionIsExact)
{
    using DetourModKit::detail::multiply_fraction;
    constexpr std::uint64_t US = 1'000'000;

    EXPECT_EQ(multiply_fraction(9223372036854775806ULL, US, 9223372036854775807ULL), 999999ULL);
    EXPECT_EQ(multiply_fraction(18446744073709551614ULL, US, 18446744073709551615ULL), 999999ULL);
    EXPECT_EQ(multiply_fraction(12345678901234567ULL, US, 99999999999999937ULL), 123456ULL);
    EXPECT_EQ(multiply_fraction(9999999999999999ULL, US, 10000000000000000ULL), 999999ULL);

    // Degenerate operands must not spin the bit loop or divide by zero.
    EXPECT_EQ(multiply_fraction(1, US, 18446744073709551615ULL), 0ULL);
    EXPECT_EQ(multiply_fraction(0, US, 7), 0ULL);
    EXPECT_EQ(multiply_fraction(5, 0, 7), 0ULL);
    EXPECT_EQ(multiply_fraction(5, US, 0), 0ULL);

    // Small exact identities, including a multiplier whose only set bit is the least significant one, and the
    // in-contract boundary where the remainder is one below the divisor.
    EXPECT_EQ(multiply_fraction(3, 5, 4), 3ULL);
    EXPECT_EQ(multiply_fraction(0, 1, 1), 0ULL);
    EXPECT_EQ(multiply_fraction(2, 4, 3), 2ULL);
    EXPECT_EQ(multiply_fraction(6, 4, 7), 3ULL);
}

TEST(ProfileRingTest, ConversionSaturatesRatherThanWrapping)
{
    constexpr std::int64_t TEN_MHZ = 10'000'000;
    // 71.6 minutes is the last representable duration; one tick more must saturate instead of wrapping the uint32.
    constexpr std::int64_t LAST_EXACT_SECONDS = 4294;
    EXPECT_EQ(ticks_to_microseconds(0, LAST_EXACT_SECONDS * TEN_MHZ, TEN_MHZ),
              static_cast<std::uint32_t>(LAST_EXACT_SECONDS) * 1'000'000u);
    EXPECT_EQ(ticks_to_microseconds(0, (LAST_EXACT_SECONDS + 1) * TEN_MHZ, TEN_MHZ), UINT32_MAX);

    // Directly multiplying this twelve-day delta by 1'000'000 overflows int64 before division.
    constexpr std::int64_t TWELVE_DAYS_TICKS = 12 * 24 * 60 * 60 * TEN_MHZ;
    EXPECT_EQ(ticks_to_microseconds(0, TWELVE_DAYS_TICKS, TEN_MHZ), UINT32_MAX);

    // The widest interval expressible in the parameters. Taken in signed arithmetic this subtraction is undefined,
    // not merely large.
    EXPECT_EQ(ticks_to_microseconds(INT64_MIN, INT64_MAX, TEN_MHZ), UINT32_MAX);
    EXPECT_EQ(ticks_to_microseconds(INT64_MIN, 0, 1), UINT32_MAX);
}

TEST(ProfileRingTest, InertRingAcceptsEveryOperationAndCommitsNothing)
{
    ProfileRing ring(0);
    EXPECT_EQ(ring.capacity(), 0u);

    const auto claim = ring.claim();
    EXPECT_FALSE(claim.owned);
    ring.publish(claim, "ignored", 1, 2, 3);

    EXPECT_EQ(ring.claims(), 1u);
    EXPECT_EQ(ring.dropped(), 1u);
    EXPECT_EQ(ring.resident(), 0u);
    EXPECT_TRUE(collect(ring).empty());

    ring.reset();
    EXPECT_EQ(ring.claims(), 0u);
}

TEST(ProfileRingTest, NonPowerOfTwoCapacityIsRefusedRatherThanMisIndexed)
{
    ProfileRing ring(6);
    EXPECT_EQ(ring.capacity(), 0u);
    EXPECT_FALSE(ring.claim().owned);
}

TEST(ProfileRingTest, CommittedSamplesRoundTripInOrder)
{
    ProfileRing ring(4);
    for (std::uint32_t i = 0; i < 3; ++i)
    {
        const auto claim = ring.claim();
        ASSERT_TRUE(claim.owned);
        ring.publish(claim, "sample", static_cast<std::int64_t>(i), i * 10, i);
    }

    const auto recovered = collect(ring);
    ASSERT_EQ(recovered.size(), 3u);
    for (std::uint32_t i = 0; i < 3; ++i)
    {
        EXPECT_EQ(recovered[i].name, "sample");
        EXPECT_EQ(recovered[i].start_ticks, static_cast<std::int64_t>(i));
        EXPECT_EQ(recovered[i].duration_us, i * 10);
        EXPECT_EQ(recovered[i].thread_id, i);
    }
    EXPECT_EQ(ring.dropped(), 0u);
    EXPECT_EQ(ring.resident(), 3u);
}

// Force one-capacity slot reuse with both writers held. A colliding writer must never turn an owned slot into a
// committed-looking state while either payload is incomplete.
TEST(ProfilerConcurrencyProof, RingSlotReuseCannotPublishTornSample)
{
    constexpr std::size_t CAPACITY = 4;
    ProfileRing ring(CAPACITY);
    ASSERT_EQ(ring.capacity(), CAPACITY);

    // Writer A opens slot 0 and stalls before publishing its payload.
    const auto writer_a = ring.claim();
    ASSERT_TRUE(writer_a.owned);
    ASSERT_EQ(writer_a.index, 0u);

    // Drive the rest of one full ring capacity so the next claim lands on slot 0 again.
    for (std::uint32_t i = 1; i < CAPACITY; ++i)
    {
        const auto filler = ring.claim();
        ASSERT_TRUE(filler.owned);
        ASSERT_NE(filler.index, writer_a.index);
        ring.publish(filler, "filler", static_cast<std::int64_t>(i), i, i);
    }

    // Writer B reuses slot 0 while A still owns it. It must be refused and counted, never overwrite A's slot.
    const auto writer_b = ring.claim();
    EXPECT_FALSE(writer_b.owned);
    EXPECT_EQ(ring.dropped(), 1u);
    ring.publish(writer_b, "writer_b", 999, 999, 999); // a refused claim publishes nothing

    // Export with both writers controlled: the contested slot is skipped entirely and every visible sample is one
    // writer's complete payload.
    auto recovered = collect(ring);
    ASSERT_EQ(recovered.size(), CAPACITY - 1);
    for (const Recovered &entry : recovered)
    {
        EXPECT_EQ(entry.name, "filler");
        EXPECT_EQ(entry.duration_us, static_cast<std::uint32_t>(entry.start_ticks));
        EXPECT_EQ(entry.thread_id, static_cast<std::uint32_t>(entry.start_ticks));
    }

    // A completing late still publishes into the slot it owns, and only then does it become visible.
    ring.publish(writer_a, "writer_a", 7, 11, 13);
    recovered = collect(ring);
    ASSERT_EQ(recovered.size(), CAPACITY);
    const Recovered &late = recovered.back();
    EXPECT_EQ(late.name, "writer_a");
    EXPECT_EQ(late.start_ticks, 7);
    EXPECT_EQ(late.duration_us, 11u);
    EXPECT_EQ(late.thread_id, 13u);
}

// The other half of the reuse collision: a writer descheduled between taking its ring position and inspecting its slot
// must not resurrect a stale sample over the newer one that took the slot meanwhile.
TEST(ProfilerConcurrencyProof, StaleWriterCannotOverwriteANewerCommittedSlot)
{
    ProfileRing ring(2);

    // Writer A takes position 0 and loses the CPU before it can inspect slot 0.
    const std::uint64_t stalled_position = ring.reserve_position();
    const auto second = ring.claim(); // position 1 -> slot 1
    ASSERT_TRUE(second.owned);
    ring.publish(second, "second", 2, 2, 2);
    const auto third = ring.claim(); // position 2 -> slot 0 again
    ASSERT_TRUE(third.owned);
    ASSERT_EQ(third.index, 0u);
    ring.publish(third, "third", 3, 3, 3);

    // A writer that took position 0 and lost the CPU for a full ring cycle resumes here.
    const auto stalled = ring.claim_at(stalled_position);
    EXPECT_FALSE(stalled.owned);
    EXPECT_EQ(ring.dropped(), 1u);
    EXPECT_EQ(ring.resident(), 2u);

    const auto recovered = collect(ring);
    ASSERT_EQ(recovered.size(), 2u);
    EXPECT_EQ(recovered[0].name, "second");
    EXPECT_EQ(recovered[1].name, "third");
}

TEST(ProfileRingTest, CommittedTicketCannotBeClaimedAgain)
{
    ProfileRing ring(2);
    const auto original = ring.claim();
    ASSERT_TRUE(original.owned);
    ring.publish(original, "original", 1, 2, 3);

    const auto duplicate = ring.claim_at(original.ticket);
    EXPECT_FALSE(duplicate.owned);
    EXPECT_EQ(ring.dropped(), 1u);

    const auto recovered = collect(ring);
    ASSERT_EQ(recovered.size(), 1u);
    EXPECT_EQ(recovered.front().name, "original");
}

TEST(ProfileRingTest, ResetClearsSamplesAndCounters)
{
    ProfileRing ring(2);
    const auto claim = ring.claim();
    ASSERT_TRUE(claim.owned);
    ring.publish(claim, "before_reset", 1, 2, 3);
    ASSERT_EQ(collect(ring).size(), 1u);

    ring.reset();
    EXPECT_EQ(ring.claims(), 0u);
    EXPECT_EQ(ring.dropped(), 0u);
    EXPECT_EQ(ring.resident(), 0u);
    EXPECT_TRUE(collect(ring).empty());

    // Ticketing restarts cleanly: the slot a reset abandoned is claimable again.
    const auto after = ring.claim();
    EXPECT_TRUE(after.owned);
}
