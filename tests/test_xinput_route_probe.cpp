#include "internal/xinput_route_probe.hpp"
#include "test_alloc_probe.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <thread>

namespace
{
    using DetourModKit::detail::XInputRouteMember;
    using DetourModKit::detail::XInputRouteProbe;
    using DetourModKit::detail::XInputRouteProbeIdentity;

    XInputRouteProbeIdentity make_identity(const void *state) noexcept
    {
        return {
            .owner = 19,
            .hook_epoch = 23,
            .member = XInputRouteMember::Primary,
            .user_index = 1,
            .state_address = reinterpret_cast<std::uintptr_t>(state),
        };
    }

    class XInputRouteProbeTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            DetourModKit::detail::set_xinput_route_probe_failures_for_test(false, false, false);
            DetourModKit::detail::close_xinput_route_probes();
            ASSERT_TRUE(DetourModKit::detail::release_xinput_route_probe_if_idle());
            ASSERT_TRUE(DetourModKit::detail::reserve_xinput_route_probe());
        }

        void TearDown() override
        {
            DetourModKit::detail::set_xinput_route_probe_failures_for_test(false, false, false);
            EXPECT_TRUE(DetourModKit::detail::set_xinput_route_probe_token_for_test(0));
            DetourModKit::detail::close_xinput_route_probes();
            EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 0);
            EXPECT_TRUE(DetourModKit::detail::release_xinput_route_probe_if_idle());
        }
    };
} // namespace

TEST_F(XInputRouteProbeTest, ExactInvocationAuthenticatesAndFinishRetainsItsLease)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    {
        XInputRouteProbe probe{identity};
        ASSERT_TRUE(probe.admitted());
        EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 1);
        DetourModKit::detail::xinput_route_probe_record(identity);
        EXPECT_TRUE(probe.finish());
        EXPECT_TRUE(probe.finish());
        EXPECT_EQ(DetourModKit::detail::xinput_route_probe_token_for_test(), 0);
        DetourModKit::detail::close_xinput_route_probes();
        EXPECT_FALSE(DetourModKit::detail::release_xinput_route_probe_if_idle());
        EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 1);
    }
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 0);
}

TEST_F(XInputRouteProbeTest, NoInvocationSuppliesNoReceipt)
{
    std::uint64_t state = 0;
    XInputRouteProbe probe{make_identity(&state)};
    ASSERT_TRUE(probe.admitted());
    EXPECT_FALSE(probe.finish());
}

TEST_F(XInputRouteProbeTest, EveryIdentityFieldMustMatch)
{
    std::uint64_t state = 0;
    std::uint64_t unrelated_state = 0;
    const auto identity = make_identity(&state);
    for (int i = 0; i < 5; ++i)
    {
        XInputRouteProbe probe{identity};
        ASSERT_TRUE(probe.admitted());
        auto wrong = identity;
        switch (i)
        {
        case 0:
            ++wrong.owner;
            break;
        case 1:
            ++wrong.hook_epoch;
            break;
        case 2:
            wrong.member = XInputRouteMember::Ex;
            break;
        case 3:
            ++wrong.user_index;
            break;
        case 4:
            wrong.state_address = reinterpret_cast<std::uintptr_t>(&unrelated_state);
            break;
        default:
            break;
        }
        DetourModKit::detail::xinput_route_probe_record(wrong);
        EXPECT_FALSE(probe.finish()) << i;
    }
}

TEST_F(XInputRouteProbeTest, ChangedNonceCannotAuthenticateTheSameSlot)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    XInputRouteProbe probe{identity};
    ASSERT_TRUE(probe.admitted());
    const auto token = DetourModKit::detail::xinput_route_probe_token_for_test();
    ASSERT_TRUE(DetourModKit::detail::set_xinput_route_probe_token_for_test(token + 128));
    DetourModKit::detail::xinput_route_probe_record(identity);
    ASSERT_TRUE(DetourModKit::detail::set_xinput_route_probe_token_for_test(token));
    EXPECT_FALSE(probe.finish());
}

TEST_F(XInputRouteProbeTest, AReusedSlotRejectsItsPreviousNonce)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    std::uintptr_t previous = 0;
    {
        XInputRouteProbe probe{identity};
        ASSERT_TRUE(probe.admitted());
        previous = DetourModKit::detail::xinput_route_probe_token_for_test();
        DetourModKit::detail::xinput_route_probe_record(identity);
        EXPECT_TRUE(probe.finish());
    }
    XInputRouteProbe probe{identity};
    ASSERT_TRUE(probe.admitted());
    const auto current = DetourModKit::detail::xinput_route_probe_token_for_test();
    ASSERT_NE(current, previous);
    ASSERT_TRUE(DetourModKit::detail::set_xinput_route_probe_token_for_test(previous));
    DetourModKit::detail::xinput_route_probe_record(identity);
    ASSERT_TRUE(DetourModKit::detail::set_xinput_route_probe_token_for_test(current));
    EXPECT_FALSE(probe.finish());
}

TEST_F(XInputRouteProbeTest, NestedMembersRestoreIndependentReceipts)
{
    std::uint64_t primary_state = 0;
    std::uint64_t ex_state = 0;
    const auto primary_identity = make_identity(&primary_state);
    auto ex_identity = make_identity(&ex_state);
    ex_identity.member = XInputRouteMember::Ex;
    XInputRouteProbe primary{primary_identity};
    ASSERT_TRUE(primary.admitted());
    const auto primary_token = DetourModKit::detail::xinput_route_probe_token_for_test();
    XInputRouteProbe ex{ex_identity};
    ASSERT_TRUE(ex.admitted());
    DetourModKit::detail::xinput_route_probe_record(primary_identity);
    DetourModKit::detail::xinput_route_probe_record(ex_identity);
    EXPECT_TRUE(ex.finish());
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_token_for_test(), primary_token);
    DetourModKit::detail::xinput_route_probe_record(primary_identity);
    EXPECT_TRUE(primary.finish());
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 2);
}

TEST_F(XInputRouteProbeTest, AnotherThreadCannotAuthenticateACopiedToken)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    XInputRouteProbe probe{identity};
    ASSERT_TRUE(probe.admitted());
    const auto token = DetourModKit::detail::xinput_route_probe_token_for_test();
    std::atomic<bool> token_stored{false};
    std::thread foreign(
        [identity, token, &token_stored]() -> void
        {
            token_stored.store(
                DetourModKit::detail::set_xinput_route_probe_token_for_test(token),
                std::memory_order_relaxed
            );
            DetourModKit::detail::xinput_route_probe_record(identity);
            (void)DetourModKit::detail::set_xinput_route_probe_token_for_test(0);
        }
    );
    foreign.join();
    ASSERT_TRUE(token_stored.load(std::memory_order_relaxed));
    EXPECT_FALSE(probe.finish());
}

TEST_F(XInputRouteProbeTest, ReservationFailureKeepsAdmissionClosed)
{
    DetourModKit::detail::close_xinput_route_probes();
    ASSERT_TRUE(DetourModKit::detail::release_xinput_route_probe_if_idle());
    DetourModKit::detail::set_xinput_route_probe_failures_for_test(true, false, false);
    EXPECT_FALSE(DetourModKit::detail::reserve_xinput_route_probe());
    std::uint64_t state = 0;
    XInputRouteProbe probe{make_identity(&state)};
    EXPECT_FALSE(probe.admitted());
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 0);
    DetourModKit::detail::set_xinput_route_probe_failures_for_test(false, false, false);
    ASSERT_TRUE(DetourModKit::detail::reserve_xinput_route_probe());
}

TEST_F(XInputRouteProbeTest, EntryFailurePreservesTheOuterTokenAndLease)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    XInputRouteProbe outer{identity};
    ASSERT_TRUE(outer.admitted());
    const auto token = DetourModKit::detail::xinput_route_probe_token_for_test();
    DetourModKit::detail::set_xinput_route_probe_failures_for_test(false, true, false);
    XInputRouteProbe inner{identity};
    EXPECT_FALSE(inner.admitted());
    EXPECT_FALSE(inner.finish());
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_token_for_test(), token);
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 1);
    DetourModKit::detail::set_xinput_route_probe_failures_for_test(false, false, false);
    DetourModKit::detail::xinput_route_probe_record(identity);
    EXPECT_TRUE(outer.finish());
}

TEST_F(XInputRouteProbeTest, FailedNestedRestoreRefusesBothVerdicts)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    XInputRouteProbe outer{identity};
    ASSERT_TRUE(outer.admitted());
    DetourModKit::detail::xinput_route_probe_record(identity);
    {
        XInputRouteProbe inner{identity};
        ASSERT_TRUE(inner.admitted());
        DetourModKit::detail::xinput_route_probe_record(identity);
        DetourModKit::detail::set_xinput_route_probe_failures_for_test(false, false, true);
        EXPECT_FALSE(inner.finish());
        DetourModKit::detail::set_xinput_route_probe_failures_for_test(false, false, false);
    }
    EXPECT_FALSE(outer.finish());
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_token_for_test(), 0);
}

TEST_F(XInputRouteProbeTest, ClosedAdmissionRetainsLeasesUntilTheirDestructors)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    const auto index = DetourModKit::detail::xinput_route_probe_tls_index_for_test();
    {
        XInputRouteProbe active{identity};
        ASSERT_TRUE(active.admitted());
        DetourModKit::detail::close_xinput_route_probes();
        XInputRouteProbe refused{identity};
        EXPECT_FALSE(refused.admitted());
        EXPECT_FALSE(DetourModKit::detail::release_xinput_route_probe_if_idle());
        EXPECT_EQ(DetourModKit::detail::xinput_route_probe_tls_index_for_test(), index);
        DetourModKit::detail::xinput_route_probe_record(identity);
        EXPECT_TRUE(active.finish());
        EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 1);
    }
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 0);
}

TEST_F(XInputRouteProbeTest, ReopenPreservesOldLeasesAndTheReservedIndex)
{
    std::uint64_t old_state = 0;
    std::uint64_t new_state = 0;
    const auto old_identity = make_identity(&old_state);
    auto new_identity = make_identity(&new_state);
    ++new_identity.hook_epoch;
    XInputRouteProbe old_probe{old_identity};
    ASSERT_TRUE(old_probe.admitted());
    const auto index = DetourModKit::detail::xinput_route_probe_tls_index_for_test();
    DetourModKit::detail::close_xinput_route_probes();
    ASSERT_TRUE(DetourModKit::detail::reserve_xinput_route_probe());
    XInputRouteProbe new_probe{new_identity};
    ASSERT_TRUE(new_probe.admitted());
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_tls_index_for_test(), index);
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 2);
    DetourModKit::detail::xinput_route_probe_record(new_identity);
    EXPECT_TRUE(new_probe.finish());
    DetourModKit::detail::xinput_route_probe_record(new_identity);
    EXPECT_FALSE(old_probe.finish());
}

TEST_F(XInputRouteProbeTest, FixedStorageRefusesOverflowWithoutAnUncountedProbe)
{
    std::array<std::uint64_t, 65> states{};
    std::array<std::optional<XInputRouteProbe>, 65> probes;
    for (std::size_t i = 0; i < 64; ++i)
    {
        probes[i].emplace(make_identity(&states[i]));
        ASSERT_TRUE(probes[i]->admitted());
    }
    probes.back().emplace(make_identity(&states.back()));
    EXPECT_FALSE(probes.back()->admitted());
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 64);
    for (std::size_t i = probes.size(); i > 0; --i)
    {
        probes[i - 1].reset();
    }
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 0);
    EXPECT_EQ(DetourModKit::detail::xinput_route_probe_token_for_test(), 0);
}

TEST_F(XInputRouteProbeTest, ProbeEntryRecordAndFinishAllocateNothingAndPreserveLastError)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    const auto before = dmk_test::thread_new_calls();
    ::SetLastError(0x4321);
    bool admitted = false;
    bool receipt = false;
    {
        XInputRouteProbe probe{identity};
        admitted = probe.admitted();
        DetourModKit::detail::xinput_route_probe_record(identity);
        receipt = probe.finish();
    }
    const DWORD last_error = ::GetLastError();
    const auto after = dmk_test::thread_new_calls();
    EXPECT_TRUE(admitted);
    EXPECT_TRUE(receipt);
    EXPECT_EQ(last_error, 0x4321);
    EXPECT_EQ(before, after);
}

TEST_F(XInputRouteProbeTest, InvalidIdentitiesNeverAcquireALease)
{
    std::uint64_t state = 0;
    const auto identity = make_identity(&state);
    for (int i = 0; i < 5; ++i)
    {
        auto invalid = identity;
        switch (i)
        {
        case 0:
            invalid.owner = 0;
            break;
        case 1:
            invalid.hook_epoch = 0;
            break;
        case 2:
            invalid.member = static_cast<XInputRouteMember>(2);
            break;
        case 3:
            invalid.user_index = 4;
            break;
        case 4:
            invalid.state_address = 0;
            break;
        default:
            break;
        }
        XInputRouteProbe probe{invalid};
        EXPECT_FALSE(probe.admitted()) << i;
        EXPECT_EQ(DetourModKit::detail::xinput_route_probe_inflight(), 0);
    }
}
