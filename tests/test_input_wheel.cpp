#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <utility>
#include <vector>

#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/input_poller.hpp"
#include "internal/input_intercept.hpp"

#include "fixtures/throwing_copy.hpp"
#include "test_alloc_probe.hpp"
#include "fixtures/input_fixture.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;
using namespace dmk_test::input_fixture;

TEST_F(InputPollerTest, WheelReRegisterDiscardsStaleNotchBacklog)
{
    // The keyboard-only poller has no wheel owner and cannot drain the live queue hook's counters.
    std::vector<detail::InputBinding> bindings;
    detail::InputBinding keyboard;
    keyboard.name = "keyboard_only";
    keyboard.keys = {keyboard_key(0x41)};
    bindings.push_back(std::move(keyboard));
    detail::InputPoller poller(std::move(bindings));

    // The transition discard drains counters the interception layer owns, so it runs only for the poller that holds
    // the layer. This case needs no OS hook, so grant the lease directly.
    ASSERT_TRUE(detail::adopt_owner_for_test(poller.intercept_owner_for_test()));

    // The hook accumulates notches after an earlier unbind. No wheel owner drains that backlog.
    detail::seed_wheel_notches_for_test({3, 2, 0, 0});

    // The first wheel binding changes m_has_wheel_bindings to true. The accumulated unbound notches must not replay as
    // phantom Press edges.
    detail::InputBinding wheel;
    wheel.name = "wheel_action";
    wheel.keys = {mouse_wheel(WheelCode::Up)};
    wheel.on_press = []() {};
    ASSERT_TRUE(poller.add_binding(std::move(wheel)));

    const auto remaining = detail::take_wheel_counts(poller.intercept_owner_for_test());
    EXPECT_EQ(remaining[0], 0);
    EXPECT_EQ(remaining[1], 0);
    EXPECT_EQ(remaining[2], 0);
    EXPECT_EQ(remaining[3], 0);

    detail::uninstall(poller.intercept_owner_for_test());
}

#if defined(DMK_ENABLE_TEST_SEAMS)

namespace
{
    std::atomic<int> g_carry_wheel_presses{0};
    std::atomic<int> g_carry_drain_budget{0};
    std::atomic<int> g_carry_drain_calls{0};
    std::atomic<bool> g_carry_probe_entered{false};
    std::atomic<bool> g_carry_probe_release{false};
    int g_carry_host_context = 0;

    int32_t DMK_WHEELHOST_CALL carry_stub_open(void *, std::uint64_t, std::uint64_t, WheelHostLease *out_lease) noexcept
    {
        *out_lease = 0xCA55;
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL
    carry_stub_drain(void *, WheelHostLease, std::uint32_t out_counts[DMK_WHEEL_DIRECTIONS]) noexcept
    {
        g_carry_drain_calls.fetch_add(1, std::memory_order_acq_rel);
        for (int i = 0; i < DMK_WHEEL_DIRECTIONS; ++i)
        {
            out_counts[i] = 0;
        }
        if (g_carry_drain_budget.exchange(0, std::memory_order_acq_rel) > 0)
        {
            out_counts[DMK_WHEEL_UP] = 1;
        }
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL carry_stub_close(void *, WheelHostLease, std::uint64_t, std::uint64_t) noexcept
    {
        return DMK_WHEELHOST_OK;
    }

    WheelHostTable g_carry_host_table{
        .struct_size = sizeof(WheelHostTable),
        .abi_version = DMK_WHEELHOST_ABI_VERSION,
        .capability_bits = DMK_WHEELHOST_CAP_VERTICAL | DMK_WHEELHOST_CAP_HORIZONTAL | DMK_WHEELHOST_CAP_CONSUME |
                           DMK_WHEELHOST_CAP_ROUTE,
        .host_identity = 1,
        .host_context = &g_carry_host_context,
        .open_lease = &carry_stub_open,
        .publish_capture = &wheel_host_stub_publish,
        .drain_counts = &carry_stub_drain,
        .close_lease = &carry_stub_close,
        .route_status = &wheel_host_stub_route_status,
        .retarget = &wheel_host_stub_retarget,
    };

    [[nodiscard]] bool carry_wait(const std::function<bool()> &done)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        while (!done())
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return done();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return true;
    }
} // namespace

// External notch counts have no physical source to replay. A concurrent reshape must retain them for the next cycle.
TEST(InputPollerExternalWheelTest, ReshapeBetweenDrainAndEvaluationCarriesDrainedNotches)
{
    struct SeamReset
    {
        ~SeamReset() { detail::g_input_external_wheel_post_drain_probe = nullptr; }
    } seam_reset;

    g_carry_wheel_presses.store(0);
    g_carry_drain_budget.store(0);
    g_carry_drain_calls.store(0);
    g_carry_probe_entered.store(false);
    g_carry_probe_release.store(false);

    std::vector<detail::InputBinding> bindings;
    detail::InputBinding binding;
    binding.name = "carry_wheel";
    binding.keys = {mouse_wheel(WheelCode::Up)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() noexcept { g_carry_wheel_presses.fetch_add(1); };
    bindings.push_back(std::move(binding));

    auto poller = std::make_shared<detail::InputPoller>(
        std::move(bindings),
        std::chrono::milliseconds{1},
        false,
        0,
        GamepadCode::TriggerThreshold,
        GamepadCode::StickThreshold,
        input::Input::WheelBackend::ExternalHost,
        &g_carry_host_table
    );
    ASSERT_EQ(poller->prepare_wheel_source(), DMK_WHEELHOST_OK);

    // The probe parks each drain with a notch. The release flag stays set after the first park for later drains.
    detail::g_input_external_wheel_post_drain_probe = [](const std::array<int, 4> &counts)
    {
        if (counts[DMK_WHEEL_UP] > 0)
        {
            g_carry_probe_entered.store(true);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
            while (!g_carry_probe_release.load() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
        }
    };

    poller->start();

    // The first cycle runs the no-wheel -> wheel discard drain. Stage the notch only after that cycle has passed, so
    // the discard cannot eat it.
    ASSERT_TRUE(carry_wait([] { return g_carry_drain_calls.load() >= 3; })) << "the poll loop never reached its drain";
    g_carry_drain_budget.store(1);
    ASSERT_TRUE(carry_wait([] { return g_carry_probe_entered.load(); }))
        << "the poll thread never drained the staged notch";

    // The poll thread parks after drain but before evaluation. The changed generation must retain the notch for another
    // cycle.
    detail::InputBinding dummy;
    dummy.name = "carry_dummy";
    dummy.keys = {keyboard_key(0x42)};
    ASSERT_TRUE(poller->add_binding(std::move(dummy)));

    g_carry_probe_release.store(true);

    EXPECT_TRUE(carry_wait([] { return g_carry_wheel_presses.load() >= 1; }))
        << "the reshaped-away cycle dropped the drained notch instead of carrying it";
    EXPECT_EQ(g_carry_wheel_presses.load(), 1) << "the carried notch must deliver exactly once";

    poller->shutdown();
    poller.reset();
}

namespace
{
    // Clears every poll-loop seam the carry cases install. Declare it before the poller, so the poll thread joins
    // before the seams and their captures die.
    struct CarrySeamReset
    {
        CarrySeamReset() noexcept
        {
            g_carry_wheel_presses.store(0);
            g_carry_drain_budget.store(0);
            g_carry_drain_calls.store(0);
            g_carry_probe_entered.store(false);
            g_carry_probe_release.store(false);
        }
        ~CarrySeamReset()
        {
            detail::g_input_external_wheel_post_drain_probe = nullptr;
            detail::g_input_post_stage_probe = nullptr;
            detail::g_input_key_state_probe = nullptr;
        }
        CarrySeamReset(const CarrySeamReset &) = delete;
        CarrySeamReset &operator=(const CarrySeamReset &) = delete;
    };

    [[nodiscard]] detail::InputBinding carry_wheel_binding(std::function<void()> on_press)
    {
        detail::InputBinding binding;
        binding.name = "carry_wheel";
        binding.keys = {mouse_wheel(WheelCode::Up)};
        binding.trigger = input::Trigger::Press;
        binding.on_press = std::move(on_press);
        return binding;
    }

    [[nodiscard]] std::shared_ptr<detail::InputPoller> make_carry_poller(std::vector<detail::InputBinding> bindings)
    {
        return std::make_shared<detail::InputPoller>(
            std::move(bindings),
            std::chrono::milliseconds{1},
            false,
            0,
            GamepadCode::TriggerThreshold,
            GamepadCode::StickThreshold,
            input::Input::WheelBackend::ExternalHost,
            &g_carry_host_table
        );
    }

    /// Parks the poll thread in the post-drain probe once, on the first drain that carries a notch.
    void park_on_first_carry_notch(const std::array<int, 4> &counts)
    {
        if (counts[DMK_WHEEL_UP] > 0 && !g_carry_probe_entered.exchange(true))
        {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
            while (!g_carry_probe_release.load() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
        }
    }

    /// Waits for @p cycles more host drains, so a late duplicate delivery has time to show.
    [[nodiscard]] bool carry_settle(int cycles)
    {
        const int target = g_carry_drain_calls.load() + cycles;
        return carry_wait([target] { return g_carry_drain_calls.load() >= target; });
    }
} // namespace

// A staging failure that lands before the wheel evaluation must park the drained external counts ([B-92]). The
// reshape grows the binding set past the staged-callback capacity, so the pass fails at its first allocation.
TEST(InputPollerExternalWheelTest, StagingFailureBeforeWheelEvaluationCarriesDrainedNotches)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    static std::atomic<bool> s_alloc_armed{false};
    static std::atomic<long long> s_calls_before{0};
    static std::atomic<long long> s_alloc_attempts{-1};
    s_alloc_armed.store(false);
    s_alloc_attempts.store(-1);
    // The failed pass logs, so the logger's first use must not land inside the armed window.
    (void)DetourModKit::log();
    CarrySeamReset seam_reset;

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(carry_wheel_binding([]() noexcept { g_carry_wheel_presses.fetch_add(1); }));
    auto poller = make_carry_poller(std::move(bindings));
    ASSERT_EQ(poller->prepare_wheel_source(), DMK_WHEELHOST_OK);

    detail::g_input_external_wheel_post_drain_probe = [](const std::array<int, 4> &counts)
    {
        const bool first = counts[DMK_WHEEL_UP] > 0 && !g_carry_probe_entered.load();
        park_on_first_carry_notch(counts);
        if (first)
        {
            // This thread's next allocation is the staging reserve that the reshape made grow.
            s_calls_before.store(dmk_test::thread_new_calls());
            dmk_test::arm_alloc_failure(0);
            s_alloc_armed.store(true);
        }
    };
    detail::g_input_post_stage_probe = [](std::size_t)
    {
        if (s_alloc_armed.exchange(false))
        {
            s_alloc_attempts.store(dmk_test::thread_new_calls() - s_calls_before.load());
            dmk_test::disarm_alloc_failure();
        }
    };
    poller->start();

    ASSERT_TRUE(carry_wait([] { return g_carry_drain_calls.load() >= 3; })) << "the poll loop never reached its drain";
    g_carry_drain_budget.store(1);
    ASSERT_TRUE(carry_wait([] { return g_carry_probe_entered.load(); }))
        << "the poll thread never drained the staged notch";
    detail::InputBinding dummy;
    dummy.name = "carry_dummy";
    dummy.keys = {keyboard_key(0x42)};
    ASSERT_TRUE(poller->add_binding(std::move(dummy)));
    g_carry_probe_release.store(true);

    ASSERT_TRUE(carry_wait([] { return s_alloc_attempts.load() >= 0; })) << "the armed cycle never reached staging";
    ASSERT_GE(s_alloc_attempts.load(), 1) << "the staging pass never allocated, so no failure preceded the wheel";
    EXPECT_TRUE(carry_wait([] { return g_carry_wheel_presses.load() >= 1; }))
        << "the failed pass lost the drained external notch";
    ASSERT_TRUE(carry_settle(8));
    EXPECT_EQ(g_carry_wheel_presses.load(), 1) << "the parked notch must deliver exactly once";

    poller->shutdown();
    poller.reset();
}

// The generation-mismatch branch already parked the drained counts when a later staging copy throws. The failed pass
// must still deliver them exactly once, so an additive re-park of the same counts fails this case.
TEST(InputPollerExternalWheelTest, StagingFailureAfterParkingCarriesDrainedNotchesOnce)
{
    constexpr int THROWING_VK = 0x43;
    static std::atomic<bool> s_key_down{false};
    static std::atomic<bool> s_notch_cycle{false};
    static std::atomic<int> s_parked_cycle_failed{-1};
    s_key_down.store(false);
    s_notch_cycle.store(false);
    s_parked_cycle_failed.store(-1);
    auto throw_on_copy = std::make_shared<std::atomic<bool>>(false);
    auto failed_copies = std::make_shared<std::atomic<int>>(0);
    auto invocations = std::make_shared<std::atomic<int>>(0);
    CarrySeamReset seam_reset;

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(carry_wheel_binding([]() noexcept { g_carry_wheel_presses.fetch_add(1); }));
    detail::InputBinding throwing;
    throwing.name = "carry_throwing_key";
    throwing.keys = {keyboard_key(THROWING_VK)};
    throwing.trigger = input::Trigger::Press;
    throwing.on_press = dmk_test::ThrowingCopyCallback{throw_on_copy, failed_copies, invocations};
    bindings.push_back(std::move(throwing));
    auto poller = make_carry_poller(std::move(bindings));
    ASSERT_EQ(poller->prepare_wheel_source(), DMK_WHEELHOST_OK);

    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == THROWING_VK && s_key_down.load(); };
    detail::g_input_external_wheel_post_drain_probe = [](const std::array<int, 4> &counts)
    {
        const bool first = counts[DMK_WHEEL_UP] > 0 && !g_carry_probe_entered.load();
        park_on_first_carry_notch(counts);
        if (first)
        {
            s_notch_cycle.store(true);
        }
    };
    detail::g_input_post_stage_probe = [throw_on_copy, failed_copies](std::size_t)
    {
        if (s_notch_cycle.exchange(false))
        {
            s_parked_cycle_failed.store(failed_copies->load() > 0 ? 1 : 0);
            throw_on_copy->store(false);
        }
    };
    poller->start();

    ASSERT_TRUE(carry_wait([] { return g_carry_drain_calls.load() >= 3; })) << "the poll loop never reached its drain";
    g_carry_drain_budget.store(1);
    ASSERT_TRUE(carry_wait([] { return g_carry_probe_entered.load(); }))
        << "the poll thread never drained the staged notch";
    throw_on_copy->store(true);
    s_key_down.store(true);
    detail::InputBinding dummy;
    dummy.name = "carry_dummy";
    dummy.keys = {keyboard_key(0x42)};
    ASSERT_TRUE(poller->add_binding(std::move(dummy)));
    g_carry_probe_release.store(true);

    ASSERT_TRUE(carry_wait([] { return s_parked_cycle_failed.load() >= 0; }))
        << "the parked cycle never reached staging";
    EXPECT_EQ(s_parked_cycle_failed.load(), 1) << "the key edge copy did not fail in the parked cycle";
    EXPECT_TRUE(carry_wait([] { return g_carry_wheel_presses.load() >= 1; }))
        << "the failed pass lost the parked external notch";
    ASSERT_TRUE(carry_settle(8));
    EXPECT_EQ(g_carry_wheel_presses.load(), 1) << "a failed pass parked the drained counts twice";
    EXPECT_EQ(invocations->load(), 1) << "the key edge must fire once on the cycle after the failure";

    poller->shutdown();
    poller.reset();
}

// The ExternalHost twin of InterceptMessageHookPollerTest.StagingFailureDoesNotDestroyTheWheelNotch. A copy failure
// after the drained counts reached the pulse leaves them to the pulse rollback, never to the carry as well.
TEST(InputPollerExternalWheelTest, StagingFailureDoesNotDestroyTheExternalWheelNotch)
{
    auto throw_on_copy = std::make_shared<std::atomic<bool>>(false);
    auto failed_copies = std::make_shared<std::atomic<int>>(0);
    auto invocations = std::make_shared<std::atomic<int>>(0);
    CarrySeamReset seam_reset;

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(carry_wheel_binding(dmk_test::ThrowingCopyCallback{throw_on_copy, failed_copies, invocations}));
    auto poller = make_carry_poller(std::move(bindings));
    ASSERT_EQ(poller->prepare_wheel_source(), DMK_WHEELHOST_OK);

    detail::g_input_external_wheel_post_drain_probe = [throw_on_copy](const std::array<int, 4> &counts)
    {
        if (counts[DMK_WHEEL_UP] > 0 && !g_carry_probe_entered.exchange(true))
        {
            throw_on_copy->store(true);
        }
    };
    detail::g_input_post_stage_probe = [throw_on_copy, failed_copies](std::size_t)
    {
        if (failed_copies->load() > 0)
        {
            throw_on_copy->store(false);
        }
    };
    poller->start();

    ASSERT_TRUE(carry_wait([] { return g_carry_drain_calls.load() >= 3; })) << "the poll loop never reached its drain";
    g_carry_drain_budget.store(1);
    ASSERT_TRUE(carry_wait([failed_copies] { return failed_copies->load() > 0; }))
        << "the notch cycle never failed its staging copy";
    EXPECT_TRUE(carry_wait([invocations] { return invocations->load() >= 1; }))
        << "the failed pass destroyed the drained external notch";
    ASSERT_TRUE(carry_settle(8));
    EXPECT_EQ(invocations->load(), 1) << "the rolled-back notch must deliver exactly once";
    EXPECT_EQ(failed_copies->load(), 1);

    poller->shutdown();
    poller.reset();
}

#endif // defined(DMK_ENABLE_TEST_SEAMS)
