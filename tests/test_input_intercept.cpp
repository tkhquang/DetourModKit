#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "fixtures/throwing_copy.hpp"
#include "internal/input_intercept.hpp"
#include "internal/input_poller.hpp"
#include "test_alloc_probe.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/logger.hpp"
#include "fixtures/intercept_lease.hpp"

using namespace DetourModKit;
using DetourModKit::detail::add_wheel_notches;
using DetourModKit::detail::evaluate_consume_rules;
using DetourModKit::detail::evaluate_published_consume_rules;
using DetourModKit::detail::GamepadConsumeRule;
using DetourModKit::detail::GamepadSuppressState;
using DetourModKit::detail::install_message_hook;
using DetourModKit::detail::install_wndproc;
using DetourModKit::detail::install_xinput;
using DetourModKit::detail::intercept_owned_by;
using DetourModKit::detail::MAX_GAMEPAD_CONSUME_RULES;
using DetourModKit::detail::MAX_WHEEL_NOTCHES;
using DetourModKit::detail::MAX_WHEEL_PENDING;
using DetourModKit::detail::message_hook_installed;
using DetourModKit::detail::next_intercept_owner;
using DetourModKit::detail::publish_gamepad_consume_rules;
using DetourModKit::detail::publish_gamepad_suppress;
using DetourModKit::detail::publish_wheel_consume;
using DetourModKit::detail::set_wndproc_uninstall_exchange_seam;
using DetourModKit::detail::set_wndproc_window_override_for_test;
using DetourModKit::detail::set_xinput_module_override_for_test;
using DetourModKit::detail::step_gamepad_suppress;
using DetourModKit::detail::step_wheel_pulse;
using DetourModKit::detail::take_wheel_counts;
using DetourModKit::detail::uninstall;
using DetourModKit::detail::wheel_direction_bit;
using DetourModKit::detail::WheelDirection;
using DetourModKit::detail::WheelPulseState;
using DetourModKit::detail::wndproc_installed;
using DetourModKit::detail::wndproc_saved_procedure;
using DetourModKit::detail::WndProcUninstallStage;
using DetourModKit::detail::xinput_bound_user_index;
using DetourModKit::detail::xinput_ex_trampoline;
using DetourModKit::detail::xinput_installed;
using DetourModKit::detail::xinput_module_refs_held;
using DetourModKit::detail::xinput_permanent_primary_retained;
using DetourModKit::detail::xinput_trampoline;
using DetourModKit::detail::XInputGetStateFn;

namespace
{
    // Direction bit positions in the wheel pulse mask (mirrors WheelCode order).
    constexpr uint8_t WHEEL_UP_BIT = 1u << 0;
    constexpr uint8_t WHEEL_DOWN_BIT = 1u << 1;
    constexpr uint8_t WHEEL_RIGHT_BIT = 1u << 3;

    constexpr uint64_t GRACE_MS = 80;

    std::atomic<bool> s_data_plane_entry_reached{false};
    std::atomic<bool> s_release_data_plane_entry{false};
    std::atomic<bool> s_wheel_capture_entry_reached{false};
    std::atomic<bool> s_release_wheel_capture_entry{false};

    void park_data_plane_entry() noexcept
    {
        s_data_plane_entry_reached.store(true, std::memory_order_release);
        while (!s_release_data_plane_entry.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    void park_wheel_capture_entry() noexcept
    {
        s_wheel_capture_entry_reached.store(true, std::memory_order_release);
        while (!s_release_wheel_capture_entry.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    // Builds a consume chord binding for the rule-publishing tests.
    detail::InputBinding make_consume_chord(std::vector<InputCode> modifiers, std::vector<InputCode> keys)
    {
        detail::InputBinding binding;
        binding.name = "chord";
        binding.modifiers = std::move(modifiers);
        binding.keys = std::move(keys);
        binding.consume = true;
        binding.trigger = input::Trigger::Hold;
        return binding;
    }
} // namespace

// Control API safe to call without an installed hook

TEST(InterceptControlTest, AccessorsAndSettersWithNothingInstalled)
{
    // A unit-test process installs no hooks, so the accessors report "off" and the setters/teardown are safe no-ops
    // that only touch atomics.
    EXPECT_FALSE(xinput_installed());
    EXPECT_FALSE(wndproc_installed());
    EXPECT_EQ(xinput_trampoline(), nullptr);

    // An unowned layer authorizes nothing. Every data-plane operation refuses rather than writing process-global state
    // the detours read on behalf of a caller that holds no lease.
    const std::uint64_t standalone = DetourModKit::detail::STANDALONE_INTERCEPT_OWNER;
    const auto counts = take_wheel_counts(standalone);
    for (const int value : counts)
    {
        EXPECT_EQ(value, 0);
    }

    EXPECT_FALSE(publish_wheel_consume(wheel_direction_bit(WheelDirection::Up), standalone));
    EXPECT_FALSE(publish_wheel_consume(0, standalone));
    EXPECT_FALSE(publish_gamepad_suppress(0x0001, standalone));
    EXPECT_FALSE(publish_gamepad_suppress(0, standalone));

    // Idempotent teardown leaves nothing installed.
    uninstall();
    EXPECT_FALSE(xinput_installed());
    EXPECT_FALSE(wndproc_installed());
}

// step_wheel_pulse: one notch maps to exactly one Press edge

TEST(WheelPulseTest, IdleProducesNoPulse)
{
    WheelPulseState state;
    EXPECT_EQ(step_wheel_pulse(state), 0u);
    EXPECT_EQ(step_wheel_pulse(state), 0u);
}

TEST(WheelPulseTest, SingleNotchPulsesThenGoesLow)
{
    WheelPulseState state;
    state.pending[0] = 1; // one Up notch

    // Cycle 1: the notch is consumed and reported pressed.
    EXPECT_EQ(step_wheel_pulse(state), WHEEL_UP_BIT);
    // Cycle 2: forced low so the edge detector can re-arm.
    EXPECT_EQ(step_wheel_pulse(state), 0u);
    // Cycle 3: nothing pending.
    EXPECT_EQ(step_wheel_pulse(state), 0u);
}

TEST(WheelPulseTest, TwoNotchesProduceTwoSeparatedPulses)
{
    WheelPulseState state;
    state.pending[1] = 2; // two Down notches

    EXPECT_EQ(step_wheel_pulse(state), WHEEL_DOWN_BIT); // first notch
    EXPECT_EQ(step_wheel_pulse(state), 0u);             // forced gap
    EXPECT_EQ(step_wheel_pulse(state), WHEEL_DOWN_BIT); // second notch
    EXPECT_EQ(step_wheel_pulse(state), 0u);             // forced gap
    EXPECT_EQ(step_wheel_pulse(state), 0u);             // drained
}

TEST(WheelPulseTest, DirectionsAreIndependent)
{
    WheelPulseState state;
    state.pending[0] = 1; // Up
    state.pending[3] = 1; // Right

    EXPECT_EQ(step_wheel_pulse(state), static_cast<uint8_t>(WHEEL_UP_BIT | WHEEL_RIGHT_BIT));
    EXPECT_EQ(step_wheel_pulse(state), 0u);
}

// add_wheel_notches: backlog accumulation is capped

TEST(WheelPulseTest, AddWheelNotchesAccumulatesBelowCap)
{
    WheelPulseState state;
    add_wheel_notches(state, {2, 0, 0, 0});
    add_wheel_notches(state, {3, 0, 0, 0});
    EXPECT_EQ(state.pending[0], 5);
}

TEST(WheelPulseTest, AddWheelNotchesClampsRunawayBacklog)
{
    WheelPulseState state;
    // A single huge burst saturates at the cap rather than queuing every notch.
    add_wheel_notches(state, {1000, 0, 0, 0});
    EXPECT_EQ(state.pending[0], MAX_WHEEL_PENDING);

    // Repeated bursts cannot push pending past the cap, so phantom notches cannot accumulate without bound under
    // sustained fast scrolling.
    for (int i = 0; i < 100; ++i)
    {
        add_wheel_notches(state, {50, 50, 50, 50});
    }
    for (int dir = 0; dir < 4; ++dir)
    {
        EXPECT_EQ(state.pending[dir], MAX_WHEEL_PENDING);
    }
}

TEST(WheelPulseTest, AddWheelNotchesIgnoresNegativeCounts)
{
    WheelPulseState state;
    state.pending[1] = 4;
    // A corrupt negative count must not drive pending negative (which would underflow the unsigned-style drain in
    // step_wheel_pulse).
    add_wheel_notches(state, {0, -10, 0, 0});
    EXPECT_EQ(state.pending[1], 4);
}

TEST(WheelPulseTest, CappedBacklogStillDrainsOnePulsePerNotch)
{
    WheelPulseState state;
    add_wheel_notches(state, {0, 1000, 0, 0});
    ASSERT_EQ(state.pending[1], MAX_WHEEL_PENDING);

    // Each retained notch still maps to exactly one Press edge (one pulse, one gap).
    int pulses = 0;
    for (int cycle = 0; cycle < MAX_WHEEL_PENDING * 2; ++cycle)
    {
        if (step_wheel_pulse(state) == WHEEL_DOWN_BIT)
        {
            ++pulses;
        }
    }
    EXPECT_EQ(pulses, MAX_WHEEL_PENDING);
    EXPECT_EQ(state.pending[1], 0);
}

// T-WHEEL: the window-procedure wheel path accumulates signed deltas per axis and publishes abs(total)/WHEEL_DELTA
// notches, retaining the sub-notch remainder. Ownership and capture-epoch tags keep owned, unowned, and cross-epoch
// fragments from combining, and the swallow verdict stays per message and per direction.

class WheelDeltaTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        uninstall();
        m_owner = next_intercept_owner();
        ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(m_owner)) << "could not claim the idle layer";
    }

    void TearDown() override { uninstall(m_owner); }

    [[nodiscard]] std::array<int, 4> drain() noexcept { return take_wheel_counts(m_owner); }

    std::uint64_t m_owner{0};
};

TEST_F(WheelDeltaTest, CoalescedMultipleEmitsEveryNotch)
{
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 240));
    const auto counts = drain();
    EXPECT_EQ(counts[0], 2) << "+240 is two notches, not one sign edge";
    EXPECT_EQ(counts[1], 0);
}

TEST_F(WheelDeltaTest, FragmentsAccumulateToOneNotch)
{
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_EQ(drain()[0], 0) << "a sub-notch fragment must not emit a notch";
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_EQ(drain()[0], 1) << "+60,+60 is one completed notch, not two";
}

TEST_F(WheelDeltaTest, ReversalCancelsAccumulatedDistance)
{
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, -60));
    auto counts = drain();
    EXPECT_EQ(counts[0], 0);
    EXPECT_EQ(counts[1], 0);

    // The cancelled remainder is really zero: two further -60 fragments complete exactly one Down notch.
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, -60));
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, -60));
    counts = drain();
    EXPECT_EQ(counts[0], 0);
    EXPECT_EQ(counts[1], 1);
}

TEST_F(WheelDeltaTest, NegativeMultipleEmitsEveryNotch)
{
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, -240));
    const auto counts = drain();
    EXPECT_EQ(counts[0], 0);
    EXPECT_EQ(counts[1], 2);
}

TEST_F(WheelDeltaTest, HorizontalAxisIsIndependent)
{
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(true, 240));
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(true, -60));
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    auto counts = drain();
    EXPECT_EQ(counts[3], 2) << "+240 horizontal is two Right notches";
    EXPECT_EQ(counts[2], 0) << "-60 horizontal is a sub-notch remainder, not a Left notch";
    EXPECT_EQ(counts[0], 0) << "the vertical +60 must not combine with horizontal distance";

    // Each axis finishes its own pending remainder independently.
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(true, -60));
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    counts = drain();
    EXPECT_EQ(counts[2], 1);
    EXPECT_EQ(counts[0], 1);
}

TEST_F(WheelDeltaTest, OwnedPartialFragmentsAreSwallowedBeforeANotchCompletes)
{
    ASSERT_TRUE(publish_wheel_consume(wheel_direction_bit(WheelDirection::Up), m_owner));
    // Both owned +60 messages are swallowed, even though only the second completes a notch.
    EXPECT_TRUE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_TRUE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_EQ(drain()[0], 1);

    // The consume ownership is per direction: an owned Up mask must not swallow a Down message.
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, -120));
    EXPECT_EQ(drain()[1], 1);
}

TEST_F(WheelDeltaTest, UnownedThenOwnedFragmentsNeverCombine)
{
    // An unowned fragment reaches the game; its distance must not complete a notch with a later owned fragment.
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    ASSERT_TRUE(publish_wheel_consume(wheel_direction_bit(WheelDirection::Up), m_owner));
    EXPECT_TRUE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_EQ(drain()[0], 0) << "owned and unowned fragments combined into one notch";

    // The owned accumulation continues on its own: one more owned fragment completes the notch.
    EXPECT_TRUE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_EQ(drain()[0], 1);
}

TEST_F(WheelDeltaTest, OwnershipEpochResetClearsTheRemainder)
{
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));

    // Revoke and re-claim: the capture epoch advances and the remainder resets with it.
    uninstall(m_owner);
    m_owner = next_intercept_owner();
    ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(m_owner));

    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_EQ(drain()[0], 0) << "a fragment from the retired epoch combined across the reset";
    EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
    EXPECT_EQ(drain()[0], 1);
}

// step_gamepad_suppress: consume-until-release latch

TEST(GamepadSuppressTest, BarePressIsNotSuppressed)
{
    GamepadSuppressState state;
    // The trigger is physically down but no chord claims it (owned_now == 0):
    // a bare D-pad tap must reach the game.
    const uint16_t mask = step_gamepad_suppress(state, 0, static_cast<uint16_t>(GamepadCode::DpadUp), 1000, GRACE_MS);
    EXPECT_EQ(mask, 0u);
}

TEST(GamepadSuppressTest, ActiveChordSuppressesTrigger)
{
    GamepadSuppressState state;
    const uint16_t buttons = static_cast<uint16_t>(GamepadCode::LeftBumper | GamepadCode::DpadUp);
    const uint16_t mask =
        step_gamepad_suppress(state, static_cast<uint16_t>(GamepadCode::DpadUp), buttons, 1000, GRACE_MS);
    EXPECT_EQ(mask, static_cast<uint16_t>(GamepadCode::DpadUp));
}

TEST(GamepadSuppressTest, ModifierReleasedBeforeTriggerKeepsSuppressing)
{
    GamepadSuppressState state;
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);

    // Chord active: LB + D-pad both held.
    EXPECT_EQ(step_gamepad_suppress(state, dpad, static_cast<uint16_t>(lb | dpad), 1000, GRACE_MS), dpad);

    // Bumper released a frame before the thumb leaves the D-pad. The chord is no longer active (owned_now == 0) but the
    // trigger is still physically down, so it must stay suppressed. This is the leak the feature exists to prevent.
    EXPECT_EQ(step_gamepad_suppress(state, 0, dpad, 1016, GRACE_MS), dpad);
}

TEST(GamepadSuppressTest, TriggerReleaseSuppressesThroughGraceThenStops)
{
    GamepadSuppressState state;
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);

    // Claimed, then trigger physically released at t=1000.
    EXPECT_EQ(step_gamepad_suppress(state, dpad, dpad, 1000, GRACE_MS), dpad);
    // Within the grace window: still suppressed so the trailing release does not leak.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1040, GRACE_MS), dpad);
    // Past the grace window: the latch disarms and the game regains the button.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1200, GRACE_MS), 0u);
    // Stays released afterwards.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1300, GRACE_MS), 0u);
}

TEST(GamepadSuppressTest, RepressDuringGraceReHolds)
{
    GamepadSuppressState state;
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);

    EXPECT_EQ(step_gamepad_suppress(state, dpad, dpad, 1000, GRACE_MS), dpad);
    // Released, enters grace.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1040, GRACE_MS), dpad);
    // Physically pressed again during grace (still no chord): keep suppressing the tail of the same gesture rather than
    // leaking it.
    EXPECT_EQ(step_gamepad_suppress(state, 0, dpad, 1050, GRACE_MS), dpad);
    // Released again; grace restarts from this release.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1060, GRACE_MS), dpad);
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1200, GRACE_MS), 0u);
}

TEST(GamepadSuppressTest, PreArmedTriggerSuppressedAtLeadingEdge)
{
    GamepadSuppressState state;
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);

    // Pre-arm: the poll loop claims the consume trigger as soon as the chord's
    // modifier is held, so owned_now carries the D-pad bit a cycle before the
    // D-pad is physically down (true_buttons has LB only). The returned mask must already include the trigger so the
    // game's independent, usually faster XInput poll cannot read the trigger's leading edge before the mask catches up.
    // Masking a bit that is not yet down is a no-op for the game, but it closes the race.
    EXPECT_EQ(step_gamepad_suppress(state, dpad, lb, 1000, GRACE_MS), dpad);

    // Trigger now goes down with the modifier still held: the leading edge is already covered, so it stays masked.
    EXPECT_EQ(step_gamepad_suppress(state, dpad, static_cast<uint16_t>(lb | dpad), 1016, GRACE_MS), dpad);
}

TEST(GamepadSuppressTest, PreArmAbandonedWithoutPressDisarmsAfterGrace)
{
    GamepadSuppressState state;
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);

    // Modifier held, trigger pre-armed but never pressed (true_buttons has LB
    // only): the bit is armed and masked (a no-op against the up button).
    EXPECT_EQ(step_gamepad_suppress(state, dpad, lb, 1000, GRACE_MS), dpad);
    // Modifier released without the trigger ever being pressed: the latch must not stick. It runs the same release
    // grace and then disarms, so a pre-arm the user abandons leaves no residual mask.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1040, GRACE_MS), dpad);
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1200, GRACE_MS), 0u);
}

// evaluate_consume_rules: detour-side chord evaluation

TEST(ConsumeRuleTest, EmptyListMasksNothing)
{
    const uint16_t buttons = static_cast<uint16_t>(GamepadCode::LeftBumper | GamepadCode::DpadUp);
    EXPECT_EQ(evaluate_consume_rules(buttons, nullptr, 0), 0u);
}

TEST(ConsumeRuleTest, ChordMaskedOnTheSameFrameAsASimultaneousPress)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);
    const GamepadConsumeRule rule{lb, 0, dpad};

    // Modifier and trigger arrive in the same snapshot (the sub-poll-interval simultaneous press the reactive pre-arm
    // cannot cover): the rule masks the trigger on the exact frame the game reads it.
    EXPECT_EQ(evaluate_consume_rules(static_cast<uint16_t>(lb | dpad), &rule, 1), dpad);

    // Modifier held, trigger not yet down: the rule still matches and returns the bit. Masking an up button is a no-op
    // against the game, but it keeps the mask continuous so no leading edge slips through.
    EXPECT_EQ(evaluate_consume_rules(lb, &rule, 1), dpad);

    // Trigger without the modifier: a bare press must reach the game.
    EXPECT_EQ(evaluate_consume_rules(dpad, &rule, 1), 0u);
}

TEST(ConsumeRuleTest, ForbiddenModifierRejectsChord)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t rb = static_cast<uint16_t>(GamepadCode::RightBumper);
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);
    // LB + D-pad is the chord; RB is a known modifier owned by a different chord.
    const GamepadConsumeRule rule{lb, rb, dpad};

    // LB + D-pad alone: masked.
    EXPECT_EQ(evaluate_consume_rules(static_cast<uint16_t>(lb | dpad), &rule, 1), dpad);
    // LB + RB + D-pad: RB (a forbidden modifier) is held, so this chord is not the active gesture and the trigger
    // reaches the game, the same decision the poll loop's strict-match check makes.
    EXPECT_EQ(evaluate_consume_rules(static_cast<uint16_t>(lb | rb | dpad), &rule, 1), 0u);
}

TEST(ConsumeRuleTest, BareTriggerRuleGatedByForbiddenModifiers)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);
    // A no-modifier consume binding (modifier_mask 0) while LB is a known modifier of some other binding, so
    // forbidden_mask carries LB.
    const GamepadConsumeRule rule{0, lb, dpad};

    // No known modifier held: the bare trigger is masked.
    EXPECT_EQ(evaluate_consume_rules(dpad, &rule, 1), dpad);
    // A known modifier (LB) held: strict matching rejects the bare-trigger chord.
    EXPECT_EQ(evaluate_consume_rules(static_cast<uint16_t>(lb | dpad), &rule, 1), 0u);
}

TEST(ConsumeRuleTest, MultipleRulesAccumulateMatchingTriggers)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t rb = static_cast<uint16_t>(GamepadCode::RightBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);
    // Two independent chords with distinct modifiers: LB + Up and RB + Down.
    const std::array<GamepadConsumeRule, 2> rules{GamepadConsumeRule{lb, 0, up}, GamepadConsumeRule{rb, 0, down}};

    // Both modifiers held: both rules match and their trigger masks union.
    EXPECT_EQ(evaluate_consume_rules(static_cast<uint16_t>(lb | rb | up | down), rules.data(), rules.size()),
              static_cast<uint16_t>(up | down));
    // Only LB held: only the LB rule contributes; the RB rule does not match.
    EXPECT_EQ(evaluate_consume_rules(static_cast<uint16_t>(lb | up), rules.data(), rules.size()), up);
    // Only RB held: only the RB rule contributes.
    EXPECT_EQ(evaluate_consume_rules(static_cast<uint16_t>(rb | down), rules.data(), rules.size()), down);
}

// publish_gamepad_consume_rules / evaluate_published_consume_rules: seqlock

// The rule list is process-global; isolate each case from neighbours and from any poller-constructing test that ran
// earlier in the same process.
class PublishedConsumeRuleFixture : public ::testing::Test
{
protected:
    // Hold the layer for the whole case: a publication is authorized against the live owner, so a case driving the
    // table directly is an owner for as long as it does. Release empties the table for the next case.
    void SetUp() override
    {
        m_lease = std::make_unique<dmk_test::StandaloneInterceptLease>();
        ASSERT_TRUE(m_lease->held()) << "the interception layer was still owned when this case started";
    }

    void TearDown() override
    {
        if (m_granted_owner != 0)
        {
            uninstall(m_granted_owner);
            m_granted_owner = 0;
        }
        m_lease.reset();
    }

    /// The owner id every data-plane call in these cases presents.
    [[nodiscard]] static std::uint64_t owner() noexcept { return dmk_test::StandaloneInterceptLease::owner(); }

    /**
     * @brief Hands the layer to @p poller and runs the republish its poll loop performs on acquisition.
     * @details A poller keeps its rules cached until it owns the layer, and a headless host has no loaded XInput
     *          module for it to hook, so a case reading the published table has to grant the lease explicitly. This
     *          drives the real publication path, so a rule that fails to reach the table still fails the case.
     */
    void grant_layer_and_publish(DetourModKit::detail::InputPoller &poller)
    {
        m_lease.reset(); // the poller cannot claim a layer this fixture still holds
        m_granted_owner = poller.intercept_owner_for_test();
        ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(m_granted_owner));
        poller.publish_consume_rules_for_test();
    }

private:
    std::unique_ptr<dmk_test::StandaloneInterceptLease> m_lease;
    std::uint64_t m_granted_owner{0};
};

class ConsumeRulePublishTest : public PublishedConsumeRuleFixture
{
};

TEST_F(ConsumeRulePublishTest, RoundTripMatchesDirectEvaluation)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t rb = static_cast<uint16_t>(GamepadCode::RightBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);
    const std::array<GamepadConsumeRule, 2> rules{GamepadConsumeRule{lb, rb, up}, GamepadConsumeRule{rb, lb, down}};
    (void)publish_gamepad_consume_rules(rules.data(), rules.size(), owner());

    // The packed, seqlock-guarded list must evaluate identically to the same rules read directly: this exercises
    // pack/unpack of all three 16-bit masks and a consistent seqlock snapshot.
    for (const uint16_t buttons : {static_cast<uint16_t>(0u), lb, static_cast<uint16_t>(lb | up),
                                   static_cast<uint16_t>(lb | rb | up | down), static_cast<uint16_t>(rb | down)})
    {
        EXPECT_EQ(evaluate_published_consume_rules(buttons),
                  evaluate_consume_rules(buttons, rules.data(), rules.size()))
            << "buttons=" << buttons;
    }
}

// An over-cap publish retains the prefix that fits. The table bound costs only the rules it turns away; clearing the
// whole table would revoke leading-edge protection from unrelated retained chords.
TEST_F(ConsumeRulePublishTest, OverCapKeepsTheRulesThatFitAndReportsTheShortfall)
{
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);

    // Distinguishable head and tail: the first cap-many rules mask Up and the overflow rules mask Down.
    std::array<GamepadConsumeRule, MAX_GAMEPAD_CONSUME_RULES + 3> rules{};
    for (std::size_t i = 0; i < rules.size(); ++i)
    {
        rules[i] = GamepadConsumeRule{0, 0, i < MAX_GAMEPAD_CONSUME_RULES ? up : down};
    }

    EXPECT_EQ(publish_gamepad_consume_rules(rules.data(), rules.size(), owner()).published, MAX_GAMEPAD_CONSUME_RULES);
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(up | down)), up);
}

TEST_F(ConsumeRulePublishTest, ExactlyAtCapacityPublishesEveryRule)
{
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);
    // The last accepted cardinality. Pins the boundary against an off-by-one in either direction.
    std::array<GamepadConsumeRule, MAX_GAMEPAD_CONSUME_RULES> rules{};
    for (auto &rule : rules)
    {
        rule = GamepadConsumeRule{0, 0, up};
    }
    rules.back() = GamepadConsumeRule{0, 0, down};
    EXPECT_EQ(publish_gamepad_consume_rules(rules.data(), rules.size(), owner()).published, MAX_GAMEPAD_CONSUME_RULES);
    EXPECT_EQ(evaluate_published_consume_rules(0), static_cast<uint16_t>(up | down));
}

TEST_F(ConsumeRulePublishTest, ClearPublishesEmpty)
{
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const GamepadConsumeRule rule{0, 0, up};
    (void)publish_gamepad_consume_rules(&rule, 1, owner());
    ASSERT_EQ(evaluate_published_consume_rules(up), up);
    // Clear through the lease this fixture already holds. Taking a second standalone lease would nest, and its release
    // revokes the layer, so the table would be emptied by revocation rather than by the publication path under test.
    EXPECT_TRUE(publish_gamepad_consume_rules(nullptr, 0, owner()).authorized);
    EXPECT_EQ(evaluate_published_consume_rules(up), 0u);
}

// build_gamepad_consume_rules, via the InputPoller build+publish path

class ConsumeRuleBuildTest : public PublishedConsumeRuleFixture
{
};

TEST_F(ConsumeRuleBuildTest, GamepadChordPublishesMaskableRule)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    // Constructing the poller runs the same build+publish path the poll thread uses.
    detail::InputPoller poller(
        {make_consume_chord({gamepad_button(GamepadCode::LeftBumper)}, {gamepad_button(GamepadCode::DpadUp)})});
    grant_layer_and_publish(poller);
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), up);
    EXPECT_EQ(evaluate_published_consume_rules(up), 0u); // modifier not held
}

TEST_F(ConsumeRuleBuildTest, OverlappingChordsGetCrossForbiddenMasks)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t rb = static_cast<uint16_t>(GamepadCode::RightBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);
    detail::InputPoller poller({
        make_consume_chord({gamepad_button(GamepadCode::LeftBumper)}, {gamepad_button(GamepadCode::DpadUp)}),
        make_consume_chord({gamepad_button(GamepadCode::RightBumper)}, {gamepad_button(GamepadCode::DpadDown)}),
    });
    grant_layer_and_publish(poller);
    // Each chord's modifier becomes the other's forbidden bit (strict-match parity).
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), up);
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(rb | down)), down);
    // Holding both modifiers rejects both single-modifier chords.
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(lb | rb | up | down)), 0u);
}

TEST_F(ConsumeRuleBuildTest, KeyboardModifierDisablesAllRules)
{
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    // A keyboard modifier is invisible to the detour, so the eligibility gate drops the whole rule list and the
    // reactive pre-arm path covers the chord instead.
    detail::InputPoller poller({make_consume_chord({keyboard_key(VK_CONTROL)}, {gamepad_button(GamepadCode::DpadUp)})});
    grant_layer_and_publish(poller);
    EXPECT_EQ(evaluate_published_consume_rules(up), 0u);
}

TEST_F(ConsumeRuleBuildTest, AnalogTriggerProducesNoRule)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    // LeftTrigger is analog (not an XINPUT_GAMEPAD.wButtons bit), so there is no digital trigger to mask and no rule is
    // emitted.
    detail::InputPoller poller(
        {make_consume_chord({gamepad_button(GamepadCode::LeftBumper)}, {gamepad_button(GamepadCode::LeftTrigger)})});
    grant_layer_and_publish(poller);
    EXPECT_EQ(evaluate_published_consume_rules(lb), 0u);
}

// The interception table's capacity bound, observed through InputPoller::consume_capacity

namespace
{
    // Digital button bits usable as chord modifiers. GamepadCode::A is deliberately absent: every generated chord
    // triggers on it, and a trigger bit that is also some other chord's modifier would land in this chord's forbidden
    // mask and make the probe below reject for a reason unrelated to the bound.
    constexpr std::array<int, 13> DIGITAL_MODIFIER_BITS{
        GamepadCode::DpadUp,     GamepadCode::DpadDown,    GamepadCode::DpadLeft,  GamepadCode::DpadRight,
        GamepadCode::Start,      GamepadCode::Back,        GamepadCode::LeftStick, GamepadCode::RightStick,
        GamepadCode::LeftBumper, GamepadCode::RightBumper, GamepadCode::B,         GamepadCode::X,
        GamepadCode::Y};
    static_assert((DIGITAL_MODIFIER_BITS.size() * (DIGITAL_MODIFIER_BITS.size() - 1)) / 2 >=
                  MAX_GAMEPAD_CONSUME_RULES + 3);

    // Creates count chords with pairwise-distinct modifier pairs, so deduplication cannot collapse them. All share
    // GamepadCode::A as the trigger.
    std::vector<detail::InputBinding> distinct_consume_chords(std::size_t count)
    {
        std::vector<detail::InputBinding> bindings;
        bindings.reserve(count);
        for (std::size_t first = 0; first < DIGITAL_MODIFIER_BITS.size() && bindings.size() < count; ++first)
        {
            for (std::size_t second = first + 1; second < DIGITAL_MODIFIER_BITS.size() && bindings.size() < count;
                 ++second)
            {
                bindings.push_back(make_consume_chord(
                    {gamepad_button(DIGITAL_MODIFIER_BITS[first]), gamepad_button(DIGITAL_MODIFIER_BITS[second])},
                    {gamepad_button(GamepadCode::A)}));
            }
        }
        return bindings;
    }

    // The button snapshot that satisfies the index-th generated chord: its two modifiers plus the shared trigger.
    // Walks the same pair enumeration as distinct_consume_chords so an index here names the same chord it built.
    uint16_t chord_buttons(std::size_t index) noexcept
    {
        std::size_t seen = 0;
        for (std::size_t first = 0; first < DIGITAL_MODIFIER_BITS.size(); ++first)
        {
            for (std::size_t second = first + 1; second < DIGITAL_MODIFIER_BITS.size(); ++second)
            {
                if (seen++ == index)
                {
                    return static_cast<uint16_t>(DIGITAL_MODIFIER_BITS[first] | DIGITAL_MODIFIER_BITS[second] |
                                                 GamepadCode::A);
                }
            }
        }
        return 0;
    }
} // namespace

class InputConsumeTest : public PublishedConsumeRuleFixture
{
};

TEST_F(InputConsumeTest, CapacityManyChordsArePublishedAndReportedAsHonored)
{
    detail::InputPoller poller(distinct_consume_chords(MAX_GAMEPAD_CONSUME_RULES));
    grant_layer_and_publish(poller);

    const auto capacity = poller.consume_capacity();
    EXPECT_EQ(capacity.capacity, MAX_GAMEPAD_CONSUME_RULES);
    EXPECT_EQ(capacity.active, MAX_GAMEPAD_CONSUME_RULES);
    EXPECT_EQ(capacity.rejected, 0u);
    // Both ends of the table, so a publish that stopped one rule short cannot read as honored.
    EXPECT_EQ(evaluate_published_consume_rules(chord_buttons(0)), static_cast<uint16_t>(GamepadCode::A));
    EXPECT_EQ(evaluate_published_consume_rules(chord_buttons(MAX_GAMEPAD_CONSUME_RULES - 1)),
              static_cast<uint16_t>(GamepadCode::A));
}

// Presenting more eligible chords than the interception table holds must preserve the prefix that fits and report the
// exact shortfall.
TEST_F(InputConsumeTest, OverCapIsRejectedOrReportedWithoutSilentGlobalDisable)
{
    constexpr std::size_t OVERFLOW_CHORDS = 3;
    detail::InputPoller poller(distinct_consume_chords(MAX_GAMEPAD_CONSUME_RULES + OVERFLOW_CHORDS));
    grant_layer_and_publish(poller);

    // Explicit rejection: the caller can see exactly how many shapes the bound turned away.
    const auto capacity = poller.consume_capacity();
    EXPECT_EQ(capacity.capacity, MAX_GAMEPAD_CONSUME_RULES);
    EXPECT_EQ(capacity.active, MAX_GAMEPAD_CONSUME_RULES);
    EXPECT_EQ(capacity.rejected, OVERFLOW_CHORDS);

    // Without publication loss: every chord that fits keeps masking, including the last one the table holds. The
    // capacity fields above are derived from the offered count, so this is the assertion that actually discriminates
    // an over-cap publish that kept the prefix from one that emptied or truncated the table.
    EXPECT_EQ(evaluate_published_consume_rules(chord_buttons(0)), static_cast<uint16_t>(GamepadCode::A));
    EXPECT_EQ(evaluate_published_consume_rules(chord_buttons(MAX_GAMEPAD_CONSUME_RULES - 1)),
              static_cast<uint16_t>(GamepadCode::A));
}

// Duplicate chord shapes decide nothing the first copy did not (evaluation ORs the trigger mask), so the bound is a
// budget of shapes. Without the dedup, 33 bindings of one chord would exhaust a 32-entry table.
TEST_F(InputConsumeTest, DuplicateChordShapesShareOneRule)
{
    std::vector<detail::InputBinding> bindings;
    for (std::size_t i = 0; i < MAX_GAMEPAD_CONSUME_RULES + 1; ++i)
    {
        bindings.push_back(
            make_consume_chord({gamepad_button(GamepadCode::LeftBumper)}, {gamepad_button(GamepadCode::DpadUp)}));
    }
    detail::InputPoller poller(std::move(bindings));
    grant_layer_and_publish(poller);

    const auto capacity = poller.consume_capacity();
    EXPECT_EQ(capacity.active, 1u);
    EXPECT_EQ(capacity.rejected, 0u);
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(GamepadCode::LeftBumper | GamepadCode::DpadUp)),
              static_cast<uint16_t>(GamepadCode::DpadUp));
}

// Live-hook lifecycle: window-procedure subclass and XInput inline hook
//
// These drive the real interceptors against a throwaway top-level window (and a loaded XInput runtime) owned by the
// test process. They exercise the install/uninstall, self-heal, and message-routing branches that the pure
// state-machine tests above cannot reach. Each is skipped (not failed) when the host has no window station or no XInput
// runtime, so a headless runner stays green while a normal desktop or CI runner gets real coverage.

namespace
{
    // A single process-lifetime window class; registering once avoids the
    // ERROR_CLASS_ALREADY_EXISTS that repeated per-test registration would hit. The class is intentionally never
    // unregistered: the OS reclaims it at process exit, and a test process owns no other consumers of the atom.
    constexpr const wchar_t *TEST_WINDOW_CLASS = L"DMKInterceptTestWindow";

    void ensure_test_window_class_registered() noexcept
    {
        static const bool registered = []
        {
            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = DefWindowProcW;
            wc.hInstance = GetModuleHandleW(nullptr);
            wc.lpszClassName = TEST_WINDOW_CLASS;
            return RegisterClassExW(&wc) != 0;
        }();
        (void)registered;
    }

    // Creates a visible, top-level, owner-less window owned by this process so find_game_window() can select it.
    // Returns nullptr when no window station is available (headless host), which makes the dependent tests skip.
    HWND make_test_window() noexcept
    {
        ensure_test_window_class_registered();
        const HWND hwnd =
            CreateWindowExW(0, TEST_WINDOW_CLASS, L"DMK Intercept Test", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                            CW_USEDEFAULT, 200, 150, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (hwnd != nullptr)
        {
            // SW_SHOWNA sets WS_VISIBLE (so IsWindowVisible passes inside find_game_window) without stealing focus from
            // the test console.
            ShowWindow(hwnd, SW_SHOWNA);
        }
        return hwnd;
    }

    // Predecessor procedure the detour forwards to. Counting forwarded wheel messages makes "did the game still see
    // this notch" observable, which is how the consume-swallow and disarm branches are checked. SendMessage to a window
    // owned by the test thread runs this synchronously on that thread, so the counter needs no cross-thread ordering
    // beyond being atomic.
    std::atomic<int> s_forwarded_wheel_msgs{0};
    std::atomic<int> s_foreign_wndproc_calls{0};
    std::atomic<LONG_PTR> s_foreign_wndproc_predecessor{0};
    std::atomic<int> s_latest_wndproc_calls{0};
    std::atomic<LONG_PTR> s_latest_wndproc_predecessor{0};

    LRESULT CALLBACK recording_wndproc(HWND h, UINT msg, WPARAM w, LPARAM l) noexcept
    {
        if (msg == WM_MOUSEWHEEL || msg == WM_MOUSEHWHEEL)
        {
            s_forwarded_wheel_msgs.fetch_add(1, std::memory_order_relaxed);
        }
        return DefWindowProcW(h, msg, w, l);
    }

    LRESULT CALLBACK foreign_wndproc(HWND h, UINT msg, WPARAM w, LPARAM l) noexcept
    {
        s_foreign_wndproc_calls.fetch_add(1, std::memory_order_relaxed);
        const WNDPROC predecessor =
            reinterpret_cast<WNDPROC>(s_foreign_wndproc_predecessor.load(std::memory_order_acquire));
        return predecessor != nullptr ? CallWindowProcW(predecessor, h, msg, w, l) : DefWindowProcW(h, msg, w, l);
    }

    LRESULT CALLBACK latest_wndproc(HWND h, UINT msg, WPARAM w, LPARAM l) noexcept
    {
        s_latest_wndproc_calls.fetch_add(1, std::memory_order_relaxed);
        const WNDPROC predecessor =
            reinterpret_cast<WNDPROC>(s_latest_wndproc_predecessor.load(std::memory_order_acquire));
        return predecessor != nullptr ? CallWindowProcW(predecessor, h, msg, w, l) : DefWindowProcW(h, msg, w, l);
    }

    void interpose_foreign_wndproc(HWND hwnd, WndProcUninstallStage stage) noexcept
    {
        if (stage != WndProcUninstallStage::BeforeExchange)
            return;
        const LONG_PTR predecessor =
            SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&foreign_wndproc));
        s_foreign_wndproc_predecessor.store(predecessor, std::memory_order_release);
    }

    void interpose_two_foreign_wndprocs(HWND hwnd, WndProcUninstallStage stage) noexcept
    {
        if (stage == WndProcUninstallStage::BeforeExchange)
        {
            interpose_foreign_wndproc(hwnd, stage);
            return;
        }
        const LONG_PTR predecessor = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&latest_wndproc));
        s_latest_wndproc_predecessor.store(predecessor, std::memory_order_release);
    }

    void destroy_window_before_exchange(HWND hwnd, WndProcUninstallStage stage) noexcept
    {
        if (stage != WndProcUninstallStage::BeforeExchange)
            return;
        // Deliver WM_NCDESTROY through the still-installed detour. Its handler clears the tracked handle and saved
        // predecessor before it clears the installed flag, which is the exact window a teardown that already read a
        // live handle lands in when the window dies underneath it.
        (void)SendMessageW(hwnd, WM_NCDESTROY, 0, 0);
    }

    // Builds a wheel-message wParam whose HIWORD contains the exact signed delta.
    WPARAM wheel_delta_wparam(short delta) noexcept
    {
        return MAKEWPARAM(0, static_cast<WORD>(delta));
    }

    // Builds an integral-detent wheel-message wParam. Positive scrolls Up or Right, and negative scrolls Down or Left.
    WPARAM wheel_wparam(int notches) noexcept
    {
        return wheel_delta_wparam(static_cast<short>(notches * WHEEL_DELTA));
    }

    // Polls a predicate until it holds or the timeout elapses. Used instead of a fixed sleep so a transition driven by
    // the background poll thread is awaited by condition, not by guessing a duration (the project's concurrency-test
    // style).
    template <typename Predicate> bool wait_until(Predicate pred, std::chrono::milliseconds timeout) noexcept
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (pred())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return pred();
    }

    class WndProcPinProofCleanup
    {
    public:
        explicit WndProcPinProofCleanup(HWND window) noexcept : m_window(window) {}

        ~WndProcPinProofCleanup() noexcept
        {
            uninstall();
            set_wndproc_window_override_for_test(nullptr);
            if (IsWindow(m_window))
            {
                DestroyWindow(m_window);
            }
        }

        WndProcPinProofCleanup(const WndProcPinProofCleanup &) = delete;
        WndProcPinProofCleanup &operator=(const WndProcPinProofCleanup &) = delete;
        WndProcPinProofCleanup(WndProcPinProofCleanup &&) = delete;
        WndProcPinProofCleanup &operator=(WndProcPinProofCleanup &&) = delete;

    private:
        HWND m_window;
    };
} // namespace

TEST(InterceptWndProcPinProof, EligibleAttemptBooksOnePermanentReasonWithoutHostSelection)
{
    namespace diag = DetourModKit::diagnostics;
    uninstall();
    const dmk_test::StandaloneInterceptLease lease;
    ASSERT_TRUE(lease.held());

    const HWND window = make_test_window();
    ASSERT_NE(window, nullptr) << "the required WndProc pin proof needs a test window";
    const WndProcPinProofCleanup cleanup{window};

    ASSERT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 0u);
    set_wndproc_window_override_for_test(reinterpret_cast<HWND>(std::uintptr_t{1}));
    ASSERT_FALSE(install_wndproc(dmk_test::StandaloneInterceptLease::owner()));
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 1u);

    set_wndproc_window_override_for_test(window);
    ASSERT_TRUE(install_wndproc(dmk_test::StandaloneInterceptLease::owner()));
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 1u);

    uninstall();
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 1u);
    ASSERT_TRUE(install_wndproc(dmk_test::StandaloneInterceptLease::owner()));
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 1u);
}

TEST(InterceptMessageHookPinProof, InstallBooksOnePermanentReasonAndUninstallRetainsIt)
{
    namespace diag = DetourModKit::diagnostics;
    uninstall();
    const dmk_test::StandaloneInterceptLease lease;
    ASSERT_TRUE(lease.held());

    const HWND window = make_test_window();
    ASSERT_NE(window, nullptr) << "the message-hook pin proof needs a test window";
    const WndProcPinProofCleanup cleanup{window};

    ASSERT_EQ(diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive), 0u);
    set_wndproc_window_override_for_test(window);
    ASSERT_TRUE(install_message_hook(dmk_test::StandaloneInterceptLease::owner()));
    EXPECT_TRUE(message_hook_installed());
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive), 1u);

    // Cleanup only: uninstall drops the OS hook but retains the permanent keepalive.
    uninstall();
    EXPECT_FALSE(message_hook_installed());
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive), 1u);

    // A re-install reuses the same reference through the once-flag rather than booking a second.
    ASSERT_TRUE(install_message_hook(dmk_test::StandaloneInterceptLease::owner()));
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive), 1u);
    uninstall();
}

class InterceptWndProcTest : public ::testing::Test
{
protected:
    HWND m_hwnd = nullptr;
    std::unique_ptr<dmk_test::StandaloneInterceptLease> m_lease;

    void SetUp() override
    {
        uninstall(); // start from a known-clean interception state
        // Hold the layer across the case so the wheel drains and swallow masks below are authorized, and so the
        // install_wndproc() calls that follow claim the same owner rather than a fresh one.
        m_lease = std::make_unique<dmk_test::StandaloneInterceptLease>();
        ASSERT_TRUE(m_lease->held()) << "the interception layer was still owned when this case started";
        s_forwarded_wheel_msgs.store(0, std::memory_order_relaxed);
        (void)take_wheel_counts(owner());
        (void)publish_wheel_consume(0, owner());
        m_hwnd = make_test_window();
        if (m_hwnd == nullptr)
        {
            GTEST_SKIP() << "no window station available to create a top-level window";
        }
    }

    void TearDown() override
    {
        set_wndproc_uninstall_exchange_seam(nullptr);
        uninstall();
        m_lease.reset();
        if (m_hwnd != nullptr && IsWindow(m_hwnd))
        {
            DestroyWindow(m_hwnd);
        }
        m_hwnd = nullptr;
    }

    /// The owner id every data-plane call in these cases presents.
    [[nodiscard]] static std::uint64_t owner() noexcept { return dmk_test::StandaloneInterceptLease::owner(); }

    // Installs the subclass and confirms it landed on our test window. Returns false when find_game_window selected a
    // different top-level window in this desktop session (so the caller skips rather than asserting on a window it does
    // not control).
    [[nodiscard]] bool install_on_our_window() noexcept
    {
        const LONG_PTR before = GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC);
        if (!install_wndproc())
        {
            return false;
        }
        return GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC) != before;
    }
};

TEST_F(InterceptWndProcTest, InstallCapturesWheelNotchesPerDirection)
{
    EXPECT_FALSE(wndproc_installed());
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    EXPECT_TRUE(wndproc_installed());
    // Idempotent: a second install while already installed is a no-op success.
    EXPECT_TRUE(install_wndproc());

    (void)take_wheel_counts(owner()); // drain any stray notch before measuring

    // Vertical wheel: HIWORD sign selects Up (+) versus Down (-).
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(-1), 0);
    auto counts = take_wheel_counts(owner());
    EXPECT_EQ(counts[0], 2); // Up
    EXPECT_EQ(counts[1], 1); // Down
    EXPECT_EQ(counts[2], 0); // Left
    EXPECT_EQ(counts[3], 0); // Right

    // Horizontal (tilt) wheel: positive tilts Right, negative Left.
    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_wparam(1), 0);
    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_wparam(-1), 0);
    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_wparam(-1), 0);
    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_wparam(-1), 0);
    counts = take_wheel_counts(owner());
    EXPECT_EQ(counts[0], 0);
    EXPECT_EQ(counts[1], 0);
    EXPECT_EQ(counts[2], 3); // Left
    EXPECT_EQ(counts[3], 1); // Right
}

// The typed count keeps the permanent WndprocKeepalive visible across uninstall and later attempts.
TEST_F(InterceptWndProcTest, WheelKeepaliveStaysVisibleAsAModulePinAcrossUninstall)
{
    namespace diag = DetourModKit::diagnostics;
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 1u);

    uninstall();
    EXPECT_FALSE(wndproc_installed());
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 1u)
        << "uninstall must not release the permanent keepalive";

    if (install_on_our_window())
    {
        EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 1u)
            << "the once-flag must prevent one leaked reference per install";
    }
}

TEST_F(InterceptWndProcTest, RawSignedDeltasReachTheAccumulatorUnchanged)
{
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    (void)take_wheel_counts(owner());

    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_delta_wparam(240), 0);
    auto counts = take_wheel_counts(owner());
    EXPECT_EQ(counts[0], 2);
    EXPECT_EQ(counts[1], 0);

    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_delta_wparam(60), 0);
    counts = take_wheel_counts(owner());
    EXPECT_EQ(counts[0], 0);
    EXPECT_EQ(counts[1], 0);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_delta_wparam(60), 0);
    counts = take_wheel_counts(owner());
    EXPECT_EQ(counts[0], 1);
    EXPECT_EQ(counts[1], 0);

    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_delta_wparam(-240), 0);
    counts = take_wheel_counts(owner());
    EXPECT_EQ(counts[2], 2);
    EXPECT_EQ(counts[3], 0);
}

// uninstall_wndproc()'s restore branch must leave s_prev_wndproc pointing at the real procedure rather than zeroing it.
// A wndproc_detour frame already in flight when the restore lands loads this value at the top of the detour and
// forwards the message there; a zeroed value would route that frame to DefWindowProcW and silently drop messages such
// as WM_CLOSE or WM_ACTIVATE at every interception teardown.
TEST_F(InterceptWndProcTest, UninstallLeavesSavedProcedureForInFlightFrames)
{
    // Make the window's own procedure the predecessor the detour will save and forward to.
    SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&recording_wndproc));
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    // install_wndproc captured recording_wndproc as the predecessor.
    ASSERT_EQ(wndproc_saved_procedure(), reinterpret_cast<LONG_PTR>(&recording_wndproc));

    uninstall(); // restore branch: the detour is removed from the chain

    EXPECT_FALSE(wndproc_installed());
    EXPECT_EQ(wndproc_saved_procedure(), reinterpret_cast<LONG_PTR>(&recording_wndproc))
        << "uninstall must not zero the saved predecessor; an in-flight detour frame would route to DefWindowProcW";
}

TEST_F(InterceptWndProcTest, ConsumeSwallowsOnlyTheOwnedWheelDirection)
{
    // Make the window's own procedure the predecessor the detour forwards to, so "was the game notified" is observable
    // via s_forwarded_wheel_msgs.
    SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&recording_wndproc));
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    s_forwarded_wheel_msgs.store(0, std::memory_order_relaxed);
    (void)take_wheel_counts(owner());

    // Not consuming: the notch is latched for the poll loop AND forwarded to the game's procedure.
    (void)publish_wheel_consume(0, owner());
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    EXPECT_EQ(s_forwarded_wheel_msgs.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(take_wheel_counts(owner())[0], 1);

    // Consume only the Up direction: the mask a "Ctrl+WheelUp" binding publishes while Ctrl is held. The Up notch is
    // still latched for the poll loop, but swallowed so the game's procedure never sees it.
    (void)publish_wheel_consume(wheel_direction_bit(WheelDirection::Up), owner());
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    EXPECT_EQ(s_forwarded_wheel_msgs.load(std::memory_order_relaxed), 1); // unchanged: Up was swallowed
    EXPECT_EQ(take_wheel_counts(owner())[0], 1);

    // A Down notch is not owned by the Up-only mask, so it must still reach the game. This is the important
    // per-direction invariant: consuming one wheel direction must not suppress the others.
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(-1), 0);
    EXPECT_EQ(s_forwarded_wheel_msgs.load(std::memory_order_relaxed), 2); // Down forwarded to the game
    EXPECT_EQ(take_wheel_counts(owner())[1], 1);

    (void)publish_wheel_consume(0, owner());
}

TEST_F(InterceptWndProcTest, WheelCounterSaturatesWhenNotDrained)
{
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    (void)take_wheel_counts(owner()); // start from a clean slate

    // Reproduce the idle-accretion case: the subclass stays installed but nothing drains the counter (the poll loop's
    // take_wheel_counts is gated on live wheel bindings, so once the last wheel binding is removed the counter is no
    // longer drained). Drive far more Up notches than the cap without draining between them; the counter must saturate
    // at MAX_WHEEL_NOTCHES rather than continuing toward signed overflow.
    const int overshoot = MAX_WHEEL_NOTCHES + 128;
    for (int i = 0; i < overshoot; ++i)
    {
        SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    }
    const auto counts = take_wheel_counts(owner());
    EXPECT_EQ(counts[0], MAX_WHEEL_NOTCHES) << "idle wheel counter must saturate at the cap, not accrete every notch";
    // The drain exchanged the slot to zero, so a second drain reads clean: saturation did not wedge the counter.
    EXPECT_EQ(take_wheel_counts(owner())[0], 0);
}

TEST_F(InterceptWndProcTest, WmNcDestroySelfHealsAndAllowsResubclass)
{
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    EXPECT_TRUE(wndproc_installed());

    // Destroying the subclassed window dispatches WM_NCDESTROY synchronously to the detour, which must mark the
    // subclass uninstalled so a later poll cycle re-subclasses a recreated window (the fullscreen-toggle
    // window-recreation case that would otherwise leave the new window unhooked).
    DestroyWindow(m_hwnd);
    m_hwnd = nullptr;
    EXPECT_FALSE(wndproc_installed());

    // After the self-heal a freshly created window can be subclassed again.
    m_hwnd = make_test_window();
    if (m_hwnd == nullptr)
    {
        GTEST_SKIP() << "no window station available to recreate a window";
    }
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "re-subclass selected a different process window";
    }
    EXPECT_TRUE(wndproc_installed());
}

TEST_F(InterceptWndProcTest, UninstallRestoresPredecessorAtTopOfChain)
{
    const LONG_PTR predecessor = reinterpret_cast<LONG_PTR>(&recording_wndproc);
    SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, predecessor);
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    // Installed: our detour sits on top, not the predecessor.
    EXPECT_NE(GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC), predecessor);

    // Still top of the chain, so uninstall restores the saved predecessor exactly.
    uninstall();
    EXPECT_EQ(GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC), predecessor);
    EXPECT_FALSE(wndproc_installed());
}

TEST_F(InterceptWndProcTest, UninstallPreservesForeignSubclassInterposedBeforeExchange)
{
    const LONG_PTR predecessor = reinterpret_cast<LONG_PTR>(&recording_wndproc);
    SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, predecessor);
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    const LONG_PTR dmk_detour = GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC);
    ASSERT_NE(dmk_detour, predecessor);

    s_foreign_wndproc_calls.store(0, std::memory_order_relaxed);
    s_foreign_wndproc_predecessor.store(0, std::memory_order_relaxed);
    set_wndproc_uninstall_exchange_seam(&interpose_foreign_wndproc);
    uninstall();
    set_wndproc_uninstall_exchange_seam(nullptr);

    ASSERT_EQ(s_foreign_wndproc_predecessor.load(std::memory_order_acquire), dmk_detour);
    ASSERT_EQ(GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC), reinterpret_cast<LONG_PTR>(&foreign_wndproc))
        << "uninstall overwrote the foreign subclass that landed before its exchange";
    EXPECT_TRUE(wndproc_installed()) << "the foreign layer still forwards through DMK, so DMK remains installed";

    SendMessageW(m_hwnd, WM_NULL, 0, 0);
    EXPECT_EQ(s_foreign_wndproc_calls.load(std::memory_order_relaxed), 1)
        << "the preserved foreign subclass must remain callable";

    // Remove the foreign top layer, reclaim the idle owner, and let DMK perform its ordinary top-of-chain restore.
    SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, s_foreign_wndproc_predecessor.load(std::memory_order_acquire));
    ASSERT_TRUE(install_wndproc());
    uninstall();
    EXPECT_EQ(GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC), predecessor);
    EXPECT_FALSE(wndproc_installed());
}

TEST_F(InterceptWndProcTest, UninstallRefusesToPublishAClearedPredecessor)
{
    const LONG_PTR predecessor = reinterpret_cast<LONG_PTR>(&recording_wndproc);
    SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, predecessor);
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    const LONG_PTR dmk_detour = GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC);
    ASSERT_NE(dmk_detour, predecessor);

    // The window dies between the handle read and the predecessor read, so the exchange has nothing valid to publish.
    set_wndproc_uninstall_exchange_seam(&destroy_window_before_exchange);
    uninstall();
    set_wndproc_uninstall_exchange_seam(nullptr);

    ASSERT_EQ(wndproc_saved_procedure(), 0) << "the seam did not reach the cleared-predecessor state";
    EXPECT_EQ(GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC), dmk_detour)
        << "uninstall exchanged against a cleared predecessor; the window manager substituted its own default "
           "procedure and detached the window from the real chain";
    EXPECT_FALSE(wndproc_installed());

    // The window still dispatches: the detour forwards to DefWindowProcW once its predecessor is gone.
    SendMessageW(m_hwnd, WM_NULL, 0, 0);
}

TEST_F(InterceptWndProcTest, UninstallPreservesLatestSubclassInterposedBeforeCompensation)
{
    const LONG_PTR predecessor = reinterpret_cast<LONG_PTR>(&recording_wndproc);
    SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, predecessor);
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    const LONG_PTR dmk_detour = GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC);
    ASSERT_NE(dmk_detour, predecessor);

    s_foreign_wndproc_calls.store(0, std::memory_order_relaxed);
    s_foreign_wndproc_predecessor.store(0, std::memory_order_relaxed);
    s_latest_wndproc_calls.store(0, std::memory_order_relaxed);
    s_latest_wndproc_predecessor.store(0, std::memory_order_relaxed);
    set_wndproc_uninstall_exchange_seam(&interpose_two_foreign_wndprocs);
    uninstall();
    set_wndproc_uninstall_exchange_seam(nullptr);

    ASSERT_EQ(s_foreign_wndproc_predecessor.load(std::memory_order_acquire), dmk_detour);
    ASSERT_EQ(s_latest_wndproc_predecessor.load(std::memory_order_acquire), predecessor);
    ASSERT_EQ(GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC), reinterpret_cast<LONG_PTR>(&latest_wndproc));
    EXPECT_TRUE(wndproc_installed()) << "the uncertain chain must keep DMK conservatively installed";

    SendMessageW(m_hwnd, WM_NULL, 0, 0);
    EXPECT_EQ(s_latest_wndproc_calls.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(s_foreign_wndproc_calls.load(std::memory_order_relaxed), 0)
        << "the latest writer's saved predecessor bypassed the temporarily displaced foreign layer";

    SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, dmk_detour);
    ASSERT_TRUE(install_wndproc());
    uninstall();
    EXPECT_EQ(GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC), predecessor);
    EXPECT_FALSE(wndproc_installed());
}

TEST_F(InterceptWndProcTest, PollerDropsCallbackStagingCopyFailureAndContinues)
{
    const LONG_PTR predecessor = GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC);

    auto throw_on_copy = std::make_shared<std::atomic<bool>>(false);
    auto failed_copies = std::make_shared<std::atomic<int>>(0);
    auto invocations = std::make_shared<std::atomic<int>>(0);

    detail::InputBinding binding;
    binding.name = "wheel_throwing_copy";
    binding.keys = {mouse_wheel(WheelCode::Up)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = dmk_test::ThrowingCopyCallback{throw_on_copy, failed_copies, invocations};

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds(2), false);
    // These cases exercise poller-owned interception, so release the fixture's direct-access lease before startup.
    m_lease.reset();
    poller.start();

    const bool hooked_ours =
        wait_until([&] { return wndproc_installed() && GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC) != predecessor; },
                   std::chrono::seconds(5));
    if (!hooked_ours)
    {
        poller.shutdown();
        GTEST_SKIP() << "poll thread did not subclass the test window";
    }

    // The first edge arms the callback's copy constructor to fail while the poll loop stages PendingCallback. The
    // failure must be contained to that cycle instead of escaping the jthread body.
    throw_on_copy->store(true, std::memory_order_relaxed);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    EXPECT_TRUE(
        wait_until([&] { return failed_copies->load(std::memory_order_relaxed) > 0; }, std::chrono::seconds(5)));
    EXPECT_TRUE(poller.is_running());
    EXPECT_EQ(invocations->load(std::memory_order_relaxed), 0);

    // Once copying succeeds again, a later wheel edge should still dispatch. This proves the failed staging pass did
    // not poison the poller or leave the edge detector permanently armed.
    throw_on_copy->store(false, std::memory_order_relaxed);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    EXPECT_TRUE(wait_until([&] { return invocations->load(std::memory_order_relaxed) > 0; }, std::chrono::seconds(5)));

    poller.shutdown();
}

// A wheel notch is consumed destructively before callback staging can fail, and it has no persistent physical state
// from which it can be re-derived. Rolling the pulse state back keeps that single notch pending for the next cycle.
TEST_F(InterceptWndProcTest, StagingFailureDoesNotDestroyTheWheelNotch)
{
    const LONG_PTR predecessor = GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC);

    const auto throw_on_copy = std::make_shared<std::atomic<bool>>(false);
    const auto failed_copies = std::make_shared<std::atomic<int>>(0);
    const auto invocations = std::make_shared<std::atomic<int>>(0);

    detail::InputBinding binding;
    binding.name = "wheel_notch_rollback";
    binding.keys = {mouse_wheel(WheelCode::Up)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = dmk_test::ThrowingCopyCallback{throw_on_copy, failed_copies, invocations};

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds(2), false);
    // These cases exercise poller-owned interception, so release the fixture's direct-access lease before startup.
    m_lease.reset();
    poller.start();

    const bool hooked_ours =
        wait_until([&] { return wndproc_installed() && GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC) != predecessor; },
                   std::chrono::seconds(5));
    if (!hooked_ours)
    {
        poller.shutdown();
        GTEST_SKIP() << "poll thread did not subclass the test window";
    }

    // Exactly ONE notch, delivered while staging is guaranteed to fail.
    throw_on_copy->store(true, std::memory_order_relaxed);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    ASSERT_TRUE(
        wait_until([&] { return failed_copies->load(std::memory_order_relaxed) > 0; }, std::chrono::seconds(5)));
    ASSERT_EQ(invocations->load(std::memory_order_relaxed), 0);

    // No further wheel message is sent. The one notch already taken from the detour must still be pending.
    throw_on_copy->store(false, std::memory_order_relaxed);
    EXPECT_TRUE(wait_until([&] { return invocations->load(std::memory_order_relaxed) > 0; }, std::chrono::seconds(5)));

    poller.shutdown();
}

TEST(InterceptXInputTest, InstallHooksExportAndTrampolineRoundTrips)
{
    HMODULE xinput = nullptr;
    for (const wchar_t *name : {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"})
    {
        xinput = LoadLibraryW(name);
        if (xinput != nullptr)
        {
            break;
        }
    }
    if (xinput == nullptr)
    {
        GTEST_SKIP() << "no XInput runtime available on this host";
    }

    uninstall();
    EXPECT_FALSE(xinput_installed());

    ASSERT_TRUE(install_xinput(0));
    EXPECT_TRUE(xinput_installed());
    // The poll thread reads the controller through the published trampoline so it observes the true (unmasked) state;
    // it must be non-null once installed.
    EXPECT_NE(xinput_trampoline(), nullptr);
    // Idempotent while already installed.
    EXPECT_TRUE(install_xinput(0));

    // Calling the now-hooked export routes through the detour into the trampoline and returns the real result without
    // crashing. With no controller bound the detour takes its non-success branch (apply_suppress is skipped). The
    // wButtons masking branch is covered by the step_gamepad_suppress unit tests and validated manually with a
    // connected controller.
    const auto get_state =
        reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
    ASSERT_NE(get_state, nullptr);
    XINPUT_STATE state{};
    const DWORD result = get_state(0, &state);
    EXPECT_TRUE(result == ERROR_SUCCESS || result == ERROR_DEVICE_NOT_CONNECTED);

    // Teardown rewrites the patched prologue before the module is released.
    uninstall();
    EXPECT_FALSE(xinput_installed());
    EXPECT_EQ(xinput_trampoline(), nullptr);

    FreeLibrary(xinput);
}

TEST(InterceptXInputTest, UninstallCleanlyReleasesAfterConcurrentCallersJoin)
{
    HMODULE xinput = nullptr;
    for (const wchar_t *name : {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"})
    {
        xinput = LoadLibraryW(name);
        if (xinput != nullptr)
        {
            break;
        }
    }
    if (xinput == nullptr)
    {
        GTEST_SKIP() << "no XInput runtime available on this host";
    }

    const auto get_state =
        reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
    ASSERT_NE(get_state, nullptr);

    // Install the hook and drive the hooked export from several threads. Join each round before uninstall so this is
    // the clean-release control: deterministic parked-route cases own the timeout path, while this case proves a normal
    // quiescent teardown releases its hook object and keepalives instead of always taking permanent DMK ownership.
    for (int round = 0; round < 5; ++round)
    {
        uninstall();
        ASSERT_TRUE(install_xinput(0));

        std::atomic<bool> stop{false};
        std::atomic<int> started{0};
        std::vector<std::thread> callers;
        for (int t = 0; t < 3; ++t)
        {
            callers.emplace_back(
                [&]
                {
                    XINPUT_STATE state{};
                    started.fetch_add(1, std::memory_order_release);
                    while (!stop.load(std::memory_order_acquire))
                    {
                        // Routes through the detour while installed, and through the restored real export after
                        // uninstall; both must be crash-free.
                        (void)get_state(0, &state);
                    }
                });
        }

        ASSERT_TRUE(wait_until([&] { return started.load(std::memory_order_acquire) == 3; }, std::chrono::seconds(5)));
        // Give the callers time to cycle through the detour, then stop and join before the clean-release witness.
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
        stop.store(true, std::memory_order_release);
        for (auto &caller : callers)
        {
            caller.join();
        }
        uninstall();
    }

    EXPECT_FALSE(xinput_installed());
    EXPECT_FALSE(xinput_permanent_primary_retained());
    EXPECT_EQ(xinput_module_refs_held(), 0);
    FreeLibrary(xinput);
}

// A witnessed clean teardown is the pair transaction's committing case: both members go back, nothing is retained, and
// the next install rebuilds the pair in full rather than settling for whichever member it can reach. Hosts without a
// distinct same-module ordinal 100 report an honest skip; the proxy lifecycle cases provide the deterministic route.
TEST(InterceptXInputTest, CleanPairTeardownReleasesBothMembersAndReinstallRepublishesThem)
{
    HMODULE xinput = nullptr;
    for (const wchar_t *name : {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"})
    {
        xinput = LoadLibraryW(name);
        if (xinput != nullptr)
        {
            break;
        }
    }
    if (xinput == nullptr)
    {
        GTEST_SKIP() << "no XInput runtime available on this host";
    }
    auto *const primary_export = GetProcAddress(xinput, "XInputGetState");
    auto *const ex_export = GetProcAddress(xinput, MAKEINTRESOURCEA(100));
    constexpr DWORD identity_flags =
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    HMODULE ex_owner = nullptr;
    const bool ex_is_local =
        primary_export != nullptr && ex_export != nullptr && ex_export != primary_export &&
        GetModuleHandleExW(identity_flags, reinterpret_cast<LPCWSTR>(ex_export), &ex_owner) != FALSE &&
        ex_owner == xinput;
    if (!ex_is_local)
    {
        FreeLibrary(xinput);
        GTEST_SKIP() << "no distinct same-module XInputGetStateEx export on this host";
    }

    const std::uint64_t owner = next_intercept_owner();
    if (!install_xinput(0, owner))
    {
        FreeLibrary(xinput);
        FAIL() << "the clean pair could not be installed";
    }
    if (xinput_trampoline() == nullptr)
    {
        uninstall(owner);
        FreeLibrary(xinput);
        FAIL() << "the primary member of the installed pair has no trampoline";
    }
    if (xinput_ex_trampoline() == nullptr)
    {
        uninstall(owner);
        FreeLibrary(xinput);
        FAIL() << "a distinct same-module ordinal-100 export was not included in the installed pair";
    }

    uninstall(owner);
    EXPECT_FALSE(xinput_installed());
    EXPECT_FALSE(xinput_permanent_primary_retained());
    EXPECT_EQ(xinput_module_refs_held(), 0);
    EXPECT_EQ(xinput_trampoline(), nullptr);
    EXPECT_EQ(xinput_ex_trampoline(), nullptr) << "a clean teardown must retire the ordinal-100 chain too";

    const std::uint64_t next_owner = next_intercept_owner();
    if (!install_xinput(0, next_owner))
    {
        FreeLibrary(xinput);
        FAIL() << "the clean pair could not be reinstalled";
    }
    EXPECT_NE(xinput_trampoline(), nullptr);
    EXPECT_NE(xinput_ex_trampoline(), nullptr) << "a reinstall must rebuild both members of the pair";
    uninstall(next_owner);
    EXPECT_EQ(xinput_module_refs_held(), 0);

    FreeLibrary(xinput);
}

TEST(InterceptXInputTest, SupersededOwnerCannotTearDownOrOverrideAnActiveInstallation)
{
    HMODULE xinput = nullptr;
    for (const wchar_t *name : {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"})
    {
        xinput = LoadLibraryW(name);
        if (xinput != nullptr)
        {
            break;
        }
    }
    if (xinput == nullptr)
    {
        GTEST_SKIP() << "no XInput runtime available on this host";
    }

    const bool zero_owner_installed = install_xinput(0, 0);
    EXPECT_FALSE(zero_owner_installed);
    if (zero_owner_installed)
    {
        uninstall(0);
    }
    EXPECT_FALSE(intercept_owned_by(0));

    const std::uint64_t failed_owner = next_intercept_owner();
    set_xinput_module_override_for_test(GetModuleHandleW(L"kernel32.dll"));
    EXPECT_FALSE(install_xinput(0, failed_owner));
    EXPECT_FALSE(intercept_owned_by(failed_owner));
    set_xinput_module_override_for_test(nullptr);

    const std::uint64_t owner_a = next_intercept_owner();
    const std::uint64_t owner_b = next_intercept_owner();
    ASSERT_NE(owner_a, owner_b);

    // A claims the layer and installs; both keepalives are held.
    ASSERT_TRUE(install_xinput(0, owner_a));
    EXPECT_TRUE(xinput_installed());
    EXPECT_TRUE(intercept_owned_by(owner_a));
    EXPECT_EQ(xinput_module_refs_held(), 2);
    EXPECT_EQ(xinput_bound_user_index(), 0);

    // A refused owner cannot replace the active owner's controller index or resources.
    EXPECT_FALSE(install_xinput(1, owner_b));
    EXPECT_TRUE(xinput_installed());
    EXPECT_TRUE(intercept_owned_by(owner_a));
    EXPECT_EQ(xinput_module_refs_held(), 2);
    EXPECT_EQ(xinput_bound_user_index(), 0);

    uninstall(owner_b);
    EXPECT_TRUE(xinput_installed());
    EXPECT_NE(xinput_trampoline(), nullptr);
    EXPECT_TRUE(intercept_owned_by(owner_a));
    EXPECT_EQ(xinput_module_refs_held(), 2);
    EXPECT_EQ(xinput_bound_user_index(), 0);

    uninstall(owner_a);
    EXPECT_FALSE(xinput_installed());
    EXPECT_EQ(xinput_trampoline(), nullptr);
    EXPECT_FALSE(intercept_owned_by(owner_a));
    EXPECT_EQ(xinput_module_refs_held(), 0);

    ASSERT_TRUE(install_xinput(1, owner_b));
    EXPECT_TRUE(xinput_installed());
    EXPECT_TRUE(intercept_owned_by(owner_b));
    EXPECT_EQ(xinput_module_refs_held(), 2);
    EXPECT_EQ(xinput_bound_user_index(), 1);
    uninstall(owner_b);
    EXPECT_EQ(xinput_module_refs_held(), 0);

    FreeLibrary(xinput);
}

// A clean XInput cycle books and releases the self and provider reasons independently.
TEST(InterceptXInputTest, InstallAndCleanUninstallBookAndReleaseTheTypedPinReasons)
{
    namespace diag = DetourModKit::diagnostics;
    HMODULE xinput = nullptr;
    for (const wchar_t *name : {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"})
    {
        xinput = LoadLibraryW(name);
        if (xinput != nullptr)
        {
            break;
        }
    }
    if (xinput == nullptr)
    {
        GTEST_SKIP() << "no XInput runtime available on this host";
    }

    const std::size_t keepalive_before = diag::module_pin_count(diag::ModulePinReason::XInputKeepalive);
    const std::size_t target_before = diag::module_pin_count(diag::ModulePinReason::XInputTarget);

    const std::uint64_t owner = next_intercept_owner();
    ASSERT_TRUE(install_xinput(0, owner));
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::XInputKeepalive), keepalive_before + 1);
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::XInputTarget),
              target_before + static_cast<std::size_t>(xinput_module_refs_held() - 1));

    uninstall(owner);
    EXPECT_EQ(xinput_module_refs_held(), 0);
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::XInputKeepalive), keepalive_before)
        << "a witnessed clean uninstall must release the self keepalive booking";
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::XInputTarget), target_before)
        << "a witnessed clean uninstall must release the provider bookings";

    FreeLibrary(xinput);
}

TEST(InterceptXInputTest, NonOwnerPollerConstructionCannotReplaceActiveOwnersConsumeRules)
{
    HMODULE xinput = nullptr;
    for (const wchar_t *name : {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"})
    {
        xinput = LoadLibraryW(name);
        if (xinput != nullptr)
        {
            break;
        }
    }
    if (xinput == nullptr)
    {
        GTEST_SKIP() << "no XInput runtime available on this host";
    }

    uninstall();
    const std::uint64_t owner_a = next_intercept_owner();
    ASSERT_TRUE(install_xinput(0, owner_a));
    ASSERT_TRUE(intercept_owned_by(owner_a));

    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t rb = static_cast<uint16_t>(GamepadCode::RightBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);
    const GamepadConsumeRule owner_a_rule{lb, rb, up};
    ASSERT_TRUE(publish_gamepad_consume_rules(&owner_a_rule, 1, owner_a).authorized);
    ASSERT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), up);

    {
        // Construction compiles the second poller's local rule cache, but the live interceptor still belongs to A.
        // A non-owner must not replace the process-global rules the active owner's detour reads.
        detail::InputPoller non_owner(
            {make_consume_chord({gamepad_button(GamepadCode::RightBumper)}, {gamepad_button(GamepadCode::DpadDown)})});

        EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), up);
        EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(rb | down)), 0u);
        EXPECT_TRUE(intercept_owned_by(owner_a));
    }

    // uninstall() revokes the layer and empties the table in one step, so no separate reset is needed here.
    uninstall(owner_a);
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), 0u);
    FreeLibrary(xinput);
}

// A poller that rebuilt its rules while another owner held the layer keeps them cached rather than overwriting that
// owner's table, so acquisition is the only moment its own chords can reach the detour. Deleting the poll loop's
// acquisition republish, or clearing the unpublished latch at construction, leaves the acquiring poller's suppression
// silently absent. Publishing a foreign rule under the same owner afterwards pins the "exactly once" half: a latch that
// never clears would republish every cycle and stomp it.
TEST(InterceptOwnerEpochTest, AcquisitionRepublishesTheOwnersCachedRulesExactlyOnce)
{
    uninstall();
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t rb = static_cast<uint16_t>(GamepadCode::RightBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);

    // Hold the layer under an unrelated owner so the poller cannot claim it, whatever this host's XInput state is.
    const std::uint64_t incumbent = next_intercept_owner();
    ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(incumbent));

    detail::InputPoller poller(
        {make_consume_chord({gamepad_button(GamepadCode::LeftBumper)}, {gamepad_button(GamepadCode::DpadUp)})},
        std::chrono::milliseconds{2}, /*require_focus=*/false);
    poller.start();
    const std::uint64_t acquirer = poller.intercept_owner_for_test();
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), 0u)
        << "a poller that does not hold the layer must not publish into the owner's table";

    // Hand the layer over. The poll loop observes ownership on a later cycle and republishes what it cached.
    uninstall(incumbent);
    ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(acquirer));
    EXPECT_TRUE(wait_until([&] { return evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)) == up; },
                           std::chrono::seconds(2)))
        << "acquiring the layer must republish the rules cached while the poller owned nothing";

    const GamepadConsumeRule foreign{rb, 0, down};
    ASSERT_TRUE(publish_gamepad_consume_rules(&foreign, 1, acquirer).authorized);
    std::this_thread::sleep_for(std::chrono::milliseconds{60});
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(rb | down)), down)
        << "the republish must happen once per acquisition, not on every cycle";
    EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), 0u);

    poller.shutdown();
    uninstall(acquirer);
}

TEST(InterceptOwnerEpochTest, PausedSupersededOwnerCannotMutateOrDrainAnyDataPlaneChannel)
{
    enum class Channel
    {
        ConsumeRules,
        ReactiveMask,
        RuleGate,
        WheelMask,
        WheelDrain
    };

    for (const Channel channel :
         {Channel::ConsumeRules, Channel::ReactiveMask, Channel::RuleGate, Channel::WheelMask, Channel::WheelDrain})
    {
        SCOPED_TRACE(static_cast<int>(channel));
        uninstall();
        const std::uint64_t owner_a = next_intercept_owner();
        const std::uint64_t owner_b = next_intercept_owner();
        ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(owner_a));

        const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
        const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);
        const GamepadConsumeRule rule_a{0, 0, up};
        const GamepadConsumeRule rule_b{0, 0, down};
        std::atomic<bool> stale_authorized{true};
        std::array<int, 4> stale_counts{};

        s_data_plane_entry_reached.store(false, std::memory_order_release);
        s_release_data_plane_entry.store(false, std::memory_order_release);
        DetourModKit::detail::set_data_plane_entry_seam(&park_data_plane_entry);
        std::thread stale_owner(
            [&]
            {
                switch (channel)
                {
                case Channel::ConsumeRules:
                    stale_authorized.store(publish_gamepad_consume_rules(&rule_a, 1, owner_a).authorized,
                                           std::memory_order_release);
                    break;
                case Channel::ReactiveMask:
                    stale_authorized.store(publish_gamepad_suppress(up, owner_a), std::memory_order_release);
                    break;
                case Channel::RuleGate:
                    stale_authorized.store(DetourModKit::detail::set_gamepad_rule_suppress_enabled(false, owner_a),
                                           std::memory_order_release);
                    break;
                case Channel::WheelMask:
                    stale_authorized.store(publish_wheel_consume(wheel_direction_bit(WheelDirection::Down), owner_a),
                                           std::memory_order_release);
                    break;
                case Channel::WheelDrain:
                    stale_counts = take_wheel_counts(owner_a);
                    break;
                }
            });

        while (!s_data_plane_entry_reached.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        DetourModKit::detail::set_data_plane_entry_seam(nullptr);
        uninstall(owner_a);
        EXPECT_TRUE(DetourModKit::detail::adopt_owner_for_test(owner_b));

        std::uint32_t sequence_before_stale = 0;
        switch (channel)
        {
        case Channel::ConsumeRules:
            EXPECT_TRUE(publish_gamepad_consume_rules(&rule_b, 1, owner_b).authorized);
            sequence_before_stale = DetourModKit::detail::consume_rules_sequence();
            break;
        case Channel::ReactiveMask:
            EXPECT_TRUE(publish_gamepad_suppress(down, owner_b));
            break;
        case Channel::RuleGate:
            EXPECT_TRUE(DetourModKit::detail::set_gamepad_rule_suppress_enabled(true, owner_b));
            break;
        case Channel::WheelMask:
            EXPECT_TRUE(publish_wheel_consume(wheel_direction_bit(WheelDirection::Up), owner_b));
            break;
        case Channel::WheelDrain:
            DetourModKit::detail::seed_wheel_notches_for_test({1, 2, 3, 4});
            break;
        }

        s_release_data_plane_entry.store(true, std::memory_order_release);
        stale_owner.join();

        switch (channel)
        {
        case Channel::ConsumeRules:
            EXPECT_FALSE(stale_authorized.load(std::memory_order_acquire));
            EXPECT_EQ(DetourModKit::detail::consume_rules_sequence(), sequence_before_stale);
            EXPECT_EQ(sequence_before_stale % 2, 0u);
            EXPECT_EQ(evaluate_published_consume_rules(static_cast<uint16_t>(up | down)), down);
            break;
        case Channel::ReactiveMask:
            EXPECT_FALSE(stale_authorized.load(std::memory_order_acquire));
            EXPECT_EQ(DetourModKit::detail::gamepad_suppress_mask_for_test(), down);
            break;
        case Channel::RuleGate:
            EXPECT_FALSE(stale_authorized.load(std::memory_order_acquire));
            EXPECT_TRUE(DetourModKit::detail::gamepad_rule_suppress_enabled_for_test());
            break;
        case Channel::WheelMask:
            EXPECT_FALSE(stale_authorized.load(std::memory_order_acquire));
            EXPECT_EQ(DetourModKit::detail::wheel_consume_mask_for_test(), wheel_direction_bit(WheelDirection::Up));
            break;
        case Channel::WheelDrain:
            EXPECT_EQ(stale_counts, (std::array<int, 4>{}));
            EXPECT_EQ(take_wheel_counts(owner_b), (std::array<int, 4>{1, 2, 3, 4}));
            break;
        }
        uninstall(owner_b);
    }
}

TEST(InterceptOwnerEpochTest, RevocationClearsWheelBacklogBeforeTheNextOwner)
{
    uninstall();
    const std::uint64_t owner_a = next_intercept_owner();
    const std::uint64_t owner_b = next_intercept_owner();
    ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(owner_a));
    DetourModKit::detail::seed_wheel_notches_for_test({7, 6, 5, 4});

    uninstall(owner_a);
    ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(owner_b));
    EXPECT_EQ(take_wheel_counts(owner_b), (std::array<int, 4>{}));
    uninstall(owner_b);
}

TEST(InterceptOwnerEpochTest, RevocationInvalidatesAnEnteredWheelCaptureWithoutWaiting)
{
    uninstall();
    const std::uint64_t owner_a = next_intercept_owner();
    ASSERT_TRUE(DetourModKit::detail::adopt_owner_for_test(owner_a));

    s_wheel_capture_entry_reached.store(false, std::memory_order_release);
    s_release_wheel_capture_entry.store(false, std::memory_order_release);
    DetourModKit::detail::set_wheel_capture_entry_seam(&park_wheel_capture_entry);

    bool message_swallowed = false;
    // The real message path: the frame samples the enabled capture state, parks at the entry seam, and must fail its
    // epoch-tagged fold (and therefore swallow nothing) once the revocation lands.
    std::thread capture([&] { message_swallowed = DetourModKit::detail::process_wheel_message_for_test(false, 60); });
    while (!s_wheel_capture_entry_reached.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::atomic<bool> revocation_returned{false};
    std::thread revocation(
        [&]
        {
            uninstall(owner_a);
            revocation_returned.store(true, std::memory_order_release);
        });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{500};
    while (!revocation_returned.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::yield();
    }
    const bool revocation_completed_without_capture = revocation_returned.load(std::memory_order_acquire);

    const std::uint64_t owner_b = next_intercept_owner();
    const bool successor_adopted =
        revocation_completed_without_capture && DetourModKit::detail::adopt_owner_for_test(owner_b);

    s_release_wheel_capture_entry.store(true, std::memory_order_release);
    capture.join();
    revocation.join();
    DetourModKit::detail::set_wheel_capture_entry_seam(nullptr);

    EXPECT_TRUE(revocation_completed_without_capture);
    EXPECT_TRUE(successor_adopted);
    EXPECT_FALSE(message_swallowed);
    if (successor_adopted)
    {
        EXPECT_EQ(take_wheel_counts(owner_b), (std::array<int, 4>{}));
        EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
        EXPECT_EQ(take_wheel_counts(owner_b), (std::array<int, 4>{}));
        EXPECT_FALSE(DetourModKit::detail::process_wheel_message_for_test(false, 60));
        EXPECT_EQ(take_wheel_counts(owner_b), (std::array<int, 4>{1, 0, 0, 0}));
        uninstall(owner_b);
    }
}

TEST(InterceptXInputTest, ConcurrentOwnersNeverCorruptTheInstallation)
{
    HMODULE xinput = nullptr;
    for (const wchar_t *name : {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"})
    {
        xinput = LoadLibraryW(name);
        if (xinput != nullptr)
        {
            break;
        }
    }
    if (xinput == nullptr)
    {
        GTEST_SKIP() << "no XInput runtime available on this host";
    }

    const auto get_state =
        reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
    ASSERT_NE(get_state, nullptr);

    constexpr int churn_iterations = 32;
    std::atomic<int> ready{0};
    std::atomic<bool> start{false};
    const auto churn = [&](std::uint64_t owner, int &successful_installs)
    {
        ready.fetch_add(1, std::memory_order_release);
        while (!start.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        for (int i = 0; i < churn_iterations; ++i)
        {
            if (install_xinput(0, owner))
            {
                ++successful_installs;
                XINPUT_STATE state{};
                (void)get_state(0, &state);
                uninstall(owner);
            }
            std::this_thread::yield();
        }
    };

    const std::uint64_t owner_a = next_intercept_owner();
    const std::uint64_t owner_b = next_intercept_owner();
    int successful_a = 0;
    int successful_b = 0;
    std::thread ta(churn, owner_a, std::ref(successful_a));
    std::thread tb(churn, owner_b, std::ref(successful_b));
    while (ready.load(std::memory_order_acquire) != 2)
    {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    ta.join();
    tb.join();

    EXPECT_GT(successful_a + successful_b, 0);
    uninstall(owner_a);
    uninstall(owner_b);
    EXPECT_FALSE(xinput_installed());
    EXPECT_EQ(xinput_module_refs_held(), 0);

    FreeLibrary(xinput);
}

TEST(InterceptDisarmTest, PollerDisarmsWheelConsumeAfterClearBindings)
{
    // Reproduces the Logic-DLL hot-reload path: a consume wheel binding arms the wheel-swallow flag, and
    // clear_bindings(false) (the loader-lock-safe reset
    // Bootstrap uses) must let the poll loop disarm it on a later cycle so the game regains its wheel even though the
    // subclass stays installed until shutdown. Observed end to end through the recording predecessor: while consuming,
    // an owned wheel message is swallowed; once disarmed it is forwarded again.
    uninstall();
    s_forwarded_wheel_msgs.store(0, std::memory_order_relaxed);

    HWND hwnd = make_test_window();
    if (hwnd == nullptr)
    {
        GTEST_SKIP() << "no window station available to create a top-level window";
    }
    const LONG_PTR predecessor = reinterpret_cast<LONG_PTR>(&recording_wndproc);
    SetWindowLongPtrW(hwnd, GWLP_WNDPROC, predecessor);

    // A consume mouse-wheel binding arms both the wheel-capture subclass and the wheel-swallow flag.
    // require_focus=false keeps process_focused true so the disarm is deterministic regardless of which window owns the
    // foreground.
    detail::InputBinding binding;
    binding.name = "wheel_zoom";
    binding.keys = {mouse_wheel(WheelCode::Up)};
    binding.consume = true;
    binding.trigger = input::Trigger::Press;

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds(2), false);
    poller.start();

    const auto cleanup = [&]() noexcept
    {
        poller.shutdown(); // routes through detail::uninstall()
        uninstall();
        if (IsWindow(hwnd))
        {
            SetWindowLongPtrW(hwnd, GWLP_WNDPROC, predecessor);
            DestroyWindow(hwnd);
        }
    };

    // The poll thread lazily subclasses the game window; wait until it lands on OUR window (procedure changes away from
    // the recording predecessor).
    const bool hooked_ours =
        wait_until([&] { return wndproc_installed() && GetWindowLongPtrW(hwnd, GWLP_WNDPROC) != predecessor; },
                   std::chrono::seconds(5));
    if (!hooked_ours)
    {
        cleanup();
        GTEST_SKIP() << "poll thread did not subclass the test window";
    }

    // Wait until the swallow flag engages: an owned wheel message stops reaching the game's predecessor procedure.
    const bool consume_engaged = wait_until(
        [&]
        {
            const int before = s_forwarded_wheel_msgs.load(std::memory_order_relaxed);
            SendMessageW(hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
            return s_forwarded_wheel_msgs.load(std::memory_order_relaxed) == before;
        },
        std::chrono::seconds(5));
    EXPECT_TRUE(consume_engaged);

    // The loader-lock-safe hot-reload reset: drop bindings without firing release callbacks. The subclass stays
    // installed, so the poll loop must clear the swallow flag on a later cycle or the game loses its wheel.
    poller.clear_bindings(false);

    // Wait until the swallow flag disarms: the message is forwarded again.
    const bool consume_disarmed = wait_until(
        [&]
        {
            const int before = s_forwarded_wheel_msgs.load(std::memory_order_relaxed);
            SendMessageW(hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
            return s_forwarded_wheel_msgs.load(std::memory_order_relaxed) == before + 1;
        },
        std::chrono::seconds(5));
    EXPECT_TRUE(consume_disarmed);

    cleanup();
}

// A failed cache rebuild clears the drain flag while the consume wheel binding stays registered, and the subclass
// installed before the failure is never removed. Arming the swallow mask in that state would eat every notch out of the
// game without delivering it to any binding, and the publish refreshes its own time-to-live on each armed cycle, so
// nothing would lapse on its own. The mask must follow the drain, not the accumulated wheel_owned bits alone.
TEST(InterceptDisarmTest, PollerDisarmsWheelConsumeWhenTheCacheRebuildFails)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    uninstall();
    s_forwarded_wheel_msgs.store(0, std::memory_order_relaxed);
    (void)DetourModKit::log();

    HWND hwnd = make_test_window();
    if (hwnd == nullptr)
    {
        GTEST_SKIP() << "no window station available to create a top-level window";
    }
    const LONG_PTR predecessor = reinterpret_cast<LONG_PTR>(&recording_wndproc);
    SetWindowLongPtrW(hwnd, GWLP_WNDPROC, predecessor);

    constexpr std::string_view WHEEL_NAME = "wheel_zoom_with_a_name_past_the_small_string_buffer";

    detail::InputBinding binding;
    binding.name = WHEEL_NAME;
    binding.keys = {mouse_wheel(WheelCode::Up)};
    binding.consume = true;
    binding.trigger = input::Trigger::Press;

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds(2), false);
    poller.start();

    const auto cleanup = [&]() noexcept
    {
        poller.shutdown();
        uninstall();
        if (IsWindow(hwnd))
        {
            SetWindowLongPtrW(hwnd, GWLP_WNDPROC, predecessor);
            DestroyWindow(hwnd);
        }
    };

    const bool hooked_ours =
        wait_until([&] { return wndproc_installed() && GetWindowLongPtrW(hwnd, GWLP_WNDPROC) != predecessor; },
                   std::chrono::seconds(5));
    if (!hooked_ours)
    {
        cleanup();
        GTEST_SKIP() << "poll thread did not subclass the test window";
    }

    const bool consume_engaged = wait_until(
        [&]
        {
            const int before = s_forwarded_wheel_msgs.load(std::memory_order_relaxed);
            SendMessageW(hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
            return s_forwarded_wheel_msgs.load(std::memory_order_relaxed) == before;
        },
        std::chrono::seconds(5));
    if (!consume_engaged)
    {
        cleanup();
        FAIL() << "the consume wheel binding never armed the swallow mask, so the disarm below would prove nothing";
    }

    // Sweep allocation budgets until one lets the reshape land but fails the cache rebuild that follows it. An emptied
    // name index is that catch's signature: a budget too low fails add_binding before the reshape and leaves the poller
    // untouched, and one too high rebuilds successfully.
    bool reached_rebuild_failure = false;
    for (long long budget = 0; budget <= 64 && !reached_rebuild_failure; ++budget)
    {
        detail::InputBinding extra;
        extra.name = "extra_binding_" + std::to_string(budget) + "_past_the_small_string_buffer";
        extra.keys = {keyboard_key(0x70)};

        bool added = false;
        {
            dmk_test::AllocFailScope fail(budget);
            added = poller.add_binding(std::move(extra));
        }
        reached_rebuild_failure = added && !poller.acquire_binding_token(WHEEL_NAME).valid();
    }
    if (!reached_rebuild_failure)
    {
        cleanup();
        FAIL() << "no allocation budget reached the cache-rebuild failure this case exists to drive";
    }

    // The subclass is still installed and the consume wheel binding is still registered, but the poll loop no longer
    // drains the counters, so the game must get its wheel back.
    const bool consume_disarmed = wait_until(
        [&]
        {
            const int before = s_forwarded_wheel_msgs.load(std::memory_order_relaxed);
            SendMessageW(hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
            return s_forwarded_wheel_msgs.load(std::memory_order_relaxed) == before + 1;
        },
        std::chrono::seconds(5));
    EXPECT_TRUE(consume_disarmed) << "a swallow mask armed without a matching drain latches the game out of its wheel";

    cleanup();
}

TEST(InterceptDisarmTest, PollerConsumeSwallowsOnlyTheBoundWheelDirection)
{
    // End-to-end proof of the per-direction wheel consume through the poll loop: a consume binding on WheelUp must
    // swallow Up notches while leaving WheelDown notches reaching the game. This exercises the poll loop's wheel_owned
    // accumulation (Up binding -> Up bit only) plus the detour's per-direction gate together.
    uninstall();
    s_forwarded_wheel_msgs.store(0, std::memory_order_relaxed);

    HWND hwnd = make_test_window();
    if (hwnd == nullptr)
    {
        GTEST_SKIP() << "no window station available to create a top-level window";
    }
    const LONG_PTR predecessor = reinterpret_cast<LONG_PTR>(&recording_wndproc);
    SetWindowLongPtrW(hwnd, GWLP_WNDPROC, predecessor);

    // require_focus=false keeps process_focused true so the consume mask is published regardless of foreground owner.
    detail::InputBinding binding;
    binding.name = "wheel_up_zoom";
    binding.keys = {mouse_wheel(WheelCode::Up)};
    binding.consume = true;
    binding.trigger = input::Trigger::Press;

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds(2), false);
    poller.start();

    const auto cleanup = [&]() noexcept
    {
        poller.shutdown();
        uninstall();
        if (IsWindow(hwnd))
        {
            SetWindowLongPtrW(hwnd, GWLP_WNDPROC, predecessor);
            DestroyWindow(hwnd);
        }
    };

    const bool hooked_ours =
        wait_until([&] { return wndproc_installed() && GetWindowLongPtrW(hwnd, GWLP_WNDPROC) != predecessor; },
                   std::chrono::seconds(5));
    if (!hooked_ours)
    {
        cleanup();
        GTEST_SKIP() << "poll thread did not subclass the test window";
    }

    // Wait until the Up swallow engages: an Up notch stops reaching the game's predecessor procedure.
    const bool up_consumed = wait_until(
        [&]
        {
            const int before = s_forwarded_wheel_msgs.load(std::memory_order_relaxed);
            SendMessageW(hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0); // Up
            return s_forwarded_wheel_msgs.load(std::memory_order_relaxed) == before;
        },
        std::chrono::seconds(5));
    EXPECT_TRUE(up_consumed);

    // A Down notch is not owned by the Up binding, so it must still reach the game even while Up is being swallowed.
    const int before_down = s_forwarded_wheel_msgs.load(std::memory_order_relaxed);
    SendMessageW(hwnd, WM_MOUSEWHEEL, wheel_wparam(-1), 0); // Down
    EXPECT_EQ(s_forwarded_wheel_msgs.load(std::memory_order_relaxed), before_down + 1)
        << "Down notch must reach the game while only Up is consumed (per-direction wheel consume)";

    cleanup();
}
