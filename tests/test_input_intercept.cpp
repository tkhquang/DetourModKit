#include <gtest/gtest.h>

#include <cstdint>

#include "input_intercept.hpp"
#include "DetourModKit/input_codes.hpp"

using namespace DetourModKit;
using DetourModKit::detail::GamepadSuppressState;
using DetourModKit::detail::publish_gamepad_suppress;
using DetourModKit::detail::set_wheel_consume;
using DetourModKit::detail::step_gamepad_suppress;
using DetourModKit::detail::step_wheel_pulse;
using DetourModKit::detail::take_wheel_counts;
using DetourModKit::detail::uninstall;
using DetourModKit::detail::WheelPulseState;
using DetourModKit::detail::wndproc_installed;
using DetourModKit::detail::xinput_installed;
using DetourModKit::detail::xinput_trampoline;

namespace
{
    // Direction bit positions in the wheel pulse mask (mirrors WheelCode order).
    constexpr uint8_t kWheelUpBit = 1u << 0;
    constexpr uint8_t kWheelDownBit = 1u << 1;
    constexpr uint8_t kWheelRightBit = 1u << 3;

    constexpr uint64_t kGraceMs = 80;
} // namespace

// --- Control API safe to call without an installed hook ---

TEST(InterceptControlTest, AccessorsAndSettersWithNothingInstalled)
{
    // A unit-test process installs no hooks, so the accessors report "off" and
    // the setters/teardown are safe no-ops that only touch atomics.
    EXPECT_FALSE(xinput_installed());
    EXPECT_FALSE(wndproc_installed());
    EXPECT_EQ(xinput_trampoline(), nullptr);

    const auto counts = take_wheel_counts();
    for (const int value : counts)
    {
        EXPECT_EQ(value, 0);
    }

    set_wheel_consume(true);
    set_wheel_consume(false);
    publish_gamepad_suppress(0x0001);
    publish_gamepad_suppress(0);

    // Idempotent teardown leaves nothing installed.
    uninstall();
    EXPECT_FALSE(xinput_installed());
    EXPECT_FALSE(wndproc_installed());
}

// --- step_wheel_pulse: one notch maps to exactly one Press edge ---

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
    EXPECT_EQ(step_wheel_pulse(state), kWheelUpBit);
    // Cycle 2: forced low so the edge detector can re-arm.
    EXPECT_EQ(step_wheel_pulse(state), 0u);
    // Cycle 3: nothing pending.
    EXPECT_EQ(step_wheel_pulse(state), 0u);
}

TEST(WheelPulseTest, TwoNotchesProduceTwoSeparatedPulses)
{
    WheelPulseState state;
    state.pending[1] = 2; // two Down notches

    EXPECT_EQ(step_wheel_pulse(state), kWheelDownBit); // first notch
    EXPECT_EQ(step_wheel_pulse(state), 0u);            // forced gap
    EXPECT_EQ(step_wheel_pulse(state), kWheelDownBit); // second notch
    EXPECT_EQ(step_wheel_pulse(state), 0u);            // forced gap
    EXPECT_EQ(step_wheel_pulse(state), 0u);            // drained
}

TEST(WheelPulseTest, DirectionsAreIndependent)
{
    WheelPulseState state;
    state.pending[0] = 1; // Up
    state.pending[3] = 1; // Right

    EXPECT_EQ(step_wheel_pulse(state), static_cast<uint8_t>(kWheelUpBit | kWheelRightBit));
    EXPECT_EQ(step_wheel_pulse(state), 0u);
}

// --- step_gamepad_suppress: consume-until-release latch ---

TEST(GamepadSuppressTest, BarePressIsNotSuppressed)
{
    GamepadSuppressState state;
    // The trigger is physically down but no chord claims it (owned_now == 0):
    // a bare D-pad tap must reach the game.
    const uint16_t mask = step_gamepad_suppress(
        state, 0, static_cast<uint16_t>(GamepadCode::DpadUp), 1000, kGraceMs);
    EXPECT_EQ(mask, 0u);
}

TEST(GamepadSuppressTest, ActiveChordSuppressesTrigger)
{
    GamepadSuppressState state;
    const uint16_t buttons =
        static_cast<uint16_t>(GamepadCode::LeftBumper | GamepadCode::DpadUp);
    const uint16_t mask = step_gamepad_suppress(
        state, static_cast<uint16_t>(GamepadCode::DpadUp), buttons, 1000, kGraceMs);
    EXPECT_EQ(mask, static_cast<uint16_t>(GamepadCode::DpadUp));
}

TEST(GamepadSuppressTest, ModifierReleasedBeforeTriggerKeepsSuppressing)
{
    GamepadSuppressState state;
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);

    // Chord active: LB + D-pad both held.
    EXPECT_EQ(step_gamepad_suppress(state, dpad, static_cast<uint16_t>(lb | dpad), 1000, kGraceMs), dpad);

    // Bumper released a frame before the thumb leaves the D-pad. The chord is no
    // longer active (owned_now == 0) but the trigger is still physically down, so
    // it must stay suppressed -- this is the leak the feature exists to prevent.
    EXPECT_EQ(step_gamepad_suppress(state, 0, dpad, 1016, kGraceMs), dpad);
}

TEST(GamepadSuppressTest, TriggerReleaseSuppressesThroughGraceThenStops)
{
    GamepadSuppressState state;
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);

    // Claimed, then trigger physically released at t=1000.
    EXPECT_EQ(step_gamepad_suppress(state, dpad, dpad, 1000, kGraceMs), dpad);
    // Within the grace window: still suppressed so the trailing release does not leak.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1040, kGraceMs), dpad);
    // Past the grace window: the latch disarms and the game regains the button.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1200, kGraceMs), 0u);
    // Stays released afterwards.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1300, kGraceMs), 0u);
}

TEST(GamepadSuppressTest, RepressDuringGraceReHolds)
{
    GamepadSuppressState state;
    const uint16_t dpad = static_cast<uint16_t>(GamepadCode::DpadUp);

    EXPECT_EQ(step_gamepad_suppress(state, dpad, dpad, 1000, kGraceMs), dpad);
    // Released, enters grace.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1040, kGraceMs), dpad);
    // Physically pressed again during grace (still no chord): keep suppressing the
    // tail of the same gesture rather than leaking it.
    EXPECT_EQ(step_gamepad_suppress(state, 0, dpad, 1050, kGraceMs), dpad);
    // Released again; grace restarts from this release.
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1060, kGraceMs), dpad);
    EXPECT_EQ(step_gamepad_suppress(state, 0, 0, 1200, kGraceMs), 0u);
}
