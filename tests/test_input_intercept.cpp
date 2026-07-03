#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <new>
#include <thread>
#include <utility>
#include <vector>

#include "internal/input_intercept.hpp"
#include "internal/input_poller.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"

using namespace DetourModKit;
using DetourModKit::detail::add_wheel_notches;
using DetourModKit::detail::evaluate_consume_rules;
using DetourModKit::detail::evaluate_published_consume_rules;
using DetourModKit::detail::GamepadConsumeRule;
using DetourModKit::detail::GamepadSuppressState;
using DetourModKit::detail::install_wndproc;
using DetourModKit::detail::install_xinput;
using DetourModKit::detail::MAX_GAMEPAD_CONSUME_RULES;
using DetourModKit::detail::MAX_WHEEL_NOTCHES;
using DetourModKit::detail::MAX_WHEEL_PENDING;
using DetourModKit::detail::publish_gamepad_consume_rules;
using DetourModKit::detail::publish_gamepad_suppress;
using DetourModKit::detail::publish_wheel_consume;
using DetourModKit::detail::step_gamepad_suppress;
using DetourModKit::detail::wheel_direction_bit;
using DetourModKit::detail::WheelDirection;
using DetourModKit::detail::step_wheel_pulse;
using DetourModKit::detail::take_wheel_counts;
using DetourModKit::detail::uninstall;
using DetourModKit::detail::WheelPulseState;
using DetourModKit::detail::wndproc_installed;
using DetourModKit::detail::xinput_installed;
using DetourModKit::detail::xinput_trampoline;
using DetourModKit::detail::XInputGetStateFn;

namespace
{
    // Direction bit positions in the wheel pulse mask (mirrors WheelCode order).
    constexpr uint8_t WHEEL_UP_BIT = 1u << 0;
    constexpr uint8_t WHEEL_DOWN_BIT = 1u << 1;
    constexpr uint8_t WHEEL_RIGHT_BIT = 1u << 3;

    constexpr uint64_t GRACE_MS = 80;

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

    class ThrowingCopyCallback
    {
    public:
        explicit ThrowingCopyCallback(std::shared_ptr<std::atomic<bool>> throw_on_copy,
                                      std::shared_ptr<std::atomic<int>> failed_copies,
                                      std::shared_ptr<std::atomic<int>> invocations) noexcept
            : m_throw_on_copy(std::move(throw_on_copy)), m_failed_copies(std::move(failed_copies)),
              m_invocations(std::move(invocations))
        {
        }

        ThrowingCopyCallback(const ThrowingCopyCallback &other)
            : m_throw_on_copy(other.m_throw_on_copy), m_failed_copies(other.m_failed_copies),
              m_invocations(other.m_invocations)
        {
            throw_if_armed();
        }

        ThrowingCopyCallback &operator=(const ThrowingCopyCallback &other)
        {
            other.throw_if_armed();
            if (this != &other)
            {
                m_throw_on_copy = other.m_throw_on_copy;
                m_failed_copies = other.m_failed_copies;
                m_invocations = other.m_invocations;
            }
            return *this;
        }

        ThrowingCopyCallback(ThrowingCopyCallback &&) noexcept = default;
        ThrowingCopyCallback &operator=(ThrowingCopyCallback &&) noexcept = default;

        void operator()() const noexcept { m_invocations->fetch_add(1, std::memory_order_relaxed); }

    private:
        void throw_if_armed() const
        {
            if (m_throw_on_copy != nullptr && m_throw_on_copy->load(std::memory_order_relaxed))
            {
                m_failed_copies->fetch_add(1, std::memory_order_relaxed);
                throw std::bad_alloc{};
            }
        }

        std::shared_ptr<std::atomic<bool>> m_throw_on_copy;
        std::shared_ptr<std::atomic<int>> m_failed_copies;
        std::shared_ptr<std::atomic<int>> m_invocations;
    };
} // namespace

// --- Control API safe to call without an installed hook ---

TEST(InterceptControlTest, AccessorsAndSettersWithNothingInstalled)
{
    // A unit-test process installs no hooks, so the accessors report "off" and the setters/teardown are safe no-ops
    // that only touch atomics.
    EXPECT_FALSE(xinput_installed());
    EXPECT_FALSE(wndproc_installed());
    EXPECT_EQ(xinput_trampoline(), nullptr);

    const auto counts = take_wheel_counts();
    for (const int value : counts)
    {
        EXPECT_EQ(value, 0);
    }

    publish_wheel_consume(wheel_direction_bit(WheelDirection::Up));
    publish_wheel_consume(0);
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

// --- add_wheel_notches: backlog accumulation is capped ---

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

// --- step_gamepad_suppress: consume-until-release latch ---

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
    // trigger is still physically down, so it must stay suppressed -- this is the leak the feature exists to prevent.
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

// --- evaluate_consume_rules: detour-side chord evaluation ---

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
    // reaches the game -- the same decision the poll loop's strict-match check makes.
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

// --- publish_gamepad_consume_rules / evaluate_published_consume_rules: seqlock ---

class ConsumeRulePublishTest : public ::testing::Test
{
protected:
    // The rule list is process-global; isolate each case from neighbours and from any poller-constructing test that ran
    // earlier in the same process.
    void SetUp() override { publish_gamepad_consume_rules(nullptr, 0); }
    void TearDown() override { publish_gamepad_consume_rules(nullptr, 0); }
};

TEST_F(ConsumeRulePublishTest, RoundTripMatchesDirectEvaluation)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t rb = static_cast<uint16_t>(GamepadCode::RightBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const uint16_t down = static_cast<uint16_t>(GamepadCode::DpadDown);
    const std::array<GamepadConsumeRule, 2> rules{GamepadConsumeRule{lb, rb, up}, GamepadConsumeRule{rb, lb, down}};
    publish_gamepad_consume_rules(rules.data(), rules.size());

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

TEST_F(ConsumeRulePublishTest, OverCapPublishesEmpty)
{
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    // One past the cap, every rule a no-modifier match. If the cap truncated instead of emptying, at least one such
    // rule would survive and mask Up.
    std::array<GamepadConsumeRule, MAX_GAMEPAD_CONSUME_RULES + 1> rules{};
    for (auto &rule : rules)
    {
        rule = GamepadConsumeRule{0, 0, up};
    }
    publish_gamepad_consume_rules(rules.data(), rules.size());
    EXPECT_EQ(evaluate_published_consume_rules(up), 0u);
}

TEST_F(ConsumeRulePublishTest, ClearPublishesEmpty)
{
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    const GamepadConsumeRule rule{0, 0, up};
    publish_gamepad_consume_rules(&rule, 1);
    ASSERT_EQ(evaluate_published_consume_rules(up), up);
    publish_gamepad_consume_rules(nullptr, 0);
    EXPECT_EQ(evaluate_published_consume_rules(up), 0u);
}

// --- build_gamepad_consume_rules, via the InputPoller build+publish path ---

class ConsumeRuleBuildTest : public ::testing::Test
{
protected:
    void SetUp() override { publish_gamepad_consume_rules(nullptr, 0); }
    void TearDown() override { publish_gamepad_consume_rules(nullptr, 0); }
};

TEST_F(ConsumeRuleBuildTest, GamepadChordPublishesMaskableRule)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    // Constructing the poller runs the same build+publish path the poll thread uses.
    detail::InputPoller poller(
        {make_consume_chord({gamepad_button(GamepadCode::LeftBumper)}, {gamepad_button(GamepadCode::DpadUp)})});
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
    EXPECT_EQ(evaluate_published_consume_rules(up), 0u);
}

TEST_F(ConsumeRuleBuildTest, AnalogTriggerProducesNoRule)
{
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    // LeftTrigger is analog (not an XINPUT_GAMEPAD.wButtons bit), so there is no digital trigger to mask and no rule is
    // emitted.
    detail::InputPoller poller(
        {make_consume_chord({gamepad_button(GamepadCode::LeftBumper)}, {gamepad_button(GamepadCode::LeftTrigger)})});
    EXPECT_EQ(evaluate_published_consume_rules(lb), 0u);
}

// --- Live-hook lifecycle: window-procedure subclass and XInput inline hook ---
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

    LRESULT CALLBACK recording_wndproc(HWND h, UINT msg, WPARAM w, LPARAM l) noexcept
    {
        if (msg == WM_MOUSEWHEEL || msg == WM_MOUSEHWHEEL)
        {
            s_forwarded_wheel_msgs.fetch_add(1, std::memory_order_relaxed);
        }
        return DefWindowProcW(h, msg, w, l);
    }

    // Builds a wheel-message wParam whose HIWORD is a signed wheel delta of
    // |notches| detents. Positive scrolls forward (vertical Up / horizontal Right),
    // negative backward (Down / Left), matching the detour's sign split.
    WPARAM wheel_wparam(int notches) noexcept
    {
        const short delta = static_cast<short>(notches * WHEEL_DELTA);
        return MAKEWPARAM(0, static_cast<WORD>(delta));
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
} // namespace

class InterceptWndProcTest : public ::testing::Test
{
protected:
    HWND m_hwnd = nullptr;

    void SetUp() override
    {
        uninstall(); // start from a known-clean interception state
        s_forwarded_wheel_msgs.store(0, std::memory_order_relaxed);
        (void)take_wheel_counts();
        publish_wheel_consume(0);
        m_hwnd = make_test_window();
        if (m_hwnd == nullptr)
        {
            GTEST_SKIP() << "no window station available to create a top-level window";
        }
    }

    void TearDown() override
    {
        uninstall();
        if (m_hwnd != nullptr && IsWindow(m_hwnd))
        {
            DestroyWindow(m_hwnd);
        }
        m_hwnd = nullptr;
    }

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

    (void)take_wheel_counts(); // drain any stray notch before measuring

    // Vertical wheel: HIWORD sign selects Up (+) versus Down (-).
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(-1), 0);
    auto counts = take_wheel_counts();
    EXPECT_EQ(counts[0], 2); // Up
    EXPECT_EQ(counts[1], 1); // Down
    EXPECT_EQ(counts[2], 0); // Left
    EXPECT_EQ(counts[3], 0); // Right

    // Horizontal (tilt) wheel: positive tilts Right, negative Left.
    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_wparam(1), 0);
    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_wparam(-1), 0);
    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_wparam(-1), 0);
    SendMessageW(m_hwnd, WM_MOUSEHWHEEL, wheel_wparam(-1), 0);
    counts = take_wheel_counts();
    EXPECT_EQ(counts[0], 0);
    EXPECT_EQ(counts[1], 0);
    EXPECT_EQ(counts[2], 3); // Left
    EXPECT_EQ(counts[3], 1); // Right
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
    (void)take_wheel_counts();

    // Not consuming: the notch is latched for the poll loop AND forwarded to the game's procedure.
    publish_wheel_consume(0);
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    EXPECT_EQ(s_forwarded_wheel_msgs.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(take_wheel_counts()[0], 1);

    // Consume only the Up direction -- the mask a "Ctrl+WheelUp" binding publishes while Ctrl is held. The Up notch is
    // still latched for the poll loop, but swallowed so the game's procedure never sees it.
    publish_wheel_consume(wheel_direction_bit(WheelDirection::Up));
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    EXPECT_EQ(s_forwarded_wheel_msgs.load(std::memory_order_relaxed), 1); // unchanged: Up was swallowed
    EXPECT_EQ(take_wheel_counts()[0], 1);

    // A Down notch is not owned by the Up-only mask, so it must still reach the game. This is the important
    // per-direction invariant: consuming one wheel direction must not suppress the others.
    SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(-1), 0);
    EXPECT_EQ(s_forwarded_wheel_msgs.load(std::memory_order_relaxed), 2); // Down forwarded to the game
    EXPECT_EQ(take_wheel_counts()[1], 1);

    publish_wheel_consume(0);
}

TEST_F(InterceptWndProcTest, WheelCounterSaturatesWhenNotDrained)
{
    if (!install_on_our_window())
    {
        GTEST_SKIP() << "install_wndproc subclassed a different process window";
    }
    (void)take_wheel_counts(); // start from a clean slate

    // Reproduce the idle-accretion case: the subclass stays installed but nothing drains the counter (the poll loop's
    // take_wheel_counts is gated on live wheel bindings, so once the last wheel binding is removed the counter is no
    // longer drained). Drive far more Up notches than the cap without draining between them; the counter must saturate
    // at MAX_WHEEL_NOTCHES rather than continuing toward signed overflow.
    const int overshoot = MAX_WHEEL_NOTCHES + 128;
    for (int i = 0; i < overshoot; ++i)
    {
        SendMessageW(m_hwnd, WM_MOUSEWHEEL, wheel_wparam(1), 0);
    }
    const auto counts = take_wheel_counts();
    EXPECT_EQ(counts[0], MAX_WHEEL_NOTCHES) << "idle wheel counter must saturate at the cap, not accrete every notch";
    // The drain exchanged the slot to zero, so a second drain reads clean -- saturation did not wedge the counter.
    EXPECT_EQ(take_wheel_counts()[0], 0);
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
    binding.on_press = ThrowingCopyCallback{throw_on_copy, failed_copies, invocations};

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds(2), false);
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

TEST(InterceptXInputTest, UninstallQuiescesInFlightDetoursUnderConcurrentCallers)
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

    // Install the hook, drive the hooked export from several threads, then signal them to stop and immediately
    // uninstall before joining. Some callers may still be inside the detour body at the instant teardown begins, so the
    // retired-trampoline plus in-flight drain path is exercised without creating an endless stream of new prologue
    // entrants while SafetyHook is restoring the target. A regression surfaces as an access violation, so surviving the
    // rounds cleanly is the assertion.
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

        ASSERT_TRUE(wait_until([&] { return started.load(std::memory_order_acquire) == 3; },
                               std::chrono::seconds(5)));
        // Give the callers time to be actively cycling through the detour, then stop new calls and tear it down before
        // joining so any caller already in the detour must quiesce safely.
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
        stop.store(true, std::memory_order_release);
        uninstall();
        for (auto &caller : callers)
        {
            caller.join();
        }
    }

    EXPECT_FALSE(xinput_installed());
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
