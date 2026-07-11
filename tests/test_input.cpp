#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <clocale>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "DetourModKit/input.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/input_poller.hpp"
#include "internal/input_intercept.hpp"
#include "internal/input_binding_gate.hpp"
#include "internal/input_key_cache.hpp"

#include "test_alloc_probe.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;

// InputSource string conversion

TEST(InputSourceTest, KeyboardToString)
{
    EXPECT_EQ(input_source_to_string(InputSource::Keyboard), "Keyboard");
}

TEST(InputSourceTest, MouseToString)
{
    EXPECT_EQ(input_source_to_string(InputSource::Mouse), "Mouse");
}

TEST(InputSourceTest, GamepadToString)
{
    EXPECT_EQ(input_source_to_string(InputSource::Gamepad), "Gamepad");
}

TEST(InputSourceTest, MouseWheelToString)
{
    EXPECT_EQ(input_source_to_string(InputSource::MouseWheel), "MouseWheel");
}

// InputCode

TEST(InputCodeTest, DefaultConstruction)
{
    InputCode code;
    EXPECT_EQ(code.source, InputSource::Keyboard);
    EXPECT_EQ(code.code, 0);
}

TEST(InputCodeTest, Equality)
{
    EXPECT_EQ(keyboard_key(0x41), keyboard_key(0x41));
    EXPECT_NE(keyboard_key(0x41), keyboard_key(0x42));
    EXPECT_NE(keyboard_key(0x41), mouse_button(0x41));
    EXPECT_NE(keyboard_key(0x41), gamepad_button(0x41));
}

TEST(InputCodeTest, FactoryFunctions)
{
    auto kb = keyboard_key(0x41);
    EXPECT_EQ(kb.source, InputSource::Keyboard);
    EXPECT_EQ(kb.code, 0x41);

    auto mouse = mouse_button(0x05);
    EXPECT_EQ(mouse.source, InputSource::Mouse);
    EXPECT_EQ(mouse.code, 0x05);

    auto gp = gamepad_button(GamepadCode::A);
    EXPECT_EQ(gp.source, InputSource::Gamepad);
    EXPECT_EQ(gp.code, GamepadCode::A);

    auto wheel = mouse_wheel(WheelCode::Up);
    EXPECT_EQ(wheel.source, InputSource::MouseWheel);
    EXPECT_EQ(wheel.code, WheelCode::Up);
}

// Mouse-wheel name resolution

TEST(WheelNameTest, ParseWheelNames)
{
    EXPECT_EQ(parse_input_name("WheelUp"), mouse_wheel(WheelCode::Up));
    EXPECT_EQ(parse_input_name("WheelDown"), mouse_wheel(WheelCode::Down));
    EXPECT_EQ(parse_input_name("WheelLeft"), mouse_wheel(WheelCode::Left));
    EXPECT_EQ(parse_input_name("WheelRight"), mouse_wheel(WheelCode::Right));
}

TEST(WheelNameTest, ParseWheelNamesCaseInsensitive)
{
    EXPECT_EQ(parse_input_name("wheelup"), mouse_wheel(WheelCode::Up));
    EXPECT_EQ(parse_input_name("WHEELDOWN"), mouse_wheel(WheelCode::Down));
}

TEST(WheelNameTest, FormatWheelNames)
{
    EXPECT_EQ(format_input_code(mouse_wheel(WheelCode::Up)), "WheelUp");
    EXPECT_EQ(format_input_code(mouse_wheel(WheelCode::Down)), "WheelDown");
    EXPECT_EQ(format_input_code(mouse_wheel(WheelCode::Left)), "WheelLeft");
    EXPECT_EQ(format_input_code(mouse_wheel(WheelCode::Right)), "WheelRight");
}

// Trigger string conversion

TEST(TriggerTest, PressToString)
{
    EXPECT_EQ(input::to_string(input::Trigger::Press), "Press");
}

TEST(TriggerTest, HoldToString)
{
    EXPECT_EQ(input::to_string(input::Trigger::Hold), "Hold");
}

// InputBinding

TEST(InputBindingTest, DefaultTriggerIsPress)
{
    detail::InputBinding binding;
    EXPECT_EQ(binding.trigger, input::Trigger::Press);
}

// InputPoller

class InputPollerTest : public ::testing::Test
{
protected:
    void TearDown() override
    {
        // Ensure no lingering pollers
    }
};

TEST_F(InputPollerTest, ConstructWithEmptyBindings)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_running());
    EXPECT_EQ(poller.binding_count(), 0u);

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, ConstructWithBindings)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding press_binding;
    press_binding.name = "test_press";
    press_binding.keys = {keyboard_key(0x41)};
    press_binding.trigger = input::Trigger::Press;
    press_binding.on_press = []() {};
    bindings.push_back(std::move(press_binding));

    detail::InputBinding hold_binding;
    hold_binding.name = "test_hold";
    hold_binding.keys = {keyboard_key(0x42)};
    hold_binding.trigger = input::Trigger::Hold;
    hold_binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(hold_binding));

    detail::InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_running());
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, DefaultPollInterval)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    EXPECT_EQ(poller.poll_interval(), input::DEFAULT_POLL_INTERVAL);
}

TEST_F(InputPollerTest, CustomPollInterval)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{50});

    EXPECT_EQ(poller.poll_interval(), std::chrono::milliseconds{50});
}

TEST_F(InputPollerTest, PollIntervalClampedToMin)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{0});

    EXPECT_EQ(poller.poll_interval(), input::MIN_POLL_INTERVAL);
}

TEST_F(InputPollerTest, PollIntervalClampedToMax)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{5000});

    EXPECT_EQ(poller.poll_interval(), input::MAX_POLL_INTERVAL);
}

TEST_F(InputPollerTest, NotRunningBeforeStart)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, StartThenRunning)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, DoubleStartIgnored)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    poller.start();
    EXPECT_TRUE(poller.is_running());

    // Second start should be a no-op
    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, ShutdownIdempotent)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
    EXPECT_FALSE(poller.is_running());

    // Second shutdown should be safe
    EXPECT_NO_THROW(poller.shutdown());
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, ShutdownWithoutStart)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    // Shutdown before start should be safe
    EXPECT_NO_THROW(poller.shutdown());
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, DestructorStopsThread)
{
    bool thread_was_running = false;

    {
        std::vector<detail::InputBinding> bindings;
        detail::InputPoller poller(std::move(bindings));
        poller.start();
        thread_was_running = poller.is_running();
    }
    // Destructor should have joined the thread without hanging

    EXPECT_TRUE(thread_was_running);
}

TEST_F(InputPollerTest, NonCopyableNonMovable)
{
    EXPECT_FALSE(std::is_copy_constructible_v<detail::InputPoller>);
    EXPECT_FALSE(std::is_copy_assignable_v<detail::InputPoller>);
    EXPECT_FALSE(std::is_move_constructible_v<detail::InputPoller>);
    EXPECT_FALSE(std::is_move_assignable_v<detail::InputPoller>);
}

TEST_F(InputPollerTest, EmptyKeysSkipped)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "empty_keys";
    binding.keys = {};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    // Should run without issues even with empty keys
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, ZeroCodeSkipped)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "zero_code";
    binding.keys = {keyboard_key(0), keyboard_key(0), keyboard_key(0)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, MultipleBindingsMixed)
{
    std::vector<detail::InputBinding> bindings;

    for (int i = 0; i < 10; ++i)
    {
        detail::InputBinding binding;
        binding.name = "binding_" + std::to_string(i);
        binding.keys = {keyboard_key(0x41 + i)};
        binding.trigger = (i % 2 == 0) ? input::Trigger::Press : input::Trigger::Hold;
        if (binding.trigger == input::Trigger::Press)
        {
            binding.on_press = []() {};
        }
        else
        {
            binding.on_state_change = [](bool) {};
        }
        bindings.push_back(std::move(binding));
    }

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    EXPECT_TRUE(poller.is_running());
    EXPECT_EQ(poller.binding_count(), 10u);

    poller.shutdown();
}

TEST_F(InputPollerTest, NullCallbackHandled)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "null_callback";
    binding.keys = {keyboard_key(0x41)};
    binding.trigger = input::Trigger::Press;
    // on_press intentionally left empty
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, ShutdownResponsiveness)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{500});

    poller.start();
    EXPECT_TRUE(poller.is_running());

    const auto start = std::chrono::steady_clock::now();
    poller.shutdown();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    // Shutdown should complete well under the poll interval due to CV wake-up
    EXPECT_LT(elapsed, std::chrono::milliseconds{200});
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, IsRunningFalseAfterShutdownCompletes)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();

    // is_running() must return false only after the thread has fully joined
    EXPECT_FALSE(poller.is_running());
}

// InputPoller: Gamepad

TEST_F(InputPollerTest, GamepadBindingConstruction)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "gamepad_test";
    binding.keys = {gamepad_button(GamepadCode::A)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));

    EXPECT_EQ(poller.binding_count(), 1u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, GamepadWithModifiers)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "gamepad_combo";
    binding.keys = {gamepad_button(GamepadCode::A)};
    binding.modifiers = {gamepad_button(GamepadCode::LeftBumper)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());
    EXPECT_FALSE(poller.is_binding_active("gamepad_combo"));

    poller.shutdown();
}

TEST_F(InputPollerTest, GamepadTriggerBinding)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "trigger_test";
    binding.keys = {gamepad_button(GamepadCode::LeftTrigger)};
    binding.trigger = input::Trigger::Hold;
    binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings), input::DEFAULT_POLL_INTERVAL, true, 0, 50);
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, GamepadIndexClamped)
{
    std::vector<detail::InputBinding> bindings;

    // Index -1 should clamp to 0, index 5 should clamp to 3
    detail::InputPoller poller_low(std::move(bindings), input::DEFAULT_POLL_INTERVAL, true, -1);
    EXPECT_EQ(poller_low.binding_count(), 0u);
    EXPECT_EQ(poller_low.gamepad_index(), 0);

    std::vector<detail::InputBinding> bindings2;
    detail::InputPoller poller_high(std::move(bindings2), input::DEFAULT_POLL_INTERVAL, true, 5);
    EXPECT_EQ(poller_high.binding_count(), 0u);
    EXPECT_EQ(poller_high.gamepad_index(), 3);
}

TEST_F(InputPollerTest, MixedKeyboardAndGamepadBindings)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding kb_binding;
    kb_binding.name = "keyboard";
    kb_binding.keys = {keyboard_key(0x41)};
    kb_binding.trigger = input::Trigger::Press;
    kb_binding.on_press = []() {};
    bindings.push_back(std::move(kb_binding));

    detail::InputBinding gp_binding;
    gp_binding.name = "gamepad";
    gp_binding.keys = {gamepad_button(GamepadCode::A)};
    gp_binding.trigger = input::Trigger::Press;
    gp_binding.on_press = []() {};
    bindings.push_back(std::move(gp_binding));

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.shutdown();
}

// Input facade

class InputTest : public ::testing::Test
{
protected:
    // shutdown() tears down the poller but does not reset require_focus (a persistent setting), so restore the
    // default here. A test that flips require_focus and then aborts on an ASSERT cannot leak that state into the
    // next test: ctest already isolates each case in its own process, and this keeps the single-process exe
    // deterministic too, without a per-test restore that an early ASSERT would skip.
    void SetUp() override
    {
        auto &mgr = input::Input::instance();
        mgr.shutdown();
        mgr.set_require_focus(true);
    }

    void TearDown() override { input::Input::instance().shutdown(); }
};

TEST_F(InputTest, EmptyStartBuildsNoEngineAndLaterRegistrationsStayStagedUntilNextStart)
{
    auto &mgr = input::Input::instance();

    // An empty start() -- nothing staged -- is a no-op success that builds no poll thread. Documented contract: it
    // does not go running, because there is nothing to poll.
    ASSERT_TRUE(mgr.start().has_value());
    EXPECT_FALSE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 0u);

    // A registration after that empty start() is STAGED, not live: it counts as pending but does not retroactively
    // start the engine (there is no live engine to forward it to).
    (void)input::register_combo(input::ComboBinding{.name = "staged_after_empty_start",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x70)}, {}}},
                                                    .on_press = [] {}});
    EXPECT_FALSE(mgr.is_running()) << "a post-empty-start registration must not start the engine on its own";
    EXPECT_EQ(mgr.binding_count(), 1u);

    // The next start() sees the staged binding, builds the engine, and now goes running.
    ASSERT_TRUE(mgr.start().has_value());
    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}

TEST_F(InputTest, SetConsumeBeforeStartUpdatesPendingBinding)
{
    auto &mgr = input::Input::instance();
    // A keyboard binding never installs a hook (suppression is gamepad/wheel only), so this exercises the consume
    // plumbing without touching real input.
    (void)input::register_combo(input::ComboBinding{.name = "consume_pending",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x70)}, {}}},
                                                    .on_press = [] {}});
    mgr.set_consume("consume_pending", true);
    mgr.set_consume("nonexistent_binding", true); // unknown name is a no-op
    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RemoveBindingsByName_PluralAliasMatchesSingular)
{
    auto &mgr = input::Input::instance();
    // Keyboard bindings install no hook, so this exercises the plural alias without touching real input.
    (void)input::register_combo(input::ComboBinding{.name = "alias_a",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x70)}, {}}},
                                                    .on_press = [] {}});
    (void)input::register_combo(input::ComboBinding{.name = "alias_b",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x71)}, {}}},
                                                    .on_press = [] {}});
    EXPECT_EQ(mgr.binding_count(), 2u);

    // The plural alias forwards to the singular implementation and returns the removed count.
    EXPECT_EQ(mgr.remove_bindings_by_name("alias_a"), 1u);
    EXPECT_EQ(mgr.binding_count(), 1u);

    // The two-arg plural overload (invoke_callbacks = false) is equally a thin forwarder.
    EXPECT_EQ(mgr.remove_bindings_by_name("alias_b", false), 1u);
    EXPECT_EQ(mgr.binding_count(), 0u);

    // Removing an unknown name returns 0, matching the singular behavior.
    EXPECT_EQ(mgr.remove_bindings_by_name("nonexistent"), 0u);
}

TEST_F(InputTest, SetConsumeWhileRunningIsSafe)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(input::ComboBinding{.name = "consume_live",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x70)}, {}}},
                                                    .on_press = [] {}});
    (void)mgr.start();
    mgr.set_consume("consume_live", true);
    mgr.set_consume("consume_live", false);
    EXPECT_TRUE(mgr.is_running());
    mgr.shutdown();
}

TEST_F(InputTest, RegisterConsumeFlagAppliesToBinding)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(input::ComboBinding{.name = "consume_cfg",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x70)}, {}}},
                                                    .on_press = [] {}});
    // The fused helper fires set_consume("consume_cfg", true) at registration time, with the same setter re-applied on
    // every load() / reload().
    config::consume_flag("Hotkeys", "ConsumeCfg.Consume", "Consume Cfg", "consume_cfg", true);
    EXPECT_EQ(mgr.binding_count(), 1u);
    // Drop the registered setter so it does not fire against later tests.
    config::clear();
}

TEST_F(InputTest, AnalogOnlyConsumeGamepadBindingInstallsNoXInputHook)
{
    // A consume binding whose only trigger is an analog code (trigger/stick) can never be masked: the XInput detour
    // clears digital wButtons bits only. The poll loop must therefore not install the hook for such a binding.
    // Asserting "no hook installed" verifies the digital-only install gate without putting a live hook into the test
    // process (no game window or controller is needed).
    auto &mgr = input::Input::instance();
    (void)input::register_combo(input::ComboBinding{.name = "analog_consume",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{gamepad_button(GamepadCode::LeftTrigger)}, {}}},
                                                    .on_press = [] {}});
    mgr.set_consume("analog_consume", true);
    (void)mgr.start();

    // Give the poll loop several cycles to reach its lazy-install check.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    // Confirm the poll thread is actually alive and cycling, so "no hook installed" reflects the install gate staying
    // closed for an analog-only consume binding rather than a thread that never reached the check.
    EXPECT_TRUE(mgr.is_running());
    EXPECT_FALSE(detail::xinput_installed());

    mgr.shutdown();
    EXPECT_FALSE(detail::xinput_installed());
}

// An empty-name consume binding's guard release must lift passthrough suppression. An empty name is legal and
// addressable only through its guard. Because the poller's name index skips empty names, a name-keyed consume clear
// would silently miss the entry and leave the game's chord suppressed for the process lifetime. The identity-keyed
// clear drops the published suppression rule to zero.
TEST_F(InputTest, EmptyNameConsumeGuardReleaseLiftsSuppression)
{
    auto &mgr = input::Input::instance();
    // Reset any suppression rule a prior test published so the assertions read this binding alone.
    DetourModKit::detail::publish_gamepad_consume_rules(nullptr, 0);

    auto guard = input::register_combo(input::ComboBinding{.name = "",
                                                           .trigger = input::Trigger::Press,
                                                           .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                           .consume = true,
                                                           .on_press = [] {}});
    ASSERT_TRUE(guard.has_value());

    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1000}});
    const std::uint16_t button = static_cast<std::uint16_t>(GamepadCode::A);
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button)
        << "the anonymous consume binding should arm suppression while its guard is live";

    guard->release();
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), 0u)
        << "releasing the guard must lift suppression even for an empty-name binding";

    mgr.shutdown();
    DetourModKit::detail::publish_gamepad_consume_rules(nullptr, 0);
}

// Scope::abandon() discards guards without running their release, while the normal Scope::clear() runs the release. A
// held Hold binding cannot be driven from a unit test (there is no GetAsyncKeyState injection seam), so a consume
// binding stands in: its release has an observable side effect (lifting suppression), which is exactly the "release
// ran" signal to detect. abandon() must leave suppression armed (no release ran); clear() must lift it.
TEST_F(InputTest, ScopeAbandonDiscardsGuardsWithoutRunningRelease)
{
    auto &mgr = input::Input::instance();
    DetourModKit::detail::publish_gamepad_consume_rules(nullptr, 0);
    const std::uint16_t button = static_cast<std::uint16_t>(GamepadCode::A);

    input::Scope scope;
    {
        auto guard = input::register_combo(input::ComboBinding{.name = "abandon_consume",
                                                               .trigger = input::Trigger::Press,
                                                               .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                               .consume = true,
                                                               .on_press = [] {}});
        ASSERT_TRUE(guard.has_value());
        scope.add(std::move(*guard));
    }
    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1000}});
    ASSERT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button);

    scope.abandon();
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button)
        << "Scope::abandon() must not run guard release, so suppression stays armed";

    mgr.shutdown();
    DetourModKit::detail::publish_gamepad_consume_rules(nullptr, 0);
}

TEST_F(InputTest, ScopeClearRunsGuardReleaseAndLiftsSuppression)
{
    auto &mgr = input::Input::instance();
    DetourModKit::detail::publish_gamepad_consume_rules(nullptr, 0);
    const std::uint16_t button = static_cast<std::uint16_t>(GamepadCode::A);

    input::Scope scope;
    {
        auto guard = input::register_combo(input::ComboBinding{.name = "clear_consume",
                                                               .trigger = input::Trigger::Press,
                                                               .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                               .consume = true,
                                                               .on_press = [] {}});
        ASSERT_TRUE(guard.has_value());
        scope.add(std::move(*guard));
    }
    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1000}});
    ASSERT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button);

    scope.clear();
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), 0u)
        << "Scope::clear() runs guard release, which lifts suppression (the control for abandon())";

    mgr.shutdown();
    DetourModKit::detail::publish_gamepad_consume_rules(nullptr, 0);
}

// A plain guard release retires only the callback; the binding stays registered, so a token keeps reflecting its
// physical press state and stays current. Only a reshape of the binding set -- a consume-flag change (which a consume
// guard's release performs), a rebind, or a removal -- advances the generation and makes a stale token fail closed.
TEST_F(InputTest, TokenStaysCurrentAfterPlainGuardRelease)
{
    auto &mgr = input::Input::instance();
    auto guard = input::register_combo(input::ComboBinding{.name = "tok_plain",
                                                           .trigger = input::Trigger::Press,
                                                           .combos = {{{keyboard_key(0x71)}, {}}},
                                                           .on_press = [] {}});
    ASSERT_TRUE(guard.has_value());
    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("tok_plain");
    ASSERT_TRUE(token.valid());
    ASSERT_TRUE(mgr.token_current(token));

    guard->release();
    EXPECT_TRUE(mgr.token_current(token))
        << "a plain (non-consume) guard release must NOT advance the generation; the binding stays registered";

    mgr.shutdown();
}

TEST_F(InputTest, TokenGoesStaleAfterConsumeGuardRelease)
{
    auto &mgr = input::Input::instance();
    auto guard = input::register_combo(input::ComboBinding{.name = "tok_consume",
                                                           .trigger = input::Trigger::Press,
                                                           .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                           .consume = true,
                                                           .on_press = [] {}});
    ASSERT_TRUE(guard.has_value());
    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("tok_consume");
    ASSERT_TRUE(token.valid());
    ASSERT_TRUE(mgr.token_current(token));

    guard->release();
    EXPECT_FALSE(mgr.token_current(token))
        << "a consume guard's release clears the consume flag (a set reshape), which advances the generation";

    mgr.shutdown();
}

TEST_F(InputTest, TokenGoesStaleAfterRebind)
{
    auto &mgr = input::Input::instance();
    auto guard = input::register_combo(input::ComboBinding{.name = "tok_rebind",
                                                           .trigger = input::Trigger::Press,
                                                           .combos = {{{keyboard_key(0x71)}, {}}},
                                                           .on_press = [] {}});
    ASSERT_TRUE(guard.has_value());
    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("tok_rebind");
    ASSERT_TRUE(mgr.token_current(token));

    ASSERT_TRUE(mgr.rebind("tok_rebind", input::KeyComboList{{{keyboard_key(0x72)}, {}}}).has_value());
    EXPECT_FALSE(mgr.token_current(token)) << "a rebind reshapes the binding set and advances the generation";

    mgr.shutdown();
}

TEST_F(InputTest, TokenGoesStaleAfterRemove)
{
    auto &mgr = input::Input::instance();
    auto guard = input::register_combo(input::ComboBinding{.name = "tok_remove",
                                                           .trigger = input::Trigger::Press,
                                                           .combos = {{{keyboard_key(0x71)}, {}}},
                                                           .on_press = [] {}});
    ASSERT_TRUE(guard.has_value());
    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("tok_remove");
    ASSERT_TRUE(mgr.token_current(token));

    EXPECT_EQ(mgr.remove_bindings_by_name("tok_remove"), 1u);
    EXPECT_FALSE(mgr.token_current(token)) << "a name-based removal reshapes the binding set and advances the generation";

    mgr.shutdown();
}

// Name resolution must fold case with an ASCII-only table, never a locale-sensitive std::tolower. Under some CRT
// locales, a locale fold can map ASCII identifiers differently enough that "I"/"i" and "Insert"/"insert" stop
// comparing equal. Force a Turkish locale best-effort and assert the ASCII pair still folds together; if the locale
// is not installed the fold is already ASCII, so the assertions hold under "C" as well.
TEST(InputCodeNameTest, NameResolutionIsLocaleIndependentAsciiFold)
{
    const char *saved = std::setlocale(LC_ALL, nullptr);
    const std::string saved_copy = saved ? saved : "C";
    (void)(std::setlocale(LC_ALL, "tr-TR") || std::setlocale(LC_ALL, "tr_TR.UTF-8") ||
           std::setlocale(LC_ALL, "Turkish"));

    const auto upper = DetourModKit::parse_input_name("I");
    const auto lower = DetourModKit::parse_input_name("i");
    const auto mixed = DetourModKit::parse_input_name("InSeRt");
    const auto plain = DetourModKit::parse_input_name("insert");

    std::setlocale(LC_ALL, saved_copy.c_str());

    ASSERT_TRUE(upper.has_value());
    ASSERT_TRUE(lower.has_value());
    EXPECT_EQ(upper, lower) << "ASCII 'I'/'i' must fold together regardless of the active C locale";
    ASSERT_TRUE(mixed.has_value());
    ASSERT_TRUE(plain.has_value());
    EXPECT_EQ(mixed, plain);
}

TEST_F(InputTest, SingletonIdentity)
{
    input::Input &a = input::Input::instance();
    input::Input &b = input::Input::instance();

    EXPECT_EQ(&a, &b);
}

TEST_F(InputTest, InitialState)
{
    input::Input &mgr = input::Input::instance();

    EXPECT_FALSE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 0u);
}

TEST_F(InputTest, RegisterPressBinding)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "test_press",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});

    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputTest, RegisterHoldBinding)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "test_hold",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_state_change = [](bool) {}});

    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputTest, RegisterMultipleBindings)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "press1",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "press2",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "hold1",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{keyboard_key(0x43)}, {}}},
                                                    .on_state_change = [](bool) {}});

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputTest, StartAndShutdown)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{
        .name = "test", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});
    (void)mgr.start();

    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();

    EXPECT_FALSE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 0u);
}

TEST_F(InputTest, StartWithoutBindingsDoesNothing)
{
    input::Input &mgr = input::Input::instance();

    (void)mgr.start();

    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputTest, ShutdownIdempotent)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{
        .name = "test", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});
    (void)mgr.start();

    mgr.shutdown();
    EXPECT_NO_THROW(mgr.shutdown());
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputTest, RegisterAppendsLiveWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "before",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    (void)input::register_combo(input::ComboBinding{.name = "after",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_press = []() {}});
    EXPECT_EQ(mgr.binding_count(), 2u);

    mgr.shutdown();
}

TEST_F(InputTest, RestartAfterShutdown)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "first_run",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
    EXPECT_FALSE(mgr.is_running());

    (void)input::register_combo(input::ComboBinding{.name = "second_run",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_state_change = [](bool) {}});
    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}

TEST_F(InputTest, StartWithCustomPollInterval)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{
        .name = "test", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});
    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{32}});

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, DoubleStartIgnored)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{
        .name = "test", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});
    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());

    // Second start should be a no-op
    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, MultipleKeysPerBinding)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{.name = "multi_key",
                            .trigger = input::Trigger::Press,
                            .combos = {{{keyboard_key(0x70), keyboard_key(0x71), keyboard_key(0x72)}, {}}},
                            .on_press = []() {}});
    (void)mgr.start();

    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}

TEST_F(InputTest, ConcurrentAccess)
{
    input::Input &mgr = input::Input::instance();

    constexpr int thread_count = 4;
    constexpr int ops_per_thread = 50;
    std::atomic<int> registered{0};

    std::vector<std::thread> threads;
    threads.reserve(thread_count);

    for (int t = 0; t < thread_count; ++t)
    {
        threads.emplace_back(
            [&registered, t]()
            {
                for (int i = 0; i < ops_per_thread; ++i)
                {
                    std::string name = "binding_" + std::to_string(t) + "_" + std::to_string(i);
                    (void)input::register_combo(input::ComboBinding{.name = name,
                                                                    .trigger = input::Trigger::Press,
                                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                                    .on_press = []() {}});
                    registered.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }

    for (auto &th : threads)
    {
        th.join();
    }

    EXPECT_EQ(mgr.binding_count(), static_cast<size_t>(thread_count * ops_per_thread));
}

// InputPoller: Focus, Modifiers, Active State

TEST_F(InputPollerTest, DefaultRequiresFocus)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

    // Default require_focus is true; poller should start and run normally
    poller.start();
    EXPECT_TRUE(poller.is_running());
    poller.shutdown();
}

TEST_F(InputPollerTest, ExplicitRequireFocusFalse)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings), input::DEFAULT_POLL_INTERVAL, false);

    poller.start();
    EXPECT_TRUE(poller.is_running());
    poller.shutdown();
}

TEST_F(InputPollerTest, SetRequireFocusWhileRunning)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings), input::DEFAULT_POLL_INTERVAL, true);

    poller.start();
    EXPECT_TRUE(poller.is_running());

    // Changing focus requirement at runtime should not crash
    poller.set_require_focus(false);
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.set_require_focus(true);
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, IsBindingActiveByIndexOutOfRange)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "test";
    binding.keys = {keyboard_key(0x41)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_binding_active(0));
    EXPECT_FALSE(poller.is_binding_active(1));
    EXPECT_FALSE(poller.is_binding_active(999));
}

TEST_F(InputPollerTest, IsBindingActiveByName)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "test_binding";
    binding.keys = {keyboard_key(0x41)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_binding_active("test_binding"));
    EXPECT_FALSE(poller.is_binding_active("nonexistent"));
    EXPECT_FALSE(poller.is_binding_active(""));
}

TEST_F(InputPollerTest, IsBindingActiveWhileRunning)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "active_test";
    binding.keys = {keyboard_key(0x41)};
    binding.trigger = input::Trigger::Hold;
    binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    // No keys pressed in test environment
    EXPECT_FALSE(poller.is_binding_active(0));
    EXPECT_FALSE(poller.is_binding_active("active_test"));

    poller.shutdown();
}

TEST_F(InputPollerTest, ModifierBindingConstruction)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "ctrl_shift_a";
    binding.keys = {keyboard_key(0x41)};
    binding.modifiers = {keyboard_key(0x11), keyboard_key(0x10)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));

    EXPECT_EQ(poller.binding_count(), 1u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, EmptyModifiersBackwardCompatible)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "no_mods";
    binding.keys = {keyboard_key(0x41)};
    // modifiers left empty (default)
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, HoldBindingShutdownSafety)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "hold_shutdown_test";
    binding.keys = {keyboard_key(0x41)};
    binding.trigger = input::Trigger::Hold;
    binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    // Shutdown with hold bindings should complete cleanly
    EXPECT_NO_THROW(poller.shutdown());
    EXPECT_FALSE(poller.is_running());
    EXPECT_FALSE(poller.is_binding_active(0));
}

// InputPoller: Strict Modifier Matching

TEST_F(InputPollerTest, StrictModifierMatchingConstruction)
{
    // When "V" and "Shift+V" are both registered, the poller should construct without error and track Shift as a known
    // modifier.
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding plain_v;
    plain_v.name = "plain_v";
    plain_v.keys = {keyboard_key(0x56)};
    plain_v.trigger = input::Trigger::Press;
    plain_v.on_press = []() {};
    bindings.push_back(std::move(plain_v));

    detail::InputBinding shift_v;
    shift_v.name = "shift_v";
    shift_v.keys = {keyboard_key(0x56)};
    shift_v.modifiers = {keyboard_key(0x10)};
    shift_v.trigger = input::Trigger::Press;
    shift_v.on_press = []() {};
    bindings.push_back(std::move(shift_v));

    detail::InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingMultipleModifiers)
{
    // "A", "Ctrl+A", "Ctrl+Shift+A" -- three levels of modifier specificity
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding plain;
    plain.name = "plain_a";
    plain.keys = {keyboard_key(0x41)};
    plain.trigger = input::Trigger::Press;
    plain.on_press = []() {};
    bindings.push_back(std::move(plain));

    detail::InputBinding ctrl_a;
    ctrl_a.name = "ctrl_a";
    ctrl_a.keys = {keyboard_key(0x41)};
    ctrl_a.modifiers = {keyboard_key(0x11)};
    ctrl_a.trigger = input::Trigger::Press;
    ctrl_a.on_press = []() {};
    bindings.push_back(std::move(ctrl_a));

    detail::InputBinding ctrl_shift_a;
    ctrl_shift_a.name = "ctrl_shift_a";
    ctrl_shift_a.keys = {keyboard_key(0x41)};
    ctrl_shift_a.modifiers = {keyboard_key(0x11), keyboard_key(0x10)};
    ctrl_shift_a.trigger = input::Trigger::Press;
    ctrl_shift_a.on_press = []() {};
    bindings.push_back(std::move(ctrl_shift_a));

    detail::InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 3u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingNoModifierBindingsUnaffected)
{
    // When no binding uses modifiers, all bindings should work normally
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding a;
    a.name = "key_a";
    a.keys = {keyboard_key(0x41)};
    a.trigger = input::Trigger::Press;
    a.on_press = []() {};
    bindings.push_back(std::move(a));

    detail::InputBinding b;
    b.name = "key_b";
    b.keys = {keyboard_key(0x42)};
    b.trigger = input::Trigger::Press;
    b.on_press = []() {};
    bindings.push_back(std::move(b));

    detail::InputPoller poller(std::move(bindings));

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingWithHoldMode)
{
    // Hold mode should also respect strict modifier matching
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding plain;
    plain.name = "hold_v";
    plain.keys = {keyboard_key(0x56)};
    plain.trigger = input::Trigger::Hold;
    plain.on_state_change = [](bool) {};
    bindings.push_back(std::move(plain));

    detail::InputBinding shift;
    shift.name = "shift_hold_v";
    shift.keys = {keyboard_key(0x56)};
    shift.modifiers = {keyboard_key(0x10)};
    shift.trigger = input::Trigger::Hold;
    shift.on_state_change = [](bool) {};
    bindings.push_back(std::move(shift));

    detail::InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingNonStandardModifier)
{
    // Non-standard modifier: "A+B" where A is the modifier
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding plain_b;
    plain_b.name = "plain_b";
    plain_b.keys = {keyboard_key(0x42)};
    plain_b.trigger = input::Trigger::Press;
    plain_b.on_press = []() {};
    bindings.push_back(std::move(plain_b));

    detail::InputBinding a_plus_b;
    a_plus_b.name = "a_plus_b";
    a_plus_b.keys = {keyboard_key(0x42)};
    a_plus_b.modifiers = {keyboard_key(0x41)};
    a_plus_b.trigger = input::Trigger::Press;
    a_plus_b.on_press = []() {};
    bindings.push_back(std::move(a_plus_b));

    detail::InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingGamepadBindings)
{
    // Gamepad modifiers should be tracked in the known modifiers set
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding plain;
    plain.name = "gp_a";
    plain.keys = {gamepad_button(GamepadCode::A)};
    plain.trigger = input::Trigger::Press;
    plain.on_press = []() {};
    bindings.push_back(std::move(plain));

    detail::InputBinding lb_a;
    lb_a.name = "lb_gp_a";
    lb_a.keys = {gamepad_button(GamepadCode::A)};
    lb_a.modifiers = {gamepad_button(GamepadCode::LeftBumper)};
    lb_a.trigger = input::Trigger::Press;
    lb_a.on_press = []() {};
    bindings.push_back(std::move(lb_a));

    detail::InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingCrossFeatureIsolation)
{
    // Modifier from unrelated binding blocks other bare bindings. Feature A: "V", Feature B: "Shift+G" -- Shift is
    // known, so plain "V" won't fire while Shift is held.
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding plain_v;
    plain_v.name = "feature_a";
    plain_v.keys = {keyboard_key(0x56)};
    plain_v.trigger = input::Trigger::Press;
    plain_v.on_press = []() {};
    bindings.push_back(std::move(plain_v));

    detail::InputBinding shift_g;
    shift_g.name = "feature_b";
    shift_g.keys = {keyboard_key(0x47)};
    shift_g.modifiers = {keyboard_key(0x10)};
    shift_g.trigger = input::Trigger::Press;
    shift_g.on_press = []() {};
    bindings.push_back(std::move(shift_g));

    detail::InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

// Input facade: Focus, Modifiers, Active State

TEST_F(InputTest, RegisterPressWithModifiers)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "ctrl_a",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {keyboard_key(0x11)}}},
                                                    .on_press = []() {}});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterHoldWithModifiers)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "shift_hold",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{keyboard_key(0x41)}, {keyboard_key(0x10)}}},
                                                    .on_state_change = [](bool) {}});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterMixedModifierBindings)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "plain",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "ctrl_b",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {keyboard_key(0x11)}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(
        input::ComboBinding{.name = "shift_c",
                            .trigger = input::Trigger::Hold,
                            .combos = {{{keyboard_key(0x43)}, {keyboard_key(0x10), keyboard_key(0x11)}}},
                            .on_state_change = [](bool) {}});

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputTest, SetRequireFocusBeforeStart)
{
    input::Input &mgr = input::Input::instance();

    mgr.set_require_focus(false);
    (void)input::register_combo(input::ComboBinding{
        .name = "test", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});
    (void)mgr.start();

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, SetRequireFocusWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{
        .name = "test", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});
    (void)mgr.start();

    EXPECT_TRUE(mgr.is_running());

    // Should not crash or affect running state
    mgr.set_require_focus(false);
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(mgr.is_running());

    mgr.set_require_focus(true);
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, IsBindingActiveNotRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{
        .name = "test", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});

    // Not started yet
    EXPECT_FALSE(mgr.is_active("test"));
    EXPECT_FALSE(mgr.is_active("nonexistent"));
}

TEST_F(InputTest, IsBindingActiveWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "press_q",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x51)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "hold_w",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{keyboard_key(0x57)}, {}}},
                                                    .on_state_change = [](bool) {}});
    (void)mgr.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    // No keys pressed in test environment
    EXPECT_FALSE(mgr.is_active("press_q"));
    EXPECT_FALSE(mgr.is_active("hold_w"));
    EXPECT_FALSE(mgr.is_active("nonexistent"));

    mgr.shutdown();
}

TEST_F(InputTest, IsBindingActiveAfterShutdown)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{
        .name = "test", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});
    (void)mgr.start();
    mgr.shutdown();

    EXPECT_FALSE(mgr.is_active("test"));
}

TEST_F(InputTest, ModifierBindingsAppendLiveWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "before",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    (void)input::register_combo(input::ComboBinding{.name = "after",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {keyboard_key(0x11)}}},
                                                    .on_press = []() {}});
    EXPECT_EQ(mgr.binding_count(), 2u);

    (void)input::register_combo(input::ComboBinding{.name = "after_hold",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{keyboard_key(0x43)}, {keyboard_key(0x10)}}},
                                                    .on_state_change = [](bool) {}});
    EXPECT_EQ(mgr.binding_count(), 3u);

    mgr.shutdown();
}

// Input facade: Gamepad

TEST_F(InputTest, RegisterGamepadBinding)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "gamepad_a",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                    .on_press = []() {}});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterGamepadWithModifier)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{.name = "lb_a",
                            .trigger = input::Trigger::Press,
                            .combos = {{{gamepad_button(GamepadCode::A)}, {gamepad_button(GamepadCode::LeftBumper)}}},
                            .on_press = []() {}});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, SetGamepadIndex)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "test",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start(input::Input::Settings{.gamepad_index = 1});

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, SetTriggerThreshold)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "lt",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{gamepad_button(GamepadCode::LeftTrigger)}, {}}},
                                                    .on_state_change = [](bool) {}});
    (void)mgr.start(input::Input::Settings{.trigger_threshold = 100});

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, MixedKeyboardAndGamepadBindings)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "kb_toggle",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x72)}, {keyboard_key(0x11)}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(
        input::ComboBinding{.name = "gp_toggle",
                            .trigger = input::Trigger::Press,
                            .combos = {{{gamepad_button(GamepadCode::A)}, {gamepad_button(GamepadCode::LeftBumper)}}},
                            .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "mouse_hold",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{mouse_button(0x05)}, {}}},
                                                    .on_state_change = [](bool) {}});

    EXPECT_EQ(mgr.binding_count(), 3u);

    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

// Input facade: KeyComboList overloads

TEST_F(InputTest, RegisterPressFromKeyComboList)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos = {
        {.keys = {keyboard_key(0x72)}, .modifiers = {}},
        {.keys = {gamepad_button(GamepadCode::A)}, .modifiers = {gamepad_button(GamepadCode::LeftBumper)}}};

    (void)input::register_combo(
        input::ComboBinding{.name = "toggle", .trigger = input::Trigger::Press, .combos = combos, .on_press = []() {}});

    EXPECT_EQ(mgr.binding_count(), 2u);
}

TEST_F(InputTest, RegisterHoldFromKeyComboList)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos = {{.keys = {keyboard_key(0x10)}, .modifiers = {}},
                                  {.keys = {gamepad_button(GamepadCode::LeftTrigger)}, .modifiers = {}}};

    (void)input::register_combo(input::ComboBinding{
        .name = "hold_action", .trigger = input::Trigger::Hold, .combos = combos, .on_state_change = [](bool) {}});

    EXPECT_EQ(mgr.binding_count(), 2u);
}

TEST_F(InputTest, RegisterPressFromEmptyKeyComboListReservesName)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos;

    (void)input::register_combo(
        input::ComboBinding{.name = "empty", .trigger = input::Trigger::Press, .combos = combos, .on_press = []() {}});

    // Empty combos still reserve the binding name so a subsequent rebind can attach a real combo list.
    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterHoldFromEmptyKeyComboListReservesName)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos;

    (void)input::register_combo(input::ComboBinding{
        .name = "empty", .trigger = input::Trigger::Hold, .combos = combos, .on_state_change = [](bool) {}});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterPressFromSingleCombo)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos = {{.keys = {keyboard_key(0x72)}, .modifiers = {keyboard_key(0x11)}}};

    (void)input::register_combo(
        input::ComboBinding{.name = "single", .trigger = input::Trigger::Press, .combos = combos, .on_press = []() {}});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, KeyComboListBindingsShareName)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos = {{.keys = {keyboard_key(0x72)}, .modifiers = {}},
                                  {.keys = {keyboard_key(0x73)}, .modifiers = {}}};

    (void)input::register_combo(input::ComboBinding{
        .name = "shared_name", .trigger = input::Trigger::Press, .combos = combos, .on_press = []() {}});
    (void)mgr.start();

    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 2u);

    // is_active queries by shared name (OR logic across combos)
    EXPECT_FALSE(mgr.is_active("shared_name"));

    mgr.shutdown();
}

TEST_F(InputTest, KeyComboListMixedWithIndividualBindings)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "individual",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});

    input::KeyComboList combos = {{.keys = {keyboard_key(0x72)}, .modifiers = {}},
                                  {.keys = {keyboard_key(0x73)}, .modifiers = {}}};

    (void)input::register_combo(input::ComboBinding{
        .name = "combo_hold", .trigger = input::Trigger::Hold, .combos = combos, .on_state_change = [](bool) {}});

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputTest, KeyComboListAppendsLiveWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "before",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    input::KeyComboList combos = {{.keys = {keyboard_key(0x72)}, .modifiers = {}}};

    (void)input::register_combo(
        input::ComboBinding{.name = "after", .trigger = input::Trigger::Press, .combos = combos, .on_press = []() {}});
    EXPECT_EQ(mgr.binding_count(), 2u);

    (void)input::register_combo(input::ComboBinding{
        .name = "after_hold", .trigger = input::Trigger::Hold, .combos = combos, .on_state_change = [](bool) {}});
    EXPECT_EQ(mgr.binding_count(), 3u);

    mgr.shutdown();
}

// InputCode: Name Resolution

TEST(InputCodeNameTest, ParseKeyboardNames)
{
    auto ctrl = parse_input_name("Ctrl");
    ASSERT_TRUE(ctrl.has_value());
    EXPECT_EQ(ctrl->source, InputSource::Keyboard);
    EXPECT_EQ(ctrl->code, 0x11);

    auto f3 = parse_input_name("F3");
    ASSERT_TRUE(f3.has_value());
    EXPECT_EQ(f3->source, InputSource::Keyboard);
    EXPECT_EQ(f3->code, 0x72);

    auto a = parse_input_name("A");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->source, InputSource::Keyboard);
    EXPECT_EQ(a->code, 0x41);
}

TEST(InputCodeNameTest, ParseMouseNames)
{
    auto m4 = parse_input_name("Mouse4");
    ASSERT_TRUE(m4.has_value());
    EXPECT_EQ(m4->source, InputSource::Mouse);
    EXPECT_EQ(m4->code, 0x05);

    auto m1 = parse_input_name("Mouse1");
    ASSERT_TRUE(m1.has_value());
    EXPECT_EQ(m1->source, InputSource::Mouse);
    EXPECT_EQ(m1->code, 0x01);
}

TEST(InputCodeNameTest, ParseGamepadNames)
{
    auto ga = parse_input_name("Gamepad_A");
    ASSERT_TRUE(ga.has_value());
    EXPECT_EQ(ga->source, InputSource::Gamepad);
    EXPECT_EQ(ga->code, GamepadCode::A);

    auto lb = parse_input_name("Gamepad_LB");
    ASSERT_TRUE(lb.has_value());
    EXPECT_EQ(lb->source, InputSource::Gamepad);
    EXPECT_EQ(lb->code, GamepadCode::LeftBumper);

    auto lt = parse_input_name("Gamepad_LT");
    ASSERT_TRUE(lt.has_value());
    EXPECT_EQ(lt->source, InputSource::Gamepad);
    EXPECT_EQ(lt->code, GamepadCode::LeftTrigger);
}

TEST(InputCodeNameTest, CaseInsensitive)
{
    auto ctrl = parse_input_name("ctrl");
    ASSERT_TRUE(ctrl.has_value());
    EXPECT_EQ(*ctrl, keyboard_key(0x11));

    auto gpa = parse_input_name("gamepad_a");
    ASSERT_TRUE(gpa.has_value());
    EXPECT_EQ(*gpa, gamepad_button(GamepadCode::A));
}

TEST(InputCodeNameTest, UnknownNameReturnsNullopt)
{
    EXPECT_FALSE(parse_input_name("InvalidKey").has_value());
    EXPECT_FALSE(parse_input_name("").has_value());
    EXPECT_FALSE(parse_input_name("Gamepad_Z").has_value());
}

TEST(InputCodeNameTest, ReverseNameLookup)
{
    EXPECT_EQ(input_code_to_name(keyboard_key(0x11)), "Ctrl");
    EXPECT_EQ(input_code_to_name(mouse_button(0x05)), "Mouse4");
    EXPECT_EQ(input_code_to_name(gamepad_button(GamepadCode::A)), "Gamepad_A");
    EXPECT_TRUE(input_code_to_name(keyboard_key(0xFF)).empty());
}

TEST(InputCodeNameTest, FormatInputCode)
{
    EXPECT_EQ(format_input_code(keyboard_key(0x11)), "Ctrl");
    EXPECT_EQ(format_input_code(keyboard_key(0x72)), "F3");
    EXPECT_EQ(format_input_code(mouse_button(0x05)), "Mouse4");
    EXPECT_EQ(format_input_code(gamepad_button(GamepadCode::A)), "Gamepad_A");
    // Unknown code falls back to hex
    EXPECT_EQ(format_input_code(keyboard_key(0xFF)), "0xFF");
}

// Thumbstick axis codes

TEST(InputCodeNameTest, ParseThumbstickNames)
{
    auto lsu = parse_input_name("Gamepad_LSUp");
    ASSERT_TRUE(lsu.has_value());
    EXPECT_EQ(lsu->source, InputSource::Gamepad);
    EXPECT_EQ(lsu->code, GamepadCode::LeftStickUp);

    auto lsd = parse_input_name("Gamepad_LSDown");
    ASSERT_TRUE(lsd.has_value());
    EXPECT_EQ(lsd->code, GamepadCode::LeftStickDown);

    auto lsl = parse_input_name("Gamepad_LSLeft");
    ASSERT_TRUE(lsl.has_value());
    EXPECT_EQ(lsl->code, GamepadCode::LeftStickLeft);

    auto lsr = parse_input_name("Gamepad_LSRight");
    ASSERT_TRUE(lsr.has_value());
    EXPECT_EQ(lsr->code, GamepadCode::LeftStickRight);

    auto rsu = parse_input_name("Gamepad_RSUp");
    ASSERT_TRUE(rsu.has_value());
    EXPECT_EQ(rsu->code, GamepadCode::RightStickUp);

    auto rsd = parse_input_name("Gamepad_RSDown");
    ASSERT_TRUE(rsd.has_value());
    EXPECT_EQ(rsd->code, GamepadCode::RightStickDown);

    auto rsl = parse_input_name("Gamepad_RSLeft");
    ASSERT_TRUE(rsl.has_value());
    EXPECT_EQ(rsl->code, GamepadCode::RightStickLeft);

    auto rsr = parse_input_name("Gamepad_RSRight");
    ASSERT_TRUE(rsr.has_value());
    EXPECT_EQ(rsr->code, GamepadCode::RightStickRight);
}

TEST(InputCodeNameTest, ThumbstickCaseInsensitive)
{
    auto code = parse_input_name("gamepad_lsup");
    ASSERT_TRUE(code.has_value());
    EXPECT_EQ(*code, gamepad_button(GamepadCode::LeftStickUp));
}

TEST(InputCodeNameTest, ThumbstickReverseNameLookup)
{
    EXPECT_EQ(input_code_to_name(gamepad_button(GamepadCode::LeftStickUp)), "Gamepad_LSUp");
    EXPECT_EQ(input_code_to_name(gamepad_button(GamepadCode::RightStickRight)), "Gamepad_RSRight");
}

TEST(InputCodeNameTest, FormatThumbstickCode)
{
    EXPECT_EQ(format_input_code(gamepad_button(GamepadCode::LeftStickUp)), "Gamepad_LSUp");
    EXPECT_EQ(format_input_code(gamepad_button(GamepadCode::RightStickDown)), "Gamepad_RSDown");
}

TEST_F(InputPollerTest, ThumbstickBindingConstruction)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "stick_test";
    binding.keys = {gamepad_button(GamepadCode::LeftStickUp)};
    binding.trigger = input::Trigger::Hold;
    binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings));

    EXPECT_EQ(poller.binding_count(), 1u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, ThumbstickWithCustomThreshold)
{
    std::vector<detail::InputBinding> bindings;

    detail::InputBinding binding;
    binding.name = "stick_custom";
    binding.keys = {gamepad_button(GamepadCode::RightStickLeft)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    detail::InputPoller poller(std::move(bindings), input::DEFAULT_POLL_INTERVAL, true, 0,
                               GamepadCode::TriggerThreshold, 16000);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());
    EXPECT_FALSE(poller.is_binding_active("stick_custom"));

    poller.shutdown();
}

TEST_F(InputTest, SetStickThreshold)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "ls_up",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{gamepad_button(GamepadCode::LeftStickUp)}, {}}},
                                                    .on_state_change = [](bool) {}});
    (void)mgr.start(input::Input::Settings{.stick_threshold = 12000});

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, ThumbstickAndButtonMixed)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(input::ComboBinding{.name = "gp_a",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "ls_up",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{gamepad_button(GamepadCode::LeftStickUp)}, {}}},
                                                    .on_state_change = [](bool) {}});
    (void)input::register_combo(input::ComboBinding{
        .name = "rs_right",
        .trigger = input::Trigger::Press,
        .combos = {{{gamepad_button(GamepadCode::RightStickRight)}, {gamepad_button(GamepadCode::LeftBumper)}}},
        .on_press = []() {}});

    EXPECT_EQ(mgr.binding_count(), 3u);

    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST(InputStringTest, TriggerToString_IsNoexcept)
{
    static_assert(noexcept(input::to_string(input::Trigger::Press)));
    static_assert(noexcept(input::to_string(input::Trigger::Hold)));
}

TEST(InputStringTest, InputSourceToString_IsNoexcept)
{
    static_assert(noexcept(input_source_to_string(InputSource::Keyboard)));
    static_assert(noexcept(input_source_to_string(InputSource::Gamepad)));
}

TEST(InputReshapeContract, MutatorsAreNoexcept)
{
    using KCL = input::KeyComboList;
    // These reshape APIs are reachable from loader-lock teardown and allocate internally. They must remain noexcept and
    // genuinely no-throw (fail-closed on out-of-memory), so removing noexcept here is a regression that this guard
    // catches at compile time. declval keeps every expression unevaluated.
    static_assert(
        noexcept(std::declval<input::Input &>().rebind(std::declval<std::string_view>(), std::declval<KCL>())),
        "Input::rebind must stay noexcept (fail-closed)");
    static_assert(
        noexcept(std::declval<input::Input &>().remove_bindings_by_name(std::declval<std::string_view>(), true)),
        "Input::remove_bindings_by_name must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<input::Input &>().clear_bindings(true)),
                  "Input::clear_bindings must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<input::Input &>().set_consume(std::declval<std::string_view>(), true)),
                  "Input::set_consume must stay noexcept (fail-closed)");

    static_assert(noexcept(std::declval<detail::InputPoller &>().update_combos(std::declval<std::string_view>(),
                                                                               std::declval<const KCL &>())),
                  "InputPoller::update_combos must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<detail::InputPoller &>().add_binding(std::declval<detail::InputBinding>())),
                  "InputPoller::add_binding must stay noexcept (fail-closed)");
    static_assert(
        noexcept(std::declval<detail::InputPoller &>().add_bindings(std::declval<std::vector<detail::InputBinding>>())),
        "InputPoller::add_bindings must stay noexcept (fail-closed)");
    static_assert(
        noexcept(std::declval<detail::InputPoller &>().remove_bindings_by_name(std::declval<std::string_view>())),
        "InputPoller::remove_bindings_by_name must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<detail::InputPoller &>().clear_bindings()),
                  "InputPoller::clear_bindings must stay noexcept (fail-closed)");
    SUCCEED();
}

// InputCodeHash

TEST(InputCodeHashTest, DifferentCodesProduceDifferentHashes)
{
    InputCodeHash hasher;

    InputCode kb_a = keyboard_key(0x41);
    InputCode kb_b = keyboard_key(0x42);
    InputCode mouse_1 = mouse_button(0x01);
    InputCode gp_a = gamepad_button(GamepadCode::A);

    std::size_t h1 = hasher(kb_a);
    std::size_t h2 = hasher(kb_b);
    std::size_t h3 = hasher(mouse_1);
    std::size_t h4 = hasher(gp_a);

    EXPECT_NE(h1, h2);
    EXPECT_NE(h1, h3);
    EXPECT_NE(h1, h4);
    EXPECT_NE(h2, h3);
    EXPECT_NE(h2, h4);
    EXPECT_NE(h3, h4);
}

TEST(InputCodeHashTest, SameCodeProducesSameHash)
{
    InputCodeHash hasher;

    InputCode a1 = keyboard_key(0x41);
    InputCode a2 = keyboard_key(0x41);

    EXPECT_EQ(hasher(a1), hasher(a2));
}

TEST(InputCodeHashTest, UsableInUnorderedSet)
{
    std::unordered_set<InputCode, InputCodeHash> codes;

    codes.insert(keyboard_key(0x41));
    codes.insert(keyboard_key(0x42));
    codes.insert(mouse_button(0x01));
    codes.insert(gamepad_button(GamepadCode::A));
    codes.insert(keyboard_key(0x41));

    EXPECT_EQ(codes.size(), 4u);
    EXPECT_EQ(codes.count(keyboard_key(0x41)), 1u);
    EXPECT_EQ(codes.count(keyboard_key(0x42)), 1u);
    EXPECT_EQ(codes.count(mouse_button(0x01)), 1u);
    EXPECT_EQ(codes.count(gamepad_button(GamepadCode::A)), 1u);
    EXPECT_NE(codes.find(keyboard_key(0x41)), codes.end());
    EXPECT_EQ(codes.find(keyboard_key(0x99)), codes.end());
}

TEST(InputCodeNameTest, FormatInputCode_UnknownMouseCode_EmitsSourceTaggedHex)
{
    // An off-table non-keyboard code carries its device source in the formatted form so the source is not lost; an
    // untagged hex would parse back as Keyboard.
    InputCode unknown_mouse = mouse_button(0xFE);
    EXPECT_EQ(format_input_code(unknown_mouse), "Mouse:0xFE");
}

TEST(InputCodeNameTest, FormatInputCode_UnknownKeyboardCode_StaysBareHex)
{
    // Keyboard off-table codes keep the bare-hex form for backward compatibility with existing configs.
    EXPECT_EQ(format_input_code(keyboard_key(0xFF)), "0xFF");
}

TEST(InputCodeNameTest, SourceTaggedHexRoundTrip)
{
    // format_input_code and parse_input_name are inverses for off-table non-keyboard codes, so a Mouse/Gamepad/Wheel
    // code written to a config and read back keeps its source instead of decaying to Keyboard.
    for (const InputCode code : {mouse_button(0xFE), gamepad_button(0x0800), mouse_wheel(0x09)})
    {
        const std::string formatted = format_input_code(code);
        const auto parsed = parse_input_name(formatted);
        ASSERT_TRUE(parsed.has_value()) << "failed to round-trip " << formatted;
        EXPECT_EQ(*parsed, code) << "round-trip mismatch for " << formatted;
    }
}

TEST(InputCodeNameTest, KeyboardBareHexRoundTripsThroughConfigParser)
{
    // format_input_code emits bare hex for an off-table keyboard code, and parse_input_name is deliberately not its
    // inverse for that form -- a bare hex token yields nullopt so it cannot silently claim a device source. The config
    // combo parser reached through config::bind_combos is the documented reconstruction path: its untagged-hex
    // fallback defaults to the Keyboard source, closing the round-trip without ambiguity.
    const InputCode original = keyboard_key(0xFF);
    const std::string formatted = format_input_code(original);
    ASSERT_EQ(formatted, "0xFF");
    EXPECT_FALSE(parse_input_name(formatted).has_value()) << "parse_input_name must not reconstruct a bare hex token";

    // bind_combos parses its default value immediately and delivers the combo list to the setter, so no INI file is
    // needed to exercise the reconstruction path end to end.
    input::KeyComboList captured;
    bool fired = false;
    config::bind_combos(
        "RoundTrip", "Key", "Round Trip Key",
        [&](const input::KeyComboList &combos)
        {
            captured = combos;
            fired = true;
        },
        formatted);
    config::clear(); // drop the registration so its setter does not fire against later config tests

    ASSERT_TRUE(fired);
    ASSERT_EQ(captured.size(), 1u);
    ASSERT_EQ(captured[0].keys.size(), 1u);
    EXPECT_EQ(captured[0].keys[0], original) << "config combo parser must recover the bare-hex keyboard code";
}

TEST(InputCodeNameTest, ParseSourceTaggedHexFormats)
{
    EXPECT_EQ(parse_input_name("Mouse:0xFE"), mouse_button(0xFE));
    EXPECT_EQ(parse_input_name("Gamepad:0x800"), gamepad_button(0x800));
    EXPECT_EQ(parse_input_name("MouseWheel:0x9"), mouse_wheel(0x9));
    // Tag and value are case-insensitive in the tag, and the 0x prefix is optional.
    EXPECT_EQ(parse_input_name("mouse:FE"), mouse_button(0xFE));
    // An unknown tag or a non-hex value fails closed.
    EXPECT_FALSE(parse_input_name("Bogus:0x10").has_value());
    EXPECT_FALSE(parse_input_name("Mouse:0xZZ").has_value());
    EXPECT_FALSE(parse_input_name("Mouse:").has_value());
}

TEST(InputCodeNameTest, ParseWindowsAndOemPunctuationNames)
{
    EXPECT_EQ(parse_input_name("LWin"), keyboard_key(0x5B));
    EXPECT_EQ(parse_input_name("RWin"), keyboard_key(0x5C));
    EXPECT_EQ(parse_input_name("Apps"), keyboard_key(0x5D));
    EXPECT_EQ(parse_input_name("Menu"), keyboard_key(0x5D));
    EXPECT_EQ(parse_input_name("Semicolon"), keyboard_key(0xBA));
    EXPECT_EQ(parse_input_name("Equals"), keyboard_key(0xBB));
    EXPECT_EQ(parse_input_name("Comma"), keyboard_key(0xBC));
    EXPECT_EQ(parse_input_name("Minus"), keyboard_key(0xBD));
    EXPECT_EQ(parse_input_name("Period"), keyboard_key(0xBE));
    EXPECT_EQ(parse_input_name("Slash"), keyboard_key(0xBF));
    EXPECT_EQ(parse_input_name("LBracket"), keyboard_key(0xDB));
    EXPECT_EQ(parse_input_name("Backslash"), keyboard_key(0xDC));
    EXPECT_EQ(parse_input_name("RBracket"), keyboard_key(0xDD));
    EXPECT_EQ(parse_input_name("Apostrophe"), keyboard_key(0xDE));
}

TEST(InputCodeNameTest, ParseGraveConsoleKeyAndAliases)
{
    // The backtick/grave/tilde key (VK_OEM_3) is the common console hotkey; every alias resolves to it.
    EXPECT_EQ(parse_input_name("Grave"), keyboard_key(0xC0));
    EXPECT_EQ(parse_input_name("Backtick"), keyboard_key(0xC0));
    EXPECT_EQ(parse_input_name("Tilde"), keyboard_key(0xC0));
    EXPECT_EQ(parse_input_name("grave"), keyboard_key(0xC0)); // case-insensitive
}

TEST(InputCodeNameTest, AddedNamesReverseLookupPicksCanonical)
{
    // Aliases parse but the reverse lookup yields the canonical (first-listed) name.
    EXPECT_EQ(input_code_to_name(keyboard_key(0xC0)), "Grave");
    EXPECT_EQ(input_code_to_name(keyboard_key(0x5D)), "Apps");
    EXPECT_EQ(input_code_to_name(keyboard_key(0xDE)), "Apostrophe");
    EXPECT_EQ(input_code_to_name(keyboard_key(0x5B)), "LWin");
}

TEST(InputSourceTest, UnknownSourceToString)
{
    auto unknown = static_cast<InputSource>(999);
    EXPECT_EQ(input_source_to_string(unknown), "Unknown");
}

TEST(TriggerTest, UnknownTriggerToString)
{
    auto unknown = static_cast<input::Trigger>(999);
    EXPECT_EQ(input::to_string(unknown), "Unknown");
}

TEST(InputUpdateCombos, UnknownNameFailsClosed)
{
    auto &im = input::Input::instance();
    im.shutdown();
    input::KeyComboList combos;
    combos.push_back({{keyboard_key(0x41)}, {}});
    const auto result = im.rebind("does-not-exist", combos);
    ASSERT_FALSE(result.has_value()) << "rebind of an unregistered name must fail closed";
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    EXPECT_EQ(category(result.error().code), ErrorCategory::General)
        << "the rebind not-found code must classify as General, not a Scan-domain leak";
}

TEST(InputUpdateCombos, UpdatesPendingBindingBeforeStart)
{
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    (void)input::register_combo(input::ComboBinding{
        .name = "update-pending", .trigger = input::Trigger::Press, .combos = initial, .on_press = []() {}});
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x42)}, {}}); // 'B'
    (void)im.rebind("update-pending", replacement);

    // Still 1 binding after replacement; cardinality preserved.
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

TEST(InputUpdateCombos, CardinalityCanGrow)
{
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    (void)input::register_combo(input::ComboBinding{
        .name = "update-grow", .trigger = input::Trigger::Press, .combos = initial, .on_press = []() {}});

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x42)}, {}});
    replacement.push_back({{keyboard_key(0x43)}, {}});
    (void)im.rebind("update-grow", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));
    im.shutdown();
}

TEST(InputUpdateCombos, CardinalityCanShrink)
{
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    initial.push_back({{keyboard_key(0x42)}, {}});
    initial.push_back({{keyboard_key(0x43)}, {}});
    (void)input::register_combo(input::ComboBinding{
        .name = "update-shrink", .trigger = input::Trigger::Press, .combos = initial, .on_press = []() {}});

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x44)}, {}});
    (void)im.rebind("update-shrink", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

TEST(InputUpdateCombos, EmptyReplacementUnbindsAndPreservesName)
{
    // Empty replacement is the explicit-unbound state. The binding name must remain addressable so a follow-up
    // non-empty update can rebind it; the entry count collapses to a single inert sentinel.
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    (void)input::register_combo(input::ComboBinding{
        .name = "update-empty-clear", .trigger = input::Trigger::Press, .combos = initial, .on_press = []() {}});
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    input::KeyComboList replacement;
    (void)im.rebind("update-empty-clear", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_FALSE(im.is_active("update-empty-clear"));

    // Rebind the same name with a real combo; the sentinel must accept it.
    input::KeyComboList rebind;
    rebind.push_back({{keyboard_key(0x42)}, {}});
    (void)im.rebind("update-empty-clear", rebind);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

TEST(InputUpdateCombos, UpdatesRunningPollerBinding)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    (void)input::register_combo(input::ComboBinding{
        .name = "update-running", .trigger = input::Trigger::Press, .combos = initial, .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(5)});

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x5A)}, {}}); // 'Z'
    (void)im.rebind("update-running", replacement);

    // Give the poller a cycle to pick up the swap, then tear down.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_TRUE(im.is_running());
    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputUpdateCombos, ConcurrentUpdateWhilePollerRunning)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    (void)input::register_combo(input::ComboBinding{
        .name = "update-stress", .trigger = input::Trigger::Press, .combos = initial, .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(1)});

    std::atomic<bool> stop{false};
    constexpr int ITERATIONS = 1000;

    std::thread writer(
        [&im, &stop]()
        {
            for (int i = 0; i < ITERATIONS && !stop.load(std::memory_order_relaxed); ++i)
            {
                input::KeyComboList replacement;
                const std::uint32_t key_code = (i % 2 == 0) ? 0x41u : 0x5Au;
                replacement.push_back({{keyboard_key(key_code)}, {}});
                (void)im.rebind("update-stress", replacement);
            }
        });

    writer.join();
    stop.store(true, std::memory_order_relaxed);

    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
    SUCCEED();
}

TEST(InputUpdateCombos, ConcurrentQueriesAndCardinalityUpdatesWhilePollerRunning)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    (void)input::register_combo(input::ComboBinding{
        .name = "update-query-stress", .trigger = input::Trigger::Press, .combos = initial, .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(1)});

    constexpr int READER_THREADS = 4;
    constexpr int ITERATIONS = 1000;
    std::atomic<bool> start{false};
    std::atomic<bool> stop{false};
    std::atomic<size_t> invalid_counts{0};

    std::vector<std::thread> readers;
    readers.reserve(READER_THREADS);
    for (int i = 0; i < READER_THREADS; ++i)
    {
        readers.emplace_back(
            [&im, &start, &stop, &invalid_counts]()
            {
                while (!start.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }

                while (!stop.load(std::memory_order_acquire))
                {
                    const size_t count = im.binding_count();
                    if (count < 1 || count > 2)
                    {
                        invalid_counts.fetch_add(1, std::memory_order_relaxed);
                    }
                    (void)im.is_active("update-query-stress");
                }
            });
    }

    start.store(true, std::memory_order_release);
    for (int i = 0; i < ITERATIONS; ++i)
    {
        input::KeyComboList replacement;
        switch (i % 3)
        {
        case 0:
            replacement.push_back({{keyboard_key(0x41)}, {}}); // 'A'
            break;
        case 1:
            replacement.push_back({{keyboard_key(0x5A)}, {}}); // 'Z'
            replacement.push_back({{keyboard_key(0x58)}, {}}); // 'X'
            break;
        default:
            break;
        }
        (void)im.rebind("update-query-stress", replacement);
        if ((i % 32) == 0)
        {
            std::this_thread::yield();
        }
    }

    stop.store(true, std::memory_order_release);
    for (auto &reader : readers)
    {
        reader.join();
    }

    EXPECT_EQ(invalid_counts.load(std::memory_order_relaxed), static_cast<size_t>(0));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputHotReload, RegisterPressWhilePollerRunning)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    (void)input::register_combo(input::ComboBinding{.name = "hr-pre",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    (void)input::register_combo(input::ComboBinding{.name = "hr-live",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_press = []() {}});

    // Give the poller a couple of cycles to absorb the new binding.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_TRUE(im.is_running());
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));

    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputHotReload, ClearBindingsKeepsPollerRunning)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    (void)input::register_combo(input::ComboBinding{.name = "hr-clear-1",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "hr-clear-2",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    im.clear_bindings();
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(0));
    EXPECT_TRUE(im.is_running());

    // Re-register after clear; poller continues without a restart.
    (void)input::register_combo(input::ComboBinding{.name = "hr-clear-after",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x43)}, {}}},
                                                    .on_press = []() {}});
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputHotReload, RemoveBindingByNameLive)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    (void)input::register_combo(input::ComboBinding{.name = "hr-keep",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "hr-drop",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    EXPECT_EQ(im.remove_bindings_by_name("hr-drop"), static_cast<size_t>(1));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputHotReload, EmptyComboListRegistersSentinelName)
{
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList empty_combos;
    (void)input::register_combo(input::ComboBinding{
        .name = "sentinel", .trigger = input::Trigger::Press, .combos = empty_combos, .on_press = []() {}});
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x41)}, {}});
    (void)im.rebind("sentinel", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

// Regression guard for the cardinality-rebuild release-callback path: a held hold-mode consumer whose combo
// cardinality changes via INI hot-reload
// must receive on_state_change(false) when its entry is wholesale-replaced;
// without it the consumer would latch in the held state forever. Without a way to drive GetAsyncKeyState in a test
// process, this case exercises the call flow against the no-active-hold branch and pins that the cardinality change
// still proceeds without crashing or leaking state.
TEST(InputPollerHoldRebuild, CardinalityChangeFiresReleaseForHeldEntries)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    auto release_count = std::make_shared<std::atomic<int>>(0);

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    initial.push_back({{keyboard_key(0x42)}, {}});
    (void)input::register_combo(input::ComboBinding{.name = "rebuild-hold",
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = initial,
                                                    .on_state_change = [release_count](bool pressed) noexcept
                                                    {
                                                        if (!pressed)
                                                        {
                                                            release_count->fetch_add(1, std::memory_order_relaxed);
                                                        }
                                                    }});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x43)}, {}});
    (void)im.rebind("rebuild-hold", replacement);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
}

// Surviving entries' atomic state must carry forward across add_binding so a subsequent add_binding does not flicker
// held bindings through one inactive tick. Verifies the binding count and lookup behaviour stay consistent across the
// rebuild.
TEST(InputPollerStatePreservation, AddBindingPreservesSurvivingState)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    (void)input::register_combo(input::ComboBinding{.name = "survive-1",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "survive-2",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    (void)input::register_combo(input::ComboBinding{.name = "survive-3",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x43)}, {}}},
                                                    .on_press = []() {}});
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(3));
    EXPECT_FALSE(im.is_active("survive-1"));
    EXPECT_FALSE(im.is_active("survive-2"));
    EXPECT_FALSE(im.is_active("survive-3"));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
}

// KeyStateCache: per-cycle keyboard memoization

TEST(KeyStateCacheTest, ProbesEachDistinctVkOncePerCycle)
{
    detail::KeyStateCache cache;
    int probe_calls = 0;
    // 'A' reads down, every other VK reads up.
    auto probe = [&](int vk) noexcept
    {
        ++probe_calls;
        return vk == 0x41;
    };

    // Repeated reads of one VK within a cycle issue a single probe.
    EXPECT_TRUE(cache.pressed(0x41, probe));
    EXPECT_TRUE(cache.pressed(0x41, probe));
    EXPECT_TRUE(cache.pressed(0x41, probe));
    EXPECT_EQ(probe_calls, 1);

    // A distinct VK probes exactly once more.
    EXPECT_FALSE(cache.pressed(0x42, probe));
    EXPECT_FALSE(cache.pressed(0x42, probe));
    EXPECT_EQ(probe_calls, 2);
}

TEST(KeyStateCacheTest, ResetReArmsForNextCycle)
{
    detail::KeyStateCache cache;
    int probe_calls = 0;
    auto probe = [&](int) noexcept
    {
        ++probe_calls;
        return true;
    };

    EXPECT_TRUE(cache.pressed(0x10, probe));
    EXPECT_EQ(probe_calls, 1);

    cache.reset();
    EXPECT_TRUE(cache.pressed(0x10, probe));
    EXPECT_EQ(probe_calls, 2);
}

TEST(KeyStateCacheTest, CachesUpStateWithoutReProbing)
{
    // The tri-state must distinguish "probed up" from "not yet probed" so a released key is not re-probed mid-cycle.
    detail::KeyStateCache cache;
    int probe_calls = 0;
    auto probe = [&](int) noexcept
    {
        ++probe_calls;
        return false;
    };

    EXPECT_FALSE(cache.pressed(0x10, probe));
    EXPECT_FALSE(cache.pressed(0x10, probe));
    EXPECT_EQ(probe_calls, 1);
}

TEST(KeyStateCacheTest, OutOfRangeVkReadsAsNotPressedWithoutProbing)
{
    detail::KeyStateCache cache;
    int probe_calls = 0;
    auto probe = [&](int) noexcept
    {
        ++probe_calls;
        return true;
    };

    EXPECT_FALSE(cache.pressed(-1, probe));
    EXPECT_FALSE(cache.pressed(256, probe));
    EXPECT_FALSE(cache.pressed(99999, probe));
    EXPECT_EQ(probe_calls, 0);
}

// The poll loop re-reserves its deferred-callback staging vector to the live binding count each cycle and stages it
// under a catch, so growing the binding set far past the startup reserve while the poll thread is running can neither
// reallocate-then-throw out of the jthread body nor leave the thread dead. Drive a large live growth and assert the
// poller stays alive with the correct count.
TEST(InputPollerPollLoopSafety, BindingGrowthPastStartupReserveKeepsPollThreadAlive)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    (void)input::register_combo(input::ComboBinding{.name = "grow-seed",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(1)});

    constexpr int extra = 300;
    for (int i = 0; i < extra; ++i)
    {
        (void)input::register_combo(input::ComboBinding{.name = "grow-" + std::to_string(i),
                                                        .trigger = input::Trigger::Press,
                                                        .combos = {{{keyboard_key(0x41 + (i % 20))}, {}}},
                                                        .on_press = []() {}});
    }

    // Let the poll thread run many cycles against the grown binding set.
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    EXPECT_TRUE(im.is_running());
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(extra + 1));

    im.shutdown();
    im.set_require_focus(true);
}

// remove_bindings_by_name must carry surviving entries' atomic states forward; is_active(name) must stay
// consistent across the reshape with no torn reads against bindings_.size().
TEST(InputPollerStatePreservation, RemovePreservesSurvivingState)
{
    auto &im = input::Input::instance();
    im.shutdown();
    im.set_require_focus(false);

    (void)input::register_combo(input::ComboBinding{.name = "keep-a",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{
        .name = "drop", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x42)}, {}}}, .on_press = []() {}});
    (void)input::register_combo(input::ComboBinding{.name = "keep-b",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x43)}, {}}},
                                                    .on_press = []() {}});
    (void)im.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});

    EXPECT_EQ(im.remove_bindings_by_name("drop"), static_cast<size_t>(1));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));
    EXPECT_FALSE(im.is_active("drop"));
    EXPECT_FALSE(im.is_active("keep-a"));
    EXPECT_FALSE(im.is_active("keep-b"));

    im.shutdown();
    im.set_require_focus(true);
}

// BindingToken: generation-checked binding handles

namespace
{
    detail::InputBinding make_token_test_binding(std::string name, InputCode key)
    {
        detail::InputBinding binding;
        binding.name = std::move(name);
        binding.keys = {key};
        binding.trigger = input::Trigger::Press;
        binding.on_press = []() {};
        return binding;
    }
} // namespace

TEST_F(InputPollerTest, BindingTokenDefaultIsInvalid)
{
    input::BindingToken token;
    EXPECT_FALSE(token.valid());

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(make_token_test_binding("a", keyboard_key(0x41)));
    detail::InputPoller poller(std::move(bindings));

    // A default token is inactive and never current against any poller.
    EXPECT_FALSE(poller.is_binding_active(token));
    EXPECT_FALSE(poller.binding_token_current(token));
}

TEST_F(InputPollerTest, BindingTokenUnknownNameIsInvalid)
{
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(make_token_test_binding("known", keyboard_key(0x41)));
    detail::InputPoller poller(std::move(bindings));

    const input::BindingToken token = poller.acquire_binding_token("missing");
    EXPECT_FALSE(token.valid());
    EXPECT_FALSE(poller.binding_token_current(token));
    EXPECT_FALSE(poller.is_binding_active(token));
}

TEST_F(InputPollerTest, BindingTokenResolvesKnownNameAndMatchesNameQuery)
{
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(make_token_test_binding("zoom", keyboard_key(0x41)));
    detail::InputPoller poller(std::move(bindings));

    const input::BindingToken token = poller.acquire_binding_token("zoom");
    EXPECT_TRUE(token.valid());
    EXPECT_TRUE(poller.binding_token_current(token));
    // No key is pressed, so both paths agree on inactive. The token path reads the same active-state slots the name
    // path does, so it tracks the name query for every state.
    EXPECT_EQ(poller.is_binding_active(token), poller.is_binding_active("zoom"));
    EXPECT_FALSE(poller.is_binding_active(token));
}

TEST_F(InputPollerTest, BindingTokenResolvesMultiComboName)
{
    // One name, two combos (OR semantics): the token caches both entry indices.
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(make_token_test_binding("multi", keyboard_key(0x41)));
    bindings.push_back(make_token_test_binding("multi", keyboard_key(0x42)));
    detail::InputPoller poller(std::move(bindings));

    const input::BindingToken token = poller.acquire_binding_token("multi");
    EXPECT_TRUE(token.valid());
    EXPECT_TRUE(poller.binding_token_current(token));
    EXPECT_EQ(poller.is_binding_active(token), poller.is_binding_active("multi"));
}

TEST_F(InputPollerTest, BindingTokenStaleAfterAddBinding)
{
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(make_token_test_binding("first", keyboard_key(0x41)));
    detail::InputPoller poller(std::move(bindings));

    input::BindingToken token = poller.acquire_binding_token("first");
    ASSERT_TRUE(poller.binding_token_current(token));

    // A reshape advances the generation, so the previously current token now fails closed.
    ASSERT_TRUE(poller.add_binding(make_token_test_binding("second", keyboard_key(0x42))));
    EXPECT_FALSE(poller.binding_token_current(token));
    EXPECT_FALSE(poller.is_binding_active(token));

    // Re-acquiring recovers a current token.
    token = poller.acquire_binding_token("first");
    EXPECT_TRUE(poller.binding_token_current(token));
}

TEST_F(InputPollerTest, BindingTokenStaleAfterRemoveOfDifferentBinding)
{
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(make_token_test_binding("survivor", keyboard_key(0x41)));
    bindings.push_back(make_token_test_binding("victim", keyboard_key(0x42)));
    detail::InputPoller poller(std::move(bindings));

    const input::BindingToken token = poller.acquire_binding_token("survivor");
    ASSERT_TRUE(poller.binding_token_current(token));

    // Removing an unrelated binding still shifts indices, so the conservative generation bump invalidates every
    // outstanding token, including the survivor's. The token fails closed rather than reading a shifted slot.
    EXPECT_EQ(poller.remove_bindings_by_name("victim"), 1u);
    EXPECT_FALSE(poller.binding_token_current(token));
    EXPECT_FALSE(poller.is_binding_active(token));
}

TEST_F(InputPollerTest, BindingTokenStaleAfterClear)
{
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(make_token_test_binding("only", keyboard_key(0x41)));
    detail::InputPoller poller(std::move(bindings));

    const input::BindingToken token = poller.acquire_binding_token("only");
    ASSERT_TRUE(poller.binding_token_current(token));

    poller.clear_bindings();
    EXPECT_FALSE(poller.binding_token_current(token));
    EXPECT_FALSE(poller.is_binding_active(token));

    // The name is gone, so a re-acquire is invalid.
    EXPECT_FALSE(poller.acquire_binding_token("only").valid());
}

TEST_F(InputPollerTest, BindingTokenStaleAfterUpdateCombos)
{
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(make_token_test_binding("rebind", keyboard_key(0x41)));
    detail::InputPoller poller(std::move(bindings));

    const input::BindingToken token = poller.acquire_binding_token("rebind");
    ASSERT_TRUE(poller.binding_token_current(token));

    // A cardinality-changing combo update rebuilds the binding array under the same name.
    input::KeyComboList combos = {{.keys = {keyboard_key(0x42)}, .modifiers = {}},
                                  {.keys = {keyboard_key(0x43)}, .modifiers = {}}};
    EXPECT_TRUE(poller.update_combos("rebind", combos));
    EXPECT_FALSE(poller.binding_token_current(token));

    // The name still exists, so a fresh token resolves and is current.
    EXPECT_TRUE(poller.acquire_binding_token("rebind").valid());
}

TEST_F(InputTest, BindingTokenInvalidBeforeStart)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(input::ComboBinding{.name = "pending",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});

    // No active poller before start(): a token cannot resolve.
    const input::BindingToken token = mgr.acquire_token("pending");
    EXPECT_FALSE(token.valid());
    EXPECT_FALSE(mgr.token_current(token));
    EXPECT_FALSE(mgr.is_active(token));
}

TEST_F(InputTest, BindingTokenResolvesAfterStart)
{
    auto &mgr = input::Input::instance();
    mgr.set_require_focus(false);
    (void)input::register_combo(input::ComboBinding{.name = "hotkey",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});

    const input::BindingToken token = mgr.acquire_token("hotkey");
    EXPECT_TRUE(token.valid());
    EXPECT_TRUE(mgr.token_current(token));
    EXPECT_EQ(mgr.is_active(token), mgr.is_active("hotkey"));

    mgr.set_require_focus(true);
}

TEST_F(InputTest, BindingTokenStaleAfterLiveRegister)
{
    auto &mgr = input::Input::instance();
    mgr.set_require_focus(false);
    (void)input::register_combo(input::ComboBinding{
        .name = "a", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x41)}, {}}}, .on_press = []() {}});
    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});

    const input::BindingToken token = mgr.acquire_token("a");
    ASSERT_TRUE(mgr.token_current(token));

    // A live registration reshapes the running poller, invalidating the token.
    (void)input::register_combo(input::ComboBinding{
        .name = "b", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x42)}, {}}}, .on_press = []() {}});
    EXPECT_FALSE(mgr.token_current(token));
    EXPECT_FALSE(mgr.is_active(token));

    mgr.set_require_focus(true);
}

TEST_F(InputTest, BindingTokenStaleAfterConsumeToggle)
{
    auto &mgr = input::Input::instance();
    mgr.set_require_focus(false);
    (void)input::register_combo(input::ComboBinding{.name = "consume_test",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});

    const input::BindingToken old_token = mgr.acquire_token("consume_test");
    ASSERT_TRUE(old_token.valid());
    ASSERT_TRUE(mgr.token_current(old_token));

    mgr.set_consume("consume_test", true);
    EXPECT_FALSE(mgr.token_current(old_token));
    EXPECT_FALSE(mgr.is_active(old_token));

    mgr.set_consume("consume_test", false);
    EXPECT_FALSE(mgr.token_current(old_token));
    EXPECT_FALSE(mgr.is_active(old_token));

    const input::BindingToken fresh_token = mgr.acquire_token("consume_test");
    EXPECT_TRUE(fresh_token.valid());
    EXPECT_TRUE(mgr.token_current(fresh_token));

    mgr.set_require_focus(true);
}

TEST_F(InputTest, BindingTokenFromPriorPollerNeverAliasesNewPoller)
{
    auto &mgr = input::Input::instance();
    mgr.set_require_focus(false);
    (void)input::register_combo(input::ComboBinding{.name = "persist",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});

    const input::BindingToken old_token = mgr.acquire_token("persist");
    ASSERT_TRUE(old_token.valid());
    ASSERT_TRUE(mgr.token_current(old_token));

    // Replace the poller. The process-wide generation counter never reuses a value, so the old token's generation
    // cannot match the freshly built poller even though the same name is registered.
    mgr.shutdown();
    (void)input::register_combo(input::ComboBinding{.name = "persist",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {}});
    (void)mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds(2)});

    EXPECT_FALSE(mgr.token_current(old_token));
    EXPECT_FALSE(mgr.is_active(old_token));

    // A fresh token against the new poller is current.
    const input::BindingToken new_token = mgr.acquire_token("persist");
    EXPECT_TRUE(new_token.valid());
    EXPECT_TRUE(mgr.token_current(new_token));

    mgr.set_require_focus(true);
}

// Binding teardown gates (input_binding_gate.hpp)

// A multi-combo Hold shares one HoldGate across all its exploded engine entries. The gate reference-counts the active
// entries so overlapping combos forward only the aggregate 0->1 and 1->0 transitions: no duplicate raise while a
// second combo comes down, and no premature release while any combo is still held.
TEST(BindingGateTest, HoldGateMultiComboForwardsOnlyAggregateEdges)
{
    std::vector<bool> seq;
    detail::HoldGate gate;
    gate.on_state_change = [&](bool active) { seq.push_back(active); };

    gate.deliver(true);  // combo A pressed           -> 0->1: one held edge
    gate.deliver(true);  // combo B pressed (A held)  -> 1->2: no forward (no duplicate raise)
    gate.deliver(false); // combo A released (B held) -> 2->1: no forward (still held via B)
    ASSERT_EQ(seq.size(), 1u);
    EXPECT_TRUE(seq[0]);

    gate.deliver(false); // combo B released          -> 1->0: one released edge
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_FALSE(seq[1]);
}

// Control: a single-combo Hold still delivers exactly one true then one false, unchanged by the refcount.
TEST(BindingGateTest, HoldGateSingleComboDeliversBalancedPair)
{
    std::vector<bool> seq;
    detail::HoldGate gate;
    gate.on_state_change = [&](bool active) { seq.push_back(active); };
    gate.deliver(true);
    gate.deliver(false);
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_TRUE(seq[0]);
    EXPECT_FALSE(seq[1]);
}

// A false edge while the active count is already zero (a re-balanced or duplicate release) is swallowed, keeping the
// counter floored so it can never go negative and invert a later 0->1 raise.
TEST(BindingGateTest, HoldGateSurplusFalseIsSwallowed)
{
    std::vector<bool> seq;
    detail::HoldGate gate;
    gate.on_state_change = [&](bool active) { seq.push_back(active); };
    gate.deliver(false); // no outstanding true -> swallowed
    EXPECT_TRUE(seq.empty());
    gate.deliver(true);  // 0->1 still raises correctly
    gate.deliver(false); // 1->0
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_TRUE(seq[0]);
    EXPECT_FALSE(seq[1]);
}

// A guard release on a still-held multi-combo hold synthesizes exactly one balancing false even though two entries
// are physically down, and the released latch swallows every later edge so no stale true/false can land.
TEST(BindingGateTest, HoldGateReleaseWhileMultiComboHeldSynthesizesOneFalse)
{
    std::vector<bool> seq;
    detail::HoldGate gate;
    gate.on_state_change = [&](bool active) { seq.push_back(active); };
    gate.deliver(true); // A
    gate.deliver(true); // B (no forward)
    ASSERT_EQ(seq.size(), 1u);
    gate.release(); // still held via both entries -> one balancing false
    ASSERT_EQ(seq.size(), 2u);
    EXPECT_FALSE(seq[1]);
    gate.deliver(false); // post-release edges swallowed
    gate.deliver(true);
    EXPECT_EQ(seq.size(), 2u);
}

// PressGate::release() runs down any in-flight on_press before returning, so a caller can safely destroy state the
// press callback captured the instant the guard is released. The releaser thread must not return while the callback
// is parked.
TEST(BindingGateTest, PressGateReleaseWaitsOutInFlightDelivery)
{
    detail::PressGate gate;
    std::atomic<int> calls{0};
    std::atomic<bool> in_callback{false};
    std::atomic<bool> may_finish{false};
    gate.on_press = [&]()
    {
        calls.fetch_add(1, std::memory_order_relaxed);
        in_callback.store(true, std::memory_order_release);
        while (!may_finish.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    std::thread deliverer([&]() { gate.deliver(); });
    while (!in_callback.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::atomic<bool> release_returned{false};
    std::thread releaser(
        [&]()
        {
            gate.release();
            release_returned.store(true, std::memory_order_release);
        });

    // While the callback is parked, release() must be blocked behind it.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_FALSE(release_returned.load(std::memory_order_acquire))
        << "release() must not return while on_press is still executing";

    may_finish.store(true, std::memory_order_release);
    releaser.join();
    deliverer.join();
    EXPECT_TRUE(release_returned.load(std::memory_order_acquire));
    EXPECT_EQ(calls.load(std::memory_order_relaxed), 1);

    gate.deliver(); // post-release: swallowed
    EXPECT_EQ(calls.load(std::memory_order_relaxed), 1);
}

// A press callback that releases its own gate (a one-shot binding destroying its guard) must not deadlock: the
// recursive mutex lets the self-release re-lock, and subsequent deliveries are swallowed.
TEST(BindingGateTest, PressGateSelfReleaseFromCallbackDoesNotDeadlock)
{
    detail::PressGate gate;
    int calls = 0;
    gate.on_press = [&]()
    {
        ++calls;
        gate.release(); // self-release on the delivering thread
    };
    gate.deliver(); // must return (no deadlock)
    EXPECT_EQ(calls, 1);
    gate.deliver(); // released -> swallowed
    EXPECT_EQ(calls, 1);
}

// The shared enabled flag gates PressGate delivery, matching BindingGuard::is_active() (the guard clears it on
// release).
TEST(BindingGateTest, PressGateEnabledFlagGatesDelivery)
{
    detail::PressGate gate;
    auto enabled = std::make_shared<std::atomic<bool>>(true);
    gate.enabled = enabled;
    int calls = 0;
    gate.on_press = [&]() { ++calls; };
    gate.deliver();
    EXPECT_EQ(calls, 1);
    enabled->store(false, std::memory_order_release);
    gate.deliver();
    EXPECT_EQ(calls, 1);
}

// A still-held hold torn down cross-thread invokes the balancing on_state_change(false) UNWRAPPED (unlike deliver(),
// which wraps user callbacks), so a throwing release-edge callback propagates out of release(). The gate must stay
// consistent regardless: forwarded_active is cleared before the call, so the throw cannot strand a stale true, a second
// release() is an idempotent no-op that neither re-throws nor re-fires, and later edges are swallowed. BindingGuard's
// composed teardown relies on this -- it runs the consume-suppression clear after the gate release even when that
// release throws, so a thrown balancing edge cannot leave passthrough suppression armed for the rest of the process.
TEST(BindingGateTest, HoldGateReleaseIsExceptionSafeWhenBalancingCallbackThrows)
{
    detail::HoldGate gate;
    gate.enabled = std::make_shared<std::atomic<bool>>(true);
    int falses = 0;
    gate.on_state_change = [&falses](bool active)
    {
        if (!active)
        {
            ++falses;
            throw std::runtime_error("release-edge callback");
        }
    };
    gate.deliver(true); // held: a true edge is outstanding

    EXPECT_THROW(gate.release(), std::runtime_error);
    EXPECT_EQ(falses, 1); // the balancing false was attempted exactly once

    // Consistent despite the throw: released is set and forwarded_active was cleared before the throwing call, so a
    // second release() is a no-op and later edges are swallowed.
    EXPECT_NO_THROW(gate.release());
    gate.deliver(false);
    gate.deliver(true);
    EXPECT_EQ(falses, 1);
}

// Releasing a consume binding's guard must lift its passthrough suppression. Suppression is enforced off the engine
// entry's consume flag, so the release clears it and republishes (mirroring set_consume(name, false)), which reshapes
// the binding set. The reshape -- observable as an outstanding token going stale -- is the proof the consume-clear path
// ran.
TEST_F(InputTest, ReleasingConsumeGuardRepublishesToLiftSuppression)
{
    auto &mgr = input::Input::instance();

    auto consume_guard = input::register_combo(input::ComboBinding{.name = "consume_zoom",
                                                                   .trigger = input::Trigger::Press,
                                                                   .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                                   .consume = true,
                                                                   .on_press = []() {}});
    ASSERT_TRUE(consume_guard.has_value());

    (void)input::register_combo(input::ComboBinding{.name = "anchor",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x70)}, {}}},
                                                    .on_press = []() {}});

    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("anchor");
    ASSERT_TRUE(mgr.token_current(token));

    consume_guard->release();
    EXPECT_FALSE(mgr.token_current(token))
        << "consume-release must republish the binding set (as set_consume(false) does) to lift suppression";
}

// Control: a non-consume guard release only gates its callback; it must NOT reshape the binding set.
TEST_F(InputTest, ReleasingPlainGuardDoesNotRepublish)
{
    auto &mgr = input::Input::instance();

    auto plain_guard = input::register_combo(input::ComboBinding{.name = "plain",
                                                                 .trigger = input::Trigger::Press,
                                                                 .combos = {{{keyboard_key(0x71)}, {}}},
                                                                 .on_press = []() {}});
    ASSERT_TRUE(plain_guard.has_value());

    (void)input::register_combo(input::ComboBinding{.name = "anchor",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x70)}, {}}},
                                                    .on_press = []() {}});

    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("anchor");
    ASSERT_TRUE(mgr.token_current(token));

    plain_guard->release();
    EXPECT_TRUE(mgr.token_current(token)) << "a non-consume guard release must not reshape the binding set";
}

// Companion to ReleasingConsumeGuardRepublishesToLiftSuppression for the Hold trigger: a consume HOLD binding's guard
// release must also lift its passthrough suppression. The composed release action runs the HoldGate teardown and then
// the consume clear; releasing while not held takes the no-balancing-edge path, so this pins that the consume clear
// (republish) is wired for hold bindings too, not only press.
TEST_F(InputTest, ReleasingConsumeHoldGuardRepublishesToLiftSuppression)
{
    auto &mgr = input::Input::instance();

    auto consume_guard = input::register_combo(input::ComboBinding{.name = "consume_hold_zoom",
                                                                   .trigger = input::Trigger::Hold,
                                                                   .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                                                                   .consume = true,
                                                                   .on_state_change = [](bool) {}});
    ASSERT_TRUE(consume_guard.has_value());

    (void)input::register_combo(input::ComboBinding{.name = "anchor",
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x70)}, {}}},
                                                    .on_press = []() {}});

    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("anchor");
    ASSERT_TRUE(mgr.token_current(token));

    consume_guard->release();
    EXPECT_FALSE(mgr.token_current(token))
        << "consume-hold release must republish the binding set (as set_consume(false) does) to lift suppression";
}

// A live multi-combo registration forwards every exploded combo entry; the common case commits the whole batch.
TEST_F(InputTest, RegisterComboLiveForwardsEveryComboEntry)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(input::ComboBinding{
        .name = "seed", .trigger = input::Trigger::Press, .combos = {{{keyboard_key(0x70)}, {}}}, .on_press = []() {}});
    ASSERT_TRUE(mgr.start().has_value());
    ASSERT_EQ(mgr.binding_count(), 1u);

    auto guard =
        input::register_combo(input::ComboBinding{.name = "multi",
                                                  .trigger = input::Trigger::Press,
                                                  .combos = {{{keyboard_key(0x71)}, {}}, {{keyboard_key(0x72)}, {}}},
                                                  .on_press = []() {}});
    ASSERT_TRUE(guard.has_value());
    EXPECT_EQ(mgr.binding_count(), 3u); // seed + two combo entries
}

// add_binding fails closed and reports the failure (returns false) when growing the engine's state array runs out of
// memory, so a caller can surface it instead of reporting success.
TEST_F(InputPollerTest, AddBindingReturnsFalseWhenGrowthAllocationFails)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputBinding seed;
    seed.name = "seed";
    seed.keys = {keyboard_key(0x70)};
    bindings.push_back(seed);
    detail::InputPoller poller(std::move(bindings));

    detail::InputBinding extra;
    extra.name = "extra";
    extra.keys = {keyboard_key(0x71)};

    // Force the process-default logger's one-time `new Logger()` to run BEFORE the allocator is armed. ctest runs each
    // test in its own process, so this test can be the first log() call in it; add_binding's OOM catch logs, and the
    // first-use logger construction deliberately terminates under OOM (a noexcept boundary). Warming it up here keeps
    // that construction out of the armed window so the catch's guarded log is exercised on an already-built logger.
    (void)DetourModKit::log();

    bool added_under_oom = true;
    {
        dmk_test::AllocFailScope fail(0); // fail the replacement state-array allocation
        added_under_oom = poller.add_binding(std::move(extra));
    }
    EXPECT_FALSE(added_under_oom);
    EXPECT_EQ(poller.binding_count(), 1u); // poller left exactly as it was

    detail::InputBinding extra2;
    extra2.name = "extra2";
    extra2.keys = {keyboard_key(0x72)};
    EXPECT_TRUE(poller.add_binding(std::move(extra2)));
    EXPECT_EQ(poller.binding_count(), 2u);
}

// add_bindings commits a batch atomically. If growth fails, no entry from the batch is published; this matters for
// consume bindings because suppression is driven by the entry's consume flag and cannot be neutralized by only clearing
// the guard's enabled flag.
TEST_F(InputPollerTest, AddBindingsReturnsFalseWithoutPartialBatchWhenGrowthAllocationFails)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputBinding seed;
    seed.name = "seed";
    seed.keys = {keyboard_key(0x70)};
    bindings.push_back(seed);
    detail::InputPoller poller(std::move(bindings));

    std::vector<detail::InputBinding> batch;
    batch.reserve(2);

    detail::InputBinding first;
    first.name = "consume_batch";
    first.keys = {gamepad_button(GamepadCode::A)};
    first.consume = true;
    batch.push_back(std::move(first));

    detail::InputBinding second;
    second.name = "consume_batch";
    second.keys = {gamepad_button(GamepadCode::B)};
    second.consume = true;
    batch.push_back(std::move(second));

    (void)DetourModKit::log();

    bool added_under_oom = true;
    {
        dmk_test::AllocFailScope fail(0);
        added_under_oom = poller.add_bindings(std::move(batch));
    }
    EXPECT_FALSE(added_under_oom);
    EXPECT_EQ(poller.binding_count(), 1u);

    std::vector<detail::InputBinding> retry;
    retry.reserve(2);

    detail::InputBinding retry_first;
    retry_first.name = "consume_batch";
    retry_first.keys = {gamepad_button(GamepadCode::A)};
    retry_first.consume = true;
    retry.push_back(std::move(retry_first));

    detail::InputBinding retry_second;
    retry_second.name = "consume_batch";
    retry_second.keys = {gamepad_button(GamepadCode::B)};
    retry_second.consume = true;
    retry.push_back(std::move(retry_second));

    EXPECT_TRUE(poller.add_bindings(std::move(retry)));
    EXPECT_EQ(poller.binding_count(), 3u);
}
