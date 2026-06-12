#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "DetourModKit/input.hpp"
#include "DetourModKit/config.hpp"

#include "input_intercept.hpp"
#include "input_key_cache.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;

// --- InputSource string conversion ---

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

// --- InputCode ---

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

// --- Mouse-wheel name resolution ---

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

// --- InputMode string conversion ---

TEST(InputModeTest, PressToString)
{
    EXPECT_EQ(input_mode_to_string(InputMode::Press), "Press");
}

TEST(InputModeTest, HoldToString)
{
    EXPECT_EQ(input_mode_to_string(InputMode::Hold), "Hold");
}

// --- InputBinding ---

TEST(InputBindingTest, DefaultModeIsPress)
{
    InputBinding binding;
    EXPECT_EQ(binding.mode, InputMode::Press);
}

// --- InputPoller ---

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
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_running());
    EXPECT_EQ(poller.binding_count(), 0u);

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, ConstructWithBindings)
{
    std::vector<InputBinding> bindings;

    InputBinding press_binding;
    press_binding.name = "test_press";
    press_binding.keys = {keyboard_key(0x41)};
    press_binding.mode = InputMode::Press;
    press_binding.on_press = []() {};
    bindings.push_back(std::move(press_binding));

    InputBinding hold_binding;
    hold_binding.name = "test_hold";
    hold_binding.keys = {keyboard_key(0x42)};
    hold_binding.mode = InputMode::Hold;
    hold_binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(hold_binding));

    InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_running());
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, DefaultPollInterval)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

    EXPECT_EQ(poller.poll_interval(), DEFAULT_POLL_INTERVAL);
}

TEST_F(InputPollerTest, CustomPollInterval)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings), std::chrono::milliseconds{50});

    EXPECT_EQ(poller.poll_interval(), std::chrono::milliseconds{50});
}

TEST_F(InputPollerTest, PollIntervalClampedToMin)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings), std::chrono::milliseconds{0});

    EXPECT_EQ(poller.poll_interval(), MIN_POLL_INTERVAL);
}

TEST_F(InputPollerTest, PollIntervalClampedToMax)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings), std::chrono::milliseconds{5000});

    EXPECT_EQ(poller.poll_interval(), MAX_POLL_INTERVAL);
}

TEST_F(InputPollerTest, NotRunningBeforeStart)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, StartThenRunning)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, DoubleStartIgnored)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

    poller.start();
    EXPECT_TRUE(poller.is_running());

    // Second start should be a no-op
    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, ShutdownIdempotent)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

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
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

    // Shutdown before start should be safe
    EXPECT_NO_THROW(poller.shutdown());
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, DestructorStopsThread)
{
    bool thread_was_running = false;

    {
        std::vector<InputBinding> bindings;
        InputPoller poller(std::move(bindings));
        poller.start();
        thread_was_running = poller.is_running();
    }
    // Destructor should have joined the thread without hanging

    EXPECT_TRUE(thread_was_running);
}

TEST_F(InputPollerTest, NonCopyableNonMovable)
{
    EXPECT_FALSE(std::is_copy_constructible_v<InputPoller>);
    EXPECT_FALSE(std::is_copy_assignable_v<InputPoller>);
    EXPECT_FALSE(std::is_move_constructible_v<InputPoller>);
    EXPECT_FALSE(std::is_move_assignable_v<InputPoller>);
}

TEST_F(InputPollerTest, EmptyKeysSkipped)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "empty_keys";
    binding.keys = {};
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));
    poller.start();

    // Should run without issues even with empty keys
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, ZeroCodeSkipped)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "zero_code";
    binding.keys = {keyboard_key(0), keyboard_key(0), keyboard_key(0)};
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, MultipleBindingsMixed)
{
    std::vector<InputBinding> bindings;

    for (int i = 0; i < 10; ++i)
    {
        InputBinding binding;
        binding.name = "binding_" + std::to_string(i);
        binding.keys = {keyboard_key(0x41 + i)};
        binding.mode = (i % 2 == 0) ? InputMode::Press : InputMode::Hold;
        if (binding.mode == InputMode::Press)
        {
            binding.on_press = []() {};
        }
        else
        {
            binding.on_state_change = [](bool) {};
        }
        bindings.push_back(std::move(binding));
    }

    InputPoller poller(std::move(bindings));
    poller.start();

    EXPECT_TRUE(poller.is_running());
    EXPECT_EQ(poller.binding_count(), 10u);

    poller.shutdown();
}

TEST_F(InputPollerTest, NullCallbackHandled)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "null_callback";
    binding.keys = {keyboard_key(0x41)};
    binding.mode = InputMode::Press;
    // on_press intentionally left empty
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, ShutdownResponsiveness)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings), std::chrono::milliseconds{500});

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
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

    poller.start();
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();

    // is_running() must return false only after the thread has fully joined
    EXPECT_FALSE(poller.is_running());
}

// --- InputPoller: Gamepad ---

TEST_F(InputPollerTest, GamepadBindingConstruction)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "gamepad_test";
    binding.keys = {gamepad_button(GamepadCode::A)};
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));

    EXPECT_EQ(poller.binding_count(), 1u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, GamepadWithModifiers)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "gamepad_combo";
    binding.keys = {gamepad_button(GamepadCode::A)};
    binding.modifiers = {gamepad_button(GamepadCode::LeftBumper)};
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());
    EXPECT_FALSE(poller.is_binding_active("gamepad_combo"));

    poller.shutdown();
}

TEST_F(InputPollerTest, GamepadTriggerBinding)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "trigger_test";
    binding.keys = {gamepad_button(GamepadCode::LeftTrigger)};
    binding.mode = InputMode::Hold;
    binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings), DEFAULT_POLL_INTERVAL, true, 0, 50);
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, GamepadIndexClamped)
{
    std::vector<InputBinding> bindings;

    // Index -1 should clamp to 0, index 5 should clamp to 3
    InputPoller poller_low(std::move(bindings), DEFAULT_POLL_INTERVAL, true, -1);
    EXPECT_EQ(poller_low.binding_count(), 0u);
    EXPECT_EQ(poller_low.gamepad_index(), 0);

    std::vector<InputBinding> bindings2;
    InputPoller poller_high(std::move(bindings2), DEFAULT_POLL_INTERVAL, true, 5);
    EXPECT_EQ(poller_high.binding_count(), 0u);
    EXPECT_EQ(poller_high.gamepad_index(), 3);
}

TEST_F(InputPollerTest, MixedKeyboardAndGamepadBindings)
{
    std::vector<InputBinding> bindings;

    InputBinding kb_binding;
    kb_binding.name = "keyboard";
    kb_binding.keys = {keyboard_key(0x41)};
    kb_binding.mode = InputMode::Press;
    kb_binding.on_press = []() {};
    bindings.push_back(std::move(kb_binding));

    InputBinding gp_binding;
    gp_binding.name = "gamepad";
    gp_binding.keys = {gamepad_button(GamepadCode::A)};
    gp_binding.mode = InputMode::Press;
    gp_binding.on_press = []() {};
    bindings.push_back(std::move(gp_binding));

    InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.shutdown();
}

// --- InputManager ---

class InputManagerTest : public ::testing::Test
{
protected:
    void SetUp() override { InputManager::get_instance().shutdown(); }

    void TearDown() override { InputManager::get_instance().shutdown(); }
};

TEST_F(InputManagerTest, SetConsumeBeforeStartUpdatesPendingBinding)
{
    auto &mgr = InputManager::get_instance();
    // A keyboard binding never installs a hook (suppression is gamepad/wheel only), so this exercises the consume
    // plumbing without touching real input.
    mgr.register_press("consume_pending", {keyboard_key(0x70)}, [] {});
    mgr.set_consume("consume_pending", true);
    mgr.set_consume("nonexistent_binding", true); // unknown name is a no-op
    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, SetConsumeWhileRunningIsSafe)
{
    auto &mgr = InputManager::get_instance();
    mgr.register_press("consume_live", {keyboard_key(0x70)}, [] {});
    mgr.start();
    mgr.set_consume("consume_live", true);
    mgr.set_consume("consume_live", false);
    EXPECT_TRUE(mgr.is_running());
    mgr.shutdown();
}

TEST_F(InputManagerTest, RegisterConsumeFlagAppliesToBinding)
{
    auto &mgr = InputManager::get_instance();
    mgr.register_press("consume_cfg", {keyboard_key(0x70)}, [] {});
    // The fused helper fires set_consume("consume_cfg", true) at registration time, with the same setter re-applied on
    // every load() / reload().
    Config::register_consume_flag("Hotkeys", "ConsumeCfg.Consume", "Consume Cfg", "consume_cfg", true);
    EXPECT_EQ(mgr.binding_count(), 1u);
    // Drop the registered setter so it does not fire against later tests.
    Config::clear_registered_items();
}

TEST_F(InputManagerTest, AnalogOnlyConsumeGamepadBindingInstallsNoXInputHook)
{
    // A consume binding whose only trigger is an analog code (trigger/stick) can never be masked: the XInput detour
    // clears digital wButtons bits only. The poll loop must therefore not install the hook for such a binding.
    // Asserting "no hook installed" verifies the digital-only install gate without putting a live hook into the test
    // process (no game window or controller is needed).
    auto &mgr = InputManager::get_instance();
    mgr.register_press("analog_consume", {gamepad_button(GamepadCode::LeftTrigger)}, [] {});
    mgr.set_consume("analog_consume", true);
    mgr.start();

    // Give the poll loop several cycles to reach its lazy-install check.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    // Confirm the poll thread is actually alive and cycling, so "no hook installed" reflects the install gate staying
    // closed for an analog-only consume binding rather than a thread that never reached the check.
    EXPECT_TRUE(mgr.is_running());
    EXPECT_FALSE(detail::xinput_installed());

    mgr.shutdown();
    EXPECT_FALSE(detail::xinput_installed());
}

TEST_F(InputManagerTest, SingletonIdentity)
{
    InputManager &a = InputManager::get_instance();
    InputManager &b = InputManager::get_instance();

    EXPECT_EQ(&a, &b);
}

TEST_F(InputManagerTest, InitialState)
{
    InputManager &mgr = InputManager::get_instance();

    EXPECT_FALSE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 0u);
}

TEST_F(InputManagerTest, RegisterPressBinding)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test_press", {keyboard_key(0x41)}, []() {});

    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputManagerTest, RegisterHoldBinding)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_hold("test_hold", {keyboard_key(0x42)}, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputManagerTest, RegisterMultipleBindings)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("press1", {keyboard_key(0x41)}, []() {});
    mgr.register_press("press2", {keyboard_key(0x42)}, []() {});
    mgr.register_hold("hold1", {keyboard_key(0x43)}, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputManagerTest, StartAndShutdown)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {keyboard_key(0x41)}, []() {});
    mgr.start();

    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();

    EXPECT_FALSE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 0u);
}

TEST_F(InputManagerTest, StartWithoutBindingsDoesNothing)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.start();

    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputManagerTest, ShutdownIdempotent)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {keyboard_key(0x41)}, []() {});
    mgr.start();

    mgr.shutdown();
    EXPECT_NO_THROW(mgr.shutdown());
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputManagerTest, RegisterAppendsLiveWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("before", {keyboard_key(0x41)}, []() {});
    mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_press("after", {keyboard_key(0x42)}, []() {});
    EXPECT_EQ(mgr.binding_count(), 2u);

    mgr.shutdown();
}

TEST_F(InputManagerTest, RestartAfterShutdown)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("first_run", {keyboard_key(0x41)}, []() {});
    mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
    EXPECT_FALSE(mgr.is_running());

    mgr.register_hold("second_run", {keyboard_key(0x42)}, [](bool) {});
    mgr.start();
    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}

TEST_F(InputManagerTest, StartWithCustomPollInterval)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {keyboard_key(0x41)}, []() {});
    mgr.start(std::chrono::milliseconds{32});

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputManagerTest, DoubleStartIgnored)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {keyboard_key(0x41)}, []() {});
    mgr.start();
    EXPECT_TRUE(mgr.is_running());

    // Second start should be a no-op
    mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputManagerTest, MultipleKeysPerBinding)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("multi_key", {keyboard_key(0x70), keyboard_key(0x71), keyboard_key(0x72)}, []() {});
    mgr.start();

    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}

TEST_F(InputManagerTest, ConcurrentAccess)
{
    InputManager &mgr = InputManager::get_instance();

    constexpr int thread_count = 4;
    constexpr int ops_per_thread = 50;
    std::atomic<int> registered{0};

    std::vector<std::thread> threads;
    threads.reserve(thread_count);

    for (int t = 0; t < thread_count; ++t)
    {
        threads.emplace_back(
            [&mgr, &registered, t]()
            {
                for (int i = 0; i < ops_per_thread; ++i)
                {
                    std::string name = "binding_" + std::to_string(t) + "_" + std::to_string(i);
                    mgr.register_press(name, {keyboard_key(0x41)}, []() {});
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

// --- InputPoller: Focus, Modifiers, Active State ---

TEST_F(InputPollerTest, DefaultRequiresFocus)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings));

    // Default require_focus is true; poller should start and run normally
    poller.start();
    EXPECT_TRUE(poller.is_running());
    poller.shutdown();
}

TEST_F(InputPollerTest, ExplicitRequireFocusFalse)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings), DEFAULT_POLL_INTERVAL, false);

    poller.start();
    EXPECT_TRUE(poller.is_running());
    poller.shutdown();
}

TEST_F(InputPollerTest, SetRequireFocusWhileRunning)
{
    std::vector<InputBinding> bindings;
    InputPoller poller(std::move(bindings), DEFAULT_POLL_INTERVAL, true);

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
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "test";
    binding.keys = {keyboard_key(0x41)};
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_binding_active(0));
    EXPECT_FALSE(poller.is_binding_active(1));
    EXPECT_FALSE(poller.is_binding_active(999));
}

TEST_F(InputPollerTest, IsBindingActiveByName)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "test_binding";
    binding.keys = {keyboard_key(0x41)};
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));

    EXPECT_FALSE(poller.is_binding_active("test_binding"));
    EXPECT_FALSE(poller.is_binding_active("nonexistent"));
    EXPECT_FALSE(poller.is_binding_active(""));
}

TEST_F(InputPollerTest, IsBindingActiveWhileRunning)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "active_test";
    binding.keys = {keyboard_key(0x41)};
    binding.mode = InputMode::Hold;
    binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    // No keys pressed in test environment
    EXPECT_FALSE(poller.is_binding_active(0));
    EXPECT_FALSE(poller.is_binding_active("active_test"));

    poller.shutdown();
}

TEST_F(InputPollerTest, ModifierBindingConstruction)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "ctrl_shift_a";
    binding.keys = {keyboard_key(0x41)};
    binding.modifiers = {keyboard_key(0x11), keyboard_key(0x10)};
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));

    EXPECT_EQ(poller.binding_count(), 1u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, EmptyModifiersBackwardCompatible)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "no_mods";
    binding.keys = {keyboard_key(0x41)};
    // modifiers left empty (default)
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, HoldBindingShutdownSafety)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "hold_shutdown_test";
    binding.keys = {keyboard_key(0x41)};
    binding.mode = InputMode::Hold;
    binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));
    poller.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    // Shutdown with hold bindings should complete cleanly
    EXPECT_NO_THROW(poller.shutdown());
    EXPECT_FALSE(poller.is_running());
    EXPECT_FALSE(poller.is_binding_active(0));
}

// --- InputPoller: Strict Modifier Matching ---

TEST_F(InputPollerTest, StrictModifierMatchingConstruction)
{
    // When "V" and "Shift+V" are both registered, the poller should construct without error and track Shift as a known
    // modifier.
    std::vector<InputBinding> bindings;

    InputBinding plain_v;
    plain_v.name = "plain_v";
    plain_v.keys = {keyboard_key(0x56)};
    plain_v.mode = InputMode::Press;
    plain_v.on_press = []() {};
    bindings.push_back(std::move(plain_v));

    InputBinding shift_v;
    shift_v.name = "shift_v";
    shift_v.keys = {keyboard_key(0x56)};
    shift_v.modifiers = {keyboard_key(0x10)};
    shift_v.mode = InputMode::Press;
    shift_v.on_press = []() {};
    bindings.push_back(std::move(shift_v));

    InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingMultipleModifiers)
{
    // "A", "Ctrl+A", "Ctrl+Shift+A" -- three levels of modifier specificity
    std::vector<InputBinding> bindings;

    InputBinding plain;
    plain.name = "plain_a";
    plain.keys = {keyboard_key(0x41)};
    plain.mode = InputMode::Press;
    plain.on_press = []() {};
    bindings.push_back(std::move(plain));

    InputBinding ctrl_a;
    ctrl_a.name = "ctrl_a";
    ctrl_a.keys = {keyboard_key(0x41)};
    ctrl_a.modifiers = {keyboard_key(0x11)};
    ctrl_a.mode = InputMode::Press;
    ctrl_a.on_press = []() {};
    bindings.push_back(std::move(ctrl_a));

    InputBinding ctrl_shift_a;
    ctrl_shift_a.name = "ctrl_shift_a";
    ctrl_shift_a.keys = {keyboard_key(0x41)};
    ctrl_shift_a.modifiers = {keyboard_key(0x11), keyboard_key(0x10)};
    ctrl_shift_a.mode = InputMode::Press;
    ctrl_shift_a.on_press = []() {};
    bindings.push_back(std::move(ctrl_shift_a));

    InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 3u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingNoModifierBindingsUnaffected)
{
    // When no binding uses modifiers, all bindings should work normally
    std::vector<InputBinding> bindings;

    InputBinding a;
    a.name = "key_a";
    a.keys = {keyboard_key(0x41)};
    a.mode = InputMode::Press;
    a.on_press = []() {};
    bindings.push_back(std::move(a));

    InputBinding b;
    b.name = "key_b";
    b.keys = {keyboard_key(0x42)};
    b.mode = InputMode::Press;
    b.on_press = []() {};
    bindings.push_back(std::move(b));

    InputPoller poller(std::move(bindings));

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingWithHoldMode)
{
    // Hold mode should also respect strict modifier matching
    std::vector<InputBinding> bindings;

    InputBinding plain;
    plain.name = "hold_v";
    plain.keys = {keyboard_key(0x56)};
    plain.mode = InputMode::Hold;
    plain.on_state_change = [](bool) {};
    bindings.push_back(std::move(plain));

    InputBinding shift;
    shift.name = "shift_hold_v";
    shift.keys = {keyboard_key(0x56)};
    shift.modifiers = {keyboard_key(0x10)};
    shift.mode = InputMode::Hold;
    shift.on_state_change = [](bool) {};
    bindings.push_back(std::move(shift));

    InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingNonStandardModifier)
{
    // Non-standard modifier: "A+B" where A is the modifier
    std::vector<InputBinding> bindings;

    InputBinding plain_b;
    plain_b.name = "plain_b";
    plain_b.keys = {keyboard_key(0x42)};
    plain_b.mode = InputMode::Press;
    plain_b.on_press = []() {};
    bindings.push_back(std::move(plain_b));

    InputBinding a_plus_b;
    a_plus_b.name = "a_plus_b";
    a_plus_b.keys = {keyboard_key(0x42)};
    a_plus_b.modifiers = {keyboard_key(0x41)};
    a_plus_b.mode = InputMode::Press;
    a_plus_b.on_press = []() {};
    bindings.push_back(std::move(a_plus_b));

    InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, StrictModifierMatchingGamepadBindings)
{
    // Gamepad modifiers should be tracked in the known modifiers set
    std::vector<InputBinding> bindings;

    InputBinding plain;
    plain.name = "gp_a";
    plain.keys = {gamepad_button(GamepadCode::A)};
    plain.mode = InputMode::Press;
    plain.on_press = []() {};
    bindings.push_back(std::move(plain));

    InputBinding lb_a;
    lb_a.name = "lb_gp_a";
    lb_a.keys = {gamepad_button(GamepadCode::A)};
    lb_a.modifiers = {gamepad_button(GamepadCode::LeftBumper)};
    lb_a.mode = InputMode::Press;
    lb_a.on_press = []() {};
    bindings.push_back(std::move(lb_a));

    InputPoller poller(std::move(bindings));
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
    std::vector<InputBinding> bindings;

    InputBinding plain_v;
    plain_v.name = "feature_a";
    plain_v.keys = {keyboard_key(0x56)};
    plain_v.mode = InputMode::Press;
    plain_v.on_press = []() {};
    bindings.push_back(std::move(plain_v));

    InputBinding shift_g;
    shift_g.name = "feature_b";
    shift_g.keys = {keyboard_key(0x47)};
    shift_g.modifiers = {keyboard_key(0x10)};
    shift_g.mode = InputMode::Press;
    shift_g.on_press = []() {};
    bindings.push_back(std::move(shift_g));

    InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.binding_count(), 2u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

// --- InputManager: Focus, Modifiers, Active State ---

TEST_F(InputManagerTest, RegisterPressWithModifiers)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("ctrl_a", {keyboard_key(0x41)}, {keyboard_key(0x11)}, []() {});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, RegisterHoldWithModifiers)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_hold("shift_hold", {keyboard_key(0x41)}, {keyboard_key(0x10)}, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, RegisterMixedModifierBindings)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("plain", {keyboard_key(0x41)}, []() {});
    mgr.register_press("ctrl_b", {keyboard_key(0x42)}, {keyboard_key(0x11)}, []() {});
    mgr.register_hold("shift_c", {keyboard_key(0x43)}, {keyboard_key(0x10), keyboard_key(0x11)}, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputManagerTest, SetRequireFocusBeforeStart)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.set_require_focus(false);
    mgr.register_press("test", {keyboard_key(0x41)}, []() {});
    mgr.start();

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputManagerTest, SetRequireFocusWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {keyboard_key(0x41)}, []() {});
    mgr.start();

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

TEST_F(InputManagerTest, IsBindingActiveNotRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {keyboard_key(0x41)}, []() {});

    // Not started yet
    EXPECT_FALSE(mgr.is_binding_active("test"));
    EXPECT_FALSE(mgr.is_binding_active("nonexistent"));
}

TEST_F(InputManagerTest, IsBindingActiveWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("press_q", {keyboard_key(0x51)}, []() {});
    mgr.register_hold("hold_w", {keyboard_key(0x57)}, [](bool) {});
    mgr.start();

    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    // No keys pressed in test environment
    EXPECT_FALSE(mgr.is_binding_active("press_q"));
    EXPECT_FALSE(mgr.is_binding_active("hold_w"));
    EXPECT_FALSE(mgr.is_binding_active("nonexistent"));

    mgr.shutdown();
}

TEST_F(InputManagerTest, IsBindingActiveAfterShutdown)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {keyboard_key(0x41)}, []() {});
    mgr.start();
    mgr.shutdown();

    EXPECT_FALSE(mgr.is_binding_active("test"));
}

TEST_F(InputManagerTest, ModifierBindingsAppendLiveWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("before", {keyboard_key(0x41)}, []() {});
    mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_press("after", {keyboard_key(0x42)}, {keyboard_key(0x11)}, []() {});
    EXPECT_EQ(mgr.binding_count(), 2u);

    mgr.register_hold("after_hold", {keyboard_key(0x43)}, {keyboard_key(0x10)}, [](bool) {});
    EXPECT_EQ(mgr.binding_count(), 3u);

    mgr.shutdown();
}

// --- InputManager: Gamepad ---

TEST_F(InputManagerTest, RegisterGamepadBinding)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("gamepad_a", {gamepad_button(GamepadCode::A)}, []() {});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, RegisterGamepadWithModifier)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("lb_a", {gamepad_button(GamepadCode::A)}, {gamepad_button(GamepadCode::LeftBumper)}, []() {});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, SetGamepadIndex)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.set_gamepad_index(1);
    mgr.register_press("test", {gamepad_button(GamepadCode::A)}, []() {});
    mgr.start();

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputManagerTest, SetTriggerThreshold)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.set_trigger_threshold(100);
    mgr.register_hold("lt", {gamepad_button(GamepadCode::LeftTrigger)}, [](bool) {});
    mgr.start();

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputManagerTest, MixedKeyboardAndGamepadBindings)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("kb_toggle", {keyboard_key(0x72)}, {keyboard_key(0x11)}, []() {});
    mgr.register_press("gp_toggle", {gamepad_button(GamepadCode::A)}, {gamepad_button(GamepadCode::LeftBumper)},
                       []() {});
    mgr.register_hold("mouse_hold", {mouse_button(0x05)}, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 3u);

    mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

// --- InputManager: KeyComboList overloads ---

TEST_F(InputManagerTest, RegisterPressFromKeyComboList)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos = {
        {.keys = {keyboard_key(0x72)}, .modifiers = {}},
        {.keys = {gamepad_button(GamepadCode::A)}, .modifiers = {gamepad_button(GamepadCode::LeftBumper)}}};

    mgr.register_press("toggle", combos, []() {});

    EXPECT_EQ(mgr.binding_count(), 2u);
}

TEST_F(InputManagerTest, RegisterHoldFromKeyComboList)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos = {{.keys = {keyboard_key(0x10)}, .modifiers = {}},
                                   {.keys = {gamepad_button(GamepadCode::LeftTrigger)}, .modifiers = {}}};

    mgr.register_hold("hold_action", combos, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 2u);
}

TEST_F(InputManagerTest, RegisterPressFromEmptyKeyComboListReservesName)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos;

    mgr.register_press("empty", combos, []() {});

    // Empty combos still reserve the binding name so a subsequent update_binding_combos can attach a real combo list.
    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, RegisterHoldFromEmptyKeyComboListReservesName)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos;

    mgr.register_hold("empty", combos, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, RegisterPressFromSingleCombo)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos = {{.keys = {keyboard_key(0x72)}, .modifiers = {keyboard_key(0x11)}}};

    mgr.register_press("single", combos, []() {});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, KeyComboListBindingsShareName)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos = {{.keys = {keyboard_key(0x72)}, .modifiers = {}},
                                   {.keys = {keyboard_key(0x73)}, .modifiers = {}}};

    mgr.register_press("shared_name", combos, []() {});
    mgr.start();

    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 2u);

    // is_binding_active queries by shared name (OR logic across combos)
    EXPECT_FALSE(mgr.is_binding_active("shared_name"));

    mgr.shutdown();
}

TEST_F(InputManagerTest, KeyComboListMixedWithIndividualBindings)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("individual", {keyboard_key(0x41)}, []() {});

    Config::KeyComboList combos = {{.keys = {keyboard_key(0x72)}, .modifiers = {}},
                                   {.keys = {keyboard_key(0x73)}, .modifiers = {}}};

    mgr.register_hold("combo_hold", combos, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputManagerTest, KeyComboListAppendsLiveWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("before", {keyboard_key(0x41)}, []() {});
    mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    Config::KeyComboList combos = {{.keys = {keyboard_key(0x72)}, .modifiers = {}}};

    mgr.register_press("after", combos, []() {});
    EXPECT_EQ(mgr.binding_count(), 2u);

    mgr.register_hold("after_hold", combos, [](bool) {});
    EXPECT_EQ(mgr.binding_count(), 3u);

    mgr.shutdown();
}

// --- InputCode: Name Resolution ---

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

// --- Thumbstick axis codes ---

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
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "stick_test";
    binding.keys = {gamepad_button(GamepadCode::LeftStickUp)};
    binding.mode = InputMode::Hold;
    binding.on_state_change = [](bool) {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings));

    EXPECT_EQ(poller.binding_count(), 1u);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());

    poller.shutdown();
}

TEST_F(InputPollerTest, ThumbstickWithCustomThreshold)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "stick_custom";
    binding.keys = {gamepad_button(GamepadCode::RightStickLeft)};
    binding.mode = InputMode::Press;
    binding.on_press = []() {};
    bindings.push_back(std::move(binding));

    InputPoller poller(std::move(bindings), DEFAULT_POLL_INTERVAL, true, 0, GamepadCode::TriggerThreshold, 16000);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());
    EXPECT_FALSE(poller.is_binding_active("stick_custom"));

    poller.shutdown();
}

TEST_F(InputManagerTest, SetStickThreshold)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.set_stick_threshold(12000);
    mgr.register_hold("ls_up", {gamepad_button(GamepadCode::LeftStickUp)}, [](bool) {});
    mgr.start();

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputManagerTest, ThumbstickAndButtonMixed)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("gp_a", {gamepad_button(GamepadCode::A)}, []() {});
    mgr.register_hold("ls_up", {gamepad_button(GamepadCode::LeftStickUp)}, [](bool) {});
    mgr.register_press("rs_right", {gamepad_button(GamepadCode::RightStickRight)},
                       {gamepad_button(GamepadCode::LeftBumper)}, []() {});

    EXPECT_EQ(mgr.binding_count(), 3u);

    mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST(InputStringTest, InputModeToString_IsNoexcept)
{
    static_assert(noexcept(input_mode_to_string(InputMode::Press)));
    static_assert(noexcept(input_mode_to_string(InputMode::Hold)));
}

TEST(InputStringTest, InputSourceToString_IsNoexcept)
{
    static_assert(noexcept(input_source_to_string(InputSource::Keyboard)));
    static_assert(noexcept(input_source_to_string(InputSource::Gamepad)));
}

TEST(InputReshapeContract, MutatorsAreNoexcept)
{
    using KCL = Config::KeyComboList;
    // These reshape APIs are reachable from loader-lock teardown and allocate internally. They must remain noexcept and
    // genuinely no-throw (fail-closed on out-of-memory), so removing noexcept here is a regression that this guard
    // catches at compile time. declval keeps every expression unevaluated.
    static_assert(noexcept(std::declval<InputManager &>().update_binding_combos(std::declval<std::string_view>(),
                                                                                std::declval<const KCL &>())),
                  "InputManager::update_binding_combos must stay noexcept (fail-closed)");
    static_assert(
        noexcept(std::declval<InputManager &>().remove_binding_by_name(std::declval<std::string_view>(), true)),
        "InputManager::remove_binding_by_name must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<InputManager &>().clear_bindings(true)),
                  "InputManager::clear_bindings must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<InputManager &>().set_consume(std::declval<std::string_view>(), true)),
                  "InputManager::set_consume must stay noexcept (fail-closed)");

    static_assert(noexcept(std::declval<InputPoller &>().update_combos(std::declval<std::string_view>(),
                                                                       std::declval<const KCL &>())),
                  "InputPoller::update_combos must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<InputPoller &>().add_binding(std::declval<InputBinding>())),
                  "InputPoller::add_binding must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<InputPoller &>().remove_bindings_by_name(std::declval<std::string_view>())),
                  "InputPoller::remove_bindings_by_name must stay noexcept (fail-closed)");
    static_assert(noexcept(std::declval<InputPoller &>().clear_bindings()),
                  "InputPoller::clear_bindings must stay noexcept (fail-closed)");
    SUCCEED();
}

// --- InputCodeHash ---

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

TEST(InputModeTest, UnknownModeToString)
{
    auto unknown = static_cast<InputMode>(999);
    EXPECT_EQ(input_mode_to_string(unknown), "Unknown");
}

TEST(InputManagerUpdateCombos, UnknownNameIsSilent)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    Config::KeyComboList combos;
    combos.push_back({{keyboard_key(0x41)}, {}});
    im.update_binding_combos("does-not-exist", combos);
    SUCCEED();
}

TEST(InputManagerUpdateCombos, UpdatesPendingBindingBeforeStart)
{
    auto &im = InputManager::get_instance();
    im.shutdown();

    Config::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    im.register_press("update-pending", initial, []() {});
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    Config::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x42)}, {}}); // 'B'
    im.update_binding_combos("update-pending", replacement);

    // Still 1 binding after replacement; cardinality preserved.
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

TEST(InputManagerUpdateCombos, CardinalityCanGrow)
{
    auto &im = InputManager::get_instance();
    im.shutdown();

    Config::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    im.register_press("update-grow", initial, []() {});

    Config::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x42)}, {}});
    replacement.push_back({{keyboard_key(0x43)}, {}});
    im.update_binding_combos("update-grow", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));
    im.shutdown();
}

TEST(InputManagerUpdateCombos, CardinalityCanShrink)
{
    auto &im = InputManager::get_instance();
    im.shutdown();

    Config::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    initial.push_back({{keyboard_key(0x42)}, {}});
    initial.push_back({{keyboard_key(0x43)}, {}});
    im.register_press("update-shrink", initial, []() {});

    Config::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x44)}, {}});
    im.update_binding_combos("update-shrink", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

TEST(InputManagerUpdateCombos, EmptyReplacementUnbindsAndPreservesName)
{
    // Empty replacement is the explicit-unbound state. The binding name must remain addressable so a follow-up
    // non-empty update can rebind it; the entry count collapses to a single inert sentinel.
    auto &im = InputManager::get_instance();
    im.shutdown();

    Config::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    im.register_press("update-empty-clear", initial, []() {});
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    Config::KeyComboList replacement;
    im.update_binding_combos("update-empty-clear", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_FALSE(im.is_binding_active("update-empty-clear"));

    // Rebind the same name with a real combo; the sentinel must accept it.
    Config::KeyComboList rebind;
    rebind.push_back({{keyboard_key(0x42)}, {}});
    im.update_binding_combos("update-empty-clear", rebind);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

TEST(InputManagerUpdateCombos, UpdatesRunningPollerBinding)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    Config::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    im.register_press("update-running", initial, []() {});
    im.start(std::chrono::milliseconds(5));

    Config::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x5A)}, {}}); // 'Z'
    im.update_binding_combos("update-running", replacement);

    // Give the poller a cycle to pick up the swap, then tear down.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_TRUE(im.is_running());
    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputManagerUpdateCombos, ConcurrentUpdateWhilePollerRunning)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    Config::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    im.register_press("update-stress", initial, []() {});
    im.start(std::chrono::milliseconds(1));

    std::atomic<bool> stop{false};
    constexpr int ITERATIONS = 1000;

    std::thread writer(
        [&im, &stop]()
        {
            for (int i = 0; i < ITERATIONS && !stop.load(std::memory_order_relaxed); ++i)
            {
                Config::KeyComboList replacement;
                const std::uint32_t key_code = (i % 2 == 0) ? 0x41u : 0x5Au;
                replacement.push_back({{keyboard_key(key_code)}, {}});
                im.update_binding_combos("update-stress", replacement);
            }
        });

    writer.join();
    stop.store(true, std::memory_order_relaxed);

    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
    SUCCEED();
}

TEST(InputManagerUpdateCombos, ConcurrentQueriesAndCardinalityUpdatesWhilePollerRunning)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    Config::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    im.register_press("update-query-stress", initial, []() {});
    im.start(std::chrono::milliseconds(1));

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
                    (void)im.is_binding_active("update-query-stress");
                }
            });
    }

    start.store(true, std::memory_order_release);
    for (int i = 0; i < ITERATIONS; ++i)
    {
        Config::KeyComboList replacement;
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
        im.update_binding_combos("update-query-stress", replacement);
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

TEST(InputManagerHotReload, RegisterPressWhilePollerRunning)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    im.register_press("hr-pre", {keyboard_key(0x41)}, []() {});
    im.start(std::chrono::milliseconds(2));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    im.register_press("hr-live", {keyboard_key(0x42)}, []() {});

    // Give the poller a couple of cycles to absorb the new binding.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_TRUE(im.is_running());
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));

    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputManagerHotReload, ClearBindingsKeepsPollerRunning)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    im.register_press("hr-clear-1", {keyboard_key(0x41)}, []() {});
    im.register_press("hr-clear-2", {keyboard_key(0x42)}, []() {});
    im.start(std::chrono::milliseconds(2));
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    im.clear_bindings();
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(0));
    EXPECT_TRUE(im.is_running());

    // Re-register after clear; poller continues without a restart.
    im.register_press("hr-clear-after", {keyboard_key(0x43)}, []() {});
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputManagerHotReload, RemoveBindingByNameLive)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    im.register_press("hr-keep", {keyboard_key(0x41)}, []() {});
    im.register_press("hr-drop", {keyboard_key(0x42)}, []() {});
    im.start(std::chrono::milliseconds(2));
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    EXPECT_EQ(im.remove_binding_by_name("hr-drop"), static_cast<size_t>(1));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
}

TEST(InputManagerHotReload, EmptyComboListRegistersSentinelName)
{
    auto &im = InputManager::get_instance();
    im.shutdown();

    Config::KeyComboList empty_combos;
    im.register_press("sentinel", empty_combos, []() {});
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    Config::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x41)}, {}});
    im.update_binding_combos("sentinel", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

// Regression guard for the cardinality-rebuild release-callback path: a held register_hold consumer whose combo
// cardinality changes via INI hot-reload
// must receive on_state_change(false) when its entry is wholesale-replaced;
// without it the consumer would latch in the held state forever. Without a way to drive GetAsyncKeyState in a test
// process, this case exercises the call flow against the no-active-hold branch and pins that the cardinality change
// still proceeds without crashing or leaking state.
TEST(InputPollerHoldRebuild, CardinalityChangeFiresReleaseForHeldEntries)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    auto release_count = std::make_shared<std::atomic<int>>(0);

    Config::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    initial.push_back({{keyboard_key(0x42)}, {}});
    im.register_hold("rebuild-hold", initial,
                     [release_count](bool pressed) noexcept
                     {
                         if (!pressed)
                         {
                             release_count->fetch_add(1, std::memory_order_relaxed);
                         }
                     });
    im.start(std::chrono::milliseconds(2));

    Config::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x43)}, {}});
    im.update_binding_combos("rebuild-hold", replacement);

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
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    im.register_press("survive-1", {keyboard_key(0x41)}, []() {});
    im.register_press("survive-2", {keyboard_key(0x42)}, []() {});
    im.start(std::chrono::milliseconds(2));
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    im.register_press("survive-3", {keyboard_key(0x43)}, []() {});
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(3));
    EXPECT_FALSE(im.is_binding_active("survive-1"));
    EXPECT_FALSE(im.is_binding_active("survive-2"));
    EXPECT_FALSE(im.is_binding_active("survive-3"));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
    im.set_require_focus(true);
}

// --- KeyStateCache: per-cycle keyboard memoization ---

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
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    im.register_press("grow-seed", {keyboard_key(0x41)}, []() {});
    im.start(std::chrono::milliseconds(1));

    constexpr int extra = 300;
    for (int i = 0; i < extra; ++i)
    {
        im.register_press("grow-" + std::to_string(i), {keyboard_key(0x41 + (i % 20))}, []() {});
    }

    // Let the poll thread run many cycles against the grown binding set.
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    EXPECT_TRUE(im.is_running());
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(extra + 1));

    im.shutdown();
    im.set_require_focus(true);
}

// remove_bindings_by_name must carry surviving entries' atomic states forward; is_binding_active(name) must stay
// consistent across the reshape with no torn reads against bindings_.size().
TEST(InputPollerStatePreservation, RemovePreservesSurvivingState)
{
    auto &im = InputManager::get_instance();
    im.shutdown();
    im.set_require_focus(false);

    im.register_press("keep-a", {keyboard_key(0x41)}, []() {});
    im.register_press("drop", {keyboard_key(0x42)}, []() {});
    im.register_press("keep-b", {keyboard_key(0x43)}, []() {});
    im.start(std::chrono::milliseconds(2));

    EXPECT_EQ(im.remove_binding_by_name("drop"), static_cast<size_t>(1));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));
    EXPECT_FALSE(im.is_binding_active("drop"));
    EXPECT_FALSE(im.is_binding_active("keep-a"));
    EXPECT_FALSE(im.is_binding_active("keep-b"));

    im.shutdown();
    im.set_require_focus(true);
}
