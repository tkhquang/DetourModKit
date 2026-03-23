#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

#include "DetourModKit/input.hpp"
#include "DetourModKit/config.hpp"

using namespace DetourModKit;
using DetourModKit::keyboard_key;
using DetourModKit::gamepad_button;

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
    void SetUp() override
    {
        InputManager::get_instance().shutdown();
    }

    void TearDown() override
    {
        InputManager::get_instance().shutdown();
    }
};

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

TEST_F(InputManagerTest, RegisterIgnoredWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("before", {keyboard_key(0x41)}, []() {});
    mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_press("after", {keyboard_key(0x42)}, []() {});
    EXPECT_EQ(mgr.binding_count(), 1u);

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
        threads.emplace_back([&mgr, &registered, t]()
                             {
            for (int i = 0; i < ops_per_thread; ++i)
            {
                std::string name = "binding_" + std::to_string(t) + "_" + std::to_string(i);
                mgr.register_press(name, {keyboard_key(0x41)}, []() {});
                registered.fetch_add(1, std::memory_order_relaxed);
            } });
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

TEST_F(InputManagerTest, ModifierBindingsIgnoredWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("before", {keyboard_key(0x41)}, []() {});
    mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_press("after", {keyboard_key(0x42)}, {keyboard_key(0x11)}, []() {});
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_hold("after_hold", {keyboard_key(0x43)}, {keyboard_key(0x10)}, [](bool) {});
    EXPECT_EQ(mgr.binding_count(), 1u);

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

    mgr.register_press("lb_a", {gamepad_button(GamepadCode::A)},
                        {gamepad_button(GamepadCode::LeftBumper)}, []() {});

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
    mgr.register_press("gp_toggle", {gamepad_button(GamepadCode::A)},
                        {gamepad_button(GamepadCode::LeftBumper)}, []() {});
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

    Config::KeyComboList combos = {
        {.keys = {keyboard_key(0x10)}, .modifiers = {}},
        {.keys = {gamepad_button(GamepadCode::LeftTrigger)}, .modifiers = {}}};

    mgr.register_hold("hold_action", combos, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 2u);
}

TEST_F(InputManagerTest, RegisterPressFromEmptyKeyComboList)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos;

    mgr.register_press("empty", combos, []() {});

    EXPECT_EQ(mgr.binding_count(), 0u);
}

TEST_F(InputManagerTest, RegisterHoldFromEmptyKeyComboList)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos;

    mgr.register_hold("empty", combos, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 0u);
}

TEST_F(InputManagerTest, RegisterPressFromSingleCombo)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos = {
        {.keys = {keyboard_key(0x72)}, .modifiers = {keyboard_key(0x11)}}};

    mgr.register_press("single", combos, []() {});

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, KeyComboListBindingsShareName)
{
    InputManager &mgr = InputManager::get_instance();

    Config::KeyComboList combos = {
        {.keys = {keyboard_key(0x72)}, .modifiers = {}},
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

    Config::KeyComboList combos = {
        {.keys = {keyboard_key(0x72)}, .modifiers = {}},
        {.keys = {keyboard_key(0x73)}, .modifiers = {}}};

    mgr.register_hold("combo_hold", combos, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputManagerTest, KeyComboListIgnoredWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("before", {keyboard_key(0x41)}, []() {});
    mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    Config::KeyComboList combos = {
        {.keys = {keyboard_key(0x72)}, .modifiers = {}}};

    mgr.register_press("after", combos, []() {});
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_hold("after_hold", combos, [](bool) {});
    EXPECT_EQ(mgr.binding_count(), 1u);

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

    InputPoller poller(std::move(bindings), DEFAULT_POLL_INTERVAL, true, 0,
                       GamepadCode::TriggerThreshold, 16000);

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
