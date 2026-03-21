#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

#include "DetourModKit/input.hpp"

using namespace DetourModKit;

// --- InputMode string conversion ---

TEST(InputModeTest, PressToString)
{
    EXPECT_EQ(input_mode_to_string(InputMode::Press), "Press");
}

TEST(InputModeTest, HoldToString)
{
    EXPECT_EQ(input_mode_to_string(InputMode::Hold), "Hold");
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
    press_binding.keys = {0x41}; // 'A' key
    press_binding.mode = InputMode::Press;
    press_binding.on_press = []() {};
    bindings.push_back(std::move(press_binding));

    InputBinding hold_binding;
    hold_binding.name = "test_hold";
    hold_binding.keys = {0x42}; // 'B' key
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

TEST_F(InputPollerTest, ZeroVkCodeSkipped)
{
    std::vector<InputBinding> bindings;

    InputBinding binding;
    binding.name = "zero_vk";
    binding.keys = {0, 0, 0};
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
        binding.keys = {0x41 + i};
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
    binding.keys = {0x41};
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

    mgr.register_press("test_press", {0x41}, []() {});

    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputManagerTest, RegisterHoldBinding)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_hold("test_hold", {0x42}, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputManagerTest, RegisterMultipleBindings)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("press1", {0x41}, []() {});
    mgr.register_press("press2", {0x42}, []() {});
    mgr.register_hold("hold1", {0x43}, [](bool) {});

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputManagerTest, StartAndShutdown)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {0x41}, []() {});
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

    mgr.register_press("test", {0x41}, []() {});
    mgr.start();

    mgr.shutdown();
    EXPECT_NO_THROW(mgr.shutdown());
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputManagerTest, RegisterIgnoredWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("before", {0x41}, []() {});
    mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_press("after", {0x42}, []() {});
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}

TEST_F(InputManagerTest, RestartAfterShutdown)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("first_run", {0x41}, []() {});
    mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
    EXPECT_FALSE(mgr.is_running());

    mgr.register_hold("second_run", {0x42}, [](bool) {});
    mgr.start();
    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}

TEST_F(InputManagerTest, StartWithCustomPollInterval)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {0x41}, []() {});
    mgr.start(std::chrono::milliseconds{32});

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputManagerTest, DoubleStartIgnored)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {0x41}, []() {});
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

    mgr.register_press("multi_key", {0x70, 0x71, 0x72}, []() {}); // F1, F2, F3
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
                mgr.register_press(name, {0x41}, []() {});
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
    binding.keys = {0x41};
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
    binding.keys = {0x41};
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
    binding.keys = {0x41};
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
    binding.keys = {0x41};
    binding.modifiers = {0x11, 0x10}; // VK_CONTROL, VK_SHIFT
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
    binding.keys = {0x41};
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
    binding.keys = {0x41};
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

    mgr.register_press("ctrl_a", {0x41}, {0x11}, []() {}); // Ctrl+A

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, RegisterHoldWithModifiers)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_hold("shift_hold", {0x41}, {0x10}, [](bool) {}); // Shift+A

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputManagerTest, RegisterMixedModifierBindings)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("plain", {0x41}, []() {});
    mgr.register_press("ctrl_b", {0x42}, {0x11}, []() {});
    mgr.register_hold("shift_c", {0x43}, {0x10, 0x11}, [](bool) {}); // Ctrl+Shift+C

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputManagerTest, SetRequireFocusBeforeStart)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.set_require_focus(false);
    mgr.register_press("test", {0x41}, []() {});
    mgr.start();

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputManagerTest, SetRequireFocusWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("test", {0x41}, []() {});
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

    mgr.register_press("test", {0x41}, []() {});

    // Not started yet
    EXPECT_FALSE(mgr.is_binding_active("test"));
    EXPECT_FALSE(mgr.is_binding_active("nonexistent"));
}

TEST_F(InputManagerTest, IsBindingActiveWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("press_q", {0x51}, []() {});
    mgr.register_hold("hold_w", {0x57}, [](bool) {});
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

    mgr.register_press("test", {0x41}, []() {});
    mgr.start();
    mgr.shutdown();

    EXPECT_FALSE(mgr.is_binding_active("test"));
}

TEST_F(InputManagerTest, ModifierBindingsIgnoredWhileRunning)
{
    InputManager &mgr = InputManager::get_instance();

    mgr.register_press("before", {0x41}, []() {});
    mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_press("after", {0x42}, {0x11}, []() {});
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.register_hold("after_hold", {0x43}, {0x10}, [](bool) {});
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}
