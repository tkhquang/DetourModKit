#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <string>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/input_poller.hpp"
#include "internal/input_key_cache.hpp"

#include "fixtures/throwing_copy.hpp"
#include "test_alloc_probe.hpp"
#include "fixtures/input_fixture.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;
using namespace dmk_test::input_fixture;

// InputBinding

TEST(InputBindingTest, DefaultTriggerIsPress)
{
    detail::InputBinding binding;
    EXPECT_EQ(binding.trigger, input::Trigger::Press);
}

// InputPoller

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

    EXPECT_NO_THROW(poller.shutdown());
    EXPECT_FALSE(poller.is_running());
}

TEST_F(InputPollerTest, ShutdownWithoutStart)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputPoller poller(std::move(bindings));

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

    // The condition-variable wake isolates shutdown latency from the poll interval.
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

TEST_F(InputTest, RemoveBindingsByName_PluralAliasMatchesSingular)
{
    auto &mgr = input::Input::instance();
    // Keyboard bindings install no hook, so this exercises the plural alias without touching real input.
    (void)input::register_combo(
        input::ComboBinding{
            .name = "alias_a",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = [] {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "alias_b",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x71)}, {}}},
            .on_press = [] {},
        }
    );
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

// A plain guard release leaves the physical token current. A consume change, rebind, or removal advances the
// generation.
TEST_F(InputTest, TokenStaysCurrentAfterPlainGuardRelease)
{
    auto &mgr = input::Input::instance();
    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "tok_plain",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x71)}, {}}},
            .on_press = [] {},
        }
    );
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
    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "tok_consume",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .consume = true,
            .on_press = [] {},
        }
    );
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
    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "tok_rebind",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x71)}, {}}},
            .on_press = [] {},
        }
    );
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
    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "tok_remove",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x71)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_TRUE(guard.has_value());
    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("tok_remove");
    ASSERT_TRUE(mgr.token_current(token));

    EXPECT_EQ(mgr.remove_bindings_by_name("tok_remove"), 1u);
    EXPECT_FALSE(mgr.token_current(token))
        << "a name-based removal reshapes the binding set and advances the generation";

    mgr.shutdown();
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

    (void)input::register_combo(
        input::ComboBinding{
            .name = "test_press",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputTest, RegisterHoldBinding)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "test_hold",
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_state_change = [](bool) {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputTest, RegisterMultipleBindings)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "press1",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "press2",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "hold1",
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x43)}, {}}},
            .on_state_change = [](bool) {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputTest, RegisterAppendsLiveWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "before",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    (void)input::register_combo(
        input::ComboBinding{
            .name = "after",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
        }
    );
    EXPECT_EQ(mgr.binding_count(), 2u);

    mgr.shutdown();
}

TEST_F(InputTest, MultipleKeysPerBinding)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "multi_key",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70), keyboard_key(0x71), keyboard_key(0x72)}, {}}},
            .on_press = []() {},
        }
    );
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
                    (void)input::register_combo(
                        input::ComboBinding{
                            .name = name,
                            .trigger = input::Trigger::Press,
                            .combos = {{{keyboard_key(0x41)}, {}}},
                            .on_press = []() {},
                        }
                    );
                    registered.fetch_add(1, std::memory_order_relaxed);
                }
            }
        );
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

    EXPECT_NO_THROW(poller.shutdown());
    EXPECT_FALSE(poller.is_running());
    EXPECT_FALSE(poller.is_binding_active(0));
}

// InputPoller: Strict Modifier Matching

TEST_F(InputPollerTest, StrictModifierMatchingConstruction)
{
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
    // "A", "Ctrl+A", "Ctrl+Shift+A": three levels of modifier specificity
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
    // Shift belongs to another binding, but still blocks bare "V".
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

    (void)input::register_combo(
        input::ComboBinding{
            .name = "ctrl_a",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {keyboard_key(0x11)}}},
            .on_press = []() {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterHoldWithModifiers)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "shift_hold",
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x41)}, {keyboard_key(0x10)}}},
            .on_state_change = [](bool) {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterMixedModifierBindings)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "plain",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "ctrl_b",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {keyboard_key(0x11)}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "shift_c",
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x43)}, {keyboard_key(0x10), keyboard_key(0x11)}}},
            .on_state_change = [](bool) {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputTest, SetRequireFocusWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "test",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start();

    EXPECT_TRUE(mgr.is_running());

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

    (void)input::register_combo(
        input::ComboBinding{
            .name = "test",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );

    // Not started yet
    EXPECT_FALSE(mgr.is_active("test"));
    EXPECT_FALSE(mgr.is_active("nonexistent"));
}

TEST_F(InputTest, IsBindingActiveWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "press_q",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x51)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "hold_w",
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x57)}, {}}},
            .on_state_change = [](bool) {},
        }
    );
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

    (void)input::register_combo(
        input::ComboBinding{
            .name = "test",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start();
    mgr.shutdown();

    EXPECT_FALSE(mgr.is_active("test"));
}

TEST_F(InputTest, ModifierBindingsAppendLiveWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "before",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    (void)input::register_combo(
        input::ComboBinding{
            .name = "after",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {keyboard_key(0x11)}}},
            .on_press = []() {},
        }
    );
    EXPECT_EQ(mgr.binding_count(), 2u);

    (void)input::register_combo(
        input::ComboBinding{
            .name = "after_hold",
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x43)}, {keyboard_key(0x10)}}},
            .on_state_change = [](bool) {},
        }
    );
    EXPECT_EQ(mgr.binding_count(), 3u);

    mgr.shutdown();
}

// Input facade: Gamepad

TEST_F(InputTest, RegisterGamepadBinding)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "gamepad_a",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .on_press = []() {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterGamepadWithModifier)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "lb_a",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {gamepad_button(GamepadCode::LeftBumper)}}},
            .on_press = []() {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, SetGamepadIndex)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "test",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start(
        input::Input::Settings{
            .gamepad_index = 1,
        }
    );

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, SetTriggerThreshold)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "lt",
            .trigger = input::Trigger::Hold,
            .combos = {{{gamepad_button(GamepadCode::LeftTrigger)}, {}}},
            .on_state_change = [](bool) {},
        }
    );
    (void)mgr.start(
        input::Input::Settings{
            .trigger_threshold = 100,
        }
    );

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, MixedKeyboardAndGamepadBindings)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "kb_toggle",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x72)}, {keyboard_key(0x11)}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "gp_toggle",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {gamepad_button(GamepadCode::LeftBumper)}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "mouse_hold",
            .trigger = input::Trigger::Hold,
            .combos = {{{mouse_button(0x05)}, {}}},
            .on_state_change = [](bool) {},
        }
    );

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
        {
            .keys = {keyboard_key(0x72)},
            .modifiers = {},
        },
        {
            .keys = {gamepad_button(GamepadCode::A)},
            .modifiers = {gamepad_button(GamepadCode::LeftBumper)},
        }
    };

    (void)input::register_combo(
        input::ComboBinding{
            .name = "toggle",
            .trigger = input::Trigger::Press,
            .combos = combos,
            .on_press = []() {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 2u);
}

TEST_F(InputTest, RegisterHoldFromKeyComboList)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos = {
        {
            .keys = {keyboard_key(0x10)},
            .modifiers = {},
        },
        {
            .keys = {gamepad_button(GamepadCode::LeftTrigger)},
            .modifiers = {},
        }
    };

    (void)input::register_combo(
        input::ComboBinding{
            .name = "hold_action",
            .trigger = input::Trigger::Hold,
            .combos = combos,
            .on_state_change = [](bool) {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 2u);
}

TEST_F(InputTest, RegisterPressFromEmptyKeyComboListReservesName)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos;

    (void)input::register_combo(
        input::ComboBinding{
            .name = "empty",
            .trigger = input::Trigger::Press,
            .combos = combos,
            .on_press = []() {},
        }
    );

    // Empty combos still reserve the binding name so a subsequent rebind can attach a real combo list.
    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterHoldFromEmptyKeyComboListReservesName)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos;

    (void)input::register_combo(
        input::ComboBinding{
            .name = "empty",
            .trigger = input::Trigger::Hold,
            .combos = combos,
            .on_state_change = [](bool) {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, RegisterPressFromSingleCombo)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos = {{
        .keys = {keyboard_key(0x72)},
        .modifiers = {keyboard_key(0x11)},
    }};

    (void)input::register_combo(
        input::ComboBinding{
            .name = "single",
            .trigger = input::Trigger::Press,
            .combos = combos,
            .on_press = []() {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, KeyComboListBindingsShareName)
{
    input::Input &mgr = input::Input::instance();

    input::KeyComboList combos = {
        {
            .keys = {keyboard_key(0x72)},
            .modifiers = {},
        },
        {
            .keys = {keyboard_key(0x73)},
            .modifiers = {},
        }
    };

    (void)input::register_combo(
        input::ComboBinding{
            .name = "shared_name",
            .trigger = input::Trigger::Press,
            .combos = combos,
            .on_press = []() {},
        }
    );
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

    (void)input::register_combo(
        input::ComboBinding{
            .name = "individual",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );

    input::KeyComboList combos = {
        {
            .keys = {keyboard_key(0x72)},
            .modifiers = {},
        },
        {
            .keys = {keyboard_key(0x73)},
            .modifiers = {},
        }
    };

    (void)input::register_combo(
        input::ComboBinding{
            .name = "combo_hold",
            .trigger = input::Trigger::Hold,
            .combos = combos,
            .on_state_change = [](bool) {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 3u);
}

TEST_F(InputTest, KeyComboListAppendsLiveWhileRunning)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "before",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start();

    EXPECT_EQ(mgr.binding_count(), 1u);

    input::KeyComboList combos = {{
        .keys = {keyboard_key(0x72)},
        .modifiers = {},
    }};

    (void)input::register_combo(
        input::ComboBinding{
            .name = "after",
            .trigger = input::Trigger::Press,
            .combos = combos,
            .on_press = []() {},
        }
    );
    EXPECT_EQ(mgr.binding_count(), 2u);

    (void)input::register_combo(
        input::ComboBinding{
            .name = "after_hold",
            .trigger = input::Trigger::Hold,
            .combos = combos,
            .on_state_change = [](bool) {},
        }
    );
    EXPECT_EQ(mgr.binding_count(), 3u);

    mgr.shutdown();
}

// Thumbstick axis codes

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

    detail::InputPoller
        poller(std::move(bindings), input::DEFAULT_POLL_INTERVAL, true, 0, GamepadCode::TriggerThreshold, 16000);

    poller.start();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_TRUE(poller.is_running());
    EXPECT_FALSE(poller.is_binding_active("stick_custom"));

    poller.shutdown();
}

TEST_F(InputTest, SetStickThreshold)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "ls_up",
            .trigger = input::Trigger::Hold,
            .combos = {{{gamepad_button(GamepadCode::LeftStickUp)}, {}}},
            .on_state_change = [](bool) {},
        }
    );
    (void)mgr.start(
        input::Input::Settings{
            .stick_threshold = 12000,
        }
    );

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, ThumbstickAndButtonMixed)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "gp_a",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "ls_up",
            .trigger = input::Trigger::Hold,
            .combos = {{{gamepad_button(GamepadCode::LeftStickUp)}, {}}},
            .on_state_change = [](bool) {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "rs_right",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::RightStickRight)}, {gamepad_button(GamepadCode::LeftBumper)}}},
            .on_press = []() {},
        }
    );

    EXPECT_EQ(mgr.binding_count(), 3u);

    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
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

    // Removal shifts indices even when it names another binding. The conservative generation bump must invalidate the
    // survivor token too.
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
    input::KeyComboList combos = {
        {
            .keys = {keyboard_key(0x42)},
            .modifiers = {},
        },
        {
            .keys = {keyboard_key(0x43)},
            .modifiers = {},
        }
    };
    EXPECT_EQ(poller.update_combos("rebind", combos), detail::InputPoller::ComboUpdate::Updated);
    EXPECT_FALSE(poller.binding_token_current(token));

    // The name still exists, so a fresh token resolves and is current.
    EXPECT_TRUE(poller.acquire_binding_token("rebind").valid());
}

TEST_F(InputTest, BindingTokenInvalidBeforeStart)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "pending",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );

    // No active poller before start(): a token cannot resolve.
    const input::BindingToken token = mgr.acquire_token("pending");
    EXPECT_FALSE(token.valid());
    EXPECT_FALSE(mgr.token_current(token));
    EXPECT_FALSE(mgr.is_active(token));
}

TEST_F(InputTest, BindingTokenResolvesAfterStart)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "hotkey",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );

    const input::BindingToken token = mgr.acquire_token("hotkey");
    EXPECT_TRUE(token.valid());
    EXPECT_TRUE(mgr.token_current(token));
    EXPECT_EQ(mgr.is_active(token), mgr.is_active("hotkey"));

    mgr.set_require_focus(true);
}

TEST_F(InputTest, BindingTokenStaleAfterLiveRegister)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "a",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );

    const input::BindingToken token = mgr.acquire_token("a");
    ASSERT_TRUE(mgr.token_current(token));

    (void)input::register_combo(
        input::ComboBinding{
            .name = "b",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
        }
    );
    EXPECT_FALSE(mgr.token_current(token));
    EXPECT_FALSE(mgr.is_active(token));

    mgr.set_require_focus(true);
}

TEST_F(InputTest, BindingTokenFromPriorPollerNeverAliasesNewPoller)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "persist",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );

    const input::BindingToken old_token = mgr.acquire_token("persist");
    ASSERT_TRUE(old_token.valid());
    ASSERT_TRUE(mgr.token_current(old_token));

    // The new poller uses the same name but a distinct process generation. The old token cannot become valid again.
    mgr.shutdown();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "persist",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );

    EXPECT_FALSE(mgr.token_current(old_token));
    EXPECT_FALSE(mgr.is_active(old_token));

    // A fresh token against the new poller is current.
    const input::BindingToken new_token = mgr.acquire_token("persist");
    EXPECT_TRUE(new_token.valid());
    EXPECT_TRUE(mgr.token_current(new_token));

    mgr.set_require_focus(true);
}

// InputPoller: callback staging under copy or allocation failure

namespace
{
    // Longer than either toolchain's small-string buffer, so copying it is a real allocation the probe can fail.
    constexpr const char *LONG_HOLD_NAME = "hold_binding_whose_name_outgrows_the_small_string_buffer";

    // arm_alloc_failure clamps negative budgets to zero. The unarmed control must skip the scope for a negative budget.
    int shutdown_held_binding_under_alloc_budget(long long budget)
    {
        std::atomic<int> releases{0};

        detail::InputBinding binding;
        binding.name = LONG_HOLD_NAME;
        binding.keys = {keyboard_key(0x41)};
        binding.trigger = input::Trigger::Hold;
        // The small callback capture fits std::function's inline buffer. Invocation throws, so the next fallible copy
        // is the staged diagnostic name.
        binding.on_state_change = [releases_ptr = &releases](bool held) -> void
        {
            if (!held)
            {
                releases_ptr->fetch_add(1, std::memory_order_relaxed);
            }
            throw std::runtime_error("hold callback failed");
        };

        std::vector<detail::InputBinding> bindings;
        bindings.push_back(std::move(binding));
        detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{1}, /*require_focus=*/false);
        poller.start();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (!poller.is_binding_active(LONG_HOLD_NAME) && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::yield();
        }
        if (!poller.is_binding_active(LONG_HOLD_NAME))
        {
            poller.shutdown();
            return -1;
        }

        if (budget < 0)
        {
            poller.shutdown();
        }
        else
        {
            dmk_test::AllocFailScope fail(budget);
            poller.shutdown();
        }
        return releases.load(std::memory_order_relaxed);
    }
} // namespace

// The action pairs a callback with its name. Budget 1 fails the long-name copy after action storage, but the terminal
// release must still occur.
TEST_F(InputPollerTest, ReleaseActiveHoldsAllocationSplitCannotIndexMissingName)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    InputSeamReset seam_reset;
    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == 0x41; };

    // Warm the process-default logger: the staging catch and the release handler both log, and first-use logger
    // construction deliberately terminates under OOM.
    (void)DetourModKit::log();

    // Control: with no injected failure the release is staged, delivered, and its throw contained.
    EXPECT_EQ(shutdown_held_binding_under_alloc_budget(-1), 1);
    // The contract itself: budget 1 lands on the long-name copy, after the callback copy has already succeeded. Losing
    // the label must not lose the balancing release.
    EXPECT_EQ(shutdown_held_binding_under_alloc_budget(1), 1);

    for (long long budget = 0; budget <= 24; ++budget)
    {
        const int releases = shutdown_held_binding_under_alloc_budget(budget);
        EXPECT_GE(releases, 0) << "budget=" << budget;
        EXPECT_LE(releases, 1) << "budget=" << budget;
    }
}

// If the second callback copy fails after the first edge was staged, neither staged edge advances its active state.
// Both are therefore re-derived on the next cycle while the shared physical key remains continuously held.
TEST_F(InputPollerTest, StagingFailureRetriesEarlierEdgesWhileStillHeld)
{
    InputSeamReset seam_reset;
    constexpr int HELD_VK = 0x41;
    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

    const auto throw_on_copy = std::make_shared<std::atomic<bool>>(true);
    const auto failed_copies = std::make_shared<std::atomic<int>>(0);
    const auto beta_invocations = std::make_shared<std::atomic<int>>(0);
    std::atomic<int> alpha_presses{0};

    // Two Press bindings on the same key, so both cross the not-active -> active edge in one cycle. Index order is
    // binding order, so alpha stages first and beta's callback copy is what throws.
    detail::InputBinding alpha;
    alpha.name = "alpha";
    alpha.keys = {keyboard_key(HELD_VK)};
    alpha.trigger = input::Trigger::Press;
    alpha.on_press = [&alpha_presses] { alpha_presses.fetch_add(1, std::memory_order_relaxed); };

    detail::InputBinding beta;
    beta.name = "beta";
    beta.keys = {keyboard_key(HELD_VK)};
    beta.trigger = input::Trigger::Press;
    beta.on_press = dmk_test::ThrowingCopyCallback{throw_on_copy, failed_copies, beta_invocations};

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(alpha));
    bindings.push_back(std::move(beta));

    // Warm the process-default logger before the poll thread can reach the rollback's guarded log.
    (void)DetourModKit::log();

    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{1}, /*require_focus=*/false);
    poller.start();

    // Let at least one cycle fail while the key is held.
    const auto failure_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (failed_copies->load(std::memory_order_relaxed) < 1 && std::chrono::steady_clock::now() < failure_deadline)
    {
        std::this_thread::yield();
    }
    if (failed_copies->load(std::memory_order_relaxed) < 1)
    {
        poller.shutdown();
        FAIL() << "poller did not reach the injected callback-copy failure";
    }
    EXPECT_EQ(alpha_presses.load(std::memory_order_relaxed), 0);

    // Recovery, with the key still down and no repress anywhere in this test.
    throw_on_copy->store(false, std::memory_order_relaxed);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (alpha_presses.load(std::memory_order_relaxed) == 0 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::yield();
    }
    poller.shutdown();

    EXPECT_EQ(alpha_presses.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(beta_invocations->load(std::memory_order_relaxed), 1);
}
