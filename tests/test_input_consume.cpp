#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "DetourModKit/input.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/input_poller.hpp"
#include "internal/input_intercept.hpp"
#include "internal/input_test_seams.hpp"

#include "test_alloc_probe.hpp"
#include "fixtures/intercept_lease.hpp"
#include "fixtures/input_fixture.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;
using namespace dmk_test::input_fixture;

TEST_F(InputTest, ConsumeCapacityReflectsTheLivePoller)
{
    auto &mgr = input::Input::instance();
    const auto before_start = mgr.consume_capacity();
    EXPECT_EQ(before_start.capacity, 0u);
    EXPECT_EQ(before_start.active, 0u);
    EXPECT_EQ(before_start.rejected, 0u);

    const auto guard = input::register_combo(
        input::ComboBinding{
            .name = "capacity_query",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .consume = true,
            .on_press = [] {},
        }
    );
    ASSERT_TRUE(guard.has_value());
    ASSERT_TRUE(mgr.start().has_value());
    // The engine publishes its consume rules only while it owns the interception layer, which a headless test
    // host cannot reach by installing. Grant it explicitly so the published table reflects this engine.
    ASSERT_TRUE(detail::InputTestSeams::adopt_intercept_owner_for_test());

    const auto running = mgr.consume_capacity();
    EXPECT_EQ(running.capacity, detail::MAX_GAMEPAD_CONSUME_RULES);
    EXPECT_EQ(running.active, 1u);
    EXPECT_EQ(running.rejected, 0u);

    mgr.shutdown();
    const auto after_shutdown = mgr.consume_capacity();
    EXPECT_EQ(after_shutdown.capacity, 0u);
    EXPECT_EQ(after_shutdown.active, 0u);
    EXPECT_EQ(after_shutdown.rejected, 0u);

    // The consume rule outlives its poller. This process-global rule needs explicit removal before the next case.
    dmk_test::reset_published_consume_rules();
}

TEST_F(InputTest, SetConsumeWhileRunningIsSafe)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "consume_live",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = [] {},
        }
    );
    (void)mgr.start();
    mgr.set_consume("consume_live", true);
    mgr.set_consume("consume_live", false);
    EXPECT_TRUE(mgr.is_running());
    mgr.shutdown();
}

TEST_F(InputTest, RegisterConsumeFlagAppliesToBinding)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "consume_cfg",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = [] {},
        }
    );
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
    (void)input::register_combo(
        input::ComboBinding{
            .name = "analog_consume",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::LeftTrigger)}, {}}},
            .on_press = [] {},
        }
    );
    mgr.set_consume("analog_consume", true);
    (void)mgr.start();

    // Give the poll loop several cycles to reach its lazy-install check.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    // The live poll loop distinguishes a closed analog consume gate from a thread that never reaches installation.
    EXPECT_TRUE(mgr.is_running());
    EXPECT_FALSE(detail::xinput_installed());

    mgr.shutdown();
    EXPECT_FALSE(detail::xinput_installed());
}

// The empty name bypasses the name index. Guard identity must still remove the consume rule.
TEST_F(InputTest, EmptyNameConsumeGuardReleaseLiftsSuppression)
{
    auto &mgr = input::Input::instance();
    // Reset any suppression rule a prior test published so the assertions read this binding alone.
    dmk_test::reset_published_consume_rules();

    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .consume = true,
            .on_press = [] {},
        }
    );
    ASSERT_TRUE(guard.has_value());

    (void)mgr.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds{1000},
        }
    );
    // The engine publishes its consume rules only while it owns the interception layer, which a headless test
    // host cannot reach by installing. Grant it explicitly so the published table reflects this engine.
    ASSERT_TRUE(detail::InputTestSeams::adopt_intercept_owner_for_test());
    const std::uint16_t button = static_cast<std::uint16_t>(GamepadCode::A);
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button)
        << "the anonymous consume binding should arm suppression while its guard is live";

    guard->release();
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), 0u)
        << "releasing the guard must lift suppression even for an empty-name binding";

    mgr.shutdown();
    dmk_test::reset_published_consume_rules();
}

TEST_F(InputTest, BindingTokenStaleAfterConsumeToggle)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "consume_test",
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

TEST_F(InputTest, BindingTokenStaysCurrentAfterRedundantConsumeSet)
{
    // A consume set that re-applies the current flag value is a no-op: no cache rebuild, no generation advance, no
    // token invalidation. Only a real transition reshapes, exactly as set_consume_by_owner already behaved.
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "redundant_consume",
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

    // false -> false: the default flag value re-applied.
    const input::BindingToken token_false = mgr.acquire_token("redundant_consume");
    ASSERT_TRUE(token_false.valid());
    ASSERT_TRUE(mgr.token_current(token_false));
    mgr.set_consume("redundant_consume", false);
    EXPECT_TRUE(mgr.token_current(token_false)) << "a redundant consume(false) must not invalidate live tokens";

    // A real transition still reshapes and invalidates.
    mgr.set_consume("redundant_consume", true);
    EXPECT_FALSE(mgr.token_current(token_false));

    // true -> true: redundant in the other flag value.
    const input::BindingToken token_true = mgr.acquire_token("redundant_consume");
    ASSERT_TRUE(token_true.valid());
    ASSERT_TRUE(mgr.token_current(token_true));
    mgr.set_consume("redundant_consume", true);
    EXPECT_TRUE(mgr.token_current(token_true)) << "a redundant consume(true) must not invalidate live tokens";

    mgr.set_require_focus(true);
}

// A guard release clears the consume flag that set_consume(name, true) enabled after registration ([B-27]). The first
// binding registers with consume on and is the control.
TEST_F(InputTest, ReleaseClearsConsumeEnabledAfterRegistration)
{
    auto &mgr = input::Input::instance();
    dmk_test::reset_published_consume_rules();

    auto at_registration = input::register_combo(
        input::ComboBinding{
            .name = "consume_at_registration",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::B)}, {}}},
            .consume = true,
            .on_press = [] {},
        }
    );
    auto enabled_later = input::register_combo(
        input::ComboBinding{
            .name = "consume_enabled_later",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_TRUE(at_registration.has_value());
    ASSERT_TRUE(enabled_later.has_value());
    ASSERT_TRUE(mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1000}}).has_value());
    ASSERT_TRUE(detail::InputTestSeams::adopt_intercept_owner_for_test());
    ASSERT_EQ(mgr.consume_capacity().active, 1u);

    mgr.set_consume("consume_enabled_later", true);
    const auto button_a = static_cast<std::uint16_t>(GamepadCode::A);
    const auto both = static_cast<std::uint16_t>(button_a | static_cast<std::uint16_t>(GamepadCode::B));
    ASSERT_EQ(mgr.consume_capacity().active, 2u);
    ASSERT_EQ(DetourModKit::detail::evaluate_published_consume_rules(both), both);

    at_registration->release();
    EXPECT_EQ(mgr.consume_capacity().active, 1u);
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(both), button_a);

    enabled_later->release();
    EXPECT_EQ(mgr.consume_capacity().active, 0u) << "the release kept the consume shape set after registration";
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(both), 0u);

    mgr.shutdown();
    dmk_test::reset_published_consume_rules();
}

// Releasing a consume binding's guard must lift its passthrough suppression. Suppression is enforced off the engine
// entry's consume flag, so the release clears it and republishes (mirroring set_consume(name, false)), which reshapes
// the binding set. The reshape (observable as an outstanding token going stale) is the proof the consume-clear path
// ran.
TEST_F(InputTest, ReleasingConsumeGuardRepublishesToLiftSuppression)
{
    auto &mgr = input::Input::instance();

    auto consume_guard = input::register_combo(
        input::ComboBinding{
            .name = "consume_zoom",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .consume = true,
            .on_press = []() {},
        }
    );
    ASSERT_TRUE(consume_guard.has_value());

    (void)input::register_combo(
        input::ComboBinding{
            .name = "anchor",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = []() {},
        }
    );

    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("anchor");
    ASSERT_TRUE(mgr.token_current(token));

    consume_guard->release();
    EXPECT_FALSE(mgr.token_current(token))
        << "consume-release must republish the binding set (as set_consume(false) does) to lift suppression";
}

// A non-consume guard release must leave the binding set unchanged.
TEST_F(InputTest, ReleasingPlainGuardDoesNotRepublish)
{
    auto &mgr = input::Input::instance();

    auto plain_guard = input::register_combo(
        input::ComboBinding{
            .name = "plain",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x71)}, {}}},
            .on_press = []() {},
        }
    );
    ASSERT_TRUE(plain_guard.has_value());

    (void)input::register_combo(
        input::ComboBinding{
            .name = "anchor",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = []() {},
        }
    );

    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("anchor");
    ASSERT_TRUE(mgr.token_current(token));

    plain_guard->release();
    EXPECT_TRUE(mgr.token_current(token)) << "a non-consume guard release must not reshape the binding set";
}

// The Hold gate has no held edge here. Consume removal must still follow the no-op gate release.
TEST_F(InputTest, ReleasingConsumeHoldGuardRepublishesToLiftSuppression)
{
    auto &mgr = input::Input::instance();

    auto consume_guard = input::register_combo(
        input::ComboBinding{
            .name = "consume_hold_zoom",
            .trigger = input::Trigger::Hold,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .consume = true,
            .on_state_change = [](bool) {},
        }
    );
    ASSERT_TRUE(consume_guard.has_value());

    (void)input::register_combo(
        input::ComboBinding{
            .name = "anchor",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = []() {},
        }
    );

    ASSERT_TRUE(mgr.start().has_value());

    const input::BindingToken token = mgr.acquire_token("anchor");
    ASSERT_TRUE(mgr.token_current(token));

    consume_guard->release();
    EXPECT_FALSE(mgr.token_current(token))
        << "consume-hold release must republish the binding set (as set_consume(false) does) to lift suppression";
}

// Consume changes no indices or names. Failed rebuild must preserve the name lookup and modifier cache, so bare V
// cannot widen while Shift remains held.
TEST_F(InputPollerTest, ConsumeToggleCacheRebuildFailureRetainsThePriorSnapshot)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    InputSeamReset seam_reset;
    std::atomic<int> key_samples{0};
    std::atomic<int> bare_presses{0};
    detail::g_input_key_state_probe = [&key_samples](int vk) noexcept
    {
        key_samples.fetch_add(1, std::memory_order_relaxed);
        return vk == 0x56 || vk == VK_SHIFT;
    };

    std::vector<detail::InputBinding> bindings;

    detail::InputBinding bare;
    bare.name = "bare_binding_with_a_name_past_the_small_string_buffer";
    bare.keys = {keyboard_key(0x56)};
    bare.on_press = [&bare_presses] { bare_presses.fetch_add(1, std::memory_order_relaxed); };
    bindings.push_back(bare);

    detail::InputBinding chord;
    chord.name = "chord_binding_with_a_name_past_the_small_string_buffer";
    chord.keys = {keyboard_key(0x56)};
    chord.modifiers = {keyboard_key(VK_SHIFT)};
    bindings.push_back(chord);

    detail::InputPoller poller(std::move(bindings), input::DEFAULT_POLL_INTERVAL, /*require_focus=*/false);
    ASSERT_TRUE(poller.acquire_binding_token(bare.name).valid());

    (void)DetourModKit::log();
    {
        // The first rebuild allocation creates the local name index. Its failure reaches the catch.
        dmk_test::AllocFailScope fail(0);
        poller.set_consume(bare.name, true);
    }

    // The Retain policy keeps the name index authoritative, so the control plane is still reachable and can repair
    // itself. A token alone cannot show that, because the degraded-index scan also resolves names.
    EXPECT_TRUE(poller.name_index_authoritative_for_test());
    EXPECT_TRUE(poller.acquire_binding_token(bare.name).valid());
    EXPECT_TRUE(poller.acquire_binding_token(chord.name).valid());

    poller.start();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (key_samples.load(std::memory_order_relaxed) < 2 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::yield();
    }
    poller.shutdown();

    EXPECT_GE(key_samples.load(std::memory_order_relaxed), 2);
    EXPECT_EQ(bare_presses.load(std::memory_order_relaxed), 0)
        << "the retained modifier set must keep bare V blocked while Shift+V is registered";
    EXPECT_EQ(poller.remove_bindings_by_name(chord.name), 1u);
}

// The lookup caches survive rebuild failure. The revoked chord must still leave the game suppression table.
TEST_F(InputPollerTest, ConsumeDisableCacheRebuildFailureStillDisarmsSuppression)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    const uint16_t lb = static_cast<uint16_t>(GamepadCode::LeftBumper);
    const uint16_t up = static_cast<uint16_t>(GamepadCode::DpadUp);
    dmk_test::reset_published_consume_rules();

    detail::InputBinding chord;
    chord.name = "consume_chord_with_a_name_past_the_small_string_buffer";
    chord.modifiers = {gamepad_button(GamepadCode::LeftBumper)};
    chord.keys = {gamepad_button(GamepadCode::DpadUp)};
    chord.consume = true;
    chord.trigger = input::Trigger::Hold;

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(chord);
    detail::InputPoller poller(std::move(bindings));
    // The poller needs interception ownership before its cached rules reach the table. The lease makes the disarm
    // observable.
    ASSERT_TRUE(detail::adopt_owner_for_test(poller.intercept_owner_for_test()));
    poller.publish_consume_rules_for_test();
    ASSERT_EQ(detail::evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), up);

    (void)DetourModKit::log();
    {
        dmk_test::AllocFailScope fail(0);
        poller.set_consume(chord.name, false); // the retirement direction
    }

    // Suppression is gone even though the rebuild failed: the game gets its button back.
    EXPECT_EQ(detail::evaluate_published_consume_rules(static_cast<uint16_t>(lb | up)), 0u);
    EXPECT_EQ(poller.consume_capacity().active, 0u);
    // The lookup caches are still retained, which is the point of the Retain policy.
    EXPECT_TRUE(poller.name_index_authoritative_for_test());
    EXPECT_TRUE(poller.acquire_binding_token(chord.name).valid());

    detail::uninstall(poller.intercept_owner_for_test());
}

namespace DetourModKit::detail
{
    extern void (*g_logger_record_probe)(DetourModKit::LogLevel, std::string_view) noexcept;
} // namespace DetourModKit::detail

namespace
{
    std::atomic<bool> s_consume_warning_entered{false};
    std::atomic<bool> s_consume_warning_release{false};

    // Parks the emitter thread inside the sink at the consume-capacity warning. The test can then check what the
    // emitter still holds while the sink is blocked.
    void block_on_consume_warning(DetourModKit::LogLevel, std::string_view message) noexcept
    {
        if (message.find("gamepad consume chords exceed") == std::string_view::npos)
        {
            return;
        }
        s_consume_warning_entered.store(true, std::memory_order_release);
        while (!s_consume_warning_release.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }
} // namespace

// The sink parks at the overflow warning after the binding lock releases. A callback-safe query must finish while that
// sink stays parked.
TEST_F(InputPollerTest, CallbackSafeQueryCompletesWhileConsumeDiagnosticSinkIsBlocked)
{
    dmk_test::reset_published_consume_rules();
    const LogLevel previous_level = DetourModKit::log().get_log_level();
    DetourModKit::log().set_log_level(LogLevel::Warning);

    // MAX_GAMEPAD_CONSUME_RULES in-table chords plus one late chord: the late transition to consume=true republishes
    // one rule past the table bound and latches the one-per-engine overflow warning.
    std::vector<detail::InputBinding> bindings;
    const int mod_pool[] = {
        GamepadCode::LeftBumper,
        GamepadCode::RightBumper,
        GamepadCode::DpadUp,
        GamepadCode::DpadDown,
        GamepadCode::DpadLeft,
        GamepadCode::DpadRight,
    };
    for (std::size_t i = 0; i < detail::MAX_GAMEPAD_CONSUME_RULES; ++i)
    {
        detail::InputBinding chord;
        chord.name = "table_chord_" + std::to_string(i);
        chord.keys = {gamepad_button(GamepadCode::A)};
        for (std::size_t bit = 0; bit < 6; ++bit)
        {
            if (((i + 1) >> bit) & 1)
            {
                chord.modifiers.push_back(gamepad_button(mod_pool[bit]));
            }
        }
        chord.consume = true;
        bindings.push_back(std::move(chord));
    }
    detail::InputBinding late;
    late.name = "late_chord";
    late.keys = {gamepad_button(GamepadCode::B)};
    bindings.push_back(std::move(late));

    detail::InputPoller poller(std::move(bindings));
    ASSERT_TRUE(detail::adopt_owner_for_test(poller.intercept_owner_for_test()));

    s_consume_warning_entered.store(false, std::memory_order_release);
    s_consume_warning_release.store(false, std::memory_order_release);
    DetourModKit::detail::g_logger_record_probe = &block_on_consume_warning;

    std::thread setter([&poller] { poller.set_consume("late_chord", true); });

    const auto entry_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!s_consume_warning_entered.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < entry_deadline)
    {
        std::this_thread::yield();
    }
    const bool sink_entered = s_consume_warning_entered.load(std::memory_order_acquire);

    if (sink_entered)
    {
        std::atomic<bool> query_done{false};
        std::thread query(
            [&poller, &query_done]
            {
                (void)poller.is_binding_active(0);
                query_done.store(true, std::memory_order_release);
            }
        );
        const auto query_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (!query_done.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < query_deadline)
        {
            std::this_thread::yield();
        }
        const bool query_completed = query_done.load(std::memory_order_acquire);
        s_consume_warning_release.store(true, std::memory_order_release);
        query.join();
        EXPECT_TRUE(query_completed) << "a callback-safe query must complete while the diagnostic sink stays blocked";
    }
    else
    {
        s_consume_warning_release.store(true, std::memory_order_release);
    }
    setter.join();
    DetourModKit::detail::g_logger_record_probe = nullptr;
    DetourModKit::log().set_log_level(previous_level);

    EXPECT_TRUE(sink_entered) << "the consume-capacity warning never reached the sink";

    detail::uninstall(poller.intercept_owner_for_test());
    dmk_test::reset_published_consume_rules();
}
