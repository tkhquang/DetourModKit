#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <new>
#include <string_view>
#include <thread>
#include <utility>

#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/input_binding_lifecycle.hpp"
#include "internal/input_poller.hpp"
#include "internal/input_test_seams.hpp"

#include "test_alloc_probe.hpp"
#include "fixtures/intercept_lease.hpp"
#include "fixtures/log_capture.hpp"
#include "fixtures/input_fixture.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;
using namespace dmk_test::input_fixture;

TEST_F(InputTest, EmptyStartBuildsNoEngineAndLaterRegistrationsStayStagedUntilNextStart)
{
    auto &mgr = input::Input::instance();

    ASSERT_TRUE(mgr.start().has_value());
    EXPECT_FALSE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 0u);

    // The empty start creates no engine. A later registration stays pending until the next start.
    (void)input::register_combo(
        input::ComboBinding{
            .name = "staged_after_empty_start",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = [] {},
        }
    );
    EXPECT_FALSE(mgr.is_running()) << "a post-empty-start registration must not start the engine on its own";
    EXPECT_EQ(mgr.binding_count(), 1u);

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
    (void)input::register_combo(
        input::ComboBinding{
            .name = "consume_pending",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = [] {},
        }
    );
    mgr.set_consume("consume_pending", true);
    mgr.set_consume("nonexistent_binding", true); // unknown name is a no-op
    EXPECT_EQ(mgr.binding_count(), 1u);
}

TEST_F(InputTest, StartAndShutdown)
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
    EXPECT_NO_THROW(mgr.shutdown());
    EXPECT_FALSE(mgr.is_running());
}

TEST_F(InputTest, RestartAfterShutdown)
{
    input::Input &mgr = input::Input::instance();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "first_run",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
    EXPECT_FALSE(mgr.is_running());

    (void)input::register_combo(
        input::ComboBinding{
            .name = "second_run",
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_state_change = [](bool) {},
        }
    );
    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());
    EXPECT_EQ(mgr.binding_count(), 1u);

    mgr.shutdown();
}

TEST_F(InputTest, StartWithCustomPollInterval)
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
    (void)mgr.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds{32},
        }
    );

    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, DoubleStartIgnored)
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

    (void)mgr.start();
    EXPECT_TRUE(mgr.is_running());

    mgr.shutdown();
}

TEST_F(InputTest, SetRequireFocusBeforeStart)
{
    input::Input &mgr = input::Input::instance();

    mgr.set_require_focus(false);
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

    mgr.shutdown();
}

// The pending focus override applies to the first engine. shutdown() discards it, so the next start uses Settings
// again.
TEST_F(InputTest, SetRequireFocusBeforeStartIsHonored)
{
    constexpr int PRESS_VK = 0x75;
    auto &mgr = input::Input::instance();
    std::atomic<int> presses{0};
    InputFacadeKeySeamCleanup cleanup;
    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == PRESS_VK; };

    const input::Input::Settings settings{.poll_interval = std::chrono::milliseconds{2}};
    const auto stage_focus_binding = [&presses]
    {
        return input::register_combo(
            input::ComboBinding{
                .name = "focus_override_press",
                .trigger = input::Trigger::Press,
                .combos = {input::KeyCombo{{keyboard_key(PRESS_VK)}, {}}},
                .on_press = [&presses] { presses.fetch_add(1, std::memory_order_acq_rel); },
            }
        );
    };
    const auto delivered_within = [&presses](std::chrono::milliseconds window)
    {
        const auto deadline = std::chrono::steady_clock::now() + window;
        while (presses.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return presses.load(std::memory_order_acquire) != 0;
    };
    const auto run_arm = [&](bool override_first, bool shutdown_first, std::chrono::milliseconds window)
    {
        presses.store(0, std::memory_order_release);
        if (override_first)
        {
            mgr.set_require_focus(false);
        }
        if (shutdown_first)
        {
            mgr.shutdown();
        }
        auto guard = stage_focus_binding();
        const bool started = guard.has_value() && mgr.start(settings).has_value() && mgr.is_running();
        const bool delivered = started && delivered_within(window);
        mgr.shutdown();
        return std::pair{started, delivered};
    };

    // Control: the default Settings gate on focus, and a headless test process does not own the foreground.
    const auto control = run_arm(false, false, std::chrono::milliseconds{200});
    ASSERT_TRUE(control.first);
    if (control.second)
    {
        GTEST_SKIP() << "this process owns the foreground window, so the focus gate cannot be observed";
    }

    const auto honored = run_arm(true, false, std::chrono::seconds{5});
    ASSERT_TRUE(honored.first);
    EXPECT_TRUE(honored.second) << "start(Settings) discarded the pre-start set_require_focus(false)";

    const auto discarded = run_arm(true, true, std::chrono::milliseconds{200});
    ASSERT_TRUE(discarded.first);
    EXPECT_FALSE(discarded.second) << "shutdown() kept a pending set_require_focus value";
}

// An empty name addresses no binding (ComboBinding::name). The pending verbs before start() follow the live engine,
// so anonymous staged bindings keep their combos, consume flag, and callables.
TEST_F(InputTest, PendingVerbsRefuseEmptyNames)
{
    InputSeamReset seam_reset;
    auto &mgr = input::Input::instance();
    (void)detail::open_input_callback_admission();
    dmk_test::reset_published_consume_rules();

    auto first_token = std::make_shared<int>(0);
    auto second_token = std::make_shared<int>(0);
    const std::weak_ptr<int> first_observer = first_token;
    const std::weak_ptr<int> second_observer = second_token;
    auto first = input::register_combo(
        input::ComboBinding{
            .name = "",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
            .on_press = [keep = std::move(first_token)] {},
        }
    );
    auto second = input::register_combo(
        input::ComboBinding{
            .name = "",
            .trigger = input::Trigger::Press,
            .combos = {{{gamepad_button(GamepadCode::B)}, {}}},
            .on_press = [keep = std::move(second_token)] {},
        }
    );
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(mgr.binding_count(), 2u);

    const auto rebound = mgr.rebind("", {});
    ASSERT_FALSE(rebound.has_value());
    EXPECT_EQ(rebound.error().code, ErrorCode::InvalidArg);
    EXPECT_EQ(mgr.binding_count(), 2u) << "rebind(\"\") collapsed the anonymous staged bindings";
    EXPECT_EQ(mgr.remove_bindings_by_name(""), 0u);
    EXPECT_EQ(mgr.binding_count(), 2u);
    mgr.set_consume("", true);

    const std::string_view names[] = {""};
    EXPECT_EQ(
        mgr.prepare_logic_dll_unload(std::span<const std::string_view>{names}, std::chrono::seconds{2}),
        input::CallbackDrainStatus::Drained
    );
    EXPECT_FALSE(first_observer.expired()) << "the drain retired an anonymous staged binding";
    EXPECT_FALSE(second_observer.expired()) << "the drain retired an anonymous staged binding";
    EXPECT_TRUE(first->is_active());
    EXPECT_EQ(mgr.binding_count(), 2u);

    (void)detail::open_input_callback_admission();
    ASSERT_TRUE(mgr.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1000}}).has_value());
    ASSERT_TRUE(detail::InputTestSeams::adopt_intercept_owner_for_test());
    EXPECT_EQ(mgr.consume_capacity().active, 0u) << "set_consume(\"\") reached an anonymous staged binding";

    mgr.shutdown();
    dmk_test::reset_published_consume_rules();
}

// A no-op second start() must report success even when its diagnostic cannot format. Input::start logs through
// try_log, so a logging failure never becomes an OutOfMemory result.
TEST_F(InputTest, DoubleStartUnderPoisonedAllocatorStaysSuccess)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    auto &mgr = input::Input::instance();
    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "double_start_oom",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_TRUE(guard.has_value());
    ASSERT_TRUE(mgr.start().has_value());
    ASSERT_TRUE(mgr.is_running());

    // The library default stamp outgrows the inline string buffer, so a record allocates whatever an earlier case left
    // configured.
    const dmk_test::LoggerFileCapture capture{LogLevel::Debug, DEFAULT_TIMESTAMP_FORMAT};
    Logger &logger = DetourModKit::log();

    // Premise: an unguarded Debug record allocates in this process, so the poisoned allocator makes it throw.
    bool control_threw = false;
    {
        dmk_test::AllocFailScope fail(0);
        try
        {
            logger.debug("input double-start control record {}", 1);
        }
        catch (const std::bad_alloc &)
        {
            control_threw = true;
        }
    }
    ASSERT_TRUE(control_threw) << "a Debug record did not allocate, so the poisoned start could not fail";

    Result<void> second;
    {
        dmk_test::AllocFailScope fail(0);
        second = mgr.start();
    }
    EXPECT_TRUE(second.has_value()) << "a no-op start() reported error code "
                                    << static_cast<int>(second.has_value() ? ErrorCode{} : second.error().code);
    EXPECT_TRUE(mgr.is_running());
}

TEST_F(InputTest, PendingRemoveOutOfMemoryLeavesBindingsUnchanged)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    auto &mgr = input::Input::instance();
    auto target = input::register_combo(
        input::ComboBinding{
            .name = "remove_oom_target",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = [] {},
        }
    );
    auto survivor = input::register_combo(
        input::ComboBinding{
            .name = "remove_oom_survivor",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_TRUE(target.has_value());
    ASSERT_TRUE(survivor.has_value());
    ASSERT_EQ(mgr.binding_count(), 2u);

    (void)DetourModKit::log();
    std::size_t removed = 1;
    for (std::size_t successful_allocations = 0; successful_allocations < 2; ++successful_allocations)
    {
        {
            dmk_test::AllocFailScope fail(successful_allocations);
            removed = mgr.remove_bindings_by_name("remove_oom_target");
        }

        EXPECT_EQ(removed, 0u);
        EXPECT_EQ(mgr.binding_count(), 2u);
    }

    EXPECT_EQ(mgr.remove_bindings_by_name("remove_oom_target"), 1u);
    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_EQ(mgr.remove_bindings_by_name("remove_oom_survivor"), 1u);
    EXPECT_EQ(mgr.binding_count(), 0u);
}
