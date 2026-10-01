#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/input_poller.hpp"

#include "test_alloc_probe.hpp"
#include "fixtures/input_fixture.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;
using namespace dmk_test::input_fixture;

TEST(InputReshapeContract, MutatorsAreNoexcept)
{
    using KCL = input::KeyComboList;
    // The loader-reachable reshape verbs retain their noexcept declarations. Unevaluated declval expressions detect a
    // signature change without a runtime allocation.
    static_assert(
        noexcept(std::declval<input::Input &>().rebind(std::declval<std::string_view>(), std::declval<KCL>())),
        "Input::rebind must stay noexcept (fail-closed)"
    );
    static_assert(
        noexcept(std::declval<input::Input &>().remove_bindings_by_name(std::declval<std::string_view>(), true)),
        "Input::remove_bindings_by_name must stay noexcept (fail-closed)"
    );
    static_assert(
        noexcept(std::declval<input::Input &>().clear_bindings(true)),
        "Input::clear_bindings must stay noexcept (fail-closed)"
    );
    static_assert(
        noexcept(std::declval<input::Input &>().set_consume(std::declval<std::string_view>(), true)),
        "Input::set_consume must stay noexcept (fail-closed)"
    );

    static_assert(
        noexcept(std::declval<detail::InputPoller &>()
                     .update_combos(std::declval<std::string_view>(), std::declval<const KCL &>())),
        "InputPoller::update_combos must stay noexcept (fail-closed)"
    );
    static_assert(
        noexcept(std::declval<detail::InputPoller &>().add_binding(std::declval<detail::InputBinding>())),
        "InputPoller::add_binding must stay noexcept (fail-closed)"
    );
    static_assert(
        noexcept(std::declval<detail::InputPoller &>().add_bindings(std::declval<std::vector<detail::InputBinding>>())),
        "InputPoller::add_bindings must stay noexcept (fail-closed)"
    );
    static_assert(
        noexcept(std::declval<detail::InputPoller &>().remove_bindings_by_name(std::declval<std::string_view>())),
        "InputPoller::remove_bindings_by_name must stay noexcept (fail-closed)"
    );
    static_assert(
        noexcept(std::declval<detail::InputPoller &>().clear_bindings()),
        "InputPoller::clear_bindings must stay noexcept (fail-closed)"
    );
    SUCCEED();
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
    (void)input::register_combo(
        input::ComboBinding{
            .name = "update-pending",
            .trigger = input::Trigger::Press,
            .combos = initial,
            .on_press = []() {},
        }
    );
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x42)}, {}}); // 'B'
    (void)im.rebind("update-pending", replacement);

    // Replacement preserves cardinality.
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

TEST(InputUpdateCombos, CardinalityCanGrow)
{
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    (void)input::register_combo(
        input::ComboBinding{
            .name = "update-grow",
            .trigger = input::Trigger::Press,
            .combos = initial,
            .on_press = []() {},
        }
    );

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
    (void)input::register_combo(
        input::ComboBinding{
            .name = "update-shrink",
            .trigger = input::Trigger::Press,
            .combos = initial,
            .on_press = []() {},
        }
    );

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x44)}, {}});
    (void)im.rebind("update-shrink", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

TEST(InputUpdateCombos, EmptyReplacementUnbindsAndPreservesName)
{
    // Empty replacement leaves one inert sentinel. The name must stay addressable for a later non-empty rebind.
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    (void)input::register_combo(
        input::ComboBinding{
            .name = "update-empty-clear",
            .trigger = input::Trigger::Press,
            .combos = initial,
            .on_press = []() {},
        }
    );
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    input::KeyComboList replacement;
    (void)im.rebind("update-empty-clear", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_FALSE(im.is_active("update-empty-clear"));

    // The sentinel must accept a non-empty rebind.
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

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    (void)input::register_combo(
        input::ComboBinding{
            .name = "update-running",
            .trigger = input::Trigger::Press,
            .combos = initial,
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(5),
        }
    );

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x5A)}, {}}); // 'Z'
    (void)im.rebind("update-running", replacement);

    // Give the poller a cycle to pick up the swap, then tear down.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    EXPECT_TRUE(im.is_running());
    im.shutdown();
}

// Live rebind preserves caller and resource failure classes. The failure leaves the same request ready for retry.
TEST(InputUpdateCombos, LiveRebindTypesAllocationFailureAsOutOfMemory)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}});
    (void)input::register_combo(
        input::ComboBinding{
            .name = "update-live-oom",
            .trigger = input::Trigger::Press,
            .combos = initial,
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(5),
        }
    );
    ASSERT_TRUE(im.is_running());

    // Create both replacement lists before fail injection. The by-value argument then needs no allocation in the
    // failure window.
    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x42)}, {}});
    replacement.push_back({{keyboard_key(0x43)}, {}});
    input::KeyComboList retry = replacement;

    // Warm the process-default logger so the OOM catch's guarded log runs on an already-built logger.
    (void)DetourModKit::log();

    auto live_oom = Result<void>{};
    {
        dmk_test::AllocFailScope fail(0); // fail the first allocation of the live cardinality-change rebuild
        live_oom = im.rebind("update-live-oom", std::move(replacement));
    }
    ASSERT_FALSE(live_oom.has_value()) << "a live rebind under injected allocation failure must fail closed";
    EXPECT_EQ(live_oom.error().code, ErrorCode::OutOfMemory);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    const auto unknown = im.rebind("update-live-absent", retry);
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(unknown.error().code, ErrorCode::InvalidArg);

    ASSERT_TRUE(im.rebind("update-live-oom", retry).has_value());
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));
    im.shutdown();
}

TEST(InputUpdateCombos, ConcurrentUpdateWhilePollerRunning)
{
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    (void)input::register_combo(
        input::ComboBinding{
            .name = "update-stress",
            .trigger = input::Trigger::Press,
            .combos = initial,
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(1),
        }
    );

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
        }
    );

    writer.join();
    stop.store(true, std::memory_order_relaxed);

    EXPECT_TRUE(im.is_running());

    im.shutdown();
    SUCCEED();
}

TEST(InputUpdateCombos, ConcurrentQueriesAndCardinalityUpdatesWhilePollerRunning)
{
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(0x41)}, {}}); // 'A'
    (void)input::register_combo(
        input::ComboBinding{
            .name = "update-query-stress",
            .trigger = input::Trigger::Press,
            .combos = initial,
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(1),
        }
    );

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
            }
        );
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
}

TEST(InputHotReload, RegisterPressWhilePollerRunning)
{
    auto &im = input::Input::instance();
    im.shutdown();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "hr-pre",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    (void)input::register_combo(
        input::ComboBinding{
            .name = "hr-live",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
        }
    );

    // Give the poller a couple of cycles to absorb the new binding.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_TRUE(im.is_running());
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));

    im.shutdown();
}

TEST(InputHotReload, ClearBindingsKeepsPollerRunning)
{
    auto &im = input::Input::instance();
    im.shutdown();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "hr-clear-1",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "hr-clear-2",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    im.clear_bindings();
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(0));
    EXPECT_TRUE(im.is_running());

    // The poller must accept registration after clear without a restart.
    (void)input::register_combo(
        input::ComboBinding{
            .name = "hr-clear-after",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x43)}, {}}},
            .on_press = []() {},
        }
    );
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
}

TEST(InputHotReload, RemoveBindingByNameLive)
{
    auto &im = input::Input::instance();
    im.shutdown();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "hr-keep",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "hr-drop",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    EXPECT_EQ(im.remove_bindings_by_name("hr-drop"), static_cast<size_t>(1));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
}

TEST(InputHotReload, EmptyComboListRegistersSentinelName)
{
    auto &im = input::Input::instance();
    im.shutdown();

    input::KeyComboList empty_combos;
    (void)input::register_combo(
        input::ComboBinding{
            .name = "sentinel",
            .trigger = input::Trigger::Press,
            .combos = empty_combos,
            .on_press = []() {},
        }
    );
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x41)}, {}});
    (void)im.rebind("sentinel", replacement);
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    im.shutdown();
}

// The seam first establishes a held consumer. The cardinality change must deliver on_state_change(false), so the case
// reaches the active-release path.
TEST(InputPollerHoldRebuild, CardinalityChangeFiresReleaseForHeldEntries)
{
    auto &im = input::Input::instance();
    im.shutdown();
    // Resets the key-state seam on any exit (including an ASSERT early-return) so it cannot leak into another test.
    InputFacadeKeySeamCleanup seam_guard;

    constexpr int HELD_VK = 0x41;
    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

    std::atomic<int> holds{0};
    std::atomic<int> releases{0};

    input::KeyComboList initial;
    initial.push_back({{keyboard_key(HELD_VK)}, {}});
    initial.push_back({{keyboard_key(0x42)}, {}});
    auto registration = im.register_combo(
        input::ComboBinding{
            .name = "rebuild-hold",
            .trigger = input::Trigger::Hold,
            .combos = initial,
            .on_state_change = [&](bool pressed) noexcept
            {
                if (pressed)
                {
                    holds.fetch_add(1, std::memory_order_relaxed);
                }
                else
                {
                    releases.fetch_add(1, std::memory_order_relaxed);
                }
            },
        }
    );
    ASSERT_TRUE(registration.has_value()) << "registration must succeed";
    // The guard keeps the callback gate live throughout the test.
    input::BindingGuard guard = std::move(*registration);
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
            .require_focus = false,
        }
    );

    // Wait for the held(true) edge before the rebuild acts on the held entry.
    for (int i = 0; i < 1000 && holds.load(std::memory_order_relaxed) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_EQ(holds.load(std::memory_order_relaxed), 1) << "the hold must be genuinely held before the rebuild";

    // Cardinality change (2 combos -> 1): the entry set is rebuilt, and the dropped held entry must receive the
    // balancing on_state_change(false) the rebuild captures.
    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x43)}, {}});
    (void)im.rebind("rebuild-hold", replacement);

    for (int i = 0; i < 1000 && releases.load(std::memory_order_relaxed) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    EXPECT_EQ(releases.load(std::memory_order_relaxed), 1)
        << "the dropped held entry must receive on_state_change(false)";
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
}

// Surviving entries' atomic state must carry forward across add_binding so a subsequent add_binding does not flicker
// held bindings through one inactive tick. Verifies the binding count and lookup behaviour stay consistent across the
// rebuild.
TEST(InputPollerStatePreservation, AddBindingPreservesSurvivingState)
{
    auto &im = input::Input::instance();
    im.shutdown();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "survive-1",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "survive-2",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );
    ASSERT_EQ(im.binding_count(), static_cast<size_t>(2));

    (void)input::register_combo(
        input::ComboBinding{
            .name = "survive-3",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x43)}, {}}},
            .on_press = []() {},
        }
    );
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(3));
    EXPECT_FALSE(im.is_active("survive-1"));
    EXPECT_FALSE(im.is_active("survive-2"));
    EXPECT_FALSE(im.is_active("survive-3"));
    EXPECT_TRUE(im.is_running());

    im.shutdown();
}

// The live set exceeds the startup callback reserve. An allocation failure during its per-cycle growth must leave the
// poll thread alive.
TEST(InputPollerPollLoopSafety, BindingGrowthPastStartupReserveKeepsPollThreadAlive)
{
    auto &im = input::Input::instance();
    im.shutdown();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "grow-seed",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(1),
        }
    );

    constexpr int extra = 300;
    for (int i = 0; i < extra; ++i)
    {
        (void)input::register_combo(
            input::ComboBinding{
                .name = "grow-" + std::to_string(i),
                .trigger = input::Trigger::Press,
                .combos = {{{keyboard_key(0x41 + (i % 20))}, {}}},
                .on_press = []() {},
            }
        );
    }

    // Let the poll thread run many cycles against the grown binding set.
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    EXPECT_TRUE(im.is_running());
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(extra + 1));

    im.shutdown();
}

// remove_bindings_by_name must preserve each survivor's atomic state. is_active(name) must stay consistent across the
// reshape.
TEST(InputPollerStatePreservation, RemovePreservesSurvivingState)
{
    auto &im = input::Input::instance();
    im.shutdown();

    (void)input::register_combo(
        input::ComboBinding{
            .name = "keep-a",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x41)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "drop",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x42)}, {}}},
            .on_press = []() {},
        }
    );
    (void)input::register_combo(
        input::ComboBinding{
            .name = "keep-b",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x43)}, {}}},
            .on_press = []() {},
        }
    );
    (void)im.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds(2),
        }
    );

    EXPECT_EQ(im.remove_bindings_by_name("drop"), static_cast<size_t>(1));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(im.binding_count(), static_cast<size_t>(2));
    EXPECT_FALSE(im.is_active("drop"));
    EXPECT_FALSE(im.is_active("keep-a"));
    EXPECT_FALSE(im.is_active("keep-b"));

    im.shutdown();
}

// A live multi-combo registration must commit every combo entry.
TEST_F(InputTest, RegisterComboLiveForwardsEveryComboEntry)
{
    auto &mgr = input::Input::instance();
    (void)input::register_combo(
        input::ComboBinding{
            .name = "seed",
            .trigger = input::Trigger::Press,
            .combos = {{{keyboard_key(0x70)}, {}}},
            .on_press = []() {},
        }
    );
    ASSERT_TRUE(mgr.start().has_value());
    ASSERT_EQ(mgr.binding_count(), 1u);

    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "multi",
            .trigger = input::Trigger::Press,
            .combos =
                {
                    {{keyboard_key(0x71)}, {}},
                    {{keyboard_key(0x72)}, {}},
                },
            .on_press = []() {},
        }
    );
    ASSERT_TRUE(guard.has_value());
    EXPECT_EQ(mgr.binding_count(), 3u); // seed + two combo entries
}

// After m_bindings changes, stale indices can exceed the new array. Name queries must find live bindings through the
// fallback scan after rebuild failure.
TEST_F(InputPollerTest, ReshapeCacheRebuildFailureLeavesCachesEmptyAndIndexSafe)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    (void)DetourModKit::log();
    constexpr std::string_view SEED_NAME = "seed_binding_with_a_name_past_the_small_string_buffer";
    constexpr std::string_view EXTRA_NAME = "extra_binding_with_a_name_past_the_small_string_buffer";
    constexpr std::string_view REPAIR_NAME = "repair_binding_with_a_name_past_the_small_string_buffer";
    bool reached_rebuild_failure = false;

    for (long long budget = 0; budget <= 64 && !reached_rebuild_failure; ++budget)
    {
        std::vector<detail::InputBinding> bindings;
        detail::InputBinding seed;
        seed.name = SEED_NAME;
        seed.keys = {keyboard_key(0x70)};
        bindings.push_back(std::move(seed));
        detail::InputPoller poller(std::move(bindings));

        detail::InputBinding extra;
        extra.name = EXTRA_NAME;
        extra.keys = {keyboard_key(0x71)};

        bool added = false;
        {
            dmk_test::AllocFailScope fail(budget);
            added = poller.add_binding(std::move(extra));
        }

        if (!added)
        {
            EXPECT_EQ(poller.binding_count(), 1u) << "budget=" << budget;
            EXPECT_TRUE(poller.acquire_binding_token(SEED_NAME).valid()) << "budget=" << budget;
            continue;
        }

        ASSERT_EQ(poller.binding_count(), 2u) << "budget=" << budget;
        if (poller.name_index_authoritative_for_test())
        {
            EXPECT_TRUE(poller.acquire_binding_token(SEED_NAME).valid()) << "budget=" << budget;
            EXPECT_TRUE(poller.acquire_binding_token(EXTRA_NAME).valid()) << "budget=" << budget;
            continue;
        }

        reached_rebuild_failure = true;
        EXPECT_FALSE(poller.is_binding_active(0));
        EXPECT_FALSE(poller.is_binding_active(1));
        EXPECT_TRUE(poller.has_bindings_by_name(SEED_NAME));
        EXPECT_TRUE(poller.acquire_binding_token(EXTRA_NAME).valid());
        EXPECT_EQ(poller.remove_bindings_by_name(SEED_NAME), 1u);
        EXPECT_TRUE(poller.name_index_authoritative_for_test()) << "the removal's rebuild did not restore the index";
        EXPECT_FALSE(poller.has_bindings_by_name(SEED_NAME));

        detail::InputBinding repair;
        repair.name = REPAIR_NAME;
        repair.keys = {keyboard_key(0x72)};
        ASSERT_TRUE(poller.add_binding(std::move(repair)));
        EXPECT_FALSE(poller.acquire_binding_token(SEED_NAME).valid());
        EXPECT_TRUE(poller.acquire_binding_token(EXTRA_NAME).valid());
        EXPECT_TRUE(poller.acquire_binding_token(REPAIR_NAME).valid());
    }

    EXPECT_TRUE(reached_rebuild_failure) << "allocation sweep never reached the post-reshape cache rebuild";
}

namespace
{
    /**
     * @brief Grows @p poller until one add_binding lands its reshape but fails the cache rebuild after it.
     * @details The first budget that lands the reshape always fails the rebuild, because the rebuild allocates more.
     * @return true when the name index is left non-authoritative.
     */
    [[nodiscard]] bool degrade_name_index(detail::InputPoller &poller)
    {
        for (long long budget = 0; budget <= 64; ++budget)
        {
            detail::InputBinding extra;
            extra.name = "degrading_binding_" + std::to_string(budget) + "_past_the_small_string_buffer";
            extra.keys = {keyboard_key(0x71)};
            bool added = false;
            {
                dmk_test::AllocFailScope fail(budget);
                added = poller.add_binding(std::move(extra));
            }
            if (added && !poller.name_index_authoritative_for_test())
            {
                return true;
            }
        }
        return false;
    }
} // namespace

// Every name verb resolves through the binding scan while a failed rebuild leaves the index non-authoritative, and an
// empty name still addresses no binding. A resolved set_consume or update_combos rebuilds the index, so each verb gets
// its own degraded poller.
TEST_F(InputPollerTest, DegradedIndexNameVerbsResolveByScan)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    (void)DetourModKit::log();
    constexpr std::string_view HELD_NAME = "held_binding_with_a_name_past_the_small_string_buffer";
    constexpr std::string_view SPARE_NAME = "spare_binding_with_a_name_past_the_small_string_buffer";
    constexpr int HELD_VK = 0x70;
    const auto make_bindings = [&]
    {
        std::vector<detail::InputBinding> bindings;
        detail::InputBinding held;
        held.name = HELD_NAME;
        held.keys = {keyboard_key(HELD_VK)};
        bindings.push_back(std::move(held));
        detail::InputBinding spare;
        spare.name = SPARE_NAME;
        spare.keys = {keyboard_key(0x72)};
        bindings.push_back(std::move(spare));
        detail::InputBinding anonymous;
        anonymous.keys = {keyboard_key(0x73)};
        bindings.push_back(std::move(anonymous));
        return bindings;
    };

    {
        detail::InputPoller poller(make_bindings());
        ASSERT_TRUE(degrade_name_index(poller));
        // Only a resolved name can flip the flag, and the flip rebuilds the index.
        poller.set_consume(SPARE_NAME, true);
        EXPECT_TRUE(poller.name_index_authoritative_for_test()) << "set_consume missed a live name";
    }
    {
        detail::InputPoller poller(make_bindings());
        ASSERT_TRUE(degrade_name_index(poller));
        const input::KeyComboList combos{
            input::KeyCombo{{keyboard_key(0x74)}, {}},
            input::KeyCombo{{keyboard_key(0x75)}, {}},
        };
        EXPECT_EQ(poller.update_combos(SPARE_NAME, combos), detail::InputPoller::ComboUpdate::Updated);
    }
    {
        detail::InputPoller poller(make_bindings());
        ASSERT_TRUE(degrade_name_index(poller));
        const std::size_t count = poller.binding_count();
        EXPECT_FALSE(poller.has_bindings_by_name(""));
        EXPECT_EQ(poller.remove_bindings_by_name(""), 0u);
        poller.set_consume("", true);
        EXPECT_FALSE(poller.name_index_authoritative_for_test()) << "set_consume(\"\") reached the anonymous binding";
        EXPECT_EQ(poller.binding_count(), count);
    }
    {
        // Declared before the poller, so the poll thread joins before the probe clears.
        struct ProbeReset
        {
            ~ProbeReset() { detail::g_input_key_state_probe = nullptr; }
        } probe_reset;
        detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };
        detail::InputPoller poller(make_bindings(), std::chrono::milliseconds{2}, false);
        poller.start();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (!poller.is_binding_active(HELD_NAME) && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        ASSERT_TRUE(poller.is_binding_active(HELD_NAME)) << "the held key never activated its binding";
        ASSERT_TRUE(degrade_name_index(poller));
        EXPECT_TRUE(poller.is_binding_active(HELD_NAME)) << "a held binding read inactive through the degraded index";
        poller.shutdown();
    }
}

// Failed state-array growth returns false from add_binding. The caller must not receive a successful registration.
TEST_F(InputPollerTest, AddBindingReturnsFalseWhenGrowthAllocationFails)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    std::vector<detail::InputBinding> bindings;
    detail::InputBinding seed;
    seed.name = "seed";
    seed.keys = {keyboard_key(0x70)};
    bindings.push_back(seed);
    detail::InputPoller poller(std::move(bindings));

    detail::InputBinding extra;
    extra.name = "extra";
    extra.keys = {keyboard_key(0x71)};

    // The process logger initializes before the poisoned window. This isolates binding allocation failure from
    // first-use logger construction.
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

// A failed batch publishes no entries. A consume rule depends on its entry flag, so the guard flag alone cannot remove
// suppression.
TEST_F(InputPollerTest, AddBindingsReturnsFalseWithoutPartialBatchWhenGrowthAllocationFails)
{
    DMK_REQUIRE_PROXY_FREE_STL();
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

// update_combos preserves caller and resource failure classes. A ResourceFailure commits no state.
TEST_F(InputPollerTest, UpdateCombosTypesAllocationFailureAsResourceFailureAndPreservesBindings)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    constexpr std::string_view name = "rebind_oom_name_past_the_small_string_buffer";
    input::KeyComboList grown;
    grown.push_back({{keyboard_key(0x71)}, {}});
    grown.push_back({{keyboard_key(0x72)}, {}});

    // Warm the process-default logger so each OOM diagnostic uses an existing logger.
    (void)DetourModKit::log();

    bool reached_success = false;
    for (long long budget = 0; budget <= 128 && !reached_success; ++budget)
    {
        std::vector<detail::InputBinding> bindings;
        detail::InputBinding seed;
        seed.name = name;
        seed.keys = {keyboard_key(0x70)};
        bindings.push_back(std::move(seed));
        detail::InputPoller poller(std::move(bindings));
        const input::BindingToken token = poller.acquire_binding_token(name);
        ASSERT_TRUE(poller.binding_token_current(token));

        auto outcome = detail::InputPoller::ComboUpdate::NameAbsent;
        {
            dmk_test::AllocFailScope fail(budget);
            outcome = poller.update_combos(name, grown);
        }

        if (outcome == detail::InputPoller::ComboUpdate::ResourceFailure)
        {
            EXPECT_EQ(poller.binding_count(), 1u) << "budget=" << budget;
            EXPECT_TRUE(poller.binding_token_current(token)) << "budget=" << budget;
            EXPECT_TRUE(poller.acquire_binding_token(name).valid()) << "budget=" << budget;
            continue;
        }

        ASSERT_EQ(outcome, detail::InputPoller::ComboUpdate::Updated) << "budget=" << budget;
        reached_success = true;
        EXPECT_EQ(poller.binding_count(), 2u);
        EXPECT_FALSE(poller.binding_token_current(token));
        EXPECT_TRUE(poller.acquire_binding_token(name).valid());
    }

    EXPECT_TRUE(reached_success) << "the allocation sweep never reached a complete cache transaction";

    std::vector<detail::InputBinding> bindings;
    detail::InputBinding seed;
    seed.name = "known";
    bindings.push_back(std::move(seed));
    detail::InputPoller poller(std::move(bindings));
    EXPECT_EQ(poller.update_combos("never_registered", grown), detail::InputPoller::ComboUpdate::NameAbsent);
}
