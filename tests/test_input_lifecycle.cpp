#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <string>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "DetourModKit/input.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/drain_backoff.hpp"
#include "internal/input_binding_lifecycle.hpp"
#include "internal/input_poller.hpp"
#include "internal/input_intercept.hpp"
#include "internal/input_test_seams.hpp"
#include "internal/input_binding_gate.hpp"

#include "test_alloc_probe.hpp"
#include "fixtures/intercept_lease.hpp"
#include "fixtures/input_fixture.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;
using namespace dmk_test::input_fixture;

// The consume binding exposes guard release through suppression. abandon() preserves that rule, while clear() removes
// it.
TEST_F(InputTest, ScopeAbandonRetainsGuardsWithoutRunningRelease)
{
    auto &mgr = input::Input::instance();
    dmk_test::reset_published_consume_rules();
    const std::uint16_t button = static_cast<std::uint16_t>(GamepadCode::A);

    input::Scope scope;
    {
        auto guard = input::register_combo(
            input::ComboBinding{
                .name = "abandon_consume",
                .trigger = input::Trigger::Press,
                .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                .consume = true,
                .on_press = [] {},
            }
        );
        ASSERT_TRUE(guard.has_value());
        scope.add(std::move(*guard));
    }
    (void)mgr.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds{1000},
        }
    );
    // The engine publishes its consume rules only while it owns the interception layer, which a headless test
    // host cannot reach by installing. Grant it explicitly so the published table reflects this engine.
    ASSERT_TRUE(detail::InputTestSeams::adopt_intercept_owner_for_test());
    ASSERT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button);

    scope.abandon();
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button)
        << "Scope::abandon() must not run guard release, so suppression stays armed";

    mgr.shutdown();
    dmk_test::reset_published_consume_rules();
}

TEST_F(InputTest, ScopeAbandonRetainsConsumerCaptureWithoutDestroyingIt)
{
    auto &mgr = input::Input::instance();
    auto capture = std::make_shared<int>(42);
    const std::weak_ptr<int> observer = capture;

    input::Scope scope;
    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "abandon_capture",
            .trigger = input::Trigger::Press,
            .on_press = [capture] {},
        }
    );
    ASSERT_TRUE(guard.has_value());
    scope.add(std::move(*guard));

    // The retained guard owns the callback after engine removal. abandon() cannot invoke or destroy that capture inside
    // DllMain.
    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::Input);
    scope.abandon();
    EXPECT_EQ(mgr.remove_bindings_by_name("abandon_capture", false), 1u);
    capture.reset();
    EXPECT_FALSE(observer.expired()) << "abandon destroyed a consumer callback capture instead of retaining it";

    // The retention is a deliberate leak, so it must be accounted like every other leak-on-purpose path. An empty
    // Scope has nothing to retain and must not inflate the count, which is what the second abandon pins.
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::Input),
        leaks_before + 1
    ) << "abandon retained a guard container without recording the intentional leak";
    scope.abandon();
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::Input),
        leaks_before + 1
    ) << "abandoning an already-abandoned Scope has nothing to retain and must record nothing";
}

TEST_F(InputTest, ScopeClearRunsGuardReleaseAndLiftsSuppression)
{
    auto &mgr = input::Input::instance();
    dmk_test::reset_published_consume_rules();
    const std::uint16_t button = static_cast<std::uint16_t>(GamepadCode::A);

    input::Scope scope;
    {
        auto guard = input::register_combo(
            input::ComboBinding{
                .name = "clear_consume",
                .trigger = input::Trigger::Press,
                .combos = {{{gamepad_button(GamepadCode::A)}, {}}},
                .consume = true,
                .on_press = [] {},
            }
        );
        ASSERT_TRUE(guard.has_value());
        scope.add(std::move(*guard));
    }
    (void)mgr.start(
        input::Input::Settings{
            .poll_interval = std::chrono::milliseconds{1000},
        }
    );
    // The engine publishes its consume rules only while it owns the interception layer, which a headless test
    // host cannot reach by installing. Grant it explicitly so the published table reflects this engine.
    ASSERT_TRUE(detail::InputTestSeams::adopt_intercept_owner_for_test());
    ASSERT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button);

    scope.clear();
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), 0u)
        << "Scope::clear() runs guard release, which lifts suppression (the control for abandon())";

    mgr.shutdown();
    dmk_test::reset_published_consume_rules();
}

// A reshape between staging and admission must refuse the old generation before its callback begins.
namespace
{
    // docs/design/testing.md owns the join-before-clear order. The cleanup owner follows the poller, and its barrier
    // atomics precede the poller.
    class StagedProbeCleanup
    {
    public:
        StagedProbeCleanup(detail::InputPoller &poller, std::atomic<bool> &allow_dispatch) noexcept
            : StagedProbeCleanup(poller, allow_dispatch, nullptr)
        {
        }

        StagedProbeCleanup(
            detail::InputPoller &poller,
            std::atomic<bool> &allow_dispatch,
            std::atomic<bool> *poller_joined
        ) noexcept
            : m_poller(&poller), m_allow_dispatch(&allow_dispatch), m_poller_joined(poller_joined)
        {
        }

        ~StagedProbeCleanup() noexcept
        {
            m_allow_dispatch->store(true, std::memory_order_release);
            m_poller->shutdown();
            if (m_poller_joined != nullptr)
            {
                m_poller_joined->store(!m_poller->is_running(), std::memory_order_release);
            }
            detail::g_input_post_stage_probe = nullptr;
        }

        StagedProbeCleanup(const StagedProbeCleanup &) = delete;
        StagedProbeCleanup &operator=(const StagedProbeCleanup &) = delete;

    private:
        detail::InputPoller *m_poller;
        std::atomic<bool> *m_allow_dispatch;
        std::atomic<bool> *m_poller_joined;
    };

    template <typename Transition>
    [[nodiscard]] bool
    wait_for_staged_operation(const std::atomic<bool> &operation_returned, Transition transition) noexcept
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (!transition() && !operation_returned.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::yield();
        }
        return transition();
    }

    struct StagedReshapeResult
    {
        bool staged; // a press was staged this run (so the refusal, if any, was actually exercised)
        int presses; // press callbacks that actually fired
    };

    // The final callable destructor must observe a nonzero staged lease count. A plain live-copy count cannot
    // distinguish early lease release.
    class TrackedCallback
    {
    public:
        TrackedCallback(std::atomic<int> &instances, std::atomic<std::uint32_t> &staged_at_destruction) noexcept
            : m_instances(&instances), m_staged_at_destruction(&staged_at_destruction)
        {
            m_instances->fetch_add(1, std::memory_order_relaxed);
        }

        TrackedCallback(const TrackedCallback &other) noexcept
            : m_instances(other.m_instances), m_staged_at_destruction(other.m_staged_at_destruction)
        {
            m_instances->fetch_add(1, std::memory_order_relaxed);
        }

        TrackedCallback(TrackedCallback &&other) noexcept
            : m_instances(other.m_instances), m_staged_at_destruction(other.m_staged_at_destruction)
        {
            m_instances->fetch_add(1, std::memory_order_relaxed);
        }

        ~TrackedCallback() noexcept
        {
            m_staged_at_destruction->store(detail::staged_input_callback_count(), std::memory_order_release);
            m_instances->fetch_sub(1, std::memory_order_relaxed);
        }

        void operator()() const noexcept {}

        TrackedCallback &operator=(const TrackedCallback &) = delete;
        TrackedCallback &operator=(TrackedCallback &&) = delete;

    private:
        std::atomic<int> *m_instances;
        std::atomic<std::uint32_t> *m_staged_at_destruction;
    };

    // Drives a Press binding through a reshape performed on a control thread after staging and before admission.
    StagedReshapeResult run_staged_reshape(const std::function<void(detail::InputPoller &)> &reshape)
    {
        InputSeamReset seam_reset;
        constexpr int HELD_VK = 0x41;

        std::atomic<int> presses{0};
        auto lifecycle = detail::make_binding_lifecycle();
        const std::uint64_t initial_generation = lifecycle->generation();
        std::vector<detail::InputBinding> bindings(1);
        bindings[0].name = "P";
        bindings[0].keys = {keyboard_key(HELD_VK)};
        bindings[0].trigger = input::Trigger::Press;
        bindings[0].on_press = [&presses] { presses.fetch_add(1, std::memory_order_relaxed); };
        bindings[0].lifecycle = lifecycle;

        detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

        // Declared before the poller so the probe's captures outlive the poll thread on every exit.
        std::atomic<bool> staged{false};
        std::atomic<bool> allow_dispatch{false};

        detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{2}, /*require_focus=*/false);
        const StagedProbeCleanup cleanup{poller, allow_dispatch};

        // Installed while the poller is stopped: the poll loop reads this global without synchronization.
        detail::g_input_post_stage_probe = [&](std::size_t count)
        {
            if (count > 0 && !staged.exchange(true, std::memory_order_acq_rel))
            {
                while (!allow_dispatch.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
            }
        };

        poller.start();
        for (int i = 0; i < 1000 && !staged.load(std::memory_order_acquire); ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }
        if (staged.load(std::memory_order_acquire) && reshape)
        {
            std::thread reshaper([&] { reshape(poller); });
            while (!lifecycle->tombstoned() && lifecycle->generation() == initial_generation)
            {
                std::this_thread::yield();
            }
            allow_dispatch.store(true, std::memory_order_release);
            reshaper.join();
        }
        else
        {
            allow_dispatch.store(true, std::memory_order_release);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
        return {staged.load(std::memory_order_acquire), presses.load(std::memory_order_relaxed)};
    }
} // namespace

TEST(InputLifecycleProof, TypedDrainWaitsUntilStagedCallableStorageIsDestroyed)
{
    InputSeamReset seam_reset;
    constexpr int HELD_VK = 0x41;
    input::Input::instance().shutdown();
    (void)detail::open_input_callback_admission();

    std::atomic<int> callable_instances{0};
    std::atomic<std::uint32_t> staged_at_last_destruction{0};
    detail::InputBinding binding;
    binding.name = "staged_storage";
    binding.keys = {keyboard_key(HELD_VK)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = TrackedCallback{callable_instances, staged_at_last_destruction};
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));

    std::atomic<bool> staged{false};
    std::atomic<bool> allow_dispatch{false};
    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };
    detail::g_input_post_stage_probe = [&](std::size_t count)
    {
        if (count != 0 && !staged.exchange(true, std::memory_order_acq_rel))
        {
            while (!allow_dispatch.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }
    };

    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{2}, false);
    const StagedProbeCleanup cleanup{poller, allow_dispatch};
    poller.start();
    for (int i = 0; i < 1000 && !staged.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(staged.load(std::memory_order_acquire));

    EXPECT_EQ(poller.remove_bindings_by_name("staged_storage", false), 1u);
    EXPECT_GT(callable_instances.load(std::memory_order_acquire), 0)
        << "the staged std::function target must still be alive while dispatch is parked";

    EXPECT_EQ(
        input::Input::instance().prepare_logic_dll_unload({}, std::chrono::milliseconds{20}),
        input::CallbackDrainStatus::TimedOut
    );
    auto rejected = input::register_combo(
        input::ComboBinding{
            .name = "must_not_register_during_retry",
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x42)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, ErrorCode::ShutdownInProgress);

    std::atomic<bool> drain_returned{false};
    input::CallbackDrainStatus drain_status = input::CallbackDrainStatus::TimedOut;
    std::thread drainer(
        [&]
        {
            drain_status = input::Input::instance().prepare_logic_dll_unload({}, std::chrono::seconds{2});
            drain_returned.store(true, std::memory_order_release);
        }
    );

    std::this_thread::sleep_for(std::chrono::milliseconds{30});
    EXPECT_FALSE(drain_returned.load(std::memory_order_acquire));

    allow_dispatch.store(true, std::memory_order_release);
    drainer.join();
    EXPECT_EQ(drain_status, input::CallbackDrainStatus::Drained);
    EXPECT_EQ(callable_instances.load(std::memory_order_acquire), 0)
        << "Drained must include destruction of the staged callable target";
    EXPECT_GT(staged_at_last_destruction.load(std::memory_order_acquire), 0u)
        << "the staging lease must still be held while the callable it covers is destroyed; a lease released first "
           "would let the drain report Drained with the callable and its captures still alive";

    ASSERT_TRUE(input::Input::instance().start().has_value());
    // The poll loop reads this plain seam each cycle. The join must precede seam removal.
    poller.shutdown();
    detail::g_input_post_stage_probe = nullptr;
}

// The pending facade entry and guard share a delivery gate. Removal drops DMK's owner but must retire the callable
// before the guard ends.
TEST(InputLifecycleProof, TypedDrainRetiresAStagedBindingGateBeforeItEverStarts)
{
    InputSeamReset seam_reset;
    constexpr std::string_view BINDING_NAME = "staged_gate_retire";
    input::Input::instance().shutdown();
    (void)detail::open_input_callback_admission();

    auto token = std::make_shared<int>(0);
    const std::weak_ptr<int> observer = token;
    auto guard = input::register_combo(
        input::ComboBinding{
            .name = std::string{BINDING_NAME},
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x41)}, {}}},
            .on_press = [keep = std::move(token)] {},
        }
    );
    ASSERT_TRUE(guard.has_value());
    ASSERT_FALSE(observer.expired());
    ASSERT_EQ(input::Input::instance().binding_count(), 1u) << "the binding must be staged, with no poller published";

    // Deliberately retained across the drain, exactly as the live-poller Logic-DLL proofs do.
    const std::string_view names[] = {BINDING_NAME};
    EXPECT_EQ(
        input::Input::instance()
            .prepare_logic_dll_unload(std::span<const std::string_view>{names}, std::chrono::seconds{2}),
        input::CallbackDrainStatus::Drained
    );
    EXPECT_TRUE(
        observer.expired()
    ) << "a staged binding's gate-owned callable must be destroyed by the drain, not left in the retained guard";
    EXPECT_FALSE(guard->is_active()) << "a retired binding must be inactive through the retained guard";

    *guard = input::BindingGuard{};
    EXPECT_TRUE(observer.expired()) << "a later guard release must have nothing left to destroy";
}

// A failed cache rebuild on the live engine empties its name index. A named drain must still retire the binding by a
// scan of the binding set, so Drained never covers a live callable ([B-74]).
TEST(InputLifecycleProof, NamedDrainAfterDegradedIndexRetiresTheBinding)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    InputSeamReset seam_reset;
    constexpr std::string_view VICTIM_NAME = "degraded_index_victim_with_a_name_past_the_small_string_buffer";
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    (void)detail::open_input_callback_admission();
    (void)DetourModKit::log();

    auto token = std::make_shared<int>(0);
    const std::weak_ptr<int> observer = token;
    auto victim = input::register_combo(
        input::ComboBinding{
            .name = std::string{VICTIM_NAME},
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x41)}, {}}},
            .on_press = [keep = std::move(token)] {},
        }
    );
    ASSERT_TRUE(victim.has_value());
    ASSERT_TRUE(mgr.start().has_value());

    // Sweep budgets until one registration lands its reshape but fails the cache rebuild that follows it.
    std::vector<input::BindingGuard> fillers;
    fillers.reserve(65);
    bool degraded = false;
    for (long long budget = 0; budget <= 64 && !degraded; ++budget)
    {
        input::ComboBinding filler{
            .name = "degraded_index_filler_" + std::to_string(budget) + "_past_the_small_string_buffer",
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x42)}, {}}},
            .on_press = [] {},
        };
        Result<input::BindingGuard> added = std::unexpected(Error{ErrorCode::OutOfMemory, "sweep"});
        {
            dmk_test::AllocFailScope fail(budget);
            added = input::register_combo(std::move(filler));
        }
        if (added.has_value())
        {
            degraded = detail::InputTestSeams::live_name_index_degraded_for_test();
            fillers.push_back(std::move(*added));
        }
    }
    ASSERT_TRUE(degraded) << "no allocation budget reached the post-reshape cache rebuild failure";
    ASSERT_FALSE(observer.expired());
    const std::size_t before = mgr.binding_count();

    const std::string_view names[] = {VICTIM_NAME};
    EXPECT_EQ(
        mgr.prepare_logic_dll_unload(std::span<const std::string_view>{names}, std::chrono::seconds{2}),
        input::CallbackDrainStatus::Drained
    );
    EXPECT_TRUE(observer.expired()) << "the drain reported Drained while the named callable stayed alive";
    EXPECT_FALSE(victim->is_active());
    EXPECT_EQ(mgr.binding_count(), before - 1) << "the drain left the named binding registered";
    EXPECT_FALSE(mgr.acquire_token(VICTIM_NAME).valid());

    fillers.clear();
    *victim = input::BindingGuard{};
    mgr.shutdown();
}

TEST_F(InputTest, ScopeClearKeepsAGuardAddedFromAReleaseCallback)
{
    constexpr int HELD_VK = 0x41;
    auto &mgr = input::Input::instance();
    std::vector<int> release_order;
    std::atomic<int> active_callbacks{0};
    std::atomic<bool> late_active{false};
    bool late_released = false;
    input::BindingGuard late;
    input::Scope scope;
    InputFacadeKeySeamCleanup cleanup;
    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

    auto late_registration = input::register_combo(
        input::ComboBinding{
            .name = "scope_reentry_late",
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(HELD_VK)}, {}}},
            .on_state_change = [&late_active, &late_released](bool active)
            {
                if (active)
                {
                    late_active.store(true, std::memory_order_release);
                    return;
                }
                late_released = true;
            },
        }
    );
    ASSERT_TRUE(late_registration.has_value());
    late = std::move(*late_registration);

    for (int index = 0; index < 3; ++index)
    {
        auto guard = input::register_combo(
            input::ComboBinding{
                .name = "scope_reentry_" + std::to_string(index),
                .trigger = input::Trigger::Hold,
                .combos = {{{keyboard_key(HELD_VK)}, {}}},
                .on_state_change = [index, &active_callbacks, &release_order, &scope, &late](bool active)
                {
                    if (active)
                    {
                        active_callbacks.fetch_add(1, std::memory_order_release);
                        return;
                    }
                    release_order.push_back(index);
                    if (index == 2)
                    {
                        scope.add(std::move(late));
                    }
                },
            }
        );
        ASSERT_TRUE(guard.has_value());
        scope.add(std::move(*guard));
    }

    ASSERT_TRUE(mgr.start(
                       input::Input::Settings{
                           .poll_interval = std::chrono::milliseconds{2},
                           .require_focus = false,
                       }
    )
                    .has_value());
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < deadline &&
           (active_callbacks.load(std::memory_order_acquire) != 3 || !late_active.load(std::memory_order_acquire)))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    ASSERT_EQ(active_callbacks.load(std::memory_order_acquire), 3) << "the poll loop missed an initial held callback";
    ASSERT_TRUE(late_active.load(std::memory_order_acquire)) << "the poll loop missed the late held callback";

    scope.clear();

    EXPECT_EQ(release_order, (std::vector<int>{2, 1, 0}))
        << "the clear must release its own batch in reverse insertion order, once each";
    EXPECT_FALSE(late_released) << "a guard added during the release belongs to the next clear, not this one";
    EXPECT_EQ(scope.size(), 1u) << "the guard added during the release must survive the outer clear";

    scope.clear();
    EXPECT_TRUE(late_released) << "the next clear must release the guard the first one carried over";
    EXPECT_EQ(scope.size(), 0u);
    EXPECT_EQ(release_order, (std::vector<int>{2, 1, 0})) << "a second clear must not re-release the old batch";
}

TEST(InputLifecycleProof, DrainWaitsForAnAdmittedRegistrationBeforeRetiringItsName)
{
    InputSeamReset seam_reset;
    auto &manager = input::Input::instance();
    manager.shutdown();
    detail::resolve_input_callback_drain();
    (void)detail::open_input_callback_admission();

    s_callback_commit_parked.store(false, std::memory_order_release);
    s_release_callback_commit.store(false, std::memory_order_release);
    detail::InputTestSeams::set_callback_admission_commit_seam_for_test(&park_callback_commit);

    std::atomic<bool> registration_succeeded{false};
    std::thread registrar(
        [&]
        {
            auto result = input::register_combo(
                input::ComboBinding{
                    .name = "drain_registration_overlap",
                    .trigger = input::Trigger::Press,
                    .combos = {input::KeyCombo{{keyboard_key(0x41)}, {}}},
                    .on_press = [] {},
                }
            );
            registration_succeeded.store(result.has_value(), std::memory_order_release);
        }
    );
    const auto commit_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!s_callback_commit_parked.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < commit_deadline)
    {
        std::this_thread::yield();
    }
    if (!s_callback_commit_parked.load(std::memory_order_acquire))
    {
        s_release_callback_commit.store(true, std::memory_order_release);
        registrar.join();
        FAIL() << "registration never reached the admission seam";
        return;
    }

    const std::string_view names[] = {"drain_registration_overlap"};
    const std::uint64_t sleeps_before = detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
    std::atomic<bool> drain_returned{false};
    input::CallbackDrainStatus drain_status = input::CallbackDrainStatus::TimedOut;
    std::thread drainer(
        [&]
        {
            drain_status = manager.prepare_logic_dll_unload(names, std::chrono::seconds{2});
            drain_returned.store(true, std::memory_order_release);
        }
    );

    const auto backoff_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed) == sleeps_before &&
           !drain_returned.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < backoff_deadline)
    {
        std::this_thread::yield();
    }
    EXPECT_FALSE(drain_returned.load(std::memory_order_acquire));
    EXPECT_GT(detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed), sleeps_before)
        << "the admission-commit drain must reach the sleep tier";

    s_release_callback_commit.store(true, std::memory_order_release);
    registrar.join();
    drainer.join();

    EXPECT_TRUE(registration_succeeded.load(std::memory_order_acquire));
    EXPECT_EQ(drain_status, input::CallbackDrainStatus::Drained);
    EXPECT_EQ(manager.binding_count(), 0u);
    ASSERT_TRUE(manager.start().has_value());
}

TEST(InputLifecycleProof, TimedOutDrainCannotBeReopenedByAnAdmittedStart)
{
    InputSeamReset seam_reset;
    auto &manager = input::Input::instance();
    manager.shutdown();
    detail::resolve_input_callback_drain();
    (void)detail::open_input_callback_admission();

    auto guard = input::register_combo(
        input::ComboBinding{
            .name = "drain_start_overlap",
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x41)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_TRUE(guard.has_value());

    s_callback_commit_parked.store(false, std::memory_order_release);
    s_release_callback_commit.store(false, std::memory_order_release);
    detail::InputTestSeams::set_callback_admission_commit_seam_for_test(&park_callback_commit);

    std::atomic<bool> start_succeeded{true};
    ErrorCode start_error = ErrorCode::Unknown;
    std::thread starter(
        [&]
        {
            const Result<void> result = manager.start();
            start_succeeded.store(result.has_value(), std::memory_order_release);
            if (!result)
            {
                start_error = result.error().code;
            }
        }
    );
    while (!s_callback_commit_parked.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    EXPECT_EQ(
        manager.prepare_logic_dll_unload_all(std::chrono::milliseconds{20}),
        input::CallbackDrainStatus::TimedOut
    );
    EXPECT_FALSE(detail::input_callback_admission_open());

    auto rejected = input::register_combo(
        input::ComboBinding{
            .name = "must_not_register_after_start_overlap",
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x42)}, {}}},
            .on_press = [] {},
        }
    );
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, ErrorCode::ShutdownInProgress);

    s_release_callback_commit.store(true, std::memory_order_release);
    starter.join();
    EXPECT_FALSE(start_succeeded.load(std::memory_order_acquire));
    EXPECT_EQ(start_error, ErrorCode::ShutdownInProgress);
    EXPECT_FALSE(detail::input_callback_admission_open());

    detail::InputTestSeams::set_callback_admission_commit_seam_for_test(nullptr);
    EXPECT_EQ(manager.prepare_logic_dll_unload_all(std::chrono::seconds{2}), input::CallbackDrainStatus::Drained);
    ASSERT_TRUE(manager.start().has_value());
    auto rearmed = input::register_combo(
        input::ComboBinding{
            .name = "registration_after_start_retry",
            .trigger = input::Trigger::Press,
            .combos = {input::KeyCombo{{keyboard_key(0x43)}, {}}},
            .on_press = [] {},
        }
    );
    EXPECT_TRUE(rearmed.has_value());
}

// The control makes a zero in the reshape cases meaningful: the same staged press fires without a reshape.
TEST(InputLifecycleProof, StagedCallbackFiresWithoutReshape)
{
    const StagedReshapeResult result = run_staged_reshape({});
    EXPECT_TRUE(result.staged) << "a press must have been staged for the control to be meaningful";
    EXPECT_GE(result.presses, 1) << "an un-reshaped staged press must be delivered";
}

// A cardinality-preserving rebind refuses a press staged from the previous generation.
TEST(InputLifecycleProof, RebindRejectsStagedOldGeneration)
{
    const StagedReshapeResult result = run_staged_reshape(
        [](detail::InputPoller &poller)
        {
            const input::KeyComboList rebound = {input::KeyCombo{{keyboard_key(0x42)}, {}}};
            (void)poller.update_combos("P", rebound);
        }
    );
    EXPECT_TRUE(result.staged) << "a press must have been staged and then rebound to exercise the refusal";
    EXPECT_EQ(result.presses, 0) << "a press staged before the rebind must be refused at dispatch (old generation)";
}

// Remove tombstones the binding, so a press staged before the removal is refused at dispatch.
TEST(InputLifecycleProof, RemoveRejectsStagedOldGeneration)
{
    const StagedReshapeResult result =
        run_staged_reshape([](detail::InputPoller &poller) { (void)poller.remove_bindings_by_name("P"); });
    EXPECT_TRUE(result.staged) << "a press must have been staged and then removed to exercise the refusal";
    EXPECT_EQ(result.presses, 0) << "a press staged before the removal must be refused at dispatch (tombstoned)";
}

// Clear tombstones every binding, so a press staged before the clear is refused at dispatch.
TEST(InputLifecycleProof, ClearRejectsStagedOldGeneration)
{
    const StagedReshapeResult result = run_staged_reshape([](detail::InputPoller &poller) { poller.clear_bindings(); });
    EXPECT_TRUE(result.staged) << "a press must have been staged and then cleared to exercise the refusal";
    EXPECT_EQ(result.presses, 0) << "a press staged before the clear must be refused at dispatch (tombstoned)";
}

// An invocation admitted before rebind can finish. Rebind cannot return before an admitted invocation begins.
TEST(InputLifecycleProof, RebindDrainsAdmittedOldGenerationBeforeReturning)
{
    InputSeamReset seam_reset;
    constexpr int HELD_VK = 0x41;

    std::atomic<int> presses{0};
    std::atomic<bool> admitted{false};
    std::atomic<bool> allow_callback{false};
    auto lifecycle = detail::make_binding_lifecycle();
    const std::uint64_t staged_generation = lifecycle->generation();

    detail::InputBinding binding;
    binding.name = "P";
    binding.keys = {keyboard_key(HELD_VK)};
    binding.trigger = input::Trigger::Press;
    binding.on_press = [&presses] { presses.fetch_add(1, std::memory_order_relaxed); };
    binding.lifecycle = lifecycle;
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));

    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };
    detail::g_input_pre_dispatch_probe = [&]
    {
        admitted.store(true, std::memory_order_release);
        while (!allow_callback.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    };

    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{2}, /*require_focus=*/false);
    poller.start();
    const auto admission_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!admitted.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < admission_deadline)
    {
        std::this_thread::yield();
    }
    if (!admitted.load(std::memory_order_acquire))
    {
        allow_callback.store(true, std::memory_order_release);
        poller.shutdown();
        FAIL() << "the poller never admitted the staged callback";
        return;
    }

    const std::uint64_t sleeps_before = detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
    std::atomic<bool> rebind_returned{false};
    std::thread rebind_thread(
        [&]
        {
            const input::KeyComboList rebound = {input::KeyCombo{{keyboard_key(0x42)}, {}}};
            (void)poller.update_combos("P", rebound);
            rebind_returned.store(true, std::memory_order_release);
        }
    );

    const bool generation_advanced =
        wait_for_staged_operation(rebind_returned, [&] { return lifecycle->generation() != staged_generation; });
    const auto backoff_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed) == sleeps_before &&
           !rebind_returned.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < backoff_deadline)
    {
        std::this_thread::yield();
    }
    EXPECT_FALSE(rebind_returned.load(std::memory_order_acquire));
    EXPECT_GT(detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed), sleeps_before)
        << "the binding-rundown drain must reach the sleep tier";

    allow_callback.store(true, std::memory_order_release);
    rebind_thread.join();
    poller.shutdown();

    EXPECT_TRUE(generation_advanced);
    EXPECT_TRUE(rebind_returned.load(std::memory_order_acquire));
    EXPECT_EQ(presses.load(std::memory_order_relaxed), 1);
}

// A terminal release(false) remains valid across the rebind generation. The held(true) edge cannot cross that
// generation.
TEST(InputLifecycleProof, InPlaceRebindStillDeliversStagedReleaseEdge)
{
    InputSeamReset seam_reset;
    constexpr int HELD_VK = 0x41;
    constexpr int NEW_VK = 0x42;

    std::atomic<bool> key_down{true};
    detail::g_input_key_state_probe = [&key_down](int vk) noexcept
    { return vk == HELD_VK && key_down.load(std::memory_order_acquire); };

    std::atomic<int> holds{0};
    std::atomic<int> releases{0};
    auto lifecycle = detail::make_binding_lifecycle();
    const std::uint64_t initial_generation = lifecycle->generation();

    detail::InputBinding binding;
    binding.name = "H";
    binding.keys = {keyboard_key(HELD_VK)};
    binding.trigger = input::Trigger::Hold;
    binding.lifecycle = lifecycle;
    binding.on_state_change = [&](bool held)
    {
        if (held)
        {
            holds.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            releases.fetch_add(1, std::memory_order_relaxed);
        }
    };
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));

    // The probe installs while the poller is stopped. Its barriers precede the poller and arm after the held edge, so
    // their lifetime spans shutdown.
    std::atomic<bool> park_release{false};
    std::atomic<bool> release_staged{false};
    std::atomic<bool> allow_dispatch{false};

    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{2}, /*require_focus=*/false);
    const StagedProbeCleanup cleanup{poller, allow_dispatch};

    // Pause dispatch the moment the release edge is staged so the rebind lands in the stage->dispatch window.
    detail::g_input_post_stage_probe = [&](std::size_t count)
    {
        if (count > 0 && park_release.load(std::memory_order_acquire) &&
            !release_staged.exchange(true, std::memory_order_acq_rel))
        {
            while (!allow_dispatch.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }
    };

    poller.start();

    for (int i = 0; i < 1000 && holds.load(std::memory_order_relaxed) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_EQ(holds.load(std::memory_order_relaxed), 1) << "the binding must be genuinely held first";

    park_release.store(true, std::memory_order_release);
    key_down.store(false, std::memory_order_release); // release the key: the next poll stages the false edge
    for (int i = 0; i < 1000 && !release_staged.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(release_staged.load(std::memory_order_acquire)) << "the release edge must have been staged";

    // In-place rebind (same cardinality) advances the generation while the release sits staged and undispatched.
    const input::KeyComboList rebound = {input::KeyCombo{{keyboard_key(NEW_VK)}, {}}};
    std::atomic<bool> rebind_returned{false};
    std::atomic<bool> rebind_succeeded{false};
    std::thread rebind_thread(
        [&]
        {
            rebind_succeeded.store(
                poller.update_combos("H", rebound) == detail::InputPoller::ComboUpdate::Updated,
                std::memory_order_release
            );
            rebind_returned.store(true, std::memory_order_release);
        }
    );
    const bool generation_advanced =
        wait_for_staged_operation(rebind_returned, [&] { return lifecycle->generation() != initial_generation; });
    allow_dispatch.store(true, std::memory_order_release);
    rebind_thread.join();
    ASSERT_TRUE(generation_advanced) << "the in-place rebind returned or timed out before advancing generation";
    ASSERT_TRUE(rebind_returned.load(std::memory_order_acquire));
    ASSERT_TRUE(rebind_succeeded.load(std::memory_order_acquire));

    for (int i = 0; i < 1000 && releases.load(std::memory_order_relaxed) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    poller.shutdown();

    EXPECT_EQ(releases.load(std::memory_order_relaxed), 1)
        << "a release staged before an in-place rebind must still be delivered, not stranded";
    EXPECT_EQ(holds.load(std::memory_order_relaxed), 1);
}

namespace
{
    // Lifetime canary captured BY VALUE in a staging probe, so its last destruction is the moment the probe's captures
    // die. What it records there is the ordering StagedProbeCleanup exists to guarantee: the poll thread was already
    // joined. Copies are counted so the record is taken exactly once, on the last one, the way TrackedCallback does.
    class ProbeLifetimeCanary
    {
    public:
        ProbeLifetimeCanary(
            std::atomic<int> &instances,
            const std::atomic<bool> &poller_joined,
            std::atomic<bool> &joined_at_last_destruction
        ) noexcept
            : m_instances(&instances), m_poller_joined(&poller_joined),
              m_joined_at_last_destruction(&joined_at_last_destruction)
        {
            m_instances->fetch_add(1, std::memory_order_relaxed);
        }

        ProbeLifetimeCanary(const ProbeLifetimeCanary &other) noexcept
            : m_instances(other.m_instances), m_poller_joined(other.m_poller_joined),
              m_joined_at_last_destruction(other.m_joined_at_last_destruction)
        {
            m_instances->fetch_add(1, std::memory_order_relaxed);
        }

        ProbeLifetimeCanary(ProbeLifetimeCanary &&other) noexcept
            : m_instances(other.m_instances), m_poller_joined(other.m_poller_joined),
              m_joined_at_last_destruction(other.m_joined_at_last_destruction)
        {
            m_instances->fetch_add(1, std::memory_order_relaxed);
        }

        ~ProbeLifetimeCanary() noexcept
        {
            if (m_instances->fetch_sub(1, std::memory_order_acq_rel) == 1)
            {
                m_joined_at_last_destruction->store(
                    m_poller_joined->load(std::memory_order_acquire),
                    std::memory_order_release
                );
            }
        }

        ProbeLifetimeCanary &operator=(const ProbeLifetimeCanary &) = delete;
        ProbeLifetimeCanary &operator=(ProbeLifetimeCanary &&) = delete;

    private:
        std::atomic<int> *m_instances;
        const std::atomic<bool> *m_poller_joined;
        std::atomic<bool> *m_joined_at_last_destruction;
    };
} // namespace

// StagedProbeCleanupJoinsBeforeDestroyingProbeCaptures isolates the cleanup order on an abandoned premise. The probe
// and its captures must outlive the joined thread.
TEST(InputLifecycleProof, StagedProbeCleanupJoinsBeforeDestroyingProbeCaptures)
{
    InputSeamReset seam_reset;
    constexpr int HELD_VK = 0x41;

    std::atomic<int> canary_instances{0};
    std::atomic<bool> poller_joined{false};
    std::atomic<bool> joined_at_last_destruction{false};
    std::atomic<int> probe_calls{0};
    std::atomic<bool> probe_parked{false};
    std::atomic<bool> allow_dispatch{false};

    detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

    {
        detail::InputBinding binding;
        binding.name = "cleanup_control";
        binding.keys = {keyboard_key(HELD_VK)};
        binding.trigger = input::Trigger::Press;
        binding.on_press = [] {};
        std::vector<detail::InputBinding> bindings;
        bindings.push_back(std::move(binding));

        detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{2}, /*require_focus=*/false);
        const StagedProbeCleanup cleanup{poller, allow_dispatch, &poller_joined};

        detail::g_input_post_stage_probe =
            [&probe_calls,
             &probe_parked,
             &allow_dispatch,
             canary = ProbeLifetimeCanary{canary_instances, poller_joined, joined_at_last_destruction}](std::size_t)
        {
            probe_calls.fetch_add(1, std::memory_order_relaxed);
            probe_parked.store(true, std::memory_order_release);
            while (!allow_dispatch.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        };

        poller.start();
        for (int i = 0; i < 1000 && !probe_parked.load(std::memory_order_acquire); ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }
        EXPECT_TRUE(probe_parked.load(std::memory_order_acquire))
            << "the control has to reach the parked state it is a control for";
        // Scope exit without manual release models the abandoned premise.
    }

    EXPECT_GT(probe_calls.load(std::memory_order_relaxed), 0) << "the probe must actually have run";
    EXPECT_EQ(canary_instances.load(std::memory_order_acquire), 0)
        << "clearing the probe must destroy every capture it owned";
    EXPECT_TRUE(joined_at_last_destruction.load(std::memory_order_acquire))
        << "the probe's captures must outlive the poll-thread join; destroying them first frees state a parked poll "
           "frame is still reading";
    EXPECT_FALSE(static_cast<bool>(detail::g_input_post_stage_probe));
}

// The poll loop clears m_active_states before dispatch. The removed entry refuses its staged false, so gate-backed
// synthesis must provide the terminal release.
TEST(InputLifecycleProof, RemoveDeliversBalancingReleaseWhenKeyReleasesConcurrently)
{
    InputSeamReset seam_reset;
    constexpr int HELD_VK = 0x41;

    auto gate = std::make_shared<detail::HoldGate>();
    gate->enabled = std::make_shared<std::atomic<bool>>(true);
    auto lifecycle = detail::make_binding_lifecycle();
    gate->lifecycle = lifecycle;

    std::atomic<int> holds{0};
    std::atomic<int> releases{0};
    gate->on_state_change = [&](bool held)
    {
        if (held)
        {
            holds.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            releases.fetch_add(1, std::memory_order_relaxed);
        }
    };

    std::atomic<bool> key_down{true};
    detail::g_input_key_state_probe = [&key_down](int vk) noexcept
    { return vk == HELD_VK && key_down.load(std::memory_order_acquire); };

    detail::InputBinding binding;
    binding.name = "H";
    binding.keys = {keyboard_key(HELD_VK)};
    binding.trigger = input::Trigger::Hold;
    binding.lifecycle = lifecycle;
    binding.release_is_idempotent = true; // the facade sets this for every gate-backed hold
    binding.on_state_change = [gate](bool active) { gate->deliver(active); };
    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(binding));

    // StagedProbeCleanup owns the barrier and probe lifetimes. Arm the release phase only after the held edge.
    std::atomic<bool> park_release{false};
    std::atomic<bool> release_staged{false};
    std::atomic<bool> allow_dispatch{false};

    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{2}, /*require_focus=*/false);
    const StagedProbeCleanup cleanup{poller, allow_dispatch};

    // The remove occurs after release staging but before dispatch, when m_active_states is already zero.
    detail::g_input_post_stage_probe = [&](std::size_t count)
    {
        if (count > 0 && park_release.load(std::memory_order_acquire) &&
            !release_staged.exchange(true, std::memory_order_acq_rel))
        {
            while (!allow_dispatch.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }
    };

    poller.start();

    for (int i = 0; i < 1000 && holds.load(std::memory_order_relaxed) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_EQ(holds.load(std::memory_order_relaxed), 1) << "the binding must be genuinely held first";

    park_release.store(true, std::memory_order_release);
    key_down.store(false, std::memory_order_release); // release the key: the next poll stages the false edge
    for (int i = 0; i < 1000 && !release_staged.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(release_staged.load(std::memory_order_acquire)) << "the release edge must have been staged";

    // The tombstone refuses the staged false. Only unconditional gate-backed synthesis can balance the removed held
    // entry.
    std::atomic<bool> remove_returned{false};
    std::atomic<std::size_t> removed_count{0};
    std::thread remove_thread(
        [&]
        {
            removed_count.store(poller.remove_bindings_by_name("H"), std::memory_order_release);
            remove_returned.store(true, std::memory_order_release);
        }
    );
    const bool tombstoned = wait_for_staged_operation(remove_returned, [&] { return lifecycle->tombstoned(); });
    allow_dispatch.store(true, std::memory_order_release);
    remove_thread.join();
    ASSERT_TRUE(tombstoned) << "remove returned or timed out before tombstoning the staged binding";
    ASSERT_TRUE(remove_returned.load(std::memory_order_acquire));
    ASSERT_EQ(removed_count.load(std::memory_order_acquire), 1u);

    for (int i = 0; i < 1000 && releases.load(std::memory_order_relaxed) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    poller.shutdown();

    EXPECT_EQ(releases.load(std::memory_order_relaxed), 1)
        << "a hold removed as its key releases must still receive released(false), not strand held";
    EXPECT_EQ(holds.load(std::memory_order_relaxed), 1);
}

// The rebind tombstones a held non-prototype entry after release staging. Gate synthesis must balance it even though
// the poll loop already cleared m_active_states.
TEST(InputLifecycleProof, CardinalityRebindReleasesDroppedNonPrototypeHold)
{
    InputSeamReset seam_reset;
    constexpr int PROTO_VK = 0x41; // The unpressed prototype survives the rebuild.
    constexpr int DROP_VK = 0x42;  // The held non-prototype must release when the rebuild drops it.

    std::atomic<bool> drop_key_down{true};
    detail::g_input_key_state_probe = [&drop_key_down](int vk) noexcept
    { return vk == DROP_VK && drop_key_down.load(std::memory_order_acquire); };

    auto proto_gate = std::make_shared<detail::HoldGate>();
    proto_gate->enabled = std::make_shared<std::atomic<bool>>(true);
    auto proto_lifecycle = detail::make_binding_lifecycle();
    proto_gate->lifecycle = proto_lifecycle;
    proto_gate->on_state_change = [](bool) {};
    detail::InputBinding proto;
    proto.name = "N";
    proto.keys = {keyboard_key(PROTO_VK)};
    proto.trigger = input::Trigger::Hold;
    proto.lifecycle = proto_lifecycle;
    proto.release_is_idempotent = true;
    proto.on_state_change = [proto_gate](bool active) { proto_gate->deliver(active); };

    std::atomic<int> drop_holds{0};
    std::atomic<int> drop_releases{0};
    auto drop_gate = std::make_shared<detail::HoldGate>();
    drop_gate->enabled = std::make_shared<std::atomic<bool>>(true);
    auto drop_lifecycle = detail::make_binding_lifecycle();
    drop_gate->lifecycle = drop_lifecycle;
    drop_gate->on_state_change = [&](bool held)
    {
        if (held)
        {
            drop_holds.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            drop_releases.fetch_add(1, std::memory_order_relaxed);
        }
    };
    detail::InputBinding drop;
    drop.name = "N"; // same name as proto, but a distinct lifecycle: the rebuild tombstones this non-prototype one
    drop.keys = {keyboard_key(DROP_VK)};
    drop.trigger = input::Trigger::Hold;
    drop.lifecycle = drop_lifecycle;
    drop.release_is_idempotent = true;
    drop.on_state_change = [drop_gate](bool active) { drop_gate->deliver(active); };

    std::vector<detail::InputBinding> bindings;
    bindings.push_back(std::move(proto));
    bindings.push_back(std::move(drop));

    // StagedProbeCleanup owns the barrier and probe lifetimes. Arm the release phase only after the held edge.
    std::atomic<bool> park_release{false};
    std::atomic<bool> release_staged{false};
    std::atomic<bool> allow_dispatch{false};

    detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{2}, /*require_focus=*/false);
    const StagedProbeCleanup cleanup{poller, allow_dispatch};

    detail::g_input_post_stage_probe = [&](std::size_t count)
    {
        if (count > 0 && park_release.load(std::memory_order_acquire) &&
            !release_staged.exchange(true, std::memory_order_acq_rel))
        {
            while (!allow_dispatch.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }
    };

    poller.start();

    for (int i = 0; i < 1000 && drop_holds.load(std::memory_order_relaxed) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_EQ(drop_holds.load(std::memory_order_relaxed), 1) << "the dropped registration must be genuinely held first";

    park_release.store(true, std::memory_order_release);
    drop_key_down.store(false, std::memory_order_release); // release the held key: the next poll stages its false edge
    for (int i = 0; i < 1000 && !release_staged.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(release_staged.load(std::memory_order_acquire)) << "the release edge must have been staged";

    // Cardinality change 2 -> 1: rebuilds "N", advancing the prototype lifecycle and tombstoning the non-prototype one
    // while its release sits staged and undispatched.
    const input::KeyComboList rebound = {input::KeyCombo{{keyboard_key(0x43)}, {}}};
    std::atomic<bool> rebind_returned{false};
    std::atomic<bool> rebind_succeeded{false};
    std::thread rebind_thread(
        [&]
        {
            rebind_succeeded.store(
                poller.update_combos("N", rebound) == detail::InputPoller::ComboUpdate::Updated,
                std::memory_order_release
            );
            rebind_returned.store(true, std::memory_order_release);
        }
    );
    const bool tombstoned = wait_for_staged_operation(rebind_returned, [&] { return drop_lifecycle->tombstoned(); });
    allow_dispatch.store(true, std::memory_order_release);
    rebind_thread.join();
    ASSERT_TRUE(tombstoned) << "cardinality rebind returned or timed out before tombstoning the dropped binding";
    ASSERT_TRUE(rebind_returned.load(std::memory_order_acquire));
    ASSERT_TRUE(rebind_succeeded.load(std::memory_order_acquire));

    for (int i = 0; i < 1000 && drop_releases.load(std::memory_order_relaxed) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    poller.shutdown();

    EXPECT_EQ(drop_releases.load(std::memory_order_relaxed), 1)
        << "a held non-prototype registration dropped by a cardinality rebind must receive released(false)";
    EXPECT_EQ(drop_holds.load(std::memory_order_relaxed), 1);
}

namespace
{
    // A leaked seam makes every later InputPoller::shutdown() abandon its poll thread.
    struct JoinFailSeamReset
    {
        ~JoinFailSeamReset() { detail::g_input_join_fail_seam = nullptr; }
    };
} // namespace

// The seam injects a join exception without an OS failure. This standalone poller retains its owner after the failed
// shutdown.
TEST(InputPollerShutdownTest, JoinFailureIsContainedAndLeavesTheThreadAbandoned)
{
    JoinFailSeamReset seam_reset;

    std::vector<detail::InputBinding> bindings;
    detail::InputBinding binding;
    binding.name = "join_fail";
    binding.keys = {keyboard_key(0x41)};
    bindings.push_back(std::move(binding));

    auto poller = std::make_shared<detail::InputPoller>(std::move(bindings), std::chrono::milliseconds{1}, false);
    poller->start();
    poller->retain_owner_for_abandonment(poller);
    const std::weak_ptr<detail::InputPoller> retained = poller;
    ASSERT_TRUE(poller->is_running());

    detail::g_input_join_fail_seam = []() { throw std::runtime_error("join failed"); };

    // The call under proof: a throw here must not escape the noexcept shutdown.
    poller->shutdown();

    EXPECT_FALSE(poller->is_running());
    EXPECT_FALSE(poller->self_retiring())
        << "an external shutdown whose join failed must not be mistaken for a poll-thread self-retirement";
    EXPECT_TRUE(poller->requires_abandonment())
        << "a detached poll thread requires its whole owner to remain alive, not only its module reference";

    detail::g_input_join_fail_seam = nullptr;
    // The detached thread can still read poller members. The reserved keepalive must retain the complete owner after
    // the external reference ends.
    poller.reset();
    EXPECT_FALSE(retained.expired());
}

// The keepalive is a self-reference. A never-started poller has no detached body, so clean shutdown must release that
// cycle.
TEST(InputPollerShutdownTest, RetainedPollerThatNeverStartedIsStillDestroyable)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputBinding binding;
    binding.name = "never_started";
    binding.keys = {keyboard_key(0x41)};
    bindings.push_back(std::move(binding));

    auto poller = std::make_shared<detail::InputPoller>(std::move(bindings), std::chrono::milliseconds{1}, false);
    poller->retain_owner_for_abandonment(poller);
    const std::weak_ptr<detail::InputPoller> retained = poller;

    poller->shutdown();
    EXPECT_FALSE(poller->requires_abandonment()) << "a poller with no worker has nothing to abandon";

    poller.reset();
    EXPECT_TRUE(
        retained.expired()
    ) << "an unstarted poller must not be retained for the process lifetime by its own keepalive";
}

// Clean shutdown releases the keepalive after join and rundown. The external owner can then destroy the poller.
TEST(InputPollerShutdownTest, CleanShutdownReleasesTheRetainedKeepalive)
{
    std::vector<detail::InputBinding> bindings;
    detail::InputBinding binding;
    binding.name = "clean_release";
    binding.keys = {keyboard_key(0x41)};
    bindings.push_back(std::move(binding));

    auto poller = std::make_shared<detail::InputPoller>(std::move(bindings), std::chrono::milliseconds{1}, false);
    poller->start();
    poller->retain_owner_for_abandonment(poller);
    const std::weak_ptr<detail::InputPoller> retained = poller;

    poller->shutdown();
    EXPECT_FALSE(poller->requires_abandonment()) << "a drained shutdown must not request abandonment";

    poller.reset();
    EXPECT_TRUE(retained.expired()) << "a drained shutdown must release the keepalive it precommitted";
}

// Detach makes the jthread non-joinable but leaves retention permanent. A later shutdown cannot interpret that state as
// permission to release.
TEST(InputPollerShutdownTest, RepeatedShutdownAfterDetachKeepsTheRetention)
{
    JoinFailSeamReset seam_reset;

    std::vector<detail::InputBinding> bindings;
    detail::InputBinding binding;
    binding.name = "detach_then_shutdown";
    binding.keys = {keyboard_key(0x41)};
    bindings.push_back(std::move(binding));

    auto poller = std::make_shared<detail::InputPoller>(std::move(bindings), std::chrono::milliseconds{1}, false);
    poller->start();
    poller->retain_owner_for_abandonment(poller);
    const std::weak_ptr<detail::InputPoller> retained = poller;

    detail::g_input_join_fail_seam = []() { throw std::runtime_error("join failed"); };
    poller->shutdown();
    detail::g_input_join_fail_seam = nullptr;
    ASSERT_TRUE(poller->requires_abandonment());

    // The idempotent second call: the thread is detached, so it is no longer joinable.
    poller->shutdown();

    poller.reset();
    EXPECT_FALSE(
        retained.expired()
    ) << "a repeated shutdown must not release a poller whose detached thread may still be reading it";
}

namespace
{
    // Static storage: the detached poll thread of the case below reads this table past the test body.
    std::atomic<int> g_detach_close_calls{0};

    int32_t DMK_WHEELHOST_CALL
    detach_stub_open(void *, std::uint64_t, std::uint64_t, WheelHostLease *out_lease) noexcept
    {
        *out_lease = 0x5EA5E;
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL
    detach_stub_drain(void *, WheelHostLease, std::uint32_t out_counts[DMK_WHEEL_DIRECTIONS]) noexcept
    {
        for (int i = 0; i < DMK_WHEEL_DIRECTIONS; ++i)
        {
            out_counts[i] = 0;
        }
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL detach_stub_close(void *, WheelHostLease, std::uint64_t, std::uint64_t) noexcept
    {
        g_detach_close_calls.fetch_add(1);
        return DMK_WHEELHOST_OK;
    }

    int g_detach_host_context = 0;
    WheelHostTable g_detach_host_table{
        .struct_size = sizeof(WheelHostTable),
        .abi_version = DMK_WHEELHOST_ABI_VERSION,
        .capability_bits = DMK_WHEELHOST_CAP_VERTICAL | DMK_WHEELHOST_CAP_HORIZONTAL | DMK_WHEELHOST_CAP_CONSUME |
                           DMK_WHEELHOST_CAP_ROUTE,
        .host_identity = 1,
        .host_context = &g_detach_host_context,
        .open_lease = &detach_stub_open,
        .publish_capture = &wheel_host_stub_publish,
        .drain_counts = &detach_stub_drain,
        .close_lease = &detach_stub_close,
        .route_status = &wheel_host_stub_route_status,
        .retarget = &wheel_host_stub_retarget,
    };
} // namespace

// The detached ExternalHost poller still reads its lease. Repeated shutdown must retain that lease with its owner.
TEST(InputPollerShutdownTest, RepeatedShutdownAfterDetachDoesNotCloseTheExternalLease)
{
    JoinFailSeamReset seam_reset;

    g_detach_close_calls.store(0);

    std::vector<detail::InputBinding> bindings;
    detail::InputBinding binding;
    binding.name = "detach_external_lease";
    binding.keys = {keyboard_key(0x41)};
    bindings.push_back(std::move(binding));

    auto poller = std::make_shared<detail::InputPoller>(
        std::move(bindings),
        std::chrono::milliseconds{1},
        false,
        0,
        GamepadCode::TriggerThreshold,
        GamepadCode::StickThreshold,
        input::Input::WheelBackend::ExternalHost,
        &g_detach_host_table
    );
    ASSERT_EQ(poller->prepare_wheel_source(), DMK_WHEELHOST_OK);
    poller->start();
    poller->retain_owner_for_abandonment(poller);

    detail::g_input_join_fail_seam = []() { throw std::runtime_error("join failed"); };
    poller->shutdown();
    detail::g_input_join_fail_seam = nullptr;
    ASSERT_TRUE(poller->requires_abandonment());
    ASSERT_EQ(g_detach_close_calls.load(), 0);

    // The nothing-to-do path of a repeated shutdown after the detach.
    poller->shutdown();
    EXPECT_EQ(g_detach_close_calls.load(), 0)
        << "a repeated shutdown must not close a lease its detached poll thread may still be reading";

    poller.reset();
}

namespace
{
    std::atomic<int> s_refuse_close_calls{0};

    int32_t DMK_WHEELHOST_CALL refuse_stub_close(void *, WheelHostLease, std::uint64_t, std::uint64_t) noexcept
    {
        s_refuse_close_calls.fetch_add(1, std::memory_order_relaxed);
        return DMK_WHEELHOST_ERR_STATE;
    }

    WheelHostTable s_refuse_host_table{
        .struct_size = sizeof(WheelHostTable),
        .abi_version = DMK_WHEELHOST_ABI_VERSION,
        .capability_bits = DMK_WHEELHOST_CAP_VERTICAL | DMK_WHEELHOST_CAP_HORIZONTAL | DMK_WHEELHOST_CAP_CONSUME |
                           DMK_WHEELHOST_CAP_ROUTE,
        .host_identity = 2,
        .host_context = &g_detach_host_context,
        .open_lease = &detach_stub_open,
        .publish_capture = &wheel_host_stub_publish,
        .drain_counts = &detach_stub_drain,
        .close_lease = &refuse_stub_close,
        .route_status = &wheel_host_stub_route_status,
        .retarget = &wheel_host_stub_retarget,
    };
} // namespace

TEST(InputPollerShutdownTest, RefusedExternalLeaseCloseIsDiagnosedAndRetainsTheLease)
{
    s_refuse_close_calls.store(0, std::memory_order_relaxed);

    std::vector<detail::InputBinding> bindings;
    detail::InputBinding binding;
    binding.name = "refused_external_close";
    binding.keys = {keyboard_key(0x41)};
    bindings.push_back(std::move(binding));

    auto poller = std::make_shared<detail::InputPoller>(
        std::move(bindings),
        std::chrono::milliseconds{1},
        false,
        0,
        GamepadCode::TriggerThreshold,
        GamepadCode::StickThreshold,
        input::Input::WheelBackend::ExternalHost,
        &s_refuse_host_table
    );
    ASSERT_EQ(poller->prepare_wheel_source(), DMK_WHEELHOST_OK);
    poller->start();

    poller->shutdown();
    EXPECT_EQ(s_refuse_close_calls.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(poller->wheel_host_logged_status_for_test(), DMK_WHEELHOST_ERR_STATE)
        << "a refused close must pass its status through the host diagnostic";

    // The retained lease makes the retry possible.
    poller->shutdown();
    EXPECT_EQ(s_refuse_close_calls.load(std::memory_order_relaxed), 2)
        << "a refused close must keep the lease for a later retry";

    poller.reset();
}

#if defined(DMK_ENABLE_TEST_SEAMS)

// A held staged count models a descheduled lease owner. The bounded drain must reach sleep-tier backoff.
TEST(InputDrainEscalation, StagedCallbackDrainEscalatesFromYieldToSleep)
{
    ASSERT_EQ(detail::staged_input_callback_count(), 0u) << "another test leaked a staged lease";
    detail::input_callback_lifecycle::s_staged_count.fetch_add(1, std::memory_order_seq_cst);

    const std::uint64_t sleeps_before = detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
    const bool drained = detail::await_staged_input_callbacks(detail::drain_deadline(std::chrono::milliseconds(300)));

    detail::input_callback_lifecycle::s_staged_count.fetch_sub(1, std::memory_order_seq_cst);

    EXPECT_FALSE(drained) << "a held staged count must expire the bounded drain, not satisfy it";
    EXPECT_GT(detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed), sleeps_before)
        << "a multi-hundred-millisecond drain never reached the sleep tier";

    EXPECT_TRUE(detail::await_staged_input_callbacks(detail::drain_deadline(std::chrono::milliseconds(300))));
}

#endif // defined(DMK_ENABLE_TEST_SEAMS)
