/**
 * @file test_input_loader.cpp
 * @brief Implements the in-process T-INPUT-LOADER proof.
 * @details The proof distinguishes the mutex boundary and capture ownership.
 */

#include <gtest/gtest.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <utility>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"

#include "internal/lifecycle_context.hpp"
#include "platform.hpp"

using namespace DetourModKit;
using namespace std::chrono_literals;

namespace
{
    std::atomic<bool> s_witness_armed{false};
    std::atomic<int> s_witness_destructions{0};
    std::atomic<bool> s_commit_seam_entered{false};
    std::atomic<bool> s_release_commit_seam{false};

    /// Counts destructions only while armed, so registration-time temporary copies never pollute the count.
    class DestructionWitness
    {
    public:
        DestructionWitness() noexcept = default;
        DestructionWitness(const DestructionWitness &) noexcept = default;
        DestructionWitness(DestructionWitness &&) noexcept = default;
        DestructionWitness &operator=(const DestructionWitness &) noexcept = default;
        DestructionWitness &operator=(DestructionWitness &&) noexcept = default;
        ~DestructionWitness() noexcept
        {
            if (s_witness_armed.load(std::memory_order_acquire))
            {
                s_witness_destructions.fetch_add(1, std::memory_order_acq_rel);
            }
        }
    };

    bool force_loader_lock_held() noexcept
    {
        return true;
    }
    bool force_loader_lock_free() noexcept
    {
        return false;
    }

    /// Forces the probe verdict and restores both the probe and the loader context on scope exit.
    class ForcedLoaderProbe
    {
    public:
        explicit ForcedLoaderProbe(bool (*probe)() noexcept) noexcept
            : m_saved_context(detail::lifecycle().loader_context())
        {
            detail::g_loader_lock_override = probe;
        }
        ~ForcedLoaderProbe() noexcept
        {
            detail::g_loader_lock_override = nullptr;
            detail::lifecycle().set_loader_context(m_saved_context);
        }
        ForcedLoaderProbe(const ForcedLoaderProbe &) = delete;
        ForcedLoaderProbe &operator=(const ForcedLoaderProbe &) = delete;

    private:
        detail::LoaderContext m_saved_context;
    };

    /// Stages one press binding with a destruction witness and no poller.
    [[nodiscard]] Result<input::BindingGuard> stage_witness_binding(const char *name)
    {
        return input::register_combo(input::ComboBinding{.name = name,
                                                         .trigger = input::Trigger::Press,
                                                         .combos = {{{keyboard_key(0x70)}, {}}},
                                                         .on_press = [witness = DestructionWitness{}] {}});
    }

    void park_admission_commit() noexcept
    {
        s_commit_seam_entered.store(true, std::memory_order_release);
        while (!s_release_commit_seam.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }
} // namespace

TEST(InputLoaderLock, VetoedShutdownDoesNotWaitOrDestroyStagedCaptures)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    s_witness_armed.store(false, std::memory_order_release);
    s_witness_destructions.store(0, std::memory_order_release);
    Result<input::BindingGuard> guard = stage_witness_binding("loader_veto_staged");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    ASSERT_EQ(mgr.binding_count(), 1u);
    guard->release();
    s_witness_armed.store(true, std::memory_order_release);

    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Input);

    // Hold the facade mutex from a peer thread so a shutdown() that still takes it cannot return.
    std::atomic<bool> mutex_held{false};
    std::atomic<bool> release_mutex{false};
    std::thread holder(
        [&]
        {
            input::Input::lock_facade_mutex_for_test();
            mutex_held.store(true, std::memory_order_release);
            while (!release_mutex.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            input::Input::unlock_facade_mutex_for_test();
        });
    while (!mutex_held.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::atomic<bool> shutdown_returned{false};
    std::thread vetoed(
        [&]
        {
            ForcedLoaderProbe probe{&force_loader_lock_held};
            mgr.shutdown();
            shutdown_returned.store(true, std::memory_order_release);
        });

    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!shutdown_returned.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::yield();
    }
    const bool returned_without_wait = shutdown_returned.load(std::memory_order_acquire);

    // Release the holder so a failed expectation cannot stall the suite.
    release_mutex.store(true, std::memory_order_release);
    holder.join();
    vetoed.join();

    EXPECT_TRUE(returned_without_wait) << "a vetoed shutdown() waited on the facade mutex";
    EXPECT_EQ(s_witness_destructions.load(std::memory_order_acquire), 0)
        << "a vetoed shutdown() destroyed a staged consumer capture";
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Input), leaks_before + 1)
        << "the vetoed retention must be recorded as an intentional leak";

    ASSERT_TRUE(input::Input::reclaim_vetoed_impl_for_test());
    EXPECT_EQ(mgr.binding_count(), 1u) << "the retained owner must still hold the staged binding";

    s_witness_armed.store(false, std::memory_order_release);
    mgr.shutdown();
}

TEST(InputLoaderLock, VetoedShutdownStopsThePollLoopWithoutJoining)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    s_witness_armed.store(false, std::memory_order_release);
    Result<input::BindingGuard> guard = stage_witness_binding("loader_veto_running_engine");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();
    const std::size_t poller_pins_before = diagnostics::module_pin_count(diagnostics::ModulePinReason::InputPoller);
    ASSERT_TRUE(mgr.start().has_value());
    ASSERT_TRUE(mgr.is_running());
    EXPECT_EQ(diagnostics::module_pin_count(diagnostics::ModulePinReason::InputPoller), poller_pins_before + 1)
        << "an active poll thread must book its InputPoller pin";

    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Input);
    const std::size_t wndproc_pins = diagnostics::module_pin_count(diagnostics::ModulePinReason::WndprocKeepalive);
    const std::size_t xinput_pins = diagnostics::module_pin_count(diagnostics::ModulePinReason::XInputKeepalive);
    {
        ForcedLoaderProbe probe{&force_loader_lock_held};
        mgr.shutdown();
    }

    // One leak records the retained facade owner, and one records the detached poll thread.
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Input), leaks_before + 2)
        << "a vetoed shutdown() must stop and detach the running poll loop, not leave it delivering callbacks";

    // The abandoned poller stays distinct from both inert input keepalive reasons.
    EXPECT_EQ(diagnostics::module_pin_count(diagnostics::ModulePinReason::InputPoller), poller_pins_before + 1)
        << "an abandoned poll thread must stay visible as an outstanding InputPoller pin";
    EXPECT_EQ(diagnostics::module_pin_count(diagnostics::ModulePinReason::WndprocKeepalive), wndproc_pins)
        << "a poller abandonment must not book the wheel keepalive reason";
    EXPECT_EQ(diagnostics::module_pin_count(diagnostics::ModulePinReason::XInputKeepalive), xinput_pins)
        << "a poller abandonment must not book the XInput keepalive reason";

    ASSERT_TRUE(input::Input::reclaim_vetoed_impl_for_test());
    mgr.shutdown();
}

TEST(InputLoaderLock, ForcedFreeProbeNeverAuthorizesAForbiddenPhase)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    s_witness_armed.store(false, std::memory_order_release);
    s_witness_destructions.store(0, std::memory_order_release);
    Result<input::BindingGuard> guard = stage_witness_binding("loader_context_staged");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();
    s_witness_armed.store(true, std::memory_order_release);

    {
        ForcedLoaderProbe probe{&force_loader_lock_free};
        detail::lifecycle().set_loader_context(detail::LoaderContext::LoaderDetach);
        mgr.shutdown();
    }

    EXPECT_EQ(s_witness_destructions.load(std::memory_order_acquire), 0)
        << "a forced-free probe authorized capture destruction inside a loader-detach phase";
    ASSERT_TRUE(input::Input::reclaim_vetoed_impl_for_test());

    s_witness_armed.store(false, std::memory_order_release);
    mgr.shutdown();
}

TEST(InputLoaderLock, AdmittedFacadeCallKeepsStableOwnerAcrossVeto)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    s_commit_seam_entered.store(false, std::memory_order_release);
    s_release_commit_seam.store(false, std::memory_order_release);
    input::Input::set_callback_admission_commit_seam_for_test(&park_admission_commit);

    std::unique_ptr<Result<input::BindingGuard>> registration;
    std::thread registrar(
        [&]
        {
            registration = std::make_unique<Result<input::BindingGuard>>(
                input::register_combo(input::ComboBinding{.name = "loader_veto_concurrent_entry",
                                                          .trigger = input::Trigger::Press,
                                                          .combos = {{{keyboard_key(0x70)}, {}}},
                                                          .on_press = [] {}}));
        });

    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!s_commit_seam_entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::yield();
    }
    const bool entry_parked = s_commit_seam_entered.load(std::memory_order_acquire);
    if (entry_parked)
    {
        ForcedLoaderProbe probe{&force_loader_lock_held};
        mgr.shutdown();
    }

    s_release_commit_seam.store(true, std::memory_order_release);
    registrar.join();
    input::Input::set_callback_admission_commit_seam_for_test(nullptr);

    if (!entry_parked)
    {
        if (registration && registration->has_value())
        {
            registration->value().release();
        }
        mgr.shutdown();
        FAIL() << "the registration never reached the deterministic pre-commit park";
    }
    ASSERT_TRUE(static_cast<bool>(registration));
    ASSERT_TRUE(registration->has_value()) << registration->error().message();
    EXPECT_EQ(mgr.binding_count(), 0u) << "new facade calls must fail closed while retention is latched";

    ASSERT_TRUE(input::Input::reclaim_vetoed_impl_for_test());
    EXPECT_EQ(mgr.binding_count(), 1u)
        << "the already-admitted call must commit through the same retained facade owner";
    registration->value().release();
    mgr.shutdown();
}
