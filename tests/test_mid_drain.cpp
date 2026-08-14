/**
 * @file test_mid_drain.cpp
 * @brief Provides proofs for bounded mid-hook teardown drains and fail-closed retention.
 * @details The callback case parks a real SafetyHook mid callback. The adapter-entry case injects a count equal to a
 *          real adapter entrant. The adapter drain consumes only this count. Both cases verify these properties:
 *          - Teardown returns before its deadline.
 *          - Executable state remains retained.
 *          - The drain reaches sleep-tier backoff.
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "internal/drain_backoff.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    // This redeclaration avoids internal/mid_hook_adapter.hpp, which pulls in safetyhook.hpp. This target carries no
    // backend include path. src/hook.cpp owns the definitions.
    [[nodiscard]] std::size_t last_claimed_mid_slot_for_test() noexcept;
    [[nodiscard]] bool mid_slot_claimed_for_test(std::size_t index) noexcept;
    void adjust_mid_adapter_entries_for_test(std::size_t index, std::int32_t delta) noexcept;
    [[nodiscard]] std::uint64_t hook_impl_destruction_count_for_test() noexcept;
} // namespace DetourModKit::detail
#endif

namespace
{
    // This indirection forces the call to reach the patched entry when the optimizer sees the callee.
    // It gives Release and Debug the same proof.
    template <class Fn, class... Args> auto call_unfolded(Fn *fn, Args... args)
    {
        Fn *const volatile indirect = fn;
        return indirect(args...);
    }

    DMK_TEST_NOINLINE int callback_expiry_site(int a)
    {
        volatile int result = a;
        return result;
    }

    DMK_TEST_NOINLINE int entry_expiry_site(int a)
    {
        volatile int result = a;
        return result;
    }

    std::atomic<int> s_entered{0};
    std::atomic<bool> s_callback_parked{false};
    std::atomic<bool> s_release_callback{false};

    // Parks inside the adapter until released, so the bounded callback drain has a genuinely in-flight entrant.
    void parking_detour(MidContext &)
    {
        s_entered.fetch_add(1, std::memory_order_relaxed);
        s_callback_parked.store(true, std::memory_order_release);
        while (!s_release_callback.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    void counting_detour(MidContext &)
    {
        s_entered.fetch_add(1, std::memory_order_relaxed);
    }

    /// Builds and arms a mid hook at @p target, then returns its RAII handle.
    template <class Fn> [[nodiscard]] Result<Hook> install_mid(std::string name, Fn *target, MidHookFn detour)
    {
        Result<Hook> hook = mid_at(
            MidRequest{.name = std::move(name), .target = Address{reinterpret_cast<std::uintptr_t>(target)}}, detour);
        if (!hook.has_value())
        {
            return hook;
        }
        if (const Result<void> armed = hook->enable(); !armed.has_value())
        {
            return std::unexpected(armed.error());
        }
        return hook;
    }
} // namespace

#if defined(DMK_ENABLE_TEST_SEAMS)

class MidHookDrainTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        s_entered.store(0);
        s_callback_parked.store(false);
        s_release_callback.store(false);
    }
};

// A callback parked past the deadline forces fail-closed retention. The teardown thread has its own deadline so a
// broken bound can be released and joined safely.
TEST_F(MidHookDrainTest, ExpiredCallbackDrainPinsTheBackendAndBoundsTeardown)
{
    Result<Hook> result = install_mid("MidDrainCallbackExpiry", &callback_expiry_site, &parking_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    auto hook = std::make_unique<Hook>(std::move(*result));

    const std::size_t slot = DetourModKit::detail::last_claimed_mid_slot_for_test();
    ASSERT_TRUE(DetourModKit::detail::mid_slot_claimed_for_test(slot));

    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    const std::uint64_t sleeps_before = DetourModKit::detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
    const std::uint64_t destructions_before = DetourModKit::detail::hook_impl_destruction_count_for_test();

    std::thread caller([] { (void)call_unfolded(&callback_expiry_site, 7); });
    const auto park_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!s_callback_parked.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < park_deadline)
    {
        std::this_thread::yield();
    }
    if (!s_callback_parked.load(std::memory_order_acquire))
    {
        s_release_callback.store(true, std::memory_order_release);
        caller.join();
        FAIL() << "the caller never entered the callback";
        return;
    }

    const auto started = std::chrono::steady_clock::now();
    std::atomic<bool> teardown_returned{false};
    std::thread destroyer(
        [&]
        {
            hook.reset();
            teardown_returned.store(true, std::memory_order_release);
        });
    const auto teardown_deadline = started + std::chrono::seconds(30);
    while (!teardown_returned.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < teardown_deadline)
    {
        std::this_thread::yield();
    }
    if (!teardown_returned.load(std::memory_order_acquire))
    {
        s_release_callback.store(true, std::memory_order_release);
        caller.join();
        destroyer.join();
        FAIL() << "teardown exceeded its callback-drain deadline";
        return;
    }
    destroyer.join();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_GE(elapsed, std::chrono::milliseconds(4900)) << "teardown returned before the bounded drain expired";
    EXPECT_LT(elapsed, std::chrono::seconds(30)) << "teardown did not return promptly after the deadline";

    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), leaks_before + 1)
        << "the expiry pin must book its intentional leak";
    EXPECT_TRUE(DetourModKit::detail::mid_slot_claimed_for_test(slot)) << "the pin must never reclaim the adapter slot";
    EXPECT_GT(DetourModKit::detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed), sleeps_before)
        << "a multi-second drain must escalate from yields to the sleep tier";
    EXPECT_EQ(DetourModKit::detail::hook_impl_destruction_count_for_test(), destructions_before)
        << "the pinned backend state must not be destroyed";

    // The target was restored. A fresh call runs the original and enters no callback.
    const int callbacks_at_pin = s_entered.load();
    EXPECT_EQ(call_unfolded(&callback_expiry_site, 21), 21);
    EXPECT_EQ(s_entered.load(), callbacks_at_pin) << "a call after the pin must not re-enter the callback";

    // The parked thread returns through the pinned stub. The retention keeps that route alive.
    s_release_callback.store(true, std::memory_order_release);
    caller.join();
    EXPECT_TRUE(DetourModKit::detail::mid_slot_claimed_for_test(slot)) << "the pin remains after the entrant drains";
}

// An injected adapter-body entrant forces the same bounded retention path. A later install proves the target and
// ledger entry were restored while the old slot remains claimed.
TEST_F(MidHookDrainTest, ExpiredAdapterEntryDrainPinsTheSlotAndBoundsTeardown)
{
    Result<Hook> result = install_mid("MidDrainEntryExpiry", &entry_expiry_site, &counting_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    auto hook = std::make_unique<Hook>(std::move(*result));

    const std::size_t slot = DetourModKit::detail::last_claimed_mid_slot_for_test();
    ASSERT_TRUE(DetourModKit::detail::mid_slot_claimed_for_test(slot));
    DetourModKit::detail::adjust_mid_adapter_entries_for_test(slot, 1);

    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    const std::uint64_t sleeps_before = DetourModKit::detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
    const std::uint64_t destructions_before = DetourModKit::detail::hook_impl_destruction_count_for_test();

    const auto started = std::chrono::steady_clock::now();
    std::atomic<bool> teardown_returned{false};
    std::thread destroyer(
        [&]
        {
            hook.reset();
            teardown_returned.store(true, std::memory_order_release);
        });
    const auto teardown_deadline = started + std::chrono::seconds(30);
    while (!teardown_returned.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < teardown_deadline)
    {
        std::this_thread::yield();
    }
    if (!teardown_returned.load(std::memory_order_acquire))
    {
        DetourModKit::detail::adjust_mid_adapter_entries_for_test(slot, -1);
        destroyer.join();
        FAIL() << "teardown exceeded its adapter-entry deadline";
        return;
    }
    destroyer.join();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_GE(elapsed, std::chrono::milliseconds(900)) << "teardown returned before the entry drain expired";
    EXPECT_LT(elapsed, std::chrono::seconds(30)) << "teardown did not return promptly after the deadline";

    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), leaks_before + 1)
        << "the expiry pin must book its intentional leak";
    EXPECT_TRUE(DetourModKit::detail::mid_slot_claimed_for_test(slot)) << "the pin must never reclaim the adapter slot";
    EXPECT_GT(DetourModKit::detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed), sleeps_before)
        << "the adapter-entry drain must reach the sleep tier";
    EXPECT_EQ(DetourModKit::detail::hook_impl_destruction_count_for_test(), destructions_before)
        << "the adapter-entry pin must retain the backend state";

    // A fresh install on the restored target must use a different slot and dispatch normally.
    Result<Hook> second = install_mid("MidDrainEntryExpirySecond", &entry_expiry_site, &counting_detour);
    ASSERT_TRUE(second.has_value()) << "reinstall after the pin failed: " << second.error().message();
    EXPECT_NE(DetourModKit::detail::last_claimed_mid_slot_for_test(), slot)
        << "a pinned slot must not be handed to a later install";
    const int entered_before = s_entered.load();
    EXPECT_EQ(call_unfolded(&entry_expiry_site, 5), 5);
    EXPECT_GT(s_entered.load(), entered_before);

    // This adjustment balances the injected entrant. The pinned slot stays claimed.
    DetourModKit::detail::adjust_mid_adapter_entries_for_test(slot, -1);
}

#endif // defined(DMK_ENABLE_TEST_SEAMS)
