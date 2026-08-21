/**
 * @file test_wheel_host_loader.cpp
 * @brief Verifies the external wheel-host client through the public input API.
 */

#include <gtest/gtest.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <thread>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/wheel_host.h"

using namespace DetourModKit;
using namespace std::chrono_literals;

namespace
{
    std::atomic<int> g_open_calls{0};
    std::atomic<int> g_publish_calls{0};
    std::atomic<int> g_drain_calls{0};
    std::atomic<int> g_close_calls{0};
    std::atomic<int32_t> g_open_status{DMK_WHEELHOST_OK};
    std::atomic<std::uint64_t> g_last_owner{0};
    std::atomic<std::uint64_t> g_last_generation{0};
    std::atomic<DmkWheelLease> g_open_lease{0};
    std::atomic<bool> g_reenter_input_on_open{false};
    std::atomic<bool> g_rebind_input_on_open{false};
    std::atomic<std::size_t> g_reentered_binding_count{0};
    std::atomic<bool> g_reentrant_rebind_succeeded{false};

    int g_stub_context = 0;

    void reset_stub_counters() noexcept
    {
        g_open_calls.store(0);
        g_publish_calls.store(0);
        g_drain_calls.store(0);
        g_close_calls.store(0);
        g_open_status.store(DMK_WHEELHOST_OK);
        g_last_owner.store(0);
        g_last_generation.store(0);
        g_open_lease.store(0);
        g_reenter_input_on_open.store(false);
        g_rebind_input_on_open.store(false);
        g_reentered_binding_count.store(0);
        g_reentrant_rebind_succeeded.store(false);
    }

    int32_t DMK_WHEELHOST_CALL stub_open(void *ctx, std::uint64_t owner, std::uint64_t generation,
                                         DmkWheelLease *out_lease) noexcept
    {
        if (ctx != &g_stub_context || out_lease == nullptr)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        g_open_calls.fetch_add(1);
        if (g_reenter_input_on_open.load())
        {
            g_reentered_binding_count.store(input::Input::instance().binding_count());
        }
        if (g_rebind_input_on_open.load())
        {
            g_reentrant_rebind_succeeded.store(
                input::Input::instance()
                    .rebind("wheelhost_reentrant_rebind", {{{mouse_wheel(WheelCode::Down)}, {}}})
                    .has_value());
        }
        g_last_owner.store(owner);
        g_last_generation.store(generation);
        const int32_t status = g_open_status.load();
        if (status != DMK_WHEELHOST_OK)
        {
            return status;
        }
        constexpr DmkWheelLease kLease = 0xA11CE;
        g_open_lease.store(kLease);
        *out_lease = kLease;
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL stub_publish(void *ctx, DmkWheelLease lease, std::uint32_t /*enabled*/,
                                            std::uint32_t /*consume_mask*/, std::uint32_t /*ttl*/) noexcept
    {
        if (ctx != &g_stub_context || lease != g_open_lease.load())
        {
            return DMK_WHEELHOST_ERR_STALE;
        }
        g_publish_calls.fetch_add(1);
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL stub_drain(void *ctx, DmkWheelLease lease,
                                          std::uint32_t out_counts[DMK_WHEEL_DIRECTIONS]) noexcept
    {
        if (ctx != &g_stub_context || lease != g_open_lease.load() || out_counts == nullptr)
        {
            return DMK_WHEELHOST_ERR_STALE;
        }
        g_drain_calls.fetch_add(1);
        for (int i = 0; i < DMK_WHEEL_DIRECTIONS; ++i)
        {
            out_counts[i] = 0;
        }
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL stub_close(void *ctx, DmkWheelLease lease, std::uint64_t owner,
                                          std::uint64_t generation) noexcept
    {
        if (ctx != &g_stub_context || lease != g_open_lease.load() || owner != g_last_owner.load() ||
            generation != g_last_generation.load())
        {
            return DMK_WHEELHOST_ERR_STALE;
        }
        g_close_calls.fetch_add(1);
        return DMK_WHEELHOST_OK;
    }

    DmkWheelHostTable make_stub_table() noexcept
    {
        DmkWheelHostTable table{};
        table.struct_size = static_cast<std::uint32_t>(sizeof(DmkWheelHostTable));
        table.abi_version = DMK_WHEELHOST_ABI_VERSION;
        table.capability_bits = DMK_WHEELHOST_CAP_VERTICAL | DMK_WHEELHOST_CAP_HORIZONTAL | DMK_WHEELHOST_CAP_CONSUME;
        table.host_identity = 1;
        table.host_context = &g_stub_context;
        table.open_lease = &stub_open;
        table.publish_capture = &stub_publish;
        table.drain_counts = &stub_drain;
        table.close_lease = &stub_close;
        return table;
    }

    [[nodiscard]] Result<input::BindingGuard> stage_wheel_binding(const char *name)
    {
        return input::register_combo(input::ComboBinding{.name = name,
                                                         .trigger = input::Trigger::Press,
                                                         .combos = {{{mouse_wheel(WheelCode::Up)}, {}}},
                                                         .on_press = [] {}});
    }
} // namespace

TEST(WheelHostLoader, ExternalBackendOpensPublishesDrainsAndClosesTheLease)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();

    // The table must outlive the poller, so it lives on this stack and shutdown() runs before the function returns.
    const DmkWheelHostTable table = make_stub_table();

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_external");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    settings.poll_interval = 5ms;
    g_reenter_input_on_open.store(true);
    ASSERT_TRUE(mgr.start(settings).has_value());
    ASSERT_TRUE(mgr.is_running());

    // The poll loop opens the lease and then publishes/drains each cycle. Wait a bounded time for the first cycle.
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while ((g_open_calls.load() == 0 || g_drain_calls.load() == 0) && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_GE(g_open_calls.load(), 1) << "the external backend must open exactly one lease";
    EXPECT_EQ(g_open_calls.load(), 1) << "the lease is opened once, not per cycle";
    EXPECT_GE(g_publish_calls.load(), 1) << "the poller must publish capture through the C ABI";
    EXPECT_GE(g_drain_calls.load(), 1) << "the poller must drain counts through the C ABI";
    EXPECT_NE(g_last_owner.load(), 0u) << "the lease owner must be the poller's nonzero intercept owner";
    EXPECT_EQ(g_reentered_binding_count.load(), 1u) << "the loader callback must run outside the Input facade lock";

    mgr.shutdown();
    EXPECT_EQ(g_close_calls.load(), 1) << "shutdown must close the lease exactly once";
}

TEST(WheelHostLoader, ExternalBackendLeavesNoWheelKeepaliveInThisImage)
{
    namespace diag = DetourModKit::diagnostics;
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();

    // The central split-topology safety property: the wheel host lives in the loader, so a generation that captures
    // through ExternalHost books neither wheel keepalive in this image and can therefore unmap cleanly.
    const std::size_t wndproc_before = diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive);
    const std::size_t msghook_before = diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive);

    const DmkWheelHostTable table = make_stub_table();
    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_no_local_pin");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    settings.poll_interval = 5ms;
    ASSERT_TRUE(mgr.start(settings).has_value());

    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (g_open_calls.load() == 0 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_GE(g_open_calls.load(), 1);

    mgr.shutdown();

    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), wndproc_before)
        << "the external backend must not take the WndProc keepalive";
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive), msghook_before)
        << "the external backend must not take the message-hook keepalive; the host owns the pin";
}

TEST(WheelHostLoader, ReentrantHostMutationInvalidatesTheStartCandidate)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();

    const DmkWheelHostTable table = make_stub_table();
    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_reentrant_rebind");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    g_rebind_input_on_open.store(true);
    const Result<void> result = mgr.start(settings);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::ShutdownInProgress);
    EXPECT_TRUE(g_reentrant_rebind_succeeded.load());
    EXPECT_EQ(g_close_calls.load(), 1);
    EXPECT_EQ(mgr.binding_count(), 1u);
    EXPECT_FALSE(mgr.is_running());
    mgr.shutdown();
}

TEST(WheelHostLoader, RequiredHostMissingRefusesStart)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_required_missing");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = nullptr;
    settings.wheel_host_required = true;
    const Result<void> result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    EXPECT_FALSE(mgr.is_running());

    mgr.shutdown();
}

TEST(WheelHostLoader, RequiredHostAbiMismatchRefusesStart)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_required_mismatch");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    DmkWheelHostTable table = make_stub_table();
    table.abi_version = DMK_WHEELHOST_ABI_VERSION + 1; // an incompatible future ABI

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    const Result<void> result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);

    mgr.shutdown();
}

TEST(WheelHostLoader, RequiredHostLeaseFailureRefusesStartSynchronously)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();
    g_open_status.store(DMK_WHEELHOST_ERR_BUSY);

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_required_busy");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    const DmkWheelHostTable table = make_stub_table();
    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    const Result<void> result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::SystemCallFailed);
    EXPECT_EQ(result.error().detail, static_cast<std::uintptr_t>(0 - DMK_WHEELHOST_ERR_BUSY));
    EXPECT_EQ(g_open_calls.load(), 1);
    EXPECT_FALSE(mgr.is_running());

    mgr.shutdown();
}

TEST(WheelHostLoader, RequiredHostCompatibilityFieldsAreValidated)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_required_capabilities");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    DmkWheelHostTable table = make_stub_table();
    table.host_identity = 0;
    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    Result<void> result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    mgr.shutdown();

    guard = stage_wheel_binding("wheelhost_required_capability_bits");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();
    table = make_stub_table();
    table.capability_bits &= ~DMK_WHEELHOST_CAP_CONSUME;
    settings.wheel_host = &table;
    result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    mgr.shutdown();
}

TEST(WheelHostLoader, UnknownBackendRefusesStart)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_unknown_backend");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = static_cast<input::Input::WheelBackend>(255);
    const Result<void> result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    EXPECT_FALSE(mgr.is_running());
    mgr.shutdown();
}

TEST(WheelHostLoader, OptionalHostMissingDowngradesToLocalFallback)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_optional_downgrade");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = nullptr;
    settings.wheel_host_required = false; // optional: downgrade to the local message-hook fallback
    settings.poll_interval = 5ms;
    ASSERT_TRUE(mgr.start(settings).has_value()) << "an optional host must downgrade, not refuse";
    EXPECT_TRUE(mgr.is_running());
    // The downgrade uses the local backend, so no host callback fires.
    EXPECT_EQ(g_open_calls.load(), 0);

    mgr.shutdown();
}
