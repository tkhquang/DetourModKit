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
#include "DetourModKit/abi/wheel_host.h"

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
    std::atomic<WheelHostLease> g_open_lease{0};
    std::atomic<bool> g_reenter_input_on_open{false};
    std::atomic<bool> g_rebind_input_on_open{false};
    std::atomic<std::size_t> g_reentered_binding_count{0};
    std::atomic<bool> g_reentrant_rebind_succeeded{false};
    std::atomic<int> g_route_status_calls{0};
    std::atomic<int> g_retarget_calls{0};
    std::atomic<std::uint32_t> g_route_state{DMK_WHEELHOST_ROUTE_READY};
    std::atomic<std::uint32_t> g_control_state{DMK_WHEELHOST_CONTROL_IDLE};
    std::atomic<std::uint32_t> g_mounted_thread_id{0x1234u};
    std::atomic<std::uint32_t> g_last_retarget_target{0};
    std::atomic<bool> g_retarget_succeeds{true};
    std::atomic<int> g_capture_armable_override{-1};

    int g_stub_context = 0;

    [[nodiscard]] constexpr std::uint32_t distinct_thread_id(std::uint32_t thread_id) noexcept
    {
        return thread_id == 1u ? 2u : 1u;
    }

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
        g_route_status_calls.store(0);
        g_retarget_calls.store(0);
        g_route_state.store(DMK_WHEELHOST_ROUTE_READY);
        g_control_state.store(DMK_WHEELHOST_CONTROL_IDLE);
        g_mounted_thread_id.store(0x1234u);
        g_last_retarget_target.store(0);
        g_retarget_succeeds.store(true);
        g_capture_armable_override.store(-1);
    }

    int32_t DMK_WHEELHOST_CALL
    stub_open(void *ctx, std::uint64_t owner, std::uint64_t generation, WheelHostLease *out_lease) noexcept
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
                input::Input::instance().rebind(
                                            "wheelhost_reentrant_rebind",
                                            {{{mouse_wheel(WheelCode::Down)}, {}}}
                ).has_value()
            );
        }
        g_last_owner.store(owner);
        g_last_generation.store(generation);
        const int32_t status = g_open_status.load();
        if (status != DMK_WHEELHOST_OK)
        {
            return status;
        }
        constexpr WheelHostLease lease_token = 0xA11CE;
        g_open_lease.store(lease_token);
        *out_lease = lease_token;
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL stub_publish(
        void *ctx,
        WheelHostLease lease,
        std::uint32_t /*enabled*/,
        std::uint32_t /*consume_mask*/,
        std::uint32_t /*ttl*/
    ) noexcept
    {
        if (ctx != &g_stub_context || lease != g_open_lease.load())
        {
            return DMK_WHEELHOST_ERR_STALE;
        }
        g_publish_calls.fetch_add(1);
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL
    stub_drain(void *ctx, WheelHostLease lease, std::uint32_t out_counts[DMK_WHEEL_DIRECTIONS]) noexcept
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

    int32_t DMK_WHEELHOST_CALL
    stub_close(void *ctx, WheelHostLease lease, std::uint64_t owner, std::uint64_t generation) noexcept
    {
        if (ctx != &g_stub_context || lease != g_open_lease.load() || owner != g_last_owner.load() ||
            generation != g_last_generation.load())
        {
            return DMK_WHEELHOST_ERR_STALE;
        }
        g_close_calls.fetch_add(1);
        return DMK_WHEELHOST_OK;
    }

    // Each snapshot field is settable. Tests can stage a mounted route with a pending transaction.
    int32_t DMK_WHEELHOST_CALL stub_route_status(
        void *ctx,
        WheelHostLease lease,
        std::uint32_t status_capacity,
        WheelHostRouteStatus *out_status
    ) noexcept
    {
        if (ctx != &g_stub_context || out_status == nullptr)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        if (status_capacity < sizeof(WheelHostRouteStatus))
        {
            return DMK_WHEELHOST_ERR_ABI;
        }
        if (lease != 0 && lease != g_open_lease.load())
        {
            return DMK_WHEELHOST_ERR_STALE;
        }
        g_route_status_calls.fetch_add(1);
        const std::uint32_t route_state = g_route_state.load();
        const std::uint32_t control_state = g_control_state.load();
        *out_status = WheelHostRouteStatus{};
        out_status->struct_size = static_cast<std::uint32_t>(sizeof(WheelHostRouteStatus));
        out_status->route_state = route_state;
        out_status->control_state = control_state;
        const int armable_override = g_capture_armable_override.load();
        const bool capture_armable = armable_override >= 0 ? armable_override != 0
                                                           : route_state == DMK_WHEELHOST_ROUTE_READY &&
                                                                 control_state == DMK_WHEELHOST_CONTROL_IDLE;
        out_status->capture_armable = lease != 0 && capture_armable ? 1u : 0u;
        out_status->mounted_thread_id = g_mounted_thread_id.load();
        out_status->mount_generation = 1;
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL stub_retarget(void *ctx, WheelHostLease lease, std::uint32_t target_thread_id) noexcept
    {
        if (ctx != &g_stub_context || lease != g_open_lease.load())
        {
            return DMK_WHEELHOST_ERR_STALE;
        }
        g_retarget_calls.fetch_add(1);
        g_last_retarget_target.store(target_thread_id);
        if (target_thread_id == 0)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        const std::uint32_t control_state = g_control_state.load();
        if (control_state != DMK_WHEELHOST_CONTROL_IDLE && control_state != DMK_WHEELHOST_CONTROL_RETARGET_PENDING)
        {
            return DMK_WHEELHOST_ERR_PENDING;
        }
        if (!g_retarget_succeeds.load())
        {
            // The failure keeps the staged state stable across poll cycles.
            return DMK_WHEELHOST_ERR_THREAD;
        }
        // Success mounts the requested thread and ends the transaction.
        g_mounted_thread_id.store(target_thread_id);
        g_route_state.store(DMK_WHEELHOST_ROUTE_READY);
        g_control_state.store(DMK_WHEELHOST_CONTROL_IDLE);
        return DMK_WHEELHOST_OK;
    }

    WheelHostTable make_stub_table() noexcept
    {
        WheelHostTable table{};
        table.struct_size = static_cast<std::uint32_t>(sizeof(WheelHostTable));
        table.abi_version = DMK_WHEELHOST_ABI_VERSION;
        table.capability_bits = DMK_WHEELHOST_CAP_VERTICAL | DMK_WHEELHOST_CAP_HORIZONTAL | DMK_WHEELHOST_CAP_CONSUME |
                                DMK_WHEELHOST_CAP_ROUTE;
        table.host_identity = 1;
        table.host_context = &g_stub_context;
        table.open_lease = &stub_open;
        table.publish_capture = &stub_publish;
        table.drain_counts = &stub_drain;
        table.close_lease = &stub_close;
        table.route_status = &stub_route_status;
        table.retarget = &stub_retarget;
        return table;
    }

    [[nodiscard]] Result<input::BindingGuard> stage_wheel_binding(const char *name)
    {
        return input::register_combo(
            input::ComboBinding{
                .name = name,
                .trigger = input::Trigger::Press,
                .combos = {{{mouse_wheel(WheelCode::Up)}, {}}},
                .on_press = [] {},
            }
        );
    }
} // namespace

TEST(WheelHostLoader, ExternalBackendOpensPublishesDrainsAndClosesTheLease)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();

    // The table must outlive the poller, so it lives on this stack and shutdown() runs before the function returns.
    const WheelHostTable table = make_stub_table();

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
    // through ExternalHost books no local message-hook keepalive in this image and can therefore unmap cleanly.
    const std::size_t msghook_before = diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive);

    const WheelHostTable table = make_stub_table();
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

    // The reserved former-WndProc reason never counts.
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive), 0u);
    EXPECT_EQ(diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive), msghook_before)
        << "the external backend must not take the message-hook keepalive; the host owns the pin";
}

TEST(WheelHostLoader, ReentrantHostMutationInvalidatesTheStartCandidate)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();

    const WheelHostTable table = make_stub_table();
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

    WheelHostTable table = make_stub_table();
    table.abi_version = DMK_WHEELHOST_ABI_VERSION - 1u;

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

    const WheelHostTable table = make_stub_table();
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

    WheelHostTable table = make_stub_table();
    table.struct_size = static_cast<std::uint32_t>(sizeof(WheelHostTable) - 1u);
    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    Result<void> result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    mgr.shutdown();

    guard = stage_wheel_binding("wheelhost_required_identity");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();
    table = make_stub_table();
    table.host_identity = 0;
    settings.wheel_host = &table;
    result = mgr.start(settings);
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

    guard = stage_wheel_binding("wheelhost_required_no_status");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();
    table = make_stub_table();
    table.route_status = nullptr;
    settings.wheel_host = &table;
    result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    mgr.shutdown();
}

TEST(WheelHostLoader, RequiredHostMissingRouteFunctionRefusesStart)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_required_no_route");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    // ABI v2 requires route_status and retarget. A table that clears the ROUTE capability or nulls a v2 function is
    // rejected as incompatible, matching a v1 host presented to v2 logic.
    WheelHostTable table = make_stub_table();
    table.retarget = nullptr;
    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    Result<void> result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    mgr.shutdown();

    guard = stage_wheel_binding("wheelhost_required_no_route_cap");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();
    table = make_stub_table();
    table.capability_bits &= ~DMK_WHEELHOST_CAP_ROUTE;
    settings.wheel_host = &table;
    result = mgr.start(settings);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    mgr.shutdown();
}

TEST(WheelHostLoader, ExplicitTargetDrivesHostRouteStatusAndRetarget)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();
    const std::uint32_t target_thread_id = GetCurrentThreadId();
    g_mounted_thread_id.store(distinct_thread_id(target_thread_id));

    const WheelHostTable table = make_stub_table();
    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_explicit_target");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    settings.poll_interval = 5ms;
    // An explicit target that differs from the stub's mounted thread makes the poll loop drive a retarget.
    settings.wheel_target_thread_id = target_thread_id;
    ASSERT_TRUE(mgr.start(settings).has_value());

    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (g_retarget_calls.load() == 0 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_GE(g_route_status_calls.load(), 1) << "the poll loop must read the route snapshot each cycle";
    EXPECT_GE(g_retarget_calls.load(), 1) << "an explicit target differing from the mount must drive a retarget";

    mgr.shutdown();
}

TEST(WheelHostLoader, PendingRetargetRetriesTheMountedThreadAndRecovers)
{
    using Health = input::Input::WheelSourceHealth;
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();

    // The hook remains on A while one retarget transaction waits.
    const std::uint32_t thread_a = GetCurrentThreadId();
    g_mounted_thread_id.store(thread_a);
    g_route_state.store(DMK_WHEELHOST_ROUTE_READY);
    g_control_state.store(DMK_WHEELHOST_CONTROL_RETARGET_PENDING);

    const WheelHostTable table = make_stub_table();
    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_pending_same_thread");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    settings.poll_interval = 5ms;
    // Discovery resolves back to A, the thread the hook is still mounted on.
    settings.wheel_target_thread_id = thread_a;
    ASSERT_TRUE(mgr.start(settings).has_value());

    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (mgr.wheel_source_health() != Health::Ready && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_GE(g_retarget_calls.load(), 1) << "a pending retarget owes a retry even when nothing else changed";
    EXPECT_EQ(g_last_retarget_target.load(), thread_a) << "the retry carries the currently desired thread";
    EXPECT_EQ(mgr.wheel_source_health(), Health::Ready) << "the cleared transaction must restore Ready";

    mgr.shutdown();
}

TEST(WheelHostLoader, PendingRetargetConvergesOnTheLatestDesiredThread)
{
    using Health = input::Input::WheelSourceHealth;
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();

    const std::uint32_t thread_c = GetCurrentThreadId();
    const std::uint32_t thread_a = distinct_thread_id(thread_c);
    g_mounted_thread_id.store(thread_a);
    g_route_state.store(DMK_WHEELHOST_ROUTE_READY);
    g_control_state.store(DMK_WHEELHOST_CONTROL_RETARGET_PENDING);

    const WheelHostTable table = make_stub_table();
    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_pending_latest_intent");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    settings.poll_interval = 5ms;
    settings.wheel_target_thread_id = thread_c;
    ASSERT_TRUE(mgr.start(settings).has_value());

    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (mgr.wheel_source_health() != Health::Ready && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_EQ(g_last_retarget_target.load(), thread_c) << "the retry must carry the latest desired thread";
    EXPECT_EQ(g_mounted_thread_id.load(), thread_c);
    EXPECT_EQ(mgr.wheel_source_health(), Health::Ready);

    mgr.shutdown();
}

TEST(WheelHostLoader, UnknownBackendRefusesStart)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    // Both an out-of-range value and reserved slot 0 are rejected as unknown. Each iteration re-stages a binding,
    // because a start() with an empty pending set is a no-op success that never reaches backend validation.
    for (const std::uint8_t value : {std::uint8_t{255}, std::uint8_t{0}})
    {
        Result<input::BindingGuard> iteration_guard = stage_wheel_binding("wheelhost_unknown_backend");
        ASSERT_TRUE(iteration_guard.has_value()) << iteration_guard.error().message();
        iteration_guard->release();

        input::Input::Settings settings;
        settings.wheel_backend = static_cast<input::Input::WheelBackend>(value);
        const Result<void> result = mgr.start(settings);
        ASSERT_FALSE(result.has_value()) << "backend value " << static_cast<int>(value) << " must be rejected";
        EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
        EXPECT_FALSE(mgr.is_running());
        mgr.shutdown();
    }
}

TEST(WheelHostLoader, DeadWheelTargetThreadRefusesStart)
{
    auto &mgr = input::Input::instance();
    mgr.shutdown();

    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_dead_target");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    // An explicit target must belong to this process and be alive. This id is not a multiple of four, so it names no
    // live thread and OpenThread refuses it.
    input::Input::Settings settings;
    settings.wheel_target_thread_id = 0x0FFFFFFEu;
    const Result<void> result = mgr.start(settings);
    ASSERT_FALSE(result.has_value()) << "a dead explicit wheel target must refuse start()";
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArg);
    EXPECT_FALSE(mgr.is_running());
    mgr.shutdown();
}

TEST(WheelHostLoader, WheelSourceHealthTracksTheExternalRouteState)
{
    using Health = input::Input::WheelSourceHealth;
    auto &mgr = input::Input::instance();
    mgr.shutdown();
    reset_stub_counters();
    EXPECT_EQ(mgr.wheel_source_health(), Health::Inactive) << "no engine must read Inactive";

    const WheelHostTable table = make_stub_table();
    Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_health");
    ASSERT_TRUE(guard.has_value()) << guard.error().message();
    guard->release();

    input::Input::Settings settings;
    settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
    settings.wheel_host = &table;
    settings.wheel_host_required = true;
    settings.poll_interval = 5ms;
    ASSERT_TRUE(mgr.start(settings).has_value());

    const auto wait_for = [&mgr](Health wanted)
    {
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while (mgr.wheel_source_health() != wanted && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(5ms);
        }
        return mgr.wheel_source_health();
    };

    EXPECT_EQ(wait_for(Health::Ready), Health::Ready) << "a ready host route must read Ready";

    // Retarget failure keeps each staged state stable across poll cycles.
    g_retarget_succeeds.store(false);

    // A host route that goes retryable must surface as a non-Ready state rather than silent zero input.
    g_route_state.store(DMK_WHEELHOST_ROUTE_RETRYABLE);
    EXPECT_EQ(wait_for(Health::Retryable), Health::Retryable);

    g_route_state.store(DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED);
    EXPECT_EQ(wait_for(Health::CleanupBlocked), Health::CleanupBlocked);

    // A pending transaction refuses capture even when the route is ready.
    g_route_state.store(DMK_WHEELHOST_ROUTE_READY);
    g_control_state.store(DMK_WHEELHOST_CONTROL_RETARGET_PENDING);
    EXPECT_EQ(wait_for(Health::Retryable), Health::Retryable);

    const int status_calls_before_non_armable = g_route_status_calls.load();
    const int non_armable_status_target = status_calls_before_non_armable + 2;
    g_control_state.store(DMK_WHEELHOST_CONTROL_IDLE);
    g_capture_armable_override.store(0);
    const auto non_armable_deadline = std::chrono::steady_clock::now() + 3s;
    while ((g_route_status_calls.load() < non_armable_status_target ||
            mgr.wheel_source_health() != Health::Retryable) &&
           std::chrono::steady_clock::now() < non_armable_deadline)
    {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_GE(g_route_status_calls.load(), non_armable_status_target);
    EXPECT_EQ(mgr.wheel_source_health(), Health::Retryable);

    g_capture_armable_override.store(-1);
    g_retarget_succeeds.store(true);
    EXPECT_EQ(wait_for(Health::Ready), Health::Ready);

    mgr.shutdown();
    EXPECT_EQ(mgr.wheel_source_health(), Health::Inactive) << "a stopped engine must read Inactive";
}

TEST(WheelHostLoader, CloseAndStopTransactionsDoNotDriveRetarget)
{
    using Health = input::Input::WheelSourceHealth;
    auto &mgr = input::Input::instance();

    for (const std::uint32_t control_state : {DMK_WHEELHOST_CONTROL_CLOSE_PENDING, DMK_WHEELHOST_CONTROL_STOP_PENDING})
    {
        mgr.shutdown();
        reset_stub_counters();
        const std::uint32_t target_thread_id = GetCurrentThreadId();
        g_mounted_thread_id.store(distinct_thread_id(target_thread_id));
        g_control_state.store(control_state);

        const WheelHostTable table = make_stub_table();
        Result<input::BindingGuard> guard = stage_wheel_binding("wheelhost_non_retarget_transaction");
        ASSERT_TRUE(guard.has_value()) << guard.error().message();
        guard->release();

        input::Input::Settings settings;
        settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
        settings.wheel_host = &table;
        settings.wheel_host_required = true;
        settings.poll_interval = 5ms;
        settings.wheel_target_thread_id = target_thread_id;
        ASSERT_TRUE(mgr.start(settings).has_value());

        constexpr int status_call_target = 3;
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while (g_route_status_calls.load() < status_call_target && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(5ms);
        }
        EXPECT_GE(g_route_status_calls.load(), status_call_target);
        EXPECT_EQ(g_retarget_calls.load(), 0);
        EXPECT_EQ(mgr.wheel_source_health(), Health::Retryable);
        mgr.shutdown();
    }
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
