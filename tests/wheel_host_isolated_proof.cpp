/**
 * @file wheel_host_isolated_proof.cpp
 * @brief Verifies the standalone wheel host C ABI against a real message
 * pump.
 */

#include "DetourModKit/abi/wheel_host.h"

#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

using HookProbe = void(DMK_WHEELHOST_CALL *)(void);
extern "C" void DMK_WHEELHOST_CALL wheel_host_test_set_hook_probe(HookProbe probe) noexcept;
extern "C" void DMK_WHEELHOST_CALL wheel_host_test_set_finalize_probe(HookProbe probe) noexcept;
extern "C" void DMK_WHEELHOST_CALL wheel_host_test_force_unhook_failure(uint32_t enabled) noexcept;
extern "C" void DMK_WHEELHOST_CALL wheel_host_test_set_drain_timeout(uint32_t timeout_ms) noexcept;
extern "C" void DMK_WHEELHOST_CALL wheel_host_test_set_process_focus(int32_t focused) noexcept;

// The status layout crosses the C ABI boundary.
static_assert(sizeof(WheelHostRouteStatus) == 32, "WheelHostRouteStatus layout is ABI");
static_assert(alignof(WheelHostRouteStatus) == 8, "WheelHostRouteStatus alignment is ABI");
static_assert(offsetof(WheelHostRouteStatus, struct_size) == 0);
static_assert(offsetof(WheelHostRouteStatus, route_state) == 4);
static_assert(offsetof(WheelHostRouteStatus, control_state) == 8);
static_assert(offsetof(WheelHostRouteStatus, capture_armable) == 12);
static_assert(offsetof(WheelHostRouteStatus, mounted_thread_id) == 16);
static_assert(offsetof(WheelHostRouteStatus, reserved) == 20);
static_assert(offsetof(WheelHostRouteStatus, mount_generation) == 24);

namespace
{
    constexpr UINT WM_APP_SENTINEL = WM_APP + 1;
    constexpr UINT WM_APP_QUIT = WM_APP + 2;
    constexpr std::uint64_t LEASE_OWNER = 0x1111u;
    constexpr std::uint64_t LEASE_GENERATION = 0x2222u;

    std::atomic<int> g_wndproc_wheel_hits{0};
    HANDLE g_hook_entered = nullptr;
    HANDLE g_hook_release = nullptr;

    void DMK_WHEELHOST_CALL park_hook_probe() noexcept
    {
        SetEvent(g_hook_entered);
        WaitForSingleObject(g_hook_release, 10000);
    }

    LRESULT CALLBACK proof_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
    {
        switch (msg)
        {
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
            g_wndproc_wheel_hits.fetch_add(1);
            return 0;
        case WM_APP_QUIT:
            PostQuitMessage(0);
            return 0;
        default:
            break;
        }
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    DWORD WINAPI exit_immediately(void *) noexcept
    {
        return 0;
    }

    const wchar_t *ensure_class()
    {
        static const wchar_t *name = L"DmkWheelHostProofWindow";
        static bool registered = false;
        if (!registered)
        {
            WNDCLASSW wc{};
            wc.lpfnWndProc = &proof_wndproc;
            wc.hInstance = GetModuleHandleW(nullptr);
            wc.lpszClassName = name;
            RegisterClassW(&wc);
            registered = true;
        }
        return name;
    }

    // A dedicated UI thread: it creates a window, signals readiness, and pumps until WM_APP_QUIT. The host hook mounts
    // on this thread.
    class PumpThread
    {
    public:
        PumpThread()
            : ready_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
              quiesced_(CreateEventW(nullptr, FALSE, FALSE, nullptr))
        {
            thread_ = std::thread([this] { run(); });
            WaitForSingleObject(ready_, 10000);
        }

        ~PumpThread()
        {
            if (root_ != nullptr)
            {
                PostMessageW(root_, WM_APP_QUIT, 0, 0);
            }
            else if (tid_ != 0)
            {
                // Window creation failed. A thread WM_QUIT still ends the pump, so the join below cannot hang.
                PostThreadMessageW(tid_, WM_QUIT, 0, 0);
            }
            if (thread_.joinable())
            {
                thread_.join();
            }
            CloseHandle(ready_);
            CloseHandle(quiesced_);
        }

        PumpThread(const PumpThread &) = delete;
        PumpThread &operator=(const PumpThread &) = delete;

        [[nodiscard]] DWORD tid() const noexcept { return tid_; }
        [[nodiscard]] HWND root() const noexcept { return root_; }

        void post_wheel(bool horizontal, int delta)
        {
            PostMessageW(root_, horizontal ? WM_MOUSEHWHEEL : WM_MOUSEWHEEL,
                         MAKEWPARAM(0, static_cast<WORD>(static_cast<short>(delta))), 0);
        }

        // Posts a trailing sentinel and waits for its dispatch, proving every earlier posted message was retrieved.
        [[nodiscard]] bool quiesce()
        {
            PostMessageW(root_, WM_APP_SENTINEL, 0, 0);
            return WaitForSingleObject(quiesced_, 10000) == WAIT_OBJECT_0;
        }

    private:
        void run()
        {
            tid_ = GetCurrentThreadId();
            root_ = CreateWindowExW(0, ensure_class(), L"proof-root", WS_OVERLAPPEDWINDOW, 0, 0, 320, 240, nullptr,
                                    nullptr, GetModuleHandleW(nullptr), nullptr);
            SetEvent(ready_);
            MSG msg{};
            while (GetMessageW(&msg, nullptr, 0, 0) > 0)
            {
                if (msg.message == WM_APP_SENTINEL)
                {
                    SetEvent(quiesced_);
                    continue;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            if (root_ != nullptr && IsWindow(root_))
            {
                DestroyWindow(root_);
            }
        }

        std::thread thread_;
        HANDLE ready_ = nullptr;
        HANDLE quiesced_ = nullptr;
        DWORD tid_ = 0;
        HWND root_ = nullptr;
    };

    // Fixture: one pump thread and one started host per case. The host is a process singleton, so Start/Stop bracket
    // every case for isolation.
    class WheelHostProof : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            g_wndproc_wheel_hits.store(0);
            pump_ = std::make_unique<PumpThread>();
            ASSERT_NE(pump_->tid(), 0u);
            ASSERT_NE(pump_->root(), nullptr);
            ASSERT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                       static_cast<std::uint32_t>(sizeof(table_)), &table_),
                      DMK_WHEELHOST_OK);
        }

        void TearDown() override
        {
            if (g_hook_release != nullptr)
            {
                SetEvent(g_hook_release);
            }
            wheel_host_test_set_hook_probe(nullptr);
            wheel_host_test_set_finalize_probe(nullptr);
            wheel_host_test_force_unhook_failure(0);
            wheel_host_test_set_drain_timeout(0);
            wheel_host_test_set_process_focus(-1);
            // v2 Stop refuses with an open lease, so close any lease the case left open before resetting the
            // singleton for the next case. A close of an already-closed or Closing lease is harmless here.
            if (active_lease_ != 0)
            {
                (void)table_.close_lease(table_.host_context, active_lease_, LEASE_OWNER, LEASE_GENERATION);
                active_lease_ = 0;
            }
            wheel_host_stop();
            pump_.reset();
            if (g_hook_release != nullptr)
            {
                CloseHandle(g_hook_release);
                g_hook_release = nullptr;
            }
            if (g_hook_entered != nullptr)
            {
                CloseHandle(g_hook_entered);
                g_hook_entered = nullptr;
            }
        }

        // Reads one snapshot and asserts the call itself succeeded, so each case asserts only on the fields.
        [[nodiscard]] WheelHostRouteStatus status(WheelHostLease lease = 0)
        {
            WheelHostRouteStatus snapshot{};
            EXPECT_EQ(table_.route_status(table_.host_context, lease, static_cast<std::uint32_t>(sizeof(snapshot)),
                                          &snapshot),
                      DMK_WHEELHOST_OK);
            return snapshot;
        }

        [[nodiscard]] WheelHostLease open()
        {
            WheelHostLease lease = 0;
            EXPECT_EQ(table_.open_lease(table_.host_context, LEASE_OWNER, LEASE_GENERATION, &lease), DMK_WHEELHOST_OK);
            EXPECT_NE(lease, 0u);
            active_lease_ = lease;
            return lease;
        }

        std::unique_ptr<PumpThread> pump_;
        WheelHostTable table_{};
        // The last lease open() returned, closed by TearDown so a leaked lease cannot block the next case's Stop.
        WheelHostLease active_lease_ = 0;
    };

    TEST_F(WheelHostProof, StartFillsAValidTable)
    {
        EXPECT_EQ(table_.struct_size, sizeof(WheelHostTable));
        EXPECT_EQ(table_.abi_version, DMK_WHEELHOST_ABI_VERSION);
        EXPECT_NE(table_.host_identity, 0u);
        EXPECT_NE(table_.host_context, nullptr);
        EXPECT_TRUE(table_.capability_bits & DMK_WHEELHOST_CAP_VERTICAL);
        EXPECT_TRUE(table_.capability_bits & DMK_WHEELHOST_CAP_HORIZONTAL);
        EXPECT_TRUE(table_.capability_bits & DMK_WHEELHOST_CAP_CONSUME);
        EXPECT_TRUE(table_.capability_bits & DMK_WHEELHOST_CAP_ROUTE);
        EXPECT_NE(table_.open_lease, nullptr);
        EXPECT_NE(table_.publish_capture, nullptr);
        EXPECT_NE(table_.drain_counts, nullptr);
        EXPECT_NE(table_.close_lease, nullptr);
        EXPECT_NE(table_.route_status, nullptr);
        EXPECT_NE(table_.retarget, nullptr);
    }

    TEST_F(WheelHostProof, DoubleStartIsRefused)
    {
        WheelHostTable second{};
        EXPECT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(second)),
                                   &second),
                  DMK_WHEELHOST_ERR_STATE);
    }

    TEST_F(WheelHostProof, StartRejectsBadArguments)
    {
        wheel_host_stop();
        // out_table must not be null.
        EXPECT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)),
                                   nullptr),
                  DMK_WHEELHOST_ERR_INVALID);
        // A zero target is valid in ABI v2: the host starts unmounted in target-wait. This also leaves a started host
        // for TearDown's Stop.
        ASSERT_EQ(wheel_host_start(0u, DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_OK);
        EXPECT_EQ(status().route_state, DMK_WHEELHOST_ROUTE_TARGET_WAIT);
    }

    TEST_F(WheelHostProof, StartRejectsAnIncompatibleOrShortTable)
    {
        ASSERT_EQ(wheel_host_stop(), DMK_WHEELHOST_OK);
        EXPECT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION + 1u,
                                   static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_ERR_ABI);
        EXPECT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION - 1u,
                                   static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_ERR_ABI);
        EXPECT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                   static_cast<std::uint32_t>(sizeof(table_) - 1u), &table_),
                  DMK_WHEELHOST_ERR_ABI);
        ASSERT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)),
                                   &table_),
                  DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, SecondLeaseIsBusy)
    {
        const WheelHostLease first = open();
        WheelHostLease second = 0;
        EXPECT_EQ(table_.open_lease(table_.host_context, 0x3u, 0x4u, &second), DMK_WHEELHOST_ERR_BUSY);
        EXPECT_EQ(second, 0u);
        EXPECT_EQ(table_.close_lease(table_.host_context, first, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
        // After close a fresh lease succeeds.
        const WheelHostLease third = open();
        EXPECT_NE(third, first);
    }

    TEST_F(WheelHostProof, CloseRequiresTheOpeningOwnerAndGeneration)
    {
        const WheelHostLease lease = open();
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER + 1u, LEASE_GENERATION),
                  DMK_WHEELHOST_ERR_STALE);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION + 1u),
                  DMK_WHEELHOST_ERR_STALE);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, VerticalAndHorizontalCountsFold)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        pump_->post_wheel(false, 120);
        pump_->post_wheel(false, 120);
        pump_->post_wheel(false, 120);
        pump_->post_wheel(false, -120);
        pump_->post_wheel(true, 120);
        pump_->post_wheel(true, -120);
        pump_->post_wheel(true, 120);
        ASSERT_TRUE(pump_->quiesce());
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 3u);
        EXPECT_EQ(counts[DMK_WHEEL_DOWN], 1u);
        EXPECT_EQ(counts[DMK_WHEEL_RIGHT], 2u);
        EXPECT_EQ(counts[DMK_WHEEL_LEFT], 1u);
        // A second drain reports zero.
        std::uint32_t again[DMK_WHEEL_DIRECTIONS] = {9, 9, 9, 9};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, again), DMK_WHEELHOST_OK);
        EXPECT_EQ(again[DMK_WHEEL_UP], 0u);
        EXPECT_EQ(again[DMK_WHEEL_DOWN], 0u);
        EXPECT_EQ(again[DMK_WHEEL_RIGHT], 0u);
        EXPECT_EQ(again[DMK_WHEEL_LEFT], 0u);
    }

    TEST_F(WheelHostProof, PartialDeltasFoldIntoWholeNotches)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        // 40 + 40 + 40 = one Up; 60 - 60 = nothing; 80 + 50 = one Up (rem 10); 10 - 130 = one Down (rem 0).
        for (const int d : {40, 40, 40, 60, -60, 80, 50, -130})
        {
            pump_->post_wheel(false, d);
        }
        ASSERT_TRUE(pump_->quiesce());
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 2u);
        EXPECT_EQ(counts[DMK_WHEEL_DOWN], 1u);
    }

    TEST_F(WheelHostProof, PartialDeltasDoNotCrossOwnershipChanges)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        pump_->post_wheel(false, 60);
        ASSERT_TRUE(pump_->quiesce());

        ASSERT_EQ(
            table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, DMK_WHEEL_CONSUME_UP, 5000u),
            DMK_WHEELHOST_OK);
        pump_->post_wheel(false, 60);
        ASSERT_TRUE(pump_->quiesce());
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 0u);

        pump_->post_wheel(false, 60);
        ASSERT_TRUE(pump_->quiesce());
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 1u);
    }

    TEST_F(WheelHostProof, CloseDrainsAParkedCallbackAndRefusesASuccessorUntilItLeaves)
    {
        // ABI v2 rundown: a close while a callback is parked in an admitted phase returns DRAIN and holds the lease in
        // a disabled Closing state. A successor open is refused until the exact close retry finishes the drain. The
        // parked callback's epoch was advanced by the close, so on release it can neither count nor swallow.
        const WheelHostLease first = open();
        ASSERT_EQ(table_.publish_capture(table_.host_context, first, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        g_hook_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_hook_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ASSERT_NE(g_hook_entered, nullptr);
        ASSERT_NE(g_hook_release, nullptr);
        wheel_host_test_set_drain_timeout(200);
        wheel_host_test_set_hook_probe(&park_hook_probe);

        pump_->post_wheel(false, 120);
        const DWORD entered = WaitForSingleObject(g_hook_entered, 10000);
        ASSERT_EQ(entered, WAIT_OBJECT_0);

        // The parked phase blocks the bounded drain: close reports DRAIN and enters Closing.
        EXPECT_EQ(table_.close_lease(table_.host_context, first, LEASE_OWNER, LEASE_GENERATION),
                  DMK_WHEELHOST_ERR_DRAIN);
        // A successor open is refused while the close is pending.
        WheelHostLease second = 0;
        EXPECT_EQ(table_.open_lease(table_.host_context, LEASE_OWNER, LEASE_GENERATION, &second),
                  DMK_WHEELHOST_ERR_PENDING);
        EXPECT_EQ(second, 0u);

        // Release the parked callback and retry the exact close, which now finishes the drain.
        SetEvent(g_hook_release);
        wheel_host_test_set_hook_probe(nullptr);
        EXPECT_EQ(table_.close_lease(table_.host_context, first, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);

        // A fresh lease now opens, and the released callback wrote nothing into it.
        const WheelHostLease third = open();
        ASSERT_EQ(table_.publish_capture(table_.host_context, third, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        ASSERT_TRUE(pump_->quiesce());
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, third, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 0u);
    }

    TEST_F(WheelHostProof, NoLeaseForwardsUnchanged)
    {
        // No lease is open, so the hook forwards. The window procedure receives the wheel.
        pump_->post_wheel(false, 120);
        ASSERT_TRUE(pump_->quiesce());
        EXPECT_GE(g_wndproc_wheel_hits.load(), 1);
    }

    TEST_F(WheelHostProof, DisabledCaptureCountsNothing)
    {
        const WheelHostLease lease = open();
        // Lease open but capture never enabled: the hook forwards and counts nothing.
        pump_->post_wheel(false, 120);
        ASSERT_TRUE(pump_->quiesce());
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 0u);
        EXPECT_GE(g_wndproc_wheel_hits.load(), 1);
    }

    TEST_F(WheelHostProof, StaleTokenIsRejected)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        EXPECT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_ERR_NO_LEASE);
        const WheelHostLease fresh = open();
        EXPECT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_ERR_STALE);
        EXPECT_EQ(table_.publish_capture(table_.host_context, fresh, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, OperationsWithoutLeaseReportNoLease)
    {
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        EXPECT_EQ(table_.drain_counts(table_.host_context, 1u, counts), DMK_WHEELHOST_ERR_NO_LEASE);
        EXPECT_EQ(table_.publish_capture(table_.host_context, 1u, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_ERR_NO_LEASE);
        EXPECT_EQ(table_.close_lease(table_.host_context, 1u, LEASE_OWNER, LEASE_GENERATION),
                  DMK_WHEELHOST_ERR_NO_LEASE);
    }

    TEST_F(WheelHostProof, BadHostContextIsRejected)
    {
        int not_the_host = 0;
        WheelHostLease lease = 0;
        EXPECT_EQ(table_.open_lease(&not_the_host, 0u, 0u, &lease), DMK_WHEELHOST_ERR_INVALID);
        const WheelHostLease good = open();
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        EXPECT_EQ(table_.drain_counts(&not_the_host, good, counts), DMK_WHEELHOST_ERR_INVALID);
        EXPECT_EQ(table_.open_lease(table_.host_context, 0u, 0u, nullptr), DMK_WHEELHOST_ERR_INVALID);
    }

    TEST_F(WheelHostProof, ConsumeSwallowsOwnedWheelButStillCounts)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(
            table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, DMK_WHEEL_CONSUME_UP, 5000u),
            DMK_WHEELHOST_OK);
        pump_->post_wheel(false, 120); // Up, owned
        ASSERT_TRUE(pump_->quiesce());
        // The owned wheel was swallowed to WM_NULL before dispatch, so the window procedure never saw it.
        EXPECT_EQ(g_wndproc_wheel_hits.load(), 0);
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 1u);
    }

    TEST_F(WheelHostProof, UnownedDirectionIsNotSwallowed)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(
            table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, DMK_WHEEL_CONSUME_UP, 5000u),
            DMK_WHEELHOST_OK);
        pump_->post_wheel(false, -120); // Down, not in the consume mask
        ASSERT_TRUE(pump_->quiesce());
        EXPECT_GE(g_wndproc_wheel_hits.load(), 1);
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_DOWN], 1u);
    }

    TEST_F(WheelHostProof, StopThenOperationsFailAndStopIsIdempotentlyRefused)
    {
        EXPECT_EQ(wheel_host_stop(), DMK_WHEELHOST_OK);
        EXPECT_EQ(wheel_host_stop(), DMK_WHEELHOST_ERR_STATE);
        // Restart so TearDown finds a started host.
        ASSERT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)),
                                   &table_),
                  DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, FailedUnhookBlocksASecondMount)
    {
        wheel_host_test_force_unhook_failure(1);
        EXPECT_EQ(wheel_host_stop(), DMK_WHEELHOST_ERR_THREAD);
        WheelHostTable second{};
        EXPECT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(second)),
                                   &second),
                  DMK_WHEELHOST_ERR_STATE);

        wheel_host_test_force_unhook_failure(0);
        ASSERT_EQ(wheel_host_stop(), DMK_WHEELHOST_OK);
        ASSERT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)),
                                   &table_),
                  DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, RouteStatusReportsAMountedThreadAndGeneration)
    {
        const WheelHostLease lease = open();
        const WheelHostRouteStatus snapshot = status(lease);
        EXPECT_EQ(snapshot.struct_size, sizeof(WheelHostRouteStatus));
        EXPECT_EQ(snapshot.route_state, DMK_WHEELHOST_ROUTE_READY);
        EXPECT_EQ(snapshot.control_state, DMK_WHEELHOST_CONTROL_IDLE);
        EXPECT_EQ(snapshot.capture_armable, 1u);
        EXPECT_EQ(snapshot.mounted_thread_id, pump_->tid());
        EXPECT_NE(snapshot.mount_generation, 0u);
        EXPECT_EQ(snapshot.reserved, 0u);

        // An unqualified probe reads the same route but arms nothing, because it named no lease.
        const WheelHostRouteStatus probe = status();
        EXPECT_EQ(probe.route_state, DMK_WHEELHOST_ROUTE_READY);
        EXPECT_EQ(probe.mounted_thread_id, pump_->tid());
        EXPECT_EQ(probe.capture_armable, 0u);
    }

    TEST_F(WheelHostProof, RouteStatusRejectsShortCapacityStaleLeaseAndNullOut)
    {
        const WheelHostLease lease = open();
        WheelHostRouteStatus snapshot{};
        EXPECT_EQ(
            table_.route_status(table_.host_context, lease, static_cast<std::uint32_t>(sizeof(snapshot)), nullptr),
            DMK_WHEELHOST_ERR_INVALID);
        EXPECT_EQ(table_.route_status(table_.host_context, lease, static_cast<std::uint32_t>(sizeof(snapshot) - 1u),
                                      &snapshot),
                  DMK_WHEELHOST_ERR_ABI);
        EXPECT_EQ(table_.route_status(table_.host_context, lease + 1u, static_cast<std::uint32_t>(sizeof(snapshot)),
                                      &snapshot),
                  DMK_WHEELHOST_ERR_STALE);
        EXPECT_EQ(table_.route_status(nullptr, lease, static_cast<std::uint32_t>(sizeof(snapshot)), &snapshot),
                  DMK_WHEELHOST_ERR_INVALID);
        // None of the refusals disturbed the route or the lease.
        EXPECT_EQ(status(lease).capture_armable, 1u);
    }

    TEST_F(WheelHostProof, RouteStatusBeforeStartReportsState)
    {
        const WheelHostTable saved = table_;
        ASSERT_EQ(wheel_host_stop(), DMK_WHEELHOST_OK);
        WheelHostRouteStatus snapshot{};
        EXPECT_EQ(saved.route_status(saved.host_context, 0u, static_cast<std::uint32_t>(sizeof(snapshot)), &snapshot),
                  DMK_WHEELHOST_ERR_STATE);
        // Restart so TearDown finds a started host.
        ASSERT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)),
                                   &table_),
                  DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, TargetWaitStartMountsAndCountsAfterRetarget)
    {
        // Restart unmounted, open a lease while unmounted, and prove capture stays disabled until the first retarget.
        ASSERT_EQ(wheel_host_stop(), DMK_WHEELHOST_OK);
        ASSERT_EQ(wheel_host_start(0u, DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_OK);
        const std::uint64_t identity_before = table_.host_identity;

        const WheelHostLease lease = open();
        EXPECT_EQ(status(lease).route_state, DMK_WHEELHOST_ROUTE_TARGET_WAIT);
        EXPECT_EQ(status(lease).capture_armable, 0u) << "an unmounted lease cannot arm capture";
        // Publish capture while unmounted: it is accepted but counting stays disabled.
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        pump_->post_wheel(false, 120);
        ASSERT_TRUE(pump_->quiesce());
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 0u) << "an unmounted lease must not count";

        // Retarget mounts the hook and preserves the host identity and the lease.
        ASSERT_EQ(table_.retarget(table_.host_context, lease, pump_->tid()), DMK_WHEELHOST_OK);
        EXPECT_EQ(table_.host_identity, identity_before);
        EXPECT_EQ(status(lease).route_state, DMK_WHEELHOST_ROUTE_READY);
        EXPECT_EQ(status(lease).capture_armable, 1u);
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        pump_->post_wheel(false, 120);
        ASSERT_TRUE(pump_->quiesce());
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 1u) << "a mounted lease counts after retarget";
    }

    TEST_F(WheelHostProof, SameThreadRetargetKeepsMountGeneration)
    {
        const WheelHostLease lease = open();
        const std::uint64_t before = status(lease).mount_generation;
        // A retarget to the already-mounted thread is a success and does not change the mount generation.
        ASSERT_EQ(table_.retarget(table_.host_context, lease, pump_->tid()), DMK_WHEELHOST_OK);
        EXPECT_EQ(status(lease).mount_generation, before);
    }

    TEST_F(WheelHostProof, FailedTargetRetargetCanRecoverOrClose)
    {
        const WheelHostLease lease = open();
        std::unique_ptr<void, decltype(&CloseHandle)> exited_thread(
            CreateThread(nullptr, 0, &exit_immediately, nullptr, 0, nullptr), &CloseHandle);
        ASSERT_NE(exited_thread.get(), nullptr);
        const DWORD exited_thread_id = GetThreadId(exited_thread.get());
        ASSERT_NE(exited_thread_id, 0u);
        ASSERT_EQ(WaitForSingleObject(exited_thread.get(), 10000), WAIT_OBJECT_0);

        const std::int32_t failed_status = table_.retarget(table_.host_context, lease, exited_thread_id);
        ASSERT_EQ(failed_status, DMK_WHEELHOST_ERR_THREAD);
        const WheelHostRouteStatus failed = status(lease);
        EXPECT_EQ(failed.route_state, DMK_WHEELHOST_ROUTE_RETRYABLE);
        EXPECT_EQ(failed.mounted_thread_id, 0u);
        EXPECT_EQ(failed.control_state, DMK_WHEELHOST_CONTROL_RETARGET_PENDING);
        EXPECT_EQ(failed.capture_armable, 0u);

        EXPECT_EQ(table_.retarget(table_.host_context, lease + 1u, pump_->tid()), DMK_WHEELHOST_ERR_PENDING);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER + 1u, LEASE_GENERATION),
                  DMK_WHEELHOST_ERR_PENDING);
        ASSERT_EQ(table_.retarget(table_.host_context, lease, pump_->tid()), DMK_WHEELHOST_OK);
        const std::int32_t second_failed_status = table_.retarget(table_.host_context, lease, exited_thread_id);
        ASSERT_EQ(second_failed_status, DMK_WHEELHOST_ERR_THREAD);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION + 1u),
                  DMK_WHEELHOST_ERR_PENDING);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
        active_lease_ = 0;
    }

    TEST_F(WheelHostProof, RetargetDrainKeepsTheMountedRouteVisible)
    {
        const WheelHostLease lease = open();
        PumpThread successor;
        ASSERT_NE(successor.tid(), 0u);
        const std::uint64_t generation = status(lease).mount_generation;
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        g_hook_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_hook_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ASSERT_NE(g_hook_entered, nullptr);
        ASSERT_NE(g_hook_release, nullptr);
        wheel_host_test_set_drain_timeout(20);
        wheel_host_test_set_hook_probe(&park_hook_probe);

        pump_->post_wheel(false, 120);
        ASSERT_EQ(WaitForSingleObject(g_hook_entered, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(table_.retarget(table_.host_context, lease, successor.tid()), DMK_WHEELHOST_ERR_DRAIN);

        // The mounted route remains alive, but a pending transaction disables the lease data plane.
        const WheelHostRouteStatus pending = status(lease);
        EXPECT_EQ(pending.route_state, DMK_WHEELHOST_ROUTE_READY);
        EXPECT_EQ(pending.mounted_thread_id, pump_->tid());
        EXPECT_EQ(pending.control_state, DMK_WHEELHOST_CONTROL_RETARGET_PENDING);
        EXPECT_EQ(pending.capture_armable, 0u) << "a pending transaction refuses the data plane";
        EXPECT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_ERR_PENDING);

        SetEvent(g_hook_release);
        wheel_host_test_set_hook_probe(nullptr);
        ASSERT_TRUE(pump_->quiesce());

        // A status query preserves the transaction after callback quiescence.
        EXPECT_EQ(status(lease).control_state, DMK_WHEELHOST_CONTROL_RETARGET_PENDING)
            << "no status query may expire a transaction";
        EXPECT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_ERR_PENDING);

        // A same-thread retry cancels the transaction without a remount.
        EXPECT_EQ(table_.retarget(table_.host_context, lease, pump_->tid()), DMK_WHEELHOST_OK);
        const WheelHostRouteStatus recovered = status(lease);
        EXPECT_EQ(recovered.mount_generation, generation);
        EXPECT_EQ(recovered.control_state, DMK_WHEELHOST_CONTROL_IDLE);
        EXPECT_EQ(recovered.capture_armable, 1u);
        EXPECT_EQ(table_.retarget(table_.host_context, lease, successor.tid()), DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, PendingRetargetConvergesOnAThirdThread)
    {
        const WheelHostLease lease = open();
        PumpThread destination_b;
        PumpThread destination_c;
        ASSERT_NE(destination_b.tid(), 0u);
        ASSERT_NE(destination_c.tid(), 0u);
        const std::uint64_t generation = status(lease).mount_generation;
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        g_hook_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_hook_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ASSERT_NE(g_hook_entered, nullptr);
        ASSERT_NE(g_hook_release, nullptr);
        wheel_host_test_set_drain_timeout(20);
        wheel_host_test_set_hook_probe(&park_hook_probe);

        pump_->post_wheel(false, 120);
        ASSERT_EQ(WaitForSingleObject(g_hook_entered, 10000), WAIT_OBJECT_0);
        ASSERT_EQ(table_.retarget(table_.host_context, lease, destination_b.tid()), DMK_WHEELHOST_ERR_DRAIN);
        SetEvent(g_hook_release);
        wheel_host_test_set_hook_probe(nullptr);
        ASSERT_TRUE(pump_->quiesce());

        ASSERT_EQ(table_.retarget(table_.host_context, lease, destination_c.tid()), DMK_WHEELHOST_OK);
        const WheelHostRouteStatus migrated = status(lease);
        EXPECT_EQ(migrated.mounted_thread_id, destination_c.tid()) << "the retry destination wins over B";
        EXPECT_EQ(migrated.control_state, DMK_WHEELHOST_CONTROL_IDLE);
        EXPECT_EQ(migrated.capture_armable, 1u);
        EXPECT_EQ(migrated.mount_generation, generation + 1u) << "one completed migration, one increment";
    }

    TEST_F(WheelHostProof, CleanupBlockedReportsTheMountedThread)
    {
        const WheelHostLease lease = open();
        PumpThread successor;
        ASSERT_NE(successor.tid(), 0u);
        wheel_host_test_force_unhook_failure(1);
        EXPECT_EQ(table_.retarget(table_.host_context, lease, successor.tid()), DMK_WHEELHOST_ERR_THREAD);

        const WheelHostRouteStatus blocked = status(lease);
        EXPECT_EQ(blocked.route_state, DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED);
        EXPECT_EQ(blocked.mounted_thread_id, pump_->tid());
        EXPECT_EQ(blocked.control_state, DMK_WHEELHOST_CONTROL_RETARGET_PENDING);
        EXPECT_EQ(blocked.capture_armable, 0u);

        wheel_host_test_force_unhook_failure(0);
        EXPECT_EQ(table_.retarget(table_.host_context, lease, successor.tid()), DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, CountAdmissionRechecksANewFocusRequirement)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        wheel_host_test_set_process_focus(0);
        g_hook_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_hook_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ASSERT_NE(g_hook_entered, nullptr);
        ASSERT_NE(g_hook_release, nullptr);
        wheel_host_test_set_hook_probe(&park_hook_probe);

        pump_->post_wheel(false, 120);
        ASSERT_EQ(WaitForSingleObject(g_hook_entered, 10000), WAIT_OBJECT_0);
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease,
                                         DMK_WHEEL_CAPTURE_ENABLED | DMK_WHEEL_CAPTURE_REQUIRE_FOCUS, 0u, 0u),
                  DMK_WHEELHOST_OK);
        SetEvent(g_hook_release);
        wheel_host_test_set_hook_probe(nullptr);
        ASSERT_TRUE(pump_->quiesce());

        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_OK);
        EXPECT_EQ(counts[DMK_WHEEL_UP], 0u);
    }

    TEST_F(WheelHostProof, ConsumeFinalizationRechecksANewFocusRequirement)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(
            table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, DMK_WHEEL_CONSUME_UP, 5000u),
            DMK_WHEELHOST_OK);
        wheel_host_test_set_process_focus(0);
        g_hook_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_hook_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ASSERT_NE(g_hook_entered, nullptr);
        ASSERT_NE(g_hook_release, nullptr);
        wheel_host_test_set_finalize_probe(&park_hook_probe);

        pump_->post_wheel(false, 120);
        ASSERT_EQ(WaitForSingleObject(g_hook_entered, 10000), WAIT_OBJECT_0);
        ASSERT_EQ(table_.publish_capture(table_.host_context, lease,
                                         DMK_WHEEL_CAPTURE_ENABLED | DMK_WHEEL_CAPTURE_REQUIRE_FOCUS,
                                         DMK_WHEEL_CONSUME_UP, 5000u),
                  DMK_WHEELHOST_OK);
        SetEvent(g_hook_release);
        wheel_host_test_set_finalize_probe(nullptr);
        ASSERT_TRUE(pump_->quiesce());
        EXPECT_GE(g_wndproc_wheel_hits.load(), 1);
    }

    TEST_F(WheelHostProof, FinalizationPhaseParticipatesInCloseDrain)
    {
        const WheelHostLease lease = open();
        ASSERT_EQ(
            table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, DMK_WHEEL_CONSUME_UP, 5000u),
            DMK_WHEELHOST_OK);
        g_hook_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_hook_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ASSERT_NE(g_hook_entered, nullptr);
        ASSERT_NE(g_hook_release, nullptr);
        wheel_host_test_set_drain_timeout(20);
        wheel_host_test_set_finalize_probe(&park_hook_probe);

        pump_->post_wheel(false, 120);
        ASSERT_EQ(WaitForSingleObject(g_hook_entered, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION),
                  DMK_WHEELHOST_ERR_DRAIN);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER + 1u, LEASE_GENERATION),
                  DMK_WHEELHOST_ERR_PENDING);

        SetEvent(g_hook_release);
        wheel_host_test_set_finalize_probe(nullptr);
        ASSERT_TRUE(pump_->quiesce());
        EXPECT_GE(g_wndproc_wheel_hits.load(), 1);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
        active_lease_ = 0;
    }

    TEST_F(WheelHostProof, StopSupersedesAPendingClose)
    {
        const WheelHostLease lease = open();
        const WheelHostRouteStatus mounted = status(lease);
        const std::uint64_t host_identity = table_.host_identity;
        ASSERT_EQ(
            table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, DMK_WHEEL_CONSUME_UP, 5000u),
            DMK_WHEELHOST_OK);
        g_hook_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_hook_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ASSERT_NE(g_hook_entered, nullptr);
        ASSERT_NE(g_hook_release, nullptr);
        wheel_host_test_set_drain_timeout(20);
        wheel_host_test_set_finalize_probe(&park_hook_probe);

        pump_->post_wheel(false, 120);
        ASSERT_EQ(WaitForSingleObject(g_hook_entered, 10000), WAIT_OBJECT_0);
        ASSERT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION),
                  DMK_WHEELHOST_ERR_DRAIN);
        EXPECT_EQ(status(lease).control_state, DMK_WHEELHOST_CONTROL_CLOSE_PENDING);

        EXPECT_EQ(wheel_host_stop(), DMK_WHEELHOST_ERR_DRAIN);
        const WheelHostRouteStatus stopping = status(lease);
        EXPECT_EQ(stopping.route_state, DMK_WHEELHOST_ROUTE_READY);
        EXPECT_EQ(stopping.control_state, DMK_WHEELHOST_CONTROL_STOP_PENDING);
        EXPECT_EQ(stopping.capture_armable, 0u);
        EXPECT_EQ(stopping.mounted_thread_id, mounted.mounted_thread_id);
        EXPECT_EQ(stopping.mount_generation, mounted.mount_generation);
        EXPECT_EQ(table_.host_identity, host_identity);
        EXPECT_EQ(table_.publish_capture(table_.host_context, lease, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_ERR_PENDING);

        // The retained lease rejects every lease-scoped escape while Stop remains pending.
        WheelHostLease successor_lease = 0;
        EXPECT_EQ(table_.open_lease(table_.host_context, LEASE_OWNER + 7u, LEASE_GENERATION + 7u, &successor_lease),
                  DMK_WHEELHOST_ERR_PENDING);
        EXPECT_EQ(table_.retarget(table_.host_context, lease, pump_->tid()), DMK_WHEELHOST_ERR_PENDING);

        SetEvent(g_hook_release);
        wheel_host_test_set_finalize_probe(nullptr);
        ASSERT_TRUE(pump_->quiesce());
        EXPECT_EQ(wheel_host_stop(), DMK_WHEELHOST_OK) << "Stop supersedes the pending close";
        active_lease_ = 0;
        // Successful Stop permits a clean restart and a new lease.
        ASSERT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)),
                                   &table_),
                  DMK_WHEELHOST_OK);
        EXPECT_EQ(status().control_state, DMK_WHEELHOST_CONTROL_IDLE);
        const WheelHostLease reopened = open();
        EXPECT_NE(reopened, 0u);
        EXPECT_EQ(status(reopened).capture_armable, 1u);
    }

    // Stop returns Busy while the lease holder retains authority over a Retarget transaction.
    TEST_F(WheelHostProof, StopWithAPendingRetargetIsBusy)
    {
        const WheelHostLease lease = open();
        std::unique_ptr<void, decltype(&CloseHandle)> exited_thread(
            CreateThread(nullptr, 0, &exit_immediately, nullptr, 0, nullptr), &CloseHandle);
        ASSERT_NE(exited_thread.get(), nullptr);
        const DWORD exited_thread_id = GetThreadId(exited_thread.get());
        ASSERT_NE(exited_thread_id, 0u);
        ASSERT_EQ(WaitForSingleObject(exited_thread.get(), 10000), WAIT_OBJECT_0);
        ASSERT_EQ(table_.retarget(table_.host_context, lease, exited_thread_id), DMK_WHEELHOST_ERR_THREAD);
        const WheelHostRouteStatus before_stop = status(lease);
        ASSERT_EQ(before_stop.control_state, DMK_WHEELHOST_CONTROL_RETARGET_PENDING);
        const std::uint64_t host_identity = table_.host_identity;

        EXPECT_EQ(wheel_host_stop(), DMK_WHEELHOST_ERR_BUSY);
        const WheelHostRouteStatus after_stop = status(lease);
        EXPECT_EQ(after_stop.struct_size, before_stop.struct_size);
        EXPECT_EQ(after_stop.route_state, before_stop.route_state);
        EXPECT_EQ(after_stop.control_state, before_stop.control_state);
        EXPECT_EQ(after_stop.capture_armable, before_stop.capture_armable);
        EXPECT_EQ(after_stop.mounted_thread_id, before_stop.mounted_thread_id);
        EXPECT_EQ(after_stop.reserved, before_stop.reserved);
        EXPECT_EQ(after_stop.mount_generation, before_stop.mount_generation);
        EXPECT_EQ(table_.host_identity, host_identity);
        EXPECT_EQ(table_.retarget(table_.host_context, lease, pump_->tid()), DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, StopWithAnOpenLeaseIsBusy)
    {
        const WheelHostLease lease = open();
        EXPECT_EQ(wheel_host_stop(), DMK_WHEELHOST_ERR_BUSY);
        // The lease is untouched: close still succeeds, then Stop proceeds.
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
        EXPECT_EQ(wheel_host_stop(), DMK_WHEELHOST_OK);
        // Restart so TearDown finds a started host.
        ASSERT_EQ(wheel_host_start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)),
                                   &table_),
                  DMK_WHEELHOST_OK);
    }

} // namespace
