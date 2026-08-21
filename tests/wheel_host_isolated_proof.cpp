/**
 * @file wheel_host_isolated_proof.cpp
 * @brief Verifies the standalone wheel host C ABI against a real message
 * pump.
 */

#include "DetourModKit/abi/wheel_host.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

using HookProbe = void(DMK_WHEELHOST_CALL *)(void);
extern "C" void DMK_WHEELHOST_CALL DmkWheelHost_TestSetHookProbe(HookProbe probe) noexcept;
extern "C" void DMK_WHEELHOST_CALL DmkWheelHost_TestForceUnhookFailure(uint32_t enabled) noexcept;

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
            ASSERT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                         static_cast<std::uint32_t>(sizeof(table_)), &table_),
                      DMK_WHEELHOST_OK);
        }

        void TearDown() override
        {
            if (g_hook_release != nullptr)
            {
                SetEvent(g_hook_release);
            }
            DmkWheelHost_TestSetHookProbe(nullptr);
            DmkWheelHost_TestForceUnhookFailure(0);
            DmkWheelHost_Stop();
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

        [[nodiscard]] DmkWheelLease open()
        {
            DmkWheelLease lease = 0;
            EXPECT_EQ(table_.open_lease(table_.host_context, LEASE_OWNER, LEASE_GENERATION, &lease), DMK_WHEELHOST_OK);
            EXPECT_NE(lease, 0u);
            return lease;
        }

        std::unique_ptr<PumpThread> pump_;
        DmkWheelHostTable table_{};
    };

    TEST_F(WheelHostProof, StartFillsAValidTable)
    {
        EXPECT_EQ(table_.struct_size, sizeof(DmkWheelHostTable));
        EXPECT_EQ(table_.abi_version, DMK_WHEELHOST_ABI_VERSION);
        EXPECT_NE(table_.host_identity, 0u);
        EXPECT_NE(table_.host_context, nullptr);
        EXPECT_TRUE(table_.capability_bits & DMK_WHEELHOST_CAP_VERTICAL);
        EXPECT_TRUE(table_.capability_bits & DMK_WHEELHOST_CAP_HORIZONTAL);
        EXPECT_TRUE(table_.capability_bits & DMK_WHEELHOST_CAP_CONSUME);
        EXPECT_NE(table_.open_lease, nullptr);
        EXPECT_NE(table_.publish_capture, nullptr);
        EXPECT_NE(table_.drain_counts, nullptr);
        EXPECT_NE(table_.close_lease, nullptr);
    }

    TEST_F(WheelHostProof, DoubleStartIsRefused)
    {
        DmkWheelHostTable second{};
        EXPECT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                     static_cast<std::uint32_t>(sizeof(second)), &second),
                  DMK_WHEELHOST_ERR_STATE);
    }

    TEST_F(WheelHostProof, StartRejectsBadArguments)
    {
        // Already started, so a second start returns STATE; prove the argument guards on a fresh stop/argument path.
        DmkWheelHost_Stop();
        EXPECT_EQ(
            DmkWheelHost_Start(0u, DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(table_)), &table_),
            DMK_WHEELHOST_ERR_INVALID);
        EXPECT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                     static_cast<std::uint32_t>(sizeof(table_)), nullptr),
                  DMK_WHEELHOST_ERR_INVALID);
        // Restart so TearDown's Stop has a started host to tear down.
        ASSERT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                     static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, StartRejectsAnIncompatibleOrShortTable)
    {
        ASSERT_EQ(DmkWheelHost_Stop(), DMK_WHEELHOST_OK);
        EXPECT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION + 1u,
                                     static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_ERR_ABI);
        EXPECT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                     static_cast<std::uint32_t>(sizeof(table_) - 1u), &table_),
                  DMK_WHEELHOST_ERR_ABI);
        ASSERT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                     static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, SecondLeaseIsBusy)
    {
        const DmkWheelLease first = open();
        DmkWheelLease second = 0;
        EXPECT_EQ(table_.open_lease(table_.host_context, 0x3u, 0x4u, &second), DMK_WHEELHOST_ERR_BUSY);
        EXPECT_EQ(second, 0u);
        EXPECT_EQ(table_.close_lease(table_.host_context, first, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
        // After close a fresh lease succeeds.
        const DmkWheelLease third = open();
        EXPECT_NE(third, first);
    }

    TEST_F(WheelHostProof, CloseRequiresTheOpeningOwnerAndGeneration)
    {
        const DmkWheelLease lease = open();
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER + 1u, LEASE_GENERATION),
                  DMK_WHEELHOST_ERR_STALE);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION + 1u),
                  DMK_WHEELHOST_ERR_STALE);
        EXPECT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, VerticalAndHorizontalCountsFold)
    {
        const DmkWheelLease lease = open();
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
        const DmkWheelLease lease = open();
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
        const DmkWheelLease lease = open();
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

    TEST_F(WheelHostProof, CallbackFromAClosedLeaseCannotWriteIntoItsSuccessor)
    {
        const DmkWheelLease first = open();
        ASSERT_EQ(table_.publish_capture(table_.host_context, first, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u),
                  DMK_WHEELHOST_OK);
        g_hook_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_hook_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ASSERT_NE(g_hook_entered, nullptr);
        ASSERT_NE(g_hook_release, nullptr);
        DmkWheelHost_TestSetHookProbe(&park_hook_probe);

        pump_->post_wheel(false, 120);
        const DWORD entered = WaitForSingleObject(g_hook_entered, 10000);
        DmkWheelLease second = 0;
        int32_t close_status = DMK_WHEELHOST_ERR_STATE;
        int32_t open_status = DMK_WHEELHOST_ERR_STATE;
        int32_t publish_status = DMK_WHEELHOST_ERR_STATE;
        if (entered == WAIT_OBJECT_0)
        {
            close_status = table_.close_lease(table_.host_context, first, LEASE_OWNER, LEASE_GENERATION);
            open_status = table_.open_lease(table_.host_context, LEASE_OWNER, LEASE_GENERATION, &second);
            if (open_status == DMK_WHEELHOST_OK)
            {
                publish_status = table_.publish_capture(table_.host_context, second, DMK_WHEEL_CAPTURE_ENABLED, 0u, 0u);
            }
        }

        SetEvent(g_hook_release);
        DmkWheelHost_TestSetHookProbe(nullptr);
        ASSERT_EQ(entered, WAIT_OBJECT_0);
        ASSERT_EQ(close_status, DMK_WHEELHOST_OK);
        ASSERT_EQ(open_status, DMK_WHEELHOST_OK);
        ASSERT_EQ(publish_status, DMK_WHEELHOST_OK);
        ASSERT_TRUE(pump_->quiesce());
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        ASSERT_EQ(table_.drain_counts(table_.host_context, second, counts), DMK_WHEELHOST_OK);
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
        const DmkWheelLease lease = open();
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
        const DmkWheelLease lease = open();
        ASSERT_EQ(table_.close_lease(table_.host_context, lease, LEASE_OWNER, LEASE_GENERATION), DMK_WHEELHOST_OK);
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        EXPECT_EQ(table_.drain_counts(table_.host_context, lease, counts), DMK_WHEELHOST_ERR_NO_LEASE);
        const DmkWheelLease fresh = open();
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
        DmkWheelLease lease = 0;
        EXPECT_EQ(table_.open_lease(&not_the_host, 0u, 0u, &lease), DMK_WHEELHOST_ERR_INVALID);
        const DmkWheelLease good = open();
        std::uint32_t counts[DMK_WHEEL_DIRECTIONS] = {0, 0, 0, 0};
        EXPECT_EQ(table_.drain_counts(&not_the_host, good, counts), DMK_WHEELHOST_ERR_INVALID);
        EXPECT_EQ(table_.open_lease(table_.host_context, 0u, 0u, nullptr), DMK_WHEELHOST_ERR_INVALID);
    }

    TEST_F(WheelHostProof, ConsumeSwallowsOwnedWheelButStillCounts)
    {
        const DmkWheelLease lease = open();
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
        const DmkWheelLease lease = open();
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
        EXPECT_EQ(DmkWheelHost_Stop(), DMK_WHEELHOST_OK);
        EXPECT_EQ(DmkWheelHost_Stop(), DMK_WHEELHOST_ERR_STATE);
        // Restart so TearDown finds a started host.
        ASSERT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                     static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_OK);
    }

    TEST_F(WheelHostProof, FailedUnhookBlocksASecondMount)
    {
        DmkWheelHost_TestForceUnhookFailure(1);
        EXPECT_EQ(DmkWheelHost_Stop(), DMK_WHEELHOST_ERR_THREAD);
        DmkWheelHostTable second{};
        EXPECT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                     static_cast<std::uint32_t>(sizeof(second)), &second),
                  DMK_WHEELHOST_ERR_STATE);

        DmkWheelHost_TestForceUnhookFailure(0);
        ASSERT_EQ(DmkWheelHost_Stop(), DMK_WHEELHOST_OK);
        ASSERT_EQ(DmkWheelHost_Start(pump_->tid(), DMK_WHEELHOST_ABI_VERSION,
                                     static_cast<std::uint32_t>(sizeof(table_)), &table_),
                  DMK_WHEELHOST_OK);
    }
} // namespace
