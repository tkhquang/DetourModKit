#ifndef DETOURMODKIT_TESTS_FIXTURES_INPUT_FIXTURE_HPP
#define DETOURMODKIT_TESTS_FIXTURES_INPUT_FIXTURE_HPP

/**
 * @file input_fixture.hpp
 * @brief GoogleTest fixtures, seam helpers, and wheel-host stubs that several input test files share.
 * @details The fixture classes live here, outside any anonymous namespace. docs/design/testing.md owns this rule.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/abi/wheel_host.h"
#include "internal/input_binding_lifecycle.hpp"
#include "internal/input_poller.hpp"
#include "internal/input_test_seams.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <thread>

namespace dmk_test::input_fixture
{
    namespace detail = DetourModKit::detail;
    namespace input = DetourModKit::input;

    class InputPollerTest : public ::testing::Test
    {
    };

    class InputTest : public ::testing::Test
    {
    protected:
        // shutdown() also clears a pending set_require_focus value. A case that sets it and then fails an ASSERT cannot
        // leak it into the next case of the single-process exe.
        void SetUp() override { input::Input::instance().shutdown(); }

        void TearDown() override { input::Input::instance().shutdown(); }
    };

    /** @brief Clears poll seams before a later case can create another poller. */
    struct InputSeamReset
    {
        InputSeamReset() = default;
        ~InputSeamReset()
        {
            detail::g_input_key_state_probe = nullptr;
            detail::g_input_post_stage_probe = nullptr;
            detail::g_input_pre_dispatch_probe = nullptr;
            detail::InputTestSeams::set_callback_admission_commit_seam_for_test(nullptr);
            detail::resolve_input_callback_drain();
            (void)detail::open_input_callback_admission();
        }
        InputSeamReset(const InputSeamReset &) = delete;
        InputSeamReset &operator=(const InputSeamReset &) = delete;
    };

    /** @brief Stops the facade before a key seam or callback capture leaves scope. */
    struct InputFacadeKeySeamCleanup
    {
        InputFacadeKeySeamCleanup() noexcept = default;
        ~InputFacadeKeySeamCleanup() noexcept
        {
            input::Input::instance().shutdown();
            detail::g_input_key_state_probe = nullptr;
        }
        InputFacadeKeySeamCleanup(const InputFacadeKeySeamCleanup &) = delete;
        InputFacadeKeySeamCleanup &operator=(const InputFacadeKeySeamCleanup &) = delete;
    };

    inline std::atomic<bool> s_callback_commit_parked{false};
    inline std::atomic<bool> s_release_callback_commit{false};

    /** @brief Parks callback admission until s_release_callback_commit reads true. */
    inline void park_callback_commit() noexcept
    {
        s_callback_commit_parked.store(true, std::memory_order_release);
        while (!s_release_callback_commit.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    // Permissive WheelHostTable entries that the external-host stub tables share.

    inline int32_t DMK_WHEELHOST_CALL
    wheel_host_stub_publish(void *, WheelHostLease, std::uint32_t, std::uint32_t, std::uint32_t) noexcept
    {
        return DMK_WHEELHOST_OK;
    }

    inline int32_t DMK_WHEELHOST_CALL wheel_host_stub_route_status(
        void *,
        WheelHostLease lease,
        std::uint32_t status_capacity,
        WheelHostRouteStatus *out_status
    ) noexcept
    {
        if (out_status == nullptr)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        if (status_capacity < sizeof(WheelHostRouteStatus))
        {
            return DMK_WHEELHOST_ERR_ABI;
        }
        *out_status = WheelHostRouteStatus{};
        out_status->struct_size = static_cast<std::uint32_t>(sizeof(WheelHostRouteStatus));
        out_status->route_state = DMK_WHEELHOST_ROUTE_READY;
        out_status->control_state = DMK_WHEELHOST_CONTROL_IDLE;
        out_status->capture_armable = lease != 0 ? 1u : 0u;
        out_status->mounted_thread_id = 0x1234u;
        out_status->mount_generation = 1;
        return DMK_WHEELHOST_OK;
    }

    inline int32_t DMK_WHEELHOST_CALL wheel_host_stub_retarget(void *, WheelHostLease, std::uint32_t) noexcept
    {
        return DMK_WHEELHOST_OK;
    }

} // namespace dmk_test::input_fixture

#endif // DETOURMODKIT_TESTS_FIXTURES_INPUT_FIXTURE_HPP
