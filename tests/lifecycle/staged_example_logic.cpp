/**
 * @file staged_example_logic.cpp
 * @brief Exercises the checked-in logic with deterministic controller input and fresh-image tags.
 */

#include "internal/input_intercept.hpp"

// NOLINTNEXTLINE(bugprone-suspicious-include): Exercise the reference implementation.
#include "staged_example_logic_source.cpp"

#include <system_error>

namespace DetourModKit::detail
{
    extern void (*g_worker_join_fail_seam)();
} // namespace DetourModKit::detail

namespace
{
    const char s_proof_tag[] = "DMKEXAMPLEFRESHTAG:0000000000000000";
    std::uint64_t s_init_calls = 0;
    std::atomic<bool> s_callback_entered{false};
    std::atomic<bool> s_callback_release{false};
    std::atomic<bool> s_callback_exited{false};
    std::atomic<bool> s_callback_expired{false};
    std::atomic<bool> s_worker_entered{false};
    std::atomic<bool> s_worker_release{false};
    std::atomic<bool> s_worker_exited{false};
    std::atomic<bool> s_worker_expired{false};
    std::atomic<HANDLE> s_worker_thread{nullptr};
    std::atomic<int> s_worker_damage{0};
    std::uint64_t s_worker_join_failures = 0;
} // namespace

/** @brief Injects the owned provider before the actual sample Init. */
extern "C" __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL Init(const StagedReloadInitRequest *request) noexcept
{
    ++s_init_calls;
    dmk::detail::set_xinput_module_override_for_test(::GetModuleHandleW(L"dmk_xinput_proxy_local.dll"));
    dmk::input::Input::instance().set_require_focus(false);
    if (::GetEnvironmentVariableW(L"DMK_EXAMPLE_PROOF_FAIL_INIT", nullptr, 0) != 0)
    {
        WheelHostTable refused_host = *request->wheel_host;
        refused_host.open_lease = nullptr;
        StagedReloadInitRequest refused_request = *request;
        refused_request.wheel_host = &refused_host;
        return example_init(&refused_request);
    }
    return example_init(request);
}

/** @brief Exposes bytes that the proof rewrites in each build-output copy. */
extern "C" __declspec(dllexport) const char *DMK_WHEELHOST_CALL Revision() noexcept
{
    return s_proof_tag + sizeof("DMKEXAMPLEFRESHTAG:") - 1;
}

/** @brief Reports generation state and callback-rundown observations. */
extern "C" __declspec(dllexport) void DMK_WHEELHOST_CALL example_proof_snapshot(std::uint64_t *out) noexcept
{
    out[0] = s_init_calls;
    out[1] = s_combo_presses.load(std::memory_order_relaxed);
    out[2] = s_session.has_value() ? 1 : 0;
    out[3] = dmk::diagnostics::module_pin_count(dmk::diagnostics::ModulePinReason::XInputKeepalive);
    out[4] = dmk::diagnostics::total_module_pins();
    out[5] = dmk::diagnostics::module_pin_count(dmk::diagnostics::ModulePinReason::Hook);
    out[6] = dmk::diagnostics::module_pin_count(dmk::diagnostics::ModulePinReason::Worker);
    out[7] = s_heartbeat.has_value() ? 1 : 0;
    out[8] = s_hook_calls.load(std::memory_order_relaxed);
    out[9] = s_callback_entered.load(std::memory_order_acquire) ? 1 : 0;
    out[10] = s_callback_exited.load(std::memory_order_acquire) ? 1 : 0;
    out[11] = s_callback_expired.load(std::memory_order_acquire) ? 1 : 0;
    out[12] = s_original.load(std::memory_order_acquire) != nullptr ? 1 : 0;
    out[13] = s_hooks.size();
    out[14] = s_worker_entered.load(std::memory_order_acquire) ? 1 : 0;
    out[15] = s_worker_exited.load(std::memory_order_acquire) ? 1 : 0;
    out[16] = s_worker_expired.load(std::memory_order_acquire) ? 1 : 0;
    out[17] = s_worker_join_failures;
    out[18] = static_cast<std::uint64_t>(s_worker_damage.load(std::memory_order_acquire));
}

/** @brief Releases the worker and waits for its native thread, which includes runtime cleanup. */
extern "C" __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL example_proof_release_worker() noexcept
{
    dmk::detail::g_worker_join_fail_seam = nullptr;
    s_worker_release.store(true, std::memory_order_release);
    const HANDLE thread = s_worker_thread.load(std::memory_order_acquire);
    if (thread == nullptr)
    {
        s_heartbeat.reset();
        return 0;
    }
    if (::WaitForSingleObject(thread, 5000) != WAIT_OBJECT_0)
        return 0;
    ::CloseHandle(thread);
    s_worker_thread.store(nullptr, std::memory_order_release);
    s_heartbeat.reset();
    return s_worker_exited.load(std::memory_order_acquire) && !s_worker_expired.load(std::memory_order_acquire) ? 1 : 0;
}

/** @brief Parks the only hook caller and injects one join failure into its next shutdown. */
extern "C" __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL example_proof_park_worker() noexcept
{
    try
    {
        s_heartbeat.reset();
        s_heartbeat.emplace(
            "proof.parked_worker",
            [](const std::stop_token &) noexcept -> void
            {
                HANDLE thread = nullptr;
                if (::DuplicateHandle(
                        ::GetCurrentProcess(),
                        ::GetCurrentThread(),
                        ::GetCurrentProcess(),
                        &thread,
                        SYNCHRONIZE,
                        FALSE,
                        0
                    ) == 0)
                {
                    s_worker_exited.store(true, std::memory_order_release);
                    return;
                }
                s_worker_thread.store(thread, std::memory_order_release);
                s_worker_entered.store(true, std::memory_order_release);
                const ULONGLONG deadline = ::GetTickCount64() + 10'000;
                while (!s_worker_release.load(std::memory_order_acquire))
                {
                    if (::GetTickCount64() >= deadline)
                    {
                        s_worker_expired.store(true, std::memory_order_release);
                        break;
                    }
                    ::Sleep(1);
                }
                s_worker_damage.store(demo_apply_damage(100, 10), std::memory_order_release);
                s_worker_exited.store(true, std::memory_order_release);
            }
        );
        const ULONGLONG deadline = ::GetTickCount64() + 5000;
        while (!s_worker_entered.load(std::memory_order_acquire))
        {
            if (s_worker_exited.load(std::memory_order_acquire) || ::GetTickCount64() >= deadline)
                return 0;
            ::Sleep(1);
        }
        dmk::detail::g_worker_join_fail_seam = []() -> void
        {
            dmk::detail::g_worker_join_fail_seam = nullptr;
            ++s_worker_join_failures;
            throw std::system_error(std::make_error_code(std::errc::no_such_process));
        };
        return 1;
    }
    catch (...)
    {
        s_worker_release.store(true, std::memory_order_release);
        return 0;
    }
}

/** @brief Runs the reference rollback against the parked worker. */
extern "C" __declspec(dllexport) void DMK_WHEELHOST_CALL example_proof_roll_back_worker() noexcept
{
    roll_back_generation();
}

/** @brief Registers a callback that the host releases after one refused drain. */
extern "C" __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL example_proof_park_callback() noexcept
{
    if (!s_session.has_value())
        return 0;
    try
    {
        auto guard = dmk::config::press_combo(
            "Proof",
            "ParkCallback",
            "Park callback",
            "proof.park_callback",
            []() noexcept -> void
            {
                s_callback_entered.store(true, std::memory_order_release);
                const ULONGLONG deadline = ::GetTickCount64() + 10'000;
                while (!s_callback_release.load(std::memory_order_acquire))
                {
                    if (::GetTickCount64() >= deadline)
                    {
                        s_callback_expired.store(true, std::memory_order_release);
                        break;
                    }
                    ::Sleep(1);
                }
                s_callback_exited.store(true, std::memory_order_release);
            },
            "Gamepad_DpadDown",
            false
        );
        if (guard.name().empty())
            return 0;
        s_session->scope().add(std::move(guard));
        return 1;
    }
    catch (...)
    {
        return 0;
    }
}

/** @brief Lets the parked callback return before the host retries Shutdown. */
extern "C" __declspec(dllexport) void DMK_WHEELHOST_CALL example_proof_release_callback() noexcept
{
    s_callback_release.store(true, std::memory_order_release);
}

/** @brief Records a leak without a module pin or latches an unsafe hook verdict. */
extern "C" __declspec(dllexport) void DMK_WHEELHOST_CALL example_proof_fault(std::uint32_t mode) noexcept
{
    if (mode == 1)
    {
        dmk::diagnostics::record_intentional_leak(dmk::diagnostics::LeakSubsystem::Input);
    }
    else
    {
        s_hook_restore_failed = true;
    }
}
