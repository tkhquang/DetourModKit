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

    std::atomic<DWORD> s_detour_park_thread_id{0};
    std::atomic<bool> s_detour_park_entered{false};
    std::atomic<bool> s_detour_park_release{false};
    HANDLE s_detour_park_thread = nullptr;
    ApplyDamageFn s_detour_park_original = nullptr;

    std::uint64_t s_shutdown_calls = 0;
    std::uint32_t s_first_shutdown_result = 0;
    std::uint32_t s_last_shutdown_result = 0;
    std::uint64_t s_busy_probe_damage = 0;
    std::uint64_t s_busy_left_generation_live = 0;

    /// Holds the parked thread inside the counted detour and forwards every other call.
    int parked_original(int amount, int resist) noexcept
    {
        if (::GetCurrentThreadId() == s_detour_park_thread_id.load(std::memory_order_acquire))
        {
            s_detour_park_entered.store(true, std::memory_order_release);
            const ULONGLONG deadline = ::GetTickCount64() + 10'000;
            while (!s_detour_park_release.load(std::memory_order_acquire) && ::GetTickCount64() < deadline)
                ::Sleep(1);
        }
        return s_detour_park_original(amount, resist);
    }

    DWORD WINAPI detour_park_body(void *) noexcept
    {
        s_detour_park_thread_id.store(::GetCurrentThreadId(), std::memory_order_release);
        (void)demo_apply_damage(100, 10);
        return 0;
    }

    /// Releases the parked call, waits for its thread to exit, and restores the sample original.
    [[nodiscard]] bool release_detour_park() noexcept
    {
        s_detour_park_release.store(true, std::memory_order_release);
        if (s_detour_park_thread == nullptr)
            return true;
        if (::WaitForSingleObject(s_detour_park_thread, 5000) != WAIT_OBJECT_0)
            return false;
        ::CloseHandle(s_detour_park_thread);
        s_detour_park_thread = nullptr;
        s_original.store(s_detour_park_original, std::memory_order_release);
        return true;
    }
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
    out[19] = s_shutdown_calls;
    out[20] = s_first_shutdown_result;
    out[21] = s_last_shutdown_result;
    out[22] = s_busy_probe_damage;
    out[23] = s_busy_left_generation_live;
}

/** @brief Records each sample Shutdown result. The first BUSY probes the armed hook, then releases the parked call. */
extern "C" __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL Shutdown() noexcept
{
    const std::uint32_t result = example_shutdown();
    if (s_shutdown_calls++ == 0)
        s_first_shutdown_result = result;
    s_last_shutdown_result = result;
    if (result == DMK_STAGED_RELOAD_BUSY && s_detour_park_thread != nullptr)
    {
        s_busy_left_generation_live = s_session.has_value() && s_heartbeat.has_value() && s_hooks.size() == 1 ? 1 : 0;
        s_busy_probe_damage = static_cast<std::uint64_t>(demo_apply_damage(100, 10));
        if (!release_detour_park())
            s_busy_left_generation_live = 0;
    }
    return result;
}

/** @brief Parks one call inside the counted detour until the next BUSY Shutdown releases it. */
extern "C" __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL example_proof_park_detour() noexcept
{
    const ApplyDamageFn original = s_original.load(std::memory_order_acquire);
    if (original == nullptr || s_detour_park_thread != nullptr)
        return 0;
    s_detour_park_original = original;
    s_original.store(&parked_original, std::memory_order_release);
    s_detour_park_thread = ::CreateThread(nullptr, 0, &detour_park_body, nullptr, 0, nullptr);
    if (s_detour_park_thread == nullptr)
    {
        s_original.store(original, std::memory_order_release);
        return 0;
    }
    const ULONGLONG deadline = ::GetTickCount64() + 5000;
    while (!s_detour_park_entered.load(std::memory_order_acquire))
    {
        if (::GetTickCount64() >= deadline)
        {
            (void)release_detour_park();
            return 0;
        }
        ::Sleep(1);
    }
    return 1;
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

/** @brief Records a leak without a module pin, or the HookManager leak of a detour that stays reachable. */
extern "C" __declspec(dllexport) void DMK_WHEELHOST_CALL example_proof_fault(std::uint32_t mode) noexcept
{
    dmk::diagnostics::record_intentional_leak(
        mode == 1 ? dmk::diagnostics::LeakSubsystem::Input : dmk::diagnostics::LeakSubsystem::HookManager
    );
}
