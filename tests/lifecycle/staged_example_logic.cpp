/**
 * @file staged_example_logic.cpp
 * @brief Exercises the checked-in logic with deterministic controller input and fresh-image tags.
 */

#include "internal/input_intercept.hpp"

// NOLINTNEXTLINE(bugprone-suspicious-include): Exercise the reference implementation.
#include "staged_example_logic_source.cpp"

namespace
{
    const char s_proof_tag[] = "DMKEXAMPLEFRESHTAG:0000000000000000";
    std::uint64_t s_init_calls = 0;
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

/** @brief Reports Init calls, press callbacks, session state, and XInput pins in this image. */
extern "C" __declspec(dllexport) void DMK_WHEELHOST_CALL example_proof_snapshot(std::uint64_t *out) noexcept
{
    out[0] = s_init_calls;
    out[1] = s_combo_presses.load(std::memory_order_relaxed);
    out[2] = s_session.has_value() ? 1 : 0;
    out[3] = dmk::diagnostics::module_pin_count(dmk::diagnostics::ModulePinReason::XInputKeepalive);
    out[4] = dmk::diagnostics::total_module_pins();
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
