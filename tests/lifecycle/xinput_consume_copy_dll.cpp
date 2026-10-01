#include "DetourModKit/input.hpp"
#include "internal/input_intercept.hpp"

#include <windows.h>
#include <Xinput.h>

#include <atomic>
#include <chrono>
#include <optional>
#include <utility>
#include <vector>

namespace
{
    std::optional<DetourModKit::input::BindingGuard> s_guard;
    std::atomic<bool> s_held{false};
    std::atomic<DWORD> s_edges{0};
    bool s_rules_only{false};
} // namespace

/** @brief Starts one independently linked poller with an overlapping consumed chord. */
extern "C" BOOL WINAPI dmk_xinput_copy_start(HMODULE module, DWORD trigger) noexcept
{
    if (module == nullptr ||
        (trigger != XINPUT_GAMEPAD_DPAD_UP && trigger != XINPUT_GAMEPAD_A && trigger != XINPUT_GAMEPAD_LEFT_SHOULDER))
        return FALSE;
    try
    {
        DetourModKit::detail::set_xinput_module_override_for_test(module);
        auto &input = DetourModKit::input::Input::instance();
        auto registered = input.register_combo({
            .name = "copy_consume",
            .trigger = DetourModKit::input::Trigger::Hold,
            .combos = {{
                .keys = {DetourModKit::gamepad_button(static_cast<int>(trigger))},
                .modifiers = trigger == XINPUT_GAMEPAD_LEFT_SHOULDER
                                 ? std::vector<DetourModKit::InputCode>{}
                                 : std::vector{DetourModKit::gamepad_button(XINPUT_GAMEPAD_LEFT_SHOULDER)},
            }},
            .consume = true,
            .on_state_change = [](bool held) -> void
            {
                s_held.store(held, std::memory_order_release);
                s_edges.fetch_add(1, std::memory_order_release);
            },
        });
        if (!registered)
            return FALSE;
        s_guard.emplace(std::move(*registered));
        const auto started = input.start({
            .poll_interval = std::chrono::milliseconds{2},
            .require_focus = false,
        });
        if (started)
            return TRUE;
        input.shutdown();
        s_guard.reset();
        return FALSE;
    }
    catch (...)
    {
        return FALSE;
    }
}

/** @brief Reports both the raw chord state and its delivered hold edge. */
extern "C" BOOL WINAPI dmk_xinput_copy_active() noexcept
{
    return DetourModKit::input::Input::instance().is_active("copy_consume") && s_held.load(std::memory_order_acquire)
               ? TRUE
               : FALSE;
}

/** @brief Reports the paired suppression gate of this independent copy. */
extern "C" BOOL WINAPI dmk_xinput_copy_installed() noexcept
{
    return DetourModKit::detail::xinput_installed() ? TRUE : FALSE;
}

/** @brief Reports the retained provider references after this copy stops. */
extern "C" DWORD WINAPI dmk_xinput_copy_module_refs() noexcept
{
    return static_cast<DWORD>(DetourModKit::detail::xinput_module_refs_held());
}

/** @brief Separates exact patch evidence from scoped route observations. */
extern "C" DWORD WINAPI dmk_xinput_copy_evidence() noexcept
{
    const auto exact = DetourModKit::detail::xinput_pair_coverage_for_test();
    const auto observed = DetourModKit::detail::xinput_pair_observation_for_test();
    return (exact.primary ? 1u : 0u) | (exact.ex ? 2u : 0u) | (observed.primary ? 4u : 0u) | (observed.ex ? 8u : 0u);
}

/** @brief Reports fresh poller deliveries after all copies enter the chain. */
extern "C" DWORD WINAPI dmk_xinput_copy_edges() noexcept
{
    return s_edges.load(std::memory_order_acquire);
}

/** @brief Publishes one same-frame rule with a zero reactive mask and no poller. */
extern "C" BOOL WINAPI dmk_xinput_copy_start_rules(HMODULE module, DWORD mode) noexcept
{
    using namespace DetourModKit::detail;
    if (module == nullptr || mode > 2)
        return FALSE;
    set_xinput_module_override_for_test(module);
    if (!install_xinput(0))
        return FALSE;
    const GamepadConsumeRule rule{
        .modifier_mask = static_cast<WORD>(mode == 1 ? XINPUT_GAMEPAD_LEFT_SHOULDER : 0),
        .forbidden_mask = 0,
        .trigger_mask = static_cast<WORD>(
            mode == 0 ? XINPUT_GAMEPAD_LEFT_SHOULDER : (mode == 1 ? XINPUT_GAMEPAD_A : XINPUT_GAMEPAD_DPAD_UP)
        ),
    };
    s_rules_only = true;
    if (publish_gamepad_consume_rules(&rule, 1, STANDALONE_INTERCEPT_OWNER).authorized &&
        set_gamepad_rule_suppress_enabled(true, STANDALONE_INTERCEPT_OWNER) &&
        publish_gamepad_suppress(0, STANDALONE_INTERCEPT_OWNER))
        return TRUE;
    uninstall();
    s_rules_only = false;
    return FALSE;
}

/** @brief Rechecks the route and refreshes only the zero-mask rule deadline. */
extern "C" BOOL WINAPI dmk_xinput_copy_refresh_rules() noexcept
{
    using namespace DetourModKit::detail;
    return s_rules_only && install_xinput(0) && publish_gamepad_suppress(0, STANDALONE_INTERCEPT_OWNER) ? TRUE : FALSE;
}

/** @brief Stops the poller and releases its registration outside the loader lock. */
extern "C" void WINAPI dmk_xinput_copy_stop() noexcept
{
    if (s_rules_only)
    {
        DetourModKit::detail::uninstall();
        s_rules_only = false;
    }
    else
    {
        DetourModKit::input::Input::instance().shutdown();
    }
    s_guard.reset();
    DetourModKit::detail::set_xinput_module_override_for_test(nullptr);
}
