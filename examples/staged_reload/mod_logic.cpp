/**
 * @file mod_logic.cpp
 * @brief Reference logic DLL for the staged-generation reload pattern.
 */

#include <DetourModKit.hpp>

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string_view>
#include <thread>
#include <utility>

namespace
{
    using namespace std::chrono_literals;

    using ApplyDamageFn = int (*)(int, int) noexcept;

    /// The build supplies DMK_EXAMPLE_MOD_NAME. One name derives the log, the INI, and every binding name.
    constexpr std::string_view MOD_NAME = DMK_EXAMPLE_MOD_NAME;

    /// Adds this bonus while the config toggle is on.
    constexpr int DAMAGE_BONUS = 25;

    constexpr auto HEARTBEAT_INTERVAL = 1s;
    constexpr auto HEARTBEAT_POLL = 100ms;

    std::optional<dmk::Session> s_session;
    dmk::hook::HookStack s_hooks;
    std::optional<dmk::StoppableWorker> s_heartbeat;
    std::atomic<ApplyDamageFn> s_original{nullptr};
    std::atomic<std::uint64_t> s_hook_calls{0};
    std::atomic<std::uint64_t> s_combo_presses{0};
    std::atomic<bool> s_bonus_enabled{true};
    // Latches the first failed hook restore. A retry must never convert retained patched bytes into an unload
    // acceptance.
    bool s_hook_restore_failed = false;

    /**
     * @brief Stands in for a game function that a real mod resolves with a scan ladder.
     * @details The sample hooks its own function so the example compiles without a game. The README code example
     *          shows the scan-ladder install that a real mod uses.
     */
    __declspec(noinline) int demo_apply_damage(int amount, int resist) noexcept
    {
        return amount - resist;
    }

    int apply_damage_detour(int amount, int resist) noexcept
    {
        s_hook_calls.fetch_add(1, std::memory_order_relaxed);
        const ApplyDamageFn original = s_original.load(std::memory_order_acquire);
        if (original == nullptr)
        {
            return amount - resist;
        }
        const int bonus = s_bonus_enabled.load(std::memory_order_relaxed) ? DAMAGE_BONUS : 0;
        return original(amount + bonus, resist);
    }

    /**
     * @brief Clears hooks and latches any restoration failure.
     * @return true only when every hook target returns to its original bytes.
     */
    [[nodiscard]] bool clear_generation_hooks() noexcept
    {
        namespace diag = dmk::diagnostics;
        const std::size_t hook_pins_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);
        s_hooks.clear();
        s_hook_restore_failed =
            s_hook_restore_failed || diag::intentional_leak_count(diag::LeakSubsystem::HookManager) != hook_pins_before;
        if (!s_hook_restore_failed)
        {
            s_original.store(nullptr, std::memory_order_release);
        }
        return !s_hook_restore_failed;
    }

    /// Drops each reclaimable generation resource after a failed Init step.
    void roll_back_generation() noexcept
    {
        s_heartbeat.reset();
        (void)clear_generation_hooks();
        s_session.reset();
    }
} // namespace

extern "C"
{
    /**
     * @brief Reports this build, so the loader can log which bytes it loaded (guide step 6).
     * @details The stamp moves only when this translation unit recompiles. A real mod exports its own build
     *          revision constant.
     */
    __declspec(dllexport) const char *Revision() noexcept
    {
        return __DATE__ " " __TIME__;
    }

    /**
     * @brief Starts one generation: session, config bind, hook, combo binding, heartbeat worker, and input polling.
     * @return true when the generation is live. A failed step releases each reclaimable resource and returns false.
     * @note The loader calls this from its control thread, off the loader lock.
     */
    __declspec(dllexport) bool Init() noexcept
    {
        if (s_session.has_value() || s_hook_restore_failed)
        {
            return false;
        }
        try
        {
            // LogOpenMode::Append preserves the prior generation's teardown records, retention warnings included.
            auto started = dmk::Session::start(dmk::ModInfo{.name = MOD_NAME,
                                                            .log_file = std::format("{}.log", MOD_NAME),
                                                            .log_open_mode = dmk::LogOpenMode::Append});
            if (!started)
            {
                return false;
            }
            s_session.emplace(std::move(*started));

            // config::bind_* replaces the item in place, so re-registration from each Init() is the supported path.
            dmk::config::bind_bool(
                "Damage", "EnableBonus", "Enable Damage Bonus",
                [](bool value) -> void { s_bonus_enabled.store(value, std::memory_order_relaxed); }, true);
            s_session->ini().load(std::format("{}.ini", MOD_NAME));

            auto installed = dmk::hook::inline_at(
                dmk::hook::InlineRequest{.name = "demo_apply_damage",
                                         .target = dmk::Address{reinterpret_cast<std::uintptr_t>(&demo_apply_damage)}},
                &apply_damage_detour);
            if (!installed)
            {
                roll_back_generation();
                return false;
            }
            dmk::hook::Hook &held = s_hooks.push(std::move(*installed));
            // Publish the original BEFORE enable(), so nothing can enter the detour unchained.
            s_original.store(held.original<ApplyDamageFn>(), std::memory_order_release);
            if (!held.enable())
            {
                roll_back_generation();
                return false;
            }

            // The wheel combo takes the permanent WndprocKeepalive pin that the Shutdown verdict accepts. The
            // digital consume gamepad combo installs the XInput interception (analog codes cannot be masked, so
            // they never install it). Under a rival writer such as the Steam overlay, the first generation cannot
            // prove its restore, keeps its XInput hook pair as a forwarding link, and stays mapped. The Shutdown
            // verdict accepts exactly that retained set, so reload stays repeatable.
            auto combo = dmk::input::register_combo(dmk::input::ComboBinding{
                .name = std::format("{}.demo_combo", MOD_NAME),
                .trigger = dmk::input::Trigger::Press,
                .combos = {{.keys = {dmk::mouse_wheel(dmk::WheelCode::Up)}, .modifiers = {}},
                           {.keys = {dmk::gamepad_button(dmk::GamepadCode::B)}, .modifiers = {}}},
                .consume = true,
                .on_press = []() noexcept -> void { s_combo_presses.fetch_add(1, std::memory_order_relaxed); }});
            if (!combo)
            {
                roll_back_generation();
                return false;
            }
            s_session->scope().add(std::move(*combo));

            // This worker is the sample target's only caller. Its destruction joins before hook teardown.
            s_heartbeat.emplace(std::format("{}.heartbeat", MOD_NAME),
                                [](std::stop_token token) -> void
                                {
                                    auto next_report = std::chrono::steady_clock::now() + HEARTBEAT_INTERVAL;
                                    while (!token.stop_requested())
                                    {
                                        std::this_thread::sleep_for(HEARTBEAT_POLL);
                                        if (std::chrono::steady_clock::now() < next_report)
                                        {
                                            continue;
                                        }
                                        next_report += HEARTBEAT_INTERVAL;
                                        const int damage = demo_apply_damage(100, 10);
                                        (void)dmk::log().try_log(
                                            dmk::LogLevel::Debug,
                                            "The heartbeat reports {} damage, {} hook calls, and {} combo presses.",
                                            damage, s_hook_calls.load(std::memory_order_relaxed),
                                            s_combo_presses.load(std::memory_order_relaxed));
                                    }
                                });

            if (!s_session->input().start(dmk::input::Input::Settings{}))
            {
                roll_back_generation();
                return false;
            }
            return true;
        }
        catch (...)
        {
            roll_back_generation();
            return false;
        }
    }

    /**
     * @brief Runs the guide's Shutdown sequence and its refusal boundary.
     * @return true only when unload is safe: callbacks drained, prologues restored, and only inert pins remain.
     * @note The loader must keep the DLL mapped after a false return and retry later (guide step 2).
     */
    __declspec(dllexport) bool Shutdown() noexcept
    {
        namespace diag = dmk::diagnostics;

        if (!s_session.has_value())
        {
            return false;
        }
        s_heartbeat.reset(); // This request stops and joins outside the loader lock.
        // Revert every raw memory::patch_code or write_bytes change here, before the drain. This sample makes none.
        if (dmk::prepare_logic_dll_unload_all() != dmk::LogicDllUnloadStatus::SafeToUnload)
        {
            return false;
        }
        (void)clear_generation_hooks(); // The stack clears newest-first while the code pages stay mapped.
        s_session.reset();              // Ordered teardown can retain XInput here.

        // The guide accepts only the wheel keepalive and an inert XInput set. Read the pins after ~Session.
        const std::size_t wheel = diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive);
        const std::size_t xinput_self = diag::module_pin_count(diag::ModulePinReason::XInputKeepalive);
        const std::size_t xinput_targets = diag::module_pin_count(diag::ModulePinReason::XInputTarget);
        const bool xinput_inert = (xinput_self == 0 && xinput_targets == 0) ||
                                  (xinput_self == 1 && xinput_targets >= 1 && xinput_targets <= 2);
        const bool only_inert_pins =
            wheel <= 1 && xinput_inert && diag::total_module_pins() == wheel + xinput_self + xinput_targets;
        return !s_hook_restore_failed && only_inert_pins;
    }
} // extern "C"

/// The loader drives Init and Shutdown explicitly, so attach and detach have no work.
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) noexcept
{
    return TRUE;
}
