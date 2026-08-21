/**
 * @file staged_generation_dll.cpp
 * @brief Defines one reloadable test generation with its own DetourModKit archive.
 * @details The fixture runs the guide's Init and Shutdown sequence. The host controls each test seam before poll start.
 */

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/session.hpp"

#include "internal/input_intercept.hpp"
#include "internal/input_poller.hpp"

#include "staged_generation_protocol.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>

#include <windows.h>

namespace
{
    using namespace std::chrono_literals;

    /// Identifies an unassigned virtual key that cannot collide with real hardware.
    constexpr int PROBE_VK = VK_F24;

    /// Adds a distinct value to each chained result.
    constexpr int DETOUR_BONUS = 1000;

    constexpr int HOOK_PROBE_BASE = 17;
    constexpr int HOOK_PROBE_MODIFIER = 5;

    /// Identifies detour execution without a trampoline because no valid input produces this result.
    constexpr int UNCHAINED_RESULT = -0x5EED;

    constexpr auto READY_TIMEOUT = 10s;
    constexpr auto PARK_WAIT_LIMIT = 30s;

    using TargetFn = int (*)(int, int);

    // The host rewrites this tag in every staged copy. The exported accessor keeps the array live. Its contents prove
    // that the loaded image uses the staged file rather than a stale pinned predecessor.
    const char s_generation_tag[] = "DMKSTAGEDGENTAG:0000000000000000";
    static_assert(sizeof(s_generation_tag) == sizeof(staged_gen::TAG_MARKER) + staged_gen::TAG_LENGTH);

    std::optional<DetourModKit::Session> s_session;
    DetourModKit::hook::HookStack s_hooks;
    HMODULE s_target_lib = nullptr;
    HMODULE s_xinput_proxy = nullptr;
    std::uint32_t s_drain_timeout_ms = 5000;
    bool s_external_wheel = false;
    // A teardown delta permanently refuses another Init or unload verdict for this mapped generation.
    bool s_hook_teardown_refused = false;

    std::atomic<TargetFn> s_original{nullptr};
    std::atomic<std::uint64_t> s_hook_calls{0};
    std::atomic<std::uint64_t> s_init_calls{0};
    std::atomic<bool> s_probe_down{false};
    std::atomic<bool> s_park_armed{false};
    std::atomic<bool> s_park_entered{false};
    std::atomic<bool> s_park_release{false};

    int compute_damage_detour(int base, int modifier)
    {
        s_hook_calls.fetch_add(1, std::memory_order_relaxed);
        const TargetFn original = s_original.load(std::memory_order_acquire);
        return original != nullptr ? original(base, modifier) + DETOUR_BONUS : UNCHAINED_RESULT;
    }

    /**
     * @brief Drops hook handles and checks the HookManager leak delta.
     * @return true if this generation has no HookManager
     *         retention.
     */
    [[nodiscard]] bool clear_generation_hooks() noexcept
    {
        namespace diag = DetourModKit::diagnostics;
        const std::size_t hook_leaks_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);
        s_hooks.clear();
        if (diag::intentional_leak_count(diag::LeakSubsystem::HookManager) != hook_leaks_before)
        {
            s_hook_teardown_refused = true;
        }
        if (!s_hook_teardown_refused)
        {
            s_original.store(nullptr, std::memory_order_release);
        }
        return !s_hook_teardown_refused;
    }

    /// Rolls back reclaimable state while a retained hook preserves its trampoline and target-module reference.
    void roll_back_generation() noexcept
    {
        const bool prologues_restored = clear_generation_hooks();
        s_session.reset();
        DetourModKit::detail::g_input_key_state_probe = nullptr;
        DetourModKit::detail::set_wndproc_window_override_for_test(nullptr);
        DetourModKit::detail::set_xinput_module_override_for_test(nullptr);
        s_external_wheel = false;
        if (s_xinput_proxy != nullptr)
        {
            ::FreeLibrary(s_xinput_proxy);
            s_xinput_proxy = nullptr;
        }
        if (prologues_restored && s_target_lib != nullptr)
        {
            ::FreeLibrary(s_target_lib);
            s_target_lib = nullptr;
        }
    }

    [[nodiscard]] bool wait_for_interception(bool wheel, bool gamepad) noexcept
    {
        const auto deadline = std::chrono::steady_clock::now() + READY_TIMEOUT;
        while (std::chrono::steady_clock::now() < deadline)
        {
            const bool wheel_ready = !wheel || DetourModKit::detail::wndproc_installed();
            const bool gamepad_ready = !gamepad || DetourModKit::detail::xinput_installed();
            if (wheel_ready && gamepad_ready)
            {
                return true;
            }
            ::Sleep(1);
        }
        return false;
    }
} // namespace

extern "C"
{
    /// Provides the address anchor named by @ref staged_gen::MARKER_SYMBOL for the host's unmap oracle.
    __declspec(dllexport) extern const unsigned char dmk_staged_marker[4] = {0xD5, 0x7A, 0x6E, 0x01};

    /// Implements @ref staged_gen::TagFn.
    __declspec(dllexport) const char *dmk_staged_tag() noexcept
    {
        return s_generation_tag + sizeof(staged_gen::TAG_MARKER) - 1;
    }

    /// Implements @ref staged_gen::StatusFn.
    __declspec(dllexport) void dmk_staged_status(staged_gen::Status *out) noexcept
    {
        namespace diag = DetourModKit::diagnostics;
        if (out == nullptr)
        {
            return;
        }
        out->wndproc_installed = DetourModKit::detail::wndproc_installed() ? 1 : 0;
        out->xinput_installed = DetourModKit::detail::xinput_installed() ? 1 : 0;
        out->wheel_pins = diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive);
        out->message_hook_pins = diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive);
        out->xinput_self_pins = diag::module_pin_count(diag::ModulePinReason::XInputKeepalive);
        out->xinput_target_pins = diag::module_pin_count(diag::ModulePinReason::XInputTarget);
        out->hook_manager_leaks = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);
        out->input_leaks = diag::intentional_leak_count(diag::LeakSubsystem::Input);
        out->total_intentional_leaks = diag::total_intentional_leaks();
        out->total_module_pins = diag::total_module_pins();
        out->hook_calls = s_hook_calls.load(std::memory_order_relaxed);
        out->init_calls = s_init_calls.load(std::memory_order_relaxed);
    }

    /// Implements @ref staged_gen::ArmParkFn.
    __declspec(dllexport) void dmk_staged_arm_park() noexcept
    {
        s_park_entered.store(false, std::memory_order_release);
        s_park_release.store(false, std::memory_order_release);
        s_park_armed.store(true, std::memory_order_release);
        s_probe_down.store(true, std::memory_order_release);
    }

    /// Implements @ref staged_gen::ReleaseParkFn.
    __declspec(dllexport) void dmk_staged_release_park() noexcept
    {
        s_probe_down.store(false, std::memory_order_release);
        s_park_armed.store(false, std::memory_order_release);
        s_park_release.store(true, std::memory_order_release);
    }

    /// Implements @ref staged_gen::WaitParkedFn.
    __declspec(dllexport) int dmk_staged_wait_parked(std::uint32_t budget_ms) noexcept
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{budget_ms};
        while (!s_park_entered.load(std::memory_order_acquire))
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return 0;
            }
            ::Sleep(1);
        }
        return 1;
    }

    /// Implements @ref staged_gen::InitFn.
    __declspec(dllexport) int dmk_staged_init(const staged_gen::InitOptions *options) noexcept
    {
        using namespace DetourModKit;

        s_init_calls.fetch_add(1, std::memory_order_relaxed);
        if (options == nullptr || s_session.has_value() || s_target_lib != nullptr || s_hook_teardown_refused)
        {
            return 0;
        }
        try
        {
            s_drain_timeout_ms = options->drain_timeout_ms;
            s_external_wheel = options->wheel_host != nullptr;

            Result<Session> started = Session::start(ModInfo{
                .name = "STAGED_GEN", .log_file = options->log_file != nullptr ? options->log_file : "staged_gen.log"});
            if (!started)
            {
                return 0;
            }
            s_session.emplace(std::move(*started));

            s_target_lib = ::LoadLibraryA(staged_gen::HOOK_TARGET_MODULE_NAME);
            const auto target = reinterpret_cast<TargetFn>(
                s_target_lib != nullptr
                    ? reinterpret_cast<void *>(::GetProcAddress(s_target_lib, staged_gen::HOOK_TARGET_SYMBOL))
                    : nullptr);
            if (target == nullptr)
            {
                roll_back_generation();
                return 0;
            }
            Result<hook::Hook> installed =
                hook::inline_at(hook::InlineRequest{.name = "staged_gen_hook",
                                                    .target = Address{reinterpret_cast<std::uintptr_t>(target)}},
                                &compute_damage_detour);
            if (!installed)
            {
                roll_back_generation();
                return 0;
            }
            hook::Hook &held = s_hooks.push(std::move(*installed));
            s_original.store(held.original<TargetFn>(), std::memory_order_release);
            if (!held.enable())
            {
                roll_back_generation();
                return 0;
            }
            const int hook_probe = target(HOOK_PROBE_BASE, HOOK_PROBE_MODIFIER);
            if (hook_probe != HOOK_PROBE_BASE + HOOK_PROBE_MODIFIER + DETOUR_BONUS)
            {
                roll_back_generation();
                return 0;
            }
            if (options->fail_stage == static_cast<int>(staged_gen::FailStage::AfterHook))
            {
                roll_back_generation();
                return 0;
            }

            if (options->enable_probe_binding != 0)
            {
                Result<input::BindingGuard> probe = input::register_combo(
                    input::ComboBinding{.name = "staged.probe",
                                        .trigger = input::Trigger::Press,
                                        .combos = {{.keys = {keyboard_key(PROBE_VK)}, .modifiers = {}}},
                                        .on_press = []() noexcept
                                        {
                                            if (!s_park_armed.load(std::memory_order_acquire))
                                            {
                                                return;
                                            }
                                            s_park_entered.store(true, std::memory_order_release);
                                            const auto deadline = std::chrono::steady_clock::now() + PARK_WAIT_LIMIT;
                                            while (!s_park_release.load(std::memory_order_acquire) &&
                                                   std::chrono::steady_clock::now() < deadline)
                                            {
                                                ::Sleep(1);
                                            }
                                        }});
                if (!probe)
                {
                    roll_back_generation();
                    return 0;
                }
                s_session->scope().add(std::move(*probe));
            }
            if (options->enable_wheel != 0)
            {
                Result<input::BindingGuard> wheel = input::register_combo(
                    input::ComboBinding{.name = "staged.wheel",
                                        .trigger = input::Trigger::Press,
                                        .combos = {{.keys = {mouse_wheel(WheelCode::Up)}, .modifiers = {}}},
                                        .consume = true,
                                        .on_press = []() noexcept {}});
                if (!wheel)
                {
                    roll_back_generation();
                    return 0;
                }
                s_session->scope().add(std::move(*wheel));
            }
            if (options->enable_consume_gamepad != 0)
            {
                Result<input::BindingGuard> chord = input::register_combo(
                    input::ComboBinding{.name = "staged.chord",
                                        .trigger = input::Trigger::Press,
                                        .combos = {{.keys = {gamepad_button(GamepadCode::DpadUp)},
                                                    .modifiers = {gamepad_button(GamepadCode::LeftBumper)}}},
                                        .consume = true,
                                        .on_press = []() noexcept {}});
                if (!chord)
                {
                    roll_back_generation();
                    return 0;
                }
                s_session->scope().add(std::move(*chord));
            }

            if (options->enable_probe_binding != 0)
            {
                detail::g_input_key_state_probe = [](int vk) noexcept
                { return vk == PROBE_VK && s_probe_down.load(std::memory_order_acquire); };
            }
            if (options->enable_wheel != 0 && !s_external_wheel)
            {
                detail::set_wndproc_window_override_for_test(options->wheel_window);
            }
            if (options->enable_consume_gamepad != 0)
            {
                s_xinput_proxy = ::LoadLibraryA(staged_gen::XINPUT_PROXY_MODULE_NAME);
                if (s_xinput_proxy == nullptr)
                {
                    roll_back_generation();
                    return 0;
                }
                detail::set_xinput_module_override_for_test(s_xinput_proxy);
            }

            input::Input::Settings input_settings{.poll_interval = 2ms, .require_focus = false};
            if (s_external_wheel)
            {
                input_settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
                input_settings.wheel_host = options->wheel_host;
                input_settings.wheel_host_required = true;
            }
            Result<void> polling = input::Input::instance().start(input_settings);
            if (!polling)
            {
                roll_back_generation();
                return 0;
            }
            if (!wait_for_interception(options->enable_wheel != 0 && !s_external_wheel,
                                       options->enable_consume_gamepad != 0))
            {
                roll_back_generation();
                return 0;
            }
            return 1;
        }
        catch (...)
        {
            roll_back_generation();
            return 0;
        }
    }

    /// Implements @ref staged_gen::ShutdownFn.
    __declspec(dllexport) int dmk_staged_shutdown() noexcept
    {
        using namespace DetourModKit;
        namespace diag = diagnostics;

        if (!s_session.has_value())
        {
            return 0;
        }
        // A refusal tells the loader to keep the DLL mapped. The callback drain stays closed until a retry completes.
        const bool drained = prepare_logic_dll_unload_all(std::chrono::milliseconds{s_drain_timeout_ms}) ==
                             LogicDllUnloadStatus::SafeToUnload;
        if (!drained)
        {
            return 0;
        }

        const bool prologues_restored = clear_generation_hooks();
        const bool external_wheel = s_external_wheel;
        s_session.reset();

        detail::g_input_key_state_probe = nullptr;
        detail::set_wndproc_window_override_for_test(nullptr);
        detail::set_xinput_module_override_for_test(nullptr);
        if (s_xinput_proxy != nullptr)
        {
            ::FreeLibrary(s_xinput_proxy);
            s_xinput_proxy = nullptr;
        }
        if (prologues_restored && s_target_lib != nullptr)
        {
            ::FreeLibrary(s_target_lib);
            s_target_lib = nullptr;
        }

        // Read the guide's refusal boundary after ~Session so XInput retention is visible.
        const std::size_t wheel = diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive);
        const std::size_t message_hook = diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive);
        const std::size_t xinput_self = diag::module_pin_count(diag::ModulePinReason::XInputKeepalive);
        const std::size_t xinput_targets = diag::module_pin_count(diag::ModulePinReason::XInputTarget);
        const std::size_t input_leaks = diag::intentional_leak_count(diag::LeakSubsystem::Input);
        const std::size_t total_leaks = diag::total_intentional_leaks();
        const bool xinput_inert = (xinput_self == 0 && xinput_targets == 0) ||
                                  (xinput_self == 1 && xinput_targets >= 1 && xinput_targets <= 2);
        const bool local_backend_safe = wheel <= 1 && message_hook == 0 && xinput_inert &&
                                        diag::total_module_pins() == wheel + xinput_self + xinput_targets;
        const bool external_backend_safe = wheel == 0 && message_hook == 0 && xinput_self == 0 && xinput_targets == 0 &&
                                           input_leaks == 0 && total_leaks == 0 && diag::total_module_pins() == 0;
        s_external_wheel = false;
        return (prologues_restored && (external_wheel ? external_backend_safe : local_backend_safe)) ? 1 : 0;
    }
} // extern "C"

// One drift gate per export, so a signature change fails here instead of at a GetProcAddress call site.
static_assert(std::is_same_v<decltype(&dmk_staged_init), staged_gen::InitFn>);
static_assert(std::is_same_v<decltype(&dmk_staged_shutdown), staged_gen::ShutdownFn>);
static_assert(std::is_same_v<decltype(&dmk_staged_tag), staged_gen::TagFn>);
static_assert(std::is_same_v<decltype(&dmk_staged_status), staged_gen::StatusFn>);
static_assert(std::is_same_v<decltype(&dmk_staged_arm_park), staged_gen::ArmParkFn>);
static_assert(std::is_same_v<decltype(&dmk_staged_release_park), staged_gen::ReleaseParkFn>);
static_assert(std::is_same_v<decltype(&dmk_staged_wait_parked), staged_gen::WaitParkedFn>);

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
