/**
 * @file staged_generation_dll.cpp
 * @brief Defines one reloadable test generation with its own DetourModKit archive.
 * @details The fixture runs the guide's Init and Shutdown sequence. The host controls each test seam before poll start.
 *          It hooks the external hook target with a raw inline, a counted inline, or a mid hook. It also exercises
 *          in-image mid hooks, an input binding, a subscribed dispatcher, and both diagnostics dispatchers, and omits
 *          VMT hooks.
 */

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/session.hpp"

#include "internal/input_intercept.hpp"
#include "internal/input_poller.hpp"

#include "fixtures/proof_section.hpp"
#include "staged_generation_protocol.hpp"

#include <safetyhook/inline_hook.hpp>
#include <safetyhook/os.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

#include <windows.h>

namespace DetourModKit::detail
{
    /// Withholds the position claim from the installs of this image's copy. src/internal/hook_backend.hpp declares it.
    extern std::atomic<bool> g_hook_position_claims_refused_for_test;
} // namespace DetourModKit::detail

namespace
{
    using namespace std::chrono_literals;

    /// Identifies an unassigned virtual key that cannot collide with real hardware.
    constexpr int PROBE_VK = VK_F24;

    /// Names the hook on the target export when InitOptions::hook_name is null.
    constexpr const char *DEFAULT_HOOK_NAME = "staged_gen_hook";

    /// Bounds the hooks of one generation: the target hook and six mid hooks.
    constexpr std::size_t HOOK_CAPACITY = 7;

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
    // Owns the generation's hooks in install order. A slot keeps its address, so a held pointer survives a later
    // install. Static destruction also runs newest first, because an array destroys its last element first.
    std::array<std::optional<DetourModKit::hook::Hook>, HOOK_CAPACITY> s_held_hooks;
    std::size_t s_held_hook_count = 0;
    /// Owns the generation's hooks in install order in the Retire mode, in place of s_held_hooks.
    DetourModKit::hook::HookStack s_hook_stack;
    int s_teardown_mode = 0;
    std::atomic<int> s_detour_park{0};
    std::atomic<std::uint64_t> s_retire_calls{0};
    std::atomic<std::uint64_t> s_self_retire_calls{0};
    DetourModKit::hook::HookRetirement s_last_retirement{};
    std::atomic<int> s_detour_bonus{0};
    HMODULE s_target_lib = nullptr;
    HMODULE s_xinput_proxy = nullptr;
    std::uint32_t s_drain_timeout_ms = 5000;
    bool s_external_wheel = false;
    // A teardown delta permanently refuses another Init or unload verdict for this mapped generation.
    bool s_hook_teardown_refused = false;

    std::atomic<TargetFn> s_original{nullptr};
    std::atomic<std::uint64_t> s_hook_calls{0};
    std::atomic<std::uint64_t> s_init_calls{0};
    std::atomic<std::uint64_t> s_mid_calls{0};
    bool s_retain_mid = false;
    std::atomic<int> s_parked_result{0};

    // Namespace scope, so the image's static destruction deregisters the dispatcher's emit-chain TLS ownership.
    DetourModKit::EventDispatcher<int> s_dispatcher;
    DetourModKit::Subscription s_subscription;
    std::atomic<std::uint64_t> s_dispatched{0};

    DetourModKit::Subscription s_lifecycle_subscription;
    DetourModKit::Subscription s_fault_subscription;
    std::atomic<std::uint64_t> s_lifecycle_events{0};
    bool s_retain_diagnostics = false;

    template <int Value> DMK_PROOF_TARGET int mid_target() noexcept
    {
        volatile int value = Value;
        return value + value + value;
    }

    using MidTarget = int (*)() noexcept;

    void mid_callback(DetourModKit::hook::MidContext &) noexcept
    {
        s_mid_calls.fetch_add(1, std::memory_order_relaxed);
    }

    /**
     * @brief Pushes @p hook onto s_hook_stack in the Retire mode, or moves it into the next free slot of s_held_hooks.
     * @return Null when the slot array already holds HOOK_CAPACITY hooks. The hook is then destroyed.
     * @throws std::bad_alloc If the stack push fails. The stack then destroys the hook.
     */
    [[nodiscard]] DetourModKit::hook::Hook *hold_hook(DetourModKit::hook::Hook hook)
    {
        if (s_teardown_mode == static_cast<int>(staged_gen::TeardownMode::Retire))
            return &s_hook_stack.push(std::move(hook));
        if (s_held_hook_count == HOOK_CAPACITY)
            return nullptr;
        DetourModKit::hook::Hook &held = s_held_hooks[s_held_hook_count].emplace(std::move(hook));
        ++s_held_hook_count;
        return &held;
    }

    bool install_mid_hooks()
    {
        constexpr std::array<MidTarget, 6> targets{
            &mid_target<1>,
            &mid_target<2>,
            &mid_target<3>,
            &mid_target<4>,
            &mid_target<5>,
            &mid_target<6>,
        };
        for (std::size_t i = 0; i < targets.size(); ++i)
        {
            auto installed = DetourModKit::hook::mid_at(
                {
                    .name = "staged_gen_mid",
                    .target = DetourModKit::Address{reinterpret_cast<std::uintptr_t>(targets[i])},
                },
                &mid_callback
            );
            DetourModKit::hook::Hook *const held = installed ? hold_hook(std::move(*installed)) : nullptr;
            if (held == nullptr || !held->enable())
                return false;
            MidTarget volatile target = targets[i];
            if (target() != static_cast<int>(3 * (i + 1)) || s_mid_calls.load() != i + 1)
                return false;
        }
        return true;
    }

    /**
     * @brief Parks one caller before the entry count of the first mid route.
     * @details The entry count does not cover that caller, so only the idle proof can retain the route.
     * @return False after the park did not engage. No caller then remains.
     */
    [[nodiscard]] bool park_mid_caller(std::thread &caller) noexcept
    {
        safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::AT_ENTRY);
        try
        {
            caller = std::thread(
                []() noexcept
                {
                    MidTarget volatile target = &mid_target<1>;
                    s_parked_result.store(target(), std::memory_order_release);
                }
            );
        }
        catch (...)
        {
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
            return false;
        }
        const auto deadline = std::chrono::steady_clock::now() + READY_TIMEOUT;
        while (!safetyhook::route_park_reached_for_test())
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
                caller.join();
                return false;
            }
            ::Sleep(1);
        }
        return true;
    }

    std::atomic<bool> s_probe_down{false};
    std::atomic<bool> s_park_armed{false};
    std::atomic<bool> s_park_entered{false};
    std::atomic<bool> s_park_release{false};

    /// Reports the park as entered, then waits for ReleaseParkFn or PARK_WAIT_LIMIT.
    void hold_park() noexcept
    {
        s_park_entered.store(true, std::memory_order_release);
        const auto deadline = std::chrono::steady_clock::now() + PARK_WAIT_LIMIT;
        while (!s_park_release.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
        {
            ::Sleep(1);
        }
    }

    /// Runs HookStack::retire on s_hook_stack with the drain deadline and records the result for StatusFn.
    [[nodiscard]] DetourModKit::hook::HookRetirement retire_generation_stack() noexcept
    {
        const DetourModKit::hook::HookRetirement retirement =
            s_hook_stack.retire(std::chrono::milliseconds{s_drain_timeout_ms});
        s_last_retirement = retirement;
        s_retire_calls.fetch_add(1, std::memory_order_relaxed);
        return retirement;
    }

    int compute_damage_detour(int base, int modifier)
    {
        s_hook_calls.fetch_add(1, std::memory_order_relaxed);
        const TargetFn original = s_original.load(std::memory_order_acquire);
        return original != nullptr ? original(base, modifier) + s_detour_bonus.load(std::memory_order_relaxed)
                                   : UNCHAINED_RESULT;
    }

    /// Takes the armed InitOptions::detour_park action on one call, then chains as compute_damage_detour does.
    int compute_damage_counted_detour(int base, int modifier) noexcept
    {
        s_hook_calls.fetch_add(1, std::memory_order_relaxed);
        const int park = s_detour_park.load(std::memory_order_relaxed);
        if (park != static_cast<int>(staged_gen::DetourPark::None) &&
            s_park_armed.exchange(false, std::memory_order_acq_rel))
        {
            if (park == static_cast<int>(staged_gen::DetourPark::SelfRetire))
            {
                s_self_retire_calls.fetch_add(1, std::memory_order_relaxed);
                (void)retire_generation_stack();
            }
            else
            {
                hold_park();
            }
        }
        const TargetFn original = s_original.load(std::memory_order_acquire);
        return original != nullptr ? original(base, modifier) + s_detour_bonus.load(std::memory_order_relaxed)
                                   : UNCHAINED_RESULT;
    }

    void compute_damage_mid_callback(DetourModKit::hook::MidContext &context) noexcept
    {
        s_hook_calls.fetch_add(1, std::memory_order_relaxed);
        // The target returns base + modifier, so a bonus in the modifier register reaches the call result. The 32-bit
        // sum zero-extends, as a 32-bit register write does.
        std::uintptr_t &modifier = DetourModKit::hook::gpr(context, DetourModKit::hook::Gpr::Rdx);
        modifier = static_cast<std::uint32_t>(
            static_cast<std::uint32_t>(modifier) +
            static_cast<std::uint32_t>(s_detour_bonus.load(std::memory_order_relaxed))
        );
    }

    /// Creates the disabled @ref staged_gen::HookKind @p kind hook named @p name on @p address.
    [[nodiscard]] DetourModKit::Result<DetourModKit::hook::Hook>
    create_target_hook(int kind, const std::string &name, DetourModKit::Address address)
    {
        using namespace DetourModKit;
        if (kind == static_cast<int>(staged_gen::HookKind::Mid))
            return hook::mid_at(hook::MidRequest{.name = name, .target = address}, &compute_damage_mid_callback);
        if (kind == static_cast<int>(staged_gen::HookKind::Counted))
            return hook::inline_at<&compute_damage_counted_detour>(
                hook::InlineRequest{.name = name, .target = address}
            );
        return hook::inline_at(hook::InlineRequest{.name = name, .target = address}, &compute_damage_detour);
    }

    /**
     * @brief Installs the InitOptions::hook_kind hook on @p target, then arms it.
     * @return False after a create or arm failure. A created hook stays held for the rollback.
     */
    [[nodiscard]] bool install_target_hook(const staged_gen::InitOptions &options, TargetFn target)
    {
        using namespace DetourModKit;
        const Address address{reinterpret_cast<std::uintptr_t>(target)};
        const std::string name = options.hook_name != nullptr ? options.hook_name : DEFAULT_HOOK_NAME;
        const bool mid = options.hook_kind == static_cast<int>(staged_gen::HookKind::Mid);
        if (options.far_hook != 0)
        {
            safetyhook::force_ff_hook_for_test(true);
        }
        Result<hook::Hook> installed = create_target_hook(options.hook_kind, name, address);
        // A claim runs no backend setup, so the one-shot request can survive it. Later installs stay near.
        safetyhook::force_ff_hook_for_test(false);
        hook::Hook *const held = installed ? hold_hook(std::move(*installed)) : nullptr;
        if (held == nullptr)
        {
            return false;
        }
        if (!mid)
        {
            s_original.store(held->original<TargetFn>(), std::memory_order_release);
        }
        return held->enable().has_value();
    }

    /// Disables every held hook, newest first, and stops at the first refusal.
    [[nodiscard]] bool disable_generation_hooks_newest_first() noexcept
    {
        for (std::size_t index = s_held_hook_count; index > 0; --index)
        {
            if (!s_held_hooks[index - 1]->disable())
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief Destroys the held hooks newest first and checks the HookManager leak delta.
     * @details A HookResidue retirement leaves no detour reachable and releases its module reference, so it does not
     *          refuse.
     * @return true if this generation has no HookManager retention.
     */
    [[nodiscard]] bool clear_generation_hooks() noexcept
    {
        namespace diag = DetourModKit::diagnostics;
        const std::size_t hook_leaks_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);
        for (; s_held_hook_count > 0; --s_held_hook_count)
        {
            s_held_hooks[s_held_hook_count - 1].reset();
        }
        s_hook_stack.clear();
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

    /// Returns the refusal of StagedShutdown: DMK_STAGED_RELOAD_RESTART_REQUIRED after a Retire-mode pin, otherwise 0.
    [[nodiscard]] int shutdown_refusal() noexcept
    {
        const bool retire_mode = s_teardown_mode == static_cast<int>(staged_gen::TeardownMode::Retire);
        return retire_mode && s_hook_teardown_refused ? static_cast<int>(DMK_STAGED_RELOAD_RESTART_REQUIRED) : 0;
    }

    /// Rolls back reclaimable state while a retained hook preserves its trampoline and target-module reference.
    void roll_back_generation() noexcept
    {
        const bool hooks_released = clear_generation_hooks();
        s_subscription.reset();
        s_lifecycle_subscription.reset();
        s_fault_subscription.reset();
        s_session.reset();
        DetourModKit::detail::g_input_key_state_probe = nullptr;
        DetourModKit::detail::set_xinput_module_override_for_test(nullptr);
        s_external_wheel = false;
        if (s_xinput_proxy != nullptr)
        {
            ::FreeLibrary(s_xinput_proxy);
            s_xinput_proxy = nullptr;
        }
        if (hooks_released && s_target_lib != nullptr)
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
            const bool wheel_ready = !wheel || DetourModKit::detail::message_hook_installed();
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
        out->wheel_hook_installed = DetourModKit::detail::message_hook_installed() ? 1 : 0;
        out->xinput_installed = DetourModKit::detail::xinput_installed() ? 1 : 0;
        out->message_hook_pins = diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive);
        out->xinput_self_pins = diag::module_pin_count(diag::ModulePinReason::XInputKeepalive);
        out->xinput_target_pins = diag::module_pin_count(diag::ModulePinReason::XInputTarget);
        out->hook_manager_leaks = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);
        out->input_leaks = diag::intentional_leak_count(diag::LeakSubsystem::Input);
        out->total_intentional_leaks = diag::total_intentional_leaks();
        out->total_module_pins = diag::total_module_pins();
        out->hook_calls = s_hook_calls.load(std::memory_order_relaxed);
        out->mid_calls = s_mid_calls.load(std::memory_order_relaxed);
        const auto coordinator = safetyhook::process_coordinator_snapshot_for_test();
        out->coordinator_identity = coordinator.identity;
        out->coordinator_bytes = coordinator.bytes;
        out->coordinator_live = coordinator.live;
        out->coordinator_retained = coordinator.retained;
        out->parked_result = s_parked_result.load(std::memory_order_acquire);
        out->init_calls = s_init_calls.load(std::memory_order_relaxed);
        out->dispatched = s_dispatched.load(std::memory_order_relaxed);
        out->lifecycle_events = s_lifecycle_events.load(std::memory_order_relaxed);
        out->diagnostics_leaks = diag::intentional_leak_count(diag::LeakSubsystem::Diagnostics);
        out->hook_residue_leaks = diag::intentional_leak_count(diag::LeakSubsystem::HookResidue);
        out->hook_module_pins = diag::module_pin_count(diag::ModulePinReason::Hook);
        out->coordinator_vacant = coordinator.vacant;
        out->retire_calls = s_retire_calls.load(std::memory_order_relaxed);
        out->retire_outcome = static_cast<int>(s_last_retirement.outcome);
        out->retire_refusal = static_cast<int>(s_last_retirement.refusal);
        out->retire_restored = s_last_retirement.restored;
        out->retire_vacated = s_last_retirement.vacated;
        out->retire_pinned = s_last_retirement.pinned;
        out->retire_in_flight = s_last_retirement.in_flight;
        out->self_retire_calls = s_self_retire_calls.load(std::memory_order_relaxed);
        out->held_hooks = s_held_hook_count + s_hook_stack.size();
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
            s_teardown_mode = options->teardown_mode;
            s_detour_park.store(options->detour_park, std::memory_order_relaxed);
            s_detour_bonus.store(options->detour_bonus, std::memory_order_relaxed);
            detail::g_hook_position_claims_refused_for_test.store(
                options->refuse_position_claims != 0,
                std::memory_order_release
            );

            Result<Session> started = Session::start(
                ModInfo{
                    .name = "STAGED_GEN",
                    .log_file = options->log_file != nullptr ? options->log_file : "staged_gen.log",
                }
            );
            if (!started)
            {
                return 0;
            }
            s_session.emplace(std::move(*started));
            s_retain_diagnostics = options->enable_diagnostics != 0 && options->retain_diagnostics != 0;
            if (options->enable_diagnostics != 0)
            {
                s_lifecycle_subscription = diagnostics::hook_lifecycle().subscribe(
                    [](const diagnostics::HookLifecycleEvent &) noexcept
                    { s_lifecycle_events.fetch_add(1, std::memory_order_relaxed); }
                );
                s_fault_subscription =
                    diagnostics::scanner_faults().subscribe([](const diagnostics::ScannerFaultEvent &) noexcept {});
                if (!s_lifecycle_subscription.active() || !s_fault_subscription.active())
                {
                    roll_back_generation();
                    return 0;
                }
            }

            s_target_lib = ::LoadLibraryA(staged_gen::HOOK_TARGET_MODULE_NAME);
            const char *const symbol =
                options->target_symbol != nullptr ? options->target_symbol : staged_gen::HOOK_TARGET_SYMBOL;
            TargetFn volatile target = reinterpret_cast<TargetFn>(
                s_target_lib != nullptr ? reinterpret_cast<void *>(::GetProcAddress(s_target_lib, symbol)) : nullptr
            );
            if (target == nullptr)
            {
                roll_back_generation();
                return 0;
            }
            // The baseline crosses every layer already on the target, so a family can arm over another family.
            const int baseline = target(HOOK_PROBE_BASE, HOOK_PROBE_MODIFIER);
            const std::uint64_t calls_before_arm = s_hook_calls.load(std::memory_order_relaxed);
            if (!install_target_hook(*options, target))
            {
                roll_back_generation();
                return 0;
            }
            const int hook_probe = target(HOOK_PROBE_BASE, HOOK_PROBE_MODIFIER);
            if (hook_probe != baseline + options->detour_bonus ||
                s_hook_calls.load(std::memory_order_relaxed) == calls_before_arm)
            {
                roll_back_generation();
                return 0;
            }
            if (options->fail_stage == static_cast<int>(staged_gen::FailStage::AfterHook))
            {
                roll_back_generation();
                return 0;
            }

            if (options->enable_mid != 0 && !install_mid_hooks())
            {
                roll_back_generation();
                return 0;
            }
            s_retain_mid = options->enable_mid != 0 && options->retain_mid != 0;
            if (options->enable_dispatcher != 0)
            {
                s_subscription = s_dispatcher.subscribe(
                    [](const int &value) noexcept
                    { s_dispatched.fetch_add(static_cast<std::uint64_t>(value), std::memory_order_relaxed); }
                );
                s_dispatcher.emit_safe(1);
                if (!s_subscription.active() || s_dispatched.load(std::memory_order_relaxed) != 1)
                {
                    roll_back_generation();
                    return 0;
                }
            }
            if (options->enable_probe_binding != 0)
            {
                Result<input::BindingGuard> probe = input::register_combo(
                    input::ComboBinding{
                        .name = "staged.probe",
                        .trigger = input::Trigger::Press,
                        .combos = {{.keys = {keyboard_key(PROBE_VK)}, .modifiers = {}}},
                        .on_press = []() noexcept
                        {
                            if (s_park_armed.load(std::memory_order_acquire))
                            {
                                hold_park();
                            }
                        },
                    }
                );
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
                    input::ComboBinding{
                        .name = "staged.wheel",
                        .trigger = input::Trigger::Press,
                        .combos = {{.keys = {mouse_wheel(WheelCode::Up)}, .modifiers = {}}},
                        .consume = true,
                        .on_press = []() noexcept {},
                    }
                );
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
                    input::ComboBinding{
                        .name = "staged.chord",
                        .trigger = input::Trigger::Press,
                        .combos =
                            {
                                {
                                    .keys = {gamepad_button(GamepadCode::DpadUp)},
                                    .modifiers = {gamepad_button(GamepadCode::LeftBumper)},
                                },
                            },
                        .consume = true,
                        .on_press = []() noexcept {},
                    }
                );
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

            input::Input::Settings input_settings{
                .poll_interval = 2ms,
                .require_focus = false,
            };
            if (s_external_wheel)
            {
                input_settings.wheel_backend = input::Input::WheelBackend::ExternalHost;
                input_settings.wheel_host = options->wheel_host;
                input_settings.wheel_host_required = true;
            }
            else if (options->enable_wheel != 0)
            {
                // The local MessageHook backend mounts on the given window's UI thread, or the init thread when the
                // host supplied no window. The thread only has to stay alive for the mount; this proof reads install
                // and pin state, not delivered wheel input.
                const DWORD wheel_thread = options->wheel_window != nullptr
                                               ? ::GetWindowThreadProcessId(options->wheel_window, nullptr)
                                               : ::GetCurrentThreadId();
                input_settings.wheel_target_thread_id = static_cast<std::uint32_t>(wheel_thread);
            }
            Result<void> polling = input::Input::instance().start(input_settings);
            if (!polling)
            {
                roll_back_generation();
                return 0;
            }
            if (!wait_for_interception(
                    options->enable_wheel != 0 && !s_external_wheel,
                    options->enable_consume_gamepad != 0
                ))
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
        const bool retire_mode = s_teardown_mode == static_cast<int>(staged_gen::TeardownMode::Retire);
        if (retire_mode)
        {
            // The stack retires before the session drain, so Busy and Refused keep every hook and the Session.
            const hook::HookRetirement retirement = retire_generation_stack();
            if (retirement.outcome == hook::RetirementOutcome::Busy)
            {
                return static_cast<int>(DMK_STAGED_RELOAD_BUSY);
            }
            if (retirement.outcome == hook::RetirementOutcome::Refused)
            {
                return static_cast<int>(DMK_STAGED_RELOAD_REFUSED);
            }
            if (retirement.pinned != 0)
            {
                s_hook_teardown_refused = true;
            }
        }
        // A refusal tells the loader to keep the DLL mapped. The callback drain stays closed until a retry completes.
        const bool drained = prepare_logic_dll_unload_all(std::chrono::milliseconds{s_drain_timeout_ms}) ==
                             LogicDllUnloadStatus::SafeToUnload;
        if (!drained)
        {
            return shutdown_refusal();
        }
        // The disable-first consumer latches a refused disable and destroys nothing, so the loader keeps it mapped.
        if (s_teardown_mode == static_cast<int>(staged_gen::TeardownMode::DisableFirst) &&
            !disable_generation_hooks_newest_first())
        {
            return 0;
        }

        std::thread parked_caller;
        if (s_retain_mid && !retire_mode && !park_mid_caller(parked_caller))
        {
            return 0;
        }
        const bool hooks_released = clear_generation_hooks();
        if (parked_caller.joinable())
        {
            // The closed route sends the released caller through its bypass to the restored target.
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
            parked_caller.join();
        }
        const bool external_wheel = s_external_wheel;
        s_subscription.reset();
        // Dropped after the hooks clear, so the subscription observes each removal.
        if (!s_retain_diagnostics)
        {
            s_lifecycle_subscription.reset();
        }
        s_fault_subscription.reset();
        s_session.reset();

        detail::g_input_key_state_probe = nullptr;
        detail::set_xinput_module_override_for_test(nullptr);
        if (s_xinput_proxy != nullptr)
        {
            ::FreeLibrary(s_xinput_proxy);
            s_xinput_proxy = nullptr;
        }
        if (hooks_released && s_target_lib != nullptr)
        {
            ::FreeLibrary(s_target_lib);
            s_target_lib = nullptr;
        }

        // Read the guide's refusal boundary after ~Session so XInput retention is visible. The reserved WndProc
        // reason never counts, and the local wheel pin is MessageHookKeepalive. A retired hook releases its Hook
        // reference, so both pin checks admit a HookResidue.
        const std::size_t wndproc = diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive);
        const std::size_t message_hook = diag::module_pin_count(diag::ModulePinReason::MessageHookKeepalive);
        const std::size_t xinput_self = diag::module_pin_count(diag::ModulePinReason::XInputKeepalive);
        const std::size_t xinput_targets = diag::module_pin_count(diag::ModulePinReason::XInputTarget);
        const std::size_t input_leaks = diag::intentional_leak_count(diag::LeakSubsystem::Input);
        // No caller reaches the detour of a HookResidue, so it does not block the unmap.
        const std::size_t blocking_leaks =
            diag::total_intentional_leaks() - diag::intentional_leak_count(diag::LeakSubsystem::HookResidue);
        const bool xinput_inert = (xinput_self == 0 && xinput_targets == 0) ||
                                  (xinput_self == 1 && xinput_targets >= 1 && xinput_targets <= 2);
        // A kept diagnostics index can belong to a handler that still runs in this image.
        const bool diagnostics_released = diag::intentional_leak_count(diag::LeakSubsystem::Diagnostics) == 0;
        // The local MessageHook backend retains at most one permanent keepalive. It never cleanly unloads; the
        // retained pin is the safety authority, and Shutdown still accepts the reload with it held.
        const bool local_backend_safe = wndproc == 0 && message_hook <= 1 && xinput_inert && diagnostics_released &&
                                        diag::total_module_pins() == message_hook + xinput_self + xinput_targets;
        const bool external_backend_safe = wndproc == 0 && message_hook == 0 && xinput_self == 0 &&
                                           xinput_targets == 0 && input_leaks == 0 && blocking_leaks == 0 &&
                                           diag::total_module_pins() == 0;
        s_external_wheel = false;
        return (hooks_released && (external_wheel ? external_backend_safe : local_backend_safe)) ? 1
                                                                                                 : shutdown_refusal();
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
