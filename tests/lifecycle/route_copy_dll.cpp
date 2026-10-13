#if !defined(ROUTE_COPY_LEGACY_POLICY)
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"
#endif

#include "route_copy_protocol.hpp"

#include <safetyhook/inline_hook.hpp>
#include <safetyhook/os.hpp>

#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#if !defined(ROUTE_COPY_LEGACY_POLICY)
namespace DetourModKit::detail
{
    extern void (*g_logger_record_probe)(LogLevel, std::string_view) noexcept;
    [[nodiscard]] std::size_t last_claimed_mid_slot_for_test() noexcept;
    void adjust_mid_adapter_entries_for_test(std::size_t index, std::int32_t delta) noexcept;
} // namespace DetourModKit::detail
#endif

namespace
{
    using route_copy::Command;
    using TargetFn = int (*)();
    std::array<std::uint8_t, safetyhook::PROCESS_ROUTE_CAPACITY> s_keys{};

#if defined(ROUTE_COPY_LEGACY_POLICY)
    // The 4.3.0 policy over the patched backend. A toggle under a newer record refuses, and a teardown that cannot
    // restore as the top layer leaks the backend. No record turns retained. A create passes no position claim and
    // emits no relay cell, so this copy never takes or leaves a claimable position. Two layers let this copy sit
    // above and below another position on one target.
    constexpr std::size_t LEGACY_LAYER_COUNT = 2;
    std::array<std::optional<safetyhook::InlineHook>, LEGACY_LAYER_COUNT> s_layers{};
    std::array<std::atomic<TargetFn>, LEGACY_LAYER_COUNT> s_layer_original{};
    std::array<std::atomic<unsigned>, LEGACY_LAYER_COUNT> s_layer_hits{};
    std::size_t s_selected_layer{0};
    std::atomic<unsigned> s_pins{0};

    template <std::size_t Layer> int legacy_callback() noexcept
    {
        s_layer_hits[Layer].fetch_add(1);
        return s_layer_original[Layer].load(std::memory_order_acquire)();
    }

    constexpr std::array<int (*)() noexcept, LEGACY_LAYER_COUNT> LEGACY_DETOURS{
        &legacy_callback<0>,
        &legacy_callback<1>,
    };

    bool install_legacy_layer(void *target)
    {
        auto &layer = s_layers[s_selected_layer];
        if (layer)
            return false;
        safetyhook::omit_relay_cell_for_test(true);
        auto created = safetyhook::InlineHook::create(
            target,
            reinterpret_cast<void *>(LEGACY_DETOURS[s_selected_layer]),
            safetyhook::InlineHook::StartDisabled
        );
        if (!created)
            return false;
        layer.emplace(std::move(*created));
        s_layer_original[s_selected_layer].store(layer->original<TargetFn>(), std::memory_order_release);
        return layer->enable().has_value();
    }

    // The LayerConflict commands report only the coordinator refusal that the backend returns before any write.
    std::uintptr_t toggle_legacy_layer(Command command)
    {
        auto &layer = s_layers[s_selected_layer];
        if (!layer)
            return 0;
        const bool arm = command == Command::Enable || command == Command::EnableLayerConflict;
        const auto result = arm ? layer->enable() : layer->disable();
        if (command == Command::Enable || command == Command::Disable)
            return result.has_value();
        return !result && result.error().type == safetyhook::InlineHook::Error::LAYER_CONFLICT;
    }

    // Restores only as the top layer. Every other answer leaks the backend and keeps a reference of its own on the
    // image, which is the 4.3.0 HookManager pin. Returns the pin count.
    std::uintptr_t reset_legacy_layer()
    {
        auto &layer = s_layers[s_selected_layer];
        if (!layer)
            return s_pins.load();
        bool restored = !layer->enabled() || layer->disable().has_value();
        if (restored)
        {
            const safetyhook::ProcessCoordinator coordinator;
            restored = static_cast<bool>(coordinator) && coordinator.top(layer->trampoline().data(), true);
        }
        if (!restored)
        {
            (void)std::make_unique<safetyhook::InlineHook>(std::move(*layer)).release();
            HMODULE image{};
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&s_pins), &image))
                s_pins.fetch_add(1);
        }
        layer.reset();
        return s_pins.load();
    }

    std::uintptr_t policy_command(Command command, void *argument)
    {
        auto &layer = s_layers[s_selected_layer];
        switch (command)
        {
        case Command::InstallInline:
            return install_legacy_layer(argument);
        case Command::Reset:
            return reset_legacy_layer();
        case Command::Disable:
        case Command::Enable:
        case Command::EnableLayerConflict:
        case Command::DisableLayerConflict:
            return toggle_legacy_layer(command);
        case Command::Enabled:
            return layer && layer->enabled();
        case Command::Trampoline:
            return reinterpret_cast<std::uintptr_t>(s_layer_original[s_selected_layer].load());
        case Command::Hits:
            return s_layer_hits[s_selected_layer].load();
        case Command::ModulePins:
            return s_pins.load();
        case Command::SelectLayer:
        {
            const auto index = reinterpret_cast<std::uintptr_t>(argument);
            if (index >= LEGACY_LAYER_COUNT)
                return 0;
            s_selected_layer = index;
            return 1;
        }
        case Command::Top:
        {
            const safetyhook::ProcessCoordinator coordinator;
            return layer && coordinator && coordinator.top(layer->trampoline().data());
        }
        default:
            break;
        }
        return 0;
    }
#else
    std::optional<DetourModKit::hook::Hook> s_hook;
    std::size_t s_mid_slot{};
    std::atomic<TargetFn> s_original{nullptr};
    std::atomic<std::uintptr_t> s_trampoline{0};
    std::atomic<unsigned> s_hits{0};
    std::atomic<unsigned> s_warnings{0};
    std::atomic<unsigned> s_dependent_retentions{0};
    std::atomic<bool> s_self_reset{false};

    void observe_warning(DetourModKit::LogLevel level, std::string_view message) noexcept
    {
        if (level != DetourModKit::LogLevel::Warning)
            return;
        if (message.find("process coordinator unavailable or timed out") != std::string_view::npos)
            s_warnings.fetch_add(1);
        if (message.find("a dependent process route remains registered") != std::string_view::npos)
            s_dependent_retentions.fetch_add(1);
    }

    int inline_callback() noexcept
    {
        s_hits.fetch_add(1);
        return s_original.load(std::memory_order_acquire)();
    }

    void callback(DetourModKit::hook::MidContext &context) noexcept
    {
        s_trampoline.store(DetourModKit::hook::instruction_pointer(context));
        s_hits.fetch_add(1);
        // The unwaitable teardown leaks the backend without a reset.
        if (s_self_reset.exchange(false))
            s_hook.reset();
    }

    std::uintptr_t policy_command(Command command, void *argument)
    {
        namespace hook = DetourModKit::hook;
        namespace diagnostics = DetourModKit::diagnostics;
        switch (command)
        {
        case Command::Install:
        case Command::InstallInline:
        {
            DetourModKit::detail::g_logger_record_probe = &observe_warning;
            auto installed =
                command == Command::InstallInline
                    ? hook::inline_at(
                          {
                              .name = "route_copy_inline",
                              .target = DetourModKit::Address{reinterpret_cast<std::uintptr_t>(argument)},
                              .options = {.prologue = hook::Prologue::Relocate, .fail_if_already_hooked = false},
                          },
                          &inline_callback
                      )
                    : hook::mid_at(
                          {
                              .name = "route_copy",
                              .target = DetourModKit::Address{reinterpret_cast<std::uintptr_t>(argument)},
                              .options = {.prologue = hook::Prologue::Relocate, .fail_if_already_hooked = false},
                          },
                          &callback
                      );
            if (!installed)
                return 0;
            s_hook.emplace(std::move(*installed));
            if (command == Command::InstallInline)
            {
                const auto original = s_hook->original<TargetFn>();
                s_original.store(original, std::memory_order_release);
                s_trampoline.store(reinterpret_cast<std::uintptr_t>(original));
            }
            else
            {
                s_mid_slot = DetourModKit::detail::last_claimed_mid_slot_for_test();
            }
            return s_hook->enable().has_value();
        }
        case Command::Reset:
            s_hook.reset();
            DetourModKit::memory::shutdown_cache();
            return diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
        case Command::Disable:
            return s_hook && s_hook->disable().has_value();
        case Command::Enable:
            return s_hook && s_hook->enable().has_value();
        case Command::Enabled:
            return s_hook && s_hook->is_enabled();
        case Command::EnableLayerConflict:
        case Command::DisableLayerConflict:
        {
            if (!s_hook)
                return 0;
            const auto result = command == Command::EnableLayerConflict ? s_hook->enable() : s_hook->disable();
            return !result && result.error().code == DetourModKit::ErrorCode::LayerConflict;
        }
        case Command::Trampoline:
            return s_trampoline.load();
        case Command::Hits:
            return s_hits.load();
        case Command::Warnings:
            return s_warnings.load();
        case Command::DependentRetentions:
            return s_dependent_retentions.load();
        case Command::SelfReset:
            s_self_reset = true;
            return 1;
        // Models an entrant inside the adapter body, which outlasts the bounded adapter drain.
        case Command::HoldAdapter:
            DetourModKit::detail::adjust_mid_adapter_entries_for_test(s_mid_slot, 1);
            return 1;
        case Command::ReleaseAdapter:
            DetourModKit::detail::adjust_mid_adapter_entries_for_test(s_mid_slot, -1);
            return 1;
        case Command::Residue:
            return diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookResidue);
        case Command::ModulePins:
            return diagnostics::module_pin_count(diagnostics::ModulePinReason::Hook);
        default:
            break;
        }
        return 0;
    }
#endif
} // namespace

/** @brief Implements the independent participant protocol. */
extern "C" __declspec(dllexport) std::uintptr_t route_copy_command(route_copy::Command command, void *argument) noexcept
{
    try
    {
        switch (command)
        {
        case Command::Scan:
        {
            const auto result = safetyhook::threads_idle_outside({}, {});
            return result && *result;
        }
        case Command::HoldScan:
            safetyhook::g_route_scan_reached = false;
            safetyhook::g_route_scan_hold = true;
            return 1;
        case Command::ScanReached:
            return safetyhook::g_route_scan_reached.load();
        case Command::ReleaseScan:
            safetyhook::g_route_scan_hold = false;
            return 1;
        case Command::HoldPatch:
            safetyhook::g_trap_transaction_reached = false;
            safetyhook::g_trap_transaction_hold = true;
            return 1;
        case Command::PatchReached:
            return safetyhook::g_trap_transaction_reached.load();
        case Command::ReleasePatch:
            safetyhook::g_trap_transaction_hold = false;
            return 1;
        case Command::HoldEntry:
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::AT_ENTRY);
            return 1;
        case Command::EntryReached:
            return safetyhook::route_park_reached_for_test();
        case Command::ReleaseEntry:
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
            return 1;
        case Command::HoldDestination:
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::BEFORE_DESTINATION);
            return 1;
        case Command::Unavailable:
            safetyhook::g_coordinator_refusal_for_test = 1;
            return 1;
        case Command::RefuseNextAcquisition:
            safetyhook::g_coordinator_refusal_for_test = 3;
            return 1;
        case Command::Incompatible:
            safetyhook::g_coordinator_refusal_for_test = 2;
            return 1;
        case Command::RestoreCoordination:
            safetyhook::g_coordinator_refusal_for_test = 0;
            return 1;
        case Command::Identity:
            return safetyhook::process_coordinator_snapshot_for_test().identity;
        case Command::Records:
        {
            const auto snapshot = safetyhook::process_coordinator_snapshot_for_test();
            return snapshot.live + snapshot.retained;
        }
        case Command::Vacant:
            return safetyhook::process_coordinator_snapshot_for_test().vacant;
        case Command::Fill:
        {
            safetyhook::ProcessCoordinator coordinator;
            std::size_t count = 0;
            for (auto &key : s_keys)
            {
                if (coordinator.add(&key, 1, {&key, &key + 1}, {}, nullptr, {}))
                    ++count;
            }
            return count;
        }
        case Command::Clear:
        {
            safetyhook::ProcessCoordinator coordinator;
            for (auto &key : s_keys)
                coordinator.remove(&key);
            return 1;
        }
        case Command::HoldCoordinator:
        {
            const auto &events = *static_cast<const route_copy::HoldEvents *>(argument);
            const safetyhook::ProcessCoordinator coordinator;
            if (!coordinator)
                return 0;
            SetEvent(events.entered);
            return WaitForSingleObject(events.release, 15000) == WAIT_OBJECT_0;
        }
        default:
            break;
        }
        return policy_command(command, argument);
    }
    catch (...)
    {
        return 0;
    }
}
