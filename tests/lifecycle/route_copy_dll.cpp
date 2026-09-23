#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"

#include "route_copy_protocol.hpp"

#include <safetyhook/inline_hook.hpp>
#include <safetyhook/os.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include <windows.h>

namespace DetourModKit::detail
{
    extern void (*g_logger_record_probe)(LogLevel, std::string_view) noexcept;
    [[nodiscard]] std::size_t last_claimed_mid_slot_for_test() noexcept;
    void adjust_mid_adapter_entries_for_test(std::size_t index, std::int32_t delta) noexcept;
} // namespace DetourModKit::detail

namespace
{
    std::optional<DetourModKit::hook::Hook> s_hook;
    std::size_t s_mid_slot{};
    std::array<std::uint8_t, safetyhook::PROCESS_ROUTE_CAPACITY> s_keys{};
    using TargetFn = int (*)();
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
} // namespace

/** @brief Implements the independent participant protocol. */
extern "C" __declspec(dllexport) std::uintptr_t route_copy_command(route_copy::Command command, void *argument) noexcept
{
    using route_copy::Command;
    namespace hook = DetourModKit::hook;
    try
    {
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
            return DetourModKit::diagnostics::intentional_leak_count(
                DetourModKit::diagnostics::LeakSubsystem::HookManager
            );
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
        case Command::Disable:
            return s_hook && s_hook->disable().has_value();
        case Command::Enable:
            return s_hook && s_hook->enable().has_value();
        case Command::EnableLayerConflict:
        case Command::DisableLayerConflict:
        {
            if (!s_hook)
                return 0;
            const auto result = command == Command::EnableLayerConflict ? s_hook->enable() : s_hook->disable();
            return !result && result.error().code == DetourModKit::ErrorCode::LayerConflict;
        }
        case Command::HoldEntry:
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::AT_ENTRY);
            return 1;
        case Command::EntryReached:
            return safetyhook::route_park_reached_for_test();
        case Command::ReleaseEntry:
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
            return 1;
        case Command::Trampoline:
            return s_trampoline.load();
        case Command::Hits:
            return s_hits.load();
        case Command::Unavailable:
            safetyhook::g_coordinator_refusal_for_test = 1;
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
        }
    }
    catch (...)
    {
        return 0;
    }
    return 0;
}
