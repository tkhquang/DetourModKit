/**
 * @file staged_reload.cpp
 * @brief The staged-reload baseline and Shutdown verdict over the diagnostics counters of this DMK copy.
 */

#include "DetourModKit/staged_reload.hpp"

#include "DetourModKit/hook.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace DetourModKit
{
    namespace staged_reload
    {
        namespace
        {
            using diagnostics::LeakSubsystem;
            using diagnostics::ModulePinReason;

            template <class Enum, std::size_t Size>
            [[nodiscard]] bool grew(
                const std::array<std::size_t, Size> &now,
                const std::array<std::size_t, Size> &baseline,
                Enum which
            ) noexcept
            {
                const auto index = static_cast<std::size_t>(which);
                return now[index] > baseline[index];
            }

            [[nodiscard]] std::uint32_t
            classify(const hook::HookRetirement &retirement, const Baseline &baseline) noexcept
            {
                if (retirement.outcome == hook::RetirementOutcome::Busy)
                {
                    return DMK_STAGED_RELOAD_BUSY;
                }
                const Baseline now = capture();
                if (retirement.outcome == hook::RetirementOutcome::Refused || retirement.pinned != 0 ||
                    grew(now.intentional_leaks, baseline.intentional_leaks, LeakSubsystem::HookManager) ||
                    grew(now.module_pins, baseline.module_pins, ModulePinReason::Hook))
                {
                    return DMK_STAGED_RELOAD_RESTART_REQUIRED;
                }
                for (std::size_t index = 0; index < now.intentional_leaks.size(); ++index)
                {
                    const auto subsystem = static_cast<LeakSubsystem>(index);
                    if (subsystem != LeakSubsystem::HookResidue &&
                        grew(now.intentional_leaks, baseline.intentional_leaks, subsystem))
                    {
                        return DMK_STAGED_RELOAD_RETAINED;
                    }
                }
                for (std::size_t index = 0; index < now.module_pins.size(); ++index)
                {
                    const auto reason = static_cast<ModulePinReason>(index);
                    if (reason != ModulePinReason::XInputTarget && grew(now.module_pins, baseline.module_pins, reason))
                    {
                        return DMK_STAGED_RELOAD_RETAINED;
                    }
                }
                return DMK_STAGED_RELOAD_OK;
            }
        } // namespace

        Baseline capture() noexcept
        {
            Baseline baseline;
            for (std::size_t index = 0; index < baseline.intentional_leaks.size(); ++index)
            {
                baseline.intentional_leaks[index] =
                    diagnostics::intentional_leak_count(static_cast<LeakSubsystem>(index));
            }
            for (std::size_t index = 0; index < baseline.module_pins.size(); ++index)
            {
                baseline.module_pins[index] = diagnostics::module_pin_count(static_cast<ModulePinReason>(index));
            }
            return baseline;
        }

        std::uint32_t verdict(
            const hook::HookRetirement &retirement,
            const Baseline &baseline,
            std::uint32_t loader_abi_version
        ) noexcept
        {
            const std::uint32_t result = classify(retirement, baseline);
            const bool unknown_to_loader =
                loader_abi_version < DMK_STAGED_RELOAD_ABI_VERSION &&
                (result == DMK_STAGED_RELOAD_BUSY || result == DMK_STAGED_RELOAD_RESTART_REQUIRED);
            return unknown_to_loader ? DMK_STAGED_RELOAD_REFUSED : result;
        }
    } // namespace staged_reload
} // namespace DetourModKit
