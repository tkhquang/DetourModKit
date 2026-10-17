#ifndef DETOURMODKIT_STAGED_RELOAD_HPP
#define DETOURMODKIT_STAGED_RELOAD_HPP

/**
 * @file staged_reload.hpp
 * @brief Computes the shutdown result of a staged-reload logic image as a DetourModKit/abi/staged_reload.h value.
 * @details docs/guides/hot-reload/README.md defines the Init and Shutdown sequence around these calls.
 *          `StagedReloadVerdict.*` pins every rule.
 */

#include "DetourModKit/abi/staged_reload.h"
#include "DetourModKit/diagnostics.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace DetourModKit
{
    namespace hook
    {
        struct HookRetirement;
    } // namespace hook

    namespace staged_reload
    {
        /// The leak and module-pin counts of this DMK copy at one instant. @ref verdict reads only the counts above it.
        struct Baseline
        {
            /// Events per subsystem, indexed by @c static_cast<std::size_t>(diagnostics::LeakSubsystem).
            std::array<std::size_t, static_cast<std::size_t>(diagnostics::LeakSubsystem::Count)> intentional_leaks{};
            /// Outstanding references per reason, indexed by @c static_cast<std::size_t>(diagnostics::ModulePinReason).
            std::array<std::size_t, static_cast<std::size_t>(diagnostics::ModulePinReason::Count)> module_pins{};
        };

        /**
         * @brief Returns the current counts as the baseline of one generation.
         * @details Capture it at the start of Init, before the generation creates a Session, hook, worker, or binding.
         *          @ref verdict ignores every count that exists at capture.
         * @note Callback-safe.
         */
        [[nodiscard]] Baseline capture() noexcept;

        /**
         * @brief Returns the Shutdown result for the loader. The first rule that matches decides it.
         * @param retirement The result of the generation's `HookStack::retire`.
         * @param baseline The @ref capture result of the generation's Init.
         * @param loader_abi_version The ABI version that the loader declared in its request.
         * @return
         *         - DMK_STAGED_RELOAD_BUSY: @p retirement is Busy.
         *         - DMK_STAGED_RELOAD_RESTART_REQUIRED: @p retirement is Refused or pinned a hook, or a HookManager leak
         *           or a Hook module reference is above the baseline. A detour of this image stays reachable.
         *         - DMK_STAGED_RELOAD_RETAINED: another leak or module reference is above the baseline.
         *           LeakSubsystem::HookResidue and ModulePinReason::XInputTarget never count. Neither one keeps code of
         *           this image reachable.
         *         - DMK_STAGED_RELOAD_OK: no rule above matches.
         *
         *         A loader below ABI 3 receives DMK_STAGED_RELOAD_REFUSED in place of BUSY and RESTART_REQUIRED.
         * @details For a Retired outcome, call it after the Session teardown, so that the counts include every
         *          subsystem teardown. Busy and Refused change nothing, so return the verdict at once.
         * @note Callback-safe.
         */
        [[nodiscard]] std::uint32_t verdict(
            const hook::HookRetirement &retirement,
            const Baseline &baseline,
            std::uint32_t loader_abi_version
        ) noexcept;
    } // namespace staged_reload
} // namespace DetourModKit

#endif // DETOURMODKIT_STAGED_RELOAD_HPP
