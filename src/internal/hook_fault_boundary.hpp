#ifndef DETOURMODKIT_INTERNAL_HOOK_FAULT_BOUNDARY_HPP
#define DETOURMODKIT_INTERNAL_HOOK_FAULT_BOUNDARY_HPP

/**
 * @file hook_fault_boundary.hpp
 * @brief Range-confined validation of a hook target's backend steal window.
 *
 * The hooking backend decodes a target's prologue with no readability or protection check of its own, so an invalid or
 * concurrently unmapped target faults inside backend code and kills the host. This boundary proves the window the
 * backend may touch is executable, committed and readable before the backend is ever called, and reports which byte
 * failed. These declarations are internal to the build and are never installed.
 *
 * @warning No function here may span a call into the hooking backend (safetyhook::InlineHook::create / enable /
 *          disable, safetyhook::MidHook::create). DMK's guarded primitives recover from a fault by abandoning the
 *          faulting frame -- __builtin_longjmp on MinGW, an asynchronous unwind under /EHsc on MSVC -- and neither
 *          runs destructors. InlineHook::enable holds its own mutex and the backend's virtual_protect_mutex across the
 *          patch, so a claimed fault would abandon both locked for the life of the process and strand the target page
 *          writable-executable. Validate before the backend call; never around it.
 */

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        static_assert(sizeof(void *) == 8, "BACKEND_MAX_STEAL_WINDOW is derived from the x86-64 backend layout: the "
                                           "JmpFF fallback it accounts for does not exist on 32-bit.");

        /**
         * @brief Largest byte offset the backend may read from a target before the target is known to be safe.
         * @details The backend hands its decoder a fixed 15-byte buffer at each instruction pointer, unclamped by any
         *          region bound, and walks until it has covered a jump's worth of prologue. Its indirect-jump fallback
         *          (6-byte jump plus an 8-byte absolute address = 14) is the deeper of the two walks, so the last
         *          instruction it decodes can begin at target + 13 and read through target + 27. The fallback is
         *          reachable whenever the near-jump attempt fails after a clean decode, so this bound is not
         *          hypothetical. These sizes are private to the backend's implementation and are not exported by its
         *          headers, so they cannot be queried and must be mirrored here; re-derive them when the backend is
         *          repinned. @ref InlineHookFaultProof.WindowBoundaryMatchesBackendSteal pins the value.
         */
        inline constexpr std::size_t BACKEND_MAX_STEAL_WINDOW = 28;

        /// Smallest patch a successful inline install writes: the backend's near jump (E9 rel32).
        inline constexpr std::size_t BACKEND_MIN_PATCH = 5;

        /// Why @ref validate_backend_steal_window refused a target, or @ref TargetWindowVerdict::Ok if it did not.
        enum class TargetWindowVerdict : std::uint8_t
        {
            Ok,
            NotExecutable,
            Unreadable,
            BoundOverrun
        };

        /**
         * @brief A window verdict and the address that explains it.
         * @details @p detail is the faulting address for @ref TargetWindowVerdict::Unreadable, the function's end for
         *          @ref TargetWindowVerdict::BoundOverrun, and the target itself otherwise.
         */
        struct TargetWindowResult
        {
            TargetWindowVerdict verdict{TargetWindowVerdict::Ok};
            std::uintptr_t detail{0};
        };

        /**
         * @brief Decides whether @p target can be handed to the backend without risking a host fault.
         * @details Requires [target, target + @ref BACKEND_MAX_STEAL_WINDOW) to be executable, committed and readable,
         *          and requires a @ref BACKEND_MIN_PATCH patch to fit inside the target's unwind-declared function
         *          bound where one exists. Code that declares no unwind bound (a leaf function, or JIT-emitted code) is
         *          accepted: absence of metadata is not evidence of an unsafe target.
         * @return @ref TargetWindowVerdict::Ok when the backend may proceed, else the refusal and its address.
         * @note Conservative by construction. The window is a worst-case bound, so a valid function entry lying within
         *       @ref BACKEND_MAX_STEAL_WINDOW of the end of its executable region is refused even though the backend
         *       might have decoded it in fewer bytes. Refusing a hookable target returns a typed error; admitting an
         *       unreadable one kills the host.
         * @warning A verdict describes the moment it was taken. A concurrent unmap can invalidate it before the caller
         *          acts on it; this narrows the window and attributes failures, and does not eliminate the race.
         */
        [[nodiscard]] TargetWindowResult validate_backend_steal_window(std::uintptr_t target) noexcept;

        /// Human-readable fragment naming a window refusal, for diagnostic log lines.
        [[nodiscard]] std::string_view target_window_description(TargetWindowVerdict verdict) noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_HOOK_FAULT_BOUNDARY_HPP
