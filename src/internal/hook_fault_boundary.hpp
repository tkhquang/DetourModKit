#ifndef DETOURMODKIT_INTERNAL_HOOK_FAULT_BOUNDARY_HPP
#define DETOURMODKIT_INTERNAL_HOOK_FAULT_BOUNDARY_HPP

/**
 * @file hook_fault_boundary.hpp
 * @brief Range-confined validation of foreign hook targets and VMT object words.
 *
 * Inline/mid validation covers the backend's unchecked decode footprint. VMT validation captures the object word for
 * DMK's detached-snapshot clone and guarded publication path. These declarations are internal and are never installed.
 *
 * @warning No function here may span a call into the hooking backend (safetyhook::InlineHook::create / enable /
 *          disable, safetyhook::MidHook::create, safetyhook::VmtHook::create / apply). DMK's guarded primitives recover
 *          from a fault by abandoning the faulting frame -- __builtin_longjmp on MinGW, an asynchronous unwind under
 *          /EHsc on MSVC -- and neither runs destructors, so a claimed fault abandons every lock and owner the frame
 *          held. InlineHook::enable holds its own mutex and the backend's virtual_protect_mutex across the patch, so a
 *          claimed fault would strand both locked for the life of the process and leave the target page
 *          writable-executable; the VMT clone path holds the process-wide object gate across its backend call, so a
 *          claimed fault there deadlocks every later VMT operation and leaks the clone's executable allocation.
 *          Validate before the backend call; never span it with a guard.
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

        /**
         * @brief Bytes written by the indirect-jump fallback and the conservative minimum for a bounded target.
         * @details The fallback stores its 8-byte absolute destination inside the target, immediately after the 6-byte
         *          jump, and NOP-fills to its stolen extent, so it writes at least 14 bytes at the target. Which form
         *          runs is decided by whether the trampoline allocation lands within near-jump reach, which happens
         *          inside the backend after this validation, so a target must satisfy the LARGER of the two minimums to
         *          be safe under either. A function shorter than this would be hooked correctly by the near jump but
         *          overwritten past its end by the fallback.
         */
        inline constexpr std::size_t BACKEND_FALLBACK_MIN_PATCH = 14;

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
         *          and requires @ref BACKEND_FALLBACK_MIN_PATCH bytes to fit inside the target's unwind-declared
         *          function bound where one exists. Code that declares no unwind bound (a leaf function, or JIT-emitted
         *          code) is accepted: absence of metadata is not evidence of an unsafe target.
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

        /// Why @ref validate_vmt_object_word refused an object, or @ref ObjectWordVerdict::Ok if it did not.
        enum class ObjectWordVerdict : std::uint8_t
        {
            Ok,
            Unreadable,
            NotWritable
        };

        /**
         * @brief An object-word verdict, the address that explains it, and the captured vptr.
         * @details @p detail is the faulting address for @ref ObjectWordVerdict::Unreadable and the object word itself
         *          otherwise. @p vptr is the value read from the object, or zero when the read failed.
         */
        struct ObjectWordResult
        {
            ObjectWordVerdict verdict{ObjectWordVerdict::Ok};
            std::uintptr_t detail{0};
            std::uintptr_t vptr{0};
        };

        /**
         * @brief Captures a readable, currently writable vptr word for guarded VMT publication.
         * @return @ref ObjectWordVerdict::Ok when publication may proceed, else the refusal and its address.
         * @note Reports writability rather than acquiring it. A caller must not make a read-only object word writable
         *       to force a clone through: the protection is the owner's, and silently widening it outlives the hook.
         * @warning A verdict describes the moment it was taken. Publication must still use a fault-contained atomic
         *          compare-exchange because a concurrent displacement, unmap, or protection change can invalidate it.
         */
        [[nodiscard]] ObjectWordResult validate_vmt_object_word(std::uintptr_t object) noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_HOOK_FAULT_BOUNDARY_HPP
