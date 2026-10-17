#ifndef DETOURMODKIT_INTERNAL_HOOK_FAULT_BOUNDARY_HPP
#define DETOURMODKIT_INTERNAL_HOOK_FAULT_BOUNDARY_HPP

/**
 * @file hook_fault_boundary.hpp
 * @brief Range-confined validation of foreign hook targets and VMT object words.
 *
 * Inline/mid validation covers the backend's unchecked decode footprint. VMT validation captures the object word for
 * DMK's detached-snapshot clone and guarded publication path. These declarations are internal and are never installed.
 *
 * @warning Never span a call into the hooking backend with a function here. A guarded primitive abandons the frame
 *          that faulted, and no destructor runs. A claimed fault inside InlineHook::enable strands its locks for the
 *          process and leaves the target page writable and executable. A claimed fault in the VMT clone path strands
 *          the process-wide object gate. Validate before the backend call.
 */

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        static_assert(
            sizeof(void *) == 8,
            "BACKEND_MAX_STEAL_WINDOW is derived from the x86-64 backend layout: the "
            "JmpFF fallback it accounts for does not exist on 32-bit."
        );

        /**
         * @brief Largest byte offset the backend may read from a target before the target is known to be safe.
         * @details The backend decodes from a fixed 15-byte buffer at each instruction, with no region bound. Its
         *          indirect-jump fallback covers 14 bytes, so its last decode can start at target + 13 and read
         *          through target + 27. The backend headers export none of these sizes, so re-derive them when the
         *          backend changes. @ref InlineHookFaultProof.WindowBoundaryMatchesBackendSteal pins the value.
         */
        inline constexpr std::size_t BACKEND_MAX_STEAL_WINDOW = 28;

        /**
         * @brief Bytes written by the indirect-jump fallback and the conservative minimum for a bounded target.
         * @details The fallback writes a 6-byte jump and an 8-byte absolute address into the target. The backend
         *          picks the jump form after this validation, so a bounded target must fit the larger minimum.
         */
        inline constexpr std::size_t BACKEND_FALLBACK_MIN_PATCH = 14;

        /**
         * @brief Hard cap on the guarded vtable slot walk and on a manifest VMT binding index.
         * @details No real vtable approaches this many methods, so a walk that reaches the cap fails closed as
         *          malformed.
         */
        inline constexpr std::size_t MAX_VMT_SLOTS = 4096;

        /// A function's half-open extent as its unwind metadata declares it.
        struct FunctionBound
        {
            std::uintptr_t lo{0};
            std::uintptr_t hi{0};
        };

        /**
         * @brief Returns the extent of the RUNTIME_FUNCTION that registers @p target, or nullopt when none does.
         * @details A leaf function or JIT code declares none, which is not a refusal. A concurrent unload can withdraw
         *          the exception directory, so the record is copied under the fault guard. An inverted or empty record
         *          reads as absent. A chained entry names another fragment of a split function, so the lookup never
         *          follows one.
         */
        [[nodiscard]] std::optional<FunctionBound> unwind_bound(std::uintptr_t target) noexcept;

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
         * @details Requires [target, target + @ref BACKEND_MAX_STEAL_WINDOW) to be executable, committed, and
         *          readable. Requires @ref BACKEND_FALLBACK_MIN_PATCH bytes inside the unwind bound of the target when
         *          one exists. Code with no unwind bound, such as a leaf function or JIT code, passes.
         * @return @ref TargetWindowVerdict::Ok when the backend may proceed, else the refusal and its address.
         * @note The window is a worst-case bound. An entry within @ref BACKEND_MAX_STEAL_WINDOW of the end of its
         *       executable region is refused, although the backend can need fewer bytes.
         * @warning A verdict describes the moment it was taken. A concurrent unmap can invalidate it before the caller
         *          acts on it. The check narrows that window and attributes the failure, but it does not close it.
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
