#ifndef DETOURMODKIT_INTERNAL_HOOK_PATCH_WITNESS_HPP
#define DETOURMODKIT_INTERNAL_HOOK_PATCH_WITNESS_HPP

/**
 * @file hook_patch_witness.hpp
 * @brief Ownership witness for inline-hook patch windows.
 */

#include "internal/hook_fault_boundary.hpp"
#include "internal/memory_guarded.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace DetourModKit::detail
{
    /**
     * @brief Who owns the bytes currently at an inline backend's patch window.
     * @details Original means no patch is installed; OwnedPatch means the bytes exactly match an encoding this backend
     *          committed; Foreign means the readable window matches neither; Indeterminate means it could not be read.
     *          LayeredOver means the window holds the patch of another coordinator layer, which an arm recaptures
     *          (`[B-110]`). Only the arm witness reports it.
     */
    enum class PatchWitness : std::uint8_t
    {
        Original,
        OwnedPatch,
        Foreign,
        Indeterminate,
        LayeredOver
    };

    /// Names a patch witness for an operator-facing diagnostic.
    [[nodiscard]] constexpr std::string_view witness_description(PatchWitness witness) noexcept
    {
        switch (witness)
        {
        case PatchWitness::Original:
            return "prologue is original";
        case PatchWitness::OwnedPatch:
            return "our patch is still installed";
        case PatchWitness::Foreign:
            return "another writer owns the prologue";
        case PatchWitness::LayeredOver:
            return "another layer owns the prologue";
        case PatchWitness::Indeterminate:
            break;
        }
        return "prologue could not be read";
    }

    /**
     * @brief Reads a backend target and classifies ownership of its patch window.
     * @details OwnedPatch requires both exact bytes and persistent provenance that the backend completed a patch-byte
     *          capture. Pre-sized or default-initialized storage is not evidence that the backend emitted those bytes.
     */
    template <class Backend> [[nodiscard]] PatchWitness witness_patch(const Backend &backend) noexcept
    {
        const auto &original = backend.original_bytes();
        std::array<std::uint8_t, BACKEND_MAX_STEAL_WINDOW> current{};
        if (original.empty() || original.size() > current.size() || backend.target() == nullptr)
        {
            return PatchWitness::Indeterminate;
        }
        const std::size_t count = original.size();
        if (!guarded_read_bytes(reinterpret_cast<std::uintptr_t>(backend.target()), current.data(), count))
        {
            return PatchWitness::Indeterminate;
        }
        const auto span = static_cast<std::ptrdiff_t>(count);
        if (std::equal(original.begin(), original.begin() + span, current.begin()))
        {
            return PatchWitness::Original;
        }
        const auto &emitted = backend.patch_bytes();
        if (backend.patch_bytes_valid() && emitted.size() == count &&
            std::equal(emitted.begin(), emitted.begin() + span, current.begin()))
        {
            return PatchWitness::OwnedPatch;
        }
        return PatchWitness::Foreign;
    }

    /// Returns whether a witness authorizes the backend to overwrite the target.
    [[nodiscard]] constexpr bool witness_permits_write(PatchWitness witness) noexcept
    {
        return witness == PatchWitness::Original || witness == PatchWitness::OwnedPatch;
    }

    /// Returns whether an arm over @p witness makes the hook the newest layer of its target (`[B-110]`).
    [[nodiscard]] constexpr bool witness_promotes_arm(PatchWitness witness) noexcept
    {
        return witness == PatchWitness::Original || witness == PatchWitness::LayeredOver;
    }

    /**
     * @brief Classifies a target for an arm: @ref witness_patch, with LayeredOver in place of Foreign when the backend
     *        reports the patch of another coordinator layer.
     * @note The backend query takes the process coordinator, so a caller that holds a target slot keeps the order of
     *       `[B-109]`.
     */
    template <class Backend> [[nodiscard]] PatchWitness witness_arm(const Backend &backend) noexcept
    {
        const PatchWitness witness = witness_patch(backend);
        return witness == PatchWitness::Foreign && backend.window_holds_layer() ? PatchWitness::LayeredOver : witness;
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_PATCH_WITNESS_HPP
