#ifndef DETOURMODKIT_INTERNAL_HOOK_PATCH_WITNESS_HPP
#define DETOURMODKIT_INTERNAL_HOOK_PATCH_WITNESS_HPP

/**
 * @file hook_patch_witness.hpp
 * @brief Four-state ownership witness for managed hook patch windows.
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
     * @brief Who owns the bytes currently at a managed hook's patch window.
     * @details Original means no patch is installed; OwnedPatch means the bytes exactly match an encoding this backend
     *          committed; Foreign means the readable window matches neither; Indeterminate means it could not be read.
     */
    enum class PatchWitness : std::uint8_t
    {
        Original,
        OwnedPatch,
        Foreign,
        Indeterminate
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

    /// Returns whether a witness authorizes the managed backend to overwrite the target.
    [[nodiscard]] constexpr bool witness_permits_write(PatchWitness witness) noexcept
    {
        return witness == PatchWitness::Original || witness == PatchWitness::OwnedPatch;
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_PATCH_WITNESS_HPP
