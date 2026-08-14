#ifndef DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP
#define DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP

/**
 * @file hook_publication.hpp
 * @brief The hook loader-lock veto and test-seam vocabulary for publication and loader-veto boundaries.
 */

#include "DetourModKit/error.hpp"

#include "platform.hpp"

#include <cstdint>
#include <optional>

namespace DetourModKit::detail
{
    /// Identifies a completed boundary in the inline/mid publication transaction.
    enum class HookPublishStep : std::uint8_t
    {
        BackendCreated,
        ImplConstructed,
        GatePublished,
        LedgerCommitted
    };

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Identifies one hook mutation entry at its first boundary after the loader-lock veto.
    enum class HookLoaderEntry : std::uint8_t
    {
        InlineAt,
        MidAt,
        InstallAll,
        VmtFor,
        Enable,
        Disable,
        VmtApply,
        VmtRemove,
        VmtHookMethod,
        VmtRemoveMethod,
        Count
    };

    /// Fires after the loader-lock check permits a mutation entry and before that entry performs other work.
    extern void (*g_hook_post_loader_veto_probe)(HookLoaderEntry) noexcept;

    /// HookTogglePublicationOrder.* owns this proof seam.
    extern void (*g_hook_toggle_publication_probe)(bool, bool, bool, bool) noexcept;
#endif
} // namespace DetourModKit::detail

namespace DetourModKit::hook
{
    /**
     * @brief Implements the hook.hpp loader-lock precondition.
     * @details T-HOOK-LOADER pins this gate before each mutation boundary.
     */
    [[nodiscard]] inline std::optional<Error> refuse_on_loader_lock(const char *operation) noexcept
    {
        if (DetourModKit::detail::is_loader_lock_held())
        {
            return Error{ErrorCode::LoaderLockActive, operation};
        }
        return std::nullopt;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    inline void note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry entry) noexcept
    {
        if (auto *probe = DetourModKit::detail::g_hook_post_loader_veto_probe)
        {
            probe(entry);
        }
    }
#endif
} // namespace DetourModKit::hook

#endif // DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP
