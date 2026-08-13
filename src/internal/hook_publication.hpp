#ifndef DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP
#define DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP

/**
 * @file hook_publication.hpp
 * @brief Declares test-seam vocabulary for hook publication and loader-veto boundaries.
 */

#include <cstdint>

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
#endif
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP
