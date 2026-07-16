#ifndef DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP
#define DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP

/**
 * @file hook_publication.hpp
 * @brief Test-seam vocabulary for the disabled-first inline/mid publication transaction.
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
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_PUBLICATION_HPP
