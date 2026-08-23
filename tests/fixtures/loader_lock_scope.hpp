#ifndef DETOURMODKIT_TEST_LOADER_LOCK_SCOPE_HPP
#define DETOURMODKIT_TEST_LOADER_LOCK_SCOPE_HPP

// The forced probe is a DMK_ENABLE_TEST_SEAMS seam, so this fixture serves the gtest binary that defines it.
#include "internal/lifecycle_context.hpp"
#include "platform.hpp"

namespace dmk_test
{
    /// Reports the loader lock as held.
    [[nodiscard]] inline bool loader_lock_always_held() noexcept
    {
        return true;
    }

    /// Reports the loader lock as free.
    [[nodiscard]] inline bool loader_lock_never_held() noexcept
    {
        return false;
    }

    /**
     * @brief Forces the verdict of the DMK loader-lock probe for the scope.
     * @details The destructor restores the prior probe and loader context, so a failed expectation affects no later
     *          case in the shared process.
     */
    class ForcedLoaderProbe
    {
    public:
        explicit ForcedLoaderProbe(bool (*probe)() noexcept = &loader_lock_always_held) noexcept
            : m_saved_probe(DetourModKit::detail::g_loader_lock_override),
              m_saved_context(DetourModKit::detail::lifecycle().loader_context())
        {
            DetourModKit::detail::g_loader_lock_override = probe;
        }
        ~ForcedLoaderProbe() noexcept
        {
            DetourModKit::detail::g_loader_lock_override = m_saved_probe;
            DetourModKit::detail::lifecycle().set_loader_context(m_saved_context);
        }
        ForcedLoaderProbe(const ForcedLoaderProbe &) = delete;
        ForcedLoaderProbe &operator=(const ForcedLoaderProbe &) = delete;
        ForcedLoaderProbe(ForcedLoaderProbe &&) = delete;
        ForcedLoaderProbe &operator=(ForcedLoaderProbe &&) = delete;

    private:
        bool (*m_saved_probe)() noexcept;
        DetourModKit::detail::LoaderContext m_saved_context;
    };
} // namespace dmk_test

#endif // DETOURMODKIT_TEST_LOADER_LOCK_SCOPE_HPP
