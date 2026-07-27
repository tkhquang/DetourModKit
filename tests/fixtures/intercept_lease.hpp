#ifndef DETOURMODKIT_TESTS_FIXTURES_INTERCEPT_LEASE_HPP
#define DETOURMODKIT_TESTS_FIXTURES_INTERCEPT_LEASE_HPP

/**
 * @file intercept_lease.hpp
 * @brief Standalone interception-layer lease for tests that drive the data plane without a poller.
 * @details Every write to the state the interception detours read is authorized against the live layer owner, so a test
 *          that publishes a mask or rule list directly must hold the layer for the duration exactly as an installing
 *          poller does. Acquisition fails while a real owner holds the layer, which is the intended outcome: a test
 *          must not be able to overwrite a live poller's published state either.
 */

#include "internal/input_intercept.hpp"

namespace dmk_test
{
    /**
     * @class StandaloneInterceptLease
     * @brief RAII hold on the interception layer for @c STANDALONE_INTERCEPT_OWNER.
     * @details Release clears every mask and rule the lease authorized, so a case cannot leave suppression armed for a
     *          later case in the same process.
     */
    class StandaloneInterceptLease
    {
    public:
        StandaloneInterceptLease() noexcept : m_held(DetourModKit::detail::acquire_standalone_lease_for_test()) {}

        ~StandaloneInterceptLease() noexcept
        {
            if (m_held)
            {
                DetourModKit::detail::release_standalone_lease_for_test();
            }
        }

        StandaloneInterceptLease(const StandaloneInterceptLease &) = delete;
        StandaloneInterceptLease &operator=(const StandaloneInterceptLease &) = delete;
        StandaloneInterceptLease(StandaloneInterceptLease &&) = delete;
        StandaloneInterceptLease &operator=(StandaloneInterceptLease &&) = delete;

        /// Returns whether the layer was free to claim.
        [[nodiscard]] bool held() const noexcept { return m_held; }

        /// The owner id a data-plane call must present while this lease is held.
        [[nodiscard]] static constexpr std::uint64_t owner() noexcept
        {
            return DetourModKit::detail::STANDALONE_INTERCEPT_OWNER;
        }

    private:
        bool m_held;
    };

    /**
     * @brief Empties the published consume-rule table if the layer is free.
     * @details Test hygiene between cases. A layer a live poller still owns is deliberately left alone; that poller's
     *          own teardown clears it, and forcing a clear here is the cross-owner stomp the lease exists to prevent.
     */
    inline void reset_published_consume_rules() noexcept
    {
        const StandaloneInterceptLease lease;
    }
} // namespace dmk_test

#endif // DETOURMODKIT_TESTS_FIXTURES_INTERCEPT_LEASE_HPP
