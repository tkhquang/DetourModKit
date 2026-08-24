#ifndef DETOURMODKIT_INTERNAL_INPUT_TEST_SEAMS_HPP
#define DETOURMODKIT_INTERNAL_INPUT_TEST_SEAMS_HPP

/**
 * @file internal/input_test_seams.hpp
 * @brief Test-only white-box access to the Input facade.
 * @details Non-installed friend accessor: the installed Input definition stays token-stable while tests reach the
 *          facade internals through this header. The member definitions live in src/input.cpp under the same gate.
 *          This header exists only in test-seam builds. See the gate rule in docs/design/testing.md.
 */

#include "DetourModKit/input.hpp"

#if defined(DMK_ENABLE_TEST_SEAMS)

namespace DetourModKit::detail
{
    /**
     * @struct InputTestSeams
     * @brief Provides private facade access to input lifecycle tests.
     */
    struct InputTestSeams
    {
        /// Probe invoked after registration or start admission and before its commit.
        using CallbackAdmissionCommitSeam = void (*)() noexcept;

        /// Installs the callback-admission commit probe. Null clears it.
        static void set_callback_admission_commit_seam_for_test(CallbackAdmissionCommitSeam seam) noexcept;

        /**
         * @brief Test-only: grants the live engine the interception layer and republishes its consume rules.
         * @details A test host has no loaded XInput module to hook. A published-table case requires this owner state.
         *          Returns false when no engine exists or another owner holds the layer. Release archives omit it.
         */
        [[nodiscard]] static bool adopt_intercept_owner_for_test() noexcept;

        /// Locks the facade mutex until the paired test seam releases it.
        static void lock_facade_mutex_for_test() noexcept;
        /// Releases the lock taken by lock_facade_mutex_for_test, on the same thread.
        static void unlock_facade_mutex_for_test() noexcept;
        /// Clears the test retention latch and reports whether it was set.
        [[nodiscard]] static bool reclaim_vetoed_impl_for_test() noexcept;
    };
} // namespace DetourModKit::detail

#endif // DMK_ENABLE_TEST_SEAMS

#endif // DETOURMODKIT_INTERNAL_INPUT_TEST_SEAMS_HPP
