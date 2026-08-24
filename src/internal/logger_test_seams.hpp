#ifndef DETOURMODKIT_INTERNAL_LOGGER_TEST_SEAMS_HPP
#define DETOURMODKIT_INTERNAL_LOGGER_TEST_SEAMS_HPP

/**
 * @file internal/logger_test_seams.hpp
 * @brief Test-only white-box access to Logger process-default state.
 * @details Non-installed friend accessor: the installed Logger definition stays token-stable while tests read the
 *          private snapshot through this header. This header exists only in test-seam builds. See the gate rule in
 *          docs/design/testing.md.
 */

#include "DetourModKit/logger.hpp"

#include <memory>

#if defined(DMK_ENABLE_TEST_SEAMS)

namespace DetourModKit::detail
{
    /**
     * @class LoggerTestSeams
     * @brief Provides private process-default snapshot access to failure-atomicity tests.
     */
    class LoggerTestSeams
    {
    public:
        /// Returns the current process-default snapshot for failure-atomicity tests.
        [[nodiscard]] static std::shared_ptr<const Logger::StaticConfig> static_config_for_test()
        {
            return Logger::get_static_config();
        }

    private:
        LoggerTestSeams() = delete;
    };
} // namespace DetourModKit::detail

#endif // DMK_ENABLE_TEST_SEAMS

#endif // DETOURMODKIT_INTERNAL_LOGGER_TEST_SEAMS_HPP
