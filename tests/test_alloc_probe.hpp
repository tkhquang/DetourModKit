#ifndef DETOURMODKIT_TEST_ALLOC_PROBE_HPP
#define DETOURMODKIT_TEST_ALLOC_PROBE_HPP

namespace dmk_test
{
    /**
     * @brief Cumulative count of throwing global operator new calls made by the calling thread.
     * @details The counter is thread-local, so allocations on a background thread (such as the async logger
     *          writer) never perturb a delta measured on the test thread. Take a before/after difference
     *          around the code under test. The single global operator new/delete replacement that feeds this
     *          counter lives in test_alloc_probe.cpp; only one translation unit in the test binary may replace
     *          the global allocation operators, so any test that needs allocation counting routes through here.
     * @return The number of throwing operator new calls charged to the current thread so far.
     */
    [[nodiscard]] long long thread_new_calls() noexcept;
} // namespace dmk_test

#endif // DETOURMODKIT_TEST_ALLOC_PROBE_HPP
