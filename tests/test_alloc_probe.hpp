#ifndef DETOURMODKIT_TEST_ALLOC_PROBE_HPP
#define DETOURMODKIT_TEST_ALLOC_PROBE_HPP

namespace dmk_test
{
    /// Returns whether this STL supports deterministic exact-allocation budgets.
    [[nodiscard]] bool stl_supports_exact_allocation_budgets() noexcept;

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

    /**
     * @brief Arms out-of-memory injection on the calling thread: the next @p allow throwing operator new calls
     *        succeed, then every subsequent one throws std::bad_alloc until disarmed.
     * @details This drives the noexcept-batch degradation contract: a resolver injected into a running host must
     *          degrade rather than terminate under true OOM. Injection is thread-local, so it
     *          only trips allocations made on THIS thread. A batch API therefore has to be driven SERIALLY
     *          (max_workers == 1) for the injected failures to land deterministically -- a parallel batch would
     *          run its per-item allocations on worker threads that never see this thread's armed state.
     *
     *          The @p allow budget picks which allocation fails: 0 fails the very first allocation (the result
     *          container itself, exercising the whole-batch out-of-memory signal); a small positive value lets
     *          the container through and fails every per-item allocation after it (exercising per-request
     *          degradation). Keep the armed window as tight as possible -- ideally spanning only the single call
     *          under test -- so the injector never trips GoogleTest's own bookkeeping allocations.
     *
     *          The budget counts the code-under-test's OWN allocations, so it relies on the standard library issuing
     *          no hidden per-container bookkeeping allocation on construction. libstdc++ (MinGW) satisfies this in
     *          every configuration; MSVC's debug STL does not, so proxy-sensitive tests call
     *          DMK_REQUIRE_PROXY_FREE_STL() first and prove the same budgets on the MSVC release STL lane.
     * @param allow Number of further operator new calls to let succeed before failing (clamped at 0).
     */
    void arm_alloc_failure(long long allow) noexcept;

    /// Disarms out-of-memory injection on the calling thread, restoring normal allocation.
    void disarm_alloc_failure() noexcept;

    /**
     * @struct AllocFailScope
     * @brief RAII wrapper that arms @ref arm_alloc_failure on construction and disarms on destruction.
     * @details Confine the guarded scope to just the call under test. Neither the constructor nor the destructor
     *          allocates, so the arm/disarm brackets never perturb the injected budget, and the guard always
     *          disarms even if the code under test throws (it must not, since the batch boundary is noexcept, but
     *          the guard stays correct if that invariant is ever violated).
     */
    struct AllocFailScope
    {
        explicit AllocFailScope(long long allow) noexcept { arm_alloc_failure(allow); }
        ~AllocFailScope() noexcept { disarm_alloc_failure(); }
        AllocFailScope(const AllocFailScope &) = delete;
        AllocFailScope &operator=(const AllocFailScope &) = delete;
        AllocFailScope(AllocFailScope &&) = delete;
        AllocFailScope &operator=(AllocFailScope &&) = delete;
    };
} // namespace dmk_test

// MSVC's debug STL allocates hidden container proxies inside noexcept constructors, so exact-budget OOM injection is
// supported only by libstdc++ and the MSVC release STL. The out-of-line runtime query keeps the remainder of a skipped
// test compile-reachable under MSVC's unreachable-code warning.
#define DMK_REQUIRE_PROXY_FREE_STL()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!dmk_test::stl_supports_exact_allocation_budgets())                                                        \
        {                                                                                                              \
            GTEST_SKIP() << "MSVC debug iterators allocate hidden container proxies; this out-of-memory contract "     \
                            "is proven on the MSVC release STL lane and on libstdc++";                                 \
        }                                                                                                              \
    } while (false)

#endif // DETOURMODKIT_TEST_ALLOC_PROBE_HPP
