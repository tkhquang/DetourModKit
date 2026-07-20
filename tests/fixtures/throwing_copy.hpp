#ifndef DETOURMODKIT_TEST_THROWING_COPY_HPP
#define DETOURMODKIT_TEST_THROWING_COPY_HPP

// The allocation probe in test_alloc_probe.hpp is thread-scoped, so arming it on the test thread cannot reach an
// allocation the poll thread makes. A callable that throws while being copied injects the same failure at the exact
// point a staging pass copies a binding's callback, on whichever thread the pass runs.

#include <atomic>
#include <memory>
#include <new>
#include <utility>

namespace dmk_test
{
    /**
     * @class ThrowingCopyCallback
     * @brief A std::function target whose copy constructor throws std::bad_alloc while armed.
     * @details Arming and the failure/invocation counters are shared through the pointers passed at construction, so a
     *          test still observes them after std::function has copied the target away.
     */
    class ThrowingCopyCallback
    {
    public:
        explicit ThrowingCopyCallback(std::shared_ptr<std::atomic<bool>> throw_on_copy,
                                      std::shared_ptr<std::atomic<int>> failed_copies,
                                      std::shared_ptr<std::atomic<int>> invocations) noexcept
            : m_throw_on_copy(std::move(throw_on_copy)), m_failed_copies(std::move(failed_copies)),
              m_invocations(std::move(invocations))
        {
        }

        ThrowingCopyCallback(const ThrowingCopyCallback &other)
            : m_throw_on_copy(other.m_throw_on_copy), m_failed_copies(other.m_failed_copies),
              m_invocations(other.m_invocations)
        {
            throw_if_armed();
        }

        // std::function stores the target by copy-construction, so copy assignment has no call site to arm.
        ThrowingCopyCallback &operator=(const ThrowingCopyCallback &) = delete;

        ThrowingCopyCallback(ThrowingCopyCallback &&) noexcept = default;
        ThrowingCopyCallback &operator=(ThrowingCopyCallback &&) noexcept = default;

        /// Invokes the callback without affecting the copy-failure controls.
        void operator()() const noexcept { m_invocations->fetch_add(1, std::memory_order_relaxed); }

    private:
        void throw_if_armed() const
        {
            if (m_throw_on_copy != nullptr && m_throw_on_copy->load(std::memory_order_relaxed))
            {
                m_failed_copies->fetch_add(1, std::memory_order_relaxed);
                throw std::bad_alloc{};
            }
        }

        std::shared_ptr<std::atomic<bool>> m_throw_on_copy;
        std::shared_ptr<std::atomic<int>> m_failed_copies;
        std::shared_ptr<std::atomic<int>> m_invocations;
    };
} // namespace dmk_test

#endif // DETOURMODKIT_TEST_THROWING_COPY_HPP
