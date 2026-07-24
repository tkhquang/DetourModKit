#include "test_alloc_probe.hpp"

#include <cstddef>
#include <cstdlib>
#include <new>

// This translation unit owns the test binary's single replacement of the global allocation operators. The
// throwing forms tally a per-thread counter that allocation-sensitive tests read through a before/after
// delta; the aligned (std::align_val_t) forms are deliberately left at their defaults, so over-aligned
// allocations stay on the runtime's own consistent new/delete pair and never cross-free against these.
namespace
{
    // Constant-initialised so it reads zero before any dynamic initialisation that might allocate.
    thread_local long long s_thread_new_calls = 0;

    // Out-of-memory injection budget for the current thread. A negative value disarms injection (the default, so
    // an unarmed test binary allocates exactly as it did before). When armed (>= 0) it is the number of further
    // throwing operator new calls to let succeed before every subsequent one throws std::bad_alloc.
    constexpr long long ALLOC_FAILURE_DISARMED = -1;
    thread_local long long s_alloc_failure_budget = ALLOC_FAILURE_DISARMED;
} // namespace

namespace dmk_test
{
    bool stl_supports_exact_allocation_budgets() noexcept
    {
#if defined(_MSC_VER) && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL != 0
        return false;
#else
        return true;
#endif
    }

    long long thread_new_calls() noexcept
    {
        return s_thread_new_calls;
    }

    void arm_alloc_failure(long long allow) noexcept
    {
        s_alloc_failure_budget = allow < 0 ? 0 : allow;
    }

    void disarm_alloc_failure() noexcept
    {
        s_alloc_failure_budget = ALLOC_FAILURE_DISARMED;
    }
} // namespace dmk_test

void *operator new(std::size_t size)
{
    ++s_thread_new_calls;
    // Injection is checked after the counter bump so an injected attempt is still counted, and before malloc so a
    // failure allocates nothing. The budget is consumed monotonically: once it reaches zero every further call on
    // this thread fails, which is what lets a serial batch degrade its remaining items uniformly under OOM.
    if (s_alloc_failure_budget >= 0)
    {
        if (s_alloc_failure_budget == 0)
        {
            throw std::bad_alloc{};
        }
        --s_alloc_failure_budget;
    }
    void *p = std::malloc(size != 0 ? size : 1);
    if (p == nullptr)
    {
        throw std::bad_alloc{};
    }
    return p;
}

void *operator new[](std::size_t size)
{
    return operator new(size);
}

void operator delete(void *p) noexcept
{
    std::free(p);
}

void operator delete(void *p, std::size_t) noexcept
{
    std::free(p);
}

void operator delete[](void *p) noexcept
{
    std::free(p);
}

void operator delete[](void *p, std::size_t) noexcept
{
    std::free(p);
}
