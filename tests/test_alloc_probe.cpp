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
} // namespace

namespace dmk_test
{
    long long thread_new_calls() noexcept
    {
        return s_thread_new_calls;
    }
} // namespace dmk_test

void *operator new(std::size_t size)
{
    ++s_thread_new_calls;
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
