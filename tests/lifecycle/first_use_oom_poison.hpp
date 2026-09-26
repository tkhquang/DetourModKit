#ifndef DETOURMODKIT_LIFECYCLE_FIRST_USE_OOM_POISON_HPP
#define DETOURMODKIT_LIFECYCLE_FIRST_USE_OOM_POISON_HPP

// Global allocation replacement for the first-use OOM proof hosts. Include it in exactly one translation unit of a
// host: it defines the program's plain and nothrow operator new and delete. Aligned forms stay at their defaults.
// An armed allowance lets that many allocations succeed and refuses every later one, which reaches a constructor's
// own allocation after the object's storage was granted. A disarmed allowance admits everything.

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

namespace dmk_first_use
{
    inline std::atomic<long long> g_allowance{-1};

    /// Admits the next @p allow allocations and refuses every later one until @ref disarm.
    inline void arm(long long allow) noexcept
    {
        g_allowance.store(allow, std::memory_order_release);
    }

    inline void disarm() noexcept
    {
        g_allowance.store(-1, std::memory_order_release);
    }

    [[nodiscard]] inline bool admit() noexcept
    {
        long long remaining = g_allowance.load(std::memory_order_acquire);
        while (remaining >= 0)
        {
            if (remaining == 0)
            {
                return false;
            }
            if (g_allowance.compare_exchange_weak(
                    remaining,
                    remaining - 1,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire
                ))
            {
                return true;
            }
        }
        return true;
    }

    /// The registered SKIP_RETURN_CODE for an arm whose subject is absent on the running STL.
    constexpr int SKIP_RETURN_CODE = 77;

    /// True on the MSVC debug STL, whose hidden container proxies derail exact allocation budgets.
    [[nodiscard]] constexpr bool debug_stl_proxies() noexcept
    {
#if defined(_MSC_VER) && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL != 0
        return true;
#else
        return false;
#endif
    }
} // namespace dmk_first_use

void *operator new(std::size_t size)
{
    if (!dmk_first_use::admit())
    {
        throw std::bad_alloc{};
    }
    if (void *p = std::malloc(size != 0 ? size : 1))
    {
        return p;
    }
    throw std::bad_alloc{};
}

void *operator new[](std::size_t size)
{
    return ::operator new(size);
}

void *operator new(std::size_t size, const std::nothrow_t &) noexcept
{
    if (!dmk_first_use::admit())
    {
        return nullptr;
    }
    return std::malloc(size != 0 ? size : 1);
}

void *operator new[](std::size_t size, const std::nothrow_t &tag) noexcept
{
    return ::operator new(size, tag);
}

void operator delete(void *p) noexcept
{
    std::free(p);
}

void operator delete[](void *p) noexcept
{
    std::free(p);
}

void operator delete(void *p, std::size_t) noexcept
{
    std::free(p);
}

void operator delete[](void *p, std::size_t) noexcept
{
    std::free(p);
}

void operator delete(void *p, const std::nothrow_t &) noexcept
{
    std::free(p);
}

void operator delete[](void *p, const std::nothrow_t &) noexcept
{
    std::free(p);
}

#endif // DETOURMODKIT_LIFECYCLE_FIRST_USE_OOM_POISON_HPP
