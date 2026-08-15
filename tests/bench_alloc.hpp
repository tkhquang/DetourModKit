#ifndef DETOURMODKIT_TESTS_BENCH_ALLOC_HPP
#define DETOURMODKIT_TESTS_BENCH_ALLOC_HPP

/**
 * @file bench_alloc.hpp
 * @brief Counting global allocator shared by the benchmark executables that measure heap footprint.
 * @details Replacing the executable's global allocation functions covers every C++ heap allocation resolved
 *          into that image, including the statically linked library's container allocations, so counter
 *          deltas snapshotted around single-threaded operations are attributable to the subsystem under
 *          measurement. The replacements FORWARD to the CRT allocator the runtime DLLs also use
 *          (malloc/_aligned_malloc): a header-prefix scheme would corrupt the heap whenever an allocation
 *          crosses the executable/runtime-DLL boundary, because only the executable's copies of new/delete
 *          are replaced on PE. Plain sizes come from _msize, which returns the recorded request size, so
 *          frees balance allocations exactly. The rare over-aligned allocations are tracked in a fixed side
 *          table because the CRT has no portable aligned msize; a foreign aligned pointer simply frees
 *          untracked.
 *
 *          One definition rather than one per benchmark, for the bench_gate.hpp reason: drifted copies are
 *          exactly what the result parser cannot catch. Define DMK_BENCH_COUNT_ALLOCATIONS in the single TU
 *          of a benchmark executable before including this header to emit the replacement definitions there.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <malloc.h>
#include <new>

namespace dmk_alloc
{
    inline std::atomic<std::uint64_t> g_alloc_calls{0};
    inline std::atomic<std::uint64_t> g_alloc_bytes{0};
    inline std::atomic<std::uint64_t> g_free_bytes{0};
    /// Monotonic high-water of net live bytes; reset_peak() rebases it for a measurement window.
    inline std::atomic<std::uint64_t> g_peak_live_bytes{0};

    struct AlignedSlot
    {
        std::atomic<void *> pointer{nullptr};
        std::atomic<std::uint64_t> size{0};
    };
    inline constexpr std::size_t ALIGNED_SLOTS = 256;
    inline AlignedSlot g_aligned_slots[ALIGNED_SLOTS];

    /**
     * @brief Net live C++ heap bytes as seen by the counting allocator, clamped at zero.
     * @details A pointer allocated by a runtime DLL's uncounted operator new and freed through the
     *          executable's counted delete raises the free counter without a matching allocation, and a
     *          wrapped difference would poison the peak tracking.
     */
    inline std::uint64_t live_bytes() noexcept
    {
        const std::uint64_t allocated = g_alloc_bytes.load(std::memory_order_relaxed);
        const std::uint64_t freed = g_free_bytes.load(std::memory_order_relaxed);
        return allocated > freed ? allocated - freed : 0;
    }

    /// Rebases the high-water to the current live figure. Call only while no other thread allocates.
    inline void reset_peak() noexcept
    {
        g_peak_live_bytes.store(live_bytes(), std::memory_order_relaxed);
    }

    inline std::uint64_t peak_live_bytes() noexcept
    {
        return g_peak_live_bytes.load(std::memory_order_relaxed);
    }

    inline void note_alloc_bytes(std::uint64_t bytes) noexcept
    {
        g_alloc_calls.fetch_add(1, std::memory_order_relaxed);
        g_alloc_bytes.fetch_add(bytes, std::memory_order_relaxed);
        const std::uint64_t live = live_bytes();
        std::uint64_t peak = g_peak_live_bytes.load(std::memory_order_relaxed);
        while (live > peak && !g_peak_live_bytes.compare_exchange_weak(peak, live, std::memory_order_relaxed))
        {
        }
    }

    inline void *allocate_plain(std::size_t size) noexcept
    {
        void *p = std::malloc(size ? size : 1);
        if (p == nullptr)
        {
            return nullptr;
        }
        note_alloc_bytes(_msize(p));
        return p;
    }

    inline void deallocate_plain(void *p) noexcept
    {
        if (p == nullptr)
        {
            return;
        }
        g_free_bytes.fetch_add(_msize(p), std::memory_order_relaxed);
        std::free(p);
    }

    inline void *allocate_aligned(std::size_t size, std::size_t alignment) noexcept
    {
        void *p = _aligned_malloc(size ? size : 1, alignment);
        if (p == nullptr)
        {
            return nullptr;
        }
        note_alloc_bytes(size);
        for (AlignedSlot &slot : g_aligned_slots)
        {
            void *expected = nullptr;
            if (slot.pointer.compare_exchange_strong(expected, p, std::memory_order_acq_rel))
            {
                slot.size.store(size, std::memory_order_release);
                return p;
            }
        }
        // Table full: the allocation stays counted and its eventual free is uncounted; the footprint phases
        // are single-threaded over a handful of aligned allocations, so this path is not expected to run.
        return p;
    }

    inline void deallocate_aligned(void *p) noexcept
    {
        if (p == nullptr)
        {
            return;
        }
        for (AlignedSlot &slot : g_aligned_slots)
        {
            if (slot.pointer.load(std::memory_order_acquire) == p)
            {
                g_free_bytes.fetch_add(slot.size.load(std::memory_order_acquire), std::memory_order_relaxed);
                slot.pointer.store(nullptr, std::memory_order_release);
                break;
            }
        }
        _aligned_free(p);
    }
} // namespace dmk_alloc

#if defined(DMK_BENCH_COUNT_ALLOCATIONS)

void *operator new(std::size_t size)
{
    void *p = dmk_alloc::allocate_plain(size);
    if (p == nullptr)
    {
        throw std::bad_alloc{};
    }
    return p;
}

void *operator new[](std::size_t size)
{
    return ::operator new(size);
}

void *operator new(std::size_t size, std::align_val_t alignment)
{
    void *p = dmk_alloc::allocate_aligned(size, static_cast<std::size_t>(alignment));
    if (p == nullptr)
    {
        throw std::bad_alloc{};
    }
    return p;
}

void *operator new[](std::size_t size, std::align_val_t alignment)
{
    return ::operator new(size, alignment);
}

void *operator new(std::size_t size, const std::nothrow_t &) noexcept
{
    return dmk_alloc::allocate_plain(size);
}

void *operator new[](std::size_t size, const std::nothrow_t &) noexcept
{
    return dmk_alloc::allocate_plain(size);
}

void *operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept
{
    return dmk_alloc::allocate_aligned(size, static_cast<std::size_t>(alignment));
}

void *operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept
{
    return dmk_alloc::allocate_aligned(size, static_cast<std::size_t>(alignment));
}

void operator delete(void *p) noexcept
{
    dmk_alloc::deallocate_plain(p);
}
void operator delete[](void *p) noexcept
{
    dmk_alloc::deallocate_plain(p);
}
void operator delete(void *p, std::size_t) noexcept
{
    dmk_alloc::deallocate_plain(p);
}
void operator delete[](void *p, std::size_t) noexcept
{
    dmk_alloc::deallocate_plain(p);
}
void operator delete(void *p, std::align_val_t) noexcept
{
    dmk_alloc::deallocate_aligned(p);
}
void operator delete[](void *p, std::align_val_t) noexcept
{
    dmk_alloc::deallocate_aligned(p);
}
void operator delete(void *p, std::size_t, std::align_val_t) noexcept
{
    dmk_alloc::deallocate_aligned(p);
}
void operator delete[](void *p, std::size_t, std::align_val_t) noexcept
{
    dmk_alloc::deallocate_aligned(p);
}
void operator delete(void *p, const std::nothrow_t &) noexcept
{
    dmk_alloc::deallocate_plain(p);
}
void operator delete[](void *p, const std::nothrow_t &) noexcept
{
    dmk_alloc::deallocate_plain(p);
}
void operator delete(void *p, std::align_val_t, const std::nothrow_t &) noexcept
{
    dmk_alloc::deallocate_aligned(p);
}
void operator delete[](void *p, std::align_val_t, const std::nothrow_t &) noexcept
{
    dmk_alloc::deallocate_aligned(p);
}

#endif // DMK_BENCH_COUNT_ALLOCATIONS

#endif // DETOURMODKIT_TESTS_BENCH_ALLOC_HPP
