/**
 * @file test_profiler_late_uaf.cpp
 * @brief Late-teardown use-after-free proof for the Profiler singleton.
 *
 * @details Profiler::get_instance() is a placement-new-into-static-storage singleton that is never destroyed, so a
 *          ScopedProfile whose destructor runs at static-teardown time can still call record() safely. A function-local
 *          ordinary static would register a destructor that frees the ring buffer during teardown; any later record()
 *          would write into freed memory during DLL unload or process exit.
 *
 *          The proof does not depend on a sanitizer. This translation unit replaces the global allocation operators
 *          with a size-targeted poisoning allocator. The profiler's fixed 2 MiB ring buffer is the only allocation
 *          above POISON_THRESHOLD, so only that buffer is served from a dedicated VirtualAlloc region; when it is
 *          freed, the region is flipped to PAGE_NOACCESS and leaked rather than released, so its address cannot be
 *          recycled and any later access faults immediately instead of silently touching still-committed freed heap.
 *
 *          The ordering is arranged so a record() runs AFTER the profiler would have been destroyed. A namespace-scope
 *          LateRecorder is initialized before main first touches the profiler, so its destructor is registered ahead of
 *          the profiler singleton's would-be destructor and therefore runs after it at exit. That is the exact ordering
 *          the implementation must survive: a scoped profile outliving ordinary static teardown. The proof's signal is
 *          the process exit code: with the never-destroyed singleton, the late record() writes into live memory and the
 *          process exits 0; with an ordinary function-local static singleton, the late record() writes into the
 *          poisoned PAGE_NOACCESS region and the process exits with an access violation.
 *
 *          Built and run by scripts/run_lifecycle_proofs.sh, which compiles src/profiler.cpp directly (the profiler
 *          depends only on <windows.h> and the standard library), so no library archive or test framework is involved.
 */

#include "DetourModKit/profiler.hpp"

#include <windows.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>

namespace
{
    // The profiler ring buffer is DEFAULT_CAPACITY (65536) * sizeof(ProfileSample) (32) = 2 MiB. One mebibyte is well
    // above any incidental allocation this tiny driver makes and comfortably below the ring buffer, so the threshold
    // isolates exactly the profiler buffer for poisoning; everything else goes to the ordinary heap.
    constexpr std::size_t POISON_THRESHOLD = 0x100000; // 1 MiB

    // A fixed, allocation-free registry of the large regions served from VirtualAlloc. A single run makes exactly one
    // such allocation (the ring buffer); a few slots is ample. It must never call into operator new itself, so it is a
    // plain aggregate with constant (zero) initialization, which guarantees it is ready before the first allocation of
    // static initialization.
    struct PoisonRegistry
    {
        static constexpr int MAX_REGIONS = 8;
        void *bases[MAX_REGIONS];
        std::size_t sizes[MAX_REGIONS];
        int count;

        void track(void *base, std::size_t size) noexcept
        {
            if (count < MAX_REGIONS)
            {
                bases[count] = base;
                sizes[count] = size;
                ++count;
            }
        }

        // Returns the index of the region beginning at @p p, or -1 if @p p was not served from VirtualAlloc.
        [[nodiscard]] int index_of(const void *p) const noexcept
        {
            for (int i = 0; i < count; ++i)
            {
                if (bases[i] == p)
                {
                    return i;
                }
            }
            return -1;
        }
    };

    PoisonRegistry s_regions{};

    void *tracked_alloc(std::size_t size)
    {
        if (size >= POISON_THRESHOLD)
        {
            // Serve the large ring buffer from its own committed region so freeing it can poison exactly those pages.
            void *region = ::VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (region != nullptr)
            {
                s_regions.track(region, size);
                return region;
            }
            throw std::bad_alloc{};
        }
        void *p = std::malloc(size != 0 ? size : 1);
        if (p == nullptr)
        {
            throw std::bad_alloc{};
        }
        return p;
    }

    void tracked_free(void *p) noexcept
    {
        if (p == nullptr)
        {
            return;
        }
        const int i = s_regions.index_of(p);
        if (i >= 0)
        {
            // Poison rather than release: flip the region to PAGE_NOACCESS and leak the address so it cannot be
            // recycled. A later read or write (the use-after-free) then faults deterministically. The size comes from
            // the region table, so it is correct regardless of which delete overload the runtime selected.
            DWORD previous = 0;
            if (::VirtualProtect(s_regions.bases[i], s_regions.sizes[i], PAGE_NOACCESS, &previous) == FALSE)
            {
                std::fprintf(stderr, "profiler-late-uaf: VirtualProtect(PAGE_NOACCESS) failed (error %lu)\n",
                             GetLastError());
                std::abort();
            }
            return;
        }
        std::free(p);
    }
} // namespace

// Replace the global allocation operators for the whole program. The profiler ring allocates with nothrow array new,
// so both forms are replaced here and the ring buffer lands in the poisoning region either way.
void *operator new(std::size_t size)
{
    return tracked_alloc(size);
}
void *operator new[](std::size_t size)
{
    return tracked_alloc(size);
}
void *operator new(std::size_t size, const std::nothrow_t &) noexcept
{
    if (size >= POISON_THRESHOLD)
    {
        void *region = ::VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (region != nullptr)
        {
            s_regions.track(region, size);
        }
        return region;
    }
    return std::malloc(size != 0 ? size : 1);
}
void *operator new[](std::size_t size, const std::nothrow_t &tag) noexcept
{
    return ::operator new(size, tag);
}
void operator delete(void *p, const std::nothrow_t &) noexcept
{
    tracked_free(p);
}
void operator delete[](void *p, const std::nothrow_t &) noexcept
{
    tracked_free(p);
}
void operator delete(void *p) noexcept
{
    tracked_free(p);
}
void operator delete[](void *p) noexcept
{
    tracked_free(p);
}
// Sized deallocation (C++14 onward, enabled by default) can be selected instead of the unsized forms; forward it so
// poisoning is never bypassed. The size argument is ignored because the true size is looked up from the region table.
void operator delete(void *p, std::size_t) noexcept
{
    tracked_free(p);
}
void operator delete[](void *p, std::size_t) noexcept
{
    tracked_free(p);
}

namespace
{
    /**
     * @brief A record() call staged to run at static-teardown time.
     * @details The single s_late_recorder instance is initialized before main first touches the profiler, so its
     *          destructor is registered ahead of the profiler singleton's would-be destructor and therefore runs AFTER
     *          the profiler teardown. That is the exact ordering the implementation must survive: a scoped profile
     *          outliving the profiler.
     */
    struct LateRecorder
    {
        ~LateRecorder() noexcept
        {
            // With the never-destroyed singleton this dereferences the live ring buffer and returns. With an ordinary
            // function-local static singleton, the buffer has already been freed and poisoned by the profiler's static
            // destructor, so this write faults.
            DetourModKit::Profiler::get_instance().record("late_teardown_sample", 0, 100, 0);
        }
    };

    LateRecorder s_late_recorder;
} // namespace

int main()
{
    // First touch of the profiler: constructs the singleton (allocating the 2 MiB ring buffer through the poisoning
    // allocator) and, for an ordinary function-local static singleton, registers its static destructor now, after
    // s_late_recorder's destructor was already registered. Record one sample so the buffer is demonstrably live.
    DetourModKit::Profiler &profiler = DetourModKit::Profiler::get_instance();
    profiler.record("main_sample", 0, 100, 0);

    // The proof has teeth only if the ring buffer actually landed in a poisoning region: otherwise the late record()
    // writes into ordinary (still-committed) heap and can never fault, so exit 0 would be a vacuous pass. Fail the
    // setup outright instead, e.g. if the buffer ever routes through an allocation path these operators do not
    // replace (such as aligned operator new for an over-aligned ProfileSample).
    if (s_regions.count == 0)
    {
        std::fprintf(stderr, "profiler-late-uaf: FAIL: the ring buffer was not served from the poisoning region, so a "
                             "use-after-free cannot fault and the proof is vacuous\n");
        return 2;
    }

    std::printf("profiler-late-uaf: recorded %zu sample(s); ring buffer = %zu bytes served from the poisoning region\n",
                profiler.available_samples(), s_regions.sizes[0]);
    std::printf("profiler-late-uaf: main returning; the verdict is the exit code after the late teardown record\n");

    // The exit code is the proof: 0 means the late teardown record() did not fault against freed storage.
    return 0;
}
