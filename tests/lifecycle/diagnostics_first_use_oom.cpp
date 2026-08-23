// Fresh-process proof that loading a module which links DMK does not depend on a successful allocation, and that the
// hook population reports exact zero state afterwards.
//
// The window this covers is unreachable from an in-process test. DMK's static initializers run inside LoadLibrary,
// before any user bootstrap gets control, and an allocation failure there has no handler: it propagates out of a
// dynamic initializer and kills the load. A test that arms poisoning from main() has already missed it.
//
// One translation unit builds twice. Compiled with DMK_DIAGNOSTICS_OOM_PROBE_DLL it is the probe DLL: it replaces every
// global allocation operator, plain AND over-aligned, with a poison that is CONSTANT-INITIALIZED TO ARMED, so every C++
// allocation attempted while the loader runs this module's initializers fails. Compiled without it, the same file
// is the host that loads the probe and reports the verdict through its exit code.
//
// The aligned operators are a separate overload family, not a spelling of the plain ones, and leaving them at their
// defaults would leave an unpoisoned channel DMK already uses (src/internal/async_logger.cpp allocates its over-aligned
// Block through the nothrow aligned operator new). An initializer that allocated through that channel would be served,
// refuse nothing, and let this proof pass while the defect it exists to catch was present.
//
// The oracle is therefore the loader itself. A DMK that establishes diagnostics state through a dynamic initializer, or
// through an allocating dispatcher subscription, cannot load here at all.
//
// Coverage is the probe's link closure, not the whole archive: DetourModKit links statically, so only the object files
// something references are present to initialize. The probe references both the diagnostics and hook surfaces, which
// is what the population tally spans.

#if defined(DMK_DIAGNOSTICS_OOM_PROBE_DLL)
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#endif

#include <cstddef>

#if defined(DMK_DIAGNOSTICS_OOM_PROBE_DLL)
#include <malloc.h>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <new>
#else
#include <windows.h>

#include <cstdio>
#include <string_view>
#endif

#if defined(DMK_DIAGNOSTICS_OOM_PROBE_DLL)

namespace
{
    // Armed before anything runs. Constant initialization is what puts it ahead of every other initializer in this
    // module, including DMK's: a dynamically initialized flag could itself be sequenced after the code under test.
    constinit std::atomic<bool> s_poison{true};

    // Counts refused allocations. Read after load, this is the assertion itself: DMK must attempt none. An initializer
    // that allocates and swallows the failure would keep the module loadable while still being the defect, and only
    // this counter distinguishes that from a module that never asked for memory.
    constinit std::atomic<unsigned long long> s_refusals{0};
} // namespace

void *operator new(std::size_t size)
{
    if (s_poison.load(std::memory_order_acquire))
    {
        s_refusals.fetch_add(1, std::memory_order_relaxed);
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
    if (s_poison.load(std::memory_order_acquire))
    {
        s_refusals.fetch_add(1, std::memory_order_relaxed);
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

// The over-aligned family is backed by _aligned_malloc / _aligned_free rather than malloc / free, because a block from
// _aligned_malloc must be released through _aligned_free. Both toolchains supply that pair from <malloc.h>. The two
// families must never cross: the compiler only selects an aligned deallocation for a type it allocated through an
// aligned allocation, so keeping each family self-consistent is what makes the pairing correct.

void *operator new(std::size_t size, std::align_val_t alignment)
{
    if (s_poison.load(std::memory_order_acquire))
    {
        s_refusals.fetch_add(1, std::memory_order_relaxed);
        throw std::bad_alloc{};
    }
    if (void *p = ::_aligned_malloc(size != 0 ? size : 1, static_cast<std::size_t>(alignment)))
    {
        return p;
    }
    throw std::bad_alloc{};
}

void *operator new[](std::size_t size, std::align_val_t alignment)
{
    return ::operator new(size, alignment);
}

void *operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept
{
    if (s_poison.load(std::memory_order_acquire))
    {
        s_refusals.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    return ::_aligned_malloc(size != 0 ? size : 1, static_cast<std::size_t>(alignment));
}

void *operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t &tag) noexcept
{
    return ::operator new(size, alignment, tag);
}

void operator delete(void *p, std::align_val_t) noexcept
{
    ::_aligned_free(p);
}

void operator delete[](void *p, std::align_val_t) noexcept
{
    ::_aligned_free(p);
}

void operator delete(void *p, std::size_t, std::align_val_t) noexcept
{
    ::_aligned_free(p);
}

void operator delete[](void *p, std::size_t, std::align_val_t) noexcept
{
    ::_aligned_free(p);
}

void operator delete(void *p, std::align_val_t, const std::nothrow_t &) noexcept
{
    ::_aligned_free(p);
}

void operator delete[](void *p, std::align_val_t, const std::nothrow_t &) noexcept
{
    ::_aligned_free(p);
}

extern "C" __declspec(dllexport) int dmk_diagnostics_probe(
    unsigned long long *refusals,
    std::size_t *total,
    std::size_t *active,
    std::size_t *disabled
) noexcept
{
    // Snapshot the load-time count before the control below adds a refusal of its own.
    const unsigned long long load_refusals = s_refusals.load(std::memory_order_relaxed);

    // DetourModKit is a static archive, so an object file nothing references is never linked into this module and its
    // load-time initialization is never exercised. Referencing the hook surface pulls hook.cpp (which owns the
    // population tally) and its ledger, adapter, and backend dependencies into the poisoned window. The address is
    // taken and never called: calling under the poison would test the call path, not module load.
    const volatile std::uintptr_t hook_tu_anchor =
        reinterpret_cast<std::uintptr_t>(&DetourModKit::hook::is_target_hooked);
    (void)hook_tu_anchor;

    // Positive control, run first and while still poisoned. Without it a module whose operator new replacement never
    // took effect (the one way this proof could pass vacuously) would be indistinguishable from a module that
    // genuinely needed no memory. A refused allocation here is what makes the load-time count below mean something.
    // Both families are exercised, because a replacement that covered only one would leave the other serving load-time
    // allocations silently. The aligned request uses an alignment above __STDCPP_DEFAULT_NEW_ALIGNMENT__ so it
    // genuinely selects the aligned operator rather than folding back onto the plain one.
    bool plain_refused = false;
    try
    {
        void *const probe_block = ::operator new(64);
        ::operator delete(probe_block);
    }
    catch (const std::bad_alloc &)
    {
        plain_refused = true;
    }

    bool aligned_refused = false;
    try
    {
        void *const probe_block = ::operator new(64, std::align_val_t{64});
        ::operator delete(probe_block, std::align_val_t{64});
    }
    catch (const std::bad_alloc &)
    {
        aligned_refused = true;
    }

    if (!plain_refused || !aligned_refused)
    {
        s_poison.store(false, std::memory_order_release);
        return plain_refused ? 2 : 1;
    }

    // Read the population while still poisoned: the tally must be readable with no heap available, because a host that
    // reached this state is exactly the one that needs a diagnostic.
    const DetourModKit::diagnostics::Snapshot snapshot = DetourModKit::diagnostics::collect();
    *refusals = load_refusals;
    *total = snapshot.hooks_total;
    *active = snapshot.hooks_active;
    *disabled = snapshot.hooks_disabled;

    // Release the heap so the loader can unmap this module normally.
    s_poison.store(false, std::memory_order_release);
    return 0;
}

#else

namespace
{
    using ProbeFn = int (*)(unsigned long long *, std::size_t *, std::size_t *, std::size_t *) noexcept;

    int run_poisoned_load()
    {
        const HMODULE probe = ::LoadLibraryA("dmk_diagnostics_oom_probe.dll");
        if (probe == nullptr)
        {
            std::fprintf(
                stderr,
                "FAIL: loading the probe DLL failed with %lu. ERROR_DLL_INIT_FAILED (1114) is the signature "
                "of an allocating DMK initializer propagating out of module load.\n",
                ::GetLastError()
            );
            return 10;
        }

        const auto probe_fn =
            reinterpret_cast<ProbeFn>(reinterpret_cast<void *>(::GetProcAddress(probe, "dmk_diagnostics_probe")));
        if (probe_fn == nullptr)
        {
            std::fprintf(stderr, "FAIL: the probe DLL exported no entry point\n");
            return 11;
        }

        unsigned long long refusals = 0;
        std::size_t total = 0;
        std::size_t active = 0;
        std::size_t disabled = 0;
        const int control = probe_fn(&refusals, &total, &active, &disabled);
        if (control != 0)
        {
            std::fprintf(
                stderr,
                "FAIL: the probe's own %s allocation was served while poisoned, so that operator new "
                "replacement never took effect and this run proves nothing\n",
                control == 2 ? "over-aligned" : "plain"
            );
            return 12;
        }

        if (refusals != 0)
        {
            std::fprintf(
                stderr,
                "FAIL: %llu allocation(s) were attempted and refused while the loader ran this module's "
                "initializers. DMK must reach user code without asking for memory.\n",
                refusals
            );
            return 13;
        }
        if (total != 0 || active != 0 || disabled != 0)
        {
            std::fprintf(
                stderr,
                "FAIL: a freshly loaded module reported a nonzero hook population (total=%zu active=%zu "
                "disabled=%zu)\n",
                total,
                active,
                disabled
            );
            return 14;
        }

        std::printf(
            "diagnostics-first-use-oom: module loaded with the heap poisoned, attempted no allocation, and "
            "reports exact zero population\n"
        );

        if (::FreeLibrary(probe) == 0)
        {
            std::fprintf(stderr, "FAIL: unloading the probe DLL failed with %lu\n", ::GetLastError());
            return 15;
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: diagnostics_first_use_oom <poisoned-load>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == "poisoned-load")
    {
        return run_poisoned_load();
    }

    std::fprintf(stderr, "unknown diagnostics first-use case\n");
    return 1;
}

#endif
