#include "tls_allocation_failure.hpp"

#include "staged_generation_tls.hpp"

#include <windows.h>

#include <atomic>

namespace
{
    constinit std::atomic<bool> s_refuse_allocation{false};
    constinit staged_gen::TlsLedger s_allocations;

    using AllocateFn = DWORD(WINAPI *)();
    using FreeFn = BOOL(WINAPI *)(DWORD);

    AllocateFn native_allocator() noexcept
    {
        // The static MinGW runtime can allocate TLS inside a local static guard.
        return reinterpret_cast<AllocateFn>(
            reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TlsAlloc"))
        );
    }

    DWORD WINAPI allocate_tls() noexcept
    {
        if (s_refuse_allocation.load(std::memory_order_acquire))
        {
            SetLastError(ERROR_NO_MORE_ITEMS);
            return TLS_OUT_OF_INDEXES;
        }
        const auto allocate = native_allocator();
        const staged_gen::TlsLedgerTransaction transaction{s_allocations};
        const DWORD index = allocate();
        if (index != TLS_OUT_OF_INDEXES)
            staged_gen::claim_tls_index(s_allocations, index);
        return index;
    }

    FreeFn native_deallocator() noexcept
    {
        return reinterpret_cast<FreeFn>(
            reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TlsFree"))
        );
    }

    BOOL WINAPI free_tls(DWORD index) noexcept
    {
        const auto free_index = native_deallocator();
        const staged_gen::TlsLedgerTransaction transaction{s_allocations};
        const BOOL result = free_index(index);
        if (result != FALSE)
            staged_gen::release_tls_index(s_allocations, index);
        return result;
    }

    DWORD WINAPI native_thread_probe(void *) noexcept
    {
        // Late system initialization must retain TLS access during the proof's failure window.
        const HMODULE core = LoadLibraryExW(L"CoreMessaging.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (core == nullptr)
            return 1;
        dmk_lifecycle::NativeTlsOwner owner;
        if (!owner.reserved())
        {
            (void)FreeLibrary(core);
            return 2;
        }
        int marker = 0;
        const bool stored = TlsSetValue(owner.index(), &marker) != FALSE && TlsGetValue(owner.index()) == &marker;
        const bool freed = owner.reset();
        const bool unloaded = FreeLibrary(core) != FALSE;
        return stored && freed && unloaded ? 0 : 3;
    }
} // namespace

extern "C"
{
    // Only calls linked into this executable use the refusal wrapper.
    decltype(&TlsAlloc) __imp_TlsAlloc = &allocate_tls;
    decltype(&TlsFree) __imp_TlsFree = &free_tls;
} // extern "C"

namespace dmk_lifecycle
{
    TlsAllocationSnapshot tls_allocation_snapshot() noexcept
    {
        const staged_gen::TlsLedgerTransaction transaction{s_allocations};
        return {
            .live = s_allocations.live.load(std::memory_order_relaxed),
            .allocations = s_allocations.allocations.load(std::memory_order_relaxed),
            .frees = s_allocations.frees.load(std::memory_order_relaxed),
            .valid = !s_allocations.invalid.load(std::memory_order_relaxed),
        };
    }

    bool tls_index_is_owned(std::uint32_t index) noexcept
    {
        const staged_gen::TlsLedgerTransaction transaction{s_allocations};
        return index < s_allocations.owned.size() && s_allocations.owned[index].load(std::memory_order_relaxed);
    }

    NativeTlsOwner::NativeTlsOwner() noexcept : m_index{static_cast<std::uint32_t>(native_allocator()())} {}

    NativeTlsOwner::~NativeTlsOwner() noexcept
    {
        (void)reset();
    }

    bool NativeTlsOwner::reserved() const noexcept
    {
        return m_index != TLS_OUT_OF_INDEXES;
    }

    std::uint32_t NativeTlsOwner::index() const noexcept
    {
        return m_index;
    }

    bool NativeTlsOwner::reset() noexcept
    {
        if (!reserved())
            return true;
        if (native_deallocator()(m_index) == FALSE)
            return false;
        m_index = TLS_OUT_OF_INDEXES;
        return true;
    }

    TlsAllocationFailure::TlsAllocationFailure() noexcept
    {
        s_refuse_allocation.store(true, std::memory_order_release);
    }

    TlsAllocationFailure::~TlsAllocationFailure() noexcept
    {
        restore();
    }

    bool TlsAllocationFailure::isolated() const noexcept
    {
        const DWORD unexpected = TlsAlloc();
        if (unexpected != TLS_OUT_OF_INDEXES)
        {
            (void)TlsFree(unexpected);
            return false;
        }
        const HANDLE thread = CreateThread(nullptr, 0, &native_thread_probe, nullptr, 0, nullptr);
        if (thread == nullptr)
            return false;
        const DWORD wait = WaitForSingleObject(thread, 10'000);
        DWORD status = 4;
        const bool completed = wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &status) != FALSE;
        (void)CloseHandle(thread);
        return completed && status == 0;
    }

    void TlsAllocationFailure::restore() noexcept
    {
        s_refuse_allocation.store(false, std::memory_order_release);
    }
} // namespace dmk_lifecycle
