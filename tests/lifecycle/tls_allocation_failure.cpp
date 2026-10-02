#include "tls_allocation_failure.hpp"

#include <windows.h>

#include <atomic>

namespace
{
    constinit std::atomic<bool> s_refuse_allocation{false};

    DWORD native_allocate_tls() noexcept
    {
        using AllocateFn = DWORD(WINAPI *)();
        // The static MinGW runtime can allocate TLS inside a local static guard.
        const auto allocate = reinterpret_cast<AllocateFn>(
            reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TlsAlloc"))
        );
        return allocate();
    }

    DWORD WINAPI allocate_tls() noexcept
    {
        if (s_refuse_allocation.load(std::memory_order_acquire))
        {
            SetLastError(ERROR_NO_MORE_ITEMS);
            return TLS_OUT_OF_INDEXES;
        }
        return native_allocate_tls();
    }

    DWORD WINAPI native_thread_probe(void *) noexcept
    {
        // Late system initialization must retain TLS access during the proof's failure window.
        const HMODULE core = LoadLibraryExW(L"CoreMessaging.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (core == nullptr)
            return 1;
        const DWORD index = native_allocate_tls();
        if (index == TLS_OUT_OF_INDEXES)
        {
            (void)FreeLibrary(core);
            return 2;
        }
        int marker = 0;
        const bool stored = TlsSetValue(index, &marker) != FALSE && TlsGetValue(index) == &marker;
        const bool freed = TlsFree(index) != FALSE;
        const bool unloaded = FreeLibrary(core) != FALSE;
        return stored && freed && unloaded ? 0 : 3;
    }
} // namespace

extern "C"
{
    // Only calls linked into this executable use the refusal wrapper.
    decltype(&TlsAlloc) __imp_TlsAlloc = &allocate_tls;
} // extern "C"

namespace dmk_lifecycle
{
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
