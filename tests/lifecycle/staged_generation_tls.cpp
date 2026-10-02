#include "staged_generation_tls.hpp"

#include <windows.h>

namespace
{
    constinit staged_gen::TlsLedger s_local;
    constinit std::atomic<staged_gen::TlsLedger *> s_host_ledger{nullptr};

    void claim(staged_gen::TlsLedger &ledger, DWORD index) noexcept
    {
        if (index >= ledger.owned.size() || ledger.owned[index].exchange(true, std::memory_order_relaxed))
        {
            ledger.invalid.store(true, std::memory_order_relaxed);
            return;
        }
        ledger.live.fetch_add(1, std::memory_order_relaxed);
    }

    void release(staged_gen::TlsLedger &ledger, DWORD index) noexcept
    {
        if (index >= ledger.owned.size() || !ledger.owned[index].exchange(false, std::memory_order_relaxed))
        {
            ledger.invalid.store(true, std::memory_order_relaxed);
            return;
        }
        ledger.live.fetch_sub(1, std::memory_order_relaxed);
    }

    DWORD WINAPI allocate_tls() noexcept
    {
        using AllocateFn = DWORD(WINAPI *)();
        static const auto allocate = reinterpret_cast<AllocateFn>(
            reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TlsAlloc"))
        );
        const DWORD index = allocate();
        if (index != TLS_OUT_OF_INDEXES)
        {
            claim(s_local, index);
            if (auto *const host = s_host_ledger.load(std::memory_order_acquire))
            {
                claim(*host, index);
                if (s_local.invalid.load(std::memory_order_relaxed))
                    host->invalid.store(true, std::memory_order_relaxed);
            }
        }
        return index;
    }

    BOOL WINAPI free_tls(DWORD index) noexcept
    {
        using FreeFn = BOOL(WINAPI *)(DWORD);
        static const auto free_index = reinterpret_cast<FreeFn>(
            reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TlsFree"))
        );
        const BOOL result = free_index(index);
        if (result != FALSE)
        {
            release(s_local, index);
            if (auto *const host = s_host_ledger.load(std::memory_order_acquire))
            {
                release(*host, index);
                if (s_local.invalid.load(std::memory_order_relaxed))
                    host->invalid.store(true, std::memory_order_relaxed);
            }
        }
        return result;
    }
} // namespace

extern "C"
{
    // Resolve these import cells locally so archive calls pass through the fixture without a runtime code patch.
    decltype(&TlsAlloc) __imp_TlsAlloc = &allocate_tls;
    decltype(&TlsFree) __imp_TlsFree = &free_tls;

    /**
     * @brief Implements the fixture's host ledger transfer before Init.
     */
    __declspec(dllexport) void dmk_staged_bind_tls_ledger(staged_gen::TlsLedger *host) noexcept
    {
        for (std::size_t i = 0; i < s_local.owned.size(); ++i)
        {
            if (s_local.owned[i].load(std::memory_order_relaxed))
                claim(*host, static_cast<DWORD>(i));
        }
        if (s_local.invalid.load(std::memory_order_relaxed))
            host->invalid.store(true, std::memory_order_relaxed);
        s_host_ledger.store(host, std::memory_order_release);
    }
} // extern "C"

namespace
{
    // This negative control allocates before the host can bind the ledger and outlives the image.
    [[maybe_unused]] const bool s_load_leak = []() noexcept -> bool
    {
        if (GetEnvironmentVariableW(L"DMK_STAGED_GENERATION_LEAK_TLS", nullptr, 0) == 0)
            return false;
        return TlsAlloc() != TLS_OUT_OF_INDEXES;
    }();
} // namespace
