#include "staged_generation_tls.hpp"

#include <windows.h>

namespace
{
    constinit staged_gen::TlsLedger s_local;
    constinit std::atomic<staged_gen::TlsLedger *> s_host_ledger{nullptr};

    DWORD WINAPI allocate_tls() noexcept
    {
        using AllocateFn = DWORD(WINAPI *)();
        const auto allocate = reinterpret_cast<AllocateFn>(
            reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TlsAlloc"))
        );
        auto *const host = s_host_ledger.load(std::memory_order_acquire);
        const staged_gen::TlsLedgerTransaction transaction{host != nullptr ? *host : s_local};
        const DWORD index = allocate();
        if (index != TLS_OUT_OF_INDEXES)
        {
            staged_gen::claim_tls_index(s_local, index);
            if (host != nullptr)
            {
                staged_gen::claim_tls_index(*host, index);
                if (s_local.invalid.load(std::memory_order_relaxed))
                    host->invalid.store(true, std::memory_order_relaxed);
            }
        }
        return index;
    }

    BOOL WINAPI free_tls(DWORD index) noexcept
    {
        using FreeFn = BOOL(WINAPI *)(DWORD);
        const auto free_index = reinterpret_cast<FreeFn>(
            reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TlsFree"))
        );
        auto *const host = s_host_ledger.load(std::memory_order_acquire);
        const staged_gen::TlsLedgerTransaction transaction{host != nullptr ? *host : s_local};
        const BOOL result = free_index(index);
        if (result != FALSE)
        {
            staged_gen::release_tls_index(s_local, index);
            if (host != nullptr)
            {
                staged_gen::release_tls_index(*host, index);
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
        const staged_gen::TlsLedgerTransaction transaction{*host};
        for (std::size_t i = 0; i < s_local.owned.size(); ++i)
        {
            if (s_local.owned[i].load(std::memory_order_relaxed))
                staged_gen::claim_tls_index(*host, i);
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
