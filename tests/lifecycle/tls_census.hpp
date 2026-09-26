#ifndef DETOURMODKIT_TESTS_LIFECYCLE_TLS_CENSUS_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_TLS_CENSUS_HPP

#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>

/**
 * @file tls_census.hpp
 * @brief Read-only census of the process Win32 TLS bitmaps for raw lifecycle hosts.
 */

namespace dmk_lifecycle
{
    /**
     * @brief Counts the clear bits of the process TLS bitmaps under the PEB lock.
     * @details The census allocates no index, so a concurrent TlsAlloc in another thread never fails because of it.
     *          Offsets 0x78 and 0x238 of the Windows x64 PEB hold TlsBitmap and TlsExpansionBitmap.
     * @return Zero when ntdll exports no PEB lock, which fails the census.
     */
    inline std::size_t free_tls_indices() noexcept
    {
        struct TlsBitmap
        {
            ULONG size;
            const ULONG *bits;
        };
        using PebLockFn = void(NTAPI *)();
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto acquire =
            reinterpret_cast<PebLockFn>(reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlAcquirePebLock")));
        const auto release =
            reinterpret_cast<PebLockFn>(reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlReleasePebLock")));
        if (acquire == nullptr || release == nullptr)
            return 0;
        const auto *const peb = reinterpret_cast<const std::uint8_t *>(NtCurrentTeb()->ProcessEnvironmentBlock);
        std::size_t count = 0;
        acquire();
        for (const std::size_t offset : {std::size_t{0x78}, std::size_t{0x238}})
        {
            const auto *const bitmap = *reinterpret_cast<const TlsBitmap *const *>(peb + offset);
            for (ULONG bit = 0; bit < bitmap->size; ++bit)
                count += ((bitmap->bits[bit / 32] >> (bit % 32)) & 1U) == 0 ? 1 : 0;
        }
        release();
        return count;
    }
} // namespace dmk_lifecycle

#endif // DETOURMODKIT_TESTS_LIFECYCLE_TLS_CENSUS_HPP
