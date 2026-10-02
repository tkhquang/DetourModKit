#ifndef DETOURMODKIT_TESTS_LIFECYCLE_TLS_CENSUS_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_TLS_CENSUS_HPP

#include <windows.h>
#include <winternl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>

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
     * @param allocated Optional storage for the current allocation state of each Win32 TLS index.
     * @return Zero when an ntdll export is unavailable or the bitmaps exceed the optional storage.
     */
    inline std::size_t free_tls_indices(std::array<bool, 1088> *allocated = nullptr) noexcept
    {
        struct TlsBitmap
        {
            ULONG size;
            const ULONG *bits;
        };
        using PebLockFn = void(NTAPI *)();
        using CurrentPebFn = PEB *(NTAPI *)();
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto acquire =
            reinterpret_cast<PebLockFn>(reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlAcquirePebLock")));
        const auto release =
            reinterpret_cast<PebLockFn>(reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlReleasePebLock")));
        const auto current_peb =
            reinterpret_cast<CurrentPebFn>(reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlGetCurrentPeb")));
        if (acquire == nullptr || release == nullptr || current_peb == nullptr)
            return 0;
        const auto *const peb = reinterpret_cast<const std::uint8_t *>(current_peb());
        std::size_t count = 0;
        std::size_t index_base = 0;
        acquire();
        for (const std::size_t offset : {std::size_t{0x78}, std::size_t{0x238}})
        {
            const auto *const bitmap = *reinterpret_cast<const TlsBitmap *const *>(peb + offset);
            if (allocated != nullptr && index_base + bitmap->size > allocated->size())
            {
                release();
                return 0;
            }
            for (ULONG bit = 0; bit < bitmap->size; ++bit)
            {
                const bool occupied = ((bitmap->bits[bit / 32] >> (bit % 32)) & 1U) != 0;
                count += occupied ? 0 : 1;
                if (allocated != nullptr)
                    (*allocated)[index_base + bit] = occupied;
            }
            index_base += bitmap->size;
        }
        release();
        return count;
    }
} // namespace dmk_lifecycle

#endif // DETOURMODKIT_TESTS_LIFECYCLE_TLS_CENSUS_HPP
