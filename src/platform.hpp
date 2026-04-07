#ifndef DETOURMODKIT_PLATFORM_HPP
#define DETOURMODKIT_PLATFORM_HPP

#include <windows.h>

namespace DetourModKit::detail
{
    /**
     * @brief Checks if the current thread holds the Windows loader lock.
     * @details Uses the PEB LoaderLock critical section at a well-known offset
     *          that has been stable across all Windows versions from XP through 11.
     *          Thread joins are unsafe while the loader lock is held (DllMain context).
     */
    inline bool is_loader_lock_held() noexcept
    {
#ifdef _WIN64
        auto *peb = reinterpret_cast<char *>(__readgsqword(0x60));
        constexpr size_t kLoaderLockOffset = 0x110;
#else
        auto *peb = reinterpret_cast<char *>(__readfsdword(0x30));
        constexpr size_t kLoaderLockOffset = 0xA0;
#endif
        if (!peb)
            return false;

        auto *cs = *reinterpret_cast<PCRITICAL_SECTION *>(peb + kLoaderLockOffset);
        if (!cs)
            return false;

        return cs->OwningThread ==
               reinterpret_cast<HANDLE>(static_cast<uintptr_t>(GetCurrentThreadId()));
    }

    /**
     * @brief Pins the current module to prevent unload while detached threads
     *        are still running.
     * @details Uses GET_MODULE_HANDLE_EX_FLAG_PIN to permanently increment the
     *          module reference count. Safe to call from DllMain. This ensures
     *          that code pages and static data remain valid for detached threads
     *          during the FreeLibrary path.
     * @return true if the module was successfully pinned, false on failure.
     */
    inline bool pin_current_module() noexcept
    {
        HMODULE pin = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(&pin_current_module),
                &pin))
        {
            OutputDebugStringA("DetourModKit: pin_current_module failed; "
                               "detached threads may access unmapped code.\n");
            return false;
        }
        return true;
    }

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_PLATFORM_HPP
