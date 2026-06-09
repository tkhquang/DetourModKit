#ifndef DETOURMODKIT_PLATFORM_HPP
#define DETOURMODKIT_PLATFORM_HPP

#include <windows.h>

namespace DetourModKit::detail
{
    /**
     * @brief Checks if the current thread holds the Windows loader lock.
     * @details Reads the loader-lock CRITICAL_SECTION pointer from the PEB at a
     *          well-known offset (0x110 on x64, 0xA0 on x86) that has been stable
     *          from Windows XP through 11, then compares its OwningThread to the
     *          current thread id. Thread joins are unsafe while the loader lock is
     *          held (DllMain context), so this gate decides detach-vs-join across
     *          every subsystem teardown.
     * @note The result is fail-safe. If the PEB or the loader-lock pointer cannot
     *       be read, or the pointer does not resolve to committed, readable memory
     *       (e.g. a future or foreign PEB layout shifted the offset), the function
     *       assumes the lock IS held and returns true. A spurious true only leaks a
     *       detached thread (bounded, with the module pinned); a spurious false
     *       would join a thread under the loader lock and deadlock the host on
     *       unload, so uncertainty must bias toward true.
     * @return true if the current thread holds the loader lock, or if ownership
     *         cannot be determined.
     */
    inline bool is_loader_lock_held() noexcept
    {
#ifdef _WIN64
        auto *peb = reinterpret_cast<char *>(__readgsqword(0x60));
        constexpr size_t LOADER_LOCK_OFFSET = 0x110;
#else
        auto *peb = reinterpret_cast<char *>(__readfsdword(0x30));
        constexpr size_t LOADER_LOCK_OFFSET = 0xA0;
#endif
        if (!peb)
            return true;

        auto *cs = *reinterpret_cast<PCRITICAL_SECTION *>(peb + LOADER_LOCK_OFFSET);
        if (!cs)
            return true;

        // Confirm the critical section lives in committed, readable memory before
        // dereferencing OwningThread. A wrong kLoaderLockOffset (foreign or future
        // PEB layout) would otherwise read a bogus pointer and fault the host.
        constexpr DWORD READABLE_PROTECT =
            PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(cs, &mbi, sizeof(mbi)) != sizeof(mbi) ||
            mbi.State != MEM_COMMIT ||
            (mbi.Protect & READABLE_PROTECT) == 0 ||
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
        {
            return true;
        }

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
