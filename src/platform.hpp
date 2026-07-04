#ifndef DETOURMODKIT_PLATFORM_HPP
#define DETOURMODKIT_PLATFORM_HPP

#include <windows.h>

namespace DetourModKit::detail
{
    /**
     * @brief Checks if the current thread holds the Windows loader lock.
     * @details Reads the loader-lock CRITICAL_SECTION pointer from the PEB at a well-known offset (0x110 on x64, 0xA0
     *          on x86) that has been stable from Windows XP through 11, then compares its OwningThread to the current
     *          thread id. Thread joins are unsafe while the loader lock is held (DllMain context), so this gate decides
     *          detach-vs-join across every subsystem teardown.
     * @note The result is fail-safe. If the PEB or the loader-lock pointer cannot be read, or the pointer does not
     *       resolve to committed, readable memory (e.g. a future or foreign PEB layout shifted the offset), the
     *       function assumes the lock IS held and returns true. A spurious true only leaks a detached thread (bounded,
     *       with the thread's module reference held); a spurious false would join a thread under the loader lock and
     *       deadlock the host on unload, so uncertainty must bias toward true.
     * @return true if the current thread holds the loader lock, or if ownership cannot be determined.
     */
    [[nodiscard]] inline bool is_loader_lock_held() noexcept
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

        // Confirm the critical section lives in committed, readable memory before dereferencing OwningThread. A wrong
        // LOADER_LOCK_OFFSET (foreign or future
        // PEB layout) would otherwise read a bogus pointer and fault the host.
        constexpr DWORD READABLE_PROTECT = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(cs, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT ||
            (mbi.Protect & READABLE_PROTECT) == 0 || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
        {
            return true;
        }

        return cs->OwningThread == reinterpret_cast<HANDLE>(static_cast<uintptr_t>(GetCurrentThreadId()));
    }

    /**
     * @brief Takes a counted reference on the module DetourModKit is linked into, keeping it mapped while a background
     *        thread runs its code.
     * @details Bumps the module's loader reference count by one, the "bonus LoadLibrary on yourself" a DLL performs so
     *          it cannot be unmapped while it still has code running. The reference is counted, not pinned: a matching
     *          @ref release_module_ref (or a thread's FreeLibraryAndExitThread) balances it, so the module can still
     *          unload once every holder releases -- unlike a GET_MODULE_HANDLE_EX_FLAG_PIN reference, which pins the
     *          module for the process lifetime and can never be released. A pin is also useless from a detach path (the
     *          loader refuses to pin a module that is already unloading), which is why this counted reference, taken
     *          while the module is live, is the correct primitive.
     *
     *          The reference MUST be taken while the module is still fully loaded -- before a background thread is
     *          created, or before a hook/callback is published -- and NEVER from a DLL_PROCESS_DETACH/unload path. Once
     *          an explicit FreeLibrary has driven the count to zero the loader has already committed to unmapping the
     *          module, and a reference requested at that point does not abort the in-progress unload (GetModuleHandleEx
     *          cannot find a module that is unloading). A thread that needs its code to survive a caller's FreeLibrary
     *          therefore acquires this reference before the thread can run, not when it is told to stop.
     *
     *          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS identifies the module from a code address; omitting
     *          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT is what makes the call take a reference (its default,
     *          count-incrementing behavior) rather than a bare identity lookup.
     * @return The module handle to pass to a matching release, or nullptr if the reference could not be taken.
     */
    [[nodiscard]] inline HMODULE acquire_module_ref() noexcept
    {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&acquire_module_ref),
                                &module))
        {
            // Preserve the failure code across the debug print: OutputDebugStringA may overwrite the thread's
            // last-error value, and callers report GetLastError() after this returns nullptr.
            const DWORD last_error = GetLastError();
            OutputDebugStringA("DetourModKit: acquire_module_ref failed; a background thread's code may be unmapped by "
                               "a caller's FreeLibrary.\n");
            SetLastError(last_error);
            return nullptr;
        }
        return module;
    }

    /**
     * @brief Releases a counted reference taken by @ref acquire_module_ref, from a thread OTHER than the one whose code
     *        the release might unmap.
     * @details Call this after a background thread has been JOINED (its code is done running) to balance the
     *          start-of-thread acquire, so the module is no longer held mapped on this account. It is safe only as long
     *          as another reference on the module still exists -- the host's own load reference, or another live
     *          worker's -- so it can never be the terminal release that unmaps the module out from under the caller,
     *          which is still executing this module's code. A background thread must NOT release its OWN reference this
     *          way as its final act: it uses FreeLibraryAndExitThread so the FreeLibrary's return address is never in
     *          code the release just unmapped.
     * @param module A handle returned by @ref acquire_module_ref; nullptr is ignored.
     */
    inline void release_module_ref(HMODULE module) noexcept
    {
        if (module != nullptr)
        {
            FreeLibrary(module);
        }
    }

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_PLATFORM_HPP
