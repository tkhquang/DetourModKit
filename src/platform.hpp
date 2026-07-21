#ifndef DETOURMODKIT_PLATFORM_HPP
#define DETOURMODKIT_PLATFORM_HPP

#include <windows.h>

namespace DetourModKit::detail
{
    /**
     * @brief Checks if the current thread holds the Windows loader lock.
     * @details Reads the loader-lock CRITICAL_SECTION pointer from the PEB at the architecture-specific offset (0x110
     *          on x64, 0xA0 on x86), then compares its OwningThread to the current thread id. Thread joins are unsafe
     *          while the loader lock is held (DllMain context), so this probe supplies the veto half of
     *          detail::blocking_teardown_permitted(), which every subsystem teardown reads.
     * @note The result is fail-safe. If the PEB or the loader-lock pointer cannot be read, or the pointer does not
     *       resolve to committed, readable memory (e.g. a future or foreign PEB layout shifted the offset), the
     *       function assumes the lock IS held and returns true. A spurious true only leaks a detached thread (bounded,
     *       with the thread's module reference held); a spurious false would join a thread under the loader lock and
     *       deadlock the host on unload, so uncertainty must bias toward true.
     * @note This is a fail-closed diagnostic only. A true or indeterminate result may veto a join, but a false result
     *       never authorizes blocking teardown; that permission comes from the explicit loader context or from the
     *       caller being the bootstrap worker (see detail::teardown_caller_authorized).
     * @return true if the current thread holds the loader lock, or if ownership cannot be determined.
     */
    [[nodiscard]] inline bool is_loader_lock_held_impl() noexcept
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
        // LOADER_LOCK_OFFSET (foreign or future PEB layout) would otherwise read a bogus pointer and fault the host.
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

#if defined(DMK_ENABLE_TEST_SEAMS)
    // Forces the probe's verdict so a proof can drive the "heuristic disagrees with the explicit context" case in both
    // directions, which is the only way to show a false result never authorizes blocking teardown on its own. Defined
    // in src/internal/lifecycle_context.cpp; set before the participating threads start and cleared after they join.
    extern bool (*g_loader_lock_override)() noexcept;
#endif

    /// Returns @ref is_loader_lock_held_impl, or the forced verdict when a test seam has overridden the probe.
    [[nodiscard]] inline bool is_loader_lock_held() noexcept
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        if (auto *const override_fn = g_loader_lock_override)
        {
            return override_fn();
        }
#endif
        return is_loader_lock_held_impl();
    }

    /**
     * @brief Tries to take a counted reference on the module DetourModKit is linked into.
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
     * @return The module handle to pass to a matching release, or nullptr without diagnostics when the reference could
     *         not be taken.
     */
    [[nodiscard]] inline HMODULE try_acquire_module_ref() noexcept
    {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                reinterpret_cast<LPCWSTR>(&try_acquire_module_ref), &module))
        {
            return nullptr;
        }
        return module;
    }

    /**
     * @brief @ref try_acquire_module_ref with a debugger diagnostic on failure.
     * @details Same acquisition contract, including the requirement to take the reference while the module is still
     *          fully loaded. Use this wherever a failure is worth reporting; use the plain try form on a path that must
     *          stay silent, such as bootstrap under the loader lock.
     * @return The module handle, which the holder must balance with @ref release_module_ref (or, for a thread
     *         releasing its own reference as its final act, FreeLibraryAndExitThread); nullptr on failure, with
     *         GetLastError() preserved across the diagnostic.
     */
    [[nodiscard]] inline HMODULE acquire_module_ref() noexcept
    {
        const HMODULE module = try_acquire_module_ref();
        if (module == nullptr)
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
