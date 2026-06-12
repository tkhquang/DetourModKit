#include "DetourModKit/bootstrap.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "DetourModKit/config.hpp"
#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger.hpp"

#include <DetourModKit.hpp>

#include <atomic>
#include <cstring>
#include <exception>

namespace DetourModKit::Bootstrap
{
    namespace
    {
        HANDLE s_shutdown_event = nullptr;
        HANDLE s_worker_thread = nullptr;
        HANDLE s_instance_mutex = nullptr;
        HMODULE s_module = nullptr;
        std::atomic<bool> s_detach_called{false};

        std::function<bool()> s_init_fn;
        std::function<void()> s_shutdown_fn;

        bool is_target_process(std::string_view expected) noexcept
        {
            if (expected.empty())
            {
                return true;
            }

            char exe_path[MAX_PATH]{};
            const DWORD len = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
            if (len == 0 || len >= MAX_PATH)
            {
                return false;
            }

            const char *exe_name = std::strrchr(exe_path, '\\');
            exe_name = exe_name ? exe_name + 1 : exe_path;

            // Copy the caller-supplied name into a bounded stack buffer to get a null-terminated string for _stricmp
            // without heap allocation: this helper is noexcept and runs on the bootstrap path, so a throwing allocation
            // would call std::terminate. A name that cannot fit a module file name cannot match the running executable.
            if (expected.size() >= MAX_PATH)
            {
                return false;
            }
            char expected_buf[MAX_PATH];
            std::memcpy(expected_buf, expected.data(), expected.size());
            expected_buf[expected.size()] = '\0';
            return _stricmp(exe_name, expected_buf) == 0;
        }

        bool acquire_instance_mutex(std::string_view prefix) noexcept
        {
            if (prefix.empty())
            {
                return true;
            }

            // Build the name in a std::wstring rather than formatting into a fixed wchar_t buffer: the prefix is
            // caller-supplied, so a bounded formatter would have to truncate or fail, and an unbounded one (wsprintfW)
            // could overflow. CreateMutexW rejects an over-long name on its own, which the null-handle check below
            // already handles. The allocation is wrapped because this helper is noexcept and runs on the bootstrap
            // path; an out-of-memory failure fails closed (no single-instance guard) rather than terminating the
            // process.
            std::wstring mutex_name;
            try
            {
                mutex_name.reserve(prefix.size() + 10);
                for (char c : prefix)
                {
                    mutex_name.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
                }
                mutex_name += std::to_wstring(GetCurrentProcessId());
            }
            catch (...)
            {
                return false;
            }

            HANDLE mutex_handle = CreateMutexW(nullptr, FALSE, mutex_name.c_str());
            if (!mutex_handle)
            {
                return false;
            }
            if (GetLastError() == ERROR_ALREADY_EXISTS)
            {
                CloseHandle(mutex_handle);
                return false;
            }

            s_instance_mutex = mutex_handle;
            return true;
        }

        DWORD WINAPI lifecycle_thread(LPVOID) noexcept
        {
            Logger &logger = Logger::get_instance();

            bool init_ok = false;
            if (s_init_fn)
            {
                try
                {
                    init_ok = s_init_fn();
                }
                catch (const std::exception &e)
                {
                    logger.error("Bootstrap: init_fn threw: {}", e.what());
                }
                catch (...)
                {
                    logger.error("Bootstrap: init_fn threw unknown exception.");
                }
            }
            else
            {
                init_ok = true;
            }

            if (!init_ok)
            {
                logger.error("Bootstrap: init_fn returned failure; worker idling until detach.");
            }

            if (s_shutdown_event)
            {
                WaitForSingleObject(s_shutdown_event, INFINITE);
            }

            if (s_shutdown_fn)
            {
                try
                {
                    s_shutdown_fn();
                }
                catch (const std::exception &e)
                {
                    logger.error("Bootstrap: shutdown_fn threw: {}", e.what());
                }
                catch (...)
                {
                    logger.error("Bootstrap: shutdown_fn threw unknown exception.");
                }
            }

            DMK_Shutdown();
            return 0;
        }

        void release_instance_mutex() noexcept
        {
            if (s_instance_mutex)
            {
                CloseHandle(s_instance_mutex);
                s_instance_mutex = nullptr;
            }
        }

        // Shared teardown path for early-attach failures. Ensures singletons initialized by Logger::configure / user
        // init_fn are torn down before on_dll_attach returns FALSE, so a subsequent DLL load starts clean.
        void unwind_early_attach_failure() noexcept
        {
            if (s_shutdown_event)
            {
                CloseHandle(s_shutdown_event);
                s_shutdown_event = nullptr;
            }
            release_instance_mutex();
            s_init_fn = nullptr;
            s_shutdown_fn = nullptr;
            s_module = nullptr;
            try
            {
                DMK_Shutdown();
            }
            catch (...)
            {
            }
        }
    } // anonymous namespace

    [[nodiscard]] BOOL on_dll_attach(HMODULE hMod, const ModInfo &info, std::function<bool()> init_fn,
                                     std::function<void()> shutdown_fn)
    {
        if (s_shutdown_event || s_worker_thread)
        {
            return FALSE;
        }

        s_module = hMod;
        if (hMod)
        {
            DisableThreadLibraryCalls(hMod);
        }

        if (!is_target_process(info.game_process_name))
        {
            s_module = nullptr;
            return FALSE;
        }

        if (!acquire_instance_mutex(info.instance_mutex_prefix))
        {
            s_module = nullptr;
            return FALSE;
        }

        Logger::configure(info.prefix, info.log_file);
        Logger::get_instance().enable_async_mode(info.async_cfg);

        s_init_fn = std::move(init_fn);
        s_shutdown_fn = std::move(shutdown_fn);

        s_shutdown_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!s_shutdown_event)
        {
            unwind_early_attach_failure();
            return FALSE;
        }

        s_worker_thread = CreateThread(nullptr, 0, lifecycle_thread, nullptr, 0, nullptr);
        if (!s_worker_thread)
        {
            unwind_early_attach_failure();
            return FALSE;
        }

        // Re-arm the detach gate now that a fresh attach has fully succeeded, so the matching on_dll_detach runs its
        // teardown instead of no-opping. Without this reset s_detach_called stays true after the first detach and a
        // second attach/detach cycle would leak the worker thread, shutdown event, and instance mutex (the header
        // contract promises a subsequent attach starts from a clean slate). Reset only on the success path: early
        // failures above never set the gate, so they must not clear it either. Release pairs with the acquire in
        // on_dll_detach's compare_exchange. Both run serialized under the loader lock.
        s_detach_called.store(false, std::memory_order_release);

        return TRUE;
    }

    void request_shutdown() noexcept
    {
        if (s_shutdown_event)
        {
            SetEvent(s_shutdown_event);
        }
    }

    void on_dll_detach(BOOL is_process_exit) noexcept
    {
        bool expected = false;
        if (!s_detach_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return;
        }

        // On process exit Windows has already terminated every other thread in the process before calling DllMain with
        // DLL_PROCESS_DETACH. Waiting on s_worker_thread would block forever because the worker was abruptly killed
        // mid-WaitForSingleObject. Skip the wait and run the explicit shutdown path directly.
        if (is_process_exit)
        {
            if (s_shutdown_fn)
            {
                try
                {
                    s_shutdown_fn();
                }
                catch (const std::exception &e)
                {
                    try
                    {
                        Logger::get_instance().error("Bootstrap: shutdown_fn threw: {}", e.what());
                    }
                    catch (...)
                    {
                    }
                }
                catch (...)
                {
                    try
                    {
                        Logger::get_instance().error("Bootstrap: shutdown_fn threw unknown exception.");
                    }
                    catch (...)
                    {
                    }
                }
            }
            try
            {
                DMK_Shutdown();
            }
            catch (const std::exception &e)
            {
                try
                {
                    Logger::get_instance().error("Bootstrap: DMK_Shutdown threw: {}", e.what());
                }
                catch (...)
                {
                }
            }
            catch (...)
            {
                try
                {
                    Logger::get_instance().error("Bootstrap: DMK_Shutdown threw unknown exception.");
                }
                catch (...)
                {
                }
            }
        }
        else if (s_shutdown_event)
        {
            // Dynamic unload under loader lock. Signal the worker but do NOT wait here: blocking under loader lock
            // deadlocks any peer DllMain that touches Win32 APIs. The contract (see bootstrap.hpp) is that callers who
            // need a clean unload call request_shutdown() before FreeLibrary and give the worker time to drain.
            SetEvent(s_shutdown_event);
            DetourModKit::Diagnostics::record_intentional_leak(DetourModKit::Diagnostics::LeakSubsystem::Bootstrap);
        }

        if (s_shutdown_event)
        {
            CloseHandle(s_shutdown_event);
            s_shutdown_event = nullptr;
        }

        if (s_worker_thread)
        {
            CloseHandle(s_worker_thread);
            s_worker_thread = nullptr;
        }

        release_instance_mutex();
        s_module = nullptr;
    }

    HMODULE module_handle() noexcept
    {
        return s_module;
    }

    void on_logic_dll_unload(std::span<const std::string_view> hook_names,
                             std::span<const std::string_view> binding_names) noexcept
    {
        Logger &logger = Logger::get_instance();
        size_t hooks_removed = 0;
        size_t bindings_removed = 0;

        for (const auto name : hook_names)
        {
            try
            {
                auto result = HookManager::get_instance().remove_hook(name);
                if (result)
                {
                    ++hooks_removed;
                }
                else
                {
                    logger.debug("Bootstrap: on_logic_dll_unload: hook '{}' not removed ({}).", name,
                                 Hook::error_to_string(result.error()));
                }
            }
            catch (const std::exception &e)
            {
                logger.error("Bootstrap: on_logic_dll_unload caught exception removing hook '{}': {}", name, e.what());
            }
            catch (...)
            {
                logger.error("Bootstrap: on_logic_dll_unload caught unknown exception removing hook '{}'.", name);
            }
        }

        for (const auto name : binding_names)
        {
            try
            {
                // Pass invoke_callbacks=false because this helper is documented as safe from DllMain detach paths. User
                // on_state_change(false)
                // callbacks for held bindings live in the unloading Logic DLL;
                // running them under loader lock is the deadlock-or-crash vector that the leak-on-purpose discipline
                // was set up to forbid.
                bindings_removed += InputManager::get_instance().remove_binding_by_name(name, false);
            }
            catch (const std::exception &e)
            {
                logger.error("Bootstrap: on_logic_dll_unload caught exception removing binding '{}': {}", name,
                             e.what());
            }
            catch (...)
            {
                logger.error("Bootstrap: on_logic_dll_unload caught unknown exception removing binding '{}'.", name);
            }
        }

        logger.info("Bootstrap: on_logic_dll_unload drained {} hook(s) and {} binding(s).", hooks_removed,
                    bindings_removed);

        // Wipe the Config registry last because the prior hook and binding teardown may invoke a registered setter one
        // final time (a setter that observes a binding-driven flag, for instance). Clearing first would orphan that
        // final-fire path mid-call. The registered std::function setters' call operators, vtables, and destructors live
        // in the Logic DLL's
        // .text segment; once the loader unmaps that segment, every surviving entry becomes a use-after-unload hazard.
        // The next attach's replace_or_append destroys the stale slot before installing the fresh one, which would
        // invoke the old setter's destructor against freed pages.
        try
        {
            Config::clear_registered_items();
        }
        catch (const std::exception &e)
        {
            try
            {
                logger.error("Bootstrap: on_logic_dll_unload caught exception in clear_registered_items: {}", e.what());
            }
            catch (...)
            {
            }
        }
        catch (...)
        {
            try
            {
                logger.error("Bootstrap: on_logic_dll_unload caught unknown exception in clear_registered_items.");
            }
            catch (...)
            {
            }
        }
    }

    void on_logic_dll_unload_all() noexcept
    {
        Logger &logger = Logger::get_instance();

        // Hooks first so the original prologue bytes are restored before the binding teardown can disturb any callback
        // that still trampolines through SafetyHook. remove_all_hooks() resets m_shutdown_called at the end, leaving
        // HookManager re-usable for the next attach.
        try
        {
            HookManager::get_instance().remove_all_hooks();
        }
        catch (const std::exception &e)
        {
            try
            {
                logger.error("Bootstrap: on_logic_dll_unload_all caught exception in remove_all_hooks: {}", e.what());
            }
            catch (...)
            {
            }
        }
        catch (...)
        {
            try
            {
                logger.error("Bootstrap: on_logic_dll_unload_all caught unknown exception in remove_all_hooks.");
            }
            catch (...)
            {
            }
        }

        // clear_bindings() leaves the poll thread running and ready to accept fresh bindings, matching the "tear down
        // per-Logic-DLL state but keep the manager re-usable" contract that the named-list overload honours. Pass
        // invoke_callbacks=false because this helper is documented as safe from DllMain detach paths: user release
        // callbacks live in the unloading Logic DLL and must not be invoked under loader lock.
        try
        {
            InputManager::get_instance().clear_bindings(false);
        }
        catch (const std::exception &e)
        {
            try
            {
                logger.error("Bootstrap: on_logic_dll_unload_all caught exception in clear_bindings: {}", e.what());
            }
            catch (...)
            {
            }
        }
        catch (...)
        {
            try
            {
                logger.error("Bootstrap: on_logic_dll_unload_all caught unknown exception in clear_bindings.");
            }
            catch (...)
            {
            }
        }

        try
        {
            logger.info("Bootstrap: on_logic_dll_unload_all drained all hooks and bindings.");
        }
        catch (...)
        {
        }

        // Wipe the Config registry last for the same reason as the named-list overload: the prior remove_all_hooks /
        // clear_bindings calls may fire a registered setter one final time, and clearing first would orphan that path.
        // The registered std::function setters' call operators, vtables,
        // and destructors live in the unloading Logic DLL's .text;
        // every surviving entry becomes a use-after-unload hazard the moment the loader reclaims those pages.
        try
        {
            Config::clear_registered_items();
        }
        catch (const std::exception &e)
        {
            try
            {
                logger.error("Bootstrap: on_logic_dll_unload_all caught exception in clear_registered_items: {}",
                             e.what());
            }
            catch (...)
            {
            }
        }
        catch (...)
        {
            try
            {
                logger.error("Bootstrap: on_logic_dll_unload_all caught unknown exception in clear_registered_items.");
            }
            catch (...)
            {
            }
        }
    }
} // namespace DetourModKit::Bootstrap
