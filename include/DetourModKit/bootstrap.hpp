#ifndef DETOURMODKIT_BOOTSTRAP_HPP
#define DETOURMODKIT_BOOTSTRAP_HPP

/**
 * @file bootstrap.hpp
 * @brief Shared DllMain scaffolding for DMK-native mods.
 */

#include "DetourModKit/async_logger.hpp"

#include <functional>
#include <span>
#include <string>
#include <string_view>

#include <windows.h>

namespace DetourModKit
{
    /**
     * @namespace Bootstrap
     * @brief DllMain-lifecycle helpers: loader-lock-safe worker thread,
     *        single-instance gating, process-name gate, and explicit
     *        DMK_Shutdown() ordering.
     */
    namespace Bootstrap
    {
        /**
         * @struct ModInfo
         * @brief Identifying strings and async-logger settings for a mod.
         * @details @p prefix and @p log_file are applied via
         *          Logger::configure() + Logger::enable_async_mode() before
         *          init_fn runs, so the first message travels the async path. If
         *          @p game_process_name is non-empty, the current EXE
         *          basename must match (case-insensitive) or on_dll_attach
         *          short-circuits to FALSE. A non-empty
         *          @p instance_mutex_prefix creates a per-PID named mutex
         *          so duplicate ASI loads bail out cleanly.
         */
        struct ModInfo
        {
            std::string_view prefix;
            std::string_view log_file;
            std::string_view game_process_name;
            std::string_view instance_mutex_prefix;
            AsyncLoggerConfig async_cfg{};
        };

        /**
         * @brief Handles DLL_PROCESS_ATTACH: spawns the lifecycle worker.
         * @details Called from DllMain's DLL_PROCESS_ATTACH case. Performs
         *          DisableThreadLibraryCalls(), configures the logger, checks
         *          the process gate and instance mutex, then starts a Win32
         *          worker thread that runs init_fn once and blocks on the
         *          shutdown event until on_dll_detach() is invoked.
         *
         *          init_fn is invoked on the worker thread (off the loader
         *          lock). It should return true on success; a false return
         *          is logged and the worker exits cleanly.
         *
         *          shutdown_fn is invoked on the worker thread after the
         *          shutdown event is signaled, then DMK_Shutdown() is
         *          called unconditionally.
         *
         * @param hMod Module handle from DllMain.
         * @param info Mod identity and async-logger settings.
         * @param init_fn Called exactly once on the worker thread.
         * @param shutdown_fn Called exactly once before DMK_Shutdown().
         * @return BOOL TRUE if the worker was started, FALSE if the process
         *         gate, instance mutex, or event creation failed.
         */
        [[nodiscard]] BOOL on_dll_attach(HMODULE hMod,
                                         const ModInfo &info,
                                         std::function<bool()> init_fn,
                                         std::function<void()> shutdown_fn);

        /**
         * @brief Handles DLL_PROCESS_DETACH.
         * @details Behaviour depends on @p is_process_exit:
         *
         *          - @p is_process_exit == TRUE (DllMain @c lpvReserved !=
         *            nullptr): the OS has already terminated every other
         *            thread in the process. on_dll_detach() invokes the
         *            user-supplied shutdown_fn (if any) inline, then calls
         *            DMK_Shutdown(). No waiting is performed; the worker
         *            thread handle is closed blindly.
         *
         *          - @p is_process_exit == FALSE (dynamic FreeLibrary):
         *            on_dll_detach() signals the shutdown event but does NOT
         *            wait for the worker to drain. Waiting under loader lock
         *            is unsafe because any peer DllMain that touches Win32
         *            APIs would deadlock on the lock this thread holds.
         *            Handles are closed and globals cleared so a subsequent
         *            attach starts from a clean slate.
         *
         *        Mods that require a clean dynamic unload must call
         *        @ref request_shutdown() (or equivalent) and give the worker
         *        time to drain before FreeLibrary. DMK does not guarantee
         *        graceful teardown of the worker thread when the host issues
         *        FreeLibrary without a pre-unload handshake.
         *
         *        Subsequent calls to on_dll_detach() are no-ops.
         *
         * @param is_process_exit TRUE when the DLL is unloaded as part of
         *        process termination (DllMain @c lpvReserved != nullptr).
         */
        void on_dll_detach(BOOL is_process_exit) noexcept;

        /**
         * @brief Signals the shutdown event so the worker thread can exit.
         * @details Safe to call from any thread. Non-blocking: does not wait
         *          for the worker to acknowledge. Intended to be invoked by
         *          a mod before issuing FreeLibrary on itself, so that the
         *          worker thread has a chance to run its user shutdown_fn
         *          and DMK_Shutdown() off the loader lock.
         *
         *          If on_dll_attach() has not run (or already completed
         *          teardown) this call is a no-op.
         */
        void request_shutdown() noexcept;

        /**
         * @brief Returns the module handle captured at attach time.
         * @details Intended for mods that need the handle for resource
         *          loading. Returns nullptr before on_dll_attach() or
         *          after on_dll_detach().
         */
        [[nodiscard]] HMODULE module_handle() noexcept;

        /**
         * @brief Drops the per-Logic-DLL state owned by the caller.
         * @details Composes HookManager::remove_hook for every entry in
         *          @p hook_names and InputManager::remove_binding_by_name
         *          for every entry in @p binding_names, then calls
         *          Config::clear_registered_items() to drop the
         *          registered setters because their call operators live
         *          in the unloading DLL's .text; Logger and
         *          ConfigWatcher are loader-side and outlive the unload.
         *          Names that do not exist are skipped (logged at
         *          Debug). Idempotent: a second call with the same names
         *          is a no-op. Use DMK_Shutdown() for whole-process
         *          teardown.
         *
         *          For guidance on choosing between this and
         *          DMK_Shutdown(), see docs/hot-reload/README.md.
         *
         *          Safe to call from any thread except: must NOT be
         *          called from the InputPoller thread (would self-join)
         *          and must NOT be called from a HookManager mutator
         *          callback (would deadlock on m_mutator_gate).
         *
         *          Marked noexcept because consumers may invoke it from a
         *          DllMain detach path. Internal allocations performed
         *          while iterating the name spans (vector growth, log
         *          formatting) may throw; every throw site is caught and
         *          logged so no exception propagates to the caller.
         *
         * @warning Stop and join every consumer-owned worker thread
         *          before calling. A worker that fires a hook between
         *          remove_hook returning and FreeLibrary reclaiming the
         *          Logic DLL's .text pages will execute freed code. This
         *          helper cannot prove worker quiescence; that is the
         *          consumer's responsibility.
         *
         * @param hook_names Names of hooks installed via HookManager.
         * @param binding_names Names of input bindings registered via
         *        InputManager (or via Config::register_press_combo).
         */
        void on_logic_dll_unload(std::span<const std::string_view> hook_names,
                                 std::span<const std::string_view> binding_names) noexcept;

        /**
         * @brief Drops every hook and binding registered through the
         *        process-wide singletons.
         * @details Composes HookManager::remove_all_hooks with
         *          InputManager::clear_bindings, then chains
         *          Config::clear_registered_items() to drop the
         *          registered setters because their call operators live
         *          in the unloading DLL's .text; Logger and
         *          ConfigWatcher are loader-side and outlive the unload.
         *          The HookManager call is remove_all_hooks() (not
         *          shutdown()) and the binding call is clear_bindings()
         *          (not shutdown()) so both subsystems stay re-usable
         *          for the next attach. Use when the caller does not
         *          maintain an explicit registry of hook or binding
         *          names. Use DMK_Shutdown() for whole-process teardown.
         *
         *          For guidance on choosing between this and
         *          DMK_Shutdown(), see docs/hot-reload/README.md.
         *
         *          Safe to call from any thread except: must NOT be
         *          called from the InputPoller thread (would self-join)
         *          and must NOT be called from a HookManager mutator
         *          callback (would deadlock on m_mutator_gate).
         *
         *          Marked noexcept because consumers may invoke it from
         *          a DllMain detach path. Internal allocations performed
         *          while logging or rebuilding active_states_ may throw;
         *          every throw site is caught and logged so no exception
         *          propagates to the caller.
         *
         * @warning In a host that loads multiple Logic DLLs sharing one
         *          process-wide DMK instance, calling this from one
         *          Logic DLL's Shutdown() rips out the other Logic DLLs'
         *          hooks and bindings as well. The named-list overload
         *          is the correct choice in that topology.
         *
         * @warning Stop and join every consumer-owned worker thread
         *          before calling. A worker that fires a hook between
         *          remove_all_hooks returning and FreeLibrary reclaiming
         *          the Logic DLL's .text pages will execute freed code.
         *          This helper cannot prove worker quiescence; that is
         *          the consumer's responsibility.
         */
        void on_logic_dll_unload_all() noexcept;
    } // namespace Bootstrap
} // namespace DetourModKit

#endif // DETOURMODKIT_BOOTSTRAP_HPP
