#ifndef DETOURMODKIT_SESSION_HPP
#define DETOURMODKIT_SESSION_HPP

/**
 * @file session.hpp
 * @brief The process-lifecycle surface: the RAII Session, the ModInfo descriptor, and the DllMain bootstrap entry
 *        points that own a mod's process lifetime.
 * @details Split out of the umbrella so a consumer can reach the Session / bootstrap / ModInfo surface without pulling
 *          in every module header. The umbrella (DetourModKit.hpp) includes this header, so a plain
 *          `#include "DetourModKit.hpp"` still sees the whole surface unchanged.
 *
 * @note This header does not include <windows.h>. The Win32 module handle is exposed through the opaque
 *       DetourModKit::ModuleHandle alias, so a consumer translation unit that needs <windows.h> for its own DllMain
 *       must include it directly; a real HMODULE binds to ModuleHandle with no cast.
 */

#include "DetourModKit/async_logger_config.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include <chrono>
#include <functional>
#include <span>
#include <string_view>

// HMODULE is `struct HINSTANCE__ *`. Forward-declaring the incomplete tag lets this public header expose the
// module-handle type without pulling <windows.h> (and its macro soup) into every consumer translation unit. A TU that
// also includes <windows.h> sees the identical type, so a real HMODULE binds with no cast. The implementation file
// (src/session.cpp) includes <windows.h> directly for the Win32 calls in the function bodies.
struct HINSTANCE__;

namespace DetourModKit
{
    /**
     * @brief Opaque Win32 module handle, identical to HMODULE (which is `struct HINSTANCE__ *`).
     * @details Aliased so the public surface needs no <windows.h>; a real HMODULE binds to it with no cast.
     */
    using ModuleHandle = ::HINSTANCE__ *;

    namespace detail
    {
        struct SessionBootstrapAccess;
    } // namespace detail

    /**
     * @struct ModInfo
     * @brief Identity, single-instance gating, process gating, and async-logger settings for a mod.
     * @details Passed to Session::start() / bootstrap(). Every field is a borrowed view or a value copied out before
     *          the call returns, so a ModInfo built from string literals at the call site is sufficient; nothing here
     *          is retained past setup. @p name doubles as the logger prefix and the mod's human identity.
     *
     *          @p game_process_name, when non-empty, is compared (case-insensitive) against the running executable's
     *          basename; a mismatch makes start() return ErrorCode::ProcessMismatch so the DLL can decline to load in
     *          the wrong process. @p instance_mutex_prefix, when non-empty, creates a per-PID named mutex so a second
     *          load of the same mod bails out with ErrorCode::InstanceAlreadyRunning.
     *
     *          There is no ini path here: the config registry is bind-then-load (binds register first, then load()
     *          applies file values), so a mod loads its INI from on_ready via session.ini().load(path) AFTER its binds
     *          exist, not implicitly at start() when the registry is still empty.
     */
    struct ModInfo
    {
        std::string_view name{};
        std::string_view log_file{};
        std::string_view game_process_name{};
        std::string_view instance_mutex_prefix{};
        AsyncLoggerConfig log{};
    };

    /**
     * @class Session
     * @brief RAII owner of a mod's process lifetime: single-instance guard, logger configuration, its input binding
     *        scope, and the correctly ordered teardown of every process-wide subsystem.
     * @details A Session makes process-lifetime teardown automatic and correctly ordered, replacing an error-prone
     *          manual shutdown that had to sequence each subsystem by hand. It is constructed two ways:
     *
     *          - Session::start(ModInfo): the synchronous, directly-held path (the one tests and simple hosts use). It
     *            runs the process gate, acquires the single-instance mutex, and configures the logger, then returns a
     *            live Session by value. When that value is destroyed, ~Session runs the ordered teardown.
     *          - bootstrap(ModInfo, on_ready): the DllMain path. It performs only allocation-free process and instance
     *            gating before starting a minimal worker. The worker configures logging, runs on_ready, and destroys
     *            the Session after shutdown is requested. See bootstrap().
     *
     *          Teardown ordering lives in exactly one place, the explicit ~Session body: first scope().clear() releases
     *          this session's input bindings (reverse insertion order, so a Hold binding's release edge fires before
     *          the bindings it depends on), then the process-wide subsystems tear down in reverse dependency order --
     *          the config auto-reload watcher, the input poll thread, the memory cache, the config registry, and the
     *          logger LAST (every prior step may still log). Each subsystem shutdown applies the same blocking-teardown
     *          gate for itself -- join when the caller is authorized (the published lifecycle phase permits blocking,
     *          or the caller is the bootstrap worker, whose teardown is never inside a loader callback) and the
     *          loader-lock probe does not veto, otherwise abandon and retain -- so ~Session delegates that decision to
     *          the leaves rather than making one central, and therefore wrong, choice.
     *
     *          Hooks are NOT owned by the Session: each hook lives in a caller-held Hook handle and unhooks when that
     *          handle drops, so hook lifetime is orthogonal to the session and correctly ordered by the caller's own
     *          scopes.
     *
     * @note A Session is move-only. A moved-from (or abandon()ed) Session is inert: its destructor does nothing, so a
     *       double-drop never double-tears-down. A mod DLL has one process lifetime, so only one Session is active at a
     *       time: a second start() returns ErrorCode::SessionAlreadyActive, and a second bootstrap() returns whichever
     *       of SessionAlreadyActive, SessionShutdownInProgress, or SessionShutdownUnavailable names what owns the
     *       bootstrap slot (see bootstrap()).
     * @note Session::start, on_ready, ~Session, and abandon() run single-threaded on the init/teardown thread. Do not
     *       call them from a hook, an input callback, or a config-reload callback.
     */
    class Session
    {
    public:
        /**
         * @brief Synchronously builds a Session: process gate, single-instance mutex, and logger configuration.
         * @param info Mod identity, gating, and async-logger settings.
         * @return A live Session on success, or an ErrorCode-bearing failure: ProcessMismatch (wrong executable),
         *         InstanceAlreadyRunning (a duplicate load holds the mutex), SessionAlreadyActive (a session already
         *         exists in this process), SystemCallFailed (a Win32 lifecycle operation failed; Error::detail =
         *         GetLastError()), OutOfMemory (setup threw std::bad_alloc), or Unknown (setup threw anything else).
         *         Allocation failure and an unclassified throw are reported distinctly; a caller may retry the first
         *         but not the second.
         * @note Setup/control-plane only. Every throwing step is caught and mapped to a Result failure.
         */
        [[nodiscard]] static Result<Session> start(const ModInfo &info) noexcept;

        /** @brief Move-constructs, transferring the live teardown; the moved-from Session is left inert. */
        Session(Session &&other) noexcept;
        /** @brief Move-assigns: ends this Session (ordered teardown) if it was active, then adopts @p other. */
        Session &operator=(Session &&other) noexcept;
        /** @brief Deleted: Session is move-only; its teardown and single-instance guard cannot be copied. */
        Session(const Session &) = delete;
        Session &operator=(const Session &) = delete;

        /**
         * @brief Runs the ordered teardown if this Session is active; otherwise a no-op (moved-from / abandoned).
         */
        ~Session() noexcept;

        /**
         * @brief The process-default logger this session configured. Convenience for `DetourModKit::log()`.
         */
        [[nodiscard]] Logger &log() const noexcept;

        /**
         * @brief A handle to the process configuration registry. Load the mod's INI here (after registering binds):
         *        `session.ini().load(path)`.
         */
        [[nodiscard]] config::Ini ini() const noexcept;

        /**
         * @brief The process input manager. Convenience for `input::Input::instance()`.
         */
        [[nodiscard]] input::Input &input() const noexcept;

        /**
         * @brief This session's input binding scope. Add BindingGuards here; ~Session clears it first (reverse order).
         */
        [[nodiscard]] input::Scope &scope() noexcept;

        /**
         * @brief True while this Session owns a live teardown; false once moved-from or abandon()ed.
         */
        [[nodiscard]] explicit operator bool() const noexcept { return m_active; }

        /**
         * @brief Neutralizes the Session so its destructor does NOTHING: no scope clear, no subsystem teardown, no
         *        unhook, no logger flush, no thread join.
         * @details For DLL_PROCESS_DETACH with `lpReserved != NULL` (process termination) ONLY. On that path the OS has
         *          already terminated every other thread and is reclaiming the address space, so touching patched
         *          pages, flushing the logger, or joining a dead thread is at best pointless and at worst a UAF.
         *          abandon() retains teardown-sensitive ownership untouched and lets the OS reclaim it at exit. Never
         *          call it for an explicit FreeLibrary (lpReserved == NULL), where a real ordered teardown must run.
         */
        void abandon() noexcept;

    private:
        friend struct detail::SessionBootstrapAccess;

        // Both start() and the bootstrap access bridge build the Session here, so the single-instance mutex is always
        // Session-owned and released in exactly one place (~Session); @p instance_mutex is null when ModInfo requested
        // no single-instance guard.
        explicit Session(void *instance_mutex) noexcept;

        // The ordered teardown, factored out so ~Session and move-assignment (which must end the session it overwrites)
        // share exactly one implementation. A no-op on an inert Session; idempotent.
        void release() noexcept;

        // The mod's input bindings; cleared first in ~Session. Move-only, default-constructible: keeps Session movable.
        input::Scope m_scope;
        // The single-instance mutex handle (or null); CloseHandle'd in ~Session. Typed as void* so this public header
        // stays free of <windows.h>.
        void *m_instance_mutex{nullptr};
        // Gates the destructor. Transferred on move (source becomes inert), cleared by abandon().
        bool m_active{false};
    };

    /**
     * @brief DllMain DLL_PROCESS_ATTACH entry point: publishes a minimal attach, then starts the Session on a worker.
     * @details Auto-captures the calling module (DetourModKit links statically into the mod DLL, so its code address
     *          resolves to the mod's HMODULE), calls DisableThreadLibraryCalls, performs the process and
     *          single-instance gates without heap allocation, copies the logger inputs into fixed bootstrap storage,
     *          and creates the shutdown event and worker. The worker cannot enter while the loader is delivering attach
     *          notifications; once it runs it:
     *            1. configures the logger and runs @p on_ready(session) off the loader lock (so it may allocate, load
     *               INIs, install hooks, and register bindings into session.scope() freely),
     *            2. blocks on the shutdown event until bootstrap_detach(), request_shutdown(), or shutdown_and_wait()
     *               wakes it,
     *            3. destroys the Session off the loader lock, so every subsystem leaf may join cleanly.
     *
     *          @p on_ready returns Result<void> so an init failure is a value logged on the worker, never an exception
     *          crossing the loader lock. It is std::move_only_function so it may capture move-only setup state.
     *
     * @param info Mod identity, gating, and async-logger settings.
     * @param on_ready Called once on the worker thread with the live Session unless process termination abandons the
     *        worker before it enters.
     * @return An empty Result once the worker is published, or ProcessMismatch, InstanceAlreadyRunning,
     *         SessionAlreadyActive, InvalidArg (a bootstrap text field exceeds the fixed attach buffer),
     *         SessionShutdownInProgress, SessionShutdownUnavailable (DllMain detach has claimed the state), or
     *         SystemCallFailed. Failures before worker publication roll back the mutex and lifecycle slot completely.
     * @note Setup/control-plane only. Call solely from DllMain's attach path. The synchronous phase performs no heap
     *       allocation, logger/file setup, callback invocation, or wait; it only publishes state and creates the Win32
     *       primitives required by the worker. noexcept by contract, so nothing unwinds across the loader lock.
     */
    [[nodiscard]] Result<void> bootstrap(const ModInfo &info,
                                         std::move_only_function<Result<void>(Session &)> on_ready) noexcept;

    /**
     * @brief DllMain DLL_PROCESS_DETACH entry point. Routes by @p reserved (DllMain's lpvReserved).
     * @details Two paths, both loader-lock-safe:
     *
     *          - @p reserved == NULL (explicit FreeLibrary): publishes LoaderDetach and returns without waiting,
     *            joining, or destroying callback state. The worker's counted module reference prevents a bare
     *            FreeLibrary from reaching this notification while the worker remains active. A mod that needs a
     *            guaranteed-drained unload must call shutdown_and_wait() before FreeLibrary.
     *          - @p reserved != NULL (process termination): the OS has already killed the worker, so this takes the
     *            abandon path -- no teardown, no unhook, no flush, no join. Handles are closed without waiting and the
     *            OS reclaims the rest.
     *
     *          Idempotent: subsequent calls are no-ops.
     * @param reserved DllMain's lpvReserved (NULL for FreeLibrary, non-NULL for process exit).
     * @note Setup/control-plane only: call it solely from DllMain's DLL_PROCESS_DETACH path. Loader-lock-safe (it never
     *       waits or joins under the loader lock); best-effort on a bare FreeLibrary, where the worker drains
     *       asynchronously.
     */
    void bootstrap_detach(void *reserved) noexcept;

    /**
     * @brief Requests asynchronous teardown of the bootstrap worker.
     * @details A no-op if bootstrap() never ran or teardown already completed. This function does not wait and
     *          therefore does not guarantee teardown has completed before a subsequent FreeLibrary; use
     *          shutdown_and_wait() when the module must be fully drained first.
     * @note Callback-safe: safe from any thread (a hook, an input callback, or DllMain). It only signals an event and
     *       never allocates, waits, or joins.
     */
    void request_shutdown() noexcept;

    /**
     * @brief Signals the bootstrap worker and waits for its complete off-loader-lock teardown.
     * @details On success the worker has exited, released its counted module reference, and drained every Session-owned
     *          subsystem. The call is idempotent after a completed drain or when bootstrap() never started. A
     *          concurrent drain is reported instead of returning before the first caller has finished.
     * @return Success after a complete drain; SessionShutdownInProgress when another control thread already owns the
     *         drain or a bootstrap attach is concurrently claiming the slot; SessionShutdownUnavailable after DllMain
     *         detach has claimed the state; SessionShutdownWouldBlock when the loader phase forbids waiting or the
     *         caller is the bootstrap worker itself; or SystemCallFailed when waiting on the worker handle fails
     *         (Error::detail = GetLastError()).
     * @note Setup/control-plane only. Call before FreeLibrary, never from DllMain, a hook, or an input callback.
     * @warning Called ON the bootstrap worker (from @p on_ready, or from a callback the worker's teardown reaches) this
     *          returns SessionShutdownWouldBlock rather than waiting, because the wait would be for the calling
     *          thread's own exit. Use request_shutdown() to retire the session from that thread.
     */
    [[nodiscard]] Result<void> shutdown_and_wait() noexcept;

    /**
     * @brief The module handle captured at bootstrap() time, or nullptr before bootstrap(), after bootstrap_detach(),
     *        after a successful shutdown_and_wait(), or when only the synchronous Session::start path was used.
     * @note A completed drain retires the identity along with the rest of the generation, so capture the handle BEFORE
     *       shutdown_and_wait() if the unload sequence needs it afterwards.
     * @note Callback-safe: published and read through a lock-free atomic, so a reader on any thread observes only the
     *       current identity or null and never races a concurrent detach-path clear.
     */
    [[nodiscard]] ModuleHandle module_handle() noexcept;

    /**
     * @enum LogicDllUnloadStatus
     * @brief Typed result of preparing consumer-owned callback state for a Logic DLL unmap.
     */
    enum class LogicDllUnloadStatus
    {
        /// With the documented caller-owned preconditions met, DMK no longer blocks unmapping the Logic DLL.
        SafeToUnload,
        /// The Windows loader lock forbids the waits and joins required to certify safe unmapping.
        LoaderLock,
        /// The caller is executing inside an input or config callback and cannot drain itself.
        SelfDelivery,
        /// Another control thread owns the safe-drain transaction.
        InProgress,
        /// Selected input bindings could not be retired.
        RetireFailed,
        /// The deadline expired while a callback or worker body remained alive.
        TimedOut
    };

    /// Default deadline for Logic DLL safe-unload preparation.
    inline constexpr std::chrono::milliseconds DEFAULT_LOGIC_DLL_DRAIN_TIMEOUT{500};

    /**
     * @brief Retires named input bindings and config callbacks before a Logic DLL is unmapped.
     * @param binding_names Names registered by the Logic DLL.
     * @param timeout End-to-end deadline for input, reload, and worker rundown.
     * @return SafeToUnload only after every callable copy DMK still owns for the named bindings, and every config
     *         setter from the old lifecycle, is gone. Retirement reaches the callback through the binding's delivery
     *         gate, so an outstanding BindingGuard does not keep one alive; a still-held Hold binding receives its
     *         balancing on_state_change(false) during the drain, while the DLL is still mapped. A balancing edge
     *         already running from a concurrent guard release is part of the same rundown.
     * @note A guard retained across a successful drain stays valid and still lifts its binding's passthrough
     *       suppression when released, but no longer reaches the callback: the drain already delivered the hold's
     *       balancing edge and destroyed the callable.
     * @note Setup/control-plane only. Call from an off-loader-lock shutdown thread after stopping consumer-owned
     *       workers and dropping dispatcher subscriptions and hook handles.
     */
    [[nodiscard]] LogicDllUnloadStatus
    prepare_logic_dll_unload(std::span<const std::string_view> binding_names,
                             std::chrono::milliseconds timeout = DEFAULT_LOGIC_DLL_DRAIN_TIMEOUT) noexcept;

    /**
     * @brief Retires every input binding and all config callbacks before Logic DLLs are unmapped.
     * @param timeout End-to-end deadline for input, reload, and worker rundown.
     * @return SafeToUnload only after every callable copy DMK still owns, and every config setter, is gone. Retirement
     *         reaches callbacks through their delivery gates, as prepare_logic_dll_unload documents.
     * @warning In a multi-Logic-DLL host this retires bindings belonging to every Logic DLL.
     */
    [[nodiscard]] LogicDllUnloadStatus
    prepare_logic_dll_unload_all(std::chrono::milliseconds timeout = DEFAULT_LOGIC_DLL_DRAIN_TIMEOUT) noexcept;

    /**
     * @brief Source-compatible best-effort abandon wrapper.
     * @details Off the loader lock it attempts prepare_logic_dll_unload. Under the loader lock it only closes new
     *          callback admission and requests no blocking rundown.
     * @warning This void result never authorizes FreeLibrary. Use prepare_logic_dll_unload and require SafeToUnload.
     */
    void on_logic_dll_unload(std::span<const std::string_view> binding_names) noexcept;

    /**
     * @brief Source-compatible best-effort abandon wrapper for every binding.
     * @warning This void result never authorizes FreeLibrary. Use prepare_logic_dll_unload_all and require
     *          SafeToUnload.
     */
    void on_logic_dll_unload_all() noexcept;
} // namespace DetourModKit

#endif // DETOURMODKIT_SESSION_HPP
