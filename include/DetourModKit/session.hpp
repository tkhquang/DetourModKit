#ifndef DETOURMODKIT_SESSION_HPP
#define DETOURMODKIT_SESSION_HPP

/**
 * @file session.hpp
 * @brief Process-lifecycle surface: the RAII Session, the ModInfo descriptor, and the DllMain bootstrap entry points.
 */

#include "DetourModKit/async_logger_config.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <span>
#include <string_view>

// HMODULE is `struct HINSTANCE__ *`. The incomplete tag exposes the handle type without <windows.h>.
struct HINSTANCE__;

namespace DetourModKit
{
    /**
     * @brief Opaque Win32 module handle, identical to HMODULE.
     * @details This header does not include <windows.h>, so a real HMODULE binds to this alias with no cast. A
     *          consumer translation unit that needs <windows.h> for its own DllMain must include it directly.
     */
    using ModuleHandle = ::HINSTANCE__ *;

    namespace detail
    {
        struct SessionBootstrapAccess;
    } // namespace detail

    /**
     * @struct ModInfo
     * @brief Identity, single-instance gating, process gating, and async-logger settings for a mod.
     * @details Every entry copies or borrows each field before return, so string literals suffice. @p name also
     *          supplies the logger prefix and mod identity. A non-empty @p game_process_name must match the process
     *          executable's basename (case-insensitive) or start() returns ErrorCode::ProcessMismatch. A non-empty
     *          @p instance_mutex_prefix creates a per-PID named mutex, so a second load of the same mod fails with
     *          ErrorCode::InstanceAlreadyRunning. There is no INI path here: the config registry is bind-then-load,
     *          so load the INI from on_ready via session.ini().load(path) after the binds exist.
     */
    struct ModInfo
    {
        std::string_view name{};
        std::string_view log_file{};
        std::string_view game_process_name{};
        std::string_view instance_mutex_prefix{};
        AsyncLoggerConfig log{};
        /**
         * @brief Selects the process-default logger's first sink open. See @ref LogOpenMode.
         * @details Append preserves the prior generation's records across a staged-generation reload.
         */
        LogOpenMode log_open_mode{LogOpenMode::Truncate};
    };

    /**
     * @class Session
     * @brief RAII owner of a mod's process lifetime: single-instance guard, logger configuration, input binding scope,
     *        and the ordered teardown of every process-wide subsystem.
     * @details Session::start(ModInfo) is the synchronous, directly-held path. bootstrap_attach(ModInfo, on_ready) is
     *          the hosted path. The private release() path owns the teardown order. ~Session and active move-assignment
     *          call it. scope().clear() releases this session's input bindings first, in reverse insertion order. The
     *          process-wide subsystems then tear down
     *          in reverse dependency order. The order is the config auto-reload watcher, the input poll thread, the
     *          memory cache, the config registry, and the logger. The logger stays last because every prior step can
     *          still log. Each subsystem shutdown applies
     *          its own teardown gate: join when the caller is authorized and the loader-lock probe does not
     *          veto, otherwise abandon and retain. Hooks are not owned by the Session: each hook lives in a
     *          caller-held Hook handle and unhooks when that handle drops.
     * @note A Session is move-only. A moved-from or abandon()ed Session is inert: its destructor does nothing. One
     *       Session is active at a time. A second start() returns ErrorCode::SessionAlreadyActive, and a second
     *       bootstrap entry returns the code that identifies the current bootstrap slot owner.
     * @note Session::start, on_ready, ~Session, and abandon() run single-threaded on the init/teardown thread. Do not
     *       call them from a hook, an input callback, or a config-reload callback.
     * @warning `[B-100]` Run Session::start, ~Session, and active move-assignment off the loader lock. Teardown invokes
     *          consumer release callbacks and joins worker threads. A DllMain caller must route both phases through
     *          bootstrap_attach and bootstrap_detach. See abandon() for the process-termination-only escape.
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
         * @note Setup/control-plane only. Each exception maps to a Result failure.
         * @warning See the class `[B-100]` loader-lock warning.
         */
        [[nodiscard]] static Result<Session> start(const ModInfo &info) noexcept;

        /** @brief Move-constructs, transferring the live teardown; the moved-from Session is left inert. */
        Session(Session &&other) noexcept;
        /**
         * @brief Move-assigns: ends this Session (ordered teardown) if it was active, then adopts @p other.
         * @note Setup/control-plane only. An active overwrite runs ordered teardown.
         * @warning See the class `[B-100]` loader-lock warning.
         */
        Session &operator=(Session &&other) noexcept;
        /** @brief Deleted: Session is move-only; its teardown and single-instance guard cannot be copied. */
        Session(const Session &) = delete;
        Session &operator=(const Session &) = delete;

        /**
         * @brief Runs the ordered teardown if this Session is active; otherwise a no-op (moved-from / abandoned).
         * @note Setup/control-plane only. Teardown clears the scope and shuts each subsystem down in order.
         * @warning See the class `[B-100]` loader-lock warning.
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
         * @note Setup/control-plane only: a process-termination detach path (see details).
         */
        void abandon() noexcept;

    private:
        friend struct detail::SessionBootstrapAccess;

        // start() and the bootstrap access bridge both build the Session here. The Session owns the single-instance
        // mutex until release(). A null instance_mutex means ModInfo requested no guard.
        explicit Session(void *instance_mutex) noexcept;

        // The ordered teardown shared by ~Session and active move-assignment. It closes the owned mutex. Idempotent and
        // inert-safe.
        void release() noexcept;

        // The mod's input bindings; cleared first in ~Session. Move-only, default-constructible: keeps Session movable.
        input::Scope m_scope;
        // The single-instance mutex handle (or null). release() closes it. The void pointer keeps this public header
        // free of <windows.h>.
        void *m_instance_mutex{nullptr};
        // Gates the destructor. Transferred on move (source becomes inert), cleared by abandon().
        bool m_active{false};
    };

    /// Defines the plain initialization callback accepted by bootstrap_attach().
    using BootstrapReadyFn = Result<void> (*)(Session &);

    /**
     * @brief DllMain DLL_PROCESS_ATTACH entry point: publishes a minimal attach, then starts the Session on a worker.
     * @details Auto-captures the module that contains the call because DetourModKit links statically into the mod DLL.
     *          It calls DisableThreadLibraryCalls and performs the process and single-instance gates without heap
     *          allocation. It copies the logger inputs into fixed bootstrap storage and creates the shutdown event and
     *          worker. The worker configures the logger and runs @p on_ready(session) off the loader lock. There it may
     *          allocate, load INIs, install hooks, and register bindings into session.scope(). It then blocks on the
     *          event until bootstrap_detach(), request_shutdown(), or shutdown_and_wait() wakes it, and destroys the
     *          Session off the loader lock. The worker logs an @p on_ready failure as a value.
     * @param info Mod identity, gating, and async-logger settings.
     * @param on_ready Called once on the worker thread with the live Session. A null value registers no callback.
     * @return An empty Result once the worker is published, or ProcessMismatch, InstanceAlreadyRunning,
     *         SessionAlreadyActive, InvalidArg, SessionShutdownInProgress, SessionShutdownUnavailable, or
     *         SystemCallFailed. Pre-publication failures roll back the mutex and lifecycle slot.
     * @note The synchronous phase calls no logger, callback, or wait. No exception crosses the loader lock.
     * @note Setup/control-plane only: the DllMain attach entry point.
     */
    [[nodiscard]] Result<void> bootstrap_attach(const ModInfo &info, BootstrapReadyFn on_ready) noexcept;

    /**
     * @brief Provides the rich bootstrap callback form for callers outside DllMain.
     * @details This entry uses bootstrap_attach() infrastructure. Its callback can own move-only setup state.
     * @param info Mod identity, gates, and asynchronous logger settings.
     * @param on_ready Called once on the worker thread with the live Session. See bootstrap_attach().
     * @return See bootstrap_attach().
     * @warning Do not call this entry from DllMain. Callable conversion can allocate at the call site.
     *          A pre-publication failure destroys the callable and its captures on the current thread.
     * @note Setup/control-plane only: the off-DllMain attach entry point.
     */
    [[nodiscard]] Result<void>
    bootstrap(const ModInfo &info, std::move_only_function<Result<void>(Session &)> on_ready) noexcept;

    /**
     * @brief DllMain DLL_PROCESS_DETACH entry point. Routes by @p reserved (DllMain's lpvReserved).
     * @details Two paths, both loader-lock-safe (neither waits nor joins):
     *
     *          - @p reserved == NULL (explicit FreeLibrary): publishes LoaderDetach and returns without a wait, join,
     *            or callback-state destruction. The worker's counted module reference blocks this notification from
     *            a bare FreeLibrary while the worker is live. A mod that needs a guaranteed-drained
     *            unload must call shutdown_and_wait() before FreeLibrary.
     *          - @p reserved != NULL (process termination): the OS has already killed the worker, so this takes the
     *            abandon path - no teardown, no unhook, no flush, no join.
     *
     *          Idempotent: subsequent calls are no-ops.
     * @param reserved DllMain's lpvReserved (NULL for FreeLibrary, non-NULL for process exit).
     * @note Setup/control-plane only: call it solely from DllMain's DLL_PROCESS_DETACH path.
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
     *          returns SessionShutdownWouldBlock rather than waiting, because the wait is for the calling thread's
     *          own exit. Use request_shutdown() to retire the session from that thread.
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
    enum class LogicDllUnloadStatus : std::uint8_t
    {
        /// With the documented caller-owned preconditions met, DMK no longer blocks unmapping the Logic DLL.
        SafeToUnload,
        /// The Windows loader lock forbids the waits and joins required to certify safe unmapping.
        LoaderLock,
        /// The caller is executing inside an input or config callback and cannot drain itself.
        SelfDelivery,
        /// Another control thread owns the safe-drain transaction.
        InProgress,
        /// Selected input bindings were not retired.
        RetireFailed,
        /// The deadline expired while a callback or worker body remained alive.
        TimedOut
    };

    /// Default deadline for Logic DLL safe-unload preparation.
    inline constexpr std::chrono::milliseconds DEFAULT_LOGIC_DLL_DRAIN_TIMEOUT{500};

    /**
     * @brief Retires named input bindings and config callbacks before a Logic DLL is unmapped.
     * @param binding_names Names registered by the Logic DLL.
     * @param timeout Deadline for the rundown waits. It bounds how long the drain waits for in-flight callbacks and
     *        worker bodies, not the consumer code it then runs: a retired hold's balancing edge and the callable's
     *        capture destructors execute after the deadline is spent and are unbounded.
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
     * @warning The drain runs your balancing callbacks and capture destructors on this thread, after the deadline is
     *          spent, and a BindingGuard release racing it blocks untimed until they finish. Neither wait is bounded,
     *          so hold no lock, and own no join, that any of that code can wait on.
     */
    [[nodiscard]] LogicDllUnloadStatus prepare_logic_dll_unload(
        std::span<const std::string_view> binding_names,
        std::chrono::milliseconds timeout = DEFAULT_LOGIC_DLL_DRAIN_TIMEOUT
    ) noexcept;

    /**
     * @brief Retires every input binding and all config callbacks before Logic DLLs are unmapped.
     * @param timeout Deadline for the rundown waits, as prepare_logic_dll_unload documents.
     * @return SafeToUnload only after every callable copy DMK still owns, and every config setter, is gone. Retirement
     *         reaches callbacks through their delivery gates, as prepare_logic_dll_unload documents.
     * @note Setup/control-plane only. Call from an off-loader-lock shutdown thread, as prepare_logic_dll_unload
     *       documents.
     * @warning The unbounded-consumer-code warning on prepare_logic_dll_unload applies here unchanged.
     * @warning In a multi-Logic-DLL host this retires bindings belonging to every Logic DLL.
     */
    [[nodiscard]] LogicDllUnloadStatus
    prepare_logic_dll_unload_all(std::chrono::milliseconds timeout = DEFAULT_LOGIC_DLL_DRAIN_TIMEOUT) noexcept;

    /**
     * @brief Source-compatible best-effort abandon wrapper.
     * @details Off the loader lock it attempts prepare_logic_dll_unload. Under the loader lock it only closes new
     *          callback admission and requests no blocking rundown.
     * @warning This void result never authorizes FreeLibrary. Use prepare_logic_dll_unload and require SafeToUnload.
     * @note Best-effort: the wrapper fails closed and reports nothing.
     */
    void on_logic_dll_unload(std::span<const std::string_view> binding_names) noexcept;

    /**
     * @brief Source-compatible best-effort abandon wrapper for every binding.
     * @warning This void result never authorizes FreeLibrary. Use prepare_logic_dll_unload_all and require
     *          SafeToUnload.
     * @note Best-effort: the wrapper fails closed and reports nothing.
     */
    void on_logic_dll_unload_all() noexcept;
} // namespace DetourModKit

#endif // DETOURMODKIT_SESSION_HPP
