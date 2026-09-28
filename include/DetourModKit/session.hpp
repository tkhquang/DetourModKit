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

struct HINSTANCE__;

namespace DetourModKit
{
    /** @brief Opaque Win32 module handle, identical to HMODULE. This header does not include <windows.h>. */
    using ModuleHandle = ::HINSTANCE__ *;

    namespace detail
    {
        struct SessionBootstrapAccess;
    } // namespace detail

    /**
     * @brief Identity, single-instance gating, process gating, and async-logger settings for a mod.
     * @details Every entry point copies each field that it keeps before it returns, so a field needs to outlive only
     *          the call. @p name is the mod identity and the logger prefix. A non-empty @p game_process_name must match
     *          the executable basename, or start() returns ErrorCode::ProcessMismatch. The match folds case on UTF-8
     *          through CompareStringOrdinal and ignores the C runtime locale. A non-empty @p instance_mutex_prefix
     *          creates a per-PID named mutex, so a second load of the mod fails with ErrorCode::InstanceAlreadyRunning.
     */
    struct ModInfo
    {
        std::string_view name{};
        std::string_view log_file{};
        std::string_view game_process_name{};
        std::string_view instance_mutex_prefix{};
        AsyncLoggerConfig log{};
        /** @brief Selects the process-default logger's first sink open. See @ref LogOpenMode. */
        LogOpenMode log_open_mode{LogOpenMode::Truncate};
        /// The source-location stamp policy for formatted records. See @ref LogSourceStampMode.
        LogSourceStampMode log_source_stamp_mode{};
    };

    /**
     * @brief Owns a mod's process lifetime: single-instance guard, logger configuration, input scope, and teardown.
     * @details ~Session and active move-assignment run the ordered teardown. First, scope().clear() releases this
     *          session's input bindings in reverse insertion order. The process-wide subsystems then tear down in
     *          reverse dependency order. The order is the config auto-reload watcher, the input poll thread, the memory
     *          cache, the config registry, the diagnostics TLS index, and the logger. Under the loader lock, or in an
     *          attach or unload phase off the bootstrap worker, no subsystem shutdown joins a thread. The Session owns
     *          no Hook: a Hook handle unhooks when the caller drops it.
     * @note A moved-from or abandon()ed Session is inert: its destructor does nothing. One Session is active at a time.
     *       A second start() returns ErrorCode::SessionAlreadyActive, and a second bootstrap entry returns the code
     *       that identifies the current bootstrap slot owner.
     * @note The init/teardown thread runs Session::start, on_ready, ~Session, and abandon() single-threaded. Do not
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
         * @return The live Session, or ProcessMismatch, InstanceAlreadyRunning, or SessionAlreadyActive (see ModInfo
         *         and Session). A failed Win32 lifecycle call, or an instance_mutex_prefix longer than 32757 bytes,
         *         returns SystemCallFailed with a Win32 error code in Error::detail. A thrown std::bad_alloc maps to
         *         OutOfMemory, and any other exception maps to Unknown.
         * @note Setup/control-plane only. If the logger refuses async mode, start succeeds with synchronous logging.
         * @warning See the class `[B-100]` loader-lock warning.
         */
        [[nodiscard]] static Result<Session> start(const ModInfo &info) noexcept;

        /** @brief Transfers the live teardown and leaves @p other inert. */
        Session(Session &&other) noexcept;
        /**
         * @brief Runs the ordered teardown if this Session is active, then adopts @p other.
         * @note Setup/control-plane only.
         * @warning See the class `[B-100]` loader-lock warning.
         */
        Session &operator=(Session &&other) noexcept;
        /** @brief Deleted: the teardown and the single-instance guard have one owner. */
        Session(const Session &) = delete;
        Session &operator=(const Session &) = delete;

        /**
         * @brief Runs the ordered teardown if this Session is active.
         * @note Setup/control-plane only.
         * @warning See the class `[B-100]` loader-lock warning.
         */
        ~Session() noexcept;

        /** @brief The process-default logger that this session configured, the same as `DetourModKit::log()`. */
        [[nodiscard]] Logger &log() const noexcept;

        /** @brief A handle to the process configuration registry. After the binds exist, call `load(path)` on it. */
        [[nodiscard]] config::Ini ini() const noexcept;

        /** @brief The process input manager, the same as `input::Input::instance()`. */
        [[nodiscard]] input::Input &input() const noexcept;

        /** @brief This session's input binding scope for BindingGuards. */
        [[nodiscard]] input::Scope &scope() noexcept;

        /** @brief True while this Session is active, false once it is moved-from or abandon()ed. */
        [[nodiscard]] explicit operator bool() const noexcept { return m_active; }

        /**
         * @brief Makes the Session inert: its destructor runs no scope clear, teardown, flush, or join.
         * @details Call it only for DLL_PROCESS_DETACH with `lpReserved != NULL` (process termination), where a
         *          teardown risks a use after free. Never call it for an explicit FreeLibrary (`lpReserved == NULL`).
         * @note Setup/control-plane only.
         */
        void abandon() noexcept;

    private:
        friend struct detail::SessionBootstrapAccess;

        // The Session owns instance_mutex until release(). Null means that ModInfo requested no guard.
        explicit Session(void *instance_mutex) noexcept;

        void release() noexcept;

        input::Scope m_scope;
        void *m_instance_mutex{nullptr};
        bool m_active{false};
    };

    /// The plain on_ready callback type of bootstrap_attach().
    using BootstrapReadyFn = Result<void> (*)(Session &);

    /**
     * @brief DllMain DLL_PROCESS_ATTACH entry point: runs the loader-safe gates, then starts the Session on a worker.
     * @details It captures the handle of the mod DLL that links this DetourModKit copy. It calls
     *          DisableThreadLibraryCalls and runs the process and single-instance gates without heap allocation. The
     *          worker configures the logger and runs @p on_ready off the loader lock. There it can allocate, load INIs,
     *          install hooks, and register bindings into session.scope(). It then waits until bootstrap_detach(),
     *          request_shutdown(), or shutdown_and_wait() wakes it, and destroys the Session off the loader lock. If
     *          @p on_ready fails, the worker logs the error and still waits, with the Session live and the DLL mapped.
     * @param on_ready Called once on the worker thread with the live Session. A null value registers no callback.
     * @return An empty Result once the worker is published, or ProcessMismatch, InstanceAlreadyRunning,
     *         SessionAlreadyActive, InvalidArg, SessionShutdownInProgress, SessionShutdownUnavailable, or
     *         SystemCallFailed. InvalidArg means that ModInfo::name or ModInfo::log_file is longer than 32768 bytes.
     *         Pre-publication failures roll back the mutex and the bootstrap slot.
     * @note Setup/control-plane only. The synchronous phase calls no logger, callback, or wait.
     */
    [[nodiscard]] Result<void> bootstrap_attach(const ModInfo &info, BootstrapReadyFn on_ready) noexcept;

    /**
     * @brief The off-DllMain form of bootstrap_attach(), with the same results. Its callable can own move-only state.
     * @note Setup/control-plane only.
     * @warning Do not call it from DllMain. The callable conversion can allocate at the call site. A pre-publication
     *          failure destroys the callable and its captures on the current thread.
     */
    [[nodiscard]] Result<void>
    bootstrap(const ModInfo &info, std::move_only_function<Result<void>(Session &)> on_ready) noexcept;

    /**
     * @brief DllMain DLL_PROCESS_DETACH entry point. Pass DllMain's lpvReserved as @p reserved.
     * @details If @p reserved is NULL (explicit FreeLibrary), it destroys no callback state. From a Ready slot, it
     *          also signals the worker and retires the slot permanently. While the worker is live, a bare
     *          FreeLibrary cannot reach this call, because the worker holds a counted module reference. For a drained
     *          unload, call shutdown_and_wait() before FreeLibrary.
     *
     *          If @p reserved is not NULL (process termination), the OS already killed the worker, so this path skips
     *          the teardown, flush, and join. Neither path waits or joins, so both are loader-lock-safe. Both publish
     *          an unload phase, so a later subsystem shutdown off the bootstrap worker joins no thread.
     * @note Setup/control-plane only. Call it only from DllMain's DLL_PROCESS_DETACH path. A later call only
     *       republishes the unload phase.
     */
    void bootstrap_detach(void *reserved) noexcept;

    /**
     * @brief Requests asynchronous teardown of the bootstrap worker.
     * @details It does nothing if no bootstrap entry ran or the teardown completed. To drain the module before
     *          FreeLibrary, use shutdown_and_wait().
     * @note Callback-safe: call it from any thread (a hook, an input callback, or DllMain). It only signals an event
     *       and never allocates, waits, or joins.
     */
    void request_shutdown() noexcept;

    /**
     * @brief Signals the bootstrap worker and waits for its complete off-loader-lock teardown.
     * @details If a bootstrap worker is live, success means that the worker exited, released its counted module
     *          reference, and drained every Session-owned subsystem. After a completed drain, or with no bootstrap
     *          entry, the call returns success and does nothing.
     * @return Success after a complete drain. SessionShutdownInProgress if another control thread owns the drain or a
     *         bootstrap entry claims the slot. SessionShutdownUnavailable if DllMain detach claimed the slot.
     *         SessionShutdownWouldBlock if the calling thread holds the loader lock or is the bootstrap worker.
     *         SystemCallFailed with Error::detail = GetLastError() if the worker-handle wait fails.
     * @note Setup/control-plane only. Call it before FreeLibrary, never from DllMain, a hook, or an input callback.
     * @warning On the bootstrap worker (in on_ready or a callback that its teardown reaches), use request_shutdown().
     */
    [[nodiscard]] Result<void> shutdown_and_wait() noexcept;

    /**
     * @brief The HMODULE of the module that links this DetourModKit copy, or nullptr outside the session window.
     * @details Session::start and a bootstrap entry publish it after the process and instance gates pass, before their
     *          fallible setup completes. A concurrent reader can observe it before the call returns, and a failure in
     *          that setup clears it. It is null before either call, after ~Session, after bootstrap_detach(), and after
     *          a successful shutdown_and_wait(). To use the handle after ~Session or a drain, capture it first.
     *          SessionStart.PublishesModuleIdentityForTheSessionLifetime proves the synchronous path.
     * @note Callback-safe: a lock-free atomic load returns the current identity or null, even during a detach.
     */
    [[nodiscard]] ModuleHandle module_handle() noexcept;

    /** @brief The status of a Logic DLL unload preparation for consumer-owned callback state. */
    enum class LogicDllUnloadStatus : std::uint8_t
    {
        /// With the caller-owned preconditions met, DMK holds nothing that blocks the Logic DLL unmap.
        SafeToUnload,
        /// The loader lock, or an attach or unload phase off the bootstrap worker, forbids the drain waits and joins.
        LoaderLock,
        /// The caller runs inside an input or config callback and cannot drain itself.
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
     * @brief Retires the named input bindings and all config callbacks before a Logic DLL is unmapped.
     * @details A completed config drain also stops auto-reload and the reload hotkey, then runs config::clear().
     * @param timeout Bounds the waits for in-flight callbacks and worker bodies, not the consumer code in the warning.
     * @return SafeToUnload only after every callable copy that DMK still owns for the named bindings, and every config
     *         setter from the old lifecycle, is gone. An outstanding BindingGuard does not keep a callback alive. A
     *         still-held Hold binding receives its balancing on_state_change(false) during the drain, while the DLL is
     *         still mapped. The drain includes a balancing edge that a concurrent guard release already started.
     * @note A guard retained across a successful drain stays valid and still lifts its binding's passthrough
     *       suppression when released.
     * @note Setup/control-plane only. Before you call it, stop consumer-owned workers and drop dispatcher subscriptions
     *       and hook handles. Call it from an off-loader-lock shutdown thread.
     * @warning The drain runs your balancing callbacks and capture destructors on this thread, after the deadline is
     *          spent. A BindingGuard release that races the drain blocks until they finish. Neither wait is bounded, so
     *          hold no lock and own no join that any of that code can wait on.
     */
    [[nodiscard]] LogicDllUnloadStatus prepare_logic_dll_unload(
        std::span<const std::string_view> binding_names,
        std::chrono::milliseconds timeout = DEFAULT_LOGIC_DLL_DRAIN_TIMEOUT
    ) noexcept;

    /**
     * @brief Retires every input binding and all config callbacks before Logic DLLs are unmapped.
     * @return SafeToUnload only after every callable copy that DMK still owns, and every config setter, is gone.
     * @note Setup/control-plane only. Every precondition and rule of prepare_logic_dll_unload applies.
     * @warning The prepare_logic_dll_unload warning applies. It retires the bindings of every Logic DLL in the host.
     */
    [[nodiscard]] LogicDllUnloadStatus
    prepare_logic_dll_unload_all(std::chrono::milliseconds timeout = DEFAULT_LOGIC_DLL_DRAIN_TIMEOUT) noexcept;

    /**
     * @brief Calls prepare_logic_dll_unload with the default deadline and discards the status.
     * @details If blocking teardown is not permitted on this thread, it closes new callback admission, disables config
     *          reloads, and does not wait.
     * @note Best-effort: the wrapper fails closed.
     * @warning This void result never authorizes FreeLibrary. Require SafeToUnload from prepare_logic_dll_unload.
     */
    void on_logic_dll_unload(std::span<const std::string_view> binding_names) noexcept;

    /**
     * @brief Acts as on_logic_dll_unload for every binding, through prepare_logic_dll_unload_all.
     * @note Best-effort: the wrapper fails closed.
     * @warning This void result never authorizes FreeLibrary. Require SafeToUnload from prepare_logic_dll_unload_all.
     */
    void on_logic_dll_unload_all() noexcept;
} // namespace DetourModKit

#endif // DETOURMODKIT_SESSION_HPP
