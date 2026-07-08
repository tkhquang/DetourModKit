#include "DetourModKit.hpp"

#include "DetourModKit/config.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"

#include "platform.hpp"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cwchar>
#include <exception>
#include <optional>
#include <string>
#include <utility>

namespace DetourModKit
{
    namespace
    {
        // Static bootstrap machinery (the async DllMain path only)
        // The synchronous Session::start path touches none of these: it returns a Session the caller holds directly.
        // These statics exist only to host a Session on a worker thread across a DllMain attach/detach pair.
        // Atomic because request_shutdown() may SetEvent it from any consumer thread at any time (its documented
        // contract), concurrently with a teardown path that retires the handle. A plain HANDLE would be a data race,
        // and closing the handle while a request_shutdown() has already loaded it would SetEvent a closed / recycled
        // handle. The teardown paths therefore exchange-to-null and, where a live thread could still race, LEAK the
        // handle rather than close it (see bootstrap_detach).
        std::atomic<HANDLE> s_shutdown_event{nullptr};
        HANDLE s_worker_thread = nullptr;
        HMODULE s_module = nullptr;

        // Idempotency gate for bootstrap_detach; re-armed by a successful bootstrap so attach/detach cycles repeat.
        std::atomic<bool> s_detach_called{false};

        // Single-session-per-process guard, shared by both construction paths. Set by Session::start on success,
        // cleared by ~Session or abandon(). A mod DLL has one process lifetime, so a second start()/bootstrap() is
        // rejected.
        std::atomic<bool> s_session_active{false};

        // The Session built (under the loader lock) by bootstrap, waiting for the worker to adopt it.
        std::optional<Session> s_pending_session;

        // The user init callback, invoked once on the worker thread. Cleared only where running its captured state's
        // destructors is safe: the synchronous setup-failure unwind and the off-loader-lock detach join (both with the
        // DLL still mapped and off any loader lock). It is deliberately LEFT populated on the loader-lock FreeLibrary
        // leak path and the process-death abandon path, where running those destructors under a loader lock or during
        // process teardown is the use-after-unload hazard the leak-on-purpose discipline forbids; the OS reclaims it.
        std::move_only_function<Result<void>(Session &)> s_on_ready;

        // Compares the running executable's basename (case-insensitive) against @p expected. An empty expectation
        // always passes. Resolved as wide (not GetModuleFileNameA) so a non-ASCII EXE basename is not mangled through
        // the active code page and cannot false-match or false-miss the gate.
        bool is_target_process(std::string_view expected) noexcept
        {
            if (expected.empty())
            {
                return true;
            }

            wchar_t exe_path[MAX_PATH]{};
            const DWORD len = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
            if (len == 0 || len >= MAX_PATH)
            {
                return false;
            }

            const wchar_t *exe_name = std::wcsrchr(exe_path, L'\\');
            exe_name = exe_name ? exe_name + 1 : exe_path;

            // Widen the caller-supplied UTF-8 name into a bounded stack buffer for a wide case-insensitive compare. A
            // name that cannot fit a module file name cannot match the running executable. MultiByteToWideChar with a
            // fixed destination and MB_ERR_INVALID_CHARS fails closed (returns 0) on overflow or malformed UTF-8 rather
            // than truncating into a false match.
            if (expected.size() >= MAX_PATH)
            {
                return false;
            }
            wchar_t expected_buf[MAX_PATH];
            const int wide_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, expected.data(),
                                                     static_cast<int>(expected.size()), expected_buf, MAX_PATH - 1);
            if (wide_len <= 0)
            {
                return false;
            }
            expected_buf[wide_len] = L'\0';
            return _wcsicmp(exe_name, expected_buf) == 0;
        }

        // Outcome of a single-instance mutex acquisition. Distinguishing AlreadyHeld from SystemError lets
        // Session::start map each to its own ErrorCode (InstanceAlreadyRunning vs SystemCallFailed).
        enum class MutexAcquire : std::uint8_t
        {
            /// A fresh mutex was created; @p out holds the handle the Session must close.
            Acquired,
            /// No prefix was requested; @p out is null and no single-instance guard exists.
            NoGuard,
            /// The named mutex already existed: another load of this mod is live.
            AlreadyHeld,
            /// CreateMutexW failed, or the name could not be built; @p err holds GetLastError().
            SystemError
        };

        // Builds a per-PID named mutex from @p prefix and reports whether this load won the single-instance race. The
        // name is built in a std::wstring (not a fixed buffer) because the prefix is caller-supplied and unbounded;
        // CreateMutexW rejects an over-long name on its own, surfaced as the null-handle SystemError below.
        MutexAcquire acquire_instance_mutex(std::string_view prefix, HANDLE &out, DWORD &err) noexcept
        {
            out = nullptr;
            err = 0;
            if (prefix.empty())
            {
                return MutexAcquire::NoGuard;
            }

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
                // Out of memory building the name. Report a system error (Session::start maps it to SystemCallFailed)
                // rather than let the throw escape this noexcept path.
                return MutexAcquire::SystemError;
            }

            HANDLE handle = CreateMutexW(nullptr, FALSE, mutex_name.c_str());
            if (!handle)
            {
                err = GetLastError();
                return MutexAcquire::SystemError;
            }
            if (GetLastError() == ERROR_ALREADY_EXISTS)
            {
                CloseHandle(handle);
                return MutexAcquire::AlreadyHeld;
            }
            out = handle;
            return MutexAcquire::Acquired;
        }

        // The ordered process-wide subsystem teardown that ~Session runs after clearing the session's own scope. This
        // is the single home for the teardown ordering: reverse dependency order, with the logger LAST because every
        // prior step may still log. Each leaf shutdown embeds its OWN loader-lock guard (join when safe,
        // detach-and-leak when the loader lock is held), so this function delegates the join/leak decision to the
        // leaves rather than making one central, and therefore wrong, choice.
        void run_subsystem_teardown() noexcept
        {
            // 1. Config auto-reload watcher first: its background thread can fire the user on_reload callback at any
            //    moment, so it must stop before any state that callback might touch is torn down.
            config::disable_auto_reload();
            // 2. Input poll thread (may invoke callbacks that log).
            input::Input::instance().shutdown();
            // 3. Memory cache cleanup thread (must stop before the logger it may log through).
            memory::shutdown_cache();
            // 4. Config registry: drops the bound std::function setters.
            config::clear();
            // 5. Logger last: flush and close the sink. Nothing may log after this.
            log().shutdown();
        }

        // Resets any partially-built bootstrap state after a setup failure. Destroying s_pending_session runs a clean
        // ~Session, which tears down whatever start() already configured.
        void unwind_bootstrap() noexcept
        {
            // Setup-failure unwind. bootstrap_core publishes s_shutdown_event before the acquire_module_ref /
            // CreateThread steps that fail into here, so the handle can already be visible to another thread. This runs
            // while the process is live, and on a re-bootstrap the consumer has held control before (the prior session
            // cleaned these statics for reuse), so a leftover consumer thread may call request_shutdown() -- documented
            // safe from any thread at any time -- and load the handle concurrently. Closing it would then race a
            // SetEvent onto a closed / recycled handle, the exact hazard the atomic keeps out. Retire it to null and
            // LEAK the one small event object instead of closing it, matching the off-loader-lock detach path; the OS
            // reclaims it at process exit. Closing is safe only where no live thread can race, which for the event is
            // the process-death detach alone.
            s_shutdown_event.store(nullptr, std::memory_order_release);
            if (s_worker_thread)
            {
                CloseHandle(s_worker_thread);
                s_worker_thread = nullptr;
            }
            if (s_pending_session)
            {
                s_pending_session.reset();
            }
            // Drop the staged init callback. This is a synchronous setup-failure path (the worker was never created, so
            // nothing is using it), and the DLL is still fully mapped, so destroying the never-invoked callback now is
            // safe. Leaving it populated would strand a callable whose destructor lives in .text the loader unmaps once
            // DllMain returns FALSE, so a later destruction (a retry's overwrite, or the process-exit static dtor)
            // would fault into freed pages.
            s_on_ready = nullptr;
            s_module = nullptr;
        }

        // The bootstrap worker. Adopts the Session built under the loader lock, runs on_ready OFF the loader lock, then
        // blocks until detach signals it and lets the Session destruct (the ordered teardown) here, off the loader
        // lock, so every subsystem leaf JOINS cleanly.
        DWORD WINAPI lifecycle_thread(LPVOID param) noexcept
        {
            const HMODULE self_ref = static_cast<HMODULE>(param);
            if (!s_pending_session)
            {
                // Should never happen: the worker is spawned only after the Session is staged. Guard defensively rather
                // than dereference an empty optional. If bootstrap_core handed this worker a module reference, release
                // it with FreeLibraryAndExitThread so the thread never returns through code it may have unmapped.
                if (self_ref != nullptr)
                {
                    FreeLibraryAndExitThread(self_ref, 0);
                }
                return 0;
            }

            {
                Session session = std::move(*s_pending_session);
                s_pending_session.reset();

                if (s_on_ready)
                {
                    try
                    {
                        Result<void> ready = s_on_ready(session);
                        if (!ready)
                        {
                            (void)log().try_log(LogLevel::Error, "bootstrap: on_ready reported failure: {}",
                                                ready.error().message());
                        }
                    }
                    catch (const std::exception &e)
                    {
                        (void)log().try_log(LogLevel::Error, "bootstrap: on_ready threw: {}", e.what());
                    }
                    catch (...)
                    {
                        (void)log().try_log(LogLevel::Error, "bootstrap: on_ready threw an unknown exception.");
                    }
                }

                if (HANDLE event = s_shutdown_event.load(std::memory_order_acquire))
                {
                    WaitForSingleObject(event, INFINITE);
                }

                // `session` destructs at the end of this inner scope -> ordered teardown off the loader lock -> leaves
                // JOIN, all while self_ref keeps this module's code mapped through the teardown.
            }

            if (self_ref != nullptr)
            {
                // The worker is done. Drop its own reference and exit the thread atomically: FreeLibraryAndExitThread
                // never returns, so the FreeLibrary's return address is never in code the release may unmap. This
                // release may be the terminal one if the consumer already dropped its LoadLibrary reference after
                // request_shutdown(), so the worker must not call plain FreeLibrary and then return through this
                // module.
                FreeLibraryAndExitThread(self_ref, 0);
            }

            // Defensive fallback for an invalid worker parameter. bootstrap_core never starts this thread without a
            // module reference, but a plain return is the only valid path when there is no reference to release.
            return 0;
        }

        // The throwing core of bootstrap, separated so the public entry point stays noexcept under the loader lock.
        [[nodiscard]] Result<void> bootstrap_core(const ModInfo &info,
                                                  std::move_only_function<Result<void>(Session &)> on_ready)
        {
            if (s_worker_thread || s_shutdown_event.load(std::memory_order_acquire))
            {
                return std::unexpected(Error{ErrorCode::SessionAlreadyActive, "bootstrap"});
            }

            // Auto-capture the calling module. DetourModKit links statically into the mod DLL, so a DetourModKit code
            // address resolves to the mod's own HMODULE -- exactly the handle DllMain would receive -- letting the
            // consumer's DllMain forward attach without threading the handle through. UNCHANGED_REFCOUNT is required:
            // this handle is for identity only (module_handle()), so it must NOT take a reference on the module. The
            // keepalive that protects the worker's code from a premature FreeLibrary is a SEPARATE counted reference
            // acquired immediately before CreateThread and handed to lifecycle_thread; keeping that concern out of
            // s_module lets module_handle() name the module without holding it mapped, and confines the "the module
            // stays mapped past a bare FreeLibrary" behavior to the worker's own lifetime.
            constexpr DWORD CAPTURE_FLAGS =
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
            if (GetModuleHandleExW(CAPTURE_FLAGS, reinterpret_cast<LPCWSTR>(&bootstrap_core), &s_module))
            {
                DisableThreadLibraryCalls(s_module);
            }

            // Run the same synchronous setup as the direct path (process gate, single-instance mutex, logger). On
            // failure, roll back the module capture and surface the error to the caller's DllMain.
            Result<Session> session = Session::start(info);
            if (!session)
            {
                s_module = nullptr;
                return std::unexpected(session.error());
            }

            // Stage the Session and the init callback for the worker to adopt.
            s_pending_session.emplace(std::move(*session));
            s_on_ready = std::move(on_ready);

            // Create into a local first, then publish with a release store so the worker's / consumer's acquire load
            // observes a fully-constructed handle. The guard above already proved s_shutdown_event was null. The TRUE
            // second argument makes this a MANUAL-RESET event: a shutdown request is a one-way latch, so once
            // request_shutdown() signals it the event stays signaled -- the worker observes it whether or not it was
            // already waiting, and a repeated request_shutdown() is idempotent (an auto-reset event would clear itself
            // after a single wait woke and could drop a later observer).
            const HANDLE shutdown_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!shutdown_event)
            {
                const DWORD err = GetLastError();
                unwind_bootstrap();
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "bootstrap", err});
            }
            s_shutdown_event.store(shutdown_event, std::memory_order_release);

            // Acquire the worker's module reference BEFORE CreateThread. A thread created from DllMain may not execute
            // its entry point until after the loader releases the attach notification, but the caller can FreeLibrary
            // immediately after LoadLibrary returns. The reference therefore has to exist before the worker is
            // scheduled, not at the top of the worker function.
            const HMODULE worker_ref = detail::acquire_module_ref();
            if (worker_ref == nullptr)
            {
                const DWORD err = GetLastError();
                unwind_bootstrap();
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "bootstrap", err});
            }

            s_worker_thread = CreateThread(nullptr, 0, lifecycle_thread, worker_ref, 0, nullptr);
            if (!s_worker_thread)
            {
                const DWORD err = GetLastError();
                detail::release_module_ref(worker_ref);
                unwind_bootstrap();
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "bootstrap", err});
            }

            // Re-arm the detach gate now that a fresh attach fully succeeded, so the matching bootstrap_detach runs its
            // teardown instead of no-opping. Only on the success path: early failures never set it.
            s_detach_called.store(false, std::memory_order_release);
            return {};
        }
    } // anonymous namespace

    Session::Session(void *instance_mutex) noexcept : m_instance_mutex(instance_mutex), m_active(true) {}

    Session::Session(Session &&other) noexcept
        : m_scope(std::move(other.m_scope)), m_instance_mutex(other.m_instance_mutex), m_active(other.m_active)
    {
        // Leave the source inert so its destructor does nothing: exactly one Session ever carries the live teardown.
        other.m_instance_mutex = nullptr;
        other.m_active = false;
    }

    Session &Session::operator=(Session &&other) noexcept
    {
        if (this != &other)
        {
            // Assigning over a live Session ends it: run the full ordered teardown of THIS session first (which also
            // clears the single-session guard), then adopt the source. A mod holds one session at a time, so the source
            // is always inert here; a no-op release() when this Session is already inert makes the common
            // reassign-a-moved-from-Session case free.
            release();
            m_scope = std::move(other.m_scope);
            m_instance_mutex = other.m_instance_mutex;
            m_active = other.m_active;
            other.m_instance_mutex = nullptr;
            other.m_active = false;
        }
        return *this;
    }

    Session::~Session() noexcept
    {
        // Moved-from or abandon()ed sessions are inert, so release() is a no-op and a double-drop never
        // double-tears-down.
        release();
    }

    void Session::release() noexcept
    {
        if (!m_active)
        {
            return;
        }

        // 1. Release this session's input bindings first, in reverse insertion order (a Hold binding's release edge
        //    fires before the bindings it may depend on).
        m_scope.clear();
        // 2. Ordered process-wide subsystem teardown (logger last).
        run_subsystem_teardown();
        // 3. Release the single-instance guard so a subsequent load starts clean.
        if (m_instance_mutex)
        {
            CloseHandle(static_cast<HANDLE>(m_instance_mutex));
            m_instance_mutex = nullptr;
        }
        m_active = false;
        s_session_active.store(false, std::memory_order_release);
    }

    Result<Session> Session::start(const ModInfo &info) noexcept
    {
        // Claim the single-session guard first; a mod DLL has one process lifetime, so a second start is a caller bug.
        bool expected = false;
        if (!s_session_active.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return std::unexpected(Error{ErrorCode::SessionAlreadyActive, "Session::start"});
        }

        if (!is_target_process(info.game_process_name))
        {
            // A clean "not for this process" outcome, not a fault: release the guard and let the caller decline to
            // load.
            s_session_active.store(false, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::ProcessMismatch, "Session::start"});
        }

        HANDLE mutex = nullptr;
        DWORD err = 0;
        switch (acquire_instance_mutex(info.instance_mutex_prefix, mutex, err))
        {
        case MutexAcquire::AlreadyHeld:
            s_session_active.store(false, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::InstanceAlreadyRunning, "Session::start"});
        case MutexAcquire::SystemError:
            s_session_active.store(false, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::SystemCallFailed, "Session::start", err});
        case MutexAcquire::NoGuard:
        case MutexAcquire::Acquired:
            break;
        }

        // Logger::configure builds std::string / std::wstring for the prefix and path and can raise bad_alloc; keep the
        // noexcept contract by catching here and undoing the mutex and the guard before returning OutOfMemory.
        try
        {
            Logger::configure(info.name, info.log_file);
            // Qualified: inside this static member the free accessor is hidden by the non-static Session::log().
            DetourModKit::log().enable_async_mode(info.log);
        }
        catch (...)
        {
            if (mutex)
            {
                CloseHandle(mutex);
            }
            s_session_active.store(false, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::OutOfMemory, "Session::start"});
        }

        // The Session now owns the guard (cleared by ~Session) and the mutex handle (closed by ~Session).
        return Session(mutex);
    }

    Logger &Session::log() const noexcept
    {
        // Qualified: the member Session::log() would otherwise hide the free accessor and recurse.
        return DetourModKit::log();
    }

    config::Ini Session::ini() const noexcept
    {
        return config::Ini{};
    }

    input::Input &Session::input() const noexcept
    {
        return input::Input::instance();
    }

    input::Scope &Session::scope() noexcept
    {
        return m_scope;
    }

    void Session::abandon() noexcept
    {
        // Neutralize so ~Session does nothing. No teardown, no unhook, no flush, no join: for process death only, where
        // the OS is reclaiming the address space and touching subsystem state is a use-after-free with no benefit. The
        // single-instance mutex handle is intentionally left for the OS to reclaim at exit.
        m_active = false;
        m_instance_mutex = nullptr;
        s_session_active.store(false, std::memory_order_release);
    }

    // Bootstrap free functions

    Result<void> bootstrap(const ModInfo &info, std::move_only_function<Result<void>(Session &)> on_ready) noexcept
    {
        // Fail closed on any throw so nothing unwinds across the loader lock; the partial attach is rolled back.
        try
        {
            return bootstrap_core(info, std::move(on_ready));
        }
        catch (...)
        {
            unwind_bootstrap();
            return std::unexpected(Error{ErrorCode::OutOfMemory, "bootstrap"});
        }
    }

    void bootstrap_detach(void *reserved) noexcept
    {
        bool expected = false;
        if (!s_detach_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return;
        }

        if (reserved != nullptr)
        {
            // PROCESS TERMINATION (abandon). The OS has already killed the worker; its adopted Session lives in that
            // dead frame and is leaked untouched -- running teardown against a dying process is a use-after-free. If
            // the worker never adopted the staged Session, neutralize it so its eventual destructor does nothing
            // either.
            if (s_pending_session)
            {
                s_pending_session->abandon();
                s_pending_session.reset();
            }
            if (s_worker_thread)
            {
                CloseHandle(s_worker_thread);
                s_worker_thread = nullptr;
            }
            // Process termination: with reserved != nullptr the OS has already terminated every other thread before
            // this DllMain notification, so no request_shutdown() can be in flight and closing the event is safe.
            if (HANDLE event = s_shutdown_event.exchange(nullptr, std::memory_order_acq_rel))
            {
                CloseHandle(event);
            }
            s_module = nullptr;
            diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Bootstrap);
            return;
        }

        // EXPLICIT FreeLibrary. Signal the worker so its ~Session teardown runs OFF the loader lock (leaves JOIN).
        if (HANDLE event = s_shutdown_event.load(std::memory_order_acquire))
        {
            SetEvent(event);
        }

        if (detail::is_loader_lock_held())
        {
            // Under the loader lock: never wait or join here -- blocking would deadlock any peer DllMain. Crucially, do
            // NOT CloseHandle s_shutdown_event or s_worker_thread here: the process keeps running and, if the worker is
            // still parked on the event, closing them would be an unsynchronized write racing the worker's read (UB)
            // and a wait-on-a-closed/recycled-handle. Leak both handles instead -- the OS reclaims them at process exit
            // -- and record the intentional leak.
            //
            // No module pin is taken here, and none is needed: the worker holds its own counted reference on this
            // module, acquired before CreateThread and released only when the worker exits. That is what keeps the
            // worker's code mapped. Because the worker holds that reference, a bare FreeLibrary of a bootstrapped mod
            // does not drive the count to zero and so does not even reach this branch. After request_shutdown(), this
            // branch can run either from the consumer's final FreeLibrary (if the worker has already released its
            // reference) or from the worker's own FreeLibraryAndExitThread terminal release (if the consumer dropped
            // its reference first). Both cases are loader-lock contexts, so this path only records the intentional
            // handle leak.
            diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Bootstrap);
            s_module = nullptr;
            return;
        }

        // Off the loader lock (a pre-unload request_shutdown handshake, or a test harness): the worker can be joined
        // safely, so wait for it to finish its ordered ~Session teardown before returning. This yields a fully drained,
        // deterministic unload and leaves the statics clean for a subsequent bootstrap. The worker's own leaf shutdowns
        // observe is_loader_lock_held() == false on their thread and join their subsystem threads in turn.
        if (s_worker_thread)
        {
            WaitForSingleObject(s_worker_thread, INFINITE);
            CloseHandle(s_worker_thread);
            s_worker_thread = nullptr;
        }
        // Do NOT close the event here. This path runs while the process is still live (an off-loader-lock unload
        // handshake or a test harness), so a consumer thread may call request_shutdown() -- documented safe from any
        // thread, even after teardown -- at any moment. Closing the handle would let a request_shutdown() that already
        // loaded it SetEvent a closed / recycled handle. Retire it to null (so a later load no-ops) and leak the one
        // tiny manual-reset event object; the OS reclaims it at process exit. Leaking one kernel handle per off-loader
        // unload is the accepted cost of an always-safe request_shutdown().
        s_shutdown_event.store(nullptr, std::memory_order_release);
        // The worker has joined, so the init callback is no longer in use. Off the loader lock its captured state's
        // destructors are safe to run, so drop it here rather than leaking it until the next bootstrap overwrites it.
        s_on_ready = nullptr;
        s_module = nullptr;
    }

    void request_shutdown() noexcept
    {
        // Safe from any thread at any time (including after teardown). The acquire load pairs with the release stores
        // in bootstrap_core (publish) and the teardown paths (retire-to-null). Because the teardown paths that run
        // while the process is live LEAK the handle instead of closing it, a non-null load here is always a still-valid
        // event, so the SetEvent can never land on a closed / recycled handle. A null load means teardown already
        // retired it, and the no-op is the documented "already torn down" behaviour.
        if (HANDLE event = s_shutdown_event.load(std::memory_order_acquire))
        {
            SetEvent(event);
        }
    }

    ModuleHandle module_handle() noexcept
    {
        return s_module;
    }

    // Test-only accessor for the bootstrap shutdown event handle (the atomic load). A test captures it before an
    // off-loader-lock bootstrap_detach and then confirms that path LEAKED the handle (it stays a valid kernel object)
    // rather than CloseHandle-ing it, which is the race request_shutdown() must never lose. Not declared in any public
    // header; the test extern-declares it (the same discipline as the loader-lock override seams).
    HANDLE bootstrap_shutdown_event_for_test() noexcept
    {
        return s_shutdown_event.load(std::memory_order_acquire);
    }

    // Hot-reload helpers

    void on_logic_dll_unload(std::span<const std::string_view> binding_names) noexcept
    {
        Logger &logger = log();
        size_t bindings_removed = 0;

        for (const auto name : binding_names)
        {
            try
            {
                // Pass invoke_callbacks == false: this helper is documented as safe from DllMain detach paths, and a
                // held binding's on_state_change(false) release callback lives in the unloading Logic DLL. Running it
                // under a loader lock is the deadlock-or-crash vector the leak-on-purpose discipline forbids.
                bindings_removed += input::Input::instance().remove_bindings_by_name(name, false);
            }
            catch (const std::exception &e)
            {
                // The formatted logger.error can itself throw (bad_alloc while rendering, or a sink error), so wrap it:
                // this is a noexcept helper on a DllMain / loader-lock path, where an escaping throw reaches
                // std::terminate and takes down the host. Same guarding as on_logic_dll_unload_all below.
                try
                {
                    logger.error("on_logic_dll_unload: exception removing binding '{}': {}", name, e.what());
                }
                catch (...)
                {
                }
            }
            catch (...)
            {
                try
                {
                    logger.error("on_logic_dll_unload: unknown exception removing binding '{}'.", name);
                }
                catch (...)
                {
                }
            }
        }

        try
        {
            logger.info("on_logic_dll_unload: drained {} binding(s).", bindings_removed);
        }
        catch (...)
        {
        }

        // Wipe the config registry last: the prior binding teardown may fire a registered setter one final time (a
        // setter observing a binding-driven flag, say), and clearing first would orphan that final-fire path mid-call.
        // The registered std::function setters' call operators and destructors live in the unloading Logic DLL's .text,
        // so any survivor becomes a use-after-unload hazard once the loader reclaims those pages.
        //
        // Stop the auto-reload watcher before wiping the registry: its worker can fire reload() (running those setters)
        // at any time, and both the user on_reload callback and the setters live in the unloading Logic DLL. A survivor
        // would call into unmapped pages after the DLL goes away, and would make the next load's enable_auto_reload()
        // report AlreadyRunning instead of starting fresh. disable_auto_reload() is noexcept and a no-op when idle.
        config::disable_auto_reload();
        config::clear();
    }

    void on_logic_dll_unload_all() noexcept
    {
        Logger &logger = log();

        // clear_bindings() leaves the poll thread running and ready for fresh bindings, matching the "tear down
        // per-Logic-DLL state but keep the manager re-usable" contract. Pass invoke_callbacks == false for the same
        // loader-lock reason as the named overload: user release callbacks live in the unloading Logic DLL.
        bool bindings_cleared = false;
        try
        {
            input::Input::instance().clear_bindings(false);
            bindings_cleared = true;
        }
        catch (const std::exception &e)
        {
            try
            {
                logger.error("on_logic_dll_unload_all: exception in clear_bindings: {}", e.what());
            }
            catch (...)
            {
            }
        }
        catch (...)
        {
            try
            {
                logger.error("on_logic_dll_unload_all: unknown exception in clear_bindings.");
            }
            catch (...)
            {
            }
        }

        // Only claim success when clear_bindings actually completed: on a caught throw the error above already recorded
        // the partial teardown, so an unconditional "drained all bindings" would misreport it as a clean drain.
        if (bindings_cleared)
        {
            try
            {
                logger.info("on_logic_dll_unload_all: drained all bindings.");
            }
            catch (...)
            {
            }
        }

        // Wipe the config registry last, for the same use-after-unload reasons as the named overload; stop the
        // auto-reload watcher first so its reload() worker cannot fire a setter into unmapped pages.
        config::disable_auto_reload();
        config::clear();
    }
} // namespace DetourModKit
