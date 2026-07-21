#include "DetourModKit/session.hpp"

#include "DetourModKit/config.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"

#include "internal/config_reload_gate.hpp"
#include "internal/lifecycle_context.hpp"
#include "platform.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <exception>
#include <new>
#include <optional>
#include <string_view>
#include <utility>

namespace DetourModKit
{
    namespace detail
    {
        struct SessionBootstrapAccess
        {
            [[nodiscard]] static Session make(void *instance_mutex) noexcept { return Session(instance_mutex); }
        };
    } // namespace detail

    namespace
    {
        // Static bootstrap machinery (the async DllMain path only)
        // The synchronous Session::start path touches none of these: it returns a Session the caller holds directly.
        // These statics exist only to host a Session on a worker thread across a DllMain attach/detach pair.
        // request_shutdown() may signal from any thread while a control thread retires the event. The high bit closes
        // admission; the remaining bits count callers that may already have loaded the handle.
        constexpr std::uint64_t SHUTDOWN_EVENT_RETIRED = std::uint64_t{1} << 63;
        constexpr std::uint64_t SHUTDOWN_EVENT_READER_MASK = ~SHUTDOWN_EVENT_RETIRED;
        constexpr size_t SHUTDOWN_EVENT_DRAIN_YIELDS = 1024;
        std::atomic<HANDLE> s_shutdown_event{nullptr};
        std::atomic<std::uint64_t> s_shutdown_event_access{SHUTDOWN_EVENT_RETIRED};
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
        HANDLE s_worker_thread = nullptr;

        enum class BootstrapState : std::uint8_t
        {
            Drained,
            Starting,
            Ready,
            Draining,
            Detached
        };

        // The single admission authority for the bootstrap statics, and the serializer for the one terminal action on
        // them, without taking a lock from DllMain. Every transition into and out of Drained brackets the whole of the
        // publication or retirement it names, so no other static may be used to decide admission: a drain nulls the
        // worker handle and the event well before it has finished retiring the callback and the module identity.
        std::atomic<BootstrapState> s_bootstrap_state{BootstrapState::Drained};

        constexpr size_t BOOTSTRAP_TEXT_CAPACITY = 32768;

        struct BootstrapLoggerInfo
        {
            std::array<char, BOOTSTRAP_TEXT_CAPACITY> name{};
            std::array<char, BOOTSTRAP_TEXT_CAPACITY> log_file{};
            size_t name_size{0};
            size_t log_file_size{0};
            size_t queue_capacity{DEFAULT_QUEUE_CAPACITY};
            size_t batch_size{DEFAULT_BATCH_SIZE};
            std::chrono::milliseconds flush_interval{DEFAULT_FLUSH_INTERVAL};
            OverflowPolicy overflow_policy{OverflowPolicy::DropOldest};
            size_t spin_backoff_iterations{DEFAULT_SPIN_BACKOFF_ITERATIONS};
            std::chrono::milliseconds block_timeout_ms{16};
            size_t block_max_spin_iterations{1000};

            [[nodiscard]] bool stage(const ModInfo &info) noexcept
            {
                if (info.name.size() > name.size() || info.log_file.size() > log_file.size())
                {
                    return false;
                }

                std::copy(info.name.begin(), info.name.end(), name.begin());
                std::copy(info.log_file.begin(), info.log_file.end(), log_file.begin());
                name_size = info.name.size();
                log_file_size = info.log_file.size();
                queue_capacity = info.log.queue_capacity;
                batch_size = info.log.batch_size;
                flush_interval = info.log.flush_interval;
                overflow_policy = info.log.overflow_policy;
                spin_backoff_iterations = info.log.spin_backoff_iterations;
                block_timeout_ms = info.log.block_timeout_ms;
                block_max_spin_iterations = info.log.block_max_spin_iterations;
                return true;
            }

            [[nodiscard]] std::string_view name_view() const noexcept { return {name.data(), name_size}; }
            [[nodiscard]] std::string_view log_file_view() const noexcept
            {
                return {log_file.data(), log_file_size};
            }

            [[nodiscard]] AsyncLoggerConfig logger_config() const
            {
                AsyncLoggerConfig config{};
                config.queue_capacity = queue_capacity;
                config.batch_size = batch_size;
                config.flush_interval = flush_interval;
                config.overflow_policy = overflow_policy;
                config.spin_backoff_iterations = spin_backoff_iterations;
                config.block_timeout_ms = block_timeout_ms;
                config.block_max_spin_iterations = block_max_spin_iterations;
                return config;
            }

            void clear() noexcept
            {
                name_size = 0;
                log_file_size = 0;
            }
        };

        BootstrapLoggerInfo s_bootstrap_logger_info;

        // Module identity, the serialized single-session state machine, generation, and loader context all live in the
        // one lifecycle control block (detail::lifecycle()). The module identity is a lock-free atomic so
        // module_handle() never races a detach-path clear; the state machine (begin_start / mark_running / begin_stop /
        // mark_stopped) is the single-session-per-process guard, admitting a new start only from Stopped.

        // These two objects may still own consumer state when DLL_PROCESS_DETACH runs. Construct them into raw static
        // storage so the CRT never registers destructors for them: a clean off-loader-lock drain resets their contents,
        // while loader detach retains them untouched instead of destroying callback captures inside DllMain.
        using ReadyCallback = std::move_only_function<Result<void>(Session &)>;
        alignas(std::optional<Session>) unsigned char s_pending_session_storage[sizeof(std::optional<Session>)];
        alignas(ReadyCallback) unsigned char s_on_ready_storage[sizeof(ReadyCallback)];
        std::optional<Session> &s_pending_session =
            *::new (static_cast<void *>(s_pending_session_storage)) std::optional<Session>();
        ReadyCallback &s_on_ready = *::new (static_cast<void *>(s_on_ready_storage)) ReadyCallback();

#if defined(DMK_ENABLE_TEST_SEAMS)
        // Counts signals that reached SetEvent on a handle the kernel had already invalidated. Admission is supposed to
        // make that impossible, so a nonzero count is the direct observation of the use-after-close this word prevents,
        // and a test can assert it unconditionally rather than inferring safety from which retirement branch ran.
        std::atomic<std::uint64_t> s_signal_on_invalid_event{0};
        void (*s_bootstrap_pre_setup_probe)() noexcept = nullptr;
#endif

        void signal_shutdown_event() noexcept
        {
            // Observing "not retired" and registering as a reader must be ONE atomic step. A plain load followed by an
            // unconditional fetch_add lets a caller preempted between the two land its increment on a generation that
            // was retired and reopened meanwhile: its matching decrement then underflows the reopened word to all-ones
            // (which has the retired bit set) and no later request can ever signal that generation again.
            std::uint64_t access = s_shutdown_event_access.load(std::memory_order_acquire);
            do
            {
                if ((access & SHUTDOWN_EVENT_RETIRED) != 0)
                {
                    return;
                }
            } while (!s_shutdown_event_access.compare_exchange_weak(access, access + 1, std::memory_order_acq_rel,
                                                                    std::memory_order_acquire));

            if (HANDLE event = s_shutdown_event.load(std::memory_order_acquire))
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (!SetEvent(event))
                {
                    s_signal_on_invalid_event.fetch_add(1, std::memory_order_relaxed);
                }
#else
                SetEvent(event);
#endif
            }
            s_shutdown_event_access.fetch_sub(1, std::memory_order_release);
        }

        /**
         * @brief Closes admission and drops the event pointer, retaining any live kernel object.
         * @return true when a live handle was dropped, so the caller records the retention it just created.
         */
        [[nodiscard]] bool abandon_shutdown_event() noexcept
        {
            s_shutdown_event_access.fetch_or(SHUTDOWN_EVENT_RETIRED, std::memory_order_acq_rel);
            return s_shutdown_event.exchange(nullptr, std::memory_order_acq_rel) != nullptr;
        }

        void close_shutdown_event_at_process_exit() noexcept
        {
            s_shutdown_event_access.fetch_or(SHUTDOWN_EVENT_RETIRED, std::memory_order_acq_rel);
            if (HANDLE event = s_shutdown_event.exchange(nullptr, std::memory_order_acq_rel))
            {
                CloseHandle(event);
            }
        }

        void retire_shutdown_event_after_drain() noexcept
        {
            s_shutdown_event_access.fetch_or(SHUTDOWN_EVENT_RETIRED, std::memory_order_acq_rel);
            const HANDLE event = s_shutdown_event.exchange(nullptr, std::memory_order_acq_rel);
            if (event == nullptr)
            {
                return;
            }

            for (size_t i = 0; i < SHUTDOWN_EVENT_DRAIN_YIELDS; ++i)
            {
                if ((s_shutdown_event_access.load(std::memory_order_acquire) & SHUTDOWN_EVENT_READER_MASK) == 0)
                {
                    CloseHandle(event);
                    return;
                }
                SwitchToThread();
            }

            // A suspended signaler may retain access indefinitely. Keep its handle valid instead of blocking teardown.
            diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Bootstrap);
        }

        // Compares the running executable's basename (case-insensitive) against @p expected. An empty expectation
        // always passes. Resolved as wide (not GetModuleFileNameA) so a non-ASCII EXE basename is not mangled through
        // the active code page and cannot false-match or false-miss the gate.
        Result<bool> is_target_process(std::string_view expected, const char *operation) noexcept
        {
            if (expected.empty())
            {
                return true;
            }

            // The full path can exceed MAX_PATH. Static storage covers Windows' extended path limit without allocating
            // in a DllMain caller; lifecycle admission serializes every writer of this scratch buffer.
            constexpr DWORD MODULE_PATH_CAPACITY = 32768;
            static wchar_t s_exe_path[MODULE_PATH_CAPACITY];
            const DWORD path_size = GetModuleFileNameW(nullptr, s_exe_path, MODULE_PATH_CAPACITY);
            if (path_size == 0)
            {
                return std::unexpected(Error{ErrorCode::SystemCallFailed, operation, GetLastError()});
            }
            if (path_size >= MODULE_PATH_CAPACITY)
            {
                return std::unexpected(Error{ErrorCode::SystemCallFailed, operation, ERROR_INSUFFICIENT_BUFFER});
            }

            const wchar_t *exe_name = std::wcsrchr(s_exe_path, L'\\');
            exe_name = exe_name ? exe_name + 1 : s_exe_path;

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

        /**
         * @brief Classifies the outcome of a single-instance mutex acquisition.
         */
        enum class MutexAcquire : std::uint8_t
        {
            /// A fresh mutex was created; @p out holds the handle the Session must close.
            Acquired,
            /// No prefix was requested; @p out is null and no single-instance guard exists.
            NoGuard,
            /// The named mutex already existed: another load of this mod is live.
            AlreadyHeld,
            /// CreateMutexW failed; @p err holds GetLastError().
            SystemError
        };

        // Builds a per-PID named mutex from @p prefix and reports whether this load won the single-instance race.
        // Static scratch storage avoids heap work in bootstrap; lifecycle admission serializes every writer.
        MutexAcquire acquire_instance_mutex(std::string_view prefix, HANDLE &out, DWORD &err) noexcept
        {
            out = nullptr;
            err = 0;
            if (prefix.empty())
            {
                return MutexAcquire::NoGuard;
            }

            constexpr size_t MUTEX_NAME_CAPACITY = 32768;
            static wchar_t s_mutex_name[MUTEX_NAME_CAPACITY];
            constexpr size_t MAX_PID_DIGITS = 10;
            if (prefix.size() > MUTEX_NAME_CAPACITY - MAX_PID_DIGITS - 1)
            {
                err = ERROR_FILENAME_EXCED_RANGE;
                return MutexAcquire::SystemError;
            }

            size_t name_size = 0;
            for (const char character : prefix)
            {
                s_mutex_name[name_size++] = static_cast<wchar_t>(static_cast<unsigned char>(character));
            }

            wchar_t reversed_pid[MAX_PID_DIGITS];
            size_t pid_digits = 0;
            DWORD pid = GetCurrentProcessId();
            do
            {
                reversed_pid[pid_digits++] = static_cast<wchar_t>(L'0' + pid % 10);
                pid /= 10;
            } while (pid != 0);
            while (pid_digits != 0)
            {
                s_mutex_name[name_size++] = reversed_pid[--pid_digits];
            }
            s_mutex_name[name_size] = L'\0';

            HANDLE handle = CreateMutexW(nullptr, FALSE, s_mutex_name);
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

        [[nodiscard]] Result<HANDLE> begin_session(const ModInfo &info, const char *operation,
                                                   detail::LoaderContext loader_context) noexcept
        {
            if (!detail::lifecycle().begin_start())
            {
                return std::unexpected(Error{ErrorCode::SessionAlreadyActive, operation});
            }

            Result<bool> target_process = is_target_process(info.game_process_name, operation);
            if (!target_process)
            {
                detail::lifecycle().mark_stopped();
                return std::unexpected(target_process.error());
            }
            if (!*target_process)
            {
                detail::lifecycle().mark_stopped();
                return std::unexpected(Error{ErrorCode::ProcessMismatch, operation});
            }

            HANDLE mutex = nullptr;
            DWORD error = 0;
            switch (acquire_instance_mutex(info.instance_mutex_prefix, mutex, error))
            {
            case MutexAcquire::AlreadyHeld:
                detail::lifecycle().mark_stopped();
                return std::unexpected(Error{ErrorCode::InstanceAlreadyRunning, operation});
            case MutexAcquire::SystemError:
                detail::lifecycle().mark_stopped();
                return std::unexpected(Error{ErrorCode::SystemCallFailed, operation, error});
            case MutexAcquire::NoGuard:
            case MutexAcquire::Acquired:
                break;
            }

            // Publish the phase only once the fallible gates have passed. begin_start() already reset the context to
            // Normal for this epoch, so every rollback above leaves a neutral phase behind rather than stranding a
            // non-blocking Attach that would fail-close every later teardown in a process that never started.
            detail::lifecycle().set_loader_context(loader_context);
            return mutex;
        }

        // The ordered process-wide subsystem teardown that ~Session runs after clearing the session's own scope. This
        // is the single home for the teardown ordering: reverse dependency order, with the logger LAST because every
        // prior step may still log. Each leaf shutdown passes the shared blocking-teardown gate, so this function
        // delegates the join/retain action without duplicating the lifecycle decision.
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

        /**
         * @brief Rolls a pre-publication attach back to a retryable Drained slot.
         * @param instance_mutex The preflight mutex, or nullptr when no guard was requested.
         * @details No Session or callback has been published when this runs. Closing the local mutex releases the
         *          instance gate without subsystem teardown or consumer destruction in DllMain.
         */
        void unwind_bootstrap(HANDLE instance_mutex) noexcept
        {
            if (abandon_shutdown_event())
            {
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Bootstrap);
            }
            if (instance_mutex != nullptr)
            {
                CloseHandle(instance_mutex);
            }
            s_bootstrap_logger_info.clear();
            detail::lifecycle().clear_module();
            // Retire the Attach phase with the attach it described. Leaving it published would fail-close every later
            // teardown in a process whose consumer declined the load but kept using the library.
            detail::lifecycle().set_loader_context(detail::LoaderContext::Normal);
            detail::lifecycle().mark_stopped();
            s_bootstrap_state.store(BootstrapState::Drained, std::memory_order_release);
        }

        void retire_bootstrap_after_drain() noexcept
        {
            // The worker retires its own identity before it exits, so on the path that reaches here this is an
            // idempotent re-store. It stays because this function is the single retirement point: any future caller
            // that arrives without a completed join must still leave no id behind for the OS to recycle onto an
            // unrelated consumer thread, which would inherit both the worker's blocking authorization and its refused
            // self-drain.
            detail::lifecycle().clear_worker_thread();
            retire_shutdown_event_after_drain();
            s_on_ready = nullptr;
            s_bootstrap_logger_info.clear();
            detail::lifecycle().clear_module();
            // Retire the drain phase with everything else this drain retires, so the published word keeps describing
            // the phase the process is actually in. Both Normal and ExplicitDrain authorize blocking, so this is a
            // consistency store rather than a change of permission.
            detail::lifecycle().set_loader_context(detail::LoaderContext::Normal);
        }

        // The bootstrap worker. It finishes Session setup, runs on_ready, and performs teardown off the loader lock.
        DWORD WINAPI lifecycle_thread(LPVOID param) noexcept
        {
            const HMODULE self_ref = static_cast<HMODULE>(param);

            // Publish this thread's identity FIRST, before any consumer code can run on it. Collecting it from
            // CreateThread's out-parameter instead would leave a window in which on_ready is already executing while
            // the id is still 0, and a drain requested from inside on_ready would then slip past the self-drain guard
            // and report success for a session that is fully live. Publishing here closes that window without
            // resuming a thread from under the loader lock. The same identity authorizes this thread's teardown to
            // block regardless of the phase the DllMain thread publishes.
            detail::lifecycle().publish_worker_thread();

            // bootstrap() publishes the thread handle before it stages the Session and callback. A thread created from
            // DllMain cannot enter until attach notifications finish, but bootstrap is also callable by test and host
            // scaffolding off the loader lock, where this short publication wait is required.
            BootstrapState state = s_bootstrap_state.load(std::memory_order_acquire);
            while (state == BootstrapState::Starting)
            {
                SwitchToThread();
                state = s_bootstrap_state.load(std::memory_order_acquire);
            }

            // A control thread may claim Ready -> Draining before this thread observes Ready. Draining still owns a
            // fully published Session, callback, and shutdown event; adopt them and let the already-signalled event
            // drive the ordinary teardown so the waiting control thread can complete the drain.
            // The second condition should never happen: the worker is spawned only after the Session is staged. Guard
            // defensively rather than dereference an empty optional.
            //
            // Retire the identity on the way out of either branch. FreeLibraryAndExitThread never returns, so no
            // scope-exit action can do it, and a published id that outlives its thread is worse than none: the OS
            // recycles thread ids, so an unrelated consumer thread would inherit both this worker's blocking
            // authorization and its refused self-drain.
            if ((state != BootstrapState::Ready && state != BootstrapState::Draining) || !s_pending_session)
            {
                detail::lifecycle().clear_worker_thread();
                // Release the reference bootstrap_core handed this worker and exit atomically, so the thread never
                // returns through code the release may have unmapped.
                FreeLibraryAndExitThread(self_ref, 0);
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            if (s_bootstrap_pre_setup_probe != nullptr)
            {
                s_bootstrap_pre_setup_probe();
            }
#endif

            // A thread created from DllMain cannot execute its entry point until the loader releases the attach
            // notification. Publishing Normal retires the Attach phase before logger/file setup begins.
            detail::lifecycle().set_loader_context(detail::LoaderContext::Normal);

            {
                Session session = std::move(*s_pending_session);
                s_pending_session.reset();

                try
                {
                    Logger::configure(s_bootstrap_logger_info.name_view(), s_bootstrap_logger_info.log_file_view());
                    DetourModKit::log().enable_async_mode(s_bootstrap_logger_info.logger_config());
                }
                catch (const std::bad_alloc &)
                {
                    OutputDebugStringA("DetourModKit: bootstrap logger setup ran out of memory; continuing without "
                                       "guaranteed logging.\n");
                }
                catch (...)
                {
                    OutputDebugStringA("DetourModKit: bootstrap logger setup failed; continuing without guaranteed "
                                       "logging.\n");
                }
                detail::lifecycle().mark_running();

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

            // Retire the identity only after the teardown it authorized, and before FreeLibraryAndExitThread can let
            // the OS recycle this id.
            detail::lifecycle().clear_worker_thread();

            // The worker is done. Drop its own reference and exit the thread atomically: FreeLibraryAndExitThread never
            // returns, so the FreeLibrary's return address is never in code the release may unmap. This release may be
            // the terminal one if the consumer already dropped its LoadLibrary reference after request_shutdown(), so
            // the worker must not call plain FreeLibrary and then return through this module.
            FreeLibraryAndExitThread(self_ref, 0);
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        // Forces worker launch to fail after process and instance gating but before consumer state is published.
        std::atomic<bool> s_fail_worker_launch{false};
#endif

        // Creates the bootstrap worker. Routed through one function so the test seam fails into CreateThread's own
        // rollback branch rather than duplicating it.
        [[nodiscard]] HANDLE launch_bootstrap_worker(HMODULE worker_ref) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (s_fail_worker_launch.load(std::memory_order_acquire))
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return nullptr;
            }
#endif
            return CreateThread(nullptr, 0, lifecycle_thread, worker_ref, 0, nullptr);
        }

        // The allocation-free bootstrap core. Every failure occurs before the Session and callback are published.
        [[nodiscard]] Result<void> bootstrap_core(const ModInfo &info,
                                                   std::move_only_function<Result<void>(Session &)> on_ready) noexcept
        {
            // Claim the slot before touching any other static. A drain nulls the worker handle and the shutdown event
            // early but publishes Drained only after it has also retired the init callback and the module identity, so
            // admitting on those handles would let this generation publish into the tail of that retirement and have
            // its own callback destroyed and its own Ready overwritten by the drainer that is still finishing.
            BootstrapState expected = BootstrapState::Drained;
            if (!s_bootstrap_state.compare_exchange_strong(expected, BootstrapState::Starting,
                                                           std::memory_order_acq_rel))
            {
                if (expected == BootstrapState::Draining)
                {
                    return std::unexpected(Error{ErrorCode::SessionShutdownInProgress, "bootstrap"});
                }
                if (expected == BootstrapState::Detached)
                {
                    return std::unexpected(Error{ErrorCode::SessionShutdownUnavailable, "bootstrap"});
                }
                // Starting or Ready: another generation owns the slot.
                return std::unexpected(Error{ErrorCode::SessionAlreadyActive, "bootstrap"});
            }

            // A retirement that had to retain its event leaves a previous generation's signaler still inside SetEvent.
            // Its pending fetch_sub would underflow the access word this generation reopens, so refuse until that
            // signaler has left rather than start on a corrupted admission count. Checked here as well as at the
            // reopen so a doomed attach costs nothing: the reopen below is the authority.
            if (s_shutdown_event_access.load(std::memory_order_acquire) != SHUTDOWN_EVENT_RETIRED)
            {
                s_bootstrap_state.store(BootstrapState::Drained, std::memory_order_release);
                return std::unexpected(Error{ErrorCode::SessionShutdownInProgress, "bootstrap"});
            }

            // Auto-capture the calling module. DetourModKit links statically into the mod DLL, so a DetourModKit code
            // address resolves to the mod's own HMODULE -- exactly the handle DllMain would receive -- letting the
            // consumer's DllMain forward attach without threading the handle through. UNCHANGED_REFCOUNT is required:
            // this handle is for identity only (module_handle()), so it must NOT take a reference on the module. The
            // keepalive that protects the worker's code from a premature FreeLibrary is a SEPARATE counted reference
            // acquired immediately before CreateThread and handed to lifecycle_thread; keeping that concern out of the
            // identity lets module_handle() name the module without holding it mapped, and confines the "the module
            // stays mapped past a bare FreeLibrary" behavior to the worker's own lifetime. Capture into a local because
            // a Win32 out-parameter cannot target the std::atomic identity slot, then publish it with a release store.
            constexpr DWORD CAPTURE_FLAGS =
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
            HMODULE captured_module = nullptr;
            if (!GetModuleHandleExW(CAPTURE_FLAGS, reinterpret_cast<LPCWSTR>(&bootstrap_core), &captured_module))
            {
                const DWORD error = GetLastError();
                s_bootstrap_state.store(BootstrapState::Drained, std::memory_order_release);
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "bootstrap", error});
            }
            (void)DisableThreadLibraryCalls(captured_module);
            detail::lifecycle().publish_module(captured_module);

            // Keep the gates that let DllMain decline the load synchronous, but defer logger/file setup to the worker.
            Result<HANDLE> instance_mutex = begin_session(info, "bootstrap", detail::LoaderContext::Attach);
            if (!instance_mutex)
            {
                detail::lifecycle().clear_module();
                s_bootstrap_state.store(BootstrapState::Drained, std::memory_order_release);
                return std::unexpected(instance_mutex.error());
            }

            if (!s_bootstrap_logger_info.stage(info))
            {
                unwind_bootstrap(*instance_mutex);
                return std::unexpected(Error{ErrorCode::InvalidArg, "bootstrap"});
            }

            // Create into a local first, then publish with a release store so the worker's / consumer's acquire load
            // observes a fully-constructed handle. Owning Starting is what makes the slot free to publish into. The
            // TRUE second argument makes this a MANUAL-RESET event: a shutdown request is a one-way latch, so once
            // request_shutdown() signals it the event stays signaled -- the worker observes it whether or not it was
            // already waiting, and a repeated request_shutdown() is idempotent (an auto-reset event would clear itself
            // after a single wait woke and could drop a later observer).
            const HANDLE shutdown_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!shutdown_event)
            {
                const DWORD err = GetLastError();
                unwind_bootstrap(*instance_mutex);
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "bootstrap", err});
            }
            // Reopen admission by CLAIMING the retired word, never by storing over it: a straggling signaler from the
            // retired generation can still be counted, and a blind store would discard its registration and leave its
            // pending decrement to underflow the word. Reopening before the handle is published also keeps a signaler
            // admitted after this point from ever loading a half-published pointer.
            std::uint64_t retired_access = SHUTDOWN_EVENT_RETIRED;
            if (!s_shutdown_event_access.compare_exchange_strong(retired_access, 0, std::memory_order_acq_rel,
                                                                 std::memory_order_acquire))
            {
                CloseHandle(shutdown_event);
                unwind_bootstrap(*instance_mutex);
                return std::unexpected(Error{ErrorCode::SessionShutdownInProgress, "bootstrap"});
            }
            s_shutdown_event.store(shutdown_event, std::memory_order_release);

            // Acquire the worker's module reference BEFORE CreateThread. A thread created from DllMain may not execute
            // its entry point until after the loader releases the attach notification, but the caller can FreeLibrary
            // immediately after LoadLibrary returns. The reference therefore has to exist before the worker is
            // scheduled, not at the top of the worker function.
            const HMODULE worker_ref = detail::try_acquire_module_ref();
            if (worker_ref == nullptr)
            {
                const DWORD err = GetLastError();
                unwind_bootstrap(*instance_mutex);
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "bootstrap", err});
            }

            // The worker publishes its own thread id as its first instruction, so this call does not collect it. A
            // CREATE_SUSPENDED / ResumeThread pair would order the publication here instead, but bootstrap() runs
            // under the loader lock and resuming a thread from inside DllMain is not leaf-safe.
            s_worker_thread = launch_bootstrap_worker(worker_ref);
            if (!s_worker_thread)
            {
                const DWORD err = GetLastError();
                detail::release_module_ref(worker_ref);
                unwind_bootstrap(*instance_mutex);
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "bootstrap", err});
            }

            // No fallible operation remains. Stage the Session and callback, then release the worker from its Starting
            // wait. This ordering also keeps a launch failure from destroying consumer state or shutting subsystems
            // down inside DllMain.
            s_pending_session.emplace(detail::SessionBootstrapAccess::make(*instance_mutex));
            s_on_ready = std::move(on_ready);
            s_bootstrap_state.store(BootstrapState::Ready, std::memory_order_release);
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

        // Enter Stopping so a start racing this teardown stays rejected until the slot is fully released.
        detail::lifecycle().begin_stop();
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
        detail::lifecycle().mark_stopped();
    }

    Result<Session> Session::start(const ModInfo &info) noexcept
    {
        Result<HANDLE> instance_mutex = begin_session(info, "Session::start", detail::LoaderContext::Normal);
        if (!instance_mutex)
        {
            return std::unexpected(instance_mutex.error());
        }

        // Logger::configure builds std::string / std::wstring for the prefix and path; keep the noexcept contract by
        // catching here and undoing the mutex and the guard first. std::bad_alloc is reported as OutOfMemory and
        // everything else as Unknown: collapsing both into OutOfMemory would tell a caller to retry after a fault that
        // retrying cannot clear.
        try
        {
            Logger::configure(info.name, info.log_file);
            // Qualified: inside this static member the free accessor is hidden by the non-static Session::log().
            DetourModKit::log().enable_async_mode(info.log);
        }
        catch (const std::bad_alloc &)
        {
            if (*instance_mutex != nullptr)
            {
                CloseHandle(*instance_mutex);
            }
            detail::lifecycle().mark_stopped();
            return std::unexpected(Error{ErrorCode::OutOfMemory, "Session::start"});
        }
        catch (...)
        {
            if (*instance_mutex != nullptr)
            {
                CloseHandle(*instance_mutex);
            }
            detail::lifecycle().mark_stopped();
            return std::unexpected(Error{ErrorCode::Unknown, "Session::start"});
        }

        // Setup succeeded: the session is Running. It now owns the single-session slot (released by ~Session) and the
        // mutex handle (closed by ~Session).
        detail::lifecycle().mark_running();
        return Session(*instance_mutex);
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
        //
        // Abandon the input scope explicitly. Clearing m_active makes release() a no-op, but m_scope is a member whose
        // own destructor still runs after this Session is destroyed. Scope::abandon retains its complete guard
        // container, so neither release logic nor consumer callback destruction can run during process detach.
        m_scope.abandon();
        m_active = false;
        m_instance_mutex = nullptr;
        detail::lifecycle().mark_stopped();
    }

    // Bootstrap free functions

    Result<void> bootstrap(const ModInfo &info, std::move_only_function<Result<void>(Session &)> on_ready) noexcept
    {
        return bootstrap_core(info, std::move(on_ready));
    }

    void bootstrap_detach(void *reserved) noexcept
    {
        // This entry point is called only from DllMain. lpReserved distinguishes process termination from an explicit
        // unload. Publish that context even when a prior drain already retired the handles, so later CRT destructors
        // cannot inherit ExplicitDrain and treat a false heuristic result as permission to block under the loader lock.
        const detail::LoaderContext context =
            reserved != nullptr ? detail::LoaderContext::ProcessExit : detail::LoaderContext::LoaderDetach;
        detail::lifecycle().set_loader_context(context);

        if (context == detail::LoaderContext::ProcessExit)
        {
            const BootstrapState previous =
                s_bootstrap_state.exchange(BootstrapState::Detached, std::memory_order_acq_rel);
            if (previous == BootstrapState::Detached)
            {
                return;
            }

            // PROCESS TERMINATION (abandon). The OS has already killed the worker; its adopted Session lives in that
            // dead frame and is leaked untouched. If the worker never adopted the pending Session, leave it engaged in
            // the never-destroyed storage too. Neither path runs consumer destruction inside DllMain.
            if (s_pending_session)
            {
                s_pending_session->abandon();
            }
            detail::lifecycle().clear_worker_thread();
            if (s_worker_thread)
            {
                CloseHandle(s_worker_thread);
                s_worker_thread = nullptr;
            }
            // Process termination: the OS has already terminated every other thread before this DllMain notification,
            // so no request_shutdown() can be in flight and closing the event is safe.
            close_shutdown_event_at_process_exit();
            detail::lifecycle().clear_module();
            if (previous != BootstrapState::Drained)
            {
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Bootstrap);
            }
            return;
        }

        BootstrapState expected = BootstrapState::Ready;
        if (!s_bootstrap_state.compare_exchange_strong(expected, BootstrapState::Detached, std::memory_order_acq_rel))
        {
            return;
        }

        // EXPLICIT FreeLibrary. Signal the worker, then stop admitting signalers and retain the event rather than
        // waiting for an already-admitted request_shutdown() call. The worker's counted module reference keeps its code
        // mapped until it exits; this path never waits or destroys callback state under the loader lock.
        signal_shutdown_event();
        if (abandon_shutdown_event())
        {
            diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Bootstrap);
        }
        // The published Detached state is terminal, so no drain, attach, or later detach can still read the worker's
        // thread handle. Closing it does not disturb the running worker and keeps a repeated load/unload cycle from
        // leaking one kernel thread object per load.
        if (s_worker_thread)
        {
            CloseHandle(s_worker_thread);
            s_worker_thread = nullptr;
        }
        detail::lifecycle().clear_module();
    }

    void request_shutdown() noexcept
    {
        // The access word admits this caller before it loads the handle. A clean drain closes the handle only after
        // closing admission and observing every admitted caller leave SetEvent.
        signal_shutdown_event();
    }

    Result<void> shutdown_and_wait() noexcept
    {
        // Refuse a self-drain before touching the state machine, so a worker-thread caller perturbs nothing and an
        // ordinary control thread can still drain afterwards. Waiting here would block on the calling thread's own
        // exit, which only that wait prevents.
        if (detail::lifecycle().is_worker_thread())
        {
            return std::unexpected(Error{ErrorCode::SessionShutdownWouldBlock, "shutdown_and_wait"});
        }

        BootstrapState expected = BootstrapState::Ready;
        if (!s_bootstrap_state.compare_exchange_strong(expected, BootstrapState::Draining, std::memory_order_acq_rel))
        {
            if (expected == BootstrapState::Drained)
            {
                return {};
            }
            if (expected == BootstrapState::Detached)
            {
                return std::unexpected(Error{ErrorCode::SessionShutdownUnavailable, "shutdown_and_wait"});
            }
            return std::unexpected(Error{ErrorCode::SessionShutdownInProgress, "shutdown_and_wait"});
        }

        // The probe, not blocking_teardown_permitted(): the published loader context describes the PHASE a teardown
        // runs in, and Attach stays published from bootstrap() until the worker retires it. A control thread that
        // drains promptly after LoadLibrary returns is off the loader lock but would still read Attach, so only the
        // per-thread probe answers "may THIS caller wait" for an entry point reached from an arbitrary thread.
        if (detail::is_loader_lock_held())
        {
            s_bootstrap_state.store(BootstrapState::Ready, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::SessionShutdownWouldBlock, "shutdown_and_wait"});
        }

        detail::lifecycle().set_loader_context(detail::LoaderContext::ExplicitDrain);
        request_shutdown();

        if (s_worker_thread != nullptr)
        {
            const DWORD wait_result = WaitForSingleObject(s_worker_thread, INFINITE);
            if (wait_result != WAIT_OBJECT_0)
            {
                const DWORD error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
                // The shutdown request is already latched, so the worker drains regardless of this failure; only the
                // slot is restored, for a caller that wants to retry the wait. Retire the drain phase with the drain
                // this caller no longer owns. The worker's own authorization comes from its identity, not this word.
                detail::lifecycle().set_loader_context(detail::LoaderContext::Normal);
                s_bootstrap_state.store(BootstrapState::Ready, std::memory_order_release);
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "shutdown_and_wait", error});
            }
            CloseHandle(s_worker_thread);
            s_worker_thread = nullptr;
        }

        retire_bootstrap_after_drain();
        s_bootstrap_state.store(BootstrapState::Drained, std::memory_order_release);
        return {};
    }

    ModuleHandle module_handle() noexcept
    {
        // Lock-free atomic acquire load: race-free against a concurrent detach-path clear, so a reader observes only
        // the current published identity or null, never a torn value.
        return detail::lifecycle().module();
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    // Test-only accessor for the bootstrap shutdown event handle. A test captures it before a synchronous drain and
    // confirms the handle closes only after racing request_shutdown() callers have left SetEvent. Not declared in a
    // public header; the test extern-declares it like the loader-lock override seams.
    HANDLE bootstrap_shutdown_event_for_test() noexcept
    {
        return s_shutdown_event.load(std::memory_order_acquire);
    }

    // Arms or disarms the worker-launch failure. Set it around one bootstrap() call only.
    void bootstrap_fail_worker_launch_for_test(bool fail) noexcept
    {
        s_fail_worker_launch.store(fail, std::memory_order_release);
    }

    void bootstrap_pre_setup_probe_for_test(void (*probe)() noexcept) noexcept
    {
        s_bootstrap_pre_setup_probe = probe;
    }

    // How many signals reached SetEvent on an already-invalidated handle. Monotonic across the process, so a case
    // brackets its own window with two reads.
    std::uint64_t bootstrap_signals_on_invalid_event_for_test() noexcept
    {
        return s_signal_on_invalid_event.load(std::memory_order_relaxed);
    }
#endif

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
        //
        // Latch background reloads off FIRST, before stopping the workers: on a DllMain-detach unload the watcher and
        // hotkey servicer are detached rather than joined, and the watcher deliberately flushes one final debounced
        // reload on its way out. Without the latch that flush (and any servicer pass) would run setters / the user
        // on_reload callback -- code in the unloading Logic DLL -- on a detached thread after the loader reclaims the
        // pages. The latch makes those passes drop at their entry gate; disable_auto_reload()/clear() then stop the
        // workers; await_reloads_quiesced waits out any pass that was already mid-flight when the latch was set so we
        // do not return (and let the caller unmap the DLL) while a detached worker is still inside a setter. The wait
        // is bounded so a setter genuinely wedged (e.g. blocked on a loader lock this thread may hold) cannot hang
        // unload.
        config::detail::disable_reloads_for_unload();
        config::disable_auto_reload();
        config::clear();
        if (!config::detail::await_reloads_quiesced(std::chrono::milliseconds(500)))
        {
            try
            {
                logger.warning("on_logic_dll_unload: a background config reload did not quiesce within 500 ms; "
                               "proceeding with unload.");
            }
            catch (...)
            {
            }
        }
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

        // Wipe the config registry last, for the same use-after-unload reasons as the named overload; latch background
        // reloads off and stop the auto-reload watcher first so neither its final debounced flush nor a hotkey-servicer
        // pass can fire a setter into unmapped pages, then wait (bounded) for any pass already in flight to finish. See
        // on_logic_dll_unload for the full rationale.
        config::detail::disable_reloads_for_unload();
        config::disable_auto_reload();
        config::clear();
        if (!config::detail::await_reloads_quiesced(std::chrono::milliseconds(500)))
        {
            try
            {
                logger.warning("on_logic_dll_unload_all: a background config reload did not quiesce within 500 ms; "
                               "proceeding with unload.");
            }
            catch (...)
            {
            }
        }
    }
} // namespace DetourModKit
