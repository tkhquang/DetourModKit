/**
 * @file config_watcher.cpp
 * @brief Implementation of the internal ConfigWatcher engine (ReadDirectoryChangesW-based), not installed.
 */

#include "config_watcher.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "DetourModKit/logger.hpp"
#include "DetourModKit/detail/worker.hpp"
#include "lifecycle_context.hpp"
#include "worker_start_log.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        enum class ConfigWatcherStartWait : std::uint8_t
        {
            Pending,
            Released,
            Cancelled,
        };

        struct ConfigWatcherStartGate
        {
            explicit ConfigWatcherStartGate(LogLevel threshold)
                : diags{
                      .threshold = threshold,
                      .records = {},
                  },
                  late_diags{
                      .threshold = threshold,
                      .records = {},
                  }
            {
            }

            std::mutex mutex;
            config::detail::DeferredDiagnostics diags;
            config::detail::DeferredDiagnostics late_diags;
            bool complete{false};
            bool emitted{false};
            std::atomic<ConfigWatcherStartWait> wait{ConfigWatcherStartWait::Pending};
        };

        namespace
        {
            void cancel_start_wait(const std::shared_ptr<ConfigWatcherStartGate> &gate) noexcept
            {
                if (!gate)
                {
                    return;
                }
                auto expected = ConfigWatcherStartWait::Pending;
                if (gate->wait.compare_exchange_strong(
                        expected,
                        ConfigWatcherStartWait::Cancelled,
                        std::memory_order_acq_rel,
                        std::memory_order_acquire
                    ))
                {
                    gate->wait.notify_all();
                }
            }
        } // anonymous namespace

#if defined(DMK_ENABLE_TEST_SEAMS)
        // Overrides loader-lock detection so teardown retention can be exercised from a normal test thread.
        bool (*g_config_watcher_loader_lock_override)() noexcept = nullptr;

        // A throwing probe exercises failure before the startup promise has been settled.
        void (*g_config_watcher_prehandshake_seam)() = nullptr;

        // These probes inject CreateEventW and initial ReadDirectoryChangesW failures.
        bool (*g_config_watcher_create_event_failure_seam)() noexcept = nullptr;
        bool (*g_config_watcher_initial_read_failure_seam)() noexcept = nullptr;

        // Published from the pump body's exit guard. A husked watcher's Impl is leaked, so worker_exited is no longer
        // reachable through the ConfigWatcher shell; this is the only channel that can observe a detached pump
        // terminating after teardown abandoned it.
        std::atomic<std::atomic<bool> *> g_config_watcher_worker_exited_probe{nullptr};
#endif

        namespace
        {
            constexpr DWORD NOTIFY_FILTER =
                FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE;

            bool watcher_must_not_block() noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                return !blocking_teardown_permitted(g_config_watcher_loader_lock_override);
#else
                return !blocking_teardown_permitted();
#endif
            }

            // Sized so bursty editor saves do not overflow a single ReadDirectoryChangesW call. The notification
            // buffer is heap-resident (a std::vector inside the WatchIoState bundle), so its size is not bounded by the
            // worker's stack.
            constexpr DWORD BUFFER_BYTES = 16 * 1024;

            // Pumping timeout for GetOverlappedResultEx. Bounds how long a pending stop() must wait for the worker to
            // observe its stop_token; idle cost is ~10 syscalls/s per watcher (not zero).
            constexpr DWORD PUMP_TIMEOUT_MS = 100;

            // Per-wait bound for the stop-path drain. Only bites when a notify IRP is genuinely stuck (a
            // deleted/orphaned watched directory); in the normal case the cancelled read completes in microseconds and
            // the wait returns immediately. Two waits (cancel, then handle-close) cap worst-case teardown at ~2 * this
            // value instead of an infinite hang.
            constexpr DWORD DRAIN_TIMEOUT_MS = 1000;

            // Case-insensitive filename comparison using ordinal (locale-independent) Unicode folding.
            // CompareStringOrdinal with bIgnoreCase == TRUE is the Microsoft-recommended primitive for matching file
            // names: it applies the same simple uppercase fold NTFS/exFAT use for case-insensitivity, and (unlike
            // ::towupper) it does not consult the process locale. A watcher running under a Turkish (or any
            // non-invariant) locale must still match "Config.ini" against "config.ini"; a locale-sensitive fold could
            // map the ASCII 'I'/'i' pair differently and silently stop firing reloads. The length pre-check keeps the
            // common mismatch cheap; the empty short-circuit avoids passing a null data()/zero count to the API.
            bool iequals_w(std::wstring_view lhs, std::wstring_view rhs) noexcept
            {
                if (lhs.size() != rhs.size())
                {
                    return false;
                }
                if (lhs.empty())
                {
                    return true;
                }
                return ::CompareStringOrdinal(
                           lhs.data(),
                           static_cast<int>(lhs.size()),
                           rhs.data(),
                           static_cast<int>(rhs.size()),
                           TRUE
                       ) == CSTR_EQUAL;
            }

            struct OwnedHandle
            {
                HANDLE h{INVALID_HANDLE_VALUE};

                OwnedHandle() = default;
                explicit OwnedHandle(HANDLE raw) noexcept : h(raw) {}

                OwnedHandle(const OwnedHandle &) = delete;
                OwnedHandle &operator=(const OwnedHandle &) = delete;

                OwnedHandle(OwnedHandle &&other) noexcept : h(std::exchange(other.h, INVALID_HANDLE_VALUE)) {}

                OwnedHandle &operator=(OwnedHandle &&other) noexcept
                {
                    if (this != &other)
                    {
                        reset();
                        h = std::exchange(other.h, INVALID_HANDLE_VALUE);
                    }
                    return *this;
                }

                ~OwnedHandle() noexcept { reset(); }

                [[nodiscard]] bool valid() const noexcept { return h != INVALID_HANDLE_VALUE && h != nullptr; }

                void reset() noexcept
                {
                    if (valid())
                    {
                        ::CloseHandle(h);
                    }
                    h = INVALID_HANDLE_VALUE;
                }
            };

            // Heap-resident I/O state for the ReadDirectoryChangesW pump. Bundled so the stop-path drain can leak the
            // entire set (directory handle, completion event, OVERLAPPED, and notification buffer) in one move when a
            // pending notify IRP cannot be confirmed complete. The kernel may still write into the OVERLAPPED and the
            // buffer after a cancellation that the filesystem never finishes (e.g. the watched directory was deleted),
            // so those structures must outlive the worker rather than be freed while an IRP still references them.
            struct WatchIoState
            {
                OwnedHandle dir_handle;
                OwnedHandle event_handle;
                std::vector<BYTE> buffer;
                OVERLAPPED overlapped{};
            };

            // Resets an atomic thread-id slot to the default (no-thread) id when the worker leaves its body, covering
            // every exit path uniformly: a requested stop, a self-induced error exit, and the early
            // CreateFileW/CreateEventW failures that return after the id was already published. The worker publishes
            // its own id on entry so is_worker_thread() can detect setter-induced self-calls; clearing it as the worker
            // exits keeps a later OS-recycled thread id from matching this dead worker and suppressing a real stop
            // request. The store happens-before thread termination, so the slot is already cleared before the id can be
            // reused.
            class WorkerThreadIdGuard
            {
            public:
                explicit WorkerThreadIdGuard(std::atomic<std::thread::id> &id_slot) noexcept : m_slot(id_slot) {}
                ~WorkerThreadIdGuard() noexcept { m_slot.store(std::thread::id{}, std::memory_order_release); }

                WorkerThreadIdGuard(const WorkerThreadIdGuard &) = delete;
                WorkerThreadIdGuard &operator=(const WorkerThreadIdGuard &) = delete;

            private:
                std::atomic<std::thread::id> &m_slot;
            };

            class WorkerExitGuard
            {
            public:
                explicit WorkerExitGuard(std::atomic<bool> &exited) noexcept : m_exited(exited) {}
                ~WorkerExitGuard() noexcept
                {
                    m_exited.store(true, std::memory_order_release);
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (auto *observed = g_config_watcher_worker_exited_probe.load(std::memory_order_acquire))
                    {
                        observed->store(true, std::memory_order_release);
                    }
#endif
                }

                WorkerExitGuard(const WorkerExitGuard &) = delete;
                WorkerExitGuard &operator=(const WorkerExitGuard &) = delete;

            private:
                std::atomic<bool> &m_exited;
            };
        } // namespace

        struct ConfigWatcher::Impl
        {
            std::string ini_path_utf8;
            std::wstring directory_wide;
            std::wstring filename_wide;
            std::chrono::milliseconds debounce;
            std::function<void()> on_reload;

            std::mutex start_mutex;
            std::unique_ptr<StoppableWorker> worker;
            std::atomic<StartGate> start_gate;
            std::atomic<std::thread::id> worker_thread_id{};
            std::atomic<bool> worker_exited{true};
            std::atomic<bool> stop_requested{false};

            Impl(std::string_view path, std::chrono::milliseconds deb, std::function<void()> cb)
                : ini_path_utf8(path), debounce(deb), on_reload(std::move(cb))
            {
                // Resolve into directory + filename components up-front.
                // weakly_canonical is avoided because the file may not exist yet;
                // absolute() is enough for ReadDirectoryChangesW.
                std::error_code ec;
                std::filesystem::path input_path(ini_path_utf8);
                std::filesystem::path absolute_path = std::filesystem::absolute(input_path, ec);
                if (ec)
                {
                    absolute_path = input_path;
                }

                directory_wide = absolute_path.parent_path().wstring();
                filename_wide = absolute_path.filename().wstring();
            }
        };

        void ConfigWatcher::leak_impl_storage(std::unique_ptr<Impl> &impl) noexcept
        {
            // new (std::nothrow) keeps the caller's noexcept teardown honest by returning nullptr on OOM rather than
            // turning a bad_alloc into std::terminate. On allocation failure, release the unique_ptr so the Impl
            // storage is leaked directly without invoking ~Impl, which would join the worker. Callers use this helper
            // only when joining is unsafe: during loader-lock teardown or after a startup handshake timed out while the
            // worker may still be blocked in a hooked system call.
            // Each invocation allocates its own cell, so prior leaked Impls are never overwritten; the leak is bounded
            // to one cell per husking call and the detached worker's raw pointers into Impl members stay valid until it
            // exits or the process tears down.
            static_assert(
                std::is_nothrow_move_constructible_v<std::unique_ptr<Impl>>,
                "Leak cell must be nothrow-move-constructible to keep the noexcept husk paths honest."
            );

            if (auto *leaked = new (std::nothrow) std::unique_ptr<Impl>(std::move(impl)))
            {
                (void)leaked;
            }
            else
            {
                (void)impl.release();
            }
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::ConfigWatcher);
        }

        ConfigWatcher::ConfigWatcher(
            std::string_view ini_path,
            std::chrono::milliseconds debounce_window,
            std::function<void()> on_reload
        )
            : m_impl(std::make_unique<Impl>(ini_path, debounce_window, std::move(on_reload)))
        {
        }

        ConfigWatcher::~ConfigWatcher() noexcept
        {
            if (m_impl && watcher_must_not_block())
            {
                // Blocking is not authorized (an unload phase, or the loader-lock veto): joining the watcher would
                // deadlock against ReadDirectoryChangesW's I/O completion, and tearing down Impl would invalidate the
                // worker_thread_id pointer the detached lambda still references. Publish the watcher's independent
                // cancellation flag and leak the entire Impl onto the heap so it outlives the destructor. The owned
                // StoppableWorker keeps the worker's code pages mapped by leaking its own module reference on its
                // unauthorized branch, so no module reference is taken here. The same leaf discipline is used by the
                // hook handle teardown and Logger::shutdown_internal.

                if (m_impl->worker)
                {
                    // StoppableWorker cannot invoke stop callbacks once blocking teardown is vetoed. Publish this
                    // watcher's independent lock-free cancellation flag first; its I/O pump observes it on a bounded
                    // cadence after any in-flight call returns. shutdown() then detaches without joining.
                    m_impl->stop_requested.store(true, std::memory_order_release);
                    cancel_start_wait(m_impl->start_gate.load(std::memory_order_acquire));
                    m_impl->worker->shutdown();
                }

                // Husk this ConfigWatcher: move Impl into a never-freed heap cell instead of running ~Impl under the
                // loader lock, where tearing down the detached worker would deadlock against ReadDirectoryChangesW's
                // I/O completion.
                leak_impl_storage(m_impl);
                return;
            }

            stop();

            // stop() reaches StoppableWorker::shutdown(), which re-queries the process-global blocking-teardown
            // predicate for itself. Another thread can narrow that predicate between the check above and shutdown()'s
            // own, so an arm entered as a join can still finish as a detach. The pump then keeps reading stop_requested
            // / worker_exited / worker_thread_id through raw slots into Impl, and running ~Impl here would
            // write-after-free them from a thread that is still executing. Observe the body's own exit publication
            // instead of re-querying the predicate (which would TOCTOU against the same decision) and husk the watcher
            // when it has not exited, the self-safe-destructor discipline AsyncLogger applies to its detached writer.
            // Leaking is the safe direction: a body that exits immediately after this load only costs one bounded Impl.
            if (m_impl && !m_impl->worker_exited.load(std::memory_order_acquire))
            {
                leak_impl_storage(m_impl);
            }
        }

        bool ConfigWatcher::is_running() const noexcept
        {
            if (!m_impl)
            {
                return false;
            }
            // Avoid reading m_impl->worker here: start() assigns it and stop() moves it out under start_mutex, so an
            // unlocked status query would race the unique_ptr. The worker publishes this atomic id before issuing the
            // first overlapped read and clears it on exit, which gives this noexcept accessor a race-free running
            // signal.
            return m_impl->worker_thread_id.load(std::memory_order_acquire) != std::thread::id{};
        }

        const std::string &ConfigWatcher::ini_path() const noexcept
        {
            if (!m_impl)
            {
                static const std::string s_empty;
                return s_empty;
            }
            return m_impl->ini_path_utf8;
        }

        std::chrono::milliseconds ConfigWatcher::debounce() const noexcept
        {
            if (!m_impl)
            {
                return std::chrono::milliseconds{0};
            }
            return m_impl->debounce;
        }

        bool ConfigWatcher::is_worker_thread(std::thread::id id) const noexcept
        {
            if (!m_impl)
            {
                return false;
            }
            const std::thread::id worker = m_impl->worker_thread_id.load(std::memory_order_acquire);
            // The default (no-thread) id means no worker is currently published. That holds before start() posts the
            // first read, and after the worker reset the slot on exit. Never report that state as a match, even when
            // the caller passes a default-constructed id, so a reset slot can never alias a real stop request.
            return worker != std::thread::id{} && worker == id;
        }

        bool ConfigWatcher::start()
        {
            config::detail::DeferredDiagnostics diags = config::detail::open_deferred_diagnostics();
            StartGate gate;
            bool started = false;
            try
            {
                started = start(diags, gate);
            }
            catch (...)
            {
                release_start_gate(gate);
                throw;
            }
            config::detail::emit_deferred_diagnostics(diags);
            release_start_gate(gate);
            return started;
        }

        void ConfigWatcher::release_start_gate(const StartGate &gate) noexcept
        {
            if (!gate)
            {
                return;
            }
            config::detail::DeferredDiagnostics to_emit;
            config::detail::DeferredDiagnostics late_to_emit;
            {
                std::lock_guard<std::mutex> lock(gate->mutex);
                gate->wait.store(ConfigWatcherStartWait::Released, std::memory_order_release);
                if (gate->complete && !gate->emitted)
                {
                    gate->emitted = true;
                    to_emit = std::move(gate->diags);
                    late_to_emit = std::move(gate->late_diags);
                }
            }
            gate->wait.notify_all();
            config::detail::emit_deferred_diagnostics(to_emit);
            config::detail::emit_deferred_diagnostics(late_to_emit);
        }

        bool ConfigWatcher::start(config::detail::DeferredDiagnostics &diags, StartGate &gate)
        {
            gate.reset();
            if (!m_impl)
            {
                // Spent watcher: a prior start() timed out and leaked the Impl (see the leak-on-timeout branch below).
                // The instance is inert; the caller is expected to have dropped it. Fail closed rather than deref null.
                return false;
            }
            std::lock_guard<std::mutex> lock(m_impl->start_mutex);

            // A worker object can already exist. If its body is still live, the watcher is running. Keep it. But a
            // post-handshake runtime failure (the watched parent removed, a GetOverlappedResultEx error, or a re-issue
            // failure) makes the body return on its own while the StoppableWorker lingers with a finished thread; a
            // restart must not treat that exited husk as success. Join and drop the exited worker, then fall through to
            // a fresh worker and handshake.
            //
            // Liveness is tested on the same worker_thread_id slot is_running() publishes, not on
            // StoppableWorker::is_running(). The two clear in a fixed order: WorkerThreadIdGuard is the body's
            // first-declared local, so the slot is cleared as the body's last act, while the Exited transition is
            // published by the StoppableWorker wrapper only after the body has returned. Testing the worker state here
            // would leave a window in which a caller that observed is_running() == false is told the restart succeeded
            // while this exited husk stays installed. Reading the published slot closes it: a non-null worker under
            // start_mutex implies a settled successful handshake (every failure path resets the worker or husks the
            // Impl), and the body stores its id before settling, so an empty slot with a live worker object means the
            // body has already finished and reset() joins a thread that is returning. The slot is tested before the
            // worker handle, not inside a null check on it: a stop() whose StoppableWorker::shutdown() hits the
            // blocking-teardown veto detaches the body and drops the handle, so a null handle does not imply a finished
            // body. That body observes only stop_requested, which the restart below clears, and resurrecting it leaves
            // two pumps sharing one Impl. Whichever exits first publishes worker_exited and lets ~ConfigWatcher free
            // storage the other still reads. Resetting a null handle is a no-op, so the settled-husk case is unchanged.
            if (m_impl->worker_thread_id.load(std::memory_order_acquire) != std::thread::id{})
            {
                gate = m_impl->start_gate.load(std::memory_order_acquire);
                return true;
            }
            m_impl->worker.reset();

            if (m_impl->directory_wide.empty() || m_impl->filename_wide.empty())
            {
                config::detail::defer_diagnostic(
                    diags,
                    LogLevel::Error,
                    "ConfigWatcher: invalid INI path '{}'; cannot start.",
                    m_impl->ini_path_utf8
                );
                return false;
            }
            m_impl->stop_requested.store(false, std::memory_order_release);

            // Capture everything the worker needs by value so the body can outlive the captured Impl members only in
            // the loader-lock detach path; under normal teardown stop() joins before m_impl unwinds.
            auto directory = m_impl->directory_wide;
            auto filename = m_impl->filename_wide;
            auto debounce_ms = m_impl->debounce;
            auto callback = m_impl->on_reload;
            auto label = m_impl->ini_path_utf8;
            const LogLevel startup_threshold = diags.threshold;

            // The StoppableWorker body is stored in std::function, so the lambda must stay copyable; we cannot move a
            // non-copyable OwnedHandle into it. Instead, open the directory handle on the worker thread and
            // synchronously report success/failure back to this thread via a shared promise. start() can then return
            // the real status without polling is_running() in a race.
            auto open_result = std::make_shared<std::promise<bool>>();
            std::future<bool> open_future = open_result->get_future();
            auto startup_gate = std::make_shared<ConfigWatcherStartGate>(diags.threshold);
            m_impl->start_gate.store(startup_gate, std::memory_order_release);
            gate = startup_gate;

            // Pointers to the Impl's atomic slots. Raw pointers rather than a captured m_impl reference: the lambda
            // may outlive this stack frame via the StoppableWorker detach path, and a detached body keeps reading all
            // three. They stay valid because Impl is never freed under a live body. Every teardown that cannot join
            // (the veto branch, and the authorized branch whose worker detached anyway) husks the watcher and leaks
            // Impl instead, so the slots outlive the detached worker for process lifetime.
            auto *worker_id_slot = &m_impl->worker_thread_id;
            auto *worker_exited_slot = &m_impl->worker_exited;
            auto *stop_requested_slot = &m_impl->stop_requested;

            auto worker_body = [directory = std::move(directory),
                                filename = std::move(filename),
                                debounce_ms,
                                callback = std::move(callback),
                                label = std::move(label),
                                open_result,
                                startup_gate,
                                startup_threshold,
                                worker_id_slot,
                                worker_exited_slot,
                                stop_requested_slot](const std::stop_token &st) -> void
            {
                const WorkerExitGuard worker_exit_guard{*worker_exited_slot};
                config::detail::DeferredDiagnostics startup_diags{
                    .threshold = startup_threshold,
                    .records = {},
                };
                // Publish our thread id so is_worker_thread() can detect setter-invoked self-calls into
                // disable_auto_reload(). The guard, declared first so its destructor runs after the final flush
                // callback on every exit path, clears the slot again as the worker exits (see WorkerThreadIdGuard).
                worker_id_slot->store(std::this_thread::get_id(), std::memory_order_release);
                const WorkerThreadIdGuard worker_id_guard{*worker_id_slot};

                // start() co-owns open_result for the whole bounded wait, so a dropped body copy cannot wake the
                // waiter through broken_promise. The body must publish the result on every exit itself. settle()
                // records success or failure exactly once. The guard publishes a failure on any exit that has not
                // settled, including a bad_alloc from the allocations just below, before the first read is queued.
                // A pre-handshake throw therefore returns start() promptly with a failure instead of running the
                // full 5s handshake timeout.
                bool handshake_settled = false;
                auto settle = [&](bool ok) noexcept -> void
                {
                    if (!handshake_settled)
                    {
                        handshake_settled = true;
                        try
                        {
                            open_result->set_value(ok);
                        }
                        catch (...)
                        {
                        }
                    }
                };
                class SettleGuard
                {
                public:
                    SettleGuard(std::shared_ptr<std::promise<bool>> promise, bool &settled) noexcept
                        : m_promise(std::move(promise)), m_settled(settled)
                    {
                    }

                    ~SettleGuard() noexcept
                    {
                        if (!m_settled)
                        {
                            m_settled = true;
                            try
                            {
                                m_promise->set_value(false);
                            }
                            catch (...)
                            {
                            }
                        }
                    }

                    SettleGuard(const SettleGuard &) = delete;
                    SettleGuard &operator=(const SettleGuard &) = delete;

                private:
                    std::shared_ptr<std::promise<bool>> m_promise;
                    bool &m_settled;
                } settle_guard{open_result, handshake_settled};

                const auto wait_for_release = [&]() noexcept
                {
                    auto state = startup_gate->wait.load(std::memory_order_acquire);
                    while (state == ConfigWatcherStartWait::Pending)
                    {
                        startup_gate->wait.wait(ConfigWatcherStartWait::Pending, std::memory_order_acquire);
                        state = startup_gate->wait.load(std::memory_order_acquire);
                    }
                };

                const auto complete_startup = [&](bool ok) noexcept
                {
                    config::detail::DeferredDiagnostics to_emit;
                    {
                        std::lock_guard<std::mutex> channel_lock(startup_gate->mutex);
                        startup_gate->diags = std::move(startup_diags);
                        startup_gate->complete = true;
                        if (startup_gate->wait.load(std::memory_order_acquire) == ConfigWatcherStartWait::Released &&
                            !startup_gate->emitted)
                        {
                            startup_gate->emitted = true;
                            to_emit = std::move(startup_gate->diags);
                        }
                    }
                    settle(ok);
                    config::detail::emit_deferred_diagnostics(to_emit);
                };

                const auto fail_startup = [&](std::string_view message) noexcept
                {
                    try
                    {
                        config::detail::defer_diagnostic(
                            startup_diags,
                            LogLevel::Error,
                            "StoppableWorker '{}': unhandled exception: {}",
                            "ConfigWatcher",
                            message
                        );
                    }
                    catch (...)
                    {
                        DetourModKit::detail::LoggerDropAccess::record(log());
                    }
                    complete_startup(false);
                };

                const auto fail_startup_unknown = [&]() noexcept
                {
                    try
                    {
                        config::detail::defer_diagnostic(
                            startup_diags,
                            LogLevel::Error,
                            "StoppableWorker '{}': unknown exception escaped body.",
                            "ConfigWatcher"
                        );
                    }
                    catch (...)
                    {
                        DetourModKit::detail::LoggerDropAccess::record(log());
                    }
                    complete_startup(false);
                };

                const std::stop_callback stop_wait_callback(
                    st,
                    [startup_gate]() noexcept { cancel_start_wait(startup_gate); }
                );

                if (st.stop_requested() || stop_requested_slot->load(std::memory_order_acquire))
                {
                    complete_startup(false);
                    return;
                }

                std::unique_ptr<WatchIoState> io;
                try
                {
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (auto *seam = g_config_watcher_prehandshake_seam)
                    {
                        seam();
                    }
#endif

                    io = std::make_unique<WatchIoState>();
                    io->buffer.resize(BUFFER_BYTES);

                    io->dir_handle = OwnedHandle(
                        ::CreateFileW(
                            directory.c_str(),
                            FILE_LIST_DIRECTORY,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                            nullptr
                        )
                    );

                    if (!io->dir_handle.valid())
                    {
                        config::detail::defer_diagnostic(
                            startup_diags,
                            LogLevel::Error,
                            "ConfigWatcher '{}': CreateFileW failed (GLE={}).",
                            label,
                            ::GetLastError()
                        );
                        complete_startup(false);
                        return;
                    }

#if defined(DMK_ENABLE_TEST_SEAMS)
                    const bool force_event_failure = g_config_watcher_create_event_failure_seam != nullptr &&
                                                     g_config_watcher_create_event_failure_seam();
#else
                    constexpr bool force_event_failure = false;
#endif
                    if (!force_event_failure)
                    {
                        io->event_handle = OwnedHandle(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
                    }
                    if (force_event_failure || !io->event_handle.valid())
                    {
                        config::detail::defer_diagnostic(
                            startup_diags,
                            LogLevel::Error,
                            "ConfigWatcher '{}': CreateEventW failed (GLE={}).",
                            label,
                            force_event_failure ? ERROR_GEN_FAILURE : ::GetLastError()
                        );
                        complete_startup(false);
                        return;
                    }

                    io->overlapped.hEvent = io->event_handle.h;
                }
                catch (const std::exception &e)
                {
                    fail_startup(e.what());
                    return;
                }
                catch (...)
                {
                    fail_startup_unknown();
                    return;
                }

                // These aliases keep the pump unchanged while its storage remains heap-owned for the drain.
                OwnedHandle &dir_handle = io->dir_handle;
                OwnedHandle &event_handle = io->event_handle;
                std::vector<BYTE> &buffer = io->buffer;
                OVERLAPPED &overlapped = io->overlapped;

                // Debounce bookkeeping: once we observe a matching change, mark it pending and defer the callback
                // until no matching change has arrived for `debounce_ms`. Using steady_clock to survive wall-clock
                // adjustments.
                bool pending = false;
                std::chrono::steady_clock::time_point last_event{};

                // Track whether an overflow/coalesced-events completion has already been logged once per instance;
                // subsequent hits stay silent at DEBUG level to avoid log spam.
                bool overflow_logged = false;

                // The callback boundary is noexcept because a thrown callback before the drain can free storage that
                // the pending I/O still uses. try_log keeps both catch handlers within that boundary.
                auto fire_reload = [&]() noexcept
                {
                    if (!callback)
                    {
                        return;
                    }
                    try
                    {
                        callback();
                    }
                    catch (const std::exception &e)
                    {
                        (void)log()
                            .try_log(LogLevel::Error, "ConfigWatcher '{}': reload callback threw: {}", label, e.what());
                    }
                    catch (...)
                    {
                        (void)log().try_log(
                            LogLevel::Error,
                            "ConfigWatcher '{}': reload callback threw a non-std exception.",
                            label
                        );
                    }
                };

                // Check the debounce deadline before every wait. Foreign file events can prevent WAIT_TIMEOUT while
                // they leave last_event unchanged. This placement fires the reload after the target quiet window.
                auto maybe_fire_debounced = [&]() noexcept
                {
                    if (pending && std::chrono::steady_clock::now() - last_event >= debounce_ms)
                    {
                        pending = false;
                        fire_reload();
                    }
                };

                auto issue_read = [&]() -> bool
                {
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (!handshake_settled && g_config_watcher_initial_read_failure_seam != nullptr &&
                        g_config_watcher_initial_read_failure_seam())
                    {
                        config::detail::defer_diagnostic(
                            startup_diags,
                            LogLevel::Error,
                            "ConfigWatcher '{}': ReadDirectoryChangesW failed (GLE={}).",
                            label,
                            ERROR_GEN_FAILURE
                        );
                        return false;
                    }
#endif
                    ::ResetEvent(event_handle.h);
                    DWORD bytes_returned = 0;
                    const BOOL ok = ::ReadDirectoryChangesW(
                        dir_handle.h,
                        buffer.data(),
                        static_cast<DWORD>(buffer.size()),
                        FALSE, // no recursion
                        NOTIFY_FILTER,
                        &bytes_returned,
                        &overlapped,
                        nullptr
                    );
                    if (!ok)
                    {
                        if (!handshake_settled)
                        {
                            config::detail::defer_diagnostic(
                                startup_diags,
                                LogLevel::Error,
                                "ConfigWatcher '{}': ReadDirectoryChangesW failed (GLE={}).",
                                label,
                                ::GetLastError()
                            );
                        }
                        else
                        {
                            (void)log().try_log(
                                LogLevel::Error,
                                "ConfigWatcher '{}': ReadDirectoryChangesW failed (GLE={}).",
                                label,
                                ::GetLastError()
                            );
                        }
                        return false;
                    }
                    return true;
                };

                try
                {
                    if (!issue_read())
                    {
                        complete_startup(false);
                        return;
                    }
                }
                catch (const std::exception &e)
                {
                    fail_startup(e.what());
                    return;
                }
                catch (...)
                {
                    fail_startup_unknown();
                    return;
                }

                // First overlapped read is queued successfully; signal start() that the watcher is ready. From here
                // on any failure is post-startup and reported only via the log.
                complete_startup(true);
                wait_for_release();

                while (!st.stop_requested() && !stop_requested_slot->load(std::memory_order_acquire))
                {
                    // Check the debounce deadline before every wait. Foreign file traffic can prevent WAIT_TIMEOUT.
                    maybe_fire_debounced();

                    DWORD bytes_transferred = 0;
                    const BOOL overlapped_ok =
                        ::GetOverlappedResultEx(dir_handle.h, &overlapped, &bytes_transferred, PUMP_TIMEOUT_MS, FALSE);

                    if (!overlapped_ok)
                    {
                        const DWORD err = ::GetLastError();

                        if (err == WAIT_TIMEOUT || err == WAIT_IO_COMPLETION)
                        {
                            // No I/O completed this tick. The loop already checked the debounce deadline.
                            continue;
                        }

                        if (err == ERROR_OPERATION_ABORTED)
                        {
                            // Directory handle closed or I/O cancelled externally (e.g. the watched parent
                            // directory was removed or renamed). We cannot recover a handle to a vanished directory
                            // here; surface the event at warning level so users notice.
                            (void)log().try_log(
                                LogLevel::Warning,
                                "ConfigWatcher '{}': directory handle "
                                "invalidated (parent removed/renamed); "
                                "watcher thread exiting.",
                                label
                            );
                            break;
                        }

                        if (err == ERROR_NOTIFY_ENUM_DIR)
                        {
                            // Kernel/redirector path for buffer overflow:
                            // events were dropped because they arrived faster than we could drain them. Treat as a
                            // coalesced match, re-issue the read, and let debounce deduplicate.
                            if (!overflow_logged)
                            {
                                (void)log().try_log(
                                    LogLevel::Debug,
                                    "ConfigWatcher '{}': notification "
                                    "buffer overflowed (ERROR_NOTIFY_ENUM_DIR); "
                                    "coalescing dropped events.",
                                    label
                                );
                                overflow_logged = true;
                            }
                            pending = true;
                            last_event = std::chrono::steady_clock::now();
                            if (!issue_read())
                            {
                                break;
                            }
                            // Some redirectors raise ERROR_NOTIFY_ENUM_DIR continuously under sustained event
                            // storms. Without a sleep the worker would spin at 100% CPU re-issuing reads. Capping
                            // at ~20 Hz keeps debounce semantics intact while bounding CPU.
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        }

                        (void)log().try_log(
                            LogLevel::Error,
                            "ConfigWatcher '{}': GetOverlappedResultEx failed (GLE={}).",
                            label,
                            err
                        );
                        break;
                    }

                    bool matched = false;

                    if (bytes_transferred == 0)
                    {
                        // Successful-completion path for buffer overflow:
                        // the kernel signals "events coalesced" by returning zero bytes. Same handling as
                        // ERROR_NOTIFY_ENUM_DIR above: mark pending, re-issue, let debounce deduplicate.
                        if (!overflow_logged)
                        {
                            (void)log().try_log(
                                LogLevel::Debug,
                                "ConfigWatcher '{}': notification buffer "
                                "overflowed (zero-byte completion); "
                                "coalescing dropped events.",
                                label
                            );
                            overflow_logged = true;
                        }
                        matched = true;
                    }
                    else
                    {
                        // Real event batch received. Reset the overflow latch so a later recurrence logs again at
                        // the DEBUG edge rather than staying silent forever.
                        overflow_logged = false;

                        // Walk the FILE_NOTIFY_INFORMATION chain. The kernel is trusted, but every kernel-supplied
                        // length/offset is bounds-checked against the buffer before any read or advance: trusting
                        // FileNameLength or NextEntryOffset blindly would turn a corrupt/malicious completion into
                        // an out-of-bounds read of the worker's heap buffer. On any inconsistency the walk stops
                        // (fails closed) rather than reading past the bytes the kernel actually returned.
                        const BYTE *cursor = buffer.data();
                        const BYTE *const end_ptr = cursor + bytes_transferred;

                        // Offset of the variable-length FileName[] member; the fixed header occupies the bytes
                        // before it. Used to bound both the header and the filename extent against end_ptr.
                        constexpr size_t name_field_offset = offsetof(FILE_NOTIFY_INFORMATION, FileName);

                        // (a) The entry header itself must fit before we dereference any of its fields. Compare on
                        // the remaining span before forming cursor + name_field_offset, so malformed trailing bytes
                        // cannot make the bounds check itself step outside the buffer.
                        while (static_cast<size_t>(end_ptr - cursor) >= name_field_offset)
                        {
                            const auto *info = reinterpret_cast<const FILE_NOTIFY_INFORMATION *>(cursor);

                            const DWORD name_bytes = info->FileNameLength;

                            // (c) FileNameLength must be a whole number of WCHARs; an odd byte count is malformed.
                            if (name_bytes % sizeof(WCHAR) != 0)
                            {
                                break;
                            }

                            // (b) FileName + FileNameLength must not run past the buffer end. Compare on the
                            // available span (end_ptr - FileName) so the addition cannot overflow a pointer.
                            const BYTE *const name_start = cursor + name_field_offset;
                            if (name_bytes > static_cast<size_t>(end_ptr - name_start))
                            {
                                break;
                            }

                            const size_t name_len = name_bytes / sizeof(WCHAR);
                            const std::wstring_view changed_name(info->FileName, name_len);

                            // Match against target filename (case-insensitive). Rename-swap-save (temp -> target)
                            // surfaces the target filename in the RENAMED_NEW_NAME entry.
                            if (iequals_w(changed_name, filename))
                            {
                                matched = true;
                            }

                            // A zero NextEntryOffset terminates the walk (the spec's end-of-chain marker).
                            const DWORD next = info->NextEntryOffset;
                            if (next == 0)
                            {
                                break;
                            }

                            // (d) NextEntryOffset must advance past at least this entry's header (forward progress,
                            // so a bogus small value cannot loop or alias the current entry) and must keep the next
                            // entry's start at or before the buffer end; the loop condition then re-validates that
                            // the next entry's header fully fits. Compare on the available span to avoid pointer
                            // overflow.
                            if (next < name_field_offset || next > static_cast<size_t>(end_ptr - cursor))
                            {
                                break;
                            }
                            cursor += next;
                        }
                    }

                    if (matched)
                    {
                        pending = true;
                        last_event = std::chrono::steady_clock::now();
                    }

                    if (!issue_read())
                    {
                        break;
                    }
                }

                // Cancel any in-flight I/O, then wait for the kernel to finish with our OVERLAPPED and notification
                // buffer before they are freed. Per MSDN the OVERLAPPED and buffer must stay valid until the
                // cancelled I/O has actually completed; freeing them early would let the kernel write into released
                // memory.
                //
                // CancelIoEx normally drives the pending ReadDirectoryChangesW to completion, but if the watched
                // directory was deleted the notify IRP can be orphaned: CancelIoEx reports success yet no
                // completion is ever delivered. A blind GetOverlappedResult with bWait=TRUE would then wait forever
                // and hang StoppableWorker's join (stalling the whole teardown). So every wait here is bounded and
                // the drain escalates:
                //   1. cancel + bounded wait for the normal case;
                //   2. on timeout, close the directory handle. Dropping the
                //      last handle to the directory forces the I/O Manager to
                //      cancel and complete the outstanding IRP, and signals our
                //      event (the mechanism .NET FileSystemWatcher.Dispose uses);
                //   3. if the IRP still cannot be confirmed complete, leak the
                //      entire I/O bundle instead of freeing it, so a late
                //      completion can never write into freed memory. Bounded to
                //      this teardown path and mirrors the leak-on-teardown
                //      discipline in ~ConfigWatcher and Logger::shutdown_internal.
                ::CancelIoEx(dir_handle.h, &overlapped);

                DWORD drain_bytes = 0;
                const BOOL drain_ok =
                    ::GetOverlappedResultEx(dir_handle.h, &overlapped, &drain_bytes, DRAIN_TIMEOUT_MS, FALSE);

                // Only WAIT_TIMEOUT / WAIT_IO_COMPLETION mean the IRP is still pending; any other status (including
                // ERROR_OPERATION_ABORTED) means the kernel is done with the OVERLAPPED and the buffer.
                bool drained = drain_ok != FALSE;
                if (!drained)
                {
                    const DWORD drain_err = ::GetLastError();
                    drained = drain_err != WAIT_TIMEOUT && drain_err != WAIT_IO_COMPLETION;
                }

                if (!drained)
                {
                    // Force completion by releasing the directory handle, then wait on the event the IRP signals on
                    // its way out.
                    dir_handle.reset();
                    drained = ::WaitForSingleObject(event_handle.h, DRAIN_TIMEOUT_MS) == WAIT_OBJECT_0;
                }

                if (!drained)
                {
                    config::detail::DeferredDiagnostics late_diags{
                        .threshold = startup_threshold,
                        .records = {},
                    };
                    try
                    {
                        config::detail::defer_diagnostic(
                            late_diags,
                            LogLevel::Warning,
                            "ConfigWatcher '{}': pending directory notification did not drain after cancel + "
                            "handle close; leaking the watch buffer to stay memory-safe.",
                            label
                        );
                        config::detail::DeferredDiagnostics to_emit;
                        {
                            std::lock_guard<std::mutex> channel_lock(startup_gate->mutex);
                            if (startup_gate->wait.load(std::memory_order_acquire) == ConfigWatcherStartWait::Released)
                            {
                                to_emit = std::move(late_diags);
                            }
                            else
                            {
                                startup_gate->late_diags = std::move(late_diags);
                            }
                        }
                        config::detail::emit_deferred_diagnostics(to_emit);
                    }
                    catch (...)
                    {
                        DetourModKit::detail::LoggerDropAccess::record(log());
                    }
                    (void)io.release();
                }

                // A final pending change fires during stop() so the debounce window does not discard it.
                // fire_reload contains callback exceptions after the I/O drain.
                if (pending)
                {
                    fire_reload();
                }
            };

            try
            {
                m_impl->worker_exited.store(false, std::memory_order_release);
                const WorkerStartLogDeferral start_log_deferral{
                    &diags,
                    &config::detail::defer_worker_start_diagnostic,
                };
                m_impl->worker = std::make_unique<StoppableWorker>("ConfigWatcher", std::move(worker_body));
            }
            catch (const std::exception &e)
            {
                m_impl->worker_exited.store(true, std::memory_order_release);
                config::detail::defer_diagnostic(
                    diags,
                    LogLevel::Error,
                    "ConfigWatcher '{}': failed to start worker: {}",
                    m_impl->ini_path_utf8,
                    e.what()
                );
                return false;
            }
            catch (...)
            {
                m_impl->worker_exited.store(true, std::memory_order_release);
                config::detail::defer_diagnostic(
                    diags,
                    LogLevel::Error,
                    "ConfigWatcher '{}': failed to start worker: unknown exception.",
                    m_impl->ini_path_utf8
                );
                return false;
            }

            // Wait for the worker's startup handshake with a bounded wait. The worker body settles the promise on
            // every exit path (see SettleGuard above), so this resolves promptly with the real result even when
            // the body throws before queuing the first read. The 5s bound only bites a genuinely wedged worker (a
            // hostile hook on CreateFileW/CreateEventW that never returns). Callers hold higher-level mutexes across
            // start(), so an unbounded wait would DoS the whole hot-reload subsystem. On a timeout the stale worker
            // must NOT be joined inline: see the handshake_timed_out branch below for why joining a possibly-hung
            // worker under start_mutex (and, via enable_auto_reload, get_watcher_mutex) would wedge the control
            // plane, and how the leak-on-timeout discipline avoids it.
            bool started = false;
            // Distinguishes the hung-worker case (handshake never completed) from a worker that reported failure and
            // is already returning. Only the former makes a join block; the two paths clean up differently.
            bool handshake_timed_out = false;
            try
            {
                const auto wait_status = open_future.wait_for(std::chrono::seconds(5));
                if (wait_status == std::future_status::ready)
                {
                    started = open_future.get();
                }
                else
                {
                    handshake_timed_out = true;
                    config::detail::defer_diagnostic(
                        diags,
                        LogLevel::Warning,
                        "ConfigWatcher '{}': start handshake timed out after 5s; treating as failed.",
                        m_impl->ini_path_utf8
                    );
                    started = false;
                }
            }
            catch (...)
            {
                started = false;
            }

            if (!started && handshake_timed_out)
            {
                // Leak-on-timeout, never block-on-timeout. The worker never completed its startup handshake, so it can
                // be genuinely wedged. A hostile-hooked CreateFileW/CreateEventW that never returns is failure mode 1
                // above. Joining it (the naive cleanup, via a local unique_ptr whose destructor joins) would block for
                // the process lifetime while this thread holds start_mutex and, when called from enable_auto_reload(),
                // get_watcher_mutex too, wedging every future start()/stop()/disable_auto_reload(). Instead request
                // stop (so the worker exits once its blocking syscall finally returns) and leak the whole Impl onto the
                // heap, mirroring ~ConfigWatcher's loader-lock branch: the detached std::jthread, its captured lambda
                // state (the directory/filename/callback strings it still reads) and the worker_thread_id slot it still
                // points at all live inside Impl, so Impl must outlive the detached thread. Leaking it skips ~Impl ->
                // ~StoppableWorker entirely (no join), and the module reference the worker took at construction is left
                // outstanding so its code pages stay mapped. A husked (null-Impl) ConfigWatcher is inert: the caller
                // drops it immediately (enable_auto_reload calls watcher.reset()), and stop()/start() null-guard
                // against it. The leak is bounded to one Impl per hostile start timeout, an exceptional path.
                if (m_impl->worker)
                {
                    m_impl->worker->request_stop();
                }
                leak_impl_storage(m_impl);
            }
            else if (!started)
            {
                // The worker reported a startup failure (CreateFileW/CreateEventW failed) or threw before the
                // handshake: either way it is already returning, so joining it does not block. Drop it the normal way,
                // which joins the exiting worker and releases its module reference. m_impl stays intact, so this
                // ConfigWatcher is reusable for a retry rather than husked, and nothing is leaked on a benign start
                // failure.
                m_impl->worker.reset();
            }
            return started;
        }

        void ConfigWatcher::stop() noexcept
        {
            if (!m_impl)
            {
                // Spent watcher (a start() timeout leaked the Impl); there is nothing left to stop.
                return;
            }
            // Publish before shutdown(), which re-queries blocking_teardown_permitted() for itself. That predicate is
            // process-global and can go false between ~ConfigWatcher's check and this one, so shutdown() may take its
            // unauthorized branch and detach without requesting stop. Without this flag the pump would then have no
            // exit signal at all while ~Impl frees the members it keeps reading. Harmless on the join path: the worker
            // is being stopped either way.
            m_impl->stop_requested.store(true, std::memory_order_release);
            cancel_start_wait(m_impl->start_gate.load(std::memory_order_acquire));

            std::unique_ptr<StoppableWorker> to_drop;
            {
                std::lock_guard<std::mutex> lock(m_impl->start_mutex);
                to_drop = std::move(m_impl->worker);
            }

            if (to_drop)
            {
                to_drop->shutdown();
            }
        }

        void ConfigWatcher::request_stop() noexcept
        {
            if (!m_impl)
            {
                return;
            }
            // The worker observes this within its 100 ms I/O pump interval. This must not take start_mutex: start()
            // may be inside its 5 s hostile-call handshake, while safe-unload preparation owns a shorter deadline.
            m_impl->stop_requested.store(true, std::memory_order_release);
            cancel_start_wait(m_impl->start_gate.load(std::memory_order_acquire));
        }

        bool ConfigWatcher::has_exited() const noexcept
        {
            return m_impl != nullptr && m_impl->worker_exited.load(std::memory_order_acquire);
        }
    } // namespace detail
} // namespace DetourModKit
