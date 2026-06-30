/**
 * @file config_watcher.cpp
 * @brief Implementation of the internal ConfigWatcher engine (ReadDirectoryChangesW-based), not installed.
 */

#include "config_watcher.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "DetourModKit/logger.hpp"
#include "DetourModKit/worker.hpp"
#include "platform.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace DetourModKit::detail
{
    // Test-only override for is_loader_lock_held(). When non-null the ConfigWatcher destructor consults this hook
    // instead of the real PEB-based detection, letting the test suite exercise the detach-and-leak branch from user
    // code. Defined as a plain function pointer because the override is set/cleared on a single thread inside a test
    // fixture.
    bool (*g_config_watcher_loader_lock_override)() noexcept = nullptr;

    namespace
    {
        constexpr DWORD NOTIFY_FILTER =
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE;

        bool loader_lock_held_for_watcher() noexcept
        {
            if (auto *override_fn = g_config_watcher_loader_lock_override)
            {
                return override_fn();
            }
            return is_loader_lock_held();
        }

        // Sized so bursty editor saves do not overflow a single call while still fitting comfortably on the worker's
        // stack.
        constexpr DWORD BUFFER_BYTES = 16 * 1024;

        // Pumping timeout for GetOverlappedResultEx. Bounds how long a pending stop() must wait for the worker to
        // observe its stop_token; idle cost is ~10 syscalls/s per watcher (not zero).
        constexpr DWORD PUMP_TIMEOUT_MS = 100;

        // Per-wait bound for the stop-path drain. Only bites when a notify IRP is genuinely stuck (a deleted/orphaned
        // watched directory); in the normal case the cancelled read completes in microseconds and the wait returns
        // immediately. Two waits (cancel, then handle-close) cap worst-case teardown at ~2 * this value instead of an
        // infinite hang.
        constexpr DWORD DRAIN_TIMEOUT_MS = 1000;

        bool iequals_w(std::wstring_view lhs, std::wstring_view rhs) noexcept
        {
            if (lhs.size() != rhs.size())
            {
                return false;
            }
            for (size_t i = 0; i < lhs.size(); ++i)
            {
                const wchar_t a = static_cast<wchar_t>(::towupper(lhs[i]));
                const wchar_t b = static_cast<wchar_t>(::towupper(rhs[i]));
                if (a != b)
                {
                    return false;
                }
            }
            return true;
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
        // buffer after a cancellation that the filesystem never finishes (e.g. the watched directory was deleted), so
        // those structures must outlive the worker rather than be freed while an IRP still references them.
        struct WatchIoState
        {
            OwnedHandle dir_handle;
            OwnedHandle event_handle;
            std::vector<BYTE> buffer;
            OVERLAPPED overlapped{};
        };

        // Resets an atomic thread-id slot to the default (no-thread) id when the worker leaves its body, covering every
        // exit path uniformly: a requested stop, a self-induced error exit, and the early CreateFileW/CreateEventW
        // failures that return after the id was already published. The worker publishes its own id on entry so
        // is_worker_thread() can detect setter-induced self-calls; clearing it as the worker exits keeps a later
        // OS-recycled thread id from matching this dead worker and suppressing a real stop request. The store
        // happens-before thread termination, so the slot is already cleared before the id can be reused.
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
        std::atomic<std::thread::id> worker_thread_id{};

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

    ConfigWatcher::ConfigWatcher(std::string_view ini_path, std::chrono::milliseconds debounce_window,
                                 std::function<void()> on_reload)
        : m_impl(std::make_unique<Impl>(ini_path, debounce_window, std::move(on_reload)))
    {
    }

    ConfigWatcher::~ConfigWatcher() noexcept
    {
        if (m_impl && loader_lock_held_for_watcher())
        {
            // Under loader lock (FreeLibrary path): joining the watcher would deadlock against ReadDirectoryChangesW's
            // I/O completion, and tearing down Impl would invalidate the worker_thread_id pointer the detached lambda
            // still references. Pin the module so trampoline and worker code pages remain mapped, request stop, then
            // leak the entire Impl onto the heap so it outlives the destructor. The same loader-lock leaf discipline
            // used by the hook handle teardown and Logger::shutdown_internal.
            pin_current_module();

            if (m_impl->worker)
            {
                // shutdown() takes its own loader-lock branch: it requests stop and detaches the std::jthread (no
                // join), then sets joined_ so the eventual ~StoppableWorker run during static teardown short-circuits
                // without trying to join a detached handle.
                m_impl->worker->shutdown();
            }

            // Per-call heap leak: each invocation allocates its own cell, so prior leaked Impls are never overwritten
            // and the leak is bounded by one cell per ~ConfigWatcher-under-loader-lock call. The detached worker thread
            // holds raw pointers and references into Impl members (worker_thread_id, captured strings); they must stay
            // valid until the OS thread either observes the stop_token and exits or the process tears down.
            //
            // new (std::nothrow) keeps this noexcept destructor honest by returning nullptr on OOM rather than turning
            // a container emplace_back bad_alloc into std::terminate. On allocation failure, fall back to releasing the
            // unique_ptr so the Impl storage is leaked directly without invoking ~Impl (which would tear down the
            // detached StoppableWorker -- safe under a normal join, but not under loader lock).
            static_assert(std::is_nothrow_move_constructible_v<std::unique_ptr<Impl>>,
                          "Leak cell must be nothrow-move-constructible to keep ~ConfigWatcher noexcept honest.");

            if (auto *leaked = new (std::nothrow) std::unique_ptr<Impl>(std::move(m_impl)))
            {
                (void)leaked;
            }
            else
            {
                (void)m_impl.release();
            }
            DetourModKit::Diagnostics::record_intentional_leak(DetourModKit::Diagnostics::LeakSubsystem::ConfigWatcher);
            return;
        }

        stop();
    }

    bool ConfigWatcher::is_running() const noexcept
    {
        return m_impl->worker && m_impl->worker->is_running();
    }

    const std::string &ConfigWatcher::ini_path() const noexcept
    {
        return m_impl->ini_path_utf8;
    }

    std::chrono::milliseconds ConfigWatcher::debounce() const noexcept
    {
        return m_impl->debounce;
    }

    bool ConfigWatcher::is_worker_thread(std::thread::id id) const noexcept
    {
        const std::thread::id worker = m_impl->worker_thread_id.load(std::memory_order_acquire);
        // The default (no-thread) id means no worker is currently published -- before start() posts the first read or
        // after the worker reset the slot on exit. Never report that state as a match, even when the caller passes a
        // default-constructed id, so a reset slot can never alias a real stop request.
        return worker != std::thread::id{} && worker == id;
    }

    bool ConfigWatcher::start()
    {
        std::lock_guard<std::mutex> lock(m_impl->start_mutex);

        // Guard on existence, not is_running(): there is a window between make_unique<StoppableWorker> and the worker
        // body flipping the running flag. Checking is_running() here would let a second caller in that window overwrite
        // the still-starting worker.
        if (m_impl->worker)
        {
            return true;
        }

        if (m_impl->directory_wide.empty() || m_impl->filename_wide.empty())
        {
            Logger::get_instance().error("ConfigWatcher: invalid INI path '{}'; cannot start.", m_impl->ini_path_utf8);
            return false;
        }

        // Capture everything the worker needs by value so the body can outlive the captured Impl members only in the
        // loader-lock detach path; under normal teardown stop() joins before m_impl unwinds.
        auto directory = m_impl->directory_wide;
        auto filename = m_impl->filename_wide;
        auto debounce_ms = m_impl->debounce;
        auto callback = m_impl->on_reload;
        auto label = m_impl->ini_path_utf8;

        // The StoppableWorker body is stored in std::function, so the lambda must stay copyable; we cannot move a
        // non-copyable
        // OwnedHandle into it. Instead, open the directory handle on the worker thread and synchronously report
        // success/failure back to this thread via a shared promise. start() can then return the real status without
        // polling is_running() in a race.
        auto open_result = std::make_shared<std::promise<bool>>();
        std::future<bool> open_future = open_result->get_future();

        // Pointer to the Impl's atomic thread-id slot. Using the raw pointer rather than capturing m_impl by reference:
        // the lambda may outlive this stack frame via the StoppableWorker detach path, but ConfigWatcher (and therefore
        // Impl) cannot be destroyed before the worker joins -- the destructor calls stop() which joins first. The
        // atomic slot is always valid for as long as the worker exists.
        auto *worker_id_slot = &m_impl->worker_thread_id;

        m_impl->worker = std::make_unique<StoppableWorker>(
            "ConfigWatcher",
            [directory = std::move(directory), filename = std::move(filename), debounce_ms,
             callback = std::move(callback), label = std::move(label), open_result, worker_id_slot](std::stop_token st)
            {
                // Publish our thread id so is_worker_thread() can detect setter-invoked self-calls into
                // disable_auto_reload(). The guard, declared first so its destructor runs after the final flush
                // callback on every exit path, clears the slot again as the worker exits (see WorkerThreadIdGuard).
                worker_id_slot->store(std::this_thread::get_id(), std::memory_order_release);
                const WorkerThreadIdGuard worker_id_guard{*worker_id_slot};
                auto io = std::make_unique<WatchIoState>();
                io->buffer.resize(BUFFER_BYTES);

                // Reference aliases keep the pump body below unchanged while the backing storage lives on the heap, so
                // the stop-path drain can leak the whole bundle in one move if a notify IRP cannot be confirmed
                // complete (see the drain at worker exit for why that matters). The references stay valid even after
                // io.release():
                // the object is leaked, not destroyed.
                OwnedHandle &dir_handle = io->dir_handle;
                OwnedHandle &event_handle = io->event_handle;
                std::vector<BYTE> &buffer = io->buffer;
                OVERLAPPED &overlapped = io->overlapped;

                dir_handle = OwnedHandle(::CreateFileW(
                    directory.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));

                if (!dir_handle.valid())
                {
                    Logger::get_instance().error("ConfigWatcher '{}': CreateFileW failed (GLE={}).", label,
                                                 ::GetLastError());
                    open_result->set_value(false);
                    return;
                }

                event_handle = OwnedHandle(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
                if (!event_handle.valid())
                {
                    Logger::get_instance().error("ConfigWatcher '{}': CreateEventW failed (GLE={}).", label,
                                                 ::GetLastError());
                    open_result->set_value(false);
                    return;
                }

                overlapped.hEvent = event_handle.h;

                // Debounce bookkeeping: once we observe a matching change, mark it pending and defer the callback until
                // no matching change has arrived for `debounce_ms`. Using steady_clock to survive wall-clock
                // adjustments.
                bool pending = false;
                std::chrono::steady_clock::time_point last_event{};

                // Track whether an overflow/coalesced-events completion has already been logged once per instance;
                // subsequent hits stay silent at DEBUG level to avoid log spam.
                bool overflow_logged = false;

                auto issue_read = [&]() -> bool
                {
                    ::ResetEvent(event_handle.h);
                    DWORD bytes_returned = 0;
                    const BOOL ok =
                        ::ReadDirectoryChangesW(dir_handle.h, buffer.data(), static_cast<DWORD>(buffer.size()),
                                                FALSE, // no recursion
                                                NOTIFY_FILTER, &bytes_returned, &overlapped, nullptr);
                    if (!ok)
                    {
                        Logger::get_instance().error("ConfigWatcher '{}': ReadDirectoryChangesW failed (GLE={}).",
                                                     label, ::GetLastError());
                        return false;
                    }
                    return true;
                };

                if (!issue_read())
                {
                    open_result->set_value(false);
                    return;
                }

                // First overlapped read is queued successfully; signal start() that the watcher is ready. From here on
                // any failure is post-startup and reported only via the log.
                open_result->set_value(true);

                while (!st.stop_requested())
                {
                    DWORD bytes_transferred = 0;
                    const BOOL overlapped_ok =
                        ::GetOverlappedResultEx(dir_handle.h, &overlapped, &bytes_transferred, PUMP_TIMEOUT_MS, FALSE);

                    if (!overlapped_ok)
                    {
                        const DWORD err = ::GetLastError();

                        if (err == WAIT_TIMEOUT || err == WAIT_IO_COMPLETION)
                        {
                            // No I/O completed this tick. If a prior event is pending and the quiet window has elapsed,
                            // fire the debounced callback.
                            if (pending)
                            {
                                const auto now = std::chrono::steady_clock::now();
                                if (now - last_event >= debounce_ms)
                                {
                                    pending = false;
                                    if (callback)
                                    {
                                        callback();
                                    }
                                }
                            }
                            continue;
                        }

                        if (err == ERROR_OPERATION_ABORTED)
                        {
                            // Directory handle closed or I/O cancelled externally (e.g. the watched parent directory
                            // was removed or renamed). We cannot recover a handle to a vanished directory here; surface
                            // the event at warning level so users notice.
                            Logger::get_instance().warning("ConfigWatcher '{}': directory handle "
                                                           "invalidated (parent removed/renamed); "
                                                           "watcher thread exiting.",
                                                           label);
                            break;
                        }

                        if (err == ERROR_NOTIFY_ENUM_DIR)
                        {
                            // Kernel/redirector path for buffer overflow:
                            // events were dropped because they arrived faster than we could drain them. Treat as a
                            // coalesced match, re-issue the read, and let debounce deduplicate.
                            if (!overflow_logged)
                            {
                                Logger::get_instance().debug("ConfigWatcher '{}': notification "
                                                             "buffer overflowed (ERROR_NOTIFY_ENUM_DIR); "
                                                             "coalescing dropped events.",
                                                             label);
                                overflow_logged = true;
                            }
                            pending = true;
                            last_event = std::chrono::steady_clock::now();
                            if (!issue_read())
                            {
                                break;
                            }
                            // Some redirectors raise ERROR_NOTIFY_ENUM_DIR continuously under sustained event storms.
                            // Without a sleep the worker would spin at
                            // 100% CPU re-issuing reads. Capping at ~20
                            // Hz keeps debounce semantics intact while bounding CPU.
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        }

                        Logger::get_instance().error("ConfigWatcher '{}': GetOverlappedResultEx failed (GLE={}).",
                                                     label, err);
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
                            Logger::get_instance().debug("ConfigWatcher '{}': notification buffer "
                                                         "overflowed (zero-byte completion); "
                                                         "coalescing dropped events.",
                                                         label);
                            overflow_logged = true;
                        }
                        matched = true;
                    }
                    else
                    {
                        // Real event batch received. Reset the overflow latch so a later recurrence logs again at the
                        // DEBUG edge rather than staying silent forever.
                        overflow_logged = false;

                        // Walk the FILE_NOTIFY_INFORMATION chain. The kernel is trusted, but every kernel-supplied
                        // length/offset is bounds-checked against the buffer before any read or advance: trusting
                        // FileNameLength or NextEntryOffset blindly would turn a corrupt/malicious completion into an
                        // out-of-bounds read of the worker's heap buffer. On any inconsistency the walk stops (fails
                        // closed) rather than reading past the bytes the kernel actually returned.
                        const BYTE *cursor = buffer.data();
                        const BYTE *const end_ptr = cursor + bytes_transferred;

                        // Offset of the variable-length FileName[] member; the fixed header occupies the bytes before
                        // it. Used to bound both the header and the filename extent against end_ptr.
                        constexpr size_t name_field_offset = offsetof(FILE_NOTIFY_INFORMATION, FileName);

                        // (a) The entry header itself must fit before we dereference any of its fields. Compare on the
                        // remaining span before forming cursor + name_field_offset, so malformed trailing bytes cannot
                        // make the bounds check itself step outside the buffer.
                        while (static_cast<size_t>(end_ptr - cursor) >= name_field_offset)
                        {
                            const auto *info = reinterpret_cast<const FILE_NOTIFY_INFORMATION *>(cursor);

                            const DWORD name_bytes = info->FileNameLength;

                            // (c) FileNameLength must be a whole number of WCHARs; an odd byte count is malformed.
                            if (name_bytes % sizeof(WCHAR) != 0)
                            {
                                break;
                            }

                            // (b) FileName + FileNameLength must not run past the buffer end. Compare on the available
                            // span (end_ptr - FileName) so the addition cannot overflow a pointer.
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

                            // (d) NextEntryOffset must advance past at least this entry's header (forward progress, so
                            // a bogus small value cannot loop or alias the current entry) and must keep the next
                            // entry's start at or before the buffer end; the loop condition then re-validates that the
                            // next entry's header fully fits. Compare on the available span to avoid pointer overflow.
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
                // buffer before they are freed. Per MSDN the OVERLAPPED and buffer must stay valid until the cancelled
                // I/O has actually completed; freeing them early would let the kernel write into released memory.
                //
                // CancelIoEx normally drives the pending ReadDirectoryChangesW to completion, but if the watched
                // directory was deleted the notify IRP can be orphaned: CancelIoEx reports success yet no completion is
                // ever delivered. A blind GetOverlappedResult with bWait=TRUE would then wait forever and hang
                // StoppableWorker's join (stalling the whole teardown). So every wait here is bounded and the drain
                // escalates:
                //   1. cancel + bounded wait for the normal case;
                //   2. on timeout, close the directory handle -- dropping the
                //      last handle to the directory forces the I/O Manager to
                //      cancel and complete the outstanding IRP, signalling our
                //      event (the mechanism .NET FileSystemWatcher.Dispose uses);
                //   3. if the IRP STILL cannot be confirmed complete, leak the
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
                    // Force completion by releasing the directory handle, then wait on the event the IRP signals on its
                    // way out.
                    dir_handle.reset();
                    drained = ::WaitForSingleObject(event_handle.h, DRAIN_TIMEOUT_MS) == WAIT_OBJECT_0;
                }

                if (!drained)
                {
                    Logger::get_instance().warning("ConfigWatcher '{}': pending directory notification did "
                                                   "not drain after cancel + handle close; leaking the watch "
                                                   "buffer to stay memory-safe.",
                                                   label);
                    (void)io.release();
                }

                // Flush a final debounced callback if we are exiting with a pending change. This intentionally fires
                // during stop() as well -- an edit that arrived inside the debounce window would otherwise be silently
                // dropped.
                if (pending && callback)
                {
                    callback();
                }
            });

        // Wait for the worker to finish its startup handshake with a bounded wait. Three failure modes to handle:
        //   1. Handshake timeout -- worker is stuck somewhere (hostile
        //      AntiCheat hook on CreateFileW, flaky redirector). Callers
        //      hold higher-level mutexes across start(); an unbounded
        //      wait would DoS the whole hot-reload subsystem.
        //   2. Worker threw before set_value() -- promise destroys,
        //      future.get() throws std::future_error(broken_promise).
        //      start() is documented to return false on failure, not
        //      throw.
        //   3. Any other exception out of the future -- treat as failed.
        // On failure we drop the StoppableWorker so a subsequent start() call can retry rather than staring at a stale
        // worker. The worker's stop_token fires on StoppableWorker destruction, so we do not need a separate cancel
        // path for the timeout branch -- the destructor does it cleanly.
        bool started = false;
        try
        {
            const auto wait_status = open_future.wait_for(std::chrono::seconds(5));
            if (wait_status == std::future_status::ready)
            {
                started = open_future.get();
            }
            else
            {
                Logger::get_instance().warning(
                    "ConfigWatcher '{}': start handshake timed out after 5s; treating as failed.",
                    m_impl->ini_path_utf8);
                started = false;
            }
        }
        catch (const std::future_error &)
        {
            // Worker threw before set_value() -- treat as startup failure.
            started = false;
        }
        catch (...)
        {
            started = false;
        }

        if (!started)
        {
            auto stale = std::move(m_impl->worker);
            // stale's destructor triggers the stop_token and joins. If the worker is still genuinely hung (case 1
            // above), the join itself will block here, but that matches the semantics a caller expects from RAII
            // cleanup; they asked to start() under a stuck CreateFileW, the destructor is the logical place to wait for
            // it to come back.
        }
        return started;
    }

    void ConfigWatcher::stop() noexcept
    {
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
} // namespace DetourModKit::detail
