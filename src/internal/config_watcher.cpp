/**
 * @file config_watcher.cpp
 * @brief Implementation of the internal ConfigWatcher engine (ReadDirectoryChangesW-based), not installed.
 */

#include "config_watcher.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "DetourModKit/logger.hpp"
#include "DetourModKit/detail/worker.hpp"
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

namespace DetourModKit
{
    namespace detail
    {
        // Test-only override for is_loader_lock_held(). When non-null the ConfigWatcher destructor consults this hook
        // instead of the real PEB-based detection, letting the test suite exercise the detach-and-leak branch from user
        // code. Defined as a plain function pointer because the override is set/cleared on a single thread inside a
        // test fixture.
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
            // names: it applies the same simple uppercase fold NTFS/exFAT use for case-insensitivity, and -- unlike
            // ::towupper -- it does not consult the process locale. A watcher running under a Turkish (or any
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
                return ::CompareStringOrdinal(lhs.data(), static_cast<int>(lhs.size()), rhs.data(),
                                              static_cast<int>(rhs.size()), TRUE) == CSTR_EQUAL;
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
                // Under loader lock (FreeLibrary path): joining the watcher would deadlock against
                // ReadDirectoryChangesW's I/O completion, and tearing down Impl would invalidate the worker_thread_id
                // pointer the detached lambda still references. Request stop and leak the entire Impl onto the heap so
                // it outlives the destructor. The owned StoppableWorker keeps the worker's code pages mapped by leaking
                // its own module reference on its loader-lock detach branch, so no module reference is taken here. The
                // same loader-lock leaf discipline is used by the hook handle teardown and Logger::shutdown_internal.

                if (m_impl->worker)
                {
                    // shutdown() takes its own loader-lock branch: it requests stop and detaches the std::jthread (no
                    // join), then sets joined_ so the eventual ~StoppableWorker run during static teardown
                    // short-circuits without trying to join a detached handle.
                    m_impl->worker->shutdown();
                }

                // Per-call heap leak: each invocation allocates its own cell, so prior leaked Impls are never
                // overwritten and the leak is bounded by one cell per ~ConfigWatcher-under-loader-lock call. The
                // detached worker thread holds raw pointers and references into Impl members (worker_thread_id,
                // captured strings); they must stay valid until the OS thread either observes the stop_token and exits
                // or the process tears down.
                //
                // new (std::nothrow) keeps this noexcept destructor honest by returning nullptr on OOM rather than
                // turning a container emplace_back bad_alloc into std::terminate. On allocation failure, fall back to
                // releasing the unique_ptr so the Impl storage is leaked directly without invoking ~Impl (which would
                // tear down the detached StoppableWorker -- safe under a normal join, but not under loader lock).
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
                DetourModKit::diagnostics::record_intentional_leak(
                    DetourModKit::diagnostics::LeakSubsystem::ConfigWatcher);
                return;
            }

            stop();
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
            // The default (no-thread) id means no worker is currently published -- before start() posts the first read
            // or after the worker reset the slot on exit. Never report that state as a match, even when the caller
            // passes a default-constructed id, so a reset slot can never alias a real stop request.
            return worker != std::thread::id{} && worker == id;
        }

        bool ConfigWatcher::start()
        {
            if (!m_impl)
            {
                // Spent watcher: a prior start() timed out and leaked the Impl (see the leak-on-timeout branch below).
                // The instance is inert; the caller is expected to have dropped it. Fail closed rather than deref null.
                return false;
            }
            std::lock_guard<std::mutex> lock(m_impl->start_mutex);

            // Guard on existence, not is_running(): there is a window between make_unique<StoppableWorker> and the
            // worker body flipping the running flag. Checking is_running() here would let a second caller in that
            // window overwrite the still-starting worker.
            if (m_impl->worker)
            {
                return true;
            }

            if (m_impl->directory_wide.empty() || m_impl->filename_wide.empty())
            {
                log().error("ConfigWatcher: invalid INI path '{}'; cannot start.", m_impl->ini_path_utf8);
                return false;
            }

            // Capture everything the worker needs by value so the body can outlive the captured Impl members only in
            // the loader-lock detach path; under normal teardown stop() joins before m_impl unwinds.
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

            // Pointer to the Impl's atomic thread-id slot. Using the raw pointer rather than capturing m_impl by
            // reference: the lambda may outlive this stack frame via the StoppableWorker detach path, but ConfigWatcher
            // (and therefore Impl) cannot be destroyed before the worker joins -- the destructor calls stop() which
            // joins first. The atomic slot is always valid for as long as the worker exists.
            auto *worker_id_slot = &m_impl->worker_thread_id;

            auto worker_body = [directory = std::move(directory), filename = std::move(filename), debounce_ms,
                                callback = std::move(callback), label = std::move(label), open_result,
                                worker_id_slot](const std::stop_token &st)
            {
                // Publish our thread id so is_worker_thread() can detect setter-invoked self-calls into
                // disable_auto_reload(). The guard, declared first so its destructor runs after the final flush
                // callback on every exit path, clears the slot again as the worker exits (see WorkerThreadIdGuard).
                worker_id_slot->store(std::this_thread::get_id(), std::memory_order_release);
                const WorkerThreadIdGuard worker_id_guard{*worker_id_slot};
                auto io = std::make_unique<WatchIoState>();
                io->buffer.resize(BUFFER_BYTES);

                // Reference aliases keep the pump body below unchanged while the backing storage lives on the heap,
                // so the stop-path drain can leak the whole bundle in one move if a notify IRP cannot be confirmed
                // complete (see the drain at worker exit for why that matters). The references stay valid even
                // after io.release(): the object is leaked, not destroyed.
                OwnedHandle &dir_handle = io->dir_handle;
                OwnedHandle &event_handle = io->event_handle;
                std::vector<BYTE> &buffer = io->buffer;
                OVERLAPPED &overlapped = io->overlapped;

                dir_handle = OwnedHandle(::CreateFileW(
                    directory.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));

                if (!dir_handle.valid())
                {
                    log().error("ConfigWatcher '{}': CreateFileW failed (GLE={}).", label, ::GetLastError());
                    open_result->set_value(false);
                    return;
                }

                event_handle = OwnedHandle(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
                if (!event_handle.valid())
                {
                    log().error("ConfigWatcher '{}': CreateEventW failed (GLE={}).", label, ::GetLastError());
                    open_result->set_value(false);
                    return;
                }

                overlapped.hEvent = event_handle.h;

                // Debounce bookkeeping: once we observe a matching change, mark it pending and defer the callback
                // until no matching change has arrived for `debounce_ms`. Using steady_clock to survive wall-clock
                // adjustments.
                bool pending = false;
                std::chrono::steady_clock::time_point last_event{};

                // Track whether an overflow/coalesced-events completion has already been logged once per instance;
                // subsequent hits stay silent at DEBUG level to avoid log spam.
                bool overflow_logged = false;

                // Invoke the user reload callback with exception containment. Honoring the header's "a throwing
                // callback is caught and the watcher keeps running" promise here is a hard memory-safety requirement:
                // if a throw were allowed to unwind out of this worker body it would run WatchIoState's destructor,
                // freeing the OVERLAPPED and the notification buffer while the pending ReadDirectoryChangesW notify IRP
                // may still reference them. That IRP is drained after the pump loop; an unwinding exception would skip
                // that drain and could let the kernel complete the cancelled I/O into freed heap. try_log keeps the
                // handlers non-throwing, and the noexcept marker turns "the drain is always reached" into a structural
                // guarantee rather than a comment.
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
                        (void)log().try_log(LogLevel::Error, "ConfigWatcher '{}': reload callback threw: {}", label,
                                            e.what());
                    }
                    catch (...)
                    {
                        (void)log().try_log(LogLevel::Error,
                                            "ConfigWatcher '{}': reload callback threw a non-std exception.", label);
                    }
                };

                // Evaluate the debounce deadline once per pump iteration, independent of which branch handled the last
                // wait. The library's own rotating log file typically shares the watched directory, so a burst of
                // sub-debounce log writes keeps GetOverlappedResultEx completing with (non-matching) events and the
                // loop never reaches its idle WAIT_TIMEOUT branch. If the deadline check lived only on that branch a
                // genuinely pending target reload would be starved until the first quiet gap. A non-matching change
                // never advances last_event (only a filename match does, in the walk below), so hoisting the check
                // preserves debounce coalescing exactly while guaranteeing the reload fires once the target's quiet
                // window elapses even under continuous foreign churn.
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
                    ::ResetEvent(event_handle.h);
                    DWORD bytes_returned = 0;
                    const BOOL ok =
                        ::ReadDirectoryChangesW(dir_handle.h, buffer.data(), static_cast<DWORD>(buffer.size()),
                                                FALSE, // no recursion
                                                NOTIFY_FILTER, &bytes_returned, &overlapped, nullptr);
                    if (!ok)
                    {
                        log().error("ConfigWatcher '{}': ReadDirectoryChangesW failed (GLE={}).", label,
                                    ::GetLastError());
                        return false;
                    }
                    return true;
                };

                if (!issue_read())
                {
                    open_result->set_value(false);
                    return;
                }

                // First overlapped read is queued successfully; signal start() that the watcher is ready. From here
                // on any failure is post-startup and reported only via the log.
                open_result->set_value(true);

                while (!st.stop_requested())
                {
                    // Evaluate the debounce deadline once per iteration, before every wait, so it is honored no matter
                    // which branch handled the previous completion. See maybe_fire_debounced above for why a per-branch
                    // (WAIT_TIMEOUT-only) check would starve a pending reload under sustained foreign-file churn.
                    maybe_fire_debounced();

                    DWORD bytes_transferred = 0;
                    const BOOL overlapped_ok =
                        ::GetOverlappedResultEx(dir_handle.h, &overlapped, &bytes_transferred, PUMP_TIMEOUT_MS, FALSE);

                    if (!overlapped_ok)
                    {
                        const DWORD err = ::GetLastError();

                        if (err == WAIT_TIMEOUT || err == WAIT_IO_COMPLETION)
                        {
                            // No I/O completed this tick. The debounce deadline is evaluated at the top of the loop, so
                            // a pending reload whose quiet window has elapsed has already fired; just re-enter the
                            // wait.
                            continue;
                        }

                        if (err == ERROR_OPERATION_ABORTED)
                        {
                            // Directory handle closed or I/O cancelled externally (e.g. the watched parent
                            // directory was removed or renamed). We cannot recover a handle to a vanished directory
                            // here; surface the event at warning level so users notice.
                            log().warning("ConfigWatcher '{}': directory handle "
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
                                log().debug("ConfigWatcher '{}': notification "
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
                            // Some redirectors raise ERROR_NOTIFY_ENUM_DIR continuously under sustained event
                            // storms. Without a sleep the worker would spin at 100% CPU re-issuing reads. Capping
                            // at ~20 Hz keeps debounce semantics intact while bounding CPU.
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        }

                        log().error("ConfigWatcher '{}': GetOverlappedResultEx failed (GLE={}).", label, err);
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
                            log().debug("ConfigWatcher '{}': notification buffer "
                                        "overflowed (zero-byte completion); "
                                        "coalescing dropped events.",
                                        label);
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
                //   2. on timeout, close the directory handle -- dropping the
                //      last handle to the directory forces the I/O Manager to
                //      cancel and complete the outstanding IRP, signalling our
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
                    log().warning("ConfigWatcher '{}': pending directory notification did "
                                  "not drain after cancel + handle close; leaking the watch "
                                  "buffer to stay memory-safe.",
                                  label);
                    (void)io.release();
                }

                // Flush a final debounced callback if we are exiting with a pending change. This intentionally
                // fires during stop() as well -- an edit that arrived inside the debounce window would otherwise be
                // silently dropped. Routed through the same guarded fire_reload so a throw on this final edge cannot
                // escape the worker body after the drain either.
                if (pending)
                {
                    fire_reload();
                }
            };

            try
            {
                m_impl->worker = std::make_unique<StoppableWorker>("ConfigWatcher", std::move(worker_body));
            }
            catch (const std::exception &e)
            {
                log().error("ConfigWatcher '{}': failed to start worker: {}", m_impl->ini_path_utf8, e.what());
                return false;
            }
            catch (...)
            {
                log().error("ConfigWatcher '{}': failed to start worker: unknown exception.", m_impl->ini_path_utf8);
                return false;
            }

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
            // On failure the stale worker must NOT be joined inline: see the !started branch below for why joining a
            // possibly-hung worker under start_mutex (and, via enable_auto_reload, get_watcher_mutex) would wedge the
            // whole hot-reload control plane, and how the leak-on-timeout discipline avoids it.
            bool started = false;
            // Distinguishes the hung-worker case (handshake never completed) from a worker that reported failure or
            // threw and is already returning. Only the former makes a join block; the two paths clean up differently.
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
                    log().warning("ConfigWatcher '{}': start handshake timed out after 5s; treating as failed.",
                                  m_impl->ini_path_utf8);
                    started = false;
                    handshake_timed_out = true;
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

            if (!started && handshake_timed_out)
            {
                // Leak-on-timeout, never block-on-timeout. The worker never completed its startup handshake, so it may
                // be genuinely wedged -- a hostile-hooked CreateFileW/CreateEventW that never returns is failure mode 1
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
                // new (std::nothrow) keeps this path allocation-honest; on OOM fall back to releasing the unique_ptr so
                // the Impl storage leaks directly without running ~Impl (which would join the hung worker).
                if (auto *leaked = new (std::nothrow) std::unique_ptr<Impl>(std::move(m_impl)))
                {
                    (void)leaked;
                }
                else
                {
                    (void)m_impl.release();
                }
                DetourModKit::diagnostics::record_intentional_leak(
                    DetourModKit::diagnostics::LeakSubsystem::ConfigWatcher);
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
    } // namespace detail
} // namespace DetourModKit
