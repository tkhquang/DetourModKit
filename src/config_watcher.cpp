/**
 * @file config_watcher.cpp
 * @brief Implementation of ConfigWatcher (ReadDirectoryChangesW-based).
 */

#include "DetourModKit/config_watcher.hpp"

#include "DetourModKit/logger.hpp"
#include "DetourModKit/worker.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace DetourModKit
{
    namespace
    {
        constexpr DWORD kNotifyFilter =
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_SIZE;

        // Sized so bursty editor saves do not overflow a single call while
        // still fitting comfortably on the worker's stack.
        constexpr DWORD kBufferBytes = 16 * 1024;

        // Pumping timeout for GetOverlappedResultEx. Bounds how long a
        // pending stop() must wait for the worker to observe its
        // stop_token; idle cost is ~10 syscalls/s per watcher (not zero).
        constexpr DWORD kPumpTimeoutMs = 100;

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

            OwnedHandle(OwnedHandle &&other) noexcept
                : h(std::exchange(other.h, INVALID_HANDLE_VALUE)) {}

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

            [[nodiscard]] bool valid() const noexcept
            {
                return h != INVALID_HANDLE_VALUE && h != nullptr;
            }

            void reset() noexcept
            {
                if (valid())
                {
                    ::CloseHandle(h);
                }
                h = INVALID_HANDLE_VALUE;
            }
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

        Impl(std::string_view path,
             std::chrono::milliseconds deb,
             std::function<void()> cb)
            : ini_path_utf8(path),
              debounce(deb),
              on_reload(std::move(cb))
        {
            // Resolve into directory + filename components up-front.
            // weakly_canonical is avoided because the file may not exist yet;
            // absolute() is enough for ReadDirectoryChangesW.
            std::error_code ec;
            std::filesystem::path p(ini_path_utf8);
            std::filesystem::path abs = std::filesystem::absolute(p, ec);
            if (ec)
            {
                abs = p;
            }

            directory_wide = abs.parent_path().wstring();
            filename_wide = abs.filename().wstring();
        }
    };

    ConfigWatcher::ConfigWatcher(std::string_view ini_path,
                                 std::chrono::milliseconds debounce_window,
                                 std::function<void()> on_reload)
        : m_impl(std::make_unique<Impl>(ini_path, debounce_window, std::move(on_reload)))
    {
    }

    ConfigWatcher::~ConfigWatcher() noexcept
    {
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
        return m_impl->worker_thread_id.load(std::memory_order_acquire) == id;
    }

    bool ConfigWatcher::start()
    {
        std::lock_guard<std::mutex> lock(m_impl->start_mutex);

        // Guard on existence, not is_running(): there is a window between
        // make_unique<StoppableWorker> and the worker body flipping the
        // running flag. Checking is_running() here would let a second
        // caller in that window overwrite the still-starting worker.
        if (m_impl->worker)
        {
            return true;
        }

        if (m_impl->directory_wide.empty() || m_impl->filename_wide.empty())
        {
            Logger::get_instance().error(
                "ConfigWatcher: invalid INI path '{}'; cannot start.",
                m_impl->ini_path_utf8);
            return false;
        }

        // Capture everything the worker needs by value so the body can
        // outlive the captured Impl members only in the loader-lock detach
        // path; under normal teardown stop() joins before m_impl unwinds.
        auto directory = m_impl->directory_wide;
        auto filename = m_impl->filename_wide;
        auto debounce_ms = m_impl->debounce;
        auto callback = m_impl->on_reload;
        auto label = m_impl->ini_path_utf8;

        // The StoppableWorker body is stored in std::function, so the
        // lambda must stay copyable; we cannot move a non-copyable
        // OwnedHandle into it. Instead, open the directory handle on the
        // worker thread and synchronously report success/failure back to
        // this thread via a shared promise. start() can then return the
        // real status without polling is_running() in a race.
        auto open_result = std::make_shared<std::promise<bool>>();
        std::future<bool> open_future = open_result->get_future();

        // Pointer to the Impl's atomic thread-id slot. Using the raw
        // pointer rather than capturing m_impl by reference: the lambda
        // may outlive this stack frame via the StoppableWorker detach
        // path, but ConfigWatcher (and therefore Impl) cannot be
        // destroyed before the worker joins -- the destructor calls
        // stop() which joins first. The atomic slot is always valid for
        // as long as the worker exists.
        auto *worker_id_slot = &m_impl->worker_thread_id;

        m_impl->worker = std::make_unique<StoppableWorker>(
            "ConfigWatcher",
            [directory = std::move(directory),
             filename = std::move(filename),
             debounce_ms,
             callback = std::move(callback),
             label = std::move(label),
             open_result,
             worker_id_slot](std::stop_token st)
            {
                // Publish our thread id so is_worker_thread() can detect
                // setter-invoked self-calls into disable_auto_reload().
                worker_id_slot->store(std::this_thread::get_id(),
                                      std::memory_order_release);
                OwnedHandle dir_handle(::CreateFileW(
                    directory.c_str(),
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    nullptr));

                if (!dir_handle.valid())
                {
                    Logger::get_instance().error(
                        "ConfigWatcher '{}': CreateFileW failed (GLE={}).",
                        label, ::GetLastError());
                    open_result->set_value(false);
                    return;
                }

                OwnedHandle event_handle(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
                if (!event_handle.valid())
                {
                    Logger::get_instance().error(
                        "ConfigWatcher '{}': CreateEventW failed (GLE={}).",
                        label, ::GetLastError());
                    open_result->set_value(false);
                    return;
                }

                std::vector<BYTE> buffer(kBufferBytes);
                OVERLAPPED overlapped{};
                overlapped.hEvent = event_handle.h;

                // Debounce bookkeeping: once we observe a matching change,
                // mark it pending and defer the callback until no matching
                // change has arrived for `debounce_ms`. Using steady_clock
                // to survive wall-clock adjustments.
                bool pending = false;
                std::chrono::steady_clock::time_point last_event{};

                // Track whether an overflow/coalesced-events completion has
                // already been logged once per instance; subsequent hits
                // stay silent at DEBUG level to avoid log spam.
                bool overflow_logged = false;

                auto issue_read = [&]() -> bool
                {
                    ::ResetEvent(event_handle.h);
                    DWORD bytes_returned = 0;
                    const BOOL ok = ::ReadDirectoryChangesW(
                        dir_handle.h,
                        buffer.data(),
                        static_cast<DWORD>(buffer.size()),
                        FALSE, // no recursion
                        kNotifyFilter,
                        &bytes_returned,
                        &overlapped,
                        nullptr);
                    if (!ok)
                    {
                        Logger::get_instance().error(
                            "ConfigWatcher '{}': ReadDirectoryChangesW failed (GLE={}).",
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

                // First overlapped read is queued successfully; signal
                // start() that the watcher is ready. From here on any
                // failure is post-startup and reported only via the log.
                open_result->set_value(true);

                while (!st.stop_requested())
                {
                    DWORD bytes_transferred = 0;
                    const BOOL overlapped_ok = ::GetOverlappedResultEx(
                        dir_handle.h, &overlapped, &bytes_transferred,
                        kPumpTimeoutMs, FALSE);

                    if (!overlapped_ok)
                    {
                        const DWORD err = ::GetLastError();

                        if (err == WAIT_TIMEOUT || err == WAIT_IO_COMPLETION)
                        {
                            // No I/O completed this tick. If a prior event
                            // is pending and the quiet window has elapsed,
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
                            // Directory handle closed or I/O cancelled
                            // externally (e.g. the watched parent
                            // directory was removed or renamed). We
                            // cannot recover a handle to a vanished
                            // directory here; surface the event at
                            // warning level so users notice.
                            Logger::get_instance().warning(
                                "ConfigWatcher '{}': directory handle "
                                "invalidated (parent removed/renamed); "
                                "watcher thread exiting.",
                                label);
                            break;
                        }

                        if (err == ERROR_NOTIFY_ENUM_DIR)
                        {
                            // Kernel/redirector path for buffer overflow:
                            // events were dropped because they arrived
                            // faster than we could drain them. Treat as
                            // a coalesced match, re-issue the read, and
                            // let debounce deduplicate.
                            if (!overflow_logged)
                            {
                                Logger::get_instance().debug(
                                    "ConfigWatcher '{}': notification "
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
                            // Some redirectors raise ERROR_NOTIFY_ENUM_DIR
                            // continuously under sustained event storms.
                            // Without a sleep the worker would spin at
                            // 100% CPU re-issuing reads. Capping at ~20
                            // Hz keeps debounce semantics intact while
                            // bounding CPU.
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(50));
                            continue;
                        }

                        Logger::get_instance().error(
                            "ConfigWatcher '{}': GetOverlappedResultEx failed (GLE={}).",
                            label, err);
                        break;
                    }

                    bool matched = false;

                    if (bytes_transferred == 0)
                    {
                        // Successful-completion path for buffer overflow:
                        // the kernel signals "events coalesced" by
                        // returning zero bytes. Same handling as
                        // ERROR_NOTIFY_ENUM_DIR above: mark pending,
                        // re-issue, let debounce deduplicate.
                        if (!overflow_logged)
                        {
                            Logger::get_instance().debug(
                                "ConfigWatcher '{}': notification buffer "
                                "overflowed (zero-byte completion); "
                                "coalescing dropped events.",
                                label);
                            overflow_logged = true;
                        }
                        matched = true;
                    }
                    else
                    {
                        // Real event batch received. Reset the overflow
                        // latch so a later recurrence logs again at the
                        // DEBUG edge rather than staying silent forever.
                        overflow_logged = false;

                        // Walk the FILE_NOTIFY_INFORMATION chain.
                        const BYTE *cursor = buffer.data();
                        const BYTE *const end_ptr = cursor + bytes_transferred;

                        while (cursor + sizeof(FILE_NOTIFY_INFORMATION) <= end_ptr)
                        {
                            const auto *info =
                                reinterpret_cast<const FILE_NOTIFY_INFORMATION *>(cursor);

                            const size_t name_len =
                                info->FileNameLength / sizeof(WCHAR);
                            const std::wstring_view changed_name(info->FileName, name_len);

                            // Match against target filename (case-insensitive).
                            // Rename-swap-save (temp -> target) surfaces the
                            // target filename in the RENAMED_NEW_NAME entry.
                            if (iequals_w(changed_name, filename))
                            {
                                matched = true;
                            }

                            if (info->NextEntryOffset == 0)
                            {
                                break;
                            }
                            cursor += info->NextEntryOffset;
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

                // Cancel any in-flight I/O and then WAIT for the kernel
                // to finish with our OVERLAPPED and buffer. Per MSDN the
                // OVERLAPPED structure and the backing buffer must remain
                // valid until the cancelled I/O has actually completed;
                // skipping the drain would let the kernel write into
                // stack memory after it had been released. Infinite wait
                // is safe because CancelIoEx guarantees completion.
                ::CancelIoEx(dir_handle.h, &overlapped);
                DWORD drain_bytes = 0;
                const BOOL drained = ::GetOverlappedResult(
                    dir_handle.h, &overlapped, &drain_bytes, TRUE);
                if (!drained)
                {
                    const DWORD drain_err = ::GetLastError();
                    if (drain_err != ERROR_OPERATION_ABORTED &&
                        drain_err != ERROR_NOTIFY_ENUM_DIR &&
                        drain_err != ERROR_INVALID_HANDLE)
                    {
                        Logger::get_instance().warning(
                            "ConfigWatcher '{}': drain GetOverlappedResult "
                            "returned unexpected error (GLE={}).",
                            label, drain_err);
                    }
                }

                // Flush a final debounced callback if we are exiting
                // with a pending change. This intentionally fires during
                // stop() as well -- an edit that arrived inside the
                // debounce window would otherwise be silently dropped.
                if (pending && callback)
                {
                    callback();
                }
            });

        // Wait for the worker to finish its startup handshake with a
        // bounded wait. Three failure modes to handle:
        //   1. Handshake timeout -- worker is stuck somewhere (hostile
        //      AntiCheat hook on CreateFileW, flaky redirector). Callers
        //      hold higher-level mutexes across start(); an unbounded
        //      wait would DoS the whole hot-reload subsystem.
        //   2. Worker threw before set_value() -- promise destroys,
        //      future.get() throws std::future_error(broken_promise).
        //      start() is documented to return false on failure, not
        //      throw.
        //   3. Any other exception out of the future -- treat as failed.
        // On failure we drop the StoppableWorker so a subsequent
        // start() call can retry rather than staring at a stale worker.
        // The worker's stop_token fires on StoppableWorker destruction,
        // so we do not need a separate cancel path for the timeout
        // branch -- the destructor does it cleanly.
        bool started = false;
        try
        {
            const auto wait_status =
                open_future.wait_for(std::chrono::seconds(5));
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
            // stale's destructor triggers the stop_token and joins. If the
            // worker is still genuinely hung (case 1 above), the join
            // itself will block here, but that matches the semantics a
            // caller expects from RAII cleanup; they asked to start()
            // under a stuck CreateFileW, the destructor is the logical
            // place to wait for it to come back.
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
} // namespace DetourModKit
