#include "DetourModKit/logger.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/filesystem.hpp"

#include "internal/async_logger.hpp"
#include "internal/win_file_stream.hpp"
#include "platform.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <new>
#include <stdexcept>
#include <type_traits>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    // Test-only probe fired from Logger::shutdown_internal() inside its dropped-mutex window -- async logging already
    // disabled but the sink stream not yet closed. When non-null, a fixture uses it to prove that enable_async_mode()'s
    // m_shutdown_called gate refuses to resurrect async logging in exactly that gap (the one interleaving a bare
    // after-shutdown enable cannot reach, because by then the stream is also closed). Set / cleared on a single thread
    // inside a test fixture; the definition and fire site compile out of shipping builds.
    void (*g_logger_shutdown_gap_probe)() noexcept = nullptr;
#endif
} // namespace DetourModKit::detail

namespace DetourModKit
{

    namespace
    {
        constexpr std::size_t EMERGENCY_ASYNC_LOGGER_LEAK_SLOTS = 16;

        struct AsyncLoggerLeakSlot
        {
            alignas(std::shared_ptr<AsyncLogger>) unsigned char storage[sizeof(std::shared_ptr<AsyncLogger>)]{};
            std::atomic<bool> occupied{false};
        };

        std::atomic<std::shared_ptr<const Logger::StaticConfig>> &static_config_atom()
        {
            static std::atomic<std::shared_ptr<const Logger::StaticConfig>> instance{
                std::make_shared<const Logger::StaticConfig>(DEFAULT_LOG_PREFIX, DEFAULT_LOG_FILE_NAME,
                                                             DEFAULT_TIMESTAMP_FORMAT)};
            return instance;
        }

        void leak_async_logger_handle(std::shared_ptr<AsyncLogger> &logger) noexcept
        {
            static_assert(std::is_nothrow_move_constructible_v<std::shared_ptr<AsyncLogger>>,
                          "AsyncLogger leak cells must be nothrow-move-constructible.");

            if (!logger)
            {
                return;
            }

            // No module reference is taken here: leaking the shared_ptr keeps the AsyncLogger and its writer thread
            // alive, and that writer thread holds its own counted reference on this module (taken before thread
            // creation, while the module was fully mapped), which is what keeps its code mapped.
            auto *leaked = new (std::nothrow) std::shared_ptr<AsyncLogger>(std::move(logger));
            if (leaked != nullptr)
            {
                (void)leaked;
                DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Logger);
                return;
            }

            void *virtual_cell =
                VirtualAlloc(nullptr, sizeof(std::shared_ptr<AsyncLogger>), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (virtual_cell != nullptr)
            {
                new (virtual_cell) std::shared_ptr<AsyncLogger>(std::move(logger));
                DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Logger);
                return;
            }

            static AsyncLoggerLeakSlot emergency_slots[EMERGENCY_ASYNC_LOGGER_LEAK_SLOTS];
            for (auto &slot : emergency_slots)
            {
                bool expected = false;
                if (slot.occupied.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
                {
                    new (static_cast<void *>(slot.storage)) std::shared_ptr<AsyncLogger>(std::move(logger));
                    DetourModKit::diagnostics::record_intentional_leak(
                        DetourModKit::diagnostics::LeakSubsystem::Logger);
                    return;
                }
            }

            std::terminate();
        }
    } // anonymous namespace

    std::shared_ptr<const Logger::StaticConfig> Logger::get_static_config()
    {
        return static_config_atom().load(std::memory_order_acquire);
    }

    void Logger::set_static_config(std::shared_ptr<const StaticConfig> config)
    {
        static_config_atom().store(std::move(config), std::memory_order_release);
    }

    LogLevel string_to_log_level(std::string_view level_str)
    {
        std::string upper_level_str(level_str);
        std::transform(upper_level_str.begin(), upper_level_str.end(), upper_level_str.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

        if (upper_level_str == "TRACE")
            return LogLevel::Trace;
        if (upper_level_str == "DEBUG")
            return LogLevel::Debug;
        if (upper_level_str == "INFO")
            return LogLevel::Info;
        if (upper_level_str == "WARNING")
            return LogLevel::Warning;
        if (upper_level_str == "ERROR")
            return LogLevel::Error;

        std::cerr << "[" << DEFAULT_LOG_PREFIX << " Logger WARNING] Unrecognized log level string '" << level_str
                  << "'. Defaulting to INFO." << '\n';
        return LogLevel::Info;
    }

    void Logger::configure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt)
    {
        set_static_config(std::make_shared<const StaticConfig>(std::string(prefix), std::string(file_name),
                                                               std::string(timestamp_fmt)));

        // Qualify the free accessor: inside this static member an unqualified log() would bind to the member log()
        // overload set (which all take arguments), hiding the namespace-scope process-default accessor.
        Logger &instance = DetourModKit::log();

        // An inert first-use logger (OOM at construction) owns no sink or mutex and cannot be reconfigured into a
        // live one; it stays inert for the process generation.
        if (instance.is_inert())
        {
            return;
        }

        // configure() is the authoritative reset path: it may re-enable the process default even after a shutdown so
        // a test fixture or re-attach can reuse the sink. Clear the shutdown flag and apply the settings UNDER the
        // same lock shutdown_internal() takes to close the sink, so the reset is serialized against a concurrent
        // shutdown -- configure never reopens in the middle of shutdown's close, and shutdown never closes a sink
        // configure just reopened. Whichever acquires the lock last determines the final sink state deterministically.
        std::scoped_lock lock(instance.m_async_mutex, *instance.m_log_mutex_ptr);
        if (instance.m_async_writer_abandoned.load(std::memory_order_acquire))
        {
            // A detached writer retains final sink ownership. Reopening this facade would create a second sink owner.
            return;
        }
        instance.m_shutdown_called.store(false, std::memory_order_release);
        instance.reconfigure_locked(prefix, file_name, timestamp_fmt);
    }

    void Logger::reconfigure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt)
    {
        if (is_inert() || m_async_writer_abandoned.load(std::memory_order_acquire))
        {
            return;
        }

        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return;
        }

        // Acquire both m_async_mutex and *m_log_mutex_ptr to prevent concurrent log() calls from reading
        // partially-updated string members during reconfiguration.
        std::scoped_lock lock(m_async_mutex, *m_log_mutex_ptr);
        if (m_shutdown_called.load(std::memory_order_acquire) ||
            m_async_writer_abandoned.load(std::memory_order_acquire))
        {
            return;
        }
        reconfigure_locked(prefix, file_name, timestamp_fmt);
    }

    void Logger::reconfigure_locked(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt)
    {
        // Precondition: the caller holds m_async_mutex and *m_log_mutex_ptr.

        // Skip only when all parameters match AND the stream is usable. After shutdown or a prior open failure the
        // stream may be closed, so fall through to reopen even if the strings are identical.
        if (m_log_file_stream_ptr->is_open() && m_log_file_stream_ptr->good() && m_log_prefix == prefix &&
            m_log_file_name == file_name && m_timestamp_format == timestamp_fmt)
        {
            return;
        }

        // The prefix and timestamp format are applied per line, not baked into the open file, so a change that keeps
        // the same file needs no reopen -- and reopening would truncate the existing records. Detect a file change to
        // decide between keeping the open stream and (re)opening a different or closed sink.
        const bool file_changed = (m_log_file_name != file_name);

        m_log_prefix = prefix;
        m_log_file_name = file_name;
        m_timestamp_format = timestamp_fmt;

        if (!file_changed && m_log_file_stream_ptr->is_open() && m_log_file_stream_ptr->good())
        {
            // Same file, still open: keep the stream and its records. Note the change in-line; never truncate.
            if (m_log_file_stream_ptr->good())
            {
                *m_log_file_stream_ptr << "[" << get_timestamp() << "] "
                                       << "[" << std::setw(7) << std::left << "INFO" << "] :: "
                                       << "Logger reconfigured (same file retained)." << '\n';
                m_log_file_stream_ptr->flush();
            }
        }
        else
        {
            // A different target file, or a closed stream: (re)open it in append mode so existing records in the
            // target file are preserved. Only the process-start constructor truncates.
            if (m_log_file_stream_ptr->is_open() && m_log_file_stream_ptr->good())
            {
                *m_log_file_stream_ptr << "[" << get_timestamp() << "] "
                                       << "[" << std::setw(7) << std::left << "INFO" << "] :: "
                                       << "Logger reconfiguring. New file: " << file_name << '\n';
                m_log_file_stream_ptr->flush();
                m_log_file_stream_ptr->close();
            }
            open_sink(/*reconfiguring=*/true, /*truncate=*/false);
        }

        // Push the new timestamp format into any live async writer. enable_async_mode snapshots the format into the
        // AsyncLogger's private config at construction and the writer shares the WinFileStream kept/reopened above, so
        // without this push a format change would leave every async line on the old format. Safe under the held
        // scoped_lock: the setter assigns without locking and the writer reads the format only under *m_log_mutex_ptr.
        if (m_async_mode_enabled.load(std::memory_order_acquire))
        {
            if (auto async_logger = m_async_logger.load(std::memory_order_acquire))
            {
                async_logger->set_timestamp_format(m_timestamp_format);
            }
        }
    }

    Logger::Logger()
        : m_log_file_stream_ptr(std::make_shared<detail::WinFileStream>()),
          m_log_mutex_ptr(std::make_shared<std::mutex>())
    {
        const auto config = get_static_config();
        m_log_prefix = config->log_prefix;
        m_log_file_name = config->log_file_name;
        m_timestamp_format = config->timestamp_format;

        // A process start truncates for a fresh log; a reconfigure never does (see reconfigure_locked).
        open_sink(false, /*truncate=*/true);
    }

    Logger::Logger(InertTag) noexcept
    {
        // Inert first-use logger. No sink, shared sink mutex, or writer is allocated, so is_inert() (a null
        // m_log_mutex_ptr) is true and every enabled log request fails closed by dropping and counting. Constructing
        // the empty string and atomic members allocates nothing, so this stays no-throw under the OOM that forced the
        // fallback.
    }

    Logger::Logger(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt)
        : m_log_prefix(prefix), m_log_file_name(file_name), m_timestamp_format(timestamp_fmt),
          m_log_file_stream_ptr(std::make_shared<detail::WinFileStream>()),
          m_log_mutex_ptr(std::make_shared<std::mutex>())
    {
        // A process start truncates for a fresh log; a reconfigure never does (see reconfigure_locked).
        open_sink(false, /*truncate=*/true);
    }

    void Logger::open_sink(bool reconfiguring, bool truncate)
    {
        // The caller owns the synchronization: a constructor runs single-threaded before the logger is reachable, and
        // reconfigure_locked() holds both lifecycle and file mutexes. open_sink never locks, so it composes with
        // either. A truncating open starts a fresh file (a process start); an append open preserves existing records
        // (every reconfigure), so a same-file reopen never loses prior lines.
        const std::wstring log_file_full_path = generate_log_file_path();
        const auto mode = truncate ? (std::ios::out | std::ios::trunc) : (std::ios::out | std::ios::app);
        m_log_file_stream_ptr->open(log_file_full_path, mode);

        if (!m_log_file_stream_ptr->is_open())
        {
            std::cerr << "[" << m_log_prefix << " Logger CRITICAL ERROR] "
                      << "Failed to open log file: " << std::filesystem::path(log_file_full_path).string()
                      << ". Subsequent logs to file will fail." << '\n';
            return;
        }

        *m_log_file_stream_ptr << "[" << get_timestamp() << "] [" << std::setw(7) << std::left << "INFO" << "] :: "
                               << "Logger "
                               << (reconfiguring ? "reconfigured. Now logging to: " : "initialized. Logging to: ")
                               << m_log_file_name << '\n';
    }

    Logger::~Logger() noexcept
    {
        bool expected = false;
        if (!m_shutdown_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return;
        }
        shutdown_internal();
    }

    void Logger::shutdown() noexcept
    {
        bool expected = false;
        if (!m_shutdown_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return;
        }
        shutdown_internal();
    }

    void Logger::shutdown_internal() noexcept
    {
        // An inert first-use logger owns no async writer, sink, or shared sink mutex, so there is nothing to drain or
        // close.
        if (is_inert())
        {
            return;
        }

        std::shared_ptr<AsyncLogger> local_logger;
        bool writer_detached = false;

        {
            std::lock_guard<std::mutex> lock(m_async_mutex);
            if (m_async_mode_enabled.load(std::memory_order_acquire))
            {
                local_logger = m_async_logger.exchange(nullptr, std::memory_order_acq_rel);
                m_async_mode_enabled.store(false, std::memory_order_release);
                if (local_logger)
                {
                    local_logger->shutdown();
                    writer_detached = local_logger->writer_was_detached();
                    m_dropped_messages.fetch_add(local_logger->dropped_count(), std::memory_order_relaxed);
                    if (writer_detached)
                    {
                        // The retained writer still owns the sink. Latch the facade inert before releasing the
                        // lifecycle mutex so configure cannot reopen behind it.
                        m_async_writer_abandoned.store(true, std::memory_order_release);
                    }
                }
            }
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        // Test-only probe: fires in the dropped-mutex window opened above -- m_async_mode_enabled is now false but the
        // sink stream is still open -- so a fixture can prove enable_async_mode()'s m_shutdown_called gate refuses to
        // resurrect async logging in exactly this gap. Null and branch-only in production.
        if (auto *gap_probe = detail::g_logger_shutdown_gap_probe)
        {
            gap_probe();
        }
#endif

        // A configure call that ran inside the gap above must not leave the facade live after this shutdown continues.
        m_shutdown_called.store(true, std::memory_order_release);

        // A detached writer still owns the AsyncLogger state and final sink access. Retain the handle permanently and
        // return without sink I/O. Keying on the recorded detach outcome avoids a loader-lock re-query race, and an
        // unconditional per-call leak protects temporary shared_ptr owners and repeated detach cycles. The retention
        // helper has non-throwing permanent-storage fallbacks.
        if (writer_detached)
        {
            leak_async_logger_handle(local_logger);
            return;
        }

        {
            // Normal path: the writer was joined (or async was never enabled), so this thread is the single owner of
            // final sink access. Acquire both mutexes to prevent configure()/reconfigure() from opening a new stream in
            // the gap after the async-logger teardown block above releases m_async_mutex.
            std::scoped_lock lock(m_async_mutex, *m_log_mutex_ptr);
            m_shutdown_called.store(true, std::memory_order_release);
            if (m_log_file_stream_ptr && m_log_file_stream_ptr->is_open())
            {
                m_log_file_stream_ptr->flush();
                m_log_file_stream_ptr->close();
            }
        }
    }

    void Logger::set_log_level(LogLevel level)
    {
        auto level_int = static_cast<std::underlying_type_t<LogLevel>>(level);
        if (level_int < 0 || level_int > static_cast<std::underlying_type_t<LogLevel>>(LogLevel::Error))
        {
            log(LogLevel::Warning, "Attempted to set an invalid log level value ({}). Keeping current level.",
                level_int);
            return;
        }

        auto old_level = m_current_log_level.load(std::memory_order_acquire);
        if (old_level == level)
        {
            return;
        }

        m_current_log_level.store(level, std::memory_order_release);

        log(LogLevel::Info, "Log level changed from {} to {}", to_string(old_level), to_string(level));
    }

    bool Logger::log(LogLevel level, std::string_view message)
    {
        if (level < m_current_log_level.load(std::memory_order_acquire))
        {
            return false;
        }

        if (m_shutdown_called.load(std::memory_order_acquire) ||
            m_async_writer_abandoned.load(std::memory_order_acquire))
        {
            m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // An inert first-use logger (construction failed under OOM) owns no sink or shared sink mutex. Drop and count
        // the record instead of dereferencing a null pointer; it stays inert for the process lifetime.
        if (is_inert())
        {
            m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // Fast path: an atomic<bool> gate (a genuine lock-free read) selects async mode. The atomic<shared_ptr>
        // snapshot that follows is correct and callback-safe but takes a bounded internal STL lock, not a lock-free
        // read (see the m_async_logger member comment in logger.hpp), so it is not described as lock-free here.
        if (m_async_mode_enabled.load(std::memory_order_acquire))
        {
            auto local_logger = m_async_logger.load(std::memory_order_acquire);
            if (local_logger)
            {
                // Propagate the queue's accept/drop result so callers learn the true delivery status instead of an
                // unconditional success.
                return local_logger->enqueue(level, message);
            }
        }

        const auto level_str = to_string(level);
        std::lock_guard<std::mutex> lock(*m_log_mutex_ptr);

        // Close the race where shutdown exchanges the async handle after the first check but before this thread reaches
        // the synchronous sink. An admitted synchronous write finishes before shutdown can acquire this same mutex.
        if (m_shutdown_called.load(std::memory_order_acquire) ||
            m_async_writer_abandoned.load(std::memory_order_acquire))
        {
            m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        if (m_log_file_stream_ptr->is_open() && m_log_file_stream_ptr->good())
        {
            *m_log_file_stream_ptr << "[" << get_timestamp() << "] "
                                   << "[" << std::setw(7) << std::left << level_str << "] :: " << message << '\n';

            // Flush on warnings/errors to ensure critical messages survive crashes
            if (level >= LogLevel::Warning)
            {
                m_log_file_stream_ptr->flush();
            }

            // Report whether the write (and any flush) left the stream healthy, so log_noexcept()/try_log() reflect
            // actual delivery rather than just a no-throw call.
            const bool delivered = m_log_file_stream_ptr->good();
            if (!delivered)
            {
                m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
            }
            return delivered;
        }

        if (level >= LogLevel::Error)
        {
            std::cerr << "[" << m_log_prefix << " LOG_FILE_WRITE_ERROR] [" << get_timestamp() << "] [" << std::setw(7)
                      << std::left << level_str << "] :: " << message << '\n';
        }

        // The file sink was closed or unhealthy; the message was not delivered to it (an error-level message reached
        // stderr only as a last resort). Count it so dropped_count() reflects the loss.
        m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    bool Logger::log_noexcept(LogLevel level, std::string_view message) noexcept
    {
        // The synchronous sink allocates (timestamp formatting) and a custom stream could raise, so the throwing log()
        // is wrapped here to keep the no-throw contract for noexcept-boundary callers. The returned bool is log()'s
        // real delivery status, not merely "did not throw".
        try
        {
            return log(level, message);
        }
        catch (...)
        {
            return false;
        }
    }

    std::string Logger::get_timestamp() const
    {
        try
        {
            const auto now = std::chrono::system_clock::now();
            const auto in_time_t = std::chrono::system_clock::to_time_t(now);
            std::tm timeinfo_struct = {};

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
            // MinGW's localtime_s takes the same (struct tm *, const time_t *) argument order as MSVC, not the ISO C11
            // Annex K order, so the call is identical.
            if (localtime_s(&timeinfo_struct, &in_time_t) != 0)
            {
                throw std::runtime_error("localtime_s failed to convert time.");
            }
#else
            if (localtime_r(&in_time_t, &timeinfo_struct) == nullptr)
            {
                throw std::runtime_error("localtime_r failed to convert time.");
            }
#endif
            // Single stack buffer for timestamp + milliseconds, no heap allocation
            char buf[134];
            const size_t len = std::strftime(buf, sizeof(buf) - 5, m_timestamp_format.c_str(), &timeinfo_struct);
            if (len == 0)
            {
                return "TIMESTAMP_FORMAT_ERROR";
            }

            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            const int ms_len = std::snprintf(buf + len, 5, ".%03d", static_cast<int>(ms.count()));
            return std::string(buf, len + static_cast<size_t>(ms_len));
        }
        catch (const std::exception &e)
        {
            std::cerr << "[" << m_log_prefix << " Logger TIMESTAMP_ERROR] Failed to generate timestamp: " << e.what()
                      << '\n';
            return "TIMESTAMP_GENERATION_ERROR";
        }
        catch (...)
        {
            std::cerr << "[" << m_log_prefix
                      << " Logger TIMESTAMP_ERROR] Unknown exception during timestamp generation." << '\n';
            return "TIMESTAMP_GENERATION_ERROR";
        }
    }

    std::wstring Logger::generate_log_file_path() const
    {
        std::filesystem::path log_file_path_obj(m_log_file_name);
        if (log_file_path_obj.is_absolute())
        {
            return log_file_path_obj.wstring();
        }

        try
        {
            std::wstring module_dir = filesystem::get_runtime_directory();
            if (module_dir.empty() || module_dir == L".")
            {
                std::cerr << "[" << m_log_prefix << " Logger PATH_WARNING] "
                          << "Could not determine module directory. Using relative path: " << m_log_file_name << '\n';
                return log_file_path_obj.wstring();
            }

            const std::filesystem::path final_log_path = std::filesystem::path(module_dir) / m_log_file_name;
            return final_log_path.lexically_normal().wstring();
        }
        catch (const std::exception &e)
        {
            std::cerr << "[" << m_log_prefix
                      << " Logger PATH_WARNING] Failed to determine module directory for log file: " << e.what()
                      << ". Using relative path for log file: " << m_log_file_name << '\n';
            return log_file_path_obj.wstring();
        }
        catch (...)
        {
            std::cerr << "[" << m_log_prefix
                      << " Logger PATH_WARNING] Unknown exception while determining module directory for log file."
                      << " Using relative path: " << m_log_file_name << '\n';
            return log_file_path_obj.wstring();
        }
    }

    void Logger::enable_async_mode(const AsyncLoggerConfig &config)
    {
        // An inert first-use logger has no sink to feed a writer thread; async mode stays unavailable for its
        // process-lifetime inert state.
        if (is_inert())
        {
            return;
        }

        bool should_log_error = false;
        bool should_log_success = false;
        std::string error_msg;
        size_t queue_cap = 0;
        size_t batch_sz = 0;

        {
            std::lock_guard<std::mutex> lock(m_async_mutex);

            // Refuse to resurrect async logging after shutdown. shutdown()/~Logger set m_shutdown_called before
            // shutdown_internal() clears m_async_mode_enabled, and shutdown_internal() drops m_async_mutex between that
            // clear and the final stream close. Checking the gate under this mutex closes that window: a concurrent
            // enable could otherwise see async mode off and a still-open stream, then start a writer that outlives
            // teardown. configure() re-clears the gate after a clean shutdown, so legitimate re-enable still works.
            if (m_shutdown_called.load(std::memory_order_acquire))
            {
                return;
            }

            if (m_async_writer_abandoned.load(std::memory_order_acquire))
            {
                return;
            }

            if (m_async_mode_enabled.load(std::memory_order_acquire))
            {
                return;
            }

            if (!m_log_file_stream_ptr->is_open())
            {
                should_log_error = true;
                error_msg = "Cannot enable async mode: log file is not open.";
            }
            else
            {
                try
                {
                    // Override the config's timestamp format with the Logger's own so the async sink emits the same
                    // timestamps as the synchronous path; callers configure the format through the Logger, not the
                    // async config.
                    AsyncLoggerConfig effective_config = config;
                    effective_config.timestamp_format = m_timestamp_format;
                    m_async_logger.store(
                        std::make_shared<AsyncLogger>(effective_config, m_log_file_stream_ptr, m_log_mutex_ptr),
                        std::memory_order_release);
                    m_async_mode_enabled.store(true, std::memory_order_release);
                    should_log_success = true;
                    queue_cap = config.queue_capacity;
                    batch_sz = config.batch_size;
                }
                catch (const std::exception &e)
                {
                    should_log_error = true;
                    error_msg = std::string("Failed to enable async mode: ") + e.what();
                }
            }
        }

        if (should_log_error)
        {
            log(LogLevel::Error, "{}", error_msg);
        }
        else if (should_log_success)
        {
            log(LogLevel::Info, "Async logging mode enabled. Queue capacity: {}, Batch size: {}", queue_cap, batch_sz);
        }
    }

    void Logger::enable_async_mode()
    {
        enable_async_mode(AsyncLoggerConfig{});
    }

    void Logger::disable_async_mode() noexcept
    {
        std::shared_ptr<AsyncLogger> local_async;
        bool should_log = false;

        {
            std::lock_guard<std::mutex> lock(m_async_mutex);

            if (!m_async_mode_enabled.load(std::memory_order_acquire))
            {
                return;
            }

            local_async = m_async_logger.exchange(nullptr, std::memory_order_acq_rel);
            if (local_async)
            {
                local_async->shutdown();
                m_dropped_messages.fetch_add(local_async->dropped_count(), std::memory_order_relaxed);
                if (local_async->writer_was_detached())
                {
                    // A detached writer retains final sink ownership. Make every facade operation fail closed rather
                    // than switching to a second synchronous writer on the same sink.
                    m_async_writer_abandoned.store(true, std::memory_order_release);
                    m_shutdown_called.store(true, std::memory_order_release);
                }
            }

            m_async_mode_enabled.store(false, std::memory_order_release);
            should_log = true;
        }

        // Mirror shutdown_internal's ownership rule: a detached writer keeps exclusive access to live AsyncLogger
        // state, so retain every detached handle through the non-throwing permanent-storage path.
        const bool leaked_under_loader_lock = local_async && local_async->writer_was_detached();
        if (leaked_under_loader_lock)
        {
            leak_async_logger_handle(local_async);
        }

        if (should_log && !leaked_under_loader_lock)
        {
            // disable_async_mode() is noexcept; the synchronous sink can allocate and throw while formatting this
            // line. Fail closed: drop the diagnostic rather than letting an exception escape the mode switch.
            try
            {
                log(LogLevel::Info, "Async logging mode disabled. Switched to synchronous mode.");
            }
            catch (...)
            {
            }
        }
    }

    bool Logger::is_async_mode_enabled() const noexcept
    {
        return m_async_mode_enabled.load(std::memory_order_acquire);
    }

    std::size_t Logger::dropped_count() const noexcept
    {
        std::size_t total = m_dropped_messages.load(std::memory_order_relaxed);
        if (m_async_mode_enabled.load(std::memory_order_acquire))
        {
            if (auto async_logger = m_async_logger.load(std::memory_order_acquire))
            {
                total += async_logger->dropped_count();
            }
        }
        return total;
    }

    void Logger::flush() noexcept
    {
        if (is_inert() || m_async_writer_abandoned.load(std::memory_order_acquire))
        {
            return;
        }

        if (m_async_mode_enabled.load(std::memory_order_acquire))
        {
            auto local_logger = m_async_logger.load(std::memory_order_acquire);
            if (local_logger)
            {
                local_logger->flush();
                return;
            }
        }

        std::lock_guard<std::mutex> lock(*m_log_mutex_ptr);
        if (m_log_file_stream_ptr->is_open())
        {
            m_log_file_stream_ptr->flush();
        }
    }

    Logger &log() noexcept
    {
        // The process-default logger, created once and INTENTIONALLY never destroyed. A plain function-local static
        // Logger would be reclaimed during CRT atexit teardown, so a later static destructor or a detached thread that
        // logs after that point would touch freed storage. Holding the object behind a leaked pointer keeps it alive
        // for the whole process; the pointer itself is a reachable static, so a leak sanitizer sees the allocation as
        // still-reachable rather than leaked. shutdown() (invoked by the Session teardown) flushes and closes the sink
        // explicitly, so the deliberate leak costs only the object's storage, never a lost flush. First-use
        // construction can allocate: create_process_default() catches an out-of-memory failure and publishes an inert
        // drop/count logger instead of letting the throw terminate this noexcept accessor.
        static Logger *const instance = Logger::create_process_default();
        return *instance;
    }

    Logger *Logger::create_process_default() noexcept
    {
        // Prefer the full logger. If its construction throws -- first-use OOM allocating the logger object, its sink,
        // or its mutex -- publish a process-lifetime inert logger rather than letting the throw escape the noexcept
        // free log() and terminate the host. The inert logger allocates nothing, so this fallback is safe even while
        // allocation is still failing, and it latches for the process generation because this static runs once.
        try
        {
            return new Logger();
        }
        catch (...)
        {
            alignas(Logger) static unsigned char inert_storage[sizeof(Logger)];
            return ::new (static_cast<void *>(inert_storage)) Logger(InertTag{});
        }
    }

} // namespace DetourModKit
