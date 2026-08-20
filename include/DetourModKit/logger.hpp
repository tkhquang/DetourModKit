#ifndef DETOURMODKIT_LOGGER_HPP
#define DETOURMODKIT_LOGGER_HPP

/**
 * @file logger.hpp
 * @brief Process logging value facade, the free log() accessor, and source-location-stamped formatting.
 * @details Logger is a VALUE FACADE: a constructible object owning one file sink and an optional async writer. The
 *          free log() returns the process-default instance. Formatted records auto-stamp their call site through
 *          LocatedFormat. Logging is FAIL-SOFT: a dropped or filtered line is a best-effort bool, never a Result. The
 *          async transport stays behind the AsyncLogger pimpl.
 */

#include "DetourModKit/async_logger_config.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <mutex>
#include <source_location>
#include <string>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        // Forward-declared so this public header never pulls the Win32-backed file-stream definition onto a
        // consumer's include path. Logger's special members are out-of-line, so the shared_ptr is instantiated only
        // in logger.cpp.
        class WinFileStream;
    } // namespace detail

    /**
     * @enum LogLevel
     * @brief Severity levels for log messages, ordered from least to most severe.
     * @note The underlying values are contiguous from 0, so a level comparison is a plain integer compare on the hot
     *       path.
     */
    enum class LogLevel : std::uint8_t
    {
        Trace = 0,
        Debug = 1,
        Info = 2,
        Warning = 3,
        Error = 4
    };

    /**
     * @brief Returns the upper-case string name of a log level.
     * @param level The level to name.
     * @return A static string view ("TRACE".."ERROR"), or "UNKNOWN" for an out-of-range value.
     * @note Callback-safe: pure, allocation-free, and noexcept.
     */
    [[nodiscard]] constexpr std::string_view to_string(LogLevel level) noexcept
    {
        switch (level)
        {
        case LogLevel::Trace:
            return "TRACE";
        case LogLevel::Debug:
            return "DEBUG";
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warning:
            return "WARNING";
        case LogLevel::Error:
            return "ERROR";
        }
        return "UNKNOWN";
    }

    /**
     * @brief Parses a level name back into a LogLevel (case-insensitive).
     * @param level_str The level name, e.g. "INFO" or "debug". Surrounding whitespace is NOT trimmed.
     * @return The matching LogLevel, or LogLevel::Info when the string is unrecognized (a warning is written to
     *         stderr).
     * @details The fail-soft default to Info keeps a typo in an INI "LogLevel" key from silencing the log entirely.
     * @note Setup/control-plane only: allocates while upper-casing and may write to stderr; call from config parsing,
     *       not from a hot path.
     */
    [[nodiscard]] LogLevel string_to_log_level(std::string_view level_str);

    /**
     * @enum LogOpenMode
     * @brief Selects whether Logger construction replaces or preserves a target file.
     * @details Truncate starts a fresh file. Append preserves prior records across process generations. The mode
     *          affects only the first sink open. @ref Logger::reconfigure never truncates.
     */
    enum class LogOpenMode : std::uint8_t
    {
        /// Starts a fresh file and remains the default.
        Truncate,
        /// Preserves prior records and writes new records after them.
        Append
    };

    /// Default subsystem prefix stamped into the log file's banner line.
    inline constexpr std::string_view DEFAULT_LOG_PREFIX{"DetourModKit"};
    /// Default log file name, resolved against the runtime module directory when relative.
    inline constexpr std::string_view DEFAULT_LOG_FILE_NAME{"DetourModKit_Log.txt"};
    /// Default strftime-style timestamp format; the writer appends a ".<ms>" fraction after it.
    inline constexpr std::string_view DEFAULT_TIMESTAMP_FORMAT{"%Y-%m-%d %H:%M:%S"};

    // Upper bound, in bytes, on a log line the formatted fast path renders without a heap allocation. Mirrors the
    // async sink's inline message buffer (LogMessage::MAX_INLINE_SIZE). Longer lines take the documented overflow
    // path on both sides.
    inline constexpr std::size_t LOG_INLINE_MESSAGE_SIZE = 512;

    // AsyncLogger stays forward-declared so the lock-free queue and string pool never reach a consumer translation
    // unit. The complete type lives in src/internal/async_logger.hpp.
    class AsyncLogger;

    /**
     * @struct LocatedFormat
     * @brief A std::format_string that also captures the call site, so a variadic log() can auto-stamp source location.
     * @details A defaulted std::source_location parameter cannot follow a variadic pack, so the format-string
     *          argument captures the location instead. The consteval constructor validates the format string at
     *          compile time and records the caller's log site, not a location inside the logger.
     * @tparam Args The formatted argument types, deduced from the trailing pack at the call site.
     */
    template <typename... Args> struct LocatedFormat
    {
        /**
         * @brief Wraps a compile-time format string and records the originating source location.
         * @param s The format string, validated against Args at compile time exactly as std::format validates.
         * @param loc Defaulted to the call site through std::source_location::current(); do not pass explicitly.
         */
        template <typename String>
        consteval LocatedFormat(const String &s, std::source_location loc = std::source_location::current()) noexcept
            : fmt(s), where(loc)
        {
        }

        /// The validated format string forwarded to std::format at render time.
        std::format_string<Args...> fmt;
        /// The captured call site, rendered as a compact [file:line] stamp ahead of the message.
        std::source_location where;
    };

    /**
     * @class Logger
     * @brief A thread-safe file logger: the value facade behind the free log() accessor and Session::log().
     * @details Owns one mutex-protected file sink plus an optional async writer. The minimum level is atomic, so a
     *          level change is lock-free and a record below it is dropped before any formatting (lazy evaluation). Two
     *          formatting tiers share the sink: the level-named templates and the variadic log()/try_log() take a
     *          LocatedFormat and auto-stamp [file:line] with compile-time format validation, while the plain
     *          log(level, string_view) / log_noexcept forms take an already-rendered line and add no stamp.
     */
    class Logger
    {
    public:
        /**
         * @brief Constructs a logger with an explicit sink, independent of the process default.
         * @details A dedicated logger uses its own file. The process default from log() is separate. This constructor
         *          does not disturb that instance.
         * @param prefix Subsystem prefix used in diagnostics printed to stderr on a file error.
         * @param file_name The log file path. Relative paths resolve against the runtime module directory.
         * @param timestamp_fmt The strftime-style timestamp format for each line.
         * @param open_mode The action for an existing target file. See @ref LogOpenMode.
         * @note Setup/control-plane only. Construction allocates and opens the sink.
         */
        explicit Logger(std::string_view prefix, std::string_view file_name,
                        std::string_view timestamp_fmt = DEFAULT_TIMESTAMP_FORMAT,
                        LogOpenMode open_mode = LogOpenMode::Truncate);

        ~Logger() noexcept;

        // A logger owns a live file handle, a mutex, and a writer thread, so it is pinned: a copy aliases the sink
        // and a move invalidates the mutex a concurrent log() may hold.
        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;
        Logger(Logger &&) = delete;
        Logger &operator=(Logger &&) = delete;

        /**
         * @brief Publishes and applies the process default configuration.
         * @details The first call creates the process default. Later calls reconfigure it. A call after shutdown() can
         *          reopen the sink. A logger stays inert if unsafe teardown detached its writer. That writer retains
         *          final sink access.
         * @param prefix Default log prefix string.
         * @param file_name Default log file name.
         * @param timestamp_fmt Default timestamp format string (strftime compatible).
         * @param open_mode The mode for the process default's first sink open. An existing default follows the
         *        @ref reconfigure reopen rule, even if its sink is closed.
         * @note Setup/control-plane only. The call allocates and can reopen the log file. Do not call it from a hook
         *       or input callback.
         */
        static void configure(std::string_view prefix, std::string_view file_name,
                              std::string_view timestamp_fmt = DEFAULT_TIMESTAMP_FORMAT,
                              LogOpenMode open_mode = LogOpenMode::Truncate);

        /**
         * @brief Reconfigures this logger with new settings, preserving records already written to the target file.
         * @details Thread-safe; a no-op when every parameter matches the current configuration and the stream is
         *          healthy. A same-file change keeps the stream open; a changed or unhealthy sink reopens in append
         *          mode. A shut-down or abandoned logger remains inert.
         * @param prefix New log prefix string.
         * @param file_name New log file name.
         * @param timestamp_fmt New timestamp format string (strftime compatible).
         * @note Setup/control-plane only: reopens the log file and is not callback-safe.
         */
        void reconfigure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt);

        /**
         * @brief Enables asynchronous logging: messages are queued and written by a dedicated writer thread.
         * @param config Async writer configuration; the timestamp format is overridden with this logger's own so both
         *               sinks emit identical timestamps.
         * @note Setup/control-plane only: starts the writer thread and takes the async lifecycle mutex; not
         *       callback-safe.
         */
        void enable_async_mode(const AsyncLoggerConfig &config);

        /// Enables asynchronous logging with the default AsyncLoggerConfig. See the config-taking overload.
        void enable_async_mode();

        /**
         * @brief Disables asynchronous logging and returns to synchronous writes.
         * @details Flushes pending async messages first. If the writer thread is detached because the caller is not
         *          authorized to block (an unload phase is published, or the fail-closed loader-lock probe vetoes, as
         *          during DLL unload), the AsyncLogger is intentionally leaked and the writer
         *          thread's own counted module reference (taken before the thread was created) is left outstanding, so
         *          the detached thread never outlives the object's storage or code pages. The Logger then stays inert
         *          rather than creating a synchronous writer against that sink; the event is recorded via
         *          diagnostics::record_intentional_leak.
         * @note Setup/control-plane only: joins or detaches the writer thread and takes the async lifecycle mutex.
         */
        void disable_async_mode() noexcept;

        /// Returns true when asynchronous logging is currently enabled. Callback-safe (a lock-free atomic read).
        [[nodiscard]] bool is_async_mode_enabled() const noexcept;

        /**
         * @brief Returns the number of records rejected or not confirmed delivered.
         * @details Aggregates facade-level drops (an inert or shut-down logger, or a failed synchronous write) with
         *          the current and normally retired async writers' admission, overflow, invalid-record, sync-fallback,
         *          and writer-sink losses. A batch whose insertion or final flush fails is counted in full because the
         *          stream exposes no complete-record durability boundary. It never counts a level-filtered record,
         *          which was intentionally skipped.
         * @note Best-effort observability, callback-safe: atomic snapshot/read operations with no allocation or I/O.
         */
        [[nodiscard]] std::size_t dropped_count() const noexcept;

        /**
         * @brief Flushes pending log output.
         * @details In async mode, waits for the queue to drain; in sync mode, flushes the file stream.
         * @note Best-effort and noexcept: in sync mode it locks and blocks on file I/O, so it is control-plane, not
         *       callback-safe.
         */
        void flush() noexcept;

        /**
         * @brief Shuts the logger down: drains async output and closes the file without logging.
         * @details Safe to call during teardown; idempotent with the destructor. After shutdown() the destructor is a
         *          no-op, preventing use-after-free if other globals are already gone.
         * @details The drain makes forward progress without allocating: when a batch reservation fails, the writer
         *          drains one record at a time through stack storage, so shutdown terminates under sustained
         *          allocation failure.
         * @note Setup/control-plane only: drains the writer thread and closes the file; not callback-safe.
         * @warning The join is unbounded by design: it returns once the writer has drained every admitted record. Do
         *          not call it from a context that cannot block, and do not call it under the loader lock (the
         *          loader-lock path detaches the writer instead of joining it).
         */
        void shutdown() noexcept;

        /// Returns the current minimum level; a record below this level is dropped before formatting. Callback-safe.
        [[nodiscard]] LogLevel get_log_level() const noexcept
        {
            return m_current_log_level.load(std::memory_order_acquire);
        }

        /**
         * @brief Tests whether a record at @p level passes the current filter.
         * @param level The level to test.
         * @return true when a message at this level is recorded.
         * @details Gate expensive trace-only work behind this (e.g. building a string solely to log it).
         * @note Callback-safe: a lock-free atomic read.
         */
        [[nodiscard]] bool is_enabled(LogLevel level) const noexcept
        {
            return level >= m_current_log_level.load(std::memory_order_acquire);
        }

        /**
         * @brief Sets the minimum level for messages to be recorded.
         * @param level The minimum LogLevel to record; an out-of-range value is ignored with a warning.
         * @note Setup/control-plane only: emits a log line about the change, so it can allocate and do sink I/O.
         */
        void set_log_level(LogLevel level);

        /**
         * @brief Logs an already-rendered message at @p level (no source-location stamp).
         * @param level The level of the message.
         * @param message The pre-formatted message.
         * @return true if the message reached the sink (enqueued in async mode, or written to a healthy file stream in
         *         sync mode); false if filtered out, dropped (queue full), or the file sink was closed/unhealthy. The
         *         return is informational; callers that do not need delivery status may ignore it.
         * @note This overload takes a finished line: a literal containing {} is written verbatim, NOT treated as a
         *       std::format placeholder. For placeholder substitution and compile-time format-string checking use the
         *       formatted overload log(level, fmt, args...) or the level-named methods.
         * @note Logging is best-effort. In async mode a message enqueued after shutdown() begins is dropped and
         *       counted, a message admitted before it is drained, and a full queue drops per the overflow policy. In
         *       synchronous mode a Warning or Error force-flushes the file stream under the log mutex, so a per-frame
         *       callback at those levels stalls the game thread on disk I/O. Enable async mode first for hot-path
         *       logging.
         */
        bool log(LogLevel level, std::string_view message);

        /**
         * @brief No-throw counterpart of log() for callers on a noexcept boundary (no source-location stamp).
         * @details Takes an already-rendered message and swallows any sink exception, so a hook callback or
         *          loader-lock teardown path cannot reach std::terminate through the sink.
         * @param level The level of the message.
         * @param message The already-rendered message.
         * @return true if the message was handed to the sink, false if filtered out or an internal failure was
         *         suppressed.
         * @note The function fails closed and never throws. Callback-safe use requires async mode, the
         *       OverflowPolicy::DropNewest policy, a message within LOG_INLINE_MESSAGE_SIZE, and no overlapping
         *       async-mode transition. Under those conditions the path avoids queue waits, the string-pool lock, the
         *       sink lock, and file I/O. The atomic writer lookup is not wait-free. Any other configuration or a
         *       concurrent transition can take the string-pool lock, park the caller, or perform sink I/O.
         */
        [[nodiscard]] bool log_noexcept(LogLevel level, std::string_view message) noexcept;

        /**
         * @brief Logs a source-location-stamped, std::format-style message at @p level.
         * @details Arguments are formatted only when @p level passes the filter (lazy evaluation). The leading
         *          LocatedFormat captures the call site, so the rendered line is prefixed with a compact [file:line]
         *          stamp; the format string is validated against @p args at compile time.
         * @tparam Args Deduced formatted argument types.
         * @param level The level of the message.
         * @param fmt The format string (auto-wrapped into a LocatedFormat capturing the call site).
         * @param args The arguments substituted into the format string.
         * @note The function renders the line and routes it through log(level, string_view). The result uses that
         *       overload's delivery notes. Its blocking hazards match @ref log_noexcept. This overload is not
         *       noexcept, and formatting or the sink can throw. On a noexcept boundary, call @ref try_log or
         *       @ref log_noexcept.
         */
        template <typename... Args>
        void log(LogLevel level, LocatedFormat<std::type_identity_t<Args>...> fmt, Args &&...args)
        {
            if (level >= m_current_log_level.load(std::memory_order_acquire))
            {
                (void)format_located([this, level](std::string_view rendered) { return this->log(level, rendered); },
                                     fmt.where, fmt.fmt, std::forward<Args>(args)...);
            }
        }

        /**
         * @name Level-named convenience loggers
         * @brief Provides shorthand for log(LogLevel::X, fmt, args...). Each function stamps the call site.
         * @note The functions inherit these contracts from @ref log:
         *       - They inherit its delivery contract.
         *       - They inherit its lazy-evaluation contract.
         *       - They inherit its callback-safety constraints.
         *       - They inherit its throwing behavior, so a noexcept boundary calls @ref try_log.
         * @{
         */
        template <typename... Args> void trace(LocatedFormat<std::type_identity_t<Args>...> fmt, Args &&...args)
        {
            log(LogLevel::Trace, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args> void debug(LocatedFormat<std::type_identity_t<Args>...> fmt, Args &&...args)
        {
            log(LogLevel::Debug, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args> void info(LocatedFormat<std::type_identity_t<Args>...> fmt, Args &&...args)
        {
            log(LogLevel::Info, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args> void warning(LocatedFormat<std::type_identity_t<Args>...> fmt, Args &&...args)
        {
            log(LogLevel::Warning, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args> void error(LocatedFormat<std::type_identity_t<Args>...> fmt, Args &&...args)
        {
            log(LogLevel::Error, fmt, std::forward<Args>(args)...);
        }
        /** @} */

        /**
         * @brief No-throw, source-location-stamped formatted logging for callers on a noexcept boundary.
         * @details Like log(level, fmt, args...) but formats inside a try/catch and routes through log_noexcept(), so
         *          neither a std::format failure nor a sink failure can propagate. Prefer this over the throwing forms
         *          inside hook callbacks. Arguments are formatted only when @p level is enabled.
         * @return true if the message was handed to the sink, false if filtered out or dropped because
         *         formatting/logging failed.
         * @note Best-effort and no-throw: it swallows every std::format and sink failure, so it will not terminate a
         *       noexcept boundary. It is not unconditionally callback-safe because format_located() may allocate for
         *       an over-long line. Delivery has @ref log_noexcept constraints and requires DropNewest.
         */
        template <typename... Args>
        [[nodiscard]] bool try_log(LogLevel level, LocatedFormat<std::type_identity_t<Args>...> fmt,
                                   Args &&...args) noexcept
        {
            if (level < m_current_log_level.load(std::memory_order_acquire))
            {
                return false;
            }
            try
            {
                return format_located([this, level](std::string_view rendered) noexcept
                                      { return this->log_noexcept(level, rendered); }, fmt.where, fmt.fmt,
                                      std::forward<Args>(args)...);
            }
            catch (...)
            {
                return false;
            }
        }

        /**
         * @struct StaticConfig
         * @brief Stores an immutable snapshot of the process default configuration.
         * @details An atomic shared pointer publishes the snapshot with acquire and release order. A reader takes no
         *          logger-level lock. configure() replaces the snapshot. The default Logger reads it at construction.
         *          Message paths do not use it.
         */
        struct StaticConfig
        {
            /// The default log prefix.
            std::string log_prefix;
            /// The default log file name.
            std::string log_file_name;
            /// The default timestamp format.
            std::string timestamp_format;
            /// The mode for the first sink open.
            LogOpenMode open_mode;

            /**
             * @brief Constructs a complete process default snapshot.
             * @param prefix The log prefix.
             * @param file The log file name.
             * @param ts_fmt The timestamp format.
             * @param mode The first sink open mode.
             */
            StaticConfig(std::string prefix, std::string file, std::string ts_fmt,
                         LogOpenMode mode = LogOpenMode::Truncate)
                : log_prefix(std::move(prefix)), log_file_name(std::move(file)), timestamp_format(std::move(ts_fmt)),
                  open_mode(mode)
            {
            }
        };

    private:
        /// Constructs the process-default logger from the published StaticConfig; reached only through log().
        Logger();

        /// Tag selecting the inert constructor taken when first-use construction fails under allocation pressure.
        struct InertTag
        {
        };

        /**
         * @brief Constructs an inert, sink-less logger that drops and counts every enabled record.
         * @details Allocates nothing: opens no file, creates no shared sink mutex or writer, and leaves the sink
         *          pointers null. Published by create_process_default() when normal first-use construction throws
         *          under OOM, so the noexcept free log() returns a usable object instead of terminating. Every
         *          operation fails closed for the process lifetime.
         */
        explicit Logger(InertTag) noexcept;

        /**
         * @brief Builds the process-default logger, falling back to an inert logger on first-use allocation failure.
         * @details The free log() is noexcept, so a throw from the default constructor (first-use OOM) terminates the
         *          host. This wraps that construction in a catch and, on failure, publishes a process-lifetime inert
         *          logger. A first failure latches inert for the process generation.
         */
        [[nodiscard]] static Logger *create_process_default() noexcept;

        /// True for the inert first-use logger, which never allocated a sink or mutex. See create_process_default().
        [[nodiscard]] bool is_inert() const noexcept { return !m_log_mutex_ptr; }

        /**
         * @brief Renders a source-located line into a stack buffer and hands it to @p sink.
         * @details Renders the "[file:line] " stamp and message into one LOG_INLINE_MESSAGE_SIZE stack buffer. A line
         *          that fits is passed as a view with no heap allocation. A longer line is re-rendered once through
         *          std::format, the documented overflow path. The formatter only reads its arguments, so forwarding
         *          the same pack to both paths is safe.
         * @return Whatever @p sink returns for the line.
         */
        template <typename Sink, typename... Args>
        static auto format_located(Sink &&sink, const std::source_location &where, std::format_string<Args...> fmt,
                                   Args &&...args)
        {
            const std::string_view file = source_basename(where.file_name());
            const auto line = where.line();

            std::array<char, LOG_INLINE_MESSAGE_SIZE> buffer;
            const auto stamp = std::format_to_n(buffer.data(), buffer.size(), "[{}:{}] ", file, line);
            const auto stamp_len = static_cast<std::size_t>(stamp.size);
            if (stamp_len <= buffer.size())
            {
                const auto body =
                    std::format_to_n(stamp.out, buffer.size() - stamp_len, fmt, std::forward<Args>(args)...);
                const auto total = stamp_len + static_cast<std::size_t>(body.size);
                if (total <= buffer.size())
                {
                    return sink(std::string_view(buffer.data(), total));
                }
            }

            return sink(
                std::string_view(std::format("[{}:{}] {}", file, line, std::format(fmt, std::forward<Args>(args)...))));
        }

        /**
         * @brief Extracts the file name from a source_location path (the segment after the last '/' or '\\').
         * @details Keeps the stamp compact and toolchain-stable: __FILE__-derived paths differ between build roots and
         *          compilers, but the trailing file name does not.
         */
        [[nodiscard]] static constexpr std::string_view source_basename(std::string_view path) noexcept
        {
            const auto slash = path.find_last_of("/\\");
            return slash == std::string_view::npos ? path : path.substr(slash + 1);
        }

        /// Shared teardown body used by both ~Logger() and shutdown().
        void shutdown_internal() noexcept;

        /// Generates the current timestamp formatted per m_timestamp_format, with a millisecond fraction appended.
        std::string get_timestamp() const;

        /// Resolves the absolute log file path (wide for Unicode fidelity), relative to the runtime directory.
        std::wstring generate_log_file_path() const;

        /**
         * @brief Opens the configured file and writes the banner for construction or reconfiguration.
         * @param reconfiguring Selects the "reconfigured" banner when true.
         * @param truncate Selects a fresh file when true. False preserves prior records.
         */
        void open_sink(bool reconfiguring, bool truncate);

        /**
         * @brief Applies new settings with the caller holding both m_async_mutex and *m_log_mutex_ptr.
         * @details The locked body shared by reconfigure() (which acquires the lock and respects shutdown) and
         *          configure() (which clears the shutdown flag under the same lock so the reset is serialized against
         *          a concurrent shutdown). A same-file option change keeps the open stream rather than truncating it.
         */
        void reconfigure_locked(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt);

        static std::shared_ptr<const StaticConfig> get_static_config();
        static void set_static_config(std::shared_ptr<const StaticConfig> config);

        // log() owns the process-default Logger through a process-lifetime allocation, so it needs access to the
        // private constructor.
        friend Logger &log() noexcept;

        // Lock ordering (must be acquired in this order to prevent deadlock):
        //   1. m_async_mutex:    async logger lifecycle
        //   2. *m_log_mutex_ptr: file stream I/O

        std::string m_log_prefix;
        std::string m_log_file_name;
        std::string m_timestamp_format;

        std::shared_ptr<detail::WinFileStream> m_log_file_stream_ptr;
        std::shared_ptr<std::mutex> m_log_mutex_ptr;
        std::atomic<LogLevel> m_current_log_level{LogLevel::Info};
        std::atomic<bool> m_shutdown_called{false};

        // Facade-level drop counter: records refused by an inert/shut-down facade, records lost at the synchronous
        // sink, and drops absorbed from normally retired async writers. dropped_count() adds the current async
        // writer's count. Relaxed: best-effort observability, never a synchronization point.
        std::atomic<std::size_t> m_dropped_messages{0};

        // Latched when an async writer is detached and retained because teardown cannot join it. That writer keeps
        // exclusive final sink ownership, so configure/reconfigure/flush must remain inert for this Logger instance.
        std::atomic<bool> m_async_writer_abandoned{false};

        // Held in an atomic so the log() hot path snapshots the writer without taking m_async_mutex.
        // std::atomic<std::shared_ptr<T>> is NOT lock-free on either shipped toolchain ([B-23]), so the load takes
        // one bounded internal critical section per log() call. Correct within log_noexcept's callback-safety
        // conditions, but not a wait-free read.
        std::atomic<std::shared_ptr<AsyncLogger>> m_async_logger{};
        std::atomic<bool> m_async_mode_enabled{false};
        std::mutex m_async_mutex;
    };

    /**
     * @brief Returns the process-default Logger.
     * @details The default is created on first use from the configuration last published by Logger::configure(). The
     *          instance is intentionally never destroyed, so the reference stays valid for the whole process,
     *          including static-destructor and detached-thread logging during teardown. Call log().shutdown() (or let
     *          the Session do it) to flush and close the sink.
     * @return A reference to the single process-default Logger.
     * @note Callback-safe in steady state: after first use it is a noexcept reference accessor. First use constructs
     *       the logger and can allocate/open the sink, so initialize it from setup code before calling log() on a hot
     *       path.
     */
    [[nodiscard]] Logger &log() noexcept;
} // namespace DetourModKit

#endif // DETOURMODKIT_LOGGER_HPP
