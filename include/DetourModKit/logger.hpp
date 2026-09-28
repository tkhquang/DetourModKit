#ifndef DETOURMODKIT_LOGGER_HPP
#define DETOURMODKIT_LOGGER_HPP

/**
 * @file logger.hpp
 * @brief Process logging value facade, the free log() accessor, and source-location stamp policy.
 * @details Logger owns one file sink and an optional async writer. Logging fails soft: a dropped or filtered record is
 *          a best-effort bool, never a Result.
 * @warning `[B-100]` Run Logger construction, first use of log(), and enable_async_mode() outside the loader lock.
 *          These routes allocate, and enable_async_mode() can create the writer thread. The loader-lock teardown path
 *          detaches the writer without a wait. `LoggerTest.LoaderLock*` pins the boundary.
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
#include <type_traits>

namespace DetourModKit
{
    class Logger;

    namespace detail
    {
        // The out-of-line Logger special members keep the Win32 file stream type out of consumer code.
        class WinFileStream;
        class LoggerDropAccess;
        class LoggerTestSeams;
    } // namespace detail

    /** @brief Severity levels for log records, ordered from least to most severe. */
    enum class LogLevel : std::uint8_t
    {
        Trace = 0,
        Debug = 1,
        Info = 2,
        Warning = 3,
        Error = 4
    };

    /**
     * @brief Returns the upper-case name of @p level, or "UNKNOWN" for an out-of-range value.
     * @note Callback-safe: the call does not allocate.
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
     * @brief Parses a level name, for example "INFO" or "debug", into a LogLevel.
     * @details The ASCII-only case fold ignores LC_CTYPE ([B-37]). The parse does not trim whitespace.
     * @return The matching level. An unrecognized name returns LogLevel::Info and writes a warning to stderr.
     * @note Setup/control-plane only: the call allocates and can write to stderr.
     */
    [[nodiscard]] LogLevel string_to_log_level(std::string_view level_str);

    /** @brief Selects whether the first sink open truncates or appends. @ref Logger::reconfigure never truncates. */
    enum class LogOpenMode : std::uint8_t
    {
        /// Starts a fresh file.
        Truncate,
        /// Preserves prior records and writes new records after them.
        Append
    };

    /** @brief Selects which formatted log levels render a source-location stamp. */
    class LogSourceStampMode
    {
    public:
        /// Constructs the default policy, which renders Trace and Debug source-location stamps.
        constexpr LogSourceStampMode() noexcept = default;

        /// Returns a policy that renders every source-location stamp.
        [[nodiscard]] static constexpr LogSourceStampMode always() noexcept { return LogSourceStampMode{ERROR_LEVEL}; }

        /**
         * @brief Returns a policy that renders stamps from Trace through @p maximum_level.
         * @return The requested policy. An out-of-range level selects @ref LogSourceStampMode::always.
         */
        [[nodiscard]] static constexpr LogSourceStampMode at_or_below(LogLevel maximum_level) noexcept
        {
            const auto level = static_cast<std::uint8_t>(maximum_level);
            return LogSourceStampMode{
                level <= static_cast<std::uint8_t>(LogLevel::Error) ? static_cast<std::int8_t>(level) : ERROR_LEVEL
            };
        }

        /// Returns a policy that renders no source-location stamp.
        [[nodiscard]] static constexpr LogSourceStampMode never() noexcept { return LogSourceStampMode{NEVER_LEVEL}; }

        /** @brief Tests whether @p level retains its source-location stamp. */
        [[nodiscard]] constexpr bool renders(LogLevel level) const noexcept
        {
            return static_cast<std::int16_t>(static_cast<std::uint8_t>(level)) <= m_maximum_level;
        }

        /// Compares two stamp policies by value.
        [[nodiscard]] friend constexpr bool
        operator==(const LogSourceStampMode &left, const LogSourceStampMode &right) noexcept = default;

    private:
        static constexpr std::int8_t NEVER_LEVEL = -1;
        static constexpr std::int8_t DEBUG_LEVEL = static_cast<std::int8_t>(LogLevel::Debug);
        static constexpr std::int8_t ERROR_LEVEL = static_cast<std::int8_t>(LogLevel::Error);

        explicit constexpr LogSourceStampMode(std::int8_t maximum_level) noexcept : m_maximum_level(maximum_level) {}

        std::int8_t m_maximum_level{DEBUG_LEVEL};
    };

    static_assert(std::is_trivially_copyable_v<LogSourceStampMode>);
    static_assert(sizeof(LogSourceStampMode) == sizeof(std::int8_t));
    static_assert(std::atomic<LogSourceStampMode>::is_always_lock_free);

    /// Default subsystem prefix of the logger's stderr diagnostics.
    inline constexpr std::string_view DEFAULT_LOG_PREFIX{"DetourModKit"};
    /// Default log file name, resolved against the runtime module directory when relative.
    inline constexpr std::string_view DEFAULT_LOG_FILE_NAME{"DetourModKit_Log.txt"};
    /// Default strftime-style timestamp format. The logger appends a ".<ms>" fraction after it.
    inline constexpr std::string_view DEFAULT_TIMESTAMP_FORMAT{"%Y-%m-%d %H:%M:%S"};

    /// The longest log line, in bytes, that the formatted path and the async queue hold without a heap allocation.
    inline constexpr std::size_t LOG_INLINE_MESSAGE_SIZE = 512;

    // The complete type lives in src/internal/async_logger.hpp, outside consumer translation units.
    class AsyncLogger;

    /** @brief A std::format_string, validated at compile time, that also captures the call site for the stamp. */
    template <typename... Args> struct LocatedFormat
    {
        /** @brief Wraps a compile-time format string and records the call site. Do not pass @p loc. */
        template <typename String>
        consteval LocatedFormat(const String &s, std::source_location loc = std::source_location::current()) noexcept
            : fmt(s), where(loc)
        {
        }

        /// The validated format string.
        std::format_string<Args...> fmt;
        /// The captured call site.
        std::source_location where;
    };

    /**
     * @brief A thread-safe file logger: the value facade behind the free log() accessor and Session::log().
     * @details The logger drops a record below the minimum level before format evaluation. Every file_name is a UTF-8
     *          path. Ill-formed UTF-8 opens no file. A first open then leaves the sink closed, and a reconfiguration
     *          keeps the previous sink.
     */
    class Logger
    {
    public:
        /**
         * @brief Constructs a logger with its own sink. The process default that log() returns does not change.
         * @param prefix The subsystem prefix of this logger's stderr diagnostics.
         * @param file_name A relative path resolves against the runtime module directory.
         * @param timestamp_fmt The strftime-style timestamp format of each line.
         * @note Setup/control-plane only. Construction allocates and opens the sink.
         */
        explicit Logger(
            std::string_view prefix,
            std::string_view file_name,
            std::string_view timestamp_fmt = DEFAULT_TIMESTAMP_FORMAT,
            LogOpenMode open_mode = LogOpenMode::Truncate,
            LogSourceStampMode source_stamp_mode = LogSourceStampMode{}
        );

        ~Logger() noexcept;

        // Pinned: a copy aliases the sink, and a move invalidates the mutex that a concurrent log() can hold.
        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;
        Logger(Logger &&) = delete;
        Logger &operator=(Logger &&) = delete;

        /**
         * @brief Publishes and applies the process default configuration.
         * @details If no process default exists, the call creates it from these values. Otherwise the call applies them
         *          as @ref reconfigure does. A rejected application restores the previous snapshot. A first-use
         *          sink-open failure leaves a closed process default with the requested strings. A call after
         *          shutdown() can reopen the sink. A logger with a detached writer stays inert.
         * @param open_mode The mode of the process default's first sink open. Once the default exists, it follows the
         *                  @ref reconfigure reopen rule, even if its sink is closed.
         * @note Setup/control-plane only. The call allocates and can reopen the log file.
         */
        static void configure(
            std::string_view prefix,
            std::string_view file_name,
            std::string_view timestamp_fmt = DEFAULT_TIMESTAMP_FORMAT,
            LogOpenMode open_mode = LogOpenMode::Truncate,
            LogSourceStampMode source_stamp_mode = LogSourceStampMode{}
        );

        /**
         * @brief Reconfigures this logger and preserves records already written to the target file.
         * @details Equal parameters and a healthy stream cause no change. A same-file change keeps the stream open. A
         *          changed or unhealthy sink reopens in append mode. A shut-down logger or a logger with a detached
         *          writer stays inert. The replacement sink opens before the current sink retires. A failed open or
         *          retirement leaves the prefix, file, format, sink, and live async writer on the previous
         *          configuration.
         * @note Setup/control-plane only: the call can reopen the log file.
         */
        void reconfigure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt);

        /**
         * @brief Enables async mode: a dedicated writer thread writes the queued records.
         * @details The call does nothing on an inert or shut-down logger, on a logger with a detached writer, or while
         *          async mode is on. A closed sink or a failure before publication, for example an invalid @p config,
         *          leaves async mode off and keeps sync delivery. A contained failure after publication keeps the
         *          writer active. A closed sink, a failed activation, and a success each log one record through
         *          @ref try_log.
         * @param config The writer uses this logger's timestamp format, not config.timestamp_format.
         * @note Setup/control-plane only: the call starts the writer thread.
         */
        void enable_async_mode(const AsyncLoggerConfig &config) noexcept;

        /// Enables async mode with the default AsyncLoggerConfig. See the overload that takes a config.
        void enable_async_mode() noexcept;

        /**
         * @brief Disables async mode and returns to sync writes after it flushes pending records.
         * @details If the caller is not authorized to block, the call detaches the writer and leaks it, and
         *          diagnostics::record_intentional_leak records the leak. This Logger then stays inert, because the
         *          detached writer still owns the sink. `[B-44]` owns the counted module reference that keeps that
         *          thread's code mapped.
         * @note Setup/control-plane only: the call joins or detaches the writer thread.
         */
        void disable_async_mode() noexcept;

        /**
         * @brief Returns true when async mode is on.
         * @note Callback-safe.
         */
        [[nodiscard]] bool is_async_mode_enabled() const noexcept;

        /**
         * @brief Returns the number of records rejected or not confirmed delivered.
         * @details The count includes facade drops: an inert or shut-down logger, a failed sync write, and a suppressed
         *          exception in @ref log_noexcept or @ref try_log. It adds the admission, overflow, invalid-record,
         *          sync-fallback, and writer-sink losses of the current and normally retired async writers. A batch
         *          whose insertion or final flush fails counts in full. A level-filtered record never counts.
         * @note Best-effort observability. Callback-safe: the call does no allocation or I/O.
         */
        [[nodiscard]] std::size_t dropped_count() const noexcept;

        /**
         * @brief Flushes pending log output: a bounded wait for the async queue to drain, or a file flush in sync mode.
         * @note Best-effort. Setup/control-plane only: in sync mode the call locks and blocks on file I/O.
         */
        void flush() noexcept;

        /**
         * @brief Drains async output and closes the file without a log message.
         * @details The call is idempotent, and the destructor does nothing after it. The drain still advances under
         *          allocation failure (Lifecycle.LoggerPersistentBatchOomStillDrainsAndJoins).
         * @note Setup/control-plane only.
         * @warning The join is unbounded: it returns after the writer drains every admitted record. Do not call it from
         *          a context that cannot block or under the loader lock. See the file `[B-100]` warning.
         */
        void shutdown() noexcept;

        /**
         * @brief Returns the minimum level.
         * @note Callback-safe.
         */
        [[nodiscard]] LogLevel get_log_level() const noexcept
        {
            return m_current_log_level.load(std::memory_order_acquire);
        }

        /**
         * @brief Tests whether a record at @p level passes the current filter.
         * @note Callback-safe.
         */
        [[nodiscard]] bool is_enabled(LogLevel level) const noexcept
        {
            return level >= m_current_log_level.load(std::memory_order_acquire);
        }

        /**
         * @brief Sets the minimum level. The call ignores an out-of-range value and logs a Warning record if Warning
         *        passes the filter.
         * @details A changed minimum level emits one Info control record that names both levels. That record bypasses
         *          the level filter, so a stricter level cannot hide it. An unchanged level emits nothing.
         * @note Setup/control-plane only: the control record can allocate and do sink I/O.
         */
        void set_log_level(LogLevel level);

        /**
         * @brief Returns the source-location stamp policy.
         * @note Callback-safe.
         */
        [[nodiscard]] LogSourceStampMode get_source_stamp_mode() const noexcept
        {
            return m_source_stamp_mode.load(std::memory_order_relaxed);
        }

        /**
         * @brief Sets the source-location stamp policy for later formatted records.
         * @note Callback-safe. The change emits no control record.
         */
        void set_source_stamp_mode(LogSourceStampMode mode) noexcept
        {
            m_source_stamp_mode.store(mode, std::memory_order_relaxed);
        }

        /**
         * @brief Logs an already-rendered message at @p level with no source-location stamp.
         * @details The call writes the line verbatim, so a {} is not a std::format placeholder. For placeholders and
         *          compile-time format checks, call the formatted overload or a level-named method.
         * @return True if the record reached the sink: the async queue took it, or a healthy file stream wrote it.
         *         False if the filter rejected it, the logger dropped it, or the file sink is closed or unhealthy.
         * @note Best-effort delivery. The call can throw. On a noexcept boundary, call @ref log_noexcept. The call
         *       drops and counts a record after shutdown() begins. In async mode, shutdown() drains each record
         *       admitted earlier. A full queue applies the overflow policy.
         * @warning In sync mode, a Warning or Error flushes the file stream under the log mutex. A per-frame callback
         *          at those levels then stalls the game thread on disk I/O. For hot-path logging, enable async mode
         *          first.
         */
        bool log(LogLevel level, std::string_view message);

        /**
         * @brief No-throw counterpart of log() for callers on a noexcept boundary (no source-location stamp).
         * @details The call suppresses every internal exception, so a hook callback or a loader-lock teardown path
         *          cannot reach std::terminate through the sink.
         * @return The @ref log status, or false after a suppressed exception, which @ref dropped_count counts.
         * @note Callback-safe only in async mode with OverflowPolicy::DropNewest, a message within
         *       LOG_INLINE_MESSAGE_SIZE, and no concurrent async-mode transition. The path then takes no queue wait,
         *       string-pool lock, sink lock, or file I/O. The atomic writer lookup is not wait-free. Any other
         *       configuration or a concurrent transition can take the string-pool lock, park the caller, or do sink
         *       I/O.
         */
        [[nodiscard]] bool log_noexcept(LogLevel level, std::string_view message) noexcept;

        /**
         * @brief Logs a std::format-style message and captures its source location.
         * @details Arguments format only after @p level passes the filter. The line starts with a [file:line] stamp
         *          only when the stamp policy enables @p level.
         * @note The delivery rules of log(level, string_view) apply, and the blocking hazards match @ref log_noexcept.
         *       Formatting or the sink can throw. On a noexcept boundary, call @ref try_log or @ref log_noexcept.
         */
        template <typename... Args>
        void log(LogLevel level, LocatedFormat<std::type_identity_t<Args>...> fmt, Args &&...args)
        {
            if (level >= m_current_log_level.load(std::memory_order_acquire))
            {
                (void)format_located(
                    [this, level](std::string_view rendered) { return this->log(level, rendered); },
                    source_stamp_enabled(level),
                    fmt.where,
                    fmt.fmt,
                    std::forward<Args>(args)...
                );
            }
        }

        /**
         * @name Level-named convenience loggers
         * @brief Provides shorthand for log(LogLevel::X, fmt, args...), with every contract of that formatted overload.
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
         * @brief Formats and logs without exceptions for callers on a noexcept boundary.
         * @details The call site capture, the stamp policy, and lazy formatting match log(level, fmt, args...).
         * @return The @ref log_noexcept status, or false after a format failure, which @ref dropped_count counts.
         * @note Best-effort. Callback-safe only under the @ref log_noexcept conditions. A rendered line longer than
         *       LOG_INLINE_MESSAGE_SIZE allocates. Inside hook callbacks, prefer this overload.
         */
        template <typename... Args>
        [[nodiscard]] bool
        try_log(LogLevel level, LocatedFormat<std::type_identity_t<Args>...> fmt, Args &&...args) noexcept
        {
            if (level < m_current_log_level.load(std::memory_order_acquire))
            {
                return false;
            }
            try
            {
                return format_located(
                    [this, level](std::string_view rendered) noexcept { return this->log_noexcept(level, rendered); },
                    source_stamp_enabled(level),
                    fmt.where,
                    fmt.fmt,
                    std::forward<Args>(args)...
                );
            }
            catch (...)
            {
                // Only a format failure reaches here. log_noexcept counts its own sink losses.
                m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
        }

        /** @brief Stores an immutable snapshot of the process default configuration, which configure() replaces. */
        struct StaticConfig
        {
            /// The default log prefix.
            std::string log_prefix;
            /// The default log file name.
            std::string log_file_name;
            /// The default timestamp format.
            std::string timestamp_format;
            /// The mode of the first sink open.
            LogOpenMode open_mode;
            /// The source-location stamp policy for formatted records.
            LogSourceStampMode source_stamp_mode;

            /** @brief Constructs a complete process default snapshot. */
            StaticConfig(
                std::string prefix,
                std::string file,
                std::string ts_fmt,
                LogOpenMode mode = LogOpenMode::Truncate,
                LogSourceStampMode stamp_mode = LogSourceStampMode{}
            )
                : log_prefix(std::move(prefix)), log_file_name(std::move(file)), timestamp_format(std::move(ts_fmt)),
                  open_mode(mode), source_stamp_mode(stamp_mode)
            {
            }
        };

    private:
        friend class detail::LoggerDropAccess;
        // Unconditional: test access lives in src/internal/logger_test_seams.hpp, so no member depends on a macro.
        friend class detail::LoggerTestSeams;

        /// Constructs the process-default logger from the published StaticConfig. Only log() reaches it.
        Logger();

        /// Selects the inert constructor. See create_process_default().
        struct InertTag
        {
        };

        /** @brief Constructs an inert logger with no sink or allocation. It drops and counts every enabled record. */
        explicit Logger(InertTag) noexcept;

        /**
         * @brief Builds the process-default logger, or an inert logger if first-use construction throws.
         * @details The inert logger fails closed for the process generation, so the noexcept log() cannot terminate.
         */
        [[nodiscard]] static Logger *create_process_default() noexcept;

        /// True for the inert first-use logger, which never allocated a sink or mutex. See create_process_default().
        [[nodiscard]] bool is_inert() const noexcept { return !m_log_mutex_ptr; }

        /**
         * @brief Attempts delivery of an already-rendered line without the level filter.
         * @details Every other delivery rule and the return value match @ref log. set_log_level() uses it for each
         *          transition control record.
         */
        bool emit_record(LogLevel level, std::string_view message);

        /**
         * @brief Renders the line, with a "[file:line] " stamp when @p with_stamp is true, and returns @p sink(line).
         * @details A line within LOG_INLINE_MESSAGE_SIZE uses a stack buffer. A longer line allocates through
         *          std::format. The formatter only reads its arguments, so both attempts can share the pack.
         */
        template <typename Sink, typename... Args>
        static auto format_located(
            Sink &&sink,
            bool with_stamp,
            const std::source_location &where,
            std::format_string<Args...> fmt,
            Args &&...args
        )
        {
            std::array<char, LOG_INLINE_MESSAGE_SIZE> buffer;
            std::string_view file;
            std::uint_least32_t line{0};
            std::size_t stamp_len{0};
            auto body_out = buffer.data();
            if (with_stamp)
            {
                file = source_basename(where.file_name());
                line = where.line();
                const auto stamp = std::format_to_n(buffer.data(), buffer.size(), "[{}:{}] ", file, line);
                stamp_len = static_cast<std::size_t>(stamp.size);
                body_out = stamp.out;
            }
            if (stamp_len <= buffer.size())
            {
                const auto body =
                    std::format_to_n(body_out, buffer.size() - stamp_len, fmt, std::forward<Args>(args)...);
                const auto total = stamp_len + static_cast<std::size_t>(body.size);
                if (total <= buffer.size())
                {
                    return sink(std::string_view(buffer.data(), total));
                }
            }

            if (with_stamp)
            {
                return sink(
                    std::string_view(
                        std::format("[{}:{}] {}", file, line, std::format(fmt, std::forward<Args>(args)...))
                    )
                );
            }
            return sink(std::string_view(std::format(fmt, std::forward<Args>(args)...)));
        }

        /// Tests whether the current stamp policy renders the stamp of @p level.
        [[nodiscard]] bool source_stamp_enabled(LogLevel level) const noexcept
        {
            return m_source_stamp_mode.load(std::memory_order_relaxed).renders(level);
        }

        /** @brief Returns the segment after the last '/' or '\\', which is stable across build roots and compilers. */
        [[nodiscard]] static constexpr std::string_view source_basename(std::string_view path) noexcept
        {
            const auto slash = path.find_last_of("/\\");
            return slash == std::string_view::npos ? path : path.substr(slash + 1);
        }

        /// Shared teardown body used by both ~Logger() and shutdown().
        void shutdown_internal() noexcept;

        /// Renders the current time through @p format, with a millisecond fraction appended.
        std::string get_timestamp(const std::string &format) const;

        /**
         * @brief Resolves a relative @p file_name against the runtime module directory, or returns the path as given
         *        when that directory is unavailable.
         * @return The wide path, or an empty path when @p file_name is ill-formed UTF-8, holds a NUL, or exceeds
         *         INT_MAX bytes.
         */
        std::wstring generate_log_file_path(const std::string &file_name) const;

        /**
         * @brief Opens a candidate sink for @p file_name and does not change this Logger.
         * @param truncate Selects a fresh file when true. False preserves prior records.
         * @return The open stream, or null after a stderr diagnostic when the file does not open.
         */
        [[nodiscard]] std::shared_ptr<detail::WinFileStream>
        open_sink(const std::string &file_name, bool truncate) const;

        /// Construction only: adopts the first sink and writes its banner. A failed open leaves a closed stream.
        void adopt_first_sink(bool truncate);

        /**
         * @brief Applies new settings while the caller holds both m_async_mutex and *m_log_mutex_ptr.
         * @details reconfigure() and configure() share this body. configure() clears the shutdown latch before the
         *          call. All allocation and candidate-open work precedes prior-sink retirement. A failed drain retains
         *          the current handle and buffered tail.
         * @return True when the settings commit. False means that the replacement did not open or the prior sink did
         *         not close cleanly, and configuration and sink ownership stay unchanged.
         */
        [[nodiscard]] bool
        reconfigure_locked(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt);

        static std::shared_ptr<const StaticConfig> get_static_config();
        static void set_static_config(std::shared_ptr<const StaticConfig> config);

        friend Logger &log() noexcept;

        // Lock order: static_config_mutex() (the configure() transaction), then m_async_mutex (the async writer
        // lifecycle), then *m_log_mutex_ptr (file stream I/O). Another order can deadlock.

        std::string m_log_prefix;
        std::string m_log_file_name;
        std::string m_timestamp_format;

        std::shared_ptr<detail::WinFileStream> m_log_file_stream_ptr;
        std::shared_ptr<std::mutex> m_log_mutex_ptr;
        std::atomic<LogLevel> m_current_log_level{LogLevel::Info};
        std::atomic<LogSourceStampMode> m_source_stamp_mode{LogSourceStampMode{}};
        std::atomic<bool> m_shutdown_called{false};

        // Facade drops, retired-writer drops, and stale-snapshot rejections. Relaxed: never a synchronization point.
        std::atomic<std::size_t> m_dropped_messages{0};

        // Latched when teardown detaches a writer that it cannot join. That writer owns the sink, so configure(),
        // reconfigure(), and flush() stay inert for this Logger.
        std::atomic<bool> m_async_writer_abandoned{false};

        // log() loads this snapshot without m_async_mutex. The load is not lock-free on either toolchain ([B-23]).
        // Each log() call takes one bounded internal critical section, which log_noexcept's callback-safety allows.
        std::atomic<std::shared_ptr<AsyncLogger>> m_async_logger{};
        std::atomic<bool> m_async_mode_enabled{false};
        std::mutex m_async_mutex;
    };

    /**
     * @brief Returns the process-default Logger.
     * @details First use creates the default from the configuration that Logger::configure() published last. If that
     *          construction throws, log() returns an inert logger that drops and counts every enabled record. The
     *          instance is never destroyed, so the reference stays valid through static destruction and detached-thread
     *          logging. To flush and close the sink, call log().shutdown() or let the Session call it.
     * @note Callback-safe in steady state. First use allocates and opens the sink, so call it first from setup code.
     */
    [[nodiscard]] Logger &log() noexcept;
} // namespace DetourModKit

#endif // DETOURMODKIT_LOGGER_HPP
