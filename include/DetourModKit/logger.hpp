#ifndef DETOURMODKIT_LOGGER_HPP
#define DETOURMODKIT_LOGGER_HPP

#include <string>
#include <string_view>
#include <mutex>
#include <memory>
#include <format>
#include <atomic>

#include "DetourModKit/win_file_stream.hpp"

namespace DetourModKit
{
    /**
     * @enum LogLevel
     * @brief Defines the severity levels for log messages.
     * @note This is an enum class (C++ Core Guidelines Enum.3) to prevent namespace pollution.
     */
    enum class LogLevel
    {
        Trace = 0,
        Debug = 1,
        Info = 2,
        Warning = 3,
        Error = 4
    };

    /**
     * @brief Converts a LogLevel enum to its string representation.
     * @param level The LogLevel enum value.
     * @return std::string_view String representation of the log level.
     */
    constexpr std::string_view log_level_to_string(LogLevel level) noexcept
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
        default:
            return "UNKNOWN";
        }
    }

    // Logger configuration defaults
    inline constexpr const char *DEFAULT_LOG_PREFIX = "DetourModKit";
    inline constexpr const char *DEFAULT_LOG_FILE_NAME = "DetourModKit_Log.txt";
    inline constexpr const char *DEFAULT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S";

    // Forward declarations
    struct AsyncLoggerConfig;
    class AsyncLogger;

    /**
     * @class Logger
     * @brief A singleton class for logging messages to a file.
     * @details Provides thread-safe logging with configurable levels, timestamps, and log file location. Uses atomic
     *          LogLevel for thread-safe level changes.
     */
    class Logger
    {
    public:
        /**
         * @brief Retrieves the singleton instance of the Logger.
         * @return Logger& Reference to the single Logger instance.
         */
        static Logger &get_instance()
        {
            static Logger instance;
            return instance;
        }

        /**
         * @brief Configures global static settings for the logger before first instantiation.
         * @details If the logger instance already exists, this will also reconfigure the instance by reopening the log
         *          file with the new settings.
         * @param prefix Default log prefix string.
         * @param file_name Default log file name.
         * @param timestamp_fmt Default timestamp format string (strftime compatible).
         */
        static void configure(std::string_view prefix, std::string_view file_name,
                              std::string_view timestamp_fmt = DEFAULT_TIMESTAMP_FORMAT);

        /**
         * @brief Reconfigures an existing logger instance with new settings.
         * @details Closes the current log file (if open) and reopens it with the new settings. Thread-safe. Logs a
         *          message about the reconfiguration.
         * @param prefix New log prefix string.
         * @param file_name New log file name.
         * @param timestamp_fmt New timestamp format string (strftime compatible).
         */
        void reconfigure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt);

        /**
         * @brief Enables asynchronous logging mode.
         * @details When enabled, log messages are queued and written by a dedicated writer thread, reducing latency on
         *          the calling thread.
         * @param config Optional async logger configuration. Uses defaults if not provided.
         */
        void enable_async_mode(const AsyncLoggerConfig &config);
        void enable_async_mode();

        /**
         * @brief Disables asynchronous logging mode and returns to synchronous mode.
         * @details Flushes all pending async messages before switching. If the writer thread is detached because this
         *          runs under the Windows loader lock (e.g. during DLL unload), the AsyncLogger is intentionally leaked
         *          and the module is pinned so the detached thread never outlives the object's storage or code pages;
         *          the event is recorded via Diagnostics::record_intentional_leak.
         */
        void disable_async_mode();

        /**
         * @brief Checks if async logging mode is enabled.
         * @return true if async mode is enabled, false otherwise.
         */
        [[nodiscard]] bool is_async_mode_enabled() const noexcept;

        /**
         * @brief Flushes all pending log messages.
         * @details In async mode, waits for all queued messages to be written. In sync mode, flushes the file stream.
         */
        void flush();

        /**
         * @brief Explicitly shuts down the Logger, closing files without logging.
         * @details This method is safe to call during shutdown. It closes the log file and shuts down async logger
         *          without attempting to log, preventing use-after-free if called after other singletons are destroyed.
         *          After calling shutdown(), the destructor becomes a no-op.
         */
        void shutdown();

        /**
         * @brief Gets the current log level.
         * @return LogLevel The current minimum log level.
         */
        [[nodiscard]] LogLevel get_log_level() const noexcept
        {
            return m_current_log_level.load(std::memory_order_acquire);
        }

        /**
         * @brief Checks whether messages at the given level would be logged.
         * @details Useful for gating expensive trace-only work (e.g. iterating a data structure solely to build a log
         *          message).
         * @param level The LogLevel to test.
         * @return true if a message at this level would pass the current filter.
         */
        [[nodiscard]] bool is_enabled(LogLevel level) const noexcept
        {
            return level >= m_current_log_level.load(std::memory_order_acquire);
        }

        /**
         * @brief Sets the minimum log level for messages to be recorded.
         * @param level The minimum LogLevel to record.
         */
        void set_log_level(LogLevel level);

        /**
         * @brief Logs a message if its level is at or above the current log level.
         * @param level The LogLevel of the message.
         * @param message The message string to log.
         * @return true if the message was delivered to the sink (enqueued in async mode, or written to a healthy file
         *         stream in sync mode); false if it was filtered out by level, dropped (queue full), or the file sink
         *         was closed/unhealthy. The return is informational; callers that do not need delivery status may
         *         ignore it.
         */
        bool log(LogLevel level, std::string_view message);

        /**
         * @brief No-throw counterpart of log() for callers that sit on a noexcept boundary.
         * @details The ordinary log()/error() path can throw (the synchronous sink allocates while formatting the
         *          timestamp, and a custom stream could raise). Calling it from a hook callback, a loader-lock teardown
         *          path, or a catch block inside a noexcept function would let that exception escape and call
         *          std::terminate, taking down the host process. This entry point takes an already-formatted message
         *          and swallows any exception the sink raises, dropping the message instead.
         * @param level The LogLevel of the message.
         * @param message The already-formatted message string.
         * @return true if the message was handed to the sink, false if it was filtered out or an internal failure was
         *         suppressed.
         */
        [[nodiscard]] bool log_noexcept(LogLevel level, std::string_view message) noexcept;

        /**
         * @brief Logs a formatted message with the specified log level.
         * @details Uses std::format-style placeholders. Arguments are only formatted if the log level is enabled (lazy
         *          evaluation).
         * @tparam Args Types of the format arguments.
         * @param level The LogLevel of the message.
         * @param fmt The format string with {} placeholders.
         * @param args The arguments to substitute into the format string.
         */
        template <typename... Args> void log(LogLevel level, std::format_string<Args...> fmt, Args &&...args)
        {
            if (level >= m_current_log_level.load(std::memory_order_acquire))
            {
                log(level, std::format(fmt, std::forward<Args>(args)...));
            }
        }

        /**
         * @name Convenience log methods
         * @brief Shorthand for `log(LogLevel::X, fmt, args...)`. See log() for parameter docs.
         * @{
         */
        template <typename... Args> void trace(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Trace, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args> void debug(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Debug, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args> void info(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Info, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args> void warning(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Warning, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args> void error(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Error, fmt, std::forward<Args>(args)...);
        }
        /** @} */

        /**
         * @brief No-throw formatted logging for callers on a noexcept boundary.
         * @details Like log(level, fmt, args...) but formats inside a try/catch and routes the result through
         *          log_noexcept(), so neither a std::format failure nor a sink failure can propagate. Prefer this over
         *          log()/error()/warning() from inside hook callbacks and other noexcept contexts. Arguments are only
         *          formatted when the level is enabled (lazy evaluation).
         * @return true if the message was handed to the sink, false if it was filtered out or dropped because
         *         formatting/logging failed.
         */
        template <typename... Args>
        [[nodiscard]] bool try_log(LogLevel level, std::format_string<Args...> fmt, Args &&...args) noexcept
        {
            if (level < m_current_log_level.load(std::memory_order_acquire))
            {
                return false;
            }
            try
            {
                return log_noexcept(level, std::format(fmt, std::forward<Args>(args)...));
            }
            catch (...)
            {
                return false;
            }
        }

        /**
         * @brief Converts a log level string to the LogLevel enum.
         * @param level_str The string to convert (case-insensitive).
         * @return The corresponding LogLevel enum. Defaults to LogLevel::Info if unrecognized.
         */
        static LogLevel string_to_log_level(std::string_view level_str);

        /**
         * @struct StaticConfig
         * @brief Immutable configuration snapshot for thread-safe static configuration.
         * @details Stored behind an atomic shared_ptr so readers never need a mutex.
         */
        struct StaticConfig
        {
            std::string log_prefix;
            std::string log_file_name;
            std::string timestamp_format;

            StaticConfig(std::string prefix, std::string file, std::string ts_fmt)
                : log_prefix(std::move(prefix)), log_file_name(std::move(file)), timestamp_format(std::move(ts_fmt))
            {
            }
        };

    private:
        Logger();
        ~Logger() noexcept;

        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;
        Logger(Logger &&) = delete;
        Logger &operator=(Logger &&) = delete;

        /**
         * @brief Shared shutdown logic used by both ~Logger() and shutdown().
         */
        void shutdown_internal();

        /**
         * @brief Generates the current timestamp formatted according to m_timestamp_format.
         * @return std::string The formatted timestamp string.
         */
        std::string get_timestamp() const;

        /**
         * @brief Determines the full path for the log file.
         * @return std::wstring The absolute path as a wide string for Unicode fidelity.
         */
        std::wstring generate_log_file_path() const;

        static std::shared_ptr<const StaticConfig> get_static_config();
        static void set_static_config(std::shared_ptr<const StaticConfig> config);

        // Lock ordering (must be acquired in this order to prevent deadlock):
        //   1. m_async_mutex      -- async logger lifecycle
        //   2. *m_log_mutex_ptr   -- file stream I/O

        std::string m_log_prefix;
        std::string m_log_file_name;
        std::string m_timestamp_format;

        std::shared_ptr<WinFileStream> m_log_file_stream_ptr;
        std::shared_ptr<std::mutex> m_log_mutex_ptr;
        std::atomic<LogLevel> m_current_log_level{LogLevel::Info};
        std::atomic<bool> m_shutdown_called{false};

        // Async logging support (forward declared). m_async_logger is atomic for lock-free reads on the log() hot path.
        // m_async_mutex serializes lifecycle operations (enable/disable/shutdown).
        //
        // On MSVC x64, std::atomic<std::shared_ptr<T>> is lock-free (uses
        // 128-bit compare-exchange). On MinGW/GCC, this may fall back to a global mutex, which is still correct but
        // serializes the hot-path load. This is an accepted trade-off: the lock-free fast path benefits the primary
        // target (MSVC), and the MinGW fallback is bounded to one mutex acquisition per log() call, which is comparable
        // to the mutex already used by synchronous mode.
        std::atomic<std::shared_ptr<AsyncLogger>> m_async_logger{};
        std::atomic<bool> m_async_mode_enabled{false};
        std::mutex m_async_mutex;
    };
} // namespace DetourModKit

#endif // DETOURMODKIT_LOGGER_HPP
