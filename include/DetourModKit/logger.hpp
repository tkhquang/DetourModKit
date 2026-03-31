#ifndef DETOURMODKIT_LOGGER_HPP
#define DETOURMODKIT_LOGGER_HPP

#include <string>
#include <string_view>
#include <mutex>
#include <memory>
#include <chrono>
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
     * @details Provides thread-safe logging with configurable levels, timestamps,
     *          and log file location. Uses atomic LogLevel for thread-safe level changes.
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
         * @details If the logger instance already exists, this will also reconfigure the instance
         *          by reopening the log file with the new settings.
         * @param prefix Default log prefix string.
         * @param file_name Default log file name.
         * @param timestamp_fmt Default timestamp format string (strftime compatible).
         */
        static void configure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt);

        /**
         * @brief Reconfigures an existing logger instance with new settings.
         * @details Closes the current log file (if open) and reopens it with the new settings.
         *          Thread-safe. Logs a message about the reconfiguration.
         * @param prefix New log prefix string.
         * @param file_name New log file name.
         * @param timestamp_fmt New timestamp format string (strftime compatible).
         */
        void reconfigure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt);

        /**
         * @brief Enables asynchronous logging mode.
         * @details When enabled, log messages are queued and written by a dedicated
         *          writer thread, reducing latency on the calling thread.
         * @param config Optional async logger configuration. Uses defaults if not provided.
         */
        void enable_async_mode(const AsyncLoggerConfig &config);
        void enable_async_mode();

        /**
         * @brief Disables asynchronous logging mode and returns to synchronous mode.
         * @details Flushes all pending async messages before switching.
         */
        void disable_async_mode();

        /**
         * @brief Checks if async logging mode is enabled.
         * @return true if async mode is enabled, false otherwise.
         */
        bool is_async_mode_enabled() const;

        /**
         * @brief Flushes all pending log messages.
         * @details In async mode, waits for all queued messages to be written.
         *          In sync mode, flushes the file stream.
         */
        void flush();

        /**
         * @brief Explicitly shuts down the Logger, closing files without logging.
         * @details This method is safe to call during shutdown. It closes the log file
         *          and shuts down async logger without attempting to log, preventing
         *          use-after-free if called after other singletons are destroyed.
         *          After calling shutdown(), the destructor becomes a no-op.
         */
        void shutdown();

        /**
         * @brief Gets the current log level.
         * @return LogLevel The current minimum log level.
         */
        LogLevel get_log_level() const
        {
            return current_log_level_.load(std::memory_order_acquire);
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
         */
        void log(LogLevel level, std::string_view message);

        /**
         * @brief Logs a formatted message with the specified log level.
         * @details Uses std::format-style placeholders. Arguments are only formatted
         *          if the log level is enabled (lazy evaluation).
         * @tparam Args Types of the format arguments.
         * @param level The LogLevel of the message.
         * @param fmt The format string with {} placeholders.
         * @param args The arguments to substitute into the format string.
         */
        template <typename... Args>
        void log(LogLevel level, std::format_string<Args...> fmt, Args &&...args)
        {
            if (level >= current_log_level_.load(std::memory_order_acquire))
            {
                log(level, std::format(fmt, std::forward<Args>(args)...));
            }
        }

        /// @name Convenience log methods
        /// Shorthand for `log(LogLevel::X, fmt, args...)`. See log() for parameter docs.
        /// @{
        template <typename... Args>
        void trace(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Trace, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args>
        void debug(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Debug, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args>
        void info(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Info, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args>
        void warning(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Warning, fmt, std::forward<Args>(args)...);
        }

        template <typename... Args>
        void error(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Error, fmt, std::forward<Args>(args)...);
        }
        /// @}

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
                : log_prefix(std::move(prefix)),
                  log_file_name(std::move(file)),
                  timestamp_format(std::move(ts_fmt)) {}
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
         * @brief Generates the current timestamp formatted according to timestamp_format_.
         * @return std::string The formatted timestamp string.
         */
        std::string get_timestamp() const;

        /**
         * @brief Determines the full path for the log file.
         * @return std::string The absolute path to the log file.
         */
        std::string generate_log_file_path() const;

        static std::shared_ptr<const StaticConfig> get_static_config();
        static void set_static_config(std::shared_ptr<const StaticConfig> config);

        // Lock ordering (must be acquired in this order to prevent deadlock):
        //   1. async_mutex_      — async logger lifecycle
        //   2. *log_mutex_ptr_   — file stream I/O

        std::string log_prefix_;
        std::string log_file_name_;
        std::string timestamp_format_;

        std::shared_ptr<WinFileStream> log_file_stream_ptr_;
        std::shared_ptr<std::mutex> log_mutex_ptr_;
        std::atomic<LogLevel> current_log_level_{LogLevel::Info};
        std::atomic<bool> shutdown_called_{false};

        // Async logging support (forward declared).
        // async_logger_ is atomic for lock-free reads on the log() hot path.
        // async_mutex_ serializes lifecycle operations (enable/disable/shutdown).
        std::atomic<std::shared_ptr<AsyncLogger>> async_logger_{};
        std::atomic<bool> async_mode_enabled_{false};
        std::mutex async_mutex_;
    };
} // namespace DetourModKit

#endif // DETOURMODKIT_LOGGER_HPP
