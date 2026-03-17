#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "DetourModKit/log_level.hpp"

#include <string>
#include <fstream>
#include <mutex>
#include <algorithm>
#include <memory>
#include <chrono>
#include <format>
#include <atomic>

namespace DetourModKit
{
    // Forward declarations to break circular dependency
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
        static Logger &getInstance()
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
        static void configure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt);

        /**
         * @brief Reconfigures an existing logger instance with new settings.
         * @details Closes the current log file (if open) and reopens it with the new settings.
         *          Thread-safe. Logs a message about the reconfiguration.
         * @param prefix New log prefix string.
         * @param file_name New log file name.
         * @param timestamp_fmt New timestamp format string (strftime compatible).
         */
        void reconfigure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt);

        /**
         * @brief Enables asynchronous logging mode.
         * @details When enabled, log messages are queued and written by a dedicated
         *          writer thread, reducing latency on the calling thread.
         * @param config Optional async logger configuration. Uses defaults if not provided.
         */
        void enableAsyncMode(const AsyncLoggerConfig &config);
        void enableAsyncMode();

        /**
         * @brief Disables asynchronous logging mode and returns to synchronous mode.
         * @details Flushes all pending async messages before switching.
         */
        void disableAsyncMode();

        /**
         * @brief Checks if async logging mode is enabled.
         * @return true if async mode is enabled, false otherwise.
         */
        bool isAsyncModeEnabled() const;

        /**
         * @brief Flushes all pending log messages.
         * @details In async mode, waits for all queued messages to be written.
         *          In sync mode, flushes the file stream.
         */
        void flush();

        /**
         * @brief Gets the current log level.
         * @return LogLevel The current minimum log level.
         */
        LogLevel getLogLevel() const
        {
            return current_log_level.load(std::memory_order_acquire);
        }

        /**
         * @brief Sets the minimum log level for messages to be recorded.
         * @param level The minimum LogLevel to record.
         */
        void setLogLevel(LogLevel level);

        /**
         * @brief Logs a message if its level is at or above the current log level.
         * @param level The LogLevel of the message.
         * @param message The message string to log.
         */
        void log(LogLevel level, const std::string &message);

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
            if (level >= current_log_level.load(std::memory_order_acquire))
            {
                log(level, std::format(fmt, std::forward<Args>(args)...));
            }
        }

        /**
         * @brief Logs a TRACE level message with format string.
         * @tparam Args Types of the format arguments.
         * @param fmt The format string.
         * @param args The arguments.
         */
        template <typename... Args>
        void trace(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Trace, fmt, std::forward<Args>(args)...);
        }

        /**
         * @brief Logs a DEBUG level message with format string.
         * @tparam Args Types of the format arguments.
         * @param fmt The format string.
         * @param args The arguments.
         */
        template <typename... Args>
        void debug(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Debug, fmt, std::forward<Args>(args)...);
        }

        /**
         * @brief Logs an INFO level message with format string.
         * @tparam Args Types of the format arguments.
         * @param fmt The format string.
         * @param args The arguments.
         */
        template <typename... Args>
        void info(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Info, fmt, std::forward<Args>(args)...);
        }

        /**
         * @brief Logs a WARNING level message with format string.
         * @tparam Args Types of the format arguments.
         * @param fmt The format string.
         * @param args The arguments.
         */
        template <typename... Args>
        void warning(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Warning, fmt, std::forward<Args>(args)...);
        }

        /**
         * @brief Logs an ERROR level message with format string.
         * @tparam Args Types of the format arguments.
         * @param fmt The format string.
         * @param args The arguments.
         */
        template <typename... Args>
        void error(std::format_string<Args...> fmt, Args &&...args)
        {
            log(LogLevel::Error, fmt, std::forward<Args>(args)...);
        }

        /**
         * @brief Converts a log level string to the LogLevel enum.
         * @param level_str The string to convert (case-insensitive).
         * @return The corresponding LogLevel enum. Defaults to LogLevel::Info if unrecognized.
         */
        static LogLevel stringToLogLevel(const std::string &level_str);

    private:
        Logger();
        ~Logger();

        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;
        Logger(Logger &&) = delete;
        Logger &operator=(Logger &&) = delete;

        /**
         * @brief Generates the current timestamp formatted according to timestamp_format_instance.
         * @return std::string The formatted timestamp string.
         */
        std::string getTimestamp() const;

        /**
         * @brief Determines the full path for the log file.
         * @return std::string The absolute path to the log file.
         */
        std::string generateLogFilePath() const;

        /**
         * @brief Provides a mutex for initializing/configuring static logger members.
         * @return A reference to a static mutex.
         */
        static std::mutex &getLoggerInitMutex();

        static std::string s_log_prefix;
        static std::string s_log_file_name;
        static std::string s_timestamp_format;

        std::string log_prefix_instance;
        std::string log_file_name_instance;
        std::string timestamp_format_instance;

        std::ofstream log_file_stream;
        std::atomic<LogLevel> current_log_level{LogLevel::Info}; // Atomic for thread-safe reads/writes
        std::mutex log_access_mutex;

        // Async logging support (forward declared)
        std::unique_ptr<AsyncLogger> async_logger_;
        std::atomic<bool> async_mode_enabled_{false};
    };
} // namespace DetourModKit

#endif // LOGGER_HPP
