#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <fstream>
#include <mutex>
#include <algorithm>

namespace DetourModKit
{
    /**
     * @enum LogLevel
     * @brief Defines the severity levels for log messages.
     */
    enum LogLevel
    {
        LOG_TRACE = 0,
        LOG_DEBUG = 1,
        LOG_INFO = 2,
        LOG_WARNING = 3,
        LOG_ERROR = 4
    };

    /**
     * @class Logger
     * @brief A singleton class for logging messages to a file.
     * @details Provides thread-safe logging with configurable levels, timestamps,
     *          and log file location.
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
         * @param prefix Default log prefix string.
         * @param file_name Default log file name.
         * @param timestamp_fmt Default timestamp format string (strftime compatible).
         */
        static void configure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt);

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
         * @brief Converts a log level string to the LogLevel enum.
         * @param level_str The string to convert (case-insensitive).
         * @return The corresponding LogLevel enum. Defaults to LOG_INFO if unrecognized.
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
        LogLevel current_log_level;
        std::mutex log_access_mutex;
    };
} // namespace DetourModKit

#endif // LOGGER_HPP
