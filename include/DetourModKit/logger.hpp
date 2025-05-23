#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <algorithm>

/**
 * @enum LogLevel
 * @brief Defines the severity levels for log messages.
 * @details Messages with a level equal to or higher than the currently set
 *          log level will be recorded.
 */
enum LogLevel
{
    LOG_TRACE = 0,   /**< Detailed diagnostic information, typically for debugging. */
    LOG_DEBUG = 1,   /**< Information useful for debugging, less verbose than TRACE. */
    LOG_INFO = 2,    /**< General informational messages about application operation. */
    LOG_WARNING = 3, /**< Indicates a potential issue or an unexpected event. */
    LOG_ERROR = 4    /**< Signifies an error that prevented normal operation. */
};

/**
 * @class Logger
 * @brief A singleton class for logging messages to a file.
 * @details Provides thread-safe logging with configurable levels, timestamps,
 *          and log file location. It's designed to be easy to use throughout
 *          an application for consistent logging.
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
        // Meyers' singleton: thread-safe in C++11 and later.
        // The constructor will be called only once.
        static Logger instance;
        return instance;
    }

    /**
     * @brief Configures global static settings for the logger BEFORE first instantiation.
     * @details Sets the default prefix, filename, and timestamp format used by the
     *          logger instance when it's first created. Call this early in application
     *          startup if custom defaults are needed.
     * @param prefix Default log prefix string (e.g., "MyMod").
     * @param file_name Default log file name (e.g., "MyMod.log").
     * @param timestamp_fmt Default timestamp format string (strftime compatible).
     */
    static void configure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt);

    /**
     * @brief Sets the minimum log level for messages to be recorded.
     * @param level The minimum LogLevel to record. Messages below this level will be ignored.
     */
    void setLogLevel(LogLevel level);

    /**
     * @brief Logs a message if its level is at or above the current log level.
     * @param level The LogLevel of the message.
     * @param message The message string to log.
     */
    void log(LogLevel level, const std::string &message);

    /**
     * @brief Converts a log level string (case-insensitive) to the LogLevel enum.
     * @param level_str The string to convert (e.g., "DEBUG", "info").
     * @return The corresponding LogLevel enum. Defaults to LOG_INFO if unrecognized.
     */
    static LogLevel stringToLogLevel(const std::string &level_str);

private:
    /**
     * @brief Private constructor to enforce singleton pattern. Initializes log file.
     */
    Logger();

    /**
     * @brief Private destructor. Closes the log file.
     */
    ~Logger();

    // Prevent copying and assignment for a singleton.
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
     * @details If log_file_name_instance is relative, it places it in the directory of the
     *          current module (DLL/EXE). If absolute, uses it directly.
     * @return std::string The absolute path to the log file.
     */
    std::string generateLogFilePath() const;

    /**
     * @brief Provides a mutex for initializing/configuring static logger members.
     * @return A reference to a static mutex.
     */
    static std::mutex &getLoggerInitMutex();

    // --- Static members for default configuration (set by ::configure) ---
    static std::string s_log_prefix;       /**< Default prefix for log messages, configurable. */
    static std::string s_log_file_name;    /**< Default name for the log file, configurable. */
    static std::string s_timestamp_format; /**< Default format for timestamps, configurable (strftime). */

    // --- Instance members (initialized from static defaults or specific settings) ---
    std::string log_prefix_instance;       /**< Prefix used by this logger instance. */
    std::string log_file_name_instance;    /**< Log file name used by this instance. */
    std::string timestamp_format_instance; /**< Timestamp format used by this instance. */

    std::ofstream log_file_stream; /**< The output file stream for logging. */
    LogLevel current_log_level;    /**< Current minimum level for messages to be logged.
                                        Potentially std::atomic<LogLevel> for lock-free reads in `log`. */
    std::mutex log_access_mutex;   /**< Mutex to protect concurrent writes to the log file stream
                                        and access to shared non-atomic members if setLogLevel is concurrent. */
};

#endif // LOGGER_HPP
