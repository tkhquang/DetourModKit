/**
 * @file logger.cpp
 * @brief Implementation of the singleton Logger class.
 */

#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <array>
#include <map>

using namespace DetourModKit;

// Static member initialization
std::string Logger::s_log_prefix = "DetourModKit";            // Default prefix
std::string Logger::s_log_file_name = "DetourModKit_Log.txt"; // Default log file name
std::string Logger::s_timestamp_format = "%Y-%m-%d %H:%M:%S"; // Default timestamp

// Helper to map LogLevel enum to string representations.
// This map ensures correct string lookup even if enum values change.
const std::map<LogLevel, std::string> LOG_LEVEL_STRING_MAP = {
    {LOG_TRACE, "TRACE"},
    {LOG_DEBUG, "DEBUG"},
    {LOG_INFO, "INFO"},
    {LOG_WARNING, "WARNING"},
    {LOG_ERROR, "ERROR"}};

/**
 * @brief Converts a LogLevel enum to its string representation.
 * @param level The LogLevel enum value.
 * @return String representation of the log level, or "UNKNOWN" if not found.
 */
static std::string logLevelToString(LogLevel level)
{
    auto it = LOG_LEVEL_STRING_MAP.find(level);
    if (it != LOG_LEVEL_STRING_MAP.end())
    {
        return it->second;
    }
    return "UNKNOWN";
}

/**
 * @brief Converts a log level string (case-insensitive) to LogLevel enum.
 * @param level_str The string representation of the log level.
 * @return The corresponding LogLevel enum. Returns LOG_INFO if string is unrecognized.
 */
LogLevel Logger::stringToLogLevel(const std::string &level_str)
{
    std::string upper_level_str = level_str;
    std::transform(upper_level_str.begin(), upper_level_str.end(), upper_level_str.begin(), ::toupper);

    if (upper_level_str == "TRACE")
        return LOG_TRACE;
    if (upper_level_str == "DEBUG")
        return LOG_DEBUG;
    if (upper_level_str == "INFO")
        return LOG_INFO;
    if (upper_level_str == "WARNING")
        return LOG_WARNING;
    if (upper_level_str == "ERROR")
        return LOG_ERROR;

    // Default to INFO if string is not recognized.
    // getInstance().log() can't be called here as it might recurse during construction
    std::cerr << "[" << s_log_prefix << " Logger WARNING] Unrecognized log level string '" << level_str
              << "'. Defaulting to INFO." << std::endl;
    return LOG_INFO;
}

void Logger::configure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt)
{
    // These static members are used by getInstance() if it's called before explicit configuration,
    // or can be called at the start of the application to override defaults.
    // Note: This configuration should ideally happen before the first getInstance() call
    // if the logger is to use these custom settings from its very first message.
    // If getInstance() has already run, it will have used the old static defaults.
    // For a singleton, this kind of reconfiguration can be tricky if the instance is already in use.
    // However, since these statics are used by the constructor, it's more about when the constructor runs.
    std::lock_guard<std::mutex> lock(Logger::getLoggerInitMutex()); // Protect static variable modification
    s_log_prefix = prefix;
    s_log_file_name = file_name;
    s_timestamp_format = timestamp_fmt;

    // If the instance already exists, it won't re-run its constructor with these new static values.
    // One might need to add a re-init method to the logger if runtime reconfiguration of an existing instance is needed.
    // For now, assume configure() is called early.
}

Logger::Logger() : current_log_level(LOG_INFO) // Default to INFO level
{
    // Use the static configurations set by ::configure or their defaults.
    // Need to ensure this constructor isn't causing issues if s_log_prefix changes after construction.
    // The 'log_prefix' member takes a snapshot at construction time.
    {
        std::lock_guard<std::mutex> lock(Logger::getLoggerInitMutex());
        log_prefix_instance = s_log_prefix; // Instance specific copy
        log_file_name_instance = s_log_file_name;
        timestamp_format_instance = s_timestamp_format;
    }

    std::string log_file_full_path = generateLogFilePath(); // Uses instance member log_file_name_instance

    // Open the log file in truncate mode to overwrite previous logs from this session.
    // Use std::ios::app for appending if desired.
    log_file_stream.open(log_file_full_path, std::ios::out | std::ios::trunc);

    if (!log_file_stream.is_open())
    {
        // Critical failure to open log file. Output to cerr.
        std::cerr << "[" << log_prefix_instance << " Logger CRITICAL ERROR] "
                  << "Failed to open log file at: " << log_file_full_path
                  << ". Subsequent logs to file will fail." << std::endl;
    }
    else
    {
        // Log successful initialization to the file itself.
        // Manually format this first message as 'log' method might not be fully ready or to avoid recursion.
        log_file_stream << "[" << getTimestamp() << "] ["
                        << std::setw(7) << std::left << "INFO"
                        << "] :: Logger initialized. Logging to: " << log_file_full_path << std::endl;
    }
}

Logger::~Logger()
{
    if (log_file_stream.is_open())
    {
        // Ensure thread safety for this final log message.
        std::lock_guard<std::mutex> lock(log_access_mutex);
        log_file_stream << "[" << getTimestamp() << "] ["
                        << std::setw(7) << std::left << "INFO"
                        << "] :: Logger shutting down." << std::endl;
        log_file_stream.flush(); // Ensure all buffered data is written
        log_file_stream.close();
    }
}

void Logger::setLogLevel(LogLevel level)
{
    // Validate if the level is one of the known enums for safety, though it's an enum.
    if (level < LOG_TRACE || level > LOG_ERROR)
    {
        log(LOG_WARNING, "Attempted to set an invalid log level value (" + std::to_string(level) + "). Keeping current level.");
        return;
    }

    std::string old_level_str = logLevelToString(current_log_level);
    current_log_level = level; // This is an atomic write if LogLevel is std::atomic, but it's not.
                               // Mutex in log() protects concurrent reads/writes of log_file_stream,
                               // but current_log_level itself might need protection if setLogLevel can be
                               // called concurrently with log(). For typical usage (set once or rarely), this is fine.
                               // Add a lock if setLogLevel is frequently called from multiple threads.
    std::string new_level_str = logLevelToString(level);
    log(LOG_INFO, "Log level changed from " + old_level_str + " to " + new_level_str);
}

void Logger::log(LogLevel level, const std::string &message)
{
    // Check if the message's level is sufficient to be logged.
    if (level >= current_log_level) // Read of current_log_level
    {
        std::string level_str = logLevelToString(level);
        std::lock_guard<std::mutex> lock(log_access_mutex); // Protect file stream access

        if (log_file_stream.is_open() && log_file_stream.good())
        {
            log_file_stream << "[" << getTimestamp() << "] " // getTimestamp is const, assumed thread-safe in its impl.
                            << "[" << std::setw(7) << std::left << level_str << "] :: "
                            << message << std::endl; // endl flushes, can be perf intensive.
                                                     // Consider just '\n' and periodic flushes if high-rate logging.
        }
        else if (level >= LOG_ERROR) // Only if file isn't open, output critical errors to cerr
        {
            // This indicates the log file itself has an issue.
            std::cerr << "[" << log_prefix_instance << " LOG_FILE_WRITE_ERROR] [" << getTimestamp() << "] ["
                      << std::setw(7) << std::left << level_str << "] :: "
                      << message << std::endl;
        }
    }
}

std::string Logger::getTimestamp() const
{
    try
    {
        const auto now = std::chrono::system_clock::now();
        const auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm timeinfo_struct = {}; // Zero-initialize

// Use platform-specific safe versions of localtime.
#if defined(_MSC_VER) // Microsoft Visual C++
        if (localtime_s(&timeinfo_struct, &in_time_t) != 0)
        {
            throw std::runtime_error("localtime_s failed to convert time.");
        }
#else // POSIX or other compilers
        std::tm *timeinfo_ptr = std::localtime(&in_time_t);
        if (!timeinfo_ptr)
        {
            throw std::runtime_error("std::localtime returned a null pointer.");
        }
        timeinfo_struct = *timeinfo_ptr; // Copy data from the thread-local storage
#endif
        std::ostringstream oss;
        // timestamp_format_instance should be used here
        oss << std::put_time(&timeinfo_struct, timestamp_format_instance.c_str());
        return oss.str();
    }
    catch (const std::exception &e)
    {
        // If timestamp generation fails, log to cerr and return an error string.
        // log_prefix_instance should be used.
        std::cerr << "[" << log_prefix_instance << " Logger TIMESTAMP_ERROR] Failed to generate timestamp: " << e.what() << std::endl;
        return "TIMESTAMP_GENERATION_ERROR";
    }
    catch (...)
    {
        std::cerr << "[" << log_prefix_instance << " Logger TIMESTAMP_ERROR] Unknown exception during timestamp generation." << std::endl;
        return "TIMESTAMP_GENERATION_ERROR";
    }
}

std::string Logger::generateLogFilePath() const
{
    // Check if log_file_name_instance is an absolute path
    std::filesystem::path log_file_path_obj(log_file_name_instance);
    if (log_file_path_obj.is_absolute())
    {
        return log_file_name_instance; // Already an absolute path
    }

    // If relative, place it in the module's directory.
    std::string determined_module_dir;
    HMODULE h_current_module = NULL;
    char module_full_path_buffer[MAX_PATH] = {0};

    try
    {
        // Get a handle to the module containing the Logger class (this DLL/EXE).
        // Address of Logger::getInstance serves this purpose.
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)&Logger::getInstance, // Address within this module
                                &h_current_module) ||
            h_current_module == NULL)
        {
            throw std::runtime_error("GetModuleHandleExA failed for logger's module. Error: " + std::to_string(GetLastError()));
        }

        DWORD path_len = GetModuleFileNameA(h_current_module, module_full_path_buffer, MAX_PATH);
        if (path_len == 0)
        {
            throw std::runtime_error("GetModuleFileNameA failed for logger's module path. Error: " + std::to_string(GetLastError()));
        }
        if (path_len == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            throw std::runtime_error("GetModuleFileNameA buffer too small for logger's module path.");
        }

        std::filesystem::path actual_module_path(module_full_path_buffer);
        determined_module_dir = actual_module_path.parent_path().string();
        std::filesystem::path final_log_path = std::filesystem::path(determined_module_dir) / log_file_name_instance;
        return final_log_path.lexically_normal().string();
    }
    catch (const std::exception &e) // Includes std::filesystem::filesystem_error
    {
        // Fallback strategy if determining module path fails.
        std::cerr << "[" << log_prefix_instance << " Logger PATH_WARNING] Failed to determine module directory for log file: "
                  << e.what() << ". Using relative path for log file: " << log_file_name_instance << std::endl;
        return log_file_name_instance; // Use the relative file name as is
    }
    catch (...)
    {
        std::cerr << "[" << log_prefix_instance << " Logger PATH_WARNING] Unknown exception while determining module directory for log file."
                  << " Using relative path: " << log_file_name_instance << std::endl;
        return log_file_name_instance;
    }
}

// Definition for the static mutex
std::mutex &Logger::getLoggerInitMutex()
{
    static std::mutex mutex;
    return mutex;
}
