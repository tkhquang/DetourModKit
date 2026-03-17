/**
 * @file logger.cpp
 * @brief Implementation of the singleton Logger class.
 */

#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger.hpp"
#include "DetourModKit/format_utils.hpp"

using namespace DetourModKit;

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

/**
 * @brief Converts a log level string (case-insensitive) to LogLevel enum.
 * @param level_str The string representation of the log level.
 * @return The corresponding LogLevel enum. Returns LogLevel::Info if string is unrecognized.
 */
LogLevel Logger::stringToLogLevel(const std::string &level_str)
{
    std::string upper_level_str = level_str;
    std::transform(upper_level_str.begin(), upper_level_str.end(), upper_level_str.begin(),
                   [](unsigned char c)
                   { return static_cast<char>(std::toupper(c)); });

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

    // Default to INFO if string is not recognized.
    // getInstance().log() can't be called here as it might recurse during construction
    std::cerr << "[" << s_log_prefix << " Logger WARNING] Unrecognized log level string '" << level_str
              << "'. Defaulting to INFO." << std::endl;
    return LogLevel::Info;
}

void Logger::configure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt)
{
    // First, update static variables (need to hold init mutex for this)
    {
        std::lock_guard<std::mutex> lock(Logger::getLoggerInitMutex()); // Protect static variable modification
        s_log_prefix = prefix;
        s_log_file_name = file_name;
        s_timestamp_format = timestamp_fmt;
    }

    // Get the instance AFTER releasing the lock to avoid deadlock
    // The Logger constructor also tries to lock getLoggerInitMutex()
    // Note: getInstance() uses a static local and cannot throw
    Logger &instance = getInstance();

    // Only reconfigure if the instance's settings differ from the new static settings
    // This prevents unnecessary file reopening if settings are the same
    if (instance.log_prefix_instance != prefix ||
        instance.log_file_name_instance != file_name ||
        instance.timestamp_format_instance != timestamp_fmt)
    {
        instance.reconfigure(prefix, file_name, timestamp_fmt);
    }
}

void Logger::reconfigure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt)
{
    std::lock_guard<std::mutex> lock(log_access_mutex);

    // Log reconfiguration message to current log file before changing settings
    if (log_file_stream.is_open() && log_file_stream.good())
    {
        log_file_stream << "[" << getTimestamp() << "] "
                        << "[" << std::setw(7) << std::left << "INFO" << "] :: "
                        << "Logger reconfiguring. New file: " << file_name << '\n';
        log_file_stream.flush();
        log_file_stream.close();
    }

    // Update instance members
    log_prefix_instance = prefix;
    log_file_name_instance = file_name;
    timestamp_format_instance = timestamp_fmt;

    // Open new log file
    std::string log_file_full_path = generateLogFilePath();
    log_file_stream.open(log_file_full_path, std::ios::out | std::ios::trunc);

    if (!log_file_stream.is_open())
    {
        std::cerr << "[" << log_prefix_instance << " Logger CRITICAL ERROR] "
                  << "Failed to open log file at: " << log_file_full_path
                  << ". Subsequent logs to file will fail." << std::endl;
    }
    else
    {
        log_file_stream << "[" << getTimestamp() << "] "
                        << "[" << std::setw(7) << std::left << "INFO" << "] :: "
                        << "Logger reconfigured. Now logging to: " << log_file_full_path << '\n';
    }
}

Logger::Logger()
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
                        << "] :: Logger initialized. Logging to: " << log_file_full_path << '\n';
    }
}

Logger::~Logger()
{
    // Shutdown async logger first if enabled
    if (async_mode_enabled_.load(std::memory_order_acquire) && async_logger_)
    {
        async_logger_->shutdown();
        async_logger_.reset();
    }

    if (log_file_stream.is_open())
    {
        // Ensure thread safety for this final log message.
        std::lock_guard<std::mutex> lock(log_access_mutex);
        log_file_stream << "[" << getTimestamp() << "] ["
                        << std::setw(7) << std::left << "INFO"
                        << "] :: Logger shutting down." << '\n';
        log_file_stream.flush(); // Ensure all buffered data is written
        log_file_stream.close();
    }
}

void Logger::setLogLevel(LogLevel level)
{
    // Validate if the level is one of the known enums for safety
    auto level_int = static_cast<std::underlying_type_t<LogLevel>>(level);
    if (level_int < 0 || level_int > 4)
    {
        log(LogLevel::Warning, "Attempted to set an invalid log level value ({}). Keeping current level.", level_int);
        return;
    }

    auto old_level = current_log_level.load(std::memory_order_acquire);
    current_log_level.store(level, std::memory_order_release);

    log(LogLevel::Info, "Log level changed from {} to {}",
        logLevelToString(old_level), logLevelToString(level));
}

void Logger::log(LogLevel level, const std::string &message)
{
    // Check if the message's level is sufficient to be logged.
    // Atomic load for thread-safe level checking without lock contention
    if (level >= current_log_level.load(std::memory_order_acquire))
    {
        // Use async logger if enabled
        if (async_mode_enabled_.load(std::memory_order_acquire) && async_logger_)
        {
            async_logger_->enqueue(level, message);
            return;
        }

        // Synchronous logging (original behavior)
        auto level_str = logLevelToString(level);
        std::lock_guard<std::mutex> lock(log_access_mutex); // Protect file stream access

        if (log_file_stream.is_open() && log_file_stream.good())
        {
            log_file_stream << "[" << getTimestamp() << "] " // getTimestamp is const, assumed thread-safe in its impl.
                            << "[" << std::setw(7) << std::left << level_str << "] :: "
                            << message << '\n'; // Use '\n' instead of std::endl to avoid implicit flush
        }
        else if (level >= LogLevel::Error) // Only if file isn't open, output critical errors to cerr
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
    catch (const std::exception &e)
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

void Logger::enableAsyncMode(const AsyncLoggerConfig &config)
{
    if (async_mode_enabled_.load(std::memory_order_acquire))
    {
        return;
    }

    if (!log_file_stream.is_open())
    {
        log(LogLevel::Error, "Cannot enable async mode: log file is not open.");
        return;
    }

    try
    {
        async_logger_ = std::make_unique<AsyncLogger>(config, log_file_stream, log_access_mutex);
        async_mode_enabled_.store(true, std::memory_order_release);
        log(LogLevel::Info, "Async logging mode enabled. Queue capacity: {}, Batch size: {}",
            config.queue_capacity, config.batch_size);
    }
    catch (const std::exception &e)
    {
        log(LogLevel::Error, "Failed to enable async mode: {}", e.what());
    }
}

void Logger::enableAsyncMode()
{
    enableAsyncMode(AsyncLoggerConfig{});
}

void Logger::disableAsyncMode()
{
    if (!async_mode_enabled_.load(std::memory_order_acquire))
    {
        return;
    }

    if (async_logger_)
    {
        async_logger_->shutdown();
        async_logger_.reset();
    }

    async_mode_enabled_.store(false, std::memory_order_release);
    log(LogLevel::Info, "Async logging mode disabled. Switched to synchronous mode.");
}

bool Logger::isAsyncModeEnabled() const
{
    return async_mode_enabled_.load(std::memory_order_acquire);
}

void Logger::flush()
{
    if (async_mode_enabled_.load(std::memory_order_acquire) && async_logger_)
    {
        async_logger_->flush();
    }
    else
    {
        std::lock_guard<std::mutex> lock(log_access_mutex);
        if (log_file_stream.is_open())
        {
            log_file_stream.flush();
        }
    }
}

// Definition for the static mutex
std::mutex &Logger::getLoggerInitMutex()
{
    static std::mutex mutex;
    return mutex;
}
