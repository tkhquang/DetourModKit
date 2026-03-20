/**
 * @file logger.cpp
 * @brief Implementation of the singleton Logger class.
 */

#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger.hpp"
#include "DetourModKit/format.hpp"

#include <windows.h>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <array>
#include <map>

using namespace DetourModKit;

std::string Logger::s_log_prefix_ = "DetourModKit";
std::string Logger::s_log_file_name_ = "DetourModKit_Log.txt";
std::string Logger::s_timestamp_format_ = "%Y-%m-%d %H:%M:%S";

LogLevel Logger::string_to_log_level(const std::string &level_str)
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
    // get_instance().log() can't be called here as it might recurse during construction
    std::cerr << "[" << s_log_prefix_ << " Logger WARNING] Unrecognized log level string '" << level_str
              << "'. Defaulting to INFO." << std::endl;
    return LogLevel::Info;
}

void Logger::configure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt)
{
    std::lock_guard<std::mutex> lock(Logger::get_init_mutex());

    s_log_prefix_ = prefix;
    s_log_file_name_ = file_name;
    s_timestamp_format_ = timestamp_fmt;

    Logger &instance = get_instance();

    if (instance.log_prefix_ != prefix ||
        instance.log_file_name_ != file_name ||
        instance.timestamp_format_ != timestamp_fmt)
    {
        instance.reconfigure(prefix, file_name, timestamp_fmt);
    }
}

void Logger::reconfigure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt)
{
    std::lock_guard<std::mutex> lock(log_access_mutex_);

    shutdown_called_ = false;

    if (log_file_stream_.is_open() && log_file_stream_.good())
    {
        log_file_stream_ << "[" << get_timestamp() << "] "
                        << "[" << std::setw(7) << std::left << "INFO" << "] :: "
                        << "Logger reconfiguring. New file: " << file_name << '\n';
        log_file_stream_.flush();
        log_file_stream_.close();
    }

    log_prefix_ = prefix;
    log_file_name_ = file_name;
    timestamp_format_ = timestamp_fmt;

    std::string log_file_full_path = generate_log_file_path();
    log_file_stream_.open(log_file_full_path, std::ios::out | std::ios::trunc);

    if (!log_file_stream_.is_open())
    {
        std::cerr << "[" << log_prefix_ << " Logger CRITICAL ERROR] "
                  << "Failed to open log file at: " << log_file_full_path
                  << ". Subsequent logs to file will fail." << std::endl;
    }
    else
    {
        log_file_stream_ << "[" << get_timestamp() << "] "
                        << "[" << std::setw(7) << std::left << "INFO" << "] :: "
                        << "Logger reconfigured. Now logging to: " << log_file_full_path << '\n';
    }
}

Logger::Logger()
{
    // No lock on get_init_mutex() here — either configure() already holds it,
    // or we're using defaults via C++11 thread-safe static local initialization.
    log_prefix_ = s_log_prefix_;
    log_file_name_ = s_log_file_name_;
    timestamp_format_ = s_timestamp_format_;

    std::string log_file_full_path = generate_log_file_path();
    log_file_stream_.open(log_file_full_path, std::ios::out | std::ios::trunc);

    if (!log_file_stream_.is_open())
    {
        std::cerr << "[" << log_prefix_ << " Logger CRITICAL ERROR] "
                  << "Failed to open log file at: " << log_file_full_path
                  << ". Subsequent logs to file will fail." << std::endl;
    }
    else
    {
        log_file_stream_ << "[" << get_timestamp() << "] ["
                        << std::setw(7) << std::left << "INFO"
                        << "] :: Logger initialized. Logging to: " << log_file_full_path << '\n';
    }
}

Logger::~Logger()
{
    if (!shutdown_called_)
    {
        // Fallback if DMK_Shutdown() was not called — cannot safely log.
        if (async_mode_enabled_.load(std::memory_order_acquire) && async_logger_)
        {
            async_logger_->shutdown();
            async_logger_.reset();
        }

        if (log_file_stream_.is_open())
        {
            std::lock_guard<std::mutex> lock(log_access_mutex_);
            log_file_stream_.flush();
            log_file_stream_.close();
        }
    }
}

void Logger::shutdown()
{
    if (shutdown_called_)
        return;
    shutdown_called_ = true;

    if (async_mode_enabled_.load(std::memory_order_acquire) && async_logger_)
    {
        async_logger_->shutdown();
        async_logger_.reset();
    }

    if (log_file_stream_.is_open())
    {
        std::lock_guard<std::mutex> lock(log_access_mutex_);
        log_file_stream_.flush();
        log_file_stream_.close();
    }
}

void Logger::set_log_level(LogLevel level)
{
    auto level_int = static_cast<std::underlying_type_t<LogLevel>>(level);
    if (level_int < 0 || level_int > 4)
    {
        log(LogLevel::Warning, "Attempted to set an invalid log level value ({}). Keeping current level.", level_int);
        return;
    }

    auto old_level = current_log_level_.load(std::memory_order_acquire);
    current_log_level_.store(level, std::memory_order_release);

    log(LogLevel::Info, "Log level changed from {} to {}",
        log_level_to_string(old_level), log_level_to_string(level));
}

void Logger::log(LogLevel level, const std::string &message)
{
    if (level >= current_log_level_.load(std::memory_order_acquire))
    {
        if (async_mode_enabled_.load(std::memory_order_acquire) && async_logger_)
        {
            async_logger_->enqueue(level, message);
            return;
        }

        auto level_str = log_level_to_string(level);
        std::lock_guard<std::mutex> lock(log_access_mutex_);

        if (log_file_stream_.is_open() && log_file_stream_.good())
        {
            log_file_stream_ << "[" << get_timestamp() << "] "
                            << "[" << std::setw(7) << std::left << level_str << "] :: "
                            << message << '\n';
        }
        else if (level >= LogLevel::Error)
        {
            std::cerr << "[" << log_prefix_ << " LOG_FILE_WRITE_ERROR] [" << get_timestamp() << "] ["
                      << std::setw(7) << std::left << level_str << "] :: "
                      << message << std::endl;
        }
    }
}

std::string Logger::get_timestamp() const
{
    try
    {
        const auto now = std::chrono::system_clock::now();
        const auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm timeinfo_struct = {};

#if defined(_MSC_VER)
        if (localtime_s(&timeinfo_struct, &in_time_t) != 0)
        {
            throw std::runtime_error("localtime_s failed to convert time.");
        }
#else
        std::tm *timeinfo_ptr = std::localtime(&in_time_t);
        if (!timeinfo_ptr)
        {
            throw std::runtime_error("std::localtime returned a null pointer.");
        }
        timeinfo_struct = *timeinfo_ptr;
#endif
        std::ostringstream oss;
        oss << std::put_time(&timeinfo_struct, timestamp_format_.c_str());
        return oss.str();
    }
    catch (const std::exception &e)
    {
        // If timestamp generation fails, log to cerr and return an error string.
        // log_prefix_ should be used.
        std::cerr << "[" << log_prefix_ << " Logger TIMESTAMP_ERROR] Failed to generate timestamp: " << e.what() << std::endl;
        return "TIMESTAMP_GENERATION_ERROR";
    }
    catch (...)
    {
        std::cerr << "[" << log_prefix_ << " Logger TIMESTAMP_ERROR] Unknown exception during timestamp generation." << std::endl;
        return "TIMESTAMP_GENERATION_ERROR";
    }
}

std::string Logger::generate_log_file_path() const
{
    std::filesystem::path log_file_path_obj(log_file_name_);
    if (log_file_path_obj.is_absolute())
    {
        return log_file_name_;
    }

    std::string determined_module_dir;
    HMODULE h_current_module = NULL;
    char module_full_path_buffer[MAX_PATH] = {0};

    try
    {
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(&Logger::get_instance),
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
        std::filesystem::path final_log_path = std::filesystem::path(determined_module_dir) / log_file_name_;
        return final_log_path.lexically_normal().string();
    }
    catch (const std::exception &e)
    {
        std::cerr << "[" << log_prefix_ << " Logger PATH_WARNING] Failed to determine module directory for log file: "
                  << e.what() << ". Using relative path for log file: " << log_file_name_ << std::endl;
        return log_file_name_;
    }
    catch (...)
    {
        std::cerr << "[" << log_prefix_ << " Logger PATH_WARNING] Unknown exception while determining module directory for log file."
                  << " Using relative path: " << log_file_name_ << std::endl;
        return log_file_name_;
    }
}

void Logger::enable_async_mode(const AsyncLoggerConfig &config)
{
    if (async_mode_enabled_.load(std::memory_order_acquire))
    {
        return;
    }

    if (!log_file_stream_.is_open())
    {
        log(LogLevel::Error, "Cannot enable async mode: log file is not open.");
        return;
    }

    try
    {
        async_logger_ = std::make_unique<AsyncLogger>(config, log_file_stream_, log_access_mutex_);
        async_mode_enabled_.store(true, std::memory_order_release);
        log(LogLevel::Info, "Async logging mode enabled. Queue capacity: {}, Batch size: {}",
            config.queue_capacity, config.batch_size);
    }
    catch (const std::exception &e)
    {
        log(LogLevel::Error, "Failed to enable async mode: {}", e.what());
    }
}

void Logger::enable_async_mode()
{
    enable_async_mode(AsyncLoggerConfig{});
}

void Logger::disable_async_mode()
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

bool Logger::is_async_mode_enabled() const
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
        std::lock_guard<std::mutex> lock(log_access_mutex_);
        if (log_file_stream_.is_open())
        {
            log_file_stream_.flush();
        }
    }
}

std::mutex &Logger::get_init_mutex()
{
    static std::mutex mutex;
    return mutex;
}
