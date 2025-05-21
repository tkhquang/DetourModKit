/**
 * @file logger.cpp
 * @brief Implementation of the singleton Logger class.
 */

#include "logger.hpp"
#include <windows.h>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <array>

std::string Logger::s_log_prefix = "";
std::string Logger::s_log_file_name = "log.txt";
std::string Logger::s_timestamp_format = "%Y-%m-%d %H:%M:%S";

void Logger::configure(const std::string &prefix, const std::string &file_name, const std::string &timestamp_fmt)
{
    s_log_prefix = prefix;
    s_log_file_name = file_name;
    s_timestamp_format = timestamp_fmt;
}

Logger::Logger() : current_log_level(LOG_INFO)
{
    log_prefix = s_log_prefix;
    log_file_name = s_log_file_name;
    timestamp_format = s_timestamp_format;

    std::string log_file_path = generateLogFilePath();
    log_file_stream.open(log_file_path, std::ios::trunc);
    if (!log_file_stream.is_open())
    {
        std::cerr << "[" << log_prefix << " Logger ERROR] "
                  << "Failed to open log file: " << log_file_path << std::endl;
    }
    else
    {
        log(LOG_INFO, "Logger initialized. Log file: " + log_file_path);
    }
}

Logger::~Logger()
{
    if (log_file_stream.is_open())
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        log_file_stream << "[" << getTimestamp() << "] [INFO   ] :: Logger shutting down." << std::endl;
        log_file_stream.flush();
        log_file_stream.close();
    }
}

void Logger::setLogLevel(LogLevel level)
{
    static const std::array<std::string, 5> log_level_strings = {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR"};

    std::string old_level_str = (current_log_level >= LOG_TRACE && current_log_level <= LOG_ERROR)
                                    ? log_level_strings[current_log_level]
                                    : "UNKNOWN";
    current_log_level = level;
    std::string new_level_str = (level >= LOG_TRACE && level <= LOG_ERROR)
                                    ? log_level_strings[level]
                                    : "UNKNOWN";
    log(LOG_INFO, "Log level changed from " + old_level_str + " to " + new_level_str);
}

void Logger::log(LogLevel level, const std::string &message)
{
    static const std::array<std::string, 5> log_level_strings = {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR"};

    if (level >= current_log_level)
    {
        std::string level_str = (level >= LOG_TRACE && level <= LOG_ERROR)
                                    ? log_level_strings[level]
                                    : "UNKNOWN";
        std::lock_guard<std::mutex> lock(log_mutex);
        if (log_file_stream.is_open() && log_file_stream.good())
        {
            log_file_stream << "[" << getTimestamp() << "] "
                            << "[" << std::setw(7) << std::left << level_str << "] :: "
                            << message << std::endl;
        }
        else if (level >= LOG_ERROR)
        {
            std::cerr << "[" << log_prefix << " LOG_FILE_ERR] [" << getTimestamp() << "] ["
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
        std::tm timeinfo = {};
#if defined(_MSC_VER)
        if (localtime_s(&timeinfo, &in_time_t) != 0)
        {
            throw std::runtime_error("localtime_s failed");
        }
#else
        std::tm *timeinfo_ptr = std::localtime(&in_time_t);
        if (!timeinfo_ptr)
            throw std::runtime_error("std::localtime returned null");
        timeinfo = *timeinfo_ptr;
#endif
        std::ostringstream oss;
        oss << std::put_time(&timeinfo, timestamp_format.c_str());
        return oss.str();
    }
    catch (const std::exception &e)
    {
        std::cerr << "[" << log_prefix << " Logger ERROR] Timestamp failed: " << e.what() << std::endl;
        return "TIMESTAMP_ERR";
    }
    catch (...)
    {
        std::cerr << "[" << log_prefix << " Logger ERROR] Unknown timestamp exception." << std::endl;
        return "TIMESTAMP_ERR";
    }
}

std::string Logger::generateLogFilePath() const
{
    std::filesystem::path log_path(log_file_name);
    if (log_path.is_absolute())
    {
        return log_file_name;
    }
    else
    {
        std::string result_path = log_file_name;
        HMODULE h_self = NULL;
        char module_path_buffer[MAX_PATH] = {0};
        try
        {
            if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    (LPCSTR)&Logger::getInstance, &h_self) ||
                h_self == NULL)
            {
                throw std::runtime_error("GetModuleHandleExA failed: " + std::to_string(GetLastError()));
            }
            DWORD path_len = GetModuleFileNameA(h_self, module_path_buffer, MAX_PATH);
            if (path_len == 0)
                throw std::runtime_error("GetModuleFileNameA failed: " + std::to_string(GetLastError()));
            if (path_len == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                throw std::runtime_error("GetModuleFileNameA failed: Buffer too small");
            std::filesystem::path module_full_path(module_path_buffer);
            std::filesystem::path log_file_full_path = module_full_path.parent_path() / log_file_name;
            result_path = log_file_full_path.string();
        }
        catch (const std::exception &e)
        {
            std::cerr << "[" << log_prefix << " Logger WARNING] Failed get module dir: " << e.what() << ". Using fallback: " << result_path << std::endl;
        }
        catch (...)
        {
            std::cerr << "[" << log_prefix << " Logger WARNING] Unknown exception get module path. Using fallback: " << result_path << std::endl;
        }
        return result_path;
    }
}
