#ifndef LOG_LEVEL_HPP
#define LOG_LEVEL_HPP

#include <string_view>

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
    constexpr std::string_view logLevelToString(LogLevel level) noexcept
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
}

#endif // LOG_LEVEL_HPP
