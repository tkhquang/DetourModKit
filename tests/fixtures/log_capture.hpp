#ifndef DETOURMODKIT_TESTS_FIXTURES_LOG_CAPTURE_HPP
#define DETOURMODKIT_TESTS_FIXTURES_LOG_CAPTURE_HPP

/**
 * @file log_capture.hpp
 * @brief Redirects the process logger to a private file for one scope and reads the captured text back.
 *
 * Sync mode is forced because a test inspects the file right after the logging call returns. The destructor parks the
 * logger on a stable per-process file so the capture file's handle is released before the remove. A later capture or
 * test reconfigures the sink as it needs.
 */

#include "DetourModKit/logger.hpp"

#include <process.h>

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>

namespace dmk_test
{
    /// Captures every record at or above @p level for the fixture's lifetime and restores the prior level after it.
    class LoggerFileCapture
    {
    public:
        explicit LoggerFileCapture(DetourModKit::LogLevel level = DetourModKit::LogLevel::Trace)
        {
            static std::atomic<int> s_counter{0};
            const int n = s_counter.fetch_add(1, std::memory_order_relaxed);
            m_capture_file = std::filesystem::temp_directory_path() /
                             ("dmk_capture_" + std::to_string(_getpid()) + "_" + std::to_string(n) + ".log");
            DetourModKit::Logger &logger = DetourModKit::log();
            m_previous_async = logger.is_async_mode_enabled();
            if (m_previous_async)
            {
                logger.disable_async_mode();
            }
            DetourModKit::Logger::configure("CAPTURE", m_capture_file.string(), "%H:%M:%S");
            m_previous_level = logger.get_log_level();
            logger.set_log_level(level);
        }

        ~LoggerFileCapture()
        {
            DetourModKit::Logger &logger = DetourModKit::log();
            logger.flush();
            const std::filesystem::path parking =
                std::filesystem::temp_directory_path() / ("dmk_capture_parked_" + std::to_string(_getpid()) + ".log");
            DetourModKit::Logger::configure("PARKED", parking.string(), "%H:%M:%S");
            logger.set_log_level(m_previous_level);
            if (m_previous_async)
            {
                logger.enable_async_mode();
            }
            std::error_code ignored;
            std::filesystem::remove(m_capture_file, ignored);
        }

        LoggerFileCapture(const LoggerFileCapture &) = delete;
        LoggerFileCapture &operator=(const LoggerFileCapture &) = delete;
        LoggerFileCapture(LoggerFileCapture &&) = delete;
        LoggerFileCapture &operator=(LoggerFileCapture &&) = delete;

        /// Flushes the logger and returns everything captured so far.
        [[nodiscard]] std::string read_all() const
        {
            DetourModKit::log().flush();
            std::ifstream in(m_capture_file);
            if (!in)
            {
                return {};
            }
            return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }

        /// True when one captured [WARNING] line contains @p needle.
        [[nodiscard]] bool contains_warning_with(std::string_view needle) const
        {
            const std::string content = read_all();
            std::size_t pos = 0;
            while (true)
            {
                const std::size_t next = content.find('\n', pos);
                const std::string_view line(
                    content.data() + pos,
                    (next == std::string::npos ? content.size() : next) - pos
                );
                if (line.find("[WARNING]") != std::string_view::npos && line.find(needle) != std::string_view::npos)
                {
                    return true;
                }
                if (next == std::string::npos)
                {
                    break;
                }
                pos = next + 1;
            }
            return false;
        }

        /// Counts the captured [WARNING] records.
        [[nodiscard]] std::size_t warning_count() const
        {
            const std::string content = read_all();
            std::size_t count = 0;
            std::size_t pos = 0;
            while ((pos = content.find("[WARNING]", pos)) != std::string::npos)
            {
                ++count;
                pos += 9;
            }
            return count;
        }

    private:
        std::filesystem::path m_capture_file;
        DetourModKit::LogLevel m_previous_level{DetourModKit::LogLevel::Info};
        bool m_previous_async{false};
    };
} // namespace dmk_test

#endif // DETOURMODKIT_TESTS_FIXTURES_LOG_CAPTURE_HPP
