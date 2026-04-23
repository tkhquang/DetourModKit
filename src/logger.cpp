#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger.hpp"
#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/format.hpp"
#include "platform.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <array>
#include <vector>

namespace DetourModKit
{

    namespace
    {
        std::atomic<std::shared_ptr<const Logger::StaticConfig>> &static_config_atom()
        {
            static std::atomic<std::shared_ptr<const Logger::StaticConfig>> instance{
                std::make_shared<const Logger::StaticConfig>(
                    DEFAULT_LOG_PREFIX, DEFAULT_LOG_FILE_NAME, DEFAULT_TIMESTAMP_FORMAT)};
            return instance;
        }
    } // anonymous namespace

    std::shared_ptr<const Logger::StaticConfig> Logger::get_static_config()
    {
        return static_config_atom().load(std::memory_order_acquire);
    }

    void Logger::set_static_config(std::shared_ptr<const StaticConfig> config)
    {
        static_config_atom().store(std::move(config), std::memory_order_release);
    }

    LogLevel Logger::string_to_log_level(std::string_view level_str)
    {
        std::string upper_level_str(level_str);
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

        std::cerr << "[" << DEFAULT_LOG_PREFIX << " Logger WARNING] Unrecognized log level string '" << level_str
                  << "'. Defaulting to INFO." << '\n';
        return LogLevel::Info;
    }

    void Logger::configure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt)
    {
        set_static_config(std::make_shared<const StaticConfig>(std::string(prefix), std::string(file_name), std::string(timestamp_fmt)));

        Logger &instance = get_instance();

        // configure() is the authoritative reset path — allow reconfiguration
        // even after shutdown to support reuse (e.g., test fixtures).
        instance.shutdown_called_.store(false, std::memory_order_release);

        // Comparison is done inside reconfigure() under the lock to prevent
        // reading string members while another thread is modifying them.
        instance.reconfigure(prefix, file_name, timestamp_fmt);
    }

    void Logger::reconfigure(std::string_view prefix, std::string_view file_name, std::string_view timestamp_fmt)
    {
        if (shutdown_called_.load(std::memory_order_acquire))
        {
            return;
        }

        // Acquire both async_mutex_ and log_mutex_ to prevent concurrent log() calls
        // from reading partially-updated string members during reconfiguration
        std::scoped_lock lock(async_mutex_, *log_mutex_ptr_);

        // Skip reconfiguration only when all parameters match AND the stream is usable.
        // After shutdown or a prior open failure the stream may be closed, so we must
        // fall through to reopen even if the strings are identical.
        if (log_file_stream_ptr_->is_open() &&
            log_prefix_ == prefix &&
            log_file_name_ == file_name &&
            timestamp_format_ == timestamp_fmt)
        {
            return;
        }

        if (log_file_stream_ptr_->is_open() && log_file_stream_ptr_->good())
        {
            *log_file_stream_ptr_ << "[" << get_timestamp() << "] "
                                  << "[" << std::setw(7) << std::left << "INFO" << "] :: "
                                  << "Logger reconfiguring. New file: " << file_name << '\n';
            log_file_stream_ptr_->flush();
            log_file_stream_ptr_->close();
        }

        log_prefix_ = prefix;
        log_file_name_ = file_name;
        timestamp_format_ = timestamp_fmt;

        std::wstring log_file_full_path = generate_log_file_path();
        log_file_stream_ptr_->open(log_file_full_path, std::ios::out | std::ios::trunc);

        if (!log_file_stream_ptr_->is_open())
        {
            std::cerr << "[" << log_prefix_ << " Logger CRITICAL ERROR] "
                      << "Failed to open log file: "
                      << std::filesystem::path(log_file_full_path).string()
                      << ". Subsequent logs to file will fail." << '\n';
        }
        else
        {
            *log_file_stream_ptr_ << "[" << get_timestamp() << "] "
                                  << "[" << std::setw(7) << std::left << "INFO" << "] :: "
                                  << "Logger reconfigured. Now logging to: " << file_name << '\n';
        }
    }

    Logger::Logger()
        : log_file_stream_ptr_(std::make_shared<WinFileStream>()),
          log_mutex_ptr_(std::make_shared<std::mutex>())
    {
        {
            auto config = get_static_config();
            log_prefix_ = config->log_prefix;
            log_file_name_ = config->log_file_name;
            timestamp_format_ = config->timestamp_format;
        }

        const std::wstring log_file_full_path = generate_log_file_path();
        log_file_stream_ptr_->open(log_file_full_path, std::ios::out | std::ios::trunc);

        if (!log_file_stream_ptr_->is_open())
        {
            std::cerr << "[" << log_prefix_ << " Logger CRITICAL ERROR] "
                      << "Failed to open log file: "
                      << std::filesystem::path(log_file_full_path).string()
                      << ". Subsequent logs to file will fail." << '\n';
        }
        else
        {
            *log_file_stream_ptr_ << "[" << get_timestamp() << "] ["
                                  << std::setw(7) << std::left << "INFO"
                                  << "] :: Logger initialized. Logging to: " << log_file_name_ << '\n';
        }
    }

    Logger::~Logger() noexcept
    {
        bool expected = false;
        if (!shutdown_called_.compare_exchange_strong(expected, true,
                                                      std::memory_order_acq_rel))
        {
            return;
        }
        shutdown_internal();
    }

    void Logger::shutdown()
    {
        bool expected = false;
        if (!shutdown_called_.compare_exchange_strong(expected, true,
                                                      std::memory_order_acq_rel))
        {
            return;
        }
        shutdown_internal();
    }

    void Logger::shutdown_internal()
    {
        std::shared_ptr<AsyncLogger> local_logger;

        {
            std::lock_guard<std::mutex> lock(async_mutex_);
            if (async_mode_enabled_.load(std::memory_order_acquire))
            {
                local_logger = async_logger_.exchange(nullptr, std::memory_order_acq_rel);
                async_mode_enabled_.store(false, std::memory_order_release);
                if (local_logger)
                {
                    local_logger->shutdown();
                }
            }
        }

        // If the writer thread was detached under loader lock, it may still
        // be accessing AsyncLogger members (queue_, flush_mutex_, etc.).
        // Transfer ownership to a static so the object outlives the detached
        // thread. The pinned module keeps code pages valid; this keeps the
        // heap-allocated state valid.
        //
        // The transfer is unconditional when loader lock is held: concurrent
        // log() callers may still own temporary shared_ptrs obtained from
        // async_logger_ before exchange(), so use_count() is not a reliable
        // proxy for "no other owners". Dropping local_logger's ref while
        // a temporary outlives us would let the last temporary's destructor
        // race the detached writer thread.
        //
        // The storage is append-only: a process that re-attaches after a
        // shutdown (e.g. hot-reload) and hits loader lock again must not
        // drop the prior handle, because its writer thread may still be
        // accessing the old AsyncLogger state.
        if (local_logger && detail::is_loader_lock_held())
        {
            static std::vector<std::shared_ptr<AsyncLogger>> s_leaked_loggers;
            s_leaked_loggers.emplace_back(std::move(local_logger));
        }

        {
            // Acquire both mutexes to prevent configure()/reconfigure() from
            // opening a new stream in the gap after BLOCK 1 releases async_mutex_.
            std::scoped_lock lock(async_mutex_, *log_mutex_ptr_);
            if (log_file_stream_ptr_ && log_file_stream_ptr_->is_open())
            {
                log_file_stream_ptr_->flush();
                log_file_stream_ptr_->close();
            }
        }
    }

    void Logger::set_log_level(LogLevel level)
    {
        auto level_int = static_cast<std::underlying_type_t<LogLevel>>(level);
        if (level_int < 0 || level_int > static_cast<std::underlying_type_t<LogLevel>>(LogLevel::Error))
        {
            log(LogLevel::Warning, "Attempted to set an invalid log level value ({}). Keeping current level.", level_int);
            return;
        }

        auto old_level = current_log_level_.load(std::memory_order_acquire);
        if (old_level == level)
        {
            return;
        }

        current_log_level_.store(level, std::memory_order_release);

        log(LogLevel::Info, "Log level changed from {} to {}",
            log_level_to_string(old_level), log_level_to_string(level));
    }

    void Logger::log(LogLevel level, std::string_view message)
    {
        if (level >= current_log_level_.load(std::memory_order_acquire))
        {
            // Fast path: lock-free check via atomic shared_ptr
            if (async_mode_enabled_.load(std::memory_order_acquire))
            {
                auto local_logger = async_logger_.load(std::memory_order_acquire);
                if (local_logger)
                {
                    static_cast<void>(local_logger->enqueue(level, message));
                    return;
                }
            }

            const auto level_str = log_level_to_string(level);
            std::lock_guard<std::mutex> lock(*log_mutex_ptr_);

            if (log_file_stream_ptr_->is_open() && log_file_stream_ptr_->good())
            {
                *log_file_stream_ptr_ << "[" << get_timestamp() << "] "
                                      << "[" << std::setw(7) << std::left << level_str << "] :: "
                                      << message << '\n';

                // Flush on warnings/errors to ensure critical messages survive crashes
                if (level >= LogLevel::Warning)
                {
                    log_file_stream_ptr_->flush();
                }
            }
            else if (level >= LogLevel::Error)
            {
                std::cerr << "[" << log_prefix_ << " LOG_FILE_WRITE_ERROR] [" << get_timestamp() << "] ["
                          << std::setw(7) << std::left << level_str << "] :: "
                          << message << '\n';
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
#elif defined(__MINGW32__) || defined(__MINGW64__)
            // MinGW: localtime_s has reversed parameter order (ISO C11 Annex K)
            if (localtime_s(&timeinfo_struct, &in_time_t) != 0)
            {
                throw std::runtime_error("localtime_s failed to convert time.");
            }
#else
            if (localtime_r(&in_time_t, &timeinfo_struct) == nullptr)
            {
                throw std::runtime_error("localtime_r failed to convert time.");
            }
#endif
            // Single stack buffer for timestamp + milliseconds, no heap allocation
            char buf[134];
            const size_t len = std::strftime(buf, sizeof(buf) - 5, timestamp_format_.c_str(), &timeinfo_struct);
            if (len == 0)
            {
                return "TIMESTAMP_FORMAT_ERROR";
            }

            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                now.time_since_epoch()) %
                            1000;
            const int ms_len = std::snprintf(buf + len, 5, ".%03d", static_cast<int>(ms.count()));
            return std::string(buf, len + static_cast<size_t>(ms_len));
        }
        catch (const std::exception &e)
        {
            std::cerr << "[" << log_prefix_ << " Logger TIMESTAMP_ERROR] Failed to generate timestamp: " << e.what() << '\n';
            return "TIMESTAMP_GENERATION_ERROR";
        }
        catch (...)
        {
            std::cerr << "[" << log_prefix_ << " Logger TIMESTAMP_ERROR] Unknown exception during timestamp generation." << '\n';
            return "TIMESTAMP_GENERATION_ERROR";
        }
    }

    std::wstring Logger::generate_log_file_path() const
    {
        std::filesystem::path log_file_path_obj(log_file_name_);
        if (log_file_path_obj.is_absolute())
        {
            return log_file_path_obj.wstring();
        }

        try
        {
            std::wstring module_dir = Filesystem::get_runtime_directory();
            if (module_dir.empty() || module_dir == L".")
            {
                std::cerr << "[" << log_prefix_ << " Logger PATH_WARNING] "
                          << "Could not determine module directory. Using relative path: " << log_file_name_ << '\n';
                return log_file_path_obj.wstring();
            }

            const std::filesystem::path final_log_path = std::filesystem::path(module_dir) / log_file_name_;
            return final_log_path.lexically_normal().wstring();
        }
        catch (const std::exception &e)
        {
            std::cerr << "[" << log_prefix_ << " Logger PATH_WARNING] Failed to determine module directory for log file: "
                      << e.what() << ". Using relative path for log file: " << log_file_name_ << '\n';
            return log_file_path_obj.wstring();
        }
        catch (...)
        {
            std::cerr << "[" << log_prefix_ << " Logger PATH_WARNING] Unknown exception while determining module directory for log file."
                      << " Using relative path: " << log_file_name_ << '\n';
            return log_file_path_obj.wstring();
        }
    }

    void Logger::enable_async_mode(const AsyncLoggerConfig &config)
    {
        bool should_log_error = false;
        bool should_log_success = false;
        std::string error_msg;
        size_t queue_cap = 0;
        size_t batch_sz = 0;

        {
            std::lock_guard<std::mutex> lock(async_mutex_);

            if (async_mode_enabled_.load(std::memory_order_acquire))
            {
                return;
            }

            if (!log_file_stream_ptr_->is_open())
            {
                should_log_error = true;
                error_msg = "Cannot enable async mode: log file is not open.";
            }
            else
            {
                try
                {
                    async_logger_.store(
                        std::make_shared<AsyncLogger>(config, log_file_stream_ptr_, log_mutex_ptr_),
                        std::memory_order_release);
                    async_mode_enabled_.store(true, std::memory_order_release);
                    should_log_success = true;
                    queue_cap = config.queue_capacity;
                    batch_sz = config.batch_size;
                }
                catch (const std::exception &e)
                {
                    should_log_error = true;
                    error_msg = std::string("Failed to enable async mode: ") + e.what();
                }
            }
        }

        if (should_log_error)
        {
            log(LogLevel::Error, "{}", error_msg);
        }
        else if (should_log_success)
        {
            log(LogLevel::Info, "Async logging mode enabled. Queue capacity: {}, Batch size: {}",
                queue_cap, batch_sz);
        }
    }

    void Logger::enable_async_mode()
    {
        enable_async_mode(AsyncLoggerConfig{});
    }

    void Logger::disable_async_mode()
    {
        bool should_log = false;

        {
            std::lock_guard<std::mutex> lock(async_mutex_);

            if (!async_mode_enabled_.load(std::memory_order_acquire))
            {
                return;
            }

            auto local_async = async_logger_.exchange(nullptr, std::memory_order_acq_rel);
            if (local_async)
            {
                local_async->shutdown();
            }

            async_mode_enabled_.store(false, std::memory_order_release);
            should_log = true;
        }

        if (should_log)
        {
            log(LogLevel::Info, "Async logging mode disabled. Switched to synchronous mode.");
        }
    }

    bool Logger::is_async_mode_enabled() const
    {
        return async_mode_enabled_.load(std::memory_order_acquire);
    }

    void Logger::flush()
    {
        if (async_mode_enabled_.load(std::memory_order_acquire))
        {
            auto local_logger = async_logger_.load(std::memory_order_acquire);
            if (local_logger)
            {
                local_logger->flush();
                return;
            }
        }

        std::lock_guard<std::mutex> lock(*log_mutex_ptr_);
        if (log_file_stream_ptr_->is_open())
        {
            log_file_stream_ptr_->flush();
        }
    }

} // namespace DetourModKit
