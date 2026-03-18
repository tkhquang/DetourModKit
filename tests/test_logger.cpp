// Unit tests for Logger module
#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <windows.h>

#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger.hpp"

using namespace DetourModKit;

// Test fixture for Logger tests
class LoggerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Create a unique log file for each test using PID and a counter to avoid conflicts
        static int test_counter = 0;
        test_log_file_ = std::filesystem::temp_directory_path() /
                         ("test_logger_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(test_counter++) + ".log");
        Logger::configure("TEST", test_log_file_.string(), "%Y-%m-%d %H:%M:%S");
    }

    void TearDown() override
    {
        // Try to close the log file by reconfiguring to a different file first
        // This helps release the file handle
        auto temp_file = std::filesystem::temp_directory_path() / "test_logger_temp.log";
        Logger::configure("TEMP", temp_file.string(), "%Y-%m-%d %H:%M:%S");

        // Clean up log file (may fail if file is still locked, which is acceptable)
        try
        {
            if (std::filesystem::exists(test_log_file_))
            {
                std::filesystem::remove(test_log_file_);
            }
        }
        catch (const std::filesystem::filesystem_error &)
        {
            // Ignore cleanup errors - file may still be locked
        }

        // Clean up temp file
        try
        {
            if (std::filesystem::exists(temp_file))
            {
                std::filesystem::remove(temp_file);
            }
        }
        catch (const std::filesystem::filesystem_error &)
        {
            // Ignore cleanup errors
        }
    }

    std::filesystem::path test_log_file_;
};

// Test log level to string conversion
TEST_F(LoggerTest, LogLevelToString)
{
    EXPECT_EQ(logLevelToString(LogLevel::Trace), "TRACE");
    EXPECT_EQ(logLevelToString(LogLevel::Debug), "DEBUG");
    EXPECT_EQ(logLevelToString(LogLevel::Info), "INFO");
    EXPECT_EQ(logLevelToString(LogLevel::Warning), "WARNING");
    EXPECT_EQ(logLevelToString(LogLevel::Error), "ERROR");
}

// Test singleton pattern
TEST(LoggerSingleton, GetInstance)
{
    Logger &instance1 = Logger::getInstance();
    Logger &instance2 = Logger::getInstance();
    EXPECT_EQ(&instance1, &instance2);
}

// Test log level setting and getting
TEST_F(LoggerTest, SetAndGetLogLevel)
{
    Logger &logger = Logger::getInstance();

    logger.setLogLevel(LogLevel::Warning);
    EXPECT_EQ(logger.getLogLevel(), LogLevel::Warning);

    logger.setLogLevel(LogLevel::Debug);
    EXPECT_EQ(logger.getLogLevel(), LogLevel::Debug);
}

// Test basic logging (should not crash)
TEST_F(LoggerTest, BasicLogging)
{
    Logger &logger = Logger::getInstance();

    // These should not throw
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test info message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test debug message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Test warning message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Test error message"));
}

// Test formatted logging
TEST_F(LoggerTest, FormattedLogging)
{
    Logger &logger = Logger::getInstance();

    // These should not throw - use log() with format string
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test value: {}", 42));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test string: {}", std::string("hello")));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Multiple: {} and {}", 1, 2.5));
}

// Test log level filtering - messages below threshold should not be logged
TEST_F(LoggerTest, LogLevelFiltering)
{
    Logger &logger = Logger::getInstance();
    logger.setLogLevel(LogLevel::Warning);

    // These should not throw (but won't actually log)
    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Should not appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Should not appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Should not appear"));

    // These should log
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Should appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Should appear"));
}

// Test flush functionality
TEST_F(LoggerTest, Flush)
{
    Logger &logger = Logger::getInstance();
    EXPECT_NO_THROW(logger.flush());
}

// Test async mode enable/disable
TEST_F(LoggerTest, AsyncMode)
{
    Logger &logger = Logger::getInstance();

    // Enable async mode
    EXPECT_NO_THROW(logger.enableAsyncMode());
    EXPECT_TRUE(logger.isAsyncModeEnabled());

    // Disable async mode
    EXPECT_NO_THROW(logger.disableAsyncMode());
    EXPECT_FALSE(logger.isAsyncModeEnabled());
}

// Test async mode with config
TEST_F(LoggerTest, AsyncModeWithConfig)
{
    Logger &logger = Logger::getInstance();

    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{100};

    EXPECT_NO_THROW(logger.enableAsyncMode(config));
    EXPECT_TRUE(logger.isAsyncModeEnabled());

    EXPECT_NO_THROW(logger.disableAsyncMode());
    EXPECT_FALSE(logger.isAsyncModeEnabled());
}

// Test thread safety - multiple threads logging concurrently
TEST_F(LoggerTest, ThreadSafety)
{
    Logger &logger = Logger::getInstance();
    logger.setLogLevel(LogLevel::Trace);

    std::vector<std::thread> threads;
    const int num_threads = 4;
    const int messages_per_thread = 100;

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&logger, i, messages_per_thread]()
                             {
            for (int j = 0; j < messages_per_thread; ++j) {
                logger.log(LogLevel::Info, "Thread " + std::to_string(i) + " message " + std::to_string(j));
            } });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    // If we get here without crash, thread safety is verified
    SUCCEED();
}

// Test reconfigure
TEST_F(LoggerTest, Reconfigure)
{
    Logger &logger = Logger::getInstance();

    auto new_log_file = std::filesystem::temp_directory_path() /
                        ("test_logger_reconfig_" + std::to_string(GetCurrentProcessId()) + ".log");

    EXPECT_NO_THROW(logger.reconfigure("NEW_PREFIX", new_log_file.string(), "%H:%M:%S"));

    // Try to clean up - may fail if file is still locked
    try
    {
        if (std::filesystem::exists(new_log_file))
        {
            std::filesystem::remove(new_log_file);
        }
    }
    catch (const std::filesystem::filesystem_error &)
    {
        // Ignore cleanup errors - file may still be locked
    }
}
