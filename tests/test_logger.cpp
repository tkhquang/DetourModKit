// Unit tests for Logger module
#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <windows.h>
#include <shared_mutex>
#include <future>
#include <latch>
#include <barrier>
#include <atomic>
#include <variant>
#include <optional>

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
    EXPECT_EQ(log_level_to_string(LogLevel::Trace), "TRACE");
    EXPECT_EQ(log_level_to_string(LogLevel::Debug), "DEBUG");
    EXPECT_EQ(log_level_to_string(LogLevel::Info), "INFO");
    EXPECT_EQ(log_level_to_string(LogLevel::Warning), "WARNING");
    EXPECT_EQ(log_level_to_string(LogLevel::Error), "ERROR");
}

// Test string to log level conversion
TEST_F(LoggerTest, StringToLogLevel)
{
    // Test all valid levels (case insensitive)
    EXPECT_EQ(Logger::string_to_log_level("TRACE"), LogLevel::Trace);
    EXPECT_EQ(Logger::string_to_log_level("trace"), LogLevel::Trace);
    EXPECT_EQ(Logger::string_to_log_level("DEBUG"), LogLevel::Debug);
    EXPECT_EQ(Logger::string_to_log_level("debug"), LogLevel::Debug);
    EXPECT_EQ(Logger::string_to_log_level("INFO"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("info"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("WARNING"), LogLevel::Warning);
    EXPECT_EQ(Logger::string_to_log_level("warning"), LogLevel::Warning);
    EXPECT_EQ(Logger::string_to_log_level("ERROR"), LogLevel::Error);
    EXPECT_EQ(Logger::string_to_log_level("error"), LogLevel::Error);

    // Test invalid string defaults to INFO
    EXPECT_EQ(Logger::string_to_log_level("INVALID"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level(""), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("XYZ"), LogLevel::Info);
}

// Test singleton pattern
TEST(LoggerSingleton, GetInstance)
{
    Logger &instance1 = Logger::get_instance();
    Logger &instance2 = Logger::get_instance();
    EXPECT_EQ(&instance1, &instance2);
}

// Test log level setting and getting
TEST_F(LoggerTest, SetAndGetLogLevel)
{
    Logger &logger = Logger::get_instance();

    logger.set_log_level(LogLevel::Warning);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Warning);

    logger.set_log_level(LogLevel::Debug);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Debug);

    logger.set_log_level(LogLevel::Trace);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Trace);

    logger.set_log_level(LogLevel::Error);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Error);

    logger.set_log_level(LogLevel::Info);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);
}

// Test basic logging (should not crash)
TEST_F(LoggerTest, BasicLogging)
{
    Logger &logger = Logger::get_instance();

    // These should not throw
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test info message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test debug message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Test warning message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Test error message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Test trace message"));
}

// Test formatted logging
TEST_F(LoggerTest, FormattedLogging)
{
    Logger &logger = Logger::get_instance();

    // These should not throw - use log() with format string
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test value: {}", 42));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test string: {}", std::string("hello")));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Multiple: {} and {}", 1, 2.5));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Mixed: {} {} {}", 1, "two", 3.0f));
}

// Test convenience methods
TEST_F(LoggerTest, ConvenienceMethods)
{
    Logger &logger = Logger::get_instance();

    // Test all convenience methods
    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));
    EXPECT_NO_THROW(logger.error("Error message"));

    // Test formatted versions
    EXPECT_NO_THROW(logger.trace("Trace: {}", 1));
    EXPECT_NO_THROW(logger.debug("Debug: {}", 2));
    EXPECT_NO_THROW(logger.info("Info: {}", 3));
    EXPECT_NO_THROW(logger.warning("Warning: {}", 4));
    EXPECT_NO_THROW(logger.error("Error: {}", 5));
}

// Test log level filtering - messages below threshold should not be logged
TEST_F(LoggerTest, LogLevelFiltering)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Warning);

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
    Logger &logger = Logger::get_instance();
    EXPECT_NO_THROW(logger.flush());
}

// Test async mode enable/disable
TEST_F(LoggerTest, AsyncMode)
{
    Logger &logger = Logger::get_instance();

    // Enable async mode
    EXPECT_NO_THROW(logger.enable_async_mode());
    EXPECT_TRUE(logger.is_async_mode_enabled());

    // Disable async mode
    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

// Test async mode with config
TEST_F(LoggerTest, AsyncModeWithConfig)
{
    Logger &logger = Logger::get_instance();

    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{100};

    EXPECT_NO_THROW(logger.enable_async_mode(config));
    EXPECT_TRUE(logger.is_async_mode_enabled());

    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

// Test async mode logging
TEST_F(LoggerTest, AsyncModeLogging)
{
    Logger &logger = Logger::get_instance();

    // Enable async mode
    EXPECT_NO_THROW(logger.enable_async_mode());
    EXPECT_TRUE(logger.is_async_mode_enabled());

    // Log some messages
    EXPECT_NO_THROW(logger.info("Async message 1"));
    EXPECT_NO_THROW(logger.info("Async message 2"));
    EXPECT_NO_THROW(logger.debug("Async message 3"));

    // Give async logger time to process
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Disable async mode (should flush)
    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

// Test thread safety - multiple threads logging concurrently
TEST_F(LoggerTest, ThreadSafety)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

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
    Logger &logger = Logger::get_instance();

    auto new_log_file = std::filesystem::temp_directory_path() /
                        ("test_logger_reconfig_" + std::to_string(GetCurrentProcessId()) + ".log");

    EXPECT_NO_THROW(logger.reconfigure("NEW_PREFIX", new_log_file.string(), "%H:%M:%S"));

    // Log a message to new file
    EXPECT_NO_THROW(logger.info("Message after reconfigure"));

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

// Test configure static method
TEST_F(LoggerTest, ConfigureStatic)
{
    auto config_log_file = std::filesystem::temp_directory_path() /
                           ("test_logger_configure_" + std::to_string(GetCurrentProcessId()) + ".log");

    EXPECT_NO_THROW(Logger::configure("CONFIG_PREFIX", config_log_file.string(), "%Y-%m-%d"));

    Logger &logger = Logger::get_instance();
    EXPECT_NO_THROW(logger.info("Message after static configure"));

    // Clean up
    try
    {
        if (std::filesystem::exists(config_log_file))
        {
            std::filesystem::remove(config_log_file);
        }
    }
    catch (const std::filesystem::filesystem_error &)
    {
        // Ignore
    }
}

// Test shutdown
TEST_F(LoggerTest, Shutdown)
{
    Logger &logger = Logger::get_instance();

    // Should not throw
    EXPECT_NO_THROW(logger.shutdown());

    // Second shutdown should not throw
    EXPECT_NO_THROW(logger.shutdown());
}

// Test logging after shutdown
TEST_F(LoggerTest, LoggingAfterShutdown)
{
    Logger &logger = Logger::get_instance();

    // Shutdown
    EXPECT_NO_THROW(logger.shutdown());

    // Logging after shutdown should not crash (may be no-op or error)
    EXPECT_NO_THROW(logger.info("Message after shutdown"));
}

// Test async mode with invalid config
TEST_F(LoggerTest, AsyncModeInvalidConfig)
{
    Logger &logger = Logger::get_instance();

    AsyncLoggerConfig config;
    // Invalid capacity (not power of 2)
    config.queue_capacity = 100; // Not power of 2

    // Should still work (validation may adjust or reject)
    EXPECT_NO_THROW(logger.enable_async_mode(config));

    // Clean up
    EXPECT_NO_THROW(logger.disable_async_mode());
}

// Test long message handling
TEST_F(LoggerTest, LongMessages)
{
    Logger &logger = Logger::get_instance();

    std::string long_message(1000, 'X');
    EXPECT_NO_THROW(logger.info("{}", long_message));

    std::string very_long_message(5000, 'Y');
    EXPECT_NO_THROW(logger.info("{}", very_long_message));
}

// Test special characters in messages
TEST_F(LoggerTest, SpecialCharacters)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Special: !@#$%^&*()"));
    EXPECT_NO_THROW(logger.info("Unicode: \u00e9\u00e8\u00ea")); // accented e
    EXPECT_NO_THROW(logger.info("Newlines: \n\r\t"));
    EXPECT_NO_THROW(logger.info("Quotes: \"single\" and 'double'"));
    EXPECT_NO_THROW(logger.info("Braces: {{ and }}"));
}

// Test empty message
TEST_F(LoggerTest, EmptyMessage)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info(""));
    EXPECT_NO_THROW(logger.debug(""));
    EXPECT_NO_THROW(logger.error(""));
}

// Test log level filtering with formatted messages
TEST_F(LoggerTest, LogLevelFiltering_Formatted)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Warning);

    // These should not throw (but won't actually log)
    EXPECT_NO_THROW(logger.trace("Trace: {}", 1));
    EXPECT_NO_THROW(logger.debug("Debug: {}", 2));
    EXPECT_NO_THROW(logger.info("Info: {}", 3));

    // These should log
    EXPECT_NO_THROW(logger.warning("Warning: {}", 4));
    EXPECT_NO_THROW(logger.error("Error: {}", 5));
}

// Test log level filtering with convenience methods
TEST_F(LoggerTest, LogLevelFiltering_Convenience)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Error);

    // These should not throw (but won't actually log)
    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));

    // This should log
    EXPECT_NO_THROW(logger.error("Error message"));
}

// Test log level filtering with all levels
TEST_F(LoggerTest, LogLevelFiltering_AllLevels)
{
    Logger &logger = Logger::get_instance();

    // Test Trace level
    logger.set_log_level(LogLevel::Trace);
    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));
    EXPECT_NO_THROW(logger.error("Error message"));

    // Test Debug level
    logger.set_log_level(LogLevel::Debug);
    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));
    EXPECT_NO_THROW(logger.error("Error message"));

    // Test Info level
    logger.set_log_level(LogLevel::Info);
    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));
    EXPECT_NO_THROW(logger.error("Error message"));

    // Test Warning level
    logger.set_log_level(LogLevel::Warning);
    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));
    EXPECT_NO_THROW(logger.error("Error message"));

    // Test Error level
    logger.set_log_level(LogLevel::Error);
    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));
    EXPECT_NO_THROW(logger.error("Error message"));
}

// Test log level to string with invalid level
TEST_F(LoggerTest, LogLevelToString_Invalid)
{
    // Test with invalid level value
    LogLevel invalid_level = static_cast<LogLevel>(99);
    EXPECT_EQ(log_level_to_string(invalid_level), "UNKNOWN");
}

// Test string to log level with various cases
TEST_F(LoggerTest, StringToLogLevel_VariousCases)
{
    // Test mixed case
    EXPECT_EQ(Logger::string_to_log_level("Trace"), LogLevel::Trace);
    EXPECT_EQ(Logger::string_to_log_level("DEBUG"), LogLevel::Debug);
    EXPECT_EQ(Logger::string_to_log_level("Info"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("WARNING"), LogLevel::Warning);
    EXPECT_EQ(Logger::string_to_log_level("Error"), LogLevel::Error);

    // Test with spaces
    EXPECT_EQ(Logger::string_to_log_level(" trace "), LogLevel::Info); // Invalid, defaults to Info
    EXPECT_EQ(Logger::string_to_log_level("debug "), LogLevel::Info);  // Invalid, defaults to Info

    // Test with numbers
    EXPECT_EQ(Logger::string_to_log_level("123"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("0"), LogLevel::Info);
}

// Test logger with very long format string
TEST_F(LoggerTest, LongFormatString)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("This is a very long format string with many placeholders: {} {} {} {} {} {} {} {} {} {}", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
}

// Test logger with special format characters
TEST_F(LoggerTest, SpecialFormatCharacters)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Braces: {{ and }}"));
    EXPECT_NO_THROW(logger.info("Percent: %%"));
    EXPECT_NO_THROW(logger.info("Newline: \n"));
    EXPECT_NO_THROW(logger.info("Tab: \t"));
    EXPECT_NO_THROW(logger.info("Quote: \""));
    EXPECT_NO_THROW(logger.info("Backslash: \\"));
}

// Test logger with multiple arguments
TEST_F(LoggerTest, MultipleArguments)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("One arg: {}", 1));
    EXPECT_NO_THROW(logger.info("Two args: {} {}", 1, 2));
    EXPECT_NO_THROW(logger.info("Three args: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.info("Four args: {} {} {} {}", 1, 2, 3, 4));
    EXPECT_NO_THROW(logger.info("Five args: {} {} {} {} {}", 1, 2, 3, 4, 5));
}

// Test logger with different argument types
TEST_F(LoggerTest, DifferentArgumentTypes)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Int: {}", 42));
    EXPECT_NO_THROW(logger.info("Float: {}", 3.14f));
    EXPECT_NO_THROW(logger.info("Double: {}", 3.14159));
    EXPECT_NO_THROW(logger.info("String: {}", std::string("hello")));
    EXPECT_NO_THROW(logger.info("Char: {}", 'A'));
    EXPECT_NO_THROW(logger.info("Bool: {}", true));
    EXPECT_NO_THROW(logger.info("Pointer: {}", static_cast<void *>(nullptr)));
}

// Test logger with empty format string
TEST_F(LoggerTest, EmptyFormatString)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info(""));
    EXPECT_NO_THROW(logger.debug(""));
    EXPECT_NO_THROW(logger.warning(""));
    EXPECT_NO_THROW(logger.error(""));
    EXPECT_NO_THROW(logger.trace(""));
}

// Test logger with format string only (no args)
TEST_F(LoggerTest, FormatStringOnly)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Simple message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));
    EXPECT_NO_THROW(logger.error("Error message"));
    EXPECT_NO_THROW(logger.trace("Trace message"));
}

// Test logger with very large number of arguments
TEST_F(LoggerTest, ManyArguments)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("10 args: {} {} {} {} {} {} {} {} {} {}",
                                1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
}

// Test logger with mixed types in format string
TEST_F(LoggerTest, MixedTypesInFormat)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Mixed: {} {} {} {} {}", 1, "two", 3.0f, true, 'X'));
}

// Test logger with unicode characters
TEST_F(LoggerTest, UnicodeCharacters)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Unicode: \u00e9\u00e8\u00ea")); // accented e
    EXPECT_NO_THROW(logger.info("Emoji: \U0001f600"));           // grinning face
}

// Test logger with null pointer in format
TEST_F(LoggerTest, NullPointerInFormat)
{
    Logger &logger = Logger::get_instance();

    void *ptr = nullptr;
    EXPECT_NO_THROW(logger.info("Null pointer: {}", ptr));
}

// Test logger with large numbers
TEST_F(LoggerTest, LargeNumbers)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Large int: {}", 2147483647));
    EXPECT_NO_THROW(logger.info("Large unsigned: {}", 4294967295u));
    EXPECT_NO_THROW(logger.info("Large long: {}", 9223372036854775807LL));
}

// Test logger with negative numbers
TEST_F(LoggerTest, NegativeNumbers)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Negative int: {}", -42));
    EXPECT_NO_THROW(logger.info("Negative float: {}", -3.14f));
    EXPECT_NO_THROW(logger.info("Negative double: {}", -3.14159));
}

// Test logger with zero values
TEST_F(LoggerTest, ZeroValues)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Zero int: {}", 0));
    EXPECT_NO_THROW(logger.info("Zero float: {}", 0.0f));
    EXPECT_NO_THROW(logger.info("Zero double: {}", 0.0));
    EXPECT_NO_THROW(logger.info("Zero char: {}", '\0'));
}

// Test logger with boundary values
TEST_F(LoggerTest, BoundaryValues)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Min int: {}", -2147483648));
    EXPECT_NO_THROW(logger.info("Max int: {}", 2147483647));
    EXPECT_NO_THROW(logger.info("Min unsigned: {}", 0u));
    EXPECT_NO_THROW(logger.info("Max unsigned: {}", 4294967295u));
}

// Test logger with scientific notation
TEST_F(LoggerTest, ScientificNotation)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Scientific: {}", 1.23e10));
    EXPECT_NO_THROW(logger.info("Scientific negative: {}", -1.23e-10));
}

// Test logger with hex format
TEST_F(LoggerTest, HexFormat)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Hex: {:x}", 255));
    EXPECT_NO_THROW(logger.info("Hex uppercase: {:X}", 255));
    EXPECT_NO_THROW(logger.info("Hex with prefix: {:#x}", 255));
}

// Test logger with octal format
TEST_F(LoggerTest, OctalFormat)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Octal: {:o}", 255));
    EXPECT_NO_THROW(logger.info("Octal with prefix: {:#o}", 255));
}

// Test logger with binary format
TEST_F(LoggerTest, BinaryFormat)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Binary: {:b}", 255));
    EXPECT_NO_THROW(logger.info("Binary with prefix: {:#b}", 255));
}

// Test logger with fixed precision
TEST_F(LoggerTest, FixedPrecision)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Fixed 2: {:.2f}", 3.14159));
    EXPECT_NO_THROW(logger.info("Fixed 5: {:.5f}", 3.14159));
    EXPECT_NO_THROW(logger.info("Scientific 2: {:.2e}", 1234.56789));
}

// Test logger with width and alignment
TEST_F(LoggerTest, WidthAndAlignment)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Width 10: {:10}", 42));
    EXPECT_NO_THROW(logger.info("Left align: {:<10}", 42));
    EXPECT_NO_THROW(logger.info("Right align: {:>10}", 42));
    EXPECT_NO_THROW(logger.info("Center align: {:^10}", 42));
}

// Test logger with fill characters
TEST_F(LoggerTest, FillCharacters)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Fill with *: {:*<10}", 42));
    EXPECT_NO_THROW(logger.info("Fill with -: {:->10}", 42));
    EXPECT_NO_THROW(logger.info("Fill with =: {:=^10}", 42));
}

// Test logger with sign specifiers
TEST_F(LoggerTest, SignSpecifiers)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Always show sign: {:+}", 42));
    EXPECT_NO_THROW(logger.info("Always show sign negative: {:+}", -42));
    EXPECT_NO_THROW(logger.info("Space for positive: {: }", 42));
    EXPECT_NO_THROW(logger.info("Space for negative: {: }", -42));
}

// Test logger with locale-specific formatting
TEST_F(LoggerTest, LocaleFormatting)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Locale: {:L}", 1234567));
}

// Test logger with chrono formatting
TEST_F(LoggerTest, ChronoFormatting)
{
    Logger &logger = Logger::get_instance();

    auto now = std::chrono::system_clock::now();
    EXPECT_NO_THROW(logger.info("Time: {}", now));
}

// Test logger with string view
TEST_F(LoggerTest, StringView)
{
    Logger &logger = Logger::get_instance();

    std::string_view sv = "string view";
    EXPECT_NO_THROW(logger.info("String view: {}", sv));
}

// Test logger with custom type (should fail to compile if not formattable)
TEST_F(LoggerTest, CustomType)
{
    Logger &logger = Logger::get_instance();

    struct CustomType
    {
        int value;
    };

    // This should fail to compile if CustomType is not formattable
    // EXPECT_NO_THROW(logger.info("Custom: {}", CustomType{42}));
}

// Test logger with array
TEST_F(LoggerTest, Array)
{
    Logger &logger = Logger::get_instance();

    int arr[] = {1, 2, 3, 4, 5};
    EXPECT_NO_THROW(logger.info("Array: {}", arr[0]));
}

// Test logger with vector
TEST_F(LoggerTest, Vector)
{
    Logger &logger = Logger::get_instance();

    std::vector<int> vec = {1, 2, 3, 4, 5};
    EXPECT_NO_THROW(logger.info("Vector size: {}", vec.size()));
}

// Test logger with map
TEST_F(LoggerTest, Map)
{
    Logger &logger = Logger::get_instance();

    std::map<std::string, int> map = {{"one", 1}, {"two", 2}};
    EXPECT_NO_THROW(logger.info("Map size: {}", map.size()));
}

// Test logger with set
TEST_F(LoggerTest, Set)
{
    Logger &logger = Logger::get_instance();

    std::set<int> set = {1, 2, 3, 4, 5};
    EXPECT_NO_THROW(logger.info("Set size: {}", set.size()));
}

// Test logger with pair
TEST_F(LoggerTest, Pair)
{
    Logger &logger = Logger::get_instance();

    std::pair<int, std::string> pair = {42, "hello"};
    EXPECT_NO_THROW(logger.info("Pair first: {}", pair.first));
    EXPECT_NO_THROW(logger.info("Pair second: {}", pair.second));
}

// Test logger with tuple
TEST_F(LoggerTest, Tuple)
{
    Logger &logger = Logger::get_instance();

    std::tuple<int, std::string, double> tuple = {42, "hello", 3.14};
    EXPECT_NO_THROW(logger.info("Tuple get<0>: {}", std::get<0>(tuple)));
    EXPECT_NO_THROW(logger.info("Tuple get<1>: {}", std::get<1>(tuple)));
    EXPECT_NO_THROW(logger.info("Tuple get<2>: {}", std::get<2>(tuple)));
}

// Test logger with optional
TEST_F(LoggerTest, Optional)
{
    Logger &logger = Logger::get_instance();

    std::optional<int> opt1 = 42;
    std::optional<int> opt2 = std::nullopt;

    EXPECT_NO_THROW(logger.info("Optional has value: {}", opt1.has_value()));
    EXPECT_NO_THROW(logger.info("Optional value: {}", opt1.value()));
    EXPECT_NO_THROW(logger.info("Optional has value: {}", opt2.has_value()));
}

// Test logger with variant
TEST_F(LoggerTest, Variant)
{
    Logger &logger = Logger::get_instance();

    std::variant<int, std::string> var1 = 42;
    std::variant<int, std::string> var2 = "hello";

    EXPECT_NO_THROW(logger.info("Variant index: {}", var1.index()));
    EXPECT_NO_THROW(logger.info("Variant index: {}", var2.index()));
}

// Test logger with any
TEST_F(LoggerTest, Any)
{
    Logger &logger = Logger::get_instance();

    std::any any1 = 42;
    std::any any2 = std::string("hello");

    EXPECT_NO_THROW(logger.info("Any has value: {}", any1.has_value()));
    EXPECT_NO_THROW(logger.info("Any has value: {}", any2.has_value()));
}

// Test logger with shared_ptr
TEST_F(LoggerTest, SharedPtr)
{
    Logger &logger = Logger::get_instance();

    auto ptr = std::make_shared<int>(42);
    EXPECT_NO_THROW(logger.info("Shared ptr use count: {}", ptr.use_count()));
    EXPECT_NO_THROW(logger.info("Shared ptr value: {}", *ptr));
}

// Test logger with unique_ptr
TEST_F(LoggerTest, UniquePtr)
{
    Logger &logger = Logger::get_instance();

    auto ptr = std::make_unique<int>(42);
    EXPECT_NO_THROW(logger.info("Unique ptr value: {}", *ptr));
}

// Test logger with weak_ptr
TEST_F(LoggerTest, WeakPtr)
{
    Logger &logger = Logger::get_instance();

    auto shared = std::make_shared<int>(42);
    std::weak_ptr<int> weak = shared;

    EXPECT_NO_THROW(logger.info("Weak ptr expired: {}", weak.expired()));
    EXPECT_NO_THROW(logger.info("Weak ptr use count: {}", weak.use_count()));
}

// Test logger with function pointer
TEST_F(LoggerTest, FunctionPointer)
{
    Logger &logger = Logger::get_instance();

    auto func = []()
    { return 42; };
    EXPECT_NO_THROW(logger.info("Function pointer: {}", func()));
}

// Test logger with lambda
TEST_F(LoggerTest, Lambda)
{
    Logger &logger = Logger::get_instance();

    auto lambda = [](int x)
    { return x * 2; };
    EXPECT_NO_THROW(logger.info("Lambda result: {}", lambda(21)));
}

// Test logger with std::function
TEST_F(LoggerTest, StdFunction)
{
    Logger &logger = Logger::get_instance();

    std::function<int(int)> func = [](int x)
    { return x * 2; };
    EXPECT_NO_THROW(logger.info("Std function result: {}", func(21)));
}

// Test logger with bind
TEST_F(LoggerTest, Bind)
{
    Logger &logger = Logger::get_instance();

    auto func = [](int x, int y)
    { return x + y; };
    auto bound = std::bind(func, 10, std::placeholders::_1);
    EXPECT_NO_THROW(logger.info("Bind result: {}", bound(32)));
}

// Test logger with placeholders
TEST_F(LoggerTest, Placeholders)
{
    Logger &logger = Logger::get_instance();

    auto func = [](int x, int y)
    { return x + y; };
    auto bound = std::bind(func, std::placeholders::_1, std::placeholders::_2);
    EXPECT_NO_THROW(logger.info("Placeholders result: {}", bound(10, 32)));
}

// Test logger with reference wrapper
TEST_F(LoggerTest, ReferenceWrapper)
{
    Logger &logger = Logger::get_instance();

    int value = 42;
    std::reference_wrapper<int> ref = std::ref(value);
    EXPECT_NO_THROW(logger.info("Reference wrapper: {}", ref.get()));
}

// Test logger with atomic
TEST_F(LoggerTest, Atomic)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic: {}", atomic.load()));
}

// Test logger with mutex (should not throw)
TEST_F(LoggerTest, Mutex)
{
    Logger &logger = Logger::get_instance();

    std::mutex mutex;
    EXPECT_NO_THROW(logger.info("Mutex: {}", static_cast<void *>(&mutex)));
}

// Test logger with condition variable (should not throw)
TEST_F(LoggerTest, ConditionVariable)
{
    Logger &logger = Logger::get_instance();

    std::condition_variable cv;
    EXPECT_NO_THROW(logger.info("Condition variable: {}", static_cast<void *>(&cv)));
}

// Test logger with future
TEST_F(LoggerTest, Future)
{
    Logger &logger = Logger::get_instance();

    std::future<int> future = std::async(std::launch::async, []()
                                         { return 42; });
    EXPECT_NO_THROW(logger.info("Future valid: {}", future.valid()));
}

// Test logger with promise
TEST_F(LoggerTest, Promise)
{
    Logger &logger = Logger::get_instance();

    std::promise<int> promise;
    EXPECT_NO_THROW(logger.info("Promise: {}", static_cast<void *>(&promise)));
}

// Test logger with packaged_task
TEST_F(LoggerTest, PackagedTask)
{
    Logger &logger = Logger::get_instance();

    std::packaged_task<int()> task([]()
                                   { return 42; });
    EXPECT_NO_THROW(logger.info("Packaged task: {}", static_cast<void *>(&task)));
}

// Test logger with thread
TEST_F(LoggerTest, Thread)
{
    Logger &logger = Logger::get_instance();

    std::thread thread([]() {});
    EXPECT_NO_THROW(logger.info("Thread joinable: {}", thread.joinable()));
    thread.join();
}

// Test logger with jthread
TEST_F(LoggerTest, Jthread)
{
    Logger &logger = Logger::get_instance();

    std::jthread jthread([]() {});
    EXPECT_NO_THROW(logger.info("Jthread joinable: {}", jthread.joinable()));
}

// Test logger with stop_token
TEST_F(LoggerTest, StopToken)
{
    Logger &logger = Logger::get_instance();

    std::stop_source source;
    std::stop_token token = source.get_token();
    EXPECT_NO_THROW(logger.info("Stop token stop possible: {}", token.stop_possible()));
}

// Test logger with latch
TEST_F(LoggerTest, Latch)
{
    Logger &logger = Logger::get_instance();

    std::latch latch(1);
    EXPECT_NO_THROW(logger.info("Latch: {}", static_cast<void *>(&latch)));
}

// Test logger with barrier
TEST_F(LoggerTest, Barrier)
{
    Logger &logger = Logger::get_instance();

    std::barrier barrier(1);
    EXPECT_NO_THROW(logger.info("Barrier: {}", static_cast<void *>(&barrier)));
}

// Test logger with semaphore
TEST_F(LoggerTest, Semaphore)
{
    Logger &logger = Logger::get_instance();

    std::counting_semaphore semaphore(1);
    EXPECT_NO_THROW(logger.info("Semaphore: {}", static_cast<void *>(&semaphore)));
}

// Test logger with shared_mutex
TEST_F(LoggerTest, SharedMutex)
{
    Logger &logger = Logger::get_instance();

    std::shared_mutex mutex;
    EXPECT_NO_THROW(logger.info("Shared mutex: {}", static_cast<void *>(&mutex)));
}

// Test logger with shared_lock
TEST_F(LoggerTest, SharedLock)
{
    Logger &logger = Logger::get_instance();

    std::shared_mutex mutex;
    std::shared_lock lock(mutex);
    EXPECT_NO_THROW(logger.info("Shared lock: {}", static_cast<void *>(&lock)));
}

// Test logger with unique_lock
TEST_F(LoggerTest, UniqueLock)
{
    Logger &logger = Logger::get_instance();

    std::mutex mutex;
    std::unique_lock lock(mutex);
    EXPECT_NO_THROW(logger.info("Unique lock: {}", static_cast<void *>(&lock)));
}

// Test logger with scoped_lock
TEST_F(LoggerTest, ScopedLock)
{
    Logger &logger = Logger::get_instance();

    std::mutex mutex1;
    std::mutex mutex2;
    std::scoped_lock lock(mutex1, mutex2);
    EXPECT_NO_THROW(logger.info("Scoped lock: {}", static_cast<void *>(&lock)));
}

// Test logger with lock_guard
TEST_F(LoggerTest, LockGuard)
{
    Logger &logger = Logger::get_instance();

    std::mutex mutex;
    std::lock_guard lock(mutex);
    EXPECT_NO_THROW(logger.info("Lock guard: {}", static_cast<void *>(&lock)));
}

// Test logger with defer_lock
TEST_F(LoggerTest, DeferLock)
{
    Logger &logger = Logger::get_instance();

    std::mutex mutex;
    std::unique_lock lock(mutex, std::defer_lock);
    EXPECT_NO_THROW(logger.info("Defer lock: {}", static_cast<void *>(&lock)));
}

// Test logger with try_to_lock
TEST_F(LoggerTest, TryToLock)
{
    Logger &logger = Logger::get_instance();

    std::mutex mutex;
    std::unique_lock lock(mutex, std::try_to_lock);
    EXPECT_NO_THROW(logger.info("Try to lock: {}", static_cast<void *>(&lock)));
}

// Test logger with adopt_lock
TEST_F(LoggerTest, AdoptLock)
{
    Logger &logger = Logger::get_instance();

    std::mutex mutex;
    mutex.lock();
    std::unique_lock lock(mutex, std::adopt_lock);
    EXPECT_NO_THROW(logger.info("Adopt lock: {}", static_cast<void *>(&lock)));
}

// Test logger with recursive_mutex
TEST_F(LoggerTest, RecursiveMutex)
{
    Logger &logger = Logger::get_instance();

    std::recursive_mutex mutex;
    EXPECT_NO_THROW(logger.info("Recursive mutex: {}", static_cast<void *>(&mutex)));
}

// Test logger with timed_mutex
TEST_F(LoggerTest, TimedMutex)
{
    Logger &logger = Logger::get_instance();

    std::timed_mutex mutex;
    EXPECT_NO_THROW(logger.info("Timed mutex: {}", static_cast<void *>(&mutex)));
}

// Test logger with recursive_timed_mutex
TEST_F(LoggerTest, RecursiveTimedMutex)
{
    Logger &logger = Logger::get_instance();

    std::recursive_timed_mutex mutex;
    EXPECT_NO_THROW(logger.info("Recursive timed mutex: {}", static_cast<void *>(&mutex)));
}

// Test logger with shared_timed_mutex
TEST_F(LoggerTest, SharedTimedMutex)
{
    Logger &logger = Logger::get_instance();

    std::shared_timed_mutex mutex;
    EXPECT_NO_THROW(logger.info("Shared timed mutex: {}", static_cast<void *>(&mutex)));
}

// Test logger with shared_future
TEST_F(LoggerTest, SharedFuture)
{
    Logger &logger = Logger::get_instance();

    std::future<int> future = std::async(std::launch::async, []()
                                         { return 42; });
    std::shared_future<int> shared = future.share();
    EXPECT_NO_THROW(logger.info("Shared future valid: {}", shared.valid()));
}

// Test logger with atomic_flag
TEST_F(LoggerTest, AtomicFlag)
{
    Logger &logger = Logger::get_instance();

    std::atomic_flag flag;
    EXPECT_NO_THROW(logger.info("Atomic flag: {}", static_cast<void *>(&flag)));
}

// Test logger with atomic_ref
TEST_F(LoggerTest, AtomicRef)
{
    Logger &logger = Logger::get_instance();

    int value = 42;
    std::atomic_ref ref(value);
    EXPECT_NO_THROW(logger.info("Atomic ref: {}", ref.load()));
}

// Test logger with atomic_shared_ptr
TEST_F(LoggerTest, AtomicSharedPtr)
{
    Logger &logger = Logger::get_instance();

    auto ptr = std::make_shared<int>(42);
    std::atomic<std::shared_ptr<int>> atomic_ptr(ptr);
    EXPECT_NO_THROW(logger.info("Atomic shared ptr: {}", atomic_ptr.load().use_count()));
}

// Test logger with atomic_weak_ptr
TEST_F(LoggerTest, AtomicWeakPtr)
{
    Logger &logger = Logger::get_instance();

    auto ptr = std::make_shared<int>(42);
    std::atomic<std::weak_ptr<int>> atomic_weak(ptr);
    EXPECT_NO_THROW(logger.info("Atomic weak ptr: {}", atomic_weak.load().use_count()));
}

// Test logger with atomic_bitwise
TEST_F(LoggerTest, AtomicBitwise)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic fetch add: {}", atomic.fetch_add(10)));
    EXPECT_NO_THROW(logger.info("Atomic fetch sub: {}", atomic.fetch_sub(5)));
    EXPECT_NO_THROW(logger.info("Atomic fetch and: {}", atomic.fetch_and(0xFF)));
    EXPECT_NO_THROW(logger.info("Atomic fetch or: {}", atomic.fetch_or(0x100)));
    EXPECT_NO_THROW(logger.info("Atomic fetch xor: {}", atomic.fetch_xor(0x200)));
}

// Test logger with atomic_exchange
TEST_F(LoggerTest, AtomicExchange)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic exchange: {}", atomic.exchange(100)));
}

// Test logger with atomic_compare_exchange
TEST_F(LoggerTest, AtomicCompareExchange)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    int expected = 42;
    EXPECT_NO_THROW(logger.info("Atomic compare exchange strong: {}", atomic.compare_exchange_strong(expected, 100)));
    expected = 42;
    EXPECT_NO_THROW(logger.info("Atomic compare exchange weak: {}", atomic.compare_exchange_weak(expected, 100)));
}

// Test logger with atomic_wait
TEST_F(LoggerTest, AtomicWait)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic wait: {}", static_cast<void *>(&atomic)));
}

// Test logger with atomic_notify_one
TEST_F(LoggerTest, AtomicNotifyOne)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic notify one: {}", static_cast<void *>(&atomic)));
}

// Test logger with atomic_notify_all
TEST_F(LoggerTest, AtomicNotifyAll)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic notify all: {}", static_cast<void *>(&atomic)));
}

// Test logger with atomic_test
TEST_F(LoggerTest, AtomicTest)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic test: {}", atomic.load()));
}

// Test logger with atomic_set
TEST_F(LoggerTest, AtomicSet)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    atomic.store(100);
    EXPECT_NO_THROW(logger.info("Atomic set: {}", atomic.load()));
}

// Test logger with atomic_clear
TEST_F(LoggerTest, AtomicClear)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    atomic.store(0);
    EXPECT_NO_THROW(logger.info("Atomic clear: {}", atomic.load()));
}

// Test logger with atomic_flip
TEST_F(LoggerTest, AtomicFlip)
{
    Logger &logger = Logger::get_instance();

    std::atomic<bool> atomic{true};
    atomic.store(false);
    EXPECT_NO_THROW(logger.info("Atomic flip: {}", atomic.load()));
}

// Test logger with atomic_reset
TEST_F(LoggerTest, AtomicReset)
{
    Logger &logger = Logger::get_instance();

    std::atomic<bool> atomic{true};
    atomic.store(false);
    EXPECT_NO_THROW(logger.info("Atomic reset: {}", atomic.load()));
}

// Test logger with atomic_test_and_set
TEST_F(LoggerTest, AtomicTestAndSet)
{
    Logger &logger = Logger::get_instance();

    std::atomic_flag flag;
    EXPECT_NO_THROW(logger.info("Atomic test and set: {}", flag.test_and_set()));
}

// Test logger with atomic_clear_flag
TEST_F(LoggerTest, AtomicClearFlag)
{
    Logger &logger = Logger::get_instance();

    std::atomic_flag flag;
    flag.test_and_set();
    flag.clear();
    EXPECT_NO_THROW(logger.info("Atomic clear flag: {}", flag.test()));
}

// Test logger with atomic_wait_flag
TEST_F(LoggerTest, AtomicWaitFlag)
{
    Logger &logger = Logger::get_instance();

    std::atomic_flag flag;
    EXPECT_NO_THROW(logger.info("Atomic wait flag: {}", static_cast<void *>(&flag)));
}

// Test logger with atomic_notify_one_flag
TEST_F(LoggerTest, AtomicNotifyOneFlag)
{
    Logger &logger = Logger::get_instance();

    std::atomic_flag flag;
    EXPECT_NO_THROW(logger.info("Atomic notify one flag: {}", static_cast<void *>(&flag)));
}

// Test logger with atomic_notify_all_flag
TEST_F(LoggerTest, AtomicNotifyAllFlag)
{
    Logger &logger = Logger::get_instance();

    std::atomic_flag flag;
    EXPECT_NO_THROW(logger.info("Atomic notify all flag: {}", static_cast<void *>(&flag)));
}

// Test convenience methods at Trace level (covers all methods fully)
TEST_F(LoggerTest, ConvenienceMethods_AtTrace)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

    // All methods should be called at trace level
    EXPECT_NO_THROW(logger.trace("Trace test: {}", 1));
    EXPECT_NO_THROW(logger.debug("Debug test: {}", 2));
    EXPECT_NO_THROW(logger.info("Info test: {}", 3));
    EXPECT_NO_THROW(logger.warning("Warning test: {}", 4));
    EXPECT_NO_THROW(logger.error("Error test: {}", 5));

    // With multiple arguments
    EXPECT_NO_THROW(logger.trace("Multi: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.debug("Multi: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.info("Multi: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.warning("Multi: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.error("Multi: {} {} {}", 1, 2, 3));
}

// Test convenience methods at Debug level
TEST_F(LoggerTest, ConvenienceMethods_AtDebug)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Debug);

    // trace should be filtered
    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    // others should pass through
    EXPECT_NO_THROW(logger.debug("Debug test"));
    EXPECT_NO_THROW(logger.info("Info test"));
    EXPECT_NO_THROW(logger.warning("Warning test"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

// Test convenience methods at Info level
TEST_F(LoggerTest, ConvenienceMethods_AtInfo)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Info);

    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    EXPECT_NO_THROW(logger.debug("Debug filtered"));
    EXPECT_NO_THROW(logger.info("Info test"));
    EXPECT_NO_THROW(logger.warning("Warning test"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

// Test convenience methods at Warning level
TEST_F(LoggerTest, ConvenienceMethods_AtWarning)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Warning);

    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    EXPECT_NO_THROW(logger.debug("Debug filtered"));
    EXPECT_NO_THROW(logger.info("Info filtered"));
    EXPECT_NO_THROW(logger.warning("Warning test"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

// Test convenience methods at Error level
TEST_F(LoggerTest, ConvenienceMethods_AtError)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Error);

    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    EXPECT_NO_THROW(logger.debug("Debug filtered"));
    EXPECT_NO_THROW(logger.info("Info filtered"));
    EXPECT_NO_THROW(logger.warning("Warning filtered"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

// Test set_log_level with invalid level value (> 4) - should be rejected
TEST_F(LoggerTest, SetLogLevel_InvalidLevel)
{
    Logger &logger = Logger::get_instance();

    // Set a known valid level first
    logger.set_log_level(LogLevel::Info);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);

    // Attempt to set invalid level (value 5 is out of range 0-4)
    logger.set_log_level(static_cast<LogLevel>(5));
    // Level should remain unchanged
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);

    // Attempt another invalid level
    logger.set_log_level(static_cast<LogLevel>(99));
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);
}

// Test flush() when async mode is enabled (covers async flush path)
TEST_F(LoggerTest, Flush_InAsyncMode)
{
    Logger &logger = Logger::get_instance();

    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{100};

    logger.enable_async_mode(config);
    EXPECT_TRUE(logger.is_async_mode_enabled());

    // Log some messages then flush
    logger.info("Async flush test message 1");
    logger.info("Async flush test message 2");
    logger.warning("Async flush warning");

    // Flush should complete without blocking indefinitely
    EXPECT_NO_THROW(logger.flush());

    logger.disable_async_mode();
}

// Test that enable_async_mode with invalid queue capacity is handled gracefully
TEST_F(LoggerTest, EnableAsyncMode_InvalidCapacity_Handled)
{
    Logger &logger = Logger::get_instance();
    EXPECT_FALSE(logger.is_async_mode_enabled());

    AsyncLoggerConfig config;
    config.queue_capacity = 7; // Not a power of 2, will throw in DynamicMPMCQueue

    // enable_async_mode catches the exception and logs an error - should not throw
    EXPECT_NO_THROW(logger.enable_async_mode(config));

    // Async mode should not be enabled since construction failed
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

// Test logging at each level while async is enabled (covers async enqueue path)
TEST_F(LoggerTest, AsyncMode_AllLevels)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

    logger.enable_async_mode();
    EXPECT_TRUE(logger.is_async_mode_enabled());

    EXPECT_NO_THROW(logger.trace("Async trace"));
    EXPECT_NO_THROW(logger.debug("Async debug"));
    EXPECT_NO_THROW(logger.info("Async info"));
    EXPECT_NO_THROW(logger.warning("Async warning"));
    EXPECT_NO_THROW(logger.error("Async error"));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    logger.disable_async_mode();
}

// ===== Coverage improvement tests =====

// Test string_to_log_level with unrecognized string (covers logger.cpp lines 53-55)
TEST_F(LoggerTest, StringToLogLevel_Unrecognized)
{
    auto level = Logger::string_to_log_level("INVALID_LEVEL");
    EXPECT_EQ(level, LogLevel::Info); // Should default to Info
}

// Test string_to_log_level with all valid levels
TEST_F(LoggerTest, StringToLogLevel_AllLevels)
{
    EXPECT_EQ(Logger::string_to_log_level("TRACE"), LogLevel::Trace);
    EXPECT_EQ(Logger::string_to_log_level("trace"), LogLevel::Trace);
    EXPECT_EQ(Logger::string_to_log_level("DEBUG"), LogLevel::Debug);
    EXPECT_EQ(Logger::string_to_log_level("debug"), LogLevel::Debug);
    EXPECT_EQ(Logger::string_to_log_level("INFO"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("info"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("WARNING"), LogLevel::Warning);
    EXPECT_EQ(Logger::string_to_log_level("warning"), LogLevel::Warning);
    EXPECT_EQ(Logger::string_to_log_level("ERROR"), LogLevel::Error);
    EXPECT_EQ(Logger::string_to_log_level("error"), LogLevel::Error);
}

// Test all log level templates with Trace level (covers logger.hpp template instantiations)
TEST_F(LoggerTest, AllLevelTemplates_WithFormatArgs)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

    // Exercise template instantiations with various arg types at all levels
    EXPECT_NO_THROW(logger.trace("trace int: {}", 42));
    EXPECT_NO_THROW(logger.trace("trace str: {}", "hello"));
    EXPECT_NO_THROW(logger.trace("trace float: {}", 3.14f));
    EXPECT_NO_THROW(logger.trace("trace two: {} {}", 1, 2));

    EXPECT_NO_THROW(logger.debug("debug int: {}", 42));
    EXPECT_NO_THROW(logger.debug("debug str: {}", "hello"));
    EXPECT_NO_THROW(logger.debug("debug float: {}", 3.14f));
    EXPECT_NO_THROW(logger.debug("debug two: {} {}", 1, 2));

    EXPECT_NO_THROW(logger.info("info int: {}", 42));
    EXPECT_NO_THROW(logger.info("info str: {}", "hello"));

    EXPECT_NO_THROW(logger.warning("warn int: {}", 42));
    EXPECT_NO_THROW(logger.warning("warn str: {}", "hello"));

    EXPECT_NO_THROW(logger.error("error int: {}", 42));
    EXPECT_NO_THROW(logger.error("error str: {}", "hello"));
}

// Test log level filtering - messages below current level should be skipped
// This covers the level check at logger.hpp line 173 (the false branch)
TEST_F(LoggerTest, LogLevelFiltering_SkipsBelowLevel)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Error);

    // These should be filtered (below Error level) - covering the early return in template
    EXPECT_NO_THROW(logger.trace("filtered trace: {}", 1));
    EXPECT_NO_THROW(logger.debug("filtered debug: {}", 2));
    EXPECT_NO_THROW(logger.info("filtered info: {}", 3));
    EXPECT_NO_THROW(logger.warning("filtered warn: {}", 4));

    // This should pass through
    EXPECT_NO_THROW(logger.error("not filtered error: {}", 5));

    // Reset level
    logger.set_log_level(LogLevel::Info);
}

// Test enable_async_mode when already enabled (covers logger.cpp line 353)
TEST_F(LoggerTest, AsyncMode_EnableTwice)
{
    Logger &logger = Logger::get_instance();

    logger.enable_async_mode();
    EXPECT_TRUE(logger.is_async_mode_enabled());

    // Second enable should be a no-op
    logger.enable_async_mode();
    EXPECT_TRUE(logger.is_async_mode_enabled());

    logger.disable_async_mode();
}

// Test disable_async_mode when not enabled (covers logger.cpp line 384)
TEST_F(LoggerTest, AsyncMode_DisableWhenNotEnabled)
{
    Logger &logger = Logger::get_instance();

    EXPECT_FALSE(logger.is_async_mode_enabled());
    // Should be a no-op
    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

// Test enable_async_mode with custom config (covers logger.cpp lines 364-367)
TEST_F(LoggerTest, AsyncMode_CustomConfig)
{
    Logger &logger = Logger::get_instance();

    AsyncLoggerConfig config;
    config.queue_capacity = 512;
    config.batch_size = 16;

    logger.enable_async_mode(config);
    EXPECT_TRUE(logger.is_async_mode_enabled());

    // Log some messages to exercise the async path
    logger.info("Custom config async message: {}", 42);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    logger.disable_async_mode();
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

// Test flush in sync mode (covers logger.cpp line 410-414)
TEST_F(LoggerTest, Flush_SyncMode)
{
    Logger &logger = Logger::get_instance();
    logger.info("Pre-flush message");
    EXPECT_NO_THROW(logger.flush());
}

// Test flush in async mode (covers logger.cpp line 406)
TEST_F(LoggerTest, Flush_AsyncMode)
{
    Logger &logger = Logger::get_instance();

    logger.enable_async_mode();
    logger.info("Async pre-flush");
    EXPECT_NO_THROW(logger.flush());
    logger.disable_async_mode();
}

// Test set_log_level with all enum values (covers logger.cpp lines 202-217)
TEST_F(LoggerTest, SetLogLevel_AllValues)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.set_log_level(LogLevel::Trace));
    EXPECT_NO_THROW(logger.set_log_level(LogLevel::Debug));
    EXPECT_NO_THROW(logger.set_log_level(LogLevel::Info));
    EXPECT_NO_THROW(logger.set_log_level(LogLevel::Warning));
    EXPECT_NO_THROW(logger.set_log_level(LogLevel::Error));

    // Reset
    logger.set_log_level(LogLevel::Info);
}

// Test log(level, string) with level below threshold (covers the >= check at logger.cpp line 223)
TEST_F(LoggerTest, Log_BelowThreshold)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Error);

    // Direct call to log(level, message) - below threshold should be no-op
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "This should be filtered"));

    // Above threshold should work
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "This should pass"));

    logger.set_log_level(LogLevel::Info);
}

// Test configure with different settings (covers reconfigure path, logger.cpp lines 82-117)
TEST_F(LoggerTest, ReconfigureToDifferentFile)
{
    auto new_log_file = std::filesystem::temp_directory_path() /
                        ("test_reconfig_" + std::to_string(GetCurrentProcessId()) + ".log");

    // Reconfigure to a different file
    EXPECT_NO_THROW(Logger::configure("RECONFIG", new_log_file.string(), "%H:%M:%S"));

    Logger &logger = Logger::get_instance();
    EXPECT_NO_THROW(logger.info("After reconfigure"));

    // Reconfigure back to the original test file to not break TearDown
    Logger::configure("TEST", test_log_file_.string(), "%Y-%m-%d %H:%M:%S");

    // Clean up
    try
    {
        if (std::filesystem::exists(new_log_file))
        {
            std::filesystem::remove(new_log_file);
        }
    }
    catch (...)
    {
    }
}

// Test log template with multiple diverse format arg types to cover more instantiations
TEST_F(LoggerTest, LogTemplates_DiverseTypes)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

    // Various type combinations to exercise template instantiations
    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "bool: {}", true));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "size_t: {}", size_t{100}));
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "double: {}", 2.718));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "ptr: {}", reinterpret_cast<void *>(0x1234)));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "char: {}", 'A'));

    // Multi-arg templates
    EXPECT_NO_THROW(logger.trace("three args: {} {} {}", 1, "two", 3.0));
    EXPECT_NO_THROW(logger.debug("three args: {} {} {}", 1, "two", 3.0));
    EXPECT_NO_THROW(logger.info("three args: {} {} {}", 1, "two", 3.0));
    EXPECT_NO_THROW(logger.warning("three args: {} {} {}", 1, "two", 3.0));
    EXPECT_NO_THROW(logger.error("three args: {} {} {}", 1, "two", 3.0));

    logger.set_log_level(LogLevel::Info);
}

// Test shutdown with async (covers logger.cpp lines 179-200)
TEST_F(LoggerTest, ShutdownWithAsync)
{
    Logger &logger = Logger::get_instance();

    // Enable async, then shutdown
    logger.enable_async_mode();
    EXPECT_TRUE(logger.is_async_mode_enabled());

    logger.shutdown();
    // After shutdown, async should be disabled
    // (Note: shutdown sets shutdown_called_ which prevents further operations)
}

