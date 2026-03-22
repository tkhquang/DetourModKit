#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <windows.h>
#include <atomic>

#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger.hpp"

using namespace DetourModKit;

class LoggerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static int test_counter = 0;
        test_log_file_ = std::filesystem::temp_directory_path() /
                         ("test_logger_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(test_counter++) + ".log");
        Logger::configure("TEST", test_log_file_.string(), "%Y-%m-%d %H:%M:%S");
    }

    void TearDown() override
    {
        auto temp_file = std::filesystem::temp_directory_path() / "test_logger_temp.log";
        Logger::configure("TEMP", temp_file.string(), "%Y-%m-%d %H:%M:%S");

        try
        {
            if (std::filesystem::exists(test_log_file_))
            {
                std::filesystem::remove(test_log_file_);
            }
        }
        catch (const std::filesystem::filesystem_error &)
        {
        }

        try
        {
            if (std::filesystem::exists(temp_file))
            {
                std::filesystem::remove(temp_file);
            }
        }
        catch (const std::filesystem::filesystem_error &)
        {
        }
    }

    std::filesystem::path test_log_file_;
};

TEST_F(LoggerTest, LogLevelToString)
{
    EXPECT_EQ(log_level_to_string(LogLevel::Trace), "TRACE");
    EXPECT_EQ(log_level_to_string(LogLevel::Debug), "DEBUG");
    EXPECT_EQ(log_level_to_string(LogLevel::Info), "INFO");
    EXPECT_EQ(log_level_to_string(LogLevel::Warning), "WARNING");
    EXPECT_EQ(log_level_to_string(LogLevel::Error), "ERROR");
}

TEST_F(LoggerTest, StringToLogLevel)
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

    EXPECT_EQ(Logger::string_to_log_level("INVALID"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level(""), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("XYZ"), LogLevel::Info);
}

TEST(LoggerSingleton, GetInstance)
{
    Logger &instance1 = Logger::get_instance();
    Logger &instance2 = Logger::get_instance();
    EXPECT_EQ(&instance1, &instance2);
}

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

TEST_F(LoggerTest, BasicLogging)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test info message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test debug message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Test warning message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Test error message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Test trace message"));
}

TEST_F(LoggerTest, FormattedLogging)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test value: {}", 42));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test string: {}", std::string("hello")));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Multiple: {} and {}", 1, 2.5));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Mixed: {} {} {}", 1, "two", 3.0f));
}

TEST_F(LoggerTest, ConvenienceMethods)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));
    EXPECT_NO_THROW(logger.error("Error message"));

    EXPECT_NO_THROW(logger.trace("Trace: {}", 1));
    EXPECT_NO_THROW(logger.debug("Debug: {}", 2));
    EXPECT_NO_THROW(logger.info("Info: {}", 3));
    EXPECT_NO_THROW(logger.warning("Warning: {}", 4));
    EXPECT_NO_THROW(logger.error("Error: {}", 5));
}

TEST_F(LoggerTest, LogLevelFiltering)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Warning);

    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Should not appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Should not appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Should not appear"));

    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Should appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Should appear"));
}

TEST_F(LoggerTest, Flush)
{
    Logger &logger = Logger::get_instance();
    EXPECT_NO_THROW(logger.flush());
}

TEST_F(LoggerTest, AsyncMode)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.enable_async_mode());
    EXPECT_TRUE(logger.is_async_mode_enabled());

    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

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

TEST_F(LoggerTest, AsyncModeLogging)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.enable_async_mode());
    EXPECT_TRUE(logger.is_async_mode_enabled());

    EXPECT_NO_THROW(logger.info("Async message 1"));
    EXPECT_NO_THROW(logger.info("Async message 2"));
    EXPECT_NO_THROW(logger.debug("Async message 3"));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

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

    SUCCEED();
}

TEST_F(LoggerTest, Reconfigure)
{
    Logger &logger = Logger::get_instance();

    auto new_log_file = std::filesystem::temp_directory_path() /
                        ("test_logger_reconfig_" + std::to_string(GetCurrentProcessId()) + ".log");

    EXPECT_NO_THROW(logger.reconfigure("NEW_PREFIX", new_log_file.string(), "%H:%M:%S"));

    EXPECT_NO_THROW(logger.info("Message after reconfigure"));

    try
    {
        if (std::filesystem::exists(new_log_file))
        {
            std::filesystem::remove(new_log_file);
        }
    }
    catch (const std::filesystem::filesystem_error &)
    {
    }
}

TEST_F(LoggerTest, ConfigureStatic)
{
    auto config_log_file = std::filesystem::temp_directory_path() /
                           ("test_logger_configure_" + std::to_string(GetCurrentProcessId()) + ".log");

    EXPECT_NO_THROW(Logger::configure("CONFIG_PREFIX", config_log_file.string(), "%Y-%m-%d"));

    Logger &logger = Logger::get_instance();
    EXPECT_NO_THROW(logger.info("Message after static configure"));

    try
    {
        if (std::filesystem::exists(config_log_file))
        {
            std::filesystem::remove(config_log_file);
        }
    }
    catch (const std::filesystem::filesystem_error &)
    {
    }
}

TEST_F(LoggerTest, Shutdown)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.shutdown());

    EXPECT_NO_THROW(logger.shutdown());
}

TEST_F(LoggerTest, LoggingAfterShutdown)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.shutdown());

    EXPECT_NO_THROW(logger.info("Message after shutdown"));
}

TEST_F(LoggerTest, AsyncModeInvalidConfig)
{
    Logger &logger = Logger::get_instance();

    AsyncLoggerConfig config;
    config.queue_capacity = 100;

    EXPECT_NO_THROW(logger.enable_async_mode(config));

    EXPECT_NO_THROW(logger.disable_async_mode());
}

TEST_F(LoggerTest, LongMessages)
{
    Logger &logger = Logger::get_instance();

    std::string long_message(1000, 'X');
    EXPECT_NO_THROW(logger.info("{}", long_message));

    std::string very_long_message(5000, 'Y');
    EXPECT_NO_THROW(logger.info("{}", very_long_message));
}

TEST_F(LoggerTest, SpecialCharacters)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Special: !@#$%^&*()"));
    EXPECT_NO_THROW(logger.info("Unicode: \u00e9\u00e8\u00ea"));
    EXPECT_NO_THROW(logger.info("Newlines: \n\r\t"));
    EXPECT_NO_THROW(logger.info("Quotes: \"single\" and 'double'"));
    EXPECT_NO_THROW(logger.info("Braces: {{ and }}"));
}

TEST_F(LoggerTest, EmptyMessage)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info(""));
    EXPECT_NO_THROW(logger.debug(""));
    EXPECT_NO_THROW(logger.error(""));
}

TEST_F(LoggerTest, LogLevelFiltering_Formatted)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Warning);

    EXPECT_NO_THROW(logger.trace("Trace: {}", 1));
    EXPECT_NO_THROW(logger.debug("Debug: {}", 2));
    EXPECT_NO_THROW(logger.info("Info: {}", 3));

    EXPECT_NO_THROW(logger.warning("Warning: {}", 4));
    EXPECT_NO_THROW(logger.error("Error: {}", 5));
}

TEST_F(LoggerTest, LogLevelFiltering_Convenience)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Error);

    EXPECT_NO_THROW(logger.trace("Trace message"));
    EXPECT_NO_THROW(logger.debug("Debug message"));
    EXPECT_NO_THROW(logger.info("Info message"));
    EXPECT_NO_THROW(logger.warning("Warning message"));

    EXPECT_NO_THROW(logger.error("Error message"));
}

TEST_F(LoggerTest, LogLevelToString_Invalid)
{
    LogLevel invalid_level = static_cast<LogLevel>(99);
    EXPECT_EQ(log_level_to_string(invalid_level), "UNKNOWN");
}

TEST_F(LoggerTest, StringToLogLevel_VariousCases)
{
    EXPECT_EQ(Logger::string_to_log_level("Trace"), LogLevel::Trace);
    EXPECT_EQ(Logger::string_to_log_level("DEBUG"), LogLevel::Debug);
    EXPECT_EQ(Logger::string_to_log_level("Info"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("WARNING"), LogLevel::Warning);
    EXPECT_EQ(Logger::string_to_log_level("Error"), LogLevel::Error);

    EXPECT_EQ(Logger::string_to_log_level(" trace "), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("debug "), LogLevel::Info);

    EXPECT_EQ(Logger::string_to_log_level("123"), LogLevel::Info);
    EXPECT_EQ(Logger::string_to_log_level("0"), LogLevel::Info);
}

TEST_F(LoggerTest, LongFormatString)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("This is a very long format string with many placeholders: {} {} {} {} {} {} {} {} {} {}", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
}

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

TEST_F(LoggerTest, MultipleArguments)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("One arg: {}", 1));
    EXPECT_NO_THROW(logger.info("Two args: {} {}", 1, 2));
    EXPECT_NO_THROW(logger.info("Three args: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.info("Four args: {} {} {} {}", 1, 2, 3, 4));
    EXPECT_NO_THROW(logger.info("Five args: {} {} {} {} {}", 1, 2, 3, 4, 5));
}

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

TEST_F(LoggerTest, MixedTypesInFormat)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Mixed: {} {} {} {} {}", 1, "two", 3.0f, true, 'X'));
}

TEST_F(LoggerTest, UnicodeCharacters)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Unicode: \u00e9\u00e8\u00ea"));
    EXPECT_NO_THROW(logger.info("Emoji: \U0001f600"));
}

TEST_F(LoggerTest, NullPointerInFormat)
{
    Logger &logger = Logger::get_instance();

    void *ptr = nullptr;
    EXPECT_NO_THROW(logger.info("Null pointer: {}", ptr));
}

TEST_F(LoggerTest, FormatSpecifiers_BasicTypes)
{
    Logger &logger = Logger::get_instance();

    EXPECT_NO_THROW(logger.info("Large int: {}", 2147483647));
    EXPECT_NO_THROW(logger.info("Negative float: {}", -3.14f));
    EXPECT_NO_THROW(logger.info("Scientific: {}", 1.23e10));
    EXPECT_NO_THROW(logger.info("Hex: {:x}", 255));
    EXPECT_NO_THROW(logger.info("Fixed 2: {:.2f}", 3.14159));
    EXPECT_NO_THROW(logger.info("Width 10: {:10}", 42));
    EXPECT_NO_THROW(logger.info("Fill with *: {:*<10}", 42));
    EXPECT_NO_THROW(logger.info("Always show sign: {:+}", 42));
}

TEST_F(LoggerTest, FormatSpecifiers_Containers)
{
    Logger &logger = Logger::get_instance();

    std::vector<int> vec = {1, 2, 3, 4, 5};
    EXPECT_NO_THROW(logger.info("Vector size: {}", vec.size()));

    std::map<std::string, int> map = {{"one", 1}, {"two", 2}};
    EXPECT_NO_THROW(logger.info("Map size: {}", map.size()));

    std::set<int> set = {1, 2, 3, 4, 5};
    EXPECT_NO_THROW(logger.info("Set size: {}", set.size()));

    std::optional<int> opt1 = 42;
    std::optional<int> opt2 = std::nullopt;
    EXPECT_NO_THROW(logger.info("Optional value: {}", opt1.value()));
    EXPECT_NO_THROW(logger.info("Optional has value: {}", opt2.has_value()));
}

TEST_F(LoggerTest, FormatSpecifiers_SmartPointers)
{
    Logger &logger = Logger::get_instance();

    auto shared = std::make_shared<int>(42);
    EXPECT_NO_THROW(logger.info("Shared ptr value: {}", *shared));
    EXPECT_NO_THROW(logger.info("Shared ptr use count: {}", shared.use_count()));

    auto unique = std::make_unique<int>(42);
    EXPECT_NO_THROW(logger.info("Unique ptr value: {}", *unique));

    std::weak_ptr<int> weak = shared;
    EXPECT_NO_THROW(logger.info("Weak ptr expired: {}", weak.expired()));
}

TEST_F(LoggerTest, StringView)
{
    Logger &logger = Logger::get_instance();

    std::string_view sv = "string view";
    EXPECT_NO_THROW(logger.info("String view: {}", sv));
}

TEST_F(LoggerTest, Atomic)
{
    Logger &logger = Logger::get_instance();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic: {}", atomic.load()));
}

TEST_F(LoggerTest, ConvenienceMethods_AtTrace)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

    EXPECT_NO_THROW(logger.trace("Trace test: {}", 1));
    EXPECT_NO_THROW(logger.debug("Debug test: {}", 2));
    EXPECT_NO_THROW(logger.info("Info test: {}", 3));
    EXPECT_NO_THROW(logger.warning("Warning test: {}", 4));
    EXPECT_NO_THROW(logger.error("Error test: {}", 5));

    EXPECT_NO_THROW(logger.trace("Multi: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.debug("Multi: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.info("Multi: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.warning("Multi: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.error("Multi: {} {} {}", 1, 2, 3));
}

TEST_F(LoggerTest, ConvenienceMethods_AtDebug)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Debug);

    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    EXPECT_NO_THROW(logger.debug("Debug test"));
    EXPECT_NO_THROW(logger.info("Info test"));
    EXPECT_NO_THROW(logger.warning("Warning test"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

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

TEST_F(LoggerTest, SetLogLevel_InvalidLevel)
{
    Logger &logger = Logger::get_instance();

    logger.set_log_level(LogLevel::Info);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);

    logger.set_log_level(static_cast<LogLevel>(5));
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);

    logger.set_log_level(static_cast<LogLevel>(99));
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);
}

TEST_F(LoggerTest, Flush_InAsyncMode)
{
    Logger &logger = Logger::get_instance();

    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{100};

    logger.enable_async_mode(config);
    EXPECT_TRUE(logger.is_async_mode_enabled());

    logger.info("Async flush test message 1");
    logger.info("Async flush test message 2");
    logger.warning("Async flush warning");

    EXPECT_NO_THROW(logger.flush());

    logger.disable_async_mode();
}

TEST_F(LoggerTest, EnableAsyncMode_InvalidCapacity_Handled)
{
    Logger &logger = Logger::get_instance();
    EXPECT_FALSE(logger.is_async_mode_enabled());

    AsyncLoggerConfig config;
    config.queue_capacity = 7;

    EXPECT_NO_THROW(logger.enable_async_mode(config));

    EXPECT_FALSE(logger.is_async_mode_enabled());
}

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

TEST_F(LoggerTest, AllLevelTemplates_WithFormatArgs)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

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

TEST_F(LoggerTest, LogLevelFiltering_SkipsBelowLevel)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Error);

    EXPECT_NO_THROW(logger.trace("filtered trace: {}", 1));
    EXPECT_NO_THROW(logger.debug("filtered debug: {}", 2));
    EXPECT_NO_THROW(logger.info("filtered info: {}", 3));
    EXPECT_NO_THROW(logger.warning("filtered warn: {}", 4));

    EXPECT_NO_THROW(logger.error("not filtered error: {}", 5));

    logger.set_log_level(LogLevel::Info);
}

TEST_F(LoggerTest, AsyncMode_EnableTwice)
{
    Logger &logger = Logger::get_instance();

    logger.enable_async_mode();
    EXPECT_TRUE(logger.is_async_mode_enabled());

    logger.enable_async_mode();
    EXPECT_TRUE(logger.is_async_mode_enabled());

    logger.disable_async_mode();
}

TEST_F(LoggerTest, AsyncMode_DisableWhenNotEnabled)
{
    Logger &logger = Logger::get_instance();

    EXPECT_FALSE(logger.is_async_mode_enabled());
    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

TEST_F(LoggerTest, AsyncMode_CustomConfig)
{
    Logger &logger = Logger::get_instance();

    AsyncLoggerConfig config;
    config.queue_capacity = 512;
    config.batch_size = 16;

    logger.enable_async_mode(config);
    EXPECT_TRUE(logger.is_async_mode_enabled());

    logger.info("Custom config async message: {}", 42);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    logger.disable_async_mode();
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

TEST_F(LoggerTest, Flush_SyncMode)
{
    Logger &logger = Logger::get_instance();
    logger.info("Pre-flush message");
    EXPECT_NO_THROW(logger.flush());
}

TEST_F(LoggerTest, Flush_AsyncMode)
{
    Logger &logger = Logger::get_instance();

    logger.enable_async_mode();
    logger.info("Async pre-flush");
    EXPECT_NO_THROW(logger.flush());
    logger.disable_async_mode();
}

TEST_F(LoggerTest, LogFileContentVerification)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Info);

    logger.info("UNIQUE_VERIFY_MSG_7a3b");
    logger.flush();

    std::ifstream ifs(test_log_file_);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("UNIQUE_VERIFY_MSG_7a3b"), std::string::npos);
}

TEST_F(LoggerTest, LogLevelFiltering_OutputVerification)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Warning);

    logger.debug("FILTERED_DEBUG_MSG_9x2k");
    logger.warning("VISIBLE_WARNING_MSG_4m8p");
    logger.flush();

    std::ifstream ifs(test_log_file_);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("VISIBLE_WARNING_MSG_4m8p"), std::string::npos);
    EXPECT_EQ(content.find("FILTERED_DEBUG_MSG_9x2k"), std::string::npos);
}

TEST_F(LoggerTest, Reconfigure_SwitchesFile)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Info);

    logger.info("MSG_IN_FILE_A_5t1w");
    logger.flush();

    auto file_b = std::filesystem::temp_directory_path() /
                  ("test_logger_reconfig_b_" + std::to_string(GetCurrentProcessId()) + ".log");

    logger.reconfigure("TEST_B", file_b.string(), "%Y-%m-%d %H:%M:%S");
    logger.info("MSG_IN_FILE_B_8q3r");
    logger.flush();

    std::ifstream ifs(file_b);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("MSG_IN_FILE_B_8q3r"), std::string::npos);
    EXPECT_EQ(content.find("MSG_IN_FILE_A_5t1w"), std::string::npos);

    try
    {
        if (std::filesystem::exists(file_b))
            std::filesystem::remove(file_b);
    }
    catch (const std::filesystem::filesystem_error &)
    {
    }
}

TEST_F(LoggerTest, ErrorOnInvalidLogPath)
{
    Logger &logger = Logger::get_instance();
    EXPECT_NO_THROW(logger.reconfigure("TEST", "/nonexistent_dir_12345/foo.log", "%Y-%m-%d %H:%M:%S"));
    EXPECT_NO_THROW(logger.info("Message after bad path"));
}

TEST_F(LoggerTest, Shutdown_AtomicCAS_OneShotExecution)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

    logger.enable_async_mode();
    logger.info("Message before concurrent shutdown");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::atomic<int> shutdown_count{0};
    std::vector<std::thread> threads;

    for (int i = 0; i < 4; ++i)
    {
        threads.emplace_back([&logger, &shutdown_count]()
                             {
            logger.shutdown();
            shutdown_count.fetch_add(1, std::memory_order_relaxed); });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_EQ(shutdown_count.load(), 4);
}

TEST_F(LoggerTest, ShutdownAndDestructor_Idempotent)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

    logger.enable_async_mode();
    logger.info("Shutdown test message");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    logger.shutdown();
    logger.shutdown();

    logger.info("Message after shutdown - should still work");
}

TEST_F(LoggerTest, ConcurrentShutdownAndLog)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Trace);

    logger.enable_async_mode();

    std::atomic<bool> shutdown_started{false};
    std::atomic<bool> shutdown_complete{false};
    std::vector<std::thread> threads;

    threads.emplace_back([&logger, &shutdown_started, &shutdown_complete]()
                         {
        shutdown_started.store(true, std::memory_order_release);
        logger.shutdown();
        shutdown_complete.store(true, std::memory_order_release); });

    threads.emplace_back([&logger, &shutdown_started]()
                         {
        while (!shutdown_started.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        for (int i = 0; i < 100; ++i)
        {
            logger.info("Concurrent log message {}", i);
        } });

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_TRUE(shutdown_complete.load());
}

TEST_F(LoggerTest, AsyncMode_OutputVerification)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Info);

    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());

    logger.info("ASYNC_VERIFY_MSG_6j9n");

    logger.disable_async_mode();
    logger.flush();

    std::ifstream ifs(test_log_file_);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("ASYNC_VERIFY_MSG_6j9n"), std::string::npos);
}

TEST_F(LoggerTest, StringToLogLevel_ConcurrentWithConfigure)
{
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;

    threads.emplace_back([&stop]()
                         {
        while (!stop.load(std::memory_order_acquire))
        {
            auto level = Logger::string_to_log_level("INVALID_LEVEL");
            EXPECT_EQ(level, LogLevel::Info);
        } });

    threads.emplace_back([&stop, this]()
                         {
        for (int i = 0; i < 50; ++i)
        {
            Logger::configure("PREFIX_" + std::to_string(i), test_log_file_.string(), "%Y-%m-%d %H:%M:%S");
        }
        stop.store(true, std::memory_order_release); });

    for (auto &t : threads)
    {
        t.join();
    }

    SUCCEED();
}

TEST_F(LoggerTest, TimestampFormat_StrftimeOutput)
{
    Logger &logger = Logger::get_instance();
    logger.set_log_level(LogLevel::Info);

    logger.info("TIMESTAMP_CHECK_MSG_2k4j");
    logger.flush();

    std::ifstream ifs(test_log_file_);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("TIMESTAMP_CHECK_MSG_2k4j"), std::string::npos);

    // Verify timestamp format: [YYYY-MM-DD HH:MM:SS]
    auto pos = content.find("[20");
    ASSERT_NE(pos, std::string::npos);
    auto end_bracket = content.find(']', pos);
    ASSERT_NE(end_bracket, std::string::npos);
    std::string timestamp = content.substr(pos + 1, end_bracket - pos - 1);
    ASSERT_GE(timestamp.size(), 19u);
    EXPECT_EQ(timestamp[4], '-');
    EXPECT_EQ(timestamp[7], '-');
    EXPECT_EQ(timestamp[10], ' ');
    EXPECT_EQ(timestamp[13], ':');
    EXPECT_EQ(timestamp[16], ':');
}
