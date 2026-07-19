#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <thread>
#include <chrono>
#include <type_traits>
#include <windows.h>
#include <atomic>

#include "DetourModKit/logger.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "internal/async_logger.hpp"

#include "test_alloc_probe.hpp"

using namespace DetourModKit;

// The loader-lock fallback in Logger::shutdown_internal and disable_async_mode() retains a
// std::shared_ptr<AsyncLogger> in permanent storage. Guard the leak cell's move constructor stays noexcept so the call
// cannot turn the noexcept ~Logger contract into std::terminate via a thrown move.
static_assert(std::is_nothrow_move_constructible_v<std::shared_ptr<AsyncLogger>>,
              "std::shared_ptr<AsyncLogger> must be nothrow-move-constructible "
              "for the Logger loader-lock leak path to keep ~Logger noexcept honest.");

class LoggerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static int s_test_counter = 0;
        m_test_log_file =
            std::filesystem::temp_directory_path() /
            ("test_logger_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(s_test_counter++) + ".log");
        Logger::configure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
    }

    void TearDown() override
    {
        auto temp_file = std::filesystem::temp_directory_path() /
                         ("test_logger_temp_" + std::to_string(GetCurrentProcessId()) + ".log");
        Logger::configure("TEMP", temp_file.string(), "%Y-%m-%d %H:%M:%S");

        try
        {
            if (std::filesystem::exists(m_test_log_file))
            {
                std::filesystem::remove(m_test_log_file);
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

    std::filesystem::path m_test_log_file;
};

TEST_F(LoggerTest, LogLevelToString)
{
    EXPECT_EQ(to_string(LogLevel::Trace), "TRACE");
    EXPECT_EQ(to_string(LogLevel::Debug), "DEBUG");
    EXPECT_EQ(to_string(LogLevel::Info), "INFO");
    EXPECT_EQ(to_string(LogLevel::Warning), "WARNING");
    EXPECT_EQ(to_string(LogLevel::Error), "ERROR");
}

TEST_F(LoggerTest, StringToLogLevel)
{
    EXPECT_EQ(string_to_log_level("TRACE"), LogLevel::Trace);
    EXPECT_EQ(string_to_log_level("trace"), LogLevel::Trace);
    EXPECT_EQ(string_to_log_level("DEBUG"), LogLevel::Debug);
    EXPECT_EQ(string_to_log_level("debug"), LogLevel::Debug);
    EXPECT_EQ(string_to_log_level("INFO"), LogLevel::Info);
    EXPECT_EQ(string_to_log_level("info"), LogLevel::Info);
    EXPECT_EQ(string_to_log_level("WARNING"), LogLevel::Warning);
    EXPECT_EQ(string_to_log_level("warning"), LogLevel::Warning);
    EXPECT_EQ(string_to_log_level("ERROR"), LogLevel::Error);
    EXPECT_EQ(string_to_log_level("error"), LogLevel::Error);

    EXPECT_EQ(string_to_log_level("INVALID"), LogLevel::Info);
    EXPECT_EQ(string_to_log_level(""), LogLevel::Info);
    EXPECT_EQ(string_to_log_level("XYZ"), LogLevel::Info);
}

TEST(LoggerProcessDefault, LogReturnsStableReference)
{
    // log() returns the process-default Logger, and the reference is stable for the life of the process, so repeated
    // calls yield the same object.
    Logger &instance1 = log();
    Logger &instance2 = log();
    EXPECT_EQ(&instance1, &instance2);
}

TEST_F(LoggerTest, SetAndGetLogLevel)
{
    Logger &logger = log();

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
    Logger &logger = log();

    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test info message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test debug message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Test warning message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Test error message"));
    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Test trace message"));
}

TEST_F(LoggerTest, FormattedLogging)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Test value: {}", 42));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Test string: {}", std::string("hello")));
    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Multiple: {} and {}", 1, 2.5));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Mixed: {} {} {}", 1, "two", 3.0f));
}

TEST_F(LoggerTest, ConvenienceMethods)
{
    Logger &logger = log();

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
    Logger &logger = log();
    logger.set_log_level(LogLevel::Warning);

    EXPECT_NO_THROW(logger.log(LogLevel::Trace, "Should not appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Debug, "Should not appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Info, "Should not appear"));

    EXPECT_NO_THROW(logger.log(LogLevel::Warning, "Should appear"));
    EXPECT_NO_THROW(logger.log(LogLevel::Error, "Should appear"));
}

TEST_F(LoggerTest, Flush)
{
    Logger &logger = log();
    EXPECT_NO_THROW(logger.flush());
}

TEST_F(LoggerTest, AsyncMode)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.enable_async_mode());
    EXPECT_TRUE(logger.is_async_mode_enabled());

    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

TEST_F(LoggerTest, AsyncModeWithConfig)
{
    Logger &logger = log();

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
    Logger &logger = log();

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
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    std::vector<std::thread> threads;
    const int num_threads = 4;
    const int messages_per_thread = 100;

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back(
            [&logger, i, messages_per_thread]()
            {
                for (int j = 0; j < messages_per_thread; ++j)
                {
                    logger.log(LogLevel::Info, "Thread " + std::to_string(i) + " message " + std::to_string(j));
                }
            });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    SUCCEED();
}

TEST_F(LoggerTest, Reconfigure)
{
    Logger &logger = log();

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

    Logger &logger = log();
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
    Logger &logger = log();

    EXPECT_NO_THROW(logger.shutdown());

    EXPECT_NO_THROW(logger.shutdown());
}

TEST_F(LoggerTest, LoggingAfterShutdown)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.shutdown());
    EXPECT_FALSE(logger.log(LogLevel::Info, "Message after shutdown"));
}

TEST_F(LoggerTest, AsyncModeInvalidConfig)
{
    Logger &logger = log();

    AsyncLoggerConfig config;
    config.queue_capacity = 100;

    EXPECT_NO_THROW(logger.enable_async_mode(config));

    EXPECT_NO_THROW(logger.disable_async_mode());
}

TEST_F(LoggerTest, LongMessages)
{
    Logger &logger = log();

    std::string long_message(1000, 'X');
    EXPECT_NO_THROW(logger.info("{}", long_message));

    std::string very_long_message(5000, 'Y');
    EXPECT_NO_THROW(logger.info("{}", very_long_message));
}

TEST_F(LoggerTest, SpecialCharacters)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.info("Special: !@#$%^&*()"));
    EXPECT_NO_THROW(logger.info("Unicode: \u00e9\u00e8\u00ea"));
    EXPECT_NO_THROW(logger.info("Newlines: \n\r\t"));
    EXPECT_NO_THROW(logger.info("Quotes: \"single\" and 'double'"));
    EXPECT_NO_THROW(logger.info("Braces: {{ and }}"));
}

TEST_F(LoggerTest, EmptyMessage)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.info(""));
    EXPECT_NO_THROW(logger.debug(""));
    EXPECT_NO_THROW(logger.error(""));
}

TEST_F(LoggerTest, LogLevelFiltering_Formatted)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Warning);

    EXPECT_NO_THROW(logger.trace("Trace: {}", 1));
    EXPECT_NO_THROW(logger.debug("Debug: {}", 2));
    EXPECT_NO_THROW(logger.info("Info: {}", 3));

    EXPECT_NO_THROW(logger.warning("Warning: {}", 4));
    EXPECT_NO_THROW(logger.error("Error: {}", 5));
}

TEST_F(LoggerTest, LogLevelFiltering_Convenience)
{
    Logger &logger = log();
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
    EXPECT_EQ(to_string(invalid_level), "UNKNOWN");
}

TEST_F(LoggerTest, StringToLogLevel_VariousCases)
{
    EXPECT_EQ(string_to_log_level("Trace"), LogLevel::Trace);
    EXPECT_EQ(string_to_log_level("DEBUG"), LogLevel::Debug);
    EXPECT_EQ(string_to_log_level("Info"), LogLevel::Info);
    EXPECT_EQ(string_to_log_level("WARNING"), LogLevel::Warning);
    EXPECT_EQ(string_to_log_level("Error"), LogLevel::Error);

    EXPECT_EQ(string_to_log_level(" trace "), LogLevel::Info);
    EXPECT_EQ(string_to_log_level("debug "), LogLevel::Info);

    EXPECT_EQ(string_to_log_level("123"), LogLevel::Info);
    EXPECT_EQ(string_to_log_level("0"), LogLevel::Info);
}

TEST_F(LoggerTest, LongFormatString)
{
    Logger &logger = log();

    EXPECT_NO_THROW(
        logger.info("This is a very long format string with many placeholders: {} {} {} {} {} {} {} {} {} {}", 1, 2, 3,
                    4, 5, 6, 7, 8, 9, 10));
}

TEST_F(LoggerTest, SpecialFormatCharacters)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.info("Braces: {{ and }}"));
    EXPECT_NO_THROW(logger.info("Percent: %%"));
    EXPECT_NO_THROW(logger.info("Newline: \n"));
    EXPECT_NO_THROW(logger.info("Tab: \t"));
    EXPECT_NO_THROW(logger.info("Quote: \""));
    EXPECT_NO_THROW(logger.info("Backslash: \\"));
}

TEST_F(LoggerTest, MultipleArguments)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.info("One arg: {}", 1));
    EXPECT_NO_THROW(logger.info("Two args: {} {}", 1, 2));
    EXPECT_NO_THROW(logger.info("Three args: {} {} {}", 1, 2, 3));
    EXPECT_NO_THROW(logger.info("Four args: {} {} {} {}", 1, 2, 3, 4));
    EXPECT_NO_THROW(logger.info("Five args: {} {} {} {} {}", 1, 2, 3, 4, 5));
}

TEST_F(LoggerTest, DifferentArgumentTypes)
{
    Logger &logger = log();

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
    Logger &logger = log();

    EXPECT_NO_THROW(logger.info("Mixed: {} {} {} {} {}", 1, "two", 3.0f, true, 'X'));
}

TEST_F(LoggerTest, UnicodeCharacters)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.info("Unicode: \u00e9\u00e8\u00ea"));
    // U+1F600 (grinning face) as raw UTF-8 bytes so the narrow literal needs no code-page conversion: the
    // \U0001F600 universal-character-name is unrepresentable in code page 1252 and warns under MSVC (C4566).
    EXPECT_NO_THROW(logger.info("Emoji: \xF0\x9F\x98\x80"));
}

TEST_F(LoggerTest, NullPointerInFormat)
{
    Logger &logger = log();

    void *ptr = nullptr;
    EXPECT_NO_THROW(logger.info("Null pointer: {}", ptr));
}

TEST_F(LoggerTest, FormatSpecifiers_BasicTypes)
{
    Logger &logger = log();

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
    Logger &logger = log();

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
    Logger &logger = log();

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
    Logger &logger = log();

    std::string_view sv = "string view";
    EXPECT_NO_THROW(logger.info("String view: {}", sv));
}

TEST_F(LoggerTest, Atomic)
{
    Logger &logger = log();

    std::atomic<int> atomic{42};
    EXPECT_NO_THROW(logger.info("Atomic: {}", atomic.load()));
}

TEST_F(LoggerTest, ConvenienceMethods_AtTrace)
{
    Logger &logger = log();
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
    Logger &logger = log();
    logger.set_log_level(LogLevel::Debug);

    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    EXPECT_NO_THROW(logger.debug("Debug test"));
    EXPECT_NO_THROW(logger.info("Info test"));
    EXPECT_NO_THROW(logger.warning("Warning test"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

TEST_F(LoggerTest, ConvenienceMethods_AtInfo)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    EXPECT_NO_THROW(logger.debug("Debug filtered"));
    EXPECT_NO_THROW(logger.info("Info test"));
    EXPECT_NO_THROW(logger.warning("Warning test"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

TEST_F(LoggerTest, ConvenienceMethods_AtWarning)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Warning);

    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    EXPECT_NO_THROW(logger.debug("Debug filtered"));
    EXPECT_NO_THROW(logger.info("Info filtered"));
    EXPECT_NO_THROW(logger.warning("Warning test"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

TEST_F(LoggerTest, ConvenienceMethods_AtError)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Error);

    EXPECT_NO_THROW(logger.trace("Trace filtered"));
    EXPECT_NO_THROW(logger.debug("Debug filtered"));
    EXPECT_NO_THROW(logger.info("Info filtered"));
    EXPECT_NO_THROW(logger.warning("Warning filtered"));
    EXPECT_NO_THROW(logger.error("Error test"));
}

TEST_F(LoggerTest, SetLogLevel_InvalidLevel)
{
    Logger &logger = log();

    logger.set_log_level(LogLevel::Info);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);

    logger.set_log_level(static_cast<LogLevel>(5));
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);

    logger.set_log_level(static_cast<LogLevel>(99));
    EXPECT_EQ(logger.get_log_level(), LogLevel::Info);
}

TEST_F(LoggerTest, Flush_InAsyncMode)
{
    Logger &logger = log();

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
    Logger &logger = log();
    EXPECT_FALSE(logger.is_async_mode_enabled());

    AsyncLoggerConfig config;
    config.queue_capacity = 7;

    EXPECT_NO_THROW(logger.enable_async_mode(config));

    EXPECT_FALSE(logger.is_async_mode_enabled());
}

TEST_F(LoggerTest, AsyncMode_AllLevels)
{
    Logger &logger = log();
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
    Logger &logger = log();
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
    Logger &logger = log();
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
    Logger &logger = log();

    logger.enable_async_mode();
    EXPECT_TRUE(logger.is_async_mode_enabled());

    logger.enable_async_mode();
    EXPECT_TRUE(logger.is_async_mode_enabled());

    logger.disable_async_mode();
}

TEST_F(LoggerTest, AsyncMode_DisableWhenNotEnabled)
{
    Logger &logger = log();

    EXPECT_FALSE(logger.is_async_mode_enabled());
    EXPECT_NO_THROW(logger.disable_async_mode());
    EXPECT_FALSE(logger.is_async_mode_enabled());
}

TEST_F(LoggerTest, AsyncMode_CustomConfig)
{
    Logger &logger = log();

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
    Logger &logger = log();
    logger.info("Pre-flush message");
    EXPECT_NO_THROW(logger.flush());
}

TEST_F(LoggerTest, Flush_AsyncMode)
{
    Logger &logger = log();

    logger.enable_async_mode();
    logger.info("Async pre-flush");
    EXPECT_NO_THROW(logger.flush());
    logger.disable_async_mode();
}

TEST_F(LoggerTest, LogFileContentVerification)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    logger.info("UNIQUE_VERIFY_MSG_7a3b");
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("UNIQUE_VERIFY_MSG_7a3b"), std::string::npos);
}

TEST_F(LoggerTest, LogLevelFiltering_OutputVerification)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Warning);

    logger.debug("FILTERED_DEBUG_MSG_9x2k");
    logger.warning("VISIBLE_WARNING_MSG_4m8p");
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("VISIBLE_WARNING_MSG_4m8p"), std::string::npos);
    EXPECT_EQ(content.find("FILTERED_DEBUG_MSG_9x2k"), std::string::npos);
}

TEST_F(LoggerTest, Reconfigure_SwitchesFile)
{
    Logger &logger = log();
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
    Logger &logger = log();
    EXPECT_NO_THROW(logger.reconfigure("TEST", "/nonexistent_dir_12345/foo.log", "%Y-%m-%d %H:%M:%S"));
    EXPECT_NO_THROW(logger.info("Message after bad path"));
}

TEST_F(LoggerTest, Shutdown_AtomicCAS_OneShotExecution)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    logger.enable_async_mode();
    logger.info("Message before concurrent shutdown");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::atomic<int> shutdown_count{0};
    std::vector<std::thread> threads;

    for (int i = 0; i < 4; ++i)
    {
        threads.emplace_back(
            [&logger, &shutdown_count]()
            {
                logger.shutdown();
                shutdown_count.fetch_add(1, std::memory_order_relaxed);
            });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_EQ(shutdown_count.load(), 4);
}

TEST_F(LoggerTest, ShutdownAndDestructor_Idempotent)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    logger.enable_async_mode();
    logger.info("Shutdown test message");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    logger.shutdown();
    logger.shutdown();

    // Logging after shutdown is safe: the facade drops rather than resurrecting or writing to the closed sink.
    EXPECT_FALSE(logger.log(LogLevel::Info, "Message after shutdown is dropped"));
}

TEST_F(LoggerTest, ConcurrentShutdownAndLog)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    logger.enable_async_mode();

    std::atomic<bool> shutdown_started{false};
    std::atomic<bool> shutdown_complete{false};
    std::vector<std::thread> threads;

    threads.emplace_back(
        [&logger, &shutdown_started, &shutdown_complete]()
        {
            shutdown_started.store(true, std::memory_order_release);
            logger.shutdown();
            shutdown_complete.store(true, std::memory_order_release);
        });

    threads.emplace_back(
        [&logger, &shutdown_started]()
        {
            while (!shutdown_started.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            for (int i = 0; i < 100; ++i)
            {
                logger.info("Concurrent log message {}", i);
            }
        });

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_TRUE(shutdown_complete.load());
}

TEST_F(LoggerTest, AsyncMode_OutputVerification)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());

    logger.info("ASYNC_VERIFY_MSG_6j9n");

    logger.disable_async_mode();
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("ASYNC_VERIFY_MSG_6j9n"), std::string::npos);
}

TEST_F(LoggerTest, StringToLogLevel_ConcurrentWithConfigure)
{
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;

    threads.emplace_back(
        [&stop]()
        {
            while (!stop.load(std::memory_order_acquire))
            {
                auto level = string_to_log_level("INVALID_LEVEL");
                EXPECT_EQ(level, LogLevel::Info);
            }
        });

    threads.emplace_back(
        [&stop, this]()
        {
            for (int i = 0; i < 50; ++i)
            {
                Logger::configure("PREFIX_" + std::to_string(i), m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
            }
            stop.store(true, std::memory_order_release);
        });

    for (auto &t : threads)
    {
        t.join();
    }

    SUCCEED();
}

TEST_F(LoggerTest, Reconfigure_InvalidPath_KeepsOldFile)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    logger.info("BEFORE_INVALID_RECONFIG_3k7m");
    logger.flush();

    logger.reconfigure("BAD", "Z:\\nonexistent\\dir\\test.log", "%Y-%m-%d %H:%M:%S");

    logger.info("AFTER_INVALID_RECONFIG_9p2x");
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("BEFORE_INVALID_RECONFIG_3k7m"), std::string::npos);
}

TEST_F(LoggerTest, FlushAsync_DrainsPendingMessages)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());

    for (int i = 0; i < 20; ++i)
    {
        logger.info("ASYNC_DRAIN_MSG_{}", i);
    }

    logger.flush();
    logger.disable_async_mode();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("ASYNC_DRAIN_MSG_0"), std::string::npos);
    EXPECT_NE(content.find("ASYNC_DRAIN_MSG_19"), std::string::npos);
}

TEST_F(LoggerTest, ShutdownWithAsyncMode_NoHang)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());

    for (int i = 0; i < 50; ++i)
    {
        logger.info("SHUTDOWN_NOHANG_MSG_{}", i);
    }

    auto start = std::chrono::steady_clock::now();
    logger.shutdown();
    auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(5));
}

TEST_F(LoggerTest, Configure_AbsolutePath_Works)
{
    static std::atomic<int> s_abs_counter{0};
    auto abs_log_file =
        std::filesystem::temp_directory_path() / ("test_logger_abspath_" + std::to_string(GetCurrentProcessId()) + "_" +
                                                  std::to_string(s_abs_counter.fetch_add(1)) + ".log");

    Logger::configure("ABS_TEST", abs_log_file.string(), "%Y-%m-%d %H:%M:%S");

    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);
    logger.info("ABS_PATH_VERIFY_2w5q");
    logger.flush();

    EXPECT_TRUE(std::filesystem::exists(abs_log_file));

    std::ifstream ifs(abs_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("ABS_PATH_VERIFY_2w5q"), std::string::npos);

    try
    {
        if (std::filesystem::exists(abs_log_file))
            std::filesystem::remove(abs_log_file);
    }
    catch (const std::filesystem::filesystem_error &)
    {
    }
}

TEST_F(LoggerTest, Reconfigure_WhileAsyncMode_Works)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());

    static std::atomic<int> s_reconfig_counter{0};
    auto new_file = std::filesystem::temp_directory_path() /
                    ("test_logger_async_reconfig_" + std::to_string(GetCurrentProcessId()) + "_" +
                     std::to_string(s_reconfig_counter.fetch_add(1)) + ".log");

    logger.reconfigure("ASYNC_RECONFIG", new_file.string(), "%Y-%m-%d %H:%M:%S");

    logger.info("ASYNC_RECONFIG_VERIFY_8n4j");
    logger.flush();
    logger.disable_async_mode();

    std::ifstream ifs(new_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("ASYNC_RECONFIG_VERIFY_8n4j"), std::string::npos);

    try
    {
        if (std::filesystem::exists(new_file))
            std::filesystem::remove(new_file);
    }
    catch (const std::filesystem::filesystem_error &)
    {
    }
}

TEST_F(LoggerTest, AsyncMode_ConcurrentLogAndDisable)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    constexpr int iterations = 200;
    constexpr int writer_count = 4;
    std::atomic<bool> stop{false};
    std::atomic<int> total_logged{0};

    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());

    // Writer threads hammer log() while async mode is active
    std::vector<std::thread> writers;
    for (int w = 0; w < writer_count; ++w)
    {
        writers.emplace_back(
            [&, w]()
            {
                for (int i = 0; i < iterations && !stop.load(std::memory_order_relaxed); ++i)
                {
                    logger.info("CONCURRENT_W{}_MSG_{}", w, i);
                    total_logged.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }

    // Toggler thread disables and re-enables async mode mid-flight
    std::thread toggler(
        [&]()
        {
            for (int i = 0; i < 5; ++i)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                logger.disable_async_mode();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                logger.enable_async_mode();
            }
        });

    for (auto &t : writers)
    {
        t.join();
    }
    stop.store(true, std::memory_order_relaxed);
    toggler.join();

    logger.disable_async_mode();
    logger.flush();

    // Verify at least some messages survived (no crashes, no hangs)
    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_GT(total_logged.load(), 0);
    EXPECT_NE(content.find("CONCURRENT_W0_MSG_"), std::string::npos);
}

TEST_F(LoggerTest, DisableAsyncMode_NoLeakInNormalContext)
{
    // Outside the Windows loader lock, disable_async_mode() joins the writer thread and drops the AsyncLogger normally:
    // the loader-lock leak/detach path (which records a Logger intentional-leak event) must not run. A spurious leak
    // here would mean the writer was detached and the object orphaned when a clean join was possible.
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger);

    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());
    logger.info("DISABLE_ASYNC_NOLEAK_MSG");
    logger.disable_async_mode();
    EXPECT_FALSE(logger.is_async_mode_enabled());
    logger.flush();

    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger), before)
        << "disable_async_mode() must not take the loader-lock leak path when the loader lock is not held";

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("DISABLE_ASYNC_NOLEAK_MSG"), std::string::npos);
}

TEST_F(LoggerTest, TimestampFormat_StrftimeOutput)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    logger.info("TIMESTAMP_CHECK_MSG_2k4j");
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("TIMESTAMP_CHECK_MSG_2k4j"), std::string::npos);

    // Verify timestamp format: [YYYY-MM-DD HH:MM:SS.mmm]
    auto pos = content.find("[20");
    ASSERT_NE(pos, std::string::npos);
    auto end_bracket = content.find(']', pos);
    ASSERT_NE(end_bracket, std::string::npos);
    std::string timestamp = content.substr(pos + 1, end_bracket - pos - 1);
    ASSERT_GE(timestamp.size(), 23u);
    EXPECT_EQ(timestamp[4], '-');
    EXPECT_EQ(timestamp[7], '-');
    EXPECT_EQ(timestamp[10], ' ');
    EXPECT_EQ(timestamp[13], ':');
    EXPECT_EQ(timestamp[16], ':');
    EXPECT_EQ(timestamp[19], '.');
}

TEST_F(LoggerTest, ConcurrentFileAccess_ReadWhileLogging)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    const int pre_open_count = 10;
    const int during_open_count = 20;
    const int post_close_count = 10;

    for (int i = 0; i < pre_open_count; ++i)
    {
        logger.info("PRE_OPEN_{}", i);
    }
    logger.flush();

    // Simulate an external process opening the log file for reading
    HANDLE external_handle = CreateFileA(m_test_log_file.string().c_str(), GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(external_handle, INVALID_HANDLE_VALUE) << "Failed to open log file externally: " << GetLastError();

    for (int i = 0; i < during_open_count; ++i)
    {
        logger.info("DURING_OPEN_{}", i);
    }
    logger.flush();

    CloseHandle(external_handle);

    for (int i = 0; i < post_close_count; ++i)
    {
        logger.info("POST_CLOSE_{}", i);
    }
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    for (int i = 0; i < pre_open_count; ++i)
    {
        EXPECT_NE(content.find("PRE_OPEN_" + std::to_string(i)), std::string::npos) << "Missing PRE_OPEN_" << i;
    }
    for (int i = 0; i < during_open_count; ++i)
    {
        EXPECT_NE(content.find("DURING_OPEN_" + std::to_string(i)), std::string::npos) << "Missing DURING_OPEN_" << i;
    }
    for (int i = 0; i < post_close_count; ++i)
    {
        EXPECT_NE(content.find("POST_CLOSE_" + std::to_string(i)), std::string::npos) << "Missing POST_CLOSE_" << i;
    }
}

TEST_F(LoggerTest, ConcurrentFileAccess_ExclusiveReadWhileLogging)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    logger.info("BEFORE_EXCLUSIVE_OPEN");
    logger.flush();

    // Open with no sharing flags (simulates an editor that locks the file)
    HANDLE exclusive_handle = CreateFileA(m_test_log_file.string().c_str(), GENERIC_READ,
                                          0, // No sharing -- exclusive lock
                                          nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    // This open may or may not succeed depending on OS sharing enforcement. The key assertion is that logging continues
    // to work regardless.
    const int msg_count = 10;
    for (int i = 0; i < msg_count; ++i)
    {
        EXPECT_NO_THROW(logger.info("EXCLUSIVE_TEST_{}", i));
    }
    logger.flush();

    if (exclusive_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(exclusive_handle);
    }

    // Re-read and verify messages written before the exclusive open
    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("BEFORE_EXCLUSIVE_OPEN"), std::string::npos);
}

TEST_F(LoggerTest, ConcurrentFileAccess_RepeatedOpenClose)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    const int iterations = 5;
    const int msgs_per_iter = 5;

    for (int iter = 0; iter < iterations; ++iter)
    {
        for (int i = 0; i < msgs_per_iter; ++i)
        {
            logger.info("ITER{}_{}", iter, i);
        }
        logger.flush();

        HANDLE h = CreateFileA(m_test_log_file.string().c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);

        if (h != INVALID_HANDLE_VALUE)
        {
            CloseHandle(h);
        }
    }

    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    for (int iter = 0; iter < iterations; ++iter)
    {
        for (int i = 0; i < msgs_per_iter; ++i)
        {
            EXPECT_NE(content.find("ITER" + std::to_string(iter) + "_" + std::to_string(i)), std::string::npos)
                << "Missing ITER" << iter << "_" << i;
        }
    }
}

TEST_F(LoggerTest, ConcurrentFileAccess_AsyncModeReadWhileLogging)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());

    const int pre_open_count = 10;
    const int during_open_count = 20;

    for (int i = 0; i < pre_open_count; ++i)
    {
        logger.info("ASYNC_PRE_{}", i);
    }
    logger.flush();

    HANDLE external_handle = CreateFileA(m_test_log_file.string().c_str(), GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(external_handle, INVALID_HANDLE_VALUE);

    for (int i = 0; i < during_open_count; ++i)
    {
        logger.info("ASYNC_DURING_{}", i);
    }
    logger.flush();

    CloseHandle(external_handle);

    logger.disable_async_mode();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    for (int i = 0; i < pre_open_count; ++i)
    {
        EXPECT_NE(content.find("ASYNC_PRE_" + std::to_string(i)), std::string::npos) << "Missing ASYNC_PRE_" << i;
    }
    for (int i = 0; i < during_open_count; ++i)
    {
        EXPECT_NE(content.find("ASYNC_DURING_" + std::to_string(i)), std::string::npos) << "Missing ASYNC_DURING_" << i;
    }
}

TEST_F(LoggerTest, SetLogLevel_SameLevel_NoLogMessage)
{
    Logger &logger = log();

    // Stabilize: set to Trace, then set again -- second call must be silent
    logger.set_log_level(LogLevel::Trace);
    logger.info("MARKER_BEFORE_SAME_a7k2");
    logger.set_log_level(LogLevel::Trace);
    logger.info("MARKER_AFTER_SAME_a7k2");
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("MARKER_BEFORE_SAME_a7k2"), std::string::npos);
    EXPECT_NE(content.find("MARKER_AFTER_SAME_a7k2"), std::string::npos);

    // Only one "Log level changed" should exist (the initial set to Trace) and none after the marker
    auto marker_pos = content.find("MARKER_BEFORE_SAME_a7k2");
    auto change_after = content.find("Log level changed", marker_pos);
    EXPECT_EQ(change_after, std::string::npos) << "set_log_level with same level should not produce a log message";
}

TEST_F(LoggerTest, SetLogLevel_DifferentLevel_LogsChange)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Debug);
    logger.set_log_level(LogLevel::Info);
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("Log level changed from DEBUG to INFO"), std::string::npos);
}

TEST_F(LoggerTest, IsEnabled_AtCurrentLevel)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    EXPECT_TRUE(logger.is_enabled(LogLevel::Info));
    EXPECT_TRUE(logger.is_enabled(LogLevel::Warning));
    EXPECT_TRUE(logger.is_enabled(LogLevel::Error));
    EXPECT_FALSE(logger.is_enabled(LogLevel::Debug));
    EXPECT_FALSE(logger.is_enabled(LogLevel::Trace));
}

TEST_F(LoggerTest, IsEnabled_TraceLevel)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    EXPECT_TRUE(logger.is_enabled(LogLevel::Trace));
    EXPECT_TRUE(logger.is_enabled(LogLevel::Debug));
    EXPECT_TRUE(logger.is_enabled(LogLevel::Info));
    EXPECT_TRUE(logger.is_enabled(LogLevel::Warning));
    EXPECT_TRUE(logger.is_enabled(LogLevel::Error));
}

TEST_F(LoggerTest, IsEnabled_ErrorLevel)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Error);

    EXPECT_FALSE(logger.is_enabled(LogLevel::Trace));
    EXPECT_FALSE(logger.is_enabled(LogLevel::Debug));
    EXPECT_FALSE(logger.is_enabled(LogLevel::Info));
    EXPECT_FALSE(logger.is_enabled(LogLevel::Warning));
    EXPECT_TRUE(logger.is_enabled(LogLevel::Error));
}

TEST_F(LoggerTest, IsEnabled_ConsistentWithGetLogLevel)
{
    Logger &logger = log();

    const LogLevel all_levels[] = {LogLevel::Trace, LogLevel::Debug, LogLevel::Info, LogLevel::Warning,
                                   LogLevel::Error};

    for (auto configured : all_levels)
    {
        logger.set_log_level(configured);
        EXPECT_EQ(logger.get_log_level(), configured);

        for (auto queried : all_levels)
        {
            EXPECT_EQ(logger.is_enabled(queried), queried >= configured)
                << "configured=" << static_cast<int>(configured) << " queried=" << static_cast<int>(queried);
        }
    }
}

TEST_F(LoggerTest, Reconfigure_SameParams_SkipsReopen)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    auto first_file = m_test_log_file;
    Logger::configure("TEST", first_file.string(), "%Y-%m-%d %H:%M:%S");
    logger.info("Before reconfigure");
    logger.flush();

    // Reconfigure with identical params should be a no-op (stream stays open)
    Logger::configure("TEST", first_file.string(), "%Y-%m-%d %H:%M:%S");
    logger.info("After reconfigure");
    logger.flush();

    std::ifstream in(first_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_TRUE(content.find("After reconfigure") != std::string::npos);
}

TEST_F(LoggerTest, Reconfigure_AfterShutdown_Succeeds)
{
    Logger &logger = log();
    logger.shutdown();

    // Reconfigure after shutdown should reopen and work
    Logger::configure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
    logger.set_log_level(LogLevel::Trace);
    logger.info("Post-shutdown message");
    logger.flush();

    std::ifstream in(m_test_log_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_TRUE(content.find("Post-shutdown message") != std::string::npos);
}

TEST_F(LoggerTest, Log_ErrorLevel_WhenFileClosed_WritesToStderr)
{
    Logger &logger = log();
    logger.shutdown();

    // Reconfigure to an invalid path so the file stream fails to open
    Logger::configure("STDERR_TEST", "Z:\\nonexistent_dir_12345\\impossible.log", "%H:%M:%S");

    // Error-level log with closed stream should go to stderr
    testing::internal::CaptureStderr();
    logger.error("Stderr fallback test");
    std::string stderr_output = testing::internal::GetCapturedStderr();

    EXPECT_TRUE(stderr_output.find("LOG_FILE_WRITE_ERROR") != std::string::npos ||
                stderr_output.find("CRITICAL ERROR") != std::string::npos);
}

TEST_F(LoggerTest, Log_InfoLevel_WhenFileClosed_SilentlyDropped)
{
    Logger &logger = log();
    logger.shutdown();
    Logger::configure("DROP_TEST", "Z:\\nonexistent_dir_12345\\impossible.log", "%H:%M:%S");

    // Info-level log with closed stream should be silently dropped
    testing::internal::CaptureStderr();
    logger.info("This should be dropped");
    std::string stderr_output = testing::internal::GetCapturedStderr();

    // stderr should NOT contain LOG_FILE_WRITE_ERROR for info-level
    EXPECT_EQ(stderr_output.find("LOG_FILE_WRITE_ERROR"), std::string::npos);
}

TEST_F(LoggerTest, LogNoexcept_IsNoThrowAndWritesMessage)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    // The no-throw entry point must be declared noexcept so it is safe to call from hook callbacks and other
    // noexcept-boundary contexts.
    static_assert(noexcept(logger.log_noexcept(LogLevel::Info, "x")),
                  "log_noexcept must be noexcept for noexcept-boundary callers");

    EXPECT_TRUE(logger.log_noexcept(LogLevel::Error, "NOEXCEPT_LOG_LINE_4k2p"));
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("NOEXCEPT_LOG_LINE_4k2p"), std::string::npos);
}

TEST_F(LoggerTest, LogNoexcept_ReturnsFalseWhenFilteredOut)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Error);

    EXPECT_FALSE(logger.log_noexcept(LogLevel::Debug, "below the threshold"));
    EXPECT_TRUE(logger.log_noexcept(LogLevel::Error, "at the threshold"));
}

TEST_F(LoggerTest, TryLog_IsNoThrowAndFormatsMessage)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    // try_log is declared noexcept, but noexcept(try_log(level, "{}", arg)) is not a useful probe: the
    // std::format_string argument is built by a consteval constructor that is not noexcept-qualified, so the noexcept
    // operator reports the whole call-expression as potentially-throwing even though try_log itself cannot throw at
    // runtime (it catches every std::format and sink failure internally). The runtime no-throw contract is exercised
    // behaviourally below.

    EXPECT_TRUE(logger.try_log(LogLevel::Warning, "FORMATTED_TRYLOG {} {}", 42, "ok"));
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("FORMATTED_TRYLOG 42 ok"), std::string::npos);
}

namespace
{
    std::filesystem::path make_logger_overload_path()
    {
        static std::atomic<int> counter{0};
        return std::filesystem::temp_directory_path() /
               ("test_logger_overload_" + std::to_string(GetCurrentProcessId()) + "_" +
                std::to_string(counter.fetch_add(1)) + ".log");
    }
} // anonymous namespace

TEST(LoggerConfigureOverload, TwoArgConfigureUsesDefaultTimestamp)
{
    const auto path = make_logger_overload_path();
    Logger::configure("PFX", path.string());
    log().info("hello");
    log().flush();
    EXPECT_TRUE(std::filesystem::exists(path));
    std::filesystem::remove(path);
}

TEST_F(LoggerTest, FormattedAsyncLog_FitsInlineBufferWithoutHeapAllocation)
{
    // The formatted log() fast path renders into a stack buffer the size of the async inline message
    // buffer, so a line that fits never materializes a heap std::format temporary. The allocation probe
    // is thread-local, so it counts only this (producer) thread's allocations and the async writer
    // thread's are invisible to it.
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);

    AsyncLoggerConfig config;
    config.flush_interval = std::chrono::milliseconds{2000}; // keep the writer mostly parked
    logger.enable_async_mode(config);
    ASSERT_TRUE(logger.is_async_mode_enabled());

    // Warm up so only steady-state per-message cost is measured: the warmup lines exercise the format
    // facets and the LogMessage inline copy, and flush() drives a producer-thread wait on the flush
    // condition variable so any one-time lazy initialization of the flush mutex/condition variable
    // happens before the measured window.
    for (int i = 0; i < 4; ++i)
    {
        logger.info("alloc warmup value={} tag={}", i, "abc");
    }
    logger.flush();
    std::this_thread::sleep_for(std::chrono::milliseconds{20});

    // Measured: a short formatted line whose rendered length is far below LOG_INLINE_MESSAGE_SIZE.
    const long long inline_before = dmk_test::thread_new_calls();
    logger.info("alloc probe value={} count={}", 1234, 5678);
    const long long inline_allocs = dmk_test::thread_new_calls() - inline_before;
    EXPECT_EQ(inline_allocs, 0)
        << "formatting a line that fits the inline buffer must not heap-allocate on the producer thread";

    // Control: a line longer than the inline buffer falls back to a heap std::format string and the
    // StringPool overflow path, so it must allocate. This proves the probe observes allocations and that
    // the inline-fit path above genuinely avoided them.
    const std::string oversized(LOG_INLINE_MESSAGE_SIZE + 64, 'X');
    const long long control_before = dmk_test::thread_new_calls();
    logger.info("{}", oversized);
    const long long control_allocs = dmk_test::thread_new_calls() - control_before;
    EXPECT_GT(control_allocs, 0) << "a line exceeding the inline buffer is expected to allocate, validating the probe";

    logger.disable_async_mode();
}

TEST_F(LoggerTest, SourceLocation_StampsFileAndLine)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    // The formatted (LocatedFormat) path auto-stamps the call site as a compact [file:line] prefix. Capture the line
    // number of the info() call from __LINE__ so the assertion is exact (it tracks future edits to this file) rather
    // than a loose digit search.
    const unsigned call_line = static_cast<unsigned>(__LINE__) + 1;
    logger.info("SOURCE_STAMP_MARKER_{}", 7);
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("SOURCE_STAMP_MARKER_7"), std::string::npos);
    const std::string expected_stamp = "[test_logger.cpp:" + std::to_string(call_line) + "]";
    EXPECT_NE(content.find(expected_stamp), std::string::npos)
        << "expected the rendered line to carry the source stamp " << expected_stamp;
}

TEST_F(LoggerTest, RawStringViewLog_HasNoSourceStamp)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);

    // The pre-formatted log(level, string_view) overload is selected for a runtime string (the consteval LocatedFormat
    // constructor is not viable for a non-constant argument), so it carries no [file:line] stamp. This documents the
    // two-tier split: located formatting stamps, pre-built strings do not.
    const std::string prebuilt = "PREBUILT_NO_STAMP_MARKER_k3";
    logger.log(LogLevel::Info, std::string_view(prebuilt));
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    const auto pos = content.find("PREBUILT_NO_STAMP_MARKER_k3");
    ASSERT_NE(pos, std::string::npos);
    auto line_start = content.rfind('\n', pos);
    line_start = (line_start == std::string::npos) ? 0 : line_start + 1;
    const std::string prefix = content.substr(line_start, pos - line_start);
    // Assert no source stamp of ANY kind: the message must begin immediately after the fixed " :: " delimiter, so a
    // located "[file:line]" prefix from any file (not just this test's basename) would break the check.
    EXPECT_TRUE(prefix.ends_with(":: ")) << "raw log(level, string_view) must place the message directly after the "
                                            "delimiter, with no source stamp; prefix was '"
                                         << prefix << "'";
}

TEST_F(LoggerTest, ConstructYourOwn_WritesToDedicatedSink)
{
    // The value facade is constructible: a Logger pointed at its own file logs independently of the process default
    // reached through log(), so a subsystem can own a private sink without disturbing the global one.
    static std::atomic<int> s_own_counter{0};
    const auto own_file =
        std::filesystem::temp_directory_path() / ("test_logger_own_" + std::to_string(GetCurrentProcessId()) + "_" +
                                                  std::to_string(s_own_counter.fetch_add(1)) + ".log");

    // The fixture points log() at m_test_log_file, so this marker lands in the process-default sink.
    Logger &default_logger = log();
    default_logger.set_log_level(LogLevel::Info);
    default_logger.info("DEFAULT_SINK_MARKER_w2");

    {
        Logger custom("CUSTOM", own_file.string(), "%Y-%m-%d %H:%M:%S");
        custom.set_log_level(LogLevel::Info);
        custom.info("OWN_SINK_MARKER_q9");
        custom.flush();
    } // custom destroyed here: the sink is flushed and closed before the file is re-read.
    default_logger.flush();

    // Each sink holds only its own marker: the dedicated Logger and the process default never cross-contaminate.
    std::ifstream own_ifs(own_file);
    ASSERT_TRUE(own_ifs.is_open());
    const std::string own_content((std::istreambuf_iterator<char>(own_ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(own_content.find("OWN_SINK_MARKER_q9"), std::string::npos);
    EXPECT_EQ(own_content.find("DEFAULT_SINK_MARKER_w2"), std::string::npos);

    std::ifstream default_ifs(m_test_log_file);
    ASSERT_TRUE(default_ifs.is_open());
    const std::string default_content((std::istreambuf_iterator<char>(default_ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(default_content.find("DEFAULT_SINK_MARKER_w2"), std::string::npos);
    EXPECT_EQ(default_content.find("OWN_SINK_MARKER_q9"), std::string::npos);

    try
    {
        if (std::filesystem::exists(own_file))
            std::filesystem::remove(own_file);
    }
    catch (const std::filesystem::filesystem_error &)
    {
    }
}

TEST_F(LoggerTest, ToString_RoundTripsWithStringToLogLevel)
{
    // to_string(LogLevel) and string_to_log_level are inverses for every named level.
    const LogLevel levels[] = {LogLevel::Trace, LogLevel::Debug, LogLevel::Info, LogLevel::Warning, LogLevel::Error};
    for (auto level : levels)
    {
        EXPECT_EQ(string_to_log_level(to_string(level)), level);
    }
}

// enable_async_mode() must not resurrect the logger after shutdown. The dangerous interleaving is a call landing in
// shutdown_internal's dropped-mutex window -- async already disabled, the sink stream NOT yet closed -- which without
// the m_shutdown_called gate would spin up a fresh writer thread that outlives teardown. A bare after-shutdown enable()
// cannot reach that window (by then the stream is closed and the is_open() check independently refuses), so it does not
// pin the gate. This drives the window directly through the shutdown-gap probe: the probe runs on the shutdown thread
// at exactly that point and attempts the resurrection the gate must reject.
namespace DetourModKit::detail
{
    extern void (*g_logger_shutdown_gap_probe)() noexcept;
} // namespace DetourModKit::detail

namespace
{
    std::atomic<bool> g_gap_probe_ran{false};
    std::atomic<bool> g_gap_probe_resurrected{false};
    std::atomic<bool> g_gap_configure_succeeded{false};
    std::string g_gap_configure_file;
} // namespace

TEST_F(LoggerTest, EnableAsyncModeAfterShutdownDoesNotResurrect)
{
    Logger &lg = log();
    lg.enable_async_mode();
    EXPECT_TRUE(lg.is_async_mode_enabled());

    g_gap_probe_ran.store(false, std::memory_order_release);
    g_gap_probe_resurrected.store(false, std::memory_order_release);

    // Inside the dropped-mutex window the stream is still open, so only the m_shutdown_called gate can refuse this
    // enable. If that gate is reverted, the enable spins up a fresh writer and is_async_mode_enabled() flips true here
    // -- deterministic teeth for the gate specifically.
    DetourModKit::detail::g_logger_shutdown_gap_probe = []() noexcept
    {
        Logger &inner = log();
        inner.enable_async_mode();
        g_gap_probe_resurrected.store(inner.is_async_mode_enabled(), std::memory_order_release);
        g_gap_probe_ran.store(true, std::memory_order_release);
    };

    lg.shutdown();
    DetourModKit::detail::g_logger_shutdown_gap_probe = nullptr;

    EXPECT_TRUE(g_gap_probe_ran.load(std::memory_order_acquire))
        << "shutdown-gap probe never fired; the test would have no teeth";
    EXPECT_FALSE(g_gap_probe_resurrected.load(std::memory_order_acquire))
        << "enable_async_mode resurrected async logging inside the dropped-mutex window";

    // The full-shutdown contract also holds: async stays disabled after shutdown returns. TearDown's configure() clears
    // m_shutdown_called and revives the logger for later tests.
    EXPECT_FALSE(lg.is_async_mode_enabled()) << "enable_async_mode after shutdown must not resurrect async logging";
}

// Concurrency: drives a racing enable against a shutdown to target the dropped-mutex window directly.
// The gate is UNDER m_async_mutex, so a racing enable that lands in the window observes m_shutdown_called and refuses;
// a resurrection would leave async enabled after shutdown returns.
//
// This is a best-effort stress check, not a deterministic discriminator: the incorrect interleaving requires the racer
// to acquire m_async_mutex inside the narrow gap between shutdown_internal clearing m_async_mode_enabled and closing
// the stream. Reliably forcing that would need a test hook that parks shutdown_internal mid-gap; the deterministic
// guard above covers the contract directly, and this run exercises the lock boundary repeatedly.
TEST_F(LoggerTest, EnableAsyncModeRacingShutdownNeverResurrects)
{
    for (int round = 0; round < 100; ++round)
    {
        // Revive the logger: stream open, m_shutdown_called cleared.
        Logger::configure("TEST", m_test_log_file.string(), "%H:%M:%S");
        Logger &lg = log();
        lg.enable_async_mode();

        std::thread racer(
            [&lg]()
            {
                for (int k = 0; k < 40; ++k)
                {
                    lg.enable_async_mode();
                }
            });
        lg.shutdown();
        racer.join();

        EXPECT_FALSE(lg.is_async_mode_enabled()) << "round " << round << ": async logging resurrected after shutdown";
    }
}

// A reconfigure that changes the timestamp format must reach the live async writer, not just the
// synchronous banner. enable_async_mode snapshots the format into the writer's private config; reconfigure now pushes
// the new format so async lines pick it up instead of keeping the stale format for the life of the writer.
TEST_F(LoggerTest, ReconfigureFormatReachesLiveAsyncWriter)
{
    const auto file_a = m_test_log_file; // cleaned by TearDown
    const auto file_b = std::filesystem::temp_directory_path() /
                        ("test_logger_reconfigure_format_" + std::to_string(GetCurrentProcessId()) + ".log");

    // strftime passes literal (non-%) text through verbatim, so these format strings are deterministic markers.
    Logger::configure("TEST", file_a.string(), "FMT_ALPHA");
    Logger &lg = log();
    lg.enable_async_mode();

    lg.info("line-in-alpha");
    lg.flush();

    // Reconfigure to a new file AND a new format while async is live. The async writer shares the reopened stream and
    // must have its format snapshot refreshed to FMT_BRAVO by the reconfigure push.
    Logger::configure("TEST", file_b.string(), "FMT_BRAVO");
    lg.info("line-in-bravo");
    lg.flush();
    lg.disable_async_mode();

    const auto slurp = [](const std::filesystem::path &p)
    {
        std::ifstream ifs(p);
        std::stringstream ss;
        ss << ifs.rdbuf();
        return ss.str();
    };

    const std::string a = slurp(file_a);
    const std::string b = slurp(file_b);

    std::error_code ec;
    std::filesystem::remove(file_b, ec);

    EXPECT_NE(a.find("line-in-alpha"), std::string::npos);
    EXPECT_NE(a.find("[FMT_ALPHA"), std::string::npos);

    // Inspect the async line in the reconfigured file directly: it must carry the NEW format, never the stale one.
    bool bravo_line_seen = false;
    std::istringstream iss(b);
    for (std::string line; std::getline(iss, line);)
    {
        if (line.find("line-in-bravo") != std::string::npos)
        {
            bravo_line_seen = true;
            EXPECT_NE(line.find("[FMT_BRAVO"), std::string::npos)
                << "async writer kept the stale timestamp format after reconfigure: " << line;
            EXPECT_EQ(line.find("FMT_ALPHA"), std::string::npos)
                << "async line still stamped with the pre-reconfigure format: " << line;
        }
    }
    EXPECT_TRUE(bravo_line_seen) << "async line missing from the reconfigured file";
}

namespace DetourModKit::detail
{
    extern bool (*g_async_logger_loader_lock_override)() noexcept;
    extern std::atomic<std::atomic<bool> *> g_async_logger_writer_gate;
} // namespace DetourModKit::detail

namespace
{
    bool logger_detach_always_true_loader_lock() noexcept
    {
        return true;
    }

    class LoggerSeamReset
    {
    public:
        explicit LoggerSeamReset(std::atomic<bool> *writer_gate) noexcept : m_writer_gate(writer_gate) {}

        ~LoggerSeamReset() noexcept
        {
            m_writer_gate->store(false, std::memory_order_release);
            DetourModKit::detail::g_async_logger_writer_gate.store(nullptr, std::memory_order_release);
            DetourModKit::detail::g_async_logger_loader_lock_override = nullptr;
        }

        LoggerSeamReset(const LoggerSeamReset &) = delete;
        LoggerSeamReset &operator=(const LoggerSeamReset &) = delete;
        LoggerSeamReset(LoggerSeamReset &&) = delete;
        LoggerSeamReset &operator=(LoggerSeamReset &&) = delete;

    private:
        std::atomic<bool> *m_writer_gate;
    };
} // namespace

TEST_F(LoggerTest, DroppedCountSurvivesNormalAsyncDisable)
{
    const auto async_file = std::filesystem::temp_directory_path() /
                            ("test_logger_drop_retirement_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::error_code error_code;
    std::filesystem::remove(async_file, error_code);

    Logger logger("TEST", async_file.string(), "%H:%M:%S");
    static std::atomic<bool> writer_gate{true};
    writer_gate.store(true, std::memory_order_release);
    DetourModKit::detail::g_async_logger_writer_gate.store(&writer_gate, std::memory_order_release);
    LoggerSeamReset seam_reset{&writer_gate};

    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1;
    config.flush_interval = std::chrono::seconds{1};
    config.overflow_policy = OverflowPolicy::DropNewest;
    logger.enable_async_mode(config);
    EXPECT_TRUE(logger.is_async_mode_enabled());

    const std::size_t baseline = logger.dropped_count();
    for (int i = 0; i < 8; ++i)
    {
        (void)logger.log(LogLevel::Info, "DROP_RETIREMENT_" + std::to_string(i));
    }
    const std::size_t before_disable = logger.dropped_count();
    EXPECT_GT(before_disable, baseline);

    writer_gate.store(false, std::memory_order_release);
    logger.disable_async_mode();
    EXPECT_FALSE(logger.is_async_mode_enabled());
    EXPECT_EQ(logger.dropped_count(), before_disable)
        << "retiring the async writer discarded its cumulative drop telemetry";

    std::filesystem::remove(async_file, error_code);
}

TEST_F(LoggerTest, LoaderLockDetachLeaksHandleAndKeepsSinkForTheRetainedWriter)
{
    const auto detach_file = std::filesystem::temp_directory_path() /
                             ("test_logger_detach_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::error_code error_code;
    std::filesystem::remove(detach_file, error_code);

    diagnostics::reset_intentional_leaks();
    const std::size_t leak_count_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger);

    // A process-lifetime flag so the detached writer never reads a dangling pointer after the test returns.
    static std::atomic<bool> writer_gate{true};
    writer_gate.store(true, std::memory_order_release);

    constexpr int MESSAGE_COUNT = 10;
    {
        Logger logger("TESTDETACH", detach_file.string(), "%H:%M:%S");
        AsyncLoggerConfig config;
        config.queue_capacity = 64;
        config.batch_size = 8;
        config.flush_interval = std::chrono::milliseconds{20};
        logger.enable_async_mode(config);
        ASSERT_TRUE(logger.is_async_mode_enabled());

        DetourModKit::detail::g_async_logger_writer_gate.store(&writer_gate, std::memory_order_release);
        DetourModKit::detail::g_async_logger_loader_lock_override = &logger_detach_always_true_loader_lock;
        LoggerSeamReset seam_reset{&writer_gate};

        for (int i = 0; i < MESSAGE_COUNT; ++i)
        {
            (void)logger.log(LogLevel::Info, "DETACH_SINK_" + std::to_string(i));
        }

        logger.shutdown();
        EXPECT_GE(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger), leak_count_before + 1)
            << "loader-lock shutdown must leak the AsyncLogger handle rather than dropping it";

        writer_gate.store(false, std::memory_order_release);

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        bool all_present = false;
        while (std::chrono::steady_clock::now() < deadline && !all_present)
        {
            std::ifstream input_stream(detach_file);
            const std::string content((std::istreambuf_iterator<char>(input_stream)), std::istreambuf_iterator<char>());
            all_present = true;
            for (int i = 0; i < MESSAGE_COUNT; ++i)
            {
                if (content.find("DETACH_SINK_" + std::to_string(i)) == std::string::npos)
                {
                    all_present = false;
                    break;
                }
            }
            if (!all_present)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        }
        EXPECT_TRUE(all_present) << "the retained writer did not deliver every message; the sink was closed on abandon";
    }

    // Best-effort removal; FILE_SHARE_DELETE allows it even with the leaked writer's handle still open.
    std::filesystem::remove(detach_file, error_code);
}

// Once shutdown has begun, the facade must drop a synchronous log rather than write it to the sink the detached
// writer now owns. On the loader-lock abandon path the sink stays OPEN, so without Logger::log()'s m_shutdown_called
// guard the facade would sync-write into the writer's file and interleave with its drain. This proves the guard: the
// post-shutdown marker never reaches the file, while the writer still delivers its own pre-shutdown messages.
TEST_F(LoggerTest, LoaderLockAbandonDropsFacadeSyncWriteToWriterOwnedSink)
{
    const auto detach_file = std::filesystem::temp_directory_path() /
                             ("test_logger_facade_drop_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::error_code error_code;
    std::filesystem::remove(detach_file, error_code);

    // A process-lifetime flag so the detached writer never reads a dangling pointer after the test returns.
    static std::atomic<bool> writer_gate{true};
    writer_gate.store(true, std::memory_order_release);

    constexpr int MESSAGE_COUNT = 6;
    {
        Logger logger("TESTDROP", detach_file.string(), "%H:%M:%S");
        AsyncLoggerConfig config;
        config.queue_capacity = 64;
        config.batch_size = 8;
        config.flush_interval = std::chrono::milliseconds{20};
        logger.enable_async_mode(config);
        ASSERT_TRUE(logger.is_async_mode_enabled());

        DetourModKit::detail::g_async_logger_writer_gate.store(&writer_gate, std::memory_order_release);
        DetourModKit::detail::g_async_logger_loader_lock_override = &logger_detach_always_true_loader_lock;
        LoggerSeamReset seam_reset{&writer_gate};

        for (int i = 0; i < MESSAGE_COUNT; ++i)
        {
            (void)logger.log(LogLevel::Info, "FACADE_KEEP_" + std::to_string(i));
        }

        // Loader-lock abandon: the writer is detached and the sink stays open under its ownership.
        logger.shutdown();

        // The facade must refuse a synchronous write now, even though the sink is still open.
        EXPECT_FALSE(logger.log(LogLevel::Error, "FACADE_POST_SHUTDOWN_DROP"));

        // A reconfigure after a detached-writer teardown must not reopen a sink: the detached writer owns the current
        // sink for the process lifetime, so reopening (to any file) would create a second sink owner racing it. The
        // teardown leaves both m_shutdown_called and m_async_writer_abandoned set and reconfigure honors both, so the
        // rival file must never be created and the facade must stay closed.
        const auto rival_file = std::filesystem::temp_directory_path() /
                                ("test_logger_facade_rival_" + std::to_string(GetCurrentProcessId()) + ".log");
        std::filesystem::remove(rival_file, error_code);
        logger.reconfigure("TESTDROP", rival_file.string(), "%H:%M:%S");
        EXPECT_FALSE(std::filesystem::exists(rival_file))
            << "reconfigure reopened a sink retained by the detached writer";
        EXPECT_FALSE(logger.log(LogLevel::Error, "FACADE_POST_RECONFIGURE_DROP"))
            << "reconfigure revived a facade whose sink the detached writer owns";
        std::filesystem::remove(rival_file, error_code);

        // Release the writer; it drains the pre-shutdown messages into the sink it exclusively owns.
        writer_gate.store(false, std::memory_order_release);

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        bool all_present = false;
        while (std::chrono::steady_clock::now() < deadline && !all_present)
        {
            std::ifstream input_stream(detach_file);
            const std::string content((std::istreambuf_iterator<char>(input_stream)), std::istreambuf_iterator<char>());
            all_present = true;
            for (int i = 0; i < MESSAGE_COUNT; ++i)
            {
                if (content.find("FACADE_KEEP_" + std::to_string(i)) == std::string::npos)
                {
                    all_present = false;
                    break;
                }
            }
            if (!all_present)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        }
        ASSERT_TRUE(all_present) << "the retained writer did not deliver the pre-shutdown messages";

        // The dropped facade write must never appear in the writer-owned sink.
        std::ifstream input_stream(detach_file);
        const std::string content((std::istreambuf_iterator<char>(input_stream)), std::istreambuf_iterator<char>());
        EXPECT_EQ(content.find("FACADE_POST_SHUTDOWN_DROP"), std::string::npos)
            << "facade wrote synchronously to the sink the detached writer owns after shutdown began";
    }

    std::filesystem::remove(detach_file, error_code);
}

// A same-file reconfigure that only changes an option (timestamp format here) must keep the open stream and its
// existing records, never truncate them.
TEST_F(LoggerTest, ReconfigureSameFileDifferentFormatPreservesRecords)
{
    Logger &logger = log();
    logger.info("MARKER_BEFORE_RECONFIGURE");
    logger.flush();

    Logger::configure("TEST", m_test_log_file.string(), "%H:%M:%S");
    logger.info("MARKER_AFTER_RECONFIGURE");
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    const std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("MARKER_BEFORE_RECONFIGURE"), std::string::npos)
        << "a same-file reconfigure truncated existing records";
    EXPECT_NE(content.find("MARKER_AFTER_RECONFIGURE"), std::string::npos);
}

// configure() is the authoritative reset path: after a shutdown it re-enables the logger by reopening the sink in
// append mode, so the pre-shutdown records survive and new records land.
TEST_F(LoggerTest, ConfigureAfterShutdownReopensInAppendAndLogs)
{
    Logger &logger = log();
    logger.info("BEFORE_SHUTDOWN");
    logger.flush();
    logger.shutdown();

    EXPECT_FALSE(logger.log(LogLevel::Info, "DURING_SHUTDOWN")) << "a shut-down logger must drop writes";

    Logger::configure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
    EXPECT_TRUE(logger.log(LogLevel::Info, "AFTER_RECONFIGURE"));
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    const std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("BEFORE_SHUTDOWN"), std::string::npos) << "reopen truncated the pre-shutdown records";
    EXPECT_EQ(content.find("DURING_SHUTDOWN"), std::string::npos);
    EXPECT_NE(content.find("AFTER_RECONFIGURE"), std::string::npos);
}

// configure() and shutdown() are serialized on the same sink lock, so racing them must not crash, hang, or leave a
// torn sink state; a final configure must leave the logger usable.
TEST_F(LoggerTest, ConcurrentConfigureAndShutdownStayConsistent)
{
    Logger &logger = log();

    constexpr int ITERATIONS = 50;
    for (int i = 0; i < ITERATIONS; ++i)
    {
        std::thread shutter([&logger]() noexcept { logger.shutdown(); });
        std::thread configurer([this]() noexcept
                               { Logger::configure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S"); });
        shutter.join();
        configurer.join();
    }

    Logger::configure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
    EXPECT_TRUE(logger.log(LogLevel::Info, "RECOVERED_AFTER_RACE"));
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    const std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("RECOVERED_AFTER_RACE"), std::string::npos);
}

TEST_F(LoggerTest, ConfigureInsideShutdownGapCannotOutliveShutdown)
{
    Logger &logger = log();
    g_gap_probe_ran.store(false, std::memory_order_release);
    g_gap_configure_succeeded.store(false, std::memory_order_release);
    g_gap_configure_file = m_test_log_file.string();

    // Run configure after shutdown has dropped its async mutex but before it closes the sink. Shutdown must restore
    // its terminal state when it continues; otherwise this configure clears the gate while shutdown still closes the
    // file, leaving a closed facade that incorrectly accepts a later instance reconfigure.
    DetourModKit::detail::g_logger_shutdown_gap_probe = []() noexcept
    {
        try
        {
            Logger::configure("TEST", g_gap_configure_file, "%Y-%m-%d %H:%M:%S");
            g_gap_configure_succeeded.store(true, std::memory_order_release);
        }
        catch (...)
        {
        }
        g_gap_probe_ran.store(true, std::memory_order_release);
    };

    logger.shutdown();
    DetourModKit::detail::g_logger_shutdown_gap_probe = nullptr;
    EXPECT_TRUE(g_gap_probe_ran.load(std::memory_order_acquire));
    EXPECT_TRUE(g_gap_configure_succeeded.load(std::memory_order_acquire));

    const auto forbidden_file = std::filesystem::temp_directory_path() /
                                ("test_logger_shutdown_winner_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::error_code error_code;
    std::filesystem::remove(forbidden_file, error_code);
    logger.reconfigure("TEST", forbidden_file.string(), "%H:%M:%S");
    EXPECT_FALSE(logger.log(LogLevel::Info, "MUST_REMAIN_SHUT_DOWN"));

    Logger::configure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
    EXPECT_TRUE(logger.log(LogLevel::Info, "RECOVERED_BY_AUTHORITATIVE_CONFIGURE"));
    std::filesystem::remove(forbidden_file, error_code);
}

// A synchronous write to a sink that never opened is a lost message; dropped_count() must report it so consumers can
// observe delivery health.
TEST_F(LoggerTest, DroppedCountReportsSyncSinkFailures)
{
    const auto bad_path =
        (std::filesystem::temp_directory_path() / "dmk_missing_log_directory" / "nested" / "log.txt").string();
    Logger dedicated("TEST", bad_path);

    const std::size_t before = dedicated.dropped_count();
    EXPECT_FALSE(dedicated.log(LogLevel::Info, "lost_1"));
    EXPECT_FALSE(dedicated.log(LogLevel::Warning, "lost_2"));
    EXPECT_EQ(dedicated.dropped_count(), before + 2);
}
