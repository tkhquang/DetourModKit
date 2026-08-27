#include <gtest/gtest.h>
#include <array>
#include <clocale>
#include <fstream>
#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <process.h>
#include <stdexcept>
#include <type_traits>
#include <windows.h>
#include <atomic>

#include "DetourModKit/logger.hpp"
#include "DetourModKit/diagnostics.hpp"

#include "internal/async_logger.hpp"
#include "internal/logger_test_seams.hpp"

#include "test_alloc_probe.hpp"

using namespace DetourModKit;

namespace DetourModKit::detail
{
    extern void (*g_logger_level_transition_probe)() noexcept;
} // namespace DetourModKit::detail

namespace
{
    std::atomic<unsigned> s_level_transition_arrivals{0};
    std::atomic<bool> s_level_transition_release{false};
    std::atomic<bool> s_level_transition_timed_out{false};
    std::atomic<unsigned> s_activation_log_counter{0};

    [[nodiscard]] std::filesystem::path unique_activation_log_path(std::string_view stem)
    {
        const unsigned counter = s_activation_log_counter.fetch_add(1, std::memory_order_relaxed);
        return std::filesystem::temp_directory_path() /
               (std::string(stem) + "_" + std::to_string(_getpid()) + "_" + std::to_string(counter) + ".log");
    }

    [[nodiscard]] std::string read_line_containing(const std::filesystem::path &path, std::string_view marker)
    {
        std::ifstream stream(path);
        for (std::string line; std::getline(stream, line);)
        {
            if (line.find(marker) != std::string::npos)
            {
                return line;
            }
        }
        return {};
    }

    [[nodiscard]] bool has_source_stamp(std::string_view line) noexcept
    {
        return line.find("] :: [") != std::string_view::npos;
    }

    void rendezvous_level_transition() noexcept
    {
        if (s_level_transition_arrivals.fetch_add(1, std::memory_order_acq_rel) + 1 == 2)
        {
            s_level_transition_release.store(true, std::memory_order_release);
            s_level_transition_release.notify_all();
            return;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        while (!s_level_transition_release.load(std::memory_order_acquire))
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                s_level_transition_timed_out.store(true, std::memory_order_release);
                s_level_transition_release.store(true, std::memory_order_release);
                s_level_transition_release.notify_all();
                return;
            }
            std::this_thread::yield();
        }
    }

    class LevelTransitionProbeScope
    {
    public:
        LevelTransitionProbeScope() noexcept
        {
            s_level_transition_arrivals.store(0, std::memory_order_release);
            s_level_transition_release.store(false, std::memory_order_release);
            s_level_transition_timed_out.store(false, std::memory_order_release);
            DetourModKit::detail::g_logger_level_transition_probe = &rendezvous_level_transition;
        }

        ~LevelTransitionProbeScope() noexcept
        {
            s_level_transition_release.store(true, std::memory_order_release);
            s_level_transition_release.notify_all();
            DetourModKit::detail::g_logger_level_transition_probe = nullptr;
        }

        LevelTransitionProbeScope(const LevelTransitionProbeScope &) = delete;
        LevelTransitionProbeScope &operator=(const LevelTransitionProbeScope &) = delete;

        [[nodiscard]] bool timed_out() const noexcept
        {
            return s_level_transition_timed_out.load(std::memory_order_acquire);
        }
    };
} // namespace

// The loader-lock path in Logger::shutdown_internal and disable_async_mode() drops the facade's handle and leaves the
// writer standing on the retention root it was published with. Both are noexcept teardowns, so pin that neither the
// copy that arms the root nor the reset that drops the handle can throw.
static_assert(
    std::is_nothrow_copy_constructible_v<std::shared_ptr<AsyncLogger>> &&
        std::is_nothrow_copy_assignable_v<std::shared_ptr<AsyncLogger>>,
    "arming the AsyncLogger retention root must not throw, or the noexcept ~Logger contract becomes "
    "std::terminate."
);

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
            }
        );
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

TEST_F(LoggerTest, StringToLogLevelUsesAsciiFold)
{
    // [B-37]: the level parse must fold ASCII and nothing else, so LC_CTYPE cannot change which name a config file
    // resolves to. Turkish is the classic counterexample locale for a locale-sensitive fold of 'i'.
    struct CtypeLocale
    {
        explicit CtypeLocale(const char *name) : m_restore(std::setlocale(LC_CTYPE, nullptr))
        {
            m_set = std::setlocale(LC_CTYPE, name);
        }
        ~CtypeLocale() noexcept { std::setlocale(LC_CTYPE, m_restore.c_str()); }
        CtypeLocale(const CtypeLocale &) = delete;
        CtypeLocale &operator=(const CtypeLocale &) = delete;
        CtypeLocale(CtypeLocale &&) = delete;
        CtypeLocale &operator=(CtypeLocale &&) = delete;
        [[nodiscard]] bool installed() const noexcept { return m_set != nullptr; }

        std::string m_restore;
        const char *m_set{nullptr};
    };

    for (const char *name : {"C", "turkish", "greek", "russian"})
    {
        const CtypeLocale locale(name);
        if (!locale.installed())
        {
            continue;
        }
        EXPECT_EQ(string_to_log_level("trace"), LogLevel::Trace) << name;
        EXPECT_EQ(string_to_log_level("dEbUg"), LogLevel::Debug) << name;
        EXPECT_EQ(string_to_log_level("warning"), LogLevel::Warning) << name;
        EXPECT_EQ(string_to_log_level("ERROR"), LogLevel::Error) << name;

        // Each installed locale must leave high-byte inputs outside the ASCII level names.
        for (int candidate = 0x80; candidate <= 0xFF; ++candidate)
        {
            std::string spelled = "WARN";
            spelled.push_back(static_cast<char>(candidate));
            spelled += "NG";
            EXPECT_EQ(string_to_log_level(spelled), LogLevel::Info)
                << name << ": byte " << candidate << " must not fold into a level name";
        }
    }
}

TEST_F(LoggerTest, LongFormatString)
{
    Logger &logger = log();

    EXPECT_NO_THROW(logger.info(
        "This is a very long format string with many placeholders: {} {} {} {} {} {} {} {} {} {}",
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10
    ));
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

    // LogLevel's base is std::uint8_t, so the top of that base is the last value an out-of-range cast can produce.
    // set_log_level checks the upper bound only, and this pins that the bound still covers the whole domain.
    static_assert(
        std::is_same_v<std::underlying_type_t<LogLevel>, std::uint8_t>,
        "set_log_level's single-bound range check assumes an unsigned base"
    );
    logger.set_log_level(static_cast<LogLevel>(std::numeric_limits<std::uint8_t>::max()));
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
            }
        );
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
        }
    );

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
        }
    );

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
        }
    );

    threads.emplace_back(
        [&stop, this]()
        {
            for (int i = 0; i < 50; ++i)
            {
                Logger::configure("PREFIX_" + std::to_string(i), m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
            }
            stop.store(true, std::memory_order_release);
        }
    );

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

    // The staged transaction opens the replacement before it retires the live sink, so a failed open leaves the prior
    // sink OPEN. A best-effort reopen cannot give that guarantee, which is why the later record is the real oracle.
    EXPECT_TRUE(logger.log(LogLevel::Info, "AFTER_INVALID_RECONFIG_9p2x"));
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("BEFORE_INVALID_RECONFIG_3k7m"), std::string::npos);
    EXPECT_NE(content.find("AFTER_INVALID_RECONFIG_9p2x"), std::string::npos);
}

TEST_F(LoggerTest, Configure_InvalidPath_KeepsOldSink)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);
    const auto accepted_snapshot = detail::LoggerTestSeams::static_config_for_test();

    logger.info("BEFORE_INVALID_CONFIGURE_5t1r");
    logger.flush();

    Logger::configure("BAD_CONFIG", "Z:\\nonexistent\\dir\\configure.log", "%H:%M:%S");

    EXPECT_EQ(detail::LoggerTestSeams::static_config_for_test(), accepted_snapshot);
    EXPECT_TRUE(logger.log(LogLevel::Info, "AFTER_INVALID_CONFIGURE_6h8d"));
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("BEFORE_INVALID_CONFIGURE_5t1r"), std::string::npos);
    EXPECT_NE(content.find("AFTER_INVALID_CONFIGURE_6h8d"), std::string::npos);
}

TEST_F(LoggerTest, Configure_AllocationFailureRestoresPublishedSnapshot)
{
    DMK_REQUIRE_PROXY_FREE_STL();

    static std::atomic<int> s_configure_alloc_counter{0};
    const auto target = std::filesystem::temp_directory_path() /
                        ("test_logger_configure_alloc_" + std::to_string(GetCurrentProcessId()) + "_" +
                         std::to_string(s_configure_alloc_counter.fetch_add(1, std::memory_order_relaxed)) + ".log");
    const std::string prior_prefix(48, 'P');
    const std::string target_prefix(48, 'T');
    const std::string prior_timestamp(48, 'A');
    const std::string target_timestamp(48, 'B');
    const std::string prior_file = m_test_log_file.string();
    const std::string target_file = target.string();

    Logger::configure(prior_prefix, prior_file, prior_timestamp, LogOpenMode::Append);
    const long long allocation_count_before = dmk_test::thread_new_calls();
    Logger::configure(prior_prefix, prior_file, prior_timestamp, LogOpenMode::Append);
    const long long publication_allocations = dmk_test::thread_new_calls() - allocation_count_before;
    const auto prior_snapshot = detail::LoggerTestSeams::static_config_for_test();
    ASSERT_GT(publication_allocations, 0);

    constexpr long long max_allocation_budget = 64;
    long long failures = 0;
    bool completed = false;
    for (long long allow = 0; allow < max_allocation_budget && !completed; ++allow)
    {
        try
        {
            const dmk_test::AllocFailScope guard(allow);
            Logger::configure(target_prefix, target_file, target_timestamp, LogOpenMode::Append);
            completed = true;
        }
        catch (const std::bad_alloc &)
        {
            ++failures;
        }

        if (!completed)
        {
            EXPECT_EQ(detail::LoggerTestSeams::static_config_for_test(), prior_snapshot)
                << "budget " << allow << " left the staged snapshot published after configure threw";
        }
    }

    EXPECT_GT(failures, publication_allocations)
        << "the sweep did not reach a reconfigure allocation after snapshot publication";
    ASSERT_TRUE(completed) << "configure never completed within the allocation budget";
    const auto committed_snapshot = detail::LoggerTestSeams::static_config_for_test();
    ASSERT_NE(committed_snapshot, prior_snapshot) << "configure rejected the final allocation budget";
    EXPECT_EQ(committed_snapshot->log_prefix, target_prefix);
    EXPECT_EQ(committed_snapshot->log_file_name, target_file);
    EXPECT_EQ(committed_snapshot->timestamp_format, target_timestamp);

    Logger::configure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
    std::error_code error_code;
    (void)std::filesystem::remove(target, error_code);
    EXPECT_FALSE(error_code) << "failed to remove configure target: " << error_code.message();
}

TEST_F(LoggerTest, Reconfigure_AllocationFailure_KeepsOldSink)
{
    DMK_REQUIRE_PROXY_FREE_STL();

    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);
    logger.info("BEFORE_ALLOC_FAIL_RECONFIG_4c9v");
    logger.flush();

    static std::atomic<int> s_alloc_reconfig_counter{0};
    const auto target = std::filesystem::temp_directory_path() /
                        ("test_logger_alloc_reconfig_" + std::to_string(GetCurrentProcessId()) + "_" +
                         std::to_string(s_alloc_reconfig_counter.fetch_add(1)) + ".log");
    const std::string target_path = target.string();
    std::error_code initial_cleanup_error;
    (void)std::filesystem::remove(target, initial_cleanup_error);
    ASSERT_FALSE(initial_cleanup_error) << "failed to clear allocation target: " << initial_cleanup_error.message();

    // The allocation sweep requires a live prior sink and no replacement file after each failure. All allocation
    // precedes file creation, so an allocation failure cannot reach CreateFile.
    int failures = 0;
    bool completed = false;
    constexpr long long max_allocation_budget = 64;
    for (long long allow = 0; allow < max_allocation_budget && !completed; ++allow)
    {
        try
        {
            const dmk_test::AllocFailScope guard(allow);
            logger.reconfigure("ALLOC_FAIL", target_path, "%H:%M:%S");
            completed = true;
        }
        catch (const std::bad_alloc &)
        {
            ++failures;
        }
        if (!completed)
        {
            EXPECT_FALSE(std::filesystem::exists(target))
                << "budget " << allow << " created the replacement file after an allocation failure";
            EXPECT_TRUE(logger.log(LogLevel::Info, "AFTER_ALLOC_FAIL_RECONFIG_7b2k"))
                << "budget " << allow << " left the prior sink unusable";
        }
    }
    EXPECT_GT(failures, 0) << "no staged allocation failed, so the rollback path was never reached";
    ASSERT_TRUE(completed) << "reconfigure never completed within the allocation budget";
    ASSERT_TRUE(logger.log(LogLevel::Info, "AFTER_ALLOC_COMMIT_1f6w"));
    logger.flush();

    {
        std::ifstream prior_input(m_test_log_file);
        ASSERT_TRUE(prior_input.is_open());
        const std::string prior_content(
            (std::istreambuf_iterator<char>(prior_input)),
            std::istreambuf_iterator<char>()
        );
        EXPECT_NE(prior_content.find("BEFORE_ALLOC_FAIL_RECONFIG_4c9v"), std::string::npos);
        EXPECT_NE(prior_content.find("AFTER_ALLOC_FAIL_RECONFIG_7b2k"), std::string::npos);
    }

    {
        std::ifstream target_input(target);
        ASSERT_TRUE(target_input.is_open()) << "reconfigure rejected the final allocation budget";
        const std::string target_content(
            (std::istreambuf_iterator<char>(target_input)),
            std::istreambuf_iterator<char>()
        );
        EXPECT_NE(target_content.find("AFTER_ALLOC_COMMIT_1f6w"), std::string::npos);
    }

    logger.reconfigure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
    logger.flush();
    std::error_code cleanup_error;
    (void)std::filesystem::remove(target, cleanup_error);
    EXPECT_FALSE(cleanup_error) << "failed to remove allocation target: " << cleanup_error.message();
}

TEST_F(LoggerTest, LogNoexceptCountsASuppressedSinkFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();

    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);
    logger.info("warm the synchronous sink");
    logger.flush();

    const std::size_t before = logger.dropped_count();
    bool delivered = true;
    {
        const dmk_test::AllocFailScope guard(0);
        delivered = logger.log_noexcept(LogLevel::Info, "NOEXCEPT_DROP_COUNT_PROBE");
    }

    EXPECT_FALSE(delivered);
    EXPECT_EQ(logger.dropped_count(), before + 1) << "a record lost to a suppressed throw must still be counted";
}

TEST_F(LoggerTest, TryLogCountsAFormatFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();

    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);
    logger.info("warm the synchronous sink");
    logger.flush();

    // The oversized message selects the documented std::format overflow path and forces an allocation.
    const std::string oversize(LOG_INLINE_MESSAGE_SIZE + 64, 'x');
    const std::size_t before = logger.dropped_count();
    bool delivered = true;
    {
        const dmk_test::AllocFailScope guard(0);
        delivered = logger.try_log(LogLevel::Info, "{}", oversize);
    }

    EXPECT_FALSE(delivered);
    EXPECT_EQ(logger.dropped_count(), before + 1) << "a record lost to a format failure must be counted once";
}

TEST_F(LoggerTest, LogNoexceptCountsARefusedRecordOnce)
{
    // The sink already counts what it refuses, so the no-throw wrapper must not add a second charge for it.
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);
    logger.shutdown();

    const std::size_t before = logger.dropped_count();
    EXPECT_FALSE(logger.log_noexcept(LogLevel::Error, "REFUSED_AFTER_SHUTDOWN_1q4z"));
    EXPECT_EQ(logger.dropped_count(), before + 1);
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
    EXPECT_TRUE(logger.is_async_mode_enabled())
        << "reconfigure retired the async transport instead of the required handoff";

    logger.info("ASYNC_RECONFIG_VERIFY_8n4j");
    logger.flush();
    logger.disable_async_mode();

    {
        std::ifstream new_input(new_file);
        ASSERT_TRUE(new_input.is_open());
        const std::string content((std::istreambuf_iterator<char>(new_input)), std::istreambuf_iterator<char>());
        EXPECT_NE(content.find("ASYNC_RECONFIG_VERIFY_8n4j"), std::string::npos);

        // The commit hands the new sink to the live writer. Without that handoff, the record stays in the old file.
        std::ifstream old_input(m_test_log_file);
        ASSERT_TRUE(old_input.is_open());
        const std::string old_content((std::istreambuf_iterator<char>(old_input)), std::istreambuf_iterator<char>());
        EXPECT_EQ(old_content.find("ASYNC_RECONFIG_VERIFY_8n4j"), std::string::npos);
    }

    logger.reconfigure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S");
    logger.flush();
    std::error_code cleanup_error;
    (void)std::filesystem::remove(new_file, cleanup_error);
    EXPECT_FALSE(cleanup_error) << "failed to remove async reconfigure target: " << cleanup_error.message();
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
            }
        );
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
        }
    );

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
    HANDLE external_handle = CreateFileA(
        m_test_log_file.string().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
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
    HANDLE exclusive_handle = CreateFileA(
        m_test_log_file.string().c_str(),
        GENERIC_READ,
        0, // No sharing: exclusive lock
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

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

        HANDLE h = CreateFileA(
            m_test_log_file.string().c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

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

    HANDLE external_handle = CreateFileA(
        m_test_log_file.string().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
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

    // Stabilize: set to Trace, then set again. The second call must be silent.
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

TEST_F(LoggerTest, SetLogLevel_ChangedThresholdsEmitInfoControlRecord)
{
    // The control route keeps each upward threshold change visible.
    Logger &logger = log();

    logger.set_log_level(LogLevel::Info);
    logger.set_log_level(LogLevel::Warning);
    logger.set_log_level(LogLevel::Info);
    logger.set_log_level(LogLevel::Error);
    logger.set_log_level(LogLevel::Warning);
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    const auto count_records = [&](std::string_view text) -> std::size_t
    {
        std::size_t count = 0;
        for (std::size_t pos = 0; (pos = content.find(text, pos)) != std::string::npos; pos += text.size())
        {
            ++count;
        }
        return count;
    };

    EXPECT_EQ(count_records("Log level changed from INFO to WARNING"), 1u);
    EXPECT_EQ(count_records("Log level changed from INFO to ERROR"), 1u);
    EXPECT_EQ(count_records("Log level changed from ERROR to WARNING"), 1u);

    // The control record carries the Info level, not the new threshold.
    std::string record_line;
    std::istringstream lines(content);
    for (std::string line; std::getline(lines, line);)
    {
        if (line.find("Log level changed from INFO to ERROR") != std::string::npos)
        {
            record_line = line;
            break;
        }
    }
    ASSERT_FALSE(record_line.empty());
    EXPECT_NE(record_line.find("[INFO   ] ::"), std::string::npos) << "control record line: " << record_line;
    EXPECT_NE(record_line.find("] :: [logger.cpp:"), std::string::npos) << "control record line: " << record_line;

    logger.set_log_level(LogLevel::Info);
}

TEST_F(LoggerTest, SetLogLevel_ConcurrentSameTargetEmitsOneControlRecord)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);
    logger.info("MARKER_BEFORE_SAME_TARGET_f3q9");

    bool rendezvous_timed_out = false;
    {
        std::jthread first;
        std::jthread second;
        LevelTransitionProbeScope probe;
        first = std::jthread([&logger] { logger.set_log_level(LogLevel::Warning); });
        second = std::jthread([&logger] { logger.set_log_level(LogLevel::Warning); });
        first.join();
        second.join();
        rendezvous_timed_out = probe.timed_out();
    }
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    const std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    const std::size_t marker_pos = content.find("MARKER_BEFORE_SAME_TARGET_f3q9");
    ASSERT_NE(marker_pos, std::string::npos);

    std::size_t count = 0;
    constexpr std::string_view transition = "Log level changed";
    for (std::size_t pos = marker_pos; (pos = content.find(transition, pos)) != std::string::npos;
         pos += transition.size())
    {
        ++count;
    }
    EXPECT_FALSE(rendezvous_timed_out);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(logger.get_log_level(), LogLevel::Warning);

    logger.set_log_level(LogLevel::Info);
}

TEST_F(LoggerTest, SetLogLevel_ConcurrentDifferentTargetsCommitBothTransitions)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Info);
    logger.info("MARKER_BEFORE_DIFFERENT_TARGETS_j6m4");

    bool rendezvous_timed_out = false;
    {
        std::jthread first;
        std::jthread second;
        LevelTransitionProbeScope probe;
        first = std::jthread([&logger] { logger.set_log_level(LogLevel::Warning); });
        second = std::jthread([&logger] { logger.set_log_level(LogLevel::Error); });
        first.join();
        second.join();
        rendezvous_timed_out = probe.timed_out();
    }
    logger.flush();

    std::ifstream ifs(m_test_log_file);
    ASSERT_TRUE(ifs.is_open());
    const std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    const std::size_t marker_pos = content.find("MARKER_BEFORE_DIFFERENT_TARGETS_j6m4");
    ASSERT_NE(marker_pos, std::string::npos);
    const std::string_view transitions{content.data() + marker_pos, content.size() - marker_pos};

    const auto count_records = [&](std::string_view text) -> std::size_t
    {
        std::size_t count = 0;
        for (std::size_t pos = 0; (pos = transitions.find(text, pos)) != std::string::npos; pos += text.size())
        {
            ++count;
        }
        return count;
    };

    EXPECT_FALSE(rendezvous_timed_out);
    const LogLevel final_level = logger.get_log_level();
    if (final_level == LogLevel::Error)
    {
        EXPECT_EQ(count_records("Log level changed from INFO to WARNING"), 1u);
        EXPECT_EQ(count_records("Log level changed from WARNING to ERROR"), 1u);
    }
    else
    {
        ASSERT_EQ(final_level, LogLevel::Warning);
        EXPECT_EQ(count_records("Log level changed from INFO to ERROR"), 1u);
        EXPECT_EQ(count_records("Log level changed from ERROR to WARNING"), 1u);
    }
    EXPECT_EQ(count_records("Log level changed"), 2u);

    logger.set_log_level(LogLevel::Info);
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

    const LogLevel all_levels[] =
        {LogLevel::Trace, LogLevel::Debug, LogLevel::Info, LogLevel::Warning, LogLevel::Error};

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

    EXPECT_TRUE(
        stderr_output.find("LOG_FILE_WRITE_ERROR") != std::string::npos ||
        stderr_output.find("CRITICAL ERROR") != std::string::npos
    );
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
    static_assert(
        noexcept(logger.log_noexcept(LogLevel::Info, "x")),
        "log_noexcept must be noexcept for noexcept-boundary callers"
    );

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

    // Control: a line longer than the inline buffer falls back to a heap std::format string and the StringPool overflow
    // path, so it must allocate. This proves the probe observes allocations and that the inline-fit path above
    // genuinely avoided them.
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

TEST_F(LoggerTest, SourceStampModePredicateTable)
{
    // An out-of-range level selects always(). An unclamped value of 255 compares as never().
    static_assert(LogSourceStampMode::at_or_below(static_cast<LogLevel>(5)) == LogSourceStampMode::always());
    static_assert(LogSourceStampMode::at_or_below(static_cast<LogLevel>(255)) == LogSourceStampMode::always());

    struct PolicyCase
    {
        LogSourceStampMode mode;
        std::array<bool, 5> expected;
    };

    constexpr std::array<LogLevel, 5> levels{
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warning,
        LogLevel::Error,
    };
    constexpr std::array<PolicyCase, 7> policies{
        PolicyCase{.mode = LogSourceStampMode::never(), .expected = {false, false, false, false, false}},
        PolicyCase{
            .mode = LogSourceStampMode::at_or_below(LogLevel::Trace),
            .expected = {true, false, false, false, false}
        },
        PolicyCase{
            .mode = LogSourceStampMode::at_or_below(LogLevel::Debug),
            .expected = {true, true, false, false, false}
        },
        PolicyCase{
            .mode = LogSourceStampMode::at_or_below(LogLevel::Info),
            .expected = {true, true, true, false, false}
        },
        PolicyCase{
            .mode = LogSourceStampMode::at_or_below(LogLevel::Warning),
            .expected = {true, true, true, true, false}
        },
        PolicyCase{
            .mode = LogSourceStampMode::at_or_below(LogLevel::Error),
            .expected = {true, true, true, true, true}
        },
        PolicyCase{.mode = LogSourceStampMode::always(), .expected = {true, true, true, true, true}},
    };

    for (const auto &policy : policies)
    {
        for (std::size_t i = 0; i < levels.size(); ++i)
        {
            EXPECT_EQ(policy.mode.renders(levels[i]), policy.expected[i]);
        }
    }
}

TEST_F(LoggerTest, SourceStampModeAtOrBelowDebugStampsTraceAndDebugOnly)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);
    logger.set_source_stamp_mode(LogSourceStampMode::at_or_below(LogLevel::Debug));

    logger.trace("STAMP_TABLE_TRACE");
    logger.debug("STAMP_TABLE_DEBUG");
    logger.info("STAMP_TABLE_INFO");
    logger.warning("STAMP_TABLE_WARNING");
    logger.error("STAMP_TABLE_ERROR");
    logger.flush();

    const std::array<std::pair<std::string_view, bool>, 5> expected{
        std::pair<std::string_view, bool>{"STAMP_TABLE_TRACE", true},
        std::pair<std::string_view, bool>{"STAMP_TABLE_DEBUG", true},
        std::pair<std::string_view, bool>{"STAMP_TABLE_INFO", false},
        std::pair<std::string_view, bool>{"STAMP_TABLE_WARNING", false},
        std::pair<std::string_view, bool>{"STAMP_TABLE_ERROR", false},
    };
    for (const auto &[marker, stamped] : expected)
    {
        const std::string line = read_line_containing(m_test_log_file, marker);
        ASSERT_FALSE(line.empty()) << marker;
        EXPECT_EQ(has_source_stamp(line), stamped) << line;
    }
}

TEST_F(LoggerTest, SourceStampModeNeverCoversTryLogAndOverflow)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);
    logger.set_source_stamp_mode(LogSourceStampMode::never());

    EXPECT_TRUE(logger.try_log(LogLevel::Debug, "TRYLOG_NO_STAMP_{}", 17));
    const std::string oversized(LOG_INLINE_MESSAGE_SIZE + 64, 'X');
    logger.info("OVERFLOW_NO_STAMP_{}", oversized);
    logger.set_source_stamp_mode(LogSourceStampMode::at_or_below(LogLevel::Debug));
    logger.debug("OVERFLOW_STAMPED_{}", oversized);
    logger.flush();

    const std::string try_log_line = read_line_containing(m_test_log_file, "TRYLOG_NO_STAMP_17");
    const std::string overflow_line = read_line_containing(m_test_log_file, "OVERFLOW_NO_STAMP_");
    const std::string stamped_overflow_line = read_line_containing(m_test_log_file, "OVERFLOW_STAMPED_");
    ASSERT_FALSE(try_log_line.empty());
    ASSERT_FALSE(overflow_line.empty());
    ASSERT_FALSE(stamped_overflow_line.empty());
    EXPECT_FALSE(has_source_stamp(try_log_line));
    EXPECT_FALSE(has_source_stamp(overflow_line));
    EXPECT_TRUE(has_source_stamp(stamped_overflow_line));
}

TEST_F(LoggerTest, SourceStampModeAccessorFlipAffectsLaterRecordsAndControlRecord)
{
    Logger &logger = log();
    logger.set_log_level(LogLevel::Trace);
    EXPECT_EQ(logger.get_source_stamp_mode(), LogSourceStampMode::always());

    logger.info("STAMP_BEFORE_MODE_FLIP");
    logger.set_source_stamp_mode(LogSourceStampMode::never());
    EXPECT_EQ(logger.get_source_stamp_mode(), LogSourceStampMode::never());
    logger.info("STAMP_AFTER_MODE_FLIP");
    logger.set_log_level(LogLevel::Warning);
    logger.flush();

    const std::string before = read_line_containing(m_test_log_file, "STAMP_BEFORE_MODE_FLIP");
    const std::string after = read_line_containing(m_test_log_file, "STAMP_AFTER_MODE_FLIP");
    const std::string control = read_line_containing(m_test_log_file, "Log level changed from TRACE to WARNING");
    ASSERT_FALSE(before.empty());
    ASSERT_FALSE(after.empty());
    ASSERT_FALSE(control.empty());
    EXPECT_TRUE(has_source_stamp(before));
    EXPECT_FALSE(has_source_stamp(after));
    EXPECT_FALSE(has_source_stamp(control));
}

TEST_F(LoggerTest, SourceStampModeConfigureCommitsOnlyAfterAcceptedSink)
{
    Logger &logger = log();
    const auto trace_and_debug = LogSourceStampMode::at_or_below(LogLevel::Debug);
    Logger::configure("TEST", m_test_log_file.string(), "%Y-%m-%d %H:%M:%S", LogOpenMode::Truncate, trace_and_debug);
    EXPECT_EQ(logger.get_source_stamp_mode(), trace_and_debug);
    EXPECT_EQ(detail::LoggerTestSeams::static_config_for_test()->source_stamp_mode, trace_and_debug);

    Logger::configure(
        "BAD_STAMP_CONFIG",
        "Z:\\nonexistent\\dir\\stamp_mode.log",
        "%H:%M:%S",
        LogOpenMode::Truncate,
        LogSourceStampMode::never()
    );
    EXPECT_EQ(logger.get_source_stamp_mode(), trace_and_debug);
    EXPECT_EQ(detail::LoggerTestSeams::static_config_for_test()->source_stamp_mode, trace_and_debug);
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
// shutdown_internal's dropped-mutex window (async already disabled, the sink stream NOT yet closed), which without
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
    // enable. If that gate is reverted, the enable spins up a fresh writer and is_async_mode_enabled() flips true
    // here, deterministic teeth for the gate specifically.
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
            }
        );
        lg.shutdown();
        racer.join();

        EXPECT_FALSE(lg.is_async_mode_enabled()) << "round " << round << ": async logging resurrected after shutdown";
    }
}

// A reconfigure that changes the timestamp format must reach the live async writer, not just the synchronous banner.
// enable_async_mode snapshots the format into the writer's private config; reconfigure now pushes the new format so
// async lines pick it up instead of keeping the stale format for the life of the writer.
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
    extern std::atomic<std::size_t> g_async_logger_live_count_for_test;
    extern void (*g_logger_publication_probe)();
    extern void (*g_logger_post_publication_probe)();
    extern void (*g_logger_async_snapshot_probe)() noexcept;
    extern int (*g_win_file_write_override)(void *, const void *, unsigned long, unsigned long *);
} // namespace DetourModKit::detail

namespace
{
    Logger *s_snapshot_probe_logger = nullptr;

    bool logger_detach_always_true_loader_lock() noexcept
    {
        return true;
    }

    void retire_snapshotted_async_writer() noexcept
    {
        s_snapshot_probe_logger->disable_async_mode();
    }

    int logger_write_always_fails(void *, const void *, unsigned long, unsigned long *written) noexcept
    {
        if (written != nullptr)
        {
            *written = 0;
        }
        return 0;
    }

    class LoggerSnapshotProbeScope
    {
    public:
        explicit LoggerSnapshotProbeScope(Logger &logger) noexcept
        {
            s_snapshot_probe_logger = &logger;
            DetourModKit::detail::g_logger_async_snapshot_probe = &retire_snapshotted_async_writer;
        }

        ~LoggerSnapshotProbeScope() noexcept
        {
            DetourModKit::detail::g_logger_async_snapshot_probe = nullptr;
            s_snapshot_probe_logger = nullptr;
        }

        LoggerSnapshotProbeScope(const LoggerSnapshotProbeScope &) = delete;
        LoggerSnapshotProbeScope &operator=(const LoggerSnapshotProbeScope &) = delete;
        LoggerSnapshotProbeScope(LoggerSnapshotProbeScope &&) = delete;
        LoggerSnapshotProbeScope &operator=(LoggerSnapshotProbeScope &&) = delete;
    };

    class LoggerWriteFailureScope
    {
    public:
        LoggerWriteFailureScope() noexcept
        {
            DetourModKit::detail::g_win_file_write_override = &logger_write_always_fails;
        }

        ~LoggerWriteFailureScope() noexcept { DetourModKit::detail::g_win_file_write_override = nullptr; }

        LoggerWriteFailureScope(const LoggerWriteFailureScope &) = delete;
        LoggerWriteFailureScope &operator=(const LoggerWriteFailureScope &) = delete;
        LoggerWriteFailureScope(LoggerWriteFailureScope &&) = delete;
        LoggerWriteFailureScope &operator=(LoggerWriteFailureScope &&) = delete;
    };

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

    [[noreturn]] void run_default_logger_disable_detach_probe()
    {
        static std::atomic<bool> writer_gate{true};
        writer_gate.store(true, std::memory_order_release);

        const auto log_file = std::filesystem::temp_directory_path() /
                              ("test_logger_default_detach_" + std::to_string(GetCurrentProcessId()) + ".log");
        const auto rival_file = std::filesystem::temp_directory_path() /
                                ("test_logger_default_rival_" + std::to_string(GetCurrentProcessId()) + ".log");
        std::error_code error_code;
        std::filesystem::remove(log_file, error_code);
        std::filesystem::remove(rival_file, error_code);

        Logger::configure("DEFAULT_DETACH", log_file.string(), "%H:%M:%S");
        Logger &logger = DetourModKit::log();
        const auto accepted_snapshot = detail::LoggerTestSeams::static_config_for_test();
        DetourModKit::detail::g_async_logger_writer_gate.store(&writer_gate, std::memory_order_release);
        DetourModKit::detail::g_async_logger_loader_lock_override = &logger_detach_always_true_loader_lock;

        AsyncLoggerConfig config;
        config.queue_capacity = 16;
        config.batch_size = 4;
        logger.enable_async_mode(config);
        if (!logger.is_async_mode_enabled() || !logger.log(LogLevel::Info, "DEFAULT_DETACH_PENDING"))
        {
            std::_Exit(31);
        }

        logger.disable_async_mode();
        Logger::configure("DEFAULT_RIVAL", rival_file.string(), "%H:%M:%S");
        const bool revived = DetourModKit::log().log(LogLevel::Error, "DEFAULT_DETACH_REVIVED");
        const bool snapshot_changed = detail::LoggerTestSeams::static_config_for_test() != accepted_snapshot;
        writer_gate.store(false, std::memory_order_release);
        std::_Exit(revived || snapshot_changed || std::filesystem::exists(rival_file) ? 32 : 0);
    }
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

TEST_F(LoggerTest, LateRetiredAsyncSnapshotCountsAtFacade)
{
    static std::atomic<int> s_snapshot_counter{0};
    const auto snapshot_file = std::filesystem::temp_directory_path() /
                               ("test_logger_stale_snapshot_" + std::to_string(GetCurrentProcessId()) + "_" +
                                std::to_string(s_snapshot_counter.fetch_add(1, std::memory_order_relaxed)) + ".log");
    std::error_code error_code;
    std::filesystem::remove(snapshot_file, error_code);

    Logger logger("STALE_SNAPSHOT", snapshot_file.string(), "%H:%M:%S");
    logger.enable_async_mode();
    ASSERT_TRUE(logger.is_async_mode_enabled());
    const std::size_t baseline = logger.dropped_count();

    bool accepted = true;
    {
        LoggerSnapshotProbeScope snapshot_probe{logger};
        accepted = logger.log(LogLevel::Info, "LATE_STALE_SNAPSHOT_7m3q");
    }

    EXPECT_FALSE(accepted);
    EXPECT_FALSE(logger.is_async_mode_enabled());
    EXPECT_EQ(logger.dropped_count(), baseline + 1)
        << "the retired writer rejected the stale snapshot but did not transfer the loss to the facade";

    logger.shutdown();
    (void)std::filesystem::remove(snapshot_file, error_code);
    EXPECT_FALSE(error_code) << "failed to remove stale-snapshot sink: " << error_code.message();
}

TEST_F(LoggerTest, ReconfigureFailedOldSinkDrainPreservesSinkAndBufferedRecord)
{
    static std::atomic<int> s_drain_counter{0};
    const int test_id = s_drain_counter.fetch_add(1, std::memory_order_relaxed);
    const auto old_file = std::filesystem::temp_directory_path() /
                          ("test_logger_failed_drain_old_" + std::to_string(GetCurrentProcessId()) + "_" +
                           std::to_string(test_id) + ".log");
    const auto candidate_file = std::filesystem::temp_directory_path() /
                                ("test_logger_failed_drain_new_" + std::to_string(GetCurrentProcessId()) + "_" +
                                 std::to_string(test_id) + ".log");
    std::error_code error_code;
    std::filesystem::remove(old_file, error_code);
    std::filesystem::remove(candidate_file, error_code);

    Logger logger("DRAIN_OLD", old_file.string(), "%H:%M:%S");
    ASSERT_TRUE(logger.log(LogLevel::Info, "BUFFERED_BEFORE_FAILED_DRAIN_2j8c"));
    {
        LoggerWriteFailureScope write_failure;
        logger.reconfigure("DRAIN_NEW", candidate_file.string(), "%H:%M:%S");
    }

    EXPECT_TRUE(logger.log(LogLevel::Info, "AFTER_FAILED_DRAIN_6p4v"));
    logger.flush();

    {
        std::ifstream old_input(old_file);
        ASSERT_TRUE(old_input.is_open());
        const std::string old_content((std::istreambuf_iterator<char>(old_input)), std::istreambuf_iterator<char>());
        EXPECT_NE(old_content.find("BUFFERED_BEFORE_FAILED_DRAIN_2j8c"), std::string::npos);
        EXPECT_NE(old_content.find("AFTER_FAILED_DRAIN_6p4v"), std::string::npos)
            << "failed retirement replaced the old sink instead of the required preservation";

        std::ifstream candidate_input(candidate_file);
        const std::string candidate_content(
            (std::istreambuf_iterator<char>(candidate_input)),
            std::istreambuf_iterator<char>()
        );
        EXPECT_EQ(candidate_content.find("AFTER_FAILED_DRAIN_6p4v"), std::string::npos);
    }

    logger.shutdown();
    (void)std::filesystem::remove(old_file, error_code);
    EXPECT_FALSE(error_code) << "failed to remove old sink: " << error_code.message();
    error_code.clear();
    (void)std::filesystem::remove(candidate_file, error_code);
    EXPECT_FALSE(error_code) << "failed to remove candidate sink: " << error_code.message();
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

// Detach retention is provisioned before publication and has no finite fallback count. Drive both detach entry points
// beyond a 16-slot ceiling with allocation poisoned across every detach.
TEST_F(LoggerTest, DetachedWriterRetentionHasNoAllocationAndNoFiniteCeiling)
{
    constexpr int detach_cycles = 24;
    static_assert(detach_cycles > 16, "the case must exceed a finite 16-slot fallback ceiling");

    static std::atomic<bool> writer_gate{true};
    std::error_code error_code;

    diagnostics::reset_intentional_leaks();
    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger);
    const std::size_t live_before =
        DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed);

    for (int cycle = 0; cycle < detach_cycles; ++cycle)
    {
        const auto cycle_file =
            std::filesystem::temp_directory_path() /
            ("test_logger_retain_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(cycle) + ".log");
        std::filesystem::remove(cycle_file, error_code);

        writer_gate.store(true, std::memory_order_release);
        {
            Logger logger("RETAIN", cycle_file.string(), "%H:%M:%S");
            AsyncLoggerConfig config;
            config.queue_capacity = 16;
            config.batch_size = 4;
            DetourModKit::detail::g_async_logger_writer_gate.store(&writer_gate, std::memory_order_release);
            LoggerSeamReset seam_reset{&writer_gate};
            logger.enable_async_mode(config);
            ASSERT_TRUE(logger.is_async_mode_enabled()) << "cycle " << cycle;

            DetourModKit::detail::g_async_logger_loader_lock_override = &logger_detach_always_true_loader_lock;
            const std::string pending_marker = "RETAIN_PENDING_" + std::to_string(cycle);
            ASSERT_TRUE(logger.log(LogLevel::Info, pending_marker)) << "cycle " << cycle;

            // Poison allocation across the detach itself. An allocating retention path would throw here, out of a
            // noexcept teardown, and terminate.
            const long long calls_before = dmk_test::thread_new_calls();
            {
                const dmk_test::AllocFailScope no_allocation{0};
                if ((cycle & 1) == 0)
                {
                    logger.shutdown();
                }
                else
                {
                    logger.disable_async_mode();
                }
            }
            EXPECT_EQ(dmk_test::thread_new_calls(), calls_before)
                << "the detach path allocated on cycle " << cycle << "; retention must be allocation-free";
            EXPECT_FALSE(logger.is_async_mode_enabled()) << "cycle " << cycle;
            EXPECT_FALSE(logger.log(LogLevel::Error, "POST_DETACH_DROP"))
                << "the facade resumed access to the sink owned by a detached writer on cycle " << cycle;

            // A disable-detach must also make the later destructor/shutdown a no-op. Without the shutdown latch this
            // call closes the sink out from under the retained writer, and its queued marker cannot drain.
            logger.shutdown();
            writer_gate.store(false, std::memory_order_release);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            bool marker_present = false;
            while (std::chrono::steady_clock::now() < deadline && !marker_present)
            {
                std::ifstream input_stream(cycle_file);
                const std::string content(
                    (std::istreambuf_iterator<char>(input_stream)),
                    std::istreambuf_iterator<char>()
                );
                marker_present = content.find(pending_marker) != std::string::npos;
                if (!marker_present)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{10});
                }
            }
            ASSERT_TRUE(marker_present) << "shutdown closed the retained writer's sink on cycle " << cycle;
        }
        std::filesystem::remove(cycle_file, error_code);
    }

    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger), leaks_before + detach_cycles)
        << "every detached writer must be recorded as an intentional retention";
    EXPECT_EQ(
        DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed),
        live_before + detach_cycles
    ) << "every detached writer must still be alive; the retention root is what keeps the state its writer thread "
         "is still reading from being freed under it";

    writer_gate.store(false, std::memory_order_release);
}

// Stays in the unit suite: the detach is driven through the loader-lock override seam, not a real loader event, and
// the probe's mutation of the process-global default sink is confined to the death-test child. AGENTS.md routes a
// fixture to tests/lifecycle/ only when it needs a real loader or teardown event that cannot share the test process.
TEST_F(LoggerTest, DisableDetachPreventsDefaultConfigureRevival)
{
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(run_default_logger_disable_detach_probe(), ::testing::ExitedWithCode(0), "");
}

// The ordinary path must not leak. A joined writer is released by breaking its root under an external strong owner,
// so the object dies with the frame that shut it down.
TEST_F(LoggerTest, CleanJoinBreaksTheRetentionRootAndLeaksNothing)
{
    const auto clean_file = std::filesystem::temp_directory_path() /
                            ("test_logger_clean_join_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::error_code error_code;
    std::filesystem::remove(clean_file, error_code);

    diagnostics::reset_intentional_leaks();
    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger);
    const std::size_t live_before =
        DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed);

    {
        Logger logger("CLEANJOIN", clean_file.string(), "%H:%M:%S");
        logger.enable_async_mode();
        ASSERT_TRUE(logger.is_async_mode_enabled());
        EXPECT_EQ(
            DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed),
            live_before + 1
        );

        // disable_async_mode joins off the loader lock, so it is the release path; shutdown() then has nothing left.
        logger.disable_async_mode();
        EXPECT_EQ(DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed), live_before)
            << "a cleanly joined writer must be destroyed, not left standing on its retention root";
    }

    // A second writer over the facade's whole lifetime, released by shutdown() rather than by disable.
    {
        Logger logger("CLEANJOIN2", clean_file.string(), "%H:%M:%S");
        logger.enable_async_mode();
        ASSERT_TRUE(logger.is_async_mode_enabled());
        logger.shutdown();
        EXPECT_EQ(DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed), live_before)
            << "a clean shutdown must release the writer it joined";
    }

    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger), leaks_before)
        << "the ordinary path must record no intentional retention";

    std::filesystem::remove(clean_file, error_code);
}

// The root is armed between make_shared and publication, so a failure inside that window has to break it: nothing
// else ever will, because no owner outside that frame knows the writer exists.
TEST_F(LoggerTest, PrePublicationFailureBreaksTheRetentionRoot)
{
    const auto rollback_file = std::filesystem::temp_directory_path() /
                               ("test_logger_rollback_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::error_code error_code;
    std::filesystem::remove(rollback_file, error_code);

    diagnostics::reset_intentional_leaks();
    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger);
    const std::size_t live_before =
        DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed);

    {
        Logger logger("ROLLBACK", rollback_file.string(), "%H:%M:%S");
        DetourModKit::detail::g_logger_publication_probe = []() { throw std::runtime_error("publication refused"); };
        logger.enable_async_mode();
        DetourModKit::detail::g_logger_publication_probe = nullptr;

        EXPECT_FALSE(logger.is_async_mode_enabled()) << "a refused publication must not leave async mode enabled";
        EXPECT_EQ(DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed), live_before)
            << "a writer that was never published must be destroyed, not stranded on its own retention root";

        // The facade is still usable: the rollback is a refused mode switch, not a poisoned logger.
        logger.enable_async_mode();
        EXPECT_TRUE(logger.is_async_mode_enabled());
        logger.disable_async_mode();
        EXPECT_EQ(
            DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed),
            live_before
        );
    }

    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Logger), leaks_before);

    std::filesystem::remove(rollback_file, error_code);
}

// The rollback window must contain every exception type. An escaped non-standard throw terminates the process.
TEST_F(LoggerTest, NonStandardThrowBeforePublicationIsContainedAndBreaksTheRoot)
{
    const std::filesystem::path rollback_file = unique_activation_log_path("test_logger_nonstd_rollback");
    std::error_code error_code;
    std::filesystem::remove(rollback_file, error_code);

    const std::size_t live_before =
        DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed);

    {
        Logger logger("NONSTD", rollback_file.string(), "%H:%M:%S");
        DetourModKit::detail::g_logger_publication_probe = []() { throw 42; };
        logger.enable_async_mode();
        DetourModKit::detail::g_logger_publication_probe = nullptr;

        EXPECT_FALSE(logger.is_async_mode_enabled()) << "a refused publication must not leave async mode enabled";
        EXPECT_EQ(DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed), live_before)
            << "a writer that was never published must be destroyed, not stranded on its own retention root";

        // The refusal is contained, so a later enable still works.
        logger.enable_async_mode();
        EXPECT_TRUE(logger.is_async_mode_enabled());
        logger.disable_async_mode();
    }

    std::filesystem::remove(rollback_file, error_code);
}

// A throw at the old diagnostic site must not escape after publication. The committed writer stays active.
TEST_F(LoggerTest, PostPublicationThrowIsContainedAndKeepsThePublishedWriter)
{
    const std::filesystem::path post_file = unique_activation_log_path("test_logger_post_publication");
    std::error_code error_code;
    std::filesystem::remove(post_file, error_code);

    const std::size_t live_before =
        DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed);

    {
        Logger logger("POSTPUB", post_file.string(), "%H:%M:%S");
        DetourModKit::detail::g_logger_post_publication_probe = []()
        { throw std::runtime_error("diagnostic refused"); };
        logger.enable_async_mode();
        DetourModKit::detail::g_logger_post_publication_probe = nullptr;

        EXPECT_TRUE(logger.is_async_mode_enabled())
            << "a contained post-publication throw must keep the activated writer";
        EXPECT_EQ(
            DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed),
            live_before + 1
        );

        (void)logger.log(LogLevel::Info, "post-publication delivery still works");
        logger.disable_async_mode();
        EXPECT_EQ(
            DetourModKit::detail::g_async_logger_live_count_for_test.load(std::memory_order_relaxed),
            live_before
        );
    }

    std::filesystem::remove(post_file, error_code);
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

// The three public logger defaults are std::string_view, matching async_logger_config.hpp. The spelling is part
// of the public surface, so it is pinned here rather than left to the header alone. The .data() assertions preserve
// the pre-conversion capability: each constant still yields a NUL-terminated const char * for a C-string consumer.
TEST(LoggerPublicConstants, DefaultsAreStringViewAndStayNulTerminated)
{
    static_assert(std::is_same_v<decltype(DEFAULT_LOG_PREFIX), const std::string_view>);
    static_assert(std::is_same_v<decltype(DEFAULT_LOG_FILE_NAME), const std::string_view>);
    static_assert(std::is_same_v<decltype(DEFAULT_TIMESTAMP_FORMAT), const std::string_view>);

    static_assert(DEFAULT_LOG_PREFIX == "DetourModKit");
    static_assert(DEFAULT_LOG_FILE_NAME == "DetourModKit_Log.txt");
    static_assert(DEFAULT_TIMESTAMP_FORMAT == "%Y-%m-%d %H:%M:%S");

    EXPECT_EQ(DEFAULT_LOG_PREFIX.data()[DEFAULT_LOG_PREFIX.size()], '\0');
    EXPECT_EQ(DEFAULT_LOG_FILE_NAME.data()[DEFAULT_LOG_FILE_NAME.size()], '\0');
    EXPECT_EQ(DEFAULT_TIMESTAMP_FORMAT.data()[DEFAULT_TIMESTAMP_FORMAT.size()], '\0');

    EXPECT_STREQ(DEFAULT_LOG_PREFIX.data(), "DetourModKit");
    EXPECT_STREQ(DEFAULT_LOG_FILE_NAME.data(), "DetourModKit_Log.txt");
    EXPECT_STREQ(DEFAULT_TIMESTAMP_FORMAT.data(), "%Y-%m-%d %H:%M:%S");
}

// DEFAULT_TIMESTAMP_FORMAT is the declared default argument of Logger(prefix, file) and of the static configure(prefix,
// file), so each omitted-argument path must stamp the format the explicit spelling renders. The sink writes
// "[<strftime>.<ms>] ...", so the default renders the 25-character head "[dddd-dd-dd dd:dd:dd.ddd]", which pins the
// spelling positionally without comparing volatile digits across lines.
TEST_F(LoggerTest, DefaultTimestampFormatArgumentMatchesExplicitSpelling)
{
    const std::string implicit_path = m_test_log_file.string() + ".implicit_default";
    const std::string explicit_path = m_test_log_file.string() + ".explicit_default";
    const std::string configure_path = m_test_log_file.string() + ".configure_default";
    std::error_code error_code;
    std::filesystem::remove(implicit_path, error_code);
    std::filesystem::remove(explicit_path, error_code);
    std::filesystem::remove(configure_path, error_code);

    {
        Logger implicit_fmt("TEST", implicit_path);
        Logger explicit_fmt("TEST", explicit_path, DEFAULT_TIMESTAMP_FORMAT);
        EXPECT_TRUE(implicit_fmt.log(LogLevel::Info, "stamp"));
        EXPECT_TRUE(explicit_fmt.log(LogLevel::Info, "stamp"));
    }

    Logger::configure("TEST", configure_path);
    EXPECT_TRUE(log().log(LogLevel::Info, "stamp"));
    log().flush();

    const auto read_stamp_head = [](const std::string &path)
    {
        std::ifstream stream(path);
        std::string line;
        while (std::getline(stream, line))
        {
            if (line.find("stamp") != std::string::npos)
            {
                return line.substr(0, line.find("stamp"));
            }
        }
        return std::string{};
    };

    const auto has_default_timestamp_shape = [](const std::string &head)
    {
        constexpr std::string_view shape = "[dddd-dd-dd dd:dd:dd.ddd]";
        if (head.size() < shape.size())
        {
            return false;
        }
        for (std::size_t i = 0; i < shape.size(); ++i)
        {
            if (shape[i] == 'd' ? (head[i] < '0' || head[i] > '9') : (head[i] != shape[i]))
            {
                return false;
            }
        }
        return true;
    };

    const std::string implicit_head = read_stamp_head(implicit_path);
    const std::string explicit_head = read_stamp_head(explicit_path);
    const std::string configure_head = read_stamp_head(configure_path);
    ASSERT_FALSE(implicit_head.empty());
    ASSERT_FALSE(explicit_head.empty());
    ASSERT_FALSE(configure_head.empty());
    EXPECT_TRUE(has_default_timestamp_shape(implicit_head));
    EXPECT_TRUE(has_default_timestamp_shape(explicit_head));
    EXPECT_TRUE(has_default_timestamp_shape(configure_head));
    EXPECT_EQ(implicit_head.size(), explicit_head.size());

    std::filesystem::remove(implicit_path, error_code);
    std::filesystem::remove(explicit_path, error_code);
    std::filesystem::remove(configure_path, error_code);
}

// Append preserves prior records when a new Logger opens the same file. The default remains Truncate.
// Lifecycle.LoggerAppendModePreservesPriorGenerationRecords proves both Session routes.
TEST_F(LoggerTest, ConstructorOpenModeControlsExistingFileFate)
{
    static_assert(std::is_same_v<std::underlying_type_t<LogOpenMode>, std::uint8_t>);

    static std::atomic<int> s_open_mode_counter{0};
    const auto file = std::filesystem::temp_directory_path() /
                      ("test_logger_openmode_" + std::to_string(_getpid()) + "_" +
                       std::to_string(s_open_mode_counter.fetch_add(1, std::memory_order_relaxed)) + ".log");
    std::error_code error_code;
    std::filesystem::remove(file, error_code);
    struct FileCleanup
    {
        const std::filesystem::path &path;
        ~FileCleanup() noexcept
        {
            std::error_code error;
            std::filesystem::remove(path, error);
        }
    } const file_cleanup{file};

    {
        Logger first("GEN1", file.string());
        EXPECT_TRUE(first.log(LogLevel::Info, "OPENMODE_MARKER_GEN1"));
    }

    {
        Logger second("GEN2", file.string(), DEFAULT_TIMESTAMP_FORMAT, LogOpenMode::Append);
        EXPECT_TRUE(second.log(LogLevel::Info, "OPENMODE_MARKER_GEN2"));
    }

    {
        std::ifstream stream(file);
        ASSERT_TRUE(stream.is_open());
        const std::string content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        const auto first_pos = content.find("OPENMODE_MARKER_GEN1");
        const auto second_pos = content.find("OPENMODE_MARKER_GEN2");
        EXPECT_NE(first_pos, std::string::npos);
        EXPECT_NE(second_pos, std::string::npos);
        EXPECT_LT(first_pos, second_pos);
    }

    // A construction without a mode still truncates. This preserves behavior from before the option.
    {
        Logger third("GEN3", file.string(), DEFAULT_TIMESTAMP_FORMAT);
        EXPECT_TRUE(third.log(LogLevel::Info, "OPENMODE_MARKER_GEN3"));
    }

    std::ifstream stream(file);
    ASSERT_TRUE(stream.is_open());
    const std::string content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content.find("OPENMODE_MARKER_GEN1"), std::string::npos);
    EXPECT_EQ(content.find("OPENMODE_MARKER_GEN2"), std::string::npos);
    EXPECT_NE(content.find("OPENMODE_MARKER_GEN3"), std::string::npos);
}
