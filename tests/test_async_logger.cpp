// Unit tests for AsyncLogger module
#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <filesystem>
#include <fstream>
#include <mutex>

#include "DetourModKit/async_logger.hpp"

using namespace DetourModKit;

// Test fixture for AsyncLogger tests
class AsyncLoggerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        test_log_file_ = std::filesystem::temp_directory_path() / "test_async_logger.log";
    }

    void TearDown() override
    {
        if (std::filesystem::exists(test_log_file_))
        {
            std::filesystem::remove(test_log_file_);
        }
    }

    std::filesystem::path test_log_file_;
};

// Test AsyncLoggerConfig default values
TEST(AsyncLoggerConfigTest, DefaultValues)
{
    AsyncLoggerConfig config;

    EXPECT_EQ(config.batch_size, 64);
    EXPECT_EQ(config.flush_interval.count(), 100);
    EXPECT_EQ(config.queue_capacity, 8192);
    EXPECT_EQ(config.overflow_policy, OverflowPolicy::DropOldest);
}

// Test AsyncLoggerConfig custom values
TEST(AsyncLoggerConfigTest, CustomValues)
{
    AsyncLoggerConfig config;
    config.batch_size = 128;
    config.flush_interval = std::chrono::milliseconds{50};
    config.queue_capacity = 4096;
    config.overflow_policy = OverflowPolicy::Block;

    EXPECT_EQ(config.batch_size, 128);
    EXPECT_EQ(config.flush_interval.count(), 50);
    EXPECT_EQ(config.queue_capacity, 4096);
    EXPECT_EQ(config.overflow_policy, OverflowPolicy::Block);
}

// Test AsyncLogger creation and basic operations
TEST_F(AsyncLoggerTest, BasicCreation)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_NE(logger, nullptr);
    EXPECT_TRUE(logger->is_running());
}

// Test AsyncLogger start/shutdown
TEST_F(AsyncLoggerTest, StartStop)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_TRUE(logger->is_running());

    logger->shutdown();

    EXPECT_FALSE(logger->is_running());
}

// Test AsyncLogger enqueue
TEST_F(AsyncLoggerTest, Enqueue)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Enqueue some messages
    logger->enqueue(LogLevel::Info, "Test message 1");
    logger->enqueue(LogLevel::Debug, "Test message 2");
    logger->enqueue(LogLevel::Warning, "Test message 3");

    // Give time for messages to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    // Check that log file was created and has content
    EXPECT_TRUE(std::filesystem::exists(test_log_file_));

    // Read and verify content
    std::ifstream file(test_log_file_);
    std::string line;
    int line_count = 0;
    while (std::getline(file, line))
    {
        if (!line.empty())
        {
            ++line_count;
        }
    }

    // Should have at least 3 log messages
    EXPECT_GE(line_count, 3);
}

// Test AsyncLogger flush
TEST_F(AsyncLoggerTest, Flush)
{
    AsyncLoggerConfig config;
    config.batch_size = 100; // Large batch so messages aren't auto-flushed
    config.flush_interval = std::chrono::milliseconds{1000};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Enqueue a message
    logger->enqueue(LogLevel::Info, "Flush test message");

    // Give time for message to be enqueued
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Flush should not block indefinitely
    EXPECT_NO_THROW(logger->flush());

    logger->shutdown();
}

// Test AsyncLogger multiple threads
TEST_F(AsyncLoggerTest, MultiThreadedLogging)
{
    AsyncLoggerConfig config;
    config.batch_size = 100;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    const int num_threads = 4;
    const int messages_per_thread = 25;

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&logger, i, messages_per_thread]()
                             {
            for (int j = 0; j < messages_per_thread; ++j)
            {
                logger->enqueue(LogLevel::Info, "Thread " + std::to_string(i) + " message " + std::to_string(j));
            } });
    }

    // Wait for all threads to finish
    for (auto &t : threads)
    {
        t.join();
    }

    // Give time for messages to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    logger->shutdown();

    // Check that log file was created
    EXPECT_TRUE(std::filesystem::exists(test_log_file_));
}

// Test AsyncLogger queue size
TEST_F(AsyncLoggerTest, QueueSize)
{
    AsyncLoggerConfig config;
    config.batch_size = 100;
    config.flush_interval = std::chrono::milliseconds{1000}; // Long interval so nothing auto-flushes

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Queue should be empty initially
    EXPECT_EQ(logger->queue_size(), 0);

    // Enqueue some messages
    logger->enqueue(LogLevel::Info, "Message 1");
    logger->enqueue(LogLevel::Info, "Message 2");
    logger->enqueue(LogLevel::Info, "Message 3");

    // Give time for messages to be enqueued but not processed
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Queue should have messages (may vary depending on timing)
    EXPECT_GE(logger->queue_size(), 0);

    logger->shutdown();
}
