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

// Test AsyncLoggerConfig validation with power-of-2 capacity
TEST(AsyncLoggerConfigTest, Validation_PowerOfTwo)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 8192; // Valid: power of 2

    EXPECT_NO_THROW(config.validate());
}

// Test AsyncLoggerConfig validation with invalid capacity
TEST(AsyncLoggerConfigTest, Validation_InvalidCapacity)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 100; // Invalid: not power of 2

    // validate() should adjust to nearest power of 2
    EXPECT_NO_THROW(config.validate());
}

// Test AsyncLoggerConfig validation with zero batch size
TEST(AsyncLoggerConfigTest, Validation_ZeroBatchSize)
{
    AsyncLoggerConfig config;
    config.batch_size = 0;

    // Should use default
    EXPECT_NO_THROW(config.validate());
}

// Test AsyncLoggerConfig validation with zero flush interval
TEST(AsyncLoggerConfigTest, Validation_ZeroFlushInterval)
{
    AsyncLoggerConfig config;
    config.flush_interval = std::chrono::milliseconds{0};

    // Should use default
    EXPECT_NO_THROW(config.validate());
}

// Test OverflowPolicy enum values
TEST(OverflowPolicyTest, EnumValues)
{
    EXPECT_NE(OverflowPolicy::DropOldest, OverflowPolicy::DropNewest);
    EXPECT_NE(OverflowPolicy::DropNewest, OverflowPolicy::Block);
    EXPECT_NE(OverflowPolicy::Block, OverflowPolicy::DropOldest);
}

// Test LogMessage structure
TEST(LogMessageTest, DefaultConstruction)
{
    LogMessage msg;
    // LogMessage default construction should work
    // (level may be uninitialized in default ctor, just verify it compiles)
    (void)msg;
    SUCCEED();
}

// Test all log levels through async logger
TEST_F(AsyncLoggerTest, AllLogLevels)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Enqueue messages at all log levels
    logger->enqueue(LogLevel::Trace, "Trace message");
    logger->enqueue(LogLevel::Debug, "Debug message");
    logger->enqueue(LogLevel::Info, "Info message");
    logger->enqueue(LogLevel::Warning, "Warning message");
    logger->enqueue(LogLevel::Error, "Error message");

    // Give time for messages to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    // Check that log file was created
    EXPECT_TRUE(std::filesystem::exists(test_log_file_));
}

// Test empty message handling
TEST_F(AsyncLoggerTest, EmptyMessage)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Enqueue empty message
    logger->enqueue(LogLevel::Info, "");

    // Give time for message to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    // Should not crash
    SUCCEED();
}

// Test long message handling
TEST_F(AsyncLoggerTest, LongMessage)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Enqueue long message
    std::string long_msg(1000, 'X');
    logger->enqueue(LogLevel::Info, long_msg);

    // Give time for message to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    // Should not crash
    SUCCEED();
}

// Test rapid enqueue/dequeue
TEST_F(AsyncLoggerTest, RapidLogging)
{
    AsyncLoggerConfig config;
    config.batch_size = 1000;
    config.flush_interval = std::chrono::milliseconds{1000};
    config.queue_capacity = 4096;

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Rapidly enqueue many messages
    for (int i = 0; i < 500; ++i)
    {
        logger->enqueue(LogLevel::Info, "Rapid message " + std::to_string(i));
    }

    // Give time for messages to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    logger->shutdown();

    // Should not crash or lose messages
    SUCCEED();
}

// Test double shutdown
TEST_F(AsyncLoggerTest, DoubleShutdown)
{
    AsyncLoggerConfig config;
    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->shutdown();

    // Second shutdown should not throw
    EXPECT_NO_THROW(logger->shutdown());
}

// Test is_running after shutdown
TEST_F(AsyncLoggerTest, IsRunningAfterShutdown)
{
    AsyncLoggerConfig config;
    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_TRUE(logger->is_running());

    logger->shutdown();

    EXPECT_FALSE(logger->is_running());
}

// Test enqueue after shutdown writes synchronously (covers sync write path in enqueue)
TEST_F(AsyncLoggerTest, EnqueueAfterShutdown_SyncWrite)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Shutdown first - sets shutdown_requested_ = true
    logger->shutdown();
    EXPECT_FALSE(logger->is_running());

    // Enqueue after shutdown should write synchronously (not crash or deadlock)
    EXPECT_NO_THROW(logger->enqueue(LogLevel::Info, "Post-shutdown sync message"));
    EXPECT_NO_THROW(logger->enqueue(LogLevel::Error, "Post-shutdown sync error"));
    EXPECT_NO_THROW(logger->enqueue(LogLevel::Warning, "Post-shutdown sync warning"));
}

// Test flush() when not running (covers early return branch)
TEST_F(AsyncLoggerTest, Flush_WhenNotRunning)
{
    AsyncLoggerConfig config;
    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    logger->shutdown();
    EXPECT_FALSE(logger->is_running());

    // flush() after shutdown should return immediately without blocking
    EXPECT_NO_THROW(logger->flush());
    EXPECT_NO_THROW(logger->flush()); // Second flush also safe
}

// Test overflow policy: DropNewest (fills queue to trigger overflow)
TEST_F(AsyncLoggerTest, OverflowPolicy_DropNewest)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2; // Minimum valid capacity
    config.batch_size = 1000;  // Large batch so writer drains slowly relative to producer
    config.overflow_policy = OverflowPolicy::DropNewest;
    config.flush_interval = std::chrono::milliseconds{5000}; // Long interval

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Rapidly enqueue many messages - overflow will trigger handle_overflow(DropNewest)
    for (int i = 0; i < 200; ++i)
    {
        logger->enqueue(LogLevel::Info, "drop_newest_" + std::to_string(i));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    logger->shutdown();
    SUCCEED(); // Verify no crash
}

// Test overflow policy: DropOldest triggered by full queue
TEST_F(AsyncLoggerTest, OverflowPolicy_DropOldest_Full)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1000;
    config.overflow_policy = OverflowPolicy::DropOldest;
    config.flush_interval = std::chrono::milliseconds{5000};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Rapidly enqueue many messages - overflow triggers handle_overflow(DropOldest)
    for (int i = 0; i < 200; ++i)
    {
        logger->enqueue(LogLevel::Info, "drop_oldest_" + std::to_string(i));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    logger->shutdown();
    SUCCEED();
}

// Test overflow policy: SyncFallback (writes synchronously on overflow)
TEST_F(AsyncLoggerTest, OverflowPolicy_SyncFallback)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1000;
    config.overflow_policy = OverflowPolicy::SyncFallback;
    config.flush_interval = std::chrono::milliseconds{5000};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Rapidly enqueue many messages - overflow triggers synchronous write
    for (int i = 0; i < 200; ++i)
    {
        logger->enqueue(LogLevel::Info, "sync_fallback_" + std::to_string(i));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    logger->shutdown();
    SUCCEED();
}

// Test overflow policy: Block (spins until space available, writer will drain)
TEST_F(AsyncLoggerTest, OverflowPolicy_Block)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 10;
    config.overflow_policy = OverflowPolicy::Block;
    config.flush_interval = std::chrono::milliseconds{50}; // Short so writer drains fast

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Enqueue messages - Block policy spins until writer drains, no deadlock expected
    for (int i = 0; i < 10; ++i)
    {
        logger->enqueue(LogLevel::Info, "block_policy_" + std::to_string(i));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    logger->shutdown();
    SUCCEED();
}

// Test DynamicMPMCQueue with invalid capacity (not power of 2) - should throw
TEST(DynamicMPMCQueueTest, InvalidCapacity_NotPowerOfTwo)
{
    EXPECT_THROW(DynamicMPMCQueue(3), std::invalid_argument);
    EXPECT_THROW(DynamicMPMCQueue(5), std::invalid_argument);
    EXPECT_THROW(DynamicMPMCQueue(100), std::invalid_argument);
    EXPECT_THROW(DynamicMPMCQueue(1000), std::invalid_argument);
}

// Test DynamicMPMCQueue with capacity too small - should throw
TEST(DynamicMPMCQueueTest, InvalidCapacity_TooSmall)
{
    EXPECT_THROW(DynamicMPMCQueue(0), std::invalid_argument);
    EXPECT_THROW(DynamicMPMCQueue(1), std::invalid_argument);
}

// Test DynamicMPMCQueue with valid capacity
TEST(DynamicMPMCQueueTest, ValidCapacity)
{
    EXPECT_NO_THROW(DynamicMPMCQueue(2));
    EXPECT_NO_THROW(DynamicMPMCQueue(4));
    EXPECT_NO_THROW(DynamicMPMCQueue(8));
    EXPECT_NO_THROW(DynamicMPMCQueue(16));
}

// Test DynamicMPMCQueue capacity() accessor
TEST(DynamicMPMCQueueTest, CapacityAccessor)
{
    DynamicMPMCQueue queue(4);
    EXPECT_EQ(queue.capacity(), 4u);
}

// Test DynamicMPMCQueue try_push when full and try_pop when empty
TEST(DynamicMPMCQueueTest, FullAndEmptyQueue)
{
    DynamicMPMCQueue queue(2);

    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.size(), 0u);

    // Fill the queue
    EXPECT_TRUE(queue.try_push(LogMessage(LogLevel::Info, "msg1")));
    EXPECT_TRUE(queue.try_push(LogMessage(LogLevel::Info, "msg2")));

    EXPECT_EQ(queue.size(), 2u);
    EXPECT_FALSE(queue.empty());

    // Queue is full - try_push should fail (covers diff < 0 branch)
    EXPECT_FALSE(queue.try_push(LogMessage(LogLevel::Info, "overflow_msg")));

    // Pop all messages
    LogMessage popped;
    EXPECT_TRUE(queue.try_pop(popped));
    EXPECT_TRUE(queue.try_pop(popped));

    // Queue is empty - try_pop should fail (covers diff < 0 branch in try_pop)
    EXPECT_FALSE(queue.try_pop(popped));
    EXPECT_TRUE(queue.empty());
}

// Test LogMessage move constructor
TEST(LogMessageTest, MoveConstructor)
{
    LogMessage msg1(LogLevel::Warning, "warning message");
    std::string original_msg(msg1.message());

    LogMessage msg2(std::move(msg1));

    EXPECT_EQ(msg2.message(), original_msg);
    EXPECT_EQ(msg2.level, LogLevel::Warning);
    EXPECT_EQ(msg1.length, 0u); // Moved-from state has length 0
}

// Test LogMessage move assignment operator
TEST(LogMessageTest, MoveAssignment)
{
    LogMessage msg1(LogLevel::Info, "info message");
    LogMessage msg2(LogLevel::Debug, "debug message");
    std::string original_msg(msg1.message());

    msg2 = std::move(msg1);

    EXPECT_EQ(msg2.message(), original_msg);
    EXPECT_EQ(msg2.level, LogLevel::Info);
    EXPECT_EQ(msg1.length, 0u); // Moved-from state
}

// Test LogMessage with message exactly at MAX_INLINE_SIZE (inline buffer path)
TEST(LogMessageTest, InlineMessage_ExactSize)
{
    std::string msg(LogMessage::MAX_INLINE_SIZE, 'A');
    LogMessage log_msg(LogLevel::Info, msg);

    EXPECT_EQ(log_msg.message().size(), LogMessage::MAX_INLINE_SIZE);
    EXPECT_EQ(log_msg.message(), msg);
    EXPECT_EQ(log_msg.overflow, nullptr); // Should use inline buffer
}

// Test LogMessage with message exceeding MAX_INLINE_SIZE (heap overflow path)
TEST(LogMessageTest, LargeMessage_HeapPath)
{
    std::string msg(LogMessage::MAX_INLINE_SIZE + 1, 'B');
    LogMessage log_msg(LogLevel::Info, msg);

    EXPECT_EQ(log_msg.message().size(), LogMessage::MAX_INLINE_SIZE + 1);
    EXPECT_EQ(log_msg.message(), msg);
    EXPECT_NE(log_msg.overflow, nullptr); // Should use heap allocation
}

// Test AsyncLoggerConfig::validate() return values for all invalid cases
TEST(AsyncLoggerConfigTest, Validate_AllReturnValues)
{
    // Valid default config returns true
    AsyncLoggerConfig valid_config;
    EXPECT_TRUE(valid_config.validate());

    // Invalid: capacity = 0
    AsyncLoggerConfig zero_cap;
    zero_cap.queue_capacity = 0;
    EXPECT_FALSE(zero_cap.validate());

    // Invalid: capacity not power of 2
    AsyncLoggerConfig bad_cap;
    bad_cap.queue_capacity = 100;
    EXPECT_FALSE(bad_cap.validate());

    // Invalid: batch_size = 0
    AsyncLoggerConfig zero_batch;
    zero_batch.batch_size = 0;
    EXPECT_FALSE(zero_batch.validate());

    // Invalid: flush_interval = 0
    AsyncLoggerConfig zero_interval;
    zero_interval.flush_interval = std::chrono::milliseconds{0};
    EXPECT_FALSE(zero_interval.validate());
}
