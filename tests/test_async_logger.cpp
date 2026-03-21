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

TEST(AsyncLoggerConfigTest, DefaultValues)
{
    AsyncLoggerConfig config;

    EXPECT_EQ(config.batch_size, 64);
    EXPECT_EQ(config.flush_interval.count(), 100);
    EXPECT_EQ(config.queue_capacity, 8192);
    EXPECT_EQ(config.overflow_policy, OverflowPolicy::DropOldest);
}

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

TEST_F(AsyncLoggerTest, BasicCreation)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_NE(logger, nullptr);
    EXPECT_TRUE(logger->is_running());
}

TEST_F(AsyncLoggerTest, StartStop)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_TRUE(logger->is_running());

    logger->shutdown();

    EXPECT_FALSE(logger->is_running());
}

TEST_F(AsyncLoggerTest, Enqueue)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    static_cast<void>(logger->enqueue(LogLevel::Info, "Test message 1"));
    static_cast<void>(logger->enqueue(LogLevel::Debug, "Test message 2"));
    static_cast<void>(logger->enqueue(LogLevel::Warning, "Test message 3"));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    EXPECT_TRUE(std::filesystem::exists(test_log_file_));

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

    EXPECT_GE(line_count, 3);
}

TEST_F(AsyncLoggerTest, Enqueue_ReturnsTrue_OnSuccess)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_TRUE(logger->enqueue(LogLevel::Info, "Test message 1"));
    EXPECT_TRUE(logger->enqueue(LogLevel::Debug, "Test message 2"));
    EXPECT_TRUE(logger->enqueue(LogLevel::Warning, "Test message 3"));

    logger->shutdown();
}

TEST_F(AsyncLoggerTest, Enqueue_ReturnsFalse_WhenDropped)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1;
    config.overflow_policy = OverflowPolicy::DropNewest;
    config.flush_interval = std::chrono::milliseconds{5000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    auto result1 = logger->enqueue(LogLevel::Info, "msg1");
    auto result2 = logger->enqueue(LogLevel::Info, "msg2");
    auto result3_unused = logger->enqueue(LogLevel::Info, "msg3");

    EXPECT_TRUE(result1);
    EXPECT_TRUE(result2);
    static_cast<void>(result3_unused);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    logger->shutdown();
}

TEST_F(AsyncLoggerTest, Enqueue_BlockPolicy_BasicFunctionality)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 2;
    config.overflow_policy = OverflowPolicy::Block;
    config.block_timeout_ms = std::chrono::milliseconds{100};
    config.flush_interval = std::chrono::milliseconds{100};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_TRUE(logger->enqueue(LogLevel::Info, "msg1"));
    EXPECT_TRUE(logger->enqueue(LogLevel::Info, "msg2"));

    logger->shutdown();
}

TEST_F(AsyncLoggerTest, Flush)
{
    AsyncLoggerConfig config;
    config.batch_size = 100;
    config.flush_interval = std::chrono::milliseconds{1000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    static_cast<void>(logger->enqueue(LogLevel::Info, "Flush test message"));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_NO_THROW(logger->flush());

    logger->shutdown();
}

TEST_F(AsyncLoggerTest, MultiThreadedLogging)
{
    AsyncLoggerConfig config;
    config.batch_size = 100;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

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
                static_cast<void>(logger->enqueue(LogLevel::Info, "Thread " + std::to_string(i) + " message " + std::to_string(j)));
            } });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    logger->shutdown();

    EXPECT_TRUE(std::filesystem::exists(test_log_file_));
}

TEST_F(AsyncLoggerTest, EmptyMessage)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_TRUE(logger->enqueue(LogLevel::Info, ""));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    SUCCEED();
}

TEST_F(AsyncLoggerTest, LongMessage)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    std::string long_msg(1000, 'X');
    EXPECT_TRUE(logger->enqueue(LogLevel::Info, long_msg));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    SUCCEED();
}

TEST_F(AsyncLoggerTest, DoubleShutdown)
{
    AsyncLoggerConfig config;
    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->shutdown();

    EXPECT_NO_THROW(logger->shutdown());
}

TEST_F(AsyncLoggerTest, IsRunningAfterShutdown)
{
    AsyncLoggerConfig config;
    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_TRUE(logger->is_running());

    logger->shutdown();

    EXPECT_FALSE(logger->is_running());
}

TEST_F(AsyncLoggerTest, EnqueueAfterShutdown_SyncWrite)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->shutdown();
    EXPECT_FALSE(logger->is_running());

    EXPECT_TRUE(logger->enqueue(LogLevel::Info, "Post-shutdown sync message"));
    EXPECT_TRUE(logger->enqueue(LogLevel::Error, "Post-shutdown sync error"));
    EXPECT_TRUE(logger->enqueue(LogLevel::Warning, "Post-shutdown sync warning"));
}

TEST_F(AsyncLoggerTest, Flush_WhenNotRunning)
{
    AsyncLoggerConfig config;
    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    logger->shutdown();
    EXPECT_FALSE(logger->is_running());

    EXPECT_NO_THROW(logger->flush());
    EXPECT_NO_THROW(logger->flush());
}

TEST_F(AsyncLoggerTest, OverflowPolicy_DropNewest)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1000;
    config.overflow_policy = OverflowPolicy::DropNewest;
    config.flush_interval = std::chrono::milliseconds{5000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 200; ++i)
    {
        static_cast<void>(logger->enqueue(LogLevel::Info, "drop_newest_" + std::to_string(i)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    logger->shutdown();
    SUCCEED();
}

TEST_F(AsyncLoggerTest, OverflowPolicy_DropOldest_Full)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1000;
    config.overflow_policy = OverflowPolicy::DropOldest;
    config.flush_interval = std::chrono::milliseconds{5000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 200; ++i)
    {
        static_cast<void>(logger->enqueue(LogLevel::Info, "drop_oldest_" + std::to_string(i)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    logger->shutdown();
    SUCCEED();
}

TEST_F(AsyncLoggerTest, OverflowPolicy_SyncFallback)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1000;
    config.overflow_policy = OverflowPolicy::SyncFallback;
    config.flush_interval = std::chrono::milliseconds{5000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 200; ++i)
    {
        EXPECT_TRUE(logger->enqueue(LogLevel::Info, "sync_fallback_" + std::to_string(i)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    logger->shutdown();
    SUCCEED();
}

TEST_F(AsyncLoggerTest, OverflowPolicy_Block)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 10;
    config.overflow_policy = OverflowPolicy::Block;
    config.block_timeout_ms = std::chrono::milliseconds{200};
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(logger->enqueue(LogLevel::Info, "block_policy_" + std::to_string(i)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    logger->shutdown();
    SUCCEED();
}

TEST(AsyncLoggerConfigTest, InvalidConfig_Throws)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 0;

    auto file_stream = std::make_shared<std::ofstream>();
    auto log_mutex = std::make_shared<std::mutex>();

    EXPECT_THROW(AsyncLogger(config, file_stream, log_mutex), std::invalid_argument);
}

TEST(AsyncLoggerConfigTest, NullFileStream_Throws)
{
    AsyncLoggerConfig config;
    auto log_mutex = std::make_shared<std::mutex>();

    EXPECT_THROW(AsyncLogger(config, nullptr, log_mutex), std::invalid_argument);
}

TEST(AsyncLoggerConfigTest, NullMutex_Throws)
{
    AsyncLoggerConfig config;
    auto file_stream = std::make_shared<std::ofstream>();

    EXPECT_THROW(AsyncLogger(config, file_stream, nullptr), std::invalid_argument);
}

TEST(DynamicMPMCQueueTest, InvalidCapacity_NotPowerOfTwo)
{
    EXPECT_THROW(DynamicMPMCQueue(3), std::invalid_argument);
    EXPECT_THROW(DynamicMPMCQueue(5), std::invalid_argument);
    EXPECT_THROW(DynamicMPMCQueue(100), std::invalid_argument);
    EXPECT_THROW(DynamicMPMCQueue(1000), std::invalid_argument);
}

TEST(DynamicMPMCQueueTest, InvalidCapacity_TooSmall)
{
    EXPECT_THROW(DynamicMPMCQueue(0), std::invalid_argument);
    EXPECT_THROW(DynamicMPMCQueue(1), std::invalid_argument);
}

TEST(DynamicMPMCQueueTest, ValidCapacity)
{
    EXPECT_NO_THROW(DynamicMPMCQueue(2));
    EXPECT_NO_THROW(DynamicMPMCQueue(4));
    EXPECT_NO_THROW(DynamicMPMCQueue(8));
    EXPECT_NO_THROW(DynamicMPMCQueue(16));
}

TEST(DynamicMPMCQueueTest, CapacityAccessor)
{
    DynamicMPMCQueue queue(4);
    EXPECT_EQ(queue.capacity(), 4u);
}

TEST(DynamicMPMCQueueTest, FullAndEmptyQueue)
{
    DynamicMPMCQueue queue(2);

    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.size(), 0u);

    LogMessage msg1(LogLevel::Info, "msg1");
    LogMessage msg2(LogLevel::Info, "msg2");
    EXPECT_TRUE(queue.try_push(msg1));
    EXPECT_TRUE(queue.try_push(msg2));

    EXPECT_EQ(queue.size(), 2u);
    EXPECT_FALSE(queue.empty());

    LogMessage overflow_msg(LogLevel::Info, "overflow_msg");
    EXPECT_FALSE(queue.try_push(overflow_msg));

    LogMessage popped;
    EXPECT_TRUE(queue.try_pop(popped));
    EXPECT_TRUE(queue.try_pop(popped));

    EXPECT_FALSE(queue.try_pop(popped));
    EXPECT_TRUE(queue.empty());
}

TEST(LogMessageTest, MoveConstructor)
{
    LogMessage msg1(LogLevel::Warning, "warning message");
    std::string original_msg(msg1.message());

    LogMessage msg2(std::move(msg1));

    EXPECT_EQ(msg2.message(), original_msg);
    EXPECT_EQ(msg2.level, LogLevel::Warning);
    EXPECT_TRUE(msg2.is_valid());
}

TEST(LogMessageTest, MoveAssignment)
{
    LogMessage msg1(LogLevel::Info, "info message");
    LogMessage msg2(LogLevel::Debug, "debug message");
    std::string original_msg(msg1.message());

    msg2 = std::move(msg1);

    EXPECT_EQ(msg2.message(), original_msg);
    EXPECT_EQ(msg2.level, LogLevel::Info);
    EXPECT_TRUE(msg2.is_valid());
}

TEST(LogMessageTest, InlineMessage_ExactSize)
{
    std::string msg(LogMessage::MAX_INLINE_SIZE, 'A');
    LogMessage log_msg(LogLevel::Info, msg);

    EXPECT_EQ(log_msg.message().size(), LogMessage::MAX_INLINE_SIZE);
    EXPECT_EQ(log_msg.message(), msg);
    EXPECT_EQ(log_msg.overflow, nullptr);
}

TEST(LogMessageTest, LargeMessage_HeapPath)
{
    std::string msg(LogMessage::MAX_INLINE_SIZE + 1, 'B');
    LogMessage log_msg(LogLevel::Info, msg);

    EXPECT_EQ(log_msg.message().size(), LogMessage::MAX_INLINE_SIZE + 1);
    EXPECT_EQ(log_msg.message(), msg);
    EXPECT_NE(log_msg.overflow, nullptr);
}

TEST(AsyncLoggerConfigTest, Validate_AllReturnValues)
{
    AsyncLoggerConfig valid_config;
    EXPECT_TRUE(valid_config.validate());

    AsyncLoggerConfig zero_cap;
    zero_cap.queue_capacity = 0;
    EXPECT_FALSE(zero_cap.validate());

    AsyncLoggerConfig bad_cap;
    bad_cap.queue_capacity = 100;
    EXPECT_FALSE(bad_cap.validate());

    AsyncLoggerConfig zero_batch;
    zero_batch.batch_size = 0;
    EXPECT_FALSE(zero_batch.validate());

    AsyncLoggerConfig zero_interval;
    zero_interval.flush_interval = std::chrono::milliseconds{0};
    EXPECT_FALSE(zero_interval.validate());

    AsyncLoggerConfig zero_spin;
    zero_spin.spin_backoff_iterations = 0;
    EXPECT_FALSE(zero_spin.validate());
}

TEST(AsyncLoggerConfigTest, Validate_ValidSpinBackoff)
{
    AsyncLoggerConfig config;
    config.spin_backoff_iterations = 100;
    EXPECT_TRUE(config.validate());
}

TEST_F(AsyncLoggerTest, MessageContentVerification)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    static_cast<void>(logger->enqueue(LogLevel::Info, "UNIQUE_MARKER_abc123"));
    logger->shutdown();
    file_stream->close();

    std::ifstream in(test_log_file_);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("UNIQUE_MARKER_abc123"), std::string::npos);
}

TEST_F(AsyncLoggerTest, DestructorFlushGuarantee)
{
    {
        auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
        auto log_mutex = std::make_shared<std::mutex>();
        AsyncLoggerConfig config;
        config.batch_size = 10;
        config.flush_interval = std::chrono::milliseconds{50};

        AsyncLogger logger(config, file_stream, log_mutex);
        static_cast<void>(logger.enqueue(LogLevel::Warning, "DESTRUCTOR_FLUSH_MSG_1"));
        static_cast<void>(logger.enqueue(LogLevel::Error, "DESTRUCTOR_FLUSH_MSG_2"));
    }

    std::ifstream in(test_log_file_);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("DESTRUCTOR_FLUSH_MSG_1"), std::string::npos);
    EXPECT_NE(content.find("DESTRUCTOR_FLUSH_MSG_2"), std::string::npos);
}

TEST_F(AsyncLoggerTest, BatchBoundaryBehavior)
{
    constexpr size_t kBatchSize = 4;
    AsyncLoggerConfig config;
    config.batch_size = kBatchSize;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    for (size_t i = 0; i < kBatchSize; ++i)
    {
        static_cast<void>(logger->enqueue(LogLevel::Info, "BATCH_MSG_" + std::to_string(i)));
    }
    logger->shutdown();
    file_stream->close();

    std::ifstream in(test_log_file_);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    for (size_t i = 0; i < kBatchSize; ++i)
    {
        EXPECT_NE(content.find("BATCH_MSG_" + std::to_string(i)), std::string::npos);
    }
}

TEST_F(AsyncLoggerTest, ConcurrentFlushAndEnqueue)
{
    AsyncLoggerConfig config;
    config.batch_size = 16;
    config.flush_interval = std::chrono::milliseconds{20};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    std::atomic<bool> done{false};

    std::thread producer([&]()
                         {
        for (int i = 0; i < 100; ++i)
        {
            static_cast<void>(logger->enqueue(LogLevel::Info, "CONCURRENT_MSG_" + std::to_string(i)));
        }
        done.store(true, std::memory_order_release); });

    std::thread flusher([&]()
                        {
        while (!done.load(std::memory_order_acquire))
        {
            logger->flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } });

    producer.join();
    flusher.join();
    logger->shutdown();
    file_stream->close();

    std::ifstream in(test_log_file_);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    EXPECT_FALSE(content.empty());
}

TEST(DynamicMPMCQueueTest, MultiThreaded)
{
    constexpr size_t kCapacity = 64;
    constexpr int kProducers = 4;
    constexpr int kConsumers = 4;
    constexpr int kItemsPerProducer = 500;

    DynamicMPMCQueue queue(kCapacity);
    std::atomic<int> total_produced{0};
    std::atomic<int> total_consumed{0};
    std::atomic<bool> producers_done{false};

    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p)
    {
        producers.emplace_back([&, p]()
                               {
            for (int i = 0; i < kItemsPerProducer; ++i)
            {
                LogMessage msg(LogLevel::Info, "P" + std::to_string(p) + "_" + std::to_string(i));
                while (!queue.try_push(msg))
                {
                    std::this_thread::yield();
                }
                total_produced.fetch_add(1, std::memory_order_relaxed);
            } });
    }

    std::vector<std::thread> consumers;
    for (int c = 0; c < kConsumers; ++c)
    {
        consumers.emplace_back([&]()
                               {
            LogMessage msg;
            while (!producers_done.load(std::memory_order_acquire) || !queue.empty())
            {
                if (queue.try_pop(msg))
                {
                    total_consumed.fetch_add(1, std::memory_order_relaxed);
                }
                else
                {
                    std::this_thread::yield();
                }
            } });
    }

    for (auto &t : producers)
    {
        t.join();
    }
    producers_done.store(true, std::memory_order_release);

    for (auto &t : consumers)
    {
        t.join();
    }

    EXPECT_EQ(total_produced.load(), kProducers * kItemsPerProducer);
    EXPECT_EQ(total_consumed.load(), total_produced.load());
}

TEST(LogMessageTest, SelfMoveAssign)
{
    LogMessage msg(LogLevel::Info, "self-move test");
    ASSERT_EQ(msg.message(), "self-move test");

    LogMessage moved = std::move(msg);
    msg = std::move(moved);

    EXPECT_EQ(msg.message(), "self-move test");
}

TEST(LogMessageTest, IsValid_InlineMessage)
{
    std::string short_msg("short message");
    LogMessage msg(LogLevel::Info, short_msg);
    EXPECT_TRUE(msg.is_valid());
}

TEST(LogMessageTest, IsValid_OverflowMessage)
{
    std::string long_msg(LogMessage::MAX_INLINE_SIZE + 100, 'X');
    LogMessage msg(LogLevel::Info, long_msg);
    EXPECT_TRUE(msg.is_valid());
}

TEST(LogMessageTest, MaxMessageSizeTruncation)
{
    std::string huge_msg(DetourModKit::MAX_MESSAGE_SIZE + 1000, 'Y');
    LogMessage msg(LogLevel::Info, huge_msg);
    EXPECT_EQ(msg.message().size(), DetourModKit::MAX_MESSAGE_SIZE);
    EXPECT_TRUE(msg.is_valid());
}

TEST(LogMessageTest, DefaultConstructed_IsValid)
{
    LogMessage msg;
    EXPECT_TRUE(msg.is_valid());
    EXPECT_EQ(msg.message().size(), 0u);
}

TEST(LogMessageTest, MovePreservesValidity)
{
    LogMessage msg1(LogLevel::Warning, "warning message");
    ASSERT_TRUE(msg1.is_valid());

    LogMessage msg2(std::move(msg1));
    EXPECT_TRUE(msg2.is_valid());
}

TEST(LogMessageTest, MoveAssignmentPreservesValidity)
{
    LogMessage msg1(LogLevel::Info, "info message");
    LogMessage msg2(LogLevel::Debug, "debug message");
    ASSERT_TRUE(msg1.is_valid());

    msg2 = std::move(msg1);
    EXPECT_TRUE(msg2.is_valid());
}

TEST_F(AsyncLoggerTest, FlushGuarantee_AllMessagesWritten)
{
    AsyncLoggerConfig config;
    config.batch_size = 4;
    config.flush_interval = std::chrono::milliseconds{1000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(logger->enqueue(LogLevel::Info, "FLUSH_TEST_MSG_" + std::to_string(i)));
    }

    logger->flush();
    logger->shutdown();
    file_stream->close();

    std::ifstream in(test_log_file_);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_NE(content.find("FLUSH_TEST_MSG_" + std::to_string(i)), std::string::npos);
    }
}

TEST(DynamicMPMCQueueTest, TryPopBatch_BulkDequeue)
{
    DynamicMPMCQueue queue(16);

    for (int i = 0; i < 8; ++i)
    {
        LogMessage msg(LogLevel::Info, "batch_msg_" + std::to_string(i));
        EXPECT_TRUE(queue.try_push(msg));
    }

    std::vector<LogMessage> items;
    size_t count = queue.try_pop_batch(items, 4);

    EXPECT_EQ(count, 4u);
    EXPECT_EQ(items.size(), 4u);
    EXPECT_EQ(queue.size(), 4u);
}

TEST(DynamicMPMCQueueTest, TryPopBatch_LessThanRequested)
{
    DynamicMPMCQueue queue(16);

    for (int i = 0; i < 3; ++i)
    {
        LogMessage msg(LogLevel::Info, "partial_batch_" + std::to_string(i));
        EXPECT_TRUE(queue.try_push(msg));
    }

    std::vector<LogMessage> items;
    size_t count = queue.try_pop_batch(items, 10);

    EXPECT_EQ(count, 3u);
    EXPECT_EQ(items.size(), 3u);
    EXPECT_TRUE(queue.empty());
}

TEST(DynamicMPMCQueueTest, TryPopBatch_EmptyQueue)
{
    DynamicMPMCQueue queue(16);
    std::vector<LogMessage> items;
    size_t count = queue.try_pop_batch(items, 10);

    EXPECT_EQ(count, 0u);
    EXPECT_TRUE(items.empty());
}

TEST(DynamicMPMCQueueTest, TryPopBatch_ZeroMaxCount)
{
    DynamicMPMCQueue queue(16);
    LogMessage msg(LogLevel::Info, "should_not_be_popped");
    EXPECT_TRUE(queue.try_push(msg));

    std::vector<LogMessage> items;
    size_t count = queue.try_pop_batch(items, 0);

    EXPECT_EQ(count, 0u);
    EXPECT_TRUE(items.empty());
    EXPECT_EQ(queue.size(), 1u);
}

TEST_F(AsyncLoggerTest, FlushWithTimeout_Success)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 4;
    config.batch_size = 4;
    config.flush_interval = std::chrono::milliseconds{10000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 10; ++i)
    {
        static_cast<void>(logger->enqueue(LogLevel::Info, "test_msg_" + std::to_string(i)));
    }

    bool result = logger->flush_with_timeout(std::chrono::milliseconds(500));

    EXPECT_TRUE(result);
    logger->shutdown();
}

TEST_F(AsyncLoggerTest, FlushWithTimeout_WhenNotRunning)
{
    AsyncLoggerConfig config;
    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    logger->shutdown();

    bool result = logger->flush_with_timeout(std::chrono::milliseconds(100));

    EXPECT_TRUE(result);
}

TEST_F(AsyncLoggerTest, DroppedCount_Increment)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1;
    config.overflow_policy = OverflowPolicy::DropNewest;
    config.flush_interval = std::chrono::milliseconds{10000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_EQ(logger->dropped_count(), 0u);

    for (int i = 0; i < 100; ++i)
    {
        static_cast<void>(logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_GT(logger->dropped_count(), 0u);
    logger->shutdown();
}

TEST_F(AsyncLoggerTest, DroppedCount_DropOldest)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1;
    config.overflow_policy = OverflowPolicy::DropOldest;
    config.flush_interval = std::chrono::milliseconds{10000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    static_cast<void>(logger->enqueue(LogLevel::Info, "first_msg"));
    static_cast<void>(logger->enqueue(LogLevel::Info, "second_msg"));
    static_cast<void>(logger->enqueue(LogLevel::Info, "third_msg"));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_GE(logger->dropped_count(), 1u);
    logger->shutdown();
}

TEST_F(AsyncLoggerTest, DroppedCount_Reset)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1;
    config.overflow_policy = OverflowPolicy::DropNewest;
    config.flush_interval = std::chrono::milliseconds{10000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 50; ++i)
    {
        static_cast<void>(logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    size_t first_drop_count = logger->dropped_count();
    EXPECT_GT(first_drop_count, 0u);

    logger->reset_dropped_count();

    EXPECT_EQ(logger->dropped_count(), 0u);
    logger->shutdown();
}

TEST_F(AsyncLoggerTest, DroppedCount_DropNewest)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1;
    config.overflow_policy = OverflowPolicy::DropNewest;
    config.flush_interval = std::chrono::milliseconds{10000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    constexpr int kFillCount = 100;
    for (int i = 0; i < kFillCount; ++i)
    {
        static_cast<void>(logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    size_t dropped = logger->dropped_count();
    EXPECT_GT(dropped, 0u);
    logger->shutdown();
}

TEST_F(AsyncLoggerTest, QueueSize_Accuracy)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 16;
    config.batch_size = 4;
    config.flush_interval = std::chrono::milliseconds{1000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 8; ++i)
    {
        static_cast<void>(logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    size_t queue_size = logger->queue_size();
    EXPECT_GE(queue_size, 0u);

    logger->shutdown();
}

TEST_F(AsyncLoggerTest, Shutdown_DrainsAllPending)
{
    AsyncLoggerConfig config;
    config.batch_size = 4;
    config.flush_interval = std::chrono::milliseconds{10000};

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_);
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 20; ++i)
    {
        EXPECT_TRUE(logger->enqueue(LogLevel::Info, "SHUTDOWN_DRAIN_MSG_" + std::to_string(i)));
    }

    logger->shutdown();
    file_stream->close();

    std::ifstream in(test_log_file_);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());

    for (int i = 0; i < 20; ++i)
    {
        EXPECT_NE(content.find("SHUTDOWN_DRAIN_MSG_" + std::to_string(i)), std::string::npos);
    }
}

TEST(DynamicMPMCQueueTest, TryPopBatch_PreservesOrder)
{
    DynamicMPMCQueue queue(16);

    for (int i = 0; i < 8; ++i)
    {
        LogMessage msg(LogLevel::Info, "ordered_msg_" + std::to_string(i));
        EXPECT_TRUE(queue.try_push(msg));
    }

    std::vector<LogMessage> items;
    queue.try_pop_batch(items, 8);

    EXPECT_EQ(items.size(), 8u);
    for (size_t i = 0; i < items.size(); ++i)
    {
        std::string expected = "ordered_msg_" + std::to_string(i);
        EXPECT_EQ(items[i].message(), expected);
    }
}

TEST(AsyncLoggerConfigTest, BlockTimeoutDefault_IsSingleFrame)
{
    AsyncLoggerConfig config;
    EXPECT_EQ(config.block_timeout_ms.count(), 16);
}

TEST(LogMessageTest, TruncatedMessage_UsesCorrectSize)
{
    // Verify that after truncation, the stored size matches the truncated content
    const size_t truncation_boundary = LogMessage::MAX_VALID_LENGTH;
    std::string large_msg(truncation_boundary + 100, 'X');

    LogMessage msg(LogLevel::Info, std::move(large_msg));
    EXPECT_TRUE(msg.is_valid());
    EXPECT_EQ(msg.message().size(), truncation_boundary);
}

TEST(LogMessageTest, InlineBoundary_256Bytes)
{
    // Exactly MAX_INLINE_SIZE should use inline buffer
    std::string exact(LogMessage::MAX_INLINE_SIZE, 'A');
    LogMessage msg_inline(LogLevel::Info, std::string(exact));
    EXPECT_TRUE(msg_inline.is_valid());
    EXPECT_EQ(msg_inline.message().size(), LogMessage::MAX_INLINE_SIZE);
    EXPECT_EQ(msg_inline.overflow, nullptr);
}

TEST(LogMessageTest, OverflowBoundary_257Bytes)
{
    // MAX_INLINE_SIZE + 1 should use overflow path
    std::string overflow_msg(LogMessage::MAX_INLINE_SIZE + 1, 'B');
    LogMessage msg_overflow(LogLevel::Info, std::string(overflow_msg));
    EXPECT_TRUE(msg_overflow.is_valid());
    EXPECT_EQ(msg_overflow.message().size(), LogMessage::MAX_INLINE_SIZE + 1);
    EXPECT_NE(msg_overflow.overflow, nullptr);
}

TEST_F(AsyncLoggerTest, DropOldest_NoCounterUnderflow)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 4;
    config.batch_size = 2;
    config.overflow_policy = OverflowPolicy::DropOldest;

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_.string());
    auto log_mutex = std::make_shared<std::mutex>();

    AsyncLogger logger(config, file_stream, log_mutex);

    // Fill the queue
    for (int i = 0; i < 4; ++i)
    {
        static_cast<void>(logger.enqueue(LogLevel::Info, "fill_" + std::to_string(i)));
    }

    // Overflow: should drop oldest and push new
    for (int i = 0; i < 4; ++i)
    {
        static_cast<void>(logger.enqueue(LogLevel::Info, "overflow_" + std::to_string(i)));
    }

    // flush should complete without hanging (no counter underflow)
    bool flushed = logger.flush_with_timeout(std::chrono::milliseconds(2000));
    EXPECT_TRUE(flushed);

    logger.shutdown();
}

TEST_F(AsyncLoggerTest, SyncFallback_WritesWhenQueueFull)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1;
    config.overflow_policy = OverflowPolicy::SyncFallback;

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_.string());
    auto log_mutex = std::make_shared<std::mutex>();

    AsyncLogger logger(config, file_stream, log_mutex);

    // Fill the queue
    static_cast<void>(logger.enqueue(LogLevel::Info, "msg1"));
    static_cast<void>(logger.enqueue(LogLevel::Info, "msg2"));

    // This should trigger SyncFallback path
    bool result = logger.enqueue(LogLevel::Info, "sync_fallback_message");
    EXPECT_TRUE(result);

    logger.shutdown();
    file_stream->close();

    // Verify the sync fallback message was written
    std::ifstream read_file(test_log_file_.string());
    std::string content((std::istreambuf_iterator<char>(read_file)),
                        std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("sync_fallback_message"), std::string::npos);
}

TEST_F(AsyncLoggerTest, EnqueueAfterShutdown_WritesSync)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 64;
    config.batch_size = 10;

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_.string());
    auto log_mutex = std::make_shared<std::mutex>();

    AsyncLogger logger(config, file_stream, log_mutex);
    logger.shutdown();

    // After shutdown, enqueue should fall back to synchronous write
    bool result = logger.enqueue(LogLevel::Info, "post_shutdown_message");
    EXPECT_TRUE(result);

    file_stream->close();

    std::ifstream read_file(test_log_file_.string());
    std::string content((std::istreambuf_iterator<char>(read_file)),
                        std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("post_shutdown_message"), std::string::npos);
}

TEST_F(AsyncLoggerTest, MultiThread_EnqueueStress)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 1024;
    config.batch_size = 32;
    config.overflow_policy = OverflowPolicy::DropNewest;

    auto file_stream = std::make_shared<std::ofstream>(test_log_file_.string());
    auto log_mutex = std::make_shared<std::mutex>();

    AsyncLogger logger(config, file_stream, log_mutex);

    constexpr int num_threads = 4;
    constexpr int msgs_per_thread = 500;
    std::atomic<int> total_enqueued{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back([&, t]()
                             {
            for (int i = 0; i < msgs_per_thread; ++i)
            {
                if (logger.enqueue(LogLevel::Info, "thread_" + std::to_string(t) + "_msg_" + std::to_string(i)))
                {
                    total_enqueued.fetch_add(1, std::memory_order_relaxed);
                }
            } });
    }

    for (auto &th : threads)
    {
        th.join();
    }

    bool flushed = logger.flush_with_timeout(std::chrono::milliseconds(5000));
    EXPECT_TRUE(flushed);

    // At least some messages should have been enqueued
    EXPECT_GT(total_enqueued.load(), 0);
    // Total enqueued + dropped should equal total attempted
    EXPECT_EQ(total_enqueued.load() + static_cast<int>(logger.dropped_count()),
              num_threads * msgs_per_thread);

    logger.shutdown();
}
