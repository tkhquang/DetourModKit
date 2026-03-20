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

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_NE(logger, nullptr);
    EXPECT_TRUE(logger->is_running());
}

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

TEST_F(AsyncLoggerTest, Enqueue)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->enqueue(LogLevel::Info, "Test message 1");
    logger->enqueue(LogLevel::Debug, "Test message 2");
    logger->enqueue(LogLevel::Warning, "Test message 3");

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

TEST_F(AsyncLoggerTest, Flush)
{
    AsyncLoggerConfig config;
    config.batch_size = 100;
    config.flush_interval = std::chrono::milliseconds{1000};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->enqueue(LogLevel::Info, "Flush test message");

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_NO_THROW(logger->flush());

    logger->shutdown();
}

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

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->enqueue(LogLevel::Info, "");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    SUCCEED();
}

TEST_F(AsyncLoggerTest, LongMessage)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    std::string long_msg(1000, 'X');
    logger->enqueue(LogLevel::Info, long_msg);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    SUCCEED();
}

TEST_F(AsyncLoggerTest, DoubleShutdown)
{
    AsyncLoggerConfig config;
    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->shutdown();

    EXPECT_NO_THROW(logger->shutdown());
}

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

TEST_F(AsyncLoggerTest, EnqueueAfterShutdown_SyncWrite)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->shutdown();
    EXPECT_FALSE(logger->is_running());

    EXPECT_NO_THROW(logger->enqueue(LogLevel::Info, "Post-shutdown sync message"));
    EXPECT_NO_THROW(logger->enqueue(LogLevel::Error, "Post-shutdown sync error"));
    EXPECT_NO_THROW(logger->enqueue(LogLevel::Warning, "Post-shutdown sync warning"));
}

TEST_F(AsyncLoggerTest, Flush_WhenNotRunning)
{
    AsyncLoggerConfig config;
    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

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

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 200; ++i)
    {
        logger->enqueue(LogLevel::Info, "drop_newest_" + std::to_string(i));
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

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 200; ++i)
    {
        logger->enqueue(LogLevel::Info, "drop_oldest_" + std::to_string(i));
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

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 200; ++i)
    {
        logger->enqueue(LogLevel::Info, "sync_fallback_" + std::to_string(i));
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
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 10; ++i)
    {
        logger->enqueue(LogLevel::Info, "block_policy_" + std::to_string(i));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    logger->shutdown();
    SUCCEED();
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

    EXPECT_TRUE(queue.try_push(LogMessage(LogLevel::Info, "msg1")));
    EXPECT_TRUE(queue.try_push(LogMessage(LogLevel::Info, "msg2")));

    EXPECT_EQ(queue.size(), 2u);
    EXPECT_FALSE(queue.empty());

    EXPECT_FALSE(queue.try_push(LogMessage(LogLevel::Info, "overflow_msg")));

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
    EXPECT_EQ(msg1.length, 0u);
}

TEST(LogMessageTest, MoveAssignment)
{
    LogMessage msg1(LogLevel::Info, "info message");
    LogMessage msg2(LogLevel::Debug, "debug message");
    std::string original_msg(msg1.message());

    msg2 = std::move(msg1);

    EXPECT_EQ(msg2.message(), original_msg);
    EXPECT_EQ(msg2.level, LogLevel::Info);
    EXPECT_EQ(msg1.length, 0u);
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
}

TEST_F(AsyncLoggerTest, MessageContentVerification)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    logger->enqueue(LogLevel::Info, "UNIQUE_MARKER_abc123");
    logger->shutdown();
    file_stream.close();

    std::ifstream in(test_log_file_);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("UNIQUE_MARKER_abc123"), std::string::npos);
}

TEST_F(AsyncLoggerTest, DestructorFlushGuarantee)
{
    {
        std::ofstream file_stream(test_log_file_);
        std::mutex log_mutex;
        AsyncLoggerConfig config;
        config.batch_size = 10;
        config.flush_interval = std::chrono::milliseconds{50};

        AsyncLogger logger(config, file_stream, log_mutex);
        logger.enqueue(LogLevel::Warning, "DESTRUCTOR_FLUSH_MSG_1");
        logger.enqueue(LogLevel::Error, "DESTRUCTOR_FLUSH_MSG_2");
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

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    for (size_t i = 0; i < kBatchSize; ++i)
    {
        logger->enqueue(LogLevel::Info, "BATCH_MSG_" + std::to_string(i));
    }
    logger->shutdown();
    file_stream.close();

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

    std::ofstream file_stream(test_log_file_);
    std::mutex log_mutex;

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    std::atomic<bool> done{false};

    std::thread producer([&]()
                         {
        for (int i = 0; i < 100; ++i)
        {
            logger->enqueue(LogLevel::Info, "CONCURRENT_MSG_" + std::to_string(i));
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
    file_stream.close();

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
                while (!queue.try_push(std::move(msg)))
                {
                    std::this_thread::yield();
                    msg = LogMessage(LogLevel::Info, "P" + std::to_string(p) + "_" + std::to_string(i));
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

    msg = std::move(msg);

    EXPECT_EQ(msg.message(), "self-move test");
}
