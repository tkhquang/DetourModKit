#include <gtest/gtest.h>
#include <algorithm>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <process.h>
#include <regex>
#include <sstream>
#include <cstdint>
#include <type_traits>

#include "DetourModKit/diagnostics.hpp"

#include "internal/async_logger.hpp"
#include "internal/async_logger_queue.hpp"
#include "internal/win_file_stream.hpp"
#include "test_alloc_probe.hpp"

using namespace DetourModKit;
// White-box access: StringPool, LogMessage, and DynamicMPMCQueue (plus their sizing constants) are the AsyncLogger
// pimpl's transport types, defined in the non-installed internal/async_logger_queue.hpp. These tests exercise that
// plumbing directly, so they include the private header and reach into the detail namespace deliberately; production
// consumers never do.
using namespace DetourModKit::detail;

class AsyncLoggerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static int s_test_counter = 0;
        m_test_log_file = std::filesystem::temp_directory_path() / ("test_async_logger_" + std::to_string(_getpid()) +
                                                                    "_" + std::to_string(s_test_counter++) + ".log");
    }

    void TearDown() override
    {
        if (std::filesystem::exists(m_test_log_file))
        {
            std::filesystem::remove(m_test_log_file);
        }
    }

    std::filesystem::path m_test_log_file;
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    (void)logger->enqueue(LogLevel::Info, "Test message 1");
    (void)logger->enqueue(LogLevel::Debug, "Test message 2");
    (void)logger->enqueue(LogLevel::Warning, "Test message 3");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logger->shutdown();

    EXPECT_TRUE(std::filesystem::exists(m_test_log_file));

    std::ifstream file(m_test_log_file);
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

TEST_F(AsyncLoggerTest, HonorsConfiguredTimestampFormat)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};
    // A format distinct from the default "%Y-%m-%d %H:%M:%S" with a literal marker that strftime/put_time passes
    // through verbatim. The marker can only appear in the output if the async sink honors the configured format.
    config.timestamp_format = "%Y/%m/%d STAMP";

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    (void)logger->enqueue(LogLevel::Info, "formatted");
    logger->shutdown(); // drains queued messages before returning

    std::ifstream file(m_test_log_file);
    std::string line;
    bool found = false;
    while (std::getline(file, line))
    {
        if (line.find("STAMP") != std::string::npos && line.find("formatted") != std::string::npos)
        {
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(AsyncLoggerTest, Enqueue_ReturnsTrue_OnSuccess)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    auto result1 = logger->enqueue(LogLevel::Info, "msg1");
    auto result2 = logger->enqueue(LogLevel::Info, "msg2");
    auto result3_unused = logger->enqueue(LogLevel::Info, "msg3");

    EXPECT_TRUE(result1);
    EXPECT_TRUE(result2);
    (void)result3_unused;

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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    (void)logger->enqueue(LogLevel::Info, "Flush test message");

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_NO_THROW(logger->flush());

    logger->shutdown();
}

TEST_F(AsyncLoggerTest, MultiThreadedLogging)
{
    AsyncLoggerConfig config;
    config.batch_size = 100;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    const int num_threads = 4;
    const int messages_per_thread = 25;

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back(
            [&logger, i, messages_per_thread]()
            {
                for (int j = 0; j < messages_per_thread; ++j)
                {
                    (void)logger->enqueue(LogLevel::Info,
                                          "Thread " + std::to_string(i) + " message " + std::to_string(j));
                }
            });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    logger->shutdown();

    EXPECT_TRUE(std::filesystem::exists(m_test_log_file));
}

TEST_F(AsyncLoggerTest, EmptyMessage)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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
    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->shutdown();

    EXPECT_NO_THROW(logger->shutdown());
}

TEST_F(AsyncLoggerTest, IsRunningAfterShutdown)
{
    AsyncLoggerConfig config;
    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_TRUE(logger->is_running());

    logger->shutdown();

    EXPECT_FALSE(logger->is_running());
}

TEST_F(AsyncLoggerTest, EnqueueAfterShutdownDropsAndCounts)
{
    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    logger->shutdown();
    EXPECT_FALSE(logger->is_running());

    // Once shutdown has begun the retained writer owns final sink access, so a callback-safe producer must drop and
    // count rather than switch to blocking synchronous I/O.
    const std::size_t before = logger->dropped_count();
    EXPECT_FALSE(logger->enqueue(LogLevel::Info, "Post-shutdown message"));
    EXPECT_FALSE(logger->enqueue(LogLevel::Error, "Post-shutdown error"));
    EXPECT_FALSE(logger->enqueue(LogLevel::Warning, "Post-shutdown warning"));
    EXPECT_EQ(logger->dropped_count(), before + 3);
}

TEST_F(AsyncLoggerTest, Flush_WhenNotRunning)
{
    AsyncLoggerConfig config;
    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 200; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "drop_newest_" + std::to_string(i));
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 200; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "drop_oldest_" + std::to_string(i));
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>();
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
    auto file_stream = std::make_shared<WinFileStream>();

    EXPECT_THROW(AsyncLogger(config, file_stream, nullptr), std::invalid_argument);
}

TEST(AsyncLoggerConfigTest, Validate_DefaultIsValid)
{
    AsyncLoggerConfig config;
    EXPECT_TRUE(config.validate());
}

TEST(AsyncLoggerConfigTest, Validate_RejectsNonPowerOfTwoCapacity)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 5;
    EXPECT_FALSE(config.validate());
}

TEST(AsyncLoggerConfigTest, Validate_RejectsCapacityBelowTwo)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 1;
    EXPECT_FALSE(config.validate());
    config.queue_capacity = 0;
    EXPECT_FALSE(config.validate());
}

TEST(AsyncLoggerConfigTest, Validate_RejectsZeroBatch)
{
    AsyncLoggerConfig config;
    config.batch_size = 0;
    EXPECT_FALSE(config.validate());
}

TEST(AsyncLoggerConfigTest, Validate_RejectsNonPositiveFlushInterval)
{
    AsyncLoggerConfig config;
    config.flush_interval = std::chrono::milliseconds{0};
    EXPECT_FALSE(config.validate());
    config.flush_interval = std::chrono::milliseconds{-1};
    EXPECT_FALSE(config.validate());
}

TEST(AsyncLoggerConfigTest, Validate_RejectsZeroSpinBackoff)
{
    AsyncLoggerConfig config;
    config.spin_backoff_iterations = 0;
    EXPECT_FALSE(config.validate());
}

TEST(AsyncLoggerConfigTest, Validate_RejectsNonPositiveBlockTimeout)
{
    AsyncLoggerConfig config;
    config.block_timeout_ms = std::chrono::milliseconds{0};
    EXPECT_FALSE(config.validate());
    config.block_timeout_ms = std::chrono::milliseconds{-5};
    EXPECT_FALSE(config.validate());
}

TEST(AsyncLoggerConfigTest, Validate_RejectsZeroBlockMaxSpin)
{
    AsyncLoggerConfig config;
    config.block_max_spin_iterations = 0;
    EXPECT_FALSE(config.validate());
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
    DynamicMPMCQueue queue(64);
    EXPECT_EQ(queue.capacity(), 64u);
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.size(), 0u);
}

TEST(DynamicMPMCQueueTest, CacheLineAlignment)
{
    DynamicMPMCQueue queue(4);
    auto addr = reinterpret_cast<std::uintptr_t>(&queue);

    // DynamicMPMCQueue contains alignas(64) members; the struct itself must satisfy that alignment so the atomics land
    // on separate cache lines.
    EXPECT_EQ(alignof(DynamicMPMCQueue), 64u);
    EXPECT_EQ(addr % 64u, 0u);
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
    EXPECT_EQ(popped.message(), "msg1");
    EXPECT_TRUE(queue.try_pop(popped));
    EXPECT_EQ(popped.message(), "msg2");

    EXPECT_FALSE(queue.try_pop(popped));
    EXPECT_TRUE(queue.empty());

    // Wraparound: push/pop again after draining to exercise head/tail wrap
    LogMessage wrap1(LogLevel::Debug, "wrap1");
    LogMessage wrap2(LogLevel::Debug, "wrap2");
    EXPECT_TRUE(queue.try_push(wrap1));
    EXPECT_TRUE(queue.try_push(wrap2));
    EXPECT_EQ(queue.size(), 2u);

    LogMessage wrap_out;
    EXPECT_TRUE(queue.try_pop(wrap_out));
    EXPECT_EQ(wrap_out.message(), "wrap1");
    EXPECT_TRUE(queue.try_pop(wrap_out));
    EXPECT_EQ(wrap_out.message(), "wrap2");
    EXPECT_TRUE(queue.empty());
}

TEST(DynamicMPMCQueueTest, TryPopBatch_ReserveOom_FailsClosed)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    // try_pop_batch is called from the writer thread's noexcept frame, so a
    // throwing reserve would std::terminate the host under memory pressure. It must instead fail closed: catch the
    // allocation failure and pop only within the vector's existing spare capacity. Here the destination vector has zero
    // capacity, so the injected reserve failure leaves no headroom and the call pops nothing -- rather than
    // terminating -- and the queued messages survive for a later, non-failing drain.
    DynamicMPMCQueue queue(8);

    // Seed short (inline-stored) messages before injection is armed, so these pushes do not allocate on the heap.
    for (int i = 0; i < 4; ++i)
    {
        LogMessage m(LogLevel::Info, "payload");
        ASSERT_TRUE(queue.try_push(m));
    }
    ASSERT_EQ(queue.size(), 4u);

    std::vector<LogMessage> out; // capacity 0, so try_pop_batch's reserve is the first (and failing) allocation

    size_t popped = 123; // sentinel; must be overwritten with 0
    {
        // Fail the very next throwing operator new on this thread -- the reserve inside try_pop_batch.
        dmk_test::AllocFailScope fail(0);
        popped = queue.try_pop_batch(out, 4);
    }

    EXPECT_EQ(popped, 0u) << "no headroom + rejected reserve must pop nothing, not terminate";
    EXPECT_TRUE(out.empty());
    EXPECT_EQ(queue.size(), 4u) << "the un-popped messages must remain queued";

    // With capacity available (reserved up front, outside the injected window), a subsequent call drains normally.
    std::vector<LogMessage> out2;
    out2.reserve(4);
    const size_t popped2 = queue.try_pop_batch(out2, 4);
    EXPECT_EQ(popped2, 4u);
    EXPECT_EQ(queue.size(), 0u);
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    (void)logger->enqueue(LogLevel::Info, "UNIQUE_MARKER_abc123");
    logger->shutdown();
    file_stream->close();

    std::ifstream in(m_test_log_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("UNIQUE_MARKER_abc123"), std::string::npos);
}

TEST_F(AsyncLoggerTest, DestructorFlushGuarantee)
{
    {
        auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
        auto log_mutex = std::make_shared<std::mutex>();
        AsyncLoggerConfig config;
        config.batch_size = 10;
        config.flush_interval = std::chrono::milliseconds{50};

        AsyncLogger logger(config, file_stream, log_mutex);
        (void)logger.enqueue(LogLevel::Warning, "DESTRUCTOR_FLUSH_MSG_1");
        (void)logger.enqueue(LogLevel::Error, "DESTRUCTOR_FLUSH_MSG_2");
    }

    std::ifstream in(m_test_log_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("DESTRUCTOR_FLUSH_MSG_1"), std::string::npos);
    EXPECT_NE(content.find("DESTRUCTOR_FLUSH_MSG_2"), std::string::npos);
}

TEST_F(AsyncLoggerTest, BatchBoundaryBehavior)
{
    constexpr size_t kBatchSize = 4;
    AsyncLoggerConfig config;
    config.batch_size = kBatchSize;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    for (size_t i = 0; i < kBatchSize; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "BATCH_MSG_" + std::to_string(i));
    }
    logger->shutdown();
    file_stream->close();

    std::ifstream in(m_test_log_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    std::atomic<bool> done{false};

    std::thread producer(
        [&]()
        {
            for (int i = 0; i < 100; ++i)
            {
                (void)logger->enqueue(LogLevel::Info, "CONCURRENT_MSG_" + std::to_string(i));
            }
            done.store(true, std::memory_order_release);
        });

    std::thread flusher(
        [&]()
        {
            while (!done.load(std::memory_order_acquire))
            {
                logger->flush();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });

    producer.join();
    flusher.join();
    logger->shutdown();
    file_stream->close();

    std::ifstream in(m_test_log_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
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
        producers.emplace_back(
            [&, p]()
            {
                for (int i = 0; i < kItemsPerProducer; ++i)
                {
                    LogMessage msg(LogLevel::Info, "P" + std::to_string(p) + "_" + std::to_string(i));
                    while (!queue.try_push(msg))
                    {
                        std::this_thread::yield();
                    }
                    total_produced.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }

    std::vector<std::thread> consumers;
    for (int c = 0; c < kConsumers; ++c)
    {
        consumers.emplace_back(
            [&]()
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
                }
            });
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
    std::string huge_msg(MAX_MESSAGE_SIZE + 1000, 'Y');
    LogMessage msg(LogLevel::Info, huge_msg);
    EXPECT_EQ(msg.message().size(), MAX_MESSAGE_SIZE);
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(logger->enqueue(LogLevel::Info, "FLUSH_TEST_MSG_" + std::to_string(i)));
    }

    logger->flush();
    logger->shutdown();
    file_stream->close();

    std::ifstream in(m_test_log_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 10; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "test_msg_" + std::to_string(i));
    }

    bool result = logger->flush_with_timeout(std::chrono::milliseconds(500));

    EXPECT_TRUE(result);
    logger->shutdown();
}

TEST_F(AsyncLoggerTest, FlushWithTimeout_WhenNotRunning)
{
    AsyncLoggerConfig config;
    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    EXPECT_EQ(logger->dropped_count(), 0u);

    for (int i = 0; i < 100; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i));
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Enqueue far more than the queue can hold so a DropOldest overflow is forced regardless of how fast the writer
    // thread drains. A handful of quick pushes can be consumed one-by-one and never fill the 2-slot queue, so only a
    // tight burst well past capacity reliably overruns it and produces drops.
    constexpr int kFillCount = 100;
    for (int i = 0; i < kFillCount; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i));
    }

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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 50; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i));
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    constexpr int kFillCount = 100;
    for (int i = 0; i < kFillCount; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i));
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 8; ++i)
    {
        (void)logger->enqueue(LogLevel::Info, "msg_" + std::to_string(i));
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 20; ++i)
    {
        EXPECT_TRUE(logger->enqueue(LogLevel::Info, "SHUTDOWN_DRAIN_MSG_" + std::to_string(i)));
    }

    logger->shutdown();
    file_stream->close();

    std::ifstream in(m_test_log_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

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
    const size_t count = queue.try_pop_batch(items, 8);

    EXPECT_EQ(count, 8u);
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

TEST(LogMessageTest, InlineBoundary_512Bytes)
{
    // Exactly MAX_INLINE_SIZE should use inline buffer
    std::string exact(LogMessage::MAX_INLINE_SIZE, 'A');
    LogMessage msg_inline(LogLevel::Info, std::string(exact));
    EXPECT_TRUE(msg_inline.is_valid());
    EXPECT_EQ(msg_inline.message().size(), LogMessage::MAX_INLINE_SIZE);
    EXPECT_EQ(msg_inline.overflow, nullptr);
}

TEST(LogMessageTest, OverflowBoundary_513Bytes)
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    AsyncLogger logger(config, file_stream, log_mutex);

    // Fill the queue
    for (int i = 0; i < 4; ++i)
    {
        (void)logger.enqueue(LogLevel::Info, "fill_" + std::to_string(i));
    }

    // Overflow: should drop oldest and push new
    for (int i = 0; i < 4; ++i)
    {
        (void)logger.enqueue(LogLevel::Info, "overflow_" + std::to_string(i));
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

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    AsyncLogger logger(config, file_stream, log_mutex);

    // Fill the queue
    (void)logger.enqueue(LogLevel::Info, "msg1");
    (void)logger.enqueue(LogLevel::Info, "msg2");

    // This should trigger SyncFallback path
    bool result = logger.enqueue(LogLevel::Info, "sync_fallback_message");
    EXPECT_TRUE(result);

    logger.shutdown();
    file_stream->close();

    // Verify the sync fallback message was written
    std::ifstream read_file(m_test_log_file.string());
    std::string content((std::istreambuf_iterator<char>(read_file)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("sync_fallback_message"), std::string::npos);
}

TEST_F(AsyncLoggerTest, EnqueueAfterShutdownIsNotWrittenToSink)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 64;
    config.batch_size = 10;

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    AsyncLogger logger(config, file_stream, log_mutex);
    logger.shutdown();

    // After shutdown the producer drops and counts; it does not write synchronously to the sink the retained writer
    // owns, so the message never reaches the file.
    EXPECT_FALSE(logger.enqueue(LogLevel::Info, "post_shutdown_message"));

    file_stream->close();

    std::ifstream read_file(m_test_log_file.string());
    std::string content((std::istreambuf_iterator<char>(read_file)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content.find("post_shutdown_message"), std::string::npos);
}

TEST_F(AsyncLoggerTest, MultiThread_EnqueueStress)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 1024;
    config.batch_size = 32;
    config.overflow_policy = OverflowPolicy::DropNewest;

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    AsyncLogger logger(config, file_stream, log_mutex);

    constexpr int num_threads = 4;
    constexpr int msgs_per_thread = 500;
    std::atomic<int> total_enqueued{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < msgs_per_thread; ++i)
                {
                    if (logger.enqueue(LogLevel::Info, "thread_" + std::to_string(t) + "_msg_" + std::to_string(i)))
                    {
                        total_enqueued.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
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
    EXPECT_EQ(total_enqueued.load() + static_cast<int>(logger.dropped_count()), num_threads * msgs_per_thread);

    logger.shutdown();
}

TEST(StringPoolTest, AllocateDeallocate_BasicCycle)
{
    auto &pool = StringPool::instance();

    std::string *s = pool.allocate(32);
    ASSERT_NE(s, nullptr);

    s->assign("hello pool");
    EXPECT_EQ(*s, "hello pool");

    pool.deallocate(s);
}

TEST(StringPoolTest, AllocateDeallocate_MultipleSlots)
{
    auto &pool = StringPool::instance();

    constexpr size_t kCount = 32;
    std::vector<std::string *> ptrs;
    ptrs.reserve(kCount);

    for (size_t i = 0; i < kCount; ++i)
    {
        std::string *s = pool.allocate(64);
        ASSERT_NE(s, nullptr);
        s->assign("slot_" + std::to_string(i));
        ptrs.push_back(s);
    }

    for (size_t i = 0; i < kCount; ++i)
    {
        EXPECT_EQ(*ptrs[i], "slot_" + std::to_string(i));
    }

    for (auto *p : ptrs)
    {
        pool.deallocate(p);
    }
}

TEST(StringPoolTest, HeapFallback_OversizedAllocation)
{
    auto &pool = StringPool::instance();

    std::string *s = pool.allocate(MAX_POOLED_STRING_SIZE + 1);
    ASSERT_NE(s, nullptr);

    s->assign("heap fallback string");
    EXPECT_EQ(*s, "heap fallback string");

    pool.deallocate(s);
}

TEST(StringPoolTest, ConcurrentAllocateDeallocate)
{
    auto &pool = StringPool::instance();

    constexpr int kThreads = 4;
    constexpr int kOpsPerThread = 100;
    std::atomic<int> success_count{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < kOpsPerThread; ++i)
                {
                    std::string *s = pool.allocate(32);
                    if (s)
                    {
                        s->assign("t" + std::to_string(t) + "_" + std::to_string(i));
                        success_count.fetch_add(1, std::memory_order_relaxed);
                        pool.deallocate(s);
                    }
                }
            });
    }

    for (auto &th : threads)
    {
        th.join();
    }

    EXPECT_EQ(success_count.load(), kThreads * kOpsPerThread);
}

TEST(StringPoolTest, ReuseAfterDeallocate)
{
    auto &pool = StringPool::instance();

    std::string *s1 = pool.allocate(16);
    ASSERT_NE(s1, nullptr);
    s1->assign("first");
    pool.deallocate(s1);

    std::string *s2 = pool.allocate(16);
    ASSERT_NE(s2, nullptr);
    s2->assign("second");
    EXPECT_EQ(*s2, "second");
    pool.deallocate(s2);
}

TEST(StringPoolTest, GrowsAcrossMultipleAlignedBlocks)
{
    // Keep more slots live than a single block holds, forcing grow_pool_locked() to allocate several additional
    // over-aligned blocks through the aligned operator new. Every allocation must succeed and stay independently
    // usable; a misaligned block would fault or trip the sanitizer probe rather than read back its stored value.
    auto &pool = StringPool::instance();

    constexpr size_t kLiveSlots = POOL_SLOTS_PER_BLOCK * 4 + 1;
    std::vector<std::string *> ptrs;
    ptrs.reserve(kLiveSlots);

    for (size_t i = 0; i < kLiveSlots; ++i)
    {
        std::string *s = pool.allocate(64);
        ASSERT_NE(s, nullptr);
        s->assign("blk_" + std::to_string(i));
        ptrs.push_back(s);
    }

    for (size_t i = 0; i < kLiveSlots; ++i)
    {
        EXPECT_EQ(*ptrs[i], "blk_" + std::to_string(i));
    }

    for (auto *p : ptrs)
    {
        pool.deallocate(p);
    }
}

TEST(StringPoolTest, AllocationChainIsNoThrow)
{
    // The logging hot path crosses noexcept boundaries (AsyncLogger::enqueue is noexcept), so every link of the
    // StringPool allocation chain must be
    // no-throw: an out-of-memory condition has to drop the message, never let
    // an exception escape and terminate the host.
    auto &pool = StringPool::instance();
    EXPECT_TRUE(noexcept(StringPool::instance()));
    EXPECT_TRUE(noexcept(pool.allocate(0)));
    EXPECT_TRUE(noexcept(pool.deallocate(nullptr)));
}

TEST(LogMessageTest, OverflowConstructionIsNoThrow)
{
    // The overflow ctor reaches into the StringPool; it must be no-throw so it is safe to build inside the noexcept
    // AsyncLogger::enqueue().
    static_assert(std::is_nothrow_constructible_v<LogMessage, LogLevel, std::string_view>,
                  "LogMessage(LogLevel, string_view) must be noexcept for the noexcept enqueue path");

    std::string big(LogMessage::MAX_INLINE_SIZE + 4096, 'Q');
    LogMessage msg(LogLevel::Warning, big);
    EXPECT_TRUE(msg.is_valid());
    EXPECT_EQ(msg.message().size(), big.size());
    EXPECT_NE(msg.overflow, nullptr);
}

TEST(LogMessageTest, Reset_ClearsOverflow)
{
    std::string long_msg(LogMessage::MAX_INLINE_SIZE + 100, 'Z');
    LogMessage msg(LogLevel::Info, long_msg);
    EXPECT_NE(msg.overflow, nullptr);
    EXPECT_TRUE(msg.is_valid());

    msg.reset();

    EXPECT_EQ(msg.overflow, nullptr);
    EXPECT_EQ(msg.length, 0u);
    EXPECT_EQ(msg.message().size(), 0u);
}

TEST(LogMessageTest, Reset_InlineMessage)
{
    LogMessage msg(LogLevel::Info, "short message");
    EXPECT_EQ(msg.overflow, nullptr);
    EXPECT_TRUE(msg.is_valid());

    msg.reset();

    EXPECT_EQ(msg.length, 0u);
    EXPECT_EQ(msg.message().size(), 0u);
}

TEST(LogMessageTest, MoveOverflowMessage_ClearsSource)
{
    std::string long_msg(LogMessage::MAX_INLINE_SIZE + 50, 'Q');
    LogMessage src(LogLevel::Error, long_msg);
    ASSERT_NE(src.overflow, nullptr);

    LogMessage dst(std::move(src));

    EXPECT_NE(dst.overflow, nullptr);
    EXPECT_EQ(dst.message().size(), LogMessage::MAX_INLINE_SIZE + 50);
    EXPECT_EQ(src.overflow, nullptr);
}

TEST(LogMessageTest, MoveConstructor_PartialBufferCopy)
{
    const std::string short_msg = "hello";
    LogMessage src(LogLevel::Info, short_msg);
    ASSERT_EQ(src.overflow, nullptr);
    ASSERT_EQ(src.length, short_msg.size());

    LogMessage dst(std::move(src));

    EXPECT_EQ(dst.length, short_msg.size());
    EXPECT_EQ(dst.overflow, nullptr);
    EXPECT_EQ(dst.message(), short_msg);
    EXPECT_EQ(dst.level, LogLevel::Info);
    EXPECT_TRUE(dst.is_valid());
}

TEST(LogMessageTest, MoveAssignment_PartialBufferCopy)
{
    const std::string msg = "partial copy test";
    LogMessage src(LogLevel::Warning, msg);
    ASSERT_EQ(src.overflow, nullptr);

    LogMessage dst;
    dst = std::move(src);

    EXPECT_EQ(dst.length, msg.size());
    EXPECT_EQ(dst.overflow, nullptr);
    EXPECT_EQ(dst.message(), msg);
    EXPECT_EQ(dst.level, LogLevel::Warning);
    EXPECT_TRUE(dst.is_valid());
}

TEST(LogMessageTest, MoveConstructor_EmptyMessage)
{
    LogMessage src(LogLevel::Debug, "");
    ASSERT_EQ(src.length, 0u);

    LogMessage dst(std::move(src));

    EXPECT_EQ(dst.length, 0u);
    EXPECT_EQ(dst.overflow, nullptr);
    EXPECT_EQ(dst.message(), "");
    EXPECT_TRUE(dst.is_valid());
}

TEST(LogMessageTest, MoveAssignment_OverflowToInline)
{
    std::string long_msg(LogMessage::MAX_INLINE_SIZE + 100, 'Z');
    LogMessage dst(LogLevel::Info, long_msg);
    ASSERT_NE(dst.overflow, nullptr);

    const std::string short_msg = "short";
    LogMessage src(LogLevel::Debug, short_msg);
    ASSERT_EQ(src.overflow, nullptr);

    dst = std::move(src);

    EXPECT_EQ(dst.overflow, nullptr);
    EXPECT_EQ(dst.length, short_msg.size());
    EXPECT_EQ(dst.message(), short_msg);
}

TEST_F(AsyncLoggerTest, FlushWithTimeout_ReturnsTrue_WhenDrained)
{
    AsyncLoggerConfig config;
    config.batch_size = 64;
    config.flush_interval = std::chrono::milliseconds{10};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_TRUE(logger->enqueue(LogLevel::Info, "flush_test_" + std::to_string(i)));
    }

    EXPECT_TRUE(logger->flush_with_timeout(std::chrono::milliseconds{500}));
    EXPECT_EQ(logger->queue_size(), 0u);

    logger->shutdown();
}

TEST_F(AsyncLoggerTest, LogFormat_MatchesSyncFormat)
{
    AsyncLoggerConfig config;
    config.batch_size = 64;
    config.flush_interval = std::chrono::milliseconds{10};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    (void)logger->enqueue(LogLevel::Info, "FORMAT_CHECK_INFO_7f3a");
    (void)logger->enqueue(LogLevel::Debug, "FORMAT_CHECK_DEBUG_8b2c");
    (void)logger->enqueue(LogLevel::Warning, "FORMAT_CHECK_WARN_9d4e");
    logger->shutdown();
    file_stream->close();

    std::ifstream in(m_test_log_file);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    // Expected format: [YYYY-MM-DD HH:MM:SS.mmm] [LEVEL  ] :: message
    // Level field is 7 chars wide, left-aligned, space-padded
    const std::regex line_pattern(R"(\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\] \[\w{1,7}\s*\] :: .+)");

    std::istringstream stream(content);
    std::string line;
    int matched = 0;
    while (std::getline(stream, line))
    {
        if (line.empty())
        {
            continue;
        }
        EXPECT_TRUE(std::regex_search(line, line_pattern)) << "Async log line does not match expected format: " << line;
        ++matched;
    }
    EXPECT_EQ(matched, 3);

    // Verify level fields use space-padding, not zero-padding
    EXPECT_NE(content.find("[INFO   ]"), std::string::npos);
    EXPECT_NE(content.find("[DEBUG  ]"), std::string::npos);
    EXPECT_NE(content.find("[WARNING]"), std::string::npos);
    EXPECT_EQ(content.find("[INFO000]"), std::string::npos);
    EXPECT_EQ(content.find("[DEBUG00]"), std::string::npos);
}

// LogMessage move semantics

TEST(LogMessageMoveTest, MoveConstructorZerosSourceLength)
{
    LogMessage src(LogLevel::Info, "hello");
    ASSERT_EQ(src.length, 5);
    ASSERT_TRUE(src.is_valid());

    LogMessage dst(std::move(src));

    EXPECT_EQ(dst.length, 5);
    EXPECT_EQ(dst.message(), "hello");
    EXPECT_EQ(src.length, 0);
    EXPECT_EQ(src.overflow, nullptr);
}

TEST(LogMessageMoveTest, MoveAssignmentZerosSourceLength)
{
    LogMessage src(LogLevel::Info, "world");
    LogMessage dst;

    dst = std::move(src);

    EXPECT_EQ(dst.length, 5);
    EXPECT_EQ(dst.message(), "world");
    EXPECT_EQ(src.length, 0);
    EXPECT_EQ(src.overflow, nullptr);
}

TEST(LogMessageMoveTest, MovedFromMessageReturnsEmpty)
{
    LogMessage src(LogLevel::Debug, "test message");
    LogMessage dst(std::move(src));

    EXPECT_TRUE(src.message().empty());
}

// Writer wakeup latency

TEST_F(AsyncLoggerTest, EnqueueWakesParkedWriterPromptly)
{
    // With a long flush interval the writer drains the empty queue and parks on m_flush_cv. A single
    // enqueue must wake it well before the interval elapses; if the wakeup were dropped, draining would
    // stall until the 2 s timeout and flush_with_timeout(500 ms) below would fail.
    AsyncLoggerConfig config;
    config.batch_size = 8;
    config.queue_capacity = 64;
    config.flush_interval = std::chrono::milliseconds{2000};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();
    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    // Wait deterministically until the writer has drained the empty queue and parked, instead of
    // relying on a fixed sleep, so the measurement below genuinely exercises the parked-writer wakeup.
    // The bounded deadline keeps a stuck writer from hanging the test.
    const auto park_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (!logger->is_writer_waiting() && std::chrono::steady_clock::now() < park_deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    ASSERT_TRUE(logger->is_writer_waiting());

    const auto start_time = std::chrono::steady_clock::now();
    ASSERT_TRUE(logger->enqueue(LogLevel::Info, "wake_parked_writer"));
    ASSERT_TRUE(logger->flush_with_timeout(std::chrono::milliseconds{500}));
    const auto elapsed = std::chrono::steady_clock::now() - start_time;

    EXPECT_LT(elapsed, config.flush_interval) << "parked writer was not woken before the flush interval elapsed";

    logger->shutdown();
}

TEST_F(AsyncLoggerTest, ParkedWriterNeverStallsToFlushInterval)
{
    // Regression for the producer->writer lost wakeup. With batch_size 1 and a long flush interval the
    // writer drains a single message and re-parks after almost every enqueue, so each iteration
    // exercises the window where a push can race the writer's pre-park predicate check. Before the
    // pending-count/writer-waiting handshake, a push landing in that window slept until the flush-interval
    // timeout and the per-iteration flush would time out. With the handshake every push is either seen
    // by the writer's predicate or wakes the parked writer, so each message drains far below the
    // interval.
    AsyncLoggerConfig config;
    config.batch_size = 1;
    config.queue_capacity = 1024;
    config.flush_interval = std::chrono::milliseconds{2000};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();
    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    constexpr int ITERATIONS = 128;
    // Well below flush_interval, with wide margin on both sides: a lost wakeup waits the full interval
    // (2000 ms), so a 1000 ms budget still catches it, while the headroom above the sub-millisecond normal
    // drain absorbs a one-off synchronous-flush or scheduler stall on a loaded runner (batch_size 1 flushes
    // the file per message).
    const auto flush_budget = std::chrono::milliseconds{1000};
    auto worst = std::chrono::steady_clock::duration::zero();

    for (int i = 0; i < ITERATIONS; ++i)
    {
        const auto start_time = std::chrono::steady_clock::now();
        ASSERT_TRUE(logger->enqueue(LogLevel::Info, "wake_probe"));
        ASSERT_TRUE(logger->flush_with_timeout(flush_budget))
            << "writer did not drain within " << flush_budget.count() << " ms on iteration " << i
            << " -- a wakeup was lost to the flush-interval timeout";
        worst = std::max(worst, std::chrono::steady_clock::now() - start_time);
    }

    EXPECT_LT(worst, config.flush_interval)
        << "worst-case drain latency reached the flush interval, indicating a lost wakeup";

    logger->shutdown();
}

// The AsyncLogger destructor must be self-safe under the loader lock. shutdown() detaches the writer there (which keeps
// reading the queue / wake event / flush channel / file stream until it observes the stop), so ~AsyncLogger must leak
// the Impl in place rather than destroy those members out from under the detached writer. The real loader lock cannot
// be entered from user code, so async_logger.cpp exposes a test-only override.
namespace DetourModKit::detail
{
    extern bool (*g_async_logger_loader_lock_override)() noexcept;
    extern std::atomic<std::atomic<bool> *> g_async_logger_writer_gate;
    extern std::atomic<std::atomic<bool> *> g_async_logger_producer_gate;
    extern std::atomic<bool> g_async_logger_producer_waiting;
    extern std::atomic<bool> g_async_logger_flush_waiting;
    extern std::atomic<std::atomic<bool> *> g_async_logger_prepush_gate;
    extern std::atomic<bool> g_async_logger_prepush_waiting;
    extern std::atomic<std::atomic<std::size_t> *> g_async_logger_idle_park_counter;
    extern std::atomic<std::atomic<bool> *> g_async_logger_flush_mutex_gate;
} // namespace DetourModKit::detail

namespace
{
    bool al_always_true_loader_lock() noexcept
    {
        return true;
    }

    class AsyncLoggerSeamReset
    {
    public:
        AsyncLoggerSeamReset(std::atomic<bool> *writer_gate, std::atomic<bool> *producer_gate) noexcept
            : m_writer_gate(writer_gate), m_producer_gate(producer_gate)
        {
        }

        ~AsyncLoggerSeamReset() noexcept
        {
            m_producer_gate->store(false, std::memory_order_release);
            m_writer_gate->store(false, std::memory_order_release);
            DetourModKit::detail::g_async_logger_producer_gate.store(nullptr, std::memory_order_release);
            DetourModKit::detail::g_async_logger_writer_gate.store(nullptr, std::memory_order_release);
            DetourModKit::detail::g_async_logger_producer_waiting.store(false, std::memory_order_release);
            DetourModKit::detail::g_async_logger_flush_waiting.store(false, std::memory_order_release);
            DetourModKit::detail::g_async_logger_prepush_gate.store(nullptr, std::memory_order_release);
            DetourModKit::detail::g_async_logger_prepush_waiting.store(false, std::memory_order_release);
            DetourModKit::detail::g_async_logger_idle_park_counter.store(nullptr, std::memory_order_release);
            DetourModKit::detail::g_async_logger_flush_mutex_gate.store(nullptr, std::memory_order_release);
            DetourModKit::detail::g_async_logger_loader_lock_override = nullptr;
        }

        AsyncLoggerSeamReset(const AsyncLoggerSeamReset &) = delete;
        AsyncLoggerSeamReset &operator=(const AsyncLoggerSeamReset &) = delete;
        AsyncLoggerSeamReset(AsyncLoggerSeamReset &&) = delete;
        AsyncLoggerSeamReset &operator=(AsyncLoggerSeamReset &&) = delete;

    private:
        std::atomic<bool> *m_writer_gate;
        std::atomic<bool> *m_producer_gate;
    };
} // namespace

TEST_F(AsyncLoggerTest, DestructorUnderLoaderLockLeaksImplAndDoesNotHang)
{
    namespace diag = DetourModKit::diagnostics;
    diag::reset_intentional_leaks();

    AsyncLoggerConfig config;
    config.batch_size = 10;
    config.flush_interval = std::chrono::milliseconds{50};

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    const auto t_start = std::chrono::steady_clock::now();
    {
        auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
        ASSERT_TRUE(logger->is_running());
        // Force the loader-lock branch: shutdown() detaches the writer and ~AsyncLogger leaks the Impl in place.
        DetourModKit::detail::g_async_logger_loader_lock_override = &al_always_true_loader_lock;
    }
    const auto elapsed = std::chrono::steady_clock::now() - t_start;
    DetourModKit::detail::g_async_logger_loader_lock_override = nullptr;

    EXPECT_LT(elapsed, std::chrono::seconds(2)) << "loader-lock detach branch must not join the writer";
    EXPECT_GE(diag::intentional_leak_count(diag::LeakSubsystem::AsyncLogger), 1u)
        << "the loader-lock detach must record an AsyncLogger intentional-leak event";

    // Discriminating check for the ~AsyncLogger behaviour specifically. The leak counter above only proves shutdown()'s
    // detach, which a defaulted destructor would also reach; it does NOT prove the destructor leaked the Impl instead
    // of destroying it. Leaking the Impl in place keeps its shared_ptr to the file stream alive, so use_count stays at
    // 2 (this local + the leaked Impl). Letting ~Impl run would drop the Impl's reference to 1 here, and the detached
    // writer would be reading a freed WinFileStream. This is deterministic (no sanitizer needed): use_count reflects
    // strong ownership, not the writer's raw access.
    EXPECT_GE(file_stream.use_count(), 2L)
        << "~AsyncLogger destroyed the Impl instead of leaking it; the detached writer's file stream was freed";
    // The Impl (queue, cv, file stream) is intentionally leaked; the detached writer observes the stop and exits on
    // its own. FILE_SHARE_DELETE lets TearDown still remove the log file even with the leaked handle open.
}

TEST_F(AsyncLoggerTest, LoaderLockAbandonLeavesDrainAndSinkToTheRetainedWriter)
{
    namespace diag = DetourModKit::diagnostics;
    diag::reset_intentional_leaks();

    AsyncLoggerConfig config;
    config.queue_capacity = 64;
    config.batch_size = 8;
    config.flush_interval = std::chrono::milliseconds{20};
    config.overflow_policy = OverflowPolicy::DropNewest;

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    static std::atomic<bool> writer_gate{true};
    static std::atomic<bool> producer_gate{true};
    writer_gate.store(true, std::memory_order_release);
    producer_gate.store(true, std::memory_order_release);
    DetourModKit::detail::g_async_logger_producer_waiting.store(false, std::memory_order_release);
    DetourModKit::detail::g_async_logger_flush_waiting.store(false, std::memory_order_release);
    DetourModKit::detail::g_async_logger_writer_gate.store(&writer_gate, std::memory_order_release);
    DetourModKit::detail::g_async_logger_loader_lock_override = &al_always_true_loader_lock;

    std::jthread producer;
    std::jthread flusher;
    AsyncLoggerSeamReset seam_reset{&writer_gate, &producer_gate};
    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);

    constexpr int MESSAGE_COUNT = 12;
    // Trailing '|' terminates each index so a later readback matches it exactly: without it "ABANDON_DRAIN_1" is a
    // prefix of "ABANDON_DRAIN_10"/"_11", and a lost message 1 would still be found inside message 10's line.
    for (int i = 0; i < MESSAGE_COUNT; ++i)
    {
        ASSERT_TRUE(logger->enqueue(LogLevel::Info, "ABANDON_DRAIN_" + std::to_string(i) + "|"));
    }
    ASSERT_EQ(logger->queue_size(), static_cast<size_t>(MESSAGE_COUNT));

    DetourModKit::detail::g_async_logger_producer_gate.store(&producer_gate, std::memory_order_release);
    std::atomic<bool> producer_result{false};
    producer = std::jthread(
        [&logger, &producer_result]() noexcept -> void
        { producer_result.store(logger->enqueue(LogLevel::Info, "ABANDON_CONCURRENT"), std::memory_order_release); });

    const auto producer_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!DetourModKit::detail::g_async_logger_producer_waiting.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < producer_deadline)
    {
        std::this_thread::yield();
    }
    ASSERT_TRUE(DetourModKit::detail::g_async_logger_producer_waiting.load(std::memory_order_acquire));

    std::atomic<bool> flush_result{false};
    std::atomic<bool> flush_finished{false};
    flusher = std::jthread(
        [&logger, &flush_result, &flush_finished]() noexcept -> void
        {
            flush_result.store(logger->flush_with_timeout(std::chrono::seconds{5}), std::memory_order_release);
            flush_finished.store(true, std::memory_order_release);
        });

    const auto flush_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!DetourModKit::detail::g_async_logger_flush_waiting.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < flush_deadline)
    {
        std::this_thread::yield();
    }
    ASSERT_TRUE(DetourModKit::detail::g_async_logger_flush_waiting.load(std::memory_order_acquire));

    const auto start_time = std::chrono::steady_clock::now();
    logger->shutdown();
    const auto shutdown_elapsed = std::chrono::steady_clock::now() - start_time;

    EXPECT_LT(shutdown_elapsed, std::chrono::seconds(2)) << "loader-lock abandon must not join the writer";
    EXPECT_TRUE(logger->writer_was_detached());
    EXPECT_EQ(logger->queue_size(), static_cast<size_t>(MESSAGE_COUNT))
        << "shutdown drained the queue; the retained writer must be the only consumer";
    EXPECT_EQ(logger->dropped_count(), 0u) << "shutdown dropped queued messages instead of leaving them to the writer";
    EXPECT_GE(diag::intentional_leak_count(diag::LeakSubsystem::AsyncLogger), 1u);

    EXPECT_FALSE(flush_finished.load(std::memory_order_acquire));

    // Draining the published queue is insufficient while an admitted producer is still paused before publication.
    writer_gate.store(false, std::memory_order_release);
    EXPECT_FALSE(flush_finished.load(std::memory_order_acquire));

    producer_gate.store(false, std::memory_order_release);
    producer.join();
    EXPECT_TRUE(producer_result.load(std::memory_order_acquire));
    flusher.join();
    EXPECT_TRUE(flush_result.load(std::memory_order_acquire))
        << "the retained writer did not drain, or the pending counter underflowed";
    EXPECT_EQ(logger->queue_size(), 0u);

    std::ifstream read_file(m_test_log_file.string());
    std::string content((std::istreambuf_iterator<char>(read_file)), std::istreambuf_iterator<char>());
    for (int i = 0; i < MESSAGE_COUNT; ++i)
    {
        EXPECT_NE(content.find("ABANDON_DRAIN_" + std::to_string(i) + "|"), std::string::npos)
            << "message " << i << " lost";
    }
    EXPECT_NE(content.find("ABANDON_CONCURRENT"), std::string::npos);
}

// A message longer than the inline buffer takes the StringPool overflow path. When that allocation fails under OOM the
// constructed LogMessage is an invalid, zero-length husk; enqueue must drop and count it, never publish an empty
// timestamped line.
TEST_F(AsyncLoggerTest, LongMessageOverflowAllocationFailureDropsAndCounts)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    AsyncLoggerConfig config;
    config.queue_capacity = 64;
    config.batch_size = 8;
    config.flush_interval = std::chrono::milliseconds{20};
    config.overflow_policy = OverflowPolicy::DropNewest;

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();
    AsyncLogger logger(config, file_stream, log_mutex);

    // Larger than MAX_POOLED_STRING_SIZE so allocate() takes the nothrow heap-string path, which the alloc probe
    // fails to a null return; the marker is distinctive so no stray line can masquerade as delivery.
    const std::string long_message(5000, 'Z');
    const std::size_t before = logger.dropped_count();

    bool accepted = true;
    {
        // allow == 0 fails the very first allocation on this thread: the overflow string object.
        dmk_test::AllocFailScope guard(0);
        accepted = logger.enqueue(LogLevel::Info, long_message);
    }

    EXPECT_FALSE(accepted) << "an over-long message whose overflow allocation failed must be dropped";
    EXPECT_EQ(logger.dropped_count(), before + 1);
    EXPECT_EQ(logger.queue_size(), 0u) << "the invalid husk must not be enqueued";

    logger.shutdown();
    file_stream->close();

    std::ifstream read_file(m_test_log_file.string());
    std::string content((std::istreambuf_iterator<char>(read_file)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content.find("ZZZ"), std::string::npos) << "the dropped husk must contribute no line";
}

// A SyncFallback overflow that reaches a closed/unhealthy sink loses the message; the failure must be counted, not
// swallowed silently.
TEST_F(AsyncLoggerTest, SyncFallbackFailureOnClosedSinkDropsAndCounts)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 2;
    config.batch_size = 1;
    config.flush_interval = std::chrono::milliseconds{1000};
    config.overflow_policy = OverflowPolicy::SyncFallback;

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    static std::atomic<bool> writer_gate{true};
    static std::atomic<bool> dummy_gate{false};
    writer_gate.store(true, std::memory_order_release);
    DetourModKit::detail::g_async_logger_writer_gate.store(&writer_gate, std::memory_order_release);
    AsyncLoggerSeamReset seam_reset{&writer_gate, &dummy_gate};

    AsyncLogger logger(config, file_stream, log_mutex);

    // Writer paused: fill the queue to capacity so the next enqueue overflows into the SyncFallback path.
    EXPECT_TRUE(logger.enqueue(LogLevel::Info, "q0"));
    EXPECT_TRUE(logger.enqueue(LogLevel::Info, "q1"));

    // Close the sink so the synchronous fallback write cannot land.
    file_stream->close();

    const std::size_t before = logger.dropped_count();
    EXPECT_FALSE(logger.enqueue(LogLevel::Warning, "sync_fallback_overflow"));
    EXPECT_EQ(logger.dropped_count(), before + 1) << "a failed SyncFallback write must be counted";

    writer_gate.store(false, std::memory_order_release);
    logger.shutdown();
}

// A callback-safe Drop-policy producer must never acquire the control-plane flush mutex on its wake path. Hold that
// mutex from a flusher while the writer is parked, then prove a Drop-policy producer still completes its enqueue.
TEST_F(AsyncLoggerTest, DropProducerNeverWaitsOnFlushMutex)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 64;
    config.batch_size = 8;
    config.flush_interval = std::chrono::milliseconds{50};
    config.overflow_policy = OverflowPolicy::DropNewest;

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    static std::atomic<bool> hold_gate{true};
    static std::atomic<bool> dummy_gate{false};
    hold_gate.store(true, std::memory_order_release);
    DetourModKit::detail::g_async_logger_flush_waiting.store(false, std::memory_order_release);
    DetourModKit::detail::g_async_logger_flush_mutex_gate.store(&hold_gate, std::memory_order_release);
    AsyncLoggerSeamReset seam_reset{&hold_gate, &dummy_gate};

    AsyncLogger logger(config, file_stream, log_mutex);

    // Wait for the writer to park so notify_writer exercises its wake path.
    const auto park_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!logger.is_writer_waiting() && std::chrono::steady_clock::now() < park_deadline)
    {
        std::this_thread::yield();
    }
    ASSERT_TRUE(logger.is_writer_waiting());

    // Flusher acquires and holds m_flush_mutex until hold_gate clears.
    std::thread flusher([&logger]() noexcept { (void)logger.flush_with_timeout(std::chrono::seconds{5}); });

    const auto held_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!DetourModKit::detail::g_async_logger_flush_waiting.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < held_deadline)
    {
        std::this_thread::yield();
    }
    EXPECT_TRUE(DetourModKit::detail::g_async_logger_flush_waiting.load(std::memory_order_acquire))
        << "flusher never acquired the control-plane mutex";

    // With m_flush_mutex held AND the writer parked, a Drop-policy producer must still complete: its wake is a
    // mutex-free SetEvent. Run on a thread so a regression (blocking on the mutex) is a failed completion flag rather
    // than a hung test.
    std::atomic<bool> produced{false};
    std::thread producer(
        [&logger, &produced]() noexcept
        {
            (void)logger.enqueue(LogLevel::Info, "no_control_plane_mutex");
            produced.store(true, std::memory_order_release);
        });

    const auto produce_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (!produced.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < produce_deadline)
    {
        std::this_thread::yield();
    }
    EXPECT_TRUE(produced.load(std::memory_order_acquire))
        << "a Drop-policy producer blocked on the held control-plane flush mutex";

    hold_gate.store(false, std::memory_order_release);
    producer.join();
    flusher.join();
    logger.shutdown();
}

// A producer preempted after counting its message but before publishing the slot must not make the writer busy-spin.
// The writer sees pending != 0 with an empty queue; it must park (bounded) rather than hot-loop.
TEST_F(AsyncLoggerTest, PreemptedProducerBeforePublishDoesNotBusySpinTheWriter)
{
    AsyncLoggerConfig config;
    config.queue_capacity = 64;
    config.batch_size = 8;
    config.flush_interval = std::chrono::milliseconds{50};
    config.overflow_policy = OverflowPolicy::DropNewest;

    auto file_stream = std::make_shared<WinFileStream>(m_test_log_file.string());
    auto log_mutex = std::make_shared<std::mutex>();

    static std::atomic<bool> prepush_gate{true};
    static std::atomic<bool> dummy_gate{false};
    static std::atomic<std::size_t> park_count{0};
    prepush_gate.store(true, std::memory_order_release);
    park_count.store(0, std::memory_order_release);
    DetourModKit::detail::g_async_logger_prepush_waiting.store(false, std::memory_order_release);
    DetourModKit::detail::g_async_logger_prepush_gate.store(&prepush_gate, std::memory_order_release);
    DetourModKit::detail::g_async_logger_idle_park_counter.store(&park_count, std::memory_order_release);
    AsyncLoggerSeamReset seam_reset{&prepush_gate, &dummy_gate};

    AsyncLogger logger(config, file_stream, log_mutex);

    std::thread producer([&logger]() noexcept { (void)logger.enqueue(LogLevel::Info, "in_flight_marker"); });

    const auto wait_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!DetourModKit::detail::g_async_logger_prepush_waiting.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < wait_deadline)
    {
        std::this_thread::yield();
    }
    EXPECT_TRUE(DetourModKit::detail::g_async_logger_prepush_waiting.load(std::memory_order_acquire));

    // The writer now sees pending != 0 with an empty queue. Count its idle-park entries over a fixed window: a parked
    // writer enters a handful of times (one per bounded recheck); a hot-spinning writer enters thousands of times.
    park_count.store(0, std::memory_order_release);
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    const std::size_t parks = park_count.load(std::memory_order_acquire);
    EXPECT_LT(parks, 2000u) << "writer busy-spun in the in-flight window instead of parking (" << parks << " entries)";

    prepush_gate.store(false, std::memory_order_release);
    producer.join();

    EXPECT_TRUE(logger.flush_with_timeout(std::chrono::seconds{5}));
    logger.shutdown();
    file_stream->close();

    std::ifstream read_file(m_test_log_file.string());
    std::string content((std::istreambuf_iterator<char>(read_file)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("in_flight_marker"), std::string::npos) << "the delayed message must still land";
}
