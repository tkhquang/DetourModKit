/**
 * @file async_logger.cpp
 * @brief Implementation of the asynchronous logging system.
 */

#include "DetourModKit/async_logger.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace DetourModKit;

// Use the shared logLevelToString from logger.hpp - no duplication needed

// ============================================================================
// LogMessage Implementation
// ============================================================================

LogMessage::LogMessage(LogLevel lvl, std::string msg)
    : level(lvl),
      timestamp(std::chrono::system_clock::now()),
      thread_id(std::this_thread::get_id())
{
    if (msg.size() <= MAX_INLINE_SIZE)
    {
        // Message fits in inline buffer - no heap allocation
        std::memcpy(buffer.data(), msg.data(), msg.size());
        length = msg.size();
    }
    else
    {
        // Message too large - use heap allocation
        overflow = std::make_unique<std::string>(std::move(msg));
        length = overflow->size();
    }
}

LogMessage::LogMessage(LogMessage &&other) noexcept
    : level(other.level),
      timestamp(other.timestamp),
      thread_id(other.thread_id),
      buffer(other.buffer),
      length(other.length),
      overflow(std::move(other.overflow))
{
    other.length = 0;
}

LogMessage &LogMessage::operator=(LogMessage &&other) noexcept
{
    if (this != &other)
    {
        level = other.level;
        timestamp = other.timestamp;
        thread_id = other.thread_id;
        buffer = other.buffer;
        length = other.length;
        overflow = std::move(other.overflow);
        other.length = 0;
    }
    return *this;
}

std::string_view LogMessage::message() const
{
    if (overflow)
    {
        return *overflow;
    }
    return std::string_view(buffer.data(), length);
}

// ============================================================================
// DynamicMPMCQueue Implementation
// ============================================================================

DynamicMPMCQueue::DynamicMPMCQueue(size_t capacity)
    : capacity_(capacity), mask_(capacity - 1)
{
    // Capacity must be a power of 2
    if ((capacity & (capacity - 1)) != 0 || capacity < 2)
    {
        throw std::invalid_argument("DynamicMPMCQueue capacity must be a power of 2 and at least 2");
    }

    buffer_.resize(capacity);

    // Initialize sequence numbers
    for (size_t i = 0; i < capacity; ++i)
    {
        buffer_[i].sequence.store(i, std::memory_order_relaxed);
    }
}

bool DynamicMPMCQueue::try_push(LogMessage item)
{
    size_t pos = enqueue_pos_.load(std::memory_order_relaxed);

    for (;;)
    {
        Slot &slot = buffer_[pos & mask_];
        size_t seq = slot.sequence.load(std::memory_order_acquire);
        intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);

        if (diff == 0)
        {
            // Slot is ready for writing
            if (enqueue_pos_.compare_exchange_weak(pos, pos + 1,
                                                   std::memory_order_relaxed))
            {
                slot.data = std::move(item);
                slot.sequence.store(pos + 1, std::memory_order_release);
                return true;
            }
        }
        else if (diff < 0)
        {
            // Queue is full
            return false;
        }
        else
        {
            // Another thread is ahead, reload position
            pos = enqueue_pos_.load(std::memory_order_relaxed);
        }
    }
}

bool DynamicMPMCQueue::try_pop(LogMessage &item)
{
    size_t pos = dequeue_pos_.load(std::memory_order_relaxed);

    for (;;)
    {
        Slot &slot = buffer_[pos & mask_];
        size_t seq = slot.sequence.load(std::memory_order_acquire);
        intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);

        if (diff == 0)
        {
            // Slot is ready for reading
            if (dequeue_pos_.compare_exchange_weak(pos, pos + 1,
                                                   std::memory_order_relaxed))
            {
                item = std::move(slot.data);
                slot.sequence.store(pos + capacity_, std::memory_order_release);
                return true;
            }
        }
        else if (diff < 0)
        {
            // Queue is empty
            return false;
        }
        else
        {
            // Another thread is ahead, reload position
            pos = dequeue_pos_.load(std::memory_order_relaxed);
        }
    }
}

size_t DynamicMPMCQueue::size() const
{
    size_t enq = enqueue_pos_.load(std::memory_order_relaxed);
    size_t deq = dequeue_pos_.load(std::memory_order_relaxed);
    return (enq >= deq) ? (enq - deq) : 0;
}

bool DynamicMPMCQueue::empty() const
{
    return size() == 0;
}

// ============================================================================
// AsyncLogger Implementation
// ============================================================================

AsyncLogger::AsyncLogger(const AsyncLoggerConfig &config,
                         std::ofstream &file_stream,
                         std::mutex &log_mutex)
    : queue_(config.queue_capacity), // Now actually uses the config capacity!
      config_(config),
      file_stream_(file_stream),
      log_mutex_(log_mutex)
{
    running_.store(true, std::memory_order_release);
    writer_thread_ = std::jthread(&AsyncLogger::writer_thread_func, this);
}

AsyncLogger::~AsyncLogger()
{
    shutdown();
}

void AsyncLogger::enqueue(LogLevel level, std::string message)
{
    if (shutdown_requested_.load(std::memory_order_acquire))
    {
        // Logger is shutting down, write synchronously
        std::lock_guard<std::mutex> lock(log_mutex_);
        if (file_stream_.is_open() && file_stream_.good())
        {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::tm tm_buf{};

#if defined(_WIN32) || defined(_MSC_VER)
            localtime_s(&tm_buf, &time_t);
#else
            localtime_r(&time_t, &tm_buf);
#endif

            // Use shared logLevelToString from logger.hpp
            file_stream_ << "[" << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << "] "
                         << "[" << std::setw(7) << std::left << logLevelToString(level) << "] :: "
                         << message << '\n';
            file_stream_.flush();
        }
        return;
    }

    LogMessage msg(level, std::move(message));

    if (!queue_.try_push(std::move(msg)))
    {
        // Queue is full, handle based on overflow policy
        handle_overflow(std::move(msg));
    }
    else
    {
        pending_messages_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AsyncLogger::flush()
{
    if (!running_.load(std::memory_order_acquire))
    {
        return;
    }

    std::unique_lock<std::mutex> lock(flush_mutex_);

    // Wait until all pending messages are written
    flush_cv_.wait(lock, [this]()
                   { return pending_messages_.load(std::memory_order_acquire) == 0; });
}

void AsyncLogger::shutdown()
{
    bool expected = false;
    if (!shutdown_requested_.compare_exchange_strong(expected, true,
                                                     std::memory_order_acq_rel))
    {
        // Already shutting down
        return;
    }

    // Signal writer thread to stop
    running_.store(false, std::memory_order_release);

    // Wait for writer thread to finish
    if (writer_thread_.joinable())
    {
        writer_thread_.join();
    }
}

bool AsyncLogger::is_running() const
{
    return running_.load(std::memory_order_acquire);
}

size_t AsyncLogger::queue_size() const
{
    return queue_.size();
}

void AsyncLogger::writer_thread_func()
{
    std::vector<LogMessage> batch;
    batch.reserve(config_.batch_size);

    auto last_flush = std::chrono::steady_clock::now();

    while (running_.load(std::memory_order_acquire) || !queue_.empty())
    {
        // Collect batch of messages
        LogMessage msg;
        while (batch.size() < config_.batch_size && queue_.try_pop(msg))
        {
            batch.push_back(std::move(msg));
            pending_messages_.fetch_sub(1, std::memory_order_relaxed);
        }

        if (!batch.empty())
        {
            // Write batch to file
            write_batch(batch);
            batch.clear();

            // Notify flush waiters
            flush_cv_.notify_all();
            last_flush = std::chrono::steady_clock::now();
        }
        else
        {
            // No messages, check if we need to flush
            auto now = std::chrono::steady_clock::now();
            if (now - last_flush >= config_.flush_interval)
            {
                std::lock_guard<std::mutex> lock(log_mutex_);
                if (file_stream_.is_open())
                {
                    file_stream_.flush();
                }
                last_flush = now;
            }

            // Sleep briefly to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Final flush on shutdown
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        if (file_stream_.is_open())
        {
            file_stream_.flush();
        }
    }
}

void AsyncLogger::write_batch(std::span<LogMessage> messages)
{
    std::lock_guard<std::mutex> lock(log_mutex_);

    if (!file_stream_.is_open() || !file_stream_.good())
    {
        return;
    }

    for (const auto &msg : messages)
    {
        // Convert timestamp to formatted string
        auto time_t = std::chrono::system_clock::to_time_t(msg.timestamp);
        std::tm tm_buf{};

#if defined(_WIN32) || defined(_MSC_VER)
        localtime_s(&tm_buf, &time_t);
#else
        localtime_r(&time_t, &tm_buf);
#endif

        // Get milliseconds
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      msg.timestamp.time_since_epoch()) %
                  1000;

        // Write log entry - use shared logLevelToString and '\n' instead of std::endl
        file_stream_ << "[" << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
                     << "." << std::setfill('0') << std::setw(3) << ms.count() << "] "
                     << "[" << std::setw(7) << std::left << logLevelToString(msg.level) << "] :: "
                     << msg.message() << '\n';
    }

    // Flush after batch write
    file_stream_.flush();
}

bool AsyncLogger::handle_overflow(LogMessage &&message)
{
    switch (config_.overflow_policy)
    {
    case OverflowPolicy::DropNewest:
        // Discard the new message
        return false;

    case OverflowPolicy::DropOldest:
    {
        // Try to pop oldest and push new
        LogMessage oldest;
        if (queue_.try_pop(oldest))
        {
            pending_messages_.fetch_sub(1, std::memory_order_relaxed);
            if (queue_.try_push(std::move(message)))
            {
                pending_messages_.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        }
        return false;
    }

    case OverflowPolicy::Block:
    {
        // Spin until space is available
        while (!queue_.try_push(LogMessage(message.level, std::string(message.message()))))
        {
            std::this_thread::yield();
        }
        pending_messages_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    case OverflowPolicy::SyncFallback:
    {
        // Write synchronously
        std::lock_guard<std::mutex> lock(log_mutex_);
        if (file_stream_.is_open() && file_stream_.good())
        {
            auto time_t = std::chrono::system_clock::to_time_t(message.timestamp);
            std::tm tm_buf{};

#if defined(_WIN32) || defined(_MSC_VER)
            localtime_s(&tm_buf, &time_t);
#else
            localtime_r(&time_t, &tm_buf);
#endif

            // Use shared logLevelToString and '\n' instead of std::endl
            file_stream_ << "[" << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << "] "
                         << "[" << std::setw(7) << std::left << logLevelToString(message.level) << "] :: "
                         << message.message() << '\n';
            file_stream_.flush();
        }
        return true;
    }

    default:
        return false;
    }
}
