#include "DetourModKit/async_logger.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace DetourModKit
{

    // ============================================================================
    // LogMessage Implementation
    // ============================================================================

    LogMessage::LogMessage(LogLevel lvl, std::string msg)
        : level(lvl),
          timestamp(std::chrono::system_clock::now()),
          thread_id(std::this_thread::get_id())
    {
        const size_t msg_size = msg.size();

        if (msg_size > MAX_VALID_LENGTH)
        {
            msg.resize(MAX_VALID_LENGTH);
        }

        if (msg_size <= MAX_INLINE_SIZE)
        {
            std::memcpy(buffer.data(), msg.data(), msg.size());
            length = msg.size();
        }
        else
        {
            overflow = std::make_unique<std::string>(std::move(msg));
            if (overflow)
            {
                length = overflow->size();
            }
            else
            {
                length = 0;
            }
        }
    }

    std::string_view LogMessage::message() const noexcept
    {
        if (overflow)
        {
            return *overflow;
        }
        return std::string_view(buffer.data(), length);
    }

    bool LogMessage::is_valid() const noexcept
    {
        if (overflow)
        {
            return length == overflow->size();
        }
        return length <= MAX_INLINE_SIZE;
    }

    // ============================================================================
    // DynamicMPMCQueue Implementation
    // ============================================================================

    DynamicMPMCQueue::DynamicMPMCQueue(size_t capacity)
        : capacity_(capacity), mask_(capacity - 1)
    {
        if ((capacity & (capacity - 1)) != 0 || capacity < 2)
        {
            throw std::invalid_argument("DynamicMPMCQueue capacity must be a power of 2 and at least 2");
        }

        buffer_.resize(capacity);

        for (size_t i = 0; i < capacity; ++i)
        {
            buffer_[i].sequence.store(i, std::memory_order_relaxed);
        }
    }

    bool DynamicMPMCQueue::try_push(LogMessage &item)
    {
        size_t pos = enqueue_pos_.load(std::memory_order_relaxed);

        for (;;)
        {
            Slot &slot = buffer_[pos & mask_];
            size_t seq = slot.sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);

            if (diff == 0)
            {
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
                return false;
            }
            else
            {
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
                return false;
            }
            else
            {
                pos = dequeue_pos_.load(std::memory_order_relaxed);
            }
        }
    }

    size_t DynamicMPMCQueue::try_pop_batch(std::vector<LogMessage> &items, size_t max_count)
    {
        size_t count = 0;
        LogMessage msg;

        while (count < max_count && try_pop(msg))
        {
            items.push_back(std::move(msg));
            ++count;
        }

        return count;
    }

    size_t DynamicMPMCQueue::size() const noexcept
    {
        size_t enq = enqueue_pos_.load(std::memory_order_relaxed);
        size_t deq = dequeue_pos_.load(std::memory_order_relaxed);
        return (enq >= deq) ? (enq - deq) : 0;
    }

    bool DynamicMPMCQueue::empty() const noexcept
    {
        return size() == 0;
    }

    // ============================================================================
    // AsyncLogger Implementation
    // ============================================================================

    AsyncLogger::AsyncLogger(const AsyncLoggerConfig &config,
                             std::shared_ptr<std::ofstream> file_stream,
                             std::shared_ptr<std::mutex> log_mutex)
        : queue_(config.queue_capacity),
          config_(config),
          file_stream_(std::move(file_stream)),
          log_mutex_(std::move(log_mutex))
    {
        if (!config_.validate())
        {
            throw std::invalid_argument("Invalid AsyncLoggerConfig: queue_capacity must be power of 2, batch_size > 0, flush_interval > 0, spin_backoff_iterations > 0");
        }

        if (!file_stream_)
        {
            throw std::invalid_argument("file_stream cannot be null");
        }

        if (!log_mutex_)
        {
            throw std::invalid_argument("log_mutex cannot be null");
        }

        running_.store(true, std::memory_order_release);
        writer_thread_ = std::jthread(&AsyncLogger::writer_thread_func, this);
    }

    AsyncLogger::~AsyncLogger()
    {
        shutdown();
    }

    bool AsyncLogger::enqueue(LogLevel level, std::string message) noexcept
    {
        if (shutdown_requested_.load(std::memory_order_acquire))
        {
            std::lock_guard<std::mutex> lock(*log_mutex_);
            if (file_stream_->is_open() && file_stream_->good())
            {
                const auto now = std::chrono::system_clock::now();
                const auto time_t = std::chrono::system_clock::to_time_t(now);
                std::tm tm_buf{};

#if defined(_WIN32) || defined(_MSC_VER)
                localtime_s(&tm_buf, &time_t);
#else
                localtime_r(&time_t, &tm_buf);
#endif

                *file_stream_ << "[" << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << "] "
                              << "[" << std::setw(7) << std::left << log_level_to_string(level) << "] :: "
                              << message << '\n';
                file_stream_->flush();
            }
            return true;
        }

        LogMessage msg(level, std::move(message));

        if (queue_.try_push(msg))
        {
            pending_messages_.fetch_add(1, std::memory_order_relaxed);
            flush_cv_.notify_one();
            return true;
        }
        else
        {
            return handle_overflow(std::move(msg));
        }
    }

    void AsyncLogger::flush() noexcept
    {
        if (!running_.load(std::memory_order_acquire))
        {
            return;
        }

        std::unique_lock<std::mutex> lock(flush_mutex_);

        flush_cv_.wait(lock, [this]() noexcept
                       { return pending_messages_.load(std::memory_order_acquire) == 0; });
    }

    void AsyncLogger::shutdown() noexcept
    {
        bool expected = false;
        if (!shutdown_requested_.compare_exchange_strong(expected, true,
                                                         std::memory_order_acq_rel))
        {
            return;
        }

        running_.store(false, std::memory_order_release);
        flush_cv_.notify_all();

        if (writer_thread_.joinable())
        {
            writer_thread_.join();
        }
    }

    bool AsyncLogger::is_running() const noexcept
    {
        return running_.load(std::memory_order_acquire);
    }

    size_t AsyncLogger::queue_size() const noexcept
    {
        return queue_.size();
    }

    void AsyncLogger::writer_thread_func() noexcept
    {
        std::vector<LogMessage> batch;
        batch.reserve(config_.batch_size);

        const auto start_time = std::chrono::steady_clock::now();
        auto last_flush = start_time;

        while (running_.load(std::memory_order_acquire) || !queue_.empty())
        {
            batch.clear();
            queue_.try_pop_batch(batch, config_.batch_size);

            if (!batch.empty())
            {
                write_batch(batch);
                const size_t batch_size = batch.size();
                pending_messages_.fetch_sub(batch_size, std::memory_order_relaxed);
                flush_cv_.notify_all();
                last_flush = std::chrono::steady_clock::now();
            }
            else
            {
                auto now = std::chrono::steady_clock::now();
                if (now - last_flush >= config_.flush_interval)
                {
                    std::lock_guard<std::mutex> lock(*log_mutex_);
                    if (file_stream_->is_open())
                    {
                        file_stream_->flush();
                    }
                    last_flush = now;
                }

                std::unique_lock<std::mutex> lock(flush_mutex_);
                flush_cv_.wait_for(lock, config_.flush_interval, [this]()
                                   { return !queue_.empty() || !running_.load(std::memory_order_acquire); });
            }
        }

        std::lock_guard<std::mutex> lock(*log_mutex_);
        if (file_stream_->is_open())
        {
            file_stream_->flush();
        }
    }

    void AsyncLogger::write_batch(std::span<LogMessage> messages) noexcept
    {
        std::lock_guard<std::mutex> lock(*log_mutex_);

        if (!file_stream_->is_open() || !file_stream_->good())
        {
            return;
        }

        for (const auto &msg : messages)
        {
            const auto time_t = std::chrono::system_clock::to_time_t(msg.timestamp);
            std::tm tm_buf{};

#if defined(_WIN32) || defined(_MSC_VER)
            localtime_s(&tm_buf, &time_t);
#else
            localtime_r(&time_t, &tm_buf);
#endif

            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                msg.timestamp.time_since_epoch()) %
                            1000;

            *file_stream_ << "[" << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
                          << "." << std::setfill('0') << std::setw(3) << ms.count() << "] "
                          << "[" << std::setw(7) << std::left << log_level_to_string(msg.level) << "] :: "
                          << msg.message() << '\n';
        }

        file_stream_->flush();
    }

    bool AsyncLogger::handle_overflow(LogMessage &&message) noexcept
    {
        switch (config_.overflow_policy)
        {
        case OverflowPolicy::DropNewest:
            return false;

        case OverflowPolicy::DropOldest:
        {
            LogMessage oldest;
            if (queue_.try_pop(oldest))
            {
                pending_messages_.fetch_sub(1, std::memory_order_relaxed);
                if (queue_.try_push(message))
                {
                    pending_messages_.fetch_add(1, std::memory_order_relaxed);
                    flush_cv_.notify_one();
                    return true;
                }
            }
            return false;
        }

        case OverflowPolicy::Block:
        {
            constexpr size_t max_spin_iterations = 1000;
            constexpr int max_backoff_us = 1024;
            constexpr auto block_timeout = std::chrono::milliseconds(100);

            const auto deadline = std::chrono::steady_clock::now() + block_timeout;
            size_t spin_count = 0;

            while (std::chrono::steady_clock::now() < deadline)
            {
                if (queue_.try_push(message))
                {
                    pending_messages_.fetch_add(1, std::memory_order_relaxed);
                    flush_cv_.notify_one();
                    return true;
                }

                if (spin_count < config_.spin_backoff_iterations)
                {
                    ++spin_count;
                }
                else
                {
                    const int backoff_us = std::min(1 << (spin_count % 8), max_backoff_us);
                    std::this_thread::sleep_for(std::chrono::microseconds(backoff_us));
                    ++spin_count;
                    if (spin_count >= max_spin_iterations)
                    {
                        spin_count = config_.spin_backoff_iterations;
                    }
                }
            }
            return false;
        }

        case OverflowPolicy::SyncFallback:
        {
            std::lock_guard<std::mutex> lock(*log_mutex_);
            if (file_stream_->is_open() && file_stream_->good())
            {
                const auto time_t = std::chrono::system_clock::to_time_t(message.timestamp);
                std::tm tm_buf{};

#if defined(_WIN32) || defined(_MSC_VER)
                localtime_s(&tm_buf, &time_t);
#else
                localtime_r(&time_t, &tm_buf);
#endif

                *file_stream_ << "[" << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << "] "
                              << "[" << std::setw(7) << std::left << log_level_to_string(message.level) << "] :: "
                              << message.message() << '\n';
                file_stream_->flush();
            }
            return true;
        }

        default:
            return false;
        }
    }

} // namespace DetourModKit
