#include "DetourModKit/async_logger.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace DetourModKit
{
    StringPool::StringPool() noexcept
    {
        grow_pool();
    }

    StringPool::~StringPool() noexcept
    {
        Block *current = head_.load(std::memory_order_relaxed);
        while (current)
        {
            Block *next = current->next;
            ::operator delete(current);
            current = next;
        }
    }

    void StringPool::grow_pool()
    {
        std::lock_guard<std::mutex> lock(pool_mutex_);

        Block *existing = head_.load(std::memory_order_relaxed);
        size_t count = 0;
        for (Block *b = existing; b; b = b->next)
        {
            if (++count >= MEMORY_POOL_BLOCK_COUNT)
            {
                return;
            }
        }

        Block *new_block = new (::operator new(sizeof(Block))) Block();
        if (!new_block)
        {
            return;
        }

        new_block->next = existing;
        new_block->free_list = nullptr;
        new_block->slot_count = POOL_SLOTS_PER_BLOCK;

        PoolSlot *slots = reinterpret_cast<PoolSlot *>(new_block->data);
        for (size_t i = 0; i < POOL_SLOTS_PER_BLOCK; ++i)
        {
            slots[i].next_free = (i + 1 < POOL_SLOTS_PER_BLOCK) ? &slots[i + 1] : nullptr;
        }
        new_block->free_list = &slots[0];

        head_.store(new_block, std::memory_order_release);
        pool_size_.fetch_add(1, std::memory_order_relaxed);
    }

    StringPool &StringPool::instance() noexcept
    {
        static StringPool pool;
        return pool;
    }

    std::string *StringPool::allocate(size_t size)
    {
        if (size > MEMORY_POOL_BLOCK_SIZE - sizeof(PoolSlot) - 16)
        {
            return new std::string();
        }

        PoolSlot *slot = nullptr;

        {
            std::lock_guard<std::mutex> lock(pool_mutex_);
            Block *block = head_.load(std::memory_order_acquire);
            for (Block *b = block; b; b = b->next)
            {
                if (b->free_list)
                {
                    slot = b->free_list;
                    b->free_list = slot->next_free;
                    --b->slot_count;
                    break;
                }
            }
        }

        if (!slot)
        {
            grow_pool();

            std::lock_guard<std::mutex> lock(pool_mutex_);
            Block *block = head_.load(std::memory_order_acquire);
            for (Block *b = block; b; b = b->next)
            {
                if (b->free_list)
                {
                    slot = b->free_list;
                    b->free_list = slot->next_free;
                    --b->slot_count;
                    break;
                }
            }
        }

        if (slot)
        {
            new (&slot->str) std::string();
            return &slot->str;
        }

        return new std::string();
    }

    void StringPool::deallocate(std::string *ptr) noexcept
    {
        if (!ptr)
        {
            return;
        }

        Block *block = head_.load(std::memory_order_acquire);
        for (Block *b = block; b; b = b->next)
        {
            PoolSlot *slots = reinterpret_cast<PoolSlot *>(b->data);
            PoolSlot *slot = slots;

            for (size_t i = 0; i < POOL_SLOTS_PER_BLOCK; ++i, ++slot)
            {
                if (&slot->str == ptr)
                {
                    slot->str.~basic_string();
                    slot->next_free = b->free_list;
                    b->free_list = slot;
                    ++b->slot_count;
                    return;
                }
            }
        }

        delete ptr;
    }

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
            overflow = StringPool::instance().allocate(msg_size);
            if (overflow)
            {
                overflow->assign(std::move(msg));
                length = overflow->size();
            }
            else
            {
                length = 0;
            }
        }
    }

    LogMessage::~LogMessage()
    {
        reset();
    }

    LogMessage::LogMessage(LogMessage &&other) noexcept
        : level(other.level),
          timestamp(other.timestamp),
          thread_id(other.thread_id),
          buffer(other.buffer),
          length(other.length),
          overflow(other.overflow)
    {
        other.overflow = nullptr;
    }

    LogMessage &LogMessage::operator=(LogMessage &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            level = other.level;
            timestamp = other.timestamp;
            thread_id = other.thread_id;
            buffer = other.buffer;
            length = other.length;
            overflow = other.overflow;
            other.overflow = nullptr;
        }
        return *this;
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

    void LogMessage::reset() noexcept
    {
        if (overflow)
        {
            StringPool::instance().deallocate(overflow);
            overflow = nullptr;
        }
        length = 0;
        buffer.fill(0);
    }

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
        if (max_count == 0)
        {
            return 0;
        }

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
            throw std::invalid_argument("Invalid AsyncLoggerConfig");
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

    bool AsyncLogger::flush_with_timeout(std::chrono::milliseconds timeout) noexcept
    {
        if (!running_.load(std::memory_order_acquire))
        {
            return true;
        }

        std::unique_lock<std::mutex> lock(flush_mutex_);

        const bool flushed = flush_cv_.wait_for(lock, timeout, [this]() noexcept
                                                { return pending_messages_.load(std::memory_order_acquire) == 0; });

        return flushed;
    }

    void AsyncLogger::flush() noexcept
    {
        static_cast<void>(flush_with_timeout(DEFAULT_FLUSH_TIMEOUT));
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

        {
            std::lock_guard<std::mutex> lock(flush_mutex_);
            pending_messages_.store(0, std::memory_order_release);
            flush_cv_.notify_all();
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

    size_t AsyncLogger::dropped_count() const noexcept
    {
        return dropped_messages_.load(std::memory_order_relaxed);
    }

    void AsyncLogger::reset_dropped_count() noexcept
    {
        dropped_messages_.store(0, std::memory_order_release);
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

        {
            std::lock_guard<std::mutex> lock(*log_mutex_);
            if (file_stream_->is_open())
            {
                file_stream_->flush();
            }
        }

        {
            std::lock_guard<std::mutex> lock(flush_mutex_);
            pending_messages_.store(0, std::memory_order_release);
            flush_cv_.notify_all();
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
            dropped_messages_.fetch_add(1, std::memory_order_relaxed);
            return false;

        case OverflowPolicy::DropOldest:
        {
            LogMessage oldest;
            if (queue_.try_pop(oldest))
            {
                pending_messages_.fetch_sub(1, std::memory_order_relaxed);
                dropped_messages_.fetch_add(1, std::memory_order_relaxed);
                if (queue_.try_push(message))
                {
                    pending_messages_.fetch_add(1, std::memory_order_relaxed);
                    flush_cv_.notify_one();
                    return true;
                }
            }
            dropped_messages_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        case OverflowPolicy::Block:
        {
            const auto deadline = std::chrono::steady_clock::now() + config_.block_timeout_ms;
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
                else if (spin_count < config_.block_max_spin_iterations)
                {
                    std::this_thread::yield();
                    ++spin_count;
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
            dropped_messages_.fetch_add(1, std::memory_order_relaxed);
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
            dropped_messages_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

} // namespace DetourModKit
