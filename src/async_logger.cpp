#include "DetourModKit/async_logger.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace DetourModKit
{
    StringPool::StringPool()
    {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        grow_pool_locked();
    }

    StringPool::~StringPool() noexcept
    {
        size_t leaked = 0;

        {
            // Acquire the mutex to synchronize with any in-flight deallocate() calls
            std::lock_guard<std::mutex> lock(pool_mutex_);
            leaked = heap_fallback_count_.load(std::memory_order_relaxed);
        }

        if (leaked > 0)
        {
            std::cerr << "[StringPool] " << leaked
                      << " heap-fallback string(s) were not returned before destruction\n";
        }

        Block *current = head_.load(std::memory_order_relaxed);
        while (current)
        {
            Block *next = current->next;

            PoolSlot *slots = reinterpret_cast<PoolSlot *>(current->data);
            for (size_t i = 0; i < POOL_SLOTS_PER_BLOCK; ++i)
            {
                if (current->constructed_mask & (1u << i))
                {
                    slots[i].~PoolSlot();
                }
            }

            ::operator delete(current);
            current = next;
        }
        head_.store(nullptr, std::memory_order_relaxed);
    }

    void StringPool::grow_pool_locked()
    {
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

        new_block->next = existing;
        new_block->free_list = nullptr;
        new_block->slot_count = POOL_SLOTS_PER_BLOCK;

        PoolSlot *slots = reinterpret_cast<PoolSlot *>(new_block->data);
        static_assert(POOL_SLOTS_PER_BLOCK <= 32, "constructed_mask is uint32_t; increase its width if POOL_SLOTS_PER_BLOCK > 32");
        uint32_t constructed = 0;
        for (size_t i = 0; i < POOL_SLOTS_PER_BLOCK; ++i)
        {
            new (&slots[i]) PoolSlot();
            constructed |= (1u << i);
            slots[i].next_free = (i + 1 < POOL_SLOTS_PER_BLOCK) ? &slots[i + 1] : nullptr;
        }
        new_block->constructed_mask = constructed;
        new_block->free_list = &slots[0];

        head_.store(new_block, std::memory_order_release);
        pool_size_.fetch_add(1, std::memory_order_relaxed);
    }

    StringPool &StringPool::instance() noexcept
    {
        static StringPool pool;
        return pool;
    }

    StringPool::PoolSlot *StringPool::claim_free_slot() noexcept
    {
        assert(!pool_mutex_.try_lock() && "claim_free_slot must be called with pool_mutex_ held");
        for (Block *b = head_.load(std::memory_order_relaxed); b; b = b->next)
        {
            if (b->free_list)
            {
                PoolSlot *slot = b->free_list;
                b->free_list = slot->next_free;
                --b->slot_count;
                return slot;
            }
        }
        return nullptr;
    }

    std::string *StringPool::allocate(size_t size)
    {
        if (size > MEMORY_POOL_BLOCK_SIZE - sizeof(PoolSlot) - 16)
        {
            auto *ptr = new (std::nothrow) std::string();
            if (ptr)
            {
                heap_fallback_count_.fetch_add(1, std::memory_order_relaxed);
            }
            return ptr;
        }

        std::lock_guard<std::mutex> lock(pool_mutex_);

        PoolSlot *slot = claim_free_slot();
        if (!slot)
        {
            grow_pool_locked();
            slot = claim_free_slot();
        }

        if (slot)
        {
            slot->str.clear();
            return &slot->str;
        }

        auto *ptr = new (std::nothrow) std::string();
        if (ptr)
        {
            heap_fallback_count_.fetch_add(1, std::memory_order_relaxed);
        }
        return ptr;
    }

    void StringPool::deallocate(std::string *ptr) noexcept
    {
        if (!ptr)
            return;

        std::lock_guard<std::mutex> lock(pool_mutex_);

        for (Block *b = head_.load(std::memory_order_relaxed); b; b = b->next)
        {
            const auto *block_begin = reinterpret_cast<const char *>(b->data);
            const auto *block_end = block_begin + POOL_SLOTS_PER_BLOCK * sizeof(PoolSlot);
            const auto *raw_ptr = reinterpret_cast<const char *>(ptr);

            if (raw_ptr >= block_begin && raw_ptr < block_end)
            {
                auto offset = static_cast<size_t>(raw_ptr - block_begin);
                PoolSlot *slot = reinterpret_cast<PoolSlot *>(b->data) + (offset / sizeof(PoolSlot));
                slot->str.clear();
                return_slot_locked(slot, b);
                return;
            }
        }

        // Not a pool allocation — heap delete under lock is safe and brief.
        delete ptr;
        if (heap_fallback_count_.load(std::memory_order_relaxed) > 0)
        {
            heap_fallback_count_.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    void StringPool::return_slot_locked(PoolSlot *slot, Block *block) noexcept
    {
        slot->next_free = block->free_list;
        block->free_list = slot;
        ++block->slot_count;
    }

    LogMessage::LogMessage(LogLevel lvl, std::string_view msg)
        : level(lvl),
          timestamp(std::chrono::system_clock::now()),
          thread_id(std::this_thread::get_id())
    {
        const size_t msg_size = std::min(msg.size(), MAX_VALID_LENGTH);

        if (msg_size <= MAX_INLINE_SIZE)
        {
            std::memcpy(buffer.data(), msg.data(), msg_size);
            length = msg_size;
        }
        else
        {
            overflow = StringPool::instance().allocate(msg_size);
            if (overflow)
            {
                try
                {
                    overflow->assign(msg.data(), msg_size);
                    length = overflow->size();
                }
                catch (...)
                {
                    StringPool::instance().deallocate(overflow);
                    overflow = nullptr;
                    length = 0;
                }
            }
            else
            {
                // Allocation failed (OOM) — message is silently dropped
                length = 0;
            }
        }
    }

    LogMessage::~LogMessage() noexcept
    {
        reset();
    }

    LogMessage::LogMessage(LogMessage &&other) noexcept
        : level(other.level),
          timestamp(other.timestamp),
          thread_id(other.thread_id),
          length(other.length),
          overflow(other.overflow)
    {
        if (length > 0 && !overflow)
        {
            std::memcpy(buffer.data(), other.buffer.data(), length);
        }
        other.overflow = nullptr;
        other.length = 0;
    }

    LogMessage &LogMessage::operator=(LogMessage &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            level = other.level;
            timestamp = other.timestamp;
            thread_id = other.thread_id;
            length = other.length;
            overflow = other.overflow;
            if (length > 0 && !overflow)
            {
                std::memcpy(buffer.data(), other.buffer.data(), length);
            }
            other.overflow = nullptr;
            other.length = 0;
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
    }

    size_t DynamicMPMCQueue::validated_capacity(size_t capacity)
    {
        if ((capacity & (capacity - 1)) != 0 || capacity < 2)
        {
            throw std::invalid_argument("DynamicMPMCQueue capacity must be a power of 2 and at least 2");
        }
        return capacity;
    }

    DynamicMPMCQueue::DynamicMPMCQueue(size_t capacity)
        : capacity_(validated_capacity(capacity)), mask_(capacity_ - 1),
          buffer_(std::make_unique<Slot[]>(capacity_))
    {
        for (size_t i = 0; i < capacity_; ++i)
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

        items.reserve(items.size() + max_count);

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
                             std::shared_ptr<WinFileStream> file_stream,
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

    AsyncLogger::~AsyncLogger() noexcept
    {
        shutdown();
    }

    bool AsyncLogger::enqueue(LogLevel level, std::string_view message) noexcept
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

                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    now.time_since_epoch()) %
                                1000;
                *file_stream_ << "[" << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
                              << "." << std::setfill('0') << std::setw(3) << ms.count()
                              << std::setfill(' ') << "] "
                              << "[" << std::setw(7) << std::left << log_level_to_string(level) << "] :: "
                              << message << '\n';
                file_stream_->flush();
            }
            return true;
        }

        LogMessage msg(level, message);

        // Increment before push so flush cannot observe zero while a message
        // is already in the queue but not yet counted.
        pending_messages_.fetch_add(1, std::memory_order_acq_rel);
        if (queue_.try_push(msg))
        {
            flush_cv_.notify_one();
            return true;
        }
        // Push failed — undo the pre-increment before entering overflow handling
        pending_messages_.fetch_sub(1, std::memory_order_acq_rel);
        return handle_overflow(std::move(msg));
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
                {
                    std::lock_guard<std::mutex> flock(flush_mutex_);
                    pending_messages_.fetch_sub(batch_size, std::memory_order_acq_rel);
                }
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
                          << "." << std::setfill('0') << std::setw(3) << ms.count()
                          << std::setfill(' ') << "] "
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
                // Count the evicted oldest message as dropped
                dropped_messages_.fetch_add(1, std::memory_order_relaxed);
                if (queue_.try_push(message))
                {
                    // Net effect on pending_messages_: pop(-1) + push(+1) = 0
                    flush_cv_.notify_one();
                    return true;
                }
                // Pop succeeded but push failed: net -1
                pending_messages_.fetch_sub(1, std::memory_order_acq_rel);
            }
            // Count the new message as dropped (separate from the evicted oldest above).
            // dropped_messages_ counts individual lost messages, not overflow events.
            dropped_messages_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        case OverflowPolicy::Block:
        {
            const auto deadline = std::chrono::steady_clock::now() + config_.block_timeout_ms;
            size_t spin_count = 0;

            // Pre-increment so flush sees the in-flight message throughout the retry loop
            pending_messages_.fetch_add(1, std::memory_order_acq_rel);

            while (std::chrono::steady_clock::now() < deadline)
            {
                if (queue_.try_push(message))
                {
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
            // Timed out — undo the pre-increment
            pending_messages_.fetch_sub(1, std::memory_order_acq_rel);
            dropped_messages_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        case OverflowPolicy::SyncFallback:
        {
            std::lock_guard<std::mutex> lock(*log_mutex_);
            if (!file_stream_->is_open() || !file_stream_->good())
            {
                return false;
            }

            const auto time_t = std::chrono::system_clock::to_time_t(message.timestamp);
            std::tm tm_buf{};

#if defined(_WIN32) || defined(_MSC_VER)
            localtime_s(&tm_buf, &time_t);
#else
            localtime_r(&time_t, &tm_buf);
#endif

            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                message.timestamp.time_since_epoch()) %
                            1000;
            *file_stream_ << "[" << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
                          << "." << std::setfill('0') << std::setw(3) << ms.count()
                          << std::setfill(' ') << "] "
                          << "[" << std::setw(7) << std::left << log_level_to_string(message.level) << "] :: "
                          << message.message() << '\n';
            file_stream_->flush();

            if (file_stream_->fail())
            {
                return false;
            }
            return true;
        }

        default:
            dropped_messages_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

} // namespace DetourModKit
