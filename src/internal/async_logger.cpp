#include "internal/async_logger.hpp"

#include "DetourModKit/diagnostics.hpp"

#include "internal/async_logger_queue.hpp"
#include "platform.hpp"
#include "internal/win_file_stream.hpp"

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <new>
#include <span>
#include <system_error>
#include <thread>
#include <type_traits>

namespace DetourModKit
{
    using detail::acquire_module_ref;
    using detail::LogMessage;
    using detail::release_module_ref;

    // The string pool, per-message record, and MPMC queue are implementation-only types that live in
    // DetourModKit::detail (see internal/async_logger_queue.hpp). Their out-of-line definitions are grouped in the
    // namespace block below; the AsyncLogger pimpl definitions that follow reach them through the using-declarations
    // above.
    namespace detail
    {
        // Test-only override for is_loader_lock_held(), mirroring g_config_watcher_loader_lock_override. When non-null,
        // AsyncLogger::Impl::shutdown() consults this instead of the real PEB-based detection, letting the suite drive
        // the writer-detach-and-leak branch (and the public destructor's leak-the-Impl path) from user code off the
        // real loader lock. Set / cleared on a single thread inside a test fixture.
        bool (*g_async_logger_loader_lock_override)() noexcept = nullptr;

        bool async_logger_loader_lock_held() noexcept
        {
            if (auto *override_fn = g_async_logger_loader_lock_override)
            {
                return override_fn();
            }
            return is_loader_lock_held();
        }

        StringPool::StringPool() noexcept
        {
            std::lock_guard<std::mutex> lock(m_pool_mutex);
            grow_pool_locked();
        }

        StringPool::~StringPool() noexcept
        {
            size_t leaked = 0;

            {
                // Acquire the mutex to synchronize with any in-flight deallocate() calls
                std::lock_guard<std::mutex> lock(m_pool_mutex);
                leaked = m_heap_fallback_count.load(std::memory_order_relaxed);
            }

            if (leaked > 0)
            {
                std::cerr << "[StringPool] " << leaked
                          << " heap-fallback string(s) were not returned before destruction\n";
            }

            Block *current = m_head.load(std::memory_order_relaxed);
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

                // Block is over-aligned (alignas(64)); it must be released through the aligned operator delete that
                // matches its aligned allocation in grow_pool_locked().
                ::operator delete(current, std::align_val_t{alignof(Block)});
                current = next;
            }
            m_head.store(nullptr, std::memory_order_relaxed);
        }

        void StringPool::grow_pool_locked() noexcept
        {
            Block *existing = m_head.load(std::memory_order_relaxed);
            size_t count = 0;
            for (Block *b = existing; b; b = b->next)
            {
                if (++count >= MEMORY_POOL_BLOCK_COUNT)
                {
                    return;
                }
            }

            // Block is over-aligned via its alignas(64) data member, so it must be allocated through the aligned
            // operator new; the plain overload is not required to honour an alignment stricter than
            // __STDCPP_DEFAULT_NEW_ALIGNMENT__ (typically 16 on x64), which would be alignment UB. The allocation is
            // also nothrow: this runs underneath the noexcept logging path, so on out-of-memory it must leave the pool
            // unchanged and let the caller fall back to a nothrow heap string (or drop the message) rather than let
            // std::bad_alloc escape and terminate.
            void *raw = ::operator new(sizeof(Block), std::align_val_t{alignof(Block)}, std::nothrow);
            if (!raw)
            {
                return;
            }
            Block *new_block = new (raw) Block();

            new_block->next = existing;
            new_block->free_list = nullptr;

            PoolSlot *slots = reinterpret_cast<PoolSlot *>(new_block->data);
            static_assert(POOL_SLOTS_PER_BLOCK <= 32,
                          "constructed_mask is uint32_t; increase its width if POOL_SLOTS_PER_BLOCK > 32");
            // Slot construction must not throw, otherwise a partially built block could leak with no unwinding under
            // this noexcept function. std::string's default constructor is noexcept, so the loop below is provably
            // no-throw.
            static_assert(std::is_nothrow_default_constructible_v<PoolSlot>,
                          "PoolSlot must be nothrow-default-constructible so grow_pool_locked stays no-throw");
            uint32_t constructed = 0;
            for (size_t i = 0; i < POOL_SLOTS_PER_BLOCK; ++i)
            {
                new (&slots[i]) PoolSlot();
                constructed |= (1u << i);
                slots[i].next_free = (i + 1 < POOL_SLOTS_PER_BLOCK) ? &slots[i + 1] : nullptr;
            }
            new_block->constructed_mask = constructed;
            new_block->free_list = &slots[0];

            m_head.store(new_block, std::memory_order_release);
        }

        StringPool &StringPool::instance() noexcept
        {
            // Constructed once into function-local static storage and never destroyed. A Meyers singleton would be
            // destroyed at static teardown and race late LogMessage destructors that call into deallocate()
            // (use-after-free under DLL unload and loader-lock teardown). A heap-allocated singleton (`*new
            // StringPool()`) would instead require a throwing operator new whose std::bad_alloc would escape this
            // noexcept accessor and terminate the host. Placement-new into static storage avoids both: the object lives
            // for the whole process, its destructor never runs, and construction performs no throwing allocation
            // because grow_pool_locked() is nothrow. The bounded block leak (at most MEMORY_POOL_BLOCK_COUNT blocks,
            // each a POOL_SLOTS_PER_BLOCK * sizeof(PoolSlot)-byte slot array) is released by the OS at process exit.
            alignas(StringPool) static unsigned char storage[sizeof(StringPool)];
            static StringPool *const pool = ::new (static_cast<void *>(storage)) StringPool();
            return *pool;
        }

        StringPool::PoolSlot *StringPool::claim_free_slot() noexcept
        {
            for (Block *b = m_head.load(std::memory_order_relaxed); b; b = b->next)
            {
                if (b->free_list)
                {
                    PoolSlot *slot = b->free_list;
                    b->free_list = slot->next_free;
                    return slot;
                }
            }
            return nullptr;
        }

        std::string *StringPool::allocate(size_t size) noexcept
        {
            if (size > MAX_POOLED_STRING_SIZE)
            {
                auto *ptr = new (std::nothrow) std::string();
                if (ptr)
                {
                    m_heap_fallback_count.fetch_add(1, std::memory_order_relaxed);
                }
                return ptr;
            }

            std::lock_guard<std::mutex> lock(m_pool_mutex);

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
                m_heap_fallback_count.fetch_add(1, std::memory_order_relaxed);
            }
            return ptr;
        }

        void StringPool::deallocate(std::string *ptr) noexcept
        {
            if (!ptr)
                return;

            std::lock_guard<std::mutex> lock(m_pool_mutex);

            for (Block *b = m_head.load(std::memory_order_relaxed); b; b = b->next)
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

            // Not a pool allocation -- heap fallback. The delete is performed under m_pool_mutex to serialize with
            // concurrent deallocate() calls that walk the block list above. Without the lock, a concurrent deallocate
            // could see a partially updated free list. The lock does not prevent double-free of heap pointers (those
            // are not tracked); callers must ensure each pointer is deallocated exactly once. The cost is a single
            // free() call (or no-op for SSO-sized strings).
            delete ptr;
            if (m_heap_fallback_count.load(std::memory_order_relaxed) > 0)
            {
                m_heap_fallback_count.fetch_sub(1, std::memory_order_relaxed);
            }
        }

        void StringPool::return_slot_locked(PoolSlot *slot, Block *block) noexcept
        {
            slot->next_free = block->free_list;
            block->free_list = slot;
        }

        // buffer is intentionally left uninitialized on this hot path (see async_logger_queue.hpp): only [0, length)
        // is written before any read, so zero-filling it every message would be wasted work.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
        LogMessage::LogMessage(LogLevel lvl, std::string_view msg) noexcept
            : level(lvl), timestamp(std::chrono::system_clock::now())
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
                        overflow->assign(msg.substr(0, msg_size));
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
                    // Allocation failed (OOM) -- message is silently dropped
                    length = 0;
                }
            }
        }

        LogMessage::~LogMessage() noexcept
        {
            reset();
        }

        // Move transfers ownership of the overflow pointer without touching the
        // StringPool or m_heap_fallback_count. The allocation/deallocation balance is maintained because exactly one
        // LogMessage owns the pointer at any time, and only reset() (called by the eventual owner's destructor) returns
        // it to the pool.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init) buffer is filled by the length-guarded memcpy below
        LogMessage::LogMessage(LogMessage &&other) noexcept
            : level(other.level), timestamp(other.timestamp), length(other.length), overflow(other.overflow)
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
            : m_capacity(validated_capacity(capacity)), m_mask(m_capacity - 1),
              m_buffer(std::make_unique<Slot[]>(m_capacity))
        {
            for (size_t i = 0; i < m_capacity; ++i)
            {
                m_buffer[i].sequence.store(i, std::memory_order_relaxed);
            }
        }

        bool DynamicMPMCQueue::try_push(LogMessage &item) noexcept
        {
            size_t pos = m_enqueue_pos.load(std::memory_order_relaxed);

            for (;;)
            {
                Slot &slot = m_buffer[pos & m_mask];
                size_t seq = slot.sequence.load(std::memory_order_acquire);
                intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);

                if (diff == 0)
                {
                    if (m_enqueue_pos.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed))
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
                    pos = m_enqueue_pos.load(std::memory_order_relaxed);
                }
            }
        }

        bool DynamicMPMCQueue::try_pop(LogMessage &item) noexcept
        {
            size_t pos = m_dequeue_pos.load(std::memory_order_relaxed);

            for (;;)
            {
                Slot &slot = m_buffer[pos & m_mask];
                size_t seq = slot.sequence.load(std::memory_order_acquire);
                intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);

                if (diff == 0)
                {
                    if (m_dequeue_pos.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed))
                    {
                        item = std::move(slot.data);
                        slot.sequence.store(pos + m_capacity, std::memory_order_release);
                        return true;
                    }
                }
                else if (diff < 0)
                {
                    return false;
                }
                else
                {
                    pos = m_dequeue_pos.load(std::memory_order_relaxed);
                }
            }
        }

        size_t DynamicMPMCQueue::try_pop_batch(std::vector<LogMessage> &items, size_t max_count) noexcept
        {
            if (max_count == 0)
            {
                return 0;
            }

            // Reserve headroom so the push_back loop below never reallocates. This runs on the writer's noexcept
            // frames, so a throwing allocator here must not escape: on bad_alloc the reserve is skipped and the pop
            // is capped to whatever spare capacity the vector already holds. Failing closed to a smaller batch is
            // correct behaviour for an out-of-memory host; terminating it is not.
            try
            {
                items.reserve(items.size() + max_count);
            }
            catch (...)
            {
            }

            // Never pop more than fits in the reserved capacity. Within capacity, push_back performs no allocation and
            // the LogMessage move constructor is noexcept, so the loop cannot throw even if the reserve above failed.
            const size_t headroom = items.capacity() - items.size();
            const size_t budget = std::min(max_count, headroom);

            size_t count = 0;
            LogMessage msg;

            while (count < budget && try_pop(msg))
            {
                items.push_back(std::move(msg));
                ++count;
            }

            return count;
        }

        size_t DynamicMPMCQueue::size() const noexcept
        {
            size_t enq = m_enqueue_pos.load(std::memory_order_relaxed);
            size_t deq = m_dequeue_pos.load(std::memory_order_relaxed);
            return (enq >= deq) ? (enq - deq) : 0;
        }

        bool DynamicMPMCQueue::empty() const noexcept
        {
            return size() == 0;
        }
    } // namespace detail

    // The AsyncLogger pimpl: every member and method that touches the queue, string pool, writer thread, or flush
    // synchronization lives here, so the header (internal/async_logger.hpp) names none of it. AsyncLogger forwards
    // each public call to the matching Impl method.
    struct AsyncLogger::Impl
    {
        Impl(const AsyncLoggerConfig &config, std::shared_ptr<detail::WinFileStream> file_stream,
             std::shared_ptr<std::mutex> log_mutex);
        ~Impl() noexcept;

        Impl(const Impl &) = delete;
        Impl &operator=(const Impl &) = delete;
        Impl(Impl &&) = delete;
        Impl &operator=(Impl &&) = delete;

        [[nodiscard]] bool enqueue(LogLevel level, std::string_view message) noexcept;
        [[nodiscard]] bool flush_with_timeout(std::chrono::milliseconds timeout) noexcept;
        void flush() noexcept;
        void shutdown() noexcept;
        [[nodiscard]] bool is_running() const noexcept;
        [[nodiscard]] bool is_writer_waiting() const noexcept;
        [[nodiscard]] size_t queue_size() const noexcept;
        [[nodiscard]] size_t dropped_count() const noexcept;
        void reset_dropped_count() noexcept;
        void set_timestamp_format(std::string timestamp_format) noexcept;
        // True once shutdown() detached the writer under the loader lock instead of joining it. The public
        // destructor reads this to decide whether the Impl (and the queue / cv / file stream the detached writer
        // still touches) may be destroyed or must be leaked in place.
        [[nodiscard]] bool writer_was_detached() const noexcept;

        void writer_thread_func() noexcept;
        // Drains any messages remaining in the queue after the writer thread exits (called during shutdown to flush
        // late-enqueued messages that arrived between m_running=false and the writer observing an empty queue).
        void drain_remaining() noexcept;
        void write_batch(std::span<detail::LogMessage> messages) noexcept;
        bool handle_overflow(detail::LogMessage &&message) noexcept;
        // Wakes the writer thread if it is parked on m_flush_cv after a successful push. The producer increments
        // m_pending_messages and publishes the slot before this load; the writer publishes m_writer_waiting before
        // checking the same count and parking. Those seq_cst operations form a store/load handshake that closes the
        // lost-wakeup window without taking m_flush_mutex while the writer is actively draining. notify_all (not
        // notify_one) keeps a flusher waiting on the same condition variable from absorbing the wake and leaving the
        // writer asleep.
        void notify_writer() noexcept;

        detail::DynamicMPMCQueue m_queue;
        AsyncLoggerConfig m_config;

        std::shared_ptr<detail::WinFileStream> m_file_stream;
        std::shared_ptr<std::mutex> m_log_mutex;

        std::jthread m_writer_thread;
        // Counted reference on the module the writer thread's code lives in, taken before the thread is created.
        // shutdown() releases it after a clean join, or leaks it on the loader-lock detach path so the writer's code
        // stays mapped. void* keeps the pimpl header-light; it holds an HMODULE in the implementation. See
        // detail::acquire_module_ref.
        void *m_writer_self_ref{nullptr};
        std::atomic<bool> m_running{false};
        std::atomic<bool> m_shutdown_requested{false};
        // Latched by shutdown() when it detaches the writer on the loader-lock path. Read by ~AsyncLogger to keep the
        // Impl alive past the detached writer. A latched flag (rather than re-querying is_loader_lock_held() in the
        // destructor) avoids a TOCTOU where the loader-lock state differs between the detach decision and the free.
        std::atomic<bool> m_writer_detached{false};

        std::mutex m_flush_mutex;
        std::condition_variable m_flush_cv;

        // Set true by the writer immediately before it parks on m_flush_cv and cleared when it wakes. Producers read it
        // outside m_flush_mutex after a successful queue push; the seq_cst order shared with m_pending_messages makes a
        // racing push either visible to the writer's wait predicate or visible here as a parked-writer wake.
        std::atomic<bool> m_writer_waiting{false};

        std::atomic<size_t> m_pending_messages{0};
        std::atomic<size_t> m_dropped_messages{0};
    };

    AsyncLogger::Impl::Impl(const AsyncLoggerConfig &config, std::shared_ptr<detail::WinFileStream> file_stream,
                            std::shared_ptr<std::mutex> log_mutex)
        : m_queue(config.queue_capacity), m_config(config), m_file_stream(std::move(file_stream)),
          m_log_mutex(std::move(log_mutex))
    {
        if (!m_config.validate())
        {
            throw std::invalid_argument("Invalid AsyncLoggerConfig");
        }

        if (!m_file_stream)
        {
            throw std::invalid_argument("file_stream cannot be null");
        }

        if (!m_log_mutex)
        {
            throw std::invalid_argument("log_mutex cannot be null");
        }

        // Hold a counted reference on this module before creating the writer thread. Once std::jthread returns, the
        // writer may already be executing this TU's code, so the keepalive has to predate the thread start. shutdown()
        // releases it after a clean join or leaks it on the loader-lock detach path.
        const HMODULE writer_self_ref = acquire_module_ref();
        if (writer_self_ref == nullptr)
        {
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                    "AsyncLogger: acquire_module_ref failed");
        }

        m_running.store(true, std::memory_order_release);
        try
        {
            m_writer_thread = std::jthread(&AsyncLogger::Impl::writer_thread_func, this);
        }
        catch (...)
        {
            m_running.store(false, std::memory_order_release);
            release_module_ref(writer_self_ref);
            throw;
        }
        m_writer_self_ref = writer_self_ref;
    }

    AsyncLogger::Impl::~Impl() noexcept
    {
        shutdown();
    }

    bool AsyncLogger::Impl::enqueue(LogLevel level, std::string_view message) noexcept
    {
        if (m_shutdown_requested.load(std::memory_order_acquire))
        {
            std::lock_guard<std::mutex> lock(*m_log_mutex);
            if (!m_file_stream->is_open() || !m_file_stream->good())
            {
                // Stream already closed or failed during teardown: the message cannot be delivered, so report the drop
                // rather than a false success.
                return false;
            }

            const auto now = std::chrono::system_clock::now();
            const auto time_t = std::chrono::system_clock::to_time_t(now);
            std::tm tm_buf{};

#if defined(_WIN32) || defined(_MSC_VER)
            localtime_s(&tm_buf, &time_t);
#else
            localtime_r(&time_t, &tm_buf);
#endif

            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            *m_file_stream << "[" << std::put_time(&tm_buf, m_config.timestamp_format.c_str()) << "."
                           << std::setfill('0') << std::setw(3) << ms.count() << std::setfill(' ') << "] "
                           << "[" << std::setw(7) << std::left << to_string(level) << "] :: " << message << '\n';
            m_file_stream->flush();

            // Surface a write/flush failure through the no-throw delivery bool.
            return m_file_stream->good();
        }

        LogMessage msg(level, message);

        // Increment before push so flush cannot observe zero while a message is already in the queue but not yet
        // counted.
        m_pending_messages.fetch_add(1, std::memory_order_seq_cst);
        if (m_queue.try_push(msg))
        {
            notify_writer();
            return true;
        }
        // Push failed -- undo the pre-increment before entering overflow handling
        m_pending_messages.fetch_sub(1, std::memory_order_seq_cst);
        return handle_overflow(std::move(msg));
    }

    bool AsyncLogger::Impl::flush_with_timeout(std::chrono::milliseconds timeout) noexcept
    {
        if (!m_running.load(std::memory_order_acquire))
        {
            return true;
        }

        std::unique_lock<std::mutex> lock(m_flush_mutex);

        const bool flushed = m_flush_cv.wait_for(lock, timeout, [this]() noexcept
                                                 { return m_pending_messages.load(std::memory_order_acquire) == 0; });

        return flushed;
    }

    void AsyncLogger::Impl::flush() noexcept
    {
        (void)flush_with_timeout(DEFAULT_FLUSH_TIMEOUT);
    }

    void AsyncLogger::Impl::shutdown() noexcept
    {
        bool expected = false;
        if (!m_shutdown_requested.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
            return;
        }

        m_running.store(false, std::memory_order_release);

        // Wake the writer if it is parked. Taking m_flush_mutex serializes this notify with the writer's
        // atomic unlock-and-block inside wait_for, so a parked writer observes m_running == false promptly
        // instead of waiting out the flush interval before it can exit and be joined below.
        {
            std::lock_guard<std::mutex> lock(m_flush_mutex);
            m_flush_cv.notify_all();
        }

        if (m_writer_thread.joinable())
        {
            if (detail::async_logger_loader_lock_held())
            {
                // Under the loader lock we cannot join. Detach the writer and leak its module reference (taken before
                // thread creation), keeping the writer's code mapped for the rest of the process while it drains and
                // exits. Latch that the writer is detached so ~AsyncLogger leaks this Impl in place instead of
                // destroying the queue / cv / file stream out from under that still-running writer.
                m_writer_thread.detach();
                m_writer_detached.store(true, std::memory_order_release);
                DetourModKit::diagnostics::record_intentional_leak(
                    DetourModKit::diagnostics::LeakSubsystem::AsyncLogger);
            }
            else
            {
                m_writer_thread.join();
                // Joined off the loader lock: the writer's code is done, so drop the reference taken before thread
                // creation. Another reference on the module still exists (the caller running this teardown), so this is
                // never terminal.
                release_module_ref(static_cast<HMODULE>(m_writer_self_ref));
                m_writer_self_ref = nullptr;
            }
        }

        // Drain any messages enqueued between m_running=false and the writer thread exiting. Without this,
        // late-arriving messages would be silently lost and the force-zero below would mask the discrepancy.
        //
        // A narrow race remains: a producer that already passed the m_shutdown_requested check in enqueue() but has not
        // yet called try_push() can enqueue one message after this drain completes. This is an accepted trade-off --
        // closing it would require a producers_in_flight atomic counter on every enqueue() call, adding two atomic RMW
        // operations to the hot path. At most one message per producer thread can be lost, and only during the
        // nanosecond window between the drain and the force-zero below.
        drain_remaining();

        {
            std::lock_guard<std::mutex> lock(m_flush_mutex);
            m_pending_messages.store(0, std::memory_order_release);
            m_flush_cv.notify_all();
        }
    }

    bool AsyncLogger::Impl::is_running() const noexcept
    {
        return m_running.load(std::memory_order_acquire);
    }

    bool AsyncLogger::Impl::is_writer_waiting() const noexcept
    {
        return m_writer_waiting.load(std::memory_order_acquire);
    }

    size_t AsyncLogger::Impl::queue_size() const noexcept
    {
        return m_queue.size();
    }

    size_t AsyncLogger::Impl::dropped_count() const noexcept
    {
        return m_dropped_messages.load(std::memory_order_relaxed);
    }

    void AsyncLogger::Impl::reset_dropped_count() noexcept
    {
        m_dropped_messages.store(0, std::memory_order_release);
    }

    void AsyncLogger::Impl::set_timestamp_format(std::string timestamp_format) noexcept
    {
        // No lock taken here: the caller holds the shared log mutex (m_log_mutex), which is the same mutex the writer
        // thread takes before it reads m_config.timestamp_format in write_batch / enqueue / handle_overflow. Because
        // the caller holds it, the writer cannot be mid-read, so the assignment is race-free; taking the mutex here
        // would self-deadlock the reconfigure path that already owns it. std::string move-assignment is noexcept, so
        // the by-value parameter (copied in the caller's throwing context) makes this frame genuinely no-throw.
        m_config.timestamp_format = std::move(timestamp_format);
    }

    bool AsyncLogger::Impl::writer_was_detached() const noexcept
    {
        return m_writer_detached.load(std::memory_order_acquire);
    }

    void AsyncLogger::Impl::notify_writer() noexcept
    {
        // The caller has already incremented m_pending_messages and published the queue slot. In the
        // seq_cst order, either the writer's pending-count predicate sees that increment before it parks,
        // or this load sees the writer's waiting flag and wakes it. That closes the lost-wakeup window
        // without taking m_flush_mutex while the writer is actively draining.
        if (m_writer_waiting.load(std::memory_order_seq_cst))
        {
            // Notify under m_flush_mutex so the wake cannot be lost against the writer's atomic
            // unlock-and-block, and notify_all (not notify_one) so a flusher blocked on the same condition
            // variable cannot absorb the single notification and leave the writer asleep.
            std::lock_guard<std::mutex> lock(m_flush_mutex);
            m_flush_cv.notify_all();
        }
    }

    void AsyncLogger::Impl::writer_thread_func() noexcept
    {
        // Per-idle-cycle cap on the cooperative yields the writer spins through when the pending count
        // shows an in-flight push whose queue slot has not landed yet. Small and fixed so a producer
        // preempted mid-publish cannot turn the idle path into a tight hot loop.
        constexpr size_t INFLIGHT_SPIN_LIMIT = 8;

        // No pre-reserve here: this frame is noexcept, so a throwing reserve would std::terminate on host OOM.
        // try_pop_batch owns the (fail-closed) reservation and only pops within the capacity it can secure. After the
        // first pop the batch retains its capacity across the clear()s below, so the steady-state reserve is a no-op.
        std::vector<LogMessage> batch;

        auto last_flush = std::chrono::steady_clock::now();

        while (m_running.load(std::memory_order_acquire) || !m_queue.empty())
        {
            batch.clear();
            // The popped count is not needed here; the batch.empty() check below decides between the write path and the
            // idle-flush path.
            (void)m_queue.try_pop_batch(batch, m_config.batch_size);

            if (!batch.empty())
            {
                write_batch(batch);
                const size_t batch_size = batch.size();
                {
                    std::lock_guard<std::mutex> flock(m_flush_mutex);
                    m_pending_messages.fetch_sub(batch_size, std::memory_order_acq_rel);
                }
                m_flush_cv.notify_all();
                last_flush = std::chrono::steady_clock::now();
            }
            else
            {
                // A producer bumps m_pending_messages before it publishes its queue slot, so a non-zero
                // pending count with an empty pop means a push is in flight. Spin a small, fixed number of
                // cooperative yields to let that push land; the common in-flight window is a few
                // instructions, so the producer usually publishes here and the next pop drains it. The cap
                // bounds the spin: if the producer is preempted past the cap, the loop falls through to the
                // wait_for below, but with pending still non-zero the predicate is already satisfied, so it
                // returns without blocking and the next cycle spins again -- bounded each pass rather than a
                // tight hot loop. The writer only truly blocks once pending reaches zero (the genuinely idle
                // case), where notify_writer() or the flush-interval timeout wakes it.
                for (size_t spin = 0; spin < INFLIGHT_SPIN_LIMIT && m_running.load(std::memory_order_acquire) &&
                                      m_pending_messages.load(std::memory_order_seq_cst) != 0 && m_queue.empty();
                     ++spin)
                {
                    std::this_thread::yield();
                }

                auto now = std::chrono::steady_clock::now();
                if (now - last_flush >= m_config.flush_interval)
                {
                    std::lock_guard<std::mutex> lock(*m_log_mutex);
                    if (m_file_stream->is_open())
                    {
                        m_file_stream->flush();
                    }
                    last_flush = now;
                }

                std::unique_lock<std::mutex> lock(m_flush_mutex);

                // Publish that the writer is about to park, then check the producer-maintained pending
                // count while m_writer_waiting is still true. In the seq_cst order, a racing producer is
                // either counted here or observes m_writer_waiting in notify_writer() and signals this
                // condition variable under m_flush_mutex.
                m_writer_waiting.store(true, std::memory_order_seq_cst);
                m_flush_cv.wait_for(lock, m_config.flush_interval,
                                    [this]() noexcept
                                    {
                                        return m_pending_messages.load(std::memory_order_seq_cst) != 0 ||
                                               !m_running.load(std::memory_order_acquire);
                                    });
                m_writer_waiting.store(false, std::memory_order_seq_cst);
            }
        }

        {
            std::lock_guard<std::mutex> lock(*m_log_mutex);
            if (m_file_stream->is_open())
            {
                m_file_stream->flush();
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_flush_mutex);
            m_pending_messages.store(0, std::memory_order_release);
            m_flush_cv.notify_all();
        }
    }

    void AsyncLogger::Impl::drain_remaining() noexcept
    {
        // No pre-reserve: this frame is noexcept and try_pop_batch owns the fail-closed reservation (see
        // writer_thread_func). Under OOM a drain iteration may pop fewer items or none; the loop then exits with
        // some messages still queued, which is the correct fail-closed shutdown behaviour (never a terminate).
        std::vector<LogMessage> remaining;
        while (m_queue.try_pop_batch(remaining, m_config.batch_size) > 0)
        {
            write_batch(remaining);
            remaining.clear();
        }
    }

    void AsyncLogger::Impl::write_batch(std::span<LogMessage> messages) noexcept
    {
        std::lock_guard<std::mutex> lock(*m_log_mutex);

        if (!m_file_stream->is_open() || !m_file_stream->good())
        {
            return;
        }

        // Cache the localtime result across consecutive messages that share the same second to avoid repeated CRT lock
        // acquisition inside localtime_s.
        std::time_t cached_second{-1};
        std::tm cached_tm{};

        for (const auto &msg : messages)
        {
            const auto time_t = std::chrono::system_clock::to_time_t(msg.timestamp);

            if (time_t != cached_second)
            {
                cached_second = time_t;
#if defined(_WIN32) || defined(_MSC_VER)
                localtime_s(&cached_tm, &time_t);
#else
                localtime_r(&time_t, &cached_tm);
#endif
            }

            const auto ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(msg.timestamp.time_since_epoch()) % 1000;

            *m_file_stream << "[" << std::put_time(&cached_tm, m_config.timestamp_format.c_str()) << "."
                           << std::setfill('0') << std::setw(3) << ms.count() << std::setfill(' ') << "] "
                           << "[" << std::setw(7) << std::left << to_string(msg.level) << "] :: " << msg.message()
                           << '\n';
        }

        m_file_stream->flush();
    }

    bool AsyncLogger::Impl::handle_overflow(LogMessage &&message) noexcept
    {
        switch (m_config.overflow_policy)
        {
        case OverflowPolicy::DropNewest:
            m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
            return false;

        case OverflowPolicy::DropOldest:
        {
            LogMessage oldest;
            if (m_queue.try_pop(oldest))
            {
                // Count the evicted oldest message as dropped
                m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
                if (m_queue.try_push(message))
                {
                    // Net effect on m_pending_messages: pop(-1) + push(+1) = 0
                    notify_writer();
                    return true;
                }
                // Pop succeeded but push failed: net -1
                m_pending_messages.fetch_sub(1, std::memory_order_seq_cst);
            }
            // Count the new message as dropped (separate from the evicted oldest above). m_dropped_messages counts
            // individual lost messages, not overflow events.
            m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        case OverflowPolicy::Block:
        {
            const auto deadline = std::chrono::steady_clock::now() + m_config.block_timeout_ms;
            size_t spin_count = 0;

            // Pre-increment so flush sees the in-flight message throughout the retry loop
            m_pending_messages.fetch_add(1, std::memory_order_seq_cst);

            while (std::chrono::steady_clock::now() < deadline)
            {
                if (m_queue.try_push(message))
                {
                    notify_writer();
                    return true;
                }

                if (spin_count < m_config.spin_backoff_iterations)
                {
                    ++spin_count;
                }
                else if (spin_count < m_config.block_max_spin_iterations)
                {
                    std::this_thread::yield();
                    ++spin_count;
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
            // Timed out -- undo the pre-increment
            m_pending_messages.fetch_sub(1, std::memory_order_seq_cst);
            m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        case OverflowPolicy::SyncFallback:
        {
            std::lock_guard<std::mutex> lock(*m_log_mutex);
            if (!m_file_stream->is_open() || !m_file_stream->good())
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

            const auto ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(message.timestamp.time_since_epoch()) % 1000;
            *m_file_stream << "[" << std::put_time(&tm_buf, m_config.timestamp_format.c_str()) << "."
                           << std::setfill('0') << std::setw(3) << ms.count() << std::setfill(' ') << "] "
                           << "[" << std::setw(7) << std::left << to_string(message.level)
                           << "] :: " << message.message() << '\n';
            m_file_stream->flush();

            if (m_file_stream->fail())
            {
                return false;
            }
            return true;
        }

        default:
            m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    // AsyncLogger is a thin facade: construction builds the Impl (which validates the config and starts the writer
    // thread), and every public method forwards to it. The out-of-line destructor sees the complete Impl so the
    // unique_ptr can delete it (Impl::~Impl drains and joins the writer).
    AsyncLogger::AsyncLogger(const AsyncLoggerConfig &config, std::shared_ptr<detail::WinFileStream> file_stream,
                             std::shared_ptr<std::mutex> log_mutex)
        : m_impl(std::make_unique<Impl>(config, std::move(file_stream), std::move(log_mutex)))
    {
    }

    AsyncLogger::~AsyncLogger() noexcept
    {
        if (!m_impl)
        {
            return;
        }

        // Drive the writer to a stop. Under the loader lock shutdown() cannot join, so it detaches the writer (which
        // keeps reading m_queue / m_flush_cv / m_file_stream until it observes the stop) and latches m_writer_detached.
        m_impl->shutdown();

        if (m_impl->writer_was_detached())
        {
            // The writer is still running against this Impl's members, so ~Impl must NOT run: destroying the condition
            // variable while the detached writer is parked on it (or the queue it is draining) is undefined behaviour.
            // Abandon the already-heap-allocated Impl in place -- release() relinquishes the unique_ptr without
            // freeing, so the members outlive the writer with zero further allocation (no tiered leak cell is needed
            // the way the shared_ptr handle in Logger requires, because there is nothing new to allocate a home for).
            // The detached writer's own counted module reference keeps the code pages it executes mapped. The
            // intentional-leak event was already recorded inside shutdown()'s detach branch, so it is not recorded a
            // second time here.
            (void)m_impl.release();
            return;
        }

        // Off the loader lock the writer was joined by shutdown(), so the unique_ptr destroys the Impl normally. ~Impl
        // calls shutdown() again, but the m_shutdown_requested CAS makes that an idempotent no-op before the members
        // are freed.
    }

    void AsyncLogger::set_timestamp_format(std::string timestamp_format) noexcept
    {
        m_impl->set_timestamp_format(std::move(timestamp_format));
    }

    bool AsyncLogger::enqueue(LogLevel level, std::string_view message) noexcept
    {
        return m_impl->enqueue(level, message);
    }

    bool AsyncLogger::flush_with_timeout(std::chrono::milliseconds timeout) noexcept
    {
        return m_impl->flush_with_timeout(timeout);
    }

    void AsyncLogger::flush() noexcept
    {
        m_impl->flush();
    }

    void AsyncLogger::shutdown() noexcept
    {
        m_impl->shutdown();
    }

    bool AsyncLogger::is_running() const noexcept
    {
        return m_impl->is_running();
    }

    bool AsyncLogger::is_writer_waiting() const noexcept
    {
        return m_impl->is_writer_waiting();
    }

    size_t AsyncLogger::queue_size() const noexcept
    {
        return m_impl->queue_size();
    }

    size_t AsyncLogger::dropped_count() const noexcept
    {
        return m_impl->dropped_count();
    }

    void AsyncLogger::reset_dropped_count() noexcept
    {
        m_impl->reset_dropped_count();
    }

} // namespace DetourModKit
