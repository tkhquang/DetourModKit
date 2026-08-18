// Fresh-process proof that the async writer keeps draining when its batch reservation can never succeed.
//
// The writer reserves headroom for a whole batch before popping. If that reservation fails it pops nothing, and a
// zero-progress pop over a non-empty queue used to skip both idle gates, spin at 100% CPU, and never let the loop
// condition go false, so shutdown()'s join() blocked forever. The failure mode is a hang, not a wrong value, so the
// ctest timeout is this proof's oracle: without the one-record floor the process never reaches its success marker.
//
// The poison remains armed from before the writer's first successful pop through shutdown. That ordering is the whole
// test: std::vector keeps its capacity across the writer's clear(), so a batch that reserved once never reserves again
// and the failure would be unreachable afterwards.

#include "internal/async_logger.hpp"
#include "internal/win_file_stream.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <malloc.h>
#include <memory>
#include <mutex>
#include <new>
#include <process.h>
#include <string>
#include <string_view>

namespace
{
    // Every allocation at or above this size fails once the poison is armed. The writer's batch reservation is
    // BATCH_RECORDS * sizeof(LogMessage), which is hundreds of kilobytes, while nothing else this process does after
    // arming comes close: the queue and the sink are already allocated by then. Selecting by size rather than by
    // thread keeps the replacement free of thread-local storage, which on MinGW is emulated and allocates on first
    // touch, which would recurse straight back into this hook.
    constexpr std::size_t POISON_MIN_BYTES = 64u * 1024u;

    // Constant-initialized so it is ready before any allocation runs.
    std::atomic<bool> g_poison{false};
    std::atomic<std::size_t> g_refused{0};
} // namespace

void *operator new(std::size_t size)
{
    if (size >= POISON_MIN_BYTES && g_poison.load(std::memory_order_acquire))
    {
        g_refused.fetch_add(1, std::memory_order_relaxed);
        throw std::bad_alloc{};
    }
    if (void *p = std::malloc(size != 0 ? size : 1))
    {
        return p;
    }
    throw std::bad_alloc{};
}

void *operator new[](std::size_t size)
{
    return ::operator new(size);
}

void *operator new(std::size_t size, const std::nothrow_t &) noexcept
{
    if (size >= POISON_MIN_BYTES && g_poison.load(std::memory_order_acquire))
    {
        g_refused.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    return std::malloc(size != 0 ? size : 1);
}

void *operator new[](std::size_t size, const std::nothrow_t &tag) noexcept
{
    return ::operator new(size, tag);
}

// GCC's allocation-pairing analysis loses track of a REPLACED operator new once it inlines it into a standard-library
// allocation helper (here make_shared's __new_allocator::allocate) and then reports the matching replaced operator
// delete as freeing a "mismatched" pointer. Both sides are these replacements, so the pairing is correct. The
// suppression is scoped to the plain family alone: the over-aligned family below stays checked, so a genuine
// free()-over-_aligned_malloc() mistake would still be caught.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif

void operator delete(void *p) noexcept
{
    std::free(p);
}

void operator delete[](void *p) noexcept
{
    std::free(p);
}

void operator delete(void *p, std::size_t) noexcept
{
    std::free(p);
}

void operator delete[](void *p, std::size_t) noexcept
{
    std::free(p);
}

void operator delete(void *p, const std::nothrow_t &) noexcept
{
    std::free(p);
}

void operator delete[](void *p, const std::nothrow_t &) noexcept
{
    std::free(p);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

// The over-aligned family is backed by _aligned_malloc / _aligned_free, because a block from _aligned_malloc must be
// released through _aligned_free, and it must be replaced rather than left at its default: the logger's string pool
// grows through the NOTHROW ALIGNED operator new, so leaving that family alone would both serve an allocation this
// proof means to refuse and mix two allocation regimes in one process.

void *operator new(std::size_t size, std::align_val_t alignment)
{
    if (size >= POISON_MIN_BYTES && g_poison.load(std::memory_order_acquire))
    {
        g_refused.fetch_add(1, std::memory_order_relaxed);
        throw std::bad_alloc{};
    }
    if (void *p = ::_aligned_malloc(size != 0 ? size : 1, static_cast<std::size_t>(alignment)))
    {
        return p;
    }
    throw std::bad_alloc{};
}

void *operator new[](std::size_t size, std::align_val_t alignment)
{
    return ::operator new(size, alignment);
}

void *operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept
{
    if (size >= POISON_MIN_BYTES && g_poison.load(std::memory_order_acquire))
    {
        g_refused.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    return ::_aligned_malloc(size != 0 ? size : 1, static_cast<std::size_t>(alignment));
}

void *operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t &tag) noexcept
{
    return ::operator new(size, alignment, tag);
}

void operator delete(void *p, std::align_val_t) noexcept
{
    ::_aligned_free(p);
}

void operator delete[](void *p, std::align_val_t) noexcept
{
    ::_aligned_free(p);
}

void operator delete(void *p, std::size_t, std::align_val_t) noexcept
{
    ::_aligned_free(p);
}

void operator delete[](void *p, std::size_t, std::align_val_t) noexcept
{
    ::_aligned_free(p);
}

void operator delete(void *p, std::align_val_t, const std::nothrow_t &) noexcept
{
    ::_aligned_free(p);
}

void operator delete[](void *p, std::align_val_t, const std::nothrow_t &) noexcept
{
    ::_aligned_free(p);
}

namespace DetourModKit::detail
{
    // Defined in the archive whenever tests are built, which is the only configuration these hosts exist in. Counts
    // records drained through the writer's one-record progress floor, which is what separates "the writer survived a
    // refused reservation" from "the reservation was never refused in the first place".
    extern std::atomic<std::atomic<std::size_t> *> g_async_logger_batch_floor_counter;
} // namespace DetourModKit::detail

namespace
{
    using DetourModKit::AsyncLogger;
    using DetourModKit::AsyncLoggerConfig;
    using DetourModKit::LogLevel;
    using DetourModKit::detail::WinFileStream;

    /// Publishes a floor counter for the writer to update, and always retracts it.
    class FloorCounterScope
    {
    public:
        explicit FloorCounterScope(std::atomic<std::size_t> &counter) noexcept
        {
            DetourModKit::detail::g_async_logger_batch_floor_counter.store(&counter, std::memory_order_release);
        }
        ~FloorCounterScope() noexcept
        {
            DetourModKit::detail::g_async_logger_batch_floor_counter.store(nullptr, std::memory_order_release);
        }
        FloorCounterScope(const FloorCounterScope &) = delete;
        FloorCounterScope &operator=(const FloorCounterScope &) = delete;
        FloorCounterScope(FloorCounterScope &&) = delete;
        FloorCounterScope &operator=(FloorCounterScope &&) = delete;
    };

    constexpr std::string_view PERSISTENT_CASE{"persistent-batch-oom"};
    constexpr std::string_view OVERSIZE_BATCH_CASE{"oversize-batch"};

    // Large enough that the batch reservation clears POISON_MIN_BYTES by a wide margin.
    constexpr std::size_t QUEUE_RECORDS = 1024;
    constexpr std::size_t MESSAGE_COUNT = 200;

    std::filesystem::path scratch_log_path(const char *tag)
    {
        return std::filesystem::temp_directory_path() /
               ("dmk_logger_writer_batch_oom_" + std::string(tag) + "_" + std::to_string(::_getpid()) + ".log");
    }

    std::string_view message_payload(const std::string &line) noexcept
    {
        constexpr std::string_view MESSAGE_SEPARATOR{":: "};
        const std::size_t separator = line.rfind(MESSAGE_SEPARATOR);
        return separator == std::string::npos ? std::string_view{}
                                              : std::string_view{line}.substr(separator + MESSAGE_SEPARATOR.size());
    }

    bool sink_has_exact_indexed_messages(const std::filesystem::path &path, std::string_view prefix, std::size_t count)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
        {
            return false;
        }

        std::string line;
        for (std::size_t i = 0; i < count; ++i)
        {
            if (!std::getline(file, line))
            {
                return false;
            }
            const std::string expected = std::string(prefix) + "_" + std::to_string(i);
            if (message_payload(line) != expected)
            {
                return false;
            }
        }
        return !std::getline(file, line);
    }

    bool sink_has_exact_message(const std::filesystem::path &path, std::string_view expected)
    {
        std::ifstream file(path, std::ios::binary);
        std::string line;
        return file.is_open() && std::getline(file, line) && message_payload(line) == expected &&
               !std::getline(file, line);
    }

    int run_persistent_case()
    {
        const std::filesystem::path log_path = scratch_log_path("persistent");
        std::atomic<std::size_t> floor_drains{0};
        const FloorCounterScope floor_scope{floor_drains};
        int result = 0;
        {
            AsyncLoggerConfig config;
            config.queue_capacity = QUEUE_RECORDS;
            config.batch_size = QUEUE_RECORDS;
            config.flush_interval = std::chrono::milliseconds{10};

            auto file_stream = std::make_shared<WinFileStream>(log_path.string());
            auto log_mutex = std::make_shared<std::mutex>();
            auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
            if (!logger->is_running())
            {
                std::fprintf(stderr, "FAIL[persistent-batch-oom]: writer did not start\n");
                return 2;
            }

            // Arm before the first record exists, so the writer's batch vector never gets a successful reservation.
            g_poison.store(true, std::memory_order_release);

            for (std::size_t i = 0; i < MESSAGE_COUNT; ++i)
            {
                std::array<char, 64> message{};
                const int length = std::snprintf(message.data(), message.size(), "persistent_batch_oom_record_%zu", i);
                if (length <= 0 || static_cast<std::size_t>(length) >= message.size() ||
                    !logger->enqueue(LogLevel::Info,
                                     std::string_view{message.data(), static_cast<std::size_t>(length)}))
                {
                    std::fprintf(stderr, "FAIL[persistent-batch-oom]: enqueue %zu was refused\n", i);
                    result = 12;
                    break;
                }
            }

            // The hang this proves against happens here: shutdown() joins the writer unconditionally.
            logger->shutdown();

            if (result == 0 && logger->is_running())
            {
                std::fprintf(stderr, "FAIL[persistent-batch-oom]: writer still running after shutdown\n");
                result = 3;
            }
            else if (result == 0 && logger->dropped_count() != 0)
            {
                std::fprintf(stderr, "FAIL[persistent-batch-oom]: dropped %zu record(s) under allocation failure\n",
                             logger->dropped_count());
                result = 4;
            }
        }
        g_poison.store(false, std::memory_order_release);

        if (result == 0 && g_refused.load(std::memory_order_relaxed) == 0)
        {
            std::fprintf(stderr, "FAIL[persistent-batch-oom]: the poison never refused an allocation, so the writer "
                                 "never reached the zero-progress path\n");
            result = 5;
        }
        if (result == 0 && floor_drains.load(std::memory_order_relaxed) != MESSAGE_COUNT)
        {
            // Without this the case could pass vacuously: if the reservation ever succeeded, the ordinary batch path
            // would drain everything and the floor would never be exercised.
            std::fprintf(stderr,
                         "FAIL[persistent-batch-oom]: %zu of %zu records went through the one-record floor; the "
                         "reservation was not refused for the whole run\n",
                         floor_drains.load(std::memory_order_relaxed), MESSAGE_COUNT);
            result = 10;
        }
        if (result == 0)
        {
            if (!sink_has_exact_indexed_messages(log_path, "persistent_batch_oom_record", MESSAGE_COUNT))
            {
                std::fprintf(stderr,
                             "FAIL[persistent-batch-oom]: sink payloads do not exactly match the %zu queued records\n",
                             MESSAGE_COUNT);
                result = 6;
            }
        }

        std::error_code ignored;
        (void)std::filesystem::remove(log_path, ignored);
        if (result == 0)
        {
            std::printf("PASS[persistent-batch-oom]: drained %zu records and joined the writer with every batch "
                        "reservation refused (%zu refusals)\n",
                        MESSAGE_COUNT, g_refused.load(std::memory_order_relaxed));
        }
        return result;
    }

    // A batch_size past what the queue can ever hold makes every reservation throw length_error with no memory
    // pressure at all. The progress floor keeps that configuration LIVE either way, so liveness alone cannot
    // distinguish the clamp; what the clamp buys is that the writer keeps batching instead of degrading to one record
    // per cycle with a thrown exception behind each one. The floor counter is that distinction: clamped, the
    // reservation succeeds and the floor is never reached.
    int run_oversize_batch_case()
    {
        const std::filesystem::path log_path = scratch_log_path("oversize");
        std::atomic<std::size_t> floor_drains{0};
        const FloorCounterScope floor_scope{floor_drains};
        int result = 0;
        {
            AsyncLoggerConfig config;
            config.queue_capacity = 2;
            config.batch_size = static_cast<std::size_t>(-1);
            config.flush_interval = std::chrono::milliseconds{10};

            auto file_stream = std::make_shared<WinFileStream>(log_path.string());
            auto log_mutex = std::make_shared<std::mutex>();
            auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
            if (!logger->is_running())
            {
                std::fprintf(stderr, "FAIL[oversize-batch]: writer did not start\n");
                return 7;
            }

            (void)logger->enqueue(LogLevel::Info, "oversize_batch_record");
            logger->shutdown();
            if (logger->is_running())
            {
                std::fprintf(stderr, "FAIL[oversize-batch]: writer still running after shutdown\n");
                result = 8;
            }
        }

        if (result == 0 && !sink_has_exact_message(log_path, "oversize_batch_record"))
        {
            std::fprintf(stderr, "FAIL[oversize-batch]: sink payload does not exactly match the queued record\n");
            result = 9;
        }
        if (result == 0 && floor_drains.load(std::memory_order_relaxed) != 0)
        {
            std::fprintf(stderr,
                         "FAIL[oversize-batch]: %zu record(s) fell back to the one-record floor, so the oversize "
                         "batch_size was not clamped to the queue capacity\n",
                         floor_drains.load(std::memory_order_relaxed));
            result = 11;
        }

        std::error_code ignored;
        (void)std::filesystem::remove(log_path, ignored);
        if (result == 0)
        {
            std::printf("PASS[oversize-batch]: an unbounded batch_size was clamped, drained through the batch path, "
                        "and joined\n");
        }
        return result;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: logger_writer_batch_oom <persistent-batch-oom|oversize-batch>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == PERSISTENT_CASE)
    {
        return run_persistent_case();
    }
    if (selected_case == OVERSIZE_BATCH_CASE)
    {
        return run_oversize_batch_case();
    }

    std::fprintf(stderr, "unknown logger writer-batch case\n");
    return 1;
}
