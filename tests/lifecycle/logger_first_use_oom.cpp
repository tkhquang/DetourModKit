// Fresh-process proofs for the process-default log() accessor. The OOM scenarios require one complete inert logger to
// be published without termination or retry; the successful control requires an ordinary live sink. Exit status is
// the oracle so first-use termination cannot be hidden by a test framework.

#include "DetourModKit/logger.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string_view>
#include <thread>

namespace
{
    // When set, every plain operator new throws, forcing the logger's first-use construction to fail. Constant-init so
    // it is ready before any allocation runs; the driver arms it only around the first log() call.
    std::atomic<bool> g_poison{false};
} // namespace

// Plain (non-aligned) global replacements. Aligned new/delete are left alone: the StringPool's aligned block growth is
// not on the first-use path this proof exercises, so intercepting the plain forms is enough to force the failure.
void *operator new(std::size_t size)
{
    if (g_poison.load(std::memory_order_acquire))
    {
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

namespace
{
    constexpr std::string_view OOM_CASE{"oom"};
    constexpr std::string_view CONCURRENT_OOM_CASE{"concurrent-oom"};
    constexpr std::string_view SUCCESS_CASE{"success"};

    int run_oom_case()
    {
        using DetourModKit::LogLevel;

        g_poison.store(true, std::memory_order_release);
        DetourModKit::Logger &logger = DetourModKit::log();
        g_poison.store(false, std::memory_order_release);

        const std::size_t before = logger.dropped_count();
        (void)logger.log(LogLevel::Error, "post_oom_error");
        (void)logger.log(LogLevel::Info, "post_oom_info");
        (void)logger.is_enabled(LogLevel::Info);
        logger.flush();
        logger.shutdown();

        if (logger.dropped_count() < before + 2)
        {
            std::fprintf(stderr, "FAIL: inert first-use logger did not drop and count post-OOM records\n");
            return 2;
        }
        return 0;
    }

    int run_concurrent_oom_case()
    {
        using DetourModKit::Logger;
        using DetourModKit::LogLevel;

        constexpr std::size_t THREAD_COUNT = 4;
        std::array<std::thread, THREAD_COUNT> threads;
        std::array<Logger *, THREAD_COUNT> instances{};
        std::atomic<std::size_t> ready{0};
        std::atomic<std::size_t> completed{0};
        std::atomic<bool> start{false};

        for (std::size_t i = 0; i < THREAD_COUNT; ++i)
        {
            threads[i] = std::thread(
                [i, &instances, &ready, &completed, &start]() noexcept
                {
                    ready.fetch_add(1, std::memory_order_release);
                    while (!start.load(std::memory_order_acquire))
                    {
                        std::this_thread::yield();
                    }
                    Logger &logger = DetourModKit::log();
                    instances[i] = &logger;
                    (void)logger.log(LogLevel::Info, "concurrent_post_oom");
                    completed.fetch_add(1, std::memory_order_release);
                });
        }

        while (ready.load(std::memory_order_acquire) != THREAD_COUNT)
        {
            std::this_thread::yield();
        }
        g_poison.store(true, std::memory_order_release);
        start.store(true, std::memory_order_release);
        while (completed.load(std::memory_order_acquire) != THREAD_COUNT)
        {
            std::this_thread::yield();
        }
        g_poison.store(false, std::memory_order_release);

        for (auto &thread : threads)
        {
            thread.join();
        }

        Logger *const instance = instances.front();
        if (instance == nullptr)
        {
            std::fprintf(stderr, "FAIL: concurrent first use returned no logger\n");
            return 3;
        }
        for (const Logger *candidate : instances)
        {
            if (candidate != instance)
            {
                std::fprintf(stderr, "FAIL: concurrent first use published multiple logger instances\n");
                return 4;
            }
        }
        if (instance->dropped_count() < THREAD_COUNT)
        {
            std::fprintf(stderr, "FAIL: concurrent inert logger did not count every refused record\n");
            return 5;
        }
        instance->shutdown();
        return 0;
    }

    int run_success_case()
    {
        DetourModKit::Logger &logger = DetourModKit::log();
        const std::size_t before = logger.dropped_count();
        if (!logger.log(DetourModKit::LogLevel::Info, "successful_first_use"))
        {
            std::fprintf(stderr, "FAIL: successful first use did not publish a live sink\n");
            return 6;
        }
        logger.flush();
        logger.shutdown();
        if (logger.dropped_count() != before)
        {
            std::fprintf(stderr, "FAIL: successful first use reported a dropped record\n");
            return 7;
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: logger_first_use_oom <oom|concurrent-oom|success>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
#if defined(_MSC_VER) && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL != 0
    // MSVC debug iterators allocate hidden container proxies that derail first-use OOM injection;
    // the release-STL lane proves this contract on MSVC. 77 is the registered SKIP_RETURN_CODE.
    if (selected_case == OOM_CASE || selected_case == CONCURRENT_OOM_CASE)
        return 77;
#endif
    if (selected_case == OOM_CASE)
        return run_oom_case();
    if (selected_case == CONCURRENT_OOM_CASE)
        return run_concurrent_oom_case();
    if (selected_case == SUCCESS_CASE)
        return run_success_case();

    std::fprintf(stderr, "unknown logger first-use case\n");
    return 1;
}
