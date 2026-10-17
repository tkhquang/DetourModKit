#ifndef DETOURMODKIT_TESTS_FIXTURES_THREAD_LOAD_HPP
#define DETOURMODKIT_TESTS_FIXTURES_THREAD_LOAD_HPP

/**
 * @file thread_load.hpp
 * @brief Waiting and spinning threads that load the idle proof of the hook backend.
 * @details test_hook_backend.cpp and bench_hook.cpp share them.
 */

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <stop_token>
#include <thread>
#include <vector>

namespace dmk_test
{
    /// The bound of every wait in this header, so a failed premise cannot wedge the process.
    inline constexpr std::chrono::seconds THREAD_LOAD_BOUND{10};

    /// Threads that wait on one event until the destructor sets it and joins them.
    class ParkedThreads
    {
    public:
        explicit ParkedThreads(std::size_t count) : m_release(CreateEventW(nullptr, TRUE, FALSE, nullptr))
        {
            if (m_release == nullptr)
            {
                return;
            }
            m_threads.reserve(count);
            for (std::size_t i = 0; i < count; ++i)
            {
                m_threads.emplace_back(
                    [this]
                    {
                        m_started.fetch_add(1, std::memory_order_acq_rel);
                        (void)WaitForSingleObject(m_release, static_cast<DWORD>(THREAD_LOAD_BOUND.count() * 1000));
                    }
                );
            }
        }

        ~ParkedThreads() noexcept
        {
            if (m_release != nullptr)
            {
                (void)SetEvent(m_release);
            }
            m_threads.clear();
            if (m_release != nullptr)
            {
                (void)CloseHandle(m_release);
            }
        }

        ParkedThreads(const ParkedThreads &) = delete;
        ParkedThreads &operator=(const ParkedThreads &) = delete;
        ParkedThreads(ParkedThreads &&) = delete;
        ParkedThreads &operator=(ParkedThreads &&) = delete;

        /// Waits up to @ref THREAD_LOAD_BOUND until @p count threads started, and reports whether they did.
        [[nodiscard]] bool wait_until_started(std::size_t count) const noexcept
        {
            const auto deadline = std::chrono::steady_clock::now() + THREAD_LOAD_BOUND;
            while (m_started.load(std::memory_order_acquire) < count && std::chrono::steady_clock::now() < deadline)
            {
                Sleep(1);
            }
            return m_started.load(std::memory_order_acquire) == count;
        }

    private:
        HANDLE m_release{nullptr};
        std::atomic<std::size_t> m_started{0};
        std::vector<std::jthread> m_threads;
    };

    /// Threads that spin in user mode until the destructor stops and joins them.
    class SpinningThreads
    {
    public:
        explicit SpinningThreads(std::size_t count)
        {
            m_threads.reserve(count);
            for (std::size_t i = 0; i < count; ++i)
            {
                m_threads.emplace_back(
                    [this](const std::stop_token &stop)
                    {
                        m_started.fetch_add(1, std::memory_order_acq_rel);
                        while (!stop.stop_requested())
                        {
                            YieldProcessor();
                        }
                    }
                );
            }
        }

        /// Waits up to @ref THREAD_LOAD_BOUND until @p count threads spin, and reports whether they do.
        [[nodiscard]] bool wait_until_started(std::size_t count) const noexcept
        {
            const auto deadline = std::chrono::steady_clock::now() + THREAD_LOAD_BOUND;
            while (m_started.load(std::memory_order_acquire) < count && std::chrono::steady_clock::now() < deadline)
            {
                Sleep(1);
            }
            return m_started.load(std::memory_order_acquire) == count;
        }

    private:
        std::atomic<std::size_t> m_started{0};
        // Declared last, so each thread stops and joins before the counter goes away.
        std::vector<std::jthread> m_threads;
    };
} // namespace dmk_test

#endif // DETOURMODKIT_TESTS_FIXTURES_THREAD_LOAD_HPP
