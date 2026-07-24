// Fresh-process proofs for the Profiler::get_instance() accessor. The OOM scenarios require one complete disabled
// profiler to be published without termination or retry; the successful control requires an ordinary live ring. Exit
// status is the oracle so first-use termination cannot be hidden by a test framework.

#include "DetourModKit/profiler.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <string_view>
#include <thread>

namespace
{
    // When set, every global allocation fails, forcing first-use construction of the profiler ring to fail. Constant-
    // init so it is ready before any allocation runs; the driver arms it only around the first get_instance() call.
    std::atomic<bool> s_poison{false};
} // namespace

void *operator new(std::size_t size)
{
    if (s_poison.load(std::memory_order_acquire))
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

// The ring allocates with nothrow array new. Replacing the nothrow forms explicitly keeps the injection independent of
// whether the runtime implements them by forwarding to the throwing form.
void *operator new(std::size_t size, const std::nothrow_t &) noexcept
{
    if (s_poison.load(std::memory_order_acquire))
    {
        return nullptr;
    }
    return std::malloc(size != 0 ? size : 1);
}

void *operator new[](std::size_t size, const std::nothrow_t &tag) noexcept
{
    return ::operator new(size, tag);
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

void operator delete(void *p, const std::nothrow_t &) noexcept
{
    std::free(p);
}

void operator delete[](void *p, const std::nothrow_t &) noexcept
{
    std::free(p);
}

namespace
{
    using DetourModKit::Profiler;

    // Every public operation a disabled profiler must answer safely. Returns 0 when all of them fail closed.
    [[nodiscard]] int check_disabled_surface(Profiler &profiler)
    {
        if (profiler.capacity() != 0)
        {
            std::fprintf(stderr, "FAIL: disabled Profiler reported ring capacity %zu\n", profiler.capacity());
            return 20;
        }
        if (profiler.qpc_frequency() <= 0)
        {
            std::fprintf(stderr, "FAIL: disabled Profiler reported a non-positive QPC frequency\n");
            return 21;
        }

        profiler.record("disabled", 0, 100, 1);
        if (profiler.available_samples() != 0)
        {
            std::fprintf(stderr, "FAIL: disabled Profiler published a sample\n");
            return 22;
        }
        if (profiler.dropped_samples() == 0)
        {
            std::fprintf(stderr, "FAIL: disabled Profiler did not count the dropped record\n");
            return 23;
        }
        if (profiler.export_chrome_json() != "[]")
        {
            std::fprintf(stderr, "FAIL: disabled Profiler exported a non-empty trace\n");
            return 24;
        }

        const std::string output_path =
            "dmk_profiler_disabled_" + std::to_string(static_cast<unsigned long>(::GetCurrentProcessId())) + ".json";
        if (!profiler.export_to_file(output_path))
        {
            std::fprintf(stderr, "FAIL: disabled Profiler could not export its empty trace\n");
            return 25;
        }
        if (std::remove(output_path.c_str()) != 0)
        {
            std::fprintf(stderr, "FAIL: disabled Profiler output could not be removed\n");
            return 26;
        }

        {
            // The RAII path is the one a live host actually takes; it must also fail closed. ScopedProfile is
            // constructed directly because DMK_PROFILE_SCOPE compiles away unless the host defines
            // DMK_ENABLE_PROFILING, which would make this check vacuous.
            const DetourModKit::ScopedProfile scope{"disabled_scope"};
        }
        if (profiler.available_samples() != 0)
        {
            std::fprintf(stderr, "FAIL: disabled Profiler published a scoped sample\n");
            return 27;
        }

        profiler.reset();
        if (profiler.total_samples_recorded() != 0 || profiler.dropped_samples() != 0)
        {
            std::fprintf(stderr, "FAIL: disabled Profiler did not clear its counters on reset\n");
            return 28;
        }
        return 0;
    }

    int run_oom_case()
    {
        s_poison.store(true, std::memory_order_release);
        Profiler &profiler = Profiler::get_instance();
        s_poison.store(false, std::memory_order_release);

        // The failure must latch: a later call cannot resurrect a live ring, and it must not retry construction.
        if (&Profiler::get_instance() != &profiler)
        {
            std::fprintf(stderr, "FAIL: a second call published a different Profiler\n");
            return 10;
        }
        if (Profiler::get_instance().capacity() != 0)
        {
            std::fprintf(stderr, "FAIL: the disabled Profiler was retried into a live one\n");
            return 11;
        }
        return check_disabled_surface(profiler);
    }

    int run_concurrent_oom_case()
    {
        constexpr std::size_t THREAD_COUNT = 4;
        std::array<std::thread, THREAD_COUNT> threads;
        std::array<Profiler *, THREAD_COUNT> instances{};
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
                    Profiler &profiler = Profiler::get_instance();
                    instances[i] = &profiler;
                    (void)profiler.capacity();
                    completed.fetch_add(1, std::memory_order_release);
                });
        }

        while (ready.load(std::memory_order_acquire) != THREAD_COUNT)
        {
            std::this_thread::yield();
        }
        s_poison.store(true, std::memory_order_release);
        start.store(true, std::memory_order_release);
        while (completed.load(std::memory_order_acquire) != THREAD_COUNT)
        {
            std::this_thread::yield();
        }
        s_poison.store(false, std::memory_order_release);

        for (auto &thread : threads)
        {
            thread.join();
        }

        Profiler *const instance = instances.front();
        if (instance == nullptr)
        {
            std::fprintf(stderr, "FAIL: concurrent first use returned no Profiler\n");
            return 3;
        }
        for (const Profiler *candidate : instances)
        {
            if (candidate != instance)
            {
                std::fprintf(stderr, "FAIL: concurrent first use published multiple Profiler instances\n");
                return 4;
            }
        }
        return check_disabled_surface(*instance);
    }

    int run_success_case()
    {
        Profiler &profiler = Profiler::get_instance();
        if (profiler.capacity() != Profiler::DEFAULT_CAPACITY)
        {
            std::fprintf(stderr, "FAIL: successful first use did not publish the full ring\n");
            return 6;
        }

        profiler.record("live", 0, profiler.qpc_frequency() / 1000, 1);
        if (profiler.available_samples() != 1 || profiler.dropped_samples() != 0)
        {
            std::fprintf(stderr, "FAIL: successful first use did not commit the sample\n");
            return 7;
        }
        if (profiler.export_chrome_json().find("\"name\":\"live\"") == std::string::npos)
        {
            std::fprintf(stderr, "FAIL: successful first use did not export the sample\n");
            return 8;
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: profiler_first_use_oom <oom|concurrent-oom|success>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
#if defined(_MSC_VER) && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL != 0
    // MSVC debug iterators allocate hidden container proxies that derail first-use OOM injection;
    // the release-STL lane proves this contract on MSVC. 77 is the registered SKIP_RETURN_CODE.
    if (selected_case == "oom" || selected_case == "concurrent-oom")
        return 77;
#endif
    if (selected_case == "oom")
        return run_oom_case();
    if (selected_case == "concurrent-oom")
        return run_concurrent_oom_case();
    if (selected_case == "success")
        return run_success_case();

    std::fprintf(stderr, "unknown profiler first-use case\n");
    return 1;
}
