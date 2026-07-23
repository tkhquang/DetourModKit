// Fresh-process proofs for the Input::instance() accessor. The OOM scenarios require one complete inert singleton to
// be published without termination or retry; the successful control requires an ordinary live engine. Exit status is
// the oracle so first-use termination cannot be hidden by a test framework.

#include "DetourModKit/input.hpp"

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
    // When set, every plain operator new throws, forcing first-use construction of the Input Impl to fail.
    // Constant-init so it is ready before any allocation runs; the driver arms it only around the first instance()
    // call.
    std::atomic<bool> g_poison{false};
} // namespace

// Plain (non-aligned) global replacements, matching the logger first-use proof: the Impl and its members allocate
// through these forms, so intercepting them is enough to force the failure.
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
    using DetourModKit::keyboard_key;
    using DetourModKit::input::ComboBinding;
    using DetourModKit::input::Input;
    using DetourModKit::input::KeyComboList;
    using DetourModKit::input::Trigger;

    [[nodiscard]] KeyComboList single_key(int vk)
    {
        KeyComboList combos;
        combos.push_back({{keyboard_key(vk)}, {}});
        return combos;
    }

    // Every public operation an inert singleton must answer safely. Returns 0 when all of them fail closed.
    [[nodiscard]] int check_inert_surface(Input &input)
    {
        if (input.is_running())
        {
            std::fprintf(stderr, "FAIL: inert Input reported running\n");
            return 20;
        }
        if (input.binding_count() != 0)
        {
            std::fprintf(stderr, "FAIL: inert Input reported registered bindings\n");
            return 21;
        }

        auto registration =
            input.register_combo(ComboBinding{.name = "inert", .trigger = Trigger::Press, .combos = single_key(0x41)});
        if (registration)
        {
            std::fprintf(stderr, "FAIL: inert Input accepted a registration\n");
            return 22;
        }
        if (registration.error().code != DetourModKit::ErrorCode::OutOfMemory)
        {
            std::fprintf(stderr, "FAIL: inert Input rejected a registration with the wrong code\n");
            return 23;
        }
        if (input.start())
        {
            std::fprintf(stderr, "FAIL: inert Input reported a successful start\n");
            return 24;
        }
        if (input.rebind("inert", single_key(0x42)))
        {
            std::fprintf(stderr, "FAIL: inert Input reported a successful rebind\n");
            return 25;
        }
        if (input.is_active("inert") || input.acquire_token("inert").valid() ||
            input.token_current(input.acquire_token("inert")))
        {
            std::fprintf(stderr, "FAIL: inert Input reported an active or current binding\n");
            return 26;
        }
        if (input.remove_bindings_by_name("inert") != 0)
        {
            std::fprintf(stderr, "FAIL: inert Input reported removing a binding\n");
            return 27;
        }

        // Mutators and teardown must be safe no-ops rather than null dereferences.
        input.set_consume("inert", true);
        input.set_require_focus(false);
        input.clear_bindings();
        input.shutdown();
        return 0;
    }

    int run_oom_case()
    {
        g_poison.store(true, std::memory_order_release);
        Input &input = Input::instance();
        g_poison.store(false, std::memory_order_release);

        return check_inert_surface(input);
    }

    int run_concurrent_oom_case()
    {
        constexpr std::size_t THREAD_COUNT = 4;
        std::array<std::thread, THREAD_COUNT> threads;
        std::array<Input *, THREAD_COUNT> instances{};
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
                    Input &input = Input::instance();
                    instances[i] = &input;
                    (void)input.is_running();
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

        Input *const instance = instances.front();
        if (instance == nullptr)
        {
            std::fprintf(stderr, "FAIL: concurrent first use returned no Input\n");
            return 3;
        }
        for (const Input *candidate : instances)
        {
            if (candidate != instance)
            {
                std::fprintf(stderr, "FAIL: concurrent first use published multiple Input instances\n");
                return 4;
            }
        }
        return check_inert_surface(*instance);
    }

    int run_success_case()
    {
        Input &input = Input::instance();

        auto registration =
            input.register_combo(ComboBinding{.name = "live", .trigger = Trigger::Press, .combos = single_key(0x41)});
        if (!registration)
        {
            std::fprintf(stderr, "FAIL: successful first use rejected a registration\n");
            return 6;
        }
        if (input.binding_count() != 1)
        {
            std::fprintf(stderr, "FAIL: successful first use did not stage the binding\n");
            return 7;
        }
        if (!input.start())
        {
            std::fprintf(stderr, "FAIL: successful first use could not start the engine\n");
            return 8;
        }
        if (!input.is_running())
        {
            std::fprintf(stderr, "FAIL: successful first use did not publish a running engine\n");
            return 9;
        }
        input.shutdown();
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: input_first_use_oom <oom|concurrent-oom|success>\n");
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

    std::fprintf(stderr, "unknown input first-use case\n");
    return 1;
}
