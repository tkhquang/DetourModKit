/**
 * @file test_input_gate_abba.cpp
 * @brief Bounded process proof for cross-binding Hold teardown.
 * @details Two public remove operations deliver balancing false edges concurrently. Each callback releases the other
 *          binding's guard after both deliveries are in flight. Completion proves that user callbacks do not carry a
 *          gate mutex into the cross-release cycle.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "internal/input_poller.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <thread>
#include <utility>

namespace
{
    using namespace DetourModKit;

    constexpr int ITERATIONS = 200;
    constexpr int KEY_A = 0x41;
    constexpr int KEY_B = 0x42;

    bool wait_for_count(const std::atomic<int> &count, int expected) noexcept
    {
        for (int i = 0; i < 2'000; ++i)
        {
            if (count.load(std::memory_order_acquire) == expected)
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return false;
    }

    input::ComboBinding make_hold_binding(std::string name, int key, std::function<void(bool)> callback)
    {
        return input::ComboBinding{.name = std::move(name),
                                   .trigger = input::Trigger::Hold,
                                   .combos = {{{keyboard_key(key)}, {}}},
                                   .on_state_change = std::move(callback)};
    }
} // namespace

int main()
{
    using namespace DetourModKit;

    input::Input &manager = input::Input::instance();
    manager.shutdown();
    detail::g_input_key_state_probe = [](int key) noexcept { return key == KEY_A || key == KEY_B; };

    for (int iteration = 0; iteration < ITERATIONS; ++iteration)
    {
        input::BindingGuard guard_a;
        input::BindingGuard guard_b;
        std::atomic<int> a_true{0};
        std::atomic<int> a_false{0};
        std::atomic<int> b_true{0};
        std::atomic<int> b_false{0};
        std::atomic<bool> a_in_callback{false};
        std::atomic<bool> b_in_callback{false};

        auto result_a = manager.register_combo(make_hold_binding(
            "abba_a", KEY_A,
            [&](bool active)
            {
                if (active)
                {
                    a_true.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
                a_false.fetch_add(1, std::memory_order_relaxed);
                a_in_callback.store(true, std::memory_order_release);
                while (!b_in_callback.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                guard_b.release();
            }));
        auto result_b = manager.register_combo(make_hold_binding(
            "abba_b", KEY_B,
            [&](bool active)
            {
                if (active)
                {
                    b_true.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
                b_false.fetch_add(1, std::memory_order_relaxed);
                b_in_callback.store(true, std::memory_order_release);
                while (!a_in_callback.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                guard_a.release();
            }));
        if (!result_a || !result_b)
        {
            std::puts("FAIL: registration");
            return 2;
        }
        guard_a = std::move(*result_a);
        guard_b = std::move(*result_b);

        if (!manager.is_running())
        {
            const auto started = manager.start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1},
                                                                       .require_focus = false});
            if (!started)
            {
                std::puts("FAIL: start");
                return 3;
            }
        }
        if (!wait_for_count(a_true, 1) || !wait_for_count(b_true, 1))
        {
            std::printf("FAIL: held edge on iteration %d\n", iteration);
            return 4;
        }

        std::thread remove_a([&] { (void)manager.remove_bindings_by_name("abba_a"); });
        std::thread remove_b([&] { (void)manager.remove_bindings_by_name("abba_b"); });
        remove_a.join();
        remove_b.join();

        if (a_true.load(std::memory_order_relaxed) != 1 || a_false.load(std::memory_order_relaxed) != 1 ||
            b_true.load(std::memory_order_relaxed) != 1 || b_false.load(std::memory_order_relaxed) != 1)
        {
            std::printf("FAIL: unbalanced edges on iteration %d\n", iteration);
            return 5;
        }
    }

    detail::g_input_key_state_probe = nullptr;
    manager.shutdown();
    std::puts("NO_ABBA");
    return 0;
}
