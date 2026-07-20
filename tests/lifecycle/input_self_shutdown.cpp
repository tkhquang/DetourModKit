// Fresh-process proofs for Input::shutdown() reached from a binding callback. The poll thread is its own teardown
// thread there, so an inline join would raise std::system_error out of a noexcept function and terminate the host.
// Exit status is the oracle: a regression terminates the process rather than failing an assertion.

#include "DetourModKit/input.hpp"
#include "internal/input_poller.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string_view>
#include <thread>

namespace
{
    using DetourModKit::input::ComboBinding;
    using DetourModKit::input::Input;
    using DetourModKit::input::KeyComboList;
    using DetourModKit::input::Trigger;

    using DetourModKit::keyboard_key;

    constexpr int HELD_VK = 0x41;
    constexpr auto DEADLINE = std::chrono::seconds{15};

    // A console proof never owns the foreground window, so the focus gate would suppress every key event.
    constexpr Input::Settings START_SETTINGS{.poll_interval = std::chrono::milliseconds{1}, .require_focus = false};

    template <typename Predicate> [[nodiscard]] bool wait_until(Predicate predicate)
    {
        const auto deadline = std::chrono::steady_clock::now() + DEADLINE;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (predicate())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return false;
    }

    // Captured by value into the callback. Its liveness is read after shutdown() returns, so a rundown that destroyed
    // the callback's owner from inside the body would be caught as a torn payload rather than as a silent crash.
    struct CapturedOwner
    {
        static constexpr std::uint32_t LIVE = 0xD11CE5EDu;
        std::uint32_t marker{LIVE};
    };

    int run_self_shutdown_case()
    {
        std::atomic<std::thread::id> hold_thread{};
        std::atomic<std::thread::id> release_thread{};
        std::atomic<bool> shutdown_returned{false};
        std::atomic<bool> capture_survived{false};
        std::atomic<bool> released{false};

        DetourModKit::detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

        auto owner = std::make_shared<CapturedOwner>();
        KeyComboList combos;
        combos.push_back({{keyboard_key(HELD_VK)}, {}});

        auto registration = Input::instance().register_combo(ComboBinding{
            .name = "self-shutdown",
            .trigger = Trigger::Hold,
            .combos = combos,
            .on_state_change = [owner, &hold_thread, &release_thread, &shutdown_returned, &capture_survived,
                                &released](bool active) noexcept
            {
                if (active)
                {
                    hold_thread.store(std::this_thread::get_id(), std::memory_order_release);
                    // The call under proof. A self-join here terminates the process.
                    Input::instance().shutdown();
                    // The captured owner must still be intact after the deferred rundown was requested. Publish this
                    // before the flag the main thread waits on, so its acquire load cannot read a not-yet-written
                    // verdict and fail the case spuriously.
                    capture_survived.store(owner->marker == CapturedOwner::LIVE, std::memory_order_release);
                    shutdown_returned.store(true, std::memory_order_release);
                    return;
                }
                release_thread.store(std::this_thread::get_id(), std::memory_order_release);
                released.store(true, std::memory_order_release);
            }});

        if (!registration)
        {
            std::fprintf(stderr, "FAIL: could not register the self-shutdown binding\n");
            return 2;
        }
        if (!Input::instance().start(START_SETTINGS))
        {
            std::fprintf(stderr, "FAIL: could not start the input engine\n");
            return 3;
        }

        if (!wait_until([&] { return shutdown_returned.load(std::memory_order_acquire); }))
        {
            std::fprintf(stderr, "FAIL: callback-reached shutdown() never returned\n");
            return 4;
        }
        if (!capture_survived.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: the callback's captured owner did not survive shutdown()\n");
            return 5;
        }
        if (Input::instance().is_running())
        {
            std::fprintf(stderr, "FAIL: is_running() stayed true after a callback-reached shutdown()\n");
            return 6;
        }

        // The balancing release is the rundown's own work, so observing it proves the deferred completion ran -- and
        // the thread it ran on proves it was not the poll thread that requested it.
        if (!wait_until([&] { return released.load(std::memory_order_acquire); }))
        {
            std::fprintf(stderr, "FAIL: the deferred rundown never delivered the balancing release\n");
            return 7;
        }
        if (release_thread.load(std::memory_order_acquire) == hold_thread.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: the rundown ran on the poll thread that requested it\n");
            return 8;
        }
        if (release_thread.load(std::memory_order_acquire) == std::this_thread::get_id())
        {
            std::fprintf(stderr, "FAIL: the rundown ran on the requesting caller's thread\n");
            return 9;
        }

        DetourModKit::detail::g_input_key_state_probe = nullptr;
        return 0;
    }

    // A registration racing the callback-reached shutdown must be answered, not deadlocked: the facade lock is
    // released before the poller rundown is requested, and an inert-or-retired engine still stages the binding.
    int run_registration_race_case()
    {
        std::atomic<bool> shutdown_requested{false};
        std::atomic<bool> registrations_done{false};
        std::atomic<bool> rundown_done{false};

        DetourModKit::detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

        KeyComboList combos;
        combos.push_back({{keyboard_key(HELD_VK)}, {}});

        auto registration = Input::instance().register_combo(
            ComboBinding{.name = "race-shutdown",
                         .trigger = Trigger::Hold,
                         .combos = combos,
                         .on_state_change = [&shutdown_requested, &rundown_done](bool active) noexcept
                         {
                             if (active)
                             {
                                 if (!shutdown_requested.exchange(true, std::memory_order_acq_rel))
                                 {
                                     Input::instance().shutdown();
                                 }
                                 return;
                             }
                             rundown_done.store(true, std::memory_order_release);
                         }});
        if (!registration || !Input::instance().start(START_SETTINGS))
        {
            std::fprintf(stderr, "FAIL: could not arm the registration race\n");
            return 10;
        }

        std::thread registrar(
            [&registrations_done]() noexcept
            {
                for (int i = 0; i < 200; ++i)
                {
                    KeyComboList extra;
                    extra.push_back({{keyboard_key(0x42)}, {}});
                    auto guard = Input::instance().register_combo(
                        ComboBinding{.name = "racer", .trigger = Trigger::Press, .combos = extra});
                    (void)guard;
                    (void)Input::instance().binding_count();
                    (void)Input::instance().is_active("racer");
                }
                registrations_done.store(true, std::memory_order_release);
            });

        const bool completed = wait_until([&] { return registrations_done.load(std::memory_order_acquire); }) &&
                               wait_until([&] { return shutdown_requested.load(std::memory_order_acquire); });
        registrar.join();
        if (!completed)
        {
            std::fprintf(stderr, "FAIL: registration racing a callback-reached shutdown did not complete\n");
            return 11;
        }

        // The balancing release is delivered by the deferred rundown, so it is the only observable proving the poll
        // thread has been joined. Clearing the key-state probe before that would destroy a callable the loop can
        // still be calling.
        if (!wait_until([&] { return rundown_done.load(std::memory_order_acquire); }))
        {
            std::fprintf(stderr, "FAIL: the deferred rundown never completed after the racing registrations\n");
            return 16;
        }
        DetourModKit::detail::g_input_key_state_probe = nullptr;
        return 0;
    }

    // Successful control: an ordinary external shutdown still runs the whole rundown synchronously on the caller.
    int run_external_shutdown_case()
    {
        std::atomic<std::thread::id> release_thread{};
        std::atomic<bool> held{false};
        std::atomic<bool> released{false};

        DetourModKit::detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

        KeyComboList combos;
        combos.push_back({{keyboard_key(HELD_VK)}, {}});
        auto registration = Input::instance().register_combo(
            ComboBinding{.name = "external-shutdown",
                         .trigger = Trigger::Hold,
                         .combos = combos,
                         .on_state_change = [&](bool active) noexcept
                         {
                             if (active)
                             {
                                 held.store(true, std::memory_order_release);
                                 return;
                             }
                             release_thread.store(std::this_thread::get_id(), std::memory_order_release);
                             released.store(true, std::memory_order_release);
                         }});
        if (!registration || !Input::instance().start(START_SETTINGS))
        {
            std::fprintf(stderr, "FAIL: could not start the external-shutdown control\n");
            return 12;
        }
        if (!wait_until([&] { return held.load(std::memory_order_acquire); }))
        {
            std::fprintf(stderr, "FAIL: the control binding never went held\n");
            return 13;
        }

        Input::instance().shutdown();

        if (!released.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: external shutdown() returned before the balancing release\n");
            return 14;
        }
        if (release_thread.load(std::memory_order_acquire) != std::this_thread::get_id())
        {
            std::fprintf(stderr, "FAIL: external shutdown() did not run the rundown on the caller\n");
            return 15;
        }

        DetourModKit::detail::g_input_key_state_probe = nullptr;
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: input_self_shutdown <self-shutdown|registration-race|external-shutdown>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == "self-shutdown")
        return run_self_shutdown_case();
    if (selected_case == "registration-race")
        return run_registration_race_case();
    if (selected_case == "external-shutdown")
        return run_external_shutdown_case();

    std::fprintf(stderr, "unknown input self-shutdown case\n");
    return 1;
}
