// Fresh-process proofs for Input::shutdown() reached from a binding callback. The poll thread is its own teardown
// thread there, so an inline join would raise std::system_error out of a noexcept function and terminate the host.
// Exit status is the oracle: a regression terminates the process rather than failing an assertion.

#include "DetourModKit/input.hpp"
#include "input_seam_cleanup.hpp"
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

    // Long enough that a rundown clearing its seams before it joins will have done so by the time the callback looks,
    // and irrelevant to a correct one, which cannot clear until that same callback returns.
    constexpr auto SEAM_ORDER_WINDOW = std::chrono::milliseconds{50};

    // A console proof never owns the foreground window, so the focus gate would suppress every key event.
    constexpr Input::Settings START_SETTINGS{
        .poll_interval = std::chrono::milliseconds{1},
        .require_focus = false,
    };

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
            .on_state_change =
                [owner, &hold_thread, &release_thread, &shutdown_returned, &capture_survived,
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
            },
        });

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

        // Declared after everything the callback captured, so every failure exit below joins the poll thread and the
        // deferred rundown while that state is still alive, then clears the probe. The balancing release is the only
        // signal that the reaper finished: shutdown() reached from the callback returns before it has been delivered.
        const dmk_lifecycle::InputSeamOwner cleanup{{},
                                                    [&]
                                                    {
                                                        return released.load(std::memory_order_acquire) ||
                                                               hold_thread.load(std::memory_order_acquire) ==
                                                                   std::thread::id{};
                                                    }};

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

        // The balancing release is the rundown's own work, so observing it proves the deferred completion ran, and
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

        auto registration = Input::instance().register_combo(ComboBinding{
            .name = "race-shutdown",
            .trigger = Trigger::Hold,
            .combos = combos,
            .on_state_change =
                [&shutdown_requested, &rundown_done](bool active) noexcept
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
            },
        });
        if (!registration || !Input::instance().start(START_SETTINGS))
        {
            std::fprintf(stderr, "FAIL: could not arm the registration race\n");
            return 10;
        }

        // shutdown_requested is set before the callback calls shutdown(), so once it is true a rundown may be in the
        // reaper's hands and only rundown_done proves it is over.
        const dmk_lifecycle::InputSeamOwner cleanup{{},
                                                    [&]
                                                    {
                                                        return rundown_done.load(std::memory_order_acquire) ||
                                                               !shutdown_requested.load(std::memory_order_acquire);
                                                    }};

        std::thread registrar(
            [&registrations_done]() noexcept
            {
                for (int i = 0; i < 200; ++i)
                {
                    KeyComboList extra;
                    extra.push_back({{keyboard_key(0x42)}, {}});
                    auto guard = Input::instance().register_combo(ComboBinding{
                        .name = "racer",
                        .trigger = Trigger::Press,
                        .combos = extra,
                    });
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
        auto registration = Input::instance().register_combo(ComboBinding{
            .name = "external-shutdown",
            .trigger = Trigger::Hold,
            .combos = combos,
            .on_state_change =
                [&](bool active) noexcept
            {
                if (active)
                {
                    held.store(true, std::memory_order_release);
                    return;
                }
                release_thread.store(std::this_thread::get_id(), std::memory_order_release);
                released.store(true, std::memory_order_release);
            },
        });
        if (!registration || !Input::instance().start(START_SETTINGS))
        {
            std::fprintf(stderr, "FAIL: could not start the external-shutdown control\n");
            return 12;
        }

        // No quiescence predicate: this case never reaches shutdown() from a callback, so the rundown is synchronous
        // on whichever thread calls it and the join is complete when the owner returns.
        const dmk_lifecycle::InputSeamOwner cleanup;

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

        return 0;
    }

    // Bounded negative cleanup control. Every case above abandons its premise on a failure exit while the poll thread
    // is live and a callback is parked; this drives exactly that path deliberately and asserts what must be true after
    // it. A rundown that cleared the seam before joining calls a null probe from the loop, one that never unblocked
    // the parked callback hangs, and one that did not run at all leaves the engine started, each a distinct red.
    int run_abandoned_premise_case()
    {
        std::atomic<bool> parked{false};
        std::atomic<bool> proceed{false};
        std::atomic<bool> shutdown_requested{false};
        std::atomic<bool> shutdown_returned{false};
        std::atomic<bool> callback_finished{false};
        std::atomic<bool> rundown_done{false};
        std::atomic<bool> seam_live_in_callback{false};

        DetourModKit::detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };

        KeyComboList combos;
        combos.push_back({{keyboard_key(HELD_VK)}, {}});

        {
            auto registration = Input::instance().register_combo(ComboBinding{
                .name = "abandoned-premise",
                .trigger = Trigger::Hold,
                .combos = combos,
                .on_state_change =
                    [&parked, &proceed, &shutdown_requested, &shutdown_returned, &callback_finished, &rundown_done,
                     &seam_live_in_callback](bool active) noexcept
                {
                    if (!active)
                    {
                        rundown_done.store(true, std::memory_order_release);
                        return;
                    }
                    shutdown_requested.store(true, std::memory_order_release);
                    // This is the distinct path under proof: the facade releases its poller to the reaper and returns
                    // while this callback is still executing. The outer cleanup therefore has no poller it can join.
                    Input::instance().shutdown();
                    shutdown_returned.store(true, std::memory_order_release);
                    parked.store(true, std::memory_order_release);
                    while (!proceed.load(std::memory_order_acquire))
                    {
                        std::this_thread::yield();
                    }
                    // Read the seam from inside the poll thread, after a delay a correct rundown cannot
                    // use: it is blocked joining THIS body, so the probe it owns must still be installed.
                    // A rundown that cleared before joining loses that race and is seen doing it. The
                    // read races the clear on purpose; that race is the defect under proof.
                    std::this_thread::sleep_for(SEAM_ORDER_WINDOW);
                    seam_live_in_callback.store(static_cast<bool>(DetourModKit::detail::g_input_key_state_probe),
                                                std::memory_order_release);
                    callback_finished.store(true, std::memory_order_release);
                },
            });
            if (!registration)
            {
                std::fprintf(stderr, "FAIL: could not register the abandoned-premise binding\n");
                return 17;
            }
            if (!Input::instance().start(START_SETTINGS))
            {
                std::fprintf(stderr, "FAIL: could not start the abandoned-premise engine\n");
                return 18;
            }

            const dmk_lifecycle::InputSeamOwner cleanup{[&] { proceed.store(true, std::memory_order_release); },
                                                        [&]
                                                        {
                                                            return rundown_done.load(std::memory_order_acquire) ||
                                                                   !shutdown_requested.load(std::memory_order_acquire);
                                                        }};

            if (!wait_until(
                    [&]
                    {
                        return parked.load(std::memory_order_acquire) &&
                               shutdown_returned.load(std::memory_order_acquire);
                    }))
            {
                std::fprintf(stderr, "FAIL: callback self-shutdown never returned and parked\n");
                return 19;
            }
            if (Input::instance().is_running())
            {
                std::fprintf(stderr, "FAIL: the callback did not hand its poller to the deferred reaper\n");
                return 24;
            }
            // The premise is abandoned here, exactly as a failed assertion above would abandon it.
        }

        if (!callback_finished.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: the rundown did not release the parked callback\n");
            return 20;
        }
        if (!seam_live_in_callback.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: the seam was cleared while the poll thread was still inside a callback\n");
            return 23;
        }
        if (!rundown_done.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: the deferred reaper did not deliver the balancing release\n");
            return 25;
        }
        if (Input::instance().is_running())
        {
            std::fprintf(stderr, "FAIL: the abandoned premise left the engine running\n");
            return 21;
        }
        if (DetourModKit::detail::g_input_key_state_probe)
        {
            std::fprintf(stderr, "FAIL: the seam outlived the rundown that owns it\n");
            return 22;
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: input_self_shutdown "
                             "<self-shutdown|registration-race|external-shutdown|abandoned-premise>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == "self-shutdown")
        return run_self_shutdown_case();
    if (selected_case == "registration-race")
        return run_registration_race_case();
    if (selected_case == "external-shutdown")
        return run_external_shutdown_case();
    if (selected_case == "abandoned-premise")
        return run_abandoned_premise_case();

    std::fprintf(stderr, "unknown input self-shutdown case\n");
    return 1;
}
