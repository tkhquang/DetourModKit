// Fresh-process proofs for Input::shutdown() reached from a hold release that a control-thread rebind delivers. That
// release runs inside the binding's gate delivery on the caller's thread. The poll thread's next hold delivery for the
// rebuilt binding waits for it. A join from inside that release therefore never returns. A watchdog turns the hang into
// exit code 42, so the exit status is the oracle.

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"
#include "input_seam_cleanup.hpp"
#include "internal/input_poller.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>
#include <thread>

namespace
{
    using DetourModKit::input::ComboBinding;
    using DetourModKit::input::Input;
    using DetourModKit::input::KeyCombo;
    using DetourModKit::input::KeyComboList;
    using DetourModKit::input::Trigger;

    using DetourModKit::keyboard_key;

    namespace diagnostics = DetourModKit::diagnostics;

    enum class Mode : std::uint8_t
    {
        ShutdownInRelease,
        ReleaseOnly,
        AbandonedPremise,
    };

    constexpr int HELD_VK = 0x75;
    constexpr int ADDED_VK = 0x76;
    constexpr auto DEADLINE = std::chrono::seconds{15};
    constexpr auto WATCHDOG = std::chrono::seconds{5};
    constexpr auto PREMISE_WAIT = std::chrono::seconds{2};
    // Long enough that a rundown that clears its seams before the parked release returns does so before the read.
    constexpr auto SEAM_ORDER_WINDOW = std::chrono::milliseconds{50};
    constexpr int WATCHDOG_EXIT = 42;

    // A console proof never owns the foreground window, and the focus gate then suppresses every key event.
    constexpr Input::Settings START_SETTINGS{
        .poll_interval = std::chrono::milliseconds{5},
        .require_focus = false,
    };

    // Namespace-scope state, so the seams and the binding callback capture nothing that a failure exit can destroy.
    std::atomic<Mode> g_mode{Mode::ShutdownInRelease};
    std::atomic<bool> g_gate_armed{false};
    std::atomic<bool> g_poll_at_gate{false};
    std::atomic<bool> g_release_poll{false};
    std::atomic<bool> g_premise_missed{false};
    std::atomic<bool> g_shutdown_requested{false};
    std::atomic<bool> g_shutdown_returned{false};
    std::atomic<bool> g_parked{false};
    std::atomic<bool> g_proceed{false};
    std::atomic<bool> g_callback_finished{false};
    std::atomic<bool> g_seam_live_in_callback{false};
    std::atomic<bool> g_done{false};
    std::atomic<int> g_trues{0};
    std::atomic<int> g_falses{0};
    std::atomic<std::thread::id> g_poll_thread{};
    std::atomic<std::thread::id> g_last_false_thread{};

    template <typename Predicate> [[nodiscard]] bool wait_until(Predicate predicate, std::chrono::milliseconds bound)
    {
        const auto deadline = std::chrono::steady_clock::now() + bound;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (predicate())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return predicate();
    }

    // Parks the poll thread before it enters the rebuilt binding's gate delivery. The control-thread release is then
    // the first crossing, and the held edge waits on it.
    void park_before_dispatch() noexcept
    {
        if (!g_gate_armed.exchange(false))
        {
            return;
        }
        g_poll_at_gate.store(true);
        (void)wait_until([] { return g_release_poll.load(); }, DEADLINE);
    }

    void on_state_change(bool active) noexcept
    {
        if (active)
        {
            g_poll_thread.store(std::this_thread::get_id());
            g_trues.fetch_add(1);
            return;
        }
        g_last_false_thread.store(std::this_thread::get_id());
        const int falses = g_falses.fetch_add(1) + 1;
        if (falses != 1)
        {
            return;
        }
        // The first release is the rebind's balancing edge on the control thread.
        if (!wait_until([] { return g_poll_at_gate.load(); }, PREMISE_WAIT))
        {
            g_premise_missed.store(true);
            return;
        }
        g_release_poll.store(true);
        if (g_mode.load() == Mode::ReleaseOnly)
        {
            return;
        }
        // One poll interval and more: the released poll thread now waits for this delivery to finish.
        std::this_thread::sleep_for(std::chrono::milliseconds{30});
        g_shutdown_requested.store(true);
        Input::instance().shutdown();
        g_shutdown_returned.store(true);
        if (g_mode.load() != Mode::AbandonedPremise)
        {
            return;
        }
        g_parked.store(true);
        (void)wait_until([] { return g_proceed.load(); }, DEADLINE);
        // The rundown joins the poll thread, which waits on this delivery. The probe it owns must still be installed.
        std::this_thread::sleep_for(SEAM_ORDER_WINDOW);
        g_seam_live_in_callback.store(static_cast<bool>(DetourModKit::detail::g_input_key_state_probe));
        g_callback_finished.store(true);
    }

    void arm_watchdog()
    {
        std::thread(
            []
            {
                if (!wait_until([] { return g_done.load(); }, WATCHDOG))
                {
                    std::fprintf(stderr, "FAIL: the run did not finish within the watchdog; shutdown() joined\n");
                    std::fflush(stderr);
                    std::_Exit(WATCHDOG_EXIT);
                }
            }
        ).detach();
    }

    [[nodiscard]] bool rebind_to_two_combos()
    {
        const KeyComboList replacement{KeyCombo{{keyboard_key(HELD_VK)}, {}}, KeyCombo{{keyboard_key(ADDED_VK)}, {}}};
        const auto rebound = Input::instance().rebind("control_thread_hold", replacement);
        if (!rebound)
        {
            std::fprintf(stderr, "FAIL: rebind() failed with code %d\n", static_cast<int>(rebound.error().code));
        }
        return rebound.has_value();
    }

    // Abandons the premise while the release is parked after its shutdown() call, as a failed assertion does. The seam
    // owner must release the parked body and wait for the deferred rundown before it clears the seams.
    int run_abandoned_premise()
    {
        {
            // A different combo count rebuilds the entry set and delivers the release on this worker thread.
            std::jthread control_thread([] { (void)rebind_to_two_combos(); });
            const dmk_lifecycle::InputSeamOwner cleanup{
                []
                {
                    g_proceed.store(true);
                    g_release_poll.store(true);
                },
                [] { return g_falses.load() >= 2 || !g_shutdown_requested.load(); }
            };
            if (!wait_until([] { return g_parked.load() && g_shutdown_returned.load(); }, DEADLINE))
            {
                std::fprintf(stderr, "FAIL: the control-thread release never returned from shutdown() and parked\n");
                return 20;
            }
            if (Input::instance().is_running())
            {
                std::fprintf(stderr, "FAIL: the release did not hand its poller to the deferred reaper\n");
                return 21;
            }
        }
        g_done.store(true);

        if (!g_callback_finished.load())
        {
            std::fprintf(stderr, "FAIL: the rundown did not release the parked release callback\n");
            return 22;
        }
        if (!g_seam_live_in_callback.load())
        {
            std::fprintf(stderr, "FAIL: the seam was cleared while the parked release was still running\n");
            return 23;
        }
        if (g_falses.load() < 2)
        {
            std::fprintf(stderr, "FAIL: the deferred reaper did not deliver the final release\n");
            return 24;
        }
        if (DetourModKit::detail::g_input_key_state_probe || DetourModKit::detail::g_input_pre_dispatch_probe)
        {
            std::fprintf(stderr, "FAIL: the seams outlived the rundown that owns them\n");
            return 25;
        }
        return 0;
    }

    int run_case(Mode mode)
    {
        g_mode.store(mode);
        const std::size_t pins_before = diagnostics::module_pin_count(diagnostics::ModulePinReason::InputPoller);

        DetourModKit::detail::g_input_key_state_probe = [](int vk) noexcept { return vk == HELD_VK; };
        DetourModKit::detail::g_input_pre_dispatch_probe = [] { park_before_dispatch(); };

        auto registration = Input::instance().register_combo(
            ComboBinding{
                .name = "control_thread_hold",
                .trigger = Trigger::Hold,
                .combos = {KeyCombo{{keyboard_key(HELD_VK)}, {}}},
                .on_state_change = &on_state_change,
            }
        );
        if (!registration)
        {
            std::fprintf(stderr, "FAIL: could not register the hold binding\n");
            return 2;
        }
        if (!Input::instance().start(START_SETTINGS))
        {
            std::fprintf(stderr, "FAIL: could not start the input engine\n");
            return 3;
        }
        if (!wait_until([] { return g_trues.load() == 1; }, DEADLINE))
        {
            std::fprintf(stderr, "FAIL: the hold never became active\n");
            dmk_lifecycle::InputSeamOwner{}.run_down();
            return 4;
        }
        g_gate_armed.store(true);
        arm_watchdog();
        if (mode == Mode::AbandonedPremise)
        {
            return run_abandoned_premise();
        }

        // Every failure exit unblocks the parked poll thread and runs the engine down. It waits for a rundown that a
        // callback handed to the reaper, then clears the seams.
        const dmk_lifecycle::InputSeamOwner cleanup{
            [] { g_release_poll.store(true); },
            [] { return g_falses.load() >= 2 || !g_shutdown_requested.load(); }
        };

        // A different combo count rebuilds the entry set and delivers the balancing release on this thread.
        const bool rebound = rebind_to_two_combos();
        g_done.store(true);
        if (!rebound)
        {
            return 5;
        }
        if (g_premise_missed.load() || g_falses.load() < 1)
        {
            std::fprintf(stderr, "FAIL: the poll thread never reached the rebuilt binding's delivery\n");
            return 6;
        }

        if (mode == Mode::ShutdownInRelease)
        {
            if (!g_shutdown_returned.load())
            {
                std::fprintf(stderr, "FAIL: shutdown() inside the release did not return\n");
                return 7;
            }
            if (Input::instance().is_running())
            {
                std::fprintf(stderr, "FAIL: is_running() stayed true after shutdown() inside the release\n");
                return 8;
            }
            // The reaper joins the poll thread and then delivers the rebuilt hold's final release.
            if (!wait_until([] { return g_falses.load() >= 2; }, DEADLINE))
            {
                std::fprintf(stderr, "FAIL: the deferred rundown never delivered the final release\n");
                return 9;
            }
            const std::thread::id final_release_thread = g_last_false_thread.load();
            if (final_release_thread == std::this_thread::get_id() || final_release_thread == g_poll_thread.load())
            {
                std::fprintf(stderr, "FAIL: the final release did not run on the retirement thread\n");
                return 10;
            }
        }
        else
        {
            if (!wait_until([] { return g_trues.load() >= 2; }, DEADLINE))
            {
                std::fprintf(stderr, "FAIL: the released poll thread never delivered the rebuilt hold\n");
                return 11;
            }
            Input::instance().shutdown();
            if (g_falses.load() != 2 || g_last_false_thread.load() != std::this_thread::get_id())
            {
                std::fprintf(stderr, "FAIL: an external shutdown() did not deliver the final release inline\n");
                return 12;
            }
            if (Input::instance().is_running())
            {
                std::fprintf(stderr, "FAIL: is_running() stayed true after an external shutdown()\n");
                return 13;
            }
        }

        if (g_trues.load() != 2 || g_falses.load() != 2)
        {
            std::fprintf(
                stderr,
                "FAIL: unbalanced hold edges, %d true and %d false\n",
                g_trues.load(),
                g_falses.load()
            );
            return 14;
        }
        if (diagnostics::module_pin_count(diagnostics::ModulePinReason::InputPoller) != pins_before)
        {
            std::fprintf(stderr, "FAIL: the rundown did not join the poll thread and release its module reference\n");
            return 15;
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(
            stderr,
            "usage: input_control_thread_shutdown <shutdown-in-release|release-only|abandoned-premise>\n"
        );
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == "shutdown-in-release")
        return run_case(Mode::ShutdownInRelease);
    if (selected_case == "release-only")
        return run_case(Mode::ReleaseOnly);
    if (selected_case == "abandoned-premise")
        return run_case(Mode::AbandonedPremise);

    std::fprintf(stderr, "unknown input control-thread shutdown case\n");
    return 1;
}
