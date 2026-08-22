/**
 * @file test_input_gate_abba.cpp
 * @brief Bounded process proofs for re-entrant input-gate teardown.
 * @details Covers cross-binding Hold callbacks that release each other's guards, retired callable destruction that
 *          releases its own gate, and the same two shapes composed with a refused TLS depth store on both threads at
 *          once. Completion proves that consumer code cannot carry a gate teardown wait into itself; a regression
 *          deadlocks, so the ctest timeout is the oracle for every scenario here.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "input_seam_cleanup.hpp"
#include "internal/input_binding_gate.hpp"
#include "internal/input_delivery_scope.hpp"
#include "internal/input_poller.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

namespace
{
    using namespace DetourModKit;

    constexpr int ITERATIONS = 200;
    constexpr int KEY_A = 0x41;
    constexpr int KEY_B = 0x42;

    // Long enough that a rundown clearing its seams before it joins will have done so by the time the parked callback
    // looks, and irrelevant to a correct one, which cannot clear until that same callback returns.
    constexpr auto SEAM_ORDER_WINDOW = std::chrono::milliseconds{50};

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

    // Bounded negative cleanup control for the cross-parking scenario below. Its callbacks block until the OTHER one
    // has entered, so a failure exit that only joined would wait on a callback nothing will ever release. This drives
    // that exact state: one binding parked on a partner edge that never arrives, then the premise abandoned. Only an
    // owner that unblocks before it joins, and clears after, can complete. A hang is the ctest timeout's verdict.
    int run_abandoned_parked_callback_case()
    {
        input::Input &manager = input::Input::instance();
        manager.shutdown();

        std::atomic<bool> partner_entered{false};
        std::atomic<bool> parked{false};
        std::atomic<bool> callback_finished{false};
        std::atomic<bool> seam_live_in_callback{false};

        detail::g_input_key_state_probe = [](int key) noexcept { return key == KEY_A; };

        {
            auto registered = manager.register_combo(
                make_hold_binding("abba_abandoned", KEY_A,
                                  [&](bool active)
                                  {
                                      if (!active)
                                      {
                                          return;
                                      }
                                      parked.store(true, std::memory_order_release);
                                      while (!partner_entered.load(std::memory_order_acquire))
                                      {
                                          std::this_thread::yield();
                                      }
                                      // Read from inside the poll thread, after a window a correct rundown cannot use:
                                      // it is blocked joining this body, so its probe must still be installed. The race
                                      // with a clear is the defect.
                                      std::this_thread::sleep_for(SEAM_ORDER_WINDOW);
                                      seam_live_in_callback.store(static_cast<bool>(detail::g_input_key_state_probe),
                                                                  std::memory_order_release);
                                      callback_finished.store(true, std::memory_order_release);
                                  }));
            if (!registered)
            {
                std::puts("FAIL: could not register the abandoned parked binding");
                return 9;
            }
            input::BindingGuard guard = std::move(*registered);

            if (!manager.start(
                    input::Input::Settings{.poll_interval = std::chrono::milliseconds{1}, .require_focus = false}))
            {
                std::puts("FAIL: could not start the abandoned parked engine");
                return 10;
            }

            dmk_lifecycle::InputSeamOwner cleanup{[&] { partner_entered.store(true, std::memory_order_release); }};

            for (int i = 0; i < 2'000 && !parked.load(std::memory_order_acquire); ++i)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            if (!parked.load(std::memory_order_acquire))
            {
                std::puts("FAIL: the callback never parked, so nothing was abandoned");
                return 11;
            }
            // Premise abandoned with a callback still parked inside the poll thread.
        }

        if (!callback_finished.load(std::memory_order_acquire))
        {
            std::puts("FAIL: the rundown did not release the parked callback");
            return 12;
        }
        if (!seam_live_in_callback.load(std::memory_order_acquire))
        {
            std::puts("FAIL: the seam was cleared while the poll thread was still inside a callback");
            return 15;
        }
        if (manager.is_running())
        {
            std::puts("FAIL: the abandoned premise left the engine running");
            return 13;
        }
        if (detail::g_input_key_state_probe)
        {
            std::puts("FAIL: the seam outlived the rundown that owns it");
            return 14;
        }

        std::puts("ABANDONED_PARKED_CALLBACK_RUNS_DOWN_BEFORE_CLEARING");
        return 0;
    }

    // Stands in for a consumer capture whose destructor re-enters DMK. Its destruction is the event under test, so a
    // copy would fire the release twice and a moved-from copy would fire it against a gate this proof never installed;
    // both are deleted, which makes the type a non-aggregate and is why the constructor is spelled out.
    template <typename Gate> struct ReleaseGateOnDisposal
    {
        explicit ReleaseGateOnDisposal(Gate *owner) noexcept : gate(owner) {}
        ~ReleaseGateOnDisposal() noexcept { gate->release(); }

        ReleaseGateOnDisposal(const ReleaseGateOnDisposal &) = delete;
        ReleaseGateOnDisposal &operator=(const ReleaseGateOnDisposal &) = delete;
        ReleaseGateOnDisposal(ReleaseGateOnDisposal &&) = delete;
        ReleaseGateOnDisposal &operator=(ReleaseGateOnDisposal &&) = delete;

        Gate *gate;
    };

    template <typename Gate, typename Install> bool retire_disposes_reentrantly(Gate &gate, Install install)
    {
        auto disposal = std::make_shared<ReleaseGateOnDisposal<Gate>>(&gate);
        const std::weak_ptr<ReleaseGateOnDisposal<Gate>> observer = disposal;
        install(std::move(disposal));

        const bool retired = gate.retire(std::chrono::steady_clock::now() + std::chrono::seconds{1});
        return retired && observer.expired();
    }

    struct InlineDisposalProbe
    {
        std::atomic<bool> armed{false};
        std::atomic<bool> saw_inactive_after_take{false};
        std::atomic<bool> saw_inactive{false};
        std::atomic<int> disposals{0};
        std::atomic<bool> *enabled = nullptr;
    };

    void observe_inactive_after_take(void *context) noexcept
    {
        auto &probe = *static_cast<InlineDisposalProbe *>(context);
        probe.saw_inactive_after_take.store(probe.enabled != nullptr && !probe.enabled->load(std::memory_order_acquire),
                                            std::memory_order_release);
    }

    /**
     * @brief Models a small consumer target whose destructor releases its own gate.
     * @details Its move leaves the source armed. MSVC exposes any inline-target destruction under the gate mutex.
     */
    template <typename Gate> struct InlineReleaseGateOnDisposal
    {
        InlineReleaseGateOnDisposal(Gate *owner, InlineDisposalProbe *state) noexcept : gate(owner), probe(state) {}
        ~InlineReleaseGateOnDisposal() noexcept
        {
            if (!probe->armed.load(std::memory_order_acquire))
            {
                return;
            }
            probe->saw_inactive.store(gate->enabled && !gate->enabled->load(std::memory_order_acquire),
                                      std::memory_order_release);
            probe->disposals.fetch_add(1, std::memory_order_relaxed);
            gate->release();
        }

        InlineReleaseGateOnDisposal(const InlineReleaseGateOnDisposal &) noexcept = default;
        InlineReleaseGateOnDisposal &operator=(const InlineReleaseGateOnDisposal &) noexcept = default;
        InlineReleaseGateOnDisposal(InlineReleaseGateOnDisposal &&) noexcept = default;
        InlineReleaseGateOnDisposal &operator=(InlineReleaseGateOnDisposal &&) noexcept = default;

        void operator()() const noexcept {}
        void operator()(bool) const noexcept {}

        Gate *gate;
        InlineDisposalProbe *probe;
    };

    static_assert(sizeof(InlineReleaseGateOnDisposal<detail::PressGate>) == 2 * sizeof(void *));
    static_assert(std::is_nothrow_move_constructible_v<InlineReleaseGateOnDisposal<detail::PressGate>>);

    template <typename Gate, typename Slot>
    bool retire_disposes_inline_target(Gate &gate, Slot &slot, InlineDisposalProbe &probe)
    {
        gate.enabled = std::make_shared<std::atomic<bool>>(true);
        probe.enabled = gate.enabled.get();
        slot = InlineReleaseGateOnDisposal<Gate>{&gate, &probe};
        slot.set_after_take_probe_for_test(&observe_inactive_after_take, &probe);
        probe.armed.store(true, std::memory_order_release);

        const bool retired = gate.retire(std::chrono::steady_clock::now() + std::chrono::seconds{1});
        if (!retired)
        {
            probe.armed.store(false, std::memory_order_release);
        }
        return retired && probe.saw_inactive_after_take.load(std::memory_order_acquire) &&
               probe.disposals.load(std::memory_order_relaxed) == 1 &&
               probe.saw_inactive.load(std::memory_order_acquire) && !gate.enabled->load(std::memory_order_acquire);
    }

    int run_press_retire_disposal_case()
    {
        detail::PressGate press_gate;
        if (!retire_disposes_reentrantly(press_gate,
                                         [&press_gate](std::shared_ptr<ReleaseGateOnDisposal<detail::PressGate>> keep)
                                         { press_gate.on_press = [keep = std::move(keep)] {}; }))
        {
            std::puts("FAIL: PressGate retirement did not finish re-entrant callable disposal");
            return 6;
        }

        InlineDisposalProbe inline_probe;
        detail::PressGate inline_gate;
        if (!retire_disposes_inline_target(inline_gate, inline_gate.on_press, inline_probe))
        {
            std::puts("FAIL: PressGate retirement mishandled inline callable disposal");
            return 16;
        }

        std::puts("NO_PRESS_RETIRE_DISPOSAL_SELF_DEADLOCK");
        return 0;
    }

    int run_hold_retire_disposal_case()
    {
        detail::HoldGate hold_gate;
        if (!retire_disposes_reentrantly(hold_gate,
                                         [&hold_gate](std::shared_ptr<ReleaseGateOnDisposal<detail::HoldGate>> keep)
                                         { hold_gate.on_state_change = [keep = std::move(keep)](bool) {}; }))
        {
            std::puts("FAIL: HoldGate retirement did not finish re-entrant callable disposal");
            return 7;
        }

        InlineDisposalProbe inline_probe;
        detail::HoldGate inline_gate;
        if (!retire_disposes_inline_target(inline_gate, inline_gate.on_state_change, inline_probe))
        {
            std::puts("FAIL: HoldGate retirement mishandled inline callable disposal");
            return 17;
        }

        std::puts("NO_HOLD_RETIRE_DISPOSAL_SELF_DEADLOCK");
        return 0;
    }

    // Two threads, each inside its own gate's mandatory teardown span, each releasing the other's gate, with the exact
    // TLS depth store refused on both at once. That composition is the one the ordinary depth marker cannot answer: a
    // teardown whose depth store failed used to read as depth-zero control plane on both threads, so each waited on
    // the other's claim. The rendezvous makes the crossing deterministic rather than hoping for an interleaving.
    struct CrossGateTeardownRacers
    {
        std::atomic<bool> a_inside{false};
        std::atomic<bool> b_inside{false};
        std::atomic<bool> a_store_refused{false};
        std::atomic<bool> b_store_refused{false};
        std::atomic<int> a_edges{0};
        std::atomic<int> b_edges{0};
    };

    void wait_for(const std::atomic<bool> &flag) noexcept
    {
        while (!flag.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    template <typename Gate> struct MeetAndReleasePeerOnDisposal
    {
        MeetAndReleasePeerOnDisposal(Gate *peer_gate, std::atomic<bool> *mine, const std::atomic<bool> *theirs,
                                     std::atomic<int> *edges) noexcept
            : peer(peer_gate), inside(mine), other(theirs), disposals(edges)
        {
        }

        ~MeetAndReleasePeerOnDisposal() noexcept
        {
            disposals->fetch_add(1, std::memory_order_relaxed);
            inside->store(true, std::memory_order_release);
            wait_for(*other);
            peer->release();
        }

        MeetAndReleasePeerOnDisposal(const MeetAndReleasePeerOnDisposal &) = delete;
        MeetAndReleasePeerOnDisposal &operator=(const MeetAndReleasePeerOnDisposal &) = delete;
        MeetAndReleasePeerOnDisposal(MeetAndReleasePeerOnDisposal &&) = delete;
        MeetAndReleasePeerOnDisposal &operator=(MeetAndReleasePeerOnDisposal &&) = delete;

        Gate *peer;
        std::atomic<bool> *inside;
        const std::atomic<bool> *other;
        std::atomic<int> *disposals;
    };

    // Runs one side of the crossing: refuse this thread's depth store, drive its teardown, meet the other side inside
    // consumer code, then release the peer's gate from in there.
    template <typename Teardown> void run_cross_gate_side(std::atomic<bool> &store_refused, Teardown teardown) noexcept
    {
        store_refused.store(DetourModKit::detail::set_delivery_scope_store_failure_for_test(true),
                            std::memory_order_release);
        teardown();
        (void)DetourModKit::detail::set_delivery_scope_store_failure_for_test(false);
    }

    int run_hold_store_failure_abba_case()
    {
        CrossGateTeardownRacers racers;
        detail::HoldGate gate_a;
        detail::HoldGate gate_b;

        // The inner lambda outlives this call, so it captures pointers by value rather than the parameter references.
        const auto arm = [](detail::HoldGate &gate, detail::HoldGate *peer, std::atomic<bool> *mine,
                            const std::atomic<bool> *theirs, std::atomic<int> *edges)
        {
            gate.active_entries = 1;
            gate.forwarded_active = true;
            gate.on_state_change = [peer, mine, theirs, edges](bool)
            {
                edges->fetch_add(1, std::memory_order_relaxed);
                mine->store(true, std::memory_order_release);
                wait_for(*theirs);
                peer->release();
            };
        };
        arm(gate_a, &gate_b, &racers.a_inside, &racers.b_inside, &racers.a_edges);
        arm(gate_b, &gate_a, &racers.b_inside, &racers.a_inside, &racers.b_edges);

        std::thread thread_a([&] { run_cross_gate_side(racers.a_store_refused, [&] { gate_a.release(); }); });
        std::thread thread_b([&] { run_cross_gate_side(racers.b_store_refused, [&] { gate_b.release(); }); });
        thread_a.join();
        thread_b.join();

        if (!racers.a_store_refused.load(std::memory_order_acquire) ||
            !racers.b_store_refused.load(std::memory_order_acquire))
        {
            std::puts("FAIL: both threads' depth stores could not be refused at once");
            return 30;
        }
        if (racers.a_edges.load(std::memory_order_relaxed) != 1 || racers.b_edges.load(std::memory_order_relaxed) != 1)
        {
            std::puts("FAIL: a cross-gate Hold teardown did not emit exactly one balancing edge per gate");
            return 31;
        }

        std::puts("NO_HOLD_STORE_FAILURE_ABBA");
        return 0;
    }

    int run_press_store_failure_abba_case()
    {
        CrossGateTeardownRacers racers;
        detail::PressGate gate_a;
        detail::PressGate gate_b;

        // The captured destructor, not the callback, is the consumer code here: retirement disposes of the callable
        // while it still owns the gate, and that disposal releases the peer's gate.
        using PressDisposal = MeetAndReleasePeerOnDisposal<detail::PressGate>;
        auto disposal_a = std::make_shared<PressDisposal>(&gate_b, &racers.a_inside, &racers.b_inside, &racers.a_edges);
        auto disposal_b = std::make_shared<PressDisposal>(&gate_a, &racers.b_inside, &racers.a_inside, &racers.b_edges);
        const std::weak_ptr<PressDisposal> observer_a = disposal_a;
        const std::weak_ptr<PressDisposal> observer_b = disposal_b;
        gate_a.on_press = [keep = std::move(disposal_a)] {};
        gate_b.on_press = [keep = std::move(disposal_b)] {};

        std::atomic<bool> retired_a{false};
        std::atomic<bool> retired_b{false};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        std::thread thread_a(
            [&]
            {
                run_cross_gate_side(racers.a_store_refused,
                                    [&] { retired_a.store(gate_a.retire(deadline), std::memory_order_release); });
            });
        std::thread thread_b(
            [&]
            {
                run_cross_gate_side(racers.b_store_refused,
                                    [&] { retired_b.store(gate_b.retire(deadline), std::memory_order_release); });
            });
        thread_a.join();
        thread_b.join();

        if (!racers.a_store_refused.load(std::memory_order_acquire) ||
            !racers.b_store_refused.load(std::memory_order_acquire))
        {
            std::puts("FAIL: both threads' depth stores could not be refused at once");
            return 32;
        }
        if (!retired_a.load(std::memory_order_acquire) || !retired_b.load(std::memory_order_acquire))
        {
            std::puts("FAIL: a cross-gate Press retirement did not complete");
            return 33;
        }
        if (!observer_a.expired() || !observer_b.expired())
        {
            std::puts("FAIL: a retired Press callable outlived its disposal");
            return 34;
        }
        if (racers.a_edges.load(std::memory_order_relaxed) != 1 || racers.b_edges.load(std::memory_order_relaxed) != 1)
        {
            std::puts("FAIL: a cross-gate Press disposal did not run exactly once per gate");
            return 35;
        }

        std::puts("NO_PRESS_STORE_FAILURE_ABBA");
        return 0;
    }

    int run_hold_retire_store_failure_abba_case()
    {
        CrossGateTeardownRacers racers;
        detail::HoldGate gate_a;
        detail::HoldGate gate_b;
        std::atomic<int> balancing_a{0};
        std::atomic<int> balancing_b{0};

        using HoldDisposal = MeetAndReleasePeerOnDisposal<detail::HoldGate>;
        auto disposal_a = std::make_shared<HoldDisposal>(&gate_b, &racers.a_inside, &racers.b_inside, &racers.a_edges);
        auto disposal_b = std::make_shared<HoldDisposal>(&gate_a, &racers.b_inside, &racers.a_inside, &racers.b_edges);
        const std::weak_ptr<HoldDisposal> observer_a = disposal_a;
        const std::weak_ptr<HoldDisposal> observer_b = disposal_b;

        const auto arm = [](detail::HoldGate &gate, std::shared_ptr<HoldDisposal> disposal, std::atomic<int> &balancing)
        {
            gate.active_entries = 1;
            gate.forwarded_active = true;
            gate.on_state_change = [keep = std::move(disposal), &balancing](bool active)
            {
                (void)keep;
                balancing.fetch_add(active ? 100 : 1, std::memory_order_relaxed);
            };
        };
        arm(gate_a, std::move(disposal_a), balancing_a);
        arm(gate_b, std::move(disposal_b), balancing_b);

        std::atomic<bool> retired_a{false};
        std::atomic<bool> retired_b{false};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        std::thread thread_a(
            [&]
            {
                run_cross_gate_side(racers.a_store_refused,
                                    [&] { retired_a.store(gate_a.retire(deadline), std::memory_order_release); });
            });
        std::thread thread_b(
            [&]
            {
                run_cross_gate_side(racers.b_store_refused,
                                    [&] { retired_b.store(gate_b.retire(deadline), std::memory_order_release); });
            });
        thread_a.join();
        thread_b.join();

        if (!racers.a_store_refused.load(std::memory_order_acquire) ||
            !racers.b_store_refused.load(std::memory_order_acquire))
        {
            std::puts("FAIL: both threads' depth stores could not be refused during Hold retirement");
            return 36;
        }
        if (!retired_a.load(std::memory_order_acquire) || !retired_b.load(std::memory_order_acquire))
        {
            std::puts("FAIL: a cross-gate Hold retirement did not complete");
            return 37;
        }
        if (!observer_a.expired() || !observer_b.expired())
        {
            std::puts("FAIL: a retired Hold callable outlived its captured disposal");
            return 38;
        }
        if (balancing_a.load(std::memory_order_relaxed) != 1 || balancing_b.load(std::memory_order_relaxed) != 1)
        {
            std::puts("FAIL: a cross-gate Hold retirement did not emit exactly one balancing false per gate");
            return 39;
        }
        if (racers.a_edges.load(std::memory_order_relaxed) != 1 || racers.b_edges.load(std::memory_order_relaxed) != 1)
        {
            std::puts("FAIL: a cross-gate Hold capture was not destroyed exactly once per gate");
            return 40;
        }

        std::puts("NO_HOLD_RETIRE_STORE_FAILURE_ABBA");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    using namespace DetourModKit;

    bool abandon_partial_registration = false;

    if (argc == 2 && std::string_view{argv[1]} == "press-retire-disposal")
    {
        return run_press_retire_disposal_case();
    }
    if (argc == 2 && std::string_view{argv[1]} == "hold-retire-disposal")
    {
        return run_hold_retire_disposal_case();
    }
    if (argc == 2 && std::string_view{argv[1]} == "hold-store-failure-abba")
    {
        return run_hold_store_failure_abba_case();
    }
    if (argc == 2 && std::string_view{argv[1]} == "press-store-failure-abba")
    {
        return run_press_store_failure_abba_case();
    }
    if (argc == 2 && std::string_view{argv[1]} == "hold-retire-store-failure-abba")
    {
        return run_hold_retire_store_failure_abba_case();
    }
    if (argc == 2 && std::string_view{argv[1]} == "abandoned-parked-callback")
    {
        const int ordering_result = run_abandoned_parked_callback_case();
        if (ordering_result != 0)
        {
            return ordering_result;
        }
        // Continue through the ordinary loop for a second abandonment: after one successful iteration leaves the
        // manager running, A becomes held and B's registration is refused. This is the pre-owner exit that used to
        // destroy A's gate before anything could release its callback from waiting for B.
        abandon_partial_registration = true;
    }
    if (argc > 1 && !abandon_partial_registration)
    {
        // A raw proof's only oracle is its exit status. Falling through to the no-argument scenario would let a typo'd
        // ctest COMMAND, or a stale host built before a scenario existed, run a different proof and report PASS having
        // asserted nothing about the one it was registered for.
        std::printf("FAIL: unknown scenario '%s'\n", argv[1]);
        return 8;
    }

    input::Input &manager = input::Input::instance();
    manager.shutdown();
    detail::g_input_key_state_probe = [](int key) noexcept { return key == KEY_A || key == KEY_B; };

    bool partial_registration_abandoned = false;
    const int iterations = abandon_partial_registration ? 2 : ITERATIONS;
    for (int iteration = 0; iteration < iterations; ++iteration)
    {
        input::BindingGuard guard_a;
        input::BindingGuard guard_b;
        std::atomic<int> a_true{0};
        std::atomic<int> a_false{0};
        std::atomic<int> b_true{0};
        std::atomic<int> b_false{0};
        std::atomic<bool> a_in_callback{false};
        std::atomic<bool> b_in_callback{false};

        // Constructed before either registration result can own a live gate. On iterations after the first the manager
        // is already running, so A can begin delivery before B's registration is attempted; if B then fails, the
        // owner must unblock and join before the moved A guard or any callback capture is destroyed.
        dmk_lifecycle::InputSeamOwner cleanup{[&]
                                              {
                                                  a_in_callback.store(true, std::memory_order_release);
                                                  b_in_callback.store(true, std::memory_order_release);
                                              }};

        auto result_a =
            manager.register_combo(make_hold_binding("abba_a", KEY_A,
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
        if (!result_a)
        {
            std::puts("FAIL: registration A");
            return 2;
        }
        guard_a = std::move(*result_a);

        const bool refuse_second_registration = abandon_partial_registration && iteration == 1;
        decltype(result_a) result_b =
            std::unexpected(Error{ErrorCode::ShutdownInProgress, "input_gate_abba::abandoned_second_registration"});
        if (refuse_second_registration)
        {
            if (!wait_for_count(a_true, 1))
            {
                std::puts("FAIL: A never became held before the second registration was abandoned");
                return 16;
            }
        }
        else
        {
            result_b =
                manager.register_combo(make_hold_binding("abba_b", KEY_B,
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
        }
        if (!result_b)
        {
            if (refuse_second_registration)
            {
                partial_registration_abandoned = true;
                break;
            }
            std::puts("FAIL: registration B");
            return 2;
        }
        guard_b = std::move(*result_b);

        if (!manager.is_running())
        {
            const auto started = manager.start(
                input::Input::Settings{.poll_interval = std::chrono::milliseconds{1}, .require_focus = false});
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

        // Both callbacks have completed and both bindings are removed. The next iteration re-registers against the
        // same started manager, so the rundown belongs to the end of the loop rather than to this scope.
        cleanup.dismiss();
    }

    if (abandon_partial_registration)
    {
        if (!partial_registration_abandoned)
        {
            std::puts("FAIL: the second registration was not abandoned");
            return 17;
        }
        if (manager.is_running())
        {
            std::puts("FAIL: the partial-registration abandonment left the engine running");
            return 18;
        }
        if (detail::g_input_key_state_probe)
        {
            std::puts("FAIL: the partial-registration abandonment left its seam installed");
            return 19;
        }
        std::puts("ABANDONED_PARTIAL_REGISTRATION_RUNS_DOWN");
        return 0;
    }

    dmk_lifecycle::InputSeamOwner final_cleanup;
    final_cleanup.run_down();
    std::puts("NO_ABBA");
    return 0;
}
