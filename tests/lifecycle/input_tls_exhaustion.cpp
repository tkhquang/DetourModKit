/**
 * @file input_tls_exhaustion.cpp
 * @brief Fresh-process proof that an input delivery with no per-thread identity is refused, not admitted untracked.
 * @details The delivery marker decides whether a control-plane release blocks for an in-flight callback. A process
 *          that has consumed every TLS index before DetourModKit reserves its slot cannot record a delivery frame, and
 *          the only answer that keeps the public rundown promise true is to refuse the delivery before consumer code
 *          starts. The `exhausted` scenario asserts that refusal and that one thread's unrecordable frame never makes
 *          another thread read as callback-entrant; `available` is the positive control that the same drive really
 *          does deliver when a slot exists. Exit status is the oracle.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "input_seam_cleanup.hpp"
#include "internal/input_binding_gate.hpp"
#include "internal/input_delivery_scope.hpp"
#include "internal/input_poller.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    using namespace DetourModKit;

    constexpr int KEY_A = 0x41;

    // Long enough for many poll cycles at the one-millisecond interval below, so "the callback never ran" is a claim
    // about refusal rather than about scheduling luck.
    constexpr std::chrono::milliseconds DELIVERY_WINDOW{200};

    // Long enough that a rundown clearing its seams before it joins will have done so by the time the parked callback
    // looks, and irrelevant to a correct one, which cannot clear until that same callback returns.
    constexpr std::chrono::milliseconds SEAM_ORDER_WINDOW{50};

    std::atomic<bool> s_worker_ready{false};
    std::atomic<bool> s_worker_scope_open{false};
    std::atomic<bool> s_worker_reservation_finished{false};
    std::atomic<bool> s_worker_reservation_succeeded{true};
    std::atomic<bool> s_worker_scope_admitted{true};
    std::atomic<bool> s_worker_scope_finished{false};
    std::atomic<bool> s_worker_release{false};
    std::atomic<int> s_reservation_arrivals{0};

    // Exactly two arrivals, and the wait is unbounded on purpose. The seam this runs from is reachable only while the
    // marker's slot is still unreserved (input_delivery_scope.cpp), so it closes the instant either racer wins the
    // serialized allocation, and the caller installs it around nothing but its own two reserve calls. A third arrival
    // would therefore need a third thread inside that window, and the scenario starts the poll thread only after the
    // seam is cleared and the worker joined, by which point the slot has latched unavailable and the seam is dead.
    void rendezvous_first_reservation() noexcept
    {
        s_reservation_arrivals.fetch_add(1, std::memory_order_acq_rel);
        while (s_reservation_arrivals.load(std::memory_order_acquire) != 2)
        {
            std::this_thread::yield();
        }
    }

    // Pre-warms the thread before any index is taken, then opens one delivery frame on demand. Warming first matters:
    // the C++ runtime materializes its own per-thread state lazily, and on MinGW that state is emulated TLS whose
    // first touch would allocate an index this proof is about to make unavailable.
    void worker_main() noexcept
    {
        s_worker_ready.store(true, std::memory_order_release);
        while (!s_worker_scope_open.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        s_worker_reservation_succeeded.store(detail::reserve_delivery_scope_tls(), std::memory_order_release);
        s_worker_reservation_finished.store(true, std::memory_order_release);
        const detail::DeliveryScope scope;
        s_worker_scope_admitted.store(scope.admitted(), std::memory_order_relaxed);
        s_worker_scope_finished.store(true, std::memory_order_release);
        while (!s_worker_release.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    // Stands in for a consumer capture whose destructor re-enters DMK, which is what PressGate::retire disposes of
    // while it still holds the gate's in-flight count. Copies would fire the release more than once.
    struct ReleasePressGateOnDisposal
    {
        explicit ReleasePressGateOnDisposal(detail::PressGate *owner) noexcept : gate(owner) {}
        ~ReleasePressGateOnDisposal() noexcept { gate->release(); }

        ReleasePressGateOnDisposal(const ReleasePressGateOnDisposal &) = delete;
        ReleasePressGateOnDisposal &operator=(const ReleasePressGateOnDisposal &) = delete;
        ReleasePressGateOnDisposal(ReleasePressGateOnDisposal &&) = delete;
        ReleasePressGateOnDisposal &operator=(ReleasePressGateOnDisposal &&) = delete;

        detail::PressGate *gate;
    };

    // Runs after marker reservation has failed permanently. CreateThread deliberately bypasses std::thread so this is
    // a foreign host thread on MinGW: the teardown owner must still be the exact, allocation-free Win32 identity.
    DWORD WINAPI native_teardown_owner_probe(void *) noexcept
    {
        if (detail::current_native_thread_id() != static_cast<std::uint32_t>(::GetCurrentThreadId()))
        {
            return 16;
        }

        std::atomic<int> balancing{0};
        detail::HoldGate hold;
        hold.forwarded_active = true;
        hold.active_entries = 1;
        hold.on_state_change = [&](bool active)
        {
            balancing.fetch_add(1, std::memory_order_relaxed);
            if (!active)
            {
                hold.release();
            }
        };
        hold.release();
        if (balancing.load(std::memory_order_relaxed) != 1)
        {
            return 17;
        }

        detail::PressGate press;
        auto disposal = std::make_shared<ReleasePressGateOnDisposal>(&press);
        const std::weak_ptr<ReleasePressGateOnDisposal> observer = disposal;
        press.on_press = [keep = std::move(disposal)] {};
        if (!press.retire(std::chrono::steady_clock::now() + std::chrono::seconds{5}) || !observer.expired())
        {
            return 18;
        }
        return 0;
    }

    [[nodiscard]] int run_native_teardown_owner_probe() noexcept
    {
        HANDLE thread = ::CreateThread(nullptr, 0, &native_teardown_owner_probe, nullptr, 0, nullptr);
        if (thread == nullptr)
        {
            return 19;
        }
        const DWORD wait_result = ::WaitForSingleObject(thread, 10'000);
        DWORD exit_code = 20;
        if (wait_result == WAIT_OBJECT_0)
        {
            (void)::GetExitCodeThread(thread, &exit_code);
        }
        (void)::CloseHandle(thread);
        return wait_result == WAIT_OBJECT_0 ? static_cast<int>(exit_code) : 20;
    }

    std::vector<DWORD> exhaust_tls_indices()
    {
        std::vector<DWORD> taken;
        for (;;)
        {
            const DWORD index = ::TlsAlloc();
            if (index == TLS_OUT_OF_INDEXES)
            {
                return taken;
            }
            taken.push_back(index);
        }
    }

    void release_tls_indices(const std::vector<DWORD> &taken) noexcept
    {
        for (const DWORD index : taken)
        {
            (void)::TlsFree(index);
        }
    }

    input::ComboBinding make_hold_binding(std::string name, int key, std::function<void(bool)> callback)
    {
        return input::ComboBinding{
            .name = std::move(name),
            .trigger = input::Trigger::Hold,
            .combos = {{{keyboard_key(key)}, {}}},
            .on_state_change = std::move(callback),
        };
    }

    // Drives one held edge through the real facade and reports how many consumer callbacks it produced.
    [[nodiscard]] int facade_hold_edges(int &error_code)
    {
        input::Input &manager = input::Input::instance();
        std::atomic<int> edges{0};
        detail::g_input_key_state_probe = [](int key) noexcept { return key == KEY_A; };

        // Declared before the binding guard and after the state the callback captures, so every exit below joins the
        // poll thread before `edges` dies and clears the probe only once nothing can be inside it. The refusal exit in
        // particular used to clear a live seam and return with the loop still running.
        const dmk_lifecycle::InputSeamOwner cleanup;

        auto registered = manager.register_combo(
            make_hold_binding("tls_exhaustion", KEY_A, [&](bool) { edges.fetch_add(1, std::memory_order_relaxed); })
        );
        if (!registered)
        {
            error_code = 10;
            return -1;
        }
        input::BindingGuard guard = std::move(*registered);

        const auto started = manager.start(
            input::Input::Settings{.poll_interval = std::chrono::milliseconds{1}, .require_focus = false}
        );
        if (!started)
        {
            error_code = 11;
            return -1;
        }

        const auto deadline = std::chrono::steady_clock::now() + DELIVERY_WINDOW;
        while (std::chrono::steady_clock::now() < deadline && edges.load(std::memory_order_relaxed) == 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }

        // A control-plane drain must never mistake an unrelated thread for a callback-entrant one. This is the exact
        // reading the process-wide fallback used to corrupt, and it is asserted while the poll thread is still live.
        if (manager.prepare_logic_dll_unload_all(std::chrono::milliseconds{500}) ==
            input::CallbackDrainStatus::SelfDelivery)
        {
            error_code = 12;
            return -1;
        }

        return edges.load(std::memory_order_relaxed);
    }

    // Bounded negative cleanup control for the drive above: abandon the premise while the poll thread is live and a
    // callback is parked, then assert the rundown released it, stopped the engine, and cleared the seam in that order.
    int run_abandoned_premise_case()
    {
        input::Input &manager = input::Input::instance();
        std::atomic<bool> parked{false};
        std::atomic<bool> proceed{false};
        std::atomic<bool> callback_finished{false};
        std::atomic<bool> seam_live_in_callback{false};

        detail::g_input_key_state_probe = [](int key) noexcept { return key == KEY_A; };

        {
            auto registered = manager.register_combo(make_hold_binding(
                "tls_abandoned",
                KEY_A,
                [&](bool active)
                {
                    if (!active)
                    {
                        return;
                    }
                    parked.store(true, std::memory_order_release);
                    while (!proceed.load(std::memory_order_acquire))
                    {
                        std::this_thread::yield();
                    }
                    // Read from inside the poll thread, after a window a correct rundown cannot use:
                    // it is blocked joining this body, so its probe must still be installed. The race
                    // with a clear is the defect.
                    std::this_thread::sleep_for(SEAM_ORDER_WINDOW);
                    seam_live_in_callback.store(
                        static_cast<bool>(detail::g_input_key_state_probe),
                        std::memory_order_release
                    );
                    callback_finished.store(true, std::memory_order_release);
                }
            ));
            if (!registered)
            {
                std::fputs("FAIL: could not register the abandoned-premise binding\n", stderr);
                return 60;
            }
            input::BindingGuard guard = std::move(*registered);

            if (!manager.start(
                    input::Input::Settings{.poll_interval = std::chrono::milliseconds{1}, .require_focus = false}
                ))
            {
                std::fputs("FAIL: could not start the abandoned-premise engine\n", stderr);
                return 61;
            }

            const dmk_lifecycle::InputSeamOwner cleanup{[&] { proceed.store(true, std::memory_order_release); }};

            const auto deadline = std::chrono::steady_clock::now() + DELIVERY_WINDOW;
            while (std::chrono::steady_clock::now() < deadline && !parked.load(std::memory_order_acquire))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            if (!parked.load(std::memory_order_acquire))
            {
                std::fputs("FAIL: the callback never parked, so nothing was abandoned\n", stderr);
                return 62;
            }
            // Premise abandoned here, exactly as the refusal exit in facade_hold_edges abandons it.
        }

        if (!callback_finished.load(std::memory_order_acquire))
        {
            std::fputs("FAIL: the rundown did not release the parked callback\n", stderr);
            return 63;
        }
        if (!seam_live_in_callback.load(std::memory_order_acquire))
        {
            std::fputs("FAIL: the seam was cleared while the poll thread was still inside a callback\n", stderr);
            return 66;
        }
        if (manager.is_running())
        {
            std::fputs("FAIL: the abandoned premise left the engine running\n", stderr);
            return 64;
        }
        if (detail::g_input_key_state_probe)
        {
            std::fputs("FAIL: the seam outlived the rundown that owns it\n", stderr);
            return 65;
        }

        std::puts("ABANDONED_PREMISE_RUNS_DOWN_BEFORE_CLEARING");
        return 0;
    }

    // Refusal must leave the gate exactly as the edge found it, or a later real delivery would see a phantom entry.
    [[nodiscard]] bool hold_gate_is_untouched(const detail::HoldGate &gate) noexcept
    {
        return gate.active_entries == 0 && !gate.forwarded_active && gate.in_flight == 0 && !gate.deferred_final;
    }

    int run_exhausted_case()
    {
        std::thread worker{worker_main};
        while (!s_worker_ready.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }

        const std::vector<DWORD> taken = exhaust_tls_indices();
        if (taken.empty())
        {
            std::fputs("FAIL: the process had no TLS index to take, so nothing was exhausted\n", stderr);
            s_worker_scope_open.store(true, std::memory_order_release);
            s_worker_release.store(true, std::memory_order_release);
            worker.join();
            return 2;
        }
        const DWORD unexpected_index = ::TlsAlloc();
        if (unexpected_index != TLS_OUT_OF_INDEXES)
        {
            std::fputs("FAIL: a TLS index was still available after exhaustion\n", stderr);
            (void)::TlsFree(unexpected_index);
            release_tls_indices(taken);
            s_worker_scope_open.store(true, std::memory_order_release);
            s_worker_release.store(true, std::memory_order_release);
            worker.join();
            return 3;
        }

        int status = 0;
        detail::set_delivery_scope_reservation_seam_for_test(&rendezvous_first_reservation);
        s_worker_scope_open.store(true, std::memory_order_release);
        const bool main_reservation_succeeded = detail::reserve_delivery_scope_tls();
        while (!s_worker_reservation_finished.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        detail::set_delivery_scope_reservation_seam_for_test(nullptr);
        if (main_reservation_succeeded || s_worker_reservation_succeeded.load(std::memory_order_acquire))
        {
            std::fputs("FAIL: a racing reservation reported success after TLS exhaustion\n", stderr);
            status = 21;
        }

        {
            std::atomic<int> hold_calls{0};
            detail::HoldGate hold;
            hold.on_state_change = [&](bool) { hold_calls.fetch_add(1, std::memory_order_relaxed); };
            hold.deliver(true);
            hold.deliver(false);
            if (hold_calls.load(std::memory_order_relaxed) != 0)
            {
                std::fputs("FAIL: a hold delivery ran consumer code without per-thread identity\n", stderr);
                status = 4;
            }
            else if (!hold_gate_is_untouched(hold))
            {
                std::fputs("FAIL: a refused hold delivery left gate bookkeeping behind\n", stderr);
                status = 5;
            }
            // A gate that never forwarded owes no balancing edge, so this must return without waiting on anything.
            hold.release();

            std::atomic<int> press_calls{0};
            detail::PressGate press;
            press.on_press = [&] { press_calls.fetch_add(1, std::memory_order_relaxed); };
            press.deliver();
            if (status == 0 && press_calls.load(std::memory_order_relaxed) != 0)
            {
                std::fputs("FAIL: a press delivery ran consumer code without per-thread identity\n", stderr);
                status = 6;
            }
            else if (status == 0 && press.in_flight != 0)
            {
                std::fputs("FAIL: a refused press delivery left an in-flight slot behind\n", stderr);
                status = 7;
            }
            press.release();
        }

        if (status == 0)
        {
            std::atomic<int> hold_calls{0};
            detail::HoldGate held;
            held.active_entries = 1;
            held.forwarded_active = true;
            held.on_state_change = [&](bool) { hold_calls.fetch_add(1, std::memory_order_relaxed); };
            held.deliver(false);
            if (hold_calls.load(std::memory_order_relaxed) != 0 || held.active_entries != 1 || !held.forwarded_active ||
                held.in_flight != 0)
            {
                std::fputs("FAIL: a refused released edge did not roll back the held gate state\n", stderr);
                status = 22;
            }
            held.on_state_change = nullptr;
            held.release();
        }

        // Self-release and disposal re-entry with no marker to lean on. The teardown claim's owning thread is the only
        // thing left that can tell these frames apart from a genuine control-plane caller, and both waits they would
        // otherwise take are unbounded. A regression here hangs rather than failing, so the ctest timeout is the
        // oracle. forwarded_active is set directly because no delivery can run in this process to set it.
        if (status == 0)
        {
            std::atomic<int> balancing{0};
            detail::HoldGate hold;
            hold.forwarded_active = true;
            hold.active_entries = 1;
            hold.on_state_change = [&](bool active)
            {
                balancing.fetch_add(1, std::memory_order_relaxed);
                if (!active)
                {
                    hold.release();
                }
            };
            hold.release();
            if (balancing.load(std::memory_order_relaxed) != 1)
            {
                std::fputs("FAIL: an untracked balancing edge was not emitted exactly once\n", stderr);
                status = 14;
            }
        }
        if (status == 0)
        {
            detail::PressGate press;
            auto disposal = std::make_shared<ReleasePressGateOnDisposal>(&press);
            const std::weak_ptr<ReleasePressGateOnDisposal> observer = disposal;
            press.on_press = [keep = std::move(disposal)] {};
            if (!press.retire(std::chrono::steady_clock::now() + std::chrono::seconds{5}) || !observer.expired())
            {
                std::fputs("FAIL: untracked callable disposal did not complete\n", stderr);
                status = 15;
            }
        }

        // Wait for the worker's own report, not for a deadline. s_worker_scope_admitted starts optimistic, so a
        // deadline that expires before the worker has written it cannot be told apart from a frame that really was
        // recorded, and the case would fail for scheduling rather than for behaviour. A worker that never reports
        // hangs to the ctest timeout, which is the oracle the rest of this scenario already uses.
        while (!s_worker_scope_finished.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        if (status == 0 && s_worker_scope_admitted.load(std::memory_order_relaxed))
        {
            std::fputs("FAIL: a delivery frame reported itself recorded with no TLS index available\n", stderr);
            status = 9;
        }
        if (status == 0 && detail::current_thread_in_delivery())
        {
            std::fputs("FAIL: another thread's unrecordable frame made this thread read as callback-entrant\n", stderr);
            status = 8;
        }
        // Hand the indices back before anything is allowed to enter or leave this window. The refusal under test is
        // latched, so the facade drive below still observes it on a process whose TLS is available again. The order
        // matters for the harness rather than for the subject: the MSVC C runtime's thread-exit path faults
        // intermittently while every index is taken, so no thread may start or finish inside the window.
        release_tls_indices(taken);
        s_worker_release.store(true, std::memory_order_release);
        worker.join();
        if (status == 0)
        {
            status = run_native_teardown_owner_probe();
            if (status != 0)
            {
                std::fprintf(stderr, "FAIL: native teardown-owner probe failed (%d)\n", status);
            }
        }
        if (status != 0)
        {
            return status;
        }

        int error_code = 0;
        const int edges = facade_hold_edges(error_code);
        if (edges < 0)
        {
            std::fprintf(stderr, "FAIL: the facade drive could not be set up (%d)\n", error_code);
            return error_code;
        }
        if (edges != 0)
        {
            std::fputs("FAIL: the poll thread delivered a held edge with no delivery marker available\n", stderr);
            return 13;
        }

        std::puts("TLS_EXHAUSTION_REFUSES_UNTRACKED_DELIVERY");
        return 0;
    }

    // Distinct status range from run_exhausted_case, which owns 2 through 22: both scenarios are the same binary
    // writing to the same stderr, so a bare exit code has to name one scenario rather than two. The codes
    // facade_hold_edges reports are shared deliberately, because they mean the same thing in both.
    // The reservation can succeed and the per-thread store still fail: a reserved index past the TEB's inline slots is
    // backed by a lazily heap-allocated expansion array, so the first store on a thread that has never used a high
    // index allocates. Exhausting TLS indices cannot reach that branch, and a delivery admitted with an unrecorded
    // depth would let a nested control-plane release read itself as control-plane and block into the ABBA. Codes 40
    // through 54 are this scenario's, distinct from the other two.
    int run_store_failure_case()
    {
        if (!detail::reserve_delivery_scope_tls())
        {
            std::fputs("FAIL: the delivery marker could not reserve its slot on an unexhausted process\n", stderr);
            return 40;
        }

        if (!detail::set_delivery_scope_store_failure_for_test(true))
        {
            std::fputs("FAIL: the store-failure seam had no registration slot for this thread\n", stderr);
            return 50;
        }
        {
            const detail::DeliveryScope refused;
            if (refused.admitted())
            {
                std::fputs("FAIL: a frame whose depth store failed reported itself recorded\n", stderr);
                (void)detail::set_delivery_scope_store_failure_for_test(false);
                return 41;
            }
        }
        if (detail::current_thread_in_delivery())
        {
            std::fputs("FAIL: a refused frame still made this thread read as callback-entrant\n", stderr);
            (void)detail::set_delivery_scope_store_failure_for_test(false);
            return 42;
        }

        // The teardown counterpart of the same failure. Ordinary delivery is refused above because it may be; a
        // balancing edge and a retired callable's destructors may not, so the mandatory span records the thread in the
        // stack-local registry instead. Exactness is the whole point: the span's own thread reads true and no other
        // thread does, which is what a control-plane release on an unrelated thread depends on.
        {
            std::atomic<bool> foreign_thread_in_delivery{true};
            const detail::MandatoryDeliveryScope mandatory;
            if (mandatory.depth_recorded())
            {
                std::fputs("FAIL: a mandatory span reported a recorded depth while the store was refused\n", stderr);
                (void)detail::set_delivery_scope_store_failure_for_test(false);
                return 51;
            }
            if (!detail::current_thread_in_delivery())
            {
                std::fputs("FAIL: a mandatory teardown span did not identify its own thread\n", stderr);
                (void)detail::set_delivery_scope_store_failure_for_test(false);
                return 52;
            }
            std::thread observer(
                [&foreign_thread_in_delivery]
                { foreign_thread_in_delivery.store(detail::current_thread_in_delivery(), std::memory_order_release); }
            );
            observer.join();
            if (foreign_thread_in_delivery.load(std::memory_order_acquire))
            {
                std::fputs(
                    "FAIL: a mandatory teardown span made an unrelated thread read as callback-entrant\n",
                    stderr
                );
                (void)detail::set_delivery_scope_store_failure_for_test(false);
                return 53;
            }
        }
        if (detail::current_thread_in_delivery())
        {
            std::fputs("FAIL: a mandatory teardown span outlived its own frame\n", stderr);
            (void)detail::set_delivery_scope_store_failure_for_test(false);
            return 54;
        }

        std::atomic<int> hold_calls{0};
        detail::HoldGate hold;
        hold.on_state_change = [&](bool) { hold_calls.fetch_add(1, std::memory_order_relaxed); };
        hold.deliver(true);
        hold.deliver(false);
        const int refused_calls = hold_calls.load(std::memory_order_relaxed);
        const bool refused_untouched = hold_gate_is_untouched(hold);
        hold.release();

        std::atomic<int> press_calls{0};
        detail::PressGate press;
        press.on_press = [&] { press_calls.fetch_add(1, std::memory_order_relaxed); };
        press.deliver();
        const int refused_presses = press_calls.load(std::memory_order_relaxed);
        const std::size_t refused_in_flight = press.in_flight;
        press.release();
        (void)detail::set_delivery_scope_store_failure_for_test(false);

        if (refused_calls != 0)
        {
            std::fputs("FAIL: a hold delivery ran consumer code with an unrecordable depth\n", stderr);
            return 43;
        }
        if (!refused_untouched)
        {
            std::fputs("FAIL: a refused hold delivery left gate bookkeeping behind\n", stderr);
            return 44;
        }
        if (refused_presses != 0)
        {
            std::fputs("FAIL: a press delivery ran consumer code with an unrecordable depth\n", stderr);
            return 45;
        }
        if (refused_in_flight != 0)
        {
            std::fputs("FAIL: a refused press delivery left an in-flight slot behind\n", stderr);
            return 46;
        }

        // Recovery is the other half: the refusal is per store, not a latch, so the very next ordinary delivery on the
        // same thread must reach the consumer. Without this, a permanently broken store would look like a pass.
        std::atomic<int> recovered_calls{0};
        detail::HoldGate recovered;
        recovered.on_state_change = [&](bool) { recovered_calls.fetch_add(1, std::memory_order_relaxed); };
        recovered.deliver(true);
        if (recovered_calls.load(std::memory_order_relaxed) != 1 || recovered.active_entries != 1 ||
            !recovered.forwarded_active)
        {
            std::fputs("FAIL: an ordinary delivery did not recover once the store worked again\n", stderr);
            return 47;
        }
        recovered.release();
        if (recovered_calls.load(std::memory_order_relaxed) != 2)
        {
            std::fputs("FAIL: release did not emit the balancing edge after recovery\n", stderr);
            return 48;
        }

        int error_code = 0;
        const int edges = facade_hold_edges(error_code);
        if (edges < 0)
        {
            std::fprintf(stderr, "FAIL: the facade drive could not be set up (%d)\n", error_code);
            return error_code;
        }
        if (edges == 0)
        {
            std::fputs("FAIL: the facade drive produced no held edge after recovery\n", stderr);
            return 49;
        }

        std::puts("TLS_STORE_FAILURE_REFUSES_UNTRACKED_DELIVERY");
        return 0;
    }

    int run_available_case()
    {
        std::atomic<int> hold_calls{0};
        detail::HoldGate hold;
        hold.on_state_change = [&](bool) { hold_calls.fetch_add(1, std::memory_order_relaxed); };
        hold.deliver(true);
        if (hold_calls.load(std::memory_order_relaxed) != 1 || hold.active_entries != 1 || !hold.forwarded_active)
        {
            std::fputs("FAIL: a tracked hold delivery did not reach the consumer\n", stderr);
            return 30;
        }
        hold.release();
        if (hold_calls.load(std::memory_order_relaxed) != 2)
        {
            std::fputs("FAIL: release did not emit the balancing edge for a tracked delivery\n", stderr);
            return 31;
        }

        int error_code = 0;
        const int edges = facade_hold_edges(error_code);
        if (edges < 0)
        {
            std::fprintf(stderr, "FAIL: the facade drive could not be set up (%d)\n", error_code);
            return error_code;
        }
        if (edges == 0)
        {
            std::fputs("FAIL: the facade drive produced no held edge, so the refusal case proves nothing\n", stderr);
            return 32;
        }

        std::puts("TRACKED_DELIVERY_IS_ADMITTED");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view{argv[1]} == "exhausted")
    {
        return run_exhausted_case();
    }
    if (argc == 2 && std::string_view{argv[1]} == "available")
    {
        return run_available_case();
    }
    if (argc == 2 && std::string_view{argv[1]} == "store-failure")
    {
        return run_store_failure_case();
    }
    if (argc == 2 && std::string_view{argv[1]} == "abandoned-premise")
    {
        return run_abandoned_premise_case();
    }
    // Exit status is the only oracle, so an unimplemented token must fail rather than fall through to a scenario it
    // was not registered for.
    std::fprintf(stderr, "usage: input_tls_exhaustion <exhausted|available|store-failure|abandoned-premise>\n");
    return 1;
}
