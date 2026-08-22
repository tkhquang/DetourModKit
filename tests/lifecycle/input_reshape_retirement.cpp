/**
 * @file input_reshape_retirement.cpp
 * @brief Provides isolated input reshape lifetime proofs.
 * @details See docs/tests/README.md for the proof contract.
 */

#include "DetourModKit/input.hpp"
#include "internal/input_poller.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace
{
    using DetourModKit::keyboard_key;
    using DetourModKit::input::BindingGuard;
    using DetourModKit::input::ComboBinding;
    using DetourModKit::input::Input;
    using DetourModKit::input::KeyCombo;
    using DetourModKit::input::Trigger;

    constexpr std::string_view PROBE_NAME = "reshape_probe";

    // Because this console never owns the foreground window, disable focus checks. The key seam prevents input edges.
    constexpr Input::Settings START_SETTINGS{.poll_interval = std::chrono::milliseconds{1}, .require_focus = false};

    std::atomic<bool> s_inside_reshape{false};
    std::atomic<bool> s_reentered{false};
    std::atomic<bool> s_reentered_inside_reshape{false};
    std::atomic<std::size_t> s_observed_bindings{0};

    /// Models a consumer capture whose destructor reenters the facade.
    struct ReenterOnDestroy
    {
        ~ReenterOnDestroy() noexcept
        {
            const std::size_t observed_bindings = Input::instance().binding_count();
            s_observed_bindings.store(observed_bindings, std::memory_order_relaxed);
            s_reentered_inside_reshape.store(s_inside_reshape.load(std::memory_order_acquire),
                                             std::memory_order_relaxed);
            s_reentered.store(true, std::memory_order_release);
        }
    };

    [[nodiscard]] BindingGuard register_probe(std::shared_ptr<ReenterOnDestroy> capture, int vk)
    {
        auto registration = Input::instance().register_combo(ComboBinding{
            .name = std::string{PROBE_NAME},
            .trigger = Trigger::Press,
            .combos = {KeyCombo{{keyboard_key(vk)}, {}}},
            .on_press = [keep = std::move(capture)] {},
        });
        return registration.has_value() ? std::move(*registration) : BindingGuard{};
    }

    /**
     * @brief Leaves one reshape entry as the sole owner of a consumer callable.
     * @details BindingGuard::release() drops the guard's gate reference without entry removal.
     */
    [[nodiscard]] bool stage_sole_owner(BindingGuard &guard, std::shared_ptr<ReenterOnDestroy> capture, int vk,
                                        const std::weak_ptr<ReenterOnDestroy> &observer)
    {
        guard = register_probe(std::move(capture), vk);
        if (!guard.is_active())
        {
            std::puts("FAIL: the probe binding was not registered");
            return false;
        }
        guard.release();
        if (observer.expired())
        {
            std::puts("FAIL: the guard release destroyed the callable too early");
            return false;
        }
        return true;
    }

    /// Reports the outcome every mode shares: the reshape destroyed the callable, and the reentry completed.
    [[nodiscard]] int report(const char *token, const std::weak_ptr<ReenterOnDestroy> &observer,
                             std::size_t expected_bindings)
    {
        if (!observer.expired())
        {
            std::puts("FAIL: the reshape did not destroy the consumer callable");
            return 3;
        }
        if (!s_reentered.load(std::memory_order_acquire))
        {
            std::puts("FAIL: the capture destructor never ran");
            return 4;
        }
        if (!s_reentered_inside_reshape.load(std::memory_order_relaxed))
        {
            std::puts("FAIL: the capture destructor ran outside the reshape call, so this mode proved nothing");
            return 5;
        }
        const std::size_t observed_bindings = s_observed_bindings.load(std::memory_order_relaxed);
        if (observed_bindings != expected_bindings)
        {
            std::printf("FAIL: the reentrant query saw %zu binding(s), expected %zu\n", observed_bindings,
                        expected_bindings);
            return 6;
        }
        std::puts(token);
        return 0;
    }

    [[nodiscard]] bool start_engine()
    {
        DetourModKit::detail::g_input_key_state_probe = [](int) noexcept { return false; };
        if (!Input::instance().start(START_SETTINGS).has_value())
        {
            std::puts("FAIL: the input engine did not start");
            return false;
        }
        return true;
    }

    int run_pending_remove()
    {
        auto capture = std::make_shared<ReenterOnDestroy>();
        const std::weak_ptr<ReenterOnDestroy> observer = capture;
        BindingGuard guard;
        if (!stage_sole_owner(guard, std::move(capture), 0x41, observer))
        {
            return 2;
        }

        s_inside_reshape.store(true, std::memory_order_release);
        (void)Input::instance().remove_bindings_by_name(PROBE_NAME, false);
        s_inside_reshape.store(false, std::memory_order_release);
        return report("PENDING_REMOVE_RETIRES_OUTSIDE_THE_FACADE_MUTEX", observer, 0);
    }

    int run_pending_clear()
    {
        auto capture = std::make_shared<ReenterOnDestroy>();
        const std::weak_ptr<ReenterOnDestroy> observer = capture;
        BindingGuard guard;
        if (!stage_sole_owner(guard, std::move(capture), 0x41, observer))
        {
            return 2;
        }

        s_inside_reshape.store(true, std::memory_order_release);
        Input::instance().clear_bindings(false);
        s_inside_reshape.store(false, std::memory_order_release);
        return report("PENDING_CLEAR_RETIRES_OUTSIDE_THE_FACADE_MUTEX", observer, 0);
    }

    int run_pending_shutdown()
    {
        auto capture = std::make_shared<ReenterOnDestroy>();
        const std::weak_ptr<ReenterOnDestroy> observer = capture;
        BindingGuard guard;
        if (!stage_sole_owner(guard, std::move(capture), 0x41, observer))
        {
            return 2;
        }

        s_inside_reshape.store(true, std::memory_order_release);
        Input::instance().shutdown();
        s_inside_reshape.store(false, std::memory_order_release);
        return report("PENDING_SHUTDOWN_RETIRES_OUTSIDE_THE_FACADE_MUTEX", observer, 0);
    }

    /**
     * @brief Verifies staged cardinality rebuild with one retained prototype entry.
     */
    int run_pending_cardinality()
    {
        BindingGuard prototype_guard = register_probe(nullptr, 0x41);
        if (!prototype_guard.is_active())
        {
            std::puts("FAIL: the prototype binding was not registered");
            return 2;
        }

        auto capture = std::make_shared<ReenterOnDestroy>();
        const std::weak_ptr<ReenterOnDestroy> observer = capture;
        BindingGuard guard;
        if (!stage_sole_owner(guard, std::move(capture), 0x42, observer))
        {
            return 2;
        }

        s_inside_reshape.store(true, std::memory_order_release);
        const auto rebound = Input::instance().rebind(PROBE_NAME, {KeyCombo{{keyboard_key(0x43)}, {}}});
        s_inside_reshape.store(false, std::memory_order_release);
        if (!rebound.has_value())
        {
            std::puts("FAIL: the cardinality rebind was refused");
            return 7;
        }
        return report("PENDING_CARDINALITY_RETIRES_OUTSIDE_THE_FACADE_MUTEX", observer, 1);
    }

    int run_live_remove()
    {
        auto capture = std::make_shared<ReenterOnDestroy>();
        const std::weak_ptr<ReenterOnDestroy> observer = capture;
        BindingGuard guard;
        if (!stage_sole_owner(guard, std::move(capture), 0x41, observer) || !start_engine())
        {
            return 2;
        }

        s_inside_reshape.store(true, std::memory_order_release);
        (void)Input::instance().remove_bindings_by_name(PROBE_NAME, false);
        s_inside_reshape.store(false, std::memory_order_release);
        return report("LIVE_REMOVE_RETIRES_OUTSIDE_THE_BINDING_LOCK", observer, 0);
    }

    int run_live_clear()
    {
        auto capture = std::make_shared<ReenterOnDestroy>();
        const std::weak_ptr<ReenterOnDestroy> observer = capture;
        BindingGuard guard;
        if (!stage_sole_owner(guard, std::move(capture), 0x41, observer) || !start_engine())
        {
            return 2;
        }

        s_inside_reshape.store(true, std::memory_order_release);
        Input::instance().clear_bindings(false);
        s_inside_reshape.store(false, std::memory_order_release);
        return report("LIVE_CLEAR_RETIRES_OUTSIDE_THE_BINDING_LOCK", observer, 0);
    }

    /// Verifies the live counterpart of run_pending_cardinality() with the same prototype rule.
    int run_live_rebind()
    {
        BindingGuard prototype_guard = register_probe(nullptr, 0x41);
        if (!prototype_guard.is_active())
        {
            std::puts("FAIL: the prototype binding was not registered");
            return 2;
        }

        auto capture = std::make_shared<ReenterOnDestroy>();
        const std::weak_ptr<ReenterOnDestroy> observer = capture;
        BindingGuard guard;
        if (!stage_sole_owner(guard, std::move(capture), 0x42, observer) || !start_engine())
        {
            return 2;
        }

        s_inside_reshape.store(true, std::memory_order_release);
        const auto rebound = Input::instance().rebind(PROBE_NAME, {KeyCombo{{keyboard_key(0x43)}, {}}});
        s_inside_reshape.store(false, std::memory_order_release);
        if (!rebound.has_value())
        {
            std::puts("FAIL: the live cardinality rebind was refused");
            return 7;
        }
        return report("LIVE_REBIND_RETIRES_OUTSIDE_THE_BINDING_LOCK", observer, 1);
    }

    int dispatch(int argc, char **argv)
    {
        const std::string_view scenario = argc == 2 ? std::string_view{argv[1]} : std::string_view{};
        if (scenario == "pending-remove")
        {
            return run_pending_remove();
        }
        if (scenario == "pending-clear")
        {
            return run_pending_clear();
        }
        if (scenario == "pending-shutdown")
        {
            return run_pending_shutdown();
        }
        if (scenario == "pending-cardinality")
        {
            return run_pending_cardinality();
        }
        if (scenario == "live-remove")
        {
            return run_live_remove();
        }
        if (scenario == "live-clear")
        {
            return run_live_clear();
        }
        if (scenario == "live-rebind")
        {
            return run_live_rebind();
        }

        std::printf("FAIL: unknown scenario '%s'\n", argc > 1 ? argv[1] : "(none)");
        return 8;
    }
} // namespace

int main(int argc, char **argv)
{
    const int status = dispatch(argc, argv);
    // Before static teardown, join the poll thread on every exit path.
    Input::instance().shutdown();
    DetourModKit::detail::g_input_key_state_probe = nullptr;
    return status;
}
