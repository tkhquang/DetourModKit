/**
 * @file test_logic_dll_unload.cpp
 * @brief Host proofs that DetourModKit's typed teardown really releases Logic-DLL code before the module is unmapped.
 * @details The host links the archive and owns every Hook, binding, and config registration; the companion DLL links
 *          no DetourModKit archive and contributes only callables. That split excludes a second library instance and
 *          any install-time self-reference it could take from the unmap verdict.
 *
 *          The oracle is the process exit status, so every assertion carries its own code. Each scenario runs in its
 *          own process because the input, config, and hook-ledger singletons are process-global, and because a failed
 *          safe-drain deliberately latches callback staging closed for the rest of the process.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/session.hpp"

#include "internal/input_poller.hpp"

#include "logic_dll_protocol.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>

#include <windows.h>

#if defined(_MSC_VER)
#include <crtdbg.h>
#endif

namespace DetourModKit::detail
{
    // Redeclared rather than included: internal/mid_hook_adapter.hpp pulls in safetyhook.hpp, and this host
    // deliberately carries no backend include path. mid_hook_adapter.hpp pins these same three values, so a reordered
    // enumerator fails to compile there instead of silently changing which interval this host selects.
    enum class MidRouteParkStage : std::uint8_t
    {
        None,
        BeforeAdapter,
        AfterAdapter
    };
    static_assert(static_cast<std::uint8_t>(MidRouteParkStage::None) == 0);
    static_assert(static_cast<std::uint8_t>(MidRouteParkStage::BeforeAdapter) == 1);
    static_assert(static_cast<std::uint8_t>(MidRouteParkStage::AfterAdapter) == 2);

    void set_mid_route_park_for_test(MidRouteParkStage stage) noexcept;
    [[nodiscard]] bool mid_route_park_reached_for_test() noexcept;
} // namespace DetourModKit::detail

namespace
{
    using namespace std::chrono_literals;

    using logic_dll::Channel;
    using logic_dll::Counter;

    static_assert(std::is_same_v<logic_dll::TargetFn, int (*)(int, int)>);

    constexpr int SETUP_FAILURE = 2;

    /// Unassigned virtual keys, so a synthesized edge cannot collide with a real one on the build machine.
    constexpr int PROBE_VK = VK_F24;
    constexpr int HOLD_PROBE_VK = VK_F23;

    constexpr const char *TARGET_MODULE = "hook_target_lib.dll";
    constexpr const char *TARGET_SYMBOL = "compute_damage";
    constexpr const char *BINDING_NAME = "logic.press";
    constexpr const char *HOLD_BINDING_NAME = "logic.hold";

    /// Bounded budgets. Each is far longer than the operation needs, so a slow machine cannot make a proof flaky.
    constexpr DWORD OBSERVE_BUDGET_MS = 10000;
    constexpr DWORD UNLOAD_POLL_BUDGET_MS = 3000;
    constexpr DWORD UNLOAD_POLL_STEP_MS = 10;

    /// How long the mid-teardown scenario holds its callback parked. The wait ~Hook owes must be at least this.
    constexpr DWORD MID_PARK_HOLD_MS = 250;
    constexpr DWORD MID_PARK_TOLERANCE_MS = 50;

    /**
     * @brief Asks the loader whether any module still owns @p address.
     * @details FROM_ADDRESS stays safe after the address is unmapped, reporting no owner rather than faulting.
     *          UNCHANGED_REFCOUNT is mandatory: without it the query itself takes a reference and the module under
     *          test could never unload.
     */
    [[nodiscard]] bool module_owns(const void *address) noexcept
    {
        HMODULE owner = nullptr;
        const BOOL ok =
            ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 reinterpret_cast<LPCWSTR>(address), &owner);
        return ok != FALSE && owner != nullptr;
    }

    /// Waits out the loader's unmap, which is not synchronous with the FreeLibrary that authorized it.
    [[nodiscard]] bool wait_for_unmap(const void *marker, DWORD &waited) noexcept
    {
        waited = 0;
        while (module_owns(marker) && waited < UNLOAD_POLL_BUDGET_MS)
        {
            ::Sleep(UNLOAD_POLL_STEP_MS);
            waited += UNLOAD_POLL_STEP_MS;
        }
        return !module_owns(marker);
    }

    template <class Fn> [[nodiscard]] Fn resolve(HMODULE module, const char *symbol) noexcept
    {
        return reinterpret_cast<Fn>(reinterpret_cast<void *>(::GetProcAddress(module, symbol)));
    }

    /**
     * @struct Logic
     * @brief The loaded companion DLL and every entry point the scenarios use.
     */
    struct Logic
    {
        HMODULE module = nullptr;
        const void *marker = nullptr;
        logic_dll::ResetFn reset = nullptr;
        logic_dll::CounterFn counter = nullptr;
        logic_dll::ArmParkFn arm_park = nullptr;
        logic_dll::ReleaseParkFn release_park = nullptr;
        logic_dll::WaitParkedFn wait_parked = nullptr;
        logic_dll::MakePressCallableFn make_press = nullptr;
        logic_dll::MakeHoldCallableFn make_hold = nullptr;
        logic_dll::MakeSetterCallableFn make_setter = nullptr;
        logic_dll::MakeReloadCallableFn make_reload = nullptr;
        logic_dll::FailNextCallableFactoryFn fail_next_callable_factory = nullptr;
        logic_dll::SetInlineOriginalFn set_inline_original = nullptr;
        logic_dll::MidDetourFn mid_detour = nullptr;
        logic_dll::InlineDetourFn inline_detour = nullptr;

        [[nodiscard]] std::uint64_t read(Counter which) const noexcept { return counter(static_cast<int>(which)); }
        void arm(Channel channel) const noexcept { arm_park(static_cast<int>(channel)); }
        void release(Channel channel) const noexcept { release_park(static_cast<int>(channel)); }
        [[nodiscard]] bool parked(Channel channel, DWORD budget) const noexcept
        {
            return wait_parked(static_cast<int>(channel), budget) != 0;
        }
    };

    [[nodiscard]] bool load_logic(Logic &logic) noexcept
    {
        logic.module = ::LoadLibraryA(logic_dll::MODULE_NAME);
        if (logic.module == nullptr)
        {
            std::fprintf(stderr, "SETUP: LoadLibrary(%s) failed (error %lu)\n", logic_dll::MODULE_NAME,
                         ::GetLastError());
            return false;
        }

        logic.marker = reinterpret_cast<const void *>(::GetProcAddress(logic.module, logic_dll::MARKER_SYMBOL));
        logic.reset = resolve<logic_dll::ResetFn>(logic.module, logic_dll::RESET_SYMBOL);
        logic.counter = resolve<logic_dll::CounterFn>(logic.module, logic_dll::COUNTER_SYMBOL);
        logic.arm_park = resolve<logic_dll::ArmParkFn>(logic.module, logic_dll::ARM_PARK_SYMBOL);
        logic.release_park = resolve<logic_dll::ReleaseParkFn>(logic.module, logic_dll::RELEASE_PARK_SYMBOL);
        logic.wait_parked = resolve<logic_dll::WaitParkedFn>(logic.module, logic_dll::WAIT_PARKED_SYMBOL);
        logic.make_press = resolve<logic_dll::MakePressCallableFn>(logic.module, logic_dll::MAKE_PRESS_CALLABLE_SYMBOL);
        logic.make_hold = resolve<logic_dll::MakeHoldCallableFn>(logic.module, logic_dll::MAKE_HOLD_CALLABLE_SYMBOL);
        logic.make_setter =
            resolve<logic_dll::MakeSetterCallableFn>(logic.module, logic_dll::MAKE_SETTER_CALLABLE_SYMBOL);
        logic.make_reload =
            resolve<logic_dll::MakeReloadCallableFn>(logic.module, logic_dll::MAKE_RELOAD_CALLABLE_SYMBOL);
        logic.fail_next_callable_factory =
            resolve<logic_dll::FailNextCallableFactoryFn>(logic.module, logic_dll::FAIL_NEXT_CALLABLE_FACTORY_SYMBOL);
        logic.set_inline_original =
            resolve<logic_dll::SetInlineOriginalFn>(logic.module, logic_dll::SET_INLINE_ORIGINAL_SYMBOL);
        logic.mid_detour = resolve<logic_dll::MidDetourFn>(logic.module, logic_dll::MID_DETOUR_SYMBOL);
        logic.inline_detour = resolve<logic_dll::InlineDetourFn>(logic.module, logic_dll::INLINE_DETOUR_SYMBOL);

        const bool complete =
            logic.marker != nullptr && logic.reset != nullptr && logic.counter != nullptr &&
            logic.arm_park != nullptr && logic.release_park != nullptr && logic.wait_parked != nullptr &&
            logic.make_press != nullptr && logic.make_hold != nullptr && logic.make_setter != nullptr &&
            logic.make_reload != nullptr && logic.fail_next_callable_factory != nullptr &&
            logic.set_inline_original != nullptr && logic.mid_detour != nullptr && logic.inline_detour != nullptr;
        if (!complete)
        {
            std::fprintf(stderr, "SETUP: the logic DLL is missing an export\n");
            return false;
        }

        logic.reset();
        logic.fail_next_callable_factory();
        std::function<void()> refused_callable;
        logic.make_press(&refused_callable);
        if (refused_callable)
        {
            std::fprintf(stderr, "SETUP: the logic DLL published a callable after its injected factory failure\n");
            return false;
        }
        return true;
    }

    [[nodiscard]] logic_dll::TargetFn load_hook_target(HMODULE &module) noexcept
    {
        module = ::LoadLibraryA(TARGET_MODULE);
        if (module == nullptr)
        {
            std::fprintf(stderr, "SETUP: LoadLibrary(%s) failed (error %lu)\n", TARGET_MODULE, ::GetLastError());
            return nullptr;
        }
        const auto target = resolve<logic_dll::TargetFn>(module, TARGET_SYMBOL);
        if (target == nullptr)
        {
            std::fprintf(stderr, "SETUP: %s export not found\n", TARGET_SYMBOL);
        }
        return target;
    }

    /// Waits for a DLL tally to reach @p wanted, so a scenario never asserts against work that has not happened yet.
    [[nodiscard]] bool await_counter(const Logic &logic, Counter which, std::uint64_t wanted) noexcept
    {
        for (DWORD waited = 0; waited < OBSERVE_BUDGET_MS; waited += UNLOAD_POLL_STEP_MS)
        {
            if (logic.read(which) >= wanted)
            {
                return true;
            }
            ::Sleep(UNLOAD_POLL_STEP_MS);
        }
        return logic.read(which) >= wanted;
    }

    [[nodiscard]] const char *status_name(DetourModKit::LogicDllUnloadStatus status) noexcept
    {
        switch (status)
        {
        case DetourModKit::LogicDllUnloadStatus::SafeToUnload:
            return "SafeToUnload";
        case DetourModKit::LogicDllUnloadStatus::LoaderLock:
            return "LoaderLock";
        case DetourModKit::LogicDllUnloadStatus::SelfDelivery:
            return "SelfDelivery";
        case DetourModKit::LogicDllUnloadStatus::InProgress:
            return "InProgress";
        case DetourModKit::LogicDllUnloadStatus::RetireFailed:
            return "RetireFailed";
        case DetourModKit::LogicDllUnloadStatus::TimedOut:
            return "TimedOut";
        }
        return "Unknown";
    }

    /// Publishes the synthesized key state the poller reads instead of GetAsyncKeyState.
    std::atomic<bool> s_probe_key_down{false};
    std::atomic<bool> s_hold_probe_key_down{false};
    std::atomic<std::uint32_t> s_ini_sequence{0};

    void install_key_probe() noexcept
    {
        DetourModKit::detail::g_input_key_state_probe = [](int vk) noexcept
        {
            if (vk == HOLD_PROBE_VK)
            {
                return s_hold_probe_key_down.load(std::memory_order_acquire);
            }
            return vk == PROBE_VK && s_probe_key_down.load(std::memory_order_acquire);
        };
    }

    /// The poller must be joined first: clearing the probe while the poll loop reads it is a data race.
    void stop_input_and_clear_probe() noexcept
    {
        DetourModKit::input::Input::instance().shutdown();
        DetourModKit::detail::g_input_key_state_probe = nullptr;
    }

    [[nodiscard]] DetourModKit::input::ComboBinding make_press_binding(std::function<void()> callable)
    {
        DetourModKit::input::KeyCombo combo;
        combo.keys.push_back(DetourModKit::keyboard_key(PROBE_VK));

        DetourModKit::input::ComboBinding binding;
        binding.name = BINDING_NAME;
        binding.trigger = DetourModKit::input::Trigger::Press;
        binding.combos.push_back(std::move(combo));
        binding.on_press = std::move(callable);
        return binding;
    }

    [[nodiscard]] DetourModKit::input::ComboBinding make_hold_binding(std::function<void(bool)> callable)
    {
        DetourModKit::input::KeyCombo combo;
        combo.keys.push_back(DetourModKit::keyboard_key(HOLD_PROBE_VK));

        DetourModKit::input::ComboBinding binding;
        binding.name = HOLD_BINDING_NAME;
        binding.trigger = DetourModKit::input::Trigger::Hold;
        binding.combos.push_back(std::move(combo));
        binding.on_state_change = std::move(callable);
        return binding;
    }

    [[nodiscard]] std::string make_ini_file_name()
    {
        const std::uint32_t sequence = s_ini_sequence.fetch_add(1, std::memory_order_relaxed);
        return "logic_dll_proof_" + std::to_string(::GetCurrentProcessId()) + "_" + std::to_string(sequence) + ".ini";
    }

    class TemporaryIniFile
    {
    public:
        TemporaryIniFile() : m_path(make_ini_file_name()) {}

        TemporaryIniFile(const TemporaryIniFile &) = delete;
        TemporaryIniFile &operator=(const TemporaryIniFile &) = delete;
        TemporaryIniFile(TemporaryIniFile &&) = delete;
        TemporaryIniFile &operator=(TemporaryIniFile &&) = delete;

        ~TemporaryIniFile() noexcept { (void)::DeleteFileA(m_path.c_str()); }

        [[nodiscard]] const std::string &path() const noexcept { return m_path; }

    private:
        std::string m_path;
    };

    [[nodiscard]] bool write_ini(const std::string &path, int value)
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file)
        {
            return false;
        }
        file << "[Proof]\r\nvalue=" << value << "\r\n";
        return file.good();
    }

    /**
     * @brief Registers one DLL-provided press callable and drives it once, then proves the typed drain releases it.
     * @details The claim is exact: when prepare_logic_dll_unload reports SafeToUnload, DetourModKit owns no remaining
     *          copy of the DLL's callable. The construct/destroy tallies are what make that checkable, since a
     *          successful status alone would also be reported by an implementation that simply stopped counting.
     */
    int run_input_drained(Logic &logic)
    {
        install_key_probe();

        DetourModKit::input::BindingGuard guard;
        {
            std::function<void()> callable;
            logic.make_press(&callable);
            if (!callable)
            {
                std::fprintf(stderr, "SETUP[input-drained]: the DLL could not construct its press callable\n");
                return SETUP_FAILURE;
            }
            auto registered = DetourModKit::input::register_combo(make_press_binding(std::move(callable)));
            if (!registered)
            {
                std::fprintf(stderr, "FAIL[input-drained]: register_combo failed: %s\n",
                             DetourModKit::to_string(registered.error().code).data());
                return 10;
            }
            guard = std::move(*registered);
        }

        if (const auto started = DetourModKit::input::Input::instance().start(
                DetourModKit::input::Input::Settings{.poll_interval = 1ms, .require_focus = false});
            !started)
        {
            std::fprintf(stderr, "FAIL[input-drained]: Input::start failed: %s\n",
                         DetourModKit::to_string(started.error().code).data());
            return 11;
        }

        s_probe_key_down.store(true, std::memory_order_release);
        if (!await_counter(logic, Counter::PressInvoked, 1))
        {
            std::fprintf(stderr, "FAIL[input-drained]: the DLL callback never ran; the proof would be vacuous\n");
            stop_input_and_clear_probe();
            return 12;
        }
        s_probe_key_down.store(false, std::memory_order_release);

        // The ordinary shutdown order: drop the guard, then drain. run_input_guard_retained covers the other order.
        guard = DetourModKit::input::BindingGuard{};

        const std::string_view names[] = {BINDING_NAME};
        const auto status = DetourModKit::prepare_logic_dll_unload(std::span<const std::string_view>{names}, 5000ms);
        if (status != DetourModKit::LogicDllUnloadStatus::SafeToUnload)
        {
            std::fprintf(stderr, "FAIL[input-drained]: expected SafeToUnload for an idle binding, got %s\n",
                         status_name(status));
            stop_input_and_clear_probe();
            return 13;
        }

        const std::uint64_t constructed = logic.read(Counter::CallableConstructed);
        const std::uint64_t destroyed = logic.read(Counter::CallableDestroyed);
        if (constructed == 0)
        {
            std::fprintf(stderr, "FAIL[input-drained]: no DLL callable was ever constructed\n");
            stop_input_and_clear_probe();
            return 14;
        }
        if (destroyed != constructed)
        {
            std::fprintf(stderr,
                         "FAIL[input-drained]: SafeToUnload was reported with %llu of %llu DLL callable copies still "
                         "alive; unmapping now would leave the library holding freed code\n",
                         static_cast<unsigned long long>(constructed - destroyed),
                         static_cast<unsigned long long>(constructed));
            stop_input_and_clear_probe();
            return 15;
        }

        stop_input_and_clear_probe();

        const void *marker = logic.marker;
        if (::FreeLibrary(logic.module) == FALSE)
        {
            std::fprintf(stderr, "FAIL[input-drained]: FreeLibrary failed (error %lu)\n", ::GetLastError());
            return 16;
        }
        logic.module = nullptr;

        DWORD waited = 0;
        if (!wait_for_unmap(marker, waited))
        {
            std::fprintf(stderr, "FAIL[input-drained]: the logic DLL is still mapped %lu ms after FreeLibrary\n",
                         waited);
            return 17;
        }

        std::printf("PASS[input-drained]: %llu DLL callable copies were all destroyed before SafeToUnload, and the "
                    "module unmapped after %lu ms\n",
                    static_cast<unsigned long long>(constructed), waited);
        return 0;
    }

    /**
     * @brief Proves SafeToUnload is truthful even when the consumer keeps its BindingGuard across the drain.
     * @details register_combo gives the binding's delivery gate two strong owners: the poller's engine entries, and
     *          the one-shot release closure inside the BindingGuard. The gate owns the consumer callable, so removing
     *          the engine entries alone leaves DLL code alive behind the retained guard while the retire check, which
     *          only asks whether the name is gone from the poller, still answers SafeToUnload.
     *
     *          Retirement therefore reaches the gate itself and destroys the callable there. This case keeps the
     *          guard deliberately, and requires the tally to balance at SafeToUnload rather than at the later
     *          release, which is what makes the status safe to unmap on without an ordering precondition.
     */
    int run_input_guard_retained(Logic &logic)
    {
        install_key_probe();

        DetourModKit::input::BindingGuard guard;
        {
            std::function<void()> callable;
            logic.make_press(&callable);
            if (!callable)
            {
                std::fprintf(stderr, "SETUP[guard-retained]: the DLL could not construct its press callable\n");
                return SETUP_FAILURE;
            }
            auto registered = DetourModKit::input::register_combo(make_press_binding(std::move(callable)));
            if (!registered)
            {
                std::fprintf(stderr, "FAIL[guard-retained]: register_combo failed: %s\n",
                             DetourModKit::to_string(registered.error().code).data());
                return 70;
            }
            guard = std::move(*registered);
        }

        if (const auto started = DetourModKit::input::Input::instance().start(
                DetourModKit::input::Input::Settings{.poll_interval = 1ms, .require_focus = false});
            !started)
        {
            std::fprintf(stderr, "FAIL[guard-retained]: Input::start failed: %s\n",
                         DetourModKit::to_string(started.error().code).data());
            return 71;
        }

        s_probe_key_down.store(true, std::memory_order_release);
        if (!await_counter(logic, Counter::PressInvoked, 1))
        {
            std::fprintf(stderr, "FAIL[guard-retained]: the DLL callback never ran; the proof would be vacuous\n");
            stop_input_and_clear_probe();
            return 72;
        }
        s_probe_key_down.store(false, std::memory_order_release);

        // Deliberately retain the guard. Retirement takes the callable out of the gate, so the guard cannot keep one
        // alive.
        const std::string_view names[] = {BINDING_NAME};
        const auto status = DetourModKit::prepare_logic_dll_unload(std::span<const std::string_view>{names}, 5000ms);

        const std::uint64_t constructed = logic.read(Counter::CallableConstructed);
        const std::uint64_t after_prepare = logic.read(Counter::CallableDestroyed);

        guard = DetourModKit::input::BindingGuard{};
        const std::uint64_t after_guard = logic.read(Counter::CallableDestroyed);

        stop_input_and_clear_probe();

        if (status != DetourModKit::LogicDllUnloadStatus::SafeToUnload)
        {
            std::fprintf(stderr, "FAIL[guard-retained]: expected SafeToUnload with the guard retained, got %s\n",
                         status_name(status));
            return 73;
        }
        if (constructed == 0)
        {
            std::fprintf(stderr, "FAIL[guard-retained]: no DLL callable was ever constructed\n");
            return 74;
        }
        if (after_prepare != constructed)
        {
            std::fprintf(stderr,
                         "FAIL[guard-retained]: SafeToUnload was reported with %llu of %llu DLL callable copies still "
                         "alive behind the retained guard; unmapping now would leave freed code reachable from it\n",
                         static_cast<unsigned long long>(constructed - after_prepare),
                         static_cast<unsigned long long>(constructed));
            return 75;
        }
        if (after_guard != after_prepare)
        {
            std::fprintf(stderr,
                         "FAIL[guard-retained]: dropping the guard destroyed %llu further callable copies, so the "
                         "drain did not actually take ownership of them\n",
                         static_cast<unsigned long long>(after_guard - after_prepare));
            return 76;
        }

        std::printf("PASS[guard-retained]: all %llu DLL callable copies were destroyed by the drain itself with the "
                    "guard still held, and dropping it afterwards destroyed nothing further\n",
                    static_cast<unsigned long long>(constructed));
        return 0;
    }

    /**
     * @brief Proves a Hold binding still held at the drain is balanced by the drain, not by a later guard release.
     * @details The press case covers destruction. A held Hold binding is the sharper half: the gate still owes a
     *          balancing on_state_change(false), which is an indirect CALL into the provider rather than a
     *          destructor, so deferring it to the guard would execute freed pages after an unmap rather than merely
     *          free through them. Retirement emits that edge while the DLL is mapped and then takes the callable, so
     *          the tally must move during the drain and stay put when the guard is dropped afterwards.
     */
    int run_hold_guard_retained(Logic &logic)
    {
        install_key_probe();

        DetourModKit::input::BindingGuard guard;
        {
            std::function<void(bool)> callable;
            logic.make_hold(&callable);
            if (!callable)
            {
                std::fprintf(stderr, "SETUP[guard-retained-hold]: the DLL could not construct its hold callable\n");
                return SETUP_FAILURE;
            }
            auto registered = DetourModKit::input::register_combo(make_hold_binding(std::move(callable)));
            if (!registered)
            {
                std::fprintf(stderr, "FAIL[guard-retained-hold]: register_combo failed: %s\n",
                             DetourModKit::to_string(registered.error().code).data());
                return 90;
            }
            guard = std::move(*registered);
        }

        if (const auto started = DetourModKit::input::Input::instance().start(
                DetourModKit::input::Input::Settings{.poll_interval = 1ms, .require_focus = false});
            !started)
        {
            std::fprintf(stderr, "FAIL[guard-retained-hold]: Input::start failed: %s\n",
                         DetourModKit::to_string(started.error().code).data());
            return 91;
        }

        // The chord stays down for the whole scenario: the hazard needs a binding that is still HELD when the drain
        // retires it, so the balancing edge is still owed.
        s_hold_probe_key_down.store(true, std::memory_order_release);
        if (!await_counter(logic, Counter::HoldInvoked, 1))
        {
            std::fprintf(stderr, "FAIL[guard-retained-hold]: the DLL hold callback never saw its true edge\n");
            stop_input_and_clear_probe();
            return 92;
        }

        // Deliberately NOT dropping the guard. Retirement owes the balancing edge here, while the DLL is mapped.
        const std::string_view names[] = {HOLD_BINDING_NAME};
        const auto status = DetourModKit::prepare_logic_dll_unload(std::span<const std::string_view>{names}, 5000ms);
        const std::uint64_t after_prepare = logic.read(Counter::HoldInvoked);
        const std::uint64_t destroyed_after_prepare = logic.read(Counter::CallableDestroyed);
        const std::uint64_t constructed = logic.read(Counter::CallableConstructed);

        // Dropping the guard here is what a host would do after unmapping. Nothing is unmapped in this process, so a
        // call that should not happen still lands on live code and is counted instead of faulting.
        guard = DetourModKit::input::BindingGuard{};
        const std::uint64_t after_guard = logic.read(Counter::HoldInvoked);

        s_hold_probe_key_down.store(false, std::memory_order_release);
        stop_input_and_clear_probe();

        if (status != DetourModKit::LogicDllUnloadStatus::SafeToUnload)
        {
            std::fprintf(stderr, "FAIL[guard-retained-hold]: expected SafeToUnload with the guard retained, got %s\n",
                         status_name(status));
            return 93;
        }
        if (after_prepare != 2)
        {
            std::fprintf(stderr,
                         "FAIL[guard-retained-hold]: the drain left the held binding at %llu invocations, so it did "
                         "not deliver the balancing edge while the DLL was still mapped\n",
                         static_cast<unsigned long long>(after_prepare));
            return 94;
        }
        if (after_guard != after_prepare)
        {
            std::fprintf(stderr,
                         "FAIL[guard-retained-hold]: dropping the guard CALLED the DLL callback again (%llu total); "
                         "after an unmap that call would execute freed pages\n",
                         static_cast<unsigned long long>(after_guard));
            return 95;
        }
        if (constructed == 0 || destroyed_after_prepare != constructed)
        {
            std::fprintf(stderr,
                         "FAIL[guard-retained-hold]: SafeToUnload was reported with %llu of %llu hold callable copies "
                         "still alive\n",
                         static_cast<unsigned long long>(constructed - destroyed_after_prepare),
                         static_cast<unsigned long long>(constructed));
            return 96;
        }

        std::printf("PASS[guard-retained-hold]: the drain delivered the held binding's balancing edge and destroyed "
                    "all %llu callable copies; dropping the retained guard afterwards called nothing\n",
                    static_cast<unsigned long long>(constructed));
        return 0;
    }

    /**
     * @brief Parks the DLL callback body and proves the typed drain refuses rather than authorizing an unmap.
     * @details This is the discriminating half of the pair. An implementation that counted only registration, or that
     *          released its staging lease before the callable's storage died, would report SafeToUnload here while
     *          the DLL's code is still on a stack.
     */
    int run_input_parked(Logic &logic)
    {
        install_key_probe();
        logic.arm(Channel::Press);

        DetourModKit::input::BindingGuard guard;
        {
            std::function<void()> callable;
            logic.make_press(&callable);
            if (!callable)
            {
                std::fprintf(stderr, "SETUP[input-parked]: the DLL could not construct its press callable\n");
                return SETUP_FAILURE;
            }
            auto registered = DetourModKit::input::register_combo(make_press_binding(std::move(callable)));
            if (!registered)
            {
                std::fprintf(stderr, "FAIL[input-parked]: register_combo failed: %s\n",
                             DetourModKit::to_string(registered.error().code).data());
                return 20;
            }
            guard = std::move(*registered);
        }

        if (const auto started = DetourModKit::input::Input::instance().start(
                DetourModKit::input::Input::Settings{.poll_interval = 1ms, .require_focus = false});
            !started)
        {
            std::fprintf(stderr, "FAIL[input-parked]: Input::start failed: %s\n",
                         DetourModKit::to_string(started.error().code).data());
            return 21;
        }

        s_probe_key_down.store(true, std::memory_order_release);
        if (!logic.parked(Channel::Press, OBSERVE_BUDGET_MS))
        {
            std::fprintf(stderr, "FAIL[input-parked]: the DLL callback never entered its park\n");
            logic.release(Channel::Press);
            stop_input_and_clear_probe();
            return 22;
        }

        const std::string_view names[] = {BINDING_NAME};
        const auto status = DetourModKit::prepare_logic_dll_unload(std::span<const std::string_view>{names}, 300ms);

        const std::uint64_t constructed = logic.read(Counter::CallableConstructed);
        const std::uint64_t destroyed = logic.read(Counter::CallableDestroyed);

        logic.release(Channel::Press);
        s_probe_key_down.store(false, std::memory_order_release);
        stop_input_and_clear_probe();
        guard = DetourModKit::input::BindingGuard{};

        if (status == DetourModKit::LogicDllUnloadStatus::SafeToUnload)
        {
            std::fprintf(stderr, "FAIL[input-parked]: SafeToUnload was reported while a DLL callback body was parked "
                                 "on the poll thread; a caller that trusted it would unmap running code\n");
            return 23;
        }
        if (status != DetourModKit::LogicDllUnloadStatus::TimedOut)
        {
            std::fprintf(stderr, "FAIL[input-parked]: expected TimedOut for a parked callback body, got %s\n",
                         status_name(status));
            return 24;
        }
        if (destroyed >= constructed)
        {
            std::fprintf(stderr,
                         "FAIL[input-parked]: the refusal is untrustworthy: all %llu DLL callable copies were already "
                         "destroyed, so the deadline expired on something other than the parked callable\n",
                         static_cast<unsigned long long>(constructed));
            return 25;
        }

        std::printf("PASS[input-parked]: the typed drain returned TimedOut with %llu DLL callable copies still alive, "
                    "and never authorized the unmap\n",
                    static_cast<unsigned long long>(constructed - destroyed));
        return 0;
    }

    /**
     * @brief Parks a DLL config setter on the watcher thread across the composed typed drain.
     * @details The watcher owns the admitted reload pass across both the setter loop and notification callback. A
     *          SafeToUnload while this setter is parked would authorize unmapping code still on its worker stack.
     */
    int run_config_setter_parked(Logic &logic)
    {
        const TemporaryIniFile ini_file;
        if (!write_ini(ini_file.path(), 1))
        {
            std::fprintf(stderr, "FAIL[config-setter-parked]: could not write %s\n", ini_file.path().c_str());
            return 80;
        }

        {
            std::function<void(int)> setter;
            logic.make_setter(&setter);
            if (!setter)
            {
                std::fprintf(stderr, "SETUP[config-setter-parked]: the DLL could not construct its setter\n");
                return SETUP_FAILURE;
            }
            DetourModKit::config::bind_int("Proof", "value", "proof value", std::move(setter), 0);
        }

        DetourModKit::config::load(ini_file.path());
        if (!await_counter(logic, Counter::SetterInvoked, 1))
        {
            std::fprintf(stderr,
                         "FAIL[config-setter-parked]: the DLL setter never ran, so the registration did not take\n");
            return 81;
        }

        const auto auto_reload = DetourModKit::config::enable_auto_reload(50ms);
        if (auto_reload != DetourModKit::config::AutoReloadStatus::Started)
        {
            std::fprintf(stderr, "FAIL[config-setter-parked]: enable_auto_reload did not start the watcher\n");
            DetourModKit::config::disable_auto_reload();
            return 82;
        }

        logic.arm(Channel::Setter);
        if (!write_ini(ini_file.path(), 2))
        {
            std::fprintf(stderr, "FAIL[config-setter-parked]: could not rewrite %s\n", ini_file.path().c_str());
            logic.release(Channel::Setter);
            DetourModKit::config::disable_auto_reload();
            return 83;
        }

        if (!logic.parked(Channel::Setter, OBSERVE_BUDGET_MS))
        {
            std::fprintf(stderr,
                         "FAIL[config-setter-parked]: the watcher never delivered a reload into the DLL setter\n");
            logic.release(Channel::Setter);
            DetourModKit::config::disable_auto_reload();
            return 84;
        }

        const auto status = DetourModKit::prepare_logic_dll_unload_all(300ms);

        logic.release(Channel::Setter);
        const auto retry_status = DetourModKit::prepare_logic_dll_unload_all(5000ms);

        const std::uint64_t constructed = logic.read(Counter::CallableConstructed);
        const std::uint64_t destroyed = logic.read(Counter::CallableDestroyed);

        if (status != DetourModKit::LogicDllUnloadStatus::TimedOut)
        {
            std::fprintf(stderr, "FAIL[config-setter-parked]: expected TimedOut for a parked setter, got %s\n",
                         status_name(status));
            return 85;
        }
        if (retry_status != DetourModKit::LogicDllUnloadStatus::SafeToUnload)
        {
            std::fprintf(stderr, "FAIL[config-setter-parked]: retry after releasing the setter returned %s\n",
                         status_name(retry_status));
            DetourModKit::config::disable_auto_reload();
            DetourModKit::config::clear();
            return 86;
        }
        if (destroyed != constructed)
        {
            std::fprintf(stderr,
                         "FAIL[config-setter-parked]: SafeToUnload left %llu DLL callable copies alive after retry\n",
                         static_cast<unsigned long long>(constructed - destroyed));
            return 87;
        }

        // No disable_auto_reload() or clear() before the unmap, deliberately. The claim under test is that
        // SafeToUnload ALONE authorizes it: the drain already requested watcher/servicer stop and observed their
        // exit, and the assertion above proves it destroyed every DLL callable. Quiescing config here by hand would
        // downgrade the proof to "the drain plus extra host cleanup is sufficient", which is the weaker property.
        const void *marker = logic.marker;
        if (::FreeLibrary(logic.module) == FALSE)
        {
            std::fprintf(stderr, "FAIL[config-setter-parked]: FreeLibrary failed (error %lu)\n", ::GetLastError());
            return 88;
        }
        logic.module = nullptr;

        DWORD unmap_waited = 0;
        if (!wait_for_unmap(marker, unmap_waited))
        {
            std::fprintf(stderr, "FAIL[config-setter-parked]: the logic DLL is still mapped %lu ms after retry\n",
                         unmap_waited);
            return 89;
        }

        std::printf("PASS[config-setter-parked]: the parked setter forced TimedOut; after release, retry destroyed "
                    "every callable and the module unmapped\n");
        return 0;
    }

    /**
     * @brief Parks a DLL reload-notification body on the watcher thread across the composed typed drain.
     * @details Input and config rundown are separate contracts composed under one deadline. This scenario holds only
     *          the config half, so a SafeToUnload here would mean the composition reported the whole transaction
     *          drained while a config callback was still executing DLL code.
     */
    int run_config_parked(Logic &logic)
    {
        const TemporaryIniFile ini_file;
        if (!write_ini(ini_file.path(), 1))
        {
            std::fprintf(stderr, "FAIL[config-parked]: could not write %s\n", ini_file.path().c_str());
            return 30;
        }

        {
            std::function<void(int)> setter;
            logic.make_setter(&setter);
            if (!setter)
            {
                std::fprintf(stderr, "SETUP[config-parked]: the DLL could not construct its setter\n");
                return SETUP_FAILURE;
            }
            DetourModKit::config::bind_int("Proof", "value", "proof value", std::move(setter), 0);
        }

        DetourModKit::config::load(ini_file.path());
        if (!await_counter(logic, Counter::SetterInvoked, 1))
        {
            std::fprintf(stderr, "FAIL[config-parked]: the DLL setter never ran, so the registration did not take\n");
            return 31;
        }

        logic.arm(Channel::Reload);

        std::function<void(bool)> on_reload;
        logic.make_reload(&on_reload);
        if (!on_reload)
        {
            std::fprintf(stderr, "SETUP[config-parked]: the DLL could not construct its reload callback\n");
            return SETUP_FAILURE;
        }
        const auto auto_reload = DetourModKit::config::enable_auto_reload(50ms, std::move(on_reload));
        if (auto_reload != DetourModKit::config::AutoReloadStatus::Started)
        {
            std::fprintf(stderr, "FAIL[config-parked]: enable_auto_reload did not start the watcher\n");
            logic.release(Channel::Reload);
            DetourModKit::config::disable_auto_reload();
            return 32;
        }

        if (!write_ini(ini_file.path(), 2))
        {
            std::fprintf(stderr, "FAIL[config-parked]: could not rewrite %s\n", ini_file.path().c_str());
            logic.release(Channel::Reload);
            DetourModKit::config::disable_auto_reload();
            return 33;
        }

        if (!logic.parked(Channel::Reload, OBSERVE_BUDGET_MS))
        {
            std::fprintf(stderr, "FAIL[config-parked]: the watcher never delivered a reload into the DLL callable\n");
            logic.release(Channel::Reload);
            DetourModKit::config::disable_auto_reload();
            return 34;
        }

        const auto status = DetourModKit::prepare_logic_dll_unload_all(300ms);

        logic.release(Channel::Reload);
        const auto retry_status = DetourModKit::prepare_logic_dll_unload_all(5000ms);

        const std::uint64_t constructed = logic.read(Counter::CallableConstructed);
        const std::uint64_t destroyed = logic.read(Counter::CallableDestroyed);

        if (status != DetourModKit::LogicDllUnloadStatus::TimedOut)
        {
            std::fprintf(stderr, "FAIL[config-parked]: expected TimedOut for a parked reload callback, got %s\n",
                         status_name(status));
            return 35;
        }
        if (retry_status != DetourModKit::LogicDllUnloadStatus::SafeToUnload)
        {
            std::fprintf(stderr, "FAIL[config-parked]: retry after releasing the reload callback returned %s\n",
                         status_name(retry_status));
            DetourModKit::config::disable_auto_reload();
            DetourModKit::config::clear();
            return 36;
        }
        if (destroyed != constructed)
        {
            std::fprintf(stderr, "FAIL[config-parked]: SafeToUnload left %llu DLL callable copies alive after retry\n",
                         static_cast<unsigned long long>(constructed - destroyed));
            return 37;
        }

        // Same deliberate omission as config-setter-parked: quiescing config by hand before the unmap would prove
        // only that the drain plus extra host cleanup is sufficient, not that SafeToUnload alone authorizes it.
        const void *marker = logic.marker;
        if (::FreeLibrary(logic.module) == FALSE)
        {
            std::fprintf(stderr, "FAIL[config-parked]: FreeLibrary failed (error %lu)\n", ::GetLastError());
            return 38;
        }
        logic.module = nullptr;

        DWORD unmap_waited = 0;
        if (!wait_for_unmap(marker, unmap_waited))
        {
            std::fprintf(stderr, "FAIL[config-parked]: the logic DLL is still mapped %lu ms after retry\n",
                         unmap_waited);
            return 39;
        }

        std::printf("PASS[config-parked]: the parked reload callback forced TimedOut; after release, retry destroyed "
                    "every callable and the module unmapped\n");
        return 0;
    }

    /**
     * @brief Proves ~Hook waits out a managed mid callback that is executing DLL code.
     * @details A mid hook is the one surface where DetourModKit owns quiescence. The measured wait is the assertion:
     *          a teardown that returned before the release would let the host unmap a module whose code is on a
     *          stack, which is precisely what the tombstone plus rundown exists to prevent.
     */
    int run_mid_parked(Logic &logic)
    {
        HMODULE target_module = nullptr;
        const logic_dll::TargetFn target = load_hook_target(target_module);
        if (target == nullptr)
        {
            return SETUP_FAILURE;
        }

        auto created = DetourModKit::hook::mid_at(
            DetourModKit::hook::MidRequest{.name = "logic.mid", .target = DetourModKit::Address{target}},
            logic.mid_detour);
        if (!created)
        {
            std::fprintf(stderr, "FAIL[mid-parked]: mid_at failed: %s\n",
                         DetourModKit::to_string(created.error().code).data());
            return 40;
        }

        std::optional<DetourModKit::hook::Hook> hook{std::move(*created)};
        if (const auto armed = hook->enable(); !armed)
        {
            std::fprintf(stderr, "FAIL[mid-parked]: enable failed: %s\n",
                         DetourModKit::to_string(armed.error().code).data());
            return 41;
        }

        logic.arm(Channel::Mid);
        std::thread caller([target]() noexcept { (void)target(10, 5); });

        if (!logic.parked(Channel::Mid, OBSERVE_BUDGET_MS))
        {
            std::fprintf(stderr, "FAIL[mid-parked]: the DLL mid detour never entered its park\n");
            logic.release(Channel::Mid);
            caller.join();
            return 42;
        }

        const auto started_at = std::chrono::steady_clock::now();
        std::thread releaser(
            [&logic]() noexcept
            {
                ::Sleep(MID_PARK_HOLD_MS);
                logic.release(Channel::Mid);
            });

        hook.reset();
        const auto waited =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started_at);

        releaser.join();
        caller.join();

        if (waited.count() + MID_PARK_TOLERANCE_MS < MID_PARK_HOLD_MS)
        {
            std::fprintf(stderr,
                         "FAIL[mid-parked]: ~Hook returned after %lld ms while the callback was parked for %lu ms; it "
                         "did not run the callback down\n",
                         static_cast<long long>(waited.count()), static_cast<unsigned long>(MID_PARK_HOLD_MS));
            return 43;
        }
        if (logic.read(Counter::MidInvoked) != 1)
        {
            std::fprintf(stderr, "FAIL[mid-parked]: expected exactly one mid dispatch, saw %llu\n",
                         static_cast<unsigned long long>(logic.read(Counter::MidInvoked)));
            return 44;
        }

        const void *marker = logic.marker;
        if (::FreeLibrary(logic.module) == FALSE)
        {
            std::fprintf(stderr, "FAIL[mid-parked]: FreeLibrary failed (error %lu)\n", ::GetLastError());
            return 45;
        }
        logic.module = nullptr;

        DWORD unmap_waited = 0;
        if (!wait_for_unmap(marker, unmap_waited))
        {
            std::fprintf(stderr, "FAIL[mid-parked]: the logic DLL is still mapped %lu ms after teardown\n",
                         unmap_waited);
            return 46;
        }

        std::printf("PASS[mid-parked]: ~Hook waited %lld ms for the parked DLL callback, then the module unmapped\n",
                    static_cast<long long>(waited.count()));
        return 0;
    }

    int run_mid_route_parked(Logic &logic, DetourModKit::detail::MidRouteParkStage stage, const char *scenario)
    {
        HMODULE target_module = nullptr;
        const logic_dll::TargetFn target = load_hook_target(target_module);
        if (target == nullptr)
        {
            return SETUP_FAILURE;
        }
        const int baseline = target(10, 5);

        auto created = DetourModKit::hook::mid_at(
            DetourModKit::hook::MidRequest{.name = scenario, .target = DetourModKit::Address{target}},
            logic.mid_detour);
        if (!created || !created->enable())
        {
            std::fprintf(stderr, "FAIL[%s]: could not arm the managed mid hook\n", scenario);
            return 69;
        }
        std::optional<DetourModKit::hook::Hook> hook{std::move(*created)};

        DetourModKit::detail::set_mid_route_park_for_test(stage);
        std::thread caller([target]() noexcept { (void)target(10, 5); });
        const ULONGLONG deadline = ::GetTickCount64() + OBSERVE_BUDGET_MS;
        while (!DetourModKit::detail::mid_route_park_reached_for_test() && ::GetTickCount64() < deadline)
        {
            std::this_thread::yield();
        }
        if (!DetourModKit::detail::mid_route_park_reached_for_test())
        {
            DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::None);
            caller.join();
            std::fprintf(stderr, "FAIL[%s]: caller never reached the selected backend route interval\n", scenario);
            return 70;
        }

        const std::uint64_t expected_dispatches =
            stage == DetourModKit::detail::MidRouteParkStage::AfterAdapter ? 1 : 0;
        if (logic.read(Counter::MidInvoked) != expected_dispatches)
        {
            std::fprintf(stderr, "FAIL[%s]: callback count did not identify the selected route interval\n", scenario);
            std::_Exit(71);
        }

        std::atomic<bool> teardown_returned{false};
        std::thread destroyer(
            [&]
            {
                hook.reset();
                teardown_returned.store(true, std::memory_order_release);
            });
        ::Sleep(MID_PARK_HOLD_MS);
        if (teardown_returned.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL[%s]: teardown reclaimed a stub while its executable route was parked\n",
                         scenario);
            std::fflush(stderr);
            std::_Exit(72);
        }

        DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::None);
        destroyer.join();
        caller.join();
        if (!teardown_returned.load(std::memory_order_acquire) ||
            logic.read(Counter::MidInvoked) != expected_dispatches || target(10, 5) != baseline)
        {
            std::fprintf(stderr, "FAIL[%s]: drained route did not leave a pristine inert target\n", scenario);
            return 73;
        }

        const void *marker = logic.marker;
        if (::FreeLibrary(logic.module) == FALSE)
        {
            std::fprintf(stderr, "FAIL[%s]: FreeLibrary failed (error %lu)\n", scenario, ::GetLastError());
            return 74;
        }
        logic.module = nullptr;
        DWORD unmap_waited = 0;
        if (!wait_for_unmap(marker, unmap_waited) || target(10, 5) != baseline)
        {
            std::fprintf(stderr, "FAIL[%s]: provider did not unmap behind a safely restored target\n", scenario);
            return 75;
        }

        std::printf("PASS[%s]: teardown waited for the full backend route, then the provider unmapped\n", scenario);
        return 0;
    }

    /**
     * @brief Pins a mid hook's backend after its tombstone, unloads the DLL, and proves the target call stays inert.
     * @details Destroying a hook that is not the newest layer on its target is a leak-on-purpose branch: the patched
     *          prologue and the adapter stub stay mapped forever so a newer layer's chain into them cannot dangle.
     *          That leaves a reachable stub whose detour lives in a module the host is about to unmap, which is the
     *          exact shape the tombstone has to make safe. The adapter's live recheck must turn the call into a no-op
     *          instead of a jump into freed code.
     */
    int run_mid_pinned(Logic &logic)
    {
        HMODULE target_module = nullptr;
        const logic_dll::TargetFn target = load_hook_target(target_module);
        if (target == nullptr)
        {
            return SETUP_FAILURE;
        }

        const int baseline = target(10, 5);

        auto older = DetourModKit::hook::mid_at(
            DetourModKit::hook::MidRequest{.name = "logic.mid.older", .target = DetourModKit::Address{target}},
            logic.mid_detour);
        if (!older)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: mid_at failed: %s\n",
                         DetourModKit::to_string(older.error().code).data());
            return 50;
        }
        std::optional<DetourModKit::hook::Hook> older_hook{std::move(*older)};
        if (const auto armed = older_hook->enable(); !armed)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: enable failed: %s\n",
                         DetourModKit::to_string(armed.error().code).data());
            return 51;
        }

        (void)target(10, 5);
        if (logic.read(Counter::MidInvoked) != 1)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: the mid hook never dispatched, so the proof would be vacuous\n");
            return 52;
        }

        auto newer = DetourModKit::hook::mid_at(
            DetourModKit::hook::MidRequest{.name = "logic.mid.newer", .target = DetourModKit::Address{target}},
            logic.mid_detour);
        if (!newer)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: layering a newer mid hook failed: %s\n",
                         DetourModKit::to_string(newer.error().code).data());
            return 53;
        }
        std::optional<DetourModKit::hook::Hook> newer_hook{std::move(*newer)};

        const std::size_t leaks_before = DetourModKit::diagnostics::total_intentional_leaks();
        older_hook.reset();
        const std::size_t leaks_after = DetourModKit::diagnostics::total_intentional_leaks();
        if (leaks_after <= leaks_before)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: destroying the older layer booked no intentional leak, so the "
                                 "backend was restored rather than pinned and the scenario proves nothing\n");
            return 54;
        }

        newer_hook.reset();

        if (!DetourModKit::hook::is_target_hooked(DetourModKit::Address{target}))
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: the target reports clean after a pinned teardown; a later install "
                                 "would layer over a stub that is still patched in\n");
            return 55;
        }

        const std::uint64_t dispatches_before = logic.read(Counter::MidInvoked);
        if (target(10, 5) != baseline)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: the pinned target no longer returns its original result\n");
            return 56;
        }
        if (logic.read(Counter::MidInvoked) != dispatches_before)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: the tombstoned adapter still called the DLL detour; unmapping the "
                                 "module would turn the next call into a jump into freed code\n");
            return 57;
        }

        const void *marker = logic.marker;
        if (::FreeLibrary(logic.module) == FALSE)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: FreeLibrary failed (error %lu)\n", ::GetLastError());
            return 58;
        }
        logic.module = nullptr;

        DWORD unmap_waited = 0;
        if (!wait_for_unmap(marker, unmap_waited))
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: the logic DLL is still mapped %lu ms after FreeLibrary\n",
                         unmap_waited);
            return 59;
        }

        // The load-bearing call: the stub is still patched into the target and still reachable, but its detour is now
        // unmapped. Reaching the DLL here faults rather than returning, so surviving this call IS the assertion.
        if (target(10, 5) != baseline)
        {
            std::fprintf(stderr, "FAIL[mid-pinned]: the target returned the wrong result after the module unmapped\n");
            return 60;
        }

        std::printf("PASS[mid-pinned]: the pinned stub went inert at its tombstone, so calling the target after the "
                    "module unmapped stayed a no-op\n");
        return 0;
    }

    /**
     * @brief Proves the caller-owned quiescence contract for an inline detour that lives in the Logic DLL.
     * @details An inline detour replaces the target outright, so DetourModKit has no frame there and cannot count or
     *          wait for an entry. The host therefore owes the ordering: stop and JOIN every thread that can reach the
     *          target, and only then destroy the hook and unmap the provider. This scenario performs that order and
     *          proves both ends of it, that the detour really ran and that the restored target still answers after
     *          the module is gone.
     */
    int run_inline_quiesced(Logic &logic)
    {
        HMODULE target_module = nullptr;
        const logic_dll::TargetFn target = load_hook_target(target_module);
        if (target == nullptr)
        {
            return SETUP_FAILURE;
        }

        const int baseline = target(10, 5);

        auto created = DetourModKit::hook::inline_at(
            DetourModKit::hook::InlineRequest{.name = "logic.inline", .target = DetourModKit::Address{target}},
            logic.inline_detour);
        if (!created)
        {
            std::fprintf(stderr, "FAIL[inline-quiesced]: inline_at failed: %s\n",
                         DetourModKit::to_string(created.error().code).data());
            return 61;
        }
        std::optional<DetourModKit::hook::Hook> hook{std::move(*created)};

        logic.set_inline_original(hook->original<logic_dll::TargetFn>());
        if (const auto armed = hook->enable(); !armed)
        {
            std::fprintf(stderr, "FAIL[inline-quiesced]: enable failed: %s\n",
                         DetourModKit::to_string(armed.error().code).data());
            return 62;
        }

        // Chaining is asserted before the park is armed, so this thread cannot park itself. A detour that never
        // received the trampoline returns UNCHAINED_RESULT, which the target cannot produce, so this call fails rather
        // than silently proving nothing about the one thing the fixture's original pointer exists for.
        const std::uint64_t dispatches_before = logic.read(Counter::InlineInvoked);
        if (target(10, 5) != baseline)
        {
            std::fprintf(stderr, "FAIL[inline-quiesced]: the armed detour did not chain to the trampoline\n");
            return 67;
        }
        if (logic.read(Counter::InlineInvoked) != dispatches_before + 1)
        {
            std::fprintf(stderr, "FAIL[inline-quiesced]: the call never reached the DLL detour, so the chained result "
                                 "came from an unhooked target\n");
            return 68;
        }

        logic.arm(Channel::Inline);
        std::atomic<bool> caller_running{true};
        std::thread caller(
            [&caller_running, target]() noexcept
            {
                while (caller_running.load(std::memory_order_acquire))
                {
                    (void)target(10, 5);
                    std::this_thread::yield();
                }
            });

        // Entering the park is also the non-vacuity assertion: the detour tallies before it parks, so observing the
        // park proves a thread is inside DLL code rather than merely that the detour ran at some point.
        if (!logic.parked(Channel::Inline, OBSERVE_BUDGET_MS))
        {
            std::fprintf(stderr, "FAIL[inline-quiesced]: the DLL inline detour never entered its park\n");
            caller_running.store(false, std::memory_order_release);
            logic.release(Channel::Inline);
            caller.join();
            return 63;
        }
        caller_running.store(false, std::memory_order_release);
        logic.release(Channel::Inline);

        // The join is the contract. It must complete before the handle dies and before the module is unmapped, or a
        // thread can still be executing a detour that either gets its prologue restored or gets unmapped underneath.
        caller.join();

        hook.reset();

        const void *marker = logic.marker;
        if (::FreeLibrary(logic.module) == FALSE)
        {
            std::fprintf(stderr, "FAIL[inline-quiesced]: FreeLibrary failed (error %lu)\n", ::GetLastError());
            return 64;
        }
        logic.module = nullptr;

        DWORD unmap_waited = 0;
        if (!wait_for_unmap(marker, unmap_waited))
        {
            std::fprintf(stderr, "FAIL[inline-quiesced]: the logic DLL is still mapped %lu ms after teardown\n",
                         unmap_waited);
            return 65;
        }

        if (target(10, 5) != baseline)
        {
            std::fprintf(stderr, "FAIL[inline-quiesced]: the target did not return to its original behavior after the "
                                 "detour's module was unmapped\n");
            return 66;
        }

        std::printf("PASS[inline-quiesced]: the caller was stopped and joined before teardown, the module unmapped "
                    "after %lu ms, and the restored target still answers\n",
                    unmap_waited);
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
#if defined(_MSC_VER)
    // A raw proof runs headless: nothing dismisses a modal CRT dialog. Route asserts and errors to stderr and make
    // abort() exit with a status, so a failure is a fast diagnostic exit rather than a hang.
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    ::SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#endif

    if (argc != 2)
    {
        std::fprintf(stderr,
                     "usage: %s <input-drained|guard-retained|guard-retained-hold|input-parked|config-setter-parked|"
                     "config-parked|mid-parked|mid-route-pre|mid-route-post|mid-pinned|inline-quiesced>\n",
                     argv[0]);
        return 1;
    }

    Logic logic;
    if (!load_logic(logic))
    {
        return SETUP_FAILURE;
    }

    const std::string_view selected{argv[1]};
    int result = 1;
    if (selected == "input-drained")
    {
        result = run_input_drained(logic);
    }
    else if (selected == "guard-retained")
    {
        result = run_input_guard_retained(logic);
    }
    else if (selected == "guard-retained-hold")
    {
        result = run_hold_guard_retained(logic);
    }
    else if (selected == "input-parked")
    {
        result = run_input_parked(logic);
    }
    else if (selected == "config-parked")
    {
        result = run_config_parked(logic);
    }
    else if (selected == "config-setter-parked")
    {
        result = run_config_setter_parked(logic);
    }
    else if (selected == "mid-parked")
    {
        result = run_mid_parked(logic);
    }
    else if (selected == "mid-route-pre")
    {
        result = run_mid_route_parked(logic, DetourModKit::detail::MidRouteParkStage::BeforeAdapter, "mid-route-pre");
    }
    else if (selected == "mid-route-post")
    {
        result = run_mid_route_parked(logic, DetourModKit::detail::MidRouteParkStage::AfterAdapter, "mid-route-post");
    }
    else if (selected == "mid-pinned")
    {
        result = run_mid_pinned(logic);
    }
    else if (selected == "inline-quiesced")
    {
        result = run_inline_quiesced(logic);
    }
    else
    {
        std::fprintf(stderr, "unknown logic-dll unload case\n");
    }

    return result;
}
