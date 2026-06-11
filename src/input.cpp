/**
 * @file input.cpp
 * @brief Implementation of the input polling and hotkey management system.
 *
 * Provides InputPoller (RAII polling engine) and InputManager (singleton wrapper) for monitoring keyboard, mouse, and
 * gamepad input states on a background thread. Supports press (edge-triggered) and hold (level-triggered) input modes
 * with modifier combinations, focus-aware polling, and XInput gamepad support.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/logger.hpp"

#include "platform.hpp"
#include "input_intercept.hpp"

#include <windows.h>
#include <Xinput.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <new>
#include <type_traits>
#include <unordered_set>

using DetourModKit::detail::is_loader_lock_held;
using DetourModKit::detail::pin_current_module;

namespace DetourModKit
{
    namespace
    {
        /**
         * @brief Checks whether a single InputCode is currently pressed.
         * @param code The input code to check.
         * @param gamepad_state Cached XInput state for the current poll cycle.
         * @param gamepad_connected Whether the gamepad is connected.
         * @param trigger_threshold Analog trigger deadzone threshold.
         * @param stick_threshold Thumbstick deadzone threshold.
         * @param wheel_pulse Per-cycle wheel pulse mask (bit 0 = WheelUp .. bit 3 =
         *        WheelRight), latched once per cycle by the poll loop so repeated reads within a cycle stay consistent.
         * @return true if the input is currently pressed.
         */
        bool is_code_pressed(const InputCode &code, const XINPUT_STATE &gamepad_state, bool gamepad_connected,
                             int trigger_threshold, int stick_threshold, uint8_t wheel_pulse) noexcept
        {
            switch (code.source)
            {
            case InputSource::Keyboard:
            case InputSource::Mouse:
                return code.code != 0 && (GetAsyncKeyState(code.code) & 0x8000) != 0;
            case InputSource::MouseWheel:
            {
                // The wheel has no held state; the poll loop latches each notch into wheel_pulse. WheelCode values are
                // 1-based and dense, so the direction index is code - WheelCode::Up.
                const int dir = code.code - WheelCode::Up;
                if (dir < 0 || dir > 3)
                {
                    return false;
                }
                return (wheel_pulse & (1u << dir)) != 0;
            }
            case InputSource::Gamepad:
            {
                if (!gamepad_connected)
                {
                    return false;
                }
                // Fast path: digital button bitmask (all codes below synthetic range)
                if (code.code < GamepadCode::LeftTrigger)
                {
                    return (gamepad_state.Gamepad.wButtons & static_cast<WORD>(code.code)) != 0;
                }
                // Synthetic analog codes
                switch (code.code)
                {
                case GamepadCode::LeftTrigger:
                    return gamepad_state.Gamepad.bLeftTrigger > trigger_threshold;
                case GamepadCode::RightTrigger:
                    return gamepad_state.Gamepad.bRightTrigger > trigger_threshold;
                case GamepadCode::LeftStickUp:
                    return gamepad_state.Gamepad.sThumbLY > stick_threshold;
                case GamepadCode::LeftStickDown:
                    return gamepad_state.Gamepad.sThumbLY < -stick_threshold;
                case GamepadCode::LeftStickLeft:
                    return gamepad_state.Gamepad.sThumbLX < -stick_threshold;
                case GamepadCode::LeftStickRight:
                    return gamepad_state.Gamepad.sThumbLX > stick_threshold;
                case GamepadCode::RightStickUp:
                    return gamepad_state.Gamepad.sThumbRY > stick_threshold;
                case GamepadCode::RightStickDown:
                    return gamepad_state.Gamepad.sThumbRY < -stick_threshold;
                case GamepadCode::RightStickLeft:
                    return gamepad_state.Gamepad.sThumbRX < -stick_threshold;
                case GamepadCode::RightStickRight:
                    return gamepad_state.Gamepad.sThumbRX > stick_threshold;
                default:
                    return false;
                }
            }
            }
            return false;
        }

        /**
         * @brief Checks if a held input satisfies a required modifier.
         * @details Returns true when the codes match exactly, or when both are keyboard modifiers in the same family
         *          (e.g., LShift satisfies generic Shift, and generic Shift satisfies LShift).
         */
        bool modifier_satisfies(const InputCode &required, const InputCode &held) noexcept
        {
            if (required == held)
            {
                return true;
            }
            if (required.source != InputSource::Keyboard || held.source != InputSource::Keyboard)
            {
                return false;
            }
            // Modifier family groups: {generic, left, right}
            constexpr int families[][3] = {
                {0x11, 0xA2, 0xA3}, // Ctrl, LCtrl, RCtrl
                {0x10, 0xA0, 0xA1}, // Shift, LShift, RShift
                {0x12, 0xA4, 0xA5}, // Alt, LAlt, RAlt
            };
            for (const auto &family : families)
            {
                bool req_in = false;
                bool held_in = false;
                for (int vk : family)
                {
                    if (required.code == vk)
                    {
                        req_in = true;
                    }
                    if (held.code == vk)
                    {
                        held_in = true;
                    }
                }
                if (req_in && held_in)
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Scans bindings to determine if any use gamepad input codes.
         * @param bindings The vector of bindings to scan.
         * @return true if at least one binding contains a gamepad InputCode.
         */
        bool scan_for_gamepad_bindings(const std::vector<InputBinding> &bindings) noexcept
        {
            for (const auto &binding : bindings)
            {
                for (const auto &key : binding.keys)
                {
                    if (key.source == InputSource::Gamepad)
                    {
                        return true;
                    }
                }
                for (const auto &mod : binding.modifiers)
                {
                    if (mod.source == InputSource::Gamepad)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /**
         * @brief Reports whether any binding uses a mouse-wheel trigger.
         * @details Wheel codes only appear as trigger keys (never modifiers), so modifiers are not scanned. Drives lazy
         *          installation of the window-procedure hook that captures wheel events.
         */
        bool scan_for_wheel_bindings(const std::vector<InputBinding> &bindings) noexcept
        {
            for (const auto &binding : bindings)
            {
                for (const auto &key : binding.keys)
                {
                    if (key.source == InputSource::MouseWheel)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /**
         * @brief Reports whether any consume binding carries a suppressible gamepad button (gates the XInput hook).
         * @details Only digital buttons gate it: the detour masks XINPUT_GAMEPAD.wButtons, so analog triggers and stick
         *          directions (the synthetic codes >=
         *          GamepadCode::LeftTrigger) can never be cleared and must not install a hook that would mask nothing.
         */
        bool scan_for_consume_gamepad_bindings(const std::vector<InputBinding> &bindings) noexcept
        {
            for (const auto &binding : bindings)
            {
                if (!binding.consume)
                {
                    continue;
                }
                for (const auto &key : binding.keys)
                {
                    if (key.source == InputSource::Gamepad && key.code > 0 && key.code < GamepadCode::LeftTrigger)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// Reports whether any consume binding carries a wheel trigger (gates wheel swallowing).
        bool scan_for_wheel_consume_bindings(const std::vector<InputBinding> &bindings) noexcept
        {
            for (const auto &binding : bindings)
            {
                if (!binding.consume)
                {
                    continue;
                }
                for (const auto &key : binding.keys)
                {
                    if (key.source == InputSource::MouseWheel)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /**
         * @brief Builds the detour-evaluable consume rule list from the current bindings.
         * @details A rule is emitted for every consume binding whose masked triggers include a digital gamepad button,
         *          but only when every known modifier (across all bindings) is itself a digital gamepad button. The
         *          XInput detour sees only
         *          XINPUT_GAMEPAD.wButtons, so it cannot observe a keyboard/mouse modifier or an analog trigger/stick
         *          used as a modifier; if any such modifier exists, the poll loop's strict-match decision is not
         *          reproducible in the detour, so the whole list is dropped and the reactive (poll-published) mask
         *          alone covers the held-modifier case. For an eligible binding the rule carries:
         *            modifier_mask  -- all of the chord's modifier bits,
         *            trigger_mask   -- the chord's digital gamepad trigger bits to clear,
         *            forbidden_mask -- every other known modifier bit, so holding a modifier
         *                              that belongs to a different chord rejects this one, exactly as the poll loop's
         *                              strict-match check does.
         */
        std::vector<detail::GamepadConsumeRule>
        build_gamepad_consume_rules(const std::vector<InputBinding> &bindings,
                                    const std::vector<InputCode> &known_modifiers)
        {
            const auto is_digital_gamepad = [](const InputCode &code) noexcept
            { return code.source == InputSource::Gamepad && code.code > 0 && code.code < GamepadCode::LeftTrigger; };

            // The detour can only reproduce strict matching when every known modifier is a digital gamepad button it
            // can read in wButtons. If any is not, emit no rules (the reactive path still handles the held-modifier
            // case).
            uint16_t known_mod_mask = 0;
            for (const auto &mod : known_modifiers)
            {
                if (!is_digital_gamepad(mod))
                {
                    return {};
                }
                known_mod_mask = static_cast<uint16_t>(known_mod_mask | static_cast<uint16_t>(mod.code));
            }

            std::vector<detail::GamepadConsumeRule> rules;
            for (const auto &binding : bindings)
            {
                if (!binding.consume)
                {
                    continue;
                }
                uint16_t trigger_mask = 0;
                for (const auto &key : binding.keys)
                {
                    if (is_digital_gamepad(key))
                    {
                        trigger_mask = static_cast<uint16_t>(trigger_mask | static_cast<uint16_t>(key.code));
                    }
                }
                if (trigger_mask == 0)
                {
                    // No digital gamepad trigger to clear (e.g. a wheel or analog consume binding); nothing here for
                    // the detour to mask.
                    continue;
                }
                // Every modifier is a digital gamepad button here: the gate above returned an empty list if any known
                // modifier was not, and a chord's modifiers are a subset of the known modifiers.
                uint16_t modifier_mask = 0;
                for (const auto &mod : binding.modifiers)
                {
                    modifier_mask = static_cast<uint16_t>(modifier_mask | static_cast<uint16_t>(mod.code));
                }
                const uint16_t forbidden_mask =
                    static_cast<uint16_t>(known_mod_mask & static_cast<uint16_t>(~modifier_mask));
                rules.push_back(detail::GamepadConsumeRule{modifier_mask, forbidden_mask, trigger_mask});
            }
            return rules;
        }

        // Release grace for gamepad consume-until-release. Long enough to absorb the modifier-released-before-trigger
        // window (the player relaxing the bumper a frame or two before the thumb leaves the D-pad) without noticeably
        // delaying a deliberate tap that follows.
        constexpr uint64_t GAMEPAD_SUPPRESS_GRACE_MS = 80;
    } // anonymous namespace

    static_assert(std::is_nothrow_move_assignable_v<InputBinding>,
                  "Input reshape commits rely on noexcept InputBinding move assignment");

    // --- InputPoller ---

    InputPoller::InputPoller(std::vector<InputBinding> bindings, std::chrono::milliseconds poll_interval,
                             bool require_focus, int gamepad_index, int trigger_threshold, int stick_threshold)
        : m_bindings(std::move(bindings)),
          m_poll_interval(std::clamp(poll_interval, MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)),
          m_require_focus(require_focus), m_active_states(std::make_unique<std::atomic<uint8_t>[]>(m_bindings.size())),
          m_gamepad_index(std::clamp(gamepad_index, 0, 3)), m_trigger_threshold(std::clamp(trigger_threshold, 0, 255)),
          m_stick_threshold(std::clamp(stick_threshold, 0, 32767))
    {
        m_name_index.reserve(m_bindings.size());
        recompute_modifier_caches_locked();
    }

    void InputPoller::recompute_modifier_caches_locked() noexcept
    {
        // Rebuild the lookup caches into local containers and commit them with non-throwing moves only after every
        // allocation has succeeded. This helper is noexcept and reachable from loader-lock teardown, so an allocation
        // failure must keep the poller internally consistent rather than letting std::bad_alloc escape and terminate
        // the host.
        try
        {
            decltype(m_name_index) name_index;
            std::unordered_set<InputCode, InputCodeHash> modifier_set;
            for (size_t i = 0; i < m_bindings.size(); ++i)
            {
                if (!m_bindings[i].name.empty())
                {
                    name_index[m_bindings[i].name].push_back(i);
                }
                for (const auto &mod : m_bindings[i].modifiers)
                {
                    modifier_set.insert(mod);
                }
            }
            std::vector<InputCode> known_modifiers(modifier_set.begin(), modifier_set.end());

            // Built from the same bindings and modifier set as the reactive path so the poll-published mask and the
            // detour-side consume rules never disagree (published in the commit step below).
            const std::vector<detail::GamepadConsumeRule> consume_rules =
                build_gamepad_consume_rules(m_bindings, known_modifiers);

            // Commit. Container move-assignment with the default allocator does not allocate, so from here the function
            // cannot fail.
            m_name_index = std::move(name_index);
            m_known_modifiers = std::move(known_modifiers);
            m_has_gamepad_bindings.store(scan_for_gamepad_bindings(m_bindings), std::memory_order_relaxed);
            m_has_wheel_bindings.store(scan_for_wheel_bindings(m_bindings), std::memory_order_relaxed);
            m_has_consume_gamepad_bindings.store(scan_for_consume_gamepad_bindings(m_bindings),
                                                 std::memory_order_relaxed);
            m_has_wheel_consume_bindings.store(scan_for_wheel_consume_bindings(m_bindings), std::memory_order_relaxed);

            // Publish the detour-side consume rule list. The XInput detour evaluates these against the exact snapshot
            // the game reads, closing the leading-edge window the poll-published mask leaves for a modifier and trigger
            // pressed inside one poll interval.
            detail::publish_gamepad_consume_rules(consume_rules.data(), consume_rules.size());
        }
        catch (...)
        {
            // m_bindings and m_active_states may already reflect a reshape. Keep every derived cache conservative and
            // index-safe rather than leaving a stale name map whose old indices could address past the new binding
            // array.
            m_name_index.clear();
            m_known_modifiers.clear();
            m_has_gamepad_bindings.store(false, std::memory_order_relaxed);
            m_has_wheel_bindings.store(false, std::memory_order_relaxed);
            m_has_consume_gamepad_bindings.store(false, std::memory_order_relaxed);
            m_has_wheel_consume_bindings.store(false, std::memory_order_relaxed);
            detail::publish_gamepad_consume_rules(nullptr, 0);
            static_cast<void>(Logger::get_instance().try_log(
                LogLevel::Error, "InputPoller: out of memory rebuilding modifier caches; "
                                 "name lookup and input interception disabled until the next successful rebuild"));
        }
    }

    InputPoller::~InputPoller() noexcept
    {
        shutdown();
    }

    void InputPoller::start()
    {
        if (m_poll_thread.joinable())
        {
            Logger::get_instance().debug("InputPoller: start() called while already running; no-op.");
            return;
        }

        m_running.store(true, std::memory_order_release);
        try
        {
            m_poll_thread = std::jthread([this](std::stop_token token) { poll_loop(std::move(token)); });
        }
        catch (...)
        {
            m_running.store(false, std::memory_order_release);
            throw;
        }
    }

    bool InputPoller::is_running() const noexcept
    {
        return m_running.load(std::memory_order_acquire);
    }

    size_t InputPoller::binding_count() const noexcept
    {
        return m_bindings.size();
    }

    std::chrono::milliseconds InputPoller::poll_interval() const noexcept
    {
        return m_poll_interval;
    }

    int InputPoller::gamepad_index() const noexcept
    {
        return m_gamepad_index;
    }

    bool InputPoller::is_binding_active(size_t index) const noexcept
    {
        // Acquire the shared lock so the index/array pair stays consistent across a reshape (add_binding,
        // remove_bindings_by_name, update_combos all swap m_active_states under the writer lock and resize m_bindings
        // alongside it). The relaxed atomic load on the element itself is still cheap; it is the unique_ptr<atomic[]>
        // ownership swap that needs synchronisation.
        std::shared_lock lock(m_bindings_rw_mutex);
        if (index >= m_bindings.size())
        {
            return false;
        }
        return m_active_states[index].load(std::memory_order_relaxed) != 0;
    }

    bool InputPoller::is_binding_active(std::string_view name) const noexcept
    {
        std::shared_lock lock(m_bindings_rw_mutex);
        const auto it = m_name_index.find(name);
        if (it != m_name_index.end())
        {
            for (const size_t idx : it->second)
            {
                if (m_active_states[idx].load(std::memory_order_relaxed) != 0)
                {
                    return true;
                }
            }
        }
        return false;
    }

    void InputPoller::set_require_focus(bool require_focus) noexcept
    {
        m_require_focus.store(require_focus, std::memory_order_relaxed);
    }

    void InputPoller::set_consume(std::string_view name, bool consume) noexcept
    {
        std::unique_lock lock(m_bindings_rw_mutex);
        const auto it = m_name_index.find(name);
        if (it == m_name_index.end())
        {
            return;
        }
        for (const size_t idx : it->second)
        {
            m_bindings[idx].consume = consume;
        }
        // Refresh the interception gates so the poll loop installs or skips the
        // XInput / window-procedure hooks on its next cycle.
        recompute_modifier_caches_locked();
    }

    void InputPoller::shutdown() noexcept
    {
        if (!m_poll_thread.joinable())
        {
            return;
        }

        m_poll_thread.request_stop();
        m_cv.notify_all();

        if (is_loader_lock_held())
        {
            // Under loader lock (FreeLibrary / process unload) the poll thread cannot be joined without deadlocking the
            // loader, so it is detached after pinning the module. It is still running and will exit only once it
            // observes the stop request, so we must NOT touch shared binding state or fire hold-release callbacks here:
            // that would race the detached thread and run user callbacks under the loader lock (a callback that enters
            // the loader -- LoadLibrary family or a peer
            // DllMain mutex -- would deadlock). Mirrors clear_bindings(invoke_callbacks=false).
            pin_current_module();
            m_poll_thread.detach();
            DetourModKit::Diagnostics::record_intentional_leak(DetourModKit::Diagnostics::LeakSubsystem::Input);
            m_running.store(false, std::memory_order_release);
            return;
        }

        m_poll_thread.join();

        // The poll thread is provably stopped here, so releasing active holds and firing their on_state_change(false)
        // callbacks is race-free.
        m_running.store(false, std::memory_order_release);

        // The poll thread is the sole publisher of the suppression mask and the sole reader of the XInput trampoline,
        // so tearing the interception hooks down now is race-free. This is skipped on the loader-lock path above:
        // safetyhook's hook removal VirtualProtects the patched code pages and registers a vectored exception handler
        // to fix up any in-flight thread, which must not run under the loader lock, so the detours are intentionally
        // left installed against the pinned module instead.
        detail::uninstall();

        release_active_holds();
    }

    void InputPoller::poll_loop(std::stop_token stop_token)
    {
        const int trigger_thresh = m_trigger_threshold;
        const int stick_thresh = m_stick_threshold;

        constexpr auto gamepad_reconnect_interval = std::chrono::seconds{2};
        bool gamepad_was_connected = false;
        auto last_gamepad_poll = std::chrono::steady_clock::time_point{};

        // Interception state, carried across cycles. Both are poll-thread-private:
        // the published mask and wheel latch they feed live in input_intercept.
        detail::WheelPulseState wheel_pulse{};
        detail::GamepadSuppressState gp_suppress{};

        struct PendingCallback
        {
            std::string name;
            std::function<void()> on_press;
            std::function<void(bool)> on_state_change;
            bool hold_value;
        };
        std::vector<PendingCallback> pending;
        {
            std::shared_lock lock(m_bindings_rw_mutex);
            pending.reserve(m_bindings.size());
        }

        while (!stop_token.stop_requested())
        {
            pending.clear();
            const bool process_focused = !m_require_focus.load(std::memory_order_relaxed) || is_process_foreground();

            // Lazily install the active-input hooks the current bindings need. Each call is idempotent and fails
            // cheaply until its target (a loaded xinput module / the game window) becomes available, so this also
            // handles a target that appears after the poller starts.
            if (m_has_consume_gamepad_bindings.load(std::memory_order_relaxed) && !detail::xinput_installed())
            {
                (void)detail::install_xinput(m_gamepad_index);
            }
            if (m_has_wheel_bindings.load(std::memory_order_relaxed) && !detail::wndproc_installed())
            {
                (void)detail::install_wndproc();
            }

            // Snapshot the wheel notches the window-procedure hook accumulated into a per-cycle pulse mask, so every
            // binding this cycle reads a consistent value and each notch maps to exactly one Press edge. The counters
            // are drained even when unfocused so a background notch is discarded rather than queued to fire on the next
            // focus.
            uint8_t wheel_pulse_mask = 0;
            if (m_has_wheel_bindings.load(std::memory_order_relaxed))
            {
                const auto taken = detail::take_wheel_counts();
                detail::add_wheel_notches(wheel_pulse, taken);
                wheel_pulse_mask = detail::step_wheel_pulse(wheel_pulse);
            }

            // Drive the wheel-swallow flag every cycle, outside the wheel-binding guard above, so it disarms on the
            // first cycle after the last consume wheel binding is removed at runtime: the window-procedure subclass
            // stays installed until shutdown, so a stale true would keep eating the game's wheel forever (the gamepad
            // mask self-heals via its TTL, but the wheel flag has none). Gate it on focus to mirror the gamepad mask
            // clear
            // below: a backgrounded mod must not swallow the focused app's wheel.
            detail::set_wheel_consume(process_focused && m_has_wheel_consume_bindings.load(std::memory_order_relaxed));

            // Digital gamepad button bits claimed by active consume chords this cycle, accumulated in the binding loop
            // and published afterwards.
            uint16_t gamepad_owned = 0;

            // Poll gamepad state once per cycle when connected. When disconnected, throttle reconnection attempts to
            // avoid the per-cycle overhead of XInputGetState on empty slots. Read through the saved trampoline when the
            // suppression hook is installed so the poll observes the true, unmasked controller state rather than its
            // own published mask.
            XINPUT_STATE gamepad_state{};
            bool gamepad_connected = false;
            if (m_has_gamepad_bindings.load(std::memory_order_relaxed) && process_focused)
            {
                const auto now = std::chrono::steady_clock::now();
                if (gamepad_was_connected || (now - last_gamepad_poll) >= gamepad_reconnect_interval)
                {
                    last_gamepad_poll = now;
                    const detail::XInputGetStateFn xinput_original = detail::xinput_trampoline();
                    const DWORD xinput_result =
                        (xinput_original != nullptr)
                            ? xinput_original(static_cast<DWORD>(m_gamepad_index), &gamepad_state)
                            : XInputGetState(static_cast<DWORD>(m_gamepad_index), &gamepad_state);
                    gamepad_was_connected = xinput_result == ERROR_SUCCESS;
                }
                gamepad_connected = gamepad_was_connected;
            }

            // Collect callbacks to fire outside the shared lock so user code can call back into update_binding_combos()
            // without deadlocking.
            {
                std::shared_lock lock(m_bindings_rw_mutex);
                const size_t count = m_bindings.size();
                const auto &known_mods = m_known_modifiers;

                for (size_t i = 0; i < count; ++i)
                {
                    const auto &binding = m_bindings[i];
                    if (binding.keys.empty())
                    {
                        continue;
                    }

                    bool any_pressed = false;

                    if (process_focused)
                    {
                        bool modifiers_held = true;
                        for (const auto &mod : binding.modifiers)
                        {
                            if (!is_code_pressed(mod, gamepad_state, gamepad_connected, trigger_thresh, stick_thresh,
                                                 wheel_pulse_mask))
                            {
                                modifiers_held = false;
                                break;
                            }
                        }

                        if (modifiers_held)
                        {
                            // Strict matching: reject if any known modifier that is
                            // NOT in this binding's required set is currently held.
                            for (const auto &km : known_mods)
                            {
                                if (!is_code_pressed(km, gamepad_state, gamepad_connected, trigger_thresh, stick_thresh,
                                                     wheel_pulse_mask))
                                {
                                    continue;
                                }
                                bool is_required = false;
                                for (const auto &mod : binding.modifiers)
                                {
                                    if (modifier_satisfies(mod, km))
                                    {
                                        is_required = true;
                                        break;
                                    }
                                }
                                if (!is_required)
                                {
                                    modifiers_held = false;
                                    break;
                                }
                            }
                        }

                        if (modifiers_held)
                        {
                            for (const auto &key : binding.keys)
                            {
                                const bool key_pressed =
                                    is_code_pressed(key, gamepad_state, gamepad_connected, trigger_thresh, stick_thresh,
                                                    wheel_pulse_mask);

                                // Pre-arm the consume bit while the binding's modifiers are held, before the trigger
                                // button itself is pressed. The suppression mask is published one poll cycle behind the
                                // physical state, so claiming the bit only once the trigger reads as pressed lets the
                                // game's own XInput poll (an independent clock, usually faster than this loop) catch
                                // the trigger's leading edge before the mask catches up -- a one-frame leak of an
                                // otherwise-suppressed press. Holding the claim to the modifier keeps the mask up
                                // before the trigger arrives. Masking a bit whose physical button is still up is a
                                // no-op: apply_suppress ANDs ~mask into wButtons, and clearing an already-zero bit
                                // changes nothing. The consume-until-release latch still trails the trigger, so the
                                // trailing edge is unchanged. Keep scanning the remaining keys so every owned bit is
                                // collected.
                                if (binding.consume && key.source == InputSource::Gamepad && key.code > 0 &&
                                    key.code < GamepadCode::LeftTrigger)
                                {
                                    gamepad_owned =
                                        static_cast<uint16_t>(gamepad_owned | static_cast<uint16_t>(key.code));
                                }

                                // Activation still keys off the real press: a non-consume binding fires on the first
                                // pressed key and stops, while a consume binding keeps scanning so the pre-arm above
                                // sees every owned bit.
                                if (!key_pressed)
                                {
                                    continue;
                                }
                                any_pressed = true;
                                if (!binding.consume)
                                {
                                    break;
                                }
                            }
                        }
                    }

                    const bool was_active = m_active_states[i].load(std::memory_order_relaxed) != 0;

                    switch (binding.mode)
                    {
                    case InputMode::Press:
                    {
                        if (any_pressed && !was_active && binding.on_press)
                        {
                            pending.push_back({binding.name, binding.on_press, {}, false});
                        }
                        m_active_states[i].store(any_pressed ? 1 : 0, std::memory_order_relaxed);
                        break;
                    }
                    case InputMode::Hold:
                    {
                        if (any_pressed != was_active && binding.on_state_change)
                        {
                            pending.push_back({binding.name, {}, binding.on_state_change, any_pressed});
                        }
                        m_active_states[i].store(any_pressed ? 1 : 0, std::memory_order_relaxed);
                        break;
                    }
                    }
                }
            }

            // Publish the gamepad suppression mask for the XInput detour. The consume-until-release latch keeps a
            // trigger masked until the physical button is released plus a grace window, so releasing the modifier
            // before the trigger cannot leak a bare trigger to the game. When unfocused or disconnected, clear the
            // latch and mask so the game keeps its input while the mod is in the background.
            if (m_has_consume_gamepad_bindings.load(std::memory_order_relaxed))
            {
                if (process_focused && gamepad_connected)
                {
                    const uint16_t suppress =
                        detail::step_gamepad_suppress(gp_suppress, gamepad_owned, gamepad_state.Gamepad.wButtons,
                                                      GetTickCount64(), GAMEPAD_SUPPRESS_GRACE_MS);
                    detail::publish_gamepad_suppress(suppress);
                    // Enable the detour's rule masking only while focused and connected. The published rule list and
                    // its time-to-live survive focus changes, so the detour needs this explicit gate to stop masking
                    // the foreground game's input once the mod is backgrounded, exactly as the reactive mask is cleared
                    // below and as the wheel-consume flag is gated.
                    detail::set_gamepad_rule_suppress_enabled(true);
                }
                else
                {
                    gp_suppress = detail::GamepadSuppressState{};
                    detail::publish_gamepad_suppress(0);
                    detail::set_gamepad_rule_suppress_enabled(false);
                }
            }

            for (auto &callback : pending)
            {
                try
                {
                    if (callback.on_press)
                    {
                        callback.on_press();
                    }
                    else if (callback.on_state_change)
                    {
                        callback.on_state_change(callback.hold_value);
                    }
                }
                catch (const std::exception &e)
                {
                    static_cast<void>(Logger::get_instance().try_log(
                        LogLevel::Error, "InputPoller: Exception in callback \"{}\": {}", callback.name, e.what()));
                }
                catch (...)
                {
                    static_cast<void>(Logger::get_instance().try_log(
                        LogLevel::Error, "InputPoller: Unknown exception in callback \"{}\"", callback.name));
                }
            }

            std::unique_lock lock(m_cv_mutex);
            m_cv.wait_for(lock, stop_token, m_poll_interval, [&stop_token]() { return stop_token.stop_requested(); });
        }
    }

    bool InputPoller::update_combos(std::string_view name, const Config::KeyComboList &combos) noexcept
    {
        std::vector<std::function<void(bool)>> hold_release_callbacks;
        std::vector<std::string> hold_release_names;

        try
        {
            std::unique_lock lock(m_bindings_rw_mutex);
            const auto it = m_name_index.find(name);
            if (it == m_name_index.end())
            {
                // Release the writer lock before logging so the emit does not run inside the critical section
                // (deferred-logging convention).
                lock.unlock();
                static_cast<void>(Logger::get_instance().try_log(
                    LogLevel::Debug, "InputPoller: update_combos(\"{}\") ignored: name not found", name));
                return false;
            }

            std::vector<size_t> indices = it->second;
            if (indices.empty())
            {
                return false;
            }

            // Cardinality-preserving fast path: in-place rewrite of keys and modifiers leaves m_bindings and
            // m_active_states in lockstep. The poll thread holds a shared_lock for the duration of one tick, so the
            // unique_lock here serializes against it; concurrent is_binding_active(size_t) reads stay valid because the
            // binding count and array sizes do not change.
            if (indices.size() == combos.size())
            {
                std::vector<InputBinding> replacements;
                replacements.reserve(indices.size());
                for (size_t i = 0; i < indices.size(); ++i)
                {
                    const size_t idx = indices[i];
                    InputBinding binding = m_bindings[idx];
                    binding.keys = combos[i].keys;
                    binding.modifiers = combos[i].modifiers;
                    replacements.push_back(std::move(binding));
                }
                for (size_t i = 0; i < indices.size(); ++i)
                {
                    m_bindings[indices[i]] = std::move(replacements[i]);
                }
                recompute_modifier_caches_locked();
                return true;
            }

            // Cardinality change requires rebuilding the bindings vector and the parallel m_active_states array.
            // Capture the prototype from the first existing entry so callback identity, mode, and name stay stable
            // across the rebuild.
            InputBinding prototype = m_bindings[indices.front()];
            std::sort(indices.begin(), indices.end());

            const size_t append_count = combos.empty() ? 1 : combos.size();
            const size_t new_size = m_bindings.size() - indices.size() + append_count;

            // Phase 1 -- allocate everything that can throw without yet touching m_bindings. If any allocation fails
            // the poller is left exactly as it was. The appended entries are prototype copies (the copy is the throwing
            // step); an empty replacement yields a single inert sentinel so the name stays addressable for a later
            // non-empty update (without it the bound -> unbound -> bound INI hot-reload cycle would break with "name
            // not found").
            std::vector<InputBinding> appended;
            appended.reserve(append_count);
            if (combos.empty())
            {
                InputBinding sentinel = prototype;
                sentinel.keys.clear();
                sentinel.modifiers.clear();
                appended.push_back(std::move(sentinel));
            }
            else
            {
                for (const auto &combo : combos)
                {
                    InputBinding binding = prototype;
                    binding.keys = combo.keys;
                    binding.modifiers = combo.modifiers;
                    appended.push_back(std::move(binding));
                }
            }

            std::vector<InputBinding> rebuilt;
            rebuilt.reserve(new_size);
            std::vector<uint8_t> rebuilt_states;
            rebuilt_states.reserve(new_size);
            auto new_states = std::make_unique<std::atomic<uint8_t>[]>(new_size);

            // Capture release callbacks for any held entries this update drops. Without this, a register_hold consumer
            // whose combo cardinality changes via INI hot-reload would latch in the held state forever because the
            // underlying entry vanishes before the next poll tick.
            for (size_t idx : indices)
            {
                if (m_active_states[idx].load(std::memory_order_relaxed) != 0 &&
                    m_bindings[idx].mode == InputMode::Hold && m_bindings[idx].on_state_change)
                {
                    hold_release_callbacks.push_back(m_bindings[idx].on_state_change);
                    hold_release_names.push_back(m_bindings[idx].name);
                }
            }

            // Phase 2 -- commit. Every operation below is non-throwing: the reserved vectors never reallocate,
            // InputBinding moves are noexcept, and the atomic stores and container move-assignments do not allocate.
            // Surviving entries carry their prior atomic state across
            // the swap so a held binding does not momentarily report inactive;
            // appended entries start at zero (no prior state to inherit).
            size_t cursor = 0;
            for (size_t skip : indices)
            {
                for (size_t i = cursor; i < skip; ++i)
                {
                    rebuilt_states.push_back(m_active_states[i].load(std::memory_order_relaxed));
                    rebuilt.push_back(std::move(m_bindings[i]));
                }
                cursor = skip + 1;
            }
            for (size_t i = cursor; i < m_bindings.size(); ++i)
            {
                rebuilt_states.push_back(m_active_states[i].load(std::memory_order_relaxed));
                rebuilt.push_back(std::move(m_bindings[i]));
            }
            for (auto &binding : appended)
            {
                rebuilt.push_back(std::move(binding));
                rebuilt_states.push_back(0);
            }

            for (size_t i = 0; i < rebuilt_states.size(); ++i)
            {
                new_states[i].store(rebuilt_states[i], std::memory_order_relaxed);
            }

            m_bindings = std::move(rebuilt);
            m_active_states = std::move(new_states);
            recompute_modifier_caches_locked();
        }
        catch (...)
        {
            // Out of memory during the rebuild. update_combos is noexcept; the poller is left unchanged (Phase 1
            // allocates before any mutation) and no release callbacks are fired.
            static_cast<void>(Logger::get_instance().try_log(
                LogLevel::Error, "InputPoller: out of memory in update_combos; combos unchanged"));
            return false;
        }

        // Fire the captured release callbacks outside the writer lock so user code may safely call back into the
        // InputManager (matching the remove_bindings_by_name pattern). This path runs in response to a user-driven INI
        // reshape, never from a DllMain detach, so synchronous callback dispatch is safe here.
        for (size_t i = 0; i < hold_release_callbacks.size(); ++i)
        {
            try
            {
                hold_release_callbacks[i](false);
            }
            catch (const std::exception &e)
            {
                static_cast<void>(Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}",
                    hold_release_names[i], e.what()));
            }
            catch (...)
            {
                static_cast<void>(Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: Unknown exception in hold release callback \"{}\"",
                    hold_release_names[i]));
            }
        }

        return true;
    }

    void InputPoller::add_binding(InputBinding binding) noexcept
    {
        std::unique_lock lock(m_bindings_rw_mutex);

        const size_t old_count = m_bindings.size();
        const size_t new_count = old_count + 1;

        try
        {
            // Build the replacement state array before mutating m_bindings so an allocation failure leaves the binding
            // vector and the state array at their prior, matching sizes. The poll thread indexes m_active_states by
            // binding position, so a size mismatch would be an out-of-bounds read. Seed each surviving slot from the
            // existing atomic value (relaxed is sufficient under the writer lock) so a held binding does not flicker
            // through a one-tick "inactive" blip.
            auto new_states = std::make_unique<std::atomic<uint8_t>[]>(new_count);
            for (size_t i = 0; i < old_count; ++i)
            {
                new_states[i].store(m_active_states[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
            }
            new_states[old_count].store(0, std::memory_order_relaxed);

            // push_back has the strong guarantee (InputBinding moves are noexcept), so if a reallocation fails here
            // m_bindings is unchanged and the new_states array is simply discarded. Only after it succeeds do the
            // non-throwing commits below run.
            m_bindings.push_back(std::move(binding));
            m_active_states = std::move(new_states);
            recompute_modifier_caches_locked();
        }
        catch (...)
        {
            // Out of memory growing the poller. add_binding is noexcept and reachable from teardown, so the binding is
            // dropped (the poller is left exactly as it was) rather than terminating the host.
            static_cast<void>(Logger::get_instance().try_log(
                LogLevel::Error, "InputPoller: out of memory in add_binding; binding not added"));
        }
    }

    size_t InputPoller::remove_bindings_by_name(std::string_view name, bool invoke_callbacks) noexcept
    {
        std::vector<std::function<void(bool)>> hold_release_callbacks;
        std::vector<std::string> hold_release_names;
        size_t removed = 0;

        try
        {
            std::unique_lock lock(m_bindings_rw_mutex);
            const auto it = m_name_index.find(name);
            if (it == m_name_index.end())
            {
                return 0;
            }

            std::vector<size_t> indices = it->second;
            std::sort(indices.begin(), indices.end());

            // Capture release callbacks for active hold bindings before erasure; fire them after the lock is released
            // so user code is free to call back into the InputManager. The Bootstrap unload path passes
            // invoke_callbacks=false to skip this step because the user callbacks live in a Logic DLL whose code pages
            // may be about to be unmapped.
            if (invoke_callbacks)
            {
                for (size_t idx : indices)
                {
                    if (m_active_states[idx].load(std::memory_order_relaxed) != 0 &&
                        m_bindings[idx].mode == InputMode::Hold && m_bindings[idx].on_state_change)
                    {
                        hold_release_callbacks.push_back(m_bindings[idx].on_state_change);
                        hold_release_names.push_back(m_bindings[idx].name);
                    }
                }
            }

            // Build a flat skip-mask so the new m_active_states slot for every surviving binding inherits its prior
            // atomic value. Without this a held binding would briefly report inactive after the reshape, breaking
            // register_hold consumers that observe the state through is_binding_active(size_t).
            std::vector<bool> drop(m_bindings.size(), false);
            for (size_t idx : indices)
            {
                drop[idx] = true;
            }
            const size_t survivor_count = m_bindings.size() - indices.size();
            std::vector<uint8_t> carried;
            carried.reserve(survivor_count);
            for (size_t i = 0; i < m_bindings.size(); ++i)
            {
                if (!drop[i])
                {
                    carried.push_back(m_active_states[i].load(std::memory_order_relaxed));
                }
            }

            // Allocate the replacement state array before erasing any binding so an allocation failure leaves
            // m_bindings and m_active_states at their prior, matching sizes (the poll thread indexes m_active_states by
            // position; a mismatch would be an out-of-bounds read).
            auto new_states = std::make_unique<std::atomic<uint8_t>[]>(survivor_count);
            for (size_t i = 0; i < carried.size(); ++i)
            {
                new_states[i].store(carried[i], std::memory_order_relaxed);
            }

            // Commit. erase moves survivors down via InputBinding's noexcept move-assignment and the array swap does
            // not allocate, so the reshape past this point cannot fail.
            for (auto idx_it = indices.rbegin(); idx_it != indices.rend(); ++idx_it)
            {
                m_bindings.erase(m_bindings.begin() + static_cast<std::ptrdiff_t>(*idx_it));
            }
            m_active_states = std::move(new_states);
            removed = indices.size();

            recompute_modifier_caches_locked();
        }
        catch (...)
        {
            // Out of memory preparing the reshape. remove_bindings_by_name is noexcept and reachable from teardown; the
            // poller is left unchanged (allocation precedes erasure) and no callbacks are fired.
            static_cast<void>(Logger::get_instance().try_log(
                LogLevel::Error, "InputPoller: out of memory in remove_bindings_by_name; bindings unchanged"));
            return 0;
        }

        for (size_t i = 0; i < hold_release_callbacks.size(); ++i)
        {
            try
            {
                hold_release_callbacks[i](false);
            }
            catch (const std::exception &e)
            {
                static_cast<void>(Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}",
                    hold_release_names[i], e.what()));
            }
            catch (...)
            {
                static_cast<void>(Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: Unknown exception in hold release callback \"{}\"",
                    hold_release_names[i]));
            }
        }

        return removed;
    }

    void InputPoller::clear_bindings(bool invoke_callbacks) noexcept
    {
        std::vector<std::pair<std::function<void(bool)>, std::string>> hold_releases;

        try
        {
            std::unique_lock lock(m_bindings_rw_mutex);
            // Skip the release-callback capture entirely on the loader-lock path (Bootstrap::on_logic_dll_unload_all).
            // Running user callbacks under loader lock is unsafe because the Logic DLL hosting those callbacks may be
            // in the middle of being unmapped, and any callback that touches Win32 LoadLibrary family or a peer
            // DllMain's mutex would deadlock.
            if (invoke_callbacks)
            {
                for (size_t i = 0; i < m_bindings.size(); ++i)
                {
                    if (m_active_states[i].load(std::memory_order_relaxed) != 0 &&
                        m_bindings[i].mode == InputMode::Hold && m_bindings[i].on_state_change)
                    {
                        hold_releases.emplace_back(m_bindings[i].on_state_change, m_bindings[i].name);
                    }
                }
            }

            // Allocate the empty replacement state array before clearing so an allocation failure leaves the poller
            // untouched. The clears, atomic stores, rule publish, and array swap below do not allocate.
            auto new_states = std::make_unique<std::atomic<uint8_t>[]>(0);

            m_bindings.clear();
            m_name_index.clear();
            m_known_modifiers.clear();
            m_has_gamepad_bindings.store(false, std::memory_order_relaxed);
            m_has_wheel_bindings.store(false, std::memory_order_relaxed);
            m_has_consume_gamepad_bindings.store(false, std::memory_order_relaxed);
            m_has_wheel_consume_bindings.store(false, std::memory_order_relaxed);
            detail::publish_gamepad_consume_rules(nullptr, 0);
            m_active_states = std::move(new_states);
        }
        catch (...)
        {
            static_cast<void>(Logger::get_instance().try_log(
                LogLevel::Error, "InputPoller: out of memory in clear_bindings; bindings unchanged"));
            return;
        }

        for (auto &[callback, name] : hold_releases)
        {
            try
            {
                callback(false);
            }
            catch (const std::exception &e)
            {
                static_cast<void>(Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}", name, e.what()));
            }
            catch (...)
            {
                static_cast<void>(Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: Unknown exception in hold release callback \"{}\"", name));
            }
        }
    }

    void InputPoller::release_active_holds() noexcept
    {
        for (size_t i = 0; i < m_bindings.size(); ++i)
        {
            if (m_active_states[i].load(std::memory_order_relaxed) != 0)
            {
                m_active_states[i].store(0, std::memory_order_relaxed);

                const auto &binding = m_bindings[i];
                if (binding.mode == InputMode::Hold && binding.on_state_change)
                {
                    try
                    {
                        binding.on_state_change(false);
                    }
                    catch (const std::exception &e)
                    {
                        static_cast<void>(Logger::get_instance().try_log(
                            LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}", binding.name,
                            e.what()));
                    }
                    catch (...)
                    {
                        static_cast<void>(Logger::get_instance().try_log(
                            LogLevel::Error, "InputPoller: Unknown exception in hold release callback \"{}\"",
                            binding.name));
                    }
                }
            }
        }
    }

    bool InputPoller::is_process_foreground() const noexcept
    {
        HWND foreground = GetForegroundWindow();
        if (!foreground)
        {
            return false;
        }
        DWORD foreground_pid = 0;
        GetWindowThreadProcessId(foreground, &foreground_pid);
        return foreground_pid == GetCurrentProcessId();
    }

    // --- InputManager ---

    void InputManager::register_press(std::string_view name, const std::vector<InputCode> &keys,
                                      std::function<void()> callback)
    {
        register_press(name, keys, {}, std::move(callback));
    }

    void InputManager::register_press(std::string_view name, const std::vector<InputCode> &keys,
                                      const std::vector<InputCode> &modifiers, std::function<void()> callback)
    {
        std::shared_ptr<InputPoller> live_poller;
        InputBinding binding;
        binding.name = std::string{name};
        binding.keys = keys;
        binding.modifiers = modifiers;
        binding.mode = InputMode::Press;
        binding.on_press = std::move(callback);

        {
            std::lock_guard lock(m_mutex);
            if (m_poller)
            {
                live_poller = m_poller;
            }
            else
            {
                m_pending_bindings.push_back(std::move(binding));
                return;
            }
        }

        // Forward outside the InputManager mutex so the poller's exclusive m_bindings_rw_mutex acquisition cannot AB/BA
        // against any caller already holding m_mutex.
        live_poller->add_binding(std::move(binding));
    }

    void InputManager::register_hold(std::string_view name, const std::vector<InputCode> &keys,
                                     std::function<void(bool)> callback)
    {
        register_hold(name, keys, {}, std::move(callback));
    }

    void InputManager::register_hold(std::string_view name, const std::vector<InputCode> &keys,
                                     const std::vector<InputCode> &modifiers, std::function<void(bool)> callback)
    {
        std::shared_ptr<InputPoller> live_poller;
        InputBinding binding;
        binding.name = std::string{name};
        binding.keys = keys;
        binding.modifiers = modifiers;
        binding.mode = InputMode::Hold;
        binding.on_state_change = std::move(callback);

        {
            std::lock_guard lock(m_mutex);
            if (m_poller)
            {
                live_poller = m_poller;
            }
            else
            {
                m_pending_bindings.push_back(std::move(binding));
                return;
            }
        }

        live_poller->add_binding(std::move(binding));
    }

    void InputManager::register_press(std::string_view name, const Config::KeyComboList &combos,
                                      std::function<void()> callback)
    {
        // An empty combo list still has to register the binding name so a later update_binding_combos() can attach a
        // real combo. Without this the for-each loop produces zero bindings, the name never lands in
        // m_pending_bindings, and the INI-driven update silently fails with "name not found".
        if (combos.empty())
        {
            register_press(name, std::vector<InputCode>{}, std::vector<InputCode>{}, std::move(callback));
            return;
        }
        for (const auto &combo : combos)
        {
            register_press(name, combo.keys, combo.modifiers, callback);
        }
    }

    void InputManager::register_hold(std::string_view name, const Config::KeyComboList &combos,
                                     std::function<void(bool)> callback)
    {
        if (combos.empty())
        {
            register_hold(name, std::vector<InputCode>{}, std::vector<InputCode>{}, std::move(callback));
            return;
        }
        for (const auto &combo : combos)
        {
            register_hold(name, combo.keys, combo.modifiers, callback);
        }
    }

    void InputManager::set_require_focus(bool require_focus)
    {
        std::lock_guard lock(m_mutex);
        m_require_focus = require_focus;
        if (m_poller)
        {
            m_poller->set_require_focus(require_focus);
        }
    }

    void InputManager::set_consume(std::string_view name, bool consume) noexcept
    {
        std::shared_ptr<InputPoller> live_poller;

        {
            std::lock_guard lock(m_mutex);
            if (m_poller)
            {
                live_poller = m_poller;
            }
            else
            {
                for (auto &binding : m_pending_bindings)
                {
                    if (binding.name == name)
                    {
                        binding.consume = consume;
                    }
                }
                return;
            }
        }

        // Forward outside the InputManager mutex so the poller's exclusive m_bindings_rw_mutex acquisition cannot
        // deadlock against a caller already holding m_mutex (matches register_press / register_hold).
        live_poller->set_consume(name, consume);
    }

    void InputManager::set_gamepad_index(int index)
    {
        std::lock_guard lock(m_mutex);
        m_gamepad_index = std::clamp(index, 0, 3);
    }

    void InputManager::set_trigger_threshold(int threshold)
    {
        std::lock_guard lock(m_mutex);
        m_trigger_threshold = std::clamp(threshold, 0, 255);
    }

    void InputManager::set_stick_threshold(int threshold)
    {
        std::lock_guard lock(m_mutex);
        m_stick_threshold = std::clamp(threshold, 0, 32767);
    }

    void InputManager::start(std::chrono::milliseconds poll_interval)
    {
        std::lock_guard lock(m_mutex);

        if (m_poller)
        {
            Logger::get_instance().debug("InputManager: start() called while already running; no-op.");
            return;
        }

        if (m_pending_bindings.empty())
        {
            return;
        }

        Logger &logger = Logger::get_instance();
        logger.info("InputManager: Starting with {} binding(s), poll interval {}ms", m_pending_bindings.size(),
                    poll_interval.count());

        for (const auto &binding : m_pending_bindings)
        {
            logger.trace("InputManager: Registered {} binding \"{}\" with {} key(s)",
                         input_mode_to_string(binding.mode), binding.name, binding.keys.size());
        }

        m_poller = std::make_shared<InputPoller>(std::move(m_pending_bindings), poll_interval, m_require_focus,
                                                 m_gamepad_index, m_trigger_threshold, m_stick_threshold);
        m_pending_bindings.clear();
        m_poller->start();
        m_active_poller.store(m_poller, std::memory_order_release);
        m_running.store(true, std::memory_order_release);
    }

    bool InputManager::is_running() const noexcept
    {
        return m_running.load(std::memory_order_acquire);
    }

    size_t InputManager::binding_count() const noexcept
    {
        std::lock_guard lock(m_mutex);
        if (m_poller)
        {
            return m_poller->binding_count();
        }
        return m_pending_bindings.size();
    }

    bool InputManager::is_binding_active(std::string_view name) const noexcept
    {
        auto active_poller = m_active_poller.load(std::memory_order_acquire);
        if (active_poller)
        {
            return active_poller->is_binding_active(name);
        }
        return false;
    }

    void InputManager::update_binding_combos(std::string_view name, const Config::KeyComboList &combos) noexcept
    {
        std::shared_ptr<InputPoller> local_poller;
        bool updated_pending = false;

        try
        {
            std::unique_lock lock(m_mutex);
            if (m_poller)
            {
                local_poller = m_poller;
            }
            else
            {
                std::vector<size_t> indices;
                indices.reserve(m_pending_bindings.size());
                for (size_t i = 0; i < m_pending_bindings.size(); ++i)
                {
                    if (m_pending_bindings[i].name == name)
                    {
                        indices.push_back(i);
                    }
                }
                if (indices.empty())
                {
                    // Release the lock before logging so the emit does not run inside the critical section
                    // (deferred-logging convention).
                    lock.unlock();
                    static_cast<void>(Logger::get_instance().try_log(
                        LogLevel::Debug, "InputManager: update_binding_combos(\"{}\") ignored: name not found", name));
                    return;
                }

                if (indices.size() == combos.size())
                {
                    std::vector<InputBinding> replacements;
                    replacements.reserve(indices.size());
                    for (size_t i = 0; i < indices.size(); ++i)
                    {
                        InputBinding binding = m_pending_bindings[indices[i]];
                        binding.keys = combos[i].keys;
                        binding.modifiers = combos[i].modifiers;
                        replacements.push_back(std::move(binding));
                    }
                    for (size_t i = 0; i < indices.size(); ++i)
                    {
                        m_pending_bindings[indices[i]] = std::move(replacements[i]);
                    }
                    updated_pending = true;
                }
                else
                {
                    InputBinding prototype = m_pending_bindings[indices.front()];
                    std::sort(indices.begin(), indices.end());

                    // Build the replacement entries (prototype copies are the throwing step) and reserve the rebuilt
                    // vector before moving any survivor out of m_pending_bindings, so an allocation failure leaves the
                    // pending list untouched. An empty replacement keeps one inert sentinel so the name stays
                    // addressable for a later non-empty update.
                    const size_t append_count = combos.empty() ? 1 : combos.size();
                    std::vector<InputBinding> appended;
                    appended.reserve(append_count);
                    if (combos.empty())
                    {
                        InputBinding sentinel = prototype;
                        sentinel.keys.clear();
                        sentinel.modifiers.clear();
                        appended.push_back(std::move(sentinel));
                    }
                    else
                    {
                        for (const auto &combo : combos)
                        {
                            InputBinding binding = prototype;
                            binding.keys = combo.keys;
                            binding.modifiers = combo.modifiers;
                            appended.push_back(std::move(binding));
                        }
                    }

                    std::vector<InputBinding> rebuilt;
                    rebuilt.reserve(m_pending_bindings.size() - indices.size() + append_count);
                    size_t cursor = 0;
                    for (size_t skip : indices)
                    {
                        for (size_t i = cursor; i < skip; ++i)
                        {
                            rebuilt.push_back(std::move(m_pending_bindings[i]));
                        }
                        cursor = skip + 1;
                    }
                    for (size_t i = cursor; i < m_pending_bindings.size(); ++i)
                    {
                        rebuilt.push_back(std::move(m_pending_bindings[i]));
                    }
                    for (auto &binding : appended)
                    {
                        rebuilt.push_back(std::move(binding));
                    }
                    m_pending_bindings = std::move(rebuilt);
                    updated_pending = true;
                }
            }
        }
        catch (...)
        {
            // update_binding_combos is noexcept; on out-of-memory the pending bindings are left unchanged (allocation
            // precedes the move-commit) rather than terminating the process.
            static_cast<void>(Logger::get_instance().try_log(
                LogLevel::Error, "InputManager: out of memory in update_binding_combos; pending bindings unchanged"));
            return;
        }

        if (local_poller)
        {
            (void)local_poller->update_combos(name, combos);
        }
        else if (updated_pending)
        {
            static_cast<void>(Logger::get_instance().try_log(
                LogLevel::Trace, "InputManager: update_binding_combos(\"{}\") applied to pending bindings", name));
        }
    }

    size_t InputManager::remove_binding_by_name(std::string_view name, bool invoke_callbacks) noexcept
    {
        std::shared_ptr<InputPoller> live_poller;
        size_t removed_pending = 0;

        {
            std::lock_guard lock(m_mutex);
            if (m_poller)
            {
                live_poller = m_poller;
            }
            else
            {
                auto new_end = std::remove_if(m_pending_bindings.begin(), m_pending_bindings.end(),
                                              [name](const InputBinding &b) { return b.name == name; });
                removed_pending = static_cast<size_t>(std::distance(new_end, m_pending_bindings.end()));
                m_pending_bindings.erase(new_end, m_pending_bindings.end());
            }
        }

        if (live_poller)
        {
            return live_poller->remove_bindings_by_name(name, invoke_callbacks);
        }
        return removed_pending;
    }

    void InputManager::clear_bindings(bool invoke_callbacks) noexcept
    {
        std::shared_ptr<InputPoller> live_poller;

        {
            std::lock_guard lock(m_mutex);
            m_pending_bindings.clear();
            if (m_poller)
            {
                live_poller = m_poller;
            }
        }

        if (live_poller)
        {
            live_poller->clear_bindings(invoke_callbacks);
        }
    }

    void InputManager::shutdown() noexcept
    {
        std::shared_ptr<InputPoller> local_poller;

        {
            std::lock_guard lock(m_mutex);
            // Clear atomic shared_ptr before releasing the poller to ensure concurrent is_binding_active() callers hold
            // a valid shared_ptr.
            m_active_poller.store(nullptr, std::memory_order_release);
            m_running.store(false, std::memory_order_release);
            local_poller = std::move(m_poller);
            m_pending_bindings.clear();
        }

        if (local_poller)
        {
            // Read loader-lock ownership once; it is stable across this call because InputPoller::shutdown() re-checks
            // it on the same thread with no intervening lock release, so both observe the same result.
            const bool under_loader_lock = is_loader_lock_held();
            local_poller->shutdown();

            if (under_loader_lock)
            {
                // Under the loader lock InputPoller::shutdown() detaches its poll thread instead of joining it (a join
                // would deadlock the loader). The detached thread keeps reading InputPoller members (m_cv, m_cv_mutex,
                // m_poll_interval, m_bindings) until it observes the stop request, so destroying the poller now would
                // free those members
                // mid-access: a use-after-free. Move the last reference into a
                // nothrow-allocated heap cell that is never freed, so the object outlives the detached thread. The
                // module is already pinned by
                // InputPoller::shutdown(). This mirrors the leak-on-loader-lock
                // discipline used for the Logger and ConfigWatcher teardown paths;
                // nothrow keeps this noexcept path honest under OOM (the poller is then destroyed -- the pre-existing
                // hazard -- rather than throwing).
                auto *leaked = new (std::nothrow) std::shared_ptr<InputPoller>(std::move(local_poller));
                (void)leaked;
            }
        }
    }
} // namespace DetourModKit
