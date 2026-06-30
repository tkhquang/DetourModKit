/**
 * @file input_poller.cpp
 * @brief Implementation of the internal input poll engine (input_poller.hpp).
 *
 * Drives the public input::Input facade: a background poll thread that reads keyboard, mouse, gamepad, and mouse-wheel
 * state, performs press/hold edge detection with strict modifier matching, and feeds the opt-in interception layer.
 */

#include "input_poller.hpp"
#include "input_intercept.hpp"
#include "input_key_cache.hpp"
#include "platform.hpp"

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <Xinput.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <new>
#include <shared_mutex>
#include <type_traits>
#include <unordered_set>

namespace DetourModKit::detail
{
    namespace
    {
        /**
         * @brief Checks whether a single InputCode is currently pressed.
         * @param code The input code to check.
         * @param key_cache Per-cycle keyboard/mouse down-state memoization, probed at most once per distinct VK.
         * @param gamepad_state Cached XInput state for the current poll cycle.
         * @param gamepad_connected Whether the gamepad is connected.
         * @param trigger_threshold Analog trigger deadzone threshold.
         * @param stick_threshold Thumbstick deadzone threshold.
         * @param wheel_pulse Per-cycle wheel pulse mask (bit 0 = WheelUp .. bit 3 =
         *        WheelRight), latched once per cycle by the poll loop so repeated reads within a cycle stay consistent.
         * @return true if the input is currently pressed.
         */
        bool is_code_pressed(const InputCode &code, KeyStateCache &key_cache, const XINPUT_STATE &gamepad_state,
                             bool gamepad_connected, int trigger_threshold, int stick_threshold,
                             uint8_t wheel_pulse) noexcept
        {
            switch (code.source)
            {
            case InputSource::Keyboard:
            case InputSource::Mouse:
                // Route every keyboard/mouse read through the per-cycle cache so a VK referenced by many bindings (and
                // by the strict known-modifier rescan) costs one GetAsyncKeyState call per cycle, not one per
                // reference. The probe reads only the high (down) bit and gives the whole cycle one coherent sample.
                return code.code != 0 && key_cache.pressed(code.code, [](int vk) noexcept
                                                           { return (GetAsyncKeyState(vk) & 0x8000) != 0; });
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
        std::vector<GamepadConsumeRule> build_gamepad_consume_rules(const std::vector<InputBinding> &bindings,
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

            std::vector<GamepadConsumeRule> rules;
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
                rules.push_back(GamepadConsumeRule{modifier_mask, forbidden_mask, trigger_mask});
            }
            return rules;
        }

        // Release grace for gamepad consume-until-release. Long enough to absorb the modifier-released-before-trigger
        // window (the player relaxing the bumper a frame or two before the thumb leaves the D-pad) without noticeably
        // delaying a deliberate tap that follows.
        constexpr uint64_t GAMEPAD_SUPPRESS_GRACE_MS = 80;

        // Process-wide monotonic source for BindingToken generations. Each InputPoller reshape draws a fresh value, so
        // a generation is unique across the whole process and across poller lifetimes: a token minted by one poller can
        // never alias a different poller's state (for example after a shutdown / start cycle swaps the poller). Starts
        // at 1 so the value 0 stays reserved for an invalid token.
        std::atomic<std::uint64_t> s_next_binding_generation{1};

        /// Draws the next unique binding generation. Lock-free; relaxed suffices (uniqueness, not ordering, is needed).
        std::uint64_t next_binding_generation() noexcept
        {
            return s_next_binding_generation.fetch_add(1, std::memory_order_relaxed);
        }
    } // anonymous namespace

    static_assert(std::is_nothrow_move_assignable_v<InputBinding>,
                  "Input reshape commits rely on noexcept InputBinding move assignment");

    InputPoller::InputPoller(std::vector<InputBinding> bindings, std::chrono::milliseconds poll_interval,
                             bool require_focus, int gamepad_index, int trigger_threshold, int stick_threshold)
        : m_bindings(std::move(bindings)),
          m_poll_interval(std::clamp(poll_interval, input::MIN_POLL_INTERVAL, input::MAX_POLL_INTERVAL)),
          m_require_focus(require_focus), m_active_states(std::make_unique<std::atomic<uint8_t>[]>(m_bindings.size())),
          m_gamepad_index(std::clamp(gamepad_index, 0, 3)), m_trigger_threshold(std::clamp(trigger_threshold, 0, 255)),
          m_stick_threshold(std::clamp(stick_threshold, 0, 32767))
    {
        m_name_index.reserve(m_bindings.size());
        recompute_modifier_caches_locked();
    }

    void InputPoller::recompute_modifier_caches_locked() noexcept
    {
        // Any call here rebuilds m_name_index, so a cached BindingToken's indices may no longer address the same
        // bindings. Advance the generation up front -- even if the rebuild below fails into the catch and clears the
        // caches -- so every outstanding token is conservatively invalidated and fails closed until re-acquired.
        m_binding_generation = next_binding_generation();

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
            const std::vector<GamepadConsumeRule> consume_rules =
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
            publish_gamepad_consume_rules(consume_rules.data(), consume_rules.size());
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
            publish_gamepad_consume_rules(nullptr, 0);
            (void)Logger::get_instance().try_log(
                LogLevel::Error, "InputPoller: out of memory rebuilding modifier caches; "
                                 "name lookup and input interception disabled until the next successful rebuild");
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
        std::shared_lock lock(m_bindings_rw_mutex);
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
                // The shared lock holds m_name_index and m_active_states consistent, so idx is in bounds here. The
                // explicit bound check is defence in depth against a future reshape that repopulates m_name_index
                // without resizing m_active_states (the same guard the BindingToken overload carries); it costs one
                // comparison per matching binding (typically 1-3).
                if (idx < m_bindings.size() && m_active_states[idx].load(std::memory_order_relaxed) != 0)
                {
                    return true;
                }
            }
        }
        return false;
    }

    input::BindingToken InputPoller::acquire_binding_token(std::string_view name) const noexcept
    {
        input::BindingToken token;
        try
        {
            std::shared_lock lock(m_bindings_rw_mutex);
            const auto it = m_name_index.find(name);
            if (it == m_name_index.end())
            {
                // Unknown name: leave the token invalid (generation 0).
                return token;
            }
            // Copy the resolved indices first (the only throwing step), then stamp the generation only once the copy
            // succeeds, so an allocation failure leaves the token invalid rather than valid-but-empty.
            token.m_indices = it->second;
            token.m_generation = m_binding_generation;
        }
        catch (...)
        {
            // Out of memory copying the index set. acquire_binding_token is noexcept; return an invalid token so the
            // consumer falls back to the name-based query rather than terminating the host.
            return input::BindingToken{};
        }
        return token;
    }

    bool InputPoller::is_binding_active(const input::BindingToken &token) const noexcept
    {
        if (!token.valid())
        {
            return false;
        }
        std::shared_lock lock(m_bindings_rw_mutex);
        // A reshape since acquisition advanced m_binding_generation, so a mismatch means the cached indices may no
        // longer address the same bindings (or may be out of bounds): fail closed without touching them.
        if (token.m_generation != m_binding_generation)
        {
            return false;
        }
        for (const size_t idx : token.m_indices)
        {
            // The generation match proves no reshape resized the binding array since acquisition, so idx is in bounds.
            // The explicit bound check is defence in depth against a future reshape path that forgets to advance the
            // generation; it costs one comparison per cached entry (typically 1-3).
            if (idx < m_bindings.size() && m_active_states[idx].load(std::memory_order_relaxed) != 0)
            {
                return true;
            }
        }
        return false;
    }

    bool InputPoller::binding_token_current(const input::BindingToken &token) const noexcept
    {
        if (!token.valid())
        {
            return false;
        }
        std::shared_lock lock(m_bindings_rw_mutex);
        return token.m_generation == m_binding_generation;
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
        uninstall();

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
        WheelPulseState wheel_pulse{};
        GamepadSuppressState gp_suppress{};

        // Reused across cycles so each tick does not re-zero a 16-byte XINPUT_STATE. Poll-thread-private: only this
        // loop reads or writes it, and a stale value is never observed because is_code_pressed reads it only when
        // gamepad_connected (recomputed every cycle) is true, which holds only after a successful poll overwrites it.
        XINPUT_STATE gamepad_state{};

        // Per-cycle keyboard/mouse down-state cache, reset at the top of every cycle so each distinct VK costs one
        // GetAsyncKeyState call per cycle instead of one per binding reference (see input_key_cache.hpp). Declared
        // once so its 256-byte table is allocated for the poll thread's lifetime, not rebuilt each cycle.
        KeyStateCache key_cache;

        struct PendingCallback
        {
            std::string name;
            std::function<void()> on_press;
            std::function<void(bool)> on_state_change;
            bool hold_value;
        };
        std::vector<PendingCallback> pending;

        while (!stop_token.stop_requested())
        {
            pending.clear();
            key_cache.reset();
            const bool process_focused = !m_require_focus.load(std::memory_order_relaxed) || is_process_foreground();

            // Lazily install the active-input hooks the current bindings need. Each call is idempotent and fails
            // cheaply until its target (a loaded xinput module / the game window) becomes available, so this also
            // handles a target that appears after the poller starts.
            if (m_has_consume_gamepad_bindings.load(std::memory_order_relaxed) && !xinput_installed())
            {
                (void)install_xinput(m_gamepad_index);
            }
            if (m_has_wheel_bindings.load(std::memory_order_relaxed) && !wndproc_installed())
            {
                (void)install_wndproc();
            }

            // Snapshot the wheel notches the window-procedure hook accumulated into a per-cycle pulse mask, so every
            // binding this cycle reads a consistent value and each notch maps to exactly one Press edge. The counters
            // are drained even when unfocused so a background notch is discarded rather than queued to fire on the next
            // focus.
            uint8_t wheel_pulse_mask = 0;
            if (m_has_wheel_bindings.load(std::memory_order_relaxed))
            {
                const auto taken = take_wheel_counts();
                add_wheel_notches(wheel_pulse, taken);
                wheel_pulse_mask = step_wheel_pulse(wheel_pulse);
            }

            // Drive the wheel-swallow flag every cycle, outside the wheel-binding guard above, so it disarms on the
            // first cycle after the last consume wheel binding is removed at runtime: the window-procedure subclass
            // stays installed until shutdown, so a stale true would keep eating the game's wheel forever (the gamepad
            // mask self-heals via its TTL, but the wheel flag has none). Gate it on focus to mirror the gamepad mask
            // clear
            // below: a backgrounded mod must not swallow the focused app's wheel.
            set_wheel_consume(process_focused && m_has_wheel_consume_bindings.load(std::memory_order_relaxed));

            // Digital gamepad button bits claimed by active consume chords this cycle, accumulated in the binding loop
            // and published afterwards.
            uint16_t gamepad_owned = 0;

            // Poll gamepad state once per cycle when connected, into the hoisted gamepad_state buffer. When
            // disconnected, throttle reconnection attempts to avoid the per-cycle overhead of XInputGetState on empty
            // slots. Read through the saved trampoline when the suppression hook is installed so the poll observes the
            // true, unmasked controller state rather than its own published mask. A successful poll overwrites the
            // whole struct, and gamepad_state is read only when gamepad_connected is true, so a stale buffer is never
            // observed.
            bool gamepad_connected = false;
            if (m_has_gamepad_bindings.load(std::memory_order_relaxed) && process_focused)
            {
                const auto now = std::chrono::steady_clock::now();
                if (gamepad_was_connected || (now - last_gamepad_poll) >= gamepad_reconnect_interval)
                {
                    last_gamepad_poll = now;
                    const XInputGetStateFn xinput_original = xinput_trampoline();
                    const DWORD xinput_result =
                        (xinput_original != nullptr)
                            ? xinput_original(static_cast<DWORD>(m_gamepad_index), &gamepad_state)
                            : XInputGetState(static_cast<DWORD>(m_gamepad_index), &gamepad_state);
                    gamepad_was_connected = xinput_result == ERROR_SUCCESS;
                }
                gamepad_connected = gamepad_was_connected;
            }

            // Stage this cycle's edge callbacks, then dispatch them after releasing the binding lock so user code can
            // call back into update_combos() without deadlocking. Growing the staging vector can allocate, and copying
            // each entry's name/std::function can allocate or run a throwing target copy constructor. The whole staging
            // pass runs under one catch so a failed callback batch is dropped instead of escaping the jthread body and
            // calling std::terminate. m_active_states may then reflect a partial pass, but the next cycle re-evaluates
            // from the live physical input, so at most one cycle of edge callbacks is missed under sustained failure.
            try
            {
                // Re-reserve to the current binding count before taking the evaluation lock. add_binding can grow
                // m_bindings past the startup capacity while the poller runs, so without this the per-cycle push_back
                // could reallocate the staging vector while the shared lock is held. Reading the count under a short
                // reader lock and reserving after releasing it keeps that growth allocation out of the evaluation
                // critical section; the catch above still covers the residual race where a concurrent add_binding
                // grows the set again before the evaluation lock is taken.
                size_t reserve_hint = 0;
                {
                    std::shared_lock count_lock(m_bindings_rw_mutex);
                    reserve_hint = m_bindings.size();
                }
                pending.reserve(reserve_hint);

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
                            if (!is_code_pressed(mod, key_cache, gamepad_state, gamepad_connected, trigger_thresh,
                                                 stick_thresh, wheel_pulse_mask))
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
                                if (!is_code_pressed(km, key_cache, gamepad_state, gamepad_connected, trigger_thresh,
                                                     stick_thresh, wheel_pulse_mask))
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
                                    is_code_pressed(key, key_cache, gamepad_state, gamepad_connected, trigger_thresh,
                                                    stick_thresh, wheel_pulse_mask);

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

                    switch (binding.trigger)
                    {
                    case input::Trigger::Press:
                    {
                        if (any_pressed && !was_active && binding.on_press)
                        {
                            pending.push_back({binding.name, binding.on_press, {}, false});
                        }
                        m_active_states[i].store(any_pressed ? 1 : 0, std::memory_order_relaxed);
                        break;
                    }
                    case input::Trigger::Hold:
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
            catch (...)
            {
                // Staging this cycle's edge callbacks failed. Drop the partial callback list (the shared lock has
                // already been released by stack unwinding, so there is no deadlock) rather than terminating the poll
                // thread. The gamepad suppression publish below still runs from whatever was accumulated, and
                // self-heals next cycle.
                pending.clear();
                (void)Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: failed staging poll-cycle callbacks; callbacks skipped");
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
                        step_gamepad_suppress(gp_suppress, gamepad_owned, gamepad_state.Gamepad.wButtons,
                                              GetTickCount64(), GAMEPAD_SUPPRESS_GRACE_MS);
                    publish_gamepad_suppress(suppress);
                    // Enable the detour's rule masking only while focused and connected. The published rule list and
                    // its time-to-live survive focus changes, so the detour needs this explicit gate to stop masking
                    // the foreground game's input once the mod is backgrounded, exactly as the reactive mask is cleared
                    // below and as the wheel-consume flag is gated.
                    set_gamepad_rule_suppress_enabled(true);
                }
                else
                {
                    gp_suppress = GamepadSuppressState{};
                    publish_gamepad_suppress(0);
                    set_gamepad_rule_suppress_enabled(false);
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
                    (void)Logger::get_instance().try_log(
                        LogLevel::Error, "InputPoller: Exception in callback \"{}\": {}", callback.name, e.what());
                }
                catch (...)
                {
                    (void)Logger::get_instance().try_log(
                        LogLevel::Error, "InputPoller: Unknown exception in callback \"{}\"", callback.name);
                }
            }

            std::unique_lock lock(m_cv_mutex);
            m_cv.wait_for(lock, stop_token, m_poll_interval, [&stop_token]() { return stop_token.stop_requested(); });
        }
    }

    bool InputPoller::update_combos(std::string_view name, const input::KeyComboList &combos) noexcept
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
                (void)Logger::get_instance().try_log(
                    LogLevel::Debug, "InputPoller: update_combos(\"{}\") ignored: name not found", name);
                return false;
            }

            std::vector<size_t> indices = it->second;
            if (indices.empty())
            {
                return false;
            }

            // Cardinality-preserving fast path: in-place rewrite of keys and modifiers leaves m_bindings and
            // m_active_states in lockstep. The poll thread's binding-evaluation pass and every other reader
            // (is_binding_active, binding_count) hold the shared lock, so the unique_lock here serializes against
            // them; concurrent is_binding_active(size_t) reads stay valid because the binding count and array
            // sizes do not change.
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
                    m_bindings[idx].trigger == input::Trigger::Hold && m_bindings[idx].on_state_change)
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
            (void)Logger::get_instance().try_log(LogLevel::Error,
                                                 "InputPoller: out of memory in update_combos; combos unchanged");
            return false;
        }

        // Fire the captured release callbacks outside the writer lock so user code may safely call back into the
        // facade (matching the remove_bindings_by_name pattern). This path runs in response to a user-driven INI
        // reshape, never from a DllMain detach, so synchronous callback dispatch is safe here.
        for (size_t i = 0; i < hold_release_callbacks.size(); ++i)
        {
            try
            {
                hold_release_callbacks[i](false);
            }
            catch (const std::exception &e)
            {
                (void)Logger::get_instance().try_log(LogLevel::Error,
                                                     "InputPoller: Exception in hold release callback \"{}\": {}",
                                                     hold_release_names[i], e.what());
            }
            catch (...)
            {
                (void)Logger::get_instance().try_log(LogLevel::Error,
                                                     "InputPoller: Unknown exception in hold release callback \"{}\"",
                                                     hold_release_names[i]);
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
            (void)Logger::get_instance().try_log(LogLevel::Error,
                                                 "InputPoller: out of memory in add_binding; binding not added");
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
            // so user code is free to call back into the facade. The Bootstrap unload path passes
            // invoke_callbacks=false to skip this step because the user callbacks live in a Logic DLL whose code pages
            // may be about to be unmapped.
            if (invoke_callbacks)
            {
                for (size_t idx : indices)
                {
                    if (m_active_states[idx].load(std::memory_order_relaxed) != 0 &&
                        m_bindings[idx].trigger == input::Trigger::Hold && m_bindings[idx].on_state_change)
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
            (void)Logger::get_instance().try_log(
                LogLevel::Error, "InputPoller: out of memory in remove_bindings_by_name; bindings unchanged");
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
                (void)Logger::get_instance().try_log(LogLevel::Error,
                                                     "InputPoller: Exception in hold release callback \"{}\": {}",
                                                     hold_release_names[i], e.what());
            }
            catch (...)
            {
                (void)Logger::get_instance().try_log(LogLevel::Error,
                                                     "InputPoller: Unknown exception in hold release callback \"{}\"",
                                                     hold_release_names[i]);
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
                        m_bindings[i].trigger == input::Trigger::Hold && m_bindings[i].on_state_change)
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
            // clear_bindings does not route through recompute_modifier_caches_locked, so advance the generation here so
            // outstanding BindingTokens fail closed once the binding set is emptied.
            m_binding_generation = next_binding_generation();
            m_has_gamepad_bindings.store(false, std::memory_order_relaxed);
            m_has_wheel_bindings.store(false, std::memory_order_relaxed);
            m_has_consume_gamepad_bindings.store(false, std::memory_order_relaxed);
            m_has_wheel_consume_bindings.store(false, std::memory_order_relaxed);
            publish_gamepad_consume_rules(nullptr, 0);
            m_active_states = std::move(new_states);
        }
        catch (...)
        {
            (void)Logger::get_instance().try_log(LogLevel::Error,
                                                 "InputPoller: out of memory in clear_bindings; bindings unchanged");
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
                (void)Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}", name, e.what());
            }
            catch (...)
            {
                (void)Logger::get_instance().try_log(
                    LogLevel::Error, "InputPoller: Unknown exception in hold release callback \"{}\"", name);
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
                if (binding.trigger == input::Trigger::Hold && binding.on_state_change)
                {
                    try
                    {
                        binding.on_state_change(false);
                    }
                    catch (const std::exception &e)
                    {
                        (void)Logger::get_instance().try_log(
                            LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}", binding.name,
                            e.what());
                    }
                    catch (...)
                    {
                        (void)Logger::get_instance().try_log(
                            LogLevel::Error, "InputPoller: Unknown exception in hold release callback \"{}\"",
                            binding.name);
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
} // namespace DetourModKit::detail
