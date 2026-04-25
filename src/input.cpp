/**
 * @file input.cpp
 * @brief Implementation of the input polling and hotkey management system.
 *
 * Provides InputPoller (RAII polling engine) and InputManager (singleton wrapper)
 * for monitoring keyboard, mouse, and gamepad input states on a background thread.
 * Supports press (edge-triggered) and hold (level-triggered) input modes with
 * modifier combinations, focus-aware polling, and XInput gamepad support.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/logger.hpp"

#include "platform.hpp"

#include <windows.h>
#include <Xinput.h>
#include <algorithm>
#include <exception>
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
         * @return true if the input is currently pressed.
         */
        bool is_code_pressed(const InputCode &code,
                             const XINPUT_STATE &gamepad_state,
                             bool gamepad_connected,
                             int trigger_threshold,
                             int stick_threshold) noexcept
        {
            switch (code.source)
            {
            case InputSource::Keyboard:
            case InputSource::Mouse:
                return code.code != 0 && (GetAsyncKeyState(code.code) & 0x8000) != 0;
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
         * @details Returns true when the codes match exactly, or when both are
         *          keyboard modifiers in the same family (e.g., LShift satisfies
         *          generic Shift, and generic Shift satisfies LShift).
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
    } // anonymous namespace

    // --- InputPoller ---

    InputPoller::InputPoller(std::vector<InputBinding> bindings,
                             std::chrono::milliseconds poll_interval,
                             bool require_focus,
                             int gamepad_index,
                             int trigger_threshold,
                             int stick_threshold)
        : bindings_(std::move(bindings)),
          poll_interval_(std::clamp(poll_interval, MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)),
          require_focus_(require_focus),
          active_states_(std::make_unique<std::atomic<uint8_t>[]>(bindings_.size())),
          gamepad_index_(std::clamp(gamepad_index, 0, 3)),
          trigger_threshold_(std::clamp(trigger_threshold, 0, 255)), stick_threshold_(std::clamp(stick_threshold, 0, 32767))
    {
        name_index_.reserve(bindings_.size());
        recompute_modifier_caches_locked();
    }

    void InputPoller::recompute_modifier_caches_locked() noexcept
    {
        name_index_.clear();
        std::unordered_set<InputCode, InputCodeHash> modifier_set;
        for (size_t i = 0; i < bindings_.size(); ++i)
        {
            if (!bindings_[i].name.empty())
            {
                name_index_[bindings_[i].name].push_back(i);
            }
            for (const auto &mod : bindings_[i].modifiers)
            {
                modifier_set.insert(mod);
            }
        }
        known_modifiers_.assign(modifier_set.begin(), modifier_set.end());
        has_gamepad_bindings_.store(scan_for_gamepad_bindings(bindings_), std::memory_order_relaxed);
    }

    InputPoller::~InputPoller() noexcept
    {
        shutdown();
    }

    void InputPoller::start()
    {
        if (poll_thread_.joinable())
        {
            Logger::get_instance().debug("InputPoller: start() called while already running; no-op.");
            return;
        }

        running_.store(true, std::memory_order_release);
        try
        {
            poll_thread_ = std::jthread([this](std::stop_token token)
                                        { poll_loop(std::move(token)); });
        }
        catch (...)
        {
            running_.store(false, std::memory_order_release);
            throw;
        }
    }

    bool InputPoller::is_running() const noexcept
    {
        return running_.load(std::memory_order_acquire);
    }

    size_t InputPoller::binding_count() const noexcept
    {
        return bindings_.size();
    }

    std::chrono::milliseconds InputPoller::poll_interval() const noexcept
    {
        return poll_interval_;
    }

    int InputPoller::gamepad_index() const noexcept
    {
        return gamepad_index_;
    }

    bool InputPoller::is_binding_active(size_t index) const noexcept
    {
        // Acquire the shared lock so the index/array pair stays consistent
        // across a reshape (add_binding, remove_bindings_by_name,
        // update_combos all swap active_states_ under the writer lock and
        // resize bindings_ alongside it). The relaxed atomic load on the
        // element itself is still cheap; it is the unique_ptr<atomic[]>
        // ownership swap that needs synchronisation.
        std::shared_lock lock(bindings_rw_mutex_);
        if (index >= bindings_.size())
        {
            return false;
        }
        return active_states_[index].load(std::memory_order_relaxed) != 0;
    }

    bool InputPoller::is_binding_active(std::string_view name) const noexcept
    {
        std::shared_lock lock(bindings_rw_mutex_);
        const auto it = name_index_.find(name);
        if (it != name_index_.end())
        {
            for (const size_t idx : it->second)
            {
                if (active_states_[idx].load(std::memory_order_relaxed) != 0)
                {
                    return true;
                }
            }
        }
        return false;
    }

    void InputPoller::set_require_focus(bool require_focus) noexcept
    {
        require_focus_.store(require_focus, std::memory_order_relaxed);
    }

    void InputPoller::shutdown() noexcept
    {
        if (!poll_thread_.joinable())
        {
            return;
        }

        poll_thread_.request_stop();
        cv_.notify_all();

        if (is_loader_lock_held())
        {
            pin_current_module();
            poll_thread_.detach();
        }
        else
        {
            poll_thread_.join();
        }

        running_.store(false, std::memory_order_release);
        release_active_holds();
    }

    void InputPoller::poll_loop(std::stop_token stop_token)
    {
        const int trigger_thresh = trigger_threshold_;
        const int stick_thresh = stick_threshold_;

        constexpr auto gamepad_reconnect_interval = std::chrono::seconds{2};
        bool gamepad_was_connected = false;
        auto last_gamepad_poll = std::chrono::steady_clock::time_point{};

        struct PendingCallback
        {
            std::string name;
            std::function<void()> on_press;
            std::function<void(bool)> on_state_change;
            bool hold_value;
        };
        std::vector<PendingCallback> pending;
        {
            std::shared_lock lock(bindings_rw_mutex_);
            pending.reserve(bindings_.size());
        }

        while (!stop_token.stop_requested())
        {
            pending.clear();
            const bool process_focused =
                !require_focus_.load(std::memory_order_relaxed) || is_process_foreground();

            // Poll gamepad state once per cycle when connected.
            // When disconnected, throttle reconnection attempts to avoid
            // the per-cycle overhead of XInputGetState on empty slots.
            XINPUT_STATE gamepad_state{};
            bool gamepad_connected = false;
            if (has_gamepad_bindings_.load(std::memory_order_relaxed) && process_focused)
            {
                const auto now = std::chrono::steady_clock::now();
                if (gamepad_was_connected ||
                    (now - last_gamepad_poll) >= gamepad_reconnect_interval)
                {
                    last_gamepad_poll = now;
                    gamepad_was_connected =
                        XInputGetState(static_cast<DWORD>(gamepad_index_),
                                       &gamepad_state) == ERROR_SUCCESS;
                }
                gamepad_connected = gamepad_was_connected;
            }

            // Collect callbacks to fire outside the shared lock so user code
            // can call back into update_binding_combos() without deadlocking.
            {
                std::shared_lock lock(bindings_rw_mutex_);
                const size_t count = bindings_.size();
                const auto &known_mods = known_modifiers_;

                for (size_t i = 0; i < count; ++i)
                {
                    const auto &binding = bindings_[i];
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
                            if (!is_code_pressed(mod, gamepad_state, gamepad_connected, trigger_thresh, stick_thresh))
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
                                if (!is_code_pressed(km, gamepad_state, gamepad_connected, trigger_thresh, stick_thresh))
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
                                if (is_code_pressed(key, gamepad_state, gamepad_connected, trigger_thresh, stick_thresh))
                                {
                                    any_pressed = true;
                                    break;
                                }
                            }
                        }
                    }

                    const bool was_active =
                        active_states_[i].load(std::memory_order_relaxed) != 0;

                    switch (binding.mode)
                    {
                    case InputMode::Press:
                    {
                        if (any_pressed && !was_active && binding.on_press)
                        {
                            pending.push_back({binding.name, binding.on_press, {}, false});
                        }
                        active_states_[i].store(any_pressed ? 1 : 0, std::memory_order_relaxed);
                        break;
                    }
                    case InputMode::Hold:
                    {
                        if (any_pressed != was_active && binding.on_state_change)
                        {
                            pending.push_back({binding.name, {}, binding.on_state_change, any_pressed});
                        }
                        active_states_[i].store(any_pressed ? 1 : 0, std::memory_order_relaxed);
                        break;
                    }
                    }
                }
            }

            for (auto &p : pending)
            {
                try
                {
                    if (p.on_press)
                    {
                        p.on_press();
                    }
                    else if (p.on_state_change)
                    {
                        p.on_state_change(p.hold_value);
                    }
                }
                catch (const std::exception &e)
                {
                    Logger::get_instance().error(
                        "InputPoller: Exception in callback \"{}\": {}", p.name, e.what());
                }
                catch (...)
                {
                    Logger::get_instance().error(
                        "InputPoller: Unknown exception in callback \"{}\"", p.name);
                }
            }

            std::unique_lock lock(cv_mutex_);
            cv_.wait_for(lock, stop_token, poll_interval_, [&stop_token]()
                         { return stop_token.stop_requested(); });
        }
    }

    bool InputPoller::update_combos(std::string_view name, const Config::KeyComboList &combos) noexcept
    {
        std::vector<std::function<void(bool)>> hold_release_callbacks;
        std::vector<std::string> hold_release_names;

        {
            std::unique_lock lock(bindings_rw_mutex_);
            const auto it = name_index_.find(name);
            if (it == name_index_.end())
            {
                Logger::get_instance().debug("InputPoller: update_combos(\"{}\") ignored: name not found", name);
                return false;
            }

            std::vector<size_t> indices = it->second;
            if (indices.empty())
            {
                return false;
            }

            // Cardinality-preserving fast path: in-place rewrite of keys and
            // modifiers leaves bindings_ and active_states_ in lockstep. The
            // poll thread holds a shared_lock for the duration of one tick,
            // so the unique_lock here serializes against it; concurrent
            // is_binding_active(size_t) reads stay valid because the
            // binding count and array sizes do not change.
            if (indices.size() == combos.size())
            {
                for (size_t i = 0; i < indices.size(); ++i)
                {
                    const size_t idx = indices[i];
                    bindings_[idx].keys = combos[i].keys;
                    bindings_[idx].modifiers = combos[i].modifiers;
                }
                recompute_modifier_caches_locked();
                return true;
            }

            // Cardinality change requires rebuilding the bindings vector and
            // the parallel active_states_ array. Capture the prototype from
            // the first existing entry so callback identity, mode, and name
            // stay stable across the rebuild.
            InputBinding prototype = bindings_[indices.front()];

            // Capture release callbacks for any held entries that this update
            // is about to drop. Without this, a register_hold consumer whose
            // combo cardinality changes via INI hot-reload would latch in the
            // held state forever because the underlying entry vanishes from
            // bindings_ before the next poll tick can observe the release.
            for (size_t idx : indices)
            {
                if (active_states_[idx].load(std::memory_order_relaxed) != 0 &&
                    bindings_[idx].mode == InputMode::Hold &&
                    bindings_[idx].on_state_change)
                {
                    hold_release_callbacks.push_back(bindings_[idx].on_state_change);
                    hold_release_names.push_back(bindings_[idx].name);
                }
            }

            std::sort(indices.begin(), indices.end());

            // Build a parallel old-state vector keyed to the new bindings_
            // order so surviving entries carry their atomic value across the
            // swap. Newly appended combos default to zero (the genuine
            // cardinality-grew case has no prior state to inherit). Entries
            // that get rewritten through the prototype path also start at
            // zero because the underlying combo is logically replaced even
            // if the binding name persists.
            std::vector<InputBinding> rebuilt;
            std::vector<uint8_t> rebuilt_states;
            rebuilt.reserve(bindings_.size() - indices.size() + combos.size());
            rebuilt_states.reserve(rebuilt.capacity());
            size_t cursor = 0;
            for (size_t skip : indices)
            {
                for (size_t i = cursor; i < skip; ++i)
                {
                    rebuilt_states.push_back(active_states_[i].load(std::memory_order_relaxed));
                    rebuilt.push_back(std::move(bindings_[i]));
                }
                cursor = skip + 1;
            }
            for (size_t i = cursor; i < bindings_.size(); ++i)
            {
                rebuilt_states.push_back(active_states_[i].load(std::memory_order_relaxed));
                rebuilt.push_back(std::move(bindings_[i]));
            }
            if (combos.empty())
            {
                // Empty replacement leaves one inert sentinel entry so the
                // binding name stays addressable for a subsequent
                // update_combos() call. Without the sentinel the name would
                // vanish from name_index_ and a later non-empty update
                // would be rejected as "name not found", breaking the
                // bound -> unbound -> bound INI hot-reload cycle.
                InputBinding b = prototype;
                b.keys.clear();
                b.modifiers.clear();
                rebuilt.push_back(std::move(b));
                rebuilt_states.push_back(0);
            }
            else
            {
                for (const auto &combo : combos)
                {
                    InputBinding b = prototype;
                    b.keys = combo.keys;
                    b.modifiers = combo.modifiers;
                    rebuilt.push_back(std::move(b));
                    rebuilt_states.push_back(0);
                }
            }
            bindings_ = std::move(rebuilt);

            // Reallocate active_states_ to match the new binding count and
            // seed each slot from the captured pre-rebuild value. Surviving
            // entries keep their atomic state so a held binding does not
            // momentarily report inactive; the writer lock serialises the
            // swap against any concurrent is_binding_active() reader.
            auto new_states = std::make_unique<std::atomic<uint8_t>[]>(bindings_.size());
            for (size_t i = 0; i < rebuilt_states.size(); ++i)
            {
                new_states[i].store(rebuilt_states[i], std::memory_order_relaxed);
            }
            active_states_ = std::move(new_states);

            recompute_modifier_caches_locked();
        }

        // Fire the captured release callbacks outside the writer lock so user
        // code may safely call back into the InputManager (matching the
        // remove_bindings_by_name pattern). This path runs in response to a
        // user-driven INI reshape, never from a DllMain detach, so synchronous
        // callback dispatch is safe here.
        for (size_t i = 0; i < hold_release_callbacks.size(); ++i)
        {
            try
            {
                hold_release_callbacks[i](false);
            }
            catch (const std::exception &e)
            {
                Logger::get_instance().error(
                    "InputPoller: Exception in hold release callback \"{}\": {}",
                    hold_release_names[i], e.what());
            }
            catch (...)
            {
                Logger::get_instance().error(
                    "InputPoller: Unknown exception in hold release callback \"{}\"",
                    hold_release_names[i]);
            }
        }

        return true;
    }

    void InputPoller::add_binding(InputBinding binding) noexcept
    {
        std::unique_lock lock(bindings_rw_mutex_);

        // Capture the existing per-binding atomic states before the swap so
        // surviving entries do not flicker through a one-tick "inactive" blip
        // while the new active_states_ array is built. The relaxed load is
        // sufficient: we already hold the writer lock, which serialises us
        // against every other reader and writer of this array.
        const size_t old_count = bindings_.size();
        std::vector<uint8_t> carried;
        carried.reserve(old_count);
        for (size_t i = 0; i < old_count; ++i)
        {
            carried.push_back(active_states_[i].load(std::memory_order_relaxed));
        }

        bindings_.push_back(std::move(binding));

        auto new_states = std::make_unique<std::atomic<uint8_t>[]>(bindings_.size());
        for (size_t i = 0; i < carried.size(); ++i)
        {
            new_states[i].store(carried[i], std::memory_order_relaxed);
        }
        active_states_ = std::move(new_states);

        recompute_modifier_caches_locked();
    }

    size_t InputPoller::remove_bindings_by_name(std::string_view name, bool invoke_callbacks) noexcept
    {
        std::vector<std::function<void(bool)>> hold_release_callbacks;
        std::vector<std::string> hold_release_names;
        size_t removed = 0;

        {
            std::unique_lock lock(bindings_rw_mutex_);
            const auto it = name_index_.find(name);
            if (it == name_index_.end())
            {
                return 0;
            }

            std::vector<size_t> indices = it->second;
            std::sort(indices.begin(), indices.end());

            // Capture release callbacks for active hold bindings before
            // erasure; fire them after the lock is released so user code
            // is free to call back into the InputManager. The Bootstrap
            // unload path passes invoke_callbacks=false to skip this step
            // because the user callbacks live in a Logic DLL whose code
            // pages may be about to be unmapped.
            if (invoke_callbacks)
            {
                for (size_t idx : indices)
                {
                    if (active_states_[idx].load(std::memory_order_relaxed) != 0 &&
                        bindings_[idx].mode == InputMode::Hold &&
                        bindings_[idx].on_state_change)
                    {
                        hold_release_callbacks.push_back(bindings_[idx].on_state_change);
                        hold_release_names.push_back(bindings_[idx].name);
                    }
                }
            }

            // Build a flat skip-mask so the new active_states_ slot for every
            // surviving binding inherits its prior atomic value. Without this
            // a held binding would briefly report inactive after the
            // reshape, breaking register_hold consumers that observe the
            // state through is_binding_active(size_t).
            std::vector<bool> drop(bindings_.size(), false);
            for (size_t idx : indices)
            {
                drop[idx] = true;
            }
            std::vector<uint8_t> carried;
            carried.reserve(bindings_.size() - indices.size());
            for (size_t i = 0; i < bindings_.size(); ++i)
            {
                if (!drop[i])
                {
                    carried.push_back(active_states_[i].load(std::memory_order_relaxed));
                }
            }

            for (auto idx_it = indices.rbegin(); idx_it != indices.rend(); ++idx_it)
            {
                bindings_.erase(bindings_.begin() + static_cast<std::ptrdiff_t>(*idx_it));
            }
            removed = indices.size();

            auto new_states = std::make_unique<std::atomic<uint8_t>[]>(bindings_.size());
            for (size_t i = 0; i < carried.size(); ++i)
            {
                new_states[i].store(carried[i], std::memory_order_relaxed);
            }
            active_states_ = std::move(new_states);

            recompute_modifier_caches_locked();
        }

        for (size_t i = 0; i < hold_release_callbacks.size(); ++i)
        {
            try
            {
                hold_release_callbacks[i](false);
            }
            catch (const std::exception &e)
            {
                Logger::get_instance().error(
                    "InputPoller: Exception in hold release callback \"{}\": {}",
                    hold_release_names[i], e.what());
            }
            catch (...)
            {
                Logger::get_instance().error(
                    "InputPoller: Unknown exception in hold release callback \"{}\"",
                    hold_release_names[i]);
            }
        }

        return removed;
    }

    void InputPoller::clear_bindings(bool invoke_callbacks) noexcept
    {
        std::vector<std::pair<std::function<void(bool)>, std::string>> hold_releases;

        {
            std::unique_lock lock(bindings_rw_mutex_);
            // Skip the release-callback capture entirely on the loader-lock
            // path (Bootstrap::on_logic_dll_unload_all). Running user
            // callbacks under loader lock is unsafe because the Logic DLL
            // hosting those callbacks may be in the middle of being
            // unmapped, and any callback that touches Win32 LoadLibrary
            // family or a peer DllMain's mutex would deadlock.
            if (invoke_callbacks)
            {
                for (size_t i = 0; i < bindings_.size(); ++i)
                {
                    if (active_states_[i].load(std::memory_order_relaxed) != 0 &&
                        bindings_[i].mode == InputMode::Hold &&
                        bindings_[i].on_state_change)
                    {
                        hold_releases.emplace_back(bindings_[i].on_state_change, bindings_[i].name);
                    }
                }
            }
            bindings_.clear();
            name_index_.clear();
            known_modifiers_.clear();
            has_gamepad_bindings_.store(false, std::memory_order_relaxed);
            active_states_ = std::make_unique<std::atomic<uint8_t>[]>(0);
        }

        for (auto &[cb, n] : hold_releases)
        {
            try
            {
                cb(false);
            }
            catch (const std::exception &e)
            {
                Logger::get_instance().error(
                    "InputPoller: Exception in hold release callback \"{}\": {}", n, e.what());
            }
            catch (...)
            {
                Logger::get_instance().error(
                    "InputPoller: Unknown exception in hold release callback \"{}\"", n);
            }
        }
    }

    void InputPoller::release_active_holds() noexcept
    {
        for (size_t i = 0; i < bindings_.size(); ++i)
        {
            if (active_states_[i].load(std::memory_order_relaxed) != 0)
            {
                active_states_[i].store(0, std::memory_order_relaxed);

                const auto &binding = bindings_[i];
                if (binding.mode == InputMode::Hold && binding.on_state_change)
                {
                    try
                    {
                        binding.on_state_change(false);
                    }
                    catch (const std::exception &e)
                    {
                        Logger::get_instance().error(
                            "InputPoller: Exception in hold release callback \"{}\": {}",
                            binding.name, e.what());
                    }
                    catch (...)
                    {
                        Logger::get_instance().error(
                            "InputPoller: Unknown exception in hold release callback \"{}\"",
                            binding.name);
                    }
                }
            }
        }
    }

    bool InputPoller::is_process_foreground() const
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
                                      const std::vector<InputCode> &modifiers,
                                      std::function<void()> callback)
    {
        std::shared_ptr<InputPoller> live_poller;
        InputBinding binding;
        binding.name = std::string{name};
        binding.keys = keys;
        binding.modifiers = modifiers;
        binding.mode = InputMode::Press;
        binding.on_press = std::move(callback);

        {
            std::lock_guard lock(mutex_);
            if (poller_)
            {
                live_poller = poller_;
            }
            else
            {
                pending_bindings_.push_back(std::move(binding));
                return;
            }
        }

        // Forward outside the InputManager mutex so the poller's exclusive
        // bindings_rw_mutex_ acquisition cannot AB/BA against any caller
        // already holding mutex_.
        live_poller->add_binding(std::move(binding));
    }

    void InputManager::register_hold(std::string_view name, const std::vector<InputCode> &keys,
                                     std::function<void(bool)> callback)
    {
        register_hold(name, keys, {}, std::move(callback));
    }

    void InputManager::register_hold(std::string_view name, const std::vector<InputCode> &keys,
                                     const std::vector<InputCode> &modifiers,
                                     std::function<void(bool)> callback)
    {
        std::shared_ptr<InputPoller> live_poller;
        InputBinding binding;
        binding.name = std::string{name};
        binding.keys = keys;
        binding.modifiers = modifiers;
        binding.mode = InputMode::Hold;
        binding.on_state_change = std::move(callback);

        {
            std::lock_guard lock(mutex_);
            if (poller_)
            {
                live_poller = poller_;
            }
            else
            {
                pending_bindings_.push_back(std::move(binding));
                return;
            }
        }

        live_poller->add_binding(std::move(binding));
    }

    void InputManager::register_press(std::string_view name, const Config::KeyComboList &combos,
                                      std::function<void()> callback)
    {
        // An empty combo list still has to register the binding name so a
        // later update_binding_combos() can attach a real combo. Without
        // this the for-each loop produces zero bindings, the name never
        // lands in pending_bindings_, and the INI-driven update silently
        // fails with "name not found".
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
        std::lock_guard lock(mutex_);
        require_focus_ = require_focus;
        if (poller_)
        {
            poller_->set_require_focus(require_focus);
        }
    }

    void InputManager::set_gamepad_index(int index)
    {
        std::lock_guard lock(mutex_);
        gamepad_index_ = std::clamp(index, 0, 3);
    }

    void InputManager::set_trigger_threshold(int threshold)
    {
        std::lock_guard lock(mutex_);
        trigger_threshold_ = std::clamp(threshold, 0, 255);
    }

    void InputManager::set_stick_threshold(int threshold)
    {
        std::lock_guard lock(mutex_);
        stick_threshold_ = std::clamp(threshold, 0, 32767);
    }

    void InputManager::start(std::chrono::milliseconds poll_interval)
    {
        std::lock_guard lock(mutex_);

        if (poller_)
        {
            Logger::get_instance().debug("InputManager: start() called while already running; no-op.");
            return;
        }

        if (pending_bindings_.empty())
        {
            return;
        }

        Logger &logger = Logger::get_instance();
        logger.info("InputManager: Starting with {} binding(s), poll interval {}ms",
                    pending_bindings_.size(), poll_interval.count());

        for (const auto &binding : pending_bindings_)
        {
            logger.debug("InputManager: Registered {} binding \"{}\" with {} key(s)",
                         input_mode_to_string(binding.mode), binding.name, binding.keys.size());
        }

        poller_ = std::make_shared<InputPoller>(std::move(pending_bindings_), poll_interval,
                                                require_focus_, gamepad_index_, trigger_threshold_,
                                                stick_threshold_);
        pending_bindings_.clear();
        poller_->start();
        active_poller_.store(poller_, std::memory_order_release);
        running_.store(true, std::memory_order_release);
    }

    bool InputManager::is_running() const noexcept
    {
        return running_.load(std::memory_order_acquire);
    }

    size_t InputManager::binding_count() const noexcept
    {
        std::lock_guard lock(mutex_);
        if (poller_)
        {
            return poller_->binding_count();
        }
        return pending_bindings_.size();
    }

    bool InputManager::is_binding_active(std::string_view name) const noexcept
    {
        auto p = active_poller_.load(std::memory_order_acquire);
        if (p)
        {
            return p->is_binding_active(name);
        }
        return false;
    }

    void InputManager::update_binding_combos(std::string_view name,
                                             const Config::KeyComboList &combos) noexcept
    {
        std::shared_ptr<InputPoller> local_poller;
        bool updated_pending = false;

        {
            std::lock_guard lock(mutex_);
            if (poller_)
            {
                local_poller = poller_;
            }
            else
            {
                std::vector<size_t> indices;
                indices.reserve(pending_bindings_.size());
                for (size_t i = 0; i < pending_bindings_.size(); ++i)
                {
                    if (pending_bindings_[i].name == name)
                    {
                        indices.push_back(i);
                    }
                }
                if (indices.empty())
                {
                    Logger::get_instance().debug(
                        "InputManager: update_binding_combos(\"{}\") ignored: name not found", name);
                    return;
                }

                if (indices.size() == combos.size())
                {
                    for (size_t i = 0; i < indices.size(); ++i)
                    {
                        pending_bindings_[indices[i]].keys = combos[i].keys;
                        pending_bindings_[indices[i]].modifiers = combos[i].modifiers;
                    }
                    updated_pending = true;
                }
                else
                {
                    InputBinding prototype = pending_bindings_[indices.front()];
                    std::sort(indices.begin(), indices.end());
                    std::vector<InputBinding> rebuilt;
                    rebuilt.reserve(pending_bindings_.size() - indices.size() +
                                    (combos.empty() ? 1 : combos.size()));
                    size_t cursor = 0;
                    for (size_t skip : indices)
                    {
                        for (size_t i = cursor; i < skip; ++i)
                        {
                            rebuilt.push_back(std::move(pending_bindings_[i]));
                        }
                        cursor = skip + 1;
                    }
                    for (size_t i = cursor; i < pending_bindings_.size(); ++i)
                    {
                        rebuilt.push_back(std::move(pending_bindings_[i]));
                    }
                    if (combos.empty())
                    {
                        // Preserve a sentinel entry so the binding name
                        // remains addressable for a later non-empty
                        // update_binding_combos() call.
                        InputBinding b = prototype;
                        b.keys.clear();
                        b.modifiers.clear();
                        rebuilt.push_back(std::move(b));
                    }
                    else
                    {
                        for (const auto &combo : combos)
                        {
                            InputBinding b = prototype;
                            b.keys = combo.keys;
                            b.modifiers = combo.modifiers;
                            rebuilt.push_back(std::move(b));
                        }
                    }
                    pending_bindings_ = std::move(rebuilt);
                    updated_pending = true;
                }
            }
        }

        if (local_poller)
        {
            (void)local_poller->update_combos(name, combos);
        }
        else if (updated_pending)
        {
            Logger::get_instance().debug(
                "InputManager: update_binding_combos(\"{}\") applied to pending bindings", name);
        }
    }

    size_t InputManager::remove_binding_by_name(std::string_view name, bool invoke_callbacks) noexcept
    {
        std::shared_ptr<InputPoller> live_poller;
        size_t removed_pending = 0;

        {
            std::lock_guard lock(mutex_);
            if (poller_)
            {
                live_poller = poller_;
            }
            else
            {
                auto new_end = std::remove_if(
                    pending_bindings_.begin(), pending_bindings_.end(),
                    [name](const InputBinding &b) { return b.name == name; });
                removed_pending = static_cast<size_t>(
                    std::distance(new_end, pending_bindings_.end()));
                pending_bindings_.erase(new_end, pending_bindings_.end());
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
            std::lock_guard lock(mutex_);
            pending_bindings_.clear();
            if (poller_)
            {
                live_poller = poller_;
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
            std::lock_guard lock(mutex_);
            // Clear atomic shared_ptr before releasing the poller to ensure
            // concurrent is_binding_active() callers hold a valid shared_ptr.
            active_poller_.store(nullptr, std::memory_order_release);
            running_.store(false, std::memory_order_release);
            local_poller = std::move(poller_);
            pending_bindings_.clear();
        }

        if (local_poller)
        {
            local_poller->shutdown();
        }
    }
} // namespace DetourModKit
