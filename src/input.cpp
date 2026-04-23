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
            Logger::get_instance().warning("InputPoller: start() called while already running");
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
        if (index >= bindings_.size())
        {
            return false;
        }
        // relaxed is sufficient: the poll thread writes and game-loop threads
        // read active_states_[] independently.  Atomicity of the load is all
        // that matters -- no cross-variable ordering is required.  A stale
        // read at worst delays the state change by one poll cycle (~5 ms).
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
        std::unique_lock lock(bindings_rw_mutex_);
        const auto it = name_index_.find(name);
        if (it == name_index_.end())
        {
            Logger::get_instance().debug("InputPoller: update_combos(\"{}\") ignored: name not found", name);
            return false;
        }
        const auto &indices = it->second;
        if (indices.size() != combos.size())
        {
            Logger::get_instance().warning(
                "InputPoller: update_combos(\"{}\") ignored: cardinality mismatch (registered={}, requested={})",
                name, indices.size(), combos.size());
            return false;
        }

        for (size_t i = 0; i < indices.size(); ++i)
        {
            const size_t idx = indices[i];
            bindings_[idx].keys = combos[i].keys;
            bindings_[idx].modifiers = combos[i].modifiers;
        }
        recompute_modifier_caches_locked();
        return true;
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
        std::lock_guard lock(mutex_);

        if (poller_)
        {
            Logger::get_instance().warning(
                "InputManager: Cannot register binding \"{}\" while poller is running", name);
            return;
        }

        InputBinding binding;
        binding.name = std::string{name};
        binding.keys = keys;
        binding.modifiers = modifiers;
        binding.mode = InputMode::Press;
        binding.on_press = std::move(callback);
        pending_bindings_.push_back(std::move(binding));
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
        std::lock_guard lock(mutex_);

        if (poller_)
        {
            Logger::get_instance().warning(
                "InputManager: Cannot register binding \"{}\" while poller is running", name);
            return;
        }

        InputBinding binding;
        binding.name = std::string{name};
        binding.keys = keys;
        binding.modifiers = modifiers;
        binding.mode = InputMode::Hold;
        binding.on_state_change = std::move(callback);
        pending_bindings_.push_back(std::move(binding));
    }

    void InputManager::register_press(std::string_view name, const Config::KeyComboList &combos,
                                      std::function<void()> callback)
    {
        for (const auto &combo : combos)
        {
            register_press(name, combo.keys, combo.modifiers, callback);
        }
    }

    void InputManager::register_hold(std::string_view name, const Config::KeyComboList &combos,
                                     std::function<void(bool)> callback)
    {
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
            Logger::get_instance().warning("InputManager: start() called while already running");
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
                // Walk pending_bindings_ by name. Cardinality must match.
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
                if (indices.size() != combos.size())
                {
                    Logger::get_instance().warning(
                        "InputManager: update_binding_combos(\"{}\") ignored: cardinality mismatch (registered={}, requested={})",
                        name, indices.size(), combos.size());
                    return;
                }
                for (size_t i = 0; i < indices.size(); ++i)
                {
                    pending_bindings_[indices[i]].keys = combos[i].keys;
                    pending_bindings_[indices[i]].modifiers = combos[i].modifiers;
                }
                updated_pending = true;
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
