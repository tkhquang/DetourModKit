/**
 * @file input.cpp
 * @brief Implementation of the input polling and hotkey management system.
 *
 * Provides InputPoller (RAII polling engine) and InputManager (singleton wrapper)
 * for monitoring virtual key states on a background thread. Supports press
 * (edge-triggered) and hold (level-triggered) input modes with modifier key
 * combinations and focus-aware polling.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <algorithm>
#include <exception>

namespace DetourModKit
{
    // --- InputPoller ---

    InputPoller::InputPoller(std::vector<InputBinding> bindings,
                             std::chrono::milliseconds poll_interval,
                             bool require_focus)
        : bindings_(std::move(bindings)),
          poll_interval_(std::clamp(poll_interval, MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)),
          require_focus_(require_focus),
          active_states_(std::make_unique<std::atomic<uint8_t>[]>(bindings_.size()))
    {
    }

    InputPoller::~InputPoller()
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

        poll_thread_ = std::jthread([this](std::stop_token token)
                                    { poll_loop(std::move(token)); });
    }

    bool InputPoller::is_running() const noexcept
    {
        return poll_thread_.joinable() && !poll_thread_.get_stop_token().stop_requested();
    }

    size_t InputPoller::binding_count() const noexcept
    {
        return bindings_.size();
    }

    std::chrono::milliseconds InputPoller::poll_interval() const noexcept
    {
        return poll_interval_;
    }

    bool InputPoller::is_binding_active(size_t index) const noexcept
    {
        if (index >= bindings_.size())
        {
            return false;
        }
        return active_states_[index].load(std::memory_order_relaxed) != 0;
    }

    bool InputPoller::is_binding_active(const std::string &name) const noexcept
    {
        for (size_t i = 0; i < bindings_.size(); ++i)
        {
            if (bindings_[i].name == name)
            {
                return active_states_[i].load(std::memory_order_relaxed) != 0;
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
        poll_thread_.join();

        release_active_holds();
    }

    void InputPoller::poll_loop(std::stop_token stop_token)
    {
        const size_t count = bindings_.size();

        while (!stop_token.stop_requested())
        {
            const bool process_focused =
                !require_focus_.load(std::memory_order_relaxed) || is_process_foreground();

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
                    for (const int mod : binding.modifiers)
                    {
                        if (mod != 0 && (GetAsyncKeyState(mod) & 0x8000) == 0)
                        {
                            modifiers_held = false;
                            break;
                        }
                    }

                    if (modifiers_held)
                    {
                        for (const int vk : binding.keys)
                        {
                            if (vk != 0 && (GetAsyncKeyState(vk) & 0x8000) != 0)
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
                    if (any_pressed && !was_active)
                    {
                        if (binding.on_press)
                        {
                            try
                            {
                                binding.on_press();
                            }
                            catch (const std::exception &e)
                            {
                                Logger::get_instance().error(
                                    "InputPoller: Exception in press callback \"{}\": {}",
                                    binding.name, e.what());
                            }
                            catch (...)
                            {
                                Logger::get_instance().error(
                                    "InputPoller: Unknown exception in press callback \"{}\"",
                                    binding.name);
                            }
                        }
                    }
                    active_states_[i].store(any_pressed ? 1 : 0, std::memory_order_relaxed);
                    break;
                }
                case InputMode::Hold:
                {
                    if (any_pressed != was_active)
                    {
                        if (binding.on_state_change)
                        {
                            try
                            {
                                binding.on_state_change(any_pressed);
                            }
                            catch (const std::exception &e)
                            {
                                Logger::get_instance().error(
                                    "InputPoller: Exception in hold callback \"{}\": {}",
                                    binding.name, e.what());
                            }
                            catch (...)
                            {
                                Logger::get_instance().error(
                                    "InputPoller: Unknown exception in hold callback \"{}\"",
                                    binding.name);
                            }
                        }
                    }
                    active_states_[i].store(any_pressed ? 1 : 0, std::memory_order_relaxed);
                    break;
                }
                }
            }

            std::unique_lock lock(cv_mutex_);
            cv_.wait_for(lock, stop_token, poll_interval_, [&stop_token]()
                         { return stop_token.stop_requested(); });
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

    void InputManager::register_press(const std::string &name, const std::vector<int> &keys,
                                      std::function<void()> callback)
    {
        register_press(name, keys, {}, std::move(callback));
    }

    void InputManager::register_press(const std::string &name, const std::vector<int> &keys,
                                      const std::vector<int> &modifiers,
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
        binding.name = name;
        binding.keys = keys;
        binding.modifiers = modifiers;
        binding.mode = InputMode::Press;
        binding.on_press = std::move(callback);
        pending_bindings_.push_back(std::move(binding));
    }

    void InputManager::register_hold(const std::string &name, const std::vector<int> &keys,
                                     std::function<void(bool)> callback)
    {
        register_hold(name, keys, {}, std::move(callback));
    }

    void InputManager::register_hold(const std::string &name, const std::vector<int> &keys,
                                     const std::vector<int> &modifiers,
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
        binding.name = name;
        binding.keys = keys;
        binding.modifiers = modifiers;
        binding.mode = InputMode::Hold;
        binding.on_state_change = std::move(callback);
        pending_bindings_.push_back(std::move(binding));
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
            logger.info("InputManager: Registered {} binding \"{}\" with {} key(s)",
                        input_mode_to_string(binding.mode), binding.name, binding.keys.size());
        }

        poller_ = std::make_unique<InputPoller>(std::move(pending_bindings_), poll_interval,
                                                require_focus_);
        pending_bindings_.clear();
        poller_->start();
    }

    bool InputManager::is_running() const noexcept
    {
        std::lock_guard lock(mutex_);
        return poller_ && poller_->is_running();
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

    bool InputManager::is_binding_active(const std::string &name) const noexcept
    {
        std::lock_guard lock(mutex_);
        if (poller_)
        {
            return poller_->is_binding_active(name);
        }
        return false;
    }

    void InputManager::shutdown() noexcept
    {
        std::lock_guard lock(mutex_);

        if (poller_)
        {
            poller_->shutdown();
            poller_.reset();
        }

        pending_bindings_.clear();
    }
} // namespace DetourModKit
