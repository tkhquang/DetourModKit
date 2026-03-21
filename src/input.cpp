/**
 * @file input.cpp
 * @brief Implementation of the input polling and hotkey management system.
 *
 * Provides InputPoller (RAII polling engine) and InputManager (singleton wrapper)
 * for monitoring virtual key states on a background thread. Supports press
 * (edge-triggered) and hold (level-triggered) input modes.
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
                             std::chrono::milliseconds poll_interval)
        : bindings_(std::move(bindings)),
          poll_interval_(std::clamp(poll_interval, MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)),
          prev_states_(bindings_.size(), 0)
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

    void InputPoller::shutdown() noexcept
    {
        if (!poll_thread_.joinable())
        {
            return;
        }

        poll_thread_.request_stop();
        cv_.notify_all();
        poll_thread_.join();
    }

    void InputPoller::poll_loop(std::stop_token stop_token)
    {
        const size_t count = bindings_.size();

        while (!stop_token.stop_requested())
        {
            for (size_t i = 0; i < count; ++i)
            {
                const auto &binding = bindings_[i];
                if (binding.keys.empty())
                {
                    continue;
                }

                bool any_pressed = false;
                for (const int vk : binding.keys)
                {
                    if (vk != 0 && (GetAsyncKeyState(vk) & 0x8000) != 0)
                    {
                        any_pressed = true;
                        break;
                    }
                }

                const bool was_active = (prev_states_[i] != 0);

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
                    prev_states_[i] = any_pressed ? 1 : 0;
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
                    prev_states_[i] = any_pressed ? 1 : 0;
                    break;
                }
                }
            }

            std::unique_lock lock(cv_mutex_);
            cv_.wait_for(lock, stop_token, poll_interval_, [&stop_token]()
                         { return stop_token.stop_requested(); });
        }
    }

    // --- InputManager ---

    void InputManager::register_press(const std::string &name, const std::vector<int> &keys,
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
        binding.mode = InputMode::Press;
        binding.on_press = std::move(callback);
        pending_bindings_.push_back(std::move(binding));
    }

    void InputManager::register_hold(const std::string &name, const std::vector<int> &keys,
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
        binding.mode = InputMode::Hold;
        binding.on_state_change = std::move(callback);
        pending_bindings_.push_back(std::move(binding));
    }

    void InputManager::start(std::chrono::milliseconds poll_interval)
    {
        std::lock_guard lock(mutex_);

        if (poller_)
        {
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

        poller_ = std::make_unique<InputPoller>(std::move(pending_bindings_), poll_interval);
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
