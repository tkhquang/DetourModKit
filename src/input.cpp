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
#include <utility>

namespace DetourModKit
{
    // --- InputPoller ---

    InputPoller::InputPoller(std::vector<InputBinding> bindings,
                             std::chrono::milliseconds poll_interval)
        : bindings_(std::move(bindings)),
          poll_interval_(std::clamp(poll_interval, MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)),
          prev_states_(bindings_.size(), false)
    {
        running_.store(true, std::memory_order_release);
        poll_thread_ = std::jthread(&InputPoller::poll_loop, this);
    }

    InputPoller::~InputPoller()
    {
        shutdown();
    }

    InputPoller::InputPoller(InputPoller &&other) noexcept
        : bindings_(std::move(other.bindings_)),
          poll_interval_(other.poll_interval_),
          running_(other.running_.load(std::memory_order_acquire)),
          poll_thread_(std::move(other.poll_thread_)),
          prev_states_(std::move(other.prev_states_))
    {
        other.running_.store(false, std::memory_order_release);
    }

    InputPoller &InputPoller::operator=(InputPoller &&other) noexcept
    {
        if (this != &other)
        {
            shutdown();
            bindings_ = std::move(other.bindings_);
            poll_interval_ = other.poll_interval_;
            prev_states_ = std::move(other.prev_states_);
            running_.store(other.running_.load(std::memory_order_acquire), std::memory_order_release);
            poll_thread_ = std::move(other.poll_thread_);
            other.running_.store(false, std::memory_order_release);
        }
        return *this;
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

    void InputPoller::shutdown() noexcept
    {
        const bool was_running = running_.exchange(false, std::memory_order_acq_rel);
        if (!was_running)
        {
            return;
        }

        if (poll_thread_.joinable())
        {
            poll_thread_.request_stop();
            poll_thread_.join();
        }
    }

    void InputPoller::poll_loop()
    {
        const auto stop_token = poll_thread_.get_stop_token();
        const size_t count = bindings_.size();

        while (!stop_token.stop_requested() && running_.load(std::memory_order_acquire))
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

                switch (binding.mode)
                {
                case InputMode::Press:
                {
                    if (any_pressed && !prev_states_[i])
                    {
                        if (binding.on_press)
                        {
                            binding.on_press();
                        }
                    }
                    prev_states_[i] = any_pressed;
                    break;
                }
                case InputMode::Hold:
                {
                    if (any_pressed != prev_states_[i])
                    {
                        if (binding.on_state_change)
                        {
                            binding.on_state_change(any_pressed);
                        }
                    }
                    prev_states_[i] = any_pressed;
                    break;
                }
                }
            }

            Sleep(static_cast<DWORD>(poll_interval_.count()));
        }
    }

    // --- InputManager ---

    void InputManager::register_press(const std::string &name, const std::vector<int> &keys,
                                      std::function<void()> callback)
    {
        if (poller_)
        {
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
        if (poller_)
        {
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
        if (poller_)
        {
            return;
        }

        if (pending_bindings_.empty())
        {
            return;
        }

        shutdown_called_.store(false, std::memory_order_release);

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
    }

    bool InputManager::is_running() const noexcept
    {
        return poller_ && poller_->is_running();
    }

    size_t InputManager::binding_count() const noexcept
    {
        if (poller_)
        {
            return poller_->binding_count();
        }
        return pending_bindings_.size();
    }

    void InputManager::shutdown() noexcept
    {
        if (poller_)
        {
            poller_->shutdown();
            poller_.reset();
        }

        pending_bindings_.clear();
        shutdown_called_.store(true, std::memory_order_release);
    }
} // namespace DetourModKit
