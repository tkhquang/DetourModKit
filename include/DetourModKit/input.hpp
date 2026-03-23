#ifndef INPUT_HPP
#define INPUT_HPP

#include "DetourModKit/input_codes.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace DetourModKit
{
    /**
     * @enum InputMode
     * @brief Defines how a registered key binding is triggered.
     */
    enum class InputMode
    {
        Press,
        Hold
    };

    /**
     * @brief Converts an InputMode enum to its string representation.
     * @param mode The InputMode enum value.
     * @return std::string_view String representation of the mode.
     */
    constexpr std::string_view input_mode_to_string(InputMode mode)
    {
        switch (mode)
        {
        case InputMode::Press:
            return "Press";
        case InputMode::Hold:
            return "Hold";
        }
        return "Unknown";
    }

    // Input system configuration defaults
    inline constexpr std::chrono::milliseconds DEFAULT_POLL_INTERVAL{16};
    inline constexpr std::chrono::milliseconds MIN_POLL_INTERVAL{1};
    inline constexpr std::chrono::milliseconds MAX_POLL_INTERVAL{1000};

    /**
     * @struct InputBinding
     * @brief Describes a single input-to-action binding.
     * @details Holds the action name, input codes, modifier codes, input mode,
     *          and callbacks. For Press mode, the press callback fires on key-down edge.
     *          For Hold mode, the state callback fires with true on press and false on
     *          release (including during shutdown for active holds).
     *
     *          The keys vector uses OR logic: any single input triggers the binding.
     *          The modifiers vector uses AND logic: all modifiers must be held
     *          simultaneously for the binding to activate.
     *
     *          Each InputCode identifies both the device source (keyboard, mouse,
     *          gamepad) and the button/key code. All codes within a binding should
     *          be from the same device group (keyboard/mouse or gamepad).
     *
     * @warning Callbacks are invoked on the polling thread. They must not capture references
     *          or pointers to objects whose lifetime may end before shutdown() completes.
     *          Callbacks should execute quickly to avoid degrading the effective poll rate.
     */
    struct InputBinding
    {
        std::string name;
        std::vector<InputCode> keys;
        std::vector<InputCode> modifiers;
        InputMode mode = InputMode::Press;
        std::function<void()> on_press;
        std::function<void(bool)> on_state_change;
    };

    /**
     * @class InputPoller
     * @brief RAII input polling engine that monitors key states on a background thread.
     * @details Manages a dedicated polling thread that checks virtual key states via
     *          GetAsyncKeyState. Supports both press (edge-triggered) and hold
     *          (level-triggered) input modes with optional modifier key combinations.
     *          When require_focus is enabled (default), key events are only processed
     *          when the current process owns the foreground window.
     *
     *          On shutdown, active hold bindings receive an on_state_change(false)
     *          callback to ensure consumers are notified of the release.
     *
     * @note Non-copyable, non-movable. Callbacks are invoked on the polling thread.
     * @note This class is the building block for the InputManager singleton.
     *
     * @warning When used inside a DLL, shutdown() must be called before DLL_PROCESS_DETACH.
     *          Calling join() on a thread during DllMain can deadlock due to the loader lock.
     *          Use DMK_Shutdown() to ensure proper teardown ordering.
     */
    class InputPoller
    {
    public:
        /**
         * @brief Constructs an InputPoller with the given bindings and poll interval.
         * @param bindings Vector of input bindings to monitor.
         * @param poll_interval Time between polling cycles.
         * @param require_focus When true, key events are ignored unless the current
         *                      process owns the foreground window.
         * @param gamepad_index XInput controller index (0-3) to poll for gamepad bindings.
         * @param trigger_threshold Analog trigger deadzone threshold (0-255). Trigger values
         *                          above this threshold are considered "pressed".
         * @param stick_threshold Thumbstick deadzone threshold (0-32767). Axis values
         *                        exceeding this threshold in any direction are "pressed".
         * @note The polling thread does not start until start() is called.
         */
        explicit InputPoller(std::vector<InputBinding> bindings,
                             std::chrono::milliseconds poll_interval = DEFAULT_POLL_INTERVAL,
                             bool require_focus = true,
                             int gamepad_index = 0,
                             int trigger_threshold = GamepadCode::TriggerThreshold,
                             int stick_threshold = GamepadCode::StickThreshold);

        ~InputPoller() noexcept;

        InputPoller(const InputPoller &) = delete;
        InputPoller &operator=(const InputPoller &) = delete;
        InputPoller(InputPoller &&) = delete;
        InputPoller &operator=(InputPoller &&) = delete;

        /**
         * @brief Starts the polling thread.
         * @details Safe to call only once. Subsequent calls are ignored with a warning.
         * @note Not thread-safe. Must be called from a single thread. Use
         *       InputManager::start() for a thread-safe wrapper.
         */
        void start();

        /**
         * @brief Checks if the polling thread is currently running.
         * @return true if the poller is active and monitoring keys.
         */
        [[nodiscard]] bool is_running() const noexcept;

        /**
         * @brief Returns the number of registered bindings.
         * @return size_t Number of bindings.
         */
        [[nodiscard]] size_t binding_count() const noexcept;

        /**
         * @brief Returns the configured poll interval.
         * @return std::chrono::milliseconds The poll interval.
         */
        [[nodiscard]] std::chrono::milliseconds poll_interval() const noexcept;

        /**
         * @brief Returns the configured gamepad controller index.
         * @return int The XInput controller index (0-3).
         */
        [[nodiscard]] int gamepad_index() const noexcept;

        /**
         * @brief Queries whether a binding is currently active by index.
         * @param index Zero-based index into the bindings vector.
         * @return true if the binding's key(s) are currently pressed.
         *         Returns false for out-of-range indices.
         * @note Thread-safe. Can be called from any thread.
         */
        [[nodiscard]] bool is_binding_active(size_t index) const noexcept;

        /**
         * @brief Queries whether a binding is currently active by name.
         * @param name The binding name to look up.
         * @return true if the named binding's key(s) are currently pressed.
         *         Returns false if no binding with the given name exists.
         * @note Thread-safe. Can be called from any thread.
         */
        [[nodiscard]] bool is_binding_active(const std::string &name) const noexcept;

        /**
         * @brief Sets whether the poller requires the current process to own the
         *        foreground window before processing key events.
         * @param require_focus true to enable focus checking (default), false to disable.
         * @note Thread-safe. Can be called while the poller is running.
         */
        void set_require_focus(bool require_focus) noexcept;

        /**
         * @brief Stops the polling thread.
         * @details Signals the thread to stop and waits for it to join. After the
         *          thread has joined, fires on_state_change(false) for any hold
         *          bindings that were active at the time of shutdown. Safe to call
         *          multiple times.
         */
        void shutdown() noexcept;

    private:
        void poll_loop(std::stop_token stop_token);
        void release_active_holds() noexcept;
        [[nodiscard]] bool is_process_foreground() const;

        std::vector<InputBinding> bindings_;
        std::unordered_map<std::string, std::vector<size_t>> name_index_;
        std::chrono::milliseconds poll_interval_;
        std::atomic<bool> require_focus_;
        std::atomic<bool> running_{false};
        std::jthread poll_thread_;
        std::mutex cv_mutex_;
        std::condition_variable_any cv_;

        // Per-binding active state, indexed parallel to bindings_.
        // Atomic for cross-thread reads via is_binding_active().
        std::unique_ptr<std::atomic<uint8_t>[]> active_states_;

        int gamepad_index_;
        int trigger_threshold_;
        int stick_threshold_;
        bool has_gamepad_bindings_;
    };

    /**
     * @class InputManager
     * @brief Singleton that provides a convenient interface for registering and
     *        monitoring hotkey bindings.
     * @details Wraps an InputPoller internally. Bindings are registered before
     *          calling start(), which constructs and starts the poller. Integrates
     *          with DMK_Shutdown() for automatic cleanup.
     *
     * @note Thread-safe. For advanced use cases requiring multiple independent
     *       pollers or custom lifetime management, use InputPoller directly.
     *
     * @warning When used inside a DLL, shutdown() must be called before DLL_PROCESS_DETACH.
     *          Calling join() on a thread during DllMain can deadlock due to the loader lock.
     */
    class InputManager
    {
    public:
        /**
         * @brief Retrieves the singleton instance of the InputManager.
         * @return InputManager& Reference to the single InputManager instance.
         */
        static InputManager &get_instance()
        {
            static InputManager instance;
            return instance;
        }

        /**
         * @brief Registers a press-mode binding.
         * @details The callback fires once per key-down edge for any key in the list.
         *          Must be called before start(). Ignored if the poller is already running.
         * @param name Unique, descriptive name for the binding.
         * @param keys Vector of input codes (any triggers the action).
         * @param callback Function to invoke on key press.
         */
        void register_press(const std::string &name, const std::vector<InputCode> &keys,
                            std::function<void()> callback);

        /**
         * @brief Registers a press-mode binding with modifier keys.
         * @details The callback fires once per key-down edge for any key in the list,
         *          but only when all modifier inputs are simultaneously held.
         * @param name Unique, descriptive name for the binding.
         * @param keys Vector of input codes (any triggers the action).
         * @param modifiers Vector of modifier input codes (all must be held).
         * @param callback Function to invoke on key press.
         */
        void register_press(const std::string &name, const std::vector<InputCode> &keys,
                            const std::vector<InputCode> &modifiers,
                            std::function<void()> callback);

        /**
         * @brief Registers a hold-mode binding.
         * @details The callback fires with true when any input in the list is pressed,
         *          and false when all are released. Must be called before start().
         *          Ignored if the poller is already running.
         * @param name Unique, descriptive name for the binding.
         * @param keys Vector of input codes (any activates the hold).
         * @param callback Function invoked with the hold state (true = held, false = released).
         */
        void register_hold(const std::string &name, const std::vector<InputCode> &keys,
                           std::function<void(bool)> callback);

        /**
         * @brief Registers a hold-mode binding with modifier keys.
         * @details The callback fires with true when any input in the list is pressed
         *          and all modifier inputs are simultaneously held, and false when the
         *          condition is no longer met.
         * @param name Unique, descriptive name for the binding.
         * @param keys Vector of input codes (any activates the hold).
         * @param modifiers Vector of modifier input codes (all must be held).
         * @param callback Function invoked with the hold state (true = held, false = released).
         */
        void register_hold(const std::string &name, const std::vector<InputCode> &keys,
                           const std::vector<InputCode> &modifiers,
                           std::function<void(bool)> callback);

        /**
         * @brief Sets whether the poller requires the current process to own the
         *        foreground window before processing key events.
         * @param require_focus true to enable focus checking (default), false to disable.
         * @note Can be called before or after start(). Changes take effect immediately.
         */
        void set_require_focus(bool require_focus);

        /**
         * @brief Sets the XInput controller index to poll for gamepad bindings.
         * @param index Controller index (0-3). Clamped to valid range.
         * @note Must be called before start(). Has no effect while the poller is running.
         */
        void set_gamepad_index(int index);

        /**
         * @brief Sets the analog trigger deadzone threshold for gamepad bindings.
         * @param threshold Trigger values above this threshold (0-255) are "pressed".
         * @note Must be called before start(). Has no effect while the poller is running.
         */
        void set_trigger_threshold(int threshold);

        /**
         * @brief Sets the thumbstick deadzone threshold for gamepad bindings.
         * @param threshold Axis values exceeding this threshold (0-32767) are "pressed".
         * @note Must be called before start(). Has no effect while the poller is running.
         */
        void set_stick_threshold(int threshold);

        /**
         * @brief Starts the input polling thread with all registered bindings.
         * @details Constructs an internal InputPoller with the current bindings
         *          and begins monitoring. Subsequent register calls are ignored
         *          until the poller is stopped and bindings are cleared.
         * @param poll_interval Time between polling cycles.
         */
        void start(std::chrono::milliseconds poll_interval = DEFAULT_POLL_INTERVAL);

        /**
         * @brief Checks if the input polling thread is currently running.
         * @return true if the poller is active.
         */
        [[nodiscard]] bool is_running() const noexcept;

        /**
         * @brief Returns the number of registered bindings.
         * @return size_t Number of bindings (pending or active).
         */
        [[nodiscard]] size_t binding_count() const noexcept;

        /**
         * @brief Queries whether a named binding is currently active.
         * @param name The binding name to look up.
         * @return true if the named binding's key(s) are currently pressed.
         *         Returns false if the poller is not running or the name is unknown.
         * @note Thread-safe. Can be called from any thread (e.g., render thread).
         */
        [[nodiscard]] bool is_binding_active(const std::string &name) const noexcept;

        /**
         * @brief Stops the polling thread and clears all registered bindings.
         * @details Safe to call multiple times. After shutdown, new bindings
         *          can be registered and start() called again.
         */
        void shutdown() noexcept;

    private:
        InputManager() = default;
        ~InputManager() = default;

        InputManager(const InputManager &) = delete;
        InputManager &operator=(const InputManager &) = delete;

        mutable std::mutex mutex_;
        std::vector<InputBinding> pending_bindings_;
        std::unique_ptr<InputPoller> poller_;
        std::atomic<InputPoller *> active_poller_{nullptr};
        std::atomic<bool> running_{false};
        bool require_focus_ = true;
        int gamepad_index_ = 0;
        int trigger_threshold_ = GamepadCode::TriggerThreshold;
        int stick_threshold_ = GamepadCode::StickThreshold;
    };
} // namespace DetourModKit

#endif // INPUT_HPP
