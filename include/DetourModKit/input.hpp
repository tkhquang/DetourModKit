#ifndef INPUT_HPP
#define INPUT_HPP

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
     * @brief Describes a single key-to-action binding.
     * @details Holds the action name, virtual key codes, input mode, and callbacks.
     *          For Press mode, the press callback fires on key-down edge.
     *          For Hold mode, the state callback fires with true on press and false on release.
     */
    struct InputBinding
    {
        std::string name;
        std::vector<int> keys;
        InputMode mode;
        std::function<void()> on_press;
        std::function<void(bool)> on_state_change;
    };

    /**
     * @class InputPoller
     * @brief RAII input polling engine that monitors key states on a background thread.
     * @details Manages a dedicated polling thread that checks virtual key states via
     *          GetAsyncKeyState. Supports both press (edge-triggered) and hold
     *          (level-triggered) input modes. The polling thread is started on
     *          construction and stopped on destruction.
     *
     * @note Non-copyable, non-movable. Callbacks are invoked on the polling thread.
     * @note This class is the building block for the InputManager singleton.
     */
    class InputPoller
    {
    public:
        /**
         * @brief Constructs an InputPoller with the given bindings and poll interval.
         * @param bindings Vector of input bindings to monitor.
         * @param poll_interval Time between polling cycles.
         * @note The polling thread starts immediately after construction.
         */
        explicit InputPoller(std::vector<InputBinding> bindings,
                             std::chrono::milliseconds poll_interval = DEFAULT_POLL_INTERVAL);

        ~InputPoller();

        InputPoller(const InputPoller &) = delete;
        InputPoller &operator=(const InputPoller &) = delete;
        InputPoller(InputPoller &&) = delete;
        InputPoller &operator=(InputPoller &&) = delete;

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
         * @brief Stops the polling thread.
         * @details Signals the thread to stop and waits for it to join.
         *          Safe to call multiple times.
         */
        void shutdown() noexcept;

    private:
        void poll_loop();

        std::vector<InputBinding> bindings_;
        std::chrono::milliseconds poll_interval_;
        std::atomic<bool> running_{false};
        std::jthread poll_thread_;
        std::mutex cv_mutex_;
        std::condition_variable cv_;

        // Per-key state tracking for edge detection, indexed parallel to bindings_.
        // For Press mode: tracks whether any key in the binding was down last cycle.
        // For Hold mode: tracks whether the hold condition was active last cycle.
        std::vector<uint8_t> prev_states_;
    };

    /**
     * @class InputManager
     * @brief Singleton that provides a convenient interface for registering and
     *        monitoring hotkey bindings.
     * @details Wraps an InputPoller internally. Bindings are registered before
     *          calling start(), which constructs the poller. Integrates with
     *          DMK_Shutdown() for automatic cleanup.
     *
     * @note Thread-safe. For advanced use cases requiring multiple independent
     *       pollers or custom lifetime management, use InputPoller directly.
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
         * @param keys Vector of virtual key codes (any triggers the action).
         * @param callback Function to invoke on key press.
         */
        void register_press(const std::string &name, const std::vector<int> &keys,
                            std::function<void()> callback);

        /**
         * @brief Registers a hold-mode binding.
         * @details The callback fires with true when any key in the list is pressed,
         *          and false when all keys are released. Must be called before start().
         *          Ignored if the poller is already running.
         * @param name Unique, descriptive name for the binding.
         * @param keys Vector of virtual key codes (any activates the hold).
         * @param callback Function invoked with the hold state (true = held, false = released).
         */
        void register_hold(const std::string &name, const std::vector<int> &keys,
                           std::function<void(bool)> callback);

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
    };
} // namespace DetourModKit

#endif // INPUT_HPP
