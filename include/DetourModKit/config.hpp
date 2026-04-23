#ifndef DETOURMODKIT_CONFIG_HPP
#define DETOURMODKIT_CONFIG_HPP

#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/logger.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    /**
     * @namespace Config
     * @brief Provides functions for registering, loading, and logging configuration settings.
     * @details This system allows mods to register their configuration variables with DetourModKit.
     *          The kit handles loading values from an INI file and provides logging functionality.
     *          Uses std::function callbacks for type-safe value setting.
     *
     * All `register_*` functions share these common parameters:
     *   - @p section     INI section name.
     *   - @p ini_key     INI key name.
     *   - @p log_key_name  Human-readable name shown in log output.
     *   - @p setter      Callback invoked with the loaded (or default) value.
     *
     * @note Setter callbacks are invoked at two points: immediately during registration
     *       (with the default value) and again during load() (with the INI or default value).
     *       Consumers that accumulate state (e.g. building a lookup map) must be idempotent --
     *       clear accumulated state before applying the new value to avoid stale entries.
     *
     * **Thread safety:** All `register_*` and `load()` functions use a deferred callback
     * pattern: state is read/written under the config mutex, but setter callbacks are
     * invoked *after* the mutex is released.  This means setter callbacks may safely call
     * back into the Config API (e.g. `register_*`, `load`, `log_all`) without deadlocking.
     * A reentrancy guard is therefore unnecessary.  `log_all()` and `clear_registered_items()`
     * hold the mutex for the entire call but only invoke Logger methods, which use an
     * independent lock hierarchy.
     */
    namespace Config
    {

        /**
         * @struct KeyCombo
         * @brief Represents a single key combination with trigger keys and modifiers.
         * @details Contains trigger keys (OR logic) and modifier keys (AND logic).
         *          Designed for direct use with InputManager::register_press/register_hold.
         *          Each key is an InputCode identifying both the device source and button.
         *
         *          Within a single combo, modifiers are separated by '+' and the last
         *          '+'-delimited token is the trigger key. Tokens can be human-readable
         *          names or hex VK codes:
         *            - "F3"                   → keys=[F3], modifiers=[]
         *            - "Ctrl+F3"              → keys=[F3], modifiers=[Ctrl]
         *            - "Ctrl+Shift+F3"        → keys=[F3], modifiers=[Ctrl, Shift]
         *            - "Mouse4"               → keys=[Mouse4], modifiers=[]
         *            - "Gamepad_LB+Gamepad_A" → keys=[Gamepad_A], modifiers=[Gamepad_LB]
         *            - "0x11+0x72"            → keys=[0x72], modifiers=[0x11] (hex fallback)
         *
         *          Multiple combos are separated by commas in INI values, parsed into
         *          a KeyComboList. Each combo is independent (OR logic between combos):
         *            - "F3,Gamepad_LT+Gamepad_B" → [{keys=[F3]}, {keys=[Gamepad_B], mods=[Gamepad_LT]}]
         *            - "Ctrl+F3,Ctrl+F4"          → [{keys=[F3], mods=[Ctrl]}, {keys=[F4], mods=[Ctrl]}]
         */
        struct KeyCombo
        {
            std::vector<InputCode> keys;
            std::vector<InputCode> modifiers;
        };

        /// A list of alternative key combinations (OR logic between combos).
        using KeyComboList = std::vector<KeyCombo>;

        /**
         * @class InputBindingGuard
         * @brief RAII cancellation token for bindings registered via
         *        register_press_combo().
         * @details The guard owns a shared atomic flag that gates the user
         *          callback. On destruction (or explicit release()) the flag
         *          is cleared and subsequent key events become no-ops. The
         *          underlying InputManager binding remains registered; it is
         *          only torn down by InputManager::shutdown() or
         *          DMK_Shutdown().
         *
         *          Non-copyable, movable. Moving transfers ownership of the
         *          cancellation flag; the moved-from guard becomes inert.
         */
        class InputBindingGuard
        {
        public:
            InputBindingGuard() = default;
            InputBindingGuard(std::string name, std::shared_ptr<std::atomic<bool>> enabled) noexcept
                : name_(std::move(name)), enabled_(std::move(enabled)) {}

            ~InputBindingGuard() noexcept { release(); }

            InputBindingGuard(const InputBindingGuard &) = delete;
            InputBindingGuard &operator=(const InputBindingGuard &) = delete;

            InputBindingGuard(InputBindingGuard &&other) noexcept
                : name_(std::move(other.name_)), enabled_(std::move(other.enabled_)) {}

            InputBindingGuard &operator=(InputBindingGuard &&other) noexcept
            {
                if (this != &other)
                {
                    release();
                    name_ = std::move(other.name_);
                    enabled_ = std::move(other.enabled_);
                }
                return *this;
            }

            /**
             * @brief Disables the binding's callback. Idempotent.
             */
            void release() noexcept
            {
                if (enabled_)
                {
                    enabled_->store(false, std::memory_order_release);
                    enabled_.reset();
                }
            }

            /**
             * @brief Returns the binding's InputManager name.
             */
            [[nodiscard]] const std::string &name() const noexcept { return name_; }

            /**
             * @brief Returns true while the binding's callback is still live.
             */
            [[nodiscard]] bool is_active() const noexcept
            {
                return enabled_ && enabled_->load(std::memory_order_acquire);
            }

        private:
            std::string name_;
            std::shared_ptr<std::atomic<bool>> enabled_;
        };

        /// Registers an integer configuration item.
        /// @note The setter is called immediately with default_value and again on load().
        void register_int(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                          std::function<void(int)> setter, int default_value);

        /// Registers a floating-point configuration item.
        /// @note The setter is called immediately with default_value and again on load().
        void register_float(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                            std::function<void(float)> setter, float default_value);

        /// Registers a boolean configuration item.
        /// @note The setter is called immediately with default_value and again on load().
        void register_bool(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                           std::function<void(bool)> setter, bool default_value);

        /// Registers a string configuration item.
        /// @note The setter is called immediately with default_value and again on load().
        void register_string(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                             std::function<void(const std::string &)> setter, std::string default_value);

        /**
         * @brief Registers a key combo configuration item.
         * @details Parses an INI value as one or more key combinations. Commas at the
         *          top level separate independent combos (OR logic). Within each combo,
         *          '+' separates modifier keys from the trigger key (last token). Tokens
         *          can be human-readable names (e.g., "Ctrl", "F3", "Gamepad_A") or hex
         *          VK codes (e.g., "0x72"). See KeyCombo for full parsing semantics.
         * @param section INI section name.
         * @param ini_key INI key name.
         * @param log_key_name Human-readable name shown in log output.
         * @param setter Callback invoked with the parsed KeyComboList.
         * @param default_value_str Default value string in the same format.
         * @note The setter is called immediately with the parsed default and again on load().
         */
        void register_key_combo(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                                std::function<void(const KeyComboList &)> setter, std::string_view default_value_str);

        /**
         * @brief Registers a key combo INI item and wires it to InputManager.
         * @details Fuses register_key_combo() with InputManager::register_press().
         *          On registration the InputManager binding is created with the
         *          parsed default combo. On each subsequent load() the setter
         *          invokes InputManager::update_binding_combos() so the bound
         *          keys and modifiers pick up the INI-sourced value without
         *          re-registering the binding. Live updates require the new
         *          combo list to have the same number of alternatives as the
         *          default (one binding entry per combo); if the cardinality
         *          differs, the update is skipped with a Debug-level warning.
         *
         *          The returned guard holds a cancellation flag that
         *          short-circuits the user callback when released, because
         *          InputManager does not support per-binding removal
         *          post-start().
         *
         *          Must be called before InputManager::start() for the
         *          binding to be picked up by the poller. Call sites that
         *          register after start() should also call
         *          InputManager::shutdown() then start() again, or accept
         *          that only the INI value is tracked and the callback
         *          never fires.
         *
         * @param section INI section name.
         * @param ini_key INI key name.
         * @param log_name Human-readable name echoed by the config logger.
         * @param input_binding_name InputManager binding name (must be unique).
         * @param on_press User callback fired on key-down edge.
         * @param default_value Default combo string (same format as register_key_combo).
         * @return InputBindingGuard RAII cancellation token for the callback.
         */
        [[nodiscard]] InputBindingGuard register_press_combo(std::string_view section,
                                                             std::string_view ini_key,
                                                             std::string_view log_name,
                                                             std::string_view input_binding_name,
                                                             std::function<void()> on_press,
                                                             std::string_view default_value);

        /**
         * @brief Loads all registered configuration settings from the specified INI file.
         * @details Parses the INI file and attempts to read values for each registered item.
         *          If a key is missing or invalid, the default value provided during
         *          registration is used.
         * @param ini_filename The base filename of the INI file. Path will be resolved
         *                     relative to the mod's runtime directory.
         */
        void load(std::string_view ini_filename);

        /**
         * @brief Logs the current values of all registered configuration settings.
         * @details Iterates through all items registered with the config system and
         *          outputs their current values to the Logger.
         */
        void log_all();

        /**
         * @brief Clears all currently registered configuration items.
         * @details Useful if the configuration system needs to be reset without
         *          restarting the application.
         */
        void clear_registered_items();

    } // namespace Config
} // namespace DetourModKit

#endif // DETOURMODKIT_CONFIG_HPP
