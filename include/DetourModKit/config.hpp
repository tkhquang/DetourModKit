#ifndef CONFIG_HPP
#define CONFIG_HPP

#include "DetourModKit/input_codes.hpp"

#include <functional>
#include <string>
#include <vector>

namespace DetourModKit
{
    class Logger;

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

        /// Registers an integer configuration item.
        void register_int(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                         std::function<void(int)> setter, int default_value);

        /// Registers a floating-point configuration item.
        void register_float(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                           std::function<void(float)> setter, float default_value);

        /// Registers a boolean configuration item.
        void register_bool(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                          std::function<void(bool)> setter, bool default_value);

        /// Registers a string configuration item.
        void register_string(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
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
         */
        void register_key_combo(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                               std::function<void(const KeyComboList &)> setter, const std::string &default_value_str);

        /**
         * @brief Loads all registered configuration settings from the specified INI file.
         * @details Parses the INI file and attempts to read values for each registered item.
         *          If a key is missing or invalid, the default value provided during
         *          registration is used.
         * @param ini_filename The base filename of the INI file. Path will be resolved
         *                     relative to the mod's runtime directory.
         */
        void load(const std::string &ini_filename);

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

#endif // CONFIG_HPP
