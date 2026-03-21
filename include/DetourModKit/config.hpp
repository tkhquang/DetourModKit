#ifndef CONFIG_HPP
#define CONFIG_HPP

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
         * @brief Represents a key combination parsed from an INI value.
         * @details Contains trigger keys (OR logic) and modifier keys (AND logic).
         *          Designed for direct use with InputManager::register_press/register_hold.
         *
         *          INI format: modifier hex codes separated by '+', with the last
         *          '+'-delimited segment containing trigger key(s) (comma-separated for
         *          multiple triggers). Examples:
         *            - "0x72"              → keys=[F3], modifiers=[]
         *            - "0x11+0x72"         → keys=[F3], modifiers=[Ctrl]
         *            - "0x11+0x10+0x72"    → keys=[F3], modifiers=[Ctrl, Shift]
         *            - "0x11+0x72,0x73"    → keys=[F3, F4], modifiers=[Ctrl]
         */
        struct KeyCombo
        {
            std::vector<int> keys;
            std::vector<int> modifiers;
        };

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
         * @details Parses an INI value as a key combination with optional modifier keys.
         *          Format: "modifier1+modifier2+trigger_key1,trigger_key2" where all
         *          values are hex VK codes. The '+' separator delimits modifier keys from
         *          trigger keys, with the last segment being trigger key(s). Commas within
         *          the last segment provide OR logic for multiple trigger keys.
         * @param section INI section name.
         * @param ini_key INI key name.
         * @param log_key_name Human-readable name shown in log output.
         * @param setter Callback invoked with the parsed KeyCombo.
         * @param default_value_str Default value string in the same format.
         */
        void register_key_combo(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                               std::function<void(const KeyCombo &)> setter, const std::string &default_value_str);

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
