#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <vector>
#include <string>
#include <functional>
#include <optional>

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

        /// Registers a key list configuration item (comma-separated hex VK codes).
        void register_key_list(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                             std::function<void(const std::vector<int> &)> setter, const std::string &default_value_str);

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
