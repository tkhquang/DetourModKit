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
     *          The kit then handles loading values from an INI file and provides logging functionality.
     *          The API uses std::function callbacks for type-safe value setting without
     *          raw reference lifetime issues.
     */
    namespace Config
    {

        /**
         * @brief Registers an integer configuration item with a callback setter.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for this setting, used in logs.
         * @param setter A callback function that receives the loaded value.
         * @param default_value The default integer value to use if the key is not found or invalid.
         */
        void registerIntCallback(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                                 std::function<void(int)> setter, int default_value);

        /**
         * @brief Registers a floating-point configuration item with a callback setter.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for logging.
         * @param setter A callback function that receives the loaded value.
         * @param default_value The default float value.
         */
        void registerFloatCallback(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                                   std::function<void(float)> setter, float default_value);

        /**
         * @brief Registers a boolean configuration item with a callback setter.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for logging.
         * @param setter A callback function that receives the loaded value.
         * @param default_value The default boolean value.
         */
        void registerBoolCallback(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                                  std::function<void(bool)> setter, bool default_value);

        /**
         * @brief Registers a string configuration item with a callback setter.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for logging.
         * @param setter A callback function that receives the loaded value.
         * @param default_value The default string value.
         */
        void registerStringCallback(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                                    std::function<void(const std::string &)> setter, std::string default_value);

        /**
         * @brief Registers a key list configuration item (comma-separated hex VK codes) with a callback setter.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for logging.
         * @param setter A callback function that receives the loaded vector of VK codes.
         * @param default_value_str A string representing the default comma-separated hex VK codes.
         */
        void registerKeyListCallback(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
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
        void logAll();

        /**
         * @brief Clears all currently registered configuration items.
         * @details Useful if the configuration system needs to be reset without
         *          restarting the application.
         */
        void clearRegisteredItems();

    } // namespace Config
} // namespace DetourModKit

#endif // CONFIG_HPP
