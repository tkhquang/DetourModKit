#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <vector>
#include <string>

namespace DetourModKit
{
    class Logger;

    /**
     * @namespace Config
     * @brief Provides functions for registering, loading, and logging configuration settings.
     * @details This system allows mods to register their configuration variables with DetourModKit.
     *          The kit then handles loading values from an INI file and provides logging functionality.
     */
    namespace Config
    {
        /**
         * @brief Registers an integer configuration item.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for this setting, used in logs.
         * @param target_variable A reference to an integer variable where the loaded value will be stored.
         * @param default_value The default integer value to use if the key is not found or invalid.
         */
        void registerInt(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                         int &target_variable, int default_value);

        /**
         * @brief Registers a floating-point configuration item.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for logging.
         * @param target_variable A reference to a float variable for storing the loaded value.
         * @param default_value The default float value.
         */
        void registerFloat(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                           float &target_variable, float default_value);

        /**
         * @brief Registers a boolean configuration item.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for logging.
         * @param target_variable A reference to a bool variable for storing the loaded value.
         * @param default_value The default boolean value.
         */
        void registerBool(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                          bool &target_variable, bool default_value);

        /**
         * @brief Registers a string configuration item.
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for logging.
         * @param target_variable A reference to a std::string variable for storing the loaded value.
         * @param default_value The default string value.
         */
        void registerString(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                            std::string &target_variable, const std::string &default_value);

        /**
         * @brief Registers a key list configuration item (comma-separated hex VK codes).
         * @param section The INI section name.
         * @param ini_key The INI key name.
         * @param log_key_name A user-friendly name for logging.
         * @param target_variable A reference to a std::vector<int> for storing the parsed VK codes.
         * @param default_value_str A string representing the default comma-separated hex VK codes.
         */
        void registerKeyList(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                             std::vector<int> &target_variable, const std::string &default_value_str);

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
