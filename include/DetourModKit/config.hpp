/**
 * @file config.hpp
 * @brief Defines the API for DetourModKit's configuration system.
 *
 * This system allows mods to register their configuration variables (which they
 * define and own) with DetourModKit. The kit then handles loading values
 * for these variables from an INI file and provides a way to log them.
 * This approach decouples the mod's configuration structure from the kit's
 * loading mechanism, making the kit more modular.
 */
#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <vector>
#include <string>

namespace DetourModKit
{
    /**
     * @namespace Config
     * @brief Provides functions for registering, loading, and logging configuration settings.
     */
    namespace Config
    {
        /**
         * @brief Registers an integer configuration item.
         * @param section The INI section name (e.g., "Main").
         * @param ini_key The INI key name (e.g., "UpdateInterval").
         * @param log_key_name A user-friendly name for this setting, used in logs (e.g., "UpdateIntervalMs").
         * @param target_variable A reference to an integer variable in the mod's code where the loaded value will be stored.
         * @param default_value The default integer value to use if the key is not found in the INI or is invalid.
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
         * @param default_value_str A string representing the default comma-separated hex VK codes (e.g., "0x20,0x70").
         */
        void registerKeyList(const std::string &section, const std::string &ini_key, const std::string &log_key_name,
                             std::vector<int> &target_variable, const std::string &default_value_str);

        /**
         * @brief Loads all registered configuration settings from the specified INI file.
         * @details Parses the INI file (typically located next to the mod DLL). For each registered item,
         *          it attempts to read the value and store it in the associated `target_variable`.
         *          If a key is missing or invalid, the `default_value` provided during registration is used.
         *          Logs progress and errors via the global Logger instance.
         * @param ini_filename The base filename of the INI file (e.g., "MyMod.ini"). The path will be
         *                     resolved relative to the mod's runtime directory.
         */
        void load(const std::string &ini_filename);

        /**
         * @brief Logs the current values of all registered configuration settings.
         * @details Iterates through all items registered with the config system and outputs their
         *          current values (as stored in the `target_variable`s) to the Logger.
         */
        void logAll();

        /**
         * @brief Clears all currently registered configuration items.
         * @details This function is useful if the configuration system needs to be reset,
         *          for example, if the mod is reinitialized without restarting the application.
         *          It empties the internal list of registered items.
         */
        void clearRegisteredItems();

    } // namespace Config
} // namespace DetourModKit

#endif // CONFIG_HPP
