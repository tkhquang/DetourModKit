/**
 * @file config.h
 * @brief Defines the Config structure and function prototypes for configuration handling.
 *
 * The Config struct is generated from configuration entries defined in
 * config_entries.h using macros. This provides a centralized, extensible way
 * to define settings that can be loaded from an INI file and logged. The framework
 * is designed to be generic and reusable across projects.
 */
#ifndef CONFIG_H
#define CONFIG_H

#include <vector>
#include <string>

struct Config
{
// Define configuration members using macros
// Each macro corresponds to a supported data type and expands to a struct member
#define CONFIG_INT(section, ini_key, var_name, default_value) int var_name;
#define CONFIG_FLOAT(section, ini_key, var_name, default_value) float var_name;
#define CONFIG_STRING(section, ini_key, var_name, default_value) std::string var_name;
#define CONFIG_BOOL(section, ini_key, var_name, default_value) bool var_name;
#define CONFIG_KEY_LIST(section, ini_key, var_name, default_value) std::vector<int> var_name;
#include "config_entries.hpp"
#undef CONFIG_INT
#undef CONFIG_FLOAT
#undef CONFIG_STRING
#undef CONFIG_BOOL
#undef CONFIG_KEY_LIST
};

/**
 * @brief Loads configuration settings from an INI file.
 * @details Uses SimpleIni to parse the INI file located next to the DLL.
 *          Populates the Config struct based on entries defined in
 *          config_entries.h. Applies default values for missing entries.
 *          Logs progress and errors via the global Logger instance.
 * @param ini_filename Base filename of the INI file (e.g., "KCD2_TPVToggle.ini").
 * @return Config Structure containing the loaded settings.
 */
Config loadConfig(const std::string &ini_filename);

/**
 * @brief Logs all configuration settings.
 * @details Outputs the current values of all configuration entries to the
 *          Logger instance, formatted consistently based on their types.
 * @param config The Config structure to log.
 */
void logConfig(const Config &config);

#endif // CONFIG_H
