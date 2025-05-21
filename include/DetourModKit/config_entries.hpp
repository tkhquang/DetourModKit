// config_entries.hpp
/**
 * @file config_entries.hpp
 * @brief Centralized definition of configuration entries.
 *
 * Defines all configuration settings using macros, including their INI section,
 * key name, variable name, and default value. This file is included by config.hpp
 * and config.cpp to generate the Config struct, load values from the INI file,
 * and log them.
 */

// [Settings] Section
CONFIG_STRING("Settings", "LogLevel", log_level, "INFO")
