/**
 * @file config.cpp
 * @brief Implementation of configuration loading and logging.
 *
 * Loads configuration settings from an INI file using SimpleIni and logs them.
 * Uses macros from config_entries.hpp to generate code for loading and logging,
 * ensuring a generic, reusable framework independent of specific settings.
 */

#include "config.hpp"
#include "logger.hpp"
#include "filesystem_utils.hpp"
#include "string_utils.hpp"
#include "SimpleIni.h"

#include <windows.h>
#include <filesystem>
#include <cctype>
#include <algorithm>
#include <string>
#include <stdexcept>
#include <sstream>

/**
 * @brief Determines the full absolute path for the INI configuration file.
 * @details Locates the INI file in the same directory as the currently
 *          running module (DLL/ASI), as determined by getRuntimeDirectory().
 *          Falls back to using just the provided filename if path
 *          determination fails or returns an unsuitable path.
 * @param ini_filename Base name of the INI file (e.g., "MyMod.ini").
 * @return std::string Full path to the INI file. If runtime directory cannot
 *         be determined or is invalid, returns ini_filename as a relative path.
 */
static std::string getIniFilePath(const std::string &ini_filename)
{
    Logger &logger = Logger::getInstance();
    std::string module_dir = getRuntimeDirectory();

    if (module_dir.empty() || module_dir == ".")
    {
        logger.log(LOG_WARNING, "Config: Could not reliably determine module directory or it's CWD. Using relative path for INI: " + ini_filename);
        return ini_filename; // Fallback to relative path
    }

    try
    {
        // Construct the full path using std::filesystem
        std::filesystem::path ini_path_obj = std::filesystem::path(module_dir) / ini_filename;
        // Normalize the path (e.g., resolves ".." and ".")
        std::string full_path = ini_path_obj.lexically_normal().string();

        logger.log(LOG_DEBUG, "Config: Determined INI file path: " + full_path);
        return full_path;
    }
    catch (const std::filesystem::filesystem_error &fs_err)
    {
        logger.log(LOG_WARNING, "Config: Filesystem error constructing INI path: " + std::string(fs_err.what()) + ". Using relative path: " + ini_filename);
    }
    catch (const std::exception &e)
    {
        logger.log(LOG_WARNING, "Config: General error constructing INI path: " + std::string(e.what()) + ". Using relative path: " + ini_filename);
    }
    // Fallback if path construction fails
    return ini_filename;
}

/**
 * @brief Parses a comma-separated string of hexadecimal VK codes from INI value.
 * @details Handles optional "0x" prefixes, trims whitespace, validates hex
 *          format for each token, and converts valid tokens to integer VK codes.
 *          Logs warnings for invalid tokens or codes outside typical range.
 * @param value_str The raw string value read from the INI file.
 * @param logger Reference to the logger for reporting parsing details/errors.
 * @param key_name The name of the INI key being parsed (e.g., "ToggleKey") for logs.
 * @return std::vector<int> A vector containing the valid integer VK codes found.
 *         Returns an empty vector if the input string is empty or contains no valid codes.
 */
static std::vector<int> parseKeyList(const std::string &value_str, Logger &logger,
                                     const std::string &key_name)
{
    std::vector<int> keys;

    // Remove any inline comment (everything after semicolon)
    std::string str_no_comment = value_str;
    size_t comment_pos = str_no_comment.find(';');
    if (comment_pos != std::string::npos)
    {
        str_no_comment = str_no_comment.substr(0, comment_pos);
    }

    std::string trimmed_val = trim(str_no_comment);

    if (trimmed_val.empty())
    {
        return keys; // Return empty vector, not an error
    }

    std::istringstream iss(trimmed_val);
    std::string token;
    logger.log(LOG_DEBUG, "Config: Parsing '" + key_name + "': \"" + trimmed_val + "\"");
    int token_idx = 0;

    while (std::getline(iss, token, ','))
    {
        token_idx++;
        // Strip any inline comments from individual tokens too
        size_t token_comment_pos = token.find(';');
        if (token_comment_pos != std::string::npos)
        {
            token = token.substr(0, token_comment_pos);
        }

        std::string trimmed_token = trim(token);
        if (trimmed_token.empty())
        {
            continue; // Ignore empty tokens
        }

        // Check for and remove optional "0x" or "0X" prefix
        std::string hex_part = trimmed_token;
        if (hex_part.size() >= 2 && hex_part[0] == '0' && (hex_part[1] == 'x' || hex_part[1] == 'X'))
        {
            hex_part = hex_part.substr(2);
            if (hex_part.empty())
            {
                logger.log(LOG_WARNING, "Config: Invalid key token '" + token + "' (just prefix) in '" + key_name + "' at token " + std::to_string(token_idx));
                continue;
            }
        }

        // Validate hexadecimal format
        if (hex_part.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        {
            logger.log(LOG_WARNING, "Config: Invalid non-hex character in key token '" + token + "' for '" + key_name + "' at token " + std::to_string(token_idx));
            continue;
        }

        // Convert to integer VK code
        try
        {
            unsigned long code_ul = std::stoul(hex_part, nullptr, 16);
            if (code_ul == 0 || code_ul > 0xFF)
            {
                logger.log(LOG_WARNING, "Config: Key code " + format_hex(static_cast<int>(code_ul)) +
                                            " ('" + token + "') for '" + key_name + "' is outside typical VK range (0x01-0xFF)");
            }
            int key_code = static_cast<int>(code_ul);
            keys.push_back(key_code);
            logger.log(LOG_DEBUG, "Config: Added key for '" + key_name + "': " + format_vkcode(key_code));
        }
        catch (const std::exception &e)
        {
            logger.log(LOG_WARNING, "Config: Error converting hex token '" + token + "' for '" + key_name + "': " + e.what());
        }
    }

    if (keys.empty() && !trimmed_val.empty())
    {
        logger.log(LOG_WARNING, "Config: Processed value for '" + key_name + "' (\"" + trimmed_val + "\") but found no valid key codes.");
    }

    return keys;
}

Config loadConfig(const std::string &ini_filename)
{
    Config config;
    Logger &logger = Logger::getInstance();
    std::string ini_path = getIniFilePath(ini_filename);
    logger.log(LOG_INFO, "Config: Attempting to load configuration from: " + ini_path);

    CSimpleIniA ini;
    ini.SetUnicode(false);  // Assuming ASCII/MBCS INI file
    ini.SetMultiKey(false); // Don't allow duplicate keys in sections

    SI_Error rc = ini.LoadFile(ini_path.c_str());
    if (rc < 0)
    {
        logger.log(LOG_ERROR, "Config: Failed to open INI file '" + ini_path + "'. Using default settings.");
    }
    else
    {
        logger.log(LOG_INFO, "Config: Successfully opened INI file.");

// Load configuration entries using macros
#define CONFIG_INT(section, ini_key, var_name, default_value) \
    config.var_name = ini.GetLongValue(section, ini_key, default_value);
#define CONFIG_FLOAT(section, ini_key, var_name, default_value) \
    config.var_name = (float)ini.GetDoubleValue(section, ini_key, default_value);
#define CONFIG_STRING(section, ini_key, var_name, default_value) \
    config.var_name = ini.GetValue(section, ini_key, default_value);
#define CONFIG_BOOL(section, ini_key, var_name, default_value) \
    config.var_name = ini.GetBoolValue(section, ini_key, default_value);
#define CONFIG_KEY_LIST(section, ini_key, var_name, default_value) \
    config.var_name = parseKeyList(ini.GetValue(section, ini_key, default_value), logger, ini_key);
#include "config_entries.hpp"
#undef CONFIG_INT
#undef CONFIG_FLOAT
#undef CONFIG_STRING
#undef CONFIG_BOOL
#undef CONFIG_KEY_LIST
    }

    // Post-load validation for log level
    std::string upper_log_level = config.log_level;
    std::transform(upper_log_level.begin(), upper_log_level.end(), upper_log_level.begin(), ::toupper);
    if (upper_log_level == "TRACE")
        config.log_level = "TRACE";
    else if (upper_log_level == "DEBUG")
        config.log_level = "DEBUG";
    else if (upper_log_level == "INFO")
        config.log_level = "INFO";
    else if (upper_log_level == "WARNING")
        config.log_level = "WARNING";
    else if (upper_log_level == "ERROR")
        config.log_level = "ERROR";
    else
    {
        logger.log(LOG_WARNING, "Config: Invalid LogLevel '" + config.log_level + "'. Using default: 'INFO'.");
        config.log_level = "INFO";
    }

    return config;
}

void logConfig(const Config &config)
{
    Logger &logger = Logger::getInstance();

// Log all configuration entries using macros
#define CONFIG_INT(section, ini_key, var_name, default_value) \
    logger.log(LOG_INFO, "Config: " + std::string(ini_key) + " = " + std::to_string(config.var_name));
#define CONFIG_FLOAT(section, ini_key, var_name, default_value) \
    logger.log(LOG_INFO, "Config: " + std::string(ini_key) + " = " + std::to_string(config.var_name));
#define CONFIG_STRING(section, ini_key, var_name, default_value) \
    logger.log(LOG_INFO, "Config: " + std::string(ini_key) + " = " + config.var_name);
#define CONFIG_BOOL(section, ini_key, var_name, default_value) \
    logger.log(LOG_INFO, "Config: " + std::string(ini_key) + " = " + (config.var_name ? "true" : "false"));
#define CONFIG_KEY_LIST(section, ini_key, var_name, default_value) \
    logger.log(LOG_INFO, "Config: " + std::string(ini_key) + " = " + format_vkcode_list(config.var_name));
#include "config_entries.hpp"
#undef CONFIG_INT
#undef CONFIG_FLOAT
#undef CONFIG_STRING
#undef CONFIG_BOOL
#undef CONFIG_KEY_LIST

    logger.log(LOG_INFO, "Config: Configuration logging completed.");
}
