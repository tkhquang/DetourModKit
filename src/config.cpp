/**
 * @file config.cpp
 * @brief Implementation of configuration loading and management.
 *
 * Provides a system for registering configuration variables, loading their
 * values from an INI file, and logging them. This allows mods to define their
 * configuration needs and have DetourModKit handle the INI parsing and value
 * assignment.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/filesystem_utils.hpp"
#include "DetourModKit/string_utils.hpp"
#include "SimpleIni.h"

#include <windows.h>
#include <filesystem>
#include <cctype>
#include <algorithm>
#include <string>
#include <stdexcept>
#include <sstream>
#include <vector>
#include <memory>
#include <variant>
#include <typeinfo>

// Anonymous namespace for internal helpers and storage
namespace
{
    /**
     * @brief Base class for typed configuration items.
     * @details This allows storing different types of configuration items
     *          polymorphically in a collection.
     */
    struct ConfigItemBase
    {
        std::string section;
        std::string ini_key;
        std::string log_key_name;

        ConfigItemBase(std::string sec, std::string key, std::string log_name)
            : section(std::move(sec)), ini_key(std::move(key)), log_key_name(std::move(log_name)) {}
        virtual ~ConfigItemBase() = default;

        /**
         * @brief Loads the configuration value from the INI file.
         * @param ini Reference to the CSimpleIniA object.
         * @param logger Reference to the Logger object.
         */
        virtual void load(CSimpleIniA &ini, Logger &logger) = 0;

        /**
         * @brief Logs the current value of the configuration item.
         * @param logger Reference to the Logger object.
         */
        virtual void log_current_value(Logger &logger) const = 0;
    };

    /**
     * @brief Template class for a specific configuration item type.
     * @tparam T The data type of the configuration item (e.g., int, bool, std::string).
     */
    template <typename T>
    struct ConfigItem : public ConfigItemBase
    {
        T &target_variable; // Reference to the user's variable where the value will be stored
        T default_value;

        ConfigItem(std::string sec, std::string key, std::string log_name, T &target, T def_val)
            : ConfigItemBase(std::move(sec), std::move(key), std::move(log_name)),
              target_variable(target), default_value(std::move(def_val))
        {
            // Initialize with default value. If INI loading fails or key is missing, this remains.
            target_variable = default_value;
        }

        void load(CSimpleIniA &ini, Logger &logger) override;  // Specialized outside
        void log_current_value(Logger &logger) const override; // Specialized outside
    };

    // --- Specializations for ConfigItem<T>::load and ConfigItem<T>::log_current_value ---

    // For int
    template <>
    void ConfigItem<int>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        target_variable = ini.GetLongValue(section.c_str(), ini_key.c_str(), default_value);
    }
    template <>
    void ConfigItem<int>::log_current_value(Logger &logger) const
    {
        logger.log(LOG_INFO, "Config: " + log_key_name + " (" + section + "." + ini_key + ") = " + std::to_string(target_variable));
    }

    // For float
    template <>
    void ConfigItem<float>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        target_variable = static_cast<float>(ini.GetDoubleValue(section.c_str(), ini_key.c_str(), static_cast<double>(default_value)));
    }
    template <>
    void ConfigItem<float>::log_current_value(Logger &logger) const
    {
        logger.log(LOG_INFO, "Config: " + log_key_name + " (" + section + "." + ini_key + ") = " + std::to_string(target_variable));
    }

    // For bool
    template <>
    void ConfigItem<bool>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        target_variable = ini.GetBoolValue(section.c_str(), ini_key.c_str(), default_value);
    }
    template <>
    void ConfigItem<bool>::log_current_value(Logger &logger) const
    {
        logger.log(LOG_INFO, "Config: " + log_key_name + " (" + section + "." + ini_key + ") = " + (target_variable ? "true" : "false"));
    }

    // For std::string
    template <>
    void ConfigItem<std::string>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        target_variable = ini.GetValue(section.c_str(), ini_key.c_str(), default_value.c_str());
    }
    template <>
    void ConfigItem<std::string>::log_current_value(Logger &logger) const
    {
        logger.log(LOG_INFO, "Config: " + log_key_name + " (" + section + "." + ini_key + ") = " + "\"" + target_variable + "\""); // Quote strings
    }

    // --- Helper: Parses a comma-separated string of hexadecimal VK codes ---
    std::vector<int> parseKeyListInternal(const std::string &value_str, Logger &logger,
                                          const std::string &section_key_for_log)
    {
        std::vector<int> keys;
        std::string str_no_comment = value_str;
        size_t comment_pos = str_no_comment.find(';');
        if (comment_pos != std::string::npos)
        {
            str_no_comment = str_no_comment.substr(0, comment_pos);
        }
        std::string trimmed_val = trim(str_no_comment);

        if (trimmed_val.empty())
        {
            return keys; // Not an error, just no keys defined.
        }

        std::istringstream iss(trimmed_val);
        std::string token;
        logger.log(LOG_DEBUG, "Config: Parsing KeyList for '" + section_key_for_log + "': \"" + trimmed_val + "\"");
        int token_idx = 0;

        while (std::getline(iss, token, ','))
        {
            token_idx++;
            size_t token_comment_pos = token.find(';');
            if (token_comment_pos != std::string::npos)
            {
                token = token.substr(0, token_comment_pos);
            }
            std::string trimmed_token = trim(token);
            if (trimmed_token.empty())
            {
                continue; // Ignore empty tokens resulting from multiple commas or spaces
            }

            std::string hex_part = trimmed_token;
            if (hex_part.size() >= 2 && hex_part[0] == '0' && (hex_part[1] == 'x' || hex_part[1] == 'X'))
            {
                hex_part = hex_part.substr(2);
                if (hex_part.empty()) // e.g., "0x,"
                {
                    logger.log(LOG_WARNING, "Config: Invalid key token '" + token + "' (prefix only) in '" + section_key_for_log + "' at token " + std::to_string(token_idx));
                    continue;
                }
            }

            if (hex_part.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
            {
                logger.log(LOG_WARNING, "Config: Invalid non-hex character in key token '" + token + "' for '" + section_key_for_log + "' at token " + std::to_string(token_idx));
                continue;
            }
            if (hex_part.empty())
            { // case where token was just "0x" and substring made it empty, or original token was empty (already handled by trim)
                logger.log(LOG_WARNING, "Config: Empty hex part after processing token '" + token + "' for '" + section_key_for_log + "' at token " + std::to_string(token_idx));
                continue;
            }

            try
            {
                unsigned long code_ul = std::stoul(hex_part, nullptr, 16);
                if (code_ul == 0 || code_ul > 0xFF) // VK codes are typically 1 byte. 0 is often not a valid user-assignable VK.
                {
                    logger.log(LOG_WARNING, "Config: Key code " + format_hex(static_cast<int>(code_ul), 2) +
                                                " from token '" + token + "' for '" + section_key_for_log + "' is 0x00 or exceeds 0xFF. It might be invalid or unintended.");
                }
                keys.push_back(static_cast<int>(code_ul));
                logger.log(LOG_DEBUG, "Config: Added key for '" + section_key_for_log + "': " + format_vkcode(static_cast<int>(code_ul)));
            }
            catch (const std::exception &e) // Catches std::invalid_argument or std::out_of_range
            {
                logger.log(LOG_WARNING, "Config: Error converting hex token '" + token + "' (from original '" + trimmed_token + "') for '" + section_key_for_log + "': " + e.what());
            }
        }

        if (keys.empty() && !trimmed_val.empty())
        {
            logger.log(LOG_WARNING, "Config: Processed value for '" + section_key_for_log + "' (\"" + trimmed_val + "\") but found no valid key codes.");
        }
        return keys;
    }

    // For std::vector<int> (KeyList)
    template <>
    void ConfigItem<std::vector<int>>::load(CSimpleIniA &ini, Logger &logger)
    {
        // The `default_value` for ConfigItem<std::vector<int>> is already a std::vector<int>,
        // parsed from a string at registration time.
        // SimpleIniA::GetValue's third argument (pDefault) is a const char*. If the key isn't in the INI,
        // SimpleIni will use *that* default.
        // Our logic is: target_variable is initialized with ConfigItem's `default_value` (the std::vector<int>).
        // If the INI key exists, we parse *its* string value and overwrite `target_variable`.
        // If the INI key does NOT exist, `target_variable` keeps its pre-assigned default vector.

        const char *ini_value_str = ini.GetValue(section.c_str(), ini_key.c_str(), nullptr); // Get nullptr if not found
        if (ini_value_str != nullptr)
        {
            // Key exists in INI, parse its string value.
            target_variable = parseKeyListInternal(ini_value_str, logger, section + "." + ini_key);
        }
        // If ini_value_str is nullptr (key not in INI), target_variable retains its value
        // which was set to `default_value` (the std::vector<int>) during ConfigItem construction.
    }

    template <>
    void ConfigItem<std::vector<int>>::log_current_value(Logger &logger) const
    {
        logger.log(LOG_INFO, "Config: " + log_key_name + " (" + section + "." + ini_key + ") = " + format_vkcode_list(target_variable));
    }

    // --- Global storage for registered configuration items ---
    std::vector<std::unique_ptr<ConfigItemBase>> &getRegisteredConfigItems()
    {
        // This static variable holds all registered config items.
        // It's function-local static to ensure controlled initialization order.
        static std::vector<std::unique_ptr<ConfigItemBase>> s_registered_items;
        return s_registered_items;
    }

    /**
     * @brief Determines the full absolute path for the INI configuration file.
     */
    static std::string getIniFilePath(const std::string &ini_filename, Logger &logger)
    {
        std::string module_dir = getRuntimeDirectory();

        if (module_dir.empty() || module_dir == ".")
        {
            logger.log(LOG_WARNING, "Config: Could not reliably determine module directory or it's current working directory. Using relative path for INI: " + ini_filename);
            return ini_filename; // Fallback to relative path
        }

        try
        {
            std::filesystem::path ini_path_obj = std::filesystem::path(module_dir) / ini_filename;
            std::string full_path = ini_path_obj.lexically_normal().string(); // Normalize (e.g., C:/path/./file -> C:/path/file)
            logger.log(LOG_DEBUG, "Config: Determined INI file path: " + full_path);
            return full_path;
        }
        catch (const std::filesystem::filesystem_error &fs_err)
        {
            logger.log(LOG_WARNING, "Config: Filesystem error constructing INI path: " + std::string(fs_err.what()) + ". Using relative path for INI: " + ini_filename);
        }
        catch (const std::exception &e) // Catch other potential exceptions
        {
            logger.log(LOG_WARNING, "Config: General error constructing INI path: " + std::string(e.what()) + ". Using relative path for INI: " + ini_filename);
        }
        return ini_filename; // Fallback
    }

} // anonymous namespace

// --- Public API for Configuration Registration ---

void DetourModKit::Config::registerInt(const std::string &section, const std::string &ini_key, const std::string &log_key_name, int &target_variable, int default_value)
{
    getRegisteredConfigItems().push_back(
        std::make_unique<ConfigItem<int>>(section, ini_key, log_key_name, target_variable, default_value));
}

void DetourModKit::Config::registerFloat(const std::string &section, const std::string &ini_key, const std::string &log_key_name, float &target_variable, float default_value)
{
    getRegisteredConfigItems().push_back(
        std::make_unique<ConfigItem<float>>(section, ini_key, log_key_name, target_variable, default_value));
}

void DetourModKit::Config::registerBool(const std::string &section, const std::string &ini_key, const std::string &log_key_name, bool &target_variable, bool default_value)
{
    getRegisteredConfigItems().push_back(
        std::make_unique<ConfigItem<bool>>(section, ini_key, log_key_name, target_variable, default_value));
}

void DetourModKit::Config::registerString(const std::string &section, const std::string &ini_key, const std::string &log_key_name, std::string &target_variable, const std::string &default_value)
{
    getRegisteredConfigItems().push_back(
        std::make_unique<ConfigItem<std::string>>(section, ini_key, log_key_name, target_variable, default_value));
}

void DetourModKit::Config::registerKeyList(const std::string &section, const std::string &ini_key, const std::string &log_key_name, std::vector<int> &target_variable, const std::string &default_value_str)
{
    // Parse the default_value_str into a vector<int> first for the ConfigItem's default_value field.
    Logger &logger = Logger::getInstance(); // Needed for parseKeyListInternal
    std::vector<int> default_keys_vector = parseKeyListInternal(default_value_str, logger, section + "." + ini_key + " [default_value]");

    getRegisteredConfigItems().push_back(
        std::make_unique<ConfigItem<std::vector<int>>>(section, ini_key, log_key_name, target_variable, default_keys_vector));
}

// --- Public API for Loading and Logging Configuration ---

void DetourModKit::Config::load(const std::string &ini_filename)
{
    Logger &logger = Logger::getInstance();
    std::string ini_path = getIniFilePath(ini_filename, logger); // Pass logger to helper
    logger.log(LOG_INFO, "Config: Attempting to load configuration from: " + ini_path);

    CSimpleIniA ini;
    ini.SetUnicode(false);  // Assume ASCII/MBCS INI
    ini.SetMultiKey(false); // Disallow duplicate keys in a section

    SI_Error rc = ini.LoadFile(ini_path.c_str());
    if (rc < 0)
    {
        logger.log(LOG_ERROR, "Config: Failed to open INI file '" + ini_path + "'. Error code: " + std::to_string(rc) + ". Using default values for all registered settings.");
        // Defaults are already set in target_variables upon registration when ConfigItem is constructed.
        // The `load` method of each ConfigItem will use its `default_value` with SimpleIni calls,
        // but effectively, if the file doesn't load, the variables retain their construction-time defaults.
    }
    else
    {
        logger.log(LOG_INFO, "Config: Successfully opened INI file: " + ini_path);
    }

    // Load all registered items.
    // Each ConfigItem<T>::load specialization will handle calling the appropriate CSimpleIniA::GetXValue method.
    // If the INI key is missing, CSimpleIniA's methods use the default provided to them,
    // which is the `item->default_value` member of the ConfigItem.
    for (const auto &item : getRegisteredConfigItems())
    {
        // This populates the user's variable referenced by 'item->target_variable'
        // using the item's own 'item->default_value' if the INI key isn't found by SimpleIni.
        item->load(ini, logger);
    }

    logger.log(LOG_INFO, "Config: Configuration loading complete. " + std::to_string(getRegisteredConfigItems().size()) + " items processed.");
}

void DetourModKit::Config::logAll()
{
    Logger &logger = Logger::getInstance();
    if (getRegisteredConfigItems().empty())
    {
        logger.log(LOG_INFO, "Config: No configuration items registered to log.");
        return;
    }

    logger.log(LOG_INFO, "Config: Logging " + std::to_string(getRegisteredConfigItems().size()) + " registered configuration values:");
    for (const auto &item : getRegisteredConfigItems())
    {
        item->log_current_value(logger);
    }
    logger.log(LOG_INFO, "Config: Configuration logging completed.");
}

void DetourModKit::Config::clearRegisteredItems()
{
    Logger &logger = Logger::getInstance();
    size_t count = getRegisteredConfigItems().size();
    if (count > 0) // Only log if there was something to clear
    {
        getRegisteredConfigItems().clear(); // This will call destructors for all unique_ptrs and ConfigItemBase objects.
        logger.log(LOG_DEBUG, "Config: Cleared " + std::to_string(count) + " registered configuration items.");
    }
    else
    {
        logger.log(LOG_DEBUG, "Config: clearRegisteredItems called, but no items were registered.");
    }
}
