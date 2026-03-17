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
#include <mutex>

using namespace DetourModKit;
using namespace DetourModKit::Filesystem;
using namespace DetourModKit::String;

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
     * @brief Configuration item using std::function callback (NEW API).
     * @tparam T The data type of the configuration item (e.g., int, bool, std::string).
     */
    template <typename T>
    struct CallbackConfigItem : public ConfigItemBase
    {
        std::function<void(T)> setter; // Callback function to set the value
        T default_value;
        T current_value;

        CallbackConfigItem(std::string sec, std::string key, std::string log_name,
                           std::function<void(T)> set_fn, T def_val)
            : ConfigItemBase(std::move(sec), std::move(key), std::move(log_name)),
              setter(std::move(set_fn)),
              default_value(std::move(def_val)),
              current_value(default_value)
        {
            // Initialize with default value via callback
            if (setter)
            {
                setter(current_value);
            }
        }

        void load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger) override;
        void log_current_value(Logger &logger) const override;
    };

    // --- Specializations for CallbackConfigItem<T>::load and ::log_current_value ---

    // For int
    template <>
    void CallbackConfigItem<int>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        current_value = static_cast<int>(ini.GetLongValue(section.c_str(), ini_key.c_str(), default_value));
        if (setter)
        {
            setter(current_value);
        }
    }

    template <>
    void CallbackConfigItem<int>::log_current_value(Logger &logger) const
    {
        logger.info("Config: {} ({}.{}) = {}", log_key_name, section, ini_key, current_value);
    }

    // For float
    template <>
    void CallbackConfigItem<float>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        current_value = static_cast<float>(ini.GetDoubleValue(section.c_str(), ini_key.c_str(), static_cast<double>(default_value)));
        if (setter)
        {
            setter(current_value);
        }
    }

    template <>
    void CallbackConfigItem<float>::log_current_value(Logger &logger) const
    {
        logger.info("Config: {} ({}.{}) = {}", log_key_name, section, ini_key, current_value);
    }

    // For bool
    template <>
    void CallbackConfigItem<bool>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        current_value = ini.GetBoolValue(section.c_str(), ini_key.c_str(), default_value);
        if (setter)
        {
            setter(current_value);
        }
    }

    template <>
    void CallbackConfigItem<bool>::log_current_value(Logger &logger) const
    {
        logger.info("Config: {} ({}.{}) = {}", log_key_name, section, ini_key, current_value ? "true" : "false");
    }

    // For std::string
    template <>
    void CallbackConfigItem<std::string>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        current_value = ini.GetValue(section.c_str(), ini_key.c_str(), default_value.c_str());
        if (setter)
        {
            setter(current_value);
        }
    }

    template <>
    void CallbackConfigItem<std::string>::log_current_value(Logger &logger) const
    {
        logger.info("Config: {} ({}.{}) = \"{}\"", log_key_name, section, ini_key, current_value);
    }

    // For std::vector<int> (KeyList) with callback
    template <>
    void CallbackConfigItem<std::vector<int>>::load(CSimpleIniA &ini, Logger &logger)
    {
        const char *ini_value_str = ini.GetValue(section.c_str(), ini_key.c_str(), nullptr);
        if (ini_value_str != nullptr)
        {
            // Parse the INI value string into a vector
            current_value.clear();
            std::string str_no_comment = ini_value_str;
            size_t comment_pos = str_no_comment.find(';');
            if (comment_pos != std::string::npos)
            {
                str_no_comment = str_no_comment.substr(0, comment_pos);
            }
            std::string trimmed_val = trim(str_no_comment);

            if (!trimmed_val.empty())
            {
                std::istringstream iss(trimmed_val);
                std::string token;
                while (std::getline(iss, token, ','))
                {
                    size_t token_comment_pos = token.find(';');
                    if (token_comment_pos != std::string::npos)
                    {
                        token = token.substr(0, token_comment_pos);
                    }
                    std::string trimmed_token = trim(token);
                    if (trimmed_token.empty())
                    {
                        continue;
                    }

                    std::string hex_part = trimmed_token;
                    if (hex_part.size() >= 2 && hex_part[0] == '0' && (hex_part[1] == 'x' || hex_part[1] == 'X'))
                    {
                        hex_part = hex_part.substr(2);
                        if (hex_part.empty())
                        {
                            continue;
                        }
                    }

                    if (hex_part.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                    {
                        continue;
                    }

                    try
                    {
                        unsigned long code_ul = std::stoul(hex_part, nullptr, 16);
                        current_value.push_back(static_cast<int>(code_ul));
                    }
                    catch (const std::exception &)
                    {
                        // Skip invalid tokens
                    }
                }
            }
        }
        // else: keep default_value which was set in constructor

        if (setter)
        {
            setter(current_value);
        }
    }

    template <>
    void CallbackConfigItem<std::vector<int>>::log_current_value(Logger &logger) const
    {
        logger.info("Config: {} ({}.{}) = {}", log_key_name, section, ini_key, format_vkcode_list(current_value));
    }

    // --- Legacy: Reference-based ConfigItem for backward compatibility ---

    template <typename T>
    struct RefConfigItem : public ConfigItemBase
    {
        T &target_variable; // Reference to the user's variable where the value will be stored
        T default_value;

        RefConfigItem(std::string sec, std::string key, std::string log_name, T &target, T def_val)
            : ConfigItemBase(std::move(sec), std::move(key), std::move(log_name)),
              target_variable(target), default_value(std::move(def_val))
        {
            // Initialize with default value. If INI loading fails or key is missing, this remains.
            target_variable = default_value;
        }

        void load(CSimpleIniA &ini, Logger &logger) override
        {
            // Delegate to callback version by creating a temporary setter
            auto temp_setter = [this](T val)
            { this->target_variable = val; };
            CallbackConfigItem<T> temp_item(section, ini_key, log_key_name, temp_setter, default_value);
            temp_item.load(ini, logger);
            target_variable = temp_item.current_value;
        }

        void log_current_value(Logger &logger) const override
        {
            CallbackConfigItem<T> temp_item(section, ini_key, log_key_name, nullptr, default_value);
            temp_item.current_value = target_variable;
            temp_item.log_current_value(logger);
        }
    };

    // --- Global storage for registered configuration items ---
    std::mutex &getConfigMutex()
    {
        static std::mutex mtx;
        return mtx;
    }

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
    std::string getIniFilePath(const std::string &ini_filename, Logger &logger)
    {
        std::string module_dir = getRuntimeDirectory();

        if (module_dir.empty() || module_dir == ".")
        {
            logger.warning("Config: Could not reliably determine module directory or it's current working directory. Using relative path for INI: {}", ini_filename);
            return ini_filename; // Fallback to relative path
        }

        try
        {
            std::filesystem::path ini_path_obj = std::filesystem::path(module_dir) / ini_filename;
            std::string full_path = ini_path_obj.lexically_normal().string(); // Normalize (e.g., C:/path/./file -> C:/path/file)
            logger.debug("Config: Determined INI file path: {}", full_path);
            return full_path;
        }
        catch (const std::filesystem::filesystem_error &fs_err)
        {
            logger.warning("Config: Filesystem error constructing INI path: {}. Using relative path for INI: {}", fs_err.what(), ini_filename);
        }
        catch (const std::exception &e) // Catch other potential exceptions
        {
            logger.warning("Config: General error constructing INI path: {}. Using relative path for INI: {}", e.what(), ini_filename);
        }
        return ini_filename; // Fallback
    }

} // anonymous namespace

// ============================================================================
// NEW API: Callback-based registration
// ============================================================================

void DetourModKit::Config::registerIntCallback(const std::string &section, const std::string &ini_key,
                                               const std::string &log_key_name, std::function<void(int)> setter,
                                               int default_value)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<CallbackConfigItem<int>>(section, ini_key, log_key_name, std::move(setter), default_value));
}

void DetourModKit::Config::registerFloatCallback(const std::string &section, const std::string &ini_key,
                                                 const std::string &log_key_name, std::function<void(float)> setter,
                                                 float default_value)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<CallbackConfigItem<float>>(section, ini_key, log_key_name, std::move(setter), default_value));
}

void DetourModKit::Config::registerBoolCallback(const std::string &section, const std::string &ini_key,
                                                const std::string &log_key_name, std::function<void(bool)> setter,
                                                bool default_value)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<CallbackConfigItem<bool>>(section, ini_key, log_key_name, std::move(setter), default_value));
}

void DetourModKit::Config::registerStringCallback(const std::string &section, const std::string &ini_key,
                                                  const std::string &log_key_name, std::function<void(const std::string &)> setter,
                                                  std::string default_value)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<CallbackConfigItem<std::string>>(section, ini_key, log_key_name, std::move(setter), std::move(default_value)));
}

void DetourModKit::Config::registerKeyListCallback(const std::string &section, const std::string &ini_key,
                                                   const std::string &log_key_name, std::function<void(const std::vector<int> &)> setter,
                                                   const std::string &default_value_str)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    // Parse the default_value_str into a vector<int>
    std::vector<int> default_keys_vector;
    std::string str_no_comment = default_value_str;
    size_t comment_pos = str_no_comment.find(';');
    if (comment_pos != std::string::npos)
    {
        str_no_comment = str_no_comment.substr(0, comment_pos);
    }
    std::string trimmed_val = trim(str_no_comment);

    if (!trimmed_val.empty())
    {
        std::istringstream iss(trimmed_val);
        std::string token;
        while (std::getline(iss, token, ','))
        {
            std::string trimmed_token = trim(token);
            if (trimmed_token.empty())
                continue;

            std::string hex_part = trimmed_token;
            if (hex_part.size() >= 2 && hex_part[0] == '0' && (hex_part[1] == 'x' || hex_part[1] == 'X'))
            {
                hex_part = hex_part.substr(2);
                if (hex_part.empty())
                    continue;
            }

            if (hex_part.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                continue;

            try
            {
                unsigned long code_ul = std::stoul(hex_part, nullptr, 16);
                default_keys_vector.push_back(static_cast<int>(code_ul));
            }
            catch (const std::exception &)
            {
                // Skip invalid
            }
        }
    }

    getRegisteredConfigItems().push_back(
        std::make_unique<CallbackConfigItem<std::vector<int>>>(section, ini_key, log_key_name, std::move(setter), default_keys_vector));
}

// ============================================================================
// LEGACY API: Reference-based registration (deprecated)
// ============================================================================

void DetourModKit::Config::registerInt(const std::string &section, const std::string &ini_key,
                                       const std::string &log_key_name, int &target_variable, int default_value)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<RefConfigItem<int>>(section, ini_key, log_key_name, target_variable, default_value));
}

void DetourModKit::Config::registerFloat(const std::string &section, const std::string &ini_key,
                                         const std::string &log_key_name, float &target_variable, float default_value)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<RefConfigItem<float>>(section, ini_key, log_key_name, target_variable, default_value));
}

void DetourModKit::Config::registerBool(const std::string &section, const std::string &ini_key,
                                        const std::string &log_key_name, bool &target_variable, bool default_value)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<RefConfigItem<bool>>(section, ini_key, log_key_name, target_variable, default_value));
}

void DetourModKit::Config::registerString(const std::string &section, const std::string &ini_key,
                                          const std::string &log_key_name, std::string &target_variable,
                                          const std::string &default_value)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<RefConfigItem<std::string>>(section, ini_key, log_key_name, target_variable, default_value));
}

void DetourModKit::Config::registerKeyList(const std::string &section, const std::string &ini_key,
                                           const std::string &log_key_name, std::vector<int> &target_variable,
                                           const std::string &default_value_str)
{
    // Parse the default_value_str into a vector<int> first
    std::vector<int> default_keys_vector;
    std::string str_no_comment = default_value_str;
    size_t comment_pos = str_no_comment.find(';');
    if (comment_pos != std::string::npos)
    {
        str_no_comment = str_no_comment.substr(0, comment_pos);
    }
    std::string trimmed_val = trim(str_no_comment);

    if (!trimmed_val.empty())
    {
        std::istringstream iss(trimmed_val);
        std::string token;
        while (std::getline(iss, token, ','))
        {
            std::string trimmed_token = trim(token);
            if (trimmed_token.empty())
                continue;

            std::string hex_part = trimmed_token;
            if (hex_part.size() >= 2 && hex_part[0] == '0' && (hex_part[1] == 'x' || hex_part[1] == 'X'))
            {
                hex_part = hex_part.substr(2);
                if (hex_part.empty())
                    continue;
            }

            if (hex_part.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                continue;

            try
            {
                unsigned long code_ul = std::stoul(hex_part, nullptr, 16);
                default_keys_vector.push_back(static_cast<int>(code_ul));
            }
            catch (const std::exception &)
            {
                // Skip invalid
            }
        }
    }

    std::lock_guard<std::mutex> lock(getConfigMutex());
    getRegisteredConfigItems().push_back(
        std::make_unique<RefConfigItem<std::vector<int>>>(section, ini_key, log_key_name, target_variable, default_keys_vector));
}

// ============================================================================
// Public API for Loading and Logging Configuration
// ============================================================================

void DetourModKit::Config::load(const std::string &ini_filename)
{
    std::lock_guard<std::mutex> lock(getConfigMutex());

    Logger &logger = Logger::getInstance();
    std::string ini_path = getIniFilePath(ini_filename, logger);
    logger.info("Config: Attempting to load configuration from: {}", ini_path);

    CSimpleIniA ini;
    ini.SetUnicode(false);  // Assume ASCII/MBCS INI
    ini.SetMultiKey(false); // Disallow duplicate keys in a section

    SI_Error rc = ini.LoadFile(ini_path.c_str());
    if (rc < 0)
    {
        logger.error("Config: Failed to open INI file '{}'. Error code: {}. Using default values for all registered settings.", ini_path, rc);
    }
    else
    {
        logger.info("Config: Successfully opened INI file: {}", ini_path);
    }

    // Load all registered items.
    for (const auto &item : getRegisteredConfigItems())
    {
        item->load(ini, logger);
    }

    logger.info("Config: Configuration loading complete. {} items processed.", getRegisteredConfigItems().size());
}

void DetourModKit::Config::logAll()
{
    std::lock_guard<std::mutex> lock(getConfigMutex());

    Logger &logger = Logger::getInstance();
    if (getRegisteredConfigItems().empty())
    {
        logger.info("Config: No configuration items registered to log.");
        return;
    }

    logger.info("Config: Logging {} registered configuration values:", getRegisteredConfigItems().size());
    for (const auto &item : getRegisteredConfigItems())
    {
        item->log_current_value(logger);
    }
    logger.info("Config: Configuration logging completed.");
}

void DetourModKit::Config::clearRegisteredItems()
{
    std::lock_guard<std::mutex> lock(getConfigMutex());

    Logger &logger = Logger::getInstance();
    size_t count = getRegisteredConfigItems().size();
    if (count > 0)
    {
        getRegisteredConfigItems().clear();
        logger.debug("Config: Cleared {} registered configuration items.", count);
    }
    else
    {
        logger.debug("Config: clearRegisteredItems called, but no items were registered.");
    }
}
