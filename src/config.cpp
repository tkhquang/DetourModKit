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
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/format.hpp"
#include "SimpleIni.h"

#include <windows.h>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

using namespace DetourModKit;
using namespace DetourModKit::Filesystem;
using namespace DetourModKit::String;

// Anonymous namespace for internal helpers and storage
namespace
{
    /**
     * @brief Parses a comma-separated string of input tokens into a vector of InputCodes.
     * @details Each token is first matched against the named key table (case-insensitive).
     *          If no name matches, the token is parsed as a hexadecimal VK code (with or
     *          without 0x prefix), defaulting to InputSource::Keyboard. Handles inline
     *          semicolon comments, whitespace, and gracefully skips invalid tokens.
     * @param input The raw string to parse.
     * @return std::vector<InputCode> Parsed valid input codes.
     */
    std::vector<InputCode> parse_input_code_list(const std::string &input)
    {
        std::vector<InputCode> result;

        // Strip trailing comment from the full line
        const size_t comment_pos = input.find(';');
        const std::string effective = trim(
            (comment_pos != std::string::npos) ? input.substr(0, comment_pos) : input);
        if (effective.empty())
        {
            return result;
        }

        // Walk comma-delimited tokens without istringstream overhead
        size_t pos = 0;
        while (pos < effective.size())
        {
            const size_t comma = effective.find(',', pos);
            const size_t end = (comma != std::string::npos) ? comma : effective.size();
            const std::string token = trim(effective.substr(pos, end - pos));
            pos = end + 1;

            if (token.empty())
            {
                continue;
            }

            // Try named key lookup first (case-insensitive)
            auto named = parse_input_name(token);
            if (named.has_value())
            {
                result.push_back(*named);
                continue;
            }

            // Fall back to hex parsing (defaults to Keyboard source)
            size_t hex_start = 0;
            if (token.size() >= 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
            {
                hex_start = 2;
            }
            if (hex_start >= token.size())
            {
                continue;
            }

            // Validate all remaining characters are hex digits
            const std::string_view hex_part(token.data() + hex_start, token.size() - hex_start);
            if (hex_part.find_first_not_of("0123456789abcdefABCDEF") != std::string_view::npos)
            {
                continue;
            }

            // Convert via strtoul — no exception overhead on invalid input
            errno = 0;
            char *end_ptr = nullptr;
            const unsigned long value = std::strtoul(token.c_str() + hex_start, &end_ptr, 16);
            if (end_ptr == token.c_str() + hex_start || errno == ERANGE)
            {
                continue;
            }
            if (value > static_cast<unsigned long>(std::numeric_limits<int>::max()))
            {
                continue;
            }

            result.push_back(InputCode{InputSource::Keyboard, static_cast<int>(value)});
        }

        return result;
    }

    /**
     * @brief Parses a single key combo string into a KeyCombo struct.
     * @details Format: "modifier1+modifier2+trigger_key" where each token is a
     *          named key or hex VK code. The last '+'-delimited token is the trigger
     *          key, all preceding tokens are modifier keys (AND logic). This function
     *          expects a single combo with no commas; use parse_key_combo_list to
     *          split comma-separated alternatives first.
     * @param input The raw string to parse (no commas expected).
     * @return Config::KeyCombo Parsed key combination.
     */
    Config::KeyCombo parse_key_combo(const std::string &input)
    {
        Config::KeyCombo result;

        const std::string effective = trim(input);
        if (effective.empty())
        {
            return result;
        }

        // Split by '+' to get segments
        std::vector<std::string> segments;
        size_t pos = 0;
        while (pos < effective.size())
        {
            const size_t plus = effective.find('+', pos);
            const size_t end = (plus != std::string::npos) ? plus : effective.size();
            const std::string segment = trim(effective.substr(pos, end - pos));
            pos = end + 1;
            if (!segment.empty())
            {
                segments.push_back(segment);
            }
        }

        if (segments.empty())
        {
            return result;
        }

        // Last segment is the trigger key
        result.keys = parse_input_code_list(segments.back());

        // All preceding segments are individual modifier keys
        for (size_t i = 0; i + 1 < segments.size(); ++i)
        {
            auto mod_codes = parse_input_code_list(segments[i]);
            result.modifiers.insert(result.modifiers.end(), mod_codes.begin(), mod_codes.end());
        }

        return result;
    }

    /**
     * @brief Parses a comma-separated string of key combos into a KeyComboList.
     * @details Commas at the top level separate independent combos (OR logic between
     *          combos). Each combo is parsed by parse_key_combo. Handles inline
     *          semicolon comments, whitespace, and gracefully skips empty/invalid combos.
     * @param input The raw string to parse.
     * @return Config::KeyComboList Parsed list of key combinations.
     */
    Config::KeyComboList parse_key_combo_list(const std::string &input)
    {
        Config::KeyComboList result;

        // Strip trailing comment from the full line
        const size_t comment_pos = input.find(';');
        const std::string effective = trim(
            (comment_pos != std::string::npos) ? input.substr(0, comment_pos) : input);
        if (effective.empty())
        {
            return result;
        }

        // Split by comma into independent combo strings
        size_t pos = 0;
        while (pos < effective.size())
        {
            const size_t comma = effective.find(',', pos);
            const size_t end = (comma != std::string::npos) ? comma : effective.size();
            const std::string combo_str = trim(effective.substr(pos, end - pos));
            pos = end + 1;

            if (combo_str.empty())
            {
                continue;
            }

            auto combo = parse_key_combo(combo_str);
            if (!combo.keys.empty())
            {
                result.push_back(std::move(combo));
            }
        }

        return result;
    }

    /**
     * @brief Formats a single KeyCombo as a human-readable string.
     * @details Uses named keys where available, falls back to hex for unknown codes.
     * @param combo The key combination to format.
     * @return std::string Formatted string (e.g., "Ctrl+Shift+F3").
     */
    std::string format_key_combo(const Config::KeyCombo &combo)
    {
        std::string result;
        for (const auto &mod : combo.modifiers)
        {
            result += DetourModKit::format_input_code(mod) + "+";
        }
        for (size_t i = 0; i < combo.keys.size(); ++i)
        {
            if (i > 0)
            {
                result += ",";
            }
            result += DetourModKit::format_input_code(combo.keys[i]);
        }
        return result;
    }

    /**
     * @brief Formats a KeyComboList as a human-readable string.
     * @details Joins individual combos with commas.
     * @param combos The list of key combinations to format.
     * @return std::string Formatted string (e.g., "F3,Gamepad_LT+Gamepad_B").
     */
    std::string format_key_combo_list(const Config::KeyComboList &combos)
    {
        std::string result;
        for (size_t i = 0; i < combos.size(); ++i)
        {
            if (i > 0)
            {
                result += ",";
            }
            result += format_key_combo(combos[i]);
        }
        return result;
    }

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
        ConfigItemBase(const ConfigItemBase &) = delete;
        ConfigItemBase &operator=(const ConfigItemBase &) = delete;
        ConfigItemBase(ConfigItemBase &&) = delete;
        ConfigItemBase &operator=(ConfigItemBase &&) = delete;

        /**
         * @brief Loads the configuration value from the INI file.
         * @param ini Reference to the CSimpleIniA object.
         * @param logger Reference to the Logger object.
         */
        virtual void load(CSimpleIniA &ini, Logger &logger) = 0;

        /**
         * @brief Returns a deferred callback to invoke the setter outside the config mutex.
         * @return A self-contained callable, or empty if no setter is configured.
         */
        [[nodiscard]] virtual std::function<void()> take_deferred_apply() const = 0;

        /**
         * @brief Logs the current value of the configuration item.
         * @param logger Reference to the Logger object.
         */
        virtual void log_current_value(Logger &logger) const = 0;
    };

    /**
     * @brief Configuration item using std::function callback for value setting.
     * @tparam T The data type of the configuration item (e.g., int, bool, std::string).
     * @note Setter callbacks are invoked outside the config mutex to prevent deadlocks.
     *       See register_* and load() for the deferred invocation pattern.
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
              default_value(def_val),
              current_value(std::move(def_val))
        {
        }

        void load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger) override;
        void log_current_value(Logger &logger) const override;

        /// Returns a self-contained callback that invokes setter with current_value.
        [[nodiscard]] std::function<void()> take_deferred_apply() const override
        {
            if (!setter)
                return {};
            return [fn = setter, val = current_value]() mutable
            { fn(std::move(val)); };
        }
    };

    // --- Specializations for CallbackConfigItem<T>::load and ::log_current_value ---

    // For int
    template <>
    void CallbackConfigItem<int>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        current_value = static_cast<int>(ini.GetLongValue(section.c_str(), ini_key.c_str(), default_value));
    }

    template <>
    void CallbackConfigItem<int>::log_current_value(Logger &logger) const
    {
        logger.debug("Config:   {} = {}", ini_key, current_value);
    }

    // For float
    template <>
    void CallbackConfigItem<float>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        current_value = static_cast<float>(ini.GetDoubleValue(section.c_str(), ini_key.c_str(), static_cast<double>(default_value)));
    }

    template <>
    void CallbackConfigItem<float>::log_current_value(Logger &logger) const
    {
        logger.debug("Config:   {} = {}", ini_key, current_value);
    }

    // For bool
    template <>
    void CallbackConfigItem<bool>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        current_value = ini.GetBoolValue(section.c_str(), ini_key.c_str(), default_value);
    }

    template <>
    void CallbackConfigItem<bool>::log_current_value(Logger &logger) const
    {
        logger.debug("Config:   {} = {}", ini_key, current_value ? "true" : "false");
    }

    // For std::string
    template <>
    void CallbackConfigItem<std::string>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        current_value = ini.GetValue(section.c_str(), ini_key.c_str(), default_value.c_str());
    }

    template <>
    void CallbackConfigItem<std::string>::log_current_value(Logger &logger) const
    {
        logger.debug("Config:   {} = \"{}\"", ini_key, current_value);
    }

    // For Config::KeyComboList (list of key combinations)
    template <>
    void CallbackConfigItem<Config::KeyComboList>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
    {
        const char *ini_value_str = ini.GetValue(section.c_str(), ini_key.c_str(), nullptr);
        if (ini_value_str != nullptr)
        {
            current_value = parse_key_combo_list(ini_value_str);
        }
        else
        {
            current_value = default_value;
        }
    }

    template <>
    void CallbackConfigItem<Config::KeyComboList>::log_current_value(Logger &logger) const
    {
        const std::string formatted = format_key_combo_list(current_value);
        if (formatted.empty())
        {
            logger.debug("Config:   {} = (none)", ini_key);
        }
        else
        {
            logger.debug("Config:   {} = {}", ini_key, formatted);
        }
    }

    // --- Global storage for registered configuration items ---
    std::mutex &getConfigMutex()
    {
        static std::mutex mtx;
        return mtx;
    }

    std::vector<std::unique_ptr<ConfigItemBase>> &getRegisteredConfigItems()
    {
        // Function-local static to ensure controlled initialization order.
        static std::vector<std::unique_ptr<ConfigItemBase>> s_registered_items;
        return s_registered_items;
    }

    /// Replaces an existing item with the same section+key, or appends if none found.
    /// Caller must hold getConfigMutex().
    void replace_or_append(std::unique_ptr<ConfigItemBase> item)
    {
        auto &items = getRegisteredConfigItems();
        for (auto &existing : items)
        {
            if (existing->section == item->section && existing->ini_key == item->ini_key)
            {
                existing = std::move(item);
                return;
            }
        }
        items.push_back(std::move(item));
    }

    /**
     * @brief Determines the full absolute path for the INI configuration file.
     */
    std::string getIniFilePath(const std::string &ini_filename, Logger &logger)
    {
        std::string module_dir = get_runtime_directory();

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

void DetourModKit::Config::register_int(const std::string &section, const std::string &ini_key,
                                               const std::string &log_key_name, std::function<void(int)> setter,
                                               int default_value)
{
    if (setter)
    {
        setter(default_value);
    }
    std::lock_guard<std::mutex> lock(getConfigMutex());
    replace_or_append(
        std::make_unique<CallbackConfigItem<int>>(section, ini_key, log_key_name, std::move(setter), default_value));
}

void DetourModKit::Config::register_float(const std::string &section, const std::string &ini_key,
                                                 const std::string &log_key_name, std::function<void(float)> setter,
                                                 float default_value)
{
    if (setter)
    {
        setter(default_value);
    }
    std::lock_guard<std::mutex> lock(getConfigMutex());
    replace_or_append(
        std::make_unique<CallbackConfigItem<float>>(section, ini_key, log_key_name, std::move(setter), default_value));
}

void DetourModKit::Config::register_bool(const std::string &section, const std::string &ini_key,
                                                const std::string &log_key_name, std::function<void(bool)> setter,
                                                bool default_value)
{
    if (setter)
    {
        setter(default_value);
    }
    std::lock_guard<std::mutex> lock(getConfigMutex());
    replace_or_append(
        std::make_unique<CallbackConfigItem<bool>>(section, ini_key, log_key_name, std::move(setter), default_value));
}

void DetourModKit::Config::register_string(const std::string &section, const std::string &ini_key,
                                                  const std::string &log_key_name, std::function<void(const std::string &)> setter,
                                                  std::string default_value)
{
    if (setter)
    {
        setter(default_value);
    }
    std::lock_guard<std::mutex> lock(getConfigMutex());
    replace_or_append(
        std::make_unique<CallbackConfigItem<std::string>>(section, ini_key, log_key_name, std::move(setter), std::move(default_value)));
}

void DetourModKit::Config::register_key_combo(const std::string &section, const std::string &ini_key,
                                                      const std::string &log_key_name, std::function<void(const KeyComboList &)> setter,
                                                      const std::string &default_value_str)
{
    Config::KeyComboList default_combos = parse_key_combo_list(default_value_str);

    if (setter)
    {
        setter(default_combos);
    }
    std::lock_guard<std::mutex> lock(getConfigMutex());
    replace_or_append(
        std::make_unique<CallbackConfigItem<Config::KeyComboList>>(section, ini_key, log_key_name, std::move(setter), std::move(default_combos)));
}

void DetourModKit::Config::load(const std::string &ini_filename)
{
    std::vector<std::function<void()>> deferred_callbacks;

    {
        std::lock_guard<std::mutex> lock(getConfigMutex());

        Logger &logger = Logger::get_instance();
        std::string ini_path = getIniFilePath(ini_filename, logger);
        CSimpleIniA ini;
        ini.SetUnicode(false);  // Assume ASCII/MBCS INI
        ini.SetMultiKey(false); // Disallow duplicate keys in a section

        SI_Error rc = ini.LoadFile(ini_path.c_str());
        if (rc < 0)
        {
            logger.error("Config: Failed to open '{}' (error {}). Using defaults.", ini_path, rc);
        }
        else
        {
            logger.debug("Config: Opened {}", ini_path);
        }

        // Read all values under lock, but defer setter callbacks
        for (const auto &item : getRegisteredConfigItems())
        {
            item->load(ini, logger);
            auto cb = item->take_deferred_apply();
            if (cb)
            {
                deferred_callbacks.push_back(std::move(cb));
            }
        }

        logger.info("Config: Loaded {} items from {}", getRegisteredConfigItems().size(), ini_path);
    }

    // Invoke setter callbacks outside the config mutex to prevent deadlocks
    for (auto &cb : deferred_callbacks)
    {
        cb();
    }
}

void DetourModKit::Config::log_all()
{
    std::lock_guard<std::mutex> lock(getConfigMutex());

    Logger &logger = Logger::get_instance();
    const auto &items = getRegisteredConfigItems();
    if (items.empty())
    {
        logger.info("Config: No configuration items registered.");
        return;
    }

    logger.info("Config: {} registered values across {} section(s)",
                items.size(), [&items]()
                {
                    size_t sections = 0;
                    std::string prev;
                    for (const auto &item : items)
                    {
                        if (item->section != prev)
                        {
                            ++sections;
                            prev = item->section;
                        }
                    }
                    return sections;
                }());

    std::string current_section;
    for (const auto &item : items)
    {
        if (item->section != current_section)
        {
            current_section = item->section;
            logger.debug("Config: [{}]", current_section);
        }
        item->log_current_value(logger);
    }
}

void DetourModKit::Config::clear_registered_items()
{
    std::lock_guard<std::mutex> lock(getConfigMutex());

    Logger &logger = Logger::get_instance();
    size_t count = getRegisteredConfigItems().size();
    if (count > 0)
    {
        getRegisteredConfigItems().clear();
        logger.debug("Config: Cleared {} registered configuration items.", count);
    }
    else
    {
        logger.debug("Config: clear_registered_items called, but no items were registered.");
    }
}
