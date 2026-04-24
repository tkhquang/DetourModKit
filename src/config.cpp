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
#include "DetourModKit/config_watcher.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/worker.hpp"
#include "SimpleIni.h"

#include <atomic>
#include <memory>

#include <windows.h>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
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

    // Holds the INI path last passed to Config::load(). Empty until the
    // first load() call -- reload() returns false in that window.
    // Caller must hold getConfigMutex() when reading or writing.
    std::string &getLastLoadedIniPath()
    {
        static std::string s_last_loaded_ini_path;
        return s_last_loaded_ini_path;
    }

    // Content hash of the bytes last successfully loaded from the INI file.
    // std::nullopt until the first successful load() (or after
    // clear_registered_items(), which wipes it alongside the path).
    // Caller must hold getConfigMutex() when reading or writing.
    std::optional<std::uint64_t> &getLastLoadedIniHash()
    {
        static std::optional<std::uint64_t> s_last_loaded_ini_hash;
        return s_last_loaded_ini_hash;
    }

    /**
     * @brief 64-bit FNV-1a hash over a raw byte range.
     * @details Computed on the disk bytes (pre-parse) so cosmetic churn by
     *          SimpleIni's own parser (comment stripping, whitespace
     *          normalisation) cannot skew the result. Produces a stable
     *          value on any platform without pulling in a dependency.
     */
    [[nodiscard]] std::uint64_t fnv1a_64(const std::vector<std::uint8_t> &bytes) noexcept
    {
        constexpr std::uint64_t offset{0xcbf29ce484222325ULL};
        constexpr std::uint64_t prime{0x00000100000001b3ULL};
        std::uint64_t h{offset};
        for (std::uint8_t b : bytes)
        {
            h ^= static_cast<std::uint64_t>(b);
            h *= prime;
        }
        return h;
    }

    /**
     * @brief Reads all bytes of @p path into memory.
     * @details Returns std::nullopt when the file cannot be opened (e.g.
     *          mid-save by an editor that locks exclusively). Callers
     *          should treat a nullopt return as "unable to verify
     *          content; proceed with a full reload" -- erring on the
     *          side of reloading is safer than skipping a real change.
     */
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    read_ini_bytes(const std::filesystem::path &path) noexcept
    {
        try
        {
            std::ifstream in(path, std::ios::binary);
            if (!in)
            {
                return std::nullopt;
            }
            in.seekg(0, std::ios::end);
            const std::streamsize size = in.tellg();
            in.seekg(0, std::ios::beg);
            if (size <= 0)
            {
                return std::vector<std::uint8_t>{};
            }
            std::vector<std::uint8_t> buf(static_cast<std::size_t>(size));
            in.read(reinterpret_cast<char *>(buf.data()), size);
            if (!in && !in.eof())
            {
                return std::nullopt;
            }
            buf.resize(static_cast<std::size_t>(in.gcount()));
            return buf;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    /**
     * @brief Result of read-hash-parse pipeline used by load() and reload().
     */
    struct IniLoadOutcome
    {
        bool read_succeeded{false};   ///< Bytes successfully read from disk
        bool parse_succeeded{false};  ///< CSimpleIniA::LoadData returned SI_OK
        SI_Error parse_rc{SI_OK};     ///< Raw SimpleIni return code (when read_succeeded)
        std::optional<std::uint64_t> hash; ///< FNV-1a hash of the read bytes
    };

    /**
     * @brief Reads the INI bytes once, computes their hash, and feeds
     *        those exact bytes to CSimpleIniA::LoadData.
     * @details Closes the TOCTOU window where LoadFile would re-read the
     *          file after our byte snapshot: if the file was rewritten
     *          between the two reads, the cached hash would reflect one
     *          version and the parsed INI another. By using LoadData on
     *          the already-buffered bytes, the hash and the parse are
     *          guaranteed to reflect the same file state.
     * @param path Absolute path to the INI file.
     * @param ini  SimpleIni instance to populate.
     * @return IniLoadOutcome describing each pipeline stage.
     */
    [[nodiscard]] IniLoadOutcome
    load_ini_into(const std::filesystem::path &path, CSimpleIniA &ini) noexcept
    {
        IniLoadOutcome outcome{};
        auto bytes = read_ini_bytes(path);
        if (!bytes.has_value())
        {
            return outcome;
        }
        outcome.read_succeeded = true;
        outcome.hash = fnv1a_64(*bytes);

        // CSimpleIniA::LoadData(const char*, size_t). Empty buffers are
        // accepted by SimpleIni (SI_OK, zero sections) -- we still
        // preserve the hash so an empty file can be content-hash-skipped.
        try
        {
            const char *data_ptr = bytes->empty()
                                       ? ""
                                       : reinterpret_cast<const char *>(bytes->data());
            outcome.parse_rc = ini.LoadData(data_ptr, bytes->size());
            outcome.parse_succeeded = (outcome.parse_rc >= 0);
        }
        catch (...)
        {
            outcome.parse_rc = SI_FAIL;
            outcome.parse_succeeded = false;
        }
        return outcome;
    }

    // Filesystem watcher owned by enable_auto_reload().  Separate mutex so
    // start / stop transitions do not contend with registration traffic.
    std::mutex &getWatcherMutex()
    {
        static std::mutex mtx;
        return mtx;
    }

    std::unique_ptr<ConfigWatcher> &getConfigWatcher()
    {
        static std::unique_ptr<ConfigWatcher> s_watcher;
        return s_watcher;
    }

    // Keeps reload-hotkey InputBindingGuards alive for the process lifetime.
    // Returning the guard by value from register_reload_hotkey would
    // immediately destroy it (the call site has nowhere to store it), and
    // ~InputBindingGuard flips the binding's enabled flag to false, so the
    // press callback would silently no-op forever. Protected by
    // getWatcherMutex() because it already serialises lifetime state that
    // lives alongside the watcher (both are Config-wide, not per-item).
    std::vector<DetourModKit::Config::InputBindingGuard> &getReloadHotkeyGuards() noexcept
    {
        static std::vector<DetourModKit::Config::InputBindingGuard> s_guards;
        return s_guards;
    }

    /**
     * @class ReloadServicer
     * @brief Background thread that coalesces reload-hotkey presses and
     *        invokes Config::reload() off the InputManager poll thread.
     * @details The hotkey press callback must return in microseconds so
     *          other hotkeys do not jitter while a 30-item INI parse runs.
     *          The servicer latches a pending-reload flag; its worker
     *          thread blocks on a condition variable, drains the flag on
     *          wake, and invokes reload() at most once per batch of
     *          presses. Exceptions from reload() are caught so the
     *          servicer never dies.
     *
     *          Lazy lifetime: created on the first register_reload_hotkey
     *          call, kept alive until clear_registered_items() tears it
     *          down. Shared via std::shared_ptr so a press callback that
     *          races with shutdown cannot dereference a freed channel.
     */
    class ReloadServicer
    {
    public:
        ReloadServicer()
        {
            // Launch the servicer worker. StoppableWorker passes its
            // own stop_token into the body; we observe it via
            // stop_requested() inside the wait predicate. To make
            // request_stop() wake a currently blocked cv.wait, we
            // install a stop_callback on the body's token (captured
            // inside service_loop) that flips m_shutdown and notifies
            // the CV.
            m_worker = std::make_unique<DetourModKit::StoppableWorker>(
                "ConfigReloadServicer",
                [this](std::stop_token st)
                {
                    service_loop(std::move(st));
                });
        }

        ~ReloadServicer() noexcept
        {
            // Flip the shutdown flag and wake the worker before the
            // StoppableWorker destructor asks it to stop + join.
            // notify_all() is harmless if the worker already exited.
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_shutdown.store(true, std::memory_order_release);
            }
            m_cv.notify_all();

            // ~StoppableWorker requests stop + joins (or detaches under
            // loader lock). Safe to let it run as-is.
            m_worker.reset();
        }

        ReloadServicer(const ReloadServicer &) = delete;
        ReloadServicer &operator=(const ReloadServicer &) = delete;
        ReloadServicer(ReloadServicer &&) = delete;
        ReloadServicer &operator=(ReloadServicer &&) = delete;

        /**
         * @brief Requests a reload. noexcept and allocation-free on the
         *        fast path; the press callback uses this and must not
         *        throw back onto the InputManager poll thread.
         */
        void request_reload() noexcept
        {
            // The predicate variable m_reload_requested must be mutated
            // under m_mutex (or at minimum the notifier must take the
            // mutex before notify_one) to close the lost-wakeup window
            // on the waiter side: waiter evaluates the predicate false
            // (pre-lock), then parks; if we stored + notified in that
            // gap without touching the mutex, the press could be
            // dropped until the next one. Taking the mutex here serialises
            // against the waiter's predicate re-check under m_mutex,
            // making the wakeup observation guaranteed.
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_reload_requested.store(true, std::memory_order_release);
            }
            m_cv.notify_one();
        }

    private:
        void service_loop(std::stop_token st) noexcept
        {
            DetourModKit::Logger &logger = DetourModKit::Logger::get_instance();

            // Wake the CV when the worker is asked to stop so the blocked
            // wait exits promptly instead of waiting for the next press.
            std::stop_callback stop_cb(
                st,
                [this]() -> void
                {
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        m_shutdown.store(true, std::memory_order_release);
                    }
                    m_cv.notify_all();
                });

            while (!st.stop_requested() &&
                   !m_shutdown.load(std::memory_order_acquire))
            {
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_cv.wait(lock, [&]()
                              {
                                  return st.stop_requested() ||
                                         m_shutdown.load(std::memory_order_acquire) ||
                                         m_reload_requested.load(std::memory_order_acquire);
                              });
                }

                if (st.stop_requested() ||
                    m_shutdown.load(std::memory_order_acquire))
                {
                    break;
                }

                // Coalesce: a burst of presses during the reload below
                // collapses into at most one follow-up pass because the
                // next iteration will exchange the flag once.
                while (m_reload_requested.exchange(false, std::memory_order_acq_rel))
                {
                    try
                    {
                        (void)DetourModKit::Config::reload();
                    }
                    catch (const std::exception &e)
                    {
                        logger.error(
                            "Config: reload servicer caught exception: {}", e.what());
                    }
                    catch (...)
                    {
                        logger.error(
                            "Config: reload servicer caught unknown exception.");
                    }
                }
            }
        }

        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic<bool> m_reload_requested{false};
        std::atomic<bool> m_shutdown{false};
        std::unique_ptr<DetourModKit::StoppableWorker> m_worker;
    };

    // Shared_ptr so a press callback holding its own strong reference
    // cannot crash when clear_registered_items() resets the slot.
    std::shared_ptr<ReloadServicer> &getReloadServicer() noexcept
    {
        static std::shared_ptr<ReloadServicer> s_servicer;
        return s_servicer;
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
    std::filesystem::path getIniFilePath(const std::string &ini_filename, Logger &logger)
    {
        std::wstring module_dir = get_runtime_directory();

        if (module_dir.empty() || module_dir == L".")
        {
            logger.warning("Config: Could not reliably determine module directory or it's current working directory. Using relative path for INI: {}", ini_filename);
            return std::filesystem::path(ini_filename); // Fallback to relative path
        }

        try
        {
            std::filesystem::path ini_path_obj = (std::filesystem::path(module_dir) / ini_filename).lexically_normal();
            logger.debug("Config: Determined INI file path: {}", ini_path_obj.string());
            return ini_path_obj;
        }
        catch (const std::filesystem::filesystem_error &fs_err)
        {
            logger.warning("Config: Filesystem error constructing INI path: {}. Using relative path for INI: {}", fs_err.what(), ini_filename);
        }
        catch (const std::exception &e)
        {
            logger.warning("Config: General error constructing INI path: {}. Using relative path for INI: {}", e.what(), ini_filename);
        }
        return std::filesystem::path(ini_filename); // Fallback
    }

} // anonymous namespace

// All register_* functions use the deferred callback pattern: state is
// mutated under getConfigMutex(), but the setter callback is invoked after
// the lock is released.  This allows setters to call back into the Config
// API without deadlocking (no reentrancy guard needed).
void DetourModKit::Config::register_int(std::string_view section, std::string_view ini_key,
                                        std::string_view log_key_name, std::function<void(int)> setter,
                                        int default_value)
{
    std::function<void()> deferred;
    {
        std::lock_guard<std::mutex> lock(getConfigMutex());
        replace_or_append(
            std::make_unique<CallbackConfigItem<int>>(std::string(section), std::string(ini_key), std::string(log_key_name), setter, default_value));
        if (setter)
        {
            deferred = [setter, default_value]()
            { setter(default_value); };
        }
    }
    if (deferred)
    {
        deferred();
    }
}

void DetourModKit::Config::register_float(std::string_view section, std::string_view ini_key,
                                          std::string_view log_key_name, std::function<void(float)> setter,
                                          float default_value)
{
    std::function<void()> deferred;
    {
        std::lock_guard<std::mutex> lock(getConfigMutex());
        replace_or_append(
            std::make_unique<CallbackConfigItem<float>>(std::string(section), std::string(ini_key), std::string(log_key_name), setter, default_value));
        if (setter)
        {
            deferred = [setter, default_value]()
            { setter(default_value); };
        }
    }
    if (deferred)
    {
        deferred();
    }
}

void DetourModKit::Config::register_bool(std::string_view section, std::string_view ini_key,
                                         std::string_view log_key_name, std::function<void(bool)> setter,
                                         bool default_value)
{
    std::function<void()> deferred;
    {
        std::lock_guard<std::mutex> lock(getConfigMutex());
        replace_or_append(
            std::make_unique<CallbackConfigItem<bool>>(std::string(section), std::string(ini_key), std::string(log_key_name), setter, default_value));
        if (setter)
        {
            deferred = [setter, default_value]()
            { setter(default_value); };
        }
    }
    if (deferred)
    {
        deferred();
    }
}

void DetourModKit::Config::register_string(std::string_view section, std::string_view ini_key,
                                           std::string_view log_key_name, std::function<void(const std::string &)> setter,
                                           std::string default_value)
{
    std::function<void()> deferred;
    {
        std::lock_guard<std::mutex> lock(getConfigMutex());
        replace_or_append(
            std::make_unique<CallbackConfigItem<std::string>>(std::string(section), std::string(ini_key), std::string(log_key_name), setter, default_value));
        if (setter)
        {
            deferred = [setter, val = std::move(default_value)]()
            { setter(val); };
        }
    }
    if (deferred)
    {
        deferred();
    }
}

void DetourModKit::Config::register_key_combo(std::string_view section, std::string_view ini_key,
                                              std::string_view log_key_name, std::function<void(const KeyComboList &)> setter,
                                              std::string_view default_value_str)
{
    Config::KeyComboList default_combos = parse_key_combo_list(std::string(default_value_str));

    std::function<void()> deferred;
    {
        std::lock_guard<std::mutex> lock(getConfigMutex());
        replace_or_append(
            std::make_unique<CallbackConfigItem<Config::KeyComboList>>(std::string(section), std::string(ini_key), std::string(log_key_name), setter, default_combos));
        if (setter)
        {
            deferred = [setter, combos = std::move(default_combos)]()
            { setter(combos); };
        }
    }
    if (deferred)
    {
        deferred();
    }
}

DetourModKit::Config::InputBindingGuard DetourModKit::Config::register_press_combo(
    std::string_view section,
    std::string_view ini_key,
    std::string_view log_name,
    std::string_view input_binding_name,
    std::function<void()> on_press,
    std::string_view default_value)
{
    auto enabled_flag = std::make_shared<std::atomic<bool>>(true);
    auto current_combos = std::make_shared<KeyComboList>(parse_key_combo_list(std::string(default_value)));
    std::string binding_name_str(input_binding_name);

    register_key_combo(section, ini_key, log_name, [current_combos, binding_name_str](const KeyComboList &combos)
                       {
                           *current_combos = combos;
                           InputManager::get_instance().update_binding_combos(binding_name_str, combos); }, default_value);

    InputManager::get_instance().register_press(
        binding_name_str,
        *current_combos,
        [enabled_flag, cb = std::move(on_press)]()
        {
            if (cb && enabled_flag->load(std::memory_order_acquire))
            {
                cb();
            }
        });

    return InputBindingGuard{std::move(binding_name_str), std::move(enabled_flag)};
}

void DetourModKit::Config::load(std::string_view ini_filename)
{
    std::vector<std::function<void()>> deferred_callbacks;

    {
        std::lock_guard<std::mutex> lock(getConfigMutex());

        Logger &logger = Logger::get_instance();
        std::filesystem::path ini_path = getIniFilePath(std::string(ini_filename), logger);
        std::string ini_path_str = ini_path.string(); // convert to narrow string for logger formatting
        CSimpleIniA ini;
        ini.SetUnicode(false);  // Assume ASCII/MBCS INI
        ini.SetMultiKey(false); // Disallow duplicate keys in a section

        // Read-hash-parse pipeline: read bytes once, hash them, feed the
        // same buffer into CSimpleIniA::LoadData so the cached hash and
        // the parsed INI state are guaranteed to reflect identical file
        // contents (TOCTOU-free vs. a separate LoadFile call).
        IniLoadOutcome outcome = load_ini_into(ini_path, ini);

        const bool load_succeeded = outcome.read_succeeded && outcome.parse_succeeded;
        if (!outcome.read_succeeded)
        {
            logger.error("Config: Failed to open '{}'. Using defaults.", ini_path_str);
            // File unreadable: wipe the cached hash so the next reload()
            // does not short-circuit against a stale value.
            getLastLoadedIniHash().reset();
        }
        else if (!outcome.parse_succeeded)
        {
            logger.error("Config: Failed to parse '{}' (error {}). Using defaults.",
                         ini_path_str, static_cast<int>(outcome.parse_rc));
            // Parse failed: clear the hash so a subsequent successful
            // load() does not spuriously hash-skip a reload against a
            // hash computed for bytes we could not actually parse.
            getLastLoadedIniHash().reset();
        }
        else
        {
            logger.debug("Config: Opened {}", ini_path_str);
            getLastLoadedIniHash() = outcome.hash;
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

        // Remember the INI path so reload() can re-run setters against the
        // same file without the caller passing it again. Only update the
        // stored path on success; a failed load must leave the previously
        // remembered path (if any) untouched so subsequent reload() calls
        // keep targeting the last good file rather than a missing or
        // malformed one.
        if (load_succeeded)
        {
            getLastLoadedIniPath() = std::string(ini_filename);
        }

        logger.info("Config: Loaded {} items from {}", getRegisteredConfigItems().size(), ini_path_str);
    }

    // Invoke setter callbacks outside the config mutex -- same deferred
    // pattern as register_*().  Setters may safely call back into Config.
    for (auto &cb : deferred_callbacks)
    {
        cb();
    }
}

namespace
{
    /**
     * @brief Internal reload implementation that also reports whether
     *        setters actually ran.
     * @param[out] out_setters_ran Set to true when setters were invoked.
     *                             False when the content-hash short-circuit
     *                             skipped the reload.
     * @return true if a previous load() path was available and the reload
     *         proceeded; false if reload() was called before any load().
     */
    bool reload_impl(bool &out_setters_ran)
    {
        out_setters_ran = false;

        std::vector<std::function<void()>> deferred_callbacks;
        std::string ini_filename;

        {
            std::lock_guard<std::mutex> lock(getConfigMutex());

            ini_filename = getLastLoadedIniPath();
            if (ini_filename.empty())
            {
                // No prior load() -- nothing to reload. Caller is expected
                // to check the return value and either call load() first
                // or surface a user-facing error.
                return false;
            }

            DetourModKit::Logger &logger = DetourModKit::Logger::get_instance();
            std::filesystem::path ini_path = getIniFilePath(ini_filename, logger);
            std::string ini_path_str = ini_path.string();

            CSimpleIniA ini;
            ini.SetUnicode(false);
            ini.SetMultiKey(false);

            // Read-hash-parse pipeline: the hash we compare against the
            // cache and the bytes SimpleIni parses come from a single
            // read. Splitting the read (one for hashing, another via
            // LoadFile for parsing) would let an editor save slip
            // between them and desync the cached hash from the parsed
            // state.
            IniLoadOutcome outcome = load_ini_into(ini_path, ini);

            if (!outcome.read_succeeded)
            {
                // Read failure: clear the cached hash before falling
                // through to run setters with defaults. Leaving it in
                // place would let a later reload find identical bytes
                // (same as the last successful load), match the stale
                // hash, and hash-skip -- silently leaving in-memory
                // state at the defaults from this failed reload.
                getLastLoadedIniHash() = std::nullopt;
                logger.warning("Config: reload() could not open '{}'; retaining last values where setters keep state.",
                               ini_path_str);
            }
            else
            {
                // Content-hash skip: compare against the hash stored on
                // the last successful load()/reload(). Identical bytes
                // -> no setters. Uses the hash we just computed in the
                // pipeline; no second read.
                if (auto &cached_hash = getLastLoadedIniHash(); cached_hash.has_value())
                {
                    const std::uint64_t current_hash = *outcome.hash;
                    if (current_hash == *cached_hash)
                    {
                        logger.debug(
                            "Config::reload: content unchanged (hash {:016x}); skipping setters.",
                            current_hash);
                        return true;
                    }
                    // Content changed: remember the new hash so a
                    // subsequent no-op reload can short-circuit.
                    cached_hash = current_hash;
                }
                else
                {
                    // No cached hash (prior failure or never-loaded):
                    // adopt the current one so a subsequent no-op
                    // reload short-circuits.
                    getLastLoadedIniHash() = outcome.hash;
                }

                if (!outcome.parse_succeeded)
                {
                    // Asymmetry with the read-failure branch above is
                    // intentional: we have already advanced the cached
                    // hash to these new bytes, so a later reload with
                    // identical bytes correctly short-circuits -- the
                    // partial state produced by re-parsing would be the
                    // same. The read-failure branch cannot make that
                    // guarantee because it never observed the bytes.
                    logger.warning("Config: reload() parse error on '{}' (error {}); retaining last values where setters keep state.",
                                   ini_path_str, static_cast<int>(outcome.parse_rc));
                }
                else
                {
                    logger.debug("Config: Reloading from {}", ini_path_str);
                }
            }

            for (const auto &item : getRegisteredConfigItems())
            {
                item->load(ini, logger);
                auto cb = item->take_deferred_apply();
                if (cb)
                {
                    deferred_callbacks.push_back(std::move(cb));
                }
            }

            logger.info("Config: Reloaded {} items from {}",
                        getRegisteredConfigItems().size(), ini_path_str);
        }

        // The registry mutex is released by the scope above; setters run
        // unlocked (the standard deferred-setter pattern). Wrap each call
        // so a single throwing setter cannot prevent the remaining setters
        // from seeing the refreshed values. Logger::error() below is also
        // outside the config mutex -- a custom Logger sink that re-enters
        // Config cannot AB/BA deadlock here.
        DetourModKit::Logger &logger = DetourModKit::Logger::get_instance();
        for (auto &cb : deferred_callbacks)
        {
            try
            {
                cb();
            }
            catch (const std::exception &e)
            {
                logger.error("Config: reload setter threw: {}", e.what());
            }
            catch (...)
            {
                logger.error("Config: reload setter threw unknown exception.");
            }
        }
        out_setters_ran = true;
        return true;
    }
} // anonymous namespace

bool DetourModKit::Config::reload()
{
    bool ignored = false;
    return reload_impl(ignored);
}

DetourModKit::Config::AutoReloadStatus DetourModKit::Config::enable_auto_reload(
    std::chrono::milliseconds debounce_window,
    std::function<void(bool)> on_reload)
{
    std::string ini_filename;
    {
        std::lock_guard<std::mutex> lock(getConfigMutex());
        ini_filename = getLastLoadedIniPath();
    }

    Logger &logger = Logger::get_instance();

    if (ini_filename.empty())
    {
        logger.warning("Config: enable_auto_reload() called before load(); watcher not started.");
        return AutoReloadStatus::NoPriorLoad;
    }

    // Resolve to the same absolute path load() uses so the watcher observes
    // the actual file on disk rather than a caller-supplied relative stub.
    std::filesystem::path ini_path = getIniFilePath(ini_filename, logger);
    std::string resolved_path = ini_path.string();

    // Hold getWatcherMutex() across start() to serialize against a
    // concurrent disable_auto_reload(). start() normally returns in
    // milliseconds; under a pathological handshake stall it returns
    // within the 5 s timeout, which is preferable to a use-after-free
    // on the watcher if we released the lock and disable_auto_reload()
    // moved the unique_ptr out and destroyed it mid-start().
    {
        std::lock_guard<std::mutex> wlock(getWatcherMutex());

        auto &watcher = getConfigWatcher();
        // Guard on existence, not is_running(): there is a window between
        // make_unique<ConfigWatcher> + start() and the worker flipping its
        // running flag true, during which a second concurrent caller would
        // otherwise overwrite the still-starting unique_ptr.
        if (watcher)
        {
            logger.warning("Config: enable_auto_reload() called while a watcher is already present; call disable_auto_reload() first.");
            return AutoReloadStatus::AlreadyRunning;
        }

        watcher = std::make_unique<ConfigWatcher>(
            resolved_path,
            debounce_window,
            [user_cb = std::move(on_reload)]()
            {
                // Reload first so any user callback observes the refreshed
                // values. The internal impl reports whether setters
                // actually ran (false when the content-hash short-circuit
                // skipped the work) so the user callback can distinguish
                // a real reload from a no-op touch.
                bool setters_ran = false;
                (void)reload_impl(setters_ran);
                if (user_cb)
                {
                    user_cb(setters_ran);
                }
            });

        if (!watcher->start())
        {
            logger.error("Config: Auto-reload watcher failed to start for {}", resolved_path);
            watcher.reset();
            return AutoReloadStatus::StartFailed;
        }
    }

    logger.info("Config: Auto-reload enabled for {} (debounce {} ms)",
                resolved_path,
                static_cast<long long>(debounce_window.count()));
    return AutoReloadStatus::Started;
}

void DetourModKit::Config::disable_auto_reload() noexcept
{
    std::unique_ptr<ConfigWatcher> to_drop;
    {
        std::lock_guard<std::mutex> wlock(getWatcherMutex());
        auto &watcher = getConfigWatcher();
        // Detect self-invocation from a setter that fires on the watcher
        // thread. Moving out and destroying the unique_ptr here would
        // force the worker to join itself inside ~StoppableWorker,
        // raising std::system_error(resource_deadlock_would_occur) from
        // std::thread::join(). Log and return instead -- callers that
        // want to cancel from inside a reload should release the
        // InputBindingGuard or flip their own disable flag.
        if (watcher && watcher->is_worker_thread(std::this_thread::get_id()))
        {
            Logger::get_instance().error(
                "Config::disable_auto_reload() called from the watcher thread; ignoring to avoid self-join deadlock. "
                "Call from a different thread or disable the hotkey binding instead.");
            return;
        }
        to_drop = std::move(watcher);
    }
    // Destructor of ConfigWatcher joins its worker outside our mutex
    // to avoid holding the watcher mutex across a thread-join.
}

bool DetourModKit::Config::register_reload_hotkey(std::string_view ini_key,
                                                  std::string_view default_combo)
{
    // An empty default causes register_press_combo to produce zero bindings,
    // which leaves the hotkey silently inert. Fail loudly instead.
    if (default_combo.empty())
    {
        Logger::get_instance().warning(
            "Config: register_reload_hotkey('{}', '<empty>') rejected; provide a non-empty default combo.",
            std::string(ini_key));
        return false;
    }

    // Pre-parse the default to reject syntactically-invalid combos.
    // register_press_combo silently no-ops on a zero-entry combo list
    // (InputManager::register_press with empty combos registers the
    // binding name but never fires). We detect this upstream so callers
    // see a false return instead of a silently inert hotkey. Piggy-back
    // on register_key_combo's parser by registering a scratch item
    // whose setter captures the parsed list -- the real
    // register_press_combo call below replaces this scratch entry via
    // replace_or_append, so nothing leaks into the registry.
    bool parse_succeeded = false;
    {
        auto probe = [&parse_succeeded](const KeyComboList &combos)
        {
            parse_succeeded = !combos.empty();
        };
        register_key_combo("Input", ini_key,
                           "Config reload hotkey (probe)",
                           probe, default_combo);
    }
    if (!parse_succeeded)
    {
        Logger::get_instance().error(
            "Config: register_reload_hotkey('{}', '{}'): combo string did not parse to any valid combo; hotkey not active.",
            std::string(ini_key), std::string(default_combo));
        return false;
    }

    // Stable binding name keyed off the INI key so repeat registrations
    // (e.g. across reload cycles) update in place rather than stacking.
    std::string binding_name = "config_reload:" + std::string(ini_key);

    // Lazily spin up the reload servicer thread on the first hotkey
    // registration. Holding getWatcherMutex() here keeps the lifetime
    // invariants aligned with disable_auto_reload / clear_registered_items.
    std::shared_ptr<ReloadServicer> servicer;
    {
        std::lock_guard<std::mutex> lock(getWatcherMutex());
        auto &slot = getReloadServicer();
        if (!slot)
        {
            slot = std::make_shared<ReloadServicer>();
        }
        servicer = slot;
    }

    InputBindingGuard guard = Config::register_press_combo(
        "Input",
        ini_key,
        "Config reload hotkey",
        binding_name,
        [servicer]() noexcept
        {
            // InputManager press callbacks run on the input-poll thread
            // and must return promptly. Defer the actual reload() work to
            // the servicer thread so a 30-item INI parse cannot jitter
            // other hotkeys. The servicer holds the shared_ptr slot and
            // cannot be destroyed while this capture is alive.
            if (servicer)
            {
                servicer->request_reload();
            }
        },
        default_combo);

    // Stash the guard under the watcher mutex so its destructor does not
    // fire at the end of this function (which would disable the binding).
    // Replace any prior guard registered for the same INI key so repeat
    // calls update in place rather than stacking.
    {
        std::lock_guard<std::mutex> lock(getWatcherMutex());
        auto &guards = getReloadHotkeyGuards();
        for (auto it = guards.begin(); it != guards.end(); ++it)
        {
            if (it->name() == binding_name)
            {
                guards.erase(it);
                break;
            }
        }
        guards.emplace_back(std::move(guard));
    }

    return true;
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
                    std::unordered_set<std::string_view> seen;
                    for (const auto &item : items)
                    {
                        seen.insert(item->section);
                    }
                    return seen.size(); }());

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

    // Drop the remembered INI path too so reload() does not act on a
    // previous file after a full reset.  Leaves the watcher alone; the
    // caller owns its lifecycle via disable_auto_reload().
    getLastLoadedIniPath().clear();
    // Wipe the cached content hash alongside the path so the next load()
    // starts from a clean slate.
    getLastLoadedIniHash().reset();

    // Release any reload-hotkey guards so the cancellation flags flip
    // deterministically. Held under the watcher mutex because that is
    // where the vector itself is serialised. Also drop our strong
    // reference to the reload servicer.
    std::shared_ptr<ReloadServicer> servicer_to_drop;
    {
        std::lock_guard<std::mutex> wlock(getWatcherMutex());
        getReloadHotkeyGuards().clear();
        servicer_to_drop = std::move(getReloadServicer());
    }
    // Release our strong reference to the servicer. The InputManager
    // binding registered by register_reload_hotkey() still holds another
    // strong ref via its captured lambda (InputBindingGuard::release()
    // only flips the cancellation flag; it does not unregister the
    // binding or drop the captured shared_ptr). The servicer worker
    // therefore joins when InputManager::shutdown() ultimately tears
    // down that binding, not at this reset() call.
    servicer_to_drop.reset();
}
