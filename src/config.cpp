/**
 * @file config.cpp
 * @brief Implementation of the INI-backed configuration surface and the INI-to-input combo fusion.
 *
 * Provides a system for binding configuration variables to atomics, callbacks, and the logger, loading their values
 * from an INI file, hot-reloading them, and fusing an INI key to a live input combo binding. The config module depends
 * on input (never the reverse); the filesystem watcher that drives auto-reload is a private engine reached through this
 * surface, not a public type.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/detail/worker.hpp"

#include "internal/config_reload_gate.hpp"
#include "internal/config_watcher.hpp"
#include "platform.hpp"

#include "SimpleIni.h"

#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <vector>

namespace DetourModKit::detail
{
    // Test-only override for is_loader_lock_held(), mirroring g_config_watcher_loader_lock_override. When non-null,
    // ~ReloadServicer consults this instead of the real PEB-based detection, letting the suite drive the servicer's
    // detach-and-leak branch from user code off the real loader lock. Defined as a plain function pointer because it is
    // set / cleared on a single thread inside a test fixture.
    bool (*g_config_reload_loader_lock_override)() noexcept = nullptr;
} // namespace DetourModKit::detail

namespace DetourModKit
{
    namespace config
    {
        using DetourModKit::filesystem::get_runtime_directory;
        using DetourModKit::string::trim;

        // Anonymous namespace for internal helpers and storage.
        namespace
        {
            /**
             * @brief Parses a comma-separated string of input tokens into a vector of InputCodes.
             * @details Each token is first matched against the named key table and source-tagged hex via
             *          parse_input_name (case-insensitive). If that yields nothing, the token is parsed as a bare
             *          hexadecimal VK code (with or without 0x prefix), defaulting to InputSource::Keyboard. That
             *          bare-hex fallback is the reconstruction path for format_input_code's bare-hex keyboard form
             *          (e.g. "0xFF" -> Keyboard 0xFF): parse_input_name alone returns nullopt for a bare-hex token, so
             *          this parser -- not parse_input_name -- closes the keyboard round-trip. Handles inline semicolon
             *          comments, whitespace, and gracefully skips invalid tokens.
             * @param input The raw string to parse.
             * @return std::vector<InputCode> Parsed valid input codes.
             */
            std::vector<InputCode> parse_input_code_list(const std::string &input)
            {
                std::vector<InputCode> result;

                // Strip trailing comment from the full line
                const size_t comment_pos = input.find(';');
                const std::string effective =
                    trim((comment_pos != std::string::npos) ? input.substr(0, comment_pos) : input);
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

                    unsigned int value = 0;
                    const char *const hex_begin = hex_part.data();
                    const char *const hex_end = hex_begin + hex_part.size();
                    const auto [parsed_end, parse_ec] = std::from_chars(hex_begin, hex_end, value, 16);
                    if (parse_ec != std::errc{} || parsed_end != hex_end)
                    {
                        continue;
                    }
                    if (value > static_cast<unsigned int>(std::numeric_limits<int>::max()))
                    {
                        continue;
                    }

                    result.push_back(InputCode{InputSource::Keyboard, static_cast<int>(value)});
                }

                return result;
            }

            /**
             * @brief Parses a single key combo string into a KeyCombo struct.
             * @details Format: "modifier1+modifier2+trigger_key" where each token is a named key or hex VK code. The
             *          last '+'-delimited token is the trigger key, all preceding tokens are modifier keys (AND logic).
             *          This function expects a single combo with no commas; use parse_key_combo_list to split
             *          comma-separated alternatives first.
             * @param input The raw string to parse (no commas expected).
             * @return input::KeyCombo Parsed key combination.
             */
            input::KeyCombo parse_key_combo(const std::string &input)
            {
                input::KeyCombo result;

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
             * @brief Returns true when @p text is the literal "NONE" sentinel (case-insensitive ASCII, exact length
             *        match).
             * @details The whole-string-only rule keeps the sentinel unambiguous: a NONE token nested inside a
             *          comma-separated list cannot be told apart from a key-name typo without a per-token lookup, and
             *          the OR-of-combos semantic makes "an unbound slot inside an OR-list" meaningless. Caller must pass
             *          a pre-trimmed view.
             */
            [[nodiscard]] bool is_none_sentinel(std::string_view text) noexcept
            {
                if (text.size() != 4)
                {
                    return false;
                }
                constexpr char target[] = {'N', 'O', 'N', 'E'};
                for (size_t i = 0; i < 4; ++i)
                {
                    const char ch = text[i];
                    const char folded = (ch >= 'a' && ch <= 'z') ? static_cast<char>(ch - ('a' - 'A')) : ch;
                    if (folded != target[i])
                    {
                        return false;
                    }
                }
                return true;
            }

            /**
             * @brief Parses a comma-separated string of key combos into a KeyComboList.
             * @details Commas at the top level separate independent combos (OR logic between combos). Each combo is
             *          parsed by parse_key_combo. Handles inline semicolon comments and whitespace. Two opt-out
             *          sentinels yield an empty result silently: an empty (post-trim) input, and the literal "NONE"
             *          (case-insensitive, whole-string only). A non-empty input that is not the NONE sentinel and whose
             *          every comma-separated token fails to parse is treated as a user typo and emits a single WARNING
             *          naming the binding and the offending raw string. Empty inner tokens (e.g. "F4,,F5") are silently
             *          skipped; the WARNING fires only when the entire result list is empty.
             * @param input The raw string to parse.
             * @param binding_log_name Optional human-readable binding name used in the typo WARNING. Defaults to an
             *                          empty view, in which case the WARNING uses "<unnamed>".
             * @return input::KeyComboList Parsed list of key combinations.
             */
            input::KeyComboList parse_key_combo_list(const std::string &input, std::string_view binding_log_name = {})
            {
                input::KeyComboList result;

                // Strip trailing comment from the full line
                const size_t comment_pos = input.find(';');
                const std::string effective =
                    trim((comment_pos != std::string::npos) ? input.substr(0, comment_pos) : input);

                // Disposition 1: explicit opt-out via empty string. Silent.
                if (effective.empty())
                {
                    return result;
                }

                // Disposition 2: explicit opt-out via NONE sentinel (whole-string, case-insensitive, post-trim).
                // Silent.
                if (is_none_sentinel(effective))
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

                // Disposition 3: input was non-empty and not the NONE sentinel, yet every token failed to parse. Real
                // user typo, name it.
                if (result.empty())
                {
                    const std::string_view name_view =
                        binding_log_name.empty() ? std::string_view{"<unnamed>"} : binding_log_name;
                    log().warning("Config: combo string \"{}\" for binding '{}' did not parse to any "
                                  "valid keys; binding will be unbound. Use \"\" or \"NONE\" to opt "
                                  "out explicitly.",
                                  effective, name_view);
                }

                return result;
            }

            /**
             * @brief Formats a single KeyCombo as a human-readable string.
             * @details Uses named keys where available, falls back to hex for unknown codes.
             * @param combo The key combination to format.
             * @return std::string Formatted string (e.g., "Ctrl+Shift+F3").
             */
            std::string format_key_combo(const input::KeyCombo &combo)
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
            std::string format_key_combo_list(const input::KeyComboList &combos)
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
             * @brief Selects the argument type the deferred setter receives.
             * @details The frozen string-bind surface delivers the raw INI value as a std::string_view valid only for
             *          the duration of the call; every other bound type passes the parsed value by value. Keeping the
             *          stored current_value a std::string (so it owns its bytes across reloads) while the setter takes a
             *          view means the deferred apply hands out a view into the captured copy.
             */
            template <typename T>
            using SetterArg = std::conditional_t<std::same_as<T, std::string>, std::string_view, T>;

            /**
             * @brief Base class for typed configuration items.
             * @details This allows storing different types of configuration items polymorphically in a collection.
             */
            struct ConfigItemBase
            {
                std::string section;
                std::string ini_key;
                std::string log_key_name;

                ConfigItemBase(std::string sec, std::string key, std::string log_name)
                    : section(std::move(sec)), ini_key(std::move(key)), log_key_name(std::move(log_name))
                {
                }
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
             * @brief Trims ASCII blanks from both ends of @p text and strips a single leading '+'.
             * @details Shared by the int and float scalar binds so both normalize forms like " +50 " / "+1.5"
             *          identically before handing the view to std::from_chars. from_chars rejects a leading '+' on the
             *          mantissa (unlike the strtod/strtoll it replaced), so one is stripped to keep a signed-positive
             *          value parsing; a lone "+" trims to an empty view and correctly falls back to the default. A
             *          leading '-' is left in place because from_chars accepts it. Returns a view into @p text and
             *          performs no allocation.
             */
            [[nodiscard]] std::string_view trim_blanks_and_leading_plus(std::string_view text) noexcept
            {
                constexpr auto is_blank = [](char c) noexcept
                { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
                while (!text.empty() && is_blank(text.front()))
                {
                    text.remove_prefix(1);
                }
                while (!text.empty() && is_blank(text.back()))
                {
                    text.remove_suffix(1);
                }
                if (!text.empty() && text.front() == '+')
                {
                    text.remove_prefix(1);
                }
                return text;
            }

            /**
             * @brief Configuration item using a std::function callback for value setting.
             * @tparam T The data type of the configuration item (e.g., int, bool, std::string).
             * @note Setter callbacks are invoked outside the config mutex to prevent deadlocks. See the bind_* free
             *       functions and load() for the deferred invocation pattern. The setter receives SetterArg<T>: a
             *       std::string_view for the string item (delivering the raw INI bytes), otherwise the parsed value by
             *       value.
             */
            template <typename T> struct CallbackConfigItem : public ConfigItemBase
            {
                std::function<void(SetterArg<T>)> setter; // Callback function to set the value
                T default_value;
                T current_value;

                CallbackConfigItem(std::string sec, std::string key, std::string log_name,
                                   std::function<void(SetterArg<T>)> set_fn, T def_val)
                    : ConfigItemBase(std::move(sec), std::move(key), std::move(log_name)), setter(std::move(set_fn)),
                      default_value(def_val), current_value(std::move(def_val))
                {
                }

                void load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger) override
                {
                    // One generic body for the scalar/string config types. KeyComboList takes the explicit
                    // specialization below instead, because its parse path differs (nullptr INI value handling,
                    // combo-list parsing).
                    if constexpr (std::same_as<T, int>)
                    {
                        // SimpleIni's GetLongValue parses into a long, which is 32-bit on this LLP64 target, so a value
                        // beyond int range can saturate before this bind sees it. Read the raw string and parse it with
                        // std::from_chars instead, so an out-of-range or non-numeric value falls back to the registered
                        // default with a Warning. Preserve the public base rule: 0x-prefixed values are hexadecimal and
                        // everything else is decimal (including leading-zero values such as "010").
                        const char *raw = ini.GetValue(section.c_str(), ini_key.c_str(), nullptr);
                        if (raw == nullptr)
                        {
                            current_value = default_value;
                        }
                        else
                        {
                            std::string_view text = trim_blanks_and_leading_plus(std::string_view{raw});

                            int base = 10;
                            if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
                            {
                                text.remove_prefix(2);
                                base = 16;
                            }

                            long long parsed = 0;
                            const auto [end, ec] =
                                std::from_chars(text.data(), text.data() + text.size(), parsed, base);
                            const bool fully_consumed = (ec == std::errc{} && end == text.data() + text.size());
                            if (!fully_consumed || parsed < static_cast<long long>(std::numeric_limits<int>::min()) ||
                                parsed > static_cast<long long>(std::numeric_limits<int>::max()))
                            {
                                logger.warning("Config: value '{}' for '{}' is not a valid int (non-numeric or out of "
                                               "range); using default {}.",
                                               raw, ini_key, default_value);
                                current_value = default_value;
                            }
                            else
                            {
                                current_value = static_cast<int>(parsed);
                            }
                        }
                    }
                    else if constexpr (std::same_as<T, float>)
                    {
                        // SimpleIni's GetDoubleValue routes through strtod, which is locale-dependent: on a host that
                        // installed a comma-decimal locale (common in European game and middleware runtimes) it parses
                        // "1.5" as 1, leaves ".5" unconsumed, and GetDoubleValue then silently returns the registered
                        // default -- no truncation warning, no trace. The int branch above was already moved off the
                        // locale-sensitive parser for the analogous saturation bug; do the same here. std::from_chars
                        // is locale-independent by definition ('.' is the only accepted decimal separator), so read the
                        // raw string and parse it directly, falling back to the default with a Warning on a non-numeric
                        // or out-of-range value with the same warn-and-default discipline as the int path.
                        const char *raw = ini.GetValue(section.c_str(), ini_key.c_str(), nullptr);
                        if (raw == nullptr)
                        {
                            current_value = default_value;
                        }
                        else
                        {
                            std::string_view text = trim_blanks_and_leading_plus(std::string_view{raw});

                            float parsed = default_value;
                            const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed);
                            const bool fully_consumed = (ec == std::errc{} && end == text.data() + text.size());
                            if (!fully_consumed)
                            {
                                logger.warning(
                                    "Config: value '{}' for '{}' is not a valid float (non-numeric or out of "
                                    "range); using default {}.",
                                    raw, ini_key, default_value);
                                current_value = default_value;
                            }
                            else
                            {
                                current_value = parsed;
                            }
                        }
                    }
                    else if constexpr (std::same_as<T, bool>)
                    {
                        current_value = ini.GetBoolValue(section.c_str(), ini_key.c_str(), default_value);
                    }
                    else if constexpr (std::same_as<T, std::string>)
                    {
                        current_value = ini.GetValue(section.c_str(), ini_key.c_str(), default_value.c_str());
                    }
                }

                void log_current_value(Logger &logger) const override
                {
                    if constexpr (std::same_as<T, bool>)
                    {
                        logger.debug("Config:   {} = {}", ini_key, current_value ? "true" : "false");
                    }
                    else if constexpr (std::same_as<T, std::string>)
                    {
                        logger.debug("Config:   {} = \"{}\"", ini_key, current_value);
                    }
                    else // int, float
                    {
                        logger.debug("Config:   {} = {}", ini_key, current_value);
                    }
                }

                /// Returns a self-contained callback that invokes setter with current_value.
                [[nodiscard]] std::function<void()> take_deferred_apply() const override
                {
                    if (!setter)
                        return {};
                    if constexpr (std::same_as<T, std::string>)
                    {
                        // The setter takes a std::string_view valid only for the call; capture the owning string by
                        // value and hand out a view into that copy, so the value stays alive for the entire call.
                        return [fn = setter, val = current_value]() mutable { fn(std::string_view{val}); };
                    }
                    else
                    {
                        return [fn = setter, val = current_value]() mutable { fn(std::move(val)); };
                    }
                }
            };

            // load() and log_current_value() use the generic if-constexpr bodies defined in the class above for the
            // scalar/string types. Only KeyComboList needs an explicit specialization, because its parse path differs.

            // For input::KeyComboList (list of key combinations)
            template <>
            void CallbackConfigItem<input::KeyComboList>::load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger)
            {
                const char *ini_value_str = ini.GetValue(section.c_str(), ini_key.c_str(), nullptr);
                if (ini_value_str != nullptr)
                {
                    current_value = parse_key_combo_list(ini_value_str, log_key_name);
                }
                else
                {
                    current_value = default_value;
                }
            }

            template <> void CallbackConfigItem<input::KeyComboList>::log_current_value(Logger &logger) const
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

            // Global storage for registered configuration items
            std::mutex &get_config_mutex()
            {
                static std::mutex s_mtx;
                return s_mtx;
            }

            // Serializes an entire reload/load application pass end to end -- the read + content-hash decision + the
            // deferred-setter application -- so two concurrent passes cannot interleave. It is deliberately DISTINCT
            // from get_config_mutex(): the setter application deliberately runs with get_config_mutex() released (so a
            // setter may re-enter bind_*/getters), which leaves the passes unordered relative to one another. Without
            // this outer mutex two reload() drivers (the watcher callback and the hotkey servicer, both documented as
            // safe from any thread) can advance the cached content hash to the newer bytes while the OLDER pass applies
            // its stale value snapshot last; the hash short-circuit then suppresses every subsequent reload of the
            // unchanged newer bytes and pins the stale state indefinitely. Holding this across the whole pass makes
            // each application atomic w.r.t. other passes: the newer pass cannot begin reading until the older one has
            // fully applied and committed its hash. Acquire it FIRST, with get_config_mutex() nested inside for the
            // capture phase; it is non-reentrant, so a bound setter that itself calls config::reload() would
            // self-deadlock (a pathological, undocumented use -- see config.hpp).
            std::mutex &get_reload_apply_mutex()
            {
                static std::mutex s_mtx;
                return s_mtx;
            }

            // Background-reload quiesce gate (see internal/config_reload_gate.hpp).
            // Two DMK-owned worker threads run reload passes that call consumer code (registered setters and the user
            // on_reload callback) living in the hot-reloadable Logic DLL: the auto-reload watcher's debounced callback
            // and the hotkey reload servicer. On a DllMain-detach unload those workers are detached, not joined, so a
            // late pass could fire setters into pages the loader has already reclaimed. This latch lets the unload path
            // stop new passes, and this counter lets it wait for a pass already mid-flight to finish first.

            // When true, a background reload pass is dropped at its entry gate instead of running consumer code. Set by
            // on_logic_dll_unload*, cleared by the next load(). seq_cst throughout: it pairs with the in-flight counter
            // in a store-then-load / increment-then-recheck handshake where a relaxed order could let the unload path
            // read a stale zero while a pass is still arming.
            std::atomic<bool> &reload_disabled_latch() noexcept
            {
                static std::atomic<bool> s_disabled{false};
                return s_disabled;
            }

            // Number of background reload passes currently running consumer code. on_logic_dll_unload* spins on this
            // (bounded) after setting the latch so it does not let the Logic DLL be unmapped out from under a detached
            // worker mid-setter.
            std::atomic<int> &reload_in_flight_count() noexcept
            {
                static std::atomic<int> s_in_flight{0};
                return s_in_flight;
            }

            /**
             * @class BackgroundReloadGuard
             * @brief RAII entry gate for a background reload pass (watcher callback / hotkey servicer).
             * @details On construction it consults @ref reload_disabled_latch. If reloads have been latched off for a
             *          Logic DLL unload it stays disengaged, so the pass is dropped before it can call a setter or the
             *          user callback into pages about to be reclaimed. While engaged it holds @ref reload_in_flight_count
             *          up for the whole pass (setters AND the user callback), so @ref await_reloads_quiesced can observe
             *          a pass that was already running when the latch was set and wait for it. The check / increment /
             *          re-check sequence pairs with the latch-store-then-count-load in await_reloads_quiesced: the
             *          re-check after the increment closes the window where the latch is set between the first check and
             *          the increment, guaranteeing that a pass the unload path fails to observe (count still zero when it
             *          reads) also fails to engage (it sees the latch on re-check and backs out).
             */
            class BackgroundReloadGuard
            {
            public:
                BackgroundReloadGuard() noexcept
                {
                    if (reload_disabled_latch().load(std::memory_order_seq_cst))
                    {
                        return;
                    }
                    reload_in_flight_count().fetch_add(1, std::memory_order_seq_cst);
                    if (reload_disabled_latch().load(std::memory_order_seq_cst))
                    {
                        // The latch flipped between the first check and the increment. Back out: the unload path sets
                        // the latch and THEN reads the count, so if it missed this increment it must still see the
                        // latch here and we must not run consumer code.
                        reload_in_flight_count().fetch_sub(1, std::memory_order_seq_cst);
                        return;
                    }
                    m_engaged = true;
                }

                ~BackgroundReloadGuard() noexcept
                {
                    if (m_engaged)
                    {
                        reload_in_flight_count().fetch_sub(1, std::memory_order_seq_cst);
                    }
                }

                BackgroundReloadGuard(const BackgroundReloadGuard &) = delete;
                BackgroundReloadGuard &operator=(const BackgroundReloadGuard &) = delete;

                /// True when reloads are armed and this pass may run consumer code; false when latched off for unload.
                [[nodiscard]] bool engaged() const noexcept { return m_engaged; }

            private:
                bool m_engaged{false};
            };

            std::vector<std::unique_ptr<ConfigItemBase>> &get_registered_config_items()
            {
                // Function-local static to ensure controlled initialization order.
                static std::vector<std::unique_ptr<ConfigItemBase>> s_registered_items;
                return s_registered_items;
            }

            // Holds the INI path last passed to load(). Empty until the first load() call -- reload() returns false in
            // that window. Caller must hold get_config_mutex() when reading or writing.
            std::string &get_last_loaded_ini_path()
            {
                static std::string s_last_loaded_ini_path;
                return s_last_loaded_ini_path;
            }

            // Tear-free snapshot of the last-loaded INI path. Takes get_config_mutex() itself and returns a copy, so a
            // caller that only needs to read the path cannot observe a reference torn by a concurrent reload()/load()
            // mutating the underlying string. Use this instead of get_last_loaded_ini_path() at any read site that is
            // not already inside a held get_config_mutex() critical section (the mutex is non-recursive). The string
            // copy can allocate, so this is intentionally not noexcept.
            [[nodiscard]] std::string snapshot_last_loaded_ini_path()
            {
                std::lock_guard<std::mutex> lock(get_config_mutex());
                return get_last_loaded_ini_path();
            }

            // Content hash of the bytes last successfully loaded from the INI file. std::nullopt until the first
            // successful load() (or after clear(), which wipes it alongside the path). Caller must hold
            // get_config_mutex() when reading or writing.
            std::optional<std::uint64_t> &get_last_loaded_ini_hash()
            {
                static std::optional<std::uint64_t> s_last_loaded_ini_hash;
                return s_last_loaded_ini_hash;
            }

            /**
             * @brief 64-bit FNV-1a hash over a raw byte range.
             * @details Computed on the disk bytes (pre-parse) so cosmetic churn by SimpleIni's own parser (comment
             *          stripping, whitespace normalisation) cannot skew the result. Produces a stable value on any
             *          platform without pulling in a dependency.
             */
            [[nodiscard]] std::uint64_t fnv1a_64(const std::vector<std::uint8_t> &bytes) noexcept
            {
                constexpr std::uint64_t FNV_OFFSET_BASIS{0xcbf29ce484222325ULL};
                constexpr std::uint64_t FNV_PRIME{0x00000100000001b3ULL};
                std::uint64_t h{FNV_OFFSET_BASIS};
                for (std::uint8_t b : bytes)
                {
                    h ^= static_cast<std::uint64_t>(b);
                    h *= FNV_PRIME;
                }
                return h;
            }

            /**
             * @brief Reads all bytes of @p path into memory.
             * @details Returns std::nullopt when the file cannot be opened (e.g. mid-save by an editor that locks
             *          exclusively). The two callers diverge on nullopt: the initial load() proceeds with the bound
             *          defaults (a first run legitimately has no file on disk yet), while reload() clears the cached
             *          hash and returns before the setter pass so the last-applied values are retained rather than
             *          snapped back to defaults.
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
                /// Bytes successfully read from disk
                bool read_succeeded{false};
                /// CSimpleIniA::LoadData returned SI_OK
                bool parse_succeeded{false};
                /// Raw SimpleIni return code (when read_succeeded)
                SI_Error parse_rc{SI_OK};
                /// FNV-1a hash of the read bytes
                std::optional<std::uint64_t> hash;
            };

            /**
             * @brief Reads the INI bytes once, computes their hash, and feeds those exact bytes to
             *        CSimpleIniA::LoadData.
             * @details Closes the TOCTOU window where LoadFile would re-read the file after our byte snapshot: if the
             *          file was rewritten between the two reads, the cached hash would reflect one version and the
             *          parsed INI another. By using LoadData on the already-buffered bytes, the hash and the parse are
             *          guaranteed to reflect the same file state.
             * @param path Absolute path to the INI file.
             * @param ini  SimpleIni instance to populate.
             * @return IniLoadOutcome describing each pipeline stage.
             */
            [[nodiscard]] IniLoadOutcome load_ini_into(const std::filesystem::path &path, CSimpleIniA &ini) noexcept
            {
                IniLoadOutcome outcome{};
                auto bytes = read_ini_bytes(path);
                if (!bytes.has_value())
                {
                    return outcome;
                }
                outcome.read_succeeded = true;
                outcome.hash = fnv1a_64(*bytes);

                // CSimpleIniA::LoadData(const char*, size_t). Empty buffers are accepted by SimpleIni (SI_OK, zero
                // sections) -- we still preserve the hash so an empty file can be content-hash-skipped.
                try
                {
                    const char *data_ptr = bytes->empty() ? "" : reinterpret_cast<const char *>(bytes->data());
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

            // Filesystem watcher owned by enable_auto_reload(). Separate mutex so start / stop transitions do not
            // contend with registration traffic. The same mutex serialises every other process-lifetime piece that
            // lives alongside the watcher (the reload servicer and the reload-hotkey guard vector).
            std::mutex &get_watcher_mutex()
            {
                static std::mutex s_mtx;
                return s_mtx;
            }

            std::unique_ptr<DetourModKit::detail::ConfigWatcher> &get_config_watcher()
            {
                static std::unique_ptr<DetourModKit::detail::ConfigWatcher> s_watcher;
                return s_watcher;
            }

            // Retains a copy of the user on_reload callback last handed to enable_auto_reload(). ConfigWatcher exposes
            // no getter for the callback it swallowed, so this copy is the only way load() can reconstruct an
            // equivalent watcher when the config file path changes under an active watcher (see load()'s re-point
            // path). Guarded by get_watcher_mutex(), the same mutex that serialises the watcher slot itself.
            std::function<void(bool)> &get_reload_user_callback() noexcept
            {
                static std::function<void(bool)> s_callback;
                return s_callback;
            }

            // Case-insensitive equality for two already-resolved INI paths. Both operands come from
            // get_ini_file_path(), so separators and normalization already match; only case can differ. Windows paths
            // are case-insensitive, so an ordinal ASCII fold is the correct and sufficient comparison here (a locale
            // fold is deliberately avoided, per the same rule that drives the watcher's ordinal filename match). Kept
            // local and minimal rather than shared: it is a three-line fold with a config-specific meaning.
            [[nodiscard]] bool resolved_paths_equivalent(std::string_view a, std::string_view b) noexcept
            {
                if (a.size() != b.size())
                {
                    return false;
                }
                const auto ascii_lower = [](char c) noexcept -> unsigned char
                {
                    const auto u = static_cast<unsigned char>(c);
                    return (u >= 'A' && u <= 'Z') ? static_cast<unsigned char>(u + ('a' - 'A')) : u;
                };
                for (size_t i = 0; i < a.size(); ++i)
                {
                    if (ascii_lower(a[i]) != ascii_lower(b[i]))
                    {
                        return false;
                    }
                }
                return true;
            }

            // Keeps reload-hotkey BindingGuards alive for the process lifetime. Returning the guard by value from
            // reload_hotkey() would immediately destroy it (the call site has nowhere to store it), and
            // ~BindingGuard flips the binding's enabled flag to false, so the press callback would silently no-op
            // forever. Protected by get_watcher_mutex() because it already serialises lifetime state that lives
            // alongside the watcher (both are config-wide, not per-item).
            std::vector<input::BindingGuard> &get_reload_hotkey_guards() noexcept
            {
                static std::vector<input::BindingGuard> s_guards;
                return s_guards;
            }

            // Consults the reload-servicer loader-lock override when a test installed one, otherwise the real
            // PEB-based detection. ~ReloadServicer uses this to choose join vs detach-and-leak, mirroring the
            // ConfigWatcher destructor's loader_lock_held_for_watcher().
            bool reload_servicer_loader_lock_held() noexcept
            {
                if (auto *override_fn = DetourModKit::detail::g_config_reload_loader_lock_override)
                {
                    return override_fn();
                }
                return DetourModKit::detail::is_loader_lock_held();
            }

            /**
             * @class ReloadServicer
             * @brief Background thread that coalesces reload-hotkey presses and invokes reload() off the input poll
             *        thread.
             * @details The hotkey press callback must return in microseconds so other hotkeys do not jitter while a
             *          30-item INI parse runs. The servicer latches a pending-reload flag; its worker thread blocks on a
             *          condition variable, drains the flag on wake, and invokes reload() at most once per batch of
             *          presses. Exceptions from reload() are caught so the servicer never dies.
             *
             *          All state the worker touches lives in a heap-owned @ref Channel, separable from the servicer
             *          shell. On a bare-FreeLibrary teardown, ~ReloadServicer runs under the loader lock (static
             *          destruction): joining is unsafe, so the worker is detached and the whole Channel is leaked so its
             *          mutex / condition variable / atomics outlive the detached thread that still reads them. This is
             *          the same leak-on-loader-lock discipline ConfigWatcher::~ConfigWatcher applies.
             *
             * Lazy lifetime: created on the first reload_hotkey call, kept alive until clear() tears it down. Shared
             * via std::shared_ptr so a press callback that races with shutdown cannot dereference a freed servicer.
             */
            class ReloadServicer
            {
                // Every field the worker thread dereferences. Heap-owned and detachable from the ReloadServicer shell
                // so the loader-lock branch can leak it: the detached service_loop keeps reading these members through
                // a raw Channel* until it observes the stop request, so they must not be destroyed with the shell.
                // worker is declared LAST so ~Channel destroys it FIRST (request stop + join) before the mutex / cv it
                // uses, keeping the off-loader-lock teardown order correct.
                struct Channel
                {
                    std::mutex mutex;
                    std::condition_variable cv;
                    std::atomic<bool> reload_requested{false};
                    std::atomic<bool> shutdown{false};
                    // Published by service_loop on entry and cleared on exit so ~ReloadServicer can detect a self-join:
                    // config::clear() reachable from a reload setter runs on this worker thread, and joining the worker
                    // from itself would raise std::system_error. Mirrors ConfigWatcher::Impl::worker_thread_id.
                    std::atomic<std::thread::id> worker_tid{};
                    std::unique_ptr<DetourModKit::StoppableWorker> worker;
                };

            public:
                ReloadServicer() : m_channel(std::make_unique<Channel>())
                {
                    // Launch the servicer worker against the heap-owned Channel, NOT `this`: the loader-lock branch of
                    // the destructor leaks the Channel while the shell is destroyed, so the worker body must reference
                    // storage that survives. StoppableWorker passes its own stop_token into the body; we observe it via
                    // stop_requested() inside the wait predicate, and a stop_callback (installed inside service_loop)
                    // flips the shutdown flag and notifies the CV so request_stop() wakes a currently blocked cv.wait.
                    Channel *channel = m_channel.get();
                    m_channel->worker = std::make_unique<DetourModKit::StoppableWorker>(
                        "ConfigReloadServicer",
                        [channel](std::stop_token st) { service_loop(*channel, std::move(st)); });
                }

                ~ReloadServicer() noexcept
                {
                    if (!m_channel)
                    {
                        return;
                    }

                    // Flip the shutdown flag and wake the worker so it observes the stop request promptly instead of
                    // waiting for the next press. notify_all() is harmless if the worker already exited.
                    {
                        std::lock_guard<std::mutex> lock(m_channel->mutex);
                        m_channel->shutdown.store(true, std::memory_order_release);
                    }
                    m_channel->cv.notify_all();

                    // Detect a self-join: config::clear() reachable from a reload setter runs on the servicer worker
                    // thread, so joining that worker from itself would raise std::system_error. Treated identically to
                    // the loader-lock case -- detach the worker and leak the Channel -- because a bare detach that let
                    // ~Channel run would free the mutex / cv / atomics the still-running service_loop dereferences.
                    const bool on_worker =
                        m_channel->worker_tid.load(std::memory_order_acquire) == std::this_thread::get_id();

                    if (reload_servicer_loader_lock_held() || on_worker)
                    {
                        // Under the loader lock, or on the worker's own thread: joining risks a deadlock (or a
                        // guaranteed self-join std::system_error), and destroying the Channel would free the mutex / cv
                        // / atomics the detached service_loop still dereferences -- destroying a condition_variable
                        // with a waiter is UB. Request stop + detach the worker (StoppableWorker's own branch leaks its
                        // module reference to keep the worker's code mapped, and self-detaches on the worker thread),
                        // then leak the whole Channel so its members outlive this destructor. No module reference is
                        // taken here because the detached worker holds its own; mirrors ConfigWatcher::~ConfigWatcher.
                        if (m_channel->worker)
                        {
                            m_channel->worker->shutdown();
                        }

                        // The Channel is already on the heap, so release() abandons it with zero further allocation
                        // (and therefore cannot fail): the unique_ptr stops owning it, ~Channel never runs, and the
                        // mutex / cv / atomics stay alive for the detached worker to keep reading through its raw
                        // Channel*. A per-call new(nothrow) leak cell would be redundant here -- that ladder only earns
                        // its cost when parking a shared_ptr that has no heap home of its own -- so this mirrors
                        // AsyncLogger::~AsyncLogger's m_impl.release() rather than allocating a fresh wrapper.
                        (void)m_channel.release();
                        DetourModKit::diagnostics::record_intentional_leak(
                            DetourModKit::diagnostics::LeakSubsystem::Worker);
                        return;
                    }

                    // Off the loader lock: destroy the Channel normally. Its worker member is declared last, so
                    // ~Channel requests stop and JOINS the worker thread before the mutex / cv it uses are destroyed.
                    m_channel.reset();
                }

                ReloadServicer(const ReloadServicer &) = delete;
                ReloadServicer &operator=(const ReloadServicer &) = delete;
                ReloadServicer(ReloadServicer &&) = delete;
                ReloadServicer &operator=(ReloadServicer &&) = delete;

                /**
                 * @brief Requests a reload. noexcept and allocation-free on the fast path; the press callback uses this
                 *        and must not throw back onto the input poll thread.
                 */
                void request_reload() noexcept
                {
                    // The predicate variable reload_requested must be mutated under the channel mutex (or at minimum
                    // the notifier must take the mutex before notify_one) to close the lost-wakeup window on the waiter
                    // side: waiter evaluates the predicate false (pre-lock), then parks; if we stored + notified in
                    // that gap without touching the mutex, the press could be dropped until the next one. Taking the
                    // mutex here serialises against the waiter's predicate re-check, making the wakeup observation
                    // guaranteed.
                    {
                        std::lock_guard<std::mutex> lock(m_channel->mutex);
                        m_channel->reload_requested.store(true, std::memory_order_release);
                    }
                    m_channel->cv.notify_one();
                }

            private:
                static void service_loop(Channel &channel, std::stop_token st) noexcept
                {
                    DetourModKit::Logger &logger = DetourModKit::log();

                    // Publish our thread id so ~ReloadServicer can detect a self-join: config::clear() reached from a
                    // reload setter runs on this very thread, and joining the worker from itself would raise
                    // std::system_error. Cleared on exit below so a later OS-recycled thread id cannot alias a dead
                    // worker. Counterpart to ConfigWatcher::Impl::worker_thread_id.
                    channel.worker_tid.store(std::this_thread::get_id(), std::memory_order_release);

                    // Wake the CV when the worker is asked to stop so the blocked wait exits promptly instead of
                    // waiting for the next press.
                    std::stop_callback stop_cb(st,
                                               [&channel]() -> void
                                               {
                                                   {
                                                       std::lock_guard<std::mutex> lock(channel.mutex);
                                                       channel.shutdown.store(true, std::memory_order_release);
                                                   }
                                                   channel.cv.notify_all();
                                               });

                    while (!st.stop_requested() && !channel.shutdown.load(std::memory_order_acquire))
                    {
                        {
                            std::unique_lock<std::mutex> lock(channel.mutex);
                            channel.cv.wait(lock,
                                            [&]()
                                            {
                                                return st.stop_requested() ||
                                                       channel.shutdown.load(std::memory_order_acquire) ||
                                                       channel.reload_requested.load(std::memory_order_acquire);
                                            });
                        }

                        if (st.stop_requested() || channel.shutdown.load(std::memory_order_acquire))
                        {
                            break;
                        }

                        // Coalesce: a burst of presses during the reload below collapses into at most one follow-up
                        // pass because the next iteration will exchange the flag once.
                        while (channel.reload_requested.exchange(false, std::memory_order_acq_rel))
                        {
                            // Gate on the unload latch. Once on_logic_dll_unload* has latched background reloads off,
                            // stop servicing rather than run reload()'s setters into a Logic DLL whose pages are being
                            // reclaimed. While engaged the guard holds the in-flight count up across the whole reload,
                            // so the unload quiesce waits for a pass that is already running before it returns.
                            BackgroundReloadGuard reload_guard;
                            if (!reload_guard.engaged())
                            {
                                break;
                            }
                            try
                            {
                                (void)config::reload();
                            }
                            catch (const std::exception &e)
                            {
                                (void)logger.try_log(LogLevel::Error, "Config: reload servicer caught exception: {}",
                                                     e.what());
                            }
                            catch (...)
                            {
                                (void)logger.try_log(LogLevel::Error,
                                                     "Config: reload servicer caught unknown exception.");
                            }
                        }
                    }

                    // Clear the published id before returning so a dead worker's stale id cannot match a live self-join
                    // check after the OS recycles this thread id onto an unrelated thread.
                    channel.worker_tid.store(std::thread::id{}, std::memory_order_release);
                }

                std::unique_ptr<Channel> m_channel;
            };

            // Shared_ptr so a press callback holding its own strong reference cannot crash when clear() resets the
            // slot.
            std::shared_ptr<ReloadServicer> &get_reload_servicer() noexcept
            {
                static std::shared_ptr<ReloadServicer> s_servicer;
                return s_servicer;
            }

            /**
             * @brief Replaces an existing item with the same section+key, or appends if none found.
             * @note Caller must hold get_config_mutex().
             */
            void replace_or_append(std::unique_ptr<ConfigItemBase> item)
            {
                auto &items = get_registered_config_items();
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
            std::filesystem::path get_ini_file_path(const std::string &ini_filename, Logger &logger)
            {
                std::wstring module_dir = get_runtime_directory();

                if (module_dir.empty() || module_dir == L".")
                {
                    logger.warning(
                        "Config: Could not reliably determine module directory or it's current working directory. "
                        "Using relative path for INI: {}",
                        ini_filename);
                    // Fallback to relative path
                    return std::filesystem::path(ini_filename);
                }

                try
                {
                    std::filesystem::path ini_path_obj =
                        (std::filesystem::path(module_dir) / ini_filename).lexically_normal();
                    logger.debug("Config: Determined INI file path: {}", ini_path_obj.string());
                    return ini_path_obj;
                }
                catch (const std::filesystem::filesystem_error &fs_err)
                {
                    logger.warning(
                        "Config: Filesystem error constructing INI path: {}. Using relative path for INI: {}",
                        fs_err.what(), ini_filename);
                }
                catch (const std::exception &e)
                {
                    logger.warning("Config: General error constructing INI path: {}. Using relative path for INI: {}",
                                   e.what(), ini_filename);
                }
                return std::filesystem::path(ini_filename); // Fallback
            }

            // All bind_* functions use the deferred callback pattern: state is mutated under get_config_mutex(), but
            // the setter callback is invoked after the lock is released. This allows setters to call back into the
            // data-plane config API (bind_* / getters) without deadlocking (no reentrancy guard needed); the load() /
            // reload() pass lock is a separate, stricter contract documented on those functions. The scalar/string
            // binds share one helper to keep the lock discipline and the "apply default once at registration" semantics
            // identical across types.
            template <typename T>
            void bind_scalar(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                             std::function<void(SetterArg<T>)> setter, T default_value)
            {
                std::function<void()> deferred;
                {
                    std::lock_guard<std::mutex> lock(get_config_mutex());
                    replace_or_append(std::make_unique<CallbackConfigItem<T>>(
                        std::string(section), std::string(ini_key), std::string(log_key_name), setter, default_value));
                    if (setter)
                    {
                        deferred = [setter = std::move(setter), val = std::move(default_value)]() mutable
                        {
                            if constexpr (std::same_as<T, std::string>)
                            {
                                setter(std::string_view{val});
                            }
                            else
                            {
                                setter(val);
                            }
                        };
                    }
                }
                if (deferred)
                {
                    deferred();
                }
            }

        } // anonymous namespace

        void bind_int(std::string_view section, std::string_view key, std::string_view display_name,
                      std::function<void(int)> setter, int default_value)
        {
            bind_scalar<int>(section, key, display_name, std::move(setter), default_value);
        }

        void bind_float(std::string_view section, std::string_view key, std::string_view display_name,
                        std::function<void(float)> setter, float default_value)
        {
            bind_scalar<float>(section, key, display_name, std::move(setter), default_value);
        }

        void bind_bool(std::string_view section, std::string_view key, std::string_view display_name,
                       std::function<void(bool)> setter, bool default_value)
        {
            bind_scalar<bool>(section, key, display_name, std::move(setter), default_value);
        }

        void bind_string(std::string_view section, std::string_view key, std::string_view display_name,
                         std::function<void(std::string_view)> setter, std::string_view default_value)
        {
            bind_scalar<std::string>(section, key, display_name, std::move(setter), std::string(default_value));
        }

        void bind_parsed(std::string_view section, std::string_view key, std::string_view display_name,
                         std::atomic<std::uint32_t> &out, std::function<std::uint32_t(std::string_view)> parse,
                         std::string_view default_value)
        {
            // Build over the string-bind machinery: the stored setter parses the raw INI value through the
            // caller-supplied function and stores the result relaxed. parse is captured by value so the setter stays
            // valid across every load() / reload(); out is captured by reference and must outlive the registration.
            bind_string(
                section, key, display_name, [&out, parse = std::move(parse)](std::string_view value)
                { out.store(parse(value), std::memory_order_relaxed); }, default_value);
        }

        void bind_log_level(std::string_view section, std::string_view key, std::string_view default_value)
        {
            bind_string(
                section, key, "Log level",
                [](std::string_view value) { log().set_log_level(string_to_log_level(value)); }, default_value);
        }

        void bind_combos(std::string_view section, std::string_view key, std::string_view display_name,
                         std::function<void(const input::KeyComboList &)> setter, std::string_view default_value)
        {
            input::KeyComboList default_combos = parse_key_combo_list(std::string(default_value), display_name);

            std::function<void()> deferred;
            {
                std::lock_guard<std::mutex> lock(get_config_mutex());
                replace_or_append(std::make_unique<CallbackConfigItem<input::KeyComboList>>(
                    std::string(section), std::string(key), std::string(display_name), setter, default_combos));
                if (setter)
                {
                    deferred = [setter = std::move(setter), combos = std::move(default_combos)]() { setter(combos); };
                }
            }
            if (deferred)
            {
                deferred();
            }
        }

        void consume_flag(std::string_view section, std::string_view ini_key, std::string_view display_name,
                          std::string_view binding_name, bool default_value)
        {
            // Capture the binding name by value so the setter, which outlives this call and re-runs on every
            // load()/reload(), stays valid. set_consume is a no-op for an unknown name, so registering this before the
            // binding exists is safe.
            std::string binding_name_str(binding_name);
            bind_bool(
                section, ini_key, display_name, [binding_name_str](bool consume)
                { input::Input::instance().set_consume(binding_name_str, consume); }, default_value);
        }

        // Anonymous namespace: the shared combo-binding fusion behind press_combo() and hold_combo().
        namespace
        {
            /**
             * @brief Shared implementation behind press_combo() and hold_combo().
             * @details Parses the default combo, registers the input binding via input::register_combo (the guard, the
             *          hold release-edge lifecycle, and callback flag-gating now live entirely inside input), wires a
             *          combo config item so an INI change rebinds the live binding on every load()/reload(), optionally
             *          registers the
             *          "<ini_key>.Consume" facet, and returns the owning guard. Exactly one of @p on_press /
             *          @p on_state_change is used, per @p trigger. Fail-soft: a registration error logs and yields an
             *          inert default guard so the caller's combo simply stays unbound rather than aborting setup.
             */
            input::BindingGuard register_combo_fusion(input::Trigger trigger, std::string_view section,
                                                      std::string_view ini_key, std::string_view log_name,
                                                      std::string_view binding_name, std::function<void()> on_press,
                                                      std::function<void(bool)> on_state_change,
                                                      std::string_view default_combo, std::optional<bool> consume)
            {
                const std::string binding_name_str(binding_name);

                // Register the binding with an empty combo set. The combo config item registered just below parses
                // default_combo exactly once (in its registration-time setter) and rebinds the live binding with the
                // resolved combos, so pre-parsing default_combo here would be a redundant second parse -- and a
                // duplicate typo WARNING when the literal default carries a mistake. One parse, one binding, then a
                // rebind on every load()/reload().
                input::ComboBinding binding{.name = binding_name_str,
                                            .trigger = trigger,
                                            .combos = {},
                                            .consume = consume.value_or(false),
                                            .on_press = std::move(on_press),
                                            .on_state_change = std::move(on_state_change)};

                input::BindingGuard guard;
                if (auto reg = input::register_combo(std::move(binding)); reg.has_value())
                {
                    guard = std::move(*reg);
                }
                else
                {
                    (void)log().try_log(LogLevel::Error,
                                        "Config: failed to register input binding '{}' for '{}'; "
                                        "binding will be inert.",
                                        binding_name_str, log_name);
                }

                // Register the live-rebind config item under (section, ini_key). The setter rebinds the named binding
                // on every load()/reload(); it parses through bind_combos (same path bind_combos uses) so an INI edit
                // resolves to a fresh KeyComboList and the binding tracks it without re-registering.
                bind_combos(
                    section, ini_key, log_name, [binding_name_str](const input::KeyComboList &combos)
                    { (void)input::Input::instance().rebind(binding_name_str, combos); }, default_combo);

                // Register the consume facet only after the binding exists: consume_flag()'s immediate setter calls
                // set_consume(), a no-op for an unknown name, so registering the bool item before the binding was
                // created would drop the registration-time default.
                if (consume.has_value())
                {
                    consume_flag(section, std::string(ini_key) + ".Consume", std::string(log_name) + " Consume",
                                 binding_name_str, *consume);
                }

                return guard;
            }
        } // anonymous namespace

        input::BindingGuard press_combo(std::string_view section, std::string_view ini_key, std::string_view log_name,
                                        std::string_view binding_name, std::function<void()> on_press,
                                        std::string_view default_combo, std::optional<bool> consume)
        {
            return register_combo_fusion(input::Trigger::Press, section, ini_key, log_name, binding_name,
                                         std::move(on_press), nullptr, default_combo, consume);
        }

        input::BindingGuard hold_combo(std::string_view section, std::string_view ini_key, std::string_view log_name,
                                       std::string_view binding_name, std::function<void(bool)> on_state_change,
                                       std::string_view default_combo, std::optional<bool> consume)
        {
            return register_combo_fusion(input::Trigger::Hold, section, ini_key, log_name, binding_name, nullptr,
                                         std::move(on_state_change), default_combo, consume);
        }

        void load(std::string_view ini_filename)
        {
            // Re-arm background reloads for this config lifecycle. A prior on_logic_dll_unload* may have latched them
            // off to quiesce the watcher/servicer during a DLL unload; a Logic DLL that (re)loads and calls load() must
            // be able to hot-reload again, so clear the latch before registering and applying this pass's values.
            detail::rearm_reloads();

            // Serialize the read + content-hash decision + setter application against any concurrent reload/load pass
            // (see get_reload_apply_mutex()). A std::unique_lock lets the watcher slot be reserved under this ordering
            // and then releases the pass lock before the stale watcher is joined.
            std::unique_lock<std::mutex> apply_lock(get_reload_apply_mutex());

            std::vector<std::function<void()>> deferred_callbacks;
            std::string loaded_resolved_path;
            std::optional<std::uint64_t> hash_to_commit;

            {
                std::lock_guard<std::mutex> lock(get_config_mutex());

                Logger &logger = log();
                std::filesystem::path ini_path = get_ini_file_path(std::string(ini_filename), logger);
                // convert to narrow string for logger formatting
                std::string ini_path_str = ini_path.string();
                loaded_resolved_path = ini_path_str;
                CSimpleIniA ini;
                ini.SetUnicode(false);  // Assume ASCII/MBCS INI
                ini.SetMultiKey(false); // Disallow duplicate keys in a section

                // Read-hash-parse pipeline: read bytes once, hash them, feed the same buffer into CSimpleIniA::LoadData
                // so the cached hash and the parsed INI state are guaranteed to reflect identical file contents
                // (TOCTOU-free vs. a separate LoadFile call).
                IniLoadOutcome outcome = load_ini_into(ini_path, ini);

                if (!outcome.read_succeeded)
                {
                    logger.error("Config: Failed to open '{}'. Using defaults.", ini_path_str);
                    // File unreadable: wipe the cached hash so the next reload() does not short-circuit against a stale
                    // value.
                    get_last_loaded_ini_hash().reset();
                }
                else if (!outcome.parse_succeeded)
                {
                    logger.error("Config: Failed to parse '{}' (error {}). Using defaults.", ini_path_str,
                                 static_cast<int>(outcome.parse_rc));
                    // Parse failed: clear the hash so a subsequent successful load() does not spuriously hash-skip a
                    // reload against a hash computed for bytes we could not actually parse.
                    get_last_loaded_ini_hash().reset();
                }
                else
                {
                    logger.debug("Config: Opened {}", ini_path_str);
                    // Do not publish this hash until every deferred setter succeeds. Reset any prior file's hash now
                    // so a transient failure cannot make reload() skip this file merely because the two files happen
                    // to hash identically.
                    get_last_loaded_ini_hash().reset();
                    hash_to_commit = outcome.hash;
                }

                // Read all values under lock, but defer setter callbacks
                for (const auto &item : get_registered_config_items())
                {
                    item->load(ini, logger);
                    auto cb = item->take_deferred_apply();
                    if (cb)
                    {
                        deferred_callbacks.push_back(std::move(cb));
                    }
                }

                // Remember the INI path so reload() and enable_auto_reload() can target the same file without the
                // caller passing it again. Store it on every outcome, not just success: the normal ship-with-defaults
                // first run has no INI on disk yet, so the read fails, but the caller still intends that path to be the
                // config. enable_auto_reload() needs the path recorded to start a watcher on the parent directory and
                // pick the file up when it later appears. Remembering a path whose load failed is safe because reload()
                // on an unreadable file retains the last in-memory values instead of snapping to defaults, and the
                // cached hash was reset above on failure so a later successful read is never hash-skipped against stale
                // state.
                get_last_loaded_ini_path() = std::string(ini_filename);

                logger.info("Config: Loaded {} items from {}", get_registered_config_items().size(), ini_path_str);
            }

            // Invoke setter callbacks outside the config mutex -- same deferred pattern as the bind_* family. Setters
            // may re-enter the data-plane config API (bind_* / getters), but not load() / reload() /
            // disable_auto_reload() / clear(): this pass still holds the outer pass lock across the setter phase, so
            // those would self-deadlock re-acquiring it or join a reload worker blocked on it (see config.hpp). Wrap
            // each call so a single throwing setter cannot prevent the remaining setters from applying the freshly
            // loaded values, mirroring reload_impl(): the initial load() and a reload() share the same per-setter
            // isolation so one bad item degrades to a logged warning instead of aborting the whole load. The logger is
            // acquired outside the config mutex -- a custom Logger sink that re-enters config cannot AB/BA deadlock
            // here.
            Logger &setter_logger = log();
            bool all_setters_applied = true;
            for (auto &cb : deferred_callbacks)
            {
                try
                {
                    cb();
                }
                catch (const std::exception &e)
                {
                    all_setters_applied = false;
                    setter_logger.error("Config: load setter threw: {}", e.what());
                }
                catch (...)
                {
                    all_setters_applied = false;
                    setter_logger.error("Config: load setter threw unknown exception.");
                }
            }
            if (all_setters_applied && hash_to_commit.has_value())
            {
                std::lock_guard<std::mutex> lock(get_config_mutex());
                get_last_loaded_ini_hash() = hash_to_commit;
            }

            // Re-point the auto-reload watcher if load() switched the config file out from under an active watcher.
            // enable_auto_reload() bound the watcher to the path recorded at enable time; a later load("other.ini")
            // advances the remembered path but leaves the watcher on the old directory/file, so edits to the
            // now-active file would never fire a reload (and stale edits to the old file would wake a reload of the
            // new one). Detect the change and reserve the watcher slot under the pass lock, preserving the caller's
            // debounce and on_reload callback. The stale watcher is joined only after the pass lock is released: a
            // background reload waiting on that mutex must be able to finish so the old watcher can exit.
            {
                std::unique_ptr<DetourModKit::detail::ConfigWatcher> stale_watcher;
                bool repoint = false;
                std::chrono::milliseconds saved_debounce{};
                std::function<void(bool)> saved_callback;
                {
                    std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                    auto &watcher = get_config_watcher();
                    if (watcher)
                    {
                        if (!resolved_paths_equivalent(watcher->ini_path(), loaded_resolved_path))
                        {
                            if (watcher->is_worker_thread(std::this_thread::get_id()))
                            {
                                // A reload callback that itself calls load() with a new filename runs on the watcher
                                // thread; moving out and destroying the watcher here would self-join the worker
                                // (std::system_error). Mirror disable_auto_reload()'s self-join guard: log and skip the
                                // re-point so the caller can re-point from another thread.
                                (void)log().try_log(
                                    LogLevel::Error,
                                    "Config: load() switched the config file on the watcher thread; not "
                                    "re-pointing auto-reload to avoid a self-join. Re-point from another "
                                    "thread via disable_auto_reload()/enable_auto_reload().");
                            }
                            else
                            {
                                saved_debounce = watcher->debounce();
                                saved_callback = get_reload_user_callback();
                                stale_watcher = std::move(watcher);
                                repoint = true;
                            }
                        }
                    }
                }

                // The value application and watcher-slot decision are complete. Drop the pass lock before joining the
                // stale watcher; the slot has already been cleared, so a later load either observes no watcher and lets
                // this enable step pick up the latest path, or observes the fresh watcher and re-points it normally.
                apply_lock.unlock();

                // Join the stale watcher OUTSIDE both mutexes (mirrors disable_auto_reload's move-out-then-drop), then
                // start a fresh watcher. enable_auto_reload() snapshots the latest remembered path, which matters if a
                // newer load completed while this thread was joining the old watcher.
                stale_watcher.reset();
                if (repoint)
                {
                    (void)enable_auto_reload(saved_debounce, std::move(saved_callback));
                }
            }
        }

        namespace
        {
            /**
             * @brief Internal reload implementation that also reports whether setters actually ran.
             * @param[out] out_setters_ran Set to true when setters were invoked. False when the content-hash
             *                             short-circuit or a read failure skipped the setter pass.
             * @return true if a previous load() path was available and the reload proceeded; false if reload() was
             *         called before any load().
             */
            bool reload_impl(bool &out_setters_ran)
            {
                out_setters_ran = false;

                // Serialize this entire pass -- read, content-hash decision, and the deferred-setter application below
                // -- against every other reload/load pass. The setter loop runs with get_config_mutex() released (so a
                // setter may re-enter bind_*/getters), which leaves passes unordered without this outer lock; two
                // reload drivers could then advance the cached hash to the newer bytes while the older pass applies its
                // stale snapshot last, pinning stale state behind the hash short-circuit. Held across the whole body so
                // each application is atomic w.r.t. other passes.
                std::lock_guard<std::mutex> apply_lock(get_reload_apply_mutex());

                std::vector<std::function<void()>> deferred_callbacks;
                std::string ini_filename;
                std::optional<std::uint64_t> hash_to_commit;

                {
                    std::lock_guard<std::mutex> lock(get_config_mutex());

                    ini_filename = get_last_loaded_ini_path();
                    if (ini_filename.empty())
                    {
                        // No prior load() -- nothing to reload. Caller is expected to check the return value and either
                        // call load() first or surface a user-facing error.
                        return false;
                    }

                    DetourModKit::Logger &logger = DetourModKit::log();
                    std::filesystem::path ini_path = get_ini_file_path(ini_filename, logger);
                    std::string ini_path_str = ini_path.string();

                    CSimpleIniA ini;
                    ini.SetUnicode(false);
                    ini.SetMultiKey(false);

                    // Read-hash-parse pipeline: the hash we compare against the cache and the bytes SimpleIni parses
                    // come from a single read. Splitting the read (one for hashing, another via LoadFile for parsing)
                    // would let an editor save slip between them and desync the cached hash from the parsed state.
                    IniLoadOutcome outcome = load_ini_into(ini_path, ini);

                    if (!outcome.read_succeeded)
                    {
                        // Read failure (e.g. the file is locked mid-save, exactly the transient the debounce window is
                        // meant to ride out). Clear the cached hash so a later reload that happens to read bytes
                        // identical to the last good load cannot match a stale hash and hash-skip. Then return before
                        // the setter pass: the CSimpleIniA below was never populated, so running item->load against it
                        // would read every bound value as its registered default and snap live state to defaults. The
                        // reload path was still available and was handled, so this is not a NoPriorLoad case and no
                        // setters ran (out_setters_ran stays false).
                        get_last_loaded_ini_hash() = std::nullopt;
                        logger.warning("Config: reload() could not open '{}'; retaining last values (setters not "
                                       "re-run).",
                                       ini_path_str);
                        return true;
                    }

                    {
                        // Content-hash skip: compare against the hash stored on the last successful load()/reload().
                        // Identical bytes -> no setters. Uses the hash we just computed in the pipeline; no second
                        // read.
                        // load_ini_into sets hash whenever read_succeeded, and this is the read_succeeded branch.
                        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
                        const std::uint64_t current_hash = *outcome.hash;
                        if (const auto &cached_hash = get_last_loaded_ini_hash(); cached_hash.has_value())
                        {
                            if (current_hash == *cached_hash)
                            {
                                logger.debug("Config: reload content unchanged (hash {:016x}); skipping setters.",
                                             current_hash);
                                return true;
                            }
                        }

                        if (!outcome.parse_succeeded)
                        {
                            // Parse failure. This is not a malformed-content case: CSimpleIniA::LoadData returns SI_OK
                            // for any byte content (embedded nulls, unclosed sections, and binary junk all parse), so a
                            // negative code here means an internal SimpleIni allocation failure, or a bad_alloc that
                            // load_ini_into caught as SI_FAIL. Treat it like the read-failure branch above: return
                            // before the setter pass so the last in-memory values are retained rather than snapped to
                            // their defaults by item->load against a parser that failed to populate. The one asymmetry
                            // that remains is the cached hash -- a read failure reset it (it never observed the bytes),
                            // but a parse failure did read the bytes, so remember that hash to avoid repeatedly parsing
                            // the same known-bad content. No setters ran, so out_setters_ran stays false and on_reload
                            // observes setters_ran == false.
                            get_last_loaded_ini_hash() = current_hash;
                            logger.warning("Config: reload() parse error on '{}' (error {}); retaining last values "
                                           "(setters not re-run).",
                                           ini_path_str, static_cast<int>(outcome.parse_rc));
                            return true;
                        }

                        // A successful parse is not fully applied until every deferred setter completes. Keep the hash
                        // pending so a transient setter failure or an unload-latch interruption retries identical bytes
                        // instead of pinning partially applied state behind the unchanged-content fast path.
                        hash_to_commit = current_hash;
                        logger.debug("Config: Reloading from {}", ini_path_str);
                    }

                    for (const auto &item : get_registered_config_items())
                    {
                        item->load(ini, logger);
                        auto cb = item->take_deferred_apply();
                        if (cb)
                        {
                            deferred_callbacks.push_back(std::move(cb));
                        }
                    }

                    logger.info("Config: Reloaded {} items from {}", get_registered_config_items().size(),
                                ini_path_str);
                }

                // The registry mutex is released by the scope above; setters run unlocked (the standard deferred-setter
                // pattern). Wrap each call so a single throwing setter cannot prevent the remaining setters from seeing
                // the refreshed values. Logger::error() below is also outside the config mutex -- a custom Logger sink
                // that re-enters config cannot AB/BA deadlock here.
                DetourModKit::Logger &logger = DetourModKit::log();
                bool all_setters_applied = true;
                for (auto &cb : deferred_callbacks)
                {
                    // Abort the setter pass early if a Logic DLL unload latched reloads off mid-pass. Every remaining
                    // setter is code in the unloading module, so stopping now shrinks the window in which this
                    // (possibly detached) worker calls into pages the loader is about to reclaim. A partially-applied
                    // pass is acceptable here: the module is being torn down, so config consistency no longer matters,
                    // and the watcher callback re-checks the latch before running the user on_reload callback.
                    if (reload_disabled_latch().load(std::memory_order_seq_cst))
                    {
                        all_setters_applied = false;
                        break;
                    }
                    try
                    {
                        cb();
                    }
                    catch (const std::exception &e)
                    {
                        all_setters_applied = false;
                        logger.error("Config: reload setter threw: {}", e.what());
                    }
                    catch (...)
                    {
                        all_setters_applied = false;
                        logger.error("Config: reload setter threw unknown exception.");
                    }
                }
                out_setters_ran = true;
                if (all_setters_applied)
                {
                    std::lock_guard<std::mutex> lock(get_config_mutex());
                    get_last_loaded_ini_hash() = hash_to_commit;
                }
                return true;
            }
        } // anonymous namespace

        bool reload()
        {
            bool ignored = false;
            return reload_impl(ignored);
        }

        namespace detail
        {
            void disable_reloads_for_unload() noexcept
            {
                reload_disabled_latch().store(true, std::memory_order_seq_cst);
            }

            bool await_reloads_quiesced(std::chrono::milliseconds timeout) noexcept
            {
                // Bounded spin on the in-flight counter. The latch (set first, by disable_reloads_for_unload) stops new
                // passes from raising the count, so this only has to drain the passes already running when the latch
                // was set. A wedged setter -- one blocked on the loader lock this unload thread may itself hold -- must
                // not hang the unload, hence the deadline: on expiry the caller proceeds best-effort.
                const std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + timeout;
                while (reload_in_flight_count().load(std::memory_order_seq_cst) != 0)
                {
                    if (std::chrono::steady_clock::now() >= deadline)
                    {
                        return false;
                    }
                    std::this_thread::yield();
                }
                return true;
            }

            void rearm_reloads() noexcept
            {
                // Clear only the latch. The in-flight counter is self-balancing (every BackgroundReloadGuard increment
                // has a matching decrement), so a straggler pass from a prior lifecycle still completes its own
                // bookkeeping; forcibly zeroing it here could underflow when that straggler decrements.
                reload_disabled_latch().store(false, std::memory_order_seq_cst);
            }
        } // namespace detail

        AutoReloadStatus enable_auto_reload(std::chrono::milliseconds debounce, std::function<void(bool)> on_reload)
        {
            const std::string ini_filename = snapshot_last_loaded_ini_path();

            Logger &logger = log();

            if (ini_filename.empty())
            {
                logger.warning("Config: enable_auto_reload() called before load(); watcher not started.");
                return AutoReloadStatus::NoPriorLoad;
            }

            // Resolve to the same absolute path load() uses so the watcher observes the actual file on disk rather than
            // a caller-supplied relative stub.
            std::filesystem::path ini_path = get_ini_file_path(ini_filename, logger);
            std::string resolved_path = ini_path.string();

            // Hold get_watcher_mutex() across start() to serialize against a concurrent disable_auto_reload(). start()
            // normally returns in milliseconds; under a pathological handshake stall it returns within the 5 s timeout,
            // which is preferable to a use-after-free on the watcher if we released the lock and disable_auto_reload()
            // moved the unique_ptr out and destroyed it mid-start().
            {
                std::lock_guard<std::mutex> wlock(get_watcher_mutex());

                auto &watcher = get_config_watcher();
                // Guard on existence, not is_running(): there is a window between make_unique<ConfigWatcher> + start()
                // and the worker flipping its running flag true, during which a second concurrent caller would
                // otherwise overwrite the still-starting unique_ptr.
                if (watcher)
                {
                    logger.warning("Config: enable_auto_reload() called while a watcher is already present; "
                                   "call disable_auto_reload() first.");
                    return AutoReloadStatus::AlreadyRunning;
                }

                // Persist a copy of the user callback so load() can reconstruct an equivalent watcher when the config
                // file path changes out from under this watcher (ConfigWatcher swallows on_reload and exposes no
                // getter). Copied before the std::move below, under the same get_watcher_mutex() that guards the
                // watcher slot.
                get_reload_user_callback() = on_reload;

                watcher = std::make_unique<DetourModKit::detail::ConfigWatcher>(
                    resolved_path, debounce,
                    [user_cb = std::move(on_reload)]()
                    {
                        // Gate the whole pass on the unload latch. If a Logic DLL unload has latched reloads off, drop
                        // it: both reload_impl's setters and the user callback are code in the unloading module. While
                        // engaged the guard holds the in-flight count up across BOTH the setter pass and the user
                        // callback, so the unload quiesce waits for a pass already running.
                        BackgroundReloadGuard reload_guard;
                        if (!reload_guard.engaged())
                        {
                            return;
                        }
                        // Reload first so any user callback observes the refreshed values. The internal impl reports
                        // whether setters actually ran (false when the content-hash short-circuit found unchanged bytes
                        // or a read failure retained the current values) so the callback can distinguish a real reload
                        // from a skipped setter pass.
                        bool setters_ran = false;
                        (void)reload_impl(setters_ran);
                        // Re-check the latch: an unload may have latched off mid-pass (the setter loop honors it too),
                        // so skip the user callback rather than run it into a module being unmapped.
                        if (user_cb && !reload_disabled_latch().load(std::memory_order_seq_cst))
                        {
                            user_cb(setters_ran);
                        }
                    });

                if (!watcher->start())
                {
                    logger.error("Config: Auto-reload watcher failed to start for {}", resolved_path);
                    watcher.reset();
                    // Drop the persisted callback alongside the failed watcher: with no live watcher there is nothing
                    // for load() to re-point, and the copy must not outlive its watcher and pin Logic DLL references.
                    get_reload_user_callback() = nullptr;
                    return AutoReloadStatus::StartFailed;
                }
            }

            logger.info("Config: Auto-reload enabled for {} (debounce {} ms)", resolved_path,
                        static_cast<long long>(debounce.count()));
            return AutoReloadStatus::Started;
        }

        void disable_auto_reload() noexcept
        {
            std::unique_ptr<DetourModKit::detail::ConfigWatcher> to_drop;
            {
                std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                auto &watcher = get_config_watcher();
                // Detect self-invocation from a setter that fires on the watcher thread. Moving out and destroying the
                // unique_ptr here would force the worker to join itself inside ~StoppableWorker, raising
                // std::system_error(resource_deadlock_would_occur) from std::thread::join(). Log and return instead --
                // callers that want to cancel from inside a reload should release the input binding guard or flip their
                // own disable flag.
                if (watcher && watcher->is_worker_thread(std::this_thread::get_id()))
                {
                    (void)log().try_log(
                        LogLevel::Error,
                        "Config: disable_auto_reload() called from the watcher thread; ignoring to avoid self-join "
                        "deadlock. Call from a different thread or disable the hotkey binding instead.");
                    return;
                }
                to_drop = std::move(watcher);
                // Drop the persisted re-point callback with the watcher it belonged to, so it does not outlive the
                // watcher and pin Logic DLL references. A fresh enable_auto_reload() repopulates it.
                get_reload_user_callback() = nullptr;
            }
            // Destructor of ConfigWatcher joins its worker outside our mutex to avoid holding the watcher mutex across
            // a thread-join.
        }

        bool reload_hotkey(std::string_view ini_key, std::string_view default_combo)
        {
            // An empty or explicitly-opt-out default would leave the hotkey silently inert (a binding registered
            // without trigger keys never fires). Surface that to the caller as a false return so they can decide
            // whether to fall back to a different combo or skip the hotkey entirely.
            if (default_combo.empty())
            {
                log().warning("Config: reload_hotkey('{}', '<empty>') rejected; provide a non-empty default combo.",
                              std::string(ini_key));
                return false;
            }

            // Pre-parse the default. The parser emits its own WARNING when a non-empty, non-sentinel string fails to
            // parse, so no extra log is needed for the typo path. Explicit opt-out via the NONE sentinel still returns
            // false because a hotkey with no keys is useless.
            const input::KeyComboList parsed = parse_key_combo_list(std::string(default_combo), "Config reload hotkey");
            if (parsed.empty())
            {
                return false;
            }

            // Stable binding name keyed off the INI key so repeat registrations (e.g. across reload cycles) update in
            // place rather than stacking.
            std::string binding_name = "config_reload:" + std::string(ini_key);

            // Lazily spin up the reload servicer thread on the first hotkey registration. Holding get_watcher_mutex()
            // here keeps the lifetime invariants aligned with disable_auto_reload / clear.
            std::shared_ptr<ReloadServicer> servicer;
            {
                std::lock_guard<std::mutex> lock(get_watcher_mutex());
                auto &slot = get_reload_servicer();
                if (!slot)
                {
                    slot = std::make_shared<ReloadServicer>();
                }
                servicer = slot;
            }

            input::BindingGuard guard = press_combo(
                "Input", ini_key, "Config reload hotkey", binding_name,
                [servicer]() noexcept
                {
                    // Input press callbacks run on the poll thread and must return promptly. Defer the actual reload()
                    // work to the servicer thread so a 30-item INI parse cannot jitter other hotkeys. The servicer
                    // holds the shared_ptr slot and cannot be destroyed while this capture is alive.
                    if (servicer)
                    {
                        servicer->request_reload();
                    }
                },
                default_combo, std::nullopt);

            // Stash the guard under the watcher mutex so its destructor does not fire at the end of this function
            // (which would disable the binding). Replace any prior guard registered for the same INI key so repeat
            // calls update in place rather than stacking.
            {
                std::lock_guard<std::mutex> lock(get_watcher_mutex());
                auto &guards = get_reload_hotkey_guards();
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

        void log_all()
        {
            std::lock_guard<std::mutex> lock(get_config_mutex());

            Logger &logger = log();
            const auto &items = get_registered_config_items();
            if (items.empty())
            {
                logger.info("Config: No configuration items registered.");
                return;
            }

            logger.info("Config: {} registered values across {} section(s)", items.size(),
                        [&items]()
                        {
                            std::unordered_set<std::string_view> seen;
                            for (const auto &item : items)
                            {
                                seen.insert(item->section);
                            }
                            return seen.size();
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

        void clear() noexcept
        {
            Logger &logger = log();
            size_t count = 0;

            {
                std::lock_guard<std::mutex> lock(get_config_mutex());
                count = get_registered_config_items().size();
                if (count > 0)
                {
                    get_registered_config_items().clear();
                }

                // Drop the remembered INI path too so reload() does not act on a previous file after a full reset.
                // Leaves the watcher alone; the caller owns its lifecycle via disable_auto_reload().
                get_last_loaded_ini_path().clear();
                // Wipe the cached content hash alongside the path so the next load() starts from a clean slate.
                get_last_loaded_ini_hash().reset();
            }

            // Release any reload-hotkey guards so the cancellation flags flip deterministically. Held under the watcher
            // mutex because that is where the vector itself is serialised. Also drop our strong reference to the reload
            // servicer. This runs outside get_config_mutex(): if the servicer is currently inside reload(), joining it
            // while holding the config mutex would deadlock the worker against the teardown thread.
            std::shared_ptr<ReloadServicer> servicer_to_drop;
            {
                std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                get_reload_hotkey_guards().clear();
                servicer_to_drop = std::move(get_reload_servicer());
            }
            // Release our strong reference to the servicer. If the input binding registered by reload_hotkey() is still
            // live, its callback capture keeps the servicer alive until the input facade tears that binding down. If
            // input has already shut down, this reset may be the final drop; that destructor is outside
            // get_config_mutex so a worker currently inside reload() cannot deadlock trying to reacquire the config
            // lock.
            servicer_to_drop.reset();

            // Logging routes through try_log (the no-throw, fail-closed path) rather than debug(): debug() formats
            // through a potentially-throwing sink, which would break this noexcept contract on a format or sink
            // failure.
            if (count > 0)
            {
                (void)logger.try_log(LogLevel::Debug, "Config: Cleared {} registered configuration items.", count);
            }
            else
            {
                (void)logger.try_log(LogLevel::Debug, "Config: clear called, but no items were registered.");
            }
        }
    } // namespace config
} // namespace DetourModKit
