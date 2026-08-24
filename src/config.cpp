/**
 * @file config.cpp
 * @brief This TU implements the INI parse and registry data plane and the INI-to-input combo fusion.
 *
 * The config module depends on input, never the reverse. SimpleIni stays confined to this TU. The reload control
 * plane lives in src/internal/config_reload.cpp and the watcher control plane in config_watch.cpp.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/format.hpp"

#include "internal/config_pass.hpp"
#include "internal/config_reload_gate.hpp"
#include "internal/config_reload_lifecycle.hpp"
#include "internal/config_watch_control.hpp"

#include <SimpleIni.h>

#include <atomic>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <vector>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    // Fires inside load()'s watcher re-point, between the stale-watcher join and replacement start. A test can then
    // place a disable_auto_reload() call in that lock gap deterministically.
    void (*g_config_repoint_window_test_hook)() = nullptr;

    // Forces read_ini_bytes() through its seek/tell failure classification.
    std::atomic<bool> g_config_read_seektell_fail{false};

    // Forces one parse failure so an identical-byte retry can exercise hash invalidation.
    std::atomic<bool> g_config_parse_fail_once{false};
#endif
} // namespace DetourModKit::detail

namespace DetourModKit
{
    namespace config
    {
        using DetourModKit::filesystem::get_runtime_directory;
        using DetourModKit::string::trim;

        namespace
        {
            /**
             * @brief Parses a comma-separated string of input tokens into a vector of InputCodes.
             * @details Named keys resolve through parse_input_name. A bare hex token falls back to a Keyboard VK
             *          code, which closes format_input_code's bare-hex keyboard round-trip. Semicolon comments and
             *          invalid tokens are skipped.
             */
            std::vector<InputCode> parse_input_code_list(const std::string &input)
            {
                std::vector<InputCode> result;

                const size_t comment_pos = input.find(';');
                const std::string effective =
                    trim((comment_pos != std::string::npos) ? input.substr(0, comment_pos) : input);
                if (effective.empty())
                {
                    return result;
                }

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

                    auto named = parse_input_name(token);
                    if (named.has_value())
                    {
                        result.push_back(*named);
                        continue;
                    }

                    size_t hex_start = 0;
                    if (token.size() >= 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
                    {
                        hex_start = 2;
                    }
                    if (hex_start >= token.size())
                    {
                        continue;
                    }

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
             * @brief Parses a single key combo string ("mod1+mod2+trigger") into a KeyCombo struct.
             * @details The last '+'-delimited token is the trigger. Earlier tokens are AND-logic modifiers. The
             *          function expects no commas. parse_key_combo_list splits alternatives first.
             */
            input::KeyCombo parse_key_combo(const std::string &input)
            {
                input::KeyCombo result;

                const std::string effective = trim(input);
                if (effective.empty())
                {
                    return result;
                }

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

                result.keys = parse_input_code_list(segments.back());

                for (size_t i = 0; i + 1 < segments.size(); ++i)
                {
                    auto mod_codes = parse_input_code_list(segments[i]);
                    result.modifiers.insert(result.modifiers.end(), mod_codes.begin(), mod_codes.end());
                }

                return result;
            }

            /**
             * @brief Returns true when @p text is the literal "NONE" sentinel (case-insensitive ASCII, pre-trimmed).
             * @details Whole-string only: a NONE token nested inside an OR-list is indistinguishable from a typo, and
             *          an unbound slot inside an OR-list is meaningless.
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

        } // anonymous namespace

        namespace detail
        {
            // Contract in internal/config_pass.hpp. The grammar helpers above stay file-local.
            input::KeyComboList parse_key_combo_list(
                const std::string &input,
                DeferredDiagnostics &diags,
                std::string_view binding_log_name
            )
            {
                input::KeyComboList result;

                const size_t comment_pos = input.find(';');
                const std::string effective =
                    trim((comment_pos != std::string::npos) ? input.substr(0, comment_pos) : input);

                // An empty string and the NONE sentinel are silent opt-outs.
                if (effective.empty())
                {
                    return result;
                }
                if (is_none_sentinel(effective))
                {
                    return result;
                }

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

                // If non-empty, non-sentinel input has no valid token, report the user typo by name.
                if (result.empty())
                {
                    const std::string_view name_view =
                        binding_log_name.empty() ? std::string_view{"<unnamed>"} : binding_log_name;
                    defer_diagnostic(
                        diags,
                        LogLevel::Warning,
                        "Config: combo string \"{}\" for binding '{}' did not parse to any "
                        "valid keys; binding will be unbound. Use \"\" or \"NONE\" to opt "
                        "out explicitly.",
                        effective,
                        name_view
                    );
                }

                return result;
            }
        } // namespace detail

        namespace
        {
            /// Formats a single KeyCombo as a human-readable string (e.g. "Ctrl+Shift+F3").
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

            /// Formats a KeyComboList as a comma-joined human-readable string (e.g. "F3,Gamepad_LT+Gamepad_B").
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
             * @details The string bind delivers a std::string_view valid only for the call. Every other bound type
             *          passes the parsed value by value.
             */
            template <typename T>
            using SetterArg = std::conditional_t<std::same_as<T, std::string>, std::string_view, T>;

            /// ConfigItemBase stores typed configuration items polymorphically in the registry.
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

                /// Loads the configuration value from the INI file and defers every diagnostic it produces.
                virtual void load(CSimpleIniA &ini, detail::DeferredDiagnostics &diags) = 0;

                /// Returns a deferred callback to invoke the setter outside the config mutex, or empty without one.
                [[nodiscard]] virtual std::function<void()> take_deferred_apply() const = 0;

                /// Defers one record that names the current value of the configuration item.
                virtual void log_current_value(detail::DeferredDiagnostics &diags) const = 0;
            };

            /**
             * @brief Trims ASCII blanks from both ends of @p text and strips one initial '+'.
             * @details from_chars rejects an initial '+' (unlike the strtod/strtoll it replaced), so this function
             *          strips one for a positive value. It returns a view into @p text and allocates nothing.
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
             * @brief Parses an INI boolean and distinguishes an unrecognized value from a valid one.
             * @details Matches SimpleIni's GetBoolValue forms.
             *          An initial t/y/1 means true, and f/n/0 means false.
             *          The exact values "on" and "off" also map to true and false. An unrecognized value returns
             *          nullopt for diagnosis. @p value must be non-null and non-empty.
             */
            [[nodiscard]] std::optional<bool> parse_ini_bool(const char *value) noexcept
            {
                switch (value[0])
                {
                case 't':
                case 'T':
                case 'y':
                case 'Y':
                case '1':
                    return true;
                case 'f':
                case 'F':
                case 'n':
                case 'N':
                case '0':
                    return false;
                case 'o':
                case 'O':
                    if (value[1] == 'n' || value[1] == 'N')
                    {
                        return true;
                    }
                    if (value[1] == 'f' || value[1] == 'F')
                    {
                        return false;
                    }
                    return std::nullopt;
                default:
                    return std::nullopt;
                }
            }

            /**
             * @brief Stores a configuration item with a std::function value setter.
             * @note Setter callbacks run outside the config mutex. This prevents deadlocks. The bind_* functions and
             *       load() use this deferred invocation pattern.
             */
            template <typename T> struct CallbackConfigItem : public ConfigItemBase
            {
                std::function<void(SetterArg<T>)> setter;
                T default_value;
                T current_value;

                CallbackConfigItem(
                    std::string sec,
                    std::string key,
                    std::string log_name,
                    std::function<void(SetterArg<T>)> set_fn,
                    T def_val
                )
                    : ConfigItemBase(std::move(sec), std::move(key), std::move(log_name)), setter(std::move(set_fn)),
                      default_value(def_val), current_value(std::move(def_val))
                {
                }

                void load(CSimpleIniA &ini, [[maybe_unused]] detail::DeferredDiagnostics &diags) override
                {
                    // The generic body handles scalar and string types. KeyComboList uses the explicit specialization.
                    if constexpr (std::same_as<T, int>)
                    {
                        // SimpleIni's GetLongValue parses into a 32-bit long on LLP64 and can saturate. Parse the raw
                        // string with std::from_chars and warn-and-default on a bad value. Values with a 0x prefix
                        // are hexadecimal. All other values are decimal.
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
                                detail::defer_diagnostic(
                                    diags,
                                    LogLevel::Warning,
                                    "Config: value '{}' for '{}' is not a valid int (non-numeric or out of "
                                    "range); using default {}.",
                                    raw,
                                    ini_key,
                                    default_value
                                );
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
                        // SimpleIni's GetDoubleValue routes through the locale-dependent strtod: a comma-decimal host
                        // locale silently turns "1.5" into the default. Parse the raw string with the
                        // locale-independent std::from_chars instead, with the int path's warn-and-default discipline.
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
                            // std::from_chars(general) accepts "inf"/"infinity"/"nan". Reject a non-finite result
                            // because it poisons bound arithmetic downstream.
                            if (!fully_consumed || !std::isfinite(parsed))
                            {
                                detail::defer_diagnostic(
                                    diags,
                                    LogLevel::Warning,
                                    "Config: value '{}' for '{}' is not a valid finite float (non-numeric, "
                                    "non-finite, or out of range); using default {}.",
                                    raw,
                                    ini_key,
                                    default_value
                                );
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
                        const char *raw = ini.GetValue(section.c_str(), ini_key.c_str(), nullptr);
                        if (raw == nullptr || raw[0] == '\0')
                        {
                            // If absent or empty, use the default silently. This matches SimpleIni's GetBoolValue.
                            current_value = default_value;
                        }
                        else if (const std::optional<bool> parsed = parse_ini_bool(raw); parsed.has_value())
                        {
                            current_value = *parsed;
                        }
                        else
                        {
                            // If present but unrecognized, diagnose it under the int/float warn-and-default rule.
                            detail::defer_diagnostic(
                                diags,
                                LogLevel::Warning,
                                "Config: value '{}' for '{}' is not a valid bool "
                                "(true/false, yes/no, on/off, 1/0); using default {}.",
                                raw,
                                ini_key,
                                default_value ? "true" : "false"
                            );
                            current_value = default_value;
                        }
                    }
                    else if constexpr (std::same_as<T, std::string>)
                    {
                        current_value = ini.GetValue(section.c_str(), ini_key.c_str(), default_value.c_str());
                    }
                }

                void log_current_value(detail::DeferredDiagnostics &diags) const override
                {
                    if constexpr (std::same_as<T, bool>)
                    {
                        detail::defer_diagnostic(
                            diags,
                            LogLevel::Debug,
                            "Config:   {} = {}",
                            ini_key,
                            current_value ? "true" : "false"
                        );
                    }
                    else if constexpr (std::same_as<T, std::string>)
                    {
                        detail::defer_diagnostic(
                            diags,
                            LogLevel::Debug,
                            "Config:   {} = \"{}\"",
                            ini_key,
                            current_value
                        );
                    }
                    else // int, float
                    {
                        detail::defer_diagnostic(diags, LogLevel::Debug, "Config:   {} = {}", ini_key, current_value);
                    }
                }

                /// Returns a self-contained callback that invokes setter with current_value.
                [[nodiscard]] std::function<void()> take_deferred_apply() const override
                {
                    if (!setter)
                        return {};
                    if constexpr (std::same_as<T, std::string>)
                    {
                        // Capture the owned string by value and hand out a view into that copy.
                        return [fn = setter, val = current_value]() mutable { fn(std::string_view{val}); };
                    }
                    else
                    {
                        return [fn = setter, val = current_value]() mutable { fn(std::move(val)); };
                    }
                }
            };

            // KeyComboList needs an explicit specialization because its parse path differs.
            template <>
            void CallbackConfigItem<input::KeyComboList>::load(CSimpleIniA &ini, detail::DeferredDiagnostics &diags)
            {
                const char *ini_value_str = ini.GetValue(section.c_str(), ini_key.c_str(), nullptr);
                if (ini_value_str != nullptr)
                {
                    current_value = detail::parse_key_combo_list(ini_value_str, diags, log_key_name);
                }
                else
                {
                    current_value = default_value;
                }
            }

            template <>
            void CallbackConfigItem<input::KeyComboList>::log_current_value(detail::DeferredDiagnostics &diags) const
            {
                const std::string formatted = format_key_combo_list(current_value);
                if (formatted.empty())
                {
                    detail::defer_diagnostic(diags, LogLevel::Debug, "Config:   {} = (none)", ini_key);
                }
                else
                {
                    detail::defer_diagnostic(diags, LogLevel::Debug, "Config:   {} = {}", ini_key, formatted);
                }
            }

            // Stores the global registry of configuration items.
            std::mutex &get_config_mutex()
            {
                static std::mutex s_mtx;
                return s_mtx;
            }

            std::vector<std::unique_ptr<ConfigItemBase>> &get_registered_config_items()
            {
                static std::vector<std::unique_ptr<ConfigItemBase>> s_registered_items;
                return s_registered_items;
            }

            // Holds the INI path last passed to load(). Empty until the first load() call, so reload() returns false
            // in that window. Caller must hold get_config_mutex() for every read or write.
            std::string &get_last_loaded_ini_path()
            {
                static std::string s_last_loaded_ini_path;
                return s_last_loaded_ini_path;
            }

        } // anonymous namespace

        namespace detail
        {
            // The config mutex is non-recursive, so callers outside a held config-mutex section use this helper.
            std::string snapshot_last_loaded_ini_path()
            {
                std::lock_guard<std::mutex> lock(get_config_mutex());
                return get_last_loaded_ini_path();
            }
        } // namespace detail

        namespace
        {

            // Stores the content hash from the last successful load. It is std::nullopt before that load and after
            // clear(). Caller must hold get_config_mutex().
            std::optional<std::uint64_t> &get_last_loaded_ini_hash()
            {
                static std::optional<std::uint64_t> s_last_loaded_ini_hash;
                return s_last_loaded_ini_hash;
            }

            // This monotonic counter advances on every registration or re-bind. reload() folds it into the unchanged-
            // content decision, so a bind_* added after a load() hydrates from disk despite unchanged bytes.
            // Caller must hold get_config_mutex().
            std::uint64_t &get_binding_generation() noexcept
            {
                static std::uint64_t s_generation = 0;
                return s_generation;
            }

            // Stores the binding generation from the last successful apply beside the content hash. reload()
            // hash-skips only when BOTH are unchanged. Caller must hold get_config_mutex().
            std::optional<std::uint64_t> &get_applied_binding_generation() noexcept
            {
                static std::optional<std::uint64_t> s_applied_generation;
                return s_applied_generation;
            }

            /**
             * @brief Computes a 64-bit FNV-1a hash over a raw byte range.
             * @details It hashes the
             * pre-parse disk bytes, so SimpleIni's cosmetic churn cannot skew the result.
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
             * @brief Reads all bytes of @p path into memory, or std::nullopt when the file cannot be opened.
             * @details On nullopt, load() proceeds with the bound defaults while reload() clears the cached hash and
             *          retains the last-applied values.
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
                    std::streamsize size = in.tellg();
                    in.seekg(0, std::ios::beg);
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (DetourModKit::detail::g_config_read_seektell_fail.load(std::memory_order_acquire))
                    {
                        // Simulate a failed tellg() so the I/O-failure classification below runs deterministically.
                        in.setstate(std::ios::failbit);
                        size = -1;
                    }
#endif
                    // A seek/tell failure is an I/O failure (nullopt), not a successful empty read. reload() then
                    // retains the last-good values instead of defaults from an empty-file hash.
                    if (!in || size < 0)
                    {
                        return std::nullopt;
                    }
                    if (size == 0)
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

            /// IniLoadOutcome reports the read-hash-parse pipeline result for load() and reload().
            struct IniLoadOutcome
            {
                /// Reports whether the byte read from disk succeeded.
                bool read_succeeded{false};
                /// Reports whether CSimpleIniA::LoadData returned SI_OK.
                bool parse_succeeded{false};
                /// Stores the raw SimpleIni return code when read_succeeded is true.
                SI_Error parse_rc{SI_OK};
                /// Stores the FNV-1a hash of the read bytes.
                std::optional<std::uint64_t> hash;
            };

            /**
             * @brief Reads the INI bytes once, computes their hash, and feeds those exact bytes to
             *        CSimpleIniA::LoadData.
             * @details Closes the TOCTOU window from a LoadFile re-read after the byte snapshot. The hash and parse
             *          reflect the same file state.
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

                // SimpleIni accepts empty buffers (SI_OK). Preserve the hash so an empty file can hash-skip.
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
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (DetourModKit::detail::g_config_parse_fail_once.exchange(false, std::memory_order_acq_rel))
                {
                    // Simulate a transient SimpleIni allocation failure. The seam clears itself before the next retry.
                    outcome.parse_rc = SI_FAIL;
                    outcome.parse_succeeded = false;
                }
#endif
                return outcome;
            }

            /**
             * @brief Replaces an item with the same section+key, or appends if none exists.
             * @note Caller must hold get_config_mutex().
             */
            void replace_or_append(std::unique_ptr<ConfigItemBase> item)
            {
                // Advance the binding generation so reload()'s unchanged-content fast path re-hydrates this item.
                ++get_binding_generation();
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

        } // anonymous namespace

        namespace detail
        {
            // Contract in internal/config_pass.hpp.
            std::filesystem::path get_ini_file_path(const std::string &ini_filename, DeferredDiagnostics &diags)
            {
                std::wstring module_dir = get_runtime_directory();

                if (module_dir.empty() || module_dir == L".")
                {
                    defer_diagnostic(
                        diags,
                        LogLevel::Warning,
                        "Config: Could not reliably determine module directory or it's current working directory. "
                        "Using relative path for INI: {}",
                        ini_filename
                    );
                    return std::filesystem::path(ini_filename);
                }

                try
                {
                    std::filesystem::path ini_path_obj =
                        (std::filesystem::path(module_dir) / ini_filename).lexically_normal();
                    defer_diagnostic(
                        diags,
                        LogLevel::Debug,
                        "Config: Determined INI file path: {}",
                        ini_path_obj.string()
                    );
                    return ini_path_obj;
                }
                catch (const std::filesystem::filesystem_error &fs_err)
                {
                    defer_diagnostic(
                        diags,
                        LogLevel::Warning,
                        "Config: Filesystem error constructing INI path: {}. Using relative path for INI: {}",
                        fs_err.what(),
                        ini_filename
                    );
                }
                catch (const std::exception &e)
                {
                    defer_diagnostic(
                        diags,
                        LogLevel::Warning,
                        "Config: General error constructing INI path: {}. Using relative path for INI: {}",
                        e.what(),
                        ini_filename
                    );
                }
                return std::filesystem::path(ini_filename); // Fallback
            }
        } // namespace detail

        namespace
        {
            // All bind_* functions use the deferred callback pattern. State mutates under get_config_mutex(). The
            // setter runs after release, so a setter can re-enter the data-plane config API with no deadlock.
            // The load()/reload() pass lock is a separate, stricter contract documented on those functions.
            template <typename T>
            void bind_scalar(
                std::string_view section,
                std::string_view ini_key,
                std::string_view log_key_name,
                std::function<void(SetterArg<T>)> setter,
                T default_value
            )
            {
                std::function<void()> deferred;
                {
                    std::lock_guard<std::mutex> lock(get_config_mutex());
                    replace_or_append(
                        std::make_unique<CallbackConfigItem<T>>(
                            std::string(section),
                            std::string(ini_key),
                            std::string(log_key_name),
                            setter,
                            default_value
                        )
                    );
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

        void bind_int(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(int)> setter,
            int default_value
        )
        {
            bind_scalar<int>(section, key, display_name, std::move(setter), default_value);
        }

        void bind_float(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(float)> setter,
            float default_value
        )
        {
            bind_scalar<float>(section, key, display_name, std::move(setter), default_value);
        }

        void bind_bool(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(bool)> setter,
            bool default_value
        )
        {
            bind_scalar<bool>(section, key, display_name, std::move(setter), default_value);
        }

        void bind_string(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(std::string_view)> setter,
            std::string_view default_value
        )
        {
            bind_scalar<std::string>(section, key, display_name, std::move(setter), std::string(default_value));
        }

        void bind_parsed(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::atomic<std::uint32_t> &out,
            std::function<std::uint32_t(std::string_view)> parse,
            std::string_view default_value
        )
        {
            // parse is captured by value so the setter stays valid across every load()/reload(). out is captured by
            // reference and must outlive the registration.
            bind_string(
                section,
                key,
                display_name,
                [&out, parse = std::move(parse)](std::string_view value)
                { out.store(parse(value), std::memory_order_relaxed); },
                default_value
            );
        }

        void bind_log_level(std::string_view section, std::string_view key, std::string_view default_value)
        {
            bind_string(
                section,
                key,
                "Log level",
                [](std::string_view value) { log().set_log_level(string_to_log_level(value)); },
                default_value
            );
        }

        void bind_combos(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(const input::KeyComboList &)> setter,
            std::string_view default_value
        )
        {
            detail::DeferredDiagnostics diags = detail::open_deferred_diagnostics();
            input::KeyComboList default_combos =
                detail::parse_key_combo_list(std::string(default_value), diags, display_name);
            detail::emit_deferred_diagnostics(diags);

            std::function<void()> deferred;
            {
                std::lock_guard<std::mutex> lock(get_config_mutex());
                replace_or_append(
                    std::make_unique<CallbackConfigItem<input::KeyComboList>>(
                        std::string(section),
                        std::string(key),
                        std::string(display_name),
                        setter,
                        default_combos
                    )
                );
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

        void consume_flag(
            std::string_view section,
            std::string_view ini_key,
            std::string_view display_name,
            std::string_view binding_name,
            bool default_value
        )
        {
            // An unknown name makes set_consume a no-op, so registration before the binding exists is safe.
            std::string binding_name_str(binding_name);
            bind_bool(
                section,
                ini_key,
                display_name,
                [binding_name_str](bool consume) { input::Input::instance().set_consume(binding_name_str, consume); },
                default_value
            );
        }

        namespace
        {
            /**
             * @brief Implements the shared path behind press_combo() and hold_combo().
             * @details The helper registers the input binding and wires a combo config item. An INI change rebinds it
             *          on every load() or reload(). It optionally registers the "<ini_key>.Consume" facet. A
             *          registration error logs and yields an inert default guard.
             */
            input::BindingGuard register_combo_fusion(
                input::Trigger trigger,
                std::string_view section,
                std::string_view ini_key,
                std::string_view log_name,
                std::string_view binding_name,
                std::function<void()> on_press,
                std::function<void(bool)> on_state_change,
                std::string_view default_combo,
                std::optional<bool> consume
            )
            {
                const std::string binding_name_str(binding_name);

                // Register the binding with an empty combo set. The combo config item below parses default_combo
                // exactly once and rebinds. A prior parse here duplicates the parse and any typo WARNING.
                input::ComboBinding binding{
                    .name = binding_name_str,
                    .trigger = trigger,
                    .combos = {},
                    .consume = consume.value_or(false),
                    .on_press = std::move(on_press),
                    .on_state_change = std::move(on_state_change),
                };

                input::BindingGuard guard;
                if (auto reg = input::register_combo(std::move(binding)); reg.has_value())
                {
                    guard = std::move(*reg);
                }
                else
                {
                    (void)log().try_log(
                        LogLevel::Error,
                        "Config: failed to register input binding '{}' for '{}'; "
                        "binding will be inert.",
                        binding_name_str,
                        log_name
                    );
                }

                // The setter rebinds the named binding on every load()/reload() without another registration.
                bind_combos(
                    section,
                    ini_key,
                    log_name,
                    [binding_name_str](const input::KeyComboList &combos)
                    { (void)input::Input::instance().rebind(binding_name_str, combos); },
                    default_combo
                );

                // Register the consume facet only after the binding exists. Otherwise its immediate default reaches
                // set_consume()'s unknown-name no-op and is lost.
                if (consume.has_value())
                {
                    consume_flag(
                        section,
                        std::string(ini_key) + ".Consume",
                        std::string(log_name) + " Consume",
                        binding_name_str,
                        *consume
                    );
                }

                return guard;
            }
        } // anonymous namespace

        input::BindingGuard press_combo(
            std::string_view section,
            std::string_view ini_key,
            std::string_view log_name,
            std::string_view binding_name,
            std::function<void()> on_press,
            std::string_view default_combo,
            std::optional<bool> consume
        )
        {
            return register_combo_fusion(
                input::Trigger::Press,
                section,
                ini_key,
                log_name,
                binding_name,
                std::move(on_press),
                nullptr,
                default_combo,
                consume
            );
        }

        input::BindingGuard hold_combo(
            std::string_view section,
            std::string_view ini_key,
            std::string_view log_name,
            std::string_view binding_name,
            std::function<void(bool)> on_state_change,
            std::string_view default_combo,
            std::optional<bool> consume
        )
        {
            return register_combo_fusion(
                input::Trigger::Hold,
                section,
                ini_key,
                log_name,
                binding_name,
                nullptr,
                std::move(on_state_change),
                default_combo,
                consume
            );
        }

        void load(std::string_view ini_filename)
        {
            // Re-arm background reloads. A Logic DLL that (re)loads and calls load() must be able to hot-reload
            // again after an unload latched them off.
            detail::rearm_reloads();

            // Serialize the whole pass (see internal/config_reload_lifecycle.hpp). Fail fast on same-thread re-entry.
            detail::ReloadApplyLock apply_lock;
            if (!apply_lock.engaged())
            {
                (void)log().try_log(
                    LogLevel::Error,
                    "Config: load() re-entered from a bound setter on the same thread; ignoring to "
                    "avoid a self-deadlock. Do not call load()/reload() from a config setter."
                );
                return;
            }

            std::vector<std::function<void()>> deferred_callbacks;
            std::string loaded_resolved_path;
            std::optional<std::uint64_t> hash_to_commit;
            std::uint64_t generation_to_commit = 0;

            // The filename is a caller argument, so the whole path resolution runs before the registry lock.
            detail::DeferredDiagnostics diags = detail::open_deferred_diagnostics();
            std::filesystem::path ini_path = detail::get_ini_file_path(std::string(ini_filename), diags);
            std::string ini_path_str = ini_path.string();
            loaded_resolved_path = ini_path_str;

            {
                std::lock_guard<std::mutex> lock(get_config_mutex());

                CSimpleIniA ini;
                ini.SetUnicode(false);  // Assume ASCII/MBCS INI
                ini.SetMultiKey(false); // Disallow duplicate keys in a section

                IniLoadOutcome outcome = load_ini_into(ini_path, ini);

                if (!outcome.read_succeeded)
                {
                    detail::defer_diagnostic(
                        diags,
                        LogLevel::Error,
                        "Config: Failed to open '{}'. Using defaults.",
                        ini_path_str
                    );
                    // Wipe the cached hash so the next reload() does not short-circuit against a stale value.
                    get_last_loaded_ini_hash().reset();
                }
                else if (!outcome.parse_succeeded)
                {
                    detail::defer_diagnostic(
                        diags,
                        LogLevel::Error,
                        "Config: Failed to parse '{}' (error {}). Using defaults.",
                        ini_path_str,
                        static_cast<int>(outcome.parse_rc)
                    );
                    // Clear the hash: it was computed for bytes that did not parse and must not enable a hash-skip.
                    get_last_loaded_ini_hash().reset();
                }
                else
                {
                    detail::defer_diagnostic(diags, LogLevel::Debug, "Config: Opened {}", ini_path_str);
                    // Do not publish this hash until every deferred setter succeeds.
                    // Reset the prior snapshot so a setter failure cannot suppress an identical-byte retry.
                    get_last_loaded_ini_hash().reset();
                    hash_to_commit = outcome.hash;
                }

                // Read all values under lock, but defer setter callbacks and diagnostics.
                for (const auto &item : get_registered_config_items())
                {
                    item->load(ini, diags);
                    auto cb = item->take_deferred_apply();
                    if (cb)
                    {
                        deferred_callbacks.push_back(std::move(cb));
                    }
                }
                // Snapshot the binding generation for the item set just read. Commit it with the hash.
                generation_to_commit = get_binding_generation();

                // Remember the INI path on every outcome, not just success. A ship-with-defaults first run has no INI
                // on disk yet. enable_auto_reload() needs the recorded path to detect the file after it appears. A
                // failed load resets the hash, and reload() retains the last values, so this path remains safe.
                get_last_loaded_ini_path() = std::string(ini_filename);

                detail::defer_diagnostic(
                    diags,
                    LogLevel::Info,
                    "Config: Loaded {} items from {}",
                    get_registered_config_items().size(),
                    ini_path_str
                );
            }

            detail::emit_deferred_diagnostics(diags);

            // Invoke setters outside the config mutex under the deferred pattern. Setters can re-enter the data-plane
            // API. The held pass lock forbids load()/reload()/disable_auto_reload()/clear() because those calls
            // self-deadlock (see config.hpp). A per-call wrapper lets every later setter run after an exception.
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
                get_applied_binding_generation() = generation_to_commit;
            }

            // Re-point the auto-reload watcher if load() switched the config file out from under it. Otherwise edits
            // to the active file never trigger reload. The stale watcher joins only after pass-lock release, so a
            // queued background reload can finish and let the old watcher exit.
            {
                detail::WatchRepoint repoint = detail::detach_watcher_if_repointed(loaded_resolved_path);

                // Drop the pass lock before the stale-watcher join. Perform the join OUTSIDE both mutexes. The stale
                // worker's final callback can enter disable/enable. A held watcher mutex then causes deadlock.
                apply_lock.unlock();
                repoint.stale.reset();
                if (repoint.repoint)
                {
                    // Deterministically drive disable_auto_reload() into the lost-disable window.
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (const auto hook = DetourModKit::detail::g_config_repoint_window_test_hook)
                    {
                        hook();
                    }
#endif
                    detail::restart_watcher_after_repoint(repoint.debounce, repoint.generation_at_move);
                }
            }
        }

        namespace detail
        {
            // Contract in internal/config_pass.hpp.
            bool reload_impl(bool &out_setters_ran, const BackgroundReloadGuard *background_guard)
            {
                out_setters_ran = false;

                // Serialize the whole pass (see internal/config_reload_lifecycle.hpp). Fail fast on same-thread
                // re-entry.
                ReloadApplyLock apply_lock;
                if (!apply_lock.engaged())
                {
                    (void)DetourModKit::log().try_log(
                        LogLevel::Error,
                        "Config: reload() re-entered from a bound setter on the same thread; ignoring to avoid a "
                        "self-deadlock. Do not call load()/reload() from a config setter."
                    );
                    return false;
                }

                std::vector<std::function<void()>> deferred_callbacks;
                std::string ini_filename;
                std::optional<std::uint64_t> hash_to_commit;
                std::uint64_t generation_to_commit = 0;

                // reload() takes its path from registry state, so resolution stays under the lock and reports through
                // deferred records. The pass emits them immediately after the unlock, before any setter runs.
                DeferredDiagnostics diags = open_deferred_diagnostics();

                // The locked pass returns a value only when it stops early. Every exit path then reaches one emit.
                const std::optional<bool> early_result = [&]() -> std::optional<bool>
                {
                    std::lock_guard<std::mutex> lock(get_config_mutex());

                    ini_filename = get_last_loaded_ini_path();
                    if (ini_filename.empty())
                    {
                        // Without a prior load(), reload has no path to use.
                        return false;
                    }

                    std::filesystem::path ini_path = get_ini_file_path(ini_filename, diags);
                    std::string ini_path_str = ini_path.string();

                    CSimpleIniA ini;
                    ini.SetUnicode(false);
                    ini.SetMultiKey(false);

                    IniLoadOutcome outcome = load_ini_into(ini_path, ini);

                    if (!outcome.read_succeeded)
                    {
                        // A read can fail when another process locks the file mid-save. Clear the cached hash so an
                        // identical-byte retry cannot hash-skip. Return before the setter pass. item->load against the
                        // unpopulated CSimpleIniA replaces live state with defaults.
                        get_last_loaded_ini_hash() = std::nullopt;
                        defer_diagnostic(
                            diags,
                            LogLevel::Warning,
                            "Config: reload() could not open '{}'; retaining last values (setters not "
                            "re-run).",
                            ini_path_str
                        );
                        return true;
                    }

                    {
                        // load_ini_into sets hash whenever read_succeeded, and this is the read_succeeded branch.
                        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
                        const std::uint64_t current_hash = *outcome.hash;
                        generation_to_commit = get_binding_generation();
                        // Skip only when both bytes and binding generation match the last successful apply. A late
                        // bind_* then forces a full setter pass and hydrates from disk.
                        const auto &cached_hash = get_last_loaded_ini_hash();
                        const auto &applied_generation = get_applied_binding_generation();
                        if (cached_hash.has_value() && current_hash == *cached_hash && applied_generation.has_value() &&
                            *applied_generation == generation_to_commit)
                        {
                            defer_diagnostic(
                                diags,
                                LogLevel::Debug,
                                "Config: reload content unchanged (hash {:016x}, binding gen {}); skipping "
                                "setters.",
                                current_hash,
                                generation_to_commit
                            );
                            return true;
                        }

                        if (!outcome.parse_succeeded)
                        {
                            // LoadData accepts any byte content, so a negative code is a transient SimpleIni
                            // allocation failure, not a property of the bytes. Treat it like the read-failure
                            // branch: retain last values and CLEAR the cached hash so the same bytes stay retryable.
                            get_last_loaded_ini_hash() = std::nullopt;
                            defer_diagnostic(
                                diags,
                                LogLevel::Warning,
                                "Config: reload() parse error on '{}' (error {}); retaining last values "
                                "(setters not re-run).",
                                ini_path_str,
                                static_cast<int>(outcome.parse_rc)
                            );
                            return true;
                        }

                        // Drop the previous snapshot now and defer this one, as load() does. A setter failure or
                        // unload-latch interruption leaves partial state. The prior pair lets old bytes hash-skip and
                        // pin that state.
                        get_last_loaded_ini_hash().reset();
                        get_applied_binding_generation().reset();
                        hash_to_commit = current_hash;
                        defer_diagnostic(diags, LogLevel::Debug, "Config: Reloading from {}", ini_path_str);
                    }

                    for (const auto &item : get_registered_config_items())
                    {
                        item->load(ini, diags);
                        auto cb = item->take_deferred_apply();
                        if (cb)
                        {
                            deferred_callbacks.push_back(std::move(cb));
                        }
                    }

                    defer_diagnostic(
                        diags,
                        LogLevel::Info,
                        "Config: Reloaded {} items from {}",
                        get_registered_config_items().size(),
                        ini_path_str
                    );
                    return std::nullopt;
                }();

                emit_deferred_diagnostics(diags);
                if (early_result.has_value())
                {
                    return *early_result;
                }

                // Setters run unlocked (the deferred pattern), each wrapped so one throw cannot block the rest.
                DetourModKit::Logger &logger = DetourModKit::log();
                bool all_setters_applied = true;
                // out_setters_ran comes from the real applied count: a pass that runs none honestly reports it. A
                // setter that throws still counts as invoked.
                bool any_setter_invoked = false;
                for (auto &cb : deferred_callbacks)
                {
                    // Abort early if a Logic DLL unload latched reloads off mid-pass. Every later setter resides in
                    // the Logic DLL under unload. Partial application is acceptable in teardown.
                    if (background_reloads_disabled() || (background_guard != nullptr && !background_guard->current()))
                    {
                        all_setters_applied = false;
                        break;
                    }
                    any_setter_invoked = true;
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
                // The real applied count closes the race where a concurrent load() re-arm clears the latch between
                // an abort and the watcher's downstream re-check.
                out_setters_ran = any_setter_invoked;
                if (all_setters_applied)
                {
                    std::lock_guard<std::mutex> lock(get_config_mutex());
                    get_last_loaded_ini_hash() = hash_to_commit;
                    get_applied_binding_generation() = generation_to_commit;
                }
                return true;
            }
        } // namespace detail

        bool reload()
        {
            bool ignored = false;
            return detail::reload_impl(ignored);
        }

        void log_all()
        {
            detail::DeferredDiagnostics diags = detail::open_deferred_diagnostics();

            {
                std::lock_guard<std::mutex> lock(get_config_mutex());

                const auto &items = get_registered_config_items();
                if (items.empty())
                {
                    detail::defer_diagnostic(diags, LogLevel::Info, "Config: No configuration items registered.");
                }
                else
                {
                    std::unordered_set<std::string_view> sections;
                    for (const auto &item : items)
                    {
                        sections.insert(item->section);
                    }
                    detail::defer_diagnostic(
                        diags,
                        LogLevel::Info,
                        "Config: {} registered values across {} section(s)",
                        items.size(),
                        sections.size()
                    );

                    std::string current_section;
                    for (const auto &item : items)
                    {
                        if (item->section != current_section)
                        {
                            current_section = item->section;
                            detail::defer_diagnostic(diags, LogLevel::Debug, "Config: [{}]", current_section);
                        }
                        item->log_current_value(diags);
                    }
                }
            }

            detail::emit_deferred_diagnostics(diags);
        }

        void clear() noexcept
        {
            Logger &logger = log();

            if (detail::reload_apply_lock_held_by_current_thread() && !detail::on_reload_servicer_thread())
            {
                (void)logger.try_log(
                    LogLevel::Error,
                    "Config: clear() called from a bound setter; ignoring to avoid joining a "
                    "reload worker that may be waiting for the active pass."
                );
                return;
            }

            size_t count = 0;

            {
                std::lock_guard<std::mutex> lock(get_config_mutex());
                count = get_registered_config_items().size();
                if (count > 0)
                {
                    get_registered_config_items().clear();
                }

                // Drop the remembered path, hash, and generation so the next load() starts clean. The watcher's
                // lifecycle stays with disable_auto_reload().
                get_last_loaded_ini_path().clear();
                get_last_loaded_ini_hash().reset();
                get_applied_binding_generation().reset();
            }

            // Move the hotkey guards and servicer out under the watcher mutex. Dispose after unlock. A guard release
            // can wait on a drain whose disposal joins the servicer, whose worker needs this mutex.
            detail::WatchHotkeyControl hotkey_control = detail::detach_hotkey_control();
            detail::dispose_reload_hotkey_guards(hotkey_control.guards);
            // A live hotkey binding's callback capture keeps the servicer alive. Otherwise this reset can be the
            // final drop, which runs outside get_config_mutex so a worker inside reload() cannot deadlock.
            hotkey_control.servicer.reset();

            // Use try_log rather than debug(). A sink exception breaks this noexcept contract.
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

#if defined(DMK_ENABLE_TEST_SEAMS)
    namespace detail
    {
        // Reports whether the registry mutex is free right now. A record producer cannot pass this probe under the
        // same non-recursive mutex.
        bool config_registry_mutex_free_for_test() noexcept
        {
            std::unique_lock<std::mutex> probe(config::get_config_mutex(), std::try_to_lock);
            return probe.owns_lock();
        }
    } // namespace detail
#endif
} // namespace DetourModKit
