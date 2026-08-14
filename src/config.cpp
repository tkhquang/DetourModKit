/**
 * @file config.cpp
 * @brief Implementation of the INI-backed configuration surface and the INI-to-input combo fusion.
 *
 * The config module depends on input, never the reverse. The auto-reload filesystem watcher is a private engine.
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
#include "internal/lifecycle_context.hpp"
#include "internal/lifecycle_reaper.hpp"

#include <SimpleIni.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
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
#if defined(DMK_ENABLE_TEST_SEAMS)
    // Test-only override for the loader-lock probe inside ~ReloadServicer's teardown gate.
    // It replaces only the veto result.
    // The explicit loader context remains the sole authorization.
    // One fixture thread sets and clears this plain function pointer.
    bool (*g_config_reload_loader_lock_override)() noexcept = nullptr;

    // Fires inside load()'s watcher re-point, between the stale-watcher join and replacement start. A test can then
    // place a disable_auto_reload() call in that lock gap deterministically.
    void (*g_config_repoint_window_test_hook)() = nullptr;

    // Forces read_ini_bytes() through its seek/tell failure classification.
    std::atomic<bool> g_config_read_seektell_fail{false};

    // Forces one parse failure so an identical-byte retry can exercise hash invalidation.
    std::atomic<bool> g_config_parse_fail_once{false};

    // Set by ~ReloadServicer on the off-thread reaper branch. A proof can observe self-retirement.
    std::atomic<bool> g_servicer_reaped_on_worker{false};

    // Parks the reload worker while it owns Channel::mutex. A subprocess can drive process-exit teardown after
    // Windows terminates the mutex owner.
    std::atomic<std::atomic<bool> *> g_config_reload_worker_mutex_gate_probe{nullptr};
    std::atomic<bool> g_config_reload_worker_mutex_waiting_probe{false};

    // Parks the reload worker after its last mutex use and before exit-guard publication. A test can keep the body
    // live but unexited across teardown.
    std::atomic<std::atomic<bool> *> g_config_reload_worker_exit_gate_probe{nullptr};

    // Fired immediately before config disposes of an internally retained reload-hotkey BindingGuard.
    void (*g_config_reload_hotkey_guard_disposal_probe)() noexcept = nullptr;
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

            /**
             * @brief Parses a comma-separated string of key combos (OR logic) into a KeyComboList.
             * @details Two opt-out sentinels yield an empty result silently: an empty post-trim input and the literal
             *          "NONE". A non-empty non-sentinel input whose every token fails to parse is a user typo and
             *          emits one WARNING that names @p binding_log_name (or "<unnamed>").
             */
            input::KeyComboList parse_key_combo_list(const std::string &input, std::string_view binding_log_name = {})
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
                    log().warning("Config: combo string \"{}\" for binding '{}' did not parse to any "
                                  "valid keys; binding will be unbound. Use \"\" or \"NONE\" to opt "
                                  "out explicitly.",
                                  effective, name_view);
                }

                return result;
            }

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

                /// Loads the configuration value from the INI file.
                virtual void load(CSimpleIniA &ini, Logger &logger) = 0;

                /// Returns a deferred callback to invoke the setter outside the config mutex, or empty without one.
                [[nodiscard]] virtual std::function<void()> take_deferred_apply() const = 0;

                /// Logs the current value of the configuration item.
                virtual void log_current_value(Logger &logger) const = 0;
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

                CallbackConfigItem(std::string sec, std::string key, std::string log_name,
                                   std::function<void(SetterArg<T>)> set_fn, T def_val)
                    : ConfigItemBase(std::move(sec), std::move(key), std::move(log_name)), setter(std::move(set_fn)),
                      default_value(def_val), current_value(std::move(def_val))
                {
                }

                void load(CSimpleIniA &ini, [[maybe_unused]] Logger &logger) override
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
                                logger.warning("Config: value '{}' for '{}' is not a valid finite float (non-numeric, "
                                               "non-finite, or out of range); using default {}.",
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
                            logger.warning("Config: value '{}' for '{}' is not a valid bool "
                                           "(true/false, yes/no, on/off, 1/0); using default {}.",
                                           raw, ini_key, default_value ? "true" : "false");
                            current_value = default_value;
                        }
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

            // Stores the global registry of configuration items.
            std::mutex &get_config_mutex()
            {
                static std::mutex s_mtx;
                return s_mtx;
            }

            // Serializes an entire reload/load pass (read + content-hash decision + deferred-setter application).
            // Setters run after get_config_mutex() release, so this separate lock prevents stale pass reorder.
            // Two reload drivers can otherwise advance the cached hash before an older pass applies its stale snapshot.
            // Acquire this mutex FIRST, then the config mutex. ReloadApplyLock refuses same-thread re-entry because the
            // lock is non-reentrant.
            std::mutex &get_reload_apply_mutex()
            {
                static std::mutex s_mtx;
                return s_mtx;
            }

            // This thread-local marker detects pass-lock re-entry without publication of a cross-thread owner id.
            bool &reload_apply_lock_held_by_current_thread() noexcept
            {
                thread_local bool s_held = false;
                return s_held;
            }

            /**
             * @class ReloadApplyLock
             * @brief RAII pass lock that fails fast on same-thread re-entry and avoids a self-deadlock.
             * @details A refused lock stays disengaged, which lets the caller report failure without a wait.
             */
            class ReloadApplyLock
            {
            public:
                ReloadApplyLock()
                {
                    if (reload_apply_lock_held_by_current_thread())
                    {
                        // Same-thread re-entry causes a self-deadlock. Do NOT lock. Leave disengaged.
                        return;
                    }
                    m_lock = std::unique_lock<std::mutex>(get_reload_apply_mutex());
                    reload_apply_lock_held_by_current_thread() = true;
                    m_engaged = true;
                }

                ~ReloadApplyLock() noexcept { unlock(); }

                ReloadApplyLock(const ReloadApplyLock &) = delete;
                ReloadApplyLock &operator=(const ReloadApplyLock &) = delete;

                /// Reports true for an acquired pass lock and false for a refused same-thread re-entry.
                [[nodiscard]] bool engaged() const noexcept { return m_engaged; }

                /// Releases the pass lock before load() performs a stale-watcher join. The operation is idempotent.
                void unlock() noexcept
                {
                    if (m_engaged && m_lock.owns_lock())
                    {
                        reload_apply_lock_held_by_current_thread() = false;
                        m_lock.unlock();
                    }
                }

            private:
                std::unique_lock<std::mutex> m_lock;
                bool m_engaged{false};
            };

            // Background-reload quiesce gate (see internal/config_reload_gate.hpp). The unload path stops new passes
            // through the latch and waits for a mid-flight pass through the in-flight count. Bit zero is the unload
            // latch. The remaining even value is the lifecycle epoch. Together they make an unload/rearm transition
            // atomic, so no callback can observe a clear latch with the previous epoch.
            inline constexpr std::uint64_t RELOADS_DISABLED_BIT = 1;

            std::atomic<std::uint64_t> &reload_lifecycle_state() noexcept
            {
                static std::atomic<std::uint64_t> s_state{0};
                return s_state;
            }

            std::atomic<bool> &reload_drain_active() noexcept
            {
                static std::atomic<bool> s_active{false};
                return s_active;
            }

            // Counts background reload passes that execute consumer code. Safe-drain finalization reads this count
            // after the latch store.
            std::atomic<int> &reload_in_flight_count() noexcept
            {
                static std::atomic<int> s_in_flight{0};
                return s_in_flight;
            }

            std::uint64_t current_reload_lifecycle_epoch() noexcept
            {
                return reload_lifecycle_state().load(std::memory_order_seq_cst) & ~RELOADS_DISABLED_BIT;
            }

            bool background_reloads_disabled() noexcept
            {
                return (reload_lifecycle_state().load(std::memory_order_seq_cst) & RELOADS_DISABLED_BIT) != 0;
            }

            /**
             * @class BackgroundReloadGuard
             * @brief RAII entry gate for a background reload pass (watcher callback / hotkey servicer).
             * @details The captured lifecycle epoch must match an enabled @ref reload_lifecycle_state before and
             *          after admission. Otherwise, the pass is dropped before it can call consumer code.
             *          While engaged it holds @ref reload_in_flight_count for the whole pass.
             *          The check / increment / re-check pairs with the drain's latch-store-then-count-load: a pass the
             *          unload path fails to observe also
             *          fails to engage.
             */
            class BackgroundReloadGuard
            {
            public:
                explicit BackgroundReloadGuard(std::uint64_t expected_epoch) noexcept : m_expected_epoch(expected_epoch)
                {
                    if (!lifecycle_current())
                    {
                        return;
                    }
                    reload_in_flight_count().fetch_add(1, std::memory_order_seq_cst);
                    if (!lifecycle_current())
                    {
                        // The unload state changed between the first check and admission. Back out.
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

                /// Returns true when reloads are armed for this lifecycle and this pass can run consumer code.
                [[nodiscard]] bool engaged() const noexcept { return m_engaged; }

                /// True while an admitted pass still belongs to the enabled lifecycle that created it.
                [[nodiscard]] bool current() const noexcept { return m_engaged && lifecycle_current(); }

            private:
                [[nodiscard]] bool lifecycle_current() const noexcept
                {
                    return reload_lifecycle_state().load(std::memory_order_seq_cst) == m_expected_epoch;
                }

                std::uint64_t m_expected_epoch{0};
                bool m_engaged{false};
            };

            [[nodiscard]] bool reload_impl(bool &out_setters_ran,
                                           const BackgroundReloadGuard *background_guard = nullptr);

            std::vector<std::unique_ptr<ConfigItemBase>> &get_registered_config_items()
            {
                static std::vector<std::unique_ptr<ConfigItemBase>> s_registered_items;
                return s_registered_items;
            }

            // Holds the INI path last passed to load(). Empty until the first load() call -- reload() returns false in
            // that window. Caller must hold get_config_mutex() for every read or write.
            std::string &get_last_loaded_ini_path()
            {
                static std::string s_last_loaded_ini_path;
                return s_last_loaded_ini_path;
            }

            // Tear-free snapshot of the last-loaded INI path: takes get_config_mutex() itself and returns a copy.
            // Use at any read site not already inside a held config-mutex section (the mutex is non-recursive).
            [[nodiscard]] std::string snapshot_last_loaded_ini_path()
            {
                std::lock_guard<std::mutex> lock(get_config_mutex());
                return get_last_loaded_ini_path();
            }

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
             * @brief 64-bit FNV-1a hash over a raw byte range.
             * @details Computed on the pre-parse disk bytes so SimpleIni's cosmetic churn cannot skew the result.
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

            // A separate mutex keeps watcher start/stop apart from registration traffic. It also serializes the reload
            // servicer and reload-hotkey guard vector.
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

            // Stores a copy of the user on_reload callback. ConfigWatcher swallows it with no getter, so only this
            // copy lets load()'s re-point reconstruct an equivalent watcher. get_watcher_mutex() guards it.
            std::function<void(bool)> &get_reload_user_callback() noexcept
            {
                static std::function<void(bool)> s_callback;
                return s_callback;
            }

            // Bumped on every real disable_auto_reload() teardown. load()'s re-point captures it before the stale-
            // watcher join and checks it again before restart. A bump in between means a disable raced into the
            // join window and the re-point must NOT resurrect the watcher. A dedicated counter because an empty
            // callback slot is a valid enabled state. Guarded by get_watcher_mutex().
            [[nodiscard]] std::uint64_t &get_watcher_disable_generation() noexcept
            {
                static std::uint64_t s_generation = 0;
                return s_generation;
            }

            // Compares two resolved INI paths without case sensitivity. Separators and normalization already match.
            // An ordinal ASCII fold is correct for case-insensitive Windows paths. A locale fold is
            // deliberately avoided, per the watcher's ordinal filename match.
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

            // Keeps reload-hotkey BindingGuards alive for the process lifetime. ~BindingGuard disables the binding,
            // so a dropped returned guard makes the hotkey a silent no-op forever. Guarded by
            // get_watcher_mutex().
            std::vector<input::BindingGuard> &get_reload_hotkey_guards() noexcept
            {
                static std::vector<input::BindingGuard> s_guards;
                return s_guards;
            }

            void run_reload_hotkey_guard_disposal_probe() noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (const auto probe = DetourModKit::detail::g_config_reload_hotkey_guard_disposal_probe)
                {
                    probe();
                }
#endif
            }

            void dispose_reload_hotkey_guards(std::vector<input::BindingGuard> &guards) noexcept
            {
                if (guards.empty())
                {
                    return;
                }
                run_reload_hotkey_guard_disposal_probe();
                guards.clear();
            }

            // ~ReloadServicer uses this to choose join versus detach-and-leak. This matches the ConfigWatcher
            // destructor's watcher_must_not_block().
            bool reload_servicer_must_not_block() noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                return !DetourModKit::detail::blocking_teardown_permitted(
                    DetourModKit::detail::g_config_reload_loader_lock_override);
#else
                return !DetourModKit::detail::blocking_teardown_permitted();
#endif
            }

            /**
             * @class ReloadServicer
             * @brief Background thread that coalesces reload-hotkey presses and invokes reload() off the input poll
             *        thread, at most once per batch of presses.
             * @details All state the worker touches lives in a heap-owned @ref Channel.
             *          It is separate from the servicer shell. The loader-lock teardown branch can detach the worker
             *          and leak the Channel under the ConfigWatcher discipline. It starts on the first reload_hotkey
             *          call.
             *          A std::shared_ptr prevents a press callback concurrent with shutdown from access to a freed
             *          servicer.
             *          The worker contains exceptions from reload(), so the service remains alive.
             */
            class ReloadServicer
            {
                // Every field the worker thread dereferences. worker is declared LAST so ~Channel destroys it FIRST
                // (request stop + join) before the mutex / cv it uses.
                struct Channel
                {
                    std::mutex mutex;
                    std::condition_variable cv;
                    std::atomic<bool> reload_requested{false};
                    std::atomic<bool> shutdown{false};
                    std::atomic<bool> worker_exited{false};
                    // service_loop publishes this value on entry and clears it on exit. ~ReloadServicer can then detect
                    // a self-join. config::clear() from a reload setter runs on this worker thread.
                    std::atomic<std::thread::id> worker_tid{};
                    // Lifecycle epoch captured at construction so superseded servicers cannot enter consumer code.
                    std::uint64_t birth_epoch{0};
                    std::unique_ptr<DetourModKit::StoppableWorker> worker;
                };

            public:
                ReloadServicer() : m_channel(std::make_unique<Channel>())
                {
                    // Launch the worker against the heap-owned Channel, NOT `this`. The loader-lock teardown branch
                    // leaks the Channel, so the body must use storage that outlives the shell.
                    m_channel->birth_epoch = current_reload_lifecycle_epoch();
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

                    if (reload_servicer_must_not_block())
                    {
                        // The worker can own the Channel mutex when process-exit teardown begins, so publish only the
                        // lock-free shutdown hint and detach without callback invocation. The wake is best-effort by
                        // construction. A servicer parked in cv.wait can stay parked for process lifetime.
                        // This does not strand resources because this branch retains the Channel and module reference.
                        m_channel->shutdown.store(true, std::memory_order_release);
                        m_channel->cv.notify_all();
                        if (m_channel->worker)
                        {
                            m_channel->worker->shutdown();
                        }

                        // The detached service_loop can still read the Channel, so retain it for process lifetime.
                        (void)m_channel.release();
                        DetourModKit::diagnostics::record_intentional_leak(
                            DetourModKit::diagnostics::LeakSubsystem::Worker);
                        return;
                    }

                    // Synchronous teardown is authorized. Serialize the shutdown predicate with the CV wait so the
                    // notification cannot land in its lost-wakeup window.
                    {
                        std::lock_guard<std::mutex> lock(m_channel->mutex);
                        m_channel->shutdown.store(true, std::memory_order_release);
                    }
                    m_channel->cv.notify_all();

                    const bool on_worker =
                        m_channel->worker_tid.load(std::memory_order_acquire) == std::this_thread::get_id();

                    if (on_worker)
                    {
                        // Self-shutdown off the loader lock cannot join this worker from itself because
                        // std::system_error results. Inline Channel destruction frees storage that service_loop uses.
                        // Hand the Channel to the off-thread reaper. It joins the worker, then destroys the Channel.
                        // No permanent leak remains.
#if defined(DMK_ENABLE_TEST_SEAMS)
                        DetourModKit::detail::g_servicer_reaped_on_worker.store(true, std::memory_order_release);
#endif
                        DetourModKit::detail::reap_owner(std::move(m_channel));
                        return;
                    }

                    // Off the loader lock and off the worker thread. shutdown() rechecks the teardown veto, so a join
                    // path can finish as a detach. Observe the body's exit publication, not another TOCTOU-prone veto
                    // check. Retain the Channel while the body remains active, as ~ConfigWatcher does. A leak is the
                    // safe direction.
                    if (m_channel->worker)
                    {
                        m_channel->worker->shutdown();
                    }
                    if (!m_channel->worker_exited.load(std::memory_order_acquire))
                    {
                        (void)m_channel.release();
                        DetourModKit::diagnostics::record_intentional_leak(
                            DetourModKit::diagnostics::LeakSubsystem::Worker);
                        return;
                    }
                    m_channel.reset();
                }

                ReloadServicer(const ReloadServicer &) = delete;
                ReloadServicer &operator=(const ReloadServicer &) = delete;
                ReloadServicer(ReloadServicer &&) = delete;
                ReloadServicer &operator=(ReloadServicer &&) = delete;

                /// Requests a reload without exceptions or allocations. The press callback must not throw.
                void request_reload() noexcept
                {
                    // Mutate the predicate under the channel mutex to close the waiter-side lost-wakeup window.
                    {
                        std::lock_guard<std::mutex> lock(m_channel->mutex);
                        m_channel->reload_requested.store(true, std::memory_order_release);
                    }
                    m_channel->cv.notify_one();
                }

                /// Requests worker stop without a join or callback-storage destruction.
                void request_stop() noexcept
                {
                    if (!m_channel)
                    {
                        return;
                    }
                    {
                        std::lock_guard<std::mutex> lock(m_channel->mutex);
                        m_channel->shutdown.store(true, std::memory_order_release);
                    }
                    m_channel->cv.notify_all();
                    if (m_channel->worker)
                    {
                        m_channel->worker->request_stop();
                    }
                }

                /// Returns true after worker body exit.
                [[nodiscard]] bool has_exited() const noexcept
                {
                    return m_channel != nullptr && m_channel->worker_exited.load(std::memory_order_acquire);
                }

                /**
                 * @brief Reports whether @p id is the servicer worker thread's id.
                 * @details Any teardown that can join this worker must query this first and skip. Otherwise it
                 *          self-joins or deadlocks. The default id never matches, so a reset slot cannot alias a live
                 *          query.
                 */
                [[nodiscard]] bool is_worker_thread(std::thread::id id) const noexcept
                {
                    if (!m_channel)
                    {
                        return false;
                    }
                    const std::thread::id worker = m_channel->worker_tid.load(std::memory_order_acquire);
                    return worker != std::thread::id{} && worker == id;
                }

            private:
                static void service_loop(Channel &channel, std::stop_token st) noexcept
                {
                    class ExitGuard
                    {
                    public:
                        explicit ExitGuard(Channel &owned_channel) noexcept : m_channel(owned_channel) {}
                        ~ExitGuard() noexcept
                        {
                            m_channel.worker_tid.store(std::thread::id{}, std::memory_order_release);
                            m_channel.worker_exited.store(true, std::memory_order_release);
                        }

                        ExitGuard(const ExitGuard &) = delete;
                        ExitGuard &operator=(const ExitGuard &) = delete;

                    private:
                        Channel &m_channel;
                    };

                    const ExitGuard exit_guard{channel};
                    DetourModKit::Logger &logger = DetourModKit::log();

                    // Publish our thread id for ~ReloadServicer's self-join detection. Clear it on exit so a later
                    // OS-recycled id cannot alias a dead worker.
                    channel.worker_tid.store(std::this_thread::get_id(), std::memory_order_release);

                    // Wake the CV on a stop request so the blocked wait exits promptly.
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
#if defined(DMK_ENABLE_TEST_SEAMS)
                            if (auto *gate = DetourModKit::detail::g_config_reload_worker_mutex_gate_probe.load(
                                    std::memory_order_acquire))
                            {
                                DetourModKit::detail::g_config_reload_worker_mutex_waiting_probe.store(
                                    true, std::memory_order_release);
                                while (gate->load(std::memory_order_acquire))
                                {
                                    std::this_thread::yield();
                                }
                                DetourModKit::detail::g_config_reload_worker_mutex_waiting_probe.store(
                                    false, std::memory_order_release);
                            }
#endif
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

                        // Coalesce: a burst of presses during the reload collapses into at most one follow-up pass.
                        while (channel.reload_requested.exchange(false, std::memory_order_acq_rel))
                        {
                            // Gate on the unload latch and this servicer's lifecycle epoch. Do not run setters into a
                            // Logic DLL under unload or a re-armed registry that belongs to a newer one.
                            BackgroundReloadGuard reload_guard{channel.birth_epoch};
                            if (!reload_guard.engaged())
                            {
                                break;
                            }
                            try
                            {
                                bool setters_ran = false;
                                (void)reload_impl(setters_ran, &reload_guard);
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

#if defined(DMK_ENABLE_TEST_SEAMS)
                    // Holds the body between its last channel.mutex use and the exit guard below. A concurrent teardown
                    // observes a worker that is provably live and lacks an exit publication.
                    if (auto *gate = DetourModKit::detail::g_config_reload_worker_exit_gate_probe.load(
                            std::memory_order_acquire))
                    {
                        while (gate->load(std::memory_order_acquire))
                        {
                            std::this_thread::yield();
                        }
                    }
#endif
                }

                std::unique_ptr<Channel> m_channel;
            };

            // A shared_ptr lets a press callback keep its own strong reference when clear() resets the slot.
            std::shared_ptr<ReloadServicer> &get_reload_servicer() noexcept
            {
                static std::shared_ptr<ReloadServicer> s_servicer;
                return s_servicer;
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

            /// Determines the full absolute path for the INI configuration file.
            std::filesystem::path get_ini_file_path(const std::string &ini_filename, Logger &logger)
            {
                std::wstring module_dir = get_runtime_directory();

                if (module_dir.empty() || module_dir == L".")
                {
                    logger.warning(
                        "Config: Could not reliably determine module directory or it's current working directory. "
                        "Using relative path for INI: {}",
                        ini_filename);
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

            // All bind_* functions use the deferred callback pattern. State mutates under get_config_mutex(). The
            // setter runs after release, so a setter can re-enter the data-plane config API with no deadlock.
            // The load()/reload() pass lock is a separate, stricter contract documented on those functions.
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
            // parse is captured by value so the setter stays valid across every load()/reload(). out is captured by
            // reference and must outlive the registration.
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
            // An unknown name makes set_consume a no-op, so registration before the binding exists is safe.
            std::string binding_name_str(binding_name);
            bind_bool(
                section, ini_key, display_name, [binding_name_str](bool consume)
                { input::Input::instance().set_consume(binding_name_str, consume); }, default_value);
        }

        namespace
        {
            // Creates and starts an auto-reload watcher on an already-resolved path, then connects the persisted user
            // callback. Precondition: get_watcher_mutex() is held. Forward-declared for load()'s re-point.
            [[nodiscard]] AutoReloadStatus start_watcher_locked(const std::string &resolved_path,
                                                                std::chrono::milliseconds debounce);

            /**
             * @brief Shared implementation behind press_combo() and hold_combo().
             * @details Registers the input binding and wires a combo config item. An INI change rebinds it on every
             *          load() or reload(). It optionally registers the "<ini_key>.Consume" facet. Fail-soft: a
             *          registration error logs and yields an inert default guard.
             */
            input::BindingGuard register_combo_fusion(input::Trigger trigger, std::string_view section,
                                                      std::string_view ini_key, std::string_view log_name,
                                                      std::string_view binding_name, std::function<void()> on_press,
                                                      std::function<void(bool)> on_state_change,
                                                      std::string_view default_combo, std::optional<bool> consume)
            {
                const std::string binding_name_str(binding_name);

                // Register the binding with an empty combo set. The combo config item below parses default_combo
                // exactly once and rebinds. A prior parse here duplicates the parse and any typo WARNING.
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

                // The setter rebinds the named binding on every load()/reload() without another registration.
                bind_combos(
                    section, ini_key, log_name, [binding_name_str](const input::KeyComboList &combos)
                    { (void)input::Input::instance().rebind(binding_name_str, combos); }, default_combo);

                // Register the consume facet only after the binding exists. Otherwise its immediate default reaches
                // set_consume()'s unknown-name no-op and is lost.
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
            // Re-arm background reloads. A Logic DLL that (re)loads and calls load() must be able to hot-reload
            // again after an unload latched them off.
            detail::rearm_reloads();

            // Serialize the whole pass (see get_reload_apply_mutex()). Fail fast on same-thread re-entry.
            ReloadApplyLock apply_lock;
            if (!apply_lock.engaged())
            {
                (void)log().try_log(LogLevel::Error,
                                    "Config: load() re-entered from a bound setter on the same thread; ignoring to "
                                    "avoid a self-deadlock. Do not call load()/reload() from a config setter.");
                return;
            }

            std::vector<std::function<void()>> deferred_callbacks;
            std::string loaded_resolved_path;
            std::optional<std::uint64_t> hash_to_commit;
            std::uint64_t generation_to_commit = 0;

            {
                std::lock_guard<std::mutex> lock(get_config_mutex());

                Logger &logger = log();
                std::filesystem::path ini_path = get_ini_file_path(std::string(ini_filename), logger);
                std::string ini_path_str = ini_path.string();
                loaded_resolved_path = ini_path_str;
                CSimpleIniA ini;
                ini.SetUnicode(false);  // Assume ASCII/MBCS INI
                ini.SetMultiKey(false); // Disallow duplicate keys in a section

                IniLoadOutcome outcome = load_ini_into(ini_path, ini);

                if (!outcome.read_succeeded)
                {
                    logger.error("Config: Failed to open '{}'. Using defaults.", ini_path_str);
                    // Wipe the cached hash so the next reload() does not short-circuit against a stale value.
                    get_last_loaded_ini_hash().reset();
                }
                else if (!outcome.parse_succeeded)
                {
                    logger.error("Config: Failed to parse '{}' (error {}). Using defaults.", ini_path_str,
                                 static_cast<int>(outcome.parse_rc));
                    // Clear the hash: it was computed for bytes that did not parse and must not enable a hash-skip.
                    get_last_loaded_ini_hash().reset();
                }
                else
                {
                    logger.debug("Config: Opened {}", ini_path_str);
                    // Do not publish this hash until every deferred setter succeeds.
                    // Reset the prior snapshot so a setter failure cannot suppress an identical-byte retry.
                    get_last_loaded_ini_hash().reset();
                    hash_to_commit = outcome.hash;
                }

                // Read all values under lock, but defer setter callbacks.
                for (const auto &item : get_registered_config_items())
                {
                    item->load(ini, logger);
                    auto cb = item->take_deferred_apply();
                    if (cb)
                    {
                        deferred_callbacks.push_back(std::move(cb));
                    }
                }
                // Snapshot the binding generation for the item set just read. Commit it with the hash.
                generation_to_commit = get_binding_generation();

                // Remember the INI path on every outcome, not just success. A ship-with-defaults first run has no INI
                // on disk yet. enable_auto_reload() needs the recorded path to detect the file after it appears. Safe
                // because a failed load resets the hash and reload() retains last values.
                get_last_loaded_ini_path() = std::string(ini_filename);

                logger.info("Config: Loaded {} items from {}", get_registered_config_items().size(), ini_path_str);
            }

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
                std::unique_ptr<DetourModKit::detail::ConfigWatcher> stale_watcher;
                bool repoint = false;
                std::chrono::milliseconds saved_debounce{};
                std::uint64_t disable_generation_at_move = 0;
                {
                    std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                    auto &watcher = get_config_watcher();
                    if (watcher)
                    {
                        if (!resolved_paths_equivalent(watcher->ini_path(), loaded_resolved_path))
                        {
                            if (watcher->is_worker_thread(std::this_thread::get_id()))
                            {
                                // Inline watcher destruction self-joins the worker. Log and skip the re-point under
                                // disable_auto_reload()'s self-join rule.
                                (void)log().try_log(
                                    LogLevel::Error,
                                    "Config: load() switched the config file on the watcher thread; not "
                                    "re-pointing auto-reload to avoid a self-join. Re-point from another "
                                    "thread via disable_auto_reload()/enable_auto_reload().");
                            }
                            else
                            {
                                // Move the stale watcher out and preserve the persisted user callback for restart.
                                // Snapshot the disable generation under this lock for the lost-disable window check.
                                saved_debounce = watcher->debounce();
                                disable_generation_at_move = get_watcher_disable_generation();
                                stale_watcher = std::move(watcher);
                                repoint = true;
                            }
                        }
                    }
                }

                // Drop the pass lock before the stale-watcher join. Perform the join OUTSIDE both mutexes. The stale
                // worker's final callback can enter disable/enable. A held get_watcher_mutex() then causes deadlock.
                apply_lock.unlock();
                stale_watcher.reset();
                if (repoint)
                {
                    // Deterministically drive disable_auto_reload() into the lost-disable window.
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (const auto hook = DetourModKit::detail::g_config_repoint_window_test_hook)
                    {
                        hook();
                    }
#endif
                    // Re-snapshot the latest remembered path and re-start under get_watcher_mutex(). A disable
                    // generation bump since the move-out means a disable raced into the join window: honor it and
                    // leave auto-reload OFF. The re-check and construction are one atomic step under the held lock.
                    const std::string repoint_filename = snapshot_last_loaded_ini_path();
                    std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                    if (!repoint_filename.empty() && get_watcher_disable_generation() == disable_generation_at_move)
                    {
                        const std::filesystem::path repoint_path = get_ini_file_path(repoint_filename, log());
                        (void)start_watcher_locked(repoint_path.string(), saved_debounce);
                    }
                }
            }
        }

        namespace
        {
            /**
             * @brief Internal reload implementation that also reports whether setters actually ran.
             * @param[out] out_setters_ran True once at least one deferred setter is invoked. False when the hash
             *                             skip, a read/parse failure, an empty setter list, or an unload latch
             *                             stopped the pass before the first setter.
             * @return true if a previous load() path was available. False if reload() preceded any load().
             */
            bool reload_impl(bool &out_setters_ran, const BackgroundReloadGuard *background_guard)
            {
                out_setters_ran = false;

                // Serialize the whole pass (see get_reload_apply_mutex()). Fail fast on same-thread re-entry.
                ReloadApplyLock apply_lock;
                if (!apply_lock.engaged())
                {
                    (void)DetourModKit::log().try_log(
                        LogLevel::Error,
                        "Config: reload() re-entered from a bound setter on the same thread; ignoring to avoid a "
                        "self-deadlock. Do not call load()/reload() from a config setter.");
                    return false;
                }

                std::vector<std::function<void()>> deferred_callbacks;
                std::string ini_filename;
                std::optional<std::uint64_t> hash_to_commit;
                std::uint64_t generation_to_commit = 0;

                {
                    std::lock_guard<std::mutex> lock(get_config_mutex());

                    ini_filename = get_last_loaded_ini_path();
                    if (ini_filename.empty())
                    {
                        // No prior load(), nothing to reload.
                        return false;
                    }

                    DetourModKit::Logger &logger = DetourModKit::log();
                    std::filesystem::path ini_path = get_ini_file_path(ini_filename, logger);
                    std::string ini_path_str = ini_path.string();

                    CSimpleIniA ini;
                    ini.SetUnicode(false);
                    ini.SetMultiKey(false);

                    IniLoadOutcome outcome = load_ini_into(ini_path, ini);

                    if (!outcome.read_succeeded)
                    {
                        // Read failure (e.g. locked mid-save). Clear the cached hash so an identical-byte retry
                        // cannot hash-skip. Return before the setter pass. item->load against the unpopulated
                        // CSimpleIniA replaces live state with defaults.
                        get_last_loaded_ini_hash() = std::nullopt;
                        logger.warning("Config: reload() could not open '{}'; retaining last values (setters not "
                                       "re-run).",
                                       ini_path_str);
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
                            logger.debug("Config: reload content unchanged (hash {:016x}, binding gen {}); skipping "
                                         "setters.",
                                         current_hash, generation_to_commit);
                            return true;
                        }

                        if (!outcome.parse_succeeded)
                        {
                            // LoadData accepts any byte content, so a negative code is a transient SimpleIni
                            // allocation failure, not a property of the bytes. Treat it like the read-failure
                            // branch: retain last values and CLEAR the cached hash so the same bytes stay retryable.
                            get_last_loaded_ini_hash() = std::nullopt;
                            logger.warning("Config: reload() parse error on '{}' (error {}); retaining last values "
                                           "(setters not re-run).",
                                           ini_path_str, static_cast<int>(outcome.parse_rc));
                            return true;
                        }

                        // Drop the previous snapshot now and defer this one, as load() does. A setter failure or
                        // unload-latch interruption leaves partial state. The prior pair lets old bytes hash-skip and
                        // pin that state.
                        get_last_loaded_ini_hash().reset();
                        get_applied_binding_generation().reset();
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

            [[nodiscard]] AutoReloadStatus start_watcher_locked(const std::string &resolved_path,
                                                                std::chrono::milliseconds debounce)
            {
                // Precondition: get_watcher_mutex() is held. enable_auto_reload() and load()'s re-point funnel
                // through this single construction site, so the presence guard and construction are atomic.
                auto &watcher = get_config_watcher();
                if (background_reloads_disabled())
                {
                    return AutoReloadStatus::StartFailed;
                }
                // Guard on existence, not is_running(). A second caller otherwise can overwrite the unique_ptr before
                // the worker publishes its active state.
                if (watcher)
                {
                    log().warning("Config: Auto-reload watcher start skipped because a watcher is already present; "
                                  "call disable_auto_reload() first.");
                    return AutoReloadStatus::AlreadyRunning;
                }

                // Copy the persisted user callback into the reload lambda. The persisted slot must survive. A later
                // load()-driven re-point can then reconstruct an equivalent watcher.
                watcher = std::make_unique<DetourModKit::detail::ConfigWatcher>(
                    resolved_path, debounce,
                    [user_cb = get_reload_user_callback(), birth_epoch = current_reload_lifecycle_epoch()]()
                    {
                        // Gate the whole pass on the unload latch and this watcher's lifecycle epoch. The guard holds
                        // the in-flight count across BOTH the setter pass and the user callback.
                        BackgroundReloadGuard reload_guard{birth_epoch};
                        if (!reload_guard.engaged())
                        {
                            return;
                        }
                        // Reload first so the user callback observes the refreshed values. setters_ran lets it
                        // distinguish a real reload from a skipped setter pass.
                        bool setters_ran = false;
                        (void)reload_impl(setters_ran, &reload_guard);
                        // Re-check the latch. An unload can set it during the pass.
                        if (user_cb && reload_guard.current())
                        {
                            user_cb(setters_ran);
                        }
                    });

                if (!watcher->start())
                {
                    log().error("Config: Auto-reload watcher failed to start for {}", resolved_path);
                    watcher.reset();
                    // Drop the persisted callback with the failed watcher so it cannot pin Logic DLL references.
                    get_reload_user_callback() = nullptr;
                    return AutoReloadStatus::StartFailed;
                }
                return AutoReloadStatus::Started;
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
                reload_lifecycle_state().fetch_or(RELOADS_DISABLED_BIT, std::memory_order_seq_cst);
            }

            ReloadDrainStatus begin_reload_drain() noexcept
            {
                if (reload_apply_lock_held_by_current_thread())
                {
                    return ReloadDrainStatus::SelfDelivery;
                }

                bool expected = false;
                if (!reload_drain_active().compare_exchange_strong(expected, true, std::memory_order_seq_cst))
                {
                    return ReloadDrainStatus::InProgress;
                }
                disable_reloads_for_unload();

                // Never wait for the control-plane lock here: finish_reload_drain owns the caller's deadline, and
                // the disabled lifecycle latch already prevents worker entry into consumer code.
                std::unique_lock<std::mutex> lock(get_watcher_mutex(), std::try_to_lock);
                if (!lock.owns_lock())
                {
                    return ReloadDrainStatus::Ready;
                }

                const auto &watcher = get_config_watcher();
                const auto &servicer = get_reload_servicer();
                if ((watcher && watcher->is_worker_thread(std::this_thread::get_id())) ||
                    (servicer && servicer->is_worker_thread(std::this_thread::get_id())))
                {
                    reload_drain_active().store(false, std::memory_order_seq_cst);
                    return ReloadDrainStatus::SelfDelivery;
                }

                if (watcher)
                {
                    watcher->request_stop();
                }
                if (servicer)
                {
                    servicer->request_stop();
                }
                return ReloadDrainStatus::Ready;
            }

            ReloadDrainStatus finish_reload_drain(std::chrono::steady_clock::time_point deadline) noexcept
            {
                std::unique_ptr<DetourModKit::detail::ConfigWatcher> watcher_to_drop;
                std::shared_ptr<ReloadServicer> servicer_to_drop;
                std::function<void(bool)> callback_to_drop;
                std::vector<input::BindingGuard> guards_to_drop;
                while (true)
                {
                    std::unique_lock<std::mutex> lock(get_watcher_mutex(), std::try_to_lock);
                    if (lock.owns_lock())
                    {
                        const auto &watcher = get_config_watcher();
                        const auto &servicer = get_reload_servicer();
                        // Control-mutex contention can hide this identity from begin_reload_drain.
                        if ((watcher && watcher->is_worker_thread(std::this_thread::get_id())) ||
                            (servicer && servicer->is_worker_thread(std::this_thread::get_id())))
                        {
                            reload_drain_active().store(false, std::memory_order_seq_cst);
                            return ReloadDrainStatus::SelfDelivery;
                        }
                        if (watcher)
                        {
                            watcher->request_stop();
                        }
                        if (servicer)
                        {
                            servicer->request_stop();
                        }
                        const bool workers_exited =
                            (!watcher || watcher->has_exited()) && (!servicer || servicer->has_exited());
                        if (workers_exited && reload_in_flight_count().load(std::memory_order_seq_cst) == 0)
                        {
                            watcher_to_drop = std::move(get_config_watcher());
                            servicer_to_drop = std::move(get_reload_servicer());
                            callback_to_drop = std::move(get_reload_user_callback());
                            guards_to_drop = std::move(get_reload_hotkey_guards());
                            ++get_watcher_disable_generation();
                            break;
                        }
                    }
                    if (std::chrono::steady_clock::now() >= deadline)
                    {
                        reload_drain_active().store(false, std::memory_order_seq_cst);
                        return ReloadDrainStatus::TimedOut;
                    }
                    std::this_thread::yield();
                }

                if (watcher_to_drop)
                {
                    watcher_to_drop->stop();
                    watcher_to_drop.reset();
                }
                dispose_reload_hotkey_guards(guards_to_drop);
                servicer_to_drop.reset();
                callback_to_drop = nullptr;
                config::clear();
                reload_drain_active().store(false, std::memory_order_seq_cst);
                return ReloadDrainStatus::Ready;
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            bool await_reloads_quiesced_for_test(std::chrono::milliseconds timeout) noexcept
            {
                const auto deadline = std::chrono::steady_clock::now() + timeout;
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
#endif

            void rearm_reloads() noexcept
            {
                if (reload_drain_active().load(std::memory_order_seq_cst))
                {
                    return;
                }
                // Advance the epoch and clear a set latch in one compare-exchange. An ordinary load while already
                // enabled changes nothing. The in-flight count balances its own admitted older passes.
                std::uint64_t state = reload_lifecycle_state().load(std::memory_order_seq_cst);
                while ((state & RELOADS_DISABLED_BIT) != 0)
                {
                    const std::uint64_t next_epoch = state + 1;
                    if (reload_lifecycle_state().compare_exchange_weak(state, next_epoch, std::memory_order_seq_cst))
                    {
                        return;
                    }
                }
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

            // Resolve to the same absolute path load() uses.
            std::filesystem::path ini_path = get_ini_file_path(ini_filename, logger);
            std::string resolved_path = ini_path.string();

            // Hold get_watcher_mutex() across publish-callback-then-start: a bounded start() stall is preferable to
            // a use-after-free if disable_auto_reload() destroyed the watcher mid-start().
            AutoReloadStatus status;
            {
                std::lock_guard<std::mutex> wlock(get_watcher_mutex());

                if (background_reloads_disabled())
                {
                    return AutoReloadStatus::StartFailed;
                }

                // On a duplicate enable attempt, preserve the live watcher's callback. A new callback publication
                // before this check makes a later re-point switch callbacks silently.
                if (get_config_watcher())
                {
                    logger.warning("Config: enable_auto_reload() called while a watcher is already present; "
                                   "call disable_auto_reload() first.");
                    return AutoReloadStatus::AlreadyRunning;
                }

                // Persist a copy of the user callback for load()'s re-point, published under the watcher mutex
                // before the construction helper reads it.
                get_reload_user_callback() = std::move(on_reload);

                status = start_watcher_locked(resolved_path, debounce);
            }

            if (status != AutoReloadStatus::Started)
            {
                return status;
            }

            logger.info("Config: Auto-reload enabled for {} (debounce {} ms)", resolved_path,
                        static_cast<long long>(debounce.count()));
            return AutoReloadStatus::Started;
        }

        void disable_auto_reload() noexcept
        {
            // A watcher join from a bound setter blocks on its final flush, which re-enters reload_impl and waits for
            // the pass lock this thread holds. Refuse to avoid deadlock.
            if (reload_apply_lock_held_by_current_thread())
            {
                (void)log().try_log(LogLevel::Error,
                                    "Config: disable_auto_reload() called from a bound setter; ignoring to avoid "
                                    "joining a watcher that may be waiting for the active reload pass.");
                return;
            }

            std::unique_ptr<DetourModKit::detail::ConfigWatcher> to_drop;
            {
                std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                auto &watcher = get_config_watcher();
                // Inline unique_ptr destruction on the watcher thread forces the worker to join itself. Log and
                // return. To cancel inside a reload, release the binding guard or flip a caller-owned flag.
                if (watcher && watcher->is_worker_thread(std::this_thread::get_id()))
                {
                    (void)log().try_log(
                        LogLevel::Error,
                        "Config: disable_auto_reload() called from the watcher thread; ignoring to avoid self-join "
                        "deadlock. Call from a different thread or disable the hotkey binding instead.");
                    return;
                }
                to_drop = std::move(watcher);
                // Drop the persisted re-point callback with its watcher so it cannot pin Logic DLL references.
                get_reload_user_callback() = nullptr;
                // Signal a load() re-point in its lost-disable window so it does not resurrect the watcher.
                ++get_watcher_disable_generation();
            }
            // ~ConfigWatcher joins its worker outside our mutex.
        }

        bool reload_hotkey(std::string_view ini_key, std::string_view default_combo)
        {
            // An empty or opt-out default leaves the hotkey inert. Return false to expose that state.
            if (default_combo.empty())
            {
                log().warning("Config: reload_hotkey('{}', '<empty>') rejected; provide a non-empty default combo.",
                              std::string(ini_key));
                return false;
            }

            // Pre-parse the default. The parser emits its own typo WARNING, and a NONE opt-out still returns false.
            const input::KeyComboList parsed = parse_key_combo_list(std::string(default_combo), "Config reload hotkey");
            if (parsed.empty())
            {
                return false;
            }

            // Stable binding name keyed off the INI key so repeat registrations update in place.
            std::string binding_name = "config_reload:" + std::string(ini_key);

            // Lazily spin up the reload servicer on the first hotkey registration, under get_watcher_mutex().
            std::shared_ptr<ReloadServicer> servicer;
            {
                std::lock_guard<std::mutex> lock(get_watcher_mutex());
                if (background_reloads_disabled())
                {
                    return false;
                }
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
                    // Press callbacks run on the poll thread and must return promptly. Defer the reload to the
                    // servicer thread. The shared_ptr capture keeps the servicer alive.
                    if (servicer)
                    {
                        servicer->request_reload();
                    }
                },
                default_combo, std::nullopt);
            input::BindingGuard replaced_guard;
            bool replaced_existing = false;

            // Store the guard under the watcher mutex so its destructor does not disable the binding. Replace any
            // prior guard for the same INI key. Release the replaced guard outside the mutex. A release under this
            // mutex can wait on an unload drain whose callable disposal joins a worker that needs the same mutex.
            {
                std::lock_guard<std::mutex> lock(get_watcher_mutex());
                if (background_reloads_disabled())
                {
                    return false;
                }
                auto &guards = get_reload_hotkey_guards();
                for (auto it = guards.begin(); it != guards.end(); ++it)
                {
                    if (it->name() == binding_name)
                    {
                        replaced_guard = std::move(*it);
                        replaced_existing = true;
                        guards.erase(it);
                        break;
                    }
                }
                guards.emplace_back(std::move(guard));
            }
            if (replaced_existing)
            {
                run_reload_hotkey_guard_disposal_probe();
                replaced_guard.release();
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

            if (reload_apply_lock_held_by_current_thread())
            {
                bool on_servicer_thread = false;
                {
                    std::lock_guard<std::mutex> lock(get_watcher_mutex());
                    const std::shared_ptr<ReloadServicer> &servicer = get_reload_servicer();
                    on_servicer_thread = servicer && servicer->is_worker_thread(std::this_thread::get_id());
                }
                if (!on_servicer_thread)
                {
                    (void)logger.try_log(LogLevel::Error,
                                         "Config: clear() called from a bound setter; ignoring to avoid joining a "
                                         "reload worker that may be waiting for the active pass.");
                    return;
                }
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
            std::vector<input::BindingGuard> guards_to_drop;
            std::shared_ptr<ReloadServicer> servicer_to_drop;
            {
                std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                guards_to_drop = std::move(get_reload_hotkey_guards());
                servicer_to_drop = std::move(get_reload_servicer());
            }
            dispose_reload_hotkey_guards(guards_to_drop);
            // A live hotkey binding's callback capture keeps the servicer alive. Otherwise this reset can be the
            // final drop, which runs outside get_config_mutex so a worker inside reload() cannot deadlock.
            servicer_to_drop.reset();

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
        // Requests one servicer-thread reload without synthetic key input. Returns false if no servicer exists.
        bool request_servicer_reload_for_test() noexcept
        {
            std::shared_ptr<config::ReloadServicer> servicer;
            {
                std::lock_guard<std::mutex> lock(config::get_watcher_mutex());
                servicer = config::get_reload_servicer();
            }
            if (!servicer)
            {
                return false;
            }
            servicer->request_reload();
            return true;
        }

        void lock_config_watcher_mutex_for_test() noexcept
        {
            std::lock_guard<std::mutex> lock(config::get_watcher_mutex());
        }
    } // namespace detail
#endif
} // namespace DetourModKit
