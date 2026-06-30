#ifndef DETOURMODKIT_CONFIG_HPP
#define DETOURMODKIT_CONFIG_HPP

/**
 * @file config.hpp
 * @brief INI-backed configuration binding, hot-reload, and the INI-to-input combo fusion.
 * @details Binds INI keys to atomics, callbacks, and the logger, loads and hot-reloads an INI file, and fuses an INI
 *          key to a live input combo binding (config depends on input, never the reverse). The filesystem watcher that
 *          drives auto-reload is folded in: there is no separate watcher header, only enable_auto_reload /
 *          disable_auto_reload over an engine living under src/internal/.
 *
 *          Config is deliberately fail-soft: a missing or malformed INI key falls back to the registered default and
 *          is logged, never reported as an error, so the bind / load / reload surface speaks void / bool /
 *          AutoReloadStatus rather than Result. Only the input combo fusion returns an input::BindingGuard.
 *
 *          The free functions operate on the process configuration registry. SectionBinder is a section-scoped view
 *          that drops the repeated section argument, and Ini is a thin handle exposing the same operations plus
 *          section(); both forward to the same process registry.
 *
 * @note Thread safety: every bind / load / reload uses a deferred-callback pattern -- registry state is read and
 *       written under the config mutex, but setter callbacks run after the mutex is released. A setter may therefore
 *       call back into the config API without deadlocking, so no reentrancy guard is needed.
 */

#include "DetourModKit/input.hpp"

#include <atomic>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace DetourModKit
{
    namespace config
    {
        /**
         * @enum AutoReloadStatus
         * @brief Outcome of a call to enable_auto_reload().
         */
        enum class AutoReloadStatus
        {
            /// The watcher is now running.
            Started,
            /// Called while a watcher was already installed; the existing one was kept.
            AlreadyRunning,
            /// load() was never called, so there is no path to watch.
            NoPriorLoad,
            /// The parent directory could not be opened or the start handshake failed.
            StartFailed
        };

        /// Constrains the atomic-backed bind to the scalar types the INI pipeline parses directly.
        template <typename T>
        concept BindableScalar = std::same_as<T, int> || std::same_as<T, bool> || std::same_as<T, float>;

        /**
         * @brief Binds an integer INI key to a callback.
         * @details The setter is invoked immediately with @p default_value and again on every load() / reload() with
         *          the parsed INI value. Integers are parsed with a hardened decimal/hex parser (range-checked) rather
         *          than the underlying INI library's saturating conversion.
         * @param section INI section name.
         * @param key INI key name.
         * @param display_name Human-readable name shown in log output.
         * @param setter Callback applied with the resolved value. Must be reentrant and thread-safe.
         * @param default_value Value used when the key is absent or unparsable.
         */
        void bind_int(std::string_view section, std::string_view key, std::string_view display_name,
                      std::function<void(int)> setter, int default_value);

        /// Binds a floating-point INI key to a callback. See bind_int for the invocation contract.
        void bind_float(std::string_view section, std::string_view key, std::string_view display_name,
                        std::function<void(float)> setter, float default_value);

        /// Binds a boolean INI key to a callback. See bind_int for the invocation contract.
        void bind_bool(std::string_view section, std::string_view key, std::string_view display_name,
                       std::function<void(bool)> setter, bool default_value);

        /**
         * @brief Binds a string INI key to a callback (the general parse-into-anything form).
         * @details The setter receives the raw INI value verbatim (narrow bytes; ASCII passes through unchanged, a
         *          non-ASCII value arrives as raw bytes for the consumer to interpret). Use it to parse a value into a
         *          mask, an enum, or a non-atomic field. The value is delivered as a string_view that is valid only for
         *          the duration of the call and is not guaranteed to be NUL-terminated.
         * @param section INI section name.
         * @param key INI key name.
         * @param display_name Human-readable name shown in log output.
         * @param setter Callback applied with the resolved value. Must be reentrant and thread-safe.
         * @param default_value Value used when the key is absent.
         */
        void bind_string(std::string_view section, std::string_view key, std::string_view display_name,
                         std::function<void(std::string_view)> setter, std::string_view default_value);

        /**
         * @brief Binds an INI combo string to a callback receiving the parsed combo list (no input binding).
         * @details Parses the INI value into an input::KeyComboList (see press_combo for the combo grammar and the
         *          "NONE"/empty opt-out) and delivers it to @p setter at registration and on each load() / reload().
         *          Unlike press_combo this registers no input binding; the consumer owns the parsed combos and uses
         *          them however it likes.
         * @param section INI section name.
         * @param key INI key name.
         * @param display_name Human-readable name shown in log output and in the typo Warning.
         * @param setter Callback applied with the parsed combo list.
         * @param default_value Default combo string when the key is absent.
         */
        void bind_combos(std::string_view section, std::string_view key, std::string_view display_name,
                         std::function<void(const input::KeyComboList &)> setter, std::string_view default_value);

        /**
         * @brief Binds an INI key to a caller-supplied atomic (the most common form).
         * @details Convenience over the matching bind_<T> callback that stores the parsed value with
         *          std::memory_order_relaxed. The atomic must outlive every load() / reload(): the setter captures
         *          @p out by reference.
         * @tparam T One of int, bool, float.
         * @param section INI section name.
         * @param key INI key name.
         * @param display_name Human-readable name shown in log output.
         * @param out Atomic destination updated on every successful parse.
         * @param default_value Value applied when the INI key is missing.
         * @note Setup/control-plane only: registration may allocate and updates the config registry.
         */
        template <BindableScalar T>
        void bind(std::string_view section, std::string_view key, std::string_view display_name, std::atomic<T> &out,
                  T default_value)
        {
            if constexpr (std::same_as<T, int>)
            {
                bind_int(
                    section, key, display_name, [&out](int v) { out.store(v, std::memory_order_relaxed); },
                    default_value);
            }
            else if constexpr (std::same_as<T, bool>)
            {
                bind_bool(
                    section, key, display_name, [&out](bool v) { out.store(v, std::memory_order_relaxed); },
                    default_value);
            }
            else
            {
                bind_float(
                    section, key, display_name, [&out](float v) { out.store(v, std::memory_order_relaxed); },
                    default_value);
            }
        }

        /**
         * @brief Binds an INI key to an atomic, using the atomic's current value as the default.
         * @details Samples @p out once with std::memory_order_relaxed at registration time to use as the INI fallback,
         *          then stores parsed values back to @p out on every load() / reload(). Initialize the atomic
         *          deliberately before calling this overload.
         * @tparam T One of int, bool, float.
         */
        template <BindableScalar T>
        void bind(std::string_view section, std::string_view key, std::string_view display_name, std::atomic<T> &out)
        {
            bind<T>(section, key, display_name, out, out.load(std::memory_order_relaxed));
        }

        /**
         * @brief Binds an INI key to an atomic uint32 through a user parse function.
         * @details The parse function turns the raw INI string into a uint32 (for example a bitmask) that is stored
         *          with std::memory_order_relaxed. Applied at registration with @p default_value and again on each
         *          load() / reload().
         * @param section INI section name.
         * @param key INI key name.
         * @param display_name Human-readable name shown in log output.
         * @param out Atomic destination for the parsed value.
         * @param parse Pure function turning the raw INI string into the stored value.
         * @param default_value Default INI string parsed when the key is absent.
         */
        void bind_parsed(std::string_view section, std::string_view key, std::string_view display_name,
                         std::atomic<std::uint32_t> &out, std::function<std::uint32_t(std::string_view)> parse,
                         std::string_view default_value);

        /**
         * @brief Binds a log-level INI key that applies directly to the logger.
         * @details Parses @p default_value via the logger's string-to-level mapping and applies it both at registration
         *          and on each load() / reload(). Unrecognized values fall back to the Info level.
         * @param section INI section name.
         * @param key INI key name.
         * @param default_value Default level string (e.g. "INFO", "DEBUG").
         */
        void bind_log_level(std::string_view section, std::string_view key, std::string_view default_value = "INFO");

        /**
         * @brief Binds an INI combo string to a press-mode input binding and returns its guard.
         * @details Parses the INI value as one or more key combinations (commas separate independent combos under OR
         *          logic; '+' separates modifiers from the trailing trigger; tokens are key names or hex VK codes),
         *          registers a press binding under @p binding_name via input::register_combo, and rebinds it on every
         *          load() / reload() so the bound keys track the INI without re-registering.
         *
         *          Two opt-out sentinels yield an unbound but addressable binding silently: an empty value and the
         *          literal "NONE" (case-insensitive, whole trimmed value only). A non-empty value whose every token
         *          fails to parse is logged once at Warning level naming @p log_name and the offending string.
         * @param section INI section name.
         * @param ini_key INI key holding the combo string.
         * @param log_name Human-readable name echoed by the config logger and in the typo Warning.
         * @param binding_name input binding name (must be unique).
         * @param on_press Callback fired on the key-down edge.
         * @param default_combo Default combo string when the key is absent.
         * @param consume Optional per-binding suppression facet. std::nullopt registers no extra key; a value registers
         *                a bool item named "<ini_key>.Consume" wired to input suppression for this binding (honored for
         *                digital gamepad buttons and the mouse wheel only).
         * @return An input::BindingGuard owning the callback's lifetime. Store it (e.g. in an input::Scope); letting it
         *         drop immediately disables the binding. Fail-soft: if the underlying input::register_combo cannot
         *         allocate, an inert guard whose name() is empty is returned and the failure is logged (the binding is
         *         simply not installed).
         */
        [[nodiscard]] input::BindingGuard press_combo(std::string_view section, std::string_view ini_key,
                                                      std::string_view log_name, std::string_view binding_name,
                                                      std::function<void()> on_press, std::string_view default_combo,
                                                      std::optional<bool> consume = std::nullopt);

        /**
         * @brief Binds an INI combo string to a hold-mode input binding and returns its guard.
         * @details The hold-mode mirror of press_combo. @p on_state_change fires true on the press edge and false on
         *          the release edge; the returned guard synthesizes a single balancing false if it cancels a still-held
         *          binding. The "NONE"/empty opt-out, the typo Warning, and the live-rebind on reload all match
         *          press_combo.
         * @param section INI section name.
         * @param ini_key INI key holding the combo string.
         * @param log_name Human-readable name echoed by the config logger and in the typo Warning.
         * @param binding_name input binding name (must be unique).
         * @param on_state_change Callback fired with the hold state (true = held, false = released).
         * @param default_combo Default combo string when the key is absent.
         * @param consume Optional per-binding suppression facet (see press_combo).
         * @return An input::BindingGuard. Destroying it may synthesize the final on_state_change(false), so treat it as
         *         setup/control-plane only. Fail-soft: a registration that cannot allocate yields an inert guard whose
         *         name() is empty and is logged (the binding is simply not installed).
         */
        [[nodiscard]] input::BindingGuard hold_combo(std::string_view section, std::string_view ini_key,
                                                     std::string_view log_name, std::string_view binding_name,
                                                     std::function<void(bool)> on_state_change,
                                                     std::string_view default_combo,
                                                     std::optional<bool> consume = std::nullopt);

        /**
         * @brief Binds a boolean INI key that toggles input suppression for an already-registered binding.
         * @details Fuses bind_bool with input suppression: the INI value decides whether @p binding_name hides its
         *          trigger from the game, applied at registration and on each load() / reload(). Register the binding
         *          first; this is a no-op for an unknown name. Suppression is honored for digital gamepad buttons and
         *          the mouse wheel only.
         * @param section INI section name.
         * @param ini_key INI key name (e.g. "SetYToggle.Consume").
         * @param display_name Human-readable name shown in log output.
         * @param binding_name input binding name to toggle.
         * @param default_value Suppression state when the INI key is missing.
         */
        void consume_flag(std::string_view section, std::string_view ini_key, std::string_view display_name,
                          std::string_view binding_name, bool default_value = false);

        /**
         * @brief Registers a hotkey combo that triggers reload() on press.
         * @details A press_combo whose callback requests a reload off a dedicated background servicer thread (the press
         *          callback only flips a flag and notifies, so per-press latency stays low). The INI-configured combo
         *          overrides @p default_combo on each load() / reload().
         * @param ini_key INI key that stores the combo string.
         * @param default_combo Combo applied when the key is absent (e.g. "Ctrl+F5").
         * @return true if the binding was registered; false if @p default_combo is empty or the NONE sentinel (a reload
         *         hotkey with no keys is never useful, so it is rejected at the call site).
         */
        [[nodiscard]] bool reload_hotkey(std::string_view ini_key, std::string_view default_combo);

        /**
         * @brief Loads all bound settings from the named INI file.
         * @details Resolves @p ini_filename against the mod's runtime directory, parses it, and applies each bound
         *          setter with the INI value (or its default if the key is missing or invalid). The path is remembered
         *          so reload() operates on the same file.
         * @param ini_filename The INI filename, resolved relative to the runtime directory.
         */
        void load(std::string_view ini_filename);

        /**
         * @brief Re-applies all bound setters against the last-loaded INI file.
         * @details Re-reads the file passed to the most recent load() and re-invokes every setter with the fresh value.
         *          If the file's bytes are unchanged since the last successful load (content-hash short-circuit), the
         *          setters are skipped. Bindings persist across reloads.
         * @return true if a previous load() path was available and the reload proceeded; false if reload() was called
         *         before any load().
         * @note Safe from any thread. Only C++ exceptions from setters are caught; a structured-exception fault or a
         *       throwing noexcept setter is not recoverable.
         */
        [[nodiscard]] bool reload();

        /**
         * @brief Starts a background watcher that calls reload() when the INI changes.
         * @details Watches the directory of the path last passed to load(), collapsing bursty editor saves into a
         *          single reload via the @p debounce quiet window. After each reload @p on_reload is invoked with a flag
         *          that is true when setters ran and false when the content-hash skip short-circuited the reload. The
         *          watcher and the callback run on the watcher's background thread.
         * @param debounce Quiet window between change detection and reload (default 250 ms).
         * @param on_reload Optional callback invoked after each reload attempt.
         * @return Started if the watcher is now running; AlreadyRunning if one was already installed; NoPriorLoad if
         *         load() has not been called; StartFailed if the directory could not be opened or the handshake failed.
         */
        [[nodiscard]] AutoReloadStatus
        enable_auto_reload(std::chrono::milliseconds debounce = std::chrono::milliseconds{250},
                           std::function<void(bool)> on_reload = {});

        /**
         * @brief Stops the auto-reload watcher.
         * @details Idempotent. Returns once the watcher thread has exited (or been detached under the Windows loader
         *          lock). Calling this from inside an on_reload callback (the watcher thread) is a no-op that logs and
         *          leaves the watcher running, since joining the worker from itself would deadlock.
         */
        void disable_auto_reload() noexcept;

        /// Logs the current value of every bound setting, grouped by section.
        void log_all();

        /**
         * @brief Clears every bound item and the cached load path.
         * @details Does not stop the auto-reload watcher; call disable_auto_reload() first so a watcher callback cannot
         *          fire against a torn-down registry.
         */
        void clear() noexcept;

        class Ini;

        /**
         * @class SectionBinder
         * @brief A section-scoped view that drops the repeated section argument from the bind family.
         * @details Obtained from Ini::section() or config::section(). Each method forwards to the matching free
         *          function with the bound section name. Lightweight and copyable; it holds only the section name.
         */
        class SectionBinder
        {
        public:
            /// Constructs a binder scoped to @p section. Prefer Ini::section() / config::section().
            explicit SectionBinder(std::string_view section) : m_section(section) {}

            /// Section-scoped atomic bind. See config::bind.
            template <BindableScalar T> void bind(std::string_view key, std::atomic<T> &out, T default_value) const
            {
                config::bind<T>(m_section, key, key, out, default_value);
            }

            /// Section-scoped atomic bind with the atomic's current value as the default.
            template <BindableScalar T> void bind(std::string_view key, std::atomic<T> &out) const
            {
                config::bind<T>(m_section, key, key, out);
            }

            /// Section-scoped atomic bind with an explicit display name.
            template <BindableScalar T>
            void bind(std::string_view key, std::string_view display_name, std::atomic<T> &out, T default_value) const
            {
                config::bind<T>(m_section, key, display_name, out, default_value);
            }

            /// Section-scoped integer callback bind. See config::bind_int.
            void bind_int(std::string_view key, std::string_view display_name, std::function<void(int)> setter,
                          int default_value) const
            {
                config::bind_int(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped float callback bind. See config::bind_float.
            void bind_float(std::string_view key, std::string_view display_name, std::function<void(float)> setter,
                            float default_value) const
            {
                config::bind_float(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped bool callback bind. See config::bind_bool.
            void bind_bool(std::string_view key, std::string_view display_name, std::function<void(bool)> setter,
                           bool default_value) const
            {
                config::bind_bool(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped string callback bind. See config::bind_string.
            void bind_string(std::string_view key, std::string_view display_name,
                             std::function<void(std::string_view)> setter, std::string_view default_value) const
            {
                config::bind_string(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped combo-list bind (no input binding). See config::bind_combos.
            void bind_combos(std::string_view key, std::string_view display_name,
                             std::function<void(const input::KeyComboList &)> setter,
                             std::string_view default_value) const
            {
                config::bind_combos(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped parsed atomic-uint32 bind. See config::bind_parsed.
            void bind_parsed(std::string_view key, std::string_view display_name, std::atomic<std::uint32_t> &out,
                             std::function<std::uint32_t(std::string_view)> parse, std::string_view default_value) const
            {
                config::bind_parsed(m_section, key, display_name, out, std::move(parse), default_value);
            }

            /// Section-scoped log-level bind. See config::bind_log_level.
            void bind_log_level(std::string_view key, std::string_view default_value = "INFO") const
            {
                config::bind_log_level(m_section, key, default_value);
            }

            /// Section-scoped press-combo fusion. See config::press_combo.
            [[nodiscard]] input::BindingGuard press_combo(std::string_view ini_key, std::string_view log_name,
                                                          std::string_view binding_name, std::function<void()> on_press,
                                                          std::string_view default_combo,
                                                          std::optional<bool> consume = std::nullopt) const
            {
                return config::press_combo(m_section, ini_key, log_name, binding_name, std::move(on_press),
                                           default_combo, consume);
            }

            /// Section-scoped hold-combo fusion. See config::hold_combo.
            [[nodiscard]] input::BindingGuard hold_combo(std::string_view ini_key, std::string_view log_name,
                                                         std::string_view binding_name,
                                                         std::function<void(bool)> on_state_change,
                                                         std::string_view default_combo,
                                                         std::optional<bool> consume = std::nullopt) const
            {
                return config::hold_combo(m_section, ini_key, log_name, binding_name, std::move(on_state_change),
                                          default_combo, consume);
            }

            /// Section-scoped consume-flag fusion. See config::consume_flag.
            void consume_flag(std::string_view ini_key, std::string_view display_name, std::string_view binding_name,
                              bool default_value = false) const
            {
                config::consume_flag(m_section, ini_key, display_name, binding_name, default_value);
            }

        private:
            std::string m_section;
        };

        /// Returns a section-scoped binder for @p name. Equivalent to Ini{}.section(name).
        [[nodiscard]] inline SectionBinder section(std::string_view name)
        {
            return SectionBinder{name};
        }

        /**
         * @class Ini
         * @brief A handle to the process configuration registry.
         * @details Exposes section() plus the common operations (bind / bind_parsed / bind_log_level / load / reload /
         *          log_all / clear / enable_auto_reload / disable_auto_reload). The rest of the bind family
         *          (bind_int/float/bool/string/combos, press_combo, hold_combo, consume_flag, reload_hotkey) is reached
         *          through the free functions or through section(). Every Ini and every free function act on one shared
         *          process registry, so an Ini is a thin, copyable handle rather than an independent configuration; it
         *          exists so a consumer can write Ini{}.section("X").bind(...) and pass the surface around as an object.
         */
        class Ini
        {
        public:
            Ini() = default;

            /// Returns a section-scoped binder. See config::section.
            [[nodiscard]] SectionBinder section(std::string_view name) const { return SectionBinder{name}; }

            /// Atomic bind. See config::bind.
            template <BindableScalar T>
            void bind(std::string_view sec, std::string_view key, std::string_view display_name, std::atomic<T> &out,
                      T default_value) const
            {
                config::bind<T>(sec, key, display_name, out, default_value);
            }

            /// Atomic bind with the atomic's current value as the default. See config::bind.
            template <BindableScalar T>
            void bind(std::string_view sec, std::string_view key, std::string_view display_name,
                      std::atomic<T> &out) const
            {
                config::bind<T>(sec, key, display_name, out);
            }

            /// Parsed atomic-uint32 bind. See config::bind_parsed.
            void bind_parsed(std::string_view sec, std::string_view key, std::string_view display_name,
                             std::atomic<std::uint32_t> &out, std::function<std::uint32_t(std::string_view)> parse,
                             std::string_view default_value) const
            {
                config::bind_parsed(sec, key, display_name, out, std::move(parse), default_value);
            }

            /// Log-level bind. See config::bind_log_level.
            void bind_log_level(std::string_view sec, std::string_view key,
                                std::string_view default_value = "INFO") const
            {
                config::bind_log_level(sec, key, default_value);
            }

            /// Loads the named INI file. See config::load.
            void load(std::string_view ini_filename) const { config::load(ini_filename); }

            /// Re-applies bound setters. See config::reload.
            [[nodiscard]] bool reload() const { return config::reload(); }

            /// Starts the auto-reload watcher. See config::enable_auto_reload.
            [[nodiscard]] AutoReloadStatus
            enable_auto_reload(std::chrono::milliseconds debounce = std::chrono::milliseconds{250},
                               std::function<void(bool)> on_reload = {}) const
            {
                return config::enable_auto_reload(debounce, std::move(on_reload));
            }

            /// Stops the auto-reload watcher. See config::disable_auto_reload.
            void disable_auto_reload() const noexcept { config::disable_auto_reload(); }

            /// Logs every bound setting. See config::log_all.
            void log_all() const { config::log_all(); }

            /// Clears every bound item. See config::clear.
            void clear() const noexcept { config::clear(); }
        };
    } // namespace config
} // namespace DetourModKit

#endif // DETOURMODKIT_CONFIG_HPP
