#ifndef DETOURMODKIT_CONFIG_HPP
#define DETOURMODKIT_CONFIG_HPP

/**
 * @file config.hpp
 * @brief INI-backed configuration, hot reload, and INI-driven input combo bindings.
 * @details Config is fail-soft, and no call returns an error for a missing or malformed value. A missing key or an
 *          empty bool value applies the registered default with no log record. A malformed int, float, or bool value
 *          applies the default, and a combo value with no parsable combo yields an empty list. Each logs a Warning,
 *          except the empty and "NONE" combo opt-outs.
 * @note Thread safety: every setter must be reentrant and thread-safe. A setter can call the bind family and log_all().
 *       In a load() or reload() pass, a setter call to load(), reload(), or disable_auto_reload() is refused. A setter
 *       call to clear() in a pass is refused except on the reload-servicer thread.
 * @warning `[B-100]` Run load(), reload(), registration, and enable_auto_reload() outside the loader lock. These calls
 *          allocate, and enable_auto_reload() creates the watcher thread. The loader-lock teardown path detaches the
 *          watcher without a wait. `ConfigWatcherLoaderLockTest.*` pins the boundary.
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
        /** @brief Outcome of enable_auto_reload(). */
        enum class AutoReloadStatus : std::uint8_t
        {
            /// The watcher started.
            Started,
            /// A watcher was already installed and stays in place.
            AlreadyRunning,
            /// No load() path is cached, as before any load() or after clear(), so there is no path to watch.
            NoPriorLoad,
            /// The watcher did not start, for example on a failed directory open or handshake, or a set unload latch.
            StartFailed
        };

        /// The value types that the atomic bind accepts.
        template <typename T>
        concept BindableScalar = std::same_as<T, int> || std::same_as<T, bool> || std::same_as<T, float>;

        /**
         * @brief Binds an integer INI key to a callback.
         * @details Registration calls @p setter with @p default_value at once. Each load() or reload() pass that
         *          applies setters calls it again with the INI value. The value is decimal, or hex with a 0x prefix. An
         *          out-of-range value falls back to the default.
         * @param display_name Not shown in log records. The records name @p key.
         * @note Setup/control-plane only: registration may allocate and updates the config registry.
         */
        void bind_int(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(int)> setter,
            int default_value
        );

        /// Binds a floating-point INI key to a callback. See bind_int for the invocation contract.
        void bind_float(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(float)> setter,
            float default_value
        );

        /// Binds a boolean INI key to a callback. See bind_int for the invocation contract.
        void bind_bool(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(bool)> setter,
            bool default_value
        );

        /**
         * @brief Binds a string INI key to a callback.
         * @details The setter receives the raw INI value as narrow bytes, with no decoding. The string_view is valid
         *          only during the call and is not guaranteed to be NUL-terminated. The invocation contract matches
         *          bind_int.
         * @note Setup/control-plane only: registration may allocate and updates the config registry.
         */
        void bind_string(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(std::string_view)> setter,
            std::string_view default_value
        );

        /**
         * @brief Binds an INI combo string to a callback that receives the parsed combo list.
         * @details It registers no input binding. The grammar and the "NONE" or empty opt-out match press_combo. The
         *          invocation contract matches bind_int.
         * @param display_name Name shown in the typo Warning.
         * @param default_value Combo string used when the key is absent.
         * @note Setup/control-plane only: registration may allocate and updates the config registry.
         */
        void bind_combos(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::function<void(const input::KeyComboList &)> setter,
            std::string_view default_value
        );

        /**
         * @brief Binds an INI key to a caller-supplied atomic.
         * @details The matching bind_<T> stores each value into @p out with std::memory_order_relaxed. @p out must
         *          outlive every later load() and reload().
         * @note Setup/control-plane only: registration may allocate and updates the config registry.
         */
        template <BindableScalar T>
        void bind(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::atomic<T> &out,
            T default_value
        )
        {
            if constexpr (std::same_as<T, int>)
            {
                bind_int(
                    section,
                    key,
                    display_name,
                    [&out](int v) { out.store(v, std::memory_order_relaxed); },
                    default_value
                );
            }
            else if constexpr (std::same_as<T, bool>)
            {
                bind_bool(
                    section,
                    key,
                    display_name,
                    [&out](bool v) { out.store(v, std::memory_order_relaxed); },
                    default_value
                );
            }
            else
            {
                bind_float(
                    section,
                    key,
                    display_name,
                    [&out](float v) { out.store(v, std::memory_order_relaxed); },
                    default_value
                );
            }
        }

        /**
         * @brief Binds an INI key to an atomic, with the current value of @p out as the default.
         * @details Registration reads @p out once, relaxed. Initialize @p out before the call.
         * @note Setup/control-plane only (see the default-taking overload).
         */
        template <BindableScalar T>
        void bind(std::string_view section, std::string_view key, std::string_view display_name, std::atomic<T> &out)
        {
            bind<T>(section, key, display_name, out, out.load(std::memory_order_relaxed));
        }

        /**
         * @brief Binds an INI key to an atomic uint32 through a caller parse function.
         * @details The parsed value is stored into @p out with std::memory_order_relaxed. @p out has the lifetime rule
         *          of bind. The invocation contract matches bind_int.
         * @param parse Pure function from the raw INI string to the stored value.
         * @param default_value INI string that @p parse receives when the key is absent.
         * @note Setup/control-plane only: registration may allocate and updates the config registry.
         */
        void bind_parsed(
            std::string_view section,
            std::string_view key,
            std::string_view display_name,
            std::atomic<std::uint32_t> &out,
            std::function<std::uint32_t(std::string_view)> parse,
            std::string_view default_value
        );

        /**
         * @brief Binds a log-level INI key that sets the logger level.
         * @details The logger's string-to-level mapping applies the value at registration and on each load() or
         *          reload(). An unrecognized value falls back to Info.
         * @param default_value Level string used when the key is absent, for example "INFO" or "DEBUG".
         * @note Setup/control-plane only: registration may allocate and updates the config registry.
         */
        void bind_log_level(std::string_view section, std::string_view key, std::string_view default_value = "INFO");

        /**
         * @brief Binds an INI combo string to a press-mode input binding and returns its guard.
         * @details It registers a press binding under @p binding_name through input::register_combo. Each load() and
         *          reload() rebinds its keys through input::Input::rebind. Commas separate combos under OR logic,
         *          and '+' separates modifiers from the trailing trigger. A token is a key name or a hex VK code.
         *
         *          An empty value or "NONE" (case-insensitive, whole trimmed value only) leaves the binding registered
         *          but unbound, with no log record. If no combo of another value parses, one Warning names @p log_name
         *          and the value.
         * @param log_name Name shown in the typo Warning and in the registration failure record.
         * @param binding_name Unique input binding name.
         * @param on_press Callback fired on the key-down edge.
         * @param default_combo Combo string used when the key is absent.
         * @param consume If set, registers consume_flag on the key "<ini_key>.Consume" with this default.
         * @return A guard that owns the binding. Store it, for example in an input::Scope. A dropped guard disables
         *         the binding. If input::register_combo fails, the guard is inert with an empty name(), and the failure
         *         is logged.
         * @note Setup/control-plane only: the bind registers an input binding and updates the config registry.
         */
        [[nodiscard]] input::BindingGuard press_combo(
            std::string_view section,
            std::string_view ini_key,
            std::string_view log_name,
            std::string_view binding_name,
            std::function<void()> on_press,
            std::string_view default_combo,
            std::optional<bool> consume = std::nullopt
        );

        /**
         * @brief Binds an INI combo string to a hold-mode input binding and returns its guard.
         * @details @p on_state_change receives true on the press edge and false on the release edge. Every other
         *          parameter and behavior matches press_combo.
         * @return A guard that owns the binding. If the guard cancels a held binding, it synthesizes one final
         *         on_state_change(false). Destroy it only in setup or control-plane code.
         * @note Setup/control-plane only: the bind registers an input binding and updates the config registry.
         */
        [[nodiscard]] input::BindingGuard hold_combo(
            std::string_view section,
            std::string_view ini_key,
            std::string_view log_name,
            std::string_view binding_name,
            std::function<void(bool)> on_state_change,
            std::string_view default_combo,
            std::optional<bool> consume = std::nullopt
        );

        /**
         * @brief Binds a boolean INI key that sets input suppression for a registered binding.
         * @details The value sets input::ComboBinding::consume for @p binding_name. Register the binding first, because
         *          each application to an unknown name is a no-op. The invocation contract matches bind_int.
         * @param default_value Suppression state when the key is absent.
         * @note Setup/control-plane only: registration may allocate and updates the config registry.
         */
        void consume_flag(
            std::string_view section,
            std::string_view ini_key,
            std::string_view display_name,
            std::string_view binding_name,
            bool default_value = false
        );

        /**
         * @brief Registers a hotkey combo that triggers reload() on press.
         * @details The binding is a press_combo, so the INI value follows the press_combo grammar, opt-out, and typo
         *          Warning. An opt-out @p default_combo instead fails the call, as @return states.
         *          The reload and its setters run on the reload-servicer thread, not on the input poll thread. A repeat
         *          call for the same @p ini_key updates that binding in place, so the last @p default_combo wins.
         * @param ini_key Key in the [Input] section that holds the combo string.
         * @param default_combo Combo used when the key is absent, for example "Ctrl+F5".
         * @return true if the binding was registered, or updated for a repeated @p ini_key. false if @p default_combo
         *         is empty, NONE, or has no parsable combo. false also when an unload latch is set or the input
         *         registration or update fails. A false return keeps any earlier binding for @p ini_key.
         * @note Setup/control-plane only: the bind registers an input binding and updates the config registry.
         */
        [[nodiscard]] bool reload_hotkey(std::string_view ini_key, std::string_view default_combo);

        /**
         * @brief Loads all bound settings from the named INI file.
         * @details reload() reuses this path. If auto-reload watches a different file, the watcher moves to the new
         *          file and keeps its debounce and on_reload callback. On the watcher thread, load() skips that move
         *          and logs an Error record. Call load() from another thread to move the watcher.
         * @param ini_filename The UTF-8 INI filename, resolved relative to filesystem::get_runtime_directory().
         *                     Ill-formed UTF-8 or an embedded NUL loads the defaults with an Error record.
         * @note Setup/control-plane only: the load reads the file and runs every bound setter.
         */
        void load(std::string_view ini_filename);

        /**
         * @brief Re-reads the file of the most recent load() and re-applies every bound setter.
         * @details The setters are skipped if the file bytes are unchanged since the last fully applied pass and no
         *          bind_* call registered since then. A later pass that fails to read, parse, or apply every setter
         *          cancels that skip. The setters are also skipped if the file is unreadable or fails to parse. A skip
         *          keeps the last-applied values instead of the defaults.
         * @return false if no load() path is cached, as before any load() or after clear(), or for a refused call from
         *         a bound setter. Otherwise true, also for a skip.
         * @note Safe from any thread. Concurrent load() and reload() passes are serialized end to end, so a stale pass
         *       never overwrites a fresher one. Only C++ exceptions from setters are caught. A structured exception or
         *       a throw from a noexcept setter is not recoverable. The file header lists the refused setter calls.
         * @note Setup/control-plane only: the reload reads the file and runs every bound setter.
         */
        [[nodiscard]] bool reload();

        /**
         * @brief Starts a background watcher that calls reload() when the INI file changes.
         * @details The watcher observes the directory of the last load() path. It reloads once @p debounce passes with
         *          no further change, so a burst of saves merges into one reload. The reload and @p on_reload run on
         *          the watcher thread.
         * @param on_reload Optional. Called after each reload attempt with true if at least one bound setter ran, and
         *                  false otherwise. It is not called once an unload latch is set.
         * @note Setup/control-plane only: the start creates the watcher thread.
         */
        [[nodiscard]] AutoReloadStatus enable_auto_reload(
            std::chrono::milliseconds debounce = std::chrono::milliseconds{250},
            std::function<void(bool)> on_reload = {}
        );

        /**
         * @brief Stops the auto-reload watcher synchronously.
         * @details Idempotent. On the authorized path it returns after any pending debounced reload callback runs and
         *          the watcher thread exits. If an unload phase is published or the fail-closed loader-lock probe
         *          vetoes, it detaches the watcher thread and does not wait for it. On the watcher thread, for example
         *          inside on_reload, it logs and does not stop the watcher.
         * @warning The authorized path has no time bound and never detaches a callback in progress. This call waits for
         *          as long as the callback blocks.
         * @note Setup/control-plane only: the stop joins the watcher thread on the authorized path.
         */
        void disable_auto_reload() noexcept;

        /// Logs the current value of every bound setting, grouped by section.
        void log_all();

        /**
         * @brief Clears every bound setting and the cached load path.
         * @details It does not stop the auto-reload watcher. Call disable_auto_reload() first, so that no watcher
         *          callback fires against the cleared registry. It releases every reload_hotkey() binding and stops the
         *          reload-servicer thread, so it can wait for a hotkey reload in progress.
         * @note Setup/control-plane only: the clear tears down the config registry.
         */
        void clear() noexcept;

        class Ini;

        /** @brief A copyable view that forwards each bind call to the matching free function with one section name. */
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
            void bind_int(
                std::string_view key,
                std::string_view display_name,
                std::function<void(int)> setter,
                int default_value
            ) const
            {
                config::bind_int(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped float callback bind. See config::bind_float.
            void bind_float(
                std::string_view key,
                std::string_view display_name,
                std::function<void(float)> setter,
                float default_value
            ) const
            {
                config::bind_float(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped bool callback bind. See config::bind_bool.
            void bind_bool(
                std::string_view key,
                std::string_view display_name,
                std::function<void(bool)> setter,
                bool default_value
            ) const
            {
                config::bind_bool(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped string callback bind. See config::bind_string.
            void bind_string(
                std::string_view key,
                std::string_view display_name,
                std::function<void(std::string_view)> setter,
                std::string_view default_value
            ) const
            {
                config::bind_string(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped combo-list bind (no input binding). See config::bind_combos.
            void bind_combos(
                std::string_view key,
                std::string_view display_name,
                std::function<void(const input::KeyComboList &)> setter,
                std::string_view default_value
            ) const
            {
                config::bind_combos(m_section, key, display_name, std::move(setter), default_value);
            }

            /// Section-scoped parsed atomic-uint32 bind. See config::bind_parsed.
            void bind_parsed(
                std::string_view key,
                std::string_view display_name,
                std::atomic<std::uint32_t> &out,
                std::function<std::uint32_t(std::string_view)> parse,
                std::string_view default_value
            ) const
            {
                config::bind_parsed(m_section, key, display_name, out, std::move(parse), default_value);
            }

            /// Section-scoped log-level bind. See config::bind_log_level.
            void bind_log_level(std::string_view key, std::string_view default_value = "INFO") const
            {
                config::bind_log_level(m_section, key, default_value);
            }

            /// Section-scoped press_combo. See config::press_combo.
            [[nodiscard]] input::BindingGuard press_combo(
                std::string_view ini_key,
                std::string_view log_name,
                std::string_view binding_name,
                std::function<void()> on_press,
                std::string_view default_combo,
                std::optional<bool> consume = std::nullopt
            ) const
            {
                return config::press_combo(
                    m_section,
                    ini_key,
                    log_name,
                    binding_name,
                    std::move(on_press),
                    default_combo,
                    consume
                );
            }

            /// Section-scoped hold_combo. See config::hold_combo.
            [[nodiscard]] input::BindingGuard hold_combo(
                std::string_view ini_key,
                std::string_view log_name,
                std::string_view binding_name,
                std::function<void(bool)> on_state_change,
                std::string_view default_combo,
                std::optional<bool> consume = std::nullopt
            ) const
            {
                return config::hold_combo(
                    m_section,
                    ini_key,
                    log_name,
                    binding_name,
                    std::move(on_state_change),
                    default_combo,
                    consume
                );
            }

            /// Section-scoped consume_flag. See config::consume_flag.
            void consume_flag(
                std::string_view ini_key,
                std::string_view display_name,
                std::string_view binding_name,
                bool default_value = false
            ) const
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

        /** @brief A copyable handle to the one process registry that every Ini and every free function share. */
        class Ini
        {
        public:
            Ini() = default;

            /// Returns a section-scoped binder. See config::section.
            [[nodiscard]] SectionBinder section(std::string_view name) const { return SectionBinder{name}; }

            /// Atomic bind. See config::bind.
            template <BindableScalar T>
            void bind(
                std::string_view sec,
                std::string_view key,
                std::string_view display_name,
                std::atomic<T> &out,
                T default_value
            ) const
            {
                config::bind<T>(sec, key, display_name, out, default_value);
            }

            /// Atomic bind with the atomic's current value as the default. See config::bind.
            template <BindableScalar T>
            void
            bind(std::string_view sec, std::string_view key, std::string_view display_name, std::atomic<T> &out) const
            {
                config::bind<T>(sec, key, display_name, out);
            }

            /// Parsed atomic-uint32 bind. See config::bind_parsed.
            void bind_parsed(
                std::string_view sec,
                std::string_view key,
                std::string_view display_name,
                std::atomic<std::uint32_t> &out,
                std::function<std::uint32_t(std::string_view)> parse,
                std::string_view default_value
            ) const
            {
                config::bind_parsed(sec, key, display_name, out, std::move(parse), default_value);
            }

            /// Log-level bind. See config::bind_log_level.
            void
            bind_log_level(std::string_view sec, std::string_view key, std::string_view default_value = "INFO") const
            {
                config::bind_log_level(sec, key, default_value);
            }

            /// Loads the named INI file. See config::load.
            void load(std::string_view ini_filename) const { config::load(ini_filename); }

            /// Re-applies bound setters. See config::reload.
            [[nodiscard]] bool reload() const { return config::reload(); }

            /// Starts the auto-reload watcher. See config::enable_auto_reload.
            [[nodiscard]] AutoReloadStatus enable_auto_reload(
                std::chrono::milliseconds debounce = std::chrono::milliseconds{250},
                std::function<void(bool)> on_reload = {}
            ) const
            {
                return config::enable_auto_reload(debounce, std::move(on_reload));
            }

            /// Stops the auto-reload watcher. See config::disable_auto_reload.
            void disable_auto_reload() const noexcept { config::disable_auto_reload(); }

            /// Logs every bound setting. See config::log_all.
            void log_all() const { config::log_all(); }

            /// Clears every bound setting. See config::clear.
            void clear() const noexcept { config::clear(); }
        };
    } // namespace config
} // namespace DetourModKit

#endif // DETOURMODKIT_CONFIG_HPP
