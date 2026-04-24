#ifndef DETOURMODKIT_CONFIG_HPP
#define DETOURMODKIT_CONFIG_HPP

#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/logger.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    // Forward-declared to keep the filesystem watcher out of this header.
    // Full definition lives in config_watcher.hpp.
    class ConfigWatcher;

    /**
     * @namespace Config
     * @brief Provides functions for registering, loading, and logging configuration settings.
     * @details This system allows mods to register their configuration variables with DetourModKit.
     *          The kit handles loading values from an INI file and provides logging functionality.
     *          Uses std::function callbacks for type-safe value setting.
     *
     * All `register_*` functions share these common parameters:
     *   - @p section     INI section name.
     *   - @p ini_key     INI key name.
     *   - @p log_key_name  Human-readable name shown in log output.
     *   - @p setter      Callback invoked with the loaded (or default) value.
     *
     * @note Setter callbacks are invoked at two points: immediately during registration
     *       (with the default value) and again during load() (with the INI or default value).
     *       Consumers that accumulate state (e.g. building a lookup map) must be idempotent --
     *       clear accumulated state before applying the new value to avoid stale entries.
     *
     * **Thread safety:** All `register_*` and `load()` functions use a deferred callback
     * pattern: state is read/written under the config mutex, but setter callbacks are
     * invoked *after* the mutex is released.  This means setter callbacks may safely call
     * back into the Config API (e.g. `register_*`, `load`, `log_all`) without deadlocking.
     * A reentrancy guard is therefore unnecessary.  `log_all()` and `clear_registered_items()`
     * hold the mutex for the entire call but only invoke Logger methods, which use an
     * independent lock hierarchy.
     */
    namespace Config
    {

        /**
         * @struct KeyCombo
         * @brief Represents a single key combination with trigger keys and modifiers.
         * @details Contains trigger keys (OR logic) and modifier keys (AND logic).
         *          Designed for direct use with InputManager::register_press/register_hold.
         *          Each key is an InputCode identifying both the device source and button.
         *
         *          Within a single combo, modifiers are separated by '+' and the last
         *          '+'-delimited token is the trigger key. Tokens can be human-readable
         *          names or hex VK codes:
         *            - "F3"                   → keys=[F3], modifiers=[]
         *            - "Ctrl+F3"              → keys=[F3], modifiers=[Ctrl]
         *            - "Ctrl+Shift+F3"        → keys=[F3], modifiers=[Ctrl, Shift]
         *            - "Mouse4"               → keys=[Mouse4], modifiers=[]
         *            - "Gamepad_LB+Gamepad_A" → keys=[Gamepad_A], modifiers=[Gamepad_LB]
         *            - "0x11+0x72"            → keys=[0x72], modifiers=[0x11] (hex fallback)
         *
         *          Multiple combos are separated by commas in INI values, parsed into
         *          a KeyComboList. Each combo is independent (OR logic between combos):
         *            - "F3,Gamepad_LT+Gamepad_B" → [{keys=[F3]}, {keys=[Gamepad_B], mods=[Gamepad_LT]}]
         *            - "Ctrl+F3,Ctrl+F4"          → [{keys=[F3], mods=[Ctrl]}, {keys=[F4], mods=[Ctrl]}]
         */
        struct KeyCombo
        {
            std::vector<InputCode> keys;
            std::vector<InputCode> modifiers;
        };

        /// A list of alternative key combinations (OR logic between combos).
        using KeyComboList = std::vector<KeyCombo>;

        /**
         * @class InputBindingGuard
         * @brief RAII cancellation token for bindings registered via
         *        register_press_combo().
         * @details The guard owns a shared atomic flag that gates the user
         *          callback. On destruction (or explicit release()) the flag
         *          is cleared and subsequent key events become no-ops. The
         *          underlying InputManager binding remains registered; it is
         *          only torn down by InputManager::shutdown() or
         *          DMK_Shutdown().
         *
         *          Non-copyable, movable. Moving transfers ownership of the
         *          cancellation flag; the moved-from guard becomes inert.
         */
        class InputBindingGuard
        {
        public:
            InputBindingGuard() = default;
            InputBindingGuard(std::string name, std::shared_ptr<std::atomic<bool>> enabled) noexcept
                : name_(std::move(name)), enabled_(std::move(enabled)) {}

            ~InputBindingGuard() noexcept { release(); }

            InputBindingGuard(const InputBindingGuard &) = delete;
            InputBindingGuard &operator=(const InputBindingGuard &) = delete;

            InputBindingGuard(InputBindingGuard &&other) noexcept
                : name_(std::move(other.name_)), enabled_(std::move(other.enabled_)) {}

            InputBindingGuard &operator=(InputBindingGuard &&other) noexcept
            {
                if (this != &other)
                {
                    release();
                    name_ = std::move(other.name_);
                    enabled_ = std::move(other.enabled_);
                }
                return *this;
            }

            /**
             * @brief Disables the binding's callback. Idempotent.
             */
            void release() noexcept
            {
                if (enabled_)
                {
                    enabled_->store(false, std::memory_order_release);
                    enabled_.reset();
                }
            }

            /**
             * @brief Returns the binding's InputManager name.
             */
            [[nodiscard]] const std::string &name() const noexcept { return name_; }

            /**
             * @brief Returns true while the binding's callback is still live.
             */
            [[nodiscard]] bool is_active() const noexcept
            {
                return enabled_ && enabled_->load(std::memory_order_acquire);
            }

        private:
            std::string name_;
            std::shared_ptr<std::atomic<bool>> enabled_;
        };

        /// Registers an integer configuration item.
        /// @note The setter is called immediately with default_value and again on load().
        void register_int(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                          std::function<void(int)> setter, int default_value);

        /// Registers a floating-point configuration item.
        /// @note The setter is called immediately with default_value and again on load().
        void register_float(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                            std::function<void(float)> setter, float default_value);

        /// Registers a boolean configuration item.
        /// @note The setter is called immediately with default_value and again on load().
        void register_bool(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                           std::function<void(bool)> setter, bool default_value);

        /// Registers a string configuration item.
        /// @note The setter is called immediately with default_value and again on load().
        void register_string(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                             std::function<void(const std::string &)> setter, std::string default_value);

        /**
         * @brief Registers a key combo configuration item.
         * @details Parses an INI value as one or more key combinations. Commas at the
         *          top level separate independent combos (OR logic). Within each combo,
         *          '+' separates modifier keys from the trigger key (last token). Tokens
         *          can be human-readable names (e.g., "Ctrl", "F3", "Gamepad_A") or hex
         *          VK codes (e.g., "0x72"). See KeyCombo for full parsing semantics.
         * @param section INI section name.
         * @param ini_key INI key name.
         * @param log_key_name Human-readable name shown in log output.
         * @param setter Callback invoked with the parsed KeyComboList.
         * @param default_value_str Default value string in the same format.
         * @note The setter is called immediately with the parsed default and again on load().
         */
        void register_key_combo(std::string_view section, std::string_view ini_key, std::string_view log_key_name,
                                std::function<void(const KeyComboList &)> setter, std::string_view default_value_str);

        /**
         * @brief Registers a key combo INI item and wires it to InputManager.
         * @details Fuses register_key_combo() with InputManager::register_press().
         *          On registration the InputManager binding is created with the
         *          parsed default combo. On each subsequent load() the setter
         *          invokes InputManager::update_binding_combos() so the bound
         *          keys and modifiers pick up the INI-sourced value without
         *          re-registering the binding. Live updates require the new
         *          combo list to have the same number of alternatives as the
         *          default (one binding entry per combo); if the cardinality
         *          differs the update is rejected and a Warning-level log
         *          message is emitted. Callers that need to change cardinality
         *          at runtime must fully stop and restart InputManager so the
         *          underlying bindings can be re-registered.
         *
         *          The returned guard holds a cancellation flag that
         *          short-circuits the user callback when released, because
         *          InputManager does not support per-binding removal
         *          post-start().
         *
         *          Must be called before InputManager::start() for the
         *          binding to be picked up by the poller. Call sites that
         *          register after start() should also call
         *          InputManager::shutdown() then start() again, or accept
         *          that only the INI value is tracked and the callback
         *          never fires.
         *
         * @param section INI section name.
         * @param ini_key INI key name.
         * @param log_name Human-readable name echoed by the config logger.
         * @param input_binding_name InputManager binding name (must be unique).
         * @param on_press User callback fired on key-down edge.
         * @param default_value Default combo string (same format as register_key_combo).
         * @return InputBindingGuard RAII cancellation token for the callback.
         */
        [[nodiscard]] InputBindingGuard register_press_combo(std::string_view section,
                                                             std::string_view ini_key,
                                                             std::string_view log_name,
                                                             std::string_view input_binding_name,
                                                             std::function<void()> on_press,
                                                             std::string_view default_value);

        /**
         * @brief Loads all registered configuration settings from the specified INI file.
         * @details Parses the INI file and attempts to read values for each registered item.
         *          If a key is missing or invalid, the default value provided during
         *          registration is used. The INI path is remembered internally so that
         *          subsequent reload() calls operate on the same file without needing
         *          the caller to pass it again.
         * @param ini_filename The base filename of the INI file. Path will be resolved
         *                     relative to the mod's runtime directory.
         */
        void load(std::string_view ini_filename);

        /**
         * @brief Re-runs all registered setters against the last-loaded INI file.
         * @details Reads the INI file previously passed to load() and re-invokes every
         *          registered setter with the fresh value (or its default if the key is
         *          missing). Registrations themselves are not touched: user lambdas
         *          persist across reloads. The deferred-setter invocation pattern used
         *          by load() applies here as well, so setters may freely call back into
         *          the Config API without deadlocking.
         * @return true if a previous load() path was available and the reload proceeded,
         *         false if reload() was called before any load().
         * @note Safe to call from any thread. Commonly wired to a filesystem watcher
         *       (see enable_auto_reload) or a hotkey (see register_reload_hotkey).
         * @note Only C++ exceptions are caught. Structured-exception (SEH) faults
         *       such as access violations bypass the handler. A `noexcept`-marked
         *       user setter that throws still invokes std::terminate.
         */
        [[nodiscard]] bool reload();

        /**
         * @enum AutoReloadStatus
         * @brief Outcome of a call to enable_auto_reload().
         */
        enum class AutoReloadStatus
        {
            Started,         ///< Watcher is now running.
            AlreadyRunning,  ///< Called twice; the existing watcher was kept.
            NoPriorLoad,     ///< Config::load() was never called; no path to watch.
            StartFailed      ///< Directory could not be opened or start handshake failed.
        };

        /**
         * @brief Starts a background watcher that calls reload() when the INI changes.
         * @details Creates a ConfigWatcher on the INI path last passed to load() and
         *          starts its worker thread. The watcher collapses bursty editor save
         *          events (e.g. Notepad++ atomic save) into a single reload via the
         *          @p debounce quiet window. After the reload completes, @p on_reload
         *          is invoked if provided, allowing the caller to refresh derived
         *          state (e.g. rebuild caches, reformat log output).
         *
         *          If load() has not been called yet, or if auto-reload is already
         *          enabled, this is a no-op and a Warning-level log message is emitted.
         *
         *          The watcher and any @p on_reload callback run on the watcher's
         *          background thread. User setters invoked by reload() also run on
         *          that thread; they must handle their own synchronization.
         *
         *          The @p on_reload callback receives a `bool content_changed`
         *          argument. When the file's byte contents are identical to the
         *          last successfully loaded version (e.g. after a `touch` or a
         *          no-op save), setters are skipped and the flag is false; the
         *          callback still fires so derived state can observe the event.
         *
         * @param debounce Quiet-window length between change detection and reload
         *                 (default 250 ms).
         * @param on_reload Optional callback invoked after each successful reload.
         *                  The bool argument is true when setters ran, false when
         *                  the content-hash skip short-circuited the reload.
         * @return AutoReloadStatus::Started if the watcher is now running;
         *         AutoReloadStatus::AlreadyRunning if a watcher was already installed
         *         (no-op, existing watcher kept);
         *         AutoReloadStatus::NoPriorLoad if load() has not been called yet
         *         (no-op, no watcher installed);
         *         AutoReloadStatus::StartFailed if the parent directory could not
         *         be opened or the start handshake failed (watcher reset, error
         *         logged).
         */
        [[nodiscard]] AutoReloadStatus enable_auto_reload(
            std::chrono::milliseconds debounce = std::chrono::milliseconds{250},
            std::function<void(bool)> on_reload = {});

        /**
         * @brief Stops the filesystem watcher started by enable_auto_reload().
         * @details Idempotent. Returns only once the watcher thread has exited
         *          (or been detached under the Windows loader lock).
         */
        void disable_auto_reload() noexcept;

        /**
         * @brief Registers a hotkey binding that triggers reload() on press.
         * @details Thin wrapper around register_press_combo() whose on-press
         *          callback calls Config::reload(). Like the underlying helper,
         *          this must be called before InputManager::start() so the
         *          binding is picked up by the poller.
         *
         *          The INI-configured combo overrides @p default_combo on each
         *          load() / reload() cycle via the standard register_press_combo
         *          machinery.
         *
         * @param ini_key INI key that stores the combo string (e.g. "ReloadConfig").
         * @param default_combo Combo string applied when the INI key is absent
         *                      (e.g. "Ctrl+F5").
         * @return true if the binding was registered, false if @p default_combo
         *         is empty (register_press_combo silently no-ops on empty combo
         *         lists, which would make the hotkey appear registered but inert).
         * @note The on-press callback runs on the InputManager poll thread,
         *       but the actual reload() work is deferred to a dedicated
         *       background servicer thread. The press callback only flips
         *       an atomic flag and notifies a condition variable, so
         *       per-press latency on the poll thread stays in the
         *       microsecond range regardless of INI size. Multiple presses
         *       during a running reload coalesce into at most one follow-up.
         *       Any exception thrown by reload() on the servicer thread is
         *       caught and logged so the servicer stays alive.
         * @note Only C++ exceptions are caught. Structured-exception (SEH) faults
         *       such as access violations bypass the handler. A `noexcept`-marked
         *       user setter that throws still invokes std::terminate.
         */
        [[nodiscard]] bool register_reload_hotkey(std::string_view ini_key,
                                                  std::string_view default_combo);

        /**
         * @brief Logs the current values of all registered configuration settings.
         * @details Iterates through all items registered with the config system and
         *          outputs their current values to the Logger.
         */
        void log_all();

        /**
         * @brief Clears all currently registered configuration items.
         * @details Useful if the configuration system needs to be reset without
         *          restarting the application.
         */
        void clear_registered_items();

    } // namespace Config
} // namespace DetourModKit

#endif // DETOURMODKIT_CONFIG_HPP
