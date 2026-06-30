#ifndef DETOURMODKIT_INTERNAL_INPUT_POLLER_HPP
#define DETOURMODKIT_INTERNAL_INPUT_POLLER_HPP

/**
 * @file input_poller.hpp
 * @brief Internal background poll engine that drives the public input::Input facade.
 * @details This is the RAII polling engine the input::Input facade owns. It monitors keyboard, mouse, gamepad, and
 *          mouse-wheel state on a dedicated thread, performs press/hold edge detection with strict modifier matching,
 *          and drives the opt-in interception layer (input_intercept.hpp). It is split out of the installed header so
 *          the facade carries no Win32 / threading state, and so the engine stays drivable white-box from the test
 *          suite. Not installed.
 *
 *          The engine works with flat InputBinding records: one combo equals one binding entry, and the facade
 *          explodes a public input::ComboBinding into one entry per combo, all sharing a name (OR logic). The engine
 *          speaks the public input vocabulary (input::Trigger, input::KeyComboList, input::BindingToken) so the facade
 *          can pass them straight through.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/srw_shared_mutex.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace DetourModKit::detail
{
    /**
     * @struct InputBinding
     * @brief Engine record for a single input-to-action binding (one combo).
     * @details Holds the action name, trigger and modifier codes, the trigger mode, the suppression opt-in, and the
     *          callbacks. The keys vector is OR logic (any single trigger fires); the modifiers vector is AND logic
     *          (all must be held). Modifier matching is strict across the whole binding set: any key used as a modifier
     *          in any binding blocks bindings that do not list it, so "V" does not fire while "Shift+V" is pressed.
     *
     *          For Trigger::Press the press callback fires on the key-down edge; for Trigger::Hold the state callback
     *          fires true on press and false on release (including a synthesized false at shutdown for an active hold).
     *          All codes in one binding should come from the same device group; mouse-wheel codes are trigger-only and
     *          Press-mode (a notch reads as one Press edge). Callbacks run on the poll thread and must be quick.
     */
    struct InputBinding
    {
        std::string name;
        std::vector<InputCode> keys;
        std::vector<InputCode> modifiers;
        input::Trigger trigger = input::Trigger::Press;

        // Opt-in passthrough suppression. Honored only for digital gamepad buttons (via the XInputGetState hook) and
        // the mouse wheel (via the window-procedure hook); analog axes and keyboard/mouse buttons cannot be masked.
        bool consume = false;

        std::function<void()> on_press;
        std::function<void(bool)> on_state_change;
    };

    /**
     * @class InputPoller
     * @brief RAII polling engine monitoring input state on a background thread.
     * @details Manages a dedicated poll thread that reads keyboard/mouse via GetAsyncKeyState, gamepad via XInput, and
     *          the mouse wheel via the window-procedure subclass. Supports press (edge-triggered) and hold
     *          (level-triggered) bindings with modifier combinations and optional foreground-focus gating. On shutdown,
     *          active holds receive a final on_state_change(false).
     *
     * @note Non-copyable, non-movable. Callbacks run on the poll thread.
     * @warning Inside a DLL, shutdown() must run before DLL_PROCESS_DETACH; joining the poll thread under the loader
     *          lock would deadlock, so shutdown() detaches against a pinned module when the loader lock is held.
     * @warning The interception layer (mouse-wheel capture and gamepad passthrough suppression) is backed by
     *          process-global state and a single set of hooks, so at most one poller may use those features at a time.
     *          The Input singleton is the intended single-instance owner; purely observational pollers install nothing.
     */
    class InputPoller
    {
    public:
        /**
         * @brief Constructs a poller with the given bindings and tuning. The poll thread does not start until start().
         * @param bindings Bindings to monitor (moved).
         * @param poll_interval Time between cycles; clamped to [MIN_POLL_INTERVAL, MAX_POLL_INTERVAL].
         * @param require_focus When true, key events are ignored unless this process owns the foreground window.
         * @param gamepad_index XInput controller index (clamped 0-3).
         * @param trigger_threshold Analog trigger deadzone (clamped 0-255).
         * @param stick_threshold Thumbstick deadzone (clamped 0-32767).
         */
        explicit InputPoller(std::vector<InputBinding> bindings,
                             std::chrono::milliseconds poll_interval = input::DEFAULT_POLL_INTERVAL,
                             bool require_focus = true, int gamepad_index = 0,
                             int trigger_threshold = GamepadCode::TriggerThreshold,
                             int stick_threshold = GamepadCode::StickThreshold);

        ~InputPoller() noexcept;

        InputPoller(const InputPoller &) = delete;
        InputPoller &operator=(const InputPoller &) = delete;
        InputPoller(InputPoller &&) = delete;
        InputPoller &operator=(InputPoller &&) = delete;

        /**
         * @brief Starts the poll thread.
         * @details Safe to call only once; subsequent calls are ignored with a warning. Not thread-safe (the Input
         *          facade serializes start).
         */
        void start();

        /// Returns true while the poll thread is running.
        [[nodiscard]] bool is_running() const noexcept;

        /// Number of registered bindings, under the binding reader lock.
        [[nodiscard]] std::size_t binding_count() const noexcept;

        /// The configured poll interval.
        [[nodiscard]] std::chrono::milliseconds poll_interval() const noexcept;

        /// The configured XInput controller index (0-3).
        [[nodiscard]] int gamepad_index() const noexcept;

        /// Queries activity by index. Returns false for out-of-range indices. Thread-safe.
        [[nodiscard]] bool is_binding_active(std::size_t index) const noexcept;

        /// Queries activity by name (OR over the name's combos). Returns false for an unknown name. Thread-safe.
        [[nodiscard]] bool is_binding_active(std::string_view name) const noexcept;

        /**
         * @brief Resolves a name to a generation-checked token for repeated low-overhead queries.
         * @return A valid token when the name is registered; an invalid token when unknown or on allocation failure.
         * @note Setup/control-plane: copies the name's index set and may allocate.
         */
        [[nodiscard]] input::BindingToken acquire_binding_token(std::string_view name) const noexcept;

        /// Queries a binding through a previously acquired token (the per-frame hot path). Fails closed when stale.
        [[nodiscard]] bool is_binding_active(const input::BindingToken &token) const noexcept;

        /// Reports whether a token still matches the live binding generation.
        [[nodiscard]] bool binding_token_current(const input::BindingToken &token) const noexcept;

        /// Sets whether the poller gates on foreground focus. Thread-safe; takes effect immediately.
        void set_require_focus(bool require_focus) noexcept;

        /**
         * @brief Sets the suppression flag on every binding sharing @p name and refreshes the interception gates.
         * @details A no-op if the name was never registered. Thread-safe; safe while running.
         */
        void set_consume(std::string_view name, bool consume) noexcept;

        /**
         * @brief Stops the poll thread.
         * @details Joins and then fires on_state_change(false) for active holds, unless the loader lock is held -- in
         *          which case the thread is detached against a pinned module and the interception detours are left
         *          installed. Idempotent.
         */
        void shutdown() noexcept;

        /**
         * @brief Replaces the trigger combos of all bindings sharing @p name.
         * @details Matching counts rewrite in place; differing counts rebuild the entry set carrying callbacks, mode,
         *          and name forward. An empty list leaves one inert sentinel so the name stays addressable. Held
         *          bindings receive on_state_change(false) before the swap. Safe while running.
         * @return true on swap (including unbind); false only if the name was never registered.
         */
        [[nodiscard]] bool update_combos(std::string_view name, const input::KeyComboList &combos) noexcept;

        /**
         * @brief Appends a binding to the running poller, carrying surviving entries' active state forward.
         */
        void add_binding(InputBinding binding) noexcept;

        /// Removes every binding sharing @p name (invoking hold-release callbacks). Returns the count removed.
        std::size_t remove_bindings_by_name(std::string_view name) noexcept
        {
            return remove_bindings_by_name(name, true);
        }

        /// Drops every binding without stopping the thread (invoking hold-release callbacks).
        void clear_bindings() noexcept { clear_bindings(true); }

        /**
         * @brief Variant of remove_bindings_by_name that can suppress the hold-release callbacks.
         * @param invoke_callbacks When false (the loader-lock unload path), the on_state_change(false) callbacks are
         *                         dropped because the hosting Logic DLL's pages may be unmapping.
         */
        std::size_t remove_bindings_by_name(std::string_view name, bool invoke_callbacks) noexcept;

        /// Variant of clear_bindings that can suppress the hold-release callbacks (the loader-lock unload path).
        void clear_bindings(bool invoke_callbacks) noexcept;

    private:
        void poll_loop(std::stop_token stop_token);
        void release_active_holds() noexcept;
        [[nodiscard]] bool is_process_foreground() const noexcept;
        void recompute_modifier_caches_locked() noexcept;

        /// Transparent hasher enabling std::string_view lookup without allocation.
        struct StringHash
        {
            using is_transparent = void;
            std::size_t operator()(std::string_view sv) const noexcept { return std::hash<std::string_view>{}(sv); }
        };

        // m_bindings_rw_mutex protects m_bindings, m_name_index, m_known_modifiers, m_binding_generation, and the
        // interception gates during a live update. The poll loop holds a shared lock across the evaluation pass and
        // releases it before dispatching callbacks, so callbacks may re-enter binding_count / is_binding_active /
        // update_combos without re-acquiring the non-recursive lock; update_combos holds an exclusive lock. The
        // m_active_states entries are always accessed via atomics and need no further guard.
        mutable SrwSharedMutex m_bindings_rw_mutex;
        std::vector<InputBinding> m_bindings;
        std::unordered_map<std::string, std::vector<std::size_t>, StringHash, std::equal_to<>> m_name_index;
        std::vector<InputCode> m_known_modifiers;
        // Advances on every binding-set reshape; an input::BindingToken captures this at acquire time and a query whose
        // token generation no longer matches fails closed. Guarded by m_bindings_rw_mutex.
        std::uint64_t m_binding_generation{0};
        std::chrono::milliseconds m_poll_interval;
        std::atomic<bool> m_require_focus;
        std::atomic<bool> m_running{false};
        std::jthread m_poll_thread;
        std::mutex m_cv_mutex;
        std::condition_variable_any m_cv;

        // Per-binding active state, indexed parallel to m_bindings. Atomic for cross-thread reads.
        std::unique_ptr<std::atomic<std::uint8_t>[]> m_active_states;

        int m_gamepad_index;
        int m_trigger_threshold;
        int m_stick_threshold;
        std::atomic<bool> m_has_gamepad_bindings{false};

        // Interception gates, recomputed alongside the modifier caches. Each lazily installs an active-input hook from
        // the poll loop, so a mod that never opts in pays no interception cost.
        std::atomic<bool> m_has_wheel_bindings{false};           // any MouseWheel trigger -> WndProc hook
        std::atomic<bool> m_has_consume_gamepad_bindings{false}; // any consume gamepad binding -> XInput hook
        std::atomic<bool> m_has_wheel_consume_bindings{false};   // any consume wheel binding -> swallow wheel messages
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_INPUT_POLLER_HPP
