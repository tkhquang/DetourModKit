#ifndef DETOURMODKIT_INPUT_HPP
#define DETOURMODKIT_INPUT_HPP

/**
 * @file input.hpp
 * @brief Hotkey and gamepad input surface: combo bindings, edge detection, and opt-in passthrough suppression.
 * @details Speaks the foundation value vocabulary (Result, ErrorCode) and the per-token InputCode types from
 *          input_codes.hpp. A binding is registered once as a ComboBinding and is owned by a move-only BindingGuard;
 *          a Scope batches guards and releases them in reverse insertion order. The Input facade owns a single
 *          background poll thread and the process-global interception layer (one XInput hook plus one
 *          window-procedure subclass), merging a singleton manager facade and a separate polling engine into one
 *          entry point.
 *
 *          The installed header carries no Win32 type and no hooking-backend type: the poll thread, the device
 *          snapshots, and the detour state live in the non-installed engine under src/internal/ and are reached only
 *          through this facade. Key-name parsing and formatting stay in input_codes.hpp.
 *
 *          Combo vocabulary (KeyCombo / KeyComboList) lives here, not in config: a combo is a pure input concept (a
 *          set of trigger codes plus modifier codes), and the input API consumes it directly. The config module
 *          depends on input to fuse an INI key to a live combo binding, never the reverse.
 */

#include "DetourModKit/error.hpp"
#include "DetourModKit/input_codes.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        // The poll/edge-detection engine. Defined in the non-installed src/internal/input_poller.hpp; named here only
        // so BindingToken can grant it friendship (the engine mints and validates tokens against its binding set).
        class InputPoller;
    } // namespace detail

    namespace input
    {
        /**
         * @struct KeyCombo
         * @brief One alternative key combination: OR across keys, AND across modifiers.
         * @details The keys vector is OR logic (any single trigger fires the combo); the modifiers vector is AND logic
         *          (all listed modifiers must be held). Each InputCode tags both the device source and the button/key
         *          code. All codes in one combo should be from the same device group (keyboard/mouse or gamepad);
         *          mouse-wheel codes are a standalone, trigger-only source.
         */
        struct KeyCombo
        {
            std::vector<InputCode> keys;
            std::vector<InputCode> modifiers;
        };

        /// A list of alternative key combinations (OR logic between combos). An empty list means "no keys bound".
        using KeyComboList = std::vector<KeyCombo>;

        /**
         * @enum Trigger
         * @brief Edge model for a binding.
         */
        enum class Trigger
        {
            /// Fires the on_press callback once per key-down edge.
            Press,
            /**
             * Fires on_state_change(true) on the press edge and on_state_change(false) on the release edge. The release
             * edge is synthesized exactly once on teardown for a binding still held at shutdown.
             */
            Hold
        };

        /**
         * @brief Converts a Trigger to its string representation.
         * @param trigger The trigger mode.
         * @return String form ("Press" / "Hold"), or "Unknown" for an out-of-range value.
         */
        [[nodiscard]] constexpr std::string_view to_string(Trigger trigger) noexcept
        {
            switch (trigger)
            {
            case Trigger::Press:
                return "Press";
            case Trigger::Hold:
                return "Hold";
            }
            return "Unknown";
        }

        /// Default poll cadence: 16 ms (~60 Hz), matching a typical frame budget.
        inline constexpr std::chrono::milliseconds DEFAULT_POLL_INTERVAL{16};
        /// Lower clamp for the poll interval.
        inline constexpr std::chrono::milliseconds MIN_POLL_INTERVAL{1};
        /// Upper clamp for the poll interval.
        inline constexpr std::chrono::milliseconds MAX_POLL_INTERVAL{1000};

        /**
         * @struct ComboBinding
         * @brief Declarative description of one named input binding, registered via register_combo.
         * @details A ComboBinding is a designated-init aggregate. It carries every combo alternative under a single
         *          name (OR logic between combos), the trigger mode, the suppression opt-in, and the callbacks. One
         *          register_combo call materializes one binding entry per combo, all sharing the name, so a name-based
         *          query is true when any of its combos is pressed.
         *
         *          Modifier matching is strict across the whole binding set: any key that appears as a modifier in any
         *          registered binding blocks bindings that do not list it. This prevents "V" from firing when
         *          "Shift+V" is pressed.
         *
         *          For Trigger::Press, on_press fires on each key-down edge; on_state_change is ignored. For
         *          Trigger::Hold, on_state_change fires with true on the press edge and false on the release edge;
         *          on_press is ignored.
         *
         * @warning Callbacks run on the poll thread. They must execute quickly and must not capture references to
         *          objects whose lifetime ends before the owning BindingGuard is released or the Input facade is shut
         *          down.
         */
        struct ComboBinding
        {
            /**
             * Binding name. A shared name groups multiple combos under OR logic and is the key for is_active / rebind.
             * An empty name registers a binding addressable only through its guard, not by name.
             */
            std::string name = {};

            /// Press or Hold edge model.
            Trigger trigger = Trigger::Press;

            /**
             * The combo alternatives (OR between combos). Empty registers an inert, addressable binding that a later
             * rebind can populate.
             */
            KeyComboList combos = {};

            /**
             * Opt-in passthrough suppression. When true, the binding's trigger is additionally hidden from the game so
             * it does not also act on it (for example an "LB + D-pad" zoom that must not move the menu cursor). Honored
             * only for digital gamepad buttons (via an XInputGetState hook) and the mouse wheel (via the
             * window-procedure hook). Analog triggers, stick directions, keyboard keys, and mouse buttons cannot be
             * masked. Default off keeps the binding purely observational.
             */
            bool consume = false;

            /// Invoked on the key-down edge when trigger == Press. Empty for a Hold binding.
            std::function<void()> on_press = {};

            /**
             * Invoked with the hold state (true held / false released) when trigger == Hold. Empty for a Press
             * binding.
             */
            std::function<void(bool)> on_state_change = {};
        };

        /**
         * @class BindingToken
         * @brief Generation-checked handle to a named binding's resolved entry set for low-overhead repeated queries.
         * @details A high-frequency consumer (a render-thread hotkey polled every frame) resolves a name once with
         *          Input::acquire_token, then queries the token every frame with Input::is_active(const BindingToken&),
         *          skipping the per-call name hash. The token caches the name's resolved entry indices.
         *
         *          The token is stamped with the binding generation it was minted at. Any reshape of the binding set
         *          (register / release / clear / rebind / consume change) advances the generation, so a query through a
         *          stale token fails closed: it returns false without dereferencing the now-meaningless cached indices.
         *          The generation comes from a process-wide monotonic counter, so a token minted by one poll engine can
         *          never alias a different engine after a shutdown / start cycle. A default token, an unknown-name
         *          token, and an allocation-failed token are all invalid and always read inactive.
         */
        class BindingToken
        {
        public:
            BindingToken() = default;

            /**
             * @brief Reports whether the token resolved a name at acquisition time.
             * @details true only means acquire_token found the name and resolved its entries; it does NOT imply the
             *          token is still current. Use Input::token_current, or the fail-closed is_active(token), to test
             *          currency after a possible reshape.
             * @return true for a resolved token; false for a default, unknown-name, or allocation-failed token.
             */
            [[nodiscard]] bool valid() const noexcept { return m_generation != 0; }

        private:
            friend class DetourModKit::detail::InputPoller;

            // Binding generation this token was minted at; 0 marks an unresolved (invalid) token. A live generation is
            // always >= 1 (drawn from the process-wide counter that starts at 1), so 0 can never collide with a real
            // one.
            std::uint64_t m_generation{0};

            // The name's resolved entry indices into the engine's binding array, captured at acquire time. Read only
            // while m_generation still matches the engine's live generation, which guarantees the indices stay in
            // bounds and address the same bindings.
            std::vector<std::size_t> m_indices;
        };

        /**
         * @class BindingGuard
         * @brief Move-only RAII cancellation token for a binding from register_combo or config::press_combo /
         * hold_combo.
         * @details The guard owns a shared atomic flag that gates the user callback. On release (or destruction) the
         *          flag is cleared and subsequent input events for the binding become no-ops. The underlying binding
         *          remains registered in the engine; per-binding removal is not offered post-start, so the gating flag
         *          is how a callback is retired.
         *
         *          A Hold guard additionally carries a one-shot release action. A hold callback has lingering state
         *          (the consumer is told "held" until told "released"), so simply gating the callback off mid-hold
         *          would strand the consumer in the held state. The release action synthesizes a single balancing
         *          on_state_change(false) if a true edge was the last one forwarded, and never re-enters the callback
         *          while it is on the stack. A Press guard carries no such action.
         *
         *          Moving transfers ownership of the cancellation flag and the release action; the moved-from guard
         *          becomes inert.
         * @note Setup/control-plane only for Hold guards: release (and therefore the destructor) may invoke the hold
         *       release callback, so destroy a Hold guard from init / shutdown / a worker thread, never from inside an
         *       input callback running on a game thread.
         */
        class BindingGuard
        {
        public:
            // Defined out-of-line in input.cpp: an inline-defaulted ctor would instantiate ~unique_ptr<Impl> against
            // the still-incomplete Impl.
            BindingGuard() noexcept;
            ~BindingGuard() noexcept;

            BindingGuard(BindingGuard &&other) noexcept;
            BindingGuard &operator=(BindingGuard &&other) noexcept;
            BindingGuard(const BindingGuard &) = delete;
            BindingGuard &operator=(const BindingGuard &) = delete;

            /**
             * @brief Disables the binding's callback, then runs the Hold release action once if present. Idempotent.
             */
            void release() noexcept;

            /**
             * @brief Returns true while the binding's callback is still live (the guard has not been released or moved
             *        from).
             */
            [[nodiscard]] bool is_active() const noexcept;

            /**
             * @brief Returns the binding name this guard gates, or an empty view for an inert/moved-from guard.
             */
            [[nodiscard]] std::string_view name() const noexcept;

        private:
            friend class Input;

            // pimpl: the shared cancellation flag, the binding name, and the optional Hold release hookup. Defined in
            // src/input.cpp so the OS-free header carries no engine type.
            struct Impl;
            explicit BindingGuard(std::unique_ptr<Impl> impl) noexcept;
            std::unique_ptr<Impl> m_impl;
        };

        /**
         * @class Scope
         * @brief Owns a batch of BindingGuards and releases them in reverse insertion order on clear / destruction.
         * @details Replaces the consumer idiom of a hand-rolled std::vector<guard> plus a push wrapper. Guards are
         *          released last-registered-first (LIFO), mirroring stack-like teardown so a later binding that may
         *          depend on an earlier one unwinds first. Because a Hold guard can synthesize a balancing
         *          on_state_change(false) on release, the reverse order is a behavioral contract, not just member
         *          cleanup.
         * @note Move-only. Destroy a Scope holding Hold guards from setup/control-plane code (see BindingGuard).
         */
        class Scope
        {
        public:
            Scope() = default;
            ~Scope() noexcept { clear(); }

            Scope(Scope &&) noexcept = default;
            Scope &operator=(Scope &&) noexcept;
            Scope(const Scope &) = delete;
            Scope &operator=(const Scope &) = delete;

            /**
             * @brief Takes ownership of a guard, keeping its callback live until the Scope is cleared or destroyed.
             * @param guard A guard from register_combo (unwrapped) or config::press_combo / hold_combo. An inert guard
             *              is stored harmlessly.
             */
            void add(BindingGuard guard);

            /**
             * @brief Releases every owned guard in reverse insertion order, then drops them. Idempotent.
             */
            void clear() noexcept;

            /// Number of guards currently owned.
            [[nodiscard]] std::size_t size() const noexcept { return m_guards.size(); }

        private:
            // Guards in registration order; clear() walks this back-to-front so the release edges fire LIFO.
            std::vector<BindingGuard> m_guards;
        };

        /**
         * @class Input
         * @brief Process singleton that owns the poll thread, the binding set, and the interception layer.
         * @details Unifies the binding-management facade and the polling engine behind one entry point. Bindings may be
         *          registered before or after start(); a post-start registration is appended to the live set and fires
         *          on the next poll cycle. The interception layer (mouse-wheel capture and gamepad passthrough
         *          suppression) is process-global and single-owner, which is why a single Input instance owns it.
         *
         * @warning Inside a DLL, shutdown() must run before DLL_PROCESS_DETACH. Joining the poll thread under the
         *          Windows loader lock would deadlock; shutdown() detects the loader lock and detaches against a pinned
         *          module instead of joining. Route teardown through the bootstrap shutdown ordering.
         */
        class Input
        {
        public:
            /**
             * @struct Settings
             * @brief Poll-thread and gamepad tuning applied when start() builds the engine.
             * @details poll_interval is clamped to [MIN_POLL_INTERVAL, MAX_POLL_INTERVAL]. The gamepad knobs take
             *          effect only at start(); change require_focus live with set_require_focus.
             */
            struct Settings
            {
                /// Time between poll cycles. Clamped to the MIN/MAX poll-interval bounds.
                std::chrono::milliseconds poll_interval = DEFAULT_POLL_INTERVAL;
                /// When true (default), key events are ignored unless this process owns the foreground window.
                bool require_focus = true;
                /// XInput controller index (0-3) polled for gamepad bindings. Clamped to range.
                int gamepad_index = 0;
                /// Analog trigger deadzone (0-255). A trigger above this reads as pressed.
                int trigger_threshold = GamepadCode::TriggerThreshold;
                /// Thumbstick deadzone (0-32767). An axis exceeding this in any direction reads as pressed.
                int stick_threshold = GamepadCode::StickThreshold;
            };

            /**
             * @brief Returns the process-wide Input singleton.
             */
            [[nodiscard]] static Input &instance() noexcept;

            /**
             * @brief Registers one binding from a ComboBinding and returns a guard that owns its callback's lifetime.
             * @details Materializes one engine entry per combo, all sharing binding.name (OR logic). Works before or
             *          after start(); a post-start registration fires on the next cycle. An empty combos list registers
             *          an inert but addressable binding (rebind can populate it later) and still returns a valid guard.
             * @param binding The binding description (moved).
             * @return A BindingGuard on success, or ErrorCode::OutOfMemory if registration could not allocate. A null
             *         callback is accepted: the binding becomes inert but stays name-addressable (a common pattern for
             *         a state-polling binding queried only through is_active).
             * @note Setup/control-plane: registration may allocate and reshapes the binding set.
             */
            [[nodiscard]] Result<BindingGuard> register_combo(ComboBinding binding) noexcept;

            /**
             * @brief Builds the poll engine with the given settings and starts the poll thread.
             * @details Bindings registered before start() seed the engine; later registrations are forwarded live.
             *          Calling start() while already running is a no-op success.
             * @param settings Poll cadence, focus gate, and gamepad tuning.
             * @return Result<void>; ErrorCode::OutOfMemory if the engine could not be constructed.
             */
            [[nodiscard]] Result<void> start(Settings settings) noexcept;

            /// Starts the engine with default settings. See start(Settings).
            [[nodiscard]] Result<void> start() noexcept { return start(Settings{}); }

            /**
             * @brief Stops the poll thread and clears all bindings. Idempotent; the facade can be started again.
             * @details Under the loader lock the poll thread is detached against a pinned module instead of joined, and
             *          the still-installed detours are left in place; otherwise the thread is joined, the detours are
             *          removed, and active holds receive a final on_state_change(false).
             */
            void shutdown() noexcept;

            /// Returns true while the poll thread is running.
            [[nodiscard]] bool is_running() const noexcept;

            /// Returns the number of registered binding entries (pending before start, or live after).
            [[nodiscard]] std::size_t binding_count() const noexcept;

            /**
             * @brief Queries whether any combo of a named binding is currently pressed.
             * @param name The binding name.
             * @return true if active; false if the engine is not running or the name is unknown.
             * @note Thread-safe and callback-safe.
             */
            [[nodiscard]] bool is_active(std::string_view name) const noexcept;

            /**
             * @brief Resolves a binding name to a generation-checked token for repeated low-overhead queries.
             * @param name The binding name.
             * @return A valid token when running and the name is registered; an invalid token otherwise.
             * @note Setup/control-plane: acquire once (or after a reshape), then query with is_active(token).
             */
            [[nodiscard]] BindingToken acquire_token(std::string_view name) const noexcept;

            /**
             * @brief Queries a binding through a previously acquired token (the per-frame hot path).
             * @param token A token from acquire_token.
             * @return true if the token's binding is currently pressed; false if inactive, stale, invalid, or not
             *         running.
             * @note Callback-safe: a shared-lock acquire plus a relaxed atomic load per cached entry, no name hash and
             *       no allocation.
             */
            [[nodiscard]] bool is_active(const BindingToken &token) const noexcept;

            /**
             * @brief Reports whether a token still matches the live binding generation.
             * @param token A token from acquire_token.
             * @return true when the token is valid and current; false otherwise (re-acquire to recover).
             */
            [[nodiscard]] bool token_current(const BindingToken &token) const noexcept;

            /**
             * @brief Replaces the trigger combos of every binding sharing @p name (the INI hot-reload rebind path).
             * @details Matching combo counts rewrite in place; differing counts rebuild the entry set carrying callback
             *          identity, mode, and name forward. An empty list unbinds while keeping a single inert sentinel so
             *          the name stays addressable. Held bindings receive on_state_change(false) before the swap.
             * @param name Binding name previously registered.
             * @param combos Replacement combos (may be empty to unbind).
             * @return Result<void>; ErrorCode::InvalidArg if the name was never registered (the call is otherwise a
             *         success, including the unbind case).
             * @note Thread-safe; safe to call while the poll thread is running.
             */
            [[nodiscard]] Result<void> rebind(std::string_view name, KeyComboList combos) noexcept;

            /**
             * @brief Enables or disables passthrough suppression for every binding sharing @p name.
             * @details Forwards to the live engine or updates pending bindings before start(). A no-op if the name is
             *          unknown. See ComboBinding::consume for which inputs can actually be masked.
             * @param name Binding name previously registered.
             * @param consume true to hide the binding's trigger from the game.
             */
            void set_consume(std::string_view name, bool consume) noexcept;

            /**
             * @brief Sets whether the engine requires foreground focus before processing key events.
             * @param require_focus true to gate on foreground (default), false to process regardless of focus.
             * @note Thread-safe; takes effect immediately, before or after start().
             */
            void set_require_focus(bool require_focus) noexcept;

            /**
             * @brief Removes every binding sharing @p name (a name maps to many combos).
             * @details Forwards to the live engine, or erases matching entries from the pending set before start().
             *          Thread-safe.
             * @param name Binding name to remove.
             * @param invoke_callbacks When true (default) an active hold receives on_state_change(false) before
             *                         erasure. The loader-lock-safe Logic-DLL unload path passes false because the
             *                         hosting DLL's callback pages may be unmapping.
             * @return Number of bindings removed.
             */
            std::size_t remove_bindings_by_name(std::string_view name, bool invoke_callbacks = true) noexcept;

            /**
             * @brief Drops every binding without stopping the poll thread.
             * @details Forwards to the live engine and clears the pending set. The poll thread keeps running and can be
             *          reseeded. Thread-safe.
             * @param invoke_callbacks When true (default) active holds receive on_state_change(false) before erasure;
             *                         the loader-lock-safe unload path passes false.
             */
            void clear_bindings(bool invoke_callbacks = true) noexcept;

        private:
            Input();
            ~Input() noexcept;

            Input(const Input &) = delete;
            Input &operator=(const Input &) = delete;
            Input(Input &&) = delete;
            Input &operator=(Input &&) = delete;

            // pimpl: owns the engine (src/internal/input_poller.hpp) and the pending-binding staging. Defined in
            // src/input.cpp so this header names no engine type.
            struct Impl;
            std::unique_ptr<Impl> m_impl;
        };

        /**
         * @brief Free-function form of Input::instance().register_combo, so a consumer writes input::register_combo.
         * @param binding The binding description (moved).
         * @return A BindingGuard on success, or an ErrorCode-bearing failure (see Input::register_combo).
         */
        [[nodiscard]] Result<BindingGuard> register_combo(ComboBinding binding) noexcept;

        /**
         * @brief Returns the process-default Scope, so a consumer can write input::scope().add(...).
         * @details The default Scope is a convenience for mods that register a fixed set of bindings for the process
         *          lifetime and tear them down together. Its guards release in reverse insertion order when the Scope
         *          is cleared or at process teardown.
         * @note The default Scope is destroyed at static-destruction time, so a still-held Hold guard parked in it runs
         *       its on_state_change(false) on the teardown thread (see the BindingGuard Hold-guard control-plane note).
         *       A consumer needing deterministic teardown timing should own its own Scope.
         */
        [[nodiscard]] Scope &scope() noexcept;
    } // namespace input
} // namespace DetourModKit

#endif // DETOURMODKIT_INPUT_HPP
