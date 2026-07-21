#ifndef DETOURMODKIT_INPUT_HPP
#define DETOURMODKIT_INPUT_HPP

/**
 * @file input.hpp
 * @brief Hotkey and gamepad input surface: combo bindings, edge detection, and opt-in passthrough suppression.
 * @details A binding is registered once as a ComboBinding and owned by a move-only BindingGuard; a Scope batches
 *          guards and releases them in reverse insertion order. The Input facade owns a single background poll thread
 *          and the process-global interception layer (one XInput hook plus one window-procedure subclass).
 *
 *          Combo vocabulary (KeyCombo / KeyComboList) lives here, not in config, because a combo is a pure input
 *          concept. config depends on input to fuse an INI key to a live binding, never the reverse.
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
        // The poll/edge-detection engine. Defined in the non-installed src/internal/input_poller.hpp and left
        // incomplete here, so BindingToken can grant it friendship (the engine mints and validates tokens against its
        // binding set) and Input's private accessors can hand one back without exposing its layout.
        class InputPoller;
    } // namespace detail

    namespace input
    {
        /**
         * @struct KeyCombo
         * @brief One alternative key combination: OR across keys, AND across modifiers.
         * @details All codes in one combo should be from the same device group (keyboard/mouse or gamepad);
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
         * @details One register_combo call materializes one binding entry per combo, all sharing the name, so a
         *          name-based query is true when any of its combos is pressed.
         *
         *          Modifier matching is strict across the whole binding set: any key that appears as a modifier in any
         *          registered binding blocks bindings that do not list it, so "V" cannot fire when "Shift+V" is
         *          pressed.
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
             * masked. Default off keeps the binding purely observational. Releasing the binding's guard lifts the
             * suppression (the game regains the chord), so suppression lasts exactly as long as the guard is held.
             *
             * Gamepad suppression has two tiers, and the stronger one is bounded. Every consume gamepad chord gets the
             * reactive mask, which hides the trigger from the game once the poll thread has observed the chord. Same-
             * frame suppression, which additionally closes the window where a modifier and its trigger go down inside
             * one poll interval, comes from a fixed-size table the game-thread hook reads. Distinct chord shapes beyond
             * that table keep the reactive mask and lose only the same-frame tier; Input::consume_capacity reports
             * whether any did.
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
         * @struct ConsumeCapacity
         * @brief Occupancy of the bounded same-frame gamepad-chord suppression table.
         * @details Registration never fails on this bound, so a mod that wants to know whether it fits must ask.
         *          @ref ConsumeCapacity::rejected counts the distinct chord shapes the table could not hold; each of
         *          those keeps the reactive mask and loses only same-frame suppression (see @ref
         *          ComboBinding::consume). Exact duplicate shapes share one entry, so @ref ConsumeCapacity::active is
         *          a count of shapes, not of bindings.
         */
        struct ConsumeCapacity
        {
            /// Distinct chord shapes the live table can hold, or zero while no engine is active.
            std::size_t capacity{0};
            /**
             * @brief Shapes currently published to the hook.
             * @details Reads zero whenever any registered modifier anywhere in the binding set is not a digital
             *          gamepad button, because the hook cannot reproduce strict matching for any chord in that case.
             *          That loss is not a capacity shortfall, so @ref rejected does not count it.
             */
            std::size_t active{0};
            /// Eligible shapes the bound turned away. Non-zero means some chords lost same-frame suppression.
            std::size_t rejected{0};
        };

        /**
         * @class BindingToken
         * @brief Generation-checked handle to a named binding's resolved entry set for low-overhead repeated queries.
         * @details The token is stamped with the binding generation it was minted at. A reshape that alters the binding
         *          SET -- register, name-based rebind, name-based removal, clear, or a consume-flag change -- advances
         *          the generation, so a stale token fails closed and reads inactive rather than dereferencing its
         *          cached indices. A plain guard release does NOT advance it: the binding stays registered, so the
         *          token keeps reflecting its physical press state. A consume binding's release does advance it, but
         *          only through the consume-flag change. The counter is process-wide and monotonic, so a token cannot
         *          alias a different engine after a shutdown / start cycle. Default, unknown-name, and
         *          allocation-failed tokens are all invalid and always read inactive.
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

            // 0 marks an unresolved token. The process-wide counter starts at 1, so it can never collide.
            std::uint64_t m_generation{0};

            // Read only while m_generation still matches the engine's, which is what keeps these in bounds.
            std::vector<std::size_t> m_indices;
        };

        /**
         * @class BindingGuard
         * @brief Move-only RAII cancellation token for a binding from register_combo or config::press_combo /
         *        hold_combo.
         * @details Release (or destruction) gates the user callback off; the binding itself stays registered, because
         *          per-binding removal is not offered post-start.
         *
         *          Release from OUTSIDE a callback runs down delivery in flight: once it returns no on_press /
         *          on_state_change for this binding is running or can start, so the caller may then destroy state a
         *          callback captured. Release from INSIDE a callback -- self-release, or one binding's callback
         *          releasing another's guard -- cannot block without deadlocking two interdependent teardowns, so it
         *          retires the callback and defers the rundown to the in-flight delivery's unwind. A caller using that
         *          pattern must not assume the other callback has finished when release() returns.
         *
         *          A Hold guard synthesizes one balancing on_state_change(false) when a true edge was the last one
         *          forwarded, so gating off mid-hold cannot strand a consumer in the held state, and never re-enters a
         *          callback that is on the stack. A consume binding's release also clears its engine-side consume flag
         *          (as set_consume(name, false) would); suppression is enforced off that flag, not the gating flag, so
         *          otherwise the game would stay deprived of the chord for the rest of the process.
         * @note Setup/control-plane only: release may invoke a Hold binding's balancing callback and may block on the
         *       poll thread. Destroy a guard from init / shutdown / a worker thread.
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

            /// Disables the binding's callback, then runs the binding teardown action once. Idempotent.
            void release() noexcept;

            /// Returns true while the binding's callback is still live (not released, not moved from).
            [[nodiscard]] bool is_active() const noexcept;

            /// Returns the binding name this guard gates, or an empty view for an inert or moved-from guard.
            [[nodiscard]] std::string_view name() const noexcept;

        private:
            friend class Input;
            // pimpl: the shared cancellation flag, the binding name, and the teardown action. Defined in src/input.cpp
            // so the OS-free header carries no engine type.
            struct Impl;
            explicit BindingGuard(std::unique_ptr<Impl> impl) noexcept;
            std::unique_ptr<Impl> m_impl;
        };

        /**
         * @class Scope
         * @brief Owns a batch of BindingGuards and releases them in reverse insertion order on clear / destruction.
         * @details Because a Hold guard can synthesize a balancing on_state_change(false) on release, the reverse order
         *          is a behavioral contract a consumer can rely on, not incidental member cleanup: a later binding that
         *          depends on an earlier one unwinds first. Guard release may also block behind an in-flight callback;
         *          see BindingGuard.
         * @note Move-only. Destroy a Scope from setup/control-plane code (see BindingGuard).
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

            /// Takes ownership of a guard. An inert guard is stored harmlessly.
            void add(BindingGuard guard);

            /// Releases every owned guard in reverse insertion order, then drops them. Idempotent.
            void clear() noexcept;

            /**
             * @brief Abandons every owned guard without running release or destruction. Idempotent. Process-death only.
             * @details Retains the complete guard container without destroying callback captures, taking a gate mutex,
             *          or synthesizing a balancing on_state_change(false). Use this only when the owning object is
             *          being abandoned during process teardown (see Session::abandon), where running release logic or
             *          consumer destructors inside DllMain is unsafe. For an ordinary live teardown use clear().
             */
            void abandon() noexcept;

            /// Number of guards currently owned.
            [[nodiscard]] std::size_t size() const noexcept { return m_guards ? m_guards->size() : 0; }

        private:
            // Heap ownership is precommitted when the first guard is added, so abandon() can retain the complete
            // container with unique_ptr::release and no allocation or destruction on the process-detach path.
            std::unique_ptr<std::vector<BindingGuard>> m_guards;
        };

        /**
         * @class Input
         * @brief Process singleton that owns the poll thread, the binding set, and the interception layer.
         * @details Bindings may be registered before or after start(): one made while the engine runs joins the live
         *          set and fires on the next cycle, one made before the engine exists is staged. A start() with
         *          nothing staged builds no poll thread and stays not-running, so registrations made after such an
         *          empty start() wait for the next one (see start()). The interception layer is process-global and
         *          single-owner, which is why one Input instance owns it.
         * @warning Inside a DLL, shutdown() must run before DLL_PROCESS_DETACH. When the lifecycle phase does not
         *          authorize blocking, or the loader-lock probe vetoes it, shutdown() detaches the poll thread and
         *          retains its module reference instead of joining. Route teardown through the bootstrap shutdown
         *          ordering.
         * @note Binding a mouse-wheel trigger installs a window-procedure subclass, after which the module keeps a
         *       never-released reference on itself. Restoring the original procedure only redirects future dispatches
         *       and cannot synchronize with a window-thread frame already inside the subclass (a modal size/move loop
         *       holds one for as long as the user drags the title bar), so those code pages must stay mapped for the
         *       rest of the process. A session that used wheel bindings therefore keeps the host DLL mapped even after
         *       a drained shutdown; every other resource still tears down normally.
         */
        class Input
        {
        public:
            /**
             * @struct Settings
             * @brief Poll-thread and gamepad tuning applied when start() builds the engine.
             * @details The gamepad knobs take effect only at start(); change require_focus live with set_require_focus.
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
             * @details Never throws and never terminates. If first-use allocation fails, a complete inert singleton is
             *          published instead: registration and start() report ErrorCode::OutOfMemory, every query reads
             *          inactive, and the mutators are no-ops. No poll thread, binding storage, or partially built
             *          engine is published on that path, and the inert state latches for the process generation.
             */
            [[nodiscard]] static Input &instance() noexcept;

            /**
             * @brief Registers one binding from a ComboBinding and returns a guard that owns its callback's lifetime.
             * @details Materializes one entry per combo, all sharing binding.name (OR logic); see the class-level
             *          details for when a registration goes live. An empty combos list registers an inert but
             *          addressable binding (rebind can populate it later) and still returns a valid guard.
             * @param binding The binding description (moved).
             * @return A BindingGuard on success, or ErrorCode::OutOfMemory if registration could not allocate. A null
             *         callback is accepted: the binding becomes inert but stays name-addressable (a common pattern for
             *         a state-polling binding queried only through is_active).
             * @note Setup/control-plane: registration may allocate and reshapes the binding set.
             */
            [[nodiscard]] Result<BindingGuard> register_combo(ComboBinding binding) noexcept;

            /**
             * @brief Builds the poll engine with the given settings and starts the poll thread.
             * @details Bindings staged before start() seed the engine; once running, later registrations are forwarded
             *          live. Calling start() while already running is a no-op success. A start() with nothing staged is
             *          also a no-op success: it builds no poll thread and is_running() stays false, because there is
             *          nothing to poll. The engine is constructed by the first start() that has at least one staged
             *          binding, so a bindings-after-empty-start() sequence takes effect only on that later start(),
             *          never retroactively on the empty one.
             * @param settings Poll cadence, focus gate, and gamepad tuning.
             * @return Result<void>; ErrorCode::OutOfMemory if the engine could not be constructed, or
             *         ErrorCode::SystemCallFailed if the poll thread could not be started safely.
             * @note Failure is retryable: on error the staged bindings remain staged (nothing is consumed until the
             *       engine has actually started), so a later start() attempts the same set again.
             */
            [[nodiscard]] Result<void> start(Settings settings) noexcept;

            /// Starts the engine with default settings. See start(Settings).
            [[nodiscard]] Result<void> start() noexcept { return start(Settings{}); }

            /**
             * @brief Stops the poll thread and clears all bindings. Idempotent; the facade can be started again.
             * @details Normally joins the poll thread, removes detours, and delivers final Hold releases before return.
             * @note Loader-lock or failed-join teardown retains the complete owner, module reference, and detours.
             * @note Callable from a binding callback, where the poll thread is its own teardown thread and cannot be
             *       joined. Such a call is asynchronous: is_running() reads false and no further poll cycle runs, but
             *       the callbacks already staged for the current cycle still complete, and the join, detour removal,
             *       and final on_state_change(false) run on a background retirement thread once the callback returns.
             *       Callback code and its captures stay mapped until then. If that thread cannot take the retirement
             *       (memory pressure), the whole owner is retained for the process lifetime instead and no final
             *       on_state_change(false) is delivered, which is the same fail-closed outcome as the note above.
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
             * @note Thread-safe and callback-safe. Each call takes an atomic<shared_ptr> snapshot of the live poller so
             *       it stays alive across the query, then hashes @p name under the engine's shared binding lock. That
             *       snapshot is a reference-count acquire and is not lock-free on the shipped toolchains; for a
             *       per-frame query resolve a BindingToken once and use is_active(token).
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
             * @note Callback-safe and allocation-free: the poller snapshot, then a shared-lock acquire plus a relaxed
             *       atomic load per cached entry, with no name hash. The token removes only the name-hash cost, not
             *       the snapshot.
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
             * @details Matching combo counts rewrite in place, carrying each entry's held state across the key swap;
             *          differing counts rebuild the entry set carrying callback identity, mode, and name forward and
             *          synthesize on_state_change(false) for any dropped held binding after the rebuild. An empty list
             *          unbinds while keeping a single inert sentinel so the name stays addressable.
             * @param name Binding name previously registered.
             * @param combos Replacement combos (may be empty to unbind).
             * @return Result<void>; ErrorCode::InvalidArg if the name was never registered (the call is otherwise a
             *         success, including the unbind case).
             * @note Thread-safe; safe to call while the poll thread is running. A press or held(true) callback staged
             *       from the prior combo cannot fire after this returns; a staged release(false) is still delivered so
             *       a binding held as the swap lands ends released, not stranded. A callback that already began may
             *       finish before an external call returns; a rebind reached from an input callback retires the old
             *       generation without waiting on the callback stack that requested it.
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
             * @brief Reports occupancy of the bounded same-frame gamepad-chord suppression table.
             * @details The companion query to the void @ref set_consume and to the registration verbs, none of which
             *          fail on this bound. A non-zero @ref ConsumeCapacity::rejected reports that the table bound left
             *          some otherwise eligible consume chords on the reactive mask alone. Every field reads zero
             *          whenever no engine is live: before the first start(), after shutdown(), and on the inert
             *          singleton a first-use allocation failure publishes.
             * @return The live occupancy.
             * @note Callback-safe and allocation-free, but not lock-free: like every facade query it first takes an
             *       atomic<shared_ptr> snapshot of the live poller, which is a bounded internal critical section on
             *       both shipped toolchains. The occupancy itself is one relaxed atomic load.
             */
            [[nodiscard]] ConsumeCapacity consume_capacity() const noexcept;

            /**
             * @brief Sets whether the engine requires foreground focus before processing key events.
             * @param require_focus true to gate on foreground (default), false to process regardless of focus.
             * @note Thread-safe; takes effect immediately, before or after start().
             */
            void set_require_focus(bool require_focus) noexcept;

            /**
             * @brief Removes every binding sharing @p name (a name maps to many combos).
             * @details Forwards to the live engine, or erases matching entries from the pending set before start(). A
             *          staged callback for a removed entry cannot begin after this returns. A call reached from an
             *          input callback does not wait on input callbacks already in flight.
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
             *          reseeded. A staged callback for a cleared entry cannot begin after this returns. A call reached
             *          from an input callback does not wait on input callbacks already in flight.
             * @param invoke_callbacks When true (default) active holds receive on_state_change(false) before erasure;
             *                         the loader-lock-safe unload path passes false.
             */
            void clear_bindings(bool invoke_callbacks = true) noexcept;

        private:
            Input() noexcept;
            ~Input() noexcept;

            Input(const Input &) = delete;
            Input &operator=(const Input &) = delete;
            Input(Input &&) = delete;
            Input &operator=(Input &&) = delete;

            // Identity-keyed consume clear used by a consume binding's guard teardown. Not part of the public surface:
            // callers address bindings by name, but a guard owns the exact registration and must clear it even when its
            // name is empty (and therefore unresolvable through set_consume). Routes live-or-pending like set_consume.
            void set_consume_by_owner(std::uint64_t owner, bool consume) noexcept;

            // pimpl: owns the engine (src/internal/input_poller.hpp) and the pending-binding staging. Defined in
            // src/input.cpp, so the only engine type this header names stays incomplete.
            struct Impl;

            // Allocates the Impl with a caught failure, so the noexcept constructor can publish the inert state.
            [[nodiscard]] static std::unique_ptr<Impl> create_impl() noexcept;

            /// True for the inert singleton whose first-use allocation failed. See instance().
            [[nodiscard]] bool is_inert() const noexcept { return !m_impl; }

            // Shared snapshot for the callback-safe queries; null when inert or not running.
            [[nodiscard]] std::shared_ptr<detail::InputPoller> poller_snapshot() const noexcept;

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
