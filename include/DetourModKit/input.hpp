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
             * masked. Default off keeps the binding purely observational. Releasing the binding's guard lifts the
             * suppression (the game regains the chord), so suppression lasts exactly as long as the guard is held.
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
         *          The token is stamped with the binding generation it was minted at. A reshape that alters the binding
         *          SET -- register, name-based rebind, name-based removal, clear, or a consume-flag change -- advances
         *          the generation, so a query through a stale token fails closed: it returns false without dereferencing
         *          the now-meaningless cached indices. A plain guard release does NOT advance the generation: it only
         *          retires the binding's callback while the binding stays registered (see BindingGuard), so the token
         *          keeps reflecting that binding's physical press state. A consume binding's guard release DOES advance
         *          the generation, but only because it clears the consume flag -- that is the consume-flag-change reshape
         *          above, not an effect of the plain release itself. The generation comes from a process-wide monotonic
         *          counter, so a token minted by one poll engine can never alias a different engine after a shutdown /
         *          start cycle. A default token, an unknown-name token, and an allocation-failed token are all invalid
         *          and always read inactive.
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
         *          release() runs down any delivery in flight: it serializes against the poll thread so that once it
         *          returns, no on_press / on_state_change for this binding is executing or will start. A caller is
         *          therefore free to destroy state a callback captured the instant release() (or the destructor)
         *          returns, without racing an in-progress invocation on the poll thread.
         *
         *          A Hold guard additionally carries a balancing edge. A hold callback has lingering state (the
         *          consumer is told "held" until told "released"), so simply gating the callback off mid-hold would
         *          strand the consumer in the held state. Release synthesizes a single on_state_change(false) if a true
         *          edge was the last one forwarded, and never re-enters the callback while it is on the stack.
         *
         *          A consume binding's release additionally lifts its passthrough suppression. Suppression is enforced
         *          off the engine entry's consume flag, not the gating flag, so releasing the guard also clears that
         *          flag (as set_consume(name, false) would); otherwise the game would stay deprived of the chord for
         *          the rest of the process.
         *
         *          Moving transfers ownership of the cancellation flag and the release action; the moved-from guard
         *          becomes inert.
         * @note Setup/control-plane only: release (and therefore the destructor) may invoke a Hold binding's balancing
         *       callback, and it blocks until any in-flight delivery on the poll thread has finished. Destroy a guard
         *       from init / shutdown / a worker thread. A guard destroyed from inside its own callback self-releases
         *       safely (the balancing edge is deferred to the callback's unwind, not re-entered), but do not park the
         *       teardown of one binding behind a long-running callback of another.
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
             * @brief Disables the binding's callback, then runs the binding teardown action once. Idempotent.
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
            friend class Scope;

            // Discards the guard's ownership WITHOUT running its teardown action: drops the pimpl so the destructor is
            // inert, but never fires the balancing Hold edge, never touches a gate mutex, and never clears a consume
            // flag. Used only by Scope::abandon() on the process-death path where running release would be unsafe. A
            // normal release() (and ~BindingGuard) is unchanged and still tears down fully.
            void disarm() noexcept;

            // pimpl: the shared cancellation flag, the binding name, and the teardown action. Defined in src/input.cpp
            // so the OS-free header carries no engine type.
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
         *          cleanup. Guard release may also block behind an in-flight callback; see BindingGuard.
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

            /**
             * @brief Discards every owned guard WITHOUT running any release. Idempotent. Process-death only.
             * @details The inverse of clear(): each guard is disarmed (its teardown action dropped) and then dropped,
             * so
             *          no callback fires, no gate mutex is taken, and no Hold binding synthesizes its balancing
             *          on_state_change(false). Use this only when the owning object is being abandoned during process
             *          teardown (see Session::abandon), where running the normal release edges -- callbacks and gate
             *          locks -- into a half-torn-down process is unsafe. For an ordinary live teardown use clear(), which
             *          preserves the reverse-order release contract.
             */
            void abandon() noexcept;

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
         *          registered before or after start(); a registration made while the engine is running is appended to
         *          the live set and fires on the next poll cycle, while one made before the engine exists is staged.
         *          A start() with no staged bindings builds no poll thread and stays not-running, so registrations made
         *          after such an empty start() remain staged until the next start() builds the engine (see start()).
         *          The interception layer (mouse-wheel capture and gamepad passthrough suppression) is process-global
         *          and single-owner, which is why a single Input instance owns it.
         *
         * @warning Inside a DLL, shutdown() must run before DLL_PROCESS_DETACH. Joining the poll thread under the
         *          Windows loader lock would deadlock; shutdown() detects the loader lock and detaches the poll thread,
         *          leaking its module reference to keep its code mapped instead of joining. Route teardown through the
         *          bootstrap shutdown ordering.
         *
         * @note Binding a mouse-wheel trigger installs a window-procedure subclass, and once that subclass has been
         *       live the module keeps a never-released reference on itself: restoring the original procedure only
         *       redirects future dispatches and cannot synchronize with a window-thread frame already inside the
         *       subclass procedure (a modal size/move loop holds one for as long as the user drags the title bar), so
         *       the code pages must stay mapped for the rest of the process. A session that used wheel bindings
         *       therefore keeps the host DLL mapped even after a drained shutdown; every other resource still tears
         *       down normally.
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
             * @details Materializes one entry per combo, all sharing binding.name (OR logic). A registration made while
             *          the engine is running is forwarded live and fires on the next cycle; one made before the engine
             *          exists -- before the first start(), or after a start() that had nothing to seed and so built no
             *          engine -- is staged and applies on the next start(). An empty combos list registers an inert but
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
             * @details Under the loader lock the poll thread is detached and its module reference leaked instead of
             *          joined, and the still-installed detours are left in place; otherwise the thread is joined, the
             *          detours are removed, and active holds receive a final on_state_change(false).
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
             * @note Thread-safe and callback-safe. Each call takes an atomic<shared_ptr> snapshot of the live poller
             *       (so it stays alive for the query even if shutdown() races), then hashes @p name under the engine's
             *       shared binding lock. The snapshot load is a reference-count acquire that is not lock-free on the
             *       shipped toolchains; for a per-frame query resolve a BindingToken once and use is_active(token).
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
             * @note Callback-safe and allocation-free: an atomic<shared_ptr> snapshot of the live poller, then a
             *       shared-lock acquire plus a relaxed atomic load per cached entry, with no name hash. The poller
             *       snapshot is a reference-count acquire (not lock-free on the shipped toolchains) taken once per call
             *       to keep the engine alive across the query; the token itself removes only the name-hash cost, not
             *       that snapshot.
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

            // Identity-keyed consume clear used by a consume binding's guard teardown. Not part of the public surface:
            // callers address bindings by name, but a guard owns the exact registration and must clear it even when its
            // name is empty (and therefore unresolvable through set_consume). Routes live-or-pending like set_consume.
            void set_consume_by_owner(std::uint64_t owner, bool consume) noexcept;

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
