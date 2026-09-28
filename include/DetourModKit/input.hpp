#ifndef DETOURMODKIT_INPUT_HPP
#define DETOURMODKIT_INPUT_HPP

/**
 * @file input.hpp
 * @brief Hotkey and gamepad input: combo bindings, edge detection, and opt-in passthrough suppression.
 * @warning `[B-100]` Run registration and Input::start() outside the loader lock. Registration allocates, and start()
 *          creates the poll thread. The loader-lock shutdown path vetoes the join and detaches the thread.
 */

#include "DetourModKit/error.hpp"
#include "DetourModKit/input_codes.hpp"
// A full include gives ExternalHost consumers the complete WheelHostTable. The C header excludes <windows.h>.
#include "DetourModKit/abi/wheel_host.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        // The poll engine (src/internal/input_poller.hpp).
        class InputPoller;

        // Test-only accessor (src/internal/input_test_seams.hpp), so this header has no macro-dependent member.
        struct InputTestSeams;
    } // namespace detail

    namespace input
    {
        /**
         * @brief One alternative key combination: OR across keys, AND across modifiers. Keep all codes of one combo in
         *        one device group (keyboard/mouse or gamepad). Mouse-wheel codes are a standalone, trigger-only source.
         */
        struct KeyCombo
        {
            std::vector<InputCode> keys;
            std::vector<InputCode> modifiers;
        };

        /// Alternative key combinations with OR between combos. An empty list binds no keys.
        using KeyComboList = std::vector<KeyCombo>;

        /** @brief Edge model for a binding. */
        enum class Trigger : std::uint8_t
        {
            /// Fires the on_press callback once per key-down edge.
            Press,
            /// Sends on_state_change(true) on press and false on release, and false once at teardown while held.
            Hold
        };

        /** @brief Typed outcome of an off-loader-lock input callback drain. */
        enum class CallbackDrainStatus : std::uint8_t
        {
            /// Every selected binding was retired, its callback destroyed, and all staged callable storage destroyed.
            Drained,
            /// A callback or staged callable storage outlived the deadline, or the drain failed to collect its gates.
            TimedOut,
            /// The caller runs inside an input callback and cannot wait for its own storage lease.
            SelfDelivery,
            /// Another control thread owns the drain transaction.
            InProgress,
            /// At least one selected binding was not retired.
            RetireFailed
        };

        /** @brief Returns "Press" or "Hold", or "Unknown" for an out-of-range value. */
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

        /// Default poll interval, about 60 Hz.
        inline constexpr std::chrono::milliseconds DEFAULT_POLL_INTERVAL{16};
        /// Lower clamp for the poll interval.
        inline constexpr std::chrono::milliseconds MIN_POLL_INTERVAL{1};
        /// Upper clamp for the poll interval.
        inline constexpr std::chrono::milliseconds MAX_POLL_INTERVAL{1000};

        /**
         * @brief Describes one named input binding for register_combo.
         * @details Modifier matching is strict across the whole binding set. A key that any binding uses as a modifier
         *          blocks each binding that does not list it, so "V" cannot fire while "Shift+V" is pressed.
         * @warning Callbacks must return quickly. They run on the poll thread, but a balancing edge can run on the
         *          thread that ends the hold. Captured objects must stay alive until the BindingGuard is released or
         *          the Input facade shuts down.
         */
        struct ComboBinding
        {
            /** @brief The key of the name-based calls. An empty name is addressable only through the guard. */
            std::string name = {};

            /// Press or Hold edge model.
            Trigger trigger = Trigger::Press;

            /// OR alternatives. An empty list registers an inert, addressable binding that rebind can populate.
            KeyComboList combos = {};

            /**
             * @brief Opt-in passthrough suppression that hides the trigger from the game while the guard is held.
             * @details Suppression covers only digital gamepad buttons (through an XInputGetState hook) and the mouse
             *          wheel. The engine masks the trigger of a gamepad chord from the poll cycle that sees the chord.
             *          A chord shape in the same-frame table (see Input::consume_capacity) masks its trigger from its
             *          first frame, with no poll-interval delay. If any pad entry point loses coverage, gamepad
             *          suppression stops on all of them until full coverage returns.
             * @note Best-effort: suppression may lapse without notice, and a later hook can restore a consumed wheel
             *       message. A binding must tolerate game access to its trigger.
             */
            bool consume = false;

            /// Invoked on the key-down edge when trigger == Press. Empty for a Hold binding.
            std::function<void()> on_press = {};

            /// Invoked with true when held and false when released, if trigger == Hold. Empty for a Press binding.
            std::function<void(bool)> on_state_change = {};
        };

        /** @brief Occupancy of the same-frame gamepad-chord table, in chord shapes. Registration never fails on it. */
        struct ConsumeCapacity
        {
            /// Distinct chord shapes the live table can hold, or zero while no engine runs.
            std::size_t capacity{0};
            /**
             * @brief Shapes published to the hook, or zero while a registered modifier is not a digital gamepad button.
             * @details In that case no chord keeps same-frame suppression, and @ref rejected does not count the loss.
             */
            std::size_t active{0};
            /// Eligible shapes the bound turned away. Non-zero means some chords lost same-frame suppression.
            std::size_t rejected{0};
        };

        /**
         * @brief Generation-checked handle to a named binding's entries for low-overhead repeated queries.
         * @details These reshapes advance the generation: register, name-based rebind or removal, clear, a real
         *          consume-flag transition, and a guard release that clears a set consume flag. A consume set that
         *          repeats the current value keeps every token current. No token matches another engine after a
         *          shutdown and start. Default, unknown-name, and allocation-failed tokens are invalid.
         */
        class BindingToken
        {
        public:
            BindingToken() = default;

            /// True if acquire_token resolved the name. A valid token can still be stale (see Input::token_current).
            [[nodiscard]] bool valid() const noexcept { return m_generation != 0; }

        private:
            friend class DetourModKit::detail::InputPoller;

            // 0 marks an unresolved token. The process-wide counter starts at 1.
            std::uint64_t m_generation{0};

            // Read only while m_generation matches the engine, which keeps each index in bounds.
            std::vector<std::size_t> m_indices;
        };

        /**
         * @brief RAII cancellation token of a binding from register_combo, config::press_combo, or config::hold_combo.
         * @details Release or destruction disables the callback and keeps the binding registered. Removal is by name
         *          through @ref Input::remove_bindings_by_name or for every binding through @ref Input::clear_bindings.
         *          After a release outside a callback returns, no callback of this binding runs or can start. No other
         *          thread is still inside its teardown code or a retired callable's capture destructors, so the caller
         *          can destroy captured state. A release inside a callback does not wait, so work on another thread
         *          can still run after it returns. Its balancing edge runs inline or at the unwind of the in-flight
         *          delivery.
         *
         *          A Hold guard synthesizes one on_state_change(false) if true was the last edge forwarded, and never
         *          re-enters a callback on the stack. Every release clears the consume flag of its registration,
         *          whether the registration or a later set_consume set it. Release and the prepare_logic_dll_unload
         *          retirement exclude each other, so the promise above holds for both. An ordinary release does not
         *          destroy a callable that the engine still holds. A guard that outlives the retirement stays valid but
         *          no longer reaches the callback.
         * @note Setup/control-plane only: destroy a guard outside hooks and input callbacks.
         * @warning release can wait, with no bound, for an in-flight callback of this binding or for a concurrent
         *          prepare_logic_dll_unload. The deadlock escape inside a callback is per-thread. Never destroy a guard
         *          while the thread owns a lock or join that callbacks or capture destructors can wait on.
         */
        class BindingGuard
        {
        public:
            // Out of line: an inline default constructor instantiates ~unique_ptr<Impl> on the incomplete Impl.
            BindingGuard() noexcept;
            ~BindingGuard() noexcept;

            BindingGuard(BindingGuard &&other) noexcept;
            BindingGuard &operator=(BindingGuard &&other) noexcept;
            BindingGuard(const BindingGuard &) = delete;
            BindingGuard &operator=(const BindingGuard &) = delete;

            /// Disables the binding's callback, then runs the binding teardown action once. Idempotent.
            void release() noexcept;

            /// True while the callback is enabled. False for a default, released, moved-from, or retired guard.
            [[nodiscard]] bool is_active() const noexcept;

            /// Returns the binding name this guard gates, or an empty view for a default or moved-from guard.
            [[nodiscard]] std::string_view name() const noexcept;

        private:
            friend class Input;
            // Defined in src/input.cpp.
            struct Impl;
            explicit BindingGuard(std::unique_ptr<Impl> impl) noexcept;
            std::unique_ptr<Impl> m_impl;
        };

        /**
         * @brief Owns BindingGuards and releases them in reverse insertion order on clear or destruction.
         * @note Setup/control-plane only: destroy a Scope where a BindingGuard can be destroyed. Release can block.
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

            /// Takes ownership of any guard, even an inert one.
            void add(BindingGuard guard);

            /**
             * @brief Releases the current guards in reverse insertion order. Idempotent.
             * @details A reentrant add stays in this Scope for the next clear.
             * @note Setup/control-plane only: the release runs consumer callbacks on the caller's thread.
             */
            void clear() noexcept;

            /**
             * @brief Abandons every guard with no release, destruction, gate mutex, or balancing edge. Idempotent.
             * @details Call it only for process termination (see Session::abandon). Guard release and capture
             *          destructors are unsafe under the loader lock. Use clear() for a live teardown.
             * @note Setup/control-plane only: a process-teardown path.
             */
            void abandon() noexcept;

            /// Number of guards currently owned.
            [[nodiscard]] std::size_t size() const noexcept { return m_guards ? m_guards->size() : 0; }

        private:
            // Allocated at the first add, so abandon() retains it with no allocation or destruction.
            std::unique_ptr<std::vector<BindingGuard>> m_guards;
        };

        /**
         * @brief Process singleton that owns the poll thread, the binding set, and the interception layer.
         * @details A binding registered while the engine runs fires from the next cycle. A binding registered before
         *          the engine exists stays pending. Each linked DMK instance has one interception layer with one owner.
         * @note MessageHook keeps this module mapped after its first successful publication.
         * @note ExternalHost keeps the wheel hook and its module reference in the loader module.
         */
        class Input
        {
        public:
            /**
             * @brief Selects the source that captures mouse-wheel notches.
             * @details Both backends see WM_MOUSEWHEEL and WM_MOUSEHWHEEL records removed from one selected UI-thread
             *          queue. Direct sent delivery, later DefWindowProc parent delivery, raw-input-only paths, and
             *          other UI-thread queues are outside support. Physical origin is not authenticated, so synthetic
             *          queued records can count, with no compatibility guarantee.
             */
            enum class WheelBackend : std::uint8_t
            {
                // Value 0 is reserved. A start() that builds the engine rejects it with ErrorCode::InvalidArg.
                /// A thread-scoped WH_GETMESSAGE hook compiled into this image (the single-DLL local default).
                MessageHook = 1,
                /// A loader-provided resident host driven through the wheel_host.h C ABI (the split topology).
                ExternalHost = 2,
            };

            /** @brief Typed health of the selected wheel route. Only Ready enables wheel counting and suppression. */
            enum class WheelSourceHealth : std::uint8_t
            {
                /// No engine runs, no wheel binding exists, or the ExternalHost lease is not open.
                Inactive,
                /// No target UI thread is selected. Automatic discovery retries each poll cycle.
                TargetWait,
                /// The wheel hook is mounted and its target thread is alive.
                Ready,
                /// The route was lost or disabled (target exit, failed mount, or a failed drain). Remount retries.
                Retryable,
                /// Old-hook removal failed on a live thread. No new mount starts until that thread exits.
                CleanupBlocked,
            };

            /** @brief Engine tuning for start(). A set_require_focus call overrides require_focus at any time. */
            struct Settings
            {
                /// Time between poll cycles. Clamped to the MIN/MAX poll-interval bounds.
                std::chrono::milliseconds poll_interval = DEFAULT_POLL_INTERVAL;
                /// If true (default), the engine ignores key events unless this process owns the foreground window.
                bool require_focus = true;
                /// XInput controller index (0 to 3) polled for gamepad bindings. Clamped to range.
                int gamepad_index = 0;
                /// Analog trigger deadzone (0 to 255). A trigger above this reads as pressed.
                int trigger_threshold = GamepadCode::TriggerThreshold;
                /// Thumbstick deadzone (0 to 32767). An axis past this value in any direction reads as pressed.
                int stick_threshold = GamepadCode::StickThreshold;
                /// Wheel-capture source that start() builds for mouse-wheel bindings.
                WheelBackend wheel_backend = WheelBackend::MessageHook;
                /**
                 * @brief ExternalHost table that wheel_host_start fills before start(). It must outlive the engine.
                 *        MessageHook ignores it.
                 */
                const WheelHostTable *wheel_host = nullptr;
                /**
                 * @brief Whether @ref WheelBackend::ExternalHost must have a valid host.
                 * @details If true, start() rejects an invalid table or failed lease, and a later host failure never
                 *          selects the local backend. If false, a start-time failure selects MessageHook.
                 */
                bool wheel_host_required = true;
                /**
                 * @brief Wheel target UI thread id. A non-zero id pins the route. Zero (default) selects discovery.
                 * @details start() rejects an id that is not a live thread of this process. Discovery follows the
                 *          foreground window of this process across its threads and keeps a healthy route through
                 *          focus loss.
                 */
                std::uint32_t wheel_target_thread_id = 0;
            };

            /**
             * @brief Returns the process-wide Input singleton.
             * @details If first-use allocation fails, it returns an inert singleton that stays inert. Registration and
             *          start() then report ErrorCode::OutOfMemory, queries read inactive, and mutators do nothing.
             * @note Callback-safe after first use: only the first call can allocate.
             */
            [[nodiscard]] static Input &instance() noexcept;

            /**
             * @brief Registers @p binding and returns the guard that owns its callback lifetime.
             * @details A null callback or an empty combo list still registers an addressable binding. A call concurrent
             *          with shutdown() can register nothing and return a guard whose is_active() is false.
             * @return ErrorCode::OutOfMemory on allocation failure. ErrorCode::ShutdownInProgress after a
             *         process-lifetime veto or while callback staging is closed (see prepare_logic_dll_unload()).
             * @note Setup/control-plane only: registration can allocate and reshapes the binding set.
             */
            [[nodiscard]] Result<BindingGuard> register_combo(ComboBinding binding) noexcept;

            /**
             * @brief Builds the engine from the pending bindings and starts the poll thread.
             * @details While a callback drain is active or pending, start() returns ShutdownInProgress. Otherwise a
             *          start() while the engine runs only re-arms callback staging and succeeds. With no pending
             *          binding, start() also succeeds, builds no poll thread, and is_running() stays false.
             * @return ErrorCode::InvalidArg reports an invalid backend, host table, or wheel target thread. OutOfMemory
             *         reports an allocation failure. ShutdownInProgress reports a teardown conflict. SystemCallFailed
             *         reports a module-reference, thread, or required-host lease failure. Its Error::detail is
             *         GetLastError(), the std::system_error code value, or the magnitude of the negative
             *         DMK_WHEELHOST_* status, in that order.
             * @note Allocation, system-call, and callback-drain failures are retryable. The pending bindings and a
             *       pending set_require_focus value remain for a later start(). A process-lifetime veto is terminal.
             * @note Setup/control-plane only: start() allocates the engine and creates the poll thread.
             */
            [[nodiscard]] Result<void> start(Settings settings) noexcept;

            /// Starts the engine with default settings. See start(Settings).
            [[nodiscard]] Result<void> start() noexcept { return start(Settings{}); }

            /**
             * @brief On the normal path, joins the poll thread, removes the detours, delivers final Hold releases, and
             *        clears all bindings.
             * @details Idempotent. Except after the process-lifetime veto below, the facade can start again.
             * @note A call under the loader lock, from DLL_PROCESS_DETACH, or at process exit is a process-lifetime
             *       veto. It retains the facade owner, the engine, module references, and detours. It takes no mutex
             *       and destroys no staged callable. Outside process exit, it stops the poll loop and detaches the poll
             *       thread. A failed join also retains the engine, module references, and detours.
             * @note A call from a binding callback on any thread is asynchronous. That covers a balancing edge that
             *       rebind, removal, clear, or a guard release delivers on its caller's thread. The call returns with
             *       is_running() false, and callbacks already staged for the current cycle still complete. An
             *       off-thread reaper runs the join, detour removal, and final on_state_change(false). If the hand-off
             *       to the reaper fails, the whole owner stays retained for the process with no final release.
             * @note Setup/control-plane only, except for the asynchronous binding-callback call.
             */
            void shutdown() noexcept;

            /// Returns true while the poll thread runs.
            [[nodiscard]] bool is_running() const noexcept;

            /**
             * @brief Returns the number of registered binding entries (pending before start, or live after).
             * @details Each combo is one entry, and an empty combo list is one inert entry.
             */
            [[nodiscard]] std::size_t binding_count() const noexcept;

            /**
             * @brief Reports whether any combo of @p name is pressed. False if no engine runs or the name is unknown.
             * @note Callback-safe and thread-safe, but not lock-free. For a per-frame query, use a BindingToken.
             */
            [[nodiscard]] bool is_active(std::string_view name) const noexcept;

            /**
             * @brief Resolves @p name to a token, which is invalid unless the engine runs and the name is registered.
             * @note Setup/control-plane only: acquire once and after each reshape. Query with is_active(token).
             */
            [[nodiscard]] BindingToken acquire_token(std::string_view name) const noexcept;

            /**
             * @brief Per-frame query: true while the token's binding is pressed. A stale or invalid token reads false.
             * @note Callback-safe and allocation-free. The token removes the name hash, not the poller snapshot.
             */
            [[nodiscard]] bool is_active(const BindingToken &token) const noexcept;

            /**
             * @brief True if @p token is valid and matches the live generation. If false, acquire a new token.
             * @note Callback-safe: the same poller-snapshot cost as is_active(token).
             */
            [[nodiscard]] bool token_current(const BindingToken &token) const noexcept;

            /**
             * @brief Replaces the combos of each binding that shares @p name. An empty list unbinds and keeps the name.
             * @details An equal combo count rewrites in place and keeps held state. Another count rebuilds every entry
             *          from the first binding of that name, then sends one on_state_change(false) to each held binding.
             * @return ErrorCode::InvalidArg for an unknown name. OutOfMemory leaves all binding state unchanged.
             * @note Thread-safe, also while the poll thread runs. After return, a press or true edge staged from the
             *       prior combos cannot fire, but a staged false edge is still delivered. A call outside an input
             *       callback waits for old-generation callbacks that already began. A call from an input callback
             *       disables the old generation and does not wait.
             * @note Setup/control-plane only: the rebind can allocate and reshapes the binding set.
             */
            [[nodiscard]] Result<void> rebind(std::string_view name, KeyComboList combos) noexcept;

            /**
             * @brief Sets ComboBinding::consume on every binding that shares @p name. An unknown name is a no-op.
             * @note Setup/control-plane only: the toggle updates the live or pending binding set.
             */
            void set_consume(std::string_view name, bool consume) noexcept;

            /**
             * @brief Reports occupancy of the same-frame gamepad-chord table. Each field is zero with no live engine.
             * @note Callback-safe and allocation-free, but not lock-free: it takes the bounded poller snapshot.
             */
            [[nodiscard]] ConsumeCapacity consume_capacity() const noexcept;

            /**
             * @brief Reports the typed health of the selected wheel route.
             * @details The engine logs a host publish, drain, health, or retarget error. A failed route reads as a
             *          non-Ready state.
             * @note Setup/control-plane only: the local backend checks the target thread under the interception lock.
             */
            [[nodiscard]] WheelSourceHealth wheel_source_health() const noexcept;

            /**
             * @brief Sets whether the engine processes key events only while this process owns the foreground window.
             * @details A live engine applies the value at once. With no engine, it overrides Settings::require_focus
             *          for the next start() that builds one. shutdown() discards a pending value.
             * @note Setup/control-plane only: a thread-safe configuration toggle, not a per-frame call.
             */
            void set_require_focus(bool require_focus) noexcept;

            /**
             * @brief Removes every live or pending binding that shares @p name.
             * @details A staged callback of a removed entry cannot begin after this returns. A call from an input
             *          callback does not wait on input callbacks in flight. If @p invoke_callbacks is true, an active
             *          hold receives on_state_change(false) after its removal. A call from an input callback can defer
             *          that edge to the unwind of the in-flight delivery. If @p invoke_callbacks is false, no edge runs
             *          and the call does not wait on callbacks in flight. Because the callback DLL can unload after its
             *          drain, prepare_logic_dll_unload() passes false.
             * @return The number of removed entries. Zero also reports a logged allocation refusal that keeps state.
             * @note Setup/control-plane only: the removal reshapes the binding set and can run callbacks.
             */
            std::size_t remove_bindings_by_name(std::string_view name, bool invoke_callbacks = true) noexcept;

            /**
             * @brief Drops every live and pending binding. The poll thread stays alive and accepts new bindings.
             * @details The callback and @p invoke_callbacks rules of remove_bindings_by_name() apply.
             * @note Setup/control-plane only: the clear drops every binding and can run callbacks.
             */
            void clear_bindings(bool invoke_callbacks = true) noexcept;

            /**
             * @brief Retires the named bindings and waits until all staged input callable storage is destroyed.
             * @details Retirement destroys each callback through its delivery gate, even while its BindingGuard lives.
             *          A held binding receives its balancing on_state_change(false) during the drain.
             * @param timeout Maximum wait after callback-staging admission closes.
             * @return Only CallbackDrainStatus::Drained meets the input precondition to unmap the callback provider.
             * @note Setup/control-plane only. Must run off the Windows loader lock and outside input callbacks.
             * @note Callback staging stays closed after return. Call start() only after the unload transaction also
             *       drained its other callback sources.
             */
            [[nodiscard]] CallbackDrainStatus prepare_logic_dll_unload(
                std::span<const std::string_view> binding_names,
                std::chrono::milliseconds timeout
            ) noexcept;

            /**
             * @brief Retires every binding and waits until all staged input callable storage is destroyed.
             * @details @p timeout, the retirement rules, and the Drained precondition match prepare_logic_dll_unload().
             * @note Setup/control-plane only. Must run off the Windows loader lock and outside input callbacks.
             * @note Callback staging stays closed after return. A later start() re-arms it only after a successful
             *       drain.
             */
            [[nodiscard]] CallbackDrainStatus prepare_logic_dll_unload_all(std::chrono::milliseconds timeout) noexcept;

        private:
            // Test access lives outside this header (see detail::InputTestSeams).
            friend struct detail::InputTestSeams;

            Input() noexcept;
            ~Input() noexcept;

            Input(const Input &) = delete;
            Input &operator=(const Input &) = delete;
            Input(Input &&) = delete;
            Input &operator=(Input &&) = delete;

            // Every guard teardown runs this identity-keyed consume clear, which also reaches an empty name.
            void set_consume_by_owner(std::uint64_t owner, bool consume) noexcept;

            // False (a gate active at the deadline, or uncollectable handles) maps to CallbackDrainStatus::TimedOut.
            [[nodiscard]] bool retire_gates_for_unload(
                std::span<const std::string_view> binding_names,
                bool every_binding,
                std::chrono::steady_clock::time_point deadline
            ) noexcept;

            // Owns the engine and the pending bindings. Defined in src/input.cpp.
            struct Impl;

            // The stateless deleter keeps the owner pointer-sized and obeys the shutdown() retention latch.
            struct ImplDeleter
            {
                void operator()(Impl *impl) const noexcept;
            };
            using ImplOwner = std::unique_ptr<Impl, ImplDeleter>;

            // Allocates the Impl with a caught failure, so the noexcept constructor can publish the inert state.
            [[nodiscard]] static ImplOwner create_impl() noexcept;

            // True after first-use allocation failure or a process-lifetime veto. See instance().
            [[nodiscard]] bool is_inert() const noexcept;

            // Shared snapshot for the callback-safe queries. Null when inert or when no engine runs.
            [[nodiscard]] std::shared_ptr<detail::InputPoller> poller_snapshot() const noexcept;

            ImplOwner m_impl;
        };

        /**
         * @brief Calls Input::instance().register_combo() and returns its result.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] Result<BindingGuard> register_combo(ComboBinding binding) noexcept;

        /**
         * @brief Returns the process-default Scope. Under `[B-47]`, it lives for the process and is never destroyed.
         * @note During an ordinary unload, call scope().clear() off the loader lock. Otherwise its guards and callbacks
         *       remain until process exit.
         */
        [[nodiscard]] Scope &scope() noexcept;
    } // namespace input
} // namespace DetourModKit

#endif // DETOURMODKIT_INPUT_HPP
