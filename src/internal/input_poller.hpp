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
#include "internal/input_binding_gate.hpp"
#include "internal/input_binding_lifecycle.hpp"
#include "internal/input_intercept.hpp"
#include "internal/srw_shared_mutex.hpp"

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
#include <utility>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @brief Allocates a fresh binding lifecycle at the next process-wide generation.
         * @details The facade calls this in register_combo to share one block across a name's exploded engine entries
         *          and their gate; the engine reuses the block a binding already carries and only allocates for one
         *          seeded without. Defined in input_poller.cpp, which owns the monotonic generation counter.
         * @note Also the point at which the delivery-scope TLS slot is reserved. A process with no slot left still
         *       registers bindings, but every delivery to them is then refused (see input_delivery_scope.hpp), so the
         *       failure is reported once through the log rather than surfacing as silently absent callbacks.
         */
        [[nodiscard]] std::shared_ptr<BindingLifecycle> make_binding_lifecycle();

        /**
         * @struct InputBinding
         * @brief Engine record for a single input-to-action binding (one combo).
         * @details Holds the action name, trigger and modifier codes, the trigger mode, the suppression opt-in, and the
         *          callbacks. The keys vector is OR logic (any single trigger fires); the modifiers vector is AND
         *          logic (all must be held). Modifier matching is strict across the whole binding set: any key used as
         *          a modifier in any binding blocks bindings that do not list it, so "V" does not fire while "Shift+V"
         *          is pressed.
         *
         *          For Trigger::Press the press callback fires on the key-down edge; for Trigger::Hold the state
         *          callback fires true on press and false on release (including a synthesized false at shutdown for an
         *          active hold). All codes in one binding should come from the same device group; mouse-wheel codes are
         *          trigger-only and Press-mode (a notch reads as one Press edge). Callbacks run on the poll thread and
         *          must be quick.
         */
        struct InputBinding
        {
            std::string name;
            std::vector<InputCode> keys;
            std::vector<InputCode> modifiers;
            input::Trigger trigger = input::Trigger::Press;

            // Opt-in passthrough suppression. Honored only for digital gamepad buttons (via the XInputGetState hook)
            // and the mouse wheel (via the window-procedure hook); analog axes and keyboard/mouse buttons cannot be
            // masked.
            bool consume = false;

            // Identity of the register_combo() call that produced this entry. A guard's teardown clears the consume
            // flag by this id, not by name: an empty-name consume binding is legal (input.hpp) but is absent from the
            // name-index (recompute skips empty names), so a name-keyed clear would silently miss it and leave
            // suppression armed for the process lifetime. 0 is the "no owner" sentinel for config-seeded / test /
            // direct-constructed bindings, which keep the by-name clear path; a by-owner clear with owner 0 is a no-op.
            std::uint64_t consume_owner = 0;

            std::function<void()> on_press;
            std::function<void(bool)> on_state_change;

            // Generation/tombstone for this binding's registration, consulted when a staged poll-cycle callback is
            // dispatched so a remove / clear / cardinality-changing rebind that lands between staging and dispatch
            // refuses the stale old-generation callback. register_combo shares one block across a name's exploded
            // entries and their gate; the poller allocates one for any entry seeded without it (config-seeded or
            // directly constructed). See BindingLifecycle.
            std::shared_ptr<BindingLifecycle> lifecycle;

            // Set when on_state_change is a self-deduplicating HoldGate wrapper (delivering released(false) with no
            // live held(true) is a no-op). A tombstoning reshape (remove / clear) then publishes the balancing false
            // unconditionally instead of gating on m_active_states, which the poll loop zeroes when it commits a cycle
            // that staged a release edge, before dispatch: a remove / clear landing between that commit and the
            // dispatch would otherwise read "not held", skip the synthesis, and have the staged release refused by the
            // tombstone, stranding the consumer held.
            // False for config-seeded or directly constructed raw callbacks, which are not self-balancing and keep the
            // m_active_states gate.
            bool release_is_idempotent = false;

            // The gate the callbacks above dispatch through, when the facade built them. Erasing this entry drops one
            // of the gate's two strong owners; the binding's BindingGuard holds the other and, through it, the
            // consumer callback. Retirement before a Logic DLL unmaps has to reach the gate itself, so the entry keeps
            // a direct handle rather than leaving it captured inside the wrappers. Null for config-seeded or directly
            // constructed raw callbacks, which have no gate and no guard.
            std::shared_ptr<BindingGate> gate;
        };

        /**
         * @class InputPoller
         * @brief RAII polling engine monitoring input state on a background thread.
         * @details Manages a dedicated poll thread that reads keyboard/mouse via GetAsyncKeyState, gamepad via XInput,
         *          and the mouse wheel via the window-procedure subclass. Supports press (edge-triggered) and hold
         *          (level-triggered) bindings with modifier combinations and optional foreground-focus gating. On
         *          shutdown, active holds receive a final on_state_change(false).
         *
         * @note Non-copyable, non-movable. Callbacks run on the poll thread.
         * @warning Inside a DLL, shutdown() must run before DLL_PROCESS_DETACH; joining the poll thread under the
         *          Windows loader lock would deadlock, so shutdown() detaches the poll thread and leaks its module
         *          reference (keeping its code mapped) when the loader lock is held.
         * @warning The interception layer (mouse-wheel capture and gamepad passthrough suppression) is backed by
         *          process-global state and a single set of hooks, so at most one poller may use those features at a
         *          time. The Input singleton is the intended single-instance owner; purely observational pollers
         *          install nothing.
         */
        class InputPoller
        {
        public:
            /**
             * @brief Constructs a poller with the given bindings and tuning. The poll thread does not start until
             *        start().
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

            /// Returns whether at least one binding uses @p name.
            [[nodiscard]] bool has_bindings_by_name(std::string_view name) const noexcept;

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
             * @return A valid token when the name is registered; an invalid token when unknown or on allocation
             *         failure.
             * @note Setup/control-plane: copies the name's index set and may allocate.
             */
            [[nodiscard]] input::BindingToken acquire_binding_token(std::string_view name) const noexcept;

            /// Queries a binding through a previously acquired token (the per-frame hot path). Fails closed when stale.
            [[nodiscard]] bool is_binding_active(const input::BindingToken &token) const noexcept;

            /// Reports whether a token still matches the live binding generation.
            [[nodiscard]] bool binding_token_current(const input::BindingToken &token) const noexcept;

#ifdef DMK_ENABLE_TEST_SEAMS
            /// Test-only: the interception-layer owner id this poller presents. Compiled out of shipping archives.
            [[nodiscard]] std::uint64_t intercept_owner_for_test() const noexcept { return m_intercept_owner; }

            /**
             * @brief Test-only: runs the acquisition republish the poll loop performs on the cycle it first owns the
             *        layer.
             * @details Lets a case observe the published table without starting a poll thread and without waiting for
             *          an install that a headless host may be unable to perform. It calls the same publication the poll
             *          loop calls, so the authorization it goes through is the real one. Compiled out of shipping
             *          archives.
             */
            void publish_consume_rules_for_test() noexcept;
#endif

            /// Sets whether the poller gates on foreground focus. Thread-safe; takes effect immediately.
            void set_require_focus(bool require_focus) noexcept;

            /**
             * @brief Sets the suppression flag on every binding sharing @p name and refreshes the interception gates.
             * @details A no-op if the name was never registered. Thread-safe; safe while running.
             */
            void set_consume(std::string_view name, bool consume) noexcept;

            /**
             * @brief Sets the suppression flag on every binding stamped with @p owner and refreshes the gates.
             * @details Identity-keyed counterpart to set_consume(name): matches on the register_combo() call id carried
             *          by InputBinding::consume_owner rather than the name, so it clears the consume flag of an
             *          empty-name binding (which is absent from the name index) and confines the clear to one
             *          registration's entries. A no-op when @p owner is 0 (the no-owner sentinel) or unmatched.
             *          Thread-safe; safe while running.
             */
            void set_consume_by_owner(std::uint64_t owner, bool consume) noexcept;

            /**
             * @brief Reports occupancy of the bounded same-frame gamepad-chord suppression table.
             * @details Reflects THIS poller's own last publish, not the live process-global table, which a later
             *          engine or a test can have republished since. @c rejected is non-zero only when the eligible
             *          rule set outgrew the detour's storage; those chords keep the reactive (poll-published) mask and
             *          lose only the leading-edge protection.
             */
            [[nodiscard]] input::ConsumeCapacity consume_capacity() const noexcept;

            /**
             * @brief Stops the poll thread.
             * @details Joins and delivers final Hold releases. Idempotent.
             * @note A poll-thread call only requests stop and makes self_retiring() true.
             * @note Loader-lock or failed-join teardown keeps the owner, module reference, and detours retained.
             */
            void shutdown() noexcept;

            /**
             * @brief Reports that shutdown() was reached on the poll thread and could not finish there.
             * @details True only after such a call. The owner must then hand its external reference to the lifecycle
             *          reaper instead of destroying the poller inline, because destroying it here would either
             *          self-join or free members the still running poll loop is reading. The reaper calls shutdown()
             *          again on its own thread, where the join, the detour uninstall, and the final
             *          on_state_change(false) rundown are safe, and releases its reference only once that returns.
             */
            [[nodiscard]] bool self_retiring() const noexcept
            {
                return m_self_retiring.load(std::memory_order_acquire);
            }

            /**
             * @brief Reports that shutdown could not prove the poll thread stopped and the owner must be retained.
             * @details Set on loader-lock detach and on a contained join failure. Destroying the poller after either
             *          path could free members a detached or still-joinable thread may still read.
             */
            [[nodiscard]] bool requires_abandonment() const noexcept
            {
                return m_requires_abandonment.load(std::memory_order_acquire);
            }

            /**
             * @brief Precommits the owner reference used when shutdown cannot drain safely.
             * @details Call once the worker is running and before the poller is reachable from another thread, so no
             *          teardown can find it unprotected and none has to allocate to retain it. The deliberate
             *          self-reference is cleared by shutdown() only after a completed join and rundown, or when there
             *          is no worker to run down at all. A poll-thread call returns with it still held, pending the
             *          off-thread re-entry that completes the rundown; the loader-lock, failed-join, and unaccepted
             *          retirement paths keep it permanently.
             * @param owner The shared owner of this poller.
             */
            void retain_owner_for_abandonment(std::shared_ptr<InputPoller> owner) noexcept
            {
                m_owner_keepalive = std::move(owner);
            }

            /**
             * @brief Replaces the trigger combos of all bindings sharing @p name.
             * @details Matching counts rewrite in place; differing counts rebuild the entry set carrying callbacks,
             *          mode, and name forward. An empty list leaves one inert sentinel so the name stays addressable.
             *          Held bindings receive on_state_change(false) before the swap. Safe while running.
             * @return true on swap (including unbind); false only if the name was never registered.
             */
            [[nodiscard]] bool update_combos(std::string_view name, const input::KeyComboList &combos) noexcept;

            /**
             * @brief Appends a binding to the running poller, carrying surviving entries' active state forward.
             * @return true when the binding was appended; false when growing the engine failed under host OOM (the
             *         poller is left exactly as it was). The caller surfaces the failure rather than silently
             *         committing a subset of a multi-combo registration.
             */
            [[nodiscard]] bool add_binding(InputBinding binding) noexcept;

            /**
             * @brief Appends a batch of bindings atomically, carrying surviving entries' active state forward.
             * @return true when every binding was appended; false when growing the engine failed under host OOM (the
             *         poller is left exactly as it was).
             */
            [[nodiscard]] bool add_bindings(std::vector<InputBinding> bindings) noexcept;

            /// Removes every binding sharing @p name (invoking hold-release callbacks). Returns the count removed.
            std::size_t remove_bindings_by_name(std::string_view name) noexcept
            {
                return remove_bindings_by_name(name, true);
            }

            /// Drops every binding without stopping the thread (invoking hold-release callbacks).
            void clear_bindings() noexcept { clear_bindings(true); }

            /**
             * @brief Variant of remove_bindings_by_name that can suppress the hold-release callbacks.
             * @param invoke_callbacks When false, the on_state_change(false) callbacks are dropped because the hosting
             *                         Logic DLL's pages may be unmapping, and the in-flight rundown is skipped: an
             *                         unload caller either must not block at all (loader lock) or owns its own bounded
             *                         wait (the typed drain).
             */
            std::size_t remove_bindings_by_name(std::string_view name, bool invoke_callbacks) noexcept;

            /// Variant of clear_bindings carrying the same invoke_callbacks contract as remove_bindings_by_name.
            void clear_bindings(bool invoke_callbacks) noexcept;

            /**
             * @brief Retires the gates of every binding sharing @p name ahead of removing them for a Logic DLL unload.
             * @param deadline Bound on the wait for an in-flight delivery to unwind, per gate.
             * @return False when a gate could not be quiesced before @p deadline, in which case its callback is still
             *         alive, and also when the handles could not be collected at all because the collection ran out of
             *         memory. Retirement did not happen on either path, so the caller must not report the callbacks
             *         gone.
             * @details Removal alone drops only the engine's owner of the gate, leaving the consumer callback alive
             *          inside a retained BindingGuard. This runs first so a still-held hold's balancing edge is
             *          delivered while the DLL is mapped and every gate-owned callback is destroyed here.
             * @warning Control-plane only, and callers must be off any delivery. Runs consumer code.
             */
            [[nodiscard]] bool retire_gates_by_name(std::string_view name,
                                                    std::chrono::steady_clock::time_point deadline) noexcept;

            /// retire_gates_by_name over every binding, for the retire-everything drain.
            [[nodiscard]] bool retire_all_gates(std::chrono::steady_clock::time_point deadline) noexcept;

        private:
            /// Shared tail of the two retire entry points: retires each collected gate off the binding lock.
            [[nodiscard]] bool retire_collected_gates(const std::vector<std::shared_ptr<BindingGate>> &gates,
                                                      std::chrono::steady_clock::time_point deadline) noexcept;

            void poll_loop(std::stop_token stop_token);
            void release_active_holds() noexcept;
            [[nodiscard]] bool is_process_foreground() const noexcept;
            /**
             * @enum CacheFailPolicy
             * @brief What a failed derived-cache rebuild leaves behind.
             */
            enum class CacheFailPolicy : std::uint8_t
            {
                /**
                 * @brief Clear every derived cache.
                 * @details For a caller that already reshaped m_bindings. The prior name index maps names to old
                 *          positions, so retaining it could address past the new binding array; empty is the only
                 *          index-safe answer.
                 */
                ClearIndexSafe,
                /**
                 * @brief Keep the previous lookup caches, but still disarm gamepad consume suppression.
                 * @details For a caller that changed only a flag on an existing binding. Cardinality, order, and names
                 *          are untouched, so the name and modifier caches still describe m_bindings exactly and
                 *          discarding them would disable name lookup, and widen firing by emptying the strict-match
                 *          modifier set, over a change that invalidated neither. Suppression is not retained: the flag
                 *          change may have been a retirement, and a retained rule list would outlive the binding that
                 *          owned it.
                 */
                Retain
            };

            void recompute_modifier_caches_locked(CacheFailPolicy policy = CacheFailPolicy::ClearIndexSafe) noexcept;
            void record_consume_capacity(std::size_t active, std::size_t rejected) noexcept;

            /**
             * @brief Offers @ref m_consume_rules to the interception layer and records the resulting occupancy.
             * @details Requires m_bindings_rw_mutex. A refusal means this poller does not hold the layer; the rules
             *          stay cached and @ref m_consume_rules_unpublished latches so the poll loop retries on
             *          acquisition.
             */
            void publish_consume_rules_locked() noexcept;

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
            // Advances on every binding-set reshape; an input::BindingToken captures this at acquire time and a query
            // whose token generation no longer matches fails closed. Guarded by m_bindings_rw_mutex.
            std::uint64_t m_binding_generation{0};
            std::chrono::milliseconds m_poll_interval;
            std::atomic<bool> m_require_focus;
            std::atomic<bool> m_running{false};
            // Set when shutdown() ran on the poll thread and deferred the rundown. See self_retiring().
            std::atomic<bool> m_self_retiring{false};
            // Set when shutdown() cannot prove that owner destruction is safe. See requires_abandonment().
            std::atomic<bool> m_requires_abandonment{false};
            // Precommitted retention for loader-lock, failed-join, or failed-reaper paths.
            std::shared_ptr<InputPoller> m_owner_keepalive;
            std::jthread m_poll_thread;
            // Counted reference on the module the poll thread's code lives in, taken before the thread is created
            // while the module is fully mapped. shutdown() releases it after a clean join, or leaks it on the
            // loader-lock detach path so the poll-loop code and the detours left installed against this module stay
            // mapped. void* keeps this header free of <windows.h>; it holds an HMODULE in the implementation. See
            // detail::acquire_module_ref.
            void *m_self_ref{nullptr};
            std::mutex m_cv_mutex;
            std::condition_variable_any m_cv;

            // Per-binding active state, indexed parallel to m_bindings. Atomic for cross-thread reads.
            std::unique_ptr<std::atomic<std::uint8_t>[]> m_active_states;

            int m_gamepad_index;
            int m_trigger_threshold;
            int m_stick_threshold;
            // Stable across poll-thread installation and off-thread teardown so only this poller can remove its hooks.
            const std::uint64_t m_intercept_owner;
            std::atomic<bool> m_has_gamepad_bindings{false};

            // Interception gates, recomputed alongside the modifier caches. Each lazily installs an active-input hook
            // from the poll loop, so a mod that never opts in pays no interception cost.
            std::atomic<bool> m_has_wheel_bindings{false};           // any MouseWheel trigger -> WndProc hook
            std::atomic<bool> m_has_consume_gamepad_bindings{false}; // any consume gamepad binding -> XInput hook

            // The consume rules this poller's current binding set calls for, kept whether or not it may publish them.
            // A rebuild runs wherever a binding changes -- including in the constructor, before this poller has claimed
            // the interception layer -- and publishing there would overwrite the rules of whichever poller actually
            // owns the layer. Guarded by m_bindings_rw_mutex.
            std::vector<GamepadConsumeRule> m_consume_rules;
            // Set when a rebuild could not publish because this poller did not hold the layer. The poll loop
            // republishes once on the cycle that observes ownership and clears it, so acquisition does not inherit
            // whatever the previous owner left behind.
            std::atomic<bool> m_consume_rules_unpublished{true};

            // Eligible rules OFFERED to the last publish, which is active + rejected. One atomic keeps the pair a
            // caller reads coherent without making the callback-safe capacity query contend for the binding lock.
            std::atomic<std::size_t> m_consume_rules_total{0};

            // One over-capacity warning per engine; see record_consume_capacity.
            std::atomic<bool> m_consume_bound_reported{false};
        };

#ifdef DMK_ENABLE_TEST_SEAMS
        // Test seams compiled out of shipping archives. They make the staging and admission windows deterministic.
        //
        // Publication rule, binding on every consumer: install a seam only while the engine is stopped, and clear it
        // only after the poll thread and any deferred reaper have finished. The poll thread reads these objects
        // without synchronization, so replacing one under a live loop destroys a callable mid-call; a host that
        // cleared before joining turned its own diagnostic into an access violation. shutdown() reached from a
        // binding callback does not close the window on return -- the rundown is handed to the reaper and completes
        // off-thread -- so the caller needs its own completion signal before clearing.
        // tests/lifecycle/input_seam_cleanup.hpp owns this order for the raw hosts.
        //
        // g_input_key_state_probe: when set, replaces GetAsyncKeyState as the keyboard/mouse down-state source, so a
        // test can raise a press/hold edge without synthesizing real OS input. Must not throw.
        //
        // g_input_post_stage_probe: runs after staging and before admission, receiving the staged-callback count.
        //
        // g_input_pre_dispatch_probe: runs after admission and before the callback begins.
        //
        // g_input_join_fail_seam: a throwing probe exercises shutdown()'s join-failure containment.
        extern std::function<bool(int)> g_input_key_state_probe;
        extern std::function<void(std::size_t)> g_input_post_stage_probe;
        extern std::function<void()> g_input_pre_dispatch_probe;
        extern void (*g_input_join_fail_seam)();
#endif
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_INPUT_POLLER_HPP
