#ifndef DETOURMODKIT_INTERNAL_INPUT_INTERCEPT_HPP
#define DETOURMODKIT_INTERNAL_INPUT_INTERCEPT_HPP

/**
 * @file input_intercept.hpp
 * @brief Internal active-input layer driven by InputPoller.
 * @details Two opt-in capabilities that the observational poll loop cannot provide on its own:
 *            1. Gamepad passthrough suppression -- an inline hook on
 *               XInputGetState masks owned button bits out of the state the game reads, so a binding the mod claims is
 *               not also acted on by the game (e.g. an "LB + D-pad" zoom that must not open the map).
 *            2. Mouse-wheel capture -- the wheel is an event with no virtual-key
 *               code, so it is invisible to GetAsyncKeyState. A window-procedure subclass intercepts WM_MOUSEWHEEL /
 *               WM_MOUSEHWHEEL and latches each notch for the poll loop to consume.
 *
 *          Ownership: this module owns its safetyhook InlineHook objects directly rather than through a separately
 *          owned DMK Hook handle. The poll thread reads the XInput trampoline pointer every cycle, and the hook
 *          lifetime must be coupled to the poll thread's lifetime; a handle owned elsewhere could be dropped (freeing
 *          the trampoline) underneath a live poll thread.
 *
 *          State the detours read lives in file-scope statics (not InputPoller members) so that on the loader-lock
 *          teardown path -- where InputPoller is leaked and its poll thread detached -- the still-installed detours
 *          never dereference freed object state. The detours run on the game's threads (XInput caller threads and the
 *          window message thread); all shared state is atomic and every detour body is allocation-free and
 *          non-throwing.
 *
 *          Windows-only internal header (mirrors platform.hpp); not installed.
 */

#include <windows.h>
#include <Xinput.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace DetourModKit::detail
{
    /// Function-pointer type for XInputGetState and the ordinal-100 XInputGetStateEx.
    using XInputGetStateFn = DWORD(WINAPI *)(DWORD, XINPUT_STATE *);

    /**
     * @struct WheelPulseState
     * @brief Poll-thread-private state that turns queued wheel notches into single-cycle pulses.
     * @details The wheel has no released state, so the poll loop synthesizes one:
     *          a notch reads as "pressed" for exactly one cycle, then is forced low for one cycle so the edge detector
     *          re-arms. Without the forced gap a continuous scroll would read as one long press and fire only once.
     *          Indices are 0=Up, 1=Down, 2=Left, 3=Right.
     */
    struct WheelPulseState
    {
        /// Unconsumed notches per direction.
        std::array<int, 4> pending{};
        /// Whether the previous cycle emitted a pulse.
        std::array<bool, 4> pulsing{};
    };

    /**
     * @brief Maximum unconsumed notches retained per direction.
     * @details The pulse stepper drains at most one notch per direction every two poll cycles (one cycle pulses, the
     *          next forces the re-arm gap), so a scroll faster than that drain accumulates a backlog. Capping it bounds
     *          how long phantom notches can replay after the user stops scrolling; a real burst rarely exceeds this,
     *          and dropping the tail of an extreme burst is preferable to an unbounded replay queue.
     */
    inline constexpr int MAX_WHEEL_PENDING = 16;

    /**
     * @brief Advances the wheel pulse state machine by one poll cycle.
     * @param state Per-direction pulse state, carried across cycles.
     * @return Bitmask of directions pressed this cycle (bit 0 = Up .. bit 3 = Right).
     */
    [[nodiscard]] uint8_t step_wheel_pulse(WheelPulseState &state) noexcept;

    /**
     * @brief Adds freshly drained wheel notches to the pending backlog, capped.
     * @details Each retained notch still maps to one Press edge via step_wheel_pulse;
     *          this only bounds the carried-over backlog per direction to @ref MAX_WHEEL_PENDING so a sustained fast
     *          scroll cannot queue notches faster than they drain. Negative inputs are ignored so a corrupt count
     *          cannot drive pending negative and underflow the drain.
     * @param state Pulse state whose pending counts are updated in place.
     * @param taken Notch counts just drained from the detour, indexed 0=Up..3=Right.
     */
    void add_wheel_notches(WheelPulseState &state, const std::array<int, 4> &taken) noexcept;

    /**
     * @struct GamepadSuppressState
     * @brief Poll-thread-private consume-until-release latch for suppressed gamepad buttons.
     */
    struct GamepadSuppressState
    {
        /// Currently suppressed XInput button bits.
        uint16_t armed{0};
        /// Per-bit release deadline; a held bit uses the sentinel.
        std::array<uint64_t, 16> deadline_ms{};
    };

    /**
     * @brief Advances the gamepad suppression latch by one poll cycle.
     * @details A bit stays suppressed from the moment an active consume chord claims it (@p owned_now) until the
     *          physical button is released (@p true_buttons no longer has it) plus @p grace_ms. This closes the
     *          modifier-released-before-trigger window: releasing the modifier a frame before the trigger cannot leak a
     *          bare trigger to the game, because suppression is latched to the trigger button's own lifetime, not the
     *          chord's.
     * @param state Latch state carried across cycles.
     * @param owned_now Digital button bits the active consume chords claim this cycle (each bit's physical button is
     *                  already known pressed).
     * @param true_buttons The unmasked XINPUT_GAMEPAD.wButtons read this cycle.
     * @param now_ms Monotonic millisecond timestamp for this cycle.
     * @param grace_ms Release grace window in milliseconds.
     * @return Bitmask of button bits to clear from the game's state this cycle.
     */
    [[nodiscard]] uint16_t step_gamepad_suppress(GamepadSuppressState &state, uint16_t owned_now, uint16_t true_buttons,
                                                 uint64_t now_ms, uint64_t grace_ms) noexcept;

    /**
     * @struct GamepadConsumeRule
     * @brief A consume chord reduced to the XInput button bits the detour can evaluate without the poll thread.
     * @details The reactive (poll-published) mask trails the physical state by up to one poll cycle, which leaves a
     *          leading-edge window: a modifier and trigger pressed inside one poll interval can be read by the game
     *          before the mask catches up. A rule lets the detour mask the trigger against the exact snapshot the game
     *          is about to read, closing that window. Built only from chords whose modifiers and masked triggers are
     *          all digital gamepad buttons (the detour sees only
     *          XINPUT_GAMEPAD.wButtons), so the decision is fully reproducible there.
     */
    struct GamepadConsumeRule
    {
        /// Digital button bits that must all be held.
        uint16_t modifier_mask{0};
        /// Known-modifier bits outside this chord; any held rejects it (strict match).
        uint16_t forbidden_mask{0};
        /// Digital button bits to clear when the chord matches.
        uint16_t trigger_mask{0};
    };

    /**
     * @brief Maximum number of consume rules the detour evaluates.
     * @details A binding set that would exceed this publishes no rules at all (the reactive mask still covers the
     *          held-modifier case), so the detour never silently evaluates a subset.
     */
    inline constexpr std::size_t MAX_GAMEPAD_CONSUME_RULES = 32;

    /**
     * @brief Evaluates consume rules against a raw button snapshot.
     * @details Pure helper shared by the XInput detour and its tests. A rule contributes its @ref
     *          GamepadConsumeRule::trigger_mask when every @ref GamepadConsumeRule::modifier_mask bit is present in @p
     *          true_buttons and no @ref GamepadConsumeRule::forbidden_mask bit is. Masking a trigger bit that is not
     *          currently down is a no-op against the game's state, so a rule may match before its trigger is pressed
     *          without observable effect.
     * @param true_buttons The unmasked XINPUT_GAMEPAD.wButtons the game will read.
     * @param rules Pointer to @p count contiguous rules (may be nullptr if 0).
     * @param count Number of rules.
     * @return Button bits to clear from the game's state.
     */
    [[nodiscard]] uint16_t evaluate_consume_rules(uint16_t true_buttons, const GamepadConsumeRule *rules,
                                                  std::size_t count) noexcept;

    /**
     * @brief Publishes the consume rule list read by the XInput detour.
     * @details Single-writer: the binding-mutation thread, serialized by
     *          InputPoller::m_bindings_rw_mutex (not the poll thread). Copies up to @ref MAX_GAMEPAD_CONSUME_RULES
     *          rules behind a seqlock so a detour on a game thread reads a consistent snapshot without locking; a @p
     *          count above the cap publishes an empty list rather than a truncated one. Rule masking shares the
     *          reactive mask's time-to-live (rules exist only while consume gamepad bindings do, which is exactly when
     *          publish_gamepad_suppress refreshes the deadline), so a stalled poll thread stops rule masking too.
     * @param rules Pointer to @p count contiguous rules (may be nullptr if 0).
     * @param count Number of rules to publish.
     */
    void publish_gamepad_consume_rules(const GamepadConsumeRule *rules, std::size_t count) noexcept;

    /**
     * @brief Reads the published consume rule list and evaluates it against a raw button snapshot.
     * @details The XInput detour's rule-read side, exported for testing. Reads the seqlock-guarded rule list in a
     *          single attempt (a torn or mid-update snapshot yields 0) and returns evaluate_consume_rules over it. This
     *          is independent of the focus gate (see set_gamepad_rule_suppress_enabled), which the detour applies
     *          separately.
     * @param true_buttons The unmasked XINPUT_GAMEPAD.wButtons the game will read.
     * @return Button bits the currently published rules would clear.
     */
    [[nodiscard]] uint16_t evaluate_published_consume_rules(uint16_t true_buttons) noexcept;

    /**
     * @brief Enables or disables detour-side consume-rule masking.
     * @details Gates whether the XInput detour evaluates the published rule list. The poll thread drives this every
     *          cycle so rule masking stops the instant the host window loses focus or the controller disconnects,
     *          matching the reactive mask (which the poll loop clears to 0 on focus loss) and the mouse-wheel consume
     *          flag. Without it the detour would keep masking the foreground game's gamepad input while the mod is in
     *          the background, because the published rule list and its time-to-live both stay alive across focus
     *          changes.
     * @param enabled True to evaluate rules, false to skip them.
     */
    void set_gamepad_rule_suppress_enabled(bool enabled) noexcept;

    // XInput interception (gamepad passthrough suppression)

    /**
     * @brief Installs the XInputGetState hook for the given controller index.
     * @details Idempotent. Resolves the first loaded xinput DLL variant and hooks its XInputGetState (and ordinal-100
     *          XInputGetStateEx when present). Returns false without side effects if no xinput module is loaded yet, so
     *          the caller can retry on a later poll cycle.
     * @param user_index The XInput controller index whose state may be masked.
     * @return true if the hook is installed (or was already), false if not yet ready.
     */
    [[nodiscard]] bool install_xinput(int user_index) noexcept;

    /**
     * @brief Returns whether XInput interception is logically armed for poller use.
     * @details A timeout during uninstall can leave a permanent forwarding detour physically installed so an in-flight
     *          trampoline is never freed. After that emergency path this returns false until a later install_xinput()
     *          re-arms interception; the detour itself still forwards game calls to the original function.
     */
    [[nodiscard]] bool xinput_installed() noexcept;

    /**
     * @brief Returns the saved original XInputGetState (trampoline), or nullptr.
     * @details The poll thread must read the controller through this trampoline so it observes the true, unmasked state
     *          rather than its own mask. Returns nullptr while logical interception is disarmed, even if an emergency
     *          permanent detour is still physically forwarding game calls after a timeout.
     */
    [[nodiscard]] XInputGetStateFn xinput_trampoline() noexcept;

    /**
     * @brief Publishes the set of button bits the XInput detour should suppress.
     * @details Refreshes a short time-to-live alongside the mask so that if the poll thread stops refreshing it
     *          (crash/hang) the detour stops masking and the game regains its input rather than latching forever.
     * @param suppress_bits Button bits to clear; 0 disables masking.
     */
    void publish_gamepad_suppress(uint16_t suppress_bits) noexcept;

    // Mouse-wheel capture (window-procedure subclass)

    /**
     * @brief Wheel direction bit positions in the per-direction consume mask.
     * @details A single wheel message carries exactly one direction. The bit order matches WheelPulseState / the
     *          s_wheel_count slots (0=Up, 1=Down, 2=Left, 3=Right) so the poll loop, the pulse machine, and the detour
     *          agree on indexing.
     */
    enum class WheelDirection : uint8_t
    {
        Up = 1u << 0,
        Down = 1u << 1,
        Left = 1u << 2,
        Right = 1u << 3,
    };

    /// Returns the mask bit for a wheel direction.
    [[nodiscard]] constexpr uint8_t wheel_direction_bit(WheelDirection direction) noexcept
    {
        return static_cast<uint8_t>(direction);
    }

    /**
     * @brief Hard ceiling on the raw per-direction wheel-notch counter the WndProc detour accumulates.
     * @details The detour increments a counter per wheel notch and the poll loop drains it with take_wheel_counts, but
     *          only while a wheel binding exists. Once the last wheel binding is removed the poll loop stops draining
     *          (its drain is gated on live wheel bindings) yet the subclass stays installed until shutdown, so the
     *          counter would otherwise accrete every idle notch until it overflows a signed int (undefined behavior)
     *          and violates the bounded-backlog rule. Saturating the raw counter at the write site bounds it
     *          regardless of poll-thread liveness (a stalled thread never drains either). The ceiling is far above any
     *          real burst a single poll interval can accumulate -- the pulse backlog itself caps at MAX_WHEEL_PENDING
     *          -- so a legitimate fast scroll is never truncated; only the pathological idle-accretion case saturates.
     */
    inline constexpr int MAX_WHEEL_NOTCHES = 1024;

    /**
     * @brief Installs the window-procedure subclass on the game's main window.
     * @details Idempotent. Returns false without side effects if no suitable top-level window owned by this process is
     *          found yet, so the caller can retry on a later poll cycle.
     * @return true if the subclass is installed (or was already), false if not yet ready.
     */
    [[nodiscard]] bool install_wndproc() noexcept;

    /// Returns whether the window-procedure subclass is currently installed.
    [[nodiscard]] bool wndproc_installed() noexcept;

    /**
     * @brief Returns the saved predecessor window procedure the detour forwards to, as a raw value (0 if none).
     * @details The detour reads this at the top of every frame and forwards the message to it. uninstall() must leave
     *          it pointing at the real procedure after restoring the chain, so a frame already in flight when the
     *          restore lands still forwards to the game's procedure rather than routing to DefWindowProcW. Exposed for
     *          that teardown-correctness assertion (and diagnostics).
     */
    [[nodiscard]] LONG_PTR wndproc_saved_procedure() noexcept;

    /**
     * @brief Atomically takes and clears the accumulated wheel notch counts.
     * @return Notch counts since the last call, indexed 0=Up, 1=Down, 2=Left, 3=Right.
     */
    [[nodiscard]] std::array<int, 4> take_wheel_counts() noexcept;

    /**
     * @brief Test-only: stages a wheel-notch backlog as if the WndProc detour had latched @p notches.
     * @details The detour increments the counters only from a real WM_MOUSEWHEEL / WM_MOUSEHWHEEL, which the unit suite
     *          cannot deliver without a live window. This seam lets a white-box test stand up the exact stale-backlog
     *          state that the poll loop's drain and recompute's no-wheel -> wheel discard exist to handle, so those
     *          paths are exercised deterministically. Each slot saturates at MAX_WHEEL_NOTCHES, matching the detour's
     *          write site. Not part of the shipping surface (this header is never installed).
     */
    void seed_wheel_notches_for_test(const std::array<int, 4> &notches) noexcept;

    /**
     * @brief Publishes the set of wheel directions the WndProc detour should swallow this cycle.
     * @details Uses a per-direction mask so a chord such as "Ctrl+WheelUp" eats neither a bare WheelDown nor an
     *          unmodified WheelUp. The poll loop evaluates each consume wheel binding's modifiers every cycle and
     *          unions the owned direction bits (see WheelDirection). Like the gamepad reactive suppression mask, the
     *          detour only swallows a message whose own direction bit is set. A short time-to-live is refreshed
     *          alongside a non-zero mask so a stalled poll thread stops swallowing and the game regains its wheel.
     * @param direction_mask OR of WheelDirection bits to swallow; 0 forwards every wheel message.
     */
    void publish_wheel_consume(uint8_t direction_mask) noexcept;

    /**
     * @brief Tears down both interceptors and stops all masking.
     * @details Must be called off the Windows loader lock and only after the poll thread has stopped. Destroying the
     *          safetyhook objects rewrites the patched prologue pages (VirtualProtect to writable, restore the original
     *          bytes) under a transiently registered vectored exception handler that relocates the instruction pointer
     *          of any thread caught executing inside the patched range -- it does not suspend threads. Registering
     *          process-global VEH machinery and rewriting live code pages this way must not run under the loader lock.
     *          The poll thread has to be joined first because it reads the XInput trampoline directly; game threads may
     *          still enter the detours until the hooks are removed, so uninstall retires the published trampoline
     *          pointers and drains in-flight detour bodies before destroying the hook objects. If that bounded drain
     *          times out, the hook objects are leaked instead, the detours keep forwarding through their trampolines,
     *          and interception is logically disarmed until a later install_xinput() re-arms it. On the loader-lock
     *          teardown path this is intentionally skipped (the detours stay installed against the module, kept mapped
     *          by the leaked poll-thread reference).
     *          Idempotent.
     */
    void uninstall() noexcept;

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_INPUT_INTERCEPT_HPP
