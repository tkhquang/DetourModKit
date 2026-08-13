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
 *          Authorization: every operation that writes or drains the state the detours read takes an owner id and is
 *          refused unless it equals the live layer owner at the moment of the write. Holding no owner is not a licence
 *          to write; an idle layer must first be claimed by installing or through the raw test seam. Owner
 *          publication, owner revocation, and every data-plane write serialize on one lock, so a superseded owner that
 *          entered a publication before it lost the layer still observes the revocation and writes nothing. The lock
 *          order is s_intercept_mutex then the data-plane lock; the detours themselves take neither and keep reading
 *          plain atomics and the rule seqlock.
 *
 *          Windows-only internal header (mirrors platform.hpp); not installed.
 */

#include <windows.h>
#include <xinput.h>

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
     * @details The bound is the detour's storage, not a policy: a longer list publishes its first this-many rules and
     *          drops the remainder. Evaluation ORs each matching rule's trigger
     *          mask, so a dropped rule costs exactly its own chord the leading-edge protection and costs the retained
     *          rules nothing.
     */
    inline constexpr std::size_t MAX_GAMEPAD_CONSUME_RULES = 32;

    /**
     * @struct ConsumePublish
     * @brief Outcome of an attempted consume-rule publication.
     */
    struct ConsumePublish
    {
        /// False when the caller did not hold the layer, in which case nothing was written.
        bool authorized{false};
        /// Rules actually written, which is @c min(count, MAX_GAMEPAD_CONSUME_RULES) when authorized and 0 otherwise.
        std::size_t published{0};
    };

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
     * @brief Publishes the consume rule list read by the XInput detour, if @p owner still holds the layer.
     * @details Copies up to @ref MAX_GAMEPAD_CONSUME_RULES rules behind a seqlock so a detour on a game thread reads a
     *          consistent snapshot without locking. A @p count above the cap publishes the first @ref
     *          MAX_GAMEPAD_CONSUME_RULES; the caller derives the shortfall from the result and owns the diagnosis.
     *          Rule masking shares the reactive mask's time-to-live (rules exist only while consume gamepad bindings
     *          do, which is exactly when publish_gamepad_suppress refreshes the deadline), so a stalled poll thread
     *          stops rule masking too.
     * @param rules Pointer to @p count contiguous rules (may be nullptr if 0).
     * @param count Number of rules offered.
     * @param owner Nonzero owner id that must equal the live layer owner; any other value writes nothing.
     */
    [[nodiscard]] ConsumePublish publish_gamepad_consume_rules(const GamepadConsumeRule *rules, std::size_t count,
                                                               std::uint64_t owner) noexcept;

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
     * @brief Enables or disables detour-side consume-rule masking, if @p owner still holds the layer.
     * @details Gates whether the XInput detour evaluates the published rule list. The poll thread drives this every
     *          cycle so rule masking stops the instant the host window loses focus or the controller disconnects,
     *          matching the reactive mask (which the poll loop clears to 0 on focus loss) and the mouse-wheel consume
     *          flag. Without it the detour would keep masking the foreground game's gamepad input while the mod is in
     *          the background, because the published rule list and its time-to-live both stay alive across focus
     *          changes.
     * @param enabled True to evaluate rules, false to skip them.
     * @param owner Nonzero owner id that must equal the live layer owner; any other value changes nothing.
     * @return true when the gate was written.
     */
    [[nodiscard]] bool set_gamepad_rule_suppress_enabled(bool enabled, std::uint64_t owner) noexcept;

    /**
     * @brief Owner id for a standalone caller (tests, direct install/uninstall) that drives the layer without a poller.
     * @details Zero is reserved for the unowned state. Pollers use ids from next_intercept_owner().
     */
    inline constexpr std::uint64_t STANDALONE_INTERCEPT_OWNER = 1;

    /**
     * @brief Draws an interception-owner id distinct from the two reserved values.
     * @details Each poller retains one id across installation and teardown so a superseded poller cannot remove a newer
     *          poller's hooks.
     */
    [[nodiscard]] std::uint64_t next_intercept_owner() noexcept;

    /// Reports whether the interception layer is currently held by the nonzero @p owner.
    [[nodiscard]] bool intercept_owned_by(std::uint64_t owner) noexcept;

    // XInput interception (gamepad passthrough suppression)

    /**
     * @brief Installs the XInputGetState hook pair for the given controller index under @p owner.
     * @details Idempotent for the current owner. A creation failure or a primary arm failure before its route becomes
     *          reachable publishes neither ownership nor a controller-index change; ambiguous target bytes retain any
     *          potentially reachable trampoline.
     *
     *          The primary export and every distinct ordinal-100 export are one coverage transaction. Both hooks
     *          are created disabled before either prologue is patched, so a creation failure rolls the pair back and
     *          leaves both entries fully open. Complete coverage is published only after a final witness reads both
     *          prologues, so a member a competing writer restored during the other member's arm window degrades the
     *          pair instead of masking one entry point while the other bypasses. A required export that exists but is
     *          not patched is degraded coverage, not success: this returns false, suppression stays inactive, and both
     *          detours stay pass-through until the pair is whole. The layer is still claimed in that state, because a
     *          live route needs an owner entitled to read its trampoline and to retire it. An absent or aliased
     *          ordinal-100 export is complete coverage, since there is no second entry point to mask. A target that a
     *          proxy forwards into another module receives its own hook and pre-acquired module keepalive.
     *
     *          Calling this while coverage is already published is the layer's health maintenance: both members are
     *          re-witnessed, so an entry point lost after publication degrades the pair rather than being hidden by
     *          the published flag. Recovery re-arms whichever member is missing, primary or ordinal-100, through that
     *          member's existing hook object, never by layering a new hook over uncertain storage.
     *
     *          Recovery is deadline-gated. Each failed re-arm grows the delay toward a cap and never stops retrying;
     *          a change of target module, owner, or member reachability drops the accumulated delay so the next call
     *          attempts immediately.
     * @param user_index The XInput controller index whose state may be masked.
     * @param owner Nonzero interception-layer owner id.
     * @return true only when coverage is complete for this owner; false when not ready, owned elsewhere, or degraded.
     * @note Every resource a non-draining teardown would need is secured here, before any prologue is patched: a
     *       reference on this module, one on the primary target module, another on a distinct forwarded target module
     *       when needed, and the storage the hook objects would be retained in. A reference that cannot be taken fails
     *       the install rather than publishing a detour that teardown could only free out from under a live thread.
     *       uninstall() releases them on a drained teardown.
     */
    [[nodiscard]] bool install_xinput(int user_index, std::uint64_t owner = STANDALONE_INTERCEPT_OWNER) noexcept;

    /**
     * @brief Returns whether XInput suppression is armed, which requires complete pair coverage.
     * @details False while any required member is unpatched, whether the pair is live or retained, and false again
     *          once maintenance observes a member lost after publication. A caller that treats false as "retry the
     *          install" is what drives the deadline-gated recovery.
     */
    [[nodiscard]] bool xinput_installed() noexcept;

    /**
     * @brief Returns the saved original XInputGetState (trampoline), or nullptr.
     * @details The poll thread uses this path to observe unmasked state. Non-null while a primary chain is published,
     *          including the degraded state, so a poller never has to reach raw controller state by calling the export
     *          it may itself have patched. Null once the layer is logically disarmed, even when retained storage still
     *          needs the trampoline.
     */
    [[nodiscard]] XInputGetStateFn xinput_trampoline() noexcept;

    /**
     * @brief Publishes the set of button bits the XInput detour should suppress, if @p owner still holds the layer.
     * @details Refreshes a short time-to-live alongside the mask so that if the poll thread stops refreshing it
     *          (crash/hang) the detour stops masking and the game regains its input rather than latching forever.
     * @param suppress_bits Button bits to clear; 0 disables masking.
     * @param owner Nonzero owner id that must equal the live layer owner; any other value writes nothing.
     * @return true when the mask was written.
     */
    [[nodiscard]] bool publish_gamepad_suppress(uint16_t suppress_bits, std::uint64_t owner) noexcept;

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
     * @brief Installs the window-procedure subclass on the game's main window under @p owner.
     * @details Idempotent for the owner that holds the layer. Returns false if no suitable window exists or another
     *          owner holds the layer; a failed attempt does not claim an otherwise idle layer.
     * @param owner Nonzero interception-layer owner id shared with the XInput hook.
     * @return true if the subclass is installed (or was already, for this owner), false if not yet ready or owned
     *         elsewhere.
     */
    [[nodiscard]] bool install_wndproc(std::uint64_t owner = STANDALONE_INTERCEPT_OWNER) noexcept;

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
     * @brief Atomically takes and clears the accumulated wheel notch counts, if @p owner still holds the layer.
     * @details Consuming notches is a destructive read of state the owner's poll loop is entitled to, so a non-owner
     *          reads all zeros and leaves the counters intact rather than swallowing the owner's backlog.
     * @param owner Nonzero owner id that must equal the live layer owner.
     * @return Notch counts since the last call, indexed 0=Up, 1=Down, 2=Left, 3=Right; all zero for a non-owner.
     */
    [[nodiscard]] std::array<int, 4> take_wheel_counts(std::uint64_t owner) noexcept;

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Claims the idle layer for STANDALONE_INTERCEPT_OWNER without installing a hook.
    [[nodiscard]] bool acquire_standalone_lease_for_test() noexcept;

    /// Releases the test-only standalone lease and clears the data it authorized.
    void release_standalone_lease_for_test() noexcept;

    /**
     * @brief Test-only: stages a wheel-notch backlog as if the WndProc detour had latched @p notches.
     * @details The detour increments the counters only from a real WM_MOUSEWHEEL / WM_MOUSEHWHEEL, which the unit suite
     *          cannot deliver without a live window. This seam lets a white-box test stand up the exact stale-backlog
     *          state that the poll loop's drain and recompute's no-wheel -> wheel discard exist to handle, so those
     *          paths are exercised deterministically. Each slot saturates at MAX_WHEEL_NOTCHES, matching the detour's
     *          write site. Compiled out of shipping archives.
     */
    void seed_wheel_notches_for_test(const std::array<int, 4> &notches) noexcept;
#endif

    /**
     * @brief Publishes the set of wheel directions the WndProc detour should swallow this cycle.
     * @details Uses a per-direction mask so a chord such as "Ctrl+WheelUp" eats neither a bare WheelDown nor an
     *          unmodified WheelUp. The poll loop evaluates each consume wheel binding's modifiers every cycle and
     *          unions the owned direction bits (see WheelDirection). Like the gamepad reactive suppression mask, the
     *          detour only swallows a message whose own direction bit is set. A short time-to-live is refreshed
     *          alongside a non-zero mask so a stalled poll thread stops swallowing and the game regains its wheel.
     * @param direction_mask OR of WheelDirection bits to swallow; 0 forwards every wheel message.
     * @param owner Nonzero owner id that must equal the live layer owner; any other value writes nothing.
     * @return true when the mask was written.
     */
    [[nodiscard]] bool publish_wheel_consume(uint8_t direction_mask, std::uint64_t owner) noexcept;

    /**
     * @brief Tears down both interceptors and stops all masking, if @p owner still holds the layer.
     * @details Retires the owner before touching backend state. XInput removal drains game detours and requires
     *          Original byte witnesses for both hooks; timeout, foreign ownership, an unreadable window, or an
     *          unconfirmed toggle retains the pair and keepalives without allocation. The two raw members are one
     *          transaction: a primary restore that refuses after the ordinal-100 restore committed re-arms that member
     *          before retaining, so retention never drops an entry point the pair covered on entry. WndProc removal
     *          preserves the procedure actually displaced by its exchange. Idempotent.
     * @param owner Nonzero interception-layer owner id. Any non-owner returns without changing the installation.
     * @warning Never call under the loader lock, and never before the poll thread has been joined: that thread reads
     *          the XInput trampoline directly, and raw hook teardown registers VEH state and rewrites executable
     *          pages.
     */
    void uninstall(std::uint64_t owner = STANDALONE_INTERCEPT_OWNER) noexcept;

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Seam signature; see set_xinput_detour_body_seam.
    using XInputDetourBodySeam = void (*)() noexcept;

    /// Stage exposed to the deterministic WndProc teardown race seam.
    enum class WndProcUninstallStage : uint8_t
    {
        BeforeExchange,
        BeforeCompensation
    };

    /// Seam signature; see set_wndproc_uninstall_exchange_seam.
    using WndProcUninstallExchangeSeam = void (*)(HWND, WndProcUninstallStage) noexcept;

    /// Seam signature; see set_xinput_arm_seam.
    using XInputArmSeam = void (*)() noexcept;

    /// Seam signature; see set_xinput_clean_release_seam.
    using XInputCleanReleaseSeam = void (*)() noexcept;

    /// Seam signature; see set_xinput_create_seam.
    using XInputCreateSeam = void (*)() noexcept;

    /**
     * @brief Installs a probe that runs inside an XInput detour body while its in-flight guard is held.
     * @details The only way to park a caller inside a detour deterministically, which is what makes uninstall()'s
     *          bounded drain time out on demand. Null clears it. Compiled out of shipping archives.
     */
    void set_xinput_detour_body_seam(XInputDetourBodySeam seam) noexcept;

    /// Holds or releases a raw-XInput caller after stable route admission but before the C++ detour body.
    void set_xinput_route_entry_hold_for_test(bool hold) noexcept;

    /// Reports whether a raw-XInput caller reached the stable pre-body route park.
    [[nodiscard]] bool xinput_route_entry_reached_for_test() noexcept;

    /**
     * @brief Runs a probe after both raw targets are witnessed restored and immediately before hook-object release.
     * @details Lets a lifecycle proof poison allocation only across the clean noexcept release boundary. Null clears
     *          the probe.
     */
    void set_xinput_clean_release_seam(XInputCleanReleaseSeam seam) noexcept;

    /**
     * @brief Runs a probe after a raw hook's isolated allocator exists and before backend construction begins.
     * @details Lets the lifecycle proof poison only allocations made inside InlineHook::create. Null clears it.
     */
    void set_xinput_create_seam(XInputCreateSeam seam) noexcept;

    /**
     * @brief Arms one raw-XInput backend toggle exception at @p target.
     * @param target Exact backend target, or nullptr to disarm the seam.
     * @param after_mutation true to throw after the byte mutation; false to throw before it.
     */
    void set_xinput_backend_toggle_exception_for_test(void *target, bool after_mutation) noexcept;

    /// Returns how many raw-XInput backend exceptions the current test arm reached and contained.
    [[nodiscard]] std::size_t xinput_backend_toggle_exception_catches_for_test() noexcept;

    /**
     * @brief Installs a probe between a raw-XInput backend toggle and the witness read that judges it.
     * @details The only deterministic way to place a competing prologue writer in that exact window. Null clears it.
     */
    void set_xinput_arm_seam(XInputArmSeam seam) noexcept;

    /**
     * @brief Installs a probe at each WndProc uninstall reconciliation boundary.
     * @details Null clears it. Compiled out of shipping archives.
     */
    void set_wndproc_uninstall_exchange_seam(WndProcUninstallExchangeSeam seam) noexcept;

    /// Reports whether the layer is claimed with at least one required entry point no longer patched.
    [[nodiscard]] bool xinput_pair_degraded_for_test() noexcept;

    /**
     * @struct XInputPairCoverage
     * @brief Which members of the pair currently cover their entry point.
     * @details Either member can be the missing one, so a proof has to name the direction it drove rather than infer
     *          it from the degraded flag alone. An absent or aliased ordinal-100 export reports covered: it has no
     *          separate entry point to mask.
     */
    struct XInputPairCoverage
    {
        bool primary{false};
        bool ex{false};
    };

    /// Re-witnesses both pair members' target bytes without changing published state.
    [[nodiscard]] XInputPairCoverage xinput_pair_coverage_for_test() noexcept;

    /**
     * @brief Counts backend re-arm transactions the recovery gate has let through.
     * @details The observable difference between "the poll loop retried the backend" and "the poll loop was refused by
     *          the deadline", which is what makes the capped-delay contract measurable without timing the test.
     */
    [[nodiscard]] std::size_t xinput_recovery_attempts_for_test() noexcept;

    /**
     * @brief Expires the current recovery delay without resetting the accumulated backoff.
     * @details Lets a proof drive many recovery attempts deterministically instead of sleeping out a growing delay.
     * @return The accumulated delay that was expired, in milliseconds.
     */
    [[nodiscard]] std::uint64_t expire_xinput_recovery_delay_for_test() noexcept;

    /**
     * @brief Returns whether permanent storage currently owns a primary raw hook.
     * @details Distinguishes a permanent-retention latch on the canonical hook and keepalives from a witnessed clean
     *          logical release. The backend's stable published gateway remains process-lifetime storage in either case.
     */
    [[nodiscard]] bool xinput_permanent_primary_retained() noexcept;

    /**
     * @brief Counts XInput keepalives: 0 with no detour, 2 for one target module, or 3 for a forwarded Ex target.
     * @details A timeout or unproved restore leaves the same set in permanent storage. A clean teardown releases it.
     *          This seam excludes independent host pins on the XInput DLL.
     */
    [[nodiscard]] int xinput_module_refs_held() noexcept;

    /// Arms the B-100 process-exit oracle with a patched XInput target byte.
    void arm_xinput_process_exit_oracle_for_test(const std::uint8_t *target) noexcept;

    /**
     * @brief Overrides the module install_xinput() resolves XInputGetState from, bypassing the DLL-name search.
     * @details Lets a test select a synthetic proxy whose ordinal 100 is local or forwarded. Null clears the override.
     *          Compiled out of shipping archives.
     */
    void set_xinput_module_override_for_test(HMODULE module) noexcept;

    /**
     * @brief Returns the saved original XInputGetStateEx (ordinal-100) trampoline, or nullptr when no chain exists.
     * @details A committed arm keeps this non-null for callers admitted before its target became unreachable, even
     *          while the pair is degraded. Absent and aliased exports have no distinct chain.
     */
    [[nodiscard]] XInputGetStateFn xinput_ex_trampoline() noexcept;

    /// Applies the raw-XInput suppression gate to a synthetic state.
    void apply_xinput_suppress_for_test(XINPUT_STATE *state, DWORD user_index) noexcept;

    /// Returns the controller index most recently published by a successful install.
    [[nodiscard]] int xinput_bound_user_index() noexcept;

    /// Seam signature; see set_data_plane_entry_seam.
    using DataPlaneEntrySeam = void (*)() noexcept;

    /// Seam signature; see set_wheel_capture_entry_seam.
    using WheelCaptureEntrySeam = void (*)() noexcept;

    /**
     * @brief Installs a probe that runs on entry to a data-plane operation, before it takes the data-plane lock.
     * @details The only way to park a caller in the window between deciding to publish and being authorized to,
     *          which is what makes a revocation land against an already-entered publication on demand. Null clears it.
     *          Compiled out of shipping archives.
     */
    void set_data_plane_entry_seam(DataPlaneEntrySeam seam) noexcept;

    /**
     * @brief Installs a probe that runs after wheel-capture state is sampled and before the epoch-tagged increment.
     * @details Lets a test prove that owner revocation invalidates an already-entered window-procedure capture without
     *          waiting for it and without polluting the successor's backlog. Null clears it. Compiled out of shipping
     *          archives.
     */
    void set_wheel_capture_entry_seam(WheelCaptureEntrySeam seam) noexcept;

    /**
     * @brief Runs the complete window-procedure wheel-message path for one signed delta (T-WHEEL).
     * @details Exactly the detour's handling: remainder accumulation under the live capture state, whole-notch
     *          publication into the drain counters, and the per-message swallow verdict against the published
     *          consume mask.
     * @return true when the real window procedure would swallow the message.
     */
    [[nodiscard]] bool process_wheel_message_for_test(bool horizontal, int delta) noexcept;

    /**
     * @brief Returns the consume-rule seqlock sequence.
     * @details Odd means a write bracket is open. A refused publication must leave it even and unchanged, which is the
     *          observable difference between refusing before the bracket and rolling one back.
     */
    [[nodiscard]] std::uint32_t consume_rules_sequence() noexcept;

    /// Returns the reactive gamepad mask currently published to the detour.
    [[nodiscard]] std::uint16_t gamepad_suppress_mask_for_test() noexcept;

    /// Returns whether detour-side consume-rule evaluation is enabled.
    [[nodiscard]] bool gamepad_rule_suppress_enabled_for_test() noexcept;

    /// Returns the wheel-direction consume mask currently published to the window procedure.
    [[nodiscard]] std::uint8_t wheel_consume_mask_for_test() noexcept;

    /**
     * @brief Claims the idle layer for an arbitrary @p owner without installing a hook.
     * @details Owner-scoped paths are otherwise only reachable by installing, which needs a live XInput module or a
     *          top-level window that a unit-test process may not have. This grants the lease alone so a white-box case
     *          can drive an owning poller's drain and publication paths on any host. Fails while another owner holds
     *          the layer. Release through uninstall(owner). Compiled out of shipping archives.
     */
    [[nodiscard]] bool adopt_owner_for_test(std::uint64_t owner) noexcept;
#endif

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_INPUT_INTERCEPT_HPP
