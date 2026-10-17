#ifndef DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_PROTOCOL_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_PROTOCOL_HPP

#include "DetourModKit/abi/staged_reload.h"
#include "DetourModKit/abi/wheel_host.h"

#include <cstddef>
#include <cstdint>

#include <windows.h>

/**
 * @file staged_generation_protocol.hpp
 * @brief Host-to-generation ABI for the staged-generation reload proofs.
 * @details The host and generation include this header. Static assertions reject export signature drift.
 */

namespace staged_gen
{
    /// Names the source image that the host copies before each LoadLibrary call.
    inline constexpr const char *SOURCE_MODULE_NAME = "staged_generation_dll.dll";

    /// Names the fixture module that owns the public inline-hook target.
    inline constexpr const char *HOOK_TARGET_MODULE_NAME = "hook_target_lib.dll";

    /// Names the export that a generation hooks when InitOptions::target_symbol is null.
    inline constexpr const char *HOOK_TARGET_SYMBOL = "compute_damage";

    /// Names the synthetic XInput provider that all generations share.
    inline constexpr const char *XINPUT_PROXY_MODULE_NAME = "dmk_xinput_proxy_local.dll";

    /**
     * @brief Marker that precedes the rewritable tag bytes inside the image.
     * @details The host locates this marker in each staged copy and rewrites the next @ref TAG_LENGTH bytes. The
     *          loaded generation reports those bytes, which rejects a stale pinned image.
     */
    inline constexpr char TAG_MARKER[] = "DMKSTAGEDGENTAG:";

    /// Defines the number of tag bytes after @ref TAG_MARKER that the host rewrites per staged copy.
    inline constexpr std::size_t TAG_LENGTH = 16;

    /**
     * @enum FailStage
     * @brief Forced Init failure points for the partial-init proof.
     * @details AfterHook fails after one call reaches the armed detour. Init invokes its rollback path before
     *          return.
     */
    enum class FailStage : int
    {
        None = 0,
        AfterHook = 1,
    };

    /**
     * @enum HookKind
     * @brief The hook that StagedInit installs on @ref HOOK_TARGET_SYMBOL.
     * @details Each kind adds InitOptions::detour_bonus to every call result that crosses it.
     */
    enum class HookKind : int
    {
        /// inline_at with a raw detour that calls the trampoline.
        Raw = 0,
        /// mid_at with a callback that adds the bonus to the modifier argument register.
        Mid = 1,
        /// The counted inline_at with a noexcept detour that calls the trampoline.
        Counted = 2,
    };

    /**
     * @enum TeardownMode
     * @brief The hook teardown sequence that StagedShutdown runs.
     * @details Every mode returns a DetourModKit/abi/staged_reload.h value. After the teardown, staged_reload::verdict
     *          decides it.
     */
    enum class TeardownMode : int
    {
        /// Destroys every held hook, newest first.
        Destroy = 0,
        /**
         * @brief Disables every hook newest first, then destroys every hook.
         * @details A failed disable returns 0 before any destroy and keeps the Session, as a consumer latch does.
         */
        DisableFirst = 1,
        /**
         * @brief Holds the hooks in a HookStack and runs HookStack::retire before the session drain.
         * @details Busy returns DMK_STAGED_RELOAD_BUSY, and Refused returns DMK_STAGED_RELOAD_RESTART_REQUIRED. Both
         *          keep every hook and the Session. A pinned hook also returns DMK_STAGED_RELOAD_RESTART_REQUIRED and
         *          refuses every later Init. InitOptions::retain_mid does not apply.
         */
        Retire = 2,
    };

    /**
     * @enum DetourPark
     * @brief The action that the next counted detour call takes after ArmParkFn.
     * @details One armed call takes the action, and later calls run the detour as usual.
     */
    enum class DetourPark : int
    {
        /// ArmParkFn arms only the press callback of the probe binding.
        None = 0,
        /// The call waits inside the detour until ReleaseParkFn, for at most 30 seconds.
        Wait = 1,
        /// The call runs HookStack::retire on the generation stack from inside the detour. Requires Retire.
        SelfRetire = 2,
    };

    /**
     * @struct InitOptions
     * @brief Per-generation configuration the host passes to StagedInit.
     */
    struct InitOptions
    {
        /**
         * @brief Names a window whose UI thread the local wheel hook mounts on when enable_wheel is nonzero.
         * @details Null selects the generation's own init thread.
         */
        HWND wheel_window = nullptr;
        /// A nonzero value registers a consume WheelUp binding and waits for the local wheel hook to mount.
        int enable_wheel = 0;
        /// A nonzero value registers a consume gamepad chord and waits for complete XInput pair coverage.
        int enable_consume_gamepad = 0;
        /// Registers the callback park probe for @ref ARM_PARK_SYMBOL when nonzero.
        int enable_probe_binding = 0;
        /// Selects one @ref FailStage that makes StagedInit roll back and return 0 when nonzero.
        int fail_stage = 0;
        /// Sets the drain deadline that StagedShutdown passes to prepare_logic_dll_unload_all, in milliseconds.
        std::uint32_t drain_timeout_ms = 5000;
        /// Sets the log file name for this generation's Session.
        const char *log_file = nullptr;
        /// Selects the required resident wheel host when non-null. Null preserves the local MessageHook backend.
        const WheelHostTable *wheel_host = nullptr;
        /// Installs and exercises six mid hooks when nonzero.
        int enable_mid = 0;
        /**
         * @brief Parks one caller at the first mid route entry through StagedShutdown when nonzero.
         * @details Teardown then retains that route. Requires enable_mid.
         */
        int retain_mid = 0;
        /**
         * @brief Subscribes the generation's namespace-scope dispatcher and emits one event when nonzero.
         * @details The dispatcher lives until the image unloads, so its static destruction returns its TLS ownership.
         */
        int enable_dispatcher = 0;
        /**
         * @brief Subscribes to both diagnostics dispatchers before the hooks install when nonzero.
         * @details StagedShutdown drops both subscriptions after the hooks clear and before ~Session.
         */
        int enable_diagnostics = 0;
        /// Keeps the hook lifecycle subscription live across ~Session when nonzero. Requires enable_diagnostics.
        int retain_diagnostics = 0;
        /// Selects the @ref HookKind on @ref HOOK_TARGET_SYMBOL.
        int hook_kind = 0;
        /// Selects the @ref TeardownMode of StagedShutdown.
        int teardown_mode = 0;
        /**
         * @brief Sets the value that this generation's hook adds to each call result of @ref HOOK_TARGET_SYMBOL.
         * @details Init measures one call before the install and requires one armed call to return that result plus
         *          this bonus. A family can therefore arm over another layer. Distinct bonuses show which layers a
         *          call crossed.
         */
        int detour_bonus = 1000;
        /**
         * @brief Names the hook on @ref HOOK_TARGET_SYMBOL. Null selects "staged_gen_hook".
         * @details The name identifies the chain position, so a successor with the same name and kind claims the
         *          position that a retired generation vacated.
         */
        const char *hook_name = nullptr;
        /// Forces the backend FF path for the hook on @ref HOOK_TARGET_SYMBOL when nonzero.
        int far_hook = 0;
        /// Withholds the position claim from every install of this copy when nonzero, so each install is fresh.
        int refuse_position_claims = 0;
        /**
         * @brief Selects the @ref DetourPark action of the counted detour. Requires HookKind::Counted.
         * @details ArmParkFn also arms the press callback of the probe binding, so leave enable_probe_binding zero.
         */
        int detour_park = 0;
        /**
         * @brief Names the export of @ref HOOK_TARGET_MODULE_NAME that the hook takes. Null selects
         *        @ref HOOK_TARGET_SYMBOL.
         * @details HookKind::Mid requires HOOK_TARGET_SYMBOL, because only that export adds its second argument to
         *          its result.
         */
        const char *target_symbol = nullptr;
    };

    /**
     * @struct Status
     * @brief State and counter snapshot read from one generation.
     * @details The snapshot remains readable after StagedShutdown. A module pin also keeps it readable after
     *          FreeLibrary. The host calls a pre-resolved export pointer while the image stays mapped.
     */
    struct Status
    {
        int wheel_hook_installed = 0;
        int xinput_installed = 0;
        std::uint64_t message_hook_pins = 0;
        std::uint64_t xinput_self_pins = 0;
        std::uint64_t xinput_target_pins = 0;
        std::uint64_t hook_manager_leaks = 0;
        std::uint64_t input_leaks = 0;
        std::uint64_t total_intentional_leaks = 0;
        std::uint64_t total_module_pins = 0;
        std::uint64_t hook_calls = 0;
        std::uint64_t init_calls = 0;
        std::uint64_t mid_calls = 0;
        std::uintptr_t coordinator_identity = 0;
        std::size_t coordinator_bytes = 0;
        std::size_t coordinator_live = 0;
        std::size_t coordinator_retained = 0;
        /// The value that the parked caller returned through the retained route, or 0.
        int parked_result = 0;
        /// Events that the generation's dispatcher delivered.
        std::uint64_t dispatched = 0;
        /// Hook lifecycle events that the generation's diagnostics subscription observed.
        std::uint64_t lifecycle_events = 0;
        std::uint64_t diagnostics_leaks = 0;
        /// LeakSubsystem::HookResidue: retired hooks that keep backend storage while no caller reaches their detour.
        std::uint64_t hook_residue_leaks = 0;
        /// ModulePinReason::Hook: one module reference per hook whose detour a caller can still reach.
        std::uint64_t hook_module_pins = 0;
        /// Process route records whose relay cell is Vacant.
        std::size_t coordinator_vacant = 0;
        /// HookStack::retire calls of the Retire mode, from Shutdown or from a counted detour.
        std::uint64_t retire_calls = 0;
        /// The DetourModKit::hook::RetirementOutcome of the last retire call.
        int retire_outcome = 0;
        /// The DetourModKit::ErrorCode refusal of the last retire call.
        int retire_refusal = 0;
        std::uint32_t retire_restored = 0;
        std::uint32_t retire_vacated = 0;
        std::uint32_t retire_pinned = 0;
        std::uint32_t retire_in_flight = 0;
        /// Retire calls that a counted detour ran on its own generation stack.
        std::uint64_t self_retire_calls = 0;
        /// Hooks that the generation holds, in its slot array or its HookStack.
        std::uint64_t held_hooks = 0;
    };

    /// Runs the guide's Init sequence and returns nonzero after every requested subsystem becomes live.
    using InitFn = int (*)(const InitOptions *options) noexcept;

    /**
     * @brief Runs the guide's Shutdown sequence and returns a DetourModKit/abi/staged_reload.h value.
     * @details A failed drain, disable, or park returns DMK_STAGED_RELOAD_REFUSED, or RESTART_REQUIRED after a pin.
     *          @ref TeardownMode owns the values of the Retire mode.
     */
    using ShutdownFn = int (*)() noexcept;

    /// Returns the embedded @ref TAG_LENGTH tag bytes that follow @ref TAG_MARKER in this image.
    using TagFn = const char *(*)() noexcept;

    /// Fills @p out from this generation's state and counters.
    using StatusFn = void (*)(Status *out) noexcept;

    /**
     * @brief Arms the probe-binding park and raises the probe key, so the next press callback enters and waits.
     * @details InitOptions::detour_park also arms the next counted detour call.
     */
    using ArmParkFn = void (*)() noexcept;

    /// Lowers the probe key and releases a parked press callback or counted detour call.
    using ReleaseParkFn = void (*)() noexcept;

    /// Blocks until @p budget_ms expires and returns nonzero if a press callback or a counted detour call parks.
    using WaitParkedFn = int (*)(std::uint32_t budget_ms) noexcept;

    inline constexpr const char *INIT_SYMBOL = "dmk_staged_init";
    inline constexpr const char *SHUTDOWN_SYMBOL = "dmk_staged_shutdown";
    inline constexpr const char *TAG_SYMBOL = "dmk_staged_tag";
    inline constexpr const char *STATUS_SYMBOL = "dmk_staged_status";
    inline constexpr const char *ARM_PARK_SYMBOL = "dmk_staged_arm_park";
    inline constexpr const char *RELEASE_PARK_SYMBOL = "dmk_staged_release_park";
    inline constexpr const char *WAIT_PARKED_SYMBOL = "dmk_staged_wait_parked";

    /**
     * @brief Exported data whose address is the unmap oracle.
     * @details The host resolves this address before unload and keeps the raw value. GetModuleHandleExW with
     *          FROM_ADDRESS and UNCHANGED_REFCOUNT reports whether a module still owns the address. This check
     *          distinguishes a real unmap from one lost FreeLibrary reference.
     */
    inline constexpr const char *MARKER_SYMBOL = "dmk_staged_marker";
} // namespace staged_gen

#endif // DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_PROTOCOL_HPP
