#ifndef DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_PROTOCOL_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_PROTOCOL_HPP

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

    /// Names the export that each generation hooks.
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
     * @struct InitOptions
     * @brief Per-generation configuration the host passes to StagedInit.
     */
    struct InitOptions
    {
        /// Identifies the required wheel-subclass window when enable_wheel is nonzero.
        HWND wheel_window = nullptr;
        /// A nonzero value registers a consume WheelUp binding and waits for the window-procedure subclass.
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
        /// Selects the required resident wheel host when non-null. Null preserves the local WndProc backend.
        const DmkWheelHostTable *wheel_host = nullptr;
    };

    /**
     * @struct Status
     * @brief State and counter snapshot read from one generation.
     * @details The snapshot remains readable after StagedShutdown. A module pin also keeps it readable after
     *          FreeLibrary. The host calls a pre-resolved export pointer while the image stays mapped.
     */
    struct Status
    {
        int wndproc_installed = 0;
        int xinput_installed = 0;
        std::uint64_t wheel_pins = 0;
        std::uint64_t message_hook_pins = 0;
        std::uint64_t xinput_self_pins = 0;
        std::uint64_t xinput_target_pins = 0;
        std::uint64_t hook_manager_leaks = 0;
        std::uint64_t input_leaks = 0;
        std::uint64_t total_intentional_leaks = 0;
        std::uint64_t total_module_pins = 0;
        std::uint64_t hook_calls = 0;
        std::uint64_t init_calls = 0;
    };

    /// Runs the guide's Init sequence and returns nonzero after every requested subsystem becomes live.
    using InitFn = int (*)(const InitOptions *options) noexcept;

    /**
     * @brief Runs the guide's Shutdown sequence and returns its refusal-boundary verdict.
     * @details A drain refusal returns 0. The loader must keep the generation mapped and retry after callback
     *          release.
     */
    using ShutdownFn = int (*)() noexcept;

    /// Returns the embedded @ref TAG_LENGTH tag bytes that follow @ref TAG_MARKER in this image.
    using TagFn = const char *(*)() noexcept;

    /// Fills @p out from this generation's state and counters.
    using StatusFn = void (*)(Status *out) noexcept;

    /// Arms the probe-binding park and raises the probe key, so the next press callback enters and waits.
    using ArmParkFn = void (*)() noexcept;

    /// Lowers the probe key and releases a parked press callback.
    using ReleaseParkFn = void (*)() noexcept;

    /// Blocks until @p budget_ms expires and returns nonzero if a press callback parks.
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
