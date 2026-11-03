#ifndef DETOURMODKIT_TESTS_LIFECYCLE_ROUTE_COPY_PROTOCOL_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_ROUTE_COPY_PROTOCOL_HPP

#include <cstdint>

namespace route_copy
{
    /** @brief Commands for one independently linked hook participant. */
    enum class Command : int
    {
        Install,
        InstallInline,
        Reset,
        Scan,
        HoldScan,
        ScanReached,
        ReleaseScan,
        HoldPatch,
        PatchReached,
        ReleasePatch,
        Disable,
        HoldEntry,
        EntryReached,
        ReleaseEntry,
        Trampoline,
        Hits,
        Unavailable,
        Incompatible,
        RestoreCoordination,
        Identity,
        Records,
        Fill,
        Clear,
        HoldCoordinator,
        Warnings,
        SelfReset,
        Enable,
        EnableLayerConflict,
        DisableLayerConflict,
        DependentRetentions,
        HoldAdapter,
        ReleaseAdapter,
        Enabled,
        RefuseNextAcquisition,
        /// Returns the HookResidue count of this copy.
        Residue,
        /// Returns the records whose relay cell is Vacant.
        Vacant,
        /// Returns the module references that this copy holds for its hooks.
        ModulePins,
        /// Selects the legacy layer, given as the argument value, that the later hook commands use.
        SelectLayer,
        /// Reports whether the process coordinator ranks the selected legacy layer as the top layer.
        Top,
        /// Parks the next caller that the route of this copy's hook admits, before its destination.
        HoldDestination,
        /// Opens backend trap windows on a target until the host stops the loop. The argument is a @ref TrapLoop.
        TrapLoop,
        /// Creates and destroys a disabled inline hook on a target for each round. The argument is a @ref CreateLoop.
        CreateLoop,
        /// Returns the coordinator wait lines that this copy logged.
        WaitWarnings,
        /// Returns the toggle refusals that this copy logged for an incompatible coordinator.
        IncompatibleWarnings,
        /// Installs and arms a hook through HookStack::install. The argument is an @ref InstallRound.
        StackInstall,
        /// Runs inline_at, the original store, HookStack::push, and enable. The argument is an @ref InstallRound.
        TwoStepInstall,
        /// Returns the position of this copy's detour in the last call through the target, or zero if it did not run.
        EntryOrder,
    };

    /// The hook shape of an install round.
    enum class HookShape : std::uint8_t
    {
        CountedInline,
        Mid,
    };

    /// How the install of one round ended in one copy. @ref InstallOutcome::Count bounds the values.
    enum class InstallOutcome : std::uint8_t
    {
        Armed,
        LayerConflict,
        EnableFailed,
        OtherFailure,
        Count,
    };

    /** @brief The target, the entry counter that the host shares, and the hook shape of one install round. */
    struct InstallRound
    {
        void *target{};
        volatile long *sequence{};
        HookShape shape{HookShape::CountedInline};
    };

    /** @brief Host events that delimit ownership of the process coordinator. */
    struct HoldEvents
    {
        void *entered{};
        void *release{};
    };

    /** @brief The target, the stop event, and the window count of a trap window loop. */
    struct TrapLoop
    {
        void *target{};
        void *started{};
        void *stop{};
        std::uint32_t windows{};
    };

    /** @brief The target, the round count, and the install results of a create loop. */
    struct CreateLoop
    {
        void *target{};
        std::uint32_t rounds{};
        std::uint32_t created{};
        std::uint32_t prologue_unsafe{};
        std::uint64_t install_microseconds_total{};
        std::uint64_t install_microseconds_max{};
    };

    /** @brief Executes a fixture command and returns its result or address. */
    using CommandFn = std::uintptr_t (*)(Command, void *) noexcept;
} // namespace route_copy

#endif // DETOURMODKIT_TESTS_LIFECYCLE_ROUTE_COPY_PROTOCOL_HPP
