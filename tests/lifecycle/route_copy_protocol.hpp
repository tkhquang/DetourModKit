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
    };

    /** @brief Host events that delimit ownership of the process coordinator. */
    struct HoldEvents
    {
        void *entered{};
        void *release{};
    };

    /** @brief Executes a fixture command and returns its result or address. */
    using CommandFn = std::uintptr_t (*)(Command, void *) noexcept;
} // namespace route_copy

#endif // DETOURMODKIT_TESTS_LIFECYCLE_ROUTE_COPY_PROTOCOL_HPP
