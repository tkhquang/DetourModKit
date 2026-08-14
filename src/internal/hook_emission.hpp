#ifndef DETOURMODKIT_INTERNAL_HOOK_EMISSION_HPP
#define DETOURMODKIT_INTERNAL_HOOK_EMISSION_HPP

/**
 * @file internal/hook_emission.hpp
 * @brief The shared hook lifecycle snapshot and emission sequence for the hook sibling TUs.
 * @details src/hook.cpp and src/hook_toggle.cpp publish lifecycle events through this one sequence, so the
 *          population-then-emit order and the owned-name lifetime rule are stated exactly once.
 */

#include "DetourModKit/diagnostics.hpp"

#include "internal/diagnostics_population.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace DetourModKit::detail
{
    struct RemovalPopulationState
    {
        bool was_active{false};
        bool remains_live{false};
    };

    /**
     * @brief Owns the identity for one enable or disable lifecycle event.
     * @details The owned name stays valid if a subscriber destroys the hook before synchronous emission ends. A
     *          failed name copy preserves the transition and publishes an empty name (HookLifecycleName.*).
     */
    struct LifecycleSnapshot
    {
        std::string name;
        std::uint64_t ledger_id{0};
        diagnostics::HookKind kind{diagnostics::HookKind::Inline};
    };

    [[nodiscard]] inline LifecycleSnapshot snapshot_lifecycle(const std::string &name, std::uint64_t ledger_id,
                                                              bool is_inline) noexcept
    {
        LifecycleSnapshot snapshot;
        snapshot.ledger_id = ledger_id;
        snapshot.kind = is_inline ? diagnostics::HookKind::Inline : diagnostics::HookKind::Mid;
        try
        {
            snapshot.name = name;
        }
        catch (...)
        {
        }
        return snapshot;
    }

    /**
     * @brief Updates the live population tally, then emits the associated hook lifecycle event.
     * @param removal Population state for a Removed event. Teardown must capture @c was_active before it forces its
     *                status to Disabled. Set @c remains_live when the target stays conservatively tracked.
     * @details The tally moves first so a subscriber that calls collect() observes the completed transition.
     */
    inline void emit_lifecycle(std::string_view name, std::uint64_t ledger_id, diagnostics::HookKind kind,
                               diagnostics::HookTransition transition, RemovalPopulationState removal = {}) noexcept
    {
        switch (transition)
        {
        case diagnostics::HookTransition::Created:
            DetourModKit::detail::hook_population::record_created(kind == diagnostics::HookKind::Vmt);
            break;
        case diagnostics::HookTransition::Enabled:
        case diagnostics::HookTransition::Disabled:
            // The status store updates the count while it still holds the call gate. This code runs after unlock.
            // Otherwise, two toggles can commit +1/-1 in an order opposite their serialized transitions.
            break;
        case diagnostics::HookTransition::Removed:
            if (!removal.remains_live)
            {
                DetourModKit::detail::hook_population::record_removed(removal.was_active);
            }
            break;
        }
        try
        {
            diagnostics::hook_lifecycle().emit_safe(diagnostics::HookLifecycleEvent{
                .name = name, .ledger_id = ledger_id, .kind = kind, .transition = transition});
        }
        catch (...)
        {
        }
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_EMISSION_HPP
