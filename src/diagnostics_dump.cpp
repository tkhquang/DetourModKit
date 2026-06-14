/**
 * @file diagnostics_dump.cpp
 * @brief Aggregates DMK's runtime diagnostics into a single Snapshot.
 */

#include "DetourModKit/diagnostics_dump.hpp"

#include <cstddef>
#include <unordered_map>

namespace DetourModKit
{
    namespace Diagnostics
    {
        Snapshot collect(const HookManager &hooks, std::span<const Anchors::ResolvedAnchor> anchor_report,
                         std::span<const Rtti::DriftEntry> drift_report)
        {
            Snapshot snapshot;

            for (std::size_t i = 0; i < snapshot.intentional_leaks.size(); ++i)
            {
                snapshot.intentional_leaks[i] = intentional_leak_count(static_cast<LeakSubsystem>(i));
            }
            snapshot.total_intentional_leaks = total_intentional_leaks();

            // get_hook_counts() reports only the inline + mid registry (VMT hooks are tracked separately). Sum every
            // status for the total so a transient Enabling / Disabling hook is still counted, and pull out the two
            // steady states callers care about.
            const std::unordered_map<HookStatus, std::size_t> hook_counts = hooks.get_hook_counts();
            for (const auto &[status, count] : hook_counts)
            {
                snapshot.hooks_total += count;
                if (status == HookStatus::Active)
                {
                    snapshot.hooks_active = count;
                }
                else if (status == HookStatus::Disabled)
                {
                    snapshot.hooks_disabled = count;
                }
            }

            snapshot.anchor_quality = Anchors::assess_quality(anchor_report);

            snapshot.drift_total = drift_report.size();
            for (const Rtti::DriftEntry &entry : drift_report)
            {
                if (entry.ok)
                {
                    ++snapshot.drift_healed;
                }
                else
                {
                    ++snapshot.drift_failed;
                }
            }

            return snapshot;
        }
    } // namespace Diagnostics
} // namespace DetourModKit
