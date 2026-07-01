/**
 * @file diagnostics_dump.cpp
 * @brief Aggregates DMK's runtime diagnostics into a single Snapshot.
 */

#include "DetourModKit/diagnostics_dump.hpp"

#include <cstddef>

namespace DetourModKit
{
    namespace Diagnostics
    {
        Snapshot collect(std::span<const rtti::DriftEntry> drift_report)
        {
            Snapshot snapshot;

            for (std::size_t i = 0; i < snapshot.intentional_leaks.size(); ++i)
            {
                snapshot.intentional_leaks[i] = intentional_leak_count(static_cast<LeakSubsystem>(i));
            }
            snapshot.total_intentional_leaks = total_intentional_leaks();

            snapshot.drift_total = drift_report.size();
            for (const rtti::DriftEntry &entry : drift_report)
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
