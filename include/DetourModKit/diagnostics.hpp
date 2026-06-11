#ifndef DETOURMODKIT_DIAGNOSTICS_HPP
#define DETOURMODKIT_DIAGNOSTICS_HPP

/**
 * @file diagnostics.hpp
 * @brief Consumer-queryable counters for DMK's intentional leak / detach paths.
 */

#include <cstddef>
#include <cstdint>

namespace DetourModKit
{
    namespace Diagnostics
    {
        /**
         * @enum LeakSubsystem
         * @brief Identifies the subsystem that took an intentional leak / detach path.
         * @details Each enumerator names one teardown site that deliberately leaks storage or detaches a thread instead
         *          of joining or freeing, to stay safe under the Windows loader lock (where a join or free would risk a
         *          deadlock or a use-after-unmap). These events fire at most once per subsystem per process and only on
         *          the loader-lock teardown path; they are not normal-shutdown counters.
         */
        enum class LeakSubsystem : std::uint8_t
        {
            HookManager,
            Logger,
            AsyncLogger,
            ConfigWatcher,
            Input,
            MemoryCache,
            Worker,
            Bootstrap,
            /// Sentinel: the number of tracked subsystems. Not a subsystem.
            Count
        };

        /**
         * @brief Records that @p subsystem took an intentional leak / detach path.
         * @details Performs a single relaxed atomic increment on a process-wide counter. Safe to call from a noexcept
         *          destructor and from
         *          DllMain / loader-lock context: it touches only a static atomic and never allocates, locks, or calls
         *          a Win32 API.
         * @param subsystem The subsystem reporting the event. @ref LeakSubsystem::Count (or any out-of-range value) is
         *                  ignored.
         * @note Relaxed ordering is sufficient: the counter is an independent event tally with no happens-before
         *       relationship to other state.
         */
        void record_intentional_leak(LeakSubsystem subsystem) noexcept;

        /**
         * @brief Returns how many intentional leak / detach events @p subsystem recorded.
         * @param subsystem The subsystem to query.
         * @return The event count, or 0 if @p subsystem is out of range.
         */
        [[nodiscard]] std::size_t intentional_leak_count(LeakSubsystem subsystem) noexcept;

        /**
         * @brief Returns the total intentional leak / detach events across all subsystems.
         * @return The summed event count.
         */
        [[nodiscard]] std::size_t total_intentional_leaks() noexcept;

        /**
         * @brief Resets every subsystem counter to zero.
         * @details Intended for test isolation; consumers normally only read.
         */
        void reset_intentional_leaks() noexcept;
    } // namespace Diagnostics
} // namespace DetourModKit

#endif // DETOURMODKIT_DIAGNOSTICS_HPP
