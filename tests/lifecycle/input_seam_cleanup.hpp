#ifndef DETOURMODKIT_TESTS_LIFECYCLE_INPUT_SEAM_CLEANUP_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_INPUT_SEAM_CLEANUP_HPP

#include "DetourModKit/input.hpp"
#include "internal/input_poller.hpp"

#include <chrono>
#include <functional>
#include <thread>
#include <utility>

/**
 * @file input_seam_cleanup.hpp
 * @brief Rundown ownership for raw lifecycle hosts that start the real input engine behind a test seam.
 * @details A raw proof's oracle is its exit status, so its failure exits are as load-bearing as its success path.
 *          They are also where the poll thread is still live: returning from a scope a binding callback captured by
 *          reference destroys that callback's payload underneath it, and clearing a process-wide seam the loop is
 *          calling destroys a callable mid-call. Either turns an intended red diagnostic into a native access
 *          violation or a hang, which reports as a different failure than the one the proof was written to state.
 *
 *          The owner below makes that ordering structural rather than something each exit path has to remember.
 */

namespace dmk_lifecycle
{
    /**
     * @brief Unblocks parked callback work, runs the input engine down, and clears the poller seams in that order.
     *
     * Declare one immediately after the engine starts and AFTER every local a binding callback captures. Reverse
     * destruction order then joins the poll thread while those captures are still alive, and no exit path can clear a
     * seam before the thread that reads it has stopped. Failure exits become a plain `return`.
     *
     * @warning One owner per host, destroyed on the thread that created it. Not thread-safe and not reentrant.
     */
    class InputSeamOwner
    {
    public:
        /// Bound on the wait for a deferred rundown, so a wedged reaper fails the host's own timeout, not this one.
        static constexpr auto QUIESCE_BOUND = std::chrono::seconds{15};

        InputSeamOwner() noexcept = default;

        /**
         * @param unblock Releases work parked inside a callback (a flag another callback spins on). Must not throw.
         * @param quiesced Reports that a deferred rundown has finished. Required only when the host can reach
         *        shutdown() from a binding callback: the facade hands that rundown to the process reaper and returns
         *        before it has delivered its balancing release, so the engine reads as stopped while a callback can
         *        still run. Hosts whose shutdown is always external do not need one; joining is synchronous there.
         */
        explicit InputSeamOwner(std::function<void()> unblock, std::function<bool()> quiesced = {}) noexcept
            : m_unblock(std::move(unblock)), m_quiesced(std::move(quiesced))
        {
        }

        InputSeamOwner(const InputSeamOwner &) = delete;
        InputSeamOwner &operator=(const InputSeamOwner &) = delete;

        ~InputSeamOwner() noexcept { run_down(); }

        /// Idempotent, so a success path may run the sequence explicitly and still let the destructor cover a return.
        void run_down() noexcept
        {
            if (m_ran_down)
            {
                return;
            }
            m_ran_down = true;

            // A callback parked on another callback's flag would never return, so the join below would never complete.
            if (m_unblock)
            {
                m_unblock();
            }

            DetourModKit::input::Input::instance().shutdown();

            // shutdown() joins the poll thread, but a rundown it handed to the reaper is still running off-thread.
            // Waiting on the host's own completion signal is what makes the clear below safe in that case.
            if (m_quiesced)
            {
                const auto deadline = std::chrono::steady_clock::now() + QUIESCE_BOUND;
                while (!m_quiesced() && std::chrono::steady_clock::now() < deadline)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{1});
                }
                if (!m_quiesced())
                {
                    // Clearing now would free a callable a live rundown is about to call. Leaving the seams installed
                    // costs nothing in a process that is exiting, and keeps the host's exit status the diagnostic.
                    return;
                }
            }

            clear_seams();
        }

        /**
         * @brief Hand the rundown to an outer owner, so this scope's exit does not perform one.
         *
         * For a scope whose SUCCESS path deliberately leaves the engine running (a loop iteration that re-registers
         * against a still-started manager) while its failure exits must still run down before the state their
         * callbacks captured dies. Call it only where the callbacks have already completed and nothing is parked.
         */
        void dismiss() noexcept { m_ran_down = true; }

        /// The seams a poller reads. Cleared only from run_down(), once nothing can be inside them.
        static void clear_seams() noexcept
        {
            DetourModKit::detail::g_input_key_state_probe = nullptr;
            DetourModKit::detail::g_input_post_stage_probe = nullptr;
            DetourModKit::detail::g_input_pre_dispatch_probe = nullptr;
            DetourModKit::detail::g_input_join_fail_seam = nullptr;
        }

    private:
        std::function<void()> m_unblock;
        std::function<bool()> m_quiesced;
        bool m_ran_down{false};
    };
} // namespace dmk_lifecycle

#endif // DETOURMODKIT_TESTS_LIFECYCLE_INPUT_SEAM_CLEANUP_HPP
