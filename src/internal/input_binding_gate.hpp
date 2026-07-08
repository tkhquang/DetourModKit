#ifndef DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP
#define DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP

/**
 * @file input_binding_gate.hpp
 * @brief Internal teardown gates that back a BindingGuard's cancellation lifecycle (press and hold).
 * @details Holds the two per-binding gates that give a binding's RAII guard a correct cancellation lifecycle:
 *          - HoldGate: a cancelled hold must deliver exactly one balancing on_state_change(false) and never let a stale
 *            true land after it, and a multi-combo hold sharing one gate must forward only the aggregate held/released
 *            transitions rather than one edge per exploded combo.
 *          - PressGate: a cancelled press must run down any in-flight on_press before release() returns, so a caller
 *            can safely destroy state the callback captured the moment the guard is released.
 *          The logic lives in its own engine header (not an anonymous namespace inside a TU) so the synchronization can
 *          be unit-tested directly. Not installed and not part of the public API.
 */

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct HoldGate
         * @brief Per-binding teardown gate shared between a hold binding's callback wrapper and its guard.
         * @details A hold callback carries lingering state: the consumer is told true (held) until told false
         *          (released). Cancelling the binding mid-hold must therefore deliver exactly one balancing false and
         *          never let a stale true land after it. The poller invokes the wrapper on edges from the poll thread,
         *          update_combos / shutdown can invoke it from another thread, and the guard's release() runs on a
         *          control-plane thread -- all of them route through this gate.
         *
         *          The recursive_mutex serializes every delivery against teardown: a cross-thread release() waits
         *          behind any in-flight callback (so it observes the true last-delivered state and cannot interleave),
         *          while a re-entrant self-release from inside the callback on the same thread re-locks without
         *          deadlocking and defers its balancing edge to the wrapper's unwind. Both invocation paths already run
         *          outside every InputPoller lock, so this gate is a leaf lock with no ordering inversion.
         *
         *          A multi-combo hold ("X = combo A | combo B") explodes into N engine entries that all share ONE gate,
         *          and the poll loop fires each entry's press/release edge independently. Forwarding every edge verbatim
         *          would desynchronize the consumer: pressing B while A is held would raise a second unbalanced true,
         *          and releasing A while B is still held would deliver a premature false. The gate therefore
         *          reference-counts the active exploded entries and forwards only the aggregate transitions: the 0->1
         *          press raises one true and the 1->0 release delivers one false, so the consumer sees "held" for the
         *          whole span any combo is down, exactly as a single-combo hold does.
         */
        struct HoldGate
        {
            std::recursive_mutex mutex;
            std::shared_ptr<std::atomic<bool>> enabled;
            std::function<void(bool)> on_state_change;

            // Number of exploded entries sharing this gate that are currently held. The consumer-visible held state is
            // (active_entries > 0); only the 0->1 and 1->0 crossings are forwarded.
            int active_entries = 0;
            // A true edge was delivered to the user and has not yet been balanced by a false edge.
            bool forwarded_active = false;
            // The guard has torn the binding down; further edges are swallowed.
            bool released = false;
            // The user callback is currently on this thread's stack.
            bool delivering = false;
            // A self-release happened mid-delivery; emit the balancing false on unwind.
            bool deferred_final = false;

            /**
             * @brief Wrapper invoked by InputPoller on each hold edge; reference-counts the shared gate's active
             *        entries and forwards only the aggregate held/released transition to the user callback.
             */
            void deliver(bool active)
            {
                std::lock_guard<std::recursive_mutex> lock(mutex);
                if (released)
                {
                    return;
                }
                if (enabled && !enabled->load(std::memory_order_acquire))
                {
                    return;
                }

                // Fold this entry's edge into the shared active-entry count and decide whether it crosses the
                // consumer-visible held boundary. Only a 0->1 or 1->0 crossing is forwarded; an overlapping combo's
                // redundant press/release moves the count without touching the user callback. A false edge while the
                // count is already zero (a re-balanced or duplicate release) is swallowed, keeping the count floored.
                bool crosses_boundary = false;
                if (active)
                {
                    crosses_boundary = (active_entries == 0);
                    ++active_entries;
                }
                else
                {
                    if (active_entries == 0)
                    {
                        return;
                    }
                    --active_entries;
                    crosses_boundary = (active_entries == 0);
                }
                if (!crosses_boundary)
                {
                    return;
                }

                forwarded_active = active;
                delivering = true;
                try
                {
                    if (on_state_change)
                    {
                        on_state_change(active);
                    }
                }
                catch (...)
                {
                    // Restore the gate invariant before the exception unwinds to the poller's callback handler (which
                    // logs it). Leaving `delivering` true would make a later release() defer its balancing edge
                    // forever.
                    delivering = false;
                    // A self-release that ran inside this now-throwing delivery set released = true and deferred its
                    // balancing false to the drain below, which the throw would skip; a later release() then
                    // short-circuits on `released` and the consumer is stranded observing the stale true. Drain it
                    // here, swallowing any secondary throw so the original exception is the one that surfaces.
                    if (deferred_final)
                    {
                        deferred_final = false;
                        if (forwarded_active && on_state_change)
                        {
                            forwarded_active = false;
                            try
                            {
                                on_state_change(false);
                            }
                            catch (...)
                            {
                            }
                        }
                    }
                    throw;
                }
                delivering = false;

                // A release() that arrived while the user callback was on this stack deferred its balancing edge here,
                // so the callback is never re-entered while still executing. Fire it once the stack has unwound, if a
                // true edge is still outstanding.
                if (deferred_final)
                {
                    deferred_final = false;
                    if (forwarded_active && on_state_change)
                    {
                        forwarded_active = false;
                        on_state_change(false);
                    }
                }
            }

            /**
             * @brief Guard teardown: disables further delivery and synthesizes one balancing false if still held.
             */
            void release()
            {
                std::lock_guard<std::recursive_mutex> lock(mutex);
                if (released)
                {
                    return;
                }
                released = true;
                if (delivering)
                {
                    // Re-entrant self-release from inside on_state_change on this same thread (the recursive_mutex let
                    // us re-lock without waiting on ourselves). Defer the balancing edge to deliver()'s unwind rather
                    // than re-entering the user callback while it is still on the stack.
                    deferred_final = true;
                    return;
                }
                // Cross-thread or post-delivery release. The lock serialized us behind any in-flight delivery, so
                // forwarded_active reflects the last edge actually delivered; balance a still-held binding with one
                // synthetic false. No edge can race past this because `released` is now set under the same lock the
                // wrapper takes.
                if (forwarded_active && on_state_change)
                {
                    forwarded_active = false;
                    on_state_change(false);
                }
            }
        };

        /**
         * @struct PressGate
         * @brief Per-binding teardown gate that runs down an in-flight press callback before the guard releases.
         * @details A press binding has no lingering state (nothing to balance the way a hold's true/false does), but it
         *          shares the hold's teardown hazard: the poll thread can be executing on_press the instant the owning
         *          BindingGuard is released on a control-plane thread. If release() only cleared a flag and returned,
         *          the caller could destroy state the callback captured while on_press is still running through it (a
         *          use-after-free). This gate closes that window by serializing delivery against release: release()
         *          takes the same lock deliver() holds while the user callback runs, so it cannot return until any
         *          in-flight on_press has finished, and it marks the gate released so no later edge re-enters.
         *
         *          The recursive_mutex mirrors HoldGate: a press callback that destroys its own guard (a one-shot
         *          binding) re-enters release() on the delivering thread, which must re-lock without deadlocking. The
         *          shared `enabled` atomic is the same flag BindingGuard::is_active() reports and the guard clears on
         *          release, so a query and the gate agree on liveness. This gate is a leaf lock: deliver() runs from the
         *          poll loop's callback-dispatch phase (outside every InputPoller lock) and release() from the guard.
         */
        struct PressGate
        {
            std::recursive_mutex mutex;
            std::shared_ptr<std::atomic<bool>> enabled;
            std::function<void()> on_press;
            // The guard has torn the binding down; further press edges are swallowed.
            bool released = false;

            /**
             * @brief Wrapper invoked by InputPoller on each press edge; forwards to the user callback under the gate.
             */
            void deliver()
            {
                std::lock_guard<std::recursive_mutex> lock(mutex);
                if (released)
                {
                    return;
                }
                if (enabled && !enabled->load(std::memory_order_acquire))
                {
                    return;
                }
                if (on_press)
                {
                    on_press();
                }
            }

            /**
             * @brief Guard teardown: marks the gate released and, by taking the lock, waits out any in-flight on_press.
             * @details The wait-out is the whole point: on return, the caller is guaranteed no on_press is running (or
             *          will start), so state the callback captured is safe to destroy. A press has no balancing edge to
             *          synthesize, so this only closes the gate.
             */
            void release()
            {
                std::lock_guard<std::recursive_mutex> lock(mutex);
                released = true;
            }
        };
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP
