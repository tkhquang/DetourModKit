#ifndef DETOURMODKIT_CONFIG_INPUT_FUSION_HPP
#define DETOURMODKIT_CONFIG_INPUT_FUSION_HPP

/**
 * @file config_input_fusion.hpp
 * @brief Internal teardown gate shared by the Config combo-binding fusions (register_press_combo /
 *        register_hold_combo).
 * @details Holds the per-binding HoldGate that gives a hold binding's RAII guard a correct cancellation lifecycle: a
 *          cancelled hold must deliver exactly one balancing on_state_change(false) and never let a stale true land
 *          after it. The logic lives in src/ (not in an anonymous namespace inside config.cpp) so the synchronization
 *          can be unit-tested directly, mirroring src/input_intercept.hpp and src/x86_decode.hpp. Not installed and not
 *          part of the public API.
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
         *          update_binding_combos / shutdown can invoke it from another thread, and the guard's release() runs
         *          on a control-plane thread -- all of them route through this gate.
         *
         *          The recursive_mutex serializes every delivery against teardown: a cross-thread release() waits
         *          behind any in-flight callback (so it observes the true last-delivered state and cannot interleave),
         *          while a re-entrant self-release from inside the callback on the same thread re-locks without
         *          deadlocking and defers its balancing edge to the wrapper's unwind. Both invocation paths already run
         *          outside every InputPoller lock, so this gate is a leaf lock with no ordering inversion.
         */
        struct HoldGate
        {
            std::recursive_mutex mutex;
            std::shared_ptr<std::atomic<bool>> enabled;
            std::function<void(bool)> on_state_change;

            // A true edge was delivered to the user and has not yet been balanced by a false edge.
            bool forwarded_active = false;
            // The guard has torn the binding down; further edges are swallowed.
            bool released = false;
            // The user callback is currently on this thread's stack.
            bool delivering = false;
            // A self-release happened mid-delivery; emit the balancing false on unwind.
            bool deferred_final = false;

            /**
             * @brief Wrapper invoked by InputManager on each hold edge; gates the edge and forwards to the user
             *        callback.
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
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_CONFIG_INPUT_FUSION_HPP
