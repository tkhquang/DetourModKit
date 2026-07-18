#ifndef DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP
#define DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP

/**
 * @file input_binding_gate.hpp
 * @brief Per-binding teardown gates backing a BindingGuard's cancellation lifecycle (press and hold).
 * @details Each gate serializes a binding's callback deliveries against its teardown so a guard can retire the
 *          callback, and a hold can synthesize its one balancing released(false), without racing the poll thread.
 *
 *          Ordering discipline (the property that keeps interdependent bindings deadlock-free): the user callback runs
 *          OUTSIDE the gate mutex, bracketed by a DeliveryScope. The mutex protects only the bookkeeping. A release
 *          reached from inside any callback (a self-release, or a callback that releases a second binding's guard)
 *          therefore never blocks on gate rundown -- it defers instead -- so no wait chain can pass through user code,
 *          and two bindings whose teardown callbacks release each other cannot form an ABBA cycle. A control-plane
 *          release (depth zero) still blocks until the in-flight delivery drains, so the caller may destroy state the
 *          callback captured the moment release() returns. Deliveries to one gate are serialized by the same in-flight
 *          count, so forwarded edges reach the consumer in decision order even though the callback runs unlocked.
 *
 *          The logic lives in its own engine header (not an anonymous namespace inside a TU) so the synchronization is
 *          unit-testable. Not installed and not part of the public API.
 */

#include "internal/input_binding_lifecycle.hpp"
#include "internal/input_delivery_scope.hpp"

#include <atomic>
#include <condition_variable>
#include <exception>
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
         *          (released), so cancelling mid-hold must deliver exactly one balancing false and never let a stale
         *          true land after it. A multi-combo hold ("X = combo A | combo B") explodes into N engine entries that
         *          all share ONE gate; the gate reference-counts the held entries in @ref active_entries and forwards
         *          only the 0->1 and 1->0 crossings, so the consumer sees "held" for the whole span any combo is down.
         *
         *          Deliveries arrive from the poll thread (edges) and from control threads (a reshape's synchronized
         *          released(false)); @ref lifecycle guards against a late true resurrecting a torn-down binding.
         */
        struct HoldGate
        {
            std::mutex mutex;
            std::condition_variable idle_cv;
            std::shared_ptr<std::atomic<bool>> enabled;
            // Shared with the binding's engine entries. Its tombstone is the resurrection guard below; may be null for
            // a gate not tied to an engine entry (never happens in the facade, tolerated for direct unit use).
            std::shared_ptr<BindingLifecycle> lifecycle;
            std::function<void(bool)> on_state_change;

            // Exploded entries sharing this gate that are currently held; consumer-visible held state is (count > 0).
            int active_entries = 0;
            // A true edge was delivered to the user and not yet balanced by a false edge.
            bool forwarded_active = false;
            // The guard has torn the binding down; further edges are swallowed.
            bool released = false;
            // Deliveries currently running the user callback outside the mutex.
            int in_flight = 0;
            // A release arrived while a delivery was in flight and could not block; the delivery emits the balancing
            // false on its unwind.
            bool deferred_final = false;

            /**
             * @brief Wrapper the poller (and a reshape's release path) invoke on each hold edge; forwards only the
             *        aggregate held/released transition to the user callback, run outside the mutex.
             */
            void deliver(bool active)
            {
                std::unique_lock<std::mutex> lock(mutex);
                if (released)
                {
                    return;
                }
                if (enabled && !enabled->load(std::memory_order_acquire))
                {
                    return;
                }
                // Serialize this delivery's callback against any other in-flight delivery for this gate, so a true and
                // a false forwarded from two threads reach the consumer in order. A delivery reached from inside a
                // callback (depth > 0) skips the wait, so no wait chain runs through user code; the concurrent-delivery
                // case that skip would otherwise expose is handled by the defer below.
                const bool in_callback = current_thread_in_delivery();
                if (!in_callback)
                {
                    idle_cv.wait(lock, [this] { return in_flight == 0; });
                    if (released)
                    {
                        return;
                    }
                }
                // Resurrection guard: once the binding is tombstoned, refuse a new held(true) edge; a balancing
                // released(false) still passes so a removed-while-held binding ends not-held regardless of the order a
                // late poll-thread true and the reshape's false arrive in.
                if (active && lifecycle && lifecycle->tombstoned())
                {
                    return;
                }

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

                // A delivery reached from inside a callback could not wait for an in-flight delivery to drain (that
                // would risk the cross-binding deadlock the skip above avoids). If one is in flight on another thread,
                // running this callback now would deliver two edges for one gate concurrently and out of decision order
                // -- a teardown false racing the poll thread's held true -- which can strand the consumer observing the
                // stale held. Defer this crossing to the in-flight delivery's unwind instead, so the consumer sees held
                // then released in order with no concurrent callback. At depth > 0 the crossing edge is always a
                // teardown false (only the poll cycle raises a held true, and it never runs inside a callback), so
                // exactly one balancing false is owed and the in-flight delivery emits it.
                if (in_callback && in_flight > 0 && !active)
                {
                    deferred_final = true;
                    return;
                }

                forwarded_active = active;
                ++in_flight;
                lock.unlock();

                std::exception_ptr err;
                {
                    DeliveryScope scope;
                    try
                    {
                        if (on_state_change)
                        {
                            on_state_change(active);
                        }
                    }
                    catch (...)
                    {
                        err = std::current_exception();
                    }
                }

                lock.lock();
                --in_flight;
                const bool emit_deferred = (in_flight == 0 && deferred_final && forwarded_active);
                if (in_flight == 0 && deferred_final)
                {
                    deferred_final = false;
                }
                if (emit_deferred)
                {
                    forwarded_active = false;
                }
                idle_cv.notify_all();
                lock.unlock();

                // A release() that could not block (self-release, or cross-binding release from inside another
                // callback) deferred its balancing false to here; emit it now the callback has unwound. When the
                // primary callback threw, swallow any secondary throw so the original exception is the one that
                // surfaces to the poller; otherwise let it propagate to the poller's dispatch handler.
                if (emit_deferred && on_state_change)
                {
                    DeliveryScope scope;
                    if (err)
                    {
                        try
                        {
                            on_state_change(false);
                        }
                        catch (...)
                        {
                        }
                    }
                    else
                    {
                        on_state_change(false);
                    }
                }
                if (err)
                {
                    std::rethrow_exception(err);
                }
            }

            /**
             * @brief Guard teardown: stops further delivery and synthesizes one balancing false if still held.
             * @details A control-plane release blocks until any in-flight delivery drains, then emits the balancing
             *          false unlocked. A release reached from inside a callback cannot block (it would deadlock), so it
             *          marks the gate released and defers the balancing false to the in-flight delivery's unwind.
             */
            void release()
            {
                std::unique_lock<std::mutex> lock(mutex);
                if (released)
                {
                    return;
                }
                released = true;
                if (in_flight > 0)
                {
                    if (current_thread_in_delivery())
                    {
                        deferred_final = true;
                        return;
                    }
                    idle_cv.wait(lock, [this] { return in_flight == 0; });
                }
                const bool emit_false = forwarded_active;
                forwarded_active = false;
                lock.unlock();
                // Emit the balancing false UNWRAPPED: forwarded_active is already cleared, so a throw here cannot
                // strand a stale true, and BindingGuard's composed teardown relies on the throw propagating (it runs
                // its consume-suppression clear even when the balancing edge throws). The noexcept facade release
                // catches it. A DeliveryScope brackets the call so a nested release from this callback still defers.
                if (emit_false && on_state_change)
                {
                    DeliveryScope scope;
                    on_state_change(false);
                }
            }
        };

        /**
         * @struct PressGate
         * @brief Per-binding teardown gate that runs down an in-flight press callback before the guard releases.
         * @details A press has no lingering state to balance, but shares the hold's teardown hazard: the poll thread
         *          can be executing on_press the instant the guard is released. A control-plane release blocks until
         *          on_press has finished, so the caller may destroy state the callback captured the moment release()
         *          returns. A one-shot press that destroys its own guard, or a callback that releases a second
         *          binding's guard, releases from inside the delivery and so cannot block; it marks the gate released
         *          and returns, and the in-flight callback observes released on its own.
         */
        struct PressGate
        {
            std::mutex mutex;
            std::condition_variable idle_cv;
            std::shared_ptr<std::atomic<bool>> enabled;
            std::shared_ptr<BindingLifecycle> lifecycle;
            std::function<void()> on_press;
            bool released = false;
            int in_flight = 0;

            /**
             * @brief Wrapper the poller invokes on each press edge; forwards to the user callback outside the mutex.
             */
            void deliver()
            {
                std::unique_lock<std::mutex> lock(mutex);
                if (released)
                {
                    return;
                }
                if (enabled && !enabled->load(std::memory_order_acquire))
                {
                    return;
                }
                if (lifecycle && lifecycle->tombstoned())
                {
                    return;
                }
                if (!current_thread_in_delivery())
                {
                    idle_cv.wait(lock, [this] { return in_flight == 0; });
                    if (released)
                    {
                        return;
                    }
                    if (lifecycle && lifecycle->tombstoned())
                    {
                        return;
                    }
                }
                ++in_flight;
                lock.unlock();

                std::exception_ptr err;
                {
                    DeliveryScope scope;
                    try
                    {
                        if (on_press)
                        {
                            on_press();
                        }
                    }
                    catch (...)
                    {
                        err = std::current_exception();
                    }
                }

                lock.lock();
                --in_flight;
                idle_cv.notify_all();
                lock.unlock();
                if (err)
                {
                    std::rethrow_exception(err);
                }
            }

            /**
             * @brief Guard teardown: marks the gate released and, off any callback, waits out any in-flight on_press.
             */
            void release()
            {
                std::unique_lock<std::mutex> lock(mutex);
                released = true;
                if (in_flight > 0 && !current_thread_in_delivery())
                {
                    idle_cv.wait(lock, [this] { return in_flight == 0; });
                }
            }
        };
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP
