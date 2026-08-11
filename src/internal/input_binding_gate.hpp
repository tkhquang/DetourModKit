#ifndef DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP
#define DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP

/**
 * @file input_binding_gate.hpp
 * @brief Per-binding teardown gates backing a BindingGuard's cancellation lifecycle (press and hold).
 * @details Each gate serializes a binding's callback deliveries against its teardown so a guard can retire the
 *          callback, and a hold can synthesize its one balancing released(false), without racing the poll thread.
 *
 *          Ordering discipline (the property that keeps interdependent bindings deadlock-free): the user callback runs
 *          OUTSIDE the gate mutex, marked as this thread's consumer code. The mutex protects only the bookkeeping. A
 *          release reached from inside any callback (a self-release, or a callback that releases a second binding's
 *          guard) therefore never blocks on gate rundown: it defers the balancing edge to an in-flight delivery's
 *          unwind, or runs it inline when that gate has none. So no wait chain closes on the thread that is running
 *          the callback, and two bindings whose teardown callbacks release each other cannot form an ABBA cycle.
 *
 *          An ordinary delivery is marked by a DeliveryScope and is refused outright when that mark cannot be
 *          recorded. Teardown consumer code -- a balancing edge, and retirement's invocation plus the destruction of
 *          the retired callable's captures -- cannot be declined, so it carries a MandatoryDeliveryScope whose
 *          stack-local registration records the thread even when the TLS depth store fails. Without that, two threads
 *          each inside a teardown callback that releases the other's gate would both read as control plane and each
 *          wait on the other's claim.
 *
 *          The escape is per-thread and exact, so it excuses only the running thread: a control-plane release on
 *          ANOTHER thread still blocks until the gate is quiesced -- any in-flight delivery drained and any concurrent
 *          teardown's consumer-code span finished, which for retirement includes destroying the callable's captures. A
 *          release wait is unbounded; retirement instead refuses when its deadline expires. A caller must therefore not
 *          hold a lock, or own a join, that callback or capture-destructor code can wait on. In exchange it may destroy
 *          state the callback captured the moment release() returns. Deliveries to one gate are serialized by the same
 *          in-flight count, so forwarded edges reach the consumer in decision order even though the callback runs
 *          unlocked.
 *
 *          The logic lives in its own engine header (not an anonymous namespace inside a TU) so the synchronization is
 *          unit-testable. Not installed and not part of the public API.
 */

#include "internal/input_binding_lifecycle.hpp"
#include "internal/input_delivery_scope.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct BindingGate
         * @brief Type-erased handle a binding's engine entry keeps on the gate its wrappers dispatch through.
         * @details A gate has two strong owners, the poller's exploded engine entries and the BindingGuard's one-shot
         *          release closure, and it owns the consumer callback. Dropping the engine entries therefore retires
         *          the binding without destroying the callback, which is safe for an ordinary reshape and unsafe
         *          before a Logic DLL is unmapped. This base gives the unload drain a way to reach the gate itself.
         */
        struct BindingGate
        {
            virtual ~BindingGate() = default;

            /**
             * @brief Ends delivery, emits a still-held hold's balancing edge, and destroys the consumer callback.
             * @param deadline Bound on the wait for an in-flight delivery to unwind.
             * @return False when the deadline expired with a delivery still running; the callback is then retained,
             *         because destroying a callable a poll thread is executing would free code out from under it.
             * @details Idempotent. Unlike @c release(), which leaves the callback in place for the binding's guard,
             *          this hands ownership of the callback to the calling thread and destroys it there, so no later
             *          guard release can reach it. Control-plane only: the wait would deadlock a caller that is
             *          itself inside a delivery.
             */
            [[nodiscard]] virtual bool retire(std::chrono::steady_clock::time_point deadline) = 0;
        };

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
        struct HoldGate : BindingGate
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
            // Callback invocations running outside the mutex, including a guard-release balancing edge.
            int in_flight = 0;
            // A release arrived while a delivery was in flight and could not block; the delivery emits the balancing
            // false on its unwind.
            bool deferred_final = false;
            // A control-plane teardown (a guard release or the unload drain's retire) has marked the gate released but
            // has not finished its consumer-code span: the release's balancing edge, or retirement's edge plus callable
            // disposal. `in_flight` cannot express this on its own: the claimant drops the mutex to wait for deliveries
            // to drain, so without a claim taken at the same moment as `released` a second teardown could observe
            // `in_flight == 0` inside that window and report a quiesced gate while the first is about to enter the
            // callback.
            bool teardown_active = false;
            // Native thread running that span, set and cleared with `teardown_active`. The same-gate recursion guard:
            // it names the one claim a waiter must not wait for, its own. Win32 thread identity is allocation-free,
            // unlike std::this_thread::get_id() on a foreign MinGW/winpthreads thread.
            std::uint32_t teardown_owner = 0;

            /**
             * @brief RAII holder for one unlocked callback invocation's slot in @ref in_flight.
             * @details A delivery holds one, including across the deferred balancing edge on its unwind. release() and
             *          retire() wait for in_flight == 0 and then act on a quiesced gate -- release() lets its caller
             *          destroy state the callback captured, retire() moves the callback out and destroys it -- so a
             *          slot released on every exit, a throw out of the callback included, is what makes that wait mean
             *          "no consumer code is running" rather than "no delivery is running". Consumer code a teardown
             *          path itself runs is covered by @ref TeardownScope instead, which spans the claim as well.
             */
            struct InFlightSlot
            {
                explicit InFlightSlot(HoldGate *owner) noexcept : m_gate(owner) {}
                ~InFlightSlot() noexcept
                {
                    std::lock_guard<std::mutex> exit_lock(m_gate->mutex);
                    --m_gate->in_flight;
                    m_gate->idle_cv.notify_all();
                }

                // One slot decrements exactly once, like the DeliveryScope it brackets. A copy would decrement twice
                // and drive in_flight negative, at which point the == 0 predicate release() and retire() wait on is
                // either already true while a callback runs or never true again.
                InFlightSlot(const InFlightSlot &) = delete;
                InFlightSlot &operator=(const InFlightSlot &) = delete;
                InFlightSlot(InFlightSlot &&) = delete;
                InFlightSlot &operator=(InFlightSlot &&) = delete;

            private:
                HoldGate *m_gate;
            };

            /**
             * @brief RAII holder for a teardown path's claim on @ref teardown_active.
             * @details Claimed under the mutex at the same moment the path sets @ref released, and cleared once its
             *          consumer-code span is over. A release spans its balancing edge; retirement also spans callable
             *          disposal. A concurrent teardown therefore waits for the whole span rather than for the callback
             *          window alone.
             */
            struct TeardownScope
            {
                explicit TeardownScope(HoldGate *owner) noexcept : m_gate(owner) {}
                ~TeardownScope() noexcept
                {
                    std::lock_guard<std::mutex> exit_lock(m_gate->mutex);
                    m_gate->teardown_active = false;
                    m_gate->teardown_owner = 0;
                    m_gate->idle_cv.notify_all();
                }

                // One claim, cleared exactly once, for the same reason InFlightSlot is neither copyable nor movable.
                TeardownScope(const TeardownScope &) = delete;
                TeardownScope &operator=(const TeardownScope &) = delete;
                TeardownScope(TeardownScope &&) = delete;
                TeardownScope &operator=(TeardownScope &&) = delete;

            private:
                HoldGate *m_gate;
            };

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

                // Take this thread's delivery identity before the crossing commits to a callback, and give the edge up
                // if it cannot be taken. Running the callback anyway would leave a control-plane release on another
                // thread unable to see that this thread is inside consumer code, and that release promises its caller
                // the opposite. Nothing consumer-visible has happened yet, so refusing here costs one edge; the entry
                // count taken above is the only state to undo. Constructing under the gate mutex is what makes that
                // undo a single decrement rather than a re-lock and a three-field rollback.
                DeliveryScope scope;
                if (!scope.admitted())
                {
                    if (active)
                    {
                        --active_entries;
                    }
                    else
                    {
                        ++active_entries;
                    }
                    return;
                }

                forwarded_active = active;
                ++in_flight;
                lock.unlock();

                // Held across the deferred balancing edge below, not just the callback: waking a waiter between the
                // two would hand it a callback that is about to execute.
                InFlightSlot in_flight_slot{this};

                std::exception_ptr err;
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

                bool emit_deferred = false;
                {
                    std::lock_guard<std::mutex> bookkeeping(mutex);
                    emit_deferred = (in_flight == 1 && deferred_final && forwarded_active);
                    if (in_flight == 1 && deferred_final)
                    {
                        deferred_final = false;
                    }
                    if (emit_deferred)
                    {
                        forwarded_active = false;
                    }
                }

                // A release() that could not block (self-release, or cross-binding release from inside another
                // callback) deferred its balancing false to here; emit it now the callback has unwound. When the
                // primary callback threw, swallow any secondary throw so the original exception is the one that
                // surfaces to the poller; otherwise let it propagate to the poller's dispatch handler.
                if (emit_deferred && on_state_change)
                {
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
             *          marks the gate released. If this gate has a delivery in flight, the balancing false is deferred
             *          to that delivery's unwind; otherwise it may run inline. A depth-zero return means the gate is
             *          quiesced, so a release that finds another teardown already claiming the gate waits for that one
             *          to finish instead of returning on the strength of its own no-op.
             */
            void release()
            {
                std::unique_lock<std::mutex> lock(mutex);
                if (released)
                {
                    // The unload drain's retire(), or a repeated direct release, already owns this gate's consumer-code
                    // span and may be inside the consumer's balancing edge right now. Returning here would tell this
                    // caller it may destroy the state that callback captured while the callback is still reading it.
                    // Wait the claimant out. A release reached from inside a delivery must not wait -- that is the
                    // ordering discipline at the top of this file -- and need not: it is not a boundary where a caller
                    // destroys captured state, and the delivery it is nested in is the very thing a waiter would await.
                    // The claim's own thread is excused for the same reason and without needing the marker, which is
                    // what keeps a refused DeliveryScope from turning a self-release into a wait on this very frame.
                    if (!current_thread_in_delivery() && teardown_owner != current_native_thread_id())
                    {
                        idle_cv.wait(lock, [this] { return !teardown_active && in_flight == 0; });
                    }
                    return;
                }
                released = true;
                // Claimed before the wait below drops the mutex. Setting it together with `released` is what closes the
                // window: any later release() now sees a claim rather than a merely-released gate.
                teardown_active = true;
                teardown_owner = current_native_thread_id();
                if (in_flight > 0)
                {
                    if (current_thread_in_delivery())
                    {
                        // The in-flight delivery emits the balancing false on its own unwind, inside its own in-flight
                        // slot, so the claim ends here and a waiter tracks that slot instead.
                        deferred_final = true;
                        teardown_active = false;
                        teardown_owner = 0;
                        idle_cv.notify_all();
                        return;
                    }
                    idle_cv.wait(lock, [this] { return in_flight == 0; });
                }
                const bool emit_false = forwarded_active;
                forwarded_active = false;
                if (!emit_false || !on_state_change)
                {
                    teardown_active = false;
                    teardown_owner = 0;
                    idle_cv.notify_all();
                    return;
                }
                lock.unlock();
                // Emit the balancing false UNWRAPPED: forwarded_active is already cleared, so a throw here cannot
                // strand a stale true, and BindingGuard's composed teardown relies on the throw propagating (it runs
                // its consume-suppression clear even when the balancing edge throws). The noexcept facade release
                // catches it. The balancing edge is mandatory consumer code, so a MandatoryDeliveryScope brackets it:
                // a nested release from this callback still defers, and it does so even when the TLS depth store is
                // refused, which is the composition where two threads each running a cross-gate teardown callback
                // would otherwise both read as control plane and wait on each other's claim.
                // The claim outlives the call, including a throw out of it, so retire() cannot move and destroy the
                // callable mid-invocation and a concurrent release() cannot report the gate quiesced.
                TeardownScope teardown_slot{this};
                MandatoryDeliveryScope scope;
                on_state_change(false);
            }

            /**
             * @copydoc BindingGate::retire
             * @details Takes the callback out of the gate under the mutex, so the balancing false runs through the
             *          caller's own copy and the DLL-defined callable is destroyed on this thread rather than
             *          surviving in a retained guard. A gate the guard already released has nothing left to balance
             *          and only the callback to hand over.
             */
            [[nodiscard]] bool retire(std::chrono::steady_clock::time_point deadline) override
            {
                std::function<void(bool)> callback;
                bool emit_false = false;
                {
                    std::unique_lock<std::mutex> lock(mutex);
                    // A concurrent release() runs its balancing edge unlocked under a teardown claim. Retiring through
                    // that claim would move and destroy the callable the other thread is still invoking, so the claim
                    // is part of the quiescence this deadline is waiting for. A claim this thread holds is the one
                    // exception: waiting for it would be waiting for the frame doing the waiting.
                    if (teardown_owner == current_native_thread_id())
                    {
                        return false;
                    }
                    if (!idle_cv.wait_until(lock, deadline, [this] { return in_flight == 0 && !teardown_active; }))
                    {
                        return false;
                    }
                    released = true;
                    emit_false = forwarded_active;
                    forwarded_active = false;
                    callback = std::move(on_state_change);
                    on_state_change = nullptr;
                    if (callback)
                    {
                        teardown_active = true;
                        teardown_owner = current_native_thread_id();
                    }
                }

                // Emit through the local copy and let it die here, both inside the claim and the mandatory delivery
                // identity: the invocation and ~std::function (which runs the consumer's captured destructors,
                // Logic-DLL code on the unload path) are equally code a racing release() must not report as quiesced.
                // The scope must outlive `owned` so a captured destructor that releases this or another gate defers
                // instead of waiting on the teardown that is destroying it, and it must be the mandatory form because
                // this disposal cannot be declined when the depth store refuses.
                if (callback)
                {
                    TeardownScope teardown_slot{this};
                    MandatoryDeliveryScope scope;
                    std::function<void(bool)> owned = std::move(callback);
                    // A moved-from std::function is only required to be valid, not empty, so clear the outer shell
                    // here rather than leave the consumer's captures to a destructor that runs after both scopes have
                    // ended. PressGate::retire() disposes through the same guaranteed form.
                    callback = nullptr;
                    if (emit_false)
                    {
                        owned(false);
                    }
                }
                return true;
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
        struct PressGate : BindingGate
        {
            std::mutex mutex;
            std::condition_variable idle_cv;
            std::shared_ptr<std::atomic<bool>> enabled;
            std::shared_ptr<BindingLifecycle> lifecycle;
            std::function<void()> on_press;
            bool released = false;
            int in_flight = 0;
            // Native thread inside retire()'s callable disposal, which is counted in `in_flight` because it runs
            // consumer destructors. Serves the same purpose as HoldGate::teardown_owner: the same-gate recursion
            // guard, naming the one claim a waiter must not wait for.
            std::uint32_t teardown_owner = 0;

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
                // Same admission rule as HoldGate::deliver, and cheaper to undo: a press commits no gate state before
                // this point, so a refused frame simply drops the edge.
                DeliveryScope scope;
                if (!scope.admitted())
                {
                    return;
                }
                ++in_flight;
                lock.unlock();

                std::exception_ptr err;
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
                if (in_flight > 0 && !current_thread_in_delivery() && teardown_owner != current_native_thread_id())
                {
                    idle_cv.wait(lock, [this] { return in_flight == 0; });
                }
            }

            /**
             * @copydoc BindingGate::retire
             * @details A press has no lingering edge to balance, so retirement is the run-down plus handing the
             *          callback to this thread to destroy. Destruction happens unlocked: it runs the consumer's
             *          captured destructors, which must not observe the gate mutex held. It is still counted, because
             *          a concurrent release() promises its caller a quiesced gate and those destructors are consumer
             *          (Logic-DLL) code.
             */
            [[nodiscard]] bool retire(std::chrono::steady_clock::time_point deadline) override
            {
                std::function<void()> callback;
                {
                    std::unique_lock<std::mutex> lock(mutex);
                    // Retiring from inside this gate's own disposal would wait on the count that disposal holds.
                    if (teardown_owner == current_native_thread_id())
                    {
                        return false;
                    }
                    if (!idle_cv.wait_until(lock, deadline, [this] { return in_flight == 0; }))
                    {
                        return false;
                    }
                    released = true;
                    callback = std::move(on_press);
                    on_press = nullptr;
                    if (callback)
                    {
                        ++in_flight;
                        teardown_owner = current_native_thread_id();
                    }
                }

                if (callback)
                {
                    // Captured destructors are consumer code and can release a binding. Mark their execution as
                    // mandatory delivery identity so a same-gate or cross-gate release cannot wait on this disposal's
                    // own count, including when the TLS depth store refuses. ~std::function is noexcept, so the
                    // decrement below still needs no unwinding guard.
                    MandatoryDeliveryScope scope;
                    callback = nullptr;
                    std::lock_guard<std::mutex> exit_lock(mutex);
                    --in_flight;
                    teardown_owner = 0;
                    idle_cv.notify_all();
                }
                return true;
            }
        };
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_INPUT_BINDING_GATE_HPP
