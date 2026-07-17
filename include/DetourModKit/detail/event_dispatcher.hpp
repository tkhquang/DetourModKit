#ifndef DETOURMODKIT_EVENT_DISPATCHER_HPP
#define DETOURMODKIT_EVENT_DISPATCHER_HPP

/**
 * @file event_dispatcher.hpp
 * @brief Typed event dispatcher with RAII subscription management.
 * @note This header sits in the detail/ directory for compile visibility: diagnostics.hpp returns
 *       EventDispatcher<T>& and must include the template. It declares EventDispatcher at the module-root
 *       DetourModKit namespace because installed headers name the type directly. Directory placement and namespace
 *       placement are independent; the directory reflects compile visibility, not privacy.
 *
 * @details A per-event-type pub/sub dispatcher. Subscribers receive events by const reference; subscriptions are RAII
 *          guards that retire their handler on destruction. The thread-safety and rundown contracts are on
 *          EventDispatcher and Subscription, where a caller reads them.
 *
 *          @code
 *          struct PlayerStateChanged { float health; };
 *
 *          EventDispatcher<PlayerStateChanged> dispatcher;
 *
 *          auto sub = dispatcher.subscribe([](const PlayerStateChanged& e) {
 *              logger.info("Health: {}", e.health);
 *          });
 *
 *          // Safe from a hook callback: no lock of ours, no allocation.
 *          dispatcher.emit(PlayerStateChanged{.health = 75.0f});
 *          @endcode
 */

#include "DetourModKit/logger.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace DetourModKit
{
    /**
     * @brief Opaque subscription identifier returned by EventDispatcher::subscribe().
     */
    enum class SubscriptionId : uint64_t
    {
    };

    /**
     * @brief The outcome of a waiting rundown.
     */
    enum class Rundown : uint8_t
    {
        /// The handler is dead and no invocation of it is running, so the objects it captured may now be destroyed.
        /// This does not on its own make it safe to unload the module the handler's own code lives in; see
        /// @ref Subscription::tombstone_and_wait.
        Drained,
        /**
         * @brief The handler is dead, but waiting cannot be proven to terminate, so nothing was waited on.
         * @details Either the calling thread is itself inside this dispatcher's emit (much the likelier cause), or an
         *          emit could not be recorded and so cannot be ruled out as the caller. The two are not distinguished
         *          because the required action is the same: the handler is retired and will not be entered again, but
         *          an invocation may still be running, so its captures must be kept alive.
         */
        Unwaitable,
        /**
         * @brief There was nothing to run down: this Subscription holds no handler at all.
         * @details Default-constructed, moved-from, or already reset. A subscription whose handler was retired by
         *          someone else (clear(), a dispatcher rundown, ~EventDispatcher) still reports Drained rather than
         *          Inactive, because it still owns the gate and the wait it performed is a real answer about it.
         */
        Inactive
    };
} // namespace DetourModKit

namespace DetourModKit::detail
{
    /**
     * @brief The rundown state of one subscription, shared by its Subscription and the published snapshot.
     * @details Non-template so the non-template Subscription can own one and tombstone it without naming the event
     *          type. Holds no callback: the handler stays in the templated Entry, so tombstoning costs no allocation
     *          and no destruction of user state.
     *
     *          One counter suffices where the mid-hook pool needs two. That pool recycles a fixed set of slots, so it
     *          needs a second count to prove no thread is anywhere in the body before reusing one. Gates are not
     *          recycled: each is freshly allocated per subscription, and the emit loop holds the snapshot that owns it
     *          alive for the whole iteration, so a gate cannot be destroyed under a thread that is inside its
     *          invocation. Note it is the SNAPSHOT that pins the gate, not InvocationGuard, which holds only a
     *          reference: anything that shortens the snapshot's lifetime inside emit() would invalidate this.
     */
    struct EntryGate
    {
        /// The rundown tombstone: false means no further invocation of this handler may begin.
        std::atomic<bool> live{true};
        /// Invocations that passed the tombstone recheck and have not returned.
        std::atomic<std::uint32_t> in_flight{0};
    };

    /**
     * @brief One frame of the calling thread's dispatcher emit chain.
     * @details Lives on emit()'s own stack, so maintaining the chain allocates nothing. It exists so a rundown can
     *          answer "is THIS thread inside THIS dispatcher", which is what stops a rundown requested from inside a
     *          handler from waiting on itself forever.
     */
    struct EmitFrame
    {
        const void *dispatcher{nullptr};
        const void *type_tag{nullptr};
        EmitFrame *prev{nullptr};
    };

    /**
     * @brief Reserves the emit chain's thread-local storage. Control-plane only; subscribe() calls it.
     * @return false when the process has no index to give, which leaves every emit untracked and every rundown
     *         Unwaitable rather than wrong.
     * @details A Win32 TLS index rather than `thread_local`: MinGW lowers every TLS spelling to
     *          `__emutls_get_address`, which allocates on a thread's first touch and calls `abort()` if that
     *          allocation fails. `abort()` raises SIGABRT, which no catch frame intercepts, so emit_safe()'s
     *          containment would not survive it. emit_safe() is reached from hook callbacks on arbitrary host
     *          threads, where neither the allocation nor the abort is acceptable. See AGENTS.md `[B-86]`.
     */
    [[nodiscard]] bool ensure_emit_frame_tls() noexcept;

    /**
     * @brief Pushes @p frame onto the calling thread's emit chain.
     * @return false when the frame could not be recorded. The caller must then count itself untracked rather than
     *         let a rundown conclude this thread is elsewhere; see @ref untracked_emit_frames.
     */
    [[nodiscard]] bool push_emit_frame(EmitFrame &frame) noexcept;

    /// Pops a frame. Only call when the matching @ref push_emit_frame returned true.
    void pop_emit_frame(const EmitFrame &frame) noexcept;

    /// True when the calling thread is inside @p dispatcher's emit.
    [[nodiscard]] bool thread_is_emitting_dispatcher(const void *dispatcher) noexcept;

    /// True when the calling thread is inside the emit of any dispatcher sharing @p type_tag.
    [[nodiscard]] bool thread_is_emitting_type(const void *type_tag) noexcept;

    /**
     * @brief Emits whose thread could not be recorded, so self-entry cannot be disproven for anyone.
     * @details Process-wide rather than per-dispatcher: a thread that failed to record its frame is invisible to
     *          every chain walk, so no dispatcher may claim it is absent. Counted rather than made sticky so a
     *          rundown recovers once the untracked emit leaves.
     */
    [[nodiscard]] std::atomic<std::uint32_t> &untracked_emit_frames() noexcept;

    /**
     * @brief Waits out the invocations committed before @p gate was tombstoned.
     * @param gate An already-tombstoned gate. Waiting on a live gate would never terminate.
     * @param dispatcher Identity used only to compare against this thread's emit chain; never dereferenced.
     * @return Drained once no invocation remains, or Unwaitable when the wait cannot be proven to terminate.
     * @details Refuses rather than waits when the calling thread is inside @p dispatcher's emit, or when any emit
     *          anywhere could not record its frame. A wrong "this thread is elsewhere" makes the rundown wait on the
     *          very thread running it; a wrong "it might be here" only costs a refusal.
     */
    [[nodiscard]] Rundown drain_gate(EntryGate &gate, const void *dispatcher) noexcept;
} // namespace DetourModKit::detail

namespace DetourModKit
{
    /**
     * @brief RAII subscription guard that unsubscribes on destruction.
     *
     * @details Move-only. When the guard is destroyed or reset, the associated handler is retired.
     *
     *          **Lifetime contract (read before using across threads):** if the dispatcher was destroyed before this
     *          operation with a happens-before edge -- ordered teardown, e.g. the dispatcher's scope closed on this
     *          thread first, or another thread's `~EventDispatcher` synchronizes-with this reset() -- the physical
     *          compaction is silently skipped: the weak_ptr is observed expired and only the tombstone runs. That
     *          ordered case is the only lifetime overlap the weak_ptr guard covers. It does not make a Subscription
     *          operation safe against a dispatcher destroyed concurrently on another thread: reset() tests the
     *          weak_ptr and then, as a separate step, calls into the dispatcher, so a `~EventDispatcher` racing
     *          between those two steps is a use-after-free. The caller must ensure the dispatcher outlives every
     *          concurrent Subscription operation.
     */
    class Subscription
    {
    public:
        Subscription() noexcept = default;

        ~Subscription() noexcept { reset(); }

        Subscription(const Subscription &) = delete;
        Subscription &operator=(const Subscription &) = delete;

        Subscription(Subscription &&other) noexcept
            : m_alive(std::move(other.m_alive)), m_gate(std::move(other.m_gate)),
              m_dispatcher(std::exchange(other.m_dispatcher, nullptr)), m_compact(std::move(other.m_compact))
        {
            other.m_compact = nullptr;
        }

        Subscription &operator=(Subscription &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                m_alive = std::move(other.m_alive);
                m_gate = std::move(other.m_gate);
                m_dispatcher = std::exchange(other.m_dispatcher, nullptr);
                m_compact = std::move(other.m_compact);
                other.m_compact = nullptr;
            }
            return *this;
        }

        /**
         * @brief Retires the handler without waiting or reclaiming its published list slot.
         * @details The handler is dead the instant the tombstone flips: no emit that has not already committed to
         *          invoking it can begin one, on this thread or any other, including an emit nested inside the very
         *          handler that called this. The operation is a single atomic store, so it does not allocate, block,
         *          or fail and is callback-safe.
         * @note Safe to call multiple times. Use @ref tombstone_and_wait before destroying the handler's code or
         *       referenced state when an invocation may already be running.
         */
        void tombstone() noexcept
        {
            if (m_gate)
            {
                m_gate->live.store(false, std::memory_order_seq_cst);
            }
        }

        /**
         * @brief Retires the handler and best-effort reclaims its published list slot.
         * @details Calls @ref tombstone first, so logical removal is synchronous and cannot fail.
         *
         *          Reclaiming the list slot is a separate, best-effort step: it briefly takes the writer mutex, it
         *          allocates, and it is skipped entirely if the dispatcher was destroyed first. Any of that may fail
         *          without consequence. A skipped compaction costs one dead vector entry that every later emit
         *          rejects at its liveness check; it never resurrects the handler.
         *
         * @warning This does not wait: an invocation already past the liveness check may still be running on another
         *          thread when this returns. It is not callback-safe because compaction can block on the writer mutex;
         *          use @ref tombstone when only non-blocking logical removal is required.
         */
        void reset() noexcept
        {
            tombstone();
            compact_and_release();
        }

        /**
         * @brief Retires the handler and waits until no invocation of it is running.
         * @return Drained when the handler is quiesced and its captures may be destroyed; Unwaitable when the wait
         *         could not be proven to terminate and was not attempted; Inactive when there was nothing to retire.
         * @details The control-plane half of @ref reset(): use it before destroying what the handler captured. On
         *          Drained, no invocation is running and none can begin, so the objects the handler references may be
         *          destroyed.
         *
         *          Called from inside a handler on this dispatcher, this returns Unwaitable rather than wait on the
         *          calling thread. The handler is still retired; only the wait is refused. A timeout is not offered,
         *          because a wait that gives up has not drained anything.
         * @note Drained does NOT by itself make it safe to unload the module the handler's own code lives in. It waits
         *       out running invocations, but an emit still iterating on another thread holds the snapshot that owns the
         *       handler's std::function, and destroying that snapshot later runs the callable's type-erased destructor.
         *       Unloading the code needs the loader-grade quiescence a real teardown host provides, not this call.
         * @note Not callable while any allocation-free guarantee is required: this blocks.
         */
        [[nodiscard]] Rundown tombstone_and_wait() noexcept
        {
            if (!m_gate)
            {
                return Rundown::Inactive;
            }
            tombstone();
            const Rundown result = detail::drain_gate(*m_gate, m_dispatcher);
            compact_and_release();
            return result;
        }

        /// Returns true if this subscription still holds a live handler.
        [[nodiscard]] bool active() const noexcept
        {
            return m_gate != nullptr && m_gate->live.load(std::memory_order_acquire);
        }

    private:
        template <typename E> friend class EventDispatcher;

        Subscription(std::weak_ptr<void> alive, std::shared_ptr<detail::EntryGate> gate, const void *dispatcher,
                     std::function<void()> compact) noexcept
            : m_alive(std::move(alive)), m_gate(std::move(gate)), m_dispatcher(dispatcher),
              m_compact(std::move(compact))
        {
        }

        void compact_and_release() noexcept
        {
            if (m_compact && !m_alive.expired())
            {
                m_compact();
            }
            m_compact = nullptr;
            m_gate.reset();
            m_dispatcher = nullptr;
            m_alive.reset();
        }

        std::weak_ptr<void> m_alive;
        std::shared_ptr<detail::EntryGate> m_gate;
        /// Compared against the emit chain to refuse a self-wait. Never dereferenced, so a stale value is harmless.
        const void *m_dispatcher{nullptr};
        std::function<void()> m_compact;
    };

    /**
     * @brief Thread-safe typed event dispatcher with RAII subscription management.
     *
     * @tparam Event The event type. Must be copyable or movable. Handlers receive events by const reference.
     *
     * @details Each EventDispatcher manages a single event type. For multiple event types, compose multiple
     *          dispatchers:
     *          @code
     *          struct MyEvents {
     *              EventDispatcher<PlayerStateChanged> player_state;
     *              EventDispatcher<CameraUpdated> camera;
     *              EventDispatcher<ConfigReloaded> config;
     *          };
     *          @endcode
     *
     * **Thread safety:**
     * - `emit()` / `emit_safe()`: no lock of ours, and no allocation to dispatch. Per handler, the invocation takes
     *   an enter/recheck/leave pass over that entry's gate; see emit(). The one exception is emit_safe()'s catch
     *   arm, which reports a throwing handler through the logger and may allocate there: that costs nothing on the
     *   success path, and a handler that throws has already left the callback-safe contract.
     * - `subscribe()` / `clear()`: copy-on-write under a small writer mutex.
     * - `Subscription::tombstone()` is synchronous, non-blocking, allocation-free, and cannot fail. `reset()`
     *   tombstones first, then best-effort compacts under the writer mutex.
     *
     * **Reentrancy guard scope:** subscribe() is rejected from within a handler on a dispatcher of the SAME Event
     * type, including a different instance of it. Use distinct event types to avoid this (the typical usage
     * pattern); a handler on `EventDispatcher<A>` may freely subscribe to `EventDispatcher<B>`. If an emit frame
     * cannot be recorded, subscriptions are conservatively rejected until that emit leaves because its type is
     * unknown.
     *
     * **Subscribe/emit ordering invariant:** A subscribe() performs a release-store on both the snapshot pointer and
     * the atomic handler count. Any thread that observes the Subscription object returned from subscribe() (or
     * synchronizes-with the thread that did) will see the subscription in subsequent emits. Without such a
     * happens-before edge, a concurrent emit may or may not observe a freshly-published handler -- this matches the
     * user's own ordering.
     */
    template <typename Event> class EventDispatcher
    {
    public:
        /// Handler function signature: receives the event by const reference.
        using Handler = std::function<void(const Event &)>;

    private:
        // Private type aliases surfaced here so they are visible to the public API's member declarations and
        // constructor below.
        struct Entry
        {
            SubscriptionId id;
            std::shared_ptr<detail::EntryGate> gate;
            Handler callback;
        };

        using HandlerList = std::vector<Entry>;
        using SharedList = std::shared_ptr<const HandlerList>;

        /**
         * @brief Keys the emit chain by Event type: one object per instantiation, identified by its address.
         * @details Address-taken so the linker cannot fold two instantiations' tags together, which would merge two
         *          event types' reentrancy guards.
         */
        inline static const char s_type_tag{};

    public:
        EventDispatcher() : m_handlers(std::make_shared<const HandlerList>()), m_alive(std::make_shared<char>('\0')) {}

        /**
         * @brief Retires every handler.
         * @details A Subscription may outlive its dispatcher, and its gate is the only thing that can tell it the
         *          handler can never run again. Retiring here keeps the gate authoritative instead of making every
         *          reader infer liveness from a second signal.
         *
         *          Takes no lock of ours and allocates nothing, so the noexcept destructor is total: the gate stores
         *          are atomic and idempotent, and a subscribe() racing this is already a caller lifetime violation.
         *          (The snapshot load still takes the STL's internal lock for atomic<shared_ptr>, as everywhere else.)
         * @warning Does not wait. Destroying a dispatcher while one of its handlers is running is a caller lifetime
         *          violation; use tombstone_and_wait() first when that is possible.
         */
        ~EventDispatcher() noexcept
        {
            auto current = this->m_handlers.load(std::memory_order_acquire);
            for (const auto &entry : *current)
            {
                entry.gate->live.store(false, std::memory_order_seq_cst);
            }
        }

        EventDispatcher(const EventDispatcher &) = delete;
        EventDispatcher &operator=(const EventDispatcher &) = delete;
        EventDispatcher(EventDispatcher &&) = delete;
        EventDispatcher &operator=(EventDispatcher &&) = delete;

        /**
         * @brief Subscribes a handler to this event type.
         * @param handler Callable invoked on each emit(). Must be safe to call from any thread. An empty handler is
         *                rejected (see @return).
         * @return RAII Subscription guard. The handler is retired when the guard is destroyed or reset(). An EMPTY
         *         handler, a call made from within a same-type handler, ambiguous emit tracking, or a dispatcher
         *         already closed by tombstone_and_wait yields an INACTIVE Subscription (active() == false) rather
         *         than throwing; test active() when any is possible.
         * @throws std::bad_alloc if the gate or the copy-on-write list cannot be allocated. This is a control-plane
         *         call and is deliberately NOT fail-soft about that: a subscribe that cannot allocate has installed
         *         nothing, which is a truthful failure the caller can act on. Retiring a handler is the operation that
         *         must never depend on an allocation, and it does not.
         * @note Copy-on-write: allocates a new handler list of size N+1. Also reserves the process's emit-chain TLS
         *       index here, on the control plane, so that emit() only ever READS it. That removes the INDEX
         *       reservation from the callback path, not every possible first touch: a thread's first TlsSetValue to
         *       an index beyond the TEB's inline slots can still lazily allocate the expansion array. The decisive
         *       difference from emulated TLS is the failure mode, not the allocation -- TlsSetValue REPORTS failure,
         *       where emutls calls abort(), so a failure here is counted and fails closed instead of killing the host.
         */
        [[nodiscard]] Subscription subscribe(Handler handler)
        {
            if (!handler)
            {
                // Rejected at the point of misuse rather than deferred into an unrelated emit, where it could only
                // surface as a bad_function_call from someone else's call site.
                report_empty_handler_rejection();
                return {};
            }

            if (detail::thread_is_emitting_type(&s_type_tag))
            {
                report_reentrant_rejection("subscribe");
                return {};
            }
            if (detail::untracked_emit_frames().load(std::memory_order_seq_cst) != 0)
            {
                report_untracked_rejection();
                return {};
            }

            // Reserved here, on the control plane, so that emit() only ever READS the index. A failure leaves every
            // rundown Unwaitable rather than wrong, which is why it does not fail the subscribe.
            (void)detail::ensure_emit_frame_tls();

            const auto id = static_cast<SubscriptionId>(this->m_next_id.fetch_add(1, std::memory_order_relaxed));

            auto gate = std::make_shared<detail::EntryGate>();
            // Build the compaction callback before publishing. If wrapping it in std::function had to allocate -- a
            // future capture overflowing the small-object buffer -- and threw, the handler must not already be live in
            // the list with no Subscription returned to retire it. Constructing it here keeps subscribe's "installs
            // nothing on allocation failure" contract intact.
            std::function<void()> compact_fn = [this, id]() noexcept { this->compact(id); };
            {
                std::scoped_lock lock{this->m_writer_mutex};
                if (this->m_closed.load(std::memory_order_seq_cst))
                {
                    // Tested under the mutex, not before it: that is what lets tombstone_and_wait treat the snapshot
                    // it loads as the complete set. A subscribe admitted here has published before that load; one
                    // refused here never publishes at all. Checking outside the lock would leave exactly the window
                    // where a handler is installed live behind a completed drain.
                    report_closed_rejection();
                    return {};
                }
                auto current = this->m_handlers.load(std::memory_order_acquire);
                auto next = std::make_shared<HandlerList>(*current);
                next->push_back(Entry{id, gate, std::move(handler)});
                // Publish the new count first so a reader that sees 0 on the counter and skips the snapshot load cannot
                // miss a handler that has already been installed in the snapshot.
                this->m_handler_count.store(next->size(), std::memory_order_release);
                this->m_handlers.store(std::shared_ptr<const HandlerList>(std::move(next)), std::memory_order_release);
            }

            return Subscription(std::weak_ptr<void>(this->m_alive), std::move(gate), this, std::move(compact_fn));
        }

        /**
         * @brief Emits an event to all subscribers.
         * @param event The event payload, passed by const reference to each handler.
         * @note Takes no lock of ours and allocates nothing to dispatch. Handlers are invoked synchronously in
         *       subscription order. Exceptions thrown by handlers propagate to the caller.
         * @warning If calling from a game hook callback or any context where an unhandled exception would crash the
         *          host process, use emit_safe() instead. emit() lets handler exceptions propagate uncaught, which will
         *          terminate the process if no catch frame exists above the call site.
         */
        void emit(const Event &event) const
        {
            // Fast path: no subscribers means no snapshot load at all.
            if (this->m_handler_count.load(std::memory_order_acquire) == 0)
            {
                return;
            }

            SharedList snap = this->m_handlers.load(std::memory_order_acquire);
            EmitGuard guard{*this};
            for (const auto &entry : *snap)
            {
                InvocationGuard invocation{*entry.gate};
                if (!invocation.admitted())
                {
                    continue;
                }
                entry.callback(event);
            }
        }

        /**
         * @brief Emits an event, catching and discarding handler exceptions.
         * @param event The event payload.
         * @note Same read-path semantics as emit(). Handlers that throw are skipped; remaining handlers still
         *       execute. Prefer this over emit() when calling from hook callbacks or other contexts where an
         *       unhandled exception would crash the host process.
         */
        void emit_safe(const Event &event) const noexcept
        {
            if (this->m_handler_count.load(std::memory_order_acquire) == 0)
            {
                return;
            }

            SharedList snap = this->m_handlers.load(std::memory_order_acquire);
            EmitGuard guard{*this};
            for (const auto &entry : *snap)
            {
                InvocationGuard invocation{*entry.gate};
                if (!invocation.admitted())
                {
                    continue;
                }
                try
                {
                    entry.callback(event);
                }
                catch (const std::exception &ex)
                {
                    // A subscriber threw. emit_safe's whole purpose is to keep one faulty handler from crashing the
                    // host, so the exception is contained here and the remaining handlers still run. Swallowing it
                    // SILENTLY would hide a real handler bug, so surface it best-effort with the exception text.
                    report_handler_exception(ex.what());
                }
                catch (...)
                {
                    // A non-std throw carries no portable message; report the swallow without one.
                    report_handler_exception(nullptr);
                }
            }
        }

        /**
         * @brief Returns the number of published subscriber slots.
         * @note Counts published entries, including any retired handler whose slot has not been compacted yet. It is
         *       a list-occupancy figure, not a count of handlers that would run.
         */
        [[nodiscard]] size_t subscriber_count() const noexcept
        {
            return this->m_handler_count.load(std::memory_order_acquire);
        }

        /// Returns true if there are no published subscriber slots.
        [[nodiscard]] bool empty() const noexcept { return this->m_handler_count.load(std::memory_order_acquire) == 0; }

        /**
         * @brief Retires every subscriber.
         * @note Every handler is dead the instant this returns; the tombstone pass allocates nothing and cannot fail.
         *       Publishing the empty snapshot afterwards can fail under memory pressure, which leaves the dead
         *       entries occupying the list until a later mutation reclaims them. It never resurrects a handler. Takes
         *       the writer mutex, so this is a control-plane call and does not wait for in-flight handlers; use
         *       @ref tombstone_and_wait when the handlers' code or captures are about to go away.
         */
        void clear() noexcept
        {
            try
            {
                std::scoped_lock lock{this->m_writer_mutex};
                // Retire first, so an allocation failure below cannot leave a live handler behind.
                auto current = this->m_handlers.load(std::memory_order_acquire);
                for (const auto &entry : *current)
                {
                    entry.gate->live.store(false, std::memory_order_seq_cst);
                }

                std::shared_ptr<const HandlerList> empty_snap;
                try
                {
                    empty_snap = std::make_shared<const HandlerList>();
                }
                catch (...)
                {
                    return;
                }
                // Counter must go to 0 before publishing the empty snapshot so an emit that reads 0 on the fast-path
                // counter cannot still see the non-empty old snapshot afterwards.
                this->m_handler_count.store(0, std::memory_order_release);
                this->m_handlers.store(std::move(empty_snap), std::memory_order_release);
            }
            catch (...)
            {
                // A synchronization failure must not escape this no-throw control path. Retire the stable snapshot
                // visible now; a concurrent unordered subscribe may still publish after it.
                auto current = this->m_handlers.load(std::memory_order_acquire);
                for (const auto &entry : *current)
                {
                    entry.gate->live.store(false, std::memory_order_seq_cst);
                }
                return;
            }
        }

        /**
         * @brief Retires every subscriber and waits until no handler of this dispatcher is running.
         * @return Drained when every handler is quiesced; Unwaitable when the calling thread is inside this
         *         dispatcher's emit, or an emit could not be recorded, so no wait was attempted.
         * @details The rundown form of @ref clear(). On Drained, no handler is running and none can begin, so the
         *          objects every handler references may be destroyed. As with @ref Subscription::tombstone_and_wait,
         *          Drained does not on its own license unloading the module the handlers' code lives in.
         *
         *          This CLOSES the dispatcher permanently: every later subscribe() is refused and hands back an
         *          inactive Subscription. That is not a convenience, it is what makes Drained true. A rundown is only
         *          complete over a set that cannot grow behind it, so the set is closed before it is read. Otherwise
         *          a subscribe racing the drain publishes a live handler this call never waited on, and Drained would
         *          license unloading code that is still executing. The mid-hook pool closes its own set the same way,
         *          by never re-arming a slot it is running down.
         * @note Holding the writer mutex across the drain would be the obvious alternative and is a deadlock: a
         *       handler may itself call subscribe(), so the drain would wait on the very callback that needs the
         *       lock. Closing the set is what makes releasing the mutex safe.
         */
        [[nodiscard]] Rundown tombstone_and_wait() noexcept
        {
            // Close first, and outside the lock. subscribe() tests this flag while HOLDING the writer mutex, so a
            // subscribe that already published is necessarily in the snapshot loaded below, and one that has not is
            // necessarily refused. That is what makes the set read below closed rather than merely current.
            this->m_closed.store(true, std::memory_order_seq_cst);

            SharedList snap;
            try
            {
                std::scoped_lock lock{this->m_writer_mutex};
                snap = this->m_handlers.load(std::memory_order_acquire);
                for (const auto &entry : *snap)
                {
                    entry.gate->live.store(false, std::memory_order_seq_cst);
                }
            }
            catch (...)
            {
                snap = this->m_handlers.load(std::memory_order_acquire);
                for (const auto &entry : *snap)
                {
                    entry.gate->live.store(false, std::memory_order_seq_cst);
                }
                return Rundown::Unwaitable;
            }

            Rundown result = Rundown::Drained;
            for (const auto &entry : *snap)
            {
                if (drain_gate(*entry.gate, this) == Rundown::Unwaitable)
                {
                    result = Rundown::Unwaitable;
                }
            }
            clear();
            return result;
        }

#if defined(DMK_EVENT_DISPATCHER_INTERNAL_TESTING) && defined(DMK_ENABLE_TEST_SEAMS)
        /**
         * @brief Test-only diagnostic: returns the number of outstanding references to the current handler snapshot,
         *        excluding the temporary this call itself creates. A value of 1 means the dispatcher's own atomic is
         *        the sole holder (steady state). A value >1 indicates an in-flight emit or a leaked snapshot reference.
         *        Not part of the public API. Compiled only when both DMK_EVENT_DISPATCHER_INTERNAL_TESTING (the
         *        per-translation-unit opt-in) and DMK_ENABLE_TEST_SEAMS (the library-wide test-seam flag, set only in a
         *        DMK test build) are defined, so the installed header never exposes it to a consumer.
         */
        [[nodiscard]] long debug_snapshot_use_count() const noexcept
        {
            // load() returns a shared_ptr copy that bumps the refcount by 1 for its own lifetime; subtract that so the
            // reported count reflects only the other holders (the dispatcher atomic and any in-flight emit snapshots).
            auto snap = this->m_handlers.load(std::memory_order_acquire);
            return snap.use_count() - 1;
        }
#endif // DMK_EVENT_DISPATCHER_INTERNAL_TESTING && DMK_ENABLE_TEST_SEAMS

    private:
        /**
         * @brief Reclaims the list slot of an already-retired entry.
         * @details Physical compaction only: the handler is dead before this runs, so every outcome here is a
         *          space question, not a correctness one. Allocation failure leaves the dead entry in place.
         *
         *          Safe to run while an emit of this instance is iterating: that iteration holds its own
         *          copy-on-write snapshot alive, and this only stores a new one for future loads to observe.
         */
        void compact(SubscriptionId id) noexcept
        {
            try
            {
                std::scoped_lock lock{this->m_writer_mutex};
                auto current = this->m_handlers.load(std::memory_order_acquire);
                auto it = std::find_if(current->begin(), current->end(),
                                       [id](const Entry &entry) { return entry.id == id; });
                if (it == current->end())
                {
                    return;
                }

                auto next = std::make_shared<HandlerList>();
                next->reserve(current->size() - 1);
                for (const auto &entry : *current)
                {
                    if (entry.id != id)
                    {
                        next->push_back(entry);
                    }
                }

                // Publish snapshot first, then the counter. An emit that loads a stale snapshot containing the removed
                // handler is still safe: the entry is tombstoned, so its liveness check rejects it.
                const size_t new_count = next->size();
                this->m_handlers.store(std::shared_ptr<const HandlerList>(std::move(next)), std::memory_order_release);
                this->m_handler_count.store(new_count, std::memory_order_release);
            }
            catch (...)
            {
                return;
            }
        }

        /**
         * @brief Surfaces an otherwise-silent rejection, best-effort.
         * @details Deliberately does not assert: a reentrant subscribe is a defined outcome the caller can test with
         *          active(), not a bug to abort on. The try/catch guards only the logger's first-use construction;
         *          try_log itself never throws.
         */
        static void report_reentrant_rejection(const char *op) noexcept
        {
            try
            {
                (void)log().try_log(
                    LogLevel::Debug,
                    "EventDispatcher: {} rejected -- called from within a handler on a same-type dispatcher "
                    "(per-instantiation reentrancy guard). Defer the mutation until the emit returns.",
                    op);
            }
            catch (...)
            {
            }
        }

        /// Surfaces an otherwise-silent rejection, best-effort. Same discipline as report_reentrant_rejection.
        static void report_closed_rejection() noexcept
        {
            try
            {
                (void)log().try_log(LogLevel::Debug,
                                    "EventDispatcher: subscribe rejected -- tombstone_and_wait has closed this "
                                    "dispatcher. The returned Subscription is inactive.");
            }
            catch (...)
            {
            }
        }

        /// Surfaces an otherwise-silent rejection, best-effort. Same discipline as report_reentrant_rejection.
        static void report_untracked_rejection() noexcept
        {
            try
            {
                (void)log().try_log(LogLevel::Debug,
                                    "EventDispatcher: subscribe rejected -- an emit frame could not be recorded, so "
                                    "same-type reentrancy cannot be ruled out. The returned Subscription is inactive.");
            }
            catch (...)
            {
            }
        }

        /// Surfaces an otherwise-silent rejection, best-effort. Same discipline as report_reentrant_rejection.
        static void report_empty_handler_rejection() noexcept
        {
            try
            {
                (void)log().try_log(LogLevel::Warning,
                                    "EventDispatcher: subscribe rejected an empty handler -- the returned Subscription "
                                    "is inactive. Pass a callable target.");
            }
            catch (...)
            {
            }
        }

        /**
         * @brief Surfaces an exception emit_safe() swallowed, best-effort.
         * @param what The std::exception::what() text, or nullptr for a non-std throw.
         */
        static void report_handler_exception(const char *what) noexcept
        {
            try
            {
                (void)log().try_log(LogLevel::Warning,
                                    "EventDispatcher: emit_safe swallowed a subscriber handler exception: {}",
                                    (what != nullptr && what[0] != '\0') ? what : "(non-std exception)");
            }
            catch (...)
            {
            }
        }

        /**
         * @brief Admits or refuses one handler invocation, and counts it for as long as it runs.
         * @details Enter, recheck, invoke, leave. The counter/recheck pair here and the tombstone/drain pair in
         *          Subscription::tombstone_and_wait() are a Dekker seam: both sides are seq_cst, so at least one of
         *          them observes the other. That is what makes "no invocation begins after a rundown returns
         *          Drained" hold without any lock on the emit path. A bare liveness check before the call would not:
         *          a tombstone landing between that check and the call would be missed entirely.
         *
         *          The count is released by the destructor, so a handler that throws out of emit() still leaves.
         */
        struct InvocationGuard
        {
            detail::EntryGate &gate;
            bool entered{false};

            explicit InvocationGuard(detail::EntryGate &gate_ref) noexcept : gate(gate_ref)
            {
                // Cheap pre-check: skips the locked increment for an entry that is already retired and merely
                // awaiting compaction. It is an optimization, never the guarantee.
                if (!gate.live.load(std::memory_order_acquire))
                {
                    return;
                }
                gate.in_flight.fetch_add(1, std::memory_order_seq_cst);
                if (!gate.live.load(std::memory_order_seq_cst))
                {
                    gate.in_flight.fetch_sub(1, std::memory_order_seq_cst);
                    return;
                }
                entered = true;
            }

            ~InvocationGuard() noexcept
            {
                if (entered)
                {
                    gate.in_flight.fetch_sub(1, std::memory_order_seq_cst);
                }
            }

            [[nodiscard]] bool admitted() const noexcept { return entered; }

            InvocationGuard(const InvocationGuard &) = delete;
            InvocationGuard &operator=(const InvocationGuard &) = delete;
            InvocationGuard(InvocationGuard &&) = delete;
            InvocationGuard &operator=(InvocationGuard &&) = delete;
        };

        /**
         * @brief RAII guard that records this dispatcher on the calling thread's emit chain.
         * @details The chain exists so a rundown can refuse to wait on its own thread, and so subscribe() can reject
         *          reentrancy. An emit whose frame cannot be recorded counts itself untracked instead, because a
         *          rundown that wrongly concludes this thread is elsewhere would wait on the very thread running it.
         */
        struct EmitGuard
        {
            detail::EmitFrame frame;
            bool tracked{false};

            explicit EmitGuard(const EventDispatcher &owner) noexcept
                : frame{&owner, &EventDispatcher::s_type_tag, nullptr}
            {
                tracked = detail::push_emit_frame(frame);
                if (!tracked)
                {
                    detail::untracked_emit_frames().fetch_add(1, std::memory_order_seq_cst);
                }
            }

            ~EmitGuard() noexcept
            {
                if (tracked)
                {
                    detail::pop_emit_frame(frame);
                }
                else
                {
                    detail::untracked_emit_frames().fetch_sub(1, std::memory_order_seq_cst);
                }
            }

            EmitGuard(const EmitGuard &) = delete;
            EmitGuard &operator=(const EmitGuard &) = delete;
            EmitGuard(EmitGuard &&) = delete;
            EmitGuard &operator=(EmitGuard &&) = delete;
        };

        // alignas(64) keeps the hot atomics on their own cache line so the writer mutex and shared_ptr control-block
        // traffic do not produce false sharing with readers doing the fast-path counter load.
        alignas(64) mutable std::atomic<SharedList> m_handlers;
        mutable std::atomic<size_t> m_handler_count{0};
        std::atomic<uint64_t> m_next_id{1};
        /**
         * @brief Set once by tombstone_and_wait, never cleared.
         * @details Read under m_writer_mutex by subscribe(), which is what closes the set the rundown drains.
         */
        std::atomic<bool> m_closed{false};
        mutable std::mutex m_writer_mutex; // serializes writers
        // Prevents Subscription::reset() from compacting a destroyed dispatcher.
        std::shared_ptr<void> m_alive;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_EVENT_DISPATCHER_HPP
