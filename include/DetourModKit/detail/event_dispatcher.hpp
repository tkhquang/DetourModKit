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
 * @details Provides a per-event-type pub/sub dispatcher. Subscribers receive events by const reference. Subscriptions
 *          are RAII objects that automatically unsubscribe on destruction.
 *
 *          **Threading model:**
 *          - `emit()` / `emit_safe()` avoid any `shared_mutex` / reader lock.
 *            The zero-subscriber fast path is wait-free: a single `memory_order_acquire` load of an atomic counter.
 *            When subscribers exist, an atomic acquire-load of a `std::shared_ptr<const std::vector<Entry>>` snapshot
 *            is performed, then the contiguous handler vector is iterated. `std::atomic<std::shared_ptr<T>>` is NOT
 *            lock-free on either shipped toolchain: libstdc++ (MinGW) and the MSVC STL both back it with an
 *            implementation-internal lock table / bit lock, so the snapshot load takes one bounded internal critical
 *            section rather than being lock-free. It still needs no reader lock of ours and no allocation, so it stays
 *            callback-safe; only the zero-subscriber fast path above is genuinely wait-free.
 *          - `subscribe()` / manual `unsubscribe()` serialize writers through
 *            a small `std::mutex` and publish a new immutable snapshot via copy-on-write. Mutation paths allocate; see
 *            the `subscribe()`, `unsubscribe()`, and `clear()` method docs for the OOM contract.
 *          - Safe to emit from multiple threads concurrently (e.g., hook callbacks).
 *          - Safe to subscribe/unsubscribe from any thread while the dispatcher is alive. The dispatcher must outlive
 *            every concurrent subscription operation; the Subscription weak_ptr guard only makes an unsubscribe safe
 *            after a happens-before ordered dispatcher destruction, not one racing on another thread. See the
 *            Subscription lifetime contract.
 *
 *          **Performance characteristics:**
 *          - `emit()`: atomic acquire-load of a `shared_ptr` snapshot, then
 *            linear iteration over the contiguous handler vector. No user-visible mutex acquisition on the hot path.
 *            When there are no subscribers, `emit()` skips the snapshot load entirely via the atomic counter (wait-free
 *            fast path).
 *          - `subscribe()` / `unsubscribe()`: copy-on-write. Each writer
 *            allocates a new handler vector (O(n) in the current subscriber count), appends or removes an entry, and
 *            publishes it atomically. Typical dispatcher usage is 1-10 subscribers and write-rarely, so the O(n)
 *            publish cost is negligible in practice.
 *          - No heap allocation on the ordinary no-deferral `emit()` path beyond the `shared_ptr` refcount bump.
 *            If a handler unsubscribes from the same dispatcher during emit, the guard may allocate a replacement
 *            snapshot while draining that deferred removal on unwind. Handler vector is cache-friendly.
 *
 *          **Usage:**
 *          @code
 *          struct PlayerStateChanged { float health; };
 *
 *          EventDispatcher<PlayerStateChanged> dispatcher;
 *
 *          // RAII subscription -- auto-unsubscribes when `sub` goes out of scope
 *          auto sub = dispatcher.subscribe([](const PlayerStateChanged& e) {
 *              logger.info("Health: {}", e.health);
 *          });
 *
 *          // Emit from a hook callback (no user-visible mutex on the read path, thread-safe)
 *          dispatcher.emit(PlayerStateChanged{.health = 75.0f});
 *          @endcode
 */

#include "DetourModKit/logger.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
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
     * @brief RAII subscription guard that unsubscribes on destruction.
     *
     * @details Move-only. When the guard is destroyed or reset, the associated handler is removed from the dispatcher.
     *
     *          **Lifetime contract (read before using across threads):** if the dispatcher was destroyed before this
     *          operation with a happens-before edge -- ordered teardown, e.g. the dispatcher's scope closed on this
     *          thread first, or another thread's `~EventDispatcher` synchronizes-with this reset() -- the unsubscribe
     *          is silently skipped: the weak_ptr is observed expired and reset() no-ops. That ordered case is the only
     *          lifetime overlap the weak_ptr guard covers. It does not make a Subscription operation safe against a
     *          dispatcher destroyed concurrently on another thread: reset() tests the weak_ptr and then, as a separate
     *          step, calls into the dispatcher, so a `~EventDispatcher` racing between those two steps is a
     *          use-after-free (the token is a distinct control block, so keeping it alive would not keep the dispatcher
     *          alive either). The caller must therefore ensure the dispatcher outlives every concurrent Subscription
     *          operation; the weak_ptr guard is an ordered-teardown convenience, not a substitute for that rule.
     */
    class Subscription
    {
    public:
        Subscription() noexcept = default;

        ~Subscription() noexcept { reset(); }

        Subscription(const Subscription &) = delete;
        Subscription &operator=(const Subscription &) = delete;

        Subscription(Subscription &&other) noexcept
            : m_alive(std::move(other.m_alive)), m_unsubscribe(std::move(other.m_unsubscribe))
        {
            other.m_unsubscribe = nullptr;
        }

        Subscription &operator=(Subscription &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                m_alive = std::move(other.m_alive);
                m_unsubscribe = std::move(other.m_unsubscribe);
                other.m_unsubscribe = nullptr;
            }
            return *this;
        }

        /**
         * @brief Manually unsubscribes. Safe to call multiple times.
         * @details If called from within a handler on the same dispatcher (that dispatcher's EmitGuard is on the
         *          current thread's stack), the removal is deferred rather than performed immediately: the dispatcher
         *          queues this subscription's id and completes the removal when this dispatcher's emit unwinds, so the
         *          handler will not fire on any subsequent emit. Rebuilding the published snapshot mid-emit would break
         *          the no-mutation-during-emit invariant the in-flight iteration relies on, which is why it is deferred
         *          and not done here. An unsubscribe for a different same-type dispatcher is removed immediately even
         *          when this thread is inside another dispatcher's handler, because that other dispatcher has no
         *          EmitGuard that could drain this one. The m_unsubscribe lambda is retained as a retry safety net: if
         *          the deferred drain cannot allocate a replacement snapshot, a later reset() outside the emit stack --
         *          including the Subscription destructor -- still completes the removal; once the drain has succeeded
         *          that retry is a harmless idempotent no-op. Because the lambda is retained, active() keeps reporting
         *          true until a reset() runs outside any emit, even though the entry itself is already gone after the
         *          drain.
         */
        void reset() noexcept
        {
            // The expired() check and the m_unsubscribe() call are two separate steps: this guards ordered teardown
            // (a dispatcher destroyed with a happens-before edge is observed expired here and skipped), not a
            // concurrent ~EventDispatcher on another thread, which could destroy the dispatcher between the check and
            // the call. The caller contract (see the class doc) is that the dispatcher outlives concurrent Subscription
            // operations; within that contract this ordering is safe.
            if (m_unsubscribe && !m_alive.expired())
            {
                if (!m_unsubscribe())
                {
                    return;
                }
            }
            m_unsubscribe = nullptr;
            m_alive.reset();
        }

        /// Returns true if this subscription is still active.
        [[nodiscard]] bool active() const noexcept { return m_unsubscribe != nullptr && !m_alive.expired(); }

    private:
        template <typename E> friend class EventDispatcher;

        Subscription(std::weak_ptr<void> alive, std::function<bool()> unsub) noexcept
            : m_alive(std::move(alive)), m_unsubscribe(std::move(unsub))
        {
        }

        std::weak_ptr<void> m_alive;
        std::function<bool()> m_unsubscribe;
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
     * - `emit()` / `emit_safe()`: the zero-subscriber fast path is wait-free
     *   (single atomic counter load). Otherwise acquires a `shared_ptr` snapshot of the immutable handler list and
     *   iterates it. `std::atomic<std::shared_ptr<T>>` is NOT lock-free on either shipped toolchain (libstdc++
     *   on MinGW and the MSVC STL both back it with an implementation-internal lock), so the snapshot load takes
     *   one bounded internal critical section rather than being lock-free. It takes no reader lock of ours and no
     *   allocation, so it stays callback-safe.
     * - `subscribe()` / `unsubscribe()`: copy-on-write under a small writer
     *   mutex. Each mutation allocates a new handler vector, appends or removes the entry, and publishes the new
     *   snapshot atomically. See the method docs for the OOM contract.
     * - Handlers are invoked while the snapshot's `shared_ptr` keeps the
     *   vector alive. A thread-local reentrancy guard rejects subscribe calls from within a same-type handler and
     *   defers unsubscribe calls only when this exact dispatcher is on the current thread's emit stack.
     *
     * **Reentrancy guard scope:** The guard is per-template-instantiation, not per-instance. Two dispatchers of the
     * same Event type share the same thread-local counter. Subscribing to a second dispatcher of the same type from
     * within a handler on the first will be rejected. Use distinct event types to avoid this (the typical usage
     * pattern).
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
            Handler callback;
        };

        struct EmitStackNode
        {
            const EventDispatcher *owner;
            EmitStackNode *previous;
        };

        using HandlerList = std::vector<Entry>;
        using SharedList = std::shared_ptr<const HandlerList>;

    public:
        EventDispatcher() : m_handlers(std::make_shared<const HandlerList>()), m_alive(std::make_shared<char>('\0')) {}

        ~EventDispatcher() noexcept = default;

        EventDispatcher(const EventDispatcher &) = delete;
        EventDispatcher &operator=(const EventDispatcher &) = delete;
        EventDispatcher(EventDispatcher &&) = delete;
        EventDispatcher &operator=(EventDispatcher &&) = delete;

        /**
         * @brief Subscribes a handler to this event type.
         * @param handler Callable invoked on each emit(). Must be safe to call from any thread.
         * @return RAII Subscription guard. The handler is removed when the guard is destroyed or reset().
         * @note Copy-on-write: allocates a new handler list of size N+1.
         *       Acceptable for the expected mutation rate (startup and occasional reconfiguration). Do not call from
         *       within a handler.
         */
        [[nodiscard]] Subscription subscribe(Handler handler)
        {
            if (emitting_depth() > 0)
            {
                // The reentrancy guard is per-template-instantiation, so a handler mutating a second dispatcher of the
                // same Event type is rejected here invisibly to the caller. Surface it best-effort (never throw, never
                // block) so the silent rejection is observable during development. assert fires the same condition in
                // debug builds.
                report_reentrant_rejection("subscribe");
                return {};
            }

            const auto id = static_cast<SubscriptionId>(this->m_next_id.fetch_add(1, std::memory_order_relaxed));

            {
                std::scoped_lock lock{this->m_writer_mutex};
                auto current = this->m_handlers.load(std::memory_order_acquire);
                auto next = std::make_shared<HandlerList>(*current);
                next->push_back(Entry{id, std::move(handler)});
                // Publish the new count first so a reader that sees 0 on the counter and skips the snapshot load cannot
                // miss a handler that has already been installed in the snapshot.
                this->m_handler_count.store(next->size(), std::memory_order_release);
                this->m_handlers.store(std::shared_ptr<const HandlerList>(std::move(next)), std::memory_order_release);
            }

            std::weak_ptr<void> weak = this->m_alive;
            return Subscription(std::move(weak), [this, id]() noexcept -> bool { return this->unsubscribe(id); });
        }

        /**
         * @brief Emits an event to all subscribers.
         * @param event The event payload, passed by const reference to each handler.
         * @note No user-visible mutex on the read path: performs one atomic acquire-load of the snapshot
         *       pointer and iterates. Multiple threads may emit concurrently without contention. Handlers are invoked
         *       synchronously in subscription order. Exceptions thrown by handlers propagate to the caller.
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
            EmitGuard guard{*this, emitting_depth()};
            for (const auto &entry : *snap)
            {
                entry.callback(event);
            }
        }

        /**
         * @brief Emits an event, catching and discarding handler exceptions.
         * @param event The event payload.
         * @note Same read-path semantics as emit() (no user-visible mutex). Handlers that throw are skipped; remaining
         *       handlers still execute. Prefer this over emit() when calling from hook callbacks or other contexts
         *       where an unhandled exception would crash the host process.
         */
        void emit_safe(const Event &event) const noexcept
        {
            if (this->m_handler_count.load(std::memory_order_acquire) == 0)
            {
                return;
            }

            // std::shared_ptr copy-construction and load are noexcept, so the entire function remains noexcept despite
            // the per-handler catch.
            SharedList snap = this->m_handlers.load(std::memory_order_acquire);
            EmitGuard guard{*this, emitting_depth()};
            for (const auto &entry : *snap)
            {
                try
                {
                    entry.callback(event);
                }
                catch (...)
                {
                }
            }
        }

        /// Returns the number of active subscribers.
        [[nodiscard]] size_t subscriber_count() const noexcept
        {
            return this->m_handler_count.load(std::memory_order_acquire);
        }

        /// Returns true if there are no subscribers.
        [[nodiscard]] bool empty() const noexcept { return this->m_handler_count.load(std::memory_order_acquire) == 0; }

        /**
         * @brief Removes all subscribers.
         * @note Serializes with other writers via the writer mutex; readers in flight keep their snapshot alive through
         *       their shared_ptr. Allocates a fresh empty snapshot. On allocation failure the dispatcher state is left
         *       unchanged (best-effort no-op) so the noexcept contract is never violated by a throwing allocator.
         */
        void clear() noexcept
        {
            std::scoped_lock lock{this->m_writer_mutex};
            // Build the replacement snapshot before touching any published state so a throwing allocator leaves
            // m_handlers / m_handler_count in their prior consistent pair. Swallowing bad_alloc keeps clear() a
            // noexcept best-effort teardown.
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

#if defined(DMK_EVENT_DISPATCHER_INTERNAL_TESTING)
        /**
         * @brief Test-only diagnostic: returns the number of outstanding references to the current handler snapshot,
         *        excluding the temporary this call itself creates. A value of 1 means the dispatcher's own atomic is
         *        the sole holder (steady state). A value >1 indicates an in-flight emit or a leaked snapshot reference.
         *        Enabled only when
         *        DMK_EVENT_DISPATCHER_INTERNAL_TESTING is defined by the test translation unit. Not part of the public
         *        API.
         */
        [[nodiscard]] long debug_snapshot_use_count() const noexcept
        {
            // load() returns a shared_ptr copy that bumps the refcount by 1 for its own lifetime; subtract that so the
            // reported count reflects only the other holders (the dispatcher atomic and any in-flight emit snapshots).
            auto snap = this->m_handlers.load(std::memory_order_acquire);
            return snap.use_count() - 1;
        }
#endif

    private:
        // Returns false when called from within a handler (reentrancy) or when the replacement snapshot could not be
        // allocated. The
        // Subscription::reset() caller retains its m_unsubscribe lambda on false returns and will retry on the next
        // reset() call (including the destructor). This is safe because the m_alive weak_ptr prevents calling into a
        // destroyed dispatcher, and on allocation failure the published state is left untouched so the retry observes
        // the same entry still present.
        //
        // Allocates (std::make_shared + vector growth). On OOM, leaves the dispatcher state unchanged and returns false
        // so the RAII retry path handles it naturally.
        bool unsubscribe(SubscriptionId id) noexcept
        {
            if (is_emitting_this_dispatcher())
            {
                // Deferred removal. A handler on this thread requested this unsubscribe mid-emit (directly, or via a
                // Subscription reset/destructor). Rebuilding the published snapshot now would break the
                // no-mutation-during-emit invariant the in-flight iteration relies on, so the id is queued and the
                // real removal runs when THIS dispatcher's emit unwinds (its own EmitGuard drains the queue).
                // If this exact dispatcher is not on the current thread's emit stack, the unsubscribe must run
                // immediately: a different same-type dispatcher has no guard that could drain this queue, and
                // stranding a destroyed owner's subscription until this dispatcher emits again would re-fire it once.
                // Returning false keeps the Subscription's m_unsubscribe lambda as a retry safety net: should the
                // deferred drain fail to allocate, a later out-of-emit reset()/destructor still completes the removal.
                // This is distinct from subscribe()'s hard reentrancy rejection, which cannot be deferred because it
                // must return a live Subscription synchronously.
                enqueue_pending_removal(id);
                return false;
            }

            std::scoped_lock lock{this->m_writer_mutex};
            auto current = this->m_handlers.load(std::memory_order_acquire);
            auto it =
                std::find_if(current->begin(), current->end(), [id](const Entry &entry) { return entry.id == id; });
            if (it == current->end())
            {
                // Not found; treat as successful (idempotent unsubscribe).
                return true;
            }

            // Build the replacement snapshot in full before touching any published state. A throwing allocator (reserve
            // / push_back / make_shared) must not leave m_handlers and m_handler_count out of sync, and noexcept
            // forbids propagation, so we catch bad_alloc and fall through to the false-return retry path.
            std::shared_ptr<HandlerList> next;
            try
            {
                next = std::make_shared<HandlerList>();
                next->reserve(current->size() - 1);
                for (const auto &entry : *current)
                {
                    if (entry.id != id)
                    {
                        next->push_back(entry);
                    }
                }
            }
            catch (...)
            {
                return false;
            }

            // Publish snapshot first, then the counter. An emit that loads a stale snapshot containing the removed
            // handler is still safe because the handler callable is retained by the old snapshot.
            this->m_handlers.store(std::shared_ptr<const HandlerList>(std::move(next)), std::memory_order_release);
            this->m_handler_count.store(current->size() - 1, std::memory_order_release);
            return true;
        }

        // Records an id whose removal was requested while this dispatcher is already emitting on the current thread,
        // for this dispatcher's own EmitGuard to drain on unwind. Duplicates are skipped so repeated in-handler
        // reset() calls on the same Subscription cannot grow the queue without bound. noexcept and best-effort: if the
        // push_back allocation fails the id is simply not queued here, and the Subscription's retained m_unsubscribe
        // lambda (unsubscribe returned false) still completes the removal after the emit unwinds.
        void enqueue_pending_removal(SubscriptionId id) noexcept
        {
            std::scoped_lock lock{this->m_writer_mutex};
            try
            {
                if (std::find(this->m_pending_removals.begin(), this->m_pending_removals.end(), id) ==
                    this->m_pending_removals.end())
                {
                    this->m_pending_removals.push_back(id);
                    // Publish that this instance has work for its next EmitGuard to drain. Set only on a successful
                    // push so an OOM here leaves the flag reflecting the unchanged queue; the Subscription's retained
                    // retry lambda then completes the removal out of emit. A duplicate id is a no-op with the flag
                    // already set by the first enqueue.
                    this->m_has_pending_removals.store(true, std::memory_order_release);
                }
            }
            catch (...)
            {
            }
        }

        // Completes the removals queued by unsubscribe() calls that occurred mid-emit on THIS dispatcher. Invoked from
        // this dispatcher's own EmitGuard as its emit() unwinds. It must drain the instance whose emit is unwinding,
        // not "the thread's outermost emit": emitting_depth() is shared across every same-type dispatcher on the
        // thread, so a depth==0 gate would drain whichever instance owns the outermost emit and strand a nested inner
        // instance's queued removals (re-fire, or a use-after-free if the handler destroyed its owner). Rebuilding the
        // snapshot here is safe even if another emit of this instance is still iterating higher on the stack, because
        // that iteration holds its own copy-on-write snapshot alive. Const because emit() is const; it mutates only the
        // mutable snapshot / count / queue / flag members, serialized against writers by the mutable writer mutex.
        // noexcept and best-effort: on allocation failure the queue and flag are left set so the next guard (or a
        // Subscription retry) completes the removal.
        void drain_pending_removals() const noexcept
        {
            std::scoped_lock lock{this->m_writer_mutex};
            if (this->m_pending_removals.empty())
            {
                // A concurrent drain on another thread may have emptied the queue after this guard observed the flag;
                // keep the flag consistent with the now-empty queue.
                this->m_has_pending_removals.store(false, std::memory_order_release);
                return;
            }

            auto current = this->m_handlers.load(std::memory_order_acquire);
            std::shared_ptr<HandlerList> next;
            try
            {
                next = std::make_shared<HandlerList>();
                next->reserve(current->size());
                for (const auto &entry : *current)
                {
                    const bool queued = std::find(this->m_pending_removals.begin(), this->m_pending_removals.end(),
                                                  entry.id) != this->m_pending_removals.end();
                    if (!queued)
                    {
                        next->push_back(entry);
                    }
                }
            }
            catch (...)
            {
                // Leave m_pending_removals and the flag set; retry on the next guard or a Subscription's lambda.
                return;
            }

            // Publish the snapshot before the counter, matching unsubscribe(): an emit that briefly loads the stale
            // snapshot (still holding a removed handler) stays safe because that handler is retained by the old
            // snapshot's shared_ptr.
            const size_t new_count = next->size();
            this->m_handlers.store(std::shared_ptr<const HandlerList>(std::move(next)), std::memory_order_release);
            this->m_handler_count.store(new_count, std::memory_order_release);
            this->m_pending_removals.clear();
            this->m_has_pending_removals.store(false, std::memory_order_release);
        }

        /**
         * @brief Best-effort report that the reentrancy guard rejected a subscribe() from within a handler.
         * @details Only subscribe() routes here. A subscribe cannot be deferred -- it must hand back a live
         *          Subscription synchronously -- so a subscribe requested from inside a handler on a same-type
         *          dispatcher is hard-rejected and reported here. (An unsubscribe requested mid-emit is NOT routed
         *          here: it is deferred and completed when that dispatcher's emit unwinds; see unsubscribe().) Emits a
         *          Debug log via log().try_log so the otherwise-silent per-instantiation rejection surfaces during
         *          development. The try/catch swallows try_log's own formatting and sink failures once the logger is
         *          available, so a routine logging hiccup never turns a rejected mutation into host termination. It
         *          cannot catch a first-use logger-construction failure: log() is noexcept, so an out-of-memory there
         *          terminates before try_log runs, an unrecoverable condition rather than this best-effort path's
         *          concern. Deliberately does NOT assert: a reentrant subscribe is a defined, observable outcome (the
         *          returned Subscription is inactive), not a bug to abort on. Zero-cost on the success path because it
         *          is only reached after the guard has already rejected the call.
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

        // Thread-local emit depth counter. This is per-template-instantiation (not per-instance) because making it
        // per-instance would require a thread_local map keyed by this pointer, adding a hash lookup to every emit() hot
        // path. The typical usage is one dispatcher per event type, so the shared counter is the correct tradeoff. See
        // the class-level doc for details.
        [[nodiscard]] int &emitting_depth() const noexcept
        {
            // Shared across all dispatcher instances on the same thread. The reentrancy guard is per-thread
            // (intentional), not per-dispatcher.
            thread_local int depth{0};
            return depth;
        }

        static EmitStackNode *&active_emit_stack() noexcept
        {
            thread_local EmitStackNode *head{nullptr};
            return head;
        }

        [[nodiscard]] bool is_emitting_this_dispatcher() const noexcept
        {
            for (const EmitStackNode *node = active_emit_stack(); node != nullptr; node = node->previous)
            {
                if (node->owner == this)
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief RAII guard that increments/decrements the emit depth counter and, on unwind, drains any
         *        unsubscribe()s that THIS dispatcher deferred while a handler was on the stack.
         */
        struct EmitGuard
        {
            const EventDispatcher &owner;
            int &depth;
            EmitStackNode node;
            EmitGuard(const EventDispatcher &owner_ref, int &depth_ref) noexcept
                : owner(owner_ref), depth(depth_ref), node{&owner_ref, EventDispatcher::active_emit_stack()}
            {
                EventDispatcher::active_emit_stack() = &node;
                ++depth;
            }
            ~EmitGuard() noexcept
            {
                EventDispatcher::active_emit_stack() = node.previous;
                --depth;
                // Each guard drains ITS OWN dispatcher's deferred removals -- not "the thread's outermost emit."
                // emitting_depth() is shared across every same-type dispatcher on the thread, so gating the drain on
                // depth==0 would drain whichever instance owns the outermost emit and strand a different instance's
                // queued removals when two same-type dispatchers nest emits on one thread (the handler then re-fires
                // on that instance's next emit -- a use-after-free if the handler destroyed its owner). `owner` is the
                // dispatcher whose emit() created this guard, so it is alive for the guard's whole lifetime and
                // draining it here is always safe. The atomic flag keeps the common no-deferral path lock-free (a
                // single acquire load); the writer mutex is taken only when a removal was actually queued on this
                // instance. drain_pending_removals is noexcept, so this stays safe even while unwinding a throwing
                // handler out of emit().
                if (owner.m_has_pending_removals.load(std::memory_order_acquire))
                {
                    owner.drain_pending_removals();
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
        // mutable: emit() is const, but its EmitGuard drains this dispatcher's deferred removals, which republishes
        // both the snapshot and this count. The drain is serialized against writers by the (also mutable) writer mutex.
        mutable std::atomic<size_t> m_handler_count{0};
        std::atomic<uint64_t> m_next_id{1};
        mutable std::mutex m_writer_mutex; // serializes writers and the const deferred-removal drain
        // Ids whose unsubscribe was requested from within a handler (emitting_depth > 0) and deferred until this
        // dispatcher's emit unwinds. Guarded by m_writer_mutex.
        mutable std::vector<SubscriptionId> m_pending_removals;
        // Fast-path flag: true iff m_pending_removals is non-empty. Lets an EmitGuard skip the writer-mutex drain
        // entirely on the common no-deferral emit (a single acquire load). Set/cleared under m_writer_mutex alongside
        // the queue so the two stay consistent; read without the lock by the guard on unwind.
        mutable std::atomic<bool> m_has_pending_removals{false};
        // Prevents Subscription::reset() from calling unsubscribe() after dispatcher destruction.
        std::shared_ptr<void> m_alive;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_EVENT_DISPATCHER_HPP
