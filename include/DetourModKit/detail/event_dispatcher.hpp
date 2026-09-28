#ifndef DETOURMODKIT_EVENT_DISPATCHER_HPP
#define DETOURMODKIT_EVENT_DISPATCHER_HPP

/**
 * @file event_dispatcher.hpp
 * @brief Typed event dispatcher with RAII subscription management.
 * @note Installed headers return EventDispatcher<T>&, so this detail/ header declares the type in the DetourModKit
 *       namespace. The directory reflects compile visibility, not privacy.
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
    /** @brief Opaque identifier of one subscription within its dispatcher. */
    enum class SubscriptionId : std::uint64_t
    {
    };

    /** @brief The outcome of a rundown that waits. */
    enum class Rundown : std::uint8_t
    {
        /**
         * @brief The handler is retired and no invocation of it runs, so its captures can be destroyed.
         * @note This is not a license to unload the handler's module. See @ref Subscription::tombstone_and_wait.
         */
        Drained,
        /**
         * @brief The handler is retired, but no wait ran, because the wait cannot be proven to end.
         * @details The calling thread is inside this dispatcher's emit, an untracked emit runs and can be on the
         *          calling thread, or the writer mutex lock failed. An invocation can still run, so keep its captures
         *          alive.
         */
        Unwaitable,
        /**
         * @brief This Subscription holds no handler: it is default-constructed, moved-from, or already reset.
         * @details A Subscription whose handler clear(), EventDispatcher::tombstone_and_wait, or ~EventDispatcher
         *          retired still holds its gate. It reports Drained or Unwaitable, not Inactive.
         */
        Inactive
    };
} // namespace DetourModKit

namespace DetourModKit::detail
{
    /**
     * @brief The rundown state of one subscription, shared by its Subscription and the published list.
     * @details The list that an emit loads, not InvocationGuard, keeps the gate alive for the whole emit iteration.
     */
    struct EntryGate
    {
        /// The rundown tombstone: false means no further invocation of this handler can begin.
        std::atomic<bool> live{true};
        /// Invocations that passed the tombstone recheck and did not return yet.
        std::atomic<std::uint32_t> in_flight{0};
    };

    /** @brief One frame of the calling thread's emit chain, stored on emit()'s stack. */
    struct EmitFrame
    {
        const void *dispatcher{nullptr};
        const void *type_tag{nullptr};
        EmitFrame *prev{nullptr};
        /// The TLS index this frame was pushed under, so the pop restores that index and no other.
        std::uint32_t tls_index{0xFFFFFFFFu};
    };

    /**
     * @brief Registers one owner of the emit chain's Win32 TLS index. The last owner to deregister returns the index.
     * @details subscribe() registers the dispatcher before its first handler publishes. Arbitrary host threads use a
     *          Win32 TLS index instead of thread_local ([B-86]). Without an index, every emit is untracked.
     *          Lifecycle.EmitTlsIndexReturnsWithTheLastSubscribedDispatcher proves the return.
     * @note Setup/control-plane only.
     */
    void acquire_emit_frame_owner() noexcept;

    /// Deregisters one owner that @ref acquire_emit_frame_owner registered.
    void release_emit_frame_owner() noexcept;

    /**
     * @brief Pushes @p frame onto the calling thread's emit chain.
     * @return false when the frame was not recorded. The caller must then count itself in @ref untracked_emit_frames.
     */
    [[nodiscard]] bool push_emit_frame(EmitFrame &frame) noexcept;

    /// Pops @p frame. If the matching @ref push_emit_frame returned false, do not call it.
    void pop_emit_frame(const EmitFrame &frame) noexcept;

    /// True when the calling thread is inside @p dispatcher's emit.
    [[nodiscard]] bool thread_is_emitting_dispatcher(const void *dispatcher) noexcept;

    /// True when the calling thread is inside the emit of any dispatcher that shares @p type_tag.
    [[nodiscard]] bool thread_is_emitting_type(const void *type_tag) noexcept;

    /**
     * @brief The count of untracked emits that still run. An untracked emit is one that did not record a frame.
     * @details The count is process-wide, because no chain walk can see an untracked emit. While it is nonzero,
     *          @ref drain_gate returns Unwaitable and subscribe() returns an inactive Subscription.
     */
    [[nodiscard]] std::atomic<std::uint32_t> &untracked_emit_frames() noexcept;

    /**
     * @brief Waits out the invocations committed before @p gate was tombstoned.
     * @param gate An already-tombstoned gate. On a live gate, a Drained result proves nothing.
     * @param dispatcher Compared against this thread's emit chain only. It is never dereferenced.
     * @return Drained once no invocation remains, or Unwaitable with no wait, as @ref Rundown::Unwaitable documents.
     */
    [[nodiscard]] Rundown drain_gate(EntryGate &gate, const void *dispatcher) noexcept;

    /** @brief Test-only accessor to EventDispatcher privates. Only the dispatcher tests define it. */
    template <typename Event> struct EventDispatcherTestAccess;

    /** @brief Returns the emit-chain TLS ownership of the never-destroyed diagnostics dispatchers at teardown. */
    struct DiagnosticsEmitOwner;
} // namespace DetourModKit::detail

namespace DetourModKit
{
    /**
     * @brief RAII guard that retires its handler when destroyed or reset.
     * @warning The dispatcher must outlive every concurrent Subscription operation. A `~EventDispatcher` that races one
     *          on another thread is a use-after-free. The weak_ptr guard covers only ordered teardown ([B-70]): after a
     *          dispatcher destruction that happens-before the operation, the operation skips compaction.
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
         * @brief Retires the handler. It does not wait and does not reclaim its list slot.
         * @details After this call, no emit on any thread can begin an invocation it did not already commit to. This
         *          includes an emit nested inside the handler that calls this. The call cannot allocate, block, or
         *          fail.
         * @note Callback-safe. Idempotent. If an invocation can already run, call @ref tombstone_and_wait before the
         *       handler's captures go away.
         */
        void tombstone() noexcept
        {
            if (m_gate)
            {
                m_gate->live.store(false, std::memory_order_seq_cst);
            }
        }

        /**
         * @brief Retires the handler, then reclaims its list slot best-effort.
         * @details The @ref tombstone runs first, so the removal is synchronous and cannot fail. The slot reclaim
         *          takes the writer mutex and allocates. If the dispatcher was destroyed first, reset() skips the
         *          reclaim. If the reclaim fails, one retired entry stays in the list, and every later emit rejects it.
         * @warning This does not wait. An invocation already past the liveness check can still run on another thread.
         *          It is not callback-safe, because the reclaim can block on the writer mutex. For a non-blocking
         *          removal, use @ref tombstone.
         */
        void reset() noexcept
        {
            tombstone();
            compact_and_release();
        }

        /**
         * @brief Retires the handler and waits until no invocation of it runs.
         * @return Drained, Unwaitable, or Inactive, as @ref Rundown documents.
         * @note Setup/control-plane only. On Drained and on Unwaitable, it then reclaims the list slot as @ref reset
         *       does. Afterward, the Subscription holds no handler.
         * @note Drained is not a license to unload the handler's module. An emit that still iterates on another thread
         *       owns the handler's std::function and later runs its destructor. Module unload needs the loader-grade
         *       quiescence of a teardown host.
         * @warning The wait has no timeout. A handler that does not return hangs this call.
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

        Subscription(
            std::weak_ptr<void> alive,
            std::shared_ptr<detail::EntryGate> gate,
            const void *dispatcher,
            std::function<void()> compact
        ) noexcept
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
        /// Compared against the emit chain to refuse a self-wait. Never dereferenced.
        const void *m_dispatcher{nullptr};
        std::function<void()> m_compact;
    };

    /**
     * @brief Thread-safe typed event dispatcher with RAII subscription management.
     *
     * **Thread safety:**
     * - `emit()` / `emit_safe()`: no DMK lock and no allocation to dispatch, except as emit_safe() documents. The list
     *   load takes the bounded internal lock of `std::atomic<std::shared_ptr>`. A thread's first emit can make
     *   TlsSetValue allocate a TLS expansion array. If that fails, the emit runs untracked.
     * - `subscribe()` / `clear()`: copy-on-write under a writer mutex. Consumer callables stay outside it ([B-101]).
     *
     * **Reentrancy:** a subscribe() from a handler on any dispatcher of the same Event type returns an inactive
     * Subscription. A handler on `EventDispatcher<A>` can subscribe to `EventDispatcher<B>`. While an untracked emit
     * runs, every subscribe() returns an inactive Subscription.
     *
     * **Ordering:** subscribe() release-stores the list and the handler count. A thread that observes the returned
     * Subscription, or synchronizes with such a thread, sees the handler in later emits. Without that happens-before
     * edge, a concurrent emit can miss a new handler.
     */
    template <typename Event> class EventDispatcher
    {
    public:
        /// Handler function signature: receives the event by const reference.
        using Handler = std::function<void(const Event &)>;

    private:
        // These types come before the public members that name them.
        struct Entry
        {
            SubscriptionId id;
            std::shared_ptr<detail::EntryGate> gate;
            Handler callback;
        };

        // EntryNode enforces the callable ownership and lock boundary in [B-101] (proof: DispatchCow.*).
        using EntryNode = std::shared_ptr<const Entry>;

        /**
         * @brief One published handler list.
         * @details Every list that one dispatcher publishes shares one epoch, so `epoch.use_count()` counts the live
         *          lists. The epoch member comes first, so a superseded list drops its epoch reference only after it
         *          destroys its entries and their callables.
         */
        struct HandlerList
        {
            HandlerList(std::shared_ptr<const char> list_epoch, std::vector<EntryNode> list_entries) noexcept
                : epoch(std::move(list_epoch)), entries(std::move(list_entries))
            {
            }

            std::shared_ptr<const char> epoch;
            std::vector<EntryNode> entries;
        };
        using SharedList = std::shared_ptr<const HandlerList>;

        /** @brief The emit-chain key of this Event type: one object per instantiation, identified by its address. */
        inline static const char s_type_tag{};

    public:
        EventDispatcher()
            : m_handlers(
                  std::make_shared<const HandlerList>(std::make_shared<const char>('\0'), std::vector<EntryNode>{})
              ),
              m_alive(std::make_shared<char>('\0'))
        {
        }

        /**
         * @brief Retires every handler, so a Subscription that outlives the dispatcher reads its handler as retired.
         * @details Takes no DMK lock and allocates nothing. A subscribe() that races this is a caller lifetime
         *          violation. A dispatcher that holds an emit-chain TLS ownership returns it here.
         * @warning This does not wait. Destruction while a handler runs is a caller lifetime violation. If that is
         *          possible, call tombstone_and_wait() first.
         */
        ~EventDispatcher() noexcept
        {
            auto current = this->m_handlers.load(std::memory_order_acquire);
            for (const auto &entry : current->entries)
            {
                entry->gate->live.store(false, std::memory_order_seq_cst);
            }
            if (this->m_emit_owner)
            {
                detail::release_emit_frame_owner();
            }
        }

        EventDispatcher(const EventDispatcher &) = delete;
        EventDispatcher &operator=(const EventDispatcher &) = delete;
        EventDispatcher(EventDispatcher &&) = delete;
        EventDispatcher &operator=(EventDispatcher &&) = delete;

        /**
         * @brief Subscribes a handler to this event type.
         * @param handler Invoked on each emit(). It must be safe to call from any thread.
         * @return The Subscription guard, or an inactive guard (active() == false) with no throw. The inactive cases
         *         are an empty handler, a call from a same-type handler, an untracked emit, and a dispatcher that
         *         tombstone_and_wait closed. If any case is possible, test active().
         * @throws std::bad_alloc if an allocation fails.
         * @throws std::system_error if the writer mutex lock fails. After either throw, the call installs nothing.
         * @note Setup/control-plane only. It allocates the entry node and a new list of N+1 entries. It also
         *       registers this dispatcher as an emit-chain TLS owner, so emit() only reads the index.
         */
        [[nodiscard]] Subscription subscribe(Handler handler)
        {
            if (!handler)
            {
                // Reject here. An empty handler in the list throws bad_function_call from an unrelated emit.
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

            // Register outside the writer mutex. The first publish keeps it, and every other exit returns it.
            EmitOwnerRegistration registration;

            const auto id = static_cast<SubscriptionId>(this->m_next_id.fetch_add(1, std::memory_order_relaxed));

            auto gate = std::make_shared<detail::EntryGate>();
            // Build it before the publish, so a throw cannot leave a live handler that no Subscription can retire.
            std::function<void()> compact_fn = [this, id]() noexcept { this->compact(id); };
            // Build the node before the lock, because it can run consumer move or copy code.
            EntryNode node = std::make_shared<const Entry>(Entry{id, gate, std::move(handler)});
            // This list outlives the lock, so any callable destruction through it runs after the unlock.
            SharedList superseded;
            {
                std::scoped_lock lock{this->m_writer_mutex};
                if (this->m_closed.load(std::memory_order_seq_cst))
                {
                    // Test under the mutex, so no handler can publish behind a completed tombstone_and_wait drain.
                    report_closed_rejection();
                    return {};
                }
                superseded = this->m_handlers.load(std::memory_order_acquire);
                auto next = std::make_shared<HandlerList>(*superseded);
                next->entries.push_back(std::move(node));
                if (!this->m_emit_owner)
                {
                    this->m_emit_owner = true;
                    registration.held = false;
                }
                // Store the count first, so a reader that reads 0 and skips the load misses no installed handler.
                this->m_handler_count.store(next->entries.size(), std::memory_order_release);
                this->m_handlers.store(std::shared_ptr<const HandlerList>(std::move(next)), std::memory_order_release);
            }

            return Subscription(std::weak_ptr<void>(this->m_alive), std::move(gate), this, std::move(compact_fn));
        }

        /**
         * @brief Emits an event to each live handler, synchronously and in subscription order.
         * @note A handler exception propagates to the caller.
         * @warning A handler exception with no catch frame above the call site terminates the process. In a hook
         *          callback, or any context where an unhandled exception crashes the host, use emit_safe().
         */
        void emit(const Event &event) const
        {
            // Fast path: with no published slot, skip the list load.
            if (this->m_handler_count.load(std::memory_order_acquire) == 0)
            {
                return;
            }

            SharedList snap = this->m_handlers.load(std::memory_order_acquire);
            EmitGuard guard{*this};
            for (const auto &entry : snap->entries)
            {
                InvocationGuard invocation{*entry->gate};
                if (!invocation.admitted())
                {
                    continue;
                }
                entry->callback(event);
            }
        }

        /**
         * @brief Emits like emit(), but catches and logs each handler exception, then continues with the next handler.
         * @note Best-effort. The log call for a caught exception can allocate.
         */
        void emit_safe(const Event &event) const noexcept
        {
            if (this->m_handler_count.load(std::memory_order_acquire) == 0)
            {
                return;
            }

            SharedList snap = this->m_handlers.load(std::memory_order_acquire);
            EmitGuard guard{*this};
            for (const auto &entry : snap->entries)
            {
                InvocationGuard invocation{*entry->gate};
                if (!invocation.admitted())
                {
                    continue;
                }
                try
                {
                    entry->callback(event);
                }
                catch (const std::exception &ex)
                {
                    // Report the swallow with its text. A silent swallow hides a handler bug.
                    report_handler_exception(ex.what());
                }
                catch (...)
                {
                    // A non-std throw carries no portable message.
                    report_handler_exception(nullptr);
                }
            }
        }

        /** @brief Returns the published slot count. A retired slot counts until compaction removes it. */
        [[nodiscard]] size_t subscriber_count() const noexcept
        {
            return this->m_handler_count.load(std::memory_order_acquire);
        }

        /// Returns true if there is no published slot.
        [[nodiscard]] bool empty() const noexcept { return this->m_handler_count.load(std::memory_order_acquire) == 0; }

        /**
         * @brief Retires every handler before this call returns.
         * @note Setup/control-plane only. It takes the writer mutex. If the empty-list publish fails, the retired
         *       entries stay until a later mutation reclaims them. This does not wait for a handler that still runs.
         *       To wait, call @ref tombstone_and_wait instead of clear().
         */
        void clear() noexcept
        {
            // This list outlives the lock, so any callable destruction through it runs after the unlock.
            SharedList superseded;
            try
            {
                std::scoped_lock lock{this->m_writer_mutex};
                // Retire first, so an allocation failure below cannot leave a live handler behind.
                superseded = this->m_handlers.load(std::memory_order_acquire);
                for (const auto &entry : superseded->entries)
                {
                    entry->gate->live.store(false, std::memory_order_seq_cst);
                }

                std::shared_ptr<const HandlerList> empty_snap;
                try
                {
                    empty_snap = std::make_shared<const HandlerList>(superseded->epoch, std::vector<EntryNode>{});
                }
                catch (...)
                {
                    return;
                }
                // Zero the counter before the empty-list publish, so an emit that reads 0 cannot see the old list.
                this->m_handler_count.store(0, std::memory_order_release);
                this->m_handlers.store(std::move(empty_snap), std::memory_order_release);
            }
            catch (...)
            {
                // A lock failure must not escape. Retire the visible list. A concurrent unordered subscribe can still
                // publish after it.
                auto current = this->m_handlers.load(std::memory_order_acquire);
                for (const auto &entry : current->entries)
                {
                    entry->gate->live.store(false, std::memory_order_seq_cst);
                }
                return;
            }
        }

        /**
         * @brief Retires every handler, then waits until no handler in the published list runs.
         * @return Drained or Unwaitable, as @ref Rundown documents.
         * @details This closes the dispatcher permanently: every later subscribe() returns an inactive Subscription.
         *          The list excludes a handler whose slot clear() or its Subscription already reclaimed, so no wait
         *          covers it. After the drain, it runs @ref clear. If the writer mutex lock fails, it retires only the
         *          visible list and returns Unwaitable with no wait and no clear.
         * @note Setup/control-plane only.
         * @warning The wait has no timeout, as @ref Subscription::tombstone_and_wait documents.
         */
        [[nodiscard]] Rundown tombstone_and_wait() noexcept
        {
            // Close before the list load. subscribe() tests the flag under the writer mutex, so the list below is
            // complete. The drain then runs without the mutex, because a handler can call subscribe().
            this->m_closed.store(true, std::memory_order_seq_cst);

            SharedList snap;
            try
            {
                std::scoped_lock lock{this->m_writer_mutex};
                snap = this->m_handlers.load(std::memory_order_acquire);
                for (const auto &entry : snap->entries)
                {
                    entry->gate->live.store(false, std::memory_order_seq_cst);
                }
            }
            catch (...)
            {
                snap = this->m_handlers.load(std::memory_order_acquire);
                for (const auto &entry : snap->entries)
                {
                    entry->gate->live.store(false, std::memory_order_seq_cst);
                }
                return Rundown::Unwaitable;
            }

            Rundown result = Rundown::Drained;
            for (const auto &entry : snap->entries)
            {
                if (drain_gate(*entry->gate, this) == Rundown::Unwaitable)
                {
                    result = Rundown::Unwaitable;
                }
            }
            clear();
            return result;
        }

    private:
        // Unconditional friends keep this installed definition token-stable under every build macro.
        friend struct detail::EventDispatcherTestAccess<Event>;
        friend struct detail::DiagnosticsEmitOwner;

        /// The outcome of @ref release_idle_emit_owner.
        enum class EmitOwnerRelease : std::uint8_t
        {
            /// This dispatcher returned its emit-chain TLS ownership.
            Released,
            /// This dispatcher holds no ownership.
            NotOwner,
            /// A live entry keeps the ownership.
            LiveSubscription,
            /// A writer or an emit holds a list. A later call can succeed.
            Busy,
            /// As Busy, but the calling thread can be the holder, so a wait on it cannot end.
            Unwaitable
        };

        /**
         * @brief Returns this dispatcher's emit-chain TLS ownership when no emit can still run a handler.
         * @param may_prune True to publish an empty list over retired entries before the return. A loader-lock caller
         *                  passes false, because the prune allocates and destroys consumer callables.
         * @details Never waits for the writer mutex. Idle means no live entry, no admitted invocation in the current
         *          list, and no emit that holds any list. A later subscribe that publishes a handler registers again.
         */
        [[nodiscard]] EmitOwnerRelease release_idle_emit_owner(bool may_prune) noexcept
        {
            // This list outlives the lock, so any callable destruction through it runs after the unlock.
            SharedList current;
            std::unique_lock lock{this->m_writer_mutex, std::try_to_lock};
            if (!lock.owns_lock())
            {
                return EmitOwnerRelease::Busy;
            }
            if (!this->m_emit_owner)
            {
                return EmitOwnerRelease::NotOwner;
            }
            current = this->m_handlers.load(std::memory_order_acquire);
            bool admitted = false;
            for (const auto &entry : current->entries)
            {
                if (entry->gate->live.load(std::memory_order_seq_cst))
                {
                    return EmitOwnerRelease::LiveSubscription;
                }
                admitted = admitted || entry->gate->in_flight.load(std::memory_order_seq_cst) != 0;
            }
            // The in-flight read pairs with InvocationGuard's recheck, as the drain does. Every list copy runs under
            // the writer mutex, so an epoch count of one proves that no superseded list survives. The atomic and
            // `current` are then the only expected holders of the current list.
            if (admitted || current.use_count() != 2 || current->epoch.use_count() != 1)
            {
                return detail::thread_is_emitting_dispatcher(this) ||
                               detail::untracked_emit_frames().load(std::memory_order_seq_cst) != 0
                           ? EmitOwnerRelease::Unwaitable
                           : EmitOwnerRelease::Busy;
            }
            // Pairs with the release decrement of the last holder, so its frame pop precedes the TlsFree below.
            std::atomic_thread_fence(std::memory_order_acquire);
            if (may_prune && !current->entries.empty())
            {
                SharedList empty;
                try
                {
                    empty = std::make_shared<const HandlerList>(current->epoch, std::vector<EntryNode>{});
                }
                catch (...)
                {
                    return EmitOwnerRelease::Busy;
                }
                this->m_handler_count.store(0, std::memory_order_release);
                this->m_handlers.store(std::move(empty), std::memory_order_release);
            }
            this->m_emit_owner = false;
            detail::release_emit_frame_owner();
            return EmitOwnerRelease::Released;
        }

        /**
         * @brief Reclaims the list slot of an already-retired entry.
         * @details An allocation failure leaves the retired entry in place. A concurrent emit keeps its own list, so
         *          this is safe while an emit iterates.
         */
        void compact(SubscriptionId id) noexcept
        {
            // This list outlives the lock, so any callable destruction through it runs after the unlock.
            SharedList superseded;
            try
            {
                std::scoped_lock lock{this->m_writer_mutex};
                superseded = this->m_handlers.load(std::memory_order_acquire);
                auto it = std::find_if(
                    superseded->entries.begin(),
                    superseded->entries.end(),
                    [id](const EntryNode &entry) { return entry->id == id; }
                );
                if (it == superseded->entries.end())
                {
                    return;
                }

                auto next = std::make_shared<HandlerList>(superseded->epoch, std::vector<EntryNode>{});
                next->entries.reserve(superseded->entries.size() - 1);
                for (const auto &entry : superseded->entries)
                {
                    if (entry->id != id)
                    {
                        next->entries.push_back(entry);
                    }
                }

                // Store the list first, then the counter. The gate rejects the removed entry in a stale list.
                const size_t new_count = next->entries.size();
                this->m_handlers.store(std::shared_ptr<const HandlerList>(std::move(next)), std::memory_order_release);
                this->m_handler_count.store(new_count, std::memory_order_release);
            }
            catch (...)
            {
                return;
            }
        }

        /** @brief Surfaces an otherwise-silent rejection, best-effort. The caller tests the outcome with active(). */
        static void report_reentrant_rejection(const char *op) noexcept
        {
            try
            {
                (void)log().try_log(
                    LogLevel::Debug,
                    "EventDispatcher: {} rejected: the call came from within a handler on a same-type dispatcher "
                    "(per-instantiation reentrancy guard). Defer the mutation until the emit returns.",
                    op
                );
            }
            catch (...)
            {
            }
        }

        /// Surfaces an otherwise-silent rejection, best-effort.
        static void report_closed_rejection() noexcept
        {
            try
            {
                (void)log().try_log(
                    LogLevel::Debug,
                    "EventDispatcher: subscribe rejected: tombstone_and_wait closed this "
                    "dispatcher. The returned Subscription is inactive."
                );
            }
            catch (...)
            {
            }
        }

        /// Surfaces an otherwise-silent rejection, best-effort.
        static void report_untracked_rejection() noexcept
        {
            try
            {
                (void)log().try_log(
                    LogLevel::Debug,
                    "EventDispatcher: subscribe rejected: an emit did not record its frame, so the dispatcher "
                    "cannot rule out same-type reentrancy. The returned Subscription is inactive."
                );
            }
            catch (...)
            {
            }
        }

        /// Surfaces an otherwise-silent rejection, best-effort.
        static void report_empty_handler_rejection() noexcept
        {
            try
            {
                (void)log().try_log(
                    LogLevel::Warning,
                    "EventDispatcher: subscribe rejected an empty handler. The returned Subscription "
                    "is inactive. Pass a callable target."
                );
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
                (void)log().try_log(
                    LogLevel::Warning,
                    "EventDispatcher: emit_safe swallowed a subscriber handler exception: {}",
                    (what != nullptr && what[0] != '\0') ? what : "(non-std exception)"
                );
            }
            catch (...)
            {
            }
        }

        /**
         * @brief Admits or refuses one handler invocation, and counts it while it runs.
         * @details The increment and recheck here, the tombstone store, and the @ref detail::drain_gate load are all
         *          seq_cst, so at least one side observes the other. No invocation can begin after a rundown returns
         *          Drained. The destructor releases the count, so a handler that throws out of emit() still leaves.
         */
        struct InvocationGuard
        {
            detail::EntryGate &gate;
            bool entered{false};

            explicit InvocationGuard(detail::EntryGate &gate_ref) noexcept : gate(gate_ref)
            {
                // This pre-check skips a retired entry. It is only an optimization. The recheck below is the guarantee.
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

        /** @brief Records this dispatcher on the calling thread's emit chain, or counts the emit as untracked. */
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

        /// One emit-chain TLS ownership that subscribe() returns unless the dispatcher keeps it.
        struct EmitOwnerRegistration
        {
            bool held{true};

            EmitOwnerRegistration() noexcept { detail::acquire_emit_frame_owner(); }

            ~EmitOwnerRegistration() noexcept
            {
                if (held)
                {
                    detail::release_emit_frame_owner();
                }
            }

            EmitOwnerRegistration(const EmitOwnerRegistration &) = delete;
            EmitOwnerRegistration &operator=(const EmitOwnerRegistration &) = delete;
            EmitOwnerRegistration(EmitOwnerRegistration &&) = delete;
            EmitOwnerRegistration &operator=(EmitOwnerRegistration &&) = delete;
        };

        // alignas(64) starts the hot atomics on a cache-line boundary. The writer mutex still shares that line.
        alignas(64) mutable std::atomic<SharedList> m_handlers;
        mutable std::atomic<size_t> m_handler_count{0};
        std::atomic<uint64_t> m_next_id{1};
        /** @brief Set once by tombstone_and_wait and never cleared. subscribe() reads it under m_writer_mutex. */
        std::atomic<bool> m_closed{false};
        /// True from the publish that kept an emit-chain TLS ownership until its return. Written under m_writer_mutex.
        bool m_emit_owner{false};
        mutable std::mutex m_writer_mutex;
        // Each Subscription holds a weak_ptr to this. Once it expires, the Subscription skips its compaction.
        std::shared_ptr<void> m_alive;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_EVENT_DISPATCHER_HPP
