#ifndef DETOURMODKIT_EVENT_DISPATCHER_HPP
#define DETOURMODKIT_EVENT_DISPATCHER_HPP

/**
 * @file event_dispatcher.hpp
 * @brief Typed event dispatcher with RAII subscription management.
 *
 * @details Provides a per-event-type pub/sub dispatcher. Subscribers receive
 *          events by const reference. Subscriptions are RAII objects that
 *          automatically unsubscribe on destruction.
 *
 *          **Threading model:**
 *          - `emit()` / `emit_safe()` are lock-free on the hot path: they
 *            acquire-load a `std::shared_ptr<const std::vector<Entry>>`
 *            snapshot and iterate it. Concurrent emits never contend.
 *          - `subscribe()` / manual `unsubscribe()` serialize writers through
 *            a small `std::mutex` and publish a new immutable snapshot via
 *            copy-on-write.
 *          - Safe to emit from multiple threads concurrently (e.g., hook callbacks).
 *          - Safe to subscribe/unsubscribe from any thread.
 *
 *          **Performance characteristics:**
 *          - `emit()`: atomic acquire-load of a `shared_ptr` snapshot, then
 *            linear iteration over the contiguous handler vector. No mutex
 *            acquisition on the hot path. When there are no subscribers,
 *            `emit()` skips the snapshot load entirely via an atomic counter.
 *          - `subscribe()` / `unsubscribe()`: copy-on-write. Each writer
 *            allocates a new handler vector (O(n) in the current subscriber
 *            count), appends or removes an entry, and publishes it atomically.
 *            Typical dispatcher usage is 1-10 subscribers and write-rarely,
 *            so the O(n) publish cost is negligible in practice.
 *          - No heap allocation on `emit()` beyond the `shared_ptr` refcount
 *            bump. Handler vector is cache-friendly.
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
 *          // Emit from a hook callback (lock-free, thread-safe)
 *          dispatcher.emit(PlayerStateChanged{.health = 75.0f});
 *          @endcode
 */

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
     * @details Move-only. When the guard is destroyed or reset, the associated
     *          handler is removed from the dispatcher. If the dispatcher has
     *          already been destroyed, the unsubscribe is silently skipped
     *          (weak_ptr safety).
     */
    class Subscription
    {
    public:
        Subscription() noexcept = default;

        ~Subscription() noexcept
        {
            reset();
        }

        Subscription(const Subscription &) = delete;
        Subscription &operator=(const Subscription &) = delete;

        Subscription(Subscription &&other) noexcept
            : alive_(std::move(other.alive_)),
              unsubscribe_(std::move(other.unsubscribe_))
        {
            other.unsubscribe_ = nullptr;
        }

        Subscription &operator=(Subscription &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                alive_ = std::move(other.alive_);
                unsubscribe_ = std::move(other.unsubscribe_);
                other.unsubscribe_ = nullptr;
            }
            return *this;
        }

        /**
         * @brief Manually unsubscribes. Safe to call multiple times.
         * @details If called from within a handler on the same dispatcher
         *          (i.e. emitting_depth > 0 on this thread), the unsubscribe
         *          is silently skipped and the subscription remains active.
         *          The unsubscribe_ lambda is retained so that a subsequent
         *          reset() call outside the emit stack -- including the
         *          Subscription destructor -- will complete the removal.
         *          If the Subscription is also destroyed inside the same
         *          handler scope, the destructor's reset() is likewise
         *          skipped because emitting_depth is still positive.
         *          This keeps the no-mutation-during-emit invariant intact
         *          so the in-flight snapshot iteration remains consistent.
         */
        void reset() noexcept
        {
            if (unsubscribe_ && !alive_.expired())
            {
                if (!unsubscribe_())
                {
                    return;
                }
            }
            unsubscribe_ = nullptr;
            alive_.reset();
        }

        /// Returns true if this subscription is still active.
        [[nodiscard]] bool active() const noexcept
        {
            return unsubscribe_ != nullptr && !alive_.expired();
        }

    private:
        template <typename E>
        friend class EventDispatcher;

        Subscription(std::weak_ptr<void> alive, std::function<bool()> unsub) noexcept
            : alive_(std::move(alive)), unsubscribe_(std::move(unsub))
        {
        }

        std::weak_ptr<void> alive_;
        std::function<bool()> unsubscribe_;
    };

    /**
     * @brief Thread-safe typed event dispatcher with RAII subscription management.
     *
     * @tparam Event The event type. Must be copyable or movable. Handlers receive
     *               events by const reference.
     *
     * @details Each EventDispatcher manages a single event type. For multiple event
     *          types, compose multiple dispatchers:
     *          @code
     *          struct MyEvents {
     *              EventDispatcher<PlayerStateChanged> player_state;
     *              EventDispatcher<CameraUpdated> camera;
     *              EventDispatcher<ConfigReloaded> config;
     *          };
     *          @endcode
     *
     * **Thread safety:**
     * - `emit()` / `emit_safe()`: lock-free. Acquires a `shared_ptr` snapshot
     *   of the immutable handler list and iterates it.
     * - `subscribe()` / `unsubscribe()`: copy-on-write under a small writer
     *   mutex. Each mutation allocates a new handler vector, appends or
     *   removes the entry, and publishes the new snapshot atomically.
     * - Handlers are invoked while the snapshot's `shared_ptr` keeps the
     *   vector alive. A thread-local reentrancy guard detects and rejects
     *   subscribe/unsubscribe calls from within a handler; the guard is what
     *   guarantees the user's "do not mutate during emit" invariant, not the
     *   snapshot mechanism.
     *
     * **Reentrancy guard scope:** The guard is per-template-instantiation,
     * not per-instance. Two dispatchers of the same Event type share the
     * same thread-local counter. Subscribing to a second dispatcher of
     * the same type from within a handler on the first will be rejected.
     * Use distinct event types to avoid this (the typical usage pattern).
     *
     * **Subscribe/emit ordering invariant:** A subscribe() performs a
     * release-store on both the snapshot pointer and the atomic handler
     * count. Any thread that observes the Subscription object returned
     * from subscribe() (or synchronizes-with the thread that did) will
     * see the subscription in subsequent emits. Without such a
     * happens-before edge, a concurrent emit may or may not observe a
     * freshly-published handler -- this matches the user's own ordering.
     */
    template <typename Event>
    class EventDispatcher
    {
    public:
        /// Handler function signature: receives the event by const reference.
        using Handler = std::function<void(const Event &)>;

    private:
        // Private type aliases surfaced here so they are visible to the
        // public API's member declarations and constructor below.
        struct Entry
        {
            SubscriptionId id;
            Handler callback;
        };

        using HandlerList = std::vector<Entry>;
        using SharedList = std::shared_ptr<const HandlerList>;

    public:
        EventDispatcher()
            : handlers_(std::make_shared<const HandlerList>()),
              alive_(std::make_shared<char>('\0'))
        {
        }

        ~EventDispatcher() noexcept = default;

        EventDispatcher(const EventDispatcher &) = delete;
        EventDispatcher &operator=(const EventDispatcher &) = delete;
        EventDispatcher(EventDispatcher &&) = delete;
        EventDispatcher &operator=(EventDispatcher &&) = delete;

        /**
         * @brief Subscribes a handler to this event type.
         * @param handler Callable invoked on each emit(). Must be safe to call
         *                from any thread.
         * @return RAII Subscription guard. The handler is removed when the guard
         *         is destroyed or reset().
         * @note Copy-on-write: allocates a new handler list of size N+1.
         *       Acceptable for the expected mutation rate (startup and
         *       occasional reconfiguration). Do not call from within a handler.
         */
        [[nodiscard]] Subscription subscribe(Handler handler)
        {
            if (emitting_depth() > 0)
            {
                return {};
            }

            const auto id = static_cast<SubscriptionId>(
                this->next_id_.fetch_add(1, std::memory_order_relaxed));

            {
                std::scoped_lock lock{this->writer_mutex_};
                auto current = this->handlers_.load(std::memory_order_acquire);
                auto next = std::make_shared<HandlerList>(*current);
                next->push_back(Entry{id, std::move(handler)});
                // Publish the new count first so a reader that sees 0 on the
                // counter and skips the snapshot load cannot miss a handler
                // that has already been installed in the snapshot.
                this->handler_count_.store(next->size(), std::memory_order_release);
                this->handlers_.store(std::shared_ptr<const HandlerList>(std::move(next)),
                                      std::memory_order_release);
            }

            std::weak_ptr<void> weak = this->alive_;
            return Subscription(
                std::move(weak),
                [this, id]() noexcept -> bool { return this->unsubscribe(id); });
        }

        /**
         * @brief Emits an event to all subscribers.
         * @param event The event payload, passed by const reference to each handler.
         * @note Lock-free: performs one atomic acquire-load of the snapshot
         *       pointer and iterates. Multiple threads may emit concurrently
         *       without contention. Handlers are invoked synchronously in
         *       subscription order. Exceptions thrown by handlers propagate
         *       to the caller.
         * @warning If calling from a game hook callback or any context where an
         *          unhandled exception would crash the host process, use
         *          emit_safe() instead. emit() lets handler exceptions propagate
         *          uncaught, which will terminate the process if no catch frame
         *          exists above the call site.
         */
        void emit(const Event &event) const
        {
            // Fast path: no subscribers means no snapshot load at all.
            if (this->handler_count_.load(std::memory_order_acquire) == 0)
            {
                return;
            }

            SharedList snap = this->handlers_.load(std::memory_order_acquire);
            EmitGuard guard{emitting_depth()};
            for (const auto &entry : *snap)
            {
                entry.callback(event);
            }
        }

        /**
         * @brief Emits an event, catching and discarding handler exceptions.
         * @param event The event payload.
         * @note Same locking semantics as emit() (lock-free). Handlers that
         *       throw are skipped; remaining handlers still execute.
         *       Prefer this over emit() when calling from hook callbacks or
         *       other contexts where an unhandled exception would crash the
         *       host process.
         */
        void emit_safe(const Event &event) const noexcept
        {
            if (this->handler_count_.load(std::memory_order_acquire) == 0)
            {
                return;
            }

            // std::shared_ptr copy-construction and load are noexcept, so the
            // entire function remains noexcept despite the per-handler catch.
            SharedList snap = this->handlers_.load(std::memory_order_acquire);
            EmitGuard guard{emitting_depth()};
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
            return this->handler_count_.load(std::memory_order_acquire);
        }

        /// Returns true if there are no subscribers.
        [[nodiscard]] bool empty() const noexcept
        {
            return this->handler_count_.load(std::memory_order_acquire) == 0;
        }

        /**
         * @brief Removes all subscribers.
         * @note Serializes with other writers via the writer mutex; readers
         *       in flight keep their snapshot alive through their shared_ptr.
         */
        void clear() noexcept
        {
            std::scoped_lock lock{this->writer_mutex_};
            // Counter must go to 0 before publishing the empty snapshot so
            // an emit that reads 0 on the fast-path counter cannot still see
            // the non-empty old snapshot afterwards.
            this->handler_count_.store(0, std::memory_order_release);
            this->handlers_.store(std::make_shared<const HandlerList>(),
                                  std::memory_order_release);
        }

#if defined(DMK_EVENT_DISPATCHER_INTERNAL_TESTING)
        /**
         * @brief Test-only diagnostic: returns the number of outstanding
         *        references to the current handler snapshot, excluding the
         *        temporary this call itself creates. A value of 1 means the
         *        dispatcher's own atomic is the sole holder (steady state).
         *        A value >1 indicates an in-flight emit or a leaked snapshot
         *        reference. Enabled only when
         *        DMK_EVENT_DISPATCHER_INTERNAL_TESTING is defined by the
         *        test translation unit. Not part of the public API.
         */
        [[nodiscard]] long debug_snapshot_use_count() const noexcept
        {
            // load() returns a shared_ptr copy that bumps the refcount by 1
            // for its own lifetime; subtract that so the reported count
            // reflects only the other holders (the dispatcher atomic and
            // any in-flight emit snapshots).
            auto snap = this->handlers_.load(std::memory_order_acquire);
            return snap.use_count() - 1;
        }
#endif

    private:
        // Returns false when called from within a handler (reentrancy).
        // The Subscription::reset() caller retains its unsubscribe_ lambda
        // and will retry on the next reset() call (including the destructor)
        // once the emit completes. This is safe because the alive_ weak_ptr
        // prevents calling into a destroyed dispatcher.
        bool unsubscribe(SubscriptionId id) noexcept
        {
            if (emitting_depth() > 0)
            {
                return false;
            }

            std::scoped_lock lock{this->writer_mutex_};
            auto current = this->handlers_.load(std::memory_order_acquire);
            auto it = std::find_if(current->begin(), current->end(),
                                   [id](const Entry &e) { return e.id == id; });
            if (it == current->end())
            {
                // Not found; treat as successful (idempotent unsubscribe).
                return true;
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

            // Publish snapshot first, then the counter. An emit that loads a
            // stale snapshot containing the removed handler is still safe
            // because the handler callable is retained by the old snapshot.
            this->handlers_.store(std::shared_ptr<const HandlerList>(std::move(next)),
                                  std::memory_order_release);
            this->handler_count_.store(current->size() - 1, std::memory_order_release);
            return true;
        }

        // Thread-local emit depth counter. This is per-template-instantiation
        // (not per-instance) because making it per-instance would require a
        // thread_local map keyed by this pointer, adding a hash lookup to
        // every emit() hot path. The typical usage is one dispatcher per
        // event type, so the shared counter is the correct tradeoff. See
        // the class-level doc for details.
        [[nodiscard]] int &emitting_depth() const noexcept
        {
            thread_local int depth{0};
            return depth;
        }

        /// RAII guard that increments/decrements the emit depth counter.
        struct EmitGuard
        {
            int &depth;
            explicit EmitGuard(int &d) noexcept : depth(d) { ++depth; }
            ~EmitGuard() noexcept { --depth; }
            EmitGuard(const EmitGuard &) = delete;
            EmitGuard &operator=(const EmitGuard &) = delete;
            EmitGuard(EmitGuard &&) = delete;
            EmitGuard &operator=(EmitGuard &&) = delete;
        };

        // alignas(64) keeps the hot atomics on their own cache line so the
        // writer mutex and shared_ptr control-block traffic do not produce
        // false sharing with readers doing the fast-path counter load.
        alignas(64) mutable std::atomic<SharedList> handlers_;
        std::atomic<size_t> handler_count_{0};
        std::atomic<uint64_t> next_id_{1};
        std::mutex writer_mutex_; // serializes writers only
        std::shared_ptr<void> alive_; // Prevents Subscription::reset() from calling
                                      // unsubscribe() after dispatcher destruction.
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_EVENT_DISPATCHER_HPP
