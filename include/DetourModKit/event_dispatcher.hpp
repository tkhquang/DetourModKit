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
 *          - `emit()` acquires a shared lock (readers do not block each other)
 *          - `subscribe()` / manual `unsubscribe()` acquire an exclusive lock
 *          - Safe to emit from multiple threads concurrently (e.g., hook callbacks)
 *          - Safe to subscribe/unsubscribe from any thread
 *
 *          **Performance characteristics:**
 *          - `emit()`: shared_lock + linear iteration over contiguous handler vector
 *          - `subscribe()`: exclusive_lock + vector push_back (amortized O(1))
 *          - `unsubscribe()`: exclusive_lock + erase-remove (O(n) subscribers)
 *          - No heap allocation on `emit()`. Handler vector is cache-friendly.
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
 *          // Emit from a hook callback (shared_lock, thread-safe)
 *          dispatcher.emit(PlayerStateChanged{.health = 75.0f});
 *          @endcode
 */

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
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
         */
        void reset() noexcept
        {
            if (unsubscribe_ && !alive_.expired())
            {
                unsubscribe_();
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

        Subscription(std::weak_ptr<void> alive, std::function<void()> unsub) noexcept
            : alive_(std::move(alive)), unsubscribe_(std::move(unsub))
        {
        }

        std::weak_ptr<void> alive_;
        std::function<void()> unsubscribe_;
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
     * - `emit()`: shared_lock (multiple concurrent emitters OK)
     * - `subscribe()` / `unsubscribe()`: exclusive_lock
     * - Handlers are invoked under shared_lock. Handlers must NOT call
     *   subscribe/unsubscribe on the same dispatcher (deadlock). Use deferred
     *   patterns if needed.
     */
    template <typename Event>
    class EventDispatcher
    {
    public:
        /// Handler function signature: receives the event by const reference.
        using Handler = std::function<void(const Event &)>;

        EventDispatcher()
            : alive_(std::make_shared<char>('\0'))
        {
        }

        ~EventDispatcher() = default;

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
         * @note Acquires exclusive lock. Do not call from within a handler.
         */
        [[nodiscard]] Subscription subscribe(Handler handler)
        {
            const auto id = static_cast<SubscriptionId>(
                this->next_id_.fetch_add(1, std::memory_order_relaxed));

            {
                auto guard = std::unique_lock{this->mutex_};
                this->handlers_.push_back(Entry{id, std::move(handler)});
            }

            std::weak_ptr<void> weak = this->alive_;
            return Subscription(
                std::move(weak),
                [this, id]() noexcept { this->unsubscribe(id); });
        }

        /**
         * @brief Emits an event to all subscribers.
         * @param event The event payload, passed by const reference to each handler.
         * @note Acquires shared lock. Multiple threads may emit concurrently.
         *       Handlers are invoked synchronously in subscription order.
         *       Exceptions thrown by handlers propagate to the caller.
         */
        void emit(const Event &event) const
        {
            auto guard = std::shared_lock{this->mutex_};
            for (const auto &entry : this->handlers_)
            {
                entry.callback(event);
            }
        }

        /**
         * @brief Emits an event, catching and discarding handler exceptions.
         * @param event The event payload.
         * @note Same locking semantics as emit(). Handlers that throw are
         *       skipped; remaining handlers still execute.
         */
        void emit_safe(const Event &event) const noexcept
        {
            auto guard = std::shared_lock{this->mutex_};
            for (const auto &entry : this->handlers_)
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
            auto guard = std::shared_lock{this->mutex_};
            return this->handlers_.size();
        }

        /// Returns true if there are no subscribers.
        [[nodiscard]] bool empty() const noexcept
        {
            auto guard = std::shared_lock{this->mutex_};
            return this->handlers_.empty();
        }

        /**
         * @brief Removes all subscribers.
         * @note Acquires exclusive lock.
         */
        void clear() noexcept
        {
            auto guard = std::unique_lock{this->mutex_};
            this->handlers_.clear();
        }

    private:
        struct Entry
        {
            SubscriptionId id;
            Handler callback;
        };

        void unsubscribe(SubscriptionId id) noexcept
        {
            auto guard = std::unique_lock{this->mutex_};
            auto it = std::find_if(this->handlers_.begin(), this->handlers_.end(),
                                   [id](const Entry &e) { return e.id == id; });
            if (it != this->handlers_.end())
            {
                if (it != this->handlers_.end() - 1)
                {
                    *it = std::move(this->handlers_.back());
                }
                this->handlers_.pop_back();
            }
        }

        mutable std::shared_mutex mutex_;
        std::vector<Entry> handlers_;
        std::atomic<uint64_t> next_id_{1};
        std::shared_ptr<void> alive_; // Prevents Subscription::reset() from calling
                                      // unsubscribe() after dispatcher destruction.
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_EVENT_DISPATCHER_HPP
