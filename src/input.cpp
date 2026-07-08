/**
 * @file input.cpp
 * @brief Implementation of the public input facade (input.hpp): Input, Scope, BindingGuard, register_combo.
 *
 * The facade owns the background poll engine (input_poller.hpp) and the process-global interception layer. It explodes
 * a public ComboBinding into one engine entry per combo (OR logic under a shared name), wraps the user callback behind
 * a guard-owned cancellation flag, and routes delivery through a guard-owned teardown gate so release can run down any
 * in-flight callback before returning.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include "platform.hpp"
#include "internal/input_binding_gate.hpp"
#include "internal/input_poller.hpp"

#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace DetourModKit
{
    namespace input
    {
        struct BindingGuard::Impl
        {
            // Shared cancellation flag the binding's callback wrapper gates on; release() clears it so subsequent
            // events become no-ops.
            std::shared_ptr<std::atomic<bool>> enabled;
            // One-shot action run once by release(): runs down the per-binding gate and, for a consume binding, lifts
            // passthrough suppression.
            std::function<void()> on_release;
            std::string name;
        };

        BindingGuard::BindingGuard() noexcept = default;

        BindingGuard::BindingGuard(std::unique_ptr<Impl> impl) noexcept : m_impl(std::move(impl)) {}

        BindingGuard::~BindingGuard() noexcept
        {
            release();
        }

        BindingGuard::BindingGuard(BindingGuard &&other) noexcept : m_impl(std::move(other.m_impl)) {}

        BindingGuard &BindingGuard::operator=(BindingGuard &&other) noexcept
        {
            if (this != &other)
            {
                // Fire this guard's own pending release before adopting the other's binding, so the binding this guard
                // currently owns is not silently abandoned in a held state.
                release();
                m_impl = std::move(other.m_impl);
            }
            return *this;
        }

        void BindingGuard::release() noexcept
        {
            if (!m_impl)
            {
                return;
            }
            if (m_impl->enabled)
            {
                m_impl->enabled->store(false, std::memory_order_release);
                m_impl->enabled.reset();
            }
            // Run the optional release action exactly once. std::exchange clears the member first so a repeated or
            // re-entrant release() cannot double-fire it, and the catch keeps this noexcept teardown honest even though
            // the action may invoke a user-supplied hold callback.
            if (m_impl->on_release)
            {
                const std::function<void()> action = std::exchange(m_impl->on_release, nullptr);
                try
                {
                    action();
                }
                catch (...)
                {
                    (void)log().log_noexcept(
                        LogLevel::Error, "BindingGuard: release action threw; suppressed in noexcept teardown");
                }
            }
        }

        bool BindingGuard::is_active() const noexcept
        {
            return m_impl && m_impl->enabled && m_impl->enabled->load(std::memory_order_acquire);
        }

        std::string_view BindingGuard::name() const noexcept
        {
            return m_impl ? std::string_view{m_impl->name} : std::string_view{};
        }

        void Scope::add(BindingGuard guard)
        {
            m_guards.push_back(std::move(guard));
        }

        void Scope::clear() noexcept
        {
            // Release last-registered-first so a Hold guard whose balancing edge may depend on an earlier binding's
            // state unwinds before that earlier binding. The vector itself is then dropped; the second release() each
            // guard's destructor performs is an idempotent no-op.
            for (auto it = m_guards.rbegin(); it != m_guards.rend(); ++it)
            {
                it->release();
            }
            m_guards.clear();
        }

        Scope &Scope::operator=(Scope &&other) noexcept
        {
            if (this != &other)
            {
                clear();
                m_guards = std::move(other.m_guards);
            }
            return *this;
        }

        struct Input::Impl
        {
            mutable std::mutex m_mutex;
            std::vector<detail::InputBinding> m_pending;
            std::shared_ptr<detail::InputPoller> m_poller;
            // Snapshot of the live poller for the hot-path queries (is_active / token), independent of m_mutex. The
            // load takes a shared_ptr copy so the poller stays alive for the duration of the query even if shutdown()
            // concurrently destroys it; that ref-count acquire is not lock-free on the shipped toolchains, so the
            // per-call cost is documented on the query methods in input.hpp rather than optimized into a bare pointer
            // (a raw atomic<InputPoller*> would reintroduce exactly the use-after-free this snapshot exists to
            // prevent).
            std::atomic<std::shared_ptr<detail::InputPoller>> m_active{};
            std::atomic<bool> m_running{false};
            // Last-applied / pending engine settings. require_focus is live-mutable via set_require_focus; the gamepad
            // knobs and poll interval are consumed when start() builds the poller.
            Settings m_settings{};
            // Liveness token for a consume binding's guard-release action. The action holds a weak_ptr to this and only
            // reaches back into the facade (set_consume) if it can still lock it. Input is a strict process singleton
            // destroyed only at static-destruction time, so this guards the one hazardous ordering: a Hold/consume
            // guard parked in the process-default Scope whose static teardown runs AFTER the facade's. When that
            // happens the token is already gone, so the action no-ops instead of touching a destroyed Impl.
            std::shared_ptr<char> m_liveness{std::make_shared<char>()};
        };

        Input::Input() : m_impl(std::make_unique<Impl>()) {}

        Input::~Input() noexcept = default;

        Input &Input::instance() noexcept
        {
            static Input instance;
            return instance;
        }

        Result<BindingGuard> Input::register_combo(ComboBinding binding) noexcept
        {
            try
            {
                auto enabled = std::make_shared<std::atomic<bool>>(true);
                auto impl = std::make_unique<BindingGuard::Impl>();
                impl->enabled = enabled;
                impl->name = binding.name;

                const bool is_hold = binding.trigger == Trigger::Hold;

                // Wrap the user callback behind a per-binding teardown gate that all of the binding's exploded combos
                // share. The gate's release() is the one-shot action the guard runs on teardown:
                //   - HoldGate reference-counts the shared combos so a multi-combo hold forwards only the aggregate
                //     held/released transitions, and it synthesizes exactly one balancing on_state_change(false) for a
                //     still-held binding without re-entering the callback while it is on the stack.
                //   - PressGate serializes delivery against release() so a caller can destroy state the press callback
                //     captured the instant the guard is released, with no in-flight on_press still running through it.
                std::function<void()> press_wrapper;
                std::function<void(bool)> hold_wrapper;
                std::function<void()> gate_release;
                if (is_hold)
                {
                    auto gate = std::make_shared<detail::HoldGate>();
                    gate->enabled = enabled;
                    gate->on_state_change = std::move(binding.on_state_change);
                    hold_wrapper = [gate](bool active) { gate->deliver(active); };
                    gate_release = [gate]() { gate->release(); };
                }
                else
                {
                    auto gate = std::make_shared<detail::PressGate>();
                    gate->enabled = enabled;
                    gate->on_press = std::move(binding.on_press);
                    press_wrapper = [gate]() { gate->deliver(); };
                    gate_release = [gate]() { gate->release(); };
                }

                // A consume binding hides its trigger from the game via the interception layer, which keys off the
                // engine entry's `consume` flag alone (the poll loop's gamepad_owned / wheel_owned pass and the
                // detour-side rules never consult the guard's enabled flag). Gating the callback off on release
                // therefore does NOT lift the suppression: the game stays deprived of that chord for the rest of the
                // process. So the guard's teardown must also clear the consume bit, exactly as the public
                // set_consume(name, false) does. Weak-token guarded so a guard released after this singleton facade's
                // own static teardown safely no-ops instead of reaching into a destroyed Impl.
                std::function<void()> consume_release;
                if (binding.consume)
                {
                    std::weak_ptr<char> facade_alive = m_impl->m_liveness;
                    Input *facade = this;
                    consume_release = [facade_alive, facade, name = binding.name]()
                    {
                        if (auto keep = facade_alive.lock())
                        {
                            facade->set_consume(name, false);
                        }
                    };
                }

                // Compose the guard's one-shot release action. Every binding has a gate release; a consume binding
                // additionally lifts its suppression. Run the gate release first (it delivers a hold's balancing edge
                // and runs down an in-flight press), then clear consume. Guarantee the clear runs even if the balancing
                // on_state_change(false) throws: HoldGate::release() invokes that callback unwrapped, so a throw would
                // otherwise skip consume_release, and suppression is enforced off the engine entry's consume flag (not
                // the guard's enable flag), so the game would stay deprived of the chord for the rest of the process.
                // The clear is effectively no-throw (a weak-token-guarded, noexcept set_consume); re-raise after it so
                // BindingGuard::release()'s own catch still logs the callback failure.
                if (consume_release)
                {
                    impl->on_release = [gate_release = std::move(gate_release),
                                        consume_release = std::move(consume_release)]()
                    {
                        try
                        {
                            gate_release();
                        }
                        catch (...)
                        {
                            consume_release();
                            throw;
                        }
                        consume_release();
                    };
                }
                else
                {
                    impl->on_release = std::move(gate_release);
                }

                // Explode the combos into one engine entry per alternative, all sharing the name (OR logic). An empty
                // list still registers a single inert sentinel so the name is addressable for a later rebind.
                const auto make_entry = [&](const std::vector<InputCode> &keys,
                                            const std::vector<InputCode> &modifiers) -> detail::InputBinding
                {
                    detail::InputBinding entry;
                    entry.name = binding.name;
                    entry.keys = keys;
                    entry.modifiers = modifiers;
                    entry.trigger = binding.trigger;
                    entry.consume = binding.consume;
                    if (is_hold)
                    {
                        entry.on_state_change = hold_wrapper;
                    }
                    else
                    {
                        entry.on_press = press_wrapper;
                    }
                    return entry;
                };

                std::vector<detail::InputBinding> entries;
                if (binding.combos.empty())
                {
                    entries.push_back(make_entry({}, {}));
                }
                else
                {
                    entries.reserve(binding.combos.size());
                    for (const auto &combo : binding.combos)
                    {
                        entries.push_back(make_entry(combo.keys, combo.modifiers));
                    }
                }

                // Register: forward each entry to the live poller, or stage it for the next start(). Forward outside
                // m_mutex so the poller's exclusive binding lock cannot AB/BA against a caller holding m_mutex.
                std::shared_ptr<detail::InputPoller> live;
                {
                    std::lock_guard lock(m_impl->m_mutex);
                    if (m_impl->m_poller)
                    {
                        live = m_impl->m_poller;
                    }
                    else
                    {
                        // Stage all-or-nothing. Reserve the whole batch up front so a mid-loop bad_alloc cannot leave a
                        // subset of a multi-combo registration staged (which would go live -- half-registered -- at the
                        // next start()). The reserve is the only allocating step; InputBinding moves are noexcept, so
                        // once capacity is secured the push_backs cannot throw.
                        m_impl->m_pending.reserve(m_impl->m_pending.size() + entries.size());
                        for (auto &entry : entries)
                        {
                            m_impl->m_pending.push_back(std::move(entry));
                        }
                        return BindingGuard{std::move(impl)};
                    }
                }
                if (!m_impl->m_running.load(std::memory_order_acquire))
                {
                    // shutdown() flips m_running false (under m_mutex) before it tears the captured poller down, so
                    // observing false here means a concurrent shutdown began after we captured the poller. Return a
                    // valid but inert guard, the same observable outcome as registering after shutdown.
                    enabled->store(false, std::memory_order_release);
                    return BindingGuard{std::move(impl)};
                }

                // Add multi-combo bindings as one batch. A per-entry append can leave a partially-registered consume
                // binding behind when a later append runs out of memory, and consume suppression is driven by the
                // engine entry's consume flag rather than the guard's enabled flag. The single-entry path keeps the
                // existing append primitive live; the multi-entry batch path either commits every combo or none.
                const bool added = (entries.size() == 1) ? live->add_binding(std::move(entries.front()))
                                                         : live->add_bindings(std::move(entries));
                if (!added)
                {
                    enabled->store(false, std::memory_order_release);
                    return std::unexpected(Error{ErrorCode::OutOfMemory, "input::register_combo"});
                }
                return BindingGuard{std::move(impl)};
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "input::register_combo"});
            }
        }

        Result<void> Input::start(Settings settings) noexcept
        {
            try
            {
                std::lock_guard lock(m_impl->m_mutex);

                if (m_impl->m_poller)
                {
                    log().debug("input::Input: start() called while already running; no-op.");
                    return {};
                }

                m_impl->m_settings = settings;

                if (m_impl->m_pending.empty())
                {
                    // No bindings to seed the engine with. Matches the historical no-op; a later register_combo stages
                    // into pending and a subsequent start() builds the poller.
                    return {};
                }

                Logger &logger = log();
                logger.info("input::Input: Starting with {} binding(s), poll interval {}ms", m_impl->m_pending.size(),
                            settings.poll_interval.count());
                for (const auto &binding : m_impl->m_pending)
                {
                    logger.trace("input::Input: Registered {} binding \"{}\" with {} key(s)",
                                 to_string(binding.trigger), binding.name, binding.keys.size());
                }

                // Seed the engine with a COPY of the staged bindings and clear them only after start() succeeds.
                // InputPoller::start() throws std::system_error when the poll thread or its module reference cannot be
                // created, and the poller -- sole owner of a moved-in vector -- is destroyed during unwind; moving
                // m_pending in before that point would destroy the staged set with it, so a later retry would hit the
                // empty-pending no-op above and the bindings would be silently lost. The copy is confined to this cold
                // path.
                auto poller = std::make_shared<detail::InputPoller>(
                    m_impl->m_pending, settings.poll_interval, settings.require_focus, settings.gamepad_index,
                    settings.trigger_threshold, settings.stick_threshold);
                poller->start();
                m_impl->m_pending.clear();
                m_impl->m_poller = poller;
                m_impl->m_active.store(poller, std::memory_order_release);
                m_impl->m_running.store(true, std::memory_order_release);
                return {};
            }
            catch (const std::system_error &e)
            {
                return std::unexpected(
                    Error{ErrorCode::SystemCallFailed, "input::start", static_cast<std::uintptr_t>(e.code().value())});
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "input::start"});
            }
        }

        void Input::shutdown() noexcept
        {
            std::shared_ptr<detail::InputPoller> local_poller;

            {
                std::lock_guard lock(m_impl->m_mutex);
                // Clear the atomic shared_ptr before releasing the poller so a concurrent is_active() caller holds a
                // valid shared_ptr.
                m_impl->m_active.store(nullptr, std::memory_order_release);
                m_impl->m_running.store(false, std::memory_order_release);
                local_poller = std::move(m_impl->m_poller);
                m_impl->m_pending.clear();
            }

            if (local_poller)
            {
                // Read loader-lock ownership once; it is stable across this call because InputPoller::shutdown()
                // re-checks it on the same thread with no intervening lock release, so both observe the same result.
                const bool under_loader_lock = detail::is_loader_lock_held();
                local_poller->shutdown();

                if (under_loader_lock)
                {
                    // Under the loader lock InputPoller::shutdown() detaches its poll thread instead of joining it. The
                    // detached thread keeps reading InputPoller members until it observes the stop request, so
                    // destroying the poller now would free them mid-access. Move the last reference into a
                    // nothrow-allocated heap cell that is never freed, so the object outlives the detached thread; the
                    // code pages that thread executes stay mapped because its own counted module reference
                    // (InputPoller::m_self_ref, taken in start()) is leaked on this same detach branch. Mirrors the
                    // leak-on-loader-lock discipline used elsewhere.
                    auto *leaked = new (std::nothrow) std::shared_ptr<detail::InputPoller>(std::move(local_poller));
                    if (leaked == nullptr)
                    {
                        // The heap cell could not be allocated under host OOM. A failed nothrow new does not run the
                        // constructor, so local_poller was NOT moved from and would destroy the poller -- freeing the
                        // members the detached thread still reads -- at scope exit. Park the last reference in
                        // never-destructed static storage via placement-new instead: no allocation can fail here, and
                        // the storage's destructor never runs, so the poller still outlives the detached thread. The
                        // loader-lock detach is process-terminal and taken at most once per module load, so one cell
                        // suffices. Mirrors the non-CRT permanent-storage fallback the async logger uses.
                        alignas(std::shared_ptr<detail::InputPoller>) static unsigned char
                            fallback_cell[sizeof(std::shared_ptr<detail::InputPoller>)];
                        ::new (static_cast<void *>(fallback_cell))
                            std::shared_ptr<detail::InputPoller>(std::move(local_poller));
                    }
                    (void)leaked;
                }
            }
        }

        bool Input::is_running() const noexcept
        {
            return m_impl->m_running.load(std::memory_order_acquire);
        }

        std::size_t Input::binding_count() const noexcept
        {
            std::shared_ptr<detail::InputPoller> live_poller;
            {
                std::lock_guard lock(m_impl->m_mutex);
                if (!m_impl->m_poller)
                {
                    return m_impl->m_pending.size();
                }
                live_poller = m_impl->m_poller;
            }
            return live_poller->binding_count();
        }

        bool Input::is_active(std::string_view name) const noexcept
        {
            auto active_poller = m_impl->m_active.load(std::memory_order_acquire);
            return active_poller ? active_poller->is_binding_active(name) : false;
        }

        BindingToken Input::acquire_token(std::string_view name) const noexcept
        {
            auto active_poller = m_impl->m_active.load(std::memory_order_acquire);
            return active_poller ? active_poller->acquire_binding_token(name) : BindingToken{};
        }

        bool Input::is_active(const BindingToken &token) const noexcept
        {
            auto active_poller = m_impl->m_active.load(std::memory_order_acquire);
            return active_poller ? active_poller->is_binding_active(token) : false;
        }

        bool Input::token_current(const BindingToken &token) const noexcept
        {
            auto active_poller = m_impl->m_active.load(std::memory_order_acquire);
            return active_poller ? active_poller->binding_token_current(token) : false;
        }

        Result<void> Input::rebind(std::string_view name, KeyComboList combos) noexcept
        {
            std::shared_ptr<detail::InputPoller> local_poller;

            try
            {
                std::unique_lock lock(m_impl->m_mutex);
                if (m_impl->m_poller)
                {
                    local_poller = m_impl->m_poller;
                }
                else
                {
                    // Apply to pending bindings (the first INI load typically runs before start()).
                    std::vector<std::size_t> indices;
                    indices.reserve(m_impl->m_pending.size());
                    for (std::size_t i = 0; i < m_impl->m_pending.size(); ++i)
                    {
                        if (m_impl->m_pending[i].name == name)
                        {
                            indices.push_back(i);
                        }
                    }
                    if (indices.empty())
                    {
                        lock.unlock();
                        (void)log().try_log(LogLevel::Debug, "input::Input: rebind(\"{}\") ignored: name not found",
                                            name);
                        return std::unexpected(Error{ErrorCode::InvalidArg, "input::rebind"});
                    }

                    if (indices.size() == combos.size())
                    {
                        std::vector<detail::InputBinding> replacements;
                        replacements.reserve(indices.size());
                        for (std::size_t i = 0; i < indices.size(); ++i)
                        {
                            detail::InputBinding binding = m_impl->m_pending[indices[i]];
                            binding.keys = combos[i].keys;
                            binding.modifiers = combos[i].modifiers;
                            replacements.push_back(std::move(binding));
                        }
                        for (std::size_t i = 0; i < indices.size(); ++i)
                        {
                            m_impl->m_pending[indices[i]] = std::move(replacements[i]);
                        }
                        return {};
                    }

                    // Cardinality change: rebuild the pending list. An empty replacement keeps one inert sentinel so
                    // the name stays addressable for a later non-empty update.
                    detail::InputBinding prototype = m_impl->m_pending[indices.front()];
                    std::sort(indices.begin(), indices.end());

                    const std::size_t append_count = combos.empty() ? 1 : combos.size();
                    std::vector<detail::InputBinding> appended;
                    appended.reserve(append_count);
                    if (combos.empty())
                    {
                        detail::InputBinding sentinel = prototype;
                        sentinel.keys.clear();
                        sentinel.modifiers.clear();
                        appended.push_back(std::move(sentinel));
                    }
                    else
                    {
                        for (const auto &combo : combos)
                        {
                            detail::InputBinding binding = prototype;
                            binding.keys = combo.keys;
                            binding.modifiers = combo.modifiers;
                            appended.push_back(std::move(binding));
                        }
                    }

                    std::vector<detail::InputBinding> rebuilt;
                    rebuilt.reserve(m_impl->m_pending.size() - indices.size() + append_count);
                    std::size_t cursor = 0;
                    for (std::size_t skip : indices)
                    {
                        for (std::size_t i = cursor; i < skip; ++i)
                        {
                            rebuilt.push_back(std::move(m_impl->m_pending[i]));
                        }
                        cursor = skip + 1;
                    }
                    for (std::size_t i = cursor; i < m_impl->m_pending.size(); ++i)
                    {
                        rebuilt.push_back(std::move(m_impl->m_pending[i]));
                    }
                    for (auto &binding : appended)
                    {
                        rebuilt.push_back(std::move(binding));
                    }
                    m_impl->m_pending = std::move(rebuilt);
                    return {};
                }
            }
            catch (...)
            {
                // rebind is noexcept-friendly via Result; on out-of-memory the pending bindings are left unchanged
                // (allocation precedes the move-commit).
                (void)log().try_log(LogLevel::Error, "input::Input: out of memory in rebind; bindings unchanged");
                return std::unexpected(Error{ErrorCode::OutOfMemory, "input::rebind"});
            }

            // Live path: forward to the running poller outside m_mutex.
            return local_poller->update_combos(name, combos)
                       ? Result<void>{}
                       : std::unexpected(Error{ErrorCode::InvalidArg, "input::rebind"});
        }

        void Input::set_consume(std::string_view name, bool consume) noexcept
        {
            std::shared_ptr<detail::InputPoller> live_poller;

            {
                std::lock_guard lock(m_impl->m_mutex);
                if (m_impl->m_poller)
                {
                    live_poller = m_impl->m_poller;
                }
                else
                {
                    for (auto &binding : m_impl->m_pending)
                    {
                        if (binding.name == name)
                        {
                            binding.consume = consume;
                        }
                    }
                    return;
                }
            }

            // Forward outside m_mutex so the poller's exclusive binding lock cannot deadlock against a caller holding
            // m_mutex (matches register_combo).
            live_poller->set_consume(name, consume);
        }

        void Input::set_require_focus(bool require_focus) noexcept
        {
            std::lock_guard lock(m_impl->m_mutex);
            m_impl->m_settings.require_focus = require_focus;
            if (m_impl->m_poller)
            {
                m_impl->m_poller->set_require_focus(require_focus);
            }
        }

        std::size_t Input::remove_bindings_by_name(std::string_view name, bool invoke_callbacks) noexcept
        {
            std::shared_ptr<detail::InputPoller> live_poller;
            std::size_t removed_pending = 0;

            {
                std::lock_guard lock(m_impl->m_mutex);
                if (m_impl->m_poller)
                {
                    live_poller = m_impl->m_poller;
                }
                else
                {
                    auto new_end = std::remove_if(m_impl->m_pending.begin(), m_impl->m_pending.end(),
                                                  [name](const detail::InputBinding &b) { return b.name == name; });
                    removed_pending = static_cast<std::size_t>(std::distance(new_end, m_impl->m_pending.end()));
                    m_impl->m_pending.erase(new_end, m_impl->m_pending.end());
                }
            }

            if (live_poller)
            {
                return live_poller->remove_bindings_by_name(name, invoke_callbacks);
            }
            return removed_pending;
        }

        void Input::clear_bindings(bool invoke_callbacks) noexcept
        {
            std::shared_ptr<detail::InputPoller> live_poller;

            {
                std::lock_guard lock(m_impl->m_mutex);
                m_impl->m_pending.clear();
                if (m_impl->m_poller)
                {
                    live_poller = m_impl->m_poller;
                }
            }

            if (live_poller)
            {
                live_poller->clear_bindings(invoke_callbacks);
            }
        }

        // Free-function ergonomics

        Result<BindingGuard> register_combo(ComboBinding binding) noexcept
        {
            return Input::instance().register_combo(std::move(binding));
        }

        Scope &scope() noexcept
        {
            static Scope process_scope;
            return process_scope;
        }
    } // namespace input
} // namespace DetourModKit
