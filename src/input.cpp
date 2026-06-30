/**
 * @file input.cpp
 * @brief Implementation of the public input facade (input.hpp): Input, Scope, BindingGuard, register_combo.
 *
 * The facade owns the background poll engine (input_poller.hpp) and the process-global interception layer. It explodes
 * a public ComboBinding into one engine entry per combo (OR logic under a shared name), wraps the user callback behind
 * a guard-owned cancellation flag, and for a Hold binding routes delivery through a HoldGate so a cancelled hold emits
 * exactly one balancing on_state_change(false).
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include "platform.hpp"
#include "internal/input_hold_gate.hpp"
#include "internal/input_poller.hpp"

#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace DetourModKit
{
    namespace input
    {
        // --- BindingGuard ---

        struct BindingGuard::Impl
        {
            // Shared cancellation flag the binding's callback wrapper gates on; release() clears it so subsequent
            // events become no-ops.
            std::shared_ptr<std::atomic<bool>> enabled;
            // One-shot action run once by release(): for a Hold guard this fires the HoldGate's balancing
            // on_state_change(false). Empty for a Press guard.
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
                    (void)Logger::get_instance().log_noexcept(
                        LogLevel::Error, "BindingGuard: hold release action threw; suppressed in noexcept teardown");
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

        // --- Scope ---

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

        // --- Input ---

        struct Input::Impl
        {
            mutable std::mutex m_mutex;
            std::vector<detail::InputBinding> m_pending;
            std::shared_ptr<detail::InputPoller> m_poller;
            // Lock-free read of the live poller for the hot-path queries (is_active / token), independent of m_mutex.
            std::atomic<std::shared_ptr<detail::InputPoller>> m_active{};
            std::atomic<bool> m_running{false};
            // Last-applied / pending engine settings. require_focus is live-mutable via set_require_focus; the gamepad
            // knobs and poll interval are consumed when start() builds the poller.
            Settings m_settings{};
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

                // Wrap the user callback so the guard's flag gates it. A Hold binding additionally routes delivery
                // through a HoldGate: all of its combos share one gate, so a guard release synthesizes exactly one
                // balancing on_state_change(false) for a still-held binding and never re-enters the callback while it
                // is on the stack.
                std::function<void()> press_wrapper;
                std::function<void(bool)> hold_wrapper;
                if (is_hold)
                {
                    auto gate = std::make_shared<detail::HoldGate>();
                    gate->enabled = enabled;
                    gate->on_state_change = std::move(binding.on_state_change);
                    hold_wrapper = [gate](bool active) { gate->deliver(active); };
                    impl->on_release = [gate]() { gate->release(); };
                }
                else
                {
                    press_wrapper = [enabled, cb = std::move(binding.on_press)]()
                    {
                        if (cb && enabled->load(std::memory_order_acquire))
                        {
                            cb();
                        }
                    };
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
                        for (auto &entry : entries)
                        {
                            m_impl->m_pending.push_back(std::move(entry));
                        }
                        return BindingGuard{std::move(impl)};
                    }
                }
                for (auto &entry : entries)
                {
                    live->add_binding(std::move(entry));
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
                    Logger::get_instance().debug("input::Input: start() called while already running; no-op.");
                    return {};
                }

                m_impl->m_settings = settings;

                if (m_impl->m_pending.empty())
                {
                    // No bindings to seed the engine with. Matches the historical no-op; a later register_combo stages
                    // into pending and a subsequent start() builds the poller.
                    return {};
                }

                Logger &logger = Logger::get_instance();
                logger.info("input::Input: Starting with {} binding(s), poll interval {}ms", m_impl->m_pending.size(),
                            settings.poll_interval.count());
                for (const auto &binding : m_impl->m_pending)
                {
                    logger.trace("input::Input: Registered {} binding \"{}\" with {} key(s)",
                                 to_string(binding.trigger), binding.name, binding.keys.size());
                }

                auto poller = std::make_shared<detail::InputPoller>(
                    std::move(m_impl->m_pending), settings.poll_interval, settings.require_focus,
                    settings.gamepad_index, settings.trigger_threshold, settings.stick_threshold);
                m_impl->m_pending.clear();
                poller->start();
                m_impl->m_poller = poller;
                m_impl->m_active.store(poller, std::memory_order_release);
                m_impl->m_running.store(true, std::memory_order_release);
                return {};
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
                    // nothrow-allocated heap cell that is never freed, so the object outlives the detached thread (the
                    // module is already pinned). Mirrors the leak-on-loader-lock discipline used elsewhere; nothrow
                    // keeps this noexcept path honest under OOM.
                    auto *leaked = new (std::nothrow) std::shared_ptr<detail::InputPoller>(std::move(local_poller));
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
                        (void)Logger::get_instance().try_log(
                            LogLevel::Debug, "input::Input: rebind(\"{}\") ignored: name not found", name);
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
                (void)Logger::get_instance().try_log(LogLevel::Error,
                                                     "input::Input: out of memory in rebind; bindings unchanged");
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

        // --- Free-function ergonomics ---

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
