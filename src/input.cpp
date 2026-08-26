/**
 * @file input.cpp
 * @brief Implementation of the public input facade (input.hpp): Input, Scope, BindingGuard, register_combo.
 *
 * The facade owns the background poll engine (input_poller.hpp) and the instance-shared interception layer. It explodes
 * a public ComboBinding into one engine entry per combo (OR logic under a shared name), wraps the user callback behind
 * a guard-owned cancellation flag, and routes delivery through a guard-owned teardown gate so release can run down any
 * in-flight callback before returning.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/drain_backoff.hpp"
#include "internal/input_binding_gate.hpp"
#include "internal/input_delivery_scope.hpp"
#include "internal/input_poller.hpp"
#include "internal/input_test_seams.hpp"
#include "internal/lifecycle_context.hpp"
#include "internal/lifecycle_reaper.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
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
                        LogLevel::Error,
                        "BindingGuard: release action threw; suppressed in noexcept teardown"
                    );
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
            if (!m_guards)
            {
                m_guards = std::make_unique<std::vector<BindingGuard>>();
            }
            m_guards->push_back(std::move(guard));
        }

        void Scope::clear() noexcept
        {
            if (!m_guards)
            {
                return;
            }
            // Consumer code can call add(), so detach the current batch before any release.
            std::vector<BindingGuard> batch = std::move(*m_guards);
            m_guards->clear();
            for (auto it = batch.rbegin(); it != batch.rend(); ++it)
            {
                it->release();
            }
        }

        void Scope::abandon() noexcept
        {
            // Retain the already-allocated container in place. Destroying the guards would destroy consumer callback
            // captures inside DllMain even if release() itself were skipped, so logical abandonment must bypass both.
            if (m_guards.release() != nullptr)
            {
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Input);
            }
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
            // The latch leaves m_impl unchanged, so an admitted facade call retains a stable pointee.
            std::atomic<bool> m_vetoed_retained{false};
            mutable std::mutex m_mutex;
            std::vector<detail::InputBinding> m_pending;
            std::uint64_t m_start_revision{1};
            std::shared_ptr<detail::InputPoller> m_poller;
            // Hot-path queries load a shared_ptr snapshot without m_mutex. The snapshot preserves poller lifetime
            // across concurrent shutdown. input.hpp documents the shared ownership cost.
            std::atomic<std::shared_ptr<detail::InputPoller>> m_active{};
            std::atomic<bool> m_running{false};
            std::atomic<bool> m_callback_drain_active{false};
            std::atomic<std::uint32_t> m_admission_commits_inflight{0};
            // Last-applied / pending engine settings. require_focus is live-mutable via set_require_focus; the gamepad
            // knobs and poll interval are consumed when start() builds the poller.
            Settings m_settings{};

            /// Advances the facade state token after a pending binding or start setting changes.
            void advance_start_revision() noexcept
            {
                m_start_revision =
                    m_start_revision == (std::numeric_limits<std::uint64_t>::max)() ? 1 : m_start_revision + 1;
            }
            // A consume release action holds a weak facade token before it calls set_consume_by_owner. The action
            // becomes a no-op after facade teardown. No other guard action reaches facade state.
            std::shared_ptr<char> m_liveness{std::make_shared<char>()};
        };

        void Input::ImplDeleter::operator()(Impl *impl) const noexcept
        {
            if (impl != nullptr && !impl->m_vetoed_retained.load(std::memory_order_acquire))
            {
                delete impl;
            }
        }

        static_assert(sizeof(Input) == sizeof(void *), "Input must retain its pointer-sized public ABI");
        static_assert(alignof(Input) == alignof(void *), "Input must retain its pointer-aligned public ABI");
        static_assert(std::atomic<bool>::is_always_lock_free, "Input's loader-lock retention latch must be lock-free");

#if defined(DMK_ENABLE_TEST_SEAMS)
        namespace
        {
            std::atomic<detail::InputTestSeams::CallbackAdmissionCommitSeam> s_callback_admission_commit_seam{nullptr};
            // Input members cast this test-only retained-owner identity through void*.
            std::atomic<void *> s_vetoed_retained_impl{nullptr};
            // The unlock seam uses the owner identity captured before a test veto.
            void *s_test_locked_impl = nullptr;
        } // namespace
#endif

        namespace
        {
            /**
             * @brief Counts one admitted registration or start operation until its commit point has passed.
             */
            class AdmissionCommitLease
            {
            public:
                AdmissionCommitLease(
                    std::atomic<bool> &drain_active,
                    std::atomic<std::uint32_t> &inflight,
                    bool require_staging_admission = true
                ) noexcept
                    : m_drain_active(drain_active), m_inflight(inflight)
                {
                    if (m_drain_active.load(std::memory_order_seq_cst) || detail::input_callback_drain_pending() ||
                        (require_staging_admission && !detail::input_callback_admission_open()))
                    {
                        return;
                    }

                    m_inflight.fetch_add(1, std::memory_order_seq_cst);
                    if (m_drain_active.load(std::memory_order_seq_cst) || detail::input_callback_drain_pending() ||
                        (require_staging_admission && !detail::input_callback_admission_open()))
                    {
                        m_inflight.fetch_sub(1, std::memory_order_seq_cst);
                        return;
                    }
                    m_engaged = true;
                }

                ~AdmissionCommitLease() noexcept
                {
                    if (m_engaged)
                    {
                        m_inflight.fetch_sub(1, std::memory_order_seq_cst);
                    }
                }

                AdmissionCommitLease(const AdmissionCommitLease &) = delete;
                AdmissionCommitLease &operator=(const AdmissionCommitLease &) = delete;

                /// Returns whether this registration may commit.
                [[nodiscard]] bool engaged() const noexcept { return m_engaged; }

            private:
                std::atomic<bool> &m_drain_active;
                std::atomic<std::uint32_t> &m_inflight;
                bool m_engaged{false};
            };

            [[nodiscard]] bool await_admission_commits(
                std::atomic<std::uint32_t> &inflight,
                std::chrono::steady_clock::time_point deadline
            ) noexcept
            {
                return detail::drain_until_zero(
                    [&inflight]() noexcept { return inflight.load(std::memory_order_seq_cst); },
                    deadline
                );
            }
        } // namespace

        Input::Input() noexcept : m_impl(create_impl()) {}

        Input::ImplOwner Input::create_impl() noexcept
        {
            // First-use allocation failure must not escape the noexcept instance() accessor. A null Impl is the inert
            // state: no thread, no binding storage, and no partially built engine is ever published. It latches for the
            // process generation because instance() constructs the singleton exactly once.
            try
            {
                return ImplOwner{new Impl{}};
            }
            catch (...)
            {
                return nullptr;
            }
        }

        Input::~Input() noexcept
        {
            // shutdown() owns the B-100 boundary.
            shutdown();
        }

        Input &Input::instance() noexcept
        {
            // The constructor is noexcept, so this local static cannot throw out of a noexcept accessor and cannot be
            // re-entered for a retry. Concurrent first callers serialize on the language's own initialization guard and
            // all observe the same object, inert or live.
            static Input instance;
            return instance;
        }

        Result<BindingGuard> Input::register_combo(ComboBinding binding) noexcept
        {
            if (is_inert())
            {
                const ErrorCode code = m_impl ? ErrorCode::ShutdownInProgress : ErrorCode::OutOfMemory;
                return std::unexpected(Error{code, "input::register_combo"});
            }
            AdmissionCommitLease registration{m_impl->m_callback_drain_active, m_impl->m_admission_commits_inflight};
            if (!registration.engaged())
            {
                return std::unexpected(Error{ErrorCode::ShutdownInProgress, "input::register_combo"});
            }

            try
            {
                auto enabled = std::make_shared<std::atomic<bool>>(true);
                auto impl = std::make_unique<BindingGuard::Impl>();
                impl->enabled = enabled;
                impl->name = binding.name;

                // One lifecycle shared by this registration's gate and every exploded engine entry: the gate reads its
                // tombstone as a resurrection guard, and each entry carries it so a poll-cycle callback staged before a
                // remove / clear / cardinality-changing rebind is refused at dispatch. Allocated once here so the gate
                // and entries share one identity. This call also reserves the delivery marker's TLS slot, which has to
                // happen on a control thread before the wrappers below can be dispatched to.
                auto lifecycle = detail::make_binding_lifecycle();

                const bool is_hold = binding.trigger == Trigger::Hold;

                // Unique identity for this registration, stamped on every exploded engine entry so the guard's teardown
                // can clear the consume flag by identity rather than by name. A monotonic process-wide counter (never
                // 0, which is the no-owner sentinel), so it cannot alias a freed binding the way a reused pointer
                // address can. Relaxed suffices: the id only has to be unique, not ordered against any other state.
                static std::atomic<std::uint64_t> s_next_consume_owner{1};
                const std::uint64_t consume_owner = s_next_consume_owner.fetch_add(1, std::memory_order_relaxed);

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
                // Also handed to every exploded engine entry, so an unload drain can retire the gate directly instead
                // of only dropping the wrappers that capture it. See InputBinding::gate.
                std::shared_ptr<detail::BindingGate> binding_gate;
                if (is_hold)
                {
                    auto gate = std::make_shared<detail::HoldGate>();
                    gate->enabled = enabled;
                    gate->lifecycle = lifecycle;
                    gate->on_state_change = std::move(binding.on_state_change);
                    hold_wrapper = [gate](bool active) { gate->deliver(active); };
                    gate_release = [gate]() { gate->release(); };
                    binding_gate = gate;
                }
                else
                {
                    auto gate = std::make_shared<detail::PressGate>();
                    gate->enabled = enabled;
                    gate->lifecycle = lifecycle;
                    gate->on_press = std::move(binding.on_press);
                    press_wrapper = [gate]() { gate->deliver(); };
                    gate_release = [gate]() { gate->release(); };
                    binding_gate = gate;
                }

                // Callback disable does not clear consume suppression, which reads InputBinding::consume. Clear by
                // owner identity because empty names do not enter the name index. The weak token rejects late release.
                std::function<void()> consume_release;
                if (binding.consume)
                {
                    const std::weak_ptr<char> facade_alive = m_impl->m_liveness;
                    Input *const facade = this;
                    consume_release = [facade_alive, facade, consume_owner]()
                    {
                        if (auto keep = facade_alive.lock())
                        {
                            facade->set_consume_by_owner(consume_owner, false);
                        }
                    };
                }

                // Release the gate before the consume clear. If a Hold edge throws, run the clear before the exception
                // resumes.
                if (consume_release)
                {
                    impl->on_release =
                        [gate_release = std::move(gate_release), consume_release = std::move(consume_release)]()
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
                    entry.consume_owner = consume_owner;
                    entry.lifecycle = lifecycle;
                    entry.gate = binding_gate;
                    if (is_hold)
                    {
                        entry.on_state_change = hold_wrapper;
                        // The gate deduplicates a released(false) with no live held(true), so a tombstoning reshape can
                        // publish this binding's balancing false without racing the state clear the poll loop commits
                        // for the cycle that staged the release.
                        entry.release_is_idempotent = true;
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

#if defined(DMK_ENABLE_TEST_SEAMS)
                if (const detail::InputTestSeams::CallbackAdmissionCommitSeam seam =
                        s_callback_admission_commit_seam.load(std::memory_order_acquire);
                    seam != nullptr)
                {
                    seam();
                }
#endif

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
                        // subset of a multi-combo registration staged (which then goes live half-registered at the
                        // next start()). The reserve is the only allocating step; InputBinding moves are noexcept, so
                        // once capacity is secured the push_backs cannot throw.
                        m_impl->m_pending.reserve(m_impl->m_pending.size() + entries.size());
                        for (auto &entry : entries)
                        {
                            m_impl->m_pending.push_back(std::move(entry));
                        }
                        m_impl->advance_start_revision();
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
            if (is_inert())
            {
                const ErrorCode code = m_impl ? ErrorCode::ShutdownInProgress : ErrorCode::OutOfMemory;
                return std::unexpected(Error{code, "input::start"});
            }
            AdmissionCommitLease start_admission{
                m_impl->m_callback_drain_active,
                m_impl->m_admission_commits_inflight,
                false
            };
            if (!start_admission.engaged())
            {
                return std::unexpected(Error{ErrorCode::ShutdownInProgress, "input::start"});
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (const detail::InputTestSeams::CallbackAdmissionCommitSeam seam =
                    s_callback_admission_commit_seam.load(std::memory_order_acquire);
                seam != nullptr)
            {
                seam();
            }
#endif

            try
            {
                std::unique_lock lock(m_impl->m_mutex);

                if (m_impl->m_callback_drain_active.load(std::memory_order_seq_cst) ||
                    detail::input_callback_drain_pending())
                {
                    return std::unexpected(Error{ErrorCode::ShutdownInProgress, "input::start"});
                }
                if (!detail::open_input_callback_admission())
                {
                    return std::unexpected(Error{ErrorCode::ShutdownInProgress, "input::start"});
                }

                if (m_impl->m_poller)
                {
                    log().debug("input::Input: start() called while already running; no-op.");
                    return {};
                }

                m_impl->m_settings = settings;
                m_impl->advance_start_revision();

                if (m_impl->m_pending.empty())
                {
                    // No bindings to seed the engine with. Preserve the no-op; a later register_combo stages
                    // into pending and a subsequent start() builds the poller.
                    return {};
                }

                // Resolve the wheel backend before building the engine. An ExternalHost selection is validated against
                // the C ABI here, once, so the poller only ever receives a known-good host. A required host that is
                // missing or ABI-incompatible fails start() closed (InvalidArg); an optional one downgrades to the
                // local MessageHook backend so a single-DLL consumer still captures the wheel.
                Input::WheelBackend resolved_backend = settings.wheel_backend;
                const WheelHostTable *resolved_host = nullptr;
                // Reserved value 0 and every other unknown value are rejected at runtime.
                if (settings.wheel_backend != Input::WheelBackend::MessageHook &&
                    settings.wheel_backend != Input::WheelBackend::ExternalHost)
                {
                    return std::unexpected(Error{ErrorCode::InvalidArg, "input::start"});
                }
                if (settings.wheel_target_thread_id != 0)
                {
                    // An explicit wheel target must belong to this process and be alive.
                    const HANDLE target = OpenThread(
                        THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                        FALSE,
                        settings.wheel_target_thread_id
                    );
                    const bool target_valid = target != nullptr &&
                                              GetProcessIdOfThread(target) == GetCurrentProcessId() &&
                                              WaitForSingleObject(target, 0) != WAIT_OBJECT_0;
                    if (target != nullptr)
                    {
                        CloseHandle(target);
                    }
                    if (!target_valid)
                    {
                        return std::unexpected(Error{ErrorCode::InvalidArg, "input::start"});
                    }
                }
                if (settings.wheel_backend == Input::WheelBackend::ExternalHost)
                {
                    const WheelHostTable *host = settings.wheel_host;
                    constexpr std::uint64_t REQUIRED_CAPABILITIES = DMK_WHEELHOST_CAP_VERTICAL |
                                                                    DMK_WHEELHOST_CAP_HORIZONTAL |
                                                                    DMK_WHEELHOST_CAP_CONSUME | DMK_WHEELHOST_CAP_ROUTE;
                    const bool host_valid = host != nullptr && host->struct_size >= sizeof(WheelHostTable) &&
                                            host->abi_version == DMK_WHEELHOST_ABI_VERSION &&
                                            (host->capability_bits & REQUIRED_CAPABILITIES) == REQUIRED_CAPABILITIES &&
                                            host->host_identity != 0 && host->host_context != nullptr &&
                                            host->open_lease != nullptr && host->publish_capture != nullptr &&
                                            host->drain_counts != nullptr && host->close_lease != nullptr &&
                                            host->route_status != nullptr && host->retarget != nullptr;
                    if (host_valid)
                    {
                        resolved_host = host;
                    }
                    else if (settings.wheel_host_required)
                    {
                        // Leave callback admission open, matching the other start() failure paths: the refusal is
                        // retryable once the loader supplies a valid host and the staged bindings remain.
                        log().error(
                            "input::Input: required wheel host is missing or ABI-incompatible; refusing start."
                        );
                        return std::unexpected(Error{ErrorCode::InvalidArg, "input::start"});
                    }
                    else
                    {
                        log().warning(
                            "input::Input: optional wheel host unavailable; using the local MessageHook "
                            "backend."
                        );
                        resolved_backend = Input::WheelBackend::MessageHook;
                    }
                }

                Logger &logger = log();
                logger.info(
                    "input::Input: Starting with {} binding(s), poll interval {}ms",
                    m_impl->m_pending.size(),
                    settings.poll_interval.count()
                );
                for (const auto &binding : m_impl->m_pending)
                {
                    logger.trace(
                        "input::Input: Registered {} binding \"{}\" with {} key(s)",
                        to_string(binding.trigger),
                        binding.name,
                        binding.keys.size()
                    );
                }

                // Seed the engine with a COPY of the staged bindings and clear them only after start() succeeds.
                // InputPoller::start() throws std::system_error when the poll thread or its module reference cannot be
                // created, and the poller (sole owner of a moved-in vector) is destroyed during unwind. Moving
                // m_pending in before that point destroys the staged set with it, so a later retry hits the
                // empty-pending no-op above and silently loses the bindings. The copy is confined to this cold
                // path.
                auto poller = std::make_shared<detail::InputPoller>(
                    m_impl->m_pending,
                    settings.poll_interval,
                    settings.require_focus,
                    settings.gamepad_index,
                    settings.trigger_threshold,
                    settings.stick_threshold,
                    resolved_backend,
                    resolved_host,
                    settings.wheel_target_thread_id
                );
                if (resolved_backend == Input::WheelBackend::ExternalHost)
                {
                    const std::uint64_t candidate_revision = m_impl->m_start_revision;
                    // The loader supplies this function pointer. B-101 requires the call outside the facade lock.
                    lock.unlock();
                    const int32_t host_status = poller->prepare_wheel_source();
                    if (host_status != DMK_WHEELHOST_OK)
                    {
                        poller.reset();
                    }
                    lock.lock();
                    if (m_impl->m_poller || m_impl->m_start_revision != candidate_revision ||
                        m_impl->m_callback_drain_active.load(std::memory_order_seq_cst) ||
                        detail::input_callback_drain_pending() || !detail::input_callback_admission_open())
                    {
                        lock.unlock();
                        poller.reset();
                        return std::unexpected(Error{ErrorCode::ShutdownInProgress, "input::start"});
                    }
                    if (host_status != DMK_WHEELHOST_OK)
                    {
                        if (settings.wheel_host_required)
                        {
                            const std::int64_t signed_status = host_status;
                            const auto detail =
                                static_cast<std::uintptr_t>(signed_status < 0 ? -signed_status : signed_status);
                            return std::unexpected(Error{ErrorCode::SystemCallFailed, "input::start", detail});
                        }
                        log().warning(
                            "input::Input: optional wheel host rejected the lease; using the local "
                            "MessageHook backend."
                        );
                        resolved_backend = Input::WheelBackend::MessageHook;
                        resolved_host = nullptr;
                        poller = std::make_shared<detail::InputPoller>(
                            m_impl->m_pending,
                            settings.poll_interval,
                            settings.require_focus,
                            settings.gamepad_index,
                            settings.trigger_threshold,
                            settings.stick_threshold,
                            resolved_backend,
                            resolved_host,
                            settings.wheel_target_thread_id
                        );
                    }
                }
                try
                {
                    poller->start();
                }
                catch (...)
                {
                    lock.unlock();
                    poller.reset();
                    throw;
                }
                // Precommit the non-draining fallback before publishing the poller. A clean shutdown clears this
                // cycle only after the join and rundown; every uncertain path leaves the complete owner reachable
                // without allocating during teardown.
                poller->retain_owner_for_abandonment(poller);
                m_impl->m_pending.clear();
                m_impl->advance_start_revision();
                m_impl->m_poller = poller;
                m_impl->m_active.store(poller, std::memory_order_release);
                m_impl->m_running.store(true, std::memory_order_release);
                return {};
            }
            catch (const std::system_error &e)
            {
                return std::unexpected(
                    Error{ErrorCode::SystemCallFailed, "input::start", static_cast<std::uintptr_t>(e.code().value())}
                );
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "input::start"});
            }
        }

        void Input::shutdown() noexcept
        {
            if (is_inert())
            {
                return;
            }

            // B-100 requires this gate before any m_mutex access.
            if (!detail::blocking_teardown_permitted())
            {
                Impl *const impl = m_impl.get();
                bool active = false;
                if (!impl->m_vetoed_retained
                         .compare_exchange_strong(active, true, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
                // Stop a running poll loop without a wait: the poller's own gate detaches instead of joining, so the
                // retained owner keeps a stopped engine rather than a live callback source. Process exit skips the
                // stop, because the OS already terminated the poll thread and no lock acquisition is safe there.
                if (detail::lifecycle().loader_context() != detail::LoaderContext::ProcessExit)
                {
                    if (const std::shared_ptr<detail::InputPoller> poller =
                            impl->m_active.load(std::memory_order_acquire))
                    {
                        poller->shutdown();
                    }
                }
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Input);
#if defined(DMK_ENABLE_TEST_SEAMS)
                s_vetoed_retained_impl.store(impl, std::memory_order_release);
#endif
                return;
            }

            std::shared_ptr<detail::InputPoller> local_poller;
            std::vector<detail::InputBinding> retired;

            {
                std::lock_guard lock(m_impl->m_mutex);
                // Clear the atomic shared_ptr before releasing the poller so a concurrent is_active() caller holds a
                // valid shared_ptr.
                m_impl->m_active.store(nullptr, std::memory_order_release);
                m_impl->m_running.store(false, std::memory_order_release);
                local_poller = std::move(m_impl->m_poller);
                if (!m_impl->m_pending.empty())
                {
                    m_impl->advance_start_revision();
                }
                retired.swap(m_impl->m_pending);
            }
            // Drop staged capture owners before poller shutdown.
            retired.clear();

            if (local_poller)
            {
                local_poller->shutdown();

                if (local_poller->self_retiring())
                {
                    // shutdown() was reached from a binding callback, so this thread IS the poll thread. Its rundown
                    // (join, detour uninstall, final on_state_change(false)) must happen after the callback returns
                    // and off this thread. Hand the facade's reference to the process-lifetime reaper, which drops it
                    // once shutdown() has joined the body there; ~InputPoller then sees a completed rundown.
                    std::shared_ptr<void> owner = std::move(local_poller);
                    const auto retire = [](void *raw_owner) noexcept -> bool
                    {
                        auto *const poller = static_cast<detail::InputPoller *>(raw_owner);
                        poller->shutdown();
                        return !poller->requires_abandonment();
                    };
                    if (!detail::reap_shared_owner(owner, retire))
                    {
                        // The precommitted self-keepalive retains the complete poller when no reaper can accept it.
                        // Stop was already requested, so the loop exits after this callback without losing its state.
                        diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::Input);
                    }
                }
            }
        }

        bool Input::is_running() const noexcept
        {
            return !is_inert() && m_impl->m_running.load(std::memory_order_acquire);
        }

        std::size_t Input::binding_count() const noexcept
        {
            if (is_inert())
            {
                return 0;
            }

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
            auto active_poller = poller_snapshot();
            return active_poller ? active_poller->is_binding_active(name) : false;
        }

        BindingToken Input::acquire_token(std::string_view name) const noexcept
        {
            auto active_poller = poller_snapshot();
            return active_poller ? active_poller->acquire_binding_token(name) : BindingToken{};
        }

        bool Input::is_active(const BindingToken &token) const noexcept
        {
            auto active_poller = poller_snapshot();
            return active_poller ? active_poller->is_binding_active(token) : false;
        }

        bool Input::token_current(const BindingToken &token) const noexcept
        {
            auto active_poller = poller_snapshot();
            return active_poller ? active_poller->binding_token_current(token) : false;
        }

        ConsumeCapacity Input::consume_capacity() const noexcept
        {
            const auto active_poller = poller_snapshot();
            return active_poller ? active_poller->consume_capacity() : ConsumeCapacity{};
        }

        Input::WheelSourceHealth Input::wheel_source_health() const noexcept
        {
            const auto active_poller = poller_snapshot();
            return active_poller ? active_poller->wheel_source_health() : WheelSourceHealth::Inactive;
        }

        bool Input::is_inert() const noexcept
        {
            const Impl *const impl = m_impl.get();
            return impl == nullptr || impl->m_vetoed_retained.load(std::memory_order_acquire);
        }

        std::shared_ptr<detail::InputPoller> Input::poller_snapshot() const noexcept
        {
            return is_inert() ? nullptr : m_impl->m_active.load(std::memory_order_acquire);
        }

        Result<void> Input::rebind(std::string_view name, KeyComboList combos) noexcept
        {
            if (is_inert())
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "input::rebind"});
            }

            std::shared_ptr<detail::InputPoller> local_poller;
            std::vector<detail::InputBinding> retired;
            std::vector<detail::InputBinding> rebuilt;

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
                        (void)log()
                            .try_log(LogLevel::Debug, "input::Input: rebind(\"{}\") ignored: name not found", name);
                        return std::unexpected(Error{ErrorCode::InvalidArg, "input::rebind"});
                    }

                    if (indices.size() == combos.size())
                    {
                        // Each replacement copies the entry's gate reference, so the locked overwrite destroys no
                        // consumer callable.
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
                        m_impl->advance_start_revision();
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

                    rebuilt.reserve(m_impl->m_pending.size() - indices.size() + append_count);
                    retired.reserve(indices.size());
                    std::size_t cursor = 0;
                    for (std::size_t skip : indices)
                    {
                        for (std::size_t i = cursor; i < skip; ++i)
                        {
                            rebuilt.push_back(std::move(m_impl->m_pending[i]));
                        }
                        retired.push_back(std::move(m_impl->m_pending[skip]));
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
                    m_impl->m_pending.swap(rebuilt);
                    m_impl->advance_start_revision();
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

            // Forward to the live poller outside m_mutex. Preserve the caller and resource failure classes.
            switch (local_poller->update_combos(name, combos))
            {
            case detail::InputPoller::ComboUpdate::Updated:
                return {};
            case detail::InputPoller::ComboUpdate::NameAbsent:
                return std::unexpected(Error{ErrorCode::InvalidArg, "input::rebind"});
            case detail::InputPoller::ComboUpdate::ResourceFailure:
                return std::unexpected(Error{ErrorCode::OutOfMemory, "input::rebind"});
            }
            return std::unexpected(Error{ErrorCode::InvalidArg, "input::rebind"});
        }

        void Input::set_consume(std::string_view name, bool consume) noexcept
        {
            if (is_inert())
            {
                return;
            }

            std::shared_ptr<detail::InputPoller> live_poller;

            {
                std::lock_guard lock(m_impl->m_mutex);
                if (m_impl->m_poller)
                {
                    live_poller = m_impl->m_poller;
                }
                else
                {
                    bool changed = false;
                    for (auto &binding : m_impl->m_pending)
                    {
                        if (binding.name == name && binding.consume != consume)
                        {
                            binding.consume = consume;
                            changed = true;
                        }
                    }
                    if (changed)
                    {
                        m_impl->advance_start_revision();
                    }
                    return;
                }
            }

            // Forward outside m_mutex so the poller's exclusive binding lock cannot deadlock against a caller holding
            // m_mutex (matches register_combo).
            live_poller->set_consume(name, consume);
        }

        void Input::set_consume_by_owner(std::uint64_t owner, bool consume) noexcept
        {
            // Identity-keyed counterpart to set_consume(name), used by a consume guard's teardown so an empty-name
            // binding (absent from the name index) still has its suppression lifted. Mirrors set_consume's live-vs-
            // pending routing: clear on the live poller if running, else on the staged bindings for the next start().
            if (is_inert())
            {
                return;
            }

            std::shared_ptr<detail::InputPoller> live_poller;

            {
                std::lock_guard lock(m_impl->m_mutex);
                if (m_impl->m_poller)
                {
                    live_poller = m_impl->m_poller;
                }
                else
                {
                    bool changed = false;
                    if (owner != 0)
                    {
                        for (auto &binding : m_impl->m_pending)
                        {
                            if (binding.consume_owner == owner && binding.consume != consume)
                            {
                                binding.consume = consume;
                                changed = true;
                            }
                        }
                    }
                    if (changed)
                    {
                        m_impl->advance_start_revision();
                    }
                    return;
                }
            }

            // Forward outside m_mutex so the poller's exclusive binding lock cannot deadlock against a caller holding
            // m_mutex (matches register_combo).
            live_poller->set_consume_by_owner(owner, consume);
        }

        void Input::set_require_focus(bool require_focus) noexcept
        {
            if (is_inert())
            {
                return;
            }

            std::lock_guard lock(m_impl->m_mutex);
            if (m_impl->m_settings.require_focus != require_focus)
            {
                m_impl->m_settings.require_focus = require_focus;
                m_impl->advance_start_revision();
            }
            if (m_impl->m_poller)
            {
                m_impl->m_poller->set_require_focus(require_focus);
            }
        }

        std::size_t Input::remove_bindings_by_name(std::string_view name, bool invoke_callbacks) noexcept
        {
            if (is_inert())
            {
                return 0;
            }

            std::shared_ptr<detail::InputPoller> live_poller;
            std::size_t removed_pending = 0;
            std::vector<detail::InputBinding> retired;
            std::vector<detail::InputBinding> staged;

            try
            {
                std::lock_guard lock(m_impl->m_mutex);
                if (m_impl->m_poller)
                {
                    live_poller = m_impl->m_poller;
                }
                else
                {
                    removed_pending = static_cast<std::size_t>(std::ranges::count_if(
                        m_impl->m_pending,
                        [name](const detail::InputBinding &b) { return b.name == name; }
                    ));
                    if (removed_pending != 0)
                    {
                        // Before mutation, reserve both batches so allocation failure preserves the staged set.
                        retired.reserve(removed_pending);
                        staged.reserve(m_impl->m_pending.size() - removed_pending);
                        for (detail::InputBinding &entry : m_impl->m_pending)
                        {
                            (entry.name == name ? retired : staged).push_back(std::move(entry));
                        }
                        m_impl->m_pending.swap(staged);
                        m_impl->advance_start_revision();
                    }
                }
            }
            catch (...)
            {
                (void)log().try_log(
                    LogLevel::Error,
                    "input::Input: out of memory in remove_bindings_by_name. Bindings unchanged"
                );
                return 0;
            }

            if (live_poller)
            {
                return live_poller->remove_bindings_by_name(name, invoke_callbacks);
            }
            return removed_pending;
        }

        void Input::clear_bindings(bool invoke_callbacks) noexcept
        {
            if (is_inert())
            {
                return;
            }

            std::shared_ptr<detail::InputPoller> live_poller;
            std::vector<detail::InputBinding> retired;

            {
                std::lock_guard lock(m_impl->m_mutex);
                if (!m_impl->m_pending.empty())
                {
                    m_impl->advance_start_revision();
                }
                retired.swap(m_impl->m_pending);
                if (m_impl->m_poller)
                {
                    live_poller = m_impl->m_poller;
                }
            }
            retired.clear();

            if (live_poller)
            {
                live_poller->clear_bindings(invoke_callbacks);
            }
        }

        bool Input::retire_gates_for_unload(
            std::span<const std::string_view> binding_names,
            bool every_binding,
            std::chrono::steady_clock::time_point deadline
        ) noexcept
        {
            if (is_inert())
            {
                return true;
            }

            std::shared_ptr<detail::InputPoller> live_poller;
            std::vector<std::shared_ptr<detail::BindingGate>> pending_gates;
            bool collected = true;

            {
                std::lock_guard lock(m_impl->m_mutex);
                live_poller = m_impl->m_poller;
                if (!live_poller)
                {
                    // Staged but never started: the gates exist and the guards are already handed out, so a pending
                    // binding's callback outlives removal exactly as a live one does.
                    try
                    {
                        for (const detail::InputBinding &staged : m_impl->m_pending)
                        {
                            const bool selected =
                                every_binding || std::ranges::any_of(
                                                     binding_names,
                                                     [&staged](std::string_view name) { return staged.name == name; }
                                                 );
                            if (selected && staged.gate)
                            {
                                pending_gates.push_back(staged.gate);
                            }
                        }
                    }
                    catch (...)
                    {
                        collected = false;
                    }
                }
            }

            if (live_poller)
            {
                if (every_binding)
                {
                    return live_poller->retire_all_gates(deadline);
                }
                bool retired_all = true;
                for (const std::string_view name : binding_names)
                {
                    if (!live_poller->retire_gates_by_name(name, deadline))
                    {
                        retired_all = false;
                    }
                }
                return retired_all;
            }

            // Off m_mutex: a retired hold delivers its balancing edge, and that consumer code may call back into the
            // facade. The gates are kept alive by the copies taken above, so a concurrent clear cannot free them here.
            for (const auto &gate : pending_gates)
            {
                try
                {
                    if (!gate->retire(deadline))
                    {
                        collected = false;
                    }
                }
                catch (...)
                {
                    // retire() moved the callback out before invoking it, so it is destroyed even on this path and
                    // only the consumer's balancing edge failed.
                }
            }
            return collected;
        }

        CallbackDrainStatus Input::prepare_logic_dll_unload(
            std::span<const std::string_view> binding_names,
            std::chrono::milliseconds timeout
        ) noexcept
        {
            if (detail::current_thread_in_delivery())
            {
                return CallbackDrainStatus::SelfDelivery;
            }
            if (is_inert())
            {
                return CallbackDrainStatus::Drained;
            }
            if (m_impl->m_callback_drain_active.exchange(true, std::memory_order_seq_cst))
            {
                return CallbackDrainStatus::InProgress;
            }

            detail::mark_input_callback_drain_pending();
            const auto deadline = detail::drain_deadline(timeout);

            CallbackDrainStatus status = CallbackDrainStatus::Drained;
            // Both refusals are the same outcome, so they share one branch and short-circuit order keeps the admission
            // check first. An unretired gate means either a selected binding was still delivering at the deadline, in
            // which case its callback is deliberately left alive because destroying a callable a poll thread is
            // executing would free the code out from under it, or the gate handles could not be collected at all under
            // memory pressure. Neither outcome has established that the callbacks are gone, so both refuse the unmap.
            if (!await_admission_commits(m_impl->m_admission_commits_inflight, deadline) ||
                !retire_gates_for_unload(binding_names, false, deadline))
            {
                status = CallbackDrainStatus::TimedOut;
            }
            else
            {
                bool retire_failed = false;
                for (const std::string_view name : binding_names)
                {
                    (void)remove_bindings_by_name(name, false);

                    std::shared_ptr<detail::InputPoller> live_poller;
                    bool pending_match = false;
                    {
                        std::lock_guard lock(m_impl->m_mutex);
                        pending_match = std::ranges::any_of(
                            m_impl->m_pending,
                            [name](const detail::InputBinding &binding) { return binding.name == name; }
                        );
                        live_poller = m_impl->m_poller;
                    }
                    if (pending_match || (live_poller && live_poller->has_bindings_by_name(name)))
                    {
                        retire_failed = true;
                        break;
                    }
                }

                if (retire_failed)
                {
                    status = CallbackDrainStatus::RetireFailed;
                }
                else if (!detail::await_staged_input_callbacks(deadline))
                {
                    status = CallbackDrainStatus::TimedOut;
                }
            }

            if (status == CallbackDrainStatus::Drained)
            {
                detail::resolve_input_callback_drain();
            }

            m_impl->m_callback_drain_active.store(false, std::memory_order_release);
            return status;
        }

        CallbackDrainStatus Input::prepare_logic_dll_unload_all(std::chrono::milliseconds timeout) noexcept
        {
            if (detail::current_thread_in_delivery())
            {
                return CallbackDrainStatus::SelfDelivery;
            }
            if (is_inert())
            {
                return CallbackDrainStatus::Drained;
            }
            if (m_impl->m_callback_drain_active.exchange(true, std::memory_order_seq_cst))
            {
                return CallbackDrainStatus::InProgress;
            }

            detail::mark_input_callback_drain_pending();
            const auto deadline = detail::drain_deadline(timeout);

            CallbackDrainStatus status = CallbackDrainStatus::Drained;
            // One branch for both refusals, for the reason given in prepare_logic_dll_unload.
            if (!await_admission_commits(m_impl->m_admission_commits_inflight, deadline) ||
                !retire_gates_for_unload({}, true, deadline))
            {
                status = CallbackDrainStatus::TimedOut;
            }
            else
            {
                clear_bindings(false);
                if (binding_count() != 0)
                {
                    status = CallbackDrainStatus::RetireFailed;
                }
                else if (!detail::await_staged_input_callbacks(deadline))
                {
                    status = CallbackDrainStatus::TimedOut;
                }
            }

            if (status == CallbackDrainStatus::Drained)
            {
                detail::resolve_input_callback_drain();
            }

            m_impl->m_callback_drain_active.store(false, std::memory_order_release);
            return status;
        }

        // Free-function ergonomics

        Result<BindingGuard> register_combo(ComboBinding binding) noexcept
        {
            return Input::instance().register_combo(std::move(binding));
        }

        Scope &scope() noexcept
        {
            alignas(Scope) static unsigned char storage[sizeof(Scope)];
            static Scope *const process_scope = ::new (static_cast<void *>(storage)) Scope();
            return *process_scope;
        }
    } // namespace input
} // namespace DetourModKit

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    // Friend-accessor bodies live beside the facade state they reach. The unnamed-namespace seam objects above are
    // reachable through the input namespace by qualified lookup.
    void InputTestSeams::set_callback_admission_commit_seam_for_test(CallbackAdmissionCommitSeam seam) noexcept
    {
        input::s_callback_admission_commit_seam.store(seam, std::memory_order_release);
    }

    void InputTestSeams::lock_facade_mutex_for_test() noexcept
    {
        input::Input::Impl *const impl = input::Input::instance().m_impl.get();
        input::s_test_locked_impl = impl;
        impl->m_mutex.lock();
    }

    void InputTestSeams::unlock_facade_mutex_for_test() noexcept
    {
        static_cast<input::Input::Impl *>(input::s_test_locked_impl)->m_mutex.unlock();
        input::s_test_locked_impl = nullptr;
    }

    bool InputTestSeams::reclaim_vetoed_impl_for_test() noexcept
    {
        void *const retained = input::s_vetoed_retained_impl.exchange(nullptr, std::memory_order_acq_rel);
        if (retained == nullptr)
        {
            return false;
        }
        input::Input &self = input::Input::instance();
        auto *const impl = static_cast<input::Input::Impl *>(retained);
        if (self.m_impl.get() != impl)
        {
            return false;
        }
        bool vetoed = true;
        return impl->m_vetoed_retained
            .compare_exchange_strong(vetoed, false, std::memory_order_acq_rel, std::memory_order_acquire);
    }

    bool InputTestSeams::adopt_intercept_owner_for_test() noexcept
    {
        input::Input &self = input::Input::instance();
        std::shared_ptr<InputPoller> live_poller;
        if (!self.is_inert())
        {
            std::lock_guard lock(self.m_impl->m_mutex);
            live_poller = self.m_impl->m_poller;
        }
        if (!live_poller)
        {
            return false;
        }
        if (!adopt_owner_for_test(live_poller->intercept_owner_for_test()))
        {
            return false;
        }
        live_poller->publish_consume_rules_for_test();
        return true;
    }
} // namespace DetourModKit::detail
#endif // DMK_ENABLE_TEST_SEAMS
