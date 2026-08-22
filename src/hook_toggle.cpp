/**
 * @file hook_toggle.cpp
 * @brief This TU implements Hook::enable and Hook::disable over the shared toggle publication order.
 */

#include "DetourModKit/hook.hpp"

#include "internal/diagnostics_population.hpp"
#include "internal/hook_backend.hpp"
#include "internal/hook_backend_visit.hpp"
#include "internal/hook_emission.hpp"
#include "internal/hook_ledger.hpp"
#include "internal/hook_patch_witness.hpp"
#include "internal/hook_publication.hpp"

#include "DetourModKit/logger.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace DetourModKit
{
    namespace hook
    {
        namespace
        {
            using DetourModKit::detail::apply_backend;
            using DetourModKit::detail::backend_value_or;
            using DetourModKit::detail::emit_lifecycle;
            using DetourModKit::detail::enable_patch_is_confirmed;
            using DetourModKit::detail::inline_trampoline;
            using DetourModKit::detail::LifecycleSnapshot;
            using DetourModKit::detail::PatchWitness;
            using DetourModKit::detail::snapshot_lifecycle;
            using DetourModKit::detail::try_backend_disable;
            using DetourModKit::detail::try_backend_enable;
            using DetourModKit::detail::witness_description;
            using DetourModKit::detail::witness_of;
            using DetourModKit::detail::witness_permits_write;

            enum class ToggleWarningKind : std::uint8_t
            {
                None,
                EnableRefused,
                EnableReconciled,
                DisableRefused,
                DisableReconciled
            };

            /**
             * @brief Defers one warning until later-declared lock guards release.
             * @details Declare it before the call-gate lock and target slot. Its destructor runs after both guards
             *          release.
             */
            class DeferredToggleWarning
            {
            public:
                DeferredToggleWarning() = default;

                ~DeferredToggleWarning() noexcept
                {
                    switch (m_kind)
                    {
                    case ToggleWarningKind::None:
                        return;
                    case ToggleWarningKind::EnableRefused:
                        (void)log().try_log(LogLevel::Warning, "hook: '{}' at 0x{:0{}X} refused enable: {}.", m_name,
                                            m_target, sizeof(std::uintptr_t) * 2, witness_description(m_witness));
                        return;
                    case ToggleWarningKind::EnableReconciled:
                        (void)log().try_log(
                            LogLevel::Warning,
                            "hook: '{}' at 0x{:0{}X} has original bytes under an active state. This enable retries "
                            "the arm.",
                            m_name, m_target, sizeof(std::uintptr_t) * 2);
                        return;
                    case ToggleWarningKind::DisableRefused:
                        (void)log().try_log(LogLevel::Warning, "hook: '{}' at 0x{:0{}X} refused disable: {}.", m_name,
                                            m_target, sizeof(std::uintptr_t) * 2, witness_description(m_witness));
                        return;
                    case ToggleWarningKind::DisableReconciled:
                        (void)log().try_log(
                            LogLevel::Warning,
                            "hook: '{}' at 0x{:0{}X} has owned bytes under a disabled state. This disable retries "
                            "the restore.",
                            m_name, m_target, sizeof(std::uintptr_t) * 2);
                        return;
                    }
                }

                DeferredToggleWarning(const DeferredToggleWarning &) = delete;
                DeferredToggleWarning &operator=(const DeferredToggleWarning &) = delete;
                DeferredToggleWarning(DeferredToggleWarning &&) = delete;
                DeferredToggleWarning &operator=(DeferredToggleWarning &&) = delete;

                /// Stores one warning and contains any name-copy failure.
                void arm(ToggleWarningKind kind, const std::string &name, std::uintptr_t target,
                         PatchWitness witness = PatchWitness::Indeterminate) noexcept
                {
                    m_kind = kind;
                    m_target = target;
                    m_witness = witness;
                    try
                    {
                        m_name = name;
                    }
                    catch (...)
                    {
                    }
                }

            private:
                ToggleWarningKind m_kind{ToggleWarningKind::None};
                std::string m_name;
                std::uintptr_t m_target{0};
                PatchWitness m_witness{PatchWitness::Indeterminate};
            };

            /**
             * @class TargetSlot
             * @brief Holds a target's ledger write slot across a toggle that can alter its bytes.
             * @details The slot blocks every same-target install while held, so it MUST be released before the
             *          caller runs user code or takes the loader lock.
             */
            class TargetSlot
            {
            public:
                TargetSlot(std::uintptr_t target, std::uint64_t id) noexcept
                    : m_target(target), m_id(id),
                      m_newer(DetourModKit::detail::HookLedger::instance().acquire_target_slot(target, id))
                {
                }

                ~TargetSlot() noexcept { release(); }

                TargetSlot(const TargetSlot &) = delete;
                TargetSlot &operator=(const TargetSlot &) = delete;
                TargetSlot(TargetSlot &&) = delete;
                TargetSlot &operator=(TargetSlot &&) = delete;

                void release() noexcept
                {
                    if (!std::exchange(m_released, true))
                    {
                        DetourModKit::detail::HookLedger::instance().release_target_slot(m_target, m_id);
                    }
                }

                /// Reports whether this hook is the newest live layer with authority to write target bytes.
                [[nodiscard]] bool is_top_layer() const noexcept { return m_newer == 0; }

            private:
                std::uintptr_t m_target;
                std::uint64_t m_id;
                std::size_t m_newer;
                bool m_released{false};
            };

            /**
             * @brief Writes the published state, its population unit, and the gate callable for one outcome.
             * @details Runs under the call gate that serialized the transition. An armed inline hook publishes its
             *          trampoline, while a mid hook gate stays null. A disarm clears the callable, so a later call()
             *          returns the inactive default.
             */
            template <class ImplT, class GateT> void write_toggle_state(ImplT &impl, GateT &gate, bool armed) noexcept
            {
                if (armed)
                {
                    impl.status.store(HookState::Active, std::memory_order_release);
                    DetourModKit::detail::hook_population::record_enabled();
                    gate.callable = inline_trampoline(impl.backend);
                }
                else
                {
                    impl.status.store(HookState::Disabled, std::memory_order_release);
                    DetourModKit::detail::hook_population::record_disabled();
                    gate.callable = nullptr;
                }
            }

            /**
             * @brief Rewrites a published state when attributable target bytes contradict it.
             * @details The rewrite updates population, gate callable, and backend flag before the caller retries.
             *          The caller performs the retry under the same locks.
             * @note It emits no event because the caller still owns the call gate and target slot.
             */
            template <class ImplT, class GateT>
            void reconcile_published_state(ImplT &impl, GateT &gate, bool armed) noexcept
            {
                write_toggle_state(impl, gate, armed);
                (void)apply_backend(impl.backend,
                                    [armed](auto &backend) noexcept { backend.reconcile_enabled(armed); });
            }

            /**
             * @brief Publishes one enable or disable outcome in the single toggle order.
             * @details The identity snapshot, slot release, unlock, and emission follow the state write
             *          (HookLifecycleName.*). The caller must read no hook state after this call because a subscriber
             *          can destroy the hook before emission ends.
             */
            template <class ImplT, class GateT>
            void publish_toggle(ImplT &impl, GateT &gate, TargetSlot &slot,
                                std::unique_lock<std::recursive_mutex> &guard, bool armed) noexcept
            {
                write_toggle_state(impl, gate, armed);
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *probe = DetourModKit::detail::g_hook_toggle_publication_probe)
                {
                    const HookState expected = armed ? HookState::Active : HookState::Disabled;
                    const bool callable_matches = (gate.callable != nullptr) == (armed && impl.is_inline);
                    probe(armed, guard.owns_lock(), impl.status.load(std::memory_order_relaxed) == expected,
                          callable_matches);
                }
#endif
                const LifecycleSnapshot snapshot = snapshot_lifecycle(impl.name, impl.ledger_id, impl.is_inline);
                slot.release();
                guard.unlock();
                emit_lifecycle(snapshot.name, snapshot.ledger_id, snapshot.kind,
                               armed ? diagnostics::HookTransition::Enabled : diagnostics::HookTransition::Disabled);
            }
        } // namespace

        Result<void> Hook::enable() noexcept
        {
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::enable"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::Enable);
#endif
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            // A live handle always has a gate. The null check fails closed on the broken invariant.
            const std::shared_ptr<CallGate> gate = m_gate.load(std::memory_order_acquire);
            if (!gate)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            DeferredToggleWarning deferred_warning;
            std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
            if (!guard.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            if (!backend_value_or(m_impl->backend, false,
                                  [](auto &backend) noexcept { return static_cast<bool>(backend); }))
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::enable"});
            }

            // Only the newest live layer can write target bytes. The slot makes the {decide, patch} pair atomic
            // against a concurrent same-target install. Claim it before the state CAS so a refusal changes nothing.
            TargetSlot slot(m_impl->target, m_impl->ledger_id);
            if (!slot.is_top_layer())
            {
                return std::unexpected(Error{ErrorCode::LayerConflict, "hook::enable", m_impl->target});
            }

            // Classify before the transition claim. The backend emits its jmp over the current bytes. Foreign or
            // unreadable bytes must refuse here while the hook remains as the caller left it.
            const PatchWitness before = witness_of(m_impl->backend);
            if (!witness_permits_write(before))
            {
                deferred_warning.arm(ToggleWarningKind::EnableRefused, m_impl->name, m_impl->target, before);
                return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable", m_impl->target});
            }

            HookState expected = HookState::Disabled;
            if (!m_impl->status.compare_exchange_strong(expected, HookState::Enabling, std::memory_order_acq_rel))
            {
                if (expected != HookState::Active)
                {
                    return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
                }
                // Active answers the request only over this hook's own patch. Here `before` is Original or
                // OwnedPatch, because every other class refused above.
                if (before == PatchWitness::OwnedPatch)
                {
                    return {};
                }
                // The bytes prove the target is unpatched. Rewrite the stale claim, then arm through the ordinary
                // path so byte authority and the population tally both stay exact.
                deferred_warning.arm(ToggleWarningKind::EnableReconciled, m_impl->name, m_impl->target);
                reconcile_published_state(*m_impl, *gate, false);
                m_impl->status.store(HookState::Enabling, std::memory_order_release);
            }
            // Create leaves the target unpatched, so this is the first operation that can make the detour reachable.
            const bool backend_enabled = backend_value_or(m_impl->backend, false, [](auto &backend) noexcept
                                                          { return try_backend_enable(backend); });
            const bool patch_confirmed = backend_value_or(m_impl->backend, false, [](auto &backend) noexcept
                                                          { return enable_patch_is_confirmed(backend); });
            if (backend_enabled && patch_confirmed)
            {
                publish_toggle(*m_impl, *gate, slot, guard, true);
                return {};
            }
            // A backend error says nothing about the target. The patch commits inside the thread trap transaction, so
            // an error can sit over a fully armed target. Witness the bytes before publication.
            if (!backend_enabled)
            {
                const bool mutation_committed =
                    backend_value_or(m_impl->backend, false, [](auto &backend) noexcept { return backend.enabled(); });
                const PatchWitness after_failure = witness_of(m_impl->backend);
                if (mutation_committed && after_failure != PatchWitness::Original)
                {
                    // The mutation committed, so Original is the only witness that proves the hook disarmed. Retain
                    // the conservative Active state and report that safe disarm lacks confirmation.
                    const std::uintptr_t armed_target = m_impl->target;
                    publish_toggle(*m_impl, *gate, slot, guard, true);
                    const ErrorCode code =
                        after_failure == PatchWitness::OwnedPatch ? ErrorCode::BackendFailed : ErrorCode::DisableFailed;
                    return std::unexpected(Error{code, "hook::enable", armed_target});
                }
                // The backend committed no mutation, or the target already returned to Original. This hook is disarmed.
                if (after_failure == PatchWitness::Original)
                {
                    (void)apply_backend(m_impl->backend,
                                        [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                }
                m_impl->status.store(HookState::Disabled, std::memory_order_release);
                return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable"});
            }

            // The backend reported success but the bytes are not this hook's patch. Publish Disabled only after a
            // compensation disable leaves the prologue at its original bytes. The rollback receives the same
            // classification as any other toggle. A third party that took the window can otherwise lose its bytes to
            // the unconditional restore. Refusal therefore falls through to the Active publication below.
            if (const PatchWitness rollback_before = witness_of(m_impl->backend);
                witness_permits_write(rollback_before))
            {
                (void)backend_value_or(m_impl->backend, false,
                                       [](auto &backend) noexcept { return try_backend_disable(backend); });
                if (witness_of(m_impl->backend) == PatchWitness::Original)
                {
                    (void)apply_backend(m_impl->backend,
                                        [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                    m_impl->status.store(HookState::Disabled, std::memory_order_release);
                    return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable"});
                }
            }

            // A completed restore can be followed by a newer or uncertain owner. Retain backend reachability so
            // is_enabled() and a later disable retry agree with the conservative Active state.
            (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.reconcile_enabled(true); });
            publish_toggle(*m_impl, *gate, slot, guard, true);
            return std::unexpected(Error{ErrorCode::DisableFailed, "hook::enable"});
        }

        Result<void> Hook::disable() noexcept
        {
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::disable"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::Disable);
#endif
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            const std::shared_ptr<CallGate> gate = m_gate.load(std::memory_order_acquire);
            if (!gate)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            DeferredToggleWarning deferred_warning;
            std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
            if (!guard.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            if (!backend_value_or(m_impl->backend, false,
                                  [](auto &backend) noexcept { return static_cast<bool>(backend); }))
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::disable"});
            }

            // Only the newest live layer can write target bytes. A restore of this hook's saved prologue below a newer
            // layer clobbers it. Refuse without any mutation.
            TargetSlot slot(m_impl->target, m_impl->ledger_id);
            if (!slot.is_top_layer())
            {
                return std::unexpected(Error{ErrorCode::LayerConflict, "hook::disable", m_impl->target});
            }

            // Classify before the transition claim (see enable()). The unconditional prologue restore clobbers a
            // foreign writer's bytes. Refuse and leave the hook Active.
            const PatchWitness before = witness_of(m_impl->backend);
            if (!witness_permits_write(before))
            {
                deferred_warning.arm(ToggleWarningKind::DisableRefused, m_impl->name, m_impl->target, before);
                return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable", m_impl->target});
            }

            HookState expected = HookState::Active;
            if (!m_impl->status.compare_exchange_strong(expected, HookState::Disabling, std::memory_order_acq_rel))
            {
                if (expected != HookState::Disabled)
                {
                    return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
                }
                // Disabled answers the request only over the saved prologue (see enable() for the polarity).
                if (before == PatchWitness::Original)
                {
                    return {};
                }
                deferred_warning.arm(ToggleWarningKind::DisableReconciled, m_impl->name, m_impl->target);
                reconcile_published_state(*m_impl, *gate, true);
                m_impl->status.store(HookState::Disabling, std::memory_order_release);
            }
            // Confirm the saved prologue is back before Disabled publication. The witness is taken whatever the
            // backend returns. An error can sit over restored bytes. A success without byte corroboration must not
            // publish Disabled.
            const bool backend_disabled = backend_value_or(m_impl->backend, false, [](auto &backend) noexcept
                                                           { return try_backend_disable(backend); });
            const PatchWitness after = witness_of(m_impl->backend);
            if (after == PatchWitness::Original)
            {
                (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                const std::uintptr_t target = m_impl->target;
                publish_toggle(*m_impl, *gate, slot, guard, false);
                if (!backend_disabled)
                {
                    // The disarm took effect, but the backend reported a post-commit failure (its page-protection
                    // restore). Report it rather than swallow it.
                    return std::unexpected(Error{ErrorCode::BackendFailed, "hook::disable", target});
                }
                return {};
            }
            // A completed restore can be followed by a newer or uncertain owner. Retain backend reachability so
            // is_enabled() and a later disable retry agree with the conservative Active state.
            (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.reconcile_enabled(true); });
            m_impl->status.store(HookState::Active, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable"});
        }
    } // namespace hook
} // namespace DetourModKit
