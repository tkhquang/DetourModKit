/**
 * @file hook_toggle.cpp
 * @brief This TU implements Hook::enable, Hook::disable, and the HookStack::install arm over the shared toggle
 *        publication order.
 */

#include "DetourModKit/hook.hpp"

#include "internal/diagnostics_population.hpp"
#include "internal/hook_backend.hpp"
#include "internal/hook_backend_visit.hpp"
#include "internal/hook_coordinator.hpp"
#include "internal/hook_emission.hpp"
#include "internal/hook_ledger.hpp"
#include "internal/hook_patch_witness.hpp"
#include "internal/hook_publication.hpp"

#include "DetourModKit/logger.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>

namespace DetourModKit
{
    namespace hook
    {
        namespace
        {
            using DetourModKit::detail::apply_backend;
            using DetourModKit::detail::arm_witness_of;
            using DetourModKit::detail::backend_claimed;
            using DetourModKit::detail::backend_value_or;
            using DetourModKit::detail::CoordinatorRefusal;
            using DetourModKit::detail::emit_lifecycle;
            using DetourModKit::detail::enable_patch_is_confirmed;
            using DetourModKit::detail::inline_trampoline;
            using DetourModKit::detail::LifecycleSnapshot;
            using DetourModKit::detail::PatchWitness;
            using DetourModKit::detail::snapshot_lifecycle;
            using DetourModKit::detail::switch_backend;
            using DetourModKit::detail::try_backend_disable;
            using DetourModKit::detail::try_backend_enable;
            using DetourModKit::detail::witness_description;
            using DetourModKit::detail::witness_of;
            using DetourModKit::detail::witness_permits_write;
            using DetourModKit::detail::witness_promotes_arm;

            /**
             * @brief Defers one toggle log line until later-declared lock guards release.
             * @details Declare it before the call-gate lock and target slot. Its destructor runs after both guards
             *          release. HookToggleWarning.* pins the witness and bypass texts, HookLayerBypass.* pins the
             *          layer-count bypass text, and Lifecycle.RouteCopiesReportCoordinatorRefusal pins the coordinator
             *          warning texts.
             */
            class DeferredToggleLog
            {
            public:
                DeferredToggleLog() = default;

                ~DeferredToggleLog() noexcept
                {
                    if (m_bypass)
                    {
                        log_bypass();
                        return;
                    }
                    if (m_text == nullptr)
                    {
                        return;
                    }
                    if (!m_reason.empty())
                    {
                        (void)log().try_log(
                            LogLevel::Warning,
                            "hook: '{}' at 0x{:0{}X} {}: {}.",
                            m_name,
                            m_target,
                            sizeof(std::uintptr_t) * 2,
                            m_text,
                            m_reason
                        );
                        return;
                    }
                    (void)log().try_log(
                        LogLevel::Warning,
                        "hook: '{}' at 0x{:0{}X} {}.",
                        m_name,
                        m_target,
                        sizeof(std::uintptr_t) * 2,
                        m_text
                    );
                }

                DeferredToggleLog(const DeferredToggleLog &) = delete;
                DeferredToggleLog &operator=(const DeferredToggleLog &) = delete;
                DeferredToggleLog(DeferredToggleLog &&) = delete;
                DeferredToggleLog &operator=(DeferredToggleLog &&) = delete;

                /**
                 * @brief Stores one warning and contains any name-copy failure.
                 * @param text A string literal: only its pointer is stored.
                 * @param reason A static description that appends as ": <reason>", or empty.
                 */
                void
                arm(const char *text,
                    const std::string &name,
                    std::uintptr_t target,
                    std::string_view reason = {}) noexcept
                {
                    m_text = text;
                    m_target = target;
                    m_reason = reason;
                    copy_name(name);
                }

                /**
                 * @brief Stores one Info line for a bypass under a newer layer.
                 * @param newer_layers The newer hooks of this kit, or zero when @p witness or a coordinator refusal
                 *        proved the newer layer.
                 */
                void arm_bypass(
                    const std::string &name,
                    std::uintptr_t target,
                    std::size_t newer_layers,
                    std::optional<PatchWitness> witness
                ) noexcept
                {
                    m_bypass = true;
                    m_target = target;
                    m_newer_layers = newer_layers;
                    m_witness = witness;
                    copy_name(name);
                }

                /// Moves the stored warning out, so this object logs nothing. Returns the text and the reason.
                [[nodiscard]] std::pair<const char *, std::string_view> detach() noexcept
                {
                    return {std::exchange(m_text, nullptr), m_reason};
                }

            private:
                void copy_name(const std::string &name) noexcept
                {
                    try
                    {
                        m_name = name;
                    }
                    catch (...)
                    {
                    }
                }

                void log_bypass() const noexcept
                {
                    if (m_newer_layers != 0)
                    {
                        (void)log().try_log(
                            LogLevel::Info,
                            "hook: '{}' at 0x{:0{}X} bypassed under {} newer layer(s).",
                            m_name,
                            m_target,
                            sizeof(std::uintptr_t) * 2,
                            m_newer_layers
                        );
                        return;
                    }
                    (void)log().try_log(
                        LogLevel::Info,
                        "hook: '{}' at 0x{:0{}X} bypassed under a newer layer: {}.",
                        m_name,
                        m_target,
                        sizeof(std::uintptr_t) * 2,
                        m_witness
                            ? witness_description(*m_witness)
                            : DetourModKit::detail::coordinator_refusal_description(CoordinatorRefusal::LayerConflict)
                    );
                }

                const char *m_text{nullptr};
                std::string_view m_reason;
                std::string m_name;
                std::uintptr_t m_target{0};
                std::optional<PatchWitness> m_witness;
                std::size_t m_newer_layers{0};
                bool m_bypass{false};
            };

            /**
             * @class TargetSlot
             * @brief Holds a target's ledger write slot across a toggle that can alter its bytes.
             * @details The slot blocks every same-target install while held, so it MUST be released before the
             *          caller runs user code or takes the loader lock. A coordinator hold nests inside the slot and
             *          releases first (`[B-109]`).
             */
            class TargetSlot
            {
            public:
                /// Selects the slot that HookStack::install keeps from its reservation.
                struct Kept
                {
                };

                TargetSlot(std::uintptr_t target, std::uint64_t id) noexcept
                    : m_target(target), m_id(id),
                      m_newer(DetourModKit::detail::HookLedger::instance().acquire_target_slot(target, id))
                {
                }

                /**
                 * @brief Adopts the slot of HookLedger::commit_hook_keep_slot, whose install holds the coordinator.
                 * @details That call proved the hook the top layer of this kit. The install releases the slot and
                 *          emits the lifecycle event that @ref defer_emission records.
                 */
                TargetSlot(std::uintptr_t target, std::uint64_t id, Kept) noexcept
                    : m_target(target), m_id(id), m_newer(0), m_released(true), m_kept(true)
                {
                }

                ~TargetSlot() noexcept { release(); }

                TargetSlot(const TargetSlot &) = delete;
                TargetSlot &operator=(const TargetSlot &) = delete;
                TargetSlot(TargetSlot &&) = delete;
                TargetSlot &operator=(TargetSlot &&) = delete;

                /**
                 * @brief Waits until this thread holds the backend coordinator, so the backend toggle acquires nested.
                 * @return False for a refusal that no retry changes. @ref coordinator_refusal names it.
                 */
                [[nodiscard]] bool hold_coordinator(std::string_view where, std::string_view name) noexcept
                {
                    if (m_kept)
                    {
                        return true;
                    }
                    m_coordinator.emplace(DetourModKit::detail::WaitUntilHeld{where, name});
                    return static_cast<bool>(*m_coordinator);
                }

                /// Releases the coordinator. Returns false for a kept slot, whose install owns the coordinator.
                [[nodiscard]] bool release_coordinator() noexcept
                {
                    m_coordinator.reset();
                    return !m_kept;
                }

                /// Records @p transition for the install of a kept slot. Returns false, and records nothing, otherwise.
                [[nodiscard]] bool defer_emission(diagnostics::HookTransition transition) noexcept
                {
                    if (m_kept)
                    {
                        m_deferred_transition = transition;
                    }
                    return m_kept;
                }

                [[nodiscard]] std::optional<diagnostics::HookTransition> deferred_transition() const noexcept
                {
                    return m_deferred_transition;
                }

                [[nodiscard]] DetourModKit::detail::CoordinatorHoldRefusal coordinator_refusal() const noexcept
                {
                    return m_coordinator ? m_coordinator->refusal()
                                         : DetourModKit::detail::CoordinatorHoldRefusal::None;
                }

                void release() noexcept
                {
                    m_coordinator.reset();
                    if (!std::exchange(m_released, true))
                    {
                        DetourModKit::detail::HookLedger::instance().release_target_slot(m_target, m_id);
                    }
                }

                /// Reports whether this hook is the newest live layer with authority to write target bytes.
                [[nodiscard]] bool is_top_layer() const noexcept { return m_newer == 0; }

                /// Reports whether the ledger failed to decide a count. The layer order is then undecided.
                [[nodiscard]] bool unavailable() const noexcept
                {
                    return m_newer == DetourModKit::detail::HookLedger::SLOT_UNAVAILABLE;
                }

                /// Returns the newer hooks of this kit, or zero when the ledger failed to decide a count.
                [[nodiscard]] std::size_t newer_layers() const noexcept { return unavailable() ? 0 : m_newer; }

            private:
                std::uintptr_t m_target;
                std::uint64_t m_id;
                std::size_t m_newer;
                bool m_released{false};
                bool m_kept{false};
                std::optional<diagnostics::HookTransition> m_deferred_transition;
                std::optional<DetourModKit::detail::BackendCoordinatorHold> m_coordinator;
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
                (
                    void
                )apply_backend(impl.backend, [armed](auto &backend) noexcept { backend.reconcile_enabled(armed); });
            }

            /**
             * @brief Publishes one enable or disable outcome in the single toggle order.
             * @details The identity snapshot, slot release, unlock, and emission follow the state write
             *          (HookLifecycleName.*). The caller must read no hook state after this call because a subscriber
             *          can destroy the hook before emission ends. A kept slot records the event for its install.
             */
            template <class ImplT, class GateT>
            void publish_toggle(
                ImplT &impl,
                GateT &gate,
                TargetSlot *slot,
                std::unique_lock<std::recursive_mutex> &guard,
                bool armed
            ) noexcept
            {
                write_toggle_state(impl, gate, armed);
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *probe = DetourModKit::detail::g_hook_toggle_publication_probe)
                {
                    const HookState expected = armed ? HookState::Active : HookState::Disabled;
                    const bool callable_matches = (gate.callable != nullptr) == (armed && impl.is_inline);
                    probe(
                        armed,
                        guard.owns_lock(),
                        impl.status.load(std::memory_order_relaxed) == expected,
                        callable_matches
                    );
                }
#endif
                const diagnostics::HookTransition transition =
                    armed ? diagnostics::HookTransition::Enabled : diagnostics::HookTransition::Disabled;
                if (slot != nullptr && slot->defer_emission(transition))
                {
                    guard.unlock();
                    return;
                }
                const LifecycleSnapshot snapshot = snapshot_lifecycle(impl.name, impl.ledger_id, impl.is_inline);
                if (slot != nullptr)
                {
                    slot->release();
                }
                guard.unlock();
                emit_lifecycle(snapshot.name, snapshot.ledger_id, snapshot.kind, transition);
            }

            /**
             * @brief Settles an enable that the backend reported as failed.
             * @note The caller holds the call-gate lock and the target slot. An Active outcome releases both through
             *       publish_toggle(), so the caller must read no hook state after the call.
             */
            template <class ImplT, class GateT>
            [[nodiscard]] Result<void> settle_backend_enable_failure(
                ImplT &impl,
                GateT &gate,
                TargetSlot &slot,
                std::unique_lock<std::recursive_mutex> &guard,
                CoordinatorRefusal refusal
            ) noexcept
            {
                // A backend error says nothing about the target. The patch commits inside the thread trap transaction,
                // so an error can sit over a fully armed target. Witness the bytes before publication.
                const bool mutation_committed =
                    backend_value_or(impl.backend, false, [](auto &backend) noexcept { return backend.enabled(); });
                const PatchWitness after_failure = witness_of(impl.backend);
                if (mutation_committed && after_failure != PatchWitness::Original)
                {
                    // The mutation committed, so Original is the only witness that proves the hook disarmed. Retain
                    // the conservative Active state. The returned error reports that a safe disarm is unproven.
                    const std::uintptr_t armed_target = impl.target;
                    publish_toggle(impl, gate, &slot, guard, true);
                    const ErrorCode code =
                        after_failure == PatchWitness::OwnedPatch ? ErrorCode::BackendFailed : ErrorCode::DisableFailed;
                    return std::unexpected(Error{code, "hook::enable", armed_target});
                }
                // The backend committed no mutation, or the target already returned to Original. This hook is disarmed.
                if (after_failure == PatchWitness::Original)
                {
                    (void)apply_backend(impl.backend, [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                }
                impl.status.store(HookState::Disabled, std::memory_order_release);
                if (refusal == CoordinatorRefusal::LayerConflict)
                {
                    return std::unexpected(Error{ErrorCode::LayerConflict, "hook::enable", impl.target});
                }
                if (refusal == CoordinatorRefusal::CallerInTrampoline)
                {
                    return std::unexpected(Error{ErrorCode::ReentrantCallRejected, "hook::enable", impl.target});
                }
                return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable"});
            }

            /**
             * @brief Settles a backend enable success that did not leave this hook's own patch armed.
             * @note The caller holds the call-gate lock and the target slot. An Active outcome releases both through
             *       publish_toggle(), so the caller must read no hook state after the call.
             */
            template <class ImplT, class GateT>
            [[nodiscard]] Result<void> settle_unconfirmed_enable(
                ImplT &impl,
                GateT &gate,
                TargetSlot &slot,
                std::unique_lock<std::recursive_mutex> &guard
            ) noexcept
            {
                // Disabled publishes only after a rollback disable leaves the prologue at its original bytes. The
                // rollback receives the same classification as any other toggle. A third party that took the window can
                // otherwise lose its bytes to the unconditional restore. Refusal therefore falls through to the Active
                // publication below.
                if (const PatchWitness rollback_before = witness_of(impl.backend);
                    witness_permits_write(rollback_before))
                {
                    (void)backend_value_or(
                        impl.backend,
                        false,
                        [](auto &backend) noexcept { return try_backend_disable(backend); }
                    );
                    if (witness_of(impl.backend) == PatchWitness::Original)
                    {
                        (
                            void
                        )apply_backend(impl.backend, [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                        impl.status.store(HookState::Disabled, std::memory_order_release);
                        return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable"});
                    }
                }

                // A newer or uncertain owner can follow a completed restore. Retain backend reachability so
                // is_enabled() and a later disable retry agree with the conservative Active state.
                (void)apply_backend(impl.backend, [](auto &backend) noexcept { backend.reconcile_enabled(true); });
                publish_toggle(impl, gate, &slot, guard, true);
                return std::unexpected(Error{ErrorCode::DisableFailed, "hook::enable"});
            }

            /**
             * @brief Switches a Disabling hook off without a target write and publishes Disabled.
             * @details The position stays in the target's chain, so every caller runs past the detour. A switch refusal
             *          restores Active and returns DisableFailed with nothing else changed. A successful switch arms
             *          the Info line in @p note, unless @p note is null.
             * @note The caller holds the call-gate lock and, when @p slot is non-null, the target slot. A Disabled
             *       outcome releases both through publish_toggle(), so the caller must read no hook state after the
             *       call.
             */
            template <class ImplT, class GateT>
            [[nodiscard]] Result<void> publish_bypass(
                ImplT &impl,
                GateT &gate,
                TargetSlot *slot,
                std::unique_lock<std::recursive_mutex> &guard,
                DeferredToggleLog *note,
                std::size_t newer_layers,
                std::optional<PatchWitness> witness
            ) noexcept
            {
                if (!switch_backend(impl.backend, false))
                {
                    impl.status.store(HookState::Active, std::memory_order_release);
                    return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable", impl.target});
                }
                impl.bypassed = true;
                if (note != nullptr)
                {
                    note->arm_bypass(impl.name, impl.target, newer_layers, witness);
                }
                publish_toggle(impl, gate, slot, guard, false);
                return {};
            }

            /**
             * @brief Switches a Disabled hook back on without a target write and publishes Active.
             * @note The caller holds the call-gate lock, and no target slot unless @p kept_slot is non-null. An Active
             *       outcome releases the lock through publish_toggle(), so the caller must read no hook state after the
             *       call.
             */
            template <class ImplT, class GateT>
            [[nodiscard]] Result<void> publish_resume(
                ImplT &impl,
                GateT &gate,
                TargetSlot *kept_slot,
                std::unique_lock<std::recursive_mutex> &guard
            ) noexcept
            {
                HookState expected = HookState::Disabled;
                if (!impl.status.compare_exchange_strong(expected, HookState::Enabling, std::memory_order_acq_rel))
                {
                    return expected == HookState::Active
                               ? Result<void>{}
                               : std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
                }
                if (!switch_backend(impl.backend, true))
                {
                    impl.status.store(HookState::Disabled, std::memory_order_release);
                    return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable", impl.target});
                }
                impl.bypassed = false;
                publish_toggle(impl, gate, kept_slot, guard, true);
                return {};
            }

            /**
             * @brief Runs the arm of Hook::enable after its call-gate lock and backend check.
             * @param kept_slot The kept slot of HookStack::install, or null to claim the target slot here.
             * @note An Active outcome releases the lock through publish_toggle(), so the caller must read no hook state
             *       after the call.
             */
            template <class ImplT, class GateT>
            [[nodiscard]] Result<void> arm_hook(
                ImplT &impl,
                GateT &gate,
                std::unique_lock<std::recursive_mutex> &guard,
                DeferredToggleLog &deferred_warning,
                TargetSlot *kept_slot
            ) noexcept
            {
                // A claimed hook writes no target byte, so it toggles by one store with no ledger slot or byte witness.
                if (backend_claimed(impl.backend))
                {
                    return publish_resume(impl, gate, kept_slot, guard);
                }
                // A bypassed hook keeps its position. Unless the bytes are back to Original, which no chain reaches,
                // the resume needs no top-layer authority.
                if (impl.bypassed)
                {
                    if (witness_of(impl.backend) != PatchWitness::Original)
                    {
                        return publish_resume(impl, gate, kept_slot, guard);
                    }
                    (void)apply_backend(impl.backend, [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                    impl.bypassed = false;
                }

                // The slot makes the {decide, patch} pair atomic against a concurrent same-target install. Claim it
                // before the state CAS so a refusal changes nothing. A ledger that cannot decide the order refuses.
                std::optional<TargetSlot> acquired_slot;
                TargetSlot &slot =
                    kept_slot != nullptr ? *kept_slot : acquired_slot.emplace(impl.target, impl.ledger_id);
                if (slot.unavailable())
                {
                    return std::unexpected(Error{ErrorCode::LayerConflict, "hook::enable", impl.target});
                }
                bool busy_logged = false;
                for (;;)
                {
                    if (!slot.hold_coordinator("hook::enable", impl.name))
                    {
                        deferred_warning.arm(
                            "refused enable",
                            impl.name,
                            impl.target,
                            DetourModKit::detail::coordinator_hold_refusal_description(slot.coordinator_refusal())
                        );
                        return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable", impl.target});
                    }

                    // Classify before the transition claim. The backend emits its jmp over the current bytes, or
                    // recaptures the patch of another layer (`[B-110]`). Foreign or unreadable bytes must refuse here
                    // while the hook remains as the caller left it.
                    const PatchWitness before = arm_witness_of(impl.backend);
                    const bool promotes = witness_promotes_arm(before);
                    if (!promotes && !witness_permits_write(before))
                    {
                        deferred_warning.arm("refused enable", impl.name, impl.target, witness_description(before));
                        return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable", impl.target});
                    }
                    // An arm over this hook's own patch keeps its layer, so only the newest layer writes it.
                    if (!promotes && !slot.is_top_layer())
                    {
                        return std::unexpected(Error{ErrorCode::LayerConflict, "hook::enable", impl.target});
                    }

                    HookState expected = HookState::Disabled;
                    if (!impl.status.compare_exchange_strong(expected, HookState::Enabling, std::memory_order_acq_rel))
                    {
                        if (expected != HookState::Active)
                        {
                            return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
                        }
                        // Active answers the request only over this hook's own patch. The patch of another layer
                        // cannot prove that its chain still reaches this hook.
                        if (before == PatchWitness::OwnedPatch)
                        {
                            return {};
                        }
                        if (before == PatchWitness::LayeredOver)
                        {
                            deferred_warning.arm("refused enable", impl.name, impl.target, witness_description(before));
                            return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable", impl.target});
                        }
                        // The bytes prove the target is unpatched. Rewrite the stale claim, then arm through the
                        // ordinary path so byte authority and the population tally both stay exact.
                        deferred_warning.arm(
                            "has original bytes under an active state. This enable retries the arm",
                            impl.name,
                            impl.target
                        );
                        reconcile_published_state(impl, gate, false);
                        impl.status.store(HookState::Enabling, std::memory_order_release);
                    }
                    // Create leaves the target unpatched, so this is the first operation that can make the detour
                    // reachable.
                    CoordinatorRefusal refusal = CoordinatorRefusal::None;
                    const bool backend_enabled = backend_value_or(
                        impl.backend,
                        false,
                        [&refusal](auto &backend) noexcept { return try_backend_enable(backend, &refusal); }
                    );
                    // A thread runs the trampoline that the arm recaptures. It leaves by itself, so the arm lets the
                    // coordinator go and tries again, with no count (`[B-110]`). Nothing changed yet.
                    if (!backend_enabled && refusal == CoordinatorRefusal::TrampolineBusy && slot.release_coordinator())
                    {
                        impl.status.store(HookState::Disabled, std::memory_order_release);
                        if (!std::exchange(busy_logged, true))
                        {
                            (void)log().try_log(
                                LogLevel::Warning,
                                "hook::enable: '{}' waits for a thread to leave its trampoline at 0x{:0{}X}.",
                                impl.name,
                                impl.target,
                                sizeof(std::uintptr_t) * 2
                            );
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds{1});
                        continue;
                    }
                    const bool patch_confirmed = backend_value_or(
                        impl.backend,
                        false,
                        [](auto &backend) noexcept { return enable_patch_is_confirmed(backend); }
                    );
                    if (backend_enabled && patch_confirmed)
                    {
                        // The backend made the record the newest layer, so the local order follows it.
                        if (promotes)
                        {
                            if (const std::uint64_t stamp = DetourModKit::detail::HookLedger::instance()
                                                                .promote_to_newest(impl.target, impl.ledger_id);
                                stamp != 0)
                            {
                                impl.layer_stamp = stamp;
                            }
                        }
                        publish_toggle(impl, gate, &slot, guard, true);
                        return {};
                    }
                    if (!backend_enabled)
                    {
                        // A promoting arm meets LayerConflict only when it cannot chain to the layer on the target.
                        if (promotes && refusal == CoordinatorRefusal::LayerConflict)
                        {
                            deferred_warning.arm(
                                "refused enable",
                                impl.name,
                                impl.target,
                                "the hook cannot chain to the layer on the target"
                            );
                        }
                        else if (refusal == CoordinatorRefusal::CallerInTrampoline)
                        {
                            deferred_warning.arm(
                                "refused enable",
                                impl.name,
                                impl.target,
                                DetourModKit::detail::coordinator_refusal_description(refusal)
                            );
                        }
                        return settle_backend_enable_failure(impl, gate, slot, guard, refusal);
                    }
                    return settle_unconfirmed_enable(impl, gate, slot, guard);
                }
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
            const std::shared_ptr<CallGate> gate = gate_slot().load(std::memory_order_acquire);
            if (!gate)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            DeferredToggleLog deferred_warning;
            std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
            if (!guard.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            if (!backend_value_or(
                    m_impl->backend,
                    false,
                    [](auto &backend) noexcept { return static_cast<bool>(backend); }
                ))
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::enable"});
            }
            return arm_hook(*m_impl, *gate, guard, deferred_warning, nullptr);
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
            const std::shared_ptr<CallGate> gate = gate_slot().load(std::memory_order_acquire);
            if (!gate)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            DeferredToggleLog deferred_warning;
            std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
            if (!guard.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            if (!backend_value_or(
                    m_impl->backend,
                    false,
                    [](auto &backend) noexcept { return static_cast<bool>(backend); }
                ))
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::disable"});
            }

            // A claimed hook never restores. It switches off by one store with no ledger slot or byte witness.
            if (backend_claimed(m_impl->backend))
            {
                HookState expected = HookState::Active;
                if (!m_impl->status.compare_exchange_strong(expected, HookState::Disabling, std::memory_order_acq_rel))
                {
                    return expected == HookState::Disabled
                               ? Result<void>{}
                               : std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
                }
                return publish_bypass(*m_impl, *gate, nullptr, guard, nullptr, 0, std::nullopt);
            }

            TargetSlot slot(m_impl->target, m_impl->ledger_id);
            if (!slot.hold_coordinator("hook::disable", m_impl->name))
            {
                deferred_warning.arm(
                    "refused disable",
                    m_impl->name,
                    m_impl->target,
                    DetourModKit::detail::coordinator_hold_refusal_description(slot.coordinator_refusal())
                );
                return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable", m_impl->target});
            }
            const PatchWitness before = witness_of(m_impl->backend);
            // The ledger failed to claim the slot, so the layer order is undecided and the toggle refuses unchanged.
            if (slot.unavailable() && !m_impl->bypassed)
            {
                return std::unexpected(Error{ErrorCode::LayerConflict, "hook::disable", m_impl->target});
            }

            // A bypassed hook is already Disabled. Once it is the top layer over its own patch again, the restore
            // removes its position. Any other answer keeps the bypass, which is a complete disarm.
            if (m_impl->bypassed)
            {
                if (slot.is_top_layer() && before == PatchWitness::OwnedPatch)
                {
                    (void)backend_value_or(
                        m_impl->backend,
                        false,
                        [](auto &backend) noexcept { return try_backend_disable(backend); }
                    );
                    if (witness_of(m_impl->backend) == PatchWitness::Original)
                    {
                        (void)apply_backend(
                            m_impl->backend,
                            [](auto &backend) noexcept { backend.reconcile_enabled(false); }
                        );
                        m_impl->bypassed = false;
                    }
                    else if (!switch_backend(m_impl->backend, false))
                    {
                        return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable", m_impl->target});
                    }
                }
                return {};
            }

            // An Active layer under a newer one cannot restore its saved prologue without clobbering the newer layer.
            // It bypasses instead.
            const bool active = m_impl->status.load(std::memory_order_acquire) == HookState::Active;
            if (active && (slot.newer_layers() > 0 || !witness_permits_write(before)))
            {
                HookState expected = HookState::Active;
                if (!m_impl->status.compare_exchange_strong(expected, HookState::Disabling, std::memory_order_acq_rel))
                {
                    return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
                }
                return publish_bypass(
                    *m_impl,
                    *gate,
                    &slot,
                    guard,
                    &deferred_warning,
                    slot.newer_layers(),
                    slot.newer_layers() > 0 ? std::nullopt : std::optional<PatchWitness>{before}
                );
            }

            // A Disabled hook that restored keeps the newest-layer rule.
            if (!slot.is_top_layer())
            {
                return std::unexpected(Error{ErrorCode::LayerConflict, "hook::disable", m_impl->target});
            }

            // Classify before the transition claim (see enable()). The unconditional prologue restore clobbers a
            // foreign writer's bytes. Refuse and leave the hook as it is.
            if (!witness_permits_write(before))
            {
                deferred_warning.arm("refused disable", m_impl->name, m_impl->target, witness_description(before));
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
                deferred_warning.arm(
                    "has owned bytes under a disabled state. This disable retries the restore",
                    m_impl->name,
                    m_impl->target
                );
                reconcile_published_state(*m_impl, *gate, true);
                m_impl->status.store(HookState::Disabling, std::memory_order_release);
            }
            // Confirm the saved prologue is back before Disabled publication. The witness is taken whatever the
            // backend returns. An error can sit over restored bytes. A success without byte corroboration must not
            // publish Disabled.
            CoordinatorRefusal refusal = CoordinatorRefusal::None;
            const bool backend_disabled = backend_value_or(
                m_impl->backend,
                false,
                [&refusal](auto &backend) noexcept { return try_backend_disable(backend, &refusal); }
            );
            const PatchWitness after = witness_of(m_impl->backend);
            if (after == PatchWitness::Original)
            {
                (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                const std::uintptr_t target = m_impl->target;
                publish_toggle(*m_impl, *gate, &slot, guard, false);
                if (!backend_disabled)
                {
                    // The disarm took effect, but the backend reported a post-commit failure (its page-protection
                    // restore). Report it rather than swallow it.
                    return std::unexpected(Error{ErrorCode::BackendFailed, "hook::disable", target});
                }
                return {};
            }
            // The coordinator refused before any write because another participant layered on top. The backend
            // still reports this hook's committed patch, so the hook bypasses like a lower local layer.
            const bool patch_committed =
                backend_value_or(m_impl->backend, false, [](auto &backend) noexcept { return backend.enabled(); });
            if (refusal == CoordinatorRefusal::LayerConflict && patch_committed && after == PatchWitness::OwnedPatch)
            {
                return publish_bypass(*m_impl, *gate, &slot, guard, &deferred_warning, 0, std::nullopt);
            }
            // A completed restore can be followed by a newer or uncertain owner. Retain backend reachability so
            // is_enabled() and a later disable retry agree with the conservative Active state.
            (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.reconcile_enabled(true); });
            m_impl->status.store(HookState::Active, std::memory_order_release);
            if (refusal == CoordinatorRefusal::LayerConflict)
            {
                return std::unexpected(Error{ErrorCode::LayerConflict, "hook::disable", m_impl->target});
            }
            return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable"});
        }

        Result<void> detail::HookAccess::arm_installed(Hook &hook, DeferredArm &deferred) noexcept
        {
            const std::shared_ptr<Hook::CallGate> gate = hook.gate_slot().load(std::memory_order_acquire);
            if (!hook.m_impl || !gate)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            DeferredToggleLog deferred_warning;
            std::unique_lock<std::recursive_mutex> guard = hook.acquire_call_lock(gate.get());
            if (!guard.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            TargetSlot slot(hook.m_impl->target, hook.m_impl->ledger_id, TargetSlot::Kept{});
            Result<void> armed = arm_hook(*hook.m_impl, *gate, guard, deferred_warning, &slot);
            deferred.transition = slot.deferred_transition();
            std::tie(deferred.warning, deferred.reason) = deferred_warning.detach();
            return armed;
        }

        void detail::HookAccess::log_deferred_arm(
            const DeferredArm &deferred,
            const std::string &name,
            std::uintptr_t target
        ) noexcept
        {
            if (deferred.warning != nullptr)
            {
                DeferredToggleLog line;
                line.arm(deferred.warning, name, target, deferred.reason);
            }
        }
    } // namespace hook
} // namespace DetourModKit
