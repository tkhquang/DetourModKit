/**
 * @file input_intercept.cpp
 * @brief This TU implements the internal active-input layer from input_intercept.hpp.
 *
 * This TU owns the XInputGetState inline hook and the window-procedure subclass. They provide gamepad passthrough
 * suppression and mouse-wheel capture for InputPoller.
 */

#include "input_intercept.hpp"
#include "internal/hook_patch_witness.hpp"
#include "platform.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

namespace DetourModKit::detail
{
    namespace
    {
        /// The game or runtime determines which DLL contains the XInput export.
        constexpr const wchar_t *XINPUT_DLL_NAMES[] = {
            L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll", L"xinput1_2.dll", L"xinput1_1.dll",
        };

        /// Identifies the undocumented ordinal that exports XInputGetStateEx and reports the Guide button.
        constexpr WORD XINPUT_GET_STATE_EX_ORDINAL = 100;

        /**
         * @brief Defines how long a published suppression mask stays valid without a refresh.
         * @details Twice MAX_POLL_INTERVAL leaves a full poll interval for cycle work before expiry. A stalled poll
         *          thread still loses suppression after a bounded delay.
         */
        constexpr uint64_t SUPPRESS_TTL_MS = 2000;

        // One owner per layer: hooks and keepalives are shared per linked DMK instance, and the token prevents
        // superseded poller teardown of a newer installation. Static SRWLOCK storage has no destructor, so late
        // process teardown cannot encounter a destroyed mutex.
        SRWLOCK s_intercept_mutex = SRWLOCK_INIT;
        // Makes the owner check and its authorized write one indivisible step. Separate locks let a revoked poller
        // overwrite the new owner's state. Acquired after s_intercept_mutex wherever both are held. The detours take
        // neither lock.
        SRWLOCK s_data_plane_mutex = SRWLOCK_INIT;
        std::atomic<std::uint64_t> s_intercept_owner{0};
        std::atomic<std::uint64_t> s_next_intercept_owner{STANDALONE_INTERCEPT_OWNER + 1};
        constexpr unsigned WHEEL_COUNT_BITS = 11;
        constexpr std::uint64_t WHEEL_COUNT_MASK = (std::uint64_t{1} << WHEEL_COUNT_BITS) - 1;
        constexpr std::uint64_t WHEEL_EPOCH_MAX =
            (std::uint64_t{1} << (std::numeric_limits<std::uint64_t>::digits - WHEEL_COUNT_BITS)) - 1;
        constexpr std::uint64_t WHEEL_CAPTURE_ENABLED = 1;
        static_assert(MAX_WHEEL_NOTCHES <= WHEEL_COUNT_MASK);

        [[nodiscard]] constexpr std::uint64_t wheel_capture_state(std::uint64_t epoch, bool enabled) noexcept
        {
            return (epoch << 1) | (enabled ? WHEEL_CAPTURE_ENABLED : 0);
        }

        [[nodiscard]] constexpr std::uint64_t wheel_capture_epoch(std::uint64_t state) noexcept
        {
            return state >> 1;
        }

        [[nodiscard]] constexpr std::uint64_t wheel_count_slot(std::uint64_t epoch, std::uint64_t count) noexcept
        {
            return (epoch << WHEEL_COUNT_BITS) | count;
        }

        [[nodiscard]] constexpr std::uint64_t wheel_slot_epoch(std::uint64_t slot) noexcept
        {
            return slot >> WHEEL_COUNT_BITS;
        }

        // The per-axis signed sub-notch remainder includes the capture epoch and consume-ownership state. A fragment
        // with a different (epoch, owned) tag resets the remainder to zero. A retired epoch fragment and an
        // owned/unowned fragment pair cannot combine into one notch (WheelDeltaTest.*).
        constexpr unsigned WHEEL_REMAINDER_BITS = 8;
        constexpr int WHEEL_REMAINDER_BIAS = 128;
        constexpr std::uint64_t WHEEL_REMAINDER_VALUE_MASK = (std::uint64_t{1} << WHEEL_REMAINDER_BITS) - 1;
        constexpr std::uint64_t WHEEL_REMAINDER_OWNED_BIT = std::uint64_t{1} << WHEEL_REMAINDER_BITS;
        constexpr unsigned WHEEL_REMAINDER_EPOCH_SHIFT = WHEEL_REMAINDER_BITS + 1;
        static_assert(WHEEL_DELTA < WHEEL_REMAINDER_BIAS, "a sub-notch remainder must fit the biased value field");
        static_assert(WHEEL_EPOCH_MAX <= (std::numeric_limits<std::uint64_t>::max() >> WHEEL_REMAINDER_EPOCH_SHIFT));

        [[nodiscard]] constexpr std::uint64_t wheel_remainder_slot(std::uint64_t epoch, bool owned,
                                                                   int remainder) noexcept
        {
            return (epoch << WHEEL_REMAINDER_EPOCH_SHIFT) | (owned ? WHEEL_REMAINDER_OWNED_BIT : 0) |
                   static_cast<std::uint64_t>(remainder + WHEEL_REMAINDER_BIAS);
        }

        std::atomic<std::uint64_t> s_wheel_capture_state{wheel_capture_state(1, false)};
#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<WheelCaptureEntrySeam> s_wheel_capture_entry_seam{nullptr};
        std::atomic<XInputRetentionAttributionSeam> s_xinput_retention_attribution_seam{nullptr};
        std::atomic<HWND> s_wndproc_window_override{nullptr};
#endif

        /** @brief Owns exclusive access to the process-lifetime interception lock. */
        class InterceptLockGuard
        {
        public:
            explicit InterceptLockGuard(SRWLOCK &mutex) noexcept : m_mutex(mutex) { AcquireSRWLockExclusive(&m_mutex); }

            ~InterceptLockGuard() noexcept
            {
                if (m_locked)
                {
                    ReleaseSRWLockExclusive(&m_mutex);
                }
            }

            InterceptLockGuard(const InterceptLockGuard &) = delete;
            InterceptLockGuard &operator=(const InterceptLockGuard &) = delete;
            InterceptLockGuard(InterceptLockGuard &&) = delete;
            InterceptLockGuard &operator=(InterceptLockGuard &&) = delete;

            /// Releases the lock before this guard leaves scope.
            void unlock() noexcept
            {
                if (m_locked)
                {
                    ReleaseSRWLockExclusive(&m_mutex);
                    m_locked = false;
                }
            }

        private:
            SRWLOCK &m_mutex;
            bool m_locked{true};
        };

        /**
         * @brief Requires s_intercept_mutex. Reports whether @p owner can claim the layer.
         * @details This claim predicate admits the unowned layer, which is invalid as write authorization. The
         *          data_plane_authorized() predicate requires an exact owner match.
         */
        [[nodiscard]] bool owner_available(std::uint64_t owner) noexcept
        {
            if (owner == 0)
            {
                return false;
            }
            const std::uint64_t current = s_intercept_owner.load(std::memory_order_relaxed);
            return current == 0 || current == owner;
        }

        /// Requires s_data_plane_mutex. Reports whether @p owner can write the state that detours read.
        [[nodiscard]] bool data_plane_authorized(std::uint64_t owner) noexcept
        {
            return owner != 0 && s_intercept_owner.load(std::memory_order_relaxed) == owner;
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<DataPlaneEntrySeam> s_data_plane_entry_seam{nullptr};
#endif

        /// Runs the entry probe, if any, before a data-plane operation takes its lock.
        void run_data_plane_entry_seam() noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (const DataPlaneEntrySeam seam = s_data_plane_entry_seam.load(std::memory_order_acquire);
                seam != nullptr)
            {
                seam();
            }
#endif
        }

        /** @brief Owns exclusive access to the process-lifetime data-plane lock. */
        class DataPlaneLockGuard
        {
        public:
            DataPlaneLockGuard() noexcept { AcquireSRWLockExclusive(&s_data_plane_mutex); }

            ~DataPlaneLockGuard() noexcept { ReleaseSRWLockExclusive(&s_data_plane_mutex); }

            DataPlaneLockGuard(const DataPlaneLockGuard &) = delete;
            DataPlaneLockGuard &operator=(const DataPlaneLockGuard &) = delete;
            DataPlaneLockGuard(DataPlaneLockGuard &&) = delete;
            DataPlaneLockGuard &operator=(DataPlaneLockGuard &&) = delete;
        };

        /// Requires s_data_plane_mutex. Clears every mask and rule that the prior owner armed.
        void clear_data_plane_locked(std::uint64_t wheel_epoch) noexcept;

        /**
         * @brief Closes wheel capture and advances its epoch so an already-entered frame cannot write into a
         *        successor.
         * @return The newly published disabled epoch.
         */
        [[nodiscard]] std::uint64_t close_wheel_capture_and_advance_epoch() noexcept
        {
            std::uint64_t state = s_wheel_capture_state.load(std::memory_order_seq_cst);
            for (;;)
            {
                const std::uint64_t epoch = wheel_capture_epoch(state);
                const std::uint64_t next_epoch = epoch == WHEEL_EPOCH_MAX ? 1 : epoch + 1;
                const std::uint64_t desired = wheel_capture_state(next_epoch, false);
                if (s_wheel_capture_state.compare_exchange_weak(state, desired, std::memory_order_seq_cst))
                {
                    return next_epoch;
                }
            }
        }

        /**
         * @brief Requires s_intercept_mutex. Publishes the owner after an installation is ready and re-opens wheel
         *        capture for it.
         * @details The arm action occurs here, not at each install site, so ownership itself controls the association.
         *          An arm with no installed subclass is inert.
         */
        void publish_owner(std::uint64_t owner) noexcept
        {
            const DataPlaneLockGuard data_lock;
            s_intercept_owner.store(owner, std::memory_order_release);
            s_wheel_capture_state.fetch_or(WHEEL_CAPTURE_ENABLED, std::memory_order_seq_cst);
        }

        /**
         * @brief Requires s_intercept_mutex. Revokes the layer and clears the data that the prior owner armed.
         * @details One step ensures an unowned layer retains no live mask that lacks an owner with revoke authority. A
         *          wheel-capture epoch advance invalidates an active window-procedure frame without a wait.
         */
        void revoke_owner_and_clear_data() noexcept
        {
            const std::uint64_t wheel_epoch = close_wheel_capture_and_advance_epoch();
            const DataPlaneLockGuard data_lock;
            clear_data_plane_locked(wheel_epoch);
            s_intercept_owner.store(0, std::memory_order_release);
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        // This oracle precedes the hook cell, so its destructor runs after later automatic objects.
        // The exit proof arms it with a patched target window.
        constexpr std::size_t XINPUT_PROCESS_EXIT_WITNESS_BYTES = 16;
        std::atomic<const std::uint8_t *> s_xinput_process_exit_target{nullptr};
        std::uint8_t s_xinput_process_exit_patch[XINPUT_PROCESS_EXIT_WITNESS_BYTES]{};
        class XInputProcessExitOracle
        {
        public:
            ~XInputProcessExitOracle() noexcept
            {
                const std::uint8_t *const target = s_xinput_process_exit_target.load(std::memory_order_acquire);
                if (target == nullptr)
                {
                    return;
                }
                for (std::size_t i = 0; i < XINPUT_PROCESS_EXIT_WITNESS_BYTES; ++i)
                {
                    if (target[i] != s_xinput_process_exit_patch[i])
                    {
                        ::RaiseFailFastException(nullptr, nullptr, 0);
                    }
                }
            }
        };
        XInputProcessExitOracle s_xinput_process_exit_oracle;
#endif
        std::atomic<XInputGetStateFn> s_xinput_original{nullptr};
        std::atomic<XInputGetStateFn> s_xinput_ex_original{nullptr};
        std::atomic<bool> s_xinput_installed{false};
        // This flag is true while the layer is claimed but a required entry point lacks its patch. Both detours pass
        // through. This flag still lets the owner poll loop read the primary trampoline directly.
        std::atomic<bool> s_xinput_pair_degraded{false};
        // This flag is true after a timeout or unproved restore latches the XInput hooks in process-lifetime storage. A
        // later Input start re-arms only through the retained primary entry, never over uncertain storage.
        std::atomic<bool> s_xinput_permanent_detour{false};
        // One-shot diagnostic latches prevent sink spam because install_xinput retries every poll cycle. uninstall()
        // clears them so a later hot-reload re-arm can warn again.
        std::atomic<bool> s_xinput_enable_warned{false};
        std::atomic<bool> s_xinput_ex_enable_warned{false};
        std::atomic<bool> s_xinput_capacity_warned{false};
        // This raw cell owns all XInput hooks and keepalives for the process lifetime.
        // A normal teardown resets its hooks and releases its module references.
        // A veto leaves the cell intact, so the CRT runs no InlineHook destructor under the loader lock.
        struct PermanentXInputHooks
        {
            safetyhook::InlineHook primary;
            safetyhook::InlineHook ex;
            HMODULE self_ref{nullptr};
            HMODULE target_ref{nullptr};
            HMODULE ex_target_ref{nullptr};
        };
        alignas(PermanentXInputHooks) unsigned char s_xinput_permanent_cell[sizeof(PermanentXInputHooks)];
        static_assert(std::is_trivially_destructible_v<decltype(s_xinput_permanent_cell)>,
                      "the raw XInput placement cell must have no automatic destructor");
        bool s_xinput_permanent_cell_ready{false};
        PermanentXInputHooks *s_xinput_permanent_hooks{nullptr};
#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<std::size_t> s_xinput_backend_toggle_exception_catches{0};
#endif

        /**
         * @brief Returns the reserved cell as a live object.
         * @return Pointer to the object that ensure_permanent_cell() constructed.
         * @note Requires s_intercept_mutex and a prior successful ensure_permanent_cell().
         */
        [[nodiscard]] PermanentXInputHooks *permanent_cell() noexcept
        {
            return std::launder(reinterpret_cast<PermanentXInputHooks *>(s_xinput_permanent_cell));
        }

        /**
         * @brief Constructs the reserved cell before an XInput detour is published.
         * @note Requires s_intercept_mutex. MSVC debug-container proxy setup can allocate, so this runs before the
         *       allocation-free teardown boundary.
         */
        [[nodiscard]] bool ensure_permanent_cell() noexcept
        {
            if (s_xinput_permanent_cell_ready)
            {
                return true;
            }
            try
            {
                ::new (static_cast<void *>(s_xinput_permanent_cell)) PermanentXInputHooks{};
            }
            catch (...)
            {
                return false;
            }
            s_xinput_permanent_cell_ready = true;
            s_xinput_permanent_hooks = permanent_cell();
            return true;
        }

        /**
         * @brief Identifies the evidence that resets the recovery deadline for an incomplete XInput pair.
         * @details The delay grows to a cap and stays there (the poll loop asks every cycle, and the target really
         *          can come back). Changed evidence drops the accumulated delay, so recovery occurs before a stale
         *          backoff expires.
         * @note Requires s_intercept_mutex.
         */
        struct XInputRecoveryEvidence
        {
            /// Identifies the module whose prologue the pair patches. A different pin identifies a different target.
            const void *target_module{nullptr};
            /// Identifies the owner that requests recovery. A poller restart supplies fresh evidence.
            std::uint64_t owner{0};
            /// Identifies the absent member. Either member can be absent, so the recovery cadence keys on both.
            bool primary_covered{false};
            bool ex_covered{false};
            /**
             * @brief Records whether each target's current bytes permit the re-arm write.
             * @details A guarded byte comparison detects when a concurrent writer returns an export. The comparison
             *          does not perform the protection change that the delay bounds.
             */
            bool primary_target_writable{false};
            bool ex_target_writable{false};

            [[nodiscard]] bool operator==(const XInputRecoveryEvidence &) const noexcept = default;
        };

        /// Defines the first delay after a failed recovery transaction.
        inline constexpr std::uint64_t XINPUT_RECOVERY_MIN_DELAY_MS = 32;
        /// Defines the delay ceiling. Recovery retries at this cadence while the pair remains broken.
        inline constexpr std::uint64_t XINPUT_RECOVERY_MAX_DELAY_MS = 2000;

        XInputRecoveryEvidence s_xinput_recovery_evidence{};
        std::uint64_t s_xinput_recovery_delay_ms{0};
        std::uint64_t s_xinput_recovery_not_before_ms{0};
#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<std::size_t> s_xinput_recovery_attempts{0};
#endif

        /// Requires s_intercept_mutex. Reports whether a recovery transaction can run for @p evidence now.
        [[nodiscard]] bool xinput_recovery_due(const XInputRecoveryEvidence &evidence) noexcept
        {
            if (evidence != s_xinput_recovery_evidence)
            {
                s_xinput_recovery_evidence = evidence;
                s_xinput_recovery_delay_ms = 0;
                s_xinput_recovery_not_before_ms = 0;
                return true;
            }
            return GetTickCount64() >= s_xinput_recovery_not_before_ms;
        }

        /// Requires s_intercept_mutex. Grows the delay toward its cap after a recovery transaction did not complete.
        void xinput_recovery_deferred() noexcept
        {
            s_xinput_recovery_delay_ms =
                (s_xinput_recovery_delay_ms == 0)
                    ? XINPUT_RECOVERY_MIN_DELAY_MS
                    : (s_xinput_recovery_delay_ms >= XINPUT_RECOVERY_MAX_DELAY_MS / 2 ? XINPUT_RECOVERY_MAX_DELAY_MS
                                                                                      : s_xinput_recovery_delay_ms * 2);
            s_xinput_recovery_not_before_ms = GetTickCount64() + s_xinput_recovery_delay_ms;
        }

        /// Requires s_intercept_mutex. Clears the gate so the next incomplete pair starts from an immediate attempt.
        void xinput_recovery_reset() noexcept
        {
            s_xinput_recovery_evidence = {};
            s_xinput_recovery_delay_ms = 0;
            s_xinput_recovery_not_before_ms = 0;
        }

        /// Counts one recovery transaction for the proofs and passes its outcome straight through.
        [[nodiscard]] bool record_xinput_recovery_attempt(bool armed) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            s_xinput_recovery_attempts.fetch_add(1, std::memory_order_relaxed);
#endif
            return armed;
        }

        std::atomic<int> s_bound_user_index{0};
        std::atomic<uint16_t> s_suppress_mask{0};
        std::atomic<uint64_t> s_suppress_deadline_ms{0};

        // This counter tracks game threads inside an XInput detour body. Before hook destruction, uninstall() retires
        // the published trampoline pointers and drains this counter. This complements SafetyHook's mid-prologue
        // relocation.
        std::atomic<int> s_xinput_inflight{0};

#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<XInputDetourBodySeam> s_xinput_detour_body_seam{nullptr};
        std::atomic<XInputArmSeam> s_xinput_arm_seam{nullptr};
        std::atomic<XInputCleanReleaseSeam> s_xinput_clean_release_seam{nullptr};
        std::atomic<XInputCreateSeam> s_xinput_create_seam{nullptr};
        // When set, install_xinput resolves XInputGetState from this module so a test can drive the install against
        // a synthetic proxy DLL. Set/cleared only on the test thread while no install runs.
        HMODULE s_xinput_module_override{nullptr};
#endif

        /// Runs the arm-boundary probe between the backend toggle and the witness read that judges it.
        void run_xinput_arm_seam() noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (const XInputArmSeam seam = s_xinput_arm_seam.load(std::memory_order_acquire); seam != nullptr)
            {
                seam();
            }
#endif
        }

        /// Balances the install-time keepalives after all detour bodies become inactive.
        void release_xinput_module_refs() noexcept
        {
            if (s_xinput_permanent_hooks == nullptr)
            {
                return;
            }
            DetourModKit::detail::release_module_ref(s_xinput_permanent_hooks->ex_target_ref,
                                                     diagnostics::ModulePinReason::XInputTarget);
            s_xinput_permanent_hooks->ex_target_ref = nullptr;
            DetourModKit::detail::release_module_ref(s_xinput_permanent_hooks->target_ref,
                                                     diagnostics::ModulePinReason::XInputTarget);
            s_xinput_permanent_hooks->target_ref = nullptr;
            DetourModKit::detail::release_module_ref(s_xinput_permanent_hooks->self_ref,
                                                     diagnostics::ModulePinReason::XInputKeepalive);
            s_xinput_permanent_hooks->self_ref = nullptr;
        }

        [[nodiscard]] PatchWitness xinput_patch_witness(const safetyhook::InlineHook &hook) noexcept
        {
            return hook ? witness_patch(hook) : PatchWitness::Original;
        }

        [[nodiscard]] PatchWitness xinput_teardown_witness(const safetyhook::InlineHook &hook) noexcept
        {
            // A reconciled disabled backend has no target entry into its trampoline. Treat retained inactive storage
            // as Original even if its old target was later repatched or unmapped.
            return hook && hook.enabled() ? witness_patch(hook) : PatchWitness::Original;
        }

        [[nodiscard]] bool try_xinput_backend_enable(safetyhook::InlineHook &hook) noexcept
        {
            try
            {
                return hook.enable().has_value();
            }
            catch (...)
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                s_xinput_backend_toggle_exception_catches.fetch_add(1, std::memory_order_relaxed);
#endif
                return false;
            }
        }

        [[nodiscard]] bool try_xinput_backend_disable(safetyhook::InlineHook &hook) noexcept
        {
            try
            {
                return hook.disable().has_value();
            }
            catch (...)
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                s_xinput_backend_toggle_exception_catches.fetch_add(1, std::memory_order_relaxed);
#endif
                return false;
            }
        }

        /**
         * @brief Classifies one raw-hook arm by whether a prologue mutation reached the target.
         * @details Uncommitted is the only outcome whose storage the caller can destroy. CommittedUnreachable wrote
         *          the prologue and then lost it. A thread already inside can still reach the trampoline.
         */
        enum class XInputArmOutcome : std::uint8_t
        {
            Armed,
            Uncommitted,
            CommittedUnreachable
        };

        /** @brief Arms a freshly created raw hook and reconciles a failed transaction from its target bytes. */
        [[nodiscard]] XInputArmOutcome arm_xinput_hook(safetyhook::InlineHook &hook,
                                                       std::atomic<XInputGetStateFn> &original,
                                                       bool original_was_published, std::atomic<bool> &warning_latch,
                                                       std::string_view warning) noexcept
        {
            const PatchWitness before = xinput_patch_witness(hook);
            if (!witness_permits_write(before))
            {
                hook.reconcile_enabled(false);
                if (!original_was_published)
                {
                    original.store(nullptr, std::memory_order_release);
                }
                return XInputArmOutcome::Uncommitted;
            }

            const bool backend_enabled = try_xinput_backend_enable(hook);
            run_xinput_arm_seam();
            const bool mutation_committed = hook.enabled();
            const PatchWitness after = xinput_patch_witness(hook);
            if (!mutation_committed || after == PatchWitness::Original)
            {
                hook.reconcile_enabled(false);
                if (!mutation_committed && !original_was_published)
                {
                    original.store(nullptr, std::memory_order_release);
                }
                if ((!backend_enabled || after != PatchWitness::Original) &&
                    !warning_latch.exchange(true, std::memory_order_relaxed))
                {
                    (void)log().log_noexcept(LogLevel::Warning, warning);
                }
                // A committed mutation routed callers through this trampoline before another writer restored the
                // bytes. No new caller can arrive, but this code still must not free the storage.
                return mutation_committed ? XInputArmOutcome::CommittedUnreachable : XInputArmOutcome::Uncommitted;
            }

            // OwnedPatch is exact reachability. Foreign and Indeterminate cannot disprove a newer chain through this
            // trampoline, so they retain the same conservative enabled state.
            hook.reconcile_enabled(true);
            if ((!backend_enabled || after != PatchWitness::OwnedPatch) &&
                !warning_latch.exchange(true, std::memory_order_relaxed))
            {
                (void)log().log_noexcept(LogLevel::Warning, warning);
            }
            return XInputArmOutcome::Armed;
        }

        /**
         * @brief Creates one disabled raw hook and contains allocation exceptions from creation.
         * @details Creation remains separate from the arm, so the whole pair exists before any prologue patch. A
         *          creation failure rolls back completely and publishes nothing.
         */
        [[nodiscard]] bool create_disabled_xinput_hook(safetyhook::RouteRetentionCredit &credit, void *target,
                                                       void *detour, safetyhook::InlineHook &destination) noexcept
        {
            try
            {
                // One fresh arena per pair member keeps the pre-reserved block worst case independent.
                const std::shared_ptr<safetyhook::Allocator> allocator = safetyhook::Allocator::create();
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (const XInputCreateSeam seam = s_xinput_create_seam.load(std::memory_order_acquire); seam != nullptr)
                {
                    seam();
                }
#endif
                auto created = safetyhook::InlineHook::create(
                    allocator, target, detour,
                    static_cast<safetyhook::InlineHook::Flags>(safetyhook::InlineHook::StartDisabled |
                                                               safetyhook::InlineHook::RoutedExternal),
                    credit);
                if (!created)
                {
                    return false;
                }
                // The move assigns onto an empty destination, so it frees nothing and takes no allocation.
                destination = std::move(created.value());
                return true;
            }
            catch (...)
            {
                return false;
            }
        }

        /** @brief Restores one raw hook only while its pre-write witness authorizes the backend mutation. */
        [[nodiscard]] PatchWitness restore_xinput_hook(safetyhook::InlineHook &hook) noexcept
        {
            if (!hook)
            {
                return PatchWitness::Original;
            }
            if (!hook.enabled())
            {
                // A disabled backend has no target entry and writes nothing. A byte check at its former target reports
                // Foreign for an unrelated writer and forces needless permanent retention.
                return PatchWitness::Original;
            }
            const PatchWitness before = xinput_teardown_witness(hook);
            if (!witness_permits_write(before))
            {
                hook.reconcile_enabled(true);
                return before;
            }

            (void)try_xinput_backend_disable(hook);
            const PatchWitness after = xinput_patch_witness(hook);
            hook.reconcile_enabled(after != PatchWitness::Original);
            return after;
        }

        /**
         * @brief Releases a hook after its target witnesses Original and its detour bodies drain.
         * @note This noexcept move release performs no allocation. Published stable gateways remain process-lifetime
         *       storage by design.
         */
        void reset_inactive_xinput_hook(safetyhook::InlineHook &hook, std::atomic<XInputGetStateFn> &original) noexcept
        {
            original.store(nullptr, std::memory_order_seq_cst);
            hook = {};
        }

        /**
         * @brief Publishes a trampoline, then arms a hook whose prologue is not patched.
         * @details Reuses the hook object and its trampoline, so nothing is created and no executable storage is
         *          freed or replaced. arm_xinput_hook's witnesses still gate the write and decide reachability.
         */
        [[nodiscard]] XInputArmOutcome arm_created_xinput_hook(safetyhook::InlineHook &hook,
                                                               std::atomic<XInputGetStateFn> &original,
                                                               std::atomic<bool> &warning_latch,
                                                               std::string_view warning) noexcept
        {
            if (!hook)
            {
                return XInputArmOutcome::Uncommitted;
            }
            if (hook.enabled())
            {
                return XInputArmOutcome::Armed;
            }
            const bool original_was_published = original.load(std::memory_order_seq_cst) != nullptr;
            original.store(hook.original<XInputGetStateFn>(), std::memory_order_seq_cst);
            return arm_xinput_hook(hook, original, original_was_published, warning_latch, warning);
        }

        /// Reports whether rearm restores the forward path.
        [[nodiscard]] bool rearm_xinput_hook(safetyhook::InlineHook &hook, std::atomic<XInputGetStateFn> &original,
                                             std::atomic<bool> &warning_latch, std::string_view warning) noexcept
        {
            return arm_created_xinput_hook(hook, original, warning_latch, warning) == XInputArmOutcome::Armed;
        }

        enum class XInputRetentionReason : std::uint8_t
        {
            InflightTimeout,
            UnrestoredPatch,
            UnprovedInstall
        };

        struct XInputPublishedChains
        {
            bool primary{false};
            bool ex{false};
        };

        struct XInputRetentionLog
        {
            std::array<char, 256> attribution{};
            std::size_t attribution_length{0};
            XInputRetentionReason reason{XInputRetentionReason::InflightTimeout};
            bool pending{false};
        };

        /// Appends @p text at @p length and truncates at the buffer end.
        void append_text(std::span<char> buffer, std::size_t &length, std::string_view text) noexcept
        {
            const std::size_t room = buffer.size() - length;
            const std::size_t count = text.size() < room ? text.size() : room;
            std::memcpy(buffer.data() + length, text.data(), count);
            length += count;
        }

        /// Appends "0x" and the fixed 16-digit hex form of @p value.
        void append_hex_address(std::span<char> buffer, std::size_t &length, std::uintptr_t value) noexcept
        {
            append_text(buffer, length, "0x");
            char digits[16];
            for (int i = 15; i >= 0; --i)
            {
                digits[i] = "0123456789ABCDEF"[value & 0xFU];
                value >>= 4U;
            }
            append_text(buffer, length, std::string_view{digits, sizeof(digits)});
        }

        /// Names the condition that forced the raw hook pair into permanent storage.
        [[nodiscard]] constexpr std::string_view xinput_retention_message(XInputRetentionReason reason) noexcept
        {
            switch (reason)
            {
            case XInputRetentionReason::InflightTimeout:
                return "XInput interception: a game thread was still inside a detour at the quiesce deadline; "
                       "retained the hook trampolines instead of freeing them.";
            case XInputRetentionReason::UnrestoredPatch:
                return "XInput interception: target bytes could not be proved restored; retained the raw hook chain "
                       "instead of overwriting or freeing it.";
            case XInputRetentionReason::UnprovedInstall:
                break;
            }
            return "XInput interception: the prologue reverted to its original bytes after the hook transaction "
                   "committed; retained the published trampoline instead of freeing it.";
        }

        /**
         * @brief Latches the canonical raw hook pair and keepalives as permanently retained.
         * @note Requires s_intercept_mutex and a constructed process-lifetime cell.
         *       A supplied publication snapshot must be exact.
         *       Omit the snapshot only when a successful drain preceded the retention decision.
         *       Forwarding state then selects the published chains on its own.
         */
        void retain_xinput_hooks(PatchWitness primary_witness, PatchWitness ex_witness, XInputRetentionReason reason,
                                 XInputRetentionLog &deferred_log, XInputPublishedChains published_chains = {}) noexcept
        {
            PermanentXInputHooks *const permanent = permanent_cell();
            const bool primary_valid = static_cast<bool>(permanent->primary);
            const bool ex_valid = static_cast<bool>(permanent->ex);
            const bool primary_forwarding_required = primary_valid && permanent->primary.enabled();
            const bool ex_forwarding_required = ex_valid && permanent->ex.enabled();
            permanent->primary.reconcile_enabled(primary_forwarding_required &&
                                                 primary_witness != PatchWitness::Original);
            permanent->ex.reconcile_enabled(ex_forwarding_required && ex_witness != PatchWitness::Original);

            // Keep a chain published when the backend still forwards. Also keep it when pointer publication preceded
            // the retention decision. An admitted caller can still reach the detour's original-pointer load.
            const bool primary_chain_required =
                primary_forwarding_required || (primary_valid && published_chains.primary);
            const bool ex_chain_required = ex_forwarding_required || (ex_valid && published_chains.ex);
            s_xinput_original.store(primary_chain_required ? permanent->primary.original<XInputGetStateFn>() : nullptr,
                                    std::memory_order_seq_cst);
            s_xinput_ex_original.store(ex_chain_required ? permanent->ex.original<XInputGetStateFn>() : nullptr,
                                       std::memory_order_seq_cst);
            s_xinput_permanent_detour.store(true, std::memory_order_release);
            s_xinput_installed.store(false, std::memory_order_release);
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);

            // Build the loader attribution under the lock. The caller emits it after the critical section.
            deferred_log.reason = reason;
            append_text(deferred_log.attribution, deferred_log.attribution_length,
                        "XInput retention attribution: XInputGetState target ");
            append_hex_address(deferred_log.attribution, deferred_log.attribution_length,
                               permanent->primary ? permanent->primary.target_address() : std::uintptr_t{0});
            append_text(deferred_log.attribution, deferred_log.attribution_length, " (");
            append_text(deferred_log.attribution, deferred_log.attribution_length,
                        witness_description(primary_witness));
            append_text(deferred_log.attribution, deferred_log.attribution_length, ")");
            if (permanent->ex)
            {
                append_text(deferred_log.attribution, deferred_log.attribution_length, ". XInputGetStateEx target ");
                append_hex_address(deferred_log.attribution, deferred_log.attribution_length,
                                   permanent->ex.target_address());
                append_text(deferred_log.attribution, deferred_log.attribution_length, " (");
                append_text(deferred_log.attribution, deferred_log.attribution_length, witness_description(ex_witness));
                append_text(deferred_log.attribution, deferred_log.attribution_length, ")");
            }
            append_text(deferred_log.attribution, deferred_log.attribution_length, ".");
            deferred_log.pending = true;

            s_xinput_pair_degraded.store(false, std::memory_order_release);
            xinput_recovery_reset();
            s_xinput_enable_warned.store(false, std::memory_order_relaxed);
            s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
            s_xinput_capacity_warned.store(false, std::memory_order_relaxed);
        }

        /** @brief Emits a retention report after its caller releases s_intercept_mutex. */
        void emit_xinput_retention_log(const XInputRetentionLog &deferred_log) noexcept
        {
            if (!deferred_log.pending)
            {
                return;
            }
            const std::string_view attribution{deferred_log.attribution.data(), deferred_log.attribution_length};
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (const XInputRetentionAttributionSeam seam =
                    s_xinput_retention_attribution_seam.load(std::memory_order_acquire);
                seam != nullptr)
            {
                seam(attribution);
            }
#endif
            (void)log().log_noexcept(LogLevel::Warning, xinput_retention_message(deferred_log.reason));
            (void)log().log_noexcept(LogLevel::Warning, attribution);
        }

        /**
         * @brief Requires s_intercept_mutex. Commits a complete XInput pair and activates suppression.
         * @details Both detours read s_xinput_installed, so suppression can never be live for one member of the
         *          pair and not the other.
         */
        void publish_complete_xinput_pair(int user_index, std::uint64_t owner) noexcept
        {
            s_bound_user_index.store(user_index, std::memory_order_relaxed);
            xinput_recovery_reset();
            s_xinput_pair_degraded.store(false, std::memory_order_release);
            s_xinput_installed.store(true, std::memory_order_release);
            publish_owner(owner);
        }

        /**
         * @brief Requires s_intercept_mutex. Reads one pair member's target bytes and reports whether it still covers.
         * @param required Whether this entry point needs coverage for a complete pair. An absent or aliased
         *                 ordinal-100 export needs no second member.
         */
        [[nodiscard]] bool xinput_member_entry_witnessed(const safetyhook::InlineHook &hook, bool required) noexcept
        {
            if (!hook)
            {
                return !required;
            }
            if (!hook.enabled())
            {
                return false;
            }
            return xinput_patch_witness(hook) == PatchWitness::OwnedPatch;
        }

        /** @brief Reports exact owned coverage and reconciles Original to disabled under s_intercept_mutex. */
        [[nodiscard]] bool xinput_member_covers_entry(safetyhook::InlineHook &hook, bool required) noexcept
        {
            if (!hook)
            {
                return !required;
            }
            if (!hook.enabled())
            {
                return false;
            }
            const PatchWitness witness = xinput_patch_witness(hook);
            if (witness == PatchWitness::OwnedPatch)
            {
                return true;
            }
            // Exact Original can be re-armed through the same object. Foreign and Indeterminate can still be a
            // newer chain through our trampoline, so preserve their enabled state and report only coverage loss.
            if (witness == PatchWitness::Original)
            {
                hook.reconcile_enabled(false);
            }
            return false;
        }

        /**
         * @brief Requires s_intercept_mutex. Publishes complete coverage only when a final witness proves both members.
         * @details If an owned patch disappears, complete state clears first. No detour masks while the other entry
         *          point bypasses. The layer remains claimed and degraded.
         * @return true when coverage was published.
         */
        [[nodiscard]] bool publish_xinput_pair_if_whole(safetyhook::InlineHook &primary, safetyhook::InlineHook &ex,
                                                        int user_index, std::uint64_t owner) noexcept
        {
            const bool primary_covered = xinput_member_covers_entry(primary, true);
            const bool ex_covered = xinput_member_covers_entry(ex, static_cast<bool>(ex));
            if (primary_covered && ex_covered)
            {
                publish_complete_xinput_pair(user_index, owner);
                return true;
            }
            s_bound_user_index.store(user_index, std::memory_order_relaxed);
            s_xinput_installed.store(false, std::memory_order_release);
            s_xinput_pair_degraded.store(true, std::memory_order_release);
            publish_owner(owner);
            return false;
        }

        /**
         * @brief Requires s_intercept_mutex. Re-arms each member that lost entry-point coverage.
         * @details Each member uses its own hook object. Recovery of only the partner leaves the required export
         *          permanently open.
         */
        [[nodiscard]] bool rearm_xinput_pair(safetyhook::InlineHook &primary, safetyhook::InlineHook &ex) noexcept
        {
            bool primary_covered = xinput_member_covers_entry(primary, true);
            if (!primary_covered && !primary.enabled())
            {
                (void)rearm_xinput_hook(primary, s_xinput_original, s_xinput_enable_warned,
                                        "InputIntercept: the XInputGetState re-arm did not complete cleanly, so XInput "
                                        "coverage stays degraded and both entries pass through.");
                primary_covered = xinput_member_entry_witnessed(primary, true);
            }
            bool ex_covered = xinput_member_covers_entry(ex, static_cast<bool>(ex));
            if (!ex_covered && !ex.enabled())
            {
                (void)rearm_xinput_hook(ex, s_xinput_ex_original, s_xinput_ex_enable_warned,
                                        "InputIntercept: the XInputGetStateEx re-arm did not complete cleanly, so "
                                        "XInput coverage stays degraded and both entries pass through.");
                ex_covered = xinput_member_entry_witnessed(ex, static_cast<bool>(ex));
            }
            return primary_covered && ex_covered;
        }

        /**
         * @brief Requires s_intercept_mutex. Re-witnesses a pair and drives deadline-gated recovery of absent members.
         * @details One routine handles per-cycle health, live-pair recovery, and retained-pair recovery. It detects
         *          loss of pair integrity after publication. Every publication uses the final pair witness.
         * @return true when complete coverage is published for @p owner.
         */
        [[nodiscard]] bool maintain_xinput_pair(safetyhook::InlineHook &primary, safetyhook::InlineHook &ex,
                                                const void *target_module, int user_index, std::uint64_t owner) noexcept
        {
            if (publish_xinput_pair_if_whole(primary, ex, user_index, owner))
            {
                return true;
            }

            const XInputRecoveryEvidence evidence{target_module,
                                                  owner,
                                                  xinput_member_entry_witnessed(primary, true),
                                                  xinput_member_entry_witnessed(ex, static_cast<bool>(ex)),
                                                  witness_permits_write(xinput_patch_witness(primary)),
                                                  witness_permits_write(xinput_patch_witness(ex))};
            if (!xinput_recovery_due(evidence))
            {
                return false;
            }
            if (record_xinput_recovery_attempt(rearm_xinput_pair(primary, ex)) &&
                publish_xinput_pair_if_whole(primary, ex, user_index, owner))
            {
                return true;
            }
            xinput_recovery_deferred();
            return false;
        }

        /**
         * @brief Marks a game thread as active inside an XInput detour body.
         * @details This counter and the published trampoline pointer form a Dekker-style pair with uninstall()'s
         *          retire-store-then-drain-load. Both sides use store then load. Acquire and release do not forbid
         *          this StoreLoad order change. The increment, trampoline load, retire store, and drain load use
         *          seq_cst. The decrement stays release and does not belong to the StoreLoad pair.
         */
        struct InflightGuard
        {
            InflightGuard() noexcept { s_xinput_inflight.fetch_add(1, std::memory_order_seq_cst); }
            ~InflightGuard() noexcept { s_xinput_inflight.fetch_sub(1, std::memory_order_release); }
            InflightGuard(const InflightGuard &) = delete;
            InflightGuard &operator=(const InflightGuard &) = delete;
            InflightGuard(InflightGuard &&) = delete;
            InflightGuard &operator=(InflightGuard &&) = delete;
        };

        // Each detour-side consume rule occupies one atomic word, so readers never see a torn rule. A seqlock protects
        // the array and count. An even value is stable, and an odd value marks an update. Game XInput threads read
        // snapshots without a lock. The two writers, clear_data_plane_locked() and publish_gamepad_consume_rules(),
        // serialize through s_data_plane_mutex. InputPoller publication also holds InputPoller::m_bindings_rw_mutex.
        std::array<std::atomic<uint64_t>, MAX_GAMEPAD_CONSUME_RULES> s_consume_rules{};
        std::atomic<uint32_t> s_consume_rule_count{0};
        std::atomic<uint32_t> s_consume_rules_seq{0};

        // This gate controls detour-side rule suppression and refreshes every poll cycle. The rule list and its TTL
        // survive focus changes. Without this gate, apply_suppress continues suppression while the mod is unfocused.
        std::atomic<bool> s_rule_suppress_enabled{false};

        /**
         * @brief Packs a rule into one word: modifier (bits 0-15), forbidden (16-31), trigger (32-47).
         * @details Three 16-bit masks fit a uint64 with room to spare, so a rule is published and read as a single
         *          atomic store/load.
         */
        constexpr uint64_t pack_consume_rule(const GamepadConsumeRule &rule) noexcept
        {
            return static_cast<uint64_t>(rule.modifier_mask) | (static_cast<uint64_t>(rule.forbidden_mask) << 16) |
                   (static_cast<uint64_t>(rule.trigger_mask) << 32);
        }

        /// Unpacks a consume rule.
        constexpr GamepadConsumeRule unpack_consume_rule(uint64_t packed) noexcept
        {
            return GamepadConsumeRule{static_cast<uint16_t>(packed & 0xFFFFu),
                                      static_cast<uint16_t>((packed >> 16) & 0xFFFFu),
                                      static_cast<uint16_t>((packed >> 32) & 0xFFFFu)};
        }

        std::array<std::atomic<std::uint64_t>, 4> s_wheel_count{wheel_count_slot(1, 0), wheel_count_slot(1, 0),
                                                                wheel_count_slot(1, 0), wheel_count_slot(1, 0)};
        // Index zero stores vertical distance, and index one stores horizontal distance. Each axis has one signed
        // remainder because a reversal cancels sub-notch distance while the axes remain independent.
        std::array<std::atomic<std::uint64_t>, 2> s_wheel_remainder{wheel_remainder_slot(1, false, 0),
                                                                    wheel_remainder_slot(1, false, 0)};
        // The per-direction wheel-swallow mask uses WheelDirection bits and pairs with a TTL. Each poll cycle refreshes
        // it, so a stalled poll thread stops the swallow action. "Ctrl+WheelUp" must not eat bare WheelDown or WheelUp.
        std::atomic<uint8_t> s_wheel_consume_mask{0};
        std::atomic<uint64_t> s_wheel_consume_deadline_ms{0};

        void clear_data_plane_locked(std::uint64_t wheel_epoch) noexcept
        {
            // Single-atomic disarms occur first, so detour suppression stops before the multi-step rule update begins.
            s_suppress_mask.store(0, std::memory_order_release);
            s_rule_suppress_enabled.store(false, std::memory_order_relaxed);
            s_wheel_consume_mask.store(0, std::memory_order_release);
            for (auto &count : s_wheel_count)
            {
                count.store(wheel_count_slot(wheel_epoch, 0), std::memory_order_relaxed);
            }
            for (auto &remainder : s_wheel_remainder)
            {
                remainder.store(wheel_remainder_slot(wheel_epoch, false, 0), std::memory_order_relaxed);
            }

            // Safe only because every writer now holds this lock, so the bracket cannot interleave with a binding
            // mutation. The clear exists so a later owner cannot inherit the previous owner's chords.
            const uint32_t seq = s_consume_rules_seq.load(std::memory_order_relaxed);
            s_consume_rules_seq.store(seq + 1, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            s_consume_rule_count.store(0, std::memory_order_relaxed);
            s_consume_rules_seq.store(seq + 2, std::memory_order_release);
        }

        std::atomic<HWND> s_hwnd{nullptr};
        std::atomic<LONG_PTR> s_prev_wndproc{0};
        std::atomic<bool> s_wndproc_installed{false};
        // Records the permanent module reference after install_wndproc takes it to keep wndproc_detour mapped. This
        // flag prevents one leaked reference per WM_NCDESTROY-rearmed window generation.
        // Only the poll thread touches it.
        std::atomic<bool> s_wndproc_ref_taken{false};

        // Local message-hook wheel-capture source (single-DLL fallback). An alternative to the WndProc subclass that
        // observes wheel messages through a thread-scoped WH_GETMESSAGE hook and feeds the same handle_wheel_message
        // fold and drain machinery. Selected instead of the WndProc subclass; both never run at once. Like the WndProc
        // keepalive, the module reference is permanent because a selected callback can run after UnhookWindowsHookEx.
        std::atomic<HHOOK> s_msg_hook{nullptr};
        std::atomic<bool> s_msg_hook_installed{false};
        std::atomic<bool> s_msg_hook_ref_taken{false};
#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<WndProcUninstallExchangeSeam> s_wndproc_uninstall_exchange_seam{nullptr};
#endif

        /// Takes a counted reference for the module at @p address and books it as an XInputTarget pin.
        [[nodiscard]] HMODULE acquire_module_ref_containing_address(const void *address) noexcept
        {
            if (address == nullptr)
            {
                return nullptr;
            }

            HMODULE module = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(address),
                                    &module))
            {
                return nullptr;
            }
            module_pin_observability::note_acquired(diagnostics::ModulePinReason::XInputTarget);
            return module;
        }

        /**
         * @brief Adds @p notches to an epoch-tagged, per-direction wheel counter with saturation.
         * @details A revocation retags the slot. A writer with the retired epoch fails and cannot publish into the
         *          successor backlog. Saturation bounds idle accretion after the last binding is gone.
         * @return true when the slot records the notches or is already saturated. Returns false when @p epoch is
         *         retired.
         */
        [[nodiscard]] bool bump_wheel_notch(std::atomic<std::uint64_t> &slot, std::uint64_t epoch,
                                            std::uint64_t notches = 1) noexcept
        {
            std::uint64_t current = slot.load(std::memory_order_relaxed);
            while (wheel_slot_epoch(current) == epoch)
            {
                const std::uint64_t count = current & WHEEL_COUNT_MASK;
                if (count >= MAX_WHEEL_NOTCHES)
                {
                    return true;
                }
                const std::uint64_t next =
                    std::min<std::uint64_t>(count + notches, static_cast<std::uint64_t>(MAX_WHEEL_NOTCHES));
                if (slot.compare_exchange_weak(current, wheel_count_slot(epoch, next), std::memory_order_relaxed,
                                               std::memory_order_relaxed))
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Folds one wheel message's signed delta into an axis remainder tagged by (epoch, owned).
         * @details A stored tag from another (epoch, owned) state contributes nothing, so ownership flips and epoch
         *          advances restart accumulation. A retired-epoch slot refuses the fold entirely.
         * @return The admission verdict and, when admitted, the signed whole-notch count of the fold.
         */
        struct WheelFold
        {
            bool admitted;
            int notches;
        };
        [[nodiscard]] WheelFold accumulate_wheel_remainder(std::atomic<std::uint64_t> &slot, std::uint64_t epoch,
                                                           bool owned, int delta) noexcept
        {
            std::uint64_t current = slot.load(std::memory_order_relaxed);
            while ((current >> WHEEL_REMAINDER_EPOCH_SHIFT) == epoch)
            {
                int prior = 0;
                if (((current & WHEEL_REMAINDER_OWNED_BIT) != 0) == owned)
                {
                    prior = static_cast<int>(current & WHEEL_REMAINDER_VALUE_MASK) - WHEEL_REMAINDER_BIAS;
                }
                // delta is a signed short and |prior| < WHEEL_DELTA, so the total cannot overflow int. The quotient
                // truncates toward zero and keeps the remainder sign equal to the total sign.
                const int total = prior + delta;
                const int notches = total / WHEEL_DELTA;
                const int remainder = total % WHEEL_DELTA;
                if (slot.compare_exchange_weak(current, wheel_remainder_slot(epoch, owned, remainder),
                                               std::memory_order_relaxed, std::memory_order_relaxed))
                {
                    return WheelFold{true, notches};
                }
            }
            return WheelFold{false, 0};
        }

        /**
         * @brief Reports whether the detour swallows a wheel message of the given direction this instant.
         * @details The acquire load of the mask orders the relaxed deadline read (publish_wheel_consume writes the
         *          deadline first). A lapsed deadline forwards, so the game is never latched out of its wheel.
         * @param direction_bit One WheelDirection bit for the message direction.
         */
        bool wheel_direction_consumed(uint8_t direction_bit) noexcept
        {
            if ((s_wheel_consume_mask.load(std::memory_order_acquire) & direction_bit) == 0)
            {
                return false;
            }
            return GetTickCount64() < s_wheel_consume_deadline_ms.load(std::memory_order_relaxed);
        }

        /**
         * @brief Processes one wheel message's signed delta: accumulates sub-notch distance, publishes whole
         *        notches, and decides the swallow verdict.
         * @details GET_WHEEL_DELTA_WPARAM is signed and need not be a WHEEL_DELTA multiple. The axis remainder folds
         *          fragments into `abs(total) / WHEEL_DELTA` notches. A reversal cancels accumulated distance. The
         *          (epoch, owned) tag separates owned and unowned fragments (WheelDeltaTest.*). The swallow verdict
         *          applies per message. An owned direction's fragment is swallowed before it completes a notch.
         * @param horizontal When true, selects Right/Left. When false, selects Up/Down.
         * @param delta Signed wheel delta from the message.
         * @param capture_state Atomic capture state sampled when the window-procedure frame began.
         * @return true when the message must be swallowed instead of forwarded.
         */
        [[nodiscard]] bool handle_wheel_message(bool horizontal, int delta, std::uint64_t capture_state) noexcept
        {
            if (delta == 0)
            {
                return false;
            }
            if ((capture_state & WHEEL_CAPTURE_ENABLED) == 0)
            {
                return false;
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (const WheelCaptureEntrySeam seam = s_wheel_capture_entry_seam.load(std::memory_order_acquire);
                seam != nullptr)
            {
                seam();
            }
#endif
            // A positive vertical delta scrolls up, and a negative delta scrolls down. A positive horizontal delta
            // tilts right, and a negative delta tilts left.
            const WheelDirection direction = horizontal ? (delta > 0 ? WheelDirection::Right : WheelDirection::Left)
                                                        : (delta > 0 ? WheelDirection::Up : WheelDirection::Down);
            const bool owned = wheel_direction_consumed(wheel_direction_bit(direction));
            const std::uint64_t epoch = wheel_capture_epoch(capture_state);
            const WheelFold fold =
                accumulate_wheel_remainder(s_wheel_remainder[horizontal ? 1 : 0], epoch, owned, delta);
            if (!fold.admitted)
            {
                return false;
            }
            if (fold.notches > 0)
            {
                const std::size_t positive_dir = horizontal ? 3u : 0u;
                (void)bump_wheel_notch(s_wheel_count[positive_dir], epoch, static_cast<std::uint64_t>(fold.notches));
            }
            else if (fold.notches < 0)
            {
                const std::size_t negative_dir = horizontal ? 2u : 1u;
                (void)bump_wheel_notch(s_wheel_count[negative_dir], epoch, static_cast<std::uint64_t>(-fold.notches));
            }
            return owned;
        }

        /**
         * @brief Clears the suppressed button bits from a game-bound XINPUT_STATE.
         * @details dwPacketNumber and the success return stay untouched, so the game sees a connected controller with
         *          packet progress. The cleared bits combine the reactive mask with the consume rules. A TTL guard
         *          drops all suppression after poll refreshes stop.
         */
        void apply_suppress(XINPUT_STATE *state, DWORD user_index) noexcept
        {
            // A retained primary route can remain physically reachable before recovery completes for its Ex partner.
            // Keep both routes fail-open until the complete logical installation is published.
            if (!s_xinput_installed.load(std::memory_order_acquire) || state == nullptr)
            {
                return;
            }
            if (static_cast<int>(user_index) != s_bound_user_index.load(std::memory_order_relaxed))
            {
                return;
            }
            // The acquire load of the mask orders the relaxed deadline read below (the writer stores the deadline
            // first), even when the mask reads as 0.
            const uint16_t reactive = s_suppress_mask.load(std::memory_order_acquire);

            // raw is the true, unmasked state because this detour runs after the trampoline call. A chord pressed
            // within one poll interval masks on the frame when the game reads it. The focus gate suppresses rule
            // evaluation while unfocused or disconnected, because the rule list and deadline survive those
            // transitions.
            const uint16_t raw = state->Gamepad.wButtons;
            const uint16_t rule_mask =
                s_rule_suppress_enabled.load(std::memory_order_relaxed) ? evaluate_published_consume_rules(raw) : 0;
            const uint16_t mask = static_cast<uint16_t>(reactive | rule_mask);
            if (mask == 0)
            {
                return;
            }
            // A stalled poll thread lets the deadline lapse and stops all suppression. The game regains its input
            // instead of a permanent latch.
            if (GetTickCount64() >= s_suppress_deadline_ms.load(std::memory_order_relaxed))
            {
                return;
            }
            state->Gamepad.wButtons = static_cast<WORD>(raw & static_cast<WORD>(~mask));
        }

        DWORD WINAPI xinput_get_state_detour(DWORD user_index, XINPUT_STATE *state) noexcept
        {
            const InflightGuard inflight;
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *seam = s_xinput_detour_body_seam.load(std::memory_order_acquire))
            {
                seam();
            }
#endif
            // This seq_cst load forms the detour side of the Dekker drain pair. See InflightGuard.
            const XInputGetStateFn original = s_xinput_original.load(std::memory_order_seq_cst);
            const DWORD result = (original != nullptr) ? original(user_index, state) : ERROR_DEVICE_NOT_CONNECTED;
            if (result == ERROR_SUCCESS)
            {
                apply_suppress(state, user_index);
            }
            return result;
        }

        DWORD WINAPI xinput_get_state_ex_detour(DWORD user_index, XINPUT_STATE *state) noexcept
        {
            const InflightGuard inflight;
            // This seq_cst load serves the same Dekker-pair reason as xinput_get_state_detour above.
            const XInputGetStateFn original = s_xinput_ex_original.load(std::memory_order_seq_cst);
            const DWORD result = (original != nullptr) ? original(user_index, state) : ERROR_DEVICE_NOT_CONNECTED;
            if (result == ERROR_SUCCESS)
            {
                apply_suppress(state, user_index);
            }
            return result;
        }

        LRESULT CALLBACK wndproc_detour(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) noexcept
        {
            const bool is_wheel_message = msg == WM_MOUSEWHEEL || msg == WM_MOUSEHWHEEL;
            const std::uint64_t capture_state =
                is_wheel_message ? s_wheel_capture_state.load(std::memory_order_seq_cst) : 0;
            const WNDPROC prev = reinterpret_cast<WNDPROC>(s_prev_wndproc.load(std::memory_order_acquire));

            switch (msg)
            {
            case WM_MOUSEWHEEL:
            {
                if (handle_wheel_message(false, GET_WHEEL_DELTA_WPARAM(wparam), capture_state))
                {
                    return 0;
                }
                break;
            }
            case WM_MOUSEHWHEEL:
            {
                if (handle_wheel_message(true, GET_WHEEL_DELTA_WPARAM(wparam), capture_state))
                {
                    return 0;
                }
                break;
            }
            case WM_NCDESTROY:
                // Drop all tracked subclass state so a later poll cycle re-subclasses a re-created game window. The
                // forward below uses the local prev copy, so the clear of s_prev_wndproc does not affect this
                // invocation. Store the installed flag last so a poll thread that observes false also sees the
                // cleared handle and predecessor.
                s_hwnd.store(nullptr, std::memory_order_release);
                s_prev_wndproc.store(0, std::memory_order_release);
                (void)close_wheel_capture_and_advance_epoch();
                s_wndproc_installed.store(false, std::memory_order_release);
                break;
            default:
                break;
            }

            if (prev != nullptr)
            {
                return CallWindowProcW(prev, hwnd, msg, wparam, lparam);
            }
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }

        // Local-fallback wheel source. A thread-scoped WH_GETMESSAGE hook on the game UI thread. It folds and counts
        // on PM_REMOVE only, reusing handle_wheel_message, and swallows an owned message with a WM_NULL rewrite. The
        // Stage 0 spike (docs/analysis/wheel_hook_spike_v4) froze these message-hook semantics: NOREMOVE observes
        // nothing, retrieval is counted once, and the consume is best effort because a newer hook can rewrite the
        // message after this callback returns.
        LRESULT CALLBACK message_hook_proc(int code, WPARAM wparam, LPARAM lparam) noexcept
        {
            if (code != HC_ACTION)
            {
                return CallNextHookEx(nullptr, code, wparam, lparam);
            }
            MSG *message = reinterpret_cast<MSG *>(lparam);
            const bool is_wheel = message->message == WM_MOUSEWHEEL || message->message == WM_MOUSEHWHEEL;
            if (!is_wheel || wparam != PM_REMOVE)
            {
                return CallNextHookEx(nullptr, code, wparam, lparam);
            }
            const std::uint64_t capture_state = s_wheel_capture_state.load(std::memory_order_seq_cst);
            const bool horizontal = message->message == WM_MOUSEHWHEEL;
            if (!handle_wheel_message(horizontal, GET_WHEEL_DELTA_WPARAM(message->wParam), capture_state))
            {
                return CallNextHookEx(nullptr, code, wparam, lparam);
            }
            // Swallow: blank before forwarding, re-assert after. A newer hook that rewrites after this returns wins,
            // which is the documented best-effort boundary.
            message->message = WM_NULL;
            message->wParam = 0;
            message->lParam = 0;
            const LRESULT result = CallNextHookEx(nullptr, code, wparam, lparam);
            message->message = WM_NULL;
            message->wParam = 0;
            message->lParam = 0;
            return result;
        }

        BOOL CALLBACK find_window_proc(HWND hwnd, LPARAM lparam) noexcept
        {
            auto *out = reinterpret_cast<HWND *>(lparam);
            DWORD window_pid = 0;
            GetWindowThreadProcessId(hwnd, &window_pid);
            // Accept the first visible, top-level, ownerless window from this process. The owner check
            // filters tool and splash windows. Visibility filters message-only and hidden helper windows.
            if (window_pid != GetCurrentProcessId() || !IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr)
            {
                return TRUE; // Continue enumeration.
            }
            *out = hwnd;
            return FALSE; // Stop enumeration.
        }

        HWND find_game_window() noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (const HWND override_window = s_wndproc_window_override.load(std::memory_order_acquire);
                override_window != nullptr)
            {
                return override_window;
            }
#endif
            HWND result = nullptr;
            EnumWindows(&find_window_proc, reinterpret_cast<LPARAM>(&result));
            if (result != nullptr)
            {
                return result;
            }
            // If enumeration finds no window, use the foreground window when this process owns it.
            const HWND foreground = GetForegroundWindow();
            if (foreground != nullptr)
            {
                DWORD pid = 0;
                GetWindowThreadProcessId(foreground, &pid);
                if (pid == GetCurrentProcessId())
                {
                    return foreground;
                }
            }
            return nullptr;
        }

        void uninstall_wndproc() noexcept
        {
            if (!s_wndproc_installed.load(std::memory_order_acquire))
            {
                return;
            }
            const HWND hwnd = s_hwnd.load(std::memory_order_acquire);
            if (hwnd == nullptr || !IsWindow(hwnd))
            {
                // The window was already destroyed. Its subclass no longer exists.
                s_hwnd.store(nullptr, std::memory_order_release);
                s_prev_wndproc.store(0, std::memory_order_release);
                s_wndproc_installed.store(false, std::memory_order_release);
                return;
            }

            const WNDPROC current = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(hwnd, GWLP_WNDPROC));
            if (current == &wndproc_detour)
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (const WndProcUninstallExchangeSeam seam =
                        s_wndproc_uninstall_exchange_seam.load(std::memory_order_acquire);
                    seam != nullptr)
                {
                    seam(hwnd, WndProcUninstallStage::BeforeExchange);
                }
#endif
                const LONG_PTR saved = s_prev_wndproc.load(std::memory_order_acquire);
                if (saved == 0)
                {
                    // A concurrent WM_NCDESTROY already cleared the predecessor. Zero is not a procedure. Its use here
                    // detaches the real chain, so converge on the destroy path and leave the chain intact.
                    s_hwnd.store(nullptr, std::memory_order_release);
                    s_wndproc_installed.store(false, std::memory_order_release);
                    return;
                }
                SetLastError(0);
                const LONG_PTR displaced = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, saved);
                if (displaced == 0 && GetLastError() != 0)
                {
                    // The exchange changed nothing. Keep the installed state so a retry cannot stack another DMK
                    // detour over a chain whose ownership was not resolved.
                    return;
                }

                if (displaced != reinterpret_cast<LONG_PTR>(&wndproc_detour))
                {
                    // A foreign subclass landed after the observation. Put the returned procedure back on top to
                    // restore foreign -> DMK -> saved, with DMK beneath the foreign subclass.
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (const WndProcUninstallExchangeSeam seam =
                            s_wndproc_uninstall_exchange_seam.load(std::memory_order_acquire);
                        seam != nullptr)
                    {
                        seam(hwnd, WndProcUninstallStage::BeforeCompensation);
                    }
#endif
                    SetLastError(0);
                    const LONG_PTR repair_displaced = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, displaced);
                    if (repair_displaced != saved && !(repair_displaced == 0 && GetLastError() != 0))
                    {
                        // A second writer won the compensation gap. Restore that latest writer rather than clobber it.
                        // Ownership is now uncertain, so retain the conservative installed state.
                        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, repair_displaced);
                    }
                    return;
                }

                // The exchange displaced DMK, so no FUTURE dispatch enters the detour. A frame already inside requires
                // the permanent module reference. Leave s_prev_wndproc set so that frame forwards to the game
                // procedure.
                s_hwnd.store(nullptr, std::memory_order_release);
                s_wndproc_installed.store(false, std::memory_order_release);
                return;
            }

            // Another subclass sits above ours. A restore clobbers it, so leave our inert forward detour installed.
            // Keep s_wndproc_installed true so a later install does not stack a duplicate detour.
        }

        void uninstall_message_hook() noexcept
        {
            if (!s_msg_hook_installed.load(std::memory_order_acquire))
            {
                return;
            }
            const HHOOK hook = s_msg_hook.load(std::memory_order_acquire);
            if (hook != nullptr)
            {
                // Cleanup only. Microsoft permits a selected callback to run after this returns, so the permanent
                // module reference is retained.
                if (UnhookWindowsHookEx(hook) == 0)
                {
                    return;
                }
            }
            s_msg_hook.store(nullptr, std::memory_order_release);
            (void)close_wheel_capture_and_advance_epoch();
            s_msg_hook_installed.store(false, std::memory_order_release);
        }
    } // anonymous namespace

    uint8_t step_wheel_pulse(WheelPulseState &state) noexcept
    {
        uint8_t mask = 0;
        for (int dir = 0; dir < 4; ++dir)
        {
            if (state.pulsing[dir])
            {
                // Force one low cycle after a pulse so the edge detector re-arms.
                state.pulsing[dir] = false;
            }
            else if (state.pending[dir] > 0)
            {
                --state.pending[dir];
                mask = static_cast<uint8_t>(mask | (1u << dir));
                state.pulsing[dir] = true;
            }
        }
        return mask;
    }

    void add_wheel_notches(WheelPulseState &state, const std::array<int, 4> &taken) noexcept
    {
        for (size_t dir = 0; dir < 4; ++dir)
        {
            const int add = taken[dir] > 0 ? taken[dir] : 0;
            // pending is in [0, MAX_WHEEL_PENDING] by induction, so room is nonnegative. Compare against room before
            // the addition so a large burst saturates instead of an int overflow.
            const int room = MAX_WHEEL_PENDING - state.pending[dir];
            state.pending[dir] = (add >= room) ? MAX_WHEEL_PENDING : state.pending[dir] + add;
        }
    }

    uint16_t step_gamepad_suppress(GamepadSuppressState &state, uint16_t owned_now, uint16_t true_buttons,
                                   uint64_t now_ms, uint64_t grace_ms) noexcept
    {
        // Sentinel deadline denotes "actively held, with no release underway."
        constexpr uint64_t held_sentinel = UINT64_MAX;

        uint16_t mask = 0;
        const uint16_t relevant = static_cast<uint16_t>(state.armed | owned_now);
        for (int bit = 0; bit < 16; ++bit)
        {
            const uint16_t bit_mask = static_cast<uint16_t>(1u << bit);
            if ((relevant & bit_mask) == 0)
            {
                continue;
            }
            const bool phys_down = (true_buttons & bit_mask) != 0;
            const bool owned = (owned_now & bit_mask) != 0;

            if (owned || ((state.armed & bit_mask) != 0 && phys_down))
            {
                // A current chord or a still-held trigger keeps suppression active after modifier release. Cancel any
                // active release grace.
                state.armed = static_cast<uint16_t>(state.armed | bit_mask);
                state.deadline_ms[static_cast<size_t>(bit)] = held_sentinel;
                mask = static_cast<uint16_t>(mask | bit_mask);
            }
            else if ((state.armed & bit_mask) != 0)
            {
                // If the armed button is physically up, run the release grace so a final bare-trigger frame cannot
                // reach the game.
                if (state.deadline_ms[static_cast<size_t>(bit)] == held_sentinel)
                {
                    state.deadline_ms[static_cast<size_t>(bit)] = now_ms + grace_ms;
                }
                if (now_ms < state.deadline_ms[static_cast<size_t>(bit)])
                {
                    mask = static_cast<uint16_t>(mask | bit_mask);
                }
                else
                {
                    state.armed = static_cast<uint16_t>(state.armed & static_cast<uint16_t>(~bit_mask));
                    state.deadline_ms[static_cast<size_t>(bit)] = 0;
                }
            }
        }
        return mask;
    }

    uint16_t evaluate_consume_rules(uint16_t true_buttons, const GamepadConsumeRule *rules, std::size_t count) noexcept
    {
        uint16_t mask = 0;
        for (std::size_t i = 0; i < count; ++i)
        {
            const GamepadConsumeRule &rule = rules[i];
            // The rule requires every modifier bit and rejects every forbidden bit. This matches the poll loop's exact
            // decision against the snapshot that the game reads. A forbidden bit belongs to a different chord.
            if ((true_buttons & rule.modifier_mask) == rule.modifier_mask && (true_buttons & rule.forbidden_mask) == 0)
            {
                mask = static_cast<uint16_t>(mask | rule.trigger_mask);
            }
        }
        return mask;
    }

    ConsumePublish publish_gamepad_consume_rules(const GamepadConsumeRule *rules, std::size_t count,
                                                 std::uint64_t owner) noexcept
    {
        run_data_plane_entry_seam();
        const DataPlaneLockGuard data_lock;
        if (!data_plane_authorized(owner))
        {
            // Refuse before the seqlock bracket opens, so an unauthorized caller leaves the sequence untouched and
            // even.
            return {};
        }

        // Keep the rules that fit and drop the rest. Each retained rule protects its chord. An empty list revokes all
        // initial-edge protection because one rule did not fit.
        const std::size_t published = count < MAX_GAMEPAD_CONSUME_RULES ? count : MAX_GAMEPAD_CONSUME_RULES;
        // This writer brackets the update with an odd sequence. The release fence keeps rule stores inside that
        // bracket. The even release store publishes the final list.
        const uint32_t seq = s_consume_rules_seq.load(std::memory_order_relaxed);
        s_consume_rules_seq.store(seq + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        for (std::size_t i = 0; i < published; ++i)
        {
            s_consume_rules[i].store(pack_consume_rule(rules[i]), std::memory_order_relaxed);
        }
        s_consume_rule_count.store(static_cast<uint32_t>(published), std::memory_order_relaxed);
        s_consume_rules_seq.store(seq + 2, std::memory_order_release);
        return {true, published};
    }

    uint16_t evaluate_published_consume_rules(uint16_t true_buttons) noexcept
    {
        // Seqlock read with one attempt and no spin. On an odd sequence or torn snapshot, skip rule suppression for
        // this frame. The reactive mask still applies. The next game poll gets the settled list.
        const uint32_t seq_before = s_consume_rules_seq.load(std::memory_order_acquire);
        if ((seq_before & 1u) != 0)
        {
            return 0;
        }
        uint32_t count = s_consume_rule_count.load(std::memory_order_relaxed);
        if (count > MAX_GAMEPAD_CONSUME_RULES)
        {
            count = MAX_GAMEPAD_CONSUME_RULES;
        }
        std::array<GamepadConsumeRule, MAX_GAMEPAD_CONSUME_RULES> snapshot{};
        for (uint32_t i = 0; i < count; ++i)
        {
            snapshot[i] = unpack_consume_rule(s_consume_rules[i].load(std::memory_order_relaxed));
        }
        // Order the rule loads before the sequence re-read, so a mid-copy writer is always detected.
        std::atomic_thread_fence(std::memory_order_acquire);
        if (s_consume_rules_seq.load(std::memory_order_relaxed) != seq_before)
        {
            return 0;
        }
        return evaluate_consume_rules(true_buttons, snapshot.data(), count);
    }

    bool set_gamepad_rule_suppress_enabled(bool enabled, std::uint64_t owner) noexcept
    {
        run_data_plane_entry_seam();
        const DataPlaneLockGuard data_lock;
        if (!data_plane_authorized(owner))
        {
            return false;
        }
        s_rule_suppress_enabled.store(enabled, std::memory_order_relaxed);
        return true;
    }

    std::uint64_t next_intercept_owner() noexcept
    {
        for (;;)
        {
            const std::uint64_t owner = s_next_intercept_owner.fetch_add(1, std::memory_order_relaxed);
            if (owner != 0 && owner != STANDALONE_INTERCEPT_OWNER)
            {
                return owner;
            }
        }
    }

    bool intercept_owned_by(std::uint64_t owner) noexcept
    {
        return owner != 0 && s_intercept_owner.load(std::memory_order_acquire) == owner;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    bool acquire_standalone_lease_for_test() noexcept
    {
        const InterceptLockGuard lock{s_intercept_mutex};
        if (!owner_available(STANDALONE_INTERCEPT_OWNER))
        {
            return false;
        }
        publish_owner(STANDALONE_INTERCEPT_OWNER);
        return true;
    }

    bool xinput_pair_degraded_for_test() noexcept
    {
        return s_xinput_pair_degraded.load(std::memory_order_acquire);
    }

    XInputPairCoverage xinput_pair_coverage_for_test() noexcept
    {
        const InterceptLockGuard lock{s_intercept_mutex};
        if (s_xinput_permanent_hooks == nullptr)
        {
            return XInputPairCoverage{false, true};
        }
        return XInputPairCoverage{xinput_member_entry_witnessed(s_xinput_permanent_hooks->primary, true),
                                  xinput_member_entry_witnessed(s_xinput_permanent_hooks->ex,
                                                                static_cast<bool>(s_xinput_permanent_hooks->ex))};
    }

    std::size_t xinput_recovery_attempts_for_test() noexcept
    {
        return s_xinput_recovery_attempts.load(std::memory_order_relaxed);
    }

    std::uint64_t expire_xinput_recovery_delay_for_test() noexcept
    {
        const InterceptLockGuard lock{s_intercept_mutex};
        const std::uint64_t delay_ms = s_xinput_recovery_delay_ms;
        s_xinput_recovery_not_before_ms = 0;
        return delay_ms;
    }

    bool adopt_owner_for_test(std::uint64_t owner) noexcept
    {
        const InterceptLockGuard lock{s_intercept_mutex};
        if (!owner_available(owner))
        {
            return false;
        }
        publish_owner(owner);
        return true;
    }
    void release_standalone_lease_for_test() noexcept
    {
        const InterceptLockGuard lock{s_intercept_mutex};
        if (s_intercept_owner.load(std::memory_order_relaxed) != STANDALONE_INTERCEPT_OWNER)
        {
            return;
        }
        revoke_owner_and_clear_data();
    }
#endif

    bool install_xinput(int user_index, std::uint64_t owner) noexcept
    {
        InterceptLockGuard lock{s_intercept_mutex};
        XInputRetentionLog deferred_log;

        if (!owner_available(owner))
        {
            return false;
        }

        if (s_xinput_permanent_detour.load(std::memory_order_acquire))
        {
            PermanentXInputHooks *const permanent = permanent_cell();
            if (!permanent->primary)
            {
                // No primary storage remains. A fresh hook over the current export creates the uncertain-storage case
                // that retention avoids.
                return false;
            }
            // Recovery re-arms each absent member through its retained hook. It never creates a second hook over the
            // current prologue.
            const bool whole = maintain_xinput_pair(permanent->primary, permanent->ex,
                                                    permanent->ex_target_ref != nullptr ? permanent->ex_target_ref
                                                                                        : permanent->target_ref,
                                                    user_index, owner);
            return whole;
        }

        // A live pair uses one transaction for health maintenance and recovery. A second hook over its prologue
        // captures the first hook's jmp as its original and corrupts the trampoline chain.
        if (s_xinput_permanent_hooks != nullptr && static_cast<bool>(s_xinput_permanent_hooks->primary))
        {
            return maintain_xinput_pair(s_xinput_permanent_hooks->primary, s_xinput_permanent_hooks->ex,
                                        s_xinput_permanent_hooks->ex_target_ref != nullptr
                                            ? s_xinput_permanent_hooks->ex_target_ref
                                            : s_xinput_permanent_hooks->target_ref,
                                        user_index, owner);
        }

        HMODULE module = nullptr;
#if defined(DMK_ENABLE_TEST_SEAMS)
        if (s_xinput_module_override != nullptr)
        {
            module = s_xinput_module_override;
        }
        else
#endif
        {
            for (const wchar_t *name : XINPUT_DLL_NAMES)
            {
                module = GetModuleHandleW(name);
                if (module != nullptr)
                {
                    break;
                }
            }
        }
        if (module == nullptr)
        {
            return false; // XInput is not loaded yet. The poll loop retries.
        }

        auto *get_state = reinterpret_cast<void *>(GetProcAddress(module, "XInputGetState"));
        if (get_state == nullptr)
        {
            return false;
        }

        // XInputGetStateEx (ordinal 100) carries the Guide button. Without its hook, a game can bypass the mask.
        // An absent export needs no second hook. The primary route already covers an alias.
        auto *get_state_ex =
            reinterpret_cast<void *>(GetProcAddress(module, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        const bool ex_is_distinct_member = get_state_ex != nullptr && get_state_ex != get_state;

        // Construct the canonical cell before any reference or target patch.
        if (!ensure_permanent_cell())
        {
            return false;
        }

        // Take every keepalive before any prologue patch. The retention teardown has no allocator or loader call.
        // Fail closed and let the poll loop retry.
        s_xinput_permanent_hooks->self_ref =
            DetourModKit::detail::acquire_module_ref(diagnostics::ModulePinReason::XInputKeepalive);
        if (s_xinput_permanent_hooks->self_ref == nullptr)
        {
            return false;
        }
        s_xinput_permanent_hooks->target_ref = acquire_module_ref_containing_address(get_state);
        if (s_xinput_permanent_hooks->target_ref == nullptr)
        {
            release_xinput_module_refs();
            return false;
        }
        if (ex_is_distinct_member)
        {
            const HMODULE ex_target_ref = acquire_module_ref_containing_address(get_state_ex);
            if (ex_target_ref == nullptr)
            {
                release_xinput_module_refs();
                return false;
            }
            if (ex_target_ref == s_xinput_permanent_hooks->target_ref)
            {
                // The primary pin already covers this prologue. Balance the duplicate probe reference now.
                DetourModKit::detail::release_module_ref(ex_target_ref, diagnostics::ModulePinReason::XInputTarget);
            }
            else
            {
                s_xinput_permanent_hooks->ex_target_ref = ex_target_ref;
            }
        }

        // Reserve the worst case for BOTH members before either creation. A primary charge followed by an Ex refusal
        // strands the primary-only coverage that this transaction prevents.
        safetyhook::RouteRetentionCredit pair_credit = safetyhook::RouteRetentionCredit::acquire(2);
        if (!pair_credit)
        {
            if (!s_xinput_capacity_warned.exchange(true, std::memory_order_relaxed))
            {
                (void)log().log_noexcept(LogLevel::Warning,
                                         "InputIntercept: the routed retention ceiling refused the XInput hook pair, "
                                         "so no XInput interception was installed and both entries remain open.");
            }
            release_xinput_module_refs();
            return false;
        }

        // Create both members before either prologue patch. Before an arm runs, no thread enters a detour. A creation
        // failure rolls the whole transaction back and leaves both entries open.
        if (!create_disabled_xinput_hook(pair_credit, get_state, reinterpret_cast<void *>(&xinput_get_state_detour),
                                         s_xinput_permanent_hooks->primary))
        {
            release_xinput_module_refs();
            return false;
        }
        if (ex_is_distinct_member && !create_disabled_xinput_hook(pair_credit, get_state_ex,
                                                                  reinterpret_cast<void *>(&xinput_get_state_ex_detour),
                                                                  s_xinput_permanent_hooks->ex))
        {
            reset_inactive_xinput_hook(s_xinput_permanent_hooks->primary, s_xinput_original);
            release_xinput_module_refs();
            return false;
        }

        const XInputArmOutcome primary_outcome = arm_created_xinput_hook(
            s_xinput_permanent_hooks->primary, s_xinput_original, s_xinput_enable_warned,
            "InputIntercept: XInputGetState hook transaction did not complete cleanly; state was "
            "reconciled from the target bytes.");
        if (primary_outcome == XInputArmOutcome::CommittedUnreachable)
        {
            // A game thread can hold this trampoline and nothing here can drain it. Retain the created, disabled
            // ordinal-100 member too. Recovery must arm that retained object rather than treat an empty
            // slot as the absent/alias exemption.
            const XInputPublishedChains published_chains{s_xinput_original.load(std::memory_order_seq_cst) != nullptr,
                                                         s_xinput_ex_original.load(std::memory_order_seq_cst) !=
                                                             nullptr};
            retain_xinput_hooks(PatchWitness::Original, PatchWitness::Original, XInputRetentionReason::UnprovedInstall,
                                deferred_log, published_chains);
            lock.unlock();
            emit_xinput_retention_log(deferred_log);
            return false;
        }
        if (primary_outcome != XInputArmOutcome::Armed)
        {
            reset_inactive_xinput_hook(s_xinput_permanent_hooks->ex, s_xinput_ex_original);
            reset_inactive_xinput_hook(s_xinput_permanent_hooks->primary, s_xinput_original);
            release_xinput_module_refs();
            return false;
        }

        if (ex_is_distinct_member)
        {
            (void)arm_created_xinput_hook(
                s_xinput_permanent_hooks->ex, s_xinput_ex_original, s_xinput_ex_enable_warned,
                "InputIntercept: the XInputGetStateEx hook transaction did not complete cleanly, so XInput coverage "
                "stays degraded and both entries pass through.");
        }

        // The final pair witness reads both prologues before the store that enables suppression. A member
        // restored by a rival writer degrades the pair and prevents publication of incomplete coverage.
        if (publish_xinput_pair_if_whole(s_xinput_permanent_hooks->primary, s_xinput_permanent_hooks->ex, user_index,
                                         owner))
        {
            return true;
        }
        // Clear the gate rather than defer: the next poll cycle attempts the first recovery immediately.
        xinput_recovery_reset();
        return false;
    }

    bool xinput_installed() noexcept
    {
        return s_xinput_installed.load(std::memory_order_acquire);
    }

    XInputGetStateFn xinput_trampoline() noexcept
    {
        if (!s_xinput_installed.load(std::memory_order_acquire) &&
            !s_xinput_pair_degraded.load(std::memory_order_acquire))
        {
            return nullptr;
        }
        return s_xinput_original.load(std::memory_order_acquire);
    }

    bool publish_gamepad_suppress(uint16_t suppress_bits, std::uint64_t owner) noexcept
    {
        run_data_plane_entry_seam();
        const DataPlaneLockGuard data_lock;
        if (!data_plane_authorized(owner))
        {
            return false;
        }
        // Write the deadline before the release store on the mask, so a fresh mask is never paired with a stale
        // deadline.
        s_suppress_deadline_ms.store(GetTickCount64() + SUPPRESS_TTL_MS, std::memory_order_relaxed);
        s_suppress_mask.store(suppress_bits, std::memory_order_release);
        return true;
    }

    bool install_wndproc(std::uint64_t owner) noexcept
    {
        const InterceptLockGuard lock{s_intercept_mutex};
        if (!owner_available(owner))
        {
            return false;
        }
        if (s_msg_hook_installed.load(std::memory_order_acquire))
        {
            return false;
        }
        if (s_wndproc_installed.load(std::memory_order_acquire))
        {
            publish_owner(owner);
            return true;
        }
        const HWND hwnd = find_game_window();
        if (hwnd == nullptr)
        {
            return false; // The window is not available yet. The poll loop retries.
        }

        // Take the keepalive before the detour becomes reachable. A successful publication makes it permanent because
        // an active frame can return through this module after a later restore. A failed publication releases it.
        HMODULE new_ref = nullptr;
        if (!s_wndproc_ref_taken.load(std::memory_order_relaxed))
        {
            new_ref = acquire_module_ref(diagnostics::ModulePinReason::WndprocKeepalive);
            if (new_ref == nullptr)
            {
                return false;
            }
        }

        // Publish the predecessor and target window before the detour goes live. A message in the gap otherwise reads
        // a zero s_prev_wndproc and routes to DefWindowProcW. A top-level window always has a non-null WNDPROC.
        // A zero read means the slot is not readable yet. A foreign subclasser that installs
        // between this read and the swap is reconciled from the returned predecessor below.
        const LONG_PTR current = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
        if (current == 0)
        {
            release_module_ref(new_ref, diagnostics::ModulePinReason::WndprocKeepalive);
            return false;
        }
        s_prev_wndproc.store(current, std::memory_order_release);
        s_hwnd.store(hwnd, std::memory_order_release);

        // Disambiguate a genuine zero predecessor from an error via GetLastError.
        SetLastError(0);
        const LONG_PTR prev = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&wndproc_detour));
        if (prev == 0 && GetLastError() != 0)
        {
            // If the swap fails, clear the published predecessor state so no stale handle survives.
            s_hwnd.store(nullptr, std::memory_order_release);
            s_prev_wndproc.store(0, std::memory_order_release);
            release_module_ref(new_ref, diagnostics::ModulePinReason::WndprocKeepalive);
            return false;
        }

        if (new_ref != nullptr)
        {
            s_wndproc_ref_taken.store(true, std::memory_order_relaxed);
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);
        }

        // The returned displaced WNDPROC is the real next link when a foreign subclasser lands in the gap. Adopt and
        // republish it so the subclass chain stays intact. A genuine zero predecessor
        // was already rejected above, so a non-zero mismatch is the only adoption case.
        if (prev != 0 && prev != current)
        {
            s_prev_wndproc.store(prev, std::memory_order_release);
        }

        // Drain notches that the detour latched while no binding owned the wheel. Without the drain, the first
        // take_wheel_counts() after a rebind replays phantom notches. This fresh-install transition discards no live
        // count.
        const std::uint64_t wheel_epoch = wheel_capture_epoch(s_wheel_capture_state.load(std::memory_order_seq_cst));
        for (auto &count : s_wheel_count)
        {
            count.store(wheel_count_slot(wheel_epoch, 0), std::memory_order_relaxed);
        }
        // A stale sub-notch fragment must not complete a notch with the new binding set's first fragment.
        for (auto &remainder : s_wheel_remainder)
        {
            remainder.store(wheel_remainder_slot(wheel_epoch, false, 0), std::memory_order_relaxed);
        }

        s_wndproc_installed.store(true, std::memory_order_release);
        publish_owner(owner);
        return true;
    }

    bool wndproc_installed() noexcept
    {
        return s_wndproc_installed.load(std::memory_order_acquire);
    }

    bool install_message_hook(std::uint64_t owner) noexcept
    {
        const InterceptLockGuard lock{s_intercept_mutex};
        if (!owner_available(owner))
        {
            return false;
        }
        if (s_wndproc_installed.load(std::memory_order_acquire))
        {
            return false;
        }
        if (s_msg_hook_installed.load(std::memory_order_acquire))
        {
            publish_owner(owner);
            return true;
        }
        const HWND hwnd = find_game_window();
        if (hwnd == nullptr)
        {
            return false; // The window is not available yet. The poll loop retries.
        }
        const DWORD thread_id = GetWindowThreadProcessId(hwnd, nullptr);
        if (thread_id == 0)
        {
            return false;
        }

        // Take the keepalive before the hook is published. A successful publication makes it permanent because a
        // selected callback can run after UnhookWindowsHookEx returns. A failed publication releases it.
        HMODULE new_ref = nullptr;
        if (!s_msg_hook_ref_taken.load(std::memory_order_relaxed))
        {
            new_ref = acquire_module_ref(diagnostics::ModulePinReason::MessageHookKeepalive);
            if (new_ref == nullptr)
            {
                return false;
            }
        }

        const HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, &message_hook_proc, nullptr, thread_id);
        if (hook == nullptr)
        {
            release_module_ref(new_ref, diagnostics::ModulePinReason::MessageHookKeepalive);
            return false;
        }
        if (new_ref != nullptr)
        {
            s_msg_hook_ref_taken.store(true, std::memory_order_relaxed);
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);
        }
        s_msg_hook.store(hook, std::memory_order_release);
        s_msg_hook_installed.store(true, std::memory_order_release);
        publish_owner(owner);
        return true;
    }

    bool message_hook_installed() noexcept
    {
        return s_msg_hook_installed.load(std::memory_order_acquire);
    }

    LONG_PTR wndproc_saved_procedure() noexcept
    {
        return s_prev_wndproc.load(std::memory_order_acquire);
    }

    std::array<int, 4> take_wheel_counts(std::uint64_t owner) noexcept
    {
        run_data_plane_entry_seam();
        const DataPlaneLockGuard data_lock;
        std::array<int, 4> out{};
        if (!data_plane_authorized(owner))
        {
            return out;
        }
        const std::uint64_t wheel_epoch = wheel_capture_epoch(s_wheel_capture_state.load(std::memory_order_seq_cst));
        for (int dir = 0; dir < 4; ++dir)
        {
            const std::uint64_t packed = s_wheel_count[static_cast<size_t>(dir)].exchange(
                wheel_count_slot(wheel_epoch, 0), std::memory_order_relaxed);
            if (wheel_slot_epoch(packed) == wheel_epoch)
            {
                out[static_cast<size_t>(dir)] = static_cast<int>(packed & WHEEL_COUNT_MASK);
            }
        }
        return out;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    void seed_wheel_notches_for_test(const std::array<int, 4> &notches) noexcept
    {
        const std::uint64_t wheel_epoch = wheel_capture_epoch(s_wheel_capture_state.load(std::memory_order_seq_cst));
        for (size_t dir = 0; dir < s_wheel_count.size(); ++dir)
        {
            // Saturate to bump_wheel_notch's ceiling so a seeded backlog stays a producible state.
            int n = notches[dir];
            if (n < 0)
            {
                n = 0;
            }
            else if (n > MAX_WHEEL_NOTCHES)
            {
                n = MAX_WHEEL_NOTCHES;
            }
            s_wheel_count[dir].store(wheel_count_slot(wheel_epoch, static_cast<std::uint64_t>(n)),
                                     std::memory_order_relaxed);
        }
    }
#endif

    bool publish_wheel_consume(uint8_t direction_mask, std::uint64_t owner) noexcept
    {
        run_data_plane_entry_seam();
        const DataPlaneLockGuard data_lock;
        if (!data_plane_authorized(owner))
        {
            return false;
        }
        // Refresh the deadline before the mask release store, but only for a nonzero arm. This order ensures a set
        // direction bit never appears with a stale deadline. A zero mask needs no deadline.
        if (direction_mask != 0)
        {
            s_wheel_consume_deadline_ms.store(GetTickCount64() + SUPPRESS_TTL_MS, std::memory_order_relaxed);
        }
        s_wheel_consume_mask.store(direction_mask, std::memory_order_release);
        return true;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    void set_xinput_arm_seam(XInputArmSeam seam) noexcept
    {
        s_xinput_arm_seam.store(seam, std::memory_order_release);
    }

    void set_xinput_detour_body_seam(XInputDetourBodySeam seam) noexcept
    {
        s_xinput_detour_body_seam.store(seam, std::memory_order_release);
    }

    void set_xinput_route_entry_hold_for_test(bool hold) noexcept
    {
        safetyhook::set_route_park_for_test(hold ? safetyhook::RouteParkStage::BEFORE_DESTINATION
                                                 : safetyhook::RouteParkStage::NONE);
    }

    bool xinput_route_entry_reached_for_test() noexcept
    {
        return safetyhook::route_park_reached_for_test();
    }

    void set_xinput_clean_release_seam(XInputCleanReleaseSeam seam) noexcept
    {
        s_xinput_clean_release_seam.store(seam, std::memory_order_release);
    }

    void set_xinput_retention_attribution_seam(XInputRetentionAttributionSeam seam) noexcept
    {
        s_xinput_retention_attribution_seam.store(seam, std::memory_order_release);
    }

    void set_xinput_create_seam(XInputCreateSeam seam) noexcept
    {
        s_xinput_create_seam.store(seam, std::memory_order_release);
    }

    void set_xinput_backend_toggle_exception_for_test(void *target, bool after_mutation) noexcept
    {
        if (target == nullptr)
        {
            safetyhook::g_trap_exception_stage_override.store(safetyhook::TrapExceptionStage::NONE,
                                                              std::memory_order_release);
            safetyhook::g_trap_exception_target_override.store(nullptr, std::memory_order_relaxed);
            return;
        }

        s_xinput_backend_toggle_exception_catches.store(0, std::memory_order_relaxed);
        safetyhook::g_trap_exception_target_override.store(static_cast<std::uint8_t *>(target),
                                                           std::memory_order_relaxed);
        safetyhook::g_trap_exception_stage_override.store(after_mutation
                                                              ? safetyhook::TrapExceptionStage::AFTER_MUTATION
                                                              : safetyhook::TrapExceptionStage::BEFORE_MUTATION,
                                                          std::memory_order_release);
    }

    std::size_t xinput_backend_toggle_exception_catches_for_test() noexcept
    {
        return s_xinput_backend_toggle_exception_catches.load(std::memory_order_relaxed);
    }

    void set_wndproc_uninstall_exchange_seam(WndProcUninstallExchangeSeam seam) noexcept
    {
        s_wndproc_uninstall_exchange_seam.store(seam, std::memory_order_release);
    }

    void set_wndproc_window_override_for_test(HWND window) noexcept
    {
        s_wndproc_window_override.store(window, std::memory_order_release);
    }

    bool xinput_permanent_primary_retained() noexcept
    {
        return s_xinput_permanent_detour.load(std::memory_order_acquire) && s_xinput_permanent_hooks != nullptr &&
               static_cast<bool>(s_xinput_permanent_hooks->primary);
    }

    int xinput_module_refs_held() noexcept
    {
        return s_xinput_permanent_hooks != nullptr ? (s_xinput_permanent_hooks->self_ref != nullptr ? 1 : 0) +
                                                         (s_xinput_permanent_hooks->target_ref != nullptr ? 1 : 0) +
                                                         (s_xinput_permanent_hooks->ex_target_ref != nullptr ? 1 : 0)
                                                   : 0;
    }

    void arm_xinput_process_exit_oracle_for_test(const std::uint8_t *target) noexcept
    {
        if (target == nullptr)
        {
            return;
        }
        for (std::size_t i = 0; i < XINPUT_PROCESS_EXIT_WITNESS_BYTES; ++i)
        {
            s_xinput_process_exit_patch[i] = target[i];
        }
        s_xinput_process_exit_target.store(target, std::memory_order_release);
    }

    void set_xinput_module_override_for_test(HMODULE module) noexcept
    {
        const InterceptLockGuard lock{s_intercept_mutex};
        s_xinput_module_override = module;
    }

    XInputGetStateFn xinput_ex_trampoline() noexcept
    {
        return s_xinput_ex_original.load(std::memory_order_acquire);
    }

    void apply_xinput_suppress_for_test(XINPUT_STATE *state, DWORD user_index) noexcept
    {
        apply_suppress(state, user_index);
    }

    int xinput_bound_user_index() noexcept
    {
        return s_bound_user_index.load(std::memory_order_relaxed);
    }

    void set_data_plane_entry_seam(DataPlaneEntrySeam seam) noexcept
    {
        s_data_plane_entry_seam.store(seam, std::memory_order_release);
    }

    void set_wheel_capture_entry_seam(WheelCaptureEntrySeam seam) noexcept
    {
        s_wheel_capture_entry_seam.store(seam, std::memory_order_release);
    }

    bool process_wheel_message_for_test(bool horizontal, int delta) noexcept
    {
        const std::uint64_t capture_state = s_wheel_capture_state.load(std::memory_order_seq_cst);
        return handle_wheel_message(horizontal, delta, capture_state);
    }

    std::uint32_t consume_rules_sequence() noexcept
    {
        return s_consume_rules_seq.load(std::memory_order_acquire);
    }

    std::uint16_t gamepad_suppress_mask_for_test() noexcept
    {
        return s_suppress_mask.load(std::memory_order_acquire);
    }

    bool gamepad_rule_suppress_enabled_for_test() noexcept
    {
        return s_rule_suppress_enabled.load(std::memory_order_acquire);
    }

    std::uint8_t wheel_consume_mask_for_test() noexcept
    {
        return s_wheel_consume_mask.load(std::memory_order_acquire);
    }
#endif

    void uninstall(std::uint64_t owner) noexcept
    {
        InterceptLockGuard lock{s_intercept_mutex};
        XInputRetentionLog deferred_log;
        if (owner == 0 || s_intercept_owner.load(std::memory_order_relaxed) != owner)
        {
            return;
        }

        // revoke_owner_and_clear_data() atomically revokes the layer and clears its data before teardown. The active
        // InterceptLockGuard serializes teardown. Data-plane writers use s_data_plane_mutex, so a revoked owner cannot
        // publish live state.
        revoke_owner_and_clear_data();

        uninstall_wndproc();
        uninstall_message_hook();

        if (s_xinput_permanent_detour.load(std::memory_order_acquire))
        {
            // A prior timeout or uncertain restore made the canonical hooks permanent.
            // This call only disarms the logical layer. A reachable retained entry continues to forward.
            s_xinput_installed.store(false, std::memory_order_release);
            s_xinput_pair_degraded.store(false, std::memory_order_release);
            xinput_recovery_reset();
            s_xinput_enable_warned.store(false, std::memory_order_relaxed);
            s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
            s_xinput_capacity_warned.store(false, std::memory_order_relaxed);
            return;
        }

        if (s_xinput_permanent_hooks == nullptr)
        {
            s_xinput_installed.store(false, std::memory_order_release);
            s_xinput_pair_degraded.store(false, std::memory_order_release);
            xinput_recovery_reset();
            return;
        }

        // Close backend admission before pointer retirement. This covers the interval before InflightGuard and the
        // body it counts. The exit structure resolves both routes from their byte witnesses. Retention exits use
        // retain_xinput_hooks. The clean exit uses reset_inactive_xinput_hook.
        s_xinput_permanent_hooks->ex.begin_route_rundown();
        s_xinput_permanent_hooks->primary.begin_route_rundown();

        // Retire the published trampoline pointers before the drain. A late entrant sees nullptr instead of a pointer
        // into a hook near destruction. seq_cst places these stores and the drain load in the detour total order.
        const XInputPublishedChains published_chains{s_xinput_original.load(std::memory_order_seq_cst) != nullptr,
                                                     s_xinput_ex_original.load(std::memory_order_seq_cst) != nullptr};
        s_xinput_ex_original.store(nullptr, std::memory_order_seq_cst);
        s_xinput_original.store(nullptr, std::memory_order_seq_cst);

        // Quiesce detours that already copied a trampoline. Use a wall-clock bound, not a yield count. A hot game
        // thread can enter after pointer retirement, and teardown must still progress.
        constexpr uint64_t xinput_quiesce_timeout_ms = 10;
        const uint64_t quiesce_deadline_ms = GetTickCount64() + xinput_quiesce_timeout_ms;
        while ((s_xinput_inflight.load(std::memory_order_seq_cst) != 0 ||
                s_xinput_permanent_hooks->primary.route_entries() != 0 ||
                s_xinput_permanent_hooks->ex.route_entries() != 0) &&
               GetTickCount64() < quiesce_deadline_ms)
        {
            std::this_thread::yield();
        }

        const bool route_still_inflight = s_xinput_inflight.load(std::memory_order_seq_cst) != 0 ||
                                          s_xinput_permanent_hooks->primary.route_entries() != 0 ||
                                          s_xinput_permanent_hooks->ex.route_entries() != 0;
        if (route_still_inflight)
        {
            retain_xinput_hooks(xinput_teardown_witness(s_xinput_permanent_hooks->primary),
                                xinput_teardown_witness(s_xinput_permanent_hooks->ex),
                                XInputRetentionReason::InflightTimeout, deferred_log, published_chains);
            lock.unlock();
            emit_xinput_retention_log(deferred_log);
            return;
        }

        // Classify both targets before either backend restore. If a newer layer owns either prologue, refuse the whole
        // pair rather than overwrite that layer with a partial teardown.
        const PatchWitness primary_before = xinput_teardown_witness(s_xinput_permanent_hooks->primary);
        const PatchWitness ex_before = xinput_teardown_witness(s_xinput_permanent_hooks->ex);
        if (!witness_permits_write(primary_before) || !witness_permits_write(ex_before))
        {
            retain_xinput_hooks(primary_before, ex_before, XInputRetentionReason::UnrestoredPatch, deferred_log);
            lock.unlock();
            emit_xinput_retention_log(deferred_log);
            return;
        }

        // Restore Ex first, then primary. A caught exception can occur before or after either mutation, so the byte
        // witness after each call is authoritative. Only Original permits the hook object and keepalives to be freed.
        const PatchWitness ex_after = restore_xinput_hook(s_xinput_permanent_hooks->ex);
        if (ex_after != PatchWitness::Original)
        {
            retain_xinput_hooks(primary_before, ex_after, XInputRetentionReason::UnrestoredPatch, deferred_log);
            lock.unlock();
            emit_xinput_retention_log(deferred_log);
            return;
        }
        const PatchWitness primary_after = restore_xinput_hook(s_xinput_permanent_hooks->primary);
        if (primary_after != PatchWitness::Original)
        {
            // The pair is one transaction and this half did not commit. Put the Ex member back first. Immediate
            // retention publishes a primary-only chain and permanently drops the covered ordinal-100 entry point.
            // Compensation reuses the current hook, and its own witness gate declines rather than fight a newer
            // writer.
            const PatchWitness ex_compensated =
                rearm_xinput_hook(s_xinput_permanent_hooks->ex, s_xinput_ex_original, s_xinput_ex_enable_warned,
                                  "InputIntercept: the XInputGetStateEx re-arm that compensates a refused primary "
                                  "restore did not complete cleanly; Ex state was reconciled from the target bytes.")
                    ? xinput_teardown_witness(s_xinput_permanent_hooks->ex)
                    : PatchWitness::Original;
            retain_xinput_hooks(primary_after, ex_compensated, XInputRetentionReason::UnrestoredPatch, deferred_log);
            lock.unlock();
            emit_xinput_retention_log(deferred_log);
            return;
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        if (const XInputCleanReleaseSeam seam = s_xinput_clean_release_seam.load(std::memory_order_acquire);
            seam != nullptr)
        {
            seam();
        }
#endif

        reset_inactive_xinput_hook(s_xinput_permanent_hooks->ex, s_xinput_ex_original);
        reset_inactive_xinput_hook(s_xinput_permanent_hooks->primary, s_xinput_original);

        // No detour code remains active. A later install_xinput() takes a fresh pair.
        release_xinput_module_refs();

        s_xinput_installed.store(false, std::memory_order_release);
        s_xinput_pair_degraded.store(false, std::memory_order_release);
        xinput_recovery_reset();
        // Re-arm the enable()-failure latches so a fresh install after a hot-reload can warn again.
        s_xinput_enable_warned.store(false, std::memory_order_relaxed);
        s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
        s_xinput_capacity_warned.store(false, std::memory_order_relaxed);
    }

} // namespace DetourModKit::detail
