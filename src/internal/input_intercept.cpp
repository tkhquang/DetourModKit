/**
 * @file input_intercept.cpp
 * @brief Implementation of the internal active-input layer (input_intercept.hpp).
 *
 * Owns the XInputGetState inline hook and the window-procedure subclass that back gamepad passthrough suppression and
 * mouse-wheel capture for InputPoller.
 */

#include "input_intercept.hpp"
#include "internal/hook_patch_witness.hpp"
#include "platform.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"

#include <safetyhook.hpp>

#include <atomic>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <string_view>
#include <thread>
#include <utility>

namespace DetourModKit::detail
{
    namespace
    {
        /// XInput export resides in one of these DLLs depending on the game/runtime.
        constexpr const wchar_t *XINPUT_DLL_NAMES[] = {
            L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll", L"xinput1_2.dll", L"xinput1_1.dll",
        };

        /// Undocumented ordinal that exports XInputGetStateEx (reports the Guide button).
        constexpr WORD XINPUT_GET_STATE_EX_ORDINAL = 100;

        /**
         * @brief How long a published suppression mask stays valid without a refresh.
         * @details Set above the maximum allowed poll interval (MAX_POLL_INTERVAL) so a healthy poll thread at any
         *          configured rate keeps the mask continuously alive, while still bounding a stalled poll thread so it
         *          cannot latch the game's input off indefinitely. Twice the largest poll interval leaves headroom for
         *          a slow cycle's own body to run before the deadline lapses.
         */
        constexpr uint64_t SUPPRESS_TTL_MS = 2000;

        // The layer has one owner because its hooks and keepalives are process-global. The token prevents a superseded
        // poller from tearing down a newer installation; the SRW lock serializes the multi-step control-plane changes.
        // Static SRWLOCK storage has no destructor, so late process teardown cannot encounter a destroyed mutex.
        SRWLOCK s_intercept_mutex = SRWLOCK_INIT;
        // Serializes owner publication, owner revocation, and every write or drain of the state the detours read, so
        // the owner check and the write it authorizes are one indivisible step. Checking the owner and then writing
        // under separate locks leaves the window this exists to close: a poller that reads its own id as current can
        // be revoked and superseded before the write lands, and would then overwrite the new owner's published state.
        // Acquired after s_intercept_mutex wherever both are held, never before it. The detours take neither lock.
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

        std::atomic<std::uint64_t> s_wheel_capture_state{wheel_capture_state(1, false)};
#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<WheelCaptureEntrySeam> s_wheel_capture_entry_seam{nullptr};
#endif

        /** @brief Scoped exclusive ownership of the process-lifetime interception lock. */
        class InterceptLockGuard
        {
        public:
            explicit InterceptLockGuard(SRWLOCK &mutex) noexcept : m_mutex(mutex) { AcquireSRWLockExclusive(&m_mutex); }

            ~InterceptLockGuard() noexcept { ReleaseSRWLockExclusive(&m_mutex); }

            InterceptLockGuard(const InterceptLockGuard &) = delete;
            InterceptLockGuard &operator=(const InterceptLockGuard &) = delete;
            InterceptLockGuard(InterceptLockGuard &&) = delete;
            InterceptLockGuard &operator=(InterceptLockGuard &&) = delete;

        private:
            SRWLOCK &m_mutex;
        };

        /**
         * @brief Requires s_intercept_mutex. Reports whether @p owner may CLAIM the layer.
         * @details A claim predicate only. It admits the unowned layer, which is correct for taking ownership and wrong
         *          for authorizing a write: owning nothing is not permission to mutate process-global state the detours
         *          read. Data-plane authorization is data_plane_authorized(), which requires an exact match.
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

        /// Requires s_data_plane_mutex. Reports whether @p owner may write the state the detours read.
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

        /** @brief Scoped exclusive ownership of the process-lifetime data-plane lock. */
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

        /// Requires s_data_plane_mutex. Clears every mask and rule the outgoing owner armed.
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
         * @details Revocation closes capture, so arming belongs to the claim that supersedes it. Doing it here rather
         *          than at each install site makes the pairing an invariant of ownership itself: an XInput-only claim
         *          arms too, and a poller that gains its first wheel binding later does not depend on reaching
         *          install_wndproc to make capture live again. Arming with no subclass installed is inert, because
         *          only the window-procedure detour reaches capture_wheel_notch.
         */
        void publish_owner(std::uint64_t owner) noexcept
        {
            const DataPlaneLockGuard data_lock;
            s_intercept_owner.store(owner, std::memory_order_release);
            s_wheel_capture_state.fetch_or(WHEEL_CAPTURE_ENABLED, std::memory_order_seq_cst);
        }

        /**
         * @brief Requires s_intercept_mutex. Revokes the layer and clears the data the outgoing owner armed.
         * @details Revocation and the clear are one step so no window exists in which the layer is unowned while a mask
         *          the departing owner armed is still live: nothing would then be entitled to revoke that mask, and its
         *          time-to-live is refreshed only by a poll loop that is already gone. Advancing the wheel-capture
         *          epoch invalidates an already-entered window-procedure frame without waiting for it; callers drain
         *          longer-lived XInput bodies after this returns.
         */
        void revoke_owner_and_clear_data() noexcept
        {
            const std::uint64_t wheel_epoch = close_wheel_capture_and_advance_epoch();
            const DataPlaneLockGuard data_lock;
            clear_data_plane_locked(wheel_epoch);
            s_intercept_owner.store(0, std::memory_order_release);
        }

        // XInput interception state

        safetyhook::InlineHook s_xinput_hook;
        safetyhook::InlineHook s_xinput_ex_hook;
        std::atomic<XInputGetStateFn> s_xinput_original{nullptr};
        std::atomic<XInputGetStateFn> s_xinput_ex_original{nullptr};
        std::atomic<bool> s_xinput_installed{false};
        // True after a timeout or unproved restore moved the XInput hooks into process-lifetime storage. Retained
        // trampolines keep forwarding while logical interception is disarmed. A later Input start re-arms only when
        // the retained primary entry is still reachable, never by layering over uncertain storage.
        std::atomic<bool> s_xinput_permanent_detour{false};
        // One-shot diagnostics latches: a failed InlineHook::enable() is otherwise swallowed silently, so surface each
        // failure the first time it happens and stay quiet afterwards (install_xinput is retried every poll cycle, so
        // an un-latched warning would spam the sink). uninstall() clears both so a later hot-reload re-arm can warn
        // again.
        std::atomic<bool> s_xinput_enable_warned{false};
        std::atomic<bool> s_xinput_ex_enable_warned{false};
        // Keepalives taken before the XInput detours go live: one pins this module's detour code, one pins the module
        // whose prologue is patched. Teardown may be unable to drain a game thread out of a detour body, and that is
        // exactly the moment at which acquiring a reference must not be attempted, so both are held in advance. A
        // drained uninstall releases them; a timed-out one retains them with the hooks it makes permanent. Only the
        // poll thread installs, and uninstall runs only after that thread has been joined, so the join supplies the
        // happens-before edge and plain handles need no synchronization.
        HMODULE s_xinput_self_ref{nullptr};
        HMODULE s_xinput_target_ref{nullptr};

        // Reserved storage for hooks a timeout or unproved restore must keep mapped rather than destroy. Constructing
        // an InlineHook move target creates a vector container proxy under MSVC's debug STL, so the cell is initialized
        // before the detour goes live. Retaining teardown then move-assigns the hooks without allocation. Never
        // destroyed; populated at most once when the hooks become permanent.
        struct PermanentXInputHooks
        {
            safetyhook::InlineHook primary;
            safetyhook::InlineHook ex;
            HMODULE self_ref{nullptr};
            HMODULE target_ref{nullptr};
            bool primary_entry_reachable{false};
        };
        alignas(PermanentXInputHooks) unsigned char s_xinput_permanent_cell[sizeof(PermanentXInputHooks)];
        bool s_xinput_permanent_cell_ready{false};
#if defined(DMK_ENABLE_TEST_SEAMS)
        PermanentXInputHooks *s_xinput_permanent_hooks{nullptr};
        std::atomic<std::size_t> s_xinput_backend_toggle_exception_catches{0};
#endif

        /**
         * @brief Returns the reserved cell as a live object.
         * @return Pointer to the object constructed by ensure_permanent_cell().
         * @note Requires s_intercept_mutex and a prior successful ensure_permanent_cell().
         */
        [[nodiscard]] PermanentXInputHooks *permanent_cell() noexcept
        {
            return std::launder(reinterpret_cast<PermanentXInputHooks *>(s_xinput_permanent_cell));
        }

        /**
         * @brief Constructs the reserved cell before an XInput detour is published.
         * @note Requires s_intercept_mutex. MSVC debug-container proxy setup may allocate, so this runs before the
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
#if defined(DMK_ENABLE_TEST_SEAMS)
            s_xinput_permanent_hooks = permanent_cell();
#endif
            return true;
        }

        std::atomic<int> s_bound_user_index{0};
        std::atomic<uint16_t> s_suppress_mask{0};
        std::atomic<uint64_t> s_suppress_deadline_ms{0};

        // Count of game threads currently executing inside an XInput detour body. uninstall() first retires the
        // published trampoline pointers, then drains this to zero before destroying the hook objects, so no thread that
        // already copied a trampoline keeps running through memory the hook owns. SafetyHook still relocates a thread
        // caught mid-prologue during removal, so this is defense-in-depth that shrinks the window rather than the sole
        // guarantee; the poll thread (our other trampoline reader) is already joined by then.
        std::atomic<int> s_xinput_inflight{0};

#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<XInputDetourBodySeam> s_xinput_detour_body_seam{nullptr};
        std::atomic<XInputArmSeam> s_xinput_arm_seam{nullptr};
        // When set, install_xinput resolves XInputGetState from this module instead of searching XINPUT_DLL_NAMES, so a
        // test can drive the install against a synthetic proxy DLL. Only ever set/cleared on the test thread while no
        // install runs, so a plain pointer under s_intercept_mutex needs no atomic.
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

        /// Balances the install-time keepalives once no detour body can still be running.
        void release_xinput_module_refs() noexcept
        {
            DetourModKit::detail::release_module_ref(s_xinput_target_ref);
            s_xinput_target_ref = nullptr;
            DetourModKit::detail::release_module_ref(s_xinput_self_ref);
            s_xinput_self_ref = nullptr;
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
         * @brief Result of arming one raw hook, split by whether a prologue mutation reached the target.
         * @details Uncommitted is the only outcome whose hook nothing can have entered, so it is the only one whose
         *          storage may be destroyed by the caller. CommittedUnreachable wrote the prologue and then lost it,
         *          which leaves the trampoline reachable from any thread already inside the detour even though no new
         *          call can arrive.
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
                                                       std::atomic<bool> &warning_latch,
                                                       std::string_view warning) noexcept
        {
            const PatchWitness before = xinput_patch_witness(hook);
            if (!witness_permits_write(before))
            {
                hook.reconcile_enabled(false);
                original.store(nullptr, std::memory_order_release);
                return XInputArmOutcome::Uncommitted;
            }

            const bool backend_enabled = try_xinput_backend_enable(hook);
            run_xinput_arm_seam();
            const bool mutation_committed = hook.enabled();
            const PatchWitness after = xinput_patch_witness(hook);
            if (!mutation_committed || after == PatchWitness::Original)
            {
                hook.reconcile_enabled(false);
                original.store(nullptr, std::memory_order_release);
                if ((!backend_enabled || after != PatchWitness::Original) &&
                    !warning_latch.exchange(true, std::memory_order_relaxed))
                {
                    (void)log().log_noexcept(LogLevel::Warning, warning);
                }
                // A committed mutation routed the patched prologue through this trampoline before another writer
                // restored the original bytes, so a game thread can be inside the detour holding that pointer. Report
                // it separately: nothing new can arrive, but the storage still may not be freed here.
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
         * @brief Creates and arms one raw hook, containing the allocation and backend exceptions it can contain.
         * @note The handler below covers creation and arming only. Releasing a trampoline goes through SafetyHook's
         *       noexcept move assignment and destructor, so an allocation failure raised there terminates at that
         *       boundary and never reaches this frame. Transferring every hook that owns a trampoline is what keeps
         *       that release off this path entirely.
         */
        [[nodiscard]] XInputArmOutcome
        create_xinput_hook(const std::shared_ptr<safetyhook::Allocator> &allocator, void *target, void *detour,
                           safetyhook::InlineHook &destination, std::atomic<XInputGetStateFn> &original,
                           std::atomic<bool> &warning_latch, std::string_view warning) noexcept
        {
            try
            {
                auto created =
                    safetyhook::InlineHook::create(allocator, target, detour, safetyhook::InlineHook::StartDisabled);
                if (!created)
                {
                    return XInputArmOutcome::Uncommitted;
                }

                safetyhook::InlineHook &candidate = created.value();
                original.store(candidate.original<XInputGetStateFn>(), std::memory_order_release);
                const XInputArmOutcome outcome = arm_xinput_hook(candidate, original, warning_latch, warning);
                if (outcome != XInputArmOutcome::Uncommitted)
                {
                    // Both remaining outcomes own a trampoline the patched prologue already published. Transfer the
                    // storage to the caller's cell so this scope never runs the destructor that would return that
                    // range to the allocator freelist while a detour body still holds a pointer into it. The move
                    // assigns onto an empty destination, so it frees nothing and takes no allocation.
                    destination = std::move(candidate);
                }
                return outcome;
            }
            catch (...)
            {
                original.store(nullptr, std::memory_order_release);
                return XInputArmOutcome::Uncommitted;
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
                // Carry the inactive-storage exemption through to the verdict, not just to the pre-write gate. A
                // disabled backend has no target entry into its trampoline and its disable() writes nothing, so
                // whatever now occupies its former target belongs to that address's current owner. Reading those
                // bytes here would report Foreign for a window this hook does not patch, and that verdict would
                // force the healthy member of the pair into permanent retention over an unrelated writer.
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
         * @brief Releases a hook whose target witnessed Original and whose detour bodies have drained.
         * @note This release cannot be wrapped in a handler that would run. SafetyHook's move assignment is noexcept
         *       and reaches the allocator through it, so a throw raised while returning the trampoline range
         *       terminates at that noexcept boundary instead of unwinding to any caller. The Original witness and the
         *       completed drain are what make the release itself correct; nothing here contains an allocation
         *       failure inside it.
         */
        void reset_inactive_xinput_hook(safetyhook::InlineHook &hook) noexcept
        {
            hook = {};
        }

        enum class XInputRetentionReason : std::uint8_t
        {
            InflightTimeout,
            UnrestoredPatch,
            UnprovedInstall
        };

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
         * @brief Transfers the raw hook pair and keepalives into never-destroyed storage.
         * @note Requires s_intercept_mutex, a constructed permanent cell, and retired trampoline publications.
         */
        void retain_xinput_hooks(PatchWitness primary_witness, PatchWitness ex_witness,
                                 XInputRetentionReason reason) noexcept
        {
            PermanentXInputHooks *const permanent = permanent_cell();
            const bool primary_valid = static_cast<bool>(s_xinput_hook);
            const bool ex_valid = static_cast<bool>(s_xinput_ex_hook);
            const bool primary_forwarding_required = primary_valid && s_xinput_hook.enabled();
            const bool ex_forwarding_required = ex_valid && s_xinput_ex_hook.enabled();
            s_xinput_hook.reconcile_enabled(primary_forwarding_required && primary_witness != PatchWitness::Original);
            s_xinput_ex_hook.reconcile_enabled(ex_forwarding_required && ex_witness != PatchWitness::Original);

            permanent->primary = std::move(s_xinput_hook);
            permanent->ex = std::move(s_xinput_ex_hook);
            permanent->self_ref = std::exchange(s_xinput_self_ref, nullptr);
            permanent->target_ref = std::exchange(s_xinput_target_ref, nullptr);
            permanent->primary_entry_reachable =
                primary_forwarding_required && primary_witness != PatchWitness::Original;

            // Republish the trampoline of every hook the backend still reports enabled, whatever its witness says:
            // Original entry bytes do not rule out a frame that entered before retirement and has not yet reached
            // its original-pointer load. A hook whose restore already committed publishes null, so a frame still
            // inside that detour returns a closed result instead of a stale chain.
            s_xinput_original.store(primary_forwarding_required ? permanent->primary.original<XInputGetStateFn>()
                                                                : nullptr,
                                    std::memory_order_seq_cst);
            s_xinput_ex_original.store(ex_forwarding_required ? permanent->ex.original<XInputGetStateFn>() : nullptr,
                                       std::memory_order_seq_cst);
            s_xinput_permanent_detour.store(true, std::memory_order_release);
            s_xinput_installed.store(false, std::memory_order_release);
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);
            (void)log().log_noexcept(LogLevel::Warning, xinput_retention_message(reason));
            s_xinput_enable_warned.store(false, std::memory_order_relaxed);
            s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
        }

        /**
         * @brief RAII marker for a game thread executing an XInput detour body.
         * @details Increment-on-entry / decrement-on-exit so uninstall() can observe when no detour is in flight. This
         *          counter and the published trampoline pointer form a Dekker-style mutual-exclusion pair: the detour
         *          increments the counter and then loads the trampoline, while uninstall() retires the trampoline
         *          (stores null) and then drains the counter. That is a store-then-load-of-a-different-location pattern
         *          on both sides, and the one reordering acquire/release does NOT forbid is exactly StoreLoad -- so
         *          with acquire/release the CPU may let the detour observe the still-non-null trampoline before its
         *          increment is visible to the drain, letting uninstall() see a zero count and free a trampoline the
         *          detour is about to run through (a use-after-free the SafetyHook mid-prologue relocation does not
         *          cover). Only a total order over the four operations forbids that interleaving, so the increment
         *          here, the detour's trampoline load, uninstall()'s retire store, and its drain load are all seq_cst.
         *          On x86-64 (the sole target) this costs nothing beyond the existing atomics: the increment is
         *          already a locked RMW (a full barrier) and a seq_cst load is a plain MOV. The decrement stays
         *          release: it is not part of the StoreLoad pair, it only has to publish the detour body's completion
         *          to the seq_cst drain load. Trivial and noexcept so it never perturbs the hot per-frame detour path.
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

        // Consume rule list (detour-side chord evaluation)
        //
        // A binding rebuild publishes one rule per detour-evaluable consume chord;
        // the XInput detour reads the list against the exact button snapshot the game is about to read. Each rule is
        // packed into a single atomic word so a reader never sees a torn rule, and the array plus its count sit behind
        // a seqlock (s_consume_rules_seq: even = stable, odd = mid-update) so the detour gets an all-or-nothing
        // snapshot of the whole list without locking. Single writer: whichever thread mutates the bindings, serialized
        // by
        // InputPoller::m_bindings_rw_mutex held in write mode while recompute_modifier_caches_locked / clear_bindings
        // publish. This is not the poll thread, which only takes a shared lock and never writes or reads this list.
        // Many readers: the game's XInput caller threads via the detour.
        std::array<std::atomic<uint64_t>, MAX_GAMEPAD_CONSUME_RULES> s_consume_rules{};
        std::atomic<uint32_t> s_consume_rule_count{0};
        std::atomic<uint32_t> s_consume_rules_seq{0};

        // Gate for detour-side rule masking, driven every poll cycle. The published rule list and its time-to-live
        // survive focus changes, so without this gate apply_suppress would keep masking the foreground game's input
        // while the mod is unfocused. The poll loop sets it true only while focused and connected, mirroring how the
        // reactive mask is cleared and how the per-direction wheel-consume mask is gated.
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

        /// Inverse of pack_consume_rule.
        constexpr GamepadConsumeRule unpack_consume_rule(uint64_t packed) noexcept
        {
            return GamepadConsumeRule{static_cast<uint16_t>(packed & 0xFFFFu),
                                      static_cast<uint16_t>((packed >> 16) & 0xFFFFu),
                                      static_cast<uint16_t>((packed >> 32) & 0xFFFFu)};
        }

        // Mouse-wheel capture state

        std::array<std::atomic<std::uint64_t>, 4> s_wheel_count{wheel_count_slot(1, 0), wheel_count_slot(1, 0),
                                                                wheel_count_slot(1, 0), wheel_count_slot(1, 0)};
        // Per-direction wheel-swallow mask (WheelDirection bits), refreshed every poll cycle. Paired with a TTL so a
        // stalled poll thread stops swallowing and the game regains its wheel. A chord such as "Ctrl+WheelUp" must not
        // eat a bare WheelDown or an unmodified WheelUp.
        std::atomic<uint8_t> s_wheel_consume_mask{0};
        std::atomic<uint64_t> s_wheel_consume_deadline_ms{0};

        void clear_data_plane_locked(std::uint64_t wheel_epoch) noexcept
        {
            // Single-atomic disarms first, so the detours stop masking before the multi-step rule update begins.
            s_suppress_mask.store(0, std::memory_order_release);
            s_rule_suppress_enabled.store(false, std::memory_order_relaxed);
            s_wheel_consume_mask.store(0, std::memory_order_release);
            for (auto &count : s_wheel_count)
            {
                count.store(wheel_count_slot(wheel_epoch, 0), std::memory_order_relaxed);
            }

            // Emptying the rule list here is safe only because every writer now holds this lock: the seqlock has one
            // writer at a time, so this bracket cannot interleave with a concurrent binding mutation's publication and
            // tear the list. The gate above is already false, so a detour reading mid-bracket skips rule masking either
            // way; the clear exists so a later owner cannot inherit the previous owner's chords by publishing nothing.
            const uint32_t seq = s_consume_rules_seq.load(std::memory_order_relaxed);
            s_consume_rules_seq.store(seq + 1, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            s_consume_rule_count.store(0, std::memory_order_relaxed);
            s_consume_rules_seq.store(seq + 2, std::memory_order_release);
        }

        std::atomic<HWND> s_hwnd{nullptr};
        std::atomic<LONG_PTR> s_prev_wndproc{0};
        std::atomic<bool> s_wndproc_installed{false};
        // Set once install_wndproc has taken the never-released module reference that keeps wndproc_detour's code
        // mapped; the acquire precedes the subclass swap so the detour is never reachable without its keepalive.
        // WM_NCDESTROY re-arms installation for a re-created game window, so without this flag every window generation
        // would take -- and leak -- another reference. Only the poll thread touches it; relaxed ordering suffices.
        std::atomic<bool> s_wndproc_ref_taken{false};
#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<WndProcUninstallExchangeSeam> s_wndproc_uninstall_exchange_seam{nullptr};
#endif

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
            return module;
        }

        /**
         * @brief Reports whether @p address lies in the module install_xinput() already pinned.
         * @details A proxy or shim xinput DLL may forward an ordinal, and GetProcAddress resolves a forwarder into the
         *          forwarded-to module. Patching there would leave a live prologue in a third module that no keepalive
         *          covers, and a retaining teardown cannot repair that: acquiring a reference is exactly what it may
         *          not do. The probe reference is released immediately and can never be the terminal one, because on a
         *          match s_xinput_target_ref still holds the module and on a mismatch the module's own load reference
         *          does, the address having just been resolved out of it.
         */
        [[nodiscard]] bool lies_in_pinned_xinput_module(const void *address) noexcept
        {
            const HMODULE owner = acquire_module_ref_containing_address(address);
            DetourModKit::detail::release_module_ref(owner);
            return owner != nullptr && owner == s_xinput_target_ref;
        }

        /**
         * @brief Saturating single-notch increment for a per-direction wheel counter, tagged with @p epoch.
         * @details Uses a compare/exchange loop so every writer sees the current slot value before incrementing, and
         *          the tagged count never exceeds MAX_WHEEL_NOTCHES even if a foreign subclass or a nested message
         *          dispatch re-enters the procedure. A concurrent drain resets the same epoch to zero; a revocation
         *          retags the slot, which makes a writer holding the retired epoch fail instead of publishing into the
         *          successor's backlog. Saturation bounds the idle-accretion case: after the last wheel binding is
         *          removed the poll loop stops draining, yet the subclass stays installed until shutdown.
         * @return true when the notch was recorded or the slot was already saturated; false when @p epoch is retired.
         */
        [[nodiscard]] bool bump_wheel_notch(std::atomic<std::uint64_t> &slot, std::uint64_t epoch) noexcept
        {
            std::uint64_t current = slot.load(std::memory_order_relaxed);
            while (wheel_slot_epoch(current) == epoch)
            {
                const std::uint64_t count = current & WHEEL_COUNT_MASK;
                if (count >= MAX_WHEEL_NOTCHES)
                {
                    return true;
                }
                if (slot.compare_exchange_weak(current, wheel_count_slot(epoch, count + 1), std::memory_order_relaxed,
                                               std::memory_order_relaxed))
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Records one wheel notch only for the enabled capture epoch observed at window-procedure entry.
         * @details Revocation advances the epoch and retags every slot, so a frame that entered before it fails its
         *          atomic update rather than publishing into the successor's backlog. Failing the write is what lets
         *          teardown proceed without waiting on, or suspending, a thread parked inside the procedure.
         * @param direction Zero-based wheel direction index known to be in range.
         * @param capture_state Capture state atomically observed when the window-procedure frame began.
         * @return true when the notch was admitted and recorded; false once capture admission has closed.
         */
        [[nodiscard]] bool capture_wheel_notch(std::size_t direction, std::uint64_t capture_state) noexcept
        {
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
            return bump_wheel_notch(s_wheel_count[direction], wheel_capture_epoch(capture_state));
        }

        /**
         * @brief Reports whether the detour should swallow a wheel message of the given direction this instant.
         * @details Reads the poll-published per-direction mask and its time-to-live. The acquire load of the mask also
         *          orders the relaxed deadline read: publish_wheel_consume writes the deadline before the release store
         *          on the mask, so observing a set direction bit guarantees observing its refreshed deadline. A lapsed
         *          deadline (stalled poll thread) forwards the message so the game is never latched out of its wheel.
         * @param direction_bit A single WheelDirection bit for the message's direction.
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
         * @brief Clears the suppressed button bits from a game-bound XINPUT_STATE.
         * @details Only the bound controller index is masked. dwPacketNumber and the success return are left untouched
         *          so the game still sees a connected, advancing controller (faking a disconnect would trigger
         *          pause/reconnect UI). The cleared bits are the union of two sources:
         *          the reactive mask the poll thread publishes (which carries the trailing-edge consume-until-release
         *          latch) and the consume rules evaluated here against the exact buttons the game is about to read
         *          (which close the leading-edge window the poll-published mask trails by up to one cycle). A
         *          time-to-live guard drops all masking if the poll thread stopped refreshing it.
         */
        void apply_suppress(XINPUT_STATE *state, DWORD user_index) noexcept
        {
            if (state == nullptr)
            {
                return;
            }
            if (static_cast<int>(user_index) != s_bound_user_index.load(std::memory_order_relaxed))
            {
                return;
            }
            // Acquire the reactive mask first. This load also orders the relaxed deadline read below:
            // publish_gamepad_suppress writes the deadline before the release store on s_suppress_mask, so the acquire
            // here establishes the happens-before even when the mask reads as 0.
            const uint16_t reactive = s_suppress_mask.load(std::memory_order_acquire);

            // raw is the true, unmasked state: this detour runs after the trampoline call. Evaluating the published
            // chord rules against it masks a chord whose modifier and trigger were pressed inside one poll interval on
            // the very frame the game reads it, rather than a cycle later. The focus gate suppresses this evaluation
            // when the host window is unfocused or the controller is gone: the rule list and its deadline both survive
            // those transitions, so the detour must not keep masking the foreground game's input (the reactive mask is
            // already cleared by the poll loop on focus loss).
            const uint16_t raw = state->Gamepad.wButtons;
            const uint16_t rule_mask =
                s_rule_suppress_enabled.load(std::memory_order_relaxed) ? evaluate_published_consume_rules(raw) : 0;
            const uint16_t mask = static_cast<uint16_t>(reactive | rule_mask);
            if (mask == 0)
            {
                return;
            }
            // The reactive mask and the rule list are both refreshed only while the poll thread is alive: rules exist
            // only when consume gamepad bindings do, and that is exactly when publish_gamepad_suppress refreshes this
            // deadline every cycle. A stalled poll thread therefore lets the deadline lapse and all masking stops, so
            // the game regains its input rather than latching off.
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
            // seq_cst: this load and the InflightGuard increment above form the detour side of the Dekker drain pair
            // (see InflightGuard). It must join the same total order as uninstall()'s retire store so a zeroed count
            // over there implies a null trampoline over here.
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
            // seq_cst for the same Dekker-pair reason as xinput_get_state_detour above.
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
                // GET_WHEEL_DELTA_WPARAM is a signed short: positive scrolls the wheel forward (up/away from the user),
                // negative backward (down). Each message is exactly one direction, so latch that direction's notch and
                // swallow the message only when a consume binding currently owns that same direction -- a
                // "Ctrl+WheelUp" binding must not eat a bare WheelDown or an unmodified WheelUp.
                const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
                if (delta > 0)
                {
                    if (capture_wheel_notch(0, capture_state) &&
                        wheel_direction_consumed(wheel_direction_bit(WheelDirection::Up)))
                    {
                        return 0;
                    }
                }
                else if (delta < 0)
                {
                    if (capture_wheel_notch(1, capture_state) &&
                        wheel_direction_consumed(wheel_direction_bit(WheelDirection::Down)))
                    {
                        return 0;
                    }
                }
                break;
            }
            case WM_MOUSEHWHEEL:
            {
                // Horizontal wheel sign is opposite the vertical intuition: positive tilts right, negative left. Same
                // per-direction latch-and-swallow as the vertical wheel.
                const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
                if (delta > 0)
                {
                    if (capture_wheel_notch(3, capture_state) &&
                        wheel_direction_consumed(wheel_direction_bit(WheelDirection::Right)))
                    {
                        return 0;
                    }
                }
                else if (delta < 0)
                {
                    if (capture_wheel_notch(2, capture_state) &&
                        wheel_direction_consumed(wheel_direction_bit(WheelDirection::Left)))
                    {
                        return 0;
                    }
                }
                break;
            }
            case WM_NCDESTROY:
                // The window is being destroyed and its window-long storage is about to be invalidated. Drop all
                // tracked subclass state and mark the subclass uninstalled so a later poll cycle re-subclasses the next
                // game window: an engine that recreates its window on a fullscreen/display-mode switch would otherwise
                // leave the new window unhooked, because install_wndproc short-circuits while s_wndproc_installed stays
                // true. The forward at the bottom of this function uses the local prev copy captured above, so clearing
                // s_prev_wndproc here does not affect this invocation's own forward. Store the installed flag last so a
                // poll thread observing it false (acquire) also sees the cleared handle and predecessor.
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

        BOOL CALLBACK find_window_proc(HWND hwnd, LPARAM lparam) noexcept
        {
            auto *out = reinterpret_cast<HWND *>(lparam);
            DWORD window_pid = 0;
            GetWindowThreadProcessId(hwnd, &window_pid);
            // Accept the first visible, top-level (owner-less) window belonging to this process. The owner check
            // filters tool/splash windows; visibility filters message-only and hidden helper windows.
            if (window_pid != GetCurrentProcessId() || !IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr)
            {
                return TRUE; // keep enumerating
            }
            *out = hwnd;
            return FALSE; // stop
        }

        HWND find_game_window() noexcept
        {
            HWND result = nullptr;
            EnumWindows(&find_window_proc, reinterpret_cast<LPARAM>(&result));
            if (result != nullptr)
            {
                return result;
            }
            // Fallback: the foreground window if it belongs to this process.
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
                // The window was already destroyed (WM_NCDESTROY cleared the handle, or it is otherwise gone); the
                // subclass went with it.
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
                    // WM_NCDESTROY clears the handle and the predecessor before it clears the installed flag, so a
                    // teardown that already read a live handle can reach this load after the predecessor is gone.
                    // Zero is not a procedure: install_wndproc refuses to adopt a zero read for the same reason, and
                    // exchanging it here does not store zero either -- the window manager substitutes its own default
                    // procedure, which detaches the window from the real chain for the rest of its life and drops the
                    // messages the game's own procedure still expects. Converge on the state the destroy path is
                    // establishing and leave the chain as it stands; the detour still forwards, and its code pages are
                    // held by the permanent install-time reference.
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
                    // A foreign subclass landed after the observation. The exchange above temporarily displaced it;
                    // put the actual returned procedure back on top. Its saved predecessor is DMK, so this restores
                    // foreign -> DMK -> saved and leaves DMK logically installed underneath it.
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
                        // A second writer won the compensation gap. Restore that latest writer rather than clobbering
                        // it; ownership is now uncertain, so retain the conservative installed state.
                        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, repair_displaced);
                    }
                    return;
                }

                // The exchange actually displaced DMK, so no FUTURE dispatch enters the detour. It does not
                // synchronize with a frame already inside wndproc_detour, which is why the install-time module
                // reference is permanent.
                // Deliberately leave s_prev_wndproc pointing at the real procedure. An in-flight wndproc_detour frame
                // on the window thread loads it at the top of the detour and forwards to it; zeroing it here would race
                // that frame and make it route the message to DefWindowProcW instead of the game's own procedure,
                // silently dropping e.g. WM_CLOSE / WM_ACTIVATE at every interception teardown. The detour is no longer
                // in the chain after the restore above, so no NEW frame enters, and a later install_wndproc overwrites
                // this value before re-subclassing -- so leaving it set is both safe and correct.
                s_hwnd.store(nullptr, std::memory_order_release);
                s_wndproc_installed.store(false, std::memory_order_release);
                return;
            }

            // Another subclass layered on top of ours. Restoring here would clobber that mod's procedure, so leave our
            // detour installed: it only forwards to s_prev_wndproc (kept intact) and is inert once wheel bindings are
            // gone. Its code stays mapped regardless -- install_wndproc took a never-released module reference when
            // the subclass first went live. Keep s_wndproc_installed true so a later install does not stack a
            // duplicate detour onto the chain.
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
            // pending is in [0, MAX_WHEEL_PENDING] by induction, so room is non-negative. Compare against room before
            // adding so a large burst saturates rather than overflowing the int sum.
            const int room = MAX_WHEEL_PENDING - state.pending[dir];
            state.pending[dir] = (add >= room) ? MAX_WHEEL_PENDING : state.pending[dir] + add;
        }
    }

    uint16_t step_gamepad_suppress(GamepadSuppressState &state, uint16_t owned_now, uint16_t true_buttons,
                                   uint64_t now_ms, uint64_t grace_ms) noexcept
    {
        // Sentinel deadline meaning "actively held, not yet releasing".
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
                // Actively held: a chord claims it now, or the trigger button is still physically down after the
                // modifier was released. Keep suppressing and cancel any in-progress release grace.
                state.armed = static_cast<uint16_t>(state.armed | bit_mask);
                state.deadline_ms[static_cast<size_t>(bit)] = held_sentinel;
                mask = static_cast<uint16_t>(mask | bit_mask);
            }
            else if ((state.armed & bit_mask) != 0)
            {
                // Armed but the physical button is up: run the release grace so a trailing bare-trigger frame cannot
                // leak to the game.
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
            // Every modifier bit held and no forbidden bit held: the exact decision the poll loop makes (chord
            // modifiers satisfied and the strict-match check passes), evaluated against the snapshot the game is about
            // to read. A forbidden bit is a known modifier that belongs to a different chord, so holding one means this
            // chord is not the active gesture.
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
            // Refuse before opening the seqlock bracket, not by rolling one back: a caller that lost the layer while it
            // was entering must leave the sequence untouched and even, so a detour reading concurrently never has to
            // skip a frame on account of a write that was never entitled to happen.
            return {};
        }

        // Keep the rules that fit and drop the rest. Evaluation ORs the trigger mask of every matching rule, so a
        // retained rule protects its own chord whether or not a later one was dropped; emptying the list instead would
        // revoke the leading-edge protection of every chord to punish the one that did not fit.
        const std::size_t published = count < MAX_GAMEPAD_CONSUME_RULES ? count : MAX_GAMEPAD_CONSUME_RULES;
        // Seqlock write (single writer). The odd sequence brackets the update so a concurrent detour read sees the
        // whole new list or skips the frame. The release fence after the odd store keeps the rule stores from being
        // observed before the bracket opens; the release store of the even sequence publishes the finished list to the
        // detour's acquire load.
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
        // Seqlock read, single attempt (no spin): an odd sequence means the writer is mid-update, and a change across
        // the copy means the snapshot tore. In either case skip rule masking for this frame (the reactive mask still
        // applies); the next game poll, microseconds later, gets the settled list. Rules change only on a binding
        // rebuild, so a torn read is rare and never coincides with steady gameplay input.
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
        // Order the rule loads above before the sequence re-read below, so a writer that updated mid-copy is always
        // detected.
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
        const InterceptLockGuard lock{s_intercept_mutex};

        if (!owner_available(owner))
        {
            return false;
        }

        if (s_xinput_permanent_detour.load(std::memory_order_acquire))
        {
            const PermanentXInputHooks *const permanent = permanent_cell();
            const bool ready =
                permanent->primary_entry_reachable && s_xinput_original.load(std::memory_order_seq_cst) != nullptr;
            if (ready)
            {
                s_bound_user_index.store(user_index, std::memory_order_relaxed);
                s_xinput_installed.store(true, std::memory_order_release);
                publish_owner(owner);
            }
            return ready;
        }
        if (s_xinput_installed.load(std::memory_order_acquire))
        {
            s_bound_user_index.store(user_index, std::memory_order_relaxed);
            publish_owner(owner);
            return true;
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
            return false; // XInput not loaded yet; the poll loop retries.
        }

        auto *get_state = reinterpret_cast<void *>(GetProcAddress(module, "XInputGetState"));
        if (get_state == nullptr)
        {
            return false;
        }

        // Take both keepalives before anything can patch the prologue. Once a detour is live a game thread can be
        // inside its body, and the teardown that must then retain the hooks has no working allocator or loader call
        // left to make. Fail closed and let the poll loop retry if either reference cannot be taken.
        s_xinput_self_ref = DetourModKit::detail::acquire_module_ref();
        if (s_xinput_self_ref == nullptr)
        {
            return false;
        }
        s_xinput_target_ref = acquire_module_ref_containing_address(get_state);
        if (s_xinput_target_ref == nullptr)
        {
            release_xinput_module_refs();
            return false;
        }

        // Construct the reserved permanent cell while allocation is permitted. A timed-out teardown can then transfer
        // the live hooks without move-constructing InlineHook's debug-container proxies.
        if (!ensure_permanent_cell())
        {
            release_xinput_module_refs();
            return false;
        }

        std::shared_ptr<safetyhook::Allocator> allocator;
        try
        {
            allocator = safetyhook::Allocator::global();
        }
        catch (...)
        {
            release_xinput_module_refs();
            return false;
        }

        // Create disabled, publish the trampoline, then arm. create_xinput_hook contains allocation and backend
        // exceptions; only a committed mutation plus a non-Original post-witness remains conservatively reachable.
        const XInputArmOutcome primary_outcome =
            create_xinput_hook(allocator, get_state, reinterpret_cast<void *>(&xinput_get_state_detour), s_xinput_hook,
                               s_xinput_original, s_xinput_enable_warned,
                               "InputIntercept: XInputGetState hook transaction did not complete cleanly; state was "
                               "reconciled from the target bytes.");
        if (primary_outcome == XInputArmOutcome::CommittedUnreachable)
        {
            // The patch went live and another writer restored the prologue before the witness read, so a game thread
            // may hold this trampoline. Nothing here can drain it: the poll thread owns this call and holds the
            // intercept mutex. Hand the storage and both keepalives to permanent ownership and fail closed; the
            // retained hook is disarmed, so no new call reaches it and no later install layers over it.
            retain_xinput_hooks(PatchWitness::Original, PatchWitness::Original, XInputRetentionReason::UnprovedInstall);
            return false;
        }
        if (primary_outcome != XInputArmOutcome::Armed)
        {
            release_xinput_module_refs();
            return false;
        }

        // XInputGetStateEx (ordinal 100) carries the Guide button; a game that polls it would otherwise bypass the
        // mask. Hook it too when present; its absence is not an error. Skip it when a proxy/shim xinput DLL aliases the
        // ordinal to the same code address as XInputGetState: that address is already covered, and a second inline hook
        // on one prologue would capture the first hook's jmp as its "original" and corrupt the trampoline chain. Skip
        // it as well when the ordinal forwards out of the pinned module, since the keepalive taken above would not
        // cover the patched prologue and a retaining teardown could not take a second one.
        auto *get_state_ex =
            reinterpret_cast<void *>(GetProcAddress(module, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        // An Ex outcome never fails the install: the primary is already armed and carries the mask on its own. A
        // committed-but-unreachable Ex keeps its storage in s_xinput_ex_hook rather than being destroyed here, and the
        // drained teardown below is what eventually frees it.
        if (get_state_ex != nullptr && get_state_ex != get_state && lies_in_pinned_xinput_module(get_state_ex))
        {
            (void)create_xinput_hook(
                allocator, get_state_ex, reinterpret_cast<void *>(&xinput_get_state_ex_detour), s_xinput_ex_hook,
                s_xinput_ex_original, s_xinput_ex_enable_warned,
                "InputIntercept: XInputGetStateEx hook transaction did not complete cleanly; the primary hook remains "
                "available and Ex state was reconciled from the target bytes.");
        }

        s_bound_user_index.store(user_index, std::memory_order_relaxed);
        s_xinput_installed.store(true, std::memory_order_release);
        publish_owner(owner);
        return true;
    }

    bool xinput_installed() noexcept
    {
        return s_xinput_installed.load(std::memory_order_acquire);
    }

    XInputGetStateFn xinput_trampoline() noexcept
    {
        if (!s_xinput_installed.load(std::memory_order_acquire))
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
        // Write the deadline before the mask (release on the mask). A detour that observes the new mask with acquire is
        // then guaranteed to also observe the refreshed deadline, so a fresh mask is never paired with a stale
        // (already-expired) deadline.
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
        if (s_wndproc_installed.load(std::memory_order_acquire))
        {
            publish_owner(owner);
            return true;
        }
        const HWND hwnd = find_game_window();
        if (hwnd == nullptr)
        {
            return false; // window not available yet; the poll loop retries.
        }

        // Take the permanent keepalive BEFORE the detour becomes reachable. Once SetWindowLongPtrW publishes
        // wndproc_detour, no later restore can sever that reachability: a restore only redirects future dispatches, so
        // a frame already inside the detour (a modal size/move loop holds one for as long as the user drags the title
        // bar) survives it and eventually returns through this module's code. The module must therefore stay mapped
        // for the rest of the process from the moment the subclass first goes live -- and if the reference cannot be
        // taken, fail closed and let the poll loop retry rather than publish a detour whose code pages nothing keeps
        // mapped. One reference covers every window generation (WM_NCDESTROY re-arms installation for a re-created
        // window); the once-flag is set as soon as the acquire succeeds, so a failed swap below cannot double-acquire
        // on its retry. This runs on the poll thread, off the loader lock, while the module is fully live.
        if (!s_wndproc_ref_taken.load(std::memory_order_relaxed))
        {
            if (acquire_module_ref() == nullptr)
            {
                return false;
            }
            s_wndproc_ref_taken.store(true, std::memory_order_relaxed);
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);
        }

        // Publish the predecessor procedure and target window before the detour goes live. SetWindowLongPtrW makes
        // wndproc_detour reachable from the window's own message thread the instant it returns; if the predecessor were
        // stored only afterwards, a message dispatched in that gap would read a zero s_prev_wndproc and route to
        // DefWindowProcW instead of the game's real procedure. A top-level window always has a non-null WNDPROC, so a
        // zero read here means the slot is not readable yet. install_wndproc runs only on the single poll thread, so
        // DMK never races its own install here; a foreign subclasser that installs in the gap between this read and the
        // swap is reconciled from SetWindowLongPtrW's returned predecessor below.
        const LONG_PTR current = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
        if (current == 0)
        {
            return false;
        }
        s_prev_wndproc.store(current, std::memory_order_release);
        s_hwnd.store(hwnd, std::memory_order_release);

        // SetWindowLongPtr returns the previous value, or 0 on failure. Disambiguate a genuine zero predecessor from an
        // error via GetLastError.
        SetLastError(0);
        const LONG_PTR prev = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&wndproc_detour));
        if (prev == 0 && GetLastError() != 0)
        {
            // Swap failed: roll back the published predecessor so no stale handle survives a failed install.
            s_hwnd.store(nullptr, std::memory_order_release);
            s_prev_wndproc.store(0, std::memory_order_release);
            return false;
        }

        // SetWindowLongPtrW returns the WNDPROC it actually displaced. If a foreign subclasser installed itself in the
        // gap between our GetWindowLongPtrW read and this swap, that returned procedure -- not the predecessor we read
        // and published -- is the real next link in the chain. Adopt and republish it so wndproc_detour forwards to the
        // procedure that was on top at swap time, keeping the subclass chain intact rather than silently dropping the
        // foreign subclasser. The release store pairs with the detour's acquire load of s_prev_wndproc. A genuine zero
        // predecessor was already rejected as a failure above, so a non-zero mismatch is the only adoption case.
        if (prev != 0 && prev != current)
        {
            s_prev_wndproc.store(prev, std::memory_order_release);
        }

        // Drain any notches the wndproc detour latched while no binding owned the wheel. uninstall() drops the consume
        // flag but leaves the detour live (it may stay layered under a foreign subclass), so it keeps incrementing
        // s_wheel_count between an unbind and this re-arm. Without this reset the first take_wheel_counts() after a
        // re-bind would replay that stale backlog as a burst of phantom notches. This is a fresh-install transition
        // (the idempotent already-installed path returned above), so resetting here cannot discard counts a live
        // binding is about to consume.
        const std::uint64_t wheel_epoch = wheel_capture_epoch(s_wheel_capture_state.load(std::memory_order_seq_cst));
        for (auto &count : s_wheel_count)
        {
            count.store(wheel_count_slot(wheel_epoch, 0), std::memory_order_relaxed);
        }

        s_wndproc_installed.store(true, std::memory_order_release);
        publish_owner(owner);
        return true;
    }

    bool wndproc_installed() noexcept
    {
        return s_wndproc_installed.load(std::memory_order_acquire);
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
            // Saturate to the same ceiling the detour's bump_wheel_notch enforces, so a seeded backlog can never place
            // the counters in a state the real write site could not produce.
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
        // Refresh the deadline before the release store on the mask (only when arming a non-zero mask), so a detour
        // observing a set direction bit with acquire is guaranteed to also observe the fresh deadline. A zero mask
        // needs no deadline: the detour checks the direction bit first and forwards immediately when it is clear, so
        // skipping the clock read on the common all-forward path costs nothing and keeps the disarm cheap.
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

    bool xinput_permanent_primary_retained() noexcept
    {
        return s_xinput_permanent_hooks != nullptr && static_cast<bool>(s_xinput_permanent_hooks->primary);
    }

    int xinput_module_refs_held() noexcept
    {
        const int install_refs = (s_xinput_self_ref != nullptr ? 1 : 0) + (s_xinput_target_ref != nullptr ? 1 : 0);
        const int permanent_refs = s_xinput_permanent_hooks != nullptr
                                       ? (s_xinput_permanent_hooks->self_ref != nullptr ? 1 : 0) +
                                             (s_xinput_permanent_hooks->target_ref != nullptr ? 1 : 0)
                                       : 0;
        return install_refs + permanent_refs;
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

    bool capture_wheel_notch_for_test(std::size_t direction) noexcept
    {
        const std::uint64_t capture_state = s_wheel_capture_state.load(std::memory_order_seq_cst);
        return direction < s_wheel_count.size() && capture_wheel_notch(direction, capture_state);
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
        const InterceptLockGuard lock{s_intercept_mutex};
        if (owner == 0 || s_intercept_owner.load(std::memory_order_relaxed) != owner)
        {
            return;
        }

        // Revoke the layer and clear every mask and rule this owner armed, in one data-plane step, before any of the
        // teardown below. Two orderings depend on it. A binding mutation racing this teardown must be refused rather
        // than allowed to re-arm a mask over a layer that is being dismantled, which the owner check inside the
        // data-plane lock now does. And the clear must not be split from the revocation: an unowned layer with a live
        // mask has nothing entitled to revoke it, and its time-to-live is refreshed only by the poll loop this teardown
        // has already joined. The lock is dropped here so the bounded drain below never runs under it.
        revoke_owner_and_clear_data();

        uninstall_wndproc();

        if (s_xinput_permanent_detour.load(std::memory_order_acquire))
        {
            // A prior timeout or unproved restore made the hook storage permanent. There is no live static handle left
            // to restore. Treat this call as a logical disarm only; any retained reachable entry keeps forwarding.
            s_xinput_installed.store(false, std::memory_order_release);
            s_xinput_enable_warned.store(false, std::memory_order_relaxed);
            s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
            return;
        }

        // Retire the published trampoline pointers before draining. A game thread that already copied one keeps the
        // in-flight counter non-zero until it leaves; a late entrant after this point sees nullptr and returns a closed
        // result instead of taking a pointer into the hook object that teardown is about to destroy. These retire
        // stores are seq_cst so they and the drain load below join the same total order as the detour's increment and
        // trampoline load: without that, StoreLoad reordering could let this thread read a zero count while a detour
        // still holds a non-null trampoline (see InflightGuard).
        s_xinput_ex_original.store(nullptr, std::memory_order_seq_cst);
        s_xinput_original.store(nullptr, std::memory_order_seq_cst);

        // Quiesce XInput detours that might already have copied a trampoline before destroying the hook objects. The
        // poll thread is already joined, so the only remaining callers are the game's own XInput threads. SafetyHook
        // additionally relocates a thread caught mid-prologue during removal, so this drain shrinks the window rather
        // than being the sole guarantee. Use a short wall-clock bound instead of a yield count: a hot game thread can
        // keep entering the detour after the trampoline pointers are retired, and teardown must still make progress.
        constexpr uint64_t xinput_quiesce_timeout_ms = 10;
        const uint64_t quiesce_deadline_ms = GetTickCount64() + xinput_quiesce_timeout_ms;
        while (s_xinput_inflight.load(std::memory_order_seq_cst) != 0 && GetTickCount64() < quiesce_deadline_ms)
        {
            std::this_thread::yield();
        }

        const int still_inflight = s_xinput_inflight.load(std::memory_order_seq_cst);
        if (still_inflight != 0)
        {
            retain_xinput_hooks(xinput_teardown_witness(s_xinput_hook), xinput_teardown_witness(s_xinput_ex_hook),
                                XInputRetentionReason::InflightTimeout);
            return;
        }

        // Classify both targets before either backend restore. If a newer layer owns either prologue, restoring one
        // member of the pair would create a partial teardown and the unconditional backend write would overwrite that
        // layer. Refuse the whole pair and retain its trampoline chain instead.
        const PatchWitness primary_before = xinput_teardown_witness(s_xinput_hook);
        const PatchWitness ex_before = xinput_teardown_witness(s_xinput_ex_hook);
        if (!witness_permits_write(primary_before) || !witness_permits_write(ex_before))
        {
            retain_xinput_hooks(primary_before, ex_before, XInputRetentionReason::UnrestoredPatch);
            return;
        }

        // Restore Ex first, then primary. A caught exception can occur before or after either mutation, so the byte
        // witness after each call is authoritative. Only Original permits the hook object and keepalives to be freed.
        const PatchWitness ex_after = restore_xinput_hook(s_xinput_ex_hook);
        if (ex_after != PatchWitness::Original)
        {
            retain_xinput_hooks(primary_before, ex_after, XInputRetentionReason::UnrestoredPatch);
            return;
        }
        const PatchWitness primary_after = restore_xinput_hook(s_xinput_hook);
        if (primary_after != PatchWitness::Original)
        {
            retain_xinput_hooks(primary_after, ex_after, XInputRetentionReason::UnrestoredPatch);
            return;
        }

        reset_inactive_xinput_hook(s_xinput_ex_hook);
        reset_inactive_xinput_hook(s_xinput_hook);

        // Nothing can be executing the detour code or the patched prologue any more, so balance the install-time
        // keepalives. A later install_xinput() takes a fresh pair.
        release_xinput_module_refs();

        s_xinput_installed.store(false, std::memory_order_release);
        // Re-arm the enable()-failure latches so a fresh install after a hot-reload can warn again.
        s_xinput_enable_warned.store(false, std::memory_order_relaxed);
        s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
    }

} // namespace DetourModKit::detail
