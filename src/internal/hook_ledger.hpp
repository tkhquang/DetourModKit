#ifndef DETOURMODKIT_INTERNAL_HOOK_LEDGER_HPP
#define DETOURMODKIT_INTERNAL_HOOK_LEDGER_HPP

/**
 * @file internal/hook_ledger.hpp
 * @brief Per-linked-instance safety ledger for the free-function hook surface; not a public registry.
 * @details Hooks are owned by the caller's handle rather than a central registry, but two safety properties still need
 *          shared state: exact same-kit duplicate detection (does this kit already patch address X?) and layer
 *          ordering for hooks stacked on one target address. This ledger is that state and only that state. It keys on
 *          the raw target address (inline/mid) and the cloned-vptr base (VMT clones), holds no names, exposes no
 *          enumeration, and is never installed.
 *
 *          SCOPE: one ledger per linked DMK instance, NOT per process. DetourModKit is a static archive
 *          (CMakeLists.txt: add_library(DetourModKit STATIC)), so two DLLs that each link it get two independent
 *          ledgers with two duplicate-detection and two layer-ordering domains. Cross-instance layering is therefore
 *          invisible here and is not defended against; a real process-shared registry would be required for that.
 *
 *          Layer ordering is not enforced by reordering destructors -- the RAII model deliberately hands lifetime to
 *          the caller. Instead an operation that would alter a target's bytes claims that target's serialization slot
 *          and measures how many NEWER live hooks sit on the same address. A non-zero answer means the caller is
 *          toggling or unwinding a hook that is no longer on top, so the operation is refused (toggle) or the backend
 *          is intentionally leaked (teardown) rather than writing bytes a newer trampoline still depends on.
 */

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        /**
         * @brief Fired immediately before every HookLedger state-lock acquisition.
         * @details A throwing probe drives the synchronization-failure branch of each noexcept ledger boundary, which a
         *          real std::mutex on Windows does not produce on demand. Intentionally NOT noexcept: the throw is the
         *          injected failure. Null in production builds, where this seam does not compile at all.
         */
        extern void (*g_hook_ledger_lock_probe)();
#endif

        /**
         * @class HookLedger
         * @brief Tracker of live and in-progress DMK hooks for one linked instance, by target address and VMT base.
         * @details Never destroyed: see @ref instance.
         */
        class HookLedger
        {
        public:
            /**
             * @brief Returns this linked instance's ledger, constructing it once on first use.
             * @details Constructed into function-local static storage and NEVER destroyed, mirroring
             *          StringPool::instance() and Profiler::instance(). A Meyers singleton (`static HookLedger l;`)
             *          would register a static destructor, and a Hook/VmtHook whose own destructor runs later would
             *          then lock a destroyed mutex and search a destroyed map -- a use-after-free reachable whenever a
             *          namespace-scope owner (e.g. an empty `static HookStack` populated after startup) registers its
             *          destructor BEFORE the first hook is created and therefore before this ledger registers its own.
             *          Leaking the state for the process lifetime is the cost of making that ordering irrelevant.
             */
            [[nodiscard]] static HookLedger &instance() noexcept;

            /// Outcome of @ref try_reserve_hook.
            enum class ReserveStatus : std::uint8_t
            {
                /// The slot is reserved and must be committed or released.
                Reserved,
                /// This instance already patches the target, so nothing was reserved.
                AlreadyHooked,
                /// Bookkeeping allocation or lock acquisition failed, so nothing was reserved.
                OutOfMemory
            };

            /**
             * @struct Reservation
             * @brief The result of an atomic check-and-reserve on the target ledger.
             * @details On @ref ReserveStatus::Reserved, @ref id MUST be committed (@ref commit_hook) or rolled back
             *          (@ref release_hook) by the caller. @ref preexisting reports whether this kit already tracked the
             *          target BEFORE this reservation, distinguishing a fresh install from a layered one.
             */
            struct Reservation
            {
                ReserveStatus status{ReserveStatus::OutOfMemory};
                std::uint64_t id{0};
                bool preexisting{false};
            };

            // Inline / mid hooks -- keyed by the patched target address. Inline and mid hooks at one address share the
            // same prologue bytes, so they share one key space, one pending queue, and one layering order.

            /**
             * @brief Atomically checks the target and reserves a ledger id under a single lock acquisition.
             * @param target The patched target address.
             * @param refuse_if_hooked Refuse (reserving nothing) if this kit already patches @p target; this is the
             *        @ref hook::Options::fail_if_already_hooked exact same-kit gate.
             * @return A @ref Reservation. On @ref ReserveStatus::Reserved the id is appended newest-last and is next in
             *         the per-target queue.
             * @details Folding the check and the record into one locked step closes the time-of-check/time-of-use gap a
             *          separate is_target_hooked + record left open. Reservations also wait their turn in creation
             *          order, so two permissive same-target installs cannot patch concurrently or invert the layering
             *          order. Allocation or lock failure returns OutOfMemory so the caller fails the install closed
             *          rather than installing a live-but-unledgered hook that duplicate detection and layer tracking
             *          cannot see.
             * @warning Setup/control-plane only, and NOT reentrant for a single target on one thread: a thread MUST
             *          commit or roll back its reservation before reserving the SAME @p target again, or the second
             *          call blocks forever waiting for the first -- which the same thread still holds -- to leave the
             *          queue. DMK's install paths honor this and never install reentrantly from a detour, so the
             *          deadlock is unreachable in supported use; it is a caller error, not a defect.
             */
            [[nodiscard]] Reservation try_reserve_hook(std::uintptr_t target, bool refuse_if_hooked) noexcept;

            /**
             * @brief Completes a reservation after backend creation and wakes the next same-target installer.
             * @return True when the reservation was committed. False on lock failure or an invalid reservation, so the
             *         installer can fail before publishing a handle.
             * @details The id stays in the target's creation order for duplicate detection and layer tracking; only the
             *          pending reservation is removed.
             */
            [[nodiscard]] bool commit_hook(std::uintptr_t target, std::uint64_t id) noexcept;

            /**
             * @brief Removes hook @p id from @p target and returns how many NEWER live hooks remain on it.
             * @return The count of hooks created AFTER @p id still live on the same target. Zero means @p id was the
             *         newest (or sole) hook, so a byte restore is in the safe newest-first order. Any positive value
             *         means newer layers sit on top and the caller must not restore. Lock failure returns a positive
             *         count so the caller fails closed to a leak.
             */
            [[nodiscard]] std::size_t release_hook(std::uintptr_t target, std::uint64_t id) noexcept;

            /**
             * @brief Claims @p target's serialization slot for an operation that may alter its bytes, returning the
             *        newer-live count measured at the instant the slot is held.
             * @return The count of hooks created AFTER @p id still live on @p target. Zero authorizes the caller to
             *         write target bytes (enable, disable, or restore); any positive value means @p id is not the top
             *         layer -- or one raced in during the claim -- and the caller MUST refuse (toggle) or leak
             *         (teardown). An absent target/id, a bookkeeping allocation failure, or a lock failure all return a
             *         positive count so the caller fails closed.
             * @details The write-side counterpart to @ref try_reserve_hook, used by enable, disable, and teardown. A
             *          bare newer-count peek followed by a byte write is not atomic against a concurrent same-target
             *          install: an install reserved after the peek reads the caller's prologue as its resume, and the
             *          caller's write then clobbers it and the trampoline the new layer chains through -- a
             *          use-after-free. This method closes that window by waiting its turn in the SAME per-target queue
             *          an install waits in, then blocking every new reserver behind this id until the slot is released.
             *          While the slot is held no install can read or write @p target's prologue, so {decide, write} is
             *          effectively atomic against installs.
             * @warning The caller MUST release the slot exactly once -- @ref release_hook (which also drops the id) or
             *          @ref release_target_slot (which keeps it) -- or later same-target installs block forever.
             *          Release it before running user code or taking the loader lock: holding it across either invites
             *          a deadlock against an install that is itself under the loader lock.
             */
            [[nodiscard]] std::size_t acquire_target_slot(std::uintptr_t target, std::uint64_t id) noexcept;

            /**
             * @brief Releases a slot claimed by @ref acquire_target_slot WITHOUT removing @p id from the creation
             *        order.
             * @details For callers whose hook remains live or remains physically patched: a refused toggle, or a
             *          teardown that leaked its backend. Only the queue sentinel is removed, waking the next
             *          same-target installer; the order entry stays so @ref is_target_hooked keeps reporting the
             *          target hooked. The restoring teardown path instead calls @ref release_hook, which drops the id
             *          from both.
             */
            void release_target_slot(std::uintptr_t target, std::uint64_t id) noexcept;

            /// True when this kit currently has at least one live or reserved hook for @p target; true on lock failure.
            [[nodiscard]] bool is_target_hooked(std::uintptr_t target) const noexcept;

            // VMT clones -- keyed by the cloned-vptr base SafetyHook installs. One base per VmtHook (every object the
            // clone is applied to shares that base), so a clone is recorded once at create.

            /**
             * @brief Records a live VMT clone (installed vptr base @p cloned_base); returns its unique ledger id.
             * @return The new ledger id, or std::nullopt if the bookkeeping allocation or the lock failed.
             * @details A nullopt result tells the caller to fail the clone closed (unwinding the backend to restore the
             *          object's vptr) rather than leave a live-but-untracked clone @ref is_vmt_clone_base cannot
             *          recognise -- the VMT analogue of the inline/mid fail-closed reservation.
             */
            [[nodiscard]] std::optional<std::uint64_t> try_record_vmt(std::uintptr_t cloned_base) noexcept;

            /// Removes the VMT clone @p id from the ledger; best-effort on lock failure.
            void release_vmt(std::uint64_t id) noexcept;

            /**
             * @brief True when @p vptr is the installed base of any live VMT clone this kit owns.
             * @return True on lock failure, so a caller refuses or warns rather than silently double-hooking an
             *         unrecognised clone.
             */
            [[nodiscard]] bool is_vmt_clone_base(std::uintptr_t vptr) const noexcept;

        private:
            HookLedger() noexcept = default;

            /**
             * @brief Acquires the state lock, containing a synchronization failure instead of crossing a noexcept edge.
             * @return An owning lock, or an unowned lock when acquisition failed. Every caller is noexcept and MUST
             *         check owns_lock() and fail closed; std::mutex::lock can throw std::system_error, which would
             *         otherwise reach a noexcept boundary and terminate the host.
             */
            [[nodiscard]] std::unique_lock<std::mutex> lock_state() const noexcept;

            struct VmtEntry
            {
                std::uint64_t id;
                std::uintptr_t base;
            };

            struct TargetEntry
            {
                std::vector<std::uint64_t> order;
                std::vector<std::uint64_t> pending;
            };

            mutable std::mutex m_mutex;
            std::condition_variable m_install_cv;
            // target address -> live/reserved hook ids in creation order (back = newest).
            std::unordered_map<std::uintptr_t, TargetEntry> m_by_target;
            // Live VMT clones (small; a linear scan is cheaper than a map at this size).
            std::vector<VmtEntry> m_vmt;
            std::atomic<std::uint64_t> m_next_id{1};
        };
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_HOOK_LEDGER_HPP
