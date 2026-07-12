#ifndef DETOURMODKIT_INTERNAL_HOOK_LEDGER_HPP
#define DETOURMODKIT_INTERNAL_HOOK_LEDGER_HPP

/**
 * @file internal/hook_ledger.hpp
 * @brief Process-wide safety ledger for the free-function hook surface; not a public registry.
 * @details When hooks are owned by the caller's handle rather than a central registry, two safety properties still
 *          need a small piece of shared state: exact same-kit duplicate detection (does this kit already patch
 *          address X?) and newest-first teardown ordering for hooks layered on one target address. This ledger is
 *          that piece, and ONLY that piece: it keys on the raw target address (for inline/mid hooks) and the
 *          cloned-vptr base (for VMT clones); it holds no names, exposes no enumeration, and is never installed. It
 *          is backend-free and allocation-light.
 *
 *          Teardown ordering is not enforced by reordering destructors (the RAII model deliberately hands lifetime
 *          to the caller). Instead a hook destructor claims the target's install-serialization slot and measures how
 *          many NEWER live hooks still sit on the same target. A non-zero answer means the caller is unwinding layered
 *          same-target hooks out of order, so the backend is intentionally leaked rather than restoring a prologue
 *          that a newer trampoline still depends on.
 */

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @class HookLedger
         * @brief Minimal process-wide tracker of live and in-progress DMK hooks, by target address and VMT clone base.
         */
        class HookLedger
        {
        public:
            /// The single process-wide instance (Meyers singleton; init is thread-safe).
            [[nodiscard]] static HookLedger &instance() noexcept
            {
                static HookLedger ledger;
                return ledger;
            }

            /// Outcome of @ref try_reserve_hook.
            enum class ReserveStatus : std::uint8_t
            {
                Reserved,      // Slot reserved; commit it or release it.
                AlreadyHooked, // @p refuse_if_hooked was set and this kit already patches the target; nothing reserved.
                OutOfMemory    // Bookkeeping allocation failed; nothing reserved (the caller must fail the install).
            };

            /**
             * @struct Reservation
             * @brief The result of an atomic check-and-reserve on the target ledger.
             * @details On @ref ReserveStatus::Reserved, @ref id is a live ledger id the caller commits (by handing it
             *          to the hook @ref Impl and calling @ref commit_hook) or rolls back (via @ref release_hook) if a
             *          later create step fails. @ref preexisting reports whether this kit already tracked the target
             *          BEFORE this reservation, so the caller can distinguish a fresh install from a layered one
             *          without a second lookup.
             */
            struct Reservation
            {
                ReserveStatus status{ReserveStatus::OutOfMemory};
                std::uint64_t id{0};
                bool preexisting{false};
            };

            // Inline / mid hooks -- keyed by the patched target address. Inline and mid hooks at one address share the
            // same prologue bytes, so they share one key space, one pending-install queue, and one layering order.

            /**
             * @brief Atomically checks the target and reserves a ledger id under a single lock acquisition.
             * @param target The patched target address.
             * @param refuse_if_hooked When set, refuse (reserving nothing) if this kit already patches @p target; this
             *        is the @ref hook::Options::fail_if_already_hooked exact same-kit gate.
             * @return A @ref Reservation. On @ref ReserveStatus::Reserved the id is appended newest-last to the target,
             *         is next in the per-target install queue, and MUST be committed or rolled back by the caller.
             * @details Folding the "is it already hooked?" check and the id record into one locked step closes the
             *          time-of-check/time-of-use gap that a separate @ref is_target_hooked + record left open: two
             *          concurrent installs on the same target can no longer both observe it un-hooked and both commit.
             *          Reservations also wait their turn in creation order before returning, so two permissive
             *          same-target installs cannot run their backend patch operations concurrently or invert the
             *          trampoline layering order recorded in the ledger.
             *          On an allocation failure it returns @ref ReserveStatus::OutOfMemory so the caller fails the
             *          install closed rather than installing a live-but-unledgered hook that duplicate detection and
             *          teardown-order tracking cannot see.
             * @warning Setup/control-plane only, and NOT reentrant for a single target on one thread: a thread MUST
             *          commit (@ref commit_hook) or roll back (@ref release_hook) its reservation before reserving the
             *          SAME @p target again, or the second call blocks forever waiting for the first reservation --
             *          which the same thread still holds -- to leave the pending queue. DMK's install paths honor this
             *          (install_all commits each row before starting the next) and never install reentrantly from a
             *          detour, so the deadlock is unreachable in supported use; it is a caller error, not a defect.
             */
            [[nodiscard]] Reservation try_reserve_hook(std::uintptr_t target, bool refuse_if_hooked) noexcept
            {
                const std::uint64_t id = m_next_id.fetch_add(1, std::memory_order_relaxed);
                try
                {
                    std::unique_lock<std::mutex> guard(m_mutex);
                    const auto it = m_by_target.find(target);
                    const bool preexisting = (it != m_by_target.end());
                    if (preexisting && refuse_if_hooked)
                    {
                        // Exact same-kit duplicate at this target: refuse without reserving. The id is simply skipped
                        // (ids are a monotonic counter with no reuse requirement).
                        return Reservation{ReserveStatus::AlreadyHooked, 0, true};
                    }
                    // No fixed ceiling on order/pending: unlike an event-rate backlog (AGENTS.md's bounded-backlog
                    // rule targets queues fed at an external event rate), this ledger is fed only by DMK install
                    // calls. `order` is the live/reserved hook set for the target -- capping it would refuse
                    // legitimate layering, and a real backend hook per entry already bounds it by backend resources
                    // -- and `pending` holds only in-flight reservations, bounded by the number of concurrent
                    // installer threads (a single thread must commit or release before reserving the same target
                    // again, or it deadlocks on the wait below per the @warning, so it cannot grow the queue alone).
                    if (preexisting)
                    {
                        // Layering on an already-tracked target: push_back gives the strong guarantee, so a failed
                        // growth leaves the existing order vector unchanged.
                        it->second.order.push_back(id);
                        it->second.pending.push_back(id);
                    }
                    else
                    {
                        // Build the order vector fully before publishing it, so a throwing allocation never leaves an
                        // empty entry in the map (which is_target_hooked would misread as a live hook).
                        TargetEntry entry;
                        entry.order.push_back(id);
                        entry.pending.push_back(id);
                        m_by_target.emplace(target, std::move(entry));
                    }

                    m_install_cv.wait(guard,
                                      [this, target, id]
                                      {
                                          const auto current = m_by_target.find(target);
                                          return current != m_by_target.end() && !current->second.pending.empty() &&
                                                 current->second.pending.front() == id;
                                      });
                    return Reservation{ReserveStatus::Reserved, id, preexisting};
                }
                catch (...)
                {
                    (void)release_hook(target, id);
                    return Reservation{ReserveStatus::OutOfMemory, 0, false};
                }
            }

            /**
             * @brief Marks a successful reservation as physically installed and wakes the next same-target installer.
             * @details The id remains in the target's creation-order vector for duplicate detection and teardown-order
             *          tracking. Only the pending reservation is removed here, allowing the next reserved installer on
             *          the same target to run its backend create after this hook is fully established.
             */
            void commit_hook(std::uintptr_t target, std::uint64_t id) noexcept
            {
                std::lock_guard<std::mutex> guard(m_mutex);
                auto it = m_by_target.find(target);
                if (it == m_by_target.end())
                {
                    return;
                }
                std::vector<std::uint64_t> &pending = it->second.pending;
                const auto found = std::find(pending.begin(), pending.end(), id);
                if (found != pending.end())
                {
                    pending.erase(found);
                }
                m_install_cv.notify_all();
            }

            /**
             * @brief Removes the hook @p id from @p target and returns how many NEWER live hooks remain on it.
             * @return The count of hooks created AFTER @p id that are still live on the same target. Zero means @p id
             *         was the newest (or sole) hook there, so its teardown is in the safe newest-first order; any
             *         positive value means the caller is tearing down a layered hook before the newer ones on top of
             *         it, the use-after-free-prone order.
             */
            [[nodiscard]] std::size_t release_hook(std::uintptr_t target, std::uint64_t id) noexcept
            {
                std::lock_guard<std::mutex> guard(m_mutex);
                auto it = m_by_target.find(target);
                if (it == m_by_target.end())
                {
                    return 0;
                }
                std::vector<std::uint64_t> &pending = it->second.pending;
                const auto pending_found = std::find(pending.begin(), pending.end(), id);
                if (pending_found != pending.end())
                {
                    pending.erase(pending_found);
                }

                std::vector<std::uint64_t> &order = it->second.order;
                const auto found = std::find(order.begin(), order.end(), id);
                if (found == order.end())
                {
                    m_install_cv.notify_all();
                    return 0;
                }
                // Entries after this id (toward the back) were created later: they are the newer layers still live.
                const std::size_t newer = static_cast<std::size_t>(std::distance(std::next(found), order.end()));
                order.erase(found);
                if (order.empty())
                {
                    m_by_target.erase(it);
                }
                m_install_cv.notify_all();
                return newer;
            }

            /**
             * @brief Claims @p target's install-serialization slot for tearing down hook @p id, returning the
             *        newer count once the slot is held.
             * @return The count of hooks created AFTER @p id still live on @p target, computed under the same lock and
             *         at the same instant the slot is claimed. Zero means the caller may restore the prologue safely;
             *         any positive value means a newer layer exists (or raced in while the slot was being claimed) and
             *         the caller MUST leak instead of restore. If the target or id is unexpectedly absent, or a
             *         bookkeeping allocation fails, it returns a positive count so the caller fails closed to a leak.
             * @details The counterpart to @ref try_reserve_hook for the teardown side. A bare newer-count peek followed
             *          by a backend restore is not atomic w.r.t. a concurrent same-target install: an
             *          install reserved after the peek reads the caller's still-patched prologue as its resume, and the
             *          caller's restore then writes the pristine prologue back over it and frees the trampoline the new
             *          layer chains through -- a use-after-free. This method closes that window by having the teardown
             *          wait its turn in the SAME per-target pending queue an install waits in: it drains any installer
             *          already mid-patch, then blocks every new reserver behind this id until the caller releases the
             *          slot (via @ref release_hook on the restore path, or @ref release_teardown_slot on the leak
             *          path). While the slot is held no install can read or write @p target's prologue, so the {decide,
             *          restore} pair is effectively atomic against installs. The count is measured after the slot is
             *          held, so a layer that raced in during the claim is counted and forces the leak branch.
             * @warning The caller MUST release the slot exactly once -- @ref release_hook (restore) or
             *          @ref release_teardown_slot (leak) -- or later same-target installs block forever behind the
             *          unreleased sentinel.
             */
            [[nodiscard]] std::size_t acquire_teardown_slot(std::uintptr_t target, std::uint64_t id) noexcept
            {
                std::unique_lock<std::mutex> guard(m_mutex);
                auto it = m_by_target.find(target);
                if (it == m_by_target.end())
                {
                    // Without the ledger entry there is no serialization guarantee. Fail closed to a backend leak.
                    return 1;
                }
                const auto order_found = std::find(it->second.order.begin(), it->second.order.end(), id);
                if (order_found == it->second.order.end())
                {
                    // An unknown id cannot safely claim this target's teardown right. Fail closed to a backend leak.
                    return 1;
                }
                try
                {
                    it->second.pending.push_back(id);
                }
                catch (...)
                {
                    // Could not claim the serialization slot. Fail closed: report a positive count so the caller LEAKS
                    // rather than restoring without the guarantee. The id was never queued, so nothing leaks.
                    return 1;
                }
                // Wait our turn behind any installer already mid-patch on this target (front of pending), exactly as an
                // installer does. Once this id is front, no install is touching the target's prologue.
                m_install_cv.wait(guard,
                                  [this, target, id]
                                  {
                                      const auto current = m_by_target.find(target);
                                      return current != m_by_target.end() && !current->second.pending.empty() &&
                                             current->second.pending.front() == id;
                                  });
                // Re-find under the still-held lock (a concurrent emplace/erase may have rehashed the map while we
                // waited) and measure the newer-live count at the instant the slot is owned.
                const auto current = m_by_target.find(target);
                if (current == m_by_target.end())
                {
                    return 1;
                }
                const std::vector<std::uint64_t> &order = current->second.order;
                const auto found = std::find(order.begin(), order.end(), id);
                if (found == order.end())
                {
                    return 1;
                }
                return static_cast<std::size_t>(std::distance(std::next(found), order.end()));
            }

            /**
             * @brief Releases a teardown slot claimed by @ref acquire_teardown_slot WITHOUT removing @p id from the
             *        target's creation order.
             * @details The leak-path counterpart to @ref release_hook. When a teardown leaks its backend (because a
             *          newer layer exists), the target stays physically hooked, so the id MUST remain in the creation
             *          order for @ref is_target_hooked / duplicate detection -- only the pending-queue sentinel that
             *          held the serialization slot is removed here, waking the next same-target installer. The restore
             *          path instead calls @ref release_hook, which drops the id from BOTH pending and order.
             */
            void release_teardown_slot(std::uintptr_t target, std::uint64_t id) noexcept
            {
                std::lock_guard<std::mutex> guard(m_mutex);
                auto it = m_by_target.find(target);
                if (it == m_by_target.end())
                {
                    return;
                }
                std::vector<std::uint64_t> &pending = it->second.pending;
                const auto found = std::find(pending.begin(), pending.end(), id);
                if (found != pending.end())
                {
                    pending.erase(found);
                }
                m_install_cv.notify_all();
            }

            /// True when this kit currently has at least one live or reserved hook for @p target.
            [[nodiscard]] bool is_target_hooked(std::uintptr_t target) const noexcept
            {
                std::lock_guard<std::mutex> guard(m_mutex);
                return m_by_target.find(target) != m_by_target.end();
            }

            // VMT clones -- keyed by the cloned-vptr base SafetyHook installs. One base per VmtHook (every object the
            // clone is applied to shares that base), so a clone is recorded once at create.

            /**
             * @brief Records a live VMT clone (installed vptr base @p cloned_base); returns its unique ledger id.
             * @return The new ledger id, or std::nullopt if the bookkeeping allocation failed under memory pressure.
             * @details A nullopt result tells the caller to fail the clone closed (unwinding the backend to restore the
             *          object's vptr) rather than leave a live-but-untracked clone that @ref is_vmt_clone_base cannot
             *          recognise -- the VMT analogue of the inline/mid fail-closed reservation.
             */
            [[nodiscard]] std::optional<std::uint64_t> try_record_vmt(std::uintptr_t cloned_base) noexcept
            {
                const std::uint64_t id = m_next_id.fetch_add(1, std::memory_order_relaxed);
                try
                {
                    std::lock_guard<std::mutex> guard(m_mutex);
                    // push_back gives the strong guarantee, so a failed growth leaves m_vmt unchanged.
                    m_vmt.push_back(VmtEntry{id, cloned_base});
                }
                catch (...)
                {
                    return std::nullopt;
                }
                return id;
            }

            /// Removes the VMT clone @p id from the ledger.
            void release_vmt(std::uint64_t id) noexcept
            {
                std::lock_guard<std::mutex> guard(m_mutex);
                std::erase_if(m_vmt, [id](const VmtEntry &entry) { return entry.id == id; });
            }

            /// True when @p vptr is the installed base of any live VMT clone this kit owns.
            [[nodiscard]] bool is_vmt_clone_base(std::uintptr_t vptr) const noexcept
            {
                if (vptr == 0)
                {
                    return false;
                }
                std::lock_guard<std::mutex> guard(m_mutex);
                return std::any_of(m_vmt.begin(), m_vmt.end(),
                                   [vptr](const VmtEntry &entry) { return entry.base == vptr; });
            }

        private:
            HookLedger() = default;

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
