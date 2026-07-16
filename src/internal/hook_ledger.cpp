#include "internal/hook_ledger.hpp"

#include <algorithm>
#include <iterator>
#include <new>

namespace DetourModKit
{
    namespace detail
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        void (*g_hook_ledger_lock_probe)() = nullptr;
#endif

        HookLedger &HookLedger::instance() noexcept
        {
            // Constructed once into static storage and never destroyed. Default construction is noexcept and leaves
            // the containers empty, so first use requires no bookkeeping allocation.
            alignas(HookLedger) static unsigned char storage[sizeof(HookLedger)];
            static HookLedger *const ledger = ::new (static_cast<void *>(storage)) HookLedger();
            return *ledger;
        }

        std::unique_lock<std::mutex> HookLedger::lock_state() const noexcept
        {
            try
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *probe = g_hook_ledger_lock_probe)
                {
                    probe();
                }
#endif
                return std::unique_lock<std::mutex>(m_mutex);
            }
            catch (...)
            {
                return std::unique_lock<std::mutex>{};
            }
        }

        HookLedger::Reservation HookLedger::try_reserve_hook(std::uintptr_t target, bool refuse_if_hooked) noexcept
        {
            const std::uint64_t id = m_next_id.fetch_add(1, std::memory_order_relaxed);
            try
            {
                std::unique_lock<std::mutex> guard = lock_state();
                if (!guard.owns_lock())
                {
                    return Reservation{ReserveStatus::OutOfMemory, 0, false};
                }
                const auto it = m_by_target.find(target);
                const bool preexisting = (it != m_by_target.end());
                if (preexisting && refuse_if_hooked)
                {
                    // Exact same-kit duplicate: refuse without reserving. The id is skipped (ids are a monotonic
                    // counter with no reuse requirement).
                    return Reservation{ReserveStatus::AlreadyHooked, 0, true};
                }
                // No fixed ceiling is needed: `order` is bounded by live backend hooks, and `pending` by concurrent
                // installer threads. Capping either would refuse legitimate layering without limiting an external
                // event-rate backlog.
                if (preexisting)
                {
                    // push_back gives the strong guarantee, so a failed growth leaves the existing order unchanged.
                    it->second.order.push_back(id);
                    it->second.pending.push_back(id);
                }
                else
                {
                    // Build the entry fully before publishing it, so a throwing allocation never leaves an empty entry
                    // in the map (which is_target_hooked would misread as a live hook).
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

        bool HookLedger::commit_hook(std::uintptr_t target, std::uint64_t id) noexcept
        {
            std::unique_lock<std::mutex> guard = lock_state();
            if (!guard.owns_lock())
            {
                return false;
            }
            auto it = m_by_target.find(target);
            if (it == m_by_target.end())
            {
                return false;
            }
            std::vector<std::uint64_t> &pending = it->second.pending;
            const auto found = std::find(pending.begin(), pending.end(), id);
            if (found == pending.end())
            {
                return false;
            }
            pending.erase(found);
            m_install_cv.notify_all();
            return true;
        }

        std::size_t HookLedger::release_hook(std::uintptr_t target, std::uint64_t id) noexcept
        {
            std::unique_lock<std::mutex> guard = lock_state();
            if (!guard.owns_lock())
            {
                // Without the lock the newer-live count is unknowable. Fail closed to a positive count so a teardown
                // caller leaks its backend rather than restoring bytes a newer layer may still depend on.
                return 1;
            }
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

        std::size_t HookLedger::acquire_target_slot(std::uintptr_t target, std::uint64_t id) noexcept
        {
            std::unique_lock<std::mutex> guard = lock_state();
            if (!guard.owns_lock())
            {
                return 1;
            }
            auto it = m_by_target.find(target);
            if (it == m_by_target.end())
            {
                // Without the ledger entry there is no serialization guarantee. Fail closed.
                return 1;
            }
            const auto order_found = std::find(it->second.order.begin(), it->second.order.end(), id);
            if (order_found == it->second.order.end())
            {
                // An unknown id cannot safely claim this target's write right. Fail closed.
                return 1;
            }
            try
            {
                it->second.pending.push_back(id);
            }
            catch (...)
            {
                // Could not claim the slot. Fail closed: report a positive count so the caller refuses or leaks rather
                // than writing bytes without the guarantee. The id was never queued, so nothing leaks.
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
            // Re-find under the still-held lock (a concurrent emplace/erase may have rehashed the map while we waited)
            // and measure the newer-live count at the instant the slot is owned.
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

        void HookLedger::release_target_slot(std::uintptr_t target, std::uint64_t id) noexcept
        {
            std::unique_lock<std::mutex> guard = lock_state();
            if (!guard.owns_lock())
            {
                return;
            }
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

        bool HookLedger::is_target_hooked(std::uintptr_t target) const noexcept
        {
            std::unique_lock<std::mutex> guard = lock_state();
            if (!guard.owns_lock())
            {
                // Fail closed: report the target as hooked so a fail_if_already_hooked install refuses rather than
                // patching over a layer this instance cannot currently see.
                return true;
            }
            return m_by_target.find(target) != m_by_target.end();
        }

        std::optional<std::uint64_t> HookLedger::try_record_vmt(std::uintptr_t cloned_base) noexcept
        {
            const std::uint64_t id = m_next_id.fetch_add(1, std::memory_order_relaxed);
            try
            {
                std::unique_lock<std::mutex> guard = lock_state();
                if (!guard.owns_lock())
                {
                    return std::nullopt;
                }
                // push_back gives the strong guarantee, so a failed growth leaves m_vmt unchanged.
                m_vmt.push_back(VmtEntry{id, cloned_base});
            }
            catch (...)
            {
                return std::nullopt;
            }
            return id;
        }

        void HookLedger::release_vmt(std::uint64_t id) noexcept
        {
            std::unique_lock<std::mutex> guard = lock_state();
            if (!guard.owns_lock())
            {
                return;
            }
            std::erase_if(m_vmt, [id](const VmtEntry &entry) { return entry.id == id; });
        }

        bool HookLedger::is_vmt_clone_base(std::uintptr_t vptr) const noexcept
        {
            if (vptr == 0)
            {
                return false;
            }
            std::unique_lock<std::mutex> guard = lock_state();
            if (!guard.owns_lock())
            {
                // Fail closed: report the vptr as one of this kit's clone bases so the caller refuses or warns rather
                // than silently baking another handle's hooked slots into its own pristine snapshot.
                return true;
            }
            return std::any_of(m_vmt.begin(), m_vmt.end(),
                               [vptr](const VmtEntry &entry) { return entry.base == vptr; });
        }
    } // namespace detail
} // namespace DetourModKit
