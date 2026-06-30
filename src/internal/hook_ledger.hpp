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
 *          to the caller). Instead a hook destructor asks the ledger, when it releases, how many NEWER live hooks
 *          still sit on the same target; a non-zero answer means the caller is unwinding layered same-target hooks
 *          out of order (the use-after-free hazard SafetyHook's saved-prologue chaining creates), which the caller
 *          surfaces as a warning rather than corrupting silently.
 */

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @class HookLedger
         * @brief Minimal process-wide tracker of live DMK hooks, by target address and by VMT clone base.
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

            // ---------------------------------------------------------------------------------------------------------
            // Inline / mid hooks -- keyed by the patched target address. Inline and mid hooks at one address share the
            // same prologue bytes, so they share one key space and one layering order.
            // ---------------------------------------------------------------------------------------------------------

            /**
             * @brief Records a live hook at @p target (appended newest-last) and returns its unique ledger id.
             * @return The new ledger id, or 0 if the bookkeeping allocation failed under memory pressure. 0 is an id no
             *         live hook ever holds, so the caller treats it as "untracked": the hook still installs, it simply
             *         is not seen by duplicate detection or teardown-order tracking rather than terminating the host
             *         from this noexcept path.
             */
            [[nodiscard]] std::uint64_t record_hook(std::uintptr_t target) noexcept
            {
                const std::uint64_t id = m_next_id.fetch_add(1, std::memory_order_relaxed);
                try
                {
                    std::lock_guard<std::mutex> guard(m_mutex);
                    const auto it = m_by_target.find(target);
                    if (it != m_by_target.end())
                    {
                        // Layering on an already-tracked target: push_back gives the strong guarantee, so a failed
                        // growth leaves the existing order vector unchanged.
                        it->second.push_back(id);
                    }
                    else
                    {
                        // Build the order vector fully before publishing it, so a throwing allocation never leaves an
                        // empty entry in the map (which is_target_hooked would misread as a live hook).
                        std::vector<std::uint64_t> order;
                        order.push_back(id);
                        m_by_target.emplace(target, std::move(order));
                    }
                }
                catch (...)
                {
                    return 0;
                }
                return id;
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
                std::vector<std::uint64_t> &order = it->second;
                const auto found = std::find(order.begin(), order.end(), id);
                if (found == order.end())
                {
                    return 0;
                }
                // Entries after this id (toward the back) were created later: they are the newer layers still live.
                const std::size_t newer = static_cast<std::size_t>(std::distance(std::next(found), order.end()));
                order.erase(found);
                if (order.empty())
                {
                    m_by_target.erase(it);
                }
                return newer;
            }

            /// True when this kit currently has at least one live hook patching @p target.
            [[nodiscard]] bool is_target_hooked(std::uintptr_t target) const noexcept
            {
                std::lock_guard<std::mutex> guard(m_mutex);
                return m_by_target.find(target) != m_by_target.end();
            }

            // ---------------------------------------------------------------------------------------------------------
            // VMT clones -- keyed by the cloned-vptr base SafetyHook installs. One base per VmtHook (every object the
            // clone is applied to shares that base), so a clone is recorded once at create.
            // ---------------------------------------------------------------------------------------------------------

            /**
             * @brief Records a live VMT clone (installed vptr base @p cloned_base); returns its unique ledger id.
             * @return The new ledger id, or 0 if the bookkeeping allocation failed under memory pressure (see
             *         @ref record_hook for the untracked-on-0 contract).
             */
            [[nodiscard]] std::uint64_t record_vmt(std::uintptr_t cloned_base) noexcept
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
                    return 0;
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

            mutable std::mutex m_mutex;
            /// target address -> live hook ids in creation order (back = newest).
            std::unordered_map<std::uintptr_t, std::vector<std::uint64_t>> m_by_target;
            /// Live VMT clones (small; a linear scan is cheaper than a map at this size).
            std::vector<VmtEntry> m_vmt;
            std::atomic<std::uint64_t> m_next_id{1};
        };
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_HOOK_LEDGER_HPP
