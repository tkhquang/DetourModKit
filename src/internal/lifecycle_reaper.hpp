#ifndef DETOURMODKIT_INTERNAL_LIFECYCLE_REAPER_HPP
#define DETOURMODKIT_INTERNAL_LIFECYCLE_REAPER_HPP

/**
 * @file internal/lifecycle_reaper.hpp
 * @brief Off-thread retirement for workers and owners torn down from their own worker body.
 * @details The process-lifetime reaper moves self-joins and dependent owner destruction to another thread,
 *          keeping captured owner state alive until the worker body returns. Loader-lock teardown remains a
 *          detach-and-retain path and does not use this facility.
 */

#include <memory>
#include <thread>

namespace DetourModKit::detail
{
    /**
     * @brief Joins @p thread on the reaper thread, then releases @p module_ref.
     * @details Ownership of @p thread transfers to the reaper. Use when a StoppableWorker's shutdown() is
     *          reached on the worker's own thread, where an inline join would self-join. The reaper joins
     *          once the body returns, then balances the module reference the worker took at construction.
     * @param thread Owned worker thread to join off-thread (moved in).
     * @param module_ref HMODULE-as-void* the worker took at construction; released after the join. May be
     *        null.
     * @note noexcept and fail-closed: if the retirement cannot be queued (allocation failure, or a reaper
     *       thread that could not start), @p thread is detached and @p module_ref is left outstanding,
     *       recorded as an intentional Worker leak. The thread is never self-joined.
     */
    void reap_worker_thread(std::unique_ptr<std::jthread> thread, void *module_ref) noexcept;

    namespace reaper_detail
    {
        void reap_owner_erased(void *owner, void (*destroy)(void *) noexcept) noexcept;
    } // namespace reaper_detail

    /**
     * @brief Destroys @p owner on the reaper thread after its worker body returns.
     * @tparam Owner Complete owner type whose destructor joins its worker.
     * @param owner Unique owner to retire off-thread.
     * @note If queuing fails, ownership is deliberately retained and recorded as an intentional Worker leak.
     */
    template <typename Owner>
    void reap_owner(std::unique_ptr<Owner> owner) noexcept
    {
        Owner *const raw_owner = owner.release();
        reaper_detail::reap_owner_erased(raw_owner, [](void *raw) noexcept
                                         { std::default_delete<Owner>{}(static_cast<Owner *>(raw)); });
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_LIFECYCLE_REAPER_HPP
