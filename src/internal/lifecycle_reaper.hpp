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
    /// Callback that completes an owner's worker rundown while the owner is still alive.
    using SharedOwnerRetire = bool (*)(void *) noexcept;

    /**
     * @brief Moves @p owner's reference to the reaper thread, so its worker can be retired before destruction.
     * @details The reaper invokes @p retire while the owner is alive, then drops its reference only after the callback
     *          reports that destruction is safe. A retirement the callback refuses stays owned by never-destroyed
     *          reaper storage. Once the reaper exists, queuing is allocation-free while its reserve holds, so a
     *          request made under host OOM still lands; only the first-ever request has to build the reaper and can
     *          therefore be refused under that pressure.
     * @param owner Reference to transfer; moved from only on success. A null pointer is accepted and reported queued.
     * @param retire Callback that stops and joins the owner's worker. Required: a null callback is refused, because an
     *        owner whose worker cannot be run down must not be released.
     * @return true when the reference was transferred. On false @p owner is untouched and its retention becomes the
     *         caller's responsibility -- through a precommitted keepalive or its own never-destroyed storage -- never
     *         a release on the retiring thread.
     */
    [[nodiscard]] bool reap_shared_owner(std::shared_ptr<void> &owner, SharedOwnerRetire retire) noexcept;

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
    template <typename Owner> void reap_owner(std::unique_ptr<Owner> owner) noexcept
    {
        Owner *const raw_owner = owner.release();
        reaper_detail::reap_owner_erased(raw_owner, [](void *raw) noexcept
                                         { std::default_delete<Owner>{}(static_cast<Owner *>(raw)); });
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_LIFECYCLE_REAPER_HPP
