#ifndef DETOURMODKIT_SRC_FORK_JOIN_HPP
#define DETOURMODKIT_SRC_FORK_JOIN_HPP

/**
 * @file fork_join.hpp
 * @brief Internal fork-join driver shared by the opt-in parallel batch resolvers.
 * @details One generic work-stealing primitive, @ref DetourModKit::detail::run_fork_join, backs the setup-time
 *          scan::resolve_batch API and the parallel anchor-table resolvers. It adds no scan or resolve logic of its
 *          own -- each item is handed to a caller-supplied resolve_one callable, and results are gathered in input
 *          order.
 */

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <span>
#include <thread>
#include <type_traits>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /// Worker count when the host cannot report hardware_concurrency(); still clamped to the item count below.
        constexpr std::size_t FORK_JOIN_DEFAULT_WORKERS = 4;

        /**
         * @brief Resolves the effective worker count for a batch.
         * @details A @p max_workers of 0 selects std::thread::hardware_concurrency() (or @ref FORK_JOIN_DEFAULT_WORKERS
         *          when the host cannot report it), then clamps the result to @p item_count so a batch never spawns
         *          more workers than it has work. Returns 0 for an empty batch.
         * @param item_count Number of items in the batch.
         * @param max_workers Caller's upper bound on workers, or 0 to auto-select.
         * @return 0 for an empty batch, otherwise a worker count in [1, item_count].
         */
        [[nodiscard]] inline std::size_t fork_join_worker_count(std::size_t item_count,
                                                                std::size_t max_workers) noexcept
        {
            if (item_count == 0)
            {
                return 0;
            }

            std::size_t count = max_workers;
            if (count == 0)
            {
                const unsigned int hardware = std::thread::hardware_concurrency();
                count = (hardware == 0) ? FORK_JOIN_DEFAULT_WORKERS : static_cast<std::size_t>(hardware);
            }
            return std::min(count, item_count);
        }

        /**
         * @brief Resolves a batch of items concurrently, gathering one result per item in input order.
         * @details Allocates the result vector up front and seeds every slot with @p fail_one, so the batch stays
         *          fail-closed even if a slot were never reached. Work is then distributed through an atomic cursor:
         *          each index is claimed by exactly one worker via a fetch_add, so every result slot is written once
         *          (no result race) and the scan path performs no allocation. The calling thread participates as one
         *          worker, so at most @ref fork_join_worker_count() threads run at once; the std::jthread workers
         *          RAII-join before the result vector is returned, and that join is the happens-before that lets the
         *          caller observe every worker's write. A single-share batch (empty, or one worker) runs serially on
         *          the calling thread with no thread creation.
         * @tparam Item The batch element type (a plain-data request).
         * @tparam Result The per-item result type. Must be nothrow-move-assignable: a worker assigns into a result slot
         *                 from inside a noexcept body, so a throwing move would terminate the host.
         * @tparam ResolveOne Callable (const Item&) -> Result, invoked once per item on a worker thread. It MAY throw;
         *                    a throw fails only that item closed (its slot keeps the @p fail_one value) and never
         *                    escapes the worker. It runs concurrently on every worker, so it must be reentrant and
         *                    share no mutable state (the serial primitives it wraps already satisfy this).
         * @tparam FailOne Callable (const Item&) -> Result giving the fail-closed result for an item. Must be noexcept:
         *                 it runs in the noexcept worker body, both as the up-front seed and on the catch path.
         * @param items The batch to resolve. An empty span returns an empty vector.
         * @param max_workers Upper bound on worker threads (0 = auto; see @ref fork_join_worker_count).
         * @param resolve_one Per-item resolver.
         * @param fail_one Per-item fail-closed result factory.
         * @return One @p Result per input item, in input order.
         */
        template <typename Item, typename Result, typename ResolveOne, typename FailOne>
        [[nodiscard]] std::vector<Result> run_fork_join(std::span<const Item> items, std::size_t max_workers,
                                                        ResolveOne resolve_one, FailOne fail_one)
        {
            static_assert(std::is_nothrow_move_assignable_v<Result>,
                          "Result is assigned into a slot inside a noexcept worker body and must not throw on move.");
            static_assert(std::is_nothrow_invocable_r_v<Result, FailOne, const Item &>,
                          "fail_one runs in the noexcept worker body; it must be noexcept and return Result.");

            std::vector<Result> results(items.size());
            for (std::size_t i = 0; i < items.size(); ++i)
            {
                results[i] = fail_one(items[i]);
            }

            const std::size_t worker_count = fork_join_worker_count(items.size(), max_workers);
            if (worker_count <= 1)
            {
                for (std::size_t i = 0; i < items.size(); ++i)
                {
                    try
                    {
                        results[i] = resolve_one(items[i]);
                    }
                    catch (...)
                    {
                        results[i] = fail_one(items[i]);
                    }
                }
                return results;
            }

            std::atomic<std::size_t> cursor{0};
            auto run = [&]() noexcept
            {
                for (;;)
                {
                    const std::size_t index = cursor.fetch_add(1, std::memory_order_relaxed);
                    if (index >= items.size())
                    {
                        break;
                    }

                    try
                    {
                        results[index] = resolve_one(items[index]);
                    }
                    catch (...)
                    {
                        results[index] = fail_one(items[index]);
                    }
                }
            };

            {
                std::vector<std::jthread> workers;
                try
                {
                    workers.reserve(worker_count - 1);
                    for (std::size_t i = 0; i + 1 < worker_count; ++i)
                    {
                        workers.emplace_back([&run]() noexcept { run(); });
                    }
                }
                catch (...)
                {
                    // Thread creation hit a resource limit after starting zero or more workers. The calling thread
                    // still drains the shared cursor below, so the batch completes on fewer workers.
                }
                run();
            }

            return results;
        }
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_SRC_FORK_JOIN_HPP
