/**
 * @file scanner_parallel.cpp
 * @brief Opt-in fork-join batch scanner: resolves many compiled patterns concurrently.
 *
 * Sibling translation unit of the scanner module (scanner.cpp / scanner_cascade.cpp), sharing the public scanner.hpp
 * surface and the internal scanner_internal.hpp module-scoped entry points. It adds no new scan primitive: each batch
 * item is dispatched to one of the existing serial scanners (scan_executable_regions / scan_readable_regions for the
 * whole process, detail::scan_module_* for one image) on a worker thread, and the results are gathered in input order.
 *
 * Correctness rests on the CompiledPattern immutability contract: find_pattern and the region walk take the pattern by
 * const reference and never write back (an un-anchored pattern recomputes its anchor into a local), so a fully compiled
 * pattern is safe to read concurrently from many threads without cloning. The runtime CPUID feature caches and the
 * Logger are thread-safe, and VirtualQuery is an OS-level read, so concurrent serial scans share no mutable state.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

#include "scanner_internal.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <span>
#include <thread>
#include <vector>

namespace DetourModKit
{
    namespace Scanner
    {
        namespace
        {
            // Worker count when the host cannot report hardware_concurrency(): a small fan-out that is still capped by
            // the item count below, so a tiny batch never spawns more workers than it has work.
            constexpr std::size_t DEFAULT_FALLBACK_WORKERS = 4;

            /**
             * @brief Resolves the effective worker count for a batch.
             * @details 0 max_workers selects std::thread::hardware_concurrency() (or DEFAULT_FALLBACK_WORKERS when the
             *          host cannot report it), then clamps to the item count so there is never an idle worker. Returns
             *          0 for an empty batch.
             */
            std::size_t resolve_worker_count(std::size_t item_count, std::size_t max_workers) noexcept
            {
                if (item_count == 0)
                {
                    return 0;
                }
                std::size_t count = max_workers;
                if (count == 0)
                {
                    const unsigned int hardware = std::thread::hardware_concurrency();
                    count = (hardware == 0) ? DEFAULT_FALLBACK_WORKERS : static_cast<std::size_t>(hardware);
                }
                return std::min(count, item_count);
            }

            /**
             * @brief Fork-join driver shared by the whole-process and module-scoped batch scanners.
             * @details Allocates the result vector up front so the scan path never allocates, then distributes items to
             *          workers through an atomic cursor: every index is claimed by exactly one thread (each result slot
             *          is written once, so there is no result race) and a worker that finishes early steals the next
             *          item, balancing uneven per-pattern scan costs. The calling thread participates as one worker, so
             *          at most @p worker_count threads scan at once. @p scan_one must be a const, allocation-free,
             *          non-throwing callable -- it is invoked concurrently from every worker and shares no mutable
             *          state.
             * @param items The batch to resolve.
             * @param max_workers Upper bound on concurrent workers (0 = auto).
             * @param scan_one Per-item resolver: maps a BatchScanItem to its match pointer (nullptr on miss / invalid).
             * @return One pointer per input item, in input order.
             */
            template <typename ScanOne>
            std::vector<const std::byte *> run_batch(std::span<const BatchScanItem> items, std::size_t max_workers,
                                                     ScanOne scan_one)
            {
                std::vector<const std::byte *> results(items.size(), nullptr);
                const std::size_t worker_count = resolve_worker_count(items.size(), max_workers);

                // Single share: run serially on the calling thread without spawning. Covers the empty batch (zero
                // iterations) and the one-worker case, so a small batch pays no thread-creation cost.
                if (worker_count <= 1)
                {
                    for (std::size_t i = 0; i < items.size(); ++i)
                    {
                        results[i] = scan_one(items[i]);
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
                        results[index] = scan_one(items[index]);
                    }
                };

                {
                    // jthreads auto-join on scope exit, so a thrown exception below cannot leak a running worker. The
                    // worker bodies ignore the jthread stop_token: a fork-join share always runs to completion, the
                    // RAII join is the only reason jthread is used here.
                    std::vector<std::jthread> workers;
                    try
                    {
                        workers.reserve(worker_count - 1);
                        for (std::size_t w = 0; w + 1 < worker_count; ++w)
                        {
                            workers.emplace_back([&run]() noexcept { run(); });
                        }
                    }
                    catch (...)
                    {
                        // Thread creation hit a resource limit after spawning some workers. The calling thread's run()
                        // below still drains every remaining item through the shared cursor, so the batch completes on
                        // fewer threads rather than failing.
                    }
                    run();
                }

                return results;
            }
        } // anonymous namespace

        std::vector<const std::byte *> scan_regions_batch(std::span<const BatchScanItem> items, ScannerKind kind,
                                                          std::size_t max_workers)
        {
            return run_batch(items, max_workers,
                             [kind](const BatchScanItem &item) noexcept -> const std::byte *
                             {
                                 if (item.pattern == nullptr)
                                 {
                                     return nullptr;
                                 }
                                 // The serial scanners do not throw in practice (Logger calls are best-effort), but the
                                 // guard keeps a stray exception from escaping the worker thread and terminating the
                                 // host: the item fails closed instead.
                                 try
                                 {
                                     return (kind == ScannerKind::Readable)
                                                ? scan_readable_regions(*item.pattern, item.occurrence)
                                                : scan_executable_regions(*item.pattern, item.occurrence);
                                 }
                                 catch (...)
                                 {
                                     return nullptr;
                                 }
                             });
        }

        std::vector<const std::byte *> scan_module_batch(std::span<const BatchScanItem> items,
                                                         Memory::ModuleRange range, ScannerKind kind,
                                                         std::size_t max_workers)
        {
            return run_batch(items, max_workers,
                             [kind, range](const BatchScanItem &item) noexcept -> const std::byte *
                             {
                                 if (item.pattern == nullptr)
                                 {
                                     return nullptr;
                                 }
                                 try
                                 {
                                     return (kind == ScannerKind::Readable)
                                                ? detail::scan_module_readable(*item.pattern, range, item.occurrence)
                                                : detail::scan_module_executable(*item.pattern, range, item.occurrence);
                                 }
                                 catch (...)
                                 {
                                     return nullptr;
                                 }
                             });
        }
    } // namespace Scanner
} // namespace DetourModKit
