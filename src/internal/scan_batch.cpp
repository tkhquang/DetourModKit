/**
 * @file internal/scan_batch.cpp
 * @brief Raw parallel batch scanners over the whole process or one module image.
 * @details Each item is dispatched to a serial page-gated scan on a worker thread, and results are gathered in input
 *          order by the shared fork-join driver. Correctness rests on read-only sharing: a fully compiled EnginePattern
 *          is immutable during scanning, so workers share the caller's patterns without cloning.
 */

#include "internal/scan_batch.hpp"

#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"

#include "fork_join.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace DetourModKit
{
    std::vector<const std::byte *> detail::scan_regions_batch(std::span<const detail::BatchScanItem> items,
                                                              detail::ScannerKind kind, std::size_t max_workers)
    {
        return detail::run_fork_join<detail::BatchScanItem, const std::byte *>(
            items, max_workers,
            [kind](const detail::BatchScanItem &item) -> const std::byte *
            {
                // The null check guards the *item.pattern dereference below. An empty pattern or occurrence == 0 is
                // intentionally not re-checked here: the serial scanners already fail both closed.
                if (item.pattern == nullptr)
                {
                    return nullptr;
                }
                // Fail closed on an incomplete sweep, mirroring scan::scan(): a region may fault under the TOCTOU guard
                // or a bounded-jump matcher may exhaust its work budget. Either makes the occurrence count a lower
                // bound, so a returned pointer could be the wrong occurrence. Map that to nullptr rather than hand back
                // a confident-but-possibly-wrong result. nullptr is already the batch's fail-closed idiom (a null
                // pattern resolves to a nullptr slot), so this needs no return-type change.
                const detail::MatchResult result =
                    (kind == detail::ScannerKind::Readable)
                        ? detail::scan_readable_regions(*item.pattern, item.occurrence)
                        : detail::scan_executable_regions(*item.pattern, item.occurrence);
                return result.incomplete ? nullptr : result.match;
            },
            [](const detail::BatchScanItem &) noexcept -> const std::byte * { return nullptr; });
    }

    std::vector<const std::byte *> detail::scan_module_batch(std::span<const detail::BatchScanItem> items,
                                                             detail::ModuleSpan range, detail::ScannerKind kind,
                                                             std::size_t max_workers)
    {
        return detail::run_fork_join<detail::BatchScanItem, const std::byte *>(
            items, max_workers,
            [kind, range](const detail::BatchScanItem &item) -> const std::byte *
            {
                // The null check guards the *item.pattern dereference below. An empty pattern or occurrence == 0 is
                // intentionally not re-checked here: the serial module scanners already fail both closed.
                if (item.pattern == nullptr)
                {
                    return nullptr;
                }
                // Fail closed on an incomplete sweep exactly as scan_regions_batch does above: a skipped faulted region
                // or a bounded-jump budget exhaustion makes the occurrence count a lower bound, so surface nullptr
                // rather than a possibly-wrong occurrence.
                const detail::MatchResult result =
                    (kind == detail::ScannerKind::Readable)
                        ? detail::scan_module_readable(*item.pattern, range, item.occurrence)
                        : detail::scan_module_executable(*item.pattern, range, item.occurrence);
                return result.incomplete ? nullptr : result.match;
            },
            [](const detail::BatchScanItem &) noexcept -> const std::byte * { return nullptr; });
    }
} // namespace DetourModKit
