/**
 * @file internal/scan_batch.cpp
 * @brief Raw parallel batch scanners over the whole process or one module image.
 * @details Each item is dispatched to a serial page-gated scan on a worker thread, and results are gathered in input
 *          order by the shared fork-join driver. Correctness rests on read-only sharing: a fully compiled EnginePattern
 *          is immutable during scanning, so workers share the caller's patterns without cloning.
 */

#include "internal/scan_batch.hpp"

#include "internal/scan_engine.hpp"
#include "internal/scan_exclusions.hpp"
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
        // The descriptor array is DMK-owned query material for the duration of the call, so a readable sweep must not
        // report a match inside it. The set is built before the fork and only read afterwards, so the workers share it
        // without synchronization.
        //
        // The engine's floor guarantee is per-scan: it excludes only the pattern being swept, not the SIBLING items'
        // compiled buffers. Those are pre-masked, so a wildcard-free pattern's bytes are byte-identical to its own
        // needle, and they live on committed readable heap pages that a whole-process readable sweep reads like any
        // other page. Add them here, where every item is known. An executable sweep needs none of this: heap pages are
        // not code pages, so no compiled buffer is ever in its scope, and skipping them keeps a large executable batch
        // clear of the bounded set's capacity.
        detail::ScanExclusions exclusions;
        exclusions.add_object_span(items);
        if (kind == detail::ScannerKind::Readable)
        {
            for (const detail::BatchScanItem &item : items)
            {
                if (item.pattern != nullptr)
                {
                    detail::add_engine_pattern_storage(exclusions, *item.pattern);
                }
            }
            if (exclusions.overflowed())
            {
                // More query storage than the bounded set holds, so a match could be one of DMK's own buffers and no
                // result is provable. nullptr is already this API's fail-closed idiom.
                return std::vector<const std::byte *>(items.size(), nullptr);
            }
        }

        return detail::run_fork_join<detail::BatchScanItem, const std::byte *>(
            items, max_workers,
            [kind, &exclusions](const detail::BatchScanItem &item) -> const std::byte *
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
                const detail::ScanQuery query{.occurrence = item.occurrence,
                                              .count_beyond = false,
                                              .exclusions = &exclusions};
                const detail::MatchResult result = (kind == detail::ScannerKind::Readable)
                                                       ? detail::scan_readable_regions(*item.pattern, query)
                                                       : detail::scan_executable_regions(*item.pattern, query);
                return result.truncated() ? nullptr : result.match;
            },
            [](const detail::BatchScanItem &) noexcept -> const std::byte * { return nullptr; });
    }

    std::vector<const std::byte *> detail::scan_module_batch(std::span<const detail::BatchScanItem> items,
                                                             detail::ModuleSpan range, detail::ScannerKind kind,
                                                             std::size_t max_workers)
    {
        // Restricting to the image first drops the descriptor array whenever it lives outside the scanned span, which
        // is the ordinary case: the walk never reads those bytes, so the slot would be spent for nothing. The workers'
        // compiled buffers are heap-resident and likewise outside a module image, so the per-scan engine floor is the
        // whole story here.
        detail::ScanExclusions exclusions;
        exclusions.restrict_to(range.base, range.end);
        exclusions.add_object_span(items);

        return detail::run_fork_join<detail::BatchScanItem, const std::byte *>(
            items, max_workers,
            [kind, range, &exclusions](const detail::BatchScanItem &item) -> const std::byte *
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
                const detail::ScanQuery query{.occurrence = item.occurrence,
                                              .count_beyond = false,
                                              .exclusions = &exclusions};
                const detail::MatchResult result = (kind == detail::ScannerKind::Readable)
                                                       ? detail::scan_module_readable(*item.pattern, range, query)
                                                       : detail::scan_module_executable(*item.pattern, range, query);
                return result.truncated() ? nullptr : result.match;
            },
            [](const detail::BatchScanItem &) noexcept -> const std::byte * { return nullptr; });
    }
} // namespace DetourModKit
