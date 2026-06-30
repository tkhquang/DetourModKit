/**
 * @file internal/scan_batch.cpp
 * @brief Raw parallel batch scanners over the whole process or one module image.
 * @details The relocated raw scan batch (the former scanner_parallel.cpp, minus the dropped cascade batch). Each item
 *          is dispatched to an existing serial page-gated scan on a worker thread, and results are gathered in input
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
                return (kind == detail::ScannerKind::Readable)
                           ? detail::scan_readable_regions(*item.pattern, item.occurrence).match
                           : detail::scan_executable_regions(*item.pattern, item.occurrence).match;
            },
            [](const detail::BatchScanItem &) noexcept -> const std::byte * { return nullptr; });
    }

    std::vector<const std::byte *> detail::scan_module_batch(std::span<const detail::BatchScanItem> items,
                                                             Memory::ModuleRange range, detail::ScannerKind kind,
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
                return (kind == detail::ScannerKind::Readable)
                           ? detail::scan_module_readable(*item.pattern, range, item.occurrence).match
                           : detail::scan_module_executable(*item.pattern, range, item.occurrence).match;
            },
            [](const detail::BatchScanItem &) noexcept -> const std::byte * { return nullptr; });
    }
} // namespace DetourModKit
