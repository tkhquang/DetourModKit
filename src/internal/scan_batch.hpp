#ifndef DETOURMODKIT_INTERNAL_SCAN_BATCH_HPP
#define DETOURMODKIT_INTERNAL_SCAN_BATCH_HPP

/**
 * @file internal/scan_batch.hpp
 * @brief True-private raw parallel batch scanner: resolve many compiled EnginePatterns concurrently over the whole
 *        process or one module image.
 * @details Never installed. The raw scan batch, an internal engine primitive: the public parallel surface is
 *          scan::resolve_batch. Each item is scanned independently by one worker through the same per-region page walk
 *          the serial scans use, via the generic fork-join driver.
 */

#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @enum ScannerKind
         * @brief Selects which whole-process / module scan a batch item resolves against.
         */
        enum class ScannerKind : std::uint8_t
        {
            /// Committed execute-readable pages only.
            Executable,
            /// All committed readable pages (the data-capable superset).
            Readable
        };

        /**
         * @struct BatchScanItem
         * @brief One pattern request in a parallel batch scan.
         * @details A plain-data request: a non-owning pointer to a caller-owned EnginePattern plus the 1-based
         *          occurrence to resolve. @p pattern must outlive the batch call; a null @p pattern resolves to a
         *          nullptr result slot (fail closed).
         */
        struct BatchScanItem
        {
            /// Non-owning pointer to a caller-owned, compiled pattern. Must outlive the batch call.
            const EnginePattern *pattern = nullptr;
            /// Which occurrence to resolve (1-based). 1 = first match. 0 yields a nullptr result.
            std::size_t occurrence = 1;
        };

        /**
         * @brief Concurrently resolves a batch of compiled patterns against the whole-process region set.
         * @param items The patterns to resolve. An empty span returns an empty vector.
         * @param kind Which whole-process scan to use (Executable default, or Readable).
         * @param max_workers Upper bound on worker threads (0 = auto from hardware concurrency, clamped to item count).
         * @return One pointer per input item, in input order (offset-applied match or nullptr).
         * @note Setup/control-plane only: spawns threads and allocates.
         */
        [[nodiscard]] std::vector<const std::byte *> scan_regions_batch(std::span<const BatchScanItem> items,
                                                                        ScannerKind kind = ScannerKind::Executable,
                                                                        std::size_t max_workers = 0);

        /**
         * @brief Module-scoped parallel batch scan: confines every item to one mapped image.
         * @param items The patterns to resolve. An empty span returns an empty vector.
         * @param range The mapped image to scan. An invalid range yields all-nullptr results (every item fails closed).
         * @param kind Readable (default) scans every readable page; Executable confines matches to code pages.
         * @param max_workers Upper bound on worker threads (see scan_regions_batch).
         * @return One pointer per input item, in input order (offset-applied match or nullptr).
         * @note Setup/control-plane only, same constraints as scan_regions_batch.
         */
        [[nodiscard]] std::vector<const std::byte *> scan_module_batch(std::span<const BatchScanItem> items,
                                                                       ModuleSpan range,
                                                                       ScannerKind kind = ScannerKind::Readable,
                                                                       std::size_t max_workers = 0);
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_BATCH_HPP
