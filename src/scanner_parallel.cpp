/**
 * @file scanner_parallel.cpp
 * @brief Opt-in fork-join batch resolvers: scan many compiled patterns, or resolve many cascades, concurrently.
 *
 * Sibling translation unit of the scanner module (scanner.cpp / scanner_cascade.cpp), sharing the public scanner.hpp
 * surface and the internal scanner_internal.hpp entry points. It adds no new scan or resolve primitive: each batch item
 * is dispatched to an existing serial entry point on a worker thread, and results are gathered in input order by the
 * shared fork-join driver in fork_join.hpp. scan_regions_batch / scan_module_batch fan the per-pattern region walk
 * (scan_executable_regions / scan_readable_regions for the whole process, detail::scan_module_* for one image) across
 * workers; resolve_cascade_batch fans the cascade resolvers (resolve_cascade / resolve_cascade_in_module and their
 * prologue-fallback variants).
 *
 * Correctness rests on read-only sharing of caller-owned inputs. The batch scanners rely on the CompiledPattern
 * immutability contract: find_pattern and the region walk take the pattern by const reference and never write back (an
 * un-anchored pattern recomputes its anchor into a local), so a compiled pattern is safe to read concurrently from
 * many threads without cloning. The cascade resolvers compile each candidate into a per-call local CompiledPattern, so
 * concurrent requests share only the immutable candidate tables. The runtime CPUID feature caches and the Logger are
 * thread-safe, and VirtualQuery is an OS-level read, so concurrent serial work shares no mutable state.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

#include "fork_join.hpp"
#include "scanner_internal.hpp"

#include <cstddef>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace DetourModKit
{
    namespace Scanner
    {
        std::vector<const std::byte *> scan_regions_batch(std::span<const BatchScanItem> items, ScannerKind kind,
                                                          std::size_t max_workers)
        {
            return DetourModKit::detail::run_fork_join<BatchScanItem, const std::byte *>(
                items, max_workers,
                [kind](const BatchScanItem &item) -> const std::byte *
                {
                    if (item.pattern == nullptr)
                    {
                        return nullptr;
                    }
                    return (kind == ScannerKind::Readable) ? scan_readable_regions(*item.pattern, item.occurrence)
                                                           : scan_executable_regions(*item.pattern, item.occurrence);
                },
                [](const BatchScanItem &) noexcept -> const std::byte * { return nullptr; });
        }

        std::vector<const std::byte *> scan_module_batch(std::span<const BatchScanItem> items,
                                                         Memory::ModuleRange range, ScannerKind kind,
                                                         std::size_t max_workers)
        {
            return DetourModKit::detail::run_fork_join<BatchScanItem, const std::byte *>(
                items, max_workers,
                [kind, range](const BatchScanItem &item) -> const std::byte *
                {
                    if (item.pattern == nullptr)
                    {
                        return nullptr;
                    }
                    return (kind == ScannerKind::Readable)
                               ? detail::scan_module_readable(*item.pattern, range, item.occurrence)
                               : detail::scan_module_executable(*item.pattern, range, item.occurrence);
                },
                [](const BatchScanItem &) noexcept -> const std::byte * { return nullptr; });
        }

        std::vector<std::expected<ResolveHit, ResolveError>>
        resolve_cascade_batch(std::span<const CascadeRequest> requests, std::size_t max_workers)
        {
            using CascadeResult = std::expected<ResolveHit, ResolveError>;
            return DetourModKit::detail::run_fork_join<CascadeRequest, CascadeResult>(
                requests, max_workers,
                [](const CascadeRequest &request) -> CascadeResult
                {
                    if (request.range)
                    {
                        if (request.prologue_fallback)
                        {
                            return resolve_cascade_in_module_with_prologue_fallback(request.candidates, request.label,
                                                                                    *request.range);
                        }
                        return resolve_cascade_in_module(request.candidates, request.label, *request.range);
                    }
                    if (request.prologue_fallback)
                    {
                        return resolve_cascade_with_prologue_fallback(request.candidates, request.label);
                    }
                    return resolve_cascade(request.candidates, request.label, request.kind);
                },
                [](const CascadeRequest &) noexcept -> CascadeResult
                { return std::unexpected(ResolveError::NoMatch); });
        }
    } // namespace Scanner
} // namespace DetourModKit
