/**
 * @file scan_matching.cpp
 * @brief Public single-pattern matching: scan(), unchecked::find_pattern(), active_simd_level(), and
 *        is_likely_function_prologue().
 * @details scan.hpp owns each contract.
 */

#include "DetourModKit/scan.hpp"

#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"
#include "internal/scan_exclusions.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_shared.hpp"

#include <cstddef>
#include <cstdint>
#include <new>
#include <span>

namespace DetourModKit
{
    namespace scan
    {
        SimdLevel active_simd_level() noexcept
        {
            return detail::active_simd_level();
        }

        Result<Address> scan(const Pattern &pattern, Region scope, std::size_t occurrence, Pages pages) noexcept
        {
            return scan(pattern, scope, std::span<const Region>{}, occurrence, pages);
        }

        Result<Address> scan(
            const Pattern &pattern,
            Region scope,
            std::span<const Region> exclusions,
            std::size_t occurrence,
            Pages pages
        ) noexcept
        {
            if (occurrence == 0)
            {
                return std::unexpected(Error{ErrorCode::NoMatch, "scan::scan"});
            }
            if (pages != Pages::Readable && pages != Pages::Executable)
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "scan::scan"});
            }
            const detail::ModuleSpan range = detail::module_span(scope);
            if (!range.valid())
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::scan"});
            }
            if (!detail::readable_scan_is_authoritative(range, pages, exclusions))
            {
                return std::unexpected(Error{ErrorCode::NotAuthoritative, "scan::scan"});
            }
            try
            {
                detail::ScanExclusions excluded;
                // Only spans the sweep will actually read can affect its result, so dropping the rest keeps a caller
                // that declares many copies from exhausting the set over spans that were never in play.
                excluded.restrict_to(range.base, range.end);
                detail::add_pattern_storage(excluded, pattern);
                detail::add_regions(excluded, exclusions);
                if (excluded.overflowed())
                {
                    // More declared spans than the set can hold: some query storage would go unexcluded, so no result
                    // from this scan is trustworthy. Fail closed instead of silently narrowing the exclusion.
                    return std::unexpected(Error{ErrorCode::NotAuthoritative, "scan::scan"});
                }

                const detail::HaystackHistogram histogram = detail::sample_haystack(scope);
                const detail::EnginePattern compiled = detail::to_engine_pattern(pattern, histogram);
                const detail::MatchResult result = detail::scan_module_pages(
                    compiled,
                    range,
                    pages,
                    detail::ScanQuery{
                        .occurrence = occurrence,
                        .count_beyond = false,
                        .exclusions = &excluded,
                    }
                );
                // A truncated sweep never visited part of the scope, so an earlier occurrence may hide there: the match
                // it did find is not provably the Nth one. That makes truncation fatal to the result whether or not a
                // match was found. The two causes are distinct caller problems and stay distinct codes: a concurrent
                // unmap of the scanned range versus a pattern whose bounded jumps are too broad to search exhaustively.
                if (result.budget_exhausted)
                {
                    return std::unexpected(Error{ErrorCode::BudgetExceeded, "scan::scan"});
                }
                if (result.incomplete)
                {
                    return std::unexpected(Error{ErrorCode::IncompleteScan, "scan::scan"});
                }
                if (result.match == nullptr)
                {
                    return std::unexpected(Error{ErrorCode::NoMatch, "scan::scan"});
                }
                return Address{reinterpret_cast<std::uintptr_t>(result.match)};
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "scan::scan"});
            }
        }

        bool is_likely_function_prologue(Address addr) noexcept
        {
            if (!addr)
            {
                return false;
            }

            const auto b0 = detail::guarded_read<std::uint8_t>(addr.raw());
            if (!b0)
            {
                return false;
            }

            // is_likely_function_prologue in scan.hpp owns the poison list.
            return *b0 != 0x00 && *b0 != 0xCC && *b0 != 0xC2 && *b0 != 0xC3;
        }

        namespace unchecked
        {
            const std::byte *find_pattern(Region region, const Pattern &pattern, std::size_t occurrence) noexcept
            {
                if (region.base.raw() == 0 || region.size == 0 || occurrence == 0)
                {
                    return nullptr;
                }
                try
                {
                    // No page filter and no haystack anchor override: the caller owns readability.
                    const std::size_t anchor = pattern.has_anchor() ? pattern.anchor_index() : pattern.size();
                    const detail::EnginePattern compiled = detail::engine_pattern_from(pattern, anchor);
                    return detail::find_pattern(region.base.ptr<const std::byte>(), region.size, compiled, occurrence);
                }
                catch (const std::bad_alloc &)
                {
                    return nullptr;
                }
            }
        } // namespace unchecked
    } // namespace scan
} // namespace DetourModKit
