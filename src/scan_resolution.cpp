/**
 * @file scan_resolution.cpp
 * @brief The candidate-ladder resolver: resolve() and resolve_batch().
 * @details Dispatches each Candidate on its active variant payload (Direct / RipRelative byte tiers, RttiVtable /
 *          StringXref text tiers) and returns the first that resolves uniquely to an in-scope, plausible address. One
 *          resolve(ScanRequest) carries scope, ordering, uniqueness, prologue fallback, and the ladder as fields. The
 *          byte tiers reuse the page-gated SIMD engine with the bounded
 *          haystack-frequency anchor override (sampled lazily on the first byte candidate, shared across the ladder);
 *          the text tiers resolve through their unique-only backends. On a full direct miss with prologue_fallback,
 *          hooked-prologue recovery is attempted.
 */

#include "DetourModKit/scan.hpp"

#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_prologue_recovery.hpp"
#include "internal/scan_shared.hpp"

#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"

#include "fork_join.hpp"

#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace DetourModKit
{
    namespace scan
    {
        namespace
        {
            // Resolve a byte-tier candidate's match to its final address: a Direct walk-back, or a RipRelative disp32
            // read. Both screen the result through the plausible-userspace floor (in the shared helpers), so a faulted
            // read or a crafted displacement is a miss, never a hit at a near-null or kernel-range address.
            std::optional<std::uintptr_t> resolve_byte_candidate(std::uintptr_t match,
                                                                 const Candidate &candidate) noexcept
            {
                if (const DirectPattern *direct = candidate.as_direct())
                {
                    return detail::resolve_direct(match, *direct);
                }
                if (const RipRelativePattern *rip = candidate.as_rip_relative())
                {
                    return detail::resolve_rip_relative_candidate(match, *rip);
                }
                return std::nullopt;
            }

            // Returns the compiled byte Pattern for a byte-tier candidate, or nullptr for a text tier.
            const Pattern *byte_pattern_of(const Candidate &candidate) noexcept
            {
                if (const DirectPattern *direct = candidate.as_direct())
                {
                    return &direct->pattern;
                }
                if (const RipRelativePattern *rip = candidate.as_rip_relative())
                {
                    return &rip->pattern;
                }
                return nullptr;
            }
        } // namespace

        Result<Hit> resolve(const ScanRequest &request)
        {
            if (request.ladder.empty())
            {
                return std::unexpected(Error{ErrorCode::EmptyCandidates, "scan::resolve"});
            }
            const Memory::ModuleRange range = detail::to_module_range(request.scope);
            if (!range.valid())
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve"});
            }

            // Lay out the try order once. The haystack histogram is sampled lazily on the first byte candidate and
            // shared across every byte candidate in the ladder, since they all scan the same scope.
            std::vector<std::size_t> order(request.ladder.size());
            const std::size_t ordered_count = order_candidates(request.order, request.ladder, order);
            std::optional<detail::HaystackHistogram> histogram;

            for (std::size_t k = 0; k < ordered_count; ++k)
            {
                const Candidate &candidate = request.ladder[order[k]];

                if (const RttiVtable *rtti = candidate.as_rtti_vtable())
                {
                    const std::optional<std::uintptr_t> vtable = Rtti::vtable_for_type(rtti->mangled, range);
                    if (vtable && Memory::contains(range, *vtable))
                    {
                        return Hit{Address{*vtable}, candidate.name()};
                    }
                    continue;
                }
                if (const StringXref *xref = candidate.as_string_xref())
                {
                    // Rebuild a borrowed StringRefQuery view over the candidate's OWNED literal and facets, then
                    // resolve through the public string-xref backend (unique-only by construction).
                    const StringRefQuery query{
                        .text = xref->text,
                        .encoding = xref->encoding,
                        .require_terminator = xref->require_terminator,
                        .return_mode = xref->return_mode,
                        .broad_match = xref->broad_match,
                    };
                    const Result<Address> site = find_string_xref(query, request.scope);
                    if (site && Memory::contains(range, site->raw()))
                    {
                        return Hit{*site, candidate.name()};
                    }
                    continue;
                }

                // Byte tiers (Direct / RipRelative).
                const Pattern *pattern = byte_pattern_of(candidate);
                if (pattern == nullptr)
                {
                    // Unreachable through the factories (every alternative is handled above); skip defensively.
                    continue;
                }
                if (!histogram)
                {
                    histogram = detail::sample_haystack(request.scope);
                }
                const detail::EnginePattern compiled = detail::to_engine_pattern(*pattern, *histogram);

                const detail::MatchResult first = detail::scan_module_readable(compiled, range, 1);
                if (first.match == nullptr)
                {
                    continue;
                }
                bool incomplete = first.incomplete;
                bool ambiguous = false;
                if (request.require_unique)
                {
                    const detail::MatchResult second = detail::scan_module_readable(compiled, range, 2);
                    ambiguous = second.match != nullptr;
                    incomplete = incomplete || second.incomplete;
                }
                if (incomplete)
                {
                    // A faulted region makes the occurrence count a lower bound. A hidden earlier match or duplicate
                    // could live in skipped bytes, so accepting this candidate would turn a race into a wrong address.
                    continue;
                }
                if (ambiguous)
                {
                    // Ambiguous in scope: the lowest-address match is not provably the intended target, so fall through
                    // to the next candidate rather than commit to an arbitrary site.
                    continue;
                }
                const std::optional<std::uintptr_t> resolved =
                    resolve_byte_candidate(reinterpret_cast<std::uintptr_t>(first.match), candidate);
                if (!resolved || !Memory::contains(range, *resolved))
                {
                    // A RipRelative displacement can resolve outside the scanned scope (e.g. an import thunk in another
                    // module); reject it here so the ladder falls through instead of committing out of scope.
                    continue;
                }
                return Hit{Address{*resolved}, candidate.name()};
            }

            if (request.prologue_fallback)
            {
                const detail::FallbackOutcome fallback = detail::resolve_prologue_fallback(
                    request, std::span<const std::size_t>{order.data(), ordered_count}, range);
                if (fallback.hit)
                {
                    return *fallback.hit;
                }
                if (fallback.had_direct && fallback.not_applicable)
                {
                    // A Direct candidate existed to rebuild, but its literal tail was too short for any shape. This is
                    // a distinct diagnostic from a plain miss (a name/string/RipRelative-only ladder has no Direct
                    // row).
                    return std::unexpected(Error{ErrorCode::PrologueFallbackNotApplicable, "scan::resolve"});
                }
            }

            return std::unexpected(Error{ErrorCode::NoMatch, "scan::resolve"});
        }

        std::vector<Result<Hit>> resolve_batch(std::span<const ScanRequest> requests, std::size_t max_workers) noexcept
        {
            try
            {
                return detail::run_fork_join<ScanRequest, Result<Hit>>(
                    requests, max_workers,
                    [](const ScanRequest &request) -> Result<Hit>
                    {
                        try
                        {
                            return resolve(request);
                        }
                        catch (const std::bad_alloc &)
                        {
                            return std::unexpected(Error{ErrorCode::OutOfMemory, "scan::resolve_batch"});
                        }
                    },
                    [](const ScanRequest &) noexcept -> Result<Hit>
                    { return std::unexpected(Error{ErrorCode::NoMatch, "scan::resolve_batch"}); });
            }
            catch (const std::bad_alloc &)
            {
                return {};
            }
            catch (...)
            {
                return {};
            }
        }
    } // namespace scan
} // namespace DetourModKit
