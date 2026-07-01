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

#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_prologue_recovery.hpp"
#include "internal/scan_shared.hpp"

#include "DetourModKit/format.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"

#include "fork_join.hpp"

#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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

            // Resolver observability: one line names the winning candidate on success, a distinct line marks
            // hooked-prologue recovery, and a miss records how many ladder rows were tried. These helpers do not alter
            // the address or outcome: formatting/allocation failures are swallowed so a diagnostic cannot turn a
            // genuine hit into a failure. The request label is echoed so callers can correlate logs with the site they
            // asked to resolve.
            void log_resolved(const ScanRequest &request, const Hit &hit, bool via_prologue_recovery) noexcept
            {
                try
                {
                    const std::string where = format::format_address(hit.address.raw());
                    if (via_prologue_recovery)
                    {
                        (void)DetourModKit::log().try_log(
                            LogLevel::Debug,
                            "scan::resolve: '{}' recovered {} via hooked-prologue reconstruction of candidate '{}'.",
                            request.label, where, hit.winning_name);
                    }
                    else
                    {
                        (void)DetourModKit::log().try_log(LogLevel::Debug,
                                                          "scan::resolve: '{}' resolved {} via candidate '{}'.",
                                                          request.label, where, hit.winning_name);
                    }
                }
                catch (...)
                {
                    // Best-effort diagnostic only: never let a logging allocation perturb the resolve() result.
                }
            }

            void log_unresolved(const ScanRequest &request, std::string_view reason) noexcept
            {
                try
                {
                    (void)DetourModKit::log().try_log(LogLevel::Warning,
                                                      "scan::resolve: '{}' matched no candidate across {} tried ({}).",
                                                      request.label, request.ladder.size(), reason);
                }
                catch (...)
                {
                }
            }
        } // namespace

        Result<Hit> resolve(const ScanRequest &request)
        {
            if (request.ladder.empty())
            {
                return std::unexpected(Error{ErrorCode::EmptyCandidates, "scan::resolve"});
            }
            const detail::ModuleSpan range = detail::module_span(request.scope);
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
                    // Fully qualify the namespace: the local `rtti` pointer would otherwise shadow the `rtti` module
                    // namespace and make `rtti::vtable_for_type` name the variable instead.
                    const std::optional<Address> vtable =
                        DetourModKit::rtti::vtable_for_type(rtti->mangled, request.scope);
                    if (vtable && range.contains(vtable->raw()))
                    {
                        const Hit hit{*vtable, candidate.name()};
                        log_resolved(request, hit, false);
                        return hit;
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
                    if (site && range.contains(site->raw()))
                    {
                        const Hit hit{*site, candidate.name()};
                        log_resolved(request, hit, false);
                        return hit;
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

                // Honour the request's page class: Readable sweeps code + data, while Executable narrows to code pages
                // so an instruction signature cannot alias an identical run in data.
                const detail::MatchResult first = detail::scan_module_pages(compiled, range, request.pages, 1);
                if (first.match == nullptr)
                {
                    continue;
                }
                bool incomplete = first.incomplete;
                bool ambiguous = false;
                if (request.require_unique)
                {
                    const detail::MatchResult second = detail::scan_module_pages(compiled, range, request.pages, 2);
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
                if (!resolved || !range.contains(*resolved))
                {
                    // A RipRelative displacement can resolve outside the scanned scope (e.g. an import thunk in another
                    // module); reject it here so the ladder falls through instead of committing out of scope.
                    continue;
                }
                const Hit hit{Address{*resolved}, candidate.name()};
                log_resolved(request, hit, false);
                return hit;
            }

            if (request.prologue_fallback)
            {
                const detail::FallbackOutcome fallback = detail::resolve_prologue_fallback(
                    request, std::span<const std::size_t>{order.data(), ordered_count}, range);
                if (fallback.hit)
                {
                    log_resolved(request, *fallback.hit, true);
                    return *fallback.hit;
                }
                if (fallback.had_direct && fallback.not_applicable)
                {
                    // A Direct candidate existed to rebuild, but its literal tail was too short for any shape. This is
                    // a distinct diagnostic from a plain miss (a name/string/RipRelative-only ladder has no Direct
                    // row).
                    log_unresolved(request, "prologue recovery had no rebuildable Direct candidate");
                    return std::unexpected(Error{ErrorCode::PrologueFallbackNotApplicable, "scan::resolve"});
                }
            }

            log_unresolved(request, "no ladder candidate resolved uniquely in scope");
            return std::unexpected(Error{ErrorCode::NoMatch, "scan::resolve"});
        }

        Result<std::vector<Result<Hit>>> resolve_batch(std::span<const ScanRequest> requests,
                                                       std::size_t max_workers) noexcept
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
                // The per-request result container itself could not be allocated under true out-of-memory, so there is
                // no batch to hand back. The whole-batch failure rides the OUTER Result, which a caller must unwrap
                // before touching any per-request slot -- there is no silently-undersized vector to index past the end
                // of. Error is const-char*-backed, so building it here allocates nothing and keeps this path no-throw.
                return std::unexpected(Error{ErrorCode::OutOfMemory, "scan::resolve_batch"});
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::Unknown, "scan::resolve_batch"});
            }
        }
    } // namespace scan
} // namespace DetourModKit
