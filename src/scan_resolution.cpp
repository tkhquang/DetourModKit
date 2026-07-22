/**
 * @file scan_resolution.cpp
 * @brief The candidate-ladder resolver: resolve() and resolve_batch().
 * @details Dispatches each Candidate on its active variant payload (Direct / RipRelative byte tiers, RttiVtable /
 *          StringXref text tiers) and returns the first that resolves uniquely to an in-scope, plausible address. One
 *          resolve(ScanRequest) carries scope, ordering, uniqueness, prologue fallback, and the ladder as fields. The
 *          byte tiers reuse the page-gated SIMD engine with the bounded
 *          haystack-frequency anchor override (sampled lazily on the first byte candidate, shared across the ladder);
 *          the text tiers resolve through their unique-only backends. On a full direct miss with a non-Off
 *          fallback_policy, hooked-prologue recovery is attempted under that policy's identity gate.
 */

#include "DetourModKit/scan.hpp"

#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"
#include "internal/scan_exclusions.hpp"
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
#if defined(DMK_ENABLE_TEST_SEAMS)
    namespace detail
    {
        void (*g_scan_after_byte_sweep_test_hook)() noexcept = nullptr;
    } // namespace detail
#endif

    namespace scan
    {
        namespace
        {
            [[nodiscard]] bool accepts_resolved_address(const ScanRequest &request, Address address) noexcept
            {
                return !request.require_executable_result || detail::is_executable_address(address.raw());
            }

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

            // A WarnOnly recovery whose identity witness disagreed: surface the possible near-twin at Warning level
            // while still returning the address. Formatting/allocation failures are swallowed like the other
            // diagnostics so a log cannot turn an accepted recovery into a failure.
            void log_identity_warning(const ScanRequest &request, const Hit &hit) noexcept
            {
                try
                {
                    (void)DetourModKit::log().try_log(
                        LogLevel::Warning,
                        "scan::resolve: '{}' recovered {} via hooked-prologue reconstruction, but its identity witness "
                        "disagreed (WarnOnly); the site may be a near-twin.",
                        request.label, format::format_address(hit.address.raw()));
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
            if (request.pages != Pages::Readable && request.pages != Pages::Executable)
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "scan::resolve"});
            }
            const detail::ModuleSpan range = detail::module_span(request.scope);
            if (!range.valid())
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve"});
            }
            if (!detail::readable_scan_is_authoritative(range, request.pages, request.exclusions))
            {
                // A readable scope wider than one image contains the memory the caller's own copies of the ladder's
                // query bytes live on, and DMK cannot enumerate those copies. Every candidate would resolve under that
                // doubt, so refuse the request rather than grade each tier against evidence it cannot trust.
                return std::unexpected(Error{ErrorCode::NotAuthoritative, "scan::resolve"});
            }

            // Query storage shared by every byte candidate: the Candidate array (each inline Pattern buffer lives in
            // it) plus each owned text literal, which the text tiers search for verbatim. Restricting to the scanned
            // range first drops every span the sweep will not read, so a large ladder still costs one or two slots.
            detail::ScanExclusions ladder_exclusions;
            ladder_exclusions.restrict_to(range.base, range.end);
            ladder_exclusions.add_object_span(request.ladder);
            for (const Candidate &entry : request.ladder)
            {
                if (const RttiVtable *rtti_payload = entry.as_rtti_vtable())
                {
                    ladder_exclusions.add_text(rtti_payload->mangled);
                }
                else if (const StringXref *xref_payload = entry.as_string_xref())
                {
                    ladder_exclusions.add_text(xref_payload->text);
                }
            }
            detail::add_regions(ladder_exclusions, request.exclusions);
            if (ladder_exclusions.overflowed())
            {
                return std::unexpected(Error{ErrorCode::NotAuthoritative, "scan::resolve"});
            }

            // Lay out the try order once. The haystack histogram is sampled lazily on the first byte candidate and
            // shared across every byte candidate in the ladder, since they all scan the same scope.
            std::vector<std::size_t> order(request.ladder.size());
            const std::size_t ordered_count = order_candidates(request.order, request.ladder, order);
            std::optional<detail::HaystackHistogram> histogram;
            // Two latches, split by what a failure proves rather than by its code. A byte rung whose own sweep went
            // short leaves the module-executable pages hooked-prologue recovery searches only partly read, so "the
            // direct candidates fully missed" is not established and recovery must not run. A text rung's failure (an
            // unencodable literal, or that tier's own readable phase-1 sweep being unconfined or truncated) says
            // nothing about executable-page coverage, and recovery acts only on Direct rungs, so it is reported in
            // place of the generic miss without suppressing recovery.
            std::optional<ErrorCode> coverage_error;
            std::optional<ErrorCode> text_error;
            const auto remember_coverage_error = [&coverage_error](ErrorCode code) noexcept -> void
            {
                if (!coverage_error)
                {
                    coverage_error = code;
                }
            };
            const auto remember_text_error = [&text_error](ErrorCode code) noexcept -> void
            {
                if (!text_error)
                {
                    text_error = code;
                }
            };

            for (std::size_t k = 0; k < ordered_count; ++k)
            {
                const Candidate &candidate = request.ladder[order[k]];

                if (const RttiVtable *rtti = candidate.as_rtti_vtable())
                {
                    // Fully qualify the namespace: the local `rtti` pointer would otherwise shadow the `rtti` module
                    // namespace and make `rtti::vtable_for_type` name the variable instead.
                    const std::optional<Address> vtable =
                        DetourModKit::rtti::vtable_for_type(rtti->mangled, request.scope);
                    if (vtable && range.contains(vtable->raw()) && accepts_resolved_address(request, *vtable))
                    {
                        Hit hit{*vtable, candidate.name()};
                        log_resolved(request, hit, false);
                        return hit;
                    }
                    continue;
                }
                if (const StringXref *xref = candidate.as_string_xref())
                {
                    // Rebuild a borrowed StringRefQuery view over the candidate's owned literal and facets. The
                    // resolver-specific entry point carries the ladder and caller exclusions through phase 1.
                    const StringRefQuery query{
                        .text = xref->text,
                        .encoding = xref->encoding,
                        .require_terminator = xref->require_terminator,
                        .return_mode = xref->return_mode,
                        .broad_match = xref->broad_match,
                    };
                    const Result<Address> site = detail::find_string_xref_with_exclusions(
                        query, request.scope, &ladder_exclusions, request.exclusions);
                    if (site && range.contains(site->raw()) && accepts_resolved_address(request, *site))
                    {
                        Hit hit{*site, candidate.name()};
                        log_resolved(request, hit, false);
                        return hit;
                    }
                    if (!site && (site.error().code == ErrorCode::IncompleteScan ||
                                  site.error().code == ErrorCode::NotAuthoritative ||
                                  site.error().code == ErrorCode::MalformedQueryText))
                    {
                        remember_text_error(site.error().code);
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
                // so an instruction signature cannot alias an identical run in data. One traversal answers both "where
                // is the first match" and "is there a second", so a concurrent write cannot produce a hit/uniqueness
                // pair that no single view of memory ever had. The candidate's inline Pattern needs no exclusion of its
                // own: it is a subobject of the ladder array, whose whole span is already excluded above.
                const detail::MatchResult found = detail::scan_module_pages(
                    compiled, range, request.pages,
                    detail::ScanQuery{.occurrence = 1,
                                      .count_beyond = request.require_unique,
                                      .exclusions = &ladder_exclusions});
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *const hook = detail::g_scan_after_byte_sweep_test_hook)
                {
                    hook();
                }
#endif
                if (found.budget_exhausted)
                {
                    remember_coverage_error(ErrorCode::BudgetExceeded);
                }
                else if (found.incomplete)
                {
                    remember_coverage_error(ErrorCode::IncompleteScan);
                }
                if (found.match == nullptr)
                {
                    continue;
                }
                if (found.truncated())
                {
                    // A skipped faulted region or a bounded-jump budget truncation makes the occurrence count a lower
                    // bound. A hidden earlier match or duplicate could exist in unscanned bytes, so accepting this
                    // candidate would turn an incomplete sweep into a wrong address.
                    continue;
                }
                if (found.count > 1)
                {
                    // Ambiguous in scope: the lowest-address match is not provably the intended target, so fall through
                    // to the next candidate rather than commit to an arbitrary site.
                    continue;
                }
                const std::optional<std::uintptr_t> resolved =
                    resolve_byte_candidate(reinterpret_cast<std::uintptr_t>(found.match), candidate);
                if (!resolved || !range.contains(*resolved) || !accepts_resolved_address(request, Address{*resolved}))
                {
                    // A RipRelative displacement can resolve outside the scanned scope (e.g. an import thunk in another
                    // module); reject it here so the ladder falls through instead of committing out of scope.
                    continue;
                }
                Hit hit{Address{*resolved}, candidate.name()};
                log_resolved(request, hit, false);
                return hit;
            }

            if (coverage_error)
            {
                // A byte rung was budget-bound or truncated, so the executable pages recovery would search were not
                // fully covered and a rebuilt-prologue hit could not be read as "the direct scan missed". Fail closed
                // before the fallback, and ahead of every other verdict so a coverage code can never become NoMatch.
                log_unresolved(request, DetourModKit::to_string(*coverage_error));
                return std::unexpected(Error{*coverage_error, "scan::resolve"});
            }

            if (request.fallback_policy != FallbackPolicy::Off)
            {
                const detail::FallbackOutcome fallback = detail::resolve_prologue_fallback(
                    request, std::span<const std::size_t>{order.data(), ordered_count}, range);
                if (fallback.hit && accepts_resolved_address(request, fallback.hit->address))
                {
                    if (fallback.identity_warned)
                    {
                        log_identity_warning(request, *fallback.hit);
                    }
                    log_resolved(request, *fallback.hit, true);
                    return *fallback.hit;
                }
                if (text_error)
                {
                    // Reported ahead of the prologue diagnostics: an unencodable literal or an unconfined text scope is
                    // a defect in the request, while an identity rejection or a missing rebuildable Direct row is a
                    // property of the recovery attempt, so the request-level code is the one the caller must act on.
                    log_unresolved(request, DetourModKit::to_string(*text_error));
                    return std::unexpected(Error{*text_error, "scan::resolve"});
                }
                if (fallback.identity_rejected)
                {
                    // RequireIdentity refused every structurally-recovered site: the rebuilt prologue matched uniquely,
                    // but no recovered address passed the witness. Distinct from a plain miss so the caller learns that
                    // a hooked near-twin exists and the signature needs a sharper witness or corroborating landmark.
                    log_unresolved(request, "prologue recovery rejected by identity gate");
                    return std::unexpected(Error{ErrorCode::PrologueIdentityRejected, "scan::resolve"});
                }
                if (fallback.incomplete)
                {
                    // Recovery's own sweep over the executable pages went short, so "no rebuildable shape matched" is
                    // not a proven absence either. Reported after the identity gate, which is a verdict about a site
                    // that WAS found, and ahead of the applicability diagnostics, which would read as a proven miss.
                    log_unresolved(request, DetourModKit::to_string(ErrorCode::IncompleteScan));
                    return std::unexpected(Error{ErrorCode::IncompleteScan, "scan::resolve"});
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

            if (text_error)
            {
                // Reached when the fallback is Off or produced no verdict of its own. The typed text-tier code is more
                // actionable than a generic miss, and a truncated text sweep must never read as a proven absence.
                log_unresolved(request, DetourModKit::to_string(*text_error));
                return std::unexpected(Error{*text_error, "scan::resolve"});
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
