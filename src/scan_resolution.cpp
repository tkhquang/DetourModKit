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
#include "internal/rtti_shared.hpp"
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
#include <utility>
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

            [[nodiscard]] constexpr bool valid_candidate_order(CandidateOrder order) noexcept
            {
                return order == CandidateOrder::AsDeclared || order == CandidateOrder::UniqueFirst;
            }

            [[nodiscard]] constexpr bool valid_fallback_policy(FallbackPolicy policy) noexcept
            {
                switch (policy)
                {
                case FallbackPolicy::Off:
                case FallbackPolicy::WarnOnly:
                case FallbackPolicy::RequireIdentity:
                    return true;
                }
                return false;
            }

            [[nodiscard]] bool valid_candidate_enums(const Candidate &candidate) noexcept
            {
                const StringXref *xref = candidate.as_string_xref();
                return xref == nullptr ||
                       (detail::valid_string_encoding(xref->encoding) && detail::valid_xref_return(xref->return_mode));
            }

            // Resolve a byte-tier candidate's match to its final address: a Direct walk-back, or a RipRelative disp32
            // read. Both screen the result through the plausible-userspace floor (in the shared helpers), so a faulted
            // read or a crafted displacement is a miss, never a hit at a near-null or kernel-range address.
            std::optional<std::uintptr_t> resolve_byte_candidate(
                std::uintptr_t match,
                const Candidate &candidate,
                std::span<const std::byte> instruction
            ) noexcept
            {
                if (const DirectPattern *direct = candidate.as_direct())
                {
                    return detail::resolve_direct(match, *direct);
                }
                if (const RipRelativePattern *rip = candidate.as_rip_relative())
                {
                    return detail::resolve_rip_relative_candidate(match, *rip, instruction);
                }
                return std::nullopt;
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
                            request.label,
                            where,
                            hit.winning_name
                        );
                    }
                    else
                    {
                        (void)DetourModKit::log().try_log(
                            LogLevel::Debug,
                            "scan::resolve: '{}' resolved {} via candidate '{}'.",
                            request.label,
                            where,
                            hit.winning_name
                        );
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
                    (void)DetourModKit::log().try_log(
                        LogLevel::Warning,
                        "scan::resolve: '{}' matched no candidate across {} tried ({}).",
                        request.label,
                        request.ladder.size(),
                        reason
                    );
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
                        request.label,
                        format::format_address(hit.address.raw())
                    );
                }
                catch (...)
                {
                }
            }
        } // namespace

        namespace
        {
            /**
             * @brief Collects the query storage of the ladder and the caller exclusions into @p ladder_exclusions.
             * @details The query storage is the Candidate array and each owned text literal that the text tiers search
             *          for verbatim. The Candidate array holds each inline Pattern buffer. The restriction to the
             *          scanned range comes first. It drops every span that the sweep does not read, so a large ladder
             *          still costs one or two slots.
             */
            void collect_ladder_exclusions(
                const ScanRequest &request,
                const detail::ModuleSpan &range,
                detail::ScanExclusions &ladder_exclusions
            ) noexcept
            {
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
            }

            /// Resolves @p xref and carries the ladder and caller exclusions through phase 1.
            [[nodiscard]] Result<Address> find_string_xref_site(
                const StringXref &xref,
                const ScanRequest &request,
                const detail::ScanExclusions &ladder_exclusions,
                Region &reference_span
            )
            {
                const StringRefQuery query{
                    .text = xref.text,
                    .encoding = xref.encoding,
                    .require_terminator = xref.require_terminator,
                    .return_mode = xref.return_mode,
                    .broad_match = xref.broad_match,
                };
                return detail::find_string_xref_with_exclusions(
                    query,
                    request.scope,
                    &ladder_exclusions,
                    request.exclusions,
                    &reference_span
                );
            }

            /**
             * @brief Sweeps @p range in one traversal for the first match of @p compiled and, when the request requires
             *        uniqueness, a second match.
             * @details The single traversal means that a concurrent write cannot produce a hit and a uniqueness verdict
             *          that no single view of memory had. The inline Pattern of @p candidate needs no exclusion of its
             *          own. It is a subobject of the ladder array, and collect_ladder_exclusions() excludes the whole
             *          array.
             */
            [[nodiscard]] detail::MatchResult sweep_byte_candidate(
                const ScanRequest &request,
                const detail::ModuleSpan &range,
                const Candidate &candidate,
                const detail::EnginePattern &compiled,
                const detail::ScanExclusions &ladder_exclusions
            ) noexcept
            {
                const RipRelativePattern *rip = candidate.as_rip_relative();
                const std::uint8_t instruction_snapshot_length =
                    rip != nullptr ? static_cast<std::uint8_t>(rip->instruction_length) : std::uint8_t{0};
                return detail::scan_module_pages(
                    compiled,
                    range,
                    request.pages,
                    detail::ScanQuery{
                        .occurrence = 1,
                        .count_beyond = request.require_unique,
                        .exclusions = &ladder_exclusions,
                        .capture_evidence = true,
                        .instruction_snapshot_length = instruction_snapshot_length,
                    }
                );
            }

            /**
             * @brief Accepts a complete byte match that the sweep counted once, whose resolved address is in scope and
             *        passes accepts_resolved_address(), and publishes its provenance.
             * @return The hit, or std::nullopt so that the ladder falls through to the next candidate.
             */
            [[nodiscard]] std::optional<Hit> accept_byte_match(
                const ScanRequest &request,
                const detail::ModuleSpan &range,
                const Candidate &candidate,
                const detail::MatchResult &found,
                std::size_t winning_index,
                detail::ResolvedScanHit *provenance
            )
            {
                if (found.match == nullptr)
                {
                    return std::nullopt;
                }
                if (found.truncated())
                {
                    // A skipped faulted region or a bounded-jump budget truncation makes the occurrence count a
                    // lower bound. Unscanned bytes can hide an earlier match or a duplicate, so a hit from an
                    // incomplete sweep can name a wrong address.
                    return std::nullopt;
                }
                if (found.count > 1)
                {
                    // The lowest-address match of an ambiguous sweep is not provably the intended target.
                    return std::nullopt;
                }
                const std::optional<std::uintptr_t> resolved = resolve_byte_candidate(
                    reinterpret_cast<std::uintptr_t>(found.match),
                    candidate,
                    found.instruction.span()
                );
                if (!resolved || !range.contains(*resolved) || !accepts_resolved_address(request, Address{*resolved}))
                {
                    // A RipRelative displacement can resolve outside the scanned scope, for example to an import
                    // thunk in another module.
                    return std::nullopt;
                }
                // The evidence comes from the sweep that produced this match. The address can be a RIP-relative
                // target elsewhere, but the witnessed bytes are always the matched span of the pattern.
                Hit hit{Address{*resolved}, candidate.name(), candidate.mode(), found.evidence};
                if (provenance != nullptr)
                {
                    // The authored match span alone understates the evidence of a RIP winner. The target came from
                    // the whole instruction that the snapshot decode consumed, and a signature can omit the trailing
                    // immediates that it authorizes. The published span therefore extends to the decoded end.
                    // Otherwise a second selector that matches those immediates abuts this span rather than overlaps
                    // it, and one instruction votes twice. The offset-applied match point sits inside the match span,
                    // so the union stays one contiguous extent.
                    Region source = found.physical_span;
                    if (found.instruction.length != 0)
                    {
                        const std::uintptr_t decoded_end =
                            reinterpret_cast<std::uintptr_t>(found.match) + found.instruction.length;
                        if (decoded_end > source.end().raw())
                        {
                            source.size = static_cast<std::size_t>(decoded_end - source.base.raw());
                        }
                    }
                    provenance->physical_source = source;
                    provenance->winning_index = winning_index;
                    provenance->match_span = found.physical_span;
                }
                log_resolved(request, hit, false);
                return hit;
            }

            /**
             * @brief Tries each candidate in @p order and returns the first hit, or std::nullopt when every candidate
             *        misses.
             * @details The first byte-sweep coverage failure latches into @p coverage_error, and the first text-tier
             *          failure latches into @p text_error. resolve_impl() states what each latch proves.
             */
            [[nodiscard]] std::optional<Hit> resolve_ladder_rungs(
                const ScanRequest &request,
                const detail::ModuleSpan &range,
                const detail::ScanExclusions &ladder_exclusions,
                const std::vector<std::size_t> &order,
                std::size_t ordered_count,
                std::optional<ErrorCode> &coverage_error,
                std::optional<ErrorCode> &text_error,
                detail::ResolvedScanHit *provenance
            )
            {
                // The first byte candidate samples the haystack histogram. Every later byte candidate reuses it,
                // because all of them scan the same scope.
                std::optional<detail::HaystackHistogram> histogram;
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
                        // Fully qualify the namespace: the local `rtti` pointer would otherwise shadow the `rtti`
                        // module namespace and make `rtti::detail` name the variable instead.
                        const DetourModKit::rtti::detail::PrimaryVtable primary =
                            DetourModKit::rtti::detail::primary_vtable_checked(rtti->mangled, request.scope);
                        const std::optional<Address> &vtable = primary.vtable;
                        if (vtable && range.contains(vtable->raw()) && accepts_resolved_address(request, *vtable))
                        {
                            Hit hit{*vtable, candidate.name(), Mode::RttiVtable};
                            if (provenance != nullptr)
                            {
                                provenance->winning_index = order[k];
                            }
                            log_resolved(request, hit, false);
                            return hit;
                        }
                        if (primary.completeness != DetourModKit::rtti::Traversal::Complete)
                        {
                            remember_text_error(ErrorCode::IncompleteScan);
                        }
                        continue;
                    }
                    if (const StringXref *xref = candidate.as_string_xref())
                    {
                        Region reference_span{};
                        const Result<Address> site =
                            find_string_xref_site(*xref, request, ladder_exclusions, reference_span);
                        if (site && range.contains(site->raw()) && accepts_resolved_address(request, *site))
                        {
                            Hit hit{*site, candidate.name(), Mode::StringXref};
                            if (provenance != nullptr)
                            {
                                provenance->physical_source = reference_span;
                                provenance->winning_index = order[k];
                            }
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
                    const Pattern *pattern = detail::byte_pattern_of(candidate);
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
                    const detail::MatchResult found =
                        sweep_byte_candidate(request, range, candidate, compiled, ladder_exclusions);
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
                    if (std::optional<Hit> hit =
                            accept_byte_match(request, range, candidate, found, order[k], provenance))
                    {
                        return hit;
                    }
                }
                return std::nullopt;
            }

            /**
             * @brief Runs hooked-prologue recovery after a full direct miss.
             * @return The recovered hit, else the latched @p text_error, else the first recovery diagnostic, or
             *         std::nullopt when none applies.
             */
            [[nodiscard]] std::optional<Result<Hit>> try_prologue_fallback(
                const ScanRequest &request,
                const std::vector<std::size_t> &order,
                std::size_t ordered_count,
                const detail::ModuleSpan &range,
                const std::optional<ErrorCode> &text_error,
                detail::ResolvedScanHit *provenance
            )
            {
                const detail::FallbackOutcome fallback = detail::resolve_prologue_fallback(
                    request,
                    std::span<const std::size_t>{order.data(), ordered_count},
                    range
                );
                if (fallback.hit && accepts_resolved_address(request, fallback.hit->address))
                {
                    if (provenance != nullptr)
                    {
                        provenance->physical_source = fallback.physical_source;
                    }
                    if (fallback.identity_warned)
                    {
                        log_identity_warning(request, *fallback.hit);
                    }
                    log_resolved(request, *fallback.hit, true);
                    return *fallback.hit;
                }
                if (text_error)
                {
                    // The text-tier code precedes the prologue diagnostics. An unencodable literal or an unconfined
                    // text scope is a defect in the request. An identity rejection or a missing rebuildable Direct
                    // candidate is a property of the recovery attempt. The caller must act on the request-level code.
                    log_unresolved(request, DetourModKit::to_string(*text_error));
                    return std::unexpected(Error{*text_error, "scan::resolve"});
                }
                if (fallback.identity_rejected)
                {
                    // RequireIdentity refused every structurally recovered site. The rebuilt prologue matched
                    // uniquely, but no recovered address passed the witness. Unlike a plain miss, this code tells the
                    // caller that a hooked near-twin exists. The signature then needs a sharper witness or a
                    // corroborating landmark.
                    log_unresolved(request, "prologue recovery rejected by identity gate");
                    return std::unexpected(Error{ErrorCode::PrologueIdentityRejected, "scan::resolve"});
                }
                if (fallback.ambiguous)
                {
                    // A rebuilt hook shape matched more than one executable site, so recovery cannot name a single
                    // redirect. This code follows the identity gate, which judges a uniquely found site. It precedes
                    // the incomplete and applicability diagnostics, because a proven multiplicity is more specific
                    // than a truncated sweep or a too-short tail. Unlike a plain miss, this code tells the caller that
                    // the surviving tail of the signature is not unique.
                    log_unresolved(request, DetourModKit::to_string(ErrorCode::PrologueFallbackAmbiguous));
                    return std::unexpected(Error{ErrorCode::PrologueFallbackAmbiguous, "scan::resolve"});
                }
                if (fallback.incomplete)
                {
                    // The recovery sweep over the executable pages went short, so "no rebuildable shape matched" is
                    // not a proven absence. This code follows the identity gate, which requires a recovered
                    // site. It precedes the applicability diagnostics, which read as a proven miss.
                    log_unresolved(request, DetourModKit::to_string(ErrorCode::IncompleteScan));
                    return std::unexpected(Error{ErrorCode::IncompleteScan, "scan::resolve"});
                }
                if (fallback.had_direct && fallback.not_applicable)
                {
                    // At least one Direct candidate existed, and no shape rebuilt a usable pattern from any of them.
                    // This code differs from a plain miss, where the ladder carries no Direct candidate to rebuild.
                    log_unresolved(request, "prologue recovery had no rebuildable Direct candidate");
                    return std::unexpected(Error{ErrorCode::PrologueFallbackNotApplicable, "scan::resolve"});
                }
                return std::nullopt;
            }

            Result<Hit> resolve_impl(const ScanRequest &request, detail::ResolvedScanHit *provenance)
            {
                if (provenance != nullptr)
                {
                    provenance->physical_source = Region{};
                    provenance->winning_index = static_cast<std::size_t>(-1);
                    provenance->match_span = Region{};
                }
                if (request.pages != Pages::Readable && request.pages != Pages::Executable)
                {
                    return std::unexpected(Error{ErrorCode::InvalidArg, "scan::resolve"});
                }
                if (!valid_candidate_order(request.order) || !valid_fallback_policy(request.fallback_policy))
                {
                    return std::unexpected(Error{ErrorCode::InvalidArg, "scan::resolve"});
                }
                for (const Candidate &candidate : request.ladder)
                {
                    if (!valid_candidate_enums(candidate))
                    {
                        return std::unexpected(Error{ErrorCode::InvalidArg, "scan::resolve"});
                    }
                }
                if (request.ladder.empty())
                {
                    return std::unexpected(Error{ErrorCode::EmptyCandidates, "scan::resolve"});
                }
                const detail::ModuleSpan range = detail::module_span(request.scope);
                if (!range.valid())
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve"});
                }
                if (!detail::readable_scan_is_authoritative(range, request.pages, request.exclusions))
                {
                    // The Readable authority rule of scan::Pages refuses the request before any tier is graded.
                    return std::unexpected(Error{ErrorCode::NotAuthoritative, "scan::resolve"});
                }

                detail::ScanExclusions ladder_exclusions;
                collect_ladder_exclusions(request, range, ladder_exclusions);
                if (ladder_exclusions.overflowed())
                {
                    return std::unexpected(Error{ErrorCode::NotAuthoritative, "scan::resolve"});
                }

                std::vector<std::size_t> order(request.ladder.size());
                const std::size_t ordered_count = order_candidates(request.order, request.ladder, order);
                // The two latches split a candidate failure by what it proves, not by its code. A byte candidate whose
                // sweep went short leaves the module-executable pages that hooked-prologue recovery searches only
                // partly read. A full direct miss is then unproven, so recovery must not run. A text candidate fails on
                // an unencodable literal, or on an unconfined or truncated readable phase-1 sweep. That failure says
                // nothing about executable-page coverage, and recovery acts only on Direct candidates. The text-tier
                // code therefore replaces the generic miss and does not suppress recovery.
                std::optional<ErrorCode> coverage_error;
                std::optional<ErrorCode> text_error;
                std::optional<Hit> hit = resolve_ladder_rungs(
                    request,
                    range,
                    ladder_exclusions,
                    order,
                    ordered_count,
                    coverage_error,
                    text_error,
                    provenance
                );
                if (hit)
                {
                    return std::move(*hit);
                }

                if (coverage_error)
                {
                    // A byte rung was budget-bound or truncated, so the executable pages recovery would search were not
                    // fully covered and a rebuilt-prologue hit could not be read as "the direct scan missed". Fail
                    // closed before the fallback, and ahead of every other verdict so a coverage code can never become
                    // NoMatch.
                    log_unresolved(request, DetourModKit::to_string(*coverage_error));
                    return std::unexpected(Error{*coverage_error, "scan::resolve"});
                }

                if (request.fallback_policy != FallbackPolicy::Off)
                {
                    std::optional<Result<Hit>> verdict =
                        try_prologue_fallback(request, order, ordered_count, range, text_error, provenance);
                    if (verdict)
                    {
                        return std::move(*verdict);
                    }
                }

                if (text_error)
                {
                    // Reached when the fallback is Off or produced no verdict of its own. The typed text-tier code is
                    // more actionable than a generic miss, and a truncated text sweep must never read as a proven
                    // absence.
                    log_unresolved(request, DetourModKit::to_string(*text_error));
                    return std::unexpected(Error{*text_error, "scan::resolve"});
                }

                log_unresolved(request, "no ladder candidate resolved uniquely in scope");
                return std::unexpected(Error{ErrorCode::NoMatch, "scan::resolve"});
            }
        } // namespace

        Result<Hit> resolve(const ScanRequest &request)
        {
            return resolve_impl(request, nullptr);
        }

        Result<std::vector<Result<Hit>>>
        resolve_batch(std::span<const ScanRequest> requests, std::size_t max_workers) noexcept
        {
            try
            {
                return detail::run_fork_join<ScanRequest, Result<Hit>>(
                    requests,
                    max_workers,
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
                    { return std::unexpected(Error{ErrorCode::NoMatch, "scan::resolve_batch"}); }
                );
            }
            catch (const std::bad_alloc &)
            {
                // The resolve_batch docblock in scan.hpp owns this outer-Result arm. Error holds a const char*, so
                // this path allocates nothing.
                return std::unexpected(Error{ErrorCode::OutOfMemory, "scan::resolve_batch"});
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::Unknown, "scan::resolve_batch"});
            }
        }
    } // namespace scan

    Result<detail::ResolvedScanHit> detail::resolve_scan_with_provenance(const scan::ScanRequest &request)
    {
        ResolvedScanHit resolved;
        Result<scan::Hit> hit = scan::resolve_impl(request, &resolved);
        if (!hit)
        {
            return std::unexpected(hit.error());
        }
        resolved.hit = std::move(*hit);
        return resolved;
    }
} // namespace DetourModKit
