/**
 * @file anchor.cpp
 * @brief The declarative anchor registry: dispatches each anchor kind to its v4 backend and reports drift uniformly.
 * @details Every kind maps onto exactly one self-healing backend that already fails closed:
 *          - VtableIdentity -> rtti::vtable_for_type (reverse-RTTI vtable resolve),
 *          - RipGlobal      -> scan::resolve         (Direct / RIP-relative candidate cascade),
 *          - CodeOperand    -> scan::read_code_constant (in-code immediate / displacement decode),
 *          - StringXref     -> scan::find_string_xref (string-literal cross-reference resolve),
 *          - Manual         -> a pinned literal (no backend),
 *          - Quorum         -> two independent sub-anchors corroborated,
 *          - CallArgHome    -> reserved (no resolver yet).
 *          This layer adds no scanning of its own: it maps each backend's typed failure onto the common
 *          AnchorStatus and threads the optional post-resolve validator and the per-game ScanProfile defaults.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/rtti.hpp"

#include "fork_join.hpp"

#include <cstdint>
#include <vector>

namespace DetourModKit
{
    namespace anchor
    {
        namespace
        {
            // Applies the profile's candidate-order preference to a cascade backend that has no order parameter of its
            // own (read_code_constant), by building a local reordered span. The caller's candidate table is typically
            // static storage and must not be mutated, so the vector owns the temporary copy for the backend call.
            // AsDeclared (and a trivially-ordered one-candidate site) returns the original span without allocation.
            [[nodiscard]] std::span<const scan::Candidate> profiled_candidates(const ScanProfile &profile,
                                                                               std::span<const scan::Candidate> site,
                                                                               std::vector<scan::Candidate> &ordered)
            {
                if (profile.candidate_order == scan::CandidateOrder::AsDeclared || site.size() < 2)
                {
                    return site;
                }

                std::vector<std::size_t> indices(site.size());
                const std::size_t count = scan::order_candidates(profile.candidate_order, site, indices);
                ordered.reserve(count);
                for (std::size_t i = 0; i < count; ++i)
                {
                    ordered.push_back(site[indices[i]]);
                }
                return ordered;
            }

            // Fail-closed agreement test for the two quorum signals. A negative tolerance is rejected outright:
            // widening it through unsigned subtraction would turn -1 into a huge bound that accepts almost any gap and
            // defeat the corroboration the quorum exists to provide.
            [[nodiscard]] bool quorum_values_agree(std::int64_t first, std::int64_t second, QuorumMatch match,
                                                   std::int64_t tolerance) noexcept
            {
                if (match == QuorumMatch::ExactValue)
                {
                    return first == second;
                }
                if (tolerance < 0)
                {
                    return false;
                }
                // Order the pair so the gap is hi - lo, then widen through unsigned subtraction to avoid signed
                // overflow across a large address span.
                const std::int64_t lo = (first < second) ? first : second;
                const std::int64_t hi = (first < second) ? second : first;
                const auto gap = static_cast<std::uint64_t>(hi) - static_cast<std::uint64_t>(lo);
                return gap <= static_cast<std::uint64_t>(tolerance);
            }

            // True when two resolvable sub-anchors share the SAME backend AND the SAME backend inputs, so they would
            // decode the identical site/name/literal and therefore cannot corroborate each other. Compared per kind so
            // only the fields that kind actually consumes participate. View/span comparison is identity over the
            // underlying storage (same data pointer and length), not a deep byte compare: two distinct candidate arrays
            // expressing the same pattern are still two independent scan sites, so only literally-shared storage
            // counts.
            [[nodiscard]] bool same_backend_config(const Anchor &a, const Anchor &b) noexcept
            {
                if (a.kind != b.kind)
                {
                    return false;
                }
                switch (a.kind)
                {
                case AnchorKind::VtableIdentity:
                    return a.mangled.data() == b.mangled.data() && a.mangled.size() == b.mangled.size();
                case AnchorKind::RipGlobal:
                    return a.site.data() == b.site.data() && a.site.size() == b.site.size();
                case AnchorKind::CodeOperand:
                    return a.site.data() == b.site.data() && a.site.size() == b.site.size() &&
                           a.operand_kind == b.operand_kind && a.operand_index == b.operand_index &&
                           a.byte_width == b.byte_width;
                case AnchorKind::StringXref:
                    return a.xref_text.data() == b.xref_text.data() && a.xref_text.size() == b.xref_text.size() &&
                           a.xref_encoding == b.xref_encoding && a.xref_return == b.xref_return &&
                           a.xref_require_terminator == b.xref_require_terminator &&
                           a.xref_broad_match == b.xref_broad_match;
                case AnchorKind::Manual:
                case AnchorKind::CallArgHome:
                case AnchorKind::Quorum:
                    // Handled by dedicated rules: a dual-Manual pair is rejected wholesale, CallArgHome cannot resolve,
                    // and a nested Quorum is already rejected upstream. No config-identity verdict is needed here.
                    return false;
                }
                return false;
            }

            // Fail-closed independence gate run BEFORE agreement is considered. Two signals are not independent
            // evidence when: (a) they are the exact same Anchor object (pointer-equal); (b) both are Manual literals --
            // two hand-pinned constants agreeing proves only that the author typed the same number twice, not that the
            // live image corroborates it; or (c) they share backend and inputs (same_backend_config), so they decode
            // one site twice. Any of these would let a dependent pair masquerade as corroboration, defeating the
            // quorum's purpose.
            [[nodiscard]] bool quorum_sub_anchors_independent(const Anchor &a, const Anchor &b) noexcept
            {
                if (&a == &b)
                {
                    return false;
                }
                if (a.kind == AnchorKind::Manual && b.kind == AnchorKind::Manual)
                {
                    return false;
                }
                return !same_backend_config(a, b);
            }

            // Commits a backend-resolved value, applying the anchor's optional fail-closed validator. On a validator
            // miss the anchor is reported Failed with no value, identical to a backend miss, so the caller re-heals by
            // re-running resolve.
            void commit_resolved(const Anchor &anchor, ResolvedAnchor &result, std::int64_t value) noexcept
            {
                // Opt-in required-validator policy: a backend-resolved (function/global) target with no domain check is
                // treated as unverified and fails closed. A Quorum is exempt -- its two-signal corroboration already is
                // the verification -- so a caller is not forced to also attach a validator to a corroborated anchor.
                if (anchor.require_validator && anchor.kind != AnchorKind::Quorum && anchor.validator == nullptr)
                {
                    result.status = AnchorStatus::Failed;
                    result.value = 0;
                    return;
                }
                if (anchor.validator != nullptr && !anchor.validator(value, anchor.validator_context))
                {
                    result.status = AnchorStatus::Failed;
                    result.value = 0;
                    return;
                }
                result.value = value;
                result.status = AnchorStatus::Resolved;
            }

            [[nodiscard]] ResolvedAnchor failed_anchor_result(const Anchor &anchor) noexcept
            {
                return ResolvedAnchor{anchor.label, anchor.kind, AnchorStatus::Failed, 0};
            }

            // FNV-1a 64 evidence hashing for anchor_fingerprint. The fingerprint must be stable across runs and builds
            // so a persisted manifest can be diffed, so integers are folded least-significant-byte first (a fixed order
            // independent of host endianness) and every variable-length field is length-prefixed to keep adjacent
            // fields unambiguous (the literal "ab" then "" cannot collide with "a" then "b").
            inline constexpr std::uint64_t FNV1A64_OFFSET = 14695981039346656037ULL;
            inline constexpr std::uint64_t FNV1A64_PRIME = 1099511628211ULL;

            [[nodiscard]] std::uint64_t fnv1a_byte(std::uint64_t hash, std::uint8_t value) noexcept
            {
                return (hash ^ value) * FNV1A64_PRIME;
            }

            // Folds an integer least-significant-byte first over sizeof(T) so the result is endianness-independent. The
            // value is widened to u64 before shifting so a 1-byte type never hits a shift-width edge case.
            template <typename T> [[nodiscard]] std::uint64_t fnv1a_int(std::uint64_t hash, T value) noexcept
            {
                auto bits = static_cast<std::uint64_t>(static_cast<std::make_unsigned_t<T>>(value));
                for (std::size_t i = 0; i < sizeof(T); ++i)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(bits & 0xFFu));
                    bits >>= 8;
                }
                return hash;
            }

            // Length-prefixed string field: the size (folded LSB-first) then the bytes, so adjacent fields never alias.
            [[nodiscard]] std::uint64_t fnv1a_field(std::uint64_t hash, std::string_view field) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(field.size()));
                for (const char c : field)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(c));
                }
                return hash;
            }

            // Length-prefixed raw-byte field for a compiled Pattern's bytes / mask spans.
            [[nodiscard]] std::uint64_t fnv1a_bytes(std::uint64_t hash, std::span<const std::byte> data) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(data.size()));
                for (const std::byte b : data)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(b));
                }
                return hash;
            }

            // Hashes one candidate's address-independent CONTENT. v3 hashed the authored AOB text; v4 scan::Pattern is
            // compiled and does not retain its source string, so the byte tiers hash the compiled bytes + wildcard mask
            // + result-offset plus the decode parameters -- content that is equally stable across a diff and computable
            // without re-parsing. The text tiers hash their owned name / literal and shape flags directly.
            [[nodiscard]] std::uint64_t fnv1a_candidate(std::uint64_t hash, const scan::Candidate &candidate) noexcept
            {
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(candidate.mode()));
                switch (candidate.mode())
                {
                case scan::Mode::Direct:
                {
                    const scan::DirectPattern &direct = *candidate.as_direct();
                    hash = fnv1a_bytes(hash, direct.pattern.bytes());
                    hash = fnv1a_bytes(hash, direct.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(direct.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(direct.walk_back));
                    break;
                }
                case scan::Mode::RipRelative:
                {
                    const scan::RipRelativePattern &rip = *candidate.as_rip_relative();
                    hash = fnv1a_bytes(hash, rip.pattern.bytes());
                    hash = fnv1a_bytes(hash, rip.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(rip.displacement_at));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.instruction_length));
                    break;
                }
                case scan::Mode::RttiVtable:
                    hash = fnv1a_field(hash, candidate.as_rtti_vtable()->mangled);
                    break;
                case scan::Mode::StringXref:
                {
                    const scan::StringXref &xref = *candidate.as_string_xref();
                    hash = fnv1a_field(hash, xref.text);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(xref.encoding));
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(xref.return_mode));
                    hash = fnv1a_byte(hash, xref.require_terminator ? 1U : 0U);
                    hash = fnv1a_byte(hash, xref.broad_match ? 1U : 0U);
                    break;
                }
                }
                return hash;
            }

            [[nodiscard]] std::uint64_t fnv1a_cascade(std::uint64_t hash,
                                                      std::span<const scan::Candidate> site) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(site.size()));
                for (const scan::Candidate &candidate : site)
                {
                    hash = fnv1a_candidate(hash, candidate);
                }
                return hash;
            }

            // Hashes one anchor's own evidence with no quorum recursion. A Quorum reaching here -- which the public
            // entry point only allows for a malformed sub-anchor, since nesting is rejected at resolve time --
            // contributes only its kind, which bounds recursion to a single level.
            [[nodiscard]] std::uint64_t fingerprint_evidence(const Anchor &anchor) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(anchor.kind));
                switch (anchor.kind)
                {
                case AnchorKind::VtableIdentity:
                    hash = fnv1a_field(hash, anchor.mangled);
                    break;
                case AnchorKind::RipGlobal:
                    hash = fnv1a_cascade(hash, anchor.site);
                    break;
                case AnchorKind::CodeOperand:
                    hash = fnv1a_cascade(hash, anchor.site);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.operand_kind));
                    hash = fnv1a_byte(hash, anchor.operand_index);
                    hash = fnv1a_byte(hash, anchor.byte_width);
                    break;
                case AnchorKind::StringXref:
                    hash = fnv1a_field(hash, anchor.xref_text);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.xref_encoding));
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.xref_return));
                    hash = fnv1a_byte(hash, anchor.xref_require_terminator ? 1U : 0U);
                    hash = fnv1a_byte(hash, anchor.xref_broad_match ? 1U : 0U);
                    break;
                case AnchorKind::Manual:
                    hash = fnv1a_int(hash, anchor.manual_value);
                    break;
                case AnchorKind::CallArgHome:
                case AnchorKind::Quorum:
                    // No address-independent evidence beyond the kind byte already folded above.
                    break;
                }
                return hash;
            }
        } // anonymous namespace

        scan::StringRefQuery apply_profile(const ScanProfile &profile, scan::StringRefQuery query) noexcept
        {
            // Widen-only: a per-anchor broad_match already set stays set; the profile can turn broad on but never off.
            query.broad_match = query.broad_match || profile.default_broad_string_xref;
            return query;
        }

        ResolvedAnchor resolve_with_profile(const Anchor &anchor, const ScanProfile &profile, Region scope)
        {
            ResolvedAnchor result{anchor.label, anchor.kind, AnchorStatus::Unresolved, 0};

            // Backend deny-list: a denied kind fails closed before any scan. It is never silently replaced by another
            // backend, which would risk returning a different, wrong target. An empty profile (the default resolve()
            // path) denies nothing, so this is a no-op there.
            if (profile.is_denied(anchor.kind))
            {
                result.status = AnchorStatus::Failed;
                return result;
            }

            switch (anchor.kind)
            {
            case AnchorKind::VtableIdentity:
            {
                const std::optional<Address> vtable = DetourModKit::rtti::vtable_for_type(anchor.mangled, scope);
                if (vtable)
                {
                    commit_resolved(anchor, result, static_cast<std::int64_t>(vtable->raw()));
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::RipGlobal:
            {
                // The cascade itself selects Direct vs RIP-relative per candidate, so a plain global address and a
                // RIP-relative one share this backend. The resolver applies the profile's candidate order internally
                // through ScanRequest::order, so no local reordered copy is needed here.
                const scan::ScanRequest request{
                    .ladder = anchor.site,
                    .label = anchor.label,
                    .scope = scope,
                    .order = profile.candidate_order,
                };
                const Result<scan::Hit> hit = scan::resolve(request);
                if (hit)
                {
                    commit_resolved(anchor, result, static_cast<std::int64_t>(hit->address.raw()));
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::CodeOperand:
            {
                // read_code_constant has no order parameter, so the profile's candidate order is applied by reordering
                // the site into a local ladder up front.
                std::vector<scan::Candidate> ordered_site;
                const scan::CodeConstant code_constant{
                    .site = profiled_candidates(profile, anchor.site, ordered_site),
                    .kind = anchor.operand_kind,
                    .operand_index = anchor.operand_index,
                    .byte_width = anchor.byte_width,
                };
                const Result<std::int64_t> constant = scan::read_code_constant(code_constant, scope);
                if (constant)
                {
                    commit_resolved(anchor, result, *constant);
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::StringXref:
            {
                // Anchor on an immutable string literal, then resolve the instruction (or enclosing function) that
                // references it. The string survives game updates far better than the surrounding code, so this is the
                // most update-resilient backend; it fails closed on a missing, duplicated, or unreferenced string.
                scan::StringRefQuery query{};
                query.text = anchor.xref_text;
                query.encoding = anchor.xref_encoding;
                query.require_terminator = anchor.xref_require_terminator;
                query.return_mode = anchor.xref_return;
                query.broad_match = anchor.xref_broad_match;
                // The profile can only widen the broad sweep on (never off); a per-anchor xref_broad_match still wins.
                query = apply_profile(profile, query);
                const Result<Address> site = scan::find_string_xref(query, scope);
                if (site)
                {
                    commit_resolved(anchor, result, static_cast<std::int64_t>(site->raw()));
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::Manual:
                // A pinned literal always "resolves"; a report should still flag it as at-risk (it cannot self-heal) by
                // inspecting the kind. By default the validator is skipped (the pinned-literal exemption); a caller
                // that opts in via validate_manual routes the literal through the same fail-closed validator path as a
                // backend.
                if (anchor.validate_manual)
                {
                    commit_resolved(anchor, result, anchor.manual_value);
                }
                else
                {
                    result.value = anchor.manual_value;
                    result.status = AnchorStatus::Resolved;
                }
                break;
            case AnchorKind::CallArgHome:
                // Reserved for a future prologue-dataflow backend; no resolver yet.
                result.status = AnchorStatus::Unsupported;
                break;
            case AnchorKind::Quorum:
            {
                // A critical target accepts only when two independent signals corroborate. Fail closed on a malformed
                // declaration (a missing sub-anchor, or a sub-anchor that is itself a Quorum) exactly as the
                // single-signal backends fail closed on ambiguity; rejecting nested Quorum bounds recursion to one
                // level.
                const Anchor *first = anchor.quorum_a;
                const Anchor *second = anchor.quorum_b;
                if (first == nullptr || second == nullptr || first->kind == AnchorKind::Quorum ||
                    second->kind == AnchorKind::Quorum)
                {
                    result.status = AnchorStatus::Failed;
                    break;
                }
                // Independence is a static property of the declaration, so check it before the (potentially expensive)
                // recursive resolves. A dependent pair (same object, dual Manual, or same backend + inputs) is not
                // corroboration; report it precisely instead of letting two scans of one site look corroborated.
                if (!quorum_sub_anchors_independent(*first, *second))
                {
                    result.status = AnchorStatus::QuorumNotIndependent;
                    break;
                }

                // Recurse with the same profile so a denied sub-anchor kind (or a profile broad-default) threads down
                // and a denied signal fails the quorum closed.
                const ResolvedAnchor resolved_first = resolve_with_profile(*first, profile, scope);
                const ResolvedAnchor resolved_second = resolve_with_profile(*second, profile, scope);
                if (resolved_first.status == AnchorStatus::Resolved &&
                    resolved_second.status == AnchorStatus::Resolved &&
                    quorum_values_agree(resolved_first.value, resolved_second.value, anchor.quorum_match,
                                        anchor.quorum_tolerance))
                {
                    // Both agree under the policy. Commit through the same path as the single-signal backends so the
                    // Quorum anchor's own validator runs on the corroborated value (each sub-anchor's validator already
                    // ran in its recursive resolve).
                    commit_resolved(anchor, result, resolved_first.value);
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            }

            return result;
        }

        ResolvedAnchor resolve(const Anchor &anchor, Region scope)
        {
            // An empty profile denies nothing and widens nothing, so this is exactly the un-profiled resolution.
            return resolve_with_profile(anchor, ScanProfile{}, scope);
        }

        std::size_t resolve_all(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out, Region scope)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = resolve(anchors[i], scope);
            }
            return count;
        }

        std::size_t resolve_all_parallel(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out, Region scope,
                                         std::size_t max_workers)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            const std::vector<ResolvedAnchor> results = DetourModKit::detail::run_fork_join<Anchor, ResolvedAnchor>(
                anchors.first(count), max_workers,
                [scope](const Anchor &anchor) -> ResolvedAnchor { return resolve(anchor, scope); },
                [](const Anchor &anchor) noexcept -> ResolvedAnchor { return failed_anchor_result(anchor); });

            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = results[i];
            }
            return count;
        }

        std::size_t resolve_all_with_profile(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                             const ScanProfile &profile, Region scope)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = resolve_with_profile(anchors[i], profile, scope);
            }
            return count;
        }

        std::size_t resolve_all_with_profile_parallel(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                                      const ScanProfile &profile, Region scope, std::size_t max_workers)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            const std::vector<ResolvedAnchor> results = DetourModKit::detail::run_fork_join<Anchor, ResolvedAnchor>(
                anchors.first(count), max_workers, [&profile, scope](const Anchor &anchor) -> ResolvedAnchor
                { return resolve_with_profile(anchor, profile, scope); },
                [](const Anchor &anchor) noexcept -> ResolvedAnchor { return failed_anchor_result(anchor); });

            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = results[i];
            }
            return count;
        }

        AnchorQuality assess_quality(std::span<const ResolvedAnchor> report) noexcept
        {
            AnchorQuality quality{};
            quality.total = report.size();
            for (const ResolvedAnchor &entry : report)
            {
                switch (entry.status)
                {
                case AnchorStatus::Resolved:
                    ++quality.resolved;
                    break;
                case AnchorStatus::Failed:
                    ++quality.failed;
                    break;
                case AnchorStatus::Unsupported:
                    ++quality.unsupported;
                    break;
                case AnchorStatus::QuorumNotIndependent:
                    ++quality.not_independent;
                    break;
                case AnchorStatus::Unresolved:
                    break;
                }
                // A pinned literal is at-risk regardless of status: it "resolves" but cannot self-heal across a patch.
                if (entry.kind == AnchorKind::Manual)
                {
                    ++quality.manual_at_risk;
                }
                // A corroborated quorum is the strongest evidence: two independent signals had to agree.
                if (entry.kind == AnchorKind::Quorum && entry.status == AnchorStatus::Resolved)
                {
                    ++quality.corroborated;
                }
            }
            return quality;
        }

        std::uint64_t anchor_fingerprint(const Anchor &anchor) noexcept
        {
            if (anchor.kind != AnchorKind::Quorum)
            {
                return fingerprint_evidence(anchor);
            }

            // A quorum's evidence is its two sub-anchors, combined order-independently (the resolver treats the pair
            // symmetrically when checking agreement, so swapping quorum_a / quorum_b must not change the fingerprint).
            // A null sub-anchor -- which fails closed at resolve time -- contributes a fixed sentinel so the result
            // stays defined rather than dereferencing through nullptr.
            constexpr std::uint64_t NULL_SUB_ANCHOR = 0;
            const std::uint64_t fp_a = anchor.quorum_a ? fingerprint_evidence(*anchor.quorum_a) : NULL_SUB_ANCHOR;
            const std::uint64_t fp_b = anchor.quorum_b ? fingerprint_evidence(*anchor.quorum_b) : NULL_SUB_ANCHOR;
            const std::uint64_t lo = fp_a < fp_b ? fp_a : fp_b;
            const std::uint64_t hi = fp_a < fp_b ? fp_b : fp_a;

            std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(AnchorKind::Quorum));
            hash = fnv1a_int(hash, lo);
            hash = fnv1a_int(hash, hi);
            hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.quorum_match));
            hash = fnv1a_int(hash, anchor.quorum_tolerance);
            return hash;
        }

        std::string_view anchor_status_to_string(AnchorStatus status) noexcept
        {
            switch (status)
            {
            case AnchorStatus::Unresolved:
                return "Unresolved";
            case AnchorStatus::Resolved:
                return "Resolved";
            case AnchorStatus::Failed:
                return "Failed";
            case AnchorStatus::Unsupported:
                return "Unsupported";
            case AnchorStatus::QuorumNotIndependent:
                return "QuorumNotIndependent";
            }
            return "Unknown";
        }
    } // namespace anchor
} // namespace DetourModKit
