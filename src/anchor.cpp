/**
 * @file anchor.cpp
 * @brief The declarative anchor registry: dispatches each anchor kind to its v4 backend and reports drift uniformly.
 * @details Every kind maps onto exactly one self-healing backend that already fails closed:
 *          - VtableIdentity -> rtti::vtable_for_type (reverse-RTTI vtable resolve),
 *          - RipGlobal      -> scan::resolve         (Direct / RIP-relative candidate cascade),
 *          - CodeOperand    -> scan::read_code_constant (in-code immediate / displacement decode),
 *          - StringXref     -> scan::find_string_xref (string-literal cross-reference resolve),
 *          - Manual         -> a pinned literal (no backend),
 *          - Quorum         -> N-of-M voting across independent sub-anchors,
 *          - CallArgHome    -> reserved (no resolver yet).
 *          This layer adds no scanning of its own: it maps each backend's typed failure onto the common
 *          AnchorStatus and threads the optional post-resolve validator and the per-game ScanProfile defaults.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/rtti.hpp"

#include "fork_join.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <span>
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

            // The independence evidence hash, defined below with the other fingerprint machinery. Declared here so the
            // independence gate can compare two members by CONTENT rather than by the storage identity of their views.
            [[nodiscard]] std::uint64_t fingerprint_independence_evidence(const Anchor &anchor) noexcept;

            // True when two resolvable sub-anchors are the SAME evidence -- same backend fed the same inputs, so they
            // would decode the identical site/name/literal and therefore cannot corroborate each other. Compared by
            // CONTENT, not by view/span storage identity: two distinct candidate arrays that compile to byte-identical
            // patterns (or two copies of the same mangled name / literal in separate buffers) still decode one
            // identical site, so they must count as dependent. It uses fingerprint_INDEPENDENCE_evidence, whose ladder
            // fold is order-INDEPENDENT: two members that list the same fallback rungs in a different order still decode
            // the same site, so a reordered copy must not masquerade as independent corroboration (the drift
            // fingerprint stays order-sensitive on purpose -- reordering a ladder IS a signature change). It folds the
            // kind byte, so a cross-kind pair never collides; the fail-closed direction is a ~2^-64 hash collision
            // rejecting a genuinely-independent pair (the quorum then fails closed, never open).
            [[nodiscard]] bool same_backend_config(const Anchor &a, const Anchor &b) noexcept
            {
                if (a.kind != b.kind)
                {
                    return false;
                }
                return fingerprint_independence_evidence(a) == fingerprint_independence_evidence(b);
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

            // Checks the M members of an N-of-M vote: EVERY pair must be independent evidence. N-of-M only corroborates
            // when no member duplicates another, so a single dependent pair taints the whole vote (one site could be
            // counted twice toward the threshold). This is also what confines a WithinTolerance quorum -- whose votes
            // need only be near, not equal -- to content-independent members, so a cluster of near values can never be
            // an artifact of two members reading adjacent bytes of one site. The caller guarantees no member pointer is
            // null before this runs. O(M^2) over a tiny declared M.
            [[nodiscard]] bool quorum_members_pairwise_independent(std::span<const Anchor *const> members) noexcept
            {
                for (std::size_t i = 0; i < members.size(); ++i)
                {
                    for (std::size_t j = i + 1; j < members.size(); ++j)
                    {
                        if (!quorum_sub_anchors_independent(*members[i], *members[j]))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }

            // Counts how many of the cast votes agree with a candidate cluster-center value under the match policy,
            // reusing the same fail-closed pairwise agreement test. A quorum accepts when some member's value anchors a
            // cluster of at least N agreeing votes. Under a negative WithinTolerance the pairwise test rejects even the
            // center against itself, so every cluster is empty and the quorum fails closed, as intended.
            [[nodiscard]] std::size_t votes_agreeing_with(std::int64_t center, std::span<const std::int64_t> votes,
                                                          QuorumMatch match, std::int64_t tolerance) noexcept
            {
                std::size_t agree = 0;
                for (const std::int64_t vote : votes)
                {
                    if (quorum_values_agree(center, vote, match, tolerance))
                    {
                        ++agree;
                    }
                }
                return agree;
            }

            // Commits a backend-resolved value, applying the anchor's optional fail-closed validator. On a validator
            // miss the anchor is reported Failed with no value, identical to a backend miss, so the caller re-heals by
            // re-running resolve.
            void commit_resolved(const Anchor &anchor, ResolvedAnchor &result, std::int64_t value) noexcept
            {
                // Opt-in required-validator policy: a backend-resolved (function/global) target with no domain check is
                // treated as unverified and fails closed. Manual and Quorum are both exempt -- a pinned Manual literal
                // is not a resolved target (require_validator is a backend-target policy, and a Manual only reaches
                // this path at all via validate_manual), and a Quorum's N-of-M corroboration is already the
                // verification. Only the four backend kinds reach this rejection.
                if (anchor.require_validator && anchor.kind != AnchorKind::Quorum &&
                    anchor.kind != AnchorKind::Manual && anchor.validator == nullptr)
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

            [[nodiscard]] double clamped_gate_ratio(double ratio) noexcept
            {
                if (std::isnan(ratio))
                {
                    return 1.0;
                }
                if (ratio < 0.0)
                {
                    return 0.0;
                }
                if (ratio > 1.0)
                {
                    return 1.0;
                }
                return ratio;
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

            // Hashes one candidate's address-independent CONTENT. scan::Pattern is compiled and does not retain its
            // source string, so the byte tiers hash the compiled bytes + wildcard mask + result-offset plus the decode
            // parameters -- content that is stable across a diff and computable without re-parsing. The text tiers hash
            // their owned name / literal and shape flags directly.
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

            // Order-INDEPENDENT cascade digest for the quorum independence gate: a fallback ladder's rungs all aim at
            // the same target, so two members listing the same rungs in a different order decode the same site and are
            // dependent evidence. Each candidate is hashed from a fixed seed, then the per-candidate hashes are combined
            // COMMUTATIVELY (a sum, so reordering cannot change the result); the candidate count is folded so a subset
            // never collides with a superset. Kept SEPARATE from fnv1a_cascade because the drift fingerprint stays
            // order-sensitive on purpose (reordering a ladder is a signature change worth reporting as drift).
            [[nodiscard]] std::uint64_t fnv1a_cascade_unordered(std::uint64_t hash,
                                                                std::span<const scan::Candidate> site) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(site.size()));
                std::uint64_t combined = 0;
                for (const scan::Candidate &candidate : site)
                {
                    combined += fnv1a_candidate(FNV1A64_OFFSET, candidate);
                }
                return fnv1a_int(hash, combined);
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
                case AnchorKind::Unset:
                    // No address-independent evidence beyond the kind byte already folded above.
                    break;
                }
                return hash;
            }

            // fingerprint_evidence with an order-INDEPENDENT ladder fold, used ONLY by the quorum independence gate.
            // Every tier except the RipGlobal / CodeOperand ladder has no ordered component, so those delegate straight
            // to fingerprint_evidence; only the two ladder tiers swap fnv1a_cascade for fnv1a_cascade_unordered so a
            // reordered copy of the same rungs hashes identically. The drift fingerprint (anchor_fingerprint /
            // fingerprint_evidence) is deliberately left untouched, so detection still reports a reordered ladder as a
            // changed signature.
            [[nodiscard]] std::uint64_t fingerprint_independence_evidence(const Anchor &anchor) noexcept
            {
                if (anchor.kind != AnchorKind::RipGlobal && anchor.kind != AnchorKind::CodeOperand)
                {
                    return fingerprint_evidence(anchor);
                }
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(anchor.kind));
                hash = fnv1a_cascade_unordered(hash, anchor.site);
                if (anchor.kind == AnchorKind::CodeOperand)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.operand_kind));
                    hash = fnv1a_byte(hash, anchor.operand_index);
                    hash = fnv1a_byte(hash, anchor.byte_width);
                }
                return hash;
            }

            constexpr std::uint64_t NULL_SUB_ANCHOR = 0;

            [[nodiscard]] std::uint64_t quorum_member_evidence(const Anchor *member) noexcept
            {
                return member != nullptr ? fingerprint_evidence(*member) : NULL_SUB_ANCHOR;
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
                // A critical target accepts only when at least N of its M candidate signals independently resolve and
                // agree (N-of-M voting). Corroboration this way survives a patch that breaks some of the M signals as
                // long as N of them still agree, which no single backend can. Fail closed on a malformed declaration
                // exactly as the single-signal backends fail closed on ambiguity.
                const std::span<const Anchor *const> members = anchor.quorum_members;

                // A quorum needs at least two members to corroborate; a null member or a member that is itself a Quorum
                // is malformed (rejecting nested Quorum bounds recursion to one level).
                if (members.size() < 2)
                {
                    result.status = AnchorStatus::Failed;
                    break;
                }
                const bool malformed_member =
                    std::any_of(members.begin(), members.end(), [](const Anchor *member) noexcept
                                { return member == nullptr || member->kind == AnchorKind::Quorum; });
                if (malformed_member)
                {
                    result.status = AnchorStatus::Failed;
                    break;
                }

                // Effective N: 0 means unanimous (all members), so a default two-member quorum is the strict 2-of-2.
                // A quorum is corroboration, so an explicit N below 2 or above the member count is a malformed vote and
                // fails closed rather than silently degrading to a single signal.
                const std::size_t threshold = (anchor.quorum_threshold == 0) ? members.size() : anchor.quorum_threshold;
                if (threshold < 2 || threshold > members.size())
                {
                    result.status = AnchorStatus::Failed;
                    break;
                }

                // Independence is a static property of the declaration, so check it before the (potentially expensive)
                // recursive resolves. Every member must be independent of every other; one dependent pair means the
                // vote could count a single site twice, so report it precisely instead of letting it look corroborated.
                if (!quorum_members_pairwise_independent(members))
                {
                    result.status = AnchorStatus::QuorumNotIndependent;
                    break;
                }

                // Resolve each member with the same profile so a denied sub-anchor kind (or a profile broad-default)
                // threads down; only a member that resolves casts a vote. A member that fails contributes nothing
                // rather than vetoing the vote -- that is the whole point of N-of-M: the target still corroborates when
                // one of several independent signals breaks on a patch, so long as N of the rest agree.
                std::vector<std::int64_t> votes;
                votes.reserve(members.size());
                for (const Anchor *member : members)
                {
                    const ResolvedAnchor resolved_member = resolve_with_profile(*member, profile, scope);
                    if (resolved_member.status == AnchorStatus::Resolved)
                    {
                        votes.push_back(resolved_member.value);
                    }
                }

                // Accept if some member's value anchors an agreement cluster of at least N votes. Scanning the votes in
                // declaration order and committing the first qualifying center keeps the corroborated value
                // deterministic: for ExactValue every cluster member shares the value; for WithinTolerance it is the
                // cluster center, within tolerance of the rest. Commit through the shared path so the Quorum's own
                // validator runs on that value (each member's validator already ran in its recursive resolve).
                bool corroborated = false;
                for (const std::int64_t center : votes)
                {
                    if (votes_agreeing_with(center, votes, anchor.quorum_match, anchor.quorum_tolerance) >= threshold)
                    {
                        commit_resolved(anchor, result, center);
                        corroborated = true;
                        break;
                    }
                }
                if (!corroborated)
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::Unset:
                // A default-constructed anchor whose kind was never set. There is no backend to resolve and no value to
                // trust, so fail closed rather than invent one -- this is the whole reason Unset exists.
                result.status = AnchorStatus::Failed;
                break;
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
                // A corroborated quorum is the strongest evidence: N independent signals had to agree.
                if (entry.kind == AnchorKind::Quorum && entry.status == AnchorStatus::Resolved)
                {
                    ++quality.corroborated;
                }
            }
            return quality;
        }

        GateVerdict evaluate_gate(const AnchorQuality &quality, const GatePolicy &policy) noexcept
        {
            // The span overload always feeds a self-consistent summary, but the direct AnchorQuality overload is
            // public. If a caller supplies impossible counts, fail closed rather than letting an inflated resolved
            // count create a healthy verdict.
            std::size_t accounted = 0;
            const auto count_fits = [&accounted, total = quality.total](std::size_t count) noexcept -> bool
            {
                if (count > total - accounted)
                {
                    return false;
                }
                accounted += count;
                return true;
            };
            if (!count_fits(quality.resolved) || !count_fits(quality.failed) || !count_fits(quality.unsupported) ||
                !count_fits(quality.not_independent))
            {
                return GateVerdict::Fail;
            }

            // A QuorumNotIndependent outcome committed no value (it fails closed exactly like a backend miss), so it
            // counts as a failure alongside Failed for the cap: both mean an anchor the manifest declared did not yield
            // a verified value. Check the hard cap first so a manifest riddled with failures fails the gate even if the
            // few that did resolve happen to clear the ratio.
            if (quality.failed > policy.max_failed)
            {
                return GateVerdict::Fail;
            }
            const std::size_t remaining_failure_budget = policy.max_failed - quality.failed;
            if (quality.not_independent > remaining_failure_budget)
            {
                return GateVerdict::Fail;
            }

            // Resolvable excludes the Unsupported (CallArgHome) kind: it has no backend and can never heal, so folding
            // it into the denominator would permanently penalize a manifest that merely declares a forward-compatible
            // kind. Everything else that could have resolved but did not -- Failed, QuorumNotIndependent, and any
            // untouched Unresolved slot (e.g. a caller that gated the whole output buffer instead of the written
            // prefix) -- stays in the denominator, so a partial resolve drags the ratio down and fails closed rather
            // than flattering the resolved count.
            const std::size_t resolvable = quality.total - quality.unsupported;
            if (resolvable == 0)
            {
                // Nothing assessable proves nothing about runtime health: an empty report or an all-unsupported table
                // should not become a healthy Pass merely because there were no resolvable anchors to contradict it.
                return GateVerdict::Degraded;
            }

            // Clamp a caller-supplied ratio to [0, 1] so an out-of-range value cannot invert the comparison. NaN is
            // treated as the strict default rather than as a threshold that never compares true. Test resolved >= ratio
            // * resolvable as `resolved < ratio * resolvable` to fail closed. The comparison avoids division so the
            // exact-full case (ratio 1.0, every resolvable anchor resolved) stays an exact floating-point equality.
            const double ratio = clamped_gate_ratio(policy.min_resolved_ratio);
            if (static_cast<double>(quality.resolved) < ratio * static_cast<double>(resolvable))
            {
                return GateVerdict::Fail;
            }

            // Cleared the hard thresholds. A pinned Manual literal resolved but cannot self-heal, so surface it as a
            // soft risk when the policy asks: the feature can run, but the caller should log that a manual offset is
            // load-bearing and will silently drift on the next patch.
            if (policy.manual_at_risk_degrades && quality.manual_at_risk > 0)
            {
                return GateVerdict::Degraded;
            }
            return GateVerdict::Pass;
        }

        GateVerdict evaluate_gate(std::span<const ResolvedAnchor> report, const GatePolicy &policy) noexcept
        {
            return evaluate_gate(assess_quality(report), policy);
        }

        std::uint64_t anchor_fingerprint(const Anchor &anchor) noexcept
        {
            if (anchor.kind != AnchorKind::Quorum)
            {
                return fingerprint_evidence(anchor);
            }

            // A quorum's evidence is the combined evidence of its M members, folded order-independently (voting is
            // symmetric, so reordering the members must not change the fingerprint) plus the effective vote threshold
            // and agreement policy. The per-member evidence hashes are emitted in sorted order without allocating: each
            // pass finds the next larger evidence value and folds all duplicates of that value. A null member -- which
            // fails closed at resolve time -- contributes a fixed sentinel so the result stays defined rather than
            // dereferencing through nullptr.
            const std::span<const Anchor *const> members = anchor.quorum_members;

            std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(AnchorKind::Quorum));
            hash = fnv1a_int(hash, static_cast<std::uint64_t>(members.size()));

            std::uint64_t previous = 0;
            bool have_previous = false;
            std::size_t emitted = 0;
            while (emitted < members.size())
            {
                std::uint64_t next = 0;
                bool found_next = false;
                for (const Anchor *member : members)
                {
                    const std::uint64_t evidence = quorum_member_evidence(member);
                    if (have_previous && evidence <= previous)
                    {
                        continue;
                    }
                    if (!found_next || evidence < next)
                    {
                        next = evidence;
                        found_next = true;
                    }
                }

                if (!found_next)
                {
                    break;
                }

                std::size_t duplicate_count = 0;
                for (const Anchor *member : members)
                {
                    if (quorum_member_evidence(member) == next)
                    {
                        ++duplicate_count;
                    }
                }
                for (std::size_t i = 0; i < duplicate_count; ++i)
                {
                    hash = fnv1a_int(hash, next);
                }

                previous = next;
                have_previous = true;
                emitted += duplicate_count;
            }
            const std::size_t effective_threshold =
                (anchor.quorum_threshold == 0) ? members.size() : anchor.quorum_threshold;
            hash = fnv1a_int(hash, static_cast<std::uint64_t>(effective_threshold));
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

        std::string_view gate_verdict_to_string(GateVerdict verdict) noexcept
        {
            switch (verdict)
            {
            case GateVerdict::Pass:
                return "Pass";
            case GateVerdict::Degraded:
                return "Degraded";
            case GateVerdict::Fail:
                return "Fail";
            }
            return "Unknown";
        }
    } // namespace anchor
} // namespace DetourModKit
