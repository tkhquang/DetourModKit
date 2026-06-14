/**
 * @file anchors.cpp
 * @brief Declarative self-healing anchor registry.
 *
 * Dispatches each anchor to the backend its kind names (reverse-RTTI vtable resolve, AOB/RIP cascade, in-code constant
 * decode, a string-literal xref resolve, or a pinned literal) and reports a uniform value + status, so a consumer
 * declares every magic constant once and resolves the whole table in a single pass. A quorum kind layers corroboration
 * on top, accepting a target only when two independent sub-anchors resolve and agree, and any resolved value may be
 * screened by an optional caller-supplied validator. Every backend already fails closed; this layer only maps their
 * typed failures onto a common status.
 */

#include "DetourModKit/anchors.hpp"

#include "DetourModKit/memory.hpp"
#include "DetourModKit/profile.hpp"
#include "DetourModKit/rtti.hpp"
#include "DetourModKit/scanner.hpp"

#include "fork_join.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <vector>

namespace DetourModKit
{
    namespace
    {
        // Applies the profile's candidate-order preference by building a local reordered span. The caller's candidate
        // table is typically static storage and must not be mutated; the vector owns the temporary copy for the
        // duration of the backend call. AsDeclared returns the original span without allocation.
        [[nodiscard]] std::span<const Scanner::AddrCandidate>
        profiled_candidates(const ScanProfile &profile, std::span<const Scanner::AddrCandidate> site,
                            std::vector<Scanner::AddrCandidate> &ordered)
        {
            if (profile.candidate_order == CandidateOrder::AsDeclared || site.size() < 2)
            {
                return site;
            }

            std::vector<std::size_t> indices(site.size());
            const std::size_t count = order_candidates(profile, site, indices);
            ordered.reserve(count);
            for (std::size_t i = 0; i < count; ++i)
            {
                ordered.push_back(site[indices[i]]);
            }
            return ordered;
        }

        // Fail-closed agreement test for the two quorum signals. A negative tolerance is rejected outright: widening it
        // through unsigned subtraction would turn -1 into a huge bound that accepts almost any gap and defeat the
        // corroboration the quorum exists to provide.
        [[nodiscard]] bool quorum_values_agree(std::int64_t first, std::int64_t second, Anchors::QuorumMatch match,
                                               std::int64_t tolerance) noexcept
        {
            if (match == Anchors::QuorumMatch::ExactValue)
            {
                return first == second;
            }
            if (tolerance < 0)
            {
                return false;
            }
            // Order the pair so the gap is hi - lo, then widen through unsigned subtraction to avoid signed overflow
            // across a large address span.
            const std::int64_t lo = (first < second) ? first : second;
            const std::int64_t hi = (first < second) ? second : first;
            const auto gap = static_cast<std::uint64_t>(hi) - static_cast<std::uint64_t>(lo);
            return gap <= static_cast<std::uint64_t>(tolerance);
        }

        // True when two resolvable sub-anchors share the SAME backend AND the SAME backend inputs, so they would decode
        // the identical site/name/literal and therefore cannot corroborate each other. Compared per kind so only the
        // fields that kind actually consumes participate. View/span comparison is identity over the underlying storage
        // (same data pointer and length), not a deep byte compare: two distinct candidate arrays expressing the same
        // pattern are still two independent scan sites, so only literally-shared storage counts as the same evidence.
        [[nodiscard]] bool same_backend_config(const Anchors::Anchor &a, const Anchors::Anchor &b) noexcept
        {
            if (a.kind != b.kind)
            {
                return false;
            }
            switch (a.kind)
            {
            case Anchors::AnchorKind::VtableIdentity:
                return a.mangled.data() == b.mangled.data() && a.mangled.size() == b.mangled.size();
            case Anchors::AnchorKind::RipGlobal:
                return a.site.data() == b.site.data() && a.site.size() == b.site.size();
            case Anchors::AnchorKind::CodeOperand:
                return a.site.data() == b.site.data() && a.site.size() == b.site.size() &&
                       a.operand_kind == b.operand_kind && a.operand_index == b.operand_index &&
                       a.byte_width == b.byte_width;
            case Anchors::AnchorKind::StringXref:
                return a.xref_text.data() == b.xref_text.data() && a.xref_text.size() == b.xref_text.size() &&
                       a.xref_encoding == b.xref_encoding && a.xref_return == b.xref_return &&
                       a.xref_require_terminator == b.xref_require_terminator &&
                       a.xref_broad_match == b.xref_broad_match;
            case Anchors::AnchorKind::Manual:
            case Anchors::AnchorKind::CallArgHome:
            case Anchors::AnchorKind::Quorum:
                // Handled by dedicated rules: a dual-Manual pair is rejected wholesale, CallArgHome cannot resolve, and
                // a nested Quorum is already rejected upstream. No config-identity verdict is needed here.
                return false;
            }
            return false;
        }

        // Fail-closed independence gate run BEFORE agreement is considered. Two signals are not independent evidence
        // when: (a) they are the exact same Anchor object (pointer-equal); (b) both are Manual literals -- two
        // hand-pinned constants agreeing proves only that the author typed the same number twice, not that the live
        // image corroborates it; or (c) they share backend and inputs (same_backend_config), so they decode one site
        // twice. Any of these would let a dependent pair masquerade as corroboration, defeating the quorum's purpose.
        [[nodiscard]] bool quorum_sub_anchors_independent(const Anchors::Anchor &a, const Anchors::Anchor &b) noexcept
        {
            if (&a == &b)
            {
                return false;
            }
            if (a.kind == Anchors::AnchorKind::Manual && b.kind == Anchors::AnchorKind::Manual)
            {
                return false;
            }
            return !same_backend_config(a, b);
        }

        // Commits a backend-resolved value, applying the anchor's optional fail-closed validator. On a validator miss
        // the anchor is reported Failed with no value, identical to a backend miss, so the caller re-heals by
        // re-running resolve.
        void commit_resolved(const Anchors::Anchor &anchor, Anchors::ResolvedAnchor &result,
                             std::int64_t value) noexcept
        {
            // Opt-in required-validator policy: a backend-resolved (function/global) target with no domain check is
            // treated as unverified and fails closed. A Quorum is exempt -- its two-signal corroboration already is the
            // verification -- so a caller is not forced to also attach a validator to a corroborated anchor.
            if (anchor.require_validator && anchor.kind != Anchors::AnchorKind::Quorum && anchor.validator == nullptr)
            {
                result.status = Anchors::AnchorStatus::Failed;
                result.value = 0;
                return;
            }
            if (anchor.validator != nullptr && !anchor.validator(value, anchor.validator_context))
            {
                result.status = Anchors::AnchorStatus::Failed;
                result.value = 0;
                return;
            }
            result.value = value;
            result.status = Anchors::AnchorStatus::Resolved;
        }

        [[nodiscard]] Anchors::ResolvedAnchor failed_anchor_result(const Anchors::Anchor &anchor) noexcept
        {
            Anchors::ResolvedAnchor result{};
            result.label = anchor.label;
            result.kind = anchor.kind;
            result.status = Anchors::AnchorStatus::Failed;
            result.value = 0;
            return result;
        }

        // FNV-1a 64 evidence hashing for anchor_fingerprint. The fingerprint must be stable across runs and builds so a
        // persisted manifest can be diffed, so integers are folded least-significant-byte first (a fixed order
        // independent of host endianness) and every variable-length field is length-prefixed to keep adjacent fields
        // unambiguous (the literal "ab" then "" cannot collide with "a" then "b").
        inline constexpr std::uint64_t FNV1A64_OFFSET = 14695981039346656037ULL;
        inline constexpr std::uint64_t FNV1A64_PRIME = 1099511628211ULL;

        [[nodiscard]] constexpr std::uint64_t fnv1a_byte(std::uint64_t hash, std::uint8_t value) noexcept
        {
            return (hash ^ value) * FNV1A64_PRIME;
        }

        template <typename T> [[nodiscard]] constexpr std::uint64_t fnv1a_int(std::uint64_t hash, T value) noexcept
        {
            auto bits = static_cast<std::make_unsigned_t<T>>(value);
            for (std::size_t i = 0; i < sizeof(T); ++i)
            {
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(bits & 0xFFu));
                bits >>= 8;
            }
            return hash;
        }

        // Length-prefixed variable-length byte field, so two adjacent variable fields cannot alias one another.
        [[nodiscard]] std::uint64_t fnv1a_field(std::uint64_t hash, std::string_view bytes) noexcept
        {
            hash = fnv1a_int(hash, bytes.size());
            for (const char ch : bytes)
            {
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(ch));
            }
            return hash;
        }

        // Folds a cascade's address-independent evidence: each candidate's pattern text as authored plus its resolve
        // mode, displacement / instruction-length offsets, and uniqueness flag. The pattern is hashed as written rather
        // than re-parsed to canonical bytes -- that keeps the fingerprint allocation-free and total (a malformed
        // pattern still hashes), and a cross-version diff reuses the same static anchor table verbatim, so two textual
        // spellings of one signature never arise in practice. The candidate's cosmetic name is excluded because it
        // never affects which address the cascade resolves.
        [[nodiscard]] std::uint64_t fnv1a_cascade(std::uint64_t hash,
                                                  std::span<const Scanner::AddrCandidate> site) noexcept
        {
            hash = fnv1a_int(hash, site.size());
            for (const Scanner::AddrCandidate &candidate : site)
            {
                hash = fnv1a_field(hash, candidate.pattern);
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(candidate.mode));
                hash = fnv1a_int(hash, static_cast<std::int64_t>(candidate.disp_offset));
                hash = fnv1a_int(hash, static_cast<std::int64_t>(candidate.instr_end_offset));
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(candidate.require_unique));
            }
            return hash;
        }

        // Hashes one anchor's own evidence with no quorum recursion. A Quorum reaching here -- which the public entry
        // point only allows for a malformed sub-anchor, since nesting is rejected at resolve time -- contributes only
        // its kind, which bounds recursion to a single level.
        [[nodiscard]] std::uint64_t fingerprint_evidence(const Anchors::Anchor &anchor) noexcept
        {
            using Anchors::AnchorKind;
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
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.xref_require_terminator));
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.xref_broad_match));
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

    Anchors::ResolvedAnchor Anchors::resolve_with_profile(const Anchor &anchor, const ScanProfile &profile,
                                                          Memory::ModuleRange range)
    {
        ResolvedAnchor result{};
        result.label = anchor.label;
        result.kind = anchor.kind;
        result.status = AnchorStatus::Unresolved;
        result.value = 0;

        // Backend deny-list: a denied kind fails closed before any scan. It is never silently replaced by another
        // backend, which would risk returning a different, wrong target. An empty profile (the default resolve() path)
        // denies nothing, so this is a no-op there.
        if (profile.is_denied(anchor.kind))
        {
            result.status = AnchorStatus::Failed;
            return result;
        }

        switch (anchor.kind)
        {
        case AnchorKind::VtableIdentity:
        {
            const auto vtable = Rtti::vtable_for_type(anchor.mangled, range);
            if (vtable)
            {
                commit_resolved(anchor, result, static_cast<std::int64_t>(*vtable));
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
            // RIP-relative one share this backend.
            std::vector<Scanner::AddrCandidate> ordered_site;
            const auto site = profiled_candidates(profile, anchor.site, ordered_site);
            const auto hit = Scanner::resolve_cascade_in_module(site, anchor.label, range);
            if (hit)
            {
                commit_resolved(anchor, result, static_cast<std::int64_t>(hit->address));
            }
            else
            {
                result.status = AnchorStatus::Failed;
            }
            break;
        }
        case AnchorKind::CodeOperand:
        {
            std::vector<Scanner::AddrCandidate> ordered_site;
            Scanner::CodeConstant code_constant{};
            code_constant.site = profiled_candidates(profile, anchor.site, ordered_site);
            code_constant.kind = anchor.operand_kind;
            code_constant.operand_index = anchor.operand_index;
            code_constant.byte_width = anchor.byte_width;
            const auto constant = Scanner::read_code_constant(code_constant, range);
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
            // references it. The string survives game updates far better than the surrounding code, so this is the most
            // update-resilient backend; it fails closed on a missing, duplicated, or unreferenced string.
            Scanner::StringRefQuery query{};
            query.text = anchor.xref_text;
            query.encoding = anchor.xref_encoding;
            query.require_terminator = anchor.xref_require_terminator;
            query.return_mode = anchor.xref_return;
            // The profile can only widen the broad sweep on (never off); a per-anchor xref_broad_match still wins.
            query.broad_match = anchor.xref_broad_match || profile.default_broad_string_xref;
            const auto site = Scanner::find_string_xref(query, range);
            if (site)
            {
                commit_resolved(anchor, result, static_cast<std::int64_t>(*site));
            }
            else
            {
                result.status = AnchorStatus::Failed;
            }
            break;
        }
        case AnchorKind::Manual:
            // A pinned literal always "resolves"; a report should still flag it as at-risk (it cannot self-heal) by
            // inspecting the kind. By default the validator is skipped (the pinned-literal exemption); a caller that
            // opts in via validate_manual routes the literal through the same fail-closed validator path as a backend.
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
            // declaration (a missing sub-anchor, or a sub-anchor that is itself a Quorum) exactly as the single-signal
            // backends fail closed on ambiguity; rejecting nested Quorum bounds the recursion to one level.
            const Anchor *first = anchor.quorum_a;
            const Anchor *second = anchor.quorum_b;
            if (!first || !second || first->kind == AnchorKind::Quorum || second->kind == AnchorKind::Quorum)
            {
                result.status = AnchorStatus::Failed;
                break;
            }
            // Independence is a static property of the declaration, so check it before the (potentially expensive)
            // recursive resolves. A dependent pair (same object, dual Manual, or same backend + inputs) is not
            // corroboration; report it precisely instead of letting two scans of one site agree and look corroborated.
            if (!quorum_sub_anchors_independent(*first, *second))
            {
                result.status = AnchorStatus::QuorumNotIndependent;
                break;
            }

            // Recurse with the same profile so a denied sub-anchor kind (or a profile broad-default) threads down and a
            // denied signal fails the quorum closed.
            const ResolvedAnchor resolved_first = resolve_with_profile(*first, profile, range);
            const ResolvedAnchor resolved_second = resolve_with_profile(*second, profile, range);
            if (resolved_first.status == AnchorStatus::Resolved && resolved_second.status == AnchorStatus::Resolved &&
                quorum_values_agree(resolved_first.value, resolved_second.value, anchor.quorum_match,
                                    anchor.quorum_tolerance))
            {
                // Both agree under the policy. Commit through the same path as the single-signal backends so the Quorum
                // anchor's own validator runs on the corroborated value (each sub-anchor's validator already ran in its
                // recursive resolve).
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

    Anchors::ResolvedAnchor Anchors::resolve(const Anchor &anchor, Memory::ModuleRange range)
    {
        // An empty profile denies nothing and widens nothing, so this is exactly the un-profiled resolution.
        return resolve_with_profile(anchor, ScanProfile{}, range);
    }

    std::size_t Anchors::resolve_all(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                     Memory::ModuleRange range)
    {
        const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
        for (std::size_t i = 0; i < count; ++i)
        {
            out[i] = resolve(anchors[i], range);
        }
        return count;
    }

    std::size_t Anchors::resolve_all_parallel(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                              Memory::ModuleRange range, std::size_t max_workers)
    {
        const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
        const auto results = DetourModKit::detail::run_fork_join<Anchor, ResolvedAnchor>(
            anchors.first(count), max_workers,
            [range](const Anchor &anchor) -> ResolvedAnchor { return resolve(anchor, range); },
            [](const Anchor &anchor) noexcept -> ResolvedAnchor { return failed_anchor_result(anchor); });

        for (std::size_t i = 0; i < count; ++i)
        {
            out[i] = results[i];
        }
        return count;
    }

    std::size_t Anchors::resolve_all_with_profile(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                                  const ScanProfile &profile, Memory::ModuleRange range)
    {
        const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
        for (std::size_t i = 0; i < count; ++i)
        {
            out[i] = resolve_with_profile(anchors[i], profile, range);
        }
        return count;
    }

    std::size_t Anchors::resolve_all_with_profile_parallel(std::span<const Anchor> anchors,
                                                           std::span<ResolvedAnchor> out, const ScanProfile &profile,
                                                           Memory::ModuleRange range, std::size_t max_workers)
    {
        const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
        const auto results = DetourModKit::detail::run_fork_join<Anchor, ResolvedAnchor>(
            anchors.first(count), max_workers, [&profile, range](const Anchor &anchor) -> ResolvedAnchor
            { return resolve_with_profile(anchor, profile, range); },
            [](const Anchor &anchor) noexcept -> ResolvedAnchor { return failed_anchor_result(anchor); });

        for (std::size_t i = 0; i < count; ++i)
        {
            out[i] = results[i];
        }
        return count;
    }

    Anchors::AnchorQuality Anchors::assess_quality(std::span<const ResolvedAnchor> report) noexcept
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

    std::uint64_t Anchors::anchor_fingerprint(const Anchor &anchor) noexcept
    {
        if (anchor.kind != AnchorKind::Quorum)
        {
            return fingerprint_evidence(anchor);
        }

        // A quorum's evidence is its two sub-anchors, combined order-independently (the resolver treats the pair
        // symmetrically when checking agreement, so swapping quorum_a / quorum_b must not change the fingerprint). A
        // null sub-anchor -- which fails closed at resolve time -- contributes a fixed sentinel so the result stays
        // defined rather than dereferencing through nullptr.
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

    std::string_view Anchors::anchor_status_to_string(AnchorStatus status) noexcept
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
} // namespace DetourModKit
