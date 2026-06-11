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
#include "DetourModKit/rtti.hpp"
#include "DetourModKit/scanner.hpp"

namespace DetourModKit
{
    namespace
    {
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

        // Commits a backend-resolved value, applying the anchor's optional fail-closed validator. On a validator miss
        // the anchor is reported Failed with no value, identical to a backend miss, so the caller re-heals by
        // re-running resolve.
        void commit_resolved(const Anchors::Anchor &anchor, Anchors::ResolvedAnchor &result,
                             std::int64_t value) noexcept
        {
            if (anchor.validator != nullptr && !anchor.validator(value, anchor.validator_context))
            {
                result.status = Anchors::AnchorStatus::Failed;
                result.value = 0;
                return;
            }
            result.value = value;
            result.status = Anchors::AnchorStatus::Resolved;
        }
    } // anonymous namespace

    Anchors::ResolvedAnchor Anchors::resolve(const Anchor &anchor, Memory::ModuleRange range)
    {
        ResolvedAnchor result{};
        result.label = anchor.label;
        result.kind = anchor.kind;
        result.status = AnchorStatus::Unresolved;
        result.value = 0;

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
            const auto hit = Scanner::resolve_cascade_in_module(anchor.site, anchor.label, range);
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
            Scanner::CodeConstant code_constant{};
            code_constant.site = anchor.site;
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
            query.broad_match = anchor.xref_broad_match;
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
            // inspecting the kind.
            result.value = anchor.manual_value;
            result.status = AnchorStatus::Resolved;
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

            const ResolvedAnchor resolved_first = resolve(*first, range);
            const ResolvedAnchor resolved_second = resolve(*second, range);
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
        }
        return "Unknown";
    }
} // namespace DetourModKit
