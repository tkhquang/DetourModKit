/**
 * @file anchors.cpp
 * @brief Declarative self-healing anchor registry.
 *
 * Dispatches each anchor to the backend its kind names (reverse-RTTI vtable
 * resolve, AOB/RIP cascade, in-code constant decode, or a pinned literal) and
 * reports a uniform value + status, so a consumer declares every magic constant
 * once and resolves the whole table in a single pass. Every backend already
 * fails closed; this layer only maps their typed failures onto a common status.
 */

#include "DetourModKit/anchors.hpp"

#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"
#include "DetourModKit/scanner.hpp"

namespace DetourModKit
{
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
                result.value = static_cast<std::int64_t>(*vtable);
                result.status = AnchorStatus::Resolved;
            }
            else
            {
                result.status = AnchorStatus::Failed;
            }
            break;
        }
        case AnchorKind::RipGlobal:
        {
            // The cascade itself selects Direct vs RIP-relative per candidate, so
            // a plain global address and a RIP-relative one share this backend.
            const auto hit = Scanner::resolve_cascade_in_module(anchor.site, anchor.label, range);
            if (hit)
            {
                result.value = static_cast<std::int64_t>(hit->address);
                result.status = AnchorStatus::Resolved;
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
                result.value = *constant;
                result.status = AnchorStatus::Resolved;
            }
            else
            {
                result.status = AnchorStatus::Failed;
            }
            break;
        }
        case AnchorKind::Manual:
            // A pinned literal always "resolves"; a report should still flag it as
            // at-risk (it cannot self-heal) by inspecting the kind.
            result.value = anchor.manual_value;
            result.status = AnchorStatus::Resolved;
            break;
        case AnchorKind::CallArgHome:
            // Reserved for a future prologue-dataflow backend; no resolver yet.
            result.status = AnchorStatus::Unsupported;
            break;
        }

        return result;
    }

    std::size_t Anchors::resolve_all(std::span<const Anchor> anchors,
                                     std::span<ResolvedAnchor> out, Memory::ModuleRange range)
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
