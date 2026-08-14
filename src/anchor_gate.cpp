/**
 * @file anchor_gate.cpp
 * @brief This TU owns the anchor quality summary, the launch gate verdict, and the report string tables.
 *
 * It consumes only the public ResolvedAnchor vocabulary. The resolution engine stays in anchor.cpp and the drift
 * fingerprints in anchor_evidence.cpp.
 */

#include "DetourModKit/anchor.hpp"

#include <cmath>
#include <cstddef>
#include <span>
#include <string_view>

namespace DetourModKit
{
    namespace anchor
    {
        namespace
        {
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
        } // anonymous namespace

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
                case AnchorStatus::QuorumAmbiguous:
                    // This status commits no trusted value, so it is a failure alongside a backend miss.
                    ++quality.failed;
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
            // public. If a caller supplies impossible counts, fail closed so an inflated resolved count cannot create
            // a healthy verdict.
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

            // QuorumNotIndependent counts as a failure alongside Failed for the cap: both mean a declared anchor
            // yielded no verified value. Check the hard cap before the ratio. A failure-heavy manifest then fails even
            // when its few resolved entries clear the ratio.
            if (quality.failed > policy.max_failed)
            {
                return GateVerdict::Fail;
            }
            const std::size_t remaining_failure_budget = policy.max_failed - quality.failed;
            if (quality.not_independent > remaining_failure_budget)
            {
                return GateVerdict::Fail;
            }

            // Resolvable excludes the Unsupported kind, which has no backend and can never heal. Every other unresolved
            // kind stays in the denominator. A partial result therefore reduces the ratio and fails closed.
            const std::size_t resolvable = quality.total - quality.unsupported;
            if (resolvable == 0)
            {
                // No assessable entry proves runtime health. An empty report or all-unsupported table must
                // not become a healthy Pass merely because no resolvable anchor contradicts it.
                return GateVerdict::Degraded;
            }

            // Clamp the ratio to [0, 1]. NaN becomes the strict default. This prevents an out-of-range value from
            // inversion of the comparison. Avoid division so the full-ratio case retains exact equality.
            const double ratio = clamped_gate_ratio(policy.min_resolved_ratio);
            if (static_cast<double>(quality.resolved) < ratio * static_cast<double>(resolvable))
            {
                return GateVerdict::Fail;
            }

            // A resolved Manual literal remains unable to self-heal. If policy requests it, surface this soft risk so
            // the caller can report silent manual offset drift after a patch.
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
            case AnchorStatus::QuorumAmbiguous:
                return "QuorumAmbiguous";
            }
            return "Unknown";
        }

        std::string_view result_domain_to_string(ResultDomain domain) noexcept
        {
            switch (domain)
            {
            case ResultDomain::Unknown:
                return "Unknown";
            case ResultDomain::CodeSite:
                return "CodeSite";
            case ResultDomain::DataAddress:
                return "DataAddress";
            case ResultDomain::VtableAddress:
                return "VtableAddress";
            case ResultDomain::Scalar:
                return "Scalar";
            }
            return "Unknown";
        }

        std::string_view physical_source_to_string(PhysicalSource source) noexcept
        {
            switch (source)
            {
            case PhysicalSource::None:
                return "None";
            case PhysicalSource::ByteSignature:
                return "ByteSignature";
            case PhysicalSource::StringLiteral:
                return "StringLiteral";
            case PhysicalSource::TypeIdentity:
                return "TypeIdentity";
            case PhysicalSource::ExportTable:
                return "ExportTable";
            case PhysicalSource::CodeOperand:
                return "CodeOperand";
            case PhysicalSource::ManualPin:
                return "ManualPin";
            case PhysicalSource::Corroborated:
                return "Corroborated";
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
