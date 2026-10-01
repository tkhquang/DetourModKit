#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <limits>
#include <span>
#include <string>

#include "DetourModKit/anchor.hpp"

#include <windows.h>
#include "fixtures/anchor_fixture.hpp"
using namespace dmk_test::anchor_fixture;

TEST(AnchorTest, ExportNameCountsInResolvableDenominator)
{
    // A resolved ExportName is ordinary resolvable evidence: it counts toward the resolved tally and, unlike the
    // unsupported CallArgHome kind, stays in the gate's resolvable denominator.
    const an::ResolvedAnchor report[] = {
        {
            .label = "export",
            .kind = an::AnchorKind::ExportName,
            .status = an::AnchorStatus::Resolved,
            .value = 0x1000,
        },
    };
    const an::AnchorQuality quality = an::assess_quality(report);
    EXPECT_EQ(quality.total, 1U);
    EXPECT_EQ(quality.resolved, 1U);
    EXPECT_EQ(quality.unsupported, 0U);
    EXPECT_EQ(an::evaluate_gate(quality), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, QuorumAmbiguousCountsAsHardFailure)
{
    // A QuorumAmbiguous entry committed no trusted value, so it is a failure the strict default gate rejects.
    const an::ResolvedAnchor report[] = {
        {"resolved", an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved, 1},
        {"ambiguous", an::AnchorKind::Quorum, an::AnchorStatus::QuorumAmbiguous, 0},
    };
    const an::AnchorQuality quality = an::assess_quality(report);
    EXPECT_EQ(quality.failed, 1u);
    EXPECT_EQ(an::evaluate_gate(quality), an::GateVerdict::Fail);
}

// Quality assessment.

TEST(AnchorTest, AssessQualityTalliesReport)
{
    const an::ResolvedAnchor report[] = {
        {"a", an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved, 1},
        {"b", an::AnchorKind::CodeOperand, an::AnchorStatus::Failed, 0},
        {"c", an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported, 0},
        {"d", an::AnchorKind::Manual, an::AnchorStatus::Resolved, 2},
        {"e", an::AnchorKind::Quorum, an::AnchorStatus::Resolved, 3},
        {"f", an::AnchorKind::Quorum, an::AnchorStatus::QuorumNotIndependent, 0},
    };
    const an::AnchorQuality quality = an::assess_quality(report);
    EXPECT_EQ(quality.total, 6u);
    EXPECT_EQ(quality.resolved, 3u);
    EXPECT_EQ(quality.failed, 1u);
    EXPECT_EQ(quality.unsupported, 1u);
    EXPECT_EQ(quality.not_independent, 1u);
    EXPECT_EQ(quality.manual_at_risk, 1u);
    EXPECT_EQ(quality.corroborated, 1u); // only the RESOLVED quorum counts as corroborated
}

// Drift-telemetry gate: assess_quality summary -> GateVerdict startup enable/disable decision.

TEST(AnchorGateTest, AllResolvedPassesDefaultPolicy)
{
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::VtableIdentity, an::AnchorStatus::Resolved)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, FailedAnchorFailsDefaultPolicy)
{
    // Default max_failed is 0, so a single failure disables the feature regardless of how many others resolved.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::CodeOperand, an::AnchorStatus::Failed)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, QuorumNotIndependentCountsAsHardFailure)
{
    // A quorum without independent sub-anchors commits no value. It counts against max_failed like a Failed anchor.
    const std::array<an::ResolvedAnchor, 2> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::Quorum, an::AnchorStatus::QuorumNotIndependent)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, PartialResolveIsGatedByRatio)
{
    // Unresolved slots still count against the resolved ratio.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved)
    };

    // 1/3 < 0.5 -> Fail.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.5,
            }
        ),
        an::GateVerdict::Fail
    );
    // One resolved anchor out of three meets the 0.3 threshold.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.3,
            }
        ),
        an::GateVerdict::Pass
    );
}

TEST(AnchorGateTest, UnsupportedKindExcludedFromDenominator)
{
    // Two resolved plus one CallArgHome (no resolver, always Unsupported). Under the strict default ratio 1.0 the
    // unsupported kind must NOT be counted against the manifest, so 2/2 resolvable resolved -> Pass.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, ResolvedManualDowngradesToDegraded)
{
    // Every anchor resolved, but one is a pinned Manual literal that cannot self-heal: Degraded by default...
    const std::array<an::ResolvedAnchor, 2> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::Manual, an::AnchorStatus::Resolved)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Degraded);
    // ...but a policy that opts out of the manual downgrade treats it as a plain Pass.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .manual_at_risk_degrades = false,
            }
        ),
        an::GateVerdict::Pass
    );
}

TEST(AnchorGateTest, FailedManualStillCountsAtRisk)
{
    // manual_at_risk counts every Manual entry regardless of status: the pin cannot self-heal whether or not it
    // resolved this run. A policy that tolerates the failure therefore lands on Degraded, not Pass.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::Manual, an::AnchorStatus::Failed)
    };
    EXPECT_EQ(an::assess_quality(report).manual_at_risk, 1u);
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.5,
                .max_failed = 1,
            }
        ),
        an::GateVerdict::Degraded
    );
    // Opting out of the manual downgrade restores the tolerated-failure Pass.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.5,
                .max_failed = 1,
                .manual_at_risk_degrades = false,
            }
        ),
        an::GateVerdict::Pass
    );
}

TEST(AnchorGateTest, EmptyReportIsDegraded)
{
    // A report without evidence cannot certify a healthy gate.
    EXPECT_EQ(an::evaluate_gate(std::span<const an::ResolvedAnchor>{}), an::GateVerdict::Degraded);
}

TEST(AnchorGateTest, AllUnsupportedReportIsDegraded)
{
    // A non-empty report with nothing assessable proves nothing about health: Degraded, never a false Pass.
    const std::array<an::ResolvedAnchor, 2> report{
        ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported),
        ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Degraded);
}

TEST(AnchorGateTest, MaxFailedToleratesConfiguredFailures)
{
    // A failure count equal to the cap passes the failure gate. The resolved fraction then decides.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Failed),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Failed)
    };
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.3,
                .max_failed = 2,
            }
        ),
        an::GateVerdict::Pass
    );
    // One below the cap still fails.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.3,
                .max_failed = 1,
            }
        ),
        an::GateVerdict::Fail
    );
}

TEST(AnchorGateTest, OutOfRangeRatioIsClamped)
{
    const std::array<an::ResolvedAnchor, 2> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved)
    };
    // A ratio above 1.0 clamps to 1.0 (still requires every resolvable anchor): 1/2 -> Fail.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 5.0,
            }
        ),
        an::GateVerdict::Fail
    );
    // A negative ratio clamps to 0.0 (any resolved fraction clears it): Pass.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = -1.0,
            }
        ),
        an::GateVerdict::Pass
    );
    // NaN is treated as the strict default, not as a threshold that silently passes every report.
    const an::GatePolicy nan_policy{
        .min_resolved_ratio = std::numeric_limits<double>::quiet_NaN(),
    };
    EXPECT_EQ(an::evaluate_gate(report, nan_policy), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, SpanOverloadMatchesQualityOverload)
{
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::Manual, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::CodeOperand, an::AnchorStatus::Failed)
    };
    const an::GatePolicy policy{
        .min_resolved_ratio = 0.5,
        .max_failed = 1,
    };
    EXPECT_EQ(an::evaluate_gate(report, policy), an::evaluate_gate(an::assess_quality(report), policy));
}

TEST(AnchorGateTest, InconsistentQualitySummaryFailsClosed)
{
    const an::AnchorQuality quality{
        .total = 1,
        .resolved = 2,
    };
    EXPECT_EQ(an::evaluate_gate(quality), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, VerdictToStringMapsEveryVerdict)
{
    EXPECT_EQ(an::gate_verdict_to_string(an::GateVerdict::Pass), "Pass");
    EXPECT_EQ(an::gate_verdict_to_string(an::GateVerdict::Degraded), "Degraded");
    EXPECT_EQ(an::gate_verdict_to_string(an::GateVerdict::Fail), "Fail");
}

TEST(AnchorGateTest, GatesARealResolvedReport)
{
    // End-to-end: resolve a real table (one healthy Manual, one Failed backend anchor whose site is absent), then gate
    // the produced report. The Failed anchor trips the default zero-failure cap, so the feature safe-disables.
    an::Anchor anchors[2]{};
    anchors[0].label = "pinned";
    anchors[0].kind = an::AnchorKind::Manual;
    anchors[0].manual_value = 0x40;
    anchors[1].label = "absent";
    anchors[1].kind = an::AnchorKind::StringXref;
    const std::string absent_text =
        std::string{"dmk-anchor-gate-absent-"} + std::to_string(GetCurrentProcessId()) + "-marker";
    anchors[1].xref_text = absent_text;

    an::ResolvedAnchor report[2]{};
    const std::size_t written = an::resolve_all(anchors, report);
    ASSERT_EQ(written, 2u);
    ASSERT_EQ(report[1].status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::evaluate_gate(std::span<const an::ResolvedAnchor>{report, written}), an::GateVerdict::Fail);
}
