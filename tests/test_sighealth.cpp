#include <gtest/gtest.h>

#include <algorithm>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/manifest.hpp"
#include "DetourModKit/scan.hpp"
#include "DetourModKit/sighealth.hpp"

namespace sh = DetourModKit::sighealth;
namespace sc = DetourModKit::scan;
namespace mf = DetourModKit::manifest;
namespace an = DetourModKit::anchor;

namespace
{
    // Compile a runtime AOB the way the resolver would; the fixtures below are all well-formed, so an unwrap is safe.
    [[nodiscard]] sc::Pattern make_pattern(std::string_view dsl)
    {
        auto compiled = sc::Pattern::compile(dsl);
        EXPECT_TRUE(compiled.has_value()) << "test fixture pattern failed to compile: " << dsl;
        return *compiled;
    }

    // Ladder-rung builders. CandidateSpec is a wide aggregate whose fields default per active mode; construct one field
    // at a time (the manifest tests' idiom) rather than a designated-initializer list so an omitted trailing member is
    // never a -Wmissing-field-initializers warning.
    [[nodiscard]] mf::CandidateSpec direct_rung(std::string pattern)
    {
        mf::CandidateSpec spec;
        spec.mode = sc::Mode::Direct;
        spec.pattern = std::move(pattern);
        return spec;
    }

    [[nodiscard]] mf::CandidateSpec string_rung(std::string text)
    {
        mf::CandidateSpec spec;
        spec.mode = sc::Mode::StringXref;
        spec.string_text = std::move(text);
        return spec;
    }

    [[nodiscard]] mf::CandidateSpec rtti_rung(std::string mangled)
    {
        mf::CandidateSpec spec;
        spec.mode = sc::Mode::RttiVtable;
        spec.mangled = std::move(mangled);
        return spec;
    }

    [[nodiscard]] bool has_finding(const std::vector<sh::Finding> &findings, sh::FindingKind kind)
    {
        return std::any_of(findings.begin(), findings.end(), [kind](const sh::Finding &f) { return f.kind == kind; });
    }

    // Returns the severity of the first finding of the given kind, or nullopt when absent. An optional (rather than a
    // sentinel severity) so an assertion on an absent finding fails loudly instead of silently matching a fallback.
    [[nodiscard]] std::optional<sh::Severity> severity_of(const std::vector<sh::Finding> &findings,
                                                          sh::FindingKind kind)
    {
        for (const sh::Finding &f : findings)
        {
            if (f.kind == kind)
            {
                return f.severity;
            }
        }
        return std::nullopt;
    }
} // namespace

// Pattern-level analysis

TEST(SigHealthPattern, LongRareByteRunGradesRobustWithNoFindings)
{
    // Six distinct, rare (frequency-class-0) bytes: a long fully-known atom that is effectively unique in any module.
    const sh::PatternHealth health = sh::analyze_pattern(make_pattern("11 22 33 44 55 66"));

    EXPECT_EQ(health.grade, sh::Grade::Robust);
    EXPECT_TRUE(health.findings.empty());
    EXPECT_EQ(health.length, 6u);
    EXPECT_EQ(health.fixed_bytes, 6u);
    EXPECT_EQ(health.wildcard_bytes, 0u);
    EXPECT_EQ(health.atom_count, 1u);
    EXPECT_EQ(health.longest_atom, 6u);
    EXPECT_FALSE(health.common_bytes_only);
    EXPECT_LT(health.expected_matches, 1.0);
}

TEST(SigHealthPattern, AllWildcardHasNoAnchorAndIsUnusable)
{
    const sh::PatternHealth health = sh::analyze_pattern(make_pattern("?? ?? ?? ??"));

    EXPECT_EQ(health.grade, sh::Grade::Unusable);
    EXPECT_EQ(health.fixed_bytes, 0u);
    EXPECT_EQ(health.wildcard_bytes, 4u);
    EXPECT_EQ(health.longest_atom, 0u);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::NoFixedAnchor));
    EXPECT_EQ(severity_of(health.findings, sh::FindingKind::NoFixedAnchor), sh::Severity::Critical);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::HighWildcardRatio));
    // Zero selectivity means every window is a candidate: the estimate is the whole nominal haystack.
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::WeakSelectivity));
    EXPECT_FALSE(health.common_bytes_only);
}

TEST(SigHealthPattern, RepetitiveCommonBytesTripEntropyAndRarity)
{
    // Six identical 0x90 (NOP) bytes: long in bytes, near-zero information, all common.
    const sh::PatternHealth health = sh::analyze_pattern(make_pattern("90 90 90 90 90 90"));

    EXPECT_TRUE(health.common_bytes_only);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::CommonBytesOnly));
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::LowByteEntropy));
    EXPECT_DOUBLE_EQ(health.byte_entropy_bits, 0.0);
    EXPECT_NE(health.grade, sh::Grade::Robust);
}

TEST(SigHealthPattern, ShortCommonAnchorIsWeaklySelective)
{
    // A three-byte lead many functions share; only 0x05 is rare, so it is far too short to be unique.
    const sh::PatternHealth health = sh::analyze_pattern(make_pattern("48 8B 05"));

    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::ShortPattern));
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::ShortestAnchorRun));
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::WeakSelectivity));
    EXPECT_GT(health.expected_matches, 1.0);
    // 0x05 is a rare byte, so the pattern is not flagged as common-bytes-only despite 0x48 / 0x8B being common.
    EXPECT_FALSE(health.common_bytes_only);
}

TEST(SigHealthPattern, AtomAndNibbleAccountingIsExact)
{
    // 48 8B  ??  05 05  -> two fully-known runs of length two, one full wildcard between them.
    const sh::PatternHealth health = sh::analyze_pattern(make_pattern("48 8B ?? 05 05"));

    EXPECT_EQ(health.length, 5u);
    EXPECT_EQ(health.fixed_bytes, 4u);
    EXPECT_EQ(health.wildcard_bytes, 1u);
    EXPECT_EQ(health.nibble_bytes, 0u);
    EXPECT_EQ(health.atom_count, 2u);
    EXPECT_EQ(health.longest_atom, 2u);

    // A half-known nibble is neither a fixed byte nor a full wildcard.
    const sh::PatternHealth nibble = sh::analyze_pattern(make_pattern("4? 8B"));
    EXPECT_EQ(nibble.fixed_bytes, 1u);
    EXPECT_EQ(nibble.nibble_bytes, 1u);
    EXPECT_EQ(nibble.wildcard_bytes, 0u);
}

TEST(SigHealthPattern, TrailingFixedRunIsCounted)
{
    // The final atom must be closed at the end of the pattern, not only when a non-fixed byte follows it.
    const sh::PatternHealth health = sh::analyze_pattern(make_pattern("?? 11 22 33"));
    EXPECT_EQ(health.atom_count, 1u);
    EXPECT_EQ(health.longest_atom, 3u);
}

// Policy knobs

TEST(SigHealthPolicy, LargerHaystackRaisesExpectedMatches)
{
    const sc::Pattern pattern = make_pattern("11 22 33 44");

    sh::HealthPolicy small;
    small.nominal_haystack_bytes = 1u * 1024u * 1024u;
    sh::HealthPolicy large;
    large.nominal_haystack_bytes = 256u * 1024u * 1024u;

    const sh::PatternHealth small_health = sh::analyze_pattern(pattern, small);
    const sh::PatternHealth large_health = sh::analyze_pattern(pattern, large);

    // Same selectivity, bigger haystack: strictly more expected false matches.
    EXPECT_DOUBLE_EQ(small_health.selectivity_bits, large_health.selectivity_bits);
    EXPECT_GT(large_health.expected_matches, small_health.expected_matches);
}

TEST(SigHealthPolicy, TighterMinLengthFlagsAnOtherwisePassingPattern)
{
    const sc::Pattern pattern = make_pattern("11 22 33 44 55 66");

    // Default floor (5) is satisfied by a six-byte pattern.
    EXPECT_FALSE(has_finding(sh::analyze_pattern(pattern).findings, sh::FindingKind::ShortPattern));

    sh::HealthPolicy strict;
    strict.min_pattern_bytes = 8;
    EXPECT_TRUE(has_finding(sh::analyze_pattern(pattern, strict).findings, sh::FindingKind::ShortPattern));
}

TEST(SigHealthPolicy, WeakSelectivityEscalatesAcrossTheThresholds)
{
    // "48 8B 05" draws thousands of estimated matches, far past both defaults, so by default it is a Critical.
    const sc::Pattern weak = make_pattern("48 8B 05");
    const sh::PatternHealth strict = sh::analyze_pattern(weak);
    ASSERT_TRUE(has_finding(strict.findings, sh::FindingKind::WeakSelectivity));
    EXPECT_EQ(severity_of(strict.findings, sh::FindingKind::WeakSelectivity), sh::Severity::Critical);

    // Raise the fail threshold above the estimate: the same pattern is now only past the warn threshold -> Warning.
    sh::HealthPolicy warn_only;
    warn_only.fail_expected_matches = 1e12;
    const sh::PatternHealth warned = sh::analyze_pattern(weak, warn_only);
    ASSERT_TRUE(has_finding(warned.findings, sh::FindingKind::WeakSelectivity));
    EXPECT_EQ(severity_of(warned.findings, sh::FindingKind::WeakSelectivity), sh::Severity::Warning);

    // Raise the warn threshold above the estimate too: WeakSelectivity no longer fires at all.
    sh::HealthPolicy lax;
    lax.warn_expected_matches = 1e12;
    lax.fail_expected_matches = 1e12;
    EXPECT_FALSE(has_finding(sh::analyze_pattern(weak, lax).findings, sh::FindingKind::WeakSelectivity));
}

TEST(SigHealthPolicy, WildcardAndAtomKnobsMoveTheirBoundaries)
{
    // min_longest_atom: a six-byte fully-known run clears the default floor (4) but trips a raised one.
    const sc::Pattern solid = make_pattern("11 22 33 44 55 66");
    EXPECT_FALSE(has_finding(sh::analyze_pattern(solid).findings, sh::FindingKind::ShortestAnchorRun));
    sh::HealthPolicy long_atom;
    long_atom.min_longest_atom = 8;
    EXPECT_TRUE(has_finding(sh::analyze_pattern(solid, long_atom).findings, sh::FindingKind::ShortestAnchorRun));

    // max_wildcard_ratio: a one-third-wildcard pattern clears the default ceiling (0.6) but trips a lowered one.
    const sc::Pattern gappy = make_pattern("11 22 33 44 ?? ??");
    EXPECT_FALSE(has_finding(sh::analyze_pattern(gappy).findings, sh::FindingKind::HighWildcardRatio));
    sh::HealthPolicy tight_wild;
    tight_wild.max_wildcard_ratio = 0.2;
    EXPECT_TRUE(has_finding(sh::analyze_pattern(gappy, tight_wild).findings, sh::FindingKind::HighWildcardRatio));
}

// Candidate (ladder rung) analysis

TEST(SigHealthCandidate, ByteRungMirrorsPatternAnalysis)
{
    const sh::CandidateHealth health = sh::analyze_candidate(direct_rung("11 22 33 44 55 66"));

    EXPECT_TRUE(health.compiled);
    EXPECT_EQ(health.grade, sh::Grade::Robust);
    EXPECT_EQ(health.pattern.longest_atom, 6u);
    EXPECT_TRUE(health.findings.empty());
}

TEST(SigHealthCandidate, UncompilableByteRungIsUnusable)
{
    const sh::CandidateHealth health = sh::analyze_candidate(direct_rung("not a pattern"));

    EXPECT_FALSE(health.compiled);
    EXPECT_EQ(health.grade, sh::Grade::Unusable);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::UncompilablePattern));
    EXPECT_EQ(severity_of(health.findings, sh::FindingKind::UncompilablePattern), sh::Severity::Critical);
}

TEST(SigHealthCandidate, ShortStringXrefIsFlaggedButEmptyIsCritical)
{
    const sh::CandidateHealth short_health = sh::analyze_candidate(string_rung("OK"));
    EXPECT_EQ(short_health.anchor_text_bytes, 2u);
    EXPECT_TRUE(has_finding(short_health.findings, sh::FindingKind::ShortAnchorText));
    EXPECT_EQ(short_health.grade, sh::Grade::Fragile);

    const sh::CandidateHealth empty_health = sh::analyze_candidate(string_rung(""));
    EXPECT_TRUE(has_finding(empty_health.findings, sh::FindingKind::EmptyAnchorText));
    EXPECT_EQ(empty_health.grade, sh::Grade::Unusable);

    EXPECT_EQ(sh::analyze_candidate(string_rung("PlayerControllerBase")).grade, sh::Grade::Robust);
}

TEST(SigHealthCandidate, ShortMangledNameIsStillRobust)
{
    // A mangled RTTI name is unique by construction, so the string length floor does not apply to it.
    EXPECT_EQ(sh::analyze_candidate(rtti_rung(".?AVX@@")).grade, sh::Grade::Robust);

    EXPECT_TRUE(has_finding(sh::analyze_candidate(rtti_rung("")).findings, sh::FindingKind::EmptyAnchorText));
}

// Record analysis

TEST(SigHealthRecord, LadderGradesByItsStrongestRung)
{
    mf::SignatureRecord record;
    record.label = "player.health";
    record.kind = an::AnchorKind::RipGlobal;
    record.ladder.push_back(direct_rung("48 8B 05"));                // weak
    record.ladder.push_back(direct_rung("11 22 33 44 55 66 77 88")); // strong

    const sh::RecordHealth health = sh::analyze_record(record);

    EXPECT_EQ(health.ladder.size(), 2u);
    EXPECT_EQ(health.robust_rungs, 1u);
    EXPECT_EQ(health.grade, sh::Grade::Robust); // as strong as its best rung
    EXPECT_GT(health.best_selectivity_bits, 0.0);
    // The weak rung is still surfaced per rung for review.
    EXPECT_NE(health.ladder[0].grade, sh::Grade::Robust);
}

// A record's grade cannot EXCEED its compilability. The per-rung analysis grades a ladder by its strongest rung, but
// the resolver only ever sees a record Signature::compile accepts, and compile enforces constraints the pattern-only
// rung analysis does not model -- here a RipRelative rung whose (displacement_at, instruction_length) layout is
// malformed. compile rejects the WHOLE record on that one rung, so grading the record by its Robust sibling would
// certify a signature the trust gate could never build; the record is floored to Unusable and names the reason.
TEST(SigHealthRecord, GradeCannotExceedCompilability)
{
    mf::SignatureRecord record;
    record.label = "camera.fov";
    record.kind = an::AnchorKind::RipGlobal;
    record.ladder.push_back(direct_rung("11 22 33 44 55 66 77 88")); // a strong, Robust-grading rung in isolation

    // A RipRelative rung whose pattern compiles fine but whose decode layout is malformed: the 4-byte disp32 at offset
    // 4 cannot fit inside a 5-byte instruction, so Signature::compile rejects the whole record. analyze_candidate only
    // compiles the pattern, so this rung reads as selective on its own -- the exact blind spot the ceiling closes.
    mf::CandidateSpec bad_rip;
    bad_rip.mode = sc::Mode::RipRelative;
    bad_rip.pattern = "F3 0F 11 05 ?? ?? ?? ??";
    bad_rip.displacement_at = 4;
    bad_rip.instruction_length = 5;
    record.ladder.push_back(bad_rip);

    // The strongest rung alone grades Robust ...
    EXPECT_EQ(sh::analyze_candidate(direct_rung("11 22 33 44 55 66 77 88")).grade, sh::Grade::Robust);

    // ... but the record as a whole cannot compile, so it is floored to Unusable and says why.
    ASSERT_FALSE(mf::Signature::compile(record).has_value());
    const sh::RecordHealth health = sh::analyze_record(record);
    EXPECT_EQ(health.grade, sh::Grade::Unusable);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::UncompilableRecord));
}

TEST(SigHealthRecord, EmptyByteLadderIsUnusable)
{
    mf::SignatureRecord record;
    record.label = "empty";
    record.kind = an::AnchorKind::RipGlobal;

    const sh::RecordHealth health = sh::analyze_record(record);
    EXPECT_EQ(health.grade, sh::Grade::Unusable);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::NoRobustRung));
    EXPECT_EQ(severity_of(health.findings, sh::FindingKind::NoRobustRung), sh::Severity::Critical);
}

TEST(SigHealthRecord, AllWeakLadderFlagsNoRobustRung)
{
    mf::SignatureRecord record;
    record.label = "weak.only";
    record.kind = an::AnchorKind::RipGlobal;
    record.ladder.push_back(direct_rung("48 8B 05"));

    const sh::RecordHealth health = sh::analyze_record(record);
    EXPECT_EQ(health.robust_rungs, 0u);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::NoRobustRung));
    EXPECT_NE(health.grade, sh::Grade::Robust);
}

TEST(SigHealthRecord, ManualPinIsFragile)
{
    mf::SignatureRecord record;
    record.label = "pinned";
    record.kind = an::AnchorKind::Manual;
    record.manual_value = 0x1234;

    const sh::RecordHealth health = sh::analyze_record(record);
    EXPECT_EQ(health.grade, sh::Grade::Fragile);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::UnhealableManual));
}

TEST(SigHealthRecord, NonSerializableKindIsUnusable)
{
    mf::SignatureRecord record;
    record.label = "composite";
    record.kind = an::AnchorKind::Quorum;

    const sh::RecordHealth health = sh::analyze_record(record);
    EXPECT_EQ(health.grade, sh::Grade::Unusable);
    EXPECT_TRUE(has_finding(health.findings, sh::FindingKind::NonSerializableKind));
}

TEST(SigHealthRecord, StringAndVtableRecordKindsGradeByTheirText)
{
    mf::SignatureRecord xref;
    xref.label = "by.string";
    xref.kind = an::AnchorKind::StringXref;
    xref.xref_text = "UniqueDiagnosticString";
    EXPECT_EQ(sh::analyze_record(xref).grade, sh::Grade::Robust);
    EXPECT_EQ(sh::analyze_record(xref).anchor_text_bytes, xref.xref_text.size());

    mf::SignatureRecord vt;
    vt.label = "by.vtable";
    vt.kind = an::AnchorKind::VtableIdentity;
    vt.mangled = ".?AVCameraManager@@";
    EXPECT_EQ(sh::analyze_record(vt).grade, sh::Grade::Robust);
}

TEST(SigHealthRecord, ReportOwnsTheLabel)
{
    sh::RecordHealth health;
    {
        mf::SignatureRecord record;
        record.label = "temporary.label";
        record.kind = an::AnchorKind::Manual;

        health = sh::analyze_record(record);
    }

    EXPECT_EQ(health.label, "temporary.label");
}

// Manifest roll-up

TEST(SigHealthManifest, GradeIsTheWeakestRecordAndCountsPartition)
{
    mf::Manifest manifest;

    mf::SignatureRecord robust;
    robust.label = "robust";
    robust.kind = an::AnchorKind::RipGlobal;
    robust.ladder.push_back(direct_rung("11 22 33 44 55 66 77 88"));
    manifest.records.push_back(robust);

    mf::SignatureRecord fragile;
    fragile.label = "fragile";
    fragile.kind = an::AnchorKind::Manual;
    manifest.records.push_back(fragile);

    mf::SignatureRecord unusable;
    unusable.label = "unusable";
    unusable.kind = an::AnchorKind::Quorum;
    manifest.records.push_back(unusable);

    const sh::ManifestHealth health = sh::analyze_manifest(manifest);
    EXPECT_EQ(health.records.size(), 3u);
    EXPECT_EQ(health.robust, 1u);
    EXPECT_EQ(health.fragile, 1u);
    EXPECT_EQ(health.unusable, 1u);
    EXPECT_EQ(health.grade, sh::Grade::Unusable); // limited by the weakest signature
}

TEST(SigHealthManifest, HealthyManifestGradesRobust)
{
    mf::Manifest manifest;

    mf::SignatureRecord a;
    a.label = "a";
    a.kind = an::AnchorKind::StringXref;
    a.xref_text = "AVeryDistinctiveLiteral";
    manifest.records.push_back(a);

    mf::SignatureRecord b;
    b.label = "b";
    b.kind = an::AnchorKind::RipGlobal;
    b.ladder.push_back(direct_rung("11 22 33 44 55 66"));
    manifest.records.push_back(b);

    const sh::ManifestHealth health = sh::analyze_manifest(manifest);
    EXPECT_EQ(health.grade, sh::Grade::Robust);
    EXPECT_EQ(health.robust, 2u);
}

// Stringifiers and report formatting

TEST(SigHealthFormat, StringifiersNeverEmptyForNamedValues)
{
    EXPECT_FALSE(sh::to_string(sh::Grade::Robust).empty());
    EXPECT_FALSE(sh::to_string(sh::Grade::Fragile).empty());
    EXPECT_FALSE(sh::to_string(sh::Grade::Unusable).empty());
    EXPECT_FALSE(sh::to_string(sh::Severity::Warning).empty());
    EXPECT_FALSE(sh::to_string(sh::Severity::Critical).empty());
    for (auto kind :
         {sh::FindingKind::NoFixedAnchor, sh::FindingKind::UncompilablePattern, sh::FindingKind::ShortPattern,
          sh::FindingKind::ShortestAnchorRun, sh::FindingKind::CommonBytesOnly, sh::FindingKind::HighWildcardRatio,
          sh::FindingKind::LowByteEntropy, sh::FindingKind::WeakSelectivity, sh::FindingKind::EmptyAnchorText,
          sh::FindingKind::ShortAnchorText, sh::FindingKind::UnhealableManual, sh::FindingKind::NonSerializableKind,
          sh::FindingKind::NoRobustRung, sh::FindingKind::UncompilableRecord})
    {
        EXPECT_FALSE(sh::to_string(kind).empty());
    }
}

TEST(SigHealthFormat, ReportsCarryTheGradeAndLabel)
{
    const sh::PatternHealth pattern = sh::analyze_pattern(make_pattern("?? ?? ?? ??"));
    const std::string pattern_report = sh::format_report(pattern, "camera.fov");
    EXPECT_NE(pattern_report.find("camera.fov"), std::string::npos);
    EXPECT_NE(pattern_report.find(sh::to_string(pattern.grade)), std::string::npos);

    mf::Manifest manifest;
    mf::SignatureRecord record;
    record.label = "player.health";
    record.kind = an::AnchorKind::RipGlobal;
    record.ladder.push_back(direct_rung("48 8B 05"));
    manifest.records.push_back(record);

    const sh::ManifestHealth health = sh::analyze_manifest(manifest);
    const std::string report = sh::format_report(health);
    EXPECT_NE(report.find("player.health"), std::string::npos);
    EXPECT_NE(report.find("manifest health"), std::string::npos);
}

TEST(SigHealthFormat, RecordReportRendersTheTextAnchorBranch)
{
    // A text-backed record (no ladder) exercises the format_report(RecordHealth) overload's "anchor text" branch, which
    // a ladder-backed record never reaches.
    mf::SignatureRecord xref;
    xref.label = "camera.by_string";
    xref.kind = an::AnchorKind::StringXref;
    xref.xref_text = "UniqueDiagnosticString";

    const sh::RecordHealth health = sh::analyze_record(xref);
    const std::string report = sh::format_report(health);
    EXPECT_NE(report.find("camera.by_string"), std::string::npos);
    EXPECT_NE(report.find("StringXref"), std::string::npos);
    EXPECT_NE(report.find("anchor text"), std::string::npos);
}
