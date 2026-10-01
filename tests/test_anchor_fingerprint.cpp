#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <gtest/gtest.h>

#include <cstdint>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/scan.hpp"

#include "fixtures/anchor_fixture.hpp"

using namespace dmk_test::anchor_fixture;

// Fingerprints: hash the resolution EVIDENCE, excluding the resolved address.

TEST(AnchorFingerprintTest, ExportNameModuleAndNameAreEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::ExportName;
    a.export_module = "kernel32.dll";
    a.export_name = "Sleep";

    an::Anchor different_name = a;
    different_name.export_name = "SleepEx";
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(different_name));

    an::Anchor different_module = a;
    different_module.export_module = "ntdll.dll";
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(different_module));

    an::Anchor identical = a;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(identical));
}

// bytes()/mask() exclude gap positions and bounds. Distinct gaps with identical fixed bytes must yield distinct drift
// fingerprints.
TEST(AnchorFingerprintTest, PatternJumpSpanIsFoldedIntoFingerprint)
{
    const sc::Candidate narrow[] = {sc::Candidate::direct("m", aob("DE AD [2-4] BE EF 10 20 30 40 50"))};
    const sc::Candidate wide[] = {sc::Candidate::direct("m", aob("DE AD [6-10] BE EF 10 20 30 40 50"))};
    const sc::Candidate shifted[] = {sc::Candidate::direct("m", aob("DE [2-4] AD BE EF 10 20 30 40 50"))};
    const sc::Candidate adjacent[] = {sc::Candidate::direct("m", aob("DE AD BE EF 10 20 30 40 50"))};
    const sc::Candidate narrow_copy[] = {sc::Candidate::direct("m", aob("DE AD [2-4] BE EF 10 20 30 40 50"))};

    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = narrow;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = wide;
    an::Anchor c{};
    c.kind = an::AnchorKind::RipGlobal;
    c.site = adjacent;
    an::Anchor d{};
    d.kind = an::AnchorKind::RipGlobal;
    d.site = narrow_copy;
    an::Anchor e{};
    e.kind = an::AnchorKind::RipGlobal;
    e.site = shifted;

    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b)); // different gap widths
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(c)); // gapped vs adjacent
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(e)); // different gap position
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(d)); // identical structure -> identical fingerprint
}

TEST(AnchorFingerprintTest, DeterministicForSameEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 0x1234;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(a));
}

TEST(AnchorFingerprintTest, IgnoresLabel)
{
    an::Anchor a{};
    a.label = "one";
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 7;
    an::Anchor b = a;
    b.label = "different-label"; // the label is cosmetic and excluded from the fingerprint
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, VtableMangledIsEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::VtableIdentity;
    a.mangled = ".?AVFoo@@";
    an::Anchor b = a;
    b.mangled = ".?AVBar@@";
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, KindIsEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    an::Anchor b{};
    b.kind = an::AnchorKind::CallArgHome;
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, IgnoresCandidateName)
{
    const sc::Candidate site_a[] = {sc::Candidate::direct("name-one", aob("48 8B 05 ?? ?? ?? ??"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("name-two", aob("48 8B 05 ?? ?? ?? ??"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = site_a;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = site_b;
    // The candidate's cosmetic name does not change which address resolves, so it is excluded.
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, RipGlobalNonDefaultPageClassIsEvidence)
{
    const sc::Candidate site[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    an::Anchor readable{};
    readable.kind = an::AnchorKind::RipGlobal;
    readable.site = site;
    an::Anchor executable = readable;
    executable.pages = sc::Pages::Executable;

    // The Executable digest equals the Readable digest with one trailing FNV-1a byte. This equality detects any extra
    // fold for the default Readable class.
    constexpr std::uint64_t fnv1a_prime = 1099511628211ULL;
    const std::uint64_t readable_fp = an::anchor_fingerprint(readable);
    const std::uint64_t expected_executable_fp =
        (readable_fp ^ static_cast<std::uint8_t>(sc::Pages::Executable)) * fnv1a_prime;
    EXPECT_EQ(an::anchor_fingerprint(executable), expected_executable_fp);
    EXPECT_NE(an::anchor_fingerprint(executable), readable_fp);
}

TEST(AnchorFingerprintTest, CascadePatternContentIsEvidence)
{
    const sc::Candidate site_a[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("c", aob("48 8B 0D ?? ?? ?? ??"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = site_a;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = site_b;
    // A different compiled pattern (different literal byte) is different evidence.
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadeFieldBoundaryResistsByteRedistribution)
{
    // The same byte stream splits into [AA BB][CC] and [AA][BB CC]. Length prefixes must distinguish those pattern
    // boundaries.
    const sc::Candidate split_left[] = {
        sc::Candidate::direct("c0", aob("AA BB")),
        sc::Candidate::direct("c1", aob("CC"))
    };
    const sc::Candidate split_right[] = {
        sc::Candidate::direct("c0", aob("AA")),
        sc::Candidate::direct("c1", aob("BB CC"))
    };
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = split_left;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = split_right;
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadeCardinalityIsEvidence)
{
    // A single candidate versus the same candidate repeated: [c] vs [c, c]. Per-candidate content is byte-identical, so
    // only the cascade length differs. The cascade's leading count prefix makes cardinality evidence, so a duplicated
    // ladder row cannot alias the singleton it duplicates.
    const sc::Candidate one[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    const sc::Candidate two[] = {
        sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??")),
        sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))
    };
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = one;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = two;
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadeWildcardMaskIsEvidence)
{
    const sc::Candidate site_a[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? 00"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = site_a;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = site_b;
    // Same length, different wildcard mask (last byte literal vs wildcard) is different evidence.
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CodeOperandDecodeParamsAreEvidence)
{
    const sc::Candidate site[] = {sc::Candidate::direct("c", aob("48 05 F0 00 00 00"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::CodeOperand;
    a.site = site;
    a.operand_index = 1;
    an::Anchor b = a;
    b.operand_index = 2; // the decode parameter is evidence
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, StringXrefShapeFlagsAreEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::StringXref;
    a.xref_text = "hello";
    an::Anchor b = a;
    b.xref_broad_match = true; // a shape flag is evidence
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, ManualLiteralIsEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 1;
    an::Anchor b = a;
    b.manual_value = 2;
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, SameEvidenceDifferentValueMatches)
{
    // The fingerprint covers declaration evidence, while ResolvedAnchor owns the resolved value. A later address change
    // alone cannot alter that fingerprint.
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 0x1000;
    const an::Anchor b = a;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, QuorumIsOrderIndependent)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::VtableIdentity;
    sub_a.mangled = ".?AVA@@";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVB@@";

    const an::Anchor *members1[] = {&sub_a, &sub_b};
    const an::Anchor *members2[] = {&sub_b, &sub_a}; // swapped
    an::Anchor q1{};
    q1.kind = an::AnchorKind::Quorum;
    q1.quorum_members = members1;
    an::Anchor q2{};
    q2.kind = an::AnchorKind::Quorum;
    q2.quorum_members = members2;
    EXPECT_EQ(an::anchor_fingerprint(q1), an::anchor_fingerprint(q2));
}

TEST(AnchorFingerprintTest, QuorumMatchModeAndToleranceAreEvidence)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::VtableIdentity;
    sub_a.mangled = ".?AVA@@";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVB@@";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor base{};
    base.kind = an::AnchorKind::Quorum;
    base.quorum_members = members;

    an::Anchor mode = base;
    mode.quorum_match = an::QuorumMatch::WithinTolerance;
    EXPECT_NE(an::anchor_fingerprint(base), an::anchor_fingerprint(mode));

    an::Anchor tol = mode;
    tol.quorum_tolerance = 8;
    EXPECT_NE(an::anchor_fingerprint(mode), an::anchor_fingerprint(tol));
}

TEST(AnchorFingerprintTest, QuorumThresholdIsEvidence)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::VtableIdentity;
    sub_a.mangled = ".?AVA@@";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVB@@";
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::VtableIdentity;
    sub_c.mangled = ".?AVC@@";

    // The members match, but the vote thresholds differ. The fingerprint must preserve that distinction.
    const an::Anchor *members[] = {&sub_a, &sub_b, &sub_c};
    an::Anchor unanimous{};
    unanimous.kind = an::AnchorKind::Quorum;
    unanimous.quorum_members = members;
    an::Anchor two_of_three = unanimous;
    two_of_three.quorum_threshold = 2;
    EXPECT_NE(an::anchor_fingerprint(unanimous), an::anchor_fingerprint(two_of_three));
}

TEST(AnchorFingerprintTest, QuorumDefaultThresholdMatchesExplicitUnanimous)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::VtableIdentity;
    sub_a.mangled = ".?AVA@@";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVB@@";
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::VtableIdentity;
    sub_c.mangled = ".?AVC@@";

    // The default threshold 0 means unanimous, so spelling a three-member quorum as 0 or 3 is the same contract.
    const an::Anchor *members[] = {&sub_a, &sub_b, &sub_c};
    an::Anchor default_unanimous{};
    default_unanimous.kind = an::AnchorKind::Quorum;
    default_unanimous.quorum_members = members;
    an::Anchor explicit_unanimous = default_unanimous;
    explicit_unanimous.quorum_threshold = 3;
    EXPECT_EQ(an::anchor_fingerprint(default_unanimous), an::anchor_fingerprint(explicit_unanimous));
}

TEST(AnchorFingerprintTest, QuorumFingerprintDistinguishesMemberMultiplicity)
{
    // The multisets {A, A, B} and {A, B, B} share distinct members but differ in multiplicity. The fingerprint must
    // distinguish them.
    an::Anchor a{};
    a.kind = an::AnchorKind::VtableIdentity;
    a.mangled = ".?AVA@@";
    an::Anchor a_dup{};
    a_dup.kind = an::AnchorKind::VtableIdentity;
    a_dup.mangled = ".?AVA@@"; // identical evidence to a
    an::Anchor b{};
    b.kind = an::AnchorKind::VtableIdentity;
    b.mangled = ".?AVB@@";
    an::Anchor b_dup{};
    b_dup.kind = an::AnchorKind::VtableIdentity;
    b_dup.mangled = ".?AVB@@"; // identical evidence to b

    const an::Anchor *two_a_one_b[] = {&a, &a_dup, &b};
    const an::Anchor *one_a_two_b[] = {&a, &b, &b_dup};
    an::Anchor q1{};
    q1.kind = an::AnchorKind::Quorum;
    q1.quorum_members = two_a_one_b;
    an::Anchor q2{};
    q2.kind = an::AnchorKind::Quorum;
    q2.quorum_members = one_a_two_b;
    EXPECT_NE(an::anchor_fingerprint(q1), an::anchor_fingerprint(q2));
}

TEST(AnchorFingerprintTest, QuorumFingerprintOrderIndependentWithDuplicates)
{
    // The multisets {A, A, B} and {A, B, A} are equal. Duplicate members cannot make the fold order-sensitive.
    an::Anchor a{};
    a.kind = an::AnchorKind::VtableIdentity;
    a.mangled = ".?AVA@@";
    an::Anchor a_dup{};
    a_dup.kind = an::AnchorKind::VtableIdentity;
    a_dup.mangled = ".?AVA@@";
    an::Anchor b{};
    b.kind = an::AnchorKind::VtableIdentity;
    b.mangled = ".?AVB@@";

    const an::Anchor *aab[] = {&a, &a_dup, &b};
    const an::Anchor *aba[] = {&a, &b, &a_dup};
    an::Anchor q1{};
    q1.kind = an::AnchorKind::Quorum;
    q1.quorum_members = aab;
    an::Anchor q2{};
    q2.kind = an::AnchorKind::Quorum;
    q2.quorum_members = aba;
    EXPECT_EQ(an::anchor_fingerprint(q1), an::anchor_fingerprint(q2));
}

TEST(AnchorFingerprintTest, QuorumNullSubAnchorIsDefined)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::VtableIdentity;
    sub.mangled = ".?AVA@@";
    const an::Anchor *members[] = {&sub, nullptr}; // a null member contributes a fixed sentinel, never a nullptr deref
    an::Anchor q{};
    q.kind = an::AnchorKind::Quorum;
    q.quorum_members = members;
    EXPECT_EQ(an::anchor_fingerprint(q), an::anchor_fingerprint(q));
}

TEST(AnchorFingerprintTest, CallArgHomeReflectsKindOnly)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::CallArgHome;
    a.manual_value = 1; // CallArgHome hashes only its kind, even when another kind consumes the field.
    an::Anchor b{};
    b.kind = an::AnchorKind::CallArgHome;
    b.manual_value = 2;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

// Trust fingerprints bind definition evidence to an ASLR-insensitive image identity.

TEST(AnchorTrustFingerprintTest, DefinitionFingerprintIsScopeFreeButTrustFingerprintBindsScope)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 42;

    const sc::ImageIdentity id1{
        .timestamp = 1,
        .size_of_image = 0x1000,
        .section_digest = 0xAA,
    };
    const sc::ImageIdentity id2{
        .timestamp = 2,
        .size_of_image = 0x2000,
        .section_digest = 0xBB,
    };

    // The definition fingerprint excludes scope. The trust fingerprint depends on the bound image identity.
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(a));
    EXPECT_NE(an::anchor_trust_fingerprint(a, id1), an::anchor_fingerprint(a));
    EXPECT_EQ(an::anchor_trust_fingerprint(a, id1), an::anchor_trust_fingerprint(a, id1));
    EXPECT_NE(an::anchor_trust_fingerprint(a, id1), an::anchor_trust_fingerprint(a, id2));
}

TEST(AnchorTrustFingerprintTest, InheritedEmptyExportModuleScopeCollidesWithExplicitSameModule)
{
    an::Anchor inherited{};
    inherited.kind = an::AnchorKind::ExportName;
    inherited.export_name = "compute_damage";
    // export_module empty: the effective module is the passed scope.

    an::Anchor explicit_mod{};
    explicit_mod.kind = an::AnchorKind::ExportName;
    explicit_mod.export_name = "compute_damage";
    explicit_mod.export_module = "game.dll";

    const sc::ImageIdentity effective{
        .timestamp = 7,
        .size_of_image = 0x4000,
        .section_digest = 0xC0FFEE,
    };

    // The effective export identity produces one trust key. The declaration fingerprints still distinguish an explicit
    // module string from an empty one.
    EXPECT_EQ(
        an::anchor_trust_fingerprint(inherited, effective),
        an::anchor_trust_fingerprint(explicit_mod, effective)
    );
    EXPECT_NE(an::anchor_fingerprint(inherited), an::anchor_fingerprint(explicit_mod));
}

TEST(AnchorTrustFingerprintTest, SameBaseRemappedModuleChangesTrustFingerprintNotDefinition)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::ExportName;
    a.export_name = "compute_damage";

    // A same-base remap keeps timestamp and size but rewrites the section table (a different PE at the same base).
    const sc::ImageIdentity before{
        .timestamp = 9,
        .size_of_image = 0x8000,
        .section_digest = 0x1111,
    };
    const sc::ImageIdentity after{
        .timestamp = 9,
        .size_of_image = 0x8000,
        .section_digest = 0x2222,
    };

    EXPECT_NE(an::anchor_trust_fingerprint(a, before), an::anchor_trust_fingerprint(a, after));
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(a));
}
