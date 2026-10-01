#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/scan.hpp"

#include "fixtures/loader_lock_scope.hpp"
#include "test_alloc_probe.hpp"

#include "fixtures/scratch_page.hpp"

#include <windows.h>
#include "fixtures/anchor_fixture.hpp"
using namespace dmk_test::anchor_fixture;

namespace
{
    bool expect_value_f0(std::int64_t value, const void *) noexcept
    {
        return value == 0xF0;
    }

    const int s_validator_context_token = 0;

    bool require_context_token(std::int64_t, const void *context) noexcept
    {
        return context == &s_validator_context_token;
    }
} // anonymous namespace

// Backend dispatch: each kind maps onto its v4 backend and maps success/failure onto AnchorStatus.

TEST(AnchorTest, ManualResolvesToLiteral)
{
    an::Anchor anchor{};
    anchor.label = "manual";
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x1234;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x1234);
    EXPECT_EQ(result.kind, an::AnchorKind::Manual);
    EXPECT_EQ(result.label, "manual");
}

TEST(AnchorTest, CallArgHomeIsUnsupported)
{
    an::Anchor anchor{};
    anchor.label = "arghome";
    anchor.kind = an::AnchorKind::CallArgHome;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Unsupported);
}

TEST(AnchorTest, CodeOperandResolvesImmediate)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "stride";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, CodeOperandResolvesDisplacementWithByteWidth)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]

    const sc::Candidate cands[] = {sc::Candidate::direct("disp8", aob("8A 45 FF"))};
    an::Anchor anchor{};
    anchor.label = "disp";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_kind = sc::OperandKind::MemoryDisplacement;
    anchor.operand_index = 1;
    anchor.byte_width = 1; // The one-byte value must stay negative.

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, -1);
}

TEST(AnchorTest, CodeOperandRejectsOutOfDomainByteWidth)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]

    const sc::Candidate candidates[] = {sc::Candidate::direct("disp8", aob("8A 45 FF"))};
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::MemoryDisplacement;
    anchor.operand_index = 1;

    for (std::uint8_t width = 0; width <= 8; ++width)
    {
        anchor.byte_width = width;
        EXPECT_EQ(an::declared_domain(anchor), an::ResultDomain::Scalar) << "width=" << static_cast<unsigned>(width);
        const an::ResolvedAnchor valid = an::resolve(anchor, page.range());
        EXPECT_EQ(valid.status, an::AnchorStatus::Resolved) << "width=" << static_cast<unsigned>(width);
        EXPECT_EQ(valid.value, -1) << "width=" << static_cast<unsigned>(width);
    }

    for (const std::uint8_t width : {std::uint8_t{9}, std::uint8_t{255}})
    {
        anchor.byte_width = width;
        EXPECT_EQ(an::declared_domain(anchor), an::ResultDomain::Unknown) << "width=" << static_cast<unsigned>(width);
        const an::ResolvedAnchor invalid = an::resolve(anchor, page.range());
        EXPECT_EQ(invalid.status, an::AnchorStatus::Failed) << "width=" << static_cast<unsigned>(width);
        EXPECT_EQ(invalid.value, 0);
    }
}

TEST(AnchorTest, RipGlobalResolvesToAddress)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});

    const sc::Candidate cands[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    an::Anchor anchor{};
    anchor.label = "global";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = cands;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), page.addr(0x200));
}

// The readable data page resolves under Readable and disappears under Executable. This distinguishes page policy from a
// coincidental byte-pattern match.
TEST(AnchorTest, RipGlobalPageClassKnobRejectsDataPageSite)
{
    void *data = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(data, nullptr);
    std::memset(data, 0xCC, 0x1000);
    const std::uint8_t marker[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40};
    std::memcpy(static_cast<std::uint8_t *>(data) + 0x200, marker, sizeof(marker));
    const dmk::Region scope{dmk::Address{reinterpret_cast<std::uintptr_t>(data)}, 0x1000};

    const sc::Candidate cands[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    an::Anchor anchor{};
    anchor.label = "global";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = cands;

    // The default Readable class resolves the data-page site.
    anchor.pages = sc::Pages::Readable;
    EXPECT_EQ(an::resolve(anchor, scope).status, an::AnchorStatus::Resolved);

    // Narrowing to Executable makes the same data-page site invisible, so the anchor fails closed.
    anchor.pages = sc::Pages::Executable;
    EXPECT_EQ(an::resolve(anchor, scope).status, an::AnchorStatus::Failed);

    VirtualFree(data, 0, MEM_RELEASE);
}

TEST(AnchorTest, RipGlobalAbsentSignatureFailsClosed)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());

    const sc::Candidate cands[] = {sc::Candidate::direct("absent", aob("11 22 33 44 55 66 77 88"))};
    an::Anchor anchor{};
    anchor.label = "global";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = cands;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, StringXrefResolvesReference)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "AnchorRegistryUniqueMarkerString";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]

    an::Anchor anchor{};
    anchor.label = "message";
    anchor.kind = an::AnchorKind::StringXref;
    anchor.xref_text = literal;

    const an::ResolvedAnchor result = an::resolve(anchor, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), image.addr(0x100));
}

TEST(AnchorTest, StringXrefFailsClosedWhenAbsent)
{
    StringImage image;
    ASSERT_TRUE(image.ok());

    an::Anchor anchor{};
    anchor.label = "message";
    anchor.kind = an::AnchorKind::StringXref;
    anchor.xref_text = "ThisStringIsDefinitelyNotPresentInTheImage";

    const an::ResolvedAnchor result = an::resolve(anchor, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorProfileTest, DenyExportNameBackendFailsClosed)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "compute_damage";

    an::ScanProfile profile{};
    profile.deny_backend[static_cast<std::size_t>(an::AnchorKind::ExportName)] = true;

    const an::ResolvedAnchor result = an::resolve_with_profile(anchor, profile, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0); // denied, never substituted with another backend's guess
}

TEST(AnchorTest, VtableIdentityFailsClosedWhenAbsent)
{
    // tests/test_rtti.cpp verifies the synthetic MSVC RTTI success path. This case covers anchor-side refusal of a
    // bogus name.
    an::Anchor anchor{};
    anchor.label = "vtable";
    anchor.kind = an::AnchorKind::VtableIdentity;
    anchor.mangled = ".?AVNoSuchTypeExistsAnywhere@dmk_test@@";

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, StatusToStringNonEmpty)
{
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::Unresolved).empty());
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::Resolved).empty());
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::Failed).empty());
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::Unsupported).empty());
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::QuorumNotIndependent).empty());
}

// Table resolution (serial, parallel, capacity).

TEST(AnchorTest, ResolveAllWritesReport)
{
    an::Anchor anchors[2]{};
    anchors[0].label = "a";
    anchors[0].kind = an::AnchorKind::Manual;
    anchors[0].manual_value = 1;
    anchors[1].label = "b";
    anchors[1].kind = an::AnchorKind::Manual;
    anchors[1].manual_value = 2;

    an::ResolvedAnchor report[2]{};
    const std::size_t written = an::resolve_all(anchors, report);
    EXPECT_EQ(written, 2u);
    EXPECT_EQ(report[0].value, 1);
    EXPECT_EQ(report[1].value, 2);
}

TEST(AnchorTest, ResolveAllParallelMatchesSerialReport)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor anchors[3]{};
    anchors[0].label = "manual";
    anchors[0].kind = an::AnchorKind::Manual;
    anchors[0].manual_value = 0x11;
    anchors[1].label = "code";
    anchors[1].kind = an::AnchorKind::CodeOperand;
    anchors[1].site = cands;
    anchors[1].operand_index = 1;
    anchors[2].label = "arghome";
    anchors[2].kind = an::AnchorKind::CallArgHome;

    an::ResolvedAnchor serial[3]{};
    an::ResolvedAnchor parallel[3]{};
    const std::size_t serial_count = an::resolve_all(anchors, serial, page.range());
    const std::size_t parallel_count = an::resolve_all_parallel(anchors, parallel, page.range(), 4);
    ASSERT_EQ(serial_count, parallel_count);
    for (std::size_t i = 0; i < serial_count; ++i)
    {
        EXPECT_EQ(parallel[i].status, serial[i].status);
        EXPECT_EQ(parallel[i].value, serial[i].value);
        EXPECT_EQ(parallel[i].label, serial[i].label);
        EXPECT_EQ(parallel[i].kind, serial[i].kind);
    }
}

TEST(AnchorTest, ResolveAllRespectsCapacity)
{
    an::Anchor anchors[3]{};
    for (an::Anchor &a : anchors)
    {
        a.kind = an::AnchorKind::Manual;
        a.manual_value = 7;
    }

    an::ResolvedAnchor report[2]{}; // smaller than the table
    const std::size_t written = an::resolve_all(anchors, report);
    EXPECT_EQ(written, 2u); // min(anchors, out)
}

// Post-resolve validators.

TEST(AnchorTest, ValidatorRejectionFailsClosed)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0xF0;
    anchor.validate_manual = true; // route the Manual through the validator path
    anchor.validator = &always_reject;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, ValidatorAcceptSeesResolvedValue)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0xF0;
    anchor.validate_manual = true;
    anchor.validator = &expect_value_f0;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, ValidatorContextPassesThrough)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0xF0;
    anchor.validate_manual = true;
    anchor.validator = &require_context_token;
    anchor.validator_context = &s_validator_context_token;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
}

TEST(AnchorTest, ValidatorNotAppliedToManualByDefault)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x99;
    anchor.validator = &always_reject; // present but validate_manual is false

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved); // pinned literal exemption
    EXPECT_EQ(result.value, 0x99);
}

TEST(AnchorTest, ValidatorNotAppliedToCallArgHome)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::CallArgHome;
    anchor.validator = &always_reject;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Unsupported); // no resolver runs, so the validator never fires
}

TEST(AnchorTest, ManualValidatorRunsWhenOptedIn)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x01; // not 0xF0
    anchor.validate_manual = true;
    anchor.validator = &expect_value_f0;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed); // validator opted-in and rejects
}

TEST(AnchorTest, ManualValidatorSkippedByDefault)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x01;
    anchor.validator = &expect_value_f0; // validate_manual is false

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x01);
}

TEST(AnchorTest, RequireValidatorRejectsUnverifiedBackend)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_index = 1;
    anchor.require_validator = true; // but no validator attached

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed); // treated as unverified
}

TEST(AnchorTest, RequireValidatorIgnoredForManualByDefault)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x22;
    anchor.require_validator = true; // ignored: the default Manual path never runs commit_resolved

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x22);
}

TEST(AnchorTest, RequireValidatorExemptsManualWhenValidated)
{
    // Manual has no backend-resolved target. The missing validator therefore cannot trigger require_validator, even if
    // validate_manual is true.
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x44;
    anchor.validate_manual = true;   // route through the commit_resolved validator path
    anchor.require_validator = true; // but Manual is exempt from the no-validator rejection (only backends are subject)

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x44);
}

TEST(AnchorTest, UnsetKindFailsClosed)
{
    // An omitted kind must refuse a trusted zero. Unset supplies the fail-closed default.
    an::Anchor anchor{};
    EXPECT_EQ(anchor.kind, an::AnchorKind::Unset) << "a default-constructed Anchor must default to Unset";
    anchor.label = "forgot-the-kind";
    anchor.manual_value = 0; // A populated field must not supply an implicit kind.

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

// ResolvedAnchor::label borrows Anchor::label storage. The report must not outlive the source anchor.

TEST(AnchorTest, ResolvedLabelBorrowedLifetimeIsExplicit)
{
    const std::string source_label = "fixture.borrowed_label";
    an::Anchor anchor{};
    anchor.label = source_label; // a std::string_view aliasing source_label's buffer
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x1234;

    const an::ResolvedAnchor result = an::resolve(anchor);
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.label, source_label);
    // The report label ALIASES the source buffer (borrowed), it is not a fresh copy. Both views point at the same
    // storage, which is the contract the doc comment now states.
    EXPECT_EQ(static_cast<const void *>(result.label.data()), static_cast<const void *>(source_label.data()));
}

TEST(AnchorTest, StatusToStringMapsQuorumAmbiguous)
{
    EXPECT_EQ(an::anchor_status_to_string(an::AnchorStatus::QuorumAmbiguous), "QuorumAmbiguous");
}

// A hand-built anchor with an out-of-range safety enum fails closed instead of selecting a permissive default.

TEST(PolicyDomainTest, InvalidEnumsFailClosedEverywhere)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());

    // The invalid AnchorKind lies beyond the deny-list bound. The result must be terminal Failed rather than the
    // initial Unresolved.
    an::Anchor bad_kind{};
    bad_kind.kind = static_cast<an::AnchorKind>(0xFF);
    EXPECT_EQ(an::resolve(bad_kind, page.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_kind), an::ResultDomain::Unknown);

    // scan::read_code_constant can reject the same invalid kind. The declared_domain expectation isolates the
    // anchor-local check from that downstream refusal.
    page.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]
    const sc::Candidate disp_site[] = {sc::Candidate::direct("disp8", aob("8A 45 FF"))};
    an::Anchor code_control{};
    code_control.kind = an::AnchorKind::CodeOperand;
    code_control.site = disp_site;
    code_control.operand_index = 1;
    code_control.operand_kind = sc::OperandKind::MemoryDisplacement;
    code_control.byte_width = 1;
    ASSERT_EQ(an::resolve(code_control, page.range()).status, an::AnchorStatus::Resolved);
    an::Anchor bad_operand_kind = code_control;
    bad_operand_kind.operand_kind = static_cast<sc::OperandKind>(0xFF);
    EXPECT_EQ(an::resolve(bad_operand_kind, page.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_operand_kind), an::ResultDomain::Unknown);

    // StringXref: a resolvable reference is failed closed by an invalid encoding or an invalid return mode.
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "PolicyDomainUniqueMarkerString";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]
    an::Anchor string_control{};
    string_control.kind = an::AnchorKind::StringXref;
    string_control.xref_text = literal;
    ASSERT_EQ(an::resolve(string_control, image.range()).status, an::AnchorStatus::Resolved);
    an::Anchor bad_encoding = string_control;
    bad_encoding.xref_encoding = static_cast<sc::StringEncoding>(0xFF);
    EXPECT_EQ(an::resolve(bad_encoding, image.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_encoding), an::ResultDomain::Unknown);
    an::Anchor bad_return = string_control;
    bad_return.xref_return = static_cast<sc::XrefReturn>(0xFF);
    EXPECT_EQ(an::resolve(bad_return, image.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_return), an::ResultDomain::Unknown);

    // The invalid match policy must refuse even when two independent members agree within zero tolerance.
    ScratchPage imm_page;
    ASSERT_TRUE(imm_page.ok());
    imm_page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate imm_site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor manual_member{};
    manual_member.kind = an::AnchorKind::Manual;
    manual_member.manual_value = 0xF0;
    an::Anchor operand_member{};
    operand_member.kind = an::AnchorKind::CodeOperand;
    operand_member.site = imm_site;
    operand_member.operand_index = 1;
    const an::Anchor *members[] = {&manual_member, &operand_member};
    an::Anchor quorum_control{};
    quorum_control.kind = an::AnchorKind::Quorum;
    quorum_control.quorum_members = members;
    ASSERT_EQ(an::resolve(quorum_control, imm_page.range()).status, an::AnchorStatus::Resolved);
    an::Anchor bad_match = quorum_control;
    bad_match.quorum_match = static_cast<an::QuorumMatch>(0xFF);
    EXPECT_EQ(an::resolve(bad_match, imm_page.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_match), an::ResultDomain::Unknown);

    // RipGlobal reaches scan::resolve's order check. CodeOperand orders its ladder locally before read_code_constant,
    // which accepts no order parameter.
    const sc::Candidate rip_site[] = {sc::Candidate::direct("byte", aob("8A 45 FF"))};
    an::Anchor rip_control{};
    rip_control.kind = an::AnchorKind::RipGlobal;
    rip_control.site = rip_site;
    an::ScanProfile bad_order_profile{};
    bad_order_profile.candidate_order = static_cast<sc::CandidateOrder>(0xFF);
    ASSERT_EQ(
        an::resolve_with_profile(rip_control, an::ScanProfile{}, page.range()).status,
        an::AnchorStatus::Resolved
    );
    EXPECT_EQ(an::resolve_with_profile(rip_control, bad_order_profile, page.range()).status, an::AnchorStatus::Failed);
    ASSERT_EQ(
        an::resolve_with_profile(code_control, an::ScanProfile{}, page.range()).status,
        an::AnchorStatus::Resolved
    );
    EXPECT_EQ(an::resolve_with_profile(code_control, bad_order_profile, page.range()).status, an::AnchorStatus::Failed);
}

// declared_domain maps each kind to the ResultDomain a consumer binding must accept.

TEST(AnchorDomainTest, DeclaredDomainPerKind)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::VtableIdentity;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::VtableAddress);
    a.kind = an::AnchorKind::CodeOperand;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::Scalar);
    a.kind = an::AnchorKind::Manual;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::Scalar);
    a.kind = an::AnchorKind::ExportName;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::CodeSite);
    a.kind = an::AnchorKind::CallArgHome;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::Unknown);
    a.kind = an::AnchorKind::Unset;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::Unknown);

    an::Anchor xref{};
    xref.kind = an::AnchorKind::StringXref;
    xref.xref_return = sc::XrefReturn::ReferencingInstruction;
    EXPECT_EQ(an::declared_domain(xref), an::ResultDomain::CodeSite);
    xref.xref_return = sc::XrefReturn::EnclosingFunction;
    EXPECT_EQ(an::declared_domain(xref), an::ResultDomain::CodeSite);
    xref.xref_return = sc::XrefReturn::StringPointerSlot;
    EXPECT_EQ(an::declared_domain(xref), an::ResultDomain::DataAddress);

    an::Anchor rip{};
    rip.kind = an::AnchorKind::RipGlobal;
    rip.pages = sc::Pages::Readable;
    EXPECT_EQ(an::declared_domain(rip), an::ResultDomain::DataAddress);
    rip.pages = sc::Pages::Executable;
    EXPECT_EQ(an::declared_domain(rip), an::ResultDomain::CodeSite);
    rip.pages = static_cast<sc::Pages>(0xFF); // an out-of-range pages knob yields no trustworthy domain
    EXPECT_EQ(an::declared_domain(rip), an::ResultDomain::Unknown);
}

TEST(AnchorDomainTest, QuorumDomainAgreesOrIsUnknown)
{
    an::Anchor code_export{};
    code_export.kind = an::AnchorKind::ExportName;
    code_export.export_name = "Foo";
    an::Anchor code_rip{};
    code_rip.kind = an::AnchorKind::RipGlobal;
    code_rip.pages = sc::Pages::Executable;
    // Two code-site members agree -> CodeSite.
    const an::Anchor *code_members[] = {&code_export, &code_rip};
    an::Anchor code_quorum{};
    code_quorum.kind = an::AnchorKind::Quorum;
    code_quorum.quorum_members = code_members;
    EXPECT_EQ(an::declared_domain(code_quorum), an::ResultDomain::CodeSite);

    // A Manual (Scalar wildcard) corroborating a code site keeps the specific CodeSite domain.
    an::Anchor manual{};
    manual.kind = an::AnchorKind::Manual;
    const an::Anchor *wild_members[] = {&code_export, &manual};
    an::Anchor wild_quorum{};
    wild_quorum.kind = an::AnchorKind::Quorum;
    wild_quorum.quorum_members = wild_members;
    EXPECT_EQ(an::declared_domain(wild_quorum), an::ResultDomain::CodeSite);

    // Conflicting specific domains (a vtable and a code site) make the target ambiguous -> Unknown.
    an::Anchor vtable{};
    vtable.kind = an::AnchorKind::VtableIdentity;
    const an::Anchor *conflict_members[] = {&vtable, &code_export};
    an::Anchor conflict_quorum{};
    conflict_quorum.kind = an::AnchorKind::Quorum;
    conflict_quorum.quorum_members = conflict_members;
    EXPECT_EQ(an::declared_domain(conflict_quorum), an::ResultDomain::Unknown);
}

TEST(AnchorDomainTest, ResolvedReportStampsDomainOnlyWhenResolved)
{
    an::Anchor manual{};
    manual.kind = an::AnchorKind::Manual;
    manual.manual_value = 0x1234;
    const an::ResolvedAnchor resolved = an::resolve(manual);
    ASSERT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(resolved.domain, an::ResultDomain::Scalar);

    an::Anchor unset{}; // kind Unset -> fails closed, no domain
    const an::ResolvedAnchor failed = an::resolve(unset);
    ASSERT_EQ(failed.status, an::AnchorStatus::Failed);
    EXPECT_EQ(failed.domain, an::ResultDomain::Unknown);

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor code_operand{};
    code_operand.kind = an::AnchorKind::CodeOperand;
    code_operand.site = cands;
    code_operand.operand_index = 1;
    const an::ResolvedAnchor operand_resolved = an::resolve(code_operand, page.range());
    ASSERT_EQ(operand_resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(operand_resolved.domain, an::ResultDomain::Scalar);
}

TEST(AnchorDomainTest, ResultDomainToStringMapsEveryDomain)
{
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::Unknown), "Unknown");
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::CodeSite), "CodeSite");
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::DataAddress), "DataAddress");
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::VtableAddress), "VtableAddress");
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::Scalar), "Scalar");
}

TEST(AnchorDomainTest, ExportNameDomainFollowsResolvedPageClass)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    // A function export resolves onto executable pages -> stays CodeSite (mid-hookable).
    an::Anchor func{};
    func.kind = an::AnchorKind::ExportName;
    func.export_module = ExportFixture::MODULE_NAME;
    func.export_name = "compute_damage";
    const an::ResolvedAnchor func_resolved = an::resolve(func, dmk::Region::host());
    ASSERT_EQ(func_resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(func_resolved.domain, an::ResultDomain::CodeSite);

    // The data export lies in non-executable .rdata. Its CodeSite claim must become DataAddress before a mid-hook gate
    // reads it.
    an::Anchor data{};
    data.kind = an::AnchorKind::ExportName;
    data.export_module = ExportFixture::MODULE_NAME;
    data.export_name = "dmk_scan_marker";
    const an::ResolvedAnchor data_resolved = an::resolve(data, dmk::Region::host());
    ASSERT_EQ(data_resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(data_resolved.domain, an::ResultDomain::DataAddress);
}

// ScanProfile: setup-only defaults (broad-widen, deny-list, candidate order), applied without overriding explicit
// calls.

TEST(AnchorProfileTest, BroadDefaultWidensQuery)
{
    an::ScanProfile profile{};
    profile.default_broad_string_xref = true;
    sc::StringRefQuery query{};
    query.broad_match = false;
    const sc::StringRefQuery widened = an::apply_profile(profile, query);
    EXPECT_TRUE(widened.broad_match);
}

TEST(AnchorProfileTest, NeverDowngradesBroad)
{
    an::ScanProfile profile{}; // default_broad_string_xref stays false
    sc::StringRefQuery query{};
    query.broad_match = true; // an explicit broad request is never turned off by the profile
    const sc::StringRefQuery result = an::apply_profile(profile, query);
    EXPECT_TRUE(result.broad_match);
}

TEST(AnchorProfileTest, DenyBackendFailsClosed)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = site;
    anchor.operand_index = 1;

    an::ScanProfile profile{};
    profile.deny_backend[static_cast<std::size_t>(an::AnchorKind::CodeOperand)] = true;

    const an::ResolvedAnchor result = an::resolve_with_profile(anchor, profile, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0); // denied, never substituted with another backend's guess
}

TEST(AnchorProfileTest, QuorumWithDeniedSubAnchorFailsClosed)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0xF0;

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    an::ScanProfile profile{};
    profile.deny_backend[static_cast<std::size_t>(an::AnchorKind::CodeOperand)] = true; // threads into the sub-anchor

    const an::ResolvedAnchor result = an::resolve_with_profile(quorum, profile, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorProfileTest, ResolveAllWithProfileCarriesDeny)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor table[2]{};
    table[0].label = "manual";
    table[0].kind = an::AnchorKind::Manual;
    table[0].manual_value = 1;
    table[1].label = "code";
    table[1].kind = an::AnchorKind::CodeOperand;
    table[1].site = site;
    table[1].operand_index = 1;

    an::ScanProfile profile{};
    profile.deny_backend[static_cast<std::size_t>(an::AnchorKind::CodeOperand)] = true;

    an::ResolvedAnchor report[2]{};
    const std::size_t written = an::resolve_all_with_profile(table, report, profile, page.range());
    ASSERT_EQ(written, 2u);
    EXPECT_EQ(report[0].status, an::AnchorStatus::Resolved); // Manual is not denied
    EXPECT_EQ(report[1].status, an::AnchorStatus::Failed);   // CodeOperand is denied
}

TEST(AnchorProfileTest, ResolveAllWithProfileParallelMatchesSerialReport)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor table[3]{};
    table[0].kind = an::AnchorKind::Manual;
    table[0].manual_value = 9;
    table[1].kind = an::AnchorKind::CodeOperand;
    table[1].site = site;
    table[1].operand_index = 1;
    table[2].kind = an::AnchorKind::CallArgHome;

    an::ScanProfile profile{};
    profile.candidate_order = sc::CandidateOrder::UniqueFirst;

    an::ResolvedAnchor serial[3]{};
    an::ResolvedAnchor parallel[3]{};
    const std::size_t serial_count = an::resolve_all_with_profile(table, serial, profile, page.range());
    const std::size_t parallel_count = an::resolve_all_with_profile_parallel(table, parallel, profile, page.range(), 4);
    ASSERT_EQ(serial_count, parallel_count);
    for (std::size_t i = 0; i < serial_count; ++i)
    {
        EXPECT_EQ(parallel[i].status, serial[i].status);
        EXPECT_EQ(parallel[i].value, serial[i].value);
    }
}

TEST(AnchorProfileTest, AppliesCandidateOrderToRipGlobal)
{
    // The broad candidate matches the first instruction, and the specific candidate matches the second. The profile
    // must preserve the successful RipGlobal resolution.
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});

    const sc::Candidate cands[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = cands;

    an::ScanProfile profile{};
    profile.candidate_order = sc::CandidateOrder::UniqueFirst;

    const an::ResolvedAnchor result = an::resolve_with_profile(anchor, profile, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), page.addr(0x200));
}

// [B-100] anchor boundary. The Callback-safe trust and quality queries answer under the loader lock with no heap
// traffic, so a startup gate decision stays available there. Resolution can allocate, scan memory, or create threads.
TEST(AnchorLoaderBoundary, TrustAndQualityQueriesAreAllocationFree)
{
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::ExportName, an::AnchorStatus::Failed)
    };

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = "kernel32.dll";
    anchor.export_name = "Sleep";

    const sc::ImageIdentity identity = sc::image_identity();
    ASSERT_TRUE(identity.present());

    // Warm every route so a first-call cost is not charged to the measured window.
    (void)an::assess_quality(report);
    (void)an::anchor_fingerprint(anchor);
    (void)an::anchor_trust_fingerprint(anchor, identity);

    an::AnchorQuality quality{};
    an::GateVerdict verdict = an::GateVerdict::Pass;
    std::uint64_t fingerprint = 0;
    std::uint64_t trust_key = 0;
    long long allocations = -1;
    long long allocation_probe_delta = -1;
    std::unique_ptr<int[]> allocation_probe;

    {
        const dmk_test::ForcedLoaderProbe held;

        const long long before = dmk_test::thread_new_calls();
        quality = an::assess_quality(report);
        verdict = an::evaluate_gate(quality);
        fingerprint = an::anchor_fingerprint(anchor);
        trust_key = an::anchor_trust_fingerprint(anchor, identity);
        allocations = dmk_test::thread_new_calls() - before;

        const long long before_probe = dmk_test::thread_new_calls();
        allocation_probe = std::make_unique<int[]>(64);
        allocation_probe_delta = dmk_test::thread_new_calls() - before_probe;
    }

    EXPECT_EQ(allocations, 0LL) << "the Callback-safe anchor surface must stay heap-free under the loader lock";
    EXPECT_EQ(quality.total, static_cast<std::size_t>(3));
    EXPECT_EQ(quality.failed, static_cast<std::size_t>(1));
    EXPECT_EQ(verdict, an::GateVerdict::Fail) << "one failed anchor still fails the default policy under the lock";
    EXPECT_NE(fingerprint, 0U);
    EXPECT_NE(trust_key, 0U);
    ASSERT_NE(allocation_probe, nullptr);
    EXPECT_GT(allocation_probe_delta, 0LL) << "the permanent counter control must detect a real allocation";
}
