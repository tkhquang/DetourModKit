#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/scan.hpp"

#include "internal/export_resolution.hpp"

#include "fixtures/scratch_page.hpp"

#include <windows.h>
#include "fixtures/anchor_fixture.hpp"
using namespace dmk_test::anchor_fixture;

TEST(AnchorTest, QuorumRejectsDualSameExport)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    // Two ExportName members on the same module + name resolve the identical EAT entry, even when the case-insensitive
    // Windows module basename is spelled differently. They are one signal, not independent corroboration, so the
    // export evidence atom must make the quorum fail QuorumNotIndependent.
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::ExportName;
    sub_a.export_module = ExportFixture::MODULE_NAME;
    sub_a.export_name = "compute_damage";
    an::Anchor sub_b = sub_a;
    sub_b.export_module = "HOOK_TARGET_LIB.DLL";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumAcceptsExportCorroboratedByManual)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    const std::uintptr_t address = fixture.proc("compute_critical");
    ASSERT_NE(address, 0U);

    // Export and Manual supply independent evidence for the same address.
    an::Anchor export_member{};
    export_member.kind = an::AnchorKind::ExportName;
    export_member.export_module = ExportFixture::MODULE_NAME;
    export_member.export_name = "compute_critical";
    an::Anchor manual_member{};
    manual_member.kind = an::AnchorKind::Manual;
    manual_member.manual_value = static_cast<std::int64_t>(address);

    const an::Anchor *members[] = {&export_member, &manual_member};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), address);
}

// Both exports name one function through distinct entries and ordinals. Their shared RVA makes one physical failure
// source.
TEST(AnchorTest, QuorumRejectsAliasedExportsOverOneTarget)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    const std::uintptr_t primary = fixture.proc("dmk_export_alias_one");
    const std::uintptr_t secondary = fixture.proc("dmk_export_alias_two");
    ASSERT_NE(primary, 0U);
    // Distinct function addresses invalidate the alias premise.
    ASSERT_EQ(primary, secondary) << "the fixture no longer exports an alias pair over one target";

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::ExportName;
    sub_a.export_module = ExportFixture::MODULE_NAME;
    sub_a.export_name = "dmk_export_alias_one";
    an::Anchor sub_b = sub_a;
    sub_b.export_name = "dmk_export_alias_two";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);

    // A disjoint second member still corroborates the export alias. The export backend alone cannot explain a
    // dependency refusal.
    an::Anchor manual_member{};
    manual_member.kind = an::AnchorKind::Manual;
    manual_member.manual_value = static_cast<std::int64_t>(primary);
    const an::Anchor *mixed[] = {&sub_a, &manual_member};
    quorum.quorum_members = mixed;

    const an::ResolvedAnchor corroborated = an::resolve(quorum, dmk::Region::host());
    EXPECT_EQ(corroborated.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(corroborated.value), primary);
}

// The other alias shape: two names sharing ONE name-ordinal, so both read the same AddressOfFunctions slot. No linker
// this project builds with emits that layout, so the table is written by hand.
TEST(AnchorTest, QuorumRejectsSameOrdinalExportAliases)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());

    constexpr std::uint32_t alias_name_rva = SyntheticExportImage::NAME_RVA + 0x20;
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.NumberOfNames = 2;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);
    image.put(SyntheticExportImage::NAMES_RVA + sizeof(std::uint32_t), alias_name_rva);
    // Both name entries index function slot 0, so the two names are one table entry read twice.
    image.put(SyntheticExportImage::ORDINALS_RVA + sizeof(std::uint16_t), std::uint16_t{0});
    image.put_string(alias_name_rva, "fixture_export_alias");

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::ExportName;
    sub_a.export_name = "fixture_export";
    an::Anchor sub_b = sub_a;
    sub_b.export_name = "fixture_export_alias";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// A shared EAT slot survives a concurrent RVA rewrite. Target identity and slot identity need separate controls.
TEST(AnchorTest, ExportProvenanceNamesTheSlotAndTheTarget)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    const dmk::Region module = dmk::Region::module_named(ExportFixture::MODULE_NAME);
    dmk::detail::ExportResolution one;
    dmk::detail::ExportResolution two;
    const dmk::Result<dmk::Address> one_result =
        dmk::detail::resolve_export_with_provenance("dmk_export_alias_one", module, one);
    const dmk::Result<dmk::Address> two_result =
        dmk::detail::resolve_export_with_provenance("dmk_export_alias_two", module, two);
    ASSERT_TRUE(one_result.has_value());
    ASSERT_TRUE(two_result.has_value());
    EXPECT_TRUE(one.present());
    EXPECT_EQ(one.module_base, module.base.raw());
    EXPECT_EQ(one.module_base, two.module_base);
    EXPECT_NE(one.function_index, two.function_index);
    EXPECT_EQ(one.function_rva, two.function_rva);
    EXPECT_EQ(one.target, two.target);
    EXPECT_EQ(one.target, *one_result);
    EXPECT_EQ(two.target, *two_result);
    EXPECT_EQ(one.target.raw(), one.module_base + one.function_rva);
    EXPECT_TRUE(dmk::detail::same_export_site(one, two));

    // A genuinely different export shares neither field, so the correlation does not swallow independent evidence.
    dmk::detail::ExportResolution other;
    ASSERT_TRUE(dmk::detail::resolve_export_with_provenance("compute_armor", module, other).has_value());
    EXPECT_NE(other.function_rva, one.function_rva);
    EXPECT_FALSE(dmk::detail::same_export_site(one, other));

    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::uint32_t alias_name_rva = SyntheticExportImage::NAME_RVA + 0x20;
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.NumberOfNames = 2;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);
    image.put(SyntheticExportImage::NAMES_RVA + sizeof(std::uint32_t), alias_name_rva);
    image.put(SyntheticExportImage::ORDINALS_RVA + sizeof(std::uint16_t), std::uint16_t{0});
    image.put_string(alias_name_rva, "fixture_export_alias");

    dmk::detail::ExportResolution syn_one;
    dmk::detail::ExportResolution syn_two;
    const dmk::Result<dmk::Address> syn_one_result =
        dmk::detail::resolve_export_with_provenance("fixture_export", image.range(), syn_one);
    const dmk::Result<dmk::Address> syn_two_result =
        dmk::detail::resolve_export_with_provenance("fixture_export_alias", image.range(), syn_two);
    ASSERT_TRUE(syn_one_result.has_value());
    ASSERT_TRUE(syn_two_result.has_value());
    EXPECT_EQ(syn_one.module_base, image.range().base.raw());
    EXPECT_EQ(syn_one.function_index, 0U);
    EXPECT_EQ(syn_one.function_rva, SyntheticExportImage::TARGET_RVA);
    EXPECT_EQ(syn_one.target, *syn_one_result);
    EXPECT_EQ(syn_one.target.raw(), image.range().base.raw() + SyntheticExportImage::TARGET_RVA);
    EXPECT_EQ(syn_two.target, *syn_two_result);
    EXPECT_EQ(syn_one.function_index, syn_two.function_index);
    EXPECT_TRUE(dmk::detail::same_export_site(syn_one, syn_two));

    // The writer changes one EAT slot between resolves. Different resolved targets still share that physical slot.
    const dmk::detail::ExportResolution rewritten{
        .module_base = syn_one.module_base,
        .function_index = syn_one.function_index,
        .function_rva = syn_one.function_rva + 0x10,
        .target = dmk::Address{syn_one.target.raw() + 0x10},
    };
    EXPECT_NE(rewritten.function_rva, syn_one.function_rva);
    EXPECT_TRUE(dmk::detail::same_export_site(syn_one, rewritten));

    SyntheticExportImage other_image;
    ASSERT_TRUE(other_image.ok());
    dmk::detail::ExportResolution other_image_resolution;
    const dmk::Result<dmk::Address> other_image_result =
        dmk::detail::resolve_export_with_provenance("fixture_export", other_image.range(), other_image_resolution);
    ASSERT_TRUE(other_image_result.has_value());
    EXPECT_NE(other_image_resolution.module_base, syn_one.module_base);
    EXPECT_EQ(other_image_resolution.function_index, syn_one.function_index);
    EXPECT_EQ(other_image_resolution.function_rva, syn_one.function_rva);
    EXPECT_EQ(other_image_resolution.target, *other_image_result);
    EXPECT_EQ(
        other_image_resolution.target.raw(),
        other_image_resolution.module_base + other_image_resolution.function_rva
    );
    EXPECT_FALSE(dmk::detail::same_export_site(syn_one, other_image_resolution));
}

// Quorum corroboration.

TEST(AnchorTest, QuorumAcceptsWhenSignalsAgree)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.label = "corroborated";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members; // default threshold 0 == unanimous == the strict 2-of-2

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumRejectsDifferentPatternsOverOneCodeOperandSite)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate exact[] = {sc::Candidate::direct("exact", aob("48 05 F0 00 00 00"))};
    const sc::Candidate wildcard[] = {sc::Candidate::direct("wildcard", aob("48 05 ?? 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = exact;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = wildcard;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// Both members read one instruction but vote for different values: its address and its immediate. Physical overlap must
// outrank the failed value cluster.
TEST(AnchorTest, QuorumRejectsOverlappingMembersAheadOfValueClustering)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    // Distinct compiled patterns, so the declaration-atom gate passes them through to the physical check.
    const sc::Candidate exact[] = {sc::Candidate::direct("exact", aob("48 05 F0 00 00 00"))};
    const sc::Candidate wildcard[] = {sc::Candidate::direct("wildcard", aob("48 05 ?? 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = exact;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = wildcard;
    sub_b.operand_kind = sc::OperandKind::Immediate;
    sub_b.operand_index = 1;

    // Control: the members really do resolve, and really do disagree.
    const an::ResolvedAnchor alone_a = an::resolve(sub_a, page.range());
    ASSERT_EQ(alone_a.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(alone_a.value, static_cast<std::int64_t>(page.addr(0x100)));
    const an::ResolvedAnchor alone_b = an::resolve(sub_b, page.range());
    ASSERT_EQ(alone_b.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(alone_b.value, 0xF0);
    ASSERT_NE(alone_a.value, alone_b.value);

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumRejectsCrossKindVotesFromOneInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    image.plant_rip_load(0x100, 0x500, 0x8B);
    const sc::Candidate target[] = {sc::Candidate::rip_relative("target", aob("48 8B 05 ?? ?? ?? ??"), 3, 7)};
    const sc::Candidate operand[] = {sc::Candidate::direct("operand", aob("48 8B 05 ?? ?? ?? ??"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = target;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = operand;
    sub_b.operand_kind = sc::OperandKind::MemoryDisplacement;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumRejectsCodeOperandWalkedBackOntoAnotherWinnersInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    image.plant_rip_load(0x100, 0x500, 0x8B); // 48 8B 05 <disp32>: mov rax, [rip+disp32]
    constexpr char LANDMARK[] = "\x11\x22\x33\x44\x55\x66\x77\x88";
    image.write_string(0x0F0, std::string_view{LANDMARK, 8});

    // The RIP match skips REX and decodes `8B 05 <disp32>`. Its span starts inside the same instruction.
    const sc::Candidate shifted[] = {sc::Candidate::rip_relative("shifted", aob("8B 05 ?? ?? ?? ??"), 2, 6)};
    // The operand match ends before the instruction and walks forward. Its authored span does not overlap the RIP
    // match.
    const sc::Candidate landmark[] = {sc::Candidate::direct("landmark", aob("11 22 33 44 55 66 77 88"), 0x10)};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = shifted;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = landmark;
    sub_b.operand_kind = sc::OperandKind::MemoryDisplacement;
    sub_b.operand_index = 1;

    // Each member resolves alone, so disagreement cannot explain quorum refusal.
    const an::ResolvedAnchor alone_a = an::resolve(sub_a, image.range());
    ASSERT_EQ(alone_a.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(alone_a.value, static_cast<std::int64_t>(image.addr(0x500)));
    const an::ResolvedAnchor alone_b = an::resolve(sub_b, image.range());
    ASSERT_EQ(alone_b.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(alone_b.value, static_cast<std::int64_t>(image.addr(0x500)));

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    // One patched disp32 breaks both votes at once, so the decoded instruction's whole extent is one failure domain.
    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumRejectsDifferentResultMarkersOverOnePhysicalSpan)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});
    const sc::Candidate at_start[] = {sc::Candidate::direct("start", aob("48 05 F0 00 00 00"))};
    const sc::Candidate after_prefix[] = {sc::Candidate::direct("offset", aob("48 | 05 F0 00 00 00"), -1)};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = at_start;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = after_prefix;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumAcceptsDistinctRipInstructionsWithOneTarget)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    image.plant_rip_load(0x100, 0x500, 0x8B);
    image.plant_rip_load(0x180, 0x500, 0x8D);
    const sc::Candidate mov[] = {sc::Candidate::rip_relative("mov", aob("48 8B 05 ?? ?? ?? ??"), 3, 7)};
    const sc::Candidate lea[] = {sc::Candidate::rip_relative("lea", aob("48 8D 05 ?? ?? ?? ??"), 3, 7)};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = mov;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = lea;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, static_cast<std::int64_t>(image.addr(0x500)));
}

TEST(AnchorTest, QuorumAcceptsAcrossBackends)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site_code[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor sub_manual{};
    sub_manual.kind = an::AnchorKind::Manual;
    sub_manual.manual_value = 0xF0;
    an::Anchor sub_code{};
    sub_code.kind = an::AnchorKind::CodeOperand;
    sub_code.site = site_code;
    sub_code.operand_index = 1;

    const an::Anchor *members[] = {&sub_manual, &sub_code};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumFailsWhenSignalsDisagree)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xE0, 0x00, 0x00, 0x00}); // add rcx, 0xE0
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 E0 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumFailsWhenOneSignalFails)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site_ok[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_absent[] = {sc::Candidate::direct("absent", aob("11 22 33 44 55 66 77 88"))};

    an::Anchor sub_ok{};
    sub_ok.kind = an::AnchorKind::CodeOperand;
    sub_ok.site = site_ok;
    sub_ok.operand_index = 1;
    an::Anchor sub_bad{};
    sub_bad.kind = an::AnchorKind::RipGlobal;
    sub_bad.site = site_absent;

    const an::Anchor *members[] = {&sub_ok, &sub_bad};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumNullSubAnchorFailsClosed)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::Manual;
    sub.manual_value = 1;

    const an::Anchor *members[] = {&sub, nullptr}; // a null member fails the quorum closed
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumRejectsNestedQuorum)
{
    an::Anchor leaf{};
    leaf.kind = an::AnchorKind::Manual;
    leaf.manual_value = 1;
    an::Anchor nested{};
    nested.kind = an::AnchorKind::Quorum; // a Quorum as a sub-anchor is rejected (nesting bounded to one level)
    const an::Anchor *members[] = {&leaf, &nested};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumWithinToleranceAcceptsCloseValues)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF2, 0x00, 0x00, 0x00}); // add rcx, 0xF2
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F2 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4; // gap is 2

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0); // the cluster center (first member's value)
}

TEST(AnchorTest, QuorumWithinToleranceRejectsDistantValues)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xFF, 0x00, 0x00, 0x00}); // add rcx, 0xFF
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 FF 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 2; // gap is 0xF (15)

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

// With votes {0, 4, 8}, threshold 3, and tolerance 4, only center 4 has three votes in range. Check every member order
// and the two-tolerance span.
TEST(AnchorTest, QuorumWithinToleranceCommitsTheCanonicalCenterForEveryMemberOrder)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x00, 0x00, 0x00, 0x00});       // add rax, 0x0
    page.put(0x140, {0x48, 0x81, 0xC1, 0x04, 0x00, 0x00, 0x00}); // add rcx, 0x4
    page.put(0x180, {0x48, 0x81, 0xC2, 0x08, 0x00, 0x00, 0x00}); // add rdx, 0x8
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 00 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 04 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 08 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::CodeOperand;
    sub_c.site = site_c;
    sub_c.operand_index = 1;

    std::array<const an::Anchor *, 3> members{&sub_a, &sub_b, &sub_c};
    std::sort(members.begin(), members.end());
    do
    {
        an::Anchor quorum{};
        quorum.kind = an::AnchorKind::Quorum;
        quorum.quorum_members = std::span<const an::Anchor *const>{members};
        quorum.quorum_threshold = 3;
        quorum.quorum_match = an::QuorumMatch::WithinTolerance;
        quorum.quorum_tolerance = 4;

        const an::ResolvedAnchor result = an::resolve(quorum, page.range());
        EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
        EXPECT_EQ(result.value, 4);
    } while (std::next_permutation(members.begin(), members.end()));
}

TEST(AnchorTest, QuorumRejectsNegativeTolerance)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0x10;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand; // distinct kind, so the pair is independent

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x10, 0x00, 0x00, 0x00}); // add rax, 0x10 (equals sub_a's value)
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 10 00 00 00"))};
    sub_b.site = site;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = -1; // a negative tolerance never accepts, even for equal values

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumHonoursOwnValidator)
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
    quorum.validator = &always_reject; // runs once on the corroborated value

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumRejectsPointerEqualSubAnchors)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::Manual;
    sub.manual_value = 1;

    const an::Anchor *members[] = {&sub, &sub}; // the same object twice is not independent evidence
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsDualManual)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 5;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::Manual;
    sub_b.manual_value = 5;

    const an::Anchor *members[] = {&sub_a, &sub_b}; // two hand-pinned literals are not live corroboration
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsSameBackendConfig)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site; // SAME storage
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site; // SAME storage -> same backend config
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsContentEqualCandidateArrays)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0: a single unique site
    // Two SEPARATELY-authored candidate arrays encoding the SAME pattern with the SAME decode params. They compile to
    // byte-identical patterns and therefore decode one identical site, so they are the same evidence and cannot
    // corroborate each other. Independence is over the pattern CONTENT, not the storage: distinct arrays that express
    // the same signature must NOT vote twice.
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    ASSERT_NE(static_cast<const void *>(site_a), static_cast<const void *>(site_b))
        << "the two ladders must live in distinct storage for this test to have teeth";

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsDifferentDescriptorsOverOnePhysicalSite)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xAD, 0xBE});

    // All three patterns resolve the same physical site. Their distinct gap descriptors are authored selectors, not
    // independent runtime evidence, so they must collapse to one failure domain.
    const sc::Candidate after_first[] = {sc::Candidate::direct("a", aob("DE [1] AD BE"))};
    const sc::Candidate after_second[] = {sc::Candidate::direct("b", aob("DE AD [1] BE"))};
    const sc::Candidate wider[] = {sc::Candidate::direct("c", aob("DE [1-2] AD BE"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = after_first;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = after_second;
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::RipGlobal;
    sub_c.site = wider;

    const an::Anchor *members[] = {&sub_a, &sub_b, &sub_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// Distinct storage and page policies still describe one site. The case distinguishes independence evidence from the
// drift fingerprint.
TEST(AnchorTest, QuorumRejectsMembersDifferingOnlyInPageClass)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});
    const sc::Candidate site_a[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    ASSERT_NE(static_cast<const void *>(site_a), static_cast<const void *>(site_b))
        << "the two ladders must live in distinct storage for this test to have teeth";

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = site_a;
    sub_a.pages = sc::Pages::Readable;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable; // differs ONLY in page policy, which is not independent evidence

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsReorderedIdenticalLadders)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    // Both rung orders resolve to 0xF0. The independence gate must identify the shared rung content before resolution.
    const sc::Candidate ladder_ab[] = {
        sc::Candidate::direct("a", aob("48 05 F0 00 00 00")),
        sc::Candidate::direct("b", aob("48 81 C1 F0 00 00 00"))
    };
    const sc::Candidate ladder_ba[] = {
        sc::Candidate::direct("b", aob("48 81 C1 F0 00 00 00")),
        sc::Candidate::direct("a", aob("48 05 F0 00 00 00"))
    };

    an::Anchor sub_ab{};
    sub_ab.kind = an::AnchorKind::CodeOperand;
    sub_ab.site = ladder_ab;
    sub_ab.operand_index = 1;
    an::Anchor sub_ba{};
    sub_ba.kind = an::AnchorKind::CodeOperand;
    sub_ba.site = ladder_ba;
    sub_ba.operand_index = 1;

    const an::Anchor *members[] = {&sub_ab, &sub_ba};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// Different broad_match, require_terminator, and return_mode facets still identify one literal. A tolerance vote cannot
// supply independent evidence.
TEST(AnchorTest, QuorumRejectsStringXrefDifferingOnlyInScanPolicy)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = "CombatSystem::ApplyDamage";
    sub_a.xref_broad_match = false;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::StringXref;
    sub_b.xref_text = "CombatSystem::ApplyDamage";
    sub_b.xref_broad_match = true; // differs ONLY in scan policy, which is not independent evidence

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// The flat StringXref and the RipGlobal rung use one literal. Different AnchorKind wrappers cannot supply a second
// signal.
TEST(AnchorTest, QuorumRejectsCrossKindStringEvidence)
{
    const sc::Candidate rip_site[] = {sc::Candidate::string_xref("wrapped", "CameraFovLiteral")};

    an::Anchor flat{};
    flat.kind = an::AnchorKind::StringXref;
    flat.xref_text = "CameraFovLiteral";
    an::Anchor wrapped{};
    wrapped.kind = an::AnchorKind::RipGlobal;
    wrapped.site = rip_site; // a RipGlobal ladder whose one rung is the same string literal

    const an::Anchor *members[] = {&flat, &wrapped};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// Distinct literals pass the independence gate. The absent reference then produces Failed rather than
// QuorumNotIndependent.
TEST(AnchorTest, QuorumAcceptsDifferentLiteralsAsIndependent)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = "FirstDistinctQuorumLiteral";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::StringXref;
    sub_b.xref_text = "SecondDistinctQuorumLiteral";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_NE(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// Both members read one 10-byte `mov dword [rip+disp32], imm32`. Their authored spans only abut, so provenance needs
// the full decoded instruction.
TEST(AnchorTest, QuorumRejectsRungMatchingAnotherWinnersTrailingImmediate)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    // At 0x100, C7 05 targets 0x300 through disp32 and carries the distinctive immediate DE C0 AD 0B.
    constexpr std::size_t instruction_offset = 0x100;
    constexpr std::size_t target_offset = 0x300;
    const std::uintptr_t instruction_address = page.addr(instruction_offset);
    const auto displacement = static_cast<std::int32_t>(
        static_cast<std::int64_t>(page.addr(target_offset)) - static_cast<std::int64_t>(instruction_address + 10)
    );
    const auto disp_byte = [displacement](unsigned shift) noexcept
    { return static_cast<std::uint8_t>((static_cast<std::uint32_t>(displacement) >> shift) & 0xFFu); };
    page.put(
        instruction_offset,
        {0xC7, 0x05, disp_byte(0), disp_byte(8), disp_byte(16), disp_byte(24), 0xDE, 0xC0, 0xAD, 0x0B}
    );

    const sc::Candidate head[] = {sc::Candidate::rip_relative("rip-head", aob("C7 05 ?? ?? ?? ??"), 2, 10)};
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = head;
    sub_a.pages = sc::Pages::Executable;

    // Direct matches the trailing immediate and walks back arithmetically. It performs no decode that can separate this
    // physical evidence.
    const auto walk_back =
        static_cast<std::ptrdiff_t>(target_offset) - static_cast<std::ptrdiff_t>(instruction_offset + 6);
    const sc::Candidate tail[] = {sc::Candidate::direct("immediate-tail", aob("DE C0 AD 0B"), walk_back)};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = tail;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// The literal and byte-pattern atoms differ but resolve to one instruction. Physical spans must prevent that double
// vote.
TEST(AnchorTest, QuorumRejectsStringXrefOverlappingAnotherWinnersInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumPhysicalOverlapLiteralMarker";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = literal;

    // Direct mode returns the match itself, so this rung commits the very instruction the xref reference resolved to.
    const sc::Candidate site_b[] = {sc::Candidate::direct("same-instruction", aob("48 8D 05 ?? ?? ?? ??"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// The StringXref rung reaches the same reference as the flat kind. A ladder cannot supply new physical provenance.
TEST(AnchorTest, QuorumRejectsStringXrefRungOverlappingAnotherWinnersInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumLadderOverlapLiteralMarker";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]

    const sc::Candidate site_a[] = {sc::Candidate::string_xref("xref-rung", std::string{literal})};
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = site_a;

    const sc::Candidate site_b[] = {sc::Candidate::direct("same-instruction", aob("48 8D 05 ?? ?? ?? ??"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// Disjoint instructions agree on one value. This control preserves cross-backend corroboration.
TEST(AnchorTest, QuorumAcceptsStringXrefAndDistinctRipInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumDisjointEvidenceLiteralMarker";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // The xref uses `lea rax, [rip+string]`.
    image.plant_rip_load(0x200, 0x100, 0x8B); // A separate `mov rax, [rip+lea]` targets the same address.

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = literal;

    const sc::Candidate site_b[] = {
        sc::Candidate::rip_relative("distinct-instruction", aob("48 8B 05 ?? ?? ?? ??"), 3, 7)
    };
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), image.addr(0x100));
}

// The reference selects a store whose disp32 supplies the result. The store span must overlap a member that reads those
// same four bytes.
TEST(AnchorTest, QuorumRejectsStringPointerSlotOverlappingTheStoreItDecoded)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumSlotStoreOverlapLiteralMarker";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]
    image.plant_rip_store(0x107, 0x600);      // mov [rip+slot], rax, immediately after the lea

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = literal;
    sub_a.xref_return = sc::XrefReturn::StringPointerSlot;

    const sc::Candidate site_b[] = {sc::Candidate::rip_relative("same-store", aob("48 89 05 ?? ?? ?? ??"), 3, 7)};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// The broad sweep publishes the full instruction extent. A selector inside that extent must count as dependent
// evidence.
TEST(AnchorTest, QuorumRejectsBroadOnlyReferenceMatchedFromItsInteriorBytes)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumBroadReferenceExtentMarker";
    image.write_string(0x400, literal);
    image.plant_broad_only_rip_load(0x100, 0x400); // lea eax, [rip+string]: no REX, so narrow-invisible
    image.put(0x106, {0xDE, 0xAD, 0xBE, 0xEF});    // distinctive tail so the co-voting rung is unique

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = literal;
    sub_a.xref_broad_match = true;

    // The match starts at the reference's second byte and walks back one. Its span remains inside the resolved
    // instruction.
    const sc::Candidate site_b[] = {sc::Candidate::direct("interior", aob("05 ?? ?? ?? ?? DE AD BE EF"), -1)};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// Different ladders share one fallback rung. Their atom sets overlap even when their complete fingerprints differ.
TEST(AnchorTest, QuorumRejectsPartialLadderOverlap)
{
    // Both ladders carry the SAME second rung ("48 05 F0 00 00 00") and a DIFFERENT first rung. Same operand selector,
    // so the shared rung yields the same evidence atom in both members.
    const sc::Candidate ladder_a[] = {
        sc::Candidate::direct("a-primary", aob("48 81 C1 F0 00 00 00")),
        sc::Candidate::direct("shared", aob("48 05 F0 00 00 00"))
    };
    const sc::Candidate ladder_b[] = {
        sc::Candidate::direct("b-primary", aob("48 81 C2 F0 00 00 00")),
        sc::Candidate::direct("shared", aob("48 05 F0 00 00 00"))
    };

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = ladder_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = ladder_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumExemptFromRequireValidator)
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
    quorum.require_validator = true; // exempt: N-of-M corroboration is the verification, no validator needed

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, ResolveAllCarriesQuorum)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0x30;

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x30, 0x00, 0x00, 0x00}); // add rax, 0x30
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 30 00 00 00"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor table[1]{};
    table[0].label = "q";
    table[0].kind = an::AnchorKind::Quorum;
    table[0].quorum_members = members;

    an::ResolvedAnchor report[1]{};
    const std::size_t written = an::resolve_all(table, report, page.range());
    ASSERT_EQ(written, 1u);
    EXPECT_EQ(report[0].status, an::AnchorStatus::Resolved);
    EXPECT_EQ(report[0].value, 0x30);
    EXPECT_EQ(report[0].kind, an::AnchorKind::Quorum);
}

// N-of-M voting: at least N of M independent members must resolve and agree.

TEST(AnchorTest, QuorumNofMResolvesWhenThresholdMetDespiteFailure)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site_code[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_absent[] = {sc::Candidate::direct("absent", aob("11 22 33 44 55 66 77 88"))};

    an::Anchor by_hand{};
    by_hand.kind = an::AnchorKind::Manual;
    by_hand.manual_value = 0xF0;
    an::Anchor by_code{};
    by_code.kind = an::AnchorKind::CodeOperand;
    by_code.site = site_code;
    by_code.operand_index = 1;
    an::Anchor by_scan{}; // this signal is broken on the "patch": its pattern is not present
    by_scan.kind = an::AnchorKind::RipGlobal;
    by_scan.site = site_absent;

    // Two independent members agree, and the third fails to resolve. This isolates the 2-of-3 threshold.
    const an::Anchor *members[] = {&by_hand, &by_code, &by_scan};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumNofMFailsBelowThreshold)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    // The absent patterns identify distinct sites. Shared-site failures reach the independence gate before the
    // below-threshold path.
    const sc::Candidate site_absent_a[] = {sc::Candidate::direct("absent-a", aob("11 22 33 44 55 66 77 88"))};
    const sc::Candidate site_absent_b[] = {sc::Candidate::direct("absent-b", aob("99 AA BB CC DD EE FF 00"))};

    an::Anchor by_hand{};
    by_hand.kind = an::AnchorKind::Manual;
    by_hand.manual_value = 0xF0;
    an::Anchor by_code{}; // fails: pattern not on the page
    by_code.kind = an::AnchorKind::CodeOperand;
    by_code.site = site_absent_a;
    by_code.operand_index = 1;
    an::Anchor by_scan{}; // fails: pattern not on the page
    by_scan.kind = an::AnchorKind::RipGlobal;
    by_scan.site = site_absent_b;

    // Only one of three members resolves, below the 2-of-3 threshold, so a lone signal cannot masquerade as
    // corroborated.
    const an::Anchor *members[] = {&by_hand, &by_code, &by_scan};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumNofMOutvotesDisagreeingMember)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    page.put(0x180, {0x48, 0x81, 0xC2, 0xE0, 0x00, 0x00, 0x00}); // add rdx, 0xE0 (the odd one out)
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 E0 00 00 00"))};

    an::Anchor agree_a{};
    agree_a.kind = an::AnchorKind::CodeOperand;
    agree_a.site = site_a;
    agree_a.operand_index = 1;
    an::Anchor agree_b{};
    agree_b.kind = an::AnchorKind::CodeOperand;
    agree_b.site = site_b;
    agree_b.operand_index = 1;
    an::Anchor dissent{};
    dissent.kind = an::AnchorKind::CodeOperand;
    dissent.site = site_c;
    dissent.operand_index = 1;

    // Two independent members agree on 0xF0 and outvote the third.
    const an::Anchor *members[] = {&agree_a, &agree_b, &dissent};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumDefaultThresholdResolvesWhenUnanimous)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    page.put(0x180, {0x48, 0x81, 0xC2, 0xF0, 0x00, 0x00, 0x00}); // add rdx, 0xF0
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 F0 00 00 00"))};

    an::Anchor m_a{};
    m_a.kind = an::AnchorKind::CodeOperand;
    m_a.site = site_a;
    m_a.operand_index = 1;
    an::Anchor m_b{};
    m_b.kind = an::AnchorKind::CodeOperand;
    m_b.site = site_b;
    m_b.operand_index = 1;
    an::Anchor m_c{};
    m_c.kind = an::AnchorKind::CodeOperand;
    m_c.site = site_c;
    m_c.operand_index = 1;

    // Default threshold 0 means unanimous: all three members must agree.
    const an::Anchor *members[] = {&m_a, &m_b, &m_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumDefaultThresholdFailsWithoutUnanimity)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    page.put(0x180, {0x48, 0x81, 0xC2, 0xE0, 0x00, 0x00, 0x00}); // add rdx, 0xE0 (breaks unanimity)
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 E0 00 00 00"))};

    an::Anchor m_a{};
    m_a.kind = an::AnchorKind::CodeOperand;
    m_a.site = site_a;
    m_a.operand_index = 1;
    an::Anchor m_b{};
    m_b.kind = an::AnchorKind::CodeOperand;
    m_b.site = site_b;
    m_b.operand_index = 1;
    an::Anchor m_c{};
    m_c.kind = an::AnchorKind::CodeOperand;
    m_c.site = site_c;
    m_c.operand_index = 1;

    // Two members agree but the default threshold demands unanimity, so a 2-of-3 majority is not enough.
    const an::Anchor *members[] = {&m_a, &m_b, &m_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumWithinToleranceNofMFormsCluster)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF2, 0x00, 0x00, 0x00}); // add rcx, 0xF2 (gap 2 from 0xF0)
    page.put(0x180, {0x48, 0x81, 0xC2, 0xFF, 0x00, 0x00, 0x00}); // add rdx, 0xFF (gap 15, outside tolerance)
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F2 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 FF 00 00 00"))};

    an::Anchor near_a{};
    near_a.kind = an::AnchorKind::CodeOperand;
    near_a.site = site_a;
    near_a.operand_index = 1;
    an::Anchor near_b{};
    near_b.kind = an::AnchorKind::CodeOperand;
    near_b.site = site_b;
    near_b.operand_index = 1;
    an::Anchor far_c{};
    far_c.kind = an::AnchorKind::CodeOperand;
    far_c.site = site_c;
    far_c.operand_index = 1;

    // Two members form a cluster within tolerance of 0xF0. The far member stays outside that cluster.
    const an::Anchor *members[] = {&near_a, &near_b, &far_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0); // the cluster center
}

TEST(AnchorTest, QuorumThresholdBelowTwoFailsClosed)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0xF0;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVAbsent@@";

    // A quorum is corroboration, so a threshold of 1 (accept any lone signal) is a malformed vote and fails closed.
    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 1;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumThresholdAboveMemberCountFailsClosed)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0xF0;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVAbsent@@";

    // Demanding more agreeing votes than there are members can never be satisfied, so it is malformed and fails closed.
    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 3;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumEmptyMembersFailsClosed)
{
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum; // quorum_members left empty

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumSingleMemberFailsClosed)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::Manual;
    sub.manual_value = 1;

    // One member cannot corroborate its own signal.
    const an::Anchor *members[] = {&sub};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumRejectsDependentPairAmongIndependentMembers)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    const sc::Candidate site_shared[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_other[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};

    an::Anchor first{};
    first.kind = an::AnchorKind::CodeOperand;
    first.site = site_shared;
    first.operand_index = 1;
    an::Anchor second{};
    second.kind = an::AnchorKind::CodeOperand;
    second.site = site_other;
    second.operand_index = 1;
    an::Anchor third{}; // SAME storage as first -> a dependent pair the all-pairs check must catch
    third.kind = an::AnchorKind::CodeOperand;
    third.site = site_shared;
    third.operand_index = 1;

    // The first and third members depend on one site. Adjacent-pair checks alone cannot detect that dependency.
    const an::Anchor *members[] = {&first, &second, &third};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// Two disagreeing values each meet the threshold. Member order cannot resolve that ambiguity. Physical correlations
// still count as one witness.

TEST(AnchorQuorumTest, MultipleQualifyingClustersAreOrderInvariantOrAmbiguous)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x10, 0x00, 0x00, 0x00});       // add rax, 0x10
    page.put(0x140, {0x48, 0x81, 0xC1, 0x10, 0x00, 0x00, 0x00}); // add rcx, 0x10
    page.put(0x180, {0x48, 0x81, 0xC2, 0x20, 0x00, 0x00, 0x00}); // add rdx, 0x20
    page.put(0x1C0, {0x48, 0x81, 0xC3, 0x20, 0x00, 0x00, 0x00}); // add rbx, 0x20
    const sc::Candidate site_a[] = {sc::Candidate::direct("a", aob("48 05 10 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("b", aob("48 81 C1 10 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("c", aob("48 81 C2 20 00 00 00"))};
    const sc::Candidate site_d[] = {sc::Candidate::direct("d", aob("48 81 C3 20 00 00 00"))};

    // Four independent CodeOperands resolving to 0x10, 0x10, 0x20, 0x20: two exact clusters of two, N = 2. Both clear
    // the threshold and disagree, so declaration order must not pick one: the vote is ambiguous, in ANY order.
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::CodeOperand;
    sub_c.site = site_c;
    sub_c.operand_index = 1;
    an::Anchor sub_d{};
    sub_d.kind = an::AnchorKind::CodeOperand;
    sub_d.site = site_d;
    sub_d.operand_index = 1;

    const an::Anchor *forward[] = {&sub_a, &sub_b, &sub_c, &sub_d};
    const an::Anchor *reversed[] = {&sub_d, &sub_c, &sub_b, &sub_a};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_threshold = 2;

    quorum.quorum_members = forward;
    const an::ResolvedAnchor forward_result = an::resolve(quorum, page.range());
    quorum.quorum_members = reversed;
    const an::ResolvedAnchor reversed_result = an::resolve(quorum, page.range());

    EXPECT_EQ(forward_result.status, an::AnchorStatus::QuorumAmbiguous);
    EXPECT_EQ(reversed_result.status, an::AnchorStatus::QuorumAmbiguous);
}

TEST(AnchorQuorumTest, OverlappingToleranceCentersAreAmbiguous)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x10, 0x00, 0x00, 0x00});       // add rax, 0x10
    page.put(0x140, {0x48, 0x81, 0xC1, 0x14, 0x00, 0x00, 0x00}); // add rcx, 0x14
    page.put(0x180, {0x48, 0x81, 0xC2, 0x18, 0x00, 0x00, 0x00}); // add rdx, 0x18
    const sc::Candidate site_a[] = {sc::Candidate::direct("a", aob("48 05 10 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("b", aob("48 81 C1 14 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("c", aob("48 81 C2 18 00 00 00"))};

    // At tolerance 4, 0x10 and 0x18 each match 0x14 but differ by 8. The overlapping centers must remain ambiguous.
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::CodeOperand;
    sub_c.site = site_c;
    sub_c.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b, &sub_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumAmbiguous);
}

TEST(AnchorQuorumTest, SingleClusterWinnerIsOrderInvariant)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF2, 0x00, 0x00, 0x00}); // add rcx, 0xF2
    const sc::Candidate site_a[] = {sc::Candidate::direct("a", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("b", aob("48 81 C1 F2 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    // One agreement cluster (gap 2 <= tolerance 4). The committed value is the canonical (smallest) member value,
    // 0xF0, regardless of which member is declared first.
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4;

    const an::Anchor *forward[] = {&sub_a, &sub_b};
    const an::Anchor *reversed[] = {&sub_b, &sub_a};
    quorum.quorum_members = forward;
    const an::ResolvedAnchor forward_result = an::resolve(quorum, page.range());
    quorum.quorum_members = reversed;
    const an::ResolvedAnchor reversed_result = an::resolve(quorum, page.range());

    EXPECT_EQ(forward_result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(forward_result.value, 0xF0);
    EXPECT_EQ(reversed_result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(reversed_result.value, 0xF0);
}

TEST(AnchorQuorumTest, CorrelatedPhysicalSourceCannotDoubleVote)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    // imul rax, qword ptr [rbp+0xF0], 0xF0: two resolvable constants in one instruction/failure domain.
    page.put(0x100, {0x48, 0x69, 0x85, 0xF0, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00});
    const sc::Candidate site_a[] = {sc::Candidate::direct("op-a", aob("48 69 85 F0 00 00 00 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("op-b", aob("48 69 85 F0 00 00 00 F0 00 00 00"))};

    // Two CodeOperands over the SAME instruction site that merely select a different operand. One patch to that
    // instruction breaks both, so they are one witness, not two: the site alone keys the failure domain.
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    sub_a.operand_kind = sc::OperandKind::MemoryDisplacement;
    sub_a.byte_width = 4;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 2;
    sub_b.operand_kind = sc::OperandKind::Immediate;
    sub_b.byte_width = 4;

    ASSERT_EQ(an::resolve(sub_a, page.range()).value, 0xF0);
    ASSERT_EQ(an::resolve(sub_b, page.range()).value, 0xF0);

    const an::Anchor *operand_members[] = {&sub_a, &sub_b};
    an::Anchor operand_quorum{};
    operand_quorum.kind = an::AnchorKind::Quorum;
    operand_quorum.quorum_members = operand_members;
    EXPECT_EQ(an::resolve(operand_quorum, page.range()).status, an::AnchorStatus::QuorumNotIndependent);

    // The empty and explicit export modules identify one EAT entry in this scope.
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    an::Anchor export_scoped{};
    export_scoped.kind = an::AnchorKind::ExportName;
    export_scoped.export_name = "compute_damage"; // module empty -> resolves within the scope
    an::Anchor export_named{};
    export_named.kind = an::AnchorKind::ExportName;
    export_named.export_module = ExportFixture::MODULE_NAME;
    export_named.export_name = "compute_damage";

    const an::Anchor *export_members[] = {&export_scoped, &export_named};
    an::Anchor export_quorum{};
    export_quorum.kind = an::AnchorKind::Quorum;
    export_quorum.quorum_members = export_members;
    EXPECT_EQ(
        an::resolve(export_quorum, dmk::Region::module_named(ExportFixture::MODULE_NAME)).status,
        an::AnchorStatus::QuorumNotIndependent
    );
}

TEST(AnchorQuorumTest, OrderAndPhysicalIndependenceAgree)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x42, 0x00, 0x00, 0x00});       // add rax, 0x42
    page.put(0x140, {0x48, 0x81, 0xC1, 0x44, 0x00, 0x00, 0x00}); // add rcx, 0x44
    const sc::Candidate site_a[] = {sc::Candidate::direct("a", aob("48 05 42 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("b", aob("48 81 C1 44 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 2;

    // The reversed order distinguishes the canonical minimum 0x42 from the first vote 0x44.
    const an::Anchor *forward[] = {&sub_a, &sub_b};
    const an::Anchor *reversed[] = {&sub_b, &sub_a};
    quorum.quorum_members = forward;
    const an::ResolvedAnchor forward_result = an::resolve(quorum, page.range());
    quorum.quorum_members = reversed;
    const an::ResolvedAnchor reversed_result = an::resolve(quorum, page.range());
    EXPECT_EQ(forward_result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(forward_result.value, 0x42);
    EXPECT_EQ(reversed_result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(reversed_result.value, 0x42);

    // Both members read one physical site. Either member order must produce QuorumNotIndependent.
    an::Anchor dep_a = sub_a;
    an::Anchor dep_b = sub_b;
    dep_b.site = site_a; // the same site as dep_a
    const an::Anchor *dep_forward[] = {&dep_a, &dep_b};
    const an::Anchor *dep_reversed[] = {&dep_b, &dep_a};
    quorum.quorum_members = dep_forward;
    EXPECT_EQ(an::resolve(quorum, page.range()).status, an::AnchorStatus::QuorumNotIndependent);
    quorum.quorum_members = dep_reversed;
    EXPECT_EQ(an::resolve(quorum, page.range()).status, an::AnchorStatus::QuorumNotIndependent);
}
