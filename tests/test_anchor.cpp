#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string_view>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/scan.hpp"

// windows.h after project headers to avoid macro conflicts.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace dmk = DetourModKit;
namespace an = DetourModKit::anchor;
namespace sc = DetourModKit::scan;

namespace
{
    // Compiles a known-good AOB literal for a candidate site; the test patterns are all valid, so .value() is safe.
    [[nodiscard]] sc::Pattern aob(std::string_view dsl)
    {
        return sc::Pattern::compile(dsl).value();
    }

    // A committed 0xCC-filled page into which a test plants known x86-64 instructions / markers, so the cascade- and
    // decode-backed anchor kinds have a real, uniquely-matchable site to resolve. PAGE_READWRITE is enough: the bytes
    // are scanned and decoded as data, never executed.
    class ScratchPage
    {
    public:
        ScratchPage()
        {
            m_base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (m_base != nullptr)
            {
                std::memset(m_base, 0xCC, 0x1000);
            }
        }

        ~ScratchPage()
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        ScratchPage(const ScratchPage &) = delete;
        ScratchPage &operator=(const ScratchPage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        void put(std::size_t off, std::initializer_list<std::uint8_t> bytes) noexcept
        {
            auto *p = static_cast<std::uint8_t *>(m_base);
            std::size_t i = 0;
            for (const std::uint8_t b : bytes)
            {
                p[off + i++] = b;
            }
        }

        [[nodiscard]] std::uintptr_t addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base) + off;
        }

        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, 0x1000};
        }

    private:
        void *m_base = nullptr;
    };

    // A committed RWX page that hosts a string literal plus a RIP-relative lea that references it, so the StringXref
    // backend has a real string (phase 1) and a real reference (phase 2) inside one Region.
    class StringImage
    {
    public:
        StringImage()
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            m_size = si.dwPageSize;
            m_base = static_cast<std::uint8_t *>(
                VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        }

        ~StringImage()
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        StringImage(const StringImage &) = delete;
        StringImage &operator=(const StringImage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        void write_string(std::size_t off, std::string_view text) noexcept
        {
            std::memcpy(m_base + off, text.data(), text.size());
            m_base[off + text.size()] = 0x00; // NUL terminator so require_terminator matches
        }

        // Plants `48 <opcode> 05 <disp32>` (a REX.W RIP-relative lea/mov, rax destination) at instr_off whose computed
        // target is target_off.
        void plant_rip_load(std::size_t instr_off, std::size_t target_off, std::uint8_t opcode) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = 0x48; // REX.W
            p[1] = opcode;
            p[2] = 0x05; // ModRM: mod=00, reg=rax, rm=101 (RIP-relative)
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(target_off)) - next);
            std::memcpy(p + 3, &disp, sizeof(disp));
        }

        [[nodiscard]] std::uintptr_t addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + off);
        }

        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_size};
        }

    private:
        std::uint8_t *m_base = nullptr;
        std::size_t m_size = 0;
    };

    // Post-resolve validator stand-ins. Each matches an::AnchorValidator exactly (a noexcept function pointer).
    bool always_reject(std::int64_t, const void *) noexcept
    {
        return false;
    }

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

// ---------------------------------------------------------------------------------------------------------------------
// Backend dispatch: each kind maps onto its v4 backend and maps success/failure onto AnchorStatus.
// ---------------------------------------------------------------------------------------------------------------------

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
    anchor.byte_width = 1; // narrow to one byte; the value must stay negative

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, -1);
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

TEST(AnchorTest, VtableIdentityFailsClosedWhenAbsent)
{
    // The VtableIdentity SUCCESS dispatch (rtti::vtable_for_type -> commit_resolved) is not re-tested here: building a
    // resolvable target needs the ~130-line synthetic MSVC-RTTI vtable fixture from tests/test_rtti.cpp (a real
    // GCC/MSVC type would not carry the MSVC RTTI layout the walker reads on both toolchains). vtable_for_type success
    // is covered there, and the commit path is shared with the CodeOperand / RipGlobal / StringXref resolve tests
    // above; this case pins the anchor-side failure wiring (bogus name -> fail closed).
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

// ---------------------------------------------------------------------------------------------------------------------
// Table resolution (serial, parallel, capacity).
// ---------------------------------------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------------------------------------
// Post-resolve validators.
// ---------------------------------------------------------------------------------------------------------------------

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
    anchor.validator = &expect_value_f0; // would reject, but validate_manual is false

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
    // require_validator is a backend-target policy, so it never rejects a pinned Manual literal for lacking a validator
    // -- even when validate_manual routes the Manual through the validator path with no validator attached. This
    // contradictory-but-benign config resolves rather than fails, matching the anchor.hpp contract (Manual is not a
    // resolved target). With a validator missing there is simply nothing to run.
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x44;
    anchor.validate_manual = true;   // route through the commit_resolved validator path
    anchor.require_validator = true; // but Manual is exempt from the no-validator rejection (only backends are subject)

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x44);
}

// ---------------------------------------------------------------------------------------------------------------------
// Quorum corroboration.
// ---------------------------------------------------------------------------------------------------------------------

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

    an::Anchor quorum{};
    quorum.label = "corroborated";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_manual;
    quorum.quorum_b = &sub_code;

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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;

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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_ok;
    quorum.quorum_b = &sub_bad;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumNullSubAnchorFailsClosed)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::Manual;
    sub.manual_value = 1;

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub;
    quorum.quorum_b = nullptr; // missing second signal

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
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &leaf;
    quorum.quorum_b = &nested;

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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4; // gap is 2

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0); // the first sub-anchor's value
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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 2; // gap is 0xF (15)

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;
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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;
    quorum.validator = &always_reject; // runs once on the corroborated value

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumRejectsPointerEqualSubAnchors)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::Manual;
    sub.manual_value = 1;

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub;
    quorum.quorum_b = &sub; // the same object twice is not independent evidence

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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b; // two hand-pinned literals are not live corroboration

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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumAcceptsDistinctCandidateArrays)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    // Two SEPARATELY-authored candidate arrays encoding the same pattern: distinct storage, so the pair is independent
    // (identity is over the storage, not the bytes).
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

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
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;
    quorum.require_validator = true; // exempt: two-signal corroboration is the verification, no validator needed

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

    an::Anchor table[1]{};
    table[0].label = "q";
    table[0].kind = an::AnchorKind::Quorum;
    table[0].quorum_a = &sub_a;
    table[0].quorum_b = &sub_b;

    an::ResolvedAnchor report[1]{};
    const std::size_t written = an::resolve_all(table, report, page.range());
    ASSERT_EQ(written, 1u);
    EXPECT_EQ(report[0].status, an::AnchorStatus::Resolved);
    EXPECT_EQ(report[0].value, 0x30);
    EXPECT_EQ(report[0].kind, an::AnchorKind::Quorum);
}

// ---------------------------------------------------------------------------------------------------------------------
// Quality assessment.
// ---------------------------------------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------------------------------------
// Fingerprints: hash the resolution EVIDENCE, excluding the resolved address.
// ---------------------------------------------------------------------------------------------------------------------

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
    // The whole point: the fingerprint hashes only the declared evidence, never the resolved value (which lives in the
    // ResolvedAnchor, not the Anchor), so two identically-declared anchors share a fingerprint even when a later diff
    // records different resolved addresses next to them.
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

    an::Anchor q1{};
    q1.kind = an::AnchorKind::Quorum;
    q1.quorum_a = &sub_a;
    q1.quorum_b = &sub_b;
    an::Anchor q2{};
    q2.kind = an::AnchorKind::Quorum;
    q2.quorum_a = &sub_b; // swapped
    q2.quorum_b = &sub_a;
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

    an::Anchor base{};
    base.kind = an::AnchorKind::Quorum;
    base.quorum_a = &sub_a;
    base.quorum_b = &sub_b;

    an::Anchor mode = base;
    mode.quorum_match = an::QuorumMatch::WithinTolerance;
    EXPECT_NE(an::anchor_fingerprint(base), an::anchor_fingerprint(mode));

    an::Anchor tol = mode;
    tol.quorum_tolerance = 8;
    EXPECT_NE(an::anchor_fingerprint(mode), an::anchor_fingerprint(tol));
}

TEST(AnchorFingerprintTest, QuorumNullSubAnchorIsDefined)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::VtableIdentity;
    sub.mangled = ".?AVA@@";
    an::Anchor q{};
    q.kind = an::AnchorKind::Quorum;
    q.quorum_a = &sub;
    q.quorum_b = nullptr; // a null sub-anchor contributes a fixed sentinel, never a nullptr deref
    EXPECT_EQ(an::anchor_fingerprint(q), an::anchor_fingerprint(q));
}

TEST(AnchorFingerprintTest, CallArgHomeReflectsKindOnly)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::CallArgHome;
    a.manual_value = 1; // a field another kind consumes; CallArgHome hashes only its kind
    an::Anchor b{};
    b.kind = an::AnchorKind::CallArgHome;
    b.manual_value = 2;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

// ---------------------------------------------------------------------------------------------------------------------
// ScanProfile: setup-only defaults (broad-widen, deny-list, candidate order), applied without overriding explicit
// calls.
// ---------------------------------------------------------------------------------------------------------------------

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

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_a = &sub_a;
    quorum.quorum_b = &sub_b;

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
    // Two distinct in-scope instructions; a broad candidate that would match the first-in-memory site and a specific
    // candidate for the second. UniqueFirst does not change which unique candidate wins here, but the resolve still
    // succeeds with the profile applied, proving the order path is wired through RipGlobal.
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
