#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <span>
#include <string>
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
    // decode-backed anchor kinds have a real, uniquely-matchable site to resolve. PAGE_EXECUTE_READWRITE, not
    // PAGE_READWRITE: a CodeOperand site is an instruction and read_code_constant scans Pages::Executable, so the
    // planted bytes must live on an execute-readable page (the bytes are still only decoded, never executed; the
    // execute bit is what the page-class gate keys on). RipGlobal markers resolve on this superset page too.
    class ScratchPage
    {
    public:
        ScratchPage()
        {
            m_base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

// The RipGlobal byte ladder honors the Anchor::pages knob. A byte run planted in a readable, NON-executable data page
// resolves under the default Readable class, but is invisible once the anchor narrows to Executable -- so a caller that
// knows its RipGlobal target is reached only through in-image code can reject a coincidental data-page twin and turn a
// fail-closed ambiguity into a clean resolve. The default stays Readable, so no existing anchor changes. A dedicated
// PAGE_READWRITE region is used here because ScratchPage is now execute-readable (for the CodeOperand tests).
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
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0 -- a single unique site
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

// The Anchor::pages knob is scan POLICY, not resolution evidence: it changes which pages are swept, never the target
// identity. So two RipGlobal members over the same site content that differ ONLY in pages are the same evidence and
// must not corroborate each other. The independence gate (fingerprint_independence_evidence) must ignore pages even
// though the drift fingerprint (anchor_fingerprint) folds it -- this locks that drift-vs-independence split for the
// pages flag. Distinct storage gives the test teeth: it can only pass because the CONTENT hashes equal with pages
// dropped; folding pages into the independence evidence would make the pair look independent and fail this.
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
    // Two ladders listing the SAME two rungs in DIFFERENT order. A fallback ladder's rungs all aim at one target, so a
    // reordered copy decodes the same site and is dependent evidence, not corroboration -- the independence gate must
    // be order-INDEPENDENT. (Here both rungs resolve to 0xF0, so a storage/order-sensitive gate would have let this
    // pair falsely corroborate; the fix reports QuorumNotIndependent before any resolve.)
    const sc::Candidate ladder_ab[] = {sc::Candidate::direct("a", aob("48 05 F0 00 00 00")),
                                       sc::Candidate::direct("b", aob("48 81 C1 F0 00 00 00"))};
    const sc::Candidate ladder_ba[] = {sc::Candidate::direct("b", aob("48 81 C1 F0 00 00 00")),
                                       sc::Candidate::direct("a", aob("48 05 F0 00 00 00"))};

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

TEST(AnchorTest, UnsetKindFailsClosed)
{
    // A default-constructed Anchor whose kind was never set (e.g. a designated-initializer table entry that omits
    // `kind`) must fail closed, not resolve as a trusted address 0. Unset is the fail-safe default.
    an::Anchor anchor{};
    EXPECT_EQ(anchor.kind, an::AnchorKind::Unset) << "a default-constructed Anchor must default to Unset";
    anchor.label = "forgot-the-kind";
    anchor.manual_value = 0; // a populated-but-ignored field, as a real misdeclaration would carry

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
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

    // 2-of-3: the third member fails to resolve, but the other two independent signals agree, so the target still
    // corroborates. A strict 2-of-2 or 3-of-3 quorum would have failed here.
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
    const sc::Candidate site_absent[] = {sc::Candidate::direct("absent", aob("11 22 33 44 55 66 77 88"))};

    an::Anchor by_hand{};
    by_hand.kind = an::AnchorKind::Manual;
    by_hand.manual_value = 0xF0;
    an::Anchor by_code{}; // fails: pattern not on the page
    by_code.kind = an::AnchorKind::CodeOperand;
    by_code.site = site_absent;
    by_code.operand_index = 1;
    an::Anchor by_scan{}; // fails: pattern not on the page
    by_scan.kind = an::AnchorKind::RipGlobal;
    by_scan.site = site_absent;

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

    // Two of three independent members agree on 0xF0; the third resolves to a different value and is outvoted.
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

    // Two of three members are within tolerance of 0xF0 and form the accepting cluster; the far member is excluded.
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

    // One member is a single signal, not corroboration; a quorum needs at least two members.
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

    // The dependent pair is (first, third), which are not adjacent in the member list: independence is checked over
    // ALL pairs, not just neighbours, so the whole vote fails as non-independent.
    const an::Anchor *members[] = {&first, &second, &third};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
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

// Fingerprints: hash the resolution EVIDENCE, excluding the resolved address.

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

    // A RipGlobal folds the page class as a single trailing FNV-1a byte, and only when it is non-default. Replicate
    // that one fold step (using the FNV-1a 64 prime the fingerprint hashes with) so the check has teeth: the Executable
    // digest must equal the Readable digest with exactly the Executable byte folded on top. That equality holds ONLY if
    // the default Readable folded nothing, which is the baseline stability that keeps fingerprints captured before the
    // page class existed valid. Comparing two identical Readable anchors instead would pass unconditionally and prove
    // nothing; here a regression that started folding Readable would leave an extra byte in the Readable digest and
    // break the equality.
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
    // Two RipGlobal cascades of the same cardinality cover the identical "AA BB CC" stream, differing only in where
    // the boundary between patterns falls: [AA BB][CC] vs [AA][BB CC]. Each pattern's bytes/mask are length-prefixed in
    // the fingerprint, so the prefix pins each pattern's extent and moving the boundary is different evidence.
    const sc::Candidate split_left[] = {sc::Candidate::direct("c0", aob("AA BB")),
                                        sc::Candidate::direct("c1", aob("CC"))};
    const sc::Candidate split_right[] = {sc::Candidate::direct("c0", aob("AA")),
                                         sc::Candidate::direct("c1", aob("BB CC"))};
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
    const sc::Candidate two[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??")),
                                 sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
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

    // Two quorums with the same members but a different vote threshold are a different corroboration contract, so
    // their fingerprints must differ (2-of-3 vs the unanimous default).
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
    // Two anchors with identical evidence (same kind + inputs) hash to the same member evidence, so the quorum
    // fingerprint must fold each evidence value once PER member, not once per distinct value. Otherwise {A, A, B}
    // and {A, B, B} -- the same distinct set at different multiplicity -- would collide. This locks the
    // duplicate-counting step of the allocation-free sorted fold.
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
    // The allocation-free sorted fold must stay order-independent even when two members share evidence: {A, A, B}
    // and {A, B, A} are the same multiset and must fingerprint identically.
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
    a.manual_value = 1; // a field another kind consumes; CallArgHome hashes only its kind
    an::Anchor b{};
    b.kind = an::AnchorKind::CallArgHome;
    b.manual_value = 2;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
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

// Drift-telemetry gate: assess_quality summary -> GateVerdict startup enable/disable decision.

namespace
{
    // Builds one synthetic ResolvedAnchor so a gate test can assemble an exact drift report without resolving real
    // anchors; only kind and status feed the quality summary the gate reads.
    [[nodiscard]] an::ResolvedAnchor ra(an::AnchorKind kind, an::AnchorStatus status)
    {
        return an::ResolvedAnchor{.label = "t", .kind = kind, .status = status, .value = 0};
    }
} // namespace

TEST(AnchorGateTest, AllResolvedPassesDefaultPolicy)
{
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::VtableIdentity, an::AnchorStatus::Resolved)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, FailedAnchorFailsDefaultPolicy)
{
    // Default max_failed is 0, so a single failure disables the feature regardless of how many others resolved.
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::CodeOperand, an::AnchorStatus::Failed)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, QuorumNotIndependentCountsAsHardFailure)
{
    // A quorum whose sub-anchors were not independent committed no value; it fails closed and counts against max_failed
    // exactly like a Failed anchor.
    const std::array<an::ResolvedAnchor, 2> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::Quorum, an::AnchorStatus::QuorumNotIndependent)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, PartialResolveIsGatedByRatio)
{
    // One of three resolvable anchors resolved; the other two are Unresolved (an untouched slot still drags the ratio).
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved)};

    // 1/3 < 0.5 -> Fail.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 0.5}), an::GateVerdict::Fail);
    // 1/3 >= 0.3 -> clears the ratio; no failure and no manual, so Pass.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 0.3}), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, UnsupportedKindExcludedFromDenominator)
{
    // Two resolved plus one CallArgHome (no resolver, always Unsupported). Under the strict default ratio 1.0 the
    // unsupported kind must NOT be counted against the manifest, so 2/2 resolvable resolved -> Pass.
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, ResolvedManualDowngradesToDegraded)
{
    // Every anchor resolved, but one is a pinned Manual literal that cannot self-heal: Degraded by default...
    const std::array<an::ResolvedAnchor, 2> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::Manual, an::AnchorStatus::Resolved)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Degraded);
    // ...but a policy that opts out of the manual downgrade treats it as a plain Pass.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.manual_at_risk_degrades = false}), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, EmptyReportIsDegraded)
{
    // No anchors means no evidence for the gate to assess; never report it as healthy.
    EXPECT_EQ(an::evaluate_gate(std::span<const an::ResolvedAnchor>{}), an::GateVerdict::Degraded);
}

TEST(AnchorGateTest, AllUnsupportedReportIsDegraded)
{
    // A non-empty report with nothing assessable proves nothing about health: Degraded, never a false Pass.
    const std::array<an::ResolvedAnchor, 2> report{ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported),
                                                   ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Degraded);
}

TEST(AnchorGateTest, MaxFailedToleratesConfiguredFailures)
{
    // Two failures with a cap of two clears the hard-failure gate; the remaining resolved fraction then decides. Here
    // 1 resolved of 3 resolvable at ratio 0.3 passes the ratio, so the verdict is Pass.
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Failed),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Failed)};
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 0.3, .max_failed = 2}),
              an::GateVerdict::Pass);
    // One below the cap still fails.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 0.3, .max_failed = 1}),
              an::GateVerdict::Fail);
}

TEST(AnchorGateTest, OutOfRangeRatioIsClamped)
{
    const std::array<an::ResolvedAnchor, 2> report{ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved)};
    // A ratio above 1.0 clamps to 1.0 (still requires every resolvable anchor): 1/2 -> Fail.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 5.0}), an::GateVerdict::Fail);
    // A negative ratio clamps to 0.0 (any resolved fraction clears it): Pass.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = -1.0}), an::GateVerdict::Pass);
    // NaN is treated as the strict default, not as a threshold that silently passes every report.
    const an::GatePolicy nan_policy{.min_resolved_ratio = std::numeric_limits<double>::quiet_NaN()};
    EXPECT_EQ(an::evaluate_gate(report, nan_policy), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, SpanOverloadMatchesQualityOverload)
{
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::Manual, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::CodeOperand, an::AnchorStatus::Failed)};
    const an::GatePolicy policy{.min_resolved_ratio = 0.5, .max_failed = 1};
    EXPECT_EQ(an::evaluate_gate(report, policy), an::evaluate_gate(an::assess_quality(report), policy));
}

TEST(AnchorGateTest, InconsistentQualitySummaryFailsClosed)
{
    const an::AnchorQuality quality{.total = 1, .resolved = 2};
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
