#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>

#include "DetourModKit/anchors.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/scanner.hpp"

// windows.h after project headers to avoid macro conflicts.
#include <windows.h>

using namespace DetourModKit;

namespace
{
    // A committed page (0xCC filled) for planting instruction bytes / markers that the cascade- and decode-backed
    // anchor kinds resolve against.
    class Region
    {
    public:
        Region()
        {
            m_base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (m_base)
            {
                std::memset(m_base, 0xCC, 0x1000);
            }
        }

        ~Region()
        {
            if (m_base)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        Region(const Region &) = delete;
        Region &operator=(const Region &) = delete;

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

        [[nodiscard]] Memory::ModuleRange range() const noexcept
        {
            const auto base = reinterpret_cast<std::uintptr_t>(m_base);
            return Memory::ModuleRange{base, base + 0x1000};
        }

    private:
        void *m_base = nullptr;
    };

    // Post-resolve validator stand-ins for the validator tests. Each signature matches Anchors::AnchorValidator exactly
    // (a noexcept function pointer).
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

TEST(AnchorsTest, ManualResolvesToLiteral)
{
    Anchors::Anchor anchor{};
    anchor.label = "manual";
    anchor.kind = Anchors::AnchorKind::Manual;
    anchor.manual_value = 0x1234;

    const auto result = Anchors::resolve(anchor);
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x1234);
    EXPECT_EQ(result.kind, Anchors::AnchorKind::Manual);
    EXPECT_EQ(result.label, "manual");
}

TEST(AnchorsTest, CallArgHomeIsUnsupported)
{
    Anchors::Anchor anchor{};
    anchor.label = "arghome";
    anchor.kind = Anchors::AnchorKind::CallArgHome;

    const auto result = Anchors::resolve(anchor);
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Unsupported);
}

TEST(AnchorsTest, CodeOperandResolvesImmediate)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor{};
    anchor.label = "stride";
    anchor.kind = Anchors::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_kind = Scanner::OperandKind::Immediate;
    anchor.operand_index = 1;

    const auto result = Anchors::resolve(anchor, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorsTest, RipGlobalResolvesToAddress)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});

    Scanner::AddrCandidate cands[] = {
        {"marker", "DE AD BE EF 10 20 30 40", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor{};
    anchor.label = "global";
    anchor.kind = Anchors::AnchorKind::RipGlobal;
    anchor.site = cands;

    const auto result = Anchors::resolve(anchor, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), reg.addr(0x200));
}

TEST(AnchorsTest, VtableIdentityFailsClosedWhenAbsent)
{
    Region reg;
    ASSERT_TRUE(reg.ok());

    Anchors::Anchor anchor{};
    anchor.label = "vt";
    anchor.kind = Anchors::AnchorKind::VtableIdentity;
    anchor.mangled = ".?AVAnchorAbsent@@";

    // The region carries no RTTI, so the backend must fail closed (not crash and not invent a value).
    const auto result = Anchors::resolve(anchor, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
}

TEST(AnchorsTest, ResolveAllWritesParallelReport)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };

    Anchors::Anchor a0{};
    a0.label = "lit";
    a0.kind = Anchors::AnchorKind::Manual;
    a0.manual_value = 7;

    Anchors::Anchor a1{};
    a1.label = "code";
    a1.kind = Anchors::AnchorKind::CodeOperand;
    a1.site = cands;
    a1.operand_index = 1;

    Anchors::Anchor a2{};
    a2.label = "future";
    a2.kind = Anchors::AnchorKind::CallArgHome;

    const Anchors::Anchor table[] = {a0, a1, a2};
    Anchors::ResolvedAnchor out[3];

    const std::size_t n = Anchors::resolve_all(table, out, reg.range());
    ASSERT_EQ(n, 3u);
    EXPECT_EQ(out[0].status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(out[0].value, 7);
    EXPECT_EQ(out[1].status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(out[1].value, 0xF0);
    EXPECT_EQ(out[2].status, Anchors::AnchorStatus::Unsupported);
    EXPECT_EQ(out[0].label, "lit");

    // kind must propagate through the batch path for every entry.
    EXPECT_EQ(out[0].kind, Anchors::AnchorKind::Manual);
    EXPECT_EQ(out[1].kind, Anchors::AnchorKind::CodeOperand);
    EXPECT_EQ(out[2].kind, Anchors::AnchorKind::CallArgHome);
}

TEST(AnchorsTest, ResolveAllParallelMatchesSerialReport)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});
    reg.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF});

    Scanner::AddrCandidate code_cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::AddrCandidate global_cands[] = {
        {"marker", "DE AD BE EF", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::AddrCandidate absent_cands[] = {
        {"absent", "13 57 9B DF 02 46 8A CE", Scanner::ResolveMode::Direct, 0, 0},
    };

    Anchors::Anchor manual{};
    manual.label = "manual";
    manual.kind = Anchors::AnchorKind::Manual;
    manual.manual_value = 0x1234;

    Anchors::Anchor code{};
    code.label = "code";
    code.kind = Anchors::AnchorKind::CodeOperand;
    code.site = code_cands;
    code.operand_index = 1;

    Anchors::Anchor global{};
    global.label = "global";
    global.kind = Anchors::AnchorKind::RipGlobal;
    global.site = global_cands;

    Anchors::Anchor absent{};
    absent.label = "absent";
    absent.kind = Anchors::AnchorKind::RipGlobal;
    absent.site = absent_cands;

    Anchors::Anchor unsupported{};
    unsupported.label = "future";
    unsupported.kind = Anchors::AnchorKind::CallArgHome;

    const Anchors::Anchor table[] = {manual, code, global, absent, unsupported};
    Anchors::ResolvedAnchor serial[5];
    Anchors::ResolvedAnchor parallel[5];

    const std::size_t serial_count = Anchors::resolve_all(table, serial, reg.range());
    const std::size_t parallel_count = Anchors::resolve_all_parallel(table, parallel, reg.range(), 4);
    // Pin both counts to the known table size so the per-entry loop below cannot pass vacuously (a bug that
    // wrote zero entries would still satisfy a bare serial == parallel check).
    ASSERT_EQ(serial_count, 5u);
    ASSERT_EQ(parallel_count, 5u);
    ASSERT_EQ(parallel_count, serial_count);

    for (std::size_t i = 0; i < serial_count; ++i)
    {
        EXPECT_EQ(parallel[i].label, serial[i].label) << "entry=" << i;
        EXPECT_EQ(parallel[i].kind, serial[i].kind) << "entry=" << i;
        EXPECT_EQ(parallel[i].status, serial[i].status) << "entry=" << i;
        EXPECT_EQ(parallel[i].value, serial[i].value) << "entry=" << i;
    }
}

TEST(AnchorsTest, ResolveAllRespectsCapacity)
{
    Anchors::Anchor anchor{};
    anchor.kind = Anchors::AnchorKind::Manual;
    anchor.manual_value = 1;

    const Anchors::Anchor table[] = {anchor, anchor, anchor};
    Anchors::ResolvedAnchor out[2]; // smaller than the table

    EXPECT_EQ(Anchors::resolve_all(table, out, Memory::host_module_range()), 2u);
}

TEST(AnchorsTest, RipGlobalAbsentSignatureFailsClosed)
{
    Region reg;
    ASSERT_TRUE(reg.ok());

    Scanner::AddrCandidate cands[] = {
        {"absent", "13 57 9B DF 02 46 8A CE 11 33 55 77", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor{};
    anchor.label = "global";
    anchor.kind = Anchors::AnchorKind::RipGlobal;
    anchor.site = cands;

    // A cascade miss maps to AnchorStatus::Failed with no value invented.
    const auto result = Anchors::resolve(anchor, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorsTest, CodeOperandResolvesDisplacementWithByteWidth)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]

    Scanner::AddrCandidate cands[] = {
        {"disp8", "8A 45 FF", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor{};
    anchor.label = "slot";
    anchor.kind = Anchors::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_kind = Scanner::OperandKind::MemoryDisplacement; // non-default kind
    anchor.operand_index = 1;
    anchor.byte_width = 1; // non-default width: proves both fields reach read_code_constant

    const auto result = Anchors::resolve(anchor, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, -1);
}

TEST(AnchorsTest, StringXrefResolvesReference)
{
    // StringXref phase 2 scans execute-readable pages, so this case needs an executable page rather than the read-write
    // Region helper.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;
    auto *base =
        static_cast<std::uint8_t *>(VirtualAlloc(nullptr, page, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!base)
    {
        GTEST_SKIP() << "could not allocate an executable page";
    }
    std::memset(base, 0x00, page);
    const char marker[] = "AnchorRegistryString";
    std::memcpy(base + 0x100, marker, sizeof(marker));
    // lea rax, [rip+disp32] at 0x10 resolving to the string at 0x100.
    base[0x10] = 0x48;
    base[0x11] = 0x8D;
    base[0x12] = 0x05;
    const auto base_addr = reinterpret_cast<std::uintptr_t>(base);
    const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(base_addr + 0x100) -
                                                static_cast<std::int64_t>(base_addr + 0x10 + 7));
    std::memcpy(base + 0x13, &disp, sizeof(disp));

    Anchors::Anchor anchor{};
    anchor.label = "string-xref";
    anchor.kind = Anchors::AnchorKind::StringXref;
    anchor.xref_text = "AnchorRegistryString";

    const auto result = Anchors::resolve(anchor, Memory::ModuleRange{base_addr, base_addr + page});
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), base_addr + 0x10);
    EXPECT_EQ(result.kind, Anchors::AnchorKind::StringXref);

    VirtualFree(base, 0, MEM_RELEASE);
}

TEST(AnchorsTest, StringXrefFailsClosedWhenAbsent)
{
    Region reg;
    ASSERT_TRUE(reg.ok());

    Anchors::Anchor anchor{};
    anchor.label = "string-xref";
    anchor.kind = Anchors::AnchorKind::StringXref;
    anchor.xref_text = "DefinitelyNotInThisRegion";

    // The string is absent, so the backend fails closed (no value invented).
    const auto result = Anchors::resolve(anchor, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorsTest, StatusToStringNonEmpty)
{
    EXPECT_FALSE(Anchors::anchor_status_to_string(Anchors::AnchorStatus::Unresolved).empty());
    EXPECT_FALSE(Anchors::anchor_status_to_string(Anchors::AnchorStatus::Resolved).empty());
    EXPECT_FALSE(Anchors::anchor_status_to_string(Anchors::AnchorStatus::Failed).empty());
    EXPECT_FALSE(Anchors::anchor_status_to_string(Anchors::AnchorStatus::Unsupported).empty());
    EXPECT_FALSE(Anchors::anchor_status_to_string(Anchors::AnchorStatus::QuorumNotIndependent).empty());
    EXPECT_EQ(Anchors::anchor_status_to_string(Anchors::AnchorStatus::QuorumNotIndependent), "QuorumNotIndependent");
}

// --- Optional post-resolve validators ---

TEST(AnchorsTest, ValidatorRejectionFailsClosed)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor{};
    anchor.label = "stride";
    anchor.kind = Anchors::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_index = 1;
    anchor.validator = always_reject;

    // The backend resolves 0xF0, but the validator rejects it: fail closed exactly like a backend miss (Failed, value
    // reset to 0).
    const auto result = Anchors::resolve(anchor, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorsTest, ValidatorAcceptSeesResolvedValue)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor{};
    anchor.kind = Anchors::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_index = 1;
    anchor.validator = expect_value_f0; // accepts only if it actually receives 0xF0

    const auto result = Anchors::resolve(anchor, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorsTest, ValidatorContextPassesThrough)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor{};
    anchor.kind = Anchors::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_index = 1;
    anchor.validator = require_context_token;
    anchor.validator_context = &s_validator_context_token;

    // The predicate accepts only when it receives the exact context pointer.
    EXPECT_EQ(Anchors::resolve(anchor, reg.range()).status, Anchors::AnchorStatus::Resolved);

    // Without the matching context the same predicate rejects.
    anchor.validator_context = nullptr;
    EXPECT_EQ(Anchors::resolve(anchor, reg.range()).status, Anchors::AnchorStatus::Failed);
}

TEST(AnchorsTest, ValidatorNotAppliedToManual)
{
    Anchors::Anchor anchor{};
    anchor.kind = Anchors::AnchorKind::Manual;
    anchor.manual_value = 0x1234;
    anchor.validator = always_reject; // a pinned literal is exempt; this is ignored

    const auto result = Anchors::resolve(anchor);
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x1234);
}

TEST(AnchorsTest, ValidatorNotAppliedToCallArgHome)
{
    Anchors::Anchor anchor{};
    anchor.kind = Anchors::AnchorKind::CallArgHome;
    anchor.validator = always_reject; // the unsupported kind is exempt; this is ignored

    EXPECT_EQ(Anchors::resolve(anchor).status, Anchors::AnchorStatus::Unsupported);
}

// --- Quorum: two independent signals must resolve and agree ---

TEST(AnchorsTest, QuorumAcceptsWhenSignalsAgree)
{
    // Independence requires two distinct backends: corroborate a decoded code constant against a pinned literal of the
    // same value (a dual-Manual pair would be rejected as non-independent before agreement is considered).
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0xF0;

    Anchors::Anchor quorum{};
    quorum.label = "quorum";
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0); // the first sub-anchor's value, the two agreeing
    EXPECT_EQ(result.kind, Anchors::AnchorKind::Quorum);
}

TEST(AnchorsTest, QuorumAcceptsAcrossBackends)
{
    // The canonical use: corroborate a decoded code constant against an independent signal of the same value (here a
    // pinned expectation).
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor code{};
    code.kind = Anchors::AnchorKind::CodeOperand;
    code.site = cands;
    code.operand_index = 1;

    Anchors::Anchor expected{};
    expected.kind = Anchors::AnchorKind::Manual;
    expected.manual_value = 0xF0;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &code;
    quorum.quorum_b = &expected;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorsTest, QuorumFailsWhenSignalsDisagree)
{
    // Two independent backends that resolve to different values: corroboration is impossible, so fail closed (this is
    // distinct from the non-independence rejection, which would short-circuit before either resolves).
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0x5000; // disagrees with the decoded 0xF0

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorsTest, QuorumFailsWhenOneSignalFails)
{
    Region reg;
    ASSERT_TRUE(reg.ok());

    Anchors::Anchor good{};
    good.kind = Anchors::AnchorKind::Manual;
    good.manual_value = 0x4000;

    Scanner::AddrCandidate absent[] = {
        {"absent", "13 57 9B DF 02 46 8A CE 11 33 55 77", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor failing{};
    failing.kind = Anchors::AnchorKind::RipGlobal;
    failing.site = absent;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &good;
    quorum.quorum_b = &failing;

    // One signal cannot resolve, so corroboration is impossible: fail closed.
    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
}

TEST(AnchorsTest, QuorumNullSubAnchorFailsClosed)
{
    Anchors::Anchor only{};
    only.kind = Anchors::AnchorKind::Manual;
    only.manual_value = 0x4000;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &only;
    quorum.quorum_b = nullptr; // missing second signal

    const auto result = Anchors::resolve(quorum);
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
}

TEST(AnchorsTest, QuorumRejectsNestedQuorum)
{
    Anchors::Anchor leaf{};
    leaf.kind = Anchors::AnchorKind::Manual;
    leaf.manual_value = 0x4000;

    Anchors::Anchor inner{};
    inner.kind = Anchors::AnchorKind::Quorum;
    inner.quorum_a = &leaf;
    inner.quorum_b = &leaf;

    Anchors::Anchor outer{};
    outer.kind = Anchors::AnchorKind::Quorum;
    outer.quorum_a = &inner; // a sub-anchor that is itself a Quorum
    outer.quorum_b = &leaf;

    // Nesting is rejected to bound recursion to one level.
    const auto result = Anchors::resolve(outer);
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
}

TEST(AnchorsTest, QuorumWithinToleranceAcceptsCloseValues)
{
    // Two independent backends within tolerance accept: a decoded 0xF0 corroborated by a pinned 0xF8 (delta 8 <= 0x10).
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0xF8;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;
    quorum.quorum_match = Anchors::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 0x10;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorsTest, QuorumWithinToleranceRejectsDistantValues)
{
    // Two independent backends outside tolerance fail closed: a decoded 0xF0 against a pinned 0x1F0 (delta 0x100 >
    // 0x10).
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0x1F0;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;
    quorum.quorum_match = Anchors::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 0x10;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
}

TEST(AnchorsTest, QuorumRejectsNegativeTolerance)
{
    // A negative tolerance must fail closed. If it were widened to unsigned it would become a huge bound and wrongly
    // accept these far-apart values. Uses two independent backends so the test exercises the tolerance path, not the
    // independence gate.
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0x1F0;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;
    quorum.quorum_match = Anchors::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = -1;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
}

TEST(AnchorsTest, QuorumHonoursOwnValidator)
{
    // Two independent signals agree, but the Quorum anchor's own validator rejects the corroborated value: the commit
    // path must apply it and fail closed.
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0xF0;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;
    quorum.validator = always_reject;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
}

TEST(AnchorsTest, ResolveAllCarriesQuorum)
{
    // A Quorum routed through the batch path with two independent signals: a decoded code constant corroborated by a
    // pinned literal of the same value.
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0xF0;

    Anchors::Anchor quorum{};
    quorum.label = "q";
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;

    const Anchors::Anchor table[] = {quorum};
    Anchors::ResolvedAnchor out[1];
    const std::size_t n = Anchors::resolve_all(table, out, reg.range());
    ASSERT_EQ(n, 1u);
    EXPECT_EQ(out[0].status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(out[0].kind, Anchors::AnchorKind::Quorum);
    EXPECT_EQ(out[0].value, 0xF0);
}

// --- Quorum independence: a dependent sub-anchor pair can never masquerade as corroboration ---

TEST(AnchorsTest, QuorumRejectsPointerEqualSubAnchors)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor code{};
    code.kind = Anchors::AnchorKind::CodeOperand;
    code.site = cands;
    code.operand_index = 1;

    // The same object used twice is one signal, not two: reject before resolving.
    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &code;
    quorum.quorum_b = &code;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorsTest, QuorumRejectsDualManual)
{
    // Two pinned literals agreeing proves only that the author typed the same number twice, not that the live image
    // corroborates it: reject as non-independent regardless of value.
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::Manual;
    first.manual_value = 0x4000;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0x4000;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;

    const auto result = Anchors::resolve(quorum);
    EXPECT_EQ(result.status, Anchors::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorsTest, QuorumRejectsSameBackendConfig)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };

    // Two distinct Anchor objects that share the same candidate array and operand config decode one site twice: the
    // shared site span (same data() and size()) makes them the same evidence.
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::CodeOperand;
    second.site = cands;
    second.operand_index = 1;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorsTest, QuorumAcceptsDistinctCandidateArrays)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    reg.put(0x200,
            {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0 -- a distinct encoding of the same value

    // Two SEPARATE candidate arrays (distinct data() pointers) decoding the same 0xF0 are two independent scan sites,
    // not one: the gate keys on span identity, not pattern equality, so this must resolve. The two encodings differ so
    // each pattern matches exactly one unique site.
    Scanner::AddrCandidate cands_a[] = {
        {"add-imm-a", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::AddrCandidate cands_b[] = {
        {"add-imm-b", "48 81 C1 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands_a;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::CodeOperand;
    second.site = cands_b;
    second.operand_index = 1;

    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

// --- Opt-in validator policies for Manual and backend kinds ---

TEST(AnchorsTest, ManualValidatorRunsWhenOptedIn)
{
    // validate_manual routes a pinned literal through the validator gate. A rejecting validator fails it closed.
    Anchors::Anchor rejected{};
    rejected.kind = Anchors::AnchorKind::Manual;
    rejected.manual_value = 0xF0;
    rejected.validate_manual = true;
    rejected.validator = always_reject;

    const auto rejected_result = Anchors::resolve(rejected);
    EXPECT_EQ(rejected_result.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(rejected_result.value, 0);

    // The same opt-in with an accepting validator that actually inspects the value resolves to the literal.
    Anchors::Anchor accepted{};
    accepted.kind = Anchors::AnchorKind::Manual;
    accepted.manual_value = 0xF0;
    accepted.validate_manual = true;
    accepted.validator = expect_value_f0;

    const auto accepted_result = Anchors::resolve(accepted);
    EXPECT_EQ(accepted_result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(accepted_result.value, 0xF0);
}

TEST(AnchorsTest, ManualValidatorSkippedByDefault)
{
    // Without validate_manual the pinned-literal exemption stands: the rejecting validator is never invoked.
    Anchors::Anchor anchor{};
    anchor.kind = Anchors::AnchorKind::Manual;
    anchor.manual_value = 0x1234;
    anchor.validator = always_reject; // present but not opted in

    const auto result = Anchors::resolve(anchor);
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x1234);
}

TEST(AnchorsTest, RequireValidatorRejectsUnverifiedBackend)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };

    // A backend-resolvable anchor with require_validator set but no validator is treated as unverified: fail closed
    // even though the backend resolved 0xF0.
    Anchors::Anchor unverified{};
    unverified.kind = Anchors::AnchorKind::CodeOperand;
    unverified.site = cands;
    unverified.operand_index = 1;
    unverified.require_validator = true;

    const auto unverified_result = Anchors::resolve(unverified, reg.range());
    EXPECT_EQ(unverified_result.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(unverified_result.value, 0);

    // Supplying a validator satisfies the policy and the same anchor resolves.
    Anchors::Anchor verified{};
    verified.kind = Anchors::AnchorKind::CodeOperand;
    verified.site = cands;
    verified.operand_index = 1;
    verified.require_validator = true;
    verified.validator = expect_value_f0;

    const auto verified_result = Anchors::resolve(verified, reg.range());
    EXPECT_EQ(verified_result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(verified_result.value, 0xF0);
}

TEST(AnchorsTest, RequireValidatorIgnoredForManualByDefault)
{
    // A Manual that did not opt in via validate_manual never reaches the commit gate, so require_validator does not
    // apply: the pinned literal resolves unchecked.
    Anchors::Anchor anchor{};
    anchor.kind = Anchors::AnchorKind::Manual;
    anchor.manual_value = 0x1234;
    anchor.require_validator = true;
    anchor.validate_manual = false;

    const auto result = Anchors::resolve(anchor);
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x1234);
}

TEST(AnchorsTest, QuorumExemptFromRequireValidator)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor first{};
    first.kind = Anchors::AnchorKind::CodeOperand;
    first.site = cands;
    first.operand_index = 1;

    Anchors::Anchor second{};
    second.kind = Anchors::AnchorKind::Manual;
    second.manual_value = 0xF0;

    // The Quorum's two-signal corroboration is itself the verification, so require_validator with no validator must not
    // fail it: the corroborated value resolves.
    Anchors::Anchor quorum{};
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &first;
    quorum.quorum_b = &second;
    quorum.require_validator = true;

    const auto result = Anchors::resolve(quorum, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

// --- Manifest quality diagnostic ---

TEST(AnchorsTest, AssessQualityTalliesReport)
{
    // A hand-built report exercising one of each tallied shape: a self-healing backend, a pinned literal, a backend
    // miss, and a non-independent quorum.
    Anchors::ResolvedAnchor report[4]{};

    report[0].label = "backend";
    report[0].kind = Anchors::AnchorKind::CodeOperand;
    report[0].status = Anchors::AnchorStatus::Resolved;
    report[0].value = 0xF0;

    report[1].label = "pinned";
    report[1].kind = Anchors::AnchorKind::Manual;
    report[1].status = Anchors::AnchorStatus::Resolved;
    report[1].value = 0x1234;

    report[2].label = "missed";
    report[2].kind = Anchors::AnchorKind::RipGlobal;
    report[2].status = Anchors::AnchorStatus::Failed;

    report[3].label = "dependent";
    report[3].kind = Anchors::AnchorKind::Quorum;
    report[3].status = Anchors::AnchorStatus::QuorumNotIndependent;

    const auto quality = Anchors::assess_quality(report);
    EXPECT_EQ(quality.total, 4u);
    EXPECT_EQ(quality.resolved, 2u); // the backend and the pinned literal
    EXPECT_EQ(quality.failed, 1u);   // the backend miss
    EXPECT_EQ(quality.unsupported, 0u);
    EXPECT_EQ(quality.not_independent, 1u); // the dependent quorum
    EXPECT_EQ(quality.manual_at_risk, 1u);  // the pinned literal cannot self-heal
    EXPECT_EQ(quality.corroborated, 0u);    // no quorum resolved
}

// ---- anchor_fingerprint: address-independent evidence hash ----

TEST(AnchorFingerprintTest, DeterministicForSameEvidence)
{
    Anchors::Anchor anchor{};
    anchor.label = "vt";
    anchor.kind = Anchors::AnchorKind::VtableIdentity;
    anchor.mangled = ".?AVCAIPlayer@@";

    EXPECT_EQ(Anchors::anchor_fingerprint(anchor), Anchors::anchor_fingerprint(anchor));
}

TEST(AnchorFingerprintTest, IgnoresLabel)
{
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::VtableIdentity;
    a.mangled = ".?AVFoo@@";
    a.label = "first";

    Anchors::Anchor b = a;
    b.label = "totally-different-label";

    // The label is cosmetic: echoed in the result but it resolves nothing, so it is not evidence.
    EXPECT_EQ(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, VtableMangledIsEvidence)
{
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::VtableIdentity;
    a.mangled = ".?AVFoo@@";

    Anchors::Anchor b = a;
    b.mangled = ".?AVBar@@";

    EXPECT_NE(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, KindIsEvidence)
{
    Scanner::AddrCandidate cands[] = {
        {"marker", "DE AD BE EF", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor global{};
    global.kind = Anchors::AnchorKind::RipGlobal;
    global.site = cands;

    Anchors::Anchor code = global;
    code.kind = Anchors::AnchorKind::CodeOperand;

    // Same cascade bytes, different backend -> different evidence path.
    EXPECT_NE(Anchors::anchor_fingerprint(global), Anchors::anchor_fingerprint(code));
}

TEST(AnchorFingerprintTest, IgnoresCandidateName)
{
    Scanner::AddrCandidate cands_a[] = {
        {"name-A", "DE AD BE EF", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::AddrCandidate cands_b[] = {
        {"name-B", "DE AD BE EF", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::RipGlobal;
    a.site = cands_a;

    Anchors::Anchor b{};
    b.kind = Anchors::AnchorKind::RipGlobal;
    b.site = cands_b;

    // The candidate name is a cosmetic log label; only the pattern + resolve params are evidence.
    EXPECT_EQ(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadePatternIsEvidence)
{
    Scanner::AddrCandidate cands_a[] = {
        {"m", "DE AD BE EF", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::AddrCandidate cands_b[] = {
        {"m", "DE AD BE 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::RipGlobal;
    a.site = cands_a;
    Anchors::Anchor b{};
    b.kind = Anchors::AnchorKind::RipGlobal;
    b.site = cands_b;

    EXPECT_NE(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CodeOperandDecodeParamsAreEvidence)
{
    Scanner::AddrCandidate cands[] = {
        {"m", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor base{};
    base.kind = Anchors::AnchorKind::CodeOperand;
    base.site = cands;
    base.operand_kind = Scanner::OperandKind::Immediate;
    base.operand_index = 1;
    base.byte_width = 0;

    Anchors::Anchor diff_index = base;
    diff_index.operand_index = 2;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_index));

    Anchors::Anchor diff_width = base;
    diff_width.byte_width = 4;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_width));

    Anchors::Anchor diff_kind = base;
    diff_kind.operand_kind = Scanner::OperandKind::MemoryDisplacement;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_kind));
}

TEST(AnchorFingerprintTest, StringXrefShapeFlagsAreEvidence)
{
    Anchors::Anchor base{};
    base.kind = Anchors::AnchorKind::StringXref;
    base.xref_text = "Health";
    base.xref_encoding = Scanner::StringEncoding::Utf8;
    base.xref_return = Scanner::XrefReturn::ReferencingInstruction;
    base.xref_require_terminator = true;
    base.xref_broad_match = false;

    Anchors::Anchor diff_text = base;
    diff_text.xref_text = "Stamina";
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_text));

    Anchors::Anchor diff_enc = base;
    diff_enc.xref_encoding = Scanner::StringEncoding::Utf16le;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_enc));

    Anchors::Anchor diff_term = base;
    diff_term.xref_require_terminator = false;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_term));

    Anchors::Anchor diff_broad = base;
    diff_broad.xref_broad_match = true;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_broad));

    Anchors::Anchor diff_return = base;
    diff_return.xref_return = Scanner::XrefReturn::EnclosingFunction;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_return));
}

TEST(AnchorFingerprintTest, ManualLiteralIsEvidence)
{
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::Manual;
    a.manual_value = 0x10;
    Anchors::Anchor b = a;
    b.manual_value = 0x20;

    EXPECT_NE(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(b));

    Anchors::Anchor c = a;
    EXPECT_EQ(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(c));
}

TEST(AnchorFingerprintTest, SameEvidenceDifferentAddressMatches)
{
    Region reg_a;
    Region reg_b;
    ASSERT_TRUE(reg_a.ok());
    ASSERT_TRUE(reg_b.ok());
    // Plant the identical marker at different offsets in two distinct allocations so it resolves to two different
    // addresses while the declarative evidence (the AOB pattern) stays byte-for-byte identical.
    reg_a.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0x66, 0x77, 0x88});
    reg_b.put(0x300, {0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0x66, 0x77, 0x88});

    Scanner::AddrCandidate cands_a[] = {
        {"a", "DE AD BE EF 55 66 77 88", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::AddrCandidate cands_b[] = {
        {"b", "DE AD BE EF 55 66 77 88", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor_a{};
    anchor_a.kind = Anchors::AnchorKind::RipGlobal;
    anchor_a.site = cands_a;
    Anchors::Anchor anchor_b{};
    anchor_b.kind = Anchors::AnchorKind::RipGlobal;
    anchor_b.site = cands_b;

    const auto res_a = Anchors::resolve(anchor_a, reg_a.range());
    const auto res_b = Anchors::resolve(anchor_b, reg_b.range());
    ASSERT_EQ(res_a.status, Anchors::AnchorStatus::Resolved);
    ASSERT_EQ(res_b.status, Anchors::AnchorStatus::Resolved);
    // The whole point: the targets moved (new address) but the evidence path did not.
    EXPECT_NE(res_a.value, res_b.value);
    EXPECT_EQ(Anchors::anchor_fingerprint(anchor_a), Anchors::anchor_fingerprint(anchor_b));
}

TEST(AnchorFingerprintTest, QuorumIsOrderIndependent)
{
    Anchors::Anchor vt{};
    vt.kind = Anchors::AnchorKind::VtableIdentity;
    vt.mangled = ".?AVFoo@@";
    Anchors::Anchor man{};
    man.kind = Anchors::AnchorKind::Manual;
    man.manual_value = 0x99;

    Anchors::Anchor q_ab{};
    q_ab.kind = Anchors::AnchorKind::Quorum;
    q_ab.quorum_a = &vt;
    q_ab.quorum_b = &man;

    Anchors::Anchor q_ba{};
    q_ba.kind = Anchors::AnchorKind::Quorum;
    q_ba.quorum_a = &man;
    q_ba.quorum_b = &vt;

    EXPECT_EQ(Anchors::anchor_fingerprint(q_ab), Anchors::anchor_fingerprint(q_ba));
}

TEST(AnchorFingerprintTest, QuorumMatchModeAndToleranceAreEvidence)
{
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::Manual;
    a.manual_value = 1;
    Anchors::Anchor b{};
    b.kind = Anchors::AnchorKind::Manual;
    b.manual_value = 2;

    Anchors::Anchor base{};
    base.kind = Anchors::AnchorKind::Quorum;
    base.quorum_a = &a;
    base.quorum_b = &b;
    base.quorum_match = Anchors::QuorumMatch::ExactValue;
    base.quorum_tolerance = 0;

    Anchors::Anchor diff_match = base;
    diff_match.quorum_match = Anchors::QuorumMatch::WithinTolerance;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_match));

    Anchors::Anchor diff_tol = base;
    diff_tol.quorum_tolerance = 8;
    EXPECT_NE(Anchors::anchor_fingerprint(base), Anchors::anchor_fingerprint(diff_tol));
}

TEST(AnchorFingerprintTest, QuorumNullSubAnchorIsDefined)
{
    Anchors::Anchor q{};
    q.kind = Anchors::AnchorKind::Quorum;
    q.quorum_a = nullptr;
    q.quorum_b = nullptr;

    // Must not dereference null; the result is well-defined and deterministic.
    EXPECT_EQ(Anchors::anchor_fingerprint(q), Anchors::anchor_fingerprint(q));
}

TEST(AnchorFingerprintTest, CallArgHomeReflectsKindOnly)
{
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::CallArgHome;
    a.label = "x";
    Anchors::Anchor b{};
    b.kind = Anchors::AnchorKind::CallArgHome;
    b.label = "y";
    b.manual_value = 0x1234; // unused by this kind

    EXPECT_EQ(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadeFieldBoundariesDoNotAlias)
{
    // Each candidate's pattern bytes are length-prefixed, so two splits that concatenate to the same bytes still
    // differ: the candidate list ["AB", ""] must not collide with ["A", "B"].
    Scanner::AddrCandidate split_one[] = {
        {"x", "AB", Scanner::ResolveMode::Direct, 0, 0},
        {"y", "", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::AddrCandidate split_two[] = {
        {"x", "A", Scanner::ResolveMode::Direct, 0, 0},
        {"y", "B", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::RipGlobal;
    a.site = split_one;
    Anchors::Anchor b{};
    b.kind = Anchors::AnchorKind::RipGlobal;
    b.site = split_two;

    EXPECT_NE(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadePatternHashedAsAuthored)
{
    // The pattern is fingerprinted as the AOB text the caller wrote, not re-parsed to canonical bytes, so two spellings
    // of one signature (hex case, spacing) are intentionally distinct -- canonicalizing would cost an allocation and a
    // parse that can fail. A cross-version diff reuses one static table verbatim, so this never causes a false "new
    // evidence path" in practice.
    Scanner::AddrCandidate upper[] = {{"x", "48 8B 05", Scanner::ResolveMode::Direct, 0, 0}};
    Scanner::AddrCandidate lower[] = {{"x", "48 8b 05", Scanner::ResolveMode::Direct, 0, 0}};
    Anchors::Anchor a{};
    a.kind = Anchors::AnchorKind::RipGlobal;
    a.site = upper;
    Anchors::Anchor b{};
    b.kind = Anchors::AnchorKind::RipGlobal;
    b.site = lower;

    EXPECT_NE(Anchors::anchor_fingerprint(a), Anchors::anchor_fingerprint(b));
}
