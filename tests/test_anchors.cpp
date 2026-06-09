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
    // A committed page (0xCC filled) for planting instruction bytes / markers that
    // the cascade- and decode-backed anchor kinds resolve against.
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

    // The region carries no RTTI, so the backend must fail closed (not crash and
    // not invent a value).
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
    // StringXref phase 2 scans execute-readable pages, so this case needs an
    // executable page rather than the read-write Region helper.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;
    auto *base = static_cast<std::uint8_t *>(
        VirtualAlloc(nullptr, page, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
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
    const auto disp = static_cast<std::int32_t>(
        static_cast<std::int64_t>(base_addr + 0x100) -
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
}
