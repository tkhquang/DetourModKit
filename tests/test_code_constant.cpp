#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

// windows.h after project headers to avoid macro conflicts.
#include <windows.h>

using namespace DetourModKit;

namespace
{
    // A committed page filled with 0xCC into which a test plants a known x86-64
    // instruction, so read_code_constant has a real, uniquely-matchable site to
    // resolve and decode. PAGE_READWRITE is enough: the bytes are decoded as data,
    // never executed.
    class CodeRegion
    {
    public:
        CodeRegion()
        {
            m_base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (m_base)
            {
                std::memset(m_base, 0xCC, 0x1000);
            }
        }

        ~CodeRegion()
        {
            if (m_base)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        CodeRegion(const CodeRegion &) = delete;
        CodeRegion &operator=(const CodeRegion &) = delete;

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

TEST(CodeConstantTest, ReadsImmediateOperand)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::Immediate;
    cc.operand_index = 1; // operand 0 is rax, operand 1 is the immediate

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0xF0);
}

TEST(CodeConstantTest, ReadsMemoryDisplacement)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x0F, 0xB6, 0x81, 0x18, 0x02, 0x00, 0x00}); // movzx eax, byte [rcx+0x218]

    Scanner::AddrCandidate cands[] = {
        {"movzx", "0F B6 81 18 02 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::MemoryDisplacement;
    cc.operand_index = 1; // operand 1 is the [rcx+disp] memory operand

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0x218);
}

TEST(CodeConstantTest, ReadsNegativeDisp8WithNarrowing)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]

    Scanner::AddrCandidate cands[] = {
        {"disp8", "8A 45 FF", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::MemoryDisplacement;
    cc.operand_index = 1;
    cc.byte_width = 1; // narrow to one byte; the value must stay negative

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, -1);
}

TEST(CodeConstantTest, ResolvesRipRelativeToAbsolute)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00}); // mov rax, [rip+0x100]

    Scanner::AddrCandidate cands[] = {
        {"riprel", "48 8B 05 00 01 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::MemoryDisplacement;
    cc.operand_index = 1;

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    // Absolute target = site + instruction length (7) + disp (0x100), not the raw
    // relative displacement.
    EXPECT_EQ(static_cast<std::uintptr_t>(*value), region.addr(0x100) + 7 + 0x100);
}

TEST(CodeConstantTest, ReportsCurrentValueNotStaleNominal)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0 (current)

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::Immediate;
    cc.operand_index = 1;
    cc.nominal = 0xE0;     // a stale last-known value
    cc.has_nominal = true;

    // The drift case: nominal differs from the live value; the live value wins.
    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0xF0);
}

TEST(CodeConstantTest, OperandIndexPastVisibleCountFails)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0 (2 visible operands)

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::Immediate;
    cc.operand_index = 5; // past the visible operand count

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error(), Scanner::ResolveError::OperandOutOfRange);
}

TEST(CodeConstantTest, WrongKindFailsUnexpectedShape)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x0F, 0xB6, 0x81, 0x18, 0x02, 0x00, 0x00}); // movzx eax, byte [rcx+0x218]

    Scanner::AddrCandidate cands[] = {
        {"movzx", "0F B6 81 18 02 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::Immediate; // but operand 1 is a memory operand
    cc.operand_index = 1;

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error(), Scanner::ResolveError::UnexpectedShape);
}

TEST(CodeConstantTest, RegisterIndirectNoDispFailsUnexpectedShape)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x8B, 0x01}); // mov eax, [rcx] (no displacement)

    Scanner::AddrCandidate cands[] = {
        {"mem-nodisp", "8B 01", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::MemoryDisplacement;
    cc.operand_index = 1;

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error(), Scanner::ResolveError::UnexpectedShape);
}

TEST(CodeConstantTest, SiteNotFoundReturnsNoMatch)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());

    Scanner::AddrCandidate cands[] = {
        {"absent", "11 22 33 44 55 66 77 88", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::Immediate;
    cc.operand_index = 1;

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error(), Scanner::ResolveError::NoMatch);
}

TEST(CodeConstantTest, EmptyCandidatesReturnsEmptyCandidates)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());

    Scanner::CodeConstant cc{}; // default-constructed: empty site span
    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error(), Scanner::ResolveError::EmptyCandidates);
}

TEST(CodeConstantTest, ImmediateNarrowsToByteWidth)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0xB0, 0xFF}); // mov al, 0xFF

    Scanner::AddrCandidate cands[] = {
        {"mov-al-imm8", "B0 FF", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::Immediate;
    cc.operand_index = 1;
    cc.byte_width = 1; // narrow the immediate to one byte: 0xFF must read as -1

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, -1);
}

TEST(CodeConstantTest, AbsoluteMemoryDisplacement)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x8B, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12}); // mov eax, [0x12345678]

    Scanner::AddrCandidate cands[] = {
        {"mov-abs", "8B 04 25 78 56 34 12", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::MemoryDisplacement;
    cc.operand_index = 1;

    // A non-RIP absolute [disp32] returns the displacement verbatim (not resolved
    // as a relative target).
    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(static_cast<std::uint32_t>(*value), 0x12345678u);
}

TEST(CodeConstantTest, TruncatedWindowReturnsDecodeFailed)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    // A REX.W mov that needs a ModRM byte, planted in the final two bytes of the
    // region so the read window is clamped to 2 bytes and the instruction cannot
    // be fully decoded.
    region.put(0xFFE, {0x48, 0x8B}); // 48 8B = REX.W + opcode, ModRM missing

    Scanner::AddrCandidate cands[] = {
        {"truncated", "48 8B", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::Immediate;
    cc.operand_index = 1;

    const auto value = Scanner::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error(), Scanner::ResolveError::DecodeFailed);
}

TEST(CodeConstantTest, InvalidRangeForwardsError)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::CodeConstant cc{};
    cc.site = cands;
    cc.kind = Scanner::OperandKind::Immediate;
    cc.operand_index = 1;

    // An invalid range is rejected by the underlying cascade and forwarded.
    const Memory::ModuleRange invalid{};
    const auto value = Scanner::read_code_constant(cc, invalid);
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error(), Scanner::ResolveError::InvalidRange);
}
