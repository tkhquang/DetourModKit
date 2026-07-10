#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string_view>

#include "DetourModKit/scan.hpp"

// windows.h after project headers to avoid macro conflicts.
#include <windows.h>

using namespace DetourModKit;

namespace
{
    // Compiles a known-good AOB literal for a candidate site. The test patterns are all valid, so the Result is always
    // engaged; .value() keeps each call site terse.
    [[nodiscard]] scan::Pattern aob(std::string_view dsl)
    {
        return scan::Pattern::compile(dsl).value();
    }

    // A committed page filled with 0xCC into which a test plants a known x86-64 instruction, so read_code_constant has
    // a real, uniquely-matchable site to resolve and decode. PAGE_EXECUTE_READWRITE, not PAGE_READWRITE: a code
    // constant is contractually encoded in executable machine code, and read_code_constant scans Pages::Executable for
    // the instruction site. The bytes are still only decoded, never executed; the execute bit is what the page-class
    // gate checks.
    class CodeRegion
    {
    public:
        CodeRegion()
        {
            m_base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

        [[nodiscard]] Region range() const noexcept
        {
            return Region{Address{reinterpret_cast<std::uintptr_t>(m_base)}, 0x1000};
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

    const scan::Candidate cands[] = {scan::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate;
    cc.operand_index = 1; // operand 0 is rax, operand 1 is the immediate

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0xF0);
}

TEST(CodeConstantTest, ReadsMemoryDisplacement)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x0F, 0xB6, 0x81, 0x18, 0x02, 0x00, 0x00}); // movzx eax, byte [rcx+0x218]

    const scan::Candidate cands[] = {scan::Candidate::direct("movzx", aob("0F B6 81 18 02 00 00"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::MemoryDisplacement;
    cc.operand_index = 1; // operand 1 is the [rcx+disp] memory operand

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0x218);
}

TEST(CodeConstantTest, ReadsNegativeDisp8WithNarrowing)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]

    const scan::Candidate cands[] = {scan::Candidate::direct("disp8", aob("8A 45 FF"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::MemoryDisplacement;
    cc.operand_index = 1;
    cc.byte_width = 1; // narrow to one byte; the value must stay negative

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, -1);
}

TEST(CodeConstantTest, ResolvesRipRelativeToAbsolute)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00}); // mov rax, [rip+0x100]

    const scan::Candidate cands[] = {scan::Candidate::direct("riprel", aob("48 8B 05 00 01 00 00"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::MemoryDisplacement;
    cc.operand_index = 1;

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    // Absolute target = site + instruction length (7) + disp (0x100), not the raw relative displacement.
    EXPECT_EQ(static_cast<std::uintptr_t>(*value), region.addr(0x100) + 7 + 0x100);
}

TEST(CodeConstantTest, ReportsCurrentValueNotStaleNominal)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0 (current)

    const scan::Candidate cands[] = {scan::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate;
    cc.operand_index = 1;
    cc.nominal = 0xE0; // a stale last-known value
    cc.has_nominal = true;

    // The drift case: nominal differs from the live value; the live value wins.
    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0xF0);
}

TEST(CodeConstantTest, OperandIndexPastVisibleCountFails)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0 (2 visible operands)

    const scan::Candidate cands[] = {scan::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate;
    cc.operand_index = 5; // past the visible operand count

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::OperandOutOfRange);
}

TEST(CodeConstantTest, WrongKindFailsUnexpectedShape)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x0F, 0xB6, 0x81, 0x18, 0x02, 0x00, 0x00}); // movzx eax, byte [rcx+0x218]

    const scan::Candidate cands[] = {scan::Candidate::direct("movzx", aob("0F B6 81 18 02 00 00"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate; // but operand 1 is a memory operand
    cc.operand_index = 1;

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::UnexpectedShape);
}

TEST(CodeConstantTest, RegisterIndirectNoDispFailsUnexpectedShape)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x8B, 0x01}); // mov eax, [rcx] (no displacement)

    const scan::Candidate cands[] = {scan::Candidate::direct("mem-nodisp", aob("8B 01"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::MemoryDisplacement;
    cc.operand_index = 1;

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::UnexpectedShape);
}

TEST(CodeConstantTest, SiteNotFoundReturnsNoMatch)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());

    const scan::Candidate cands[] = {scan::Candidate::direct("absent", aob("11 22 33 44 55 66 77 88"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate;
    cc.operand_index = 1;

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::NoMatch);
}

TEST(CodeConstantTest, EmptyCandidatesReturnsEmptyCandidates)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());

    scan::CodeConstant cc{}; // default-constructed: empty site span
    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::EmptyCandidates);
}

TEST(CodeConstantTest, ImmediateNarrowsToByteWidth)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0xB0, 0xFF}); // mov al, 0xFF

    const scan::Candidate cands[] = {scan::Candidate::direct("mov-al-imm8", aob("B0 FF"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate;
    cc.operand_index = 1;
    cc.byte_width = 1; // narrow the immediate to one byte: 0xFF must read as -1

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, -1);
}

TEST(CodeConstantTest, AbsoluteMemoryDisplacement)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x8B, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12}); // mov eax, [0x12345678]

    const scan::Candidate cands[] = {scan::Candidate::direct("mov-abs", aob("8B 04 25 78 56 34 12"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::MemoryDisplacement;
    cc.operand_index = 1;

    // A non-RIP absolute [disp32] returns the displacement verbatim (not resolved as a relative target).
    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(static_cast<std::uint32_t>(*value), 0x12345678u);
}

TEST(CodeConstantTest, TruncatedWindowReturnsDecodeFailed)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    // A REX.W mov that needs a ModRM byte, planted in the final two bytes of the region so the read window is clamped
    // to 2 bytes and the instruction cannot be fully decoded.
    region.put(0xFFE, {0x48, 0x8B}); // 48 8B = REX.W + opcode, ModRM missing

    const scan::Candidate cands[] = {scan::Candidate::direct("truncated", aob("48 8B"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate;
    cc.operand_index = 1;

    const auto value = scan::read_code_constant(cc, region.range());
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::DecodeFailed);
}

TEST(CodeConstantTest, InvalidRangeForwardsError)
{
    CodeRegion region;
    ASSERT_TRUE(region.ok());
    region.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    const scan::Candidate cands[] = {scan::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate;
    cc.operand_index = 1;

    // An invalid scope is rejected by the resolver and forwarded.
    const auto value = scan::read_code_constant(cc, Region{});
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::InvalidRange);
}

// A byte run that only exists on a readable, NON-executable page must not be resolved as a code constant.
// read_code_constant scans Pages::Executable, so an instruction-shaped pattern planted in PAGE_READWRITE data is
// invisible to the site scan and the resolve fails closed (NoMatch) rather than decoding the data twin into a confident
// wrong value. Staging the identical bytes on an executable page (every other test above) resolves; staging them on a
// data page here does not.
TEST(CodeConstantTest, DataPageSiteYieldsNoMatch)
{
    void *data = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(data, nullptr);
    std::memset(data, 0xCC, 0x1000);
    auto *bytes = static_cast<std::uint8_t *>(data);
    const std::uint8_t insn[] = {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}; // add rax, 0xF0
    std::memcpy(bytes + 0x100, insn, sizeof(insn));

    const scan::Candidate cands[] = {scan::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    scan::CodeConstant cc{};
    cc.site = cands;
    cc.kind = scan::OperandKind::Immediate;
    cc.operand_index = 1;

    const Region scope{Address{reinterpret_cast<std::uintptr_t>(data)}, 0x1000};
    const auto value = scan::read_code_constant(cc, scope);
    EXPECT_FALSE(value.has_value());
    if (!value.has_value())
    {
        EXPECT_EQ(value.error().code, ErrorCode::NoMatch);
    }

    VirtualFree(data, 0, MEM_RELEASE);
}

// Byte-tier filtering alone is not enough: a RIP-relative candidate can match code and resolve its Hit to data. The
// final-address gate rejects that rung as a candidate miss, so a data address is never handed to the decoder.
TEST(CodeConstantTest, ResolvedDataAddressYieldsNoMatch)
{
    auto *base = static_cast<std::uint8_t *>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);
    std::memset(base, 0xCC, 0x2000);

    DWORD old_protection = 0;
    ASSERT_NE(VirtualProtect(base, 0x1000, PAGE_EXECUTE_READWRITE, &old_protection), 0);

    constexpr std::size_t CODE_OFFSET = 0x100;
    constexpr std::size_t DATA_OFFSET = 0x1100;
    const std::uintptr_t code_site = reinterpret_cast<std::uintptr_t>(base + CODE_OFFSET);
    const std::uintptr_t data_site = reinterpret_cast<std::uintptr_t>(base + DATA_OFFSET);
    const std::int32_t displacement = static_cast<std::int32_t>(data_site - (code_site + 7));

    const std::uint8_t lea[] = {0x48, 0x8D, 0x05}; // lea rax, [rip+disp32]
    std::memcpy(base + CODE_OFFSET, lea, sizeof(lea));
    std::memcpy(base + CODE_OFFSET + sizeof(lea), &displacement, sizeof(displacement));
    const std::uint8_t data_instruction[] = {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}; // add rax, 0xF0
    std::memcpy(base + DATA_OFFSET, data_instruction, sizeof(data_instruction));

    const scan::Candidate candidates[] = {
        scan::Candidate::rip_relative("lea-to-data", aob("48 8D 05 ?? ?? ?? ??"), 3, 7)};
    scan::CodeConstant code_constant{};
    code_constant.site = candidates;
    code_constant.kind = scan::OperandKind::Immediate;
    code_constant.operand_index = 1;

    const Region scope{Address{reinterpret_cast<std::uintptr_t>(base)}, 0x2000};
    const auto value = scan::read_code_constant(code_constant, scope);
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::NoMatch);

    VirtualFree(base, 0, MEM_RELEASE);
}

// A rejected code-to-data rung must not end the cascade. The later Direct rung still names an executable instruction,
// so read_code_constant must decode it rather than returning an error from the earlier transformed candidate.
TEST(CodeConstantTest, ResolvedDataAddressFallsThroughToExecutableRung)
{
    auto *base = static_cast<std::uint8_t *>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);
    std::memset(base, 0xCC, 0x2000);

    DWORD old_protection = 0;
    ASSERT_NE(VirtualProtect(base, 0x1000, PAGE_EXECUTE_READWRITE, &old_protection), 0);

    constexpr std::size_t CODE_OFFSET = 0x100;
    constexpr std::size_t FALLBACK_OFFSET = 0x200;
    constexpr std::size_t DATA_OFFSET = 0x1100;
    const std::uintptr_t code_site = reinterpret_cast<std::uintptr_t>(base + CODE_OFFSET);
    const std::uintptr_t data_site = reinterpret_cast<std::uintptr_t>(base + DATA_OFFSET);
    const std::int32_t displacement = static_cast<std::int32_t>(data_site - (code_site + 7));

    const std::uint8_t lea[] = {0x48, 0x8D, 0x05}; // lea rax, [rip+disp32]
    std::memcpy(base + CODE_OFFSET, lea, sizeof(lea));
    std::memcpy(base + CODE_OFFSET + sizeof(lea), &displacement, sizeof(displacement));
    const std::uint8_t data_instruction[] = {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    std::memcpy(base + DATA_OFFSET, data_instruction, sizeof(data_instruction));
    const std::uint8_t fallback_instruction[] = {0x48, 0x05, 0x2A, 0x00, 0x00, 0x00}; // add rax, 0x2A
    std::memcpy(base + FALLBACK_OFFSET, fallback_instruction, sizeof(fallback_instruction));

    const scan::Candidate candidates[] = {
        scan::Candidate::rip_relative("lea-to-data", aob("48 8D 05 ?? ?? ?? ??"), 3, 7),
        scan::Candidate::direct("fallback-add", aob("48 05 2A 00 00 00")),
    };
    scan::CodeConstant code_constant{};
    code_constant.site = candidates;
    code_constant.kind = scan::OperandKind::Immediate;
    code_constant.operand_index = 1;

    const Region scope{Address{reinterpret_cast<std::uintptr_t>(base)}, 0x2000};
    const auto value = scan::read_code_constant(code_constant, scope);
    ASSERT_TRUE(value.has_value()) << value.error().message();
    EXPECT_EQ(*value, 0x2A);

    VirtualFree(base, 0, MEM_RELEASE);
}

// A two-byte pattern can land at the end of an executable page while the decoded instruction continues into readable
// data. The byte-tier gate and the first-byte result gate both pass, so the decoder must validate the full instruction
// span after Zydis reports its length.
TEST(CodeConstantTest, InstructionCrossingIntoDataPageYieldsDecodeFailed)
{
    auto *base = static_cast<std::uint8_t *>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);
    std::memset(base, 0xCC, 0x2000);

    DWORD old_protection = 0;
    ASSERT_NE(VirtualProtect(base, 0x1000, PAGE_EXECUTE_READWRITE, &old_protection), 0);

    constexpr std::size_t INSTRUCTION_OFFSET = 0xFFE;
    const std::uint8_t instruction[] = {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}; // add rax, 0xF0
    std::memcpy(base + INSTRUCTION_OFFSET, instruction, sizeof(instruction));

    const scan::Candidate candidates[] = {scan::Candidate::direct("boundary-add", aob("48 05"))};
    scan::CodeConstant code_constant{};
    code_constant.site = candidates;
    code_constant.kind = scan::OperandKind::Immediate;
    code_constant.operand_index = 1;

    const Region scope{Address{reinterpret_cast<std::uintptr_t>(base)}, 0x2000};
    const auto value = scan::read_code_constant(code_constant, scope);
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, ErrorCode::DecodeFailed);

    VirtualFree(base, 0, MEM_RELEASE);
}
