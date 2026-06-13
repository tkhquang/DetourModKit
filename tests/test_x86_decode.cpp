#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "x86_decode.hpp"

using DetourModKit::detail::decode_e9_rel32;
using DetourModKit::detail::decode_eb_rel8;
using DetourModKit::detail::decode_ff25_indirect;
using DetourModKit::detail::decode_mov_rax_imm64_jmp_rax;

namespace
{
    // Writes a little-endian 32-bit value into a byte buffer. Avoids pulling in <bit> / std::bit_cast for what is
    // effectively the same thing std::memcpy does in the decoders under test.
    void write_le32(std::uint8_t *dst, std::int32_t value) noexcept
    {
        std::memcpy(dst, &value, sizeof(value));
    }
} // namespace

TEST(X86DecodeTest, DecodeE9Rel32_NullAddressRejected)
{
    const auto result = decode_e9_rel32(0);
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeE9Rel32_WrongOpcodeRejected)
{
    // The buffer is readable but the leading byte is not 0xE9.
    std::array<std::uint8_t, 5> buf{0x90, 0x00, 0x00, 0x00, 0x00};

    const auto result = decode_e9_rel32(reinterpret_cast<std::uintptr_t>(buf.data()));
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeE9Rel32_ValidForwardDisplacement)
{
    std::array<std::uint8_t, 5> buf{0xE9, 0x00, 0x00, 0x00, 0x00};
    write_le32(buf.data() + 1, 0x10);

    const auto base = reinterpret_cast<std::uintptr_t>(buf.data());
    const auto result = decode_e9_rel32(base);
    ASSERT_TRUE(result.has_value());
    // Next-instruction address is base + 5; destination = next + disp.
    EXPECT_EQ(*result, base + 5 + 0x10);
}

TEST(X86DecodeTest, DecodeE9Rel32_ValidBackwardDisplacement)
{
    std::array<std::uint8_t, 5> buf{0xE9, 0x00, 0x00, 0x00, 0x00};
    write_le32(buf.data() + 1, -32);

    const auto base = reinterpret_cast<std::uintptr_t>(buf.data());
    const auto result = decode_e9_rel32(base);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, base + 5 - 32);
}

TEST(X86DecodeTest, DecodeE9Rel32_UnmappedInstructionRejected)
{
    // Reserve a page with no committed backing and no access, then decode at its base. The decoders do not pre-probe
    // with is_readable; the SEH fault guard inside seh_read_bytes is the only thing between a bad address and an access
    // violation, so this asserts that an unmapped instruction yields nullopt instead of faulting the process. Covers
    // the time-of-check to time-of-use hazard on the instruction-bytes read shared by all three decoders.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    LPVOID region = VirtualAlloc(nullptr, si.dwPageSize, MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(region, nullptr);

    const auto result = decode_e9_rel32(reinterpret_cast<std::uintptr_t>(region));
    EXPECT_FALSE(result.has_value());

    VirtualFree(region, 0, MEM_RELEASE);
}

TEST(X86DecodeTest, DecodeEbRel8_NullAddressRejected)
{
    const auto result = decode_eb_rel8(0);
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeEbRel8_WrongOpcodeRejected)
{
    std::array<std::uint8_t, 2> buf{0x90, 0x10};

    const auto result = decode_eb_rel8(reinterpret_cast<std::uintptr_t>(buf.data()));
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeEbRel8_ValidForwardDisplacement)
{
    std::array<std::uint8_t, 2> buf{0xEB, 0x04};

    const auto base = reinterpret_cast<std::uintptr_t>(buf.data());
    const auto result = decode_eb_rel8(base);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, base + 2 + 0x04);
}

TEST(X86DecodeTest, DecodeEbRel8_NegativeDisplacementSignExtended)
{
    // 0xFE is -2 when interpreted as signed 8-bit; verifies the cast to std::int8_t in decode_eb_rel8 sign-extends
    // correctly.
    std::array<std::uint8_t, 2> buf{0xEB, 0xFE};

    const auto base = reinterpret_cast<std::uintptr_t>(buf.data());
    const auto result = decode_eb_rel8(base);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, base);
}

TEST(X86DecodeTest, DecodeFf25Indirect_NullAddressRejected)
{
    const auto result = decode_ff25_indirect(0);
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeFf25Indirect_WrongFirstByteRejected)
{
    std::array<std::uint8_t, 6> buf{0x48, 0x25, 0x00, 0x00, 0x00, 0x00};

    const auto result = decode_ff25_indirect(reinterpret_cast<std::uintptr_t>(buf.data()));
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeFf25Indirect_WrongSecondByteRejected)
{
    // First byte matches, second byte does not; covers the second half of the compound opcode predicate.
    std::array<std::uint8_t, 6> buf{0xFF, 0x15, 0x00, 0x00, 0x00, 0x00};

    const auto result = decode_ff25_indirect(reinterpret_cast<std::uintptr_t>(buf.data()));
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeFf25Indirect_UnreadableSlotRejected)
{
    // Reserve two adjacent pages, commit only the first, then place the
    // FF 25 instruction at the end of the committed page. The disp32 is chosen to point the slot into the uncommitted
    // second page, which the SEH-guarded slot read rejects deterministically (no reliance on ambient process layout).
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;

    LPVOID region = VirtualAlloc(nullptr, page * 2, MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(region, nullptr);
    LPVOID committed = VirtualAlloc(region, page, MEM_COMMIT, PAGE_READWRITE);
    ASSERT_EQ(committed, region);

    auto *page_bytes = static_cast<std::uint8_t *>(region);
    std::uint8_t *instr = page_bytes + page - 6;
    instr[0] = 0xFF;
    instr[1] = 0x25;
    // Slot must land in the uncommitted page: any disp >= 0 puts the
    // 8-byte slot at instr + 6 + disp == page boundary or beyond.
    write_le32(instr + 2, 0);

    const auto base = reinterpret_cast<std::uintptr_t>(instr);
    const auto result = decode_ff25_indirect(base);
    EXPECT_FALSE(result.has_value());

    VirtualFree(region, 0, MEM_RELEASE);
}

TEST(X86DecodeTest, DecodeFf25Indirect_SlotProducesDestination)
{
    // Lay out the instruction and its slot in a single aligned struct and point the RIP-relative displacement at the
    // slot explicitly rather than assuming zero padding. The decoder computes the slot address as base + 6 + disp32, so
    // disp must equal (offsetof(slot) - 6) regardless of how the compiler pads.
    struct alignas(8) Layout
    {
        std::uint8_t instruction[6];
        std::uintptr_t slot;
    };
    Layout layout{};
    layout.instruction[0] = 0xFF;
    layout.instruction[1] = 0x25;
    const auto slot_offset = static_cast<std::int32_t>(offsetof(Layout, slot));
    write_le32(&layout.instruction[2], slot_offset - 6);
    layout.slot = static_cast<std::uintptr_t>(0xDEADBEEFCAFEBABEull);

    const auto base = reinterpret_cast<std::uintptr_t>(&layout.instruction[0]);
    const auto result = decode_ff25_indirect(base);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, layout.slot);
}

TEST(X86DecodeTest, DecodeMovRaxJmpRax_NullAddressRejected)
{
    const auto result = decode_mov_rax_imm64_jmp_rax(0);
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeMovRaxJmpRax_WrongMovOpcodeRejected)
{
    // 48 B9 is mov rcx, imm64 (B8+rcx), not the rax form the decoder pins; the trailing jmp rax is present but must not
    // rescue a non-rax load.
    std::array<std::uint8_t, 12> buf{0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};

    const auto result = decode_mov_rax_imm64_jmp_rax(reinterpret_cast<std::uintptr_t>(buf.data()));
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeMovRaxJmpRax_WrongJmpOperandRejected)
{
    // 48 B8 ... FF E1 is jmp rcx, not jmp rax; the absolute target would be loaded into rax but jumped through a
    // different register, so the pair is not the recognised shape.
    std::array<std::uint8_t, 12> buf{0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE1};

    const auto result = decode_mov_rax_imm64_jmp_rax(reinterpret_cast<std::uintptr_t>(buf.data()));
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeMovRaxJmpRax_ReturnsInlinedImmediate)
{
    // 48 B8 <imm64> FF E0: the absolute destination is the imm64 baked directly into the instruction (no slot read).
    std::array<std::uint8_t, 12> buf{0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
    const std::uintptr_t target = static_cast<std::uintptr_t>(0x0123456789ABCDEFull);
    std::memcpy(buf.data() + 2, &target, sizeof(target));

    const auto result = decode_mov_rax_imm64_jmp_rax(reinterpret_cast<std::uintptr_t>(buf.data()));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, target);
}

TEST(X86DecodeTest, DecodeMovRaxJmpRax_UnmappedInstructionRejected)
{
    // The 12-byte read is SEH-guarded like the other decoders: an unmapped instruction yields nullopt, not a fault.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    LPVOID region = VirtualAlloc(nullptr, si.dwPageSize, MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(region, nullptr);

    const auto result = decode_mov_rax_imm64_jmp_rax(reinterpret_cast<std::uintptr_t>(region));
    EXPECT_FALSE(result.has_value());

    VirtualFree(region, 0, MEM_RELEASE);
}
