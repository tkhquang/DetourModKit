#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "x86_decode.hpp"

using DetourModKit::detail::decode_e9_rel32;
using DetourModKit::detail::decode_eb_rel8;
using DetourModKit::detail::decode_ff25_indirect;

namespace
{
    // Writes a little-endian 32-bit value into a byte buffer. Avoids
    // pulling in <bit> / std::bit_cast for what is effectively the same
    // thing std::memcpy does in the decoders under test.
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

    const auto result =
        decode_e9_rel32(reinterpret_cast<std::uintptr_t>(buf.data()));
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

TEST(X86DecodeTest, DecodeEbRel8_NullAddressRejected)
{
    const auto result = decode_eb_rel8(0);
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeEbRel8_WrongOpcodeRejected)
{
    std::array<std::uint8_t, 2> buf{0x90, 0x10};

    const auto result =
        decode_eb_rel8(reinterpret_cast<std::uintptr_t>(buf.data()));
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
    // 0xFE is -2 when interpreted as signed 8-bit; verifies the cast
    // to std::int8_t in decode_eb_rel8 sign-extends correctly.
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

    const auto result =
        decode_ff25_indirect(reinterpret_cast<std::uintptr_t>(buf.data()));
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeFf25Indirect_WrongSecondByteRejected)
{
    // First byte matches, second byte does not; covers the second half
    // of the compound opcode predicate.
    std::array<std::uint8_t, 6> buf{0xFF, 0x15, 0x00, 0x00, 0x00, 0x00};

    const auto result =
        decode_ff25_indirect(reinterpret_cast<std::uintptr_t>(buf.data()));
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeFf25Indirect_UnreadableSlotRejected)
{
    // Instruction is readable, but the disp32 is chosen so the slot
    // address points into kernel-reserved space that is_readable will
    // reject. disp = INT32_MAX makes target = base + 6 + INT32_MAX,
    // which overflows above the user address range on Win64.
    alignas(8) std::array<std::uint8_t, 6> buf{
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    write_le32(buf.data() + 2, 0x7FFFFFFF);

    const auto base = reinterpret_cast<std::uintptr_t>(buf.data());
    const auto result = decode_ff25_indirect(base);
    EXPECT_FALSE(result.has_value());
}

TEST(X86DecodeTest, DecodeFf25Indirect_SlotProducesDestination)
{
    // Lay out the instruction and its slot in a single aligned struct
    // and point the RIP-relative displacement at the slot explicitly
    // rather than assuming zero padding. The decoder computes the slot
    // address as base + 6 + disp32, so disp must equal
    // (offsetof(slot) - 6) regardless of how the compiler pads.
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
