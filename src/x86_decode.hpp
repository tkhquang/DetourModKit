#ifndef DETOURMODKIT_X86_DECODE_HPP
#define DETOURMODKIT_X86_DECODE_HPP

#include "DetourModKit/memory.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>

namespace DetourModKit::detail
{
    /**
     * @brief Decodes an E9 rel32 near JMP at @p address and returns its absolute destination.
     * @details Copies the candidate instruction bytes into a local buffer under a single SEH fault guard
     *          (seh_read_bytes), then inspects the copy. Read-then-test on a local buffer closes the time-of-check to
     *          time-of-use gap that is_readable + a raw dereference leaves open: the target page can change protection
     *          or unmap between the probe and the access, and these decoders run on the nested-hook detection and
     *          prologue-recovery paths where the page state is most likely to be in flux. A faulting read returns
     *          nullopt rather than taking down the host.
     * @param address Absolute address of the candidate instruction.
     * @return The absolute jump destination, or std::nullopt when the bytes are unreadable or the opcode is not E9.
     */
    [[nodiscard]] inline std::optional<std::uintptr_t> decode_e9_rel32(std::uintptr_t address) noexcept
    {
        std::array<std::uint8_t, 5> code{};
        if (!Memory::seh_read_bytes(address, code.data(), code.size()))
        {
            return std::nullopt;
        }
        if (code[0] != 0xE9)
        {
            return std::nullopt;
        }
        std::int32_t disp = 0;
        std::memcpy(&disp, code.data() + 1, sizeof(disp));
        return static_cast<std::uintptr_t>(static_cast<std::int64_t>(address) + 5 + disp);
    }

    /**
     * @brief Decodes an EB rel8 short JMP at @p address and returns its absolute destination.
     * @details Copies the candidate instruction bytes into a local buffer under a single SEH fault guard
     *          (seh_read_bytes), then inspects the copy. Read-then-test on a local buffer closes the time-of-check to
     *          time-of-use gap that is_readable + a raw dereference leaves open: the target page can change protection
     *          or unmap between the probe and the access, and this decoder runs on hook-detection pre-flight paths
     *          (the VMT slot pre-flight) where the page state is most likely to be in flux. A faulting read returns
     *          nullopt rather than taking down the host.
     * @param address Absolute address of the candidate instruction.
     * @return The absolute jump destination (rel8 sign-extended), or std::nullopt when the bytes are unreadable or the
     *         opcode is not EB.
     */
    [[nodiscard]] inline std::optional<std::uintptr_t> decode_eb_rel8(std::uintptr_t address) noexcept
    {
        std::array<std::uint8_t, 2> code{};
        if (!Memory::seh_read_bytes(address, code.data(), code.size()))
        {
            return std::nullopt;
        }
        if (code[0] != 0xEB)
        {
            return std::nullopt;
        }
        const auto disp = static_cast<std::int8_t>(code[1]);
        return static_cast<std::uintptr_t>(static_cast<std::int64_t>(address) + 2 + disp);
    }

    /**
     * @brief Decodes an FF 25 disp32 indirect JMP at @p address and returns the target stored in its memory slot.
     * @details FF 25 disp32 on x86-64 is RIP-relative: the 32-bit signed displacement is added to the address of the
     *          next instruction. On x86 (32-bit) the same encoding is absolute, which this decoder does not handle.
     *          Copies the candidate instruction bytes into a local buffer under a single SEH fault guard
     *          (seh_read_bytes), then inspects the copy. Read-then-test on a local buffer closes the time-of-check to
     *          time-of-use gap that is_readable + a raw dereference leaves open: the target page can change protection
     *          or unmap between the probe and the access, and these decoders run on the nested-hook detection and
     *          prologue-recovery paths where the page state is most likely to be in flux. A faulting read returns
     *          nullopt rather than taking down the host.
     * @param address Absolute address of the candidate instruction.
     * @return The final indirect target read from the slot, or std::nullopt when the instruction bytes or the slot are
     *         unreadable or the opcode is not FF 25.
     */
    [[nodiscard]] inline std::optional<std::uintptr_t> decode_ff25_indirect(std::uintptr_t address) noexcept
    {
        static_assert(sizeof(void *) == 8, "decode_ff25_indirect assumes x86-64 RIP-relative semantics");
        std::array<std::uint8_t, 6> code{};
        if (!Memory::seh_read_bytes(address, code.data(), code.size()))
        {
            return std::nullopt;
        }
        if (code[0] != 0xFF || code[1] != 0x25)
        {
            return std::nullopt;
        }
        std::int32_t disp = 0;
        std::memcpy(&disp, code.data() + 2, sizeof(disp));
        const auto slot_addr = static_cast<std::uintptr_t>(static_cast<std::int64_t>(address) + 6 + disp);
        // The slot stores the final indirect target; read it under the same fault guard rather than is_readable + a raw
        // dereference.
        const auto indirect_destination = Memory::seh_read<std::uintptr_t>(slot_addr);
        if (!indirect_destination)
        {
            return std::nullopt;
        }
        return *indirect_destination;
    }

    /**
     * @brief Decodes a `mov rax, imm64; jmp rax` absolute-jump pair at @p address and returns the imm64 destination.
     * @details Some inline hooks emit this 12-byte absolute jump -- `48 B8 <imm64>` (REX.W mov rax, imm64) immediately
     *          followed by `FF E0` (jmp rax) -- when the detour trampoline is beyond rel32 reach and the hooking
     *          library does not use the FF 25 RIP-relative form. Unlike FF 25 the absolute target is the imm64 baked
     *          directly into the instruction, so no pointer-slot dereference is needed. Copies the candidate bytes
     *          into a local buffer under a single SEH fault guard (seh_read_bytes), then inspects the copy.
     *          Read-then-test on a local buffer closes the time-of-check to time-of-use gap that is_readable + a raw
     *          dereference leaves open: the target page can change protection or unmap between the probe and the
     *          access, and this decoder
     *          runs on the prologue-recovery path where the page state is most likely to be in flux. A faulting read
     *          returns nullopt rather than taking down the host.
     * @param address Absolute address of the candidate instruction pair.
     * @return The absolute jump destination (the imm64), or std::nullopt when the bytes are unreadable or the opcodes
     *         are not `48 B8 ... FF E0`.
     */
    [[nodiscard]] inline std::optional<std::uintptr_t> decode_mov_rax_imm64_jmp_rax(std::uintptr_t address) noexcept
    {
        static_assert(sizeof(void *) == 8, "decode_mov_rax_imm64_jmp_rax assumes a 64-bit absolute target");
        std::array<std::uint8_t, 12> code{};
        if (!Memory::seh_read_bytes(address, code.data(), code.size()))
        {
            return std::nullopt;
        }
        // 48 B8 = REX.W + mov rax, imm64; bytes [2..9] hold the imm64; FF E0 = jmp rax.
        if (code[0] != 0x48 || code[1] != 0xB8 || code[10] != 0xFF || code[11] != 0xE0)
        {
            return std::nullopt;
        }
        std::uintptr_t destination = 0;
        std::memcpy(&destination, code.data() + 2, sizeof(destination));
        return destination;
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_X86_DECODE_HPP
