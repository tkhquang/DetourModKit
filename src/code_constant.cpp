/**
 * @file code_constant.cpp
 * @brief Zydis-backed extraction of a constant encoded in engine machine code.
 *
 * The code-side twin of the RTTI self-heal: an AOB cascade lands on an
 * instruction, the instruction is decoded, and the requested operand's immediate
 * or memory displacement is returned as the CURRENT value. The caller's nominal
 * is never a short-circuit, so a same-shape / different-value drift (for example
 * an array stride 232 -> 240) is reported as the new value, which is the entire
 * point of re-deriving it.
 *
 * Zydis is confined to this translation unit: no public DetourModKit header
 * exposes a Zydis type. An installed-package consumer therefore only links
 * DetourModKit (which already links Zydis statically) and never needs Zydis
 * headers on its own include path.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>

namespace DetourModKit
{
    namespace
    {
        // Narrows an already-64-bit-sign-extended value to @p byte_width bytes and
        // re-sign-extends from that width, so a deliberately narrowed negative
        // value (for example a disp8 of -1) stays negative instead of becoming a
        // large positive number. @p byte_width 0 returns the value verbatim, since
        // Zydis has already sign-extended immediates and displacements to 64 bits.
        std::int64_t narrow_signed(std::int64_t value, std::uint8_t byte_width) noexcept
        {
            if (byte_width == 0 || byte_width >= sizeof(std::int64_t))
            {
                return value;
            }
            const unsigned bits = static_cast<unsigned>(byte_width) * 8u;
            const std::uint64_t mask = (std::uint64_t{1} << bits) - 1u;
            const std::uint64_t masked = static_cast<std::uint64_t>(value) & mask;
            const std::uint64_t sign_bit = std::uint64_t{1} << (bits - 1u);
            // Two's-complement sign-extension from the top bit of the chosen width.
            const std::uint64_t extended = (masked ^ sign_bit) - sign_bit;
            return static_cast<std::int64_t>(extended);
        }
    } // anonymous namespace

    std::expected<std::int64_t, Scanner::ResolveError>
    Scanner::read_code_constant(const CodeConstant &cc, Memory::ModuleRange range)
    {
        // Resolve the instruction site through the existing module-scoped cascade
        // and propagate its typed failure verbatim (EmptyCandidates, NoMatch,
        // InvalidRange, ...).
        const auto hit = resolve_cascade_in_module(cc.site, "read_code_constant", range);
        if (!hit)
        {
            return std::unexpected(hit.error());
        }
        const std::uintptr_t site = hit->address;

        // Read a full maximum-length instruction window, clamped to the module so
        // the read never runs past the end of the image, behind a fault guard. A
        // truncated window that fails to decode is reported as DecodeFailed below.
        std::byte buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
        std::size_t avail = sizeof(buf);
        if (range.valid() && site < range.end)
        {
            const std::uintptr_t to_end = range.end - site;
            if (to_end < avail)
            {
                avail = static_cast<std::size_t>(to_end);
            }
        }
        if (avail == 0 || !Memory::seh_read_bytes(site, buf, avail))
        {
            return std::unexpected(ResolveError::DecodeFailed);
        }

        ZydisDecoder decoder;
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                           ZYDIS_STACK_WIDTH_64)))
        {
            return std::unexpected(ResolveError::DecodeFailed);
        }

        ZydisDecodedInstruction insn;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buf, avail, &insn, operands)))
        {
            return std::unexpected(ResolveError::DecodeFailed);
        }

        // Index the VISIBLE operands -- the ones a human counts in a disassembler.
        // operand_count includes implicit/hidden operands (flags, implicit
        // registers, stack writes), which would make a fixed operand_index drift
        // between mnemonics.
        if (cc.operand_index >= insn.operand_count_visible)
        {
            return std::unexpected(ResolveError::OperandOutOfRange);
        }
        const ZydisDecodedOperand &operand = operands[cc.operand_index];

        if (cc.kind == OperandKind::Immediate)
        {
            if (operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                return std::unexpected(ResolveError::UnexpectedShape);
            }
            // imm.value.s is already 64-bit sign-extended by Zydis.
            return narrow_signed(static_cast<std::int64_t>(operand.imm.value.s), cc.byte_width);
        }

        // MemoryDisplacement. A register-indirect operand with no displacement
        // (for example plain `[rcx]`) carries no constant to read.
        if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY || !operand.mem.disp.has_displacement)
        {
            return std::unexpected(ResolveError::UnexpectedShape);
        }

        if (operand.mem.base == ZYDIS_REGISTER_RIP)
        {
            // RIP-relative: the raw displacement is measured from the next
            // instruction, not the absolute constant the caller wants. Resolve it
            // to the absolute target so the return value is meaningful rather than
            // a misleading relative offset.
            ZyanU64 absolute = 0;
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operand, static_cast<ZyanU64>(site),
                                                       &absolute)))
            {
                return std::unexpected(ResolveError::DecodeFailed);
            }
            return static_cast<std::int64_t>(absolute);
        }

        // disp.value is already 64-bit sign-extended.
        return narrow_signed(static_cast<std::int64_t>(operand.mem.disp.value), cc.byte_width);
    }
} // namespace DetourModKit
