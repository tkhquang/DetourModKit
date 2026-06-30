/**
 * @file scan_code_constant.cpp
 * @brief Zydis-backed extraction of a constant encoded in engine machine code: read_code_constant().
 * @details The code-side twin of the RTTI self-heal: the CodeConstant's candidate ladder resolves to an instruction
 *          site (via scan::resolve), the live instruction is decoded, and the requested operand's immediate or memory
 *          displacement is returned as the CURRENT value. The caller's nominal is never a short-circuit, so a same-shape
 *          / different-value drift is reported as the new value. The CodeConstant's Candidate ladder resolves the site;
 *          Zydis is confined to this TU.
 */

#include "DetourModKit/scan.hpp"

#include "internal/scan_shared.hpp"

#include "DetourModKit/memory.hpp"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>

namespace DetourModKit
{
    namespace scan
    {
        namespace
        {
            // Narrows an already-64-bit-sign-extended value to @p byte_width bytes and re-sign-extends from that width,
            // so a deliberately narrowed negative value (for example a disp8 of -1) stays negative instead of becoming
            // a large positive number. @p byte_width 0 returns the value verbatim, since Zydis has already
            // sign-extended immediates and displacements to 64 bits.
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
        } // namespace

        Result<std::int64_t> read_code_constant(const CodeConstant &code_constant, Region scope)
        {
            // Resolve the instruction site through the candidate ladder and propagate its typed failure verbatim
            // (EmptyCandidates, NoMatch, InvalidRange, ...). A code-constant site is a Direct candidate with walk_back
            // 0, so the resolved address is the instruction itself.
            const ScanRequest request{
                .ladder = code_constant.site,
                .label = "read_code_constant",
                .scope = scope,
            };
            const Result<Hit> hit = resolve(request);
            if (!hit)
            {
                return std::unexpected(hit.error());
            }
            const std::uintptr_t site = hit->address.raw();

            const Memory::ModuleRange range = detail::to_module_range(scope);

            // Read a full maximum-length instruction window, clamped to the module so the read never runs past the end
            // of the image, behind a fault guard. A truncated window that fails to decode is reported as DecodeFailed
            // below.
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
                return std::unexpected(Error{ErrorCode::DecodeFailed, "scan::read_code_constant"});
            }

            ZydisDecoder decoder;
            if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
            {
                return std::unexpected(Error{ErrorCode::DecodeFailed, "scan::read_code_constant"});
            }

            ZydisDecodedInstruction insn;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buf, avail, &insn, operands)))
            {
                return std::unexpected(Error{ErrorCode::DecodeFailed, "scan::read_code_constant"});
            }

            // Index the VISIBLE operands -- the ones a human counts in a disassembler. operand_count includes
            // implicit/hidden operands (flags, implicit registers, stack writes), which would make a fixed
            // operand_index drift between mnemonics.
            if (code_constant.operand_index >= insn.operand_count_visible)
            {
                return std::unexpected(Error{ErrorCode::OperandOutOfRange, "scan::read_code_constant"});
            }
            const ZydisDecodedOperand &operand = operands[code_constant.operand_index];

            if (code_constant.kind == OperandKind::Immediate)
            {
                if (operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    return std::unexpected(Error{ErrorCode::UnexpectedShape, "scan::read_code_constant"});
                }
                // imm.value.s is already 64-bit sign-extended by Zydis.
                return narrow_signed(static_cast<std::int64_t>(operand.imm.value.s), code_constant.byte_width);
            }

            // MemoryDisplacement. A register-indirect operand with no displacement (for example plain `[rcx]`) carries
            // no constant to read.
            if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY || !operand.mem.disp.has_displacement)
            {
                return std::unexpected(Error{ErrorCode::UnexpectedShape, "scan::read_code_constant"});
            }

            if (operand.mem.base == ZYDIS_REGISTER_RIP)
            {
                // RIP-relative: the raw displacement is measured from the next instruction, not the absolute constant
                // the caller wants. Resolve it to the absolute target so the return value is meaningful rather than a
                // misleading relative offset.
                ZyanU64 absolute = 0;
                if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operand, static_cast<ZyanU64>(site), &absolute)))
                {
                    return std::unexpected(Error{ErrorCode::DecodeFailed, "scan::read_code_constant"});
                }
                return static_cast<std::int64_t>(absolute);
            }

            // disp.value is already 64-bit sign-extended.
            return narrow_signed(static_cast<std::int64_t>(operand.mem.disp.value), code_constant.byte_width);
        }
    } // namespace scan
} // namespace DetourModKit
