/**
 * @file scan_code_constant.cpp
 * @brief Zydis-backed extraction of a constant encoded in engine machine code: read_code_constant().
 * @details The code-side twin of the RTTI self-heal: the CodeConstant's candidate ladder resolves to an instruction
 *          site (via scan::resolve), the live instruction is decoded, and the requested operand's immediate or memory
 *          displacement is returned as the CURRENT value. The caller's nominal is never a short-circuit, so a
 *          same-shape / different-value drift is reported as the new value. The CodeConstant's Candidate ladder
 *          resolves the site; Zydis is confined to this TU.
 */

#include "DetourModKit/scan.hpp"

#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_shared.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

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

        namespace
        {
            void overlay_snapshot(std::span<std::byte> destination, std::uintptr_t destination_base,
                                  std::span<const std::byte> source, std::uintptr_t source_base) noexcept
            {
                std::size_t destination_offset = 0;
                std::size_t source_offset = 0;
                if (destination_base < source_base)
                {
                    const std::uintptr_t delta = source_base - destination_base;
                    if (delta >= destination.size())
                    {
                        return;
                    }
                    destination_offset = static_cast<std::size_t>(delta);
                }
                else
                {
                    const std::uintptr_t delta = destination_base - source_base;
                    if (delta >= source.size())
                    {
                        return;
                    }
                    source_offset = static_cast<std::size_t>(delta);
                }

                const std::size_t overlap =
                    std::min(destination.size() - destination_offset, source.size() - source_offset);
                std::memcpy(destination.data() + destination_offset, source.data() + source_offset, overlap);
            }

            [[nodiscard]] bool selector_still_resolves_site(const Candidate &candidate, Region match_span,
                                                            Region physical_source, std::uintptr_t decoded_site,
                                                            std::uintptr_t window_base,
                                                            std::span<const std::byte> window)
            {
                constexpr std::size_t MAX_EVIDENCE_SPAN =
                    detail::MAX_PATTERN_BYTES + detail::MAX_PATTERN_JUMPS * detail::MAX_JUMP_SPAN;
                constexpr std::size_t MAX_SOURCE_SPAN = MAX_EVIDENCE_SPAN + MAX_X86_INSTRUCTION_LENGTH;
                const Pattern *pattern = detail::byte_pattern_of(candidate);
                const std::uintptr_t span_base = match_span.base.raw();
                const std::uintptr_t source_base = physical_source.base.raw();
                if (pattern == nullptr || span_base == 0 || match_span.size == 0 || match_span.size > MAX_EVIDENCE_SPAN)
                {
                    return false;
                }
                if (source_base != span_base || physical_source.size < match_span.size ||
                    physical_source.size > MAX_SOURCE_SPAN)
                {
                    return false;
                }
                std::byte fresh[MAX_SOURCE_SPAN];
                if (!detail::guarded_read_bytes(source_base, fresh, physical_source.size))
                {
                    return false;
                }
                overlay_snapshot(std::span<std::byte>{fresh, physical_source.size}, source_base, window, window_base);
                const detail::EnginePattern engine = detail::engine_pattern_from(
                    *pattern, pattern->has_anchor() ? pattern->anchor_index() : pattern->size());
                const detail::RawMatch fresh_match = detail::find_pattern_raw(fresh, match_span.size, engine);
                if (fresh_match.budget_exhausted || fresh_match.start != fresh ||
                    fresh_match.end != fresh + match_span.size || fresh_match.point == nullptr ||
                    fresh_match.point < fresh || fresh_match.point > fresh + match_span.size)
                {
                    return false;
                }

                const std::size_t point_offset = static_cast<std::size_t>(fresh_match.point - fresh);
                if (point_offset > static_cast<std::size_t>(UINTPTR_MAX - source_base))
                {
                    return false;
                }
                const std::uintptr_t live_point = source_base + point_offset;
                std::optional<std::uintptr_t> fresh_site;
                if (const DirectPattern *direct = candidate.as_direct())
                {
                    fresh_site = detail::resolve_direct(live_point, *direct);
                }
                else if (const RipRelativePattern *rip = candidate.as_rip_relative())
                {
                    if (point_offset > physical_source.size ||
                        rip->instruction_length > physical_source.size - point_offset)
                    {
                        return false;
                    }
                    const std::span<const std::byte> instruction_snapshot{fresh + point_offset,
                                                                          rip->instruction_length};
                    fresh_site = detail::resolve_rip_relative_candidate(live_point, *rip, instruction_snapshot);
                }
                return fresh_site && *fresh_site == decoded_site;
            }

            Result<std::int64_t> read_code_constant_impl(const CodeConstant &code_constant, Region scope,
                                                         Region *instruction_span, Region *physical_source)
            {
                if (instruction_span != nullptr)
                {
                    *instruction_span = Region{};
                }
                if (physical_source != nullptr)
                {
                    *physical_source = Region{};
                }
                if ((code_constant.kind != OperandKind::Immediate &&
                     code_constant.kind != OperandKind::MemoryDisplacement) ||
                    !detail::valid_code_constant_byte_width(code_constant.byte_width))
                {
                    return std::unexpected(Error{ErrorCode::InvalidArg, "scan::read_code_constant"});
                }

                // Resolve the instruction site through the candidate ladder and propagate its typed failure verbatim
                // (EmptyCandidates, NoMatch, InvalidRange, ...). The resolved address must name an executable
                // instruction site; require_executable_result rejects an unsuitable rung and lets resolve() try a later
                // ladder fallback.
                //
                // A code constant is encoded in machine code. Restrict byte tiers to execute-readable pages so an
                // identical run in .rdata / .data cannot win or make the code match ambiguous. A RipRelative or
                // walked-back candidate can still transform an executable match into a data address, so enforce the
                // final-page policy in resolve() and recheck below before the fault-safe read and decode. The recheck
                // narrows, but cannot eliminate, a concurrent protection change; guarded_read_bytes preserves the
                // fail-closed host-safety guarantee.
                const ScanRequest request{
                    .ladder = code_constant.site,
                    .label = "read_code_constant",
                    .scope = scope,
                    .pages = Pages::Executable,
                    .require_executable_result = true,
                };
                const Result<detail::ResolvedScanHit> resolved = detail::resolve_scan_with_provenance(request);
                if (!resolved)
                {
                    return std::unexpected(resolved.error());
                }
                const std::uintptr_t site = resolved->hit.address.raw();
                if (physical_source != nullptr)
                {
                    *physical_source = resolved->physical_source;
                }
                if (!detail::is_executable_address(site))
                {
                    return std::unexpected(Error{ErrorCode::DecodeFailed, "scan::read_code_constant"});
                }

                const detail::ModuleSpan range = detail::module_span(scope);

                // Read a full maximum-length instruction window, clamped to the module so the read never runs past the
                // end of the image, behind a fault guard. A truncated window that fails to decode is reported as
                // DecodeFailed below.
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
                if (avail == 0 || !detail::guarded_read_bytes(site, buf, avail))
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
                if (!detail::is_executable_range(site, insn.length))
                {
                    return std::unexpected(Error{ErrorCode::DecodeFailed, "scan::read_code_constant"});
                }

                if (resolved->winning_index < code_constant.site.size() && resolved->match_span.size != 0)
                {
                    const Candidate &winning_candidate = code_constant.site[resolved->winning_index];
                    if (detail::byte_pattern_of(winning_candidate) != nullptr &&
                        !selector_still_resolves_site(winning_candidate, resolved->match_span,
                                                      resolved->physical_source, site, site,
                                                      std::span<const std::byte>{buf, avail}))
                    {
                        return std::unexpected(Error{ErrorCode::EvidenceMismatch, "scan::read_code_constant"});
                    }
                }

                // Published only once the decode has proven the length, so the provenance names the instruction's real
                // extent rather than a one-byte point a co-voting selector could straddle without overlapping.
                if (instruction_span != nullptr)
                {
                    *instruction_span = Region{Address{site}, static_cast<std::size_t>(insn.length)};
                }

                // Index the VISIBLE operands - the ones a human counts in a disassembler. operand_count includes
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

                // MemoryDisplacement. A register-indirect operand with no displacement (for example plain `[rcx]`)
                // carries no constant to read.
                if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY || !operand.mem.disp.has_displacement)
                {
                    return std::unexpected(Error{ErrorCode::UnexpectedShape, "scan::read_code_constant"});
                }

                if (operand.mem.base == ZYDIS_REGISTER_RIP)
                {
                    // RIP-relative: the raw displacement is measured from the next instruction, not the absolute
                    // constant the caller wants. Resolve it to the absolute target so the return value is meaningful
                    // rather than a misleading relative offset.
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
        } // namespace

        Result<std::int64_t> read_code_constant(const CodeConstant &code_constant, Region scope)
        {
            return read_code_constant_impl(code_constant, scope, nullptr, nullptr);
        }
    } // namespace scan

    Result<detail::ResolvedCodeConstant>
    detail::read_code_constant_with_provenance(const scan::CodeConstant &code_constant, Region scope)
    {
        Region instruction_span;
        Region physical_source;
        Result<std::int64_t> value =
            scan::read_code_constant_impl(code_constant, scope, &instruction_span, &physical_source);
        if (!value)
        {
            return std::unexpected(value.error());
        }
        return ResolvedCodeConstant{*value, instruction_span, physical_source};
    }
} // namespace DetourModKit
