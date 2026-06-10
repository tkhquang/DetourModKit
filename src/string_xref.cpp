/**
 * @file string_xref.cpp
 * @brief String-reference (xref) anchor backend: locate an immutable string
 *        literal in a module image, then resolve the unique instruction that
 *        references it.
 *
 * Two fail-closed phases. Phase 1 locates the single occurrence of the query
 * string in the image's readable pages (reusing the scanner's module-scoped
 * readable scan). Phase 2 finds the single RIP-relative reference to that string:
 * a fast, desync-immune shape scan for the dominant lea/mov forms by default, or
 * that same shape scan plus a Zydis-verified linear sweep (broad_match) that also
 * recognizes the rarer shapes (cmp/push [rip+d], no-REX lea/mov, ...).
 *
 * Zydis is confined to this translation unit, exactly as code_constant.cpp confines
 * it: no public DetourModKit header exposes a Zydis type, so an installed-package
 * consumer links DetourModKit (which already links Zydis statically) without ever
 * needing Zydis headers on its own include path. Keeping the broad sweep here also
 * keeps scanner.cpp -- the core scan engine -- free of the decoder.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"
#include "scanner_internal.hpp"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

namespace DetourModKit
{
    namespace
    {
        struct ReferenceScanResult
        {
            std::uintptr_t site = 0;
            std::size_t count = 0;
        };

        void merge_reference_scan(ReferenceScanResult &result,
                                  std::uintptr_t site, std::size_t count) noexcept
        {
            if (count == 0)
            {
                return;
            }
            if (count >= 2)
            {
                result.count = 2;
                result.site = 0;
                return;
            }
            if (result.count == 0)
            {
                result.site = site;
                result.count = 1;
                return;
            }
            if (result.site != site)
            {
                result.site = 0;
                result.count = 2;
            }
        }

        // Builds a literal-byte CompiledPattern from a string query: the raw bytes
        // of the text (UTF-8, or each code unit widened to UTF-16LE) plus an
        // optional trailing NUL. The query content is emitted as a hex AOB and run
        // through parse_aob so the string scan reuses the exact same
        // compiled-pattern path as every other AOB. Returns nullopt on an empty
        // query. Non-ASCII UTF-16 is out of scope: each byte is widened verbatim
        // (Latin-1), which covers the ASCII identifiers that anchor strings almost
        // always are.
        std::optional<Scanner::CompiledPattern> compile_string_pattern(const Scanner::StringRefQuery &query)
        {
            if (query.text.empty())
            {
                return std::nullopt;
            }
            const bool wide = (query.encoding == Scanner::StringEncoding::Utf16le);
            std::string aob;
            aob.reserve(query.text.size() * (wide ? 6 : 3) + 6);
            const auto emit = [&aob](std::uint8_t byte)
            {
                static constexpr char hex_digits[] = "0123456789ABCDEF";
                aob.push_back(hex_digits[byte >> 4]);
                aob.push_back(hex_digits[byte & 0x0F]);
                aob.push_back(' ');
            };
            for (const char ch : query.text)
            {
                emit(static_cast<std::uint8_t>(ch));
                if (wide)
                {
                    emit(0x00); // High byte of a Latin-1 code unit in UTF-16LE.
                }
            }
            if (query.require_terminator)
            {
                emit(0x00);
                if (wide)
                {
                    emit(0x00);
                }
            }
            return Scanner::parse_aob(aob);
        }

        // Phase 2 (default, "narrow") of find_string_xref: scan the image's
        // execute-readable windows for the dominant 64-bit string-load forms whose
        // resolved absolute target is string_addr.
        //
        // Recognizes a mandatory REX.W prefix (0x48..0x4F), opcode 8D (lea) or 8B
        // (mov), and a ModRM byte in the RIP-relative form -- mod == 00b and
        // rm == 101b, i.e. (modrm & 0xC7) == 0x05 -- followed by a 4-byte
        // displacement. That required REX.W byte makes the instruction exactly 7
        // bytes and the disp32 sits at offset 3, so the candidate is self-delimiting from
        // its shape: this needs no instruction-aligned linear sweep and therefore
        // cannot desync on data or jump tables embedded in .text.
        //
        // The resolved target is next-instruction-address + sign-extended disp32,
        // done in unsigned modular arithmetic so it is well-defined for every input.
        // Only a target that exactly equals string_addr is accepted, which is an
        // extremely strong filter: string_addr is the already-located, plausible
        // .rdata address, so this equality subsumes the plausible_userspace_ptr
        // floor (an implausible target cannot equal it) and a coincidental byte
        // sequence resolving to precisely string_addr is not a realistic false
        // positive. Counting stops at the second hit so the caller can fail closed
        // on ambiguity.
        std::uintptr_t scan_string_ref_narrow(std::uintptr_t string_addr, Memory::ModuleRange range,
                                              std::size_t &found_count)
        {
            found_count = 0;
            std::uintptr_t first_site = 0;
            constexpr std::size_t instr_len = 7; // REX.W + opcode + ModRM + disp32.

            for (const auto &window : Scanner::detail::collect_executable_windows(range))
            {
                if (window.span < instr_len)
                {
                    continue;
                }
                const auto *bytes = reinterpret_cast<const std::uint8_t *>(window.base);
                for (std::size_t i = 0; i + instr_len <= window.span; ++i)
                {
                    const std::uint8_t rex = bytes[i];
                    const std::uint8_t opcode = bytes[i + 1];
                    const std::uint8_t modrm = bytes[i + 2];
                    if (rex < 0x48 || rex > 0x4F ||
                        (opcode != 0x8D && opcode != 0x8B) ||
                        (modrm & 0xC7) != 0x05)
                    {
                        continue;
                    }
                    std::int32_t disp = 0;
                    std::memcpy(&disp, &bytes[i + 3], sizeof(disp));
                    const std::uintptr_t instr_addr = window.base + i;
                    const std::uintptr_t target = instr_addr + instr_len +
                                                  static_cast<std::uintptr_t>(static_cast<std::int64_t>(disp));
                    if (target != string_addr)
                    {
                        continue;
                    }
                    ++found_count;
                    if (found_count == 1)
                    {
                        first_site = instr_addr;
                    }
                    else
                    {
                        return 0; // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                    }
                }
            }
            return (found_count == 1) ? first_site : 0;
        }

        // Phase 2 ("broad") add-on for find_string_xref: a Zydis-verified linear
        // sweep that recognizes the rarer RIP-relative reference shapes the narrow
        // scan does not model -- cmp [rip+d], imm; push [rip+d]; a no-REX lea/mov;
        // any instruction whose memory operand is [rip+disp] and resolves to
        // string_addr. The caller merges this with the narrow scan so broad_match
        // cannot lose coverage for the default lea/mov anchors.
        //
        // The sweep decodes each position with the same decoder code_constant.cpp
        // uses (ZydisDecoderDecodeFull + ZydisCalcAbsoluteAddress). x86-64 is not
        // self-synchronizing, so on a decode failure the cursor advances one byte to
        // realign past embedded data or jump tables (recovery); on success it
        // advances by the decoded instruction length, which is always >= 1 so the
        // sweep cannot stall. As in the narrow scan, only a RIP-relative operand
        // whose absolute target exactly equals string_addr counts. That exact-target
        // filter subsumes the plausibility floor and neutralizes a mid-.text desync:
        // a bogus instruction decoded out of embedded data almost never carries a RIP
        // operand resolving to precisely string_addr. The one residual miss is a
        // reference truncated at the very end of a window (too few bytes to decode,
        // so the sweep byte-restarts past it); that cannot happen mid-image, since a
        // PE's executable section is one contiguous window and a real reference never
        // sits in its final few bytes. Counting stops at the second referencing
        // instruction so the caller fails closed on ambiguity.
        std::uintptr_t scan_string_ref_broad(std::uintptr_t string_addr, Memory::ModuleRange range,
                                             std::size_t &found_count)
        {
            found_count = 0;
            std::uintptr_t first_site = 0;

            ZydisDecoder decoder;
            if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                               ZYDIS_STACK_WIDTH_64)))
            {
                // A decoder that will not initialize cannot verify any reference;
                // fail closed as "no reference" rather than guess a site.
                return 0;
            }

            for (const auto &window : Scanner::detail::collect_executable_windows(range))
            {
                const auto *bytes = reinterpret_cast<const std::uint8_t *>(window.base);
                std::size_t offset = 0;
                while (offset < window.span)
                {
                    ZydisDecodedInstruction insn;
                    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                    const std::uintptr_t instr_addr = window.base + offset;
                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes + offset,
                                                             window.span - offset, &insn, operands)))
                    {
                        ++offset; // Byte-restart recovery: realign past data / jump tables.
                        continue;
                    }

                    // A referencing instruction has a visible memory operand based on
                    // RIP whose absolute target is the string. Visible operands are
                    // ordered first in the array, so iterating the visible count
                    // covers every explicit operand a disassembler would show.
                    bool references_string = false;
                    for (std::size_t op = 0; op < insn.operand_count_visible; ++op)
                    {
                        const ZydisDecodedOperand &operand = operands[op];
                        if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY ||
                            operand.mem.base != ZYDIS_REGISTER_RIP)
                        {
                            continue;
                        }
                        ZyanU64 absolute = 0;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operand,
                                                                  static_cast<ZyanU64>(instr_addr),
                                                                  &absolute)) &&
                            static_cast<std::uintptr_t>(absolute) == string_addr)
                        {
                            references_string = true;
                            break;
                        }
                    }

                    if (references_string)
                    {
                        ++found_count;
                        if (found_count == 1)
                        {
                            first_site = instr_addr;
                        }
                        else
                        {
                            return 0; // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                        }
                    }

                    offset += insn.length;
                }
            }
            return (found_count == 1) ? first_site : 0;
        }

        // Best-effort enclosing-function entry for a referencing instruction. Walks
        // backward for the nearest function boundary -- a terminal RET (0xC3) or a
        // run of INT3 (0xCC) alignment padding -- and returns the first byte after
        // it that passes is_likely_function_prologue, skipping any further INT3
        // padding. The back-scan is bounded so a pathological region cannot scan
        // unboundedly, and it fails closed (returns 0) when no boundary is found in
        // the window. This is a heuristic, not control-flow analysis: a 0xC3 / 0xCC
        // byte that is actually operand data inside an instruction can mark a false
        // boundary, which is why the default return mode is the exact referencing
        // instruction.
        std::uintptr_t enclosing_function_start(std::uintptr_t instr_addr, std::uintptr_t window_lo) noexcept
        {
            constexpr std::uintptr_t back_scan_window = 0x2000; // 8 KiB.
            const std::uintptr_t floor =
                (instr_addr - window_lo > back_scan_window) ? instr_addr - back_scan_window : window_lo;

            for (std::uintptr_t probe = instr_addr; probe > floor; --probe)
            {
                const auto boundary_byte = Memory::seh_read<std::uint8_t>(probe - 1);
                if (!boundary_byte)
                {
                    return 0;
                }
                if (*boundary_byte != 0xCC && *boundary_byte != 0xC3)
                {
                    continue;
                }
                // The boundary byte ends the previous function (or its padding); the
                // enclosing function begins at the first non-INT3 byte after it.
                std::uintptr_t start = probe;
                while (start < instr_addr)
                {
                    const auto pad_byte = Memory::seh_read<std::uint8_t>(start);
                    if (!pad_byte)
                    {
                        return 0;
                    }
                    if (*pad_byte != 0xCC)
                    {
                        break;
                    }
                    ++start;
                }
                return Scanner::is_likely_function_prologue(start) ? start : 0;
            }
            return 0;
        }
    } // anonymous namespace

    std::expected<std::uintptr_t, Scanner::StringXrefError>
    Scanner::find_string_xref(const StringRefQuery &query, Memory::ModuleRange range)
    {
        if (query.text.empty())
        {
            return std::unexpected(StringXrefError::EmptyQuery);
        }
        if (!range.valid())
        {
            return std::unexpected(StringXrefError::InvalidRange);
        }

        // Phase 1: locate the single occurrence of the string in the image's
        // readable pages. The linker pools identical literals, so a second
        // occurrence makes the anchor ambiguous and must fail closed.
        const auto pattern = compile_string_pattern(query);
        if (!pattern)
        {
            // Non-empty text that does not compile to a pattern cannot be located;
            // report not-found rather than guess.
            return std::unexpected(StringXrefError::StringNotFound);
        }
        const std::byte *first = detail::scan_module_readable(*pattern, range, 1);
        if (first == nullptr)
        {
            return std::unexpected(StringXrefError::StringNotFound);
        }
        if (detail::scan_module_readable(*pattern, range, 2) != nullptr)
        {
            return std::unexpected(StringXrefError::StringAmbiguous);
        }
        const auto string_addr = reinterpret_cast<std::uintptr_t>(first);

        // Phase 2: find the single RIP-relative reference whose target is the
        // string. The narrow scan is the fast, desync-immune default; broad_match
        // keeps that coverage and adds a Zydis sweep for rarer reference shapes.
        ReferenceScanResult references{};
        std::size_t narrow_count = 0;
        const std::uintptr_t narrow_site = scan_string_ref_narrow(string_addr, range, narrow_count);
        merge_reference_scan(references, narrow_site, narrow_count);
        if (query.broad_match && references.count < 2)
        {
            std::size_t broad_count = 0;
            const std::uintptr_t broad_site = scan_string_ref_broad(string_addr, range, broad_count);
            merge_reference_scan(references, broad_site, broad_count);
        }

        if (references.count == 0)
        {
            return std::unexpected(StringXrefError::NoReference);
        }
        if (references.count >= 2)
        {
            return std::unexpected(StringXrefError::AmbiguousReference);
        }

        if (query.return_mode == XrefReturn::EnclosingFunction)
        {
            const std::uintptr_t function_start = enclosing_function_start(references.site, range.base);
            if (function_start == 0)
            {
                return std::unexpected(StringXrefError::FunctionNotFound);
            }
            return function_start;
        }
        return references.site;
    }
} // namespace DetourModKit
