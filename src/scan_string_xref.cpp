/**
 * @file scan_string_xref.cpp
 * @brief String-reference (xref) anchor resolver: locate an immutable string literal in a module image, then resolve
 *        the unique instruction that references it.
 * @details Two fail-closed phases. Phase 1 locates the single occurrence of the query string in the image's readable
 *          pages (the page-gated readable scan). Phase 2 finds the single RIP-relative reference to that string: a fast,
 *          desync-immune shape scan for the dominant lea/mov forms by default, plus an optional Zydis-verified linear
 *          sweep (broad_match) for the rarer shapes. Both phases resolve through the private engine page primitives.
 *          Zydis is confined to this TU: no public header exposes a Zydis type.
 */

#include "DetourModKit/scan.hpp"

#include "internal/memory_fault.hpp"
#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_shared.hpp"

#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"

#include <windows.h>

#include <Zydis/Zydis.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

namespace DetourModKit
{
    namespace scan
    {
        namespace
        {
            struct ReferenceScanResult
            {
                std::uintptr_t site = 0;
                std::size_t count = 0;
            };

            // The matched narrow reference's lea destination register and instruction length, recovered alongside the
            // unique-site search so the store-xref forward scan needs no second decode of the reference. Valid only
            // when the unique reference is a REX.W `lea reg, [rip+string]` (is_lea == true); a `mov reg, [rip+string]`
            // load already delivered the value to a register, so there is no store to model from the lea. reg is the
            // 4-bit x86-64 register number (REX.R << 3 | ModRM.reg).
            struct LeaReferenceInfo
            {
                std::uint8_t reg = 0;
                std::size_t instr_len = 0;
                std::uintptr_t window_end = 0;
                bool is_lea = false;
            };

            void merge_reference_scan(ReferenceScanResult &result, std::uintptr_t site, std::size_t count) noexcept
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

            // Builds a literal-byte EnginePattern from a string query: the raw bytes of the text (UTF-8, or each code
            // unit widened to UTF-16LE) plus an optional trailing NUL. The query content is emitted as a hex AOB and
            // run through parse_aob so the string scan reuses the exact same compiled-pattern path as every other AOB.
            // Returns nullopt on an empty query. Non-ASCII UTF-16 is out of scope: each byte is widened verbatim
            // (Latin-1), which covers the ASCII identifiers that anchor strings almost always are.
            std::optional<detail::EnginePattern> compile_string_pattern(const StringRefQuery &query)
            {
                if (query.text.empty())
                {
                    return std::nullopt;
                }
                const bool wide = (query.encoding == StringEncoding::Utf16le);
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
                        // High byte of a Latin-1 code unit in UTF-16LE.
                        emit(0x00);
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
                return detail::parse_aob(aob);
            }

            // Best-effort diagnosis for executable windows skipped because they faulted mid-scan. A module image is
            // rarely decommitted under a live resolve, but collect_executable_windows only proves readability at gate
            // time, so the window scans below guard their reads and a faulted window is skipped, not fatal. try_log is
            // level-gated and no-throw.
            void log_faulted_windows(std::size_t faulted_windows) noexcept
            {
                if (faulted_windows == 0)
                {
                    return;
                }
                (void)log().try_log(
                    LogLevel::Debug,
                    "scan::find_string_xref: skipped {} executable window(s) that faulted mid-scan (concurrent "
                    "decommit/reprotect).",
                    faulted_windows);
            }

            // Inner narrow scan of one already-gated executable window (no fault guard). Mutates found_count /
            // first_site, returning once a second referencing site is seen (found_count == 2) so the caller fails
            // closed on ambiguity. The recognized instruction shape is documented on scan_string_ref_narrow.
            void scan_window_narrow_body(const detail::ExecutableWindow &window, std::uintptr_t string_addr,
                                         std::size_t instr_len, std::size_t &found_count, std::uintptr_t &first_site,
                                         LeaReferenceInfo *info) noexcept
            {
                const auto *bytes = reinterpret_cast<const std::uint8_t *>(window.base);
                for (std::size_t i = 0; i + instr_len <= window.span; ++i)
                {
                    const std::uint8_t rex = bytes[i];
                    const std::uint8_t opcode = bytes[i + 1];
                    const std::uint8_t modrm = bytes[i + 2];
                    if (rex < 0x48 || rex > 0x4F || (opcode != 0x8D && opcode != 0x8B) || (modrm & 0xC7) != 0x05)
                    {
                        continue;
                    }
                    std::int32_t disp = 0;
                    std::memcpy(&disp, &bytes[i + 3], sizeof(disp));
                    const std::uintptr_t instr_addr = window.base + i;
                    const std::uintptr_t target =
                        instr_addr + instr_len + static_cast<std::uintptr_t>(static_cast<std::int64_t>(disp));
                    if (target != string_addr)
                    {
                        continue;
                    }
                    ++found_count;
                    if (found_count == 1)
                    {
                        first_site = instr_addr;
                        if (info != nullptr)
                        {
                            // REX.R (bit 2 of the REX byte) is the high bit of the ModRM.reg field; the narrow shape
                            // accepts REX in 0x48..0x4F, so REX.R may be set for an r8..r15 destination. opcode 0x8D is
                            // lea (a load whose pointer a following store can cache); 0x8B is a mov load with no such
                            // store to model.
                            const std::uint8_t reg =
                                static_cast<std::uint8_t>(((rex & 0x04) << 1) | ((modrm >> 3) & 0x07));
                            *info = LeaReferenceInfo{reg, instr_len, window.base + window.span, opcode == 0x8D};
                        }
                    }
                    else
                    {
                        // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                        return;
                    }
                }
            }

            // Window-granular TOCTOU fault guard around scan_window_narrow_body. collect_executable_windows gated each
            // window with one VirtualQuery; a concurrent decommit / reprotect before these unguarded byte reads
            // complete would otherwise fault the host. On MSVC the body runs inside a __try / __except that swallows
            // exactly the foreign-read faults (detail::is_guarded_read_fault) and reports the window faulted so
            // the sweep skips it. On MinGW x64 the body runs through the same process-wide vectored read guard the
            // guarded_read paths use (detail::run_guarded_region), so the fault is swallowed and the window skipped
            // + counted there too; only on 32-bit MinGW, where that x64-only vectored guard is unavailable, does the
            // body run directly behind just the VirtualQuery gate. Returns true when a fault was swallowed.
            bool scan_window_narrow_guarded(const detail::ExecutableWindow &window, std::uintptr_t string_addr,
                                            std::size_t instr_len, std::size_t &found_count, std::uintptr_t &first_site,
                                            LeaReferenceInfo *info) noexcept
            {
#ifdef _MSC_VER
                const std::size_t original_found_count = found_count;
                const std::uintptr_t original_first_site = first_site;
                const LeaReferenceInfo original_info = (info != nullptr) ? *info : LeaReferenceInfo{};
                __try
                {
                    scan_window_narrow_body(window, string_addr, instr_len, found_count, first_site, info);
                    return false;
                }
                __except (detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                            : EXCEPTION_CONTINUE_SEARCH)
                {
                    // The caller skips faulted windows, so discard any reference count (and recovered lea info)
                    // collected before the fault, or a partially-scanned window could leak a stale site/register.
                    found_count = original_found_count;
                    first_site = original_first_site;
                    if (info != nullptr)
                    {
                        *info = original_info;
                    }
                    return true;
                }
#elif defined(_WIN64)
                // MinGW x64: arm the process-wide vectored read guard over exactly the bytes the window gate proved
                // readable, so a concurrent decommit / reprotect that faults the scan is swallowed and the window
                // reported faulted -- the same skip-the-window contract the MSVC __except arm follows.
                const std::size_t original_found_count = found_count;
                const std::uintptr_t original_first_site = first_site;
                const LeaReferenceInfo original_info = (info != nullptr) ? *info : LeaReferenceInfo{};
                struct NarrowScanContext
                {
                    const detail::ExecutableWindow *window;
                    std::uintptr_t string_addr;
                    std::size_t instr_len;
                    std::size_t *found_count;
                    std::uintptr_t *first_site;
                    LeaReferenceInfo *info;
                } scan_ctx{&window, string_addr, instr_len, &found_count, &first_site, info};

                const auto run_scan = [](void *opaque) noexcept -> void
                {
                    auto *context = static_cast<NarrowScanContext *>(opaque);
                    scan_window_narrow_body(*context->window, context->string_addr, context->instr_len,
                                            *context->found_count, *context->first_site, context->info);
                };

                if (detail::run_guarded_region(window.base, window.base + window.span, run_scan, &scan_ctx))
                {
                    return false;
                }
                // Faulted: discard any partial count / site / lea info so a partially-scanned window cannot leak a
                // stale site or register, exactly as the MSVC arm does.
                found_count = original_found_count;
                first_site = original_first_site;
                if (info != nullptr)
                {
                    *info = original_info;
                }
                return true;
#else
                scan_window_narrow_body(window, string_addr, instr_len, found_count, first_site, info);
                return false;
#endif
            }

            // Phase 2 (default, "narrow") of find_string_xref: scan the image's execute-readable windows for the
            // dominant 64-bit string-load forms whose resolved absolute target is string_addr.
            //
            // Recognizes a mandatory REX.W prefix (0x48..0x4F), opcode 8D (lea) or 8B (mov), and a ModRM byte in the
            // RIP-relative form -- mod == 00b and rm == 101b, i.e. (modrm & 0xC7) == 0x05 -- followed by a 4-byte
            // displacement. That required REX.W byte makes the instruction exactly 7 bytes and the disp32 sits at
            // offset 3, so the candidate is self-delimiting from its shape: this needs no instruction-aligned linear
            // sweep and therefore cannot desync on data or jump tables embedded in .text.
            //
            // The resolved target is next-instruction-address + sign-extended disp32, done in unsigned modular
            // arithmetic so it is well-defined for every input. Only a target that exactly equals string_addr is
            // accepted, which is an extremely strong filter: string_addr is the already-located, plausible .rdata
            // address, so this equality subsumes the is_plausible_ptr floor and a coincidental byte sequence
            // resolving to precisely string_addr is not a realistic false positive. Counting stops at the second hit so
            // the caller can fail closed on ambiguity.
            std::uintptr_t scan_string_ref_narrow(std::uintptr_t string_addr, detail::ModuleSpan range,
                                                  std::size_t &found_count, LeaReferenceInfo &info)
            {
                found_count = 0;
                std::uintptr_t first_site = 0;
                info = LeaReferenceInfo{};
                // REX.W + opcode + ModRM + disp32.
                constexpr std::size_t instr_len = 7;
                // scan_window_narrow_body reads bytes[i], bytes[i+1], bytes[i+2] and a disp32 at bytes[i+3..i+6], so
                // the highest index it touches is i+6. The per-window loop only bounds i + instr_len <= span, so
                // instr_len must cover that widest read or the disp32 fetch could run up to four bytes past the window.
                // Pin the coupling here, beside the shape's byte count, so a future instr_len change cannot silently
                // reopen it.
                constexpr std::size_t narrow_max_read_index = 6;
                static_assert(narrow_max_read_index < instr_len,
                              "instr_len must span scan_window_narrow_body's disp32 tail read at bytes[i+3..i+6]");
                std::size_t faulted_windows = 0;

                for (const auto &window : detail::collect_executable_windows(range))
                {
                    if (window.span < instr_len)
                    {
                        continue;
                    }
                    if (scan_window_narrow_guarded(window, string_addr, instr_len, found_count, first_site, &info))
                    {
                        ++faulted_windows;
                        continue;
                    }
                    if (found_count >= 2)
                    {
                        // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                        log_faulted_windows(faulted_windows);
                        return 0;
                    }
                }
                log_faulted_windows(faulted_windows);
                return (found_count == 1) ? first_site : 0;
            }

            // Store-xref forward scan: starting just past a `lea reg, [rip+string]`, decode forward instruction by
            // instruction (Zydis, the same decoder scan_string_ref_broad uses) and return the slot a `mov [rip+slot],
            // reg` store caches the loaded pointer into, where reg is the lea destination. Decoding rather than a raw
            // byte sweep keeps the match instruction-aligned and lets the scan stop the moment the loaded register is
            // overwritten. The store shape is REX.W MOV [rip+disp32], reg64. The match is first-within-window, not
            // uniqueness-checked, so the window is kept tight. Returns 0 (the caller maps it to StoreNotFound) on no
            // store, a write to the loaded register, a CALL, a decode failure, an unreadable byte, or the bound being
            // hit. Reads go through detail::guarded_read_bytes so a truncated or unmapped tail cannot fault the host.
            std::uintptr_t scan_store_slot_after_lea(std::uintptr_t lea_site, std::size_t lea_len,
                                                     std::uintptr_t window_end, std::uint8_t lea_reg,
                                                     detail::ModuleSpan range) noexcept
            {
                // A cached pointer is stored very close to its load; bound the forward scan so a pathological region
                // cannot scan unboundedly and the store cannot be attributed to a distant, unrelated reuse of the same
                // register.
                constexpr std::size_t forward_window = 0x80; // 128 bytes.
                const std::uintptr_t scan_lo = lea_site + lea_len;
                if (scan_lo < lea_site)
                {
                    return 0;
                }
                const std::uintptr_t scan_end = (window_end < range.end) ? window_end : range.end;
                if (scan_lo >= scan_end)
                {
                    return 0;
                }
                const std::uintptr_t scan_hi =
                    (scan_end - scan_lo < forward_window) ? scan_end : scan_lo + forward_window;

                ZydisDecoder decoder;
                if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
                {
                    return 0;
                }
                // The lea wrote a 64-bit pointer, so the store source and any clobber are tested against the full
                // 64-bit register. ZydisRegisterEncode maps the x86 register number (REX.R << 3 | ModRM.reg) to the
                // GPR64 register.
                const ZydisRegister target_reg = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, lea_reg);
                if (target_reg == ZYDIS_REGISTER_NONE)
                {
                    return 0;
                }

                std::uintptr_t p = scan_lo;
                while (p < scan_hi)
                {
                    std::array<std::uint8_t, ZYDIS_MAX_INSTRUCTION_LENGTH> code{};
                    const std::size_t avail =
                        (scan_hi - p < code.size()) ? static_cast<std::size_t>(scan_hi - p) : code.size();
                    if (!detail::guarded_read_bytes(p, code.data(), avail))
                    {
                        // Unreadable byte: the store sits in the same execute-readable window as the lea, so a fault
                        // here means it is not present in mapped code.
                        return 0;
                    }

                    ZydisDecodedInstruction insn;
                    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code.data(), avail, &insn, operands)))
                    {
                        // The store must be instruction-aligned with the lea; a decode failure means alignment was lost
                        // or the bytes are not code. Fail closed rather than accept a misaligned match.
                        return 0;
                    }

                    // The store: MOV with a RIP-relative memory destination (operand 0) and the matching 64-bit source
                    // register (operand 1). ZydisCalcAbsoluteAddress turns the destination into the slot's effective
                    // address (next-instruction address + sign-extended disp32).
                    if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && insn.operand_count_visible >= 2 &&
                        operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[0].mem.base == ZYDIS_REGISTER_RIP &&
                        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].reg.value == target_reg)
                    {
                        ZyanU64 absolute = 0;
                        if (ZYAN_SUCCESS(
                                ZydisCalcAbsoluteAddress(&insn, &operands[0], static_cast<ZyanU64>(p), &absolute)))
                        {
                            return static_cast<std::uintptr_t>(absolute);
                        }
                        return 0;
                    }

                    // A CALL clobbers the caller-saved registers; a store after it cannot be trusted to cache this
                    // lea's pointer, so stop conservatively rather than attribute a post-call store to the wrong value.
                    if (insn.meta.category == ZYDIS_CATEGORY_CALL)
                    {
                        return 0;
                    }
                    // Any write to the loaded register (at any width -- a 32-bit write zeroes the upper half) means a
                    // later store would cache a different value. Check every operand, including implicit ones.
                    for (std::size_t op = 0; op < insn.operand_count; ++op)
                    {
                        const ZydisDecodedOperand &operand = operands[op];
                        if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0 &&
                            ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, operand.reg.value) ==
                                target_reg)
                        {
                            return 0;
                        }
                    }

                    p += insn.length;
                }
                return 0;
            }

            // Inner broad scan of one already-gated executable window (no fault guard). Decodes each position with
            // Zydis, counting RIP-relative operands whose absolute target equals string_addr; mutates found_count /
            // first_site and returns once a second referencing site is seen. The decode/recovery contract is documented
            // on scan_string_ref_broad.
            void scan_window_broad_body(const ZydisDecoder &decoder, const detail::ExecutableWindow &window,
                                        std::uintptr_t string_addr, std::size_t &found_count,
                                        std::uintptr_t &first_site) noexcept
            {
                const auto *bytes = reinterpret_cast<const std::uint8_t *>(window.base);
                std::size_t offset = 0;
                while (offset < window.span)
                {
                    ZydisDecodedInstruction insn;
                    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                    const std::uintptr_t instr_addr = window.base + offset;
                    if (!ZYAN_SUCCESS(
                            ZydisDecoderDecodeFull(&decoder, bytes + offset, window.span - offset, &insn, operands)))
                    {
                        // Byte-restart recovery: realign past data / jump tables.
                        ++offset;
                        continue;
                    }

                    // A referencing instruction has a visible memory operand based on RIP whose absolute target is the
                    // string. Visible operands are ordered first in the array, so iterating the visible count covers
                    // every explicit operand a disassembler would show.
                    bool references_string = false;
                    for (std::size_t op = 0; op < insn.operand_count_visible; ++op)
                    {
                        const ZydisDecodedOperand &operand = operands[op];
                        if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY || operand.mem.base != ZYDIS_REGISTER_RIP)
                        {
                            continue;
                        }
                        ZyanU64 absolute = 0;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operand, static_cast<ZyanU64>(instr_addr),
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
                            // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                            return;
                        }
                    }

                    offset += insn.length;
                }
            }

            // Window-granular TOCTOU fault guard around scan_window_broad_body; the narrow sibling
            // scan_window_narrow_guarded documents the rationale. Returns true when a fault was swallowed.
            bool scan_window_broad_guarded(const ZydisDecoder &decoder, const detail::ExecutableWindow &window,
                                           std::uintptr_t string_addr, std::size_t &found_count,
                                           std::uintptr_t &first_site) noexcept
            {
#ifdef _MSC_VER
                const std::size_t original_found_count = found_count;
                const std::uintptr_t original_first_site = first_site;
                __try
                {
                    scan_window_broad_body(decoder, window, string_addr, found_count, first_site);
                    return false;
                }
                __except (detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                            : EXCEPTION_CONTINUE_SEARCH)
                {
                    // The caller skips faulted windows, so discard any reference count collected before the fault.
                    found_count = original_found_count;
                    first_site = original_first_site;
                    return true;
                }
#elif defined(_WIN64)
                // MinGW x64: same vectored read guard as the narrow sibling, armed over the gated window bytes; a fault
                // is swallowed and the window reported faulted. Only 32-bit MinGW falls back to the bare VirtualQuery
                // gate.
                const std::size_t original_found_count = found_count;
                const std::uintptr_t original_first_site = first_site;
                struct BroadScanContext
                {
                    const ZydisDecoder *decoder;
                    const detail::ExecutableWindow *window;
                    std::uintptr_t string_addr;
                    std::size_t *found_count;
                    std::uintptr_t *first_site;
                } scan_ctx{&decoder, &window, string_addr, &found_count, &first_site};

                const auto run_scan = [](void *opaque) noexcept -> void
                {
                    auto *context = static_cast<BroadScanContext *>(opaque);
                    scan_window_broad_body(*context->decoder, *context->window, context->string_addr,
                                           *context->found_count, *context->first_site);
                };

                if (detail::run_guarded_region(window.base, window.base + window.span, run_scan, &scan_ctx))
                {
                    return false;
                }
                // Faulted: discard any partial count / site so a partially-scanned window cannot leak a stale site.
                found_count = original_found_count;
                first_site = original_first_site;
                return true;
#else
                scan_window_broad_body(decoder, window, string_addr, found_count, first_site);
                return false;
#endif
            }

            // Phase 2 ("broad") add-on for find_string_xref: a Zydis-verified linear sweep that recognizes the rarer
            // RIP-relative reference shapes the narrow scan does not model -- cmp [rip+d], imm; push [rip+d]; a no-REX
            // lea/mov; any instruction whose memory operand is [rip+disp] and resolves to string_addr. The caller
            // merges this with the narrow scan so broad_match cannot lose coverage for the default lea/mov anchors.
            //
            // The sweep decodes each position with the same decoder code_constant uses. x86-64 is not
            // self-synchronizing, so on a decode failure the cursor advances one byte to realign (recovery); on success
            // it advances by the decoded instruction length, which is always >= 1 so the sweep cannot stall. Only a
            // RIP-relative operand whose absolute target exactly equals string_addr counts. That exact-target filter
            // subsumes the plausibility floor and neutralizes a mid-.text desync. Counting stops at the second
            // referencing instruction so the caller fails closed on ambiguity.
            std::uintptr_t scan_string_ref_broad(std::uintptr_t string_addr, detail::ModuleSpan range,
                                                 std::size_t &found_count)
            {
                found_count = 0;
                std::uintptr_t first_site = 0;

                ZydisDecoder decoder;
                if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
                {
                    // A decoder that will not initialize cannot verify any reference; fail closed as "no reference"
                    // rather than guess a site.
                    return 0;
                }

                std::size_t faulted_windows = 0;
                for (const auto &window : detail::collect_executable_windows(range))
                {
                    if (scan_window_broad_guarded(decoder, window, string_addr, found_count, first_site))
                    {
                        ++faulted_windows;
                        continue;
                    }
                    if (found_count >= 2)
                    {
                        // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                        log_faulted_windows(faulted_windows);
                        return 0;
                    }
                }
                log_faulted_windows(faulted_windows);
                return (found_count == 1) ? first_site : 0;
            }

            // Best-effort enclosing-function entry for a referencing instruction. Walks backward for the nearest
            // function boundary -- a terminal RET (0xC3) or a run of INT3 (0xCC) alignment padding -- and returns the
            // first byte after it that passes is_likely_function_prologue, skipping any further INT3 padding. The
            // back-scan is bounded so a pathological region cannot scan unboundedly, and it fails closed (returns 0)
            // when no boundary is found in the window. This is a heuristic, not control-flow analysis.
            std::uintptr_t enclosing_function_start(std::uintptr_t instr_addr, std::uintptr_t window_lo) noexcept
            {
                constexpr std::uintptr_t back_scan_window = 0x2000; // 8 KiB.
                const std::uintptr_t floor =
                    (instr_addr - window_lo > back_scan_window) ? instr_addr - back_scan_window : window_lo;
                if (instr_addr <= floor)
                {
                    return 0;
                }

                // Buffer the back-scan window once instead of issuing a guarded read per byte. The window is read in
                // page-sized chunks from high address to low: a chunk that faults stops the read exactly where the
                // byte-at-a-time walk would have faulted going downward, so any boundary in the already-buffered higher
                // bytes is still found, and a fault below them returns 0 just as the per-byte version did. window[k]
                // holds the byte at floor + k; valid_lo is the lowest address actually buffered.
                std::array<std::uint8_t, static_cast<std::size_t>(back_scan_window)> window{};
                std::uintptr_t valid_lo = instr_addr;
                // Windows x86/x64 base page size; guarded_read_bytes faults at this granularity. Chunks are
                // page-aligned, not instr-aligned, so a single guarded read covers at most one page and never straddles
                // a readable/unreadable page boundary.
                constexpr std::uintptr_t page_size = 0x1000;
                for (std::uintptr_t hi = instr_addr; hi > floor;)
                {
                    const std::uintptr_t page_lo = (hi - 1) & ~(page_size - 1);
                    const std::uintptr_t lo = (page_lo > floor) ? page_lo : floor;
                    const std::size_t len = static_cast<std::size_t>(hi - lo);
                    if (!detail::guarded_read_bytes(lo, window.data() + (lo - floor), len))
                    {
                        // This page is unreadable; stop. The byte-at-a-time walk would fault on the first byte here
                        // too, after exhausting the readable bytes buffered above it.
                        break;
                    }
                    valid_lo = lo;
                    hi = lo;
                }
                if (valid_lo >= instr_addr)
                {
                    // Not even the highest chunk was readable: the first probed byte would have faulted.
                    return 0;
                }

                for (std::uintptr_t probe = instr_addr; probe > valid_lo; --probe)
                {
                    const std::uint8_t boundary_byte = window[static_cast<std::size_t>(probe - 1 - floor)];
                    if (boundary_byte != 0xCC && boundary_byte != 0xC3)
                    {
                        continue;
                    }
                    // The boundary byte ends the previous function (or its padding); the enclosing function begins at
                    // the first non-INT3 byte after it.
                    std::uintptr_t start = probe;
                    while (start < instr_addr && window[static_cast<std::size_t>(start - floor)] == 0xCC)
                    {
                        ++start;
                    }
                    return is_likely_function_prologue(Address{start}) ? start : 0;
                }
                return 0;
            }
        } // namespace

        Result<Address> find_string_xref(const StringRefQuery &query, Region scope)
        {
            if (query.text.empty())
            {
                return std::unexpected(Error{ErrorCode::EmptyQuery, "scan::find_string_xref"});
            }
            const detail::ModuleSpan range = detail::module_span(scope);
            if (!range.valid())
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::find_string_xref"});
            }

            // Phase 1: locate the single occurrence of the string in the image's readable pages. The linker pools
            // identical literals, so a second occurrence makes the anchor ambiguous and must fail closed.
            const auto pattern = compile_string_pattern(query);
            if (!pattern)
            {
                // Non-empty text that does not compile to a pattern cannot be located; report not-found rather than
                // guess.
                return std::unexpected(Error{ErrorCode::StringNotFound, "scan::find_string_xref"});
            }
            const detail::MatchResult first = detail::scan_module_readable(*pattern, range, 1);
            if (first.match == nullptr)
            {
                return std::unexpected(Error{ErrorCode::StringNotFound, "scan::find_string_xref"});
            }
            if (detail::scan_module_readable(*pattern, range, 2).match != nullptr)
            {
                return std::unexpected(Error{ErrorCode::StringAmbiguous, "scan::find_string_xref"});
            }
            const auto string_addr = reinterpret_cast<std::uintptr_t>(first.match);

            // Phase 2: find the single RIP-relative reference whose target is the string. The narrow scan is the fast,
            // desync-immune default; broad_match keeps that coverage and adds a Zydis sweep for rarer reference shapes.
            ReferenceScanResult references{};
            std::size_t narrow_count = 0;
            LeaReferenceInfo lea_info{};
            const std::uintptr_t narrow_site = scan_string_ref_narrow(string_addr, range, narrow_count, lea_info);
            merge_reference_scan(references, narrow_site, narrow_count);
            if (query.broad_match && references.count < 2)
            {
                std::size_t broad_count = 0;
                const std::uintptr_t broad_site = scan_string_ref_broad(string_addr, range, broad_count);
                merge_reference_scan(references, broad_site, broad_count);
            }

            if (references.count == 0)
            {
                return std::unexpected(Error{ErrorCode::NoReference, "scan::find_string_xref"});
            }
            if (references.count >= 2)
            {
                return std::unexpected(Error{ErrorCode::AmbiguousReference, "scan::find_string_xref"});
            }

            if (query.return_mode == XrefReturn::StringPointerSlot)
            {
                // Store-xref needs the unique reference to be the narrow `lea reg, [rip+string]` whose loaded pointer a
                // following `mov [rip+slot], reg` caches. A broad-only surviving reference (references.site differs
                // from the narrow site, so lea_info was never populated for it) or a `mov reg, [rip+string]` load has
                // no such store to attribute. With broad_match false, references.site == narrow_site whenever count ==
                // 1, so the second guard is a no-op there.
                if (!lea_info.is_lea || references.site != narrow_site)
                {
                    return std::unexpected(Error{ErrorCode::StoreNotFound, "scan::find_string_xref"});
                }
                const std::uintptr_t slot = scan_store_slot_after_lea(references.site, lea_info.instr_len,
                                                                      lea_info.window_end, lea_info.reg, range);
                if (slot == 0)
                {
                    return std::unexpected(Error{ErrorCode::StoreNotFound, "scan::find_string_xref"});
                }
                return Address{slot};
            }

            if (query.return_mode == XrefReturn::EnclosingFunction)
            {
                const std::uintptr_t function_start = enclosing_function_start(references.site, range.base);
                if (function_start == 0)
                {
                    return std::unexpected(Error{ErrorCode::FunctionNotFound, "scan::find_string_xref"});
                }
                return Address{function_start};
            }
            return Address{references.site};
        }
    } // namespace scan
} // namespace DetourModKit
