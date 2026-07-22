/**
 * @file scan_string_xref.cpp
 * @brief String-reference (xref) anchor resolver: locate an immutable string literal in a module image, then resolve
 *        the unique instruction that references it.
 * @details Two fail-closed phases. Phase 1 locates the single occurrence of the query string in the image's readable
 *          pages (the page-gated readable scan). Phase 2 finds the single RIP-relative reference to that string: a
 *          fast, desync-immune shape scan for the dominant lea/mov forms by default, plus Zydis-verified candidate
 *          discovery for opt-in broad matches and derived-return uniqueness confirmation. Both phases resolve through
 *          the private engine page primitives. Zydis is confined to this TU: no public header exposes a Zydis type.
 */

#include "DetourModKit/scan.hpp"

#include "internal/memory_fault.hpp"
#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"
#include "internal/scan_exclusions.hpp"
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
#include <span>
#include <string>
#include <vector>

namespace DetourModKit
{
    namespace scan
    {
        namespace
        {
            struct ReferenceScanResult
            {
                std::uintptr_t site = 0;
                // Address of the reference's disp32 field. This, not the instruction start, is what identifies a
                // reference across the two phases: the field address is a property of the reference itself and is
                // identical in both, while the instruction start is a framing verdict the leaf/JIT probe may place
                // earlier than the narrow shape scan does when a byte the decoder absorbs precedes the instruction.
                std::uintptr_t key = 0;
                std::size_t count = 0;
                // True when any execute-readable window faulted mid-sweep and was skipped under the TOCTOU guard, so
                // the reference count is only a lower bound: a second reference to the string could hide in the skipped
                // window. A uniqueness verdict must then fail closed to ambiguous rather than report the lone surviving
                // reference as the unique site. Accumulated across the narrow and broad merges.
                bool incomplete = false;
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

            void merge_reference_scan(ReferenceScanResult &result, std::uintptr_t site, std::uintptr_t key,
                                      std::size_t count, bool incomplete) noexcept
            {
                // Incompleteness is monotonic: once either sweep skipped a faulted window, the merged count is a lower
                // bound regardless of what the other sweep found.
                result.incomplete = result.incomplete || incomplete;
                if (count == 0)
                {
                    return;
                }
                if (count >= 2)
                {
                    result.count = 2;
                    result.site = 0;
                    result.key = 0;
                    return;
                }
                if (result.count == 0)
                {
                    result.site = site;
                    result.key = key;
                    result.count = 1;
                    return;
                }
                if (result.key != key)
                {
                    result.site = 0;
                    result.key = 0;
                    result.count = 2;
                }
            }

            // Decodes one code point from well-formed UTF-8 at @p pos, advancing it past the sequence. Returns false on
            // any ill-formed input: a continuation byte in leader position, a truncated tail, a leader byte that no
            // valid encoding uses (0xC0/0xC1/0xF5..0xFF), an overlong form, a value above U+10FFFF, or a surrogate code
            // point, which UTF-8 must never encode. Rejecting rather than substituting U+FFFD is deliberate: a
            // replacement character would make the scan search for a literal the caller never asked for.
            bool decode_utf8(std::string_view text, std::size_t &pos, char32_t &out) noexcept
            {
                const auto byte_at = [&text](std::size_t index) noexcept
                { return static_cast<std::uint8_t>(text[index]); };

                const std::uint8_t lead = byte_at(pos);
                std::size_t extra = 0;
                char32_t value = 0;
                if (lead < 0x80)
                {
                    out = lead;
                    ++pos;
                    return true;
                }
                if (lead >= 0xC2 && lead <= 0xDF)
                {
                    extra = 1;
                    value = lead & 0x1FU;
                }
                else if (lead >= 0xE0 && lead <= 0xEF)
                {
                    extra = 2;
                    value = lead & 0x0FU;
                }
                else if (lead >= 0xF0 && lead <= 0xF4)
                {
                    extra = 3;
                    value = lead & 0x07U;
                }
                else
                {
                    return false;
                }

                // The caller guarantees pos < size, so size - pos is at least 1; the sequence fits only when every
                // continuation byte is still inside the view. Subtracting keeps the check free of pointer overflow.
                if (extra >= text.size() - pos)
                {
                    return false;
                }
                for (std::size_t i = 1; i <= extra; ++i)
                {
                    const std::uint8_t continuation = byte_at(pos + i);
                    if ((continuation & 0xC0U) != 0x80U)
                    {
                        return false;
                    }
                    value = (value << 6) | (continuation & 0x3FU);
                }

                // The leader ranges above already exclude the two-byte overlongs (0xC0/0xC1); these reject the three-
                // and four-byte overlongs, the surrogate range, and anything past the Unicode maximum.
                if ((extra == 2 && value < 0x800) || (extra == 3 && value < 0x10000) ||
                    (value >= 0xD800 && value <= 0xDFFF) || value > 0x10FFFF)
                {
                    return false;
                }
                pos += extra + 1;
                out = value;
                return true;
            }

            // Why a query cannot be compiled, so the caller can report a precise error instead of "not found".
            enum class QueryTextStatus : std::uint8_t
            {
                Ok,
                Malformed
            };

            // Builds a literal-byte EnginePattern from a string query plus an optional trailing NUL, emitted as a hex
            // AOB and run through parse_aob so the string scan reuses the exact same compiled-pattern path as every
            // other AOB.
            //
            // StringEncoding::Utf8 searches for query.text byte for byte, so a caller may anchor on any byte sequence.
            // StringEncoding::Utf16le searches for the UTF-16LE encoding of that text, which requires it to be
            // well-formed UTF-8: each code point is transcoded, and a supplementary one becomes a surrogate pair.
            // Byte-wise widening is correct only for ASCII and would search for a different literal otherwise.
            //
            // An embedded NUL is rejected on both routes: it contradicts require_terminator, cannot appear in the C
            // string literals these anchors name, and would otherwise make the compiled pattern's terminator ambiguous.
            std::optional<detail::EnginePattern> compile_string_pattern(const StringRefQuery &query,
                                                                        QueryTextStatus &status)
            {
                status = QueryTextStatus::Ok;
                if (query.text.find('\0') != std::string_view::npos)
                {
                    status = QueryTextStatus::Malformed;
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
                const auto emit_utf16_unit = [&emit](char16_t unit)
                {
                    emit(static_cast<std::uint8_t>(unit & 0xFFU));
                    emit(static_cast<std::uint8_t>((unit >> 8) & 0xFFU));
                };

                if (!wide)
                {
                    for (const char ch : query.text)
                    {
                        emit(static_cast<std::uint8_t>(ch));
                    }
                }
                else
                {
                    std::size_t pos = 0;
                    while (pos < query.text.size())
                    {
                        char32_t code_point = 0;
                        if (!decode_utf8(query.text, pos, code_point))
                        {
                            status = QueryTextStatus::Malformed;
                            return std::nullopt;
                        }
                        if (code_point < 0x10000)
                        {
                            emit_utf16_unit(static_cast<char16_t>(code_point));
                        }
                        else
                        {
                            const char32_t offset = code_point - 0x10000;
                            emit_utf16_unit(static_cast<char16_t>(0xD800 + (offset >> 10)));
                            emit_utf16_unit(static_cast<char16_t>(0xDC00 + (offset & 0x3FF)));
                        }
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
            // complete would otherwise fault the host. On MSVC the body runs inside a __try / __except whose filter is
            // the shared detail::guarded_fault_filter: it swallows exactly the foreign-read fault set
            // (detail::is_guarded_read_fault), re-arms a consumed PAGE_GUARD, and reports the window faulted so the
            // sweep skips it. On MinGW x64 the body runs through the same process-wide vectored read guard the
            // guarded_read paths use (detail::run_guarded_region), so the fault is swallowed and the window skipped
            // + counted there too. A 32-bit build is rejected by the defines.hpp architecture gate, so only the two
            // x64 arms exist. Returns true when a fault was swallowed.
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
                __except (detail::guarded_fault_filter(GetExceptionInformation()))
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
            std::uintptr_t scan_string_ref_narrow(std::uintptr_t string_addr,
                                                  std::span<const detail::ExecutableWindow> windows,
                                                  std::size_t &found_count, LeaReferenceInfo &info, bool &incomplete)
            {
                found_count = 0;
                incomplete = false;
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

                // Cross-window back-carry, mirroring the phase-1 scan_regions_filtered carry. A `.text` section split
                // by a VirtualProtect into two abutting execute-readable regions yields two windows; an instruction
                // that STARTS in the first window's tail and ENDS in the second fits in neither window's independent
                // [0, span - instr_len] sweep and would be silently missed -- so with two real references the straddler
                // is dropped and the survivor falsely certified unique (a wrong-site anchor). When this window abuts
                // the previous one, extend its scan start back by instr_len - 1 so those straddlers are caught. The
                // carry bytes lie inside the previous window (gated readable at collect time and abutting), so the
                // guarded read stays over already-gated memory. No count floor is needed: a fixed-length instruction
                // starting in the carry region [base - (instr_len-1), base) can never have fit in the previous window's
                // own sweep (its starts end one byte earlier, at base - instr_len), so the carry region is disjoint and
                // nothing is double-counted. The carry is bounded by the previous window's span so it never reads
                // before it into a possible gap; page-granular regions make that bound a formality.
                std::uintptr_t prev_end = 0;
                std::size_t prev_span = 0;
                bool have_prev = false;
                for (const detail::ExecutableWindow &window : windows)
                {
                    detail::ExecutableWindow effective = window;
                    if (have_prev && window.base == prev_end)
                    {
                        const std::size_t carry = (instr_len - 1 < prev_span) ? instr_len - 1 : prev_span;
                        effective.base = window.base - carry;
                        effective.span = window.span + carry;
                    }
                    prev_end = window.base + window.span;
                    prev_span = window.span;
                    have_prev = true;

                    if (effective.span < instr_len)
                    {
                        continue;
                    }
                    if (scan_window_narrow_guarded(effective, string_addr, instr_len, found_count, first_site, &info))
                    {
                        ++faulted_windows;
                        continue;
                    }
                    if (found_count >= 2)
                    {
                        // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                        incomplete = faulted_windows > 0;
                        log_faulted_windows(faulted_windows);
                        return 0;
                    }
                }
                // A skipped faulted window makes the count a lower bound: surface it so a lone surviving reference is
                // not committed as unique. The caller fails closed on the truncation itself.
                incomplete = faulted_windows > 0;
                log_faulted_windows(faulted_windows);
                return (found_count == 1) ? first_site : 0;
            }

            // Store-xref forward scan: starting just past a `lea reg, [rip+string]`, decode forward instruction by
            // instruction (Zydis, the same decoder scan_string_ref_broad uses) and return the slot a `mov [rip+slot],
            // reg` store caches the loaded pointer into, where reg is the lea destination. Decoding rather than a raw
            // byte sweep keeps the match instruction-aligned and lets the scan stop the moment the loaded register is
            // overwritten. The store shape is REX.W MOV [rip+disp32], reg64. The match is first-within-window, not
            // uniqueness-checked, so the window is kept tight. Returns 0 (the caller maps it to StoreNotFound) on no
            // store, a write to the loaded register, a CALL, an unconditional control transfer (JMP / RET), UD2, or an
            // INT3, a decode failure, an unreadable byte, or the bound being hit. Reads go through
            // detail::guarded_read_bytes so a truncated or unmapped tail cannot fault the host.
            //
            // The scan must be control-flow-aware: the linear byte window can run past the end of this function into
            // the next one, and a store there caches an UNRELATED pointer. A `ret`, an unconditional `jmp` (a tail
            // call), UD2, or an `int3` alignment pad each ends this function's straight-line flow, so any store decoded
            // after one of them is not on the lea's execution path. Crucially, INT3 (0xCC) decodes as a valid
            // one-byte instruction and UD2 (0F 0B) as a valid two-byte instruction, neither of which clobbers the
            // loaded register, is a CALL, or carries a RET / unconditional-branch category, so a category-only check
            // would miss them: without an explicit mnemonic stop the cursor would walk straight through the INT3
            // padding between functions into the next one and return its store -- a wrong slot the mod would then
            // write through, strictly worse than a fail-closed StoreNotFound. A NOP (0x90) is deliberately NOT a stop
            // even though it can also pad, because unlike an INT3 run it legitimately appears as intra-function
            // alignment; the common-case RET / JMP / CALL stops already end the scan at the true function boundary
            // before any inter-function padding is reached. A CONDITIONAL branch (Jcc) is deliberately NOT a stop:
            // its fall-through path can legitimately reach the caching store, so stopping there would drop a real
            // capability.
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
                    // A RET, an unconditional JMP (a tail call), or UD2 ends this function's straight-line flow. INT3
                    // padding also marks an inter-function boundary. Any store past one of them belongs to a different
                    // function, so fail closed rather than walk into the next function's store. A conditional branch
                    // (ZYDIS_CATEGORY_COND_BR) is intentionally excluded -- its fall-through can still reach the
                    // caching store. INT3 and UD2 are checked explicitly because they decode as valid instructions
                    // that neither category check catches.
                    if (insn.meta.category == ZYDIS_CATEGORY_RET || insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                        insn.mnemonic == ZYDIS_MNEMONIC_INT3 || insn.mnemonic == ZYDIS_MNEMONIC_UD2)
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

            // Most bytes an x86-64 instruction can place before its disp32 field: up to four legacy prefixes, a REX
            // byte, a three-byte opcode escape, and the ModRM byte the displacement directly follows. Bounding the
            // leaf/JIT backward probe by this is what keeps candidate verification constant-cost.
            constexpr std::size_t MAX_BYTES_BEFORE_DISP32 = 9;

            // Instructions decoded while walking a trusted function stream forward to reach one candidate. A real
            // function cannot exceed this before the walk is worth abandoning, and the bound stops a corrupt or hostile
            // .pdata record from turning one candidate into an unbounded decode.
            constexpr std::size_t MAX_TRUSTED_STREAM_STEPS = 8192;

            // True when @p insn has a visible memory operand based on RIP whose absolute target is @p string_addr, and
            // that operand's displacement field sits exactly at @p disp_field. Visible operands are ordered first in
            // the array, so iterating the visible count covers every explicit operand a disassembler would show. The
            // displacement-position check is what makes this a verification of a specific candidate rather than a
            // second, independent search: a decode that happens to reference the string through some other field does
            // not confirm the framing under test.
            bool instruction_references_at(const ZydisDecodedInstruction &insn, const ZydisDecodedOperand *operands,
                                           std::uintptr_t instr_addr, std::uintptr_t disp_field,
                                           std::uintptr_t string_addr) noexcept
            {
                if (insn.raw.disp.size != 32 || instr_addr + insn.raw.disp.offset != disp_field)
                {
                    return false;
                }
                for (std::size_t op = 0; op < insn.operand_count_visible; ++op)
                {
                    const ZydisDecodedOperand &operand = operands[op];
                    if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY || operand.mem.base != ZYDIS_REGISTER_RIP)
                    {
                        continue;
                    }
                    ZyanU64 absolute = 0;
                    if (ZYAN_SUCCESS(
                            ZydisCalcAbsoluteAddress(&insn, &operand, static_cast<ZyanU64>(instr_addr), &absolute)) &&
                        static_cast<std::uintptr_t>(absolute) == string_addr)
                    {
                        return true;
                    }
                }
                return false;
            }

            // Resolves the candidate at @p disp_field against a decode stream that starts at a trusted boundary. The
            // innermost .pdata RUNTIME_FUNCTION's BeginAddress is a real instruction boundary by construction, so
            // decoding forward from it reaches @p disp_field synchronized with the compiler's own framing.
            //
            // Three outcomes, and the difference between the last two is load-bearing. A nonzero value is the
            // referencing instruction's address. Zero means the stream REACHED the candidate and rejected it, so
            // probing a shorter inner framing would contradict a boundary the compiler itself declared. No value means
            // the stream produced no verdict at all -- no record covers the candidate, the record is unreadable, the
            // function begins outside the bytes this window proved readable, or the decode broke or ran out of budget
            // before arriving. Treating no verdict as a rejection is what would let one undecodable byte (an embedded
            // jump table is the common case) suppress every reference after it in the same function, which is the
            // failure mode this whole discovery path exists to prevent, so those cases fall through to the probe.
            std::optional<std::uintptr_t> resolve_candidate_from_trusted_origin(const ZydisDecoder &decoder,
                                                                                const detail::ExecutableWindow &window,
                                                                                std::uintptr_t disp_field,
                                                                                std::uintptr_t string_addr) noexcept
            {
                DWORD64 image_base = 0;
                const PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(disp_field, &image_base, nullptr);
                if (entry == nullptr || image_base == 0)
                {
                    return std::nullopt;
                }
                RUNTIME_FUNCTION record{};
                if (!detail::guarded_read_bytes(reinterpret_cast<std::uintptr_t>(entry), &record, sizeof(record)))
                {
                    // The record exists but could not be read, so it adjudicates nothing.
                    return std::nullopt;
                }
                const std::uintptr_t origin = static_cast<std::uintptr_t>(image_base) + record.BeginAddress;
                if (origin < window.base || origin > disp_field)
                {
                    // Decoding must start inside bytes this window already proved readable, and a record that does not
                    // actually precede the candidate cannot describe its stream. A function whose entry lies in an
                    // earlier window is ordinary, not suspicious, so this yields no verdict rather than a rejection.
                    return std::nullopt;
                }

                const auto *bytes = reinterpret_cast<const std::uint8_t *>(window.base);
                std::uintptr_t cursor = origin;
                for (std::size_t step = 0; step < MAX_TRUSTED_STREAM_STEPS; ++step)
                {
                    if (cursor >= window.base + window.span)
                    {
                        // The stream left the readable window before arriving, so it never saw the candidate.
                        return std::nullopt;
                    }
                    ZydisDecodedInstruction insn;
                    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                    const std::size_t offset = static_cast<std::size_t>(cursor - window.base);
                    if (!ZYAN_SUCCESS(
                            ZydisDecoderDecodeFull(&decoder, bytes + offset, window.span - offset, &insn, operands)))
                    {
                        // Real functions carry undecodable bytes: an embedded jump table, compiler padding, or data a
                        // switch lowered into .text. The stream stops there and adjudicates nothing beyond it.
                        return std::nullopt;
                    }
                    if (cursor + insn.length > disp_field)
                    {
                        // Arrived. This instruction is the compiler's own framing of the candidate's bytes, so its
                        // verdict is final in both directions.
                        return instruction_references_at(insn, operands, cursor, disp_field, string_addr) ? cursor : 0;
                    }
                    cursor += insn.length;
                }
                return std::nullopt;
            }

            // Resolves the candidate at @p disp_field without a trusted origin: leaf functions carry no unwind data,
            // and JIT or raw code buffers have no exception table at all. Every instruction start that could place a
            // disp32 at the candidate is probed, so no single framing can suppress the reference.
            //
            // Probing runs from the earliest possible start toward the candidate, so the LONGEST accepted framing wins.
            // That is the disambiguation rule, not a preference: an instruction's encoding includes its legacy prefixes
            // and REX byte, so a start that skips one decodes a different instruction that merely happens to share the
            // displacement. Reporting the shorter framing would put the site one byte past the instruction and disagree
            // with the exact narrow shape scan for the very shapes both can see.
            //
            // The converse is possible too and is not a defect here: an unrelated byte before the true start that the
            // decoder absorbs as a legacy prefix or a superseded REX yields an earlier accepted framing than the narrow
            // shape scan reports. The two phases therefore identify a reference by its displacement FIELD, not by the
            // instruction start, so a framing disagreement over one genuine reference cannot manufacture ambiguity.
            std::uintptr_t resolve_candidate_by_probe(const ZydisDecoder &decoder,
                                                      const detail::ExecutableWindow &window, std::uintptr_t disp_field,
                                                      std::uintptr_t string_addr) noexcept
            {
                const auto *bytes = reinterpret_cast<const std::uint8_t *>(window.base);
                const std::uintptr_t floor = (disp_field - window.base >= MAX_BYTES_BEFORE_DISP32)
                                                 ? disp_field - MAX_BYTES_BEFORE_DISP32
                                                 : window.base;
                for (std::uintptr_t start = floor; start < disp_field; ++start)
                {
                    ZydisDecodedInstruction insn;
                    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                    const std::size_t offset = static_cast<std::size_t>(start - window.base);
                    if (!ZYAN_SUCCESS(
                            ZydisDecoderDecodeFull(&decoder, bytes + offset, window.span - offset, &insn, operands)))
                    {
                        continue;
                    }
                    if (instruction_references_at(insn, operands, start, disp_field, string_addr))
                    {
                        return start;
                    }
                }
                return 0;
            }

            // Inner broad scan of one already-gated executable window (no fault guard). Mutates found_count /
            // first_site and returns once a second referencing site is seen. The discovery/verification contract is
            // documented on scan_string_ref_broad.
            void scan_window_broad_body(const ZydisDecoder &decoder, const detail::ExecutableWindow &window,
                                        std::uintptr_t string_addr, std::uintptr_t count_floor,
                                        std::size_t &found_count, std::uintptr_t &first_site,
                                        std::uintptr_t &first_key) noexcept
            {
                if (window.span < sizeof(std::int32_t))
                {
                    return;
                }
                const auto *bytes = reinterpret_cast<const std::uint8_t *>(window.base);
                const std::size_t limit = window.span - sizeof(std::int32_t);
                for (std::size_t i = 0; i <= limit; ++i)
                {
                    // Candidate discovery, at every byte offset and independent of any decode. A RIP-relative operand
                    // computes target = end_of_instruction + disp32, and the instruction ends at the displacement field
                    // plus four plus whatever immediate follows, so a field can only reference the string when
                    // string_addr - (field + 4) - disp is one of the immediate widths an x86-64 instruction may place
                    // after a disp32. This is the property that makes the sweep desync-immune: a false boundary can
                    // mis-frame the bytes around a reference, but it cannot make this arithmetic stop holding.
                    std::int32_t disp = 0;
                    std::memcpy(&disp, bytes + i, sizeof(disp));
                    const std::uintptr_t disp_field = window.base + i;
                    const std::int64_t immediate_width = static_cast<std::int64_t>(string_addr) -
                                                         static_cast<std::int64_t>(disp_field + sizeof(disp)) - disp;
                    if (immediate_width != 0 && immediate_width != 1 && immediate_width != 2 && immediate_width != 4)
                    {
                        continue;
                    }

                    // Verification. The trusted .pdata stream decides wherever an exception record covers the
                    // candidate; otherwise the bounded probe covers leaf functions and code with no registered table.
                    const std::optional<std::uintptr_t> trusted_site =
                        resolve_candidate_from_trusted_origin(decoder, window, disp_field, string_addr);
                    const std::uintptr_t site =
                        trusted_site.has_value() ? *trusted_site
                                                 : resolve_candidate_by_probe(decoder, window, disp_field, string_addr);
                    if (site == 0)
                    {
                        continue;
                    }

                    // Cross-window back-carry de-duplication: this window may have been extended backward into the
                    // previous window's tail so a boundary-straddling instruction is discovered whole (see the loop in
                    // scan_string_ref_broad). An instruction that ENDS at or before count_floor lies wholly in the
                    // previous window and was already counted there. count_floor equals this window's real base, so an
                    // un-extended window counts every reference it finds.
                    const std::uintptr_t site_end = disp_field + sizeof(disp) + static_cast<std::uintptr_t>(
                                                                                   immediate_width);
                    if (site_end <= count_floor)
                    {
                        continue;
                    }

                    ++found_count;
                    if (found_count == 1)
                    {
                        first_site = site;
                        first_key = disp_field;
                    }
                    else
                    {
                        // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                        return;
                    }
                }
            }

            // Window-granular TOCTOU fault guard around scan_window_broad_body; the narrow sibling
            // scan_window_narrow_guarded documents the rationale. The address-screening filter is used here rather than
            // the narrow sibling's whole-region one because this body leaves the window: resolve_candidate_from_trusted
            // _origin calls RtlLookupFunctionEntry, whose dynamic-function-table walk is not the scanned range. A fault
            // raised in there is a defect or a hostile registration, not the concurrent unmap this guard exists to
            // absorb, so it must reach the host's handlers instead of being recorded as a faulted window. The nested
            // guarded_read_bytes of the .pdata record carries its own inner range filter, so its faults never arrive
            // here. Returns true when a fault was swallowed.
            bool scan_window_broad_guarded(const ZydisDecoder &decoder, const detail::ExecutableWindow &window,
                                           std::uintptr_t string_addr, std::uintptr_t count_floor,
                                           std::size_t &found_count, std::uintptr_t &first_site,
                                           std::uintptr_t &first_key) noexcept
            {
#ifdef _MSC_VER
                const std::size_t original_found_count = found_count;
                const std::uintptr_t original_first_site = first_site;
                const std::uintptr_t original_first_key = first_key;
                __try
                {
                    scan_window_broad_body(decoder, window, string_addr, count_floor, found_count, first_site,
                                           first_key);
                    return false;
                }
                __except (detail::guarded_range_fault_filter(GetExceptionInformation(), window.base,
                                                             window.base + window.span))
                {
                    // The caller skips faulted windows, so discard any reference count collected before the fault.
                    found_count = original_found_count;
                    first_site = original_first_site;
                    first_key = original_first_key;
                    return true;
                }
#elif defined(_WIN64)
                // MinGW x64: same vectored read guard as the narrow sibling, armed over the gated window bytes; a fault
                // is swallowed and the window reported faulted. A 32-bit build is rejected by the defines.hpp
                // architecture gate, so only the two x64 arms exist.
                const std::size_t original_found_count = found_count;
                const std::uintptr_t original_first_site = first_site;
                const std::uintptr_t original_first_key = first_key;
                struct BroadScanContext
                {
                    const ZydisDecoder *decoder;
                    const detail::ExecutableWindow *window;
                    std::uintptr_t string_addr;
                    std::uintptr_t count_floor;
                    std::size_t *found_count;
                    std::uintptr_t *first_site;
                    std::uintptr_t *first_key;
                } scan_ctx{&decoder, &window, string_addr, count_floor, &found_count, &first_site, &first_key};

                const auto run_scan = [](void *opaque) noexcept -> void
                {
                    auto *context = static_cast<BroadScanContext *>(opaque);
                    scan_window_broad_body(*context->decoder, *context->window, context->string_addr,
                                           context->count_floor, *context->found_count, *context->first_site,
                                           *context->first_key);
                };

                if (detail::run_guarded_region(window.base, window.base + window.span, run_scan, &scan_ctx))
                {
                    return false;
                }
                // Faulted: discard any partial count / site so a partially-scanned window cannot leak a stale site.
                found_count = original_found_count;
                first_site = original_first_site;
                first_key = original_first_key;
                return true;
#endif
            }

            // Phase 2 ("broad") add-on for find_string_xref: a Zydis-verified sweep that recognizes the rarer
            // RIP-relative reference shapes the narrow scan does not model -- cmp [rip+d], imm; push [rip+d]; a no-REX
            // lea/mov; any instruction whose memory operand is [rip+disp] and resolves to string_addr. The caller
            // merges this with the narrow scan so broad_match cannot lose coverage for the default lea/mov anchors.
            //
            // Discovery is separated from framing, because x86-64 is not self-synchronizing and a linear decode is
            // therefore not a search: one mis-framed instruction consumes the bytes of the next, so a single false
            // boundary early in a window can swallow a real referencing instruction and report it absent. Discovery
            // instead tests the RIP-relative arithmetic at EVERY byte offset, which no framing can affect, and only the
            // handful of positions that survive it pay for a decode. Each survivor is then framed against the innermost
            // .pdata function start where one exists (a boundary the compiler itself declared) and against a bounded
            // probe of every possible instruction start otherwise, which is what covers leaf functions and code with no
            // registered exception table. Counting stops at the second referencing instruction so the caller fails
            // closed on ambiguity.
            std::uintptr_t scan_string_ref_broad(std::uintptr_t string_addr,
                                                 std::span<const detail::ExecutableWindow> windows,
                                                 std::size_t &found_count, std::uintptr_t &out_key, bool &incomplete)
            {
                found_count = 0;
                out_key = 0;
                incomplete = false;
                std::uintptr_t first_site = 0;
                std::uintptr_t first_key = 0;

                ZydisDecoder decoder;
                if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
                {
                    // A decoder that will not initialize cannot verify any reference; fail closed as "no reference"
                    // rather than guess a site.
                    return 0;
                }

                std::size_t faulted_windows = 0;
                // Cross-window back-carry, mirroring the narrow scan (and phase 1). A variable-length reference can
                // straddle the split between two abutting execute-readable windows, decodable by neither window's own
                // sweep (the previous window's decoder truncates at its end, and this window decodes from its base,
                // mid-instruction). When this window abuts the previous, decode from ZYDIS_MAX_INSTRUCTION_LENGTH - 1
                // bytes earlier so the straddler is decoded whole. A count floor at this window's real base then
                // de-duplicates: an instruction ending at or before the base was already counted by the previous
                // window, so scan_window_broad_body skips it (see there). The carry is bounded by the previous window's
                // span so it never reads before it; page-granular regions make that bound a formality.
                constexpr std::size_t broad_carry = ZYDIS_MAX_INSTRUCTION_LENGTH - 1;
                std::uintptr_t prev_end = 0;
                std::size_t prev_span = 0;
                bool have_prev = false;
                for (const detail::ExecutableWindow &window : windows)
                {
                    detail::ExecutableWindow effective = window;
                    if (have_prev && window.base == prev_end)
                    {
                        const std::size_t carry = (broad_carry < prev_span) ? broad_carry : prev_span;
                        effective.base = window.base - carry;
                        effective.span = window.span + carry;
                    }
                    prev_end = window.base + window.span;
                    prev_span = window.span;
                    have_prev = true;

                    if (scan_window_broad_guarded(decoder, effective, string_addr, window.base, found_count, first_site,
                                                  first_key))
                    {
                        ++faulted_windows;
                        continue;
                    }
                    if (found_count >= 2)
                    {
                        // Ambiguous; caller maps found_count >= 2 to AmbiguousReference.
                        incomplete = faulted_windows > 0;
                        log_faulted_windows(faulted_windows);
                        return 0;
                    }
                }
                // Surface any skipped faulted window (see scan_string_ref_narrow): the caller fails closed on a
                // lower-bound count rather than reporting a lone surviving reference as unique.
                incomplete = faulted_windows > 0;
                log_faulted_windows(faulted_windows);
                if (found_count != 1)
                {
                    return 0;
                }
                out_key = first_key;
                return first_site;
            }

            // Authoritative x64 function-boundary lookup through the exception directory (.pdata). Every function that
            // touches the stack or calls another function must register a RUNTIME_FUNCTION in its module's .pdata, so
            // the OS-maintained function table yields the exact [BeginAddress, EndAddress) bounds. This is strictly
            // better than the byte back-scan below: it is exact rather than heuristic, carries no distance bound (a
            // reference far into a large function still resolves, where the fixed back-scan window would give up), and
            // cannot be fooled by a 0xC3/0xCC byte that is really part of an instruction's immediate or displacement.
            // RtlLookupFunctionEntry resolves instr_addr against whichever loaded module -- or dynamically registered
            // table -- covers it and reports that module's image base plus the innermost RUNTIME_FUNCTION. It returns
            // nullptr for a leaf function (one with no unwind data) or an address in a region with no registered table
            // (a raw code buffer), which is the caller's signal to fall back to the heuristic.
            //
            // A funclet (a catch/finally handler) or a hot/cold-split fragment carries its own RUNTIME_FUNCTION whose
            // UNWIND_INFO sets UNW_FLAG_CHAININFO and chains back to the primary function. The enclosing function is
            // the root of that chain, not the fragment -- retail game builds routinely split cold paths out via PGO, so
            // a string reference on a cold path resolves to a fragment start unless the chain is followed. The chained
            // RUNTIME_FUNCTION sits immediately after the even-count-padded unwind-code array (each code is two bytes),
            // at UnwindData + 4 + 2 * ((CountOfCodes + 1) & ~1). Every module read is fault-guarded: .pdata /
            // .xdata is normally resident, but a partially unmapped or corrupt module must degrade to the fallback
            // rather than fault the host, and the hop count is bounded against a malformed self-referential chain.
            std::uintptr_t function_entry_via_pdata(std::uintptr_t instr_addr) noexcept
            {
                DWORD64 image_base = 0;
                PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(instr_addr, &image_base, nullptr);
                if (entry == nullptr || image_base == 0)
                {
                    return 0;
                }

                // Copy the resolved record under the guard before walking .xdata by hand. RtlLookupFunctionEntry may
                // return a module .pdata record or a dynamically registered table record; both are still process memory
                // that must fail closed on an unexpected fault.
                RUNTIME_FUNCTION current{};
                if (!detail::guarded_read_bytes(reinterpret_cast<std::uintptr_t>(entry), &current, sizeof(current)))
                {
                    return 0;
                }

                constexpr int MAX_CHAIN_HOPS = 16;
                for (int hop = 0; hop < MAX_CHAIN_HOPS; ++hop)
                {
                    // UNWIND_INFO fixed header: byte 0 packs Version:3 | Flags:5 (so Flags = byte0 >> 3) and byte 2 is
                    // CountOfCodes. Only these two fields drive chain traversal, so read the 4-byte header instead of
                    // modelling the whole variable-length structure.
                    std::uint8_t unwind_header[4] = {};
                    const std::uintptr_t unwind_addr = static_cast<std::uintptr_t>(image_base) + current.UnwindData;
                    if (!detail::guarded_read_bytes(unwind_addr, unwind_header, sizeof(unwind_header)))
                    {
                        return 0;
                    }
                    if (((unwind_header[0] >> 3) & UNW_FLAG_CHAININFO) == 0)
                    {
                        return static_cast<std::uintptr_t>(image_base) + current.BeginAddress;
                    }
                    // The chained RUNTIME_FUNCTION follows the unwind-code array, padded up to an even entry count;
                    // UnwindData is that structure's own RVA.
                    const std::uint32_t count_of_codes = unwind_header[2];
                    const std::uint32_t chained_rva = current.UnwindData + 4u + 2u * ((count_of_codes + 1u) & ~1u);
                    RUNTIME_FUNCTION chained{};
                    if (!detail::guarded_read_bytes(static_cast<std::uintptr_t>(image_base) + chained_rva, &chained,
                                                    sizeof(chained)))
                    {
                        return 0;
                    }
                    current = chained;
                }

                return 0;
            }

            // Enclosing-function entry for a referencing instruction. The authoritative .pdata lookup above is tried
            // first; it resolves any function with unwind data exactly. Only a leaf function (no unwind data) or an
            // address in a region with no registered exception table (a raw code buffer) falls through to this bounded
            // heuristic, which walks backward for the nearest function boundary -- a terminal RET (0xC3) or a run of
            // INT3 (0xCC) alignment padding -- and returns the first byte after it that passes
            // is_likely_function_prologue, skipping further INT3 padding. The back-scan is bounded so a pathological
            // region cannot scan unboundedly, and it fails closed (returns 0) when no boundary is found in the window.
            std::uintptr_t enclosing_function_start(std::uintptr_t instr_addr, std::uintptr_t window_lo) noexcept
            {
                if (const std::uintptr_t via_pdata = function_entry_via_pdata(instr_addr); via_pdata != 0)
                {
                    return via_pdata;
                }

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
                //
                // Left deliberately uninitialized: the chunk-read loop fills exactly [valid_lo, instr_addr) via
                // guarded_read_bytes, and both probe loops below read only indices within that filled span (they are
                // bounded by valid_lo / instr_addr), so no unwritten byte is ever observed. Value-initializing the full
                // 8 KiB every call would be dead work on this control-plane path.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init) filled before any read, see above
                std::array<std::uint8_t, static_cast<std::size_t>(back_scan_window)> window;
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

        namespace
        {
            // The whole two-phase resolve. Both entry points below are thin wrappers over it: the public one passes no
            // exclusion set, the internal one carries the ladder resolver's.
            Result<Address> resolve_string_xref(const StringRefQuery &query, Region scope,
                                                const detail::ScanExclusions *provided_exclusions,
                                                std::span<const Region> declared_exclusions)
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
                // Phase 1 is a readable sweep, so it inherits the same authority rule as every other readable scan: a
                // scope wider than one image or allocation also covers the caller's own copy of the literal, and a
                // located address there would be the query finding itself rather than the image's string.
                if (!detail::readable_scan_is_authoritative(range, Pages::Readable, declared_exclusions))
                {
                    return std::unexpected(Error{ErrorCode::NotAuthoritative, "scan::find_string_xref"});
                }

                detail::ScanExclusions direct_exclusions;
                if (provided_exclusions == nullptr)
                {
                    direct_exclusions.restrict_to(range.base, range.end);
                    direct_exclusions.add_text(query.text);
                    provided_exclusions = &direct_exclusions;
                }
                if (provided_exclusions->overflowed())
                {
                    return std::unexpected(Error{ErrorCode::NotAuthoritative, "scan::find_string_xref"});
                }

                // Phase 1: locate the single occurrence of the string in the image's readable pages. The linker pools
                // identical literals, so a second occurrence makes the anchor ambiguous and must fail closed.
                QueryTextStatus text_status = QueryTextStatus::Ok;
                const auto pattern = compile_string_pattern(query, text_status);
                if (!pattern)
                {
                    if (text_status == QueryTextStatus::Malformed)
                    {
                        // The text is not encodable as asked, so no literal to search for was ever defined. Distinct
                        // from "searched and absent" so the caller fixes the query rather than the signature.
                        return std::unexpected(Error{ErrorCode::MalformedQueryText, "scan::find_string_xref"});
                    }
                    return std::unexpected(Error{ErrorCode::StringNotFound, "scan::find_string_xref"});
                }
                // One traversal counts zero, one, or two-or-more occurrences, so the located address and the uniqueness
                // verdict describe the same view of memory; two independent passes could straddle a concurrent write
                // and certify a pairing that never existed. compile_string_pattern emits literal bytes only, so this
                // pattern carries no bounded jumps and a skipped faulted region is its only truncation channel.
                const detail::MatchResult located = detail::scan_module_readable(
                    *pattern, range,
                    detail::ScanQuery{.occurrence = 1, .count_beyond = true, .exclusions = provided_exclusions});
                if (located.match == nullptr)
                {
                    if (located.truncated())
                    {
                        // A truncated sweep never read part of the image, so it cannot report the literal absent.
                        return std::unexpected(Error{ErrorCode::IncompleteScan, "scan::find_string_xref"});
                    }
                    return std::unexpected(Error{ErrorCode::StringNotFound, "scan::find_string_xref"});
                }
                if (located.count > 1)
                {
                    // A second pooled copy was actually observed, so the anchor is genuinely non-unique. That verdict
                    // is authoritative and stays ambiguous even when the sweep was also truncated.
                    return std::unexpected(Error{ErrorCode::StringAmbiguous, "scan::find_string_xref"});
                }
                if (located.truncated())
                {
                    // One copy was seen, but a truncated sweep makes the count a lower bound: a second pooled copy
                    // could hide in bytes that were never read, so uniqueness is unproven. Fail closed on the
                    // truncation itself rather than on an ambiguity verdict, so the reason survives to the caller and
                    // the ladder resolver's typed-failure latch cannot degrade it to NoMatch.
                    return std::unexpected(Error{ErrorCode::IncompleteScan, "scan::find_string_xref"});
                }
                const auto string_addr = reinterpret_cast<std::uintptr_t>(located.match);

                // Phase 2: find the single RIP-relative reference whose target is the string. The narrow scan is the
                // fast, desync-immune default; broad_match keeps that coverage and adds a Zydis sweep for rarer
                // reference shapes.
                //
                // Both sweeps run over ONE enumeration of the execute-readable windows. Enumerating twice would
                // let a concurrent reprotect hide a window from the second sweep only, and a window that is absent is
                // indistinguishable from a window that agreed: the confirmation below would then certify a site it
                // never examined. Sharing the list routes any mid-sweep loss through the faulted-window channel, which
                // does fail closed.
                const std::vector<detail::ExecutableWindow> windows = detail::collect_executable_windows(range);

                ReferenceScanResult references{};
                std::size_t narrow_count = 0;
                LeaReferenceInfo lea_info{};
                bool narrow_incomplete = false;
                const std::uintptr_t narrow_site =
                    scan_string_ref_narrow(string_addr, windows, narrow_count, lea_info, narrow_incomplete);
                // The narrow shape is REX + opcode + ModRM + disp32, so its disp32 field sits exactly three bytes into
                // the instruction and the reference key is derivable from the site alone.
                merge_reference_scan(references, narrow_site, (narrow_site != 0) ? narrow_site + 3 : 0, narrow_count,
                                     narrow_incomplete);

                // The narrow scan only models the dominant REX.W lea/mov shapes, so a narrow count of 1 is a
                // SHAPE-LOCAL uniqueness verdict: a second reference of a rarer shape (cmp [rip+d], imm; push [rip+d];
                // a no-REX lea/mov) elsewhere is invisible to it. For the derived return modes the result is computed
                // FROM that single reference -- the enclosing function it sits in (EnclosingFunction), or the store
                // slot its loaded pointer feeds (StringPointerSlot) -- so a hidden second reference would make that
                // derivation attribute the answer to a site that is not actually unique. Confirm uniqueness with the
                // broad Zydis sweep (a superset of every reference shape) before certifying, even when the caller did
                // not opt into broad_match. ReferencingInstruction returns the dominant reference directly and stays on
                // the fast narrow-only path. The broad sweep re-counts the narrow lea itself, so a genuinely-unique
                // reference stays count 1 at the same site while a rarer-shape twin trips count 2 and fails closed;
                // lea_info is untouched by the sweep, so StringPointerSlot still derives from the narrow lea.
                //
                // Cost note: a genuinely-unique reference keeps the narrow count at 1, so this confirmation
                // disassembles the whole scanned range once per derived-return anchor -- there is no early-out to skip
                // it. A manifest that anchors many EnclosingFunction/StringPointerSlot strings in one module therefore
                // pays one full decode per such anchor at startup. Sharing a disassembly across anchors would require a
                // cross-thread reference index in the parallel resolver, while skipping confirmation based on the
                // narrow count is unsound because the narrow scan cannot see rarer reference shapes. Callers that
                // resolve many string anchors in one image and can key on the referencing instruction should prefer
                // ReferencingInstruction, which stays on the narrow-only path.
                const bool derived_return = query.return_mode != XrefReturn::ReferencingInstruction;
                const bool confirm_derived_uniqueness = derived_return && references.count == 1;
                if (references.count < 2 && (query.broad_match || confirm_derived_uniqueness))
                {
                    std::size_t broad_count = 0;
                    std::uintptr_t broad_key = 0;
                    bool broad_incomplete = false;
                    const std::uintptr_t broad_site =
                        scan_string_ref_broad(string_addr, windows, broad_count, broad_key, broad_incomplete);
                    merge_reference_scan(references, broad_site, broad_key, broad_count, broad_incomplete);
                }

                if (references.count >= 2)
                {
                    return std::unexpected(Error{ErrorCode::AmbiguousReference, "scan::find_string_xref"});
                }
                if (references.incomplete)
                {
                    // An execute-readable window faulted mid-sweep and was skipped, so the reference count is a lower
                    // bound: a second reference to the string could hide in the skipped window. A lone surviving
                    // reference (or none) is therefore not provably unique. Fail closed on the truncation itself, the
                    // phase-2 twin of the phase-1 gate above; the count-driven AmbiguousReference just above stays the
                    // authoritative multiplicity verdict. Only the faulted-window channel reaches here, because
                    // merge_reference_scan carries no work budget.
                    return std::unexpected(Error{ErrorCode::IncompleteScan, "scan::find_string_xref"});
                }
                if (references.count == 0)
                {
                    return std::unexpected(Error{ErrorCode::NoReference, "scan::find_string_xref"});
                }

                if (query.return_mode == XrefReturn::StringPointerSlot)
                {
                    // Store-xref needs the unique reference to be the narrow `lea reg, [rip+string]` whose loaded
                    // pointer a following `mov [rip+slot], reg` caches. A broad-only surviving reference never
                    // populates lea_info, and a `mov reg, [rip+string]` load has no store to attribute, so is_lea is
                    // the whole test: it is set only by the narrow sweep, and only for the site it returned.
                    if (!lea_info.is_lea)
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

        } // namespace

        Result<Address> find_string_xref(const StringRefQuery &query, Region scope)
        {
            return resolve_string_xref(query, scope, nullptr, {});
        }
    } // namespace scan

    Result<Address> detail::find_string_xref_with_exclusions(const scan::StringRefQuery &query,
                                                             Region scope, const ScanExclusions *exclusions,
                                                             std::span<const Region> declared_exclusions)
    {
        return scan::resolve_string_xref(query, scope, exclusions, declared_exclusions);
    }
} // namespace DetourModKit
