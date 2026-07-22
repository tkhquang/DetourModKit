/**
 * @file internal/scan_prologue_recovery.cpp
 * @brief Hooked-prologue recovery: rebuild a Direct candidate's prologue as a recognised inline-hook jump shape and
 *        recover the single redirected site.
 * @details Acts only on Direct candidates, dispatched through Candidate::as_direct(). Each rebuilt prologue runs
 *          through the shared constexpr DSL core so the jump-prefix encoding has one source of truth, scans over the
 *          image's executable pages, and gates the decoded jump destination as a plausible, executable address before
 *          acceptance.
 */

#include "internal/scan_prologue_recovery.hpp"

#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_shared.hpp"

#include "DetourModKit/detail/pattern_core.hpp"

#include "x86_decode.hpp"

#include <Zydis/Zydis.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace DetourModKit
{
    namespace
    {
        // One inline-hook prologue shape the fallback can rebuild and recover. patch_minimum is the jump's own length
        // -- the minimum the hook overwrites, which the rebuild rounds up to a whole instruction. jump_prefix is the
        // AOB fragment that replaces them; decode recovers the absolute target the rebuilt jump redirects to, so a
        // match can be confirmed as a real hook rather than a coincidental opcode collision.
        struct PrologueShape
        {
            std::size_t patch_minimum;
            std::string_view jump_prefix;
            std::optional<std::uintptr_t> (*decode)(std::uintptr_t) noexcept;
        };

        // Minimum fully-known tail bytes a rebuilt pattern must keep after the jump prefix. Ten literal bytes is
        // roughly two to four real instructions of context, which drops the false-positive rate of the generic near-JMP
        // shape to near zero on a multi-megabyte .text section.
        constexpr std::size_t PROLOGUE_MIN_TAIL_LITERALS = 10;

        // Inline-hook prologue shapes the fallback tries, in order. E9 is the five-byte near jump for a trampoline
        // within rel32 reach; the rest are the far-jump shapes emitted when the trampoline is beyond rel32 reach (an
        // FF 25 RIP-relative indirect jump through a pointer slot, the fourteen-byte FF 25 absolute form whose disp32
        // is zero so the 8-byte target is inlined after the instruction, and the twelve-byte `mov rax, imm64; jmp
        // rax`). The opcode groups differ and the two FF 25 forms differ only by overwrite length, so the shapes are
        // mutually exclusive at a real hook site and the try order only affects which is attempted first, never
        // correctness; E9 leads because it is by far the common case.
        constexpr std::array<PrologueShape, 4> PROLOGUE_SHAPES = {{
            {5, std::string_view{"E9 ?? ?? ?? ??"}, &detail::decode_e9_rel32},
            {6, std::string_view{"FF 25 ?? ?? ?? ??"}, &detail::decode_ff25_indirect},
            {14, std::string_view{"FF 25 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??"}, &detail::decode_ff25_indirect},
            {12, std::string_view{"48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0"}, &detail::decode_mov_rax_imm64_jmp_rax},
        }};

        // Rebuild a Direct candidate's signature as one prologue shape: drop the instruction-rounded stolen span (the
        // jump patch minimum rounded up to a whole instruction), prepend the shape's jump prefix, fill any rounded
        // excess with don't-care bytes, and keep the surviving tail token-exact. The jump prefix is parsed through the
        // shared constexpr DSL core so the prefix encoding has one source of truth. Returns nullopt when the pattern is
        // shorter than the patch, its leading span is undecodable, or its literal tail is below the floor (the shape is
        // "not applicable" then). The rebuilt pattern carries offset 0: replacing the prologue dropped the original `|`
        // anchor, which the caller re-applies after the scan so a `|`-anchored candidate recovered here lands on the
        // same byte the direct scan would have.
        std::optional<detail::EnginePattern> build_rebuilt_prologue(const scan::Pattern &original,
                                                                    const PrologueShape &shape)
        {
            // A bounded-jump pattern cannot be rebuilt by a flat byte-and-mask concatenation: this rebuild drops the
            // instruction-rounded stolen span and prepends the jump prefix, but it copies only bytes/mask and never
            // carries the original's `jumps` across (nor rebases their positions past the shifted prologue, nor
            // re-splits a gap that straddled the patched bytes). Carrying no jumps would collapse every variable gap
            // into a fixed run, so the rebuilt pattern would match a wrong, gap-collapsed shape. Fail closed on any
            // jump-bearing pattern instead: the jump-bearing tail still resolves through the normal (non-fallback)
            // scan path, so this only forgoes prologue RECOVERY for such a signature, never a correct direct match.
            if (original.has_jumps())
            {
                return std::nullopt;
            }
            const std::size_t size = original.size();
            if (size < shape.patch_minimum)
            {
                return std::nullopt;
            }
            const std::span<const std::byte> original_bytes = original.bytes();
            const std::span<const std::byte> original_mask = original.mask();

            // Round the stolen span up to a whole-instruction boundary. A jump patch overwrites shape.patch_minimum
            // bytes, but if that splits an instruction the installer must steal the whole straddling instruction, so
            // the true stolen span is the first instruction boundary at or past the patch minimum. Decode the original
            // leading instructions until the cumulative length reaches it. Every byte handed to the decoder must be
            // fully known: a wildcard within a required leading instruction makes the span untrustworthy.
            ZydisDecoder decoder;
            if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
            {
                return std::nullopt;
            }
            std::size_t stolen_span = 0;
            while (stolen_span < shape.patch_minimum)
            {
                std::size_t literal_run = 0;
                while (stolen_span + literal_run < size && literal_run < ZYDIS_MAX_INSTRUCTION_LENGTH &&
                       original_mask[stolen_span + literal_run] == std::byte{0xFF})
                {
                    ++literal_run;
                }
                if (literal_run == 0)
                {
                    return std::nullopt;
                }
                std::uint8_t window[ZYDIS_MAX_INSTRUCTION_LENGTH];
                for (std::size_t i = 0; i < literal_run; ++i)
                {
                    window[i] = std::to_integer<std::uint8_t>(original_bytes[stolen_span + i]);
                }
                ZydisDecodedInstruction instruction;
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, window, literal_run, &instruction)))
                {
                    // The bytes do not decode as a whole instruction within the known-literal run (a wildcard truncates
                    // it, or the bytes are not valid code): undecodable, so not applicable.
                    return std::nullopt;
                }
                stolen_span += instruction.length;
            }

            // The excess beyond the jump patch minimum -- what an installer NOP-pads or leaves as the straddled
            // instruction's orphaned tail -- is matched don't-care, so recovery succeeds whether that gap is
            // zero-filled, NOP-padded, or left as the original bytes. Only the surviving literal tail past the stolen
            // span must match exactly, and enough of it must remain to keep the generic jump shape selective.
            const std::size_t padding_bytes = stolen_span - shape.patch_minimum;
            std::size_t literal_tail = 0;
            for (std::size_t i = stolen_span; i < size; ++i)
            {
                if (original_mask[i] == std::byte{0xFF})
                {
                    ++literal_tail;
                }
            }
            if (literal_tail < PROLOGUE_MIN_TAIL_LITERALS)
            {
                return std::nullopt;
            }
            const detail::PatternParse prefix = detail::parse_pattern(shape.jump_prefix);
            if (prefix.status != detail::PatternStatus::Ok)
            {
                // The shape prefixes are constant and well-formed; a parse failure would be a library defect, not user
                // input, so fail this shape closed rather than scan a malformed pattern.
                return std::nullopt;
            }
            detail::EnginePattern rebuilt;
            rebuilt.bytes.reserve(prefix.buffer.length + padding_bytes + (size - stolen_span));
            rebuilt.mask.reserve(prefix.buffer.length + padding_bytes + (size - stolen_span));
            for (std::size_t i = 0; i < prefix.buffer.length; ++i)
            {
                rebuilt.bytes.push_back(prefix.buffer.bytes[i]);
                rebuilt.mask.push_back(prefix.buffer.mask[i]);
            }
            for (std::size_t i = 0; i < padding_bytes; ++i)
            {
                rebuilt.bytes.push_back(std::byte{0});
                rebuilt.mask.push_back(std::byte{0});
            }
            for (std::size_t i = stolen_span; i < size; ++i)
            {
                rebuilt.bytes.push_back(original_bytes[i]);
                rebuilt.mask.push_back(original_mask[i]);
            }
            rebuilt.offset = 0;
            rebuilt.compile_anchor();
            return rebuilt;
        }

        // Try one prologue shape for one Direct candidate: rebuild, require the rebuilt pattern to match exactly once
        // in the scope's executable pages (a hooked prologue is code), decode the jump to confirm a real redirect, and
        // resolve the anchored match. applicable becomes true once the rebuilt pattern is usable (enough literal tail),
        // independent of whether it then matches, so the caller can tell "no shape applied" from "applied but missed".
        std::optional<std::uintptr_t> try_prologue_shape(const scan::DirectPattern &direct, const PrologueShape &shape,
                                                         detail::ModuleSpan range, bool &applicable,
                                                         detail::FallbackOutcome &outcome)
        {
            const scan::Pattern &pattern = direct.pattern;
            const std::optional<detail::EnginePattern> rebuilt = build_rebuilt_prologue(pattern, shape);
            if (!rebuilt)
            {
                return std::nullopt;
            }
            applicable = true;

            // Count zero, one, or two-or-more occurrences over the executable pages in ONE traversal, so the hit and
            // the ambiguity verdict describe the same view of memory. A truncated sweep (a faulted region skipped, or
            // bounded-jump backtracking spent) makes the count a lower bound, so a single hit does not prove
            // uniqueness; fail closed. More than one hit makes the rebuilt jump ambiguous; fail closed.
            const detail::MatchResult found = detail::scan_module_executable(
                *rebuilt, range, detail::ScanQuery{.occurrence = 1, .count_beyond = true, .exclusions = nullptr});
            // Truncation is recorded even when this shape would have been rejected anyway: it says the executable
            // pages were not fully read, so the caller must not report the whole recovery pass as a proven absence.
            // build_rebuilt_prologue refuses jump-bearing patterns, so a skipped faulted region is the only channel.
            outcome.incomplete = outcome.incomplete || found.truncated();
            if (found.count > 1)
            {
                // The rebuilt shape collides at two or more executable sites (a count that a truncated sweep only
                // raises), so no single redirect can be trusted. Record the ambiguity so the resolver reports it
                // distinctly from a plain miss, and still fail closed.
                outcome.ambiguous = true;
                return std::nullopt;
            }
            if (found.match == nullptr || found.truncated())
            {
                return std::nullopt;
            }

            const std::uintptr_t match = reinterpret_cast<std::uintptr_t>(found.match);
            const std::optional<std::uintptr_t> jump_target = shape.decode(match);
            if (!jump_target || !detail::is_plausible_ptr(*jump_target) || !detail::is_executable_address(*jump_target))
            {
                // The matched bytes do not redirect to executable code, so this is a coincidental opcode collision, not
                // a hooked prologue. The jump destination itself is intentionally NOT range-constrained: a sibling
                // mod's trampoline is allocated outside every loaded module.
                return std::nullopt;
            }

            const std::uintptr_t anchored = match + static_cast<std::uintptr_t>(pattern.offset());
            const std::optional<std::uintptr_t> resolved = detail::resolve_direct(anchored, direct);
            if (!resolved || !range.contains(*resolved))
            {
                // Bound the recovered address to the requested scope, matching the normal byte path: a Direct walk-back
                // must not resolve outside the range even when it is reached through prologue recovery.
                return std::nullopt;
            }
            return resolved;
        }
    } // anonymous namespace

    detail::FallbackOutcome detail::resolve_prologue_fallback(const scan::ScanRequest &request,
                                                              std::span<const std::size_t> order, ModuleSpan range)
    {
        FallbackOutcome outcome;
        const scan::FallbackPolicy policy = request.fallback_policy;
        const scan::FallbackWitness witness = request.fallback_witness;
        for (const std::size_t index : order)
        {
            const scan::Candidate &candidate = request.ladder[index];
            const scan::DirectPattern *direct = candidate.as_direct();
            if (direct == nullptr)
            {
                continue;
            }
            outcome.had_direct = true;
            for (const PrologueShape &shape : PROLOGUE_SHAPES)
            {
                bool applicable = false;
                const std::optional<std::uintptr_t> recovered =
                    try_prologue_shape(*direct, shape, range, applicable, outcome);
                if (applicable)
                {
                    outcome.not_applicable = false;
                }
                if (!recovered)
                {
                    continue;
                }

                // Structural recovery succeeded (unique rebuilt match, decoded redirect into executable memory,
                // in-scope walk-back). Apply the caller's identity gate before trusting the address: the structural
                // gate is address-blind, so a reshaped near-twin whose surviving tail matches and which is itself
                // hooked would resolve here uniformly. The witness is the only thing that can tell the intended
                // function from a coincidental twin.
                const std::int64_t recovered_value = static_cast<std::int64_t>(*recovered);
                if (policy == scan::FallbackPolicy::RequireIdentity)
                {
                    // Fail closed on an unconfirmed site: a missing witness cannot confirm identity, and a witness that
                    // rejects the site marks it a twin. Record the rejection so the resolver reports it distinctly, and
                    // keep trying other shapes / candidates for one that does pass identity rather than stopping here.
                    if (witness.predicate == nullptr || !witness.predicate(recovered_value, witness.context))
                    {
                        outcome.identity_rejected = true;
                        continue;
                    }
                }
                else if (witness.predicate != nullptr && !witness.predicate(recovered_value, witness.context))
                {
                    // WarnOnly: a supplied witness that disagrees does not veto the recovery, but it is surfaced so the
                    // resolver logs the disagreement. A consumer can observe near-twin drift in this mode before
                    // switching to RequireIdentity and failing closed on it.
                    outcome.identity_warned = true;
                }

                outcome.hit = scan::Hit{Address{*recovered}, candidate.name()};
                return outcome;
            }
        }
        return outcome;
    }
} // namespace DetourModKit
