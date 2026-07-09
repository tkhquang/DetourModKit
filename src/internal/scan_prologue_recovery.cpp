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
        // One inline-hook prologue shape the fallback can rebuild and recover. patch_bytes is how many leading prologue
        // bytes the hook overwrites; jump_prefix is the AOB fragment that replaces them; decode recovers the absolute
        // target the rebuilt jump redirects to, so a match can be confirmed as a real hook rather than a coincidental
        // opcode collision.
        struct PrologueShape
        {
            std::size_t patch_bytes;
            std::string_view jump_prefix;
            std::optional<std::uintptr_t> (*decode)(std::uintptr_t) noexcept;
        };

        // Minimum fully-known tail bytes a rebuilt pattern must keep after the jump prefix. Ten literal bytes is
        // roughly two to four real instructions of context, which drops the false-positive rate of the generic near-JMP
        // shape to near zero on a multi-megabyte .text section.
        constexpr int PROLOGUE_MIN_TAIL_LITERALS = 10;

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

        // Rebuild a Direct candidate's signature as one prologue shape: drop the patch_bytes leading prologue tokens,
        // prepend the shape's jump prefix, and keep the surviving tail token-exact. The jump prefix is parsed through
        // the shared constexpr DSL core so the prefix encoding has one source of truth. Returns nullopt when the
        // pattern is shorter than the patch or its literal tail is below the floor (the shape is "not applicable"
        // then). The rebuilt pattern carries offset 0: replacing the prologue dropped the original `|` anchor, which
        // the caller re-applies after the scan so a `|`-anchored candidate recovered here lands on the same byte the
        // direct scan would have.
        std::optional<detail::EnginePattern> build_rebuilt_prologue(const scan::Pattern &original,
                                                                    const PrologueShape &shape)
        {
            // A bounded-jump pattern cannot be rebuilt by a flat byte-and-mask concatenation: this rebuild drops the
            // leading patch_bytes and prepends the jump prefix, but it copies only bytes/mask and never carries the
            // original's `jumps` across (nor rebases their positions past the shifted prologue, nor re-splits a gap
            // that straddled the patched bytes). Carrying no jumps would collapse every variable gap into a fixed run,
            // so the rebuilt pattern would match a wrong, gap-collapsed shape. Fail closed on any jump-bearing pattern
            // instead: the jump-bearing tail still resolves through the normal (non-fallback) scan path, so this only
            // forgoes prologue RECOVERY for such a signature, never a correct direct match. Rebuilding the gaps is
            // deferred until a real consumer needs hooked-prologue recovery of a bounded-jump signature.
            if (original.has_jumps())
            {
                return std::nullopt;
            }
            const std::size_t size = original.size();
            if (size < shape.patch_bytes)
            {
                return std::nullopt;
            }
            const std::span<const std::byte> original_bytes = original.bytes();
            const std::span<const std::byte> original_mask = original.mask();
            int literal_tail = 0;
            for (std::size_t i = shape.patch_bytes; i < size; ++i)
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
            rebuilt.bytes.reserve(prefix.buffer.length + (size - shape.patch_bytes));
            rebuilt.mask.reserve(prefix.buffer.length + (size - shape.patch_bytes));
            for (std::size_t i = 0; i < prefix.buffer.length; ++i)
            {
                rebuilt.bytes.push_back(prefix.buffer.bytes[i]);
                rebuilt.mask.push_back(prefix.buffer.mask[i]);
            }
            for (std::size_t i = shape.patch_bytes; i < size; ++i)
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
                                                         detail::ModuleSpan range, bool &applicable)
        {
            const scan::Pattern &pattern = direct.pattern;
            const std::optional<detail::EnginePattern> rebuilt = build_rebuilt_prologue(pattern, shape);
            if (!rebuilt)
            {
                return std::nullopt;
            }
            applicable = true;

            // Count up to two occurrences over the executable pages. A faulted region mid-scan makes the count a lower
            // bound, so a single hit over an incomplete sweep does not prove uniqueness; fail closed. More than one hit
            // makes the rebuilt jump ambiguous; fail closed.
            const detail::MatchResult first = detail::scan_module_executable(*rebuilt, range, 1);
            if (first.match == nullptr)
            {
                return std::nullopt;
            }
            const detail::MatchResult second = detail::scan_module_executable(*rebuilt, range, 2);
            const bool ambiguous = second.match != nullptr;
            const bool incomplete = first.incomplete || second.incomplete;
            if (ambiguous || incomplete)
            {
                return std::nullopt;
            }

            const std::uintptr_t match = reinterpret_cast<std::uintptr_t>(first.match);
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
                const std::optional<std::uintptr_t> recovered = try_prologue_shape(*direct, shape, range, applicable);
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
