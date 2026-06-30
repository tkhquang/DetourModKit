/**
 * @file internal/scan_prologue_recovery.cpp
 * @brief Hooked-prologue recovery: rebuild a Direct candidate's prologue as a recognised inline-hook jump shape and
 *        recover the single redirected site.
 * @details The relocated prologue-recovery control flow of the former scan.cpp anonymous namespace, adapted to the
 *          variant Candidate (it acts only on Direct candidates, dispatched through Candidate::as_direct()). Rebuilds
 *          run through the shared constexpr DSL core so the jump-prefix encoding has one source of truth, scan over the
 *          image's executable pages, and gate the decoded jump destination as a plausible, executable address before
 *          acceptance.
 */

#include "internal/scan_prologue_recovery.hpp"

#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_shared.hpp"

#include "DetourModKit/detail/pattern_core.hpp"
#include "DetourModKit/memory.hpp"

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
        // rax`). The literal opcode bytes make the shapes mutually exclusive at a real hook site, so the try order only
        // affects which is attempted first, never correctness; E9 leads because it is by far the common case.
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
                                                         Memory::ModuleRange range, bool &applicable)
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
            if (!jump_target || !Memory::plausible_userspace_ptr(*jump_target) ||
                !detail::is_executable_address(*jump_target))
            {
                // The matched bytes do not redirect to executable code, so this is a coincidental opcode collision, not
                // a hooked prologue. The jump destination itself is intentionally NOT range-constrained: a sibling
                // mod's trampoline is allocated outside every loaded module.
                return std::nullopt;
            }

            const std::uintptr_t anchored = match + static_cast<std::uintptr_t>(pattern.offset());
            const std::optional<std::uintptr_t> resolved = detail::resolve_direct(anchored, direct);
            if (!resolved || !Memory::contains(range, *resolved))
            {
                // Bound the recovered address to the requested scope, matching the normal byte path: a Direct walk-back
                // must not resolve outside the range even when it is reached through prologue recovery.
                return std::nullopt;
            }
            return resolved;
        }
    } // anonymous namespace

    detail::FallbackOutcome detail::resolve_prologue_fallback(const scan::ScanRequest &request,
                                                              std::span<const std::size_t> order,
                                                              Memory::ModuleRange range)
    {
        FallbackOutcome outcome;
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
                if (recovered)
                {
                    outcome.hit = scan::Hit{Address{*recovered}, candidate.name()};
                    return outcome;
                }
            }
        }
        return outcome;
    }
} // namespace DetourModKit
