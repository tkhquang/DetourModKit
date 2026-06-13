/**
 * @file scanner_cascade.cpp
 * @brief Multi-candidate cascade resolver with hooked-prologue recovery.
 *
 * The higher-level resolution layer over the scan primitives in scanner.cpp:
 * it tries an ordered list of AOB candidates (whole-process, module-scoped, or host-EXE-scoped), enforces per-candidate
 * uniqueness, and -- when every direct candidate misses -- rebuilds each Direct candidate's prologue as a near-JMP and
 * retries to recover a target another mod already inline-hooked. Kept in its own translation unit so the cascade logic
 * and the SIMD scan engine evolve independently; both share one public header (scanner.hpp) plus the internal
 * module-scoped scan entry points in scanner_internal.hpp.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/format.hpp"
#include "x86_decode.hpp"

#include "scanner_internal.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace
    {
        std::optional<std::uintptr_t>
        resolve_candidate_match(std::uintptr_t match_addr,
                                const DetourModKit::Scanner::AddrCandidate &candidate) noexcept
        {
            using DetourModKit::Scanner::ResolveMode;
            if (candidate.mode == ResolveMode::Direct)
            {
                const auto resolved = match_addr + static_cast<std::uintptr_t>(candidate.disp_offset);
                // Apply the same plausibility floor the RipRelative path uses below. A Direct result is normally a real
                // in-process address, but a pathological disp_offset (a large negative value that underflows the match
                // address, or a crafted candidate table) can resolve to 0, a low guard-page address, or a kernel-range
                // / non-canonical value. Reject it here rather than commit to a hit the caller cannot later reverse;
                // the module-scoped path layers a stricter contains() check on top.
                if (!DetourModKit::Memory::plausible_userspace_ptr(resolved))
                {
                    return std::nullopt;
                }
                return resolved;
            }
            const auto disp_addr = match_addr + static_cast<std::uintptr_t>(candidate.disp_offset);
            // Fault-guarded read instead of is_readable + raw memcpy: the page can change between the check and the
            // copy (TOCTOU), so an unguarded memcpy could fault the host process. seh_read returns nullopt on any
            // fault.
            const auto disp = DetourModKit::Memory::seh_read<std::int32_t>(disp_addr);
            if (!disp)
            {
                // A faulted displacement read is a miss, not a hit at address 0: the whole-process path has no in-range
                // guard to reject a zero result, so returning nullopt here prevents a false ResolveHit at 0.
                return std::nullopt;
            }
            const auto resolved = static_cast<std::uintptr_t>(
                static_cast<std::int64_t>(match_addr + static_cast<std::uintptr_t>(candidate.instr_end_offset)) +
                *disp);
            // Mirror resolve_rip_relative's plausibility floor. A corrupt or crafted displacement can resolve to 0, a
            // low guard-page address, or a kernel-range value; the whole-process cascade path has no image to bound the
            // result (the module-scoped path layers a stricter contains() check on top), so reject an implausible
            // target here rather than commit to a hit the caller cannot later reverse.
            if (!DetourModKit::Memory::plausible_userspace_ptr(resolved))
            {
                return std::nullopt;
            }
            return resolved;
        }

        // Minimum number of literal (non-wildcard) bytes the tail of the pattern must contain after dropping the first
        // 5 prologue tokens. Five literal bytes still leave the rebuilt pattern shaped like a generic near-JMP plus a
        // short common-instruction tail, which collides with thousands of unrelated E9 sites in a multi-megabyte .text
        // section. Ten literal bytes is roughly two to four real instructions of context and reduces the false-positive
        // rate to near zero on real binaries while staying inside the 12 to 20 byte sweet spot documented for fallback
        // signatures.
        constexpr int PROLOGUE_FALLBACK_MIN_TAIL_LITERALS = 10;

        // Upper bound on hits the rebuilt fallback pattern may produce within the scanned scope (the module image when
        // a range is supplied, the process's executable regions otherwise) before we reject it as ambiguous. The
        // fallback only exists to recover the single site where a sibling mod inline-hooked the target function, so the
        // legitimate rewritten pattern must match exactly once: the unique JMP into that mod's trampoline. Any value
        // above 1 admits a false positive whose blast radius (a hook installed at an unrelated function) far outweighs
        // the benefit of tolerating duplicate matches.
        constexpr std::size_t PROLOGUE_FALLBACK_MAX_HITS = 1;

        // Bytes each recognised inline-hook prologue shape overwrites. E9 rel32 is five bytes (one opcode plus one
        // int32 displacement); FF 25 disp32 is six (a two-byte opcode plus one int32 RIP-relative displacement). The
        // 14-byte FF 25 absolute form is the same two-byte opcode and a disp32 of zero, followed by the 8-byte absolute
        // target inlined immediately after the instruction (RIP then points at it). The `mov rax, imm64; jmp rax`
        // absolute jump is twelve bytes: REX.W B8 plus an 8-byte immediate, then the two-byte FF E0.
        constexpr std::size_t PROLOGUE_PATCH_BYTES_E9 = 5;
        constexpr std::size_t PROLOGUE_PATCH_BYTES_FF25 = 6;
        constexpr std::size_t PROLOGUE_PATCH_BYTES_FF25_ABS64 = 14;
        constexpr std::size_t PROLOGUE_PATCH_BYTES_MOV_RAX_JMP = 12;

        /**
         * @struct PrologueShape
         * @brief One inline-hook prologue shape the fallback can rebuild and recover.
         * @details @ref patch_bytes is how many leading prologue bytes the hook overwrites; @ref jump_prefix is the AOB
         *          fragment that replaces them; @ref decode recovers the absolute target the jump redirects to so the
         *          rebuilt match can be gated as a real hook rather than a coincidental opcode collision.
         */
        struct PrologueShape
        {
            std::size_t patch_bytes = 0;
            std::string_view jump_prefix;
            std::optional<std::uintptr_t> (*decode)(std::uintptr_t) noexcept = nullptr;
        };

        // Inline-hook prologue shapes the fallback tries, in order. E9 is the five-byte near jump SafetyHook / MinHook
        // emit for a trampoline within rel32 reach; the rest are the far-jump shapes a hook emits when the trampoline
        // is beyond rel32 reach:
        //   - FF 25 disp32: a six-byte RIP-relative indirect jump whose disp32 points at a separate pointer slot
        //     (a Detours-style far jump) -- decode_ff25_indirect dereferences that slot.
        //   - FF 25 00000000 <abs64>: the fourteen-byte absolute form, a disp32 of zero so the slot is the 8-byte
        //     absolute target inlined right after the instruction. It reuses decode_ff25_indirect, which already
        //     resolves the disp32==0 slot at address+6. A six-byte FF 25 shape cannot recover it: a 14-byte overwrite
        //     leaves a different surviving tail, so the two shapes are disjoint and never alias.
        //   - 48 B8 <imm64> FF E0: the twelve-byte `mov rax, imm64; jmp rax` absolute jump some libraries emit instead
        //     of the FF 25 form -- decode_mov_rax_imm64_jmp_rax returns the inlined imm64 directly (no slot read).
        // Each shape rebuilds a distinct pattern from the original signature (its own patch_bytes leading drop plus its
        // jump_prefix), and the prefixes' literal opcode bytes (E9 vs FF 25 vs 48 B8) make the shapes mutually
        // exclusive at a real hook site, so the try order only affects which is attempted first, never correctness. E9
        // is first because it is by far the common case; the FF 25 variants precede the rarer mov rax form.
        constexpr std::array<PrologueShape, 4> PROLOGUE_SHAPES = {{
            {PROLOGUE_PATCH_BYTES_E9, std::string_view{"E9 ?? ?? ?? ??"}, &DetourModKit::detail::decode_e9_rel32},
            {PROLOGUE_PATCH_BYTES_FF25, std::string_view{"FF 25 ?? ?? ?? ??"},
             &DetourModKit::detail::decode_ff25_indirect},
            {PROLOGUE_PATCH_BYTES_FF25_ABS64, std::string_view{"FF 25 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??"},
             &DetourModKit::detail::decode_ff25_indirect},
            {PROLOGUE_PATCH_BYTES_MOV_RAX_JMP, std::string_view{"48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0"},
             &DetourModKit::detail::decode_mov_rax_imm64_jmp_rax},
        }};

        void append_hex_byte(std::string &out, std::byte value)
        {
            constexpr char digits[] = "0123456789ABCDEF";
            const auto byte_value = std::to_integer<unsigned>(value);
            out.push_back(digits[(byte_value >> 4) & 0xF]);
            out.push_back(digits[byte_value & 0xF]);
        }

        // Re-emits one parsed (byte, mask) pair as the AOB token parse_aob would accept: a full literal (mask 0xFF), a
        // per-nibble token (mask 0xF0 / 0x0F), or a full wildcard (mask 0x00). Keeping the round-trip token-exact
        // preserves a partially-masked tail byte instead of widening it to a full byte (which would over-constrain) or
        // to a wildcard.
        void append_pattern_token(std::string &out, std::byte value, std::byte mask)
        {
            constexpr char digits[] = "0123456789ABCDEF";
            const auto byte_value = std::to_integer<unsigned>(value);
            switch (std::to_integer<unsigned>(mask))
            {
            case 0xFF:
                append_hex_byte(out, value);
                break;
            case 0xF0:
                out.push_back(digits[(byte_value >> 4) & 0xF]);
                out.push_back('?');
                break;
            case 0x0F:
                out.push_back('?');
                out.push_back(digits[byte_value & 0xF]);
                break;
            default:
                out.append("??");
                break;
            }
        }

        // Build from the parsed pattern so parse_aob remains the only token parser. The caller keeps original.offset
        // and applies it after the fallback scan, which makes `|`-anchored recovery match the direct path exactly.
        // patch_bytes leading prologue bytes are replaced by jump_prefix; the surviving literal tail is re-emitted
        // token-exact. Only fully-known tail bytes count toward the literal-tail floor: a partially-masked nibble byte
        // adds context but not a full byte of false-positive defense, so the conservative count keeps the uniqueness
        // pre-filter strict.
        std::string build_hooked_prologue_pattern(const DetourModKit::Scanner::CompiledPattern &original,
                                                  std::size_t patch_bytes, std::string_view jump_prefix)
        {
            if (original.size() < patch_bytes)
            {
                return {};
            }
            int literal_tail_count = 0;
            for (std::size_t i = patch_bytes; i < original.size(); ++i)
            {
                if (original.mask[i] == std::byte{0xFF})
                {
                    ++literal_tail_count;
                }
            }
            if (literal_tail_count < PROLOGUE_FALLBACK_MIN_TAIL_LITERALS)
            {
                return {};
            }
            std::string out(jump_prefix);
            for (std::size_t i = patch_bytes; i < original.size(); ++i)
            {
                out.push_back(' ');
                append_pattern_token(out, original.bytes[i], original.mask[i]);
            }
            return out;
        }

        // Counts up to (max_hits + 1) occurrences of `pattern`. When `range` is set the count is confined to that
        // module image; otherwise it spans the whole process's executable regions. Returning max_hits+1 signals "too
        // many to be unique". The count must use the same scope as the eventual match scan, or a pattern unique inside
        // the target module but duplicated in a sibling overlay would be wrongly rejected (or accepted) on the wrong
        // evidence. When first_match_out is non-null it receives the first occurrence (the n == 1 scan result, or
        // nullptr when there were no hits) so a caller that needs both the count and the first match -- the same scan,
        // same scope -- does not have to sweep again to fetch it.
        std::size_t count_pattern_hits_bounded(const DetourModKit::Scanner::CompiledPattern &pattern,
                                               std::size_t max_hits,
                                               std::optional<DetourModKit::Memory::ModuleRange> range,
                                               const std::byte **first_match_out = nullptr) noexcept
        {
            if (first_match_out != nullptr)
            {
                *first_match_out = nullptr;
            }
            std::size_t hits = 0;
            for (std::size_t n = 1; n <= max_hits + 1; ++n)
            {
                const auto *match = range ? Scanner::detail::scan_module_executable(pattern, *range, n)
                                          : DetourModKit::Scanner::scan_executable_regions(pattern, n);
                if (match == nullptr)
                {
                    break;
                }
                if (n == 1 && first_match_out != nullptr)
                {
                    *first_match_out = match;
                }
                ++hits;
            }
            return hits;
        }

        struct CascadeAttempt
        {
            std::uintptr_t address{0};
            std::size_t index{0};
            bool success{false};
        };

        CascadeAttempt scan_candidates(std::span<const DetourModKit::Scanner::AddrCandidate> candidates,
                                       bool &all_parse_failed, DetourModKit::Scanner::ScannerKind kind,
                                       std::optional<DetourModKit::Memory::ModuleRange> range = std::nullopt)
        {
            DetourModKit::Logger &logger = DetourModKit::Logger::get_instance();
            all_parse_failed = true;
            for (std::size_t i = 0; i < candidates.size(); ++i)
            {
                const auto &candidate = candidates[i];
                auto compiled = DetourModKit::Scanner::parse_aob(candidate.pattern);
                if (!compiled)
                {
                    logger.warning("Scanner: Failed to parse AOB for candidate '{}'.",
                                   candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name);
                    continue;
                }
                all_parse_failed = false;

                // Resolves the Nth occurrence in the active scope. A supplied module range takes precedence over
                // `kind`: one scan of the contiguous image already covers both .text and .rdata / .data candidates, so
                // the executable-vs-readable split is moot inside it.
                const auto scan_for = [&](std::size_t occurrence) -> const std::byte *
                {
                    if (range)
                    {
                        return Scanner::detail::scan_module_readable(*compiled, *range, occurrence);
                    }
                    return (kind == DetourModKit::Scanner::ScannerKind::Readable)
                               ? DetourModKit::Scanner::scan_readable_regions(*compiled, occurrence)
                               : DetourModKit::Scanner::scan_executable_regions(*compiled, occurrence);
                };

                const auto *match = scan_for(1);
                if (match == nullptr)
                {
                    continue;
                }

                // Per-candidate uniqueness guard. A candidate flagged require_unique must match exactly once in the
                // scanned scope; a second occurrence means the pattern is ambiguous, so the first (lowest-address)
                // match is not provably the intended target. Skip it so the cascade falls through to the next candidate
                // instead of committing to an arbitrary hit -- the choice between equally-matching sites is semantic
                // and the scanner cannot make it. The extra occurrence scan only runs for a candidate that already
                // matched and has require_unique set (the default); set require_unique = false to accept the first
                // match and skip it.
                if (candidate.require_unique && scan_for(2) != nullptr)
                {
                    logger.debug("Scanner: candidate '{}' skipped: matches more than once in "
                                 "the scanned scope (require_unique).",
                                 candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name);
                    continue;
                }

                const auto addr = resolve_candidate_match(reinterpret_cast<std::uintptr_t>(match), candidate);
                // A RipRelative candidate whose displacement read faulted or resolved to an implausible address yields
                // nothing here (resolve_candidate_match applies the same plausibility floor as resolve_rip_relative),
                // so the whole-process path cannot commit to a near-null or kernel-range hit. The module-scoped path
                // below adds a stricter in-image guard.
                if (!addr)
                {
                    continue;
                }
                // Module-scoped resolutions must land inside the image. The match site is already in-range (the
                // module-scoped scan only searches it), but a RipRelative disp read at an in-module instruction can
                // still resolve outside the image (e.g. an import thunk in another module). Reject that here so the
                // cascade falls through to the next candidate instead of committing to an out-of-module address -- a
                // decision a post-resolution check by the caller could not reverse.
                if (range && !DetourModKit::Memory::contains(*range, *addr))
                {
                    continue;
                }
                return CascadeAttempt{*addr, i, true};
            }
            return CascadeAttempt{0, 0, false};
        }

        struct PrologueFallbackResult
        {
            CascadeAttempt attempt{};
            bool not_applicable{true};
        };

        // Attempts one prologue shape for a single Direct candidate: rebuilds the patched prologue as shape.jump_prefix
        // plus the candidate's surviving literal tail, requires that rebuilt pattern to match exactly once in scope,
        // decodes the jump to recover the redirected target, and gates that destination as a plausible, executable
        // address. Returns the resolved attempt on success, or nullopt when this shape does not apply or does not
        // uniquely recover a target. *applicable is set true once the shape produces a usable rebuilt pattern (enough
        // literal tail), regardless of whether it then matches, so the caller can distinguish "no shape was applicable"
        // from "applicable but no match".
        std::optional<CascadeAttempt> try_prologue_shape(const DetourModKit::Scanner::AddrCandidate &candidate,
                                                         std::size_t index,
                                                         const DetourModKit::Scanner::CompiledPattern &original,
                                                         std::optional<DetourModKit::Memory::ModuleRange> range,
                                                         const PrologueShape &shape, bool &applicable)
        {
            DetourModKit::Logger &logger = DetourModKit::Logger::get_instance();
            const std::string hooked = build_hooked_prologue_pattern(original, shape.patch_bytes, shape.jump_prefix);
            if (hooked.empty())
            {
                return std::nullopt;
            }
            auto compiled = DetourModKit::Scanner::parse_aob(hooked);
            if (!compiled)
            {
                return std::nullopt;
            }
            applicable = true;
            const std::byte *first_match = nullptr;
            const std::size_t hits =
                count_pattern_hits_bounded(*compiled, PROLOGUE_FALLBACK_MAX_HITS, range, &first_match);
            if (hits == 0)
            {
                return std::nullopt;
            }
            if (hits > PROLOGUE_FALLBACK_MAX_HITS)
            {
                logger.debug("Scanner: prologue fallback rejected for '{}': {} hits exceed uniqueness ceiling ({})",
                             candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name, hits,
                             PROLOGUE_FALLBACK_MAX_HITS);
                return std::nullopt;
            }
            // Reuse the first occurrence the count already located (hits is in [1, PROLOGUE_FALLBACK_MAX_HITS] here, so
            // first_match is the unique match) instead of re-sweeping the same scope for it.
            const auto match_addr = reinterpret_cast<std::uintptr_t>(first_match);
            const auto decoded = shape.decode(match_addr);
            if (!decoded)
            {
                return std::nullopt;
            }
            const auto jmp_destination = *decoded;
            // The rewritten jump was FOUND inside the target (the module image when `range` is set, the process
            // otherwise), but its destination must NOT be constrained to that module. When a sibling mod inline-hooks
            // the target, its jump can land on a trampoline the sibling allocated outside every loaded module;
            // SafetyHook does this for inline hooks, and an FF 25 far jump stores an absolute trampoline address in its
            // slot. An in-module requirement would reject the very recovery this path exists for. Gate the destination
            // on "plausible user-space pointer on a committed, execute-readable page" instead: that still rejects a
            // jump into unmapped or data-only memory (a coincidental opcode match whose tail happened to align), while
            // the uniqueness ceiling and the literal-tail floor remain the primary false-positive defense.
            if (!DetourModKit::Memory::plausible_userspace_ptr(jmp_destination) ||
                !Scanner::detail::is_executable_address(jmp_destination))
            {
                logger.debug("Scanner: prologue fallback rejected for '{}': jump destination {} is not executable",
                             candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name,
                             Format::format_address(jmp_destination));
                return std::nullopt;
            }

            // The rebuilt pattern compiled with offset 0: replacing the prologue with the jump prefix dropped the
            // original
            // `|` anchor, so its scan returned the bare match start. Reconstruct the anchored match the direct pass
            // would have produced (match start plus the original anchor offset) before resolving, so a `|`-anchored
            // Direct candidate recovered here lands on the same byte as the unhooked direct scan instead of short by
            // the offset.
            const auto anchored_match = match_addr + static_cast<std::uintptr_t>(original.offset);
            const auto addr = resolve_candidate_match(anchored_match, candidate);
            if (!addr)
            {
                return std::nullopt;
            }
            return CascadeAttempt{*addr, index, true};
        }

        PrologueFallbackResult
        scan_candidates_hooked_prologue(std::span<const DetourModKit::Scanner::AddrCandidate> candidates,
                                        std::optional<DetourModKit::Memory::ModuleRange> range = std::nullopt)
        {
            using DetourModKit::Scanner::ResolveMode;
            DetourModKit::Logger &logger = DetourModKit::Logger::get_instance();
            PrologueFallbackResult out;
            for (std::size_t i = 0; i < candidates.size(); ++i)
            {
                const auto &candidate = candidates[i];
                if (candidate.mode != ResolveMode::Direct)
                {
                    continue;
                }
                // Parse the original signature with the same parser the direct pass uses, so the fallback inherits its
                // token validation and -- critically -- its `|` anchor offset, carried into the resolve below. A
                // malformed pattern was already reported by the direct pass, so skip it silently here.
                const auto original = DetourModKit::Scanner::parse_aob(candidate.pattern);
                if (!original)
                {
                    continue;
                }
                // Try each recognised inline-hook prologue shape in turn. The first that uniquely recovers an
                // executable target wins; E9 is tried before FF 25 because it is by far the common case.
                bool any_applicable = false;
                for (const PrologueShape &shape : PROLOGUE_SHAPES)
                {
                    bool applicable = false;
                    const auto attempt = try_prologue_shape(candidate, i, *original, range, shape, applicable);
                    if (applicable)
                    {
                        any_applicable = true;
                        out.not_applicable = false;
                    }
                    if (attempt)
                    {
                        out.attempt = *attempt;
                        return out;
                    }
                }
                if (!any_applicable)
                {
                    logger.debug("Scanner: prologue fallback skipped for '{}' (insufficient literal tail bytes)",
                                 candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name);
                }
            }
            return out;
        }

        // Maps a finished non-fallback cascade attempt to the public result, emitting the single success debug line or
        // the matching failure diagnostic. Shared by the whole-process and module-scoped resolvers so the three-way
        // mapping (success / AllPatternsInvalid / NoMatch) stays identical across both.
        std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
        finalize_cascade(const CascadeAttempt &attempt, bool all_parse_failed,
                         std::span<const DetourModKit::Scanner::AddrCandidate> candidates, std::string_view label)
        {
            using DetourModKit::Scanner::ResolveError;
            using DetourModKit::Scanner::ResolveHit;
            DetourModKit::Logger &logger = DetourModKit::Logger::get_instance();
            if (attempt.success)
            {
                const auto &winner = candidates[attempt.index];
                logger.debug("{} resolved via '{}' at {}", label,
                             winner.name.empty() ? std::string_view{"<unnamed>"} : winner.name,
                             Format::format_address(attempt.address));
                return ResolveHit{attempt.address, winner.name};
            }
            if (all_parse_failed)
            {
                logger.error("{}: every candidate pattern failed to parse.", label);
                return std::unexpected(ResolveError::AllPatternsInvalid);
            }
            logger.warning("{}: cascade AOB scan failed (no candidate matched).", label);
            return std::unexpected(ResolveError::NoMatch);
        }

        // Maps a finished cascade + prologue-fallback attempt to the public result. Mirrors finalize_cascade but adds
        // the pre-hooked-prologue success line and the fallback-specific failure diagnostics (not-applicable vs
        // no-match).
        std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
        finalize_cascade_with_fallback(const CascadeAttempt &attempt, bool all_parse_failed,
                                       const PrologueFallbackResult &hooked,
                                       std::span<const DetourModKit::Scanner::AddrCandidate> candidates,
                                       std::string_view label)
        {
            using DetourModKit::Scanner::ResolveError;
            using DetourModKit::Scanner::ResolveHit;
            DetourModKit::Logger &logger = DetourModKit::Logger::get_instance();
            if (attempt.success)
            {
                const auto &winner = candidates[attempt.index];
                logger.debug("{} resolved via '{}' at {}", label,
                             winner.name.empty() ? std::string_view{"<unnamed>"} : winner.name,
                             Format::format_address(attempt.address));
                return ResolveHit{attempt.address, winner.name};
            }
            if (hooked.attempt.success)
            {
                const auto &winner = candidates[hooked.attempt.index];
                logger.debug("{} resolved via '{}' at {} (pre-hooked prologue; reusing target)", label,
                             winner.name.empty() ? std::string_view{"<unnamed>"} : winner.name,
                             Format::format_address(hooked.attempt.address));
                return ResolveHit{hooked.attempt.address, winner.name};
            }
            if (all_parse_failed)
            {
                logger.error("{}: every candidate pattern failed to parse.", label);
                return std::unexpected(ResolveError::AllPatternsInvalid);
            }
            if (hooked.not_applicable)
            {
                logger.warning(
                    "{}: cascade AOB scan failed; prologue fallback not applicable (insufficient literal tail bytes).",
                    label);
                return std::unexpected(ResolveError::PrologueFallbackNotApplicable);
            }
            logger.warning("{}: cascade AOB scan failed (including prologue fallback).", label);
            return std::unexpected(ResolveError::NoMatch);
        }
    } // anonymous namespace

    std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
    DetourModKit::Scanner::resolve_cascade(std::span<const AddrCandidate> candidates, std::string_view label,
                                           ScannerKind kind)
    {
        auto &logger = Logger::get_instance();

        if (candidates.empty())
        {
            logger.warning("Scanner: resolve_cascade for '{}' called with no candidates.", label);
            return std::unexpected(ResolveError::EmptyCandidates);
        }

        bool all_parse_failed = true;
        const auto attempt = scan_candidates(candidates, all_parse_failed, kind);
        return finalize_cascade(attempt, all_parse_failed, candidates, label);
    }

    std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
    DetourModKit::Scanner::resolve_cascade_in_module(std::span<const AddrCandidate> candidates, std::string_view label,
                                                     Memory::ModuleRange range)
    {
        auto &logger = Logger::get_instance();

        if (candidates.empty())
        {
            logger.warning("Scanner: resolve_cascade_in_module for '{}' called with no candidates.", label);
            return std::unexpected(ResolveError::EmptyCandidates);
        }
        if (!range.valid())
        {
            logger.warning("Scanner: resolve_cascade_in_module for '{}' called with an invalid module range.", label);
            return std::unexpected(ResolveError::InvalidRange);
        }

        bool all_parse_failed = true;
        // The ScannerKind argument is unused once a range is supplied (see
        // scan_candidates): one module-scoped scan covers .text and .rdata together.
        const auto attempt = scan_candidates(candidates, all_parse_failed, ScannerKind::Executable, range);
        return finalize_cascade(attempt, all_parse_failed, candidates, label);
    }

    std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
    DetourModKit::Scanner::resolve_cascade_with_prologue_fallback(std::span<const AddrCandidate> candidates,
                                                                  std::string_view label)
    {
        auto &logger = Logger::get_instance();

        if (candidates.empty())
        {
            logger.warning("Scanner: resolve_cascade_with_prologue_fallback for '{}' called with no candidates.",
                           label);
            return std::unexpected(ResolveError::EmptyCandidates);
        }

        // Prologue recovery is a code-shape heuristic (it rebuilds a hooked
        // near-JMP prologue), so this resolver is executable-only by construction;
        // the readable sweep is meaningless for it.
        bool all_parse_failed = true;
        const auto attempt = scan_candidates(candidates, all_parse_failed, ScannerKind::Executable);
        // The prologue-recovery pass is expensive (it rescans the process), so run it only when the direct pass found
        // nothing.
        PrologueFallbackResult hooked;
        if (!attempt.success)
        {
            hooked = scan_candidates_hooked_prologue(candidates);
        }
        return finalize_cascade_with_fallback(attempt, all_parse_failed, hooked, candidates, label);
    }

    std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
    DetourModKit::Scanner::resolve_cascade_in_module_with_prologue_fallback(std::span<const AddrCandidate> candidates,
                                                                            std::string_view label,
                                                                            Memory::ModuleRange range)
    {
        auto &logger = Logger::get_instance();

        if (candidates.empty())
        {
            logger.warning(
                "Scanner: resolve_cascade_in_module_with_prologue_fallback for '{}' called with no candidates.", label);
            return std::unexpected(ResolveError::EmptyCandidates);
        }
        if (!range.valid())
        {
            logger.warning("Scanner: resolve_cascade_in_module_with_prologue_fallback for '{}' called with an invalid "
                           "module range.",
                           label);
            return std::unexpected(ResolveError::InvalidRange);
        }

        // Both the direct pass and the prologue-recovery pass confine their scans to the module image: the match site
        // must be in-range, while a rebuilt near-JMP may still jump to a trampoline outside it (see
        // scan_candidates_hooked_prologue).
        bool all_parse_failed = true;
        const auto attempt = scan_candidates(candidates, all_parse_failed, ScannerKind::Executable, range);
        PrologueFallbackResult hooked;
        if (!attempt.success)
        {
            hooked = scan_candidates_hooked_prologue(candidates, range);
        }
        return finalize_cascade_with_fallback(attempt, all_parse_failed, hooked, candidates, label);
    }

    std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
    DetourModKit::Scanner::resolve_cascade_in_host_module(std::span<const AddrCandidate> candidates,
                                                          std::string_view label)
    {
        // host_module_range() returns an invalid range (base == end == 0) when the main module cannot be resolved;
        // forward the typed failure rather than letting the underlying resolver scan an empty span and report NoMatch.
        const auto range = Memory::host_module_range();
        if (!range.valid())
        {
            Logger::get_instance().warning(
                "Scanner: resolve_cascade_in_host_module for '{}' could not determine the host module range.", label);
            return std::unexpected(ResolveError::InvalidRange);
        }
        return resolve_cascade_in_module(candidates, label, range);
    }

    std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
    DetourModKit::Scanner::resolve_cascade_in_host_module_with_prologue_fallback(
        std::span<const AddrCandidate> candidates, std::string_view label)
    {
        const auto range = Memory::host_module_range();
        if (!range.valid())
        {
            Logger::get_instance().warning(
                "Scanner: resolve_cascade_in_host_module_with_prologue_fallback for '{}' could not "
                "determine the host module range.",
                label);
            return std::unexpected(ResolveError::InvalidRange);
        }
        return resolve_cascade_in_module_with_prologue_fallback(candidates, label, range);
    }
} // namespace DetourModKit
