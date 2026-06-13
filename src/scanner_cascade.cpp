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

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <cstddef>
#include <cstdint>

using namespace DetourModKit;

namespace
{
    std::optional<std::uintptr_t>
    resolve_candidate_match(std::uintptr_t match_addr, const DetourModKit::Scanner::AddrCandidate &candidate) noexcept
    {
        using DetourModKit::Scanner::ResolveMode;
        if (candidate.mode == ResolveMode::Direct)
        {
            return match_addr + static_cast<std::uintptr_t>(candidate.disp_offset);
        }
        const auto disp_addr = match_addr + static_cast<std::uintptr_t>(candidate.disp_offset);
        // Fault-guarded read instead of is_readable + raw memcpy: the page can change between the check and the copy
        // (TOCTOU), so an unguarded memcpy could fault the host process. seh_read returns nullopt on any fault.
        const auto disp = DetourModKit::Memory::seh_read<std::int32_t>(disp_addr);
        if (!disp)
        {
            // A faulted displacement read is a miss, not a hit at address 0: the whole-process path has no in-range
            // guard to reject a zero result, so returning nullopt here prevents a false ResolveHit at 0.
            return std::nullopt;
        }
        const auto resolved = static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(match_addr + static_cast<std::uintptr_t>(candidate.instr_end_offset)) + *disp);
        // Mirror resolve_rip_relative's plausibility floor. A corrupt or crafted displacement can resolve to 0, a low
        // guard-page address, or a kernel-range value; the whole-process cascade path has no image to bound the result
        // (the module-scoped path layers a stricter contains() check on top), so reject an implausible target here
        // rather than commit to a hit the caller cannot later reverse.
        if (!DetourModKit::Memory::plausible_userspace_ptr(resolved))
        {
            return std::nullopt;
        }
        return resolved;
    }

    // Minimum number of literal (non-wildcard) bytes the tail of the pattern must contain after dropping the first 5
    // prologue tokens. Five literal bytes still leave the rebuilt pattern shaped like a generic near-JMP plus a short
    // common-instruction tail, which collides with thousands of unrelated E9 sites in a multi-megabyte .text section.
    // Ten literal bytes is roughly two to four real instructions of context and reduces the false-positive rate to near
    // zero on real binaries while staying inside the 12 to 20 byte sweet spot documented for fallback signatures.
    constexpr int PROLOGUE_FALLBACK_MIN_TAIL_LITERALS = 10;

    // Upper bound on hits the rebuilt fallback pattern may produce within the scanned scope (the module image when a
    // range is supplied, the process's executable regions otherwise) before we reject it as ambiguous. The fallback
    // only exists to recover the single site where a sibling mod inline-hooked the target function, so the legitimate
    // rewritten pattern must match exactly once: the unique JMP into that mod's trampoline. Any value above 1 admits a
    // false positive whose blast radius (a hook installed at an unrelated function) far outweighs the benefit of
    // tolerating duplicate matches.
    constexpr std::size_t PROLOGUE_FALLBACK_MAX_HITS = 1;

    // E9 rel32 inline hooks overwrite exactly five bytes: one opcode plus one int32 displacement.
    constexpr std::size_t PROLOGUE_PATCH_BYTES = 5;

    void append_hex_byte(std::string &out, std::byte value)
    {
        constexpr char digits[] = "0123456789ABCDEF";
        const auto byte_value = std::to_integer<unsigned>(value);
        out.push_back(digits[(byte_value >> 4) & 0xF]);
        out.push_back(digits[byte_value & 0xF]);
    }

    // Build from the parsed pattern so parse_aob remains the only token parser. The caller keeps original.offset and
    // applies it after the fallback scan, which makes `|`-anchored recovery match the direct path exactly.
    std::string build_hooked_prologue_pattern(const DetourModKit::Scanner::CompiledPattern &original)
    {
        if (original.size() < PROLOGUE_PATCH_BYTES)
        {
            return {};
        }
        int literal_tail_count = 0;
        for (std::size_t i = PROLOGUE_PATCH_BYTES; i < original.size(); ++i)
        {
            if (original.mask[i] != std::byte{0x00})
            {
                ++literal_tail_count;
            }
        }
        if (literal_tail_count < PROLOGUE_FALLBACK_MIN_TAIL_LITERALS)
        {
            return {};
        }
        std::string out = "E9 ?? ?? ?? ??";
        for (std::size_t i = PROLOGUE_PATCH_BYTES; i < original.size(); ++i)
        {
            out.push_back(' ');
            if (original.mask[i] == std::byte{0x00})
            {
                out.append("??");
            }
            else
            {
                append_hex_byte(out, original.bytes[i]);
            }
        }
        return out;
    }

    // Counts up to (max_hits + 1) occurrences of `pattern`. When `range` is set the count is confined to that module
    // image; otherwise it spans the whole process's executable regions. Returning max_hits+1 signals "too many to be
    // unique". The count must use the same scope as the eventual match scan, or a pattern unique inside the target
    // module but duplicated in a sibling overlay would be wrongly rejected (or accepted) on the wrong evidence. When
    // first_match_out is non-null it receives the first occurrence (the n == 1 scan result, or nullptr when there were
    // no hits) so a caller that needs both the count and the first match -- the same scan, same scope -- does not have
    // to sweep again to fetch it.
    std::size_t count_pattern_hits_bounded(const DetourModKit::Scanner::CompiledPattern &pattern, std::size_t max_hits,
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

            // Resolves the Nth occurrence in the active scope. A supplied module range takes precedence over `kind`:
            // one scan of the contiguous image already covers both .text and .rdata / .data candidates, so the
            // executable-vs-readable split is moot inside it.
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

            // Per-candidate uniqueness guard. A candidate flagged require_unique must match exactly once in the scanned
            // scope; a second occurrence means the pattern is ambiguous, so the first (lowest-address) match is not
            // provably the intended target. Skip it so the cascade falls through to the next candidate instead of
            // committing to an arbitrary hit -- the choice between equally-matching sites is semantic and the scanner
            // cannot make it. The extra occurrence scan only runs for a candidate that already matched and has
            // require_unique set (the default); set require_unique = false to accept the first match and skip it.
            if (candidate.require_unique && scan_for(2) != nullptr)
            {
                logger.debug("Scanner: candidate '{}' skipped: matches more than once in "
                             "the scanned scope (require_unique).",
                             candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name);
                continue;
            }

            const auto addr = resolve_candidate_match(reinterpret_cast<std::uintptr_t>(match), candidate);
            // A RipRelative candidate whose displacement read faulted or resolved to an implausible address yields
            // nothing here (resolve_candidate_match applies the same plausibility floor as resolve_rip_relative), so
            // the whole-process path cannot commit to a near-null or kernel-range hit. The module-scoped path below
            // adds a stricter in-image guard.
            if (!addr)
            {
                continue;
            }
            // Module-scoped resolutions must land inside the image. The match site is already in-range (the
            // module-scoped scan only searches it), but a RipRelative disp read at an in-module instruction can still
            // resolve outside the image (e.g. an import thunk in another module). Reject that here so the cascade falls
            // through to the next candidate instead of committing to an out-of-module address -- a decision a
            // post-resolution check by the caller could not reverse.
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
            // token validation and -- critically -- its `|` anchor offset, carried into the resolve below. A malformed
            // pattern was already reported by the direct pass, so skip it silently here.
            const auto original = DetourModKit::Scanner::parse_aob(candidate.pattern);
            if (!original)
            {
                continue;
            }
            const auto hooked = build_hooked_prologue_pattern(*original);
            if (hooked.empty())
            {
                logger.debug("Scanner: prologue fallback skipped for '{}' (insufficient literal tail bytes)",
                             candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name);
                continue;
            }
            auto compiled = DetourModKit::Scanner::parse_aob(hooked);
            if (!compiled)
            {
                continue;
            }
            out.not_applicable = false;
            const std::byte *first_match = nullptr;
            const std::size_t hits =
                count_pattern_hits_bounded(*compiled, PROLOGUE_FALLBACK_MAX_HITS, range, &first_match);
            if (hits == 0)
            {
                continue;
            }
            if (hits > PROLOGUE_FALLBACK_MAX_HITS)
            {
                logger.debug("Scanner: prologue fallback rejected for '{}': {} hits exceed uniqueness ceiling ({})",
                             candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name, hits,
                             PROLOGUE_FALLBACK_MAX_HITS);
                continue;
            }
            // Reuse the first occurrence the count already located (hits is in [1, PROLOGUE_FALLBACK_MAX_HITS] here, so
            // first_match is the unique match) instead of re-sweeping the same scope for it.
            const auto match_addr = reinterpret_cast<std::uintptr_t>(first_match);
            const auto decoded = DetourModKit::detail::decode_e9_rel32(match_addr);
            if (!decoded)
            {
                continue;
            }
            const auto jmp_destination = *decoded;
            // The rewritten near-JMP was FOUND inside the target (the module image when `range` is set, the process
            // otherwise), but its destination must NOT be constrained to that module. When a sibling mod inline-hooks
            // the target, its E9 can jump to a trampoline the sibling allocated outside every loaded module; SafetyHook
            // does this for inline hooks. An in-module requirement would reject the very recovery this path exists for.
            // Gate the destination on "plausible user-space pointer on a committed, execute-readable page" instead:
            // that still rejects a jump into unmapped or data-only memory (a coincidental E9 match whose tail happened
            // to align), while the uniqueness ceiling and the literal-tail floor remain the primary false-positive
            // defense.
            if (!DetourModKit::Memory::plausible_userspace_ptr(jmp_destination) ||
                !Scanner::detail::is_executable_address(jmp_destination))
            {
                logger.debug("Scanner: prologue fallback rejected for '{}': E9 destination {} is not executable",
                             candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name,
                             Format::format_address(jmp_destination));
                continue;
            }

            // The rebuilt pattern compiled with offset 0: replacing the prologue with `E9 ?? ?? ?? ??` dropped the
            // original `|` anchor, so its scan returned the bare match start. Reconstruct the anchored match the direct
            // pass would have produced (match start plus the original anchor offset) before resolving, so a
            // `|`-anchored Direct candidate recovered here lands on the same byte as the unhooked direct scan instead
            // of short by the anchor offset.
            const auto anchored_match = match_addr + static_cast<std::uintptr_t>(original->offset);
            const auto addr = resolve_candidate_match(anchored_match, candidate);
            if (!addr)
            {
                continue;
            }
            out.attempt = CascadeAttempt{*addr, i, true};
            return out;
        }
        return out;
    }

    // Maps a finished non-fallback cascade attempt to the public result, emitting the single success debug line or the
    // matching failure diagnostic. Shared by the whole-process and module-scoped resolvers so the three-way mapping
    // (success / AllPatternsInvalid / NoMatch) stays identical across both.
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

    // Maps a finished cascade + prologue-fallback attempt to the public result. Mirrors finalize_cascade but adds the
    // pre-hooked-prologue success line and the fallback-specific failure diagnostics (not-applicable vs no-match).
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
        logger.warning("Scanner: resolve_cascade_with_prologue_fallback for '{}' called with no candidates.", label);
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
        logger.warning("Scanner: resolve_cascade_in_module_with_prologue_fallback for '{}' called with no candidates.",
                       label);
        return std::unexpected(ResolveError::EmptyCandidates);
    }
    if (!range.valid())
    {
        logger.warning(
            "Scanner: resolve_cascade_in_module_with_prologue_fallback for '{}' called with an invalid module range.",
            label);
        return std::unexpected(ResolveError::InvalidRange);
    }

    // Both the direct pass and the prologue-recovery pass confine their scans to the module image: the match site must
    // be in-range, while a rebuilt near-JMP may still jump to a trampoline outside it (see
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
DetourModKit::Scanner::resolve_cascade_in_host_module(std::span<const AddrCandidate> candidates, std::string_view label)
{
    // host_module_range() returns an invalid range (base == end == 0) when the main module cannot be resolved; forward
    // the typed failure rather than letting the underlying resolver scan an empty span and report NoMatch.
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
DetourModKit::Scanner::resolve_cascade_in_host_module_with_prologue_fallback(std::span<const AddrCandidate> candidates,
                                                                             std::string_view label)
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
