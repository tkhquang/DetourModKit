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

#include <windows.h>
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

    bool is_wildcard_token(std::string_view token) noexcept
    {
        return token == "?" || token == "??";
    }

    // Walks the AOB token stream and splits it into (first 5 byte-tokens, tail).
    // The `|` anchor marker is stripped because the rebuilt pattern targets
    // the hooked-prologue start. Returns false if the source has fewer than
    // 5 byte-tokens.
    struct PrologueSplit
    {
        std::vector<std::string_view> tail_tokens;
        int literal_tail_count{0};
    };

    bool split_prologue(std::string_view orig, PrologueSplit &out) noexcept
    {
        std::size_t i = 0;
        int byte_tokens = 0;
        while (i < orig.size())
        {
            while (i < orig.size() && (orig[i] == ' ' || orig[i] == '\t' || orig[i] == '\n' || orig[i] == '\r'))
            {
                ++i;
            }
            if (i >= orig.size())
            {
                break;
            }
            if (orig[i] == '|')
            {
                ++i;
                continue;
            }
            const std::size_t tok_start = i;
            while (i < orig.size() && orig[i] != ' ' && orig[i] != '\t' && orig[i] != '\n' && orig[i] != '\r' &&
                   orig[i] != '|')
            {
                ++i;
            }
            const std::string_view tok = orig.substr(tok_start, i - tok_start);
            if (tok.empty())
            {
                continue;
            }
            if (byte_tokens >= 5)
            {
                out.tail_tokens.push_back(tok);
                if (!is_wildcard_token(tok))
                {
                    ++out.literal_tail_count;
                }
            }
            ++byte_tokens;
        }
        return byte_tokens >= 5;
    }

    std::string build_hooked_prologue_pattern(std::string_view orig)
    {
        if (orig.empty())
        {
            return {};
        }
        PrologueSplit split;
        if (!split_prologue(orig, split))
        {
            return {};
        }
        if (split.literal_tail_count < PROLOGUE_FALLBACK_MIN_TAIL_LITERALS)
        {
            return {};
        }
        std::string out = "E9 ?? ?? ?? ??";
        for (const auto &tok : split.tail_tokens)
        {
            out.push_back(' ');
            out.append(tok);
        }
        return out;
    }

    // Returns true if `addr` lies inside any currently loaded module's executable image range. Used to reject E9-rel32
    // destinations that resolve into unmapped or data-only memory.
    bool is_address_in_module(std::uintptr_t addr) noexcept
    {
        if (addr == 0)
        {
            return false;
        }
        HMODULE mod = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(addr), &mod) ||
            mod == nullptr)
        {
            return false;
        }
        return true;
    }

    // Counts up to (max_hits + 1) occurrences of `pattern`. When `range` is set the count is confined to that module
    // image; otherwise it spans the whole process's executable regions. Returning max_hits+1 signals "too many to be
    // unique". The count must use the same scope as the eventual match scan, or a pattern unique inside the target
    // module but duplicated in a sibling overlay would be wrongly rejected (or accepted) on the wrong evidence.
    std::size_t count_pattern_hits_bounded(const DetourModKit::Scanner::CompiledPattern &pattern, std::size_t max_hits,
                                           std::optional<DetourModKit::Memory::ModuleRange> range) noexcept
    {
        std::size_t hits = 0;
        for (std::size_t n = 1; n <= max_hits + 1; ++n)
        {
            const auto *match = range ? Scanner::detail::scan_module_executable(pattern, *range, n)
                                      : DetourModKit::Scanner::scan_executable_regions(pattern, n);
            if (match == nullptr)
            {
                break;
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
            auto hooked = build_hooked_prologue_pattern(candidate.pattern);
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
            const std::size_t hits = count_pattern_hits_bounded(*compiled, PROLOGUE_FALLBACK_MAX_HITS, range);
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
            const auto *match = range ? Scanner::detail::scan_module_executable(*compiled, *range)
                                      : DetourModKit::Scanner::scan_executable_regions(*compiled);
            if (match == nullptr)
            {
                continue;
            }

            const auto match_addr = reinterpret_cast<std::uintptr_t>(match);
            const auto decoded = DetourModKit::detail::decode_e9_rel32(match_addr);
            if (!decoded)
            {
                continue;
            }
            const auto jmp_destination = *decoded;
            // The rewritten near-JMP itself was FOUND inside the target (the module image when `range` is set, the
            // process otherwise), but its destination must NOT be constrained to that module. When a sibling mod
            // inline-hooks the target, its E9 jumps to a trampoline the sibling allocated outside this image, so
            // requiring the destination in-range would reject the very recovery this path performs. Gate the
            // destination only on "lies in some loaded module", which still rejects a jump into unmapped or data-only
            // memory.
            if (!is_address_in_module(jmp_destination))
            {
                logger.debug("Scanner: prologue fallback rejected for '{}': E9 destination {} not in any module",
                             candidate.name.empty() ? std::string_view{"<unnamed>"} : candidate.name, jmp_destination);
                continue;
            }

            const auto addr = resolve_candidate_match(match_addr, candidate);
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
