#ifndef DETOURMODKIT_INTERNAL_SCAN_SHARED_HPP
#define DETOURMODKIT_INTERNAL_SCAN_SHARED_HPP

/**
 * @file internal/scan_shared.hpp
 * @brief Small shared helpers for the public scan-module TUs: the bounded haystack-frequency anchor override and the
 *        per-byte-tier resolution arithmetic.
 * @details Never installed. The scan_matching, scan_resolution, and scan_prologue_recovery TUs all turn a value Pattern
 *          into an EnginePattern with a haystack-chosen anchor and screen byte-tier resolutions through the same
 *          plausible-userspace floor, so those helpers live here in one place rather than being duplicated. The anchor
 *          override is correctness-neutral: it only changes which single byte the memchr prefilter sweeps for; the full
 *          masked compare still decides every accepted position.
 */

#include "internal/memory_guarded.hpp"
#include "internal/scan_engine.hpp"

#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace DetourModKit
{
    namespace detail
    {
        // Bounded haystack sampling budget. A byte-frequency ranking needs only a representative sample, not the whole
        // image: 64 page reads (256 KiB) strided across the scope are ample to rank 256 byte values, and the fixed cap
        // keeps anchor selection a constant cost regardless of scope size so it never approaches the cost of the scan
        // it accelerates. Scopes larger than the budget ceiling (a whole-process window, terabytes of mostly-unmapped
        // address space) are not sampled at all: the sample would be unrepresentative and would pay for dozens of
        // guaranteed page faults, so those fall back to the compile-time anchor.
        inline constexpr std::size_t SAMPLE_PAGE = 0x1000;
        inline constexpr std::size_t SAMPLE_MAX_PAGES = 64;
        inline constexpr std::size_t SAMPLE_MIN_BYTES = SAMPLE_PAGE;
        inline constexpr std::size_t SAMPLE_MAX_SCOPE = std::size_t{512} * 1024 * 1024;

        struct HaystackHistogram
        {
            std::array<std::uint32_t, 256> counts{};
            std::size_t sampled = 0;
        };

        // Sample a bounded, strided set of pages from the scope and tally a 256-bin byte-frequency histogram. Reads go
        // through guarded_read_bytes one page at a time, so an unmapped / guard page inside the scope is skipped rather
        // than faulting the host; the stride spreads the sample across .text and .rdata / .data so the frequencies
        // reflect the whole image, not just its first pages. Entirely stack-based (the histogram and the page buffer
        // are locals), so it never allocates and is safe to call from the noexcept scan paths.
        [[nodiscard]] inline HaystackHistogram sample_haystack(Region scope) noexcept
        {
            HaystackHistogram histogram;
            const std::uintptr_t base = scope.base.raw();
            if (base == 0 || scope.size == 0 || scope.size > SAMPLE_MAX_SCOPE)
            {
                return histogram;
            }
            const std::size_t total_pages = (scope.size + SAMPLE_PAGE - 1) / SAMPLE_PAGE;
            const std::size_t stride = (total_pages > SAMPLE_MAX_PAGES) ? (total_pages / SAMPLE_MAX_PAGES) : 1;
            std::array<std::uint8_t, SAMPLE_PAGE> buffer{};
            std::size_t pages_read = 0;
            for (std::size_t page = 0; page < total_pages && pages_read < SAMPLE_MAX_PAGES; page += stride)
            {
                const std::uintptr_t page_address = base + static_cast<std::uintptr_t>(page) * SAMPLE_PAGE;
                const std::size_t remaining = scope.size - page * SAMPLE_PAGE;
                const std::size_t want = (remaining < SAMPLE_PAGE) ? remaining : SAMPLE_PAGE;
                if (!guarded_read_bytes(page_address, buffer.data(), want))
                {
                    // A page that faults mid-read is skipped; the sample stays a valid (smaller) lower bound.
                    continue;
                }
                for (std::size_t i = 0; i < want; ++i)
                {
                    ++histogram.counts[buffer[i]];
                }
                histogram.sampled += want;
                ++pages_read;
            }
            return histogram;
        }

        // When a sufficient haystack sample exists, pick the pattern's fully-known byte whose value is rarest in this
        // image (the most selective prefilter for this haystack), overriding the compile-time rarest-byte anchor the
        // Pattern carries; otherwise fall back to that compile-time anchor. Returns the engine "no fully-known byte"
        // sentinel (size()) when segment 0 has no full byte. Correctness-neutral: the anchor only selects which single
        // byte the memchr prefilter sweeps for; the full masked compare still decides every accepted position.
        //
        // The override is confined to segment 0 (the fixed run before the first bounded jump), exactly like the
        // compile-time anchor: the segmented matcher locates that first run and then walks the variable gaps, so a byte
        // in a later segment sits at a gap-dependent address the memchr prefilter cannot sweep for. Choosing an anchor
        // outside segment 0 would compute a wrong candidate start and silently miss real matches.
        [[nodiscard]] inline std::size_t choose_scan_anchor(const scan::Pattern &pattern,
                                                            const HaystackHistogram &histogram) noexcept
        {
            const std::size_t size = pattern.size();
            if (histogram.sampled < SAMPLE_MIN_BYTES)
            {
                return pattern.has_anchor() ? pattern.anchor_index() : size;
            }
            const std::span<const std::byte> bytes = pattern.bytes();
            const std::span<const std::byte> mask = pattern.mask();
            const detail::PatternBuffer &data = detail::pattern_buffer(pattern);
            const std::size_t segment0_end = (data.jump_count == 0) ? size : data.jumps[0].position;
            std::size_t best_index = size;
            std::uint32_t best_count = 0;
            for (std::size_t i = 0; i < segment0_end; ++i)
            {
                if (mask[i] != std::byte{0xFF})
                {
                    // Only a fully-known byte gives the prefilter one exact value to memchr for; nibble / wildcard
                    // positions cannot anchor.
                    continue;
                }
                const std::uint32_t count = histogram.counts[std::to_integer<std::uint8_t>(bytes[i])];
                if (best_index == size || count < best_count)
                {
                    best_index = i;
                    best_count = count;
                }
            }
            return best_index;
        }

        // Builds the engine pattern for a value Pattern with the haystack-chosen anchor. Allocates two small vectors,
        // so every caller on a noexcept path guards this against std::bad_alloc.
        [[nodiscard]] inline EnginePattern to_engine_pattern(const scan::Pattern &pattern,
                                                             const HaystackHistogram &histogram)
        {
            const std::size_t anchor = choose_scan_anchor(pattern, histogram);
            return engine_pattern_from(pattern, anchor);
        }

        // Direct-tier resolution: the resolved address is the match plus the signed walk-back. Screened through the
        // plausible-userspace floor so a pathological walk-back that underflows to a near-null / kernel-range address
        // is a miss, never a hit.
        [[nodiscard]] inline std::optional<std::uintptr_t> resolve_direct(std::uintptr_t match,
                                                                          const scan::DirectPattern &direct) noexcept
        {
            const std::uintptr_t resolved = match + static_cast<std::uintptr_t>(direct.walk_back);
            if (!is_plausible_ptr(resolved))
            {
                return std::nullopt;
            }
            return resolved;
        }

        // RipRelative-tier resolution: read the disp32 the instruction spans under a fault guard and compute
        // (next-IP + sign-extended disp). A faulted read or an implausible target is a miss, matching
        // resolve_rip_relative's contract.
        [[nodiscard]] inline std::optional<std::uintptr_t>
        resolve_rip_relative_candidate(std::uintptr_t match, const scan::RipRelativePattern &rip) noexcept
        {
            const std::uintptr_t displacement_address = match + static_cast<std::uintptr_t>(rip.displacement_at);
            const std::optional<std::int32_t> displacement = guarded_read<std::int32_t>(displacement_address);
            if (!displacement)
            {
                return std::nullopt;
            }
            const std::uintptr_t next_instruction = match + static_cast<std::uintptr_t>(rip.instruction_length);
            const std::uintptr_t resolved =
                static_cast<std::uintptr_t>(static_cast<std::int64_t>(next_instruction) + *displacement);
            if (!is_plausible_ptr(resolved))
            {
                return std::nullopt;
            }
            return resolved;
        }
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_SHARED_HPP
