#ifndef DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP
#define DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP

/**
 * @file internal/scan_engine.hpp
 * @brief True-private raw AOB matching engine: the compiled-pattern representation, the rarest-byte anchor selector,
 *        the memchr-prefiltered SIMD match loop, and the runtime SIMD-tier report.
 * @details This header is never installed. It owns the heap-backed engine vocabulary the public scan module builds on:
 *          EnginePattern (the heap-backed compiled byte/mask representation), parse_aob (string -> EnginePattern), the raw
 *          find_pattern matcher (single + Nth occurrence) with its SSE2 / AVX2 / AVX-512 verify tiers, and
 *          active_simd_level(). The public scan::Pattern is converted to an EnginePattern through
 *          engine_pattern_from() so the matcher sees one representation regardless of whether the pattern came from a
 *          DSL string or the value-semantic Pattern.
 */

#include "DetourModKit/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct EnginePattern
         * @brief A heap-backed compiled AOB pattern with separate bytes and mask, plus a cached scan anchor.
         * @details The heap-backed compiled engine pattern. Stores the pattern bytes and a
         *          per-byte mask: a position passes when (memory_byte ^ bytes) & mask == 0, so 0xFF marks a fully
         *          literal byte, 0x00 a wildcard, and 0xF0 / 0x0F a per-nibble token. @ref offset is the `|` result
         *          marker (0 when absent). @ref anchor is the rarest fully-known byte the memchr prefilter sweeps for.
         */
        struct EnginePattern
        {
            /**
             * @brief Pattern bytes, one per token in the source AOB string.
             * @details Each entry is pre-masked to its known bits: a wildcard position (mask 0x00) holds 0, and a
             *          partially-masked nibble position holds its known nibble with the wildcard nibble zeroed. A plain
             *          (memory_byte ^ bytes) & mask compare is therefore correct at every position without
             *          special-casing the wildcard slots.
             */
            std::vector<std::byte> bytes;

            /**
             * @brief Per-byte match mask paralleling @ref bytes.
             * @details The mask selects which bits of each byte must match: a position passes when
             *          (memory_byte ^ @ref bytes) & mask == 0. 0xFF marks a fully-literal byte, 0x00 a wildcard slot,
             *          and 0xF0 / 0x0F a per-nibble wildcard. Sized identically to @ref bytes.
             */
            std::vector<std::byte> mask;

            /**
             * @brief Byte offset from pattern start to the point of interest.
             * @details Set by the `|` marker in the AOB string, or 0 if absent. May equal bytes.size() when `|` appears
             *          at the end of the pattern. Signed to match pointer-arithmetic conventions.
             */
            std::ptrdiff_t offset = 0;

            /**
             * @brief Cached anchor index selected by compile_anchor().
             * @details find_pattern() drives its memchr sweep on the byte at this position: the rarest literal byte in
             *          the pattern, so a single memchr pass produces far fewer false candidate hits than anchoring on
             *          bytes[0].
             *
             *          Sentinel values:
             *          - `[0, size())`   valid anchor.
             *          - `size()`        pattern has no fully-known byte to anchor on (all wildcards, or only nibble
             *                            constraints); the scan degenerates accordingly.
             *          - `>= size() + 1` anchor not yet selected; find_pattern() picks one inline (slower path).
             */
            std::size_t anchor = std::numeric_limits<std::size_t>::max();

            /// Returns the size of the pattern (number of bytes).
            [[nodiscard]] std::size_t size() const noexcept { return bytes.size(); }

            /// Checks if the pattern has no bytes.
            [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }

            /**
             * @brief Selects and stores the rarest fully-known byte's index as the scan anchor.
             * @details Walks the pattern once, scoring each fully-known (mask 0xFF) byte against a small byte-frequency
             *          table (common opcodes / padding score high; uncommon bytes score 0), and stores the
             *          lowest-scoring index in @ref anchor. Partially-masked nibble bytes are skipped: the prefilter
             *          needs one exact byte value, which a nibble does not provide. Ties break by first occurrence. A
             *          pattern with no fully-known byte sets @ref anchor to size(). Idempotent and O(size()). Callers
             *          that mutate @ref bytes or @ref mask afterwards MUST call it again before the next scan or the
             *          cached anchor drifts. Not thread-safe with concurrent find_pattern() on the same instance.
             */
            void compile_anchor() noexcept;
        };

        /**
         * @brief Parses a space-separated AOB string into a compiled EnginePattern.
         * @details Converts hex byte tokens (e.g. "48") to literal bytes, full-wildcard tokens ('??' or '?') to skip
         *          slots, and per-nibble tokens ("4?" / "?5") to partially-masked bytes. An optional `|` token marks
         *          the offset within the pattern. The rarest-byte anchor is computed before returning.
         * @param aob_str The AOB pattern string.
         * @return The compiled pattern, or std::nullopt on parse failure (empty, malformed token, or duplicate offset).
         */
        [[nodiscard]] std::optional<EnginePattern> parse_aob(std::string_view aob_str);

        /**
         * @brief Builds an EnginePattern from a public value-semantic scan::Pattern.
         * @param pattern The compiled value Pattern.
         * @param anchor_index The position the scan should prefilter on, already translated to the engine sentinel
         *                      convention (anchor == size() means "no fully-known byte").
         * @return The heap-backed engine pattern. Allocates two small vectors, so callers on a noexcept path guard this
         *         against std::bad_alloc.
         */
        [[nodiscard]] EnginePattern engine_pattern_from(const scan::Pattern &pattern, std::size_t anchor_index);

        /**
         * @brief Scans a readable memory region for the first occurrence of a byte pattern.
         * @details Optimized search: finds the rarest non-wildcard byte and uses memchr for fast skipping, then
         * verifies
         *          the full pattern with the widest available SIMD tier.
         * @param start_address Pointer to the beginning of the region to scan.
         * @param region_size The size in bytes of the region to scan.
         * @param pattern The compiled pattern.
         * @return Pointer to the match (adjusted by pattern.offset), or nullptr if not found.
         * @warning READABLE-RANGE PRECONDITION: this raw matcher performs no page filtering. The caller MUST guarantee
         *          the entire span is committed and readable; the search reads it with raw memchr/SIMD loads.
         */
        [[nodiscard]] const std::byte *find_pattern(const std::byte *start_address, std::size_t region_size,
                                                    const EnginePattern &pattern);

        /**
         * @brief Scans a readable region for the Nth occurrence of a byte pattern.
         * @param start_address Pointer to the beginning of the region to scan.
         * @param region_size The size in bytes of the region to scan.
         * @param pattern The compiled pattern.
         * @param occurrence Which occurrence to return (1-based). Passing 0 returns nullptr.
         * @return Pointer to the Nth occurrence (adjusted by pattern.offset), or nullptr if fewer than N matches exist.
         * @warning Same READABLE-RANGE PRECONDITION as the single-occurrence overload.
         */
        [[nodiscard]] const std::byte *find_pattern(const std::byte *start_address, std::size_t region_size,
                                                    const EnginePattern &pattern, std::size_t occurrence);

        /// Span convenience over the pointer+size single-occurrence matcher (same READABLE-RANGE precondition).
        [[nodiscard]] inline const std::byte *find_pattern(std::span<const std::byte> region,
                                                           const EnginePattern &pattern)
        {
            return find_pattern(region.data(), region.size(), pattern);
        }

        /// Span convenience over the pointer+size Nth-occurrence matcher (same READABLE-RANGE precondition).
        [[nodiscard]] inline const std::byte *find_pattern(std::span<const std::byte> region,
                                                           const EnginePattern &pattern, std::size_t occurrence)
        {
            return find_pattern(region.data(), region.size(), pattern, occurrence);
        }

        /**
         * @brief Internal raw scan primitive: returns the match start WITHOUT applying pattern.offset.
         * @details The page-walking sweeps and the Nth-occurrence loop call this directly so the final
         *          `+ pattern.offset` applies exactly once.
         */
        [[nodiscard]] const std::byte *find_pattern_raw(const std::byte *start_address, std::size_t region_size,
                                                        const EnginePattern &pattern) noexcept;

        /**
         * @brief True when @p pattern carries at least one literal (non-wildcard) byte.
         * @details Shared guard for the "all wildcards matches anywhere" degenerate case the page sweeps screen for.
         */
        [[nodiscard]] bool pattern_has_literal_byte(const EnginePattern &pattern) noexcept;

        /**
         * @brief Reports the SIMD tier find_pattern matching uses at runtime.
         * @details Reflects compile-time support (which intrinsics were built) and runtime CPU detection (CPUID + OS
         *          XGETBV). Reports Avx512 only on a DMK_ENABLE_AVX512 build on an AVX-512F + AVX-512BW host; otherwise
         *          the highest available lower tier.
         */
        [[nodiscard]] scan::SimdLevel active_simd_level() noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_ENGINE_HPP
