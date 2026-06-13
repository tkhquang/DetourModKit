#ifndef DETOURMODKIT_SCANNER_HPP
#define DETOURMODKIT_SCANNER_HPP

#include "DetourModKit/memory.hpp"

#include <array>
#include <vector>
#include <string>
#include <string_view>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <span>

namespace DetourModKit
{
    /**
     * @enum RipResolveError
     * @brief Error codes for RIP-relative resolution failures.
     */
    enum class RipResolveError
    {
        NullInput,
        PrefixNotFound,
        RegionTooSmall,
        UnreadableDisplacement,
        ImplausibleTarget
    };

    /**
     * @brief Converts a RipResolveError to a human-readable string.
     * @param error The error code.
     * @return A string view describing the error.
     */
    [[nodiscard]] constexpr std::string_view rip_resolve_error_to_string(RipResolveError error) noexcept
    {
        switch (error)
        {
        case RipResolveError::NullInput:
            return "Null input pointer";
        case RipResolveError::PrefixNotFound:
            return "Opcode prefix not found in search region";
        case RipResolveError::RegionTooSmall:
            return "Search region too small for prefix + displacement";
        case RipResolveError::UnreadableDisplacement:
            return "Displacement bytes at matched location are not readable";
        case RipResolveError::ImplausibleTarget:
            return "Resolved target is not a plausible user-mode address";
        default:
            return "Unknown RIP resolve error";
        }
    }

    namespace Scanner
    {
        /**
         * @struct CompiledPattern
         * @brief A pre-compiled AOB pattern with separate bytes and mask.
         * @details Stores the pattern bytes and a bitmask indicating which bytes are wildcards (mask=false) vs. literal
         *          values to match (mask=true). This design avoids sentinel byte conflicts (e.g., 0xCC is a valid
         *          byte).
         */
        struct CompiledPattern
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
             *          (memory_byte ^ @ref bytes) & mask == 0. 0xFF marks a fully-literal byte that must match exactly,
             *          0x00 marks a wildcard slot to skip, and 0xF0 / 0x0F mark a per-nibble wildcard (a high-nibble or
             *          low-nibble token such as "4?" or "?5") where only the masked nibble must match. Sized
             *          identically to @ref bytes.
             */
            std::vector<std::byte> mask;

            /**
             * @brief Byte offset from pattern start to the point of interest.
             * @details Set by the `|` marker in the AOB string, or 0 if absent.
             *          May equal bytes.size() when `|` appears at the end of the
             *          pattern. The offset is non-negative under the current
             *          parser (`|` cannot precede tokens), but the type is
             *          signed to match pointer-arithmetic conventions (C++ Core Guidelines ES.106) and to future-proof
             *          against negative anchors.
             */
            std::ptrdiff_t offset = 0;

            /**
             * @brief Cached anchor index selected by compile_anchor().
             * @details find_pattern() drives its memchr sweep on the byte at this position. The index is the rarest
             *          literal byte in the pattern (lowest score in a small frequency table tuned for typical x64 .text
             *          sections), so a single memchr pass produces far fewer false candidate hits than anchoring on
             *          `bytes[0]` would.
             *
             *          Sentinel values:
             *          - `[0, size())`            valid anchor.
             *          - `size()`                 pattern has no fully-known byte to anchor on (all wildcards, or only
             *                                     nibble constraints); scan degenerates to "match at start" for an
             *                                     all-wildcard pattern, or a masked compare at every position when only
             *                                     nibble constraints remain.
             *          - `>= size() + 1`          anchor not yet selected;
             *                                     find_pattern() will pick one inline (slower path).
             *
             *          parse_aob() always calls compile_anchor() before returning, so patterns produced through the
             *          public API enter find_pattern() with the cached anchor in place. Manually constructed patterns
             *          (assigning `bytes`/`mask` by hand) start in the "not yet selected" state and should call @ref
             *          compile_anchor() once after population if they will be scanned repeatedly.
             */
            std::size_t anchor = std::numeric_limits<std::size_t>::max();

            /**
             * @brief Returns the size of the pattern.
             * @return size_t The number of bytes in the pattern.
             */
            [[nodiscard]] size_t size() const noexcept { return bytes.size(); }

            /**
             * @brief Checks if the pattern is empty.
             * @return true if the pattern has no bytes.
             */
            [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }

            /**
             * @brief Selects and stores the rarest fully-known byte's index as the scan anchor.
             * @details Walks the pattern once, scoring each fully-known (mask 0xFF) byte against a small byte-frequency
             *          table (`0x00`, `0xCC`, `0x48`, ... receive high scores; uncommon bytes score 0), and stores the
             *          lowest-scoring index in @ref anchor. Partially-masked nibble bytes are skipped: the prefilter
             *          needs one exact byte value to scan for, which a nibble does not provide. Ties are broken by
             *          first occurrence for deterministic behaviour. A pattern with no fully-known byte sets @ref
             *          anchor to `size()`; find_pattern() then either takes the degenerate "match at region start" path
             *          (an all-wildcard pattern) or, when only nibble constraints remain, a masked compare at every
             *          position.
             *
             *          Safe to call repeatedly; the operation is idempotent and O(size()). Callers that mutate @ref
             *          bytes or @ref mask after a prior compile_anchor() MUST call it again before the next scan or the
             *          cached anchor will drift from the pattern contents.
             *
             *          Not thread-safe with concurrent find_pattern() calls on the same CompiledPattern instance;
             *          sequence the compile step before publishing the pattern to scanners.
             */
            void compile_anchor() noexcept;
        };

        /**
         * @brief Parses a space-separated AOB string into a compiled pattern.
         * @details Converts hexadecimal byte tokens (e.g. "48") to literal byte values, full-wildcard tokens ('??' or
         *          '?') to skip slots, and per-nibble tokens ("4?" with a known high nibble, "?5" with a known low
         *          nibble) to partially-masked bytes. An optional `|` token marks the offset within the pattern (stored
         *          in CompiledPattern::offset). This lets wider patterns precisely target a specific instruction: e.g.,
         *          "48 8B 88 B8 00 00 00 | 48 89 4C 24 68" sets offset=7, and "48 8B ?D" matches any ModRM byte whose
         *          low nibble is D.
         * @param aob_str The AOB pattern string.
         * @return std::optional<CompiledPattern> The compiled pattern, or std::nullopt on parse failure.
         */
        [[nodiscard]] std::optional<CompiledPattern> parse_aob(std::string_view aob_str);

        /**
         * @brief Scans a specified memory region for a given byte pattern.
         * @details Uses an optimized search algorithm that finds the first non-wildcard byte and uses memchr for fast
         *          skipping, then verifies the full pattern.
         * @param start_address Pointer to the beginning of the memory region to scan.
         * @param region_size The size (in bytes) of the memory region to scan.
         * @param pattern The compiled pattern to search for.
         * @return const std::byte* Pointer to the match within the specified region, already adjusted by
         *         `pattern.offset`. Returns nullptr if pattern not found.
         * @note A pattern with zero literal bytes (every token wildcarded) returns `start_address` (plus offset) and
         *       emits a warning through the shared
         *       Logger. This case almost always indicates a caller bug; the behaviour is preserved for backwards
         *       compatibility but should not be relied upon.
         * @note `pattern.offset` (set by a `|` marker in the AOB string) is applied
         *       exactly once. When no marker is present `offset == 0` and the returned pointer is the match start.
         *       Callers must NOT add `pattern.offset` manually; doing so double-applies and will miss the intended
         *       byte.
         * @warning When `pattern.offset == pattern.size()` (a trailing `|` marker),
         *          the returned pointer addresses one-past the matched range. Depending on where in the region the
         *          match landed, this may also be one-past the scanned region. The pointer is valid for arithmetic and
         *          bounds comparisons but MUST NOT be dereferenced without an explicit readability check (e.g.
         *          `Memory::is_readable`).
         * @warning READABLE-RANGE PRECONDITION: this raw overload performs no page filtering. The caller MUST guarantee
         *          the entire span `[start_address, start_address + region_size)` is committed and readable, because
         *          the search reads it with raw `memchr`/SIMD loads and an unreadable byte faults the host. Use it only
         *          on byte buffers or module sections whose readability is already known. To scan arbitrary process or
         *          module memory, prefer the page-gated helpers (`scan_executable_regions`, `scan_readable_regions`) or
         *          the module-scoped cascade (`resolve_cascade_in_module`) which walk `VirtualQuery` and skip guard,
         *          no-access, and non-readable pages.
         */
        [[nodiscard]] const std::byte *find_pattern(const std::byte *start_address, size_t region_size,
                                                    const CompiledPattern &pattern);

        /**
         * @brief std::span convenience overload of the single-occurrence raw scan.
         * @details Delegates to find_pattern(region.data(), region.size(), pattern). An empty span yields nullptr.
         *          Carries the same READABLE-RANGE PRECONDITION as the pointer+size overload: the entire span must be
         *          committed and readable, because the search uses raw memchr/SIMD loads.
         * @param region Contiguous, committed, readable byte span to scan.
         * @param pattern The compiled pattern to search for.
         * @return Pointer to the match within @p region (adjusted by pattern.offset), or nullptr if not found.
         */
        [[nodiscard]] inline const std::byte *find_pattern(std::span<const std::byte> region,
                                                           const CompiledPattern &pattern)
        {
            return find_pattern(region.data(), region.size(), pattern);
        }

        /**
         * @brief Scans a memory region for the Nth occurrence of a byte pattern.
         * @param start_address Pointer to the beginning of the memory region to scan.
         * @param region_size The size (in bytes) of the memory region to scan.
         * @param pattern The compiled pattern to search for.
         * @param occurrence Which occurrence to return (1-based). 1 = first match. Passing 0 returns nullptr.
         * @return const std::byte* Pointer to the Nth occurrence (already adjusted by `pattern.offset`), or nullptr if
         *         fewer than N matches exist.
         * @note Like the single-occurrence overload, `pattern.offset` is applied exactly once. Callers must NOT add it
         *       manually.
         * @warning A trailing `|` marker produces a one-past pointer identical in
         *          kind to the single-occurrence overload; do not dereference without a bounds or readability check.
         * @warning READABLE-RANGE PRECONDITION: like the single-occurrence overload, this raw overload performs no page
         *          filtering. The caller MUST guarantee the entire span `[start_address, start_address + region_size)`
         *          is committed and readable; the scan uses raw `memchr`/SIMD loads and an unreadable byte faults the
         *          host. For arbitrary process or module memory, prefer the page-gated helpers
         *          (`scan_executable_regions`, `scan_readable_regions`) or the module-scoped cascade
         *          (`resolve_cascade_in_module`).
         */
        [[nodiscard]] const std::byte *find_pattern(const std::byte *start_address, size_t region_size,
                                                    const CompiledPattern &pattern, size_t occurrence);

        /**
         * @brief std::span convenience overload of the Nth-occurrence raw scan.
         * @details Delegates to find_pattern(region.data(), region.size(), pattern, occurrence). Same READABLE-RANGE
         *          PRECONDITION as the pointer+size overload: the entire span must be committed and readable.
         * @param region Contiguous, committed, readable byte span to scan.
         * @param pattern The compiled pattern to search for.
         * @param occurrence Which occurrence to return (1-based). Passing 0 returns nullptr.
         * @return Pointer to the Nth occurrence (adjusted by pattern.offset), or nullptr if fewer than N matches.
         */
        [[nodiscard]] inline const std::byte *find_pattern(std::span<const std::byte> region,
                                                           const CompiledPattern &pattern, size_t occurrence)
        {
            return find_pattern(region.data(), region.size(), pattern, occurrence);
        }

        /// Common x86-64 RIP-relative opcode prefixes (bytes preceding the disp32 field).
        inline constexpr std::array<std::byte, 3> PREFIX_MOV_RAX_RIP = {std::byte{0x48}, std::byte{0x8B},
                                                                        std::byte{0x05}};
        inline constexpr std::array<std::byte, 3> PREFIX_MOV_RCX_RIP = {std::byte{0x48}, std::byte{0x8B},
                                                                        std::byte{0x0D}};
        inline constexpr std::array<std::byte, 3> PREFIX_MOV_RDX_RIP = {std::byte{0x48}, std::byte{0x8B},
                                                                        std::byte{0x15}};
        inline constexpr std::array<std::byte, 3> PREFIX_MOV_RBX_RIP = {std::byte{0x48}, std::byte{0x8B},
                                                                        std::byte{0x1D}};
        inline constexpr std::array<std::byte, 3> PREFIX_LEA_RAX_RIP = {std::byte{0x48}, std::byte{0x8D},
                                                                        std::byte{0x05}};
        inline constexpr std::array<std::byte, 3> PREFIX_LEA_RCX_RIP = {std::byte{0x48}, std::byte{0x8D},
                                                                        std::byte{0x0D}};
        inline constexpr std::array<std::byte, 3> PREFIX_LEA_RDX_RIP = {std::byte{0x48}, std::byte{0x8D},
                                                                        std::byte{0x15}};
        inline constexpr std::array<std::byte, 1> PREFIX_CALL_REL32 = {std::byte{0xE8}};
        inline constexpr std::array<std::byte, 1> PREFIX_JMP_REL32 = {std::byte{0xE9}};

        /**
         * @brief Resolves an absolute address from an x86-64 RIP-relative instruction.
         * @details Extracts the int32 displacement at the given offset within the instruction and computes the absolute
         *          target: instruction_address + instruction_length + displacement.
         * @param instruction_address Pointer to the first byte of the instruction.
         * @param displacement_offset Byte offset from instruction_address to the disp32 field.
         * @param instruction_length Total length of the instruction in bytes.
         * @return The resolved absolute address, or RipResolveError on failure.
         * @note The displacement is read under an SEH fault guard. A resolved address that is not a plausible user-mode
         *       pointer (a crafted or corrupt displacement that resolves to 0, a low guard-page address, or a
         *       kernel-range address) is rejected with
         *       RipResolveError::ImplausibleTarget rather than returned as a valid result. For `FF 15`/`FF 25` forms
         *       the gated value is the pointer slot, which is itself an in-image address.
         */
        [[nodiscard]] std::expected<uintptr_t, RipResolveError>
        resolve_rip_relative(const std::byte *instruction_address, size_t displacement_offset,
                             size_t instruction_length);

        /**
         * @brief Scans forward from a starting address for an opcode prefix, then resolves the RIP-relative target.
         * @details Searches up to search_length bytes for the given opcode prefix. Once found, the displacement is
         *          assumed to immediately follow the prefix. The absolute address is computed as: found_address +
         *          instruction_length + displacement.
         * @param search_start Pointer to the beginning of the search region.
         * @param search_length Maximum number of bytes to search forward.
         * @param opcode_prefix The opcode byte sequence to search for (disp32 must follow immediately).
         * @param instruction_length Total length of the instruction in bytes.
         * @return The resolved absolute address, or RipResolveError describing the failure.
         * @warning For indirect-call / indirect-jump forms (`FF 15 disp32`, `FF 25 disp32`) the returned address is the
         *          *pointer slot* (the address that stores the final target), not the target itself. Dereference it
         *          with `Memory::read_ptr_unsafe` (or an equivalent checked read) to obtain the callee / jump
         *          destination.
         * @note Matching is first-prefix-wins: the scan resolves the first location whose bytes equal @p opcode_prefix
         *       and does not detect whether the prefix occurs more than once. When a signature may be ambiguous, anchor
         *       it through @ref resolve_cascade (which enforces per-candidate uniqueness) instead. The resolved target
         *       is gated by the same RipResolveError::ImplausibleTarget check as @ref resolve_rip_relative.
         */
        [[nodiscard]] std::expected<uintptr_t, RipResolveError>
        find_and_resolve_rip_relative(const std::byte *search_start, size_t search_length,
                                      std::span<const std::byte> opcode_prefix, size_t instruction_length);

        /**
         * @brief Scans all committed executable memory regions for a byte pattern.
         * @details Walks the process address space via VirtualQuery, scanning each committed region with execute
         *          permission. Useful for games with packed or protected binaries that unpack code into anonymous pages
         *          outside any loaded module's address range.
         * @param pattern The compiled pattern to search for.
         * @param occurrence Which occurrence to return (1-based). 1 = first match.
         * @return Pointer to the match (adjusted by pattern offset), or nullptr if not found.
         * @note Pure-execute pages (`PAGE_EXECUTE` without any read bit) are skipped:
         *       they are not guaranteed readable and dereferencing them raises an access violation. Only
         *       `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, and `PAGE_EXECUTE_WRITECOPY` regions are inspected.
         *       Guard and no-access pages are skipped unconditionally.
         * @note `pattern.offset` is applied to the returned pointer, matching `find_pattern`. Callers must not add it
         *       manually.
         * @warning A trailing `|` marker (offset == pattern.size()) yields a
         *          one-past pointer; bounds-check before dereferencing.
         * @note A pattern that straddles the boundary between two adjacent accepted regions IS found: the sweep carries
         *       a `pattern_len - 1` byte overlap across the contiguous run of accepted (execute-readable) regions, so a
         *       signature split by a sibling VirtualProtect, or spanning two adjacent execute-readable VAD entries
         *       (JIT-compiled code from Mono / Unreal AngelScript, or heavily unpacked payloads), is still located. The
         *       overlap is capped at `pattern_len - 1` so an interior match is never re-counted. A straddle is missed
         *       only when the regions are not contiguous (a gap between them) or an interior region is unreadable,
         *       which breaks the run.
         */
        [[nodiscard]] const std::byte *scan_executable_regions(const CompiledPattern &pattern, size_t occurrence = 1);

        /**
         * @brief Scans all committed readable memory regions for a byte pattern.
         * @details Data-section sibling of scan_executable_regions. Walks the process address space via VirtualQuery
         *          and scans every committed region whose base protection is PAGE_READONLY, PAGE_READWRITE,
         *          PAGE_WRITECOPY, or one of the three execute-readable variants. This reaches .rdata / .data and
         *          read-only heaps: C++ vtables, RTTI type descriptors, localized string pools, and other read-only
         *          metadata that the executable-only sweep cannot see.
         * @param pattern The compiled pattern to search for.
         * @param occurrence Which occurrence to return (1-based). 1 = first match. Passing 0 returns nullptr.
         * @return Pointer to the match (adjusted by pattern offset), or nullptr if not found.
         * @note The accepted protection set is a strict superset of
         *       scan_executable_regions: execute-readable code pages are included,
         *       so a pattern present in .text is found by both. Callers that specifically want non-code matches must
         *       post-filter (e.g. against
         *       Memory::module_range_for).
         * @note Guard pages (PAGE_GUARD), no-access pages (PAGE_NOACCESS), and uncommitted regions are skipped: the
         *       first two fault on any touch and are never dereferenced.
         * @note `pattern.offset` is applied to the returned pointer, matching scan_executable_regions. Callers must not
         *       add it manually.
         * @note The compiled pattern's own `bytes` buffer is itself readable memory and would otherwise match the
         *       needle against itself. The scan excludes any match overlapping that buffer, so it never returns the
         *       caller's pattern storage. (scan_executable_regions is unaffected because that storage is not
         *       executable.)
         * @warning The readable address space is far larger than the executable subset (a typical x64 game process maps
         *          hundreds of MB of data versus tens of MB of code) and .rdata pointer tables look random, so a
         *          pattern unique in .text may collide in data. Supply patterns with enough literal bytes (>= 8) to
         *          keep the false-positive rate low. An RTTI mangled-name anchor is fully
         *          ASLR-invariant and far stronger than a raw vtable-header signature, whose relocated pointers vary
         *          per launch.
         * @warning A trailing `|` marker (offset == pattern.size()) yields a
         *          one-past pointer; bounds-check before dereferencing.
         * @note A pattern that straddles the boundary between two adjacent accepted regions IS found: the sweep carries
         *       a `pattern_len - 1` byte overlap across the contiguous run of accepted (readable) regions, capped so an
         *       interior match is never re-counted. A straddle is missed only across a gap between regions or an
         *       interior unreadable region that breaks the run.
         */
        [[nodiscard]] const std::byte *scan_readable_regions(const CompiledPattern &pattern, size_t occurrence = 1);

        /**
         * @enum ScannerKind
         * @brief Selects which whole-process scanner a cascade resolves against.
         */
        enum class ScannerKind : std::uint8_t
        {
            /// scan_executable_regions: committed execute-readable pages.
            Executable,
            /// scan_readable_regions: all committed readable pages (superset).
            Readable
        };

        /**
         * @struct BatchScanItem
         * @brief One pattern request in a parallel batch scan.
         * @details A plain-data request: a non-owning pointer to a caller-owned CompiledPattern plus the 1-based
         *          occurrence to resolve. @p pattern must outlive the batch call; a null @p pattern resolves to a
         *          nullptr result slot (fail closed).
         */
        struct BatchScanItem
        {
            /// Non-owning pointer to a caller-owned, compiled pattern. Must outlive the batch call.
            const CompiledPattern *pattern = nullptr;
            /// Which occurrence to resolve (1-based). 1 = first match. 0 yields a nullptr result.
            std::size_t occurrence = 1;
        };

        /**
         * @brief Concurrently resolves a batch of compiled patterns against the whole-process region set.
         * @details Opt-in fork-join sibling of scan_executable_regions / scan_readable_regions. Each item is scanned
         *          independently by exactly one worker through the same per-pattern region walk the serial scanners
         *          use, so a batch of N startup signatures resolves in roughly the time of the slowest single scan
         *          rather than their sum. Results are returned in input order: result[i] is item[i]'s offset-applied
         *          match, or nullptr when the item did not match, its @c pattern is null or empty, or its @c
         *          occurrence is 0.
         *
         *          Sharing is read-only: a fully compiled CompiledPattern is immutable during scanning (find_pattern
         *          and the region walk take it by const reference and never write back -- an un-anchored pattern
         *          recomputes its anchor into a local, it is not stored), so the workers share the caller's patterns
         *          without cloning. Compile every pattern (parse_aob calls compile_anchor()) before the batch; a
         *          pattern whose anchor is not yet selected still scans correctly but each worker redundantly
         *          recomputes it.
         *
         *          The driver allocates the result vector up front and hands each worker disjoint result slots through
         *          an atomic work cursor, so there is no result race and no allocation on the scan path. A worker that
         *          throws fails only its own item closed (nullptr); an exception never escapes a worker thread.
         * @param items The patterns to resolve. An empty span returns an empty vector.
         * @param kind Which whole-process scanner to use: ScannerKind::Executable (default, execute-readable pages) or
         *             ScannerKind::Readable (all committed readable pages).
         * @param max_workers Upper bound on worker threads. 0 (default) selects std::thread::hardware_concurrency(),
         *                    clamped to the item count. The calling thread participates, so at most @p max_workers
         *                    threads scan concurrently.
         * @return One pointer per input item, in input order (offset-applied match or nullptr).
         * @note Setup/control-plane only: spawns threads and allocates. Call from init or a worker thread, never from a
         *       hook or input callback, and never under the loader lock (it joins worker threads before returning).
         */
        [[nodiscard]] std::vector<const std::byte *> scan_regions_batch(std::span<const BatchScanItem> items,
                                                                        ScannerKind kind = ScannerKind::Executable,
                                                                        std::size_t max_workers = 0);

        /**
         * @brief Module-scoped parallel batch scan: confines every item to one mapped image.
         * @details Fork-join batch sibling of the module-scoped scanners. Each item is resolved only within
         *          [range.base, range.end), reusing the same per-region protection gate and TOCTOU fault guard as the
         *          serial module scans. Threading, result ordering, the immutable-pattern sharing contract, the
         *          per-item fail-closed behaviour, and the @p max_workers semantics match scan_regions_batch.
         * @param items The patterns to resolve. An empty span returns an empty vector.
         * @param range The mapped image to scan. An invalid range yields all-nullptr results (every item fails closed).
         * @param kind ScannerKind::Readable (default) scans every readable page so one pass covers .text and
         *             .rdata / .data candidates; ScannerKind::Executable confines matches to execute-readable code
         *             pages.
         * @param max_workers Upper bound on worker threads (see scan_regions_batch). 0 selects hardware_concurrency().
         * @return One pointer per input item, in input order (offset-applied match or nullptr).
         * @note Setup/control-plane only, same constraints as scan_regions_batch.
         */
        [[nodiscard]] std::vector<const std::byte *> scan_module_batch(std::span<const BatchScanItem> items,
                                                                       Memory::ModuleRange range,
                                                                       ScannerKind kind = ScannerKind::Readable,
                                                                       std::size_t max_workers = 0);

        /**
         * @enum ResolveMode
         * @brief How a cascade candidate's pattern maps to a final address.
         */
        enum class ResolveMode : std::uint8_t
        {
            /// Returned address = match + disp_offset.
            Direct,
            /// Read int32 displacement at (match + disp_offset), compute match + instr_end_offset + disp.
            RipRelative
        };

        /**
         * @struct AddrCandidate
         * @brief One ordered attempt in a cascade.
         * @details The cascade scans candidates in array order and returns the first successful resolution. @p name is
         *          echoed back in the
         *          ResolveHit on success so callers can log which candidate won -- useful when multiple patterns cover
         *          different game versions.
         */
        struct AddrCandidate
        {
            std::string_view name;
            std::string_view pattern;
            ResolveMode mode = ResolveMode::Direct;
            std::ptrdiff_t disp_offset = 0;
            std::ptrdiff_t instr_end_offset = 0;

            /**
             * @brief Require the candidate to match exactly once in the scanned scope; defaults to true. A second match
             *        makes the candidate ambiguous and it is skipped.
             * @details A cascade returns the first candidate that resolves, and a single scan returns the
             *          lowest-address match. A loose pattern that matches several functions would therefore win on
             *          whichever address sorts first -- usually not the intended one, and impossible to recover from
             *          after the fact (the resolver has already committed). Defaulting this to true makes the resolver
             *          count the candidate's matches within the scanned scope (the module image for the @c *_in_module
             *          resolvers, the whole process otherwise); if a second match exists the candidate falls through to
             *          the next one. That converts a silent wrong resolution into a clean fall-through, and -- when no
             *          candidate is provably unique -- a NoMatch the caller can act on (a signal that the target binary
             *          changed enough to need new signatures) rather than a confidently wrong hit.
             *
             *          Set this to false for a candidate that is deliberately non-unique and whose first match is the
             *          intended one (e.g. "first occurrence of a common instruction", or a last-resort broad net). The
             *          flag is per-candidate, so a strict primary anchor keeps the default while a broad fallback opts
             *          out. The uniqueness scan runs once per candidate that already matched; opt out to skip it.
             */
            bool require_unique = true;
        };

        /**
         * @enum ResolveError
         * @brief Reasons a cascade resolve may fail.
         */
        enum class ResolveError : std::uint8_t
        {
            EmptyCandidates,
            NoMatch,
            AllPatternsInvalid,
            PrologueFallbackNotApplicable,
            InvalidRange,
            DecodeFailed,
            UnexpectedShape,
            OperandOutOfRange
        };

        /**
         * @brief Human-readable mapping for ResolveError.
         */
        [[nodiscard]] constexpr std::string_view resolve_error_to_string(ResolveError error) noexcept
        {
            switch (error)
            {
            case ResolveError::EmptyCandidates:
                return "No candidates supplied";
            case ResolveError::NoMatch:
                return "No candidate pattern matched the scanned regions";
            case ResolveError::AllPatternsInvalid:
                return "Every candidate pattern failed to parse";
            case ResolveError::PrologueFallbackNotApplicable:
                return "Prologue fallback pattern too short to be unique";
            case ResolveError::InvalidRange:
                return "Supplied module range is invalid";
            case ResolveError::DecodeFailed:
                return "Instruction at the resolved site did not decode";
            case ResolveError::UnexpectedShape:
                return "Decoded operand is not the requested kind";
            case ResolveError::OperandOutOfRange:
                return "Operand index exceeds the instruction operand count";
            default:
                return "Unknown resolve error";
            }
        }

        /**
         * @struct ResolveHit
         * @brief Successful cascade outcome.
         * @details @p winning_name aliases the matching candidate's @c name field. The underlying storage must outlive
         *          the ResolveHit (AddrCandidate arrays typically live in static storage).
         */
        struct ResolveHit
        {
            std::uintptr_t address{0};
            std::string_view winning_name;
        };

        /**
         * @struct CascadeRequest
         * @brief One cascade resolver request in a parallel batch.
         * @details A plain-data request over caller-owned storage: @ref candidates and @ref label must outlive the
         *          batch call, and any successful @ref ResolveHit::winning_name aliases the winning candidate's @ref
         *          AddrCandidate::name. When @ref range is set the request uses the module-scoped cascade; when it is
         *          empty the whole-process cascade is used. @ref prologue_fallback selects the matching
         *          *_with_prologue_fallback resolver. @ref kind applies only to whole-process non-fallback requests;
         *          module-scoped and prologue-fallback requests keep their existing serial resolver semantics.
         */
        struct CascadeRequest
        {
            /// Ordered candidates for one target.
            std::span<const AddrCandidate> candidates;
            /// Human-readable identifier used in log messages.
            std::string_view label;
            /// Optional module image scope; std::nullopt selects the whole-process resolver.
            std::optional<Memory::ModuleRange> range = std::nullopt;
            /// Whole-process scanner kind for non-fallback requests.
            ScannerKind kind = ScannerKind::Executable;
            /// Enable the hooked-prologue recovery variant for this request.
            bool prologue_fallback = false;
        };

        /**
         * @brief Resolves independent cascade requests concurrently.
         * @details Fork-join resolver layer over resolve_cascade(), resolve_cascade_in_module(), and their
         *          prologue-fallback variants. Each request is resolved by exactly one worker through the existing
         *          serial resolver, preserving candidate order, first-success semantics, uniqueness checks, typed
         *          errors, and @ref ResolveHit::winning_name aliasing. Results are returned in input order.
         * @param requests Cascade requests to resolve. An empty span returns an empty vector.
         * @param max_workers Upper bound on concurrent workers. 0 selects std::thread::hardware_concurrency(), clamped
         *                    to the request count. The calling thread participates.
         * @return One expected result per input request, in input order.
         * @note Setup/control-plane only: spawns threads and allocates. Call from init or a worker thread, never from a
         *       hook or input callback, and never under the loader lock.
         */
        [[nodiscard]] std::vector<std::expected<ResolveHit, ResolveError>>
        resolve_cascade_batch(std::span<const CascadeRequest> requests, std::size_t max_workers = 0);

        /**
         * @brief Try candidates in order; return the first successful address.
         * @details Each candidate's pattern is compiled via parse_aob() and searched via the scanner selected by @p
         *          kind:
         *          scan_executable_regions() for ScannerKind::Executable (the default) or scan_readable_regions() for
         *          ScannerKind::Readable when the target lives in .rdata / .data. Direct mode returns @c match +
         *          disp_offset. RipRelative mode treats @c match + disp_offset as a disp32 field and resolves against
         *          @c match + instr_end_offset. On success, the winning candidate's name is logged and returned.
         *
         *          Logging:
         *          - Debug on first success: "<label> resolved via '<name>' at 0x...".
         *          - Warning per candidate whose pattern fails to parse.
         *          - Warning on total failure.
         *
         *          The success line is Debug-level, consistent with the other resolution diagnostics, so it stays
         *          silent at the default
         *          Info threshold; raise the log level to Debug to surface it for build identification. No
         *          per-candidate "miss" line is produced, so even a long cascade stays quiet at Info and above. The
         *          implementation does not log again when resolve_cascade_with_prologue_fallback() retries, so exactly
         *          one success line is emitted per resolve.
         *
         * @param candidates Ordered list of candidates. Empty -> EmptyCandidates.
         * @param label Human-readable identifier used in log messages.
         * @param kind Which scanner to search with. Defaults to
         *             ScannerKind::Executable so existing call sites are unchanged; pass ScannerKind::Readable for
         *             data-section targets.
         * @return ResolveHit on success; ResolveError on failure.
         */
        [[nodiscard]] std::expected<ResolveHit, ResolveError>
        resolve_cascade(std::span<const AddrCandidate> candidates, std::string_view label,
                        ScannerKind kind = ScannerKind::Executable);

        /**
         * @brief Cascade resolver with inline-hooked-prologue recovery.
         * @details Equivalent to resolve_cascade() on the happy path. If every candidate fails, rebuilds each
         *          Direct-mode candidate's pattern with the patched prologue replaced by a jump shape and retries. Two
         *          shapes are tried in order: the 5-byte `E9 ?? ?? ?? ??` near jump (SafetyHook and other rel32 inline
         *          detours) and the 6-byte `FF 25 ?? ?? ?? ??` RIP-relative indirect jump a detour emits when its
         *          trampoline is beyond rel32 reach (a Detours-style far jump). The recovered jump destination is gated
         *          as a plausible, executable address before acceptance. If the recovery path succeeds the log line
         *          calls this out explicitly.
         *
         *          RipRelative candidates are skipped in the fallback phase since they target instructions deeper than
         *          the patched prologue and are unaffected by the overwrite.
         *
         * @note Recovery covers only the E9 near-jump and FF25 indirect-jump trampoline shapes. A prologue
         *       overwritten by another inline-hook style (a push imm32 / ret thunk, an FF15 call thunk, or a jump
         *       carrying a REX or segment prefix) is not decoded, so the request fails closed as an ordinary NoMatch
         *       rather than recovering a wrong address. Callers needing interop with such foreign hooks resolve by
         *       other means.
         * @param candidates Ordered candidates.
         * @param label Human-readable identifier used in log messages.
         * @return ResolveHit on success; ResolveError on failure.
         */
        [[nodiscard]] std::expected<ResolveHit, ResolveError>
        resolve_cascade_with_prologue_fallback(std::span<const AddrCandidate> candidates, std::string_view label);

        /**
         * @brief Module-scoped cascade: like resolve_cascade(), but searches only the mapped image [range.base,
         *        range.end) and rejects any resolution that lands outside it.
         * @details A whole-process scan (resolve_cascade) returns the first candidate that matches anywhere in the
         *          address space. For an unpacked PE whose every hook target lives inside one module that is unsafe: a
         *          generic-shaped candidate (a stock compiler prologue, a `mov reg,[rip]; ...; ret` epilogue) can
         *          false-match inside another injected module (a graphics overlay, a sibling mod). Because the cascade
         *          is first-match-wins, the wrong match is returned and shadows the correct in-module one; a caller's
         *          post-resolution bounds check cannot undo it, since the cascade has already committed to the
         *          colliding candidate.
         *
         *          This overload moves the scope and bounds decision inside the cascade loop. A candidate wins only
         *          when it (1) parses, (2) matches via a scan confined to [range.base, range.end), and (3) resolves
         *          (Direct walk or RipRelative disp read) to an address for which Memory::contains(range, addr) is
         *          true. Any failure at any step falls through to the next candidate, so a
         *          P1 that resolves out of module yields to the in-module P2/P3.
         *
         *          One scan of the contiguous image covers both .text and
         *          .rdata / .data candidates, so there is no ScannerKind
         *          parameter: the section split that ScannerKind selects for
         *          whole-process sweeps is moot inside a single mapped PE. The scan reuses the same per-region
         *          protection filter as the whole-process scanners, so a non-readable interior page (a
         *          section-alignment gap, a guard page, a sibling VirtualProtect) is skipped rather than dereferenced.
         *
         * @param candidates Ordered list of candidates. Empty -> EmptyCandidates.
         * @param label Human-readable identifier used in log messages.
         * @param range The mapped image to scan, e.g. from
         *              Memory::module_range_for(), Memory::own_module_range(), or an explicit {base, base +
         *              SizeOfImage}.
         * @return ResolveHit on success; ResolveError on failure. An invalid @p range returns
         *         ResolveError::InvalidRange and never falls back to a whole-process scan.
         * @note Memory::contains gates reachability, not section identity: a
         *       RipRelative candidate resolving into .rdata / .data inside the image is accepted. Direct candidates
         *       that must land on code should still be paired with is_likely_function_prologue().
         * @pre @p range must describe a single contiguous mapped image. Do not use this overload for packed or
         *      protected targets whose code is unpacked into separate VirtualAlloc regions outside the module image;
         *      use resolve_cascade() for those.
         */
        [[nodiscard]] std::expected<ResolveHit, ResolveError>
        resolve_cascade_in_module(std::span<const AddrCandidate> candidates, std::string_view label,
                                  Memory::ModuleRange range);

        /**
         * @brief Module-scoped variant of resolve_cascade_with_prologue_fallback().
         * @details Equivalent to resolve_cascade_in_module() on the happy path. If every candidate fails, it rebuilds
         *          each Direct-mode candidate's prologue as `E9 ?? ?? ?? ??` plus the original literal tail and
         *          retries, confining both the uniqueness count and the match to
         *          [range.base, range.end). The fallback scan is restricted to the image's executable pages: a hooked
         *          near-JMP overwrites a code prologue, never data, so a match in .rdata / .data would be a false
         *          positive (the data-capable readable sweep is only used for the primary candidate pass).
         *
         *          The rebuilt near-JMP must be found inside @p range, but its jump destination is intentionally not
         *          constrained to @p range or to any loaded module. When a sibling mod inline-hooks the target, its E9
         *          usually jumps to a VirtualAlloc'd trampoline outside every image, so the destination is validated as
         *          a plausible pointer on a committed, execute-readable page instead. This still rejects jumps into
         *          unmapped or data-only memory without rejecting the recovery this path exists to perform.
         *
         * @param candidates Ordered candidates.
         * @param label Human-readable identifier used in log messages.
         * @param range The mapped image to scan.
         * @return ResolveHit on success; ResolveError on failure. An invalid @p range returns
         *         ResolveError::InvalidRange.
         */
        [[nodiscard]] std::expected<ResolveHit, ResolveError>
        resolve_cascade_in_module_with_prologue_fallback(std::span<const AddrCandidate> candidates,
                                                         std::string_view label, Memory::ModuleRange range);

        /**
         * @brief Convenience: resolve_cascade_in_module() scoped to the host EXE.
         * @details Forwards to resolve_cascade_in_module() with the range of the process's main executable image
         *          (Memory::host_module_range()). This is the overwhelmingly common scope for an injected ASI whose
         *          target code lives in the game's own EXE, and it removes the boilerplate of building the range at
         *          every call site.
         * @warning Use this ONLY when the host executable is the image that holds the target code. For a game whose
         *          logic lives in a separate module (for example an engine DLL loaded by a thin launcher
         *          EXE), resolve that module's range explicitly and call resolve_cascade_in_module(): the host EXE then
         *          holds none of the target code, so host-scoping would scan the wrong image.
         * @param candidates Ordered candidates.
         * @param label Human-readable identifier used in log messages.
         * @return ResolveHit on success; ResolveError on failure. If the host module range cannot be determined the
         *         result is
         *         ResolveError::InvalidRange.
         */
        [[nodiscard]] std::expected<ResolveHit, ResolveError>
        resolve_cascade_in_host_module(std::span<const AddrCandidate> candidates, std::string_view label);

        /**
         * @brief Host-EXE-scoped variant of resolve_cascade_in_module_with_prologue_fallback().
         * @details Forwards to resolve_cascade_in_module_with_prologue_fallback() with Memory::host_module_range().
         *          Same host-scope caveat as resolve_cascade_in_host_module() applies.
         * @param candidates Ordered candidates.
         * @param label Human-readable identifier used in log messages.
         * @return ResolveHit on success; ResolveError on failure. If the host module range cannot be determined the
         *         result is
         *         ResolveError::InvalidRange.
         */
        [[nodiscard]] std::expected<ResolveHit, ResolveError>
        resolve_cascade_in_host_module_with_prologue_fallback(std::span<const AddrCandidate> candidates,
                                                              std::string_view label);

        /**
         * @enum OperandKind
         * @brief Which operand field @ref read_code_constant extracts.
         */
        enum class OperandKind : std::uint8_t
        {
            /// An immediate operand (e.g. the imm of `add reg, imm`).
            Immediate,
            /// A memory operand's displacement (e.g. the disp of `[reg + disp]`).
            MemoryDisplacement
        };

        /**
         * @struct CodeConstant
         * @brief Declares a constant encoded in the engine's machine code so DMK can re-derive it after a patch instead
         *        of hard-coding it.
         * @details The code-side twin of the RTTI self-heal: where a struct stride or field displacement is an
         *          immediate or `[reg + disp]` in a dispatch loop, declare the AOB-resolved instruction site plus which
         *          operand to read, and @ref read_code_constant decodes the live instruction and returns the current
         *          value. A consumer stops hand-reading the immediate every patch.
         */
        struct CodeConstant
        {
            /// AOB cascade that lands ON the instruction (a Direct candidate, disp_offset 0).
            std::span<const AddrCandidate> site;
            /// Which operand field to read: an immediate or a memory displacement.
            OperandKind kind = OperandKind::Immediate;
            /// Index into the instruction's VISIBLE operands, as counted in a disassembler.
            std::uint8_t operand_index = 0;
            /// 0 returns Zydis's already-sign-extended value; > 0 narrows to this many bytes then re-sign-extends.
            std::uint8_t byte_width = 0;
            /// Last-known value, for telemetry/baseline ONLY; never returned in place of a live decode.
            std::int64_t nominal = 0;
            /// Set true to make @ref nominal meaningful (do not overload nominal == 0 as "unset").
            bool has_nominal = false;
        };

        /**
         * @brief Resolves @p cc.site, decodes the instruction there, and returns the requested operand's current value.
         * @details Always decodes and returns the live operand (sign-extended);
         *          @c cc.nominal is never a short-circuit, so a same-shape / different-value drift (e.g. a stride 232
         *          -> 240) is reported as the new value, which is the whole point. Self-validating and
         *          fail-closed: a site that no longer decodes, or whose requested
         *          operand is the wrong kind or out of range, returns a typed error rather than a guess. A RIP-relative
         *          memory operand is resolved to its absolute target (so the return is an absolute address in that
         *          case); other relative forms are reported as a value as-is.
         * @param cc The code-constant declaration.
         * @param range Module image to resolve the site in. Defaults to the host EXE.
         * @return The decoded value, or:
         *         - any @ref ResolveError from resolving @c cc.site (EmptyCandidates,
         *           NoMatch, InvalidRange, ...);
         *         - @ref ResolveError::DecodeFailed if the site does not decode;
         *         - @ref ResolveError::OperandOutOfRange if @c operand_index is past
         *           the visible operand count;
         *         - @ref ResolveError::UnexpectedShape if the operand is not the
         *           requested @c kind (or a memory operand carries no displacement).
         */
        [[nodiscard]] std::expected<std::int64_t, ResolveError>
        read_code_constant(const CodeConstant &cc, Memory::ModuleRange range = Memory::host_module_range());

        /**
         * @enum StringEncoding
         * @brief Byte encoding of an anchor string as it is stored in the image.
         */
        enum class StringEncoding : std::uint8_t
        {
            /// One byte per character (char / std::string literals).
            Utf8,
            /// Two bytes per character, little-endian (wchar_t / L"" on Windows).
            Utf16le
        };

        /**
         * @enum XrefReturn
         * @brief What a resolved string cross-reference returns.
         */
        enum class XrefReturn : std::uint8_t
        {
            /// Exact address of the instruction that loads the string.
            ReferencingInstruction,
            /// Best-effort prologue back-scan from the instruction (heuristic).
            EnclosingFunction,
            /**
             * @brief Address of the global data slot a `mov [rip+slot], reg` stores the loaded string pointer into.
             * @details Applies when the unique reference is a `lea reg, [rip+string]` shortly followed by that store.
             *          Resolves a cached global string pointer rather than the load site. Reports @ref
             *          StringXrefError::StoreNotFound when no such store follows the reference.
             */
            StringPointerSlot
        };

        /**
         * @enum StringXrefError
         * @brief Typed failure of @ref find_string_xref. Fail-closed, like @ref RipResolveError.
         */
        enum class StringXrefError : std::uint8_t
        {
            /// The query text was empty.
            EmptyQuery,
            /// @p range was not a valid mapped image.
            InvalidRange,
            /// The string bytes were not found in any readable page of the image.
            StringNotFound,
            /// The string occurs more than once (linker-pooled or repeated).
            StringAmbiguous,
            /// No recognized RIP-relative reference in the image resolves to the string.
            NoReference,
            /// More than one instruction references the string.
            AmbiguousReference,
            /// EnclosingFunction mode: no prologue within the back-scan window.
            FunctionNotFound,
            /// StringPointerSlot mode: no `mov [rip+slot], reg` store of the loaded pointer follows the reference.
            StoreNotFound
        };

        /**
         * @brief Converts a StringXrefError to a human-readable string.
         * @param error The error code.
         * @return A string view describing the error.
         */
        [[nodiscard]] constexpr std::string_view string_xref_error_to_string(StringXrefError error) noexcept
        {
            switch (error)
            {
            case StringXrefError::EmptyQuery:
                return "Query text was empty";
            case StringXrefError::InvalidRange:
                return "Module range is not a valid mapped image";
            case StringXrefError::StringNotFound:
                return "String bytes not found in the image";
            case StringXrefError::StringAmbiguous:
                return "String occurs more than once in the image";
            case StringXrefError::NoReference:
                return "No instruction references the string";
            case StringXrefError::AmbiguousReference:
                return "More than one instruction references the string";
            case StringXrefError::FunctionNotFound:
                return "No enclosing function prologue found in the back-scan window";
            case StringXrefError::StoreNotFound:
                return "No store of the loaded string pointer into a global slot follows the reference";
            default:
                return "Unknown string xref error";
            }
        }

        /**
         * @struct StringRefQuery
         * @brief A string-reference anchor query.
         * @details Anchors a target on an immutable string literal in the image's read-only data, then resolves the
         *          unique RIP-relative reference to it. Strings survive game updates far better than the code bytes
         *          around them, so a string xref is the most update-resilient anchor source. @ref text is a non-owning
         *          view into caller storage (a static table), matching the @ref AddrCandidate / @ref Rtti::Landmark
         *          style.
         */
        struct StringRefQuery
        {
            /// Literal content (no quotes).
            std::string_view text;
            /// How it is stored in the image.
            StringEncoding encoding = StringEncoding::Utf8;
            /**
             * @brief Match a trailing NUL so a prefix of a longer literal is not matched (e.g. "Player" inside
             *        "PlayerController").
             */
            bool require_terminator = true;
            /// Selects the exact instruction site, the enclosing function heuristic, or the cached global pointer slot.
            XrefReturn return_mode = XrefReturn::ReferencingInstruction;
            /**
             * @brief Selects the phase-2 reference scan.
             * @details false (default) runs the fast, desync-immune all-offset shape scan that recognizes only the
             *          REX.W `lea`/`mov reg, [rip+disp32]` forms. true keeps that scan and also runs a Zydis-verified
             *          linear sweep that recognizes the rarer RIP-relative reference shapes (`cmp [rip+d], imm`, `push
             *          [rip+d]`, a no-REX `lea`/`mov`, ...), at the cost of a full decode per instruction. Both scans
             *          apply the same exact-target and single-reference uniqueness guards, so broad mode adds coverage
             *          without relaxing fail-closed behaviour.
             */
            bool broad_match = false;
        };

        /**
         * @brief Resolves a string-reference anchor inside one mapped image.
         * @details Two fail-closed phases. Phase 1 locates the single occurrence of @p query.text in the image's
         *          readable pages (zero ->
         *          StringNotFound, more than one -> StringAmbiguous; the linker pools identical literals, so a
         *          non-unique string is genuinely ambiguous). Phase 2 scans the image's execute-readable pages for the
         *          single RIP-relative reference whose resolved absolute target is that string (zero -> NoReference,
         *          more than one ->
         *          AmbiguousReference). A reference counts only when its resolved target exactly equals the located
         *          string address, which is itself a plausible in-image pointer, so the equality subsumes the @ref
         *          Memory::plausible_userspace_ptr floor that @ref resolve_rip_relative applies, without a separate
         *          check. The xref is RIP-relative, so the result is ASLR-correct by construction (no fixed address is
         *          baked in).
         * @param query The string and how to interpret the reference.
         * @param range Module image to search. Defaults to the host EXE.
         * @return The referencing instruction (or enclosing function) address, or a StringXrefError.
         * @note By default phase 2 recognizes the dominant 64-bit string-load forms: REX.W `lea`/`mov reg,
         *       [rip+disp32]` (opcodes 8D / 8B with a RIP ModRM). Set @ref StringRefQuery::broad_match to keep that
         *       all-offset shape scan and additionally recognize the rarer RIP-relative shapes (`cmp [rip+d], imm`,
         *       `push [rip+d]`, a no-REX `lea`/`mov`) via a Zydis-verified sweep. Either way, a shape the active scans
         *       do not model reports NoReference rather than a guess.
         * @note XrefReturn::StringPointerSlot requires the unique reference to be a REX.W `lea reg, [rip+string]` and
         *       returns the effective address of the global slot the first `mov [rip+slot], reg` (same source register)
         *       within a bounded forward window stores the loaded pointer into. It resolves a cached global string
         *       pointer rather than the load site. A `mov reg, [rip+string]` load, a broad-only reference, or no
         *       matching store reports StoreNotFound. The store match is first-within-window (compilers emit it next
         *       to the load), not uniqueness-checked, and intervening reuse of the register is not modelled.
         * @note Choose a string referenced exactly once (a long, specific literal such as a format or assert message);
         *       short, common strings are pooled and shared and will report StringAmbiguous / AmbiguousReference.
         * @note StringEncoding::Utf16le widens each query byte to a little-endian 16-bit code unit (the byte
         *       followed by 0x00), treating query bytes as Latin-1 code units; this covers the ASCII identifiers
         *       anchor strings almost always are. Multi-byte UTF-8 sequences are widened byte by byte, so non-ASCII
         *       text never matches its true UTF-16LE encoding and in practice reports StringNotFound.
         * @warning XrefReturn::EnclosingFunction is a bounded heuristic prologue back-scan, not control-flow analysis;
         *          prefer the default ReferencingInstruction when an exact site is acceptable.
         */
        [[nodiscard]] std::expected<std::uintptr_t, StringXrefError>
        find_string_xref(const StringRefQuery &query, Memory::ModuleRange range = Memory::host_module_range());

        /**
         * @brief Cheap heuristic: does @p addr look like the first byte of a real function body?
         * @details Reads exactly one byte from @p addr under an SEH fault guard (Memory::seh_read) and rejects a small
         *          blacklist of bytes that are never the first opcode of a callable x86-64 function:
         *
         *          - 0x00       uninitialised page / zero-fill BSS / NULL page
         *          - 0xCC       int3 breakpoint / alignment pad / debugger trap
         *          - 0xC2 0xC3  bare RET (stub, not a callable body)
         *
         *          Returns true for every other byte, including 0xE9 / 0xEB / the 0xFF 0x25 prefix of an indirect JMP,
         *          so a target whose prologue has already been overwritten by SafetyHook or MinHook still passes -- the
         *          resolver must succeed for nested-hook scenarios.
         *
         *          This is the negative complement to resolve_cascade_with_prologue_fallback(), which is a positive
         *          recovery (rebuild the hooked-prologue pattern and retry). Both can be used together: the cascade
         *          resolves the target, then this helper filters scan poison if the AOB happened to land on a zero page
         *          or an alignment pad.
         *
         * @param addr Absolute address to probe. @p addr == 0 returns false without reading memory. An unreadable
         *             address returns false (the byte could not be read, so the answer is "not a prologue").
         * @return true if the byte at @p addr is not on the poison list and was readable; false otherwise.
         */
        [[nodiscard]] bool is_likely_function_prologue(std::uintptr_t addr) noexcept;

        /**
         * @enum SimdLevel
         * @brief Reports the highest SIMD tier available for pattern verification.
         */
        enum class SimdLevel
        {
            /// No SIMD (byte-by-byte verification)
            Scalar,
            /// SSE2 (16 bytes per iteration)
            Sse2,
            /// AVX2 (32 bytes per iteration, with SSE2 + scalar tail)
            Avx2,
            /// AVX-512F + AVX-512BW (64 bytes/iteration). Opt-in: DMK_ENABLE_AVX512 build on an AVX-512 host.
            Avx512
        };

        /**
         * @brief Returns the SIMD tier that find_pattern() will use at runtime.
         * @details Reflects both compile-time support (intrinsics available) and runtime CPU detection (CPUID + OS
         *          XGETBV). Reports SimdLevel::Avx512 only when the library was built with the opt-in DMK_ENABLE_AVX512
         *          option and the host has AVX-512F + AVX-512BW; otherwise it reports the highest available lower tier
         *          (AVX2, then SSE2, then Scalar).
         */
        [[nodiscard]] SimdLevel active_simd_level() noexcept;

    } // namespace Scanner
} // namespace DetourModKit

#endif // DETOURMODKIT_SCANNER_HPP
