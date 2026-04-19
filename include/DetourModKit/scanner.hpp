#ifndef DETOURMODKIT_SCANNER_HPP
#define DETOURMODKIT_SCANNER_HPP

#include <array>
#include <vector>
#include <string>
#include <string_view>
#include <cstddef>
#include <cstdint>
#include <expected>
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
        UnreadableDisplacement
    };

    /**
     * @brief Converts a RipResolveError to a human-readable string.
     * @param error The error code.
     * @return A string view describing the error.
     */
    constexpr std::string_view rip_resolve_error_to_string(RipResolveError error) noexcept
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
        default:
            return "Unknown RIP resolve error";
        }
    }

    namespace Scanner
    {
        /**
         * @struct CompiledPattern
         * @brief A pre-compiled AOB pattern with separate bytes and mask.
         * @details Stores the pattern bytes and a bitmask indicating which bytes
         *          are wildcards (mask=false) vs. literal values to match (mask=true).
         *          This design avoids sentinel byte conflicts (e.g., 0xCC is a valid byte).
         */
        struct CompiledPattern
        {
            /**
             * @brief Pattern bytes, one per token in the source AOB string.
             * @details Entries at wildcard positions (mask byte == 0x00) contain
             *          arbitrary values and must not be compared against memory.
             */
            std::vector<std::byte> bytes;

            /**
             * @brief Per-byte match mask paralleling @ref bytes.
             * @details 0xFF marks a literal byte that must match exactly; 0x00
             *          marks a wildcard slot to skip. Sized identically to
             *          @ref bytes.
             */
            std::vector<std::byte> mask;

            /**
             * @brief Byte offset from pattern start to the point of interest.
             * @details Set by the `|` marker in the AOB string, or 0 if absent.
             *          May equal bytes.size() when `|` appears at the end of the
             *          pattern. The offset is non-negative under the current
             *          parser (`|` cannot precede tokens), but the type is
             *          signed to match pointer-arithmetic conventions
             *          (C++ Core Guidelines ES.106) and to future-proof against
             *          negative anchors.
             */
            std::ptrdiff_t offset = 0;

            /**
             * @brief Returns the size of the pattern.
             * @return size_t The number of bytes in the pattern.
             */
            size_t size() const noexcept { return bytes.size(); }

            /**
             * @brief Checks if the pattern is empty.
             * @return true if the pattern has no bytes.
             */
            bool empty() const noexcept { return bytes.empty(); }
        };

        /**
         * @brief Parses a space-separated AOB string into a compiled pattern.
         * @details Converts hexadecimal strings to byte values and wildcard tokens
         *          ('??' or '?') into mask=false entries. An optional `|` token marks
         *          the offset within the pattern (stored in CompiledPattern::offset).
         *          This lets wider patterns precisely target a specific instruction:
         *          e.g., "48 8B 88 B8 00 00 00 | 48 89 4C 24 68" sets offset=7.
         * @param aob_str The AOB pattern string.
         * @return std::optional<CompiledPattern> The compiled pattern, or std::nullopt on parse failure.
         */
        [[nodiscard]] std::optional<CompiledPattern> parse_aob(std::string_view aob_str);

        /**
         * @brief Scans a specified memory region for a given byte pattern.
         * @details Uses an optimized search algorithm that finds the first non-wildcard
         *          byte and uses memchr for fast skipping, then verifies the full pattern.
         * @param start_address Pointer to the beginning of the memory region to scan.
         * @param region_size The size (in bytes) of the memory region to scan.
         * @param pattern The compiled pattern to search for.
         * @return const std::byte* Pointer to the match within the specified region,
         *         already adjusted by `pattern.offset`. Returns nullptr if pattern
         *         not found.
         * @note A pattern with zero literal bytes (every token wildcarded) returns
         *       `start_address` (plus offset) and emits a warning through the shared
         *       Logger. This case almost always indicates a caller bug; the behaviour
         *       is preserved for backwards compatibility but should not be relied upon.
         * @note `pattern.offset` (set by a `|` marker in the AOB string) is applied
         *       exactly once. When no marker is present `offset == 0` and the returned
         *       pointer is the match start. Callers must NOT add `pattern.offset`
         *       manually; doing so double-applies and will miss the intended byte.
         * @warning When `pattern.offset == pattern.size()` (a trailing `|` marker),
         *          the returned pointer addresses one-past the matched range. Depending
         *          on where in the region the match landed, this may also be
         *          one-past the scanned region. The pointer is valid for arithmetic
         *          and bounds comparisons but MUST NOT be dereferenced without an
         *          explicit readability check (e.g. `Memory::is_readable`).
         */
        [[nodiscard]] const std::byte *find_pattern(const std::byte *start_address, size_t region_size,
                                                    const CompiledPattern &pattern);

        /**
         * @brief Scans a memory region for the Nth occurrence of a byte pattern.
         * @param start_address Pointer to the beginning of the memory region to scan.
         * @param region_size The size (in bytes) of the memory region to scan.
         * @param pattern The compiled pattern to search for.
         * @param occurrence Which occurrence to return (1-based). 1 = first match.
         *                   Passing 0 returns nullptr.
         * @return const std::byte* Pointer to the Nth occurrence (already adjusted
         *         by `pattern.offset`), or nullptr if fewer than N matches exist.
         * @note Like the single-occurrence overload, `pattern.offset` is applied
         *       exactly once. Callers must NOT add it manually.
         * @warning A trailing `|` marker produces a one-past pointer identical in
         *          kind to the single-occurrence overload; do not dereference
         *          without a bounds or readability check.
         */
        [[nodiscard]] const std::byte *find_pattern(const std::byte *start_address, size_t region_size,
                                                    const CompiledPattern &pattern, size_t occurrence);
        // Common x86-64 RIP-relative opcode prefixes (bytes preceding the disp32 field)
        inline constexpr std::array<std::byte, 3> PREFIX_MOV_RAX_RIP = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};
        inline constexpr std::array<std::byte, 3> PREFIX_MOV_RCX_RIP = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x0D}};
        inline constexpr std::array<std::byte, 3> PREFIX_MOV_RDX_RIP = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x15}};
        inline constexpr std::array<std::byte, 3> PREFIX_MOV_RBX_RIP = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x1D}};
        inline constexpr std::array<std::byte, 3> PREFIX_LEA_RAX_RIP = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x05}};
        inline constexpr std::array<std::byte, 3> PREFIX_LEA_RCX_RIP = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x0D}};
        inline constexpr std::array<std::byte, 3> PREFIX_LEA_RDX_RIP = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x15}};
        inline constexpr std::array<std::byte, 1> PREFIX_CALL_REL32 = {std::byte{0xE8}};
        inline constexpr std::array<std::byte, 1> PREFIX_JMP_REL32 = {std::byte{0xE9}};

        /**
         * @brief Resolves an absolute address from an x86-64 RIP-relative instruction.
         * @details Extracts the int32 displacement at the given offset within the instruction
         *          and computes the absolute target: instruction_address + instruction_length + displacement.
         * @param instruction_address Pointer to the first byte of the instruction.
         * @param displacement_offset Byte offset from instruction_address to the disp32 field.
         * @param instruction_length Total length of the instruction in bytes.
         * @return The resolved absolute address, or RipResolveError on failure.
         */
        [[nodiscard]] std::expected<uintptr_t, RipResolveError> resolve_rip_relative(
            const std::byte *instruction_address,
            size_t displacement_offset,
            size_t instruction_length);

        /**
         * @brief Scans forward from a starting address for an opcode prefix, then resolves the RIP-relative target.
         * @details Searches up to search_length bytes for the given opcode prefix. Once found,
         *          the displacement is assumed to immediately follow the prefix. The absolute address
         *          is computed as: found_address + instruction_length + displacement.
         * @param search_start Pointer to the beginning of the search region.
         * @param search_length Maximum number of bytes to search forward.
         * @param opcode_prefix The opcode byte sequence to search for (disp32 must follow immediately).
         * @param instruction_length Total length of the instruction in bytes.
         * @return The resolved absolute address, or RipResolveError describing the failure.
         * @warning For indirect-call / indirect-jump forms (`FF 15 disp32`, `FF 25 disp32`)
         *          the returned address is the *pointer slot* (the address that stores
         *          the final target), not the target itself. Dereference it with
         *          `Memory::read_ptr_unsafe` (or an equivalent checked read) to obtain
         *          the callee / jump destination.
         */
        [[nodiscard]] std::expected<uintptr_t, RipResolveError> find_and_resolve_rip_relative(
            const std::byte *search_start,
            size_t search_length,
            std::span<const std::byte> opcode_prefix,
            size_t instruction_length);

        /**
         * @brief Scans all committed executable memory regions for a byte pattern.
         * @details Walks the process address space via VirtualQuery, scanning each
         *          committed region with execute permission. Useful for games with
         *          packed or protected binaries that unpack code into anonymous pages
         *          outside any loaded module's address range.
         * @param pattern The compiled pattern to search for.
         * @param occurrence Which occurrence to return (1-based). 1 = first match.
         * @return Pointer to the match (adjusted by pattern offset), or nullptr if not found.
         * @note Pure-execute pages (`PAGE_EXECUTE` without any read bit) are skipped:
         *       they are not guaranteed readable and dereferencing them raises an
         *       access violation. Only `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`,
         *       and `PAGE_EXECUTE_WRITECOPY` regions are inspected. Guard and
         *       no-access pages are skipped unconditionally.
         * @note `pattern.offset` is applied to the returned pointer, matching
         *       `find_pattern`. Callers must not add it manually.
         * @warning A trailing `|` marker (offset == pattern.size()) yields a
         *          one-past pointer; bounds-check before dereferencing.
         * @note A pattern that straddles a region boundary (e.g. two separately
         *       allocated `PAGE_EXECUTE_READ` regions that happen to be adjacent)
         *       will not be found: each region is scanned independently. PE-loaded
         *       code does not cross section boundaries so normal module scanning is
         *       unaffected, but JIT-compiled code (Mono, Unreal AngelScript) or
         *       heavily unpacked payloads may split contiguous bytes across VAD
         *       entries.
         */
        [[nodiscard]] const std::byte *scan_executable_regions(const CompiledPattern &pattern, size_t occurrence = 1);

        /**
         * @enum SimdLevel
         * @brief Reports the highest SIMD tier available for pattern verification.
         */
        enum class SimdLevel
        {
            Scalar, ///< No SIMD (byte-by-byte verification)
            Sse2,   ///< SSE2 (16 bytes per iteration)
            Avx2    ///< AVX2 (32 bytes per iteration, with SSE2 + scalar tail)
        };

        /**
         * @brief Returns the SIMD tier that find_pattern() will use at runtime.
         * @details Reflects both compile-time support (intrinsics available) and
         *          runtime CPU detection (CPUID + OS XGETBV for AVX2).
         */
        [[nodiscard]] SimdLevel active_simd_level() noexcept;

    } // namespace Scanner
} // namespace DetourModKit

#endif // DETOURMODKIT_SCANNER_HPP
