#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <vector>
#include <string>
#include <cstddef>
#include <optional>
#include <cstdint>
#include <span>

namespace DetourModKit
{
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
            std::vector<std::byte> bytes; ///< Pattern bytes (wildcard positions contain arbitrary values)
            std::vector<std::byte> mask;  ///< 0xFF = match this byte, 0x00 = wildcard (skip)

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
         *          ('??' or '?') into mask=false entries.
         * @param aob_str The AOB pattern string.
         * @return std::optional<CompiledPattern> The compiled pattern, or std::nullopt on parse failure.
         */
        std::optional<CompiledPattern> parse_aob(std::string_view aob_str);

        /**
         * @brief Scans a specified memory region for a given byte pattern.
         * @details Uses an optimized search algorithm that finds the first non-wildcard
         *          byte and uses memchr for fast skipping, then verifies the full pattern.
         * @param start_address Pointer to the beginning of the memory region to scan.
         * @param region_size The size (in bytes) of the memory region to scan.
         * @param pattern The compiled pattern to search for.
         * @return const std::byte* Pointer to the first occurrence of the pattern within
         *         the specified region. Returns nullptr if pattern not found.
         */
        const std::byte *find_pattern(const std::byte *start_address, size_t region_size,
                                      const CompiledPattern &pattern);
        // Common x86-64 RIP-relative opcode prefixes (bytes preceding the disp32 field)
        inline constexpr std::byte PREFIX_MOV_RAX_RIP[] = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};
        inline constexpr std::byte PREFIX_MOV_RCX_RIP[] = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x0D}};
        inline constexpr std::byte PREFIX_MOV_RDX_RIP[] = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x15}};
        inline constexpr std::byte PREFIX_MOV_RBX_RIP[] = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x1D}};
        inline constexpr std::byte PREFIX_LEA_RAX_RIP[] = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x05}};
        inline constexpr std::byte PREFIX_LEA_RCX_RIP[] = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x0D}};
        inline constexpr std::byte PREFIX_LEA_RDX_RIP[] = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x15}};
        inline constexpr std::byte PREFIX_CALL_REL32[] = {std::byte{0xE8}};
        inline constexpr std::byte PREFIX_JMP_REL32[] = {std::byte{0xE9}};

        /**
         * @brief Resolves an absolute address from an x86-64 RIP-relative instruction.
         * @details Extracts the int32 displacement at the given offset within the instruction
         *          and computes the absolute target: instruction_address + instruction_length + displacement.
         * @param instruction_address Pointer to the first byte of the instruction.
         * @param displacement_offset Byte offset from instruction_address to the disp32 field.
         * @param instruction_length Total length of the instruction in bytes.
         * @return The resolved absolute address, or std::nullopt on null input or unreadable displacement.
         */
        std::optional<uintptr_t> resolve_rip_relative(const std::byte *instruction_address,
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
         * @return The resolved absolute address, or std::nullopt if prefix not found or displacement unreadable.
         */
        std::optional<uintptr_t> find_and_resolve_rip_relative(const std::byte *search_start,
                                                               size_t search_length,
                                                               std::span<const std::byte> opcode_prefix,
                                                               size_t instruction_length);

    } // namespace Scanner
} // namespace DetourModKit

#endif // SCANNER_HPP
