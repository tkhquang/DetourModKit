#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <vector>
#include <string>
#include <cstddef>
#include <optional>
#include <cstdint>

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
            std::vector<uint8_t> mask;    ///< 1 = match this byte, 0 = wildcard (skip)

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
         * @return std::byte* Pointer to the first occurrence of the pattern within
         *         the specified region. Returns nullptr if pattern not found.
         */
        std::byte *find_pattern(std::byte *start_address, size_t region_size,
                               const CompiledPattern &pattern);
    } // namespace Scanner
} // namespace DetourModKit

#endif // SCANNER_HPP
