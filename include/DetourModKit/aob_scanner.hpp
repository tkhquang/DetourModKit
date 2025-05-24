#ifndef AOB_SCANNER_HPP
#define AOB_SCANNER_HPP

#include <vector>
#include <string>
#include <cstddef>

namespace DetourModKit
{
    namespace Scanner
    {
        /**
         * @brief Parses a space-separated AOB string into a byte vector for scanning.
         * @details Converts hexadecimal strings to their corresponding byte values.
         *          Converts wildcard tokens ('??' or '?') into placeholder bytes
         *          (std::byte{0xCC}) recognized by FindPattern.
         * @param aob_str The AOB pattern string.
         * @return std::vector<std::byte> Vector of bytes representing the pattern,
         *         where std::byte{0xCC} signifies a wildcard. Returns empty on failure.
         */
        std::vector<std::byte> parseAOB(const std::string &aob_str);

        /**
         * @brief Scans a specified memory region for a given byte pattern.
         * @details The pattern can include wildcards represented by std::byte{0xCC}.
         *          A wildcard byte will match any byte at the corresponding position.
         * @param start_address Pointer to the beginning of the memory region to scan.
         * @param region_size The size (in bytes) of the memory region to scan.
         * @param pattern_with_placeholders The byte vector pattern to search for.
         * @return std::byte* Pointer to the first occurrence of the pattern within
         *         the specified region. Returns nullptr if pattern not found.
         */
        std::byte *FindPattern(std::byte *start_address, size_t region_size,
                               const std::vector<std::byte> &pattern_with_placeholders);
    } // namespace Scanner
} // namespace DetourModKit

#endif // AOB_SCANNER_HPP
