/**
 * @file aob_scanner.hpp
 * @brief Header for Array-of-Bytes (AOB) scanning functionality.
 *
 * Declares functions to parse AOB pattern strings (supporting hex bytes and
 * wildcards '??' or '?') and to search memory regions for these patterns.
 */
#ifndef AOB_SCANNER_HPP
#define AOB_SCANNER_HPP

#include <vector>
#include <string>
#include <cstddef>

/**
 * @brief Parses a space-separated AOB string into a byte vector for scanning.
 * @details Converts hexadecimal strings (e.g., "4A") to their corresponding
 * byte values. Converts wildcard tokens ('??' or '?') into a placeholder byte
 * (std::byte{0xCC}) which is specifically recognized by `FindPattern`. Logs parsing errors
 * via the global Logger. Whitespace between tokens is flexible.
 * Example: "48 8B ?? C1 ?" becomes {std::byte{0x48}, std::byte{0x8B}, std::byte{0xCC}, std::byte{0xC1}, std::byte{0xCC}}.
 * @param aob_str The AOB pattern string.
 * @return std::vector<std::byte> Vector of bytes representing the pattern, where
 *         std::byte{0xCC} signifies a wildcard. Returns an empty vector on failure
 *         (e.g., invalid token, hex conversion error) or if the input string
 *         is effectively empty after trimming.
 */
std::vector<std::byte> parseAOB(const std::string &aob_str);

/**
 * @brief Scans a specified memory region for a given byte pattern.
 * @details The pattern can include wildcards represented by `std::byte{0xCC}`.
 *          A `std::byte{0xCC}` byte in the `pattern_with_placeholders` vector will match
 *          any byte at the corresponding position in the memory region.
 * @param start_address Pointer to the beginning of the memory region to scan.
 *                      Must be a valid readable address. This pointer will be to std::byte.
 * @param region_size The size (in bytes) of the memory region to scan.
 * @param pattern_with_placeholders The byte vector pattern to search for.
 *                                  `std::byte{0xCC}` represents a wildcard byte.
 * @return std::byte* Pointer to the first occurrence of the pattern within the
 *         specified region. Returns `nullptr` if the pattern is not found,
 *         if input parameters are invalid (null address, empty pattern,
 *         region too small for pattern), or if an error occurs during scanning.
 *         The returned pointer allows access to the found memory as std::byte.
 */
std::byte *FindPattern(std::byte *start_address, size_t region_size,
                       const std::vector<std::byte> &pattern_with_placeholders);

#endif // AOB_SCANNER_HPP
