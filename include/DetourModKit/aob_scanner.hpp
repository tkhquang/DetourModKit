/**
 * @file aob_scanner.h
 * @brief Header for Array-of-Bytes (AOB) scanning functionality.
 *
 * Declares functions to parse AOB pattern strings (supporting hex bytes and
 * wildcards '??' or '?') and to search memory regions for these patterns.
 */
#ifndef AOB_SCANNER_H
#define AOB_SCANNER_H

#include <windows.h> // For BYTE definition
#include <vector>
#include <string>

/**
 * @brief Parses a space-separated AOB string into a byte vector for scanning.
 * @details Converts hexadecimal strings (e.g., "4A") to their corresponding
 * byte values. Converts wildcard tokens ('??' or '?') into a placeholder byte
 * (0xCC) which is specifically recognized by `FindPattern`. Logs parsing errors
 * via the global Logger. Whitespace between tokens is flexible.
 * Example: "48 8B ?? C1 ??" becomes {0x48, 0x8B, 0xCC, 0xC1, 0xCC}.
 * @param aob_str The AOB pattern string.
 * @return std::vector<BYTE> Vector of bytes representing the pattern, where
 *         0xCC signifies a wildcard. Returns an empty vector on failure
 *         (e.g., invalid token, hex conversion error) or if the input string
 *         is effectively empty after trimming.
 */
std::vector<BYTE> parseAOB(const std::string &aob_str);

/**
 * @brief Scans a specified memory region for a given byte pattern.
 * @details The pattern can include wildcards represented by the byte 0xCC.
 *          A 0xCC byte in the `pattern_with_placeholders` vector will match
 *          any byte at the corresponding position in the memory region.
 * @param start_address Pointer to the beginning of the memory region to scan.
 *                      Must be a valid readable address.
 * @param region_size The size (in bytes) of the memory region to scan.
 * @param pattern_with_placeholders The byte vector pattern to search for.
 *                                  0xCC represents a wildcard byte.
 * @return BYTE* Pointer to the first occurrence of the pattern within the
 *         specified region. Returns `nullptr` if the pattern is not found,
 *         if input parameters are invalid (null address, empty pattern,
 *         region too small), or if an error occurs.
 */
BYTE *FindPattern(BYTE *start_address, size_t region_size,
                  const std::vector<BYTE> &pattern_with_placeholders);

#endif // AOB_SCANNER_H
