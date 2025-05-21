/**
 * @file aob_scanner.cpp
 * @brief Implementation of Array-of-Bytes (AOB) parsing and scanning.
 */

#include "aob_scanner.hpp"
#include "logger.hpp"       // For logging parse errors and scan details
#include "string_utils.hpp" // For trim() and format_address()

#include <vector>
#include <string>
#include <sstream>   // For std::istringstream
#include <iomanip>   // For std::setw, std::setfill
#include <cctype>    // For std::isxdigit
#include <stdexcept> // For std::stoul exceptions
#include <limits>    // Required by some compilers for std::stoul

/**
 * @struct PatternByte
 * @brief Internal helper struct representing a parsed AOB element clearly.
 * @details Used temporarily during parsing before converting to the final
 *          BYTE vector with 0xCC wildcards.
 */
struct PatternByte
{
    BYTE value;       /**< Byte value (used if not a wildcard). */
    bool is_wildcard; /**< True if this element represents '??' or '?'. */
};

/**
 * @brief Internal parser: Converts AOB string to a structured vector.
 * @details Parses the input string token by token (space-separated).
 *          Validates each token for format ('??', '?', or two hex digits).
 *          Uses the Logger for detailed debug/error messages.
 * @param aob_str Raw AOB string (e.g., "48 ?? 8B").
 * @return std::vector<PatternByte> Vector of parsed structs, or empty on error.
 */
static std::vector<PatternByte> parseAOBInternal(const std::string &aob_str)
{
    std::vector<PatternByte> pattern_elements;
    std::string trimmed_aob = trim(aob_str);
    std::istringstream iss(trimmed_aob);
    std::string token;
    Logger &logger = Logger::getInstance();
    int token_idx = 0;

    if (trimmed_aob.empty())
    {
        if (!aob_str.empty())
        {
            logger.log(LOG_WARNING, "AOB Parser: Input empty after trim.");
        }
        return pattern_elements;
    }

    logger.log(LOG_DEBUG, "AOB Parser: Parsing string: '" + trimmed_aob + "'");

    while (iss >> token)
    {
        token_idx++;
        if (token == "??" || token == "?")
        {
            pattern_elements.push_back({0x00, true});
        }
        else if (token.length() == 2 && std::isxdigit(static_cast<unsigned char>(token[0])) && std::isxdigit(static_cast<unsigned char>(token[1])))
        {
            try
            {
                unsigned long ulong_val = std::stoul(token, nullptr, 16);
                if (ulong_val > 0xFF)
                {
                    throw std::out_of_range("Value exceeds BYTE range");
                }
                pattern_elements.push_back({static_cast<BYTE>(ulong_val), false});
            }
            catch (const std::exception &e)
            {
                logger.log(LOG_ERROR, "AOB Parser: Hex conversion error for '" + token + "' (Pos " + std::to_string(token_idx) + "): " + e.what());
                return {}; // Return empty on error
            }
        }
        else
        {
            std::ostringstream oss_err;
            // *** CORRECTED LINE TO AVOID TRIGRAPH WARNING ***
            oss_err << "AOB Parser: Invalid token '" << token << "' at position " << token_idx
                    << ". Expected hex byte (e.g., FF), '?', or '" << '?' << "?'.";
            logger.log(LOG_ERROR, oss_err.str());
            return {}; // Return empty on error
        }
    }

    if (pattern_elements.empty() && token_idx > 0)
    {
        logger.log(LOG_ERROR, "AOB Parser: Processed tokens but found no valid elements.");
    }
    else if (!pattern_elements.empty())
    {
        logger.log(LOG_DEBUG, "AOB Parser: Parsed " + std::to_string(pattern_elements.size()) + " elements.");
    }

    return pattern_elements;
}

/**
 * @brief Public interface to parse an AOB string into a byte vector suitable
 *        for the FindPattern function (using 0xCC for wildcards).
 * @param aob_str The AOB pattern string (e.g., "48 8B ?? C1").
 * @return std::vector<BYTE> Vector of bytes (0xCC represents wildcards).
 *         Returns an empty vector if parsing fails or input is empty.
 */
std::vector<BYTE> parseAOB(const std::string &aob_str)
{
    Logger &logger = Logger::getInstance();

    std::vector<PatternByte> internal_pattern = parseAOBInternal(aob_str);
    std::vector<BYTE> byte_vector;

    if (internal_pattern.empty())
    {
        if (!trim(aob_str).empty())
        {
            logger.log(LOG_ERROR, "AOB: Parsing resulted in empty pattern.");
        }
        return byte_vector;
    }

    byte_vector.reserve(internal_pattern.size());
    for (const auto &element : internal_pattern)
    {
        byte_vector.push_back(element.is_wildcard ? 0xCC : element.value);
    }

    logger.log(LOG_DEBUG, "AOB: Converted pattern for scanning (0xCC = wildcard).");
    return byte_vector;
}

/**
 * @brief Scans a memory region for a specific sequence of bytes, supporting
 *        wildcards represented by the byte 0xCC.
 * @param start_address Start address of the memory region.
 * @param region_size Size (in bytes) of the memory region.
 * @param pattern_with_placeholders The pattern vector (0xCC = wildcard).
 * @return Pointer (BYTE*) to the first byte of the found pattern occurrence,
 *         or nullptr if not found or if inputs are invalid.
 */
BYTE *FindPattern(BYTE *start_address, size_t region_size,
                  const std::vector<BYTE> &pattern_with_placeholders)
{
    Logger &logger = Logger::getInstance();
    const size_t pattern_size = pattern_with_placeholders.size();

    // Input Validation
    if (pattern_size == 0)
    {
        logger.log(LOG_ERROR, "FindPattern: Empty pattern.");
        return nullptr;
    }
    if (!start_address)
    {
        logger.log(LOG_ERROR, "FindPattern: Null start address.");
        return nullptr;
    }
    if (region_size < pattern_size)
    {
        logger.log(LOG_WARNING, "FindPattern: Region smaller than pattern.");
        return nullptr;
    }

    logger.log(LOG_DEBUG, "FindPattern: Scanning " + std::to_string(region_size) + " bytes from " +
                              format_address(reinterpret_cast<uintptr_t>(start_address)) + " for " + std::to_string(pattern_size) + " byte pattern.");

    // Prepare Wildcard Mask
    std::vector<bool> is_wildcard(pattern_size);
    int wildcard_count = 0;
    for (size_t i = 0; i < pattern_size; ++i)
    {
        if ((is_wildcard[i] = (pattern_with_placeholders[i] == 0xCC)))
        {
            wildcard_count++;
        }
    }
    if (wildcard_count > 0)
    {
        logger.log(LOG_DEBUG, "FindPattern: Pattern has " + std::to_string(wildcard_count) + " wildcards.");
    }

    // Scanning Loop
    BYTE *const scan_end_addr = start_address + (region_size - pattern_size);
    for (BYTE *current_pos = start_address; current_pos <= scan_end_addr; ++current_pos)
    {
        bool match_found = true;
        for (size_t j = 0; j < pattern_size; ++j)
        {
            if (!is_wildcard[j] && current_pos[j] != pattern_with_placeholders[j])
            {
                match_found = false;
                break;
            }
        }

        if (match_found)
        {
            uintptr_t absolute_match_address = reinterpret_cast<uintptr_t>(current_pos);
            uintptr_t rva = absolute_match_address - reinterpret_cast<uintptr_t>(start_address);
            logger.log(LOG_INFO, "FindPattern: Match found at address: " +
                                     format_address(absolute_match_address) +
                                     " (RVA: " + format_address(rva) + ")");
            return current_pos;
        }
    }

    logger.log(LOG_WARNING, "FindPattern: Pattern not found.");
    return nullptr;
}
