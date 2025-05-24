/**
 * @file aob_scanner.cpp
 * @brief Implementation of Array-of-Bytes (AOB) parsing and scanning.
 */

#include "DetourModKit/aob_scanner.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/string_utils.hpp"

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <stdexcept>
#include <limits>
#include <cstddef>

using namespace DetourModKit;
using namespace DetourModKit::String;

// Anonymous namespace for internal helpers and storage
namespace
{
    /**
     * @struct ParsedPatternByte
     * @brief Internal helper struct representing a parsed AOB element clearly for std::byte.
     * @details Used temporarily during parsing before converting to the final
     *          std::vector<std::byte> with std::byte{0xCC} wildcards.
     */
    struct ParsedPatternByte
    {
        std::byte value;  /**< Byte value (used if not a wildcard). */
        bool is_wildcard; /**< True if this element represents '??' or '?'. */
    };

    /**
     * @brief Internal parser: Converts AOB string to a structured vector of ParsedPatternByte.
     * @details Parses the input string token by token (space-separated).
     *          Validates each token for format ('??', '?', or two hex digits).
     *          Uses the Logger for detailed debug/error messages.
     * @param aob_str Raw AOB string (e.g., "48 ?? 8B").
     * @return std::vector<ParsedPatternByte> Vector of parsed structs, or empty on error.
     */
    static std::vector<ParsedPatternByte> parseAOBInternal(const std::string &aob_str)
    {
        std::vector<ParsedPatternByte> pattern_elements;
        std::string trimmed_aob = trim(aob_str);
        std::istringstream iss(trimmed_aob);
        std::string token;
        Logger &logger = Logger::getInstance();
        int token_idx = 0;

        if (trimmed_aob.empty())
        {
            if (!aob_str.empty())
            {
                logger.log(LOG_WARNING, "AOB Parser: Input string became empty after trimming.");
            }
            return pattern_elements;
        }

        logger.log(LOG_DEBUG, "AOB Parser: Parsing string: '" + trimmed_aob + "'");

        while (iss >> token)
        {
            token_idx++;
            if (token == "??" || token == "?")
            {
                pattern_elements.push_back({std::byte{0x00}, true}); // Wildcard value can be anything, 0xCC is conventional for final vector
            }
            else if (token.length() == 2 && std::isxdigit(static_cast<unsigned char>(token[0])) && std::isxdigit(static_cast<unsigned char>(token[1])))
            {
                try
                {
                    unsigned long ulong_val = std::stoul(token, nullptr, 16);
                    if (ulong_val > 0xFF)
                    {
                        throw std::out_of_range("Value parsed exceeds byte range (0xFF).");
                    }
                    pattern_elements.push_back({static_cast<std::byte>(ulong_val), false});
                }
                catch (const std::out_of_range &oor)
                {
                    logger.log(LOG_ERROR, "AOB Parser: Hex conversion out of range for '" + token + "' (Pos " + std::to_string(token_idx) + "): " + oor.what());
                    return {};
                }
                catch (const std::invalid_argument &ia)
                {
                    logger.log(LOG_ERROR, "AOB Parser: Invalid argument for hex conversion '" + token + "' (Pos " + std::to_string(token_idx) + "): " + ia.what());
                    return {};
                }
            }
            else
            {
                std::ostringstream oss_err;
                oss_err << "AOB Parser: Invalid token '" << token << "' at position " << token_idx
                        << ". Expected hex byte (e.g., FF), '?', or '" << '?' << "?'.";
                logger.log(LOG_ERROR, oss_err.str());
                return {};
            }
        }

        if (pattern_elements.empty() && token_idx > 0)
        {
            logger.log(LOG_ERROR, "AOB Parser: Processed tokens but resulting pattern is empty.");
        }
        else if (!pattern_elements.empty())
        {
            logger.log(LOG_DEBUG, "AOB Parser: Parsed " + std::to_string(pattern_elements.size()) + " elements.");
        }

        return pattern_elements;
    }
} // anonymous namespace

std::vector<std::byte> DetourModKit::AOB::parseAOB(const std::string &aob_str)
{
    Logger &logger = Logger::getInstance();
    const std::byte WILDCARD_BYTE_VALUE{0xCC}; // Define the wildcard representation

    std::vector<ParsedPatternByte> internal_pattern = parseAOBInternal(aob_str);
    std::vector<std::byte> byte_vector;

    if (internal_pattern.empty())
    {
        if (!trim(aob_str).empty())
        {
            logger.log(LOG_WARNING, "AOB: Parsing AOB string '" + aob_str + "' resulted in an empty pattern.");
        }
        return byte_vector;
    }

    byte_vector.reserve(internal_pattern.size());
    for (const auto &element : internal_pattern)
    {
        byte_vector.push_back(element.is_wildcard ? WILDCARD_BYTE_VALUE : element.value);
    }

    logger.log(LOG_DEBUG, "AOB: Converted pattern for scanning (" +
                              format_hex(static_cast<int>(WILDCARD_BYTE_VALUE)) +
                              " = wildcard). Size: " + std::to_string(byte_vector.size()));
    return byte_vector;
}

std::byte *DetourModKit::AOB::FindPattern(std::byte *start_address, size_t region_size,
                                          const std::vector<std::byte> &pattern_with_placeholders)
{
    Logger &logger = Logger::getInstance();
    const size_t pattern_size = pattern_with_placeholders.size();
    const std::byte WILDCARD_BYTE_VALUE{0xCC};

    if (pattern_size == 0)
    {
        logger.log(LOG_ERROR, "FindPattern: Pattern is empty. Cannot scan.");
        return nullptr;
    }
    if (!start_address)
    {
        logger.log(LOG_ERROR, "FindPattern: Start address is null. Cannot scan.");
        return nullptr;
    }
    if (region_size < pattern_size)
    {
        logger.log(LOG_WARNING, "FindPattern: Search region (" + std::to_string(region_size) +
                                    " bytes) is smaller than pattern (" + std::to_string(pattern_size) + " bytes).");
        return nullptr;
    }

    logger.log(LOG_DEBUG, "FindPattern: Scanning " + std::to_string(region_size) + " bytes from " +
                              format_address(reinterpret_cast<uintptr_t>(start_address)) + " for a " + std::to_string(pattern_size) + " byte pattern.");

    std::vector<bool> is_wildcard_mask(pattern_size);
    int wildcard_count = 0;
    for (size_t i = 0; i < pattern_size; ++i)
    {
        if (pattern_with_placeholders[i] == WILDCARD_BYTE_VALUE)
        {
            is_wildcard_mask[i] = true;
            wildcard_count++;
        }
        else
        {
            is_wildcard_mask[i] = false;
        }
    }

    if (wildcard_count > 0)
    {
        logger.log(LOG_DEBUG, "FindPattern: Pattern contains " + std::to_string(wildcard_count) + " wildcard(s).");
    }

    std::byte *const scan_boundary = start_address + (region_size - pattern_size);
    for (std::byte *current_scan_ptr = start_address; current_scan_ptr <= scan_boundary; ++current_scan_ptr)
    {
        bool match_found_at_current_ptr = true;
        for (size_t j = 0; j < pattern_size; ++j)
        {
            if (!is_wildcard_mask[j] && current_scan_ptr[j] != pattern_with_placeholders[j])
            {
                match_found_at_current_ptr = false;
                break;
            }
        }

        if (match_found_at_current_ptr)
        {
            uintptr_t absolute_match_address = reinterpret_cast<uintptr_t>(current_scan_ptr);
            uintptr_t rva_offset = absolute_match_address - reinterpret_cast<uintptr_t>(start_address);
            logger.log(LOG_INFO, "FindPattern: Pattern match found at address: " +
                                     format_address(absolute_match_address) +
                                     " (RVA: " + format_address(rva_offset) + ")");
            return current_scan_ptr;
        }
    }

    logger.log(LOG_WARNING, "FindPattern: Pattern not found in the specified memory region.");
    return nullptr;
}
