/**
 * @file scanner.cpp
 * @brief Implementation of Array-of-Bytes (AOB) parsing and scanning.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/format.hpp"

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <stdexcept>
#include <limits>
#include <cstddef>
#include <cstring>

using namespace DetourModKit;
using namespace DetourModKit::String;

// Anonymous namespace for internal helpers
namespace
{
    /**
     * @struct ParsedPatternByte
     * @brief Internal helper struct representing a parsed AOB element.
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
    std::vector<ParsedPatternByte> parseAOBInternal(std::string_view aob_str)
    {
        std::vector<ParsedPatternByte> pattern_elements;
        std::string trimmed_aob = trim(std::string(aob_str));
        std::istringstream iss(trimmed_aob);
        std::string token;
        Logger &logger = Logger::getInstance();
        int token_idx = 0;

        if (trimmed_aob.empty())
        {
            if (!aob_str.empty())
            {
                logger.warning("AOB Parser: Input string became empty after trimming.");
            }
            return pattern_elements;
        }

        logger.debug("AOB Parser: Parsing string: '{}'", trimmed_aob);

        while (iss >> token)
        {
            token_idx++;
            if (token == "??" || token == "?")
            {
                pattern_elements.push_back({std::byte{0x00}, true});
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
                    logger.error("AOB Parser: Hex conversion out of range for '{}' (Pos {}): {}", token, token_idx, oor.what());
                    return {};
                }
                catch (const std::invalid_argument &ia)
                {
                    logger.error("AOB Parser: Invalid argument for hex conversion '{}' (Pos {}): {}", token, token_idx, ia.what());
                    return {};
                }
            }
            else
            {
                std::ostringstream oss_err;
                oss_err << "AOB Parser: Invalid token '" << token << "' at position " << token_idx
                        << ". Expected hex byte (e.g., FF), '?', or '?\?'.";
                logger.log(LogLevel::Error, oss_err.str());
                return {};
            }
        }

        if (pattern_elements.empty() && token_idx > 0)
        {
            logger.error("AOB Parser: Processed tokens but resulting pattern is empty.");
        }
        else if (!pattern_elements.empty())
        {
            logger.debug("AOB Parser: Parsed {} elements.", pattern_elements.size());
        }

        return pattern_elements;
    }
} // anonymous namespace

// ============================================================================
// AOB Scanner API: parseAOB and FindPattern with CompiledPattern
// ============================================================================

std::optional<Scanner::CompiledPattern> DetourModKit::Scanner::parseAOB(std::string_view aob_str)
{
    Logger &logger = Logger::getInstance();

    std::vector<ParsedPatternByte> internal_pattern = parseAOBInternal(aob_str);

    if (internal_pattern.empty())
    {
        if (!trim(std::string(aob_str)).empty())
        {
            logger.warning("AOB: Parsing AOB string '{}' resulted in an empty pattern.", aob_str);
        }
        return std::nullopt;
    }

    CompiledPattern result;
    result.bytes.reserve(internal_pattern.size());
    result.mask.reserve(internal_pattern.size());

    for (const auto &element : internal_pattern)
    {
        result.bytes.push_back(element.value);
        result.mask.push_back(element.is_wildcard ? 0 : 1);
    }

    logger.debug("AOB: Compiled pattern with {} bytes, {} wildcards.",
                 result.bytes.size(),
                 std::count(result.mask.begin(), result.mask.end(), 0));
    return result;
}

std::byte *DetourModKit::Scanner::FindPattern(std::byte *start_address, size_t region_size,
                                              const CompiledPattern &pattern)
{
    Logger &logger = Logger::getInstance();
    const size_t pattern_size = pattern.size();

    if (pattern_size == 0)
    {
        logger.error("FindPattern: Pattern is empty. Cannot scan.");
        return nullptr;
    }
    if (!start_address)
    {
        logger.error("FindPattern: Start address is null. Cannot scan.");
        return nullptr;
    }
    if (region_size < pattern_size)
    {
        logger.warning("FindPattern: Search region ({} bytes) is smaller than pattern ({} bytes).", region_size, pattern_size);
        return nullptr;
    }

    logger.debug("FindPattern: Scanning {} bytes from {} for a {} byte pattern.",
                 region_size, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(start_address)), pattern_size);

    // Count wildcards for optimization decisions
    int wildcard_count = 0;
    size_t first_non_wildcard = pattern_size; // invalid index = all wildcards
    for (size_t i = 0; i < pattern_size; ++i)
    {
        if (pattern.mask[i] == 0)
        {
            wildcard_count++;
        }
        else if (first_non_wildcard == pattern_size)
        {
            first_non_wildcard = i;
        }
    }

    if (wildcard_count > 0)
    {
        logger.debug("FindPattern: Pattern contains {} wildcard(s).", wildcard_count);
    }

    // Optimization: If pattern is ALL wildcards, return start_address (matches immediately)
    if (first_non_wildcard == pattern_size)
    {
        logger.warning("FindPattern: Pattern is all wildcards. Returning start address.");
        return start_address;
    }

    // Optimization: Use memchr to find the first non-wildcard byte, then verify full pattern
    // This dramatically reduces the number of full pattern comparisons needed
    const std::byte target_byte = pattern.bytes[first_non_wildcard];
    const unsigned char target_val = static_cast<unsigned char>(target_byte);

    std::byte *search_start = start_address;
    const std::byte *const search_end = start_address + (region_size - pattern_size);

    while (search_start <= search_end)
    {
        // Use memchr to find the next occurrence of the first non-wildcard byte
        void *found = memchr(search_start, static_cast<int>(target_val),
                             static_cast<size_t>(search_end - search_start + 1));

        if (!found)
        {
            // First non-wildcard byte not found in remaining region
            break;
        }

        std::byte *current_scan_ptr = static_cast<std::byte *>(found);

        // Adjust back by first_non_wildcard to get the pattern start position
        if (current_scan_ptr < start_address + first_non_wildcard)
        {
            // Would go before start, skip to next
            search_start = current_scan_ptr + 1;
            continue;
        }

        std::byte *pattern_start = current_scan_ptr - first_non_wildcard;

        // Verify the full pattern at this position
        bool match_found = true;
        for (size_t j = 0; j < pattern_size; ++j)
        {
            if (pattern.mask[j] != 0 && pattern_start[j] != pattern.bytes[j])
            {
                match_found = false;
                break;
            }
        }

        if (match_found)
        {
            uintptr_t absolute_match_address = reinterpret_cast<uintptr_t>(pattern_start);
            uintptr_t rva_offset = absolute_match_address - reinterpret_cast<uintptr_t>(start_address);
            logger.info("FindPattern: Pattern match found at address: {} (RVA: {})",
                        DetourModKit::Format::format_address(absolute_match_address), DetourModKit::Format::format_address(rva_offset));
            return pattern_start;
        }

        // No match, continue searching from next position
        search_start = current_scan_ptr + 1;
    }

    logger.warning("FindPattern: Pattern not found in the specified memory region.");
    return nullptr;
}
