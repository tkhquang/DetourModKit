/**
 * @file string_utils.h
 * @brief Header for string formatting and manipulation utilities.
 *
 * Provides inline functions for formatting addresses, hexadecimal values, and trimming strings.
 */

#ifndef STRING_UTILS_H
#define STRING_UTILS_H

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <algorithm>

/**
 * @brief Formats a memory address into a standard hex string.
 * @param address The memory address to format.
 * @return Formatted hex string with prefix (e.g., "0x7FFE12345678").
 */
inline std::string format_address(uintptr_t address)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase
        << std::setw(sizeof(uintptr_t) * 2) << std::setfill('0') << address;
    return oss.str();
}

/**
 * @brief Formats an integer as an uppercase hex string.
 * @param value The integer value to format.
 * @param width Optional width for zero-padding (0 = no padding).
 * @return Formatted hex string with "0x" prefix.
 */
inline std::string format_hex(int value, int width = 0)
{
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex;
    if (width > 0)
    {
        oss << std::setw(width) << std::setfill('0');
    }
    oss << value;
    return oss.str();
}

/**
 * @brief Formats a Virtual Key (VK) code as a standard 2-digit hex string.
 * @param vk_code The virtual key code to format.
 * @return Formatted VK code (e.g., "0x72" for F3 key).
 */
inline std::string format_vkcode(int vk_code)
{
    return format_hex(vk_code);
}

/**
 * @brief Formats a vector of VK codes into a human-readable hex list string.
 * @param keys Vector of virtual key codes.
 * @return Comma-separated list (e.g., "0x72, 0x73") or "(None)" if empty.
 */
inline std::string format_vkcode_list(const std::vector<int> &keys)
{
    if (keys.empty())
        return "(None)";
    std::ostringstream oss;
    for (size_t i = 0; i < keys.size(); ++i)
    {
        oss << format_vkcode(keys[i]);
        if (i < keys.size() - 1)
        {
            oss << ", ";
        }
    }
    return oss.str();
}

/**
 * @brief Trims leading and trailing whitespace characters from a string.
 * @param s The string to trim.
 * @return The trimmed string.
 */
inline std::string trim(const std::string &s)
{
    const char *WHITESPACE = " \t\n\r\f\v";
    size_t first = s.find_first_not_of(WHITESPACE);
    if (first == std::string::npos)
        return "";
    size_t last = s.find_last_not_of(WHITESPACE);
    return s.substr(first, (last - first + 1));
}

#endif // STRING_UTILS_H
