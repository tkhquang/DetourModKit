/**
 * @file string_utils.hpp
 * @brief Header for string formatting and manipulation utilities.
 *
 * Provides inline functions for formatting addresses, hexadecimal values,
 * virtual key codes, and for trimming strings. These are general-purpose
 * utilities useful in modding contexts.
 *
 * @deprecated Many functions in this header are deprecated in favor of
 *             DetourModKit::Format utilities which use C++23 std::format
 *             for better performance. Prefer Format:: functions for new code.
 */

#ifndef STRING_UTILS_HPP
#define STRING_UTILS_HPP

#include "DetourModKit/format_utils.hpp"

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <algorithm>
#include <cctype>

namespace DetourModKit
{
    namespace String
    {
        /**
         * @brief Formats a memory address (uintptr_t) into a standard hexadecimal string.
         * @deprecated Use DetourModKit::Format::format_address instead for C++23 std::format.
         * @param address The memory address to format.
         * @return std::string A formatted hexadecimal string, prefixed with "0x" and
         *         zero-padded to the size of a pointer (e.g., "0x00007FFE12345678").
         */
        [[deprecated("Use DetourModKit::Format::format_address() instead for better performance with C++23 std::format")]]
        inline std::string format_address(uintptr_t address)
        {
            return DetourModKit::Format::format_address(address);
        }

        /**
         * @brief Formats an integer value as an uppercase hexadecimal string.
         * @deprecated Use DetourModKit::Format::format_hex instead for C++23 std::format.
         * @param value The integer value to format.
         * @param width Optional. The minimum width of the hexadecimal part (excluding "0x").
         *              If the hex string is shorter, it will be zero-padded.
         *              A width of 0 (default) means no specific padding beyond natural length.
         * @return std::string A formatted hexadecimal string, prefixed with "0x" (e.g., "0xFF", "0x00A5").
         */
        [[deprecated("Use DetourModKit::Format::format_hex() instead for better performance with C++23 std::format")]]
        inline std::string format_hex(int value, int width = 0)
        {
            return DetourModKit::Format::format_hex(value, width);
        }

        /**
         * @brief Formats a Virtual Key (VK) code as a standard 2-digit hexadecimal string.
         * @deprecated Use DetourModKit::Format::format_vkcode instead for C++23 std::format.
         * @details This is a convenience wrapper around `format_hex` specifically for VK codes,
         *          ensuring they are typically displayed with 2 hex digits (e.g., "0x72" for F3).
         * @param vk_code The virtual key code (integer) to format.
         * @return std::string Formatted VK code string (e.g., "0x72").
         *         If `vk_code` is, for example, `0x7`, it will be formatted as `0x07`.
         *         If `vk_code` is `0x123`, it will be `0x123` (width adapts if >2 hex digits).
         *         Consider passing `width=2` to `format_hex` if strict 2-digit desired.
         *         Currently uses default format_hex, which for VK codes is fine.
         */
        [[deprecated("Use DetourModKit::Format::format_vkcode() instead for better performance with C++23 std::format")]]
        inline std::string format_vkcode(int vk_code)
        {
            return DetourModKit::Format::format_vkcode(vk_code);
        }

        /**
         * @brief Formats a vector of Virtual Key (VK) codes into a human-readable, comma-separated hex list.
         * @deprecated Use DetourModKit::Format::format_vkcode_list instead for C++23 std::format.
         * @param keys A const reference to a vector of integer VK codes.
         * @return std::string A string representing the list (e.g., "0x72, 0xA0, 0x20").
         *         Returns "(None)" if the input vector is empty.
         */
        [[deprecated("Use DetourModKit::Format::format_vkcode_list() instead for better performance with C++23 std::format")]]
        inline std::string format_vkcode_list(const std::vector<int> &keys)
        {
            if (keys.empty())
            {
                return "(None)";
            }

            std::ostringstream oss;
            for (size_t i = 0; i < keys.size(); ++i)
            {
                oss << format_vkcode(keys[i]); // Uses 2-digit formatting for each VK code
                if (i < keys.size() - 1)
                {
                    oss << ", ";
                }
            }
            return oss.str();
        }

        /**
         * @brief Trims leading and trailing whitespace characters from a string.
         * @details Whitespace characters considered are space, tab, newline, carriage return,
         *          form feed, and vertical tab.
         * @param s The const reference to the std::string to trim.
         * @return std::string A new string with leading/trailing whitespace removed.
         *         Returns an empty string if the input string is empty or contains only whitespace.
         */
        inline std::string trim(const std::string &s)
        {
            // Define whitespace characters as per std::isspace (locale-dependent) or a fixed set.
            // Using a fixed set for predictable behavior across locales.
            const char *whitespace_chars = " \t\n\r\f\v";

            size_t first_non_whitespace = s.find_first_not_of(whitespace_chars);
            if (std::string::npos == first_non_whitespace) // String is empty or all whitespace
            {
                return "";
            }

            size_t last_non_whitespace = s.find_last_not_of(whitespace_chars);
            // (last_non_whitespace - first_non_whitespace + 1) is the length of the substring
            return s.substr(first_non_whitespace, (last_non_whitespace - first_non_whitespace + 1));
        }
    } // namespace String
} // namespace DetourModKit

#endif // STRING_UTILS_HPP
