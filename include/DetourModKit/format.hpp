#pragma once

/**
 * @file format.hpp
 * @brief String and format utilities for DetourModKit.
 * @details Provides string manipulation (trimming) and formatting utilities
 *          for common game modding types like memory addresses, byte values,
 *          and virtual key codes.
 */

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace String
    {
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
            const char *whitespace_chars = " \t\n\r\f\v";

            size_t first_non_whitespace = s.find_first_not_of(whitespace_chars);
            if (std::string::npos == first_non_whitespace)
            {
                return "";
            }

            size_t last_non_whitespace = s.find_last_not_of(whitespace_chars);
            return s.substr(first_non_whitespace, (last_non_whitespace - first_non_whitespace + 1));
        }
    } // namespace String

    namespace Format
    {
        /**
         * @brief Formats a memory address as a hexadecimal string.
         * @param address The memory address to format.
         * @return std::string Formatted address (e.g., "0x00007FFE12345678").
         */
        inline std::string format_address(uintptr_t address)
        {
            return std::format("0x{:0{}X}", address, sizeof(uintptr_t) * 2);
        }

        /**
         * @brief Formats an integer as a hexadecimal string.
         * @param value The integer value to format.
         * @param width Minimum width of the hex part (0 for no padding).
         * @return std::string Formatted hex string (e.g., "0xFF").
         */
        inline std::string format_hex(int value, int width = 0)
        {
            if (width > 0)
                return std::format("0x{:0{}X}", static_cast<unsigned int>(value), width);
            return std::format("0x{:X}", static_cast<unsigned int>(value));
        }

        /**
         * @brief Formats a ptrdiff_t as a signed hexadecimal string.
         * @param value The value to format.
         * @return std::string Formatted hex string (e.g., "0xFF" or "-0x10").
         */
        inline std::string format_hex(ptrdiff_t value)
        {
            if (value < 0)
                return std::format("-0x{:X}", static_cast<size_t>(-value));
            return std::format("0x{:X}", static_cast<size_t>(value));
        }

        /**
         * @brief Formats a byte value as a two-digit hexadecimal string.
         * @param b The byte value to format.
         * @return std::string Formatted byte (e.g., "0xCC").
         */
        inline std::string format_byte(std::byte b)
        {
            return std::format("0x{:02X}", static_cast<unsigned int>(b));
        }

        /**
         * @brief Formats a vector of integers as a comma-separated hex list.
         * @param values The vector of integer values.
         * @return std::string Formatted list (e.g., "[0x72, 0xA0, 0x20]").
         */
        inline std::string format_int_vector(const std::vector<int> &values)
        {
            if (values.empty())
            {
                return "[]";
            }

            // "0x" + 2+ hex digits ≈ 4 chars per entry, plus ", " separator
            std::string result;
            result.reserve(1 + values.size() * 6 + 1);
            result += '[';
            for (size_t i = 0; i < values.size(); ++i)
            {
                if (i > 0)
                {
                    result += ", ";
                }
                result += format_hex(values[i], 2);
            }
            result += ']';
            return result;
        }

        /**
         * @brief Formats a Virtual Key code as a two-digit hexadecimal string.
         * @param vk_code The virtual key code.
         * @return std::string Formatted VK code (e.g., "0x72").
         */
        inline std::string format_vkcode(int vk_code)
        {
            return format_hex(vk_code, 2);
        }

        /**
         * @brief Formats a vector of Virtual Key codes.
         * @param keys The vector of VK codes.
         * @return std::string Formatted VK code list.
         */
        inline std::string format_vkcode_list(const std::vector<int> &keys)
        {
            return format_int_vector(keys);
        }

    } // namespace Format
} // namespace DetourModKit
