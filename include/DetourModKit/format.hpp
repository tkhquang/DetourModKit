#ifndef DETOURMODKIT_FORMAT_HPP
#define DETOURMODKIT_FORMAT_HPP

/**
 * @file format.hpp
 * @brief String and format utilities for DetourModKit.
 * @details Provides string manipulation (trimming) and formatting utilities for common game modding types like memory
 *          addresses, byte values, and virtual key codes.
 */

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace string
    {
        /**
         * @brief Trims leading and trailing whitespace characters from a string.
         * @details Whitespace characters considered are space, tab, newline, carriage return, form feed, and vertical
         *          tab.
         * @param s The string_view to trim.
         * @return std::string A new string with leading/trailing whitespace removed. Returns an empty string if the
         *         input string is empty or contains only whitespace.
         */
        [[nodiscard]] inline std::string trim(std::string_view s)
        {
            const char *whitespace_chars = " \t\n\r\f\v";

            const size_t first_non_whitespace = s.find_first_not_of(whitespace_chars);
            if (std::string_view::npos == first_non_whitespace)
            {
                return "";
            }

            const size_t last_non_whitespace = s.find_last_not_of(whitespace_chars);
            return std::string(s.substr(first_non_whitespace, (last_non_whitespace - first_non_whitespace + 1)));
        }
    } // namespace string

    namespace format
    {
        /**
         * @brief Formats a memory address as a hexadecimal string.
         * @param address The memory address to format.
         * @return std::string Formatted address (e.g., "0x00007FFE12345678").
         */
        [[nodiscard]] inline std::string format_address(uintptr_t address)
        {
            return std::format("0x{:0{}X}", address, sizeof(uintptr_t) * 2);
        }

        /**
         * @brief Formats a signed integer as an unsigned hexadecimal string.
         * @details Prints the unsigned two's-complement bit pattern, so a negative value widens to its unsigned
         *          representation (e.g. -1 -> "0xFFFFFFFF"). Use the ptrdiff_t overload when a leading '-' and the
         *          signed magnitude are wanted, or the unsigned-integral overload for size_t / unsigned values.
         * @param value The integer value to format.
         * @param width Minimum width of the hex part (0 for no padding).
         * @return std::string Formatted hex string (e.g., "0xFF").
         */
        [[nodiscard]] inline std::string format_hex(int value, int width = 0)
        {
            if (width > 0)
                return std::format("0x{:0{}X}", static_cast<unsigned int>(value), width);
            return std::format("0x{:X}", static_cast<unsigned int>(value));
        }

        /**
         * @brief Formats a signed long as an unsigned hexadecimal string.
         * @details Exact match for the 32-bit Win32 LONG family (HRESULT, LONG, LSTATUS, NTSTATUS). Negative values
         *          print the unsigned two's-complement bit pattern like the int overload.
         * @param value The long value to format.
         * @param width Minimum width of the hex part (0 for no padding).
         * @return std::string Formatted hex string (e.g., "0x80004005").
         */
        [[nodiscard]] inline std::string format_hex(long value, int width = 0)
        {
            if (width > 0)
                return std::format("0x{:0{}X}", static_cast<unsigned long>(value), width);
            return std::format("0x{:X}", static_cast<unsigned long>(value));
        }

        /**
         * @brief Formats any unsigned integer as a hexadecimal string.
         * @details Constrained to std::unsigned_integral so a size_t / unsigned / uint64_t argument binds here exactly
         *          instead of being ambiguous between the int and ptrdiff_t overloads. The full value is preserved
         *          with no narrowing. The signed int and ptrdiff_t overloads are unaffected because a signed argument
         *          does not satisfy the constraint.
         * @tparam T The unsigned integral type of the value.
         * @param value The unsigned value to format.
         * @param width Minimum width of the hex part (0 for no padding).
         * @return std::string Formatted hex string (e.g., "0xDEADBEEF").
         */
        template <std::unsigned_integral T> [[nodiscard]] inline std::string format_hex(T value, int width = 0)
        {
            if (width > 0)
                return std::format("0x{:0{}X}", value, width);
            return std::format("0x{:X}", value);
        }

        /**
         * @brief Formats a ptrdiff_t as a signed hexadecimal string.
         * @details The signed 64-bit path (LONG_PTR / SSIZE_T / long long on LLP64), and the one signed overload that
         *          prints a leading '-' with the magnitude rather than the two's-complement bit pattern -- a pointer
         *          difference is a distance, not a register image. The pad count applies to the hex digits only; the
         *          '-' and the "0x" prefix sit outside the padded field, matching the other overloads.
         * @param value The value to format.
         * @param width Minimum width of the hex part (0 for no padding).
         * @return std::string Formatted hex string (e.g., "0xFF" or "-0x10").
         */
        [[nodiscard]] inline std::string format_hex(ptrdiff_t value, int width = 0)
        {
            if (value < 0)
            {
                // Two's complement negation via unsigned cast avoids UB on PTRDIFF_MIN
                const auto magnitude = static_cast<size_t>(~static_cast<size_t>(value) + 1u);
                if (width > 0)
                    return std::format("-0x{:0{}X}", magnitude, width);
                return std::format("-0x{:X}", magnitude);
            }
            if (width > 0)
                return std::format("0x{:0{}X}", static_cast<size_t>(value), width);
            return std::format("0x{:X}", static_cast<size_t>(value));
        }

        /**
         * @brief Formats a byte value as a two-digit hexadecimal string.
         * @param b The byte value to format.
         * @return std::string Formatted byte (e.g., "0xCC").
         */
        [[nodiscard]] inline std::string format_byte(std::byte b)
        {
            return std::format("0x{:02X}", static_cast<unsigned int>(b));
        }

        /**
         * @brief Formats a vector of integers as a comma-separated hex list.
         * @param values The vector of integer values.
         * @return std::string Formatted list (e.g., "[0x72, 0xA0, 0x20]").
         */
        [[nodiscard]] inline std::string format_int_vector(const std::vector<int> &values)
        {
            if (values.empty())
            {
                return "[]";
            }

            // "0x" + 2+ hex digits ~4 chars per entry, plus ", " separator
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
        [[nodiscard]] inline std::string format_vkcode(int vk_code)
        {
            return format_hex(vk_code, 2);
        }

        /**
         * @brief Formats a vector of Virtual Key codes.
         * @param keys The vector of VK codes.
         * @return std::string Formatted VK code list.
         */
        [[nodiscard]] inline std::string format_vkcode_list(const std::vector<int> &keys)
        {
            return format_int_vector(keys);
        }

    } // namespace format
} // namespace DetourModKit

#endif // DETOURMODKIT_FORMAT_HPP
