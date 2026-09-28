#ifndef DETOURMODKIT_FORMAT_HPP
#define DETOURMODKIT_FORMAT_HPP

/**
 * @file format.hpp
 * @brief String trimming and hex formatting for addresses, integers, bytes, and virtual key codes.
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
        /** @brief Trims leading and trailing space, tab, newline, carriage return, form feed, and vertical tab. */
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
        /** @brief Formats an address as full-width hex, for example "0x00007FFE12345678". */
        [[nodiscard]] inline std::string format_address(uintptr_t address)
        {
            return std::format("0x{:0{}X}", address, sizeof(uintptr_t) * 2);
        }

        /**
         * @brief Formats the unsigned two's-complement bit pattern of @p value, for example -1 as "0xFFFFFFFF".
         * @param width Minimum digit count of the zero-padded hex part. 0 adds no padding. Every format_hex overload
         *              keeps the "0x" prefix and any '-' outside the padded field.
         * @note For a leading '-' and the signed magnitude, pass a ptrdiff_t.
         */
        [[nodiscard]] inline std::string format_hex(int value, int width = 0)
        {
            if (width > 0)
                return std::format("0x{:0{}X}", static_cast<unsigned int>(value), width);
            return std::format("0x{:X}", static_cast<unsigned int>(value));
        }

        /** @brief Formats a long as the int overload does. HRESULT, LONG, LSTATUS, and NTSTATUS bind here exactly. */
        [[nodiscard]] inline std::string format_hex(long value, int width = 0)
        {
            if (width > 0)
                return std::format("0x{:0{}X}", static_cast<unsigned long>(value), width);
            return std::format("0x{:X}", static_cast<unsigned long>(value));
        }

        /** @brief Formats the full unsigned value with no narrowing. @p width works as in the int overload. */
        template <std::unsigned_integral T> [[nodiscard]] inline std::string format_hex(T value, int width = 0)
        {
            if (width > 0)
                return std::format("0x{:0{}X}", value, width);
            return std::format("0x{:X}", value);
        }

        /**
         * @brief Formats a signed 64-bit value. A negative value prints '-' and the magnitude, for example "-0x10".
         * @details LONG_PTR, SSIZE_T, and long long bind here on LLP64. @p width works as in the int overload.
         */
        [[nodiscard]] inline std::string format_hex(ptrdiff_t value, int width = 0)
        {
            if (value < 0)
            {
                // The unsigned negation avoids undefined behavior on PTRDIFF_MIN.
                const auto magnitude = static_cast<size_t>(~static_cast<size_t>(value) + 1u);
                if (width > 0)
                    return std::format("-0x{:0{}X}", magnitude, width);
                return std::format("-0x{:X}", magnitude);
            }
            if (width > 0)
                return std::format("0x{:0{}X}", static_cast<size_t>(value), width);
            return std::format("0x{:X}", static_cast<size_t>(value));
        }

        /** @brief Formats a byte as two hex digits, for example "0xCC". */
        [[nodiscard]] inline std::string format_byte(std::byte b)
        {
            return std::format("0x{:02X}", static_cast<unsigned int>(b));
        }

        /** @brief Formats integers as a comma-separated hex list, for example "[0x72, 0xA0, 0x20]". */
        [[nodiscard]] inline std::string format_int_vector(const std::vector<int> &values)
        {
            if (values.empty())
            {
                return "[]";
            }

            // Each entry is about 4 characters ("0x" and 2 or more hex digits) plus the ", " separator.
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

        /** @brief Formats a virtual key code as two hex digits, for example "0x72". */
        [[nodiscard]] inline std::string format_vkcode(int vk_code)
        {
            return format_hex(vk_code, 2);
        }

        /** @brief Formats virtual key codes as format_int_vector does. */
        [[nodiscard]] inline std::string format_vkcode_list(const std::vector<int> &keys)
        {
            return format_int_vector(keys);
        }

    } // namespace format
} // namespace DetourModKit

#endif // DETOURMODKIT_FORMAT_HPP
