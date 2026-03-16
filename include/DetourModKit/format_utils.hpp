#ifndef FORMAT_UTILS_HPP
#define FORMAT_UTILS_HPP

/**
 * @file format_utils.hpp
 * @brief Format string utilities and custom formatters for game modding types.
 * @details Provides std::format-style formatting with custom formatters for
 *          common game modding types like memory addresses, byte values, and
 *          virtual key codes. Supports both C++20 std::format and a fallback
 *          implementation for C++17.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <sstream>
#include <iomanip>
#include <type_traits>

// Check for C++20 std::format support
#if __has_include(<format>) && defined(__cpp_lib_format)
#include <format>
#define DMK_HAS_STD_FORMAT 1
#else
#define DMK_HAS_STD_FORMAT 0
#endif

namespace DetourModKit
{
    namespace Format
    {
        /**
         * @brief Formats a memory address as a hexadecimal string.
         * @param address The memory address to format.
         * @return std::string Formatted address (e.g., "0x00007FFE12345678").
         */
        inline std::string format_address(uintptr_t address)
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << std::uppercase
                << std::setw(sizeof(uintptr_t) * 2)
                << std::setfill('0') << address;
            return oss.str();
        }

        /**
         * @brief Formats an integer as a hexadecimal string.
         * @param value The integer value to format.
         * @param width Minimum width of the hex part (0 for no padding).
         * @return std::string Formatted hex string (e.g., "0xFF").
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
         * @brief Formats a byte value as a two-digit hexadecimal string.
         * @param b The byte value to format.
         * @return std::string Formatted byte (e.g., "0xCC").
         */
        inline std::string format_byte(std::byte b)
        {
            std::ostringstream oss;
            oss << "0x" << std::uppercase << std::hex
                << std::setw(2) << std::setfill('0')
                << static_cast<unsigned int>(b);
            return oss.str();
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

            std::ostringstream oss;
            oss << "[";
            for (size_t i = 0; i < values.size(); ++i)
            {
                if (i > 0)
                {
                    oss << ", ";
                }
                oss << format_hex(values[i], 2);
            }
            oss << "]";
            return oss.str();
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

// C++20 std::format custom formatters must be in the std namespace
#if DMK_HAS_STD_FORMAT

/**
 * @brief Custom formatter for uintptr_t (memory addresses).
 */
template <>
struct std::formatter<uintptr_t>
{
    constexpr auto parse(std::format_parse_context &ctx)
    {
        auto it = ctx.begin();
        auto end = ctx.end();

        // Check for format specifiers
        if (it != end && *it != '}')
        {
            if (*it == 'x' || *it == 'X')
            {
                uppercase_ = (*it == 'X');
                ++it;
            }
        }
        return it;
    }

    auto format(uintptr_t addr, std::format_context &ctx) const
    {
        if (uppercase_)
        {
            return std::format_to(ctx.out(), "0x{:0{}X}",
                                  addr, sizeof(uintptr_t) * 2);
        }
        else
        {
            return std::format_to(ctx.out(), "0x{:0{}x}",
                                  addr, sizeof(uintptr_t) * 2);
        }
    }

private:
    bool uppercase_{true};
};

/**
 * @brief Custom formatter for std::byte.
 */
template <>
struct std::formatter<std::byte>
{
    constexpr auto parse(std::format_parse_context &ctx)
    {
        return ctx.begin();
    }

    auto format(std::byte b, std::format_context &ctx) const
    {
        return std::format_to(ctx.out(), "0x{:02X}",
                              static_cast<unsigned int>(b));
    }
};

/**
 * @brief Custom formatter for std::vector<int> (e.g., VK code lists).
 */
template <>
struct std::formatter<std::vector<int>>
{
    constexpr auto parse(std::format_parse_context &ctx)
    {
        return ctx.begin();
    }

    auto format(const std::vector<int> &vec, std::format_context &ctx) const
    {
        auto out = ctx.out();
        *out++ = '[';
        for (size_t i = 0; i < vec.size(); ++i)
        {
            if (i > 0)
            {
                *out++ = ',';
                *out++ = ' ';
            }
            out = std::format_to(out, "0x{:02X}", vec[i]);
        }
        *out++ = ']';
        return out;
    }
};

#endif // DMK_HAS_STD_FORMAT

#endif // FORMAT_UTILS_HPP
