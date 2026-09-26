#ifndef DETOURMODKIT_INTERNAL_UTF8_CONVERSION_HPP
#define DETOURMODKIT_INTERNAL_UTF8_CONVERSION_HPP

/**
 * @file utf8_conversion.hpp
 * @brief UTF-8 and UTF-16 conversion for paths and names. No conversion uses the ANSI code page.
 */

#include <windows.h>

#include <climits>
#include <cstddef>
#include <string>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @brief Widens strict UTF-8 text to UTF-16.
         * @details Reads exactly @c text.size() bytes, so a view without a terminator is safe.
         * @param text The UTF-8 text.
         * @return The UTF-16 text. The result is empty for empty input, an embedded NUL, a size over INT_MAX, or
         *         ill-formed UTF-8.
         * @throws std::bad_alloc when the result cannot be allocated.
         */
        [[nodiscard]] inline std::wstring widen_utf8(std::string_view text)
        {
            if (text.empty() || text.size() > static_cast<std::size_t>(INT_MAX) ||
                text.find('\0') != std::string_view::npos)
            {
                return std::wstring{};
            }

            const int input_length = static_cast<int>(text.size());
            const int wide_length =
                ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), input_length, nullptr, 0);
            if (wide_length <= 0)
            {
                return std::wstring{};
            }
            std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
            const int converted = ::MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                text.data(),
                input_length,
                wide.data(),
                wide_length
            );
            if (converted != wide_length)
            {
                return std::wstring{};
            }
            return wide;
        }

        /**
         * @brief Renders UTF-16 text as UTF-8.
         * @details An unpaired surrogate becomes U+FFFD, so the conversion does not fail on content.
         * @param wide The UTF-16 text.
         * @return The UTF-8 text. The result is empty for empty input or a size over INT_MAX.
         * @throws std::bad_alloc when the result cannot be allocated.
         */
        [[nodiscard]] inline std::string utf8_from_wide(std::wstring_view wide)
        {
            if (wide.empty() || wide.size() > static_cast<std::size_t>(INT_MAX))
            {
                return std::string{};
            }

            const int input_length = static_cast<int>(wide.size());
            const int byte_length =
                ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), input_length, nullptr, 0, nullptr, nullptr);
            if (byte_length <= 0)
            {
                return std::string{};
            }
            std::string text(static_cast<std::size_t>(byte_length), '\0');
            const int converted = ::WideCharToMultiByte(
                CP_UTF8,
                0,
                wide.data(),
                input_length,
                text.data(),
                byte_length,
                nullptr,
                nullptr
            );
            if (converted != byte_length)
            {
                return std::string{};
            }
            return text;
        }
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_UTF8_CONVERSION_HPP
