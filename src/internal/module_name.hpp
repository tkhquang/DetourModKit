#ifndef DETOURMODKIT_INTERNAL_MODULE_NAME_HPP
#define DETOURMODKIT_INTERNAL_MODULE_NAME_HPP

/**
 * @file module_name.hpp
 * @brief Shared bounded UTF-8 -> UTF-16 widening for module-name lookups.
 */

#include "internal/utf8_conversion.hpp"

#include <climits>
#include <cstddef>
#include <new>
#include <string>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @brief Reports whether a module-name byte count fits the Win32 conversion API.
         * @param length The byte count to test.
         * @return True when @p length can be represented by the converter's signed count.
         */
        [[nodiscard]] constexpr bool module_name_length_fits_win32(std::size_t length) noexcept
        {
            return length <= static_cast<std::size_t>(INT_MAX);
        }

        /**
         * @brief Widens a pointer/count UTF-8 module name after validating its Win32 length.
         * @details The length check precedes construction of a view and every access through @p data. Embedded NUL and
         *          malformed UTF-8 are rejected because GetModuleHandleW would otherwise observe a different name.
         * @param data The first name byte; may be null only when @p length is zero or oversized.
         * @param length The number of name bytes.
         * @return The UTF-16 name, or an empty string when validation, conversion, or allocation fails.
         * @pre When @p length is nonzero and at most INT_MAX, @p data addresses @p length readable bytes.
         */
        [[nodiscard]] inline std::wstring widen_module_name_bytes(const char *data, std::size_t length) noexcept
        {
            if (length == 0 || !module_name_length_fits_win32(length) || data == nullptr)
            {
                return std::wstring{};
            }
            try
            {
                return widen_utf8(std::string_view{data, length});
            }
            catch (const std::bad_alloc &)
            {
                return std::wstring{};
            }
        }

        /**
         * @brief Widens a UTF-8 module name to the UTF-16 the Win32 module APIs expect.
         * @details Reads exactly @c name.size() bytes, so a non-NUL-terminated view is safe.
         * @param name The bounded UTF-8 module name.
         * @return The UTF-16 name, or an empty string when validation, conversion, or allocation fails.
         */
        [[nodiscard]] inline std::wstring widen_module_name(std::string_view name) noexcept
        {
            return widen_module_name_bytes(name.data(), name.size());
        }
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_MODULE_NAME_HPP
