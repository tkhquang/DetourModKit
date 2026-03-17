/**
 * @file string_utils.hpp
 * @brief Header for string manipulation utilities.
 *
 * Provides inline functions for trimming strings. These are general-purpose
 * utilities useful in modding contexts.
 */

#ifndef STRING_UTILS_HPP
#define STRING_UTILS_HPP

#include <string>
#include <algorithm>
#include <cctype>

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
