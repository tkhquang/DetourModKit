/**
 * @file filesystem.hpp
 * @brief Header for file system utilities.
 *
 * Declares functions for file system operations, such as retrieving the directory
 * of the currently executing module.
 */

#ifndef DETOURMODKIT_FILESYSTEM_HPP
#define DETOURMODKIT_FILESYSTEM_HPP

#include <string>

namespace DetourModKit
{
    namespace Filesystem
    {

        /**
         * @brief Gets the directory containing the currently executing module (DLL/EXE).
         * @details Uses Windows Wide APIs (GetModuleHandleExW, GetModuleFileNameW) to determine
         *          the full path of the current module and extracts its parent directory using
         *          std::filesystem. The result is cached after the first successful resolution,
         *          making subsequent calls zero-cost. Falls back to the current working directory
         *          if module path detection fails for any reason.
         * @return std::wstring The absolute directory path of the current module as a wide
         *         string, preserving full Unicode fidelity for paths with non-ASCII characters
         *         (e.g. CJK/Cyrillic usernames). Returns L"." on total failure.
         */
        std::wstring get_runtime_directory();

        /**
         * @brief UTF-8 sibling of get_runtime_directory().
         * @details Converts the cached wide-string module directory to UTF-8
         *          via WideCharToMultiByte(CP_UTF8). The conversion result is
         *          cached separately so repeated calls are allocation-free.
         *          Returns "." if the wide-string resolution failed or if the
         *          UTF-8 conversion itself fails (best-effort fallback).
         * @return std::string Absolute module directory encoded in UTF-8.
         */
        [[nodiscard]] std::string get_runtime_directory_utf8();
    } // namespace Filesystem
} // namespace DetourModKit

#endif // DETOURMODKIT_FILESYSTEM_HPP
