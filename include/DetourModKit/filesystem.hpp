#ifndef DETOURMODKIT_FILESYSTEM_HPP
#define DETOURMODKIT_FILESYSTEM_HPP

/**
 * @file filesystem.hpp
 * @brief Header for file system utilities.
 *
 * Declares functions for file system operations, such as retrieving the directory of the currently executing module.
 */

#include <string>

namespace DetourModKit
{
    namespace filesystem
    {

        /**
         * @brief Gets the directory containing the currently executing module (DLL/EXE).
         * @details Resolution (GetModuleHandleExW, GetModuleFileNameW, parent-path extraction) runs once and the
         *          resolved path is cached, but every call returns an owning copy of that cached string, so each call
         *          still pays a string copy and may allocate (a typical path exceeds the small-string buffer). Not
         *          allocation-free and therefore not callback-safe; capture the result once at setup instead of
         *          calling from a hot or allocation-restricted path. Falls back to the current working directory if
         *          module path detection fails for any reason.
         * @return std::wstring The absolute directory path of the current module as a wide string, preserving full
         *         Unicode fidelity for paths with non-ASCII characters (e.g. CJK/Cyrillic usernames). Returns L"." on
         *         total failure.
         */
        [[nodiscard]] std::wstring get_runtime_directory();

        /**
         * @brief UTF-8 sibling of get_runtime_directory().
         * @details The WideCharToMultiByte(CP_UTF8) conversion runs once and its result is cached separately, but as
         *          with the wide getter every call returns an owning copy of the cached string and may allocate; it
         *          is not allocation-free or callback-safe. Returns "." if the wide-string resolution failed or if
         *          the UTF-8 conversion itself fails (best-effort fallback).
         * @return std::string Absolute module directory encoded in UTF-8.
         */
        [[nodiscard]] std::string get_runtime_directory_utf8();
    } // namespace filesystem
} // namespace DetourModKit

#endif // DETOURMODKIT_FILESYSTEM_HPP
