#ifndef DETOURMODKIT_FILESYSTEM_HPP
#define DETOURMODKIT_FILESYSTEM_HPP

/**
 * @file filesystem.hpp
 * @brief Module-path filesystem utilities.
 * @warning `[B-100]` Call both functions outside the loader lock. First use queries the loader and caches the path.
 *          Each call can allocate, so neither is callback-safe. `FilesystemLoaderBoundary.*` pins the boundary.
 */

#include <string>

namespace DetourModKit
{
    namespace filesystem
    {

        /**
         * @brief Returns the absolute directory of the module that links DMK, with every non-ASCII character kept.
         *        If the module lookup fails, it returns the current working directory, or L"." if that also fails.
         */
        [[nodiscard]] std::wstring get_runtime_directory();

        /** @brief Returns get_runtime_directory() in UTF-8, or "." if the conversion fails. */
        [[nodiscard]] std::string get_runtime_directory_utf8();
    } // namespace filesystem
} // namespace DetourModKit

#endif // DETOURMODKIT_FILESYSTEM_HPP
