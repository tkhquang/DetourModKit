/**
 * @file filesystem_utils.hpp
 * @brief Header for file system utilities.
 *
 * Declares functions for file system operations, such as retrieving the directory
 * of the currently executing module.
 */

#ifndef FILESYSTEM_UTILS_HPP
#define FILESYSTEM_UTILS_HPP

#include <string>

namespace DetourModKit
{
    namespace Filesystem
    {

        /**
         * @brief Gets the directory containing the currently executing module (DLL/EXE).
         * @details Uses Windows API (GetModuleHandleExA, GetModuleFileNameA) to determine
         *          the full path of the current module and extracts its parent directory using
         *          std::filesystem. Falls back to the current working directory if module
         *          path detection fails for any reason. Logs details of its operation and
         *          any fallbacks using the Logger.
         * @return std::string The absolute directory path of the current module. If detection fails,
         *         it returns the current working directory. In case of further failure, it might
         *         return ".", representing the current directory in a relative sense.
         */
        std::string getRuntimeDirectory();
    } // namespace Filesystem
} // namespace DetourModKit

#endif // FILESYSTEM_UTILS_HPP
