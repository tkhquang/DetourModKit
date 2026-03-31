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
         *          if module path detection fails for any reason. Logs details of its operation
         *          and any fallbacks using the Logger.
         * @return std::string The absolute directory path of the current module, encoded in the
         *         system's active code page (ACP). If
         *         detection fails, it returns the current working directory. In case of further
         *         failure, it might return ".", representing the current directory in a relative
         *         sense.
         */
        std::string get_runtime_directory();
    } // namespace Filesystem
} // namespace DetourModKit

#endif // DETOURMODKIT_FILESYSTEM_HPP
