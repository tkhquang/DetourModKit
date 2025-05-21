/**
 * @file filesystem_utils.h
 * @brief Header for file system utilities.
 *
 * Declares functions for file system operations, such as retrieving the directory
 * of the currently executing module.
 */

#ifndef FILESYSTEM_UTILS_H
#define FILESYSTEM_UTILS_H

#include <string>

/**
 * @brief Gets the directory containing the currently executing module (DLL/EXE).
 * @details Uses Windows API to determine the full path of the current module
 *          and extracts its parent directory. Falls back to the current working
 *          directory if module path detection fails.
 * @return The directory path of the current module or the fallback directory.
 */
std::string getRuntimeDirectory();

#endif // FILESYSTEM_UTILS_H
