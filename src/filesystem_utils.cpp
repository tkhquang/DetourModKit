/**
 * @file filesystem_utils.cpp
 * @brief Implementation of file system utilities.
 *
 * Provides functions for file system operations, such as retrieving the directory
 * of the currently executing module.
 */

#include "DetourModKit/filesystem_utils.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <filesystem>
#include <stdexcept>

std::string getRuntimeDirectory()
{
    HMODULE h_self_module = NULL;
    char module_path_buffer[MAX_PATH] = {0}; // Initialize buffer
    std::string result_directory_path;
    Logger &logger = Logger::getInstance(); // Get logger instance for messages

    try
    {
        // Get a handle to the current module (DLL or EXE).
        // The address of this function (getRuntimeDirectory) is used to find the module.
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)&getRuntimeDirectory, // Address within the current module
                                &h_self_module) ||
            h_self_module == NULL)
        {
            throw std::runtime_error("GetModuleHandleExA failed to retrieve module handle. Error: " + std::to_string(GetLastError()));
        }

        // Get the full path of the module.
        DWORD path_length = GetModuleFileNameA(h_self_module, module_path_buffer, MAX_PATH);
        if (path_length == 0)
        {
            throw std::runtime_error("GetModuleFileNameA failed to retrieve module path. Error: " + std::to_string(GetLastError()));
        }
        // Check for buffer insufficiency.
        if (path_length == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            throw std::runtime_error("GetModuleFileNameA failed: Path buffer was too small.");
        }

        // Use std::filesystem to reliably get the parent directory.
        std::filesystem::path module_full_path(module_path_buffer);
        result_directory_path = module_full_path.parent_path().string();

        logger.log(LOG_DEBUG, "getRuntimeDirectory: Successfully determined module directory: " + result_directory_path);
    }
    catch (const std::filesystem::filesystem_error &fs_err)
    {
        // Log filesystem specific errors during path manipulation
        logger.log(LOG_WARNING, "getRuntimeDirectory: Filesystem error: " + std::string(fs_err.what()) +
                                    ". Attempting to fall back to current working directory.");
        // Fallback implemented below the catch block
    }
    catch (const std::exception &e)
    {
        // Log other runtime errors (e.g., from GetModuleHandleExA or GetModuleFileNameA).
        logger.log(LOG_WARNING, "getRuntimeDirectory: Failed to determine module directory: " +
                                    std::string(e.what()) + ". Attempting to fall back to current working directory.");
        // Fallback implemented below the catch block
    }

    // If result_directory_path is still empty (due to an exception caught above), try fallback.
    if (result_directory_path.empty())
    {
        char current_dir_buffer[MAX_PATH] = {0};
        if (GetCurrentDirectoryA(MAX_PATH, current_dir_buffer) > 0)
        {
            result_directory_path = current_dir_buffer;
            logger.log(LOG_WARNING, "getRuntimeDirectory: Using current working directory as fallback: " + result_directory_path);
        }
        else
        {
            // If even GetCurrentDirectoryA fails, use "." as a last resort.
            result_directory_path = ".";
            logger.log(LOG_ERROR, "getRuntimeDirectory: Failed to get current working directory. Using relative path anchor '.'. Error: " + std::to_string(GetLastError()));
        }
    }
    return result_directory_path;
}
