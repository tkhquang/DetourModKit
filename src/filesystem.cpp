/**
 * @file filesystem.cpp
 * @brief Implementation of file system utilities.
 *
 * Provides functions for file system operations, such as retrieving the directory
 * of the currently executing module.
 */

#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <filesystem>
#include <stdexcept>

using namespace DetourModKit;

std::string DetourModKit::Filesystem::get_runtime_directory()
{
    HMODULE h_self_module = NULL;
    char module_path_buffer[MAX_PATH] = {0};
    std::string result_directory_path;
    Logger &logger = Logger::get_instance();

    try
    {
        // Use the address of this function to locate the containing module (DLL or EXE).
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(&get_runtime_directory),
                                &h_self_module) ||
            h_self_module == NULL)
        {
            throw std::runtime_error("GetModuleHandleExA failed to retrieve module handle. Error: " + std::to_string(GetLastError()));
        }

        DWORD path_length = GetModuleFileNameA(h_self_module, module_path_buffer, MAX_PATH);
        if (path_length == 0)
        {
            throw std::runtime_error("GetModuleFileNameA failed to retrieve module path. Error: " + std::to_string(GetLastError()));
        }
        if (path_length >= MAX_PATH)
        {
            throw std::runtime_error("GetModuleFileNameA failed: Path buffer was too small.");
        }

        std::filesystem::path module_full_path(module_path_buffer);
        result_directory_path = module_full_path.parent_path().string();

        logger.debug("get_runtime_directory: Successfully determined module directory: {}", result_directory_path);
    }
    catch (const std::filesystem::filesystem_error &fs_err)
    {
        logger.warning("get_runtime_directory: Filesystem error: {}. Attempting to fall back to current working directory.", fs_err.what());
    }
    catch (const std::exception &e)
    {
        logger.warning("get_runtime_directory: Failed to determine module directory: {}. Attempting to fall back to current working directory.", e.what());
    }

    if (result_directory_path.empty())
    {
        char current_dir_buffer[MAX_PATH] = {0};
        if (GetCurrentDirectoryA(MAX_PATH, current_dir_buffer) > 0)
        {
            result_directory_path = current_dir_buffer;
            logger.warning("get_runtime_directory: Using current working directory as fallback: {}", result_directory_path);
        }
        else
        {
            // If even GetCurrentDirectoryA fails, use "." as a last resort.
            result_directory_path = ".";
            logger.error("get_runtime_directory: Failed to get current working directory. Using relative path anchor '.'. Error: {}", GetLastError());
        }
    }
    return result_directory_path;
}
