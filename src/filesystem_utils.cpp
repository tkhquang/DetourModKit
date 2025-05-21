/**
 * @file filesystem_utils.cpp
 * @brief Implementation of file system utilities.
 *
 * Provides functions for file system operations, such as retrieving the directory
 * of the currently executing module.
 */

#include "filesystem_utils.hpp"
#include "logger.hpp"
#include <windows.h>
#include <filesystem>
#include <stdexcept>

std::string getRuntimeDirectory()
{
    HMODULE h_self = NULL;
    char module_path_buffer[MAX_PATH] = {0};
    std::string result_path = "";
    try
    {
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)&getRuntimeDirectory, &h_self) ||
            h_self == NULL)
        {
            throw std::runtime_error("GetModuleHandleExA failed: " + std::to_string(GetLastError()));
        }

        DWORD path_len = GetModuleFileNameA(h_self, module_path_buffer, MAX_PATH);
        if (path_len == 0)
            throw std::runtime_error("GetModuleFileNameA failed: " + std::to_string(GetLastError()));
        if (path_len == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            throw std::runtime_error("GetModuleFileNameA failed: Buffer too small");

        std::filesystem::path module_full_path(module_path_buffer);
        result_path = module_full_path.parent_path().string();

        Logger::getInstance().log(LOG_DEBUG, "getRuntimeDirectory: Found module directory: " + result_path);
    }
    catch (const std::exception &e)
    {
        char current_dir[MAX_PATH] = {0};
        if (GetCurrentDirectoryA(MAX_PATH, current_dir))
        {
            result_path = current_dir;
        }
        else
        {
            result_path = ".";
        }
        Logger::getInstance().log(LOG_WARNING, "getRuntimeDirectory: Failed to get module directory: " +
                                                   std::string(e.what()) + ". Using fallback: " + result_path);
    }
    return result_path;
}
