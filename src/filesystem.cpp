/**
 * @file filesystem.cpp
 * @brief Implementation of file system utilities.
 *
 * Provides functions for file system operations, such as retrieving the directory
 * of the currently executing module.
 */

#include "DetourModKit/filesystem.hpp"

#include <windows.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace DetourModKit;

namespace
{
    /**
     * @brief Resolves the directory of the currently executing module.
     *
     * @details Called exactly once; the result is cached by the caller.
     * Diagnostics are written to stderr rather than Logger because this
     * function executes during Logger construction (via generate_log_file_path),
     * and calling Logger::get_instance() here would deadlock on the magic-static
     * guard that is already held by the in-progress Logger singleton init.
     */
    std::string resolve_module_directory()
    {
        HMODULE h_self_module = nullptr;
        wchar_t module_path_buffer[MAX_PATH] = {0};
        std::string result_directory_path;

        try
        {
            // Use the address of the public function to locate the containing module (DLL or EXE).
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(&Filesystem::get_runtime_directory),
                                    &h_self_module) ||
                h_self_module == nullptr)
            {
                const DWORD last_error = GetLastError();
                throw std::runtime_error("GetModuleHandleExW failed to retrieve module handle. Error: " + std::to_string(last_error));
            }

            const DWORD path_length = GetModuleFileNameW(h_self_module, module_path_buffer, MAX_PATH);
            if (path_length == 0)
            {
                const DWORD last_error = GetLastError();
                throw std::runtime_error("GetModuleFileNameW failed to retrieve module path. Error: " + std::to_string(last_error));
            }
            if (path_length >= MAX_PATH)
            {
                throw std::runtime_error("GetModuleFileNameW failed: Path buffer was too small.");
            }

            const std::filesystem::path module_full_path(module_path_buffer);
            result_directory_path = module_full_path.parent_path().string();
        }
        catch (const std::filesystem::filesystem_error &fs_err)
        {
            std::cerr << "[DMK Filesystem WARNING] Filesystem error: " << fs_err.what()
                      << ". Attempting to fall back to current working directory." << '\n';
        }
        catch (const std::exception &e)
        {
            std::cerr << "[DMK Filesystem WARNING] Failed to determine module directory: " << e.what()
                      << ". Attempting to fall back to current working directory." << '\n';
        }

        if (result_directory_path.empty())
        {
            wchar_t current_dir_buffer[MAX_PATH] = {0};
            if (GetCurrentDirectoryW(MAX_PATH, current_dir_buffer) > 0)
            {
                result_directory_path = std::filesystem::path(current_dir_buffer).string();
                std::cerr << "[DMK Filesystem WARNING] Using current working directory as fallback: "
                          << result_directory_path << '\n';
            }
            else
            {
                const DWORD last_error = GetLastError();
                result_directory_path = ".";
                std::cerr << "[DMK Filesystem ERROR] Failed to get current working directory."
                          << " Using relative path anchor '.'. Error: " << last_error << '\n';
            }
        }
        return result_directory_path;
    }
} // anonymous namespace

std::string DetourModKit::Filesystem::get_runtime_directory()
{
    // C++11 magic statics guarantee thread-safe, one-time initialization.
    // The module directory never changes at runtime, so caching is safe.
    static const std::string cached_directory = resolve_module_directory();
    return cached_directory;
}
