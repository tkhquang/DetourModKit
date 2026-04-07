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
     * Returns a wide string to preserve full Unicode fidelity on Windows.
     * Diagnostics are written to stderr rather than Logger because this
     * function executes during Logger construction (via generate_log_file_path),
     * and calling Logger::get_instance() here would deadlock on the magic-static
     * guard that is already held by the in-progress Logger singleton init.
     */
    std::wstring resolve_module_directory()
    {
        HMODULE h_self_module = nullptr;
        std::wstring result_directory_path;

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

            // Dynamic buffer to support paths longer than MAX_PATH
            DWORD buf_size = MAX_PATH;
            std::wstring module_path_buffer(buf_size, L'\0');

            constexpr DWORD MAX_MODULE_PATH = 32768;

            for (;;)
            {
                const DWORD path_length = GetModuleFileNameW(h_self_module, module_path_buffer.data(), buf_size);
                if (path_length == 0)
                {
                    const DWORD last_error = GetLastError();
                    throw std::runtime_error("GetModuleFileNameW failed to retrieve module path. Error: " + std::to_string(last_error));
                }
                if (path_length < buf_size)
                {
                    module_path_buffer.resize(path_length);
                    break;
                }
                if (buf_size >= MAX_MODULE_PATH)
                {
                    throw std::runtime_error("GetModuleFileNameW: path exceeds maximum supported length.");
                }
                // Buffer was too small, double and retry
                buf_size = (buf_size <= MAX_MODULE_PATH / 2) ? buf_size * 2 : MAX_MODULE_PATH;
                module_path_buffer.resize(buf_size, L'\0');
            }

            const std::filesystem::path module_full_path(module_path_buffer);
            result_directory_path = module_full_path.parent_path().wstring();
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
            DWORD cwd_len = GetCurrentDirectoryW(0, nullptr);
            std::wstring current_dir_buffer;

            if (cwd_len > 0)
            {
                current_dir_buffer.resize(cwd_len, L'\0');
                const DWORD written = GetCurrentDirectoryW(cwd_len, current_dir_buffer.data());
                if (written > 0 && written < cwd_len)
                {
                    current_dir_buffer.resize(written);
                }
                else if (written >= cwd_len)
                {
                    // Directory changed between calls, retry with new size
                    current_dir_buffer.resize(static_cast<size_t>(written) + 1, L'\0');
                    const DWORD retry = GetCurrentDirectoryW(written + 1, current_dir_buffer.data());
                    current_dir_buffer.resize(retry > 0 ? retry : 0);
                }
                else
                {
                    current_dir_buffer.clear();
                }
            }

            if (!current_dir_buffer.empty())
            {
                result_directory_path = std::filesystem::path(current_dir_buffer).wstring();
                std::cerr << "[DMK Filesystem WARNING] Using current working directory as fallback: "
                          << std::filesystem::path(result_directory_path).string() << '\n';
            }
            else
            {
                const DWORD last_error = GetLastError();
                result_directory_path = L".";
                std::cerr << "[DMK Filesystem ERROR] Failed to get current working directory."
                          << " Using relative path anchor '.'. Error: " << last_error << '\n';
            }
        }
        return result_directory_path;
    }
} // anonymous namespace

std::wstring DetourModKit::Filesystem::get_runtime_directory()
{
    // C++11 magic statics guarantee thread-safe, one-time initialization.
    // The module directory never changes at runtime, so caching is safe.
    static const std::wstring cached_directory = resolve_module_directory();
    return cached_directory;
}
