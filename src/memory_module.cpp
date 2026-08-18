/**
 * @file memory_module.cpp
 * @brief Module-presence and address-to-module queries: memory::module_of and memory::is_module_loaded.
 *
 * module_of answers "which loaded image owns this pointer, and what is its full mapped span?" by resolving the owning
 * module handle through the loader and reading its PE headers via the guarded read engine, so a partially-mapped or
 * corrupt image fails closed instead of faulting the host. is_module_loaded answers "is a module with this base name
 * present?" against the loader's own table rather than a from-scratch enumeration.
 */

#include "DetourModKit/memory.hpp"
#include "internal/memory_representation_win32.hpp"
#include "internal/module_name.hpp"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <string>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        // The canonical module-base -> Region resolver (declared in internal/memory_guarded.hpp). Both region.cpp's
        // Region factories (host/module_named/own) and memory::module_of route through this one definition, so the
        // PE-header walk (DOS magic, a bounded e_lfanew, the NT signature, and OptionalHeader.SizeOfImage) has a
        // single source of truth. Reads go through the guarded engine (memory::read), so a partially-mapped or corrupt
        // image fails closed to an empty Region rather than faulting the host. The walk is repeated per call rather
        // than memoized per handle: an HMODULE IS its image base and Windows reuses it after an unload, so any cached
        // span is a claim about an identity the loader can reassign, and a completed same-base replacement carrying a
        // different SizeOfImage would keep serving the previous image's extent from this public query.
        Region module_image_region(Address module_base) noexcept
        {
            if (!module_base)
            {
                return Region{};
            }

            const auto dos = memory::read<IMAGE_DOS_HEADER>(module_base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return Region{};
            }

            // Bound e_lfanew. A genuine PE places its NT headers within the first few KiB; anything beyond a generous
            // 1 MiB cap is corrupt or hostile.
            if (dos->e_lfanew <= 0 || static_cast<std::uint32_t>(dos->e_lfanew) > 0x100000U)
            {
                return Region{};
            }

            const auto nt = memory::read<IMAGE_NT_HEADERS>(module_base.offset(dos->e_lfanew));
            if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return Region{};
            }

            const std::size_t size_of_image = static_cast<std::size_t>(nt->OptionalHeader.SizeOfImage);
            if (size_of_image == 0)
            {
                return Region{};
            }

            return Region{module_base, size_of_image};
        }

        Region live_module_region(Address address) noexcept
        {
            if (!address)
                return Region{};

            HMODULE owning_module = nullptr;
            if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      address.as<LPCWSTR>(), &owning_module) ||
                owning_module == nullptr)
                return Region{};
            return module_image_region(Address{owning_module});
        }
    } // namespace detail

    namespace memory
    {
        Region module_of(Address address) noexcept
        {
            return detail::live_module_region(address);
        }

        bool is_module_loaded(std::string_view basename, bool case_insensitive) noexcept
        {
            const std::wstring wide_name = detail::widen_module_name(basename);
            if (wide_name.empty())
            {
                return false;
            }

            // GetModuleHandleW performs a case-insensitive base-name (or path) match against the loader's table without
            // taking a reference, so the handle is safe to use immediately and is never an ownership claim.
            const HMODULE module_handle = ::GetModuleHandleW(wide_name.c_str());
            if (module_handle == nullptr)
            {
                return false;
            }
            if (case_insensitive)
            {
                return true;
            }

            // Case-sensitive request: the loader matched case-insensitively, so confirm the loaded module's actual base
            // name equals the requested spelling exactly. Pull the full path, isolate the base name, and compare.
            wchar_t module_path[MAX_PATH];
            const DWORD length = ::GetModuleFileNameW(module_handle, module_path, MAX_PATH);
            if (length == 0 || length >= MAX_PATH)
            {
                return false;
            }
            const std::wstring_view path_view{module_path, length};
            const std::size_t separator = path_view.find_last_of(L"\\/");
            const std::wstring_view actual_basename =
                (separator == std::wstring_view::npos) ? path_view : path_view.substr(separator + 1);
            return actual_basename == std::wstring_view{wide_name};
        }
    } // namespace memory
} // namespace DetourModKit
