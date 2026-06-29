#include "DetourModKit/region.hpp"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace DetourModKit
{
    namespace
    {
        /**
         * @brief Reads the mapped image size (PE SizeOfImage) of a loaded module from its in-memory headers.
         * @param module_handle Loaded module base, as returned by GetModuleHandleW.
         * @return The SizeOfImage in bytes, or 0 when the handle is null or its PE headers do not validate.
         * @details A loaded HMODULE points at the module's IMAGE_DOS_HEADER. Its `e_lfanew` field gives the byte
         *          offset from that base to the IMAGE_NT_HEADERS, whose OptionalHeader.SizeOfImage is the contiguous
         *          virtual span the loader reserved for the whole image (headers + all sections). That is exactly the
         *          Region a scan over "this module" should cover. Both signatures are checked first so a bogus or
         *          partially-mapped handle fails closed to 0 instead of reading past unmapped memory.
         */
        [[nodiscard]] std::size_t module_image_size(HMODULE module_handle) noexcept
        {
            if (module_handle == nullptr)
            {
                return 0;
            }

            const auto *dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(module_handle);
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return 0;
            }

            const auto *nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(
                reinterpret_cast<const std::byte *>(module_handle) + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
            {
                return 0;
            }

            return static_cast<std::size_t>(nt_headers->OptionalHeader.SizeOfImage);
        }

        /**
         * @brief Builds a Region covering a loaded module's full mapped image, failing closed to an empty Region.
         * @param module_handle Loaded module base, or null.
         * @return The module image span, or an empty Region when the handle is null or its headers do not validate.
         */
        [[nodiscard]] Region region_for_module(HMODULE module_handle) noexcept
        {
            const std::size_t image_size = module_image_size(module_handle);
            if (image_size == 0)
            {
                return Region{};
            }
            return Region{Address{module_handle}, image_size};
        }
    } // namespace

    Region Region::host() noexcept
    {
        // GetModuleHandleW(nullptr) returns the base of the process image -- the host .exe the mod DLL was injected
        // into -- which is the default scan scope for a cascade that carries no explicit range.
        return region_for_module(::GetModuleHandleW(nullptr));
    }

    Region Region::module_named(std::string_view name) noexcept
    {
        if (name.empty())
        {
            return Region{};
        }

        // Widen the UTF-8 module name to the UTF-16 the Win32 W API expects. A zero/failed measurement (malformed
        // UTF-8) or an unloaded module both fall through to an empty Region, so a bad name never throws or scans.
        const int wide_length =
            ::MultiByteToWideChar(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), nullptr, 0);
        if (wide_length <= 0)
        {
            return Region{};
        }

        std::wstring wide_name(static_cast<std::size_t>(wide_length), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), wide_name.data(), wide_length);

        // GetModuleHandleW does not add a reference, so the returned handle is only valid while the module stays
        // loaded. That is the correct contract here: a Region is a transient scan scope, not an ownership claim.
        return region_for_module(::GetModuleHandleW(wide_name.c_str()));
    }

    Region Region::whole_process() noexcept
    {
        // Span the user-mode virtual-address window the OS reports for this process rather than hardcoding the
        // canonical x64 0x7FFF'FFFFFFFF ceiling, so the Region stays correct regardless of address-layout settings.
        SYSTEM_INFO system_info{};
        ::GetSystemInfo(&system_info);

        const auto minimum_address = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
        const auto maximum_address = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);
        if (maximum_address <= minimum_address)
        {
            return Region{};
        }

        return Region{Address{minimum_address}, static_cast<std::size_t>(maximum_address - minimum_address)};
    }
} // namespace DetourModKit
