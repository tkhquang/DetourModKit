#include "DetourModKit/region.hpp"

#include "internal/memory_guarded.hpp"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace DetourModKit
{
    Region Region::host() noexcept
    {
        // GetModuleHandleW(nullptr) returns the base of the process image -- the host .exe the mod DLL was injected
        // into -- which is the default scan scope for a cascade that carries no explicit range. The base is resolved
        // to a full image span by the shared guarded PE resolver, cached per module handle so a repeated Region::host()
        // does not re-walk the PE headers (detail::cached_module_image_region).
        return detail::cached_module_image_region(Address{::GetModuleHandleW(nullptr)});
    }

    Region Region::own() noexcept
    {
        // Resolve the module that contains this function's own code. Because DetourModKit is a static library, the
        // address of Region::own lands inside whichever DLL/EXE linked it, so GetModuleHandleExW(FROM_ADDRESS, ...)
        // returns that consumer module rather than the process EXE. FROM_ADDRESS plus UNCHANGED_REFCOUNT looks the
        // handle up without taking a reference, matching the transient-scope contract every Region factory keeps.
        HMODULE owning_module = nullptr;
        if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                  reinterpret_cast<LPCWSTR>(&Region::own), &owning_module) ||
            owning_module == nullptr)
        {
            return Region{};
        }
        return detail::cached_module_image_region(Address{owning_module});
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
        // loaded. That is the correct contract here: a Region is a transient scan scope, not an ownership claim. The
        // resolved span is cached per module handle (detail::cached_module_image_region).
        return detail::cached_module_image_region(Address{::GetModuleHandleW(wide_name.c_str())});
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

        // lpMaximumApplicationAddress is the highest address usable by the process and is INCLUSIVE, so the half-open
        // Region must run one byte past it to actually contain that last address: size = (max - min) + 1. The guard
        // above guarantees max > min, and an application maximum is never UINTPTR_MAX, so the + 1 cannot overflow.
        return Region{Address{minimum_address}, static_cast<std::size_t>(maximum_address - minimum_address) + 1U};
    }
} // namespace DetourModKit
