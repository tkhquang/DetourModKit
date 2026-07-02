/**
 * @file memory_module.cpp
 * @brief Module-presence and address-to-module queries: memory::module_of and memory::is_module_loaded.
 *
 * module_of answers "which loaded image owns this pointer, and what is its full mapped span?" by resolving the owning
 * module handle through the loader and reading its PE headers via the guarded read engine (so a partially-mapped or
 * corrupt image fails closed instead of faulting the host); results are cached per module handle for the process
 * lifetime. is_module_loaded answers "is a module with this base name present?" against the loader's own table rather
 * than a from-scratch enumeration.
 */

#include "DetourModKit/memory.hpp"
#include "internal/srw_shared_mutex.hpp"

#include <windows.h>

#include <cstdint>
#include <cwchar>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace DetourModKit
{
    namespace
    {
        using DetourModKit::detail::SrwSharedMutex;

        /**
         * @struct ModuleRangeCache
         * @brief Per-process cache mapping a loaded module handle to its resolved image Region.
         * @details Shared by detail::cached_module_image_region, and thus by both memory::module_of and the Region
         *          factories in region.cpp (host / own / module_named), so a repeated module-range query resolves
         *          against one cache rather than re-walking PE headers per caller. Consulted only by DetourModKit code
         *          that has already initialized its own subsystems, so the static-storage destruction order is a
         *          non-issue (no caller queries ranges from an atexit handler).
         *
         *          Lifetime tradeoff (intentional): entries live for the process lifetime and are NOT invalidated on
         *          module unload, so if a module unloads and the loader reuses its base address for a different module,
         *          a later query for that handle returns the stale span. This is accepted rather than defect: (1) the
         *          Region is a transient, non-owning scan scope, not an ownership claim, so pinning the module to keep
         *          the cache exact would violate that contract and leak references for modules the host wanted unloaded;
         *          (2) every consumer feeds the span to the guarded read/scan engine, so a stale (larger) span at worst
         *          over-scans into adjacent mappings whose faults are contained, never a crash or UB; (3) DMK resolves
         *          module ranges at init for images that do not unload mid-session (the host EXE, the mod's own DLL).
         *          The alternative -- hooking loader unload notifications to evict -- is disproportionate machinery for
         *          this fault-contained, rare (base-reuse-after-unload) case. Callers that must track a module across an
         *          unload/reload should resolve the range fresh at the point of use instead of caching a handle.
         */
        struct ModuleRangeCache
        {
            SrwSharedMutex mutex;
            std::unordered_map<HMODULE, Region> entries;
        };

        [[nodiscard]] ModuleRangeCache &module_range_cache() noexcept
        {
            static ModuleRangeCache cache;
            return cache;
        }
    } // namespace

    namespace detail
    {
        // The canonical module-base -> Region resolver (declared in internal/memory_guarded.hpp). Both region.cpp's
        // Region factories (host/module_named/own) and memory::module_of route through this one definition, so the
        // PE-header walk -- DOS magic, a bounded e_lfanew, the NT signature, and OptionalHeader.SizeOfImage -- has a
        // single source of truth. Reads go through the guarded engine (memory::read), so a partially-mapped or corrupt
        // image fails closed to an empty Region rather than faulting the host.
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

        Region cached_module_image_region(Address module_base) noexcept
        {
            if (!module_base)
            {
                return Region{};
            }

            // An HMODULE IS the mapped image's base address, so the base address is the natural per-module cache key.
            const HMODULE handle = reinterpret_cast<HMODULE>(module_base.raw());
            ModuleRangeCache &cache = module_range_cache();
            {
                std::shared_lock<SrwSharedMutex> lock(cache.mutex);
                const auto it = cache.entries.find(handle);
                if (it != cache.entries.end())
                {
                    return it->second;
                }
            }

            const Region range = module_image_region(module_base);
            if (!range.base || range.size == 0)
            {
                // Do not cache a failed resolve: a partially-mapped image that later completes, or a handle value a
                // freshly loaded module reuses, must stay resolvable on a later call.
                return Region{};
            }

            {
                try
                {
                    std::unique_lock<SrwSharedMutex> lock(cache.mutex);
                    // Another thread may have inserted between the shared and unique acquisitions; emplace keeps the
                    // first-resolved entry.
                    cache.entries.emplace(handle, range);
                }
                catch (const std::bad_alloc &)
                {
                    // Caching is a performance hint. Returning the freshly resolved range keeps this noexcept query
                    // useful under memory pressure instead of terminating the host.
                }
            }
            return range;
        }
    } // namespace detail

    namespace memory
    {
        namespace
        {
            /**
             * @brief Widens a UTF-8 module name to the UTF-16 the Win32 module APIs expect.
             * @return The widened name, or an empty string when the name is empty or the conversion measurement fails.
             */
            [[nodiscard]] std::wstring widen_module_name(std::string_view name) noexcept
            {
                if (name.empty())
                {
                    return std::wstring{};
                }
                const int wide_length =
                    ::MultiByteToWideChar(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), nullptr, 0);
                if (wide_length <= 0)
                {
                    return std::wstring{};
                }
                std::wstring wide_name(static_cast<std::size_t>(wide_length), L'\0');
                ::MultiByteToWideChar(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), wide_name.data(),
                                      wide_length);
                return wide_name;
            }
        } // namespace

        Region module_of(Address address) noexcept
        {
            if (!address)
            {
                return Region{};
            }

            // FROM_ADDRESS resolves the module that contains the address; UNCHANGED_REFCOUNT looks it up without taking
            // a reference, matching the transient-scope contract a Region keeps.
            HMODULE owning_module = nullptr;
            if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      address.as<LPCWSTR>(), &owning_module) ||
                owning_module == nullptr)
            {
                return Region{};
            }

            // The resolved image span is cached per module handle by cached_module_image_region, so a repeated probe of
            // the same module degenerates to this loader lookup plus a hash hit rather than re-walking the PE headers.
            return detail::cached_module_image_region(Address{owning_module});
        }

        bool is_module_loaded(std::string_view basename, bool case_insensitive) noexcept
        {
            const std::wstring wide_name = widen_module_name(basename);
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
