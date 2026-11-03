#include "internal/hook_fault_boundary.hpp"

#include "internal/memory_guarded.hpp"
#include "internal/scan_pages.hpp"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace DetourModKit
{
    std::optional<detail::FunctionBound> detail::unwind_bound(std::uintptr_t target) noexcept
    {
        DWORD64 image_base = 0;
        const PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(target, &image_base, nullptr);
        if (entry == nullptr || image_base == 0)
        {
            return std::nullopt;
        }

        RUNTIME_FUNCTION record{};
        if (!guarded_read_bytes(reinterpret_cast<std::uintptr_t>(entry), &record, sizeof(record)))
        {
            return std::nullopt;
        }
        if (record.EndAddress <= record.BeginAddress)
        {
            return std::nullopt;
        }
        const auto base = static_cast<std::uintptr_t>(image_base);
        if (record.BeginAddress > UINTPTR_MAX - base || record.EndAddress > UINTPTR_MAX - base)
        {
            return std::nullopt;
        }
        const FunctionBound bound{base + record.BeginAddress, base + record.EndAddress};
        if (target < bound.lo || target >= bound.hi)
        {
            return std::nullopt;
        }
        return bound;
    }

    namespace
    {
        /// The protection granularity of a mapped section on x86-64 Windows.
        constexpr std::uintptr_t SECTION_PAGE_BYTES = 0x1000;

        /**
         * @brief Reports whether every page of [address, address + size) is committed image memory that is readable
         *        and either executable or writable.
         * @details A patch window writes its page, so it leaves the page writable. A guard, no-access, read-only, or
         *          execute-only page keeps that protection until its owner changes it, so it is never a patch window.
         */
        [[nodiscard]] bool image_pages_patchable(std::uintptr_t address, std::size_t size) noexcept
        {
            constexpr DWORD PATCHABLE_PAGE_FLAGS =
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READWRITE | PAGE_WRITECOPY;
            if (size > UINTPTR_MAX - address)
            {
                return false;
            }
            const std::uintptr_t end = address + size;
            for (std::uintptr_t cursor = address; cursor < end;)
            {
                MEMORY_BASIC_INFORMATION region{};
                if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &region, sizeof(region)) != sizeof(region) ||
                    region.State != MEM_COMMIT || region.Type != MEM_IMAGE ||
                    (region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 ||
                    (region.Protect & PATCHABLE_PAGE_FLAGS) == 0)
                {
                    return false;
                }
                const std::uintptr_t region_end =
                    reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize;
                if (region_end <= cursor)
                {
                    return false;
                }
                cursor = region_end;
            }
            return true;
        }

        /// Reports whether every byte of [address, address + size) lies in an executable section of one mapped image.
        [[nodiscard]] bool image_sections_execute(std::uintptr_t address, std::size_t size) noexcept
        {
            MEMORY_BASIC_INFORMATION region{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &region, sizeof(region)) != sizeof(region) ||
                region.State != MEM_COMMIT || region.Type != MEM_IMAGE)
            {
                return false;
            }
            const auto base = reinterpret_cast<std::uintptr_t>(region.AllocationBase);
            IMAGE_DOS_HEADER dos{};
            if (!detail::guarded_read_bytes(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
                dos.e_lfanew <= 0)
            {
                return false;
            }
            const std::uintptr_t nt = base + static_cast<std::uintptr_t>(dos.e_lfanew);
            DWORD signature = 0;
            IMAGE_FILE_HEADER file{};
            if (!detail::guarded_read_bytes(nt, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
                !detail::guarded_read_bytes(nt + sizeof(signature), &file, sizeof(file)))
            {
                return false;
            }
            const std::uintptr_t table = nt + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + file.SizeOfOptionalHeader;
            // Section headers ascend by address, so one pass covers a window that spans two adjacent sections.
            std::uintptr_t cursor = address - base;
            const std::uintptr_t end = cursor + size;
            for (WORD index = 0; index < file.NumberOfSections && cursor < end; ++index)
            {
                IMAGE_SECTION_HEADER section{};
                if (!detail::guarded_read_bytes(table + index * sizeof(section), &section, sizeof(section)))
                {
                    return false;
                }
                const std::uintptr_t begin = section.VirtualAddress;
                const std::uintptr_t extent =
                    (static_cast<std::uintptr_t>(section.Misc.VirtualSize) + SECTION_PAGE_BYTES - 1) &
                    ~(SECTION_PAGE_BYTES - 1);
                if (cursor < begin || cursor - begin >= extent)
                {
                    continue;
                }
                if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                {
                    return false;
                }
                cursor = begin + extent;
            }
            return cursor >= end;
        }
    } // namespace

    detail::TargetWindowResult detail::validate_backend_steal_window(std::uintptr_t target) noexcept
    {
        // The backend decodes forward with no region bound, so the whole window must be executable and committed.
        if (!is_executable_range(target, BACKEND_MAX_STEAL_WINDOW))
        {
            // Code runs only from executable pages, so a patcher restores execute access to an image section that
            // carries it before that code runs again.
            const TargetWindowVerdict verdict = image_pages_patchable(target, BACKEND_MAX_STEAL_WINDOW) &&
                                                        image_sections_execute(target, BACKEND_MAX_STEAL_WINDOW)
                                                    ? TargetWindowVerdict::PatchInFlight
                                                    : TargetWindowVerdict::NotExecutable;
            return TargetWindowResult{verdict, target};
        }

        // Only a guarded touch finds a guard page or a backing store that fails to fault in.
        std::array<std::uint8_t, BACKEND_MAX_STEAL_WINDOW> window{};
        volatile std::uintptr_t fault_address = target;
        if (!guarded_read_bytes(target, window.data(), window.size(), &fault_address))
        {
            return TargetWindowResult{TargetWindowVerdict::Unreadable, fault_address};
        }

        // The fallback can write more bytes than the near jump, and the backend picks the form after this check.
        const std::optional<FunctionBound> bound = unwind_bound(target);
        if (bound && target + BACKEND_FALLBACK_MIN_PATCH > bound->hi)
        {
            return TargetWindowResult{TargetWindowVerdict::BoundOverrun, bound->hi};
        }

        return TargetWindowResult{TargetWindowVerdict::Ok, target};
    }

    std::string_view detail::target_window_description(TargetWindowVerdict verdict) noexcept
    {
        switch (verdict)
        {
        case TargetWindowVerdict::NotExecutable:
            return "the bytes the backend decodes are not all executable committed memory";
        case TargetWindowVerdict::Unreadable:
            return "the bytes the backend decodes are not all readable";
        case TargetWindowVerdict::BoundOverrun:
            return "the target function is shorter than the largest patch minimum the backend may select";
        case TargetWindowVerdict::PatchInFlight:
            return "a patch window outside the process coordinator holds the target page without execute access";
        case TargetWindowVerdict::Ok:
            return "the target is hookable";
        }
        return "the target is hookable";
    }

    detail::ObjectWordResult detail::validate_vmt_object_word(std::uintptr_t object) noexcept
    {
        // Readability first, and by touching rather than querying: VirtualQuery cannot report that a guard page will
        // trap the first access.
        volatile std::uintptr_t fault_address = object;
        std::uintptr_t vptr = 0;
        if (!guarded_read_bytes(object, &vptr, sizeof(vptr), &fault_address))
        {
            return ObjectWordResult{ObjectWordVerdict::Unreadable, fault_address, 0};
        }

        // Readable does not imply writable. There is no non-mutating write probe, so ask the OS and let the later
        // fault-contained publication compare-exchange close a displacement/protection/unmap race.
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(object), &info, sizeof(info)) != sizeof(info))
        {
            return ObjectWordResult{ObjectWordVerdict::NotWritable, object, vptr};
        }
        if (info.State != MEM_COMMIT)
        {
            return ObjectWordResult{ObjectWordVerdict::NotWritable, object, vptr};
        }
        // A guard armed before the read already failed it closed above. This catches one armed since: PAGE_GUARD traps
        // the first access to a page whose protection otherwise reads as writable, so the word is not publishable even
        // though its protection bits say it is.
        if ((info.Protect & PAGE_GUARD) != 0)
        {
            return ObjectWordResult{ObjectWordVerdict::NotWritable, object, vptr};
        }
        constexpr DWORD WRITABLE_PROTECTIONS =
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if ((info.Protect & WRITABLE_PROTECTIONS) == 0)
        {
            return ObjectWordResult{ObjectWordVerdict::NotWritable, object, vptr};
        }

        // The word must not straddle two regions with different protections: VirtualQuery reports the region containing
        // the first byte, so a pointer-sized word ending in a read-only neighbour would pass on its first byte alone.
        // VirtualQuery places @p object inside the region it reports, so measuring the remainder as an offset from the
        // region base keeps this arithmetic wrap-free without trusting the reported bounds not to overflow.
        const std::uintptr_t offset_in_region = object - reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        if (static_cast<std::uintptr_t>(info.RegionSize) - offset_in_region < sizeof(std::uintptr_t))
        {
            return ObjectWordResult{ObjectWordVerdict::NotWritable, object, vptr};
        }

        return ObjectWordResult{ObjectWordVerdict::Ok, object, vptr};
    }
} // namespace DetourModKit
