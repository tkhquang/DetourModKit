#include "internal/hook_fault_boundary.hpp"

#include "internal/memory_guarded.hpp"
#include "internal/scan_pages.hpp"

#include <windows.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace DetourModKit
{
    namespace
    {
        /// A function's half-open extent as declared by its unwind metadata.
        struct FunctionBound
        {
            std::uintptr_t lo{0};
            std::uintptr_t hi{0};
        };

        // Resolves the unwind-declared extent of the function containing target, or nullopt when the target declares
        // none. Absence is the normal case for a leaf function or JIT-emitted code and is never treated as a refusal.
        //
        // The RUNTIME_FUNCTION the loader hands back points into the image's exception directory, which is ordinary
        // process memory that a concurrent unload can withdraw; it is copied under the fault guard rather than
        // dereferenced. A record whose extent is inverted or empty is discarded as untrustworthy.
        //
        // Only the directly registered entry is honoured. A chained entry names the primary fragment of a
        // hot/cold-split function, which is a different, non-contiguous span that does not contain target and is
        // therefore not a containment bound for it.
        std::optional<FunctionBound> unwind_bound(std::uintptr_t target) noexcept
        {
            DWORD64 image_base = 0;
            const PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(target, &image_base, nullptr);
            if (entry == nullptr || image_base == 0)
            {
                return std::nullopt;
            }

            RUNTIME_FUNCTION record{};
            if (!detail::guarded_read_bytes(reinterpret_cast<std::uintptr_t>(entry), &record, sizeof(record)))
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
    } // namespace

    detail::TargetWindowResult detail::validate_backend_steal_window(std::uintptr_t target) noexcept
    {
        // Executable and committed across the whole window. Stricter than testing the first byte: the backend decodes
        // forward without a region bound, so a prologue whose tail runs off the end of its executable region would let
        // the decoder consume an adjacent data page (or unmapped space) as instruction bytes.
        if (!is_executable_range(target, BACKEND_MAX_STEAL_WINDOW))
        {
            return TargetWindowResult{TargetWindowVerdict::NotExecutable, target};
        }

        // Executable-and-committed is not readable. VirtualQuery reports the protection the OS recorded; it cannot
        // report that a guard page will trap the first touch, or that a section's backing store will fail to fault in.
        // Touching the bytes under the guard is the only way to learn that, and it consults no protection cache, so it
        // cannot answer from a stale snapshot.
        std::array<std::uint8_t, BACKEND_MAX_STEAL_WINDOW> window{};
        volatile std::uintptr_t fault_address = target;
        if (!guarded_read_bytes(target, window.data(), window.size(), &fault_address))
        {
            return TargetWindowResult{TargetWindowVerdict::Unreadable, fault_address};
        }

        // Which patch form runs is decided after this check. The fallback can overwrite more bytes than the near jump,
        // so an unwind-bounded target must accommodate the fallback minimum even when the near form might be selected.
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
