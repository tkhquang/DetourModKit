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

        // A declared function must be long enough for EITHER patch form, because which one runs is decided inside the
        // backend after this returns: the near jump needs BACKEND_MIN_PATCH bytes, the indirect fallback needs
        // BACKEND_FALLBACK_MIN_PATCH. Checking only the near jump would admit a function the fallback overwrites past
        // its end, silently corrupting whatever follows, and the fallback is chosen exactly when the trampoline cannot
        // be allocated nearby -- a condition this code cannot predict. Requiring the larger minimum refuses a short
        // function the near jump would have hooked safely; that costs a typed error, where guessing costs the host.
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
            return "the target function is shorter than the smallest patch the backend writes";
        case TargetWindowVerdict::Ok:
            return "the target is hookable";
        }
        return "the target is hookable";
    }
} // namespace DetourModKit
