#ifndef DETOURMODKIT_INTERNAL_MEMORY_FAULT_HPP
#define DETOURMODKIT_INTERNAL_MEMORY_FAULT_HPP

/**
 * @file memory_fault.hpp
 * @brief Shared fault-handling primitives for the SEH-guarded foreign-read paths in the memory engine and the scanner.
 *
 * The probe paths that read foreign (host-owned) memory -- the pointer-chain walks and guarded byte copies in the
 * memory engine, and the protection-gated region / window sweeps in the scan engine -- all run their reads inside a
 * Structured Exception Handling frame on MSVC. They must agree on exactly which exception codes belong to such a read
 * so the __except filters stay identical: a single predicate keeps that set in one place and makes it unit-testable in
 * isolation. The codes are spelled as numeric literals (matching <winnt.h>) so this header stays free of <windows.h>
 * and can be included by any translation unit. These declarations are internal to the build and are NEVER part of the
 * installed public surface, so they live under src/internal/ rather than include/.
 */

#include <cstdint>

#if defined(_MSC_VER)
// Forward-declared at global scope so this header stays free of <windows.h>. ::_EXCEPTION_POINTERS is the Win32 SEH
// structure GetExceptionInformation() yields; every translation unit that calls guarded_fault_filter includes
// <windows.h>, which supplies the full definition. Declaring the tag at global scope (not inside a namespace) keeps
// the parameter type identical to the pointer the __except call sites pass.
struct _EXCEPTION_POINTERS;
#endif

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @brief True when @p exception_code is a fault a guarded foreign read may legitimately raise and must swallow
         *        (reporting read failure) rather than let escape and terminate the host.
         * @details The accepted set, spelled as literals so this header needs no <windows.h>:
         *          - 0xC0000005 EXCEPTION_ACCESS_VIOLATION  -- the page is unmapped / PAGE_NOACCESS, or the access
         *            collided with a concurrent decommit / reprotect after the probe's readability gate passed.
         *          - 0x80000001 STATUS_GUARD_PAGE_VIOLATION  -- first touch of a PAGE_GUARD page.
         *          - 0xC0000006 EXCEPTION_IN_PAGE_ERROR      -- a file-backed or image-mapped page failed to page in
         *            (for example an RTTI / section walk of a module whose backing view was invalidated). Omitting this
         *            code would let the fault continue the handler search and terminate the host, violating the "false
         *            on any fault" contract every probe documents.
         *          Any other code (illegal instruction, breakpoint, stack overflow, ...) did not originate from the
         *          probe's own read, so the filter must continue the search and let the host's real handler see it.
         * @param exception_code The value returned by GetExceptionCode() inside an __except filter.
         * @return true to execute the handler (swallow and fail closed); false to continue the search.
         */
        [[nodiscard]] constexpr bool is_guarded_read_fault(unsigned long exception_code) noexcept
        {
            return exception_code == 0xC0000005ul     // EXCEPTION_ACCESS_VIOLATION
                   || exception_code == 0x80000001ul  // STATUS_GUARD_PAGE_VIOLATION
                   || exception_code == 0xC0000006ul; // EXCEPTION_IN_PAGE_ERROR
        }

#if defined(_MSC_VER)
        /**
         * @brief The complete __except filter for a frame-based guarded foreign read: claim exactly the guarded-read
         *        fault set and re-arm a consumed PAGE_GUARD before the handler runs.
         * @param info The EXCEPTION_POINTERS from GetExceptionInformation() (valid only inside a filter expression).
         * @return EXCEPTION_EXECUTE_HANDLER to swallow and fail the read closed -- after re-arming the host's
         *         guard-page fence if the OS cleared it on dispatch -- or EXCEPTION_CONTINUE_SEARCH when the fault is
         *         not one a guarded read owns.
         * @details One filter shared by every MSVC frame-based probe -- the memory engine's guarded read / write /
         *          chain walk and the scanner's protection-gated region / window sweeps -- so both the claimed fault
         *          set and the guard-page re-arm stay identical across them. A bare
         *          `is_guarded_read_fault(GetExceptionCode())` predicate at a call site swallows a
         *          STATUS_GUARD_PAGE_VIOLATION WITHOUT restoring the PAGE_GUARD the OS consumed on dispatch,
         *          permanently disarming a foreign guard page the host meant to keep armed (a fail-open); routing
         *          every filter through this one entry closes that gap everywhere. The value lives in the single SEH
         *          engine translation unit (memory_guarded.cpp), so each __except stays a one-call filter
         *          expression. Declared MSVC-only because MinGW has no frame-based SEH; its probes route through the
         *          vectored handler, which re-arms on the same path.
         */
        long guarded_fault_filter(::_EXCEPTION_POINTERS *info) noexcept;

        /**
         * @brief The range-aware __except filter for a guarded foreign read/write over a known [@p lo, @p hi) span.
         * @param info The EXCEPTION_POINTERS from GetExceptionInformation() (valid only inside a filter expression).
         * @param lo First byte of the declared foreign range the operation is permitted to fault inside.
         * @param hi One past the last byte of that range.
         * @return EXCEPTION_EXECUTE_HANDLER only when the fault is a guarded-read fault whose faulting address lies in
         *         [@p lo, @p hi) -- after re-arming a consumed PAGE_GUARD; EXCEPTION_CONTINUE_SEARCH otherwise.
         * @details The memory engine's guarded byte read/write knows the exact foreign span it touches, so unlike the
         *          scanner's whole-region @ref guarded_fault_filter it also screens the faulting address: a fault
         *          OUTSIDE the declared span (an unrelated DMK defect that happens to occur inside the __try, or a fault
         *          on the caller-owned source/destination buffer rather than the foreign target) is NOT swallowed and
         *          reaches the host's handlers. This matches the MinGW vectored handler, which arms only [lo, hi) and
         *          passes through a fault outside it. A record carrying no faulting address is never claimed.
         */
        long guarded_range_fault_filter(::_EXCEPTION_POINTERS *info, std::uintptr_t lo, std::uintptr_t hi,
                                        volatile std::uintptr_t *fault_address = nullptr) noexcept;
#endif

#if !defined(_MSC_VER) && defined(_WIN64)
        /**
         * @brief Runs @p fn(@p ctx) with the process-wide vectored read guard armed over [@p lo, @p hi).
         * @details MinGW x64 has no frame-based __try / __except, so a bulk in-place foreign read -- the scanner's
         *          memchr / SIMD region sweep -- cannot wrap itself in SEH the way the MSVC path does. This routes such
         *          a read through the same vectored exception handler, thread-local guard slot, and drain epoch the
         *          guarded byte-copy path uses: the guard is armed for [lo, hi), @p fn performs the read, and a guarded
         *          read fault (is_guarded_read_fault) inside that range is turned into a clean failure (the handler
         *          longjmps back) instead of terminating the host. @p fn must be a self-contained read with no resources
         *          that need unwinding, because a guarded fault abandons its frame via __builtin_longjmp without running
         *          destructors -- exactly the contract the copy-based guard relies on. When the handler could not be
         *          installed @p fn is not run; callers treat false as a skipped/faulted range and fail
         *          uniqueness-sensitive work closed.
         * @param lo First byte of the foreign range @p fn will read.
         * @param hi One past the last byte of that range. An empty or wrapping range (hi <= lo) runs @p fn directly
         *           because there is no foreign byte span to guard.
         * @param fn The read to perform; must be noexcept and must not throw.
         * @param ctx Opaque pointer forwarded to @p fn.
         * @return true if @p fn completed without a guarded read fault; false if a fault inside [lo, hi) was swallowed,
         *         in which case @p fn did not run to completion.
         */
        [[nodiscard]] bool run_guarded_region(std::uintptr_t lo, std::uintptr_t hi, void (*fn)(void *) noexcept,
                                              void *ctx) noexcept;
#endif
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_MEMORY_FAULT_HPP
