#ifndef DETOURMODKIT_MEMORY_INTERNAL_HPP
#define DETOURMODKIT_MEMORY_INTERNAL_HPP

/**
 * @file memory_internal.hpp
 * @brief Shared fault-handling primitives for the SEH-guarded foreign-read paths in memory.cpp and the scan engine.
 *
 * The probe paths that read foreign (host-owned) memory -- the pointer-chain walks in memory.cpp and the protection-
 * gated region/window sweeps in the scan engine -- all run their reads inside a Structured Exception Handling frame on
 * MSVC. They must agree on exactly which exception codes belong to such a read so the __except filters stay identical:
 * a single predicate keeps that set in one place and makes it unit-testable in isolation. The codes are spelled as
 * numeric literals (matching <winnt.h>) so this header stays free of <windows.h> and can be included by any TU. The
 * declarations are internal to the build and are NOT part of the installed public surface.
 */

#include <cstdint>

namespace DetourModKit
{
    namespace Memory
    {
        namespace detail
        {
            /**
             * @brief True when @p exception_code is a fault a guarded foreign read may legitimately raise and must
             *        swallow (reporting read failure) rather than let escape and terminate the host.
             * @details The accepted set, spelled as literals so this header needs no <windows.h>:
             *          - 0xC0000005 EXCEPTION_ACCESS_VIOLATION  -- the page is unmapped / PAGE_NOACCESS, or the access
             *            collided with a concurrent decommit / reprotect after the probe's readability gate passed.
             *          - 0x80000001 STATUS_GUARD_PAGE_VIOLATION  -- first touch of a PAGE_GUARD page.
             *          - 0xC0000006 EXCEPTION_IN_PAGE_ERROR      -- a file-backed or image-mapped page failed to page
             *            in (for example an RTTI / section walk of a module whose backing view was invalidated).
             *            Omitting this code let the fault continue the handler search and terminate the host, violating
             *            the "false on any fault" contract every probe documents.
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

#if !defined(_MSC_VER) && defined(_WIN64)
            /**
             * @brief Runs @p fn(@p ctx) with the process-wide vectored read guard armed over [@p lo, @p hi).
             * @details MinGW x64 has no frame-based __try / __except, so a bulk in-place foreign read -- the scanner's
             *          memchr / SIMD region sweep -- cannot wrap itself in SEH the way the MSVC path does. This routes
             *          such a read through the same vectored exception handler, thread-local guard slot, and drain
             *          epoch the seh_read_bytes path uses: the guard is armed for [lo, hi), @p fn performs the read,
             *          and a guarded read fault (is_guarded_read_fault) inside that range is turned into a clean
             *          failure (the handler longjmps back) instead of terminating the host. @p fn must be a
             *          self-contained read with no resources that need unwinding, because a guarded fault abandons its
             *          frame via __builtin_longjmp without running destructors -- exactly the contract the copy-based
             *          guard relies on. When the handler could not be installed @p fn is not run; callers treat false
             *          as a skipped/faulted range and fail uniqueness-sensitive work closed.
             * @param lo First byte of the foreign range @p fn will read.
             * @param hi One past the last byte of that range. An empty or wrapping range (hi <= lo) runs @p fn
             *           directly because there is no foreign byte span to guard.
             * @param fn The read to perform; must be noexcept and must not throw.
             * @param ctx Opaque pointer forwarded to @p fn.
             * @return true if @p fn completed without a guarded read fault; false if a fault inside [lo, hi) was
             *         swallowed, in which case @p fn did not run to completion.
             */
            [[nodiscard]] bool run_guarded_region(std::uintptr_t lo, std::uintptr_t hi, void (*fn)(void *) noexcept,
                                                  void *ctx) noexcept;
#endif
        } // namespace detail
    } // namespace Memory
} // namespace DetourModKit

#endif // DETOURMODKIT_MEMORY_INTERNAL_HPP
