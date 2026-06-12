#ifndef DETOURMODKIT_MEMORY_INTERNAL_HPP
#define DETOURMODKIT_MEMORY_INTERNAL_HPP

/**
 * @file memory_internal.hpp
 * @brief Shared fault-handling primitives for the SEH-guarded foreign-read paths in memory.cpp, scanner.cpp, and
 *        string_xref.cpp.
 *
 * The probe paths that read foreign (host-owned) memory -- the pointer-chain walks in memory.cpp and the protection-
 * gated region/window sweeps in scanner.cpp and string_xref.cpp -- all run their reads inside a Structured Exception
 * Handling frame on MSVC. They must agree on exactly which exception codes belong to such a read so the __except
 * filters stay identical: a single predicate keeps that set in one place and makes it unit-testable in isolation. The
 * codes are spelled as numeric literals (matching <winnt.h>) so this header stays free of <windows.h> and can be
 * included by any TU -- mirroring the way scanner_internal.hpp keeps the Windows page-protection masks private to
 * scanner.cpp. The declarations are internal to the build and are NOT part of the installed public surface.
 */

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
        } // namespace detail
    } // namespace Memory
} // namespace DetourModKit

#endif // DETOURMODKIT_MEMORY_INTERNAL_HPP
