#ifndef DETOURMODKIT_INTERNAL_MEMORY_FAULT_HPP
#define DETOURMODKIT_INTERNAL_MEMORY_FAULT_HPP

/**
 * @file memory_fault.hpp
 * @brief Shared fault-handling primitives for SEH-guarded foreign-memory operations and scanner sweeps.
 *
 * Foreign reads, writes, compare-exchange operations, and protection-gated scanner sweeps all run inside a Structured
 * Exception Handling frame on MSVC. Their filters must agree on which codes belong to an access within the guarded
 * span. A single predicate keeps that rule consistent and unit-testable. The codes use numeric literals matching
 * <winnt.h> so this header remains free of <windows.h>. These declarations are internal to the build and are never
 * installed.
 */

#include <cstdint>

#if defined(_MSC_VER)
// Forward-declared at global scope so this header stays free of <windows.h>. ::_EXCEPTION_POINTERS is the Win32 SEH
// structure GetExceptionInformation() yields; every translation unit that calls the filter includes <windows.h>,
// which supplies the full definition. Declaring the tag at global scope (not inside a namespace) keeps the parameter
// type identical to the pointer the __except call sites pass.
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
         *          - 0xC0000005 EXCEPTION_ACCESS_VIOLATION:   the page is unmapped / PAGE_NOACCESS, or the access
         *            collided with a concurrent decommit / reprotect after the probe's readability gate passed.
         *          - 0x80000001 STATUS_GUARD_PAGE_VIOLATION:  first touch of a PAGE_GUARD page.
         *          - 0xC0000006 EXCEPTION_IN_PAGE_ERROR:      a file-backed or image-mapped page failed to page in
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
         * @brief The __except filter every MSVC frame-based guarded foreign access uses, over a known [@p lo, @p hi)
         *        span.
         * @param info The EXCEPTION_POINTERS from GetExceptionInformation() (valid only inside a filter expression).
         * @param lo First byte of the declared foreign range the operation is permitted to fault inside.
         * @param hi One past the last byte of that range.
         * @param fault_address Optional output assigned only when the fault is claimed.
         * @return EXCEPTION_EXECUTE_HANDLER only when the fault is a guarded-read fault whose faulting address lies in
         *         [@p lo, @p hi) and a consumed PAGE_GUARD was re-armed; EXCEPTION_CONTINUE_SEARCH otherwise.
         * @details Screening the faulting address is what keeps a fault OUTSIDE the declared span reaching the host's
         *          handlers instead of being silently swallowed. An outside fault is an unrelated DMK defect that
         *          happens to occur inside the __try, or a fault on the caller-owned source/destination buffer rather
         *          than the foreign target. This matches the MinGW vectored handler, which arms only [lo, hi) and
         *          passes through a fault outside it. Re-arming a PAGE_GUARD the OS cleared on dispatch, before the
         *          access fails closed, is what stops a swallowed foreign guard-page fault from leaving the host's
         *          fence disarmed. Routing every MSVC probe (the memory engine's read / write / chain walk and the
         *          scanner's region / window sweeps) through this one entry keeps that behavior identical across them.
         *          A record carrying no faulting address, or a guard-page fault whose fence cannot be restored, is
         *          never claimed. Declared MSVC-only because MinGW has no frame-based SEH.
         */
        long guarded_range_fault_filter(
            ::_EXCEPTION_POINTERS *info,
            std::uintptr_t lo,
            std::uintptr_t hi,
            volatile std::uintptr_t *fault_address = nullptr
        ) noexcept;
#endif

#if !defined(_MSC_VER) && defined(_WIN64)
        /**
         * @brief Runs @p fn(@p ctx) with the process-wide vectored read guard armed over [@p lo, @p hi).
         * @details MinGW x64 has no frame-based __try / __except, so a bulk in-place foreign read (the scanner's
         *          memchr / SIMD region sweep) cannot wrap itself in SEH the way the MSVC path does. This routes such
         *          a read through the same vectored exception handler, thread-local guard slot, and drain epoch the
         *          guarded byte-copy path uses: the guard is armed for [lo, hi), @p fn performs the read, and a guarded
         *          read fault (is_guarded_read_fault) inside that range is turned into a clean failure (the handler
         *          longjmps back) instead of terminating the host. @p fn must be a self-contained read with no
         *          resources that need unwinding, because a guarded fault abandons its frame via __builtin_longjmp
         *          without running destructors. That is exactly the contract the copy-based guard relies on. When the
         *          handler cannot be installed @p fn is not run. Callers treat false as a skipped/faulted range and
         *          fail uniqueness-sensitive work closed.
         * @param lo First byte of the foreign range @p fn will read.
         * @param hi One past the last byte of that range. An empty or wrapping range (hi <= lo) runs @p fn directly
         *           because there is no foreign byte span to guard.
         * @param fn The read to perform; must be noexcept and must not throw.
         * @param ctx Opaque pointer forwarded to @p fn.
         * @return true if @p fn completed without a guarded read fault; false if a fault inside [lo, hi) was swallowed,
         *         in which case @p fn did not run to completion.
         */
        [[nodiscard]] bool
        run_guarded_region(std::uintptr_t lo, std::uintptr_t hi, void (*fn)(void *) noexcept, void *ctx) noexcept;
#endif
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_MEMORY_FAULT_HPP
