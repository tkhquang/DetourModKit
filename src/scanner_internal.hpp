#ifndef DETOURMODKIT_SCANNER_INTERNAL_HPP
#define DETOURMODKIT_SCANNER_INTERNAL_HPP

/**
 * @file scanner_internal.hpp
 * @brief Shared module-scoped scan primitives for the scanner.cpp, scanner_cascade.cpp, and string_xref.cpp TUs.
 *
 * The cascade resolver and the string-xref backend each live in their own translation unit but still need to search a
 * single mapped image. These entry points expose that capability without leaking the Windows page-protection
 * masks: the scan_module_* mask choice (code-only vs. all-readable pages) is
 * encoded in the function name, and collect_executable_windows centralizes the executable-page gate, so
 * scan_regions_filtered and the PAGE_* constants stay private to scanner.cpp. The declarations are internal to the
 * build and are
 * NOT part of the installed public surface.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace DetourModKit
{
    namespace Scanner
    {
        namespace detail
        {
            /**
             * @brief Module-scoped scan over the image's execute-readable pages.
             * @details Searches only [range.base, range.end) and only the
             *          PAGE_EXECUTE_READ / _READWRITE / _WRITECOPY pages, so a match can only land on code. Used by the
             *          prologue-recovery fallback, whose rebuilt near-JMP can overwrite only a code prologue. Returns
             *          the Nth match (1-based, adjusted by pattern.offset) or nullptr.
             */
            [[nodiscard]] const std::byte *scan_module_executable(const CompiledPattern &pattern,
                                                                  Memory::ModuleRange range,
                                                                  std::size_t occurrence = 1) noexcept;

            /**
             * @brief Module-scoped scan over every readable page of the image.
             * @details Superset of @ref scan_module_executable that also accepts the non-executable readable pages
             *          (.rdata / .data), so a single pass covers both code and data candidates. This is why the
             *          in-module cascade needs no ScannerKind distinction. Returns the Nth match (1-based, adjusted by
             *          pattern.offset) or nullptr.
             */
            [[nodiscard]] const std::byte *scan_module_readable(const CompiledPattern &pattern,
                                                                Memory::ModuleRange range,
                                                                std::size_t occurrence = 1) noexcept;

            /**
             * @struct ExecutableWindow
             * @brief One committed, execute-readable slice of a module image.
             * @details @ref base / @ref span describe live, directly-readable
             *          bytes: the region passed the same VirtualQuery protection
             *          gate the whole-process scanners apply (MEM_COMMIT, an execute-readable base protection, not
             *          PAGE_GUARD /
             *          PAGE_NOACCESS), so a caller may read [base, base + span) without a fault guard, exactly as
             *          scan_regions_filtered does.
             */
            struct ExecutableWindow
            {
                /// Absolute address of the first readable byte.
                std::uintptr_t base = 0;
                /// Window length in bytes.
                std::size_t span = 0;
            };

            /**
             * @brief Collects the execute-readable windows of a module image.
             * @details Walks [range.base, range.end) via VirtualQuery and returns each committed, execute-readable
             *          region clamped to that range, applying the identical page-protection gate @ref
             *          scan_module_executable uses. This centralizes that gate so an out-of-TU caller (the string-xref
             *          backend in string_xref.cpp) scans the image's code without re-deriving the Windows page masks.
             * @param range The mapped image to walk.
             * @return The execute-readable windows in ascending address order;
             *         empty when @p range is invalid or the image exposes no readable code pages.
             */
            [[nodiscard]] std::vector<ExecutableWindow> collect_executable_windows(Memory::ModuleRange range);

            /**
             * @brief True when @p address lies on a committed, execute-readable page.
             * @details Single-address VirtualQuery gate using the same page-protection set the module and
             *          whole-process executable scans accept (PAGE_EXECUTE_READ / _READWRITE / _WRITECOPY, MEM_COMMIT,
             *          neither PAGE_GUARD nor PAGE_NOACCESS). The prologue-recovery fallback validates a decoded E9
             *          destination with it: a sibling mod's inline-hook trampoline is VirtualAlloc'd outside every
             *          loaded module, so an in-module requirement would reject the exact recovery this path performs,
             *          while this test still rejects a jump into unmapped or data-only memory. Centralizing it here
             *          keeps the Windows page masks private to scanner.cpp.
             * @param address Absolute address to test.
             * @return true when the page is committed and execute-readable; false otherwise, including an unmapped
             *         address (VirtualQuery failure) or a guard / no-access page.
             */
            [[nodiscard]] bool is_executable_address(std::uintptr_t address) noexcept;
        } // namespace detail
    } // namespace Scanner
} // namespace DetourModKit

#endif // DETOURMODKIT_SCANNER_INTERNAL_HPP
