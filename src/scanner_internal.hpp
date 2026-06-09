#ifndef DETOURMODKIT_SCANNER_INTERNAL_HPP
#define DETOURMODKIT_SCANNER_INTERNAL_HPP

/**
 * @file scanner_internal.hpp
 * @brief Shared module-scoped scan primitives for the scanner.cpp and
 *        scanner_cascade.cpp TUs.
 *
 * The cascade resolver lives in its own translation unit but still needs to
 * search a single mapped image. These two entry points expose that capability
 * without leaking the Windows page-protection masks: the mask choice (code-only
 * vs. all-readable pages) is encoded in the function name and kept private to
 * scanner.cpp, where scan_regions_filtered and the PAGE_* constants live. The
 * declarations are internal to the build and are NOT part of the installed
 * public surface.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

#include <cstddef>

namespace DetourModKit
{
    namespace Scanner
    {
        namespace detail
        {
            /**
             * @brief Module-scoped scan over the image's execute-readable pages.
             * @details Searches only [range.base, range.end) and only the
             *          PAGE_EXECUTE_READ / _READWRITE / _WRITECOPY pages, so a
             *          match can only land on code. Used by the prologue-recovery
             *          fallback, whose rebuilt near-JMP can overwrite only a code
             *          prologue. Returns the Nth match (1-based, adjusted by
             *          pattern.offset) or nullptr.
             */
            [[nodiscard]] const std::byte *scan_module_executable(
                const CompiledPattern &pattern, Memory::ModuleRange range,
                std::size_t occurrence = 1) noexcept;

            /**
             * @brief Module-scoped scan over every readable page of the image.
             * @details Superset of @ref scan_module_executable that also accepts
             *          the non-executable readable pages (.rdata / .data), so a
             *          single pass covers both code and data candidates. This is
             *          why the in-module cascade needs no ScannerKind distinction.
             *          Returns the Nth match (1-based, adjusted by pattern.offset)
             *          or nullptr.
             */
            [[nodiscard]] const std::byte *scan_module_readable(
                const CompiledPattern &pattern, Memory::ModuleRange range,
                std::size_t occurrence = 1) noexcept;
        } // namespace detail
    } // namespace Scanner
} // namespace DetourModKit

#endif // DETOURMODKIT_SCANNER_INTERNAL_HPP
