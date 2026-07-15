#ifndef DETOURMODKIT_INTERNAL_MEMORY_REPRESENTATION_WIN32_HPP
#define DETOURMODKIT_INTERNAL_MEMORY_REPRESENTATION_WIN32_HPP

/**
 * @file memory_representation_win32.hpp
 * @brief Private representation-safety opt-ins for Win32 PE header structures used by guarded reads.
 *
 * The classified structures contain only fixed-layout integer fields and integer arrays. Keeping these opt-ins in a
 * Win32-only internal header preserves the public memory header's platform-neutral boundary.
 */

#include "DetourModKit/memory.hpp"

#include <windows.h>

namespace DetourModKit::detail
{
    template <> struct enable_representation_safe_aggregate<IMAGE_DOS_HEADER> : std::true_type
    {
    };

    template <> struct enable_representation_safe_aggregate<IMAGE_NT_HEADERS64> : std::true_type
    {
    };

    template <> struct enable_representation_safe_aggregate<IMAGE_SECTION_HEADER> : std::true_type
    {
    };

    template <> struct enable_representation_safe_aggregate<IMAGE_EXPORT_DIRECTORY> : std::true_type
    {
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_MEMORY_REPRESENTATION_WIN32_HPP
