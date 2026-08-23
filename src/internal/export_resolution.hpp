#ifndef DETOURMODKIT_INTERNAL_EXPORT_RESOLUTION_HPP
#define DETOURMODKIT_INTERNAL_EXPORT_RESOLUTION_HPP

/**
 * @file internal/export_resolution.hpp
 * @brief The resolved physical provenance of a named export, for callers that must tell two names for one EAT entry
 *        apart from two genuinely independent signals.
 * @details A module's export table maps many names onto one function array. Two names may share an ordinal, or two
 *          ordinals may carry one function RVA, and in both cases a single patched instruction breaks every name that
 *          reaches it. A quorum that counts those names separately reports corroboration it does not have, so the
 *          resolver publishes the physical site it actually read instead of only the address it returns.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/scan.hpp"

#include <cstdint>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct ExportResolution
         * @brief Where a resolved export physically came from.
         * @details @ref module_base identifies the mapping, since two images cannot occupy one base at once, and it is
         *          what keeps two modules that export the same RVA apart. @ref function_index is the slot in
         *          AddressOfFunctions the name mapped to, and @ref function_rva is the value read out of it.
         */
        struct ExportResolution
        {
            std::uintptr_t module_base{0};
            std::uint32_t function_index{0};
            std::uint32_t function_rva{0};
            Address target{};

            [[nodiscard]] constexpr bool present() const noexcept { return module_base != 0 && target.raw() != 0; }
        };

        /**
         * @brief True when both resolutions name one physical export site.
         * @details Equal slots are the same table entry read twice; equal RVAs in one image are the same code reached
         *          through two entries. Either makes the pair one failure domain, so a quorum must count them once.
         *          An absent resolution correlates with nothing: only a member that can name its physical source may
         *          take part in this test.
         */
        [[nodiscard]] constexpr bool same_export_site(const ExportResolution &a, const ExportResolution &b) noexcept
        {
            if (!a.present() || !b.present() || a.module_base != b.module_base)
            {
                return false;
            }
            return a.function_index == b.function_index || a.function_rva == b.function_rva;
        }

        /**
         * @brief @ref scan::resolve_export, additionally publishing the physical site the match was read from.
         * @param export_name Export name to resolve; matched byte-exactly and case-sensitively.
         * @param module Module scope to walk.
         * @param out Receives the resolved provenance on success; left default on any failure.
         * @return The resolved address, or the same typed failure @ref scan::resolve_export reports.
         */
        [[nodiscard]] Result<Address>
        resolve_export_with_provenance(std::string_view export_name, Region module, ExportResolution &out) noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_EXPORT_RESOLUTION_HPP
