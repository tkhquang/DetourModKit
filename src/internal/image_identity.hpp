#ifndef DETOURMODKIT_INTERNAL_IMAGE_IDENTITY_HPP
#define DETOURMODKIT_INTERNAL_IMAGE_IDENTITY_HPP

/**
 * @file internal/image_identity.hpp
 * @brief The one guarded PE-identity read shared by the scanner witness and the RTTI generation token.
 * @details Both subsystems answer one question: "is this still the image I resolved against?" Both must answer it
 *          the same way, or a caller can hold an RTTI cache that a scanner witness already calls stale. The
 *          fields are read from mapped headers without consulting the loader. Each read is fault-contained and every
 *          address after the NT header is bounded by its SizeOfImage. The sequence is not a linearizable snapshot
 *          across a concurrent unload/reload, so callers authorizing work across a mapping transition must revalidate.
 */

#include <cstdint>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct ImageIdentityFields
         * @brief The identity-bearing PE header fields of one mapped image.
         * @details @ref section_digest folds the section table (count, then each header's name, virtual address,
         *          virtual size, and characteristics), which separates layout-differing images that share a base,
         *          @ref timestamp, and @ref size_of_image. It is base-independent so a persisted baseline survives
         *          ASLR; callers that must distinguish two modules add the base themselves.
         */
        struct ImageIdentityFields
        {
            std::uint32_t timestamp{0};
            std::uint32_t size_of_image{0};
            std::uint64_t section_digest{0};
            bool valid{false};
        };

        /**
         * @brief Reads the identity fields of the image mapped at @p module_base without consulting the loader.
         * @param module_base The image base to parse. An implausible pointer is rejected without a read.
         * @return Populated fields with @ref ImageIdentityFields::valid set, or a default (invalid) value when the DOS
         *         or NT headers, the PE32+ magic, the optional-header size, the image size, or the section count fails
         *         validation, or when any guarded read faults.
         */
        [[nodiscard]] ImageIdentityFields image_identity_at(std::uintptr_t module_base) noexcept;

        /**
         * @brief Folds @ref image_identity_at plus the base into the mapping-scoped generation token.
         * @param module_base The image base to parse.
         * @return A nonzero token, or 0 when the image at @p module_base does not parse. The token changes when a
         *         replacement at the same base changes an identity-bearing PE header field, including the section
         *         layout when timestamp and image size are preserved.
         */
        [[nodiscard]] std::uint64_t image_generation_token(std::uintptr_t module_base) noexcept;
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_IMAGE_IDENTITY_HPP
