/**
 * @file internal/image_identity.cpp
 * @brief Guarded PE-header identity read shared by scan::image_identity and the RTTI generation token.
 */

#include "internal/image_identity.hpp"

#include "internal/memory_guarded.hpp"
#include "internal/memory_representation_win32.hpp"

#include <windows.h>

#include <cstddef>
#include <cstring>
#include <limits>
#include <optional>

namespace DetourModKit
{
    namespace detail
    {
        namespace
        {
            // The Windows loader caps a PE at 96 sections; a larger count is corrupt and would otherwise let the
            // section walk below run away.
            constexpr std::uint32_t MAX_SECTIONS = 96;

            // A wild e_lfanew is the signature of a forged or truncated header. The NT headers are re-bounded against
            // SizeOfImage once that field has been read; this cap only keeps the first read off a wild address.
            constexpr std::uint32_t MAX_NT_OFFSET = 0x100000;

            [[nodiscard]] constexpr std::uint64_t mix(std::uint64_t seed, std::uint64_t value) noexcept
            {
                seed ^= value + 0x9E3779B97F4A7C15ULL + (seed << 6) + (seed >> 2);
                return seed;
            }

            // True when [offset, offset + bytes) lies wholly inside an image of image_size bytes, with an explicit
            // wrap guard so a hostile offset/size cannot alias a low offset.
            [[nodiscard]] constexpr bool fits_image(std::uint64_t offset, std::uint64_t bytes,
                                                    std::uint32_t image_size) noexcept
            {
                return bytes <= image_size && offset <= static_cast<std::uint64_t>(image_size) - bytes;
            }
        } // namespace

        ImageIdentityFields image_identity_at(std::uintptr_t module_base) noexcept
        {
            if (!is_plausible_ptr(module_base))
            {
                return ImageIdentityFields{};
            }

            const std::optional<IMAGE_DOS_HEADER> dos = guarded_read<IMAGE_DOS_HEADER>(module_base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
                static_cast<std::uint32_t>(dos->e_lfanew) > MAX_NT_OFFSET)
            {
                return ImageIdentityFields{};
            }

            const auto nt_offset = static_cast<std::uint32_t>(dos->e_lfanew);
            const std::optional<IMAGE_NT_HEADERS64> nt = guarded_read<IMAGE_NT_HEADERS64>(module_base + nt_offset);
            if (!nt || nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
                nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
                nt->OptionalHeader.SizeOfImage == 0)
            {
                return ImageIdentityFields{};
            }

            // Every later address is bounded by the image size this header declares. Guarding contains a concurrent
            // unmap fault, but does not pin the mapping; callers that authorize work across a transition revalidate.
            const std::uint32_t image_size = nt->OptionalHeader.SizeOfImage;
            if (!fits_image(nt_offset, sizeof(IMAGE_NT_HEADERS64), image_size))
            {
                return ImageIdentityFields{};
            }

            const std::uint32_t num_sections = nt->FileHeader.NumberOfSections;
            if (num_sections == 0 || num_sections > MAX_SECTIONS)
            {
                return ImageIdentityFields{};
            }

            // IMAGE_FIRST_SECTION: the section table starts immediately after the optional header, whose length is
            // SizeOfOptionalHeader. Using sizeof(IMAGE_NT_HEADERS64) would misplace the table whenever that size
            // differs from the compile-time struct size.
            const std::uint64_t table_offset = static_cast<std::uint64_t>(nt_offset) +
                                               offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                                               nt->FileHeader.SizeOfOptionalHeader;
            const std::uint64_t table_bytes = static_cast<std::uint64_t>(num_sections) * sizeof(IMAGE_SECTION_HEADER);
            if (!fits_image(table_offset, table_bytes, image_size))
            {
                return ImageIdentityFields{};
            }

            // One guarded read for the whole table rather than one per header keeps the fault-guard entry count bounded
            // on a path that a warm TypeIdentity revalidates on every call. The buffer is the loader's own section cap,
            // so it needs no heap.
            alignas(alignof(IMAGE_SECTION_HEADER)) std::byte section_table[MAX_SECTIONS * sizeof(IMAGE_SECTION_HEADER)];
            if (!guarded_read_bytes(module_base + static_cast<std::uintptr_t>(table_offset), section_table,
                                    static_cast<std::size_t>(table_bytes)))
            {
                return ImageIdentityFields{};
            }

            std::uint64_t digest = mix(0x0DDC0FFEEULL, static_cast<std::uint64_t>(num_sections));
            for (std::uint32_t i = 0; i < num_sections; ++i)
            {
                IMAGE_SECTION_HEADER section{};
                std::memcpy(&section, section_table + static_cast<std::size_t>(i) * sizeof(IMAGE_SECTION_HEADER),
                            sizeof(section));
                std::uint64_t name = 0;
                for (std::size_t byte = 0; byte < IMAGE_SIZEOF_SHORT_NAME; ++byte)
                {
                    name |= static_cast<std::uint64_t>(section.Name[byte]) << (byte * 8);
                }
                digest = mix(digest, name);
                digest = mix(digest, static_cast<std::uint64_t>(section.VirtualAddress));
                digest = mix(digest, static_cast<std::uint64_t>(section.Misc.VirtualSize));
                digest = mix(digest, static_cast<std::uint64_t>(section.Characteristics));
            }

            return ImageIdentityFields{.timestamp = nt->FileHeader.TimeDateStamp,
                                       .size_of_image = image_size,
                                       .section_digest = digest,
                                       .valid = true};
        }

        std::uint64_t image_generation_token(std::uintptr_t module_base) noexcept
        {
            const ImageIdentityFields fields = image_identity_at(module_base);
            if (!fields.valid)
            {
                return 0;
            }
            // The base separates two modules that carry byte-identical headers; the section digest separates
            // layout-differing images the loader mapped at one base across an unload/reload.
            std::uint64_t token = static_cast<std::uint64_t>(module_base);
            token = mix(token, static_cast<std::uint64_t>(fields.size_of_image));
            token = mix(token, static_cast<std::uint64_t>(fields.timestamp));
            token = mix(token, fields.section_digest);
            return token == 0 ? 1 : token;
        }
    } // namespace detail
} // namespace DetourModKit
