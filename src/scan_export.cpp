/**
 * @file scan_export.cpp
 * @brief The named-export resolver: maps a module + export name to an address by walking the PE Export Address Table.
 * @details The walk parses the mapped image's own IMAGE_EXPORT_DIRECTORY. It never calls GetProcAddress, enters the
 *          loader, or triggers DllMain. It bound-checks every RVA and reads through the guarded path. scan.hpp's
 *          resolve_export owns the public contract. A forwarder is classified by the loader's own range check: a
 *          function RVA inside the export directory's [VirtualAddress, VirtualAddress + Size) window. The walk lives
 *          in `detail::resolve_export_with_provenance`. The public entry point is a thin wrapper because only the walk
 *          knows the slot and RVA that resolved a name.
 */

#include "DetourModKit/scan.hpp"

#include "internal/export_resolution.hpp"
#include "internal/image_identity.hpp"
#include "internal/memory_guarded.hpp"
#include "internal/memory_representation_win32.hpp"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        namespace
        {
            // Upper bound on the export name / function counts the walk will iterate. No real module approaches this;
            // the cap exists only so a corrupt or hostile IMAGE_EXPORT_DIRECTORY (whose count fields are entirely
            // attacker-controlled) cannot steer the scan into an unbounded loop. It is far below any value that can
            // overflow the byte-size arithmetic on the parallel arrays below.
            constexpr std::uint32_t MAX_EXPORT_ENTRIES = 1U << 20;

            // Reports whether the half-open byte range [start, start + bytes) lies wholly inside the module image, with
            // an explicit wrap guard so a hostile RVA/size that overflows the address space is rejected rather than
            // aliasing a low address. A zero-length range is vacuously contained.
            [[nodiscard]] bool
            region_in_span(const ModuleSpan &span, std::uintptr_t start, std::uintptr_t bytes) noexcept
            {
                if (bytes == 0)
                {
                    return true;
                }
                if (start > std::numeric_limits<std::uintptr_t>::max() - (bytes - 1))
                {
                    // Address-space wrap: a corrupt RVA or size pushed the range past the top of memory.
                    return false;
                }
                const std::uintptr_t last = start + (bytes - 1);
                return span.contains(start) && span.contains(last);
            }

            // Converts an image-relative address to an absolute range only when the addition cannot wrap and the
            // entire range lies inside the mapped image. Keeping this arithmetic in one helper prevents a hostile RVA
            // from wrapping below the module base before a later span check sees it.
            [[nodiscard]] std::optional<std::uintptr_t>
            checked_rva(const ModuleSpan &span, std::uint32_t rva, std::uintptr_t bytes) noexcept
            {
                if (static_cast<std::uintptr_t>(rva) > std::numeric_limits<std::uintptr_t>::max() - span.base)
                {
                    return std::nullopt;
                }
                const std::uintptr_t address = span.base + static_cast<std::uintptr_t>(rva);
                if (!region_in_span(span, address, bytes))
                {
                    return std::nullopt;
                }
                return address;
            }

            // Byte-exact, case-sensitive compare of the NUL-terminated export name at name_addr against target, with
            // every byte bound-checked and fault-guarded so a truncated name table fails closed. PE export names are
            // case-sensitive (GetProcAddress matches them exactly), so the anchor must be too. Comparing target.size()
            // bytes AND the following terminator rejects both a shorter name (its NUL lands early) and a longer one
            // (its byte at target.size() is not the terminator), so "malloc" never matches "malloc_base".
            [[nodiscard]] std::optional<bool>
            export_name_matches(const ModuleSpan &span, std::uintptr_t name_addr, std::string_view target) noexcept
            {
                for (std::size_t index = 0; index < target.size(); ++index)
                {
                    if (index > std::numeric_limits<std::uintptr_t>::max() - name_addr)
                    {
                        return std::nullopt;
                    }
                    const std::uintptr_t byte_addr = name_addr + index;
                    if (!span.contains(byte_addr))
                    {
                        return std::nullopt;
                    }
                    const std::optional<char> byte = guarded_read<char>(byte_addr);
                    if (!byte)
                    {
                        return std::nullopt;
                    }
                    if (*byte != target[index])
                    {
                        return false;
                    }
                }
                if (target.size() > std::numeric_limits<std::uintptr_t>::max() - name_addr)
                {
                    return std::nullopt;
                }
                const std::uintptr_t terminator_addr = name_addr + target.size();
                if (!span.contains(terminator_addr))
                {
                    return std::nullopt;
                }
                const std::optional<char> terminator = guarded_read<char>(terminator_addr);
                if (!terminator)
                {
                    return std::nullopt;
                }
                return *terminator == '\0';
            }

            /**
             * @brief Reads and checks the DOS and NT headers inside @p supplied_span.
             * @details The checks cover both signatures, the PE32+ magic, and the export data-directory entry. An
             *          invalid span or a bad header returns InvalidRange, and a missing export data-directory entry
             *          returns ExportNotFound. On success the helper writes the NT header address to @p nt_address.
             */
            [[nodiscard]] Result<IMAGE_NT_HEADERS64>
            read_nt_headers(const ModuleSpan &supplied_span, std::uintptr_t &nt_address) noexcept
            {
                if (!supplied_span.valid())
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
                }
                const std::uintptr_t base = supplied_span.base;
                if (!region_in_span(supplied_span, base, sizeof(IMAGE_DOS_HEADER)))
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
                }

                // The library is x64-only, and an #error arch gate enforces it. The explicit PE32+ magic check on
                // IMAGE_NT_HEADERS64 rejects a wrong-bitness image and is not a portability branch.
                //
                // This parse stays separate from the RTTI image walk because the error models differ. Here a bad header
                // fails closed with an ErrorCode. The RTTI image walk returns a range count, and its caller falls back
                // to the whole module. A shared helper couples the two subsystems and removes no real duplication.
                const std::optional<IMAGE_DOS_HEADER> dos = guarded_read<IMAGE_DOS_HEADER>(base);
                if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
                }
                if (dos->e_lfanew < 0)
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
                }
                const std::optional<std::uintptr_t> nt_addr =
                    checked_rva(supplied_span, static_cast<std::uint32_t>(dos->e_lfanew), sizeof(IMAGE_NT_HEADERS64));
                if (!nt_addr)
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
                }
                const std::optional<IMAGE_NT_HEADERS64> nt = guarded_read<IMAGE_NT_HEADERS64>(*nt_addr);
                if (!nt || nt->Signature != IMAGE_NT_SIGNATURE ||
                    nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
                }

                constexpr std::size_t export_directory_end =
                    offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
                    (IMAGE_DIRECTORY_ENTRY_EXPORT + 1) * sizeof(IMAGE_DATA_DIRECTORY);
                if (nt->FileHeader.SizeOfOptionalHeader < export_directory_end ||
                    nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                nt_address = *nt_addr;
                return *nt;
            }

            /**
             * @brief Returns @p supplied_span clipped to the image size that the NT headers declare.
             * @details The helper returns InvalidRange when SizeOfImage is zero, when the declared image end wraps, or
             *          when the NT headers fall outside the clipped span. @p supplied_span is only an outer safety
             *          boundary. The SizeOfImage that @p nt declares is the authoritative inner boundary for every EAT
             *          read. Stale or oversized mapped backing therefore cannot make a declared out-of-image RVA appear
             *          valid.
             */
            [[nodiscard]] Result<ModuleSpan> clip_span_to_declared_image(
                const ModuleSpan &supplied_span,
                const IMAGE_NT_HEADERS64 &nt,
                std::uintptr_t nt_address
            ) noexcept
            {
                const std::uintptr_t base = supplied_span.base;
                const std::uintptr_t image_size = nt.OptionalHeader.SizeOfImage;
                if (image_size == 0 || image_size > std::numeric_limits<std::uintptr_t>::max() - base)
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
                }
                const std::uintptr_t declared_end = base + image_size;
                const ModuleSpan span{base, declared_end < supplied_span.end ? declared_end : supplied_span.end};
                if (!region_in_span(span, nt_address, sizeof(IMAGE_NT_HEADERS64)))
                {
                    return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
                }
                return span;
            }

            /**
             * @brief Reads the IMAGE_EXPORT_DIRECTORY that @p dir locates inside @p span.
             * @details The helper returns ExportNotFound when @p dir is empty, too small, outside @p span, or
             *          unreadable.
             */
            [[nodiscard]] Result<IMAGE_EXPORT_DIRECTORY>
            read_export_directory(const ModuleSpan &span, const IMAGE_DATA_DIRECTORY &dir) noexcept
            {
                // A module with no exports leaves dir zeroed. That is not a fault: the module has no name for this
                // backend to resolve.
                if (dir.VirtualAddress == 0 || dir.Size == 0)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                const std::optional<std::uintptr_t> export_va = checked_rva(span, dir.VirtualAddress, dir.Size);
                if (!export_va || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                const std::optional<IMAGE_EXPORT_DIRECTORY> exports = guarded_read<IMAGE_EXPORT_DIRECTORY>(*export_va);
                if (!exports)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                return *exports;
            }

            /**
             * @brief Maps the matched name @p index through the ordinal and function arrays to its physical slot.
             * @details A forwarder returns ExportForwarded. A bad ordinal, an unreadable or empty slot, or a target
             *          outside @p span returns ExportNotFound.
             */
            [[nodiscard]] Result<ExportResolution> resolve_export_slot(
                const ModuleSpan &span,
                const IMAGE_DATA_DIRECTORY &dir,
                std::uintptr_t ordinals_va,
                std::uintptr_t funcs_va,
                std::uint32_t func_count,
                std::uint32_t index
            ) noexcept
            {
                // The name index maps to the function index AddressOfNameOrdinals[index]. That WORD is a 0-based index
                // into AddressOfFunctions. The directory's Base biases only the ordinal exposed to callers, not this
                // array index. The helper uses the WORD as-is after the bounds check.
                const std::optional<std::uint16_t> ordinal = guarded_read<std::uint16_t>(
                    ordinals_va + static_cast<std::uintptr_t>(index) * sizeof(std::uint16_t)
                );
                if (!ordinal || *ordinal >= func_count)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                const std::optional<std::uint32_t> func_rva = guarded_read<std::uint32_t>(
                    funcs_va + static_cast<std::uintptr_t>(*ordinal) * sizeof(std::uint32_t)
                );
                if (!func_rva || *func_rva == 0)
                {
                    // A zero RVA in the functions array marks an unused or absent slot, not a resolvable address.
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }

                // A function RVA inside the export directory is a forwarder. The DWORD addresses an ASCII
                // "TargetDll.TargetFunc" string, not code in this image. Only the loader can resolve it. The helper
                // fails closed so that a declared forwarder never becomes a code anchor to hook or read through.
                const std::uint64_t forwarder_begin = dir.VirtualAddress;
                const std::uint64_t forwarder_end = forwarder_begin + dir.Size;
                if (static_cast<std::uint64_t>(*func_rva) >= forwarder_begin &&
                    static_cast<std::uint64_t>(*func_rva) < forwarder_end)
                {
                    return std::unexpected(Error{ErrorCode::ExportForwarded, "scan::resolve_export"});
                }

                const std::optional<std::uintptr_t> target = checked_rva(span, *func_rva, 1);
                if (!target)
                {
                    // An RVA outside the mapped image marks a corrupt entry, not a usable code address.
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                return ExportResolution{
                    .module_base = span.base,
                    .function_index = *ordinal,
                    .function_rva = *func_rva,
                    .target = Address{*target},
                };
            }
        } // namespace

        Result<Address>
        resolve_export_with_provenance(std::string_view export_name, Region module, ExportResolution &out) noexcept
        {
            out = ExportResolution{};

            // PE names are non-empty NUL-terminated byte strings. The check rejects an embedded terminator up front so
            // that a query cannot match zero padding after the real name's terminator.
            if (export_name.empty() || export_name.find('\0') != std::string_view::npos)
            {
                return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
            }

            const ModuleSpan supplied_span = module_span(module);
            std::uintptr_t nt_address = 0;
            const Result<IMAGE_NT_HEADERS64> nt = read_nt_headers(supplied_span, nt_address);
            if (!nt)
            {
                return std::unexpected(nt.error());
            }
            const Result<ModuleSpan> declared_span = clip_span_to_declared_image(supplied_span, *nt, nt_address);
            if (!declared_span)
            {
                return std::unexpected(declared_span.error());
            }
            const ModuleSpan &span = *declared_span;

            const IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            const Result<IMAGE_EXPORT_DIRECTORY> exports = read_export_directory(span, dir);
            if (!exports)
            {
                return std::unexpected(exports.error());
            }

            const std::uint32_t name_count = exports->NumberOfNames;
            const std::uint32_t func_count = exports->NumberOfFunctions;
            if (name_count == 0 || func_count == 0 || name_count > MAX_EXPORT_ENTRIES ||
                func_count > MAX_EXPORT_ENTRIES)
            {
                // No name table to match against, or an implausibly large count from a corrupt/hostile directory.
                return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
            }

            const std::optional<std::uintptr_t> names_va = checked_rva(
                span,
                exports->AddressOfNames,
                static_cast<std::uintptr_t>(name_count) * sizeof(std::uint32_t)
            );
            const std::optional<std::uintptr_t> ordinals_va = checked_rva(
                span,
                exports->AddressOfNameOrdinals,
                static_cast<std::uintptr_t>(name_count) * sizeof(std::uint16_t)
            );
            const std::optional<std::uintptr_t> funcs_va = checked_rva(
                span,
                exports->AddressOfFunctions,
                static_cast<std::uintptr_t>(func_count) * sizeof(std::uint32_t)
            );
            if (!names_va || !ordinals_va || !funcs_va)
            {
                return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
            }

            // Linear scan the parallel name / ordinal arrays. The name table is spec-sorted for GetProcAddress's binary
            // search, but a linear scan is chosen deliberately: it is O(exports) at setup time (never a hot path) and
            // stays correct on the unsorted tables some packers emit. A duplicate matching name is rejected as an
            // ambiguous, malformed table rather than letting array order choose a target.
            std::optional<Address> match;
            ExportResolution resolution;
            for (std::uint32_t index = 0; index < name_count; ++index)
            {
                const std::optional<std::uint32_t> name_rva =
                    guarded_read<std::uint32_t>(*names_va + static_cast<std::uintptr_t>(index) * sizeof(std::uint32_t));
                if (!name_rva)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                const std::optional<std::uintptr_t> name_va = checked_rva(span, *name_rva, 1);
                if (!name_va)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                const std::optional<bool> name_matches = export_name_matches(span, *name_va, export_name);
                if (!name_matches)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                if (!*name_matches)
                {
                    continue;
                }
                if (match)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }

                const Result<ExportResolution> slot =
                    resolve_export_slot(span, dir, *ordinals_va, *funcs_va, func_count, index);
                if (!slot)
                {
                    return std::unexpected(slot.error());
                }
                match = slot->target;
                // The slot this name mapped to and the value read out of it, so a caller weighing two names can tell
                // one physical entry point from two. A duplicate name aborts above, so this is written at most once.
                resolution = *slot;
            }

            if (match)
            {
                out = resolution;
                return *match;
            }
            return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
        }

    } // namespace detail

    namespace scan
    {
        Result<Address> resolve_export(std::string_view export_name, Region module) noexcept
        {
            detail::ExportResolution ignored;
            return detail::resolve_export_with_provenance(export_name, module, ignored);
        }

        ImageIdentity image_identity(Region range) noexcept
        {
            if (range.base.raw() == 0 || range.size == 0)
            {
                return ImageIdentity{};
            }

            // The supplied range may be a narrow scan scope or a stale cached extent after a same-base remap, so the
            // authoritative extent is re-read from the PE at the base. The base itself is never folded in, which keeps
            // a persisted baseline ASLR-insensitive; the RTTI generation token adds the base separately because it
            // must also separate two modules.
            const detail::ImageIdentityFields fields = detail::image_identity_at(range.base.raw());
            if (!fields.valid)
            {
                return ImageIdentity{};
            }
            return ImageIdentity{
                .timestamp = fields.timestamp,
                .size_of_image = fields.size_of_image,
                .section_digest = fields.section_digest,
            };
        }
    } // namespace scan
} // namespace DetourModKit
