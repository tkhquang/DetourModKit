/**
 * @file scan_export.cpp
 * @brief The named-export resolver: maps a module + export name to an address by walking the PE Export Address Table.
 * @details A named export is the most update-resilient anchor a mod can hold. The export table is a module's documented
 *          ABI, so an exported name survives a game patch far better than the code bytes, string literals, or absolute
 *          addresses a byte scan keys on: an internal function may move or be rewritten every build, but an exported
 *          entry point keeps its name across versions.
 *
 *          The walk is deterministic and loader-free. It parses the mapped image's own IMAGE_EXPORT_DIRECTORY rather
 *          than calling GetProcAddress, so it never invokes the loader, never triggers a DllMain, and resolves from a
 *          module range alone -- the same self-healing contract the other scan backends share. Every RVA is
 *          bound-checked against the image before it is dereferenced and every read goes through the guarded
 *          (fault-trapping) path, so a truncated or hostile export section yields a fail-closed Error rather than a
 *          host fault or an out-of-image read. Forwarded exports (whose function RVA points back inside the export
 *          directory, naming another DLL's symbol as an ASCII string instead of code here) are rejected rather than
 *          returned. That test -- a function RVA landing inside the export directory's own
 *          [VirtualAddress, VirtualAddress + Size) window -- is the same range check the Windows loader uses to
 *          classify a forwarder, so any forwarder a module actually declares is never handed back as a code anchor to
 *          hook or read through.
 */

#include "DetourModKit/scan.hpp"

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
    namespace scan
    {
        namespace
        {
            // Upper bound on the export name / function counts the walk will iterate. No real module approaches this;
            // the cap exists only so a corrupt or hostile IMAGE_EXPORT_DIRECTORY -- whose count fields are entirely
            // attacker-controlled -- cannot steer the scan into an unbounded loop. It is far below any value that could
            // overflow the byte-size arithmetic on the parallel arrays below.
            constexpr std::uint32_t MAX_EXPORT_ENTRIES = 1U << 20;

            // Reports whether the half-open byte range [start, start + bytes) lies wholly inside the module image, with
            // an explicit wrap guard so a hostile RVA/size that overflows the address space is rejected rather than
            // aliasing a low address. A zero-length range is vacuously contained.
            [[nodiscard]] bool region_in_span(const detail::ModuleSpan &span, std::uintptr_t start,
                                              std::uintptr_t bytes) noexcept
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
            [[nodiscard]] std::optional<std::uintptr_t> checked_rva(const detail::ModuleSpan &span, std::uint32_t rva,
                                                                    std::uintptr_t bytes) noexcept
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
            [[nodiscard]] bool export_name_matches(const detail::ModuleSpan &span, std::uintptr_t name_addr,
                                                   std::string_view target) noexcept
            {
                for (std::size_t index = 0; index < target.size(); ++index)
                {
                    if (index > std::numeric_limits<std::uintptr_t>::max() - name_addr)
                    {
                        return false;
                    }
                    const std::uintptr_t byte_addr = name_addr + index;
                    if (!span.contains(byte_addr))
                    {
                        return false;
                    }
                    const std::optional<char> byte = detail::guarded_read<char>(byte_addr);
                    if (!byte || *byte != target[index])
                    {
                        return false;
                    }
                }
                if (target.size() > std::numeric_limits<std::uintptr_t>::max() - name_addr)
                {
                    return false;
                }
                const std::uintptr_t terminator_addr = name_addr + target.size();
                if (!span.contains(terminator_addr))
                {
                    return false;
                }
                const std::optional<char> terminator = detail::guarded_read<char>(terminator_addr);
                return terminator && *terminator == '\0';
            }
        } // namespace

        Result<Address> resolve_export(std::string_view export_name, Region module) noexcept
        {
            // An empty name can never name an export entry; reject up front so the walk below never treats a
            // zero-length compare as a spurious match against the first name in the table.
            if (export_name.empty())
            {
                return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
            }

            const detail::ModuleSpan span = detail::module_span(module);
            if (!span.valid())
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
            }
            const std::uintptr_t base = span.base;

            // DOS -> NT header walk, with the same discipline as the RTTI image walk: read the DOS header, bound the NT
            // offset inside the image, then read the 64-bit NT headers and confirm both signatures and the PE32+
            // optional-header magic before trusting any field. The library is x64-only (an #error arch gate enforces
            // it), so the explicit IMAGE_NT_HEADERS64 + PE32+ magic check is a defensive assertion against a
            // wrong-bitness image, not a portability branch. The parse is kept local rather than shared with the RTTI
            // walk: the two differ in error model (fail-closed ErrorCodes here vs a range count with a whole-module
            // fallback there), so a shared helper would couple the two subsystems without removing real duplication.
            const std::optional<IMAGE_DOS_HEADER> dos = detail::guarded_read<IMAGE_DOS_HEADER>(base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
            }
            if (dos->e_lfanew < 0)
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
            }
            const std::optional<std::uintptr_t> nt_addr =
                checked_rva(span, static_cast<std::uint32_t>(dos->e_lfanew), sizeof(IMAGE_NT_HEADERS64));
            if (!nt_addr)
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve_export"});
            }
            const std::optional<IMAGE_NT_HEADERS64> nt = detail::guarded_read<IMAGE_NT_HEADERS64>(*nt_addr);
            if (!nt || nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
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

            // The export directory is data-directory entry 0. A module with no exports leaves it zeroed; that is not a
            // fault, it simply has no name for this backend to resolve.
            const IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (dir.VirtualAddress == 0 || dir.Size == 0)
            {
                return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
            }
            const std::optional<std::uintptr_t> export_va = checked_rva(span, dir.VirtualAddress, dir.Size);
            if (!export_va || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
            {
                return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
            }
            const std::optional<IMAGE_EXPORT_DIRECTORY> exports =
                detail::guarded_read<IMAGE_EXPORT_DIRECTORY>(*export_va);
            if (!exports)
            {
                return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
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
                span, exports->AddressOfNames, static_cast<std::uintptr_t>(name_count) * sizeof(std::uint32_t));
            const std::optional<std::uintptr_t> ordinals_va = checked_rva(
                span, exports->AddressOfNameOrdinals, static_cast<std::uintptr_t>(name_count) * sizeof(std::uint16_t));
            const std::optional<std::uintptr_t> funcs_va = checked_rva(
                span, exports->AddressOfFunctions, static_cast<std::uintptr_t>(func_count) * sizeof(std::uint32_t));
            if (!names_va || !ordinals_va || !funcs_va)
            {
                return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
            }

            // Linear scan the parallel name / ordinal arrays. The name table is spec-sorted for GetProcAddress's binary
            // search, but a linear scan is chosen deliberately: it is O(exports) at setup time (never a hot path) and
            // stays correct on the unsorted tables some packers emit. A duplicate matching name is rejected as an
            // ambiguous, malformed table rather than letting array order choose a target.
            std::optional<Address> match;
            for (std::uint32_t index = 0; index < name_count; ++index)
            {
                const std::optional<std::uint32_t> name_rva = detail::guarded_read<std::uint32_t>(
                    *names_va + static_cast<std::uintptr_t>(index) * sizeof(std::uint32_t));
                if (!name_rva)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                const std::optional<std::uintptr_t> name_va = checked_rva(span, *name_rva, 1);
                if (!name_va || !export_name_matches(span, *name_va, export_name))
                {
                    continue;
                }
                if (match)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }

                // Name index maps to function index AddressOfNameOrdinals[index]. That WORD is a 0-based index into
                // AddressOfFunctions directly (the directory's Base biases only the ORDINAL exposed to callers, not
                // this array index), so it is used as-is after the bounds check.
                const std::optional<std::uint16_t> ordinal = detail::guarded_read<std::uint16_t>(
                    *ordinals_va + static_cast<std::uintptr_t>(index) * sizeof(std::uint16_t));
                if (!ordinal || *ordinal >= func_count)
                {
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                const std::optional<std::uint32_t> func_rva = detail::guarded_read<std::uint32_t>(
                    *funcs_va + static_cast<std::uintptr_t>(*ordinal) * sizeof(std::uint32_t));
                if (!func_rva || *func_rva == 0)
                {
                    // A zero RVA in the functions array is an unused / absent slot, not a resolvable address.
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }

                // A function RVA that points back inside the export directory region is a FORWARDER: the DWORD
                // addresses an ASCII "TargetDll.TargetFunc" string, not code in this image. Following it would need the
                // loader, and this [VirtualAddress, VirtualAddress + Size) window is exactly the loader's own forwarder
                // test; fail closed so a declared forwarder is never handed back as a code anchor to hook or read
                // through.
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
                    // The RVA resolved outside the mapped image: a corrupt entry, not a usable code address.
                    return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
                }
                match = Address{*target};
            }

            if (match)
            {
                return *match;
            }
            return std::unexpected(Error{ErrorCode::ExportNotFound, "scan::resolve_export"});
        }
    } // namespace scan
} // namespace DetourModKit
