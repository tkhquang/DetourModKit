#ifndef DETOURMODKIT_RTTI_INTERNAL_HPP
#define DETOURMODKIT_RTTI_INTERNAL_HPP

/**
 * @file rtti_internal.hpp
 * @brief Shared MSVC RTTI prelude for the rtti.cpp and rtti_dissect.cpp TUs.
 *
 * Houses the verified COL -> TypeDescriptor walk (@ref resolve_col_site) and the page-bounded name copy (@ref
 * read_name_seh) that both the forward walker (type_name_of / vtable_is_type) and the reverse dissector
 * (identify_pointee_type / heal_landmark) consume. The structures and helpers live in DetourModKit::rtti::detail and
 * are NOT part of the installed public surface; ColHead in particular encodes a raw ABI layout that must never leak
 * into a consumer-visible header.
 */

#include "DetourModKit/rtti.hpp"

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace DetourModKit
{
    // Forward declaration so the ModuleSpan overload of resolve_col_site can be declared here without pulling the
    // guarded-memory engine header into this internal header. Both TUs that define or call the overload
    // (rtti.cpp, rtti_dissect.cpp) already include the full definition via internal/memory_guarded.hpp.
    namespace detail
    {
        struct ModuleSpan;
    }

    namespace rtti
    {
        namespace detail
        {
            // MSVC x64 RTTI layout constants. Stable across every Visual C++ release since 2010 and assumed to remain
            // stable; the ABI is not officially documented but is what every disassembler (IDA, Ghidra, Binary Ninja)
            // and every interop tool (MinHook, Detours, EasyHook, SafetyHook) relies on, so DetourModKit treats it as a
            // long-term contract.
            inline constexpr std::ptrdiff_t COL_OFFSET_FROM_VTABLE = -8;
            inline constexpr std::ptrdiff_t TD_NAME_OFFSET = 0x10;
            inline constexpr std::uint32_t COL_SIGNATURE_X64 = 1;
            inline constexpr std::uintptr_t MIN_VALID_PTR = 0x10000;

            // Page size used to bound name reads so a single SEH read never spans a page boundary; this lets the walker
            // tolerate a string that ends just before an unmapped page rather than failing the whole read.
            inline constexpr std::uintptr_t PAGE_MASK = 0xFFF;

            /**
             * @struct ColHead
             * @brief First 24 bytes of an MSVC x64 RTTICompleteObjectLocator.
             * @details Field order is fixed by the MSVC ABI; declaring it as a packed POD lets resolve_col_site() pull
             *          every field in a single SEH read rather than six separate ones. The struct is trivially copyable
             *          so guarded_read<ColHead> instantiates cleanly.
             */
            struct ColHead
            {
                std::uint32_t signature;
                std::uint32_t offset;
                std::uint32_t cd_offset;
                std::uint32_t p_type_descriptor;
                std::uint32_t p_class_descriptor;
                std::uint32_t p_self;
            };
            static_assert(sizeof(ColHead) == 24, "ColHead must match MSVC x64 ABI layout");
            static_assert(std::is_trivially_copyable_v<ColHead>);

            /**
             * @struct ColSite
             * @brief Fully resolved COL/TypeDescriptor coordinates for a vtable.
             * @details Output of @ref resolve_col_site. Carries every address the verified prelude recovers so a caller
             *          can read the name (@ref name_addr) or recover the complete object from @ref col_offset without
             *          re-walking the COL.
             */
            struct ColSite
            {
                /// Address of the COL the vtable points back to.
                std::uintptr_t col_addr = 0;
                /// TypeDescriptor base (image base + COL.pTypeDescriptor RVA).
                std::uintptr_t td_addr = 0;
                /// Mangled-name buffer (td_addr + TD_NAME_OFFSET).
                std::uintptr_t name_addr = 0;
                /// Exclusive end [base, end) of the owning module; bounds the name read (see @ref read_name_seh).
                std::uintptr_t module_end = 0;
                /// COL.offset (+0x04): this vtable's offset in the complete object.
                std::uint32_t col_offset = 0;
            };

            /**
             * @brief Runs the verified COL prelude for @p vtable and reports every recovered coordinate in @p out.
             * @details Every intermediate address (the COL pointer, the pSelf-recovered image base, and the final name
             *          buffer) is required to lie inside the vtable's owning module range. This forces a poisoned COL
             *          to fail closed: a forged pTypeDescriptor that would otherwise redirect a read to another loaded
             *          module or to unmapped memory is rejected here instead of read-through. @p out is left untouched
             *          on any failure.
             * @param vtable Runtime vtable pointer (first qword of the object).
             * @param out Receives the resolved coordinates on success only.
             * @return true on a fully validated walk, false for every failure mode (vtable not in a loaded module,
             *         unreadable COL, COL pointer escaping the module range, pSelf disagreeing with the loader-reported
             *         base, zero TypeDescriptor RVA, name address escaping the module range).
             */
            [[nodiscard]] bool resolve_col_site(std::uintptr_t vtable, ColSite &out) noexcept;

            /**
             * @brief resolve_col_site variant that reuses a caller-held owning-module span.
             * @details Identical validation to the single-argument overload, but the caller supplies @p mod_range (the
             *          span of the module that owns @p vtable) instead of this function resolving it via
             *          memory::module_of. The reverse sweep already holds the module span for every candidate it tests,
             *          so routing through this overload removes a per-candidate GetModuleHandleExW loader lookup from
             *          the hot RTTI scan -- the per-frame cliff a TypeIdentity polled for an absent type would hit. The
             *          overload requires @p vtable to lie inside @p mod_range (the same invariant module_of grants
             *          implicitly: the loader only resolves a module that contains the address), so a candidate one
             *          past the module end still fails closed.
             * @param vtable Runtime vtable pointer (first qword of the object).
             * @param mod_range Pre-resolved span of the module that owns @p vtable.
             * @param out Receives the resolved coordinates on success only.
             * @return true on a fully validated walk; false for every failure mode the single-argument overload
             *         rejects, plus a @p vtable outside @p mod_range.
             */
            [[nodiscard]] bool resolve_col_site(std::uintptr_t vtable,
                                                const DetourModKit::detail::ModuleSpan &mod_range,
                                                ColSite &out) noexcept;

            /**
             * @brief Page-bounded, module-bounded NUL-terminated copy from @p addr into @p out.
             * @details Reads in chunks that never cross a 4 KiB page boundary so a string that ends just before an
             *          unmapped page still terminates cleanly. To honour the all-or-nothing failure contract, bytes are
             *          first accumulated in a local temporary; the final commit into @p out only happens when either
             *          the terminating NUL is observed or the allowed length is filled in full. A read fault before
             *          either condition leaves @p out as the empty NUL-terminated string and returns 0. The read is
             *          additionally clamped to @p module_end so a mangled name that lacks a NUL before the end of its
             *          owning module (a forged or edge-of-module TypeDescriptor) is truncated at the module boundary
             *          rather than read-through into an adjacent mapped image, which would surface another module's
             *          bytes as a confident type name (an information leak).
             * @param addr Address of the first name byte. Values below
             *             MIN_VALID_PTR are rejected without a read.
             * @param out Destination buffer. nullptr or zero length returns 0.
             * @param out_len Capacity of @p out including the NUL terminator.
             * @param module_end Exclusive end of the owning module range; the read never advances to or past it. Zero
             *        means "no module bound known" and only the length caps apply (@ref resolve_col_site supplies
             *        a real end, so a caller threading a @ref ColSite gets the bound automatically).
             * @return Number of bytes written excluding the NUL terminator, or
             *         0 on any partial-read failure.
             */
            [[nodiscard]] std::size_t read_name_seh(std::uintptr_t addr, char *out, std::size_t out_len,
                                                    std::uintptr_t module_end) noexcept;
        } // namespace detail
    } // namespace rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_RTTI_INTERNAL_HPP
