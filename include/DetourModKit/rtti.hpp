#ifndef DETOURMODKIT_RTTI_HPP
#define DETOURMODKIT_RTTI_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace DetourModKit
{
    /**
     * @namespace DetourModKit::Rtti
     * @brief MSVC RTTI introspection primitives.
     * @details Walks the x64 MSVC C++ ABI structures laid down by the Visual
     *          Studio toolchain to recover the mangled type-descriptor name
     *          for a runtime object pointed to by a vtable. The implementation
     *          operates on raw addresses and never invokes typeid() or
     *          dynamic_cast, so it works across DLL boundaries and against
     *          third-party MSVC binaries (game engines, middleware) without
     *          symbol cooperation.
     *
     *          All entry points are noexcept and SEH-guarded; an unreadable
     *          page, missing COL, or zero RVA produces a failure return
     *          rather than a fault. Names are returned in the MSVC mangled
     *          form (e.g. ".?AVMyClass@ns@@") so callers can perform an
     *          exact byte-equal comparison instead of resolving through
     *          UnDecorateSymbolName.
     *
     *          The ABI layout this module relies on (COL at vtable - 8,
     *          TypeDescriptor RVA at COL + 0x0C, mangled name at TD + 0x10,
     *          COL.pSelf RVA at COL + 0x14 on x64) has been stable across
     *          every release of MSVC since Visual C++ 2010.
     */
    namespace Rtti
    {
        /// Default cap on the mangled-name length read into a heap-allocated string.
        inline constexpr std::size_t DEFAULT_TYPE_NAME_MAX = 256;

        /// Hard upper bound on any single mangled-name read.
        inline constexpr std::size_t MAX_TYPE_NAME_LEN = 1024;

        /**
         * @brief Reads the MSVC RTTI mangled type-descriptor name for the
         *        object whose runtime vtable is at @p vtable.
         * @details Walks @c vtable - 8 (RTTICompleteObjectLocator pointer),
         *          then @c col + 0x0C (TypeDescriptor RVA, base-relative),
         *          then @c td + 0x10 (zero-terminated mangled name such as
         *          ".?AVMyClass@ns@@"). The owning module's image base is
         *          recovered from @c col.pSelf at @c col + 0x14 (x64 only,
         *          signature == 1) so vtables in any loaded module resolve
         *          correctly without consulting GetModuleHandleEx; the call
         *          is used only as a fallback when @c pSelf is zero (32-bit
         *          signature) or when the self-RVA produces an out-of-range
         *          base.
         *
         *          Reads up to @p max_len bytes from the name buffer in
         *          page-bounded chunks via @ref Memory::seh_read_bytes; the
         *          first NUL byte terminates the result. All reads are
         *          SEH-guarded on MSVC and VirtualQuery-guarded on MinGW.
         * @param vtable Runtime vtable pointer (the first qword of the object).
         * @param max_len Maximum mangled-name length to copy; clamped to
         *                @ref MAX_TYPE_NAME_LEN. Zero is replaced with
         *                @ref DEFAULT_TYPE_NAME_MAX.
         * @return The mangled name on success, std::nullopt on any failure
         *         (null vtable, unmapped page, missing COL, bad RVA, allocation
         *         failure).
         * @note Performs one heap allocation for the returned std::string.
         *       For per-frame identity probes use @ref vtable_is_type or
         *       @ref type_name_into to avoid the allocation.
         */
        [[nodiscard]] std::optional<std::string> type_name_of(
            std::uintptr_t vtable,
            std::size_t max_len = DEFAULT_TYPE_NAME_MAX) noexcept;

        /**
         * @brief Zero-allocation form of @ref type_name_of.
         * @details Writes the mangled name into @p out (always NUL-terminated
         *          when @p out_len > 0) and returns the number of bytes
         *          written excluding the terminator. On any failure the output
         *          buffer's first byte is set to '\0' and 0 is returned.
         * @param vtable Runtime vtable pointer (the first qword of the object).
         * @param out Destination buffer. Must be non-null when @p out_len > 0.
         * @param out_len Capacity of @p out including the NUL terminator.
         *                The function never writes more than @p out_len bytes.
         * @return Number of name bytes written (excluding the NUL terminator),
         *         or 0 on failure or empty output.
         */
        [[nodiscard]] std::size_t type_name_into(
            std::uintptr_t vtable,
            char *out,
            std::size_t out_len) noexcept;

        /**
         * @brief Tests whether the MSVC RTTI mangled name for @p vtable equals
         *        @p expected exactly.
         * @details Performs a byte-exact comparison of the mangled name plus
         *          the terminating NUL, rejecting both proper prefix and
         *          substring matches. The read is bounded by the length of
         *          @p expected plus one byte, so no allocation occurs and
         *          the per-call cost is dominated by the SEH-guarded read
         *          of @p expected.size() + 1 bytes from the name buffer.
         * @param vtable Runtime vtable pointer.
         * @param expected Mangled name to compare against. Must be non-empty
         *                 and shorter than @ref MAX_TYPE_NAME_LEN.
         * @return true on exact match; false on mismatch, on any read failure,
         *         or when @p expected is empty or oversized.
         */
        [[nodiscard]] bool vtable_is_type(std::uintptr_t vtable,
                                          std::string_view expected) noexcept;

        /**
         * @brief Scans a pointer-table for the first slot whose object has the
         *        given RTTI type-descriptor name.
         * @details Treats @p table as an array of @p slot_count entries each
         *          @p stride bytes wide. For every non-null slot the function
         *          dereferences the object pointer, reads the object's first
         *          qword as a vtable, and either:
         *          - on a cold cache (or when @p vtable_cache is nullptr)
         *            calls @ref vtable_is_type to perform the full RTTI walk;
         *          - on a warm cache (a previously-resolved vtable address)
         *            performs a single qword compare and skips slots whose
         *            vtable differs.
         *
         *          The first matching slot is returned. When a match is found
         *          on the cold path and @p vtable_cache is non-null, the
         *          matching vtable is stored with memory_order_relaxed so
         *          subsequent calls can take the warm path. Cache writes use
         *          a single relaxed store because concurrent first-callers
         *          converge on the same vtable value (image-resident
         *          vtables are unique per concrete type).
         *
         *          Caller-owned cache shape: one std::atomic<std::uintptr_t>
         *          per expected name, default-initialised to zero. Zero
         *          encodes "cold".
         * @param table Base address of the pointer table.
         * @param slot_count Number of slots to scan.
         * @param expected Mangled name to match.
         * @param vtable_cache Optional caller-owned cache slot. Pass nullptr
         *                     to skip caching (every call walks RTTI).
         * @param stride Byte distance between adjacent slot addresses.
         *               Defaults to sizeof(std::uintptr_t) for a packed
         *               pointer array; pass a larger stride for tables that
         *               interleave per-slot metadata between pointers.
         * @return The object pointer (the value stored in the slot) on first
         *         match, or std::nullopt if no slot matched.
         * @warning The warm-cache path assumes one canonical vtable address
         *          per expected name. If multiple derived concrete classes
         *          share the same base-mangled name and the table holds a
         *          mix of them, only slots whose vtable equals the
         *          first-resolved instance are returned on the warm path;
         *          other matches are skipped. For MSVC RTTI this is correct
         *          because mangled names encode the most-derived class, not
         *          the base.
         */
        [[nodiscard]] std::optional<std::uintptr_t> find_in_pointer_table(
            std::uintptr_t table,
            std::size_t slot_count,
            std::string_view expected,
            std::atomic<std::uintptr_t> *vtable_cache = nullptr,
            std::size_t stride = sizeof(std::uintptr_t)) noexcept;
    } // namespace Rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_RTTI_HPP
