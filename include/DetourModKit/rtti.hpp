#ifndef DETOURMODKIT_RTTI_HPP
#define DETOURMODKIT_RTTI_HPP

#include "DetourModKit/memory.hpp"

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
     *          Studio toolchain to recover the mangled type-descriptor name for a runtime object pointed to by a
     *          vtable. The implementation operates on raw addresses and never invokes typeid() or dynamic_cast, so it
     *          works across DLL boundaries and against third-party MSVC binaries (game engines, middleware) without
     *          symbol cooperation.
     *
     *          All entry points are noexcept and SEH-guarded; an unreadable page, missing COL, or zero RVA produces a
     *          failure return rather than a fault. Names are returned in the MSVC mangled form (e.g.
     *          ".?AVMyClass@ns@@") so callers can perform an exact byte-equal comparison instead of resolving through
     *          UnDecorateSymbolName.
     *
     *          The ABI layout this module relies on (COL at vtable - 8, TypeDescriptor RVA at COL + 0x0C, mangled name
     *          at TD + 0x10, COL.pSelf RVA at COL + 0x14 on x64) has been stable across every release of MSVC since
     *          Visual C++ 2010.
     *
     *          RTTI-disabled host binaries: every resolver in this namespace -- @ref type_name_of,
     *          @ref type_name_into, @ref vtable_is_type, @ref find_in_pointer_table, the reverse-direction
     *          @ref vtable_for_type / @ref vtables_for_type / @ref TypeIdentity::matches, and the self-heal backends
     *          in @ref rtti_dissect.hpp (which include @ref identify_pointee_type, @ref reverse_scan_block,
     *          @ref heal_landmark, @ref heal_offset, and @ref solve_fingerprint) -- is built on the
     *          COL/TypeDescriptor layout above. When the host binary is compiled with RTTI disabled (`/GR-` for MSVC
     *          and clang-cl), the TypeDescriptor records DMK needs to read are not emitted, and every RTTI-based
     *          resolver returns its fail-closed sentinel (`std::nullopt`, `std::unexpected`, `false`, or a zero
     *          count) rather than a fault or a wrong answer. The forward walker is still safe to call; it just
     *          cannot identify types.
     *
     *          The primary fallback for an RTTI-off consumer is @ref scan::find_string_xref or
     *          @ref scan::read_code_constant, which operate on raw bytes and do not require RTTI records. The
     *          long-form failure-mode discussion for each function is in docs/misc/rtti-walker.md and
     *          docs/misc/rtti-self-heal.md.
     */
    namespace Rtti
    {
        /// Default cap on the mangled-name length read into a heap-allocated string.
        inline constexpr std::size_t DEFAULT_TYPE_NAME_MAX = 256;

        /// Hard upper bound on any single mangled-name read.
        inline constexpr std::size_t MAX_TYPE_NAME_LEN = 1024;

        /**
         * @brief Reads the MSVC RTTI mangled type-descriptor name for the object whose runtime vtable is at @p vtable.
         * @details Walks @c vtable - 8 (RTTICompleteObjectLocator pointer), then @c col + 0x0C (TypeDescriptor RVA,
         *          base-relative), then @c td + 0x10 (zero-terminated mangled name such as ".?AVMyClass@ns@@"). The
         *          owning module's image base comes from the loader-reported module range; on x64 the @c col.pSelf RVA
         *          at @c col + 0x14 (signature == 1) must reconstruct that same base (@c col_addr - @c pSelf), which
         *          cross-checks the COL against a forged or relocated structure. Any signature other than the x64 value
         *          is rejected.
         *
         *          Reads up to @p max_len bytes from the name buffer in page-bounded chunks via @ref
         *          Memory::seh_read_bytes; the first NUL byte terminates the result. All reads are
         *          SEH-guarded on MSVC and VirtualQuery-guarded on MinGW.
         * @param vtable Runtime vtable pointer (the first qword of the object).
         * @param max_len Maximum mangled-name length to copy; clamped to @ref MAX_TYPE_NAME_LEN. Zero is replaced with
         *                @ref DEFAULT_TYPE_NAME_MAX.
         * @return The mangled name on success, std::nullopt on any failure (null vtable, unmapped page, missing COL,
         *         bad RVA, allocation failure).
         * @note Performs one heap allocation for the returned std::string. For per-frame identity probes use @ref
         *       vtable_is_type or @ref type_name_into to avoid the allocation.
         */
        [[nodiscard]] std::optional<std::string> type_name_of(std::uintptr_t vtable,
                                                              std::size_t max_len = DEFAULT_TYPE_NAME_MAX) noexcept;

        /**
         * @brief Zero-allocation form of @ref type_name_of.
         * @details Writes the mangled name into @p out (always NUL-terminated when @p out_len > 0) and returns the
         *          number of bytes written excluding the terminator. On any failure the output buffer's first byte is
         *          set to '\0' and 0 is returned.
         * @param vtable Runtime vtable pointer (the first qword of the object).
         * @param out Destination buffer. Must be non-null when @p out_len > 0.
         * @param out_len Capacity of @p out including the NUL terminator. The function never writes more than @p
         *                out_len bytes.
         * @return Number of name bytes written (excluding the NUL terminator), or 0 on failure or empty output.
         */
        [[nodiscard]] std::size_t type_name_into(std::uintptr_t vtable, char *out, std::size_t out_len) noexcept;

        /**
         * @brief Tests whether the MSVC RTTI mangled name for @p vtable equals @p expected exactly.
         * @details Performs a byte-exact comparison of the mangled name plus the terminating NUL, rejecting both proper
         *          prefix and substring matches. The read is bounded by the length of @p expected plus one byte, so no
         *          allocation occurs and the per-call cost is dominated by the SEH-guarded read of @p expected.size() +
         *          1 bytes from the name buffer.
         * @param vtable Runtime vtable pointer.
         * @param expected Mangled name to compare against. Must be non-empty and shorter than @ref MAX_TYPE_NAME_LEN.
         * @return true on exact match; false on mismatch, on any read failure, or when @p expected is empty or
         *         oversized.
         */
        [[nodiscard]] bool vtable_is_type(std::uintptr_t vtable, std::string_view expected) noexcept;

        /**
         * @brief Scans a pointer-table for the first slot whose object has the given RTTI type-descriptor name.
         * @details Treats @p table as an array of @p slot_count entries each @p stride bytes wide. For every non-null
         *          slot the function dereferences the object pointer, reads the object's first qword as a vtable, and
         *          either:
         *          - on a cold cache (or when @p vtable_cache is nullptr)
         *            calls @ref vtable_is_type to perform the full RTTI walk;
         *          - on a warm cache (a previously-resolved vtable address)
         *            performs a single qword compare and skips slots whose vtable differs.
         *
         *          The first matching slot is returned. When a match is found on the cold path and @p vtable_cache is
         *          non-null, the matching vtable is stored with memory_order_relaxed so subsequent calls can take the
         *          warm path. Cache writes use a single relaxed store because concurrent first-callers converge on the
         *          same vtable value (image-resident vtables are unique per concrete type).
         *
         *          Caller-owned cache shape: one std::atomic<std::uintptr_t> per expected name, default-initialised to
         *          zero. Zero encodes "cold".
         * @param table Base address of the pointer table.
         * @param slot_count Number of slots to scan.
         * @param expected Mangled name to match.
         * @param vtable_cache Optional caller-owned cache slot. Pass nullptr to skip caching (every call walks RTTI).
         * @param stride Byte distance between adjacent slot addresses. Defaults to sizeof(std::uintptr_t) for a packed
         *               pointer array; pass a larger stride for tables that interleave per-slot metadata between
         *               pointers.
         * @return The object pointer (the value stored in the slot) on first match, or std::nullopt if no slot matched.
         * @warning The warm-cache path assumes one canonical vtable address per expected name. If multiple derived
         *          concrete classes share the same base-mangled name and the table holds a mix of them, only slots
         *          whose vtable equals the
         *          first-resolved instance are returned on the warm path;
         *          other matches are skipped. For MSVC RTTI this is correct because mangled names encode the
         *          most-derived class, not the base.
         */
        [[nodiscard]] std::optional<std::uintptr_t>
        find_in_pointer_table(std::uintptr_t table, std::size_t slot_count, std::string_view expected,
                              std::atomic<std::uintptr_t> *vtable_cache = nullptr,
                              std::size_t stride = sizeof(std::uintptr_t)) noexcept;

        /**
         * @brief Resolves the primary (most-derived) vtable for a class by its
         *        MSVC mangled name, scoped to one module image.
         * @details The reverse of @ref vtable_is_type: instead of "what type is this vtable", it answers "where is the
         *          vtable for this type". The module's readable, non-executable sections are swept for an
         *          RTTICompleteObjectLocator whose TypeDescriptor name equals @p mangled and whose COL.offset is 0, and
         *          the vtable that points back to that COL (via its vtable[-1] meta-slot) is returned. Every candidate
         *          is validated through the same COL prelude the forward walker uses (x64 signature, the
         *          pSelf-vs-loader-base cross-check, in-module bounds), so a forged or coincidental match is rejected
         *          rather than returned.
         *
         *          COL.offset == 0 is required so the result is the vtable an object pointer's first qword holds for a
         *          most-derived instance, which is exactly what an identity check compares against. A class used only
         *          as a secondary or virtual base has its first qword pointing at a COL.offset != 0 sub-object vtable;
         *          use @ref vtables_for_type for that case.
         * @param mangled Exact MSVC mangled name (e.g. ".?AVMyClass@ns@@").
         * @param range Module image to search. Defaults to the host EXE. The scope is load-bearing for correctness, not
         *              merely
         *              ergonomic: the same mangled name can appear in several
         *              loaded modules and COL RVAs are image-base-relative.
         * @return The primary vtable address on a unique match; std::nullopt when no COL.offset == 0 match exists, when
         *         @p range is invalid, or when more than one distinct primary vtable shares the name (an ambiguous
         *         image: the resolver fails closed rather than guessing).
         */
        [[nodiscard]] std::optional<std::uintptr_t>
        vtable_for_type(std::string_view mangled, Memory::ModuleRange range = Memory::host_module_range()) noexcept;

        /**
         * @brief Collects every sub-object vtable sharing a class's mangled name.
         * @details Multiple or virtual inheritance gives one class (one
         *          TypeDescriptor, one mangled name) several COLs -- one per base sub-object, each at a distinct
         *          COL.offset and each referenced by its own vtable. This returns all of them so a caller matching an
         *          object pointer that may point at a secondary base is not limited to the primary vtable. Each match
         *          is validated through the COL prelude exactly as @ref vtable_for_type.
         * @param mangled Exact MSVC mangled name.
         * @param out Destination buffer for the matching vtable addresses, written in ascending COL.offset order (the
         *            primary, offset 0, first). May be nullptr only when @p out_cap is 0 (count-only query).
         * @param out_cap Capacity of @p out; at most @p out_cap addresses are written even when more matches exist.
         * @param range Module image to search. Defaults to the host EXE.
         * @return Total number of distinct matching vtables found (capped at an internal upper bound that far exceeds
         *         any real inheritance graph). A return value greater than @p out_cap signals the output was truncated.
         */
        [[nodiscard]] std::size_t vtables_for_type(std::string_view mangled, std::uintptr_t *out, std::size_t out_cap,
                                                   Memory::ModuleRange range = Memory::host_module_range()) noexcept;

        /**
         * @brief Cached, self-healing identity handle for a class vtable.
         * @details Resolves the primary vtable for a mangled name once (lazily, on first use) via @ref vtable_for_type
         *          and caches it, so a per-frame identity check is a single qword compare with no RTTI walk -- the same
         *          warm-cache shape as @ref find_in_pointer_table. Because the cached value is keyed on the stable
         *          class name, it survives a game patch that relocates the vtable (the name does not move), which a
         *          hard-coded vtable literal does not.
         * @note Take identity from the cached vtable ADDRESS (the vtable[-1]
         *       COL-anchored value), never from the vtable's slot contents: under the MSVC linker's identical-COMDAT
         *       folding (/OPT:ICF) two distinct classes can share folded function-pointer slots, so a slot-content
         *       comparison is not class-unique.
         * @note Holds the name as a non-owning view; the backing string must outlive the handle. Non-copyable and
         *       non-movable (it owns atomic cache state); hold it as a static or a long-lived member.
         */
        class TypeIdentity
        {
        public:
            /**
             * @brief Constructs an identity for @p mangled, scoped to @p range.
             * @param mangled Exact MSVC mangled name. Stored as a view; the backing storage must outlive the handle.
             * @param range Module image to resolve in. Defaults to the host EXE.
             */
            explicit TypeIdentity(std::string_view mangled,
                                  Memory::ModuleRange range = Memory::host_module_range()) noexcept;

            /**
             * @brief Constructs a cached identity from a null-terminated mangled type name.
             * @details This exact-match overload keeps string-literal call sites unambiguous while the deleted
             *          std::string rvalue overload rejects dangling temporaries. A null pointer is treated as an empty
             *          name and resolves to no match.
             * @param mangled Null-terminated MSVC RTTI name. The backing bytes must outlive this identity.
             * @param range Module range searched for the primary vtable.
             */
            explicit TypeIdentity(const char *mangled, Memory::ModuleRange range = Memory::host_module_range()) noexcept
                : TypeIdentity(mangled != nullptr ? std::string_view(mangled) : std::string_view{}, range)
            {
            }

            /**
             * @brief Rejects std::string temporaries because the identity stores a non-owning view.
             * @details A string literal, std::string_view, or long-lived std::string lvalue can still bind safely. A
             *          std::string rvalue would dangle as soon as the constructor returns, so it is a compile-time
             *          error.
             */
            TypeIdentity(std::string &&mangled, Memory::ModuleRange range = Memory::host_module_range()) = delete;

            /**
             * @brief Tests whether @p vtable is this type's primary vtable.
             * @details Resolves on first call, then compares. Returns false when the type cannot be resolved, so a
             *          missing type never matches.
             * @param vtable Candidate vtable (an object's first qword).
             * @return true when @p vtable equals the resolved primary vtable.
             */
            [[nodiscard]] bool matches(std::uintptr_t vtable) const noexcept;

            /**
             * @brief Returns the resolved primary vtable, resolving on first use.
             * @return The vtable address, or std::nullopt if it cannot be resolved in the configured module range.
             */
            [[nodiscard]] std::optional<std::uintptr_t> vtable() const noexcept;

        private:
            std::string_view m_mangled;
            Memory::ModuleRange m_range;

            // m_cached holds the resolved primary vtable and is written only on a SUCCESSFUL (nonzero) resolve.
            // m_resolved latches that success and is published with release after m_cached is stored, so an
            // acquire-load that observes m_resolved == true also observes the cached value. A failed resolve latches
            // neither flag, so a later call retries once the type becomes resolvable instead of caching the miss as
            // permanent.
            mutable std::atomic<std::uintptr_t> m_cached{0};
            mutable std::atomic<bool> m_resolved{false};
        };
    } // namespace Rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_RTTI_HPP
