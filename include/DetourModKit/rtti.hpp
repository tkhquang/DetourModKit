#ifndef DETOURMODKIT_RTTI_HPP
#define DETOURMODKIT_RTTI_HPP

#include "DetourModKit/region.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace DetourModKit
{
    /**
     * @namespace DetourModKit::rtti
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
     *          The ABI layout this module relies on is the supported MSVC x64 COL and TypeDescriptor layout.
     *
     *          RTTI-disabled host binaries: every resolver in this namespace -- @ref type_name_of,
     *          @ref type_name_into, @ref vtable_is_type, @ref find_in_pointer_table, the reverse-direction
     *          @ref vtable_for_type / @ref vtables_for_type / @ref TypeIdentity::matches, and the self-heal backends
     *          in @ref rtti_dissect.hpp (which include @ref identify_pointee_type, @ref reverse_scan_block,
     *          @ref heal_landmark, and @ref solve_fingerprint) -- is built on the
     *          COL/TypeDescriptor layout above. When the host binary is compiled with RTTI disabled (`/GR-` for MSVC
     *          and clang-cl), the TypeDescriptor records DMK needs to read are not emitted, and every RTTI-based
     *          resolver returns its fail-closed sentinel (`std::nullopt`, `std::unexpected`, `false`, or a zero
     *          count) rather than a fault or a wrong answer. The forward walker is still safe to call; it just
     *          cannot identify types.
     *
     *          The primary fallback for an RTTI-off consumer is @ref scan::find_string_xref or
     *          @ref scan::read_code_constant, which operate on raw bytes and do not require RTTI records. A consumer
     *          that cannot tell a genuine miss from an RTTI-less module can call @ref region_rtti_presence first. Only
     *          @ref RttiPresence::Absent proves a complete records-free sweep; a true @ref region_has_rtti result only
     *          proves the module carries some record, not that the caller's own type resolves. The
     *          long-form failure-mode discussion for each function is in docs/guides/rtti/rtti-walker.md and
     *          docs/guides/rtti/rtti-self-heal.md.
     */
    namespace rtti
    {
        /// Default cap on the mangled-name length read into a heap-allocated string.
        inline constexpr std::size_t DEFAULT_TYPE_NAME_MAX = 256;

        /// Hard upper bound on any single mangled-name read.
        inline constexpr std::size_t MAX_TYPE_NAME_LEN = 1024;

        /**
         * @enum Traversal
         * @brief Completeness of a reverse-RTTI section/page sweep.
         * @details A reverse resolver answers "is there a unique vtable for this type" or "does this scope hold any
         *          record" by sweeping the module's readable non-executable sections. A verdict that depends on having
         *          seen the WHOLE image -- a unique vtable, an authoritative absence -- is trustworthy only under @ref
         *          Complete. A truncated sweep can hide a second primary (false uniqueness) or the only record
         *          (false absence), so the checked reverse forms surface this rather than reporting a positive prefix
         *          as final.
         */
        enum class Traversal : std::uint8_t
        {
            /// Every qualifying section was enumerated and every page in it was read.
            Complete = 0,
            /** @brief The sweep under-covered the image, so a unique or absent verdict cannot be authorized. */
            Incomplete = 1,
            /** @brief More qualifying sections or matches existed than the internal fixed buffer could hold. */
            Saturated = 2
        };

        /**
         * @enum NameStatus
         * @brief Outcome of a checked mangled-name read (@ref type_name_checked).
         */
        enum class NameStatus : std::uint8_t
        {
            /// The full NUL-terminated name was copied.
            Ok = 0,
            /** @brief The NUL-terminated copy is a proper prefix and must not be compared for identity. */
            Truncated = 1,
            /// No name could be read (null/low vtable, missing or forged COL, unreadable page).
            Failed = 2
        };

        /**
         * @struct NameRead
         * @brief Result of @ref type_name_checked: bytes written plus whether the copy is the complete name.
         */
        struct NameRead
        {
            /// Name bytes written excluding the NUL terminator.
            std::size_t written = 0;
            /// Whether the copy is complete, a truncated prefix, or a failure.
            NameStatus status = NameStatus::Failed;
        };

        /**
         * @struct VtablesResult
         * @brief Result of @ref vtables_for_type_checked: the match count plus the sweep completeness.
         */
        struct VtablesResult
        {
            /// Distinct matching sub-object vtables found (the same value @ref vtables_for_type returns).
            std::size_t count = 0;
            /** @brief Sweep completeness; under Incomplete or Saturated, count is only a floor. */
            Traversal completeness = Traversal::Complete;
        };

        /**
         * @enum RttiPresence
         * @brief Trit answer of @ref region_rtti_presence, separating an authoritative absence from an incomplete
         *        sweep.
         */
        enum class RttiPresence : std::uint8_t
        {
            /// At least one resolvable RTTI record was found (sound regardless of completeness: a hit is a hit).
            Present = 0,
            /// The sweep completed and found no record: an authoritative absence (an MSVC /GR- scope, a data module).
            Absent = 1,
            /** @brief The sweep could not complete, so absence cannot be concluded. */
            Incomplete = 2
        };

        /**
         * @brief Reads the MSVC RTTI mangled type-descriptor name for the object whose runtime vtable is at @p vtable.
         * @details Walks @c vtable - 8 (RTTICompleteObjectLocator pointer), then @c col + 0x0C (TypeDescriptor RVA,
         *          base-relative), then @c td + 0x10 (zero-terminated mangled name such as ".?AVMyClass@ns@@"). The
         *          owning module's image base comes from the loader-reported module range; on x64 the @c col.pSelf RVA
         *          at @c col + 0x14 (signature == 1) must reconstruct that same base (@c col_addr - @c pSelf), which
         *          cross-checks the COL against a forged or relocated structure. Any signature other than the x64 value
         *          is rejected.
         *
         *          Reads up to @p max_len bytes from the name buffer in page-bounded chunks through the guarded read
         *          engine; the first NUL byte terminates the result. All reads are SEH-guarded on MSVC and
         *          vectored-handler-guarded on MinGW.
         * @param vtable Runtime vtable pointer (the first qword of the object).
         * @param max_len Maximum mangled-name length to copy; clamped to @ref MAX_TYPE_NAME_LEN. Zero is replaced with
         *                @ref DEFAULT_TYPE_NAME_MAX.
         * @return The mangled name on success, std::nullopt on any failure (null vtable, unmapped page, missing COL,
         *         bad RVA, allocation failure).
         * @note Performs one heap allocation for the returned std::string. For per-frame identity probes use @ref
         *       vtable_is_type or @ref type_name_into to avoid the allocation.
         */
        [[nodiscard]] std::optional<std::string> type_name_of(Address vtable,
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
         * @note Zero-allocation, but each call runs the loader-querying COL prelude (a GetModuleHandleEx-class lookup),
         *       so it is an occasional identity probe, not a zero-cost per-frame test; cache a @ref TypeIdentity when
         *       checking the same type every frame.
         */
        [[nodiscard]] std::size_t type_name_into(Address vtable, char *out, std::size_t out_len) noexcept;

        /**
         * @brief Truncation-reporting form of @ref type_name_into.
         * @details Writes the mangled name into @p out exactly as @ref type_name_into, but distinguishes a name that
         *          fit from one that was cut. @ref type_name_into cannot: it returns the bytes written, which equals
         *          the capacity both when the name fit exactly and when it was truncated, so a caller comparing the
         *          result for identity could match a proper prefix of a longer name against a shorter expected name.
         *          This form reports @ref NameStatus::Truncated whenever the real name did not fit @p out (or the @ref
         *          MAX_TYPE_NAME_LEN hard cap), so an identity comparison can reject a truncated read instead of
         *          treating a prefix as a whole name.
         * @param vtable Runtime vtable pointer (the first qword of the object).
         * @param out Destination buffer; always NUL-terminated when @p out_len > 0. Must be non-null when @p
         *            out_len > 0.
         * @param out_len Capacity of @p out including the NUL terminator.
         * @return @ref NameRead::written name bytes (excluding the NUL) and a @ref NameRead::status of @ref
         *         NameStatus::Ok (complete), @ref NameStatus::Truncated (a prefix; do not compare for identity), or
         *         @ref NameStatus::Failed (nothing read; @p out is left empty).
         */
        [[nodiscard]] NameRead type_name_checked(Address vtable, char *out, std::size_t out_len) noexcept;

        /**
         * @brief A stable, mapping-scoped identity token for the module currently mapped over @p addr.
         * @details Derives a 64-bit token from the module's image base, SizeOfImage, and PE TimeDateStamp, read through
         *          the guarded engine. The token is stable while one image stays mapped and changes when that image is
         *          unloaded or a DIFFERENT image is mapped at the same base (a same-base remap) -- the case a base-only
         *          key cannot see. It is the generation @ref TypeIdentity keys its cached resolve on, and the value a
         *          consumer of a @ref rtti_dissect.hpp @ref HealedOffset compares @ref HealedOffset::generation against
         *          to decide whether a healed value still refers to the image it was resolved in.
         * @param addr Any address inside the module of interest (typically a module base or a live object pointer).
         * @return A nonzero identity token for a module-backed address; 0 when @p addr is not inside any loaded module
         *         (an unmapped address or a private @c VirtualAlloc buffer carries no module-backed identity to track).
         * @note Setup/control-plane only -- resolves the owning module through the loader before reading its PE header.
         */
        [[nodiscard]] std::uint64_t image_generation(Address addr) noexcept;

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
         * @note Each call runs the loader-querying COL prelude, so it is an occasional identity probe, not a zero-cost
         *       per-frame test; cache a @ref TypeIdentity when checking the same type every frame.
         */
        [[nodiscard]] bool vtable_is_type(Address vtable, std::string_view expected) noexcept;

        /**
         * @class PointerTableCache
         * @brief Generation-bearing cache for repeated @ref find_in_pointer_table calls with one expected type.
         * @details Stores the resolved vtable together with its image base and generation. Concurrent reads are
         *          supported; publication is non-blocking, and a competing publisher leaves the existing snapshot for
         *          the next call to validate.
         */
        class PointerTableCache
        {
        public:
            /// Constructs an empty cache.
            PointerTableCache() noexcept = default;
            PointerTableCache(const PointerTableCache &) = delete;
            PointerTableCache &operator=(const PointerTableCache &) = delete;
            PointerTableCache(PointerTableCache &&) = delete;
            PointerTableCache &operator=(PointerTableCache &&) = delete;
            ~PointerTableCache() noexcept = default;

            /**
             * @brief Clears the cached identity so the next lookup starts cold.
             * @note Setup/control-plane only -- waits for an in-progress cache publication to finish.
             */
            void reset() noexcept;

        private:
            friend std::optional<Address> find_in_pointer_table(Address table, std::size_t slot_count,
                                                                std::string_view expected, PointerTableCache &cache,
                                                                std::size_t stride) noexcept;

            // Single-writer sequence protects a coherent {vtable, image base, generation} snapshot.
            std::atomic_flag m_writer{};
            std::atomic<std::uint32_t> m_seq{0};
            std::atomic<Address> m_vtable{Address{}};
            std::atomic<Address> m_image_base{Address{}};
            std::atomic<std::uint64_t> m_generation{0};
            // Advanced by reset() so a lookup that started earlier cannot publish across the reset boundary.
            std::atomic<std::uint64_t> m_epoch{0};
        };

        /**
         * @brief Scans a pointer-table for the first slot whose object has the given RTTI type-descriptor name.
         * @details Treats @p table as an array of @p slot_count entries each @p stride bytes wide. For every non-null
         *          slot the function dereferences the object pointer, reads the object's first qword as a vtable, and
         *          either:
         *          - on a cold cache (or when @p vtable_cache is nullptr)
         *            calls @ref vtable_is_type to perform the full RTTI walk;
         *          - on a warm cache (a previously-resolved vtable address), first performs qword comparisons; if no
         *            slot carries the cached vtable, clears the observed stale value and performs one cold RTTI pass.
         *
         *          The first matching slot is returned. A cold-path match refreshes @p vtable_cache with
         *          memory_order_relaxed so subsequent calls can take the warm path.
         *
         *          Caller-owned cache shape: one std::atomic<Address> per expected name, default-initialised to a null
         *          Address. A null Address encodes "cold".
         * @param table Base address of the pointer table.
         * @param slot_count Number of slots to scan.
         * @param expected Mangled name to match.
         * @param vtable_cache Optional caller-owned cache slot. Pass nullptr to skip caching (every call walks RTTI).
         * @param stride Byte distance between adjacent slot addresses. Defaults to sizeof(std::uintptr_t) for a packed
         *               pointer array; pass a larger stride for tables that interleave per-slot metadata between
         *               pointers.
         * @return The object pointer (the value stored in the slot) on first match, or std::nullopt if no slot matched.
         * @note The cold path runs the RTTI walk per slot; a valid warm cache needs only one qword compare per slot.
         * @warning The warm-cache path assumes one canonical vtable address per expected name. If multiple derived
         *          concrete classes share the same base-mangled name and the table holds a mix of them, only slots
         *          whose vtable equals the
         *          first-resolved instance are returned on the warm path;
         *          other matches are skipped. For MSVC RTTI this is correct because mangled names encode the
         *          most-derived class, not the base.
         * @warning This compatibility overload's raw atomic carries no image generation. Clear it at module-lifecycle
         *          boundaries, or use the @ref PointerTableCache overload for generation-checked caching.
         */
        [[nodiscard]] std::optional<Address>
        find_in_pointer_table(Address table, std::size_t slot_count, std::string_view expected,
                              std::atomic<Address> *vtable_cache = nullptr,
                              std::size_t stride = sizeof(std::uintptr_t)) noexcept;

        /**
         * @brief Generation-checked overload of @ref find_in_pointer_table.
         * @details A warm snapshot is accepted only while its image generation remains current. A stale snapshot is
         *          cleared and cold-resolved; publication revalidates the type and generation before caching it.
         * @param table Base address of the pointer table.
         * @param slot_count Number of slots to scan.
         * @param expected Mangled name to match; one cache instance is dedicated to one expected name.
         * @param cache Caller-owned generation-bearing cache.
         * @param stride Byte distance between adjacent slot addresses.
         * @return The first matching object pointer, or std::nullopt.
         * @note Prefer this overload when the cache survives module unload/reload boundaries.
         */
        [[nodiscard]] std::optional<Address>
        find_in_pointer_table(Address table, std::size_t slot_count, std::string_view expected,
                              PointerTableCache &cache, std::size_t stride = sizeof(std::uintptr_t)) noexcept;

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
         * @param range Module image to search. Defaults to the host EXE. The scope is required because the same mangled
         *              name can appear in several loaded modules and COL RVAs are image-base-relative.
         * @return The primary vtable on a unique match; std::nullopt on absence, invalid scope, ambiguous primaries, or
         *         incomplete traversal. A partial sweep cannot authorize uniqueness because a second primary may be in
         *         the un-swept region. Use @ref vtables_for_type_checked to distinguish absence from an incomplete
         *         traversal.
         * @note Setup/control-plane only: it sweeps the module's readable sections, so run it once at init (or behind a
         *       cached @ref TypeIdentity), never per-frame.
         */
        [[nodiscard]] std::optional<Address> vtable_for_type(std::string_view mangled,
                                                             Region range = Region::host()) noexcept;

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
         * @note Setup/control-plane only: a full module-section sweep, like @ref vtable_for_type; run it at init.
         */
        [[nodiscard]] std::size_t vtables_for_type(std::string_view mangled, Address *out, std::size_t out_cap,
                                                   Region range = Region::host()) noexcept;

        /**
         * @brief Completeness-reporting form of @ref vtables_for_type.
         * @details Writes the matching sub-object vtables into @p out exactly as @ref vtables_for_type, but also
         *          reports whether the section/page sweep that produced them was complete. @ref vtables_for_type
         *          returns only a count, which a caller cannot distinguish from a truncated sweep, so "count == 0"
         *          could mean either a
         *          genuine absence or a sweep that faulted before reaching the record. This form returns @ref
         *          VtablesResult::completeness so a caller reasoning about absence or uniqueness accepts the count as
         *          final only under @ref Traversal::Complete.
         * @param mangled Exact MSVC mangled name.
         * @param out Destination buffer for the matching vtable addresses, ascending COL.offset order (primary first).
         *            May be nullptr only when @p out_cap is 0 (count-only query).
         * @param out_cap Capacity of @p out; at most @p out_cap addresses are written even when more matches exist.
         * @param range Module image to search. Defaults to the host EXE.
         * @return The distinct-match @ref VtablesResult::count (a @ref VtablesResult::completeness other than @ref
         *         Traversal::Complete means the count is a floor, not the authoritative total).
         * @note Setup/control-plane only: a full module-section sweep, like @ref vtable_for_type; run it at init.
         */
        [[nodiscard]] VtablesResult vtables_for_type_checked(std::string_view mangled, Address *out,
                                                             std::size_t out_cap,
                                                             Region range = Region::host()) noexcept;

        /**
         * @brief Reports whether a module region currently contains any resolvable MSVC RTTI record.
         * @details Sweeps @p range for any COL that passes the reverse resolver's x64 signature, pSelf/base, and
         *          in-module bounds checks.
         *
         *          The predicate is region-level and its two answers are deliberately asymmetric:
         *          - true is sound: at least one resolvable record was found. It only proves SOME record exists, not
         *            that the caller's type resolves -- a /GR- executable that links a /GR CRT returns true off those
         *            library COLs while an executable-owned type still needs the raw-byte fallback.
         *          - false means "no record was found in what was swept" and is the go-to-raw-fallback signal, but it
         *            is not by itself proof of absence: if the sweep could not complete (a faulted section header or an
         *            unreadable page), a record may exist in the un-swept region. Use @ref region_rtti_presence when
         *            the difference between an authoritative absence and an incomplete sweep matters (it returns @ref
         *            RttiPresence::Incomplete instead of collapsing the two into a bare false).
         * @param range Module image to inspect. Defaults to the host EXE.
         * @return true if @p range holds at least one resolvable RTTI record; false if none was found in the swept
         *         portion or @p range is not a valid mapped image.
         * @note Setup/control-plane only: it sweeps the module's readable sections like @ref vtable_for_type, so run it
         *       once after a resolve miss, never per-frame. It carries no re-sweep throttle, so a records-free scope
         *       pays a full sweep on every call.
         * @note An absent verdict on a still-packed image is a transient truth about the CURRENT mapping, not proof the
         *       binary was built /GR-; re-inspect after the image unpacks rather than caching the result as permanent.
         */
        [[nodiscard]] bool region_has_rtti(Region range = Region::host()) noexcept;

        /**
         * @brief Completeness-reporting form of @ref region_has_rtti.
         * @details Sweeps @p range exactly as @ref region_has_rtti but reports a trit that keeps an authoritative
         *          absence distinct from a sweep that could not finish. @ref region_has_rtti collapses both into false;
         *          this returns @ref RttiPresence::Absent only when the sweep completed and found nothing, and @ref
         *          RttiPresence::Incomplete when a section header faulted or a page was unreadable before a record
         *          could be found -- so a caller never mistakes "the sweep stopped early" for "this module has no
         *          RTTI".
         * @param range Module image to inspect. Defaults to the host EXE.
         * @return @ref RttiPresence::Present (a record was found), @ref RttiPresence::Absent (completed, none found),
         *         or @ref RttiPresence::Incomplete (invalid range or incomplete sweep, so absence cannot be concluded).
         * @note Setup/control-plane only, like @ref region_has_rtti.
         */
        [[nodiscard]] RttiPresence region_rtti_presence(Region range = Region::host()) noexcept;

        /**
         * @brief Cached, self-healing, generation-aware identity handle for a class vtable.
         * @details Resolves the primary vtable for a mangled name lazily via @ref vtable_for_type and caches it. Warm
         *          calls re-read the image identity without repeating the RTTI sweep. Because the cached value is keyed
         *          on the stable class name, it survives a game patch that relocates the vtable (the name does not
         *          move), which a hard-coded vtable literal does not.
         * @details A module-backed resolve is published only when the image generation is stable across the sweep. The
         *          warm path re-validates that stamp on every call and refreshes the full module extent after a remap.
         *          @ref invalidate forces an immediate cold resolve. A private-buffer scope has no module generation
         *          and must be reset explicitly.
         * @note Take identity from the cached vtable ADDRESS (the vtable[-1]
         *       COL-anchored value), never from the vtable's slot contents: under the MSVC linker's identical-COMDAT
         *       folding (/OPT:ICF) two distinct classes can share folded function-pointer slots, so a slot-content
         *       comparison is not class-unique.
         * @note Owns its mangled name (a private std::string copy), so it is self-contained: a string literal, a
         *       std::string_view into any storage, or a std::string temporary can all initialise it safely with no
         *       lifetime coupling to the caller's buffer. Non-copyable and non-movable (it owns atomic cache state);
         *       hold it as a static or a long-lived member.
         */
        class TypeIdentity
        {
        public:
            /**
             * @brief Constructs a cached identity for @p mangled, scoped to @p range.
             * @details Copies @p mangled into an owned std::string, so a string literal, a std::string_view, or a
             *          std::string temporary all bind safely without the caller having to keep the backing bytes alive.
             * @param mangled Exact MSVC mangled name. Copied into owned storage.
             * @param range Module image to resolve in. Defaults to the host EXE.
             */
            explicit TypeIdentity(std::string_view mangled, Region range = Region::host());

            TypeIdentity(const TypeIdentity &) = delete;
            TypeIdentity &operator=(const TypeIdentity &) = delete;
            TypeIdentity(TypeIdentity &&) = delete;
            TypeIdentity &operator=(TypeIdentity &&) = delete;
            ~TypeIdentity() noexcept = default;

            /**
             * @brief Tests whether @p vtable is this type's primary vtable.
             * @details Resolves on first call, then compares. Returns false when the type cannot be resolved, so a
             *          missing type never matches.
             * @param vtable Candidate vtable (an object's first qword).
             * @return true when @p vtable equals the resolved primary vtable.
             * @note Callback-safe once warm: the generation check performs bounded guarded PE-header reads; a changed
             *       image triggers a setup-cost resolve.
             */
            [[nodiscard]] bool matches(Address vtable) const noexcept;

            /**
             * @brief Returns the resolved primary vtable, resolving on first use.
             * @return The vtable address, or std::nullopt if it cannot be resolved in the configured module range.
             * @note Callback-safe once warm: the first call resolves (a setup-cost module sweep), and a successful
             *       result is cached. An unresolved result is not
             *       cached (the owning module may map the type later), but the re-sweep is throttled to at most
             *       once per internal cooldown, so polling this every frame for a type that is not present does
             *       not re-scan the whole module each frame.
             */
            [[nodiscard]] std::optional<Address> vtable() const noexcept;

            /**
             * @brief Drops the cached resolve so the next @ref vtable / @ref matches re-resolves from scratch.
             * @details Idempotent and safe to call at any time. Use it when a consumer knows the resolving module was
             *          unloaded or reloaded. Does not change the mangled name or range the handle was constructed with.
             * @note Setup/control-plane only -- waits for an in-progress cache publication to finish; never throws.
             */
            void invalidate() noexcept;

        private:
            std::string m_mangled;
            Region m_range;
            bool m_tracks_module_range{false};

            // m_cached holds the resolved primary vtable and is written only on a SUCCESSFUL (non-null) resolve.
            // m_resolved latches that success and is published with release after m_cached is stored, so an
            // acquire-load that observes m_resolved == true also observes the cached value. A failed resolve latches
            // neither flag, so a later call retries once the type becomes resolvable instead of caching the miss as
            // permanent.
            mutable std::atomic<Address> m_cached{Address{}};
            mutable std::atomic<bool> m_resolved{false};

            // The resolving module's image_generation at the last successful resolve (0 = none, or a non-module range).
            // The warm path re-reads the current generation and drops the cache when it differs, so an unload or a
            // same-base remap invalidates the cached vtable instead of matching against a module that is no longer
            // mapped.
            mutable std::atomic<std::uint64_t> m_image_stamp{0};
            mutable std::atomic<Address> m_image_base{Address{}};

            // Serializes the short publish/clear transaction; the RTTI sweep itself runs without holding it.
            mutable std::atomic_flag m_cache_writer{};
            // Incremented whenever the cache is cleared so a resolve already in flight cannot republish afterward.
            mutable std::atomic<std::uint64_t> m_cache_epoch{0};

            // Millisecond timestamp of the last unresolved sweep (0 = never). It bounds whole-module retries for a type
            // that is not present; successful warm calls do not modify it.
            mutable std::atomic<std::uint64_t> m_last_attempt_ms{0};
        };
    } // namespace rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_RTTI_HPP
