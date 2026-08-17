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
     * @details Walks the x64 MSVC COL/TypeDescriptor layout to recover the mangled type-descriptor name for a runtime
     *          object. The implementation operates on raw addresses and never invokes typeid() or dynamic_cast, so it
     *          works across DLL boundaries against third-party MSVC binaries. Every entry point except the allocating
     *          TypeIdentity constructor is noexcept and guarded: an unreadable page, missing COL, or zero RVA produces
     *          a failure return. Names are returned in
     *          the MSVC mangled form (for example ".?AVMyClass@ns@@") for exact byte-equal comparison.
     *
     *          When the host binary is compiled with RTTI disabled (/GR-), the TypeDescriptor records are not emitted
     *          and every RTTI-based resolver returns its fail-closed sentinel rather than a fault or a wrong answer.
     *          The raw-byte fallbacks are @ref scan::find_string_xref and @ref scan::read_code_constant. Only
     *          @ref RttiPresence::Absent proves a complete records-free sweep. The failure-mode discussion is in
     *          docs/guides/rtti/rtti-walker.md and docs/guides/rtti/rtti-self-heal.md.
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
            /** @brief More qualifying sections or matches existed than the internal fixed buffer can hold. */
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
            /// No name was read (null/low vtable, missing or forged COL, unreadable page).
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
            /** @brief The sweep did not complete, so absence cannot be concluded. */
            Incomplete = 2
        };

        /**
         * @brief Reads the MSVC RTTI mangled type-descriptor name for the object whose runtime vtable is at @p vtable.
         * @details Walks vtable[-1] to the COL, the TypeDescriptor RVA, and the zero-terminated mangled name. The
         *          @c col.pSelf cross-check rejects a forged or relocated COL, and any signature other than the x64
         *          value is rejected. Reads are page-bounded and guarded. The first NUL terminates the result.
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
         * @details Writes the mangled name into @p out exactly as @ref type_name_into, but reports
         *          @ref NameStatus::Truncated whenever the real name did not fit @p out or the @ref MAX_TYPE_NAME_LEN
         *          hard cap, so an identity comparison can reject a truncated read instead of matching a prefix.
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
         * @details Folds the image base, SizeOfImage, PE TimeDateStamp, and the section table into a 64-bit token,
         *          read through the guarded engine. The token is stable while one image stays mapped and changes when
         *          a same-base replacement changes an identity-bearing PE header field. It carries the same
         *          discrimination as @ref scan::image_identity. @ref TypeIdentity keys its cached resolve on it, and a
         *          @ref HealedOffset consumer compares @ref HealedOffset::generation against it.
         * @param addr Any address inside the module of interest (typically a module base or a live object pointer).
         * @return A nonzero identity token for a module-backed address; 0 when @p addr is not inside any loaded module
         *         (an unmapped address or a private @c VirtualAlloc buffer carries no module-backed identity to track).
         * @note Setup/control-plane only -- resolves the owning module through the loader before reading its PE header.
         * @warning Like @ref scan::image_identity, this is layout identity rather than content identity. A replacement
         *          that preserves every folded header field while changing only section bytes remains invisible.
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
         * @details Treats @p table as an array of @p slot_count entries each @p stride bytes wide. A cold cache (or a
         *          nullptr @p vtable_cache) walks RTTI per slot via @ref vtable_is_type. A warm cache compares each
         *          slot against the cached vtable. If no slot carries it, the stale value is cleared and one cold pass
         *          runs. A cold-path match refreshes @p vtable_cache. The cache shape is one std::atomic<Address> per
         *          expected name. A null Address encodes "cold".
         * @param table Base address of the pointer table.
         * @param slot_count Number of slots to scan.
         * @param expected Mangled name to match.
         * @param vtable_cache Optional caller-owned cache slot. Pass nullptr to skip caching (every call walks RTTI).
         * @param stride Byte distance between adjacent slot addresses. Defaults to sizeof(std::uintptr_t) for a packed
         *               pointer array; pass a larger stride for tables that interleave per-slot metadata between
         *               pointers.
         * @return The object pointer (the value stored in the slot) on first match, or std::nullopt if no slot matched.
         * @note The cold path walks RTTI for each slot. A warm cache costs two guarded reads and one compare per slot.
         * @warning The warm-cache path assumes one canonical vtable address per expected name. If multiple derived
         *          concrete classes share the same base-mangled name and the table holds a mix of them, only slots
         *          whose vtable equals the first-resolved instance are returned on the warm path. Other matches are
         *          skipped. For MSVC RTTI this is correct: mangled names encode the most-derived class, not the base.
         * @warning This compatibility overload's raw atomic carries no image generation. Clear it at module-lifecycle
         *          boundaries, or use the @ref PointerTableCache overload for generation-checked caching.
         */
        [[nodiscard]] std::optional<Address>
        find_in_pointer_table(Address table, std::size_t slot_count, std::string_view expected,
                              std::atomic<Address> *vtable_cache = nullptr,
                              std::size_t stride = sizeof(std::uintptr_t)) noexcept;

        /**
         * @brief Generation-checked overload of @ref find_in_pointer_table.
         * @details A warm snapshot is accepted only while its image generation remains current. A warm call reads the
         *          image-generation token twice, once before the slot sweep and once before it returns. A stale
         *          snapshot is cleared and cold-resolved. Publication revalidates the type and generation before it
         *          caches them.
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
         * @details Sweeps the module's readable, non-executable sections for a COL whose TypeDescriptor name equals
         *          @p mangled and whose COL.offset is 0, and returns the vtable that points back to that COL. Every
         *          candidate passes the same COL prelude the forward walker uses, so a forged or coincidental match is
         *          rejected. COL.offset == 0 selects the most-derived instance's vtable. For a class used only as a
         *          secondary or virtual base, use @ref vtables_for_type.
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
         * @details Multiple or virtual inheritance gives one class several COLs, one per base sub-object, each
         *          referenced by its own vtable. This returns all of them. Each match is validated through the COL
         *          prelude exactly as @ref vtable_for_type.
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
         * @details Writes the matching sub-object vtables into @p out exactly as @ref vtables_for_type, and also
         *          reports whether the sweep was complete. Accept the count as final only under
         *          @ref Traversal::Complete. Otherwise it is a floor.
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
         * @details Sweeps @p range for any COL that passes the reverse resolver's validation checks. The two answers
         *          are asymmetric:
         *          - true is sound but only proves SOME record exists, not that the caller's type resolves (a /GR-
         *            executable that links a /GR CRT returns true off those library COLs);
         *          - false means "no record was found in what was swept" and is not by itself proof of absence. Use
         *            @ref region_rtti_presence when absence versus an incomplete sweep matters.
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
         * @details Sweeps @p range exactly as @ref region_has_rtti. Returns @ref RttiPresence::Absent only when the
         *          sweep completed and found nothing, and @ref RttiPresence::Incomplete when the sweep stopped early,
         *          so a caller never mistakes an early stop for an RTTI-free module.
         * @param range Module image to inspect. Defaults to the host EXE.
         * @return @ref RttiPresence::Present (a record was found), @ref RttiPresence::Absent (completed, none found),
         *         or @ref RttiPresence::Incomplete (invalid range or incomplete sweep, so absence cannot be concluded).
         * @note Setup/control-plane only, like @ref region_has_rtti.
         */
        [[nodiscard]] RttiPresence region_rtti_presence(Region range = Region::host()) noexcept;

        /**
         * @brief Cached, self-healing, generation-aware identity handle for a class vtable.
         * @details Resolves the primary vtable for a mangled name lazily via @ref vtable_for_type and caches it. A
         *          module-backed resolve is published only when the image generation is stable across the sweep. The
         *          warm path re-validates that stamp on every call and refreshes the full module extent after a remap.
         *          @ref invalidate forces an immediate cold resolve. A private-buffer scope has no module generation
         *          and must be reset explicitly.
         * @note Take identity from the cached vtable ADDRESS (the vtable[-1]
         *       COL-anchored value), never from the vtable's slot contents: under the MSVC linker's identical-COMDAT
         *       folding (/OPT:ICF) two distinct classes can share folded function-pointer slots, so a slot-content
         *       comparison is not class-unique.
         * @note Owns its mangled name (a private std::string copy), so no lifetime coupling to the caller's buffer.
         *       Non-copyable and non-movable. Hold it as a static or a long-lived member.
         */
        class TypeIdentity
        {
        public:
            /**
             * @brief Constructs a cached identity for @p mangled, scoped to @p range.
             * @details Construction allocates the owned name copy and can throw std::bad_alloc.
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
             *       result is cached. An unresolved result is not cached, but the re-sweep is throttled to at most
             *       once per internal cooldown, so per-frame polling for an absent type does not re-scan the module
             *       each frame.
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
            // detectable same-base remap invalidates the cached vtable instead of matching against a module that is
            // no longer mapped.
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
